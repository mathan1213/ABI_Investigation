import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from database import get_db
import db_models
from modules.auth_module import (
    check_login_rate_limit,
    record_login_attempt,
    check_username_rate_limit,
    record_username_check,
    validate_username,
    validate_email_format,
    validate_password_strength,
    hash_password,
    verify_password,
    create_access_token,
    get_current_user,
    log_activity,
    check_account_lockout,
    record_failed_login,
    reset_failed_login,
    parse_permissions,
)
from modules.email_service import send_welcome_email

router = APIRouter(prefix="/api/auth", tags=["auth"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    name: str
    username: Optional[str] = None
    email: str
    password: str
    consent: bool = False

class LoginRequest(BaseModel):
    identifier: str  # Email or username
    password: str

class ForgotPasswordRequest(BaseModel):
    email: str

class ResetPasswordRequest(BaseModel):
    email: str
    newPassword: str

class UpdateUsernameRequest(BaseModel):
    username: str

class UserResponse(BaseModel):
    id: int
    name: str
    username: Optional[str] = None
    email: str
    role: str
    permissions: list[str] = []
    is_active: bool
    is_email_verified: bool = True
    needs_username_change: bool = False
    created_at: datetime.datetime
    last_login_at: Optional[datetime.datetime] = None

class AuthResponse(BaseModel):
    token: str
    user: UserResponse


def mask_email(email: str) -> str:
    parts = email.split("@")
    if len(parts) != 2:
        return email
    name, domain = parts
    if len(name) <= 2:
        masked_name = name[0] + "***"
    else:
        masked_name = name[0] + "***" + name[-1]
    return f"{masked_name}@{domain}"


def to_user_response(user: db_models.User) -> UserResponse:
    return UserResponse(
        id=user.id,
        name=user.name,
        username=user.username,
        email=user.email,
        role=user.role,
        permissions=parse_permissions(user.permissions),
        is_active=user.is_active,
        is_email_verified=bool(user.is_email_verified),
        needs_username_change=bool(user.needs_username_change),
        created_at=user.created_at,
        last_login_at=user.last_login_at,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/check-username")
def check_username(
    username: str = Query(..., description="Username to check for availability"),
    request: Request = None,
    db: Session = Depends(get_db),
):
    client_ip = request.client.host if request and request.client else "127.0.0.1"
    check_username_rate_limit(client_ip)
    record_username_check(client_ip)

    # 1. Format & rule validation
    is_valid, msg, reason = validate_username(username)
    if not is_valid:
        return {
            "available": False,
            "reason": reason,
            "message": msg,
        }

    # 2. Database uniqueness check
    clean_lower = username.strip().lower()
    existing = db.query(db_models.User).filter(db_models.User.username_lower == clean_lower).first()
    if existing:
        return {
            "available": False,
            "reason": "taken",
            "message": "This username is already taken, try another",
        }

    return {
        "available": True,
        "reason": None,
        "message": "Username is available",
    }


@router.post("/register")
def register(
    req: RegisterRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    name = req.name.strip()
    raw_username = (req.username or "").strip()
    email = req.email.strip().lower()
    password = req.password

    if not name:
        raise HTTPException(status_code=400, detail="Name is required.")
    if not req.consent:
        raise HTTPException(status_code=400, detail="You must agree to the data storage and privacy terms to register.")

    # Validate email
    if not validate_email_format(email):
        raise HTTPException(status_code=400, detail="Please enter a valid email address.")

    # Validate password
    is_strong, p_msg = validate_password_strength(password)
    if not is_strong:
        raise HTTPException(status_code=400, detail=p_msg)

    # Validate username if provided, else generate one from email prefix
    if raw_username:
        is_valid_u, u_msg, u_reason = validate_username(raw_username)
        if not is_valid_u:
            raise HTTPException(status_code=400, detail=u_msg)
        username = raw_username
    else:
        prefix = email.split("@")[0]
        username = prefix[:20] if len(prefix) >= 3 else f"user_{prefix}"

    # Uniqueness checks
    existing_e = db.query(db_models.User).filter(db_models.User.email == email).first()
    if existing_e:
        raise HTTPException(status_code=409, detail="An account with this email already exists.")

    existing_u = db.query(db_models.User).filter(db_models.User.username_lower == username.lower()).first()
    if existing_u:
        raise HTTPException(status_code=409, detail="This username is already taken, try another.")

    try:
        user = db_models.User(
            name=name,
            username=username,
            username_lower=username.lower(),
            email=email,
            password_hash=hash_password(password),
            role="user",
            is_active=True,
            is_email_verified=True,
            token_version=1,
            permissions="[]",
            needs_username_change=False,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="An account with this username or email already exists.")

    log_activity(db, "register", user_id=user.id, detail=f"Registered account for {email}")

    # Send Welcome Email notification asynchronously via Gmail SMTP (never blocks)
    send_welcome_email(to_email=email, user_name=name)

    return {
        "success": True,
        "message": "Account created successfully. Please sign in with your email and password.",
        "email": email,
        "userId": user.id,
    }


@router.post("/login", response_model=AuthResponse)
def login(req: LoginRequest, request: Request, db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "127.0.0.1"
    check_login_rate_limit(client_ip)

    identifier = req.identifier.strip().lower()
    user = (
        db.query(db_models.User)
        .filter((db_models.User.email == identifier) | (db_models.User.username_lower == identifier))
        .first()
    )

    if user:
        check_account_lockout(user)

    if not user or not verify_password(req.password, user.password_hash):
        record_login_attempt(client_ip)
        record_failed_login(db, user)
        # Generic error message to prevent account enumeration
        raise HTTPException(status_code=401, detail="Incorrect email, username or password.")

    if not user.is_active:
        raise HTTPException(
            status_code=403,
            detail="Your account has been deactivated. Please contact an administrator.",
        )

    reset_failed_login(db, user)
    user.last_login_at = datetime.datetime.now(datetime.timezone.utc)
    db.commit()

    log_activity(db, "login", user_id=user.id, detail=f"User {user.email} logged in")

    token = create_access_token({
        "sub": str(user.id),
        "email": user.email,
        "role": user.role,
        "token_version": user.token_version,
    })

    return AuthResponse(token=token, user=to_user_response(user))


@router.post("/forgot-password")
def forgot_password(req: ForgotPasswordRequest, request: Request, db: Session = Depends(get_db)):
    email = req.email.strip().lower()
    user = db.query(db_models.User).filter(db_models.User.email == email).first()

    # Always return generic response to avoid enumeration
    return {
        "success": True,
        "message": "If an account matches that email address, you may reset your password.",
    }


@router.post("/reset-password")
def reset_password(req: ResetPasswordRequest, db: Session = Depends(get_db)):
    email = req.email.strip().lower()
    user = db.query(db_models.User).filter(db_models.User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="Account with that email address not found.")

    is_strong, p_msg = validate_password_strength(req.newPassword)
    if not is_strong:
        raise HTTPException(status_code=400, detail=p_msg)

    user.password_hash = hash_password(req.newPassword)
    user.token_version = (user.token_version or 1) + 1  # Invalidate all active sessions
    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()

    log_activity(db, "password_reset", user_id=user.id, detail=f"User {user.email} reset password")

    return {
        "success": True,
        "message": "Password reset successfully. You can now log in with your new password.",
    }


@router.patch("/username", response_model=UserResponse)
def update_username(
    req: UpdateUsernameRequest,
    current_user: db_models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    new_username = req.username.strip()
    is_valid, msg, reason = validate_username(new_username)
    if not is_valid:
        raise HTTPException(status_code=400, detail=msg)

    existing = (
        db.query(db_models.User)
        .filter(
            db_models.User.username_lower == new_username.lower(),
            db_models.User.id != current_user.id,
        )
        .first()
    )
    if existing:
        raise HTTPException(status_code=409, detail="This username is already taken, try another.")

    current_user.username = new_username
    current_user.username_lower = new_username.lower()
    current_user.needs_username_change = False
    db.commit()

    log_activity(db, "update_username", user_id=current_user.id, detail=f"User changed username to {new_username}")
    return to_user_response(current_user)


@router.get("/me", response_model=UserResponse)
def get_me(current_user: db_models.User = Depends(get_current_user)):
    return to_user_response(current_user)


@router.post("/logout")
def logout(current_user: db_models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Bump token_version to invalidate tokens
    current_user.token_version = (current_user.token_version or 1) + 1
    db.commit()
    log_activity(db, "logout", user_id=current_user.id, detail=f"User {current_user.email} logged out")
    return {"success": True, "message": "Logged out successfully."}


@router.delete("/me")
def delete_own_account(current_user: db_models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Protect last active admin
    if current_user.role in ("admin", "super_admin"):
        active_admins = (
            db.query(db_models.User)
            .filter(db_models.User.role.in_(["admin", "super_admin"]), db_models.User.is_active.is_(True))
            .count()
        )
        if active_admins <= 1:
            raise HTTPException(
                status_code=400,
                detail="Cannot delete account: You are the last active administrator.",
            )

    user_id = current_user.id
    email = current_user.email
    db.delete(current_user)
    db.commit()
    log_activity(db, "delete_account", user_id=None, detail=f"User ID {user_id} ({email}) deleted their own account")
    return {"success": True, "message": "Account and all associated scan data have been permanently deleted."}
