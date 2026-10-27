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
    create_and_send_otp,
    verify_otp_attempt,
    check_account_lockout,
    record_failed_login,
    reset_failed_login,
    cleanup_unverified_accounts,
    parse_permissions,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    name: str
    username: str
    email: str
    password: str
    consent: bool = False

class VerifyEmailRequest(BaseModel):
    email: str
    code: str

class ResendOtpRequest(BaseModel):
    email: str
    purpose: str = "register"

class LoginRequest(BaseModel):
    identifier: str  # Email or username
    password: str

class VerifyLoginOtpRequest(BaseModel):
    userId: int
    code: str

class ForgotPasswordRequest(BaseModel):
    email: str

class ResetPasswordRequest(BaseModel):
    email: str
    code: str
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
    is_email_verified: bool
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
        is_email_verified=user.is_email_verified,
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
    client_ip = request.client.host if request.client else "127.0.0.1"

    # Purge old unverified accounts (>24h)
    cleanup_unverified_accounts(db)

    name = req.name.strip()
    username = req.username.strip()
    email = req.email.strip().lower()
    password = req.password

    if not name:
        raise HTTPException(status_code=400, detail="Name is required.")
    if not req.consent:
        raise HTTPException(status_code=400, detail="You must agree to the data storage and privacy terms to register.")

    # Validate username
    is_valid_u, u_msg, u_reason = validate_username(username)
    if not is_valid_u:
        raise HTTPException(status_code=400, detail=u_msg)

    # Validate email
    if not validate_email_format(email):
        raise HTTPException(status_code=400, detail="Please enter a valid email address.")

    # Validate password
    is_strong, p_msg = validate_password_strength(password)
    if not is_strong:
        raise HTTPException(status_code=400, detail=p_msg)

    # Uniqueness checks
    existing_u = db.query(db_models.User).filter(db_models.User.username_lower == username.lower()).first()
    if existing_u:
        raise HTTPException(status_code=409, detail="This username is already taken, try another.")

    existing_e = db.query(db_models.User).filter(db_models.User.email == email).first()
    if existing_e:
        raise HTTPException(status_code=409, detail="An account with this email already exists.")

    try:
        user = db_models.User(
            name=name,
            username=username,
            username_lower=username.lower(),
            email=email,
            password_hash=hash_password(password),
            role="user",
            is_active=False,
            is_email_verified=False,
            token_version=1,
            permissions="[]",
            needs_username_change=False,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="This username or email is already taken. Please try another.")

    log_activity(db, "register_pending", user_id=user.id, detail=f"Registered pending verification for {email}")

    # Send registration OTP
    create_and_send_otp(db, email=email, purpose="register", user_id=user.id, client_ip=client_ip)

    return {
        "success": True,
        "message": f"Verification code sent to {mask_email(email)}.",
        "email": email,
        "userId": user.id,
    }


@router.post("/verify-email", response_model=AuthResponse)
def verify_email(req: VerifyEmailRequest, db: Session = Depends(get_db)):
    email = req.email.strip().lower()
    user = db.query(db_models.User).filter(db_models.User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="Account not found. Please register first.")

    verified, msg = verify_otp_attempt(db, email=email, purpose="register", input_code=req.code)
    if not verified:
        raise HTTPException(status_code=400, detail=msg)

    user.is_email_verified = True
    user.is_active = True
    user.last_login_at = datetime.datetime.now(datetime.timezone.utc)
    db.commit()

    log_activity(db, "verify_email", user_id=user.id, detail=f"User {email} verified email and activated account")

    token = create_access_token({
        "sub": str(user.id),
        "email": user.email,
        "role": user.role,
        "token_version": user.token_version,
    })

    return AuthResponse(token=token, user=to_user_response(user))


@router.post("/resend-otp")
def resend_otp(req: ResendOtpRequest, request: Request, db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "127.0.0.1"
    email = req.email.strip().lower()
    user = db.query(db_models.User).filter(db_models.User.email == email).first()

    # For login / password_reset, if user not found, don't leak information
    if not user and req.purpose in ("login", "admin_login", "password_reset"):
        return {"success": True, "message": "If an account exists, a new verification code has been sent."}

    user_id = user.id if user else None
    create_and_send_otp(db, email=email, purpose=req.purpose, user_id=user_id, client_ip=client_ip)
    return {"success": True, "message": "A new verification code has been sent."}


@router.post("/login")
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
        # Always return the exact same generic error
        raise HTTPException(status_code=401, detail="Incorrect email, username or password.")

    if not user.is_email_verified:
        raise HTTPException(
            status_code=403,
            detail="Your email is not verified. Please complete email verification before logging in.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=403,
            detail="Your account has been deactivated. Please contact an administrator.",
        )

    reset_failed_login(db, user)

    # Two-step login: send OTP
    create_and_send_otp(db, email=user.email, purpose="login", user_id=user.id, client_ip=client_ip)

    return {
        "requiresOtp": True,
        "userId": user.id,
        "emailMasked": mask_email(user.email),
        "message": f"Verification code sent to {mask_email(user.email)}.",
    }


@router.post("/verify-login-otp", response_model=AuthResponse)
def verify_login_otp(req: VerifyLoginOtpRequest, db: Session = Depends(get_db)):
    user = db.query(db_models.User).filter(db_models.User.id == req.userId).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid login session. Please sign in again.")

    verified, msg = verify_otp_attempt(db, email=user.email, purpose="login", input_code=req.code)
    if not verified:
        raise HTTPException(status_code=400, detail=msg)

    user.last_login_at = datetime.datetime.now(datetime.timezone.utc)
    db.commit()

    log_activity(db, "login", user_id=user.id, detail=f"User {user.email} completed 2-step login")

    token = create_access_token({
        "sub": str(user.id),
        "email": user.email,
        "role": user.role,
        "token_version": user.token_version,
    })

    return AuthResponse(token=token, user=to_user_response(user))


@router.post("/forgot-password")
def forgot_password(req: ForgotPasswordRequest, request: Request, db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "127.0.0.1"
    email = req.email.strip().lower()
    user = db.query(db_models.User).filter(db_models.User.email == email).first()

    if user and user.is_active:
        try:
            create_and_send_otp(db, email=email, purpose="password_reset", user_id=user.id, client_ip=client_ip)
        except HTTPException:
            pass  # Rate limits handled gracefully

    # Always return generic success message
    return {
        "success": True,
        "message": "If an account matches that email address, a password reset code has been sent.",
    }


@router.post("/reset-password")
def reset_password(req: ResetPasswordRequest, db: Session = Depends(get_db)):
    email = req.email.strip().lower()
    user = db.query(db_models.User).filter(db_models.User.email == email).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid password reset request.")

    is_strong, p_msg = validate_password_strength(req.newPassword)
    if not is_strong:
        raise HTTPException(status_code=400, detail=p_msg)

    verified, msg = verify_otp_attempt(db, email=email, purpose="password_reset", input_code=req.code)
    if not verified:
        raise HTTPException(status_code=400, detail=msg)

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
    # Protect last active super_admin
    if current_user.role == "super_admin":
        active_supers = (
            db.query(db_models.User)
            .filter(db_models.User.role == "super_admin", db_models.User.is_active.is_(True))
            .count()
        )
        if active_supers <= 1:
            raise HTTPException(
                status_code=400,
                detail="Cannot delete account: You are the last active super administrator.",
            )

    user_id = current_user.id
    email = current_user.email
    db.delete(current_user)
    db.commit()
    log_activity(db, "delete_account", user_id=None, detail=f"User ID {user_id} ({email}) deleted their own account")
    return {"success": True, "message": "Account and all associated scan data have been permanently deleted."}
