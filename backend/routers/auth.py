import datetime
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db
import db_models
from modules.auth_module import (
    check_login_rate_limit,
    record_login_attempt,
    validate_email_format,
    validate_password_strength,
    hash_password,
    verify_password,
    create_access_token,
    get_current_user,
    log_activity
)

router = APIRouter(prefix="/api/auth", tags=["auth"])

class RegisterRequest(BaseModel):
    name: str
    email: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str

class UserResponse(BaseModel):
    id: int
    name: str
    email: str
    role: str
    is_active: bool
    created_at: datetime.datetime
    last_login_at: datetime.datetime | None = None

class AuthResponse(BaseModel):
    token: str
    user: UserResponse


@router.post("/register", response_model=AuthResponse)
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    name = req.name.strip()
    email = req.email.strip().lower()
    password = req.password

    if not name:
        raise HTTPException(status_code=400, detail="Name is required.")
    if not validate_email_format(email):
        raise HTTPException(status_code=400, detail="Please enter a valid email address.")
    
    is_strong, msg = validate_password_strength(password)
    if not is_strong:
        raise HTTPException(status_code=400, detail=msg)

    existing = db.query(db_models.User).filter(db_models.User.email == email).first()
    if existing:
        raise HTTPException(status_code=400, detail="An account with this email already exists.")

    user = db_models.User(
        name=name,
        email=email,
        password_hash=hash_password(password),
        role="user",
        is_active=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    log_activity(db, "register", user_id=user.id, detail=f"Registered user {email}")

    token = create_access_token({"sub": str(user.id), "email": user.email, "role": user.role})
    return AuthResponse(
        token=token,
        user=UserResponse(
            id=user.id,
            name=user.name,
            email=user.email,
            role=user.role,
            is_active=user.is_active,
            created_at=user.created_at,
            last_login_at=user.last_login_at
        )
    )


@router.post("/login", response_model=AuthResponse)
def login(req: LoginRequest, request: Request, db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "127.0.0.1"
    check_login_rate_limit(client_ip)
    record_login_attempt(client_ip)

    email = req.email.strip().lower()
    user = db.query(db_models.User).filter(db_models.User.email == email).first()
    if not user or not verify_password(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not user.is_active:
        raise HTTPException(
            status_code=403,
            detail="Your account has been deactivated. Please contact an administrator."
        )

    user.last_login_at = datetime.datetime.now(datetime.timezone.utc)
    db.commit()

    log_activity(db, "login", user_id=user.id, detail=f"User {email} logged in from {client_ip}")

    token = create_access_token({"sub": str(user.id), "email": user.email, "role": user.role})
    return AuthResponse(
        token=token,
        user=UserResponse(
            id=user.id,
            name=user.name,
            email=user.email,
            role=user.role,
            is_active=user.is_active,
            created_at=user.created_at,
            last_login_at=user.last_login_at
        )
    )


@router.get("/me", response_model=UserResponse)
def get_me(current_user: db_models.User = Depends(get_current_user)):
    return UserResponse(
        id=current_user.id,
        name=current_user.name,
        email=current_user.email,
        role=current_user.role,
        is_active=current_user.is_active,
        created_at=current_user.created_at,
        last_login_at=current_user.last_login_at
    )


@router.post("/logout")
def logout(current_user: db_models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    log_activity(db, "logout", user_id=current_user.id, detail=f"User {current_user.email} logged out")
    return {"success": True, "message": "Logged out successfully."}


@router.delete("/me")
def delete_own_account(current_user: db_models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    user_id = current_user.id
    email = current_user.email
    db.delete(current_user)
    db.commit()
    log_activity(db, "delete_account", user_id=None, detail=f"User ID {user_id} ({email}) deleted their own account and scan history")
    return {"success": True, "message": "Account and all associated scan data have been permanently deleted."}
