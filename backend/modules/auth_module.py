import re
import time
import datetime
from collections import defaultdict
from typing import Optional

import bcrypt
import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from config import settings
from database import get_db
import db_models

security_bearer = HTTPBearer(auto_error=False)

# In-memory rate limiting for login: client_ip -> list of timestamps
_login_attempts: dict[str, list[float]] = defaultdict(list)

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


def validate_email_format(email: str) -> bool:
    return bool(email and EMAIL_REGEX.match(email.strip()))


def validate_password_strength(password: str) -> tuple[bool, str]:
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters long."
    return True, ""


def hash_password(password: str) -> str:
    pwd_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8")
        )
    except Exception:
        return False


def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None) -> str:
    to_encode = data.copy()
    now = datetime.datetime.now(datetime.timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + datetime.timedelta(hours=settings.JWT_EXPIRATION_HOURS)
    to_encode.update({"exp": expire, "iat": now})
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session token has expired. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )


def check_login_rate_limit(client_ip: str) -> None:
    now = time.time()
    attempts = _login_attempts[client_ip]
    # Keep attempts from last 60 seconds
    valid_attempts = [t for t in attempts if now - t < 60]
    _login_attempts[client_ip] = valid_attempts

    if len(valid_attempts) >= settings.AUTH_LOGIN_RATE_LIMIT:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please wait 1 minute before trying again."
        )


def record_login_attempt(client_ip: str) -> None:
    _login_attempts[client_ip].append(time.time())


def log_activity(db: Session, action: str, user_id: Optional[int] = None, detail: Optional[str] = None):
    try:
        activity = db_models.ActivityLog(
            user_id=user_id,
            action=action,
            detail=detail[:500] if detail else None
        )
        db.add(activity)
        db.commit()
    except Exception:
        db.rollback()


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer),
    db: Session = Depends(get_db)
) -> db_models.User:
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please log in.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    payload = decode_access_token(token)
    user_id = payload.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.query(db_models.User).filter(db_models.User.id == int(user_id)).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or account was deleted.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account has been disabled. Please contact the administrator.",
        )
    return user


def require_admin(current_user: db_models.User = Depends(get_current_user)) -> db_models.User:
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: Admin privilege required."
        )
    return current_user


def seed_admin_if_needed(db: Session):
    existing_admin = db.query(db_models.User).filter(db_models.User.role == "admin").first()
    if not existing_admin and settings.ADMIN_EMAIL and settings.ADMIN_PASSWORD:
        admin_user = db_models.User(
            name="System Administrator",
            email=settings.ADMIN_EMAIL.strip().lower(),
            password_hash=hash_password(settings.ADMIN_PASSWORD),
            role="admin",
            is_active=True
        )
        db.add(admin_user)
        db.commit()
        log_activity(db, "register", user_id=admin_user.id, detail="Seeded initial system administrator")
