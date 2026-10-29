import re
import time
import json
import secrets
import hashlib
import hmac
import datetime
from collections import defaultdict
from typing import Optional

import bcrypt
import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from sqlalchemy import func

from config import settings
from database import get_db
import db_models

security_bearer = HTTPBearer(auto_error=False)

# In-memory IP tracking: client_ip -> list of timestamps
_login_attempts: dict[str, list[float]] = defaultdict(list)
_username_checks: dict[str, list[float]] = defaultdict(list)

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
USERNAME_REGEX = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.]{2,19}$")

RESERVED_USERNAMES = {
    "admin",
    "administrator",
    "root",
    "support",
    "system",
    "null",
    "owner",
    "moderator",
    "superadmin",
}

COMMON_PASSWORDS = {
    "password",
    "password123",
    "12345678",
    "123456789",
    "qwerty123",
    "admin123",
    "welcome1",
    "letmein1",
    "iloveyou",
    "monkey123",
    "superman1",
    "trustno1",
    "sunshine1",
    "master123",
    "dragon123",
    "football",
    "baseball",
}

ALL_PERMISSIONS = [
    "view_users",
    "disable_users",
    "delete_users",
    "view_scans",
    "view_reports",
    "export_data",
    "view_activity",
    "manage_admins",
]


# ---------------------------------------------------------------------------
# Validation Helpers
# ---------------------------------------------------------------------------

def validate_username(username: str) -> tuple[bool, str, Optional[str]]:
    """
    Checks if username is 3-20 chars, letters/digits/underscore/dot only, starts with a letter.
    Also blocks reserved names.
    Returns: (is_valid, message, reason) where reason in ('invalid', 'reserved', None)
    """
    if not username or not isinstance(username, str):
        return False, "Username is required.", "invalid"

    trimmed = username.strip()
    if not USERNAME_REGEX.match(trimmed):
        return (
            False,
            "Username must be 3-20 characters, start with a letter, and contain only letters, numbers, underscores, or dots.",
            "invalid",
        )

    if trimmed.lower() in RESERVED_USERNAMES:
        return False, "This username is reserved by the system. Please choose another.", "reserved"

    return True, "Username is valid.", None


def validate_email_format(email: str) -> bool:
    return bool(email and EMAIL_REGEX.match(email.strip()))


def validate_password_strength(password: str) -> tuple[bool, str]:
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if password.lower() in COMMON_PASSWORDS:
        return False, "This password is too common and easily guessed. Please choose a stronger password."
    return True, ""


# ---------------------------------------------------------------------------
# Cryptographic & Hash Functions
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    pwd_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False


# ---------------------------------------------------------------------------
# JWT Access Tokens
# ---------------------------------------------------------------------------

def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None) -> str:
    to_encode = data.copy()
    now = datetime.datetime.now(datetime.timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + datetime.timedelta(hours=settings.JWT_EXPIRATION_HOURS)
    to_encode.update({"exp": expire, "iat": now})
    return jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> dict:
    try:
        return jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
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


# ---------------------------------------------------------------------------
# Rate Limiting
# ---------------------------------------------------------------------------

def check_login_rate_limit(client_ip: str) -> None:
    now = time.time()
    valid_attempts = [t for t in _login_attempts[client_ip] if now - t < 60]
    _login_attempts[client_ip] = valid_attempts

    if len(valid_attempts) >= settings.AUTH_LOGIN_RATE_LIMIT:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please wait 1 minute before trying again.",
        )


def record_login_attempt(client_ip: str) -> None:
    _login_attempts[client_ip].append(time.time())


def check_username_rate_limit(client_ip: str) -> None:
    now = time.time()
    valid_checks = [t for t in _username_checks[client_ip] if now - t < 60]
    _username_checks[client_ip] = valid_checks

    if len(valid_checks) >= 30:  # 30 per minute
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many username checks. Please wait a minute.",
        )


def record_username_check(client_ip: str) -> None:
    _username_checks[client_ip].append(time.time())


# ---------------------------------------------------------------------------
# Account Lockout & Cleanup Helpers
# ---------------------------------------------------------------------------

def check_account_lockout(user: db_models.User) -> None:
    now = datetime.datetime.now(datetime.timezone.utc)
    if user.locked_until:
        lock = user.locked_until
        if lock.tzinfo is None:
            lock = lock.replace(tzinfo=datetime.timezone.utc)
        if lock > now:
            minutes_left = max(1, int((lock - now).total_seconds() / 60))
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Account is temporarily locked due to too many failed attempts. Try again in {minutes_left} minutes.",
            )


def record_failed_login(db: Session, user: Optional[db_models.User]) -> None:
    if not user:
        return
    now = datetime.datetime.now(datetime.timezone.utc)
    user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
    if user.failed_login_attempts >= settings.MAX_FAILED_LOGINS:
        user.locked_until = now + datetime.timedelta(minutes=settings.LOCKOUT_MINUTES)
    db.commit()


def reset_failed_login(db: Session, user: db_models.User) -> None:
    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()


# ---------------------------------------------------------------------------
# Current User Dependency
# ---------------------------------------------------------------------------

def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer),
    db: Session = Depends(get_db),
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

    # Check token version for logout-everywhere / password change / promotion invalidation
    token_ver = payload.get("token_version")
    if token_ver is not None and token_ver != user.token_version:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has been invalidated. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


# ---------------------------------------------------------------------------
# Permissions & Roles
# ---------------------------------------------------------------------------

def parse_permissions(perms_str: Optional[str]) -> list[str]:
    if not perms_str:
        return []
    try:
        res = json.loads(perms_str)
        return res if isinstance(res, list) else []
    except Exception:
        return []


def has_permission(user: db_models.User, perm: str) -> bool:
    if user.role == "super_admin":
        return True
    if user.role == "admin":
        user_perms = parse_permissions(user.permissions)
        # Administrators have all permissions by default unless explicitly restricted
        if not user_perms or "*" in user_perms:
            return True
        return perm in user_perms
    return False


def require_permission(perm: str):
    def dependency(current_user: db_models.User = Depends(get_current_user)) -> db_models.User:
        if current_user.role not in ("admin", "super_admin"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access forbidden: Administrator privilege required.",
            )
        if not has_permission(current_user, perm):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access forbidden: Missing required permission '{perm}'.",
            )
        return current_user
    return dependency


def require_super_admin(current_user: db_models.User = Depends(get_current_user)) -> db_models.User:
    if current_user.role != "super_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: Super administrator privilege required.",
        )
    return current_user


def require_admin(current_user: db_models.User = Depends(get_current_user)) -> db_models.User:
    if current_user.role not in ("admin", "super_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: Administrator privilege required.",
        )
    return current_user


# ---------------------------------------------------------------------------
# Logging & Auditing
# ---------------------------------------------------------------------------

def log_activity(db: Session, action: str, user_id: Optional[int] = None, detail: Optional[str] = None):
    try:
        activity = db_models.ActivityLog(
            user_id=user_id,
            action=action,
            detail=detail[:500] if detail else None,
        )
        db.add(activity)
        db.commit()
    except Exception:
        db.rollback()


def log_audit(
    db: Session,
    action: str,
    actor: Optional[db_models.User] = None,
    target: Optional[db_models.User] = None,
    before: Optional[dict] = None,
    after: Optional[dict] = None,
):
    try:
        entry = db_models.AuditLog(
            actor_id=actor.id if actor else None,
            actor_email=actor.email if actor else None,
            target_id=target.id if target else None,
            target_email=target.email if target else None,
            action=action,
            before_state=json.dumps(before) if before else None,
            after_state=json.dumps(after) if after else None,
            created_at=datetime.datetime.now(datetime.timezone.utc),
        )
        db.add(entry)
        db.commit()
    except Exception:
        db.rollback()


# ---------------------------------------------------------------------------
# Initial Admin Seeder
# ---------------------------------------------------------------------------

def seed_admin_if_needed(db: Session):
    admin_emails: list[str] = []
    if settings.ADMIN_EMAIL:
        admin_emails.append(settings.ADMIN_EMAIL.strip().lower())
    for extra_email in ["63796174@gmail.com", "mathan63796174@gmail.com"]:
        if extra_email not in admin_emails:
            admin_emails.append(extra_email)

    for a_email in admin_emails:
        u = db.query(db_models.User).filter(db_models.User.email == a_email).first()
        if u:
            u.role = "admin"
            u.permissions = json.dumps(ALL_PERMISSIONS)
            u.is_active = True
            u.is_email_verified = True
            db.commit()
        elif a_email == settings.ADMIN_EMAIL.strip().lower() or a_email == "63796174@gmail.com":
            prefix = a_email.split("@")[0].replace(".", "_")
            base_u = prefix[:15] or "admin"
            cand_u = base_u
            idx = 1
            while db.query(db_models.User).filter(db_models.User.username_lower == cand_u.lower()).first():
                cand_u = f"{base_u}_{idx}"
                idx += 1
            admin_user = db_models.User(
                name="System Administrator",
                username=cand_u,
                username_lower=cand_u.lower(),
                email=a_email,
                password_hash=hash_password(settings.ADMIN_PASSWORD or "Mathan@1213"),
                role="admin",
                is_active=True,
                is_email_verified=True,
                token_version=1,
                permissions=json.dumps(ALL_PERMISSIONS),
                needs_username_change=False,
            )
            db.add(admin_user)
            db.commit()
            log_activity(db, "register", user_id=admin_user.id, detail=f"Seeded administrator {a_email}")

    # Ensure all administrators have full permissions populated
    all_admins = db.query(db_models.User).filter(db_models.User.role.in_(["admin", "super_admin"])).all()
    for adm in all_admins:
        if not adm.permissions or adm.permissions == "[]":
            adm.permissions = json.dumps(ALL_PERMISSIONS)
    db.commit()
