import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    username = Column(String(50), nullable=True)  # display casing
    username_lower = Column(String(50), unique=True, index=True, nullable=True)  # lowercase unique
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), default="user", nullable=False)  # "user", "admin", "super_admin"
    is_active = Column(Boolean, default=True, nullable=False)
    is_email_verified = Column(Boolean, default=False, nullable=False)
    token_version = Column(Integer, default=1, nullable=False)
    permissions = Column(Text, default="[]", nullable=False)  # JSON array string
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)
    needs_username_change = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)
    last_login_at = Column(DateTime, nullable=True)

    scans = relationship("Scan", back_populates="user", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="user", cascade="all, delete-orphan")
    otps = relationship("EmailOtp", back_populates="user", cascade="all, delete-orphan")

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True)
    module = Column(String(50), nullable=False)  # "telegram", "repo", "network"
    target_label = Column(String(255), nullable=False)
    risk_score = Column(Integer, default=0, nullable=False)
    risk_level = Column(String(20), default="low", nullable=False)
    is_demo = Column(Boolean, default=False, nullable=False)
    findings_json = Column(Text, nullable=False)  # Sanitized findings only
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False, index=True)

    user = relationship("User", back_populates="scans")

class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True)
    overall_score = Column(Integer, default=0, nullable=False)
    overall_risk = Column(String(20), default="low", nullable=False)
    report_json = Column(Text, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False, index=True)

    user = relationship("User", back_populates="reports")

class EmailOtp(Base):
    __tablename__ = "email_otps"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True)
    email = Column(String(255), nullable=False, index=True)
    purpose = Column(String(50), nullable=False, index=True)  # "register", "login", "admin_login", "password_reset"
    code_hash = Column(String(255), nullable=False)
    expires_at = Column(DateTime, nullable=False, index=True)
    attempts = Column(Integer, default=0, nullable=False)
    used = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False, index=True)

    user = relationship("User", back_populates="otps")

class ActivityLog(Base):
    __tablename__ = "activity_log"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, nullable=True, index=True)
    action = Column(String(50), nullable=False, index=True)
    detail = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False, index=True)

class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    actor_id = Column(Integer, nullable=True, index=True)
    actor_email = Column(String(255), nullable=True)
    target_id = Column(Integer, nullable=True, index=True)
    target_email = Column(String(255), nullable=True)
    action = Column(String(100), nullable=False, index=True)
    before_state = Column(Text, nullable=True)
    after_state = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False, index=True)
