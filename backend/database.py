import re
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker
from config import settings

engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {},
    echo=False
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def _sanitize_username(prefix: str) -> str:
    sanitized = re.sub(r"[^a-zA-Z0-9_.]", "_", prefix)
    if not re.match(r"^[a-zA-Z]", sanitized):
        sanitized = "u_" + sanitized
    if len(sanitized) < 3:
        sanitized = sanitized.ljust(3, "0")
    return sanitized[:20]

def init_db():
    import db_models  # noqa: F401
    Base.metadata.create_all(bind=engine)

    # SQLite column migrations
    inspector = inspect(engine)
    if "users" in inspector.get_table_names():
        columns = {c["name"] for c in inspector.get_columns("users")}
        with engine.begin() as conn:
            if "username" not in columns:
                conn.execute(text("ALTER TABLE users ADD COLUMN username VARCHAR(50)"))
            if "username_lower" not in columns:
                conn.execute(text("ALTER TABLE users ADD COLUMN username_lower VARCHAR(50)"))
                conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_lower ON users (username_lower)"))
            if "is_email_verified" not in columns:
                conn.execute(text("ALTER TABLE users ADD COLUMN is_email_verified BOOLEAN DEFAULT 0"))
            if "token_version" not in columns:
                conn.execute(text("ALTER TABLE users ADD COLUMN token_version INTEGER DEFAULT 1"))
            if "permissions" not in columns:
                conn.execute(text("ALTER TABLE users ADD COLUMN permissions TEXT DEFAULT '[]'"))
            if "failed_login_attempts" not in columns:
                conn.execute(text("ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0"))
            if "locked_until" not in columns:
                conn.execute(text("ALTER TABLE users ADD COLUMN locked_until DATETIME"))
            if "needs_username_change" not in columns:
                conn.execute(text("ALTER TABLE users ADD COLUMN needs_username_change BOOLEAN DEFAULT 0"))

    # Auto-generate unique username for existing users without username
    db = SessionLocal()
    try:
        users = db.query(db_models.User).filter(
            (db_models.User.username_lower.is_(None)) | (db_models.User.username_lower == "")
        ).all()
        for u in users:
            prefix = u.email.split("@")[0] if u.email else f"user_{u.id}"
            sanitized = _sanitize_username(prefix)
            candidate = sanitized
            counter = 1
            while db.query(db_models.User).filter(db_models.User.username_lower == candidate.lower(), db_models.User.id != u.id).first():
                suffix = f"_{counter}"
                candidate = sanitized[:20 - len(suffix)] + suffix
                counter += 1

            u.username = candidate
            u.username_lower = candidate.lower()
            u.is_email_verified = True
            u.needs_username_change = True
            if u.role in ("admin", "super_admin") or (settings.ADMIN_EMAIL and u.email.lower() == settings.ADMIN_EMAIL.lower()):
                u.role = "admin"
                u.needs_username_change = False
                u.permissions = "[]"
        db.commit()
    except Exception as e:
        db.rollback()
    finally:
        db.close()
