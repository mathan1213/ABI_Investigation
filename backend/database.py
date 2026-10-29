import re
import os
import shutil
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

def _backup_db_file_if_needed():
    """Safely creates a .bak backup of the SQLite database file before applying migrations."""
    if settings.DATABASE_URL.startswith("sqlite:///"):
        rel_path = settings.DATABASE_URL.replace("sqlite:///", "")
        if not os.path.isabs(rel_path):
            base_dir = os.path.dirname(__file__)
            db_path = os.path.normpath(os.path.join(base_dir, rel_path))
        else:
            db_path = rel_path
        if os.path.exists(db_path) and os.path.getsize(db_path) > 0:
            bak_path = f"{db_path}.bak"
            try:
                shutil.copy2(db_path, bak_path)
            except Exception as e:
                print(f"[DB BACKUP WARNING] Could not backup db file: {e}")

def _sanitize_username(prefix: str) -> str:
    sanitized = re.sub(r"[^a-zA-Z0-9_.]", "_", prefix)
    if not re.match(r"^[a-zA-Z]", sanitized):
        sanitized = "u_" + sanitized
    if len(sanitized) < 3:
        sanitized = sanitized.ljust(3, "0")
    return sanitized[:20]

def init_db():
    _backup_db_file_if_needed()
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
                # Mark existing users verified upon migration so nobody is locked out
                conn.execute(text("UPDATE users SET is_email_verified = 1"))
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
            if "welcome_email_sent" not in columns:
                conn.execute(text("ALTER TABLE users ADD COLUMN welcome_email_sent BOOLEAN DEFAULT 0"))
            if "welcome_email_sent_at" not in columns:
                conn.execute(text("ALTER TABLE users ADD COLUMN welcome_email_sent_at DATETIME"))
            if "welcome_email_error" not in columns:
                conn.execute(text("ALTER TABLE users ADD COLUMN welcome_email_error VARCHAR(255)"))

            # Ensure all administrators and super administrators are always verified
            conn.execute(text("UPDATE users SET is_email_verified = 1 WHERE role IN ('admin', 'super_admin')"))

    if "uploaded_files" in inspector.get_table_names():
        uf_cols = {c["name"] for c in inspector.get_columns("uploaded_files")}
        with engine.begin() as conn:
            if "stored_filename" not in uf_cols:
                conn.execute(text("ALTER TABLE uploaded_files ADD COLUMN stored_filename VARCHAR(255)"))
                conn.execute(text("CREATE INDEX IF NOT EXISTS idx_uploaded_files_stored_filename ON uploaded_files (stored_filename)"))
            if "file_path" not in uf_cols:
                conn.execute(text("ALTER TABLE uploaded_files ADD COLUMN file_path VARCHAR(500)"))
            if "user_id" not in uf_cols:
                conn.execute(text("ALTER TABLE uploaded_files ADD COLUMN user_id INTEGER"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_uploaded_files_user_id ON uploaded_files (user_id)"))

    if "scans" in inspector.get_table_names():
        s_cols = {c["name"] for c in inspector.get_columns("scans")}
        with engine.begin() as conn:
            if "user_id" not in s_cols:
                conn.execute(text("ALTER TABLE scans ADD COLUMN user_id INTEGER"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans (user_id)"))

    if "reports" in inspector.get_table_names():
        r_cols = {c["name"] for c in inspector.get_columns("reports")}
        with engine.begin() as conn:
            if "user_id" not in r_cols:
                conn.execute(text("ALTER TABLE reports ADD COLUMN user_id INTEGER"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_reports_user_id ON reports (user_id)"))

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
