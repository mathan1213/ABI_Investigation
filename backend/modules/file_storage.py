import os
import re
import uuid
from pathlib import Path
from typing import Optional, Tuple

# Base directory for uploads, kept strictly private inside the backend
BASE_UPLOAD_DIR = Path(__file__).resolve().parent.parent / "uploads"


def get_user_upload_dir(user_id: int) -> Path:
    """
    Returns the secure, user-isolated upload directory Path for a given immutable user ID.
    Directory structure: uploads/user_{user_id}/
    """
    if not isinstance(user_id, int) or user_id <= 0:
        raise ValueError("Invalid user_id for secure file storage")

    user_dir = (BASE_UPLOAD_DIR / f"user_{user_id}").resolve()
    # Path traversal protection
    if not str(user_dir).startswith(str(BASE_UPLOAD_DIR.resolve())):
        raise ValueError("Path traversal attempt detected in user directory resolution")

    user_dir.mkdir(parents=True, exist_ok=True)
    return user_dir


def sanitize_filename(filename: str) -> str:
    """
    Sanitizes user-provided filename by removing path separators and dangerous characters.
    """
    base_name = os.path.basename(filename).strip()
    # Replace non-alphanumeric (except standard safe extensions) with underscore
    clean_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", base_name)
    clean_name = clean_name.strip("._")
    if not clean_name:
        clean_name = "upload.bin"
    return clean_name[:120]


def save_user_uploaded_file(user_id: int, original_filename: str, content: bytes) -> Tuple[str, str, int]:
    """
    Securely saves file bytes into the user's private upload directory.
    Returns:
        (stored_filename, relative_file_path, file_size)
    """
    user_dir = get_user_upload_dir(user_id)
    clean_name = sanitize_filename(original_filename)
    unique_prefix = uuid.uuid4().hex[:12]
    stored_filename = f"{unique_prefix}_{clean_name}"

    target_path = (user_dir / stored_filename).resolve()

    # Strict path traversal check
    if not str(target_path).startswith(str(user_dir)):
        raise ValueError("Path traversal attempt detected in target file path")

    with open(target_path, "wb") as f:
        f.write(content)

    file_size = len(content)
    # Store relative path e.g. "uploads/user_1/abc_file.txt"
    relative_path = f"uploads/user_{user_id}/{stored_filename}"
    return stored_filename, relative_path, file_size


def resolve_user_file_path(user_id: int, stored_filename: str) -> Optional[Path]:
    """
    Safely resolves the Path to a user's stored file, ensuring no path traversal.
    Returns Path if file exists, None otherwise.
    """
    if not stored_filename:
        return None

    user_dir = get_user_upload_dir(user_id)
    # Strip any directory components from stored_filename
    safe_name = os.path.basename(stored_filename)
    target_path = (user_dir / safe_name).resolve()

    # Ensure target_path is strictly within user_dir
    if not str(target_path).startswith(str(user_dir)):
        return None

    if target_path.is_file():
        return target_path
    return None


def delete_user_stored_file(user_id: int, stored_filename: str) -> bool:
    """
    Safely deletes a user's file from disk.
    """
    file_path = resolve_user_file_path(user_id, stored_filename)
    if file_path and file_path.is_file():
        try:
            file_path.unlink()
            return True
        except OSError:
            return False
    return False
