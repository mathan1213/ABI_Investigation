import os
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from database import get_db
import db_models
from modules.auth_module import get_current_user, has_permission, log_activity
from modules.file_storage import resolve_user_file_path, delete_user_stored_file

router = APIRouter(prefix="/api/files", tags=["User Files"])


@router.get("", summary="List current user's uploaded files")
def list_user_files(
    module: Optional[str] = Query(None, description="Filter by module"),
    page: int = Query(1, ge=1),
    per_page: int = Query(25, ge=1, le=100),
    current_user: db_models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Returns files uploaded strictly by the authenticated user.
    Never exposes other users' files.
    """
    query = db.query(db_models.UploadedFile).filter(db_models.UploadedFile.user_id == current_user.id)
    if isinstance(module, str) and module:
        query = query.filter(db_models.UploadedFile.module == module)

    page_val = page if isinstance(page, int) else 1
    per_page_val = per_page if isinstance(per_page, int) else 25

    total_count = query.count()
    records = (
        query.order_by(db_models.UploadedFile.uploaded_at.desc())
        .offset((page_val - 1) * per_page_val)
        .limit(per_page_val)
        .all()
    )

    items = [
        {
            "id": f.id,
            "filename": f.filename,
            "fileSize": f.file_size,
            "fileType": f.file_type,
            "module": f.module,
            "uploadedAt": f.uploaded_at,
        }
        for f in records
    ]

    return {
        "items": items,
        "total": total_count,
        "page": page_val,
        "perPage": per_page_val,
        "totalPages": (total_count + per_page_val - 1) // per_page_val if total_count > 0 else 1,
    }


@router.get("/{file_id}/download", summary="Download an authenticated user's uploaded file")
def download_user_file(
    file_id: int,
    current_user: db_models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Securely serves a file if the authenticated user owns it (or if user is authorized admin).
    Verifies ownership to prevent Insecure Direct Object References (IDOR).
    """
    file_record = db.query(db_models.UploadedFile).filter(db_models.UploadedFile.id == file_id).first()
    if not file_record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found.")

    # Strict ownership check: owner or authorized admin
    is_owner = file_record.user_id == current_user.id
    is_authorized_admin = (
        current_user.role in ("admin", "super_admin") and has_permission(current_user, "view_scans")
    )
    if not is_owner and not is_authorized_admin:
        # Return 404 to avoid disclosing existence of other users' files
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found.")

    file_path = resolve_user_file_path(file_record.user_id, file_record.stored_filename)
    if not file_path or not file_path.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File content not found on disk.")

    log_activity(
        db,
        action="download_file",
        user_id=current_user.id,
        detail=f"Downloaded file '{file_record.filename}' (ID: {file_record.id})",
    )

    return FileResponse(
        path=str(file_path),
        filename=file_record.filename,
        media_type=file_record.file_type or "application/octet-stream",
    )


@router.delete("/{file_id}", summary="Delete an authenticated user's uploaded file")
def delete_user_file(
    file_id: int,
    current_user: db_models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Deletes an uploaded file owned by the authenticated user.
    """
    file_record = db.query(db_models.UploadedFile).filter(db_models.UploadedFile.id == file_id).first()
    if not file_record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found.")

    is_owner = file_record.user_id == current_user.id
    is_authorized_admin = (
        current_user.role in ("admin", "super_admin") and has_permission(current_user, "delete_users")
    )
    if not is_owner and not is_authorized_admin:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found.")

    delete_user_stored_file(file_record.user_id, file_record.stored_filename)
    db.delete(file_record)
    db.commit()

    log_activity(
        db,
        action="delete_file",
        user_id=current_user.id,
        detail=f"Deleted file '{file_record.filename}' (ID: {file_id})",
    )

    return {"success": True, "message": "File deleted successfully."}
