import json
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from database import get_db
import db_models
from modules.auth_module import get_current_user, has_permission, log_activity

router = APIRouter(prefix="/api/scans", tags=["User Scans"])


@router.get("/history", summary="List current user's scan history")
def list_user_scans(
    module: Optional[str] = Query(None, description="Filter by module (telegram, repo, network)"),
    page: int = Query(1, ge=1),
    per_page: int = Query(25, ge=1, le=100),
    current_user: db_models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Returns scan history strictly owned by the authenticated user.
    Never exposes other users' scans.
    """
    query = db.query(db_models.Scan).filter(db_models.Scan.user_id == current_user.id)
    if isinstance(module, str) and module:
        query = query.filter(db_models.Scan.module == module)

    page_val = page if isinstance(page, int) else 1
    per_page_val = per_page if isinstance(per_page, int) else 25

    total_count = query.count()
    records = (
        query.order_by(db_models.Scan.created_at.desc())
        .offset((page_val - 1) * per_page_val)
        .limit(per_page_val)
        .all()
    )

    items = []
    for s in records:
        try:
            findings = json.loads(s.findings_json)
        except Exception:
            findings = []

        items.append({
            "id": s.id,
            "module": s.module,
            "targetLabel": s.target_label,
            "riskScore": s.risk_score,
            "riskLevel": s.risk_level,
            "createdAt": s.created_at,
            "findingsCount": len(findings),
            "findings": findings,
        })

    return {
        "items": items,
        "total": total_count,
        "page": page_val,
        "perPage": per_page_val,
        "totalPages": (total_count + per_page_val - 1) // per_page_val if total_count > 0 else 1,
    }


@router.get("/{scan_id}", summary="Get a specific scan owned by the user")
def get_user_scan(
    scan_id: int,
    current_user: db_models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Retrieves a single scan if owned by the authenticated user (or authorized admin).
    Verifies ownership to prevent IDOR attacks.
    """
    scan = db.query(db_models.Scan).filter(db_models.Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    is_owner = scan.user_id == current_user.id
    is_authorized_admin = (
        current_user.role in ("admin", "super_admin") and has_permission(current_user, "view_scans")
    )
    if not is_owner and not is_authorized_admin:
        # Return 404 to prevent ID enumeration
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    try:
        findings = json.loads(scan.findings_json)
    except Exception:
        findings = []

    return {
        "id": scan.id,
        "userId": scan.user_id,
        "module": scan.module,
        "targetLabel": scan.target_label,
        "riskScore": scan.risk_score,
        "riskLevel": scan.risk_level,
        "findings": findings,
        "createdAt": scan.created_at,
    }


@router.delete("/{scan_id}", summary="Delete an authenticated user's scan")
def delete_user_scan(
    scan_id: int,
    current_user: db_models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Deletes a scan owned by the authenticated user.
    """
    scan = db.query(db_models.Scan).filter(db_models.Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    is_owner = scan.user_id == current_user.id
    is_authorized_admin = (
        current_user.role in ("admin", "super_admin") and has_permission(current_user, "delete_users")
    )
    if not is_owner and not is_authorized_admin:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    db.delete(scan)
    db.commit()

    log_activity(
        db,
        action="delete_scan",
        user_id=current_user.id,
        detail=f"Deleted scan ID {scan_id} ({scan.module}: {scan.target_label})",
    )

    return {"success": True, "message": "Scan deleted successfully."}
