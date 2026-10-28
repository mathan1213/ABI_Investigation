import csv
import io
import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import func

from database import get_db
import db_models
from modules.auth_module import (
    require_admin,
    require_permission,
    check_login_rate_limit,
    record_login_attempt,
    verify_password,
    create_access_token,
    log_activity,
    parse_permissions,
)
from routers.auth import UserResponse, AuthResponse, to_user_response

router = APIRouter(prefix="/api/admin", tags=["admin"])


# ---------------------------------------------------------------------------
# Admin Auth Schemas & Endpoints
# ---------------------------------------------------------------------------

class AdminLoginRequest(BaseModel):
    identifier: str
    password: str

class UserPatchRequest(BaseModel):
    is_active: Optional[bool] = None
    role: Optional[str] = None


@router.post("/login", response_model=AuthResponse)
def admin_login(req: AdminLoginRequest, request: Request, db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "127.0.0.1"
    check_login_rate_limit(client_ip)

    identifier = req.identifier.strip().lower()
    user = (
        db.query(db_models.User)
        .filter((db_models.User.email == identifier) | (db_models.User.username_lower == identifier))
        .first()
    )

    if not user or user.role not in ("admin", "super_admin") or not verify_password(req.password, user.password_hash):
        record_login_attempt(client_ip)
        raise HTTPException(status_code=401, detail="Incorrect email, username or password.")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Your administrator account has been deactivated.")

    user.last_login_at = datetime.datetime.now(datetime.timezone.utc)
    db.commit()

    log_activity(db, "admin_login", user_id=user.id, detail=f"Admin {user.email} signed into admin portal")

    token = create_access_token({
        "sub": str(user.id),
        "email": user.email,
        "role": user.role,
        "token_version": user.token_version,
    })

    return AuthResponse(token=token, user=to_user_response(user))


# ---------------------------------------------------------------------------
# Gated Admin Endpoints (admin-only, protected by role check)
# ---------------------------------------------------------------------------

@router.get("/overview")
def get_admin_overview(
    admin_user: db_models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    now = datetime.datetime.now(datetime.timezone.utc)
    seven_days_ago = now - datetime.timedelta(days=7)
    thirty_days_ago = now - datetime.timedelta(days=30)

    total_users = db.query(func.count(db_models.User.id)).scalar() or 0
    new_users_7d = db.query(func.count(db_models.User.id)).filter(db_models.User.created_at >= seven_days_ago).scalar() or 0

    total_scans = db.query(func.count(db_models.Scan.id)).scalar() or 0
    total_files = db.query(func.count(db_models.UploadedFile.id)).scalar() or 0
    total_reports = db.query(func.count(db_models.Report.id)).scalar() or 0

    module_rows = db.query(db_models.Scan.module, func.count(db_models.Scan.id)).group_by(db_models.Scan.module).all()
    scans_per_module = {m: count for m, count in module_rows}

    risk_rows = db.query(db_models.Scan.risk_level, func.count(db_models.Scan.id)).group_by(db_models.Scan.risk_level).all()
    risk_distribution = {r.lower(): count for r, count in risk_rows}

    avg_risk = db.query(func.avg(db_models.Scan.risk_score)).scalar() or 0.0

    all_scans_30d = db.query(db_models.Scan.created_at).filter(db_models.Scan.created_at >= thirty_days_ago).all()
    day_counts: dict[str, int] = {}
    for d in range(30, -1, -1):
        day_str = (now - datetime.timedelta(days=d)).strftime("%Y-%m-%d")
        day_counts[day_str] = 0
    for s in all_scans_30d:
        if s.created_at:
            ds = s.created_at.strftime("%Y-%m-%d")
            if ds in day_counts:
                day_counts[ds] += 1

    scans_per_day = [{"date": k, "count": v} for k, v in day_counts.items()]

    return {
        "totalUsers": total_users,
        "newUsers7d": new_users_7d,
        "totalScans": total_scans,
        "totalFiles": total_files,
        "totalReports": total_reports,
        "averageRisk": round(float(avg_risk), 1),
        "scansPerModule": {
            "telegram": scans_per_module.get("telegram", 0),
            "repo": scans_per_module.get("repo", 0),
            "network": scans_per_module.get("network", 0),
        },
        "riskDistribution": {
            "low": risk_distribution.get("low", 0),
            "medium": risk_distribution.get("medium", 0),
            "high": risk_distribution.get("high", 0),
            "critical": risk_distribution.get("critical", 0),
        },
        "scansPerDay": scans_per_day,
    }


@router.get("/users")
def get_admin_users(
    search: Optional[str] = None,
    role: Optional[str] = None,
    is_active: Optional[bool] = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(15, ge=1, le=100),
    admin_user: db_models.User = Depends(require_permission("view_users")),
    db: Session = Depends(get_db),
):
    query = db.query(db_models.User)
    if search:
        s = f"%{search.strip()}%"
        query = query.filter(
            (db_models.User.name.ilike(s))
            | (db_models.User.email.ilike(s))
            | (db_models.User.username.ilike(s))
        )
    if role:
        query = query.filter(db_models.User.role == role)
    if is_active is not None:
        query = query.filter(db_models.User.is_active == is_active)

    total_count = query.count()
    users = query.order_by(db_models.User.created_at.desc()).offset((page - 1) * per_page).limit(per_page).all()

    user_ids = [u.id for u in users]

    scan_counts = dict(
        db.query(db_models.Scan.user_id, func.count(db_models.Scan.id))
        .filter(db_models.Scan.user_id.in_(user_ids))
        .group_by(db_models.Scan.user_id)
        .all()
    ) if user_ids else {}

    file_counts = dict(
        db.query(db_models.UploadedFile.user_id, func.count(db_models.UploadedFile.id))
        .filter(db_models.UploadedFile.user_id.in_(user_ids))
        .group_by(db_models.UploadedFile.user_id)
        .all()
    ) if user_ids else {}

    report_counts = dict(
        db.query(db_models.Report.user_id, func.count(db_models.Report.id))
        .filter(db_models.Report.user_id.in_(user_ids))
        .group_by(db_models.Report.user_id)
        .all()
    ) if user_ids else {}

    items = []
    for u in users:
        items.append({
            "id": u.id,
            "name": u.name,
            "username": u.username,
            "email": u.email,
            "role": u.role,
            "permissions": parse_permissions(u.permissions),
            "isActive": u.is_active,
            "createdAt": u.created_at,
            "lastLoginAt": u.last_login_at,
            "scanCount": scan_counts.get(u.id, 0),
            "fileCount": file_counts.get(u.id, 0),
            "reportCount": report_counts.get(u.id, 0),
        })

    return {
        "items": items,
        "total": total_count,
        "page": page,
        "perPage": per_page,
        "totalPages": (total_count + per_page - 1) // per_page if total_count > 0 else 1,
    }


@router.get("/users/{user_id}")
def get_user_detail(
    user_id: int,
    admin_user: db_models.User = Depends(require_permission("view_users")),
    db: Session = Depends(get_db),
):
    user = db.query(db_models.User).filter(db_models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    log_activity(db, "admin_viewed_user", user_id=admin_user.id, detail=f"Admin {admin_user.email} viewed details of user ID {user.id} ({user.email})")

    scans = db.query(db_models.Scan).filter(db_models.Scan.user_id == user.id).order_by(db_models.Scan.created_at.desc()).limit(50).all()
    reports = db.query(db_models.Report).filter(db_models.Report.user_id == user.id).order_by(db_models.Report.created_at.desc()).limit(50).all()
    uploaded_files = db.query(db_models.UploadedFile).filter(db_models.UploadedFile.user_id == user.id).order_by(db_models.UploadedFile.uploaded_at.desc()).all()
    activities = db.query(db_models.ActivityLog).filter(db_models.ActivityLog.user_id == user.id).order_by(db_models.ActivityLog.created_at.desc()).limit(30).all()

    return {
        "profile": {
            "id": user.id,
            "name": user.name,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "permissions": parse_permissions(user.permissions),
            "isActive": user.is_active,
            "createdAt": user.created_at,
            "lastLoginAt": user.last_login_at,
        },
        "files": [
            {
                "id": f.id,
                "filename": f.filename,
                "fileSize": f.file_size,
                "fileType": f.file_type,
                "module": f.module,
                "uploadedAt": f.uploaded_at,
            }
            for f in uploaded_files
        ],
        "reports": [
            {
                "id": r.id,
                "overallScore": r.overall_score,
                "overallRisk": r.overall_risk,
                "reportJson": r.report_json,
                "createdAt": r.created_at,
            }
            for r in reports
        ],
        "scans": [
            {
                "id": s.id,
                "module": s.module,
                "targetLabel": s.target_label,
                "riskScore": s.risk_score,
                "riskLevel": s.risk_level,
                "isDemo": s.is_demo,
                "createdAt": s.created_at,
                "findingsSummary": s.findings_json[:200] if s.findings_json else "",
            }
            for s in scans
        ],
        "activity": [
            {
                "id": a.id,
                "action": a.action,
                "detail": a.detail,
                "createdAt": a.created_at,
            }
            for a in activities
        ],
    }


@router.get("/files")
def get_all_uploaded_files(
    search: Optional[str] = None,
    user_id: Optional[int] = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(25, ge=1, le=100),
    admin_user: db_models.User = Depends(require_permission("view_scans")),
    db: Session = Depends(get_db),
):
    """View all files uploaded by each user."""
    query = db.query(db_models.UploadedFile, db_models.User).join(db_models.User, db_models.UploadedFile.user_id == db_models.User.id)
    if user_id:
        query = query.filter(db_models.UploadedFile.user_id == user_id)
    if search:
        s = f"%{search.strip()}%"
        query = query.filter(
            (db_models.UploadedFile.filename.ilike(s))
            | (db_models.User.name.ilike(s))
            | (db_models.User.email.ilike(s))
        )
    total_count = query.count()
    rows = query.order_by(db_models.UploadedFile.uploaded_at.desc()).offset((page - 1) * per_page).limit(per_page).all()
    items = []
    for f, u in rows:
        items.append({
            "id": f.id,
            "userId": u.id,
            "userName": u.name,
            "userEmail": u.email,
            "filename": f.filename,
            "fileSize": f.file_size,
            "fileType": f.file_type,
            "module": f.module,
            "uploadedAt": f.uploaded_at,
        })
    return {
        "items": items,
        "total": total_count,
        "page": page,
        "perPage": per_page,
        "totalPages": (total_count + per_page - 1) // per_page if total_count > 0 else 1,
    }


@router.get("/reports")
def get_all_user_reports(
    search: Optional[str] = None,
    user_id: Optional[int] = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(25, ge=1, le=100),
    admin_user: db_models.User = Depends(require_permission("view_reports")),
    db: Session = Depends(get_db),
):
    """View all reports submitted by each user."""
    query = db.query(db_models.Report, db_models.User).join(db_models.User, db_models.Report.user_id == db_models.User.id)
    if user_id:
        query = query.filter(db_models.Report.user_id == user_id)
    if search:
        s = f"%{search.strip()}%"
        query = query.filter(
            (db_models.User.name.ilike(s))
            | (db_models.User.email.ilike(s))
            | (db_models.Report.overall_risk.ilike(s))
        )
    total_count = query.count()
    rows = query.order_by(db_models.Report.created_at.desc()).offset((page - 1) * per_page).limit(per_page).all()
    items = []
    for r, u in rows:
        items.append({
            "id": r.id,
            "userId": u.id,
            "userName": u.name,
            "userEmail": u.email,
            "overallScore": r.overall_score,
            "overallRisk": r.overall_risk,
            "reportJson": r.report_json,
            "createdAt": r.created_at,
        })
    return {
        "items": items,
        "total": total_count,
        "page": page,
        "perPage": per_page,
        "totalPages": (total_count + per_page - 1) // per_page if total_count > 0 else 1,
    }


@router.patch("/users/{user_id}")
def update_user(
    user_id: int,
    patch: UserPatchRequest,
    admin_user: db_models.User = Depends(require_permission("disable_users")),
    db: Session = Depends(get_db),
):
    user = db.query(db_models.User).filter(db_models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.id == admin_user.id and patch.is_active is False:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own administrator account.")

    # Protect last active admin
    if user.role in ("admin", "super_admin") and patch.is_active is False:
        active_admins = (
            db.query(db_models.User)
            .filter(db_models.User.role.in_(["admin", "super_admin"]), db_models.User.is_active.is_(True))
            .count()
        )
        if active_admins <= 1:
            raise HTTPException(status_code=400, detail="Cannot disable the last active administrator.")

    if patch.is_active is not None:
        user.is_active = patch.is_active
        if not patch.is_active:
            user.token_version = (user.token_version or 1) + 1

    db.commit()
    log_activity(db, "admin_updated_user", user_id=admin_user.id, detail=f"Admin {admin_user.email} updated user {user.email} (active={user.is_active})")

    return {
        "success": True,
        "user": {
            "id": user.id,
            "name": user.name,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "isActive": user.is_active,
        },
    }


@router.delete("/users/{user_id}")
def delete_user(
    user_id: int,
    admin_user: db_models.User = Depends(require_permission("delete_users")),
    db: Session = Depends(get_db),
):
    user = db.query(db_models.User).filter(db_models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.id == admin_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own administrator account.")

    if user.role in ("admin", "super_admin"):
        active_admins = (
            db.query(db_models.User)
            .filter(db_models.User.role.in_(["admin", "super_admin"]), db_models.User.is_active.is_(True))
            .count()
        )
        if active_admins <= 1:
            raise HTTPException(status_code=400, detail="Cannot delete the last active administrator.")

    user_email = user.email
    db.delete(user)
    db.commit()
    log_activity(db, "admin_deleted_user", user_id=admin_user.id, detail=f"Admin {admin_user.email} deleted user {user_email} (ID {user_id})")

    return {"success": True, "message": f"User {user_email} and all associated data deleted."}


@router.get("/activity")
def get_activity_logs(
    user_id: Optional[int] = None,
    action: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    admin_user: db_models.User = Depends(require_permission("view_activity")),
    db: Session = Depends(get_db),
):
    query = db.query(db_models.ActivityLog)
    if user_id is not None:
        query = query.filter(db_models.ActivityLog.user_id == user_id)
    if action:
        query = query.filter(db_models.ActivityLog.action == action)

    total = query.count()
    logs = query.order_by(db_models.ActivityLog.created_at.desc()).offset(offset).limit(limit).all()

    return {
        "items": [
            {
                "id": log.id,
                "userId": log.user_id,
                "action": log.action,
                "detail": log.detail,
                "createdAt": log.created_at,
            }
            for log in logs
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/export/users.csv")
def export_users_csv(
    admin_user: db_models.User = Depends(require_permission("export_data")),
    db: Session = Depends(get_db),
):
    users = db.query(db_models.User).order_by(db_models.User.id.asc()).all()
    user_ids = [u.id for u in users]

    scan_counts = dict(
        db.query(db_models.Scan.user_id, func.count(db_models.Scan.id))
        .filter(db_models.Scan.user_id.in_(user_ids))
        .group_by(db_models.Scan.user_id)
        .all()
    ) if user_ids else {}

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "name", "username", "email", "role", "is_active", "created_at", "last_login_at", "scan_count"])

    for u in users:
        writer.writerow([
            u.id,
            u.name,
            u.username or "",
            u.email,
            u.role,
            u.is_active,
            u.created_at.isoformat() if u.created_at else "",
            u.last_login_at.isoformat() if u.last_login_at else "",
            scan_counts.get(u.id, 0),
        ])

    csv_data = output.getvalue()
    log_activity(db, "export_users_csv", user_id=admin_user.id, detail=f"Admin {admin_user.email} exported users.csv")

    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=users.csv"},
    )
