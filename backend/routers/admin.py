import csv
import io
import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import func

from database import get_db
import db_models
from modules.auth_module import require_admin, log_activity

router = APIRouter(prefix="/api/admin", tags=["admin"], dependencies=[Depends(require_admin)])

class UserPatchRequest(BaseModel):
    is_active: Optional[bool] = None
    role: Optional[str] = None


@router.get("/overview")
def get_admin_overview(db: Session = Depends(get_db)):
    now = datetime.datetime.now(datetime.timezone.utc)
    seven_days_ago = now - datetime.timedelta(days=7)
    thirty_days_ago = now - datetime.timedelta(days=30)

    total_users = db.query(func.count(db_models.User.id)).scalar() or 0
    new_users_7d = db.query(func.count(db_models.User.id)).filter(db_models.User.created_at >= seven_days_ago).scalar() or 0

    # Scans counts
    total_scans = db.query(func.count(db_models.Scan.id)).scalar() or 0
    demo_scans = db.query(func.count(db_models.Scan.id)).filter(db_models.Scan.is_demo.is_(True)).scalar() or 0
    real_scans = db.query(func.count(db_models.Scan.id)).filter(db_models.Scan.is_demo.is_(False)).scalar() or 0

    # Scans per module
    module_rows = db.query(db_models.Scan.module, func.count(db_models.Scan.id)).group_by(db_models.Scan.module).all()
    scans_per_module = {m: count for m, count in module_rows}

    # Risk level distribution
    risk_rows = db.query(db_models.Scan.risk_level, func.count(db_models.Scan.id)).group_by(db_models.Scan.risk_level).all()
    risk_distribution = {r.lower(): count for r, count in risk_rows}

    # Average risk score
    avg_risk = db.query(func.avg(db_models.Scan.risk_score)).scalar() or 0.0

    # Scans per day for last 30 days
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
        "realScans": real_scans,
        "demoScans": demo_scans,
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
        "scansPerDay": scans_per_day
    }


@router.get("/users")
def get_admin_users(
    search: Optional[str] = None,
    role: Optional[str] = None,
    is_active: Optional[bool] = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(15, ge=1, le=100),
    db: Session = Depends(get_db)
):
    query = db.query(db_models.User)
    if search:
        s = f"%{search.strip()}%"
        query = query.filter((db_models.User.name.ilike(s)) | (db_models.User.email.ilike(s)))
    if role:
        query = query.filter(db_models.User.role == role)
    if is_active is not None:
        query = query.filter(db_models.User.is_active == is_active)

    total_count = query.count()
    users = query.order_by(db_models.User.created_at.desc()).offset((page - 1) * per_page).limit(per_page).all()

    user_ids = [u.id for u in users]
    scan_counts_rows = db.query(db_models.Scan.user_id, func.count(db_models.Scan.id)).filter(
        db_models.Scan.user_id.in_(user_ids)
    ).group_by(db_models.Scan.user_id).all() if user_ids else []
    counts_map = {uid: c for uid, c in scan_counts_rows}

    items = []
    for u in users:
        items.append({
            "id": u.id,
            "name": u.name,
            "email": u.email,
            "role": u.role,
            "isActive": u.is_active,
            "createdAt": u.created_at,
            "lastLoginAt": u.last_login_at,
            "scanCount": counts_map.get(u.id, 0)
        })

    return {
        "items": items,
        "total": total_count,
        "page": page,
        "perPage": per_page,
        "totalPages": (total_count + per_page - 1) // per_page if total_count > 0 else 1
    }


@router.get("/users/{user_id}")
def get_user_detail(
    user_id: int,
    admin_user: db_models.User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    user = db.query(db_models.User).filter(db_models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # MUST log admin_viewed_user as requested in Part D.4
    log_activity(db, "admin_viewed_user", user_id=admin_user.id, detail=f"Admin {admin_user.email} viewed details of user ID {user.id} ({user.email})")

    scans = db.query(db_models.Scan).filter(db_models.Scan.user_id == user.id).order_by(db_models.Scan.created_at.desc()).limit(50).all()
    reports = db.query(db_models.Report).filter(db_models.Report.user_id == user.id).order_by(db_models.Report.created_at.desc()).limit(20).all()
    activities = db.query(db_models.ActivityLog).filter(db_models.ActivityLog.user_id == user.id).order_by(db_models.ActivityLog.created_at.desc()).limit(30).all()

    return {
        "profile": {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "role": user.role,
            "isActive": user.is_active,
            "createdAt": user.created_at,
            "lastLoginAt": user.last_login_at
        },
        "scans": [
            {
                "id": s.id,
                "module": s.module,
                "targetLabel": s.target_label,
                "riskScore": s.risk_score,
                "riskLevel": s.risk_level,
                "isDemo": s.is_demo,
                "createdAt": s.created_at,
                "findingsSummary": s.findings_json[:200] if s.findings_json else ""
            }
            for s in scans
        ],
        "reports": [
            {
                "id": r.id,
                "overallScore": r.overall_score,
                "overallRisk": r.overall_risk,
                "createdAt": r.created_at
            }
            for r in reports
        ],
        "activity": [
            {
                "id": a.id,
                "action": a.action,
                "detail": a.detail,
                "createdAt": a.created_at
            }
            for a in activities
        ]
    }


@router.patch("/users/{user_id}")
def update_user(
    user_id: int,
    patch: UserPatchRequest,
    admin_user: db_models.User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    user = db.query(db_models.User).filter(db_models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.id == admin_user.id and patch.is_active is False:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own administrator account.")

    if patch.is_active is not None:
        user.is_active = patch.is_active
    if patch.role is not None and patch.role in ("user", "admin"):
        user.role = patch.role

    db.commit()
    log_activity(db, "admin_updated_user", user_id=admin_user.id, detail=f"Admin {admin_user.email} updated user {user.email} (active={user.is_active}, role={user.role})")

    return {
        "success": True,
        "user": {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "role": user.role,
            "isActive": user.is_active
        }
    }


@router.delete("/users/{user_id}")
def delete_user(
    user_id: int,
    admin_user: db_models.User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    user = db.query(db_models.User).filter(db_models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.id == admin_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own administrator account.")

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
    db: Session = Depends(get_db)
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
                "createdAt": log.created_at
            }
            for log in logs
        ],
        "total": total,
        "limit": limit,
        "offset": offset
    }


@router.get("/export/users.csv")
def export_users_csv(db: Session = Depends(get_db)):
    users = db.query(db_models.User).order_by(db_models.User.id.asc()).all()
    user_ids = [u.id for u in users]

    scan_counts_rows = db.query(db_models.Scan.user_id, func.count(db_models.Scan.id)).filter(
        db_models.Scan.user_id.in_(user_ids)
    ).group_by(db_models.Scan.user_id).all() if user_ids else []
    counts_map = {uid: c for uid, c in scan_counts_rows}

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "name", "email", "role", "is_active", "created_at", "last_login_at", "scan_count"])

    for u in users:
        writer.writerow([
            u.id,
            u.name,
            u.email,
            u.role,
            u.is_active,
            u.created_at.isoformat() if u.created_at else "",
            u.last_login_at.isoformat() if u.last_login_at else "",
            counts_map.get(u.id, 0)
        ])

    csv_data = output.getvalue()
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=users.csv"}
    )
