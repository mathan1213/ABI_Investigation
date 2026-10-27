import json
import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db
import db_models
from modules.auth_module import (
    require_super_admin,
    ALL_PERMISSIONS,
    parse_permissions,
    log_audit,
    log_activity,
)
from routers.auth import UserResponse, to_user_response

router = APIRouter(prefix="/api/superadmin", tags=["superadmin"], dependencies=[Depends(require_super_admin)])


class CreateAdminRequest(BaseModel):
    userId: Optional[int] = None
    email: Optional[str] = None
    permissions: list[str]

class UpdatePermissionsRequest(BaseModel):
    permissions: list[str]

class UpdateRoleRequest(BaseModel):
    role: str
    permissions: Optional[list[str]] = None


@router.get("/admins")
def list_admins(
    db: Session = Depends(get_db),
    current_super: db_models.User = Depends(require_super_admin),
):
    admins = (
        db.query(db_models.User)
        .filter(db_models.User.role.in_(["admin", "super_admin"]))
        .order_by(db_models.User.role.desc(), db_models.User.created_at.asc())
        .all()
    )
    return {
        "items": [
            {
                "id": a.id,
                "name": a.name,
                "username": a.username,
                "email": a.email,
                "role": a.role,
                "permissions": ALL_PERMISSIONS if a.role == "super_admin" else parse_permissions(a.permissions),
                "isActive": a.is_active,
                "isEmailVerified": a.is_email_verified,
                "createdAt": a.created_at,
                "lastLoginAt": a.last_login_at,
            }
            for a in admins
        ],
        "availablePermissions": ALL_PERMISSIONS,
    }


@router.get("/eligible-users")
def get_eligible_users(
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_super: db_models.User = Depends(require_super_admin),
):
    query = db.query(db_models.User).filter(
        db_models.User.role == "user",
        db_models.User.is_active.is_(True),
        db_models.User.is_email_verified.is_(True),
    )
    if search:
        s = f"%{search.strip()}%"
        query = query.filter(
            (db_models.User.name.ilike(s))
            | (db_models.User.email.ilike(s))
            | (db_models.User.username.ilike(s))
        )
    users = query.order_by(db_models.User.name.asc()).limit(50).all()
    return [
        {
            "id": u.id,
            "name": u.name,
            "username": u.username,
            "email": u.email,
        }
        for u in users
    ]


@router.post("/admins")
def create_admin(
    req: CreateAdminRequest,
    db: Session = Depends(get_db),
    current_super: db_models.User = Depends(require_super_admin),
):
    # Validate permissions
    for p in req.permissions:
        if p not in ALL_PERMISSIONS:
            raise HTTPException(status_code=400, detail=f"Invalid permission: '{p}'")

    target: Optional[db_models.User] = None
    if req.userId:
        target = db.query(db_models.User).filter(db_models.User.id == req.userId).first()
    elif req.email:
        target = db.query(db_models.User).filter(db_models.User.email == req.email.strip().lower()).first()

    if not target:
        raise HTTPException(status_code=404, detail="User not found. User must have an existing verified account.")

    if not target.is_email_verified:
        raise HTTPException(status_code=400, detail="User must have a verified email before being granted admin privileges.")

    if target.role == "super_admin":
        raise HTTPException(status_code=400, detail="User is already a super administrator.")

    before_state = {
        "role": target.role,
        "permissions": parse_permissions(target.permissions),
    }

    target.role = "admin"
    target.permissions = json.dumps(req.permissions)
    target.token_version = (target.token_version or 1) + 1  # Invalidate old tokens so new rights apply
    db.commit()

    after_state = {
        "role": target.role,
        "permissions": req.permissions,
    }

    log_audit(
        db,
        action="create_admin",
        actor=current_super,
        target=target,
        before=before_state,
        after=after_state,
    )
    log_activity(db, "superadmin_promoted_admin", user_id=current_super.id, detail=f"Promoted {target.email} to admin")

    return {
        "success": True,
        "message": f"User {target.email} promoted to admin.",
        "admin": {
            "id": target.id,
            "name": target.name,
            "username": target.username,
            "email": target.email,
            "role": target.role,
            "permissions": req.permissions,
        },
    }


@router.patch("/admins/{admin_id}/permissions")
def update_admin_permissions(
    admin_id: int,
    req: UpdatePermissionsRequest,
    db: Session = Depends(get_db),
    current_super: db_models.User = Depends(require_super_admin),
):
    target = db.query(db_models.User).filter(db_models.User.id == admin_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Administrator not found.")

    if target.id == current_super.id:
        raise HTTPException(status_code=400, detail="Cannot edit your own administrator permissions.")

    if target.role == "super_admin":
        raise HTTPException(status_code=400, detail="Cannot modify permissions of a super administrator.")

    # Validate permissions
    for p in req.permissions:
        if p not in ALL_PERMISSIONS:
            raise HTTPException(status_code=400, detail=f"Invalid permission: '{p}'")

    before_state = {
        "role": target.role,
        "permissions": parse_permissions(target.permissions),
    }

    target.permissions = json.dumps(req.permissions)
    target.token_version = (target.token_version or 1) + 1  # Bumps token version so new rights apply on next request
    db.commit()

    after_state = {
        "role": target.role,
        "permissions": req.permissions,
    }

    log_audit(
        db,
        action="update_permissions",
        actor=current_super,
        target=target,
        before=before_state,
        after=after_state,
    )
    log_activity(db, "superadmin_updated_permissions", user_id=current_super.id, detail=f"Updated permissions for admin {target.email}")

    return {
        "success": True,
        "message": f"Permissions updated for {target.email}.",
        "permissions": req.permissions,
    }


@router.patch("/users/{user_id}/role")
def update_user_role(
    user_id: int,
    req: UpdateRoleRequest,
    db: Session = Depends(get_db),
    current_super: db_models.User = Depends(require_super_admin),
):
    target = db.query(db_models.User).filter(db_models.User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found.")

    if target.id == current_super.id:
        raise HTTPException(status_code=400, detail="Cannot change your own role.")

    new_role = req.role.strip().lower()
    if new_role not in ("user", "admin", "super_admin"):
        raise HTTPException(status_code=400, detail="Invalid role. Choose 'user', 'admin', or 'super_admin'.")

    # Protection: Prevent demoting the last active super_admin
    if target.role == "super_admin" and new_role != "super_admin":
        active_supers = (
            db.query(db_models.User)
            .filter(db_models.User.role == "super_admin", db_models.User.is_active.is_(True))
            .count()
        )
        if active_supers <= 1:
            raise HTTPException(
                status_code=400,
                detail="Cannot demote the last active super administrator.",
            )

    before_state = {
        "role": target.role,
        "permissions": parse_permissions(target.permissions),
    }

    target.role = new_role
    if new_role == "admin":
        perms = req.permissions if req.permissions is not None else ["view_users", "view_scans", "view_reports"]
        # Validate
        for p in perms:
            if p not in ALL_PERMISSIONS:
                raise HTTPException(status_code=400, detail=f"Invalid permission: '{p}'")
        target.permissions = json.dumps(perms)
    elif new_role == "super_admin":
        target.permissions = "[]"
    else:  # user
        target.permissions = "[]"

    target.token_version = (target.token_version or 1) + 1
    db.commit()

    after_state = {
        "role": target.role,
        "permissions": parse_permissions(target.permissions),
    }

    log_audit(
        db,
        action="update_role",
        actor=current_super,
        target=target,
        before=before_state,
        after=after_state,
    )
    log_activity(db, "superadmin_updated_role", user_id=current_super.id, detail=f"Changed role of {target.email} to {new_role}")

    return {
        "success": True,
        "message": f"Role updated to {new_role} for {target.email}.",
        "user": {
            "id": target.id,
            "name": target.name,
            "username": target.username,
            "email": target.email,
            "role": target.role,
            "permissions": parse_permissions(target.permissions),
        },
    }


@router.delete("/admins/{admin_id}")
def remove_admin(
    admin_id: int,
    db: Session = Depends(get_db),
    current_super: db_models.User = Depends(require_super_admin),
):
    target = db.query(db_models.User).filter(db_models.User.id == admin_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Administrator not found.")

    if target.id == current_super.id:
        raise HTTPException(status_code=400, detail="Cannot remove your own administrator access.")

    if target.role == "super_admin":
        active_supers = (
            db.query(db_models.User)
            .filter(db_models.User.role == "super_admin", db_models.User.is_active.is_(True))
            .count()
        )
        if active_supers <= 1:
            raise HTTPException(
                status_code=400,
                detail="Cannot remove the last active super administrator.",
            )

    before_state = {
        "role": target.role,
        "permissions": parse_permissions(target.permissions),
    }

    target.role = "user"
    target.permissions = "[]"
    target.token_version = (target.token_version or 1) + 1
    db.commit()

    after_state = {
        "role": "user",
        "permissions": [],
    }

    log_audit(
        db,
        action="remove_admin",
        actor=current_super,
        target=target,
        before=before_state,
        after=after_state,
    )
    log_activity(db, "superadmin_demoted_admin", user_id=current_super.id, detail=f"Demoted admin {target.email} to normal user")

    return {
        "success": True,
        "message": f"Administrator privileges removed for {target.email}. User has been returned to normal user status.",
    }


@router.get("/audit")
def get_audit_logs(
    page: int = Query(1, ge=1),
    per_page: int = Query(30, ge=1, le=100),
    action: Optional[str] = None,
    db: Session = Depends(get_db),
    current_super: db_models.User = Depends(require_super_admin),
):
    query = db.query(db_models.AuditLog)
    if action:
        query = query.filter(db_models.AuditLog.action == action)

    total = query.count()
    items = (
        query.order_by(db_models.AuditLog.created_at.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )

    formatted = []
    for item in items:
        try:
            b = json.loads(item.before_state) if item.before_state else None
        except Exception:
            b = None
        try:
            a = json.loads(item.after_state) if item.after_state else None
        except Exception:
            a = None

        formatted.append({
            "id": item.id,
            "actorId": item.actor_id,
            "actorEmail": item.actor_email,
            "targetId": item.target_id,
            "targetEmail": item.target_email,
            "action": item.action,
            "beforeState": b,
            "afterState": a,
            "createdAt": item.created_at,
        })

    return {
        "items": formatted,
        "total": total,
        "page": page,
        "perPage": per_page,
        "totalPages": (total + per_page - 1) // per_page if total > 0 else 1,
    }
