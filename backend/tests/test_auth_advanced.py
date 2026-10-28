import json
import pytest
from httpx import AsyncClient, ASGITransport
import bcrypt
from unittest.mock import patch

from main import app
from database import SessionLocal
import db_models
from modules.auth_module import (
    get_current_user,
    create_access_token,
    hash_password,
    ALL_PERMISSIONS,
)


@pytest.fixture
def clean_db():
    db = SessionLocal()
    try:
        db.query(db_models.UploadedFile).delete()
        db.query(db_models.AuditLog).delete()
        db.query(db_models.ActivityLog).delete()
        db.query(db_models.Report).delete()
        db.query(db_models.Scan).delete()
        db.query(db_models.User).delete()
        db.commit()
    finally:
        db.close()


@pytest.mark.asyncio
async def test_check_username_rules(clean_db):
    app.dependency_overrides.pop(get_current_user, None)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Valid username
        r = await ac.get("/api/auth/check-username?username=cyber_hero99")
        assert r.status_code == 200
        assert r.json()["available"] is True

        # Too short (< 3)
        r = await ac.get("/api/auth/check-username?username=ab")
        assert r.status_code == 200
        assert r.json()["available"] is False
        assert r.json()["reason"] == "invalid"

        # Does not start with a letter
        r = await ac.get("/api/auth/check-username?username=1hero")
        assert r.status_code == 200
        assert r.json()["available"] is False
        assert r.json()["reason"] == "invalid"

        # Invalid characters
        r = await ac.get("/api/auth/check-username?username=hero@world!")
        assert r.status_code == 200
        assert r.json()["available"] is False
        assert r.json()["reason"] == "invalid"

        # Reserved names
        for res_name in ["admin", "Administrator", "root", "support", "system", "null", "owner", "moderator", "superadmin"]:
            r = await ac.get(f"/api/auth/check-username?username={res_name}")
            assert r.status_code == 200
            assert r.json()["available"] is False
            assert r.json()["reason"] == "reserved"


@pytest.mark.asyncio
async def test_username_uniqueness_case_insensitive_and_409(clean_db):
    app.dependency_overrides.pop(get_current_user, None)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Register user with mixed case
        r1 = await ac.post("/api/auth/register", json={
            "name": "David Miller",
            "username": "David_Miller",
            "email": "david@test.com",
            "password": "Password123!",
            "consent": True
        })
        assert r1.status_code == 200

        # Check availability with lowercase
        r_chk = await ac.get("/api/auth/check-username?username=david_miller")
        assert r_chk.status_code == 200
        assert r_chk.json()["available"] is False
        assert r_chk.json()["reason"] == "taken"

        # Attempt to register with same username in all lowercase
        r2 = await ac.post("/api/auth/register", json={
            "name": "David Two",
            "username": "david_miller",
            "email": "david2@test.com",
            "password": "Password123!",
            "consent": True
        })
        assert r2.status_code == 409


@pytest.mark.asyncio
async def test_welcome_email_and_instant_login(clean_db):
    app.dependency_overrides.pop(get_current_user, None)
    with patch("routers.auth.send_welcome_email") as mock_email:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            # 1. Register account
            r = await ac.post("/api/auth/register", json={
                "name": "Emma Watson",
                "username": "emma_w",
                "email": "emma@test.com",
                "password": "StrongPassword123!",
                "consent": True
            })
            assert r.status_code == 200
            mock_email.assert_called_once_with(to_email="emma@test.com", user_name="Emma Watson")

            # 2. Account is directly active and email verified in DB
            db = SessionLocal()
            user_in_db = db.query(db_models.User).filter(db_models.User.email == "emma@test.com").first()
            assert user_in_db is not None
            assert user_in_db.is_active is True
            assert user_in_db.is_email_verified is True
            assert user_in_db.role == "user"
            db.close()

            # 3. Direct login with email + password immediately succeeds without any OTP!
            login_res = await ac.post("/api/auth/login", json={
                "identifier": "emma@test.com",
                "password": "StrongPassword123!"
            })
            assert login_res.status_code == 200
            login_data = login_res.json()
            assert "token" in login_data
            assert login_data["user"]["email"] == "emma@test.com"
            assert login_data["user"]["name"] == "Emma Watson"

            # 4. Direct login with username + password also succeeds
            login_user_res = await ac.post("/api/auth/login", json={
                "identifier": "emma_w",
                "password": "StrongPassword123!"
            })
            assert login_user_res.status_code == 200
            assert "token" in login_user_res.json()


@pytest.mark.asyncio
async def test_login_account_lockout_after_failed_attempts(clean_db):
    app.dependency_overrides.pop(get_current_user, None)
    db = SessionLocal()
    user = db_models.User(
        name="Lockout Target",
        username="lockout_user",
        username_lower="lockout_user",
        email="lockout@test.com",
        password_hash=hash_password("Password123!"),
        role="user",
        is_active=True,
        is_email_verified=True,
        token_version=1,
    )
    db.add(user)
    db.commit()
    db.close()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Submit 10 wrong password attempts
        for _ in range(10):
            res_fail = await ac.post("/api/auth/login", json={
                "identifier": "lockout_user",
                "password": "WrongPassword!"
            })
            assert res_fail.status_code in (401, 429)

        # 11th attempt should trigger account lockout (429 or 401 indicating locked)
        res_locked = await ac.post("/api/auth/login", json={
            "identifier": "lockout_user",
            "password": "Password123!"
        })
        assert res_locked.status_code in (401, 429)
        detail = res_locked.json()["detail"].lower()
        assert "locked" in detail or "too many" in detail


@pytest.mark.asyncio
async def test_permissions_enforcement_and_superadmin(clean_db):
    app.dependency_overrides.pop(get_current_user, None)
    db = SessionLocal()

    # 1. Admin with only view_users permission
    view_admin = db_models.User(
        name="Viewer Admin",
        username="viewer_admin",
        username_lower="viewer_admin",
        email="viewer@test.com",
        password_hash="hash",
        role="admin",
        permissions=json.dumps(["view_users"]),
        is_active=True,
        is_email_verified=True,
        token_version=1
    )

    # 2. Super admin
    super_admin = db_models.User(
        name="Super Admin",
        username="super_admin",
        username_lower="super_admin",
        email="super@test.com",
        password_hash="hash",
        role="super_admin",
        permissions="[]",
        is_active=True,
        is_email_verified=True,
        token_version=1
    )

    # 3. Normal user target
    target = db_models.User(
        name="Target User",
        username="target_user",
        username_lower="target_user",
        email="target@test.com",
        password_hash="hash",
        role="user",
        is_active=True,
        is_email_verified=True,
        token_version=1
    )

    db.add_all([view_admin, super_admin, target])
    db.commit()
    for u in [view_admin, super_admin, target]:
        db.refresh(u)

    view_token = create_access_token({"sub": str(view_admin.id), "email": view_admin.email, "role": "admin", "token_version": 1})
    super_token = create_access_token({"sub": str(super_admin.id), "email": super_admin.email, "role": "super_admin", "token_version": 1})
    db.close()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Viewer admin CAN view users
        res_view = await ac.get("/api/admin/users", headers={"Authorization": f"Bearer {view_token}"})
        assert res_view.status_code == 200

        # Viewer admin CANNOT export data (missing export_data permission) -> 403
        res_exp = await ac.get("/api/admin/export/users.csv", headers={"Authorization": f"Bearer {view_token}"})
        assert res_exp.status_code == 403
        assert "export_data" in res_exp.json()["detail"]

        # Viewer admin CANNOT disable users (missing disable_users permission) -> 403
        res_dis = await ac.patch(f"/api/admin/users/{target.id}", headers={"Authorization": f"Bearer {view_token}"}, json={"is_active": False})
        assert res_dis.status_code == 403

        # Super admin CAN do everything implicitly
        res_super_exp = await ac.get("/api/admin/export/users.csv", headers={"Authorization": f"Bearer {super_token}"})
        assert res_super_exp.status_code == 200

        res_super_dis = await ac.patch(f"/api/admin/users/{target.id}", headers={"Authorization": f"Bearer {super_token}"}, json={"is_active": False})
        assert res_super_dis.status_code == 200


@pytest.mark.asyncio
async def test_superadmin_management_and_audit_log(clean_db):
    app.dependency_overrides.pop(get_current_user, None)
    db = SessionLocal()

    super_admin = db_models.User(
        name="Chief Super",
        username="chief_super",
        username_lower="chief_super",
        email="chief@test.com",
        password_hash="hash",
        role="super_admin",
        is_active=True,
        is_email_verified=True,
        token_version=1
    )

    verified_user = db_models.User(
        name="Candidate Admin",
        username="candidate_admin",
        username_lower="candidate_admin",
        email="candidate@test.com",
        password_hash="hash",
        role="user",
        is_active=True,
        is_email_verified=True,
        token_version=1
    )

    db.add_all([super_admin, verified_user])
    db.commit()
    db.refresh(super_admin)
    db.refresh(verified_user)
    super_token = create_access_token({"sub": str(super_admin.id), "email": super_admin.email, "role": "super_admin", "token_version": 1})
    db.close()

    headers = {"Authorization": f"Bearer {super_token}"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. Super admin promotes user to admin with granular permissions
        res_create = await ac.post("/api/superadmin/admins", headers=headers, json={
            "userId": verified_user.id,
            "permissions": ["view_users", "view_scans"]
        })
        assert res_create.status_code == 200
        assert res_create.json()["admin"]["role"] == "admin"
        assert res_create.json()["admin"]["permissions"] == ["view_users", "view_scans"]

        # 2. Check audit log row created
        res_audit = await ac.get("/api/superadmin/audit", headers=headers)
        assert res_audit.status_code == 200
        assert len(res_audit.json()["items"]) >= 1
        assert res_audit.json()["items"][0]["action"] == "create_admin"
        assert res_audit.json()["items"][0]["targetEmail"] == "candidate@test.com"

        # 3. Super admin updates permissions
        res_perm = await ac.patch(f"/api/superadmin/admins/{verified_user.id}/permissions", headers=headers, json={
            "permissions": ["view_users", "view_scans", "export_data"]
        })
        assert res_perm.status_code == 200
        assert "export_data" in res_perm.json()["permissions"]

        # 4. Super admin cannot edit their own permissions
        res_self = await ac.patch(f"/api/superadmin/admins/{super_admin.id}/permissions", headers=headers, json={
            "permissions": ["view_users"]
        })
        assert res_self.status_code == 400

        # 5. Last active super admin protection: cannot demote last super admin
        res_demote = await ac.patch(f"/api/superadmin/users/{super_admin.id}/role", headers=headers, json={
            "role": "user"
        })
        assert res_demote.status_code == 400


@pytest.mark.asyncio
async def test_token_version_invalidation_on_password_reset(clean_db):
    app.dependency_overrides.pop(get_current_user, None)
    db = SessionLocal()
    user = db_models.User(
        name="Version User",
        username="version_user",
        username_lower="version_user",
        email="version@test.com",
        password_hash=hash_password("OldPassword123!"),
        role="user",
        is_active=True,
        is_email_verified=True,
        token_version=1
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    # Issue token with token_version 1
    token_v1 = create_access_token({"sub": str(user.id), "email": user.email, "role": "user", "token_version": 1})
    db.close()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Token v1 works
        res_me1 = await ac.get("/api/auth/me", headers={"Authorization": f"Bearer {token_v1}"})
        assert res_me1.status_code == 200

        # Reset password -> bumps token_version
        res_reset = await ac.post("/api/auth/reset-password", json={
            "email": "version@test.com",
            "newPassword": "NewPassword123!"
        })
        assert res_reset.status_code == 200

        # Old token v1 MUST be rejected with 401
        res_me_old = await ac.get("/api/auth/me", headers={"Authorization": f"Bearer {token_v1}"})
        assert res_me_old.status_code == 401
        assert "session has been invalidated" in res_me_old.json()["detail"].lower()
