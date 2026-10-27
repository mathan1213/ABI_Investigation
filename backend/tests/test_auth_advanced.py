import json
import datetime
import pytest
from httpx import AsyncClient, ASGITransport
import bcrypt

from main import app
from database import SessionLocal
import db_models
from modules.auth_module import (
    get_current_user,
    create_access_token,
    hash_otp_code,
    hash_password,
    ALL_PERMISSIONS,
)


@pytest.fixture
def clean_db():
    db = SessionLocal()
    try:
        db.query(db_models.EmailOtp).delete()
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
async def test_email_otp_generation_hash_storage_and_activation(clean_db):
    app.dependency_overrides.pop(get_current_user, None)
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
        user_id = r.json()["userId"]

        # 2. Verify OTP row in database: code_hash is NOT plain text
        db = SessionLocal()
        otp_row = db.query(db_models.EmailOtp).filter(db_models.EmailOtp.user_id == user_id).first()
        assert otp_row is not None
        assert len(otp_row.code_hash) == 64  # SHA256 hex digest
        assert not otp_row.code_hash.isdigit()  # NEVER store 6 digit plain text!

        # 3. Unverified account cannot log in
        login_unverified = await ac.post("/api/auth/login", json={
            "identifier": "emma_w",
            "password": "StrongPassword123!"
        })
        assert login_unverified.status_code == 403
        assert "not verified" in login_unverified.json()["detail"].lower()

        # 4. Incorrect code attempt
        r_bad = await ac.post("/api/auth/verify-email", json={
            "email": "emma@test.com",
            "code": "000000"
        })
        assert r_bad.status_code == 400
        assert "incorrect" in r_bad.json()["detail"].lower()

        # 5. Overwrite hash with known code to test successful activation
        known_code = "123456"
        otp_row.code_hash = hash_otp_code(known_code)
        db.commit()
        db.close()

        r_verify = await ac.post("/api/auth/verify-email", json={
            "email": "emma@test.com",
            "code": known_code
        })
        assert r_verify.status_code == 200
        data = r_verify.json()
        assert "token" in data
        assert data["user"]["is_email_verified"] is True
        assert data["user"]["is_active"] is True

        # 6. Used code cannot be reused
        r_reuse = await ac.post("/api/auth/verify-email", json={
            "email": "emma@test.com",
            "code": known_code
        })
        assert r_reuse.status_code == 400


@pytest.mark.asyncio
async def test_otp_lockout_after_5_wrong_attempts(clean_db):
    app.dependency_overrides.pop(get_current_user, None)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        await ac.post("/api/auth/register", json={
            "name": "Lockout User",
            "username": "lockout_user",
            "email": "lockout@test.com",
            "password": "Password123!",
            "consent": True
        })

        # Submit 5 incorrect codes
        for _ in range(5):
            await ac.post("/api/auth/verify-email", json={
                "email": "lockout@test.com",
                "code": "999999"
            })

        # Check DB that OTP row is marked used/invalidated
        db = SessionLocal()
        otp = db.query(db_models.EmailOtp).filter(db_models.EmailOtp.email == "lockout@test.com").first()
        assert otp.attempts >= 5
        assert otp.used is True
        db.close()


@pytest.mark.asyncio
async def test_admin_login_rejects_normal_user(clean_db):
    app.dependency_overrides.pop(get_current_user, None)
    db = SessionLocal()
    # Create verified normal user
    user = db_models.User(
        name="Regular Joe",
        username="regular_joe",
        username_lower="regular_joe",
        email="joe@test.com",
        password_hash=hash_password("Password123!"),
        role="user",
        is_active=True,
        is_email_verified=True,
    )
    db.add(user)
    db.commit()
    db.close()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Regular user attempting admin login gets generic 401
        res = await ac.post("/api/admin/login", json={
            "identifier": "regular_joe",
            "password": "Password123!"
        })
        assert res.status_code == 401
        assert res.json()["detail"] == "Incorrect email, username or password."


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

    # Prepare password reset OTP
    reset_code = "789123"
    otp = db_models.EmailOtp(
        user_id=user.id,
        email="version@test.com",
        purpose="password_reset",
        code_hash=hash_otp_code(reset_code),
        expires_at=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=10),
        attempts=0,
        used=False,
    )
    db.add(otp)
    db.commit()
    db.close()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Token v1 works
        res_me1 = await ac.get("/api/auth/me", headers={"Authorization": f"Bearer {token_v1}"})
        assert res_me1.status_code == 200

        # Reset password -> bumps token_version
        res_reset = await ac.post("/api/auth/reset-password", json={
            "email": "version@test.com",
            "code": reset_code,
            "newPassword": "NewPassword123!"
        })
        assert res_reset.status_code == 200

        # Old token v1 MUST be rejected with 401
        res_me_old = await ac.get("/api/auth/me", headers={"Authorization": f"Bearer {token_v1}"})
        assert res_me_old.status_code == 401
        assert "session has been invalidated" in res_me_old.json()["detail"].lower()
