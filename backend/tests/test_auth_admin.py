import json
import pytest
from httpx import AsyncClient, ASGITransport
import bcrypt

from main import app
from database import SessionLocal
import db_models
from modules.auth_module import get_current_user, create_access_token, ALL_PERMISSIONS, hash_otp_code


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
async def test_auth_registration_and_password_hashing(clean_db):
    app.dependency_overrides.pop(get_current_user, None)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. Invalid email
        res = await ac.post("/api/auth/register", json={
            "name": "Alice",
            "username": "alice_smith",
            "email": "not-an-email",
            "password": "Password123!",
            "consent": True
        })
        assert res.status_code == 400

        # 2. Short password
        res = await ac.post("/api/auth/register", json={
            "name": "Alice",
            "username": "alice_smith",
            "email": "alice@test.com",
            "password": "short",
            "consent": True
        })
        assert res.status_code == 400

        # 3. Valid registration (requires OTP verification next)
        res = await ac.post("/api/auth/register", json={
            "name": "Alice Smith",
            "username": "Alice_Smith",
            "email": "alice@test.com",
            "password": "StrongPassword123!",
            "consent": True
        })
        assert res.status_code == 200
        data = res.json()
        assert data["success"] is True
        assert data["email"] == "alice@test.com"

        # 4. Verify password hash in DB is NOT plain text and is valid bcrypt
        db = SessionLocal()
        user_in_db = db.query(db_models.User).filter(db_models.User.email == "alice@test.com").first()
        assert user_in_db is not None
        assert user_in_db.password_hash != "StrongPassword123!"
        assert bcrypt.checkpw("StrongPassword123!".encode("utf-8"), user_in_db.password_hash.encode("utf-8"))
        assert user_in_db.username == "Alice_Smith"
        assert user_in_db.username_lower == "alice_smith"
        assert user_in_db.is_email_verified is False
        db.close()

        # 5. Duplicate email rejected with 409
        res_dup = await ac.post("/api/auth/register", json={
            "name": "Alice Copy",
            "username": "alice_copy",
            "email": "alice@test.com",
            "password": "AnotherPassword123!",
            "consent": True
        })
        assert res_dup.status_code == 409


@pytest.mark.asyncio
async def test_auth_login_and_me_and_self_deletion(clean_db):
    app.dependency_overrides.pop(get_current_user, None)
    db = SessionLocal()
    # Directly insert verified user
    user = db_models.User(
        name="Bob Jones",
        username="bobjones",
        username_lower="bobjones",
        email="bob@test.com",
        password_hash=bcrypt.hashpw("PasswordBob123!".encode("utf-8"), bcrypt.gensalt()).decode("utf-8"),
        role="user",
        is_active=True,
        is_email_verified=True,
        token_version=1,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    user_id = user.id
    db.close()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Login with wrong password
        login_fail = await ac.post("/api/auth/login", json={
            "identifier": "bob@test.com",
            "password": "WrongPassword!"
        })
        assert login_fail.status_code == 401
        assert login_fail.json()["detail"] == "Incorrect email, username or password."

        # Login with correct password by username
        login_step1 = await ac.post("/api/auth/login", json={
            "identifier": "bobjones",
            "password": "PasswordBob123!"
        })
        assert login_step1.status_code == 200
        assert login_step1.json()["requiresOtp"] is True

        # Intercept generated OTP from test database to verify
        db = SessionLocal()
        otp_entry = db.query(db_models.EmailOtp).filter(db_models.EmailOtp.user_id == user_id).order_by(db_models.EmailOtp.id.desc()).first()
        assert otp_entry is not None
        # Overwrite hash with known code "654321"
        known_code = "654321"
        otp_entry.code_hash = hash_otp_code(known_code)
        db.commit()
        db.close()

        # Step 2: verify login OTP
        login_step2 = await ac.post("/api/auth/verify-login-otp", json={
            "userId": user_id,
            "code": known_code
        })
        assert login_step2.status_code == 200
        token = login_step2.json()["token"]

        # GET /api/auth/me
        headers = {"Authorization": f"Bearer {token}"}
        me_res = await ac.get("/api/auth/me", headers=headers)
        assert me_res.status_code == 200
        assert me_res.json()["name"] == "Bob Jones"
        assert me_res.json()["username"] == "bobjones"

        # DELETE /api/auth/me
        del_res = await ac.delete("/api/auth/me", headers=headers)
        assert del_res.status_code == 200

        # After deletion, me should return 401
        me_after = await ac.get("/api/auth/me", headers=headers)
        assert me_after.status_code == 401


@pytest.mark.asyncio
async def test_rbac_normal_user_gets_403_on_admin_endpoints(clean_db):
    app.dependency_overrides.pop(get_current_user, None)
    db = SessionLocal()
    # Create normal user
    normal_user = db_models.User(
        name="Normal User",
        username="normal_user",
        username_lower="normal_user",
        email="normal@test.com",
        password_hash="hash",
        role="user",
        is_active=True,
        is_email_verified=True,
        token_version=1
    )
    db.add(normal_user)
    db.commit()
    db.refresh(normal_user)
    normal_token = create_access_token({"sub": str(normal_user.id), "email": normal_user.email, "role": "user", "token_version": 1})
    db.close()

    headers = {"Authorization": f"Bearer {normal_token}"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Normal user must receive 403 on ALL admin endpoints
        endpoints = [
            ("GET", "/api/admin/overview"),
            ("GET", "/api/admin/users"),
            ("GET", f"/api/admin/users/{normal_user.id}"),
            ("PATCH", f"/api/admin/users/{normal_user.id}"),
            ("DELETE", f"/api/admin/users/{normal_user.id}"),
            ("GET", "/api/admin/activity"),
            ("GET", "/api/admin/export/users.csv"),
            ("GET", "/api/superadmin/admins"),
            ("GET", "/api/superadmin/audit"),
        ]

        for method, endpoint in endpoints:
            if method == "GET":
                resp = await ac.get(endpoint, headers=headers)
            elif method == "PATCH":
                resp = await ac.patch(endpoint, headers=headers, json={"is_active": False})
            elif method == "DELETE":
                resp = await ac.delete(endpoint, headers=headers)
            assert resp.status_code == 403, f"Expected 403 on {method} {endpoint}, got {resp.status_code}"


@pytest.mark.asyncio
async def test_admin_operations_and_view_activity_logging(clean_db):
    app.dependency_overrides.pop(get_current_user, None)
    db = SessionLocal()
    # Create super admin user and a normal user
    admin_user = db_models.User(
        name="Root Admin",
        username="root_admin",
        username_lower="root_admin",
        email="root@test.com",
        password_hash="hash",
        role="super_admin",
        is_active=True,
        is_email_verified=True,
        token_version=1,
        permissions=json.dumps(ALL_PERMISSIONS)
    )
    target_user = db_models.User(
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
    db.add(admin_user)
    db.add(target_user)
    db.commit()
    db.refresh(admin_user)
    db.refresh(target_user)

    admin_token = create_access_token({"sub": str(admin_user.id), "email": admin_user.email, "role": "super_admin", "token_version": 1})
    db.close()

    headers = {"Authorization": f"Bearer {admin_token}"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. Admin overview
        res_overview = await ac.get("/api/admin/overview", headers=headers)
        assert res_overview.status_code == 200
        assert res_overview.json()["totalUsers"] >= 2

        # 2. Admin users list
        res_users = await ac.get("/api/admin/users", headers=headers)
        assert res_users.status_code == 200
        assert len(res_users.json()["items"]) >= 2

        # 3. Admin views target user detail -> MUST log admin_viewed_user
        res_detail = await ac.get(f"/api/admin/users/{target_user.id}", headers=headers)
        assert res_detail.status_code == 200
        assert res_detail.json()["profile"]["email"] == "target@test.com"

        # Check DB for admin_viewed_user
        db = SessionLocal()
        view_activity = db.query(db_models.ActivityLog).filter(
            db_models.ActivityLog.action == "admin_viewed_user"
        ).first()
        assert view_activity is not None
        assert str(target_user.id) in view_activity.detail
        db.close()

        # 4. Admin toggles user is_active
        res_patch = await ac.patch(f"/api/admin/users/{target_user.id}", headers=headers, json={"is_active": False})
        assert res_patch.status_code == 200
        assert res_patch.json()["user"]["isActive"] is False

        # 5. Admin CSV export
        res_csv = await ac.get("/api/admin/export/users.csv", headers=headers)
        assert res_csv.status_code == 200
        assert "target@test.com" in res_csv.text
        assert "text/csv" in res_csv.headers.get("content-type", "")


@pytest.mark.asyncio
async def test_database_hygiene_no_raw_files_or_codes_in_db(clean_db):
    app.dependency_overrides.pop(get_current_user, None)
    db = SessionLocal()
    user = db_models.User(
        name="Hygiene User",
        username="hygiene_user",
        username_lower="hygiene_user",
        email="hygiene@test.com",
        password_hash="hash",
        role="user",
        is_active=True,
        is_email_verified=True,
        token_version=1
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    token = create_access_token({"sub": str(user.id), "email": user.email, "role": user.role, "token_version": 1})
    db.close()

    headers = {"Authorization": f"Bearer {token}"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Upload a chat containing a sensitive login code
        raw_code = "84729"
        chat_content = json.dumps({
            "id": 777000,
            "name": "Telegram",
            "messages": [
                {
                    "id": 1,
                    "date": "2026-10-24T12:00:00",
                    "text": f"Your secret login code is {raw_code}. Do not share."
                },
                {
                    "id": 2,
                    "date": "2026-10-24T12:05:00",
                    "text": "Login alert: We detected a new login from device MacBook Pro in Germany."
                }
            ]
        }).encode("utf-8")

        files = [("files", ("service_chat.json", chat_content, "application/json"))]
        upload_res = await ac.post("/api/telegram/logs/analyze", headers=headers, files=files)
        assert upload_res.status_code == 200

        # Query all rows in database and confirm raw_code is nowhere
        db = SessionLocal()
        all_scans = db.query(db_models.Scan).all()
        assert len(all_scans) >= 1
        for s in all_scans:
            assert raw_code not in s.findings_json
            assert raw_code not in s.target_label
            findings_data = json.loads(s.findings_json)
            for item in findings_data:
                assert "raw_file" not in item
                assert raw_code not in str(item)

        all_logs = db.query(db_models.ActivityLog).all()
        for log in all_logs:
            assert raw_code not in (log.detail or "")

        db.close()
