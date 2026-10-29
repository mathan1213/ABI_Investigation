import pytest
from httpx import AsyncClient, ASGITransport
import bcrypt
from unittest.mock import patch, MagicMock

from main import app
from database import SessionLocal
import db_models
from modules.auth_module import get_current_user
from modules.email_service import generate_email_bodies, EMAIL_SUBJECT, send_welcome_email
from config import settings


@pytest.fixture
def clean_db():
    db = SessionLocal()
    try:
        db.query(db_models.UploadedFile).delete()
        db.query(db_models.AuditLog).delete()
        db.query(db_models.ActivityLog).delete()
        db.query(db_models.Report).delete()
        db.query(db_models.Scan).delete()
        # Keep real admin accounts safe
        db.query(db_models.User).filter(~db_models.User.email.in_(["63796174@gmail.com", "mathan63796174@gmail.com", "admin@breach-investigation.local"])).delete()
        db.commit()
    finally:
        db.close()


def test_email_template_subject_and_content():
    """Verifies that the generated email subject and body match all required specifications."""
    to_email = "investigator@example.com"
    user_name = "Jane Investigator"

    assert EMAIL_SUBJECT == "Welcome to Account Breach Investigation — Registration Successful"

    text_body, html_body = generate_email_bodies(to_email, user_name)

    # Check Plain-Text body requirements
    assert "Hello Jane Investigator," in text_body
    assert "Welcome to Account Breach Investigation!" in text_body
    assert "Your account has been successfully registered." in text_body
    assert "Telegram Account Investigation" in text_body
    assert "Repository URL Security Check" in text_body
    assert "Network IP Address Investigation" in text_body
    assert "Thank you for joining us." in text_body
    assert "Best regards," in text_body
    assert "Account Breach Investigation Team" in text_body

    # Check HTML body requirements
    assert "Hello <strong>Jane Investigator</strong>," in html_body
    assert "Welcome to <strong>Account Breach Investigation</strong>!" in html_body
    assert "Your account has been successfully registered." in html_body
    assert "Telegram Account Investigation" in html_body
    assert "Repository URL Security Check" in html_body
    assert "Network IP Address Investigation" in html_body
    assert "Thank you for joining us." in html_body
    assert "Account Breach Investigation Team" in html_body
    assert to_email in html_body


@pytest.mark.asyncio
async def test_full_registration_and_email_delivery(clean_db):
    """
    Scenario 1, 2, 3:
    1. A new user registers with a valid name, username, email, password, and confirm password.
    2. The user record is saved to SQLite with bcrypt password hash.
    3. Verification email delivery is triggered to the user's actual email address.
    """
    app.dependency_overrides.pop(get_current_user, None)
    with patch("routers.auth.send_verification_email") as mock_email:
        mock_email.return_value = (True, None)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            res = await ac.post("/api/auth/register", json={
                "name": "Sarah Connor",
                "username": "sarah_connor",
                "email": "sarah@cyberdyne.org",
                "password": "Password2026!Secure",
                "confirm_password": "Password2026!Secure",
                "consent": True
            })
            assert res.status_code == 200
            data = res.json()
            assert data["success"] is True
            assert data["email_sent"] is True
            assert "verification link has been sent" in data["message"].lower()

            # Verify email was sent to actual registered email
            mock_email.assert_called_once()
            assert mock_email.call_args.kwargs["to_email"] == "sarah@cyberdyne.org"
            assert mock_email.call_args.kwargs["user_name"] == "Sarah Connor"

            # Verify saved in SQLite database
            db = SessionLocal()
            user = db.query(db_models.User).filter(db_models.User.email == "sarah@cyberdyne.org").first()
            assert user is not None
            assert user.name == "Sarah Connor"
            assert user.username == "sarah_connor"
            assert user.username_lower == "sarah_connor"
            assert user.password_hash != "Password2026!Secure"
            assert bcrypt.checkpw("Password2026!Secure".encode("utf-8"), user.password_hash.encode("utf-8"))
            db.close()


@pytest.mark.asyncio
async def test_confirm_password_validation(clean_db):
    """Verifies that registration fails with 400 when confirm password does not match."""
    app.dependency_overrides.pop(get_current_user, None)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.post("/api/auth/register", json={
            "name": "Mismatch User",
            "username": "mismatch_user",
            "email": "mismatch@test.com",
            "password": "Password123!",
            "confirm_password": "DifferentPassword123!",
            "consent": True
        })
        assert res.status_code == 400
        assert "passwords do not match" in res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_duplicate_email_and_username_rejected(clean_db):
    """Scenario 4: An existing email or username cannot register another account."""
    app.dependency_overrides.pop(get_current_user, None)
    with patch("routers.auth.send_welcome_email") as mock_email:
        mock_email.return_value = (True, None)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            # First registration succeeds
            r1 = await ac.post("/api/auth/register", json={
                "name": "First User",
                "username": "first_user",
                "email": "user1@test.com",
                "password": "Password123!",
                "confirm_password": "Password123!",
                "consent": True
            })
            assert r1.status_code == 200

            # Second registration with duplicate email -> 409
            r2 = await ac.post("/api/auth/register", json={
                "name": "Second User",
                "username": "second_user",
                "email": "user1@test.com",
                "password": "Password123!",
                "confirm_password": "Password123!",
                "consent": True
            })
            assert r2.status_code == 409
            assert "already exists" in r2.json()["detail"].lower()

            # Registration with duplicate username -> 409
            r3 = await ac.post("/api/auth/register", json={
                "name": "Third User",
                "username": "first_user",
                "email": "user3@test.com",
                "password": "Password123!",
                "confirm_password": "Password123!",
                "consent": True
            })
            assert r3.status_code == 409
            assert "taken" in r3.json()["detail"].lower()


@pytest.mark.asyncio
async def test_invalid_email_format_rejected(clean_db):
    """Scenario 5: An invalid email is rejected with 400."""
    app.dependency_overrides.pop(get_current_user, None)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        invalid_emails = ["not-an-email", "@missinguser.com", "user@", "plainword"]
        for bad_email in invalid_emails:
            res = await ac.post("/api/auth/register", json={
                "name": "Bad Email User",
                "username": "bad_email_u",
                "email": bad_email,
                "password": "Password123!",
                "confirm_password": "Password123!",
                "consent": True
            })
            assert res.status_code == 400
            assert "valid email" in res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_smtp_failure_handled_gracefully(clean_db):
    """
    Scenario 6:
    When SMTP is unconfigured or fails, registration succeeds without failing the account creation,
    but email_sent is False and the system does NOT falsely tell the user the email was sent.
    """
    app.dependency_overrides.pop(get_current_user, None)
    with patch("routers.auth.send_verification_email") as mock_email:
        mock_email.return_value = (False, "SMTP authentication failed")

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            res = await ac.post("/api/auth/register", json={
                "name": "Fallback User",
                "username": "fallback_user",
                "email": "fallback@test.com",
                "password": "Password123!",
                "confirm_password": "Password123!",
                "consent": True
            })
            assert res.status_code == 200
            data = res.json()
            assert data["success"] is True
            assert data["email_sent"] is False
            # Does NOT falsely claim email was sent
            assert "has been sent" not in data["message"].lower()
            assert "could not send the email" in data["message"].lower() or "resend" in data["message"].lower()

            # Verify in DB: user exists and is not verified
            db = SessionLocal()
            user = db.query(db_models.User).filter(db_models.User.email == "fallback@test.com").first()
            assert user is not None
            assert user.is_email_verified is False
            db.close()


@pytest.mark.asyncio
async def test_resend_welcome_email_and_duplicate_prevention(clean_db):
    """
    Scenario 6 & 8:
    Tests the resend endpoint. Retries delivery for pending emails,
    and prevents sending duplicate welcome emails once sent.
    """
    app.dependency_overrides.pop(get_current_user, None)
    with patch("routers.auth.send_verification_email", return_value=(True, None)):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            res_reg = await ac.post("/api/auth/register", json={
                "name": "Retry User",
                "username": "retry_user",
                "email": "retry@test.com",
                "password": "Password123!",
                "confirm_password": "Password123!",
                "consent": True
            })
            assert res_reg.status_code == 200

            # Test resending welcome email when not yet marked sent
            with patch("routers.auth.send_welcome_email", return_value=(True, None)):
                res_retry = await ac.post("/api/auth/resend-welcome-email", json={
                    "email": "retry@test.com"
                })
                assert res_retry.status_code == 200
                assert res_retry.json()["success"] is True
                assert res_retry.json()["email_sent"] is True

                # In DB: welcome_email_sent is now True
                db = SessionLocal()
                user = db.query(db_models.User).filter(db_models.User.email == "retry@test.com").first()
                assert user.welcome_email_sent is True
                db.close()

                # Try to send a duplicate welcome email -> must prevent duplicate sending!
                res_duplicate = await ac.post("/api/auth/resend-welcome-email", json={
                    "email": "retry@test.com"
                })
                assert res_duplicate.status_code == 200
                assert res_duplicate.json()["already_sent"] is True
                assert "already been sent" in res_duplicate.json()["message"].lower()


@pytest.mark.asyncio
async def test_login_after_registration(clean_db):
    """Scenario 7: The user can log in after registration and email verification using username/email and password."""
    app.dependency_overrides.pop(get_current_user, None)
    with patch("routers.auth.send_verification_email", return_value=(True, None)):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            # 1. Register
            r_reg = await ac.post("/api/auth/register", json={
                "name": "Login Tester",
                "username": "logintester",
                "email": "tester@test.com",
                "password": "Password2026!Secure",
                "confirm_password": "Password2026!Secure",
                "consent": True
            })
            assert r_reg.status_code == 200

            # 2. Verify account
            db = SessionLocal()
            user = db.query(db_models.User).filter(db_models.User.email == "tester@test.com").first()
            assert user is not None
            user.is_email_verified = True
            db.commit()
            db.close()

            # 3. Login by email
            r_login_email = await ac.post("/api/auth/login", json={
                "identifier": "tester@test.com",
                "password": "Password2026!Secure"
            })
            assert r_login_email.status_code == 200
            assert "token" in r_login_email.json()
            assert r_login_email.json()["user"]["email"] == "tester@test.com"

            # 4. Login by username
            r_login_user = await ac.post("/api/auth/login", json={
                "identifier": "logintester",
                "password": "Password2026!Secure"
            })
            assert r_login_user.status_code == 200
            assert "token" in r_login_user.json()
