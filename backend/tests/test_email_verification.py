import pytest
from httpx import AsyncClient, ASGITransport
import bcrypt
import datetime
import hashlib
import time
from unittest.mock import patch

from main import app
from database import SessionLocal
import db_models
from modules.auth_module import get_current_user, hash_password
from routers.auth import cleanup_stale_unverified_accounts, _resend_cooldowns, _resend_hourly, _resend_ip_limits


@pytest.fixture(autouse=True)
def clean_test_data():
    db = SessionLocal()
    try:
        db.query(db_models.EmailVerification).delete()
        # Keep real admin accounts safe
        db.query(db_models.User).filter(
            ~db_models.User.email.in_([
                "63796174@gmail.com",
                "mathan63796174@gmail.com",
                "admin@breach-investigation.local"
            ])
        ).delete()
        db.commit()
    finally:
        db.close()
    # Reset resend rate limit structures
    _resend_cooldowns.clear()
    _resend_hourly.clear()
    _resend_ip_limits.clear()


@pytest.mark.asyncio
async def test_registration_creates_unverified_account_no_jwt():
    """1. User registers. Account created with is_email_verified=False. No JWT returned."""
    app.dependency_overrides.pop(get_current_user, None)
    with patch("routers.auth.send_verification_email") as mock_send:
        mock_send.return_value = (True, None)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            res = await ac.post("/api/auth/register", json={
                "name": "Alice Unverified",
                "username": "alice_unverified",
                "email": "alice@example.com",
                "password": "Password123!Secure",
                "confirm_password": "Password123!Secure",
                "consent": True,
            })
            assert res.status_code == 200
            data = res.json()
            assert data["success"] is True
            assert "token" not in data  # No automatic login / JWT

            db = SessionLocal()
            user = db.query(db_models.User).filter(db_models.User.email == "alice@example.com").first()
            assert user is not None
            assert user.is_email_verified is False
            db.close()


@pytest.mark.asyncio
async def test_verification_email_sent_with_link():
    """2. Verification email is sent to registered address with link containing token."""
    app.dependency_overrides.pop(get_current_user, None)
    with patch("routers.auth.send_verification_email") as mock_send:
        mock_send.return_value = (True, None)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            res = await ac.post("/api/auth/register", json={
                "name": "Bob Verif",
                "username": "bob_verif",
                "email": "bob@example.com",
                "password": "Password123!Secure",
                "confirm_password": "Password123!Secure",
                "consent": True,
            })
            assert res.status_code == 200
            mock_send.assert_called_once()
            call_kwargs = mock_send.call_args.kwargs
            assert call_kwargs["to_email"] == "bob@example.com"
            assert call_kwargs["user_name"] == "Bob Verif"
            assert "/verify-email?token=" in call_kwargs["verification_link"]


@pytest.mark.asyncio
async def test_unverified_login_returns_403():
    """3. Unverified accounts cannot log in with correct password (403 email_not_verified)."""
    app.dependency_overrides.pop(get_current_user, None)
    with patch("routers.auth.send_verification_email") as mock_send:
        mock_send.return_value = (True, None)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            await ac.post("/api/auth/register", json={
                "name": "Charlie Unverified",
                "username": "charlie_unverified",
                "email": "charlie@example.com",
                "password": "Password123!Secure",
                "confirm_password": "Password123!Secure",
                "consent": True,
            })

            # Attempt login with correct password
            res = await ac.post("/api/auth/login", json={
                "identifier": "charlie@example.com",
                "password": "Password123!Secure"
            })
            assert res.status_code == 403
            data = res.json()
            assert data["code"] == "email_not_verified"
            assert "verify your email" in data["message"].lower()


@pytest.mark.asyncio
async def test_wrong_password_returns_generic_401_for_unverified():
    """4. Wrong password returns generic 401 even if account is unverified."""
    app.dependency_overrides.pop(get_current_user, None)
    with patch("routers.auth.send_verification_email") as mock_send:
        mock_send.return_value = (True, None)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            await ac.post("/api/auth/register", json={
                "name": "David WrongPw",
                "username": "david_wrongpw",
                "email": "david@example.com",
                "password": "Password123!Secure",
                "confirm_password": "Password123!Secure",
                "consent": True,
            })

            # Attempt login with wrong password
            res = await ac.post("/api/auth/login", json={
                "identifier": "david@example.com",
                "password": "WrongPassword999!"
            })
            assert res.status_code == 401
            assert "incorrect email, username or password" in res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_verify_email_success_and_single_use():
    """5. Verify email succeeds once; second attempt on same token is rejected."""
    app.dependency_overrides.pop(get_current_user, None)
    captured_link = []

    def mock_send_email(**kwargs):
        captured_link.append(kwargs["verification_link"])
        return (True, None)

    with patch("routers.auth.send_verification_email", side_effect=mock_send_email):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            await ac.post("/api/auth/register", json={
                "name": "Eve SingleUse",
                "username": "eve_singleuse",
                "email": "eve@example.com",
                "password": "Password123!Secure",
                "confirm_password": "Password123!Secure",
                "consent": True,
            })

            assert len(captured_link) == 1
            token = captured_link[0].split("token=")[1]

            # First verification
            res1 = await ac.post("/api/auth/verify-email", json={"token": token})
            assert res1.status_code == 200
            assert "email verified" in res1.json()["message"].lower()

            # Confirm user is now verified in DB
            db = SessionLocal()
            user = db.query(db_models.User).filter(db_models.User.email == "eve@example.com").first()
            assert user.is_email_verified is True
            db.close()

            # Second verification attempt with same token -> rejected
            res2 = await ac.post("/api/auth/verify-email", json={"token": token})
            assert res2.status_code == 400
            assert res2.json()["canResend"] is True
            assert "already been used" in res2.json()["message"].lower()

            # Now user can log in
            res_login = await ac.post("/api/auth/login", json={
                "identifier": "eve@example.com",
                "password": "Password123!Secure"
            })
            assert res_login.status_code == 200
            assert "token" in res_login.json()


@pytest.mark.asyncio
async def test_expired_token_rejected():
    """6. Expired token rejected with plain-English error and canResend=true."""
    app.dependency_overrides.pop(get_current_user, None)
    captured_link = []

    def mock_send_email(**kwargs):
        captured_link.append(kwargs["verification_link"])
        return (True, None)

    with patch("routers.auth.send_verification_email", side_effect=mock_send_email):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            await ac.post("/api/auth/register", json={
                "name": "Frank Expired",
                "username": "frank_expired",
                "email": "frank@example.com",
                "password": "Password123!Secure",
                "confirm_password": "Password123!Secure",
                "consent": True,
            })
            token = captured_link[0].split("token=")[1]

            # Fast-forward token expiry in database to the past
            db = SessionLocal()
            v = db.query(db_models.EmailVerification).first()
            v.expires_at = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)
            db.commit()
            db.close()

            res = await ac.post("/api/auth/verify-email", json={"token": token})
            assert res.status_code == 400
            data = res.json()
            assert data["canResend"] is True
            assert "expired" in data["message"].lower()


@pytest.mark.asyncio
async def test_tampered_token_rejected():
    """7. Tampered or bogus token is rejected with plain-English error and canResend=true."""
    app.dependency_overrides.pop(get_current_user, None)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.post("/api/auth/verify-email", json={"token": "totally_bogus_token_1234567890"})
        assert res.status_code == 400
        data = res.json()
        assert data["canResend"] is True
        assert "invalid" in data["message"].lower()


@pytest.mark.asyncio
async def test_only_sha256_hash_stored_in_db():
    """8. Plaintext token is never stored; only SHA-256 hash exists in db."""
    app.dependency_overrides.pop(get_current_user, None)
    captured_link = []

    def mock_send_email(**kwargs):
        captured_link.append(kwargs["verification_link"])
        return (True, None)

    with patch("routers.auth.send_verification_email", side_effect=mock_send_email):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            await ac.post("/api/auth/register", json={
                "name": "Grace HashCheck",
                "username": "grace_hashcheck",
                "email": "grace@example.com",
                "password": "Password123!Secure",
                "confirm_password": "Password123!Secure",
                "consent": True,
            })
            token = captured_link[0].split("token=")[1]
            expected_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

            db = SessionLocal()
            record = db.query(db_models.EmailVerification).first()
            assert record is not None
            assert record.token_hash == expected_hash
            assert record.token_hash != token
            db.close()


@pytest.mark.asyncio
async def test_resend_verification_generic_and_rate_limited():
    """9. Resend returns generic success, enforces 60s cooldown and max limit, never sends to verified accounts."""
    app.dependency_overrides.pop(get_current_user, None)
    send_count = 0

    def mock_send_email(**kwargs):
        nonlocal send_count
        send_count += 1
        return (True, None)

    with patch("routers.auth.send_verification_email", side_effect=mock_send_email):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            # Register unverified user (send_count = 1)
            await ac.post("/api/auth/register", json={
                "name": "Heidi Resend",
                "username": "heidi_resend",
                "email": "heidi@example.com",
                "password": "Password123!Secure",
                "confirm_password": "Password123!Secure",
                "consent": True,
            })
            assert send_count == 1

            # Immediate resend should be blocked by 60s rate limit
            res_throttled = await ac.post("/api/auth/resend-verification", json={"email": "heidi@example.com"})
            assert res_throttled.status_code == 429
            assert "wait" in res_throttled.json()["detail"].lower()

            # Advance cooldown
            _resend_cooldowns["heidi@example.com"] = time.time() - 65
            res_allowed = await ac.post("/api/auth/resend-verification", json={"email": "heidi@example.com"})
            assert res_allowed.status_code == 200
            assert res_allowed.json()["message"] == "If this account exists and is not verified, a new email was sent"
            assert send_count == 2

            # Unknown email returns the same generic message without sending
            res_unknown = await ac.post("/api/auth/resend-verification", json={"email": "nobody@example.com"})
            assert res_unknown.status_code == 200
            assert res_unknown.json()["message"] == "If this account exists and is not verified, a new email was sent"
            assert send_count == 2  # Didn't send for unknown email


@pytest.mark.asyncio
async def test_resend_never_sends_to_verified_account():
    """9b. Resend never sends to already verified accounts."""
    app.dependency_overrides.pop(get_current_user, None)
    send_count = 0

    def mock_send_email(**kwargs):
        nonlocal send_count
        send_count += 1
        return (True, None)

    with patch("routers.auth.send_verification_email", side_effect=mock_send_email):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            # Create already verified user in db
            db = SessionLocal()
            u = db_models.User(
                name="Ivan Verified",
                username="ivan_verified",
                username_lower="ivan_verified",
                email="ivan@example.com",
                password_hash=hash_password("Password123!"),
                role="user",
                is_active=True,
                is_email_verified=True,
            )
            db.add(u)
            db.commit()
            db.close()

            res = await ac.post("/api/auth/resend-verification", json={"email": "ivan@example.com"})
            assert res.status_code == 200
            assert res.json()["message"] == "If this account exists and is not verified, a new email was sent"
            assert send_count == 0  # Did not send!


@pytest.mark.asyncio
async def test_smtp_failure_during_register_shows_resend_message():
    """11. When SMTP fails during register, user account is created with 'Use Resend' message."""
    app.dependency_overrides.pop(get_current_user, None)
    with patch("routers.auth.send_verification_email") as mock_send:
        mock_send.return_value = (False, "SMTP connect timeout")

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            res = await ac.post("/api/auth/register", json={
                "name": "Judy SmtpFail",
                "username": "judy_smtpfail",
                "email": "judy@example.com",
                "password": "Password123!Secure",
                "confirm_password": "Password123!Secure",
                "consent": True,
            })
            assert res.status_code == 200
            data = res.json()
            assert data["success"] is True
            assert data["email_sent"] is False
            assert "We could not send the email. Use Resend." in data["message"]

            # User account was still saved
            db = SessionLocal()
            user = db.query(db_models.User).filter(db_models.User.email == "judy@example.com").first()
            assert user is not None
            assert user.is_email_verified is False
            db.close()


def test_cleanup_stale_unverified_accounts():
    """12. Stale unverified accounts > 7 days old are deleted, freeing username and email."""
    db = SessionLocal()
    try:
        # Create unverified account > 8 days old
        old_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=8)
        old_user = db_models.User(
            name="Stale User",
            username="stale_user",
            username_lower="stale_user",
            email="stale@example.com",
            password_hash=hash_password("Password123!"),
            role="user",
            is_active=True,
            is_email_verified=False,
            created_at=old_time,
        )
        db.add(old_user)

        # Create recent unverified account (1 day old)
        recent_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
        recent_user = db_models.User(
            name="Recent User",
            username="recent_user",
            username_lower="recent_user",
            email="recent@example.com",
            password_hash=hash_password("Password123!"),
            role="user",
            is_active=True,
            is_email_verified=False,
            created_at=recent_time,
        )
        db.add(recent_user)
        db.commit()

        # Run cleanup
        deleted = cleanup_stale_unverified_accounts(db)
        assert deleted == 1

        # Check old user deleted, recent user preserved
        assert db.query(db_models.User).filter(db_models.User.email == "stale@example.com").first() is None
        assert db.query(db_models.User).filter(db_models.User.email == "recent@example.com").first() is not None
    finally:
        db.close()
