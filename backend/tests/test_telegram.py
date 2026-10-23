import datetime
import time
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from config import settings
from main import app
from modules.telegram_module import (
    TelegramFloodWaitException,
    TelegramFlow,
    TelegramIntegrationNotConfigured,
    _flows,
    cleanup_expired_flows,
    mask_phone,
)
from routers.telegram import reset_rate_limits

client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_test_environment():
    """Reset flows and rate limits before and after every test."""
    reset_rate_limits()
    _flows.clear()
    yield
    reset_rate_limits()
    _flows.clear()


# ---------------------------------------------------------------------------
# 1. Phone Formatting and Masking Tests
# ---------------------------------------------------------------------------

def test_mask_phone():
    assert mask_phone("+919876543210") == "+91*****3210"
    assert mask_phone("+14155552671") == "+14*****2671"
    assert mask_phone("+447911123456") == "+44*****3456"
    assert mask_phone("1234") == "12****34"


def test_send_code_invalid_phone_format():
    with patch.object(settings, "TELEGRAM_API_ID", 12345), patch.object(
        settings, "TELEGRAM_API_HASH", "mock_hash"
    ):
        # Invalid phone numbers should fail with 400
        for bad_phone in ["12345", "not-a-phone", "+0123456", "919876543210", "+"]:
            resp = client.post("/api/telegram/send-code", json={"phone": bad_phone})
            assert resp.status_code == 400
            assert "Invalid phone number format" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# 2. Configuration Availability (503) Tests
# ---------------------------------------------------------------------------

def test_unconfigured_telegram_returns_503():
    with patch.object(settings, "TELEGRAM_API_ID", None), patch.object(
        settings, "TELEGRAM_API_HASH", None
    ):
        resp_send = client.post("/api/telegram/send-code", json={"phone": "+919876543210"})
        assert resp_send.status_code == 503
        assert "Telegram integration is not configured" in resp_send.json()["detail"]

        resp_verify = client.post("/api/telegram/verify", json={"flowId": "any", "code": "12345"})
        assert resp_verify.status_code == 503
        assert "Telegram integration is not configured" in resp_verify.json()["detail"]

        resp_analyze = client.post("/api/telegram/analyze", json={"flowId": "any"})
        assert resp_analyze.status_code == 503
        assert "Telegram integration is not configured" in resp_analyze.json()["detail"]

        resp_cancel = client.post("/api/telegram/cancel", json={"flowId": "any"})
        assert resp_cancel.status_code == 503
        assert "Telegram integration is not configured" in resp_cancel.json()["detail"]


# ---------------------------------------------------------------------------
# 3. Send Code Endpoint Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_send_code_success():
    mock_tg_client = AsyncMock()
    mock_sent_code = MagicMock()
    mock_sent_code.phone_code_hash = "fake_code_hash_999"
    mock_tg_client.send_code_request = AsyncMock(return_value=mock_sent_code)
    mock_tg_client.connect = AsyncMock()

    with patch.object(settings, "TELEGRAM_API_ID", 12345), patch.object(
        settings, "TELEGRAM_API_HASH", "mock_hash"
    ), patch("telethon.TelegramClient", return_value=mock_tg_client):
        resp = client.post("/api/telegram/send-code", json={"phone": "+919876543210"})
        assert resp.status_code == 200
        data = resp.json()
        assert "flowId" in data
        assert data["message"] == "Verification code requested from Telegram. Check your Telegram app or SMS."

        flow_id = data["flowId"]
        assert flow_id in _flows
        flow = _flows[flow_id]
        assert flow.phone == "+919876543210"
        assert flow.phone_code_hash == "fake_code_hash_999"


def test_send_code_flood_wait():
    from telethon.errors import FloodWaitError

    mock_tg_client = AsyncMock()
    mock_tg_client.connect = AsyncMock()
    mock_tg_client.send_code_request = AsyncMock(side_effect=FloodWaitError(request=None))
    mock_tg_client.send_code_request.side_effect.seconds = 75
    mock_tg_client.disconnect = AsyncMock()

    with patch.object(settings, "TELEGRAM_API_ID", 12345), patch.object(
        settings, "TELEGRAM_API_HASH", "mock_hash"
    ), patch("telethon.TelegramClient", return_value=mock_tg_client):
        resp = client.post("/api/telegram/send-code", json={"phone": "+919876543210"})
        assert resp.status_code == 429
        assert "75 seconds" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# 4. Verify Code Endpoint Tests
# ---------------------------------------------------------------------------

def test_verify_code_needs_password_401():
    from telethon.errors import SessionPasswordNeededError

    mock_client = AsyncMock()
    mock_client.sign_in = AsyncMock(side_effect=SessionPasswordNeededError(request=None))

    flow_id = "test-flow-2fa"
    _flows[flow_id] = TelegramFlow(flow_id, "+919876543210", mock_client, "fake_hash")

    with patch.object(settings, "TELEGRAM_API_ID", 12345), patch.object(
        settings, "TELEGRAM_API_HASH", "mock_hash"
    ):
        resp = client.post("/api/telegram/verify", json={"flowId": flow_id, "code": "54321"})
        assert resp.status_code == 401
        data = resp.json()
        assert data["needsPassword"] is True
        assert data["status"] == "needs_password"
        assert data["flowId"] == flow_id


def test_verify_code_success_with_password():
    mock_client = AsyncMock()
    mock_client.sign_in = AsyncMock(return_value=MagicMock())

    flow_id = "test-flow-pwd"
    _flows[flow_id] = TelegramFlow(flow_id, "+919876543210", mock_client, "fake_hash")

    with patch.object(settings, "TELEGRAM_API_ID", 12345), patch.object(
        settings, "TELEGRAM_API_HASH", "mock_hash"
    ):
        resp = client.post(
            "/api/telegram/verify",
            json={"flowId": flow_id, "code": "54321", "password": "supersecretpassword"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "verified"
        assert data["needsPassword"] is False
        assert _flows[flow_id].status == "verified"


def test_verify_code_invalid_code():
    from telethon.errors import PhoneCodeInvalidError

    mock_client = AsyncMock()
    mock_client.sign_in = AsyncMock(side_effect=PhoneCodeInvalidError(request=None))

    flow_id = "test-flow-badcode"
    _flows[flow_id] = TelegramFlow(flow_id, "+919876543210", mock_client, "fake_hash")

    with patch.object(settings, "TELEGRAM_API_ID", 12345), patch.object(
        settings, "TELEGRAM_API_HASH", "mock_hash"
    ):
        resp = client.post("/api/telegram/verify", json={"flowId": flow_id, "code": "00000"})
        assert resp.status_code == 400
        assert "verification code you entered is incorrect" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# 5. Analysis & Mandatory Logout Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_analyze_unverified_flow_fails():
    mock_client = AsyncMock()
    flow_id = "test-unverified"
    flow = TelegramFlow(flow_id, "+919876543210", mock_client, "fake_hash")
    flow.status = "code_sent"  # Not yet verified
    _flows[flow_id] = flow

    with patch.object(settings, "TELEGRAM_API_ID", 12345), patch.object(
        settings, "TELEGRAM_API_HASH", "mock_hash"
    ):
        resp = client.post("/api/telegram/analyze", json={"flowId": flow_id})
        assert resp.status_code == 400
        assert "verified before running" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_analyze_account_success_and_logout_called():
    mock_client = AsyncMock()
    mock_client.log_out = AsyncMock()
    mock_client.disconnect = AsyncMock()

    # Mock user details
    mock_me = MagicMock()
    mock_me.first_name = "Alex"
    mock_me.last_name = "Tester"
    mock_me.username = "alextester"
    mock_client.get_me = AsyncMock(return_value=mock_me)

    # Mock authorizations
    # 1 current session (this tool)
    sess_curr = MagicMock()
    sess_curr.current = True
    sess_curr.device_model = "Antigravity Security Inspector"
    sess_curr.app_name = "ABI Web"
    sess_curr.app_version = "1.0"
    sess_curr.ip = "127.0.0.1"
    sess_curr.country = "Localhost"
    sess_curr.date_active = datetime.datetime.now(datetime.timezone.utc)
    sess_curr.official_app = True
    sess_curr.hash = 111

    # 1 normal authorized session
    sess_user = MagicMock()
    sess_user.current = False
    sess_user.device_model = "iPhone 14 Pro"
    sess_user.app_name = "Telegram iOS"
    sess_user.app_version = "10.2"
    sess_user.ip = "103.21.244.1"
    sess_user.country = "India"
    sess_user.date_active = datetime.datetime.now(datetime.timezone.utc)
    sess_user.official_app = True
    sess_user.hash = 222

    # 1 foreign suspicious session
    sess_foreign = MagicMock()
    sess_foreign.current = False
    sess_foreign.device_model = "Unknown Linux Machine"
    sess_foreign.app_name = "Custom Client"
    sess_foreign.app_version = "0.1"
    sess_foreign.ip = "185.220.101.5"
    sess_foreign.country = "Russia"
    sess_foreign.date_active = datetime.datetime.now(datetime.timezone.utc)
    sess_foreign.official_app = False
    sess_foreign.hash = 333

    auth_res = MagicMock()
    auth_res.authorizations = [sess_curr, sess_user, sess_foreign]

    # Mock telethon call
    async def mock_call(req):
        req_name = type(req).__name__
        if "GetAuthorizationsRequest" in req_name:
            return auth_res
        if "GetPasswordRequest" in req_name:
            pwd = MagicMock()
            pwd.has_password = True
            pwd.has_recovery = True
            return pwd
        return MagicMock()

    mock_client.side_effect = mock_call

    # Mock empty messages iterator
    async def mock_iter(*args, **kwargs):
        if False:
            yield None

    mock_client.iter_messages = mock_iter

    flow_id = "flow-analyze-test"
    flow = TelegramFlow(flow_id, "+919876543210", mock_client, "fake_hash")
    flow.status = "verified"
    _flows[flow_id] = flow

    with patch.object(settings, "TELEGRAM_API_ID", 12345), patch.object(
        settings, "TELEGRAM_API_HASH", "mock_hash"
    ):
        resp = client.post("/api/telegram/analyze", json={"flowId": flow_id})
        assert resp.status_code == 200
        data = resp.json()

        # Check masked phone & account name
        assert data["phone"] == "+91*****3210"
        assert "Alex Tester (@alextester)" in data["accountName"]

        # Check sessions
        sessions = data["sessions"]
        assert len(sessions) == 3

        curr_sess = next((s for s in sessions if s.get("isCurrent") is True), None)
        assert curr_sess is not None
        assert curr_sess["isSuspicious"] is False
        assert "This Security Analysis Session" in curr_sess["device"]

        foreign_sess = next((s for s in sessions if s.get("country") == "Russia"), None)
        assert foreign_sess is not None
        assert foreign_sess["isSuspicious"] is True

        # Check 2FA is recognized as enabled
        assert data["twoFactorEnabled"] is True

        # Check that client.log_out was called in finally
        mock_client.log_out.assert_called_once()
        mock_client.disconnect.assert_called_once()

        # Check that the flow was purged from memory
        assert flow_id not in _flows


@pytest.mark.asyncio
async def test_analyze_impossible_travel_detection():
    mock_client = AsyncMock()
    mock_client.log_out = AsyncMock()
    mock_client.disconnect = AsyncMock()
    mock_client.get_me = AsyncMock(return_value=MagicMock(first_name="Traveler", last_name="", username=""))

    t0 = datetime.datetime.now(datetime.timezone.utc)
    t1 = t0 - datetime.timedelta(minutes=45)  # 45 minutes earlier

    sess1 = MagicMock()
    sess1.current = False
    sess1.device_model = "MacBook Pro"
    sess1.app_name = "Telegram macOS"
    sess1.app_version = "10.0"
    sess1.ip = "80.1.2.3"
    sess1.country = "Germany"
    sess1.date_active = t0
    sess1.official_app = True
    sess1.hash = 1

    sess2 = MagicMock()
    sess2.current = False
    sess2.device_model = "Windows PC"
    sess2.app_name = "Telegram Desktop"
    sess2.app_version = "4.15"
    sess2.ip = "139.130.4.5"
    sess2.country = "Australia"
    sess2.date_active = t1
    sess2.official_app = True
    sess2.hash = 2

    auth_res = MagicMock()
    auth_res.authorizations = [sess1, sess2]

    async def mock_call(req):
        if "GetAuthorizationsRequest" in type(req).__name__:
            return auth_res
        if "GetPasswordRequest" in type(req).__name__:
            pwd = MagicMock()
            pwd.has_password = True
            pwd.has_recovery = True
            return pwd
        return MagicMock()

    mock_client.side_effect = mock_call

    async def mock_iter(*args, **kwargs):
        if False:
            yield None

    mock_client.iter_messages = mock_iter

    flow_id = "flow-travel"
    flow = TelegramFlow(flow_id, "+447911123456", mock_client, "fake_hash")
    flow.status = "verified"
    _flows[flow_id] = flow

    with patch.object(settings, "TELEGRAM_API_ID", 12345), patch.object(
        settings, "TELEGRAM_API_HASH", "mock_hash"
    ):
        resp = client.post("/api/telegram/analyze", json={"flowId": flow_id})
        assert resp.status_code == 200
        data = resp.json()

        # Finding must include impossible travel
        findings = data["findings"]
        travel_finding = next((f for f in findings if f["type"] == "impossible_travel"), None)
        assert travel_finding is not None
        assert travel_finding["risk"] == "critical"
        assert "Physically Impossible Travel Detected" in travel_finding["title"]


@pytest.mark.asyncio
async def test_analyze_no_2fa_detected():
    mock_client = AsyncMock()
    mock_client.log_out = AsyncMock()
    mock_client.disconnect = AsyncMock()
    mock_client.get_me = AsyncMock(return_value=MagicMock(first_name="No2FA", last_name="", username=""))

    auth_res = MagicMock()
    auth_res.authorizations = []

    async def mock_call(req):
        if "GetAuthorizationsRequest" in type(req).__name__:
            return auth_res
        if "GetPasswordRequest" in type(req).__name__:
            pwd = MagicMock()
            pwd.has_password = False  # 2FA disabled
            return pwd
        return MagicMock()

    mock_client.side_effect = mock_call

    async def mock_iter(*args, **kwargs):
        if False:
            yield None

    mock_client.iter_messages = mock_iter

    flow_id = "flow-no2fa"
    flow = TelegramFlow(flow_id, "+14155552671", mock_client, "fake_hash")
    flow.status = "verified"
    _flows[flow_id] = flow

    with patch.object(settings, "TELEGRAM_API_ID", 12345), patch.object(
        settings, "TELEGRAM_API_HASH", "mock_hash"
    ):
        resp = client.post("/api/telegram/analyze", json={"flowId": flow_id})
        assert resp.status_code == 200
        data = resp.json()
        assert data["twoFactorEnabled"] is False

        findings = data["findings"]
        no_2fa_finding = next((f for f in findings if f["type"] == "no_2fa"), None)
        assert no_2fa_finding is not None
        assert "Two-Step Verification Password Is Off" in no_2fa_finding["title"]


# ---------------------------------------------------------------------------
# 6. Flow TTL Cleanup & Cancel Endpoint Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_flow_ttl_cleanup():
    mock_client = AsyncMock()
    mock_client.disconnect = AsyncMock()

    flow_id = "expired-flow"
    flow = TelegramFlow(flow_id, "+919876543210", mock_client)
    flow.created_at = time.time() - 700  # 700s ago (> 600s TTL)
    _flows[flow_id] = flow

    await cleanup_expired_flows()
    assert flow_id not in _flows
    mock_client.disconnect.assert_called_once()


def test_cancel_flow_endpoint():
    mock_client = AsyncMock()
    mock_client.disconnect = AsyncMock()

    flow_id = "cancel-flow-id"
    flow = TelegramFlow(flow_id, "+919876543210", mock_client)
    _flows[flow_id] = flow

    with patch.object(settings, "TELEGRAM_API_ID", 12345), patch.object(
        settings, "TELEGRAM_API_HASH", "mock_hash"
    ):
        resp = client.post("/api/telegram/cancel", json={"flowId": flow_id})
        assert resp.status_code == 200
        assert resp.json()["status"] == "cancelled"
        assert flow_id not in _flows


# ---------------------------------------------------------------------------
# 7. Rate Limiting Tests
# ---------------------------------------------------------------------------

def test_send_code_rate_limiting():
    mock_client = AsyncMock()
    mock_sent = MagicMock()
    mock_sent.phone_code_hash = "hash1"
    mock_client.send_code_request = AsyncMock(return_value=mock_sent)
    mock_client.connect = AsyncMock()

    with patch.object(settings, "TELEGRAM_API_ID", 12345), patch.object(
        settings, "TELEGRAM_API_HASH", "mock_hash"
    ), patch("telethon.TelegramClient", return_value=mock_client):
        # Allow 3 requests
        for i in range(3):
            r = client.post("/api/telegram/send-code", json={"phone": f"+91987654321{i}"})
            assert r.status_code == 200

        # 4th request must be rate limited (429)
        r4 = client.post("/api/telegram/send-code", json={"phone": "+919876543219"})
        assert r4.status_code == 429
        assert "Too many verification code requests" in r4.json()["detail"]
