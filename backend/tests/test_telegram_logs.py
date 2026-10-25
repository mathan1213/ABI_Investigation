import io
import json
import zipfile
import datetime
import pytest
from unittest.mock import AsyncMock, patch
from httpx import AsyncClient, ASGITransport

from main import app
from models import IpCheckResponse, LinkCheckResponse, DnsRecords
from modules.telegram_log_parser import redact_sensitive_codes


@pytest.fixture
def mock_network_tools():
    mock_ip = IpCheckResponse(
        ip="198.51.100.5",
        country="Germany",
        city="Frankfurt",
        isp="Hosting Provider",
        asn="AS12345",
        isVpn=True,
        isProxy=False,
        isTor=False,
        isHosting=True,
        abuseScore=65,
        verdict="Suspicious",
        riskLevel="medium",
        explanation="Commercial VPN endpoint",
        timestamp="2026-10-24T00:00:00Z"
    )
    mock_link = LinkCheckResponse(
        url="https://phish-telegram-verify.com",
        domain="phish-telegram-verify.com",
        domainAge="1 days",
        dnsRecords=DnsRecords(a=["1.2.3.4"]),
        sslValid=False,
        reputationScore=10,
        verdict="Dangerous",
        riskLevel="high",
        explanation="Phishing site mimicking Telegram",
        timestamp="2026-10-24T00:00:00Z"
    )
    with patch("modules.telegram_log_parser.inspect_ip", AsyncMock(return_value=mock_ip)), \
         patch("modules.telegram_log_parser.inspect_link", AsyncMock(return_value=mock_link)):
        yield


def test_login_code_immediate_redaction():
    text = "Your login code is 54912. Never share this code with anyone! Web code: 12345678."
    redacted = redact_sensitive_codes(text)
    assert "54912" not in redacted
    assert "12345678" not in redacted
    assert "****" in redacted


@pytest.mark.asyncio
async def test_analyze_sessions_json(mock_network_tools):
    sessions_payload = {
        "sessions": [
            {
                "device_model": "MacBook Pro M2",
                "application_name": "Telegram Desktop",
                "platform": "macOS 14.1",
                "ip": "103.21.244.1",
                "country": "India",
                "last_active": "2026-10-24T12:00:00Z"
            }
        ]
    }
    file_bytes = json.dumps(sessions_payload).encode("utf-8")

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        files = [("files", ("result.json", file_bytes, "application/json"))]
        resp = await ac.post("/api/telegram/logs/analyze", files=files)
        assert resp.status_code == 200
        data = resp.json()

        assert data["phone"] == "Uploaded Export"
        assert len(data["sessions"]) == 1
        assert data["sessions"][0]["device"] == "MacBook Pro M2"
        assert data["twoFactorEnabled"] is None  # Never claim 2FA is on or off
        assert len(data["manualChecks"]) >= 3
        assert "Snapshot exports cannot" in data["dataCoverage"]


@pytest.mark.asyncio
async def test_analyze_sessions_html(mock_network_tools):
    html_content = """
    <!DOCTYPE html>
    <html>
    <head><title>Active Sessions</title></head>
    <body>
        <h1>Active sessions</h1>
        <table class="sessions">
            <tr><th>Device</th><th>Application</th><th>IP</th><th>Location</th><th>Last active</th></tr>
            <tr><td>Dell XPS 15</td><td>Telegram Desktop</td><td>103.21.244.2</td><td>India</td><td>2026-10-24 10:00:00</td></tr>
        </table>
    </body>
    </html>
    """
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        files = [("files", ("sessions.html", html_content.encode("utf-8"), "text/html"))]
        resp = await ac.post("/api/telegram/logs/analyze", files=files)
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["sessions"]) == 1
        assert data["sessions"][0]["device"] == "Dell XPS 15"


@pytest.mark.asyncio
async def test_analyze_service_chat_json_redaction_and_alerts(mock_network_tools):
    chat_payload = {
        "id": 777000,
        "name": "Telegram",
        "type": "saved_messages",
        "messages": [
            {
                "id": 1,
                "type": "message",
                "date": "2026-10-24T08:00:00",
                "text": "Login code: 78945. Do not give this code to anyone."
            },
            {
                "id": 2,
                "type": "message",
                "date": "2026-10-24T08:05:00",
                "text": "Login alert: We detected a login to your account from a new device.\nDevice: Linux Workstation\nLocation: Germany\nIP: 198.51.100.5"
            }
        ]
    }
    file_bytes = json.dumps(chat_payload).encode("utf-8")

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        files = [("files", ("telegram_chat.json", file_bytes, "application/json"))]
        resp = await ac.post("/api/telegram/logs/analyze", files=files)
        assert resp.status_code == 200
        data = resp.json()
        assert data["detectedFiles"]["loginAlerts"] is True
        # Verify 78945 does NOT appear anywhere in the response
        resp_text = json.dumps(data)
        assert "78945" not in resp_text


@pytest.mark.asyncio
async def test_non_service_chat_ignored(mock_network_tools):
    personal_chat = {
        "id": 1234567,
        "name": "Personal Friend Chat",
        "type": "personal_chat",
        "messages": [
            {
                "id": 1,
                "text": "Hey check out this code 99999"
            }
        ]
    }
    file_bytes = json.dumps(personal_chat).encode("utf-8")

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        files = [("files", ("chat.json", file_bytes, "application/json"))]
        resp = await ac.post("/api/telegram/logs/analyze", files=files)
        # Should return 422 because personal chat was completely ignored and no valid telegram data exists!
        assert resp.status_code == 422
        assert "No recognizable Telegram export data" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_detection_rules_composite(mock_network_tools):
    # Rule 1: Unofficial app ("TelePlus")
    # Rule 2: Multi-country (India + Germany)
    # Rule 3: Impossible travel (< 3 hours between India and Germany)
    # Rule 5: Inactive session (> 30 days old)
    sessions_payload = {
        "sessions": [
            {
                "device_model": "Android Phone",
                "application_name": "TelePlus Unofficial Client",
                "ip": "103.21.244.1",
                "country": "India",
                "last_active": "2026-10-24T12:00:00Z"
            },
            {
                "device_model": "Chrome Browser",
                "application_name": "Telegram Web",
                "ip": "198.51.100.5",
                "country": "Germany",
                "last_active": "2026-10-24T13:30:00Z"  # 1.5 hours later -> Impossible travel!
            },
            {
                "device_model": "Old iPad",
                "application_name": "Telegram iOS",
                "ip": "103.21.244.3",
                "country": "India",
                "last_active": "2026-08-01T10:00:00Z"  # > 30 days inactive
            }
        ]
    }
    file_bytes = json.dumps(sessions_payload).encode("utf-8")

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        files = [("files", ("result.json", file_bytes, "application/json"))]
        resp = await ac.post("/api/telegram/logs/analyze", files=files)
        assert resp.status_code == 200
        data = resp.json()

        finding_types = [f["type"] for f in data["findings"]]
        assert "unofficial_app" in finding_types
        assert "foreign_login" in finding_types
        assert "impossible_travel" in finding_types
        assert "inactive_session" in finding_types
        assert data["riskLevel"] == "critical"  # Due to impossible travel


@pytest.mark.asyncio
async def test_zip_archive_processing(mock_network_tools):
    sessions_data = {
        "sessions": [
            {
                "device": "MacBook Air",
                "app": "Telegram Desktop",
                "ip": "103.21.244.1",
                "country": "India",
                "last_active": "2026-10-24T12:00:00Z"
            }
        ]
    }
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("export/sessions.json", json.dumps(sessions_data))

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        files = [("files", ("export.zip", zip_buffer.getvalue(), "application/zip"))]
        resp = await ac.post("/api/telegram/logs/analyze", files=files)
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["sessions"]) == 1


@pytest.mark.asyncio
async def test_zip_path_traversal_rejected():
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("../../etc/passwd", "root:x:0:0:")

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        files = [("files", ("evil.zip", zip_buffer.getvalue(), "application/zip"))]
        resp = await ac.post("/api/telegram/logs/analyze", files=files)
        assert resp.status_code == 400
        assert "path traversal" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_nested_zip_rejected():
    inner_buffer = io.BytesIO()
    with zipfile.ZipFile(inner_buffer, "w", zipfile.ZIP_DEFLATED) as zf_inner:
        zf_inner.writestr("test.txt", "hello")

    outer_buffer = io.BytesIO()
    with zipfile.ZipFile(outer_buffer, "w", zipfile.ZIP_DEFLATED) as zf_outer:
        zf_outer.writestr("nested.zip", inner_buffer.getvalue())

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        files = [("files", ("outer.zip", outer_buffer.getvalue(), "application/zip"))]
        resp = await ac.post("/api/telegram/logs/analyze", files=files)
        assert resp.status_code == 400
        assert "nested zip" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_zip_bomb_entry_limit():
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for i in range(205):
            zf.writestr(f"file_{i}.txt", "sample")

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        files = [("files", ("bomb.zip", zip_buffer.getvalue(), "application/zip"))]
        resp = await ac.post("/api/telegram/logs/analyze", files=files)
        assert resp.status_code == 400
        assert "entries" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_oversize_file_rejected():
    big_data = b"X" * (11 * 1024 * 1024)  # 11 MB > 10 MB limit
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        files = [("files", ("big.txt", big_data, "text/plain"))]
        resp = await ac.post("/api/telegram/logs/analyze", files=files)
        assert resp.status_code == 400
        assert "exceeds the maximum allowed size" in resp.json()["detail"].lower()
