import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from fastapi.testclient import TestClient
from main import app
from routers.network import _rate_limit_records

client = TestClient(app)

@pytest.fixture(autouse=True)
def reset_rate_limits():
    """Resets in-memory rate limiting before each test."""
    _rate_limit_records.clear()


# ---------------------------------------------------------------------------
# 1. Health Check Test
# ---------------------------------------------------------------------------

def test_health_check():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "version" in data


# ---------------------------------------------------------------------------
# 2. SSRF Protection Tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("blocked_ip", [
    "127.0.0.1",
    "10.0.0.1",
    "192.168.1.1",
    "172.16.0.1",
    "169.254.169.254",
    "0.0.0.0",
    "::1",
    "fe80::1",
])
def test_ssrf_blocking_ip_endpoint(blocked_ip):
    response = client.post("/api/network/ip", json={"ip": blocked_ip})
    assert response.status_code == 400
    assert "SSRF blocked" in response.json()["detail"] or "private" in response.json()["detail"]


@pytest.mark.parametrize("blocked_url", [
    "http://127.0.0.1:8000/admin",
    "http://localhost:5000/secret",
    "http://169.254.169.254/latest/meta-data/",
    "http://192.168.0.100/router",
])
def test_ssrf_blocking_link_endpoint(blocked_url):
    response = client.post("/api/network/link", json={"url": blocked_url})
    assert response.status_code == 400
    assert "SSRF blocked" in response.json()["detail"] or "private" in response.json()["detail"]


def test_ssrf_blocking_website_endpoint():
    response = client.post("/api/network/website", json={"domain": "127.0.0.1"})
    assert response.status_code == 400
    assert "SSRF blocked" in response.json()["detail"] or "private" in response.json()["detail"]


# ---------------------------------------------------------------------------
# 3. Input Validation Tests
# ---------------------------------------------------------------------------

def test_invalid_ip_format():
    response = client.post("/api/network/ip", json={"ip": "999.999.999.999"})
    assert response.status_code == 400
    assert "Invalid IP address format" in response.json()["detail"]


def test_invalid_ip_payload():
    response = client.post("/api/network/ip", json={})
    assert response.status_code == 422  # Pydantic validation error


def test_invalid_url_format():
    response = client.post("/api/network/link", json={"url": "htp:/broken"})
    # Host resolution will fail safely
    assert response.status_code in [400, 422]


# ---------------------------------------------------------------------------
# 4. IP Check Logic & Mocked Offline Verification
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_inspect_ip_safe_verdict():
    mock_ip_api_response = MagicMock()
    mock_ip_api_response.status_code = 200
    mock_ip_api_response.json.return_value = {
        "status": "success",
        "country": "United States",
        "city": "Mountain View",
        "isp": "Google LLC",
        "as": "AS15169 Google LLC",
        "proxy": False,
        "hosting": False,
    }

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_ip_api_response
        with patch("modules.network_module.get_tor_exit_nodes", new_callable=AsyncMock) as mock_tor:
            mock_tor.return_value = set()

            response = client.post("/api/network/ip", json={"ip": "8.8.8.8"})
            assert response.status_code == 200
            data = response.json()

            assert data["ip"] == "8.8.8.8"
            assert data["country"] == "United States"
            assert data["isTor"] is False
            assert data["isProxy"] is False
            assert data["verdict"] == "Safe"
            assert data["riskLevel"] == "low"
            assert data["abuseScore"] == 0
            assert "standard residential connection" in data["explanation"] or "Google LLC" in data["explanation"]


@pytest.mark.asyncio
async def test_inspect_ip_tor_dangerous_verdict():
    mock_ip_api_response = MagicMock()
    mock_ip_api_response.status_code = 200
    mock_ip_api_response.json.return_value = {
        "status": "success",
        "country": "Germany",
        "city": "Frankfurt",
        "isp": "Tor Exit ISP",
        "as": "AS12345 Tor",
        "proxy": True,
        "hosting": True,
    }

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_ip_api_response
        with patch("modules.network_module.get_tor_exit_nodes", new_callable=AsyncMock) as mock_tor:
            mock_tor.return_value = {"185.220.101.5"}

            response = client.post("/api/network/ip", json={"ip": "185.220.101.5"})
            assert response.status_code == 200
            data = response.json()

            assert data["isTor"] is True
            assert data["verdict"] == "Dangerous"
            assert data["riskLevel"] == "critical"
            assert data["abuseScore"] >= 75
            assert "Tor anonymizer exit node" in data["explanation"]


# ---------------------------------------------------------------------------
# 5. Link Check Logic & Mocked Offline Verification
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_inspect_link_mocked():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.is_redirect = False
    mock_resp.url = "https://example.com"
    mock_resp.headers = {}

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        with patch("modules.network_module.validate_hostname_or_ip") as mock_val:
            mock_val.return_value = ["93.184.216.34"]

            response = client.post("/api/network/link", json={"url": "https://example.com"})
            assert response.status_code == 200
            data = response.json()

            assert data["url"] == "https://example.com"
            assert data["domain"] == "example.com"
            assert "dnsRecords" in data
            assert "redirectChain" in data
            assert "reputationScore" in data
            assert data["verdict"] in ["Safe", "Suspicious", "Dangerous"]


# ---------------------------------------------------------------------------
# 6. Website Check Logic & Mocked Offline Verification
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_inspect_website_mocked():
    with patch("modules.network_module.validate_hostname_or_ip") as mock_val:
        mock_val.return_value = ["142.250.190.46"]
        with patch("modules.network_module.check_single_port", new_callable=AsyncMock) as mock_port:
            # Mock port 80 and 443 open, 22 and 21 closed
            async def fake_port_check(host, port):
                if port in (80, 443):
                    return (port, "Open")
                return (port, "Closed")
            mock_port.side_effect = fake_port_check

            response = client.post("/api/network/website", json={"domain": "google.com"})
            assert response.status_code == 200
            data = response.json()

            assert data["domain"] == "google.com"
            assert len(data["ports"]) == 4
            assert "securityHeaders" in data
            assert "sslExpiry" in data
            assert "riskScore" in data
            assert data["verdict"] in ["Safe", "Suspicious", "Dangerous"]


# ---------------------------------------------------------------------------
# 7. Rate Limiter Test
# ---------------------------------------------------------------------------

def test_rate_limiter_exceeded():
    import time
    _rate_limit_records["testclient"] = [time.time()] * 20  # 20 requests currently active in the window
    with patch("modules.network_module.inspect_ip", new_callable=AsyncMock) as mock_insp:
        mock_insp.return_value = MagicMock()
        response = client.post("/api/network/ip", json={"ip": "8.8.8.8"})
        assert response.status_code == 429
        assert "Rate limit exceeded" in response.json()["detail"]
