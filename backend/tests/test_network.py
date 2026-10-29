import pytest
import time
import datetime
from unittest.mock import patch, MagicMock, AsyncMock
from fastapi.testclient import TestClient
from main import app
from routers.network import _rate_limit_records
from modules.network_module import get_apex_domain, format_asn, detect_cdn

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
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# 4. Bug Fix 1 Tests: IP Check Accuracy & 8.8.8.8 Safe Guarantee
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_known_public_dns_8888_is_safe():
    """8.8.8.8 must come out Safe with 0 abuse score, isProxy=False, isVpn=False."""
    mock_geo = MagicMock()
    mock_geo.status_code = 200
    mock_geo.json.return_value = {
        "status": "success",
        "country": "United States",
        "city": "Ashburn",
        "isp": "Google LLC",
        "as": "AS15169 Google LLC",
        "proxy": False,
        "hosting": True,
    }

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_geo
        with patch("modules.network_module.get_tor_exit_nodes", new_callable=AsyncMock) as mock_tor:
            mock_tor.return_value = set()

            response = client.post("/api/network/ip", json={"ip": "8.8.8.8"})
            assert response.status_code == 200
            data = response.json()

            assert data["ip"] == "8.8.8.8"
            assert data["verdict"] == "Safe"
            assert data["riskLevel"] == "low"
            assert data["abuseScore"] == 0
            assert data["isVpn"] is False
            assert data["isProxy"] is False
            assert data["isTor"] is False
            assert data["isHosting"] is True
            assert "verified public infrastructure" in data["explanation"]


@pytest.mark.asyncio
async def test_hosting_ip_is_not_flagged_as_vpn():
    """Datacenter hosting without proxy flag should have low bump and not be marked VPN."""
    mock_geo = MagicMock()
    mock_geo.status_code = 200
    mock_geo.json.return_value = {
        "status": "success",
        "country": "Germany",
        "city": "Nuremberg",
        "isp": "Hetzner Online GmbH",
        "as": "AS24940 Hetzner",
        "proxy": False,
        "hosting": True,
    }

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_geo
        with patch("modules.network_module.get_tor_exit_nodes", new_callable=AsyncMock) as mock_tor:
            mock_tor.return_value = set()

            response = client.post("/api/network/ip", json={"ip": "159.69.1.1"})
            assert response.status_code == 200
            data = response.json()

            assert data["isProxy"] is False
            assert data["isVpn"] is False
            assert data["isHosting"] is True
            assert data["abuseScore"] == 10  # small bump for hosting only
            assert data["verdict"] == "Safe"
            assert "datacenter hosting" in data["explanation"]


@pytest.mark.asyncio
async def test_inspect_ip_tor_dangerous():
    mock_geo = MagicMock()
    mock_geo.status_code = 200
    mock_geo.json.return_value = {
        "status": "success",
        "country": "Germany",
        "city": "Frankfurt",
        "isp": "Tor Exit ISP",
        "as": "AS12345 Tor",
        "proxy": True,
        "hosting": True,
    }

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_geo
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
# 5. Bug Fix 2 Tests: Website Headers, Redirects & Accurate Explanation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_website_headers_from_final_redirect():
    """Security headers must be read from the final response after redirects, not the 301."""
    # First response: 301 with location
    resp1 = MagicMock()
    resp1.status_code = 301
    resp1.is_redirect = True
    resp1.headers = {"Location": "https://example.com/en"}

    # Second response: 200 with headers
    resp2 = MagicMock()
    resp2.status_code = 200
    resp2.is_redirect = False
    resp2.headers = {
        "strict-transport-security": "max-age=31536000",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        # Missing Content-Security-Policy & Referrer-Policy
    }

    with patch("modules.network_module.validate_hostname_or_ip") as mock_val:
        mock_val.return_value = ["93.184.216.34"]
        with patch("modules.network_module.check_single_port", new_callable=AsyncMock) as mock_port:
            async def fake_ports(host, p):
                return (p, "Open" if p in (80, 443) else "Closed")
            mock_port.side_effect = fake_ports

            with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
                mock_get.side_effect = [resp1, resp2]

                response = client.post("/api/network/website", json={"domain": "example.com"})
                assert response.status_code == 200
                data = response.json()

                # Verify headers read from final response (resp2)
                headers_map = {h["header"]: h["status"] for h in data["securityHeaders"]}
                assert headers_map["Strict-Transport-Security"] == "Pass"
                assert headers_map["X-Frame-Options"] == "Pass"
                assert headers_map["X-Content-Type-Options"] == "Pass"
                assert headers_map["Content-Security-Policy"] == "Fail"
                assert headers_map["Referrer-Policy"] == "Fail"

                # Missing headers alone: verdict stays Safe, riskLevel medium
                assert data["verdict"] == "Safe"
                assert data["riskLevel"] == "medium"
                assert "This site works safely but is missing 2 recommended hardening headers" in data["explanation"]
                assert "Content-Security-Policy" in data["explanation"]
                assert "Referrer-Policy" in data["explanation"]
                assert "HSTS may be enforced by the browser preload list" in data["explanation"]
                assert "well-hardened" not in data["explanation"]


@pytest.mark.asyncio
async def test_website_real_threat_signal_ports():
    """Real threat signals like exposed SSH port 22 make verdict Dangerous."""
    resp = MagicMock()
    resp.status_code = 200
    resp.is_redirect = False
    resp.headers = {
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
    }

    with patch("modules.network_module.validate_hostname_or_ip") as mock_val:
        mock_val.return_value = ["93.184.216.34"]
        with patch("modules.network_module.check_single_port", new_callable=AsyncMock) as mock_port:
            async def fake_ports(host, p):
                return (p, "Open" if p in (80, 443, 22) else "Closed")
            mock_port.side_effect = fake_ports

            with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
                mock_get.return_value = resp

                response = client.post("/api/network/website", json={"domain": "insecure.example.com"})
                assert response.status_code == 200
                data = response.json()

                assert data["verdict"] == "Dangerous"
                assert data["riskLevel"] == "critical"
                assert "administrative ports" in data["explanation"]


@pytest.mark.asyncio
async def test_website_all_headers_pass_is_well_hardened():
    """When all 5 headers pass, verdict must be Safe and say well-hardened."""
    resp = MagicMock()
    resp.status_code = 200
    resp.is_redirect = False
    resp.headers = {
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
    }

    with patch("modules.network_module.validate_hostname_or_ip") as mock_val:
        mock_val.return_value = ["93.184.216.34"]
        with patch("modules.network_module.check_single_port", new_callable=AsyncMock) as mock_port:
            async def fake_ports(host, p):
                return (p, "Open" if p in (80, 443) else "Closed")
            mock_port.side_effect = fake_ports

            with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
                mock_get.return_value = resp

                response = client.post("/api/network/website", json={"domain": "secure.example.com"})
                assert response.status_code == 200
                data = response.json()

                assert data["verdict"] == "Safe"
                assert data["riskLevel"] == "low"
                assert "well-hardened" in data["explanation"]


# ---------------------------------------------------------------------------
# 6. Bug Fix 3 Tests: Apex Domain DNS Lookup
# ---------------------------------------------------------------------------

def test_get_apex_domain_helper():
    assert get_apex_domain("www.google.com") == "google.com"
    assert get_apex_domain("sub.test.example.co.uk") == "example.co.uk"
    assert get_apex_domain("google.com") == "google.com"


@pytest.mark.asyncio
async def test_link_check_apex_dns_lookup():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.is_redirect = False
    mock_resp.url = "https://www.google.com"
    mock_resp.headers = {}

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        with patch("modules.network_module.validate_hostname_or_ip") as mock_val:
            mock_val.return_value = ["142.250.190.46"]

            resolved_domains = []
            mock_resolver = MagicMock()
            def fake_resolve(domain, rtype):
                resolved_domains.append((domain, rtype))
                ans = MagicMock()
                ans.to_text.return_value = "1.2.3.4"
                return [ans]
            mock_resolver.resolve.side_effect = fake_resolve

            with patch("dns.resolver.Resolver", return_value=mock_resolver):
                response = client.post("/api/network/link", json={"url": "https://www.google.com"})
                assert response.status_code == 200
                data = response.json()

                # Verify A record was queried on actual host (www.google.com)
                a_queries = [d for d, r in resolved_domains if r == "A"]
                assert "www.google.com" in a_queries

                # Verify MX, NS, TXT were queried on apex domain (google.com)
                apex_queries = [d for d, r in resolved_domains if r in ("MX", "NS", "TXT")]
                assert all(d == "google.com" for d in apex_queries)


# ---------------------------------------------------------------------------
# 7. Rate Limiter Test
# ---------------------------------------------------------------------------

def test_rate_limiter_exceeded():
    _rate_limit_records["testclient"] = [time.time()] * 20
    with patch("modules.network_module.inspect_ip", new_callable=AsyncMock) as mock_insp:
        mock_insp.return_value = MagicMock()
        response = client.post("/api/network/ip", json={"ip": "8.8.8.8"})
        assert response.status_code == 429
        assert "Rate limit exceeded" in response.json()["detail"]


# ---------------------------------------------------------------------------
# 8. Network Check Accuracy & Wording Tests (8 Specific Coverage Tests)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_no_residential_wording_in_ip_check():
    """1. Remove every claim that an IP is residential. Use 'Internet provider network' instead."""
    mock_geo_home = MagicMock()
    mock_geo_home.status_code = 200
    mock_geo_home.json.return_value = {
        "status": "success",
        "country": "United States",
        "city": "Dallas",
        "isp": "AT&T Internet Services",
        "as": "AS7018 AT&T Services",
        "proxy": False,
        "hosting": False,
    }
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_geo_home
        with patch("modules.network_module.get_tor_exit_nodes", new_callable=AsyncMock) as mock_tor:
            mock_tor.return_value = set()
            resp = client.post("/api/network/ip", json={"ip": "12.34.56.78"})
            assert resp.status_code == 200
            data = resp.json()
            text_dump = str(data).lower()
            assert "residential" not in text_dump
            assert "broadband" not in text_dump
            assert "internet provider network" in data["explanation"].lower()


@pytest.mark.asyncio
async def test_abuse_wording_without_key():
    """2. When ABUSEIPDB_KEY is unset: rename to estimated score, note DBs not checked, never write 'zero reports'."""
    mock_geo = MagicMock()
    mock_geo.status_code = 200
    mock_geo.json.return_value = {
        "status": "success",
        "country": "United States",
        "city": "Austin",
        "isp": "Local ISP",
        "as": "AS12345 Local ISP",
        "proxy": False,
        "hosting": False,
    }
    with patch("config.settings.ABUSEIPDB_KEY", ""):
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_geo
            with patch("modules.network_module.get_tor_exit_nodes", new_callable=AsyncMock) as mock_tor:
                mock_tor.return_value = set()
                resp = client.post("/api/network/ip", json={"ip": "93.184.216.34"})
                assert resp.status_code == 200
                data = resp.json()
                assert data["abuseDbChecked"] is False
                assert data["totalReports"] is None
                assert "Abuse report databases were not checked" in data["explanation"]
                assert "zero reports" not in data["explanation"].lower()
                assert "no reports of malicious activity" not in data["explanation"].lower()


@pytest.mark.asyncio
async def test_zero_redirect_counting():
    """3. Direct link is 0 redirects (only count actual 3xx codes, fix off-by-one)."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.is_redirect = False
    mock_resp.url = "https://example.com"
    mock_resp.headers = {"server": "nginx"}
    mock_resp.text = "<html><head><title>Test</title></head><body>Hello</body></html>"

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        with patch("modules.network_module.validate_hostname_or_ip") as mock_val:
            mock_val.return_value = ["93.184.216.34"]
            with patch("dns.resolver.Resolver"):
                resp = client.post("/api/network/link", json={"url": "https://example.com"})
                assert resp.status_code == 200
                data = resp.json()
                assert data["redirectCount"] == 0
                assert len(data["redirectChain"]) == 1
                assert "Direct connection" in data["redirectChain"][0]["note"]


@pytest.mark.asyncio
async def test_cloudflare_cdn_detection():
    """4. Detect Cloudflare CIDR range and headers, show edge disclaimer note."""
    cdn = detect_cdn({"cf-ray": "12345abcde"}, ["104.16.1.1"])
    assert cdn == "Cloudflare"

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.is_redirect = False
    mock_resp.url = "https://cloudflare-site.com"
    mock_resp.headers = {"server": "cloudflare", "cf-ray": "87654321"}
    mock_resp.text = "<html><body>Protected by CF</body></html>"

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        with patch("modules.network_module.validate_hostname_or_ip") as mock_val:
            mock_val.return_value = ["104.16.1.1"]
            with patch("dns.resolver.Resolver"):
                resp = client.post("/api/network/link", json={"url": "https://cloudflare-site.com"})
                assert resp.status_code == 200
                data = resp.json()
                assert data["cdnDetected"] == "Cloudflare"
                assert "Cloudflare" in data["cdnNote"]
                assert "The SSL certificate and headers shown belong to the CDN" in data["cdnNote"]


@pytest.mark.asyncio
async def test_blocked_403_inconclusive():
    """5. Blocked responses (401/403/429/503) must be marked Inconclusive, never Safe."""
    mock_resp = MagicMock()
    mock_resp.status_code = 403
    mock_resp.is_redirect = False
    mock_resp.url = "https://protected-site.com"
    mock_resp.headers = {"server": "cloudflare"}
    mock_resp.text = "<html><title>Access Denied / 403 Forbidden</title><body>Forbidden</body></html>"

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        with patch("modules.network_module.validate_hostname_or_ip") as mock_val:
            mock_val.return_value = ["104.16.1.1"]
            with patch("dns.resolver.Resolver"):
                resp = client.post("/api/network/link", json={"url": "https://protected-site.com"})
                assert resp.status_code == 200
                data = resp.json()
                assert data["isInconclusive"] is True
                assert data["verdict"] == "Suspicious"
                assert data["verdict"] != "Safe"
                assert data["riskLevel"] == "medium"
                assert data["reputationScore"] <= 60
                assert "Inconclusive: the site blocked automated checks" in data["explanation"]
                assert "HTTP 403" in data["explanation"]


@pytest.mark.asyncio
async def test_score_cap_without_virustotal():
    """6. Without VIRUSTOTAL_KEY, technical checks score capped at 85, no 'clean reputation' claim."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.is_redirect = False
    mock_resp.url = "https://safe-domain.org"
    mock_resp.headers = {"server": "apache"}
    mock_resp.text = "<html><body>Clean Domain</body></html>"

    mock_whois = MagicMock()
    mock_whois.creation_date = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1200)

    with patch("config.settings.VIRUSTOTAL_KEY", ""):
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            with patch("modules.network_module.validate_hostname_or_ip") as mock_val:
                mock_val.return_value = ["93.184.216.34"]
                with patch("dns.resolver.Resolver"):
                    with patch("whois.whois", return_value=mock_whois):
                        resp = client.post("/api/network/link", json={"url": "https://safe-domain.org"})
                        assert resp.status_code == 200
                        data = resp.json()
                        assert data["reputationChecked"] is False
                        assert data["reputationScore"] <= 85
                        assert "Reputation databases were not checked" in data["explanation"]
                        assert "clean reputation" not in data["explanation"].lower()


@pytest.mark.asyncio
async def test_domain_age_unknown_on_whois_failure():
    """7. WHOIS failure results in 'Domain age: unknown' without 40-point score deduction."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.is_redirect = False
    mock_resp.url = "https://cctld-restricted.de"
    mock_resp.headers = {}
    mock_resp.text = "<html><body>German site</body></html>"

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        with patch("modules.network_module.validate_hostname_or_ip") as mock_val:
            mock_val.return_value = ["93.184.216.34"]
            with patch("dns.resolver.Resolver"):
                with patch("whois.whois", side_effect=Exception("WHOIS connection failed")):
                    resp = client.post("/api/network/link", json={"url": "https://cctld-restricted.de"})
                    assert resp.status_code == 200
                    data = resp.json()
                    assert data["domainAgeDays"] is None
                    assert "Domain age: unknown" in data["domainAge"]
                    assert "WHOIS query unavailable or registry restricted" in data["domainAge"]
                    assert data["reputationScore"] >= 70


def test_generic_asn_label_replacement():
    """8. Generic ASN descriptions are replaced with organization or ISP name."""
    formatted = format_asn("AS12345 AS Number for Interdomain Routing", isp="MegaCorp Fiber", org="MegaCorp LLC")
    assert formatted == "AS12345 - MegaCorp LLC"

    formatted_org = format_asn("AS67890 AS-BLOCK", isp="Acme ISP", org="")
    assert formatted_org == "AS67890 - Acme ISP"

    formatted_clean = format_asn("AS15169 Google LLC", isp="Google LLC", org="Google LLC")
    assert formatted_clean == "AS15169 - Google LLC"
