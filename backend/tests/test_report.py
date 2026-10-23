import json
import pytest
from fastapi.testclient import TestClient

from main import app
from routers.report import reset_rate_limits

client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_test_rate_limits():
    reset_rate_limits()
    yield
    reset_rate_limits()


# Sample Mock Objects for Testing
MOCK_TELEGRAM_CLEAN = {
    "phone": "+91*****7890",
    "accountName": "Alice Smith",
    "riskScore": 10,
    "riskLevel": "low",
    "summary": "Account clean",
    "sessions": [
        {
            "id": "s1",
            "device": "iPhone 15",
            "app": "Telegram iOS",
            "ip": "103.21.244.1",
            "country": "India",
            "lastActive": "Just now",
            "isSuspicious": False,
            "isCurrent": True,
        }
    ],
    "findings": [],
    "howItHappened": "Clean account",
    "actionChecklist": ["Maintain Two-Step Verification"],
    "timestamp": "2026-10-24T00:00:00Z",
    "twoFactorEnabled": True,
}

MOCK_TELEGRAM_CRITICAL = {
    "phone": "+91*****7890",
    "accountName": "Alice Smith",
    "riskScore": 80,
    "riskLevel": "critical",
    "summary": "Compromised account",
    "sessions": [
        {
            "id": "s1",
            "device": "Linux Host",
            "app": "Custom Client",
            "ip": "185.220.101.5",
            "country": "Germany",
            "lastActive": "10 minutes ago",
            "isSuspicious": True,
            "flagNote": "Confirmed Tor exit node",
        }
    ],
    "findings": [
        {
            "id": "f1",
            "type": "unknown_device",
            "title": "Tor Node Logged In",
            "explanation": "Active Tor node access",
            "risk": "critical",
        }
    ],
    "howItHappened": "Compromised",
    "actionChecklist": [
        "Open Telegram Settings > Devices > Tap 'Terminate All Other Sessions' immediately."
    ],
    "timestamp": "2026-10-24T00:00:00Z",
    "twoFactorEnabled": False,
}

MOCK_REPO_MEDIUM = {
    "repoUrl": "https://github.com/test/repo",
    "repoName": "test/repo",
    "riskScore": 40,
    "riskLevel": "medium",
    "summary": "Some issues",
    "counts": {"critical": 0, "high": 0, "medium": 2, "low": 1, "total": 3},
    "findings": [
        {
            "id": "rf1",
            "category": "dependencies",
            "severity": "medium",
            "title": "Outdated Package",
            "filePath": "requirements.txt",
            "lineNumber": 1,
            "explanation": "Outdated version",
            "suggestedFix": "Upgrade package",
        },
        {
            "id": "rf2",
            "category": "network",
            "severity": "medium",
            "title": "Insecure HTTP URL in Code",
            "filePath": "api.py",
            "lineNumber": 10,
            "explanation": "Used http://insecure-api.internal",
            "suggestedFix": "Use HTTPS",
        },
    ],
    "timestamp": "2026-10-24T00:00:00Z",
    "branch": "main",
    "scannedFilesCount": 10,
}

MOCK_REPO_CRITICAL = {
    "repoUrl": "https://github.com/test/leaked",
    "repoName": "test/leaked",
    "riskScore": 90,
    "riskLevel": "critical",
    "summary": "Leaked secret",
    "counts": {"critical": 1, "high": 1, "medium": 0, "low": 0, "total": 2},
    "findings": [
        {
            "id": "rf-sec-1",
            "category": "secrets",
            "severity": "critical",
            "title": "Leaked AWS Secret Key",
            "filePath": "config.py",
            "lineNumber": 5,
            "explanation": "Hardcoded secret",
            "suggestedFix": "Roll secret immediately",
        }
    ],
    "timestamp": "2026-10-24T00:00:00Z",
    "branch": "main",
    "scannedFilesCount": 5,
}

MOCK_NETWORK_CHECK = {
    "ipResult": {
        "ip": "185.220.101.5",
        "country": "Germany",
        "city": "Frankfurt",
        "isp": "Tor Exit Service",
        "asn": "AS12345",
        "isVpn": True,
        "isProxy": True,
        "isTor": True,
        "abuseScore": 85,
        "verdict": "Dangerous",
        "riskLevel": "critical",
        "explanation": "Active Tor node",
        "timestamp": "2026-10-24T00:00:00Z",
    },
    "websiteResult": {
        "domain": "test.com",
        "ports": [
            {
                "port": 22,
                "service": "SSH",
                "state": "Open",
                "risk": "high",
                "note": "Exposed SSH port",
            }
        ],
        "sslExpiry": "Valid",
        "sslDaysRemaining": 120,
        "securityHeaders": [],
        "riskScore": 60,
        "riskLevel": "high",
        "verdict": "Suspicious",
        "explanation": "Port 22 open",
        "timestamp": "2026-10-24T00:00:00Z",
    },
}


# ---------------------------------------------------------------------------
# 1. Formula & Missing Modules Tests
# ---------------------------------------------------------------------------

def test_report_no_modules_scanned():
    resp = client.post("/api/report/generate", json={})
    assert resp.status_code == 200
    data = resp.json()
    assert data["overallScore"] == 0
    assert data["overallRisk"] == "low"
    assert len(data["limitations"]) >= 3  # All 3 modules noted as unscanned


def test_report_single_module_formula():
    # Only Repo scanned (score 40)
    # 0.5 * 40 + 0.5 * 40 = 40
    resp = client.post(
        "/api/report/generate",
        json={"repo": MOCK_REPO_MEDIUM, "telegram": None, "network": None},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["overallScore"] == 40
    assert data["overallRisk"] == "medium"
    repo_mod = next(m for m in data["modules"] if m["module"] == "repo")
    assert repo_mod["scanned"] is True
    assert repo_mod["score"] == 40
    tg_mod = next(m for m in data["modules"] if m["module"] == "telegram")
    assert tg_mod["scanned"] is False


def test_report_multi_module_formula():
    # Telegram clean (score 10) + Repo medium (score 40)
    # Highest: 40, Avg: (10 + 40) / 2 = 25
    # Formula: 0.5 * 40 + 0.5 * 25 = 20 + 12.5 = 32.5 -> round to 32 or 33
    resp = client.post(
        "/api/report/generate",
        json={"telegram": MOCK_TELEGRAM_CLEAN, "repo": MOCK_REPO_MEDIUM},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["overallScore"] in (32, 33)
    assert data["overallRisk"] == "medium"


def test_report_critical_finding_forces_at_least_high():
    # Telegram has Critical finding, but score is 20 (low/medium score)
    low_score_tg_with_critical_finding = dict(MOCK_TELEGRAM_CRITICAL)
    low_score_tg_with_critical_finding["riskScore"] = 20
    low_score_tg_with_critical_finding["riskLevel"] = "low"

    resp = client.post(
        "/api/report/generate",
        json={"telegram": low_score_tg_with_critical_finding},
    )
    assert resp.status_code == 200
    data = resp.json()
    # Even though score is 20 (normally low), critical finding must force overallRisk to at least "high"
    assert data["overallRisk"] in ("high", "critical")


def test_report_all_modules_present():
    resp = client.post(
        "/api/report/generate",
        json={
            "telegram": MOCK_TELEGRAM_CRITICAL,
            "repo": MOCK_REPO_CRITICAL,
            "network": MOCK_NETWORK_CHECK,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["overallScore"] >= 75
    assert data["overallRisk"] == "critical"
    assert len(data["howItHappened"]) >= 2
    assert len(data["whatToDoNow"]) >= 2
    assert len(data["networkFindings"]) >= 2


# ---------------------------------------------------------------------------
# 2. De-duplication Tests
# ---------------------------------------------------------------------------

def test_report_deduplication_network_findings():
    resp = client.post(
        "/api/report/generate",
        json={
            "telegram": MOCK_TELEGRAM_CRITICAL,
            "repo": MOCK_REPO_MEDIUM,
            "network": MOCK_NETWORK_CHECK,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    net_findings = data["networkFindings"]
    titles = [f["title"] for f in net_findings]
    # Verify titles are unique
    assert len(titles) == len(set(titles))


def test_report_action_plan_deduplication_and_limit():
    resp = client.post(
        "/api/report/generate",
        json={
            "telegram": MOCK_TELEGRAM_CRITICAL,
            "repo": MOCK_REPO_CRITICAL,
            "network": MOCK_NETWORK_CHECK,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    actions = data["whatToDoNow"]
    assert len(actions) <= 10
    titles = [a["title"] for a in actions]
    assert len(titles) == len(set(titles))


# ---------------------------------------------------------------------------
# 3. Demo Flag Handling Tests
# ---------------------------------------------------------------------------

def test_report_demo_modules_flag():
    resp = client.post(
        "/api/report/generate",
        json={
            "telegram": MOCK_TELEGRAM_CLEAN,
            "demoModules": ["telegram"],
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    tg_mod = next(m for m in data["modules"] if m["module"] == "telegram")
    assert tg_mod["isDemo"] is True
    assert "demo" in data["summary"].lower()
    assert any("DEMO DATA" in limit for limit in data["limitations"])


# ---------------------------------------------------------------------------
# 4. Body Size Limit (1 MB) Test
# ---------------------------------------------------------------------------

def test_report_body_size_limit_exceeded():
    huge_padding = "x" * (1024 * 1024 + 100)  # > 1 MB
    resp = client.post(
        "/api/report/generate",
        content=json.dumps({"telegram": None, "padding": huge_padding}),
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 413
    assert "1 MB" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# 5. Rate Limiting Test
# ---------------------------------------------------------------------------

def test_report_rate_limiting():
    # Allow 20 requests per minute
    for i in range(20):
        r = client.post("/api/report/generate", json={})
        assert r.status_code == 200

    # 21st request must return 429
    r21 = client.post("/api/report/generate", json={})
    assert r21.status_code == 429
    assert "Too many report requests" in r21.json()["detail"]
