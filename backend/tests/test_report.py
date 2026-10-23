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
    "riskScore": 0,
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
    "counts": {"critical": 1, "high": 0, "medium": 0, "low": 0, "total": 1},
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

def test_report_no_modules_scanned_not_enough_data():
    resp = client.post("/api/report/generate", json={})
    assert resp.status_code == 200
    data = resp.json()
    assert data["overallScore"] is None
    assert data["overallRisk"] is None
    assert "not enough real data to calculate an overall score" in data["summary"].lower()
    assert len(data["limitations"]) >= 3  # All 3 modules noted as unscanned


def test_report_all_demo_modules_returns_no_score():
    resp = client.post(
        "/api/report/generate",
        json={
            "telegram": MOCK_TELEGRAM_CRITICAL,
            "demoModules": ["telegram"],
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["overallScore"] is None
    assert data["overallRisk"] is None
    assert "not enough real data to calculate an overall score" in data["summary"].lower()


def test_report_single_real_module_formula():
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
    assert repo_mod["isDemo"] is False
    tg_mod = next(m for m in data["modules"] if m["module"] == "telegram")
    assert tg_mod["scanned"] is False


def test_report_demo_exclusion_from_score():
    # Telegram is Demo with score 90 (critical finding)
    # Repo is Real with score 20 (low, no critical finding)
    # Overall score must come ONLY from Repo (score 20, low)
    # Demo Telegram must NOT drive score or force High
    repo_low = dict(MOCK_REPO_MEDIUM)
    repo_low["riskScore"] = 20
    repo_low["riskLevel"] = "low"

    resp = client.post(
        "/api/report/generate",
        json={
            "telegram": MOCK_TELEGRAM_CRITICAL,
            "repo": repo_low,
            "demoModules": ["telegram"],
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["overallScore"] == 20
    assert data["overallRisk"] == "low"  # NOT elevated by demo critical finding!


def test_report_multi_module_formula():
    # Telegram (score 80, 1 finding) + Repo (score 40, 2 findings)
    # Highest: 80, Avg: (80 + 40) / 2 = 60
    # Formula: 0.5 * 80 + 0.5 * 60 = 40 + 30 = 70
    resp = client.post(
        "/api/report/generate",
        json={"telegram": MOCK_TELEGRAM_CRITICAL, "repo": MOCK_REPO_MEDIUM},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["overallScore"] == 70
    assert data["overallRisk"] in ("high", "critical")


def test_report_critical_finding_forces_at_least_high():
    # Real Telegram has Critical finding, but score is 20
    low_score_tg_with_critical_finding = dict(MOCK_TELEGRAM_CRITICAL)
    low_score_tg_with_critical_finding["riskScore"] = 20
    low_score_tg_with_critical_finding["riskLevel"] = "low"

    resp = client.post(
        "/api/report/generate",
        json={"telegram": low_score_tg_with_critical_finding},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["overallRisk"] in ("high", "critical")


# ---------------------------------------------------------------------------
# 2. Evidence-Based Narrative & Hedged Language Tests
# ---------------------------------------------------------------------------

def test_report_no_cross_module_narrative():
    # Both Telegram and Repo have findings.
    # The narrative MUST NOT link repo leak to Telegram compromise.
    resp = client.post(
        "/api/report/generate",
        json={
            "telegram": MOCK_TELEGRAM_CRITICAL,
            "repo": MOCK_REPO_CRITICAL,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    explanations = data["howItHappened"]

    # Explanations must be partitioned by module prefix
    has_tg = any(exp.startswith("Telegram:") for exp in explanations)
    has_repo = any(exp.startswith("Repository:") for exp in explanations)
    assert has_tg is True
    assert has_repo is True

    # Confirm repo leak is not claimed as the cause of telegram compromise
    for exp in explanations:
        if "Repository:" in exp:
            assert "telegram" not in exp.lower()
            assert "sms" not in exp.lower()
            assert "sim" not in exp.lower()


def test_report_hedged_wording():
    resp = client.post(
        "/api/report/generate",
        json={
            "telegram": MOCK_TELEGRAM_CRITICAL,
            "repo": MOCK_REPO_CRITICAL,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    explanations = " ".join(data["howItHappened"]).lower()

    # Must contain hedged words
    assert any(h in explanations for h in ["may", "could", "is consistent with"])
    # Must NOT assert absolute breach facts
    assert "gained access" not in explanations
    assert "gained complete access" not in explanations
    assert "breached your perimeter" not in explanations


def test_report_summary_compromise_vs_credentials():
    # Only Repo has leaked secrets (no Telegram)
    resp = client.post(
        "/api/report/generate",
        json={"repo": MOCK_REPO_CRITICAL},
    )
    assert resp.status_code == 200
    data = resp.json()
    summary = data["summary"].lower()
    # Must describe as exposed credentials, NOT account compromise
    assert "exposed credentials" in summary
    assert "active compromise indicators" not in summary

    # Real Telegram has unknown session
    resp_tg = client.post(
        "/api/report/generate",
        json={"telegram": MOCK_TELEGRAM_CRITICAL},
    )
    assert resp_tg.status_code == 200
    data_tg = resp_tg.json()
    assert "active compromise indicators" in data_tg["summary"].lower()


# ---------------------------------------------------------------------------
# 3. 2FA Step Text and Priority Tests
# ---------------------------------------------------------------------------

def test_report_2fa_missing_step_text_and_priority():
    # Telegram with 2FA disabled
    resp = client.post(
        "/api/report/generate",
        json={"telegram": MOCK_TELEGRAM_CRITICAL},
    )
    assert resp.status_code == 200
    data = resp.json()
    actions = data["whatToDoNow"]

    # Must contain 2FA setup step with High priority
    two_fa_step = next(
        (a for a in actions if "Turn on two-step verification and add a recovery email" in a["title"]),
        None,
    )
    assert two_fa_step is not None
    assert two_fa_step["priority"] == "high"

    # Must NOT suggest changing password when 2FA is off
    assert not any("change your two-step verification password" in a["title"].lower() for a in actions)


def test_report_2fa_enabled_suggests_change_password():
    tg_with_2fa = dict(MOCK_TELEGRAM_CRITICAL)
    tg_with_2fa["twoFactorEnabled"] = True

    resp = client.post(
        "/api/report/generate",
        json={"telegram": tg_with_2fa},
    )
    assert resp.status_code == 200
    data = resp.json()
    actions = data["whatToDoNow"]

    # When 2FA is already ON and suspicious login exists, suggest changing password
    change_pw_step = next(
        (a for a in actions if "Change your two-step verification password" in a["title"]),
        None,
    )
    assert change_pw_step is not None
    assert change_pw_step["priority"] == "high"


# ---------------------------------------------------------------------------
# 4. Consistency Warning: Score vs Findings Count
# ---------------------------------------------------------------------------

def test_report_score_finding_inconsistency_warning():
    inconsistent_repo = dict(MOCK_REPO_MEDIUM)
    inconsistent_repo["riskScore"] = 75
    inconsistent_repo["findings"] = []  # Score 75 but 0 findings!

    resp = client.post(
        "/api/report/generate",
        json={"repo": inconsistent_repo},
    )
    assert resp.status_code == 200
    data = resp.json()
    limitations = data["limitations"]

    # Must return a warning naming the module
    warning = next((w for w in limitations if "GitHub Repository Forensics" in w and "inconsistent" in w), None)
    assert warning is not None
    assert "score (75)" in warning or "score of 75" in warning


# ---------------------------------------------------------------------------
# 5. De-duplication and Rate Limiting
# ---------------------------------------------------------------------------

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


def test_report_body_size_limit_exceeded():
    huge_padding = "x" * (1024 * 1024 + 100)  # > 1 MB
    resp = client.post(
        "/api/report/generate",
        content=json.dumps({"telegram": None, "padding": huge_padding}),
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 413
    assert "1 MB" in resp.json()["detail"]


def test_report_rate_limiting():
    for _ in range(20):
        r = client.post("/api/report/generate", json={})
        assert r.status_code == 200

    # 21st request must return 429
    r21 = client.post("/api/report/generate", json={})
    assert r21.status_code == 429
    assert "Too many report requests" in r21.json()["detail"]
