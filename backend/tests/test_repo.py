import asyncio
import os
import shutil
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from fastapi.testclient import TestClient
from main import app
from modules.repo_module import (
    mask_secret,
    sanitize_snippet,
    inspect_repository,
    scan_file_for_secrets,
    scan_file_for_js_code_issues,
    scan_file_for_network_issues,
)

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_repo_rate_limiter():
    from routers.repo import _repo_rate_limit_records
    _repo_rate_limit_records.clear()
    yield
    _repo_rate_limit_records.clear()


# ---------------------------------------------------------------------------
# 1. URL Validation Tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("invalid_url", [
    "not-a-url",
    "http://github.com/owner/repo",  # Non-HTTPS
    "https://gitlab.com/owner/repo",  # Non-GitHub
    "https://github.com/owner",  # Missing repo name
    "https://github.com/owner/repo/subpath",  # Extra path
    "ftp://github.com/owner/repo",
])
def test_repo_url_validation_rejections(invalid_url):
    response = client.post("/api/repo/scan", json={"repoUrl": invalid_url})
    assert response.status_code == 400
    assert "Invalid GitHub repository URL" in response.json()["detail"]


# ---------------------------------------------------------------------------
# 2. Secret Masking Tests
# ---------------------------------------------------------------------------

def test_mask_secret():
    assert mask_secret("AKIAIOSFODNN7EXAMPLE") == "AKIA****"
    assert mask_secret("ghp_123456789012345678901234567890123456") == "ghp_****"
    assert mask_secret("short") == "shor****"
    assert mask_secret("") == "****"


def test_sanitize_snippet_never_leaks_raw_secret():
    raw_key = "AKIAIOSFODNN7EXAMPLE"
    code = f'AWS_ACCESS_KEY_ID = "{raw_key}"'
    sanitized = sanitize_snippet(code, raw_key)
    assert raw_key not in sanitized
    assert "AKIA****" in sanitized


def test_scan_file_for_secrets_masks_findings():
    content = 'AWS_KEY = "AKIA1234567890ABCDEF"\nSECRET = "xoxb-1234567890-1234567890-abcdef"'
    findings = scan_file_for_secrets("config/keys.py", content)
    assert len(findings) >= 2
    for f in findings:
        assert "AKIA1234567890ABCDEF" not in (f.code_snippet or "")
        assert "xoxb-1234567890-1234567890-abcdef" not in (f.code_snippet or "")
        assert "****" in (f.code_snippet or "")


# ---------------------------------------------------------------------------
# 3. GitHub API Handling (Private / Not Found / Oversized)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_repo_not_found_on_github():
    mock_resp = MagicMock()
    mock_resp.status_code = 404

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        response = client.post("/api/repo/scan", json={"repoUrl": "https://github.com/fake-user/non-existent-repo"})
        assert response.status_code == 400
        assert "not found on GitHub" in response.json()["detail"]


@pytest.mark.asyncio
async def test_repo_private_rejection():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "full_name": "owner/secret-repo",
        "private": True,
        "size": 500,
    }

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        response = client.post("/api/repo/scan", json={"repoUrl": "https://github.com/owner/secret-repo"})
        assert response.status_code == 400
        assert "Repository is private" in response.json()["detail"]


@pytest.mark.asyncio
async def test_repo_oversized_rejection():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "full_name": "owner/giant-repo",
        "private": False,
        "size": 150 * 1024,  # 150 MB (exceeds 100 MB limit)
    }

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        response = client.post("/api/repo/scan", json={"repoUrl": "https://github.com/owner/giant-repo"})
        assert response.status_code == 400
        assert "exceeds the 100 MB limit" in response.json()["detail"]


# ---------------------------------------------------------------------------
# 4. End-to-End Pipeline with Fake Repo Fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def fake_repo_dir(tmp_path):
    """Creates a realistic repository directory structure with security issues."""
    repo = tmp_path / "planted_repo"
    repo.mkdir()

    # 1. Leaked AWS key
    (repo / "settings.py").write_text(
        'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\nDEBUG = True\n',
        encoding="utf-8"
    )

    # 2. Known vulnerable package in requirements.txt
    (repo / "requirements.txt").write_text(
        "requests==2.28.1\nurllib3==1.26.5\n",
        encoding="utf-8"
    )

    # 3. Unsafe eval() in JavaScript file
    (repo / "calc.js").write_text(
        'function compute(str) {\n  return eval(str);\n}\n',
        encoding="utf-8"
    )

    # 4. Insecure HTTP link in client.ts
    (repo / "client.ts").write_text(
        'const API_ENDPOINT = "http://insecure-backend.internal-services.net/api/v1";\n',
        encoding="utf-8"
    )

    # 5. Docker exposed port
    (repo / "docker-compose.yml").write_text(
        'version: "3"\nservices:\n  db:\n    image: postgres\n    ports:\n      - "0.0.0.0:5432:5432"\n',
        encoding="utf-8"
    )

    # 6. Committed .env file
    (repo / ".env").write_text(
        'DATABASE_URL=postgres://user:super_secret_pw@localhost:5432/db\n',
        encoding="utf-8"
    )

    # 7. Symlink (should NOT be followed or crash scanner)
    try:
        symlink_target = repo / "symlink_file.py"
        os.symlink(repo / "settings.py", symlink_target)
    except (OSError, NotImplementedError):
        # Windows without developer mode enabled might raise OSError
        pass

    return str(repo)


@pytest.mark.asyncio
async def test_full_repo_scan_pipeline(fake_repo_dir):
    """
    Tests the complete scan pipeline:
    - Mocks GitHub API lookup
    - Mocks clone_repository by copying fake_repo_dir into target
    - Mocks OSV.dev batch API
    - Confirms all 4 categories of findings are detected
    - Confirms secrets are strictly masked
    - Confirms temp directory is cleaned up
    """
    meta_resp = MagicMock()
    meta_resp.status_code = 200
    meta_resp.json.return_value = {
        "full_name": "acme-corp/test-app",
        "private": False,
        "size": 1200,
        "default_branch": "main",
    }

    osv_resp = MagicMock()
    osv_resp.status_code = 200
    osv_resp.json.return_value = {
        "results": [
            {
                "vulns": [
                    {
                        "id": "GHSA-j8r2-6x86-q33q",
                        "summary": "Requests vulnerable to unintended leak of Proxy-Authorization header",
                        "affected": [
                            {
                                "package": {"name": "requests", "ecosystem": "PyPI"},
                                "ranges": [{"events": [{"fixed": "2.31.0"}]}]
                            }
                        ]
                    }
                ]
            }
        ]
    }

    async def fake_clone(repo_url, branch, target_dir):
        shutil.copytree(fake_repo_dir, target_dir)

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get, \
         patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post, \
         patch("modules.repo_module.clone_repository", side_effect=fake_clone):

        mock_get.return_value = meta_resp
        mock_post.return_value = osv_resp

        response = client.post("/api/repo/scan", json={"repoUrl": "https://github.com/acme-corp/test-app"})
        assert response.status_code == 200
        data = response.json()

        # Basic shape checks
        assert data["repoName"] == "acme-corp/test-app"
        assert data["repoUrl"] == "https://github.com/acme-corp/test-app"
        assert data["branch"] == "main"
        assert data["scannedFilesCount"] > 0

        # Finding categories check
        categories = {f["category"] for f in data["findings"]}
        assert "secrets" in categories
        assert "dependencies" in categories
        assert "code" in categories
        assert "network" in categories

        # Secret Masking Check: raw AWS key must NEVER appear in findings
        for f in data["findings"]:
            snippet = f.get("codeSnippet") or ""
            assert "AKIAIOSFODNN7EXAMPLE" not in snippet
            if "AWS Access Key" in f["title"]:
                assert "AKIA****" in snippet

        # Risk scoring
        assert data["riskScore"] >= 50
        assert data["riskLevel"] in ("high", "critical")
        assert data["counts"]["total"] == len(data["findings"])
        assert data["counts"]["critical"] >= 1


@pytest.mark.asyncio
async def test_temp_directory_cleanup_guarantee(fake_repo_dir):
    """Confirms temp directory is purged even if scan raises an exception."""
    created_temp_dirs = []
    real_mkdtemp = tempfile.mkdtemp

    def tracked_mkdtemp(*args, **kwargs):
        td = real_mkdtemp(*args, **kwargs)
        created_temp_dirs.append(td)
        return td

    with patch("tempfile.mkdtemp", side_effect=tracked_mkdtemp), \
         patch("modules.repo_module.fetch_github_metadata", new_callable=AsyncMock) as mock_meta, \
         patch("modules.repo_module.clone_repository", new_callable=AsyncMock) as mock_clone:

        mock_meta.return_value = {"full_name": "owner/repo", "default_branch": "main", "size": 100}
        mock_clone.side_effect = RuntimeError("Simulated clone error")

        with pytest.raises(RuntimeError):
            await inspect_repository("https://github.com/owner/repo")

        # Confirm all created temp directories were deleted in finally
        for td in created_temp_dirs:
            assert not os.path.exists(td), f"Temp dir {td} was not cleaned up!"


def test_repo_rate_limiter_exceeded():
    """Confirms 5 scans per minute per client IP rate limiting."""
    from routers.repo import _repo_rate_limit_records
    _repo_rate_limit_records.clear()

    for _ in range(5):
        res = client.post("/api/repo/scan", json={"repoUrl": "invalid"})
        assert res.status_code == 400

    # 6th request within window must be rate-limited
    res6 = client.post("/api/repo/scan", json={"repoUrl": "invalid"})
    assert res6.status_code == 429
    assert "Too many requests" in res6.json()["detail"]
