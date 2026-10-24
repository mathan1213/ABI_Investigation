import pytest
from httpx import AsyncClient, ASGITransport
from main import app


@pytest.mark.asyncio
async def test_get_system_status():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get("/api/status")
        assert response.status_code == 200
        data = response.json()

        # Check all required keys exist
        assert "telegram" in data
        assert "githubToken" in data or "github_token" in data
        assert "abuseipdb" in data
        assert "virustotal" in data
        assert "gitInstalled" in data or "git_installed" in data
        assert "banditAvailable" in data or "bandit_available" in data

        # Check types are boolean
        assert isinstance(data["telegram"], bool)
        assert isinstance(data.get("githubToken", data.get("github_token")), bool)
        assert isinstance(data["abuseipdb"], bool)
        assert isinstance(data["virustotal"], bool)
        assert isinstance(data.get("gitInstalled", data.get("git_installed")), bool)
        assert isinstance(data.get("banditAvailable", data.get("bandit_available")), bool)

        # Make sure no secret key strings are leaked in response
        for k, v in data.items():
            assert not isinstance(v, str) or k in ("version", "status")
