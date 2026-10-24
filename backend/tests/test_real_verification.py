import pytest
from httpx import AsyncClient, ASGITransport
from main import app


@pytest.mark.asyncio
async def test_live_network_and_repo_and_report_end_to_end():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. Real Status Check
        status_res = await ac.get("/api/status")
        assert status_res.status_code == 200
        status_data = status_res.json()
        assert "telegram" in status_data
        assert "gitInstalled" in status_data or "git_installed" in status_data

        # 2. Real Network Check: IP (8.8.8.8)
        ip_res = await ac.post("/api/network/ip", json={"ip": "8.8.8.8"})
        assert ip_res.status_code == 200
        ip_data = ip_res.json()
        assert ip_data["ip"] == "8.8.8.8"
        assert ip_data["verdict"] == "Safe"
        assert "Google" in ip_data["isp"] or "DNS" in ip_data["explanation"]

        # 3. Real Network Check: Link (https://example.com)
        link_res = await ac.post("/api/network/link", json={"url": "https://example.com"})
        assert link_res.status_code == 200
        link_data = link_res.json()
        assert link_data["domain"] == "example.com"
        assert "verdict" in link_data

        # 4. Real Network Check: Website (example.com)
        web_res = await ac.post("/api/network/website", json={"domain": "example.com"})
        assert web_res.status_code == 200
        web_data = web_res.json()
        assert web_data["domain"] == "example.com"
        assert len(web_data["ports"]) > 0

        # 5. Real Repo Scan: Small Public Repo (octocat/Hello-World)
        repo_res = await ac.post(
            "/api/repo/scan",
            json={"repoUrl": "https://github.com/octocat/Hello-World"},
            timeout=60.0
        )
        assert repo_res.status_code == 200
        repo_data = repo_res.json()
        assert repo_data["repoName"] == "octocat/Hello-World"
        assert "riskScore" in repo_data
        assert "findings" in repo_data
        assert "counts" in repo_data

        # 6. Real Report Generation: synthesize the live results
        net_payload = {
            "ipResult": ip_data,
            "linkResult": link_data,
            "websiteResult": web_data,
        }
        report_res = await ac.post(
            "/api/report/generate",
            json={
                "telegram": None,
                "repo": repo_data,
                "network": net_payload,
                "demoModules": [],
            },
            timeout=30.0
        )
        assert report_res.status_code == 200
        report_data = report_res.json()

        # Verify demoModules is empty and score derived from real data
        assert report_data["demoModules"] == []
        assert report_data["overallScore"] is not None
        assert report_data["overallRisk"] is not None
        assert "summary" in report_data
        assert "actionPlan" in report_data or "whatToDoNow" in report_data

        # Modules list must indicate repo and network are scanned without demo flag
        repo_mod = next(m for m in report_data["modules"] if m["module"] == "repo")
        assert repo_mod["scanned"] is True
        assert repo_mod.get("isDemo") is False or repo_mod.get("is_demo") is False

        net_mod = next(m for m in report_data["modules"] if m["module"] == "network")
        assert net_mod["scanned"] is True
        assert net_mod.get("isDemo") is False or net_mod.get("is_demo") is False
