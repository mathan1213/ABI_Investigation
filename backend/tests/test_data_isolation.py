import os
import json
import pytest
from httpx import AsyncClient, ASGITransport
from unittest.mock import patch, AsyncMock

from main import app
from database import SessionLocal
import db_models
from models import TelegramScanResult, IpCheckResponse, DnsRecords
from modules.auth_module import hash_password, get_current_user, create_access_token


@pytest.fixture
def isolation_users():
    db = SessionLocal()
    try:
        # Create User A
        user_a = db.query(db_models.User).filter(db_models.User.email == "usera@isolation.test").first()
        if not user_a:
            user_a = db_models.User(
                name="User Alpha",
                username="user_alpha",
                username_lower="user_alpha",
                email="usera@isolation.test",
                password_hash="precomputed_hash",
                role="user",
                is_active=True,
                is_email_verified=True,
                token_version=1,
                permissions="[]",
            )
            db.add(user_a)

        # Create User B
        user_b = db.query(db_models.User).filter(db_models.User.email == "userb@isolation.test").first()
        if not user_b:
            user_b = db_models.User(
                name="User Beta",
                username="user_beta",
                username_lower="user_beta",
                email="userb@isolation.test",
                password_hash="precomputed_hash",
                role="user",
                is_active=True,
                is_email_verified=True,
                token_version=1,
                permissions="[]",
            )
            db.add(user_b)

        db.commit()
        user_a_id = user_a.id
        user_a_email = user_a.email
        user_a_role = user_a.role
        user_b_id = user_b.id
        user_b_email = user_b.email
        user_b_role = user_b.role
    finally:
        db.close()

    token_a = create_access_token({"sub": str(user_a_id), "email": user_a_email, "role": user_a_role, "token_version": 1})
    token_b = create_access_token({"sub": str(user_b_id), "email": user_b_email, "role": user_b_role, "token_version": 1})

    yield {
        "user_a_id": user_a_id,
        "user_b_id": user_b_id,
        "headers_a": {"Authorization": f"Bearer {token_a}"},
        "headers_b": {"Authorization": f"Bearer {token_b}"},
    }


@pytest.mark.asyncio
async def test_file_upload_and_isolation(isolation_users):
    """
    Requirements 1, 2, 3:
    - User A uploads a file, can list it.
    - User B uploads a different file and sees ONLY User B's file.
    - User B CANNOT download User A's file by changing file ID in URL (IDOR prevented).
    - User B CANNOT delete User A's file (returns 404).
    """
    app.dependency_overrides.pop(get_current_user, None)
    headers_a = isolation_users["headers_a"]
    headers_b = isolation_users["headers_b"]

    dummy_result = TelegramScanResult(
        phone="+1234567890",
        account_name="Test User",
        risk_score=15,
        risk_level="low",
        summary="Clean export",
        how_it_happened="Routine analysis",
        sessions=[],
        findings=[],
        alerts=[],
        action_checklist=[],
        timestamp="2026-10-29T12:00:00Z",
    )

    with patch("routers.telegram.parse_and_analyze_telegram_export", new_callable=AsyncMock) as mock_parser:
        mock_parser.return_value = dummy_result

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            # 1. User A uploads Telegram export file
            sample_tg_a = b'{"about": "Telegram export", "sessions": {"list": []}}'
            files_a = [("files", ("export_alpha.json", sample_tg_a, "application/json"))]
            res_a = await ac.post("/api/telegram/logs/analyze", headers=headers_a, files=files_a)
            assert res_a.status_code == 200

            # User A lists their files
            list_a = await ac.get("/api/files", headers=headers_a)
            assert list_a.status_code == 200
            items_a = list_a.json()["items"]
            assert len(items_a) >= 1
            user_a_file = next(f for f in items_a if f["filename"] == "export_alpha.json")
            user_a_file_id = user_a_file["id"]

            # 2. User B uploads different file
            sample_tg_b = b'{"about": "Telegram export user B", "sessions": {"list": []}}'
            files_b = [("files", ("export_beta.json", sample_tg_b, "application/json"))]
            res_b = await ac.post("/api/telegram/logs/analyze", headers=headers_b, files=files_b)
            assert res_b.status_code == 200

            # User B lists their files -> must see ONLY User B's file
            list_b = await ac.get("/api/files", headers=headers_b)
            assert list_b.status_code == 200
            items_b = list_b.json()["items"]
            assert any(f["filename"] == "export_beta.json" for f in items_b)
            assert not any(f["filename"] == "export_alpha.json" for f in items_b)

            # 3. User A can download User A's file
            dl_a = await ac.get(f"/api/files/{user_a_file_id}/download", headers=headers_a)
            assert dl_a.status_code == 200
            assert dl_a.content == sample_tg_a

            # User B attempts to download User A's file -> MUST return 404 Not Found (Strict IDOR Protection)
            dl_b_attack = await ac.get(f"/api/files/{user_a_file_id}/download", headers=headers_b)
            assert dl_b_attack.status_code == 404

            # User B attempts to delete User A's file -> MUST return 404 Not Found
            del_b_attack = await ac.delete(f"/api/files/{user_a_file_id}", headers=headers_b)
            assert del_b_attack.status_code == 404

            # User A can delete their own file
            del_a = await ac.delete(f"/api/files/{user_a_file_id}", headers=headers_a)
            assert del_a.status_code == 200


@pytest.mark.asyncio
async def test_scan_and_investigation_isolation(isolation_users):
    """
    Requirements 4, 8:
    - User A performs network check (stores scan).
    - User B cannot read, modify, or delete User A's scan record.
    - User B's scan history does not include User A's scans.
    """
    app.dependency_overrides.pop(get_current_user, None)
    headers_a = isolation_users["headers_a"]
    headers_b = isolation_users["headers_b"]

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

    with patch("routers.network.inspect_ip", new_callable=AsyncMock) as mock_insp:
        mock_insp.return_value = mock_ip

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            # User A performs an IP check
            res_scan_a = await ac.post("/api/network/ip", headers=headers_a, json={"ip": "198.51.100.5"})
            assert res_scan_a.status_code == 200

            # User A checks their scan history
            history_a = await ac.get("/api/scans/history", headers=headers_a)
            assert history_a.status_code == 200
            items_a = history_a.json()["items"]
            scan_a = next(s for s in items_a if "198.51.100.5" in s["targetLabel"])
            scan_a_id = scan_a["id"]

            # User B checks their scan history -> MUST NOT see User A's scan
            history_b = await ac.get("/api/scans/history", headers=headers_b)
            assert history_b.status_code == 200
            items_b = history_b.json()["items"]
            assert not any(s["id"] == scan_a_id for s in items_b)

            # User B tries to directly fetch User A's scan by ID -> 404
            get_b_attack = await ac.get(f"/api/scans/{scan_a_id}", headers=headers_b)
            assert get_b_attack.status_code == 404

            # User B tries to delete User A's scan -> 404
            del_b_attack = await ac.delete(f"/api/scans/{scan_a_id}", headers=headers_b)
            assert del_b_attack.status_code == 404

            # User A can delete their own scan
            del_a = await ac.delete(f"/api/scans/{scan_a_id}", headers=headers_a)
            assert del_a.status_code == 200


@pytest.mark.asyncio
async def test_report_isolation(isolation_users):
    """
    Requirements 5:
    - User A compiles a report.
    - User B cannot view User A's report or list it in User B's report history.
    - User B cannot delete User A's report.
    """
    app.dependency_overrides.pop(get_current_user, None)
    headers_a = isolation_users["headers_a"]
    headers_b = isolation_users["headers_b"]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # User A generates a report
        gen_res = await ac.post("/api/report/generate", headers=headers_a, json={
            "telegram": None,
            "repo": None,
            "network": None,
            "demoModules": [],
        })
        assert gen_res.status_code == 200

        # User A lists reports
        rep_a = await ac.get("/api/report/history", headers=headers_a)
        assert rep_a.status_code == 200
        items_a = rep_a.json()["items"]
        assert len(items_a) >= 1
        user_a_report_id = items_a[0]["id"]

        # User B lists reports -> MUST NOT contain User A's report
        rep_b = await ac.get("/api/report/history", headers=headers_b)
        assert rep_b.status_code == 200
        items_b = rep_b.json()["items"]
        assert not any(r["id"] == user_a_report_id for r in items_b)

        # User B tries to access User A's report by ID -> 404
        get_rep_b = await ac.get(f"/api/report/{user_a_report_id}", headers=headers_b)
        assert get_rep_b.status_code == 404

        # User B tries to delete User A's report -> 404
        del_rep_b = await ac.delete(f"/api/report/{user_a_report_id}", headers=headers_b)
        assert del_rep_b.status_code == 404

        # User A can delete their own report
        del_a = await ac.delete(f"/api/report/{user_a_report_id}", headers=headers_a)
        assert del_a.status_code == 200


@pytest.mark.asyncio
async def test_unauthenticated_requests_blocked():
    """
    Requirement 6:
    - Unauthenticated requests cannot access private files, scans, or reports.
    """
    app.dependency_overrides.pop(get_current_user, None)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res_files = await ac.get("/api/files")
        assert res_files.status_code in (401, 403)

        res_scans = await ac.get("/api/scans/history")
        assert res_scans.status_code in (401, 403)

        res_reports = await ac.get("/api/report/history")
        assert res_reports.status_code in (401, 403)

        res_dl = await ac.get("/api/files/1/download")
        assert res_dl.status_code in (401, 403)
