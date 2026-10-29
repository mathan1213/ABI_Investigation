import os
import sys
import asyncio
import httpx

# Add backend directory to sys.path so we can import app directly
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from main import app

async def run_tests():
    print("=" * 70)
    print("RUNNING STRICT PER-USER DATA ISOLATION TEST SUITE")
    print("=" * 70)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test", timeout=30.0) as client:
        # 1. Health check
        res = await client.get("/api/health")
        assert res.status_code == 200, f"Health check failed: {res.text}"
        print("[PASS] 1. Backend health check (HTTP 200)")

        # 2. Register / Login User A
        user_a_email = "usera_isolation@test.local"
        user_a_pw = "PasswordAlpha123!"
        reg_a = await client.post("/api/auth/register", json={
            "name": "User Alpha",
            "username": "user_alpha_iso",
            "email": user_a_email,
            "password": user_a_pw,
            "confirm_password": user_a_pw,
            "consent": True,
        })
        assert reg_a.status_code in (200, 409), f"Register A failed: {reg_a.text}"

        login_a = await client.post("/api/auth/login", json={"identifier": user_a_email, "password": user_a_pw})
        assert login_a.status_code == 200, f"Login A failed: {login_a.text}"
        token_a = login_a.json()["token"]
        user_a_id = login_a.json()["user"]["id"]
        headers_a = {"Authorization": f"Bearer {token_a}"}
        print(f"[PASS] 2. User A authenticated (ID: {user_a_id}, Email: {user_a_email})")

        # 3. Register / Login User B
        user_b_email = "userb_isolation@test.local"
        user_b_pw = "PasswordBeta123!"
        reg_b = await client.post("/api/auth/register", json={
            "name": "User Beta",
            "username": "user_beta_iso",
            "email": user_b_email,
            "password": user_b_pw,
            "confirm_password": user_b_pw,
            "consent": True,
        })
        assert reg_b.status_code in (200, 409), f"Register B failed: {reg_b.text}"

        login_b = await client.post("/api/auth/login", json={"identifier": user_b_email, "password": user_b_pw})
        assert login_b.status_code == 200, f"Login B failed: {login_b.text}"
        token_b = login_b.json()["token"]
        user_b_id = login_b.json()["user"]["id"]
        headers_b = {"Authorization": f"Bearer {token_b}"}
        print(f"[PASS] 3. User B authenticated (ID: {user_b_id}, Email: {user_b_email})")

        # 4. User A uploads private file
        file_content_a = b'{"about": "Telegram export A", "sessions": {"list": []}}'
        upload_res_a = await client.post(
            "/api/telegram/logs/analyze",
            headers=headers_a,
            files={"files": ("export_user_a.json", file_content_a, "application/json")},
        )
        assert upload_res_a.status_code == 200, f"Upload A failed: {upload_res_a.text}"

        files_list_a = await client.get("/api/files", headers=headers_a)
        assert files_list_a.status_code == 200
        files_a = files_list_a.json()["items"]
        assert len(files_a) >= 1
        user_a_file = next(f for f in files_a if f["filename"] == "export_user_a.json")
        user_a_file_id = user_a_file["id"]
        print(f"[PASS] 4. User A uploaded file saved securely (File ID: {user_a_file_id})")

        # 5. User B lists files -> User A's file is NOT visible
        files_list_b = await client.get("/api/files", headers=headers_b)
        assert files_list_b.status_code == 200
        files_b = files_list_b.json()["items"]
        assert not any(f["id"] == user_a_file_id for f in files_b)
        print(f"[PASS] 5. User B cannot see User A's file in file list")

        # 6. User B uploads their own file
        file_content_b = b'{"about": "Telegram export B", "sessions": {"list": []}}'
        upload_res_b = await client.post(
            "/api/telegram/logs/analyze",
            headers=headers_b,
            files={"files": ("export_user_b.json", file_content_b, "application/json")},
        )
        assert upload_res_b.status_code == 200

        files_list_b_after = await client.get("/api/files", headers=headers_b)
        assert files_list_b_after.status_code == 200
        files_b_after = files_list_b_after.json()["items"]
        assert any(f["filename"] == "export_user_b.json" for f in files_b_after)
        assert not any(f["filename"] == "export_user_a.json" for f in files_b_after)
        print(f"[PASS] 6. User B sees only User B's file")

        # 7. User A can download User A's file
        dl_a = await client.get(f"/api/files/{user_a_file_id}/download", headers=headers_a)
        assert dl_a.status_code == 200
        assert dl_a.content == file_content_a
        print(f"[PASS] 7. User A successfully downloaded own file")

        # 8. User B attempts to download User A's file by ID -> 404 (IDOR Protection)
        dl_b_attack = await client.get(f"/api/files/{user_a_file_id}/download", headers=headers_b)
        assert dl_b_attack.status_code == 404, f"IDOR vulnerability! Expected 404, got {dl_b_attack.status_code}"
        print(f"[PASS] 8. User B cannot download User A's file (HTTP 404 IDOR protected)")

        # 9. User B attempts to delete User A's file -> 404
        del_b_attack = await client.delete(f"/api/files/{user_a_file_id}", headers=headers_b)
        assert del_b_attack.status_code == 404
        print(f"[PASS] 9. User B cannot delete User A's file (HTTP 404 protected)")

        # 10. User A performs scan (IP Check)
        scan_res_a = await client.post("/api/network/ip", headers=headers_a, json={"ip": "1.1.1.1"})
        assert scan_res_a.status_code == 200
        scans_a = (await client.get("/api/scans/history", headers=headers_a)).json()["items"]
        assert len(scans_a) >= 1
        user_a_scan = next(s for s in scans_a if "1.1.1.1" in s["targetLabel"])
        user_a_scan_id = user_a_scan["id"]
        print(f"[PASS] 10. User A performed network scan (Scan ID: {user_a_scan_id})")

        # 11. User B cannot see User A's scan in history
        scans_b = (await client.get("/api/scans/history", headers=headers_b)).json()["items"]
        assert not any(s["id"] == user_a_scan_id for s in scans_b)
        print(f"[PASS] 11. User B cannot see User A's scan in history")

        # 12. User B cannot read User A's scan by ID -> 404
        get_scan_b = await client.get(f"/api/scans/{user_a_scan_id}", headers=headers_b)
        assert get_scan_b.status_code == 404
        print(f"[PASS] 12. User B cannot read User A's scan by ID (HTTP 404 protected)")

        # 13. User B cannot delete User A's scan -> 404
        del_scan_b = await client.delete(f"/api/scans/{user_a_scan_id}", headers=headers_b)
        assert del_scan_b.status_code == 404
        print(f"[PASS] 13. User B cannot delete User A's scan (HTTP 404 protected)")

        # 14. User A generates a report
        rep_res_a = await client.post("/api/report/generate", headers=headers_a, json={
            "telegram": None,
            "repo": None,
            "network": None,
            "demoModules": [],
        })
        assert rep_res_a.status_code == 200
        rep_list_a = (await client.get("/api/report/history", headers=headers_a)).json()["items"]
        assert len(rep_list_a) >= 1
        user_a_rep_id = rep_list_a[0]["id"]
        print(f"[PASS] 14. User A generated report (Report ID: {user_a_rep_id})")

        # 15. User B cannot see User A's report in history
        rep_list_b = (await client.get("/api/report/history", headers=headers_b)).json()["items"]
        assert not any(r["id"] == user_a_rep_id for r in rep_list_b)
        print(f"[PASS] 15. User B cannot see User A's report in history")

        # 16. User B cannot read User A's report by ID -> 404
        get_rep_b = await client.get(f"/api/report/{user_a_rep_id}", headers=headers_b)
        assert get_rep_b.status_code == 404
        print(f"[PASS] 16. User B cannot read User A's report by ID (HTTP 404 protected)")

        # 17. User B cannot delete User A's report -> 404
        del_rep_b = await client.delete(f"/api/report/{user_a_rep_id}", headers=headers_b)
        assert del_rep_b.status_code == 404
        print(f"[PASS] 17. User B cannot delete User A's report (HTTP 404 protected)")

        # 18. Unauthenticated requests are blocked (401/403)
        assert (await client.get("/api/files")).status_code in (401, 403)
        assert (await client.get(f"/api/files/{user_a_file_id}/download")).status_code in (401, 403)
        assert (await client.get("/api/scans/history")).status_code in (401, 403)
        assert (await client.get(f"/api/scans/{user_a_scan_id}")).status_code in (401, 403)
        assert (await client.get("/api/report/history")).status_code in (401, 403)
        assert (await client.get(f"/api/report/{user_a_rep_id}")).status_code in (401, 403)
        print(f"[PASS] 18. All unauthenticated requests rejected (HTTP 401/403)")

        # 19. Verify user isolated storage on disk
        upload_dir_a = os.path.join(os.path.dirname(__file__), "..", "uploads", f"user_{user_a_id}")
        upload_dir_b = os.path.join(os.path.dirname(__file__), "..", "uploads", f"user_{user_b_id}")
        assert os.path.isdir(upload_dir_a), f"Directory {upload_dir_a} does not exist"
        assert os.path.isdir(upload_dir_b), f"Directory {upload_dir_b} does not exist"
        assert len(os.listdir(upload_dir_a)) >= 1
        assert len(os.listdir(upload_dir_b)) >= 1
        print(f"[PASS] 19. Separate on-disk storage verified: uploads/user_{user_a_id}/ and uploads/user_{user_b_id}/")

        # 20. Clean deletion by authorized owner
        del_file_a = await client.delete(f"/api/files/{user_a_file_id}", headers=headers_a)
        assert del_file_a.status_code == 200
        del_scan_a = await client.delete(f"/api/scans/{user_a_scan_id}", headers=headers_a)
        assert del_scan_a.status_code == 200
        del_rep_a = await client.delete(f"/api/report/{user_a_rep_id}", headers=headers_a)
        assert del_rep_a.status_code == 200
        print(f"[PASS] 20. Authorized owners successfully delete their own records")

        print("=" * 70)
        print("ALL 20 STRICT DATA ISOLATION VERIFICATION CHECKS PASSED!")
        print("=" * 70)

if __name__ == "__main__":
    asyncio.run(run_tests())
