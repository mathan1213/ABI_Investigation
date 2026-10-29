import os
import sys
import uuid
from io import BytesIO
from fastapi import HTTPException
from fastapi.datastructures import UploadFile

# Add backend directory to sys.path
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from database import SessionLocal, init_db
import db_models
from modules.file_storage import (
    get_user_upload_dir,
    save_user_uploaded_file,
    resolve_user_file_path,
    delete_user_stored_file,
)
from routers.files import list_user_files, download_user_file, delete_user_file
from routers.scans import list_user_scans, get_user_scan, delete_user_scan
from routers.report import list_user_reports, get_user_report, delete_user_report

def run_direct_isolation_tests():
    print("=" * 70)
    print("RUNNING DIRECT STRICT PER-USER DATA ISOLATION VERIFICATION SUITE")
    print("=" * 70)

    init_db()
    db = SessionLocal()

    try:
        # Step 1: Ensure User Alpha and User Beta exist in DB
        user_a = db.query(db_models.User).filter(db_models.User.email == "alpha_direct@test.local").first()
        if not user_a:
            user_a = db_models.User(
                name="User Alpha",
                username="alpha_direct",
                username_lower="alpha_direct",
                email="alpha_direct@test.local",
                password_hash="hash_alpha",
                role="user",
                is_active=True,
                is_email_verified=True,
                token_version=1,
                permissions="[]",
            )
            db.add(user_a)

        user_b = db.query(db_models.User).filter(db_models.User.email == "beta_direct@test.local").first()
        if not user_b:
            user_b = db_models.User(
                name="User Beta",
                username="beta_direct",
                username_lower="beta_direct",
                email="beta_direct@test.local",
                password_hash="hash_beta",
                role="user",
                is_active=True,
                is_email_verified=True,
                token_version=1,
                permissions="[]",
            )
            db.add(user_b)

        db.commit()
        db.refresh(user_a)
        db.refresh(user_b)
        print(f"[PASS] 1. Test users ready (User A ID: {user_a.id}, User B ID: {user_b.id})")

        # Step 2: Storage path traversal prevention check
        traversal_attempts = ["../evil.txt", "../../etc/passwd", "..\\..\\windows\\system32", "user_2/secret.txt"]
        for bad_filename in traversal_attempts:
            resolved = resolve_user_file_path(user_a.id, bad_filename)
            assert resolved is None, f"Path traversal attempt should resolve to None: {bad_filename}"
        print("[PASS] 2. Path traversal attempts safely neutralized and rejected (resolved is None)")

        # Step 3: User A saves a file using safe storage
        file_content_a = b'{"data": "Confidential User A Forensics"}'
        stored_name_a, rel_path_a, size_a = save_user_uploaded_file(
            user_id=user_a.id,
            original_filename="user_a_evidence.json",
            content=file_content_a
        )
        file_rec_a = db_models.UploadedFile(
            user_id=user_a.id,
            filename="user_a_evidence.json",
            stored_filename=stored_name_a,
            file_path=rel_path_a,
            file_size=size_a,
            file_type="application/json",
            module="telegram"
        )
        db.add(file_rec_a)
        db.commit()
        db.refresh(file_rec_a)
        user_a_file_id = file_rec_a.id
        print(f"[PASS] 3. User A file stored in uploads/user_{user_a.id}/ (File ID: {user_a_file_id})")

        # Step 4: User B saves a file
        file_content_b = b'{"data": "Confidential User B Forensics"}'
        stored_name_b, rel_path_b, size_b = save_user_uploaded_file(
            user_id=user_b.id,
            original_filename="user_b_evidence.json",
            content=file_content_b
        )
        file_rec_b = db_models.UploadedFile(
            user_id=user_b.id,
            filename="user_b_evidence.json",
            stored_filename=stored_name_b,
            file_path=rel_path_b,
            file_size=size_b,
            file_type="application/json",
            module="telegram"
        )
        db.add(file_rec_b)
        db.commit()
        db.refresh(file_rec_b)
        user_b_file_id = file_rec_b.id
        print(f"[PASS] 4. User B file stored in uploads/user_{user_b.id}/ (File ID: {user_b_file_id})")

        # Step 5: User A lists files -> must see only User A's file
        list_a = list_user_files(current_user=user_a, db=db)
        items_a_ids = [f["id"] for f in list_a["items"]]
        assert user_a_file_id in items_a_ids, "User A cannot see their own file"
        assert user_b_file_id not in items_a_ids, "User A can see User B's file! Isolation breach!"
        print(f"[PASS] 5. User A file listing strictly isolated (Contains File {user_a_file_id}, excludes File {user_b_file_id})")

        # Step 6: User B lists files -> must see only User B's file
        list_b = list_user_files(current_user=user_b, db=db)
        items_b_ids = [f["id"] for f in list_b["items"]]
        assert user_b_file_id in items_b_ids, "User B cannot see their own file"
        assert user_a_file_id not in items_b_ids, "User B can see User A's file! Isolation breach!"
        print(f"[PASS] 6. User B file listing strictly isolated (Contains File {user_b_file_id}, excludes File {user_a_file_id})")

        # Step 7: User A downloads own file -> HTTP 200 FileResponse
        resp_a = download_user_file(file_id=user_a_file_id, current_user=user_a, db=db)
        assert str(resp_a.path) == str(resolve_user_file_path(user_a.id, stored_name_a))
        print(f"[PASS] 7. User A successfully downloaded own file")

        # Step 8: User B attempts to download User A's file (IDOR attempt) -> 404
        try:
            download_user_file(file_id=user_a_file_id, current_user=user_b, db=db)
            assert False, "User B was able to download User A's file! IDOR vulnerability!"
        except HTTPException as exc:
            assert exc.status_code == 404
            print(f"[PASS] 8. User B download of User A file blocked with HTTP 404 (IDOR prevented)")

        # Step 9: User B attempts to delete User A's file -> 404
        try:
            delete_user_file(file_id=user_a_file_id, current_user=user_b, db=db)
            assert False, "User B was able to delete User A's file!"
        except HTTPException as exc:
            assert exc.status_code == 404
            print(f"[PASS] 9. User B deletion of User A file blocked with HTTP 404")

        # Step 10: Create Scans for User A and User B
        scan_a = db_models.Scan(
            user_id=user_a.id,
            module="network",
            target_label="IP: 198.51.100.1",
            risk_score=20,
            risk_level="low",
            findings_json="[]"
        )
        scan_b = db_models.Scan(
            user_id=user_b.id,
            module="repo",
            target_label="https://github.com/test/repo-b",
            risk_score=80,
            risk_level="high",
            findings_json="[]"
        )
        db.add(scan_a)
        db.add(scan_b)
        db.commit()
        db.refresh(scan_a)
        db.refresh(scan_b)
        print(f"[PASS] 10. Scans created (Scan A ID: {scan_a.id}, Scan B ID: {scan_b.id})")

        # Step 11: User A scan history isolation
        scans_a = list_user_scans(current_user=user_a, db=db)
        scan_a_ids = [s["id"] for s in scans_a["items"]]
        assert scan_a.id in scan_a_ids
        assert scan_b.id not in scan_a_ids
        print(f"[PASS] 11. User A scan history strictly isolated")

        # Step 12: User B scan history isolation
        scans_b = list_user_scans(current_user=user_b, db=db)
        scan_b_ids = [s["id"] for s in scans_b["items"]]
        assert scan_b.id in scan_b_ids
        assert scan_a.id not in scan_b_ids
        print(f"[PASS] 12. User B scan history strictly isolated")

        # Step 13: User B direct fetch of User A's scan (IDOR attempt) -> 404
        try:
            get_user_scan(scan_id=scan_a.id, current_user=user_b, db=db)
            assert False, "User B was able to fetch User A's scan!"
        except HTTPException as exc:
            assert exc.status_code == 404
            print(f"[PASS] 13. User B direct fetch of User A scan blocked with HTTP 404 (IDOR prevented)")

        # Step 14: User B deletion of User A's scan -> 404
        try:
            delete_user_scan(scan_id=scan_a.id, current_user=user_b, db=db)
            assert False, "User B was able to delete User A's scan!"
        except HTTPException as exc:
            assert exc.status_code == 404
            print(f"[PASS] 14. User B deletion of User A scan blocked with HTTP 404")

        # Step 15: Create Reports for User A and User B
        report_a = db_models.Report(
            user_id=user_a.id,
            overall_score=25,
            overall_risk="low",
            report_json="{}"
        )
        report_b = db_models.Report(
            user_id=user_b.id,
            overall_score=85,
            overall_risk="high",
            report_json="{}"
        )
        db.add(report_a)
        db.add(report_b)
        db.commit()
        db.refresh(report_a)
        db.refresh(report_b)
        print(f"[PASS] 15. Reports created (Report A ID: {report_a.id}, Report B ID: {report_b.id})")

        # Step 16: User A report history isolation
        reps_a = list_user_reports(current_user=user_a, db=db)
        rep_a_ids = [r["id"] for r in reps_a["items"]]
        assert report_a.id in rep_a_ids
        assert report_b.id not in rep_a_ids
        print(f"[PASS] 16. User A report history strictly isolated")

        # Step 17: User B report history isolation
        reps_b = list_user_reports(current_user=user_b, db=db)
        rep_b_ids = [r["id"] for r in reps_b["items"]]
        assert report_b.id in rep_b_ids
        assert report_a.id not in rep_b_ids
        print(f"[PASS] 17. User B report history strictly isolated")

        # Step 18: User B direct fetch of User A's report (IDOR attempt) -> 404
        try:
            get_user_report(report_id=report_a.id, current_user=user_b, db=db)
            assert False, "User B was able to fetch User A's report!"
        except HTTPException as exc:
            assert exc.status_code == 404
            print(f"[PASS] 18. User B fetch of User A report blocked with HTTP 404 (IDOR prevented)")

        # Step 19: User B deletion of User A's report -> 404
        try:
            delete_user_report(report_id=report_a.id, current_user=user_b, db=db)
            assert False, "User B was able to delete User A's report!"
        except HTTPException as exc:
            assert exc.status_code == 404
            print(f"[PASS] 19. User B deletion of User A report blocked with HTTP 404")

        # Step 20: Clean deletion by authorized owners
        res_del_f = delete_user_file(file_id=user_a_file_id, current_user=user_a, db=db)
        assert res_del_f["success"] is True
        res_del_s = delete_user_scan(scan_id=scan_a.id, current_user=user_a, db=db)
        assert res_del_s["success"] is True
        res_del_r = delete_user_report(report_id=report_a.id, current_user=user_a, db=db)
        assert res_del_r["success"] is True

        # Clean User B records
        delete_user_file(file_id=user_b_file_id, current_user=user_b, db=db)
        delete_user_scan(scan_id=scan_b.id, current_user=user_b, db=db)
        delete_user_report(report_id=report_b.id, current_user=user_b, db=db)
        print(f"[PASS] 20. Authorized owners successfully delete their own records and disk files")

        print("=" * 70)
        print("ALL 20 STRICT DATA ISOLATION & IDOR DEFENSE CHECKS PASSED!")
        print("=" * 70)

    finally:
        db.close()

if __name__ == "__main__":
    run_direct_isolation_tests()
