import json
from typing import List
from fastapi import APIRouter, Depends, File, UploadFile
from sqlalchemy.orm import Session

from database import get_db
import db_models
from models import TelegramScanResult
from modules.auth_module import get_current_user, log_activity
from modules.file_storage import save_user_uploaded_file
from modules.telegram_log_parser import parse_and_analyze_telegram_export

router = APIRouter(prefix="/api/telegram", tags=["Telegram Security"])


@router.post("/logs/analyze", response_model=TelegramScanResult)
async def analyze_telegram_logs(
    files: List[UploadFile] = File(...),
    current_user: db_models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Analyzes user-uploaded Telegram export files (active sessions, service chat alerts).
    Requires user authentication.
    Saves only sanitized findings summary to the database.
    Never stores uploaded files, message text, or verification codes.
    """
    # Save uploaded files into user's isolated directory and record in DB
    for f in files:
        content = await f.read()
        await f.seek(0)
        stored_name, rel_path, actual_size = save_user_uploaded_file(
            user_id=current_user.id,
            original_filename=f.filename or "telegram_export.json",
            content=content,
        )
        uploaded_record = db_models.UploadedFile(
            user_id=current_user.id,
            filename=f.filename or "uploaded_log",
            stored_filename=stored_name,
            file_path=rel_path,
            file_size=actual_size,
            file_type=f.content_type or "text/plain",
            module="telegram",
        )
        db.add(uploaded_record)

    result = await parse_and_analyze_telegram_export(files)

    # Save sanitized scan summary to DB
    findings_summary = [
        {
            "id": f.id,
            "type": f.type,
            "title": f.title,
            "risk": f.risk,
            "date": f.date,
            "explanation": f.explanation
        }
        for f in result.findings
    ]

    scan_record = db_models.Scan(
        user_id=current_user.id,
        module="telegram",
        target_label="Telegram Export Logs",
        risk_score=result.risk_score,
        risk_level=result.risk_level,
        is_demo=False,
        findings_json=json.dumps(findings_summary)
    )
    db.add(scan_record)
    db.commit()

    log_activity(
        db,
        action="upload_logs",
        user_id=current_user.id,
        detail=f"Analyzed {len(files)} Telegram export file(s). Score: {result.risk_score} ({result.risk_level})"
    )

    return result
