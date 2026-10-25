import json
import time
from collections import defaultdict
from typing import Dict, List
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from config import settings
from database import get_db
import db_models
from models import GenerateReportRequest, GenerateReportResponse
from modules.auth_module import get_current_user, log_activity
from modules.risk_engine import generate_comprehensive_report

router = APIRouter(prefix="/api/report", tags=["Risk Engine & Reports"])

# In-Memory Rate Limiter (20 requests per minute per client IP)
_report_rate_limit_records: Dict[str, List[float]] = defaultdict(list)

def reset_rate_limits():
    """Clears rate limit records during unit testing."""
    _report_rate_limit_records.clear()

def enforce_report_rate_limit(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    window_start = now - 60.0

    records = _report_rate_limit_records[client_ip]
    _report_rate_limit_records[client_ip] = [ts for ts in records if ts > window_start]

    if len(_report_rate_limit_records[client_ip]) >= settings.RATE_LIMIT_PER_MINUTE:
        raise HTTPException(
            status_code=429,
            detail="Too many report requests. Please wait a minute before generating another report.",
        )

    _report_rate_limit_records[client_ip].append(now)


@router.post(
    "/generate",
    response_model=GenerateReportResponse,
    summary="Generate Comprehensive Security Incident Dossier",
)
async def generate_report_endpoint(
    request: Request,
    current_user: db_models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> GenerateReportResponse:
    """
    Stateless risk synthesis engine that aggregates Telegram (based on uploaded logs),
    Repository, and Network investigation results into an executive incident dossier.
    Requires user authentication and persists the generated report summary for the user.
    """
    enforce_report_rate_limit(request)

    # 1. Enforce 1 MB Payload Limit (HTTP 413)
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > 1024 * 1024:
        raise HTTPException(status_code=413, detail="Request body exceeds 1 MB limit")

    body_bytes = await request.body()
    if len(body_bytes) > 1024 * 1024:
        raise HTTPException(status_code=413, detail="Request body exceeds 1 MB limit")

    # 2. Parse and Validate Request
    try:
        data = json.loads(body_bytes) if body_bytes else {}
        payload = GenerateReportRequest.model_validate(data)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON in request body")
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Request validation error: {str(e)}")

    # 3. Generate Report via Pure In-Memory Risk Engine
    try:
        report = generate_comprehensive_report(payload)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate investigation report: {str(e)}")

    # 4. Save report in database
    report_record = db_models.Report(
        user_id=current_user.id,
        overall_score=report.overall_score or 0,
        overall_risk=report.overall_risk or "low",
        report_json=report.model_dump_json()
    )
    db.add(report_record)
    db.commit()

    # 5. Log activity
    log_activity(
        db,
        action="generate_report",
        user_id=current_user.id,
        detail=f"Generated report {report.id} (Score: {report.overall_score}, Risk: {report.overall_risk})"
    )

    return report


@router.post("/log-download", summary="Log PDF Download Event")
def log_download_pdf(
    current_user: db_models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Logs the download_pdf event when user downloads dossier PDF."""
    log_activity(db, "download_pdf", user_id=current_user.id, detail="Downloaded PDF investigation dossier")
    return {"success": True}
