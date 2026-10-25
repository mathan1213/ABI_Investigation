import json
import time
from collections import defaultdict
from typing import Dict, List
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from config import settings
from database import get_db
import db_models
from models import RepoScanRequest, RepoScanResponse
from modules.auth_module import get_current_user, log_activity
from modules.repo_module import inspect_repository

router = APIRouter(prefix="/api/repo", tags=["Repository Security"])

# In-Memory Rate Limiter (5 scans per minute per client IP)
_repo_rate_limit_records: Dict[str, List[float]] = defaultdict(list)

def enforce_repo_rate_limit(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    window_start = now - 60.0

    records = _repo_rate_limit_records[client_ip]
    _repo_rate_limit_records[client_ip] = [ts for ts in records if ts > window_start]

    if len(_repo_rate_limit_records[client_ip]) >= settings.REPO_RATE_LIMIT_PER_MINUTE:
        raise HTTPException(
            status_code=429,
            detail="Too many requests, please wait a minute before scanning again."
        )

    _repo_rate_limit_records[client_ip].append(now)


@router.post("/scan", response_model=RepoScanResponse, summary="Audit GitHub Repository Security")
async def scan_repo_endpoint(
    payload: RepoScanRequest,
    request: Request,
    current_user: db_models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> RepoScanResponse:
    """
    Scans a public GitHub repository for leaked API credentials, vulnerable package dependencies,
    dangerous code patterns, and insecure network configurations.
    Requires user authentication.
    """
    enforce_repo_rate_limit(request)
    try:
        result = await inspect_repository(payload.repo_url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        err_msg = str(e).strip() or type(e).__name__
        raise HTTPException(status_code=500, detail=f"Failed to scan repository: {err_msg}")

    # Save sanitized findings only to DB
    findings_summary = [
        {
            "id": f.id,
            "category": f.category,
            "severity": f.severity,
            "title": f.title,
            "filePath": f.file_path,
            "lineNumber": f.line_number,
            "explanation": f.explanation,
            "suggestedFix": f.suggested_fix
        }
        for f in result.findings
    ]

    scan_record = db_models.Scan(
        user_id=current_user.id,
        module="repo",
        target_label=result.repo_name,
        risk_score=result.risk_score,
        risk_level=result.risk_level,
        is_demo=False,
        findings_json=json.dumps(findings_summary)
    )
    db.add(scan_record)
    db.commit()

    log_activity(
        db,
        action="scan_repo",
        user_id=current_user.id,
        detail=f"Scanned {result.repo_url} - Score: {result.risk_score} ({result.risk_level})"
    )

    return result
