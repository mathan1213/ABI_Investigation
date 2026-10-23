import json
import time
from collections import defaultdict
from typing import Dict, List
from fastapi import APIRouter, HTTPException, Request

from config import settings
from models import GenerateReportRequest, GenerateReportResponse
from modules.risk_engine import generate_comprehensive_report

router = APIRouter(prefix="/api/report", tags=["Risk Engine & Reports"])

# ---------------------------------------------------------------------------
# In-Memory Rate Limiter (20 requests per minute per client IP)
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Report Generation Endpoint (Stateless, 1 MB Body Cap)
# ---------------------------------------------------------------------------

@router.post(
    "/generate",
    response_model=GenerateReportResponse,
    summary="Generate Comprehensive Security Incident Dossier",
)
async def generate_report_endpoint(request: Request) -> GenerateReportResponse:
    """
    Stateless risk synthesis engine that aggregates Telegram, Repository, and Network
    investigation results into an executive incident dossier with composite scoring and action plan.
    Enforces a strict 1 MB payload limit and logs zero user credentials.
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
        return generate_comprehensive_report(payload)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate investigation report: {str(e)}")
