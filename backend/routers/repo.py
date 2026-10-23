import time
from collections import defaultdict
from typing import Dict, List
from fastapi import APIRouter, HTTPException, Request
from config import settings
from models import RepoScanRequest, RepoScanResponse
from modules.repo_module import inspect_repository

router = APIRouter(prefix="/api/repo", tags=["Repository Security"])

# ---------------------------------------------------------------------------
# In-Memory Rate Limiter (5 scans per minute per client IP)
# ---------------------------------------------------------------------------
_repo_rate_limit_records: Dict[str, List[float]] = defaultdict(list)

def enforce_repo_rate_limit(request: Request):
    """
    Checks and enforces in-memory rate limiting of 5 repo scans per minute per client IP.
    """
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    window_start = now - 60.0

    # Prune expired timestamps
    records = _repo_rate_limit_records[client_ip]
    _repo_rate_limit_records[client_ip] = [ts for ts in records if ts > window_start]

    if len(_repo_rate_limit_records[client_ip]) >= settings.REPO_RATE_LIMIT_PER_MINUTE:
        raise HTTPException(
            status_code=429,
            detail="Too many requests, please wait a minute"
        )

    _repo_rate_limit_records[client_ip].append(now)


# ---------------------------------------------------------------------------
# Repository Scan Endpoint
# ---------------------------------------------------------------------------

@router.post("/scan", response_model=RepoScanResponse, summary="Audit GitHub Repository Security")
async def scan_repo_endpoint(payload: RepoScanRequest, request: Request) -> RepoScanResponse:
    """
    Scans a public GitHub repository for leaked API credentials, vulnerable package dependencies,
    dangerous code patterns (Bandit & JS AST patterns), and insecure network configurations.
    """
    enforce_repo_rate_limit(request)
    try:
        return await inspect_repository(payload.repo_url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to scan repository: {str(e)}")
