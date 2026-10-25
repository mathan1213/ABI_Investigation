import json
import time
from collections import defaultdict
from typing import Dict, List
from fastapi import APIRouter, Depends, HTTPException, Request, Query
from sqlalchemy.orm import Session

from config import settings
from database import get_db
import db_models
from models import (
    IpCheckRequest,
    IpCheckResponse,
    LinkCheckRequest,
    LinkCheckResponse,
    WebsiteCheckRequest,
    WebsiteCheckResponse,
)
from modules.auth_module import get_current_user, log_activity
from modules.network_module import inspect_ip, inspect_link, inspect_website

router = APIRouter(prefix="/api/network", tags=["Network Security"])

# In-Memory Rate Limiter (20 requests per minute per client IP)
_rate_limit_records: Dict[str, List[float]] = defaultdict(list)

def enforce_rate_limit(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    window_start = now - 60.0

    records = _rate_limit_records[client_ip]
    _rate_limit_records[client_ip] = [ts for ts in records if ts > window_start]

    if len(_rate_limit_records[client_ip]) >= settings.RATE_LIMIT_PER_MINUTE:
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded: Maximum 20 requests per minute allowed."
        )

    _rate_limit_records[client_ip].append(now)


# ---------------------------------------------------------------------------
# 1. IP Check Endpoint
# ---------------------------------------------------------------------------

@router.post("/ip", response_model=IpCheckResponse, summary="Inspect IP Address Reputation")
async def check_ip_endpoint(
    payload: IpCheckRequest,
    request: Request,
    current_user: db_models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> IpCheckResponse:
    enforce_rate_limit(request)
    try:
        result = await inspect_ip(payload.ip)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to inspect IP: {str(e)}")

    scan_record = db_models.Scan(
        user_id=current_user.id,
        module="network",
        target_label=f"IP: {payload.ip}",
        risk_score=result.abuse_score,
        risk_level=result.risk_level,
        is_demo=False,
        findings_json=json.dumps([{
            "type": "ip_reputation",
            "ip": result.ip,
            "verdict": result.verdict,
            "riskLevel": result.risk_level,
            "explanation": result.explanation
        }])
    )
    db.add(scan_record)
    db.commit()

    log_activity(db, "scan_network", user_id=current_user.id, detail=f"Checked IP {payload.ip} ({result.verdict})")
    return result


@router.get("/ip", response_model=IpCheckResponse, include_in_schema=False)
async def check_ip_get_endpoint(
    request: Request,
    ip: str = Query(..., description="IP to check"),
    current_user: db_models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> IpCheckResponse:
    return await check_ip_endpoint(IpCheckRequest(ip=ip), request, current_user, db)


# ---------------------------------------------------------------------------
# 2. Link Check Endpoint
# ---------------------------------------------------------------------------

@router.post("/link", response_model=LinkCheckResponse, summary="Inspect Web Link or URL")
async def check_link_endpoint(
    payload: LinkCheckRequest,
    request: Request,
    current_user: db_models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> LinkCheckResponse:
    enforce_rate_limit(request)
    try:
        result = await inspect_link(payload.url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to inspect link: {str(e)}")

    scan_record = db_models.Scan(
        user_id=current_user.id,
        module="network",
        target_label=f"URL: {payload.url}",
        risk_score=result.reputation_score,
        risk_level=result.risk_level,
        is_demo=False,
        findings_json=json.dumps([{
            "type": "link_reputation",
            "url": result.url,
            "verdict": result.verdict,
            "riskLevel": result.risk_level,
            "explanation": result.explanation
        }])
    )
    db.add(scan_record)
    db.commit()

    log_activity(db, "scan_network", user_id=current_user.id, detail=f"Checked link {payload.url} ({result.verdict})")
    return result


@router.get("/link", response_model=LinkCheckResponse, include_in_schema=False)
async def check_link_get_endpoint(
    request: Request,
    url: str = Query(..., description="URL to check"),
    current_user: db_models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> LinkCheckResponse:
    return await check_link_endpoint(LinkCheckRequest(url=url), request, current_user, db)


# ---------------------------------------------------------------------------
# 3. Website Check Endpoint
# ---------------------------------------------------------------------------

@router.post("/website", response_model=WebsiteCheckResponse, summary="Inspect Website Infrastructure")
async def check_website_endpoint(
    payload: WebsiteCheckRequest,
    request: Request,
    current_user: db_models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> WebsiteCheckResponse:
    enforce_rate_limit(request)
    try:
        result = await inspect_website(payload.domain)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to inspect website: {str(e)}")

    scan_record = db_models.Scan(
        user_id=current_user.id,
        module="network",
        target_label=f"Domain: {payload.domain}",
        risk_score=result.risk_score,
        risk_level=result.risk_level,
        is_demo=False,
        findings_json=json.dumps([{
            "type": "website_infrastructure",
            "domain": result.domain,
            "verdict": result.verdict,
            "riskLevel": result.risk_level,
            "explanation": result.explanation
        }])
    )
    db.add(scan_record)
    db.commit()

    log_activity(db, "scan_network", user_id=current_user.id, detail=f"Checked domain {payload.domain} ({result.verdict})")
    return result


@router.get("/website", response_model=WebsiteCheckResponse, include_in_schema=False)
async def check_website_get_endpoint(
    request: Request,
    domain: str = Query(..., description="Domain to check"),
    current_user: db_models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> WebsiteCheckResponse:
    return await check_website_endpoint(WebsiteCheckRequest(domain=domain), request, current_user, db)
