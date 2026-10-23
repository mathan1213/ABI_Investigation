import time
from collections import defaultdict
from typing import Dict, List
from fastapi import APIRouter, HTTPException, Request, Query
from config import settings
from models import (
    IpCheckRequest,
    IpCheckResponse,
    LinkCheckRequest,
    LinkCheckResponse,
    WebsiteCheckRequest,
    WebsiteCheckResponse,
)
from modules.network_module import inspect_ip, inspect_link, inspect_website

router = APIRouter(prefix="/api/network", tags=["Network Security"])

# ---------------------------------------------------------------------------
# In-Memory Rate Limiter (20 requests per minute per client IP)
# ---------------------------------------------------------------------------
_rate_limit_records: Dict[str, List[float]] = defaultdict(list)

def enforce_rate_limit(request: Request):
    """
    Checks and enforces in-memory rate limiting of 20 req/min per client IP.
    """
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    window_start = now - 60.0

    # Prune expired timestamps
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
async def check_ip_endpoint(payload: IpCheckRequest, request: Request) -> IpCheckResponse:
    """
    Audits an IP address for geolocation, ISP identity, proxy/VPN/Tor usage,
    and abuse threat score.
    """
    enforce_rate_limit(request)
    try:
        return await inspect_ip(payload.ip)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to inspect IP: {str(e)}")


@router.get("/ip", response_model=IpCheckResponse, include_in_schema=False)
async def check_ip_get_endpoint(request: Request, ip: str = Query(..., description="IP to check")) -> IpCheckResponse:
    """Convenience GET endpoint supporting frontend query params."""
    enforce_rate_limit(request)
    try:
        return await inspect_ip(ip)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to inspect IP: {str(e)}")


# ---------------------------------------------------------------------------
# 2. Link Check Endpoint
# ---------------------------------------------------------------------------

@router.post("/link", response_model=LinkCheckResponse, summary="Inspect Web Link or URL")
async def check_link_endpoint(payload: LinkCheckRequest, request: Request) -> LinkCheckResponse:
    """
    Audits a web link/URL for phishing indicators, domain registration age,
    SSL validity, and redirect chains.
    """
    enforce_rate_limit(request)
    try:
        return await inspect_link(payload.url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to inspect link: {str(e)}")


@router.get("/link", response_model=LinkCheckResponse, include_in_schema=False)
async def check_link_get_endpoint(request: Request, url: str = Query(..., description="URL to check")) -> LinkCheckResponse:
    """Convenience GET endpoint supporting frontend query params."""
    enforce_rate_limit(request)
    try:
        return await inspect_link(url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to inspect link: {str(e)}")


# ---------------------------------------------------------------------------
# 3. Website Check Endpoint
# ---------------------------------------------------------------------------

@router.post("/website", response_model=WebsiteCheckResponse, summary="Inspect Website Server Security")
async def check_website_endpoint(payload: WebsiteCheckRequest, request: Request) -> WebsiteCheckResponse:
    """
    Audits a website for open ports (80, 443, 22, 21), SSL certificate expiry,
    and essential HTTP browser security headers.
    """
    enforce_rate_limit(request)
    try:
        return await inspect_website(payload.domain)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to inspect website: {str(e)}")


@router.get("/website", response_model=WebsiteCheckResponse, include_in_schema=False)
async def check_website_get_endpoint(request: Request, domain: str = Query(..., description="Domain to check")) -> WebsiteCheckResponse:
    """Convenience GET endpoint supporting frontend query params."""
    enforce_rate_limit(request)
    try:
        return await inspect_website(domain)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to inspect website: {str(e)}")
