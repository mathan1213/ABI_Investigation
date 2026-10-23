import time
from collections import defaultdict
from typing import Dict, List
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from config import settings
from models import (
    TelegramAnalyzeRequest,
    TelegramCancelRequest,
    TelegramCancelResponse,
    TelegramScanResult,
    TelegramSendCodeRequest,
    TelegramSendCodeResponse,
    TelegramVerifyRequest,
    TelegramVerifyResponse,
)
from modules.telegram_module import (
    PHONE_REGEX,
    TelegramFloodWaitException,
    TelegramIntegrationNotConfigured,
    analyze_telegram_account,
    cancel_telegram_flow,
    send_telegram_code,
    verify_telegram_code,
)
import re

router = APIRouter(prefix="/api/telegram", tags=["Telegram Security"])

# ---------------------------------------------------------------------------
# In-Memory Rate Limiting
# ---------------------------------------------------------------------------
_send_code_rate_limit_records: Dict[str, List[float]] = defaultdict(list)
_default_rate_limit_records: Dict[str, List[float]] = defaultdict(list)


def reset_rate_limits():
    """Helper to clear rate limit caches during tests."""
    _send_code_rate_limit_records.clear()
    _default_rate_limit_records.clear()


def enforce_send_code_rate_limit(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    window_start = now - settings.TELEGRAM_FLOW_TTL_SECONDS  # 10 minutes (600s)

    records = _send_code_rate_limit_records[client_ip]
    _send_code_rate_limit_records[client_ip] = [ts for ts in records if ts > window_start]

    if len(_send_code_rate_limit_records[client_ip]) >= settings.TELEGRAM_SEND_CODE_RATE_LIMIT:
        raise HTTPException(
            status_code=429,
            detail="Too many verification code requests. Please wait 10 minutes before requesting another code.",
        )

    _send_code_rate_limit_records[client_ip].append(now)


def enforce_default_rate_limit(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    window_start = now - 60.0  # 1 minute

    records = _default_rate_limit_records[client_ip]
    _default_rate_limit_records[client_ip] = [ts for ts in records if ts > window_start]

    if len(_default_rate_limit_records[client_ip]) >= settings.TELEGRAM_DEFAULT_RATE_LIMIT:
        raise HTTPException(
            status_code=429,
            detail="Too many requests. Please wait a moment.",
        )

    _default_rate_limit_records[client_ip].append(now)


# ---------------------------------------------------------------------------
# Telegram Endpoints
# ---------------------------------------------------------------------------

@router.post("/send-code", response_model=TelegramSendCodeResponse, summary="Send Telegram Login Code")
async def send_code_endpoint(payload: TelegramSendCodeRequest, request: Request) -> TelegramSendCodeResponse:
    """
    Validates the user's phone number, initializes an in-memory Telethon MTProto client,
    and requests a Telegram login code.
    """
    clean_digits = re.sub(r"[\s\-\(\)]", "", payload.phone.strip())
    if not PHONE_REGEX.match(clean_digits):
        raise HTTPException(
            status_code=400,
            detail="Invalid phone number format. Please provide a valid international phone number in E.164 format (e.g. +911234567890).",
        )

    enforce_send_code_rate_limit(request)
    try:
        flow_id = await send_telegram_code(payload.phone)
        return TelegramSendCodeResponse(
            flow_id=flow_id,
            message="Verification code requested from Telegram. Check your Telegram app or SMS.",
        )
    except TelegramIntegrationNotConfigured as e:
        raise HTTPException(status_code=503, detail=str(e))
    except TelegramFloodWaitException as e:
        raise HTTPException(status_code=429, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Telegram login initialization error: {str(e)}")


@router.post("/verify", response_model=TelegramVerifyResponse, summary="Verify Telegram Code & Password")
async def verify_code_endpoint(payload: TelegramVerifyRequest, request: Request):
    """
    Verifies the login code and optional two-step verification password.
    Returns 401 if two-step verification is active on the account and password is missing.
    """
    enforce_default_rate_limit(request)
    try:
        status, needs_password = await verify_telegram_code(payload.flow_id, payload.code, payload.password)
        if needs_password:
            return JSONResponse(
                status_code=401,
                content={
                    "status": "needs_password",
                    "flowId": payload.flow_id,
                    "needsPassword": True,
                    "detail": "Two-step verification password is required for this account.",
                },
            )
        return TelegramVerifyResponse(status=status, flow_id=payload.flow_id, needs_password=False)
    except TelegramIntegrationNotConfigured as e:
        raise HTTPException(status_code=503, detail=str(e))
    except TelegramFloodWaitException as e:
        raise HTTPException(status_code=429, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Verification failed: {str(e)}")


@router.post("/analyze", response_model=TelegramScanResult, summary="Run Telegram Account Security Investigation")
async def analyze_account_endpoint(payload: TelegramAnalyzeRequest, request: Request) -> TelegramScanResult:
    """
    Conducts read-only forensic inspection of active sessions, foreign logins, impossible travel,
    and 2FA status. Automatically logs out and clears the session upon completion.
    """
    enforce_default_rate_limit(request)
    try:
        return await analyze_telegram_account(payload.flow_id)
    except TelegramIntegrationNotConfigured as e:
        raise HTTPException(status_code=503, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.post("/cancel", response_model=TelegramCancelResponse, summary="Cancel Telegram Investigation Flow")
async def cancel_flow_endpoint(payload: TelegramCancelRequest, request: Request) -> TelegramCancelResponse:
    """
    Immediately terminates and disconnects an in-flight authentication flow.
    """
    enforce_default_rate_limit(request)
    try:
        await cancel_telegram_flow(payload.flow_id)
        return TelegramCancelResponse(status="cancelled")
    except TelegramIntegrationNotConfigured as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Cancellation failed: {str(e)}")
