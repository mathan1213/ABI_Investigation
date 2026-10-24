import asyncio
import datetime
import logging
import re
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from config import settings
from models import (
    RiskLevel,
    TelegramFinding,
    TelegramScanResult,
    TelegramSession,
)
from modules.network_module import inspect_ip, inspect_link, is_safe_ip

logger = logging.getLogger("telegram_audit")

# E.164 International Phone Regex
PHONE_REGEX = re.compile(r"^\+[1-9]\d{6,14}$")


def mask_phone(phone: str) -> str:
    """Masks a phone number, preserving country prefix and trailing digits."""
    clean = re.sub(r"[\s\-\(\)]", "", phone)
    if len(clean) <= 6:
        return clean[:2] + "****" + clean[-2:] if len(clean) >= 4 else "****"
    return clean[:3] + "*****" + clean[-4:]


class TelegramIntegrationNotConfigured(Exception):
    """Raised when TELEGRAM_API_ID or TELEGRAM_API_HASH is missing."""
    pass


class TelegramFloodWaitException(Exception):
    def __init__(self, seconds: int):
        super().__init__(f"Too many attempts. Telegram requires waiting {seconds} seconds.")
        self.seconds = seconds


class TelegramFlow:
    """Represents a temporary in-memory Telegram authentication and audit flow."""

    def __init__(self, flow_id: str, phone: str, client: Any, phone_code_hash: Optional[str] = None):
        self.flow_id = flow_id
        self.phone = phone
        self.client = client
        self.phone_code_hash = phone_code_hash
        self.created_at = time.time()
        self.status = "code_sent"  # 'code_sent', 'verified', 'analyzing', 'completed'

    def is_expired(self) -> bool:
        return (time.time() - self.created_at) > settings.TELEGRAM_FLOW_TTL_SECONDS


# In-memory session store (keyed by flow_id)
_flows: Dict[str, TelegramFlow] = {}


async def cleanup_expired_flows() -> None:
    """Cleans up and disconnects any in-memory flows that exceeded their TTL."""
    expired_ids = [fid for fid, flow in _flows.items() if flow.is_expired()]
    for fid in expired_ids:
        flow = _flows.pop(fid, None)
        if flow and flow.client:
            try:
                await flow.client.disconnect()
            except Exception:
                pass


def verify_telegram_configuration() -> None:
    """Validates that Telegram credentials are provided in configuration."""
    if not settings.TELEGRAM_API_ID or not settings.TELEGRAM_API_HASH:
        raise TelegramIntegrationNotConfigured("Telegram integration is not configured")


# ---------------------------------------------------------------------------
# Flow Step 1: Send Code
# ---------------------------------------------------------------------------

async def send_telegram_code(phone_raw: str) -> str:
    """
    Validates phone format, creates in-memory Telethon client, sends code request,
    and returns a unique flow ID.
    """
    verify_telegram_configuration()
    await cleanup_expired_flows()

    # Normalize phone: remove spaces, dashes, parentheses
    clean_phone = re.sub(r"[\s\-\(\)]", "", phone_raw.strip())
    if not PHONE_REGEX.match(clean_phone):
        raise ValueError(
            "Invalid phone number format. Please provide a valid international phone number in E.164 format (e.g. +911234567890)."
        )

    from telethon import TelegramClient
    from telethon.sessions import StringSession
    from telethon.errors import FloodWaitError, PhoneNumberInvalidError

    # Create Telethon client using purely in-memory session (never written to disk)
    client = TelegramClient(StringSession(), settings.TELEGRAM_API_ID, settings.TELEGRAM_API_HASH)
    await client.connect()

    try:
        sent = await client.send_code_request(clean_phone)
        phone_code_hash = sent.phone_code_hash
    except FloodWaitError as e:
        await client.disconnect()
        raise TelegramFloodWaitException(e.seconds)
    except PhoneNumberInvalidError:
        await client.disconnect()
        raise ValueError("The phone number provided is not recognized by Telegram. Please check the digits.")
    except Exception as e:
        await client.disconnect()
        raise ValueError(f"Failed to request Telegram login code: {str(e)}")

    flow_id = str(uuid.uuid4())
    _flows[flow_id] = TelegramFlow(flow_id, clean_phone, client, phone_code_hash)
    return flow_id


# ---------------------------------------------------------------------------
# Flow Step 2: Verify Code
# ---------------------------------------------------------------------------

async def verify_telegram_code(flow_id: str, code: str, password: Optional[str] = None) -> Tuple[str, bool]:
    """
    Verifies code and optional 2-step verification password.
    Returns (status, needs_password).
    """
    verify_telegram_configuration()
    await cleanup_expired_flows()

    flow = _flows.get(flow_id)
    if not flow or flow.is_expired():
        raise ValueError("Invalid or expired login session. Please start over by requesting a new code.")

    from telethon.errors import (
        SessionPasswordNeededError,
        PhoneCodeInvalidError,
        PhoneCodeExpiredError,
        PasswordHashInvalidError,
        FloodWaitError,
    )

    client = flow.client
    clean_code = code.strip() if code else ""

    try:
        if password:
            await client.sign_in(password=password)
            flow.status = "verified"
            return ("verified", False)
        else:
            try:
                await client.sign_in(phone=flow.phone, code=clean_code, phone_code_hash=flow.phone_code_hash)
                flow.status = "verified"
                return ("verified", False)
            except SessionPasswordNeededError:
                return ("needs_password", True)
    except FloodWaitError as e:
        raise TelegramFloodWaitException(e.seconds)
    except PhoneCodeInvalidError:
        raise ValueError("The verification code you entered is incorrect. Please check your Telegram app and try again.")
    except PhoneCodeExpiredError:
        raise ValueError("The verification code has expired. Please request a new verification code.")
    except PasswordHashInvalidError:
        raise ValueError("The two-step verification password you entered is incorrect. Please try again.")
    except Exception as e:
        raise ValueError(f"Verification failed: {str(e)}")


# ---------------------------------------------------------------------------
# Flow Step 3: Analyze Account
# ---------------------------------------------------------------------------

async def analyze_telegram_account(flow_id: str) -> TelegramScanResult:
    """
    Performs comprehensive security inspection:
    - Lists active sessions & checks for foreign / impossible travel logins
    - Inspects session IPs for Tor / VPN / Proxy abuse
    - Checks Two-Step Verification protection
    - Audits Telegram service notification messages (user 777000) for security alerts
    - Always logs out and disconnects in finally block
    """
    verify_telegram_configuration()
    flow = _flows.get(flow_id)
    if not flow or flow.is_expired():
        raise ValueError("Session expired or invalid. Please request a new verification code.")

    if flow.status != "verified":
        raise ValueError("Account must be successfully verified before running the investigation.")

    client = flow.client
    phone_masked = mask_phone(flow.phone)

    try:
        from telethon.tl import functions

        # 1. Read account user info
        me = await client.get_me()
        account_name = f"{me.first_name or ''} {me.last_name or ''}".strip()
        if me.username:
            account_name += f" (@{me.username})"
        if not account_name:
            account_name = f"Telegram User ({phone_masked})"

        # 2. Read active authorizations (sessions)
        authorizations_res = await client(functions.account.GetAuthorizationsRequest())
        raw_auths = authorizations_res.authorizations

        # 3. Read 2-step verification password status
        has_password = False
        has_recovery = False
        try:
            pwd_info = await client(functions.account.GetPasswordRequest())
            has_password = getattr(pwd_info, "has_password", False)
            has_recovery = getattr(pwd_info, "has_recovery", False)
        except Exception:
            pass

        # 4. Read official Telegram service chat (user 777000)
        service_alerts: List[str] = []
        extracted_urls: List[str] = []
        url_regex = re.compile(r"https?://[^\s<>\"']+")

        try:
            async for msg in client.iter_messages(777000, limit=50):
                if msg.text:
                    lower_text = msg.text.lower()
                    if any(term in lower_text for term in ["login", "device", "authorized", "new login", "ip"]):
                        service_alerts.append(msg.text)
                    for u in url_regex.findall(msg.text):
                        if u not in extracted_urls and len(extracted_urls) < 5:
                            extracted_urls.append(u)
        except Exception:
            pass

        # 5. Process sessions and analyze IPs
        sessions: List[TelegramSession] = []
        findings: List[TelegramFinding] = []
        countries_list: List[str] = []
        now = time.time()

        for a in raw_auths:
            is_current = getattr(a, "current", False)
            dev_model = getattr(a, "device_model", "Unknown Device")
            app_name = f"{getattr(a, 'app_name', 'Telegram')} {getattr(a, 'app_version', '')}".strip()
            ip_addr = getattr(a, "ip", "")
            country = getattr(a, "country", "Unknown")
            date_active = getattr(a, "date_active", None)
            official_app = getattr(a, "official_app", True)

            # Format lastActive string
            if is_current:
                last_active_str = "Just now"
            elif date_active:
                if isinstance(date_active, datetime.datetime):
                    dt_active = date_active
                else:
                    dt_active = datetime.datetime.fromtimestamp(date_active, tz=datetime.timezone.utc)
                diff = now - dt_active.timestamp()
                if diff < 3600:
                    last_active_str = f"{int(diff // 60)} minutes ago"
                elif diff < 86400:
                    last_active_str = f"{int(diff // 3600)} hours ago"
                else:
                    last_active_str = f"{int(diff // 86400)} days ago"
            else:
                last_active_str = "Recently"

            # EXCLUDE or clearly label the current analysis session
            if is_current:
                sessions.append(
                    TelegramSession(
                        id=str(getattr(a, "hash", "curr")),
                        device=f"{dev_model} (This Security Analysis Session)",
                        app=app_name,
                        ip=ip_addr,
                        country=country,
                        lastActive=last_active_str,
                        isSuspicious=False,
                        isCurrent=True,
                        flagNote="Your current session for this security check (automatically logged out upon completion)",
                    )
                )
                continue

            # Non-current session: evaluate suspicion
            if country and country != "Unknown":
                countries_list.append(country)

            is_suspicious = False
            flag_note = None

            # Check IP using in-process network inspection logic
            ip_audit = None
            if ip_addr and is_safe_ip(ip_addr):
                try:
                    ip_audit = await inspect_ip(ip_addr)
                    if ip_audit.is_tor:
                        is_suspicious = True
                        flag_note = "Confirmed Tor anonymizer node used to connect"
                        findings.append(
                            TelegramFinding(
                                id=f"tg-tor-{len(findings) + 1}",
                                type="unknown_device",
                                title="Tor Anonymizer Node Logged Into Account",
                                explanation=f"An active session ({dev_model}) is routed through a known Tor exit node ({ip_addr}). Attackers use Tor to mask their identity.",
                                risk="critical",
                                date=last_active_str,
                            )
                        )
                    elif ip_audit.is_vpn or ip_audit.is_proxy or ip_audit.abuse_score > 50:
                        is_suspicious = True
                        flag_note = f"Masked datacenter proxy/VPN (Threat score: {ip_audit.abuse_score}/100)"
                        findings.append(
                            TelegramFinding(
                                id=f"tg-vpn-{len(findings) + 1}",
                                type="unknown_device",
                                title="Suspicious Proxy / VPN Session Detected",
                                explanation=f"A device ({dev_model}) logged in from an anonymizing proxy server in {ip_audit.country} ({ip_addr}).",
                                risk="high",
                                date=last_active_str,
                            )
                        )
                except Exception:
                    pass

            # Non-official or unknown client check
            if not official_app or "unknown" in dev_model.lower() or "linux" in dev_model.lower():
                is_suspicious = True
                flag_note = flag_note or "Unverified or custom desktop client"
                findings.append(
                    TelegramFinding(
                        id=f"tg-device-{len(findings) + 1}",
                        type="unknown_device",
                        title=f"Unrecognized Device: {dev_model}",
                        explanation=f"A login was authorized on '{dev_model}' running '{app_name}'. If you do not own this device, an unauthorized party has access.",
                        risk="high",
                        date=last_active_str,
                    )
                )

            # Inactive session check (> 30 days old)
            if date_active:
                dt_ts = date_active.timestamp() if isinstance(date_active, datetime.datetime) else date_active
                if (now - dt_ts) > (30 * 86400):
                    findings.append(
                        TelegramFinding(
                            id=f"tg-dormant-{len(findings) + 1}",
                            type="unknown_device",
                            title=f"Dormant Inactive Device: {dev_model}",
                            explanation=f"'{dev_model}' has remained logged into your account without activity for over 30 days. Recommended action: log out old devices.",
                            risk="medium",
                            date=last_active_str,
                        )
                    )

            sessions.append(
                TelegramSession(
                    id=str(getattr(a, "hash", f"sess-{len(sessions) + 1}")),
                    device=dev_model,
                    app=app_name,
                    ip=ip_addr,
                    country=country,
                    lastActive=last_active_str,
                    isSuspicious=is_suspicious,
                    isCurrent=False,
                    flagNote=flag_note,
                )
            )

        # 6. Foreign login & impossible travel detection
        from collections import Counter
        if countries_list:
            most_common_country, _ = Counter(countries_list).most_common(1)[0]
            for s in sessions:
                if not s.is_current and s.country != "Unknown" and s.country != most_common_country:
                    s.is_suspicious = True
                    s.flag_note = s.flag_note or f"Foreign access from {s.country}"
                    findings.append(
                        TelegramFinding(
                            id=f"tg-foreign-{len(findings) + 1}",
                            type="foreign_login",
                            title=f"Foreign Login from {s.country}",
                            explanation=f"Your account was accessed from {s.country}, while your primary login location is {most_common_country}.",
                            risk="high",
                            date=s.last_active,
                        )
                    )

        # Impossible travel: two sessions in different countries active within 3 hours
        for i in range(len(raw_auths)):
            for j in range(i + 1, len(raw_auths)):
                a1 = raw_auths[i]
                a2 = raw_auths[j]
                c1 = getattr(a1, "country", "")
                c2 = getattr(a2, "country", "")
                t1 = getattr(a1, "date_active", 0)
                t2 = getattr(a2, "date_active", 0)

                t1_ts = t1.timestamp() if isinstance(t1, datetime.datetime) else (t1 or 0)
                t2_ts = t2.timestamp() if isinstance(t2, datetime.datetime) else (t2 or 0)

                if c1 and c2 and c1 != "Unknown" and c2 != "Unknown" and c1 != c2:
                    if abs(t1_ts - t2_ts) < (3 * 3600):
                        findings.append(
                            TelegramFinding(
                                id=f"tg-travel-{len(findings) + 1}",
                                type="impossible_travel",
                                title="Physically Impossible Travel Detected",
                                explanation=f"Your account was active in {c1} and {c2} within under 3 hours apart. A person cannot travel that fast, indicating concurrent access by two different people.",
                                risk="critical",
                            )
                        )
                        break

        # 7. Two-step verification evaluation
        if not has_password:
            findings.append(
                TelegramFinding(
                    id=f"tg-2fa-{len(findings) + 1}",
                    type="no_2fa",
                    title="Two-Step Verification Password Is Off",
                    explanation="Your account is only guarded by SMS verification codes. If someone steals or intercepts your text code, they can access your account immediately without needing a password.",
                    risk="high",
                )
            )
        elif not has_recovery:
            findings.append(
                TelegramFinding(
                    id=f"tg-2fa-rec-{len(findings) + 1}",
                    type="no_2fa",
                    title="Two-Step Password Missing Recovery Email",
                    explanation="Two-step verification is enabled, but no recovery email is configured. If you ever forget your password, you could be permanently locked out.",
                    risk="medium",
                )
            )

        # 8. Service alerts findings
        if service_alerts:
            findings.append(
                TelegramFinding(
                    id=f"tg-alert-{len(findings) + 1}",
                    type="unknown_device",
                    title="Telegram Official Security Warning Received",
                    explanation="Your official Telegram notification history contains warnings about recent logins from unfamiliar devices or web portals.",
                    risk="high",
                )
            )

        if extracted_urls:
            for u in extracted_urls[:5]:
                try:
                    link_audit = await inspect_link(u)
                    if link_audit.verdict in ("Suspicious", "Dangerous"):
                        findings.append(
                            TelegramFinding(
                                id=f"tg-link-{len(findings) + 1}",
                                type="suspicious_link",
                                title=f"Suspicious Link in Security Notice: {link_audit.domain}",
                                explanation=f"A link sent in an official Telegram alert ({u}) was inspected: {link_audit.explanation}",
                                risk=link_audit.risk_level if link_audit.risk_level in ("high", "critical") else "high",
                            )
                        )
                except Exception:
                    pass

        # 9. Compute risk score & risk level
        crit_count = sum(1 for f in findings if f.risk == "critical")
        high_count = sum(1 for f in findings if f.risk == "high")
        med_count = sum(1 for f in findings if f.risk == "medium")
        low_count = sum(1 for f in findings if f.risk == "low")

        score = (crit_count * 30) + (high_count * 20) + (med_count * 10) + (low_count * 5)
        if not has_password:
            score = max(score, 35)

        score = max(0, min(100, score))

        if score >= 75 or crit_count > 0:
            risk_level: RiskLevel = "critical"
        elif score >= 50 or high_count > 0:
            risk_level = "high"
        elif score >= 25 or med_count > 0:
            risk_level = "medium"
        else:
            risk_level = "low"

        # 10. Generate plain-English summary, howItHappened & action checklist
        if crit_count > 0 or high_count > 0:
            summary = (
                f"Elevated risk: we detected {len(findings)} security finding(s), "
                f"including unfamiliar devices or foreign logins active on your Telegram account."
            )
            how_it_happened = (
                "An external party may have gained access if an SMS login code was shared or entered on an unverified link, "
                "or if an older active session was compromised. Because secondary two-step password verification was not protecting "
                "the account or was bypassed, persistent access could be established."
            )
        elif not has_password:
            summary = "Your account is active on authorized devices, but lacks secondary Two-Step password protection."
            how_it_happened = "No active intruder was identified, but your account could be vulnerable if someone intercepts your SMS login code."
        else:
            summary = "Your Telegram account is safe. All active logins match your regular devices and two-step verification is active."
            how_it_happened = "No indicators of unauthorized access were found. All active sessions match your regular devices and two-step verification is enabled."

        action_checklist = [
            "Open Telegram Settings > Devices > Tap 'Terminate All Other Sessions' immediately to kick out unknown devices.",
            "Turn on Two-Step Verification right now: Settings > Privacy and Security > Two-Step Verification.",
            "Verify your Recovery Email address under Two-Step Verification settings so you never get locked out.",
            "Never share SMS verification codes or login links with anyone, including anyone claiming to be Telegram Support."
        ]
        if any(f.type == "unknown_device" and "Dormant" in f.title for f in findings):
            action_checklist.insert(1, "Log out old devices: Open Settings > Devices and terminate sessions older than 30 days.")

        return TelegramScanResult(
            phone=phone_masked,
            accountName=account_name,
            riskScore=score,
            riskLevel=risk_level,
            summary=summary,
            sessions=sessions,
            findings=findings,
            howItHappened=how_it_happened,
            actionChecklist=action_checklist,
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            twoFactorEnabled=has_password,
        )

    finally:
        # Mandatory cleanup: Always log out this tool's session, disconnect, and remove flow from memory
        try:
            await client.log_out()
        except Exception:
            pass
        try:
            await client.disconnect()
        except Exception:
            pass
        _flows.pop(flow_id, None)


# ---------------------------------------------------------------------------
# Flow Step 4: Cancel Flow
# ---------------------------------------------------------------------------

async def cancel_telegram_flow(flow_id: str) -> None:
    """Disconnects and clears an active in-memory login flow."""
    verify_telegram_configuration()
    flow = _flows.pop(flow_id, None)
    if flow and flow.client:
        try:
            await flow.client.disconnect()
        except Exception:
            pass
