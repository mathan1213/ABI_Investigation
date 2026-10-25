import io
import re
import json
import zipfile
import logging
import datetime
from typing import Any, Optional
from urllib.parse import urlparse

import dateutil.parser
from bs4 import BeautifulSoup
from fastapi import HTTPException, UploadFile, status

from models import (
    TelegramScanResult,
    TelegramSession,
    TelegramFinding,
    DetectedFilesInfo,
    RiskLevel
)
from modules.network_module import inspect_ip, inspect_link, is_safe_ip

logger = logging.getLogger("telegram_log_parser")

# Limits
MAX_FILES = 5
MAX_FILE_BYTES = 10 * 1024 * 1024       # 10 MB per file
MAX_TOTAL_BYTES = 25 * 1024 * 1024      # 25 MB across all files
MAX_ZIP_ENTRIES = 200
MAX_ZIP_UNCOMPRESSED_BYTES = 50 * 1024 * 1024  # 50 MB
MAX_JSON_DEPTH = 20

# Regex Patterns
LOGIN_CODE_PATTERN = re.compile(r"\b\d{4,8}\b")
URL_PATTERN = re.compile(r"https?://[^\s<>\"'()]+")
IP_PATTERN = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

OFFICIAL_APP_KEYWORDS = [
    "telegram desktop",
    "telegram android",
    "telegram ios",
    "telegram macos",
    "telegram web",
    "telegram windows",
    "telegram linux",
    "telegram x",
    "telegram for android",
    "telegram for ios",
    "telegram for macos",
    "telegram for windows",
]

# Set of normalized key names (lowercase, stripped of spaces, underscores, and hyphens)
# A dict counts as a session if it has at least 2 keys from this set.
SESSION_KEY_SET = {
    "device",
    "devicemodel",
    "devicename",
    "model",
    "platform",
    "systemversion",
    "system",
    "application",
    "applicationname",
    "appname",
    "appversion",
    "applicationversion",
    "app",
    "lastip",
    "ip",
    "ipaddress",
    "lastcountry",
    "country",
    "location",
    "region",
    "lastregion",
    "lastactive",
    "dateactive",
    "datelastactive",
    "lastseen",
    "active",
    "date",
    "datecreated",
    "created",
    "createdat",
    "browser",
}


def _normalize_key(k: Any) -> str:
    """Normalizes key name: lowercase, stripping spaces, underscores and hyphens."""
    return re.sub(r"[\s_\-]+", "", str(k).lower())


def is_session_dict(d: Any) -> bool:
    """A dict counts as a session if it has at least two keys from SESSION_KEY_SET."""
    if not isinstance(d, dict):
        return False
    matched = 0
    for k in d.keys():
        if _normalize_key(k) in SESSION_KEY_SET:
            matched += 1
            if matched >= 2:
                return True
    return False


def redact_sensitive_codes(text: str) -> str:
    """Immediately masks login codes and 4-8 digit numeric sequences to ****."""
    if not text:
        return ""
    return LOGIN_CODE_PATTERN.sub("****", str(text))


def check_json_depth(obj: Any, current_depth: int = 0, max_depth: int = MAX_JSON_DEPTH) -> None:
    """Enforces JSON recursion depth limits to prevent stack overflow/DOS attacks."""
    if current_depth > max_depth:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Uploaded JSON file exceeds maximum allowed nesting depth of {max_depth} levels."
        )
    if isinstance(obj, dict):
        for v in obj.values():
            check_json_depth(v, current_depth + 1, max_depth)
    elif isinstance(obj, list):
        for item in obj:
            check_json_depth(item, current_depth + 1, max_depth)


def parse_date_robust(date_val: Any) -> Optional[datetime.datetime]:
    """
    Parses various date and timestamp formats into UTC datetime.
    Supports epoch seconds, epoch milliseconds, ISO strings, and Telegram's 'YYYY-MM-DD HH:MM:SS'.
    """
    if not date_val:
        return None
    if isinstance(date_val, datetime.datetime):
        if date_val.tzinfo is None:
            return date_val.replace(tzinfo=datetime.timezone.utc)
        return date_val
    if isinstance(date_val, (int, float)):
        # Support milliseconds or seconds
        if date_val > 1e11:
            date_val = date_val / 1000.0
        try:
            return datetime.datetime.fromtimestamp(date_val, tz=datetime.timezone.utc)
        except Exception:
            return None
    if isinstance(date_val, str):
        date_str = date_val.strip()
        if not date_str:
            return None
        # Support numeric string timestamps
        if date_str.isdigit():
            try:
                val = float(date_str)
                if val > 1e11:
                    val = val / 1000.0
                return datetime.datetime.fromtimestamp(val, tz=datetime.timezone.utc)
            except Exception:
                pass
        try:
            dt = dateutil.parser.parse(date_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            return dt
        except Exception:
            return None
    return None


def is_official_app(app_name: str) -> bool:
    if not app_name:
        return False
    app_lower = app_name.strip().lower()
    return any(official in app_lower for official in OFFICIAL_APP_KEYWORDS)


def normalize_session_entry(item: dict) -> Optional[dict]:
    """
    Normalizes a session dictionary to one internal shape:
    (device, app, platform, ip, country, region, createdAt, lastActive).
    Accepts epoch seconds, ISO strings, and Telegram's 'YYYY-MM-DD HH:MM:SS' format.
    """
    if not isinstance(item, dict):
        return None

    k_map: dict[str, Any] = {_normalize_key(k): v for k, v in item.items() if v is not None}

    # 1. Device
    device = (
        k_map.get("devicemodel")
        or k_map.get("device")
        or k_map.get("devicename")
        or k_map.get("model")
        or ""
    )

    # 2. App
    app = (
        k_map.get("applicationname")
        or k_map.get("appname")
        or k_map.get("application")
        or k_map.get("app")
        or ""
    )

    # 3. Platform
    platform = (
        k_map.get("platform")
        or k_map.get("systemversion")
        or k_map.get("system")
        or ""
    )

    # 4. IP
    ip = (
        k_map.get("lastip")
        or k_map.get("ip")
        or k_map.get("ipaddress")
        or ""
    )

    # 5. Country
    country = (
        k_map.get("lastcountry")
        or k_map.get("country")
        or k_map.get("location")
        or "Unknown"
    )

    # 6. Region
    region = (
        k_map.get("lastregion")
        or k_map.get("region")
        or ""
    )

    # Fallback inference for web sessions or sparse dicts
    browser = k_map.get("browser")
    if not device:
        if browser:
            device = f"Web Browser ({browser})"
        elif platform:
            device = f"{platform} Device"
        else:
            device = "Unknown Device"

    if not app:
        if browser or (platform and "web" in str(platform).lower()):
            app = f"Telegram Web ({browser})" if browser else "Telegram Web"
        else:
            app = "Telegram Client"

    # 7. createdAt
    created_raw = (
        k_map.get("datecreated")
        or k_map.get("created")
        or k_map.get("createdat")
    )
    created_dt = parse_date_robust(created_raw)

    # 8. lastActive
    last_active_raw = (
        k_map.get("lastactive")
        or k_map.get("dateactive")
        or k_map.get("datelastactive")
        or k_map.get("lastseen")
        or k_map.get("active")
        or k_map.get("date")
    )
    last_active_dt = parse_date_robust(last_active_raw)
    if not last_active_dt:
        last_active_dt = datetime.datetime.now(datetime.timezone.utc)

    is_current = bool(k_map.get("iscurrent") or k_map.get("current"))

    return {
        "device": str(device).strip(),
        "app": str(app).strip(),
        "platform": str(platform).strip(),
        "ip": str(ip).strip(),
        "country": str(country).strip(),
        "region": str(region).strip(),
        "createdAt": created_dt,
        "lastActive": last_active_dt,
        # Backward compatibility aliases
        "created": created_dt,
        "last_active": last_active_dt,
        "is_current": is_current,
    }


def extract_sessions_recursive(data: Any, depth: int = 0, max_depth: int = MAX_JSON_DEPTH) -> list[dict]:
    """
    Recursively searches parsed JSON for lists of session dictionaries.
    A dict counts as a session if it has at least two keys from SESSION_KEY_SET
    (case-insensitive, ignoring underscores and spaces).
    Accepts sessions under any key name (sessions, list, active_sessions, authorizations, web_sessions, etc.)
    or as a top-level list.
    """
    if depth > max_depth or not data:
        return []

    collected: list[dict] = []

    if isinstance(data, list):
        for item in data:
            if is_session_dict(item):
                normalized = normalize_session_entry(item)
                if normalized:
                    collected.append(normalized)
            elif isinstance(item, (dict, list)):
                collected.extend(extract_sessions_recursive(item, depth + 1, max_depth))
    elif isinstance(data, dict):
        if is_session_dict(data):
            norm = normalize_session_entry(data)
            if norm:
                collected.append(norm)
                return collected
        for k, v in data.items():
            if isinstance(v, (dict, list)):
                collected.extend(extract_sessions_recursive(v, depth + 1, max_depth))

    return collected


def parse_service_chat_messages(messages: list, out: "ParsedRawData", filename_hint: str) -> None:
    """Parses messages from official Telegram service chat, redacting codes and collecting login alerts."""
    for msg in messages:
        if not isinstance(msg, dict):
            continue

        raw_text = msg.get("text", "")
        # Text can sometimes be a list of mixed strings/dicts in Telegram export
        if isinstance(raw_text, list):
            text_parts = []
            for part in raw_text:
                if isinstance(part, str):
                    text_parts.append(part)
                elif isinstance(part, dict) and "text" in part:
                    text_parts.append(str(part["text"]))
            combined_text = " ".join(text_parts)
        else:
            combined_text = str(raw_text)

        # IMMEDIATE REDACTION OF ALL CODES
        redacted_text = redact_sensitive_codes(combined_text)
        date_dt = parse_date_robust(msg.get("date") or msg.get("date_unixtime"))

        # Check for service chat URLs
        found_urls = URL_PATTERN.findall(redacted_text)
        for u in found_urls:
            if u not in out.service_urls and len(out.service_urls) < 5:
                out.service_urls.append(u)

        lower_text = redacted_text.lower()

        # Check if it's a login code notification
        if "login code" in lower_text or "web login code" in lower_text or "code: ****" in lower_text:
            if date_dt:
                out.login_code_events.append(date_dt)

        # Check if it's a new login alert
        if any(marker in lower_text for marker in ("login alert", "new login", "we detected a login", "signed in", "device:")):
            device_match = re.search(r"device[:\s]+([^\n,]+)", redacted_text, re.IGNORECASE)
            location_match = re.search(r"(?:location|country)[:\s]+([^\n,]+)", redacted_text, re.IGNORECASE)
            ip_match = IP_PATTERN.search(redacted_text)

            device = device_match.group(1).strip() if device_match else "Unknown Device"
            location = location_match.group(1).strip() if location_match else "Unknown Location"
            ip = ip_match.group(0) if ip_match else ""

            out.login_alerts.append({
                "device": device,
                "location": location,
                "ip": ip,
                "date": date_dt or datetime.datetime.now(datetime.timezone.utc),
                "summary": f"Login alert for {device} ({location})"
            })


def extract_service_chats_recursive(
    data: Any,
    out: "ParsedRawData",
    filename_hint: str,
    depth: int = 0,
    max_depth: int = MAX_JSON_DEPTH
) -> bool:
    """
    Recursively finds official Telegram service chat (id 777000 or name 'Telegram')
    and ignores non-service chats.
    """
    if depth > max_depth or not data:
        return False

    found_any = False

    if isinstance(data, dict):
        chat_id = str(data.get("id", ""))
        chat_name = str(data.get("name", "")).strip().lower()
        messages = data.get("messages")

        if isinstance(messages, list):
            # It's a chat!
            is_service = (chat_id == "777000" or chat_name == "telegram")
            if is_service:
                out.has_service_chat_file = True
                out.recognized_sources.append(f"Official Telegram Service Chat (JSON: {filename_hint})")
                parse_service_chat_messages(messages, out, filename_hint)
                found_any = True
            else:
                out.ignored_non_service_chats += 1
        else:
            for k, v in data.items():
                if isinstance(v, (dict, list)):
                    if extract_service_chats_recursive(v, out, filename_hint, depth + 1, max_depth):
                        found_any = True
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, (dict, list)):
                if extract_service_chats_recursive(item, out, filename_hint, depth + 1, max_depth):
                    found_any = True

    return found_any


class ParsedRawData:
    def __init__(self):
        self.sessions: list[dict] = []
        self.login_alerts: list[dict] = []
        self.login_code_events: list[datetime.datetime] = []
        self.service_urls: list[str] = []
        self.has_sessions_file: bool = False
        self.has_service_chat_file: bool = False
        self.ignored_non_service_chats: int = 0
        self.recognized_sources: list[str] = []


def safe_unzip(content_bytes: bytes) -> list[tuple[str, bytes]]:
    """
    Safely unpacks a zip archive in memory.
    Guards against zip bombs, path traversal, nested zips, and limits entry counts.
    """
    files: list[tuple[str, bytes]] = []
    total_uncompressed = 0

    try:
        with zipfile.ZipFile(io.BytesIO(content_bytes)) as zf:
            infolist = zf.infolist()
            if len(infolist) > MAX_ZIP_ENTRIES:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Zip archive contains {len(infolist)} entries, exceeding the maximum allowed limit of {MAX_ZIP_ENTRIES}."
                )

            for info in infolist:
                # Path traversal guard
                filename = info.filename
                if ".." in filename or filename.startswith("/") or filename.startswith("\\") or ":" in filename:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Zip archive contains invalid or suspicious file paths (path traversal attempt)."
                    )

                # Nested zip guard
                if filename.lower().endswith(".zip"):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Nested zip archives are strictly prohibited for security reasons."
                    )

                if info.is_dir():
                    continue

                total_uncompressed += info.file_size
                if total_uncompressed > MAX_ZIP_UNCOMPRESSED_BYTES:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Uncompressed size of zip archive exceeds the safe limit of {MAX_ZIP_UNCOMPRESSED_BYTES // (1024*1024)} MB."
                    )

                entry_bytes = zf.read(info)
                files.append((filename, entry_bytes))
    except zipfile.BadZipFile:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The provided zip file appears to be corrupted or invalid."
        )

    return files


def parse_html_content(html_str: str, out: ParsedRawData, filename_hint: str) -> bool:
    """Safely parses Telegram export HTML files using BeautifulSoup (read-only AST parsing)."""
    soup = BeautifulSoup(html_str, "html.parser")
    found_something = False

    # Check for Active Sessions in HTML
    session_rows = soup.find_all(["tr", "div"], class_=lambda c: c and ("session" in c.lower() or "entry" in c.lower()))
    if not session_rows:
        # Check if table headers look like sessions
        tables = soup.find_all("table")
        for table in tables:
            headers = [th.get_text(strip=True).lower() for th in table.find_all(["th", "td"])]
            if any("device" in h or "application" in h or "last active" in h for h in headers):
                session_rows = table.find_all("tr")[1:]  # skip header
                break

    if session_rows:
        for row in session_rows:
            text = row.get_text(" ", strip=True)
            if not text:
                continue
            cols = [td.get_text(strip=True) for td in row.find_all(["td", "div"])]
            if len(cols) >= 3:
                device = cols[0]
                app = cols[1]
                ip_match = IP_PATTERN.search(text)
                ip = ip_match.group(0) if ip_match else ""

                country = "Unknown"
                last_active_dt = None
                for col in cols[2:]:
                    parsed_dt = parse_date_robust(col)
                    if parsed_dt:
                        last_active_dt = parsed_dt
                    elif not ip_match or col != ip:
                        country = col

                normalized = normalize_session_entry({
                    "device": device or "Unknown Device",
                    "app": app or "Unknown App",
                    "ip": ip,
                    "country": country,
                    "last_active": last_active_dt or datetime.datetime.now(datetime.timezone.utc),
                })
                if normalized:
                    out.sessions.append(normalized)
                    found_something = True

        if found_something:
            out.has_sessions_file = True
            out.recognized_sources.append(f"Active Sessions (HTML: {filename_hint})")

    # Check for Chat History
    title_tag = soup.find(["title", "h1", "div"], class_=lambda c: c and ("title" in c.lower() or "header" in c.lower()))
    title_text = title_tag.get_text(strip=True).lower() if title_tag else ""

    messages_divs = soup.find_all("div", class_=lambda c: c and "message" in c.lower())
    if messages_divs:
        is_service_chat = ("telegram" in title_text)
        if not is_service_chat:
            for m in messages_divs[:5]:
                if "login alert" in m.get_text().lower() or "we detected a login" in m.get_text().lower():
                    is_service_chat = True
                    break

        if not is_service_chat:
            out.ignored_non_service_chats += 1
        else:
            out.has_service_chat_file = True
            out.recognized_sources.append(f"Official Telegram Service Chat (HTML: {filename_hint})")
            for m in messages_divs:
                msg_text = redact_sensitive_codes(m.get_text(" ", strip=True))
                date_attr = m.get("title") or ""
                date_tag = m.find(class_=lambda c: c and "date" in c.lower())
                date_str = date_tag.get_text(strip=True) if date_tag else date_attr
                date_dt = parse_date_robust(date_str)

                for u in URL_PATTERN.findall(msg_text):
                    if u not in out.service_urls and len(out.service_urls) < 5:
                        out.service_urls.append(u)

                lower_text = msg_text.lower()
                if "login code" in lower_text or "code: ****" in lower_text:
                    if date_dt:
                        out.login_code_events.append(date_dt)

                if any(k in lower_text for k in ("login alert", "new login", "we detected a login", "device:")):
                    device_m = re.search(r"device[:\s]+([^\n,]+)", msg_text, re.IGNORECASE)
                    loc_m = re.search(r"(?:location|country)[:\s]+([^\n,]+)", msg_text, re.IGNORECASE)
                    ip_m = IP_PATTERN.search(msg_text)

                    out.login_alerts.append({
                        "device": device_m.group(1).strip() if device_m else "Unknown Device",
                        "location": loc_m.group(1).strip() if loc_m else "Unknown Location",
                        "ip": ip_m.group(0) if ip_m else "",
                        "date": date_dt or datetime.datetime.now(datetime.timezone.utc),
                        "summary": "Login alert from service chat"
                    })
            found_something = True

    return found_something


def parse_text_content(text: str, out: ParsedRawData, filename_hint: str) -> bool:
    """Parses text file exports, checking for JSON first or line-by-line session/alert dumps."""
    clean_text = text.strip()
    if clean_text.startswith("{") or clean_text.startswith("["):
        try:
            data = json.loads(clean_text)
            check_json_depth(data)
            sessions = extract_sessions_recursive(data)
            chat_found = extract_service_chats_recursive(data, out, filename_hint)
            if sessions:
                out.sessions.extend(sessions)
                out.has_sessions_file = True
                out.recognized_sources.append(f"Active Sessions ({len(sessions)} found in {filename_hint})")
            return bool(sessions or chat_found)
        except json.JSONDecodeError:
            pass

    # Line-by-line parse for raw text session exports
    lines = clean_text.splitlines()
    found = False
    for line in lines:
        line_redacted = redact_sensitive_codes(line)
        lower_line = line_redacted.lower()
        if "device:" in lower_line or "ip:" in lower_line:
            ip_m = IP_PATTERN.search(line_redacted)
            dev_m = re.search(r"device[:\s]+([^\n,;]+)", line_redacted, re.IGNORECASE)
            app_m = re.search(r"app[:\s]+([^\n,;]+)", line_redacted, re.IGNORECASE)
            loc_m = re.search(r"(?:country|location)[:\s]+([^\n,;]+)", line_redacted, re.IGNORECASE)

            if dev_m or ip_m:
                norm = normalize_session_entry({
                    "device": dev_m.group(1).strip() if dev_m else "Unknown Device",
                    "app": app_m.group(1).strip() if app_m else "Telegram Desktop",
                    "ip": ip_m.group(0) if ip_m else "",
                    "country": loc_m.group(1).strip() if loc_m else "Unknown",
                    "last_active": datetime.datetime.now(datetime.timezone.utc),
                })
                if norm:
                    out.sessions.append(norm)
                    found = True

    if found:
        out.has_sessions_file = True
        out.recognized_sources.append(f"Plaintext Sessions ({filename_hint})")
    return found


async def parse_and_analyze_telegram_export(files: list[UploadFile]) -> TelegramScanResult:
    """
    Main entry point for analyzing Telegram Desktop export files.
    Enforces security constraints, searches JSON recursively for sessions and service chat,
    applies 8 detection rules, logs safe diagnostics at INFO level, and returns TelegramScanResult.
    """
    if not files or len(files) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No files were provided. Please upload between 1 and 5 export files."
        )

    if len(files) > MAX_FILES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Too many files uploaded ({len(files)}). The maximum allowed is {MAX_FILES} files."
        )

    parsed_data = ParsedRawData()
    total_upload_size = 0
    discovered_keys_by_file: dict[str, list[str]] = {}

    try:
        for upload_file in files:
            file_bytes = await upload_file.read()
            file_size = len(file_bytes)
            total_upload_size += file_size

            if file_size > MAX_FILE_BYTES:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"File '{upload_file.filename}' exceeds the maximum allowed size of {MAX_FILE_BYTES // (1024*1024)} MB."
                )

            if total_upload_size > MAX_TOTAL_BYTES:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Total upload size exceeds the maximum allowed limit of {MAX_TOTAL_BYTES // (1024*1024)} MB."
                )

            # Unpack zip in memory if content is a zip file
            is_zip = file_bytes.startswith(b"PK\x03\x04") or (upload_file.filename and upload_file.filename.lower().endswith(".zip"))

            extracted_items: list[tuple[str, bytes]] = []
            if is_zip:
                extracted_items = safe_unzip(file_bytes)
            else:
                extracted_items = [(upload_file.filename or "uploaded_file", file_bytes)]

            # Analyze each extracted item
            for fname, content in extracted_items:
                # 1. Read with utf-8-sig (BOM support) and fallback to utf-8 with errors='replace'
                try:
                    text_content = content.decode("utf-8-sig")
                except Exception:
                    text_content = content.decode("utf-8", errors="replace")

                stripped = text_content.strip()
                handled = False

                # 2. Try JSON
                if stripped.startswith("{") or stripped.startswith("["):
                    try:
                        json_data = json.loads(stripped)
                        check_json_depth(json_data)

                        top_keys: list[str] = []
                        if isinstance(json_data, dict):
                            top_keys = sorted(list(json_data.keys()))
                            discovered_keys_by_file[fname] = top_keys
                        elif isinstance(json_data, list):
                            discovered_keys_by_file[fname] = [f"[list of {len(json_data)} items]"]

                        # Recursive sessions search
                        found_sessions = extract_sessions_recursive(json_data)
                        if found_sessions:
                            parsed_data.sessions.extend(found_sessions)
                            parsed_data.has_sessions_file = True
                            source_label = f"Active Sessions ({len(found_sessions)} found in {fname})"
                            if "web_sessions" in top_keys:
                                source_label += " (including Web Sessions)"
                            parsed_data.recognized_sources.append(source_label)
                            handled = True

                        # Recursive service chat search
                        if extract_service_chats_recursive(json_data, parsed_data, fname):
                            handled = True

                        # 6. Safe debug log at INFO level if unrecognized (key names and counts only, never values)
                        if not handled:
                            if isinstance(json_data, dict):
                                logger.info(
                                    "Unrecognized Telegram export file '%s'. Top-level keys: %s (count: %d)",
                                    fname,
                                    top_keys,
                                    len(top_keys)
                                )
                            elif isinstance(json_data, list):
                                logger.info(
                                    "Unrecognized Telegram export file '%s'. Top-level list with %d items.",
                                    fname,
                                    len(json_data)
                                )
                            else:
                                logger.info(
                                    "Unrecognized Telegram export file '%s'. Data type: %s",
                                    fname,
                                    type(json_data).__name__
                                )
                    except json.JSONDecodeError:
                        pass

                if handled:
                    continue

                # 3. Try HTML
                lower_preview = stripped[:500].lower()
                if "<html" in lower_preview or "<!doctype html" in lower_preview or "<div" in lower_preview or "<table" in lower_preview:
                    if parse_html_content(stripped, parsed_data, fname):
                        handled = True
                        continue
                    else:
                        logger.info("Unrecognized HTML export file '%s'. No sessions table or service chat messages detected.", fname)

                # 4. Try Text
                if not handled:
                    if parse_text_content(stripped, parsed_data, fname):
                        handled = True
                        continue
                    else:
                        logger.info("Unrecognized plaintext export file '%s'.", fname)

    finally:
        for f in files:
            await f.close()

    # Verify if ANY recognizable Telegram data was discovered
    has_valid_data = (
        len(parsed_data.sessions) > 0
        or len(parsed_data.login_alerts) > 0
        or len(parsed_data.login_code_events) > 0
    )

    if not has_valid_data:
        # Build improved 422 error message with found keys and specific hints
        all_keys: list[str] = []
        for keys in discovered_keys_by_file.values():
            for k in keys:
                if not k.startswith("[list of") and k not in all_keys:
                    all_keys.append(k)

        all_keys = sorted(all_keys)

        if parsed_data.ignored_non_service_chats > 0 or "messages" in all_keys:
            hint = "This looks like a personal chat export, which is ignored on purpose. Please upload only the official 'Telegram' service chat (User ID 777000) or your 'Active sessions' export."
        elif all_keys:
            hint = "This file has no session list. Re-export with only 'Active sessions' ticked in Telegram Desktop (Settings > Advanced > Export Telegram data)."
        else:
            hint = "Please follow the export guide: in Telegram Desktop, go to Settings > Advanced > Export Telegram data, select 'Active sessions' (Machine-readable JSON) or export your official 'Telegram' service chat history."

        if all_keys:
            detail = f"No recognizable Telegram export data could be found in the uploaded file(s). Found top-level keys: {all_keys}. Hint: {hint}"
        else:
            detail = f"No recognizable Telegram export data could be found in the uploaded file(s). Hint: {hint}"

        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=detail
        )

    # -----------------------------------------------------------------------
    # Apply the 8 Forensic Detection Rules
    # -----------------------------------------------------------------------
    findings: list[TelegramFinding] = []
    finding_id_counter = 1

    def add_finding(f_type: str, title: str, explanation: str, risk: RiskLevel, date_str: Optional[str] = None):
        nonlocal finding_id_counter
        findings.append(TelegramFinding(
            id=f"tg-{finding_id_counter}",
            type=f_type,
            title=title,
            explanation=explanation,
            risk=risk,
            date=date_str
        ))
        finding_id_counter += 1

    # Rule 1: Unofficial app or unfamiliar device/platform
    for s in parsed_data.sessions:
        app = s.get("app", "")
        if app and not is_official_app(app):
            add_finding(
                f_type="unofficial_app",
                title=f"Unofficial Telegram Client Detected ({app})",
                explanation=(
                    f"An active session is running on an unrecognized or unofficial client application: '{app}' "
                    f"on device '{s.get('device', 'Unknown')}'. Unofficial clients may harvest user data, "
                    "bypass official security protections, or act as unauthorized access channels."
                ),
                risk="high",
                date_str=s.get("last_active").isoformat() if isinstance(s.get("last_active"), datetime.datetime) else None
            )

    # Rule 2: Multi-country sessions
    countries = [s.get("country") for s in parsed_data.sessions if s.get("country") and s.get("country").lower() != "unknown"]
    unique_countries = sorted(list(set(countries)))
    if len(unique_countries) > 1:
        country_counts = {c: countries.count(c) for c in unique_countries}
        main_country = max(country_counts, key=country_counts.get)
        other_countries = [c for c in unique_countries if c != main_country]
        add_finding(
            f_type="foreign_login",
            title="Active Sessions from Multiple Countries",
            explanation=(
                f"Sessions were observed across {len(unique_countries)} distinct countries: {', '.join(unique_countries)}. "
                f"While the primary activity is in {main_country}, additional sessions originate from {', '.join(other_countries)}. "
                "Unless you frequently travel or use VPN services, foreign sessions represent high-probability unauthorized access."
            ),
            risk="high"
        )

    # Rule 3: Impossible Travel (< 3 hours between different countries)
    travel_events: list[tuple[datetime.datetime, str, str]] = []
    for s in parsed_data.sessions:
        dt = s.get("last_active")
        c = s.get("country", "")
        if isinstance(dt, datetime.datetime) and c and c.lower() != "unknown":
            travel_events.append((dt, c, s.get("device", "Session")))

    for a in parsed_data.login_alerts:
        dt = a.get("date")
        c = a.get("location", "")
        if isinstance(dt, datetime.datetime) and c and c.lower() != "unknown":
            travel_events.append((dt, c, a.get("device", "Alert")))

    travel_events.sort(key=lambda x: x[0])
    for i in range(len(travel_events) - 1):
        t1, c1, d1 = travel_events[i]
        t2, c2, d2 = travel_events[i + 1]
        if c1.lower() != c2.lower():
            diff_hours = abs((t2 - t1).total_seconds()) / 3600.0
            if diff_hours < 3.0:
                add_finding(
                    f_type="impossible_travel",
                    title="Impossible Travel Detected",
                    explanation=(
                        f"An account event in {c1} ({d1}) was followed by activity in {c2} ({d2}) "
                        f"just {diff_hours:.1f} hours later. Physical transit between these two countries "
                        "in under 3 hours is not plausible, strongly indicating session hijacking or credential sharing."
                    ),
                    risk="critical",
                    date_str=t2.isoformat()
                )
                break

    # Rule 4: Tor / VPN / Proxy / High-Abuse IP via inspect_ip
    unique_ips: list[str] = []
    for s in parsed_data.sessions:
        ip = s.get("ip", "").strip()
        if ip and ip not in unique_ips and len(unique_ips) < 20:
            unique_ips.append(ip)

    for a in parsed_data.login_alerts:
        ip = a.get("ip", "").strip()
        if ip and ip not in unique_ips and len(unique_ips) < 20:
            unique_ips.append(ip)

    for ip_str in unique_ips:
        if not is_safe_ip(ip_str):
            continue
        try:
            ip_check = await inspect_ip(ip_str)
            if ip_check.is_tor:
                add_finding(
                    f_type="threat_ip",
                    title=f"Tor Anonymizer Exit Node Used ({ip_str})",
                    explanation=(
                        f"The IP address {ip_str} associated with account activity is a verified Tor exit node in {ip_check.country}. "
                        "Tor routing is routinely employed by threat actors to conceal unauthorized logins and evasion tactics."
                    ),
                    risk="critical"
                )
            elif ip_check.is_vpn or ip_check.is_proxy or ip_check.abuse_score >= 20:
                add_finding(
                    f_type="threat_ip",
                    title=f"Commercial VPN, Proxy or Flagged IP ({ip_str})",
                    explanation=(
                        f"The IP address {ip_str} ({ip_check.country}, abuse score: {ip_check.abuse_score}%) "
                        f"is flagged as an anonymizing proxy, VPN, or abusive network. {ip_check.explanation}"
                    ),
                    risk="high"
                )
        except Exception:
            pass

    # Rule 5: Inactive sessions for 30+ days
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    for s in parsed_data.sessions:
        last_act = s.get("last_active")
        if isinstance(last_act, datetime.datetime):
            inactive_days = (now_utc - last_act).days
            if inactive_days >= 30:
                add_finding(
                    f_type="inactive_session",
                    title=f"Stale Inactive Session ({s.get('device', 'Device')})",
                    explanation=(
                        f"A session on '{s.get('device', 'Unknown')}' ({s.get('app', 'App')}) has remained logged in "
                        f"without activity for {inactive_days} days. Abandoned active sessions increase exposure if the underlying hardware is lost or decommissioned."
                    ),
                    risk="low",
                    date_str=last_act.isoformat()
                )

    # Rule 6: High frequency login alerts / codes (>= 3 within 24 hours)
    alert_timestamps = [a["date"] for a in parsed_data.login_alerts if isinstance(a.get("date"), datetime.datetime)]
    alert_timestamps.extend(parsed_data.login_code_events)
    alert_timestamps.sort()

    for i in range(len(alert_timestamps)):
        window_events = [t for t in alert_timestamps if 0 <= (t - alert_timestamps[i]).total_seconds() <= 86400]
        if len(window_events) >= 3:
            add_finding(
                f_type="takeover_attempt",
                title="Rapid Succession of Login Requests (Possible Takeover)",
                explanation=(
                    f"Observed {len(window_events)} login alerts or authentication code events within a single 24-hour window. "
                    "Surges in login verification events typically correspond to active account takeover attempts or brute-force OTP interception."
                ),
                risk="high",
                date_str=alert_timestamps[i].isoformat()
            )
            break

    # Rule 7: Login alerts for devices not currently in sessions (session ended)
    current_device_names = [s.get("device", "").lower() for s in parsed_data.sessions]
    for alert in parsed_data.login_alerts:
        alert_dev = alert.get("device", "")
        if alert_dev and alert_dev.lower() != "unknown device":
            match = any(alert_dev.lower() in d or d in alert_dev.lower() for d in current_device_names)
            if not match and len(parsed_data.sessions) > 0:
                add_finding(
                    f_type="ended_session",
                    title=f"Historical Login Alert for Ended Session ({alert_dev})",
                    explanation=(
                        f"Official Telegram alert recorded a successful login for '{alert_dev}' in {alert.get('location', 'Unknown')}, "
                        "but this device does not appear in your current active sessions. The session was subsequently terminated or logged out."
                    ),
                    risk="medium",
                    date_str=alert.get("date").isoformat() if isinstance(alert.get("date"), datetime.datetime) else None
                )
                break

    # Rule 8: URLs in service chat run through inspect_link
    for url in parsed_data.service_urls[:5]:
        try:
            link_check = await inspect_link(url)
            if link_check.risk_level in ("high", "critical") or link_check.verdict in ("Suspicious", "Dangerous"):
                add_finding(
                    f_type="suspicious_link",
                    title=f"Suspicious Link in Service Chat ({link_check.domain})",
                    explanation=(
                        f"The link '{url}' was found in messages and flagged with {link_check.risk_level} risk. "
                        f"{link_check.explanation}"
                    ),
                    risk=link_check.risk_level
                )
        except Exception:
            pass

    # -----------------------------------------------------------------------
    # Score and Overall Risk Computation
    # -----------------------------------------------------------------------
    severity_weights = {"low": 5, "medium": 10, "high": 20, "critical": 35}
    risk_score = 0
    has_critical = False
    has_high = False
    has_medium = False

    for f in findings:
        risk_score += severity_weights.get(f.risk, 5)
        if f.risk == "critical":
            has_critical = True
        elif f.risk == "high":
            has_high = True
        elif f.risk == "medium":
            has_medium = True

    risk_score = min(100, risk_score)

    if has_critical or risk_score >= 60:
        overall_risk = "critical"
    elif has_high or risk_score >= 40:
        overall_risk = "high"
    elif has_medium or risk_score >= 15:
        overall_risk = "medium"
    else:
        overall_risk = "low"

    # Build Session objects with normalized shape
    session_models: list[TelegramSession] = []
    for idx, s in enumerate(parsed_data.sessions):
        app = s.get("app", "")
        country = s.get("country", "")
        is_susp = (not is_official_app(app)) or (len(unique_countries) > 1 and country and country != unique_countries[0])

        last_act = s.get("lastActive") or s.get("last_active")
        last_act_str = last_act.isoformat() if isinstance(last_act, datetime.datetime) else str(last_act)

        created_val = s.get("createdAt") or s.get("created")
        created_str = created_val.isoformat() if isinstance(created_val, datetime.datetime) else (str(created_val) if created_val else None)

        session_models.append(TelegramSession(
            id=f"sess-{idx + 1}",
            device=s.get("device", "Unknown Device"),
            app=s.get("app", "Telegram Client"),
            platform=s.get("platform", ""),
            ip=s.get("ip", "Unknown IP"),
            country=s.get("country", "Unknown Location"),
            region=s.get("region", ""),
            createdAt=created_str,
            lastActive=last_act_str,
            isSuspicious=is_susp,
            isCurrent=s.get("is_current"),
            flagNote="Suspicious client or foreign location" if is_susp else None
        ))

    # Mandatory manualChecks
    manual_checks = [
        "Turn on Two-Step Verification (Settings > Privacy and Security > Two-Step Verification) with a strong, unique password.",
        "Add and verify a recovery email address to prevent irreversible lockout.",
        "Review Active Sessions periodically in Settings > Devices and terminate any unfamiliar sessions immediately.",
        "Audit Phone Number Privacy settings (Settings > Privacy and Security > Phone Number) so that only your contacts can see your number.",
    ]

    # Data Coverage note
    data_coverage = (
        "This analysis was produced from uploaded export files. Active session records and official Telegram service chat "
        "alerts were parsed and correlated. Limitations: Snapshot exports cannot verify real-time Two-Step Verification status, "
        "cannot determine whether an authorized session was physically shared, and cannot reveal sessions opened after the export was generated."
    )

    action_checklist = [
        "Terminate all unrecognized active sessions immediately in Telegram Desktop (Settings > Devices > Terminate All Other Sessions).",
        "Enable Two-Step Verification with a memorable password and recovery email.",
        "Verify your linked phone number and SIM security with your mobile carrier.",
        "Report any suspicious login alerts or phishing URLs received in the service chat."
    ]

    how_it_happened = (
        f"Forensic analysis of the uploaded export identified {len(findings)} anomaly indicator(s). "
        f"{len(parsed_data.sessions)} active session(s) and {len(parsed_data.login_alerts)} service chat login alert(s) were evaluated. "
        "Attackers frequently target Telegram accounts via SMS interception, malicious unofficial client apps, or phishing links designed to capture OTP codes."
    )

    summary = (
        f"Export analysis completed with risk score {risk_score}/100 ({overall_risk.upper()}). "
        f"Identified {len(findings)} security finding(s) across {len(parsed_data.sessions)} session(s)."
    )

    detected_files_info = DetectedFilesInfo(
        sessions=parsed_data.has_sessions_file,
        loginAlerts=parsed_data.has_service_chat_file,
        ignoredNonServiceChats=parsed_data.ignored_non_service_chats,
        fileDetails=parsed_data.recognized_sources
    )

    return TelegramScanResult(
        phone="Uploaded Export",
        accountName="Telegram User",
        riskScore=risk_score,
        riskLevel=overall_risk,
        summary=summary,
        sessions=session_models,
        findings=findings,
        howItHappened=how_it_happened,
        actionChecklist=action_checklist,
        timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        twoFactorEnabled=None,  # NEVER claim 2FA is on or off
        detectedFiles=detected_files_info,
        dataCoverage=data_coverage,
        manualChecks=manual_checks
    )
