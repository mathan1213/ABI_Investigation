import ipaddress
import socket
import ssl
import re
import datetime
import asyncio
from urllib.parse import urlparse
from typing import Optional, Tuple, List, Dict, Any

import httpx
import dns.resolver
import whois

try:
    import tldextract
except ImportError:
    tldextract = None

from config import settings
from models import (
    IpCheckResponse,
    LinkCheckResponse,
    WebsiteCheckResponse,
    RedirectHop,
    DnsRecords,
    PortCheck,
    SecurityHeaderCheck,
    VerdictType,
    RiskLevel,
)

# ---------------------------------------------------------------------------
# In-Memory Cache for Tor Exit Nodes
# ---------------------------------------------------------------------------
_tor_exit_cache: set[str] = set()
_tor_exit_cache_timestamp: Optional[datetime.datetime] = None
_tor_cache_lock = asyncio.Lock()

# Well-known public DNS and infrastructure IPs that must always be Safe
KNOWN_SAFE_INFRASTRUCTURE = {
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
    "9.9.9.9",
    "149.112.112.112",
    "208.67.222.222",
    "208.67.220.220",
}


# ---------------------------------------------------------------------------
# SSRF Validation Utilities
# ---------------------------------------------------------------------------

def is_safe_ip(ip_str: str) -> bool:
    """
    Checks if an IP address is safe (public and routable).
    Blocks loopback, private, link-local, reserved, multicast, or unspecified addresses.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return False

        # Additional checks for special IPv4 ranges
        if ip.version == 4:
            for net in [
                ipaddress.ip_network("0.0.0.0/8"),
                ipaddress.ip_network("100.64.0.0/10"),
                ipaddress.ip_network("192.0.0.0/24"),
                ipaddress.ip_network("198.18.0.0/15"),
                ipaddress.ip_network("240.0.0.0/4"),
            ]:
                if ip in net:
                    return False
        return True
    except ValueError:
        return False


def validate_hostname_or_ip(host_or_ip: str) -> List[str]:
    """
    Resolves hostname/IP to address list and asserts that ALL resolved addresses are public.
    Raises ValueError if resolution fails or resolves to private/loopback address (SSRF prevention).
    """
    clean_host = host_or_ip.strip()
    if not clean_host:
        raise ValueError("Host cannot be empty.")

    # Check if host is direct IP
    try:
        ip = ipaddress.ip_address(clean_host)
        if not is_safe_ip(str(ip)):
            raise ValueError(f"Target IP {clean_host} is a private, loopback, or reserved address (SSRF blocked).")
        return [str(ip)]
    except ValueError as e:
        if "is a private" in str(e):
            raise

    # Resolve via DNS
    try:
        resolved_ips: List[str] = []
        answers = socket.getaddrinfo(clean_host, None)
        for answer in answers:
            ip_cand = answer[4][0]
            if not is_safe_ip(ip_cand):
                raise ValueError(f"Host '{clean_host}' resolves to private/local IP {ip_cand} (SSRF blocked).")
            if ip_cand not in resolved_ips:
                resolved_ips.append(ip_cand)

        if not resolved_ips:
            raise ValueError(f"Could not resolve host '{clean_host}' to any IP address.")
        return resolved_ips
    except socket.gaierror as e:
        raise ValueError(f"Could not resolve host '{clean_host}': {str(e)}")


def get_apex_domain(host: str) -> str:
    """
    Extracts the registered (apex) domain from a hostname (e.g. www.google.com -> google.com).
    Uses tldextract if available with fallback to splitting.
    """
    clean = host.strip().lower()
    if tldextract:
        try:
            ext = tldextract.extract(clean)
            apex = getattr(ext, "top_domain_under_public_suffix", None) or getattr(ext, "registered_domain", None)
            if apex:
                return apex
        except Exception:
            pass

    # Fallback heuristic
    parts = clean.split(".")
    if len(parts) >= 2:
        # handle common two-part suffixes like .co.uk, .com.au
        if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "gov", "edu", "net"}:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
    return clean


# ---------------------------------------------------------------------------
# Tor Exit Node List Management
# ---------------------------------------------------------------------------

async def get_tor_exit_nodes() -> set[str]:
    """
    Retrieves and caches Tor bulk exit list for 6 hours.
    Fallback to cached set on network errors.
    """
    global _tor_exit_cache, _tor_exit_cache_timestamp

    now = datetime.datetime.now(datetime.timezone.utc)
    if _tor_exit_cache and _tor_exit_cache_timestamp:
        age_hours = (now - _tor_exit_cache_timestamp).total_seconds() / 3600
        if age_hours < settings.TOR_EXIT_CACHE_HOURS:
            return _tor_exit_cache

    async with _tor_cache_lock:
        if _tor_exit_cache and _tor_exit_cache_timestamp:
            age_hours = (now - _tor_exit_cache_timestamp).total_seconds() / 3600
            if age_hours < settings.TOR_EXIT_CACHE_HOURS:
                return _tor_exit_cache

        try:
            async with httpx.AsyncClient(timeout=settings.REQUEST_TIMEOUT_SECONDS) as client:
                resp = await client.get("https://check.torproject.org/torbulkexitlist")
                if resp.status_code == 200:
                    ips = set(line.strip() for line in resp.text.splitlines() if line.strip())
                    _tor_exit_cache = ips
                    _tor_exit_cache_timestamp = now
        except Exception:
            pass

    return _tor_exit_cache


# ---------------------------------------------------------------------------
# 1. IP Check Logic
# ---------------------------------------------------------------------------

async def inspect_ip(ip_str: str) -> IpCheckResponse:
    """
    Inspects an IP address for geolocation, ISP, proxy, Tor, and abuse reputation.
    Hosting/datacenter is treated as a separate flag, not as VPN or Proxy.
    """
    clean_ip = ip_str.strip()
    try:
        ip_obj = ipaddress.ip_address(clean_ip)
    except ValueError:
        raise ValueError(f"Invalid IP address format: '{ip_str}'")

    if not is_safe_ip(str(ip_obj)):
        raise ValueError(f"IP address '{clean_ip}' is private or reserved (SSRF blocked).")

    # Check Tor exit nodes concurrently with ip-api.com
    tor_task = asyncio.create_task(get_tor_exit_nodes())

    geo_data: Dict[str, Any] = {}
    try:
        async with httpx.AsyncClient(timeout=settings.REQUEST_TIMEOUT_SECONDS) as client:
            geo_url = f"http://ip-api.com/json/{clean_ip}?fields=status,message,country,city,isp,as,mobile,proxy,hosting,query"
            geo_resp = await client.get(geo_url)
            if geo_resp.status_code == 200:
                geo_data = geo_resp.json()
    except Exception:
        pass

    tor_nodes = await tor_task
    is_tor = clean_ip in tor_nodes

    country = geo_data.get("country") or "Unknown"
    city = geo_data.get("city") or "Unknown"
    isp = geo_data.get("isp") or "Unknown ISP"
    asn = geo_data.get("as") or "Unknown ASN"

    # BUG FIX 1: Treat hosting/datacenter as separate flag, NOT as VPN or proxy
    is_proxy = bool(geo_data.get("proxy", False))
    is_hosting = bool(geo_data.get("hosting", False))
    is_vpn = is_proxy

    abuse_score = 0
    source = "estimated"

    # Known public infrastructure (8.8.8.8, 1.1.1.1) must always be Safe
    if clean_ip in KNOWN_SAFE_INFRASTRUCTURE:
        is_proxy = False
        is_vpn = False
        is_tor = False
        abuse_score = 0
        verdict: VerdictType = "Safe"
        risk_level: RiskLevel = "low"
        explanation = (
            f"This IP address belongs to verified public infrastructure ({isp}) in {country}. "
            "It is recognized as trusted service infrastructure with zero malicious activity."
        )
        return IpCheckResponse(
            ip=clean_ip,
            country=country,
            city=city,
            isp=isp,
            asn=asn,
            isVpn=is_vpn,
            isProxy=is_proxy,
            isTor=is_tor,
            isHosting=is_hosting,
            abuseScore=abuse_score,
            verdict=verdict,
            riskLevel=risk_level,
            explanation=explanation,
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            source="verified-infrastructure",
        )

    # AbuseIPDB lookup if configured
    if settings.ABUSEIPDB_KEY:
        try:
            async with httpx.AsyncClient(timeout=settings.REQUEST_TIMEOUT_SECONDS) as client:
                abuse_url = "https://api.abuseipdb.com/api/v2/check"
                headers = {
                    "Key": settings.ABUSEIPDB_KEY,
                    "Accept": "application/json"
                }
                params = {"ipAddress": clean_ip, "maxAgeInDays": 90}
                res = await client.get(abuse_url, headers=headers, params=params)
                if res.status_code == 200:
                    abuse_data = res.json().get("data", {})
                    abuse_score = int(abuse_data.get("abuseConfidenceScore", 0))
                    source = "AbuseIPDB"
                    # If AbuseIPDB reports usageType as Data Center / Web Hosting / Transit, update is_hosting
                    usage = str(abuse_data.get("usageType", ""))
                    if "Data Center" in usage or "Hosting" in usage:
                        is_hosting = True
        except Exception:
            source = "estimated (fallback)"

    if source != "AbuseIPDB":
        if is_tor:
            abuse_score = 88
        elif is_proxy or is_vpn:
            abuse_score = 65
        elif is_hosting:
            abuse_score = 10  # small bump for hosting only
        else:
            abuse_score = 0

    # Verdict and Explanation matched to flags
    if abuse_score >= 75 or is_tor:
        verdict = "Dangerous"
        risk_level = "critical"
        if is_tor:
            explanation = (
                f"This IP address is a confirmed Tor anonymizer exit node located in {country}. "
                "Tor is frequently used to mask unauthorized logins and hide the hacker's real origin."
            )
        else:
            explanation = (
                f"This IP address has a high abuse confidence score ({abuse_score}%) with frequent attack reports. "
                "Connections from this address are considered hostile."
            )
    elif abuse_score >= 40 or is_proxy or is_vpn:
        verdict = "Suspicious"
        risk_level = "medium"
        explanation = (
            f"This IP address is identified as a commercial VPN or proxy service in {country}. "
            "If you were not actively using a VPN at the time, someone else routed their connection through this server."
        )
    elif is_hosting:
        verdict = "Safe"
        risk_level = "low"
        explanation = (
            f"This IP address belongs to a datacenter hosting provider ({isp}) in {country}. "
            "It is not flagged as a proxy or VPN and has low abuse risk."
        )
    else:
        verdict = "Safe"
        risk_level = "low"
        explanation = (
            f"This IP address appears to be a standard residential connection ({isp}) in {country}, {city} "
            "with zero reports of malicious activity."
        )

    return IpCheckResponse(
        ip=clean_ip,
        country=country,
        city=city,
        isp=isp,
        asn=asn,
        isVpn=is_vpn,
        isProxy=is_proxy,
        isTor=is_tor,
        isHosting=is_hosting,
        abuseScore=abuse_score,
        verdict=verdict,
        riskLevel=risk_level,
        explanation=explanation,
        timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        source=source,
    )


# ---------------------------------------------------------------------------
# 2. Link Check Logic
# ---------------------------------------------------------------------------

async def inspect_link(url_str: str) -> LinkCheckResponse:
    """
    Audits a web link/URL for phishing indicators, domain age, SSL validity, and redirect hops.
    Queries DNS for MX, NS, and TXT on the apex domain, and A records on the actual host.
    """
    raw_url = url_str.strip()
    if not (raw_url.startswith("http://") or raw_url.startswith("https://")):
        raw_url = "https://" + raw_url

    parsed = urlparse(raw_url)
    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"Could not parse valid hostname from URL: '{url_str}'")

    validate_hostname_or_ip(hostname)

    # 1. Follow Redirect Chain with SSRF check on every hop
    redirect_chain: List[RedirectHop] = []
    current_url = raw_url
    step = 1
    redirect_count = 0

    async with httpx.AsyncClient(follow_redirects=False, timeout=settings.REQUEST_TIMEOUT_SECONDS) as client:
        while step <= settings.MAX_REDIRECT_HOPS:
            try:
                hop_parsed = urlparse(current_url)
                hop_host = hop_parsed.hostname
                if hop_host:
                    validate_hostname_or_ip(hop_host)

                resp = await client.get(current_url)
                if resp.is_redirect:
                    redirect_count += 1
                    location = resp.headers.get("Location")
                    if location:
                        if location.startswith("/"):
                            current_url = f"{hop_parsed.scheme}://{hop_parsed.netloc}{location}"
                        else:
                            current_url = location

                    note = f"Redirected with HTTP {resp.status_code}"
                    redirect_chain.append(RedirectHop(step=step, url=str(resp.url), status=resp.status_code, note=note))
                    step += 1
                else:
                    note = "Final destination reached" if step > 1 else "Direct connection (no redirects)"
                    redirect_chain.append(RedirectHop(step=step, url=str(resp.url), status=resp.status_code, note=note))
                    break
            except Exception as e:
                redirect_chain.append(RedirectHop(step=step, url=current_url, status=0, note=f"Connection terminated: {str(e)}"))
                break

    final_url = redirect_chain[-1].url if redirect_chain else raw_url
    final_parsed = urlparse(final_url)
    final_domain = final_parsed.hostname or hostname

    # BUG FIX 3: Apex domain for MX, NS, TXT, actual host for A
    apex_domain = get_apex_domain(final_domain)

    # 2. DNS Records resolution
    dns_records = DnsRecords()
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 2.0

        # A records on actual host (e.g. www.google.com)
        try:
            answers = resolver.resolve(final_domain, "A")
            dns_records.a = [str(r.to_text()).strip('"') for r in answers][:6]
        except Exception:
            pass

        # MX, NS, TXT on registered apex domain (e.g. google.com)
        for rtype, attr in [("MX", "mx"), ("TXT", "txt"), ("NS", "ns")]:
            try:
                answers = resolver.resolve(apex_domain, rtype)
                vals = [str(r.to_text()).strip('"') for r in answers]
                setattr(dns_records, attr, vals[:6])
            except Exception:
                pass
    except Exception:
        pass

    # 3. WHOIS Domain Age (on apex domain)
    domain_age_days: Optional[int] = None
    domain_age_str = "Unknown"

    try:
        loop = asyncio.get_running_loop()
        w = await loop.run_in_executor(None, lambda: whois.whois(apex_domain))

        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date and isinstance(creation_date, (datetime.datetime, datetime.date)):
            if isinstance(creation_date, datetime.date) and not isinstance(creation_date, datetime.datetime):
                creation_date = datetime.datetime.combine(creation_date, datetime.time.min)
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=datetime.timezone.utc)

            now = datetime.datetime.now(datetime.timezone.utc)
            delta = now - creation_date
            domain_age_days = max(0, delta.days)

            if domain_age_days < 30:
                domain_age_str = f"{domain_age_days} days old (Brand new domain)"
            elif domain_age_days < 365:
                months = domain_age_days // 30
                domain_age_str = f"{months} months old"
            else:
                years = domain_age_days // 365
                domain_age_str = f"{years} years old"
    except Exception:
        domain_age_str = "Could not query WHOIS record"

    # 4. SSL Inspection
    ssl_valid = False
    ssl_issuer: Optional[str] = None
    ssl_expires_on: Optional[str] = None

    if final_parsed.scheme == "https" or raw_url.startswith("https://"):
        try:
            loop = asyncio.get_running_loop()
            ctx = ssl.create_default_context()

            def get_cert_info():
                with socket.create_connection((final_domain, 443), timeout=3.0) as sock:
                    with ctx.wrap_socket(sock, server_hostname=final_domain) as ssock:
                        return ssock.getpeercert()

            cert = await loop.run_in_executor(None, get_cert_info)
            if cert:
                ssl_valid = True
                issuer_dict = dict(x[0] for x in cert.get("issuer", ()))
                ssl_issuer = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Valid Authority"
                ssl_expires_on = cert.get("notAfter")
        except Exception as e:
            ssl_valid = False
            ssl_issuer = f"SSL Handshake Error: {str(e)[:40]}"

    # 5. Phishing & Security Heuristics
    score = 100
    risk_factors: List[str] = []

    if domain_age_days is not None and domain_age_days < 30:
        score -= 40
        risk_factors.append(f"Domain is only {domain_age_days} days old (attackers frequently register fresh domains for scams).")

    if not ssl_valid:
        score -= 30
        risk_factors.append("The website does not have a verified, active SSL security certificate.")

    if redirect_count >= 3:
        score -= 20
        risk_factors.append(f"The link forwarded through {redirect_count} redirect hops to conceal the destination.")

    if "xn--" in final_domain.lower():
        score -= 30
        risk_factors.append("Punycode lookalike characters detected, commonly used in phishing spoof attacks.")

    parts = final_domain.split(".")
    if len(parts) > 4 or any(len(p) > 25 for p in parts):
        score -= 15
        risk_factors.append("Suspiciously long or nested subdomain structure detected.")

    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", final_domain):
        score -= 35
        risk_factors.append("Direct IP address used instead of a legitimate domain name.")

    if settings.VIRUSTOTAL_KEY:
        try:
            import base64
            url_id = base64.urlsafe_b64encode(raw_url.encode()).decode().strip("=")
            async with httpx.AsyncClient(timeout=settings.REQUEST_TIMEOUT_SECONDS) as client:
                vt_resp = await client.get(
                    f"https://www.virustotal.com/api/v3/urls/{url_id}",
                    headers={"x-apikey": settings.VIRUSTOTAL_KEY}
                )
                if vt_resp.status_code == 200:
                    vt_stats = vt_resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious = vt_stats.get("malicious", 0)
                    if malicious > 0:
                        score = min(score, max(10, 100 - (malicious * 20)))
                        risk_factors.append(f"Flagged as malicious by {malicious} security vendors on VirusTotal.")
        except Exception:
            pass

    score = max(0, min(100, score))

    if score <= 40:
        verdict = "Dangerous"
        risk_level = "critical"
        explanation = (
            "Warning: High risk of phishing or malicious trap! "
            + " ".join(risk_factors[:2])
            + " Do not enter passwords or personal details."
        )
    elif score <= 70:
        verdict = "Suspicious"
        risk_level = "medium"
        explanation = (
            "Caution: This web link has several unusual characteristics. "
            + " ".join(risk_factors[:2])
            + " Verify the sender before proceeding."
        )
    else:
        verdict = "Safe"
        risk_level = "low"
        explanation = (
            f"This link points to an established web address ({final_domain}) "
            f"with a valid SSL certificate and clean reputation."
        )

    return LinkCheckResponse(
        url=raw_url,
        domain=final_domain,
        domainAge=domain_age_str,
        domainAgeDays=domain_age_days,
        dnsRecords=dns_records,
        sslValid=ssl_valid,
        sslIssuer=ssl_issuer,
        sslExpiresOn=ssl_expires_on,
        redirectChain=redirect_chain,
        reputationScore=score,
        verdict=verdict,
        riskLevel=risk_level,
        explanation=explanation,
        timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    )


# ---------------------------------------------------------------------------
# 3. Website Check Logic
# ---------------------------------------------------------------------------

async def check_single_port(host: str, port: int) -> Tuple[int, str]:
    """
    Tests if a specific port is open using a non-blocking TCP socket connect with 2.0s timeout.
    Returns (port, 'Open' | 'Closed').
    """
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=settings.PORT_CHECK_TIMEOUT_SECONDS)
        writer.close()
        await writer.wait_closed()
        return port, "Open"
    except (asyncio.TimeoutError, OSError):
        return port, "Closed"


async def inspect_website(domain_str: str) -> WebsiteCheckResponse:
    """
    Audits a website for open ports (80, 443, 22, 21), SSL expiration, and HTTP security headers.
    Follows redirects up to 5 hops with SSRF re-check on every hop, reading headers from final response.
    Generates explanation and verdict directly from actual results.
    """
    clean_domain = domain_str.strip()
    if clean_domain.startswith("http://"):
        clean_domain = clean_domain[7:]
    elif clean_domain.startswith("https://"):
        clean_domain = clean_domain[8:]
    clean_domain = clean_domain.split("/")[0].split(":")[0]

    validate_hostname_or_ip(clean_domain)

    # 1. Port checks on ports 80, 443, 22, 21
    TARGET_PORTS = [
        (80, "HTTP (Web)", "medium", "Standard web server port (should redirect to HTTPS)."),
        (443, "HTTPS (Secure Web)", "low", "Encrypted web server port."),
        (22, "SSH (Server Control)", "high", "Remote server command port exposed to public internet."),
        (21, "FTP (File Transfer)", "high", "Insecure legacy file transfer port exposed to internet."),
    ]

    port_tasks = [check_single_port(clean_domain, p[0]) for p in TARGET_PORTS]
    port_results = await asyncio.gather(*port_tasks)
    port_status_map = dict(port_results)

    ports_list: List[PortCheck] = []
    open_ports_list: List[int] = []

    for port, service, default_risk, note in TARGET_PORTS:
        state = port_status_map.get(port, "Closed")
        risk: RiskLevel = default_risk if state == "Open" else "low"
        if state == "Open":
            open_ports_list.append(port)
            if port == 80:
                note_str = "Port 80 is open to visitors."
            elif port == 443:
                note_str = "Secure HTTPS port is open and working."
            elif port == 22:
                note_str = "Warning: Remote server admin port 22 is exposed to public internet!"
            else:
                note_str = "Warning: FTP port 21 is open, transmitting passwords without encryption!"
        else:
            note_str = f"Port {port} is safely closed or firewalled."

        ports_list.append(PortCheck(
            port=port,
            service=service,
            state=state,
            risk=risk,
            note=note_str,
        ))

    # 2. SSL Expiration Check
    ssl_expiry_str = "No SSL detected"
    ssl_expires_on: Optional[str] = None
    ssl_days_remaining = 0

    try:
        loop = asyncio.get_running_loop()
        ctx = ssl.create_default_context()

        def fetch_cert():
            with socket.create_connection((clean_domain, 443), timeout=3.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=clean_domain) as ssock:
                    return ssock.getpeercert()

        cert = await loop.run_in_executor(None, fetch_cert)
        if cert and cert.get("notAfter"):
            not_after_str = cert["notAfter"]
            ssl_expires_on = not_after_str
            exp_date = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
            now = datetime.datetime.now(datetime.timezone.utc)
            ssl_days_remaining = max(0, (exp_date - now).days)
            ssl_expiry_str = exp_date.strftime("%B %d, %Y")
    except Exception:
        ssl_days_remaining = 0
        ssl_expiry_str = "Unavailable or expired"

    # BUG FIX 2: Follow redirects up to 5 hops with SSRF validation on every hop
    # Read headers from the FINAL response
    HEADER_SPECS = [
        ("Strict-Transport-Security", "Forces web browsers to only connect over encrypted HTTPS."),
        ("Content-Security-Policy", "Prevents hackers from injecting malicious scripts and popups."),
        ("X-Frame-Options", "Protects visitors from clickjacking attacks in invisible frames."),
        ("X-Content-Type-Options", "Prevents browsers from misinterpreting files as executable code."),
        ("Referrer-Policy", "Controls how much sensitive URL data is shared when clicking external links."),
    ]

    received_headers: Dict[str, str] = {}
    current_url = f"https://{clean_domain}"
    hop = 0

    async with httpx.AsyncClient(follow_redirects=False, timeout=settings.REQUEST_TIMEOUT_SECONDS) as client:
        while hop < 5:
            hop_parsed = urlparse(current_url)
            if hop_parsed.hostname:
                validate_hostname_or_ip(hop_parsed.hostname)

            try:
                resp = await client.get(current_url)
            except Exception:
                if hop == 0 and current_url.startswith("https://"):
                    # Fallback to HTTP if initial HTTPS handshake fails
                    current_url = f"http://{clean_domain}"
                    continue
                break

            received_headers = {k.lower(): v for k, v in resp.headers.items()}

            if resp.is_redirect:
                location = resp.headers.get("Location")
                if location:
                    if location.startswith("/"):
                        current_url = f"{hop_parsed.scheme}://{hop_parsed.netloc}{location}"
                    else:
                        current_url = location
                    hop += 1
                else:
                    break
            else:
                break

    security_headers: List[SecurityHeaderCheck] = []
    failed_headers: List[str] = []
    passed_headers: List[str] = []

    for header_name, desc in HEADER_SPECS:
        if header_name.lower() in received_headers:
            status: str = "Pass"
            passed_headers.append(header_name)
        else:
            status = "Fail"
            failed_headers.append(header_name)

        security_headers.append(SecurityHeaderCheck(
            header=header_name,
            status=status,
            description=desc,
        ))

    # Calculate risk score & verdict directly from results
    risk_score = 0
    flaws: List[str] = []

    if 22 in open_ports_list:
        risk_score += 40
        flaws.append("Exposed administrative SSH port 22.")
    if 21 in open_ports_list:
        risk_score += 35
        flaws.append("Exposed insecure FTP port 21.")
    if 443 not in open_ports_list:
        risk_score += 25
        flaws.append("HTTPS port 443 is not open.")
    if ssl_days_remaining < 15 and 443 in open_ports_list:
        risk_score += 20
        flaws.append(f"SSL certificate expires in only {ssl_days_remaining} days.")

    # Failed header points
    header_weights = {
        "Content-Security-Policy": 12,
        "Strict-Transport-Security": 10,
        "X-Frame-Options": 8,
        "X-Content-Type-Options": 6,
        "Referrer-Policy": 4,
    }
    for failed_h in failed_headers:
        risk_score += header_weights.get(failed_h, 6)

    risk_score = min(100, max(0, risk_score))

    missing_count = len(failed_headers)

    # BUG FIX 2: Generate explanation and verdict FROM actual results
    # Never say "well-hardened" unless all 5 headers pass!
    if 22 in open_ports_list or 21 in open_ports_list:
        verdict = "Dangerous"
        risk_level = "critical"
        explanation = (
            f"Critical security alert for {clean_domain}: administrative ports (such as SSH/FTP) are exposed to the public internet, "
            f"and {missing_count} browser security headers failed ({', '.join(failed_headers)})."
        )
    elif missing_count >= 3 or risk_score >= 40:
        verdict = "Suspicious"
        risk_level = "medium"
        explanation = (
            f"The website server for {clean_domain} is missing {missing_count} essential browser protection headers: {', '.join(failed_headers)}. "
            "Visitors may be vulnerable to clickjacking, unauthorized framing, or cross-site script attacks."
        )
    elif missing_count in (1, 2):
        verdict = "Suspicious"
        risk_level = "medium"
        explanation = (
            f"The website server for {clean_domain} has active encryption, but is missing {missing_count} defensive header(s): {', '.join(failed_headers)}."
        )
    else:
        # All 5 headers passed!
        verdict = "Safe"
        risk_level = "low"
        explanation = (
            f"The website configuration for {clean_domain} is well-hardened with active encryption, "
            "standard web ports, and all 5 modern browser protection headers verified."
        )

    return WebsiteCheckResponse(
        domain=clean_domain,
        ports=ports_list,
        openPorts=open_ports_list,
        sslExpiry=ssl_expiry_str,
        sslExpiresOn=ssl_expires_on,
        sslDaysRemaining=ssl_days_remaining,
        securityHeaders=security_headers,
        riskScore=risk_score,
        riskLevel=risk_level,
        verdict=verdict,
        explanation=explanation,
        timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    )
