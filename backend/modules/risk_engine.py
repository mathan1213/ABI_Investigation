import datetime
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple

from config import settings
from models import (
    ActionPlanItem,
    ConnectedAccountItem,
    GenerateReportRequest,
    GenerateReportResponse,
    ModuleScore,
    NetworkFindingItem,
    RiskLevel,
)


def score_to_risk_level(score: int) -> RiskLevel:
    """Standard risk level calculation matching system thresholds."""
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def _extract_network_components(network_raw: Any) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """Extracts ip_result, link_result, website_result from flexible input types."""
    if not network_raw:
        return None, None, None

    ip_res, link_res, web_res = None, None, None

    if isinstance(network_raw, dict):
        ip_res = network_raw.get("ipResult") or network_raw.get("ip_result")
        link_res = network_raw.get("linkResult") or network_raw.get("link_result")
        web_res = network_raw.get("websiteResult") or network_raw.get("website_result")
        # If dict itself looks like an IP check
        if not ip_res and "abuseScore" in network_raw or "abuse_score" in network_raw:
            ip_res = network_raw
        elif not web_res and ("openPorts" in network_raw or "securityHeaders" in network_raw):
            web_res = network_raw
    elif isinstance(network_raw, list):
        for item in network_raw:
            if isinstance(item, dict):
                if "abuseScore" in item or "abuse_score" in item:
                    ip_res = item
                elif "reputationScore" in item or "reputation_score" in item:
                    link_res = item
                elif "openPorts" in item or "securityHeaders" in item:
                    web_res = item

    return ip_res, link_res, web_res


def generate_comprehensive_report(payload: GenerateReportRequest) -> GenerateReportResponse:
    """
    Synthesizes multi-vector security findings into an executive plain-English dossier.
    Calculates composite risk: 0.5 * max(scores) + 0.5 * avg(scores).
    Enforces that any Critical finding elevates overall level to at least High.
    """
    demo_modules = [m.lower() for m in payload.demo_modules]
    modules: List[ModuleScore] = []
    has_critical_finding = False

    # -----------------------------------------------------------------------
    # 1. Telegram Module Evaluation
    # -----------------------------------------------------------------------
    tg = payload.telegram
    is_tg_demo = "telegram" in demo_modules or getattr(tg, "is_demo", False)
    if tg:
        tg_score = tg.risk_score
        tg_level = tg.risk_level
        if any(f.risk == "critical" for f in tg.findings):
            has_critical_finding = True
        modules.append(
            ModuleScore(
                module="telegram",
                name="Telegram Account Security",
                scanned=True,
                score=tg_score,
                riskLevel=tg_level,
                isDemo=is_tg_demo,
                details=f"{len(tg.sessions)} session(s) inspected, {len(tg.findings)} finding(s)",
            )
        )
    else:
        modules.append(
            ModuleScore(
                module="telegram",
                name="Telegram Account Security",
                scanned=False,
                score=None,
                riskLevel=None,
                isDemo=False,
                details="Not scanned yet",
            )
        )

    # -----------------------------------------------------------------------
    # 2. GitHub Repository Module Evaluation
    # -----------------------------------------------------------------------
    repo = payload.repo
    is_repo_demo = "repo" in demo_modules or "github" in demo_modules
    if repo:
        repo_score = repo.risk_score
        repo_level = repo.risk_level
        if repo.counts.critical > 0 or any(f.severity == "critical" for f in repo.findings):
            has_critical_finding = True
        modules.append(
            ModuleScore(
                module="repo",
                name="GitHub Repository Forensics",
                scanned=True,
                score=repo_score,
                riskLevel=repo_level,
                isDemo=is_repo_demo,
                details=f"{repo.repo_name} ({repo.counts.total} issue(s) in {repo.scanned_files_count} file(s))",
            )
        )
    else:
        modules.append(
            ModuleScore(
                module="repo",
                name="GitHub Repository Forensics",
                scanned=False,
                score=None,
                riskLevel=None,
                isDemo=False,
                details="Not scanned yet",
            )
        )

    # -----------------------------------------------------------------------
    # 3. Network Infrastructure Evaluation
    # -----------------------------------------------------------------------
    ip_res, link_res, web_res = _extract_network_components(payload.network)
    has_network = bool(ip_res or link_res or web_res)
    is_net_demo = "network" in demo_modules

    if has_network:
        net_scores: List[int] = []
        net_details: List[str] = []

        if ip_res:
            abuse = int(ip_res.get("abuseScore") or ip_res.get("abuse_score") or 0)
            net_scores.append(abuse)
            ip_str = ip_res.get("ip", "IP")
            net_details.append(f"IP {ip_str} (Threat: {abuse}/100)")
            if ip_res.get("riskLevel") == "critical" or ip_res.get("risk_level") == "critical":
                has_critical_finding = True

        if link_res:
            rep = int(link_res.get("reputationScore") or link_res.get("reputation_score") or 100)
            link_score = max(0, 100 - rep)
            net_scores.append(link_score)
            url_str = link_res.get("url") or link_res.get("domain", "Link")
            net_details.append(f"Link {url_str}")
            if link_res.get("riskLevel") == "critical" or link_res.get("risk_level") == "critical":
                has_critical_finding = True

        if web_res:
            w_score = int(web_res.get("riskScore") or web_res.get("risk_score") or 0)
            net_scores.append(w_score)
            dom = web_res.get("domain", "Website")
            net_details.append(f"Web {dom} (Risk: {w_score}/100)")
            if web_res.get("riskLevel") == "critical" or web_res.get("risk_level") == "critical":
                has_critical_finding = True

        composite_net_score = max(net_scores) if net_scores else 0
        net_level = score_to_risk_level(composite_net_score)
        modules.append(
            ModuleScore(
                module="network",
                name="Network & Web Infrastructure",
                scanned=True,
                score=composite_net_score,
                riskLevel=net_level,
                isDemo=is_net_demo,
                details=", ".join(net_details),
            )
        )
    else:
        modules.append(
            ModuleScore(
                module="network",
                name="Network & Web Infrastructure",
                scanned=False,
                score=None,
                riskLevel=None,
                isDemo=False,
                details="Not scanned yet",
            )
        )

    # -----------------------------------------------------------------------
    # 4. Overall Composite Risk Calculation
    # Formula: 0.5 * max(scores) + 0.5 * avg(scores)
    # Special rule: If any finding is Critical, overall level is at least High.
    # -----------------------------------------------------------------------
    scanned_scores = [m.score for m in modules if m.scanned and m.score is not None]

    if not scanned_scores:
        overall_score = 0
        overall_risk: RiskLevel = "low"
    else:
        highest_score = max(scanned_scores)
        average_score = sum(scanned_scores) / len(scanned_scores)
        overall_score = round(0.5 * highest_score + 0.5 * average_score)
        overall_score = max(0, min(100, overall_score))
        overall_risk = score_to_risk_level(overall_score)

        if has_critical_finding and overall_risk in ("low", "medium"):
            overall_risk = "high"

    # -----------------------------------------------------------------------
    # 5. Network Findings Consolidation (De-duplicated)
    # -----------------------------------------------------------------------
    network_findings: List[NetworkFindingItem] = []
    seen_network_signatures: Set[str] = set()

    def add_network_finding(source: str, title: str, detail: str, severity: RiskLevel, target: Optional[str] = None):
        sig = f"{title.strip().lower()}::{target or ''}"
        if sig in seen_network_signatures:
            return
        seen_network_signatures.add(sig)
        network_findings.append(
            NetworkFindingItem(
                id=f"net-{len(network_findings) + 1}",
                source=source,
                title=title,
                detail=detail,
                severity=severity,
                target=target,
            )
        )

    # A. From Telegram sessions & links
    if tg:
        for s in tg.sessions:
            if s.is_suspicious and s.ip:
                sev: RiskLevel = "critical" if "tor" in (s.flag_note or "").lower() else "high"
                add_network_finding(
                    source="Telegram",
                    title=f"Suspicious IP Access from {s.country}",
                    detail=f"Device '{s.device}' connected from {s.ip}. {s.flag_note or 'Unusual geolocation'}.",
                    severity=sev,
                    target=s.ip,
                )
        for f in tg.findings:
            if f.type == "suspicious_link":
                add_network_finding(
                    source="Telegram",
                    title=f.title,
                    detail=f.explanation,
                    severity=f.risk,
                    target="Official Notifications",
                )

    # B. From Repository findings (network & exposed endpoints)
    if repo:
        for rf in repo.findings:
            if rf.category == "network" or "http://" in rf.explanation or "port" in rf.title.lower():
                add_network_finding(
                    source="GitHub Repo",
                    title=rf.title,
                    detail=f"File {rf.file_path}:{rf.line_number} — {rf.explanation}",
                    severity=rf.severity,
                    target=rf.file_path,
                )

    # C. From Network Check results
    if ip_res:
        ip_addr = ip_res.get("ip", "Unknown")
        abuse_val = int(ip_res.get("abuseScore") or ip_res.get("abuse_score") or 0)
        is_tor = ip_res.get("isTor") or ip_res.get("is_tor")
        is_vpn = ip_res.get("isVpn") or ip_res.get("is_vpn")
        is_proxy = ip_res.get("isProxy") or ip_res.get("is_proxy")
        if is_tor:
            add_network_finding(
                source="IP Check",
                title=f"Hostile Tor Exit Node: {ip_addr}",
                detail=f"IP address {ip_addr} is an active Tor routing node. Abuse threat score: {abuse_val}/100.",
                severity="critical",
                target=ip_addr,
            )
        elif is_vpn or is_proxy or abuse_val > 40:
            add_network_finding(
                source="IP Check",
                title=f"Masked VPN / Proxy Address: {ip_addr}",
                detail=f"IP {ip_addr} belongs to an anonymizing service in {ip_res.get('country', 'unknown')}.",
                severity="high" if abuse_val > 50 else "medium",
                target=ip_addr,
            )

    if link_res:
        link_url = link_res.get("url") or link_res.get("domain", "")
        ssl_val = link_res.get("sslValid") if "sslValid" in link_res else link_res.get("ssl_valid", True)
        if not ssl_val:
            add_network_finding(
                source="Link Check",
                title=f"Invalid or Untrusted SSL Certificate: {link_url}",
                detail=link_res.get("explanation", "The website SSL connection failed verification."),
                severity="high",
                target=link_url,
            )
        hops = link_res.get("redirectChain") or link_res.get("redirect_chain") or []
        if len(hops) > 2:
            add_network_finding(
                source="Link Check",
                title=f"Multiple Redirect Hops ({len(hops)} steps): {link_url}",
                detail="Deep redirect sequences are commonly used in phishing attacks to bypass domain filters.",
                severity="medium",
                target=link_url,
            )

    if web_res:
        dom = web_res.get("domain", "Website")
        ports = web_res.get("ports") or []
        for p in ports:
            p_state = p.get("state")
            p_num = p.get("port")
            p_risk = p.get("risk", "low")
            if p_state == "Open" and p_risk in ("high", "critical", "medium"):
                add_network_finding(
                    source="Website Check",
                    title=f"Dangerous Open Port {p_num} ({p.get('service', 'Service')}): {dom}",
                    detail=p.get("note") or f"Public port {p_num} is actively accepting incoming TCP connections.",
                    severity=p_risk,
                    target=f"{dom}:{p_num}",
                )

    # -----------------------------------------------------------------------
    # 6. Plain-English "How It Likely Happened" Attack Story
    # -----------------------------------------------------------------------
    how_it_happened: List[str] = []

    has_repo_secret = repo and any(f.category == "secrets" for f in repo.findings)
    has_foreign_login = tg and any(f.type in ("foreign_login", "unknown_device") and f.risk in ("high", "critical") for f in tg.findings)
    has_no_2fa = tg and not tg.two_factor_enabled
    has_tor_active = any("tor" in f.title.lower() for f in network_findings)

    if has_repo_secret and has_foreign_login:
        how_it_happened.append(
            "Step 1 (Credential Leak): An API credential or authorization secret was published in a public GitHub code repository, exposing it to automated scrapers."
        )
        how_it_happened.append(
            "Step 2 (Interception / SIM Swapping): Attackers likely cross-referenced account records or targeted SMS verification codes to initiate a secondary login."
        )
        if has_no_2fa:
            how_it_happened.append(
                "Step 3 (Immediate Persistence): Because Two-Step Verification was turned off, the intruder gained complete access to your account without encountering a secondary cloud password."
            )
        else:
            how_it_happened.append(
                "Step 3 (Session Foothold): An unauthorized session was authorized from another country, establishing a persistent channel to read messages."
            )
        if has_tor_active:
            how_it_happened.append(
                "Step 4 (Identity Masking): The connection routed through an anonymizing Tor network node to prevent tracing the intruder's physical origin."
            )
    elif has_foreign_login:
        how_it_happened.append(
            "Step 1 (Foreign Authorization): A device from an unfamiliar geographic region successfully logged into your account using an intercepted or forwarded one-time code."
        )
        if has_no_2fa:
            how_it_happened.append(
                "Step 2 (Unprotected Cloud Access): The account lacked a Two-Step Verification password, allowing the outsider immediate entry into your profile."
            )
        how_it_happened.append(
            "Step 3 (Active Hijack): The remote device remains connected, meaning the unauthorized party can view notifications and past activity until forcibly terminated."
        )
    elif has_repo_secret:
        how_it_happened.append(
            "Step 1 (Secret Exposure): Hardcoded API keys or credentials were committed to your repository's version history."
        )
        how_it_happened.append(
            "Step 2 (Public Enumeration): Automated bots continuously monitor public code hosts and index new secrets within seconds of commit."
        )
        how_it_happened.append(
            "Step 3 (Privilege Exploitation): Attackers can leverage these keys to query cloud databases, generate unauthorized bills, or access connected services."
        )
    elif overall_score > 30:
        how_it_happened.append(
            "Step 1 (Perimeter Weaknesses): One or more scanned assets (network ports, old sessions, or missing headers) have defensive gaps."
        )
        how_it_happened.append(
            "Step 2 (Reconnaissance Risk): Internet port scanners and opportunistic threat actors exploit unhardened configurations to compromise infrastructure."
        )
    else:
        how_it_happened.append(
            "Step 1 (Baseline Verification): All active sessions, repositories, and network perimeter endpoints were audited for known compromise indicators."
        )
        how_it_happened.append(
            "Step 2 (Secure Status): No evidence of active unauthorized sessions, credential leaks, or hostile network footprints was identified."
        )

    # -----------------------------------------------------------------------
    # 7. Prioritized, De-duplicated "What To Do Now" Checklist (Max 10)
    # -----------------------------------------------------------------------
    raw_actions: List[Tuple[int, str, str, RiskLevel]] = []

    # Priority 1: Terminate sessions & turn on 2FA
    if tg:
        for act in tg.action_checklist:
            if "terminate" in act.lower():
                raw_actions.append((1, "Terminate All Other Telegram Sessions", act, "critical"))
            elif "two-step" in act.lower():
                raw_actions.append((2, "Enable Telegram Two-Step Password", act, "high"))
            elif "log out old" in act.lower():
                raw_actions.append((5, "Log Out Old Devices", act, "medium"))
            else:
                raw_actions.append((7, "Telegram Defensive Hygiene", act, "low"))

    # Priority 2: Revoke exposed secrets from Repo
    if repo:
        for rf in repo.findings:
            if rf.category == "secrets":
                raw_actions.append(
                    (
                        2,
                        f"Revoke Leaked Secret ({rf.title})",
                        f"Immediately invalidate and rotate the credential found in '{rf.file_path}'. {rf.suggested_fix}",
                        rf.severity,
                    )
                )
            elif rf.category == "dependencies":
                raw_actions.append(
                    (
                        6,
                        f"Upgrade Vulnerable Dependency: {rf.title}",
                        f"Update the package mentioned in '{rf.file_path}' to the latest safe release.",
                        rf.severity,
                    )
                )

    # Priority 3: Close exposed network ports
    if web_res:
        ports = web_res.get("ports") or []
        for p in ports:
            if p.get("state") == "Open" and p.get("port") in (21, 22, 23, 3389, 445):
                raw_actions.append(
                    (
                        3,
                        f"Close Exposed Admin Port {p.get('port')}",
                        f"Configure your cloud firewall to restrict port {p.get('port')} access only to authorized IP addresses.",
                        "high",
                    )
                )

    # Sort actions by priority index, then severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    raw_actions.sort(key=lambda x: (x[0], severity_order.get(x[3], 4)))

    what_to_do_now: List[ActionPlanItem] = []
    seen_action_titles: Set[str] = set()

    for idx, (prio, title, detail, sev) in enumerate(raw_actions):
        t_clean = title.strip().lower()
        if t_clean in seen_action_titles:
            continue
        seen_action_titles.add(t_clean)
        what_to_do_now.append(
            ActionPlanItem(
                id=len(what_to_do_now) + 1,
                title=title,
                detail=detail,
                priority=sev,
                completed=False,
            )
        )
        if len(what_to_do_now) >= 10:
            break

    if not what_to_do_now:
        what_to_do_now.append(
            ActionPlanItem(
                id=1,
                title="Maintain Routine Security Audits",
                detail="Your digital perimeter is currently secure. Continue reviewing active devices and code commits once a month.",
                priority="low",
                completed=False,
            )
        )

    # -----------------------------------------------------------------------
    # 8. Limitations & Transparency Disclosures
    # -----------------------------------------------------------------------
    limitations: List[str] = []

    if not tg:
        limitations.append("Telegram module was not scanned; unauthorized devices and active chat sessions cannot be verified.")
    if not repo:
        limitations.append("GitHub repository module was not scanned; source code secrets and vulnerable dependencies cannot be verified.")
    if not has_network:
        limitations.append("Network check module was not scanned; public IP reputation and website ports were not tested.")

    if not settings.ABUSEIPDB_KEY:
        limitations.append("AbuseIPDB API key is not configured on the server; IP abuse scores are calculated from proxy/hosting heuristics.")
    if not settings.VIRUSTOTAL_KEY:
        limitations.append("VirusTotal API key is not configured on the server; link reputation relies on domain age, DNS records, and SSL health.")

    for m in modules:
        if m.scanned and m.is_demo:
            limitations.append(f"DEMO DATA WARNING: The '{m.name}' module was evaluated in Demo Mode. Results are simulated.")

    # -----------------------------------------------------------------------
    # 9. Plain-English Summary Generation
    # -----------------------------------------------------------------------
    scanned_count = sum(1 for m in modules if m.scanned)
    demo_count = sum(1 for m in modules if m.scanned and m.is_demo)

    if overall_risk in ("critical", "high"):
        summary = (
            f"High security risk identified across {scanned_count} audited module(s). "
            f"We detected active compromise indicators, including unauthorized access or leaked credentials requiring immediate remediation. "
            f"Review the prioritized recovery checklist below to secure your accounts."
        )
    elif overall_risk == "medium":
        summary = (
            f"Moderate vulnerabilities detected across {scanned_count} audited module(s). "
            f"While no confirmed hostile intrusion is ongoing, key defensive safeguards (such as Two-Step Verification or software updates) are missing. "
            f"Following the recovery steps will harden your assets against opportunistic attacks."
        )
    else:
        summary = (
            f"All {scanned_count} audited module(s) appear secure with low overall risk. "
            f"Connected sessions match recognized hardware, and no leaked credentials were uncovered in public repositories. "
            f"Maintain standard hygiene and review permissions periodically."
        )

    if demo_count > 0:
        summary += f" (Note: {demo_count} module(s) used simulated Demo data because server API keys were not configured.)"

    # -----------------------------------------------------------------------
    # 10. Connected Accounts & Audit History
    # -----------------------------------------------------------------------
    connected_accounts: List[ConnectedAccountItem] = []
    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%B %d, %Y at %I:%M %p UTC")

    if tg:
        connected_accounts.append(
            ConnectedAccountItem(
                name=f"Telegram ({tg.phone})",
                service="Telegram MTProto",
                connectedAt=now_str,
                status=f"Risk Score {tg.risk_score}/100 ({tg.risk_level.title()})",
                isDemo=is_tg_demo,
            )
        )
    if repo:
        connected_accounts.append(
            ConnectedAccountItem(
                name=repo.repo_name,
                service="GitHub Public Repo",
                connectedAt=now_str,
                status=f"Risk Score {repo.risk_score}/100 ({repo.risk_level.title()})",
                isDemo=is_repo_demo,
            )
        )
    if ip_res:
        connected_accounts.append(
            ConnectedAccountItem(
                name=f"IP {ip_res.get('ip', 'Unknown')}",
                service="Network Intelligence",
                connectedAt=now_str,
                status=f"Abuse Score {ip_res.get('abuseScore', ip_res.get('abuse_score', 0))}/100",
                isDemo=is_net_demo,
            )
        )

    methodology = (
        "Overall composite risk is computed as 50% highest individual module score plus 50% mean score across all scanned modules. "
        "If any evaluated module contains a finding with Critical severity, the composite risk rating is elevated to at least High. "
        "Modules that were not scanned are omitted from the computation."
    )

    report_id = f"ABI-{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

    return GenerateReportResponse(
        id=report_id,
        generatedAt=now_str,
        overallScore=overall_score,
        overallRisk=overall_risk,
        summary=summary,
        howItHappened=how_it_happened,
        whatToDoNow=what_to_do_now,
        actionPlan=what_to_do_now,
        modules=modules,
        networkFindings=network_findings,
        limitations=limitations,
        methodology=methodology,
        demoModules=payload.demo_modules,
        telegram=tg,
        repo=repo,
        network=payload.network,
        connectedAccounts=connected_accounts,
    )
