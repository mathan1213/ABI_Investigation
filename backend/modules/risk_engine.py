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


def _extract_network_components(
    network_raw: Any,
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """Extracts ip_result, link_result, website_result from flexible input types."""
    if not network_raw:
        return None, None, None

    ip_res, link_res, web_res = None, None, None

    if isinstance(network_raw, dict):
        ip_res = network_raw.get("ipResult") or network_raw.get("ip_result")
        link_res = network_raw.get("linkResult") or network_raw.get("link_result")
        web_res = network_raw.get("websiteResult") or network_raw.get("website_result")
        # If dict itself looks like an IP check
        if not ip_res and ("abuseScore" in network_raw or "abuse_score" in network_raw):
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
    Synthesizes multi-vector security findings into an evidence-based plain-English dossier.
    Computes overall score and overall level from REAL modules only.
    Excludes demo modules from the score and from the Critical-forces-High rule.
    """
    demo_modules = [m.lower() for m in payload.demo_modules]
    modules: List[ModuleScore] = []
    limitations: List[str] = []

    # -----------------------------------------------------------------------
    # 1. Telegram Module Evaluation
    # -----------------------------------------------------------------------
    tg = payload.telegram
    is_tg_demo = "telegram" in demo_modules or getattr(tg, "is_demo", False)

    if tg:
        tg_score = tg.risk_score
        base_tg_level = score_to_risk_level(tg_score)
        has_tg_critical = any(f.risk == "critical" for f in tg.findings)
        tg_findings_count = len(tg.findings)

        if has_tg_critical and base_tg_level != "critical":
            tg_level: RiskLevel = "critical"
            tg_details = f"{len(tg.sessions)} session(s) inspected, {tg_findings_count} finding(s) (raised to Critical by a critical finding)"
        else:
            tg_level: RiskLevel = base_tg_level
            tg_details = f"{len(tg.sessions)} session(s) inspected, {tg_findings_count} finding(s)"

        # Consistency check: score vs findings
        if tg_score > 0 and tg_findings_count == 0:
            limitations.append(
                f"Warning: Telegram Account Security has a risk score of {tg_score} but reported 0 findings; score and findings are inconsistent."
            )
        elif tg_score == 0 and tg_findings_count > 0:
            limitations.append(
                f"Warning: Telegram Account Security has a risk score of 0 but reported {tg_findings_count} finding(s); score and findings are inconsistent."
            )

        modules.append(
            ModuleScore(
                module="telegram",
                name="Telegram Account Security",
                scanned=True,
                score=tg_score,
                riskLevel=tg_level,
                isDemo=is_tg_demo,
                details=tg_details,
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
    is_repo_demo = "repo" in demo_modules or "github" in demo_modules or getattr(repo, "is_demo", False)

    if repo:
        repo_score = repo.risk_score
        base_repo_level = score_to_risk_level(repo_score)
        has_repo_critical = (repo.counts.critical > 0 or any(f.severity == "critical" for f in repo.findings))
        repo_findings_count = len(repo.findings)

        if has_repo_critical and base_repo_level != "critical":
            repo_level: RiskLevel = "critical"
            repo_details = f"{repo.repo_name} ({repo_findings_count} finding(s) in {repo.scanned_files_count} file(s), raised to Critical by a critical finding)"
        else:
            repo_level: RiskLevel = base_repo_level
            repo_details = f"{repo.repo_name} ({repo_findings_count} finding(s) in {repo.scanned_files_count} file(s))"

        # Consistency check: score vs findings
        if repo_score > 0 and repo_findings_count == 0:
            limitations.append(
                f"Warning: GitHub Repository Forensics has a risk score of {repo_score} but reported 0 findings; score and findings are inconsistent."
            )
        elif repo_score == 0 and repo_findings_count > 0:
            limitations.append(
                f"Warning: GitHub Repository Forensics has a risk score of 0 but reported {repo_findings_count} finding(s); score and findings are inconsistent."
            )

        modules.append(
            ModuleScore(
                module="repo",
                name="GitHub Repository Forensics",
                scanned=True,
                score=repo_score,
                riskLevel=repo_level,
                isDemo=is_repo_demo,
                details=repo_details,
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

    # Network findings list (populated from all modules)
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

    # Add network findings from Network checks
    net_findings_from_network = 0

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
            net_findings_from_network += 1
        elif is_vpn or is_proxy or abuse_val > 40:
            add_network_finding(
                source="IP Check",
                title=f"Masked VPN / Proxy Address: {ip_addr}",
                detail=f"IP {ip_addr} belongs to an anonymizing service in {ip_res.get('country', 'unknown')}.",
                severity="high" if abuse_val > 50 else "medium",
                target=ip_addr,
            )
            net_findings_from_network += 1

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
            net_findings_from_network += 1

        hops = link_res.get("redirectChain") or link_res.get("redirect_chain") or []
        if len(hops) > 2:
            add_network_finding(
                source="Link Check",
                title=f"Multiple Redirect Hops ({len(hops)} steps): {link_url}",
                detail="Deep redirect sequences are commonly used in phishing attacks to bypass domain filters.",
                severity="medium",
                target=link_url,
            )
            net_findings_from_network += 1

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
                net_findings_from_network += 1

        # Check for failed security headers
        sec_headers = web_res.get("securityHeaders") or web_res.get("security_headers") or []
        failed_headers = [h for h in sec_headers if h.get("status") == "Fail"]
        if failed_headers and len(failed_headers) >= 3:
            add_network_finding(
                source="Website Check",
                title=f"Missing Critical Security Headers: {dom}",
                detail=f"{len(failed_headers)} security headers are missing, weakening browser defense mechanisms.",
                severity="medium",
                target=dom,
            )
            net_findings_from_network += 1

    # Also add network findings from Telegram sessions/links and Repo code
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

    if has_network:
        net_scores: List[int] = []
        if ip_res:
            net_scores.append(int(ip_res.get("abuseScore") or ip_res.get("abuse_score") or 0))
        if link_res:
            rep = int(link_res.get("reputationScore") or link_res.get("reputation_score") or 100)
            net_scores.append(max(0, 100 - rep))
        if web_res:
            net_scores.append(int(web_res.get("riskScore") or web_res.get("risk_score") or 0))

        composite_net_score = max(net_scores) if net_scores else 0
        base_net_level = score_to_risk_level(composite_net_score)
        has_net_critical = any(
            nf.severity == "critical"
            for nf in network_findings
            if nf.source in ("IP Check", "Link Check", "Website Check")
        )

        if has_net_critical and base_net_level != "critical":
            net_level: RiskLevel = "critical"
            net_details = f"{net_findings_from_network} finding(s) across network targets (raised to Critical by a critical finding)"
        else:
            net_level: RiskLevel = base_net_level
            net_details = f"{net_findings_from_network} finding(s) across network targets"

        # Consistency check: score vs findings
        if composite_net_score > 0 and net_findings_from_network == 0:
            limitations.append(
                f"Warning: Network & Web Infrastructure has a risk score of {composite_net_score} but reported 0 findings; score and findings are inconsistent."
            )
        elif composite_net_score == 0 and net_findings_from_network > 0:
            limitations.append(
                f"Warning: Network & Web Infrastructure has a risk score of 0 but reported {net_findings_from_network} finding(s); score and findings are inconsistent."
            )

        modules.append(
            ModuleScore(
                module="network",
                name="Network & Web Infrastructure",
                scanned=True,
                score=composite_net_score,
                riskLevel=net_level,
                isDemo=is_net_demo,
                details=net_details,
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
    # 4. Overall Composite Risk Calculation (REAL MODULES ONLY)
    # Demo modules are strictly excluded from score and Critical-forces-High rule.
    # -----------------------------------------------------------------------
    real_modules = [m for m in modules if m.scanned and not m.is_demo and m.score is not None]

    if not real_modules:
        overall_score: Optional[int] = None
        overall_risk: Optional[RiskLevel] = None
    else:
        real_scores = [m.score for m in real_modules if m.score is not None]
        highest_score = max(real_scores)
        average_score = sum(real_scores) / len(real_scores)
        calc_score = round(0.5 * highest_score + 0.5 * average_score)
        overall_score = max(0, min(100, calc_score))
        overall_risk = score_to_risk_level(overall_score)

        # Critical-forces-High rule: ONLY checks REAL (non-demo) modules
        real_has_critical = False
        if tg and not is_tg_demo and any(f.risk == "critical" for f in tg.findings):
            real_has_critical = True
        if repo and not is_repo_demo and (
            repo.counts.critical > 0 or any(f.severity == "critical" for f in repo.findings)
        ):
            real_has_critical = True
        if has_network and not is_net_demo and any(
            nf.severity == "critical" for nf in network_findings if nf.source in ("IP Check", "Link Check", "Website Check")
        ):
            real_has_critical = True

        if real_has_critical and overall_risk in ("low", "medium"):
            overall_risk = "high"

    # -----------------------------------------------------------------------
    # 5. Evidence-Based "Possible Explanations" (howItHappened)
    # Built ONLY from findings that actually exist in that module.
    # Telegram, repo, and network explanations are kept completely SEPARATE.
    # No invented causes (no unbacked SIM swapping / interception).
    # Uses hedged language ("may", "could", "is consistent with").
    # Never asserts unauthorized access as an absolute certainty.
    # -----------------------------------------------------------------------
    how_it_happened: List[str] = []

    # A. Telegram Explanations (Independent)
    if tg and tg.findings:
        unknown_sessions = [s for s in tg.sessions if s.is_suspicious]
        has_dormant = any(f.type == "unknown_device" and "dormant" in f.title.lower() for f in tg.findings)
        service_chat_alert = any(
            "login code" in f.explanation.lower() or "service chat" in f.explanation.lower()
            or "777000" in f.explanation
            for f in tg.findings
        )

        if unknown_sessions:
            locs = ", ".join(sorted({s.country for s in unknown_sessions if s.country})) or "unfamiliar locations"
            devs = ", ".join(sorted({s.device for s in unknown_sessions if s.device})) or "unrecognized devices"
            if service_chat_alert:
                how_it_happened.append(
                    f"Telegram: An unfamiliar device in {locs} ({devs}) authorized a session, which is consistent with someone using a forwarded or intercepted one-time login code received in service alerts."
                )
            else:
                how_it_happened.append(
                    f"Telegram: An unfamiliar session was authorized from {locs} ({devs}), which is consistent with someone accessing your account if they obtained your one-time verification code or session credentials."
                )

        if not tg.two_factor_enabled:
            how_it_happened.append(
                "Telegram: No two-step verification means someone with your login code alone could sign in without needing a secondary cloud password."
            )

        if any(f.type == "suspicious_link" for f in tg.findings):
            how_it_happened.append(
                "Telegram: Suspicious links or unauthorized bot permissions were identified in notifications, which could be an attempt to harvest verification codes or session tokens."
            )

        if has_dormant:
            how_it_happened.append(
                "Telegram: Inactive sessions that remain logged in over 30 days may expand your attack surface if older devices are misplaced, sold, or compromised."
            )

    # B. GitHub Repository Explanations (Independent — NEVER linked to Telegram)
    if repo and repo.findings:
        secret_findings = [f for f in repo.findings if f.category == "secrets"]
        dep_findings = [f for f in repo.findings if f.category == "dependencies"]
        code_findings = [f for f in repo.findings if f.category in ("code", "network")]

        if secret_findings:
            files_mentioned = ", ".join(sorted({f.file_path for f in secret_findings[:3]}))
            how_it_happened.append(
                f"Repository: Exposed credentials were found in the source code ({files_mentioned}). Automated scanners continuously monitor public repositories, which means these credentials may be discovered and used to interact with connected services until revoked."
            )

        if dep_findings:
            how_it_happened.append(
                f"Repository: Known vulnerabilities in project dependencies ({len(dep_findings)} package(s)) could allow external parties to exploit unpatched security weaknesses in running environments."
            )

        if code_findings:
            how_it_happened.append(
                f"Repository: Insecure code patterns or plaintext HTTP network endpoints could expose application traffic to interception or tampering."
            )

    # C. Network Infrastructure Explanations (Independent)
    if has_network and network_findings:
        net_issues = [nf for nf in network_findings if nf.source in ("IP Check", "Link Check", "Website Check")]
        if net_issues:
            tor_or_proxy = [nf for nf in net_issues if "tor" in nf.title.lower() or "vpn" in nf.title.lower() or "proxy" in nf.title.lower()]
            web_or_port = [nf for nf in net_issues if "port" in nf.title.lower() or "header" in nf.title.lower() or "ssl" in nf.title.lower()]

            if tor_or_proxy:
                how_it_happened.append(
                    "Network: The audited IP address is associated with an anonymizing Tor node or proxy network, which is consistent with traffic routing designed to mask origin location."
                )

            if web_or_port:
                how_it_happened.append(
                    "Network: Unhardened website configuration, open administration ports, or missing security headers could leave communication channels less protected against eavesdropping or unauthorized connections."
                )

    # D. Default neutral statement if no findings exist anywhere
    if not how_it_happened:
        scanned_count = sum(1 for m in modules if m.scanned)
        if scanned_count > 0:
            how_it_happened.append(
                "All scanned assets: No active compromise indicators, exposed credentials, or hostile network footprints were identified in the audited data."
            )
        else:
            how_it_happened.append(
                "No modules have been scanned yet. Connect an account or test an asset to view evidence-based explanations."
            )

    # -----------------------------------------------------------------------
    # 6. Actionable Checklist ("What To Do Now")
    # Generated from the ACTUAL finding type, with priority EQUAL to finding severity.
    # Missing 2FA -> "Turn on two-step verification and add a recovery email" (High priority).
    # Only suggest "change your password" when 2FA is already ON!
    # Checklist steps that come from demo modules must end with " (demo)".
    # De-duplicated and capped at maximum 10 items, most urgent first.
    # -----------------------------------------------------------------------
    raw_actions: List[Tuple[int, str, str, RiskLevel, bool]] = []

    # Priority rank for sorting: critical=0, high=1, medium=2, low=3
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    # A. Telegram Actions
    if tg:
        has_suspicious_session = any(s.is_suspicious for s in tg.sessions)
        dormant_session_finding = next((f for f in tg.findings if f.type == "unknown_device" and "dormant" in f.title.lower()), None)
        unauthorized_finding = next((f for f in tg.findings if f.type in ("foreign_login", "unknown_device", "impossible_travel") and "dormant" not in f.title.lower()), None)

        if has_suspicious_session or unauthorized_finding:
            prio = unauthorized_finding.risk if unauthorized_finding else "critical"
            raw_actions.append(
                (
                    sev_rank[prio],
                    "Terminate unfamiliar Telegram sessions",
                    "Go to Telegram Settings > Devices and tap 'Terminate all other sessions' to disconnect unrecognized devices immediately.",
                    prio,
                    is_tg_demo,
                )
            )

        # 2FA rule: If missing 2FA -> "Turn on two-step verification and add a recovery email" at High priority
        if not tg.two_factor_enabled:
            raw_actions.append(
                (
                    sev_rank["high"],
                    "Turn on two-step verification and add a recovery email",
                    "Configure a secondary cloud password and recovery email under Telegram Settings > Privacy and Security > Two-Step Verification.",
                    "high",
                    is_tg_demo,
                )
            )
        else:
            # Only suggest changing password when 2FA is ALREADY ON and suspicious logins exist
            if has_suspicious_session or unauthorized_finding:
                raw_actions.append(
                    (
                        sev_rank["high"],
                        "Change your two-step verification password",
                        "Update your cloud password under Telegram Settings > Privacy and Security > Two-Step Verification to ensure existing sessions cannot regain access.",
                        "high",
                        is_tg_demo,
                    )
                )

        if dormant_session_finding:
            raw_actions.append(
                (
                    sev_rank[dormant_session_finding.risk],
                    "Log out old devices",
                    "Review Telegram Settings > Devices and log out old devices that have been inactive for over 30 days.",
                    dormant_session_finding.risk,
                    is_tg_demo,
                )
            )

        for f in tg.findings:
            if f.type == "suspicious_link":
                raw_actions.append(
                    (
                        sev_rank[f.risk],
                        f"Review Telegram alert: {f.title}",
                        f"Check official Telegram notifications. {f.explanation}",
                        f.risk,
                        is_tg_demo,
                    )
                )

    # B. Repository Actions (Priority = Finding Severity)
    if repo:
        for rf in repo.findings:
            if rf.category == "secrets":
                raw_actions.append(
                    (
                        sev_rank[rf.severity],
                        f"Revoke leaked secret ({rf.title})",
                        f"Immediately invalidate and rotate the credential found in '{rf.file_path}'. {rf.suggested_fix}",
                        rf.severity,
                        is_repo_demo,
                    )
                )
            elif rf.category == "dependencies":
                raw_actions.append(
                    (
                        sev_rank[rf.severity],
                        f"Upgrade vulnerable package ({rf.title})",
                        f"Update the package mentioned in '{rf.file_path}' to the latest safe release.",
                        rf.severity,
                        is_repo_demo,
                    )
                )
            elif rf.category in ("code", "network"):
                raw_actions.append(
                    (
                        sev_rank[rf.severity],
                        f"Remediate code finding ({rf.title})",
                        f"In '{rf.file_path}': {rf.suggested_fix}",
                        rf.severity,
                        is_repo_demo,
                    )
                )

    # C. Network Actions (Priority = Finding Severity)
    if has_network:
        for nf in network_findings:
            if nf.source in ("IP Check", "Link Check", "Website Check"):
                if "tor" in nf.title.lower() or "proxy" in nf.title.lower():
                    raw_actions.append(
                        (
                            sev_rank[nf.severity],
                            f"Block hostile network address ({nf.target or 'IP'})",
                            f"Restrict inbound and outbound firewall connections to {nf.target or 'this address'}. {nf.detail}",
                            nf.severity,
                            is_net_demo,
                        )
                    )
                elif "port" in nf.title.lower():
                    raw_actions.append(
                        (
                            sev_rank[nf.severity],
                            f"Close exposed port ({nf.target or 'service'})",
                            f"Configure network security group or firewall to restrict access to {nf.target or 'open ports'}.",
                            nf.severity,
                            is_net_demo,
                        )
                    )
                elif "header" in nf.title.lower() or "ssl" in nf.title.lower():
                    raw_actions.append(
                        (
                            sev_rank[nf.severity],
                            f"Harden web security ({nf.target or 'Domain'})",
                            f"Configure security headers (HSTS, CSP) and maintain valid SSL certificates.",
                            nf.severity,
                            is_net_demo,
                        )
                    )

    # Sort actions: most urgent first (critical -> high -> medium -> low)
    raw_actions.sort(key=lambda x: x[0])

    what_to_do_now: List[ActionPlanItem] = []
    seen_action_signatures: Set[str] = set()

    for prio_idx, title, detail, sev, is_action_demo in raw_actions:
        if is_action_demo and not title.endswith(" (demo)"):
            title = f"{title} (demo)"

        sig = title.strip().lower()
        if sig in seen_action_signatures:
            continue
        seen_action_signatures.add(sig)

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
                detail="Your digital perimeter is currently secure. Continue reviewing active sessions and code commits periodically.",
                priority="low",
                completed=False,
            )
        )

    # -----------------------------------------------------------------------
    # 7. Disclosures & API Key Warnings in Limitations
    # -----------------------------------------------------------------------
    if not tg:
        limitations.append("Telegram module was not scanned; unauthorized devices and active chat sessions cannot be verified.")
    if not repo:
        limitations.append("GitHub repository module was not scanned; source code secrets and vulnerable dependencies cannot be verified.")
    if not has_network:
        limitations.append("Network check module was not scanned; public IP reputation and website ports were not tested.")

    # Only add AbuseIPDB and VirusTotal warnings when the report actually contains IP checks, link checks, or Telegram session IPs
    has_ip_checks = bool(ip_res)
    has_telegram_ips = bool(tg and any(s.ip for s in tg.sessions))
    has_link_checks = bool(link_res)

    if (has_ip_checks or has_telegram_ips) and not settings.ABUSEIPDB_KEY:
        limitations.append("AbuseIPDB API key is not configured on the server; IP abuse scores are calculated from proxy/hosting heuristics.")

    if has_link_checks and not settings.VIRUSTOTAL_KEY:
        limitations.append("VirusTotal API key is not configured on the server; link reputation relies on domain age, DNS records, and SSL health.")

    for m in modules:
        if m.scanned and m.is_demo:
            limitations.append(f"DEMO DATA NOTICE: The '{m.name}' module was evaluated in Demo Mode and is excluded from the overall score.")

    # -----------------------------------------------------------------------
    # 8. Plain-English Summary Generation
    # Rule 5: Say "active compromise indicators" ONLY when REAL (non-demo)
    # Telegram findings show an unknown session, impossible travel, or suspicious IP.
    # Exposed repo secrets must be described as "exposed credentials", NOT as an account compromise.
    # -----------------------------------------------------------------------
    is_real_tg = tg is not None and not is_tg_demo
    has_real_tg_compromise = is_real_tg and any(
        f.type in ("foreign_login", "unknown_device", "impossible_travel") and f.risk in ("high", "critical")
        for f in tg.findings
    )

    is_real_repo = repo is not None and not is_repo_demo
    has_real_repo_secrets = is_real_repo and any(f.category == "secrets" for f in repo.findings)

    is_real_net = has_network and not is_net_demo
    has_real_net_threat = is_real_net and any(
        nf.severity in ("high", "critical")
        for nf in network_findings
        if nf.source in ("IP Check", "Link Check", "Website Check")
    )

    real_count = len(real_modules)
    demo_count = sum(1 for m in modules if m.scanned and m.is_demo)

    if overall_score is None:
        summary = (
            "Not enough real data to calculate an overall score. "
            f"All {demo_count} scanned module(s) used simulated Demo data. "
            "Connect an account or test real assets to generate an official composite threat score."
        )
    else:
        # Build evidence-based summary from real findings
        summary_clauses: List[str] = []

        if has_real_tg_compromise:
            summary_clauses.append("active compromise indicators were detected on your Telegram account (unauthorized or suspicious sessions)")

        if has_real_repo_secrets:
            summary_clauses.append("exposed credentials were discovered in your public GitHub repository")

        if has_real_net_threat:
            summary_clauses.append("hostile or unhardened network endpoints were detected")

        if summary_clauses:
            joined_reasons = "; ".join(summary_clauses)
            summary = (
                f"Elevated security risk identified across {real_count} real-data module(s): {joined_reasons}. "
                "Immediate remediation is recommended following the prioritized checklist below."
            )
        elif overall_risk in ("critical", "high"):
            summary = (
                f"Elevated security risk identified across {real_count} real-data module(s). "
                "Significant vulnerabilities or exposures were identified requiring remediation."
            )
        elif overall_risk == "medium":
            summary = (
                f"Moderate exposures detected across {real_count} real-data module(s). "
                "No active compromise indicators were detected, but defensive gaps (such as missing two-step verification or outdated components) require hardening."
            )
        else:
            summary = (
                f"All {real_count} real-data module(s) appear secure with low overall risk. "
                "No active compromise indicators or exposed credentials were identified."
            )

        if demo_count > 0:
            summary += f" ({demo_count} additional module(s) evaluated as Demo data and excluded from this score.)"

    # -----------------------------------------------------------------------
    # 9. Connected Accounts
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
        "Overall composite risk is computed as 50% highest individual module score plus 50% mean score across all completed real-data modules. "
        "Demo modules are strictly excluded from the overall score and the Critical-forces-High rule. "
        "If any real module contains a finding with Critical severity, the composite risk rating is elevated to at least High. "
        "Unscanned and demo modules are omitted from the computation."
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
