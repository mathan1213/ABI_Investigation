import asyncio
import datetime
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import httpx
from config import settings
from models import FindingCounts, RepoFinding, RepoScanResponse, RiskLevel

# ---------------------------------------------------------------------------
# Helpers & Regex Patterns
# ---------------------------------------------------------------------------

GITHUB_URL_REGEX = re.compile(
    r"^https:\/\/github\.com\/([a-zA-Z0-9_\-\.]+)\/([a-zA-Z0-9_\-\.]+?)(?:\.git)?\/?$",
    re.IGNORECASE
)

# Secret detection patterns with corresponding severity
SECRET_PATTERNS = [
    (
        "AWS Access Key ID",
        re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "critical",
        "An active Amazon Web Services Access Key ID was hardcoded in this file. Anyone with this key can access your AWS cloud infrastructure.",
        "Immediately revoke this key in AWS IAM. Store keys in secure environment variables or AWS Secrets Manager."
    ),
    (
        "AWS Secret Access Key",
        re.compile(r"(?i)\b(?:aws_secret_access_key|aws_secret_key)\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]"),
        "critical",
        "An Amazon Web Services secret password was left in source code. Combined with an access key, attackers gain total control of your cloud.",
        "Revoke and delete this key pair immediately in the AWS IAM Console. Never commit secrets to version control."
    ),
    (
        "GitHub Personal Access Token",
        re.compile(r"\b(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})\b"),
        "critical",
        "A live GitHub access token was published in this repository. Attackers can push unauthorized code, steal repositories, or delete branches.",
        "Revoke this token immediately under GitHub Settings > Developer Settings > Personal Access Tokens."
    ),
    (
        "Google Cloud / Firebase API Key",
        re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
        "high",
        "A Google Cloud or Firebase API key is hardcoded. Depending on API restrictions, hackers may rack up cloud charges or access backend databases.",
        "Restrict this key's HTTP referrers and API scopes in the Google Cloud Console, or rotate the key."
    ),
    (
        "Slack Bot / User Token",
        re.compile(r"\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)\b"),
        "high",
        "A Slack workspace authentication token was found. An attacker can read team messages, list employees, or download private attachments.",
        "Revoke this token on the Slack API portal and regenerate application credentials."
    ),
    (
        "Unencrypted Private Cryptographic Key",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        "critical",
        "An SSH or SSL private encryption key is stored in plain text. Attackers can impersonate your servers or decrypt confidential traffic.",
        "Remove this private key immediately. Generate a new key pair and store the private key securely on your local computer or in a secret vault."
    ),
    (
        "Exposed Password / API Secret Assignment",
        re.compile(r"(?i)\b(?:api_key|apikey|secret_key|api_secret|auth_token|client_secret|db_password|password|passwd)\s*[:=]\s*['\"]([a-zA-Z0-9_\-\.\$\!\@\#]{8,})['\"]"),
        "high",
        "A hardcoded authentication password or API secret key was detected in code.",
        "Move sensitive credentials into a private .env file and ensure that .env is listed in your .gitignore."
    )
]

# Excluded generic dummy values
DUMMY_VALUES = {
    "your_api_key_here", "your_secret_here", "changeme", "password", "password123",
    "secret123", "placeholder", "dummy_key", "test_key", "12345678", "admin123"
}

# Ignore list for network URLs
IGNORED_URL_DOMAINS = {
    "localhost", "127.0.0.1", "0.0.0.0", "w3.org", "schemas.xmlsoap.org",
    "xml.org", "apache.org", "example.com", "schema.org", "json-schema.org"
}

# Directories to skip when scanning
IGNORED_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", ".venv", "venv",
    "__pycache__", ".tox", ".idea", ".vscode", ".pytest_cache", ".mypy_cache"
}

# Binary file extensions to skip
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".svg", ".zip", ".tar",
    ".gz", ".7z", ".rar", ".exe", ".dll", ".so", ".dylib", ".bin", ".pdf",
    ".mp4", ".mp3", ".wav", ".pyc", ".woff", ".woff2", ".ttf", ".eot"
}


def mask_secret(secret_str: str) -> str:
    """Masks a secret string showing only the first 4 characters followed by asterisks."""
    if not secret_str:
        return "****"
    clean = secret_str.strip("'\" \t\r\n")
    if len(clean) <= 4:
        return clean[:2] + "****" if len(clean) >= 2 else "****"
    return clean[:4] + "****"


def sanitize_snippet(snippet: str, secret_val: Optional[str] = None) -> str:
    """Sanitizes snippet so no raw secrets ever leak to the frontend."""
    if not snippet:
        return ""
    res = snippet
    if secret_val:
        res = res.replace(secret_val, mask_secret(secret_val))
    # Apply regex masking passes on the snippet itself
    for _, pattern, _, _, _ in SECRET_PATTERNS:
        matches = pattern.findall(res)
        for m in matches:
            if isinstance(m, str) and len(m) > 6 and m.lower() not in DUMMY_VALUES:
                res = res.replace(m, mask_secret(m))
    return res


def remove_readonly(func, path, exc_info):
    """Windows-safe error handler for shutil.rmtree on read-only git files."""
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        pass


def is_binary_file(filepath: str) -> bool:
    """Checks extension and probes for null bytes in the first 1024 bytes."""
    _, ext = os.path.splitext(filepath)
    if ext.lower() in BINARY_EXTENSIONS:
        return True
    try:
        with open(filepath, "rb") as f:
            chunk = f.read(1024)
            if b"\x00" in chunk:
                return True
    except Exception:
        return True
    return False


# ---------------------------------------------------------------------------
# GitHub Repository Lookup & Validation
# ---------------------------------------------------------------------------

async def fetch_github_metadata(owner: str, repo: str) -> Dict[str, Any]:
    """
    Queries GitHub REST API to verify repository exists, is public, and within size limits.
    """
    api_url = f"https://api.github.com/repos/{owner}/{repo}"
    headers = {
        "User-Agent": "AccountBreachInvestigation-Bot/1.0",
        "Accept": "application/vnd.github.v3+json",
    }
    if settings.GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {settings.GITHUB_TOKEN}"

    async with httpx.AsyncClient(timeout=settings.REQUEST_TIMEOUT_SECONDS * 2) as client:
        try:
            resp = await client.get(api_url, headers=headers)
        except Exception as e:
            raise ValueError(f"Could not connect to GitHub API: {str(e)}")

        if resp.status_code == 404:
            raise ValueError(
                f"Repository '{owner}/{repo}' not found on GitHub. "
                "Please verify the owner and repo name, and ensure the repository is public."
            )
        if resp.status_code == 403:
            msg = resp.json().get("message", "API rate limit reached")
            raise ValueError(f"GitHub API restriction: {msg}")
        if resp.status_code != 200:
            raise ValueError(f"GitHub API returned error status {resp.status_code}.")

        data = resp.json()
        if data.get("private", False):
            raise ValueError("Repository is private. Only public repositories can be scanned.")

        size_kb = data.get("size", 0)
        if size_kb == 0:
            raise ValueError("Repository appears to be completely empty.")
        if size_kb > settings.REPO_MAX_SIZE_KB:
            raise ValueError(
                f"Repository size ({size_kb // 1024} MB) exceeds the {settings.REPO_MAX_SIZE_KB // 1024} MB limit."
            )

        return data


# ---------------------------------------------------------------------------
# Shallow Clone
# ---------------------------------------------------------------------------

async def clone_repository(repo_url: str, branch: str, target_dir: str) -> None:
    """
    Performs a safe, shallow clone without git hooks or submodules.
    """
    cmd = [
        "git",
        "clone",
        "--depth", "1",
        "--single-branch",
        "--branch", branch,
        "--no-tags",
        "-c", "core.hooksPath=",
        repo_url,
        target_dir
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=settings.REPO_CLONE_TIMEOUT_SECONDS
            )
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            raise ValueError("Git clone operation timed out after 60 seconds.")

        if proc.returncode != 0:
            err_text = stderr.decode(errors="replace").strip()
            raise ValueError(f"Git clone failed: {err_text or 'Unknown git error'}")
    except FileNotFoundError:
        raise ValueError("Git command not found on server system.")


# ---------------------------------------------------------------------------
# Scanner 1: Secrets & Sensitive Files
# ---------------------------------------------------------------------------

def scan_file_for_secrets(rel_path: str, content: str) -> List[RepoFinding]:
    findings: List[RepoFinding] = []
    lines = content.splitlines()

    # Check for committed .env files
    base_name = os.path.basename(rel_path).lower()
    if (base_name == ".env" or base_name.startswith(".env.")) and not (
        base_name.endswith(".example") or base_name.endswith(".sample") or base_name.endswith(".template")
    ):
        findings.append(
            RepoFinding(
                id=f"secret-env-{len(findings) + 1}",
                category="secrets",
                severity="critical",
                title="Committed Environment Secrets File (.env)",
                filePath=rel_path,
                lineNumber=1,
                explanation="A live environment variable file (.env) was committed to the repository. These files usually store production database passwords and API keys.",
                suggestedFix="Add '.env' and '.env.*' to your .gitignore file immediately, and rotate any secrets that were committed.",
                codeSnippet=lines[0][:80] if lines else None
            )
        )

    for line_idx, line in enumerate(lines, start=1):
        for name, pattern, severity, expl, fix in SECRET_PATTERNS:
            match = pattern.search(line)
            if match:
                raw_secret = match.group(1) if match.groups() else match.group(0)
                if raw_secret.lower() in DUMMY_VALUES:
                    continue
                findings.append(
                    RepoFinding(
                        id=f"secret-{len(findings) + 1}-{line_idx}",
                        category="secrets",
                        severity=severity,
                        title=f"Leaked Secret: {name}",
                        filePath=rel_path,
                        lineNumber=line_idx,
                        explanation=expl,
                        suggestedFix=fix,
                        codeSnippet=sanitize_snippet(line.strip(), raw_secret)
                    )
                )
    return findings


# ---------------------------------------------------------------------------
# Scanner 2: Dependencies via OSV.dev Batch API
# ---------------------------------------------------------------------------

async def scan_dependencies(clone_dir: str) -> List[RepoFinding]:
    """
    Parses manifest files (requirements.txt, package.json) and checks OSV.dev batch API.
    """
    findings: List[RepoFinding] = []
    queries: List[Dict[str, Any]] = []
    meta_records: List[Dict[str, Any]] = []

    # 1. Parse requirements.txt
    req_path = os.path.join(clone_dir, "requirements.txt")
    if os.path.isfile(req_path):
        try:
            with open(req_path, "r", encoding="utf-8", errors="replace") as f:
                for idx, line in enumerate(f, start=1):
                    clean = line.strip().split("#")[0]
                    if "==" in clean:
                        pkg, ver = clean.split("==", 1)
                        pkg = pkg.strip()
                        ver = ver.strip()
                        if pkg and ver:
                            queries.append({"package": {"name": pkg, "ecosystem": "PyPI"}, "version": ver})
                            meta_records.append({
                                "pkg": pkg, "ver": ver, "file": "requirements.txt",
                                "line": idx, "ecosystem": "Python / PyPI", "raw": clean
                            })
        except Exception:
            pass

    # 2. Parse package.json
    pkg_json_path = os.path.join(clone_dir, "package.json")
    if os.path.isfile(pkg_json_path):
        try:
            with open(pkg_json_path, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
                all_deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                for pkg, ver_spec in all_deps.items():
                    # Clean semantic version markers (^, ~, >=)
                    ver = re.sub(r"[^0-9\.]", "", ver_spec)
                    if pkg and ver:
                        queries.append({"package": {"name": pkg, "ecosystem": "npm"}, "version": ver})
                        meta_records.append({
                            "pkg": pkg, "ver": ver, "file": "package.json",
                            "line": 1, "ecosystem": "JavaScript / npm", "raw": f'"{pkg}": "{ver_spec}"'
                        })
        except Exception:
            pass

    # Cap dependencies queried at 300
    if len(queries) > 300:
        queries = queries[:300]
        meta_records = meta_records[:300]

    if not queries:
        return findings

    # Query OSV.dev batch API
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post("https://api.osv.dev/v1/querybatch", json={"queries": queries})
            if resp.status_code == 200:
                results = resp.json().get("results", [])
                for i, r in enumerate(results):
                    meta = meta_records[i]
                    vulns = r.get("vulns", [])
                    for vuln in vulns[:2]:  # Limit to 2 notable CVEs per vulnerable package
                        vuln_id = vuln.get("id", "VULN-ALERT")
                        summary = vuln.get("summary") or (vuln.get("details", "")[:120] + "...") or "Security flaw in package"
                        
                        # Find fixed version
                        fixed_ver = None
                        for aff in vuln.get("affected", []):
                            for rng in aff.get("ranges", []):
                                for ev in rng.get("events", []):
                                    if "fixed" in ev:
                                        fixed_ver = ev["fixed"]
                                        break

                        # Severity determination
                        sev_level: RiskLevel = "high"
                        for s in vuln.get("severity", []):
                            score_str = s.get("score", "")
                            if "CVSS:3" in score_str:
                                try:
                                    base_score = float(score_str.split("/")[0].split(":")[-1])
                                    if base_score >= 9.0:
                                        sev_level = "critical"
                                    elif base_score >= 7.0:
                                        sev_level = "high"
                                    elif base_score >= 4.0:
                                        sev_level = "medium"
                                    else:
                                        sev_level = "low"
                                except Exception:
                                    pass

                        fix_msg = f"Upgrade '{meta['pkg']}' to version {fixed_ver} or higher." if fixed_ver else f"Update '{meta['pkg']}' to the latest safe release."

                        findings.append(
                            RepoFinding(
                                id=f"dep-{len(findings) + 1}",
                                category="dependencies",
                                severity=sev_level,
                                title=f"Vulnerable {meta['ecosystem']} Package: {meta['pkg']} ({vuln_id})",
                                filePath=meta["file"],
                                lineNumber=meta["line"],
                                explanation=f"Package '{meta['pkg']}' version {meta['ver']} contains known security flaw {vuln_id}: {summary}",
                                suggestedFix=fix_msg,
                                codeSnippet=meta["raw"]
                            )
                        )
    except Exception:
        # Graceful fallback if OSV.dev network query is unavailable or mocked
        pass

    return findings


# ---------------------------------------------------------------------------
# Scanner 3: Code Security (Bandit for Python + Pattern Checks for JS/TS)
# ---------------------------------------------------------------------------

async def run_bandit_scanner(clone_dir: str) -> List[RepoFinding]:
    findings: List[RepoFinding] = []
    cmd = [sys.executable, "-m", "bandit", "-r", clone_dir, "-f", "json", "-q"]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=35.0)
        output_str = stdout.decode(errors="replace").strip()
        if output_str:
            data = json.loads(output_str)
            for res in data.get("results", []):
                rel_f = os.path.relpath(res.get("filename", ""), clone_dir).replace("\\", "/")
                b_sev = res.get("issue_severity", "MEDIUM").upper()
                sev: RiskLevel = "critical" if b_sev == "HIGH" else "high" if b_sev == "MEDIUM" else "medium"
                test_name = res.get("test_name", "bandit_issue")
                line_no = res.get("line_number", 1)
                expl = res.get("issue_text", "Dangerous code pattern identified by static analysis.")
                snippet = res.get("code", "").strip()

                findings.append(
                    RepoFinding(
                        id=f"code-py-{len(findings) + 1}",
                        category="code",
                        severity=sev,
                        title=f"Python Security Flaw: {test_name}",
                        filePath=rel_f,
                        lineNumber=line_no,
                        explanation=f"{expl} Attackers can exploit this pattern if untrusted user input reaches it.",
                        suggestedFix="Review and replace this pattern with safe alternatives (e.g. use parameterized queries or ast.literal_eval).",
                        codeSnippet=snippet[:120] if snippet else None
                    )
                )
    except Exception:
        pass

    return findings


def scan_file_for_js_code_issues(rel_path: str, content: str) -> List[RepoFinding]:
    findings: List[RepoFinding] = []
    lines = content.splitlines()

    JS_PATTERNS = [
        (
            re.compile(r"\beval\s*\("),
            "Dangerous eval() Call Detected",
            "high",
            "The code uses 'eval()', which executes strings as live JavaScript code. Attackers can execute arbitrary browser actions or steal session cookies.",
            "Replace eval() with structured JSON.parse() or mathematical parsing libraries. Never pass untrusted user data to eval()."
        ),
        (
            re.compile(r"\bnew\s+Function\s*\("),
            "Dynamic Code Generation (new Function)",
            "high",
            "The code constructs functions dynamically from text at runtime, which behaves like eval() and creates code injection vulnerabilities.",
            "Refactor code to use static function declarations instead of building executable functions from strings."
        ),
        (
            re.compile(r"\.(?:innerHTML|outerHTML)\s*="),
            "Unsafe DOM HTML Injection (innerHTML)",
            "medium",
            "Directly writing into innerHTML without sanitization allows Cross-Site Scripting (XSS) attacks in visitors' browsers.",
            "Use textContent, innerText, or DOMPurify.sanitize() before inserting HTML content into the document."
        ),
        (
            re.compile(r"\bdocument\.write\s*\("),
            "Unsafe document.write() Execution",
            "medium",
            "The code uses 'document.write', which can overwrite entire page contents and introduce script injection flaws.",
            "Use modern DOM manipulation APIs like appendChild() or framework state rendering."
        ),
        (
            re.compile(r"(?:\bchild_process\.)?\bexec\s*\(\s*(?:`|'.*\$\{|.*\+.*)"),
            "Command Injection Risk in Child Process Exec",
            "critical",
            "Operating system commands are concatenated dynamically with variables. If an attacker inputs command separators (like ';' or '|'), they can take over the server.",
            "Use child_process.execFile() or spawn() with argument arrays instead of passing raw concatenated shell strings."
        ),
    ]

    for idx, line in enumerate(lines, start=1):
        for pattern, title, sev, expl, fix in JS_PATTERNS:
            if pattern.search(line):
                findings.append(
                    RepoFinding(
                        id=f"code-js-{len(findings) + 1}-{idx}",
                        category="code",
                        severity=sev,
                        title=title,
                        filePath=rel_path,
                        lineNumber=idx,
                        explanation=expl,
                        suggestedFix=fix,
                        codeSnippet=sanitize_snippet(line.strip())
                    )
                )
    return findings


# ---------------------------------------------------------------------------
# Scanner 4: Network & Infrastructure Issues
# ---------------------------------------------------------------------------

PUBLIC_IP_REGEX = re.compile(
    r"\b(?!(?:10\.|127\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.|169\.254\.|0\.0\.0\.0|255\.255\.255\.255|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.))([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\b"
)
HTTP_URL_REGEX = re.compile(r"http:\/\/([a-zA-Z0-9\-\.]+(?::\d+)?)(?:[/?#][^\s'\"<>]*)?")


def scan_file_for_network_issues(rel_path: str, content: str) -> List[RepoFinding]:
    findings: List[RepoFinding] = []
    lines = content.splitlines()
    base_name = os.path.basename(rel_path).lower()

    # 1. Exposed ports in Docker / Compose files
    if "docker" in base_name or "compose" in base_name or base_name == "dockerfile":
        DOCKER_PORT_REGEX = re.compile(r"['\"]?(?:0\.0\.0\.0:)?(21|22|23|3306|5432|6379|27017):\1['\"]?|EXPOSE\s+(21|22|23)")
        for idx, line in enumerate(lines, start=1):
            m = DOCKER_PORT_REGEX.search(line)
            if m:
                port_num = m.group(1) or m.group(2)
                findings.append(
                    RepoFinding(
                        id=f"net-docker-{len(findings) + 1}",
                        category="network",
                        severity="high" if port_num in ("21", "22", "23") else "medium",
                        title=f"Exposed Database / Remote Port {port_num} in Container Configuration",
                        filePath=rel_path,
                        lineNumber=idx,
                        explanation=f"Port {port_num} is exposed directly to 0.0.0.0 (all network interfaces). Anyone with network access can connect to internal services.",
                        suggestedFix=f"Bind the port to localhost only ('127.0.0.1:{port_num}:{port_num}') or keep it inside the private Docker network.",
                        codeSnippet=line.strip()
                    )
                )

    for idx, line in enumerate(lines, start=1):
        # 2. Insecure unencrypted HTTP connections
        for m in HTTP_URL_REGEX.finditer(line):
            host = m.group(1).lower().split(":")[0]
            if host not in IGNORED_URL_DOMAINS and not any(host.endswith("." + d) for d in IGNORED_URL_DOMAINS):
                findings.append(
                    RepoFinding(
                        id=f"net-http-{len(findings) + 1}-{idx}",
                        category="network",
                        severity="medium",
                        title="Insecure Unencrypted HTTP Connection",
                        filePath=rel_path,
                        lineNumber=idx,
                        explanation=f"Your application connects to an unencrypted address ({m.group(0)[:60]}). Hackers on the same Wi-Fi can intercept or tamper with the transmission.",
                        suggestedFix="Upgrade the web address to use secure encrypted HTTPS (https://).",
                        codeSnippet=m.group(0)[:80]
                    )
                )
                break

        # 3. Hardcoded public IP addresses
        ip_matches = PUBLIC_IP_REGEX.findall(line)
        for ip in ip_matches:
            octets = ip.split(".")
            if len(octets) == 4 and all(0 <= int(o) <= 255 for o in octets):
                # Ignore common safe DNS IPs (8.8.8.8, 1.1.1.1) to avoid alert fatigue
                if ip not in ("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"):
                    findings.append(
                        RepoFinding(
                            id=f"net-ip-{len(findings) + 1}-{idx}",
                            category="network",
                            severity="low",
                            title="Hardcoded Public IP Address in Source Code",
                            filePath=rel_path,
                            lineNumber=idx,
                            explanation=f"A static public IP address ({ip}) is hardcoded in this file. Hardcoding IPs makes the code fragile and leaks internal infrastructure topology.",
                            suggestedFix="Use configuration files, DNS hostnames, or service discovery instead of hardcoded raw IP addresses.",
                            codeSnippet=sanitize_snippet(line.strip())
                        )
                    )
                    break

    return findings


# ---------------------------------------------------------------------------
# Master Scan Pipeline
# ---------------------------------------------------------------------------

async def inspect_repository(raw_url: str) -> RepoScanResponse:
    """
    Executes the full repository security audit pipeline:
    1. Validate GitHub URL strictly
    2. Lookup metadata via GitHub REST API
    3. Shallow clone into fresh temporary directory
    4. Safe directory walk with symlink and size guards
    5. Run secret, dependency, code, and network scanners
    6. Mask all secrets and calculate risk score
    7. Always clean up temporary directory in a finally block
    """
    # 1. URL validation
    match = GITHUB_URL_REGEX.match(raw_url.strip())
    if not match:
        raise ValueError(
            "Invalid GitHub repository URL. Must be in the format 'https://github.com/owner/repository'."
        )

    owner, repo_name = match.group(1), match.group(2)
    normalized_url = f"https://github.com/{owner}/{repo_name}"

    # 2. Metadata lookup
    meta = await fetch_github_metadata(owner, repo_name)
    default_branch = meta.get("default_branch", "main")
    full_repo_name = meta.get("full_name", f"{owner}/{repo_name}")

    # 3. Create temp directory
    temp_dir = tempfile.mkdtemp(prefix="repo_audit_")
    clone_dir = os.path.join(temp_dir, "repo")

    all_findings: List[RepoFinding] = []
    scanned_files_count = 0
    start_time = time.time()
    timed_out = False

    try:
        # Clone repository
        await clone_repository(normalized_url, default_branch, clone_dir)

        # 4. Walk files with limits
        files_to_scan: List[str] = []
        for root, dirs, files in os.walk(clone_dir, followlinks=False):
            # Exclude ignored directories in-place
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRS and not os.path.islink(os.path.join(root, d))]

            for f in files:
                full_path = os.path.join(root, f)
                # DO NOT follow symlinks
                if os.path.islink(full_path):
                    continue
                # Path traversal guard
                if not os.path.abspath(full_path).startswith(os.path.abspath(clone_dir)):
                    continue
                files_to_scan.append(full_path)
                if len(files_to_scan) >= settings.REPO_MAX_FILES:
                    break
            if len(files_to_scan) >= settings.REPO_MAX_FILES:
                break

        # 5. Run scanners
        # Scanner A: Dependencies
        dep_findings = await scan_dependencies(clone_dir)
        all_findings.extend(dep_findings)

        # Scanner B: Python static code analysis (Bandit)
        bandit_findings = await run_bandit_scanner(clone_dir)
        all_findings.extend(bandit_findings)

        # Scanner C: File-by-file secrets, JS code, and network issues
        for full_path in files_to_scan:
            # Check overall timeout limit
            if (time.time() - start_time) > (settings.REPO_OVERALL_TIMEOUT_SECONDS - 5.0):
                timed_out = True
                break

            try:
                file_size = os.path.getsize(full_path)
            except Exception:
                continue

            if file_size > settings.REPO_MAX_FILE_BYTES:
                continue

            if is_binary_file(full_path):
                continue

            rel_path = os.path.relpath(full_path, clone_dir).replace("\\", "/")
            scanned_files_count += 1

            try:
                with open(full_path, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
            except Exception:
                continue

            # Secrets check
            file_secrets = scan_file_for_secrets(rel_path, content)
            all_findings.extend(file_secrets)

            # JS/TS code pattern checks
            _, ext = os.path.splitext(rel_path)
            if ext.lower() in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
                js_issues = scan_file_for_js_code_issues(rel_path, content)
                all_findings.extend(js_issues)

            # Network checks
            net_issues = scan_file_for_network_issues(rel_path, content)
            all_findings.extend(net_issues)

    finally:
        # 8. ALWAYS delete temp directory in finally block
        shutil.rmtree(temp_dir, onerror=remove_readonly)

    # 6. Scoring & summary
    crit_count = sum(1 for f in all_findings if f.severity == "critical")
    high_count = sum(1 for f in all_findings if f.severity == "high")
    med_count = sum(1 for f in all_findings if f.severity == "medium")
    low_count = sum(1 for f in all_findings if f.severity == "low")
    total_count = len(all_findings)

    # Calculate weighted risk score
    raw_score = (crit_count * 25) + (high_count * 15) + (med_count * 8) + (low_count * 3)
    risk_score = min(100, raw_score)

    if risk_score >= 75 or crit_count > 0:
        risk_level: RiskLevel = "critical"
    elif risk_score >= 50 or high_count > 0:
        risk_level = "high"
    elif risk_score >= 25 or med_count > 0:
        risk_level = "medium"
    else:
        risk_level = "low"

    if total_count == 0:
        summary = (
            f"Repository '{full_repo_name}' is in excellent condition! "
            f"Scanned {scanned_files_count} files with zero exposed credentials, vulnerable dependencies, or unsafe code patterns."
        )
    else:
        timeout_note = " (Note: scan reached time limit; partial results returned.)" if timed_out else ""
        summary = (
            f"We discovered {total_count} security issue(s) across {scanned_files_count} scanned files in '{full_repo_name}', "
            f"including {crit_count} critical and {high_count} high severity alert(s).{timeout_note} "
            "Exposed credentials and vulnerable components should be addressed immediately."
        )

    counts = FindingCounts(
        critical=crit_count,
        high=high_count,
        medium=med_count,
        low=low_count,
        total=total_count
    )

    return RepoScanResponse(
        repoUrl=normalized_url,
        repoName=full_repo_name,
        riskScore=risk_score,
        riskLevel=risk_level,
        summary=summary,
        counts=counts,
        findings=all_findings,
        timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        branch=default_branch,
        scannedFilesCount=scanned_files_count
    )
