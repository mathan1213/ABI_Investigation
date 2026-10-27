# Account Breach Investigation (ABI) — Viva & Defense Notes

---

## 1. Project Explanation (One-Page Summary)

**Project Name:** Account Breach Investigation (ABI)  
**Tagline:** *"Find out if you were hacked, and how."*  
**Core Problem:** When ordinary internet users receive security alerts (e.g., "new login detected", "account compromised"), they face technical jargon, confusing IP addresses, and opaque logs. Existing tools like Wireshark or Nessus are built for enterprise sysadmins, while consumer antivirus software only scans local hard drives, missing cloud-account hijacks and leaked code tokens.

**Our Solution:**  
ABI is a consumer-focused, web-based cybersecurity investigation platform. It provides a multi-vector investigation across three primary channels:
1. **Telegram Account Forensics:** Forensic log analysis of user-uploaded Telegram Desktop data exports (`sessions.json`/HTML, service notifications) to detect unauthorized devices, physically impossible travel, Tor/VPN connections, rapid login bursts, and dormant sessions with zero Telegram API keys required.
2. **GitHub Repository Security:** AST and pattern scanning for hardcoded secrets, API tokens, and vulnerable package dependencies.
3. **Network & Web Infrastructure:** Real-time IP threat intelligence, Tor exit node detection, SSL certificate expiry checks, open port probing, and HTTP security header evaluation.

**Central Innovation — The Risk Synthesis Engine:**  
Rather than presenting disjointed tables of raw data, a centralized Risk Engine aggregates findings, computes a composite score, drafts a plain-English attack story ("How It Likely Happened"), and produces a prioritized, de-duplicated 10-step recovery plan ("What To Do Now").

**Privacy & Security Architecture:**  
- **Zero Raw File Storage & Instant Redaction:** Uploaded Telegram export files are parsed purely in volatile RAM (`io.BytesIO`) and discarded in a `finally` block. Raw files and raw message text are never stored. All OTP verification codes are immediately redacted to `****`. Personal chats are filtered out and ignored.
- **Defensive Zip Handling:** Zip archives are protected against Zip Slip (path traversal), nested zip exploitation, and decompression bombs (capped at 200 entries and 50 MB uncompressed).
- **Authentication & RBAC:** SQLite database (`app.db`) stores user accounts with `bcrypt` password hashes, JWT authorization tokens, and immutable audit logs (`activity_log`).

---

## 2. Risk Scoring Formula & Mathematical Model

$$\text{Composite Score} = \text{round}\Big(0.5 \times \max(\text{Scores}) + 0.5 \times \text{mean}(\text{Scores})\Big)$$

- **Why this formula?** A simple average would dilute serious threats (e.g., a score of 100 on an active breach averaged with two 0 scores would yield 33 — "Low Risk"). Using 50% weight on the maximum score ensures severe threats are surfaced, while 50% on the mean accounts for broad hygiene issues.
- **Risk Level Thresholds:**
  - `0 – 24`: Low Risk
  - `25 – 49`: Medium Risk
  - `50 – 74`: High Risk
  - `75 – 100`: Critical Risk
- **Critical Finding Override Rule:** If any finding across any audited module has **Critical** severity (e.g., active Tor exit node, impossible travel between continents in <3 hours, or exposed AWS keys), the composite risk level is guaranteed to be at least **High**, regardless of how many clean modules were tested.
- **Unscanned Modules:** Unscanned modules are excluded from the calculation so users are not penalized or falsely reassured for modules they did not run.

---

## 3. Core Networking & Security Concepts Implemented

1. **DNS (Domain Name System):**
   - Resolves A records on specific hosts (`www.domain.com`), and apex queries (MX, NS, TXT) on registered apex domains using `tldextract`.
2. **WHOIS & Domain Age:**
   - Queries WHOIS registrar databases to identify newly registered domains (<30 days old), a primary heuristic for phishing campaigns.
3. **TLS/SSL Handshake & Certificate Inspection:**
   - Performs standard TLS handshakes using Python `ssl` and `socket` to extract certificate issuer, expiration timestamps, and calculate days remaining before expiration.
4. **TCP Port Probing:**
   - Non-intrusive asynchronous TCP connect probes (`socket.create_connection`) testing common service ports (21 FTP, 22 SSH, 23 Telnet, 80 HTTP, 443 HTTPS, 3389 RDP).
5. **HTTP Redirect Hop Chains & Security Headers:**
   - Traces up to 8 redirect hops via HTTP 301/302. Evaluates defensive security headers (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`) on the **final** landing response.
6. **IP Geolocation & Autonomous System Numbers (ASN):**
   - Translates raw IP addresses into physical locations (Country, City, ISP, ASN) using `ip-api.com` and validates infrastructure hosting status.
7. **Tor Exit Node & Anonymizer Detection:**
   - Caches and compares session IPs against the live official Tor Project directory (`https://check.torproject.org/torbulkexitlist`).
8. **Server-Side Request Forgery (SSRF) Protection:**
   - Resolves all user-supplied hostnames to IPs and rejects private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`), and carrier-grade NAT ranges across every hop.
9. **Safe In-Memory File & Archive Parsing:**
   - Zip Slip mitigation by validating `os.path.commonpath([target, dest]) == dest`.
   - Zip bomb mitigation (max 200 files, max 50 MB total uncompressed, 10 MB per file, max depth 20 in JSON).
   - Read-only BeautifulSoup parsing to prevent HTML injection and XSS execution during file inspection.
10. **Application Security & RBAC:**
    - Bcrypt password hashing with unique salts.
    - JWT signing with SHA-256 for stateless session authorization.
    - Role-based authorization middleware protecting Admin API endpoints.
    - IP-based sliding window rate limiting (5 req/min on `/login`, 10–20 req/min on scan routes).

---

## 4. System Limitations

1. **Static & Heuristic Analysis Only:** The repository checker analyzes code patterns, dependencies, and regex entropy; it does not perform dynamic runtime execution or sandbox testing.
2. **Snapshot Export Limitations:** Offline Telegram exports represent point-in-time snapshots and cannot query live 2FA settings or revoke sessions in real time. The report explicitly highlights manual steps the user should verify.
3. **External Key Dependency:** Without configured keys (`ABUSEIPDB_KEY`, `VIRUSTOTAL_KEY`), IP and link reputation scores rely on proxy/hosting heuristics and domain age rather than global threat feeds.

---

## 5. 15 Likely Examiner Questions & Direct Answers

### Q1: Why did you build a custom Risk Engine instead of using an existing scanner like Nessus or OpenVAS?
**Answer:** Nessus and OpenVAS are infrastructure vulnerability scanners intended for security professionals. They output technical CVE listings that confuse normal users. Our Risk Engine synthesizes cross-vector issues (cloud account + code repo + network) and converts them into an actionable, plain-English attack narrative and a prioritized recovery checklist.

### Q2: What is the math behind your overall risk score?
**Answer:** We use the formula $\text{Overall} = 0.5 \times \max(\text{Scores}) + 0.5 \times \text{mean}(\text{Scores})$. The maximum score prevents severe, high-confidence compromise indicators from being diluted by clean modules, while the average reflects general security hygiene. Furthermore, any Critical finding automatically sets the overall threat level to at least High.

### Q3: Why did you switch from live Telegram MTProto login to log export analysis?
**Answer:** Live MTProto authentication required end users or developers to register on `my.telegram.org` to obtain `API_ID` and `API_HASH`, which created friction. More importantly, entering phone numbers and OTP codes into web forms poses severe phishing risks and triggers Telegram `FloodWait` bans. Analyzing official Telegram Desktop export files provides rich forensic data (sessions, IPs, devices, service alerts) completely offline without credential exposure or API dependencies.

### Q4: Does the tool read or store the user's private messages or OTP codes?
**Answer:** Absolutely not. Uploaded exports are parsed strictly in memory and discarded in a `finally` block. Personal chat files are completely ignored. For official service chat notifications (ID 777000), all OTP and verification numbers are immediately redacted (`****`) via regex before any parsing. Only sanitized metadata (device, location, date) is processed, and zero raw files or message texts reach the database.

### Q5: What is Server-Side Request Forgery (SSRF), and how did you prevent it?
**Answer:** SSRF occurs when an attacker tricks a backend server into requesting internal or sensitive network resources (e.g., `http://169.254.169.254/latest/meta-data` or `http://localhost:8000`). We resolve target domains to IP addresses before initiating requests and reject private, loopback, link-local, multicast, and carrier-grade NAT addresses. We re-validate this check on every redirect hop.

### Q6: How does your tool detect "Physically Impossible Travel"?
**Answer:** When inspecting active authorizations, we record the geographic country and the `date_active` timestamp of each session. If two sessions in different countries were active less than 3 hours apart, human physical travel between them is impossible, indicating concurrent access by two different entities.

### Q7: Why did you separate apex domains from subdomains during DNS queries?
**Answer:** Host records (like A records) belong to specific subdomains (e.g., `www.example.com`). However, MX (mail exchange), NS (name servers), and TXT records (SPF, DKIM, DMARC) are registered on the apex domain (`example.com`). Querying `www.example.com` for MX records frequently returns empty results. We use `tldextract` to accurately isolate the registered apex domain.

### Q8: How are secrets detected in GitHub repositories?
**Answer:** We clone repositories with `--depth 1` into isolated temporary directories and scan text files using regular expressions with high-entropy pattern matching for AWS keys, GitHub tokens, Slack webhooks, Stripe keys, and private SSH keys. We never execute the code, and we sanitize temporary folders immediately after analysis.

### Q9: Why is the backend built in Python FastAPI while the frontend is Vite + React?
**Answer:** Python is the industry standard for cybersecurity and forensics due to mature libraries like `dnspython`, `httpx`, `beautifulsoup4`, and `bcrypt`. FastAPI provides high-speed asynchronous concurrency and Pydantic validation. React with TypeScript provides a snappy, responsive UI with client-side PDF compilation via `html2canvas` and `jsPDF`.

### Q10: What happens if an attacker enters a very large JSON payload to exhaust server memory?
**Answer:** In `backend/routers/report.py`, we enforce a hard 1 MB cap on the request body. If the `Content-Length` or the actual body stream exceeds 1 MB, the server immediately rejects the request with HTTP `413 Payload Too Large`. Similarly, uploaded zip files are capped at 10 MB per file, 25 MB total, and 50 MB uncompressed.

### Q11: How do you handle Telegram Two-Step Verification (2FA) status in log export mode?
**Answer:** Offline export files do not contain a flag indicating whether 2FA is currently active. The application never claims 2FA is enabled or disabled. Instead, it generates a clear "Manual Verification Needed" finding explaining what offline logs cannot show and providing step-by-step instructions on how the user can check and enable 2FA directly inside the official app.

### Q12: Why are public DNS resolvers like 8.8.8.8 not flagged as VPNs?
**Answer:** Datacenter IP heuristics can mistakenly label public infrastructure as proxies. We maintain an allowlist for known public resolvers (Google `8.8.8.8`, Cloudflare `1.1.1.1`), and we treat `isHosting` as a separate flag from `isVpn` and `isProxy`, only raising suspicion if ip-api or threat feeds explicitly flag anonymizer activity.

### Q13: Why is a missing HSTS header labeled "Safe" or "Low" instead of "Suspicious"?
**Answer:** Missing HTTP hardening headers represent weak configuration, not an active attack or malicious website. Labeling popular sites like Google as "Suspicious" due to missing headers is a false positive that harms user trust. Threat verdicts ("Suspicious" / "Dangerous") are reserved for expired SSL certificates, hostile open ports, or active malware flags.

### Q14: How does authentication, two-step OTP, and granular RBAC work in the platform?
**Answer:** The platform implements a production-grade multi-tier authentication and authorization system:
1. **Unique Usernames & Email Validation:** Accounts require a unique username (3-20 characters, starting with a letter, letters/digits/_/. only, case-insensitive uniqueness with a database unique index, reserved names like `admin`/`root`/`superadmin` blocked) checked live via debouncing.
2. **Mandatory Two-Step Email OTP Verification:** All registrations and logins require a 6-digit cryptographic OTP generated via Python's `secrets` module. Codes are **never stored in plain text**—only HMAC-SHA256 hashes are persisted. OTPs expire in 10 minutes, enforce a maximum of 5 failed attempts before permanent invalidation, and rate-limit resends to 60-second cooldowns and 5 per hour per account.
3. **Session Versioning (`token_version`):** Users have an incremental `token_version` included in JWT claims. Password changes, logouts, and administrative promotions immediately bump `token_version`, instantly invalidating all active tokens across devices.
4. **Granular RBAC & Permissions:** Three roles exist: `user`, `admin`, and `super_admin`. Regular admins hold granular permissions (`view_users`, `disable_users`, `delete_users`, `view_scans`, `view_reports`, `export_data`, `view_activity`, `manage_admins`) enforced on the backend with 403 Forbidden checks. The super admin holds all permissions implicitly and manages other administrators. An immutable `audit_log` records every administrative change with actor, action, target, and before/after diffs.
5. **Separate Admin Experience:** Administrators access a dedicated `/admin/login` page with two-factor authentication, leading to an isolated admin dashboard with an independent layout (no user navbar) and a 30-minute inactivity auto-logout.

### Q15: How do you protect against brute-force attacks and credential stuffing?
**Answer:** We enforce multiple defense-in-depth measures:
- IP sliding-window rate limiting (maximum 5 login attempts per minute per client IP).
- Account lockout: after 10 failed login attempts, the account is temporarily locked for 15 minutes.
- Common password dictionary rejection (disallowing common passwords like `password123`, `admin123`, etc.).
- Identical generic error responses ("Incorrect email, username or password.") for both non-existent accounts and wrong passwords to eliminate account enumeration vectors.
- Constant-time comparison (`hmac.compare_digest`) for all OTP verification codes to prevent side-channel timing attacks.

### Q16: How does the application function if external APIs (AbuseIPDB, VirusTotal) are missing or offline?
**Answer:** The architecture is designed to fail gracefully. If threat intelligence keys are absent, the network module computes heuristic threat scores from open ports, domain age, and proxy indicators, noting the limitation in the final report. Core scanning (repo analysis, Telegram log analysis, network probes) functions completely without paid third-party APIs.
