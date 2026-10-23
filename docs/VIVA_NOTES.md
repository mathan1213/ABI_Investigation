# Account Breach Investigation (ABI) — Viva & Defense Notes

---

## 1. Project Explanation (One-Page Summary)

**Project Name:** Account Breach Investigation (ABI)  
**Tagline:** *"Find out if you were hacked, and how."*  
**Core Problem:** When ordinary internet users receive security alerts (e.g., "new login detected", "account compromised"), they face technical jargon, confusing IP addresses, and opaque logs. Existing tools like Wireshark or Nessus are built for enterprise sysadmins, while consumer antivirus software only scans local hard drives, missing cloud-account hijacks and leaked code tokens.

**Our Solution:**  
ABI is a consumer-focused, web-based cybersecurity investigation platform. It provides a multi-vector investigation across three primary channels:
1. **Telegram Account Forensics:** Direct MTProto read-only audit to detect unauthorized devices, physically impossible travel, and missing 2-step verification.
2. **GitHub Repository Security:** AST and pattern scanning for hardcoded secrets, API tokens, and vulnerable package dependencies.
3. **Network & Web Infrastructure:** Real-time IP threat intelligence, Tor exit node detection, SSL certificate expiry checks, open port probing, and HTTP security header evaluation.

**Central Innovation — The Risk Synthesis Engine:**  
Rather than presenting disjointed tables of raw data, a stateless Risk Engine aggregates findings, computes a composite score, drafts a plain-English attack story ("How It Likely Happened"), and produces a prioritized, de-duplicated 10-step recovery plan ("What To Do Now").

**Zero-Storage Privacy Architecture:**  
The backend is completely stateless. No phone numbers, passwords, OTPs, session strings, or chat contents are saved to disk or database. MTProto sessions exist solely in memory and are immediately terminated (`client.log_out()`) upon audit completion.

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
9. **In-Memory Rate Limiting:**
   - Sliding window rate limiting per client IP (3 requests / 10 min on SMS login; 10–20 requests / min on general endpoints) to prevent resource abuse and API flooding.

---

## 4. System Limitations

1. **Static Analysis Only:** The repository checker analyzes code patterns, dependencies, and regex entropy; it does not perform dynamic runtime execution or sandbox testing.
2. **External Key Dependency:** Without configured keys (`ABUSEIPDB_KEY`, `VIRUSTOTAL_KEY`), IP and link reputation scores rely on proxy/hosting heuristics and domain age rather than global threat feeds.
3. **Stateless Scope:** Because the system preserves zero database state, it cannot correlate user incidents across weeks or provide background 24/7 continuous monitoring.
4. **Telegram API Constraints:** Telegram's MTProto API enforces strict `FloodWait` protections; repeated code requests can trigger temporary account cooldowns imposed by Telegram.

---

## 5. 15 Likely Examiner Questions & Direct Answers

### Q1: Why did you build a custom Risk Engine instead of using an existing scanner like Nessus or OpenVAS?
**Answer:** Nessus and OpenVAS are infrastructure vulnerability scanners intended for security professionals. They output technical CVE listings that confuse normal users. Our Risk Engine synthesizes cross-vector issues (cloud account + code repo + network) and converts them into an actionable, plain-English attack narrative and a prioritized recovery checklist.

### Q2: What is the math behind your overall risk score?
**Answer:** We use the formula $\text{Overall} = 0.5 \times \max(\text{Scores}) + 0.5 \times \text{mean}(\text{Scores})$. The maximum score prevents severe, high-confidence compromise indicators from being diluted by clean modules, while the average reflects general security hygiene. Furthermore, any Critical finding automatically sets the overall threat level to at least High.

### Q3: How do you guarantee user privacy during Telegram authentication?
**Answer:** The application is strictly stateless. We use Telethon with in-memory `StringSession` objects in RAM. No phone numbers, passwords, or session tokens are ever written to disk. In a mandatory `finally` block in `analyze_telegram_account`, we call `await client.log_out()` to terminate the session on Telegram's servers and delete the client from memory.

### Q4: Does the tool read the user's private messages on Telegram?
**Answer:** No. The module is restricted to forensic metadata: active authorizations via `GetAuthorizationsRequest`, 2-step verification status via `GetPasswordRequest`, and login alerts from Telegram's official service notifications account (User ID `777000`). It never queries user chats, group chats, contacts, or media.

### Q5: What is Server-Side Request Forgery (SSRF), and how did you prevent it?
**Answer:** SSRF occurs when an attacker tricks a backend server into requesting internal or sensitive network resources (e.g., `http://169.254.169.254/latest/meta-data` or `http://localhost:8000`). We resolve target domains to IP addresses before initiating requests and reject private, loopback, link-local, multicast, and carrier-grade NAT addresses. We re-validate this check on every redirect hop.

### Q6: How does your tool detect "Physically Impossible Travel"?
**Answer:** When inspecting active authorizations, we record the geographic country and the `date_active` timestamp of each session. If two sessions in different countries were active less than 3 hours apart, human physical travel between them is impossible, indicating concurrent access by two different entities.

### Q7: Why did you separate apex domains from subdomains during DNS queries?
**Answer:** Host records (like A records) belong to specific subdomains (e.g., `www.example.com`). However, MX (mail exchange), NS (name servers), and TXT records (SPF, DKIM, DMARC) are registered on the apex domain (`example.com`). Querying `www.example.com` for MX records frequently returns empty results. We use `tldextract` to accurately isolate the registered apex domain.

### Q8: How are secrets detected in GitHub repositories?
**Answer:** We clone repositories with `--depth 1` into isolated temporary directories and scan text files using regular expressions with high-entropy pattern matching for AWS keys, GitHub tokens, Slack webhooks, Stripe keys, and private SSH keys. We never execute the code, and we sanitize temporary folders immediately after analysis.

### Q9: Why is the backend built in Python FastAPI while the frontend is Vite + React?
**Answer:** Python is the industry standard for cybersecurity and networking due to mature libraries like `telethon` (MTProto), `dnspython`, `httpx`, and `python-whois`. FastAPI provides asynchronous concurrency and Pydantic validation. React with TypeScript provides a snappy, responsive UI with client-side PDF compilation via `html2canvas` and `jsPDF`.

### Q10: What happens if an attacker enters a very large JSON payload to exhaust server memory?
**Answer:** In `backend/routers/report.py`, we enforce a hard 1 MB cap on the request body. If the `Content-Length` or the actual body stream exceeds 1 MB, the server immediately rejects the request with HTTP `413 Payload Too Large`.

### Q11: How do you handle Telegram accounts that have Two-Step Verification enabled?
**Answer:** If `client.sign_in()` raises a `SessionPasswordNeededError`, the backend returns HTTP 401 with `{"needsPassword": true}`. The frontend dynamically reveals a cloud password input field. The password is submitted temporarily to authenticate and is never stored.

### Q12: Why are public DNS resolvers like 8.8.8.8 not flagged as VPNs?
**Answer:** Datacenter IP heuristics can mistakenly label public infrastructure as proxies. We maintain an allowlist for known public resolvers (Google `8.8.8.8`, Cloudflare `1.1.1.1`), and we treat `isHosting` as a separate flag from `isVpn` and `isProxy`, only raising suspicion if ip-api or threat feeds explicitly flag anonymizer activity.

### Q13: Why is a missing HSTS header labeled "Safe" or "Low" instead of "Suspicious"?
**Answer:** Missing HTTP hardening headers represent weak configuration, not an active attack or malicious website. Labeling popular sites like Google as "Suspicious" due to missing headers is a false positive that harms user trust. Threat verdicts ("Suspicious" / "Dangerous") are reserved for expired SSL certificates, hostile open ports, or active malware flags.

### Q14: How does rate limiting work across the application?
**Answer:** We built in-memory sliding-window rate limiters grouped by client IP (`request.client.host`). `/api/telegram/send-code` is restricted to 3 requests per 10 minutes to prevent SMS abuse, while other endpoints allow 10–20 requests per minute. Exceeding the threshold returns HTTP `429 Too Many Requests`.

### Q15: How does the application function if external APIs (AbuseIPDB, VirusTotal, Telegram) are missing or offline?
**Answer:** The architecture is designed to fail gracefully. If Telegram API keys are missing, the endpoint returns HTTP 503, and the frontend automatically offers a realistic **Demo Mode** with a prominent warning banner. If threat intelligence keys are absent, the network module computes heuristic threat scores from open ports and proxy indicators, noting the limitation in the final report.
