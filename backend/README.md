# Account Breach Investigation — Backend (Network Check Module)

FastAPI backend service powering the Network Check module of **Account Breach Investigation** (*"Find out if you were hacked, and how."*).

Designed for everyday, non-technical users, it translates low-level network signals, threat intelligence, and protocol headers into clear plain-English security verdicts (`Safe`, `Suspicious`, `Dangerous`).

---

## 🛠 Features & Capabilities

1. **IP Reputation & Anonymizer Check (`POST /api/network/ip`)**
   - Geolocation, ISP, and ASN lookups.
   - Live Tor bulk exit list verification (cached in memory for 6 hours).
   - Commercial VPN, proxy, and datacenter hosting detection.
   - Threat abuse scoring with fallback estimation if no API key is provided.

2. **Web Link & Phishing Investigation (`POST /api/network/link`)**
   - Follows redirect chains up to 8 hops with per-hop SSRF validation.
   - WHOIS domain creation age lookup (identifies brand new scam domains).
   - DNS resolution (A, MX, TXT, NS records).
   - SSL certificate validity and issuer authority inspection.
   - Heuristics for punycode lookalikes, excessively long subdomains, direct IP hosts, and missing SSL.

3. **Website Server Security Audit (`POST /api/network/website`)**
   - Restricted port checks limited strictly to ports 80, 443, 22, 21 with a 2-second timeout.
   - SSL certificate expiration calculation and days-remaining countdown.
   - Browser defense header audit:
     - `Strict-Transport-Security` (HSTS)
     - `Content-Security-Policy` (CSP)
     - `X-Frame-Options`
     - `X-Content-Type-Options`
     - `Referrer-Policy`

4. **Robust SSRF Protection**
   - Rejects any destination that resolves to loopback, private, link-local, or reserved IPv4/IPv6 address spaces (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `::1`, etc.).
   - Re-checks SSRF on every HTTP redirect hop.

5. **In-Memory Rate Limiting**
   - Enforces 20 requests per minute per client IP to prevent abuse.

---

## 🚀 Setup & Local Execution

### 1. Create Virtual Environment & Install Dependencies
```bash
# From the backend directory
python -m venv .venv

# Activate virtual environment
# Windows PowerShell:
.\.venv\Scripts\Activate.ps1
# Linux / macOS:
source .venv/bin/activate

# Install requirements
python -m pip install -r requirements.txt
```

### 2. Configure Environment Variables (Optional)
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
The backend functions completely without any third-party keys using built-in heuristics, Tor exit lists, and public lookups.

### 3. Start the Server
```bash
uvicorn main:app --reload --port 8000
```
- Interactive Swagger UI: `http://localhost:8000/docs`
- ReDoc Documentation: `http://localhost:8000/redoc`
- Health Endpoint: `http://localhost:8000/api/health`

---

## 🔑 Optional Free API Keys

You can add optional free API keys to `backend/.env`:

1. **AbuseIPDB API Key (Free Tier: 1,000 checks/day)**
   - Register at [https://www.abuseipdb.com/register](https://www.abuseipdb.com/register)
   - Go to **Account** > **API** > **Create Key**
   - Add to `.env`: `ABUSEIPDB_KEY=your_key_here`

2. **VirusTotal API Key (Free Tier: 500 requests/day)**
   - Register at [https://www.virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us)
   - Go to your profile menu > **API Key**
   - Add to `.env`: `VIRUSTOTAL_KEY=your_key_here`

---

## 📡 Example API Requests

### 1. Check IP (`POST /api/network/ip`)
```bash
curl -X POST "http://localhost:8000/api/network/ip" \
     -H "Content-Type: application/json" \
     -d '{"ip": "8.8.8.8"}'
```

**Response:**
```json
{
  "ip": "8.8.8.8",
  "country": "United States",
  "city": "Ashburn",
  "isp": "Google LLC",
  "asn": "AS15169 Google LLC",
  "isVpn": true,
  "isProxy": true,
  "isTor": false,
  "abuseScore": 72,
  "verdict": "Suspicious",
  "riskLevel": "medium",
  "explanation": "This IP address belongs to a commercial VPN, datacenter hosting, or proxy service...",
  "timestamp": "2026-10-23T18:15:52Z",
  "source": "estimated"
}
```

### 2. Check Link (`POST /api/network/link`)
```bash
curl -X POST "http://localhost:8000/api/network/link" \
     -H "Content-Type: application/json" \
     -d '{"url": "https://google.com"}'
```

**Response:**
```json
{
  "url": "https://google.com",
  "domain": "www.google.com",
  "domainAge": "29 years old",
  "domainAgeDays": 10630,
  "dnsRecords": {
    "a": ["142.251.150.119"],
    "mx": [],
    "txt": [],
    "ns": []
  },
  "sslValid": true,
  "sslIssuer": "Google Trust Services",
  "redirectChain": [
    { "step": 1, "url": "https://google.com", "status": 301, "note": "Redirected with HTTP 301" },
    { "step": 2, "url": "https://www.google.com/", "status": 200, "note": "Final destination reached" }
  ],
  "reputationScore": 100,
  "verdict": "Safe",
  "riskLevel": "low",
  "explanation": "This link points to an established web address with a valid SSL certificate.",
  "timestamp": "2026-10-23T18:16:15Z"
}
```

### 3. Check Website (`POST /api/network/website`)
```bash
curl -X POST "http://localhost:8000/api/network/website" \
     -H "Content-Type: application/json" \
     -d '{"domain": "google.com"}'
```

**Response:**
```json
{
  "domain": "google.com",
  "ports": [
    { "port": 80, "service": "HTTP (Web)", "state": "Open", "risk": "medium", "note": "Port 80 is open to visitors." },
    { "port": 443, "service": "HTTPS (Secure Web)", "state": "Open", "risk": "low", "note": "Secure HTTPS port is open." },
    { "port": 22, "service": "SSH (Server Control)", "state": "Closed", "risk": "low", "note": "Port 22 is safely closed or firewalled." },
    { "port": 21, "service": "FTP (File Transfer)", "state": "Closed", "risk": "low", "note": "Port 21 is safely closed or firewalled." }
  ],
  "openPorts": [80, 443],
  "sslExpiry": "December 21, 2026",
  "sslDaysRemaining": 59,
  "securityHeaders": [
    { "header": "X-Frame-Options", "status": "Pass", "description": "Protects visitors from clickjacking attacks." }
  ],
  "riskScore": 24,
  "riskLevel": "low",
  "verdict": "Safe",
  "explanation": "The website configuration for google.com is well-hardened.",
  "timestamp": "2026-10-23T18:17:22Z"
}
```

---

## 🧪 Running Tests

All unit and security tests run offline using mocks:
```bash
python -m pytest tests/ -v
```
All 22 test suites cover:
- SSRF prevention against loopback, RFC 1918 private ranges, and cloud metadata (`169.254.169.254`)
- Input validation and malformed payload handling
- Tor detection and dangerous verdict assignment
- Safe residential connection scoring
- Redirect hop tracking
- In-memory rate limiting (429 HTTP responses)
- Health check status
