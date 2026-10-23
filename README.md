# ABI_Investigation — Account Breach Investigation

> **Tagline:** *"Find out if you were hacked, and how."*

A cybersecurity web application designed specifically for everyday, non-technical users. It analyzes connected accounts, detects unauthorized foreign logins, flags leaked passwords and API keys in source code, checks suspicious links and hostile IP addresses, and explains everything in clear plain English with actionable recovery steps.

---

## 🛠 Tech Stack

- **Framework:** [React 19](https://react.dev/) + [Vite](https://vite.dev/) + [TypeScript](https://www.typescriptlang.org/)
- **Styling:** [Tailwind CSS](https://tailwindcss.com/)
  - Dark navy theme: Background `#0B1220`, Cards `#111A2E`, Primary Accent Cyan `#22D3EE`
  - Color-coded risk badges: **Low** (Green), **Medium** (Yellow), **High** (Orange), **Critical** (Red)
  - Inter typography + JetBrains Mono for code snippets
- **Routing:** [React Router](https://reactrouter.com/) (Classic `<Routes>` & `<Route>`)
- **Visualizations:** [Recharts](https://recharts.org/) (Donut charts, category bar charts, risk trend line charts)
- **Icons:** [lucide-react](https://lucide.dev/)
- **Exporting:** [jsPDF](https://github.com/parallax/jsPDF) + [html2canvas](https://html2canvas.hertzen.com/) for one-click PDF report generation and native printing

---

## 📁 Project Architecture

```text
src/
├── lib/
│   ├── api.ts              # ALL mock API calls with realistic 1-2s latency & FastAPI swap comments
│   └── types.ts            # Strict shared TypeScript models (Zero 'any')
├── context/
│   └── ScanContext.tsx     # Centralized, null-safe scan state & session management + toasts
├── components/
│   ├── RiskBadge.tsx       # Standardized risk pill (Low, Medium, High, Critical)
│   ├── RiskGauge.tsx       # Speedometer-style SVG threat level gauge
│   ├── StatCard.tsx        # High-level metric card with hover glow
│   ├── FindingCard.tsx     # Plain-language finding card with copyable fix snippet
│   ├── Stepper.tsx         # 4-Step progress tracker (Consent -> Connect -> Analyze -> Result)
│   ├── SessionTable.tsx    # Device sessions table with Trusted/Suspicious flags
│   ├── Analyzing.tsx       # Animated cyber radar sweep & rotating status messages
│   ├── VerdictCard.tsx     # High-contrast verdict summary card (Safe, Suspicious, Dangerous)
│   ├── Navbar.tsx          # Top navigation bar with active route highlight & mobile drawer
│   ├── Footer.tsx          # Privacy-guarantee footer with zero-storage note & session wipe
│   ├── EmptyState.tsx      # Friendly call-to-action state when no scans are loaded
│   ├── ToastContainer.tsx  # Floating cyber toast notification stack
│   └── LoadingSkeleton.tsx # Shimmer skeletons for async state transitions
├── pages/
│   ├── Dashboard.tsx       # Risk overview, 4 metric cards, 3 Recharts graphs, connected assets
│   ├── LinkTelegram.tsx    # 4-step wizard: Consent, Phone+OTP, Radar scan, Forensic verdict
│   ├── RepoCheck.tsx       # Public GitHub repo URL scanner for secrets, CVEs, and insecure code
│   ├── NetworkCheck.tsx    # Multi-tab audit: IP reputation, Phishing link redirects, Website ports/SSL
│   ├── Report.tsx          # Incident dossier with working "Download PDF" & "Print" buttons
│   └── NotFound.tsx        # Styled 404 error page
├── App.tsx                 # Route declarations & App layout shell
└── main.tsx                # React DOM mounting
```

---

## 🚀 Running the Project

### Prerequisites
- Node.js (v18 or newer recommended, tested on Node v24)
- npm or yarn

### 1. Install Dependencies
```bash
npm install
```

### 2. Start the Development Server
```bash
npm run dev
```
Open your browser at `http://localhost:5173/`.

### 3. Production Build & Verification
```bash
npm run build
npm run preview
```
The build passes TypeScript compilation (`tsc -b`) and bundles production assets into `dist/` with zero errors.

---

## 🔌 Connecting to the Real Python FastAPI Backend

All mock data and async functions are centralized in:
`src/lib/api.ts`

### 1. Backend Base URL Constant
At line 11 of `src/lib/api.ts`:
```typescript
export const API_BASE = "http://localhost:8000";
```
When running with an external backend or environment variable, you can update this to:
```typescript
export const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:8000";
```

### 2. Endpoint Replacement Guide

Each function in `src/lib/api.ts` contains clear comments and commented-out `fetch()` boilerplate ready for seamless migration:

| Frontend Function | HTTP Method | Python FastAPI Route | Description |
| :--- | :--- | :--- | :--- |
| `analyzeTelegram(phone, otp)` | `POST` | `/api/v1/telegram/analyze` | Passes phone and OTP, receives active sessions, geolocations, and 2FA status |
| `scanRepo(repoUrl)` | `POST` | `/api/v1/repo/scan` | Submits a public GitHub URL to clone metadata, scan for secrets, and check CVEs |
| `checkIp(ip)` | `GET` | `/api/v1/network/ip?ip={ip}` | Queries abuse confidence, Tor exit nodes, and VPN flags |
| `checkLink(url)` | `GET` | `/api/v1/network/link?url={url}` | Follows redirect hops, validates SSL certificate age, checks phishing databases |
| `checkWebsite(domain)` | `GET` | `/api/v1/network/website?domain={domain}` | Scans ports (80, 443, 22, 21), checks SSL expiry, audits security headers |
| `getReport()` | `GET` | `/api/v1/report` | Generates a synthesized security incident report across all scanned assets |

#### Example: Replacing `analyzeTelegram` with Real Backend Call
In `src/lib/api.ts`:
```typescript
export async function analyzeTelegram(phone: string, otp: string): Promise<TelegramScanResult> {
  const response = await fetch(`${API_BASE}/api/v1/telegram/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ phone, otp }),
  });
  
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || 'Failed to inspect Telegram account');
  }
  
  return await response.json();
}
```

---

## 🔒 Privacy & Safety Features

- **Zero-Storage Architecture:** No passwords, phone numbers, or code contents are ever written to a permanent database by the frontend.
- **In-Memory & Local Session Storage:** Scans persist only for the duration of the user's active session and can be wiped instantly with the **"Clear Session Data"** button in the footer.
- **Client-Side PDF Generation:** PDF reports are generated directly in the user's browser using `html2canvas` and `jsPDF`. No report files are uploaded to an external server.

---

## 💡 Setting the Active Workspace in Antigravity IDE

If you are using the Antigravity IDE without an open project folder, set your workspace to:
`C:\Users\matha\.gemini\antigravity\scratch\account-breach-investigation-frontend`
