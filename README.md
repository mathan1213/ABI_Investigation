# Account Breach Investigation

> **Tagline:** *"Find out if you were hacked, and how."*

A cybersecurity monorepo web application designed specifically for everyday, non-technical users. It analyzes connected accounts, detects unauthorized foreign logins, flags leaked passwords and API keys in source code, checks suspicious links and hostile IP addresses, and explains everything in clear plain English with actionable recovery steps.

---

## 🏗 Repository Structure (Monorepo)

This repository is structured as a clean monorepo separating client and server concerns:

```text
ABI_Investigation/
├── frontend/             # Complete Vite + React + TypeScript web application
│   ├── src/
│   │   ├── components/   # Reusable UI widgets (RiskBadge, RiskGauge, Stepper, etc.)
│   │   ├── context/      # Null-safe scan state management (ScanContext.tsx)
│   │   ├── lib/          # Typed schemas and API layer with FastAPI-ready mock hooks
│   │   ├── pages/        # Dashboard, LinkTelegram, RepoCheck, NetworkCheck, Report, 404
│   │   ├── App.tsx       # Route definitions
│   │   └── main.tsx      # Application entry point
│   ├── public/           # Static icons and assets
│   ├── package.json      # Dependencies (Tailwind, Lucide, Recharts, jsPDF, html2canvas)
│   └── vite.config.ts    # Vite bundler configuration
├── backend/              # Python FastAPI backend service
│   ├── .gitkeep          # Workspace placeholder
│   └── .gitignore        # Backend-specific ignore rules (.env, .venv, pycache)
├── .gitignore            # Root repository ignore rules
└── README.md             # Project documentation and quickstart guide
```

### 1. `frontend/`
Contains the complete, production-ready user interface built with:
- **Vite + React 19 + TypeScript**
- **Tailwind CSS** with dark navy theme (`#0B1220` background, `#111A2E` cards, `#22D3EE` cyan accent)
- **React Router** for seamless multi-page navigation
- **Recharts** for visual risk and trend analytics
- **jsPDF + html2canvas** for generating downloadable PDF investigation reports
- **Lucide Icons** for cybersecurity status indicators

### 2. `backend/`
Designated home for the Python FastAPI server. It exposes REST API endpoints for session auditing, IP threat intelligence, and GitHub repository analysis. All mock functions in `frontend/src/lib/api.ts` are pre-wired with route comments to connect to `http://localhost:8000`.

---

## 🚀 Running the Frontend

To start the frontend application locally:

```bash
# 1. Navigate to the frontend directory
cd frontend

# 2. Install all required dependencies
npm install

# 3. Start the development server
npm run dev
```

Open your browser at `http://localhost:5173/`.

### Building for Production
```bash
cd frontend
npm run build
npm run preview
```

---

## 🔌 Connecting Frontend to Backend

All mock data and async functions are centralized in:
`frontend/src/lib/api.ts`

### Backend URL
`const API_BASE = "http://localhost:8000";`

| Frontend Function | Method | FastAPI Route | Purpose |
| :--- | :--- | :--- | :--- |
| `analyzeTelegram(phone, otp)` | `POST` | `/api/v1/telegram/analyze` | Read-only check for foreign sessions & 2FA |
| `scanRepo(repoUrl)` | `POST` | `/api/v1/repo/scan` | Scans public GitHub repositories for leaked keys |
| `checkIp(ip)` | `GET` | `/api/v1/network/ip?ip={ip}` | Resolves IP abuse scores and Tor/VPN status |
| `checkLink(url)` | `GET` | `/api/v1/network/link?url={url}` | Audits redirect chains and domain age |
| `checkWebsite(domain)` | `GET` | `/api/v1/network/website?domain={domain}` | Checks open ports (80, 443, 22, 21) & SSL expiry |
| `getReport()` | `GET` | `/api/v1/report` | Returns synthesized security dossier |

---

## 🔒 Privacy & Safety Guarantee

- **Zero-Storage:** No credentials, phone numbers, or private code are permanently stored.
- **Client-Side PDF:** Reports are rendered locally in your browser using `html2canvas` and `jsPDF`.
