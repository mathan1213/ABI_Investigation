import {
  TelegramScanResult,
  RepoScanResult,
  IpCheckResult,
  LinkCheckResult,
  WebsiteCheckResult,
  NetworkScanResult,
  FullReport,
  SystemStatus,
} from './types';

// API Base URL constant connecting to the Python FastAPI backend
export const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:8000";

/**
 * Fetches configuration and availability status of backend integrations and tools.
 */
export async function getSystemStatus(): Promise<SystemStatus> {
  try {
    const res = await fetch(`${API_BASE}/api/status`);
    if (!res.ok) {
      throw new Error('Failed to fetch system status');
    }
    const data = await res.json();
    return {
      telegram: Boolean(data.telegram),
      githubToken: Boolean(data.githubToken ?? data.github_token),
      abuseipdb: Boolean(data.abuseipdb),
      virustotal: Boolean(data.virustotal),
      gitInstalled: Boolean(data.gitInstalled ?? data.git_installed),
      banditAvailable: Boolean(data.banditAvailable ?? data.bandit_available),
    };
  } catch {
    return {
      telegram: false,
      githubToken: false,
      abuseipdb: false,
      virustotal: false,
      gitInstalled: false,
      banditAvailable: false,
    };
  }
}

// Helper delay simulating network latency (1.2 to 1.8 seconds)
const wait = (ms = 1400) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Common response handler for network inspection endpoints.
 * Handles 400 (bad input / SSRF blocked), 429 (rate limit), and unexpected errors.
 */
async function handleResponse<T>(res: Response, defaultErrorMsg: string): Promise<T> {
  if (res.status === 429) {
    throw new Error("Too many requests, please wait a minute");
  }
  if (!res.ok) {
    try {
      const errorData = await res.json();
      if (errorData?.detail) {
        if (typeof errorData.detail === 'string') {
          throw new Error(errorData.detail);
        } else if (Array.isArray(errorData.detail)) {
          throw new Error(errorData.detail.map((e: any) => e.msg || JSON.stringify(e)).join(', '));
        }
      }
    } catch (e: any) {
      if (e?.message && e.message !== 'Unexpected end of JSON input') {
        throw e;
      }
    }
    throw new Error(defaultErrorMsg);
  }
  return await res.json() as T;
}

// ---------------------------------------------------------------------------
// Telegram Account Forensics & Authentication API
// ---------------------------------------------------------------------------

export interface SendTelegramCodeResult {
  flowId: string;
  isDemo?: boolean;
  message?: string;
}

export interface VerifyTelegramCodeResult {
  status: string;
  needsPassword?: boolean;
  isDemo?: boolean;
}

/**
 * Realistic mock sample generator for fallback / demo mode.
 */
function getDemoTelegramResult(phone: string): TelegramScanResult {
  const isDemoClean = phone.endsWith('0000');

  if (isDemoClean) {
    return {
      phone,
      accountName: "Alex Rivera",
      riskScore: 12,
      riskLevel: "low",
      summary: "Your Telegram account looks safe. All active logins are from your own devices in your home region.",
      twoFactorEnabled: true,
      timestamp: new Date().toISOString(),
      isDemo: true,
      sessions: [
        {
          id: 'sess-1',
          device: 'Apple iPhone 15 Pro',
          app: 'Telegram iOS 10.8',
          ip: '198.51.100.24',
          country: 'United States',
          lastActive: 'Just now',
          isSuspicious: false,
          isCurrent: true,
          flagNote: 'Current device',
        },
        {
          id: 'sess-2',
          device: 'MacBook Pro 16" M3',
          app: 'Telegram Desktop 4.16',
          ip: '198.51.100.24',
          country: 'United States',
          lastActive: '3 hours ago',
          isSuspicious: false,
        }
      ],
      findings: [
        {
          id: 'find-clean-1',
          type: 'no_2fa',
          title: 'Two-Step Verification is Active',
          explanation: 'Your account has an extra password set up, protecting you even if someone intercepts an SMS code.',
          risk: 'low',
        }
      ],
      howItHappened: "No compromise detected. Your devices match your standard location, and two-step verification is active.",
      actionChecklist: [
        "Keep Two-Step Verification enabled.",
        "Review your active sessions once every month.",
        "Never share login verification codes with anyone, including people claiming to be Telegram Support."
      ]
    };
  }

  // Realistic breach scenario
  return {
    phone,
    accountName: "Alex Rivera (@arivera)",
    riskScore: 78,
    riskLevel: "critical",
    summary: "Someone logged into your Telegram account from another country without your permission, and your account lacks two-step password protection.",
    twoFactorEnabled: false,
    timestamp: new Date().toISOString(),
    isDemo: true,
    sessions: [
      {
        id: 'sess-1',
        device: 'Apple iPhone 15 Pro',
        app: 'Telegram iOS 10.8',
        ip: '73.189.44.12',
        country: 'United States (California)',
        lastActive: 'Just now',
        isSuspicious: false,
        isCurrent: true,
        flagNote: 'Your current device',
      },
      {
        id: 'sess-2',
        device: 'Linux PC / Ubuntu',
        app: 'Telegram Desktop 4.9.2 (Old version)',
        ip: '185.220.101.5',
        country: 'Germany (Frankfurt am Main)',
        lastActive: '42 minutes ago',
        isSuspicious: true,
        flagNote: 'Unknown device in a foreign country',
      },
      {
        id: 'sess-3',
        device: 'Samsung Galaxy A12',
        app: 'Telegram Android 10.2',
        ip: '91.240.118.88',
        country: 'Netherlands (Amsterdam)',
        lastActive: 'Yesterday at 11:15 PM',
        isSuspicious: true,
        flagNote: 'Impossible travel: logged in 20 minutes after California',
      }
    ],
    findings: [
      {
        id: 'tg-1',
        type: 'unknown_device',
        title: 'Unknown Computer Logged In',
        explanation: 'A computer running Linux in Frankfurt, Germany logged into your account 42 minutes ago. If this was not you or your VPN, someone else has your chats.',
        risk: 'critical',
        date: '42 minutes ago',
      },
      {
        id: 'tg-2',
        type: 'foreign_login',
        title: 'Login from Another Country',
        explanation: 'We detected access from Germany and the Netherlands, while your main phone is active in the United States.',
        risk: 'high',
        date: 'Today',
      },
      {
        id: 'tg-3',
        type: 'impossible_travel',
        title: 'Physically Impossible Travel Detected',
        explanation: 'Your account was used in California and Amsterdam just 20 minutes apart. A person cannot travel that fast, meaning two different people were logged in.',
        risk: 'critical',
        date: 'Yesterday',
      },
      {
        id: 'tg-4',
        type: 'no_2fa',
        title: 'Two-Step Verification is Turned Off',
        explanation: 'Your account is only guarded by SMS text codes. If someone steals or intercepts your text code, they can take over your account immediately.',
        risk: 'high',
      },
      {
        id: 'tg-5',
        type: 'suspicious_link',
        title: 'Suspicious Bot Authorization Found',
        explanation: 'An external automation bot with broad message-reading permissions was linked to your profile.',
        risk: 'medium',
      }
    ],
    howItHappened: "An intruder likely intercepted or tricked you into providing an SMS login code (or intercepted it via an infected app), then logged in from a remote server. Because no two-step password was set, they gained instant access to your chats and contacts.",
    actionChecklist: [
      "Open Telegram Settings > Devices > Tap 'Terminate all other sessions' immediately.",
      "Turn on Two-Step Verification right now: Settings > Privacy and Security > Two-Step Verification.",
      "Check your Telegram cloud chat backups and saved messages for any sensitive passwords or photos.",
      "Warn close friends or family if the intruder may have sent them phishing requests posing as you."
    ]
  };
}

/**
 * Requests a one-time verification code from Telegram.
 * Calls real backend: POST /api/telegram/send-code
 * Never silently substitutes mock data.
 */
export async function sendTelegramCode(phone: string): Promise<SendTelegramCodeResult> {
  const cleanPhone = phone.trim();
  let res: Response;
  try {
    res = await fetch(`${API_BASE}/api/telegram/send-code`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ phone: cleanPhone }),
    });
  } catch {
    throw new Error(`Cannot reach the analysis server at ${API_BASE}. Please ensure the backend is running (cd backend && .venv/bin/uvicorn main:app --reload).`);
  }

  if (res.status === 503) {
    throw new Error('Telegram integration is not configured on the server. Please add TELEGRAM_API_ID and TELEGRAM_API_HASH from https://my.telegram.org to backend/.env.');
  }

  if (res.status === 429) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err?.detail || 'Too many verification code requests. Please wait 10 minutes.');
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err?.detail || 'Failed to request Telegram verification code. Please check the phone number.');
  }

  const data = await res.json();
  return {
    flowId: data.flowId,
    message: data.message,
    isDemo: false,
  };
}

/**
 * Verifies code (and optional two-step cloud password).
 * If 2FA password is required, returns { needsPassword: true }.
 */
export async function verifyTelegramCode(
  flowId: string,
  code: string,
  password?: string
): Promise<VerifyTelegramCodeResult> {
  if (flowId.startsWith('demo-flow-')) {
    await wait(400);
    if (code.trim() === '2fa' && !password) {
      return { status: 'needs_password', needsPassword: true, isDemo: true };
    }
    return { status: 'verified', needsPassword: false, isDemo: true };
  }

  let res: Response;
  try {
    res = await fetch(`${API_BASE}/api/telegram/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        flowId,
        code: code.trim(),
        password: password ? password.trim() : null,
      }),
    });
  } catch {
    throw new Error(`Cannot reach the analysis server at ${API_BASE}. Is the backend running?`);
  }

  if (res.status === 401) {
    const data = await res.json().catch(() => ({}));
    if (data?.needsPassword) {
      return { status: 'needs_password', needsPassword: true };
    }
    throw new Error(data?.detail || 'Two-step verification password is required for this account.');
  }

  if (res.status === 429) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data?.detail || 'Too many attempts. Please wait a moment.');
  }

  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data?.detail || 'Verification failed. Please check the code.');
  }

  const data = await res.json();
  return {
    status: data.status || 'verified',
    needsPassword: !!data.needsPassword,
  };
}

/**
 * Analyzes a Telegram account for suspicious logins, unexpected sessions, and security weaknesses.
 * Calls real backend: POST /api/telegram/analyze
 * Never silently substitutes mock data.
 */
export async function analyzeTelegram(
  flowIdOrPhone: string,
  legacyOtp?: string
): Promise<TelegramScanResult> {
  if (flowIdOrPhone.startsWith('demo-flow-')) {
    await wait(1200);
    return getDemoTelegramResult('+1 (555) 019-2834');
  }

  if (flowIdOrPhone.startsWith('+') && legacyOtp === 'demo') {
    return getDemoTelegramResult(flowIdOrPhone);
  }

  const flowId = flowIdOrPhone;
  let res: Response;
  try {
    res = await fetch(`${API_BASE}/api/telegram/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ flowId }),
    });
  } catch {
    throw new Error(`Cannot reach the analysis server at ${API_BASE}. Is the backend running?`);
  }

  if (res.status === 503) {
    throw new Error('Telegram integration is not configured on the server. Please add TELEGRAM_API_ID and TELEGRAM_API_HASH from https://my.telegram.org to backend/.env.');
  }

  return await handleResponse<TelegramScanResult>(res, 'Failed to complete Telegram security investigation');
}

/**
 * Cancels and disconnects an in-flight Telegram login flow.
 */
export async function cancelTelegram(flowId: string): Promise<void> {
  if (!flowId || flowId.startsWith('demo-flow-')) return;
  try {
    await fetch(`${API_BASE}/api/telegram/cancel`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ flowId }),
    });
  } catch {
    // Suppress network errors on unmount cancellation
  }
}

/**
 * Scans a public GitHub repository for leaked passwords, API keys, vulnerable packages, and unsafe code.
 * Real backend endpoint: POST /api/repo/scan
 */
export async function scanRepo(repoUrl: string): Promise<RepoScanResult> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 120000); // 2 minute timeout

  let res: Response;
  try {
    res = await fetch(`${API_BASE}/api/repo/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ repoUrl: repoUrl.trim() }),
      signal: controller.signal,
    });
  } catch (err: any) {
    if (err?.name === 'AbortError') {
      throw new Error("The repository scan timed out after 2 minutes. The repository may be very large or taking longer to process.");
    }
    throw new Error("Cannot reach the analysis server. Is the backend running?");
  } finally {
    clearTimeout(timeoutId);
  }

  return await handleResponse<RepoScanResult>(res, 'Failed to inspect repository');
}

/**
 * Checks an IP address for bad reputation, proxy/VPN/Tor usage, and malicious history.
 * Real backend endpoint: POST /api/network/ip
 */
export async function checkIp(ip: string): Promise<IpCheckResult> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}/api/network/ip`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip: ip.trim() }),
    });
  } catch {
    throw new Error("Cannot reach the analysis server. Is the backend running?");
  }
  return await handleResponse<IpCheckResult>(res, 'Failed to inspect IP address');
}

/**
 * Checks a suspicious link or URL for phishing redirects, domain age, and fake identity.
 * Real backend endpoint: POST /api/network/link
 */
export async function checkLink(url: string): Promise<LinkCheckResult> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}/api/network/link`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url.trim() }),
    });
  } catch {
    throw new Error("Cannot reach the analysis server. Is the backend running?");
  }
  return await handleResponse<LinkCheckResult>(res, 'Failed to inspect suspicious link');
}

/**
 * Checks a website domain for open doors (ports), certificate expiration, and browser safety shields.
 * Real backend endpoint: POST /api/network/website
 */
export async function checkWebsite(domain: string): Promise<WebsiteCheckResult> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}/api/network/website`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain: domain.trim() }),
    });
  } catch {
    throw new Error("Cannot reach the analysis server. Is the backend running?");
  }
  return await handleResponse<WebsiteCheckResult>(res, 'Failed to inspect website');
}

export interface GenerateReportPayload {
  telegram?: TelegramScanResult | null;
  repo?: RepoScanResult | null;
  network?: NetworkScanResult | null;
  demoModules?: string[];
}

/**
 * Compiles a comprehensive full investigation report across all scanned channels.
 * Calls real backend: POST /api/report/generate
 * Never silently substitutes mock data.
 */
export async function getReport(payload?: GenerateReportPayload): Promise<FullReport> {
  const requestBody = payload || {};

  let res: Response;
  try {
    res = await fetch(`${API_BASE}/api/report/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        telegram: requestBody.telegram || null,
        repo: requestBody.repo || null,
        network: requestBody.network || null,
        demoModules: requestBody.demoModules || [],
      }),
    });
  } catch {
    throw new Error(`Cannot reach the report server at ${API_BASE}. Please ensure the backend is running (cd backend && .venv/bin/uvicorn main:app --reload).`);
  }

  if (res.status === 413) {
    throw new Error('Report data exceeded the 1 MB size limit.');
  }
  if (res.status === 429) {
    throw new Error('Too many report requests. Please wait a minute.');
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err?.detail || 'Failed to generate investigation report on backend.');
  }

  const data: FullReport = await res.json();
  return data;
}
