import {
  TelegramScanResult,
  RepoScanResult,
  IpCheckResult,
  LinkCheckResult,
  WebsiteCheckResult,
  FullReport,
} from './types';

// API Base URL constant connecting to the Python FastAPI backend
export const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:8000";

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

/**
 * Analyzes a Telegram account for suspicious logins, unexpected sessions, and security weaknesses.
 * TODO: real backend (POST /api/v1/telegram/analyze)
 */
export async function analyzeTelegram(phone: string, otp: string): Promise<TelegramScanResult> {
  await wait(1600);

  // In production with FastAPI:
  // const res = await fetch(`${API_BASE}/api/v1/telegram/analyze`, {
  //   method: 'POST',
  //   headers: { 'Content-Type': 'application/json' },
  //   body: JSON.stringify({ phone, otp }),
  // });
  // if (!res.ok) throw new Error('Failed to analyze Telegram account');
  // return await res.json();

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

/**
 * Compiles a comprehensive full investigation report across all scanned channels.
 * TODO: real backend (GET /api/v1/report)
 */
export async function getReport(): Promise<FullReport> {
  await wait(1200);

  // In production with FastAPI:
  // const res = await fetch(`${API_BASE}/api/v1/report`);
  // return await res.json();

  return {
    id: `REP-${Math.floor(100000 + Math.random() * 900000)}`,
    generatedAt: new Date().toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    }),
    overallScore: 78,
    overallRisk: 'critical',
    summary: 'High likelihood of account unauthorized access: an unknown device in Germany accessed Telegram, and a public code repository leaked credentials.',
    howItHappened: [
      "Step 1: Your GitHub repository accidentally published an API credential in settings.py.",
      "Step 2: Automated internet bots found this credential within minutes of publication.",
      "Step 3: An intruder in Frankfurt, Germany logged into your Telegram session using an intercepted verification code.",
      "Step 4: Because Two-Step Verification was not turned on, the intruder accessed your account without needing an extra password."
    ],
    actionPlan: [
      {
        id: 1,
        title: "Kick out unknown Telegram devices",
        detail: "Open Telegram > Settings > Devices > Tap 'Terminate all other sessions' to kick out the intruder in Germany.",
        completed: false,
      },
      {
        id: 2,
        title: "Turn on Telegram Two-Step Password",
        detail: "Go to Settings > Privacy and Security > Two-Step Verification. Set a strong password so SMS alone cannot access your account.",
        completed: false,
      },
      {
        id: 3,
        title: "Revoke the leaked Stripe secret key",
        detail: "Log in to your Stripe dashboard, roll the leaked key immediately, and check recent charges for fraudulent activity.",
        completed: false,
      },
      {
        id: 4,
        title: "Close exposed port 22 on your web server",
        detail: "Adjust your cloud firewall (AWS/DigitalOcean/Hetzner) to block public access to port 22 except from your personal IP address.",
        completed: false,
      }
    ],
    connectedAccounts: [
      { name: "Telegram Messenger", service: "Telegram", connectedAt: "Today at 10:14 PM", status: "Active (Critical Risk)" },
      { name: "my-project/api-backend", service: "GitHub", connectedAt: "Today at 09:30 PM", status: "Scanned (High Risk)" },
      { name: "185.220.101.5", service: "Network IP", connectedAt: "Today at 09:45 PM", status: "Tor Exit Node (Dangerous)" }
    ]
  };
}
