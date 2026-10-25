import {
  TelegramScanResult,
  RepoScanResult,
  IpCheckResult,
  LinkCheckResult,
  WebsiteCheckResult,
  NetworkScanResult,
  FullReport,
  User,
  AuthResponse,
  AdminOverview,
  UserDetail,
  ActivityLogItem,
} from './types';

export const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:8000";

export function getAuthToken(): string | null {
  return localStorage.getItem("abi_token");
}

export function setAuthToken(token: string | null): void {
  if (token) {
    localStorage.setItem("abi_token", token);
  } else {
    localStorage.removeItem("abi_token");
  }
}

export function getAuthHeaders(): Record<string, string> {
  const token = getAuthToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function handleResponse<T>(res: Response, defaultErrorMsg: string): Promise<T> {
  if (res.status === 401) {
    // If unauthorized, clear token
    if (res.url.includes('/api/auth/me')) {
      setAuthToken(null);
    }
    throw new Error("Authentication required. Please log in.");
  }
  if (res.status === 403) {
    throw new Error("Access forbidden: You do not have permission to perform this action.");
  }
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
  return (await res.json()) as T;
}

// ---------------------------------------------------------------------------
// Authentication API
// ---------------------------------------------------------------------------

export async function registerUser(name: string, email: string, password: string): Promise<AuthResponse> {
  const res = await fetch(`${API_BASE}/api/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, email, password }),
  });
  const data = await handleResponse<AuthResponse>(res, "Failed to register account.");
  setAuthToken(data.token);
  return data;
}

export async function loginUser(email: string, password: string): Promise<AuthResponse> {
  const res = await fetch(`${API_BASE}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  const data = await handleResponse<AuthResponse>(res, "Failed to log in.");
  setAuthToken(data.token);
  return data;
}

export async function getCurrentUser(): Promise<User> {
  const token = getAuthToken();
  if (!token) {
    throw new Error("No active session");
  }
  const res = await fetch(`${API_BASE}/api/auth/me`, {
    headers: { ...getAuthHeaders() },
  });
  return await handleResponse<User>(res, "Failed to fetch user profile.");
}

export async function logoutUser(): Promise<void> {
  try {
    await fetch(`${API_BASE}/api/auth/logout`, {
      method: "POST",
      headers: { ...getAuthHeaders() },
    });
  } catch {
    // Continue with client logout even if backend fails
  } finally {
    setAuthToken(null);
  }
}

export async function deleteMyAccount(): Promise<void> {
  const res = await fetch(`${API_BASE}/api/auth/me`, {
    method: "DELETE",
    headers: { ...getAuthHeaders() },
  });
  await handleResponse<{ success: boolean }>(res, "Failed to delete account.");
  setAuthToken(null);
}

// ---------------------------------------------------------------------------
// Telegram Logs Forensics API
// ---------------------------------------------------------------------------

export async function analyzeTelegramLogs(files: File[]): Promise<TelegramScanResult> {
  if (!files || files.length === 0) {
    throw new Error("Please select at least 1 file to analyze.");
  }
  if (files.length > 5) {
    throw new Error("Maximum 5 files allowed per upload.");
  }

  const formData = new FormData();
  for (const f of files) {
    formData.append("files", f);
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 60000); // 60s timeout

  try {
    const res = await fetch(`${API_BASE}/api/telegram/logs/analyze`, {
      method: "POST",
      headers: { ...getAuthHeaders() },
      body: formData,
      signal: controller.signal,
    });
    return await handleResponse<TelegramScanResult>(res, "Failed to analyze Telegram logs.");
  } catch (err: any) {
    if (err.name === 'AbortError') {
      throw new Error("Analysis timed out. Please try uploading a smaller export file.");
    }
    throw err;
  } finally {
    clearTimeout(timeoutId);
  }
}

// ---------------------------------------------------------------------------
// GitHub Repository Forensics API
// ---------------------------------------------------------------------------

export async function scanRepo(repoUrl: string): Promise<RepoScanResult> {
  const res = await fetch(`${API_BASE}/api/repo/scan`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...getAuthHeaders(),
    },
    body: JSON.stringify({ repoUrl }),
  });
  return await handleResponse<RepoScanResult>(res, "Failed to scan repository.");
}

// ---------------------------------------------------------------------------
// Network Threat Intelligence API
// ---------------------------------------------------------------------------

export async function checkIp(ip: string): Promise<IpCheckResult> {
  const res = await fetch(`${API_BASE}/api/network/ip`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...getAuthHeaders(),
    },
    body: JSON.stringify({ ip }),
  });
  return await handleResponse<IpCheckResult>(res, "Failed to inspect IP address.");
}

export async function checkLink(url: string): Promise<LinkCheckResult> {
  const res = await fetch(`${API_BASE}/api/network/link`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...getAuthHeaders(),
    },
    body: JSON.stringify({ url }),
  });
  return await handleResponse<LinkCheckResult>(res, "Failed to inspect web link.");
}

export async function checkWebsite(domain: string): Promise<WebsiteCheckResult> {
  const res = await fetch(`${API_BASE}/api/network/website`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...getAuthHeaders(),
    },
    body: JSON.stringify({ domain }),
  });
  return await handleResponse<WebsiteCheckResult>(res, "Failed to inspect website infrastructure.");
}

// ---------------------------------------------------------------------------
// Comprehensive Report Generation API
// ---------------------------------------------------------------------------

export async function getReport(
  paramsOrTelegram?: {
    telegram?: TelegramScanResult | null;
    repo?: RepoScanResult | null;
    network?: NetworkScanResult | null;
    demoModules?: string[];
  } | TelegramScanResult | null,
  repoResult?: RepoScanResult | null,
  networkResult?: NetworkScanResult | null,
  demoModules: string[] = []
): Promise<FullReport> {
  let tg: TelegramScanResult | null = null;
  let repo: RepoScanResult | null = null;
  let net: NetworkScanResult | null = null;
  let demos: string[] = [];

  if (
    paramsOrTelegram &&
    typeof paramsOrTelegram === 'object' &&
    ('telegram' in paramsOrTelegram ||
      'repo' in paramsOrTelegram ||
      'network' in paramsOrTelegram ||
      'demoModules' in paramsOrTelegram)
  ) {
    const p = paramsOrTelegram as any;
    tg = p.telegram || null;
    repo = p.repo || null;
    net = p.network || null;
    demos = p.demoModules || [];
  } else {
    tg = (paramsOrTelegram as TelegramScanResult) || null;
    repo = repoResult || null;
    net = networkResult || null;
    demos = demoModules || [];
  }

  const res = await fetch(`${API_BASE}/api/report/generate`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...getAuthHeaders(),
    },
    body: JSON.stringify({
      telegram: tg,
      repo: repo,
      network: net,
      demoModules: demos,
    }),
  });
  return await handleResponse<FullReport>(res, "Failed to generate security dossier.");
}

export async function logPdfDownload(): Promise<void> {
  try {
    await fetch(`${API_BASE}/api/report/log-download`, {
      method: "POST",
      headers: { ...getAuthHeaders() },
    });
  } catch {
    // Non-blocking telemetry
  }
}

// ---------------------------------------------------------------------------
// Admin Dashboard API
// ---------------------------------------------------------------------------

export async function getAdminOverview(): Promise<AdminOverview> {
  const res = await fetch(`${API_BASE}/api/admin/overview`, {
    headers: { ...getAuthHeaders() },
  });
  return await handleResponse<AdminOverview>(res, "Failed to load admin overview metrics.");
}

export async function getAdminUsers(params: {
  search?: string;
  role?: string;
  isActive?: boolean;
  page?: number;
  perPage?: number;
}): Promise<{ items: User[]; total: number; page: number; totalPages: number }> {
  const query = new URLSearchParams();
  if (params.search) query.set("search", params.search);
  if (params.role && params.role !== "all") query.set("role", params.role);
  if (params.isActive !== undefined) query.set("is_active", String(params.isActive));
  if (params.page) query.set("page", String(params.page));
  if (params.perPage) query.set("per_page", String(params.perPage));

  const res = await fetch(`${API_BASE}/api/admin/users?${query.toString()}`, {
    headers: { ...getAuthHeaders() },
  });
  return await handleResponse(res, "Failed to load users list.");
}

export async function getAdminUserDetail(userId: number): Promise<UserDetail> {
  const res = await fetch(`${API_BASE}/api/admin/users/${userId}`, {
    headers: { ...getAuthHeaders() },
  });
  return await handleResponse<UserDetail>(res, "Failed to load user details.");
}

export async function patchAdminUser(
  userId: number,
  patch: { isActive?: boolean; role?: string }
): Promise<{ success: boolean; user: Partial<User> }> {
  const res = await fetch(`${API_BASE}/api/admin/users/${userId}`, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
      ...getAuthHeaders(),
    },
    body: JSON.stringify(patch),
  });
  return await handleResponse(res, "Failed to update user.");
}

export async function deleteAdminUser(userId: number): Promise<{ success: boolean }> {
  const res = await fetch(`${API_BASE}/api/admin/users/${userId}`, {
    method: "DELETE",
    headers: { ...getAuthHeaders() },
  });
  return await handleResponse(res, "Failed to delete user.");
}

export async function getAdminActivity(params?: {
  userId?: number;
  action?: string;
  limit?: number;
  offset?: number;
}): Promise<{ items: ActivityLogItem[]; total: number }> {
  const query = new URLSearchParams();
  if (params?.userId) query.set("user_id", String(params.userId));
  if (params?.action && params.action !== "all") query.set("action", params.action);
  if (params?.limit) query.set("limit", String(params.limit));
  if (params?.offset) query.set("offset", String(params.offset));

  const res = await fetch(`${API_BASE}/api/admin/activity?${query.toString()}`, {
    headers: { ...getAuthHeaders() },
  });
  return await handleResponse(res, "Failed to load activity logs.");
}

export async function downloadUsersCsv(): Promise<void> {
  const res = await fetch(`${API_BASE}/api/admin/export/users.csv`, {
    headers: { ...getAuthHeaders() },
  });
  if (!res.ok) {
    throw new Error("Failed to export users CSV.");
  }
  const blob = await res.blob();
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `users_export_${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  window.URL.revokeObjectURL(url);
}

// ---------------------------------------------------------------------------
// Demo Incident Data (Available ONLY via explicit "Load demo data" button)
// ---------------------------------------------------------------------------

export const sampleIncident: {
  telegram: TelegramScanResult;
  repo: RepoScanResult;
  network: NetworkScanResult;
} = {
  telegram: {
    phone: "Demo Account",
    accountName: "Simulated Alex Rivera",
    riskScore: 78,
    riskLevel: "high",
    summary: "Simulated Demo: Account compromised via session hijacking from unfamiliar geography.",
    twoFactorEnabled: null,
    sessions: [
      {
        id: "demo-sess-1",
        device: "Chrome 122 on Windows 11",
        app: "Telegram Desktop",
        ip: "103.21.244.0",
        country: "India",
        lastActive: "Active now",
        isSuspicious: false,
        isCurrent: true,
      },
      {
        id: "demo-sess-2",
        device: "Ubuntu Workstation",
        app: "TelePlus Unofficial",
        ip: "185.220.101.5",
        country: "Germany",
        lastActive: "12 minutes ago",
        isSuspicious: true,
        flagNote: "Suspicious unofficial client and foreign hosting provider",
      },
    ],
    findings: [
      {
        id: "demo-f-1",
        type: "unofficial_app",
        title: "Unofficial Telegram Client Detected (TelePlus)",
        explanation: "Simulated finding: An active session connects using an unauthorized client app.",
        risk: "high",
        date: "Today at 02:40 PM",
      },
      {
        id: "demo-f-2",
        type: "impossible_travel",
        title: "Impossible Travel Anomaly",
        explanation: "Simulated finding: Simultaneous sessions observed across different continents.",
        risk: "critical",
        date: "Today at 02:40 PM",
      },
    ],
    howItHappened: "A malicious session was authorized from an unverified client app via OTP interception.",
    actionChecklist: [
      "Terminate all other active sessions in Settings > Devices (demo).",
      "Enable Two-Step Verification with a strong passphrase (demo).",
    ],
    timestamp: new Date().toISOString(),
    isDemo: true,
    dataCoverage: "Simulated demonstration dataset.",
    manualChecks: [
      "Turn on Two-Step Verification (Settings > Privacy and Security > Two-Step Verification).",
      "Add a recovery email address.",
      "Review Active Sessions periodically in Settings > Devices.",
    ],
  },
  repo: {
    repoUrl: "https://github.com/example/demo-vulnerable-repo",
    repoName: "example/demo-vulnerable-repo",
    riskScore: 72,
    riskLevel: "high",
    summary: "Simulated Demo: Hardcoded AWS credential discovered in config.py.",
    counts: { critical: 1, high: 0, medium: 1, low: 0, total: 2 },
    findings: [
      {
        id: "demo-repo-1",
        category: "secrets",
        severity: "critical",
        title: "AWS Access Key ID Leaked",
        filePath: "config.py",
        lineNumber: 14,
        explanation: "Simulated secret finding: AKIA**************** exposed in source code.",
        suggestedFix: "Revoke AWS IAM key immediately and use environment variables.",
        codeSnippet: "AWS_ACCESS_KEY_ID = 'AKIA****************'",
      },
    ],
    timestamp: new Date().toISOString(),
    branch: "main",
    scannedFilesCount: 24,
    isDemo: true,
  },
  network: {
    ipResult: {
      ip: "185.220.101.5",
      country: "Germany",
      city: "Frankfurt",
      isp: "Hosting GmbH",
      asn: "AS12345",
      isVpn: true,
      isProxy: false,
      isTor: true,
      isHosting: true,
      abuseScore: 88,
      verdict: "Dangerous",
      riskLevel: "critical",
      explanation: "Simulated Tor exit node with elevated attack reports.",
      timestamp: new Date().toISOString(),
    },
    linkResult: {
      url: "https://phish-login-tele.example",
      domainAge: "2 days",
      dnsRecords: { a: ["185.220.101.5"], mx: [], txt: [] },
      sslValid: false,
      redirectChain: [],
      reputationScore: 12,
      verdict: "Dangerous",
      riskLevel: "high",
      explanation: "Simulated domain flagged as credential harvesting site.",
      timestamp: new Date().toISOString(),
    },
    websiteResult: {
      domain: "demo-vulnerable-site.local",
      ports: [
        { port: 22, service: "SSH", state: "Open", risk: "medium", note: "SSH port open" },
        { port: 3389, service: "RDP", state: "Open", risk: "high", note: "RDP exposed to public Internet" },
      ],
      sslExpiry: "Expired 4 days ago",
      sslDaysRemaining: -4,
      securityHeaders: [
        { header: "Strict-Transport-Security", status: "Fail", description: "Missing HSTS" },
      ],
      riskScore: 65,
      riskLevel: "high",
      verdict: "Dangerous",
      explanation: "Simulated server with exposed management ports and missing security headers.",
      timestamp: new Date().toISOString(),
    },
  },
};
