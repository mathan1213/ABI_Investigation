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
  RegisterResult,
  ResendWelcomeEmailResult,
  CheckUsernameResult,
  AuditLogItem,
  EligibleUser,
  AdminOverview,
  UserDetail,
  ActivityLogItem,
  UploadedFileItem,
  AdminReportItem,
} from './types';

export const API_BASE = import.meta.env.VITE_API_BASE || "";

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
    // If unauthorized on /api/auth/me, clear token
    if (res.url.includes('/api/auth/me')) {
      setAuthToken(null);
    }
    try {
      const errorData = await res.json();
      if (errorData?.detail) {
        throw new Error(typeof errorData.detail === 'string' ? errorData.detail : defaultErrorMsg);
      }
    } catch (e: any) {
      if (e?.message && e.message !== 'Unexpected end of JSON input') throw e;
    }
    throw new Error("Authentication required. Please log in.");
  }
  if (res.status === 403) {
    try {
      const errorData = await res.json();
      if (errorData?.detail) {
        throw new Error(typeof errorData.detail === 'string' ? errorData.detail : defaultErrorMsg);
      }
    } catch (e: any) {
      if (e?.message && e.message !== 'Unexpected end of JSON input') throw e;
    }
    throw new Error("Access forbidden: You do not have permission to perform this action.");
  }
  if (res.status === 429) {
    try {
      const errorData = await res.json();
      if (errorData?.detail) {
        throw new Error(typeof errorData.detail === 'string' ? errorData.detail : defaultErrorMsg);
      }
    } catch (e: any) {
      if (e?.message && e.message !== 'Unexpected end of JSON input') throw e;
    }
    throw new Error("Too many requests, please wait a minute.");
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
// Authentication & Username API
// ---------------------------------------------------------------------------

export async function checkUsername(username: string): Promise<CheckUsernameResult> {
  const res = await fetch(`${API_BASE}/api/auth/check-username?username=${encodeURIComponent(username)}`);
  return await handleResponse<CheckUsernameResult>(res, "Failed to verify username availability.");
}

export async function registerUser(
  name: string,
  username: string,
  email: string,
  password: string,
  confirmPassword?: string,
  consent: boolean = true
): Promise<RegisterResult> {
  const res = await fetch(`${API_BASE}/api/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      name,
      username,
      email,
      password,
      confirm_password: confirmPassword,
      confirmPassword,
      consent,
    }),
  });
  return await handleResponse<RegisterResult>(res, "Failed to register account.");
}

export async function resendWelcomeEmail(
  email: string
): Promise<ResendWelcomeEmailResult> {
  const res = await fetch(`${API_BASE}/api/auth/resend-welcome-email`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
  });
  return await handleResponse<ResendWelcomeEmailResult>(res, "Failed to resend welcome email.");
}

export async function loginUser(identifier: string, password: string): Promise<AuthResponse> {
  const res = await fetch(`${API_BASE}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ identifier, password }),
  });
  const data = await handleResponse<AuthResponse>(res, "Failed to sign in.");
  setAuthToken(data.token);
  return data;
}

export async function adminLogin(identifier: string, password: string): Promise<AuthResponse> {
  const res = await fetch(`${API_BASE}/api/admin/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ identifier, password }),
  });
  const data = await handleResponse<AuthResponse>(res, "Administrative sign in failed.");
  setAuthToken(data.token);
  return data;
}

export async function forgotPassword(email: string): Promise<{ success: boolean; message: string }> {
  const res = await fetch(`${API_BASE}/api/auth/forgot-password`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
  });
  return await handleResponse(res, "Failed to process forgot password request.");
}

export async function resetPassword(email: string, newPassword: string): Promise<{ success: boolean; message: string }> {
  const res = await fetch(`${API_BASE}/api/auth/reset-password`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, newPassword }),
  });
  return await handleResponse(res, "Failed to reset password.");
}

export async function updateUsername(username: string): Promise<User> {
  const res = await fetch(`${API_BASE}/api/auth/username`, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
      ...getAuthHeaders(),
    },
    body: JSON.stringify({ username }),
  });
  return await handleResponse<User>(res, "Failed to update username.");
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
// Super Admin API
// ---------------------------------------------------------------------------

export async function getSuperAdminAdmins(): Promise<{ items: User[]; availablePermissions: string[] }> {
  const res = await fetch(`${API_BASE}/api/superadmin/admins`, {
    headers: { ...getAuthHeaders() },
  });
  return await handleResponse(res, "Failed to load administrators list.");
}

export async function getEligibleUsers(search?: string): Promise<EligibleUser[]> {
  const query = search ? `?search=${encodeURIComponent(search)}` : "";
  const res = await fetch(`${API_BASE}/api/superadmin/eligible-users${query}`, {
    headers: { ...getAuthHeaders() },
  });
  return await handleResponse(res, "Failed to load eligible users.");
}

export async function createSuperAdminAdmin(data: {
  userId?: number;
  email?: string;
  permissions: string[];
}): Promise<{ success: boolean; message: string; admin: User }> {
  const res = await fetch(`${API_BASE}/api/superadmin/admins`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...getAuthHeaders(),
    },
    body: JSON.stringify(data),
  });
  return await handleResponse(res, "Failed to create administrator.");
}

export async function updateAdminPermissions(
  adminId: number,
  permissions: string[]
): Promise<{ success: boolean; message: string; permissions: string[] }> {
  const res = await fetch(`${API_BASE}/api/superadmin/admins/${adminId}/permissions`, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
      ...getAuthHeaders(),
    },
    body: JSON.stringify({ permissions }),
  });
  return await handleResponse(res, "Failed to update administrator permissions.");
}

export async function updateUserRole(
  userId: number,
  role: string,
  permissions?: string[]
): Promise<{ success: boolean; message: string; user: Partial<User> }> {
  const res = await fetch(`${API_BASE}/api/superadmin/users/${userId}/role`, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
      ...getAuthHeaders(),
    },
    body: JSON.stringify({ role, permissions }),
  });
  return await handleResponse(res, "Failed to update user role.");
}

export async function removeAdmin(adminId: number): Promise<{ success: boolean; message: string }> {
  const res = await fetch(`${API_BASE}/api/superadmin/admins/${adminId}`, {
    method: "DELETE",
    headers: { ...getAuthHeaders() },
  });
  return await handleResponse(res, "Failed to remove administrator.");
}

export async function getSuperAdminAuditLogs(params?: {
  page?: number;
  perPage?: number;
  action?: string;
}): Promise<{ items: AuditLogItem[]; total: number; page: number; totalPages: number }> {
  const query = new URLSearchParams();
  if (params?.page) query.set("page", String(params.page));
  if (params?.perPage) query.set("per_page", String(params.perPage));
  if (params?.action && params.action !== "all") query.set("action", params.action);

  const res = await fetch(`${API_BASE}/api/superadmin/audit?${query.toString()}`, {
    headers: { ...getAuthHeaders() },
  });
  return await handleResponse(res, "Failed to load audit logs.");
}

export async function getAdminFiles(params?: {
  search?: string;
  userId?: number;
  page?: number;
  perPage?: number;
}): Promise<{ items: UploadedFileItem[]; total: number; page: number; perPage: number; totalPages?: number }> {
  const query = new URLSearchParams();
  if (params?.search) query.append("search", params.search);
  if (params?.userId) query.append("user_id", String(params.userId));
  if (params?.page) query.append("page", String(params.page));
  if (params?.perPage) query.append("per_page", String(params.perPage));

  const res = await fetch(`${API_BASE}/api/admin/files?${query.toString()}`, {
    headers: { ...getAuthHeaders() },
  });
  return await handleResponse(res, "Failed to load uploaded files.");
}

export async function getAdminReports(params?: {
  search?: string;
  userId?: number;
  page?: number;
  perPage?: number;
}): Promise<{ items: AdminReportItem[]; total: number; page: number; perPage: number; totalPages?: number }> {
  const query = new URLSearchParams();
  if (params?.search) query.append("search", params.search);
  if (params?.userId) query.append("user_id", String(params.userId));
  if (params?.page) query.append("page", String(params.page));
  if (params?.perPage) query.append("per_page", String(params.perPage));

  const res = await fetch(`${API_BASE}/api/admin/reports?${query.toString()}`, {
    headers: { ...getAuthHeaders() },
  });
  return await handleResponse(res, "Failed to load reports.");
}


