export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

export interface TelegramSession {
  id: string;
  device: string;
  app: string;
  platform?: string;
  ip: string;
  country: string;
  region?: string;
  createdAt?: string;
  lastActive: string;
  isSuspicious: boolean;
  isCurrent?: boolean;
  flagNote?: string;
}

export type TelegramFindingType = string;

export interface TelegramFinding {
  id: string;
  type: TelegramFindingType;
  title: string;
  explanation: string;
  risk: RiskLevel;
  date?: string;
}

export interface DetectedFilesInfo {
  sessions: boolean;
  loginAlerts: boolean;
  ignoredNonServiceChats: number;
  fileDetails: string[];
}

export interface TelegramScanResult {
  phone: string;
  accountName: string;
  riskScore: number; // 0 - 100
  riskLevel: RiskLevel;
  summary: string;
  sessions: TelegramSession[];
  findings: TelegramFinding[];
  howItHappened: string;
  actionChecklist: string[];
  timestamp: string;
  twoFactorEnabled?: boolean | null;
  detectedFiles?: DetectedFilesInfo;
  dataCoverage?: string;
  manualChecks?: string[];
  isDemo?: boolean;
}

export type RepoFindingCategory = 'secrets' | 'dependencies' | 'code' | 'network';

export interface RepoFinding {
  id: string;
  category: RepoFindingCategory;
  severity: RiskLevel;
  title: string;
  filePath: string;
  lineNumber: number;
  explanation: string;
  suggestedFix: string;
  codeSnippet?: string;
}

export interface RepoScanResult {
  repoUrl: string;
  repoName: string;
  riskScore: number;
  riskLevel: RiskLevel;
  summary: string;
  counts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
  findings: RepoFinding[];
  timestamp: string;
  branch: string;
  scannedFilesCount: number;
  isDemo?: boolean;
}

export interface IpCheckResult {
  ip: string;
  country: string;
  city: string;
  isp: string;
  asn: string;
  isVpn: boolean;
  isProxy: boolean;
  isTor: boolean;
  isHosting?: boolean;
  abuseScore: number; // 0 - 100
  verdict: 'Safe' | 'Suspicious' | 'Dangerous';
  riskLevel: RiskLevel;
  explanation: string;
  timestamp: string;
}

export interface RedirectHop {
  step: number;
  url: string;
  status: number;
  note?: string;
}

export interface LinkCheckResult {
  url: string;
  domainAge: string;
  dnsRecords: {
    a: string[];
    mx: string[];
    txt: string[];
  };
  sslValid: boolean;
  sslIssuer?: string;
  redirectChain: RedirectHop[];
  reputationScore: number; // 0 - 100 (100 is cleanest)
  verdict: 'Safe' | 'Suspicious' | 'Dangerous';
  riskLevel: RiskLevel;
  explanation: string;
  timestamp: string;
}

export interface PortCheck {
  port: number;
  service: string;
  state: 'Open' | 'Closed' | 'Filtered';
  risk: RiskLevel;
  note: string;
}

export interface SecurityHeaderCheck {
  header: string;
  status: 'Pass' | 'Fail';
  description: string;
}

export interface WebsiteCheckResult {
  domain: string;
  ports: PortCheck[];
  sslExpiry: string;
  sslDaysRemaining: number;
  securityHeaders: SecurityHeaderCheck[];
  riskScore: number;
  riskLevel: RiskLevel;
  verdict: 'Safe' | 'Suspicious' | 'Dangerous';
  explanation: string;
  timestamp: string;
}

export interface NetworkScanResult {
  ipResult?: IpCheckResult;
  linkResult?: LinkCheckResult;
  websiteResult?: WebsiteCheckResult;
}

export interface RecentScan {
  id: string;
  date: string;
  type: 'Telegram' | 'Repository' | 'Network IP' | 'Network Link' | 'Network Website';
  target: string;
  riskLevel: RiskLevel;
  score: number;
  status: 'Completed' | 'Alert' | 'Secure';
}

export interface ModuleScore {
  module: string;
  name: string;
  scanned: boolean;
  score?: number | null;
  riskLevel?: RiskLevel | null;
  isDemo?: boolean;
  details?: string;
}

export interface NetworkFindingItem {
  id: string;
  source: string;
  title: string;
  detail: string;
  severity: RiskLevel;
  target?: string;
}

export interface ActionPlanItem {
  id: number;
  title: string;
  detail: string;
  priority?: RiskLevel;
  completed?: boolean;
}

export interface FullReport {
  id: string;
  generatedAt: string;
  overallScore: number | null;
  overallRisk: RiskLevel | null;
  summary: string;
  telegram?: TelegramScanResult;
  repo?: RepoScanResult;
  network?: NetworkScanResult;
  howItHappened: string[];
  actionPlan: ActionPlanItem[];
  whatToDoNow?: ActionPlanItem[];
  modules?: ModuleScore[];
  networkFindings?: NetworkFindingItem[];
  limitations?: string[];
  methodology?: string;
  demoModules?: string[];
  connectedAccounts: {
    name: string;
    service: string;
    connectedAt: string;
    status: string;
    isDemo?: boolean;
  }[];
}

export interface ToastNotification {
  id: string;
  type: 'success' | 'error' | 'info' | 'warning';
  title: string;
  message?: string;
}

// User & Auth Types
export interface User {
  id: number;
  name: string;
  email: string;
  role: 'user' | 'admin';
  isActive: boolean;
  createdAt: string;
  lastLoginAt?: string | null;
  scanCount?: number;
}

export interface AuthResponse {
  token: string;
  user: User;
}

// Admin Types
export interface AdminOverview {
  totalUsers: number;
  newUsers7d: number;
  totalScans: number;
  realScans: number;
  demoScans: number;
  averageRisk: number;
  scansPerModule: {
    telegram: number;
    repo: number;
    network: number;
  };
  riskDistribution: {
    low: number;
    medium: number;
    high: number;
    critical: number;
  };
  scansPerDay: { date: string; count: number }[];
}

export interface ActivityLogItem {
  id: number;
  userId?: number | null;
  action: string;
  detail?: string | null;
  createdAt: string;
}

export interface UserDetail {
  profile: User;
  scans: {
    id: number;
    module: string;
    targetLabel: string;
    riskScore: number;
    riskLevel: RiskLevel;
    isDemo: boolean;
    createdAt: string;
    findingsSummary: string;
  }[];
  reports: {
    id: number;
    overallScore: number;
    overallRisk: RiskLevel;
    createdAt: string;
  }[];
  activity: ActivityLogItem[];
}
