export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

export interface TelegramSession {
  id: string;
  device: string;
  app: string;
  ip: string;
  country: string;
  lastActive: string;
  isSuspicious: boolean;
  isCurrent?: boolean;
  flagNote?: string;
}

export type TelegramFindingType =
  | 'unknown_device'
  | 'foreign_login'
  | 'impossible_travel'
  | 'no_2fa'
  | 'suspicious_link';

export interface TelegramFinding {
  id: string;
  type: TelegramFindingType;
  title: string;
  explanation: string;
  risk: RiskLevel;
  date?: string;
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
  twoFactorEnabled: boolean;
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

export interface FullReport {
  id: string;
  generatedAt: string;
  overallScore: number;
  overallRisk: RiskLevel;
  summary: string;
  telegram?: TelegramScanResult;
  repo?: RepoScanResult;
  network?: NetworkScanResult;
  howItHappened: string[];
  actionPlan: {
    id: number;
    title: string;
    detail: string;
    completed?: boolean;
  }[];
  connectedAccounts: {
    name: string;
    service: string;
    connectedAt: string;
    status: string;
  }[];
}

export interface ToastNotification {
  id: string;
  type: 'success' | 'error' | 'info' | 'warning';
  title: string;
  message?: string;
}
