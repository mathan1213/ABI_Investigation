import React, { createContext, useContext, useState, useEffect, useMemo } from 'react';
import {
  TelegramScanResult,
  RepoScanResult,
  NetworkScanResult,
  IpCheckResult,
  LinkCheckResult,
  WebsiteCheckResult,
  RecentScan,
  RiskLevel,
  ToastNotification,
} from '../lib/types';
import {
  analyzeTelegram,
  scanRepo,
  checkIp,
  checkLink,
  checkWebsite,
} from '../lib/api';

interface ScanContextType {
  telegramScan: TelegramScanResult | null;
  repoScan: RepoScanResult | null;
  networkScan: NetworkScanResult;
  recentScans: RecentScan[];
  overallScore: number | null;
  overallRisk: RiskLevel | null;
  hasAnyScan: boolean;
  demoModules: string[];
  toasts: ToastNotification[];
  setTelegramScan: (scan: TelegramScanResult | null) => void;
  setRepoScan: (scan: RepoScanResult) => void;
  setIpScan: (res: IpCheckResult) => void;
  setLinkScan: (res: LinkCheckResult) => void;
  setWebsiteScan: (res: WebsiteCheckResult) => void;
  clearAllScans: () => void;
  loadSampleData: () => void;
  addToast: (toast: Omit<ToastNotification, 'id'>) => void;
  removeToast: (id: string) => void;
}

const ScanContext = createContext<ScanContextType | undefined>(undefined);

const INITIAL_RECENT_SCANS: RecentScan[] = [
  {
    id: 'sc-1',
    date: '10 mins ago',
    type: 'Telegram',
    target: '+1 (555) 019-2834',
    riskLevel: 'critical',
    score: 78,
    status: 'Alert',
  },
  {
    id: 'sc-2',
    date: '2 hours ago',
    type: 'Repository',
    target: 'github.com/my-project/api-backend',
    riskLevel: 'high',
    score: 72,
    status: 'Alert',
  },
  {
    id: 'sc-3',
    date: 'Yesterday',
    type: 'Network IP',
    target: '185.220.101.5 (Frankfurt)',
    riskLevel: 'critical',
    score: 89,
    status: 'Alert',
  },
  {
    id: 'sc-4',
    date: '2 days ago',
    type: 'Network Link',
    target: 'https://security-verify-telegram.cc',
    riskLevel: 'critical',
    score: 86,
    status: 'Alert',
  },
  {
    id: 'sc-5',
    date: '3 days ago',
    type: 'Network Website',
    target: 'my-service-portal.io',
    riskLevel: 'medium',
    score: 65,
    status: 'Completed',
  }
];

export const ScanProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [telegramScan, setTelegramScanState] = useState<TelegramScanResult | null>(() => {
    const saved = localStorage.getItem('abi_tg_scan');
    return saved ? JSON.parse(saved) : null;
  });

  const [repoScan, setRepoScanState] = useState<RepoScanResult | null>(() => {
    const saved = localStorage.getItem('abi_repo_scan');
    return saved ? JSON.parse(saved) : null;
  });

  const [networkScan, setNetworkScanState] = useState<NetworkScanResult>(() => {
    const saved = localStorage.getItem('abi_net_scan');
    return saved ? JSON.parse(saved) : {};
  });

  const [demoModules, setDemoModules] = useState<string[]>(() => {
    const saved = localStorage.getItem('abi_demo_modules');
    return saved ? JSON.parse(saved) : [];
  });

  const [recentScans, setRecentScans] = useState<RecentScan[]>(() => {
    const saved = localStorage.getItem('abi_recent_scans');
    return saved ? JSON.parse(saved) : INITIAL_RECENT_SCANS;
  });

  const [toasts, setToasts] = useState<ToastNotification[]>([]);

  // Persist state to local storage safely
  useEffect(() => {
    if (telegramScan) {
      localStorage.setItem('abi_tg_scan', JSON.stringify(telegramScan));
    }
  }, [telegramScan]);

  useEffect(() => {
    if (repoScan) {
      localStorage.setItem('abi_repo_scan', JSON.stringify(repoScan));
    }
  }, [repoScan]);

  useEffect(() => {
    if (Object.keys(networkScan).length > 0) {
      localStorage.setItem('abi_net_scan', JSON.stringify(networkScan));
    }
  }, [networkScan]);

  useEffect(() => {
    localStorage.setItem('abi_recent_scans', JSON.stringify(recentScans));
  }, [recentScans]);

  useEffect(() => {
    localStorage.setItem('abi_demo_modules', JSON.stringify(demoModules));
  }, [demoModules]);

  const addToast = (toast: Omit<ToastNotification, 'id'>) => {
    const id = `toast-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const newToast = { ...toast, id };
    setToasts((prev) => [...prev, newToast]);
    setTimeout(() => {
      removeToast(id);
    }, 4500);
  };

  const removeToast = (id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  };

  const setTelegramScan = (scan: TelegramScanResult | null) => {
    setTelegramScanState(scan);
    if (!scan) {
      localStorage.removeItem('abi_tg_scan');
      setDemoModules((prev) => prev.filter((m) => m !== 'telegram'));
      return;
    }
    if (scan.isDemo) {
      setDemoModules((prev) => Array.from(new Set([...prev, 'telegram'])));
    } else {
      setDemoModules((prev) => prev.filter((m) => m !== 'telegram'));
    }
    addRecentScan({
      id: `sc-${Date.now()}`,
      date: 'Just now',
      type: 'Telegram',
      target: scan.phone,
      riskLevel: scan.riskLevel,
      score: scan.riskScore,
      status: scan.riskScore > 50 ? 'Alert' : 'Secure',
    });
    addToast({
      type: scan.riskLevel === 'critical' || scan.riskLevel === 'high' ? 'warning' : 'success',
      title: 'Telegram Analysis Complete',
      message: scan.summary,
    });
  };

  const setRepoScan = (scan: RepoScanResult) => {
    setRepoScanState(scan);
    setDemoModules((prev) => prev.filter((m) => m !== 'repo'));
    addRecentScan({
      id: `sc-${Date.now()}`,
      date: 'Just now',
      type: 'Repository',
      target: scan.repoName,
      riskLevel: scan.riskLevel,
      score: scan.riskScore,
      status: scan.riskScore > 50 ? 'Alert' : 'Secure',
    });
    addToast({
      type: scan.riskLevel === 'critical' || scan.riskLevel === 'high' ? 'warning' : 'success',
      title: 'Repository Scan Complete',
      message: `Found ${scan.counts.total} security findings in ${scan.repoName}`,
    });
  };

  const setIpScan = (res: IpCheckResult) => {
    setNetworkScanState((prev) => ({ ...prev, ipResult: res }));
    setDemoModules((prev) => prev.filter((m) => m !== 'network'));
    addRecentScan({
      id: `sc-${Date.now()}`,
      date: 'Just now',
      type: 'Network IP',
      target: `${res.ip} (${res.country})`,
      riskLevel: res.riskLevel,
      score: res.abuseScore,
      status: res.verdict === 'Dangerous' ? 'Alert' : 'Secure',
    });
    addToast({
      type: res.verdict === 'Dangerous' ? 'error' : res.verdict === 'Suspicious' ? 'warning' : 'success',
      title: 'IP Reputation Check Complete',
      message: `${res.ip} verdict: ${res.verdict}`,
    });
  };

  const setLinkScan = (res: LinkCheckResult) => {
    setNetworkScanState((prev) => ({ ...prev, linkResult: res }));
    setDemoModules((prev) => prev.filter((m) => m !== 'network'));
    addRecentScan({
      id: `sc-${Date.now()}`,
      date: 'Just now',
      type: 'Network Link',
      target: res.url.replace(/^https?:\/\//i, '').slice(0, 30),
      riskLevel: res.riskLevel,
      score: 100 - res.reputationScore,
      status: res.verdict === 'Dangerous' ? 'Alert' : 'Secure',
    });
    addToast({
      type: res.verdict === 'Dangerous' ? 'error' : res.verdict === 'Suspicious' ? 'warning' : 'success',
      title: 'Link Safety Check Complete',
      message: `Link verdict: ${res.verdict}`,
    });
  };

  const setWebsiteScan = (res: WebsiteCheckResult) => {
    setNetworkScanState((prev) => ({ ...prev, websiteResult: res }));
    setDemoModules((prev) => prev.filter((m) => m !== 'network'));
    addRecentScan({
      id: `sc-${Date.now()}`,
      date: 'Just now',
      type: 'Network Website',
      target: res.domain,
      riskLevel: res.riskLevel,
      score: res.riskScore,
      status: res.riskScore > 50 ? 'Alert' : 'Secure',
    });
    addToast({
      type: res.verdict === 'Dangerous' ? 'error' : res.verdict === 'Suspicious' ? 'warning' : 'success',
      title: 'Website Security Check Complete',
      message: `${res.domain} verdict: ${res.verdict}`,
    });
  };

  const addRecentScan = (scan: RecentScan) => {
    setRecentScans((prev) => [scan, ...prev.slice(0, 7)]);
  };

  const clearAllScans = () => {
    setTelegramScanState(null);
    setRepoScanState(null);
    setNetworkScanState({});
    setDemoModules([]);
    localStorage.removeItem('abi_tg_scan');
    localStorage.removeItem('abi_repo_scan');
    localStorage.removeItem('abi_net_scan');
    localStorage.removeItem('abi_demo_modules');
    addToast({
      type: 'info',
      title: 'Session Scans Cleared',
      message: 'All your temporary scan records have been deleted.',
    });
  };

  const loadSampleData = () => {
    const sampleTg: TelegramScanResult = {
      phone: '+1 (555) 019-2834',
      accountName: 'Alex Rivera (@arivera)',
      riskScore: 78,
      riskLevel: 'critical',
      summary: 'Someone logged into your Telegram account from another country without your permission, and your account lacks two-step password protection.',
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
        },
      ],
      findings: [
        {
          id: 'tg-1',
          type: 'unknown_device',
          title: 'Unknown Computer Logged In',
          explanation: 'A computer running Linux in Frankfurt, Germany logged into your account 42 minutes ago.',
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
          explanation: 'Your account was used in California and Amsterdam just 20 minutes apart.',
          risk: 'critical',
          date: 'Yesterday',
        },
        {
          id: 'tg-4',
          type: 'no_2fa',
          title: 'Two-Step Verification is Turned Off',
          explanation: 'Your account is only guarded by SMS text codes.',
          risk: 'high',
        },
        {
          id: 'tg-5',
          type: 'suspicious_link',
          title: 'Suspicious Bot Authorization Found',
          explanation: 'An external automation bot with broad message-reading permissions was linked to your profile.',
          risk: 'medium',
        },
      ],
      howItHappened: 'An unfamiliar session was authorized from Germany and the Netherlands, which is consistent with someone accessing your account without secondary verification.',
      actionChecklist: [
        "Open Telegram Settings > Devices > Tap 'Terminate all other sessions' immediately.",
        'Turn on Two-Step Verification and add a recovery email.',
      ],
    };

    const sampleRepo: RepoScanResult = {
      repoUrl: 'https://github.com/my-project/api-backend',
      repoName: 'my-project/api-backend',
      riskScore: 85,
      riskLevel: 'critical',
      summary: "We discovered 3 security issues across 42 scanned files in 'my-project/api-backend', including live API secret keys and an insecure HTTP connection.",
      branch: 'main',
      scannedFilesCount: 42,
      timestamp: new Date().toISOString(),
      counts: {
        critical: 1,
        high: 1,
        medium: 1,
        low: 0,
        total: 3,
      },
      findings: [
        {
          id: 'rf-1',
          category: 'secrets',
          severity: 'critical',
          title: 'Live AWS Access Key ID Exposed',
          filePath: 'config/aws.py',
          lineNumber: 14,
          explanation: 'Exposed AWS credentials allow external parties to query connected cloud services.',
          suggestedFix: 'Immediately revoke the access key in AWS IAM and use environment variables.',
          codeSnippet: 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"',
        },
        {
          id: 'rf-2',
          category: 'secrets',
          severity: 'high',
          title: 'Hardcoded Production Database Password',
          filePath: 'docker-compose.yml',
          lineNumber: 22,
          explanation: 'Database password stored in version control plaintext.',
          suggestedFix: 'Remove password and inject via environment file.',
          codeSnippet: 'POSTGRES_PASSWORD=super_secret_db_pass',
        },
        {
          id: 'rf-3',
          category: 'network',
          severity: 'medium',
          title: 'Insecure Unencrypted HTTP Connection',
          filePath: 'src/services/api.ts',
          lineNumber: 8,
          explanation: 'The application connects to an unencrypted HTTP URL over plaintext.',
          suggestedFix: 'Switch address to secure HTTPS (https://).',
          codeSnippet: 'const ENDPOINT = "http://api.internal-dev.net";',
        },
      ],
    };

    const sampleIp: IpCheckResult = {
      ip: '185.220.101.5',
      country: 'Germany',
      city: 'Frankfurt am Main',
      isp: 'Tor Relay Network Services',
      asn: 'AS208323',
      isVpn: false,
      isProxy: false,
      isTor: true,
      isHosting: true,
      abuseScore: 85,
      verdict: 'Dangerous',
      riskLevel: 'critical',
      explanation: 'This IP address is a verified active Tor exit node frequently associated with automated scanning and anonymized proxy connections.',
      timestamp: new Date().toISOString(),
    };

    const sampleLink: LinkCheckResult = {
      url: 'https://security-verify-telegram.cc',
      domainAge: '3 days old',
      dnsRecords: {
        a: ['104.21.45.19'],
        mx: [],
        txt: [],
      },
      sslValid: true,
      sslIssuer: "Let's Encrypt",
      redirectChain: [
        { step: 1, url: 'https://security-verify-telegram.cc', status: 301 },
        { step: 2, url: 'https://auth-telegram-session.top', status: 200 },
      ],
      reputationScore: 14,
      verdict: 'Dangerous',
      riskLevel: 'critical',
      explanation: 'This domain was registered only 3 days ago, redirects across suspicious foreign domains, and mimics an official verification service.',
      timestamp: new Date().toISOString(),
    };

    const sampleWeb: WebsiteCheckResult = {
      domain: 'portal.example-cloud.io',
      ports: [
        {
          port: 22,
          service: 'SSH Remote Administration',
          state: 'Open',
          risk: 'high',
          note: 'Public administration port is accepting external TCP connections.',
        },
        {
          port: 443,
          service: 'HTTPS Web Portal',
          state: 'Open',
          risk: 'low',
          note: 'Standard secure web port.',
        },
      ],
      sslExpiry: 'Valid (45 days remaining)',
      sslDaysRemaining: 45,
      securityHeaders: [
        { header: 'Strict-Transport-Security (HSTS)', status: 'Fail', description: 'Missing HSTS header' },
        { header: 'Content-Security-Policy (CSP)', status: 'Fail', description: 'Missing CSP header' },
        { header: 'X-Frame-Options', status: 'Pass', description: 'Configured properly' },
        { header: 'X-Content-Type-Options', status: 'Pass', description: 'Configured properly' },
        { header: 'Referrer-Policy', status: 'Pass', description: 'Configured properly' },
      ],
      riskScore: 60,
      riskLevel: 'high',
      verdict: 'Suspicious',
      explanation: 'Public SSH port is exposed to the internet, and 2 critical security headers are missing.',
      timestamp: new Date().toISOString(),
    };

    setTelegramScanState(sampleTg);
    setRepoScanState(sampleRepo);
    setNetworkScanState({
      ipResult: sampleIp,
      linkResult: sampleLink,
      websiteResult: sampleWeb,
    });
    setDemoModules(['telegram', 'repo', 'network']);

    addToast({
      type: 'warning',
      title: 'Demo Incident Data Loaded',
      message: 'Loaded simulated demo data across Telegram, Repository, and Network (excluded from real score).',
    });
  };

  const hasAnyScan = Boolean(
    telegramScan || repoScan || networkScan.ipResult || networkScan.linkResult || networkScan.websiteResult
  );

  // Compute overall score dynamically from REAL modules only
  const { overallScore, overallRisk } = useMemo<{
    overallScore: number | null;
    overallRisk: RiskLevel | null;
  }>(() => {
    const realModuleScores: number[] = [];
    let hasRealCriticalFinding = false;

    if (telegramScan && !demoModules.includes('telegram')) {
      realModuleScores.push(telegramScan.riskScore);
      if (telegramScan.findings?.some((f) => f.risk === 'critical')) {
        hasRealCriticalFinding = true;
      }
    }

    if (repoScan && !demoModules.includes('repo')) {
      realModuleScores.push(repoScan.riskScore);
      if ((repoScan.counts?.critical ?? 0) > 0 || repoScan.findings?.some((f) => f.severity === 'critical')) {
        hasRealCriticalFinding = true;
      }
    }

    if (!demoModules.includes('network')) {
      const netScores: number[] = [];
      if (networkScan.ipResult) {
        netScores.push(networkScan.ipResult.abuseScore);
        if (networkScan.ipResult.riskLevel === 'critical') hasRealCriticalFinding = true;
      }
      if (networkScan.linkResult) {
        netScores.push(100 - networkScan.linkResult.reputationScore);
        if (networkScan.linkResult.riskLevel === 'critical') hasRealCriticalFinding = true;
      }
      if (networkScan.websiteResult) {
        netScores.push(networkScan.websiteResult.riskScore);
        if (networkScan.websiteResult.riskLevel === 'critical') hasRealCriticalFinding = true;
      }

      if (netScores.length > 0) {
        realModuleScores.push(Math.max(...netScores));
      }
    }

    if (realModuleScores.length === 0) {
      return { overallScore: null, overallRisk: null };
    }

    const highest = Math.max(...realModuleScores);
    const avg = realModuleScores.reduce((a, b) => a + b, 0) / realModuleScores.length;
    let score = Math.round(0.5 * highest + 0.5 * avg);
    score = Math.max(0, Math.min(100, score));

    let level: RiskLevel = 'low';
    if (score >= 75) level = 'critical';
    else if (score >= 50) level = 'high';
    else if (score >= 25) level = 'medium';
    else level = 'low';

    // Special Rule: If any finding in REAL modules is Critical, overall level is at least High
    if (hasRealCriticalFinding && (level === 'low' || level === 'medium')) {
      level = 'high';
    }

    return { overallScore: score, overallRisk: level };
  }, [telegramScan, repoScan, networkScan, demoModules]);

  return (
    <ScanContext.Provider
      value={{
        telegramScan,
        repoScan,
        networkScan,
        recentScans,
        overallScore,
        overallRisk,
        hasAnyScan,
        demoModules,
        toasts,
        setTelegramScan,
        setRepoScan,
        setIpScan,
        setLinkScan,
        setWebsiteScan,
        clearAllScans,
        loadSampleData,
        addToast,
        removeToast,
      }}
    >
      {children}
    </ScanContext.Provider>
  );
};

export const useScan = (): ScanContextType => {
  const context = useContext(ScanContext);
  if (!context) {
    throw new Error('useScan must be used within a ScanProvider');
  }
  return context;
};
