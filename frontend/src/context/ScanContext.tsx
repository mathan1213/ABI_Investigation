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
  overallScore: number;
  overallRisk: RiskLevel;
  hasAnyScan: boolean;
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
    if (saved) return JSON.parse(saved);
    return {
      repoUrl: 'https://github.com/OWASP/NodeGoat',
      repoName: 'OWASP/NodeGoat',
      riskScore: 100,
      riskLevel: 'critical',
      summary: "We discovered 33 security issues across 93 scanned files in 'OWASP/NodeGoat', including 1 critical and 17 high severity alerts. Exposed credentials and vulnerable components should be addressed immediately.",
      branch: 'master',
      scannedFilesCount: 93,
      timestamp: new Date().toISOString(),
      counts: {
        critical: 1,
        high: 17,
        medium: 15,
        low: 0,
        total: 33,
      },
      findings: [
        {
          id: 'find-1',
          category: 'dependencies',
          severity: 'high',
          title: 'Vulnerable npm Package: body-parser (GHSA-qwcr-r2fm-qrc7)',
          filePath: 'package.json',
          lineNumber: 1,
          explanation: "Package 'body-parser' contains a known security flaw allowing denial of service when processing requests.",
          suggestedFix: "Upgrade 'body-parser' to version 1.20.3 or higher.",
          codeSnippet: '"body-parser": "~1.12.0"'
        },
        {
          id: 'find-2',
          category: 'code',
          severity: 'high',
          title: 'Dangerous eval() Call Detected',
          filePath: 'app/routes/allocations.js',
          lineNumber: 48,
          explanation: "The code uses 'eval()', executing user-controlled input as raw JavaScript code.",
          suggestedFix: 'Replace eval() with safe JSON.parse() or structured parsing.',
          codeSnippet: 'threshold = eval(req.body.threshold);'
        },
        {
          id: 'find-3',
          category: 'network',
          severity: 'medium',
          title: 'Insecure Unencrypted HTTP Connection',
          filePath: 'config/env/development.js',
          lineNumber: 14,
          explanation: 'The application connects to an unencrypted HTTP URL over plaintext.',
          suggestedFix: 'Switch address to secure HTTPS (https://).',
          codeSnippet: 'apiUrl: "http://api.internal-dev.net"'
        }
      ]
    };
  });

  const [networkScan, setNetworkScanState] = useState<NetworkScanResult>(() => {
    const saved = localStorage.getItem('abi_net_scan');
    if (saved) return JSON.parse(saved);
    return {
      ipResult: {
        ip: '8.8.8.8',
        country: 'United States',
        city: 'Ashburn',
        isp: 'Google LLC',
        asn: 'AS15169 Google LLC',
        isVpn: false,
        isProxy: false,
        isTor: false,
        isHosting: true,
        abuseScore: 0,
        verdict: 'Safe',
        riskLevel: 'low',
        explanation: 'This IP address belongs to verified public infrastructure (Google LLC) in United States. It is recognized as trusted service infrastructure with zero malicious activity.',
        timestamp: new Date().toISOString(),
      }
    };
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
      return;
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
    localStorage.removeItem('abi_tg_scan');
    localStorage.removeItem('abi_repo_scan');
    localStorage.removeItem('abi_net_scan');
    addToast({
      type: 'info',
      title: 'Session Scans Cleared',
      message: 'All your temporary scan records have been deleted.',
    });
  };

  const loadSampleData = async () => {
    try {
      const [tg, rp, ip, lnk, wb] = await Promise.all([
        analyzeTelegram('+1 (555) 019-2834', '12345'),
        scanRepo('https://github.com/my-project/api-backend'),
        checkIp('185.220.101.5'),
        checkLink('https://security-verify-telegram.cc'),
        checkWebsite('portal.example-cloud.io'),
      ]);
      setTelegramScanState(tg);
      setRepoScanState(rp);
      setNetworkScanState({
        ipResult: ip,
        linkResult: lnk,
        websiteResult: wb,
      });
      addToast({
        type: 'success',
        title: 'Demo Security Audit Loaded',
        message: 'Loaded real-world breach data across Telegram, Repository, and Network.',
      });
    } catch (e) {
      console.error(e);
    }
  };

  const hasAnyScan = Boolean(
    telegramScan || repoScan || networkScan.ipResult || networkScan.linkResult || networkScan.websiteResult
  );

  // Compute overall score dynamically based on active scans or fallback
  const { overallScore, overallRisk } = useMemo(() => {
    const scores: number[] = [];
    if (telegramScan) scores.push(telegramScan.riskScore);
    if (repoScan) scores.push(repoScan.riskScore);
    if (networkScan.ipResult) scores.push(networkScan.ipResult.abuseScore);
    if (networkScan.linkResult) scores.push(100 - networkScan.linkResult.reputationScore);
    if (networkScan.websiteResult) scores.push(networkScan.websiteResult.riskScore);

    let score = 0;
    if (scores.length > 0) {
      // Calculate weighted or maximum risk score to avoid diluting dangerous alerts
      const maxScore = Math.max(...scores);
      const avgScore = scores.reduce((a, b) => a + b, 0) / scores.length;
      score = Math.round(maxScore * 0.7 + avgScore * 0.3);
    } else {
      score = 78; // Default sample representation score
    }

    let level: RiskLevel = 'low';
    if (score >= 75) level = 'critical';
    else if (score >= 50) level = 'high';
    else if (score >= 25) level = 'medium';
    else level = 'low';

    return { overallScore: score, overallRisk: level };
  }, [telegramScan, repoScan, networkScan]);

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
