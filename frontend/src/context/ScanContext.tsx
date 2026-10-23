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

  const loadSampleData = async () => {
    try {
      const [tg, rp, ip, lnk, wb] = await Promise.all([
        analyzeTelegram('+1 (555) 019-2834', '12345'),
        scanRepo('https://github.com/my-project/api-backend'),
        checkIp('185.220.101.5'),
        checkLink('https://security-verify-telegram.cc'),
        checkWebsite('portal.example-cloud.io'),
      ]);
      setTelegramScanState({ ...tg, isDemo: true });
      setRepoScanState(rp);
      setNetworkScanState({
        ipResult: ip,
        linkResult: lnk,
        websiteResult: wb,
      });
      setDemoModules(['telegram', 'repo', 'network']);
      addToast({
        type: 'warning',
        title: 'Demo Incident Data Loaded',
        message: 'Loaded simulated demo data across Telegram, Repository, and Network.',
      });
    } catch (e) {
      console.error(e);
    }
  };

  const hasAnyScan = Boolean(
    telegramScan || repoScan || networkScan.ipResult || networkScan.linkResult || networkScan.websiteResult
  );

  // Compute overall score dynamically matching the backend risk engine formula
  const { overallScore, overallRisk } = useMemo(() => {
    const moduleScores: number[] = [];
    let hasCriticalFinding = false;

    if (telegramScan) {
      moduleScores.push(telegramScan.riskScore);
      if (telegramScan.findings?.some((f) => f.risk === 'critical')) {
        hasCriticalFinding = true;
      }
    }

    if (repoScan) {
      moduleScores.push(repoScan.riskScore);
      if ((repoScan.counts?.critical ?? 0) > 0 || repoScan.findings?.some((f) => f.severity === 'critical')) {
        hasCriticalFinding = true;
      }
    }

    const netScores: number[] = [];
    if (networkScan.ipResult) {
      netScores.push(networkScan.ipResult.abuseScore);
      if (networkScan.ipResult.riskLevel === 'critical') hasCriticalFinding = true;
    }
    if (networkScan.linkResult) {
      netScores.push(100 - networkScan.linkResult.reputationScore);
      if (networkScan.linkResult.riskLevel === 'critical') hasCriticalFinding = true;
    }
    if (networkScan.websiteResult) {
      netScores.push(networkScan.websiteResult.riskScore);
      if (networkScan.websiteResult.riskLevel === 'critical') hasCriticalFinding = true;
    }

    if (netScores.length > 0) {
      moduleScores.push(Math.max(...netScores));
    }

    if (moduleScores.length === 0) {
      return { overallScore: 0, overallRisk: 'low' as RiskLevel };
    }

    const highest = Math.max(...moduleScores);
    const avg = moduleScores.reduce((a, b) => a + b, 0) / moduleScores.length;
    let score = Math.round(0.5 * highest + 0.5 * avg);
    score = Math.max(0, Math.min(100, score));

    let level: RiskLevel = 'low';
    if (score >= 75) level = 'critical';
    else if (score >= 50) level = 'high';
    else if (score >= 25) level = 'medium';
    else level = 'low';

    // Special Rule: If any finding anywhere is Critical, overall level is at least High
    if (hasCriticalFinding && (level === 'low' || level === 'medium')) {
      level = 'high';
    }

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
