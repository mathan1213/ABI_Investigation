import React, { createContext, useContext, useState, useEffect, useMemo, useRef } from 'react';
import { useAuth } from './AuthContext';
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
  FullReport,
} from '../lib/types';
import {
  scanRepo,
  checkIp,
  checkLink,
  checkWebsite,
  getReport,
  getUserScans,
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
  reportData: FullReport | null;
  isReportLoading: boolean;
  refreshReport: () => Promise<void>;
  setTelegramScan: (scan: TelegramScanResult | null) => void;
  setRepoScan: (scan: RepoScanResult) => void;
  setIpScan: (res: IpCheckResult) => void;
  setLinkScan: (res: LinkCheckResult) => void;
  setWebsiteScan: (res: WebsiteCheckResult) => void;
  clearAllScans: (silent?: boolean | React.MouseEvent) => void;
  addToast: (toast: Omit<ToastNotification, 'id'>) => void;
  removeToast: (id: string) => void;
}

const ScanContext = createContext<ScanContextType | undefined>(undefined);

export const ScanProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  // Scans are kept strictly in React memory across page navigation.
  // No localStorage is used for scan results, phone numbers, or credentials.
  const [telegramScan, setTelegramScanState] = useState<TelegramScanResult | null>(null);
  const [repoScan, setRepoScanState] = useState<RepoScanResult | null>(null);
  const [networkScan, setNetworkScanState] = useState<NetworkScanResult>({});
  const [recentScans, setRecentScans] = useState<RecentScan[]>([]);
  const [reportData, setReportData] = useState<FullReport | null>(null);
  const [isReportLoading, setIsReportLoading] = useState<boolean>(false);
  const demoModules: string[] = [];

  const [toasts, setToasts] = useState<ToastNotification[]>([]);

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
    if (!scan) return;
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

  const { user } = useAuth();
  const currentUserIdRef = useRef<number | null>(null);

  const clearAllScans = (silent?: boolean | React.MouseEvent) => {
    const isSilent = typeof silent === 'boolean' ? silent : false;
    setTelegramScanState(null);
    setRepoScanState(null);
    setNetworkScanState({});
    setRecentScans([]);
    setReportData(null);
    try {
      localStorage.removeItem('abi_tg_scan');
      localStorage.removeItem('abi_repo_scan');
      localStorage.removeItem('abi_net_scan');
      localStorage.removeItem('abi_demo_modules');
      localStorage.removeItem('abi_recent_scans');
    } catch {}
    if (!isSilent) {
      addToast({
        type: 'info',
        title: 'Session Scans Cleared',
        message: 'All in-memory scan records have been deleted.',
      });
    }
  };

  // Strict Per-User Data Isolation: wipe on user change/logout, load on login
  useEffect(() => {
    const nextUserId = user?.id ?? null;
    if (currentUserIdRef.current !== nextUserId) {
      currentUserIdRef.current = nextUserId;
      clearAllScans(true);

      if (nextUserId) {
        getUserScans({ perPage: 10 })
          .then((res) => {
            if (res.items && res.items.length > 0) {
              const loaded: RecentScan[] = res.items.map((s) => {
                let scanType: 'Telegram' | 'Repository' | 'Network IP' | 'Network Link' | 'Network Website' = 'Network IP';
                if (s.module === 'telegram') scanType = 'Telegram';
                else if (s.module === 'repo') scanType = 'Repository';
                else if (s.targetLabel.startsWith('URL:')) scanType = 'Network Link';
                else if (s.targetLabel.startsWith('Domain:')) scanType = 'Network Website';

                return {
                  id: `sc-${s.id}`,
                  date: new Date(s.createdAt).toLocaleDateString(),
                  type: scanType,
                  target: s.targetLabel,
                  riskLevel: s.riskLevel as RiskLevel,
                  score: s.riskScore,
                  status: (s.riskScore > 50 ? 'Alert' : 'Secure') as 'Alert' | 'Secure',
                };
              });
              setRecentScans(loaded);
            }
          })
          .catch(() => {
            // Silently continue if fresh session
          });
      }
    }
  }, [user?.id]);

  const hasAnyScan = Boolean(
    telegramScan || repoScan || networkScan.ipResult || networkScan.linkResult || networkScan.websiteResult
  );

  const refreshReport = async () => {
    if (!hasAnyScan) {
      setReportData(null);
      return;
    }
    setIsReportLoading(true);
    try {
      const rep = await getReport({
        telegram: telegramScan,
        repo: repoScan,
        network: networkScan,
        demoModules: [],
      });
      setReportData(rep);
    } catch (err) {
      console.error('Failed to sync report with backend:', err);
    } finally {
      setIsReportLoading(false);
    }
  };

  // Sync report data whenever scanned assets change
  useEffect(() => {
    let isCurrent = true;
    if (!hasAnyScan) {
      setReportData(null);
      return;
    }

    const syncReport = async () => {
      setIsReportLoading(true);
      try {
        const rep = await getReport({
          telegram: telegramScan,
          repo: repoScan,
          network: networkScan,
          demoModules: [],
        });
        if (isCurrent) {
          setReportData(rep);
        }
      } catch (err) {
        console.error('Failed to sync report with backend:', err);
      } finally {
        if (isCurrent) {
          setIsReportLoading(false);
        }
      }
    };

    syncReport();
    return () => {
      isCurrent = false;
    };
  }, [telegramScan, repoScan, networkScan, hasAnyScan]);

  // Display overallScore and overallRisk exactly as returned by POST /api/report/generate
  const overallScore = reportData ? reportData.overallScore : null;
  const overallRisk = reportData ? reportData.overallRisk : null;

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
        reportData,
        isReportLoading,
        refreshReport,
        setTelegramScan,
        setRepoScan,
        setIpScan,
        setLinkScan,
        setWebsiteScan,
        clearAllScans,
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
