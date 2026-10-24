import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Network,
  Globe,
  Link2,
  ShieldCheck,
  ShieldAlert,
  Server,
  ArrowRight,
  Search,
  ExternalLink,
  Lock,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  RotateCcw,
  Sparkles,
  Calendar,
  Layers,
  ArrowDownRight,
  ShieldX,
  FileText,
} from 'lucide-react';
import { useScan } from '../context/ScanContext';
import { checkIp, checkLink, checkWebsite } from '../lib/api';
import {
  IpCheckResult,
  LinkCheckResult,
  WebsiteCheckResult,
} from '../lib/types';
import { Analyzing } from '../components/Analyzing';
import { VerdictCard } from '../components/VerdictCard';
import { RiskBadge } from '../components/RiskBadge';

const IP_MESSAGES = [
  'Connecting to global threat intelligence databases...',
  'Resolving geographic coordinates & hosting ISP...',
  'Checking known Tor exit node registries...',
  'Inspecting VPN & anonymizer proxy signatures...',
  'Calculating fraud & brute-force abuse score...',
];

const LINK_MESSAGES = [
  'Querying WHOIS domain registration records...',
  'Inspecting DNS A, MX, and TXT configurations...',
  'Following HTTP redirect chain hops...',
  'Checking SSL certificate legitimacy & issue date...',
  'Testing URL against phishing blocklists...',
];

const WEBSITE_MESSAGES = [
  'Probing essential public ports (80, 443, 22, 21)...',
  'Analyzing SSL encryption grade & expiry calendar...',
  'Auditing modern browser security headers...',
  'Checking clickjacking and script injection shields...',
  'Compiling plain-English server risk report...',
];

/**
 * Checks if a target string points to a private, loopback, link-local, or reserved address.
 */
function isPrivateOrLoopback(target: string): boolean {
  const clean = target.trim().toLowerCase().replace(/^https?:\/\//i, '').split(/[:/?#]/)[0];
  if (!clean) return false;
  if (
    clean === 'localhost' ||
    clean.endsWith('.localhost') ||
    clean.endsWith('.local') ||
    clean.endsWith('.internal')
  ) {
    return true;
  }
  // IPv4 checks
  if (clean === '0.0.0.0') return true;
  if (clean.startsWith('127.')) return true;
  if (clean.startsWith('10.')) return true;
  if (clean.startsWith('192.168.')) return true;
  if (clean.startsWith('169.254.')) return true;
  const match172 = clean.match(/^172\.(\d+)\./);
  if (match172) {
    const second = parseInt(match172[1], 10);
    if (second >= 16 && second <= 31) return true;
  }
  // IPv6 checks
  if (clean === '::1' || clean === '::' || clean.startsWith('fe80:') || clean.startsWith('fc00:') || clean.startsWith('fd00:')) {
    return true;
  }
  return false;
}

export const NetworkCheck: React.FC = () => {
  const { networkScan, setIpScan, setLinkScan, setWebsiteScan, addToast, systemStatus } = useScan();
  const [activeTab, setActiveTab] = useState<'ip' | 'link' | 'website'>('ip');

  // Form states - empty defaults in real data mode
  const [ipInput, setIpInput] = useState(networkScan.ipResult ? networkScan.ipResult.ip : '');
  const [linkInput, setLinkInput] = useState(networkScan.linkResult ? networkScan.linkResult.url : '');
  const [websiteInput, setWebsiteInput] = useState(networkScan.websiteResult ? networkScan.websiteResult.domain : '');

  // Loading states
  const [isScanning, setIsScanning] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Tab 1: IP Scan handler
  const handleCheckIp = async (targetIp = ipInput) => {
    const trimmed = targetIp.trim();
    if (!trimmed) {
      setErrorMsg('Please enter an IP address to inspect.');
      return;
    }
    if (isPrivateOrLoopback(trimmed)) {
      setErrorMsg('Private and internal network addresses (such as 127.x, 192.168.x, 10.x, or localhost) cannot be inspected because they are not accessible from the public internet.');
      return;
    }
    const isIpv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(trimmed);
    const isIpv6 = trimmed.includes(':');
    if (!isIpv4 && !isIpv6) {
      setErrorMsg('Please enter a valid IPv4 or IPv6 address (e.g. 8.8.8.8).');
      return;
    }
    if (isIpv4) {
      const octets = trimmed.split('.').map(Number);
      if (octets.some((n) => isNaN(n) || n < 0 || n > 255)) {
        setErrorMsg('Invalid IP address format: octets must be numbers between 0 and 255.');
        return;
      }
    }

    setErrorMsg(null);
    setIsScanning(true);
    try {
      const res: IpCheckResult = await checkIp(trimmed);
      setIpScan(res);
    } catch (err: any) {
      const msg = err?.message || 'Failed to check IP address reputation.';
      setErrorMsg(msg);
      addToast({
        type: 'error',
        title: 'IP Inspection Error',
        message: msg,
      });
    } finally {
      setIsScanning(false);
    }
  };

  // Tab 2: Link Scan handler
  const handleCheckLink = async (targetUrl = linkInput) => {
    const trimmed = targetUrl.trim();
    if (!trimmed) {
      setErrorMsg('Please enter a web link or URL to inspect.');
      return;
    }
    if (isPrivateOrLoopback(trimmed)) {
      setErrorMsg('Private and internal links (such as localhost or internal IPs) cannot be inspected because they are not reachable on the public web.');
      return;
    }
    if (!trimmed.includes('.') && !trimmed.startsWith('http')) {
      setErrorMsg('Please enter a valid web link or URL (e.g. https://example.com).');
      return;
    }

    setErrorMsg(null);
    setIsScanning(true);
    try {
      const res: LinkCheckResult = await checkLink(trimmed);
      setLinkScan(res);
    } catch (err: any) {
      const msg = err?.message || 'Failed to inspect suspicious link.';
      setErrorMsg(msg);
      addToast({
        type: 'error',
        title: 'Link Inspection Error',
        message: msg,
      });
    } finally {
      setIsScanning(false);
    }
  };

  // Tab 3: Website Scan handler
  const handleCheckWebsite = async (targetDomain = websiteInput) => {
    const trimmed = targetDomain.trim();
    if (!trimmed) {
      setErrorMsg('Please enter a website domain name (e.g. google.com).');
      return;
    }
    if (isPrivateOrLoopback(trimmed)) {
      setErrorMsg('Local or private hostnames (such as localhost) cannot be inspected because they only exist on your private machine.');
      return;
    }
    if (!trimmed.includes('.') || trimmed.length < 3) {
      setErrorMsg('Please enter a valid domain name with an extension (e.g. google.com).');
      return;
    }

    setErrorMsg(null);
    setIsScanning(true);
    try {
      const res: WebsiteCheckResult = await checkWebsite(trimmed);
      setWebsiteScan(res);
    } catch (err: any) {
      const msg = err?.message || 'Failed to inspect website server security.';
      setErrorMsg(msg);
      addToast({
        type: 'error',
        title: 'Website Inspection Error',
        message: msg,
      });
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div className="max-w-5xl mx-auto space-y-8 animate-fadeIn">
      {/* Header */}
      <div className="text-center space-y-2">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-semibold uppercase tracking-wider">
          <Network size={13} />
          <span>Network & Infrastructure Investigation</span>
        </div>
        <h1 className="text-3xl font-extrabold text-white tracking-tight">
          Verify IPs, Suspicious Links & Websites
        </h1>
        <p className="text-slate-400 text-sm max-w-xl mx-auto">
          Identify hackers hiding behind Tor or VPN proxies, uncover fake phishing links, and check your server for exposed open ports.
        </p>
      </div>

      {/* Optional Threat Intel Status Info */}
      {systemStatus && (!systemStatus.abuseipdb || !systemStatus.virustotal) && (
        <div className="max-w-2xl mx-auto p-3 rounded-xl bg-slate-900/60 border border-slate-800 text-[11px] text-slate-400 flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Sparkles size={14} className="text-cyan-400 shrink-0" />
            <span>
              Threat Intelligence:{' '}
              {!systemStatus.abuseipdb && !systemStatus.virustotal
                ? 'Running on native heuristics & public registries.'
                : !systemStatus.abuseipdb
                ? 'AbuseIPDB unconfigured; using native IP heuristics.'
                : 'VirusTotal unconfigured; using DNS & SSL analysis.'}
            </span>
          </div>
          <span className="text-slate-500 font-medium shrink-0 hidden sm:inline">
            Optional keys in backend/.env improve accuracy
          </span>
        </div>
      )}

      {/* Tabs Selector */}
      <div className="flex justify-center">
        <div className="glass-card p-1.5 rounded-2xl border border-slate-800 flex gap-2 w-full max-w-md">
          <button
            onClick={() => {
              setActiveTab('ip');
              setErrorMsg(null);
            }}
            className={`flex-1 py-2.5 px-3 rounded-xl text-xs font-bold transition-all flex items-center justify-center gap-2 ${
              activeTab === 'ip'
                ? 'bg-cyan-400 text-slate-950 shadow-glow'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Globe size={15} />
            <span>IP Check</span>
          </button>

          <button
            onClick={() => {
              setActiveTab('link');
              setErrorMsg(null);
            }}
            className={`flex-1 py-2.5 px-3 rounded-xl text-xs font-bold transition-all flex items-center justify-center gap-2 ${
              activeTab === 'link'
                ? 'bg-cyan-400 text-slate-950 shadow-glow'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Link2 size={15} />
            <span>Link Check</span>
          </button>

          <button
            onClick={() => {
              setActiveTab('website');
              setErrorMsg(null);
            }}
            className={`flex-1 py-2.5 px-3 rounded-xl text-xs font-bold transition-all flex items-center justify-center gap-2 ${
              activeTab === 'website'
                ? 'bg-cyan-400 text-slate-950 shadow-glow'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Server size={15} />
            <span>Website Check</span>
          </button>
        </div>
      </div>

      {/* TAB 1: IP CHECK */}
      {activeTab === 'ip' && (
        <div className="space-y-6">
          {/* Input Box */}
          <div className="glass-card rounded-2xl p-6 sm:p-8 border border-slate-800 space-y-4">
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-2">
                Enter IP Address to Inspect
              </label>
              <div className="flex flex-col sm:flex-row gap-3">
                <div className="relative flex-1">
                  <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
                    <Globe size={18} />
                  </div>
                  <input
                    type="text"
                    value={ipInput}
                    onChange={(e) => setIpInput(e.target.value)}
                    placeholder="e.g. 8.8.8.8 or 1.1.1.1"
                    className="w-full pl-10 pr-4 py-3 rounded-xl bg-slate-900 border border-slate-700 text-white placeholder-slate-500 text-sm font-mono focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 transition-colors"
                  />
                </div>
                <button
                  disabled={isScanning}
                  onClick={() => handleCheckIp()}
                  className="flex items-center justify-center gap-2 px-6 py-3 rounded-xl bg-cyan-400 text-slate-950 font-bold text-sm hover:bg-cyan-300 disabled:opacity-50 transition-all shadow-glow hover:shadow-glow-lg shrink-0"
                >
                  <Search size={16} />
                  <span>{isScanning ? 'Checking IP...' : 'Audit IP Address'}</span>
                </button>
              </div>
            </div>

            {errorMsg && (
              <div className="p-3.5 rounded-xl bg-red-500/10 border border-red-500/30 text-red-300 text-xs">
                {errorMsg}
              </div>
            )}

            <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400 pt-1">
              <span className="flex items-center gap-1 font-semibold text-slate-400">
                <Sparkles size={12} className="text-cyan-400" />
                Quick presets:
              </span>
              <button
                onClick={() => {
                  setIpInput('185.220.101.5');
                  handleCheckIp('185.220.101.5');
                }}
                className="font-mono text-[11px] bg-red-500/10 hover:bg-red-500/20 text-red-300 px-2.5 py-1 rounded-lg border border-red-500/30 transition-colors"
              >
                185.220.101.5 (Known Tor node)
              </button>
              <button
                onClick={() => {
                  setIpInput('8.8.8.8');
                  handleCheckIp('8.8.8.8');
                }}
                className="font-mono text-[11px] bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-300 px-2.5 py-1 rounded-lg border border-emerald-500/30 transition-colors"
              >
                8.8.8.8 (Google Safe DNS)
              </button>
            </div>
          </div>

          {/* Analyzing State */}
          {isScanning && (
            <Analyzing
              messages={IP_MESSAGES}
              title="Auditing IP Network Reputation"
              subtitle="Checking ISP registry, proxy exit nodes, and attack history..."
            />
          )}

          {/* Result State */}
          {!isScanning && networkScan.ipResult && (
            <div className="space-y-6">
              <VerdictCard
                verdict={networkScan.ipResult.verdict}
                title={`IP Address ${networkScan.ipResult.ip}`}
                explanation={networkScan.ipResult.explanation}
                score={networkScan.ipResult.abuseScore}
                scoreLabel="Abuse Confidence Score"
                items={[
                  { label: 'Country & Location', value: `${networkScan.ipResult.country} (${networkScan.ipResult.city})` },
                  { label: 'Internet Service Provider', value: networkScan.ipResult.isp },
                  { label: 'Autonomous System (ASN)', value: networkScan.ipResult.asn },
                  {
                    label: 'VPN / Proxy Detected',
                    value: networkScan.ipResult.isVpn || networkScan.ipResult.isProxy ? 'Active (Masked IP)' : 'Clean Direct',
                    isDanger: networkScan.ipResult.isVpn,
                  },
                  {
                    label: 'Tor Anonymizer Node',
                    value: networkScan.ipResult.isTor ? 'Confirmed Tor Exit' : 'No Tor Detected',
                    isDanger: networkScan.ipResult.isTor,
                  },
                  {
                    label: 'Hosting / Cloud Datacenter',
                    value: networkScan.ipResult.isHosting ? 'Datacenter / Cloud Server' : 'Residential / Broadband',
                    isDanger: false,
                  },
                  {
                    label: 'Recommendation',
                    value: networkScan.ipResult.abuseScore > 50 ? 'Block Immediately' : 'Allow Traffic',
                    isDanger: networkScan.ipResult.abuseScore > 50,
                  },
                ]}
              />

              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
                <div className="glass-card rounded-2xl p-5 border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between text-xs text-slate-400 font-semibold uppercase">
                    <span>Tor Exit Node</span>
                    {networkScan.ipResult.isTor ? (
                      <span className="text-red-400 font-bold">YES</span>
                    ) : (
                      <span className="text-emerald-400 font-bold">NO</span>
                    )}
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    Tor nodes allow individuals to completely hide their real location. Attackers frequently use them for brute-force attacks.
                  </p>
                </div>

                <div className="glass-card rounded-2xl p-5 border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between text-xs text-slate-400 font-semibold uppercase">
                    <span>VPN / Proxy</span>
                    {networkScan.ipResult.isVpn || networkScan.ipResult.isProxy ? (
                      <span className="text-yellow-400 font-bold">YES</span>
                    ) : (
                      <span className="text-emerald-400 font-bold">NO</span>
                    )}
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    Anonymizing relay or commercial VPN disguising the originating device.
                  </p>
                </div>

                <div className="glass-card rounded-2xl p-5 border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between text-xs text-slate-400 font-semibold uppercase">
                    <span>Hosting / Cloud</span>
                    {networkScan.ipResult.isHosting ? (
                      <span className="text-cyan-400 font-bold">DATACENTER</span>
                    ) : (
                      <span className="text-emerald-400 font-bold">RESIDENTIAL</span>
                    )}
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    {networkScan.ipResult.isHosting
                      ? 'Cloud datacenter server rather than a private residential broadband connection.'
                      : 'Standard residential or consumer broadband internet connection.'}
                  </p>
                </div>

                <div className="glass-card rounded-2xl p-5 border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between text-xs text-slate-400 font-semibold uppercase">
                    <span>Abuse Score</span>
                    <span className="text-cyan-400 font-bold font-mono">
                      {networkScan.ipResult.abuseScore} / 100
                    </span>
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    Calculated confidence rating based on threat intelligence reports and server signals.
                  </p>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 2: LINK CHECK */}
      {activeTab === 'link' && (
        <div className="space-y-6">
          {/* Input Box */}
          <div className="glass-card rounded-2xl p-6 sm:p-8 border border-slate-800 space-y-4">
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-2">
                Enter Suspicious Link or URL
              </label>
              <div className="flex flex-col sm:flex-row gap-3">
                <div className="relative flex-1">
                  <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
                    <Link2 size={18} />
                  </div>
                  <input
                    type="url"
                    value={linkInput}
                    onChange={(e) => setLinkInput(e.target.value)}
                    placeholder="e.g. https://example.com/login"
                    className="w-full pl-10 pr-4 py-3 rounded-xl bg-slate-900 border border-slate-700 text-white placeholder-slate-500 text-sm font-mono focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 transition-colors"
                  />
                </div>
                <button
                  disabled={isScanning}
                  onClick={() => handleCheckLink()}
                  className="flex items-center justify-center gap-2 px-6 py-3 rounded-xl bg-cyan-400 text-slate-950 font-bold text-sm hover:bg-cyan-300 disabled:opacity-50 transition-all shadow-glow hover:shadow-glow-lg shrink-0"
                >
                  <Search size={16} />
                  <span>{isScanning ? 'Inspecting Link...' : 'Inspect Link'}</span>
                </button>
              </div>
            </div>

            {errorMsg && (
              <div className="p-3.5 rounded-xl bg-red-500/10 border border-red-500/30 text-red-300 text-xs">
                {errorMsg}
              </div>
            )}

            <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400 pt-1">
              <span className="flex items-center gap-1 font-semibold text-slate-400">
                <Sparkles size={12} className="text-cyan-400" />
                Quick presets:
              </span>
              <button
                onClick={() => {
                  setLinkInput('https://security-verify-telegram.cc/login');
                  handleCheckLink('https://security-verify-telegram.cc/login');
                }}
                className="font-mono text-[11px] bg-red-500/10 hover:bg-red-500/20 text-red-300 px-2.5 py-1 rounded-lg border border-red-500/30 transition-colors"
              >
                Fake Telegram Phishing Scam
              </button>
              <button
                onClick={() => {
                  setLinkInput('https://github.com/trending');
                  handleCheckLink('https://github.com/trending');
                }}
                className="font-mono text-[11px] bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-300 px-2.5 py-1 rounded-lg border border-emerald-500/30 transition-colors"
              >
                Genuine GitHub Link
              </button>
            </div>
          </div>

          {/* Analyzing State */}
          {isScanning && (
            <Analyzing
              messages={LINK_MESSAGES}
              title="Inspecting Suspicious Web Link"
              subtitle="Unraveling redirect chains, domain creation age, and phishing fingerprints..."
            />
          )}

          {/* Result State */}
          {!isScanning && networkScan.linkResult && (
            <div className="space-y-6">
              <VerdictCard
                verdict={networkScan.linkResult.verdict}
                title="Link Security Assessment"
                explanation={networkScan.linkResult.explanation}
                score={networkScan.linkResult.reputationScore}
                scoreLabel="Trust Score"
                items={[
                  { label: 'Domain Age', value: networkScan.linkResult.domainAge, isDanger: networkScan.linkResult.domainAge.includes('days') },
                  { label: 'SSL Certificate', value: networkScan.linkResult.sslValid ? 'Active SSL' : 'Invalid / Insecure' },
                  { label: 'SSL Issuer', value: networkScan.linkResult.sslIssuer || 'Unknown' },
                  {
                    label: 'Redirect Hops',
                    value: `${networkScan.linkResult.redirectChain.length} Re-routes`,
                    isDanger: networkScan.linkResult.redirectChain.length > 1,
                  },
                ]}
              />

              {/* Redirect Chain Step List */}
              <div className="glass-card rounded-2xl p-6 border border-slate-800 space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-base font-bold text-white">Full Redirect Chain Path</h3>
                    <p className="text-xs text-slate-400">
                      Shows how attackers hide their true destination through multiple link re-routes.
                    </p>
                  </div>
                  <span className="text-xs font-mono text-cyan-400">
                    {networkScan.linkResult.redirectChain.length} Hops Recorded
                  </span>
                </div>

                <div className="space-y-3">
                  {networkScan.linkResult.redirectChain.map((hop, idx) => (
                    <div
                      key={hop.step}
                      className={`p-4 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${
                        idx === networkScan.linkResult!.redirectChain.length - 1 && networkScan.linkResult!.verdict === 'Dangerous'
                          ? 'bg-red-500/10 border-red-500/30'
                          : 'bg-[#0B1220] border-slate-800'
                      }`}
                    >
                      <div className="flex items-start gap-3">
                        <span className="w-6 h-6 rounded-full bg-slate-800 text-cyan-400 flex items-center justify-center text-xs font-bold shrink-0 mt-0.5 border border-slate-700">
                          {hop.step}
                        </span>
                        <div>
                          <div className="font-mono text-xs sm:text-sm text-white break-all">
                            {hop.url}
                          </div>
                          {hop.note && (
                            <span className="text-xs text-slate-400 block mt-0.5">
                              {hop.note}
                            </span>
                          )}
                        </div>
                      </div>

                      <div className="flex items-center gap-2 self-start sm:self-center shrink-0">
                        <span className="text-xs font-mono bg-slate-800 px-2 py-1 rounded text-slate-300">
                          HTTP {hop.status}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* DNS Records */}
              <div className="glass-card rounded-2xl p-6 border border-slate-800 space-y-3">
                <h3 className="text-base font-bold text-white">DNS Records Discovered</h3>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono">
                  <div className="p-3 rounded-xl bg-[#0B1220] border border-slate-800 space-y-1">
                    <span className="text-slate-400 uppercase font-sans text-[10px] block">A Records (IPs)</span>
                    {networkScan.linkResult.dnsRecords.a.map((ip, i) => (
                      <div key={i} className="text-cyan-300">{ip}</div>
                    ))}
                  </div>
                  <div className="p-3 rounded-xl bg-[#0B1220] border border-slate-800 space-y-1">
                    <span className="text-slate-400 uppercase font-sans text-[10px] block">MX Records (Mail)</span>
                    {networkScan.linkResult.dnsRecords.mx.map((mx, i) => (
                      <div key={i} className="text-slate-300 truncate">{mx}</div>
                    ))}
                  </div>
                  <div className="p-3 rounded-xl bg-[#0B1220] border border-slate-800 space-y-1">
                    <span className="text-slate-400 uppercase font-sans text-[10px] block">TXT Records (Verification)</span>
                    {networkScan.linkResult.dnsRecords.txt.map((txt, i) => (
                      <div key={i} className="text-slate-400 truncate">{txt}</div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 3: WEBSITE CHECK */}
      {activeTab === 'website' && (
        <div className="space-y-6">
          {/* Input Box */}
          <div className="glass-card rounded-2xl p-6 sm:p-8 border border-slate-800 space-y-4">
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-2">
                Enter Website Domain Name
              </label>
              <div className="flex flex-col sm:flex-row gap-3">
                <div className="relative flex-1">
                  <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
                    <Server size={18} />
                  </div>
                  <input
                    type="text"
                    value={websiteInput}
                    onChange={(e) => setWebsiteInput(e.target.value)}
                    placeholder="e.g. example.com"
                    className="w-full pl-10 pr-4 py-3 rounded-xl bg-slate-900 border border-slate-700 text-white placeholder-slate-500 text-sm font-mono focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 transition-colors"
                  />
                </div>
                <button
                  disabled={isScanning}
                  onClick={() => handleCheckWebsite()}
                  className="flex items-center justify-center gap-2 px-6 py-3 rounded-xl bg-cyan-400 text-slate-950 font-bold text-sm hover:bg-cyan-300 disabled:opacity-50 transition-all shadow-glow hover:shadow-glow-lg shrink-0"
                >
                  <Search size={16} />
                  <span>{isScanning ? 'Testing Server...' : 'Audit Website'}</span>
                </button>
              </div>
            </div>

            {errorMsg && (
              <div className="p-3.5 rounded-xl bg-red-500/10 border border-red-500/30 text-red-300 text-xs">
                {errorMsg}
              </div>
            )}

            <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400 pt-1">
              <span className="flex items-center gap-1 font-semibold text-slate-400">
                <Sparkles size={12} className="text-cyan-400" />
                Quick presets:
              </span>
              <button
                onClick={() => {
                  setWebsiteInput('portal.example-cloud.io');
                  handleCheckWebsite('portal.example-cloud.io');
                }}
                className="font-mono text-[11px] bg-yellow-500/10 hover:bg-yellow-500/20 text-yellow-300 px-2.5 py-1 rounded-lg border border-yellow-500/30 transition-colors"
              >
                portal.example-cloud.io (Open SSH & Missing Headers)
              </button>
              <button
                onClick={() => {
                  setWebsiteInput('google.com');
                  handleCheckWebsite('google.com');
                }}
                className="font-mono text-[11px] bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-300 px-2.5 py-1 rounded-lg border border-emerald-500/30 transition-colors"
              >
                google.com (Hardened Production)
              </button>
            </div>
          </div>

          {/* Analyzing State */}
          {isScanning && (
            <Analyzing
              messages={WEBSITE_MESSAGES}
              title="Auditing Website Security Configuration"
              subtitle="Probing port entry points, SSL cert expiration, and defensive browser shields..."
            />
          )}

          {/* Result State */}
          {!isScanning && networkScan.websiteResult && (
            <div className="space-y-6">
              <VerdictCard
                verdict={networkScan.websiteResult.verdict}
                title={`Security Configuration for ${networkScan.websiteResult.domain}`}
                explanation={networkScan.websiteResult.explanation}
                score={networkScan.websiteResult.riskScore}
                scoreLabel="Website Risk Score"
                items={[
                  { label: 'SSL Expiry Date', value: networkScan.websiteResult.sslExpiry },
                  {
                    label: 'Days Until Expiration',
                    value: `${networkScan.websiteResult.sslDaysRemaining} Days`,
                    isDanger: networkScan.websiteResult.sslDaysRemaining < 30,
                  },
                  {
                    label: 'Exposed Admin Port 22',
                    value: networkScan.websiteResult.ports.find((p) => p.port === 22)?.state === 'Open' ? 'Open to Internet' : 'Closed',
                    isDanger: networkScan.websiteResult.ports.find((p) => p.port === 22)?.state === 'Open',
                  },
                ]}
              />

              {/* Open Ports Table */}
              <div className="glass-card rounded-2xl p-6 border border-slate-800 space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-base font-bold text-white">Common Server Ports Audited</h3>
                    <p className="text-xs text-slate-400">
                      Ports are digital doors into your computer. Only standard web doors should be open to visitors.
                    </p>
                  </div>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs sm:text-sm text-slate-300">
                    <thead className="bg-[#0B1220]/80 text-[11px] uppercase tracking-wider text-slate-400 border-b border-slate-800">
                      <tr>
                        <th className="px-4 py-3">Port</th>
                        <th className="px-4 py-3">Standard Service</th>
                        <th className="px-4 py-3">State</th>
                        <th className="px-4 py-3">Security Meaning</th>
                        <th className="px-4 py-3 text-right">Risk Level</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/80">
                      {networkScan.websiteResult.ports.map((port) => (
                        <tr key={port.port} className="hover:bg-slate-800/30">
                          <td className="px-4 py-3 font-mono font-bold text-cyan-300">
                            Port {port.port}
                          </td>
                          <td className="px-4 py-3 font-semibold text-white">
                            {port.service}
                          </td>
                          <td className="px-4 py-3">
                            <span
                              className={`px-2 py-0.5 rounded text-xs font-bold ${
                                port.state === 'Open'
                                  ? port.port === 22 || port.port === 21
                                    ? 'bg-red-500/20 text-red-300'
                                    : 'bg-emerald-500/20 text-emerald-300'
                                  : 'bg-slate-800 text-slate-400'
                              }`}
                            >
                              {port.state}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-xs text-slate-300">
                            {port.note}
                          </td>
                          <td className="px-4 py-3 text-right">
                            <RiskBadge level={port.risk} size="sm" />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Security Headers Checklist */}
              <div className="glass-card rounded-2xl p-6 border border-slate-800 space-y-4">
                <div>
                  <h3 className="text-base font-bold text-white">Browser Security Shields (HTTP Headers)</h3>
                  <p className="text-xs text-slate-400">
                    Rules your server sends to web browsers to prevent cookie theft and fake popups.
                  </p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {networkScan.websiteResult.securityHeaders.map((header) => {
                    const isPass = header.status === 'Pass';
                    return (
                      <div
                        key={header.header}
                        className={`p-4 rounded-xl border flex items-start gap-3 ${
                          isPass
                            ? 'bg-emerald-950/15 border-emerald-800/30'
                            : 'bg-red-950/15 border-red-800/30'
                        }`}
                      >
                        <div className="mt-0.5 shrink-0">
                          {isPass ? (
                            <CheckCircle2 size={18} className="text-emerald-400" />
                          ) : (
                            <XCircle size={18} className="text-red-400" />
                          )}
                        </div>
                        <div>
                          <div className="flex items-center gap-2 mb-1">
                            <h4 className="text-xs sm:text-sm font-bold text-white font-mono">{header.header}</h4>
                            <span
                              className={`text-[10px] uppercase font-bold px-1.5 py-0.5 rounded ${
                                isPass ? 'bg-emerald-500/20 text-emerald-300' : 'bg-red-500/20 text-red-300'
                              }`}
                            >
                              {header.status}
                            </span>
                          </div>
                          <p className="text-xs text-slate-300 leading-relaxed">
                            {header.description}
                          </p>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Bottom Actions */}
      <div className="flex flex-wrap items-center justify-between gap-4 pt-4 border-t border-slate-800">
        <Link
          to="/repo"
          className="flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-750 text-xs font-semibold text-slate-300 border border-slate-700 transition-colors"
        >
          <span>← Back to Repo Check</span>
        </Link>

        <Link
          to="/report"
          className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-slate-950 text-xs font-bold transition-all shadow-glow hover:shadow-glow-lg"
        >
          <FileText size={15} />
          <span>Generate Full Investigation Report</span>
        </Link>
      </div>
    </div>
  );
};
