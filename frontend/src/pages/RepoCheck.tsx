import React, { useState, useMemo } from 'react';
import { Link } from 'react-router-dom';
import {
  GitBranch,
  ShieldAlert,
  Search,
  KeyRound,
  Package,
  Code,
  Network,
  ArrowRight,
  RotateCcw,
  Sparkles,
  AlertCircle,
  FileText,
  Filter,
} from 'lucide-react';
import { useScan } from '../context/ScanContext';
import { scanRepo } from '../lib/api';
import { RepoScanResult, RepoFindingCategory } from '../lib/types';
import { RiskGauge } from '../components/RiskGauge';
import { RiskBadge } from '../components/RiskBadge';
import { FindingCard } from '../components/FindingCard';
import { Analyzing } from '../components/Analyzing';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts';

const SCAN_MESSAGES = [
  'Cloning repository tree and branch metadata...',
  'Scanning files for leaked API keys, tokens & credentials...',
  'Checking software dependencies against OSV.dev CVE database...',
  'Running static code security analysis with Bandit...',
  'Auditing web connections and container port exposure...',
  'Compiling plain-English remediation report...',
];

const EXAMPLE_REPOS = [
  'https://github.com/OWASP/NodeGoat',
  'https://github.com/expressjs/express',
  'https://github.com/pallets/flask',
];

export const RepoCheck: React.FC = () => {
  const { repoScan, setRepoScan, addToast } = useScan();
  const [repoUrl, setRepoUrl] = useState(repoScan ? repoScan.repoUrl : 'https://github.com/OWASP/NodeGoat');
  const [isScanning, setIsScanning] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'all' | RepoFindingCategory>('all');

  const validateUrl = (url: string) => {
    return /^https:\/\/github\.com\/[a-zA-Z0-9_\-\.]+\/[a-zA-Z0-9_\-\.]+/.test(url.trim());
  };

  const handleScan = async (targetUrl = repoUrl) => {
    const trimmed = targetUrl.trim();
    if (!validateUrl(trimmed)) {
      setErrorMsg('Please enter a valid GitHub repository URL (e.g. https://github.com/owner/repository).');
      return;
    }
    setErrorMsg(null);
    setIsScanning(true);

    try {
      const result: RepoScanResult = await scanRepo(trimmed);
      setRepoScan(result);
    } catch (err: any) {
      const msg = err?.message || 'Failed to inspect repository. Please confirm the repository is public.';
      setErrorMsg(msg);
      addToast({
        type: 'error',
        title: 'Repository Scan Failed',
        message: msg,
      });
    } finally {
      setIsScanning(false);
    }
  };

  const scanData = repoScan;

  // Dynamic counts by category
  const secretCount = useMemo(() => scanData?.findings.filter((f) => f.category === 'secrets').length || 0, [scanData]);
  const depCount = useMemo(() => scanData?.findings.filter((f) => f.category === 'dependencies').length || 0, [scanData]);
  const codeCount = useMemo(() => scanData?.findings.filter((f) => f.category === 'code').length || 0, [scanData]);
  const netCount = useMemo(() => scanData?.findings.filter((f) => f.category === 'network').length || 0, [scanData]);

  // Chart data for findings by category
  const categoryChartData = useMemo(() => [
    { name: 'Secrets', count: secretCount, color: '#EF4444' },
    { name: 'Dependencies', count: depCount, color: '#F97316' },
    { name: 'Code Issues', count: codeCount, color: '#EAB308' },
    { name: 'Network', count: netCount, color: '#06B6D4' },
  ], [secretCount, depCount, codeCount, netCount]);

  const filteredFindings = scanData
    ? activeTab === 'all'
      ? scanData.findings
      : scanData.findings.filter((f) => f.category === activeTab)
    : [];

  return (
    <div className="max-w-5xl mx-auto space-y-8 animate-fadeIn">
      {/* Header */}
      <div className="text-center space-y-2">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-purple-500/10 border border-purple-500/20 text-purple-400 text-xs font-semibold uppercase tracking-wider">
          <GitBranch size={13} />
          <span>GitHub Repository Security Audit</span>
        </div>
        <h1 className="text-3xl font-extrabold text-white tracking-tight">
          Find Leaked Passwords & Flaws in Code
        </h1>
        <p className="text-slate-400 text-sm max-w-xl mx-auto">
          Scan any public GitHub repository to discover exposed API keys, vulnerable software libraries, and unsafe configurations before hackers do.
        </p>
      </div>

      {/* Input Box Card */}
      <div className="glass-card rounded-2xl p-6 sm:p-8 border border-slate-800 space-y-4">
        <div>
          <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-2">
            Public GitHub Repository URL
          </label>
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
                <Search size={18} />
              </div>
              <input
                type="url"
                value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)}
                placeholder="https://github.com/organization/project-name"
                className="w-full pl-10 pr-4 py-3 rounded-xl bg-slate-900 border border-slate-700 text-white placeholder-slate-500 text-sm font-mono focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 transition-colors"
              />
            </div>
            <button
              disabled={isScanning}
              onClick={() => handleScan()}
              className="flex items-center justify-center gap-2 px-6 py-3 rounded-xl bg-cyan-400 text-slate-950 font-bold text-sm hover:bg-cyan-300 disabled:opacity-50 transition-all shadow-glow hover:shadow-glow-lg shrink-0"
            >
              <GitBranch size={16} />
              <span>{isScanning ? 'Scanning...' : 'Analyze Repository'}</span>
            </button>
          </div>
        </div>

        {errorMsg && (
          <div className="p-3.5 rounded-xl bg-red-500/10 border border-red-500/30 text-red-300 text-xs flex items-center gap-2">
            <AlertCircle size={15} className="shrink-0" />
            <span>{errorMsg}</span>
          </div>
        )}

        {/* Quick Example URLs */}
        <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400 pt-1">
          <span className="flex items-center gap-1 font-semibold text-slate-400">
            <Sparkles size={12} className="text-cyan-400" />
            Try an example:
          </span>
          {EXAMPLE_REPOS.map((sample) => (
            <button
              key={sample}
              onClick={() => {
                setRepoUrl(sample);
                handleScan(sample);
              }}
              className="font-mono text-[11px] bg-slate-800 hover:bg-slate-700 text-slate-300 px-2.5 py-1 rounded-lg border border-slate-700/80 transition-colors"
            >
              {sample.replace('https://github.com/', '')}
            </button>
          ))}
        </div>
      </div>

      {/* Analyzing State */}
      {isScanning && (
        <Analyzing
          messages={SCAN_MESSAGES}
          title="Scanning Repository Artifacts"
          subtitle="Searching for leaked credentials, outdated dependencies, and dangerous code patterns..."
        />
      )}

      {/* Results Section */}
      {!isScanning && scanData && (
        <div className="space-y-6">
          {/* Main Verdict Card with Risk Meter */}
          <div className="glass-card rounded-2xl p-6 sm:p-8 border border-slate-800 flex flex-col md:flex-row items-center justify-between gap-6">
            <div className="flex-1 space-y-3 text-center md:text-left">
              <div className="flex flex-wrap items-center justify-center md:justify-start gap-2">
                <RiskBadge level={scanData.riskLevel} size="lg" />
                <span className="text-xs text-slate-400 font-mono bg-slate-800 px-2.5 py-1 rounded-md border border-slate-700">
                  {scanData.repoName} ({scanData.branch} branch)
                </span>
              </div>
              <h2 className="text-2xl font-extrabold text-white">
                Vulnerabilities & Leaks Detected
              </h2>
              <p className="text-sm text-slate-300 leading-relaxed max-w-xl">
                {scanData.summary}
              </p>
            </div>

            <div className="shrink-0 flex flex-col items-center">
              <RiskGauge score={scanData.riskScore} level={scanData.riskLevel} size="lg" />
            </div>
          </div>

          {/* Counts & Category Chart Row */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Counts for Critical / High / Medium / Low */}
            <div className="glass-card rounded-2xl p-6 border border-slate-800 flex flex-col justify-between">
              <div>
                <h3 className="text-base font-bold text-white mb-1">Severity Breakdown</h3>
                <p className="text-xs text-slate-400 mb-4">Total of {scanData.counts.total} actionable flaws found</p>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="p-3.5 rounded-xl bg-red-500/10 border border-red-500/20 text-center">
                  <span className="text-2xl font-black text-red-400 block">{scanData.counts.critical}</span>
                  <span className="text-xs font-semibold text-red-300 uppercase tracking-wider">Critical</span>
                </div>
                <div className="p-3.5 rounded-xl bg-orange-500/10 border border-orange-500/20 text-center">
                  <span className="text-2xl font-black text-orange-400 block">{scanData.counts.high}</span>
                  <span className="text-xs font-semibold text-orange-300 uppercase tracking-wider">High</span>
                </div>
                <div className="p-3.5 rounded-xl bg-yellow-500/10 border border-yellow-500/20 text-center">
                  <span className="text-2xl font-black text-yellow-400 block">{scanData.counts.medium}</span>
                  <span className="text-xs font-semibold text-yellow-300 uppercase tracking-wider">Medium</span>
                </div>
                <div className="p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-center">
                  <span className="text-2xl font-black text-emerald-400 block">{scanData.counts.low}</span>
                  <span className="text-xs font-semibold text-emerald-300 uppercase tracking-wider">Low</span>
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-slate-800 text-[11px] text-slate-400 text-center">
                Scanned {scanData.scannedFilesCount} files across code & config
              </div>
            </div>

            {/* Findings by Category Chart */}
            <div className="lg:col-span-2 glass-card rounded-2xl p-6 border border-slate-800 flex flex-col justify-between">
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-base font-bold text-white">Findings by Category</h3>
                <span className="text-xs text-cyan-400 font-mono">Distribution</span>
              </div>

              <div className="h-44 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={categoryChartData} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                    <XAxis dataKey="name" stroke="#64748B" fontSize={11} tickLine={false} />
                    <YAxis stroke="#64748B" fontSize={11} tickLine={false} allowDecimals={false} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#0E1629',
                        borderColor: '#1E293B',
                        borderRadius: '8px',
                        color: '#fff',
                        fontSize: '12px',
                      }}
                    />
                    <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                      {categoryChartData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>

              <p className="text-xs text-slate-400 pt-2 border-t border-slate-800">
                Secrets left in code require the fastest remediation: revoke and cycle credentials immediately.
              </p>
            </div>
          </div>

          {/* Category Tabs */}
          <div className="space-y-4">
            <div className="flex flex-wrap items-center gap-2 border-b border-slate-800 pb-3">
              <button
                onClick={() => setActiveTab('all')}
                className={`px-3.5 py-2 rounded-xl text-xs font-semibold transition-all flex items-center gap-1.5 ${
                  activeTab === 'all'
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-glow'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                }`}
              >
                <Filter size={13} />
                <span>All Issues ({scanData.findings.length})</span>
              </button>

              <button
                onClick={() => setActiveTab('secrets')}
                className={`px-3.5 py-2 rounded-xl text-xs font-semibold transition-all flex items-center gap-1.5 ${
                  activeTab === 'secrets'
                    ? 'bg-red-500/20 text-red-300 border border-red-500/40'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                }`}
              >
                <KeyRound size={13} className="text-red-400" />
                <span>Secrets ({secretCount})</span>
              </button>

              <button
                onClick={() => setActiveTab('dependencies')}
                className={`px-3.5 py-2 rounded-xl text-xs font-semibold transition-all flex items-center gap-1.5 ${
                  activeTab === 'dependencies'
                    ? 'bg-orange-500/20 text-orange-300 border border-orange-500/40'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                }`}
              >
                <Package size={13} className="text-orange-400" />
                <span>Vulnerable Dependencies ({depCount})</span>
              </button>

              <button
                onClick={() => setActiveTab('code')}
                className={`px-3.5 py-2 rounded-xl text-xs font-semibold transition-all flex items-center gap-1.5 ${
                  activeTab === 'code'
                    ? 'bg-yellow-500/20 text-yellow-300 border border-yellow-500/40'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                }`}
              >
                <Code size={13} className="text-yellow-400" />
                <span>Code Issues ({codeCount})</span>
              </button>

              <button
                onClick={() => setActiveTab('network')}
                className={`px-3.5 py-2 rounded-xl text-xs font-semibold transition-all flex items-center gap-1.5 ${
                  activeTab === 'network'
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                }`}
              >
                <Network size={13} className="text-cyan-400" />
                <span>Network Issues ({netCount})</span>
              </button>
            </div>

            {/* Findings Card List */}
            <div className="space-y-4">
              {filteredFindings.map((finding) => (
                <FindingCard
                  key={finding.id}
                  severity={finding.severity}
                  title={finding.title}
                  filePath={finding.filePath}
                  lineNumber={finding.lineNumber}
                  explanation={finding.explanation}
                  suggestedFix={finding.suggestedFix}
                  codeSnippet={finding.codeSnippet}
                  category={finding.category}
                />
              ))}
            </div>
          </div>

          {/* Bottom Actions */}
          <div className="flex flex-wrap items-center justify-between gap-4 pt-4 border-t border-slate-800">
            <button
              onClick={() => handleScan()}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-750 text-xs font-semibold text-slate-300 border border-slate-700 transition-colors"
            >
              <RotateCcw size={14} />
              <span>Rescan Repository</span>
            </button>

            <div className="flex items-center gap-3">
              <Link
                to="/network"
                className="flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-750 text-xs font-semibold text-white border border-slate-700 transition-colors"
              >
                <span>Check Network & IP</span>
                <ArrowRight size={14} />
              </Link>
              <Link
                to="/report"
                className="flex items-center gap-2 px-4 py-2 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-slate-950 text-xs font-bold transition-all shadow-glow hover:shadow-glow-lg"
              >
                <FileText size={14} />
                <span>Download Report</span>
              </Link>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
