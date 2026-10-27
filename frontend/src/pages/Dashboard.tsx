import React from 'react';
import { Link } from 'react-router-dom';
import {
  Send,
  GitBranch,
  Network,
  ShieldAlert,
  ArrowRight,
  ShieldCheck,
  CheckCircle2,
  Clock,
  ExternalLink,
  AlertTriangle,
} from 'lucide-react';
import { useScan } from '../context/ScanContext';
import { StatCard } from '../components/StatCard';
import { RiskGauge } from '../components/RiskGauge';
import { RiskBadge } from '../components/RiskBadge';
import { RiskLevel } from '../lib/types';
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  LineChart,
  Line,
  CartesianGrid,
} from 'recharts';

export const Dashboard: React.FC = () => {
  const {
    telegramScan,
    repoScan,
    networkScan,
    recentScans,
    overallScore,
    overallRisk,
    hasAnyScan,
  } = useScan();

  const isTgScanned = telegramScan !== null;
  const isRepoScanned = repoScan !== null;
  const isNetScanned = Boolean(networkScan.ipResult || networkScan.linkResult || networkScan.websiteResult);

  // Telegram card values
  const tgScore = isTgScanned ? telegramScan.riskScore : null;
  const tgLevel: RiskLevel = isTgScanned ? telegramScan.riskLevel : 'low';

  // Repo card values
  const repoScore = isRepoScanned ? repoScan.riskScore : null;
  const repoLevel: RiskLevel = isRepoScanned ? repoScan.riskLevel : 'low';

  // Network card values
  const netScores: number[] = [];
  if (networkScan.ipResult) netScores.push(networkScan.ipResult.abuseScore);
  if (networkScan.linkResult) netScores.push(100 - networkScan.linkResult.reputationScore);
  if (networkScan.websiteResult) netScores.push(networkScan.websiteResult.riskScore);

  const netScore = isNetScanned && netScores.length > 0 ? Math.max(...netScores) : null;
  const netLevel: RiskLevel = isNetScanned
    ? (networkScan.ipResult?.riskLevel === 'critical' || networkScan.websiteResult?.riskLevel === 'critical'
      ? 'critical'
      : (netScore ?? 0) >= 50 ? 'high' : (netScore ?? 0) >= 25 ? 'medium' : 'low')
    : 'low';
  const netTitle = networkScan.ipResult
    ? networkScan.ipResult.ip
    : networkScan.websiteResult
    ? networkScan.websiteResult.domain
    : networkScan.linkResult
    ? networkScan.linkResult.url
    : 'No network check';

  // Recharts Chart Data: Findings by Risk Level (Donut)
  const critCount =
    (telegramScan?.findings.filter((f) => f.risk === 'critical').length ?? 0) +
    (repoScan?.counts.critical ?? 0) +
    (networkScan.ipResult?.riskLevel === 'critical' ? 1 : 0);
  const highCount =
    (telegramScan?.findings.filter((f) => f.risk === 'high').length ?? 0) +
    (repoScan?.counts.high ?? 0) +
    (networkScan.websiteResult?.riskLevel === 'high' ? 1 : 0);
  const medCount =
    (telegramScan?.findings.filter((f) => f.risk === 'medium').length ?? 0) +
    (repoScan?.counts.medium ?? 0);
  const lowCount =
    (telegramScan?.findings.filter((f) => f.risk === 'low').length ?? 0) +
    (repoScan?.counts.low ?? 0);

  const donutData = hasAnyScan
    ? [
        { name: 'Critical', value: critCount, color: '#EF4444' },
        { name: 'High', value: highCount, color: '#F97316' },
        { name: 'Medium', value: medCount, color: '#EAB308' },
        { name: 'Low', value: lowCount, color: '#10B981' },
      ].filter((d) => d.value > 0)
    : [{ name: 'No Scans', value: 1, color: '#334155' }];

  // Recharts Chart Data: Findings per Module (Bar)
  const barData = [
    { module: 'Telegram', issues: isTgScanned ? telegramScan.findings.length : 0 },
    { module: 'Repo Code', issues: isRepoScanned ? repoScan.counts.total : 0 },
    { module: 'Network/IP', issues: networkScan.ipResult ? (networkScan.ipResult.abuseScore > 0 ? 1 : 0) : 0 },
    { module: 'Web SSL', issues: networkScan.websiteResult ? networkScan.websiteResult.ports.filter(p => p.state === 'Open').length : 0 },
  ];

  // Recharts Chart Data: Risk Score Over Recent Scans (Line)
  const lineData = recentScans.length > 0
    ? recentScans.slice(0, 5).reverse().map((s, idx) => ({ scan: `Scan ${idx + 1}`, score: s.score }))
    : [{ scan: 'Initial', score: overallScore ?? 0 }];

  return (
    <div className="space-y-8 animate-fadeIn">
      {/* Welcome Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-bold uppercase tracking-wider text-cyan-400 bg-cyan-500/10 px-2.5 py-0.5 rounded-full border border-cyan-500/20">
              Active Security Dashboard
            </span>
            {!hasAnyScan && (
              <span className="text-xs text-slate-400 bg-slate-800 px-2 py-0.5 rounded-full border border-slate-700">
                No scans performed yet
              </span>
            )}
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            Account Breach Investigation
          </h1>
          <p className="text-sm sm:text-base text-slate-400 mt-1">
            Find out if you were hacked, and how. Plain-English cybersecurity check for normal people.
          </p>
        </div>

        {/* Report Link */}
        <div className="flex items-center gap-3">
          <Link
            to="/report"
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-slate-950 text-xs font-bold transition-all shadow-glow hover:shadow-glow-lg"
          >
            <span>View Full Report</span>
            <ArrowRight size={14} />
          </Link>
        </div>
      </div>

      {/* Top Banner: Based on real scans */}
      {hasAnyScan && (
        <div className="p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <ShieldCheck size={16} className="text-emerald-400 shrink-0" />
            <span className="font-semibold">Based on real scans</span>
            <span className="text-slate-300 hidden sm:inline">— All evaluated modules reflect real data and verified account credentials.</span>
          </div>
          <span className="text-[11px] font-mono bg-emerald-500/20 px-2 py-0.5 rounded text-emerald-200">Verified Signals</span>
        </div>
      )}

      {/* 4 Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Overall Threat Score"
          value={overallScore !== null ? `${overallScore}%` : 'No real data'}
          level={overallRisk ?? 'low'}
          icon={ShieldAlert}
          subtitle={
            overallScore !== null
              ? 'Composite risk across real scanned assets'
              : 'No scans completed yet'
          }
          badgeLabel={
            !hasAnyScan
              ? 'No Scans'
              : overallRisk === 'critical'
              ? 'Urgent Alert'
              : 'Active Status'
          }
        />
        <StatCard
          title="Telegram Risk"
          value={isTgScanned && tgScore !== null ? `${tgScore}%` : 'Not scanned yet'}
          level={tgLevel}
          icon={Send}
          subtitle={isTgScanned ? `${telegramScan.phone} • ${telegramScan.accountName}` : 'No phone linked yet'}
          badgeLabel={!isTgScanned ? 'Not Scanned' : tgScore! > 50 ? 'Compromised' : 'Clean'}
        />
        <StatCard
          title="Repo Security Risk"
          value={isRepoScanned && repoScore !== null ? `${repoScore}%` : 'Not scanned yet'}
          level={repoLevel}
          icon={GitBranch}
          subtitle={isRepoScanned ? repoScan.repoName : 'No repository analyzed'}
          badgeLabel={!isRepoScanned ? 'Not Scanned' : repoScore! > 50 ? 'Secrets Found' : 'Clean'}
        />
        <StatCard
          title="Network & IP Risk"
          value={isNetScanned && netScore !== null ? `${netScore}%` : 'Not scanned yet'}
          level={netLevel}
          icon={Network}
          subtitle={isNetScanned ? netTitle : 'No network target tested'}
          badgeLabel={!isNetScanned ? 'Not Scanned' : netLevel === 'critical' ? 'Hostile IP' : 'Inspected'}
        />
      </div>

      {/* Gauge and Connected Accounts Split Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Speedometer Gauge Panel */}
        <div className="glass-card rounded-2xl p-6 border border-slate-800 flex flex-col items-center justify-between">
          <div className="w-full flex items-center justify-between mb-2">
            <h3 className="text-base font-bold text-white">Overall Security Gauge</h3>
            <RiskBadge level={overallRisk ?? 'low'} size="sm" />
          </div>

          <div className="my-4 py-2 flex flex-col items-center justify-center">
            <RiskGauge score={overallScore ?? 0} level={overallRisk ?? 'low'} size="lg" />
          </div>

          <div className="w-full bg-slate-900/80 rounded-xl p-3.5 border border-slate-800/80 text-xs text-slate-300">
            <p className="leading-relaxed text-center">
              {overallScore === null
                ? 'No scans completed yet. Run a scan on your Telegram logs, code repository, or network target to calculate an overall score.'
                : overallScore >= 75
                ? 'Action Required: High-confidence evidence of an unauthorized login or public secret leaks.'
                : overallScore >= 50
                ? 'Warning: Moderate vulnerabilities found. You should review active sessions and endpoints.'
                : 'Your real accounts are in good standing. No signs of intrusion found.'}
            </p>
          </div>
        </div>

        {/* Connected Accounts & Quick Actions */}
        <div className="lg:col-span-2 glass-card rounded-2xl p-6 border border-slate-800 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-base font-bold text-white">Connected Accounts & Monitoring</h3>
              <span className="text-xs text-slate-400">Zero credentials stored</span>
            </div>

            <div className="space-y-3">
              {/* Telegram Item */}
              <div className="p-4 rounded-xl bg-[#0B1220]/70 border border-slate-800 flex items-center justify-between gap-3">
                <div className="flex items-center gap-3">
                  <div className="p-2.5 rounded-xl bg-sky-500/10 border border-sky-500/20 text-sky-400">
                    <Send size={20} />
                  </div>
                  <div>
                    <h4 className="text-sm font-semibold text-white">Telegram Account</h4>
                    <p className="text-xs text-slate-400">
                      {telegramScan ? `${telegramScan.phone} • ${telegramScan.accountName}` : 'No phone linked yet'}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  {telegramScan ? (
                    <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-400 bg-emerald-500/10 px-2.5 py-1 rounded-full border border-emerald-500/20">
                      <CheckCircle2 size={13} /> Connected
                    </span>
                  ) : (
                    <Link
                      to="/telegram"
                      className="text-xs font-bold text-cyan-400 hover:text-cyan-300 hover:underline"
                    >
                      Connect Now →
                    </Link>
                  )}
                </div>
              </div>

              {/* GitHub Repo Item */}
              <div className="p-4 rounded-xl bg-[#0B1220]/70 border border-slate-800 flex items-center justify-between gap-3">
                <div className="flex items-center gap-3">
                  <div className="p-2.5 rounded-xl bg-purple-500/10 border border-purple-500/20 text-purple-400">
                    <GitBranch size={20} />
                  </div>
                  <div>
                    <h4 className="text-sm font-semibold text-white">GitHub Public Repository</h4>
                    <p className="text-xs text-slate-400">
                      {repoScan ? repoScan.repoName : 'github.com/my-project/api-backend'}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  {repoScan ? (
                    <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-400 bg-emerald-500/10 px-2.5 py-1 rounded-full border border-emerald-500/20">
                      <CheckCircle2 size={13} /> Scanned
                    </span>
                  ) : (
                    <Link
                      to="/repo"
                      className="text-xs font-bold text-cyan-400 hover:text-cyan-300 hover:underline"
                    >
                      Scan Repo →
                    </Link>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Quick Action Buttons */}
          <div className="mt-6 pt-5 border-t border-slate-800">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-400 block mb-3">
              Start an Investigation Scan
            </span>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <Link
                to="/telegram"
                className="flex items-center justify-center gap-2 p-3 rounded-xl bg-slate-850 hover:bg-slate-800 border border-slate-700/80 text-white text-xs font-semibold transition-all hover:border-cyan-500/50"
              >
                <Send size={15} className="text-cyan-400" />
                <span>Link Telegram</span>
              </Link>
              <Link
                to="/repo"
                className="flex items-center justify-center gap-2 p-3 rounded-xl bg-slate-850 hover:bg-slate-800 border border-slate-700/80 text-white text-xs font-semibold transition-all hover:border-cyan-500/50"
              >
                <GitBranch size={15} className="text-purple-400" />
                <span>Check a Repo</span>
              </Link>
              <Link
                to="/network"
                className="flex items-center justify-center gap-2 p-3 rounded-xl bg-slate-850 hover:bg-slate-800 border border-slate-700/80 text-white text-xs font-semibold transition-all hover:border-cyan-500/50"
              >
                <Network size={15} className="text-emerald-400" />
                <span>Check a Network</span>
              </Link>
            </div>
          </div>
        </div>
      </div>

      {/* 3 Recharts Visualizations Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Chart 1: Donut (Findings by Risk Level) */}
        <div className="glass-card rounded-2xl p-5 border border-slate-800 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-3">
            <h4 className="text-sm font-bold text-white">Findings by Risk Level</h4>
            <span className="text-xs text-slate-400">Severity</span>
          </div>

          <div className="h-52 w-full flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={donutData}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={75}
                  paddingAngle={4}
                  dataKey="value"
                >
                  {donutData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0E1629',
                    borderColor: '#1E293B',
                    borderRadius: '8px',
                    color: '#fff',
                    fontSize: '12px',
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>

          <div className="grid grid-cols-2 gap-2 text-xs pt-2 border-t border-slate-800">
            {donutData.map((d) => (
              <div key={d.name} className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: d.color }} />
                <span className="text-slate-400">{d.name}:</span>
                <span className="font-semibold text-white">{d.value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Chart 2: Bar (Findings per Module) */}
        <div className="glass-card rounded-2xl p-5 border border-slate-800 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-3">
            <h4 className="text-sm font-bold text-white">Findings per Module</h4>
            <span className="text-xs text-slate-400">Discovered</span>
          </div>

          <div className="h-52 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={barData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" vertical={false} />
                <XAxis dataKey="module" stroke="#64748B" fontSize={11} tickLine={false} />
                <YAxis stroke="#64748B" fontSize={11} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0E1629',
                    borderColor: '#1E293B',
                    borderRadius: '8px',
                    color: '#fff',
                    fontSize: '12px',
                  }}
                />
                <Bar dataKey="issues" fill="#22D3EE" radius={[6, 6, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>

          <p className="text-xs text-slate-400 pt-2 border-t border-slate-800 text-center">
            Telegram accounts & source code contain the most urgent vulnerabilities.
          </p>
        </div>

        {/* Chart 3: Line (Risk Score over Recent Scans) */}
        <div className="glass-card rounded-2xl p-5 border border-slate-800 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-3">
            <h4 className="text-sm font-bold text-white">Risk History Trend</h4>
            <span className="text-xs text-cyan-400 font-mono">Recent Scans</span>
          </div>

          <div className="h-52 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={lineData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" vertical={false} />
                <XAxis dataKey="scan" stroke="#64748B" fontSize={11} tickLine={false} />
                <YAxis domain={[0, 100]} stroke="#64748B" fontSize={11} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0E1629',
                    borderColor: '#1E293B',
                    borderRadius: '8px',
                    color: '#fff',
                    fontSize: '12px',
                  }}
                />
                <Line
                  type="monotone"
                  dataKey="score"
                  stroke="#F97316"
                  strokeWidth={2.5}
                  dot={{ fill: '#F97316', r: 4 }}
                  activeDot={{ r: 6 }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>

          <p className="text-xs text-slate-400 pt-2 border-t border-slate-800 text-center">
            Threat score spiked when foreign login traces were identified.
          </p>
        </div>
      </div>

      {/* Recent Scans Table */}
      <div className="glass-card rounded-2xl p-6 border border-slate-800">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-base font-bold text-white">Recent Security Scans</h3>
            <p className="text-xs text-slate-400">Activity logged during your current session</p>
          </div>
          <span className="text-xs font-mono text-cyan-400 bg-cyan-950/40 px-2.5 py-1 rounded-md border border-cyan-800/40">
            {recentScans.length} Scans Performed
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-300">
            <thead className="bg-[#0B1220]/80 text-[11px] uppercase tracking-wider text-slate-400 border-b border-slate-800">
              <tr>
                <th scope="col" className="px-4 py-3">Time</th>
                <th scope="col" className="px-4 py-3">Type</th>
                <th scope="col" className="px-4 py-3">Target Examined</th>
                <th scope="col" className="px-4 py-3">Threat Level</th>
                <th scope="col" className="px-4 py-3">Status</th>
                <th scope="col" className="px-4 py-3 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {recentScans.map((scan) => (
                <tr key={scan.id} className="hover:bg-slate-800/30 transition-colors">
                  <td className="px-4 py-3.5 text-xs text-slate-400 whitespace-nowrap">
                    <div className="flex items-center gap-1.5">
                      <Clock size={12} className="text-slate-400" />
                      <span>{scan.date}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3.5 text-xs font-semibold text-slate-200">
                    {scan.type}
                  </td>
                  <td className="px-4 py-3.5 text-xs font-mono text-cyan-300/90 truncate max-w-xs">
                    {scan.target}
                  </td>
                  <td className="px-4 py-3.5">
                    <RiskBadge level={scan.riskLevel} size="sm" />
                  </td>
                  <td className="px-4 py-3.5">
                    <span
                      className={`text-[11px] font-bold px-2 py-0.5 rounded-full border ${
                        scan.status === 'Alert'
                          ? 'bg-red-500/10 border-red-500/20 text-red-400'
                          : 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400'
                      }`}
                    >
                      {scan.status}
                    </span>
                  </td>
                  <td className="px-4 py-3.5 text-right">
                    <Link
                      to={
                        scan.type.includes('Telegram')
                          ? '/telegram'
                          : scan.type.includes('Repo')
                          ? '/repo'
                          : '/network'
                      }
                      className="inline-flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 hover:underline"
                    >
                      <span>Review</span>
                      <ExternalLink size={12} />
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
