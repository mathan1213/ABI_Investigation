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
  Sparkles,
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
    loadSampleData,
    hasAnyScan,
  } = useScan();

  // Telegram card values
  const tgScore = telegramScan ? telegramScan.riskScore : 78;
  const tgLevel: RiskLevel = telegramScan ? telegramScan.riskLevel : 'critical';
  const tgTitle = telegramScan ? telegramScan.phone : '+1 (555) 019-2834 (Sample)';

  // Repo card values
  const repoScore = repoScan ? repoScan.riskScore : 72;
  const repoLevel: RiskLevel = repoScan ? repoScan.riskLevel : 'high';
  const repoTitle = repoScan ? repoScan.repoName : 'my-project/api-backend (Sample)';

  // Network card values
  const netScore = networkScan.ipResult
    ? networkScan.ipResult.abuseScore
    : networkScan.websiteResult
    ? networkScan.websiteResult.riskScore
    : 89;
  const netLevel: RiskLevel = networkScan.ipResult
    ? networkScan.ipResult.riskLevel
    : 'critical';
  const netTitle = networkScan.ipResult
    ? networkScan.ipResult.ip
    : networkScan.websiteResult
    ? networkScan.websiteResult.domain
    : '185.220.101.5 (Sample)';

  // Recharts Chart Data: Findings by Risk Level (Donut)
  const donutData = [
    { name: 'Critical', value: telegramScan ? telegramScan.findings.filter(f => f.risk === 'critical').length : 3, color: '#EF4444' },
    { name: 'High', value: (repoScan?.counts.high ?? 2) + (telegramScan ? telegramScan.findings.filter(f => f.risk === 'high').length : 2), color: '#F97316' },
    { name: 'Medium', value: (repoScan?.counts.medium ?? 1) + 1, color: '#EAB308' },
    { name: 'Low', value: (repoScan?.counts.low ?? 1) + 2, color: '#10B981' },
  ];

  // Recharts Chart Data: Findings per Module (Bar)
  const barData = [
    { module: 'Telegram', issues: telegramScan ? telegramScan.findings.length : 5 },
    { module: 'Repo Code', issues: repoScan ? repoScan.counts.total : 5 },
    { module: 'Network/IP', issues: networkScan.ipResult ? (networkScan.ipResult.abuseScore > 0 ? 3 : 0) : 3 },
    { module: 'Web SSL', issues: networkScan.websiteResult ? 2 : 2 },
  ];

  // Recharts Chart Data: Risk Score Over Recent Scans (Line)
  const lineData = [
    { scan: 'Scan 1', score: 32 },
    { scan: 'Scan 2', score: 45 },
    { scan: 'Scan 3', score: 60 },
    { scan: 'Scan 4', score: 85 },
    { scan: 'Latest', score: overallScore },
  ];

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
              <span className="text-xs text-amber-400 bg-amber-500/10 px-2 py-0.5 rounded-full border border-amber-500/20">
                Sample preview mode
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

        {/* Demo Helper Button */}
        <div className="flex items-center gap-3">
          {!hasAnyScan && (
            <button
              onClick={loadSampleData}
              className="flex items-center gap-2 px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-750 text-xs font-semibold text-cyan-300 border border-slate-700 shadow-sm transition-all"
            >
              <Sparkles size={14} className="text-cyan-400" />
              <span>Load Full Sample Incident</span>
            </button>
          )}
          <Link
            to="/report"
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-slate-950 text-xs font-bold transition-all shadow-glow hover:shadow-glow-lg"
          >
            <span>View Full Report</span>
            <ArrowRight size={14} />
          </Link>
        </div>
      </div>

      {/* 4 Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Overall Threat Score"
          value={`${overallScore}%`}
          level={overallRisk}
          icon={ShieldAlert}
          subtitle="Weighted risk across all monitored assets"
          badgeLabel={overallRisk === 'critical' ? 'Urgent Alert' : 'Active Status'}
        />
        <StatCard
          title="Telegram Risk"
          value={`${tgScore}%`}
          level={tgLevel}
          icon={Send}
          subtitle={telegramScan ? 'Live verified session' : tgTitle}
          badgeLabel={tgLevel === 'critical' ? 'Breached' : 'Secure'}
        />
        <StatCard
          title="Repo Security Risk"
          value={`${repoScore}%`}
          level={repoLevel}
          icon={GitBranch}
          subtitle={repoScan ? repoScan.repoName : repoTitle}
          badgeLabel={repoLevel === 'high' ? 'Secrets Found' : 'Clean'}
        />
        <StatCard
          title="Network & IP Risk"
          value={`${netScore}%`}
          level={netLevel}
          icon={Network}
          subtitle={netTitle}
          badgeLabel={netLevel === 'critical' ? 'Hostile IP' : 'Safe IP'}
        />
      </div>

      {/* Gauge and Connected Accounts Split Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Speedometer Gauge Panel */}
        <div className="glass-card rounded-2xl p-6 border border-slate-800 flex flex-col items-center justify-between">
          <div className="w-full flex items-center justify-between mb-2">
            <h3 className="text-base font-bold text-white">Overall Security Gauge</h3>
            <RiskBadge level={overallRisk} size="sm" />
          </div>

          <div className="my-4 py-2 flex flex-col items-center justify-center">
            <RiskGauge score={overallScore} level={overallRisk} size="lg" />
          </div>

          <div className="w-full bg-slate-900/80 rounded-xl p-3.5 border border-slate-800/80 text-xs text-slate-300">
            <p className="leading-relaxed text-center">
              {overallScore >= 75
                ? 'Action Required: We detected high-confidence evidence of an unauthorized login and public secret leaks.'
                : overallScore >= 50
                ? 'Warning: Moderate vulnerabilities found. You should revoke unused sessions.'
                : 'Your accounts are in good standing. No signs of intrusion found.'}
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
