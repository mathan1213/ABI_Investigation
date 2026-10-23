import React, { useState, useRef } from 'react';
import { Link } from 'react-router-dom';
import {
  FileText,
  Download,
  Printer,
  ShieldAlert,
  Send,
  GitBranch,
  Network,
  CheckCircle,
  Clock,
  Sparkles,
  ArrowRight,
  ExternalLink,
  ShieldCheck,
  Calendar,
  AlertTriangle,
  RotateCcw,
} from 'lucide-react';
import { useScan } from '../context/ScanContext';
import { RiskGauge } from '../components/RiskGauge';
import { RiskBadge } from '../components/RiskBadge';
import { EmptyState } from '../components/EmptyState';
import { RiskLevel } from '../lib/types';
import jsPDF from 'jspdf';
import html2canvas from 'html2canvas';
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
} from 'recharts';

export const Report: React.FC = () => {
  const {
    telegramScan,
    repoScan,
    networkScan,
    overallScore,
    overallRisk,
    hasAnyScan,
    loadSampleData,
    addToast,
  } = useScan();

  const [isExporting, setIsExporting] = useState(false);
  const [completedSteps, setCompletedSteps] = useState<Record<number, boolean>>({});
  const reportRef = useRef<HTMLDivElement>(null);

  const toggleStep = (id: number) => {
    setCompletedSteps((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const handleDownloadPdf = async () => {
    if (!reportRef.current) return;
    setIsExporting(true);

    try {
      addToast({
        type: 'info',
        title: 'Rendering PDF Report',
        message: 'Converting high-resolution investigation dossier to PDF...',
      });

      const element = reportRef.current;
      const canvas = await html2canvas(element, {
        scale: 2,
        useCORS: true,
        backgroundColor: '#0B1220',
        logging: false,
      });

      const imgData = canvas.toDataURL('image/png');
      const pdf = new jsPDF({
        orientation: 'portrait',
        unit: 'mm',
        format: 'a4',
      });

      const imgWidth = 210;
      const pageHeight = 297;
      const imgHeight = (canvas.height * imgWidth) / canvas.width;
      let heightLeft = imgHeight;
      let position = 0;

      pdf.addImage(imgData, 'PNG', 0, position, imgWidth, imgHeight);
      heightLeft -= pageHeight;

      while (heightLeft > 5) {
        position = heightLeft - imgHeight;
        pdf.addPage();
        pdf.addImage(imgData, 'PNG', 0, position, imgWidth, imgHeight);
        heightLeft -= pageHeight;
      }

      const dateStr = new Date().toISOString().slice(0, 10);
      pdf.save(`Account-Breach-Report-${dateStr}.pdf`);

      addToast({
        type: 'success',
        title: 'Report Download Complete',
        message: 'Your official investigation PDF has been saved.',
      });
    } catch (err) {
      console.error('PDF Generation failed:', err);
      addToast({
        type: 'error',
        title: 'PDF Generation Error',
        message: 'Browser canvas render failed. You can use the Print button to Save as PDF.',
      });
    } finally {
      setIsExporting(false);
    }
  };

  const handlePrint = () => {
    window.print();
  };

  if (!hasAnyScan) {
    return (
      <div className="max-w-4xl mx-auto space-y-8 animate-fadeIn">
        <div className="text-center space-y-2">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-xs font-semibold uppercase tracking-wider">
            <FileText size={13} />
            <span>Investigation Dossier</span>
          </div>
          <h1 className="text-3xl font-extrabold text-white tracking-tight">
            Security Incident Report
          </h1>
          <p className="text-slate-400 text-sm max-w-xl mx-auto">
            Comprehensive forensics, compromise reconstruction, and prioritized recovery action plan.
          </p>
        </div>

        <EmptyState
          title="No Scans Completed Yet"
          description="We need at least one completed scan to generate your breach investigation report. You can link your Telegram, check a public GitHub repository, or test a suspicious network address."
          actionText="Link Telegram to Start"
          actionLink="/telegram"
          secondaryActionText="Load Sample Report Incident"
          onSecondaryAction={loadSampleData}
        />
      </div>
    );
  }

  // Prepared data
  const reportDate = new Date().toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });

  const chartData = [
    { name: 'Critical Risk', value: 2, color: '#EF4444' },
    { name: 'High Risk', value: 3, color: '#F97316' },
    { name: 'Medium Risk', value: 1, color: '#EAB308' },
    { name: 'Low Risk', value: 2, color: '#10B981' },
  ];

  const defaultActions = [
    {
      id: 1,
      title: "Disconnect all unauthorized Telegram devices",
      detail: "Go to Telegram Settings > Devices > Terminate all other sessions to boot out unauthorized connections in Germany.",
    },
    {
      id: 2,
      title: "Turn on Telegram Two-Step Password",
      detail: "Go to Settings > Privacy and Security > Two-Step Verification. Set a strong password so SMS codes alone cannot access your account.",
    },
    {
      id: 3,
      title: "Revoke leaked API keys from GitHub",
      detail: "Roll the Stripe secret key found in config/settings.py immediately. Anyone who saw the repository has your billing privileges.",
    },
    {
      id: 4,
      title: "Upgrade vulnerable software packages",
      detail: "Update 'requests' library to version 2.31.0 to close security flaw CVE-2023-32681.",
    },
    {
      id: 5,
      title: "Block access to SSH Port 22 on your website server",
      detail: "Close port 22 in your cloud provider's firewall so attackers cannot brute-force administrative access.",
    },
  ];

  return (
    <div className="max-w-4xl mx-auto space-y-8 animate-fadeIn">
      {/* Action Header bar (Hidden in print) */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4 pb-4 border-b border-slate-800 no-print">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-bold uppercase tracking-wider text-cyan-400 bg-cyan-500/10 px-2.5 py-0.5 rounded-full border border-cyan-500/20">
              Investigation Report Ready
            </span>
            <span className="text-xs text-slate-400">Date: {reportDate}</span>
          </div>
          <h1 className="text-2xl font-extrabold text-white tracking-tight">
            Account Breach Investigation Report
          </h1>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handlePrint}
            className="flex items-center gap-2 px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-750 text-xs font-semibold text-slate-200 border border-slate-700 transition-colors"
          >
            <Printer size={15} />
            <span>Print</span>
          </button>

          <button
            disabled={isExporting}
            onClick={handleDownloadPdf}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-slate-950 text-xs font-bold transition-all shadow-glow hover:shadow-glow-lg disabled:opacity-50"
          >
            <Download size={15} />
            <span>{isExporting ? 'Generating PDF...' : 'Download PDF'}</span>
          </button>
        </div>
      </div>

      {/* PRINTABLE / EXPORTABLE REPORT CONTAINER */}
      <div
        ref={reportRef}
        id="investigation-report-content"
        className="glass-card rounded-2xl p-6 sm:p-10 border border-slate-800 space-y-8 bg-[#0B1220]"
      >
        {/* Report Top Header */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-6">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 rounded-2xl bg-cyan-400 text-slate-950 flex items-center justify-center font-black shadow-glow">
              <ShieldAlert size={28} />
            </div>
            <div>
              <span className="text-xs font-bold uppercase tracking-wider text-cyan-400">
                Official Cyber Incident Dossier
              </span>
              <h2 className="text-xl font-extrabold text-white">Investigation Report</h2>
              <span className="text-xs text-slate-400">Reference: ABI-2026-X992 • Generated {reportDate}</span>
            </div>
          </div>

          <RiskBadge level={overallRisk} size="lg" />
        </div>

        {/* Top Summary & Gauge */}
        <div className="p-6 rounded-2xl bg-[#111A2E] border border-slate-800 flex flex-col md:flex-row items-center justify-between gap-6">
          <div className="space-y-3 flex-1 text-center md:text-left">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-400">
              Executive Finding Summary
            </span>
            <h3 className="text-xl font-bold text-white leading-snug">
              {overallScore >= 70
                ? "Multiple high-risk security flaws and evidence of unauthorized access from another country were detected."
                : "Your scanned assets appear predominantly safe with minor defensive improvements recommended."}
            </h3>
            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed max-w-xl">
              This report was automatically synthesized by evaluating session anomalies, public source repository leaks, and hostile IP network footprints.
            </p>
          </div>

          <div className="shrink-0 flex flex-col items-center">
            <RiskGauge score={overallScore} level={overallRisk} size="md" />
          </div>
        </div>

        {/* Section 1: What We Found */}
        <div className="space-y-4">
          <div className="border-b border-slate-800 pb-2">
            <h3 className="text-lg font-bold text-white flex items-center gap-2">
              <span className="w-6 h-6 rounded-lg bg-cyan-500/20 text-cyan-400 text-xs font-bold flex items-center justify-center">1</span>
              <span>What We Found Across Monitored Channels</span>
            </h3>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Telegram Channel */}
            <div className="p-4 rounded-xl bg-[#111A2E] border border-slate-800 flex flex-col justify-between space-y-3">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2 text-cyan-400 font-semibold text-xs uppercase">
                    <Send size={14} />
                    <span>Telegram</span>
                  </div>
                  <RiskBadge level={telegramScan ? telegramScan.riskLevel : 'critical'} size="sm" />
                </div>
                <h4 className="text-sm font-bold text-white mb-1">
                  {telegramScan ? telegramScan.phone : '+1 (555) 019-2834'}
                </h4>
                <p className="text-xs text-slate-300 leading-relaxed">
                  {telegramScan
                    ? telegramScan.summary
                    : "Foreign session logged in from Frankfurt, Germany. Two-step verification was disabled."}
                </p>
              </div>
              <span className="text-[11px] text-slate-400 pt-2 border-t border-slate-800">
                {telegramScan ? `${telegramScan.sessions.length} devices inspected` : '3 sessions identified'}
              </span>
            </div>

            {/* Repo Channel */}
            <div className="p-4 rounded-xl bg-[#111A2E] border border-slate-800 flex flex-col justify-between space-y-3">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2 text-purple-400 font-semibold text-xs uppercase">
                    <GitBranch size={14} />
                    <span>GitHub Code</span>
                  </div>
                  <RiskBadge level={repoScan ? repoScan.riskLevel : 'high'} size="sm" />
                </div>
                <h4 className="text-sm font-bold text-white mb-1 truncate">
                  {repoScan ? repoScan.repoName : 'my-project/api-backend'}
                </h4>
                <p className="text-xs text-slate-300 leading-relaxed">
                  {repoScan
                    ? repoScan.summary
                    : "Live Stripe API secret key exposed in public commit history, and outdated requests package."}
                </p>
              </div>
              <span className="text-[11px] text-slate-400 pt-2 border-t border-slate-800">
                {repoScan ? `${repoScan.counts.total} code vulnerabilities` : '5 flaws uncovered'}
              </span>
            </div>

            {/* Network Channel */}
            <div className="p-4 rounded-xl bg-[#111A2E] border border-slate-800 flex flex-col justify-between space-y-3">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2 text-emerald-400 font-semibold text-xs uppercase">
                    <Network size={14} />
                    <span>Network & IP</span>
                  </div>
                  <RiskBadge
                    level={networkScan.ipResult ? networkScan.ipResult.riskLevel : 'critical'}
                    size="sm"
                  />
                </div>
                <h4 className="text-sm font-bold text-white mb-1">
                  {networkScan.ipResult ? networkScan.ipResult.ip : '185.220.101.5'}
                </h4>
                <p className="text-xs text-slate-300 leading-relaxed">
                  {networkScan.ipResult
                    ? networkScan.ipResult.explanation
                    : "IP is an active Tor exit node in Germany with an 89/100 abuse history score."}
                </p>
              </div>
              <span className="text-[11px] text-slate-400 pt-2 border-t border-slate-800">
                High-confidence malicious proxy
              </span>
            </div>
          </div>
        </div>

        {/* Section 2: How It Happened */}
        <div className="space-y-4">
          <div className="border-b border-slate-800 pb-2">
            <h3 className="text-lg font-bold text-white flex items-center gap-2">
              <span className="w-6 h-6 rounded-lg bg-cyan-500/20 text-cyan-400 text-xs font-bold flex items-center justify-center">2</span>
              <span>How It Likely Happened (Plain English)</span>
            </h3>
          </div>

          <div className="p-5 rounded-2xl bg-[#111A2E] border border-slate-800 space-y-3">
            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
              Based on the digital fingerprints collected, here is the reconstructed timeline of how an intruder breached your security perimeter:
            </p>

            <div className="space-y-2.5 pt-1">
              <div className="flex items-start gap-3 p-3 rounded-xl bg-[#0B1220] border border-slate-800">
                <span className="w-5 h-5 rounded-full bg-cyan-500/10 text-cyan-400 flex items-center justify-center text-xs font-bold shrink-0 mt-0.5">1</span>
                <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
                  <strong>Accidental Secret Publication:</strong> A live configuration file containing private credentials was committed to a public GitHub repository.
                </p>
              </div>

              <div className="flex items-start gap-3 p-3 rounded-xl bg-[#0B1220] border border-slate-800">
                <span className="w-5 h-5 rounded-full bg-cyan-500/10 text-cyan-400 flex items-center justify-center text-xs font-bold shrink-0 mt-0.5">2</span>
                <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
                  <strong>Automated Scraping:</strong> Malicious scanner bots detected the exposed credentials within minutes of push.
                </p>
              </div>

              <div className="flex items-start gap-3 p-3 rounded-xl bg-[#0B1220] border border-slate-800">
                <span className="w-5 h-5 rounded-full bg-cyan-500/10 text-cyan-400 flex items-center justify-center text-xs font-bold shrink-0 mt-0.5">3</span>
                <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
                  <strong>Unauthorized Access:</strong> An intruder operating from Frankfurt, Germany logged in through Telegram. Because Two-Step Verification was missing, no secondary password was required.
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Section 3: Risk Level Breakdown */}
        <div className="space-y-4">
          <div className="border-b border-slate-800 pb-2">
            <h3 className="text-lg font-bold text-white flex items-center gap-2">
              <span className="w-6 h-6 rounded-lg bg-cyan-500/20 text-cyan-400 text-xs font-bold flex items-center justify-center">3</span>
              <span>Risk Level & Flaw Distribution</span>
            </h3>
          </div>

          <div className="p-5 rounded-2xl bg-[#111A2E] border border-slate-800 grid grid-cols-1 md:grid-cols-2 gap-6 items-center">
            <div className="h-48 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={chartData}
                    cx="50%"
                    cy="50%"
                    outerRadius={65}
                    dataKey="value"
                    paddingAngle={3}
                  >
                    {chartData.map((entry, index) => (
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

            <div className="space-y-2.5">
              {chartData.map((d) => (
                <div key={d.name} className="flex items-center justify-between text-xs p-2 rounded-lg bg-[#0B1220] border border-slate-800">
                  <div className="flex items-center gap-2">
                    <span className="w-3 h-3 rounded-full shrink-0" style={{ backgroundColor: d.color }} />
                    <span className="text-slate-300 font-medium">{d.name}</span>
                  </div>
                  <span className="font-bold text-white font-mono">{d.value} Findings</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Section 4: What You Should Do Now (Checklist) */}
        <div className="space-y-4">
          <div className="border-b border-slate-800 pb-2">
            <h3 className="text-lg font-bold text-white flex items-center gap-2">
              <span className="w-6 h-6 rounded-lg bg-cyan-500/20 text-cyan-400 text-xs font-bold flex items-center justify-center">4</span>
              <span>What You Should Do Now (Numbered Recovery Plan)</span>
            </h3>
          </div>

          <div className="space-y-3">
            {defaultActions.map((act) => {
              const isDone = !!completedSteps[act.id];
              return (
                <div
                  key={act.id}
                  onClick={() => toggleStep(act.id)}
                  className={`p-4 rounded-xl border transition-all cursor-pointer flex items-start gap-3.5 ${
                    isDone
                      ? 'bg-emerald-950/20 border-emerald-800/40 text-emerald-200'
                      : 'bg-[#111A2E] border-slate-800 text-slate-300 hover:border-slate-700'
                  }`}
                >
                  <div
                    className={`w-6 h-6 rounded-lg flex items-center justify-center font-bold text-xs shrink-0 mt-0.5 transition-colors ${
                      isDone ? 'bg-emerald-500 text-slate-950' : 'bg-slate-800 text-cyan-400 border border-slate-700'
                    }`}
                  >
                    {isDone ? <CheckCircle size={15} /> : act.id}
                  </div>
                  <div>
                    <h5 className={`text-sm font-bold text-white ${isDone ? 'line-through text-slate-400' : ''}`}>
                      {act.title}
                    </h5>
                    <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                      {act.detail}
                    </p>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Section 5: Connected Accounts & Scanned History */}
        <div className="space-y-4">
          <div className="border-b border-slate-800 pb-2">
            <h3 className="text-lg font-bold text-white flex items-center gap-2">
              <span className="w-6 h-6 rounded-lg bg-cyan-500/20 text-cyan-400 text-xs font-bold flex items-center justify-center">5</span>
              <span>Audited Accounts & Investigation Assets</span>
            </h3>
          </div>

          <div className="overflow-x-auto rounded-xl border border-slate-800 bg-[#111A2E]">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-[#0B1220] uppercase text-[10px] tracking-wider text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="px-4 py-3">Asset Name</th>
                  <th className="px-4 py-3">Platform</th>
                  <th className="px-4 py-3">Investigation Time</th>
                  <th className="px-4 py-3 text-right">Audit Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80">
                <tr>
                  <td className="px-4 py-3 font-semibold text-white">
                    {telegramScan ? telegramScan.phone : '+1 (555) 019-2834'}
                  </td>
                  <td className="px-4 py-3">Telegram Messenger</td>
                  <td className="px-4 py-3 text-slate-400">Today at 10:14 PM</td>
                  <td className="px-4 py-3 text-right">
                    <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-red-500/15 text-red-400 border border-red-500/30">
                      Compromised
                    </span>
                  </td>
                </tr>
                <tr>
                  <td className="px-4 py-3 font-semibold text-white">
                    {repoScan ? repoScan.repoName : 'my-project/api-backend'}
                  </td>
                  <td className="px-4 py-3">GitHub Public Repository</td>
                  <td className="px-4 py-3 text-slate-400">Today at 09:30 PM</td>
                  <td className="px-4 py-3 text-right">
                    <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-orange-500/15 text-orange-400 border border-orange-500/30">
                      Secret Leak
                    </span>
                  </td>
                </tr>
                <tr>
                  <td className="px-4 py-3 font-semibold text-white">
                    {networkScan.ipResult ? networkScan.ipResult.ip : '185.220.101.5'}
                  </td>
                  <td className="px-4 py-3">IP Threat Intelligence</td>
                  <td className="px-4 py-3 text-slate-400">Today at 09:45 PM</td>
                  <td className="px-4 py-3 text-right">
                    <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-red-500/15 text-red-400 border border-red-500/30">
                      Hostile Tor Node
                    </span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        {/* Security Watermark & Privacy Verification */}
        <div className="pt-6 border-t border-slate-800/80 flex flex-col sm:flex-row items-center justify-between gap-4 text-center sm:text-left text-xs text-slate-400">
          <div className="flex items-center gap-2">
            <ShieldCheck size={16} className="text-emerald-400" />
            <span>Zero Data Stored • Verified In-Memory Security Audit</span>
          </div>
          <span className="font-mono text-[11px] text-slate-400">
            Account Breach Investigation • Tagline: Find out if you were hacked, and how.
          </span>
        </div>
      </div>
    </div>
  );
};
