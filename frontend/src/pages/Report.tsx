import React, { useState, useEffect, useRef } from 'react';
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
  Loader2,
  Info,
} from 'lucide-react';
import { useScan } from '../context/ScanContext';
import { RiskGauge } from '../components/RiskGauge';
import { RiskBadge } from '../components/RiskBadge';
import { EmptyState } from '../components/EmptyState';
import { FullReport, RiskLevel, NetworkFindingItem, ActionPlanItem } from '../lib/types';
import { getReport } from '../lib/api';
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
    overallScore: ctxScore,
    overallRisk: ctxRisk,
    hasAnyScan,
    demoModules,
    loadSampleData,
    addToast,
  } = useScan();

  const [reportData, setReportData] = useState<FullReport | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isExporting, setIsExporting] = useState(false);
  const [completedSteps, setCompletedSteps] = useState<Record<number, boolean>>({});
  const reportRef = useRef<HTMLDivElement>(null);

  // Fetch synthesized report from real backend risk engine
  useEffect(() => {
    let isMounted = true;
    if (!hasAnyScan) {
      setReportData(null);
      setIsLoading(false);
      return;
    }

    const fetchReport = async () => {
      setIsLoading(true);
      setError(null);

      try {
        const data = await getReport({
          telegram: telegramScan,
          repo: repoScan,
          network: networkScan,
          demoModules,
        });
        if (isMounted) {
          setReportData(data);
        }
      } catch (err: any) {
        if (isMounted) {
          setError(err?.message || 'Failed to synthesize investigation report.');
          addToast({
            type: 'error',
            title: 'Report Synthesis Notice',
            message: err?.message || 'Using local report representation.',
          });
        }
      } finally {
        if (isMounted) {
          setIsLoading(false);
        }
      }
    };

    fetchReport();
    return () => {
      isMounted = false;
    };
  }, [telegramScan, repoScan, networkScan, demoModules, hasAnyScan]);

  const toggleStep = (id: number) => {
    setCompletedSteps((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  // High-Resolution Multi-page PDF Export with Professional Title & Disclaimer Footer
  const handleDownloadPdf = async () => {
    if (!reportRef.current) return;
    setIsExporting(true);

    try {
      addToast({
        type: 'info',
        title: 'Rendering Investigation Dossier',
        message: 'Building high-resolution PDF with official cover page and risk disclaimer...',
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
      let pageNum = 1;

      // First Page
      pdf.addImage(imgData, 'PNG', 0, position, imgWidth, imgHeight);

      // Add Running Footer on Page 1
      pdf.setFontSize(8);
      pdf.setTextColor(148, 163, 184); // Slate-400
      pdf.text(
        'This report is a risk estimate based on automated security signals, not legal or definitive proof of a breach. • Page 1',
        105,
        292,
        { align: 'center' }
      );

      heightLeft -= pageHeight;

      // Subsequent Pages
      while (heightLeft > 5) {
        position = heightLeft - imgHeight;
        pdf.addPage();
        pageNum += 1;
        pdf.addImage(imgData, 'PNG', 0, position, imgWidth, imgHeight);

        // Add Running Footer on every page
        pdf.setFontSize(8);
        pdf.setTextColor(148, 163, 184);
        pdf.text(
          `This report is a risk estimate based on automated security signals, not legal or definitive proof of a breach. • Page ${pageNum}`,
          105,
          292,
          { align: 'center' }
        );

        heightLeft -= pageHeight;
      }

      const dateStr = new Date().toISOString().slice(0, 10);
      pdf.save(`Account-Breach-Report-${dateStr}.pdf`);

      addToast({
        type: 'success',
        title: 'PDF Download Complete',
        message: `Saved ${pageNum}-page investigation report dossier.`,
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
          secondaryActionText="Load Sample Report Incident (Demo Data)"
          onSecondaryAction={loadSampleData}
        />
      </div>
    );
  }

  // Prepared data from risk engine
  const reportDate = reportData?.generatedAt || new Date().toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });

  const displayScore = reportData ? reportData.overallScore : ctxScore;
  const displayRisk = reportData ? reportData.overallRisk : ctxRisk;
  const displaySummary = reportData ? reportData.summary : 'Compiling security findings across channels...';
  const displayHowItHappened = reportData?.howItHappened || [];
  const displayActions: ActionPlanItem[] = reportData?.whatToDoNow || reportData?.actionPlan || [];
  const displayNetworkFindings: NetworkFindingItem[] = reportData?.networkFindings || [];
  const displayModules = reportData?.modules || [];
  const displayLimitations = reportData?.limitations || [];
  const displayMethodology =
    reportData?.methodology ||
    'Overall composite risk is computed as 50% highest individual module score plus 50% mean score across all completed modules. If any module contains a finding with Critical severity, the composite risk rating is elevated to at least High.';
  const isAnyDemo = (reportData?.demoModules && reportData.demoModules.length > 0) || demoModules.length > 0;

  // Chart data
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

  const chartData = [
    { name: 'Critical Risk', value: critCount, color: '#EF4444' },
    { name: 'High Risk', value: highCount, color: '#F97316' },
    { name: 'Medium Risk', value: medCount, color: '#EAB308' },
    { name: 'Low Risk', value: lowCount, color: '#10B981' },
  ].filter((d) => d.value > 0);

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

      {isLoading && (
        <div className="glass-card rounded-2xl p-8 border border-slate-800 flex items-center justify-center gap-3 text-cyan-400 text-sm">
          <Loader2 size={20} className="animate-spin" />
          <span>Synthesizing cross-module findings with backend risk engine...</span>
        </div>
      )}

      {/* PRINTABLE / EXPORTABLE REPORT CONTAINER */}
      <div
        ref={reportRef}
        id="investigation-report-content"
        className="glass-card rounded-2xl p-6 sm:p-10 border border-slate-800 space-y-8 bg-[#0B1220]"
      >
        {/* Official Cover / Title Banner (Included in PDF & Print) */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-6">
          <div className="flex items-center gap-3.5">
            <div className="w-14 h-14 rounded-2xl bg-cyan-400 text-slate-950 flex items-center justify-center font-black shadow-glow shrink-0">
              <ShieldAlert size={32} />
            </div>
            <div>
              <span className="text-[11px] font-bold uppercase tracking-wider text-cyan-400 block">
                Account Breach Investigation • Cyber Incident Dossier
              </span>
              <h2 className="text-2xl font-black text-white tracking-tight">
                Official Security Investigation Report
              </h2>
              <span className="text-xs text-slate-400">
                Reference: {reportData?.id || 'ABI-REPORT-ONLINE'} • Generated {reportDate}
              </span>
            </div>
          </div>

          <div className="shrink-0 flex items-center gap-2">
            <RiskBadge level={displayRisk} size="lg" />
          </div>
        </div>

        {/* Prominent Demo Mode Banner (Visible in PDF, Print & Screen if any demo data used) */}
        {isAnyDemo && (
          <div className="p-4 rounded-xl bg-amber-500/10 border-2 border-amber-500/40 text-amber-300 text-xs flex items-start gap-3">
            <AlertTriangle size={18} className="shrink-0 text-amber-400 mt-0.5" />
            <div>
              <span className="font-bold text-amber-200 block text-sm uppercase tracking-wide">
                Demo Data Notice
              </span>
              <p className="text-slate-300 mt-0.5 leading-relaxed">
                This investigation dossier incorporates simulated demonstration data for one or more modules{' '}
                {reportData?.demoModules && reportData.demoModules.length > 0
                  ? `(${reportData.demoModules.join(', ')})`
                  : ''}
                . Findings in demo-flagged sections are illustrative test scenarios and do not indicate a verified compromise on your real account.
              </p>
            </div>
          </div>
        )}

        {/* Top Summary & Gauge */}
        <div className="p-6 rounded-2xl bg-[#111A2E] border border-slate-800 flex flex-col md:flex-row items-center justify-between gap-6">
          <div className="space-y-3 flex-1 text-center md:text-left">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-400">
              Executive Finding Summary
            </span>
            <h3 className="text-xl font-bold text-white leading-snug">
              {displayRisk === 'critical' || displayRisk === 'high'
                ? 'High security threat: critical vulnerabilities or active foreign intrusions require remediation.'
                : displayRisk === 'medium'
                ? 'Moderate exposure: defensive gaps were detected across audited infrastructure.'
                : 'Defenses in good standing: no active intrusions or exposed credentials detected.'}
            </h3>
            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed max-w-xl">
              {displaySummary}
            </p>
          </div>

          <div className="shrink-0 flex flex-col items-center">
            <RiskGauge score={displayScore} level={displayRisk} size="md" />
          </div>
        </div>

        {/* Section 1: Per-Module Breakdown */}
        <div className="space-y-4">
          <div className="border-b border-slate-800 pb-2">
            <h3 className="text-lg font-bold text-white flex items-center gap-2">
              <span className="w-6 h-6 rounded-lg bg-cyan-500/20 text-cyan-400 text-xs font-bold flex items-center justify-center">1</span>
              <span>Audited Modules & Forensic Status</span>
            </h3>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Telegram Module */}
            <div className="p-4 rounded-xl bg-[#111A2E] border border-slate-800 flex flex-col justify-between space-y-3">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2 text-cyan-400 font-semibold text-xs uppercase">
                    <Send size={14} />
                    <span>Telegram</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    {(demoModules.includes('telegram') || telegramScan?.isDemo) && (
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/15 text-amber-300 border border-amber-500/30">
                        Demo Data
                      </span>
                    )}
                    <RiskBadge level={telegramScan ? telegramScan.riskLevel : 'low'} size="sm" />
                  </div>
                </div>
                <h4 className="text-sm font-bold text-white mb-1">
                  {telegramScan ? telegramScan.phone : 'Not Scanned Yet'}
                </h4>
                <p className="text-xs text-slate-300 leading-relaxed">
                  {telegramScan
                    ? telegramScan.summary
                    : 'Module not executed during this session. Run Telegram Check to inspect active sessions.'}
                </p>
              </div>
              <span className="text-[11px] text-slate-400 pt-2 border-t border-slate-800">
                {telegramScan ? `${telegramScan.sessions.length} session(s) audited` : 'No sessions tested'}
              </span>
            </div>

            {/* Repo Module */}
            <div className="p-4 rounded-xl bg-[#111A2E] border border-slate-800 flex flex-col justify-between space-y-3">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2 text-purple-400 font-semibold text-xs uppercase">
                    <GitBranch size={14} />
                    <span>GitHub Code</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    {demoModules.includes('repo') && (
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/15 text-amber-300 border border-amber-500/30">
                        Demo Data
                      </span>
                    )}
                    <RiskBadge level={repoScan ? repoScan.riskLevel : 'low'} size="sm" />
                  </div>
                </div>
                <h4 className="text-sm font-bold text-white mb-1 truncate">
                  {repoScan ? repoScan.repoName : 'Not Scanned Yet'}
                </h4>
                <p className="text-xs text-slate-300 leading-relaxed">
                  {repoScan
                    ? repoScan.summary
                    : 'Module not executed during this session. Run Repo Check to scan for leaked credentials.'}
                </p>
              </div>
              <span className="text-[11px] text-slate-400 pt-2 border-t border-slate-800">
                {repoScan ? `${repoScan.counts.total} finding(s) in ${repoScan.scannedFilesCount} file(s)` : 'No repo analyzed'}
              </span>
            </div>

            {/* Network Module */}
            <div className="p-4 rounded-xl bg-[#111A2E] border border-slate-800 flex flex-col justify-between space-y-3">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2 text-emerald-400 font-semibold text-xs uppercase">
                    <Network size={14} />
                    <span>Network & Web</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    {demoModules.includes('network') && (
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/15 text-amber-300 border border-amber-500/30">
                        Demo Data
                      </span>
                    )}
                    <RiskBadge
                      level={
                        networkScan.ipResult
                          ? networkScan.ipResult.riskLevel
                          : networkScan.websiteResult
                          ? networkScan.websiteResult.riskLevel
                          : 'low'
                      }
                      size="sm"
                    />
                  </div>
                </div>
                <h4 className="text-sm font-bold text-white mb-1">
                  {networkScan.ipResult
                    ? networkScan.ipResult.ip
                    : networkScan.websiteResult
                    ? networkScan.websiteResult.domain
                    : 'Not Scanned Yet'}
                </h4>
                <p className="text-xs text-slate-300 leading-relaxed">
                  {networkScan.ipResult
                    ? networkScan.ipResult.explanation
                    : networkScan.websiteResult
                    ? networkScan.websiteResult.explanation
                    : 'Module not executed during this session. Test an IP, link, or website.'}
                </p>
              </div>
              <span className="text-[11px] text-slate-400 pt-2 border-t border-slate-800">
                {networkScan.ipResult
                  ? `IP Abuse Score: ${networkScan.ipResult.abuseScore}/100`
                  : networkScan.websiteResult
                  ? `Port Risk: ${networkScan.websiteResult.riskScore}/100`
                  : 'No network checks'}
              </span>
            </div>
          </div>
        </div>

        {/* Section 2: Consolidated Network Findings */}
        <div className="space-y-4">
          <div className="border-b border-slate-800 pb-2 flex items-center justify-between">
            <h3 className="text-lg font-bold text-white flex items-center gap-2">
              <span className="w-6 h-6 rounded-lg bg-cyan-500/20 text-cyan-400 text-xs font-bold flex items-center justify-center">2</span>
              <span>Network Findings & Hostile Signatures</span>
            </h3>
            <span className="text-xs text-cyan-400 font-mono">
              {displayNetworkFindings.length} Network Issue(s) Identified
            </span>
          </div>

          {displayNetworkFindings.length === 0 ? (
            <div className="p-4 rounded-xl bg-[#111A2E] border border-slate-800 text-xs text-slate-300 flex items-center gap-2">
              <CheckCircle size={16} className="text-emerald-400 shrink-0" />
              <span>No hostile IP addresses, Tor routing nodes, or unencrypted network endpoints detected.</span>
            </div>
          ) : (
            <div className="space-y-2.5">
              {displayNetworkFindings.map((nf) => (
                <div
                  key={nf.id}
                  className={`p-4 rounded-xl bg-[#111A2E] border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 ${
                    nf.severity === 'critical'
                      ? 'border-red-500/40 bg-red-950/10'
                      : nf.severity === 'high'
                      ? 'border-orange-500/40 bg-orange-950/10'
                      : 'border-slate-800'
                  }`}
                >
                  <div className="space-y-1 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                        {nf.source}
                      </span>
                      {nf.target && (
                        <span className="text-xs font-mono text-cyan-300 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                          {nf.target}
                        </span>
                      )}
                      <h4 className="text-sm font-bold text-white">{nf.title}</h4>
                    </div>
                    <p className="text-xs text-slate-300 leading-relaxed">{nf.detail}</p>
                  </div>
                  <RiskBadge level={nf.severity} size="sm" />
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Section 3: How It Likely Happened */}
        <div className="space-y-4">
          <div className="border-b border-slate-800 pb-2">
            <h3 className="text-lg font-bold text-white flex items-center gap-2">
              <span className="w-6 h-6 rounded-lg bg-cyan-500/20 text-cyan-400 text-xs font-bold flex items-center justify-center">3</span>
              <span>How It Likely Happened (Plain English Story)</span>
            </h3>
          </div>

          <div className="p-5 rounded-2xl bg-[#111A2E] border border-slate-800 space-y-3">
            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
              Based on the digital fingerprints collected, here is the reconstructed timeline of how an intruder breached your perimeter or could exploit your accounts:
            </p>

            <div className="space-y-2.5 pt-1">
              {displayHowItHappened.map((stepText, idx) => (
                <div key={idx} className="flex items-start gap-3 p-3.5 rounded-xl bg-[#0B1220] border border-slate-800">
                  <span className="w-6 h-6 rounded-full bg-cyan-500/10 text-cyan-400 flex items-center justify-center text-xs font-bold shrink-0 mt-0.5 border border-cyan-500/20">
                    {idx + 1}
                  </span>
                  <p className="text-xs sm:text-sm text-slate-200 leading-relaxed">{stepText}</p>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Section 4: What You Should Do Now (Checklist) */}
        <div className="space-y-4">
          <div className="border-b border-slate-800 pb-2 flex items-center justify-between">
            <h3 className="text-lg font-bold text-white flex items-center gap-2">
              <span className="w-6 h-6 rounded-lg bg-cyan-500/20 text-cyan-400 text-xs font-bold flex items-center justify-center">4</span>
              <span>What You Should Do Now (Prioritized Recovery Plan)</span>
            </h3>
            <span className="text-xs font-mono text-cyan-400">
              {Object.values(completedSteps).filter(Boolean).length}/{displayActions.length} Completed
            </span>
          </div>

          <div className="space-y-3">
            {displayActions.map((act) => {
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
                  <div className="flex-1">
                    <div className="flex items-center justify-between gap-2">
                      <h5 className={`text-sm font-bold text-white ${isDone ? 'line-through text-slate-400' : ''}`}>
                        {act.title}
                      </h5>
                      {act.priority && <RiskBadge level={act.priority} size="sm" />}
                    </div>
                    <p className="text-xs text-slate-400 mt-1 leading-relaxed">{act.detail}</p>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Section 5: Limitations & Transparency Disclosures */}
        <div className="space-y-4">
          <div className="border-b border-slate-800 pb-2">
            <h3 className="text-lg font-bold text-white flex items-center gap-2">
              <span className="w-6 h-6 rounded-lg bg-cyan-500/20 text-cyan-400 text-xs font-bold flex items-center justify-center">5</span>
              <span>Investigation Limitations & Disclosures</span>
            </h3>
          </div>

          <div className="p-4 rounded-xl bg-[#111A2E] border border-slate-800 space-y-2 text-xs text-slate-300">
            <div className="flex items-center gap-2 text-slate-400 font-semibold mb-2">
              <Info size={15} className="text-cyan-400" />
              <span>Coverage & Heuristic Disclosures:</span>
            </div>
            <ul className="list-disc list-inside space-y-1.5 text-slate-300 leading-relaxed">
              {displayLimitations.map((limitText, idx) => (
                <li key={idx} className={limitText.includes('DEMO DATA') ? 'text-amber-300 font-medium' : ''}>
                  {limitText}
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* Section 6: Methodology */}
        <div className="space-y-4">
          <div className="border-b border-slate-800 pb-2">
            <h3 className="text-lg font-bold text-white flex items-center gap-2">
              <span className="w-6 h-6 rounded-lg bg-cyan-500/20 text-cyan-400 text-xs font-bold flex items-center justify-center">6</span>
              <span>Scoring Methodology</span>
            </h3>
          </div>

          <div className="p-4 rounded-xl bg-[#111A2E] border border-slate-800 text-xs text-slate-300 leading-relaxed">
            <p>{displayMethodology}</p>
          </div>
        </div>

        {/* Running Official Disclaimer Footer (Mandatory Requirement) */}
        <div className="pt-6 border-t border-slate-800/80 flex flex-col sm:flex-row items-center justify-between gap-4 text-center sm:text-left text-xs text-slate-400">
          <div className="flex items-center gap-2">
            <ShieldCheck size={16} className="text-emerald-400 shrink-0" />
            <span>Zero Data Stored • Verified Stateless Risk Engine</span>
          </div>
          <p className="text-[11px] text-slate-400 max-w-xl text-center sm:text-right">
            This report is a risk estimate based on automated security signals, not legal or definitive proof of a breach.
          </p>
        </div>
      </div>
    </div>
  );
};