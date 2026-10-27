import React, { useState, useRef } from 'react';
import { Link } from 'react-router-dom';
import {
  DownloadCloud,
  Upload,
  FileText,
  Trash2,
  AlertTriangle,
  ArrowRight,
  ShieldCheck,
  CheckCircle2,
  FileCheck,
  Laptop,
  MessageSquare,
  Shield,
  RotateCcw,
  ExternalLink,
  Info,
  Check,
} from 'lucide-react';
import { Stepper, StepItem } from '../components/Stepper';
import { Analyzing } from '../components/Analyzing';
import { RiskGauge } from '../components/RiskGauge';
import { RiskBadge } from '../components/RiskBadge';
import { SessionTable } from '../components/SessionTable';
import { useScan } from '../context/ScanContext';
import { analyzeTelegramLogs } from '../lib/api';
import { TelegramScanResult } from '../lib/types';

const STEPS: StepItem[] = [
  { id: 1, title: 'Export Logs', description: 'Export from Telegram Desktop' },
  { id: 2, title: 'Upload', description: 'Upload sessions & chat files' },
  { id: 3, title: 'Analyze', description: 'In-memory forensic audit' },
  { id: 4, title: 'Result', description: 'Breach verdict & action plan' },
];

const ANALYZE_MESSAGES = [
  'Verifying uploaded files and archive safety limits...',
  'Parsing active sessions and identifying device platforms...',
  'Inspecting IP reputation, geolocations, and Tor/VPN nodes...',
  'Evaluating impossible travel anomalies across session timestamps...',
  'Auditing official service chat for takeover patterns & unlinked logins...',
  'Redacting verification OTPs and building forensic report...',
];

const ACCEPTED_EXTENSIONS = ['.json', '.html', '.htm', '.txt', '.zip'];
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB
const MAX_TOTAL_SIZE = 25 * 1024 * 1024; // 25 MB
const MAX_FILES = 5;

export const LinkTelegram: React.FC = () => {
  const { telegramScan, setTelegramScan } = useScan();

  const [currentStep, setCurrentStep] = useState<number>(telegramScan ? 4 : 1);
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [consentAgreed, setConsentAgreed] = useState<boolean>(false);
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isDragOver, setIsDragOver] = useState<boolean>(false);

  const fileInputRef = useRef<HTMLInputElement>(null);

  // File validation
  const validateAndAddFiles = (newFiles: FileList | File[]) => {
    setErrorMessage(null);
    const validList: File[] = [...selectedFiles];
    let totalSize = validList.reduce((acc, f) => acc + f.size, 0);

    for (let i = 0; i < newFiles.length; i++) {
      const file = newFiles[i];

      if (validList.length >= MAX_FILES) {
        setErrorMessage(`Maximum ${MAX_FILES} files allowed.`);
        break;
      }

      // Check extension
      const ext = '.' + file.name.split('.').pop()?.toLowerCase();
      if (!ACCEPTED_EXTENSIONS.includes(ext)) {
        setErrorMessage(`File '${file.name}' is not supported. Please upload .json, .html, .txt, or .zip files.`);
        continue;
      }

      // Check size
      if (file.size > MAX_FILE_SIZE) {
        setErrorMessage(`File '${file.name}' exceeds the 10 MB per-file limit.`);
        continue;
      }

      if (totalSize + file.size > MAX_TOTAL_SIZE) {
        setErrorMessage(`Total upload size exceeds the 25 MB limit.`);
        break;
      }

      // Avoid duplicates by name + size
      if (!validList.some((existing) => existing.name === file.name && existing.size === file.size)) {
        validList.push(file);
        totalSize += file.size;
      }
    }

    setSelectedFiles(validList);
  };

  const handleRemoveFile = (index: number) => {
    setSelectedFiles((prev) => prev.filter((_, i) => i !== index));
    setErrorMessage(null);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    if (e.dataTransfer.files) {
      validateAndAddFiles(e.dataTransfer.files);
    }
  };

  const handleStartAnalysis = async () => {
    if (selectedFiles.length === 0) {
      setErrorMessage('Please select at least 1 file to analyze.');
      return;
    }
    if (!consentAgreed) {
      setErrorMessage('Please check the consent box to proceed with analysis.');
      return;
    }

    setErrorMessage(null);
    setIsAnalyzing(true);
    setCurrentStep(3);

    try {
      const result = await analyzeTelegramLogs(selectedFiles);
      setTelegramScan(result);
      setCurrentStep(4);
    } catch (err: any) {
      setErrorMessage(err?.message || 'Failed to analyze Telegram export files. Please verify the files and try again.');
      setCurrentStep(2);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleReset = () => {
    setTelegramScan(null);
    setSelectedFiles([]);
    setConsentAgreed(false);
    setErrorMessage(null);
    setCurrentStep(1);
  };

  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
  };

  return (
    <div className="max-w-5xl mx-auto px-4 py-8 space-y-8">
      {/* Page Header */}
      <div className="text-center max-w-2xl mx-auto space-y-2">
        <div className="inline-flex p-3 bg-blue-500/10 border border-blue-500/20 rounded-2xl text-blue-400 mb-1">
          <DownloadCloud className="w-8 h-8" />
        </div>
        <h1 className="text-3xl font-bold text-white tracking-tight">Telegram Security Forensics</h1>
        <p className="text-sm text-slate-400">
          Upload your Telegram Desktop export logs to detect unauthorized sessions, foreign logins, impossible travel, and account takeover signals.
        </p>
      </div>

      {/* Stepper */}
      <Stepper steps={STEPS} currentStep={currentStep} />

      {/* STEP 1: EXPORT GUIDE */}
      {currentStep === 1 && (
        <div className="bg-[#111827] border border-slate-800 rounded-2xl p-6 md:p-8 space-y-8 shadow-xl">
          <div>
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              <Laptop className="w-5 h-5 text-blue-400" />
              Step 1: How to Export Your Telegram Logs
            </h2>
            <p className="text-xs text-slate-400 mt-1">
              Telegram only allows exporting logs through the official desktop application. Mobile apps cannot generate machine-readable exports.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Card 1 */}
            <div className="bg-[#0B0F19] border border-slate-800 rounded-xl p-5 space-y-2 relative overflow-hidden">
              <span className="text-3xl font-black text-slate-800 absolute right-4 top-2 select-none">01</span>
              <div className="flex items-center gap-2 text-sm font-semibold text-white">
                <Laptop className="w-4 h-4 text-blue-400" />
                <span>Install Telegram Desktop</span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                Download and install Telegram Desktop on your computer (Windows, macOS, or Linux). Sign in securely by scanning the QR code using your phone's Telegram app (Settings &gt; Devices &gt; Link Desktop Device).
              </p>
            </div>

            {/* Card 2 */}
            <div className="bg-[#0B0F19] border border-slate-800 rounded-xl p-5 space-y-2 relative overflow-hidden">
              <span className="text-3xl font-black text-slate-800 absolute right-4 top-2 select-none">02</span>
              <div className="flex items-center gap-2 text-sm font-semibold text-white">
                <ShieldCheck className="w-4 h-4 text-purple-400" />
                <span>Export Active Sessions</span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                Click <strong>Menu &gt; Settings &gt; Advanced &gt; Export Telegram data</strong>. Untick everything and tick only <strong>"Active sessions"</strong>. Choose <strong>"Machine-readable JSON"</strong> and click Export. (Approve the prompt on your phone if asked).
              </p>
            </div>

            {/* Card 3 */}
            <div className="bg-[#0B0F19] border border-slate-800 rounded-xl p-5 space-y-2 relative overflow-hidden">
              <span className="text-3xl font-black text-slate-800 absolute right-4 top-2 select-none">03</span>
              <div className="flex items-center gap-2 text-sm font-semibold text-white">
                <MessageSquare className="w-4 h-4 text-emerald-400" />
                <span>Export Service Chat (Recommended)</span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                Open the official chat called <strong>"Telegram"</strong> (verified blue tick). Click the <strong>three dots &gt; Export chat history</strong>, untick media, select <strong>JSON</strong> format, and click Export. This contains login alerts and security notifications.
              </p>
            </div>

            {/* Card 4 */}
            <div className="bg-[#0B0F19] border border-slate-800 rounded-xl p-5 space-y-2 relative overflow-hidden">
              <span className="text-3xl font-black text-slate-800 absolute right-4 top-2 select-none">04</span>
              <div className="flex items-center gap-2 text-sm font-semibold text-white">
                <FileCheck className="w-4 h-4 text-amber-400" />
                <span>Upload result.json or ZIP</span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                Each export produces a <code className="text-amber-300 bg-slate-900 px-1 py-0.5 rounded">result.json</code> or HTML file. File names do not matter because our tool detects files by content. You can upload 1 to 5 files or a single ZIP archive.
              </p>
            </div>
          </div>

          {/* Privacy Notice Alert */}
          <div className="p-4 bg-amber-950/30 border border-amber-800/50 rounded-xl flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
            <div className="text-xs text-amber-200/90 leading-relaxed space-y-1">
              <p className="font-semibold text-amber-100">Strict Privacy Guarantee &amp; Scope:</p>
              <p>
                Do <strong>NOT</strong> upload personal or private group chats. Upload only your <em>Active sessions</em> and the official <em>Telegram service chat</em>. Any verification codes or numeric OTP sequences found in service notifications are automatically masked (<code className="bg-amber-900/60 text-white px-1 rounded">****</code>) upon upload and never stored.
              </p>
            </div>
          </div>

          <div className="flex justify-end pt-4 border-t border-slate-800">
            <button
              onClick={() => setCurrentStep(2)}
              className="w-full sm:w-auto px-6 py-3 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium rounded-xl flex items-center justify-center gap-2 shadow-lg shadow-blue-600/20 transition-all"
            >
              I Have My Export Files Ready
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* STEP 2: UPLOAD LOGS */}
      {currentStep === 2 && (
        <div className="bg-[#111827] border border-slate-800 rounded-2xl p-6 md:p-8 space-y-6 shadow-xl">
          <div>
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              <Upload className="w-5 h-5 text-blue-400" />
              Step 2: Upload Export Files
            </h2>
            <p className="text-xs text-slate-400 mt-1">
              Select 1 to 5 files (.json, .html, .txt, or .zip) from your Telegram Desktop export folder.
            </p>
          </div>

          {errorMessage && (
            <div className="p-3.5 bg-red-900/30 border border-red-800/60 rounded-xl flex items-start gap-2.5 text-xs text-red-300">
              <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
              <span>{errorMessage}</span>
            </div>
          )}

          {/* Drag & Drop Zone */}
          <div
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className={`border-2 border-dashed rounded-2xl p-8 text-center cursor-pointer transition-all ${
              isDragOver
                ? 'border-blue-500 bg-blue-500/10'
                : 'border-slate-700 hover:border-slate-600 bg-[#0B0F19]'
            }`}
          >
            <input
              ref={fileInputRef}
              type="file"
              multiple
              accept=".json,.html,.htm,.txt,.zip"
              className="hidden"
              onChange={(e) => e.target.files && validateAndAddFiles(e.target.files)}
            />
            <div className="flex flex-col items-center gap-3">
              <div className="p-3 bg-blue-500/10 rounded-full text-blue-400">
                <Upload className="w-6 h-6" />
              </div>
              <div>
                <p className="text-sm font-semibold text-white">
                  Drag and drop your export files here, or <span className="text-blue-400 underline">browse</span>
                </p>
                <p className="text-xs text-slate-500 mt-1">
                  Supports JSON, HTML, TXT, or ZIP (Max 5 files, 10 MB each, 25 MB total)
                </p>
              </div>
            </div>
          </div>

          {/* Selected File List */}
          {selectedFiles.length > 0 && (
            <div className="space-y-2">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                Selected Files ({selectedFiles.length} of {MAX_FILES})
              </span>
              <div className="space-y-2">
                {selectedFiles.map((file, idx) => (
                  <div
                    key={`${file.name}-${idx}`}
                    className="flex items-center justify-between p-3 bg-[#0B0F19] border border-slate-800 rounded-xl text-xs"
                  >
                    <div className="flex items-center gap-3">
                      <FileText className="w-4 h-4 text-blue-400" />
                      <div>
                        <span className="font-medium text-white block">{file.name}</span>
                        <span className="text-[11px] text-slate-500">{formatFileSize(file.size)}</span>
                      </div>
                    </div>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        handleRemoveFile(idx);
                      }}
                      className="p-1.5 text-slate-400 hover:text-red-400 rounded-lg hover:bg-slate-800 transition-colors"
                      title="Remove file"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Consent Checkbox */}
          <div className="p-4 bg-[#0B0F19] border border-slate-800 rounded-xl">
            <label className="flex items-start gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={consentAgreed}
                onChange={(e) => setConsentAgreed(e.target.checked)}
                className="mt-0.5 rounded bg-slate-900 border-slate-700 text-blue-600 focus:ring-blue-500 cursor-pointer"
              />
              <span className="text-xs text-slate-300 leading-relaxed">
                <strong className="text-white">I agree to analyze these files.</strong> I understand that my uploaded log files are processed in server memory and deleted immediately after the analysis. Only a sanitized summary of findings is recorded.
              </span>
            </label>
          </div>

          {/* Action Buttons */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4 pt-4 border-t border-slate-800">
            <button
              onClick={() => setCurrentStep(1)}
              className="text-xs text-slate-400 hover:text-slate-200 transition-colors"
            >
              &larr; Back to Export Instructions
            </button>

            <button
              onClick={handleStartAnalysis}
              disabled={selectedFiles.length === 0 || !consentAgreed}
              className="w-full sm:w-auto px-6 py-3 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-sm font-medium rounded-xl flex items-center justify-center gap-2 shadow-lg shadow-blue-600/20 transition-all"
            >
              Analyze Logs
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* STEP 3: ANALYZING */}
      {currentStep === 3 && (
        <div className="bg-[#111827] border border-slate-800 rounded-2xl p-10 shadow-xl">
          <Analyzing title="Auditing Telegram Export Snapshot" messages={ANALYZE_MESSAGES} />
        </div>
      )}

      {/* STEP 4: RESULT VIEW */}
      {currentStep === 4 && telegramScan && (
        <div className="space-y-6">
          {/* Result Banner Card */}
          <div className="bg-[#111827] border border-slate-800 rounded-2xl p-6 md:p-8 shadow-xl relative overflow-hidden">
            <div className="flex flex-col md:flex-row items-center justify-between gap-6">
              <div className="space-y-2 text-center md:text-left">
                <div className="flex flex-wrap items-center justify-center md:justify-start gap-2">
                  <span className="px-2.5 py-1 rounded-md text-xs font-semibold bg-blue-500/20 text-blue-300 border border-blue-500/30">
                    Offline Export Analysis
                  </span>
                  <RiskBadge level={telegramScan.riskLevel} />
                </div>
                <h2 className="text-2xl font-bold text-white tracking-tight">
                  Telegram Forensic Verdict: {telegramScan.riskLevel.toUpperCase()} RISK
                </h2>
                <p className="text-sm text-slate-300 max-w-xl">{telegramScan.summary}</p>
                {telegramScan.detectedFiles && (
                  <div className="flex flex-wrap items-center gap-3 pt-2 text-xs text-slate-400">
                    <span className="inline-flex items-center gap-1">
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                      Sessions: {telegramScan.detectedFiles.sessions ? 'Detected' : 'Not included'}
                    </span>
                    <span className="inline-flex items-center gap-1">
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                      Login Alerts: {telegramScan.detectedFiles.loginAlerts ? 'Detected' : 'Not included'}
                    </span>
                    {telegramScan.detectedFiles.ignoredNonServiceChats > 0 && (
                      <span className="text-amber-400">
                        ({telegramScan.detectedFiles.ignoredNonServiceChats} personal chat ignored)
                      </span>
                    )}
                  </div>
                )}
              </div>

              <div className="shrink-0 flex flex-col items-center">
                <RiskGauge score={telegramScan.riskScore} size="lg" />
              </div>
            </div>
          </div>

          {/* What These Logs Could NOT Show Card (Part C.4 / B.4 requirement) */}
          <div className="bg-[#111827] border border-blue-900/40 rounded-2xl p-6 space-y-4 shadow-lg">
            <div className="flex items-center gap-2.5 text-blue-400">
              <Info className="w-5 h-5 shrink-0" />
              <h3 className="text-base font-semibold text-white">What These Export Logs Could Not Show</h3>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              {telegramScan.dataCoverage ||
                'Telegram snapshot exports cannot verify real-time Two-Step Verification status or prove who physically operated the authorized devices.'}
            </p>
            <div className="bg-[#0B0F19] border border-slate-800 rounded-xl p-4 space-y-2">
              <span className="text-xs font-semibold text-slate-200 uppercase tracking-wider block">
                Required Manual Verification Checks:
              </span>
              <ul className="space-y-1.5 text-xs text-slate-300">
                {(telegramScan.manualChecks || [
                  'Turn on Two-Step Verification (Settings > Privacy and Security > Two-Step Verification).',
                  'Add a verified recovery email address.',
                  'Review Active Sessions periodically in Settings > Devices.',
                  'Audit Phone Number Privacy settings to ensure your number is private.',
                ]).map((checkText, idx) => (
                  <li key={idx} className="flex items-start gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                    <span>{checkText}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {/* Active Sessions Table */}
          {telegramScan.sessions.length > 0 && (
            <div className="bg-[#111827] border border-slate-800 rounded-2xl p-6 space-y-4 shadow-xl">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Laptop className="w-4 h-4 text-blue-400" />
                Active Sessions Identified ({telegramScan.sessions.length})
              </h3>
              <SessionTable sessions={telegramScan.sessions} />
            </div>
          )}

          {/* Forensic Findings */}
          {telegramScan.findings.length > 0 && (
            <div className="bg-[#111827] border border-slate-800 rounded-2xl p-6 space-y-4 shadow-xl">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                Identified Security Findings ({telegramScan.findings.length})
              </h3>
              <div className="space-y-3">
                {telegramScan.findings.map((f) => (
                  <div
                    key={f.id}
                    className="p-4 bg-[#0B0F19] border border-slate-800 rounded-xl flex items-start justify-between gap-4"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-sm text-white">{f.title}</span>
                        {f.date && <span className="text-[11px] text-slate-500 font-mono">({f.date})</span>}
                      </div>
                      <p className="text-xs text-slate-300 leading-relaxed">{f.explanation}</p>
                    </div>
                    <RiskBadge level={f.risk} />
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Action Checklist */}
          {telegramScan.actionChecklist.length > 0 && (
            <div className="bg-[#111827] border border-slate-800 rounded-2xl p-6 space-y-3 shadow-xl">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                Recommended Immediate Actions
              </h3>
              <ul className="space-y-2">
                {telegramScan.actionChecklist.map((action, idx) => (
                  <li key={idx} className="p-3 bg-[#0B0F19] border border-slate-800 rounded-xl text-xs text-slate-200 flex items-center gap-2.5">
                    <span className="w-5 h-5 rounded-full bg-blue-500/20 text-blue-400 font-bold flex items-center justify-center shrink-0 text-[10px]">
                      {idx + 1}
                    </span>
                    <span>{action}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Action Buttons */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4 pt-4">
            <button
              onClick={handleReset}
              className="px-4 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium rounded-xl flex items-center gap-2 transition-colors"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              Scan Another Export
            </button>

            <Link
              to="/report"
              className="w-full sm:w-auto px-6 py-3 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium rounded-xl flex items-center justify-center gap-2 shadow-lg shadow-blue-600/20 transition-all"
            >
              View Full Incident Dossier
              <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
        </div>
      )}
    </div>
  );
};
