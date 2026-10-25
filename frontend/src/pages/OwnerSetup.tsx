import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Settings,
  AlertTriangle,
  RotateCcw,
  ExternalLink,
  CheckCircle2,
  XCircle,
  Key,
  GitBranch,
  Terminal,
  ArrowLeft,
  Send,
  Lock,
} from 'lucide-react';
import { useScan } from '../context/ScanContext';

export const OwnerSetup: React.FC = () => {
  const { systemStatus, refreshStatus, addToast } = useScan();
  const [isChecking, setIsChecking] = useState(false);

  const handleRecheck = async () => {
    setIsChecking(true);
    try {
      await refreshStatus();
      addToast({
        type: 'info',
        title: 'Status Refreshed',
        message: 'Checked backend integration status.',
      });
    } catch {
      addToast({
        type: 'error',
        title: 'Check Failed',
        message: 'Could not contact backend at http://localhost:8000.',
      });
    } finally {
      setIsChecking(false);
    }
  };

  const isTgReady = Boolean(systemStatus?.telegram);
  const isGitReady = Boolean(systemStatus?.gitInstalled);

  return (
    <div className="max-w-4xl mx-auto space-y-8 pb-12">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-6">
        <div>
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-xs font-semibold uppercase tracking-wider mb-2">
            <Settings size={13} />
            <span>Service Administration</span>
          </div>
          <h1 className="text-3xl font-extrabold text-white tracking-tight">
            Owner Setup Instructions
          </h1>
          <p className="text-slate-400 text-sm mt-1 max-w-xl">
            Configure backend API keys, MTProto credentials, and external intelligence integrations for this deployment.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Link
            to="/telegram"
            className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-750 text-slate-300 hover:text-white border border-slate-700 text-xs font-semibold transition-colors"
          >
            <ArrowLeft size={14} />
            <span>Back to Telegram</span>
          </Link>
          <button
            type="button"
            disabled={isChecking}
            onClick={handleRecheck}
            className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs disabled:opacity-50 transition-colors shadow-glow"
          >
            <RotateCcw size={13} className={isChecking ? 'animate-spin' : ''} />
            <span>{isChecking ? 'Checking...' : 'Re-check Configuration'}</span>
          </button>
        </div>
      </div>

      {/* Integration Status Grid */}
      <div className="glass-card rounded-2xl p-6 border border-slate-800 space-y-4">
        <h2 className="text-sm font-bold uppercase tracking-wider text-slate-300">
          Live Service Status
        </h2>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3.5">
          {/* Telegram */}
          <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 flex items-start justify-between">
            <div>
              <div className="flex items-center gap-2 font-semibold text-sm text-white">
                <Send size={15} className="text-sky-400" />
                <span>Telegram MTProto</span>
              </div>
              <p className="text-xs text-slate-400 mt-1">Required for session audit</p>
            </div>
            {isTgReady ? (
              <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
                <CheckCircle2 size={13} /> Active
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full bg-amber-500/10 border border-amber-500/30 text-amber-400 text-xs font-semibold">
                <AlertTriangle size={13} /> Missing
              </span>
            )}
          </div>

          {/* Git CLI */}
          <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 flex items-start justify-between">
            <div>
              <div className="flex items-center gap-2 font-semibold text-sm text-white">
                <GitBranch size={15} className="text-purple-400" />
                <span>Git CLI</span>
              </div>
              <p className="text-xs text-slate-400 mt-1">Required for repo clone</p>
            </div>
            {isGitReady ? (
              <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
                <CheckCircle2 size={13} /> Installed
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-semibold">
                <XCircle size={13} /> Missing
              </span>
            )}
          </div>

          {/* Bandit Code Analyzer */}
          <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 flex items-start justify-between">
            <div>
              <div className="flex items-center gap-2 font-semibold text-sm text-white">
                <Terminal size={15} className="text-blue-400" />
                <span>Bandit Analyzer</span>
              </div>
              <p className="text-xs text-slate-400 mt-1">Python AST security scan</p>
            </div>
            {systemStatus?.banditAvailable ? (
              <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
                <CheckCircle2 size={13} /> Available
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full bg-slate-800 text-slate-400 text-xs">
                Optional
              </span>
            )}
          </div>

          {/* AbuseIPDB */}
          <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 flex items-start justify-between">
            <div>
              <div className="flex items-center gap-2 font-semibold text-sm text-white">
                <Key size={15} className="text-amber-400" />
                <span>AbuseIPDB Key</span>
              </div>
              <p className="text-xs text-slate-400 mt-1">IP threat reputation</p>
            </div>
            {systemStatus?.abuseipdb ? (
              <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
                <CheckCircle2 size={13} /> Configured
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full bg-slate-800 text-slate-400 text-xs">
                Optional
              </span>
            )}
          </div>

          {/* VirusTotal */}
          <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 flex items-start justify-between">
            <div>
              <div className="flex items-center gap-2 font-semibold text-sm text-white">
                <Key size={15} className="text-teal-400" />
                <span>VirusTotal Key</span>
              </div>
              <p className="text-xs text-slate-400 mt-1">Phishing & URL lookup</p>
            </div>
            {systemStatus?.virustotal ? (
              <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
                <CheckCircle2 size={13} /> Configured
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full bg-slate-800 text-slate-400 text-xs">
                Optional
              </span>
            )}
          </div>

          {/* GitHub Token */}
          <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 flex items-start justify-between">
            <div>
              <div className="flex items-center gap-2 font-semibold text-sm text-white">
                <Key size={15} className="text-indigo-400" />
                <span>GitHub Token</span>
              </div>
              <p className="text-xs text-slate-400 mt-1">Higher API rate limits</p>
            </div>
            {systemStatus?.githubToken ? (
              <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
                <CheckCircle2 size={13} /> Configured
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full bg-slate-800 text-slate-400 text-xs">
                Optional
              </span>
            )}
          </div>
        </div>
      </div>

      {/* Telegram Setup Card */}
      <div className="glass-card rounded-2xl p-6 sm:p-8 border border-slate-800 space-y-6">
        <div className="flex items-start gap-4">
          <div className="p-3 rounded-2xl bg-sky-500/10 border border-sky-500/20 text-sky-400 shrink-0">
            <Send size={24} />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white">
              How to Connect Telegram (3 Simple Steps)
            </h2>
            <p className="text-sm text-slate-400 mt-1">
              Telegram requires a free application ID and hash to allow reading active session logs via MTProto.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Step 1 */}
          <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-3">
            <div className="flex items-center gap-2 text-cyan-400 font-bold text-sm">
              <span className="w-6 h-6 rounded-full bg-cyan-500/20 text-cyan-300 flex items-center justify-center text-xs font-mono">1</span>
              <span>Get Free Telegram Keys</span>
            </div>
            <p className="text-slate-300 text-xs leading-relaxed">
              Open{' '}
              <a
                href="https://my.telegram.org"
                target="_blank"
                rel="noopener noreferrer"
                className="text-cyan-400 hover:underline font-semibold inline-flex items-center gap-1"
              >
                my.telegram.org <ExternalLink size={12} />
              </a>{' '}
              and sign in with your Telegram phone number.
            </p>
            <p className="text-slate-400 text-xs leading-relaxed">
              Navigate to <strong>API development tools</strong>. Enter any App title (e.g. <code>ABI Security</code>), a short name, select <strong>Desktop</strong>, and submit to generate your <code>api_id</code> (numbers) and <code>api_hash</code> (hex string).
            </p>
          </div>

          {/* Step 2 */}
          <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-3">
            <div className="flex items-center gap-2 text-cyan-400 font-bold text-sm">
              <span className="w-6 h-6 rounded-full bg-cyan-500/20 text-cyan-300 flex items-center justify-center text-xs font-mono">2</span>
              <span>Add to backend/.env</span>
            </div>
            <p className="text-slate-300 text-xs leading-relaxed">
              Open the configuration file <code className="bg-slate-950 px-1.5 py-0.5 rounded text-amber-300">backend/.env</code> and paste your credentials:
            </p>
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 font-mono text-xs text-amber-300 select-all leading-relaxed">
              TELEGRAM_API_ID=12345678<br />
              TELEGRAM_API_HASH=0123456789abcdef0123456789abcdef
            </div>
            <p className="text-slate-400 text-xs">
              Save the file. The FastAPI server automatically reloads configuration upon save.
            </p>
          </div>

          {/* Step 3 */}
          <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-3">
            <div className="flex items-center gap-2 text-cyan-400 font-bold text-sm">
              <span className="w-6 h-6 rounded-full bg-cyan-500/20 text-cyan-300 flex items-center justify-center text-xs font-mono">3</span>
              <span>Re-check Configuration</span>
            </div>
            <p className="text-slate-300 text-xs leading-relaxed">
              Click the <strong>Re-check Configuration</strong> button at the top of this page.
            </p>
            <p className="text-emerald-400 text-xs font-medium leading-relaxed">
              ✓ Once active, end users can audit their Telegram accounts with phone SMS/app verification codes or QR code scanning.
            </p>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-cyan-950/20 border border-cyan-800/30 flex items-start gap-3">
          <Lock size={18} className="text-cyan-400 shrink-0 mt-0.5" />
          <div className="text-xs text-slate-300 leading-relaxed">
            <strong className="text-cyan-300 block mb-1">Zero Credentials Leakage</strong>
            The backend API never exposes your keys, tokens, or environment values through any endpoint. Sessions run entirely in ephemeral memory and automatically log out when inspection finishes.
          </div>
        </div>
      </div>
    </div>
  );
};
