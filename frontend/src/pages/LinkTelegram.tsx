import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Send,
  ShieldCheck,
  ShieldAlert,
  Lock,
  Eye,
  CheckCircle,
  AlertTriangle,
  ArrowRight,
  RotateCcw,
  Smartphone,
  KeyRound,
  FileText,
  HelpCircle,
  Laptop,
  Globe,
  Footprints,
  Compass,
  Link2,
} from 'lucide-react';
import { Stepper, StepItem } from '../components/Stepper';
import { Analyzing } from '../components/Analyzing';
import { RiskGauge } from '../components/RiskGauge';
import { RiskBadge } from '../components/RiskBadge';
import { SessionTable } from '../components/SessionTable';
import { useScan } from '../context/ScanContext';
import { analyzeTelegram } from '../lib/api';
import { TelegramScanResult, TelegramFindingType } from '../lib/types';

const STEPS: StepItem[] = [
  { id: 1, title: 'Consent', description: 'Read-only safety guarantee' },
  { id: 2, title: 'Connect', description: 'Phone & verification code' },
  { id: 3, title: 'Analyze', description: 'Deep security inspection' },
  { id: 4, title: 'Result', description: 'Breach verdict & fixes' },
];

const ANALYZE_MESSAGES = [
  'Connecting to Telegram session auditor...',
  'Checking active sessions and devices...',
  'Looking up login locations & IP geolocations...',
  'Checking for impossible travel across continents...',
  'Evaluating Two-Step Password protection status...',
  'Calculating risk and compiling plain-English verdict...',
];

export const LinkTelegram: React.FC = () => {
  const { telegramScan, setTelegramScan } = useScan();

  // If already scanned previously, default to Step 4, otherwise Step 1
  const [step, setStep] = useState<number>(telegramScan ? 4 : 1);
  const [agreedToConsent, setAgreedToConsent] = useState(false);
  const [phone, setPhone] = useState('+1 (555) 019-2834');
  const [otp, setOtp] = useState('');
  const [otpSent, setOtpSent] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [activeChecklist, setActiveChecklist] = useState<Record<number, boolean>>({});

  const handleStartAnalysis = async () => {
    if (!phone || phone.trim().length < 8) {
      setErrorMsg('Please enter a valid international phone number.');
      return;
    }
    if (!otp || otp.trim().length < 4) {
      setErrorMsg('Please enter the 5-digit verification code sent to your Telegram app.');
      return;
    }

    setErrorMsg(null);
    setStep(3);

    try {
      const result: TelegramScanResult = await analyzeTelegram(phone, otp);
      setTelegramScan(result);
      setStep(4);
    } catch {
      setErrorMsg('Could not complete security inspection. Please check your credentials.');
      setStep(2);
    }
  };

  const handleSendOtp = () => {
    if (!phone || phone.trim().length < 8) {
      setErrorMsg('Please enter a valid phone number first.');
      return;
    }
    setErrorMsg(null);
    setOtpSent(true);
    setOtp('59381'); // Pre-fill realistic code for smooth testing
  };

  const toggleChecklist = (index: number) => {
    setActiveChecklist((prev) => ({
      ...prev,
      [index]: !prev[index],
    }));
  };

  const getFindingIcon = (type: TelegramFindingType) => {
    switch (type) {
      case 'unknown_device':
        return <Laptop size={18} className="text-red-400" />;
      case 'foreign_login':
        return <Globe size={18} className="text-orange-400" />;
      case 'impossible_travel':
        return <Footprints size={18} className="text-red-400" />;
      case 'no_2fa':
        return <Lock size={18} className="text-amber-400" />;
      case 'suspicious_link':
        return <Link2 size={18} className="text-yellow-400" />;
      default:
        return <AlertTriangle size={18} className="text-yellow-400" />;
    }
  };

  const scanData = telegramScan;

  return (
    <div className="max-w-4xl mx-auto space-y-8 animate-fadeIn">
      {/* Header */}
      <div className="text-center space-y-2">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-sky-500/10 border border-sky-500/20 text-sky-400 text-xs font-semibold uppercase tracking-wider">
          <Send size={13} />
          <span>Telegram Account Investigation</span>
        </div>
        <h1 className="text-3xl font-extrabold text-white tracking-tight">
          Find Out If Someone Is In Your Telegram
        </h1>
        <p className="text-slate-400 text-sm max-w-xl mx-auto">
          We inspect active sessions, unfamiliar devices, and foreign logins using plain English so you know exactly what is happening.
        </p>
      </div>

      {/* Stepper Component */}
      <div className="glass-card rounded-2xl p-4 sm:p-6 border border-slate-800">
        <Stepper steps={STEPS} currentStep={step} />
      </div>

      {/* STEP 1: CONSENT */}
      {step === 1 && (
        <div className="glass-card rounded-2xl p-6 sm:p-8 border border-slate-800 space-y-6">
          <div className="flex items-start gap-4">
            <div className="p-3 rounded-2xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 shrink-0">
              <ShieldCheck size={28} />
            </div>
            <div>
              <h2 className="text-xl font-bold text-white">Your Privacy & Consent First</h2>
              <p className="text-sm text-slate-300 mt-1 leading-relaxed">
                Before connecting, please review exactly what this tool inspects. We believe in complete transparency.
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
            <div className="p-4 rounded-xl bg-[#0B1220] border border-slate-800 space-y-2">
              <div className="flex items-center gap-2 text-cyan-400 font-semibold text-sm">
                <Laptop size={16} />
                <span>1. Active Sessions</span>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">
                We read the list of computers, tablets, and phones currently connected to your profile and their IP locations.
              </p>
            </div>

            <div className="p-4 rounded-xl bg-[#0B1220] border border-slate-800 space-y-2">
              <div className="flex items-center gap-2 text-cyan-400 font-semibold text-sm">
                <Eye size={16} />
                <span>2. Login Alerts</span>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">
                We check official Telegram notifications for warning alerts about logins from new cities or strange IP addresses.
              </p>
            </div>

            <div className="p-4 rounded-xl bg-[#0B1220] border border-slate-800 space-y-2">
              <div className="flex items-center gap-2 text-cyan-400 font-semibold text-sm">
                <Lock size={16} />
                <span>3. Two-Step Password</span>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">
                We verify whether you have a secondary cloud password set up to prevent SMS interception attacks.
              </p>
            </div>
          </div>

          <div className="p-4 rounded-xl bg-cyan-950/20 border border-cyan-800/30 flex items-start gap-3">
            <Lock size={18} className="text-cyan-400 shrink-0 mt-0.5" />
            <div className="text-xs text-slate-300 leading-relaxed space-y-1">
              <span className="font-bold text-cyan-300 block">Strict Zero-Storage Guarantee</span>
              <p>
                We do not read your private chat messages, photos, contacts, or voice notes. We never store your phone number or access codes. All audit calculations happen in real-time memory and are cleared when you close your browser.
              </p>
            </div>
          </div>

          <div className="pt-2">
            <label className="flex items-start gap-3 cursor-pointer group select-none">
              <input
                type="checkbox"
                checked={agreedToConsent}
                onChange={(e) => setAgreedToConsent(e.target.checked)}
                className="mt-1 h-4 w-4 rounded border-slate-700 bg-slate-900 text-cyan-500 focus:ring-cyan-400 focus:ring-offset-slate-950 transition-colors"
              />
              <span className="text-sm text-slate-300 group-hover:text-white transition-colors">
                I understand and agree to run a read-only cybersecurity investigation on my Telegram account.
              </span>
            </label>
          </div>

          <div className="flex items-center justify-end gap-3 pt-4 border-t border-slate-800">
            <button
              disabled={!agreedToConsent}
              onClick={() => setStep(2)}
              className="flex items-center gap-2 px-6 py-2.5 rounded-xl bg-cyan-400 text-slate-950 font-bold text-sm hover:bg-cyan-300 disabled:opacity-40 disabled:cursor-not-allowed transition-all shadow-glow hover:shadow-glow-lg"
            >
              <span>Continue to Connect</span>
              <ArrowRight size={16} />
            </button>
          </div>
        </div>
      )}

      {/* STEP 2: CONNECT */}
      {step === 2 && (
        <div className="glass-card rounded-2xl p-6 sm:p-8 border border-slate-800 space-y-6">
          <div className="flex items-start justify-between">
            <div>
              <h2 className="text-xl font-bold text-white">Connect Telegram for Audit</h2>
              <p className="text-sm text-slate-400 mt-1">
                Enter your international phone number to receive a temporary one-time verification code.
              </p>
            </div>
            <button
              onClick={() => setStep(1)}
              className="text-xs text-slate-400 hover:text-white"
            >
              Back to Consent
            </button>
          </div>

          {errorMsg && (
            <div className="p-3.5 rounded-xl bg-red-500/10 border border-red-500/30 text-red-300 text-xs flex items-center gap-2">
              <AlertTriangle size={15} className="shrink-0" />
              <span>{errorMsg}</span>
            </div>
          )}

          <div className="space-y-4 max-w-lg">
            {/* Phone input */}
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1.5">
                Phone Number (with Country Code)
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
                  <Smartphone size={17} />
                </div>
                <input
                  type="text"
                  value={phone}
                  onChange={(e) => setPhone(e.target.value)}
                  placeholder="+1 (555) 000-0000"
                  className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-slate-900 border border-slate-700 text-white placeholder-slate-500 text-sm focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 transition-colors"
                />
              </div>
              <p className="text-[11px] text-slate-400 mt-1">
                Tip: Enter your real test number, or leave the demo number as is.
              </p>
            </div>

            {/* OTP Section */}
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300">
                  Telegram Verification Code (OTP)
                </label>
                {!otpSent ? (
                  <button
                    type="button"
                    onClick={handleSendOtp}
                    className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold"
                  >
                    Send Verification Code
                  </button>
                ) : (
                  <span className="text-xs text-emerald-400 font-medium flex items-center gap-1">
                    <CheckCircle size={12} /> Code Sent to Telegram App
                  </span>
                )}
              </div>

              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
                  <KeyRound size={17} />
                </div>
                <input
                  type="text"
                  value={otp}
                  onChange={(e) => setOtp(e.target.value)}
                  placeholder="e.g. 59381"
                  className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-slate-900 border border-slate-700 text-white placeholder-slate-500 text-sm font-mono tracking-widest focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 transition-colors"
                />
              </div>
              <p className="text-[11px] text-slate-400 mt-1">
                Telegram sends this code inside your official Telegram app, not via SMS.
              </p>
            </div>
          </div>

          <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 text-xs text-slate-400 flex items-center gap-2">
            <HelpCircle size={15} className="text-cyan-400 shrink-0" />
            <span>
              Clicking <strong>Connect & Analyze</strong> performs a simulated read-only security query against your active Telegram sessions.
            </span>
          </div>

          <div className="flex items-center justify-end gap-3 pt-4 border-t border-slate-800">
            <button
              onClick={handleStartAnalysis}
              className="flex items-center gap-2 px-6 py-2.5 rounded-xl bg-cyan-400 text-slate-950 font-bold text-sm hover:bg-cyan-300 transition-all shadow-glow hover:shadow-glow-lg"
            >
              <span>Connect & Run Audit</span>
              <ArrowRight size={16} />
            </button>
          </div>
        </div>
      )}

      {/* STEP 3: ANALYZE */}
      {step === 3 && (
        <Analyzing
          messages={ANALYZE_MESSAGES}
          title="Investigating Telegram Session Footprints"
          subtitle="Looking for unauthorized foreign logins, impossible travel, and unverified devices..."
        />
      )}

      {/* STEP 4: RESULT */}
      {step === 4 && scanData && (
        <div className="space-y-6">
          {/* Main Verdict Card with Large Risk Gauge */}
          <div className="glass-card rounded-2xl p-6 sm:p-8 border border-slate-800 flex flex-col md:flex-row items-center justify-between gap-6">
            <div className="flex-1 space-y-3 text-center md:text-left">
              <div className="flex flex-wrap items-center justify-center md:justify-start gap-2">
                <RiskBadge level={scanData.riskLevel} size="lg" />
                <span className="text-xs text-slate-400 font-mono">
                  Target: {scanData.phone}
                </span>
              </div>
              <h2 className="text-2xl font-extrabold text-white">
                {scanData.riskLevel === 'critical' || scanData.riskLevel === 'high'
                  ? 'Compromise Evidence Identified'
                  : 'Your Telegram Account Is Clean'}
              </h2>
              <p className="text-sm text-slate-300 leading-relaxed max-w-xl">
                {scanData.summary}
              </p>
            </div>

            <div className="shrink-0 flex flex-col items-center">
              <RiskGauge score={scanData.riskScore} level={scanData.riskLevel} size="lg" />
            </div>
          </div>

          {/* Active Sessions Table */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-lg font-bold text-white">Active Sessions & Logged-In Devices</h3>
                <p className="text-xs text-slate-400">
                  Every computer, phone, or application that currently has access to your chats.
                </p>
              </div>
              <span className="text-xs font-semibold text-cyan-400">
                {scanData.sessions.length} Sessions Detected
              </span>
            </div>
            <SessionTable
              sessions={scanData.sessions}
              onTerminateSession={(id) => {
                const updated = {
                  ...scanData,
                  sessions: scanData.sessions.filter((s) => s.id !== id),
                };
                setTelegramScan(updated);
              }}
            />
          </div>

          {/* Security Findings List */}
          <div className="space-y-3">
            <h3 className="text-lg font-bold text-white">Security Findings & Red Flags</h3>
            <div className="space-y-3">
              {scanData.findings.map((f) => (
                <div
                  key={f.id}
                  className={`glass-card rounded-2xl p-5 border border-slate-800 flex items-start gap-4 ${
                    f.risk === 'critical'
                      ? 'border-l-4 border-l-red-500'
                      : f.risk === 'high'
                      ? 'border-l-4 border-l-orange-500'
                      : 'border-l-4 border-l-yellow-500'
                  }`}
                >
                  <div className="p-2.5 rounded-xl bg-slate-800 text-white shrink-0 border border-slate-700/80">
                    {getFindingIcon(f.type)}
                  </div>
                  <div className="flex-1">
                    <div className="flex flex-wrap items-center justify-between gap-2 mb-1">
                      <h4 className="text-sm font-bold text-white">{f.title}</h4>
                      <RiskBadge level={f.risk} size="sm" />
                    </div>
                    <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
                      {f.explanation}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* How It Likely Happened */}
          <div className="glass-card rounded-2xl p-6 border border-slate-800 bg-gradient-to-br from-[#111A2E] to-[#0D1526] space-y-3">
            <div className="flex items-center gap-2.5 text-cyan-400">
              <Compass size={20} />
              <h3 className="text-base font-bold text-white">How It Likely Happened</h3>
            </div>
            <p className="text-sm text-slate-300 leading-relaxed">
              {scanData.howItHappened}
            </p>
          </div>

          {/* What To Do Now Checklist */}
          <div className="glass-card rounded-2xl p-6 border border-slate-800 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-base font-bold text-white">What You Should Do Right Now</h3>
                <p className="text-xs text-slate-400">Follow these plain-English steps to kick out the intruder.</p>
              </div>
              <span className="text-xs text-cyan-400 font-mono">
                {Object.values(activeChecklist).filter(Boolean).length}/{scanData.actionChecklist.length} Done
              </span>
            </div>

            <div className="space-y-2.5">
              {scanData.actionChecklist.map((action, idx) => {
                const isChecked = !!activeChecklist[idx];
                return (
                  <div
                    key={idx}
                    onClick={() => toggleChecklist(idx)}
                    className={`p-3.5 rounded-xl border transition-all cursor-pointer flex items-start gap-3 ${
                      isChecked
                        ? 'bg-emerald-950/20 border-emerald-800/40 text-emerald-200'
                        : 'bg-[#0B1220] border-slate-800 text-slate-300 hover:border-slate-700'
                    }`}
                  >
                    <div
                      className={`w-5 h-5 rounded-md flex items-center justify-center shrink-0 mt-0.5 transition-colors ${
                        isChecked ? 'bg-emerald-500 text-slate-950' : 'border border-slate-600 bg-slate-900'
                      }`}
                    >
                      {isChecked && <CheckCircle size={14} />}
                    </div>
                    <span className={`text-xs sm:text-sm leading-relaxed ${isChecked ? 'line-through text-slate-400' : ''}`}>
                      {action}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Bottom Actions */}
          <div className="flex flex-wrap items-center justify-between gap-4 pt-4 border-t border-slate-800">
            <button
              onClick={() => {
                setStep(1);
                setAgreedToConsent(false);
              }}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-750 text-xs font-semibold text-slate-300 border border-slate-700 transition-colors"
            >
              <RotateCcw size={14} />
              <span>Audit Another Number</span>
            </button>

            <div className="flex items-center gap-3">
              <Link
                to="/repo"
                className="flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-750 text-xs font-semibold text-white border border-slate-700 transition-colors"
              >
                <span>Check Your GitHub Repo</span>
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
