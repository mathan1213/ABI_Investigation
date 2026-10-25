import React, { useState, useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import { QRCodeSVG } from 'qrcode.react';
import {
  Send,
  ShieldCheck,
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
  Compass,
  Loader2,
  ExternalLink,
  QrCode,
  Globe,
  Footprints,
  Link2,
} from 'lucide-react';
import { Stepper, StepItem } from '../components/Stepper';
import { Analyzing } from '../components/Analyzing';
import { RiskGauge } from '../components/RiskGauge';
import { RiskBadge } from '../components/RiskBadge';
import { SessionTable } from '../components/SessionTable';
import { useScan } from '../context/ScanContext';
import {
  sendTelegramCode,
  resendTelegramCode,
  startTelegramQr,
  getTelegramQrStatus,
  verifyTelegramCode,
  analyzeTelegram,
  cancelTelegram,
} from '../lib/api';
import { TelegramScanResult, TelegramFindingType } from '../lib/types';
import {
  COUNTRIES,
  splitAndCleanPhoneNumber,
  validateNationalPhone,
  maskE164Phone,
} from '../lib/phoneUtils';

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
  'Auditing official Telegram security service notifications...',
  'Calculating risk and compiling plain-English verdict...',
  'Logging out security inspection session permanently...',
];

export const LinkTelegram: React.FC = () => {
  const { telegramScan, setTelegramScan, addToast, systemStatus, refreshStatus } = useScan();

  // If already scanned previously, default to Step 4, otherwise Step 1
  const [step, setStep] = useState<number>(telegramScan ? 4 : 1);
  const [agreedToConsent, setAgreedToConsent] = useState(false);

  // Phone input states
  const [countryCode, setCountryCode] = useState('+91');
  const [nationalPhone, setNationalPhone] = useState('');
  const [maskedPhone, setMaskedPhone] = useState('');

  // Flow & auth states
  const [flowId, setFlowId] = useState<string | null>(null);
  const [otp, setOtp] = useState('');
  const [password, setPassword] = useState('');
  const [needsPassword, setNeedsPassword] = useState(false);
  const [otpSent, setOtpSent] = useState(false);
  const [codeType, setCodeType] = useState<'app' | 'sms' | 'call' | 'other'>('app');
  const [nextType, setNextType] = useState<'sms' | 'call' | 'other' | null>(null);
  const [countdown, setCountdown] = useState<number>(0);
  const [isResending, setIsResending] = useState(false);

  // QR Mode states
  const [isQrMode, setIsQrMode] = useState(false);
  const [qrUrl, setQrUrl] = useState<string>('');
  const [qrExpiresIn, setQrExpiresIn] = useState<number>(60);
  const [isStartingQr, setIsStartingQr] = useState(false);

  // Progress & loading states
  const [isDemo, setIsDemo] = useState(false);
  const [isSendingCode, setIsSendingCode] = useState(false);
  const [isVerifying, setIsVerifying] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [activeChecklist, setActiveChecklist] = useState<Record<number, boolean>>({});

  const qrPollRef = useRef<number | null>(null);

  // Countdown timer effect for code resend
  useEffect(() => {
    if (countdown <= 0) return;
    const timer = setInterval(() => {
      setCountdown((prev) => (prev > 0 ? prev - 1 : 0));
    }, 1000);
    return () => clearInterval(timer);
  }, [countdown]);

  // QR Code polling effect
  useEffect(() => {
    if (!isQrMode || !flowId || step !== 2) {
      if (qrPollRef.current) {
        clearInterval(qrPollRef.current);
        qrPollRef.current = null;
      }
      return;
    }

    const pollStatus = async () => {
      try {
        const res = await getTelegramQrStatus(flowId);
        if (res.status === 'scanned') {
          if (qrPollRef.current) clearInterval(qrPollRef.current);
          addToast({
            type: 'success',
            title: 'QR Code Scanned',
            message: 'Telegram app authorized! Starting security inspection...',
          });
          setStep(3);
          runAnalysis(flowId);
        } else if (res.status === 'needsPassword') {
          if (qrPollRef.current) clearInterval(qrPollRef.current);
          setNeedsPassword(true);
          addToast({
            type: 'warning',
            title: 'Cloud Password Required',
            message: 'Your account has Two-Step Verification enabled.',
          });
        } else if (res.status === 'expired') {
          if (res.qrUrl) {
            setQrUrl(res.qrUrl);
            setQrExpiresIn(res.expiresIn || 60);
          }
        }
      } catch (err: any) {
        // Silently tolerate transient poll error
      }
    };

    qrPollRef.current = window.setInterval(pollStatus, 2000);
    return () => {
      if (qrPollRef.current) {
        clearInterval(qrPollRef.current);
        qrPollRef.current = null;
      }
    };
  }, [isQrMode, flowId, step]);

  // Cleanup on unmount if in-flight flow exists
  useEffect(() => {
    return () => {
      if (flowId && step < 4) {
        cancelTelegram(flowId);
      }
    };
  }, [flowId, step]);

  const phoneValidation = validateNationalPhone(countryCode, nationalPhone);

  const handlePhoneChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const raw = e.target.value;
    const res = splitAndCleanPhoneNumber(raw, countryCode);
    setCountryCode(res.countryCode);
    setNationalPhone(res.nationalNumber);
    if (otpSent) {
      setOtpSent(false);
      setFlowId(null);
      setNeedsPassword(false);
    }
  };

  const handleSendCode = async () => {
    if (!phoneValidation.isValid) {
      setErrorMsg(phoneValidation.message);
      return;
    }

    const e164 = `${countryCode}${nationalPhone}`;
    const masked = maskE164Phone(countryCode, nationalPhone);
    setMaskedPhone(masked);

    setIsSendingCode(true);
    setErrorMsg(null);

    try {
      const res = await sendTelegramCode(e164);
      setFlowId(res.flowId);
      setIsDemo(!!res.isDemo);
      setOtpSent(true);
      setCodeType(res.codeType || 'app');
      setNextType(res.nextType || null);
      setCountdown(res.timeout ?? 60);

      if (res.isDemo) {
        addToast({
          type: 'info',
          title: 'Demo Mode Active',
          message: 'Explicit demo mode active. Enter any verification code.',
        });
      } else {
        const methodMsg =
          res.codeType === 'sms'
            ? `SMS code sent to ${masked}`
            : 'Telegram sent a code to your official Telegram app.';
        addToast({
          type: 'success',
          title: 'Verification Code Sent',
          message: methodMsg,
        });
      }
    } catch (err: any) {
      const msg = err?.message || 'Failed to send verification code. Please check your phone number.';
      setErrorMsg(msg);
      addToast({
        type: 'error',
        title: 'Could Not Send Code',
        message: msg,
      });
    } finally {
      setIsSendingCode(false);
    }
  };

  const handleResendCode = async () => {
    if (!flowId) return;
    setIsResending(true);
    setErrorMsg(null);

    try {
      const res = await resendTelegramCode(flowId);
      setCodeType(res.codeType || 'app');
      setNextType(res.nextType || null);
      setCountdown(res.timeout ?? 60);

      const deliveryName = res.codeType === 'sms' ? 'SMS' : res.codeType === 'call' ? 'Phone call' : 'Telegram app';
      addToast({
        type: 'success',
        title: 'Code Resent',
        message: `Verification code requested via ${deliveryName}.`,
      });
    } catch (err: any) {
      const msg = err?.message || 'Failed to resend code.';
      setErrorMsg(msg);
      addToast({
        type: 'error',
        title: 'Resend Failed',
        message: msg,
      });
    } finally {
      setIsResending(false);
    }
  };

  const handleStartQr = async () => {
    setIsStartingQr(true);
    setErrorMsg(null);
    try {
      const res = await startTelegramQr();
      setFlowId(res.flowId);
      setQrUrl(res.qrUrl);
      setQrExpiresIn(res.expiresIn || 60);
      setIsQrMode(true);
      setNeedsPassword(false);
      addToast({
        type: 'info',
        title: 'QR Code Ready',
        message: 'Scan the code with your official Telegram mobile app.',
      });
    } catch (err: any) {
      const msg = err?.message || 'Failed to initialize Telegram QR code.';
      setErrorMsg(msg);
      addToast({
        type: 'error',
        title: 'QR Code Error',
        message: msg,
      });
    } finally {
      setIsStartingQr(false);
    }
  };

  const handleCancelQr = () => {
    if (flowId) {
      cancelTelegram(flowId);
    }
    setFlowId(null);
    setIsQrMode(false);
    setNeedsPassword(false);
  };

  const runAnalysis = async (currentFlowId: string) => {
    try {
      const scanResult: TelegramScanResult = await analyzeTelegram(currentFlowId);
      setTelegramScan(scanResult);
      setStep(4);
      addToast({
        type: 'success',
        title: 'Investigation Complete',
        message: 'Telegram session and security footprint audit finished.',
      });
    } catch (err: any) {
      const msg = err?.message || 'Account forensics analysis failed. Please try again.';
      setErrorMsg(msg);
      setStep(2);
      addToast({
        type: 'error',
        title: 'Audit Failed',
        message: msg,
      });
    }
  };

  const handleVerifyAndAnalyze = async () => {
    if (!flowId) {
      setErrorMsg('Please request a verification code or QR session first.');
      return;
    }
    if (!isQrMode && (!otp || otp.trim().length < 4)) {
      setErrorMsg('Please enter the verification code sent by Telegram.');
      return;
    }
    if (needsPassword && (!password || password.trim().length === 0)) {
      setErrorMsg('Please enter your Two-Step Verification cloud password.');
      return;
    }

    setIsVerifying(true);
    setErrorMsg(null);

    try {
      const verifyRes = await verifyTelegramCode(flowId, otp, password);

      if (verifyRes.needsPassword) {
        setNeedsPassword(true);
        setIsVerifying(false);
        addToast({
          type: 'warning',
          title: 'Cloud Password Required',
          message: 'Your Telegram account has Two-Step Verification enabled.',
        });
        return;
      }

      setStep(3);
      await runAnalysis(flowId);
    } catch (err: any) {
      const msg = err?.message || 'Invalid code or password. Please verify and try again.';
      setErrorMsg(msg);
      addToast({
        type: 'error',
        title: 'Verification Failed',
        message: msg,
      });
    } finally {
      setIsVerifying(false);
    }
  };

  const handleAuditAnotherNumber = () => {
    if (flowId) cancelTelegram(flowId);
    setTelegramScan(null);
    setStep(2);
    setNationalPhone('');
    setMaskedPhone('');
    setOtp('');
    setPassword('');
    setNeedsPassword(false);
    setOtpSent(false);
    setIsQrMode(false);
    setFlowId(null);
    setErrorMsg(null);
  };

  const toggleChecklist = (idx: number) => {
    setActiveChecklist((prev) => ({
      ...prev,
      [idx]: !prev[idx],
    }));
  };

  const getFindingIcon = (type: TelegramFindingType) => {
    switch (type) {
      case 'unknown_device':
        return <Laptop size={20} className="text-red-400" />;
      case 'foreign_login':
        return <Globe size={20} className="text-orange-400" />;
      case 'impossible_travel':
        return <Footprints size={20} className="text-red-400" />;
      case 'no_2fa':
        return <Lock size={20} className="text-yellow-400" />;
      case 'suspicious_link':
        return <Link2 size={20} className="text-cyan-400" />;
    }
  };

  const scanData = telegramScan;

  return (
    <div className="max-w-4xl mx-auto space-y-8">
      {/* Top Banner & Header */}
      <div className="text-center space-y-3">
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
                We do not read your private chat messages, photos, contacts, or voice notes. We never store your phone number or access codes. All audit calculations happen in real-time memory and this inspection session is immediately logged out when finished.
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
              <h2 className="text-xl font-bold text-white">
                {isQrMode ? 'Scan QR Code with Telegram' : 'Connect Telegram for Audit'}
              </h2>
              <p className="text-sm text-slate-400 mt-1">
                {isQrMode
                  ? 'Open Telegram on your mobile phone and scan this QR code to authorize inspection.'
                  : 'Enter your mobile number to receive a temporary one-time verification code.'}
              </p>
            </div>
            <button
              onClick={() => {
                if (flowId) cancelTelegram(flowId);
                setStep(1);
              }}
              className="text-xs text-slate-400 hover:text-white transition-colors"
            >
              Back to Consent
            </button>
          </div>

          {/* Service Unavailable Friendly Notice (PART A requirement) */}
          {systemStatus && !systemStatus.telegram && (
            <div className="p-8 rounded-2xl bg-slate-900/90 border border-slate-800 text-center space-y-4">
              <div className="w-14 h-14 rounded-2xl bg-amber-500/10 border border-amber-500/30 text-amber-400 flex items-center justify-center mx-auto">
                <AlertTriangle size={28} />
              </div>
              <div className="space-y-1.5">
                <h3 className="text-lg font-bold text-white">
                  Telegram linking is not available right now.
                </h3>
                <p className="text-sm text-slate-400 max-w-md mx-auto">
                  The service owner needs to finish a one-time setup.
                </p>
              </div>
              <div className="pt-2 flex flex-col sm:flex-row items-center justify-center gap-3">
                <Link
                  to="/setup"
                  className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold underline inline-flex items-center gap-1"
                >
                  <span>Owner setup instructions</span>
                  <ExternalLink size={12} />
                </Link>
                <button
                  type="button"
                  onClick={async () => {
                    await refreshStatus();
                    addToast({
                      type: 'info',
                      title: 'Configuration Checked',
                      message: 'Backend status re-checked.',
                    });
                  }}
                  className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-750 text-slate-300 border border-slate-700 text-xs font-semibold flex items-center gap-1.5 transition-colors"
                >
                  <RotateCcw size={12} />
                  <span>Re-check configuration</span>
                </button>
              </div>
            </div>
          )}

          {/* Demo Mode Notice Banner */}
          {isDemo && (
            <div className="p-3.5 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs flex items-center gap-2.5">
              <AlertTriangle size={16} className="shrink-0 text-amber-400" />
              <div>
                <span className="font-semibold block text-amber-200">
                  Demo Mode Active
                </span>
                <span className="text-slate-300">
                  You can test this audit flow with any phone number. A simulated verification code (e.g. 12345) will work.
                </span>
              </div>
            </div>
          )}

          {errorMsg && (
            <div className="p-3.5 rounded-xl bg-red-500/10 border border-red-500/30 text-red-300 text-xs flex items-center gap-2">
              <AlertTriangle size={15} className="shrink-0" />
              <span>{errorMsg}</span>
            </div>
          )}

          {/* Only render connection forms if Telegram is configured or in demo */}
          {(!systemStatus || systemStatus.telegram) && (
            <div className="space-y-6 max-w-xl">
              {/* QR Code Flow (PART D) */}
              {isQrMode ? (
                <div className="space-y-5 animate-fadeIn">
                  <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 flex flex-col items-center text-center space-y-4">
                    {/* Render QR with qrcode.react */}
                    {qrUrl ? (
                      <div className="p-3 bg-white rounded-2xl shadow-xl">
                        <QRCodeSVG value={qrUrl} size={210} level="M" />
                      </div>
                    ) : (
                      <div className="w-[210px] h-[210px] flex items-center justify-center bg-slate-950 rounded-2xl border border-slate-800">
                        <Loader2 size={32} className="animate-spin text-cyan-400" />
                      </div>
                    )}

                    <div className="space-y-2">
                      <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-300 text-xs font-semibold">
                        <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
                        <span>Waiting for scan in Telegram app...</span>
                      </div>
                      <p className="text-xs text-slate-300 font-medium">
                        Telegram app &rarr; Settings &rarr; Devices &rarr; Link Desktop Device &rarr; scan
                      </p>
                    </div>
                  </div>

                  {/* Cloud Password field if QR scan triggered SessionPasswordNeededError */}
                  {needsPassword && (
                    <div className="space-y-2 p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 animate-fadeIn">
                      <div className="flex items-center gap-2 text-amber-300 font-semibold text-xs">
                        <Lock size={15} />
                        <span>Two-Step Verification Password Required</span>
                      </div>
                      <p className="text-xs text-slate-300 leading-relaxed">
                        Your Telegram account has cloud password protection enabled. Enter your password to complete verification. It is held only in temporary server memory and never stored.
                      </p>
                      <div className="relative mt-2">
                        <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
                          <KeyRound size={17} />
                        </div>
                        <input
                          type="password"
                          value={password}
                          onChange={(e) => setPassword(e.target.value)}
                          placeholder="Enter your Two-Step Verification password"
                          className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-slate-900 border border-slate-700 text-white placeholder-slate-500 text-sm focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 transition-colors"
                        />
                      </div>
                      <button
                        type="button"
                        disabled={isVerifying || !password}
                        onClick={handleVerifyAndAnalyze}
                        className="mt-2 w-full py-2.5 rounded-xl bg-cyan-400 text-slate-950 font-bold text-xs hover:bg-cyan-300 disabled:opacity-50 transition-all flex items-center justify-center gap-2"
                      >
                        {isVerifying ? (
                          <>
                            <Loader2 size={14} className="animate-spin" />
                            <span>Verifying Password...</span>
                          </>
                        ) : (
                          <span>Submit Password & Start Audit</span>
                        )}
                      </button>
                    </div>
                  )}

                  <div className="flex items-center justify-between pt-2">
                    <button
                      type="button"
                      onClick={handleCancelQr}
                      className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-white transition-colors"
                    >
                      <Smartphone size={14} />
                      <span>Use phone number instead</span>
                    </button>
                  </div>
                </div>
              ) : (
                /* Phone Number & OTP Flow (PART B & PART C) */
                <div className="space-y-5">
                  {/* Phone input with Country Code Dropdown */}
                  {!otpSent && (
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300">
                          Mobile Number
                        </label>
                        <button
                          type="button"
                          disabled={isStartingQr}
                          onClick={handleStartQr}
                          className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold inline-flex items-center gap-1.5 transition-colors"
                        >
                          <QrCode size={14} />
                          <span>Link with QR code instead</span>
                        </button>
                      </div>

                      <div className="flex gap-2">
                        {/* Country Code Dropdown */}
                        <div className="relative w-40 shrink-0">
                          <select
                            value={countryCode}
                            onChange={(e) => setCountryCode(e.target.value)}
                            className="w-full h-11 pl-3 pr-8 rounded-xl bg-slate-900 border border-slate-700 text-white text-xs font-semibold focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 appearance-none transition-colors cursor-pointer"
                          >
                            {COUNTRIES.map((c) => (
                              <option key={c.code} value={c.code} className="bg-slate-900 text-white">
                                {c.flag} {c.code} ({c.name})
                              </option>
                            ))}
                          </select>
                          <div className="absolute inset-y-0 right-0 pr-2.5 flex items-center pointer-events-none text-slate-400 text-xs">
                            ▼
                          </div>
                        </div>

                        {/* National Number Input */}
                        <div className="relative flex-1">
                          <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
                            <Smartphone size={17} />
                          </div>
                          <input
                            type="tel"
                            value={nationalPhone}
                            onChange={handlePhoneChange}
                            placeholder={countryCode === '+91' ? 'e.g. 98765 43210' : 'Mobile number'}
                            className="w-full h-11 pl-10 pr-4 rounded-xl bg-slate-900 border border-slate-700 text-white placeholder-slate-500 text-sm focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 transition-colors"
                          />
                        </div>

                        {/* Send Code Button */}
                        <button
                          type="button"
                          disabled={isSendingCode || !phoneValidation.isValid}
                          onClick={handleSendCode}
                          className="h-11 px-5 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold text-xs disabled:opacity-40 disabled:cursor-not-allowed transition-all flex items-center gap-1.5 shrink-0 shadow-glow"
                        >
                          {isSendingCode ? (
                            <>
                              <Loader2 size={13} className="animate-spin" />
                              <span>Sending...</span>
                            </>
                          ) : (
                            <span>Send Code</span>
                          )}
                        </button>
                      </div>

                      {/* Live validation feedback */}
                      <p
                        className={`text-xs transition-colors ${
                          phoneValidation.isValid ? 'text-emerald-400 font-medium' : 'text-slate-400'
                        }`}
                      >
                        {phoneValidation.message}
                      </p>
                    </div>
                  )}

                  {/* OTP Section once code is sent */}
                  {otpSent && (
                    <div className="space-y-4 animate-fadeIn">
                      {/* Masked Phone Info Banner */}
                      <div className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800 flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <CheckCircle size={16} className="text-emerald-400" />
                          <span className="text-xs text-slate-300">
                            Code requested for <strong className="text-white font-mono">{maskedPhone}</strong>
                          </span>
                        </div>
                        <button
                          type="button"
                          onClick={() => {
                            if (flowId) cancelTelegram(flowId);
                            setOtpSent(false);
                            setFlowId(null);
                            setOtp('');
                          }}
                          className="text-[11px] text-cyan-400 hover:underline font-semibold"
                        >
                          Change Number
                        </button>
                      </div>

                      <div>
                        <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1.5">
                          Telegram Verification Code
                        </label>
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

                        {/* Truthful delivery instruction based on codeType (PART C requirement) */}
                        <div className="mt-2 text-xs space-y-1">
                          <p className="text-slate-300 font-medium flex items-center gap-1.5">
                            <Send size={12} className="text-cyan-400 shrink-0" />
                            <span>
                              {codeType === 'app'
                                ? "Open your Telegram app and look for a message from 'Telegram'"
                                : codeType === 'sms'
                                ? `We sent an SMS to ${maskedPhone}`
                                : codeType === 'call'
                                ? `Telegram will call ${maskedPhone} with your code`
                                : 'Check your Telegram app or SMS for the verification code'}
                            </span>
                          </p>

                          {/* Countdown and Resend */}
                          <div className="flex items-center gap-3 pt-1 text-[11px]">
                            {countdown > 0 ? (
                              <span className="text-slate-500 font-mono">
                                Resend available in {countdown}s
                              </span>
                            ) : nextType ? (
                              <button
                                type="button"
                                disabled={isResending}
                                onClick={handleResendCode}
                                className="text-cyan-400 hover:text-cyan-300 font-semibold underline flex items-center gap-1"
                              >
                                {isResending && <Loader2 size={11} className="animate-spin" />}
                                <span>Didn't get the code? Send it another way</span>
                              </button>
                            ) : (
                              <span className="text-slate-500">
                                No alternative delivery method reported by Telegram
                              </span>
                            )}
                          </div>
                        </div>

                        {/* Telegram Login Alert Disclaimer */}
                        <p className="text-[11px] text-cyan-400/90 mt-2 flex items-center gap-1.5">
                          <ShieldCheck size={13} className="shrink-0 text-cyan-400" />
                          <span>Telegram will send you a 'new login' alert. That is this tool, and it logs out when finished.</span>
                        </p>
                      </div>

                      {/* Password field if 2-step verification is enabled */}
                      {needsPassword && (
                        <div className="space-y-2 p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 animate-fadeIn">
                          <div className="flex items-center gap-2 text-amber-300 font-semibold text-xs">
                            <Lock size={15} />
                            <span>Two-Step Verification Password Required</span>
                          </div>
                          <p className="text-xs text-slate-300 leading-relaxed">
                            Your Telegram account has cloud password protection enabled. Enter your password to inspect session logs. It is held only in temporary server memory and never stored.
                          </p>
                          <div className="relative mt-2">
                            <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
                              <KeyRound size={17} />
                            </div>
                            <input
                              type="password"
                              value={password}
                              onChange={(e) => setPassword(e.target.value)}
                              placeholder="Enter your Two-Step Verification password"
                              className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-slate-900 border border-slate-700 text-white placeholder-slate-500 text-sm focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 transition-colors"
                            />
                          </div>
                        </div>
                      )}

                      {/* Connect & Run Audit Button */}
                      <div className="pt-2">
                        <button
                          disabled={!otpSent || isVerifying || otp.trim().length < 4}
                          onClick={handleVerifyAndAnalyze}
                          className="w-full flex items-center justify-center gap-2 py-3 rounded-xl bg-cyan-400 text-slate-950 font-bold text-sm hover:bg-cyan-300 disabled:opacity-40 disabled:cursor-not-allowed transition-all shadow-glow hover:shadow-glow-lg"
                        >
                          {isVerifying ? (
                            <>
                              <Loader2 size={16} className="animate-spin" />
                              <span>Verifying & Starting Audit...</span>
                            </>
                          ) : (
                            <>
                              <span>Connect & Run Audit</span>
                              <ArrowRight size={16} />
                            </>
                          )}
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 text-xs text-slate-400 flex items-center gap-2">
            <HelpCircle size={15} className="text-cyan-400 shrink-0" />
            <span>
              Clicking <strong>Connect & Run Audit</strong> queries active sessions and IP geolocations, then immediately calls logout.
            </span>
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
          {/* Demo Mode Notice Banner on Result */}
          {(isDemo || scanData.isDemo) && (
            <div className="p-3.5 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs flex items-center gap-2.5">
              <AlertTriangle size={16} className="shrink-0 text-amber-400" />
              <div>
                <span className="font-semibold block text-amber-200">
                  Demo Mode Active
                </span>
                <span className="text-slate-300">
                  This report was generated using simulated mock data.
                </span>
              </div>
            </div>
          )}

          {/* Main Verdict Card with Large Risk Gauge */}
          <div className="glass-card rounded-2xl p-6 sm:p-8 border border-slate-800 flex flex-col md:flex-row items-center justify-between gap-6">
            <div className="flex-1 space-y-3 text-center md:text-left">
              <div className="flex flex-wrap items-center justify-center md:justify-start gap-2">
                <RiskBadge level={scanData.riskLevel} size="lg" />
                <span className="text-xs text-slate-400 font-mono">
                  Target: {maskedPhone || scanData.phone}
                </span>
                <span className="text-xs text-cyan-400 font-medium">
                  {scanData.accountName}
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
              onClick={handleAuditAnotherNumber}
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
