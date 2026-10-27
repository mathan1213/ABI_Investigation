import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  Lock,
  User as UserIcon,
  AlertCircle,
  CheckCircle2,
  ArrowRight,
  ArrowLeft,
  Loader2,
  KeyRound,
  RotateCcw,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { adminLogin, adminVerifyLoginOtp, resendOtp } from '../lib/api';

export const AdminLogin: React.FC = () => {
  const { setAuthSession } = useAuth();
  const navigate = useNavigate();

  // Mode: 'login' | 'otp'
  const [mode, setMode] = useState<'login' | 'otp'>('login');

  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  // OTP State
  const [userId, setUserId] = useState<number | null>(null);
  const [maskedEmail, setMaskedEmail] = useState('');
  const [otp, setOtp] = useState<string[]>(['', '', '', '', '', '']);
  const [otpError, setOtpError] = useState<string | null>(null);
  const [isVerifyingOtp, setIsVerifyingOtp] = useState(false);
  const [resendCountdown, setResendCountdown] = useState(60);
  const [resendStatus, setResendStatus] = useState<string | null>(null);
  const [isResending, setIsResending] = useState(false);

  const otpInputRefs = useRef<(HTMLInputElement | null)[]>([]);

  useEffect(() => {
    let interval: any = null;
    if (mode === 'otp' && resendCountdown > 0) {
      interval = setInterval(() => {
        setResendCountdown((prev) => prev - 1);
      }, 1000);
    }
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [mode, resendCountdown]);

  const handleAdminLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!identifier.trim() || !password) {
      setError('Please provide administrative username/email and password.');
      return;
    }

    setIsLoading(true);
    try {
      const res = await adminLogin(identifier.trim(), password);
      if (res.requiresOtp) {
        setUserId(res.userId);
        setMaskedEmail(res.emailMasked);
        setMode('otp');
        setResendCountdown(60);
        setOtp(['', '', '', '', '', '']);
        setTimeout(() => otpInputRefs.current[0]?.focus(), 100);
      }
    } catch (err: any) {
      setError(err?.message || 'Administrative credentials verification failed.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleOtpChange = (index: number, value: string) => {
    const cleaned = value.replace(/\D/g, '');
    const newOtp = [...otp];

    if (cleaned.length > 1) {
      const digits = cleaned.slice(0, 6).split('');
      for (let i = 0; i < 6; i++) {
        newOtp[i] = digits[i] || '';
      }
      setOtp(newOtp);
      const nextIdx = Math.min(digits.length, 5);
      otpInputRefs.current[nextIdx]?.focus();
      return;
    }

    newOtp[index] = cleaned;
    setOtp(newOtp);

    if (cleaned && index < 5) {
      otpInputRefs.current[index + 1]?.focus();
    }
  };

  const handleOtpKeyDown = (index: number, e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Backspace' && !otp[index] && index > 0) {
      otpInputRefs.current[index - 1]?.focus();
    }
  };

  const handleVerifyOtp = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!userId) return;
    setOtpError(null);
    const code = otp.join('').trim();
    if (code.length !== 6) {
      setOtpError('Please enter the 6-digit administrative verification code.');
      return;
    }

    setIsVerifyingOtp(true);
    try {
      const res = await adminVerifyLoginOtp(userId, code);
      setAuthSession(res.user, res.token);
      navigate('/admin', { replace: true });
    } catch (err: any) {
      setOtpError(err?.message || 'Verification failed. Please check the code.');
    } finally {
      setIsVerifyingOtp(false);
    }
  };

  const handleResendOtp = async () => {
    if (resendCountdown > 0 || isResending) return;
    setIsResending(true);
    setResendStatus(null);
    setOtpError(null);
    try {
      await resendOtp(identifier.trim(), 'admin_login');
      setResendCountdown(60);
      setResendStatus('A new administrative code has been dispatched.');
    } catch (err: any) {
      setOtpError(err?.message || 'Failed to resend code.');
    } finally {
      setIsResending(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#070B14] flex items-center justify-center px-4 py-12 selection:bg-purple-500/30 selection:text-purple-200">
      <div className="max-w-md w-full bg-[#0F1424] border border-purple-900/40 rounded-2xl p-8 shadow-2xl relative overflow-hidden">
        {/* Glow accent */}
        <div className="absolute -top-24 -right-24 w-52 h-52 bg-purple-600/10 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute -bottom-24 -left-24 w-52 h-52 bg-indigo-600/10 rounded-full blur-3xl pointer-events-none" />

        {mode === 'login' ? (
          <>
            <div className="text-center mb-8">
              <div className="inline-flex p-3 bg-purple-500/15 border border-purple-500/30 rounded-xl text-purple-400 mb-3 shadow-lg shadow-purple-950/50">
                <ShieldAlert className="w-8 h-8" />
              </div>
              <h1 className="text-2xl font-bold text-white tracking-tight">Administrator sign in</h1>
              <p className="text-xs text-purple-300/80 mt-1.5 uppercase tracking-widest font-mono">
                Authorized Personnel Only
              </p>
            </div>

            {error && (
              <div className="mb-6 p-3.5 bg-red-950/50 border border-red-800/60 rounded-xl flex items-start gap-2.5 text-xs text-red-300">
                <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                <span>{error}</span>
              </div>
            )}

            <form onSubmit={handleAdminLoginSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-purple-200/90 mb-1.5 uppercase tracking-wider">
                  Admin Identifier
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                    <UserIcon className="w-4 h-4" />
                  </div>
                  <input
                    type="text"
                    required
                    value={identifier}
                    onChange={(e) => setIdentifier(e.target.value)}
                    placeholder="Admin username or email"
                    className="w-full bg-[#080C18] border border-purple-900/50 rounded-xl pl-10 pr-4 py-2.5 text-sm text-slate-100 placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500 transition-colors"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-purple-200/90 mb-1.5 uppercase tracking-wider">
                  Password
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                    <Lock className="w-4 h-4" />
                  </div>
                  <input
                    type="password"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••••••"
                    className="w-full bg-[#080C18] border border-purple-900/50 rounded-xl pl-10 pr-4 py-2.5 text-sm text-slate-100 placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500 transition-colors"
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={isLoading || !identifier.trim() || !password}
                className="w-full mt-3 py-3 px-4 bg-purple-600 hover:bg-purple-500 active:bg-purple-700 disabled:opacity-50 text-white font-medium rounded-xl text-sm transition-all flex items-center justify-center gap-2 shadow-lg shadow-purple-600/25 cursor-pointer disabled:cursor-not-allowed"
              >
                {isLoading ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Authenticating Admin...
                  </>
                ) : (
                  <>
                    Continue to OTP Verification
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </form>

            <div className="mt-8 pt-6 border-t border-slate-800/80 text-center">
              <p className="text-[11px] text-slate-500">
                All administrative access attempts and actions are monitored and recorded in audit logs.
              </p>
            </div>
          </>
        ) : (
          /* Mode 2: Admin OTP */
          <div>
            <div className="text-center mb-6">
              <div className="inline-flex p-3 bg-purple-500/15 border border-purple-500/30 rounded-xl text-purple-400 mb-3">
                <KeyRound className="w-8 h-8" />
              </div>
              <h1 className="text-2xl font-bold text-white tracking-tight">Admin Two-Step Auth</h1>
              <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">
                Enter the 6-digit administrative verification code sent to <br />
                <span className="text-purple-300 font-mono font-medium">{maskedEmail}</span>
              </p>
            </div>

            {otpError && (
              <div className="mb-5 p-3.5 bg-red-950/50 border border-red-800/60 rounded-xl flex items-start gap-2.5 text-xs text-red-300">
                <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                <span>{otpError}</span>
              </div>
            )}

            {resendStatus && (
              <div className="mb-5 p-3.5 bg-emerald-950/40 border border-emerald-800/60 rounded-xl flex items-start gap-2.5 text-xs text-emerald-300">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                <span>{resendStatus}</span>
              </div>
            )}

            <form onSubmit={handleVerifyOtp} className="space-y-6">
              <div className="flex justify-center gap-2 sm:gap-3">
                {otp.map((digit, idx) => (
                  <input
                    key={idx}
                    ref={(el) => {
                      otpInputRefs.current[idx] = el;
                    }}
                    type="text"
                    inputMode="numeric"
                    maxLength={1}
                    value={digit}
                    onChange={(e) => handleOtpChange(idx, e.target.value)}
                    onKeyDown={(e) => handleOtpKeyDown(idx, e)}
                    className="w-11 h-13 sm:w-12 sm:h-14 bg-[#080C18] border border-purple-900/60 rounded-xl text-center text-xl sm:text-2xl font-mono font-bold text-purple-300 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-purple-500 transition-colors"
                  />
                ))}
              </div>

              <button
                type="submit"
                disabled={isVerifyingOtp || otp.join('').length !== 6}
                className="w-full py-3 px-4 bg-purple-600 hover:bg-purple-500 active:bg-purple-700 disabled:opacity-50 text-white font-medium rounded-xl text-sm transition-all flex items-center justify-center gap-2 shadow-lg shadow-purple-600/25 cursor-pointer disabled:cursor-not-allowed"
              >
                {isVerifyingOtp ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Validating admin session...
                  </>
                ) : (
                  <>
                    Access Admin Portal
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </form>

            <div className="mt-6 pt-5 border-t border-slate-800/80 space-y-3 text-center">
              <div>
                {resendCountdown > 0 ? (
                  <p className="text-xs text-slate-500">
                    Resend code in <span className="text-purple-300 font-mono font-medium">{resendCountdown}s</span>
                  </p>
                ) : (
                  <button
                    onClick={handleResendOtp}
                    disabled={isResending}
                    className="inline-flex items-center gap-1.5 text-xs text-purple-400 hover:text-purple-300 font-medium transition-colors"
                  >
                    {isResending ? (
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    ) : (
                      <RotateCcw className="w-3.5 h-3.5" />
                    )}
                    Resend verification code
                  </button>
                )}
              </div>

              <div>
                <button
                  onClick={() => {
                    setMode('login');
                    setOtp(['', '', '', '', '', '']);
                    setOtpError(null);
                  }}
                  className="inline-flex items-center gap-1 text-xs text-slate-400 hover:text-slate-200 transition-colors"
                >
                  <ArrowLeft className="w-3.5 h-3.5" />
                  Switch account
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
