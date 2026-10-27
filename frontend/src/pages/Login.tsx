import React, { useState, useEffect, useRef } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import {
  Shield,
  Lock,
  User as UserIcon,
  AlertCircle,
  CheckCircle2,
  ArrowRight,
  ArrowLeft,
  Loader2,
  RotateCcw,
  KeyRound,
  AtSign,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import {
  loginUser,
  verifyLoginOtp,
  resendOtp,
  forgotPassword,
  resetPassword,
  checkUsername,
  updateUsername,
} from '../lib/api';

export const Login: React.FC = () => {
  const { setAuthSession, user, updateUserContext } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  // Mode: 'login' | 'otp' | 'forgot_step1' | 'forgot_step2'
  const [mode, setMode] = useState<'login' | 'otp' | 'forgot_step1' | 'forgot_step2'>('login');

  // Login inputs
  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [loginError, setLoginError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // OTP State
  const [userId, setUserId] = useState<number | null>(null);
  const [maskedEmail, setMaskedEmail] = useState('');
  const [otp, setOtp] = useState<string[]>(['', '', '', '', '', '']);
  const [otpError, setOtpError] = useState<string | null>(null);
  const [isVerifyingOtp, setIsVerifyingOtp] = useState(false);
  const [resendCountdown, setResendCountdown] = useState(60);
  const [resendStatus, setResendStatus] = useState<string | null>(null);
  const [isResending, setIsResending] = useState(false);

  // Forgot password state
  const [forgotEmail, setForgotEmail] = useState('');
  const [resetCode, setResetCode] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [forgotMsg, setForgotMsg] = useState<string | null>(null);
  const [forgotError, setForgotError] = useState<string | null>(null);
  const [isForgotLoading, setIsForgotLoading] = useState(false);

  // One-time username prompt state (for migrated users)
  const [showUsernameModal, setShowUsernameModal] = useState(false);
  const [newUsername, setNewUsername] = useState('');
  const [usernameStatus, setUsernameStatus] = useState<'idle' | 'checking' | 'available' | 'taken' | 'invalid' | 'reserved'>('idle');
  const [usernameMsg, setUsernameMsg] = useState('');
  const [isUpdatingUsername, setIsUpdatingUsername] = useState(false);

  const otpInputRefs = useRef<(HTMLInputElement | null)[]>([]);

  const from = (location.state as any)?.from?.pathname || '/dashboard';

  // ---------------------------------------------------------------------------
  // OTP Countdown
  // ---------------------------------------------------------------------------
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

  // ---------------------------------------------------------------------------
  // Check for migrated user needing username choice
  // ---------------------------------------------------------------------------
  useEffect(() => {
    if (user && user.needsUsernameChange) {
      setNewUsername(user.username || '');
      setShowUsernameModal(true);
    }
  }, [user]);

  // Debounced username check for modal
  useEffect(() => {
    if (!showUsernameModal) return;
    const trimmed = newUsername.trim();
    if (!trimmed) {
      setUsernameStatus('idle');
      setUsernameMsg('');
      return;
    }
    if (user?.username && trimmed.toLowerCase() === user.username.toLowerCase()) {
      setUsernameStatus('available');
      setUsernameMsg('Current username');
      return;
    }

    if (!/^[a-zA-Z][a-zA-Z0-9_.]{2,19}$/.test(trimmed)) {
      setUsernameStatus('invalid');
      setUsernameMsg('3-20 chars: start with letter, letters/digits/_/. only');
      return;
    }

    setUsernameStatus('checking');
    const timer = setTimeout(async () => {
      try {
        const res = await checkUsername(trimmed);
        if (res.available) {
          setUsernameStatus('available');
          setUsernameMsg('Username is available');
        } else {
          setUsernameStatus(res.reason || 'taken');
          setUsernameMsg(res.message);
        }
      } catch {
        setUsernameStatus('idle');
      }
    }, 400);

    return () => clearTimeout(timer);
  }, [newUsername, showUsernameModal, user]);

  // ---------------------------------------------------------------------------
  // Step 1: Submit Credentials
  // ---------------------------------------------------------------------------
  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoginError(null);

    if (!identifier.trim() || !password) {
      setLoginError('Please enter both email/username and password.');
      return;
    }

    setIsSubmitting(true);
    try {
      const res = await loginUser(identifier.trim(), password);
      if (res.requiresOtp) {
        setUserId(res.userId);
        setMaskedEmail(res.emailMasked);
        setMode('otp');
        setResendCountdown(60);
        setOtp(['', '', '', '', '', '']);
        setTimeout(() => otpInputRefs.current[0]?.focus(), 100);
      }
    } catch (err: any) {
      setLoginError(err?.message || 'Incorrect email, username or password.');
    } finally {
      setIsSubmitting(false);
    }
  };

  // ---------------------------------------------------------------------------
  // Step 2: Verify Login OTP
  // ---------------------------------------------------------------------------
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
      setOtpError('Please enter the complete 6-digit verification code.');
      return;
    }

    setIsVerifyingOtp(true);
    try {
      const res = await verifyLoginOtp(userId, code);
      setAuthSession(res.user, res.token);
      if (res.user.needsUsernameChange) {
        setNewUsername(res.user.username || '');
        setShowUsernameModal(true);
      } else {
        navigate(from, { replace: true });
      }
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
      await resendOtp(identifier.trim(), 'login');
      setResendCountdown(60);
      setResendStatus('A fresh verification code has been dispatched to your email.');
    } catch (err: any) {
      setOtpError(err?.message || 'Failed to resend code.');
    } finally {
      setIsResending(false);
    }
  };

  // ---------------------------------------------------------------------------
  // Forgot Password Flow
  // ---------------------------------------------------------------------------
  const handleForgotStep1 = async (e: React.FormEvent) => {
    e.preventDefault();
    setForgotError(null);
    setForgotMsg(null);
    if (!forgotEmail.trim()) {
      setForgotError('Please enter your account email address.');
      return;
    }
    setIsForgotLoading(true);
    try {
      const res = await forgotPassword(forgotEmail.trim());
      setForgotMsg(res.message);
      setMode('forgot_step2');
    } catch (err: any) {
      setForgotError(err?.message || 'Unable to process request.');
    } finally {
      setIsForgotLoading(false);
    }
  };

  const handleForgotStep2 = async (e: React.FormEvent) => {
    e.preventDefault();
    setForgotError(null);
    setForgotMsg(null);
    if (!resetCode.trim() || resetCode.trim().length !== 6) {
      setForgotError('Please enter the 6-digit code received in your email.');
      return;
    }
    if (newPassword.length < 8) {
      setForgotError('New password must be at least 8 characters long.');
      return;
    }
    setIsForgotLoading(true);
    try {
      const res = await resetPassword(forgotEmail.trim(), resetCode.trim(), newPassword);
      setLoginError(null);
      setMode('login');
      setLoginError(res.message); // show success message in login banner
    } catch (err: any) {
      setForgotError(err?.message || 'Password reset failed.');
    } finally {
      setIsForgotLoading(false);
    }
  };

  // ---------------------------------------------------------------------------
  // One-Time Username Change Confirmation
  // ---------------------------------------------------------------------------
  const handleSaveUsername = async () => {
    if (usernameStatus !== 'available') return;
    setIsUpdatingUsername(true);
    try {
      const updated = await updateUsername(newUsername.trim());
      updateUserContext(updated);
      setShowUsernameModal(false);
      navigate(from, { replace: true });
    } catch (err: any) {
      setUsernameMsg(err?.message || 'Failed to update username.');
    } finally {
      setIsUpdatingUsername(false);
    }
  };

  return (
    <div className="min-h-[calc(100vh-140px)] flex items-center justify-center px-4 py-12">
      <div className="max-w-md w-full bg-[#111827] border border-slate-800 rounded-2xl p-8 shadow-2xl relative overflow-hidden">
        {/* Glow accent */}
        <div className="absolute -top-24 -right-24 w-48 h-48 bg-blue-500/10 rounded-full blur-3xl pointer-events-none" />

        {/* MODE 1: Standard Login Form */}
        {mode === 'login' && (
          <>
            <div className="text-center mb-8">
              <div className="inline-flex p-3 bg-blue-500/10 border border-blue-500/20 rounded-xl text-blue-400 mb-3">
                <Shield className="w-8 h-8" />
              </div>
              <h1 className="text-2xl font-bold text-white tracking-tight">Account Sign In</h1>
              <p className="text-sm text-slate-400 mt-1">
                Access your forensic investigation dashboard
              </p>
            </div>

            {loginError && (
              <div
                className={`mb-6 p-3.5 rounded-xl flex items-start gap-2.5 text-sm ${
                  loginError.includes('successfully')
                    ? 'bg-emerald-950/40 border border-emerald-800/60 text-emerald-300'
                    : 'bg-red-900/30 border border-red-800/60 text-red-300'
                }`}
              >
                {loginError.includes('successfully') ? (
                  <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
                ) : (
                  <AlertCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
                )}
                <span>{loginError}</span>
              </div>
            )}

            <form onSubmit={handleLoginSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5 uppercase tracking-wider">
                  Email or Username
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
                    placeholder="name@example.com or username"
                    className="w-full bg-[#0B0F19] border border-slate-700/80 rounded-xl pl-10 pr-4 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500 transition-colors"
                  />
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className="block text-xs font-medium text-slate-300 uppercase tracking-wider">
                    Password
                  </label>
                  <button
                    type="button"
                    onClick={() => {
                      setForgotEmail(identifier.includes('@') ? identifier : '');
                      setMode('forgot_step1');
                    }}
                    className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
                  >
                    Forgot password?
                  </button>
                </div>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                    <Lock className="w-4 h-4" />
                  </div>
                  <input
                    type="password"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••"
                    className="w-full bg-[#0B0F19] border border-slate-700/80 rounded-xl pl-10 pr-4 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500 transition-colors"
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={isSubmitting || !identifier.trim() || !password}
                className="w-full mt-3 py-3 px-4 bg-blue-600 hover:bg-blue-500 active:bg-blue-700 disabled:opacity-50 text-white font-medium rounded-xl text-sm transition-all flex items-center justify-center gap-2 shadow-lg shadow-blue-600/20 cursor-pointer disabled:cursor-not-allowed"
              >
                {isSubmitting ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Checking credentials...
                  </>
                ) : (
                  <>
                    Continue
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </form>

            <div className="mt-8 pt-6 border-t border-slate-800 text-center">
              <p className="text-xs text-slate-400">
                Don&apos;t have an account?{' '}
                <Link to="/register" className="text-blue-400 hover:text-blue-300 font-medium">
                  Create one now
                </Link>
              </p>
            </div>
          </>
        )}

        {/* MODE 2: 2-Step Login OTP */}
        {mode === 'otp' && (
          <div>
            <div className="text-center mb-6">
              <div className="inline-flex p-3 bg-blue-500/10 border border-blue-500/20 rounded-xl text-blue-400 mb-3">
                <KeyRound className="w-8 h-8" />
              </div>
              <h1 className="text-2xl font-bold text-white tracking-tight">Two-Step Verification</h1>
              <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">
                For security, we sent a 6-digit sign in code to <br />
                <span className="text-blue-300 font-mono font-medium">{maskedEmail}</span>
              </p>
            </div>

            {otpError && (
              <div className="mb-5 p-3.5 bg-red-900/30 border border-red-800/60 rounded-xl flex items-start gap-2.5 text-xs text-red-300">
                <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                <span>{otpError}</span>
              </div>
            )}

            {resendStatus && (
              <div className="mb-5 p-3.5 bg-emerald-900/30 border border-emerald-800/60 rounded-xl flex items-start gap-2.5 text-xs text-emerald-300">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                <span>{resendStatus}</span>
              </div>
            )}

            <form onSubmit={handleVerifyOtp} className="space-y-6">
              {/* 6 Digit Boxes */}
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
                    className="w-11 h-13 sm:w-12 sm:h-14 bg-[#0B0F19] border border-slate-700/80 rounded-xl text-center text-xl sm:text-2xl font-mono font-bold text-blue-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors"
                  />
                ))}
              </div>

              <button
                type="submit"
                disabled={isVerifyingOtp || otp.join('').length !== 6}
                className="w-full py-3 px-4 bg-blue-600 hover:bg-blue-500 active:bg-blue-700 disabled:opacity-50 text-white font-medium rounded-xl text-sm transition-all flex items-center justify-center gap-2 shadow-lg shadow-blue-600/20 cursor-pointer disabled:cursor-not-allowed"
              >
                {isVerifyingOtp ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Signing in...
                  </>
                ) : (
                  <>
                    Verify &amp; Sign In
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </form>

            <div className="mt-6 pt-5 border-t border-slate-800 space-y-3 text-center">
              <div>
                {resendCountdown > 0 ? (
                  <p className="text-xs text-slate-500">
                    Resend code in <span className="text-slate-300 font-mono font-medium">{resendCountdown}s</span>
                  </p>
                ) : (
                  <button
                    onClick={handleResendOtp}
                    disabled={isResending}
                    className="inline-flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300 font-medium transition-colors"
                  >
                    {isResending ? (
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    ) : (
                      <RotateCcw className="w-3.5 h-3.5" />
                    )}
                    Resend sign-in code
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
                  Use a different account
                </button>
              </div>
            </div>
          </div>
        )}

        {/* MODE 3: Forgot Password - Step 1 (Request Code) */}
        {mode === 'forgot_step1' && (
          <div>
            <div className="text-center mb-6">
              <div className="inline-flex p-3 bg-purple-500/10 border border-purple-500/20 rounded-xl text-purple-400 mb-3">
                <Lock className="w-8 h-8" />
              </div>
              <h1 className="text-2xl font-bold text-white tracking-tight">Reset Password</h1>
              <p className="text-xs text-slate-400 mt-1.5">
                Enter your account email to receive a password reset verification code.
              </p>
            </div>

            {forgotError && (
              <div className="mb-5 p-3.5 bg-red-900/30 border border-red-800/60 rounded-xl flex items-start gap-2.5 text-xs text-red-300">
                <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                <span>{forgotError}</span>
              </div>
            )}

            <form onSubmit={handleForgotStep1} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5 uppercase tracking-wider">
                  Account Email
                </label>
                <input
                  type="email"
                  required
                  value={forgotEmail}
                  onChange={(e) => setForgotEmail(e.target.value)}
                  placeholder="name@example.com"
                  className="w-full bg-[#0B0F19] border border-slate-700/80 rounded-xl px-4 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500 transition-colors"
                />
              </div>

              <button
                type="submit"
                disabled={isForgotLoading || !forgotEmail.trim()}
                className="w-full py-3 px-4 bg-purple-600 hover:bg-purple-500 active:bg-purple-700 disabled:opacity-50 text-white font-medium rounded-xl text-sm transition-all flex items-center justify-center gap-2 cursor-pointer disabled:cursor-not-allowed"
              >
                {isForgotLoading ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Sending Code...
                  </>
                ) : (
                  <>
                    Send Reset Code
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </form>

            <div className="mt-6 pt-5 border-t border-slate-800 text-center">
              <button
                onClick={() => setMode('login')}
                className="inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors"
              >
                <ArrowLeft className="w-3.5 h-3.5" />
                Back to Sign in
              </button>
            </div>
          </div>
        )}

        {/* MODE 4: Forgot Password - Step 2 (Enter Code & New Password) */}
        {mode === 'forgot_step2' && (
          <div>
            <div className="text-center mb-6">
              <div className="inline-flex p-3 bg-purple-500/10 border border-purple-500/20 rounded-xl text-purple-400 mb-3">
                <KeyRound className="w-8 h-8" />
              </div>
              <h1 className="text-2xl font-bold text-white tracking-tight">Create New Password</h1>
              <p className="text-xs text-slate-400 mt-1.5">
                Enter the 6-digit code sent to <span className="text-purple-300 font-mono">{forgotEmail}</span> and choose a new password.
              </p>
            </div>

            {forgotMsg && (
              <div className="mb-5 p-3.5 bg-purple-950/40 border border-purple-800/60 rounded-xl text-xs text-purple-300">
                {forgotMsg}
              </div>
            )}

            {forgotError && (
              <div className="mb-5 p-3.5 bg-red-900/30 border border-red-800/60 rounded-xl flex items-start gap-2.5 text-xs text-red-300">
                <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                <span>{forgotError}</span>
              </div>
            )}

            <form onSubmit={handleForgotStep2} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5 uppercase tracking-wider">
                  6-Digit Verification Code
                </label>
                <input
                  type="text"
                  required
                  maxLength={6}
                  value={resetCode}
                  onChange={(e) => setResetCode(e.target.value.replace(/\D/g, ''))}
                  placeholder="123456"
                  className="w-full bg-[#0B0F19] border border-slate-700/80 rounded-xl px-4 py-2.5 text-center text-lg font-mono tracking-widest text-purple-300 placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500 transition-colors"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5 uppercase tracking-wider">
                  New Password (Min. 8 characters)
                </label>
                <input
                  type="password"
                  required
                  minLength={8}
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="••••••••"
                  className="w-full bg-[#0B0F19] border border-slate-700/80 rounded-xl px-4 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500 transition-colors"
                />
              </div>

              <button
                type="submit"
                disabled={isForgotLoading || resetCode.length !== 6 || newPassword.length < 8}
                className="w-full py-3 px-4 bg-purple-600 hover:bg-purple-500 active:bg-purple-700 disabled:opacity-50 text-white font-medium rounded-xl text-sm transition-all flex items-center justify-center gap-2 cursor-pointer disabled:cursor-not-allowed"
              >
                {isForgotLoading ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Resetting Password...
                  </>
                ) : (
                  <>
                    Set New Password
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </form>

            <div className="mt-6 pt-5 border-t border-slate-800 text-center">
              <button
                onClick={() => setMode('forgot_step1')}
                className="inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors"
              >
                <ArrowLeft className="w-3.5 h-3.5" />
                Resend code / Change email
              </button>
            </div>
          </div>
        )}
      </div>

      {/* ONE-TIME "CHOOSE YOUR USERNAME" MODAL (For Migrated Existing Accounts) */}
      {showUsernameModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#111827] border border-cyan-500/40 rounded-2xl w-full max-w-md p-6 space-y-4 shadow-2xl relative">
            <div className="flex items-center gap-3 text-cyan-400">
              <AtSign className="w-6 h-6" />
              <h3 className="text-lg font-bold text-white">Choose Your Permanent Username</h3>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              We generated a temporary username based on your email. You can confirm it or pick a custom unique handle now.
            </p>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5 uppercase tracking-wider">
                Username
              </label>
              <input
                type="text"
                value={newUsername}
                onChange={(e) => setNewUsername(e.target.value)}
                placeholder="your_handle"
                className="w-full bg-[#0B0F19] border border-slate-700 rounded-xl px-4 py-2.5 text-sm text-cyan-300 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500"
              />
              {usernameMsg && (
                <p
                  className={`text-xs mt-1.5 ${
                    usernameStatus === 'available' ? 'text-emerald-400' : 'text-red-400'
                  }`}
                >
                  {usernameMsg}
                </p>
              )}
            </div>

            <div className="flex justify-end gap-2.5 pt-3">
              <button
                onClick={() => {
                  setShowUsernameModal(false);
                  navigate(from, { replace: true });
                }}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl text-xs font-medium"
              >
                Keep current &amp; continue
              </button>
              <button
                onClick={handleSaveUsername}
                disabled={isUpdatingUsername || usernameStatus !== 'available'}
                className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-xl text-xs font-medium flex items-center gap-1.5 disabled:opacity-50"
              >
                {isUpdatingUsername && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                Confirm Username
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
