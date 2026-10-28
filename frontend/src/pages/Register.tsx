import React, { useState, useEffect, useRef } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  Shield,
  User as UserIcon,
  AtSign,
  Lock,
  Mail,
  AlertCircle,
  CheckCircle2,
  ArrowRight,
  ArrowLeft,
  Loader2,
  RotateCcw,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { checkUsername, registerUser, verifyEmail, resendOtp } from '../lib/api';

export const Register: React.FC = () => {
  const { setAuthSession } = useAuth();
  const navigate = useNavigate();

  // Form Fields
  const [name, setName] = useState('');
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [consentAgreed, setConsentAgreed] = useState(false);

  // Status & Errors
  const [formError, setFormError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  // Username validation state
  const [usernameStatus, setUsernameStatus] = useState<
    'idle' | 'checking' | 'available' | 'taken' | 'invalid' | 'reserved'
  >('idle');
  const [usernameMessage, setUsernameMessage] = useState<string>('');

  // Step state: 'form' or 'otp'
  const [step, setStep] = useState<'form' | 'otp'>('form');

  // OTP State
  const [otp, setOtp] = useState<string[]>(['', '', '', '', '', '']);
  const [otpError, setOtpError] = useState<string | null>(null);
  const [isVerifyingOtp, setIsVerifyingOtp] = useState(false);
  const [resendCountdown, setResendCountdown] = useState(60);
  const [resendStatus, setResendStatus] = useState<string | null>(null);
  const [isResending, setIsResending] = useState(false);

  const otpInputRefs = useRef<(HTMLInputElement | null)[]>([]);

  // ---------------------------------------------------------------------------
  // Debounced Username Checking (~400 ms)
  // ---------------------------------------------------------------------------
  useEffect(() => {
    const trimmed = username.trim();
    if (!trimmed) {
      setUsernameStatus('idle');
      setUsernameMessage('');
      return;
    }

    if (trimmed.length < 3) {
      setUsernameStatus('invalid');
      setUsernameMessage('Username must be at least 3 characters.');
      return;
    }

    if (!/^[a-zA-Z]/.test(trimmed)) {
      setUsernameStatus('invalid');
      setUsernameMessage('Username must start with a letter.');
      return;
    }

    if (!/^[a-zA-Z][a-zA-Z0-9_.]{2,19}$/.test(trimmed)) {
      setUsernameStatus('invalid');
      setUsernameMessage('Only letters, digits, underscores, and dots are allowed (max 20 chars).');
      return;
    }

    setUsernameStatus('checking');
    setUsernameMessage('Checking availability...');

    const timer = setTimeout(async () => {
      try {
        const res = await checkUsername(trimmed);
        if (res.available) {
          setUsernameStatus('available');
          setUsernameMessage('Username is available');
        } else {
          setUsernameStatus(res.reason || 'taken');
          setUsernameMessage(res.message);
        }
      } catch {
        // If backend check fails (e.g. backend offline or network error), fallback to client-side format validation
        if (/^[a-zA-Z][a-zA-Z0-9_.]{2,19}$/.test(trimmed)) {
          setUsernameStatus('available');
          setUsernameMessage('Username format is valid');
        } else {
          setUsernameStatus('invalid');
          setUsernameMessage('3-20 characters: letters, digits, underscores, dots. Must start with letter.');
        }
      }
    }, 400);

    return () => clearTimeout(timer);
  }, [username]);

  // ---------------------------------------------------------------------------
  // Resend OTP Countdown Timer
  // ---------------------------------------------------------------------------
  useEffect(() => {
    let interval: any = null;
    if (step === 'otp' && resendCountdown > 0) {
      interval = setInterval(() => {
        setResendCountdown((prev) => prev - 1);
      }, 1000);
    }
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [step, resendCountdown]);

  // ---------------------------------------------------------------------------
  // Handle Register Form Submit
  // ---------------------------------------------------------------------------
  const handleRegisterSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);

    const trimmedName = name.trim();
    const trimmedUsername = username.trim();
    const trimmedEmail = email.trim();

    if (!trimmedName) {
      setFormError('Please enter your full name.');
      return;
    }

    if (!trimmedUsername) {
      setFormError('Please choose a username.');
      return;
    }

    if (usernameStatus === 'checking') {
      setFormError('Please wait a moment while username availability is checked.');
      return;
    }

    if (usernameStatus === 'taken') {
      setFormError('This username is already taken. Please try another.');
      return;
    }

    if (usernameStatus === 'reserved') {
      setFormError('This username is reserved. Please choose another.');
      return;
    }

    if (!/^[a-zA-Z][a-zA-Z0-9_.]{2,19}$/.test(trimmedUsername)) {
      setFormError('Username must be 3-20 characters, start with a letter, and use only letters, digits, underscores, or dots.');
      return;
    }

    if (!trimmedEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmedEmail)) {
      setFormError('Please provide a valid email address.');
      return;
    }

    if (password.length < 8) {
      setFormError('Password must be at least 8 characters long.');
      return;
    }

    if (!consentAgreed) {
      setFormError('Please agree to the data storage and privacy terms by checking the box below.');
      return;
    }

    setIsLoading(true);
    try {
      await registerUser(trimmedName, trimmedUsername, trimmedEmail, password, consentAgreed);
      setStep('otp');
      setResendCountdown(60);
      setOtp(['', '', '', '', '', '']);
      setTimeout(() => otpInputRefs.current[0]?.focus(), 100);
    } catch (err: any) {
      const msg = err?.message || '';
      if (msg.includes('Failed to fetch') || msg.includes('NetworkError') || msg.includes('Network request failed')) {
        setFormError('Unable to connect to the backend server. Please make sure the backend is running at http://127.0.0.1:8000.');
      } else {
        setFormError(msg || 'Registration failed. Please check your inputs.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  // ---------------------------------------------------------------------------
  // OTP Input Handlers
  // ---------------------------------------------------------------------------
  const handleOtpChange = (index: number, value: string) => {
    // Only accept numeric digit
    const cleaned = value.replace(/\D/g, '');
    const newOtp = [...otp];

    if (cleaned.length > 1) {
      // Paste handling
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

    // Auto-advance
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
    setOtpError(null);
    const code = otp.join('').trim();
    if (code.length !== 6) {
      setOtpError('Please enter the full 6-digit verification code.');
      return;
    }

    setIsVerifyingOtp(true);
    try {
      const res = await verifyEmail(email.trim(), code);
      setAuthSession(res.user, res.token);
      navigate('/dashboard', { replace: true });
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
      await resendOtp(email.trim(), 'register');
      setResendCountdown(60);
      setResendStatus('A new 6-digit verification code has been sent.');
    } catch (err: any) {
      setOtpError(err?.message || 'Failed to resend verification code.');
    } finally {
      setIsResending(false);
    }
  };

  return (
    <div className="min-h-[calc(100vh-140px)] flex items-center justify-center px-4 py-12">
      <div className="max-w-md w-full bg-[#111827] border border-slate-800 rounded-2xl p-8 shadow-2xl relative overflow-hidden">
        {/* Glow accent */}
        <div className="absolute -top-24 -right-24 w-48 h-48 bg-blue-500/10 rounded-full blur-3xl pointer-events-none" />

        {step === 'form' ? (
          <>
            <div className="text-center mb-8">
              <div className="inline-flex p-3 bg-blue-500/10 border border-blue-500/20 rounded-xl text-blue-400 mb-3">
                <Shield className="w-8 h-8" />
              </div>
              <h1 className="text-2xl font-bold text-white tracking-tight">Create Account</h1>
              <p className="text-sm text-slate-400 mt-1">
                Sign up to run security audits and track incident investigations
              </p>
            </div>

            {formError && (
              <div className="mb-6 p-3.5 bg-red-900/30 border border-red-800/60 rounded-xl flex items-start gap-2.5 text-sm text-red-300">
                <AlertCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
                <span>{formError}</span>
              </div>
            )}

            <form onSubmit={handleRegisterSubmit} className="space-y-4">
              {/* Full Name */}
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5 uppercase tracking-wider">
                  Full Name
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                    <UserIcon className="w-4 h-4" />
                  </div>
                  <input
                    type="text"
                    required
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="Jane Doe"
                    className="w-full bg-[#0B0F19] border border-slate-700/80 rounded-xl pl-10 pr-4 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500 transition-colors"
                  />
                </div>
              </div>

              {/* Username with Live Debounced Availability */}
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5 uppercase tracking-wider">
                  Username (Unique handle)
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                    <AtSign className="w-4 h-4" />
                  </div>
                  <input
                    type="text"
                    required
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="janedoe"
                    className={`w-full bg-[#0B0F19] border rounded-xl pl-10 pr-10 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none transition-colors ${
                      usernameStatus === 'available'
                        ? 'border-emerald-500/60 focus:ring-2 focus:ring-emerald-500/50'
                        : usernameStatus === 'taken' || usernameStatus === 'invalid' || usernameStatus === 'reserved'
                        ? 'border-red-500/60 focus:ring-2 focus:ring-red-500/50'
                        : 'border-slate-700/80 focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500'
                    }`}
                  />
                  <div className="absolute inset-y-0 right-0 pr-3.5 flex items-center pointer-events-none">
                    {usernameStatus === 'checking' && (
                      <Loader2 className="w-4 h-4 text-cyan-400 animate-spin" />
                    )}
                    {usernameStatus === 'available' && (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    )}
                    {(usernameStatus === 'taken' ||
                      usernameStatus === 'invalid' ||
                      usernameStatus === 'reserved') && (
                      <AlertCircle className="w-4 h-4 text-red-400" />
                    )}
                  </div>
                </div>

                {/* Username Feedback Message */}
                {usernameMessage && (
                  <p
                    className={`text-xs mt-1.5 flex items-center gap-1.5 ${
                      usernameStatus === 'available'
                        ? 'text-emerald-400'
                        : usernameStatus === 'checking'
                        ? 'text-cyan-400'
                        : 'text-red-400'
                    }`}
                  >
                    <span>{usernameMessage}</span>
                  </p>
                )}
                {!usernameMessage && (
                  <p className="text-[11px] text-slate-500 mt-1">
                    3-20 characters: letters, digits, underscores, dots. Must start with letter.
                  </p>
                )}
              </div>

              {/* Email Address */}
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5 uppercase tracking-wider">
                  Email Address
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                    <Mail className="w-4 h-4" />
                  </div>
                  <input
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="name@example.com"
                    className="w-full bg-[#0B0F19] border border-slate-700/80 rounded-xl pl-10 pr-4 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500 transition-colors"
                  />
                </div>
              </div>

              {/* Password */}
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5 uppercase tracking-wider">
                  Password (Min. 8 characters)
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                    <Lock className="w-4 h-4" />
                  </div>
                  <input
                    type="password"
                    required
                    minLength={8}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••"
                    className="w-full bg-[#0B0F19] border border-slate-700/80 rounded-xl pl-10 pr-4 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500 transition-colors"
                  />
                </div>
              </div>

              {/* Consent Checkbox */}
              <div className="pt-2">
                <label className="flex items-start gap-3 cursor-pointer group">
                  <input
                    type="checkbox"
                    required
                    checked={consentAgreed}
                    onChange={(e) => setConsentAgreed(e.target.checked)}
                    className="mt-1 rounded bg-[#0B0F19] border-slate-700 text-blue-600 focus:ring-blue-500 focus:ring-offset-0 focus:ring-2 cursor-pointer"
                  />
                  <span className="text-xs text-slate-300 leading-relaxed group-hover:text-slate-200">
                    I understand and agree that my account and a summary of my scan results are stored,
                    and that authorized administrators can view these summaries as detailed in the{' '}
                    <Link to="/privacy" target="_blank" className="text-blue-400 underline hover:text-blue-300">
                      Privacy Policy
                    </Link>
                    . Uploaded log files are processed in memory and never retained.
                  </span>
                </label>
              </div>

              <button
                type="submit"
                disabled={isLoading}
                className="w-full mt-3 py-3 px-4 bg-blue-600 hover:bg-blue-500 active:bg-blue-700 disabled:opacity-60 text-white font-medium rounded-xl text-sm transition-all duration-150 flex items-center justify-center gap-2 shadow-lg shadow-blue-600/20 cursor-pointer disabled:cursor-not-allowed"
              >
                {isLoading ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Sending Verification Code...
                  </>
                ) : (
                  <>
                    Create Account &amp; Verify Email
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </form>

            <div className="mt-8 pt-6 border-t border-slate-800 text-center">
              <p className="text-xs text-slate-400">
                Already have an account?{' '}
                <Link to="/login" className="text-blue-400 hover:text-blue-300 font-medium">
                  Sign in
                </Link>
              </p>
            </div>
          </>
        ) : (
          /* Step 2: Email OTP Screen */
          <div>
            <div className="text-center mb-6">
              <div className="inline-flex p-3 bg-cyan-500/10 border border-cyan-500/20 rounded-xl text-cyan-400 mb-3">
                <Mail className="w-8 h-8" />
              </div>
              <h1 className="text-2xl font-bold text-white tracking-tight">Verify Your Email</h1>
              <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">
                We sent a 6-digit verification code to <br />
                <span className="text-cyan-300 font-mono font-medium">{email}</span>
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
                    className="w-11 h-13 sm:w-12 sm:h-14 bg-[#0B0F19] border border-slate-700/80 rounded-xl text-center text-xl sm:text-2xl font-mono font-bold text-cyan-300 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500 transition-colors"
                  />
                ))}
              </div>

              <div className="space-y-2 text-center">
                <p className="text-[11px] text-slate-400">
                  Code expires in 10 minutes. If you don&apos;t see it, check your spam folder.
                </p>
                <div className="p-2.5 bg-cyan-950/30 border border-cyan-800/30 rounded-xl">
                  <p className="text-[11px] text-cyan-300/90 leading-relaxed">
                    <span className="font-semibold text-cyan-200">Local Testing Note:</span> If SMTP / Resend is unconfigured in <code className="bg-slate-900 px-1 py-0.5 rounded text-cyan-300">backend/.env</code>, the OTP verification code is printed directly in your backend terminal console.
                  </p>
                </div>
              </div>

              <button
                type="submit"
                disabled={isVerifyingOtp || otp.join('').length !== 6}
                className="w-full py-3 px-4 bg-cyan-600 hover:bg-cyan-500 active:bg-cyan-700 disabled:opacity-50 text-white font-medium rounded-xl text-sm transition-all flex items-center justify-center gap-2 shadow-lg shadow-cyan-600/20 cursor-pointer disabled:cursor-not-allowed"
              >
                {isVerifyingOtp ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Verifying Code...
                  </>
                ) : (
                  <>
                    Verify &amp; Activate Account
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </form>

            {/* Resend & Change Email controls */}
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
                    className="inline-flex items-center gap-1.5 text-xs text-cyan-400 hover:text-cyan-300 font-medium transition-colors"
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
                    setStep('form');
                    setOtp(['', '', '', '', '', '']);
                    setOtpError(null);
                  }}
                  className="inline-flex items-center gap-1 text-xs text-slate-400 hover:text-slate-200 transition-colors"
                >
                  <ArrowLeft className="w-3.5 h-3.5" />
                  Change email or details
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
