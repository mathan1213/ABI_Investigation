import React, { useState, useEffect } from 'react';
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
  KeyRound,
  Send,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { loginUser, resetPassword, resendVerification } from '../lib/api';

export const Login: React.FC = () => {
  const { setAuthSession } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  // Mode: 'login' | 'forgot'
  const [mode, setMode] = useState<'login' | 'forgot'>('login');

  // Login inputs
  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [loginError, setLoginError] = useState<string | null>(null);
  const [isEmailUnverified, setIsEmailUnverified] = useState(false);
  const [unverifiedEmail, setUnverifiedEmail] = useState('');
  const [isResendingVerification, setIsResendingVerification] = useState(false);
  const [resendSuccess, setResendSuccess] = useState<string | null>(null);
  const [resendError, setResendError] = useState<string | null>(null);
  const [successBanner, setSuccessBanner] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Forgot password inputs
  const [forgotEmail, setForgotEmail] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [forgotMsg, setForgotMsg] = useState<string | null>(null);
  const [forgotError, setForgotError] = useState<string | null>(null);
  const [isForgotLoading, setIsForgotLoading] = useState(false);

  const from = (location.state as any)?.from?.pathname || '/dashboard';

  // Check for success message passed from registration
  useEffect(() => {
    if (location.state?.successMessage) {
      setSuccessBanner(location.state.successMessage);
    }
    if (location.state?.registeredEmail) {
      setIdentifier(location.state.registeredEmail);
    }
  }, [location.state]);

  // ---------------------------------------------------------------------------
  // Submit Credentials (Email/Username + Password)
  // ---------------------------------------------------------------------------
  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoginError(null);
    setIsEmailUnverified(false);
    setResendSuccess(null);
    setResendError(null);

    if (!identifier.trim() || !password) {
      setLoginError('Please enter both your email/username and password.');
      return;
    }

    setIsSubmitting(true);
    try {
      const res = await loginUser(identifier.trim(), password);
      setAuthSession(res.user, res.token);

      // Requirement 4: Admin logs in through the normal login page and is redirected to the admin dashboard
      if (res.user.role === 'admin' || res.user.role === 'super_admin') {
        navigate('/admin', { replace: true });
      } else {
        navigate(from, { replace: true });
      }
    } catch (err: any) {
      if (
        err?.code === 'email_not_verified' ||
        (err?.message && err.message.toLowerCase().includes('verify your email'))
      ) {
        setIsEmailUnverified(true);
        setUnverifiedEmail(identifier.trim());
        setLoginError(err?.message || 'Please verify your email first. Check your inbox.');
      } else {
        setIsEmailUnverified(false);
        setLoginError(err?.message || 'Incorrect email, username or password.');
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleResendVerification = async () => {
    const targetEmail = unverifiedEmail || identifier.trim();
    if (!targetEmail || isResendingVerification) return;

    setIsResendingVerification(true);
    setResendSuccess(null);
    setResendError(null);

    try {
      const res = await resendVerification(targetEmail);
      setResendSuccess(
        res.message || 'If this account exists and is not verified, a new email was sent'
      );
    } catch (err: any) {
      setResendError(err?.message || 'Failed to resend verification email.');
    } finally {
      setIsResendingVerification(false);
    }
  };

  // ---------------------------------------------------------------------------
  // Forgot / Reset Password Handler
  // ---------------------------------------------------------------------------
  const handleResetPasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setForgotError(null);
    setForgotMsg(null);

    if (!forgotEmail.trim() || !newPassword) {
      setForgotError('Please enter your email and new password.');
      return;
    }
    if (newPassword.length < 8) {
      setForgotError('Password must be at least 8 characters long.');
      return;
    }

    setIsForgotLoading(true);
    try {
      const res = await resetPassword(forgotEmail.trim(), newPassword);
      setForgotMsg(res.message || 'Password reset successfully. You can now sign in.');
      setTimeout(() => {
        setIdentifier(forgotEmail.trim());
        setPassword('');
        setMode('login');
      }, 1500);
    } catch (err: any) {
      setForgotError(err?.message || 'Failed to update password. Please check your email.');
    } finally {
      setIsForgotLoading(false);
    }
  };

  return (
    <div className="min-h-[calc(100vh-140px)] flex items-center justify-center px-4 py-12">
      <div className="max-w-md w-full bg-[#111827] border border-slate-800 rounded-2xl p-8 shadow-2xl relative overflow-hidden">
        {/* Glow accent */}
        <div className="absolute -top-24 -right-24 w-48 h-48 bg-blue-500/10 rounded-full blur-3xl pointer-events-none" />

        {mode === 'login' ? (
          <>
            <div className="text-center mb-8">
              <div className="inline-flex p-3 bg-blue-500/10 border border-blue-500/20 rounded-xl text-blue-400 mb-3">
                <Shield className="w-8 h-8" />
              </div>
              <h1 className="text-2xl font-bold text-white tracking-tight">Sign In</h1>
              <p className="text-sm text-slate-400 mt-1">
                Access your forensics dashboard and security investigation records
              </p>
            </div>

            {successBanner && (
              <div className="mb-6 p-3.5 bg-emerald-900/30 border border-emerald-800/60 rounded-xl flex items-start gap-2.5 text-sm text-emerald-300">
                <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
                <span>{successBanner}</span>
              </div>
            )}

            {loginError && (
              <div className="mb-6 p-3.5 bg-red-900/30 border border-red-800/60 rounded-xl space-y-2.5 text-xs text-red-300">
                <div className="flex items-start gap-2.5 text-sm">
                  <AlertCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
                  <span className="flex-1">{loginError}</span>
                </div>
                {isEmailUnverified && (
                  <div className="pt-2 border-t border-red-800/40 space-y-2">
                    <p className="text-xs text-slate-300">
                      Didn't receive the email or has your link expired?
                    </p>
                    <button
                      type="button"
                      disabled={isResendingVerification}
                      onClick={handleResendVerification}
                      className="py-1.5 px-3 bg-red-950/80 hover:bg-red-900 border border-red-700/60 rounded-lg text-xs font-medium text-white flex items-center gap-1.5 transition-colors cursor-pointer disabled:opacity-50"
                    >
                      {isResendingVerification ? (
                        <>
                          <Loader2 className="w-3.5 h-3.5 animate-spin" />
                          <span>Sending verification email...</span>
                        </>
                      ) : (
                        <>
                          <Send className="w-3.5 h-3.5 text-cyan-400" />
                          <span>Resend verification email</span>
                        </>
                      )}
                    </button>
                    {resendSuccess && (
                      <p className="text-xs text-emerald-300 font-medium">{resendSuccess}</p>
                    )}
                    {resendError && (
                      <p className="text-xs text-red-400 font-medium">{resendError}</p>
                    )}
                  </div>
                )}
              </div>
            )}

            <form onSubmit={handleLoginSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5 uppercase tracking-wider">
                  Email Address or Username
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
                      setMode('forgot');
                    }}
                    className="text-xs text-blue-400 hover:text-blue-300"
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
                disabled={isSubmitting}
                className="w-full mt-2 py-3 px-4 bg-blue-600 hover:bg-blue-500 active:bg-blue-700 disabled:opacity-60 text-white font-medium rounded-xl text-sm transition-all duration-150 flex items-center justify-center gap-2 shadow-lg shadow-blue-600/20 cursor-pointer disabled:cursor-not-allowed"
              >
                {isSubmitting ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Signing in...
                  </>
                ) : (
                  <>
                    Sign In
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </form>

            <div className="mt-8 pt-6 border-t border-slate-800 text-center">
              <p className="text-xs text-slate-400">
                Don't have an account yet?{' '}
                <Link to="/register" className="text-blue-400 hover:text-blue-300 font-medium">
                  Create account
                </Link>
              </p>
            </div>
          </>
        ) : (
          /* Forgot Password Form */
          <div>
            <div className="text-center mb-6">
              <div className="inline-flex p-3 bg-amber-500/10 border border-amber-500/20 rounded-xl text-amber-400 mb-3">
                <KeyRound className="w-8 h-8" />
              </div>
              <h1 className="text-2xl font-bold text-white tracking-tight">Reset Password</h1>
              <p className="text-xs text-slate-400 mt-1">
                Enter your registered email and choose a new password
              </p>
            </div>

            {forgotError && (
              <div className="mb-5 p-3.5 bg-red-900/30 border border-red-800/60 rounded-xl flex items-start gap-2.5 text-xs text-red-300">
                <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                <span>{forgotError}</span>
              </div>
            )}

            {forgotMsg && (
              <div className="mb-5 p-3.5 bg-emerald-900/30 border border-emerald-800/60 rounded-xl flex items-start gap-2.5 text-xs text-emerald-300">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                <span>{forgotMsg}</span>
              </div>
            )}

            <form onSubmit={handleResetPasswordSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5 uppercase tracking-wider">
                  Registered Email
                </label>
                <input
                  type="email"
                  required
                  value={forgotEmail}
                  onChange={(e) => setForgotEmail(e.target.value)}
                  placeholder="name@example.com"
                  className="w-full bg-[#0B0F19] border border-slate-700/80 rounded-xl px-4 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-amber-500/50 focus:border-amber-500 transition-colors"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5 uppercase tracking-wider">
                  New Password (min. 8 characters)
                </label>
                <input
                  type="password"
                  required
                  minLength={8}
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="••••••••"
                  className="w-full bg-[#0B0F19] border border-slate-700/80 rounded-xl px-4 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-amber-500/50 focus:border-amber-500 transition-colors"
                />
              </div>

              <button
                type="submit"
                disabled={isForgotLoading}
                className="w-full mt-2 py-3 px-4 bg-amber-600 hover:bg-amber-500 active:bg-amber-700 disabled:opacity-60 text-white font-medium rounded-xl text-sm transition-all duration-150 flex items-center justify-center gap-2 cursor-pointer"
              >
                {isForgotLoading ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Resetting Password...
                  </>
                ) : (
                  'Update Password'
                )}
              </button>
            </form>

            <button
              type="button"
              onClick={() => setMode('login')}
              className="mt-6 w-full text-center text-xs text-slate-400 hover:text-slate-300 flex items-center justify-center gap-1.5"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              Back to sign in
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

export default Login;
