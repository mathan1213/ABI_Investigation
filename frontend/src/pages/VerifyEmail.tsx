import React, { useEffect, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import {
  CheckCircle2,
  AlertCircle,
  Loader2,
  Mail,
  ArrowRight,
  Send,
} from 'lucide-react';
import { verifyEmail, resendVerification } from '../lib/api';

export const VerifyEmail: React.FC = () => {
  const [searchParams] = useSearchParams();
  const [status, setStatus] = useState<'loading' | 'success' | 'error'>('loading');
  const [message, setMessage] = useState<string>('');
  
  // Resend form state for error cases
  const [resendEmail, setResendEmail] = useState<string>('');
  const [isResending, setIsResending] = useState<boolean>(false);
  const [resendMessage, setResendMessage] = useState<string | null>(null);
  const [resendError, setResendError] = useState<string | null>(null);

  // StrictMode double-execution guard
  const hasExecutedRef = useRef(false);

  useEffect(() => {
    const token = searchParams.get('token');

    // Scrub token from the address bar immediately
    if (token) {
      window.history.replaceState({}, document.title, window.location.pathname);
    }

    if (hasExecutedRef.current) return;
    hasExecutedRef.current = true;

    if (!token) {
      setStatus('error');
      setMessage('No verification token provided. Please check the link from your email.');
      return;
    }

    verifyEmail(token)
      .then((res) => {
        setStatus('success');
        setMessage(res.message || 'Email verified. You can now log in.');
      })
      .catch((err: any) => {
        setStatus('error');
        setMessage(
          err?.message ||
            'This verification link is invalid, expired, or has already been used.'
        );
      });
  }, [searchParams]);

  const handleResend = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = resendEmail.trim();
    if (!trimmed) return;

    setIsResending(true);
    setResendMessage(null);
    setResendError(null);

    try {
      const res = await resendVerification(trimmed);
      setResendMessage(res.message || 'If this account exists and is not verified, a new email was sent.');
    } catch (err: any) {
      setResendError(err?.message || 'Failed to send verification email. Please try again later.');
    } finally {
      setIsResending(false);
    }
  };

  return (
    <div className="min-h-[calc(100vh-140px)] flex items-center justify-center px-4 py-12">
      <div className="max-w-md w-full bg-[#111827] border border-slate-800 rounded-2xl p-8 shadow-2xl relative overflow-hidden text-center space-y-6">
        <div className="absolute -top-24 -right-24 w-48 h-48 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />

        {/* LOADING STATE */}
        {status === 'loading' && (
          <div className="space-y-4 py-6">
            <div className="flex justify-center">
              <div className="w-16 h-16 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shadow-lg shadow-cyan-500/20">
                <Loader2 className="w-8 h-8 animate-spin" />
              </div>
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white tracking-tight">
                Verifying your email...
              </h1>
              <p className="text-xs text-slate-400 mt-1">
                Please wait while we confirm your verification link.
              </p>
            </div>
          </div>
        )}

        {/* SUCCESS STATE */}
        {status === 'success' && (
          <div className="space-y-6">
            <div className="flex justify-center">
              <div className="w-16 h-16 rounded-2xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 shadow-lg shadow-emerald-500/20">
                <CheckCircle2 className="w-8 h-8" />
              </div>
            </div>

            <div>
              <h1 className="text-2xl font-bold text-white tracking-tight">
                Email Verified!
              </h1>
              <p className="text-xs text-slate-400 mt-1">
                Account Breach Investigation Platform
              </p>
            </div>

            <div className="p-4 rounded-xl bg-emerald-950/40 border border-emerald-800/60 text-emerald-300 text-sm leading-relaxed text-center">
              {message || 'Email verified. You can now log in.'}
            </div>

            <div className="pt-2">
              <Link
                to="/login"
                state={{ successMessage: 'Email verified. You can now log in.' }}
                className="w-full py-3 px-4 bg-blue-600 hover:bg-blue-500 active:bg-blue-700 text-white font-medium rounded-xl text-sm transition-all duration-150 flex items-center justify-center gap-2 shadow-lg shadow-blue-600/25"
              >
                <span>Log in</span>
                <ArrowRight className="w-4 h-4" />
              </Link>
            </div>
          </div>
        )}

        {/* ERROR STATE */}
        {status === 'error' && (
          <div className="space-y-6">
            <div className="flex justify-center">
              <div className="w-16 h-16 rounded-2xl bg-red-500/10 border border-red-500/30 flex items-center justify-center text-red-400 shadow-lg shadow-red-500/20">
                <AlertCircle className="w-8 h-8" />
              </div>
            </div>

            <div>
              <h1 className="text-2xl font-bold text-white tracking-tight">
                Verification Failed
              </h1>
              <p className="text-xs text-slate-400 mt-1">
                Account Breach Investigation Platform
              </p>
            </div>

            <div className="p-4 rounded-xl bg-red-950/40 border border-red-800/60 text-red-300 text-sm leading-relaxed text-left">
              {message}
            </div>

            {/* Resend Verification Form */}
            <div className="bg-[#0B0F19] border border-slate-800 rounded-xl p-4 text-left space-y-3">
              <p className="text-xs font-medium text-slate-300">
                Need a new verification link?
              </p>
              <form onSubmit={handleResend} className="space-y-2.5">
                <div className="relative">
                  <Mail className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="email"
                    required
                    value={resendEmail}
                    onChange={(e) => setResendEmail(e.target.value)}
                    placeholder="Enter your registered email"
                    className="w-full bg-[#111827] border border-slate-700 rounded-lg pl-9 pr-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                  />
                </div>
                <button
                  type="submit"
                  disabled={isResending || !resendEmail.trim()}
                  className="w-full py-2 px-3 bg-slate-800 hover:bg-slate-700 active:bg-slate-900 text-slate-200 text-xs font-medium rounded-lg transition-colors border border-slate-700 flex items-center justify-center gap-1.5 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
                >
                  {isResending ? (
                    <>
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      <span>Sending...</span>
                    </>
                  ) : (
                    <>
                      <Send className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Resend verification email</span>
                    </>
                  )}
                </button>
              </form>

              {resendMessage && (
                <div className="p-2.5 bg-emerald-900/30 border border-emerald-800/60 rounded-lg text-xs text-emerald-300 flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                  <span>{resendMessage}</span>
                </div>
              )}
              {resendError && (
                <div className="p-2.5 bg-red-900/30 border border-red-800/60 rounded-lg text-xs text-red-300 flex items-center gap-2">
                  <AlertCircle className="w-3.5 h-3.5 text-red-400 shrink-0" />
                  <span>{resendError}</span>
                </div>
              )}
            </div>

            <div className="pt-2">
              <Link
                to="/login"
                className="block w-full py-2.5 px-4 text-center text-sm font-medium text-slate-400 hover:text-white transition-colors"
              >
                Return to Log in
              </Link>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
