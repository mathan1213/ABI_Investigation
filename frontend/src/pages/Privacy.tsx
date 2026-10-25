import React from 'react';
import { ShieldCheck, Database, Eye, Trash2, Lock, ArrowLeft } from 'lucide-react';
import { Link } from 'react-router-dom';

export const Privacy: React.FC = () => {
  return (
    <div className="max-w-4xl mx-auto px-4 py-12">
      <div className="mb-6">
        <Link
          to="/"
          className="inline-flex items-center gap-2 text-sm text-slate-400 hover:text-slate-200 transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Overview
        </Link>
      </div>

      <div className="bg-[#111827] border border-slate-800 rounded-2xl p-8 md:p-10 shadow-xl space-y-8">
        <div className="border-b border-slate-800 pb-6">
          <div className="inline-flex p-3 bg-blue-500/10 border border-blue-500/20 rounded-xl text-blue-400 mb-3">
            <ShieldCheck className="w-8 h-8" />
          </div>
          <h1 className="text-3xl font-bold text-white tracking-tight">Privacy Policy & Data Architecture</h1>
          <p className="text-slate-400 mt-2 text-sm">
            Last updated: October 2026 • Transparency disclosure on data storage, memory processing, and administrator oversight.
          </p>
        </div>

        {/* Section 1: Exactly What is Stored */}
        <section className="space-y-3">
          <div className="flex items-center gap-2 text-lg font-semibold text-white">
            <Database className="w-5 h-5 text-blue-400" />
            <h2>1. What Data We Store</h2>
          </div>
          <p className="text-sm text-slate-300 leading-relaxed">
            To provide persistent investigative dossiers and user account management, our system stores:
          </p>
          <ul className="list-disc list-inside space-y-1.5 text-sm text-slate-300 pl-2">
            <li><strong className="text-white">Account Details:</strong> Your name, email address, password hash (securely hashed with bcrypt; we never see or store plain passwords), and login timestamps.</li>
            <li><strong className="text-white">Scan Summaries:</strong> Metadata of scans you initiate (module name, target label, overall risk score, risk level, and sanitized finding summaries).</li>
            <li><strong className="text-white">Generated Reports:</strong> Composite risk scores, recommended actions, and executive dossiers created by the risk engine.</li>
            <li><strong className="text-white">Activity Logs:</strong> Timestamps of system actions (e.g. login, log upload, repo scan, report generation) for security auditing.</li>
          </ul>
        </section>

        {/* Section 2: What We NEVER Store */}
        <section className="space-y-3">
          <div className="flex items-center gap-2 text-lg font-semibold text-white">
            <Lock className="w-5 h-5 text-emerald-400" />
            <h2>2. What We Never Store (In-Memory Processing)</h2>
          </div>
          <p className="text-sm text-slate-300 leading-relaxed">
            Your privacy and digital security are our top priorities. The following items are strictly transient:
          </p>
          <ul className="list-disc list-inside space-y-1.5 text-sm text-slate-300 pl-2">
            <li><strong className="text-white">No Raw Uploaded Files:</strong> Uploaded Telegram exports and log files are parsed purely in server memory and discarded immediately upon request completion.</li>
            <li><strong className="text-white">No Message Contents:</strong> Chat messages are never saved to disk or database. Non-service personal chats are discarded completely without inspection.</li>
            <li><strong className="text-white">Immediate OTP Masking:</strong> Any 4-to-8 digit login code in service chat notifications is immediately masked with <code className="text-blue-300 bg-slate-900 px-1 py-0.5 rounded">****</code> upon parsing.</li>
            <li><strong className="text-white">No Raw Secrets:</strong> Secrets detected in code repositories are masked prior to database persistence.</li>
          </ul>
        </section>

        {/* Section 3: Administrator Visibility */}
        <section className="space-y-3">
          <div className="flex items-center gap-2 text-lg font-semibold text-white">
            <Eye className="w-5 h-5 text-amber-400" />
            <h2>3. Administrator Visibility</h2>
          </div>
          <p className="text-sm text-slate-300 leading-relaxed">
            Authorized platform administrators have access to an administrative dashboard containing:
          </p>
          <ul className="list-disc list-inside space-y-1.5 text-sm text-slate-300 pl-2">
            <li>Aggregate system statistics (total users, scan counts, risk distributions).</li>
            <li>User account profiles and their associated scan summaries and reports.</li>
            <li>System activity logs. Whenever an administrator accesses a user's forensic details, an immutable <code className="text-amber-300 bg-slate-900 px-1 py-0.5 rounded">admin_viewed_user</code> activity log is generated.</li>
          </ul>
        </section>

        {/* Section 4: Self-Service Deletion */}
        <section className="space-y-3">
          <div className="flex items-center gap-2 text-lg font-semibold text-white">
            <Trash2 className="w-5 h-5 text-red-400" />
            <h2>4. Your Right to Immediate Deletion</h2>
          </div>
          <p className="text-sm text-slate-300 leading-relaxed">
            You retain absolute ownership of your data. You may delete your account and all associated scan history, reports, and session records at any time directly through the navbar user menu by selecting <strong className="text-white">"Delete my account"</strong>. Deletion is instantaneous and permanent.
          </p>
        </section>
      </div>
    </div>
  );
};
