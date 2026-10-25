import React from 'react';
import { Link } from 'react-router-dom';
import { ShieldCheck, Lock, Trash2, Settings } from 'lucide-react';
import { useScan } from '../context/ScanContext';

export const Footer: React.FC = () => {
  const { clearAllScans } = useScan();

  return (
    <footer className="w-full border-t border-slate-850 bg-[#070C15] py-8 text-xs text-slate-400 no-print">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex flex-col md:flex-row items-center justify-between gap-4 text-center md:text-left">
          {/* Privacy Note Required */}
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 flex items-center justify-center shrink-0">
              <ShieldCheck size={18} />
            </div>
            <div>
              <div className="font-semibold text-slate-300 flex items-center justify-center md:justify-start gap-1.5">
                <Lock size={12} className="text-cyan-400" />
                <span>Zero-Knowledge Architecture</span>
              </div>
              <p className="text-slate-400 mt-0.5">
                We never store your data. Results are deleted after your session.
              </p>
            </div>
          </div>

          {/* Actions & session clear */}
          <div className="flex items-center gap-4 flex-wrap justify-center md:justify-end">
            <Link
              to="/setup"
              className="text-slate-400 hover:text-cyan-400 transition-colors flex items-center gap-1"
              title="View backend configuration and developer setup"
            >
              <Settings size={13} />
              <span>Owner setup instructions</span>
            </Link>

            <span className="text-slate-700 hidden sm:inline">•</span>

            <button
              onClick={clearAllScans}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-900 text-slate-400 hover:text-red-400 hover:border-red-500/30 transition-colors"
              title="Wipe all in-memory scan results and state"
            >
              <Trash2 size={13} />
              <span>Clear all data</span>
            </button>

            <span className="text-slate-700 hidden sm:inline">•</span>

            <div className="text-slate-400 flex items-center gap-1">
              <span>ABI Investigation</span>
              <span>•</span>
              <span className="text-cyan-400">v1.0</span>
            </div>
          </div>
        </div>
      </div>
    </footer>
  );
};
