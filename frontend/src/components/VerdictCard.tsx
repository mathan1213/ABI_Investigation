import React from 'react';
import { ShieldCheck, AlertTriangle, ShieldX } from 'lucide-react';

interface VerdictItem {
  label: string;
  value: React.ReactNode;
  isDanger?: boolean;
}

interface VerdictCardProps {
  verdict: 'Safe' | 'Suspicious' | 'Dangerous';
  title?: string;
  explanation: string;
  score?: number;
  scoreLabel?: string;
  items?: VerdictItem[];
  className?: string;
}

export const VerdictCard: React.FC<VerdictCardProps> = ({
  verdict,
  title,
  explanation,
  score,
  scoreLabel = 'Risk Score',
  items,
  className = '',
}) => {
  const config = {
    Dangerous: {
      border: 'border-red-500/40 bg-gradient-to-br from-red-950/40 via-[#111A2E] to-[#111A2E]',
      badge: 'bg-red-500/20 text-red-400 border-red-500/40 shadow-glow-red',
      icon: ShieldX,
      iconColor: 'text-red-400 bg-red-500/10 border-red-500/30',
      label: 'Dangerous / Action Required',
    },
    Suspicious: {
      border: 'border-yellow-500/40 bg-gradient-to-br from-yellow-950/30 via-[#111A2E] to-[#111A2E]',
      badge: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40 shadow-glow-yellow',
      icon: AlertTriangle,
      iconColor: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30',
      label: 'Suspicious Activity Detected',
    },
    Safe: {
      border: 'border-emerald-500/40 bg-gradient-to-br from-emerald-950/30 via-[#111A2E] to-[#111A2E]',
      badge: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40 shadow-glow-green',
      icon: ShieldCheck,
      iconColor: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
      label: 'Safe & Clean',
    },
  }[verdict];

  const Icon = config.icon;

  return (
    <div className={`glass-card rounded-2xl p-6 border ${config.border} ${className}`}>
      <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
        <div className="flex items-start gap-4">
          <div className={`p-3 rounded-2xl border ${config.iconColor} shrink-0`}>
            <Icon size={28} />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2 mb-1">
              <span className={`px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider border ${config.badge}`}>
                {verdict}
              </span>
              {title && <h3 className="text-lg font-bold text-white">{title}</h3>}
            </div>
            <p className="text-sm text-slate-300 leading-relaxed max-w-2xl mt-2">
              {explanation}
            </p>
          </div>
        </div>

        {score !== undefined && (
          <div className="flex md:flex-col items-center md:items-end justify-between border-t md:border-t-0 pt-3 md:pt-0 border-slate-800">
            <span className="text-xs uppercase tracking-wider text-slate-400 font-medium">
              {scoreLabel}
            </span>
            <span className="text-3xl font-extrabold text-white mt-0.5">
              {score}
              <span className="text-xs text-slate-400 font-normal">/100</span>
            </span>
          </div>
        )}
      </div>

      {items && items.length > 0 && (
        <div className="mt-6 pt-5 border-t border-slate-800/80 grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-4 text-xs">
          {items.map((item, index) => (
            <div key={index} className="space-y-1">
              <span className="text-slate-400 uppercase tracking-wider block text-[11px] font-medium">
                {item.label}
              </span>
              <div className={`font-medium ${item.isDanger ? 'text-red-400 font-semibold' : 'text-slate-200'}`}>
                {item.value}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
