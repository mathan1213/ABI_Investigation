import React from 'react';
import { LucideIcon } from 'lucide-react';
import { RiskLevel } from '../lib/types';
import { RiskBadge } from './RiskBadge';

interface StatCardProps {
  title: string;
  value: string | number;
  level: RiskLevel;
  icon: LucideIcon;
  subtitle?: string;
  badgeLabel?: string;
  trend?: string;
  onClick?: () => void;
  className?: string;
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  level,
  icon: Icon,
  subtitle,
  badgeLabel,
  trend,
  onClick,
  className = '',
}) => {
  const glowColors = {
    critical: 'hover:border-red-500/40 hover:shadow-glow-red',
    high: 'hover:border-orange-500/40 hover:shadow-glow-orange',
    medium: 'hover:border-yellow-500/40 hover:shadow-glow-yellow',
    low: 'hover:border-emerald-500/40 hover:shadow-glow-green',
  }[level];

  const iconColors = {
    critical: 'text-red-400 bg-red-500/10 border-red-500/20',
    high: 'text-orange-400 bg-orange-500/10 border-orange-500/20',
    medium: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
    low: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
  }[level];

  return (
    <div
      onClick={onClick}
      className={`glass-card rounded-2xl p-5 border border-slate-800 transition-all duration-300 ${glowColors} ${
        onClick ? 'cursor-pointer' : ''
      } ${className}`}
    >
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <div className={`p-2.5 rounded-xl border ${iconColors}`}>
            <Icon size={22} />
          </div>
          <div>
            <h3 className="text-sm font-medium text-slate-400">{title}</h3>
            <div className="flex items-baseline gap-2 mt-1">
              <span className="text-2xl font-bold tracking-tight text-white">{value}</span>
              {trend && <span className="text-xs text-slate-400 font-medium">{trend}</span>}
            </div>
          </div>
        </div>
        <RiskBadge level={level} size="sm" label={badgeLabel} />
      </div>

      {subtitle && (
        <div className="mt-3 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-400">
          <span className="truncate">{subtitle}</span>
        </div>
      )}
    </div>
  );
};
