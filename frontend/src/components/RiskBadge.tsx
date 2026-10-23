import React from 'react';
import { RiskLevel } from '../lib/types';
import { AlertCircle, AlertTriangle, CheckCircle2, ShieldAlert } from 'lucide-react';

interface RiskBadgeProps {
  level: RiskLevel;
  size?: 'sm' | 'md' | 'lg';
  showIcon?: boolean;
  label?: string;
  className?: string;
}

export const RiskBadge: React.FC<RiskBadgeProps> = ({
  level,
  size = 'md',
  showIcon = true,
  label,
  className = '',
}) => {
  const config = {
    critical: {
      bg: 'bg-red-500/10 text-red-400 border-red-500/30',
      dot: 'bg-red-500 shadow-glow-red',
      icon: ShieldAlert,
      defaultLabel: 'Critical Risk',
    },
    high: {
      bg: 'bg-orange-500/10 text-orange-400 border-orange-500/30',
      dot: 'bg-orange-500 shadow-glow-orange',
      icon: AlertTriangle,
      defaultLabel: 'High Risk',
    },
    medium: {
      bg: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
      dot: 'bg-yellow-500 shadow-glow-yellow',
      icon: AlertCircle,
      defaultLabel: 'Medium Risk',
    },
    low: {
      bg: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
      dot: 'bg-emerald-500 shadow-glow-green',
      icon: CheckCircle2,
      defaultLabel: 'Safe / Low Risk',
    },
  }[level];

  const sizeClasses = {
    sm: 'text-xs px-2 py-0.5 gap-1',
    md: 'text-xs px-2.5 py-1 gap-1.5 font-medium',
    lg: 'text-sm px-3.5 py-1.5 gap-2 font-semibold',
  }[size];

  const iconSizes = {
    sm: 12,
    md: 14,
    lg: 16,
  }[size];

  const Icon = config.icon;

  return (
    <span
      className={`inline-flex items-center rounded-full border tracking-wide uppercase font-semibold ${config.bg} ${sizeClasses} ${className}`}
    >
      {showIcon && <Icon size={iconSizes} className="shrink-0" />}
      <span>{label || config.defaultLabel}</span>
    </span>
  );
};
