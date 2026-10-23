import React from 'react';
import { RiskLevel } from '../lib/types';

interface RiskGaugeProps {
  score: number; // 0 to 100
  level?: RiskLevel;
  size?: 'sm' | 'md' | 'lg';
  showLabel?: boolean;
  subtitle?: string;
  className?: string;
}

export const RiskGauge: React.FC<RiskGaugeProps> = ({
  score,
  level,
  size = 'md',
  showLabel = true,
  subtitle,
  className = '',
}) => {
  // Clamp score
  const safeScore = Math.min(100, Math.max(0, score));

  // Determine level if not explicitly provided
  const computedLevel: RiskLevel =
    level ||
    (safeScore >= 75
      ? 'critical'
      : safeScore >= 50
      ? 'high'
      : safeScore >= 25
      ? 'medium'
      : 'low');

  const colorConfig = {
    critical: {
      color: '#EF4444',
      label: 'Critical Risk',
      glow: 'drop-shadow(0 0 12px rgba(239, 68, 68, 0.4))',
      textColor: 'text-red-400',
    },
    high: {
      color: '#F97316',
      label: 'High Risk',
      glow: 'drop-shadow(0 0 12px rgba(249, 115, 22, 0.4))',
      textColor: 'text-orange-400',
    },
    medium: {
      color: '#EAB308',
      label: 'Medium Risk',
      glow: 'drop-shadow(0 0 12px rgba(234, 179, 8, 0.4))',
      textColor: 'text-yellow-400',
    },
    low: {
      color: '#10B981',
      label: 'Low / Secure',
      glow: 'drop-shadow(0 0 12px rgba(16, 185, 129, 0.4))',
      textColor: 'text-emerald-400',
    },
  }[computedLevel];

  const dimensions = {
    sm: { width: 140, height: 85, radius: 55, strokeWidth: 10, fontSize: 'text-2xl' },
    md: { width: 220, height: 130, radius: 85, strokeWidth: 14, fontSize: 'text-4xl' },
    lg: { width: 280, height: 165, radius: 110, strokeWidth: 18, fontSize: 'text-5xl' },
  }[size];

  // SVG semicircular calculations
  const cx = dimensions.width / 2;
  const cy = dimensions.height;
  const r = dimensions.radius;
  const strokeWidth = dimensions.strokeWidth;

  // Arc length for semicircle: PI * r
  const arcLength = Math.PI * r;
  // Progress fraction
  const progressOffset = arcLength * (1 - safeScore / 100);

  // Angle for speedometer needle: from -180 deg (left) to 0 deg (right)
  const needleAngle = -180 + (safeScore / 100) * 180;
  const needleRad = (needleAngle * Math.PI) / 180;
  const needleLength = r - 12;
  const nx = cx + needleLength * Math.cos(needleRad);
  const ny = cy + needleLength * Math.sin(needleRad);

  return (
    <div className={`flex flex-col items-center justify-center text-center ${className}`}>
      <div className="relative inline-flex items-center justify-center" style={{ width: dimensions.width, height: dimensions.height }}>
        <svg
          width={dimensions.width}
          height={dimensions.height + 10}
          viewBox={`0 0 ${dimensions.width} ${dimensions.height + 10}`}
          className="overflow-visible"
        >
          <defs>
            <linearGradient id="gaugeBgGrad" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#10B981" stopOpacity="0.25" />
              <stop offset="35%" stopColor="#EAB308" stopOpacity="0.25" />
              <stop offset="70%" stopColor="#F97316" stopOpacity="0.25" />
              <stop offset="100%" stopColor="#EF4444" stopOpacity="0.25" />
            </linearGradient>

            <linearGradient id="gaugeValueGrad" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#10B981" />
              <stop offset="35%" stopColor="#EAB308" />
              <stop offset="70%" stopColor="#F97316" />
              <stop offset="100%" stopColor="#EF4444" />
            </linearGradient>
          </defs>

          {/* Background Track Arc */}
          <path
            d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
            fill="none"
            stroke="rgba(255, 255, 255, 0.08)"
            strokeWidth={strokeWidth}
            strokeLinecap="round"
          />

          {/* Subtle colored background segments */}
          <path
            d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
            fill="none"
            stroke="url(#gaugeBgGrad)"
            strokeWidth={strokeWidth}
            strokeLinecap="round"
          />

          {/* Active Progress Arc */}
          <path
            d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
            fill="none"
            stroke={colorConfig.color}
            strokeWidth={strokeWidth}
            strokeDasharray={arcLength}
            strokeDashoffset={progressOffset}
            strokeLinecap="round"
            style={{
              transition: 'stroke-dashoffset 1s ease-out, stroke 0.5s ease',
              filter: colorConfig.glow,
            }}
          />

          {/* Center Hub */}
          <circle cx={cx} cy={cy} r={strokeWidth * 0.75} fill="#1E293B" stroke={colorConfig.color} strokeWidth="3" />

          {/* Needle Indicator */}
          <line
            x1={cx}
            y1={cy}
            x2={nx}
            y2={ny}
            stroke={colorConfig.color}
            strokeWidth="3.5"
            strokeLinecap="round"
            style={{
              transition: 'all 0.8s cubic-bezier(0.34, 1.56, 0.64, 1)',
              filter: `drop-shadow(0 0 6px ${colorConfig.color})`,
            }}
          />
        </svg>

        {/* Numeric value readout inside arc */}
        <div
          className="absolute flex flex-col items-center justify-end pointer-events-none"
          style={{ bottom: size === 'sm' ? 0 : 4 }}
        >
          <span className={`font-extrabold tracking-tight ${dimensions.fontSize} ${colorConfig.textColor}`}>
            {safeScore}
            <span className="text-xs font-semibold text-slate-400 ml-0.5">/100</span>
          </span>
        </div>
      </div>

      {showLabel && (
        <div className="mt-2 flex flex-col items-center">
          <span className={`text-sm font-bold uppercase tracking-wider ${colorConfig.textColor}`}>
            {colorConfig.label}
          </span>
          {subtitle && <p className="text-xs text-slate-400 mt-0.5 max-w-xs">{subtitle}</p>}
        </div>
      )}
    </div>
  );
};
