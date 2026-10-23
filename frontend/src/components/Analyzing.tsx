import React, { useState, useEffect } from 'react';
import { Shield, Sparkles } from 'lucide-react';

interface AnalyzingProps {
  messages: string[];
  title?: string;
  subtitle?: string;
  className?: string;
}

export const Analyzing: React.FC<AnalyzingProps> = ({
  messages,
  title = 'Security Investigation in Progress',
  subtitle = 'Analyzing account traces, connection signatures, and access logs...',
  className = '',
}) => {
  const [currentMessageIndex, setCurrentMessageIndex] = useState(0);
  const [progress, setProgress] = useState(15);

  useEffect(() => {
    // Cycle messages every 1.1s
    const messageInterval = setInterval(() => {
      setCurrentMessageIndex((prev) => (prev + 1) % messages.length);
    }, 1100);

    // Smooth progress simulation
    const progressInterval = setInterval(() => {
      setProgress((prev) => {
        if (prev >= 94) return prev;
        const increment = Math.floor(Math.random() * 8) + 4;
        return Math.min(prev + increment, 94);
      });
    }, 250);

    return () => {
      clearInterval(messageInterval);
      clearInterval(progressInterval);
    };
  }, [messages.length]);

  return (
    <div
      className={`glass-card rounded-2xl p-8 md:p-12 border border-slate-800 text-center flex flex-col items-center justify-center relative overflow-hidden ${className}`}
    >
      {/* Background glow orb */}
      <div className="absolute w-72 h-72 rounded-full bg-cyan-500/10 blur-3xl pointer-events-none -top-10 -left-10" />
      <div className="absolute w-72 h-72 rounded-full bg-indigo-500/10 blur-3xl pointer-events-none -bottom-10 -right-10" />

      {/* Cyber Radar Animation */}
      <div className="relative w-36 h-36 flex items-center justify-center mb-8">
        {/* Pulsing Concentric Rings */}
        <div className="absolute inset-0 rounded-full border border-cyan-500/20 animate-ping opacity-75" />
        <div className="absolute inset-3 rounded-full border border-cyan-400/30 animate-pulse" />
        <div className="absolute inset-7 rounded-full border border-cyan-300/40" />

        {/* Sweeping Radar Beam */}
        <div
          className="absolute inset-0 rounded-full animate-spin"
          style={{
            animationDuration: '3s',
            background: 'conic-gradient(from 0deg, transparent 0deg, transparent 270deg, rgba(34, 211, 238, 0.4) 360deg)',
          }}
        />

        {/* Center Shield Icon */}
        <div className="relative z-10 w-16 h-16 rounded-2xl bg-[#0E1629] border border-cyan-400/40 shadow-glow flex items-center justify-center text-cyan-300">
          <Shield size={32} className="animate-pulse" />
        </div>
      </div>

      {/* Title & Subtitle */}
      <h3 className="text-xl md:text-2xl font-bold text-white mb-2 tracking-tight">
        {title}
      </h3>
      <p className="text-sm text-slate-400 max-w-md mb-8">
        {subtitle}
      </p>

      {/* Progress Bar Container */}
      <div className="w-full max-w-md space-y-2.5">
        <div className="flex justify-between items-center text-xs">
          <span className="font-mono text-cyan-400 flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping inline-block" />
            {messages[currentMessageIndex]}
          </span>
          <span className="font-mono font-semibold text-slate-400">{progress}%</span>
        </div>

        <div className="h-2.5 w-full bg-slate-900 rounded-full overflow-hidden p-0.5 border border-slate-800">
          <div
            className="h-full bg-gradient-to-r from-cyan-500 via-sky-400 to-indigo-400 rounded-full transition-all duration-300 relative shadow-glow"
            style={{ width: `${progress}%` }}
          >
            <div className="absolute inset-0 bg-white/20 animate-pulse-slow" />
          </div>
        </div>
      </div>

      {/* Security Privacy Reminder */}
      <div className="mt-8 flex items-center gap-2 text-xs text-slate-400 bg-slate-900/60 px-4 py-2 rounded-full border border-slate-800/80">
        <Sparkles size={13} className="text-cyan-400 shrink-0" />
        <span>Read-only inspection. We never save or transmit your credentials.</span>
      </div>
    </div>
  );
};
