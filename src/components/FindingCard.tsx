import React, { useState } from 'react';
import { RiskLevel } from '../lib/types';
import { RiskBadge } from './RiskBadge';
import { FileCode, AlertOctagon, Check, Copy, ChevronDown, ChevronUp, Lightbulb } from 'lucide-react';

interface FindingCardProps {
  severity: RiskLevel;
  title: string;
  filePath?: string;
  lineNumber?: number;
  explanation: string;
  suggestedFix: string;
  codeSnippet?: string;
  category?: string;
  date?: string;
}

export const FindingCard: React.FC<FindingCardProps> = ({
  severity,
  title,
  filePath,
  lineNumber,
  explanation,
  suggestedFix,
  codeSnippet,
  category,
  date,
}) => {
  const [copied, setCopied] = useState(false);
  const [expanded, setExpanded] = useState(true);

  const handleCopy = () => {
    navigator.clipboard.writeText(suggestedFix);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const borderAccent = {
    critical: 'border-l-4 border-l-red-500',
    high: 'border-l-4 border-l-orange-500',
    medium: 'border-l-4 border-l-yellow-500',
    low: 'border-l-4 border-l-emerald-500',
  }[severity];

  return (
    <div
      className={`glass-card rounded-2xl p-5 border border-slate-800 transition-all duration-200 ${borderAccent} hover:border-slate-700`}
    >
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div className="flex items-start gap-3">
          <div className="p-2 rounded-xl bg-slate-800/80 text-cyan-400 mt-0.5 shrink-0 border border-slate-700/60">
            <AlertOctagon size={18} />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <h4 className="text-base font-semibold text-white">{title}</h4>
              {category && (
                <span className="text-[11px] font-mono uppercase bg-slate-800 text-slate-400 px-2 py-0.5 rounded-md border border-slate-700">
                  {category}
                </span>
              )}
            </div>

            {filePath && (
              <div className="flex items-center gap-1.5 mt-1 text-xs font-mono text-cyan-300/80">
                <FileCode size={13} />
                <span>{filePath}{lineNumber ? ` : Line ${lineNumber}` : ''}</span>
              </div>
            )}
          </div>
        </div>

        <div className="flex items-center gap-2 self-start md:self-center shrink-0">
          {date && <span className="text-xs text-slate-400 mr-2">{date}</span>}
          <RiskBadge level={severity} size="sm" />
          <button
            onClick={() => setExpanded(!expanded)}
            className="p-1 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
            title={expanded ? 'Collapse' : 'Expand'}
          >
            {expanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
          </button>
        </div>
      </div>

      {expanded && (
        <div className="mt-4 pt-3 border-t border-slate-800/80 space-y-3 text-sm">
          {/* Plain English explanation */}
          <div>
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 block mb-1">
              What this means
            </span>
            <p className="text-slate-300 leading-relaxed">{explanation}</p>
          </div>

          {/* Code snippet if applicable */}
          {codeSnippet && (
            <div className="rounded-xl bg-[#070C15] border border-slate-800/90 p-3 font-mono text-xs text-amber-300 overflow-x-auto">
              <div className="text-[10px] text-slate-400 uppercase tracking-widest mb-1 select-none font-sans">
                Problematic code detected
              </div>
              <pre className="whitespace-pre-wrap">{codeSnippet}</pre>
            </div>
          )}

          {/* Plain English suggested fix */}
          <div className="p-3.5 rounded-xl bg-cyan-950/20 border border-cyan-800/30 flex items-start justify-between gap-3">
            <div className="flex items-start gap-2.5">
              <Lightbulb size={18} className="text-cyan-400 shrink-0 mt-0.5" />
              <div>
                <span className="text-xs font-bold text-cyan-300 block mb-0.5">
                  How to fix this
                </span>
                <p className="text-slate-200 text-xs md:text-sm leading-relaxed">{suggestedFix}</p>
              </div>
            </div>
            <button
              onClick={handleCopy}
              className="p-1.5 text-slate-400 hover:text-cyan-300 hover:bg-cyan-900/30 rounded-lg transition-colors shrink-0 flex items-center gap-1 text-xs"
              title="Copy recommendation"
            >
              {copied ? <Check size={14} className="text-emerald-400" /> : <Copy size={14} />}
              <span className="hidden sm:inline">{copied ? 'Copied' : 'Copy'}</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
