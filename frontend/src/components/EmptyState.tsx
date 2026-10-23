import React from 'react';
import { LucideIcon, ShieldQuestion } from 'lucide-react';
import { Link } from 'react-router-dom';

interface EmptyStateProps {
  title: string;
  description: string;
  icon?: LucideIcon;
  actionText?: string;
  actionLink?: string;
  onAction?: () => void;
  secondaryActionText?: string;
  onSecondaryAction?: () => void;
  className?: string;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  title,
  description,
  icon: Icon = ShieldQuestion,
  actionText,
  actionLink,
  onAction,
  secondaryActionText,
  onSecondaryAction,
  className = '',
}) => {
  return (
    <div
      className={`glass-card rounded-2xl p-8 md:p-12 border border-slate-800 text-center flex flex-col items-center justify-center ${className}`}
    >
      <div className="w-16 h-16 rounded-2xl bg-slate-800/80 border border-slate-700/60 flex items-center justify-center text-cyan-400 mb-5 shadow-glow">
        <Icon size={32} />
      </div>

      <h3 className="text-xl font-bold text-white mb-2">{title}</h3>
      <p className="text-sm text-slate-400 max-w-md mb-6 leading-relaxed">
        {description}
      </p>

      <div className="flex flex-wrap items-center justify-center gap-3">
        {actionText && (
          actionLink ? (
            <Link
              to={actionLink}
              className="px-5 py-2.5 rounded-xl bg-cyan-400 text-slate-950 font-bold text-sm hover:bg-cyan-300 transition-all shadow-glow hover:shadow-glow-lg"
            >
              {actionText}
            </Link>
          ) : (
            <button
              onClick={onAction}
              className="px-5 py-2.5 rounded-xl bg-cyan-400 text-slate-950 font-bold text-sm hover:bg-cyan-300 transition-all shadow-glow hover:shadow-glow-lg"
            >
              {actionText}
            </button>
          )
        )}

        {secondaryActionText && (
          <button
            onClick={onSecondaryAction}
            className="px-5 py-2.5 rounded-xl bg-slate-800 text-slate-200 font-medium text-sm hover:bg-slate-700 border border-slate-700 transition-all"
          >
            {secondaryActionText}
          </button>
        )}
      </div>
    </div>
  );
};
