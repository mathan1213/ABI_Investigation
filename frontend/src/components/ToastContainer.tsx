import React from 'react';
import { useScan } from '../context/ScanContext';
import { CheckCircle2, AlertTriangle, AlertCircle, Info, X } from 'lucide-react';

export const ToastContainer: React.FC = () => {
  const { toasts, removeToast } = useScan();

  if (toasts.length === 0) return null;

  return (
    <div className="fixed bottom-5 right-5 z-50 flex flex-col gap-2 max-w-sm w-full pointer-events-none no-print">
      {toasts.map((toast) => {
        const icons = {
          success: <CheckCircle2 size={18} className="text-emerald-400 shrink-0" />,
          error: <AlertCircle size={18} className="text-red-400 shrink-0" />,
          warning: <AlertTriangle size={18} className="text-yellow-400 shrink-0" />,
          info: <Info size={18} className="text-cyan-400 shrink-0" />,
        };

        const borders = {
          success: 'border-emerald-500/40 bg-[#0E1629]/95 text-emerald-300',
          error: 'border-red-500/40 bg-[#0E1629]/95 text-red-300',
          warning: 'border-yellow-500/40 bg-[#0E1629]/95 text-yellow-300',
          info: 'border-cyan-500/40 bg-[#0E1629]/95 text-cyan-300',
        };

        return (
          <div
            key={toast.id}
            className={`pointer-events-auto flex items-start gap-3 p-4 rounded-xl border shadow-xl backdrop-blur-md transition-all duration-300 ${borders[toast.type]}`}
          >
            {icons[toast.type]}
            <div className="flex-1 min-w-0">
              <h5 className="text-xs font-bold text-white tracking-wide">{toast.title}</h5>
              {toast.message && (
                <p className="text-xs text-slate-300 mt-0.5 line-clamp-2 leading-relaxed">
                  {toast.message}
                </p>
              )}
            </div>
            <button
              onClick={() => removeToast(toast.id)}
              className="text-slate-400 hover:text-white p-1 rounded-md transition-colors"
            >
              <X size={14} />
            </button>
          </div>
        );
      })}
    </div>
  );
};
