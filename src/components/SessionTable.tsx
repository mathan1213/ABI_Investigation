import React from 'react';
import { TelegramSession } from '../lib/types';
import { Smartphone, Laptop, Globe, ShieldAlert, CheckCircle2, Clock } from 'lucide-react';

interface SessionTableProps {
  sessions: TelegramSession[];
  onTerminateSession?: (sessionId: string) => void;
  className?: string;
}

export const SessionTable: React.FC<SessionTableProps> = ({
  sessions,
  onTerminateSession,
  className = '',
}) => {
  const getDeviceIcon = (device: string) => {
    const d = device.toLowerCase();
    if (d.includes('phone') || d.includes('android') || d.includes('ios') || d.includes('samsung')) {
      return <Smartphone size={16} className="text-cyan-400" />;
    }
    return <Laptop size={16} className="text-cyan-400" />;
  };

  return (
    <div className={`overflow-hidden rounded-2xl border border-slate-800 bg-[#111A2E] ${className}`}>
      {/* Desktop Table View */}
      <div className="hidden md:block overflow-x-auto">
        <table className="w-full text-left text-sm text-slate-300">
          <thead className="bg-[#0B1220]/80 text-xs uppercase tracking-wider text-slate-400 border-b border-slate-800">
            <tr>
              <th scope="col" className="px-5 py-3.5">Device & Application</th>
              <th scope="col" className="px-5 py-3.5">Location & Country</th>
              <th scope="col" className="px-5 py-3.5">IP Address</th>
              <th scope="col" className="px-5 py-3.5">Last Active</th>
              <th scope="col" className="px-5 py-3.5">Verdict</th>
              <th scope="col" className="px-5 py-3.5 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/80">
            {sessions.map((sess) => (
              <tr
                key={sess.id}
                className={`transition-colors hover:bg-slate-800/40 ${
                  sess.isSuspicious ? 'bg-red-500/5' : ''
                }`}
              >
                {/* Device & App */}
                <td className="px-5 py-4">
                  <div className="flex items-center gap-3">
                    <div className={`p-2 rounded-xl border ${sess.isSuspicious ? 'bg-red-500/10 border-red-500/20 text-red-400' : 'bg-slate-800 border-slate-700'}`}>
                      {getDeviceIcon(sess.device)}
                    </div>
                    <div>
                      <div className="font-semibold text-white flex items-center gap-2">
                        {sess.device}
                        {sess.isCurrent && (
                          <span className="text-[10px] font-mono uppercase bg-cyan-500/10 text-cyan-300 px-1.5 py-0.5 rounded border border-cyan-500/20">
                            Current
                          </span>
                        )}
                      </div>
                      <div className="text-xs text-slate-400 mt-0.5">{sess.app}</div>
                    </div>
                  </div>
                </td>

                {/* Country */}
                <td className="px-5 py-4">
                  <div className="flex items-center gap-1.5 text-slate-200">
                    <Globe size={14} className="text-slate-400 shrink-0" />
                    <span>{sess.country}</span>
                  </div>
                </td>

                {/* IP */}
                <td className="px-5 py-4 font-mono text-xs text-slate-300">
                  {sess.ip}
                </td>

                {/* Last active */}
                <td className="px-5 py-4 text-xs text-slate-400">
                  <div className="flex items-center gap-1">
                    <Clock size={13} className="text-slate-400" />
                    <span>{sess.lastActive}</span>
                  </div>
                </td>

                {/* Status Badge */}
                <td className="px-5 py-4">
                  {sess.isSuspicious ? (
                    <span className="inline-flex items-center gap-1.5 rounded-full border border-red-500/30 bg-red-500/10 px-2.5 py-1 text-xs font-semibold text-red-400">
                      <ShieldAlert size={12} />
                      Suspicious
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1 text-xs font-semibold text-emerald-400">
                      <CheckCircle2 size={12} />
                      Trusted
                    </span>
                  )}
                </td>

                {/* Action button */}
                <td className="px-5 py-4 text-right">
                  {sess.isCurrent ? (
                    <span className="text-xs text-slate-400 italic">This Device</span>
                  ) : (
                    <button
                      onClick={() => onTerminateSession && onTerminateSession(sess.id)}
                      className={`text-xs px-2.5 py-1 rounded-lg border transition-all ${
                        sess.isSuspicious
                          ? 'border-red-500/30 bg-red-500/10 text-red-300 hover:bg-red-500/20'
                          : 'border-slate-700 bg-slate-800 text-slate-300 hover:bg-slate-700'
                      }`}
                    >
                      Disconnect
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Mobile Card View */}
      <div className="md:hidden divide-y divide-slate-800/80">
        {sessions.map((sess) => (
          <div
            key={sess.id}
            className={`p-4 space-y-3 ${sess.isSuspicious ? 'bg-red-500/5' : ''}`}
          >
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-2.5">
                <div className={`p-2 rounded-xl border ${sess.isSuspicious ? 'bg-red-500/10 border-red-500/20 text-red-400' : 'bg-slate-800 border-slate-700'}`}>
                  {getDeviceIcon(sess.device)}
                </div>
                <div>
                  <div className="font-semibold text-white text-sm flex items-center gap-1.5">
                    {sess.device}
                    {sess.isCurrent && (
                      <span className="text-[10px] font-mono bg-cyan-500/10 text-cyan-300 px-1 py-0.5 rounded">
                        Current
                      </span>
                    )}
                  </div>
                  <div className="text-xs text-slate-400">{sess.app}</div>
                </div>
              </div>

              {sess.isSuspicious ? (
                <span className="inline-flex items-center gap-1 rounded-full border border-red-500/30 bg-red-500/10 px-2 py-0.5 text-[11px] font-semibold text-red-400">
                  <ShieldAlert size={11} />
                  Suspicious
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[11px] font-semibold text-emerald-400">
                  <CheckCircle2 size={11} />
                  Trusted
                </span>
              )}
            </div>

            <div className="grid grid-cols-2 gap-2 text-xs text-slate-400 pt-1">
              <div>
                <span className="text-slate-400 block text-[10px] uppercase">Location</span>
                <span className="text-slate-200">{sess.country}</span>
              </div>
              <div>
                <span className="text-slate-400 block text-[10px] uppercase">IP Address</span>
                <span className="font-mono text-slate-300">{sess.ip}</span>
              </div>
              <div>
                <span className="text-slate-400 block text-[10px] uppercase">Last Active</span>
                <span className="text-slate-300">{sess.lastActive}</span>
              </div>
              <div className="flex items-end justify-end">
                {!sess.isCurrent && (
                  <button
                    onClick={() => onTerminateSession && onTerminateSession(sess.id)}
                    className="text-xs px-2.5 py-1 rounded-lg border border-red-500/30 bg-red-500/10 text-red-300 hover:bg-red-500/20"
                  >
                    Disconnect
                  </button>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
