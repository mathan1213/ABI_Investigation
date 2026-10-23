import React, { useState } from 'react';
import { NavLink, Link } from 'react-router-dom';
import { ShieldAlert, Menu, X, BarChart3, Send, GitBranch, Network, FileText } from 'lucide-react';
import { useScan } from '../context/ScanContext';

export const Navbar: React.FC = () => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const { overallScore, overallRisk, hasAnyScan } = useScan();

  const navLinks = [
    { to: '/', label: 'Dashboard', icon: BarChart3 },
    { to: '/telegram', label: 'Link Telegram', icon: Send },
    { to: '/repo', label: 'Repo Check', icon: GitBranch },
    { to: '/network', label: 'Network Check', icon: Network },
    { to: '/report', label: 'Report', icon: FileText },
  ];

  return (
    <nav className="sticky top-0 z-50 w-full bg-[#0B1220]/90 backdrop-blur-md border-b border-slate-800/80 no-print">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Brand Logo */}
          <Link to="/" className="flex items-center gap-3 group">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-400 to-sky-600 flex items-center justify-center text-slate-950 shadow-glow group-hover:scale-105 transition-transform">
              <ShieldAlert size={22} className="stroke-[2.2]" />
            </div>
            <div>
              <span className="font-bold text-base sm:text-lg tracking-tight text-white flex items-center gap-1.5">
                Account Breach Investigation
              </span>
              <span className="text-[11px] text-cyan-400 font-medium block -mt-1 hidden sm:block">
                Find out if you were hacked, and how
              </span>
            </div>
          </Link>

          {/* Desktop Links */}
          <div className="hidden md:flex items-center gap-1 lg:gap-2">
            {navLinks.map((link) => {
              const Icon = link.icon;
              return (
                <NavLink
                  key={link.to}
                  to={link.to}
                  className={({ isActive }) =>
                    `px-3.5 py-2 rounded-xl text-xs font-semibold tracking-wide transition-all flex items-center gap-2 ${
                      isActive
                        ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-glow'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                    }`
                  }
                >
                  <Icon size={15} />
                  <span>{link.label}</span>
                </NavLink>
              );
            })}

            {/* Quick status pill */}
            {hasAnyScan && (
              <div className="ml-3 pl-3 border-l border-slate-800 flex items-center gap-2">
                <span className="text-[11px] text-slate-400">Risk Score:</span>
                <span
                  className={`text-xs font-bold px-2 py-0.5 rounded-full border ${
                    overallRisk === 'critical'
                      ? 'bg-red-500/10 border-red-500/30 text-red-400'
                      : overallRisk === 'high'
                      ? 'bg-orange-500/10 border-orange-500/30 text-orange-400'
                      : overallRisk === 'medium'
                      ? 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400'
                      : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                  }`}
                >
                  {overallScore}/100
                </span>
              </div>
            )}
          </div>

          {/* Mobile Menu Button */}
          <div className="flex items-center gap-2 md:hidden">
            {hasAnyScan && (
              <span
                className={`text-[11px] font-bold px-2 py-0.5 rounded-full border ${
                  overallRisk === 'critical'
                    ? 'bg-red-500/10 border-red-500/30 text-red-400'
                    : 'bg-cyan-500/10 border-cyan-500/30 text-cyan-300'
                }`}
              >
                {overallScore}/100
              </span>
            )}
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="p-2 rounded-xl bg-slate-800 text-slate-300 hover:text-white hover:bg-slate-700 transition-colors"
              aria-label="Toggle navigation menu"
            >
              {mobileMenuOpen ? <X size={20} /> : <Menu size={20} />}
            </button>
          </div>
        </div>
      </div>

      {/* Mobile Dropdown Menu */}
      {mobileMenuOpen && (
        <div className="md:hidden bg-[#0B1220] border-b border-slate-800 px-4 pt-2 pb-4 space-y-1">
          {navLinks.map((link) => {
            const Icon = link.icon;
            return (
              <NavLink
                key={link.to}
                to={link.to}
                onClick={() => setMobileMenuOpen(false)}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-colors ${
                    isActive
                      ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30'
                      : 'text-slate-300 hover:bg-slate-800 hover:text-white'
                  }`
                }
              >
                <Icon size={18} className="text-cyan-400" />
                <span>{link.label}</span>
              </NavLink>
            );
          })}
        </div>
      )}
    </nav>
  );
};
