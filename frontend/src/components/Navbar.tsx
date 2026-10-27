import React, { useState, useRef, useEffect } from 'react';
import { NavLink, Link, useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  Menu,
  X,
  BarChart3,
  Send,
  GitBranch,
  Network,
  FileText,
  User as UserIcon,
  LogOut,
  Trash2,
  Shield,
  ChevronDown,
  AlertTriangle,
  Loader2,
} from 'lucide-react';
import { useScan } from '../context/ScanContext';
import { useAuth } from '../context/AuthContext';

export const Navbar: React.FC = () => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [userDropdownOpen, setUserDropdownOpen] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);

  const { overallScore, overallRisk, hasAnyScan } = useScan();
  const { user, isAuthenticated, isAdmin, logout, deleteAccount } = useAuth();
  const navigate = useNavigate();
  const dropdownRef = useRef<HTMLDivElement>(null);

  // Close dropdown on click outside
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setUserDropdownOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleLogout = async () => {
    setUserDropdownOpen(false);
    await logout();
    navigate('/login');
  };

  const handleDeleteAccountConfirm = async () => {
    setIsDeleting(true);
    try {
      await deleteAccount();
      setShowDeleteModal(false);
      setUserDropdownOpen(false);
      navigate('/register');
    } catch {
      // Error handled by AuthContext
    } finally {
      setIsDeleting(false);
    }
  };

  const navLinks = [
    { to: '/', label: 'Dashboard', icon: BarChart3 },
    { to: '/telegram', label: 'Link Telegram', icon: Send },
    { to: '/repo', label: 'Repo Check', icon: GitBranch },
    { to: '/network', label: 'Network Check', icon: Network },
    { to: '/report', label: 'Report', icon: FileText },
  ];

  return (
    <>
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

            {/* Desktop Navigation */}
            {isAuthenticated && user ? (
              <div className="hidden md:flex items-center gap-1 lg:gap-2">
                {navLinks.map((link) => {
                  const Icon = link.icon;
                  return (
                    <NavLink
                      key={link.to}
                      to={link.to}
                      className={({ isActive }) =>
                        `px-3 py-2 rounded-xl text-xs font-semibold tracking-wide transition-all flex items-center gap-1.5 ${
                          isActive
                            ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-glow'
                            : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                        }`
                      }
                    >
                      <Icon size={14} />
                      <span>{link.label}</span>
                    </NavLink>
                  );
                })}

                {/* Quick Risk Score Pill */}
                {hasAnyScan && (
                  <div className="flex items-center gap-1.5 pl-2">
                    <span className="text-[11px] text-slate-400">Risk:</span>
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

                {/* User Account Menu */}
                <div className="ml-2 pl-3 border-l border-slate-800 relative" ref={dropdownRef}>
                  <button
                    onClick={() => setUserDropdownOpen(!userDropdownOpen)}
                    className="flex items-center gap-2 px-3 py-1.5 bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700 rounded-xl text-xs font-medium text-slate-200 transition-colors"
                  >
                    <UserIcon className="w-3.5 h-3.5 text-blue-400" />
                    <span className="max-w-[120px] truncate">{user.name}</span>
                    {isAdmin && (
                      <span className="px-1.5 py-0.2 bg-purple-500/20 text-purple-300 text-[10px] rounded font-semibold uppercase">
                        Admin
                      </span>
                    )}
                    <ChevronDown className="w-3 h-3 text-slate-400" />
                  </button>

                  {/* User Dropdown */}
                  {userDropdownOpen && (
                    <div className="absolute right-0 mt-2 w-56 bg-[#111827] border border-slate-800 rounded-xl shadow-2xl py-2 z-50 text-xs">
                      <div className="px-4 py-2 border-b border-slate-800/80">
                        <p className="font-semibold text-white truncate">{user.name}</p>
                        <p className="text-[11px] text-slate-400 truncate">{user.email}</p>
                      </div>

                      {isAdmin && (
                        <div className="py-1 border-b border-slate-800/80">
                          <Link
                            to="/admin"
                            onClick={() => setUserDropdownOpen(false)}
                            className="w-full flex items-center gap-2.5 px-4 py-2 text-purple-300 hover:bg-purple-950/30 transition-colors font-medium"
                          >
                            <Shield className="w-3.5 h-3.5" />
                            Admin Dashboard
                          </Link>
                        </div>
                      )}

                      <div className="py-1">
                        <button
                          onClick={handleLogout}
                          className="w-full flex items-center gap-2.5 px-4 py-2 text-slate-300 hover:bg-slate-800 hover:text-white transition-colors"
                        >
                          <LogOut className="w-3.5 h-3.5" />
                          Log out
                        </button>
                        <button
                          onClick={() => {
                            setUserDropdownOpen(false);
                            setShowDeleteModal(true);
                          }}
                          className="w-full flex items-center gap-2.5 px-4 py-2 text-red-400 hover:bg-red-950/30 transition-colors"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                          Delete my account
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div className="hidden md:flex items-center gap-2">
                <Link
                  to="/login"
                  className="px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white transition-colors"
                >
                  Sign In
                </Link>
                <Link
                  to="/register"
                  className="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-xs font-medium transition-colors"
                >
                  Register
                </Link>
              </div>
            )}

            {/* Mobile Header Right */}
            {isAuthenticated && user ? (
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
            ) : (
              <div className="flex items-center gap-2 md:hidden">
                <Link
                  to="/login"
                  className="px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white transition-colors"
                >
                  Sign In
                </Link>
                <Link
                  to="/register"
                  className="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-xs font-medium transition-colors"
                >
                  Register
                </Link>
              </div>
            )}
          </div>
        </div>

        {/* Mobile Dropdown */}
        {isAuthenticated && user && mobileMenuOpen && (
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

            <div className="pt-3 border-t border-slate-800 space-y-1 text-sm">
              <div className="px-3 py-1 text-slate-400 text-xs">
                Signed in as <span className="text-white font-medium">{user.name}</span>
              </div>
              {isAdmin && (
                <Link
                  to="/admin"
                  onClick={() => setMobileMenuOpen(false)}
                  className="flex items-center gap-3 px-3 py-2 rounded-xl text-purple-300 hover:bg-purple-950/30"
                >
                  <Shield size={16} />
                  <span>Admin Dashboard</span>
                </Link>
              )}
              <button
                onClick={handleLogout}
                className="w-full flex items-center gap-3 px-3 py-2 rounded-xl text-slate-300 hover:bg-slate-800"
              >
                <LogOut size={16} />
                <span>Log out</span>
              </button>
              <button
                onClick={() => {
                  setMobileMenuOpen(false);
                  setShowDeleteModal(true);
                }}
                className="w-full flex items-center gap-3 px-3 py-2 rounded-xl text-red-400 hover:bg-red-950/30"
              >
                <Trash2 size={16} />
                <span>Delete my account</span>
              </button>
            </div>
          </div>
        )}
      </nav>

      {/* Delete Account Modal */}
      {showDeleteModal && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#111827] border border-red-900/60 rounded-2xl w-full max-w-md p-6 space-y-4 shadow-2xl">
            <div className="flex items-center gap-3 text-red-400">
              <AlertTriangle className="w-6 h-6" />
              <h3 className="text-lg font-bold text-white">Permanently Delete Account?</h3>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              This action cannot be undone. Your user profile, all saved investigation scan results,
              and generated forensic incident reports will be permanently deleted from our database.
            </p>
            <div className="flex justify-end gap-2.5 pt-2">
              <button
                onClick={() => setShowDeleteModal(false)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-xl text-xs font-medium"
              >
                Cancel
              </button>
              <button
                onClick={handleDeleteAccountConfirm}
                disabled={isDeleting}
                className="px-4 py-2 bg-red-600 hover:bg-red-500 text-white rounded-xl text-xs font-medium flex items-center gap-1.5 disabled:opacity-50"
              >
                {isDeleting && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                Delete My Account
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
};
