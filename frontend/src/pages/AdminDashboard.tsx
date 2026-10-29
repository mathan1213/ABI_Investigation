import React, { useState, useEffect, useRef } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import {
  Users,
  Shield,
  Activity,
  Download,
  Search,
  Filter,
  Eye,
  UserCheck,
  UserX,
  Trash2,
  AlertTriangle,
  RefreshCw,
  Clock,
  FileText,
  BarChart3,
  Calendar,
  X,
  CheckCircle,
  AlertCircle,
  Loader2,
  LogOut,
  ShieldAlert,
  ShieldCheck,
  UserPlus,
  Settings,
  History,
  ExternalLink,
  ChevronRight,
  Database,
  Lock,
  UploadCloud,
} from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from 'recharts';
import { useAuth } from '../context/AuthContext';
import {
  getAdminOverview,
  getAdminUsers,
  getAdminUserDetail,
  patchAdminUser,
  deleteAdminUser,
  getAdminActivity,
  downloadUsersCsv,
  getSuperAdminAdmins,
  getEligibleUsers,
  createSuperAdminAdmin,
  updateAdminPermissions,
  updateUserRole,
  removeAdmin,
  getSuperAdminAuditLogs,
  getAdminFiles,
  getAdminReports,
} from '../lib/api';
import {
  AdminOverview,
  User,
  UserDetail,
  ActivityLogItem,
  AuditLogItem,
  EligibleUser,
  AdminPermission,
  RiskLevel,
  UploadedFileItem,
  AdminReportItem,
} from '../lib/types';
import { RiskBadge } from '../components/RiskBadge';

const RISK_COLORS: Record<string, string> = {
  low: '#10B981',
  medium: '#F59E0B',
  high: '#F97316',
  critical: '#EF4444',
};

const MODULE_COLORS: Record<string, string> = {
  telegram: '#3B82F6',
  repo: '#8B5CF6',
  network: '#06B6D4',
};

const PERMISSION_DESCRIPTIONS: Record<string, { label: string; desc: string }> = {
  view_users: { label: 'View Users', desc: 'Browse user directory and inspection histories' },
  disable_users: { label: 'Disable Users', desc: 'Deactivate or reactivate user accounts' },
  delete_users: { label: 'Delete Users', desc: 'Permanently remove users and their scans' },
  view_scans: { label: 'View Scans', desc: 'Inspect forensic scan findings and summaries' },
  view_reports: { label: 'View Reports', desc: 'Read compiled forensic incident reports' },
  export_data: { label: 'Export Data', desc: 'Download CSV audit reports and user rosters' },
  view_activity: { label: 'View Activity', desc: 'Inspect system-wide security activity records' },
  manage_admins: { label: 'Manage Admins', desc: 'Create and configure administrator privileges' },
};

export const AdminDashboard: React.FC = () => {
  const { user, isAdmin, isSuperAdmin, hasPermission, logout, isLoading: isAuthLoading } = useAuth();
  const navigate = useNavigate();

  // Navigation tab state
  type AdminTab = 'overview' | 'users' | 'uploaded_files' | 'user_reports' | 'scans_reports' | 'activity' | 'export' | 'admin_mgmt' | 'audit_log';
  const [activeTab, setActiveTab] = useState<AdminTab>('overview');

  // Uploaded files data
  const [uploadedFiles, setUploadedFiles] = useState<UploadedFileItem[]>([]);
  const [filesSearch, setFilesSearch] = useState('');
  const [filesTotal, setFilesTotal] = useState(0);

  // User Reports data
  const [adminReports, setAdminReports] = useState<AdminReportItem[]>([]);
  const [reportsSearch, setReportsSearch] = useState('');
  const [reportsTotal, setReportsTotal] = useState(0);

  // Overview data
  const [overview, setOverview] = useState<AdminOverview | null>(null);

  // Users data
  const [users, setUsers] = useState<User[]>([]);
  const [totalUsersCount, setTotalUsersCount] = useState(0);
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [searchQuery, setSearchQuery] = useState('');
  const [roleFilter, setRoleFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState<'all' | 'active' | 'disabled'>('all');

  // Activity logs
  const [activityLogs, setActivityLogs] = useState<ActivityLogItem[]>([]);
  const [activityActionFilter, setActivityActionFilter] = useState('all');
  const [totalLogsCount, setTotalLogsCount] = useState(0);

  // User Detail Drawer
  const [selectedUserDetail, setSelectedUserDetail] = useState<UserDetail | null>(null);
  const [isDetailLoading, setIsDetailLoading] = useState(false);

  // Delete User Dialog
  const [userToDelete, setUserToDelete] = useState<User | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);

  // Super Admin: Admins List
  const [adminsList, setAdminsList] = useState<User[]>([]);
  const [availablePermissions, setAvailablePermissions] = useState<string[]>([]);
  const [showCreateAdminModal, setShowCreateAdminModal] = useState(false);
  const [eligibleUsers, setEligibleUsers] = useState<EligibleUser[]>([]);
  const [selectedEligibleUserId, setSelectedEligibleUserId] = useState<number | null>(null);
  const [newAdminPerms, setNewAdminPerms] = useState<string[]>([
    'view_users',
    'view_scans',
    'view_reports',
  ]);
  const [isCreatingAdmin, setIsCreatingAdmin] = useState(false);

  // Super Admin: Edit Permissions Modal
  const [editingAdmin, setEditingAdmin] = useState<User | null>(null);
  const [editPerms, setEditPerms] = useState<string[]>([]);
  const [isSavingPerms, setIsSavingPerms] = useState(false);

  // Super Admin: Demote/Remove Admin Modal
  const [adminToRemove, setAdminToRemove] = useState<User | null>(null);
  const [isRemovingAdmin, setIsRemovingAdmin] = useState(false);

  // Super Admin: Audit Logs
  const [auditLogs, setAuditLogs] = useState<AuditLogItem[]>([]);
  const [auditTotal, setAuditTotal] = useState(0);
  const [auditPage, setAuditPage] = useState(1);
  const [auditTotalPages, setAuditTotalPages] = useState(1);

  // Feedback & Loading
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // ---------------------------------------------------------------------------
  // 30-Minute Inactivity Auto-Logout
  // ---------------------------------------------------------------------------
  const lastActivityRef = useRef<number>(Date.now());
  useEffect(() => {
    const updateActivity = () => {
      lastActivityRef.current = Date.now();
    };

    const events = ['mousemove', 'keydown', 'mousedown', 'scroll', 'touchstart'];
    events.forEach((ev) => window.addEventListener(ev, updateActivity, { passive: true }));

    const checkInterval = setInterval(() => {
      const inactiveMinutes = (Date.now() - lastActivityRef.current) / 1000 / 60;
      if (inactiveMinutes >= 30) {
        logout();
        navigate('/admin/login', { replace: true });
      }
    }, 15000);

    return () => {
      events.forEach((ev) => window.removeEventListener(ev, updateActivity));
      clearInterval(checkInterval);
    };
  }, [logout, navigate]);

  // Auth Protection
  useEffect(() => {
    if (!isAuthLoading) {
      if (!user || !isAdmin) {
        navigate('/admin/login', { replace: true });
      }
    }
  }, [user, isAdmin, isAuthLoading, navigate]);

  // ---------------------------------------------------------------------------
  // Data Loaders
  // ---------------------------------------------------------------------------
  const loadTabContent = async () => {
    setIsRefreshing(true);
    setErrorMessage(null);
    try {
      if (activeTab === 'overview' || activeTab === 'scans_reports') {
        if (hasPermission('view_users') || hasPermission('view_scans')) {
          const ov = await getAdminOverview();
          setOverview(ov);
        }
      }

      if (activeTab === 'users' && hasPermission('view_users')) {
        const uRes = await getAdminUsers({
          search: searchQuery,
          role: roleFilter === 'all' ? undefined : roleFilter,
          isActive: statusFilter === 'all' ? undefined : statusFilter === 'active',
          page: currentPage,
          perPage: 10,
        });
        setUsers(uRes.items);
        setTotalUsersCount(uRes.total);
        setTotalPages(uRes.totalPages);
      }

      if (activeTab === 'uploaded_files') {
        const fRes = await getAdminFiles({ search: filesSearch, page: 1, perPage: 50 });
        setUploadedFiles(fRes.items);
        setFilesTotal(fRes.total);
      }

      if (activeTab === 'user_reports') {
        const rRes = await getAdminReports({ search: reportsSearch, page: 1, perPage: 50 });
        setAdminReports(rRes.items);
        setReportsTotal(rRes.total);
      }

      if (activeTab === 'activity' && hasPermission('view_activity')) {
        const actRes = await getAdminActivity({
          action: activityActionFilter,
          limit: 30,
        });
        setActivityLogs(actRes.items);
        setTotalLogsCount(actRes.total);
      }

      if (activeTab === 'admin_mgmt' && isSuperAdmin) {
        const [admRes, eligRes] = await Promise.all([
          getSuperAdminAdmins(),
          getEligibleUsers(),
        ]);
        setAdminsList(admRes.items);
        setAvailablePermissions(admRes.availablePermissions);
        setEligibleUsers(eligRes);
        if (eligRes.length > 0 && selectedEligibleUserId === null) {
          setSelectedEligibleUserId(eligRes[0].id);
        }
      }

      if (activeTab === 'audit_log' && isSuperAdmin) {
        const audRes = await getSuperAdminAuditLogs({ page: auditPage, perPage: 25 });
        setAuditLogs(audRes.items);
        setAuditTotal(audRes.total);
        setAuditTotalPages(audRes.totalPages);
      }
    } catch (err: any) {
      setErrorMessage(err?.message || 'Failed to retrieve administrative data.');
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    if (!isAuthLoading && isAdmin) {
      loadTabContent();
    }
  }, [activeTab, currentPage, roleFilter, statusFilter, activityActionFilter, auditPage, filesSearch, reportsSearch, isAuthLoading, isAdmin]);

  // Handle Search in Users Tab
  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setCurrentPage(1);
    loadTabContent();
  };

  // View User Detail
  const handleViewUserDetail = async (userId: number) => {
    setIsDetailLoading(true);
    try {
      const data = await getAdminUserDetail(userId);
      setSelectedUserDetail(data);
    } catch (err: any) {
      setErrorMessage(err?.message || 'Failed to load user details.');
    } finally {
      setIsDetailLoading(false);
    }
  };

  // Toggle User Active Status
  const handleToggleUserStatus = async (userToUpdate: User) => {
    try {
      const newStatus = !userToUpdate.isActive;
      await patchAdminUser(userToUpdate.id, { isActive: newStatus });
      setSuccessMessage(`User ${userToUpdate.email} is now ${newStatus ? 'active' : 'deactivated'}.`);
      setUsers((prev) =>
        prev.map((u) => (u.id === userToUpdate.id ? { ...u, isActive: newStatus } : u))
      );
      if (selectedUserDetail && selectedUserDetail.profile.id === userToUpdate.id) {
        setSelectedUserDetail({
          ...selectedUserDetail,
          profile: { ...selectedUserDetail.profile, isActive: newStatus },
        });
      }
    } catch (err: any) {
      setErrorMessage(err?.message || 'Failed to update user status.');
    }
  };

  // Delete User
  const handleDeleteUserConfirm = async () => {
    if (!userToDelete) return;
    setIsDeleting(true);
    try {
      await deleteAdminUser(userToDelete.id);
      setSuccessMessage(`User ${userToDelete.email} and all data were deleted.`);
      setUserToDelete(null);
      if (selectedUserDetail && selectedUserDetail.profile.id === userToDelete.id) {
        setSelectedUserDetail(null);
      }
      loadTabContent();
    } catch (err: any) {
      setErrorMessage(err?.message || 'Failed to delete user.');
    } finally {
      setIsDeleting(false);
    }
  };

  // Super Admin: Create Admin
  const handleCreateAdminSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedEligibleUserId) {
      setErrorMessage('Please choose a user to promote.');
      return;
    }
    setIsCreatingAdmin(true);
    try {
      await createSuperAdminAdmin({
        userId: selectedEligibleUserId,
        permissions: newAdminPerms,
      });
      setSuccessMessage('Administrator created successfully.');
      setShowCreateAdminModal(false);
      loadTabContent();
    } catch (err: any) {
      setErrorMessage(err?.message || 'Failed to promote administrator.');
    } finally {
      setIsCreatingAdmin(false);
    }
  };

  // Super Admin: Save Edited Permissions
  const handleSaveEditedPerms = async () => {
    if (!editingAdmin) return;
    setIsSavingPerms(true);
    try {
      await updateAdminPermissions(editingAdmin.id, editPerms);
      setSuccessMessage(`Permissions updated for ${editingAdmin.email}.`);
      setEditingAdmin(null);
      loadTabContent();
    } catch (err: any) {
      setErrorMessage(err?.message || 'Failed to update permissions.');
    } finally {
      setIsSavingPerms(false);
    }
  };

  // Super Admin: Remove Admin Privileges
  const handleRemoveAdminConfirm = async () => {
    if (!adminToRemove) return;
    setIsRemovingAdmin(true);
    try {
      await removeAdmin(adminToRemove.id);
      setSuccessMessage(`Administrator privileges revoked for ${adminToRemove.email}.`);
      setAdminToRemove(null);
      loadTabContent();
    } catch (err: any) {
      setErrorMessage(err?.message || 'Failed to remove administrator.');
    } finally {
      setIsRemovingAdmin(false);
    }
  };

  // ---------------------------------------------------------------------------
  // Check permission for active tab
  // ---------------------------------------------------------------------------
  const isTabAllowed = (tab: AdminTab): boolean => {
    if (tab === 'overview') return hasPermission('view_users') || hasPermission('view_scans');
    if (tab === 'users') return hasPermission('view_users');
    if (tab === 'uploaded_files') return hasPermission('view_scans') || isAdmin;
    if (tab === 'user_reports') return hasPermission('view_reports') || isAdmin;
    if (tab === 'scans_reports') return hasPermission('view_scans') || hasPermission('view_reports');
    if (tab === 'activity') return hasPermission('view_activity');
    if (tab === 'export') return hasPermission('export_data');
    if (tab === 'admin_mgmt') return isSuperAdmin;
    if (tab === 'audit_log') return isSuperAdmin;
    return false;
  };

  // Permission Gate Screen
  const renderAccessDenied = (requiredPermission: string) => (
    <div className="bg-[#111827] border border-red-900/60 rounded-2xl p-12 text-center max-w-xl mx-auto shadow-2xl space-y-4">
      <div className="w-14 h-14 bg-red-500/10 border border-red-500/30 rounded-2xl flex items-center justify-center text-red-400 mx-auto">
        <ShieldAlert className="w-8 h-8" />
      </div>
      <h2 className="text-xl font-bold text-white">Access Denied</h2>
      <p className="text-sm text-slate-300 leading-relaxed">
        Your administrator account does not possess the required privilege (
        <span className="font-mono text-red-400 font-semibold">{requiredPermission}</span>) to view this section.
      </p>
      <div className="pt-2">
        <button
          onClick={() => setActiveTab('overview')}
          className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-xl text-xs font-medium"
        >
          Return to Overview
        </button>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-[#070B14] flex flex-col md:flex-row text-slate-100 selection:bg-purple-500/30 selection:text-purple-200">
      {/* -------------------------------------------------------------------------
          ADMIN SIDEBAR
      ------------------------------------------------------------------------- */}
      <aside className="w-full md:w-64 bg-[#0A0F1D] border-b md:border-b-0 md:border-r border-purple-950/40 p-4 flex flex-col shrink-0">
        {/* Brand */}
        <div className="flex items-center gap-3 px-3 py-3 border-b border-slate-800/80 mb-4">
          <div className="w-9 h-9 rounded-xl bg-purple-600 flex items-center justify-center text-white shadow-lg shadow-purple-600/30">
            <ShieldAlert size={20} className="stroke-[2.2]" />
          </div>
          <div>
            <h1 className="font-bold text-sm text-white tracking-tight">Admin Console</h1>
            <span className="text-[10px] text-purple-400 font-mono uppercase tracking-wider block">
              Control Center
            </span>
          </div>
        </div>

        {/* Sidebar Nav Items */}
        <nav className="flex-1 space-y-1">
          {/* Overview */}
          {(hasPermission('view_users') || hasPermission('view_scans')) && (
            <button
              onClick={() => setActiveTab('overview')}
              className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-xs font-medium transition-all ${
                activeTab === 'overview'
                  ? 'bg-purple-600/20 text-purple-300 border border-purple-500/30 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <BarChart3 size={16} />
              <span>Overview</span>
            </button>
          )}

          {/* Users */}
          {hasPermission('view_users') && (
            <button
              onClick={() => setActiveTab('users')}
              className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-xs font-medium transition-all ${
                activeTab === 'users'
                  ? 'bg-purple-600/20 text-purple-300 border border-purple-500/30 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <Users size={16} />
              <span>Users Directory</span>
            </button>
          )}

          {/* Uploaded Files */}
          <button
            onClick={() => setActiveTab('uploaded_files')}
            className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-xs font-medium transition-all ${
              activeTab === 'uploaded_files'
                ? 'bg-purple-600/20 text-purple-300 border border-purple-500/30 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <UploadCloud size={16} />
            <span>Uploaded Files</span>
          </button>

          {/* User Reports */}
          <button
            onClick={() => setActiveTab('user_reports')}
            className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-xs font-medium transition-all ${
              activeTab === 'user_reports'
                ? 'bg-purple-600/20 text-purple-300 border border-purple-500/30 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <FileText size={16} />
            <span>User Reports</span>
          </button>

          {/* Scans & Reports */}
          {(hasPermission('view_scans') || hasPermission('view_reports')) && (
            <button
              onClick={() => setActiveTab('scans_reports')}
              className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-xs font-medium transition-all ${
                activeTab === 'scans_reports'
                  ? 'bg-purple-600/20 text-purple-300 border border-purple-500/30 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <FileText size={16} />
              <span>Scans &amp; Reports</span>
            </button>
          )}

          {/* Activity Log */}
          {hasPermission('view_activity') && (
            <button
              onClick={() => setActiveTab('activity')}
              className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-xs font-medium transition-all ${
                activeTab === 'activity'
                  ? 'bg-purple-600/20 text-purple-300 border border-purple-500/30 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <Activity size={16} />
              <span>Activity Log</span>
            </button>
          )}

          {/* Export */}
          {hasPermission('export_data') && (
            <button
              onClick={() => setActiveTab('export')}
              className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-xs font-medium transition-all ${
                activeTab === 'export'
                  ? 'bg-purple-600/20 text-purple-300 border border-purple-500/30 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <Download size={16} />
              <span>Export Data</span>
            </button>
          )}

          {/* Super Admin Section */}
          {isSuperAdmin && (
            <div className="pt-4 mt-3 border-t border-slate-800/80">
              <span className="text-[10px] font-semibold text-purple-400 uppercase tracking-widest px-3 block mb-1">
                Super Admin
              </span>
              <button
                onClick={() => setActiveTab('admin_mgmt')}
                className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-xs font-medium transition-all ${
                  activeTab === 'admin_mgmt'
                    ? 'bg-purple-600/20 text-purple-300 border border-purple-500/30 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
              >
                <ShieldCheck size={16} className="text-purple-400" />
                <span>Admin Management</span>
              </button>
              <button
                onClick={() => setActiveTab('audit_log')}
                className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-xs font-medium transition-all ${
                  activeTab === 'audit_log'
                    ? 'bg-purple-600/20 text-purple-300 border border-purple-500/30 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
              >
                <History size={16} className="text-purple-400" />
                <span>Audit Log</span>
              </button>
            </div>
          )}
        </nav>

        {/* Footer info in sidebar */}
        <div className="pt-4 border-t border-slate-800/80 space-y-2">
          <Link
            to="/dashboard"
            className="flex items-center gap-2 px-3 py-2 rounded-xl text-xs text-slate-400 hover:text-white hover:bg-slate-800/60 transition-colors"
          >
            <ExternalLink size={14} />
            <span>Exit to User App</span>
          </Link>
        </div>
      </aside>

      {/* -------------------------------------------------------------------------
          MAIN CONTENT AREA & HEADER
      ------------------------------------------------------------------------- */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Admin Header */}
        <header className="h-16 bg-[#0A0F1D]/80 border-b border-purple-950/40 px-6 flex items-center justify-between backdrop-blur-md sticky top-0 z-30">
          <div className="flex items-center gap-3">
            <span className="text-xs text-slate-400 uppercase tracking-widest font-mono">
              Portal / {activeTab.replace('_', ' ')}
            </span>
          </div>

          {/* Right Header: Admin profile & logout */}
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 text-right">
              <div>
                <p className="text-xs font-semibold text-white">{user?.name}</p>
                <p className="text-[11px] text-slate-400 truncate max-w-[140px]">{user?.email}</p>
              </div>
              <span
                className={`text-[10px] font-bold px-2 py-0.5 rounded-full uppercase tracking-wider border ${
                  isSuperAdmin
                    ? 'bg-purple-500/20 text-purple-300 border-purple-500/40'
                    : 'bg-blue-500/20 text-blue-300 border-blue-500/40'
                }`}
              >
                {isSuperAdmin ? 'Super Admin' : 'Admin'}
              </span>
            </div>

            <button
              onClick={async () => {
                await logout();
                navigate('/admin/login', { replace: true });
              }}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-800/80 hover:bg-red-950/40 text-slate-300 hover:text-red-300 border border-slate-700/80 hover:border-red-900/60 text-xs font-medium transition-colors cursor-pointer"
            >
              <LogOut size={14} />
              <span>Log out</span>
            </button>
          </div>
        </header>

        {/* Feedback Banners */}
        {errorMessage && (
          <div className="mx-6 mt-4 p-3 bg-red-950/40 border border-red-800/60 rounded-xl flex items-center justify-between text-xs text-red-300">
            <div className="flex items-center gap-2">
              <AlertCircle size={16} className="text-red-400 shrink-0" />
              <span>{errorMessage}</span>
            </div>
            <button onClick={() => setErrorMessage(null)}>
              <X size={14} />
            </button>
          </div>
        )}
        {successMessage && (
          <div className="mx-6 mt-4 p-3 bg-emerald-950/40 border border-emerald-800/60 rounded-xl flex items-center justify-between text-xs text-emerald-300">
            <div className="flex items-center gap-2">
              <CheckCircle size={16} className="text-emerald-400 shrink-0" />
              <span>{successMessage}</span>
            </div>
            <button onClick={() => setSuccessMessage(null)}>
              <X size={14} />
            </button>
          </div>
        )}

        {/* Tab Body */}
        <main className="flex-1 p-6 overflow-y-auto">
          {/* TAB: OVERVIEW */}
          {activeTab === 'overview' && (
            isTabAllowed('overview') ? (
              <div className="space-y-6">
                {/* Stats Cards */}
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                  <div className="bg-[#111827] border border-slate-800 rounded-2xl p-5 shadow-xl">
                    <div className="flex items-center justify-between text-slate-400 mb-2">
                      <span className="text-xs uppercase tracking-wider font-semibold">Total Users</span>
                      <Users size={18} className="text-purple-400" />
                    </div>
                    <div className="text-2xl font-bold text-white">{overview?.totalUsers ?? '...'}</div>
                    <p className="text-[11px] text-slate-500 mt-1">
                      +{overview?.newUsers7d ?? 0} new in the last 7 days
                    </p>
                  </div>

                  <div className="bg-[#111827] border border-slate-800 rounded-2xl p-5 shadow-xl">
                    <div className="flex items-center justify-between text-slate-400 mb-2">
                      <span className="text-xs uppercase tracking-wider font-semibold">Total Scans</span>
                      <Activity size={18} className="text-cyan-400" />
                    </div>
                    <div className="text-2xl font-bold text-white">{overview?.totalScans ?? '...'}</div>
                    <p className="text-[11px] text-slate-500 mt-1">
                      {overview?.realScans ?? 0} authentic scans executed
                    </p>
                  </div>

                  <div className="bg-[#111827] border border-slate-800 rounded-2xl p-5 shadow-xl">
                    <div className="flex items-center justify-between text-slate-400 mb-2">
                      <span className="text-xs uppercase tracking-wider font-semibold">Average Risk</span>
                      <Shield size={18} className="text-yellow-400" />
                    </div>
                    <div className="text-2xl font-bold text-white">{overview?.averageRisk ?? 0} / 100</div>
                    <p className="text-[11px] text-slate-500 mt-1">Platform-wide risk score</p>
                  </div>

                  <div className="bg-[#111827] border border-slate-800 rounded-2xl p-5 shadow-xl">
                    <div className="flex items-center justify-between text-slate-400 mb-2">
                      <span className="text-xs uppercase tracking-wider font-semibold">Critical Threats</span>
                      <AlertTriangle size={18} className="text-red-400" />
                    </div>
                    <div className="text-2xl font-bold text-red-400">
                      {overview?.riskDistribution.critical ?? 0}
                    </div>
                    <p className="text-[11px] text-slate-500 mt-1">Urgent compromise signals</p>
                  </div>
                </div>

                {/* 30-Day Trend Chart */}
                {overview?.scansPerDay && overview.scansPerDay.length > 0 && (
                  <div className="bg-[#111827] border border-slate-800 rounded-2xl p-6 shadow-xl">
                    <h2 className="text-sm font-bold text-white mb-4">Inspection Volume (Last 30 Days)</h2>
                    <div className="h-64">
                      <ResponsiveContainer width="100%" height="100%">
                        <AreaChart data={overview.scansPerDay}>
                          <defs>
                            <linearGradient id="scansGradient" x1="0" y1="0" x2="0" y2="1">
                              <stop offset="5%" stopColor="#8B5CF6" stopOpacity={0.4} />
                              <stop offset="95%" stopColor="#8B5CF6" stopOpacity={0.0} />
                            </linearGradient>
                          </defs>
                          <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" />
                          <XAxis dataKey="date" stroke="#64748B" fontSize={11} />
                          <YAxis stroke="#64748B" fontSize={11} allowDecimals={false} />
                          <Tooltip contentStyle={{ backgroundColor: '#0B0F19', borderColor: '#334155' }} />
                          <Area type="monotone" dataKey="count" stroke="#8B5CF6" strokeWidth={2} fill="url(#scansGradient)" />
                        </AreaChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
                )}
              </div>
            ) : (
              renderAccessDenied('view_users')
            )
          )}

          {/* TAB: USERS */}
          {activeTab === 'users' && (
            isTabAllowed('users') ? (
              <div className="space-y-4">
                {/* Search & Filter Header */}
                <div className="flex flex-col sm:flex-row gap-3 items-center justify-between bg-[#111827] border border-slate-800 rounded-2xl p-4 shadow-xl">
                  <form onSubmit={handleSearchSubmit} className="flex-1 w-full sm:w-auto relative">
                    <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
                    <input
                      type="text"
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      placeholder="Search users by name, username or email..."
                      className="w-full bg-[#0B0F19] border border-slate-700/80 rounded-xl pl-9 pr-4 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-purple-500/50"
                    />
                  </form>

                  <div className="flex items-center gap-2 w-full sm:w-auto">
                    <select
                      value={roleFilter}
                      onChange={(e) => {
                        setRoleFilter(e.target.value);
                        setCurrentPage(1);
                      }}
                      className="bg-[#0B0F19] border border-slate-700/80 rounded-xl px-3 py-2 text-xs text-slate-200 focus:outline-none"
                    >
                      <option value="all">All Roles</option>
                      <option value="user">User</option>
                      <option value="admin">Admin</option>
                      <option value="super_admin">Super Admin</option>
                    </select>

                    <select
                      value={statusFilter}
                      onChange={(e) => {
                        setStatusFilter(e.target.value as any);
                        setCurrentPage(1);
                      }}
                      className="bg-[#0B0F19] border border-slate-700/80 rounded-xl px-3 py-2 text-xs text-slate-200 focus:outline-none"
                    >
                      <option value="all">All Status</option>
                      <option value="active">Active</option>
                      <option value="disabled">Disabled</option>
                    </select>

                    <button
                      onClick={loadTabContent}
                      disabled={isRefreshing}
                      className="p-2 bg-slate-800 hover:bg-slate-700 rounded-xl text-slate-300 hover:text-white transition-colors"
                      title="Refresh"
                    >
                      <RefreshCw size={14} className={isRefreshing ? 'animate-spin' : ''} />
                    </button>
                  </div>
                </div>

                {/* Users Table */}
                <div className="bg-[#111827] border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs">
                      <thead className="bg-[#0B0F19] text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
                        <tr>
                          <th className="py-3 px-4">User</th>
                          <th className="py-3 px-4">Username</th>
                          <th className="py-3 px-4">Role</th>
                          <th className="py-3 px-4">Status</th>
                          <th className="py-3 px-4">Files</th>
                          <th className="py-3 px-4">Reports</th>
                          <th className="py-3 px-4">Scans</th>
                          <th className="py-3 px-4">Joined</th>
                          <th className="py-3 px-4 text-right">Actions</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/80">
                        {users.map((u) => (
                          <tr key={u.id} className="hover:bg-slate-800/30 transition-colors">
                            <td className="py-3 px-4">
                              <p className="font-semibold text-white">{u.name}</p>
                              <p className="text-[11px] text-slate-400">{u.email}</p>
                            </td>
                            <td className="py-3 px-4 font-mono text-cyan-400">
                              @{u.username || 'unassigned'}
                            </td>
                            <td className="py-3 px-4">
                              <span
                                className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${
                                  u.role === 'super_admin'
                                    ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40'
                                    : u.role === 'admin'
                                    ? 'bg-blue-500/20 text-blue-300 border border-blue-500/40'
                                    : 'bg-slate-800 text-slate-300'
                                }`}
                              >
                                {u.role === 'super_admin' ? 'Super Admin' : u.role}
                              </span>
                            </td>
                            <td className="py-3 px-4">
                              <span
                                className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${
                                  u.isActive
                                    ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                                    : 'bg-red-500/10 text-red-400 border border-red-500/30'
                                }`}
                              >
                                {u.isActive ? 'Active' : 'Disabled'}
                              </span>
                            </td>
                            <td className="py-3 px-4 text-cyan-400 font-semibold font-mono">
                              {u.fileCount ?? 0}
                            </td>
                            <td className="py-3 px-4 text-purple-400 font-semibold font-mono">
                              {u.reportCount ?? 0}
                            </td>
                            <td className="py-3 px-4 text-slate-300 font-semibold font-mono">
                              {u.scanCount ?? 0}
                            </td>
                            <td className="py-3 px-4 text-slate-400 text-[11px]">
                              {u.createdAt ? new Date(u.createdAt).toLocaleDateString() : 'N/A'}
                            </td>
                            <td className="py-3 px-4 text-right">
                              <div className="flex items-center justify-end gap-1.5">
                                <button
                                  onClick={() => handleViewUserDetail(u.id)}
                                  className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white rounded-lg transition-colors"
                                  title="View Details"
                                >
                                  <Eye size={14} />
                                </button>
                                {hasPermission('disable_users') && u.id !== user?.id && (
                                  <button
                                    onClick={() => handleToggleUserStatus(u)}
                                    className={`p-1.5 rounded-lg transition-colors ${
                                      u.isActive
                                        ? 'bg-slate-800 hover:bg-yellow-950/40 text-yellow-400'
                                        : 'bg-slate-800 hover:bg-emerald-950/40 text-emerald-400'
                                    }`}
                                    title={u.isActive ? 'Deactivate user' : 'Reactivate user'}
                                  >
                                    {u.isActive ? <UserX size={14} /> : <UserCheck size={14} />}
                                  </button>
                                )}
                                {hasPermission('delete_users') && u.id !== user?.id && (
                                  <button
                                    onClick={() => setUserToDelete(u)}
                                    className="p-1.5 bg-slate-800 hover:bg-red-950/40 text-red-400 rounded-lg transition-colors"
                                    title="Delete user"
                                  >
                                    <Trash2 size={14} />
                                  </button>
                                )}
                              </div>
                            </td>
                          </tr>
                        ))}
                        {users.length === 0 && (
                          <tr>
                            <td colSpan={9} className="py-8 text-center text-slate-500">
                              No users matching search filters found.
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>

                  {/* Pagination */}
                  {totalPages > 1 && (
                    <div className="p-4 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
                      <span>
                        Showing page {currentPage} of {totalPages} ({totalUsersCount} users total)
                      </span>
                      <div className="flex gap-1.5">
                        <button
                          disabled={currentPage <= 1}
                          onClick={() => setCurrentPage((p) => p - 1)}
                          className="px-3 py-1 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 rounded-lg"
                        >
                          Prev
                        </button>
                        <button
                          disabled={currentPage >= totalPages}
                          onClick={() => setCurrentPage((p) => p + 1)}
                          className="px-3 py-1 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 rounded-lg"
                        >
                          Next
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            ) : (
              renderAccessDenied('view_users')
            )
          )}

          {/* TAB: UPLOADED FILES */}
          {activeTab === 'uploaded_files' && (
            <div className="space-y-4">
              <div className="flex flex-col sm:flex-row gap-3 items-center justify-between bg-[#111827] border border-slate-800 rounded-2xl p-4 shadow-xl">
                <div className="flex-1 w-full sm:w-auto relative">
                  <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    value={filesSearch}
                    onChange={(e) => setFilesSearch(e.target.value)}
                    placeholder="Search uploaded files by name or user email..."
                    className="w-full bg-[#0B0F19] border border-slate-700/80 rounded-xl pl-9 pr-4 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-purple-500/50"
                  />
                </div>
                <div className="text-xs text-slate-400 font-mono">
                  Total Files: <span className="font-bold text-white">{filesTotal}</span>
                </div>
              </div>

              <div className="bg-[#111827] border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-[#0B0F19] text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
                      <tr>
                        <th className="py-3 px-4">Uploaded File</th>
                        <th className="py-3 px-4">User</th>
                        <th className="py-3 px-4">Size</th>
                        <th className="py-3 px-4">Module</th>
                        <th className="py-3 px-4">Uploaded At</th>
                        <th className="py-3 px-4 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/80">
                      {uploadedFiles.map((file) => (
                        <tr key={file.id} className="hover:bg-slate-800/30 transition-colors">
                          <td className="py-3 px-4">
                            <div className="flex items-center gap-2.5">
                              <UploadCloud className="w-4 h-4 text-cyan-400 shrink-0" />
                              <div>
                                <p className="font-semibold text-white">{file.filename}</p>
                                <p className="text-[11px] text-slate-500">{file.fileType || 'binary'}</p>
                              </div>
                            </div>
                          </td>
                          <td className="py-3 px-4">
                            <p className="font-semibold text-slate-200">{file.userName}</p>
                            <p className="text-[11px] text-slate-400">{file.userEmail}</p>
                          </td>
                          <td className="py-3 px-4 font-mono text-slate-300">
                            {(file.fileSize / 1024).toFixed(1)} KB
                          </td>
                          <td className="py-3 px-4">
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-blue-500/10 text-blue-400 border border-blue-500/20">
                              {file.module}
                            </span>
                          </td>
                          <td className="py-3 px-4 text-slate-400 text-[11px]">
                            {new Date(file.uploadedAt).toLocaleString()}
                          </td>
                          <td className="py-3 px-4 text-right">
                            <button
                              onClick={() => handleViewUserDetail(file.userId)}
                              className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white rounded-lg transition-colors text-[11px] font-medium inline-flex items-center gap-1"
                            >
                              <Eye size={12} />
                              <span>View User</span>
                            </button>
                          </td>
                        </tr>
                      ))}
                      {uploadedFiles.length === 0 && (
                        <tr>
                          <td colSpan={6} className="py-8 text-center text-slate-500">
                            No uploaded files found.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* TAB: SUBMITTED REPORTS */}
          {activeTab === 'user_reports' && (
            <div className="space-y-4">
              <div className="flex flex-col sm:flex-row gap-3 items-center justify-between bg-[#111827] border border-slate-800 rounded-2xl p-4 shadow-xl">
                <div className="flex-1 w-full sm:w-auto relative">
                  <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    value={reportsSearch}
                    onChange={(e) => setReportsSearch(e.target.value)}
                    placeholder="Search reports by user name or risk..."
                    className="w-full bg-[#0B0F19] border border-slate-700/80 rounded-xl pl-9 pr-4 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-purple-500/50"
                  />
                </div>
                <div className="text-xs text-slate-400 font-mono">
                  Total Reports: <span className="font-bold text-white">{reportsTotal}</span>
                </div>
              </div>

              <div className="bg-[#111827] border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-[#0B0F19] text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
                      <tr>
                        <th className="py-3 px-4">Report ID</th>
                        <th className="py-3 px-4">Submitted By</th>
                        <th className="py-3 px-4">Overall Score</th>
                        <th className="py-3 px-4">Risk Level</th>
                        <th className="py-3 px-4">Date</th>
                        <th className="py-3 px-4 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/80">
                      {adminReports.map((report) => (
                        <tr key={report.id} className="hover:bg-slate-800/30 transition-colors">
                          <td className="py-3 px-4 font-mono font-semibold text-white">
                            #{report.id}
                          </td>
                          <td className="py-3 px-4">
                            <p className="font-semibold text-slate-200">{report.userName}</p>
                            <p className="text-[11px] text-slate-400">{report.userEmail}</p>
                          </td>
                          <td className="py-3 px-4 font-mono font-bold text-cyan-400">
                            {report.overallScore}/100
                          </td>
                          <td className="py-3 px-4">
                            <RiskBadge level={report.overallRisk} />
                          </td>
                          <td className="py-3 px-4 text-slate-400 text-[11px]">
                            {new Date(report.createdAt).toLocaleString()}
                          </td>
                          <td className="py-3 px-4 text-right">
                            <button
                              onClick={() => handleViewUserDetail(report.userId)}
                              className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white rounded-lg transition-colors text-[11px] font-medium inline-flex items-center gap-1"
                            >
                              <Eye size={12} />
                              <span>View User</span>
                            </button>
                          </td>
                        </tr>
                      ))}
                      {adminReports.length === 0 && (
                        <tr>
                          <td colSpan={6} className="py-8 text-center text-slate-500">
                            No submitted reports found.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}
          {activeTab === 'scans_reports' && (
            isTabAllowed('scans_reports') ? (
              <div className="space-y-6">
                <div className="bg-[#111827] border border-slate-800 rounded-2xl p-6 shadow-xl">
                  <h2 className="text-sm font-bold text-white mb-2">Platform Scan Modules Breakdown</h2>
                  <p className="text-xs text-slate-400 mb-6">
                    Distribution of user-initiated threat inspections across Telegram, Repository checks, and Network scanning.
                  </p>

                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                    <div className="bg-[#0B0F19] border border-blue-900/40 rounded-xl p-4">
                      <span className="text-xs text-blue-400 font-semibold">Telegram Log Forensics</span>
                      <div className="text-2xl font-bold text-white mt-1">
                        {overview?.scansPerModule.telegram ?? 0}
                      </div>
                    </div>
                    <div className="bg-[#0B0F19] border border-purple-900/40 rounded-xl p-4">
                      <span className="text-xs text-purple-400 font-semibold">Repository Inspections</span>
                      <div className="text-2xl font-bold text-white mt-1">
                        {overview?.scansPerModule.repo ?? 0}
                      </div>
                    </div>
                    <div className="bg-[#0B0F19] border border-cyan-900/40 rounded-xl p-4">
                      <span className="text-xs text-cyan-400 font-semibold">Network &amp; Threat Intelligence</span>
                      <div className="text-2xl font-bold text-white mt-1">
                        {overview?.scansPerModule.network ?? 0}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              renderAccessDenied('view_scans')
            )
          )}

          {/* TAB: ACTIVITY LOG */}
          {activeTab === 'activity' && (
            isTabAllowed('activity') ? (
              <div className="space-y-4">
                <div className="flex items-center justify-between bg-[#111827] border border-slate-800 rounded-2xl p-4">
                  <div className="flex items-center gap-2">
                    <Activity className="w-4 h-4 text-purple-400" />
                    <h2 className="text-xs font-bold text-white uppercase tracking-wider">
                      Security Activity Feed ({totalLogsCount})
                    </h2>
                  </div>

                  <select
                    value={activityActionFilter}
                    onChange={(e) => setActivityActionFilter(e.target.value)}
                    className="bg-[#0B0F19] border border-slate-700/80 rounded-xl px-3 py-1.5 text-xs text-slate-200 focus:outline-none"
                  >
                    <option value="all">All Actions</option>
                    <option value="login">Login</option>
                    <option value="register">Register</option>
                    <option value="logout">Logout</option>
                    <option value="admin_viewed_user">Admin Viewed User</option>
                    <option value="admin_updated_user">Admin Updated User</option>
                  </select>
                </div>

                <div className="bg-[#111827] border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
                  <div className="divide-y divide-slate-800/80 text-xs">
                    {activityLogs.map((log) => (
                      <div key={log.id} className="p-3.5 flex items-start gap-3 hover:bg-slate-800/30 transition-colors">
                        <div className="w-2 h-2 rounded-full bg-purple-400 mt-1.5 shrink-0" />
                        <div className="flex-1 min-w-0">
                          <p className="font-semibold text-slate-200">
                            {log.action}{' '}
                            {log.userId && <span className="text-slate-400 font-normal">by User #{log.userId}</span>}
                          </p>
                          <p className="text-slate-400 text-[11px] truncate mt-0.5">{log.detail}</p>
                        </div>
                        <span className="text-[10px] text-slate-500 font-mono shrink-0">
                          {new Date(log.createdAt).toLocaleString()}
                        </span>
                      </div>
                    ))}
                    {activityLogs.length === 0 && (
                      <div className="p-8 text-center text-slate-500">No activity logged.</div>
                    )}
                  </div>
                </div>
              </div>
            ) : (
              renderAccessDenied('view_activity')
            )
          )}

          {/* TAB: EXPORT DATA */}
          {activeTab === 'export' && (
            isTabAllowed('export') ? (
              <div className="max-w-2xl bg-[#111827] border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
                <div className="flex items-center gap-3 text-purple-400">
                  <Download className="w-6 h-6" />
                  <h2 className="text-lg font-bold text-white">Export Forensic Records</h2>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed">
                  Download a complete CSV archive of registered user accounts, active roles, verification statuses,
                  and executed investigation counts. All sensitive fields (e.g. passwords, hashes, authentication tokens)
                  are excluded from the export.
                </p>

                <div className="pt-2">
                  <button
                    onClick={downloadUsersCsv}
                    className="px-5 py-2.5 bg-purple-600 hover:bg-purple-500 active:bg-purple-700 text-white rounded-xl text-xs font-semibold flex items-center gap-2 shadow-lg shadow-purple-600/30 cursor-pointer"
                  >
                    <Download size={15} />
                    Download users.csv
                  </button>
                </div>
              </div>
            ) : (
              renderAccessDenied('export_data')
            )
          )}

          {/* TAB: SUPER ADMIN - ADMIN MANAGEMENT */}
          {activeTab === 'admin_mgmt' && (
            isSuperAdmin ? (
              <div className="space-y-6">
                <div className="flex items-center justify-between bg-[#111827] border border-purple-900/40 rounded-2xl p-4 shadow-xl">
                  <div>
                    <h2 className="text-sm font-bold text-white flex items-center gap-2">
                      <ShieldCheck className="w-4 h-4 text-purple-400" />
                      Administrator Privilege Management
                    </h2>
                    <p className="text-xs text-slate-400 mt-0.5">
                      Grant, customize, or revoke granular administrative permissions.
                    </p>
                  </div>
                  <button
                    onClick={() => setShowCreateAdminModal(true)}
                    className="px-4 py-2 bg-purple-600 hover:bg-purple-500 text-white rounded-xl text-xs font-semibold flex items-center gap-1.5 shadow-md shadow-purple-600/30 cursor-pointer"
                  >
                    <UserPlus size={14} />
                    Create Admin
                  </button>
                </div>

                {/* Admins Table */}
                <div className="bg-[#111827] border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-[#0B0F19] text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
                      <tr>
                        <th className="py-3 px-4">Admin</th>
                        <th className="py-3 px-4">Role</th>
                        <th className="py-3 px-4">Assigned Permissions</th>
                        <th className="py-3 px-4">Status</th>
                        <th className="py-3 px-4">Last Login</th>
                        <th className="py-3 px-4 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/80">
                      {adminsList.map((adm) => (
                        <tr key={adm.id} className="hover:bg-slate-800/30 transition-colors">
                          <td className="py-3 px-4">
                            <p className="font-semibold text-white">{adm.name}</p>
                            <p className="text-[11px] text-slate-400">{adm.email}</p>
                          </td>
                          <td className="py-3 px-4">
                            <span
                              className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider border ${
                                adm.role === 'super_admin'
                                  ? 'bg-purple-500/20 text-purple-300 border-purple-500/40'
                                  : 'bg-blue-500/20 text-blue-300 border-blue-500/40'
                              }`}
                            >
                              {adm.role === 'super_admin' ? 'Super Admin' : 'Admin'}
                            </span>
                          </td>
                          <td className="py-3 px-4">
                            {adm.role === 'super_admin' ? (
                              <span className="text-[11px] text-purple-300 font-mono italic">
                                Full System Permissions (Implicit)
                              </span>
                            ) : (
                              <div className="flex flex-wrap gap-1 max-w-sm">
                                {(adm.permissions || []).map((p) => (
                                  <span
                                    key={p}
                                    className="px-1.5 py-0.5 rounded bg-slate-800 text-[10px] text-slate-300 border border-slate-700/60 font-mono"
                                  >
                                    {p}
                                  </span>
                                ))}
                                {(!adm.permissions || adm.permissions.length === 0) && (
                                  <span className="text-slate-500 italic text-[11px]">None assigned</span>
                                )}
                              </div>
                            )}
                          </td>
                          <td className="py-3 px-4">
                            <span
                              className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${
                                adm.isActive
                                  ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                                  : 'bg-red-500/10 text-red-400 border border-red-500/30'
                              }`}
                            >
                              {adm.isActive ? 'Active' : 'Disabled'}
                            </span>
                          </td>
                          <td className="py-3 px-4 text-slate-400 text-[11px]">
                            {adm.lastLoginAt ? new Date(adm.lastLoginAt).toLocaleString() : 'Never'}
                          </td>
                          <td className="py-3 px-4 text-right">
                            {adm.role !== 'super_admin' && adm.id !== user?.id && (
                              <div className="flex items-center justify-end gap-2">
                                <button
                                  onClick={() => {
                                    setEditingAdmin(adm);
                                    setEditPerms(adm.permissions || []);
                                  }}
                                  className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-[11px] font-medium transition-colors"
                                >
                                  Edit Permissions
                                </button>
                                <button
                                  onClick={() => setAdminToRemove(adm)}
                                  className="px-2.5 py-1 bg-red-950/40 hover:bg-red-900/60 text-red-300 border border-red-800/40 rounded-lg text-[11px] font-medium transition-colors"
                                >
                                  Demote
                                </button>
                              </div>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ) : (
              renderAccessDenied('manage_admins')
            )
          )}

          {/* TAB: SUPER ADMIN - AUDIT LOG */}
          {activeTab === 'audit_log' && (
            isSuperAdmin ? (
              <div className="space-y-4">
                <div className="bg-[#111827] border border-purple-900/40 rounded-2xl p-4 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <History className="w-4 h-4 text-purple-400" />
                    <h2 className="text-xs font-bold text-white uppercase tracking-wider">
                      Administrator Audit Trail ({auditTotal})
                    </h2>
                  </div>
                </div>

                <div className="bg-[#111827] border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-[#0B0F19] text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
                      <tr>
                        <th className="py-3 px-4">Timestamp</th>
                        <th className="py-3 px-4">Actor</th>
                        <th className="py-3 px-4">Action</th>
                        <th className="py-3 px-4">Target User</th>
                        <th className="py-3 px-4">State Transition</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/80 font-mono text-[11px]">
                      {auditLogs.map((item) => (
                        <tr key={item.id} className="hover:bg-slate-800/30 transition-colors">
                          <td className="py-3 px-4 text-slate-400">
                            {new Date(item.createdAt).toLocaleString()}
                          </td>
                          <td className="py-3 px-4 text-purple-300 font-sans">
                            {item.actorEmail || 'System'}
                          </td>
                          <td className="py-3 px-4">
                            <span className="px-2 py-0.5 rounded bg-purple-950/60 border border-purple-800/50 text-purple-300 font-mono text-[10px]">
                              {item.action}
                            </span>
                          </td>
                          <td className="py-3 px-4 text-slate-300 font-sans">
                            {item.targetEmail || 'N/A'}
                          </td>
                          <td className="py-3 px-4 text-[10px] text-slate-400 max-w-xs truncate">
                            {item.beforeState && <span>Before: {JSON.stringify(item.beforeState)} </span>}
                            {item.afterState && <span className="text-emerald-400">After: {JSON.stringify(item.afterState)}</span>}
                          </td>
                        </tr>
                      ))}
                      {auditLogs.length === 0 && (
                        <tr>
                          <td colSpan={5} className="py-8 text-center text-slate-500 font-sans text-xs">
                            No administrative audit records found.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>

                  {/* Audit Pagination */}
                  {auditTotalPages > 1 && (
                    <div className="p-4 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400 font-sans">
                      <span>Page {auditPage} of {auditTotalPages}</span>
                      <div className="flex gap-2">
                        <button
                          disabled={auditPage <= 1}
                          onClick={() => setAuditPage((p) => p - 1)}
                          className="px-3 py-1 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 rounded-lg"
                        >
                          Prev
                        </button>
                        <button
                          disabled={auditPage >= auditTotalPages}
                          onClick={() => setAuditPage((p) => p + 1)}
                          className="px-3 py-1 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 rounded-lg"
                        >
                          Next
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            ) : (
              renderAccessDenied('super_admin')
            )
          )}
        </main>
      </div>

      {/* -------------------------------------------------------------------------
          USER DETAIL MODAL / DRAWER
      ------------------------------------------------------------------------- */}
      {selectedUserDetail && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#111827] border border-slate-800 rounded-2xl w-full max-w-2xl max-h-[85vh] overflow-y-auto p-6 space-y-5 shadow-2xl relative">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-base font-bold text-white flex items-center gap-2">
                  <UserCheck className="w-5 h-5 text-purple-400" />
                  User Profile: {selectedUserDetail.profile.name}
                </h3>
                <p className="text-xs text-slate-400 font-mono">@{selectedUserDetail.profile.username || 'unassigned'} &bull; {selectedUserDetail.profile.email}</p>
              </div>
              <button
                onClick={() => setSelectedUserDetail(null)}
                className="p-1 rounded-lg text-slate-400 hover:text-white bg-slate-800"
              >
                <X size={18} />
              </button>
            </div>

            {/* Quick stats */}
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 text-center">
              <div className="bg-[#0B0F19] p-3 rounded-xl border border-slate-800">
                <span className="text-[10px] text-slate-400 uppercase tracking-wider">Role</span>
                <p className="font-bold text-sm text-white uppercase">{selectedUserDetail.profile.role}</p>
              </div>
              <div className="bg-[#0B0F19] p-3 rounded-xl border border-slate-800">
                <span className="text-[10px] text-slate-400 uppercase tracking-wider">Status</span>
                <p className={`font-bold text-sm ${selectedUserDetail.profile.isActive ? 'text-emerald-400' : 'text-red-400'}`}>
                  {selectedUserDetail.profile.isActive ? 'Active' : 'Disabled'}
                </p>
              </div>
              <div className="bg-[#0B0F19] p-3 rounded-xl border border-slate-800">
                <span className="text-[10px] text-slate-400 uppercase tracking-wider">Files Uploaded</span>
                <p className="font-bold text-sm text-cyan-400">{(selectedUserDetail.files || []).length}</p>
              </div>
              <div className="bg-[#0B0F19] p-3 rounded-xl border border-slate-800">
                <span className="text-[10px] text-slate-400 uppercase tracking-wider">Reports</span>
                <p className="font-bold text-sm text-amber-400">{(selectedUserDetail.reports || []).length}</p>
              </div>
              <div className="bg-[#0B0F19] p-3 rounded-xl border border-slate-800 col-span-2 sm:col-span-1">
                <span className="text-[10px] text-slate-400 uppercase tracking-wider">Scans Conducted</span>
                <p className="font-bold text-sm text-purple-400">{selectedUserDetail.scans.length}</p>
              </div>
            </div>

            {/* Uploaded Files */}
            <div>
              <h4 className="text-xs font-bold text-white uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <UploadCloud className="w-3.5 h-3.5 text-cyan-400" />
                Files Uploaded ({ (selectedUserDetail.files || []).length })
              </h4>
              <div className="bg-[#0B0F19] border border-slate-800 rounded-xl divide-y divide-slate-800/80 max-h-40 overflow-y-auto text-xs">
                {(selectedUserDetail.files || []).map((f) => (
                  <div key={f.id} className="p-3 flex items-center justify-between">
                    <div>
                      <p className="font-medium text-slate-200">{f.filename}</p>
                      <p className="text-[11px] text-slate-500 capitalize">{f.module} &bull; {(f.fileSize / 1024).toFixed(1)} KB</p>
                    </div>
                    <span className="text-[10px] text-slate-400">{new Date(f.uploadedAt).toLocaleString()}</span>
                  </div>
                ))}
                {(!selectedUserDetail.files || selectedUserDetail.files.length === 0) && (
                  <div className="p-3 text-center text-slate-500">No files uploaded by this user.</div>
                )}
              </div>
            </div>

            {/* Submitted Reports */}
            <div>
              <h4 className="text-xs font-bold text-white uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <FileText className="w-3.5 h-3.5 text-amber-400" />
                Submitted Reports ({ (selectedUserDetail.reports || []).length })
              </h4>
              <div className="bg-[#0B0F19] border border-slate-800 rounded-xl divide-y divide-slate-800/80 max-h-40 overflow-y-auto text-xs">
                {(selectedUserDetail.reports || []).map((r) => (
                  <div key={r.id} className="p-3 flex items-center justify-between">
                    <div>
                      <span className="font-medium text-slate-200">Investigation Report #{r.id}</span>
                      <p className="text-[11px] text-slate-500">Risk Level: <span className="font-semibold uppercase text-slate-300">{r.overallRisk}</span></p>
                    </div>
                    <div className="text-right">
                      <span className="font-mono text-xs font-bold text-amber-400">{r.overallScore}/100</span>
                      <p className="text-[10px] text-slate-500">{new Date(r.createdAt).toLocaleDateString()}</p>
                    </div>
                  </div>
                ))}
                {(!selectedUserDetail.reports || selectedUserDetail.reports.length === 0) && (
                  <div className="p-3 text-center text-slate-500">No reports submitted by this user.</div>
                )}
              </div>
            </div>

            {/* Recent Scans */}
            <div>
              <h4 className="text-xs font-bold text-white uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <Activity className="w-3.5 h-3.5 text-purple-400" />
                Investigation History ({ selectedUserDetail.scans.length })
              </h4>
              <div className="bg-[#0B0F19] border border-slate-800 rounded-xl divide-y divide-slate-800/80 max-h-44 overflow-y-auto text-xs">
                {selectedUserDetail.scans.map((s) => (
                  <div key={s.id} className="p-3 flex items-center justify-between">
                    <div>
                      <span className="font-semibold text-slate-200 capitalize">{s.module} inspection</span>
                      <p className="text-[11px] text-slate-400">{s.targetLabel}</p>
                    </div>
                    <div className="text-right">
                      <span className="font-mono text-xs font-bold text-cyan-400">{s.riskScore}/100</span>
                      <p className="text-[10px] text-slate-500">{new Date(s.createdAt).toLocaleDateString()}</p>
                    </div>
                  </div>
                ))}
                {selectedUserDetail.scans.length === 0 && (
                  <div className="p-3 text-center text-slate-500">No scans executed yet.</div>
                )}
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedUserDetail(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-xl text-xs font-medium"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* -------------------------------------------------------------------------
          DELETE USER CONFIRMATION MODAL
      ------------------------------------------------------------------------- */}
      {userToDelete && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#111827] border border-red-900/60 rounded-2xl w-full max-w-md p-6 space-y-4 shadow-2xl">
            <div className="flex items-center gap-3 text-red-400">
              <AlertTriangle className="w-6 h-6" />
              <h3 className="text-lg font-bold text-white">Permanently Delete User?</h3>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              Are you sure you want to permanently delete{' '}
              <span className="text-white font-semibold">{userToDelete.email}</span>? All of their forensic scans,
              incident reports, and user profile data will be permanently removed.
            </p>
            <div className="flex justify-end gap-2.5 pt-2">
              <button
                onClick={() => setUserToDelete(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-xl text-xs font-medium"
              >
                Cancel
              </button>
              <button
                onClick={handleDeleteUserConfirm}
                disabled={isDeleting}
                className="px-4 py-2 bg-red-600 hover:bg-red-500 text-white rounded-xl text-xs font-medium flex items-center gap-1.5 disabled:opacity-50"
              >
                {isDeleting && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                Delete User
              </button>
            </div>
          </div>
        </div>
      )}

      {/* -------------------------------------------------------------------------
          CREATE ADMIN MODAL (Super Admin)
      ------------------------------------------------------------------------- */}
      {showCreateAdminModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#111827] border border-purple-900/60 rounded-2xl w-full max-w-lg p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <UserPlus className="w-5 h-5 text-purple-400" />
                Promote Verified User to Administrator
              </h3>
              <button onClick={() => setShowCreateAdminModal(false)} className="text-slate-400 hover:text-white">
                <X size={18} />
              </button>
            </div>

            <form onSubmit={handleCreateAdminSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5 uppercase tracking-wider">
                  Select User (Verified accounts only)
                </label>
                <select
                  value={selectedEligibleUserId || ''}
                  onChange={(e) => setSelectedEligibleUserId(Number(e.target.value))}
                  className="w-full bg-[#0B0F19] border border-slate-700 rounded-xl px-3 py-2 text-xs text-slate-100 focus:outline-none focus:ring-2 focus:ring-purple-500"
                >
                  {eligibleUsers.map((u) => (
                    <option key={u.id} value={u.id}>
                      {u.name} (@{u.username || 'user'}) - {u.email}
                    </option>
                  ))}
                  {eligibleUsers.length === 0 && <option value="">No verified standard users available</option>}
                </select>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-2 uppercase tracking-wider">
                  Grant Granular Permissions
                </label>
                <div className="space-y-2 bg-[#0B0F19] border border-slate-800 rounded-xl p-3 max-h-56 overflow-y-auto">
                  {Object.entries(PERMISSION_DESCRIPTIONS).map(([permKey, info]) => {
                    const checked = newAdminPerms.includes(permKey);
                    return (
                      <label key={permKey} className="flex items-start gap-2.5 cursor-pointer group">
                        <input
                          type="checkbox"
                          checked={checked}
                          onChange={(e) => {
                            if (e.target.checked) {
                              setNewAdminPerms([...newAdminPerms, permKey]);
                            } else {
                              setNewAdminPerms(newAdminPerms.filter((p) => p !== permKey));
                            }
                          }}
                          className="mt-0.5 rounded bg-slate-900 border-slate-700 text-purple-600 focus:ring-purple-500"
                        />
                        <div>
                          <p className="text-xs font-semibold text-slate-200 group-hover:text-purple-300">
                            {info.label} <span className="font-mono text-[10px] text-slate-500">({permKey})</span>
                          </p>
                          <p className="text-[11px] text-slate-400">{info.desc}</p>
                        </div>
                      </label>
                    );
                  })}
                </div>
              </div>

              <div className="flex justify-end gap-2.5 pt-2">
                <button
                  type="button"
                  onClick={() => setShowCreateAdminModal(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-xl text-xs font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isCreatingAdmin || !selectedEligibleUserId}
                  className="px-4 py-2 bg-purple-600 hover:bg-purple-500 text-white rounded-xl text-xs font-medium flex items-center gap-1.5 disabled:opacity-50"
                >
                  {isCreatingAdmin && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                  Create Admin
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* -------------------------------------------------------------------------
          EDIT PERMISSIONS MODAL (Super Admin)
      ------------------------------------------------------------------------- */}
      {editingAdmin && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#111827] border border-purple-900/60 rounded-2xl w-full max-w-lg p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-base font-bold text-white flex items-center gap-2">
                  <Settings className="w-5 h-5 text-purple-400" />
                  Edit Admin Permissions
                </h3>
                <p className="text-xs text-slate-400">{editingAdmin.email}</p>
              </div>
              <button onClick={() => setEditingAdmin(null)} className="text-slate-400 hover:text-white">
                <X size={18} />
              </button>
            </div>

            <div className="space-y-2 bg-[#0B0F19] border border-slate-800 rounded-xl p-3 max-h-64 overflow-y-auto">
              {Object.entries(PERMISSION_DESCRIPTIONS).map(([permKey, info]) => {
                const checked = editPerms.includes(permKey);
                return (
                  <label key={permKey} className="flex items-start gap-2.5 cursor-pointer group">
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setEditPerms([...editPerms, permKey]);
                        } else {
                          setEditPerms(editPerms.filter((p) => p !== permKey));
                        }
                      }}
                      className="mt-0.5 rounded bg-slate-900 border-slate-700 text-purple-600 focus:ring-purple-500"
                    />
                    <div>
                      <p className="text-xs font-semibold text-slate-200 group-hover:text-purple-300">
                        {info.label} <span className="font-mono text-[10px] text-slate-500">({permKey})</span>
                      </p>
                      <p className="text-[11px] text-slate-400">{info.desc}</p>
                    </div>
                  </label>
                );
              })}
            </div>

            <div className="flex justify-end gap-2.5 pt-2">
              <button
                type="button"
                onClick={() => setEditingAdmin(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-xl text-xs font-medium"
              >
                Cancel
              </button>
              <button
                onClick={handleSaveEditedPerms}
                disabled={isSavingPerms}
                className="px-4 py-2 bg-purple-600 hover:bg-purple-500 text-white rounded-xl text-xs font-medium flex items-center gap-1.5 disabled:opacity-50"
              >
                {isSavingPerms && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                Save Permissions
              </button>
            </div>
          </div>
        </div>
      )}

      {/* -------------------------------------------------------------------------
          DEMOTE / REMOVE ADMIN MODAL (Super Admin)
      ------------------------------------------------------------------------- */}
      {adminToRemove && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#111827] border border-red-900/60 rounded-2xl w-full max-w-md p-6 space-y-4 shadow-2xl">
            <div className="flex items-center gap-3 text-red-400">
              <AlertTriangle className="w-6 h-6" />
              <h3 className="text-lg font-bold text-white">Revoke Administrator Privileges?</h3>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              Are you sure you want to demote <span className="text-white font-semibold">{adminToRemove.email}</span> back
              to a standard user? They will immediately lose all administrative rights, and active sessions will be invalidated.
            </p>
            <div className="flex justify-end gap-2.5 pt-2">
              <button
                onClick={() => setAdminToRemove(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-xl text-xs font-medium"
              >
                Cancel
              </button>
              <button
                onClick={handleRemoveAdminConfirm}
                disabled={isRemovingAdmin}
                className="px-4 py-2 bg-red-600 hover:bg-red-500 text-white rounded-xl text-xs font-medium flex items-center gap-1.5 disabled:opacity-50"
              >
                {isRemovingAdmin && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                Revoke Admin Status
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
