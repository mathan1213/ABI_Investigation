import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
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
} from '../lib/api';
import { AdminOverview, User, UserDetail, ActivityLogItem, RiskLevel } from '../lib/types';
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

export const AdminDashboard: React.FC = () => {
  const { user, isAdmin, isLoading: isAuthLoading } = useAuth();
  const navigate = useNavigate();

  const [activeTab, setActiveTab] = useState<'overview' | 'users' | 'activity'>('overview');
  const [overview, setOverview] = useState<AdminOverview | null>(null);
  const [users, setUsers] = useState<User[]>([]);
  const [totalUsersCount, setTotalUsersCount] = useState(0);
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);

  // Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [roleFilter, setRoleFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState<'all' | 'active' | 'disabled'>('all');
  const [activityActionFilter, setActivityActionFilter] = useState('all');

  // Logs
  const [activityLogs, setActivityLogs] = useState<ActivityLogItem[]>([]);
  const [totalLogsCount, setTotalLogsCount] = useState(0);

  // User Detail Modal
  const [selectedUserDetail, setSelectedUserDetail] = useState<UserDetail | null>(null);
  const [isDetailLoading, setIsDetailLoading] = useState(false);

  // Deletion state
  const [userToDelete, setUserToDelete] = useState<User | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);

  // General Loading & Feedback
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // Check admin permission
  useEffect(() => {
    if (!isAuthLoading) {
      if (!user || !isAdmin) {
        navigate('/dashboard', { replace: true });
      }
    }
  }, [user, isAdmin, isAuthLoading, navigate]);

  const loadData = async () => {
    setIsRefreshing(true);
    setErrorMessage(null);
    try {
      const [ovData, usersData, actData] = await Promise.all([
        getAdminOverview(),
        getAdminUsers({
          search: searchQuery,
          role: roleFilter,
          isActive: statusFilter === 'all' ? undefined : statusFilter === 'active',
          page: currentPage,
          perPage: 10,
        }),
        getAdminActivity({
          action: activityActionFilter === 'all' ? undefined : activityActionFilter,
          limit: 30,
        }),
      ]);

      setOverview(ovData);
      setUsers(usersData.items);
      setTotalUsersCount(usersData.total);
      setTotalPages(usersData.totalPages);
      setActivityLogs(actData.items);
      setTotalLogsCount(actData.total);
    } catch (err: any) {
      setErrorMessage(err?.message || 'Failed to load administrative data.');
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    if (isAdmin) {
      loadData();
    }
  }, [isAdmin, currentPage, roleFilter, statusFilter, activityActionFilter]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setCurrentPage(1);
    loadData();
  };

  const handleViewUser = async (userId: number) => {
    setIsDetailLoading(true);
    setErrorMessage(null);
    try {
      const detail = await getAdminUserDetail(userId);
      setSelectedUserDetail(detail);
    } catch (err: any) {
      setErrorMessage(err?.message || 'Failed to load user details.');
    } finally {
      setIsDetailLoading(false);
    }
  };

  const handleToggleUserStatus = async (targetUser: User) => {
    const nextStatus = !targetUser.isActive;
    try {
      await patchAdminUser(targetUser.id, { isActive: nextStatus });
      setSuccessMessage(
        `User ${targetUser.email} has been ${nextStatus ? 'enabled' : 'disabled'}.`
      );
      loadData();
      if (selectedUserDetail && selectedUserDetail.profile.id === targetUser.id) {
        setSelectedUserDetail({
          ...selectedUserDetail,
          profile: { ...selectedUserDetail.profile, isActive: nextStatus },
        });
      }
    } catch (err: any) {
      setErrorMessage(err?.message || 'Failed to update user status.');
    }
  };

  const handleDeleteUserConfirm = async () => {
    if (!userToDelete) return;
    setIsDeleting(true);
    try {
      await deleteAdminUser(userToDelete.id);
      setSuccessMessage(`User ${userToDelete.email} and all data were deleted.`);
      setUserToDelete(null);
      if (selectedUserDetail?.profile.id === userToDelete.id) {
        setSelectedUserDetail(null);
      }
      loadData();
    } catch (err: any) {
      setErrorMessage(err?.message || 'Failed to delete user.');
    } finally {
      setIsDeleting(false);
    }
  };

  const handleExportCsv = async () => {
    try {
      await downloadUsersCsv();
      setSuccessMessage('Users CSV export generated successfully.');
    } catch (err: any) {
      setErrorMessage(err?.message || 'Failed to export CSV.');
    }
  };

  if (isAuthLoading || isLoading) {
    return (
      <div className="min-h-[60vh] flex flex-col items-center justify-center gap-3">
        <Loader2 className="w-8 h-8 animate-spin text-blue-500" />
        <p className="text-sm text-slate-400">Loading Administrative Control Center...</p>
      </div>
    );
  }

  // Chart data formatting
  const modulePieData = overview
    ? [
        { name: 'Telegram', value: overview.scansPerModule.telegram, color: MODULE_COLORS.telegram },
        { name: 'Repo Check', value: overview.scansPerModule.repo, color: MODULE_COLORS.repo },
        { name: 'Network', value: overview.scansPerModule.network, color: MODULE_COLORS.network },
      ]
    : [];

  const riskBarData = overview
    ? [
        { name: 'Low', count: overview.riskDistribution.low, fill: RISK_COLORS.low },
        { name: 'Medium', count: overview.riskDistribution.medium, fill: RISK_COLORS.medium },
        { name: 'High', count: overview.riskDistribution.high, fill: RISK_COLORS.high },
        { name: 'Critical', count: overview.riskDistribution.critical, fill: RISK_COLORS.critical },
      ]
    : [];

  return (
    <div className="max-w-7xl mx-auto px-4 py-8 space-y-8">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-6">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-blue-500/10 border border-blue-500/20 rounded-xl text-blue-400">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-2xl font-bold text-white tracking-tight">Admin Control Center</h1>
                <span className="px-2 py-0.5 text-xs font-semibold uppercase tracking-wider bg-blue-500/20 text-blue-300 border border-blue-500/30 rounded-md">
                  Administrator
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                System telemetry, user management, and investigative audit logs
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={loadData}
            disabled={isRefreshing}
            className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-xl text-xs font-medium flex items-center gap-2 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button
            onClick={handleExportCsv}
            className="px-3.5 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-xs font-medium flex items-center gap-2 transition-colors shadow-sm"
          >
            <Download className="w-3.5 h-3.5" />
            Export Users CSV
          </button>
        </div>
      </div>

      {/* Notifications */}
      {errorMessage && (
        <div className="p-3.5 bg-red-900/30 border border-red-800/60 rounded-xl flex items-center justify-between text-sm text-red-300">
          <div className="flex items-center gap-2.5">
            <AlertCircle className="w-5 h-5 text-red-400 shrink-0" />
            <span>{errorMessage}</span>
          </div>
          <button onClick={() => setErrorMessage(null)} className="text-red-400 hover:text-red-200">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {successMessage && (
        <div className="p-3.5 bg-emerald-900/30 border border-emerald-800/60 rounded-xl flex items-center justify-between text-sm text-emerald-300">
          <div className="flex items-center gap-2.5">
            <CheckCircle className="w-5 h-5 text-emerald-400 shrink-0" />
            <span>{successMessage}</span>
          </div>
          <button onClick={() => setSuccessMessage(null)} className="text-emerald-400 hover:text-emerald-200">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Navigation Tabs */}
      <div className="flex gap-2 border-b border-slate-800">
        <button
          onClick={() => setActiveTab('overview')}
          className={`pb-3 px-4 text-sm font-medium transition-colors border-b-2 flex items-center gap-2 ${
            activeTab === 'overview'
              ? 'border-blue-500 text-blue-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <BarChart3 className="w-4 h-4" />
          Overview & Analytics
        </button>
        <button
          onClick={() => setActiveTab('users')}
          className={`pb-3 px-4 text-sm font-medium transition-colors border-b-2 flex items-center gap-2 ${
            activeTab === 'users'
              ? 'border-blue-500 text-blue-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Users className="w-4 h-4" />
          User Management ({totalUsersCount})
        </button>
        <button
          onClick={() => setActiveTab('activity')}
          className={`pb-3 px-4 text-sm font-medium transition-colors border-b-2 flex items-center gap-2 ${
            activeTab === 'activity'
              ? 'border-blue-500 text-blue-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Activity className="w-4 h-4" />
          Activity Log ({totalLogsCount})
        </button>
      </div>

      {/* TAB 1: OVERVIEW */}
      {activeTab === 'overview' && overview && (
        <div className="space-y-8">
          {/* Metrics Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="bg-[#111827] border border-slate-800 rounded-2xl p-5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Total Users</span>
                <Users className="w-4 h-4 text-blue-400" />
              </div>
              <div className="mt-3 flex items-baseline gap-2">
                <span className="text-3xl font-bold text-white">{overview.totalUsers}</span>
                <span className="text-xs text-emerald-400 font-medium">+{overview.newUsers7d} this week</span>
              </div>
            </div>

            <div className="bg-[#111827] border border-slate-800 rounded-2xl p-5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Total Scans Run</span>
                <Activity className="w-4 h-4 text-purple-400" />
              </div>
              <div className="mt-3 flex items-baseline gap-2">
                <span className="text-3xl font-bold text-white">{overview.totalScans}</span>
                <span className="text-xs text-slate-400">
                  ({overview.realScans} real, {overview.demoScans} demo)
                </span>
              </div>
            </div>

            <div className="bg-[#111827] border border-slate-800 rounded-2xl p-5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Average Risk Score</span>
                <Shield className="w-4 h-4 text-amber-400" />
              </div>
              <div className="mt-3 flex items-baseline gap-2">
                <span className="text-3xl font-bold text-white">{overview.averageRisk}</span>
                <span className="text-xs text-slate-400">/ 100</span>
              </div>
            </div>

            <div className="bg-[#111827] border border-slate-800 rounded-2xl p-5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Critical Anomalies</span>
                <AlertTriangle className="w-4 h-4 text-red-400" />
              </div>
              <div className="mt-3 flex items-baseline gap-2">
                <span className="text-3xl font-bold text-red-400">{overview.riskDistribution.critical}</span>
                <span className="text-xs text-slate-400">scans flagged Critical</span>
              </div>
            </div>
          </div>

          {/* Charts Row */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Scans over 30 days line chart */}
            <div className="lg:col-span-2 bg-[#111827] border border-slate-800 rounded-2xl p-6">
              <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
                <Calendar className="w-4 h-4 text-blue-400" />
                Scans Over Time (Last 30 Days)
              </h3>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={overview.scansPerDay}>
                    <defs>
                      <linearGradient id="scansGradient" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.4} />
                        <stop offset="95%" stopColor="#3B82F6" stopOpacity={0.0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1F2937" vertical={false} />
                    <XAxis
                      dataKey="date"
                      stroke="#6B7280"
                      fontSize={11}
                      tickLine={false}
                      tickFormatter={(val) => val.slice(5)}
                    />
                    <YAxis stroke="#6B7280" fontSize={11} tickLine={false} allowDecimals={false} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#0B0F19',
                        borderColor: '#374151',
                        borderRadius: '0.75rem',
                        fontSize: '12px',
                        color: '#F3F4F6',
                      }}
                    />
                    <Area
                      type="monotone"
                      dataKey="count"
                      stroke="#3B82F6"
                      strokeWidth={2}
                      fillOpacity={1}
                      fill="url(#scansGradient)"
                      name="Scans"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Module Donut */}
            <div className="bg-[#111827] border border-slate-800 rounded-2xl p-6 flex flex-col justify-between">
              <div>
                <h3 className="text-sm font-semibold text-white mb-4">Module Utilization</h3>
                <div className="h-44">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={modulePieData}
                        dataKey="value"
                        nameKey="name"
                        cx="50%"
                        cy="50%"
                        innerRadius={45}
                        outerRadius={70}
                        paddingAngle={4}
                      >
                        {modulePieData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#0B0F19',
                          borderColor: '#374151',
                          borderRadius: '0.75rem',
                          fontSize: '12px',
                        }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              </div>

              <div className="space-y-2 pt-2 border-t border-slate-800/80">
                {modulePieData.map((m) => (
                  <div key={m.name} className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-2">
                      <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: m.color }} />
                      <span className="text-slate-300">{m.name}</span>
                    </div>
                    <span className="font-semibold text-white">{m.value}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Risk Level Distribution Bar */}
          <div className="bg-[#111827] border border-slate-800 rounded-2xl p-6">
            <h3 className="text-sm font-semibold text-white mb-4">Risk Severity Distribution</h3>
            <div className="h-48">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={riskBarData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1F2937" vertical={false} />
                  <XAxis dataKey="name" stroke="#6B7280" fontSize={11} tickLine={false} />
                  <YAxis stroke="#6B7280" fontSize={11} tickLine={false} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0B0F19',
                      borderColor: '#374151',
                      borderRadius: '0.75rem',
                      fontSize: '12px',
                    }}
                  />
                  <Bar dataKey="count" radius={[6, 6, 0, 0]} name="Investigations">
                    {riskBarData.map((entry, index) => (
                      <Cell key={`bar-${index}`} fill={entry.fill} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: USERS MANAGEMENT */}
      {activeTab === 'users' && (
        <div className="space-y-4">
          {/* Search & Filter Bar */}
          <div className="bg-[#111827] border border-slate-800 rounded-2xl p-4 flex flex-col md:flex-row gap-3 items-center justify-between">
            <form onSubmit={handleSearchSubmit} className="relative w-full md:w-80">
              <Search className="w-4 h-4 absolute left-3.5 top-3 text-slate-500" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search user by name or email..."
                className="w-full bg-[#0B0F19] border border-slate-700/80 rounded-xl pl-10 pr-4 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
              />
            </form>

            <div className="flex flex-wrap items-center gap-2.5 w-full md:w-auto">
              <div className="flex items-center gap-1.5 text-xs text-slate-400">
                <Filter className="w-3.5 h-3.5" />
                <span>Role:</span>
                <select
                  value={roleFilter}
                  onChange={(e) => {
                    setRoleFilter(e.target.value);
                    setCurrentPage(1);
                  }}
                  className="bg-[#0B0F19] border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none"
                >
                  <option value="all">All Roles</option>
                  <option value="user">Users</option>
                  <option value="admin">Admins</option>
                </select>
              </div>

              <div className="flex items-center gap-1.5 text-xs text-slate-400">
                <span>Status:</span>
                <select
                  value={statusFilter}
                  onChange={(e) => {
                    setStatusFilter(e.target.value as any);
                    setCurrentPage(1);
                  }}
                  className="bg-[#0B0F19] border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none"
                >
                  <option value="all">All Statuses</option>
                  <option value="active">Active</option>
                  <option value="disabled">Disabled</option>
                </select>
              </div>
            </div>
          </div>

          {/* Users Table */}
          <div className="bg-[#111827] border border-slate-800 rounded-2xl overflow-hidden shadow-lg">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs text-slate-300">
                <thead className="bg-[#0B0F19] text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
                  <tr>
                    <th className="py-3.5 px-4">User</th>
                    <th className="py-3.5 px-4">Role</th>
                    <th className="py-3.5 px-4">Status</th>
                    <th className="py-3.5 px-4">Scans</th>
                    <th className="py-3.5 px-4">Registered</th>
                    <th className="py-3.5 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/80 font-normal">
                  {users.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="py-8 text-center text-slate-500">
                        No users found matching current filters.
                      </td>
                    </tr>
                  ) : (
                    users.map((u) => (
                      <tr key={u.id} className="hover:bg-slate-800/40 transition-colors">
                        <td className="py-3.5 px-4">
                          <div className="font-medium text-white">{u.name}</div>
                          <div className="text-slate-400 text-[11px]">{u.email}</div>
                        </td>
                        <td className="py-3.5 px-4">
                          <span
                            className={`px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase tracking-wider border ${
                              u.role === 'admin'
                                ? 'bg-purple-900/30 text-purple-300 border-purple-800/50'
                                : 'bg-slate-800 text-slate-300 border-slate-700'
                            }`}
                          >
                            {u.role}
                          </span>
                        </td>
                        <td className="py-3.5 px-4">
                          <span
                            className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium ${
                              u.isActive
                                ? 'bg-emerald-900/30 text-emerald-400 border border-emerald-800/40'
                                : 'bg-red-900/30 text-red-400 border border-red-800/40'
                            }`}
                          >
                            {u.isActive ? 'Active' : 'Disabled'}
                          </span>
                        </td>
                        <td className="py-3.5 px-4 font-mono text-white">{u.scanCount ?? 0}</td>
                        <td className="py-3.5 px-4 text-slate-400">
                          {new Date(u.createdAt).toLocaleDateString()}
                        </td>
                        <td className="py-3.5 px-4 text-right">
                          <div className="flex items-center justify-end gap-1.5">
                            <button
                              onClick={() => handleViewUser(u.id)}
                              title="View User Detail"
                              className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors"
                            >
                              <Eye className="w-3.5 h-3.5" />
                            </button>
                            <button
                              onClick={() => handleToggleUserStatus(u)}
                              disabled={u.id === user?.id}
                              title={u.isActive ? 'Disable User' : 'Enable User'}
                              className={`p-1.5 rounded-lg transition-colors ${
                                u.isActive
                                  ? 'bg-amber-950/40 hover:bg-amber-900/60 text-amber-400'
                                  : 'bg-emerald-950/40 hover:bg-emerald-900/60 text-emerald-400'
                              } disabled:opacity-30`}
                            >
                              {u.isActive ? <UserX className="w-3.5 h-3.5" /> : <UserCheck className="w-3.5 h-3.5" />}
                            </button>
                            <button
                              onClick={() => setUserToDelete(u)}
                              disabled={u.id === user?.id}
                              title="Delete User"
                              className="p-1.5 bg-red-950/40 hover:bg-red-900/60 text-red-400 rounded-lg transition-colors disabled:opacity-30"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination Controls */}
            {totalPages > 1 && (
              <div className="p-3.5 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
                <span>
                  Page {currentPage} of {totalPages} ({totalUsersCount} total)
                </span>
                <div className="flex items-center gap-2">
                  <button
                    disabled={currentPage <= 1}
                    onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                    className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded disabled:opacity-40"
                  >
                    Previous
                  </button>
                  <button
                    disabled={currentPage >= totalPages}
                    onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                    className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded disabled:opacity-40"
                  >
                    Next
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 3: ACTIVITY LOG */}
      {activeTab === 'activity' && (
        <div className="space-y-4">
          <div className="bg-[#111827] border border-slate-800 rounded-2xl p-4 flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <Filter className="w-3.5 h-3.5" />
              <span>Filter Action:</span>
              <select
                value={activityActionFilter}
                onChange={(e) => setActivityActionFilter(e.target.value)}
                className="bg-[#0B0F19] border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none"
              >
                <option value="all">All Actions</option>
                <option value="register">register</option>
                <option value="login">login</option>
                <option value="upload_logs">upload_logs</option>
                <option value="scan_repo">scan_repo</option>
                <option value="scan_network">scan_network</option>
                <option value="generate_report">generate_report</option>
                <option value="admin_viewed_user">admin_viewed_user</option>
                <option value="delete_account">delete_account</option>
              </select>
            </div>
            <span className="text-xs text-slate-500">{totalLogsCount} total recorded events</span>
          </div>

          <div className="bg-[#111827] border border-slate-800 rounded-2xl overflow-hidden shadow-lg">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs text-slate-300">
                <thead className="bg-[#0B0F19] text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
                  <tr>
                    <th className="py-3 px-4">Timestamp</th>
                    <th className="py-3 px-4">Action</th>
                    <th className="py-3 px-4">User ID</th>
                    <th className="py-3 px-4">Audit Details</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/80 font-mono text-[11px]">
                  {activityLogs.length === 0 ? (
                    <tr>
                      <td colSpan={4} className="py-8 text-center text-slate-500 font-sans text-xs">
                        No activity records found.
                      </td>
                    </tr>
                  ) : (
                    activityLogs.map((log) => (
                      <tr key={log.id} className="hover:bg-slate-800/30 transition-colors">
                        <td className="py-2.5 px-4 text-slate-400 whitespace-nowrap">
                          {new Date(log.createdAt).toLocaleString()}
                        </td>
                        <td className="py-2.5 px-4">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                              log.action.includes('admin')
                                ? 'bg-purple-900/40 text-purple-300'
                                : log.action.includes('delete')
                                ? 'bg-red-900/40 text-red-300'
                                : 'bg-slate-800 text-blue-300'
                            }`}
                          >
                            {log.action}
                          </span>
                        </td>
                        <td className="py-2.5 px-4 text-slate-400">{log.userId ?? 'system'}</td>
                        <td className="py-2.5 px-4 text-slate-200 font-sans text-xs">{log.detail}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* USER DETAIL MODAL */}
      {selectedUserDetail && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#111827] border border-slate-800 rounded-2xl w-full max-w-3xl max-h-[85vh] overflow-y-auto p-6 space-y-6 shadow-2xl relative">
            <button
              onClick={() => setSelectedUserDetail(null)}
              className="absolute top-4 right-4 p-1.5 text-slate-400 hover:text-white rounded-lg bg-slate-800"
            >
              <X className="w-5 h-5" />
            </button>

            {/* Profile Overview */}
            <div className="border-b border-slate-800 pb-4">
              <h2 className="text-xl font-bold text-white flex items-center gap-2">
                <Users className="w-5 h-5 text-blue-400" />
                User Dossier: {selectedUserDetail.profile.name}
              </h2>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-4 text-xs">
                <div className="bg-[#0B0F19] p-3 rounded-xl border border-slate-800">
                  <span className="text-slate-400 block mb-1">Email</span>
                  <span className="text-white font-medium">{selectedUserDetail.profile.email}</span>
                </div>
                <div className="bg-[#0B0F19] p-3 rounded-xl border border-slate-800">
                  <span className="text-slate-400 block mb-1">Role</span>
                  <span className="text-white font-medium uppercase">{selectedUserDetail.profile.role}</span>
                </div>
                <div className="bg-[#0B0F19] p-3 rounded-xl border border-slate-800">
                  <span className="text-slate-400 block mb-1">Status</span>
                  <span className={selectedUserDetail.profile.isActive ? 'text-emerald-400' : 'text-red-400'}>
                    {selectedUserDetail.profile.isActive ? 'Active' : 'Disabled'}
                  </span>
                </div>
                <div className="bg-[#0B0F19] p-3 rounded-xl border border-slate-800">
                  <span className="text-slate-400 block mb-1">Registered</span>
                  <span className="text-slate-200">
                    {new Date(selectedUserDetail.profile.createdAt).toLocaleDateString()}
                  </span>
                </div>
              </div>
            </div>

            {/* Scan History */}
            <div>
              <h3 className="text-sm font-semibold text-white mb-2 flex items-center gap-2">
                <Shield className="w-4 h-4 text-blue-400" />
                Scan History ({selectedUserDetail.scans.length})
              </h3>
              {selectedUserDetail.scans.length === 0 ? (
                <p className="text-xs text-slate-500 italic">No investigations performed by this user yet.</p>
              ) : (
                <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                  {selectedUserDetail.scans.map((s) => (
                    <div
                      key={s.id}
                      className="bg-[#0B0F19] border border-slate-800 rounded-xl p-3 flex items-center justify-between text-xs"
                    >
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-semibold text-white uppercase text-[10px] bg-slate-800 px-1.5 py-0.5 rounded">
                            {s.module}
                          </span>
                          <span className="text-slate-200 font-medium">{s.targetLabel}</span>
                          {s.isDemo && (
                            <span className="px-1.5 py-0.2 text-[9px] bg-amber-500/20 text-amber-300 rounded">
                              Demo
                            </span>
                          )}
                        </div>
                        <div className="text-[11px] text-slate-400 mt-1">
                          {new Date(s.createdAt).toLocaleString()}
                        </div>
                      </div>
                      <RiskBadge level={s.riskLevel} />
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Reports Generated */}
            <div>
              <h3 className="text-sm font-semibold text-white mb-2 flex items-center gap-2">
                <FileText className="w-4 h-4 text-purple-400" />
                Generated Incident Reports ({selectedUserDetail.reports.length})
              </h3>
              {selectedUserDetail.reports.length === 0 ? (
                <p className="text-xs text-slate-500 italic">No dossiers generated.</p>
              ) : (
                <div className="space-y-2 max-h-40 overflow-y-auto pr-1">
                  {selectedUserDetail.reports.map((r) => (
                    <div
                      key={r.id}
                      className="bg-[#0B0F19] border border-slate-800 rounded-xl p-3 flex items-center justify-between text-xs"
                    >
                      <div className="text-slate-300">
                        <span>Report #{r.id}</span>
                        <div className="text-[11px] text-slate-500">{new Date(r.createdAt).toLocaleString()}</div>
                      </div>
                      <div className="flex items-center gap-3">
                        <span className="font-bold text-white">Score {r.overallScore}/100</span>
                        <RiskBadge level={r.overallRisk} />
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* DELETE CONFIRMATION MODAL */}
      {userToDelete && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#111827] border border-red-900/60 rounded-2xl w-full max-w-md p-6 space-y-4 shadow-2xl">
            <div className="flex items-center gap-3 text-red-400">
              <AlertTriangle className="w-6 h-6" />
              <h3 className="text-lg font-bold text-white">Delete User Account</h3>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              Are you sure you want to permanently delete account{' '}
              <strong className="text-white">{userToDelete.email}</strong>? All associated scan records,
              generated incident reports, and activity logs will be permanently deleted.
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
                Confirm Deletion
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
