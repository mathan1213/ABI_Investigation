import React, { createContext, useContext, useState, useEffect } from 'react';
import { User, AdminPermission } from '../lib/types';
import {
  getCurrentUser,
  logoutUser as apiLogout,
  deleteMyAccount as apiDeleteMyAccount,
  getAuthToken,
  setAuthToken,
} from '../lib/api';

interface AuthContextType {
  user: User | null;
  token: string | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  isAdmin: boolean;
  isSuperAdmin: boolean;
  hasPermission: (perm: AdminPermission | string) => boolean;
  setAuthSession: (user: User, token: string) => void;
  updateUserContext: (user: User) => void;
  refreshUser: () => Promise<void>;
  logout: () => Promise<void>;
  deleteAccount: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(getAuthToken());
  const [isLoading, setIsLoading] = useState<boolean>(true);

  const refreshUser = async () => {
    const storedToken = getAuthToken();
    if (!storedToken) {
      setUser(null);
      setIsLoading(false);
      return;
    }
    try {
      const u = await getCurrentUser();
      setUser(u);
      setToken(storedToken);
    } catch {
      setUser(null);
      setToken(null);
      setAuthToken(null);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    refreshUser();
  }, []);

  const setAuthSession = (newUser: User, newToken: string) => {
    setAuthToken(newToken);
    setUser(newUser);
    setToken(newToken);
  };

  const updateUserContext = (updatedUser: User) => {
    setUser(updatedUser);
  };

  const logout = async () => {
    await apiLogout();
    setUser(null);
    setToken(null);
  };

  const deleteAccount = async () => {
    await apiDeleteMyAccount();
    setUser(null);
    setToken(null);
  };

  const isAuthenticated = Boolean(user && token);
  const isAdmin = Boolean(user && (user.role === 'admin' || user.role === 'super_admin'));
  const isSuperAdmin = Boolean(user && user.role === 'super_admin');

  const hasPermission = (perm: AdminPermission | string): boolean => {
    if (!user) return false;
    if (user.role === 'super_admin') return true;
    if (user.role === 'admin') {
      return Boolean(user.permissions && user.permissions.includes(perm));
    }
    return false;
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isLoading,
        isAuthenticated,
        isAdmin,
        isSuperAdmin,
        hasPermission,
        setAuthSession,
        updateUserContext,
        refreshUser,
        logout,
        deleteAccount,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
