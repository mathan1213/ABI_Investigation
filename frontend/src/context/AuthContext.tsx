import React, { createContext, useContext, useState, useEffect } from 'react';
import { User } from '../lib/types';
import {
  getCurrentUser,
  loginUser,
  registerUser,
  logoutUser as apiLogout,
  deleteMyAccount as apiDeleteMyAccount,
  getAuthToken,
} from '../lib/api';

interface AuthContextType {
  user: User | null;
  token: string | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  isAdmin: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (name: string, email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  deleteAccount: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(getAuthToken());
  const [isLoading, setIsLoading] = useState<boolean>(true);

  useEffect(() => {
    async function loadUser() {
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
      } finally {
        setIsLoading(false);
      }
    }
    loadUser();
  }, []);

  const login = async (email: string, password: string) => {
    const res = await loginUser(email, password);
    setUser(res.user);
    setToken(res.token);
  };

  const register = async (name: string, email: string, password: string) => {
    const res = await registerUser(name, email, password);
    setUser(res.user);
    setToken(res.token);
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
  const isAdmin = Boolean(user?.role === 'admin');

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isLoading,
        isAuthenticated,
        isAdmin,
        login,
        register,
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
