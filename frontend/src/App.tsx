import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import { ScanProvider } from './context/ScanContext';
import { Navbar } from './components/Navbar';
import { Footer } from './components/Footer';
import { ToastContainer } from './components/ToastContainer';
import { ProtectedRoute } from './components/ProtectedRoute';

import { Dashboard } from './pages/Dashboard';
import { LinkTelegram } from './pages/LinkTelegram';
import { RepoCheck } from './pages/RepoCheck';
import { NetworkCheck } from './pages/NetworkCheck';
import { Report } from './pages/Report';
import { Login } from './pages/Login';
import { Register } from './pages/Register';
import { Privacy } from './pages/Privacy';
import { AdminDashboard } from './pages/AdminDashboard';
import { NotFound } from './pages/NotFound';

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <ScanProvider>
        <BrowserRouter>
          <div className="min-h-screen flex flex-col bg-[#0B1220] bg-cyber-gradient text-slate-100 selection:bg-cyan-500/30 selection:text-cyan-200">
            {/* Top Sticky Navigation */}
            <Navbar />

            {/* Main Page Area */}
            <main className="flex-1 w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 md:py-10">
              <Routes>
                {/* Public Auth & Info Routes */}
                <Route path="/login" element={<Login />} />
                <Route path="/register" element={<Register />} />
                <Route path="/privacy" element={<Privacy />} />

                {/* Protected User Routes */}
                <Route
                  path="/"
                  element={
                    <ProtectedRoute>
                      <Dashboard />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/dashboard"
                  element={
                    <ProtectedRoute>
                      <Dashboard />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/telegram"
                  element={
                    <ProtectedRoute>
                      <LinkTelegram />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/repo"
                  element={
                    <ProtectedRoute>
                      <RepoCheck />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/network"
                  element={
                    <ProtectedRoute>
                      <NetworkCheck />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/report"
                  element={
                    <ProtectedRoute>
                      <Report />
                    </ProtectedRoute>
                  }
                />

                {/* Guarded Admin Route */}
                <Route
                  path="/admin"
                  element={
                    <ProtectedRoute adminOnly>
                      <AdminDashboard />
                    </ProtectedRoute>
                  }
                />

                {/* Fallback */}
                <Route path="*" element={<NotFound />} />
              </Routes>
            </main>

            {/* Toast Notification Container */}
            <ToastContainer />

            {/* Privacy-Centric Footer */}
            <Footer />
          </div>
        </BrowserRouter>
      </ScanProvider>
    </AuthProvider>
  );
};

export default App;
