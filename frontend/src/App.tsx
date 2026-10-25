import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { ScanProvider } from './context/ScanContext';
import { Navbar } from './components/Navbar';
import { Footer } from './components/Footer';
import { ToastContainer } from './components/ToastContainer';
import { Dashboard } from './pages/Dashboard';
import { LinkTelegram } from './pages/LinkTelegram';
import { RepoCheck } from './pages/RepoCheck';
import { NetworkCheck } from './pages/NetworkCheck';
import { Report } from './pages/Report';
import { OwnerSetup } from './pages/OwnerSetup';
import { NotFound } from './pages/NotFound';

export const App: React.FC = () => {
  return (
    <ScanProvider>
      <BrowserRouter>
        <div className="min-h-screen flex flex-col bg-[#0B1220] bg-cyber-gradient text-slate-100 selection:bg-cyan-500/30 selection:text-cyan-200">
          {/* Top Sticky Navigation */}
          <Navbar />

          {/* Main Page Area */}
          <main className="flex-1 w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 md:py-10">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/telegram" element={<LinkTelegram />} />
              <Route path="/repo" element={<RepoCheck />} />
              <Route path="/network" element={<NetworkCheck />} />
              <Route path="/report" element={<Report />} />
              <Route path="/setup" element={<OwnerSetup />} />
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
  );
};

export default App;
