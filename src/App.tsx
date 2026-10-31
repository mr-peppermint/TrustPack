import { useEffect, useState } from 'react';
import { useLocation } from 'react-router-dom';
import Sidebar from './components/layout/Sidebar';
import Header from './components/layout/Header';
import AppRoutes from './routes/AppRoutes';
import PageBackdrop from './components/common/PageBackdrop';
import IntroSplash from './components/common/IntroSplash';

export default function App() {
  const [menuOpen, setMenuOpen] = useState(false);
  const { pathname } = useLocation();
  useEffect(() => setMenuOpen(false), [pathname]);

  return (
    <div className="relative isolate min-h-screen">
      <PageBackdrop />
      <IntroSplash />
      <Sidebar open={menuOpen} onClose={() => setMenuOpen(false)} />
      <div className="lg:pl-64">
        <Header onMenu={() => setMenuOpen(true)} />
        <main className="mx-auto w-full max-w-6xl px-4 py-8 sm:px-6 lg:px-8">
          <div key={pathname} className="animate-rise">
            <AppRoutes />
          </div>
        </main>
      </div>
    </div>
  );
}
