import { Link, useLocation } from 'react-router-dom';
import { ArrowLeft, FileText } from 'lucide-react';

export default function Footer() {
  const { pathname } = useLocation();
  if (pathname !== '/' && pathname !== '/terms') return null;
  const onTerms = pathname === '/terms';
  return (
    <footer className="mx-auto flex w-full max-w-6xl flex-col items-center justify-between gap-3 border-t border-line px-4 py-6 sm:flex-row sm:px-6 lg:px-8">
      <p className="text-xs text-muted">TrustPack · Open-source package integrity analyzer</p>
      {onTerms ? (
        <Link to="/" className="btn">
          <ArrowLeft className="h-4 w-4" aria-hidden />Back to landing page
        </Link>
      ) : (
        <Link to="/terms" className="btn">
          <FileText className="h-4 w-4" aria-hidden />Terms and conditions
        </Link>
      )}
    </footer>
  );
}
