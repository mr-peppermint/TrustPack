import { Link } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';
import Terms from '../components/about/Terms';

export default function TermsPage() {
  return (
    <div className="max-w-3xl space-y-6">
      <Link to="/" className="inline-flex items-center gap-1.5 text-sm text-muted hover:text-fg">
        <ArrowLeft className="h-4 w-4" aria-hidden />Back to About TrustPack
      </Link>
      <Terms />
    </div>
  );
}
