import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { Search } from 'lucide-react';
import AnalysisTable from '../components/analysis/AnalysisTable';
import LoadingState from '../components/common/LoadingState';
import ErrorState from '../components/common/ErrorState';
import EmptyState from '../components/common/EmptyState';
import { useAnalysisHistory } from '../hooks/useAnalysis';

export default function History() {
  const { data, loading, error, reload } = useAnalysisHistory();
  const [q, setQ] = useState('');
  const [eco, setEco] = useState('all');
  const [status, setStatus] = useState('all');

  const items = useMemo(
    () => (data ?? []).filter((a) =>
      a.package.name.toLowerCase().includes(q.trim().toLowerCase()) &&
      (eco === 'all' || a.package.ecosystem === eco) &&
      (status === 'all' || a.status === status)),
    [data, q, eco, status],
  );

  if (loading) return <LoadingState label="Loading history…" />;
  if (error || !data) return <ErrorState message={error ?? 'No data was returned.'} onRetry={reload} />;

  const clear = () => { setQ(''); setEco('all'); setStatus('all'); };

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-3 sm:flex-row">
        <div className="relative flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" aria-hidden />
          <input type="search" className="input pl-9" placeholder="Search by package name" aria-label="Search by package name" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <select className="input sm:w-40" aria-label="Filter by ecosystem" value={eco} onChange={(e) => setEco(e.target.value)}>
          <option value="all">All ecosystems</option>
          <option value="npm">npm</option>
          <option value="PyPI">PyPI</option>
          <option value="Maven Central">Maven Central</option>
          <option value="NuGet">NuGet</option>
          <option value="crates.io">crates.io</option>
          <option value="Go modules">Go modules</option>
          <option value="RubyGems">RubyGems</option>
          <option value="Packagist">Packagist</option>
          <option value="pub.dev">pub.dev</option>
          <option value="Hex">Hex</option>
          <option value="CocoaPods">CocoaPods</option>
          <option value="SwiftPM">SwiftPM</option>
          <option value="Conda">Conda</option>
          <option value="Linux">Linux</option>
          <option value="OCI">OCI</option>
        </select>
        <select className="input sm:w-40" aria-label="Filter by risk status" value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="all">All statuses</option>
          <option value="verified">Verified</option>
          <option value="warning">Warning</option>
          <option value="high_risk">High risk</option>
        </select>
      </div>

      {data.length === 0 ? (
        <EmptyState title="No analyses yet" description="Completed analyses will appear here." action={<Link to="/new" className="btn btn-primary">New Analysis</Link>} />
      ) : items.length === 0 ? (
        <EmptyState title="No matching analyses" description="Try a different search or clear the filters." action={<button type="button" className="btn" onClick={clear}>Clear filters</button>} />
      ) : (
        <AnalysisTable items={items} actionLabel="View results" />
      )}
    </div>
  );
}
