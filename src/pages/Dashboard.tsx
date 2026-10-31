import { Link } from 'react-router-dom';
import { AlertTriangle, ArrowRight, BarChart3, CheckCircle2, Plus } from 'lucide-react';
import StatCard from '../components/dashboard/StatCard';
import AnalysisTable from '../components/analysis/AnalysisTable';
import LoadingState from '../components/common/LoadingState';
import ErrorState from '../components/common/ErrorState';
import EmptyState from '../components/common/EmptyState';
import SampleDataNotice from '../components/common/SampleDataNotice';
import { useAnalysisHistory } from '../hooks/useAnalysis';

export default function Dashboard() {
  const { data, loading, error, reload } = useAnalysisHistory();

  if (loading) return <LoadingState label="Loading overview…" />;
  if (error || !data) return <ErrorState message={error ?? 'No data was returned.'} onRetry={reload} />;

  const verified = data.filter((a) => a.status === 'verified').length;

  return (
    <div className="space-y-6">
      <section className="card relative overflow-hidden p-6 sm:p-8">
        <div className="pointer-events-none absolute -right-20 -top-20 h-64 w-64 rounded-full bg-accent/10 blur-2xl" aria-hidden />
        <div className="relative max-w-2xl">
          <p className="eyebrow">Software supply-chain integrity</p>
          <h2 className="mt-2 font-display text-3xl font-semibold tracking-tight sm:text-4xl">Does the package match its source?</h2>
          <p className="mt-3 leading-relaxed text-muted">
            TrustPack helps developers verify the integrity of published npm and PyPI packages against their corresponding source repositories.
          </p>
          <div className="mt-6 flex flex-wrap gap-3">
            <Link to="/new" className="btn btn-primary"><Plus className="h-4 w-4" aria-hidden />New Analysis</Link>
            <Link to="/" className="btn">About TrustPack<ArrowRight className="h-4 w-4" aria-hidden /></Link>
          </div>
        </div>
      </section>

      <SampleDataNotice />

      <div className="grid gap-4 sm:grid-cols-3">
        <StatCard label="Total analyses" value={data.length} icon={BarChart3} />
        <StatCard label="Verified packages" value={verified} icon={CheckCircle2} tone="ok" delay={0.1} />
        <StatCard label="Require attention" value={data.length - verified} icon={AlertTriangle} tone="warn" delay={0.2} />
      </div>

      <section className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="font-display text-xl font-semibold tracking-tight">Recent analyses</h2>
          <Link to="/history" className="text-sm text-accent hover:underline">View all</Link>
        </div>
        {data.length === 0 ? (
          <EmptyState title="No analyses yet" description="Run your first analysis to see results here." action={<Link to="/new" className="btn btn-primary">New Analysis</Link>} />
        ) : (
          <AnalysisTable items={data.slice(0, 5)} />
        )}
      </section>
    </div>
  );
}
