import type { ReactNode } from 'react';
import { Link, useParams } from 'react-router-dom';
import { ArrowLeft, CheckCircle2, ExternalLink, FileCheck, FileMinus, FilePen, FilePlus, XCircle } from 'lucide-react';
import RiskSummary from '../components/analysis/RiskSummary';
import FileChangesTable from '../components/analysis/FileChangesTable';
import StatCard from '../components/dashboard/StatCard';
import LoadingState from '../components/common/LoadingState';
import ErrorState from '../components/common/ErrorState';
import { useAnalysisResult } from '../hooks/useAnalysis';
import { formatDateTime } from '../lib/format';

function Check({ ok, label }: { ok: boolean; label: string }) {
  const Icon = ok ? CheckCircle2 : XCircle;
  return <span className={`inline-flex items-center gap-1.5 ${ok ? 'text-ok' : 'text-risk'}`}><Icon className="h-4 w-4" aria-hidden />{label}</span>;
}

export default function AnalysisResults() {
  const { id } = useParams();
  const { data, loading, error, reload } = useAnalysisResult(id);

  if (loading) return <LoadingState label="Loading results…" />;
  if (error || !data) return <ErrorState title="Results unavailable" message={error ?? 'No data was returned.'} onRetry={reload} />;

  const { package: pkg, comparison: c, provenance: p } = data;
  const rows: [string, ReactNode][] = [
    ['Source repository', <a key="r" href={p.sourceRepo} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 break-all text-accent hover:underline">{p.sourceRepo}<ExternalLink className="h-3.5 w-3.5 shrink-0" aria-hidden /></a>],
    ['Source commit', p.sourceCommit ? <span className="font-mono">{p.sourceCommit}</span> : <span className="text-risk">Not matched</span>],
    ['Published', formatDateTime(p.publishedAt)],
    ['Publisher', p.publisher],
    ['Registry checksum', <span key="c" className="break-all font-mono text-xs">{p.registryChecksum}</span>],
    ['Signature', <Check key="s" ok={p.signatureVerified} label={p.signatureVerified ? 'Verified' : 'Not verified'} />],
    ['Build provenance', <Check key="b" ok={p.buildProvenance} label={p.buildProvenance ? 'Available' : 'Not available'} />],
    ['Attestation', p.attestation],
  ];

  return (
    <div className="space-y-6">
      <div>
        <Link to="/history" className="mb-3 inline-flex items-center gap-1.5 text-sm text-muted hover:text-fg"><ArrowLeft className="h-4 w-4" aria-hidden />Analysis History</Link>
        <h2 className="flex flex-wrap items-baseline gap-x-3 text-xl font-semibold">
          <span className="font-mono">{pkg.name}</span>
          <span className="font-mono text-base font-normal text-muted">{pkg.version}</span>
          <span className="rounded-full border border-line bg-sunken px-2 py-0.5 text-xs font-normal text-muted">{pkg.ecosystem}</span>
        </h2>
      </div>

      <RiskSummary risk={data.risk} explanation={data.aiExplanation} />

      <section className="space-y-3">
        <h3 className="font-display text-xl font-semibold tracking-tight">Comparison summary</h3>
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <StatCard label="Added files" value={c.added} icon={FilePlus} tone={c.added ? 'warn' : 'default'} />
          <StatCard label="Removed files" value={c.removed} icon={FileMinus} />
          <StatCard label="Modified files" value={c.modified} icon={FilePen} />
          <StatCard label="Unchanged files" value={c.unchanged} icon={FileCheck} tone="ok" />
        </div>
      </section>

      <section className="space-y-3">
        <h3 className="font-display text-xl font-semibold tracking-tight">File differences</h3>
        <FileChangesTable files={data.files} />
        <p className="text-xs text-muted">Select a file to see details. Unchanged files beyond those listed are counted above.</p>
      </section>

      <section className="space-y-3">
        <h3 className="font-display text-xl font-semibold tracking-tight">Provenance and verification</h3>
        <dl className="card divide-y divide-line text-sm">
          {rows.map(([k, v]) => (
            <div key={k} className="grid gap-1 px-4 py-3 sm:grid-cols-[11rem_1fr] sm:gap-4">
              <dt className="text-muted">{k}</dt>
              <dd>{v}</dd>
            </div>
          ))}
        </dl>
      </section>
    </div>
  );
}
