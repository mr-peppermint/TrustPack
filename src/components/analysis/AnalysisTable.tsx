import { Link } from 'react-router-dom';
import StatusBadge from '../common/StatusBadge';
import { formatDate } from '../../lib/format';
import type { AnalysisSummary } from '../../types/analysis';

interface Props { items: AnalysisSummary[]; actionLabel?: string }

export default function AnalysisTable({ items, actionLabel = 'View details' }: Props) {
  return (
    <div className="card overflow-x-auto">
      <table className="w-full min-w-[40rem] text-left text-sm">
        <thead className="bg-sunken/60 text-xs uppercase tracking-wide text-muted">
          <tr>
            {['Package', 'Ecosystem', 'Version', 'Risk status', 'Date'].map((h) => <th key={h} className="px-4 py-3 font-medium">{h}</th>)}
            <th className="px-4 py-3"><span className="sr-only">Action</span></th>
          </tr>
        </thead>
        <tbody>
          {items.map((a) => (
            <tr key={a.id} className="border-t border-line hover:bg-sunken/50">
              <td className="px-4 py-3 font-mono text-[13px]">{a.package.name}</td>
              <td className="px-4 py-3 text-muted">{a.package.ecosystem}</td>
              <td className="px-4 py-3 font-mono text-[13px] text-muted">{a.package.version}</td>
              <td className="px-4 py-3"><StatusBadge status={a.status} /></td>
              <td className="whitespace-nowrap px-4 py-3 text-muted">{formatDate(a.createdAt)}</td>
              <td className="px-4 py-3 text-right">
                <Link to={`/analysis/${a.id}`} className="whitespace-nowrap rounded font-medium text-accent hover:underline" aria-label={`${actionLabel}: ${a.package.name} ${a.package.version}`}>
                  {actionLabel}
                </Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
