import StatusBadge from '../common/StatusBadge';
import type { RiskAssessment } from '../../types/analysis';

const BAR = { verified: 'bg-ok', warning: 'bg-warn', high_risk: 'bg-risk' };

export default function RiskSummary({ risk, explanation }: { risk: RiskAssessment; explanation: string }) {
  return (
    <section className="card overflow-hidden" aria-label="Risk summary">
      <div className={`h-1.5 ${BAR[risk.status]}`} />
      <div className="space-y-5 p-5 sm:p-6">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <StatusBadge status={risk.status} size="lg" />
          <p className="text-sm text-muted">Risk score <span className="font-mono text-fg">{risk.score}</span> / 100</p>
        </div>
        <p className="max-w-prose leading-relaxed">{explanation}</p>
        <div>
          <h3 className="mb-2 text-sm font-medium">Key findings</h3>
          <ul className="list-disc space-y-1.5 pl-5 text-sm text-muted">
            {risk.findings.map((x) => <li key={x}>{x}</li>)}
          </ul>
        </div>
      </div>
    </section>
  );
}
