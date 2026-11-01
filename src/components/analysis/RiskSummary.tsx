import { useState } from 'react';
import { ChevronRight } from 'lucide-react';
import StatusBadge from '../common/StatusBadge';
import type { RiskAssessment, RiskLevel } from '../../types/analysis';

const BAR = { verified: 'bg-ok', warning: 'bg-warn', high_risk: 'bg-risk' };
const DOT: Record<RiskLevel, string> = { none: 'bg-muted/40', low: 'bg-ok', medium: 'bg-warn', high: 'bg-risk' };

export default function RiskSummary({ risk, explanation }: { risk: RiskAssessment; explanation: string }) {
  const [detailsOpen, setDetailsOpen] = useState(false);
  const hasElaboration = risk.findings.some((f) => f.explanation || f.recommendation);

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
          <div className="mb-2 flex items-center justify-between gap-3">
            <h3 className="text-sm font-medium">Key findings</h3>
            {hasElaboration && (
              <button
                type="button"
                aria-expanded={detailsOpen}
                onClick={() => setDetailsOpen((v) => !v)}
                className="flex items-center gap-1 rounded text-xs font-medium text-accent hover:underline"
              >
                {detailsOpen ? 'Hide why it matters' : 'Why it matters'}
                <ChevronRight className={`h-3.5 w-3.5 shrink-0 transition-transform ${detailsOpen ? 'rotate-90' : ''}`} aria-hidden />
              </button>
            )}
          </div>
          <ul className="space-y-2 text-sm text-muted">
            {risk.findings.map((f, i) => (
              <li key={i}>
                <div className="flex items-start gap-2.5">
                  <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${DOT[f.risk]}`} aria-hidden />
                  <span>{f.summary}</span>
                </div>
                {(f.explanation || f.recommendation) && (
                  <div className={`grid overflow-hidden pl-[1.125rem] transition-[grid-template-rows] duration-300 ease-in-out ${detailsOpen ? 'grid-rows-[1fr]' : 'grid-rows-[0fr]'}`}>
                    <div className="overflow-hidden">
                      <div className="ml-[0.125rem] mt-1.5 space-y-1 border-l-2 border-line pl-3 text-xs leading-relaxed text-muted">
                        {f.explanation && <p><span className="font-medium text-fg/80">Why it matters: </span>{f.explanation}</p>}
                        {f.recommendation && <p><span className="font-medium text-fg/80">Recommended: </span>{f.recommendation}</p>}
                      </div>
                    </div>
                  </div>
                )}
              </li>
            ))}
          </ul>
        </div>
      </div>
    </section>
  );
}
