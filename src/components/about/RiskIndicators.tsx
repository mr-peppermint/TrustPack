import { Info } from 'lucide-react';
import SectionHeading from './SectionHeading';
import StatusBadge from '../common/StatusBadge';
import type { RiskStatus } from '../../types/analysis';

const INDICATORS: { status: RiskStatus; text: string }[] = [
  { status: 'verified', text: 'No concerning differences were identified by the implemented checks.' },
  { status: 'warning', text: 'Differences or missing verification evidence require further investigation.' },
  { status: 'high_risk', text: 'Significant suspicious differences or concerning evidence were detected.' },
];

export default function RiskIndicators() {
  return (
    <section className="space-y-6">
      <SectionHeading eyebrow="Understanding the results" title="Three risk indicators" />
      <ul className="card divide-y divide-line">
        {INDICATORS.map(({ status, text }) => (
          <li key={status} className="flex flex-col gap-2 px-4 py-4 sm:flex-row sm:items-center sm:gap-6">
            <div className="sm:w-32 sm:shrink-0"><StatusBadge status={status} /></div>
            <p className="text-sm leading-relaxed">{text}</p>
          </li>
        ))}
      </ul>
      <p className="flex items-start gap-2 text-sm text-muted">
        <Info className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
        These indicators describe analysis findings. They are not a guarantee that a package is safe or malicious.
      </p>
    </section>
  );
}
