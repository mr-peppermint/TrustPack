import type { LucideIcon } from 'lucide-react';
import { useCountUp } from '../../hooks/useCountUp';
import { after } from '../../lib/motion';

const TONES = {
  default: 'bg-accent/10 text-accent',
  ok: 'bg-ok/10 text-ok',
  warn: 'bg-warn/10 text-warn',
  risk: 'bg-risk/10 text-risk',
};

interface Props { label: string; value: number | string; icon: LucideIcon; tone?: keyof typeof TONES; delay?: number }

export default function StatCard({ label, value, icon: Icon, tone = 'default', delay = 0 }: Props) {
  const counted = useCountUp(typeof value === 'number' ? value : 0);
  return (
    <div className="card card-hover flex animate-rise items-center gap-4 p-4" style={after(delay)}>
      <span className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg ${TONES[tone]}`}>
        <Icon className="h-5 w-5" aria-hidden />
      </span>
      <div>
        <p className="text-2xl font-semibold leading-none tabular-nums">{typeof value === 'number' ? counted : value}</p>
        <p className="mt-1.5 text-sm text-muted">{label}</p>
      </div>
    </div>
  );
}
