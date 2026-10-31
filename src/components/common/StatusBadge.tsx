import { AlertTriangle, CheckCircle2, ShieldAlert } from 'lucide-react';
import type { RiskLevel, RiskStatus } from '../../types/analysis';

const MAP = {
  verified: { label: 'Verified', Icon: CheckCircle2, cls: 'border-ok/30 bg-ok/10 text-ok' },
  warning: { label: 'Warning', Icon: AlertTriangle, cls: 'border-warn/30 bg-warn/10 text-warn' },
  high_risk: { label: 'High risk', Icon: ShieldAlert, cls: 'border-risk/30 bg-risk/10 text-risk' },
} as const;

export default function StatusBadge({ status, size = 'sm' }: { status: RiskStatus; size?: 'sm' | 'lg' }) {
  const { label, Icon, cls } = MAP[status];
  const dims = size === 'lg' ? 'gap-2 px-3 py-1.5 text-base' : 'gap-1.5 px-2 py-0.5 text-xs';
  return (
    <span className={`inline-flex items-center rounded-full border font-medium ${dims} ${cls}`}>
      <Icon className={size === 'lg' ? 'h-5 w-5' : 'h-3.5 w-3.5'} aria-hidden />
      {label}
    </span>
  );
}

const LEVELS: Record<RiskLevel, { label: string; dot: string }> = {
  none: { label: 'None', dot: 'bg-muted/40' },
  low: { label: 'Low', dot: 'bg-ok' },
  medium: { label: 'Medium', dot: 'bg-warn' },
  high: { label: 'High', dot: 'bg-risk' },
};

export function RiskDot({ level }: { level: RiskLevel }) {
  const { label, dot } = LEVELS[level];
  return (
    <span className="inline-flex items-center gap-2 text-sm">
      <span className={`h-2 w-2 rounded-full ${dot}`} aria-hidden />
      {label}
    </span>
  );
}
