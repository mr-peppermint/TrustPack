import { Loader2 } from 'lucide-react';

interface ProgressBarProps {
  percent: number;
  label: string;
  stage?: string;
  showPercent?: boolean;
}

/** Determinate progress bar used while the backend boots and while a package is analysed. */
export default function ProgressBar({ percent = 0, label, stage, showPercent = true }: ProgressBarProps) {
  const clamped = Math.max(0, Math.min(100, percent));
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between text-sm">
        <span className="text-muted">{label}</span>
        {showPercent && <span className="font-mono text-xs">{clamped}%</span>}
      </div>
      {stage && <p className="text-xs text-muted">{stage}</p>}
      <div className="w-full bg-line rounded-full h-2.5 overflow-hidden border border-line/50">
        <div className="h-full bg-accent rounded-full transition-all duration-500" style={{ width: `${clamped}%` }} />
      </div>
      {clamped < 100 && (
        <Loader2 className="h-4 w-4 mx-auto mt-2 text-muted animate-spin" aria-hidden />
      )}
    </div>
  );
}
