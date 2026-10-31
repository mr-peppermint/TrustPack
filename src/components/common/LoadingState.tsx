import { Loader2 } from 'lucide-react';

export default function LoadingState({ label = 'Loading…' }: { label?: string }) {
  return (
    <div role="status" className="card flex items-center justify-center gap-3 px-4 py-12 text-sm text-muted">
      <Loader2 className="h-5 w-5 animate-spin" aria-hidden />
      {label}
    </div>
  );
}
