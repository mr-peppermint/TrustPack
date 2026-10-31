import type { ReactNode } from 'react';
import { Inbox } from 'lucide-react';

export default function EmptyState({ title, description, action }: { title: string; description?: string; action?: ReactNode }) {
  return (
    <div className="card flex flex-col items-center px-4 py-12 text-center">
      <Inbox className="mb-3 h-8 w-8 text-muted" aria-hidden />
      <h3 className="font-medium">{title}</h3>
      {description && <p className="mt-1 max-w-sm text-sm text-muted">{description}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}
