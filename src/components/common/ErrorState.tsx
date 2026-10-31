import { AlertCircle } from 'lucide-react';

interface Props { title?: string; message: string; onRetry?: () => void }

export default function ErrorState({ title = 'Something went wrong', message, onRetry }: Props) {
  return (
    <div role="alert" className="card flex flex-col items-center border-risk/30 px-4 py-10 text-center">
      <AlertCircle className="mb-3 h-8 w-8 text-risk" aria-hidden />
      <h3 className="font-medium">{title}</h3>
      <p className="mt-1 max-w-sm text-sm text-muted">{message}</p>
      {onRetry && <button type="button" className="btn mt-4" onClick={onRetry}>Try again</button>}
    </div>
  );
}
