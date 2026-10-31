import { Info } from 'lucide-react';
import { apiConfig } from '../../services/analysisService';

/** Shown only while the app runs on built-in sample data, so nothing is mistaken for a real analysis. */
export default function SampleDataNotice() {
  if (!apiConfig.useMock) return null;
  return (
    <p className="flex items-start gap-2 rounded-lg border border-line bg-sunken px-3 py-2 text-xs text-muted">
      <Info className="mt-px h-3.5 w-3.5 shrink-0" aria-hidden />
      The analyses shown here are sample data for interface preview. They are not results from real packages.
    </p>
  );
}
