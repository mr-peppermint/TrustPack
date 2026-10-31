import { useCallback, useEffect, useState } from 'react';
import { getAnalysisHistory, getAnalysisResult, startAnalysis } from '../services/analysisService';
import type { AnalysisRequest } from '../types/analysis';

function useAsync<T>(load: () => Promise<T>, deps: unknown[]) {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tick, setTick] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    load()
      .then((d) => !cancelled && setData(d))
      .catch((e: Error) => !cancelled && setError(e.message || 'Something went wrong.'))
      .finally(() => !cancelled && setLoading(false));
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);

  const reload = useCallback(() => setTick((t) => t + 1), []);
  return { data, loading, error, reload };
}

export const useAnalysisHistory = () => useAsync(getAnalysisHistory, []);
export const useAnalysisResult = (id: string | undefined) => useAsync(() => getAnalysisResult(id ?? ''), [id]);

export function useStartAnalysis() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const start = async (req: AnalysisRequest) => {
    setLoading(true);
    setError(null);
    try {
      return await startAnalysis(req);
    } catch (e) {
      setError((e as Error).message || 'The analysis could not be started.');
      return null;
    } finally {
      setLoading(false);
    }
  };
  return { start, loading, error };
}
