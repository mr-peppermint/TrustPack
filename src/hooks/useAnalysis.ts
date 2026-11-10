import { useCallback, useEffect, useState } from 'react';
import { analysisErrorMessage, analysisProgress, getAnalysisHistory, getAnalysisResult, startAnalysis } from '../services/analysisService';
import type { AnalysisProgress, AnalysisRequest } from '../types/analysis';

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
      // The backend starts the analysis in the background and returns the id immediately;
      // callers poll useAnalysisProgress(id) for real progress.
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

/** Polls the backend for the progress of an in-flight analysis. */
export function useAnalysisProgress(analysisId: string | null) {
  const [progress, setProgress] = useState<AnalysisProgress | null>(null);
  const [status, setStatus] = useState<"idle" | "running" | "done" | "failed">("idle");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!analysisId) {
      setProgress(null);
      setStatus("idle");
      setError(null);
      return;
    }

    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const poll = async () => {
      try {
        const p = await analysisProgress(analysisId);
        if (cancelled) return;
        setProgress(p);
        if (p.status === "done") {
          setStatus("done");
        } else if (p.status === "failed") {
          setStatus("failed");
          setError(analysisErrorMessage(p.errorCode, p.error));
        } else {
          // Treat the backend's initial queued state as active so the progress view
          // is shown immediately while the worker picks up the job.
          setStatus("running");
          timer = setTimeout(poll, 1000);
        }
      } catch (e) {
        if (cancelled) return;
        setError((e as Error).message || "Could not read analysis progress.");
        setStatus("failed");
      }
    };

    poll();
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [analysisId]);

  return { progress, status, error };
}
