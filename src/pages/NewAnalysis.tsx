import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import AnalysisForm from '../components/analysis/AnalysisForm';
import ErrorState from '../components/common/ErrorState';
import ProgressBar from '../components/common/ProgressBar';
import { apiConfig, health } from '../services/analysisService';
import { useStartAnalysis, useAnalysisProgress } from '../hooks/useAnalysis';
import { useStartupStatus } from '../hooks/useStartupStatus';
import type { AnalysisRequest } from '../types/analysis';

export default function NewAnalysis() {
  const navigate = useNavigate();

  // Backend boot progress (non-blocking: the form still loads below).
  const { ready, checking, progress: startupProgress } = useStartupStatus();
  const [wakingBackend, setWakingBackend] = useState(false);
  const [wakeMessage, setWakeMessage] = useState<string | null>(null);

  const healthUrl = new URL(
    apiConfig.endpoints.health,
    apiConfig.baseUrl || window.location.origin,
  ).toString();

  const wakeBackend = async () => {
    setWakingBackend(true);
    setWakeMessage(null);
    try {
      const result = await health();
      setWakeMessage(`Backend responded: ${result.status}. Startup progress will update automatically.`);
    } catch (error) {
      setWakeMessage(`${(error as Error).message || 'The request did not complete.'} The backend may still be starting; progress will keep updating.`);
    } finally {
      setWakingBackend(false);
    }
  };

  const { start, error: startError, loading: startLoading } = useStartAnalysis();
  const [analysisId, setAnalysisId] = useState<string | null>(null);
  const { progress: analysisProgress, status: analysisStatus, error: analysisError } = useAnalysisProgress(
    analysisId,
  );

  const handleSubmit = async (req: AnalysisRequest) => {
    setAnalysisId(null);
    const res = await start(req);
    if (res) setAnalysisId(res.id);
  };

  // Finished: navigate to the results page.
  useEffect(() => {
    if (analysisId && analysisStatus === "done") {
      navigate(`/analysis/${analysisId}`);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [analysisId, analysisStatus, navigate]);

  // Analysis in flight: replace the form with the real analysing progress bar.
  // The initial backend state is "queued"; the hook exposes it as running.
  if (analysisId && (analysisStatus === "running" || analysisStatus === "idle")) {
    return (
      <div className="max-w-2xl space-y-5">
        <div>
          <h2 className="font-display text-2xl font-semibold tracking-tight">Analyzing package</h2>
          <p className="mt-1 text-sm text-muted">
            TrustPack is downloading and comparing the package against its source repository.
          </p>
        </div>
        <ProgressBar
          percent={analysisProgress?.percent ?? 0}
          label={analysisProgress?.message ?? "Starting analysis…"}
          stage={analysisProgress?.stage}
        />
        <p className="text-xs text-muted">
          You will be taken to the results automatically when the analysis finishes.
        </p>
      </div>
    );
  }

  // Analysis failed: show the error with a retry option.
  if (analysisId && analysisStatus === "failed") {
    return (
      <div className="max-w-2xl space-y-5">
        <div>
          <h2 className="font-display text-2xl font-semibold tracking-tight">Analysis failed</h2>
        </div>
        <ErrorState
          title="Analysis failed"
          message={analysisError ?? "The analysis could not be completed."}
          onRetry={() => setAnalysisId(null)}
        />
      </div>
    );
  }

  return (
    <div className="max-w-2xl space-y-5">
      <div>
        <h2 className="font-display text-2xl font-semibold tracking-tight">Analyze a package</h2>
        <p className="mt-1 text-sm text-muted">
          Enter a package release or paste a GitHub repository or directory link to detect package manifests and compare a release with its source.
        </p>
      </div>

      {/* Startup progress banner: shown while the backend is offline or still booting. */}
      {!ready && (
        <div className="card border-line/50 p-4">
          <ProgressBar
            percent={startupProgress?.percent ?? 0}
            label={startupProgress?.message ?? (checking ? "Starting backend…" : "Waiting for backend…")}
            stage={startupProgress?.phase}
          />
          {!startupProgress?.ready && (
            <div className="mt-3 space-y-2">
              <p className="text-xs text-muted">
                The TrustPack backend is starting up. The form below is disabled until it is ready.
              </p>
              <div className="flex flex-wrap items-center gap-2">
                <button type="button" className="btn text-xs" onClick={wakeBackend} disabled={wakingBackend}>
                  {wakingBackend ? 'Sending request…' : 'Wake backend'}
                </button>
                <code className="break-all text-xs text-muted">GET {healthUrl}</code>
              </div>
              {wakeMessage && <p role="status" className="text-xs text-muted">{wakeMessage}</p>}
            </div>
          )}
        </div>
      )}

      <AnalysisForm
        onSubmit={handleSubmit}
        loading={!ready || startLoading}
      />
      {startError && <ErrorState title="Could not start analysis" message={startError} />}
    </div>
  );
}
