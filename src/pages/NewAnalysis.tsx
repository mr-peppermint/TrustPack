import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import AnalysisForm from '../components/analysis/AnalysisForm';
import ErrorState from '../components/common/ErrorState';
import ProgressBar from '../components/common/ProgressBar';
import { useStartAnalysis, useAnalysisProgress } from '../hooks/useAnalysis';
import { useStartupStatus } from '../hooks/useStartupStatus';
import type { AnalysisRequest } from '../types/analysis';

export default function NewAnalysis() {
  const navigate = useNavigate();

  // Backend boot progress (non-blocking: the form still loads below).
  const { ready, checking, progress: startupProgress } = useStartupStatus();

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
          Enter a published npm or PyPI package and its source repository to check for unexpected differences.
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
            <p className="mt-2 text-xs text-muted">
              The TrustPack backend is starting up. The form below is disabled until it is ready.
            </p>
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
