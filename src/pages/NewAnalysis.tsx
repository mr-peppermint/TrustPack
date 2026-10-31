import { useNavigate } from 'react-router-dom';
import AnalysisForm from '../components/analysis/AnalysisForm';
import LoadingState from '../components/common/LoadingState';
import ErrorState from '../components/common/ErrorState';
import SampleDataNotice from '../components/common/SampleDataNotice';
import { useStartAnalysis } from '../hooks/useAnalysis';
import type { AnalysisRequest } from '../types/analysis';

export default function NewAnalysis() {
  const navigate = useNavigate();
  const { start, loading, error } = useStartAnalysis();

  const handleSubmit = async (req: AnalysisRequest) => {
    const res = await start(req);
    if (res) navigate(`/analysis/${res.id}`);
  };

  return (
    <div className="max-w-2xl space-y-5">
      <div>
        <h2 className="font-display text-2xl font-semibold tracking-tight">Analyze a package</h2>
        <p className="mt-1 text-sm text-muted">Enter a published npm or PyPI package and its source repository to check for unexpected differences.</p>
      </div>
      <SampleDataNotice />
      <AnalysisForm onSubmit={handleSubmit} loading={loading} />
      {loading && <LoadingState label="Comparing the published package with the repository…" />}
      {error && <ErrorState title="Analysis failed" message={error} />}
    </div>
  );
}
