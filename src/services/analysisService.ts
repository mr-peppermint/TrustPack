import type { AnalysisRequest, AnalysisResult, AnalysisSummary } from '../types/analysis';

const env = import.meta.env;

export const apiConfig = {
  baseUrl: (env.VITE_API_BASE_URL as string | undefined) ?? '',
  endpoints: {
    startAnalysis: (env.VITE_ENDPOINT_START_ANALYSIS as string | undefined) ?? '/analyses',
    getResult: (env.VITE_ENDPOINT_GET_RESULT as string | undefined) ?? '/analyses/{id}',
    history: (env.VITE_ENDPOINT_HISTORY as string | undefined) ?? '/analyses',
  },
};

async function http<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${apiConfig.baseUrl}${path}`, { headers: { 'Content-Type': 'application/json' }, ...init });
  if (!res.ok) throw new Error(`The server returned an error (${res.status}).`);
  return (await res.json()) as T;
}

/** Starts an analysis. The backend should respond with the new analysis id. */
export function startAnalysis(req: AnalysisRequest): Promise<{ id: string }> {
  return http(apiConfig.endpoints.startAnalysis, { method: 'POST', body: JSON.stringify(req) });
}

export function getAnalysisResult(id: string): Promise<AnalysisResult> {
  return http(apiConfig.endpoints.getResult.replace('{id}', encodeURIComponent(id)));
}

export function getAnalysisHistory(): Promise<AnalysisSummary[]> {
  return http(apiConfig.endpoints.history);
}
