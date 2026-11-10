import type {
  AnalysisProgress,
  AnalysisRequest,
  AnalysisResult,
  AnalysisSummary,
  RepositoryDetection,
  StartupProgress,
} from '../types/analysis';

const env = import.meta.env;

type ApiErrorPayload = { error?: { code?: string; message?: string; details?: unknown }; detail?: unknown };

export function analysisErrorMessage(code?: string | null, message?: string | null): string {
  const serverMessage = message?.trim();
  switch (code) {
    case 'package_not_found': return `${serverMessage || 'That package name was not found in the selected registry.'} Check that the selected ecosystem matches the package type; each ecosystem uses a different registry.`;
    case 'version_not_found': return serverMessage || 'That version was not found for this package. Enter an exact published version.';
    case 'invalid_package_name': return serverMessage || 'The package name is invalid for the selected ecosystem.';
    case 'invalid_version': return serverMessage || 'The version format is invalid. Enter an exact published version.';
    case 'unsupported_ecosystem': return serverMessage || 'Choose one of the supported package ecosystems.';
    case 'unsupported_host': return serverMessage || 'The repository link is not supported. Use a GitHub repository URL.';
    case 'upstream_rate_limited': return serverMessage || 'The package registry or source host is rate limiting requests. Please try again shortly.';
    case 'upstream_timeout':
    case 'analysis_timeout': return serverMessage || 'The analysis took too long. Please try again.';
    case 'registry_error': return serverMessage || 'The package registry could not complete the lookup. Please try again shortly.';
    case 'download_error': return serverMessage || 'The package could not be downloaded from its registry.';
    case 'validation_error': return validationMessage(serverMessage);
    default: return serverMessage || 'The analysis could not be completed. Please check the package details and try again.';
  }
}

function validationMessage(message?: string): string {
  if (message && message !== 'Invalid request payload') return message;
  return 'Some package details are invalid. Check the package name, exact version, and GitHub repository link.';
}

function errorFromPayload(payload: ApiErrorPayload, status: number): Error {
  const detail = payload.detail && typeof payload.detail === 'object'
    ? payload.detail as { code?: string; message?: string }
    : undefined;
  const code = payload.error?.code ?? detail?.code;
  const message = payload.error?.message ?? detail?.message;
  if (code || message) return new Error(analysisErrorMessage(code, message));
  if (typeof payload.detail === 'string') return new Error(payload.detail);
  return new Error(`The server returned an error (${status}).`);
}

export const apiConfig = {
  baseUrl: (env.VITE_API_BASE_URL as string | undefined) ?? '',
  endpoints: {
    health: (env.VITE_ENDPOINT_HEALTH as string | undefined) ?? '/api/health',
    startAnalysis: (env.VITE_ENDPOINT_START_ANALYSIS as string | undefined) ?? '/analyses',
    getResult: (env.VITE_ENDPOINT_GET_RESULT as string | undefined) ?? '/analyses/{id}',
    getProgress: (env.VITE_ENDPOINT_GET_PROGRESS as string | undefined) ?? '/analyses/{id}/progress',
    history: (env.VITE_ENDPOINT_HISTORY as string | undefined) ?? '/analyses',
    startupProgress: (env.VITE_ENDPOINT_STARTUP_PROGRESS as string | undefined) ?? '/api/startup-progress',
    detectRepository: (env.VITE_ENDPOINT_DETECT_REPOSITORY as string | undefined) ?? '/api/detect-repository',
  },
};

async function http<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${apiConfig.baseUrl}${path}`, { headers: { 'Content-Type': 'application/json' }, ...init });
  if (!res.ok) {
    let payload: ApiErrorPayload = {};
    try { payload = (await res.json()) as ApiErrorPayload; } catch { /* non-JSON server response */ }
    throw errorFromPayload(payload, res.status);
  }
  return (await res.json()) as T;
}

/** Checks whether the backend is reachable and ready. */
export function health(): Promise<{ status: string }> {
  return http(apiConfig.endpoints.health);
}

/** Returns the backend's boot progress (phase / percent / ready). */
export function startupProgress(): Promise<StartupProgress> {
  return http(apiConfig.endpoints.startupProgress);
}

export function detectRepository(url: string): Promise<RepositoryDetection> {
  return http(`${apiConfig.endpoints.detectRepository}?url=${encodeURIComponent(url)}`);
}

/** Returns the in-flight progress of an analysis started via POST /analyses. */
export function analysisProgress(id: string): Promise<AnalysisProgress> {
  return http(apiConfig.endpoints.getProgress.replace('{id}', encodeURIComponent(id)));
}

/** Starts an analysis. The backend responds with the new analysis id immediately and
 *  runs the analysis in the background; poll `analysisProgress` for progress. */
export function startAnalysis(req: AnalysisRequest): Promise<{ id: string }> {
  return http(apiConfig.endpoints.startAnalysis, { method: 'POST', body: JSON.stringify(req) });
}

export function getAnalysisResult(id: string): Promise<AnalysisResult> {
  return http(apiConfig.endpoints.getResult.replace('{id}', encodeURIComponent(id)));
}

export function getAnalysisHistory(): Promise<AnalysisSummary[]> {
  return http(apiConfig.endpoints.history);
}
