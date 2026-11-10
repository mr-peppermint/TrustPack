import { useEffect, useState } from 'react';
import { health, startupProgress } from '../services/analysisService';
import type { StartupProgress } from '../types/analysis';

export interface StartupStatus {
  ready: boolean;
  checking: boolean;
  progress: StartupProgress | null;
}

const POLL_INTERVAL = 1000;

/** Waits for the backend to become reachable, reporting boot progress along the way.

While the backend is offline or still starting up the frontend polls
``/api/startup-progress`` and returns a determinate progress bar's worth of data.
Once the backend reports ready, callers can proceed with an analysis.
*/
export function useStartupStatus(): StartupStatus {
  const [ready, setReady] = useState(false);
  const [checking, setChecking] = useState(true);
  const [progress, setProgress] = useState<StartupProgress | null>(null);

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;

    const check = async () => {
      try {
        const healthStatus = await health();
        if (healthStatus.status === "ok") {
          if (!cancelled) {
            setReady(true);
            setChecking(false);
            setProgress({ phase: "ready", percent: 100, message: "Ready", ready: true });
          }
          return;
        }
      } catch {
        // Backend unreachable (offline or still booting) — fall through to the startup-progress poll.
      }

      try {
        const sp = await startupProgress();
        if (!cancelled) setProgress(sp);
        if (sp.ready) {
          setReady(true);
          setChecking(false);
        }
      } catch {
        // Startup-progress endpoint not available yet; keep polling.
      }
    };

    check();
    timer = setInterval(check, POLL_INTERVAL);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, []);

  return { ready, checking, progress };
}
