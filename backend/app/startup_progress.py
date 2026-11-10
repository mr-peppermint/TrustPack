"""Tracks the backend's boot progress so the frontend can show a startup bar.

The phases are intentionally coarse and deterministic: the frontend polls
``/api/startup-progress`` while the server appears offline or is still booting,
and renders a determinate progress bar until the backend reports ``ready``.
"""
import time
from typing import Any, Dict

_PHASES = [
    ("booting", 5, "Starting server…"),
    ("loading-config", 20, "Loading configuration…"),
    ("connecting-database", 50, "Opening history database…"),
    ("warming-cache", 80, "Warming analysis cache…"),
    ("ready", 100, "Ready"),
]


class StartupProgress:
    def __init__(self) -> None:
        self.started_at = time.time()
        self.phase = "booting"
        self.percent = 5
        self.message = "Starting server…"
        self.ready = False

    def advance(self, phase: str, percent: int, message: str) -> None:
        self.phase = phase
        self.percent = max(0, min(100, percent))
        self.message = message

    def mark_ready(self) -> None:
        self.ready = True
        self.phase = "ready"
        self.percent = 100
        self.message = "Ready"

    def snapshot(self) -> Dict[str, Any]:
        return {
            "phase": self.phase,
            "percent": self.percent,
            "message": self.message,
            "ready": self.ready,
            "startedAt": self.started_at,
        }


startup = StartupProgress()
