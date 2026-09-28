"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, dict] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store input and timing metadata until the matching output arrives."""
        key = request_id or user_id
        self._open[key] = {
            "request_id": request_id or key,
            "user_id": user_id,
            "input": text,
            "started_at": utc_now_iso(),
            "started_perf": time.perf_counter(),
        }

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Close an interaction and append its forensic record."""
        key = request_id or user_id
        opened = self._open.pop(key, {})
        started_perf = opened.get("started_perf")
        latency_ms = None
        if started_perf is not None:
            latency_ms = round((time.perf_counter() - started_perf) * 1000, 2)

        self.logs.append(
            {
                "request_id": opened.get("request_id", request_id or key),
                "user_id": opened.get("user_id", user_id),
                "input": opened.get("input", ""),
                "output": text,
                "blocked": blocked,
                "layer": layer,
                "started_at": opened.get("started_at"),
                "completed_at": utc_now_iso(),
                "latency_ms": latency_ms,
            }
        )

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.logs, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return path


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
