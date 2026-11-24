"""Stage 8: Structured SIEM-ready JSONL telemetry logging."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from phishing_detector.models import AnalysisReport


def build_siem_event(report: AnalysisReport) -> dict[str, Any]:
    """Build a structured JSON event suitable for SIEM ingestion (ECS-inspired)."""
    return {
        "@timestamp": report.timestamp_utc,
        "event": {
            "kind": "alert" if report.is_phishing else "event",
            "category": ["email", "intrusion_detection"],
            "action": report.recommended_action.value.lower(),
            "outcome": report.verdict.value.lower(),
            "risk_score": report.risk_score,
            "severity": report.risk_level.value.lower(),
        },
        "trace_id": report.trace_id,
        "email": {
            "source_name": report.source_name,
            "from": report.sender,
            "subject": report.subject,
            "headers": report.header_summary,
            "attachments": report.attachments_summary,
        },
        "semantic": report.semantic_summary,
        "iocs": report.iocs,
        "findings": [f.to_dict() for f in report.findings],
        "stage_timings_ms": report.stage_timings_ms,
    }


class TelemetryLogger:
    """Appends structured JSONL analysis events to disk for SIEM / observability."""

    def __init__(self, log_path: str | Path) -> None:
        self.log_path = Path(log_path)

    def write(self, report: AnalysisReport) -> Path:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        event = build_siem_event(report)
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, ensure_ascii=False) + "\n")
        return self.log_path
