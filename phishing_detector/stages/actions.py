"""Stage 8: Automated response actions (ALLOW, WARN banner injection, QUARANTINE/BLOCK)."""

from __future__ import annotations

import html
import json
from pathlib import Path
import re

from phishing_detector.config import DetectorConfig
from phishing_detector.models import (
    ActionOutcome,
    ActionType,
    AnalysisReport,
    PipelineContext,
)
from phishing_detector.telemetry import TelemetryLogger


_BODY_OPEN_RE = re.compile(r"(<body[^>]*>)", re.IGNORECASE)


def inject_warning_banner(raw_html: str, report: AnalysisReport) -> str:
    """Safely inject a visible, HTML-escaped phishing caution banner into an HTML email."""
    top_reasons = "; ".join(f.title for f in report.findings[:3]) or "Suspicious indicators detected"
    banner = (
        '<div data-phishing-detector-banner="true" '
        'style="background:#fff3cd;border:2px solid #d97706;color:#78350f;'
        'padding:12px 16px;margin:0 0 12px 0;font-family:sans-serif;font-size:14px;">'
        f"<strong>[ADVERTENCIA DE SEGURIDAD — Riesgo {html.escape(report.risk_level.value)} "
        f"(Puntaje: {report.risk_score})]</strong><br>"
        "Este correo presenta señales sospechosas. No haga clic en enlaces ni comparta credenciales "
        "sin verificar al remitente por un canal independiente.<br>"
        f"<small>Indicadores: {html.escape(top_reasons)}</small>"
        "</div>"
    )
    if not raw_html:
        return banner
    if _BODY_OPEN_RE.search(raw_html):
        return _BODY_OPEN_RE.sub(rf"\1{banner}", raw_html, count=1)
    return f"{banner}{raw_html}"


class ActionEngine:
    """Stage 8: Executes policy actions (ALLOW, WARN, QUARANTINE, BLOCK) and logs telemetry."""

    def __init__(self, config: DetectorConfig | None = None) -> None:
        self.config = config or DetectorConfig()

    def handle(self, context: PipelineContext, report: AnalysisReport) -> ActionOutcome:
        action = report.recommended_action
        outcome = ActionOutcome(action=action)

        if action == ActionType.WARN:
            base_html = context.email.text_html or f"<pre>{html.escape(context.email.text_plain)}</pre>"
            outcome.modified_html = inject_warning_banner(base_html, report)
            outcome.banner_injected = True

        elif action in (ActionType.QUARANTINE, ActionType.BLOCK):
            if self.config.quarantine_dir:
                q_path = self._quarantine_email(context, report)
                outcome.quarantine_path = str(q_path)

        if self.config.telemetry_log_path:
            TelemetryLogger(self.config.telemetry_log_path).write(report)
            outcome.telemetry_written = True

        return outcome

    def _quarantine_email(self, context: PipelineContext, report: AnalysisReport) -> Path:
        q_dir = Path(self.config.quarantine_dir or "quarantine")
        q_dir.mkdir(parents=True, exist_ok=True)
        safe_id = re.sub(r"[^a-zA-Z0-9_-]", "", report.trace_id)

        eml_path = q_dir / f"{safe_id}.eml"
        meta_path = q_dir / f"{safe_id}.report.json"

        if context.email.raw_bytes:
            eml_path.write_bytes(context.email.raw_bytes)
        else:
            reconstructed = (
                f"From: {context.email.from_raw}\r\n"
                f"Subject: {context.email.subject}\r\n\r\n"
                f"{context.email.text_html or context.email.text_plain}"
            )
            eml_path.write_text(reconstructed, encoding="utf-8")

        meta_path.write_text(
            json.dumps(report.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return eml_path
