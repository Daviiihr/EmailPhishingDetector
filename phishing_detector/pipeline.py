"""Multi-layer Email Phishing Detection Pipeline orchestrator."""

from __future__ import annotations

from pathlib import Path
import time
from typing import Callable

from phishing_detector.config import DetectorConfig
from phishing_detector.enrichment.threat_intel import ThreatIntelEnricher
from phishing_detector.models import (
    ActionOutcome,
    AnalysisReport,
    EmailMessage,
    PipelineContext,
)
from phishing_detector.scoring import ScoringEngine
from phishing_detector.stages.attachments import (
    AttachmentInspectionStage,
    QrCodeDecoder,
    SandboxClient,
)
from phishing_detector.stages.base import PipelineStage
from phishing_detector.stages.headers import HeaderAuthStage
from phishing_detector.stages.ingestion import MimeIngestionStage
from phishing_detector.stages.normalization import NormalizationStage
from phishing_detector.stages.semantic import (
    NaiveBayesPhishingClassifier,
    SemanticAnalysisStage,
)
from phishing_detector.stages.url_analysis import UrlAnalysisStage


ActionHandler = Callable[[PipelineContext, AnalysisReport], ActionOutcome]


class PhishingPipeline:
    """Orchestrates the sequential Defense-in-Depth phishing detection stages."""

    def __init__(
        self,
        config: DetectorConfig | None = None,
        *,
        enricher: ThreatIntelEnricher | None = None,
        qr_decoder: QrCodeDecoder | None = None,
        sandbox_client: SandboxClient | None = None,
        classifier: NaiveBayesPhishingClassifier | None = None,
        action_handler: ActionHandler | None = None,
    ) -> None:
        self.config = config or DetectorConfig()
        self.ingestion_stage = MimeIngestionStage(self.config)
        self.url_stage = UrlAnalysisStage(self.config, enricher=enricher)
        self.stages: list[PipelineStage] = [
            self.ingestion_stage,
            HeaderAuthStage(self.config),
            NormalizationStage(self.config),
            self.url_stage,
            AttachmentInspectionStage(
                self.config,
                qr_decoder=qr_decoder,
                sandbox_client=sandbox_client,
                url_stage=self.url_stage,
            ),
            SemanticAnalysisStage(self.config, classifier=classifier),
        ]
        self.scoring_engine = ScoringEngine(self.config)
        self.action_handler = action_handler

    def analyze_context(self, context: PipelineContext) -> AnalysisReport:
        """Run all stages, score findings, and optionally execute Stage 8 actions."""
        for stage in self.stages:
            stage.execute(context)

        start_score = time.perf_counter()
        report = self.scoring_engine.build_report(context)
        context.stage_timings_ms["scoring"] = round(
            (time.perf_counter() - start_score) * 1000.0, 3
        )
        report.stage_timings_ms["scoring"] = context.stage_timings_ms["scoring"]

        if self.action_handler is not None:
            start_act = time.perf_counter()
            outcome = self.action_handler(context, report)
            elapsed_act = round((time.perf_counter() - start_act) * 1000.0, 3)
            context.action_outcome = outcome
            report.action_outcome = outcome
            report.stage_timings_ms["actions"] = elapsed_act

        return report

    def analyze_bytes(
        self, raw_bytes: bytes, source_name: str = "<memory>"
    ) -> AnalysisReport:
        ctx = PipelineContext(
            email=EmailMessage(raw_bytes=raw_bytes, source_name=source_name),
            enable_external_enrichment=self.config.enable_external_enrichment,
        )
        return self.analyze_context(ctx)

    def analyze_string(
        self, raw_email: str, source_name: str = "<string>"
    ) -> AnalysisReport:
        return self.analyze_bytes(
            raw_email.encode("utf-8", errors="replace"), source_name=source_name
        )

    def analyze_file(self, path: str | Path) -> AnalysisReport:
        file_path = Path(path)
        return self.analyze_bytes(file_path.read_bytes(), source_name=str(file_path))

    def analyze_parts(
        self,
        subject: str,
        body: str,
        *,
        sender: str = "",
        headers: dict[str, str] | None = None,
        source_name: str = "<inline>",
    ) -> AnalysisReport:
        msg = self.ingestion_stage.from_parts(
            subject, body, sender=sender, headers=headers, source_name=source_name
        )
        ctx = PipelineContext(
            email=msg,
            enable_external_enrichment=self.config.enable_external_enrichment,
        )
        return self.analyze_context(ctx)


def analyze_email(
    subject: str,
    raw_body: str,
    *,
    sender: str = "",
    headers: dict[str, str] | None = None,
    config: DetectorConfig | None = None,
) -> AnalysisReport:
    """Convenience API to analyze an email from subject + body strings."""
    pipeline = PhishingPipeline(config=config)
    return pipeline.analyze_parts(subject, raw_body, sender=sender, headers=headers)
