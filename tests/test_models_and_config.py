"""Unit tests for core models, configuration, and stage base class."""

from phishing_detector.config import (
    DEFAULT_SCORING_WEIGHTS,
    DetectorConfig,
    RISKY_TLDS,
    URGENCY_PATTERN,
    URL_SHORTENERS,
)
from phishing_detector.models import (
    ActionType,
    Finding,
    PipelineContext,
    RiskLevel,
    Severity,
    Verdict,
)
from phishing_detector.stages.base import PipelineStage


class DummyStage(PipelineStage):
    name = "dummy"

    def run(self, context: PipelineContext) -> PipelineContext:
        context.add_finding(
            Finding(
                stage=self.name,
                rule_id="TEST_RULE",
                title="Test signal",
                description="Emitted by dummy stage",
                score=2,
                severity=Severity.LOW,
            )
        )
        return context


def test_readme_scoring_weights_match_specification():
    assert DEFAULT_SCORING_WEIGHTS["URL_IP_BASED"] == 5
    assert DEFAULT_SCORING_WEIGHTS["URL_VISUAL_SPOOFING"] == 5
    assert DEFAULT_SCORING_WEIGHTS["URL_RISKY_TLD"] == 4
    assert DEFAULT_SCORING_WEIGHTS["HTML_HIDDEN_CSS_TEXT"] == 4
    assert DEFAULT_SCORING_WEIGHTS["URL_SHORTENER"] == 3
    assert DEFAULT_SCORING_WEIGHTS["SEMANTIC_URGENCY_KEYWORD"] == 2


def test_default_config_thresholds():
    cfg = DetectorConfig()
    assert cfg.phishing_threshold == 5
    assert cfg.warn_threshold == 3
    assert ".xyz" in RISKY_TLDS
    assert "bit.ly" in URL_SHORTENERS
    assert URGENCY_PATTERN.search("Acción urgente requerida") is not None


def test_pipeline_stage_records_timing_and_findings():
    ctx = PipelineContext()
    stage = DummyStage()
    stage.execute(ctx)
    assert "dummy" in ctx.stage_timings_ms
    assert ctx.stage_timings_ms["dummy"] >= 0.0
    assert len(ctx.findings) == 1
    assert ctx.findings[0].to_dict()["severity"] == "low"


def test_enums_values():
    assert Verdict.PHISHING_DETECTED.value == "PHISHING_DETECTED"
    assert RiskLevel.HIGH.value == "HIGH"
    assert ActionType.QUARANTINE.value == "QUARANTINE"
