"""Email Phishing Detector — Multi-layer Defense-in-Depth Engine."""

from phishing_detector.config import DetectorConfig
from phishing_detector.feedback import FeedbackStore
from phishing_detector.models import (
    ActionOutcome,
    ActionType,
    AnalysisReport,
    AttachmentInfo,
    EmailMessage,
    ExtractedLink,
    Finding,
    HeaderAnalysis,
    NormalizedContent,
    PipelineContext,
    ReceivedHop,
    RiskLevel,
    SemanticAnalysis,
    Severity,
    Verdict,
)

from phishing_detector.pipeline import PhishingPipeline, analyze_email
from phishing_detector.scoring import ScoringEngine
from phishing_detector.stages.actions import ActionEngine
from phishing_detector.telemetry import TelemetryLogger

__version__ = "1.0.0"

__all__ = [
    "ActionEngine",
    "ActionOutcome",
    "ActionType",
    "AnalysisReport",
    "AttachmentInfo",
    "DetectorConfig",
    "EmailMessage",
    "ExtractedLink",
    "FeedbackStore",
    "Finding",
    "HeaderAnalysis",
    "NormalizedContent",
    "PhishingPipeline",
    "PipelineContext",
    "ReceivedHop",
    "RiskLevel",
    "ScoringEngine",
    "SemanticAnalysis",
    "Severity",
    "TelemetryLogger",
    "Verdict",
    "analyze_email",
]
