"""Email Phishing Detector — Multi-layer Defense-in-Depth Engine."""

from phishing_detector.config import DetectorConfig
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

__version__ = "1.0.0"

__all__ = [
    "ActionOutcome",
    "ActionType",
    "AnalysisReport",
    "AttachmentInfo",
    "DetectorConfig",
    "EmailMessage",
    "ExtractedLink",
    "Finding",
    "HeaderAnalysis",
    "NormalizedContent",
    "PipelineContext",
    "ReceivedHop",
    "RiskLevel",
    "SemanticAnalysis",
    "Severity",
    "Verdict",
]
