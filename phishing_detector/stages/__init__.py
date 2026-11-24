"""Pipeline stages package."""

from phishing_detector.stages.actions import ActionEngine, inject_warning_banner
from phishing_detector.stages.attachments import (
    AttachmentInspectionStage,
    DefaultQrCodeDecoder,
    LocalStaticSandboxClient,
    QrCodeDecoder,
    SandboxClient,
    SandboxResult,
)
from phishing_detector.stages.base import PipelineStage
from phishing_detector.stages.headers import HeaderAuthStage
from phishing_detector.stages.ingestion import MimeIngestionStage, decode_mime_header
from phishing_detector.stages.normalization import NormalizationStage, normalize_text
from phishing_detector.stages.semantic import (
    NaiveBayesPhishingClassifier,
    SemanticAnalysisStage,
)
from phishing_detector.stages.url_analysis import UrlAnalysisStage

__all__ = [
    "ActionEngine",
    "AttachmentInspectionStage",
    "DefaultQrCodeDecoder",
    "HeaderAuthStage",
    "LocalStaticSandboxClient",
    "MimeIngestionStage",
    "NaiveBayesPhishingClassifier",
    "NormalizationStage",
    "PipelineStage",
    "QrCodeDecoder",
    "SandboxClient",
    "SandboxResult",
    "SemanticAnalysisStage",
    "UrlAnalysisStage",
    "decode_mime_header",
    "inject_warning_banner",
    "normalize_text",
]
