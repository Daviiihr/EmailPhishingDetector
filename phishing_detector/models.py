"""Core domain models for the multi-layer Email Phishing Detection Engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
import uuid


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Verdict(str, Enum):
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    PHISHING_DETECTED = "PHISHING_DETECTED"


class ActionType(str, Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    QUARANTINE = "QUARANTINE"
    BLOCK = "BLOCK"


@dataclass
class Finding:
    """A single security signal emitted by any stage in the pipeline."""

    stage: str
    rule_id: str
    title: str
    description: str
    score: int
    severity: Severity = Severity.MEDIUM
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "score": self.score,
            "severity": self.severity.value,
            "evidence": self.evidence,
        }


@dataclass
class AttachmentInfo:
    """Isolated representation of an email attachment or embedded resource."""

    filename: str
    content_type: str
    size_bytes: int
    payload: bytes = field(repr=False, default=b"")
    content_disposition: str = "attachment"
    content_id: str | None = None
    sha256: str = ""
    md5: str = ""
    detected_magic_type: str | None = None
    has_macros: bool = False
    extracted_qr_urls: list[str] = field(default_factory=list)
    nested_files: list[str] = field(default_factory=list)
    sandbox_verdict: str | None = None

    def to_summary_dict(self) -> dict[str, Any]:
        return {
            "filename": self.filename,
            "content_type": self.content_type,
            "size_bytes": self.size_bytes,
            "content_disposition": self.content_disposition,
            "sha256": self.sha256,
            "md5": self.md5,
            "detected_magic_type": self.detected_magic_type,
            "has_macros": self.has_macros,
            "extracted_qr_urls": list(self.extracted_qr_urls),
            "nested_files": list(self.nested_files),
            "sandbox_verdict": self.sandbox_verdict,
        }


@dataclass
class EmailMessage:
    """Structured output of Stage 1 (MIME / RFC 5322 Ingestion)."""

    raw_bytes: bytes = field(repr=False, default=b"")
    source_name: str = "<memory>"
    subject: str = ""
    from_raw: str = ""
    from_display_name: str = ""
    from_address: str = ""
    to_addresses: list[str] = field(default_factory=list)
    reply_to_raw: str = ""
    reply_to_address: str = ""
    return_path_raw: str = ""
    return_path_address: str = ""
    date_raw: str = ""
    message_id: str = ""
    headers: dict[str, list[str]] = field(default_factory=dict)
    text_plain: str = ""
    text_html: str = ""
    attachments: list[AttachmentInfo] = field(default_factory=list)
    parse_warnings: list[str] = field(default_factory=list)


@dataclass
class ReceivedHop:
    """Single hop parsed from a Received header."""

    raw: str
    from_host: str | None = None
    by_host: str | None = None
    ip_addresses: list[str] = field(default_factory=list)
    timestamp_raw: str | None = None


@dataclass
class HeaderAnalysis:
    """Output of Stage 2 (Authentication & Header Analysis)."""

    spf_result: str = "none"
    dkim_result: str = "none"
    dmarc_result: str = "none"
    arc_result: str = "none"
    from_domain: str = ""
    return_path_domain: str = ""
    reply_to_domain: str = ""
    originating_ip: str | None = None
    received_hops: list[ReceivedHop] = field(default_factory=list)
    identity_mismatches: list[str] = field(default_factory=list)
    display_name_spoof: bool = False


@dataclass
class ExtractedLink:
    """Structured link extracted from HTML, plain text, or QR codes."""

    original_url: str
    normalized_url: str
    anchor_text: str = ""
    source: str = "html_href"  # html_href, plain_text, html_form, meta_refresh, qr_code
    domain: str = ""
    decoded_domain: str = ""
    is_punycode: bool = False
    is_idn_homograph: bool = False
    is_ip_url: bool = False
    is_shortener: bool = False
    has_risky_tld: bool = False
    is_visual_spoof: bool = False
    resolved_url: str | None = None
    domain_age_days: int | None = None
    reputation_hits: list[str] = field(default_factory=list)


@dataclass
class NormalizedContent:
    """Output of Stage 3 (Normalization & Deobfuscation)."""

    clean_subject: str = ""
    clean_plain_text: str = ""
    clean_html_text: str = ""
    combined_text: str = ""
    hidden_texts: list[str] = field(default_factory=list)
    has_hidden_css: bool = False
    zero_width_chars_removed: int = 0
    bidi_controls_removed: int = 0
    homoglyph_words: list[str] = field(default_factory=list)
    links: list[ExtractedLink] = field(default_factory=list)
    form_actions: list[str] = field(default_factory=list)
    meta_refresh_urls: list[str] = field(default_factory=list)
    decoding_layers_applied: list[str] = field(default_factory=list)


@dataclass
class SemanticAnalysis:
    """Output of Stage 6 (Semantic / NLP / BEC Analysis)."""

    urgency_matches: list[str] = field(default_factory=list)
    authority_matches: list[str] = field(default_factory=list)
    financial_matches: list[str] = field(default_factory=list)
    credential_matches: list[str] = field(default_factory=list)
    secrecy_matches: list[str] = field(default_factory=list)
    bec_suspected: bool = False
    ml_phishing_probability: float = 0.0
    ml_top_features: list[str] = field(default_factory=list)
    detected_intents: list[str] = field(default_factory=list)


@dataclass
class ActionOutcome:
    """Output of Stage 8 (Automated Action & Telemetry)."""

    action: ActionType = ActionType.ALLOW
    banner_injected: bool = False
    modified_html: str | None = None
    quarantine_path: str | None = None
    telemetry_written: bool = False


@dataclass
class PipelineContext:
    """Mutable analysis context passed through all 8 stages."""

    trace_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    email: EmailMessage = field(default_factory=EmailMessage)
    headers: HeaderAnalysis = field(default_factory=HeaderAnalysis)
    normalized: NormalizedContent = field(default_factory=NormalizedContent)
    semantic: SemanticAnalysis = field(default_factory=SemanticAnalysis)
    findings: list[Finding] = field(default_factory=list)
    stage_timings_ms: dict[str, float] = field(default_factory=dict)
    action_outcome: ActionOutcome | None = None
    enable_external_enrichment: bool = False

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)


@dataclass
class AnalysisReport:
    """Final consolidated report returned by the Phishing Pipeline."""

    trace_id: str
    timestamp_utc: str
    source_name: str
    subject: str
    sender: str
    risk_score: int
    risk_level: RiskLevel
    verdict: Verdict
    is_phishing: bool
    recommended_action: ActionType
    findings: list[Finding]
    stage_timings_ms: dict[str, float]
    iocs: dict[str, list[str]]
    action_outcome: ActionOutcome | None = None
    header_summary: dict[str, Any] = field(default_factory=dict)
    semantic_summary: dict[str, Any] = field(default_factory=dict)
    attachments_summary: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "timestamp_utc": self.timestamp_utc,
            "source_name": self.source_name,
            "subject": self.subject,
            "sender": self.sender,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level.value,
            "verdict": self.verdict.value,
            "is_phishing": self.is_phishing,
            "recommended_action": self.recommended_action.value,
            "findings": [f.to_dict() for f in self.findings],
            "stage_timings_ms": dict(self.stage_timings_ms),
            "iocs": self.iocs,
            "header_summary": self.header_summary,
            "semantic_summary": self.semantic_summary,
            "attachments_summary": self.attachments_summary,
            "action_outcome": (
                {
                    "action": self.action_outcome.action.value,
                    "banner_injected": self.action_outcome.banner_injected,
                    "quarantine_path": self.action_outcome.quarantine_path,
                    "telemetry_written": self.action_outcome.telemetry_written,
                }
                if self.action_outcome
                else None
            ),
        }
