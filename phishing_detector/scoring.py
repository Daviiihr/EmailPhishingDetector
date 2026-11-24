"""Stage 7: Consolidated weighted Scoring Engine and IOC extractor."""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any

from phishing_detector.config import DetectorConfig
from phishing_detector.models import (
    ActionType,
    AnalysisReport,
    Finding,
    PipelineContext,
    RiskLevel,
    Severity,
    Verdict,
)
from phishing_detector.stages.headers import organizational_domain


@dataclass
class ScoringDecision:
    risk_score: int
    risk_level: RiskLevel
    verdict: Verdict
    is_phishing: bool
    recommended_action: ActionType
    deduplicated_findings: list[Finding]


def _finding_dedup_key(finding: Finding) -> tuple[str, str, str]:
    evidence_sig = json.dumps(finding.evidence, sort_keys=True, default=str)
    return (finding.stage, finding.rule_id, evidence_sig)


def extract_iocs(context: PipelineContext) -> dict[str, list[str]]:
    """Extract normalized Indicators of Compromise (IoCs) for SIEM/SOC reporting."""
    urls: list[str] = []
    domains: list[str] = []
    ips: list[str] = []
    senders: list[str] = []
    hashes: list[str] = []

    if context.email.from_address:
        senders.append(context.email.from_address)
    if context.email.reply_to_address and context.email.reply_to_address not in senders:
        senders.append(context.email.reply_to_address)
    if context.email.return_path_address and context.email.return_path_address not in senders:
        senders.append(context.email.return_path_address)

    if context.headers.originating_ip:
        ips.append(context.headers.originating_ip)
    for dom in (
        context.headers.from_domain,
        context.headers.reply_to_domain,
        context.headers.return_path_domain,
    ):
        if dom and dom not in domains:
            domains.append(dom)

    for link in context.normalized.links:
        if link.normalized_url and link.normalized_url not in urls:
            urls.append(link.normalized_url)
        if link.resolved_url and link.resolved_url not in urls:
            urls.append(link.resolved_url)
        if link.domain and link.domain not in domains:
            domains.append(link.domain)

    for att in context.email.attachments:
        if att.sha256 and att.sha256 not in hashes:
            hashes.append(att.sha256)

    return {
        "urls": urls,
        "domains": domains,
        "ips": ips,
        "sender_addresses": senders,
        "attachment_sha256s": hashes,
    }


class ScoringEngine:
    """Stage 7: Consolidates findings across all stages into a weighted risk decision."""

    def __init__(self, config: DetectorConfig | None = None) -> None:
        self.config = config or DetectorConfig()

    def evaluate(self, context: PipelineContext) -> ScoringDecision:
        seen: set[tuple[str, str, str]] = set()
        deduped: list[Finding] = []
        for finding in context.findings:
            key = _finding_dedup_key(finding)
            if key not in seen:
                seen.add(key)
                deduped.append(finding)

        total_score = sum(max(0, f.score) for f in deduped)

        # Allowlist trust check: if sender org domain is explicitly allowlisted,
        # passed full SPF+DKIM+DMARC, and has no critical findings, mitigate score.
        from_org = organizational_domain(context.headers.from_domain)
        has_critical = any(f.severity == Severity.CRITICAL for f in deduped)
        fully_authenticated = (
            context.headers.spf_result == "pass"
            and context.headers.dkim_result == "pass"
            and context.headers.dmarc_result == "pass"
        )
        if (
            from_org
            and (from_org in self.config.allowlisted_domains or context.headers.from_domain in self.config.allowlisted_domains)
            and fully_authenticated
            and not has_critical
        ):
            total_score = max(0, total_score - 4)

        is_phishing = total_score >= self.config.phishing_threshold

        if total_score >= self.config.critical_threshold:
            risk_level = RiskLevel.CRITICAL
            verdict = Verdict.PHISHING_DETECTED
            action = ActionType.BLOCK
        elif is_phishing:
            risk_level = RiskLevel.HIGH
            verdict = Verdict.PHISHING_DETECTED
            action = ActionType.QUARANTINE
        elif total_score >= self.config.warn_threshold:
            risk_level = RiskLevel.MEDIUM
            verdict = Verdict.SUSPICIOUS
            action = ActionType.WARN
        else:
            risk_level = RiskLevel.LOW
            verdict = Verdict.CLEAN
            action = ActionType.ALLOW

        return ScoringDecision(
            risk_score=total_score,
            risk_level=risk_level,
            verdict=verdict,
            is_phishing=is_phishing,
            recommended_action=action,
            deduplicated_findings=deduped,
        )

    def build_report(self, context: PipelineContext) -> AnalysisReport:
        decision = self.evaluate(context)
        context.findings = decision.deduplicated_findings

        header_summary: dict[str, Any] = {
            "spf": context.headers.spf_result,
            "dkim": context.headers.dkim_result,
            "dmarc": context.headers.dmarc_result,
            "from_domain": context.headers.from_domain,
            "return_path_domain": context.headers.return_path_domain,
            "reply_to_domain": context.headers.reply_to_domain,
            "originating_ip": context.headers.originating_ip,
            "hop_count": len(context.headers.received_hops),
            "display_name_spoof": context.headers.display_name_spoof,
        }

        semantic_summary: dict[str, Any] = {
            "bec_suspected": context.semantic.bec_suspected,
            "ml_phishing_probability": context.semantic.ml_phishing_probability,
            "ml_top_features": list(context.semantic.ml_top_features),
            "detected_intents": list(context.semantic.detected_intents),
        }

        return AnalysisReport(
            trace_id=context.trace_id,
            timestamp_utc=context.timestamp_utc,
            source_name=context.email.source_name,
            subject=context.normalized.clean_subject or context.email.subject,
            sender=context.email.from_raw or context.email.from_address,
            risk_score=decision.risk_score,
            risk_level=decision.risk_level,
            verdict=decision.verdict,
            is_phishing=decision.is_phishing,
            recommended_action=decision.recommended_action,
            findings=decision.deduplicated_findings,
            stage_timings_ms=dict(context.stage_timings_ms),
            iocs=extract_iocs(context),
            action_outcome=context.action_outcome,
            header_summary=header_summary,
            semantic_summary=semantic_summary,
            attachments_summary=[a.to_summary_dict() for a in context.email.attachments],
        )
