"""Stage 2: Authentication validation (SPF/DKIM/DMARC), identity alignment, and hop tracing."""

from __future__ import annotations

import ipaddress
import re

from phishing_detector.config import DetectorConfig, PROTECTED_BRANDS
from phishing_detector.models import (
    Finding,
    HeaderAnalysis,
    PipelineContext,
    ReceivedHop,
    Severity,
)
from phishing_detector.stages.base import PipelineStage


_AUTH_MECHANISM_RE = re.compile(
    r"\b(spf|dkim|dmarc|arc)\s*=\s*(pass|fail|softfail|hardfail|neutral|none|temperror|permerror|bestguesspass)\b",
    re.IGNORECASE,
)
_RECEIVED_SPF_RE = re.compile(
    r"^\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b",
    re.IGNORECASE,
)
_RECEIVED_FROM_RE = re.compile(r"\bfrom\s+([^\s\(\);]+)", re.IGNORECASE)
_RECEIVED_BY_RE = re.compile(r"\bby\s+([^\s\(\);]+)", re.IGNORECASE)
_IPV4_EXTRACT_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_EXTRACT_RE = re.compile(r"(?:IPv6:)?([0-9a-fA-F:]{2,39}:[0-9a-fA-F:]+)")
_EMAIL_IN_TEXT_RE = re.compile(r"[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}")

_SECOND_LEVEL_CCTLDS = frozenset(
    {
        "co.uk",
        "org.uk",
        "gov.uk",
        "com.br",
        "com.mx",
        "com.ar",
        "com.co",
        "com.pe",
        "com.au",
        "co.jp",
        "co.nz",
        "co.za",
    }
)


def extract_domain(email_address: str) -> str:
    """Return lowercased domain portion of an email address."""
    if not email_address or "@" not in email_address:
        return ""
    return email_address.rsplit("@", 1)[-1].strip().strip(">").lower()


def organizational_domain(domain: str) -> str:
    """Return the approximate registrable organizational domain (eTLD+1)."""
    clean = domain.strip().lower().strip(".")
    if not clean:
        return ""
    parts = clean.split(".")
    if len(parts) <= 2:
        return clean
    last_two = ".".join(parts[-2:])
    if last_two in _SECOND_LEVEL_CCTLDS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


def _is_public_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return not (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        )
    except ValueError:
        return False


def _extract_valid_ips(text: str) -> list[str]:
    ips: list[str] = []
    for match in _IPV4_EXTRACT_RE.findall(text):
        try:
            ipaddress.IPv4Address(match)
            if match not in ips:
                ips.append(match)
        except ValueError:
            pass
    for match in _IPV6_EXTRACT_RE.findall(text):
        candidate = match.strip("[]()")
        if candidate.count(":") < 2:
            continue
        try:
            ipaddress.IPv6Address(candidate)
            if candidate not in ips:
                ips.append(candidate)
        except ValueError:
            pass
    return ips


class HeaderAuthStage(PipelineStage):
    """Stage 2: Validate SPF/DKIM/DMARC, sender identity alignment, and Received hops."""

    name = "header_auth"

    def __init__(self, config: DetectorConfig | None = None) -> None:
        super().__init__(config)

    def run(self, context: PipelineContext) -> PipelineContext:
        email = context.email
        analysis = HeaderAnalysis()

        # 1. Authentication-Results & Received-SPF
        self._evaluate_auth_results(email.headers, analysis, context)

        # 2. Identity consistency (From vs Return-Path vs Reply-To & display name)
        analysis.from_domain = extract_domain(email.from_address)
        analysis.return_path_domain = extract_domain(email.return_path_address)
        analysis.reply_to_domain = extract_domain(email.reply_to_address)
        self._evaluate_identity_alignment(email, analysis, context)

        # 3. Received hop chain & IP tracing
        self._trace_received_hops(email.headers, analysis, context)

        # 4. Basic RFC 5322 structural hygiene (only when full email headers exist)
        if email.headers and email.from_address and not email.message_id:
            w = self.config.weights.get("HEADER_MISSING_MESSAGE_ID", 1)
            context.add_finding(
                Finding(
                    stage=self.name,
                    rule_id="HEADER_MISSING_MESSAGE_ID",
                    title="Missing Message-ID header",
                    description="Email lacks a standard RFC 5322 Message-ID header, common in crude phishing scripts.",
                    score=w,
                    severity=Severity.LOW,
                )
            )

        context.headers = analysis
        return context

    def _evaluate_auth_results(
        self,
        headers: dict[str, list[str]],
        analysis: HeaderAnalysis,
        context: PipelineContext,
    ) -> None:
        auth_headers = headers.get("authentication-results", []) + headers.get(
            "arc-authentication-results", []
        )
        results: dict[str, str] = {}

        for raw in auth_headers:
            for mech, verdict in _AUTH_MECHANISM_RE.findall(raw):
                mech_l = mech.lower()
                verdict_l = verdict.lower()
                # Prefer explicit fail/pass over none if multiple headers exist
                if mech_l not in results or results[mech_l] == "none":
                    results[mech_l] = verdict_l

        # Fallback to Received-SPF if Authentication-Results had no spf
        if "spf" not in results:
            for raw_spf in headers.get("received-spf", []):
                m = _RECEIVED_SPF_RE.match(raw_spf)
                if m:
                    results["spf"] = m.group(1).lower()
                    break

        analysis.spf_result = results.get("spf", "none")
        analysis.dkim_result = results.get("dkim", "none")
        analysis.dmarc_result = results.get("dmarc", "none")
        analysis.arc_result = results.get("arc", "none")

        if analysis.spf_result in ("fail", "hardfail"):
            context.add_finding(
                Finding(
                    stage=self.name,
                    rule_id="AUTH_SPF_FAIL",
                    title="SPF validation failed",
                    description="Sending server IP is not authorized by the sender domain SPF policy.",
                    score=self.config.weights.get("AUTH_SPF_FAIL", 4),
                    severity=Severity.HIGH,
                    evidence={"spf": analysis.spf_result},
                )
            )
        elif analysis.spf_result == "softfail":
            context.add_finding(
                Finding(
                    stage=self.name,
                    rule_id="AUTH_SPF_SOFTFAIL",
                    title="SPF validation softfail",
                    description="Sending server IP is discouraged (~all) by the sender domain SPF policy.",
                    score=self.config.weights.get("AUTH_SPF_SOFTFAIL", 2),
                    severity=Severity.MEDIUM,
                    evidence={"spf": analysis.spf_result},
                )
            )

        if analysis.dkim_result == "fail":
            context.add_finding(
                Finding(
                    stage=self.name,
                    rule_id="AUTH_DKIM_FAIL",
                    title="DKIM cryptographic signature failed",
                    description="DKIM signature verification failed; message may be spoofed or altered in transit.",
                    score=self.config.weights.get("AUTH_DKIM_FAIL", 4),
                    severity=Severity.HIGH,
                    evidence={"dkim": analysis.dkim_result},
                )
            )

        if analysis.dmarc_result == "fail":
            context.add_finding(
                Finding(
                    stage=self.name,
                    rule_id="AUTH_DMARC_FAIL",
                    title="DMARC alignment/validation failed",
                    description="Email failed DMARC policy check for the visible From domain.",
                    score=self.config.weights.get("AUTH_DMARC_FAIL", 5),
                    severity=Severity.HIGH,
                    evidence={"dmarc": analysis.dmarc_result},
                )
            )

    def _evaluate_identity_alignment(
        self, email, analysis: HeaderAnalysis, context: PipelineContext
    ) -> None:
        from_org = organizational_domain(analysis.from_domain)
        rp_org = organizational_domain(analysis.return_path_domain)
        rt_org = organizational_domain(analysis.reply_to_domain)

        if from_org and rp_org and from_org != rp_org:
            analysis.identity_mismatches.append(
                f"From ({analysis.from_domain}) != Return-Path ({analysis.return_path_domain})"
            )
            context.add_finding(
                Finding(
                    stage=self.name,
                    rule_id="HEADER_FROM_RETURN_PATH_MISMATCH",
                    title="From and Return-Path domain mismatch",
                    description=(
                        f"Visible sender domain '{analysis.from_domain}' differs from "
                        f"envelope Return-Path domain '{analysis.return_path_domain}'."
                    ),
                    score=self.config.weights.get("HEADER_FROM_RETURN_PATH_MISMATCH", 2),
                    severity=Severity.MEDIUM,
                    evidence={
                        "from_domain": analysis.from_domain,
                        "return_path_domain": analysis.return_path_domain,
                    },
                )
            )

        if from_org and rt_org and from_org != rt_org:
            analysis.identity_mismatches.append(
                f"From ({analysis.from_domain}) != Reply-To ({analysis.reply_to_domain})"
            )
            context.add_finding(
                Finding(
                    stage=self.name,
                    rule_id="HEADER_FROM_REPLY_TO_MISMATCH",
                    title="From and Reply-To domain mismatch",
                    description=(
                        f"Replies are redirected to a different domain ('{analysis.reply_to_domain}') "
                        f"than the visible sender ('{analysis.from_domain}')."
                    ),
                    score=self.config.weights.get("HEADER_FROM_REPLY_TO_MISMATCH", 3),
                    severity=Severity.MEDIUM,
                    evidence={
                        "from_domain": analysis.from_domain,
                        "reply_to_domain": analysis.reply_to_domain,
                    },
                )
            )

        # Display-name spoofing checks
        display = email.from_display_name.strip()
        if display and analysis.from_domain:
            # Case A: Display name contains a different email address
            embedded_emails = _EMAIL_IN_TEXT_RE.findall(display)
            for emb in embedded_emails:
                emb_org = organizational_domain(extract_domain(emb))
                if emb_org and emb_org != from_org:
                    analysis.display_name_spoof = True
                    context.add_finding(
                        Finding(
                            stage=self.name,
                            rule_id="HEADER_DISPLAY_NAME_SPOOF",
                            title="Display-name email spoofing",
                            description=(
                                f"Display name embeds '{emb}' while actual sender is "
                                f"'{email.from_address}'."
                            ),
                            score=self.config.weights.get("HEADER_DISPLAY_NAME_SPOOF", 5),
                            severity=Severity.HIGH,
                            evidence={
                                "display_name": display,
                                "embedded_email": emb,
                                "from_address": email.from_address,
                            },
                        )
                    )
                    return

            # Case B: Display name impersonates a protected brand from an unauthorized domain
            display_lower = display.lower()
            for brand, official_domains in PROTECTED_BRANDS.items():
                if re.search(rf"\b{re.escape(brand)}\b", display_lower):
                    if from_org not in official_domains and analysis.from_domain not in official_domains:
                        analysis.display_name_spoof = True
                        context.add_finding(
                            Finding(
                                stage=self.name,
                                rule_id="HEADER_DISPLAY_NAME_SPOOF",
                                title=f"Brand impersonation in display name ({brand})",
                                description=(
                                    f"Sender display name '{display}' references '{brand}', "
                                    f"but email originates from unauthorized domain '{analysis.from_domain}'."
                                ),
                                score=self.config.weights.get("HEADER_DISPLAY_NAME_SPOOF", 5),
                                severity=Severity.HIGH,
                                evidence={
                                    "brand": brand,
                                    "display_name": display,
                                    "from_domain": analysis.from_domain,
                                },
                            )
                        )
                        return

    def _trace_received_hops(
        self,
        headers: dict[str, list[str]],
        analysis: HeaderAnalysis,
        context: PipelineContext,
    ) -> None:
        raw_received = headers.get("received", [])
        if not raw_received:
            return

        # RFC 5322 prepends Received headers; reverse for chronological order (origin -> destination)
        hops: list[ReceivedHop] = []
        for raw in reversed(raw_received):
            from_match = _RECEIVED_FROM_RE.search(raw)
            by_match = _RECEIVED_BY_RE.search(raw)
            timestamp_raw = raw.rsplit(";", 1)[-1].strip() if ";" in raw else None
            ips = _extract_valid_ips(raw)
            hops.append(
                ReceivedHop(
                    raw=raw.strip(),
                    from_host=from_match.group(1).strip("[]()") if from_match else None,
                    by_host=by_match.group(1).strip("[]()") if by_match else None,
                    ip_addresses=ips,
                    timestamp_raw=timestamp_raw,
                )
            )

        analysis.received_hops = hops

        # Identify first public IP from the originating side
        for hop in hops:
            for ip in hop.ip_addresses:
                if _is_public_ip(ip):
                    analysis.originating_ip = ip
                    break
            if analysis.originating_ip:
                break

        if analysis.originating_ip and analysis.originating_ip in self.config.blocklisted_ips:
            context.add_finding(
                Finding(
                    stage=self.name,
                    rule_id="HEADER_BLOCKLISTED_IP",
                    title="Originating IP found on blocklist",
                    description=f"Originating relay IP '{analysis.originating_ip}' is listed on the blocklist.",
                    score=self.config.weights.get("HEADER_BLOCKLISTED_IP", 6),
                    severity=Severity.CRITICAL,
                    evidence={"originating_ip": analysis.originating_ip},
                )
            )

        # Detect suspiciously unauthenticated hop claiming a protected brand hostname
        first_hop = hops[0]
        if first_hop.from_host and analysis.spf_result in ("fail", "softfail", "none"):
            host_org = organizational_domain(first_hop.from_host)
            for brand, official_domains in PROTECTED_BRANDS.items():
                if host_org in official_domains and analysis.from_domain and organizational_domain(analysis.from_domain) not in official_domains:
                    context.add_finding(
                        Finding(
                            stage=self.name,
                            rule_id="HEADER_SUSPICIOUS_HOP",
                            title="Suspicious forged Received hop",
                            description=(
                                f"Originating Received header claims '{first_hop.from_host}' "
                                f"without matching authenticated sender domain."
                            ),
                            score=self.config.weights.get("HEADER_SUSPICIOUS_HOP", 2),
                            severity=Severity.MEDIUM,
                            evidence={"from_host": first_hop.from_host},
                        )
                    )
                    break
