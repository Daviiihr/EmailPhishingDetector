"""Stage 4: URL heuristic inspection, Punycode/IDN homograph detection, visual spoofing, and Threat Intel."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

import idna

from phishing_detector.config import (
    DetectorConfig,
    HOMOGLYPH_MAP,
    IPV4_HOST_PATTERN,
    OBFUSCATED_IP_PATTERN,
    PROTECTED_BRANDS,
    RISKY_TLDS,
    SUSPICIOUS_URL_PATH_KEYWORDS,
    URL_SHORTENERS,
)
from phishing_detector.enrichment.threat_intel import ThreatIntelEnricher
from phishing_detector.models import (
    ExtractedLink,
    Finding,
    PipelineContext,
    Severity,
)
from phishing_detector.stages.base import PipelineStage
from phishing_detector.stages.headers import organizational_domain


_DANGEROUS_SCHEMES = frozenset({"javascript", "data", "vbscript", "file"})
_ANCHOR_DOMAIN_RE = re.compile(
    r"(?:https?://)?(?:www\.)?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z]{2,})+)",
    re.IGNORECASE,
)
_LEET_TRANS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a"})


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ch_a in enumerate(a, start=1):
        curr = [i]
        for j, ch_b in enumerate(b, start=1):
            cost = 0 if ch_a == ch_b else 1
            curr.append(min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost))
        prev = curr
    return prev[-1]


def _is_ip_host(host: str) -> bool:
    if not host:
        return False
    clean = host.strip("[]")
    if IPV4_HOST_PATTERN.match(clean) or OBFUSCATED_IP_PATTERN.match(clean):
        return True
    try:
        ipaddress.ip_address(clean)
        return True
    except ValueError:
        return False


def _decode_punycode_host(host: str) -> tuple[str, bool, bool]:
    """Return (decoded_host, is_punycode, is_homograph)."""
    lowered = host.lower()
    is_punycode = "xn--" in lowered
    decoded = lowered
    if is_punycode:
        try:
            decoded = idna.decode(lowered)
        except Exception:
            decoded = lowered

    # Homograph check: non-ASCII chars or confusables present in domain
    has_non_ascii = any(ord(ch) > 127 for ch in decoded)
    has_confusable = any(ch in HOMOGLYPH_MAP for ch in decoded)
    is_homograph = is_punycode or (has_non_ascii and has_confusable)
    return decoded, is_punycode, is_homograph


def _detect_brand_typosquatting(host: str, decoded_host: str) -> str | None:
    """Return spoofed brand name if host mimics a protected brand via typosquatting/leet/homoglyph."""
    org = organizational_domain(host)
    if not org or "." not in org:
        return None
    label = org.split(".", 1)[0]
    decoded_org = organizational_domain(decoded_host)
    decoded_label = decoded_org.split(".", 1)[0] if decoded_org else label
    folded_label = "".join(HOMOGLYPH_MAP.get(ch, ch) for ch in decoded_label)
    leet_label = folded_label.translate(_LEET_TRANS).replace("rn", "m")

    for brand, official_domains in PROTECTED_BRANDS.items():
        if org in official_domains or host in official_domains:
            continue
        brand_slug = brand.replace(" ", "")
        if len(brand_slug) < 4:
            continue

        # Exact match after homoglyph/leet folding (e.g., g00gle.com, paypa1.com, googlе.com)
        if leet_label == brand_slug and label != brand_slug:
            return brand
        if folded_label == brand_slug and decoded_label != brand_slug:
            return brand
        # Brand embedded with phishing affixes (e.g. paypal-secure.com, google-verify.net)
        if brand_slug in leet_label and org not in official_domains:
            if any(
                kw in leet_label
                for kw in ("login", "secure", "verify", "account", "support", "alert", "update", "bank", "signin")
            ):
                return brand
        # Close Levenshtein distance (1 edit for short brands, <=2 for longer brands)
        max_dist = 1 if len(brand_slug) <= 6 else 2
        if abs(len(leet_label) - len(brand_slug)) <= max_dist:
            dist = _levenshtein(leet_label, brand_slug)
            if 0 < dist <= max_dist:
                return brand

    return None


def _extract_anchor_domain(anchor_text: str) -> str | None:
    if not anchor_text:
        return None
    stripped = anchor_text.strip()
    if " " in stripped and not stripped.lower().startswith(("http://", "https://", "www.")):
        return None
    m = _ANCHOR_DOMAIN_RE.search(stripped)
    if not m:
        return None
    return m.group(1).lower()


class UrlAnalysisStage(PipelineStage):
    """Stage 4: Analyze extracted links for phishing heuristics and threat intelligence."""

    name = "url_analysis"

    def __init__(
        self,
        config: DetectorConfig | None = None,
        enricher: ThreatIntelEnricher | None = None,
    ) -> None:
        super().__init__(config)
        self.enricher = enricher or ThreatIntelEnricher(
            blocklisted_domains=self.config.blocklisted_domains,
            timeout=self.config.enrichment_timeout_seconds,
            max_redirects=self.config.max_redirects,
        )

    def _is_allowlisted(self, host: str) -> bool:
        if not host:
            return False
        org = organizational_domain(host)
        return host in self.config.allowlisted_domains or org in self.config.allowlisted_domains

    def analyze_link(self, link: ExtractedLink, context: PipelineContext) -> None:
        url = link.normalized_url.strip()
        if not url:
            return

        parsed = urlparse(url)
        scheme = (parsed.scheme or "").lower()

        if scheme in _DANGEROUS_SCHEMES:
            context.add_finding(
                Finding(
                    stage=self.name,
                    rule_id="URL_DANGEROUS_SCHEME",
                    title=f"Dangerous URI scheme ({scheme}:)",
                    description=f"Link uses dangerous non-HTTP scheme '{scheme}:' capable of script execution or smuggling.",
                    score=self.config.weights.get("URL_DANGEROUS_SCHEME", 6),
                    severity=Severity.CRITICAL,
                    evidence={"url": url, "scheme": scheme},
                )
            )
            return

        if scheme not in ("http", "https"):
            return

        host = (parsed.hostname or "").lower()
        link.domain = host

        if not host:
            return

        # Check '@' credential trick in netloc (e.g., https://google.com@evil.xyz)
        if "@" in (parsed.netloc or ""):
            context.add_finding(
                Finding(
                    stage=self.name,
                    rule_id="URL_CREDENTIAL_AT_SIGN",
                    title="URL uses '@' userinfo obfuscation",
                    description=f"URL '{url}' contains '@' to disguise the actual destination host '{host}'.",
                    score=self.config.weights.get("URL_CREDENTIAL_AT_SIGN", 5),
                    severity=Severity.HIGH,
                    evidence={"url": url, "real_host": host},
                )
            )

        # Decode Punycode / IDN homographs
        decoded_host, is_punycode, is_homograph = _decode_punycode_host(host)
        link.decoded_domain = decoded_host
        link.is_punycode = is_punycode
        link.is_idn_homograph = is_homograph

        if is_homograph:
            context.add_finding(
                Finding(
                    stage=self.name,
                    rule_id="URL_PUNYCODE_HOMOGRAPH",
                    title="Punycode / IDN homograph domain detected",
                    description=(
                        f"Domain '{host}' decodes to '{decoded_host}', indicating potential "
                        "internationalized visual spoofing."
                    ),
                    score=self.config.weights.get("URL_PUNYCODE_HOMOGRAPH", 5),
                    severity=Severity.HIGH,
                    evidence={"raw_domain": host, "decoded_domain": decoded_host, "url": url},
                )
            )

        if self._is_allowlisted(host):
            return

        # IP-based URL check (+5)
        if _is_ip_host(host):
            link.is_ip_url = True
            context.add_finding(
                Finding(
                    stage=self.name,
                    rule_id="URL_IP_BASED",
                    title="Direct IP-based URL detected",
                    description=f"URL points directly to IP address '{host}' instead of a legitimate domain.",
                    score=self.config.weights.get("URL_IP_BASED", 5),
                    severity=Severity.HIGH,
                    evidence={"url": url, "host": host},
                )
            )

        # Exact URL shortener host check (+3)
        if host in URL_SHORTENERS or (host.startswith("www.") and host[4:] in URL_SHORTENERS):
            link.is_shortener = True
            context.add_finding(
                Finding(
                    stage=self.name,
                    rule_id="URL_SHORTENER",
                    title="URL shortener service used",
                    description=f"Link uses shortener '{host}' to obscure the final destination.",
                    score=self.config.weights.get("URL_SHORTENER", 3),
                    severity=Severity.MEDIUM,
                    evidence={"url": url, "shortener": host},
                )
            )

        # Exact risky TLD suffix check (+4)
        for tld in RISKY_TLDS:
            if host.endswith(tld):
                link.has_risky_tld = True
                context.add_finding(
                    Finding(
                        stage=self.name,
                        rule_id="URL_RISKY_TLD",
                        title=f"High-risk TLD detected ({tld})",
                        description=f"Destination domain '{host}' uses high-risk top-level domain '{tld}'.",
                        score=self.config.weights.get("URL_RISKY_TLD", 4),
                        severity=Severity.HIGH,
                        evidence={"url": url, "domain": host, "tld": tld},
                    )
                )
                break

        # Visual spoofing: anchor text domain != destination domain (+5)
        anchor_domain = _extract_anchor_domain(link.anchor_text)
        if anchor_domain:
            anchor_org = organizational_domain(anchor_domain)
            dest_org = organizational_domain(host)
            if anchor_org and dest_org and anchor_org != dest_org:
                link.is_visual_spoof = True
                context.add_finding(
                    Finding(
                        stage=self.name,
                        rule_id="URL_VISUAL_SPOOFING",
                        title="Visual link spoofing (anchor text mismatches destination)",
                        description=(
                            f"Visible anchor text '{link.anchor_text}' displays domain '{anchor_domain}' "
                            f"but actually redirects to '{decoded_host or host}'."
                        ),
                        score=self.config.weights.get("URL_VISUAL_SPOOFING", 5),
                        severity=Severity.HIGH,
                        evidence={
                            "anchor_text": link.anchor_text,
                            "anchor_domain": anchor_domain,
                            "destination_domain": decoded_host or host,
                            "url": url,
                        },
                    )
                )

        # Brand typosquatting (+5)
        spoofed_brand = _detect_brand_typosquatting(host, decoded_host)
        if spoofed_brand:
            context.add_finding(
                Finding(
                    stage=self.name,
                    rule_id="URL_BRAND_TYPOSQUATTING",
                    title=f"Brand typosquatting domain mimicking '{spoofed_brand}'",
                    description=(
                        f"Domain '{decoded_host or host}' closely mimics protected brand "
                        f"'{spoofed_brand}'."
                    ),
                    score=self.config.weights.get("URL_BRAND_TYPOSQUATTING", 5),
                    severity=Severity.HIGH,
                    evidence={"domain": decoded_host or host, "brand": spoofed_brand, "url": url},
                )
            )

        # Excessive subdomains hiding real domain (e.g., paypal.com.verify.evil.com)
        labels = host.split(".")
        if len(labels) >= 4 and not link.is_ip_url:
            sub_part = ".".join(labels[:-2])
            if any(b.replace(" ", "") in sub_part for b in PROTECTED_BRANDS) or any(
                kw in sub_part for kw in SUSPICIOUS_URL_PATH_KEYWORDS
            ):
                context.add_finding(
                    Finding(
                        stage=self.name,
                        rule_id="URL_EXCESSIVE_SUBDOMAINS",
                        title="Suspicious multi-level subdomain structure",
                        description=(
                            f"Domain '{host}' nests brand/security keywords inside deep subdomains "
                            "to disguise the true root domain."
                        ),
                        score=self.config.weights.get("URL_EXCESSIVE_SUBDOMAINS", 3),
                        severity=Severity.MEDIUM,
                        evidence={"domain": host, "url": url},
                    )
                )

        # Suspicious credential/login path on plain HTTP or suspicious domain
        path_lower = (parsed.path or "").lower()
        if any(kw in path_lower for kw in SUSPICIOUS_URL_PATH_KEYWORDS):
            if scheme == "http" or link.has_risky_tld or link.is_ip_url or spoofed_brand:
                context.add_finding(
                    Finding(
                        stage=self.name,
                        rule_id="URL_SUSPICIOUS_LOGIN_PATH",
                        title="Suspicious credential/login path on untrusted URL",
                        description=f"URL '{url}' exposes a login/verification path over an untrusted or unencrypted host.",
                        score=self.config.weights.get("URL_SUSPICIOUS_LOGIN_PATH", 2),
                        severity=Severity.MEDIUM,
                        evidence={"url": url, "path": parsed.path},
                    )
                )

        # Offline local blocklist check (always active)
        local_hits = self.enricher.check_local(url, host)
        if local_hits:
            link.reputation_hits.extend(local_hits)
            context.add_finding(
                Finding(
                    stage=self.name,
                    rule_id="URL_THREAT_INTEL_HIT",
                    title="URL matched local threat blocklist",
                    description=f"Domain '{host}' matched local blocklist: {', '.join(local_hits)}.",
                    score=self.config.weights.get("URL_THREAT_INTEL_HIT", 8),
                    severity=Severity.CRITICAL,
                    evidence={"url": url, "hits": local_hits},
                )
            )

        # Opt-in external threat intelligence enrichment
        if context.enable_external_enrichment or self.config.enable_external_enrichment:
            self._enrich_externally(link, host, url, context)

    def _enrich_externally(
        self, link: ExtractedLink, host: str, url: str, context: PipelineContext
    ) -> None:
        # 1. Safe unshortening
        if link.is_shortener:
            resolved = self.enricher.unshortener.resolve(url)
            if resolved:
                link.resolved_url = resolved
                resolved_link = ExtractedLink(
                    original_url=resolved,
                    normalized_url=resolved,
                    anchor_text=link.anchor_text,
                    source="unshortened_redirect",
                )
                self.analyze_link(resolved_link, context)

        # 2. RDAP domain age check
        if not link.is_ip_url:
            org = organizational_domain(host)
            age_days = self.enricher.rdap_client.get_domain_age_days(org)
            if age_days is not None:
                link.domain_age_days = age_days
                if age_days < self.config.newly_registered_days:
                    context.add_finding(
                        Finding(
                            stage=self.name,
                            rule_id="URL_NEWLY_REGISTERED_DOMAIN",
                            title="Newly registered domain detected via RDAP",
                            description=(
                                f"Domain '{org}' was registered only {age_days} day(s) ago "
                                f"(threshold: {self.config.newly_registered_days} days)."
                            ),
                            score=self.config.weights.get("URL_NEWLY_REGISTERED_DOMAIN", 4),
                            severity=Severity.HIGH,
                            evidence={"domain": org, "age_days": age_days},
                        )
                    )

        # 3. External reputation feeds (URLhaus, VirusTotal, Google Safe Browsing)
        ext_hits = self.enricher.check_external(url, host)
        if ext_hits:
            link.reputation_hits.extend(ext_hits)
            context.add_finding(
                Finding(
                    stage=self.name,
                    rule_id="URL_THREAT_INTEL_HIT",
                    title="URL flagged by external Threat Intelligence",
                    description=f"External threat feeds flagged '{url}': {', '.join(ext_hits)}.",
                    score=self.config.weights.get("URL_THREAT_INTEL_HIT", 8),
                    severity=Severity.CRITICAL,
                    evidence={"url": url, "hits": ext_hits},
                )
            )

    def run(self, context: PipelineContext) -> PipelineContext:
        for link in list(context.normalized.links):
            self.analyze_link(link, context)
        return context
