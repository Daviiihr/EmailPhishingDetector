"""Unit tests for Stage 4: URL Analysis & Threat Intelligence."""

from datetime import datetime, timedelta, timezone

from phishing_detector.config import DetectorConfig
from phishing_detector.enrichment.threat_intel import (
    RdapDomainAgeClient,
    SafeRedirectUnshortener,
    ThreatIntelEnricher,
    ThreatIntelProvider,
)
from phishing_detector.models import ExtractedLink, NormalizedContent, PipelineContext
from phishing_detector.stages.url_analysis import UrlAnalysisStage


class StubThreatProvider(ThreatIntelProvider):
    name = "stub_feed"

    def check_url(self, url: str, domain: str) -> str | None:
        if "malicious-feed.org" in domain:
            return "stub_feed:phishing"
        return None


def _run_url_stage(links: list[ExtractedLink], *, config=None, enricher=None) -> PipelineContext:
    ctx = PipelineContext(normalized=NormalizedContent(links=links))
    UrlAnalysisStage(config=config, enricher=enricher).execute(ctx)
    return ctx


def test_visual_spoofing_punycode_and_scores_properly():
    link = ExtractedLink(
        original_url="http://xn--googl-0qa.com/login",
        normalized_url="http://xn--googl-0qa.com/login",
        anchor_text="https://www.google.com/login",
    )
    ctx = _run_url_stage([link])
    rules = {f.rule_id: f.score for f in ctx.findings}

    assert link.is_punycode is True
    assert link.is_visual_spoof is True
    assert rules["URL_PUNYCODE_HOMOGRAPH"] == 5
    assert rules["URL_VISUAL_SPOOFING"] == 5


def test_ip_url_shortener_and_risky_tld_without_false_positives():
    links = [
        ExtractedLink("http://192.0.2.55/login", "http://192.0.2.55/login"),
        ExtractedLink("https://bit.ly/abc123", "https://bit.ly/abc123"),
        ExtractedLink("https://verify-billing.xyz/auth", "https://verify-billing.xyz/auth"),
        # Benign domains that previously caused substring false positives (.cc in account, t.co in best.com, .top in laptop.com)
        ExtractedLink("https://account.best.com/laptop", "https://account.best.com/laptop"),
    ]
    ctx = _run_url_stage(links)
    rule_ids = [f.rule_id for f in ctx.findings]

    assert "URL_IP_BASED" in rule_ids
    assert "URL_SHORTENER" in rule_ids
    assert "URL_RISKY_TLD" in rule_ids
    # Benign link should not be flagged
    benign = links[3]
    assert benign.is_shortener is False
    assert benign.has_risky_tld is False
    assert benign.is_ip_url is False


def test_typosquatting_credential_at_sign_and_subdomains():
    links = [
        ExtractedLink("https://paypa1.com/signin", "https://paypa1.com/signin"),
        ExtractedLink("https://google.com@evil-login.net/auth", "https://google.com@evil-login.net/auth"),
        ExtractedLink("https://paypal.com.verify.account.evil.org/step1", "https://paypal.com.verify.account.evil.org/step1"),
    ]
    ctx = _run_url_stage(links)
    rule_ids = {f.rule_id for f in ctx.findings}

    assert "URL_BRAND_TYPOSQUATTING" in rule_ids
    assert "URL_CREDENTIAL_AT_SIGN" in rule_ids
    assert "URL_EXCESSIVE_SUBDOMAINS" in rule_ids


def test_external_enrichment_unshortener_rdap_and_threat_intel():
    recent_date = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()

    def fake_head(url: str, timeout: float):
        if "bit.ly" in url:
            return 302, "https://malicious-feed.org/steal"
        return 200, None

    def fake_rdap(url: str, timeout: float):
        return {"events": [{"eventAction": "registration", "eventDate": recent_date}]}

    enricher = ThreatIntelEnricher(
        unshortener=SafeRedirectUnshortener(
            host_safety_check=lambda h: True, http_head=fake_head
        ),
        rdap_client=RdapDomainAgeClient(fetcher=fake_rdap),
        providers=[StubThreatProvider()],
    )
    cfg = DetectorConfig(enable_external_enrichment=True)
    link = ExtractedLink("https://bit.ly/phish", "https://bit.ly/phish")
    ctx = _run_url_stage([link], config=cfg, enricher=enricher)

    rule_ids = {f.rule_id for f in ctx.findings}
    assert link.resolved_url == "https://malicious-feed.org/steal"
    assert "URL_NEWLY_REGISTERED_DOMAIN" in rule_ids
    assert "URL_THREAT_INTEL_HIT" in rule_ids


def test_ssrf_guard_blocks_private_ip_redirect():
    unshortener = SafeRedirectUnshortener(
        http_head=lambda u, t: (200, None),
    )
    assert unshortener.resolve("http://127.0.0.1/admin") is None
    assert unshortener.resolve("http://10.0.0.1/internal") is None
