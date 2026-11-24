"""Unit tests for Stage 2: Authentication & Header Analysis."""

from phishing_detector.config import DetectorConfig
from phishing_detector.models import PipelineContext
from phishing_detector.stages.headers import HeaderAuthStage, organizational_domain
from phishing_detector.stages.ingestion import MimeIngestionStage


def _ingest_raw(raw_eml: str) -> PipelineContext:
    msg = MimeIngestionStage().parse_string(raw_eml)
    return PipelineContext(email=msg)


def test_spf_dkim_dmarc_failures_emit_findings():
    raw = (
        "From: Security <security@example.com>\r\n"
        "To: victim@corp.local\r\n"
        "Subject: Alert\r\n"
        "Message-ID: <1@example.com>\r\n"
        "Authentication-Results: mx.corp.local; spf=fail; dkim=fail; dmarc=fail\r\n"
        "\r\n"
        "Body\r\n"
    )
    ctx = _ingest_raw(raw)
    HeaderAuthStage().execute(ctx)

    rule_ids = {f.rule_id for f in ctx.findings}
    assert ctx.headers.spf_result == "fail"
    assert ctx.headers.dkim_result == "fail"
    assert ctx.headers.dmarc_result == "fail"
    assert {"AUTH_SPF_FAIL", "AUTH_DKIM_FAIL", "AUTH_DMARC_FAIL"}.issubset(rule_ids)


def test_identity_alignment_and_display_name_brand_spoof():
    raw = (
        "From: PayPal Security <alerts@evil-billing.xyz>\r\n"
        "Return-Path: <bounce@mailer-bot.top>\r\n"
        "Reply-To: harvest@collector.click\r\n"
        "Message-ID: <abc@evil-billing.xyz>\r\n"
        "Subject: Verify account\r\n"
        "\r\n"
        "Please verify.\r\n"
    )
    ctx = _ingest_raw(raw)
    HeaderAuthStage().execute(ctx)

    rule_ids = {f.rule_id for f in ctx.findings}
    assert ctx.headers.display_name_spoof is True
    assert "HEADER_DISPLAY_NAME_SPOOF" in rule_ids
    assert "HEADER_FROM_RETURN_PATH_MISMATCH" in rule_ids
    assert "HEADER_FROM_REPLY_TO_MISMATCH" in rule_ids


def test_display_name_embedded_email_spoof():
    raw = (
        'From: "ceo@mycompany.com" <attacker@freemail.xyz>\r\n'
        "Message-ID: <123@freemail.xyz>\r\n"
        "Subject: Wire transfer\r\n\r\nHi\r\n"
    )
    ctx = _ingest_raw(raw)
    HeaderAuthStage().execute(ctx)
    assert ctx.headers.display_name_spoof is True
    assert any(f.rule_id == "HEADER_DISPLAY_NAME_SPOOF" for f in ctx.findings)


def test_received_hops_extract_originating_public_ip_and_check_blocklist():
    raw = (
        "Received: from mx2.corp.local (10.0.0.5) by inbox.corp.local; Tue, 24 Nov 2026 12:01:00 +0000\r\n"
        "Received: from bad-relay.net ([93.184.216.34]) by mx2.corp.local; Tue, 24 Nov 2026 12:00:00 +0000\r\n"
        "From: user@trusted.org\r\n"
        "Return-Path: <bounce@mail.trusted.org>\r\n"
        "Message-ID: <ok@trusted.org>\r\n"
        "Authentication-Results: mx2.corp.local; spf=pass; dkim=pass; dmarc=pass\r\n"
        "Subject: Hello\r\n\r\nHello\r\n"
    )
    cfg = DetectorConfig(blocklisted_ips={"93.184.216.34"})
    ctx = _ingest_raw(raw)
    HeaderAuthStage(cfg).execute(ctx)

    assert len(ctx.headers.received_hops) == 2
    assert ctx.headers.originating_ip == "93.184.216.34"
    assert any(f.rule_id == "HEADER_BLOCKLISTED_IP" for f in ctx.findings)
    # Subdomain alignment (mail.trusted.org == trusted.org) should NOT trigger mismatch
    assert not any(f.rule_id == "HEADER_FROM_RETURN_PATH_MISMATCH" for f in ctx.findings)


def test_organizational_domain_handles_multilevel_cctld():
    assert organizational_domain("mail.bank.co.uk") == "bank.co.uk"
    assert organizational_domain("notify.santander.cl") == "santander.cl"
