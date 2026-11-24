"""Integration tests for Stage 7 Scoring Engine and full PhishingPipeline."""

from email.message import EmailMessage as StdEmailMessage

from phishing_detector import (
    ActionType,
    DetectorConfig,
    PhishingPipeline,
    RiskLevel,
    Verdict,
    analyze_email,
)


def test_full_pipeline_catches_obfuscated_phishing_email():
    subject = "=?utf-8?q?Acci=C3=B3n_Requerida=3A_Cuenta_Bloqueada?="
    body = """
        <html>
          <body>
            <p>Estimado usuario, se requiere acci&#243;n <b>urgente</b>.</p>
            <p>Su c\u200buen\u200bta ha sido suspendida.</p>
            <div style="display:none">Texto oculto para evadir filtros</div>
            <p>Verifique su identidad aqu&#x2F;:
               <a href="http://xn--googl-0qa.com/login">https://www.google.com/login</a>
            </p>
          </body>
        </html>
    """
    report = analyze_email(subject, body, sender="Google Support <alert@verify-login.xyz>")

    assert report.is_phishing is True
    assert report.verdict == Verdict.PHISHING_DETECTED
    assert report.risk_level == RiskLevel.CRITICAL
    assert report.recommended_action == ActionType.BLOCK
    assert report.risk_score >= 20
    rule_ids = {f.rule_id for f in report.findings}
    assert {
        "HEADER_DISPLAY_NAME_SPOOF",
        "HTML_HIDDEN_CSS_TEXT",
        "TEXT_ZERO_WIDTH_OBFUSCATION",
        "URL_PUNYCODE_HOMOGRAPH",
        "URL_VISUAL_SPOOFING",
        "SEMANTIC_URGENCY_KEYWORD",
    }.issubset(rule_ids)
    assert "scoring" in report.stage_timings_ms


def test_full_pipeline_allows_clean_authenticated_eml():
    msg = StdEmailMessage()
    msg["From"] = "Ana Perez <ana.perez@acme.org>"
    msg["To"] = "equipo@acme.org"
    msg["Return-Path"] = "<ana.perez@acme.org>"
    msg["Message-ID"] = "<meeting-42@acme.org>"
    msg["Authentication-Results"] = "mx.acme.org; spf=pass; dkim=pass; dmarc=pass"
    msg["Subject"] = "Notas de la reunion semanal"
    msg.set_content(
        "Hola equipo, adjunto el resumen de nuestra reunion semanal del proyecto. "
        "Nos vemos el jueves en la cafeteria."
    )

    pipeline = PhishingPipeline()
    report = pipeline.analyze_bytes(msg.as_bytes(), source_name="clean.eml")

    assert report.is_phishing is False
    assert report.verdict == Verdict.CLEAN
    assert report.risk_level == RiskLevel.LOW
    assert report.recommended_action == ActionType.ALLOW
    assert report.risk_score == 0


def test_full_pipeline_catches_linkless_bec_fraud():
    msg = StdEmailMessage()
    msg["From"] = "Director General <ceo.office@external-mail.xyz>"
    msg["Reply-To"] = "director.privado@gmail.com"
    msg["Message-ID"] = "<bec-1@external-mail.xyz>"
    msg["Authentication-Results"] = "mx.corp.local; spf=softfail; dkim=none; dmarc=fail"
    msg["Subject"] = "Transferencia urgente y confidencial"
    msg.set_content(
        "Hola, soy el Director General. Estoy en una reunion y no me llames. "
        "Necesito una transferencia bancaria urgente hoy mismo. "
        "Manten esto en reserva y solo responde por correo."
    )

    report = PhishingPipeline().analyze_bytes(msg.as_bytes(), source_name="bec.eml")

    assert report.is_phishing is True
    assert report.semantic_summary["bec_suspected"] is True
    assert report.recommended_action in (ActionType.QUARANTINE, ActionType.BLOCK)


def test_allowlisted_authenticated_domain_reduces_false_positives():
    msg = StdEmailMessage()
    msg["From"] = "Notificaciones <notify@trusted-corp.org>"
    msg["Return-Path"] = "<notify@trusted-corp.org>"
    msg["Message-ID"] = "<n-1@trusted-corp.org>"
    msg["Authentication-Results"] = "mx.corp.local; spf=pass; dkim=pass; dmarc=pass"
    msg["Subject"] = "Recordatorio para verificar datos del evento"
    msg.set_content("Hola equipo, por favor verificar la asistencia al almuerzo del viernes.")

    cfg = DetectorConfig(allowlisted_domains={"trusted-corp.org"})
    report = PhishingPipeline(cfg).analyze_bytes(msg.as_bytes())

    assert report.is_phishing is False
    assert report.verdict == Verdict.CLEAN
