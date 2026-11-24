"""Unit tests for Stage 1: MIME / RFC 5322 Ingestion."""

from email.message import EmailMessage as StdEmailMessage

from phishing_detector.config import DetectorConfig
from phishing_detector.models import EmailMessage, PipelineContext
from phishing_detector.stages.ingestion import MimeIngestionStage, decode_mime_header


def _build_sample_multipart_eml() -> bytes:
    msg = StdEmailMessage()
    msg["From"] = "Soporte Banco <alertas@banco-seguro.com>"
    msg["To"] = "cliente@ejemplo.cl"
    msg["Reply-To"] = "respuestas@attacker.xyz"
    msg["Return-Path"] = "<bounce@mailer-externo.top>"
    msg["Subject"] = "=?utf-8?q?Acci=C3=B3n_Requerida=3A_Cuenta_Bloqueada?="
    msg["Date"] = "Tue, 24 Nov 2026 12:00:00 +0000"
    msg["Message-ID"] = "<abc123@mailer-externo.top>"
    msg.set_content("Texto plano de prueba.")
    msg.add_alternative(
        "<html><body><p>Hola <b>cliente</b></p></body></html>",
        subtype="html",
    )
    msg.add_attachment(
        b"%PDF-1.7\nfake pdf content",
        maintype="application",
        subtype="pdf",
        filename="factura.pdf",
    )
    return msg.as_bytes()


def test_parse_multipart_eml_separates_headers_bodies_and_attachments():
    stage = MimeIngestionStage()
    parsed = stage.parse_bytes(_build_sample_multipart_eml(), source_name="test.eml")

    assert parsed.source_name == "test.eml"
    assert parsed.from_display_name == "Soporte Banco"
    assert parsed.from_address == "alertas@banco-seguro.com"
    assert parsed.reply_to_address == "respuestas@attacker.xyz"
    assert parsed.return_path_address == "bounce@mailer-externo.top"
    assert parsed.to_addresses == ["cliente@ejemplo.cl"]
    assert "Texto plano de prueba." in parsed.text_plain
    assert "<b>cliente</b>" in parsed.text_html
    assert len(parsed.attachments) == 1
    assert parsed.attachments[0].filename == "factura.pdf"
    assert parsed.attachments[0].content_type == "application/pdf"
    assert parsed.attachments[0].payload.startswith(b"%PDF-1.7")


def test_decode_mime_header_rfc2047():
    raw = "=?utf-8?q?Acci=C3=B3n_Requerida=3A_Cuenta_Bloqueada?="
    assert decode_mime_header(raw) == "Acción Requerida: Cuenta Bloqueada"


def test_attachment_size_limit_truncates_and_warns():
    cfg = DetectorConfig(max_attachment_bytes=10)
    stage = MimeIngestionStage(cfg)
    parsed = stage.parse_bytes(_build_sample_multipart_eml())

    assert len(parsed.attachments) == 1
    assert len(parsed.attachments[0].payload) == 10
    assert parsed.attachments[0].size_bytes > 10
    assert any("truncated" in w for w in parsed.parse_warnings)


def test_from_parts_builds_html_and_plain_messages():
    stage = MimeIngestionStage()
    html_msg = stage.from_parts(
        "Aviso", "<p>Contenido <a href='https://example.com'>link</a></p>"
    )
    assert html_msg.text_html != ""
    assert html_msg.text_plain == ""

    plain_msg = stage.from_parts("Aviso", "Solo texto normal")
    assert plain_msg.text_plain == "Solo texto normal"
    assert plain_msg.text_html == ""


def test_stage_execute_parses_raw_bytes_in_context():
    stage = MimeIngestionStage()
    ctx = PipelineContext(email=EmailMessage(raw_bytes=_build_sample_multipart_eml()))
    stage.execute(ctx)

    assert ctx.email.from_address == "alertas@banco-seguro.com"
    assert "ingestion" in ctx.stage_timings_ms
