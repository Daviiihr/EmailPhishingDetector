"""Unit tests for Stage 5: Attachment Inspection, Quishing QR, and Sandbox."""

import hashlib
import io
import zipfile

from phishing_detector.config import DetectorConfig
from phishing_detector.models import AttachmentInfo, EmailMessage, PipelineContext
from phishing_detector.stages.attachments import (
    AttachmentInspectionStage,
    QrCodeDecoder,
)


class StubQrDecoder(QrCodeDecoder):
    def decode_urls(self, image_bytes: bytes, content_type: str) -> list[str]:
        return ["http://198.51.100.10/verify.xyz"]


def _make_zip_bytes(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_magic_bytes_mismatch_and_double_extension():
    pe_bytes = b"MZ\x90\x00fake-pe-executable-header"
    att = AttachmentInfo(
        filename="factura.pdf.exe",
        content_type="application/pdf",
        size_bytes=len(pe_bytes),
        payload=pe_bytes,
    )
    renamed_pdf = AttachmentInfo(
        filename="recibo.pdf",
        content_type="application/pdf",
        size_bytes=len(pe_bytes),
        payload=pe_bytes,
    )
    ctx = PipelineContext(email=EmailMessage(attachments=[att, renamed_pdf]))
    AttachmentInspectionStage().execute(ctx)

    rule_ids = {f.rule_id for f in ctx.findings}
    assert "ATTACHMENT_DOUBLE_EXTENSION" in rule_ids
    assert "ATTACHMENT_MAGIC_MISMATCH" in rule_ids
    assert att.sha256 == hashlib.sha256(pe_bytes).hexdigest()


def test_ooxml_macro_and_zip_nested_executable():
    docm_bytes = _make_zip_bytes({"word/document.xml": b"<doc/>", "word/vbaProject.bin": b"macro"})
    zip_bytes = _make_zip_bytes({"readme.txt": b"hi", "invoice.pdf.js": b"WScript.Shell"})

    docm = AttachmentInfo("report.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", len(docm_bytes), docm_bytes)
    archive = AttachmentInfo("docs.zip", "application/zip", len(zip_bytes), zip_bytes)

    ctx = PipelineContext(email=EmailMessage(attachments=[docm, archive]))
    AttachmentInspectionStage().execute(ctx)

    rule_ids = {f.rule_id for f in ctx.findings}
    assert docm.has_macros is True
    assert "ATTACHMENT_OFFICE_MACRO" in rule_ids
    assert "ATTACHMENT_NESTED_DANGEROUS_FILE" in rule_ids


def test_html_smuggling_and_malicious_hash_and_sandbox():
    html_payload = b"<html><script>var b = new Blob([atob('TVo=')]); URL.createObjectURL(b);</script></html>"
    ps1_payload = b"powershell -EncodedCommand SQBFAFgA"
    sha = hashlib.sha256(html_payload).hexdigest()

    cfg = DetectorConfig(blocklisted_hashes={sha})
    att_html = AttachmentInfo("invoice.html", "text/html", len(html_payload), html_payload)
    att_ps1 = AttachmentInfo("update.ps1", "text/plain", len(ps1_payload), ps1_payload)

    ctx = PipelineContext(email=EmailMessage(attachments=[att_html, att_ps1]))
    AttachmentInspectionStage(config=cfg).execute(ctx)

    rule_ids = {f.rule_id for f in ctx.findings}
    assert "ATTACHMENT_HTML_SMUGGLING" in rule_ids
    assert "ATTACHMENT_MALICIOUS_HASH" in rule_ids
    assert "ATTACHMENT_SANDBOX_MALICIOUS" in rule_ids
    assert att_ps1.sandbox_verdict == "malicious"


def test_quishing_qr_code_feeds_extracted_url_into_stage4():
    png_bytes = b"\x89PNG\r\n\x1a\nfake-qr-image"
    img = AttachmentInfo("scan_qr.png", "image/png", len(png_bytes), png_bytes)
    ctx = PipelineContext(email=EmailMessage(attachments=[img]))

    AttachmentInspectionStage(qr_decoder=StubQrDecoder()).execute(ctx)

    rule_ids = {f.rule_id for f in ctx.findings}
    assert img.extracted_qr_urls == ["http://198.51.100.10/verify.xyz"]
    assert "ATTACHMENT_QUISHING_QR_URL" in rule_ids
    # Re-analyzed by Stage 4 URL analyzer as direct IP URL!
    assert "URL_IP_BASED" in rule_ids
