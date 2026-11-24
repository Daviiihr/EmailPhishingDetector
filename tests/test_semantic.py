"""Unit tests for Stage 6: Semantic NLP, BEC detection, and ML classifier."""

from phishing_detector.models import NormalizedContent, PipelineContext
from phishing_detector.stages.semantic import SemanticAnalysisStage


def test_bec_attack_without_links_or_attachments_is_detected():
    text = (
        "Hola, soy el Director General. Estoy en una reunión y no me llames. "
        "Necesito que realices una transferencia bancaria urgente hoy mismo y mantén esto en reserva. "
        "Solo responde por correo con el comprobante."
    )
    ctx = PipelineContext(normalized=NormalizedContent(combined_text=text))
    SemanticAnalysisStage().execute(ctx)

    rule_ids = {f.rule_id for f in ctx.findings}
    assert ctx.semantic.bec_suspected is True
    assert "SEMANTIC_BEC_PATTERN" in rule_ids
    assert "SEMANTIC_URGENCY_KEYWORD" in rule_ids
    assert ctx.semantic.ml_phishing_probability >= 0.85


def test_legitimate_business_email_has_low_probability_and_no_findings():
    text = (
        "Hola equipo, adjunto las notas de la reunión semanal del proyecto. "
        "Podemos revisar el pull request mañana por la tarde en la cafetería."
    )
    ctx = PipelineContext(normalized=NormalizedContent(combined_text=text))
    SemanticAnalysisStage().execute(ctx)

    assert ctx.semantic.bec_suspected is False
    assert ctx.semantic.ml_phishing_probability < 0.5
    assert ctx.findings == []


def test_urgency_scoring_matches_readme_two_points_per_unique_match():
    text = "Aviso urgente: su cuenta suspendida requiere acción urgente para verificar."
    ctx = PipelineContext(normalized=NormalizedContent(combined_text=text))
    SemanticAnalysisStage().execute(ctx)

    urg_findings = [f for f in ctx.findings if f.rule_id == "SEMANTIC_URGENCY_KEYWORD"]
    assert len(urg_findings) == 1
    # Unique matches: 'urgente', 'cuenta suspendida', 'verificar' -> 3 * 2 = 6
    assert urg_findings[0].score == 6
