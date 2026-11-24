"""Stage 6: Semantic content analysis, BEC / social engineering detection, and lightweight ML classifier."""

from __future__ import annotations

from collections import Counter
import math
import re
import unicodedata

from phishing_detector.config import DetectorConfig, URGENCY_PATTERN
from phishing_detector.models import (
    Finding,
    PipelineContext,
    SemanticAnalysis,
    Severity,
)
from phishing_detector.stages.base import PipelineStage


_AUTHORITY_PATTERN = re.compile(
    r"\b("
    r"ceo|cfo|director general|gerente general|presidencia|recursos humanos|"
    r"departamento de finanzas|soporte t[eé]cnico|administrador del sistema|"
    r"executive|managing director|finance department|hr department|it security|"
    r"board of directors|chief executive|estoy en una reuni[oó]n|i am in a meeting"
    r")\b",
    re.IGNORECASE,
)

_FINANCIAL_PATTERN = re.compile(
    r"\b("
    r"transferencia bancaria|transferencia urgente|wire transfer|bank transfer|"
    r"tarjetas? de regalo|gift cards?|apple gift|google play card|"
    r"cambio de cuenta bancaria|new bank account|updated bank details|"
    r"factura pendiente|overdue invoice|pago inmediato|urgent payment|"
    r"iban|swift|routing number|bitcoin|usdt|criptomonedas|depositar hoy"
    r")\b",
    re.IGNORECASE,
)

_SECRECY_PATTERN = re.compile(
    r"\b("
    r"estrictamente confidencial|mant[eé]n esto en reserva|no me llames|"
    r"no llames|solo responde por correo|entre nosotros|m[aá]xima discreci[oó]n|"
    r"strictly confidential|keep this confidential|do not call|don't call|"
    r"reply by email only|between us|handle discreetly|secret acquisition"
    r")\b",
    re.IGNORECASE,
)

_CREDENTIAL_PATTERN = re.compile(
    r"\b("
    r"contrase[nñ]a|clave de acceso|c[oó]digo de verificaci[oó]n|c[oó]digo sms|"
    r"token bancario|datos de tarjeta|n[uú]mero de tarjeta|pin de seguridad|"
    r"inicie sesi[oó]n|confirmar credenciales|restablecer contrase[nñ]a|"
    r"password|passcode|verification code|one-time password|otp|mfa code|"
    r"credit card details|social security|sign in immediately|confirm credentials"
    r")\b",
    re.IGNORECASE,
)

_TOKEN_RE = re.compile(r"[a-z0-9áéíóúüñ]{2,}", re.IGNORECASE)

# Curated bilingual training corpus (phishing/BEC = 1, legitimate = 0)
_DEFAULT_TRAINING_CORPUS: list[tuple[str, int]] = [
    # Phishing & BEC (Spanish)
    ("accion requerida cuenta bloqueada verifique su identidad urgente ingrese su contrasena", 1),
    ("estimado cliente su cuenta bancaria ha sido suspendida actualizar datos de inmediato", 1),
    ("alerta de seguridad acceso no autorizado confirme credenciales para evitar bloqueo", 1),
    ("soy el director general estoy en una reunion necesito una transferencia bancaria urgente confidencial no me llames", 1),
    ("urgente comprar tarjetas de regalo apple gift para clientes mantener estrictamente confidencial", 1),
    ("cambio de cuenta bancaria para pago de factura pendiente realizar transferencia hoy mismo", 1),
    ("ultimo aviso su clave de acceso expira hoy valide su token bancario aqui", 1),
    ("paquete retenido en aduana realice pago inmediato actualice datos de tarjeta", 1),
    ("soporte tecnico buzon lleno restablecer contrasena inmediatamente para no perder correos", 1),
    ("factura vencida adjunta abrir archivo html e iniciar sesion con su correo corporativo", 1),
    # Phishing & BEC (English)
    ("urgent action required account suspended verify your account immediately sign in password", 1),
    ("security alert unauthorized access detected confirm credentials or account locked", 1),
    ("i am in a meeting need urgent wire transfer updated bank details keep this confidential do not call", 1),
    ("please purchase gift cards urgently for executive team reply by email only", 1),
    ("overdue invoice final notice update payment details immediately bank transfer swift", 1),
    ("your password expires today reset credentials enter verification code otp", 1),
    ("dhl delivery failed confirm shipping address and credit card details immediately", 1),
    ("hr department confidential bonus document sign in with office365 password", 1),
    # Legitimate emails (Spanish)
    ("hola equipo adjunto las notas de la reunion semanal del proyecto nos vemos el jueves", 0),
    ("confirmacion de reserva de hotel para el proximo mes gracias por su preferencia", 0),
    ("resumen semanal de noticias de tecnologia y arquitectura de software", 0),
    ("buenos dias te envio el informe trimestral revisado para tus comentarios", 0),
    ("recordatorio de clase de matematicas mañana a las diez en la sala cuatro", 0),
    ("gracias por tu compra tu boleta electronica esta disponible en el historial", 0),
    ("invitacion a almuerzo de cumpleaños el viernes en la cafeteria central", 0),
    ("actualizacion del calendario de vacaciones y feriados del semestre", 0),
    ("hola david puedes revisar el pull request cuando tengas un momento gracias", 0),
    ("confirmacion de cita medica programada para el martes por la tarde", 0),
    # Legitimate emails (English)
    ("hi team here are the meeting minutes from our sprint planning session yesterday", 0),
    ("thanks for your pull request the unit tests look clean and well structured", 0),
    ("weekly engineering newsletter featuring python release notes and tutorials", 0),
    ("friendly reminder about our coffee chat tomorrow afternoon at three", 0),
    ("attached is the quarterly roadmap slides for next week review meeting", 0),
    ("order shipped your book package will arrive on friday afternoon", 0),
    ("welcome to the conference schedule and venue map for attendees", 0),
    ("happy birthday wishing you a wonderful weekend with family and friends", 0),
]


def _strip_accents(text: str) -> str:
    nfd = unicodedata.normalize("NFD", text)
    return "".join(ch for ch in nfd if unicodedata.category(ch) != "Mn")


def _tokenize(text: str) -> list[str]:
    clean = _strip_accents(text.lower())
    unigrams = _TOKEN_RE.findall(clean)
    bigrams = [f"{unigrams[i]}_{unigrams[i + 1]}" for i in range(len(unigrams) - 1)]
    return unigrams + bigrams


class NaiveBayesPhishingClassifier:
    """Explainable, lightweight multinomial Naive Bayes text classifier (unigrams + bigrams)."""

    def __init__(self, alpha: float = 1.0) -> None:
        self.alpha = alpha
        self.phish_counts: Counter[str] = Counter()
        self.ham_counts: Counter[str] = Counter()
        self.phish_total = 0
        self.ham_total = 0
        self.phish_docs = 0
        self.ham_docs = 0
        self.vocab: set[str] = set()

    def fit(self, samples: list[tuple[str, int]]) -> "NaiveBayesPhishingClassifier":
        for text, label in samples:
            tokens = _tokenize(text)
            self.vocab.update(tokens)
            if label == 1:
                self.phish_docs += 1
                self.phish_counts.update(tokens)
                self.phish_total += len(tokens)
            else:
                self.ham_docs += 1
                self.ham_counts.update(tokens)
                self.ham_total += len(tokens)
        return self

    def predict(self, text: str) -> tuple[float, list[str]]:
        """Return (phishing_probability, top_contributing_features)."""
        tokens = _tokenize(text)
        if not tokens or not self.vocab:
            return 0.0, []

        total_docs = self.phish_docs + self.ham_docs
        log_prior_phish = math.log((self.phish_docs + 1) / (total_docs + 2))
        log_prior_ham = math.log((self.ham_docs + 1) / (total_docs + 2))

        vocab_size = len(self.vocab)
        denom_phish = self.phish_total + self.alpha * vocab_size
        denom_ham = self.ham_total + self.alpha * vocab_size

        log_p_phish = log_prior_phish
        log_p_ham = log_prior_ham
        feature_contributions: dict[str, float] = {}
        matched_vocab_tokens = 0

        for tok in tokens:
            if tok not in self.vocab:
                continue
            matched_vocab_tokens += 1
            lp_phish = math.log((self.phish_counts[tok] + self.alpha) / denom_phish)
            lp_ham = math.log((self.ham_counts[tok] + self.alpha) / denom_ham)
            log_p_phish += lp_phish
            log_p_ham += lp_ham
            llr = lp_phish - lp_ham
            if llr > 0:
                feature_contributions[tok] = feature_contributions.get(tok, 0.0) + llr

        # Require at least 2 known vocabulary tokens to avoid noisy predictions on tiny text
        if matched_vocab_tokens < 2:
            return 0.0, []

        # Numerically stable sigmoid on log-odds
        log_odds = max(-30.0, min(30.0, log_p_phish - log_p_ham))
        prob = 1.0 / (1.0 + math.exp(-log_odds))

        top_features = [
            feat for feat, _ in sorted(feature_contributions.items(), key=lambda x: x[1], reverse=True)[:5]
        ]
        return round(prob, 4), top_features


class SemanticAnalysisStage(PipelineStage):
    """Stage 6: Social engineering intent analysis, BEC detection, and ML classification."""

    name = "semantic"

    def __init__(
        self,
        config: DetectorConfig | None = None,
        classifier: NaiveBayesPhishingClassifier | None = None,
    ) -> None:
        super().__init__(config)
        if classifier is None:
            self.classifier = NaiveBayesPhishingClassifier().fit(_DEFAULT_TRAINING_CORPUS)
        else:
            self.classifier = classifier

    def run(self, context: PipelineContext) -> PipelineContext:
        text = context.normalized.combined_text
        if not text:
            # Fallback if normalization stage was skipped in isolated unit tests
            text = " ".join(
                p for p in (context.email.subject, context.email.text_plain, context.email.text_html) if p
            ).strip()

        analysis = SemanticAnalysis()
        if not text:
            context.semantic = analysis
            return context

        # 1. Extract unique lowercased intent matches
        urgency = sorted({m.lower() for m in URGENCY_PATTERN.findall(text)})
        authority = sorted({m.lower() for m in _AUTHORITY_PATTERN.findall(text)})
        financial = sorted({m.lower() for m in _FINANCIAL_PATTERN.findall(text)})
        secrecy = sorted({m.lower() for m in _SECRECY_PATTERN.findall(text)})
        credentials = sorted({m.lower() for m in _CREDENTIAL_PATTERN.findall(text)})

        analysis.urgency_matches = urgency
        analysis.authority_matches = authority
        analysis.financial_matches = financial
        analysis.secrecy_matches = secrecy
        analysis.credential_matches = credentials

        if urgency:
            analysis.detected_intents.append("artificial_urgency")
            per_kw = self.config.weights.get("SEMANTIC_URGENCY_KEYWORD", 2)
            # Matches README: +2 per unique urgency keyword match
            context.add_finding(
                Finding(
                    stage=self.name,
                    rule_id="SEMANTIC_URGENCY_KEYWORD",
                    title="Artificial urgency / pressure language detected",
                    description=f"Detected {len(urgency)} unique urgency cue(s): {', '.join(urgency)}.",
                    score=len(urgency) * per_kw,
                    severity=Severity.MEDIUM if len(urgency) == 1 else Severity.HIGH,
                    evidence={"keywords": urgency},
                )
            )

        if authority:
            analysis.detected_intents.append("authority_reference")
        if financial:
            analysis.detected_intents.append("financial_request")
        if secrecy:
            analysis.detected_intents.append("secrecy_bypass")
        if credentials:
            analysis.detected_intents.append("credential_request")

        # 2. BEC (Business Email Compromise) synthesis (works even with zero links/attachments!)
        if (financial and secrecy) or (financial and authority and (urgency or secrecy)):
            analysis.bec_suspected = True
            analysis.detected_intents.append("bec_fraud")
            context.add_finding(
                Finding(
                    stage=self.name,
                    rule_id="SEMANTIC_BEC_PATTERN",
                    title="Business Email Compromise (BEC) social engineering pattern",
                    description=(
                        "Email combines financial request cues with executive authority and/or secrecy "
                        "tactics typical of CEO fraud / BEC attacks."
                    ),
                    score=self.config.weights.get("SEMANTIC_BEC_PATTERN", 5),
                    severity=Severity.CRITICAL,
                    evidence={
                        "authority": authority,
                        "financial": financial,
                        "secrecy": secrecy,
                    },
                )
            )
        elif authority and financial:
            analysis.bec_suspected = True
            context.add_finding(
                Finding(
                    stage=self.name,
                    rule_id="SEMANTIC_AUTHORITY_FINANCIAL",
                    title="Executive/authority financial request detected",
                    description="Email combines authority impersonation indicators with a financial request.",
                    score=self.config.weights.get("SEMANTIC_AUTHORITY_FINANCIAL", 4),
                    severity=Severity.HIGH,
                    evidence={"authority": authority, "financial": financial},
                )
            )

        # 3. Credential harvesting language
        if credentials and (urgency or context.normalized.links or context.normalized.form_actions):
            context.add_finding(
                Finding(
                    stage=self.name,
                    rule_id="SEMANTIC_CREDENTIAL_HARVEST",
                    title="Credential harvesting language detected",
                    description=(
                        f"Email solicits sensitive credentials ({', '.join(credentials[:4])}) "
                        "alongside urgency cues or interactive links."
                    ),
                    score=self.config.weights.get("SEMANTIC_CREDENTIAL_HARVEST", 3),
                    severity=Severity.HIGH,
                    evidence={"credential_cues": credentials},
                )
            )

        # 4. Lightweight ML classifier score
        prob, top_features = self.classifier.predict(text)
        analysis.ml_phishing_probability = prob
        analysis.ml_top_features = top_features

        if prob >= 0.85:
            context.add_finding(
                Finding(
                    stage=self.name,
                    rule_id="SEMANTIC_ML_HIGH_PROBABILITY",
                    title=f"ML classifier high phishing confidence ({prob:.0%})",
                    description=(
                        f"NLP Naive Bayes model scored phishing probability at {prob:.1%}. "
                        f"Top signals: {', '.join(top_features)}."
                    ),
                    score=self.config.weights.get("SEMANTIC_ML_HIGH_PROBABILITY", 4),
                    severity=Severity.HIGH,
                    evidence={"probability": prob, "top_features": top_features},
                )
            )
        elif prob >= 0.68:
            context.add_finding(
                Finding(
                    stage=self.name,
                    rule_id="SEMANTIC_ML_MEDIUM_PROBABILITY",
                    title=f"ML classifier elevated phishing likelihood ({prob:.0%})",
                    description=(
                        f"NLP Naive Bayes model scored phishing probability at {prob:.1%}. "
                        f"Top signals: {', '.join(top_features)}."
                    ),
                    score=self.config.weights.get("SEMANTIC_ML_MEDIUM_PROBABILITY", 2),
                    severity=Severity.MEDIUM,
                    evidence={"probability": prob, "top_features": top_features},
                )
            )

        context.semantic = analysis
        return context
