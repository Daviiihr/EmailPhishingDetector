"""Centralized configuration: IoCs, scoring weights, thresholds, and rule catalogs."""

from __future__ import annotations

from dataclasses import dataclass, field
import re


# ---------------------------------------------------------------------------
# Scoring weights (aligned with README specification + extended stages)
# ---------------------------------------------------------------------------

DEFAULT_SCORING_WEIGHTS: dict[str, int] = {
    # Stage 2: Authentication & Headers
    "AUTH_SPF_FAIL": 4,
    "AUTH_SPF_SOFTFAIL": 2,
    "AUTH_DKIM_FAIL": 4,
    "AUTH_DMARC_FAIL": 5,
    "HEADER_FROM_RETURN_PATH_MISMATCH": 2,
    "HEADER_FROM_REPLY_TO_MISMATCH": 3,
    "HEADER_DISPLAY_NAME_SPOOF": 5,
    "HEADER_MISSING_MESSAGE_ID": 1,
    "HEADER_SUSPICIOUS_HOP": 2,
    "HEADER_BLOCKLISTED_IP": 6,
    # Stage 3: Normalization & Deobfuscation
    "HTML_HIDDEN_CSS_TEXT": 4,
    "TEXT_ZERO_WIDTH_OBFUSCATION": 3,
    "TEXT_BIDI_OVERRIDE": 6,
    "TEXT_HOMOGLYPH_OBFUSCATION": 4,
    "HTML_EXTERNAL_FORM": 4,
    "HTML_META_REFRESH": 3,
    # Stage 4: URL Analysis & Threat Intelligence
    "URL_IP_BASED": 5,
    "URL_VISUAL_SPOOFING": 5,
    "URL_RISKY_TLD": 4,
    "URL_SHORTENER": 3,
    "URL_PUNYCODE_HOMOGRAPH": 5,
    "URL_CREDENTIAL_AT_SIGN": 5,
    "URL_EXCESSIVE_SUBDOMAINS": 3,
    "URL_BRAND_TYPOSQUATTING": 5,
    "URL_DANGEROUS_SCHEME": 6,
    "URL_NEWLY_REGISTERED_DOMAIN": 4,
    "URL_THREAT_INTEL_HIT": 8,
    "URL_SUSPICIOUS_LOGIN_PATH": 2,
    # Stage 5: Attachments & Quishing
    "ATTACHMENT_DANGEROUS_EXTENSION": 6,
    "ATTACHMENT_DOUBLE_EXTENSION": 6,
    "ATTACHMENT_MAGIC_MISMATCH": 6,
    "ATTACHMENT_OFFICE_MACRO": 7,
    "ATTACHMENT_ENCRYPTED_ARCHIVE": 4,
    "ATTACHMENT_NESTED_DANGEROUS_FILE": 7,
    "ATTACHMENT_MALICIOUS_HASH": 10,
    "ATTACHMENT_HTML_SMUGGLING": 5,
    "ATTACHMENT_QUISHING_QR_URL": 4,
    "ATTACHMENT_SANDBOX_MALICIOUS": 10,
    # Stage 6: Semantic / NLP / BEC
    "SEMANTIC_URGENCY_KEYWORD": 2,  # per unique keyword match
    "SEMANTIC_BEC_PATTERN": 5,
    "SEMANTIC_CREDENTIAL_HARVEST": 3,
    "SEMANTIC_AUTHORITY_FINANCIAL": 4,
    "SEMANTIC_ML_HIGH_PROBABILITY": 4,
    "SEMANTIC_ML_MEDIUM_PROBABILITY": 2,
}


@dataclass
class DetectorConfig:
    """Runtime configuration for the multi-layer phishing detection pipeline."""

    phishing_threshold: int = 5
    warn_threshold: int = 3
    critical_threshold: int = 12
    weights: dict[str, int] = field(
        default_factory=lambda: dict(DEFAULT_SCORING_WEIGHTS)
    )
    allowlisted_domains: set[str] = field(default_factory=set)
    blocklisted_domains: set[str] = field(default_factory=set)
    blocklisted_ips: set[str] = field(default_factory=set)
    blocklisted_hashes: set[str] = field(default_factory=set)
    max_attachment_bytes: int = 25 * 1024 * 1024  # 25 MB safety limit
    enable_external_enrichment: bool = False
    enrichment_timeout_seconds: float = 4.0
    max_redirects: int = 5
    newly_registered_days: int = 30
    quarantine_dir: str | None = None
    telemetry_log_path: str | None = None
    feedback_store_path: str | None = None


# ---------------------------------------------------------------------------
# Stage 3 & 4: Regexes, TLDs, Shorteners, Protected Brands
# ---------------------------------------------------------------------------

URGENCY_PATTERN = re.compile(
    r"\b("
    r"urgente|inmediato|inmediatamente|cuenta suspendida|verificar|verifique|"
    r"actualizar datos|alerta de seguridad|bloqueada|bloqueado|acci[oó]n requerida|"
    r"expira hoy|[uú]ltimo aviso|suspensi[oó]n|cancelaci[oó]n inmediata|"
    r"urgent|immediately|account suspended|verify your account|update your details|"
    r"security alert|account locked|action required|expires today|final notice|"
    r"unauthorized access|confirm your identity"
    r")\b",
    re.IGNORECASE,
)

URL_PATTERN = re.compile(
    r"https?://[^\s<>\"'\)\]]+|www\.[^\s<>\"'\)\]]+",
    re.IGNORECASE,
)

IPV4_HOST_PATTERN = re.compile(
    r"^(?:\d{1,3}\.){3}\d{1,3}$"
)

OBFUSCATED_IP_PATTERN = re.compile(
    r"^(?:0x[0-9a-f]+|\d{8,10}|(?:0[0-7]+\.){3}0[0-7]+)$",
    re.IGNORECASE,
)

RISKY_TLDS: frozenset[str] = frozenset(
    {
        ".xyz",
        ".top",
        ".gq",
        ".ml",
        ".cf",
        ".tk",
        ".cc",
        ".buzz",
        ".club",
        ".work",
        ".click",
        ".link",
        ".zip",
        ".mov",
        ".rest",
        ".icu",
        ".ru",
        ".su",
        ".cn",
        ".pw",
        ".bid",
        ".loan",
        ".win",
    }
)

URL_SHORTENERS: frozenset[str] = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "ow.ly",
        "buff.ly",
        "goo.gl",
        "is.gd",
        "rebrand.ly",
        "cutt.ly",
        "rb.gy",
        "shorturl.at",
        "tiny.cc",
        "s.id",
        "lnkd.in",
    }
)

# Protected high-value brands -> legitimate canonical base domains
PROTECTED_BRANDS: dict[str, set[str]] = {
    "google": {"google.com", "gmail.com", "youtube.com", "google.cl", "google.es"},
    "microsoft": {"microsoft.com", "outlook.com", "live.com", "office.com", "office365.com"},
    "apple": {"apple.com", "icloud.com"},
    "paypal": {"paypal.com"},
    "amazon": {"amazon.com", "amazon.es", "aws.amazon.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "meta.com"},
    "instagram": {"instagram.com"},
    "linkedin": {"linkedin.com"},
    "dropbox": {"dropbox.com"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "santander": {"santander.com", "santander.cl", "bancosantander.es"},
    "bbva": {"bbva.com", "bbva.es", "bbva.mx"},
    "bancochile": {"bancochile.cl"},
    "bancoestado": {"bancoestado.cl"},
    "mercado libre": {"mercadolibre.com", "mercadolibre.cl", "mercadopago.com"},
    "stripe": {"stripe.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "github": {"github.com"},
}

SUSPICIOUS_URL_PATH_KEYWORDS: frozenset[str] = frozenset(
    {
        "login",
        "signin",
        "verify",
        "verification",
        "account",
        "secure",
        "banking",
        "update",
        "confirm",
        "password",
        "credential",
        "webscr",
        "wp-admin",
        "o365",
        "recuperar",
        "validar",
    }
)

# ---------------------------------------------------------------------------
# Stage 3: Invisible characters, BiDi overrides, Homoglyph map
# ---------------------------------------------------------------------------

ZERO_WIDTH_CHARS: tuple[str, ...] = (
    "\u200b",  # Zero Width Space
    "\u200c",  # Zero Width Non-Joiner
    "\u200d",  # Zero Width Joiner
    "\u2060",  # Word Joiner
    "\ufeff",  # Zero Width No-Break Space / BOM
    "\u00ad",  # Soft Hyphen
    "\u034f",  # Combining Grapheme Joiner
    "\u180e",  # Mongolian Vowel Separator
)

BIDI_CONTROL_CHARS: tuple[str, ...] = (
    "\u202a",  # LRE
    "\u202b",  # RLE
    "\u202c",  # PDF
    "\u202d",  # LRO
    "\u202e",  # RLO (Right-to-Left Override - commonly abused in filenames/text)
    "\u2066",  # LRI
    "\u2067",  # RLI
    "\u2068",  # FSI
    "\u2069",  # PDI
)

# Common Cyrillic & Greek homoglyphs mapped to Latin equivalents
HOMOGLYPH_MAP: dict[str, str] = {
    "\u0430": "a",  # Cyrillic а
    "\u0410": "A",  # Cyrillic А
    "\u0435": "e",  # Cyrillic е
    "\u0415": "E",  # Cyrillic Е
    "\u043e": "o",  # Cyrillic о
    "\u041e": "O",  # Cyrillic О
    "\u0440": "p",  # Cyrillic р
    "\u0420": "P",  # Cyrillic Р
    "\u0441": "c",  # Cyrillic с
    "\u0421": "C",  # Cyrillic С
    "\u0443": "y",  # Cyrillic у
    "\u0423": "Y",  # Cyrillic У
    "\u0445": "x",  # Cyrillic х
    "\u0425": "X",  # Cyrillic Х
    "\u0456": "i",  # Cyrillic і
    "\u0406": "I",  # Cyrillic І
    "\u0458": "j",  # Cyrillic ј
    "\u0455": "s",  # Cyrillic ѕ
    "\u043a": "k",  # Cyrillic к
    "\u041a": "K",  # Cyrillic К
    "\u041c": "M",  # Cyrillic М
    "\u041d": "H",  # Cyrillic Н
    "\u0422": "T",  # Cyrillic Т
    "\u0412": "B",  # Cyrillic В
    "\u03b1": "a",  # Greek α
    "\u03bf": "o",  # Greek ο
    "\u03c1": "p",  # Greek ρ
    "\u03b5": "e",  # Greek ε
    "\u03b9": "i",  # Greek ι
    "\u03ba": "k",  # Greek κ
    "\u03bd": "v",  # Greek ν
    "\u0391": "A",  # Greek Α
    "\u0392": "B",  # Greek Β
    "\u0395": "E",  # Greek Ε
    "\u0397": "H",  # Greek Η
    "\u0399": "I",  # Greek Ι
    "\u039a": "K",  # Greek Κ
    "\u039c": "M",  # Greek Μ
    "\u039d": "N",  # Greek Ν
    "\u039f": "O",  # Greek Ο
    "\u03a1": "P",  # Greek Ρ
    "\u03a4": "T",  # Greek Τ
    "\u03a7": "X",  # Greek Χ
}

# ---------------------------------------------------------------------------
# Stage 5: Dangerous extensions & magic bytes signatures
# ---------------------------------------------------------------------------

DANGEROUS_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".exe",
        ".scr",
        ".bat",
        ".cmd",
        ".com",
        ".pif",
        ".vbs",
        ".vbe",
        ".js",
        ".jse",
        ".wsf",
        ".wsh",
        ".ps1",
        ".hta",
        ".msi",
        ".msp",
        ".dll",
        ".lnk",
        ".iso",
        ".img",
        ".vhd",
        ".cab",
        ".jar",
        ".chm",
        ".reg",
        ".docm",
        ".xlsm",
        ".pptm",
    }
)

HTML_SMUGGLING_EXTENSIONS: frozenset[str] = frozenset(
    {".html", ".htm", ".shtml", ".svg", ".mht", ".mhtml"}
)

BENIGN_DOCUMENT_EXTENSIONS: frozenset[str] = frozenset(
    {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".csv", ".png", ".jpg", ".jpeg", ".gif"}
)

MAGIC_SIGNATURES: list[tuple[bytes, str, set[str]]] = [
    (b"MZ", "pe_executable", {".exe", ".dll", ".scr", ".sys", ".com"}),
    (b"\x7fELF", "elf_executable", {".elf", ".so", ".bin", ""}),
    (b"%PDF-", "pdf", {".pdf"}),
    (b"PK\x03\x04", "zip_archive", {".zip", ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm", ".odt", ".jar", ".apk"}),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole2_compound", {".doc", ".xls", ".ppt", ".msi", ".msg"}),
    (b"\x89PNG\r\n\x1a\n", "png", {".png"}),
    (b"\xff\xd8\xff", "jpeg", {".jpg", ".jpeg"}),
    (b"GIF87a", "gif", {".gif"}),
    (b"GIF89a", "gif", {".gif"}),
    (b"Rar!\x1a\x07", "rar_archive", {".rar"}),
    (b"7z\xbc\xaf\x27\x1c", "7z_archive", {".7z"}),
    (b"L\x00\x00\x00\x01\x14\x02\x00", "windows_lnk", {".lnk"}),
]
