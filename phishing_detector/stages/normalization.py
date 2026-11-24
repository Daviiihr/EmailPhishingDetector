"""Stage 3: Multi-layer text decoding, Unicode normalization, homoglyph detection, and HTML analysis."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
import html
import quopri
import re
import unicodedata

from bs4 import BeautifulSoup, NavigableString, Tag
import ftfy

from phishing_detector.config import (
    BIDI_CONTROL_CHARS,
    DetectorConfig,
    HOMOGLYPH_MAP,
    URL_PATTERN,
    ZERO_WIDTH_CHARS,
)
from phishing_detector.models import (
    ExtractedLink,
    Finding,
    NormalizedContent,
    PipelineContext,
    Severity,
)
from phishing_detector.stages.base import PipelineStage
from phishing_detector.stages.ingestion import decode_mime_header


_QP_HEX_RE = re.compile(r"=[0-9A-Fa-f]{2}")
_B64_STRICT_RE = re.compile(r"^[A-Za-z0-9+/=\r\n]+$")
_META_REFRESH_URL_RE = re.compile(r"url\s*=\s*['\"]?([^'\"\s;]+)", re.IGNORECASE)
_WORD_RE = re.compile(r"[^\s\.,;:!?()\[\]{}<>\"']+")
_LATIN_RE = re.compile(r"[A-Za-z]")

_HIDDEN_STYLE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"display\s*:\s*none", re.IGNORECASE),
    re.compile(r"visibility\s*:\s*hidden", re.IGNORECASE),
    re.compile(r"opacity\s*:\s*0(?:\.0+)?(?:\s*;|\s*$)", re.IGNORECASE),
    re.compile(r"font-size\s*:\s*0(?:px|pt|em|rem|%)?(?:\s*;|\s*$)", re.IGNORECASE),
    re.compile(r"color\s*:\s*transparent", re.IGNORECASE),
    re.compile(r"text-indent\s*:\s*-\d{3,}", re.IGNORECASE),
    re.compile(r"clip\s*:\s*rect\(\s*0", re.IGNORECASE),
)

_SKIP_HTML_TAGS = frozenset({"style", "script", "head", "title", "meta", "noscript"})


@dataclass
class TextNormalizationResult:
    text: str
    zero_width_removed: int = 0
    bidi_removed: int = 0
    homoglyph_words: list[str] = field(default_factory=list)
    layers_applied: list[str] = field(default_factory=list)


def _strip_invisible_and_bidi(text: str) -> tuple[str, int, int]:
    zw_count = 0
    for ch in ZERO_WIDTH_CHARS:
        c = text.count(ch)
        if c:
            zw_count += c
            text = text.replace(ch, "")

    bidi_count = 0
    for ch in BIDI_CONTROL_CHARS:
        c = text.count(ch)
        if c:
            bidi_count += c
            text = text.replace(ch, "")

    return text, zw_count, bidi_count


def _detect_and_fold_homoglyphs(text: str) -> tuple[str, list[str]]:
    """Detect mixed-script Latin+Cyrillic/Greek homoglyph words and fold them to ASCII Latin."""
    suspicious_words: list[str] = []

    def _replace_word(match: re.Match[str]) -> str:
        word = match.group(0)
        has_homoglyph = any(ch in HOMOGLYPH_MAP for ch in word)
        if not has_homoglyph:
            return word
        # Flag when mixed with Latin characters (classic homoglyph obfuscation)
        if _LATIN_RE.search(word):
            folded = "".join(HOMOGLYPH_MAP.get(ch, ch) for ch in word)
            if word not in suspicious_words:
                suspicious_words.append(f"{word} -> {folded}")
            return folded
        return word

    cleaned = _WORD_RE.sub(_replace_word, text)
    return cleaned, suspicious_words


def normalize_text(raw_text: str, *, unescape_html: bool = True) -> TextNormalizationResult:
    """Apply multi-layer decoding, invisible char stripping, NFKC, and homoglyph folding."""
    if not raw_text:
        return TextNormalizationResult(text="")

    layers: list[str] = []
    text = raw_text

    # 1. RFC 2047 encoded-word header decoding
    if "=?" in text and "?=" in text:
        decoded_rfc = decode_mime_header(text)
        if decoded_rfc != text:
            text = decoded_rfc
            layers.append("rfc2047")

    # 2. Repair mojibake via ftfy
    fixed = ftfy.fix_text(text)
    if fixed != text:
        text = fixed
        layers.append("ftfy")

    # 3. Quoted-Printable decoding (only when explicit =XX hex sequences exist)
    if _QP_HEX_RE.search(text):
        try:
            qp_decoded = quopri.decodestring(text.encode("utf-8")).decode(
                "utf-8", errors="ignore"
            )
            if qp_decoded and qp_decoded != text:
                text = qp_decoded
                layers.append("quoted_printable")
        except Exception:
            pass

    # 4. Pure Base64 block decoding
    stripped = text.strip()
    if (
        len(stripped) >= 20
        and len(stripped.replace("\n", "").replace("\r", "")) % 4 == 0
        and _B64_STRICT_RE.match(stripped)
    ):
        try:
            b64_bytes = base64.b64decode(stripped, validate=True)
            b64_decoded = b64_bytes.decode("utf-8")
            if any(c.isalpha() for c in b64_decoded):
                text = b64_decoded
                layers.append("base64")
        except Exception:
            pass

    # 5. HTML entities unescaping (up to 2 passes for double-encoded entities)
    if unescape_html and ("&" in text):
        for _ in range(2):
            unescaped = html.unescape(text)
            if unescaped == text:
                break
            text = unescaped
            if "html_entities" not in layers:
                layers.append("html_entities")

    # 6. Zero-width & BiDi control character removal
    text, zw_count, bidi_count = _strip_invisible_and_bidi(text)
    if zw_count:
        layers.append("zero_width_strip")
    if bidi_count:
        layers.append("bidi_strip")

    # 7. Unicode NFKC normalization
    nfkc = unicodedata.normalize("NFKC", text)
    if nfkc != text:
        text = nfkc
        layers.append("unicode_nfkc")

    # 8. Mixed-script homoglyph detection & folding
    text, homoglyphs = _detect_and_fold_homoglyphs(text)
    if homoglyphs:
        layers.append("homoglyph_fold")

    return TextNormalizationResult(
        text=text,
        zero_width_removed=zw_count,
        bidi_removed=bidi_count,
        homoglyph_words=homoglyphs,
        layers_applied=layers,
    )


def _is_element_hidden(tag: Tag) -> bool:
    if tag.has_attr("hidden"):
        return True
    style = str(tag.get("style", ""))
    if style:
        for pat in _HIDDEN_STYLE_PATTERNS:
            if pat.search(style):
                return True
    return False


def _has_hidden_ancestor(node: NavigableString | Tag) -> bool:
    for parent in node.parents:
        if isinstance(parent, Tag):
            if parent.name in _SKIP_HTML_TAGS:
                return True
            if _is_element_hidden(parent):
                return True
    return False


def parse_html_content(raw_html: str) -> tuple[
    str,
    list[str],
    list[ExtractedLink],
    list[str],
    list[str],
    int,
    int,
    list[str],
    list[str],
]:
    """Parse HTML safely, separating visible/hidden text, links, forms, and meta refreshes."""
    if not raw_html:
        return "", [], [], [], [], 0, 0, [], []

    # Pre-decode QP/Base64/zero-width/BiDi without unescaping structural HTML tags yet
    pre = normalize_text(raw_html, unescape_html=False)
    soup = BeautifulSoup(pre.text, "html.parser")

    hidden_texts: list[str] = []
    visible_chunks: list[str] = []
    links: list[ExtractedLink] = []
    form_actions: list[str] = []
    meta_refresh_urls: list[str] = []

    # Detect meta refresh redirects
    for meta in soup.find_all("meta"):
        http_equiv = str(meta.get("http-equiv", "")).lower()
        if http_equiv == "refresh":
            content = str(meta.get("content", ""))
            m = _META_REFRESH_URL_RE.search(content)
            if m:
                refresh_url = html.unescape(m.group(1)).strip()
                meta_refresh_urls.append(refresh_url)
                links.append(
                    ExtractedLink(
                        original_url=refresh_url,
                        normalized_url=refresh_url,
                        source="meta_refresh",
                    )
                )

    # Detect forms submitting credentials to external actions
    for form in soup.find_all("form"):
        action = str(form.get("action", "")).strip()
        if action and action.lower().startswith(("http://", "https://")):
            clean_action = html.unescape(action)
            form_actions.append(clean_action)
            links.append(
                ExtractedLink(
                    original_url=clean_action,
                    normalized_url=clean_action,
                    source="html_form",
                )
            )

    # Extract anchor links
    seen_hrefs: set[tuple[str, str]] = set()
    for a in soup.find_all("a", href=True):
        raw_href = str(a["href"]).strip()
        if not raw_href or raw_href.startswith("#"):
            continue
        clean_href = html.unescape(raw_href).strip()
        anchor_raw = a.get_text(" ", strip=True)
        anchor_norm = normalize_text(anchor_raw, unescape_html=True).text.strip()
        key = (clean_href, anchor_norm)
        if key not in seen_hrefs:
            seen_hrefs.add(key)
            links.append(
                ExtractedLink(
                    original_url=raw_href,
                    normalized_url=clean_href,
                    anchor_text=anchor_norm,
                    source="html_href",
                )
            )

    # Collect hidden elements
    for tag in soup.find_all(True):
        if tag.name in _SKIP_HTML_TAGS:
            continue
        if _is_element_hidden(tag):
            txt = tag.get_text(" ", strip=True)
            if txt and txt not in hidden_texts:
                hidden_texts.append(txt)

    # Collect all visible text nodes (excluding hidden/script/style subtrees)
    for node in soup.descendants:
        if isinstance(node, NavigableString):
            if _has_hidden_ancestor(node):
                continue
            chunk = str(node).strip()
            if chunk:
                visible_chunks.append(chunk)

    joined_visible = " ".join(visible_chunks)
    post_visible = normalize_text(joined_visible, unescape_html=True)

    total_zw = pre.zero_width_removed + post_visible.zero_width_removed
    total_bidi = pre.bidi_removed + post_visible.bidi_removed
    homoglyphs = list(dict.fromkeys(pre.homoglyph_words + post_visible.homoglyph_words))
    layers = list(dict.fromkeys(pre.layers_applied + post_visible.layers_applied))

    return (
        post_visible.text,
        hidden_texts,
        links,
        form_actions,
        meta_refresh_urls,
        total_zw,
        total_bidi,
        homoglyphs,
        layers,
    )


class NormalizationStage(PipelineStage):
    """Stage 3: Deobfuscate subject, plain text, and HTML; emit obfuscation findings."""

    name = "normalization"

    def __init__(self, config: DetectorConfig | None = None) -> None:
        super().__init__(config)

    def run(self, context: PipelineContext) -> PipelineContext:
        email = context.email

        subj_res = normalize_text(email.subject, unescape_html=True)
        plain_res = normalize_text(email.text_plain, unescape_html=True)
        (
            html_visible,
            hidden_texts,
            links,
            form_actions,
            meta_refresh_urls,
            html_zw,
            html_bidi,
            html_homoglyphs,
            html_layers,
        ) = parse_html_content(email.text_html)

        # Also extract standalone URLs from plain text not already captured in HTML hrefs
        existing_urls = {lnk.normalized_url for lnk in links}
        for source_text in (plain_res.text, html_visible):
            for match in URL_PATTERN.findall(source_text):
                cleaned_url = match.rstrip(".,;:!?)")
                if cleaned_url.lower().startswith("www."):
                    cleaned_url = f"http://{cleaned_url}"
                if cleaned_url not in existing_urls:
                    existing_urls.add(cleaned_url)
                    links.append(
                        ExtractedLink(
                            original_url=match,
                            normalized_url=cleaned_url,
                            source="plain_text",
                        )
                    )

        total_zw = (
            subj_res.zero_width_removed
            + plain_res.zero_width_removed
            + html_zw
        )
        total_bidi = (
            subj_res.bidi_removed
            + plain_res.bidi_removed
            + html_bidi
        )
        all_homoglyphs = list(
            dict.fromkeys(
                subj_res.homoglyph_words
                + plain_res.homoglyph_words
                + html_homoglyphs
            )
        )
        all_layers = list(
            dict.fromkeys(
                subj_res.layers_applied
                + plain_res.layers_applied
                + html_layers
            )
        )

        # Combine cleanly with space separator (fixes legacy concatenation bug)
        body_parts = [p for p in (plain_res.text, html_visible) if p]
        # Avoid duplicating if plain and html carry identical text
        if len(body_parts) == 2 and body_parts[0].strip() == body_parts[1].strip():
            body_parts = [body_parts[0]]
        combined = " ".join(p for p in [subj_res.text, *body_parts] if p).strip()

        normalized = NormalizedContent(
            clean_subject=subj_res.text,
            clean_plain_text=plain_res.text,
            clean_html_text=html_visible,
            combined_text=combined,
            hidden_texts=hidden_texts,
            has_hidden_css=len(hidden_texts) > 0,
            zero_width_chars_removed=total_zw,
            bidi_controls_removed=total_bidi,
            homoglyph_words=all_homoglyphs,
            links=links,
            form_actions=form_actions,
            meta_refresh_urls=meta_refresh_urls,
            decoding_layers_applied=all_layers,
        )
        context.normalized = normalized

        # Emit Stage 3 obfuscation findings
        if normalized.has_hidden_css:
            context.add_finding(
                Finding(
                    stage=self.name,
                    rule_id="HTML_HIDDEN_CSS_TEXT",
                    title="Hidden HTML text detected via CSS",
                    description=(
                        f"Detected {len(hidden_texts)} hidden HTML element(s) using CSS/hidden attributes "
                        "to evade text filters."
                    ),
                    score=self.config.weights.get("HTML_HIDDEN_CSS_TEXT", 4),
                    severity=Severity.HIGH,
                    evidence={"hidden_snippets": hidden_texts[:3]},
                )
            )

        if total_zw >= 2:
            context.add_finding(
                Finding(
                    stage=self.name,
                    rule_id="TEXT_ZERO_WIDTH_OBFUSCATION",
                    title="Zero-width character obfuscation",
                    description=(
                        f"Removed {total_zw} invisible zero-width character(s) often used to split "
                        "keywords and evade filters."
                    ),
                    score=self.config.weights.get("TEXT_ZERO_WIDTH_OBFUSCATION", 3),
                    severity=Severity.MEDIUM,
                    evidence={"zero_width_count": total_zw},
                )
            )

        if total_bidi > 0:
            context.add_finding(
                Finding(
                    stage=self.name,
                    rule_id="TEXT_BIDI_OVERRIDE",
                    title="Bidirectional (BiDi) Unicode control character detected",
                    description=(
                        f"Detected {total_bidi} BiDi override control character(s) used to visually "
                        "reverse text or disguise file extensions."
                    ),
                    score=self.config.weights.get("TEXT_BIDI_OVERRIDE", 6),
                    severity=Severity.CRITICAL,
                    evidence={"bidi_count": total_bidi},
                )
            )

        if all_homoglyphs:
            context.add_finding(
                Finding(
                    stage=self.name,
                    rule_id="TEXT_HOMOGLYPH_OBFUSCATION",
                    title="Mixed-script Unicode homoglyph obfuscation",
                    description=(
                        "Detected words mixing Latin and Cyrillic/Greek lookalike characters "
                        "to bypass keyword filters."
                    ),
                    score=self.config.weights.get("TEXT_HOMOGLYPH_OBFUSCATION", 4),
                    severity=Severity.HIGH,
                    evidence={"homoglyph_words": all_homoglyphs[:5]},
                )
            )

        if form_actions:
            context.add_finding(
                Finding(
                    stage=self.name,
                    rule_id="HTML_EXTERNAL_FORM",
                    title="Embedded HTML form submitting to external URL",
                    description=(
                        f"Email contains {len(form_actions)} HTML <form> element(s) posting directly "
                        "to external endpoints (common credential harvesting technique)."
                    ),
                    score=self.config.weights.get("HTML_EXTERNAL_FORM", 4),
                    severity=Severity.HIGH,
                    evidence={"form_actions": form_actions},
                )
            )

        if meta_refresh_urls:
            context.add_finding(
                Finding(
                    stage=self.name,
                    rule_id="HTML_META_REFRESH",
                    title="HTML meta-refresh redirect detected",
                    description="Email uses <meta http-equiv='refresh'> to redirect users automatically.",
                    score=self.config.weights.get("HTML_META_REFRESH", 3),
                    severity=Severity.MEDIUM,
                    evidence={"meta_refresh_urls": meta_refresh_urls},
                )
            )

        return context
