"""Stage 5: Attachment static analysis, magic bytes, macro/archive inspection, Quishing QR, and sandbox interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
import hashlib
import io
from pathlib import PurePosixPath
import re
import zipfile

from phishing_detector.config import (
    BENIGN_DOCUMENT_EXTENSIONS,
    BIDI_CONTROL_CHARS,
    DANGEROUS_EXTENSIONS,
    DetectorConfig,
    HTML_SMUGGLING_EXTENSIONS,
    MAGIC_SIGNATURES,
    URL_PATTERN,
)
from phishing_detector.models import (
    AttachmentInfo,
    ExtractedLink,
    Finding,
    PipelineContext,
    Severity,
)
from phishing_detector.stages.base import PipelineStage
from phishing_detector.stages.url_analysis import UrlAnalysisStage


_HTML_SMUGGLING_RE = re.compile(
    r"(<script\b|atob\s*\(|new\s+Blob\s*\(|createObjectURL|msSaveOrOpenBlob|type\s*=\s*['\"]password['\"])",
    re.IGNORECASE,
)
_SCRIPT_SUSPICIOUS_RE = re.compile(
    r"(powershell\s+-e(?:nc|ncodedcommand)?|WScript\.Shell|Invoke-Expression|IEX\s*\(|cmd\.exe\s*/c|certutil\s+-urlcache)",
    re.IGNORECASE,
)
_EICAR_SIGNATURE = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


@dataclass
class SandboxResult:
    verdict: str  # "clean", "suspicious", "malicious", "skipped"
    details: str = ""


class QrCodeDecoder(ABC):
    """Pluggable interface for decoding QR codes embedded in image attachments (Quishing)."""

    @abstractmethod
    def decode_urls(self, image_bytes: bytes, content_type: str) -> list[str]:
        raise NotImplementedError


class DefaultQrCodeDecoder(QrCodeDecoder):
    """Attempts optional runtime QR decoding via pyzbar or OpenCV when installed."""

    def decode_urls(self, image_bytes: bytes, content_type: str) -> list[str]:
        if not image_bytes:
            return []
        extracted: list[str] = []

        # Attempt pyzbar + Pillow if installed
        try:
            from PIL import Image  # type: ignore
            from pyzbar.pyzbar import decode as pyzbar_decode  # type: ignore

            with Image.open(io.BytesIO(image_bytes)) as img:
                for obj in pyzbar_decode(img):
                    raw = obj.data.decode("utf-8", errors="ignore").strip()
                    for match in URL_PATTERN.findall(raw):
                        if match not in extracted:
                            extracted.append(match)
            if extracted:
                return extracted
        except Exception:
            pass

        # Attempt OpenCV QRCodeDetector if installed
        try:
            import cv2  # type: ignore
            import numpy as np  # type: ignore

            arr = np.frombuffer(image_bytes, dtype=np.uint8)
            img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
            if img is not None:
                detector = cv2.QRCodeDetector()
                data, _, _ = detector.detectAndDecode(img)
                if data:
                    for match in URL_PATTERN.findall(data):
                        if match not in extracted:
                            extracted.append(match)
        except Exception:
            pass

        return extracted


class SandboxClient(ABC):
    """Pluggable interface for isolated attachment detonation / behavioral analysis."""

    @abstractmethod
    def detonate(self, attachment: AttachmentInfo) -> SandboxResult:
        raise NotImplementedError


class LocalStaticSandboxClient(SandboxClient):
    """Offline static behavioral scanner (EICAR & malicious script payload heuristics)."""

    def detonate(self, attachment: AttachmentInfo) -> SandboxResult:
        payload = attachment.payload
        if not payload:
            return SandboxResult(verdict="skipped")

        if _EICAR_SIGNATURE in payload:
            return SandboxResult(
                verdict="malicious",
                details="Matched EICAR standard antivirus test signature",
            )

        # Check text-based scripts for obfuscated execution patterns
        ext = _get_extension(attachment.filename)
        if ext in {".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".wsf"} or attachment.content_type.startswith("text/"):
            text = payload[:65536].decode("utf-8", errors="ignore")
            m = _SCRIPT_SUSPICIOUS_RE.search(text)
            if m:
                return SandboxResult(
                    verdict="malicious",
                    details=f"Detected malicious execution primitive: '{m.group(0)}'",
                )

        return SandboxResult(verdict="clean")


def _get_extension(filename: str) -> str:
    if not filename:
        return ""
    suffixes = PurePosixPath(filename.strip()).suffixes
    return suffixes[-1].lower() if suffixes else ""


def _is_double_extension(filename: str) -> bool:
    suffixes = [s.lower() for s in PurePosixPath(filename.strip()).suffixes]
    if len(suffixes) < 2:
        return False
    prev_ext, final_ext = suffixes[-2], suffixes[-1]
    return prev_ext in BENIGN_DOCUMENT_EXTENSIONS and (
        final_ext in DANGEROUS_EXTENSIONS or final_ext in HTML_SMUGGLING_EXTENSIONS
    )


def detect_magic_type(payload: bytes) -> tuple[str | None, set[str]]:
    """Inspect leading magic bytes and return (type_name, expected_extensions)."""
    for sig, type_name, expected_exts in MAGIC_SIGNATURES:
        if payload.startswith(sig):
            return type_name, expected_exts
    return None, set()


class AttachmentInspectionStage(PipelineStage):
    """Stage 5: Static analysis, magic bytes, macros, archive inspection, Quishing, and sandbox."""

    name = "attachments"

    def __init__(
        self,
        config: DetectorConfig | None = None,
        qr_decoder: QrCodeDecoder | None = None,
        sandbox_client: SandboxClient | None = None,
        url_stage: UrlAnalysisStage | None = None,
    ) -> None:
        super().__init__(config)
        self.qr_decoder = qr_decoder or DefaultQrCodeDecoder()
        self.sandbox_client = sandbox_client or LocalStaticSandboxClient()
        self.url_stage = url_stage or UrlAnalysisStage(config=self.config)

    def run(self, context: PipelineContext) -> PipelineContext:
        for att in context.email.attachments:
            self._inspect_attachment(att, context)
        return context

    def _inspect_attachment(self, att: AttachmentInfo, context: PipelineContext) -> None:
        payload = att.payload
        filename = att.filename or ""
        ext = _get_extension(filename)

        # 1. Cryptographic hashes & blocklist lookup
        if payload:
            att.sha256 = hashlib.sha256(payload).hexdigest()
            att.md5 = hashlib.md5(payload).hexdigest()
            if (
                att.sha256.lower() in self.config.blocklisted_hashes
                or att.md5.lower() in self.config.blocklisted_hashes
            ):
                context.add_finding(
                    Finding(
                        stage=self.name,
                        rule_id="ATTACHMENT_MALICIOUS_HASH",
                        title=f"Attachment matches known malicious hash ({filename})",
                        description=f"Attachment '{filename}' SHA-256 ({att.sha256[:16]}...) is blocklisted.",
                        score=self.config.weights.get("ATTACHMENT_MALICIOUS_HASH", 10),
                        severity=Severity.CRITICAL,
                        evidence={"filename": filename, "sha256": att.sha256, "md5": att.md5},
                    )
                )

        # 2. BiDi control chars in filename (RLO extension spoofing)
        if any(ch in filename for ch in BIDI_CONTROL_CHARS):
            context.add_finding(
                Finding(
                    stage=self.name,
                    rule_id="TEXT_BIDI_OVERRIDE",
                    title="Attachment filename uses BiDi override character",
                    description=f"Attachment filename '{filename!r}' uses Unicode BiDi override to disguise its real extension.",
                    score=self.config.weights.get("TEXT_BIDI_OVERRIDE", 6),
                    severity=Severity.CRITICAL,
                    evidence={"filename_repr": repr(filename)},
                )
            )

        # 3. Double extension & dangerous extension checks
        if _is_double_extension(filename):
            context.add_finding(
                Finding(
                    stage=self.name,
                    rule_id="ATTACHMENT_DOUBLE_EXTENSION",
                    title=f"Double file extension spoofing ({filename})",
                    description=f"Attachment '{filename}' uses a decoy document extension followed by executable/script '{ext}'.",
                    score=self.config.weights.get("ATTACHMENT_DOUBLE_EXTENSION", 6),
                    severity=Severity.CRITICAL,
                    evidence={"filename": filename, "extension": ext},
                )
            )
        elif ext in DANGEROUS_EXTENSIONS:
            context.add_finding(
                Finding(
                    stage=self.name,
                    rule_id="ATTACHMENT_DANGEROUS_EXTENSION",
                    title=f"High-risk attachment extension ({ext})",
                    description=f"Attachment '{filename}' has an executable, script, container, or macro-enabled extension.",
                    score=self.config.weights.get("ATTACHMENT_DANGEROUS_EXTENSION", 6),
                    severity=Severity.HIGH,
                    evidence={"filename": filename, "extension": ext},
                )
            )

        # 4. HTML Smuggling inspection
        if ext in HTML_SMUGGLING_EXTENSIONS or att.content_type in ("text/html", "image/svg+xml"):
            sample_text = payload[:65536].decode("utf-8", errors="ignore")
            m = _HTML_SMUGGLING_RE.search(sample_text)
            if m:
                context.add_finding(
                    Finding(
                        stage=self.name,
                        rule_id="ATTACHMENT_HTML_SMUGGLING",
                        title=f"HTML/SVG smuggling or credential form attachment ({filename})",
                        description=(
                            f"Attachment '{filename}' contains active script/smuggling or password form "
                            f"indicators ('{m.group(0)}')."
                        ),
                        score=self.config.weights.get("ATTACHMENT_HTML_SMUGGLING", 5),
                        severity=Severity.HIGH,
                        evidence={"filename": filename, "indicator": m.group(0)},
                    )
                )

        # 5. Magic bytes vs declared extension validation
        magic_type, expected_exts = detect_magic_type(payload)
        att.detected_magic_type = magic_type
        if magic_type and ext and ext not in expected_exts:
            context.add_finding(
                Finding(
                    stage=self.name,
                    rule_id="ATTACHMENT_MAGIC_MISMATCH",
                    title=f"File magic bytes mismatch ({filename})",
                    description=(
                        f"Attachment '{filename}' declares extension '{ext}', but binary signature "
                        f"identifies it as '{magic_type}'."
                    ),
                    score=self.config.weights.get("ATTACHMENT_MAGIC_MISMATCH", 6),
                    severity=Severity.CRITICAL,
                    evidence={
                        "filename": filename,
                        "declared_ext": ext,
                        "detected_magic_type": magic_type,
                    },
                )
            )

        # 6. Office macro & ZIP archive inspection
        if magic_type == "zip_archive":
            self._inspect_zip_or_ooxml(att, context)
        elif magic_type == "ole2_compound":
            self._inspect_ole2_macros(att, context)

        # 7. Quishing (QR code extraction on images)
        if att.content_type.startswith("image/") or magic_type in ("png", "jpeg", "gif"):
            qr_urls = self.qr_decoder.decode_urls(payload, att.content_type)
            if qr_urls:
                att.extracted_qr_urls.extend(qr_urls)
                context.add_finding(
                    Finding(
                        stage=self.name,
                        rule_id="ATTACHMENT_QUISHING_QR_URL",
                        title=f"QR code containing URL detected in image ({filename})",
                        description=(
                            f"Image '{filename}' embeds QR code(s) pointing to: {', '.join(qr_urls)} "
                            "(potential Quishing attack)."
                        ),
                        score=self.config.weights.get("ATTACHMENT_QUISHING_QR_URL", 4),
                        severity=Severity.HIGH,
                        evidence={"filename": filename, "qr_urls": qr_urls},
                    )
                )
                for qurl in qr_urls:
                    link = ExtractedLink(
                        original_url=qurl,
                        normalized_url=qurl,
                        source="qr_code",
                    )
                    context.normalized.links.append(link)
                    self.url_stage.analyze_link(link, context)

        # 8. Isolated sandbox detonation / behavioral check
        sb_result = self.sandbox_client.detonate(att)
        att.sandbox_verdict = sb_result.verdict
        if sb_result.verdict == "malicious":
            context.add_finding(
                Finding(
                    stage=self.name,
                    rule_id="ATTACHMENT_SANDBOX_MALICIOUS",
                    title=f"Sandbox flagged attachment as malicious ({filename})",
                    description=f"Sandbox analysis of '{filename}' returned malicious: {sb_result.details}",
                    score=self.config.weights.get("ATTACHMENT_SANDBOX_MALICIOUS", 10),
                    severity=Severity.CRITICAL,
                    evidence={"filename": filename, "details": sb_result.details},
                )
            )

    def _inspect_zip_or_ooxml(self, att: AttachmentInfo, context: PipelineContext) -> None:
        try:
            with zipfile.ZipFile(io.BytesIO(att.payload)) as zf:
                infos = zf.infolist()
                names = [info.filename for info in infos]
                att.nested_files = names[:50]

                # Check encrypted entries
                if any(info.flag_bits & 0x1 for info in infos):
                    context.add_finding(
                        Finding(
                            stage=self.name,
                            rule_id="ATTACHMENT_ENCRYPTED_ARCHIVE",
                            title=f"Password-protected ZIP archive ({att.filename})",
                            description=(
                                f"Archive '{att.filename}' contains encrypted entries, a common technique "
                                "to bypass automated malware scanners."
                            ),
                            score=self.config.weights.get("ATTACHMENT_ENCRYPTED_ARCHIVE", 4),
                            severity=Severity.HIGH,
                            evidence={"filename": att.filename, "members": names[:10]},
                        )
                    )

                # Check OOXML VBA macro payloads
                macro_entries = [
                    n for n in names
                    if "vbaproject.bin" in n.lower() or "vbadata.xml" in n.lower()
                ]
                if macro_entries:
                    att.has_macros = True
                    context.add_finding(
                        Finding(
                            stage=self.name,
                            rule_id="ATTACHMENT_OFFICE_MACRO",
                            title=f"Office VBA macro detected ({att.filename})",
                            description=f"Document '{att.filename}' embeds VBA macro payload(s): {', '.join(macro_entries)}.",
                            score=self.config.weights.get("ATTACHMENT_OFFICE_MACRO", 7),
                            severity=Severity.CRITICAL,
                            evidence={"filename": att.filename, "macro_entries": macro_entries},
                        )
                    )

                # Check nested dangerous files in regular ZIP archives
                nested_dangerous = [
                    n for n in names
                    if _get_extension(n) in DANGEROUS_EXTENSIONS
                    or _is_double_extension(n)
                ]
                if nested_dangerous:
                    context.add_finding(
                        Finding(
                            stage=self.name,
                            rule_id="ATTACHMENT_NESTED_DANGEROUS_FILE",
                            title=f"Archive contains dangerous executable/script ({att.filename})",
                            description=(
                                f"Archive '{att.filename}' contains high-risk file(s): "
                                f"{', '.join(nested_dangerous[:5])}."
                            ),
                            score=self.config.weights.get("ATTACHMENT_NESTED_DANGEROUS_FILE", 7),
                            severity=Severity.CRITICAL,
                            evidence={"filename": att.filename, "nested_dangerous": nested_dangerous[:5]},
                        )
                    )
        except zipfile.BadZipFile:
            pass

    def _inspect_ole2_macros(self, att: AttachmentInfo, context: PipelineContext) -> None:
        # Look for canonical OLE2 VBA storage/stream markers
        markers = (b"_VBA_PROJECT", b"VBA_PROJECT", b"vbaProject", b"Macros\x00")
        if any(m in att.payload for m in markers):
            att.has_macros = True
            context.add_finding(
                Finding(
                    stage=self.name,
                    rule_id="ATTACHMENT_OFFICE_MACRO",
                    title=f"Legacy Office OLE2 macro detected ({att.filename})",
                    description=f"OLE2 document '{att.filename}' contains embedded VBA macro streams.",
                    score=self.config.weights.get("ATTACHMENT_OFFICE_MACRO", 7),
                    severity=Severity.CRITICAL,
                    evidence={"filename": att.filename},
                )
            )
