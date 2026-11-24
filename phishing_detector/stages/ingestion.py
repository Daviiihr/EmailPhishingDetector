"""Stage 1: Safe MIME / RFC 5322 email ingestion and structural parsing."""

from __future__ import annotations

from email import policy
from email.header import decode_header
from email.message import Message
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from pathlib import Path
from typing import Iterable

from phishing_detector.config import DetectorConfig
from phishing_detector.models import AttachmentInfo, EmailMessage, PipelineContext
from phishing_detector.stages.base import PipelineStage


def decode_mime_header(value: str | None) -> str:
    """Safely decode an RFC 2047 MIME header value into a Unicode string."""
    if not value:
        return ""
    try:
        parts = decode_header(str(value))
        decoded: list[str] = []
        for chunk, charset in parts:
            if isinstance(chunk, bytes):
                enc = charset or "utf-8"
                try:
                    decoded.append(chunk.decode(enc, errors="replace"))
                except LookupError:
                    decoded.append(chunk.decode("utf-8", errors="replace"))
            else:
                decoded.append(str(chunk))
        return "".join(decoded).strip()
    except Exception:
        return str(value).strip()


def _safe_decode_payload(part: Message) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        raw = part.get_payload()
        return raw if isinstance(raw, str) else ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def _extract_address(raw_header: str) -> tuple[str, str]:
    """Return (decoded_display_name, lowercased_email_address)."""
    if not raw_header:
        return "", ""
    decoded = decode_mime_header(raw_header)
    display_name, addr = parseaddr(decoded)
    return display_name.strip(), addr.strip().lower()


def _extract_all_addresses(raw_headers: Iterable[str]) -> list[str]:
    decoded = [decode_mime_header(h) for h in raw_headers if h]
    return [addr.strip().lower() for _, addr in getaddresses(decoded) if addr]


class MimeIngestionStage(PipelineStage):
    """Stage 1: Parse raw RFC 5322 / MIME bytes into a structured EmailMessage."""

    name = "ingestion"

    def __init__(self, config: DetectorConfig | None = None) -> None:
        super().__init__(config)

    def parse_bytes(
        self, raw_bytes: bytes, source_name: str = "<memory>"
    ) -> EmailMessage:
        """Parse raw RFC 5322 bytes without executing any active content."""
        msg = BytesParser(policy=policy.compat32).parsebytes(raw_bytes)
        headers: dict[str, list[str]] = {}
        for key, val in msg.items():
            headers.setdefault(key.lower(), []).append(str(val))

        from_raw = msg.get("From", "")
        from_display, from_addr = _extract_address(from_raw)
        reply_to_raw = msg.get("Reply-To", "")
        _, reply_to_addr = _extract_address(reply_to_raw)
        return_path_raw = msg.get("Return-Path", "")
        _, return_path_addr = _extract_address(return_path_raw)

        to_addresses = _extract_all_addresses(
            headers.get("to", []) + headers.get("cc", [])
        )

        text_plain_parts: list[str] = []
        text_html_parts: list[str] = []
        attachments: list[AttachmentInfo] = []
        parse_warnings: list[str] = []

        if msg.is_multipart():
            for part in msg.walk():
                if part.is_multipart():
                    continue
                self._classify_part(
                    part,
                    text_plain_parts,
                    text_html_parts,
                    attachments,
                    parse_warnings,
                )
        else:
            self._classify_part(
                msg,
                text_plain_parts,
                text_html_parts,
                attachments,
                parse_warnings,
            )

        return EmailMessage(
            raw_bytes=raw_bytes,
            source_name=source_name,
            subject=msg.get("Subject", "") or "",
            from_raw=from_raw or "",
            from_display_name=from_display,
            from_address=from_addr,
            to_addresses=to_addresses,
            reply_to_raw=reply_to_raw or "",
            reply_to_address=reply_to_addr,
            return_path_raw=return_path_raw or "",
            return_path_address=return_path_addr,
            date_raw=msg.get("Date", "") or "",
            message_id=(msg.get("Message-ID", "") or "").strip(),
            headers=headers,
            text_plain="\n".join(p for p in text_plain_parts if p).strip(),
            text_html="\n".join(p for p in text_html_parts if p).strip(),
            attachments=attachments,
            parse_warnings=parse_warnings,
        )

    def _classify_part(
        self,
        part: Message,
        text_plain_parts: list[str],
        text_html_parts: list[str],
        attachments: list[AttachmentInfo],
        parse_warnings: list[str],
    ) -> None:
        content_type = (part.get_content_type() or "application/octet-stream").lower()
        disposition = (part.get_content_disposition() or "").lower()
        raw_filename = part.get_filename()
        filename = decode_mime_header(raw_filename) if raw_filename else ""
        content_id = part.get("Content-ID")
        if content_id:
            content_id = content_id.strip("<> ")

        is_attachment = (
            disposition == "attachment"
            or bool(filename)
            or (disposition == "inline" and content_type.startswith(("image/", "application/")))
            or content_type not in ("text/plain", "text/html")
        )

        if is_attachment:
            payload = part.get_payload(decode=True) or b""
            size_bytes = len(payload)
            if size_bytes > self.config.max_attachment_bytes:
                parse_warnings.append(
                    f"Attachment '{filename or content_type}' truncated: "
                    f"{size_bytes} bytes exceeds limit {self.config.max_attachment_bytes}"
                )
                payload = payload[: self.config.max_attachment_bytes]

            if not filename:
                ext = content_type.split("/")[-1].split(";")[0]
                filename = f"unnamed.{ext}" if ext else "unnamed.bin"

            attachments.append(
                AttachmentInfo(
                    filename=filename,
                    content_type=content_type,
                    size_bytes=size_bytes,
                    payload=payload,
                    content_disposition=disposition or "attachment",
                    content_id=content_id,
                )
            )
            return

        decoded_text = _safe_decode_payload(part)
        if content_type == "text/html":
            text_html_parts.append(decoded_text)
        else:
            text_plain_parts.append(decoded_text)

    def parse_string(
        self, raw_email: str, source_name: str = "<string>"
    ) -> EmailMessage:
        return self.parse_bytes(raw_email.encode("utf-8", errors="replace"), source_name)

    def parse_file(self, path: str | Path) -> EmailMessage:
        file_path = Path(path)
        return self.parse_bytes(file_path.read_bytes(), source_name=str(file_path))

    def from_parts(
        self,
        subject: str,
        body: str,
        *,
        sender: str = "",
        headers: dict[str, str] | None = None,
        is_html: bool | None = None,
        source_name: str = "<inline>",
    ) -> EmailMessage:
        """Construct an EmailMessage directly from subject/body for legacy callers."""
        if is_html is None:
            lowered = body.lower()
            is_html = "<html" in lowered or "<body" in lowered or "<a " in lowered or "<p" in lowered

        normalized_headers: dict[str, list[str]] = {}
        if headers:
            for k, v in headers.items():
                normalized_headers.setdefault(k.lower(), []).append(v)
        if sender and "from" not in normalized_headers:
            normalized_headers["from"] = [sender]
        if subject and "subject" not in normalized_headers:
            normalized_headers["subject"] = [subject]

        from_raw = normalized_headers.get("from", [""])[0]
        from_display, from_addr = _extract_address(from_raw)
        reply_to_raw = normalized_headers.get("reply-to", [""])[0]
        _, reply_to_addr = _extract_address(reply_to_raw)
        return_path_raw = normalized_headers.get("return-path", [""])[0]
        _, return_path_addr = _extract_address(return_path_raw)

        return EmailMessage(
            source_name=source_name,
            subject=subject,
            from_raw=from_raw,
            from_display_name=from_display,
            from_address=from_addr,
            reply_to_raw=reply_to_raw,
            reply_to_address=reply_to_addr,
            return_path_raw=return_path_raw,
            return_path_address=return_path_addr,
            date_raw=normalized_headers.get("date", [""])[0],
            message_id=normalized_headers.get("message-id", [""])[0],
            headers=normalized_headers,
            text_plain="" if is_html else body,
            text_html=body if is_html else "",
        )

    def run(self, context: PipelineContext) -> PipelineContext:
        """If raw_bytes is present and headers/body aren't parsed yet, parse it."""
        if (
            context.email.raw_bytes
            and not context.email.headers
            and not context.email.text_plain
            and not context.email.text_html
        ):
            context.email = self.parse_bytes(
                context.email.raw_bytes, source_name=context.email.source_name
            )
        return context
