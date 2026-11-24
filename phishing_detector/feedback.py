"""Stage 8: Analyst feedback loop store for continuous false-positive / false-negative tuning."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from pathlib import Path

from phishing_detector.config import DetectorConfig


VALID_LABELS = frozenset({"false_positive", "false_negative", "confirmed_phishing"})


@dataclass
class FeedbackRecord:
    trace_id: str
    label: str
    timestamp_utc: str
    domain: str = ""
    notes: str = ""


class FeedbackStore:
    """Persists analyst feedback in JSONL and applies learned allowlist/blocklist overrides."""

    def __init__(self, store_path: str | Path) -> None:
        self.store_path = Path(store_path)

    def record(
        self,
        trace_id: str,
        label: str,
        *,
        domain: str = "",
        notes: str = "",
    ) -> FeedbackRecord:
        if label not in VALID_LABELS:
            raise ValueError(f"Invalid feedback label '{label}'. Must be one of: {sorted(VALID_LABELS)}")

        entry = FeedbackRecord(
            trace_id=trace_id,
            label=label,
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            domain=domain.strip().lower(),
            notes=notes.strip(),
        )
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        with self.store_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(asdict(entry), ensure_ascii=False) + "\n")
        return entry

    def load_all(self) -> list[FeedbackRecord]:
        if not self.store_path.exists():
            return []
        records: list[FeedbackRecord] = []
        with self.store_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    records.append(FeedbackRecord(**data))
                except Exception:
                    continue
        return records

    def apply_to_config(self, config: DetectorConfig) -> DetectorConfig:
        """Apply analyst feedback domains to config allowlist/blocklist."""
        for rec in self.load_all():
            if not rec.domain:
                continue
            if rec.label == "false_positive":
                config.allowlisted_domains.add(rec.domain)
                config.blocklisted_domains.discard(rec.domain)
            elif rec.label in ("false_negative", "confirmed_phishing"):
                config.blocklisted_domains.add(rec.domain)
                config.allowlisted_domains.discard(rec.domain)
        return config
