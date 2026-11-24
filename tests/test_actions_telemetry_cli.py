"""Unit and end-to-end tests for Stage 8 Actions, Telemetry, Feedback, and CLI."""

import json
from pathlib import Path

from phishing_detector import (
    ActionType,
    DetectorConfig,
    FeedbackStore,
    PhishingPipeline,
)
from phishing_detector.cli import main as cli_main


def test_warn_action_injects_warning_banner_into_html():
    # Single URL shortener (+3) -> MEDIUM risk -> WARN action
    pipeline = PhishingPipeline()
    report = pipeline.analyze_parts(
        "Enlace del evento",
        "<html><body><p>Mira el calendario en <a href='https://bit.ly/evento123'>ver mapa</a></p></body></html>",
    )
    assert report.recommended_action == ActionType.WARN
    assert report.action_outcome is not None
    assert report.action_outcome.banner_injected is True
    assert report.action_outcome.modified_html is not None
    assert "data-phishing-detector-banner" in report.action_outcome.modified_html


def test_quarantine_and_siem_telemetry_written(tmp_path: Path):
    q_dir = tmp_path / "quarantine"
    t_log = tmp_path / "siem_telemetry.jsonl"
    cfg = DetectorConfig(
        quarantine_dir=str(q_dir),
        telemetry_log_path=str(t_log),
    )
    pipeline = PhishingPipeline(config=cfg)
    sample = Path(__file__).resolve().parent.parent / "samples" / "02_obfuscated_phishing.eml"
    report = pipeline.analyze_file(sample)

    assert report.is_phishing is True
    assert report.action_outcome is not None
    assert report.action_outcome.quarantine_path is not None
    assert Path(report.action_outcome.quarantine_path).exists()
    assert Path(f"{q_dir}/{report.trace_id}.report.json").exists()
    assert report.action_outcome.telemetry_written is True

    lines = t_log.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["trace_id"] == report.trace_id
    assert event["event"]["kind"] == "alert"
    assert "iocs" in event


def test_feedback_store_persists_and_updates_allowlist_and_blocklist(tmp_path: Path):
    fb_path = tmp_path / "feedback.jsonl"
    store = FeedbackStore(fb_path)
    store.record("trace-1", "false_positive", domain="trusted-partner.cl", notes="Legit newsletter")
    store.record("trace-2", "confirmed_phishing", domain="evil-domain.xyz", notes="Confirmed phish")

    cfg = DetectorConfig()
    store.apply_to_config(cfg)
    assert "trusted-partner.cl" in cfg.allowlisted_domains
    assert "evil-domain.xyz" in cfg.blocklisted_domains


def test_cli_scan_scan_dir_and_feedback(tmp_path: Path, capsys):
    samples_dir = Path(__file__).resolve().parent.parent / "samples"
    clean_eml = samples_dir / "01_clean_meeting.eml"
    phish_eml = samples_dir / "02_obfuscated_phishing.eml"

    # Clean scan returns exit code 0
    rc_clean = cli_main(["scan", str(clean_eml), "--json"])
    assert rc_clean == 0
    out_clean = json.loads(capsys.readouterr().out)
    assert out_clean["verdict"] == "CLEAN"

    # Phishing scan returns exit code 1 and writes telemetry
    t_log = tmp_path / "cli_telemetry.jsonl"
    rc_phish = cli_main(["scan", str(phish_eml), "--json", "--telemetry-log", str(t_log)])
    assert rc_phish == 1
    out_phish = json.loads(capsys.readouterr().out)
    assert out_phish["verdict"] == "PHISHING_DETECTED"
    assert t_log.exists()

    # Feedback CLI command
    fb_file = tmp_path / "fb.jsonl"
    rc_fb = cli_main([
        "feedback",
        out_phish["trace_id"],
        "--label",
        "confirmed_phishing",
        "--domain",
        "seguridad-cuenta.xyz",
        "--store",
        str(fb_file),
    ])
    assert rc_fb == 0
    assert fb_file.exists()
    assert "Recorded feedback" in capsys.readouterr().out

    # scan-dir scans all 4 samples
    rc_dir = cli_main(["scan-dir", str(samples_dir), "--json"])
    assert rc_dir == 1
    reports = json.loads(capsys.readouterr().out)
    assert len(reports) == 4
