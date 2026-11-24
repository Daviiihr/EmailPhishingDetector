"""Command-line interface for the Email Phishing Detector."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from phishing_detector.config import DetectorConfig
from phishing_detector.feedback import FeedbackStore
from phishing_detector.models import AnalysisReport
from phishing_detector.pipeline import PhishingPipeline


def format_report_text(report: AnalysisReport) -> str:
    lines = [
        "=" * 64,
        f"Email Phishing Analysis Report | Source: {report.source_name}",
        "=" * 64,
        f"Trace ID:     {report.trace_id}",
        f"Sender:       {report.sender or '(unknown)'}",
        f"Subject:      {report.subject or '(empty)'}",
        f"Risk Score:   {report.risk_score} ({report.risk_level.value})",
        f"Verdict:      {report.verdict.value}",
        f"Action:       {report.recommended_action.value}",
        (
            "Auth Headers: "
            f"SPF={report.header_summary.get('spf', 'none')} | "
            f"DKIM={report.header_summary.get('dkim', 'none')} | "
            f"DMARC={report.header_summary.get('dmarc', 'none')}"
        ),
        (
            "Semantic/ML:  "
            f"BEC={report.semantic_summary.get('bec_suspected', False)} | "
            f"ML Phishing Prob={report.semantic_summary.get('ml_phishing_probability', 0.0):.1%}"
        ),
    ]
    if report.findings:
        lines.append("Findings:")
        for f in report.findings:
            lines.append(
                f"  [+{f.score} | {f.severity.value.upper()} | {f.stage}] {f.title}: {f.description}"
            )
    else:
        lines.append("Findings:     None (no suspicious indicators detected)")

    if report.action_outcome:
        if report.action_outcome.banner_injected:
            lines.append("Stage 8:      Warning banner injected into HTML copy")
        if report.action_outcome.quarantine_path:
            lines.append(f"Stage 8:      Quarantined at {report.action_outcome.quarantine_path}")
        if report.action_outcome.telemetry_written:
            lines.append("Stage 8:      SIEM telemetry event written")

    total_ms = sum(report.stage_timings_ms.values())
    lines.append(f"Total Time:   {total_ms:.2f} ms")
    return "\n".join(lines)


def _build_pipeline(args: argparse.Namespace) -> PhishingPipeline:
    cfg = DetectorConfig(
        enable_external_enrichment=getattr(args, "enrich", False),
        quarantine_dir=getattr(args, "quarantine_dir", None),
        telemetry_log_path=getattr(args, "telemetry_log", None),
        feedback_store_path=getattr(args, "feedback_store", None),
    )
    if cfg.feedback_store_path:
        FeedbackStore(cfg.feedback_store_path).apply_to_config(cfg)
    return PhishingPipeline(config=cfg)


def _cmd_scan(args: argparse.Namespace) -> int:
    path = Path(args.file)
    if not path.is_file():
        print(f"Error: file not found: {path}", file=sys.stderr)
        return 2
    pipeline = _build_pipeline(args)
    report = pipeline.analyze_file(path)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    else:
        print(format_report_text(report))
    return 1 if report.is_phishing else 0


def _cmd_scan_dir(args: argparse.Namespace) -> int:
    directory = Path(args.directory)
    if not directory.is_dir():
        print(f"Error: directory not found: {directory}", file=sys.stderr)
        return 2
    eml_files = sorted(directory.glob("*.eml"))
    if not eml_files:
        print(f"No .eml files found in {directory}")
        return 0
    pipeline = _build_pipeline(args)
    reports = [pipeline.analyze_file(f) for f in eml_files]
    if args.json:
        print(json.dumps([r.to_dict() for r in reports], indent=2, ensure_ascii=False))
    else:
        for r in reports:
            print(format_report_text(r))
            print()
        phish_count = sum(1 for r in reports if r.is_phishing)
        print(f"Summary: scanned {len(reports)} email(s) — {phish_count} phishing detected.")
    return 1 if any(r.is_phishing for r in reports) else 0


def _cmd_demo(args: argparse.Namespace) -> int:
    samples_dir = Path(__file__).resolve().parent.parent / "samples"
    if samples_dir.is_dir() and list(samples_dir.glob("*.eml")):
        ns = argparse.Namespace(
            directory=str(samples_dir),
            json=args.json,
            enrich=False,
            quarantine_dir=args.quarantine_dir,
            telemetry_log=args.telemetry_log,
            feedback_store=None,
        )
        _cmd_scan_dir(ns)
        return 0

    pipeline = _build_pipeline(args)
    report = pipeline.analyze_parts(
        "=?utf-8?q?Acci=C3=B3n_Requerida=3A_Cuenta_Bloqueada?=",
        """
        <html><body>
          <p>Estimado usuario, se requiere acci&#243;n <b>urgente</b>.</p>
          <p>Su c\u200buen\u200bta ha sido suspendida.</p>
          <div style="display:none">Texto oculto para evadir filtros</div>
          <p>Verifique aqu&#x2F;:
             <a href="http://xn--googl-0qa.com/login">https://www.google.com/login</a>
          </p>
        </body></html>
        """,
        sender="Soporte Google <alertas@seguridad-cuenta.xyz>",
        source_name="demo_inline",
    )
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    else:
        print(format_report_text(report))
    return 0


def _cmd_feedback(args: argparse.Namespace) -> int:
    store = FeedbackStore(args.store)
    rec = store.record(
        args.trace_id,
        args.label,
        domain=args.domain or "",
        notes=args.notes or "",
    )
    print(
        f"Recorded feedback [{rec.label}] for trace {rec.trace_id}"
        + (f" (domain={rec.domain})" if rec.domain else "")
        + f" in {args.store}"
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishing-detector",
        description="Multi-layer Defense-in-Depth Email Phishing Detector",
    )
    sub = parser.add_subparsers(dest="command")

    # scan
    p_scan = sub.add_parser("scan", help="Scan a single .eml file")
    p_scan.add_argument("file", help="Path to the .eml file")
    p_scan.add_argument("--json", action="store_true", help="Output report as JSON")
    p_scan.add_argument("--enrich", action="store_true", help="Enable live RDAP/unshortener/Threat Intel lookups")
    p_scan.add_argument("--quarantine-dir", help="Directory to quarantine high/critical emails")
    p_scan.add_argument("--telemetry-log", help="Path to JSONL SIEM telemetry log file")
    p_scan.add_argument("--feedback-store", help="Path to feedback JSONL store for allow/block overrides")
    p_scan.set_defaults(func=_cmd_scan)

    # scan-dir
    p_dir = sub.add_parser("scan-dir", help="Scan all .eml files in a directory")
    p_dir.add_argument("directory", help="Directory containing .eml files")
    p_dir.add_argument("--json", action="store_true", help="Output reports as JSON array")
    p_dir.add_argument("--enrich", action="store_true", help="Enable live RDAP/unshortener/Threat Intel lookups")
    p_dir.add_argument("--quarantine-dir", help="Directory to quarantine high/critical emails")
    p_dir.add_argument("--telemetry-log", help="Path to JSONL SIEM telemetry log file")
    p_dir.add_argument("--feedback-store", help="Path to feedback JSONL store for allow/block overrides")
    p_dir.set_defaults(func=_cmd_scan_dir)

    # demo
    p_demo = sub.add_parser("demo", help="Run demonstration analysis on sample emails")
    p_demo.add_argument("--json", action="store_true", help="Output reports as JSON")
    p_demo.add_argument("--quarantine-dir", help="Optional quarantine directory")
    p_demo.add_argument("--telemetry-log", help="Optional SIEM telemetry JSONL file")
    p_demo.set_defaults(func=_cmd_demo)

    # feedback
    p_fb = sub.add_parser("feedback", help="Record analyst feedback for false positive/negative tuning")
    p_fb.add_argument("trace_id", help="Trace ID from a previous scan report")
    p_fb.add_argument(
        "--label",
        required=True,
        choices=["false_positive", "false_negative", "confirmed_phishing"],
        help="Analyst classification",
    )
    p_fb.add_argument("--domain", help="Sender/destination domain to allowlist or blocklist")
    p_fb.add_argument("--notes", help="Optional analyst notes")
    p_fb.add_argument("--store", default="feedback.jsonl", help="Path to feedback JSONL store")
    p_fb.set_defaults(func=_cmd_feedback)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        args = parser.parse_args(["demo"])
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
