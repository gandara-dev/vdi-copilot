"""Command-line interface."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .evidence import collect_windows_events, load_evidence, write_bundle
from .llm import explain_with_ollama
from .models import AnalysisReport, Evidence
from .redact import redact_text
from .report import render_console, render_json
from .rules import evaluate_rules, load_rules


def _add_privacy_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--no-redact",
        action="store_true",
        help="Preserve sensitive identifiers in evidence (unsafe by default).",
    )
    parser.add_argument(
        "--acknowledge-sensitive-data",
        action="store_true",
        help="Required with --no-redact to confirm the data-handling risk.",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vdi-copilot",
        description="Evidence-first VDI troubleshooting with deterministic rules.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser("analyze", help="Analyze a file, directory, or bundle.")
    analyze.add_argument("input", help="Evidence file, directory, or collected bundle.")
    analyze.add_argument("--rules", help="Custom schema-version 1 JSON rule file.")
    analyze.add_argument("--format", choices=("console", "json"), default="console")
    analyze.add_argument("--output", help="Write the rendered report to this file.")
    analyze.add_argument("--llm", choices=("none", "ollama"), default="none")
    analyze.add_argument("--endpoint", default="http://127.0.0.1:11434")
    analyze.add_argument("--model", default="qwen3:4b-instruct")
    analyze.add_argument(
        "--api-key-env",
        default="VDI_COPILOT_API_KEY",
        help="Environment variable containing a remote endpoint bearer token.",
    )
    _add_privacy_arguments(analyze)

    collect = subparsers.add_parser("collect", help="Create a portable evidence bundle.")
    collect.add_argument("--output", required=True, help="Destination JSON bundle.")
    collect.add_argument(
        "--log",
        action="append",
        default=[],
        help="Product log file or directory; repeat for multiple paths.",
    )
    collect.add_argument(
        "--event-log",
        action="append",
        default=[],
        help="Windows event channel; repeat for multiple channels.",
    )
    collect.add_argument("--max-events", type=int, default=200)
    _add_privacy_arguments(collect)
    return parser


def _validate_privacy(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    if args.no_redact and not args.acknowledge_sensitive_data:
        parser.error("--no-redact requires --acknowledge-sensitive-data")


def _analyze(args: argparse.Namespace) -> int:
    should_redact = not args.no_redact
    evidence = load_evidence(args.input, redact=should_redact)
    findings = evaluate_rules(evidence, load_rules(args.rules))
    report = AnalysisReport(
        findings=findings,
        sources=[item.source for item in evidence],
        redacted=should_redact,
    )

    if args.llm == "ollama" and findings:
        report.explanation = explain_with_ollama(
            findings,
            evidence,
            endpoint=args.endpoint,
            model=args.model,
            api_key=os.environ.get(args.api_key_env),
        )

    rendered = render_json(report) if args.format == "json" else render_console(report)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0


def _collect(args: argparse.Namespace) -> int:
    if not args.log and not args.event_log:
        raise ValueError("At least one --log or --event-log input is required.")
    if args.max_events < 1 or args.max_events > 10_000:
        raise ValueError("--max-events must be between 1 and 10000.")

    should_redact = not args.no_redact
    evidence: list[Evidence] = []
    for path in args.log:
        evidence.extend(load_evidence(path, redact=should_redact))
    if args.event_log:
        windows_events = collect_windows_events(args.event_log, args.max_events)
        evidence.extend(
            Evidence(item.source, redact_text(item.text) if should_redact else item.text)
            for item in windows_events
        )
    write_bundle(args.output, evidence, redacted=should_redact)
    print(f"Wrote {len(evidence)} evidence source(s) to {args.output}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _validate_privacy(args, parser)
    try:
        if args.command == "analyze":
            return _analyze(args)
        return _collect(args)
    except (FileNotFoundError, ValueError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
