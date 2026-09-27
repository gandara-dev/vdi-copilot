"""Create a deterministic asciinema cast from the synthetic VDA incident."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from vdi_copilot.evidence import load_evidence  # noqa: E402
from vdi_copilot.rules import evaluate_rules, load_rules  # noqa: E402


def main() -> None:
    evidence = load_evidence(ROOT / "samples/incidents/vda-registration-dns")
    finding = evaluate_rules(evidence, load_rules())[0]
    escape = "\x1b"
    green = f"{escape}[32m"
    yellow = f"{escape}[33m"
    cyan = f"{escape}[36m"
    dim = f"{escape}[2m"
    reset = f"{escape}[0m"
    elapsed = 0.0
    events: list[str] = []

    def add(delay: float, text: str) -> None:
        nonlocal elapsed
        elapsed += delay
        events.append(json.dumps([elapsed, "o", text], separators=(",", ":")))

    header = {
        "version": 2,
        "width": 112,
        "height": 27,
        "timestamp": 0,
        "env": {"SHELL": "bash", "TERM": "xterm-256color"},
        "title": "VDI Copilot demo",
    }
    add(0.0, f"{cyan}VDI COPILOT{reset}  {dim}Evidence first, LLM optional{reset}\r\n\r\n")
    add(0.6, f"{yellow}${reset} vdi-copilot analyze samples/incidents/vda-registration-dns\r\n\r\n")
    add(0.5, "Sources: 1 | Findings: 1\r\n")
    add(0.3, f"Evidence redacted: {green}yes{reset}\r\n\r\n")
    add(0.5, f"{green}[{finding.severity.upper()}]{reset} {finding.title}\r\n")
    add(0.3, f"Rule: {finding.rule_id} | confidence: {finding.confidence}\r\n")
    for recommendation in finding.recommendations:
        add(0.3, f"  - {recommendation}\r\n")
    add(0.6, f"\r\n{dim}No model or Citrix site was contacted.{reset}\r\n")
    add(1.8, f"{cyan}Collect -> redact -> match -> validate{reset}\r\n")

    output = ROOT / "demo/demo.cast"
    output.write_text(
        "\n".join([json.dumps(header, separators=(",", ":")), *events]) + "\n",
        encoding="utf-8",
    )
    print(f"Created asciinema recording: {output}")


if __name__ == "__main__":
    main()
