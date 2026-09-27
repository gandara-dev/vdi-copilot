"""Report rendering."""

from __future__ import annotations

import json

from .models import AnalysisReport


def render_json(report: AnalysisReport) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)


def render_console(report: AnalysisReport) -> str:
    lines = ["VDI COPILOT", "Evidence-first troubleshooting report", ""]
    lines.append(f"Sources: {len(report.sources)} | Findings: {len(report.findings)}")
    lines.append(f"Evidence redacted: {'yes' if report.redacted else 'NO'}")
    lines.append("")

    if not report.findings:
        lines.extend(
            [
                "No deterministic rule matched.",
                "This is not proof that the environment is healthy; collect more evidence.",
            ]
        )
    for index, finding in enumerate(report.findings, start=1):
        lines.append(
            f"{index}. [{finding.severity.upper()}] {finding.title} "
            f"(confidence: {finding.confidence})"
        )
        lines.append(f"   Rule: {finding.rule_id}")
        lines.append(f"   Evidence: {', '.join(finding.evidence) or 'combined corpus'}")
        for recommendation in finding.recommendations:
            lines.append(f"   - {recommendation}")
        lines.append("")

    if report.explanation:
        lines.extend(["LLM explanation (advisory):", report.explanation, ""])
    lines.append("Validate every recommendation in a non-production scope first.")
    return "\n".join(lines)
