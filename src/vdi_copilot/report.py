"""Report rendering."""

from __future__ import annotations

import html
import json

from .models import AnalysisReport

_HTML_STYLE = """
:root { color-scheme: light dark; --bg: #f4f6f9; --surface: #fff; --border: #d6dde7;
  --text: #16202c; --muted: #5b6878; --critical: #7a1111; --high: #b42318; --medium: #9a5b00;
  --low: #16794a; }
@media (prefers-color-scheme: dark) { :root { --bg: #0d131b; --surface: #141c26;
  --border: #2a3645; --text: #e6edf5; --muted: #9aa8b8; --critical: #ff8a80; --high: #f47066;
  --medium: #f0b659; --low: #4cc38a; } }
body { margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.5 system-ui, "Segoe UI", Roboto, sans-serif; }
main { max-width: 900px; margin: 0 auto; padding: 24px 16px 48px; }
h1 { margin: 0; font-size: 24px; }
.summary { color: var(--muted); margin: 4px 0 20px; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px;
  padding: 16px; margin-bottom: 14px; }
.card h2 { margin: 0 0 6px; font-size: 17px; }
.badge { display: inline-block; font-size: 12px; font-weight: 700; border: 1px solid;
  border-radius: 999px; padding: 1px 8px; margin-right: 6px; text-transform: uppercase; }
.critical { color: var(--critical); } .high { color: var(--high); }
.medium { color: var(--medium); } .low { color: var(--low); }
.meta { color: var(--muted); font-size: 13px; }
code { font-family: ui-monospace, Consolas, monospace; font-size: 13px; }
.explanation { white-space: pre-wrap; }
footer { color: var(--muted); font-size: 13px; margin-top: 24px; }
"""


def render_html(report: AnalysisReport) -> str:
    """Render a standalone HTML report. Every value from evidence or rules is escaped."""

    def esc(value: object) -> str:
        return html.escape(str(value), quote=True)

    redaction = "yes" if report.redacted else "NO (sensitive data may be present)"
    parts = [
        "<!doctype html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>VDI Copilot report</title>",
        f"<style>{_HTML_STYLE}</style>",
        "</head>",
        "<body>",
        "<main>",
        "<h1>VDI Copilot report</h1>",
        f'<p class="summary">Sources: {len(report.sources)} | '
        f"Findings: {len(report.findings)} | Evidence redacted: {esc(redaction)}</p>",
    ]
    if report.sources:
        sources = ", ".join(f"<code>{esc(source)}</code>" for source in report.sources)
        parts.append(f'<p class="meta">Analyzed: {sources}</p>')

    if not report.findings:
        parts.append(
            '<section class="card"><h2>No deterministic rule matched</h2>'
            "<p>This is not proof that the environment is healthy; collect more evidence.</p>"
            "</section>"
        )
    for finding in report.findings:
        severity = finding.severity.lower()
        css = severity if severity in {"critical", "high", "medium", "low"} else ""
        evidence = ", ".join(f"<code>{esc(item)}</code>" for item in finding.evidence)
        recommendations = "".join(f"<li>{esc(item)}</li>" for item in finding.recommendations)
        parts.append(
            '<section class="card">'
            f'<h2><span class="badge {css}">{esc(finding.severity)}</span>{esc(finding.title)}</h2>'
            f'<p class="meta">Rule <code>{esc(finding.rule_id)}</code> | '
            f"confidence: {esc(finding.confidence)} | "
            f"evidence: {evidence or 'combined corpus'}</p>"
            f"<ul>{recommendations}</ul>"
            "</section>"
        )

    if report.explanation:
        parts.append(
            '<section class="card"><h2>LLM explanation (advisory)</h2>'
            f'<p class="explanation">{esc(report.explanation)}</p></section>'
        )
    parts.extend(
        [
            "<footer>Validate every recommendation in a non-production scope first. "
            "Redaction is best effort and does not replace a human review.</footer>",
            "</main>",
            "</body>",
            "</html>",
        ]
    )
    return "\n".join(parts)


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
