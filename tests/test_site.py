"""Keeps the Evidence Analyzer page in sync with the Python engine."""

import importlib.util
import json
from pathlib import Path
from types import ModuleType

from vdi_copilot.cli import main
from vdi_copilot.models import AnalysisReport, Finding
from vdi_copilot.report import render_html

ROOT = Path(__file__).parents[1]


def _load(path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_site_data_is_current() -> None:
    exporter = _load(ROOT / "scripts" / "export_site_data.py")
    published = json.loads((ROOT / "site" / "data" / "analyzer-data.json").read_text("utf-8"))

    assert exporter.build() == published


def test_analyzer_fixtures_are_current() -> None:
    generator = _load(ROOT / "tests" / "update_analyzer_fixtures.py")
    published = json.loads((ROOT / "tests" / "fixtures" / "analyzer-cases.json").read_text("utf-8"))

    assert generator.build() == published


def test_html_report_escapes_evidence_and_rules() -> None:
    finding = Finding(
        rule_id="<script>",
        title='Title with "quotes" & <b>markup</b>',
        severity="high",
        confidence="high",
        evidence=("vda<1>.log",),
        recommendations=("Run <this>",),
    )
    report = AnalysisReport(findings=[finding], sources=["vda<1>.log"], explanation="<img>")

    rendered = render_html(report)

    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered
    assert "&quot;quotes&quot; &amp; &lt;b&gt;markup&lt;/b&gt;" in rendered
    assert "Run &lt;this&gt;" in rendered
    assert "&lt;img&gt;" in rendered


def test_html_report_without_findings_says_so() -> None:
    rendered = render_html(AnalysisReport(sources=["empty.log"]))

    assert "No deterministic rule matched" in rendered


def test_analyze_html_output(tmp_path: Path) -> None:
    output = tmp_path / "report.html"
    exit_code = main(
        [
            "analyze",
            str(ROOT / "samples/incidents/kerberos-clock-skew"),
            "--format",
            "html",
            "--output",
            str(output),
        ]
    )

    rendered = output.read_text(encoding="utf-8")
    assert exit_code == 0
    assert rendered.startswith("<!doctype html>")
    assert "authentication-clock-skew" in rendered
    assert "198.51.100.14" not in rendered
