# Testing Guide

Install development dependencies and run the complete local gate:

```bash
python -m pip install -e ".[dev]"
python -m pytest --cov=vdi_copilot --cov-report=term-missing --cov-fail-under=75
ruff check .
ruff format --check .
```

The tests cover deterministic rule matches, privacy redaction, CLI output,
collection limits, the optional LLM contract through a unit mock, and a real
loopback HTTP request to a disposable compatible endpoint. Every packaged rule
has a synthetic incident with a known expected finding, and a test fails when a
rule has no incident.

## Evidence Analyzer parity

The page's engine (`site/lib/analyzer.js`) must redact and match exactly like
the Python package. The package is the reference:

- `tests/update_analyzer_fixtures.py` records Python's output for redaction
  inputs, every sample incident, custom rules (exclusions, severity ordering,
  multiple sources), redaction disabled, and invalid rule files;
- `scripts/export_site_data.py` bundles the default rules and incidents into
  `site/data/analyzer-data.json` for the page;
- pytest fails if either generated file is out of date, and
  `node --test tests/web/*.test.mjs` fails if the browser engine disagrees.

After changing rules, redaction, or incidents, regenerate and review the diff:

```bash
python scripts/export_site_data.py
python tests/update_analyzer_fixtures.py
```

The browser applies ASCII word boundaries and lower-casing; the fixtures use
ASCII evidence, which is what VDI product logs contain.

CI runs Python 3.11 and 3.13 on Windows and Linux, Ruff, smoke analysis, a
one-event Windows collector check, the Evidence Analyzer suite, and Mermaid
rendering. `.github/workflows/pages.yml` tests the page again and publishes
`site/` to GitHub Pages when it changes on `main`. It downloads no model
and accesses no Citrix infrastructure.

New rules require positive and negative fixtures, fixed expected findings, and
synthetic evidence containing no customer or production identifiers.
