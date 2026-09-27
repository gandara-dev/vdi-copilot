# Testing Guide

Install development dependencies and run the complete local gate:

```bash
python -m pip install -e ".[dev]"
python -m pytest --cov=vdi_copilot --cov-report=term-missing --cov-fail-under=75
ruff check .
ruff format --check .
```

The tests cover deterministic rule matches, privacy redaction, CLI output,
collection limits, and the optional LLM contract through an HTTP mock. Synthetic
DNS and STA incidents have known expected findings.

CI runs Python 3.11 and 3.13 on Windows and Linux, Ruff, smoke analysis, and
Mermaid rendering. It downloads no model and accesses no Citrix infrastructure.

New rules require positive and negative fixtures, fixed expected findings, and
synthetic evidence containing no customer or production identifiers.
