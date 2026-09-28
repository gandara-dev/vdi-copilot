# Release Verification

## Public release gate

Every change must pass:

- editable installation from a fresh clone with no runtime dependencies;
- pytest on Python 3.11 and 3.13, Windows and Linux, with at least 75% coverage;
- both synthetic known-cause incidents through the installed CLI;
- privacy, rule validation, CLI, and Ollama request-contract tests;
- Ruff lint and formatting checks;
- CodeQL and Mermaid rendering;
- a Windows collector smoke test that queries an event channel, writes a
  redacted bundle, and analyzes that bundle;
- an end-to-end `/api/chat` call to a local mock endpoint proving non-streaming
  JSON request and response handling without sending evidence externally.

Run the portable checks in an isolated environment:

```bash
python -m venv .venv
# Windows: .venv\Scripts\python -m pip install -e ".[dev]"
# Linux/macOS: .venv/bin/python -m pip install -e ".[dev]"
python -m pytest --cov=vdi_copilot --cov-fail-under=75
ruff check .
ruff format --check .
vdi-copilot analyze samples/incidents/vda-registration-dns
vdi-copilot analyze samples/incidents/storefront-sta-failure --format json
```

## Environment acceptance gate

Before using real incident evidence:

1. Test event-channel access under the intended Windows identity.
2. Collect the smallest representative log set and inspect the redacted bundle.
3. Add organization-specific redaction rules outside the public repository when
   the default patterns do not cover local identifiers.
4. Validate deterministic findings against a known incident before operational
   use.
5. If an LLM is enabled, test the exact endpoint, model, authentication,
   retention policy, timeout behavior, and invalid-response failure path.
6. Keep original evidence under existing incident-response controls.

A passing public build validates deterministic rules, packaging, collection,
redaction patterns, reporting, and the compatible HTTP contract. It does not
guarantee exhaustive diagnosis or that best-effort redaction replaces DLP and
human review.
