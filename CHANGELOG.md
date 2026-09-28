# Changelog

All notable changes to this project will be documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-09-28

### Added

- Evidence Analyzer page (`site/`), published with GitHub Pages: sample
  incidents or your own logs, redaction summary, findings with triggering terms,
  highlighted evidence, and the CLI's JSON report, all in the browser.
- `--format html` standalone report with escaped content.
- Synthetic incidents for the profile-container lock and Kerberos clock-skew
  rules, so every packaged rule has a known-cause sample.
- `validate_rules` for parsed rule documents.
- Fixtures generated from the Python engine that the page's JavaScript engine
  must reproduce exactly, plus a Node test suite.

### Fixed

- The CI lint job pinned Ruff 0.13.2 while the development dependencies used
  0.16.9; both now use 0.16.9.

## [0.1.1] - 2026-09-28

### Added

- Real loopback HTTP contract test for the optional Ollama-compatible endpoint.
- Windows event-log collector smoke test in CI.
- Release-verification guide and expanded environment configuration guidance.

## [0.1.0] - 2026-09-27

### Added

- Cross-platform VDI evidence analyzer with deterministic rules.
- Windows event-log and product-log collection with default redaction.
- Optional local or remote Ollama-compatible explanation provider.
- Synthetic incidents with known causes, pytest coverage, and CI.
- Static architecture diagram and architecture, operations, testing, security,
  and contribution documentation.
