# Operations and Privacy Guide

Run collection from a trusted workstation or the affected Windows host under an
identity permitted to read the selected event channels and files. Scope inputs
narrowly and write bundles to an access-controlled directory.

## Isolated installation

Use a virtual environment so upgrades and rollback do not change the system
Python installation:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\vdi-copilot.exe analyze samples/incidents/vda-registration-dns
```

On Linux or macOS, replace `.venv\Scripts` with `.venv/bin`. The CLI has no
runtime package dependencies. Python 3.11 or newer is required.

## Environment configuration

The CLI is configured entirely through explicit arguments:

| Setting | Default | Guidance |
|---|---|---|
| `--rules` | packaged deterministic rules | Copy and version the JSON file before adding organization-specific rules |
| `--event-log` | none | Repeat for each Windows channel the operator is authorized to read |
| `--log` | none | Pass narrow files or directories; each file is limited to 2 MB |
| `--max-events` | `200` | Reduce for a first collection; valid range is 1 through 10,000 |
| `--llm` | `none` | Enable `ollama` only after deterministic output is accepted |
| `--endpoint` | `http://127.0.0.1:11434` | Use an approved compatible `/api/chat` service |
| `--model` | `qwen3:4b-instruct` | Confirm the model exists on the selected endpoint |
| `--api-key-env` | `VDI_COPILOT_API_KEY` | Name of the environment variable containing the bearer token |

Test collection and analysis separately before enabling an LLM:

```powershell
vdi-copilot collect `
  --event-log Application `
  --max-events 20 `
  --output collected-incident.json
vdi-copilot analyze collected-incident.json --format json --output report.json
```

Review `collected-incident.json` directly. Its `redacted` field must be `true`
unless both unsafe opt-out flags were intentionally supplied.

## Evidence handling

Redaction is enabled by default and covers common credentials, bearer tokens,
email addresses, IPv4 addresses, FQDNs, user-profile paths, and domain SIDs.
Inspect the resulting bundle before attaching it to a ticket or sending it to
another system. Define retention, deletion, regional processing, and access
controls according to the incident's data classification.

Do not place real evidence in this repository, CI artifacts, public issues, or
sample fixtures.

## Analysis workflow

1. Preserve original logs under existing incident-response controls.
2. Collect the smallest useful evidence scope.
3. Review redaction and source metadata.
4. Run deterministic analysis and validate timestamps and affected scope.
5. Treat recommendations as checks, not automatic remediation.
6. Record confirmed cause separately from the tool's diagnostic lead.

## Optional LLM

Prefer a local approved endpoint. Before using any remote compatible API, review
the redacted bundle and the provider's retention and regional-processing terms.
Set API tokens outside shell history and rotate them according to policy.

If the model endpoint is unavailable or returns invalid JSON, preserve the
deterministic report and investigate the model path separately.

For a remote compatible endpoint, set the token without placing it in a command
line and name the environment variable explicitly when it differs from the
default:

```powershell
$env:VDI_COPILOT_API_KEY = Read-Host 'API key' -MaskInput
vdi-copilot analyze collected-incident.json `
  --llm ollama `
  --endpoint https://llm.example.test `
  --model approved-model
Remove-Item Env:VDI_COPILOT_API_KEY
```

Complete the environment acceptance checklist in
[Release verification](release-verification.md) before using real evidence.

## Upgrades and rollback

Rules and output schema are operational interfaces. Review the changelog, run
both synthetic known-cause incidents, and compare JSON output before upgrading.
Rollback by reinstalling the previous repository tag; keep incident evidence
independent of the installed package directory.
