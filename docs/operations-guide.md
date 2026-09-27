# Operations and Privacy Guide

Run collection from a trusted workstation or the affected Windows host under an
identity permitted to read the selected event channels and files. Scope inputs
narrowly and write bundles to an access-controlled directory.

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

## Upgrades and rollback

Rules and output schema are operational interfaces. Review the changelog, run
both synthetic known-cause incidents, and compare JSON output before upgrading.
Rollback by reinstalling the previous repository tag; keep incident evidence
independent of the installed package directory.
