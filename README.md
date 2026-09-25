# Communication Privacy Benchmark

An open, GitHub Actions-based behavioral benchmark for email clients, webmail, and
messaging applications.

Every canonical privacy check is selected, executed, finalized, and published through
GitHub Actions. Persistent canary services and physical devices are dependencies of
those jobs; they do not independently produce benchmark outcomes.

> **Status:** Alpha scaffold. No product privacy conclusions have been published yet.

## Principles

- Configuration-aware subjects, not product logos.
- Per-check, per-subject, and per-threat results; no single privacy score.
- Versioned tests, adapters, subjects, evidence, and result contracts.
- Measured, static, documented/audit, and human-review evidence remain distinct.
- A product privacy `fail` is a successful measurement, not a CI failure.
- GitHub re-runs recover infrastructure failures; they are not new scientific repetitions.
- Synthetic accounts, contacts, and canary identifiers only.
- First-party code is licensed under AGPL-3.0-only.

## Current scope

This repository currently provides:

- A Python 3.14 package managed by `uv`.
- Versioned Pydantic/JSON Schema contracts for checks, subjects, run plans, results, evidence, and execution manifests.
- A `pt-bench` Click CLI.
- A check/subject/suite registry with coverage validation.
- A fake adapter for end-to-end GitHub Actions smoke testing.
- Deterministic result-bundle aggregation and checksums.
- CI for schemas, types, tests, packaging, dependency audit, licenses, and workflow security.

## Chat pilot lane

Signal, WhatsApp, and Telegram are declared as Android subjects, with one draft check
and one draft suite:

```text
subjects/signal-android-default/1.0.0      org.thoughtcrime.securesms
subjects/whatsapp-android-default/1.0.0     com.whatsapp
subjects/telegram-android-default/1.0.0     org.telegram.messenger
checks/chat/link-preview-fetch/1.0.0        draft
suites/chat/1.0.0                           draft
```

These are **lane declarations, not measurements.** They pin the parts of a subject
that the lab controls — app, package, service, account slot, settings profile, and
runner class — and deliberately leave the runtime-derived facts unset: app version,
build, APK hash, device model, OS build, and measurement region. Those are captured by
`device-preflight` at measurement time, so a subject never asserts an app version that
was not observed.

The suite stays `draft` until four gates close: a real `chat` adapter, a dedicated
physical Android device per account slot, a synthetic phone number per app, and a
provider-terms review. Until then no chat result can be canonical or published.

Real email subjects follow the same gate.

## Quick start

```bash
uv sync --locked --all-extras --all-groups

# Validate every checked-in check, subject, and suite.
uv run --locked pt-bench registry validate

# Confirm committed public schemas match the Pydantic models.
uv run --locked pt-bench schemas export --output-dir schemas/v1alpha1 --check

# Build a local, non-canonical smoke plan.
uv run --locked pt-bench plan \
  --suite suites/smoke/1.0.0/suite.toml \
  --output build/smoke-plan.json

# Run the fake adapter and create a deterministic execution bundle.
uv run --locked pt-bench execute \
  --plan build/smoke-plan.json \
  --subject fake-client \
  --adapter fake \
  --output-dir build/executions

# Finalize, verify, and aggregate the bundle.
uv run --locked pt-bench finalize \
  --plan build/smoke-plan.json \
  --execution-dir build/executions/fake-client/0001

uv run --locked pt-bench aggregate \
  --plan build/smoke-plan.json \
  --executions build/executions \
  --output build/run-bundle
```

Local runs record `execution.mode = "local"` and cannot become canonical benchmark
results. GitHub Actions records `execution.mode = "github_actions"` with run provenance.

## Commands

```text
pt-bench registry validate
pt-bench schemas export
pt-bench schemas validate PATH...
pt-bench plan --suite ... --output ...
pt-bench execute --plan ... --subject ... --adapter ... --output-dir ...
pt-bench finalize --plan ... --execution-dir ...
pt-bench aggregate --plan ... --executions ... --output ...
```

## Repository layout

```text
src/privacy_benchmark/   First-party Python package
checks/                  Versioned check definitions
subjects/                Versioned subject definitions
suites/                  Versioned suite definitions
schemas/v1alpha1/        Generated public JSON Schemas
infra/                   Persistent canary and runner configuration
.github/workflows/       Canonical execution and CI workflows
TECH_STACK_DECISION.md   Approved technology baseline
GITHUB_ACTIONS_ARCHITECTURE.md
```

## Documentation

- [Competitive and collaboration landscape](COMMUNICATION_PRIVACY_LANDSCAPE.md)
- [GitHub Actions architecture](GITHUB_ACTIONS_ARCHITECTURE.md)
- [Technology stack decision](TECH_STACK_DECISION.md)
- [Changelog](CHANGELOG.md)

## License

AGPL-3.0-only. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
