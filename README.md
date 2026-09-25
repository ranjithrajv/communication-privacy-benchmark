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
- Repetition roll-up and longitudinal bundle comparison.
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

# Reduce the bundle to a per-check stability verdict across repetitions.
uv run --locked pt-bench rollup \
  --bundle build/run-bundle \
  --output build/run-rollup.json

# Compare this run against an earlier one, without collapsing checks into a score.
uv run --locked pt-bench compare \
  --baseline build/previous-run-bundle \
  --candidate build/run-bundle \
  --output build/run-comparison.json
```

Local runs record `execution.mode = "local"` and cannot become canonical benchmark
results. GitHub Actions records `execution.mode = "github_actions"` with run provenance.

## Commands

```text
pt-bench registry validate
pt-bench operations validate
pt-bench schemas export
pt-bench schemas validate PATH...
pt-bench plan --suite ... --output ... [--allow-unapproved-subjects]
pt-bench execute --plan ... --subject ... --adapter ... --output-dir ...
pt-bench finalize --plan ... --execution-dir ...
pt-bench aggregate --plan ... --executions ... --output ...
pt-bench rollup --bundle ... --output ...
pt-bench compare --baseline ... --candidate ... --output ... [--fail-on-regression]
```

## Operational policy and the canonical gate

`operations/1.0.0/operations.toml` records the decisions that must exist before any
canonical measurement: the reference network vantage, runner lanes, synthetic account
recovery procedures, canary services, evidence retention and redaction rules, the
publication target, and one provider-terms review per subject.

`pt-bench operations validate` reports readiness. It exits `2` while anything is still
blocked, which is the current state, and `1` only when the policy is missing or invalid.

The load-bearing part is the gate in `pt-bench plan`: a GitHub Actions run is refused
for any subject whose provider-terms review is not `approved`.

```console
$ pt-bench plan --suite suites/chat/1.0.0/suite.toml --output plan.json
Error: subject signal-android-default@1.0.0 has a pending provider-terms review;
canonical runs require an approved review
subject whatsapp-android-default@1.0.0 has a pending provider-terms review;
canonical runs require an approved review
subject telegram-android-default@1.0.0 has a pending provider-terms review;
canonical runs require an approved review
```

This fails closed on purpose. The largest existential risk in this project is not a
wrong measurement; it is a provider account being terminated for automating an
interaction its terms do not permit, which would destroy the lab rather than corrupt one
row. Approving a review is a human decision that requires a reviewer, the terms URL, and
the specific actions being authorized — see [CONTRIBUTING.md](CONTRIBUTING.md).

Only `fake-client` is currently approved, and that approval covers only the account-free
harness path. It deliberately authorizes no product claim.

## Reading a run

A run bundle holds one raw result per check, per subject, per repetition. Two derived
views sit on top of it, and neither is a benchmark result:

`pt-bench rollup` reduces the repetitions to one stability verdict per check:

| Outcome | Meaning |
|---|---|
| `pass` / `fail` | Every repetition agreed. A stable product property. |
| `flaky` | Both a pass and a fail occurred. Not a stable property. |
| `inconclusive` | No stable pass or fail, e.g. a pass mixed with an error. |
| `not_applicable` / `unsupported` | Every repetition agreed the check does not apply. |
| `incomplete` | Fewer repetitions than planned. No stability claim is made. |

A pass rate and a 95% Wilson score interval accompany every decisive check. The
interval is wide at small repetition counts, which is the point: three passing runs are
reported as the evidence they are, not as a guarantee.

`pt-bench compare` reports the direction of change between two bundles. Only a verdict
that established a pass or a fail on both sides is ordered as `improved` or
`regressed`; anything else is `unorderable` and is deliberately left unscored. New and
dropped checks are reported as `added` and `removed`, and a client or check version
bump is flagged on the same row rather than split into two.

Both commands verify bundle checksums before reading and refuse to write inside a
bundle, so the evidence record stays append-only. `compare --fail-on-regression` exits
non-zero on a regression for use in a scheduled lane.

## Repository layout

```text
src/privacy_benchmark/   First-party Python package
checks/                  Versioned check definitions
subjects/                Versioned subject definitions
suites/                  Versioned suite definitions
operations/              Versioned operational policy and approval gate
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
