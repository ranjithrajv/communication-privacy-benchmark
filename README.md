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

Signal, WhatsApp, and Telegram are declared as Android subjects, with two draft checks
and one draft suite:

```text
subjects/signal-android-default/1.0.0      org.thoughtcrime.securesms
subjects/whatsapp-android-default/1.0.0     com.whatsapp
subjects/telegram-android-default/1.0.0     org.telegram.messenger
checks/chat/link-preview-fetch/1.0.0        draft   network surface
checks/chat/notification-preview/1.0.0      draft   display surface
suites/chat/1.0.0                           draft
```

The two checks observe different surfaces and so need different adapters.
`link-preview-fetch` watches the network: does opening a message fetch a canary URL?
`notification-preview` watches the lock screen: how much of the message body does the
client put in a notification? The second leaks with no canary contact at all, so the
canary guards do not apply to it and its evidence kind is `notification_shade` rather
than `canary_event`.

These are **lane declarations, not measurements.** They pin the parts of a subject
that the lab controls — app, package, service, account slot, settings profile, and
runner class — and deliberately leave the runtime-derived facts unset: app version,
build, APK hash, device model, OS build, and measurement region. Those are captured by
`device-preflight` at measurement time, so a subject never asserts an app version that
was not observed.

Each chat subject declares a `notification_privacy` level of `content`, `sender_only`,
or `none`. One normalized vocabulary across all three apps on purpose: each names this
setting differently in its own UI, so subjects declare the normalized level and a
published row compares like with like.

The suite stays `draft` until four gates close: a dedicated physical Android device per
account slot, a synthetic phone number per app, a provider-terms review, and — for the
notification check specifically — verification of the `dumpsys` parser against the
target Android build. Until then no chat result can be canonical or published.

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
pt-bench preflight --subject ... --output ... [--app-bundle ... | --adb-serial ...]
pt-bench verify-shade --serial ... --package ...
pt-bench execute --plan ... --subject ... --adapter ... --output-dir ... [--observation ...]
pt-bench finalize --plan ... --execution-dir ...
pt-bench aggregate --plan ... --executions ... --output ...
pt-bench rollup --bundle ... --output ...
pt-bench compare --baseline ... --candidate ... --output ... [--fail-on-regression]
pt-bench report --bundle ... --output ... [--stdout]
pt-bench site --bundle ... --output-dir ... [--root .]
pt-bench publish --bundle ... --staging ...
```

`preflight` observes the runtime identity a measurement will be attributed to — the
app version, build, artifact hash, device model, and vantage that a subject deliberately
leaves unset. `verify-shade` is a standalone capability probe that asks whether this
harness can read a device's notification shade at all, before a lane is built on that
assumption. Both fail closed: `preflight` exits `2` when the observation blocks a
measurement, and `verify-shade` exits `2` when the shade is unreadable.

## The published page

`pt-bench site` renders a bundle as a static GitHub Pages site. The page is a *view* over a
bundle that cleared the publication gate, never a second artifact of record: it is regenerated
from the bundle on every publish and never edited by hand, so it cannot drift from the
evidence it describes. The release asset and its receipt remain what a reader cites.

```bash
uv run --locked pt-bench site --bundle build/run-bundle --output-dir build/site
```

The command fails closed on the operations policy, which must name `github_pages` as its
publication target. A run that did not clear the gate still renders a page, and that page
carries the refusal, so the reason is on the public record rather than inferred from a run
that is simply absent. The command exits `2` in that case, so a scheduled lane can refuse to
deploy it.

Pages are static, so the "server" htmx requests from is the filesystem: every fragment is
pre-rendered at build time and the page is fully readable with JavaScript disabled. htmx 4 is
pinned to an exact version and loaded only on the pages that use it.

A web page is a materially wider surface than a release asset — indexable, cached
indefinitely, and quotable cell by cell without its run provenance — so the page keeps every
rate beside the 95% interval that qualifies it, and marks a cell that establishes no product
property in three channels rather than colour alone.

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

## Email pilot lane

Two native mail clients are declared as subjects, with one check and one draft suite:

```text
subjects/apple-mail-gmail-consumer/1.0.0      Apple Mail  + Gmail consumer
subjects/thunderbird-gmail-consumer/1.0.0     Thunderbird + the same Gmail account
checks/email/remote-content/1.0.0              draft
suites/email/1.0.0                             draft
```

Both subjects read the **same synthetic account from the same vantage**, and they differ
in exactly the setting the check measures (`load_remote_content`). A difference between
the two rows is therefore attributable to the client, which is the whole point of a
configuration-aware benchmark.

### The EPT adapter

`pt-bench execute --adapter ept` drives a private gateway in front of a pinned upstream
Email Privacy Tester deployment. The benchmark never calls undocumented EPT routes,
reads its database, or scrapes its UI.

Configuration comes from the environment, never from a checked-in definition, so a real
mailbox address cannot reach the repository:

| Variable | Purpose |
|---|---|
| `PT_BENCH_EPT_GATEWAY_URL` | Private gateway base URL |
| `PT_BENCH_EPT_GATEWAY_TOKEN` | Gateway bearer token |
| `PT_BENCH_EPT_MAILBOXES` | JSON object mapping account slot ids to synthetic addresses |

The adapter is only registered when a gateway is configured, so a checkout without
credentials cannot accidentally address a real deployment.

### What is observed, and what is claimed

The gateway contract is derived from the pinned upstream source, not from its
documentation. `infra/ept/UPSTREAM_FINDINGS.md` records what was verified, and three
facts changed the design:

**Only three observation channels exist.** EPT ships two watcher processes plus the canary
web server. There is no TCP watcher: the preconnect vector is typed `tcp` upstream but is
observable *only* through the SNI watcher. A MIME watcher does not exist at all.

**EPT has no open signal.** `Tests.accessed` is set when the test mail is *sent* and again
on the first callback, so it is not a delivery or open confirmation. The open is an
interaction the harness performs, so the adapter takes an `open_observer` and reports
`inconclusive` when it is not supplied. An adapter cannot claim a `pass` it did not earn.

**A canary contact is not automatically the client's fault.** EPT's own `dnsAnchor` text
warns that provider spam filters prefetch the canary, and those lookups are recorded
exactly like a client rendering the message. Every observation therefore carries an
`origin`:

| Origin | Result |
|---|---|
| `client` | Scored. A client-attributed contact is a `fail`. |
| `provider` | Recorded as evidence, never scored as a client leak. Provider-only activity is `inconclusive`. |
| `unknown` | `inconclusive`. Something happened; it cannot be pinned to the client. |

The gateway must also confirm **delivery** and **watcher health** before an absence means
anything, since upstream records neither.

| Gateway state | Result |
|---|---|
| Never delivered | `inconclusive` |
| Watchers unhealthy | `inconclusive` |
| Delivered, open not asserted | `inconclusive` |
| Opened, client-attributed contact | `fail` |
| Opened, provider-only or unattributed contact | `inconclusive` |
| Opened, watchers healthy, no contact | `pass` |

Observations carrying a foreign `probe_id` are rejected rather than adjudicated, so a
gateway mix-up cannot be reported as a product property.

### What has been validated, and what has not

`harness/canary.py` runs a real, self-hosted canary: a real HTTP server that serves an
actual GIF, a real authoritative DNS server that answers over UDP and logs in BIND's
query format, and real MIME messages carrying real canary URLs.
`tests/integration/test_live_canary.py` drives it over real sockets and asserts that a
genuine client fetch and a genuine DNS prefetch are both detected and adjudicated as
client-attributed failures.

**Validated:** the adapter observes and adjudicates real network activity, the canary
serves and records real requests, the DNS watcher semantics are reproduced, real MIME
delivery works, and the full harness path (evidence hashing, result writing, checksums)
runs against all of it.

**Not validated:** whether a real mail client fetches remote content, and whether a real
provider mailbox accepts and renders a probe. Both need a provider account and a
provider-terms approval, which the canonical gate refuses to bypass. `mailboxes` remains
the one input the lab cannot supply for itself.

Two upstream traps are reproduced deliberately in the canary so a lab learns about them
rather than tripping over them: the watchers refuse to record the lab's own host address,
so client and canary must be on different machines; and the DNS watcher's pattern matches
only the `anchor-test` and `link-test` labels, so the `img-test` label used by the
`dnsImg` vector can never fire it.

## Reading a run## Reading a run

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
