# GitHub Actions Architecture for the Communication Privacy Benchmark

**Study date:** 25 September 2026<br>
**Reference implementation:** [`privacytests/privacytests`](https://github.com/privacytests/privacytests), commit `d9eb923044d197837a630a25d29c3061a1afd258`<br>
**Scope:** benchmark execution and evidence publication. The public website remains a separate repository.<br>
**Related decision:** [`TECH_STACK_DECISION.md`](TECH_STACK_DECISION.md)

## Executive summary

PrivacyTests.org uses GitHub Actions as a **control plane for an already-running measurement laboratory**:

- GitHub-hosted macOS runners launch browsers and execute tests.
- A self-hosted mobile pool runs Appium and mobile clients.
- Long-lived test pages, WebSocket orchestration, HTTP/DNS/TLS endpoints, and result collection run outside Actions.
- Each test job writes JSON/HTML artifacts.
- A final job downloads those artifacts and renders aggregate pages.
- The checked-in workflows do **not** publish the separate website automatically.

Our Actions should follow that separation, but improve it in five important ways:

1. Keep persistent canary, account, device, and network-vantage infrastructure outside ephemeral jobs.
2. Represent a subject as a versioned configuration tuple rather than a product name.
3. Keep a product privacy `fail` separate from workflow/infrastructure failure.
4. Treat GitHub re-runs as recovery attempts, not independent measurement repetitions.
5. Publish content-addressed, validated run bundles; do not treat expiring Actions artifacts as the canonical dataset.

GitHub Actions should schedule and record the benchmark. It must not be the only place where the lab or evidence exists.

---

## 1. What PrivacyTests.org actually does

The current repository has six checked-in workflow files. GitHub also reports generated Dependabot and Pages workflows through its API.

### 1.1 Desktop benchmark

Source: [`.github/workflows/desktop-tests.yml`](https://github.com/privacytests/privacytests/blob/master/.github/workflows/desktop-tests.yml)

**Triggers**

- Manual `workflow_dispatch`
- Daily at `00:00 UTC`

**Flow**

1. `preflight`
   - Calls the reusable [`preflight.yml`](https://github.com/privacytests/privacytests/blob/master/.github/workflows/preflight.yml).
   - Runs on `macos-latest`.
   - Installs a Homebrew `curl` with HTTP/3 support.
   - Verifies three HTTP/3 canary endpoints.
2. `desktop-tests`
   - Runs a large matrix on GitHub-hosted `macos-latest`.
   - Uses `npm ci` with the npm cache.
   - Installs `mkcert` and the selected browser build.
   - Starts a privileged local DNS monitor backed by `tcpdump`.
   - Runs `node scripts/test.js`.
   - Always attempts to upload JSON, HTML, and a failure screenshot.
3. `render-results`
   - Waits for the matrix.
   - Downloads all `*-results` artifacts.
   - Aggregates them into index/private/nightly pages.
   - Uploads rendered pages as another artifact.

The matrix expands to **200 test jobs**:

- 20 browser/build variants
- 5 repetitions
- normal and private modes
- Tor exclusions
- 10 explicitly included Brave Tor repetitions

With preflight and rendering, the workflow has **202 jobs**. A completed desktop run inspected on 24 September 2026 had 202 successful jobs and took about 9 hours 8 minutes from first job start to final completion.

### 1.2 Mobile benchmark

Source: [`.github/workflows/mobile-tests.yml`](https://github.com/privacytests/privacytests/blob/master/.github/workflows/mobile-tests.yml)

**Triggers**

- Manual
- Daily at `00:00 UTC`

**Flow**

1. A reusable preflight runs on the custom `mobile` runner label.
2. An Android preflight job:
   - Ensures Appium is listening.
   - Opens the Play Store.
   - Updates installed applications and waits for completion.
3. The mobile test matrix has:
   - 11 Android browser configurations
   - 8 iOS browser configurations
   - 5 repetitions
   - **95 test jobs**
4. `fail-fast` is disabled, but `max-parallel: 1` serializes the entire mobile matrix on the shared `mobile` execution pool.
5. Each job reuses or starts Appium, runs the client, and uploads an artifact.
6. An Ubuntu renderer aggregates the Android and iOS results.

The September 24 mobile run produced 95 result artifacts plus one rendered-pages artifact. Because the pool is serialized, its wall-clock duration was roughly 8 hours 45 minutes.

### 1.3 Operational workflows

- [`retry-failed-tests.yml`](https://github.com/privacytests/privacytests/blob/master/.github/workflows/retry-failed-tests.yml) listens for failed desktop/mobile workflows and calls `gh run rerun --failed`, up to run attempt 3.
- [`single-browser-test.yml`](https://github.com/privacytests/privacytests/blob/master/.github/workflows/single-browser-test.yml) provides a protected manual debugging path for one desktop/Android/iOS configuration.
- [`lint.yml`](https://github.com/privacytests/privacytests/blob/master/.github/workflows/lint.yml) runs Semistandard on push and pull request. It does not run the full harness test suite or validate result contracts.
- The mobile workflow uses a static concurrency group with `cancel-in-progress: false`, protecting the shared device pool from overlapping runs.

### 1.4 Infrastructure outside Actions

The runner is only one component. [`scripts/test.js`](https://github.com/privacytests/privacytests/blob/master/scripts/test.js):

- Opens a WebSocket to `wss://results.privacytests.org/ws`.
- Receives a session identifier.
- Navigates browser clients through pages on several `privacytests*.org` domains.
- Receives browser-side observations over the WebSocket.
- Uses a local MITM proxy for cookie-sharing tests.
- Uses a local DNS monitor for DNS-leak tests.
- Writes a result JSON containing the Git commit, product/build information, timestamps, and test output.

The live results service stores short-lived in-memory sessions, coordinates page navigation, and forwards results. This service and the canary domains must remain online independently of any one GitHub Actions run.

### 1.5 Publication behavior

The current Actions workflows **do not deploy the website**.

They stop after uploading rendered artifacts. The repository README and `scripts/README.md` describe a manual workflow that copies results into the sibling `privacytests-website` repository, commits, and pushes them.

That separation is sensible, but the manual handoff should become a validated, append-only data-publication step in our project.

---

## 2. What to learn from PrivacyTests.org

### Keep these patterns

- A cheap shared preflight before an expensive matrix.
- `fail-fast: false` so one subject does not cancel unrelated subjects.
- Artifact upload with `if: always()` for diagnostics.
- A dedicated, serialized lane for scarce physical devices.
- A manual single-subject workflow for diagnosis.
- Capture product versions and runner environment in result provenance.
- Keep the measurement service independent from the job runner.
- Aggregate raw subject outputs in a separate deterministic job.

### Do not copy directly

- A Cartesian matrix with every repetition displayed as a separate Actions job.
- Daily full runs at exactly `00:00 UTC`; GitHub schedules can be delayed under load.
- Automatic generic retries that could blur infrastructure recovery with scientific repetition.
- Workflow failure as the representation of a product privacy failure.
- Artifact-only publication with no durable public archive.
- Mutable third-party Action major tags without a deliberate pinning policy.
- Running arbitrary code from pull requests on self-hosted lab machines.
- Broad workflow permissions or account secrets passed to every matrix job.
- Permanent app/device state without a documented reset and state manifest.
- Treating uploaded artifacts as durable long-term evidence.

---

## 3. Core rule: GitHub concepts are not benchmark concepts

GitHub is useful execution metadata, but it must not define the benchmark data model.

| GitHub concept | Benchmark meaning |
|---|---|
| Workflow run | One orchestration envelope for one benchmark run plan |
| `run_attempt` | Recovery attempt for that orchestration, not a new sample |
| Matrix job | One subject execution, or a scheduling unit only |
| Step | An implementation action, not automatically a privacy result |
| Artifact | A transport bundle, not the canonical database |
| Workflow conclusion | Execution health, not product privacy |

Every local run must be representable without GitHub. The schemas should contain optional CI provenance such as repository, workflow, run ID, run attempt, job, and commit, but the core `test`, `subject`, `run`, `result`, and `evidence` objects must not require GitHub.

### Mandatory GitHub Actions execution invariant

**Every canonical privacy check must be selected, started, finalized, recorded, and published through GitHub Actions.**

This does not require one workflow file per check. It requires every registered check to execute inside a GitHub Actions job and to produce its canonical result from that job.

1. Every check has a stable `check_id` in the versioned check registry.
2. Every active check belongs to at least one versioned suite.
3. A GitHub Actions workflow expands the selected suite into subject executions.
4. The subject job invokes the check through its versioned adapter/CLI.
5. The job always finalizes a schema-valid result, including `error` and `not_tested` outcomes.
6. Only an execution whose manifest records `execution.mode = github_actions` may enter the canonical public dataset.
7. Local execution remains useful for development and debugging, but it is marked `execution.mode = local` and cannot be published as a canonical result.
8. A missing runner, permission, account, device, or canary dependency blocks the check in GitHub Actions; it does not move the canonical check to an untracked manual system.

The external canary, database, account broker, and device lab are dependencies of Actions jobs. They may passively receive and retain observations, but they do not independently schedule benchmark checks, decide benchmark outcomes, or publish canonical results.

CI must include a `check-registry-coverage` job that fails when an active check is missing from a suite, has no runnable adapter, has no declared runner class, or lacks a schema/result contract.

| Check class | GitHub Actions execution |
|---|---|
| Static/source/documentation check | Hosted Ubuntu job that retrieves the versioned source or document and writes evidence |
| Email runtime check | Appropriate hosted or self-hosted subject job coordinated with the persistent EPT-compatible canary |
| Webmail check | Automated or manually authenticated persistent-profile self-hosted browser job |
| Native/mobile chat check | Protected self-hosted physical-device job using the official client |
| Multi-window background check | GitHub Actions `prepare` and `collect` phases, with the external service storing observations between them |
| Human-reviewed evidence | Protected `workflow_dispatch` or review workflow that records reviewer, source, decision, and evidence provenance |

A GitHub Actions step may execute several related checks for one subject when they share setup and device state. The subject job must still emit one independently identified result per check. Splitting every check into a separate Actions job is optional and should be based on isolation, runner, security, and sequencing needs rather than a one-check-per-job rule.

---

## 4. Proposed Actions topology

Checked in today:

```text
.github/workflows/
├── ci.yml                       # PR and push code validation
├── adapter-smoke.yml            # fake/local canary, no real accounts
├── email-benchmark.yml          # protected manual + scheduled entry point
├── chat-benchmark.yml           # protected manual + scheduled entry point
├── _publish-benchmark.yml       # reusable aggregation and publication workflow
├── publish-site.yml             # renders a bundle as the GitHub Page
├── release.yml                  # tagged package release, SBOM, attestation
├── codeql.yml                   # security scanning
└── workflow-security.yml        # actionlint + zizmor over the workflows themselves
```

Specified below but **not implemented**. They are design targets for a later phase, not
descriptions of the current tree:

```text
├── full-benchmark.yml           # optional orchestration for a complete weekly run
└── maintain-subjects.yml        # controlled app/version maintenance
```

The leading underscore is a naming convention, not a GitHub feature. It marks reusable implementation workflows. Entry-point workflows remain visible in the Actions tab.

### 4.1 `ci.yml`: code correctness

**Triggers**

- Pull request
- Push to the default branch

**No real product accounts or external canary traffic.**

Recommended jobs:

1. `schemas`
   - Parse all JSON Schemas.
   - Validate examples and bundled fixtures.
   - Check backward compatibility for supported schema versions.
2. `check-registry-coverage`
   - Require every active `check_id` to belong to a suite.
   - Require a versioned runner class, adapter, result contract, and evidence policy.
   - Reject checks that have no GitHub Actions execution path.
3. `python`
   - `uv sync --locked`
   - Ruff formatting and linting
   - ty
   - pytest unit/property tests
   - Wheel and source-distribution installation checks
4. `integration`
   - Exercise the CLI, fake canary, and upstream adapter contracts with fixtures
   - Add PostgreSQL 18/Alembic/FastAPI tests only after the optional canary service exists
5. `automation`
   - Playwright Python subprocess tests
   - Appium Python client contract tests
   - Native macOS/Android adapter tests against fakes or local targets
6. `security`
   - Dependency and license scanning
   - Secret scanning
   - CodeQL where applicable
   - `actionlint` and a workflow security analyzer such as `zizmor`
7. `images`
   - Build persistent canary or upstream-service images where applicable
   - Generate an SBOM
   - Scan images

Use a PR concurrency group with cancellation enabled. Old CI runs add no scientific value.

### 4.2 `adapter-smoke.yml`: orchestration smoke test

This proves that a subject adapter, canary, evidence collector, and result finalizer work together without real accounts.

It should run:

- After changes to `harness`, adapters, or evidence schemas
- On demand
- Optionally after merge to the default branch

It uses a fake client and local canary fixture. It verifies that:

- A run can be planned and leased.
- A unique probe token is issued.
- Timing windows are recorded.
- `error` results are finalized even when an adapter throws.
- Evidence is redacted, hashed, and schema-valid.
- The aggregate job can represent missing subjects correctly.

### 4.3 `email-benchmark.yml`: email measurement lane

**Triggers**

- Manual dispatch with a checked-in suite/subject selection
- Weekly schedule at an off-hour UTC minute
- Called by `full-benchmark.yml` (not implemented; the workflow already accepts
  `workflow_call` so a future orchestrator needs no change here)

**Suggested initial schedule:** weekly rather than daily. Increase frequency only after we understand account lock rates, provider throttling, and meaningful temporal variance.

**Jobs**

1. `plan`
   - Validate the suite definition.
   - Resolve exact subject snapshots.
   - Validate runner requirements and account slots.
   - Create a run identifier and expected-subject manifest.
2. `preflight`
   - Validate the pinned EPT endpoint, DNS, TLS, HTTP, and SMTP/IMAP prerequisites.
   - Check database health only if the optional unified canary service has been introduced.
   - Check the required network vantage from the actual measurement runner where possible.
3. `subject`
   - One job per subject/account slot, with a bounded number of controlled repetitions.
   - Use a versioned adapter command, not workflow-defined test logic.
4. `aggregate`
   - Run with `if: always()`.
   - Download all available bundles.
   - Validate every document against the schemas.
   - Verify SHA-256 hashes and uniqueness.
   - Turn missing expected subjects into `error` or `not_tested`; never product `fail`.
5. `publish`
   - Publish only validated, sanitized bundles.
   - Record benchmark and application commit provenance.
   - Trigger the separate website repository.
6. `final-health-check`
   - Fail the workflow if the benchmark is incomplete or internally invalid.

### 4.4 `chat-benchmark.yml`: physical-device measurement lane

The DAG is the same, but the runner and secret boundaries are stricter.

**Jobs**

1. `plan`
2. `device-preflight`
   - Verify device model, OS build, app package/version/hash, clock health, network, storage, battery, and Appium/Playwright readiness.
3. `subject`
   - Runs on a protected, dedicated self-hosted lane.
   - Uses official clients and pre-provisioned synthetic accounts.
   - Never creates accounts from workflow input.
4. `aggregate`
5. `publish`
6. `final-health-check`

Long observation windows may need a phased workflow:

```text
prepare -> close job -> observation window outside Actions -> collect -> aggregate
```

A GitHub Actions job should not be used as a 12- or 24-hour timer. Persistent orchestration outside Actions should schedule and trigger `collect`, or a dedicated collector service can finalize the run directly.

### 4.5 `maintain-subjects.yml` (specified, not implemented)

For communication apps, blindly updating every application immediately before a test can create uncontrolled state changes.

The maintenance workflow should instead:

1. Discover available versions.
2. Stage a controlled update.
3. Verify package/bundle version and cryptographic identity.
4. Reset the controlled profile/account state.
5. Run a health check.
6. Record the new subject revision.

Actual installed version and hash are always captured at measurement time, whether or not an update occurred.

---

## 5. Runner lanes

### GitHub-hosted runners

Use for:

- Schema and Python CI
- Local integration tests
- Harness self-tests
- Non-account canary service tests
- Container builds and SBOM generation

Public repositories receive free, unlimited use of standard hosted runners, subject to GitHub's normal limits and fair-use policies. Pin an Ubuntu image rather than relying on `latest` for reproducible CI where practical.

### Self-hosted runners

Required for:

- Real Apple Mail and other desktop mail clients
- Persistent webmail profiles
- Physical Android devices
- Physical iOS devices and Xcode/WebDriverAgent
- Real mobile networks, SIMs, push services, and regional vantages

Recommended labels should describe capability, not secrets:

```text
self-hosted, lab-macos, os-15, arm64
self-hosted, lab-android, physical-device
self-hosted, lab-ios, physical-device
self-hosted, vantage-de
```

A subject's account ID and authentication material must never appear in labels.

GitHub warns that persistent self-hosted runners can be compromised by untrusted code and recommends considering ephemeral runners. Our lab runners must therefore:

- Never execute fork pull-request code.
- Be restricted by runner group to approved benchmark workflows.
- Execute only trusted default-branch or manually approved workflow revisions.
- Run in dedicated accounts/VMs with no personal data.
- Use ephemeral runner workspaces and, where possible, ephemeral runner registrations.
- Have automatic cleanup and health checks.
- Use separate machines/devices for provider administration and measurement.

---

## 6. Concurrency and retry policy

### Concurrency

Use two levels:

1. **Workflow/lane concurrency**
   - For example, `benchmark-email` or `chat-android-01`.
   - `cancel-in-progress: false` for real measurements.
2. **Subject/device concurrency**
   - For example, `subject-apple-mail-gmail-slot-1`.
   - Prevent two jobs from using the same account, profile, device, or canary identity.

A product measurement should never be cancelled halfway merely because a newer workflow started.

A cancelled or timed-out run is an infrastructure event, not a privacy result.

### Repetition versus retry

These must be different concepts:

- **Measurement repetition:** a new, valid execution after controlled state reset, with a new run/probe identity.
- **Actions retry:** another `run_attempt` recovering an infrastructure or adapter error.

A GitHub retry must record `retry_of_execution_id` or equivalent. It must not silently replace the original result or count as another sample.

Do not automatically retry a product `fail`. During the MVP, prefer explicit setup retries inside the adapter and a manual infrastructure-retry workflow. Add generic `workflow_run` retries only after the result/error taxonomy is mature enough to target infrastructure failures safely.

---

## 7. Product result versus workflow health

A product privacy failure is a successful measurement.

| Condition | Benchmark result | Workflow/job outcome |
|---|---|---|
| Expected privacy behavior observed | `pass` | success |
| Expected privacy violation observed | `fail` | success |
| Some evidence available but criterion not fully met | `partial` | success if bundle is valid |
| Evidence cannot decide the criterion | `inconclusive` | success |
| Criterion does not apply | `not_applicable` | success |
| Client/platform lacks capability | `unsupported` | success |
| Harness, account, device, service, or collection failed | `error` | failure after finalizing an error bundle |
| Planned subject was not executed | `not_tested` in aggregate | benchmark run incomplete |

The harness must convert exceptions into a valid `error` result during `finally`/cleanup. `if: always()` only uploads files that were produced; it does not guarantee that a result exists.

This separation prevents privacy regressions from appearing to be flaky CI failures and prevents infrastructure failures from being published as product failures.

---

## 8. Result bundle and provenance

Each subject job should create a directory such as:

```text
out/<execution-id>/
├── manifest.json
├── results/
│   ├── <test-id>/<test-version>.json
│   └── ...
├── evidence/
│   ├── <evidence-id>.json
│   └── ...
└── checksums.sha256
```

The execution manifest should include at least:

- Core schema version
- Benchmark run ID and execution ID
- Execution mode (`github_actions` or non-canonical `local`)
- GitHub repository, workflow, run ID, run attempt, job, and commit when applicable
- Test ID/version/spec digest
- Subject ID/version and complete subject snapshot
- Adapter ID/version/commit
- Threat-model/test configuration
- Network vantage and observed public network attributes
- Device/emulator model, OS version/build, and hardware
- App/client name, version, build, package/bundle identifier, and cryptographic hash when available
- Account type and pseudonymous account-slot ID, never account credentials
- Runner image/device-agent identity
- Start/end timestamps and clock uncertainty
- Probe IDs and observation windows
- Result/evidence references and SHA-256 hashes
- Error and retry metadata

GitHub fields are provenance, not domain fields required by every local run.

### Evidence handling

Evidence can include:

- Canary HTTP/DNS/TLS/TCP events
- Filtered packet traces
- Screenshots and UI hierarchy dumps
- App/service logs
- Static-analysis reports
- Policy/audit snapshots
- Human-review records

Before upload or publication:

1. Remove credentials, registration identifiers, phone numbers, email addresses, message content, and unrelated traffic.
2. Prefer one-time synthetic probe IDs.
3. Restrict raw traces to the declared destination, interface, and time window.
4. Record redaction policy and capture provenance.
5. Hash the published artifact.
6. Separate measured, static, documented/audit, and human-review evidence types.

A GitHub artifact should have an explicit short retention period. The sanitized canonical bundle needs a durable public archive.

---

## 9. Canonical publication and the separate website

Recommended MVP:

1. Aggregate and validate all sanitized subject bundles.
2. Produce a content-addressed run bundle and top-level manifest.
3. Fail if a checksum or schema is invalid.
4. Attach the bundle to a dated or weekly GitHub Release using an isolated publisher identity.
5. Generate a GitHub artifact attestation for the bundle.
6. Send the website repository a `repository_dispatch` containing only the release URL, manifest digest, run IDs, and schema version.
7. Let the website repository validate the public bundle and deploy independently.

The benchmark repository should not check out or directly push the website repository. The website should never be able to alter a measurement run.

For higher volume, mirror the same append-only bundles and checksums to a public versioned object store. Keep GitHub Releases or the benchmark repository as the human-visible index.

Artifacts, issue summaries, and website pages are views of the canonical run bundle, not the source of truth.

---

## 10. Email Privacy Tester integration

Email Privacy Tester's current repository metadata declares GPL-3.0. It remains an upstream component with its own notices and source obligations. Confirm relicensing and attribution terms before adapting its corpus. The benchmark code is AGPL-3.0-only.

Recommended boundary:

- Run the complete pinned EPT application and watchers privately; do not port or reimplement EPT.
- Pin the EPT commit and container image by immutable digest.
- Put a thin authenticated gateway in front of undocumented internal routes when necessary.
- Use a Python HTTP adapter and correlate EPT's opaque test code with our run/probe ID.
- Never access EPT's database directly, scrape its UI, or use its public SaaS for canonical runs.
- Do not track a floating `latest` image in a measurement run.
- Preserve license notices and generate dependency/license manifests.
- Do not assume process isolation automatically resolves network-copyleft obligations; obtain legal review before distributing a modified service.

EPT currently requires persistent SMTP, DNS, HTTP/TLS, and callback infrastructure. GitHub Actions should request a test, interact with the selected mail client, correlate the unique EPT test code with our run/probe ID, poll or receive results, and export normalized evidence. Actions should not be the only place where those watchers run.

Not every real mail subject is suitable for a fresh GitHub-hosted runner:

- Apple Mail requires macOS and a controlled native profile.
- Webmail often needs a persistent authenticated profile and may trigger anti-bot controls.
- OAuth and CAPTCHA flows can invalidate unattended runs.
- Fresh GitHub-hosted network egress is not a stable subject attribute.

Therefore, GitHub-hosted CI can validate the EPT adapter, but canonical native/web client measurements should use controlled lab runners.

---

## 11. Controlled chat pilot

### First-wave recommendation

1. Prove the harness with one controlled Android Signal subject.
2. Add WhatsApp and Telegram sequentially on dedicated Android account/device slots.
3. Add iOS only after Android cleanup, account health, and attribution are reliable.

For each subject, begin with defensible black-box tests:

- Synthetic identifiers in contacts and account/profile flows
- Honey message content inspection
- Honey link fetch and link-preview IP exposure
- Notification/preview behavior
- Background/idle connection behavior where feasible
- Visible third-party endpoints and attribution
- App permissions and local-storage findings as static evidence
- E2EE claims only as protocol/audit/documentation evidence, never inferred from packet capture alone

Rules:

- Official clients only.
- Appium bound to loopback or a protected lab network, with `appium driver doctor` in preflight.
- Dedicated synthetic accounts and contacts.
- Manual registration and recovery.
- No mass contact enumeration.
- No unauthorized pinning bypass or penetration testing.
- Low message and probe rates.
- Explicit provider terms review before automation.
- No real-user communications or real contact lists.

One physical device/account slot must be serialized. Parallelism is allowed only across independent devices, accounts, probe namespaces, and network vantages.

---

## 12. Representative workflow shape

This is a structural example, not the final implementation:

```yaml
name: Email benchmark

on:
  workflow_dispatch:
    inputs:
      suite:
        type: choice
        options: [smoke, weekly-full]
        default: smoke
  schedule:
    - cron: '17 3 * * 1'

permissions:
  contents: read

concurrency:
  group: benchmark-email
  cancel-in-progress: false

jobs:
  plan:
    runs-on: ubuntu-24.04
    outputs:
      subjects: ${{ steps.plan.outputs.subjects }}
    steps:
      - uses: actions/checkout@<full-commit-sha>
      - uses: astral-sh/setup-uv@<full-commit-sha>
        with:
          version: '<pinned-version>'
      - run: uv sync --locked
      - id: plan
        run: >-
          uv run pt-bench plan
          --suite "${{ inputs.suite || 'weekly-full' }}"
          --output plan.json
          --github-output "$GITHUB_OUTPUT"
      - uses: actions/upload-artifact@<full-commit-sha>
        with:
          name: benchmark-plan
          path: plan.json

  preflight:
    needs: plan
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@<full-commit-sha>
      - uses: astral-sh/setup-uv@<full-commit-sha>
        with:
          version: '<pinned-version>'
      - run: uv sync --locked
      - uses: actions/download-artifact@<full-commit-sha>
        with:
          name: benchmark-plan
      - run: uv run pt-bench preflight --plan plan.json

  subject:
    needs: [plan, preflight]
    strategy:
      fail-fast: false
      matrix:
        subject: ${{ fromJSON(needs.plan.outputs.subjects) }}
    runs-on: ${{ matrix.subject.runner }}
    environment: measurement-email
    concurrency:
      group: measurement-${{ matrix.subject.id }}-${{ matrix.subject.account_slot }}
      cancel-in-progress: false
    steps:
      - uses: actions/checkout@<full-commit-sha>
      - uses: astral-sh/setup-uv@<full-commit-sha>
        with:
          version: '<pinned-version>'
      - run: uv sync --locked
      - uses: actions/download-artifact@<full-commit-sha>
        with:
          name: benchmark-plan
      - run: uv run pt-bench execute --plan plan.json --subject "${{ matrix.subject.id }}"
      - name: Finalize even after adapter failure
        if: always()
        run: uv run pt-bench finalize --plan plan.json --subject "${{ matrix.subject.id }}"
      - uses: actions/upload-artifact@<full-commit-sha>
        if: always()
        with:
          name: result-${{ matrix.subject.id }}-${{ matrix.subject.account_slot }}-${{ github.run_attempt }}
          path: out/
          retention-days: 30

  aggregate:
    if: always()
    needs: [plan, preflight, subject]
    runs-on: ubuntu-24.04
    outputs:
      publishable: ${{ steps.aggregate.outputs.publishable }}
      complete: ${{ steps.aggregate.outputs.complete }}
    steps:
      - uses: actions/checkout@<full-commit-sha>
      - uses: astral-sh/setup-uv@<full-commit-sha>
        with:
          version: '<pinned-version>'
      - run: uv sync --locked
      - uses: actions/download-artifact@<full-commit-sha>
        with:
          name: benchmark-plan
      - uses: actions/download-artifact@<full-commit-sha>
        with:
          pattern: 'result-*'
          path: artifacts
      - id: aggregate
        run: >-
          uv run pt-bench aggregate
          --plan plan.json
          --artifacts artifacts
          --output run-bundle.tar.zst
          --github-output "$GITHUB_OUTPUT"
      - uses: actions/upload-artifact@<full-commit-sha>
        if: steps.aggregate.outputs.publishable == 'true'
        with:
          name: sanitized-run-bundle
          path: run-bundle.tar.zst
          retention-days: 7

  publish:
    needs: aggregate
    if: needs.aggregate.outputs.publishable == 'true'
    runs-on: ubuntu-24.04
    permissions:
      contents: write
      id-token: write
      attestations: write
    steps:
      - uses: actions/checkout@<full-commit-sha>
      - uses: astral-sh/setup-uv@<full-commit-sha>
        with:
          version: '<pinned-version>'
      - run: uv sync --locked
      - uses: actions/download-artifact@<full-commit-sha>
        with:
          name: sanitized-run-bundle
      - uses: actions/attest@<full-commit-sha>
        with:
          subject-path: run-bundle.tar.zst
      - run: uv run pt-bench publish --bundle run-bundle.tar.zst
```

Implementation requirements for the real files:

- Pin every third-party Action to a reviewed full commit SHA.
- Do not use `secrets: inherit` globally.
- Keep the lab environment and publication permissions in separate jobs.
- Ensure `pt-bench finalize` cannot mark an incomplete product observation as a product `fail`.
- Run publication only from sanitized, schema-valid bundles.
- Use a final completeness check to make infrastructure incompleteness visible.

---

## 13. MVP rollout

### Phase 0: repository and contracts

- `AGPL-3.0-only` license and dependency policy
- One Python 3.14 distribution managed by uv
- Versioned schemas for test, subject, run, result, and evidence
- `spec` validation CLI
- `harness` fake adapter and local canary fixture
- PR CI and workflow security linting

### Phase 1: email wedge

- Deploy or reuse the pinned EPT application/watchers behind a private gateway
- Integrate a thin Python EPT adapter; do not port or scrape the EPT UI/database
- Two tightly defined native-client subjects on controlled runners
- Three controlled repetitions per scheduled run
- Short-retention raw artifacts
- Weekly append-only, attested publication
- Separate website ingestion

### Phase 2: controlled chat pilot

- Dedicated Android lab and synthetic accounts
- Introduce a unified FastAPI/PostgreSQL canary only if existing upstream services cannot satisfy the chat correlation contract
- Signal first
- WhatsApp and Telegram after cleanup/account-health validation
- Honey message, honey link, preview IP, notifications, and background behavior
- Versioned public result bundles

### Phase 3: expansion

- iOS lab
- Regional vantages
- More mail clients/providers
- Static and documented evidence pipelines
- Independent replication
- Human remediation/review workflow

---

## 14. Decisions still to make before implementation

1. Which two email subjects form the first canonical pilot?
2. Is the first chat pilot Android-only?
3. Where will persistent canary watchers and account/device management run?
4. Which regional/network vantage is the initial reference location?
5. Should the MVP canonical archive use weekly GitHub Releases, or is a public object store available immediately?
6. What account reset/recovery process has been approved for each provider?
7. Which tests are safe to automate under each provider's current terms?
8. What evidence retention and redaction policy will the project publish?

The architecture should be scaffolded only after these are represented as checked-in configuration and operational documentation, not embedded as logic in workflow YAML.

---

## 15. Primary sources

- [PrivacyTests.org desktop workflow](https://github.com/privacytests/privacytests/blob/master/.github/workflows/desktop-tests.yml)
- [PrivacyTests.org mobile workflow](https://github.com/privacytests/privacytests/blob/master/.github/workflows/mobile-tests.yml)
- [PrivacyTests.org preflight workflow](https://github.com/privacytests/privacytests/blob/master/.github/workflows/preflight.yml)
- [PrivacyTests.org retry workflow](https://github.com/privacytests/privacytests/blob/master/.github/workflows/retry-failed-tests.yml)
- [PrivacyTests.org single-subject workflow](https://github.com/privacytests/privacytests/blob/master/.github/workflows/single-browser-test.yml)
- [Inspected desktop run, 24 September 2026](https://github.com/privacytests/privacytests/actions/runs/35944460164)
- [Inspected mobile run, 24 September 2026](https://github.com/privacytests/privacytests/actions/runs/35945562739)
- [GitHub-hosted runner specifications and public-repository usage](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
- [GitHub self-hosted runner reference](https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners)
- [GitHub secure-use reference for self-hosted runners](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations)
- [GitHub guidance on delayed scheduled workflows](https://docs.github.com/en/actions/how-tos/troubleshoot-workflows#scheduled-events-can-be-delayed-during-periods-of-high-loads-of-github-actions-workflow-runs)
- [Email Privacy Tester v3 source](https://gitlab.com/grepular/ept3)
