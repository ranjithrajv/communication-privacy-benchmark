# Communication Privacy Benchmark Tech Stack Decision

**Decision date:** 25 September 2026<br>
**Status:** Recommended baseline for implementation<br>
**Constraint:** Every canonical privacy check is selected, executed, finalized, and published through GitHub Actions.<br>
**License:** All first-party code and workflows are `AGPL-3.0-only`; the public website is a separate project.<br>
**Related decision:** [`GITHUB_ACTIONS_ARCHITECTURE.md`](GITHUB_ACTIONS_ARCHITECTURE.md)

## Decision summary

The re-evaluation keeps a Python-first platform but changes the earlier baseline in four important ways:

1. Move from Python 3.12 to **Python 3.14**.
2. Remove the requirement for first-party Node.js/TypeScript sidecars. Use the official **Python clients** for Playwright and Appium. Node.js 24 LTS remains an external runtime for Appium 3; Playwright Python ships and versions its own driver runtime.
3. Make the MVP core one small, deterministic CLI distribution. Do not start with FastAPI, SQLAlchemy, PostgreSQL, or a worker inside the benchmark core.
4. Treat a unified FastAPI/PostgreSQL canary service as separate lab infrastructure to introduce only when the email/chat contracts prove it is needed.

The recommended first-party implementation language is Python. The MVP should not introduce Go, Rust, Celery, Redis, Kafka, Kubernetes, or a general-purpose workflow engine.

## Why the stack changed

GitHub Actions changes the optimization function:

- Canonical execution jobs are short-lived and disposable.
- Persistent canary and device infrastructure still exists, but it provides passive capabilities and observations rather than benchmark outcomes.
- The core needs a dependable CLI, schema validation, evidence analysis, and HTTP integration more than it needs a high-throughput application server or database.
- Every dependency added to a self-hosted measurement runner increases operational and supply-chain risk.
- A second first-party language is justified only when an official automation client cannot perform a required operation.

The official Appium Python client is maintained by the Appium organization, supports Appium 3 and Python 3.14, and covers the W3C/Appium operations needed by the initial Android/iOS checks. Playwright also has an official, active Python API. A TypeScript sidecar is therefore not required for the MVP.

## Selected stack

| Layer | Selection | Rationale |
|---|---|---|
| Core language | CPython 3.14.x | Current stable Python line with first-party support from the selected libraries; do not enable free-threaded Python initially |
| Python packaging | One distribution initially, managed by `uv` with `uv.lock` | Keep the MVP small; add a uv workspace only when a genuinely separate service or adapter package exists |
| Dependency audit | `uv audit --locked --preview-features audit-command` | Audits the committed lockfile through uv's built-in vulnerability service without a second Python audit tool |
| Public contracts | JSON Schema Draft 2020-12 generated from Pydantic | One source of truth for language-neutral, versionable GitHub artifact contracts |
| Runtime models | Pydantic v2 | Typed configuration and serialized model boundaries with reviewed schema generation |
| Independent schema tests | `jsonschema` | Validate representative artifacts against committed schemas without making the core depend on itself for validation |
| CLI | Click 8.x | Direct, stable command framework with explicit stdout/stderr and exit-code control |
| HTTP client | HTTPX | Sync/async-capable client for EPT, canary, and publication APIs with first-class Python support |
| Unit/integration tests | pytest | Mature fixture/plugin ecosystem for Python and automation adapters |
| Property-based tests | Hypothesis | Useful for schema round trips, parser edge cases, and idempotency behavior |
| Formatting/linting | Ruff | Fast formatter, import management, and linting |
| Static typing | mypy with Pydantic plugin | Stable typed checks across spec, harness, CLI, and adapters |
| Coverage | coverage.py | Core-package branch coverage reporting in CI |
| Web automation | Playwright for Python | Official Python API, traces/HAR/video/screenshots, persistent profiles, and browser-version provenance |
| Mobile automation | Appium-Python-Client 6.x | Official Appium client; communicates with Appium 3 over W3C WebDriver |
| Appium server | Appium 3.x on external runners | Current Appium generation; installed and version-pinned outside the Python package |
| Email corpus/watchers | Pinned Email Privacy Tester components | Reuse the strongest existing email corpus and watcher behavior without adopting its legacy application stack as our core |
| TLS edge | Caddy 2.x | Small, reproducible HTTPS reverse proxy and certificate management |
| Authoritative DNS | PowerDNS + existing EPT watcher model | Proven query logging and compatibility with the EPT DNS-watcher approach |
| Packet capture | `tcpdump`/`pcapng` | Standard, mature capture format and tooling; avoid a custom raw-socket parser initially |
| Packet inspection | tshark/Wireshark CLI | Mature protocol dissection instead of custom Rust/Go parsers |
| CI/orchestration | GitHub Actions | Mandatory execution and publication control plane |
| Workflow quality | `actionlint` + `zizmor` | Workflow syntax and GitHub Actions security checks |
| Artifact provenance | GitHub artifact attestations + SBOM | Links public result bundles to the workflow and source revision |
| Public archive | GitHub Releases initially | Public append-only/versioned bundles with checksums and attestations, without making expiring Actions artifacts canonical |
| Machine authentication | GitHub OIDC plus short-lived execution tokens | Avoid long-lived cloud credentials in benchmark jobs |
| Conditional canary API | FastAPI + Uvicorn, deployed separately | Add only if EPT/Honeymessages/upstream collectors cannot provide the unified correlation API the chat checks require |
| Conditional canary store | PostgreSQL 18.x, SQLAlchemy 2.0 Core, Psycopg 3, Alembic | Add only with the separate canary service; use Core first and avoid an ORM/worker unless real mapping or backlog complexity appears |
| Privileged infrastructure containers | Docker Compose v2 or equivalent host services | Use for persistent canary/watchers and upstream services, not for running the benchmark CLI in every Actions job |

## Current evaluated versions

These are version families observed on 25 September 2026, not floating dependencies. Exact versions and image digests must be committed to lockfiles or deployment configuration.

- CPython 3.14.7
- uv 0.12.18
- Pydantic 2.13.x
- Click 8.5.x
- HTTPX 0.28.x
- pytest 9.x and pytest-cov 7.x
- Ruff 0.16.x
- mypy 2.3.x
- Node.js 24.21 LTS for the external Appium 3 server; Playwright's Python package versions its bundled driver separately
- Appium server 3.7.x
- Appium-Python-Client 6.0.7
- Appium UiAutomator2 driver 8.7.x and XCUITest driver 12.13.x at the evaluated baseline
- Playwright Python 1.63.x
- Caddy 2.x
- Conditional service baseline: PostgreSQL 18.6, FastAPI 0.141.x, SQLAlchemy 2.0.x rather than the 2.1 release candidate, Psycopg 3.3.x, and Alembic 1.20.x

The project should upgrade through pull requests and dependency review, not automatically at the start of a measurement run.

## Architecture

```text
MVP execution plane
  GitHub Actions job
    ├── pt-bench plan/preflight
    ├── one Python distribution
    │     ├── spec + Pydantic models
    │     ├── harness/check protocol
    │     ├── Playwright Python adapter
    │     ├── Appium Python adapter
    │     ├── native OS adapter
    │     └── evidence collector/finalizer
    ├── external tools/dependencies
    │     ├── Appium 3 server
    │     ├── Playwright driver/browser
    │     ├── pinned EPT or Honeymessages service
    │     ├── tcpdump
    │     └── tshark
    └── validated result bundle
          ├── short-retention GitHub artifact
          └── append-only GitHub Release/object-store copy

Optional later canary plane, only if existing upstreams cannot provide unified correlation
  ├── Caddy HTTPS edge
  ├── FastAPI canary/control API
  ├── PostgreSQL
  ├── PowerDNS/query logs
  └── EPT-compatible SNI/DNS collectors
```

The Actions job owns check logic and result finalization. External services provide observations, browser/device automation, and transport; they do not independently decide benchmark outcomes. The optional canary plane is a separate deployment, not a dependency of the core package.

## Repository shape

```text
privacy-benchmark/
├── pyproject.toml
├── uv.lock
├── src/privacy_benchmark/
│   ├── spec/                    # Pydantic models + schema generation
│   ├── harness/                 # check protocol, execution, evidence, finalizer
│   ├── adapters/                # EPT, Playwright, Appium, and native adapters
│   └── cli/                     # Click commands
├── checks/                      # versioned check definitions and suites
├── schemas/                     # generated and reviewed public JSON Schemas
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── contract/
│   └── fixtures/
├── infra/
│   ├── compose/                 # only when persistent services are introduced
│   ├── ept/
│   ├── appium/                  # exact external server/driver lock only
│   └── device-runners/
├── tools/                       # release, schema export, and validation commands
└── .github/workflows/
```

Start with one distribution and clear internal module boundaries. Do not create a separate package for every check. Split `spec`, `harness`, or adapters into independently distributed packages only when a real consumer or release boundary appears.

## Data and API design

The portable source of truth is the validated result bundle produced by the GitHub Actions job. The core CLI does not need a database.

For the first implementation:

1. `plan` reads checked-in check, subject, suite, and threat-model definitions.
2. An adapter calls a pinned upstream service such as EPT or Honeymessages, or uses a small purpose-built canary endpoint.
3. The adapter retrieves only the observations associated with its unique run/probe identifiers.
4. The harness analyzes those observations and writes schema-valid JSON plus evidence hashes.
5. The aggregate job downloads subject artifacts and emits the append-only public run bundle.

The core should expose a small internal protocol for adapters rather than persistence interfaces:

```python
class CheckAdapter(Protocol):
    async def execute(self, context: ExecutionContext) -> CheckResult: ...
```

Exact signatures should be designed with the first two real checks. Do not build a plugin framework or generic workflow engine before an adapter boundary is stable.

### Conditional unified canary service

If EPT and Honeymessages cannot provide the correlation and lifecycle operations required by the first chat checks, add a separate service. Start with SQLAlchemy Core and a small schema:

- `runs`
- `subject_executions`
- `probe_leases`
- `observations`
- `evidence_objects`
- `result_indexes`

Guidelines for that service:

- Store timestamps as PostgreSQL `timestamptz`.
- Generate UUIDv7 identifiers in Python for portable ordering.
- Use normal columns for queryable metadata and `jsonb` for check-specific payloads.
- Require an idempotency key on every watcher observation.
- Index `(run_id, probe_id, observed_at)` and execution state.
- Scope Actions executions with short-lived opaque tokens after GitHub OIDC authentication.
- Do not expose database credentials to subject jobs.
- Do not put raw evidence bytes in PostgreSQL; store content-addressed files or object references plus hashes.
- Never silently update a stored result. Corrections create a new execution and a supersession relationship.
- Do not add an ORM unless real mapping complexity appears.

Even with the optional service, the MVP does not need a worker or message bus. The Actions job requests observations and the service stores them synchronously. Add asynchronous processing only when measured event volume or multiple independent consumers justify it.

## Check execution model

A check is not a GitHub Actions implementation. It is a versioned definition executed by an adapter inside a GitHub Actions job.

```text
check registry
  └── suite
      └── subject
          └── GitHub Actions job
              ├── preflight
              ├── check A adapter step
              ├── check B adapter step
              ├── check C adapter step
              └── finalizer
```

Each check adapter must:

- Accept a typed execution context.
- Use only synthetic identifiers and canary material.
- Open and close explicit observation windows.
- Return a typed result even after an exception.
- Avoid raising a process failure merely because a product privacy result is `fail`.
- Produce evidence references and hashes.
- Be runnable locally for development, while canonical publication requires `execution.mode = github_actions`.

## Automation decision

### Playwright

Use Playwright Python directly for:

- Gmail web
- Outlook web
- Other browser-based mail clients
- Browser probes and rendering checks

Run browser automation in a short-lived Python subprocess launched by the same GitHub Actions job. The parent `pt-bench` process finalizes an `error` result if the subprocess crashes. Do not use Playwright Test, pytest reports, or a custom sidecar RPC protocol as the canonical result authority; `pt-bench` owns repetitions, retries, status, and publication.

Use a real installed browser channel when the subject is a specific released browser. Record its executable version/hash. Use Playwright's bundled browser only when that browser identity is the intended subject.

Treat `trace.zip`, HAR files, screenshots, video, DOM snapshots, console output, page source, and logs as sensitive raw evidence. Redact before publication or publish only derived evidence plus a hash reference to restricted raw material.

### Appium

Use Appium-Python-Client directly for Signal, WhatsApp, Telegram, and mobile mail clients.

External runner prerequisites:

- Appium server 3.x
- Exact UiAutomator2 or XCUITest driver versions
- Node.js 24 LTS
- Android SDK/ADB or Xcode/WebDriverAgent
- Pinned runner image and device OS build

Keep the Appium server and driver installation in an infrastructure lockfile under `infra/appium/` so npm resolves exact, reviewed versions even though there is no first-party Node application. The Python client is first-party adapter code. The Appium server and drivers remain separately licensed external tools.

Bind Appium to loopback or a protected lab network; never expose it to the internet. Run `appium driver doctor` in device preflight and record one automation-stack manifest containing the Python client, Appium server, driver, WebDriverAgent, Node, JDK, Android SDK, Xcode, macOS, and device OS versions.

Use W3C commands by default. Keep driver-specific `mobile:` or execute-script calls inside narrow adapter helpers. Physical iOS requires a self-hosted macOS runner, pinned Xcode, paired/trusted devices, Developer Mode, UI Automation, and a signed WebDriverAgent app. Simulators are acceptable for smoke tests, not canonical push or notification results.

### Native clients

Use thin Python adapters around stable OS facilities:

- AppleScript or accessibility APIs on macOS
- ADB/device APIs on Android
- Provider/client APIs only where terms and account controls permit

Do not build a native automation framework when an official client or OS API provides the required operation. Direct Swift/XCTest or Kotlin/UI Automator code is an escape hatch only when Appium cannot expose a required OS capability; it must emit the same benchmark contracts rather than becoming a second result model.

## Email Privacy Tester boundary

The EPT repository currently contains a mixture of modern watcher components and a legacy Node/Babel/Express/MongoDB application stack. We should not make the legacy application stack the foundation of the new benchmark.

Preferred integration order:

1. Pin an EPT source commit and built image by digest.
2. Run the complete upstream application and DNS/SNI watchers privately; do not port or reimplement EPT.
3. Put a thin authenticated gateway in front of EPT if its internal routes do not already provide the required API boundary.
4. Use a Python HTTP adapter that allocates a test, correlates its opaque code with our run/probe ID, and exports neutral observations.
5. Let the GitHub Actions harness adjudicate those observations and produce the canonical result.
6. Never access EPT's database directly, scrape its web UI, or use its public SaaS for canonical runs.
7. Propose a supported authenticated/versioned API upstream instead of coupling the benchmark permanently to private routes.
8. Add our own canary API only when a concrete email or chat requirement cannot be met through an upstream service or small gateway.
9. Copy or adapt GPL-covered corpus material only after license review and attribution are agreed.

The checked-in EPT `package.json` declares `GPL-3.0`; do not assume relicensing to `GPL-3.0-or-later` without explicit upstream permission. Process separation does not automatically settle copyleft obligations.

If the complete upstream EPT application is distributed, preserve all GPL notices and corresponding source. If only the corpus is adapted with permission, record the exact upstream revision and license provenance. This is a technical recommendation, not legal advice.

## Capture and evidence

Use existing tools before writing parsers:

- HTTP/HTTPS canary: Caddy plus a pinned upstream service or the optional FastAPI endpoint
- DNS: authoritative query logs + EPT watcher pattern
- TLS SNI/ClientHello: pinned EPT SNI watcher
- Packet evidence: filtered `tcpdump` output in pcapng format
- Protocol details: tshark CLI and generated JSON/PDML/fields
- Browser internals: Playwright trace, HAR, screenshot, and console log
- Mobile internals: Appium screenshots, page source, and device metadata
- Static analysis: MobSF/Exodus as optional isolated tools, not runtime authority

Do not upload unrelated traffic. Capture interfaces, destination filters, and time windows must be recorded in provenance. Treat raw traces, packet captures, page source, logs, screenshots, and video as sensitive; redact before publication or publish derived evidence with a hash reference to restricted raw material.

## Security and secrets

- Run real-account jobs only from protected default-branch/scheduled workflows.
- Never run fork code on self-hosted measurement runners.
- Restrict self-hosted runner groups to approved repository workflows.
- Use GitHub Environments for lab-scoped configuration.
- Prefer GitHub OIDC over long-lived API/cloud keys.
- Keep account credentials out of workflow logs and artifacts.
- Use synthetic accounts, one-time canary identifiers, and pseudonymous account-slot IDs.
- Pin Actions to reviewed full commit SHAs.
- Pin container images by digest.
- Generate SBOMs and license manifests.
- Use a final completeness check separate from product privacy outcomes.

## Explicitly rejected for the MVP

### First-party Node.js/TypeScript

Rejected because official Python clients cover the required browser and mobile operations. Node remains an external Appium server runtime; Playwright Python supplies its own driver.

Revisit only if:

- A required Appium capability is missing from the official Python client.
- The browser team specifically needs Playwright Test UI mode, HTML reports, sharding, or existing TypeScript selector infrastructure.
- We must maintain an EPT browser component that cannot be upstreamed.
- A benchmark adapter needs a mature Node-only instrumentation library.

### Go

Rejected for the core and initial canary path. The workload is I/O-bound orchestration, validation, and artifact processing. Go remains appropriate for a future standalone lab agent only if profiling or operational constraints demonstrate a need.

### Rust

Rejected for packet/TLS parsers. Use EPT watchers, tshark, and existing packet libraries. Add Rust only when a protocol cannot be analyzed with existing tools and profiling shows that implementation language is the limiting factor.

### Celery/Redis/RabbitMQ/Kafka

Rejected. There is no need for a distributed task system when GitHub Actions controls execution and the canary only ingests observations.

### Kubernetes/Airflow/Temporal

Rejected. The MVP can run as a small Docker Compose deployment on a dedicated canary host, with GitHub Actions as the workflow engine.

### MongoDB

Rejected as a new project dependency. A pinned upstream EPT deployment may still contain its legacy MongoDB component, but that does not justify adopting MongoDB in our core or optional canary service.

### TypeScript all-in-one

Rejected. Python provides a better shared core for schemas, evidence analysis, API integration, CLI behavior, and test fixtures.

### Test-runner reports as benchmark results

Rejected. Playwright Test, pytest, WebdriverIO, and Appium process exit codes are useful for testing the harness, but they cannot own privacy-result status, repetitions, evidence provenance, or publication semantics. `pt-bench` remains authoritative.

### WebdriverIO and Selenium Grid

Rejected for the MVP. Appium-Python-Client is Appium-maintained, while the JavaScript client path is not. Selenium Grid does not solve controlled physical-device state, and Selenium adds no browser capability that Playwright does not already provide.

### Custom automation RPC

Rejected by default. Run Playwright and other adapters as subprocesses in the same Actions job. If remote Playwright is unavoidable, use Playwright's documented same-version WebSocket connection rather than inventing a custom sidecar protocol.

## Evolution triggers

Reconsider components only when evidence requires it:

| Trigger | Possible change |
|---|---|
| Sustained canary ingest overwhelms the simple API/database design | Go collector or asynchronous Python workers |
| Existing packet tools cannot decode a required protocol | Rust parser isolated behind the evidence API |
| Official Python automation lacks a required capability | Small Node/TypeScript sidecar |
| Multiple regions/consumers create a real backlog | Durable task queue |
| High availability and horizontal scaling become necessary | Kubernetes or an equivalent orchestrator |
| Evidence volume exceeds practical GitHub Release limits | Public versioned object storage |
| Long-term time-series analysis becomes central | Prometheus/other metrics store, separate from evidence storage |

## CI consequences

`ci.yml` should run on pinned `ubuntu-24.04` and include:

- `uv sync --locked` and `uv run --locked`
- Ruff format check and lint
- mypy
- pytest unit/property tests
- Wheel and source-distribution installation checks
- Fake/local canary and upstream contract fixtures
- PostgreSQL/Alembic integration tests only after the optional canary service is introduced
- JSON Schema generation drift check
- Check-registry coverage check
- Playwright/Appium adapter contract tests against fakes or local services
- actionlint and zizmor
- `uv audit --locked --preview-features audit-command` dependency scanning
- License and image scanning
- SBOM and artifact-attestation verification

The CI jobs test the harness; their test-runner reports are not benchmark outputs. No CI job may use real communication-product accounts.

## Implementation baseline

The first scaffold should use:

```toml
requires-python = ">=3.14,<3.15"
```

with CPython 3.14 in CI and, where needed, canary service images. Do not enable free-threaded Python until every critical dependency is tested and benchmark workloads show a reason.

Run the CLI directly with pinned Python and uv in Actions; do not wrap every job in a container. The exact dependency versions belong in `uv.lock`; workflow files and persistent-service image definitions must never resolve floating versions during a canonical run.

## Primary sources

- [Python release status](https://devguide.python.org/versions/)
- [uv project synchronization](https://docs.astral.sh/uv/concepts/projects/sync/)
- [uv dependency auditing](https://docs.astral.sh/uv/guides/dependency-audit/)
- [uv in GitHub Actions](https://docs.astral.sh/uv/guides/integration/github/)
- [Pydantic JSON Schema](https://docs.pydantic.dev/latest/concepts/json_schema/)
- [Click documentation](https://click.palletsprojects.com/en/stable/)
- [pytest good integration practices](https://docs.pytest.org/en/stable/explanation/goodpractices.html)
- [Playwright supported languages](https://playwright.dev/docs/languages)
- [Playwright Python CI and trace guidance](https://playwright.dev/python/docs/ci-intro)
- [Appium official clients](https://appium.io/docs/en/latest/ecosystem/clients/)
- [Appium client/server architecture](https://appium.io/docs/en/latest/intro/clients/)
- [Appium security guidance](https://appium.io/docs/en/latest/guides/security/)
- [Appium UiAutomator2 driver](https://github.com/appium/appium-uiautomator2-driver)
- [Appium XCUITest system requirements](https://appium.github.io/appium-xcuitest-driver/latest/getting-started/system-requirements/)
- [FastAPI release notes](https://fastapi.tiangolo.com/release-notes/)
- [SQLAlchemy release status](https://www.sqlalchemy.org/download.html)
- [PostgreSQL current release](https://www.postgresql.org/docs/current/release.html)
- [GitHub-hosted runner guidance](https://docs.github.com/en/actions/how-tos/write-workflows/choose-where-workflows-run/choose-the-runner-for-a-job)
- [Email Privacy Tester source](https://gitlab.com/grepular/ept3)
- [EPT package metadata declaring GPL-3.0](https://gitlab.com/grepular/ept3/-/blob/master/package.json)
- [FSF license compatibility](https://www.gnu.org/licenses/license-list.html)
- [AGPLv3 section 13](https://www.gnu.org/licenses/agpl-3.0.html#section13)
