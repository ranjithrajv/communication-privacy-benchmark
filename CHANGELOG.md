# Changelog

All notable changes to this project are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) with `0.x` alpha releases.

## [Unreleased]

### Changed

- The gateway contract no longer claims an observation channel or signal that upstream
  cannot produce. There is no TCP channel (preconnect arrives via SNI) and no MIME
  channel, and the open assertion moved from the gateway to the harness, because EPT has
  no open signal. An adapter constructed without an `open_observer` always reports
  `inconclusive`.
- Replaced the separate `pip-audit` development dependency with uv's built-in
  `uv audit --locked --preview-features audit-command` workflow.
- Pinned the uv CLI to 0.12.18 in every workflow.

### Added

- EPT gateway adapter behind `pt-bench execute --adapter ept`, implementing
  `email.remote-content` against a versioned private-gateway contract. Gateway
  configuration and the slot-to-mailbox mapping are read from the environment, never
  from a checked-in definition, and the adapter is only registered when a gateway is
  configured.
- A typed gateway observation contract over the three channels upstream can actually
  produce, with probe correlation: observations carrying a foreign `probe_id` are
  rejected rather than adjudicated.
- An adjudication guard against false passes. Delivery, an asserted open, and watcher
  health must all be confirmed before an empty observation set may be reported as
  `pass`; anything short of that is `inconclusive`.
- `harness/canary.py`: a real self-hosted canary used to validate the email lane
  without a third-party account. A real HTTP canary serving an actual GIF, a real
  authoritative DNS server answering over UDP and logging in BIND's query format, and
  real MIME messages carrying real canary URLs. `tests/integration/test_live_canary.py`
  drives it over real sockets.
- `infra/ept/UPSTREAM_FINDINGS.md`: the upstream source facts the gateway contract is
  derived from, verified against the pinned repository.
- Observation origin attribution. EPT records a provider spam filter prefetching the
  canary identically to a client rendering the message, and its own documentation warns
  about it. Observations now carry an origin, and only a `client` origin is scored; a
  provider-only or unattributed contact is `inconclusive` rather than a false `fail`
  about a provider.
- Draft email lane declarations for Apple Mail and Thunderbird reading the same
  synthetic Gmail account from the same vantage, differing only in the setting the
  check measures, plus a draft `email` suite repeating three times to expose flaky
  behaviour. Pending provider-terms reviews for both subjects keep the lane blocked.
- Repetition roll-up: `pt-bench rollup` reduces a run bundle to a per-check stability
  verdict (`pass`, `fail`, `flaky`, `inconclusive`, `not_applicable`, `unsupported`,
  `incomplete`) with a Wilson 95% pass-rate interval. An under-sampled run is reported
  as `incomplete` rather than as a pass, and a missing subject still appears in the
  rollup.
- Longitudinal comparison: `pt-bench compare` reports per-check `improved`,
  `regressed`, `unchanged`, `unorderable`, `new`, and `removed` verdicts between two
  bundles. Only an established pass or fail is ordered; flaky, inconclusive,
  unsupported, and under-sampled outcomes are reported as `unorderable` and never
  scored. Client and check version bumps are compared rather than split into new rows.
- `run-rollup` and `run-comparison` JSON Schema contracts, validated in CI against the
  Pydantic models. Roll-ups and comparisons are refused inside a checksummed bundle so
  the evidence record stays append-only.
- `operations/1.0.0/operations.toml`: a versioned operational policy recording the
  reference network vantage, runner lanes, synthetic account recovery procedures,
  canary services, evidence retention and redaction rules, the publication target, and
  one provider-terms review per subject.
- A canonical-approval gate: `pt-bench plan` refuses a GitHub Actions run for any
  subject whose provider-terms review is not `approved`, and fails closed when the
  policy is absent. `--allow-unapproved-subjects` bypasses it for a dry run only.
- `pt-bench operations validate`, which reports per-subject readiness and exits `2`
  while canonical measurement is blocked, `1` only on an invalid policy. Wired into
  CI so a broken policy fails while a legitimately blocked one does not.
- Draft Android chat lane declarations for Signal (`org.thoughtcrime.securesms`),
  WhatsApp (`com.whatsapp`), and Telegram (`org.telegram.messenger`), each with a
  dedicated synthetic account slot and an explicit settings profile.
- Draft `chat.link-preview-fetch` check and draft `chat` suite covering the three
  chat subjects. Both stay non-active until a physical Android device per slot,
  synthetic phone numbers, and provider-terms review are in place.
- Appium chat adapter driving a private canary gateway, plus the gateway contract in
  `infra/chat/README.md`. Adjudication distinguishes delivered from displayed, reports a
  resolved-but-unfetched canary name as `partial` rather than a clean client, and does
  not score a contact that predates delivery against the reader. Per-app selectors ship
  unverified, so the adapter reports `inconclusive` rather than a fabricated pass.
- Chat subjects now measure from the reference network vantage instead of the unassigned
  `ZZ` placeholder, so a chat row and an email row are comparable.
- First real email, webmail, or messaging subject adapter.
- Pinned Email Privacy Tester gateway and lab deployment.
- Protected physical-device or regional measurement infrastructure.

## [0.1.0] - 2026-09-25

### Added

- Python 3.14 package and `pt-bench` command-line interface.
- Versioned Pydantic models and committed JSON Schema Draft 2020-12 contracts for
  checks, subjects, run plans, results, evidence, execution manifests, and run bundles.
- Check, subject, and suite registry with cross-file coverage validation.
- Account-free fake adapter for GitHub Actions execution smoke tests.
- Deterministic execution finalization, evidence hashing, checksum verification, and
  run-bundle aggregation.
- GitHub Actions workflows for CI, account-free adapter smoke tests, CodeQL, workflow
  security, Dependabot, and attested releases.
- AGPL-3.0-only licensing, contribution guidance, security policy, and research and
  architecture decision records.

[Unreleased]: https://github.com/ranjithrajv/communication-privacy-benchmark/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ranjithrajv/communication-privacy-benchmark/releases/tag/v0.1.0
