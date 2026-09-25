# Changelog

All notable changes to this project are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) with `0.x` alpha releases.

## [Unreleased]

### Changed

- Replaced the separate `pip-audit` development dependency with uv's built-in
  `uv audit --locked --preview-features audit-command` workflow.
- Pinned the uv CLI to 0.12.18 in every workflow.

### Added

- Draft Android chat lane declarations for Signal (`org.thoughtcrime.securesms`),
  WhatsApp (`com.whatsapp`), and Telegram (`org.telegram.messenger`), each with a
  dedicated synthetic account slot and an explicit settings profile.
- Draft `chat.link-preview-fetch` check and draft `chat` suite covering the three
  chat subjects. Both stay non-active until a real adapter, a physical Android device
  per slot, synthetic phone numbers, and provider-terms review are in place.
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
