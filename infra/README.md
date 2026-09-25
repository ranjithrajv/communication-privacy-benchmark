# Lab Infrastructure

This directory holds persistent service and self-hosted runner configuration. Canonical
check logic does not live here, and no real-account workflow may be added without the
security controls described in `GITHUB_ACTIONS_ARCHITECTURE.md`.

Planned subdirectories:

- `appium/`: exact Appium server and driver lock plus runner health checks.
- `ept/`: pinned upstream EPT image/gateway configuration.
- `compose/`: local-only persistent canary services after the unified canary contract
  is approved.

Do not commit credentials, account identifiers, device logs, packet captures, browser
profiles, or generated test output.
