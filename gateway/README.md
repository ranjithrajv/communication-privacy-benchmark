# Canary gateway

The private, authenticated service the benchmark's email and webmail lanes measure
against. It allocates a probe for a synthetic mailbox, serves the canary URLs a reader's
client will contact, records what came back, and reports the state the harness needs to
tell a clean client apart from a measurement that never happened.

Separate distribution from `communication-privacy-benchmark` because it is long-lived
infrastructure, not code every Actions job installs. AGPL-3.0-only, like the core.

## Contract

Implements the three routes in `../infra/ept/README.md` — `POST /v1/tests`,
`GET /v1/tests/{id}/state`, `GET /v1/tests/{id}/observations` — plus the write path the
collectors use. `Authorization: Bearer <token>` on everything except `/healthz`.

## Three decisions that are not incidental

**Watcher health is a heartbeat, never a flag.** `watchers_healthy` is computed from
whether every required collector has checked in inside a grace period. A service that
hardcoded it would report every unwatched window as a clean client — the worst failure
available to this benchmark. A freshly started service reports unhealthy until its
collectors announce themselves, which is the correct default.

**The `Referer` header is recorded verbatim, and the capability is declared.** The
adapter refuses to report a clean client unless the gateway says it captured the header,
because a service that stopped recording it would otherwise produce byte-identical
observations for a leaking and a clean client. `referer_captured` is therefore a promise
this code has to keep.

**Contacts for an unknown or expired probe are refused.** A contact nobody allocated is
not evidence about anything, and a late contact must not be able to change a verdict the
harness has already read.

## Configuration

| Variable | Meaning |
|---|---|
| `CANARY_GATEWAY_TOKEN` | Required. The service refuses to start without it. |
| `CANARY_GATEWAY_THIRD_PARTY_HOSTS` | Comma-separated canary hosts outside the message, for third-party `Referer` leakage. |
| `CANARY_GATEWAY_REQUIRED_WATCHERS` | Comma-separated collector names. May not be empty. |

No secret and no mailbox address is read from a checked-in file.

## Not built yet

Honest inventory of what this increment does **not** provide:

- **SMTP delivery.** `POST /v1/tests/delivered` is an explicit assertion the mail path
  must make; nothing here sends the canary message or its MIME vectors.
- **The DNS and SNI watchers.** They are required for a window to be healthy, so the
  service reports unhealthy until they exist and send heartbeats. That is why no
  measurement can run yet.
- **Persistent storage.** The store is a `Protocol` with an in-memory implementation.
  PostgreSQL with SQLAlchemy Core is a substitution behind that interface, per
  `TECH_STACK_DECISION.md`, not a rewrite.
- **Upstream EPT integration.** This service does not embed, proxy, or wrap upstream
  Email Privacy Tester. Upstream is GPL-3.0 and cannot be combined into an AGPL-3.0-only
  distribution; the contract is implemented from `infra/ept/README.md` instead. See
  `../infra/ept/UPSTREAM_FINDINGS.md`.

## Tests

`tests/test_contract.py` runs the benchmark's real `EptGatewayClient` against this real
application. The models on the two sides are written independently, so a renamed field or
a changed default fails here rather than on a measurement runner.
