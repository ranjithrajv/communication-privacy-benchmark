# Email Privacy Tester Deployment

The canonical email wedge will run a pinned upstream Email Privacy Tester source commit
and image digest behind a private authenticated gateway. The Python harness correlates
an opaque EPT test code with its run/probe ID and adjudicates exported observations.

Do not call undocumented EPT routes directly from benchmark code, access its database,
scrape its UI, or use its public SaaS for canonical measurements. Preserve GPL notices
and corresponding source when distributing the upstream application or modifications.

## Gateway contract

`src/privacy_benchmark/adapters/ept.py` is the only consumer. The gateway must expose
this versioned surface; nothing else about the upstream deployment is contractual.

| Route | Purpose |
|---|---|
| `POST /v1/tests` | Allocate a test for a synthetic mailbox. Returns `test_id`, `probe_id`, `expires_at`. |
| `GET /v1/tests/{id}/state` | Report `delivered_at`, `watchers_healthy`, `window_expires_at`. |
| `GET /v1/tests/{id}/observations` | Return typed observations correlated by `probe_id`. |

Requests carry `Authorization: Bearer <token>`. Redirects are not followed.

## The state route is not optional

`state` exists to separate a client that suppressed remote content from a measurement
that never happened. The adapter will not report `pass` unless the gateway has
positively confirmed all three of:

- **delivery** — the message reached the synthetic mailbox;
- **an open** — the client actually displayed it, so remote-content behaviour was
  exercised. This precondition is the one the gateway cannot supply: upstream EPT sets
  `Tests.accessed` on send and on the first callback of any kind, so it is not an open
  confirmation. The harness asserts the open through an `open_observer` instead, and an
  adapter without one reports `inconclusive` rather than claiming a pass it did not
  earn. See `UPSTREAM_FINDINGS.md`; and
- **watcher health** — the DNS, SNI, TCP, and HTTP watchers were up, so an absence of
  traffic is evidence rather than an artefact.

Without that route the harness cannot distinguish the two cases, and every empty
observation set would be reported as a clean client. A gateway that omits it is not
compatible with canonical measurement.

## Configuration

The gateway URL, bearer token, and the account-slot-to-mailbox mapping are supplied at
run time from a secret store. No mailbox address is written to a checked-in definition.
