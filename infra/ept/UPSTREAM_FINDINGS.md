# EPT Upstream Findings

Verified by reading the pinned upstream source on 25 September 2026. These are the
facts the benchmark's gateway contract is derived from, and the corrections they force
on any contract inferred from EPT's documentation alone.

Source: <https://gitlab.com/grepular/ept3> (`master`, 97 commits, 7 tags).

## Observation sources are exactly three

EPT ships **two** watcher processes plus the canary web server. There is no standalone
TCP watcher and no standalone HTTP watcher process.

| Channel | Mechanism | Source file |
|---|---|---|
| `http` | The tracking URL *is* the backend `/callback?code=…&test=…` route, so a canary contact is a direct request the web server records with the client address, user agent, and `X-Forwarded-For`. | `backend/routes/callback.js` |
| `dns` | An authoritative BIND server with query logging. `dns-watcher.js` tails `/var/log/bind/query.log` and POSTs a callback per match. | `dns-watcher.js` |
| `tls_sni` | A passive raw-socket capture (`AF_PACKET` + in-kernel BPF on `tcp dst port 443`) that reassembles ClientHello messages and extracts the SNI hostname. | `sni-watcher/sni-watcher.py` |

`sni-watcher.py` is MIT-compatible Python but the repository is GPL-3.0; the
`FROM scratch` image contains a PyInstaller binary. It needs host networking,
`CAP_NET_RAW`, and an ethernet-framed interface.

## The `type` field is a label, not a transport

`backend/lib/tests.js` assigns each of the ~45 vectors a `type` of `dns`, `tcp`,
`http`, or `email`. This taxonomy is a **label on the vector**, not the channel that
observed it:

- `linkPreconnect` is typed `tcp` but is detected **only** by the SNI watcher, via
  `^([A-Za-z0-9]+)\.(link-preconnect)-test\.<domain>$`. There is no TCP watcher.
- `dispositionNotification` and `returnReceipt` are typed `email`. They add a MIME
  header that makes the **mail server** emit a notification email. They are not
  client-side network fetches, and in `callback.js` a `tcp`/`dns` callback reports the
  watcher's observed client while every other type reports the *requesting* address —
  so for an `email` callback that address is a mail server, not the reader.

Any contract that maps `type` straight onto a channel will misattribute `email` vectors
as client behaviour.

## Provider prefetch is a real false-positive source

EPT's own `dnsAnchor` documentation warns:

> Some mail servers do DNS lookups on these URLs as part of their spam filtering
> process, so you may see the IP address of the mail servers DNS resolvers here, as
> well as, or instead of, your own.

A provider spam filter prefetching the canary is recorded as an observation **before the
recipient ever sees the message**. Scoring that as "the client leaked the open" is a
false `fail` on a provider behaviour. Observation origin has to be attributed, and an
unattributable observation must not be scored as a client leak.

## There is no delivery signal and no open signal

`Tests.accessed` is set to `true` in two places, and neither is what it looks like:

- `backend/routes/sendTest.js` sets it when the test email is **sent**.
- `backend/routes/callback.js` sets it on the **first callback** of any kind.

There is no field anywhere recording that the message reached an inbox, or that a
recipient opened it. `Tests` also carries a `testEmailsSent` counter and
`expireTests = 7 days` (604800 s).

Consequently:

- **`opened_at` cannot come from EPT.** An open is an interaction the *harness*
  performs by driving the client. A contract that requires the gateway to supply an
  open signal is unsatisfiable and would report `inconclusive` for every clean run.
- **`delivered_at` is not an EPT capability either**, but a self-hosted deployment does
  control its own SMTP path, so a private gateway *can* report it. That is a gateway
  capability, not an upstream one, and the contract must say so.

## Watchers cannot observe the lab's own host

- `dns-watcher.js` drops any query whose client IP matches a local interface address
  (`localIPs`).
- `sni-watcher.py` drops private, loopback, and link-local addresses (`is_private`).

A single-host lab therefore observes nothing. The client under test and the canary must
be on different hosts, or the ignore rules must be deliberately widened, which is itself
a threat to result validity and must be recorded as a subject attribute.

Both watchers also dedupe within 30 seconds (`dns-watcher.js` cache, `sni-watcher.py`
`FLOW_TTL`), so burst behaviour inside one window is invisible.

## An upstream gap: `dnsImg` cannot fire the DNS watcher

`dnsImg` instructs the client to request `http://CODE.img-test.DNS_ZONE/pixel.gif`, but
the DNS watcher's regex only matches `anchor` and `link` labels:

```js
: query: ([a-zA-Z0-9]+)\\.(anchor|link)-test\\.<zone> IN A(?:AAA)?
```

An `img-test` lookup is never matched, so a client that DNS-prefetches images would be
recorded as clean. Do not rely on `dnsImg` until upstream widens the pattern.

## License: the badge is not the declaration

`package.json` declares `"license": "GPL-3.0"` with no "or later". GitLab renders the
project badge as "GNU General Public License v3.0 or later", which is GitLab's default
rendering for a bare `GPL-3.0` identifier. `TECH_STACK_DECISION.md` was right to refuse
to assume relicensing: the authoritative declaration is **GPL-3.0**, and the badge
disagrees with it. Preserve notices and corresponding source, and do not adapt the
corpus without explicit upstream permission.
