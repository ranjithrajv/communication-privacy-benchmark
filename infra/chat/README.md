# Chat Canary Deployment

The canonical chat lane will run a pinned upstream [Honeymessages](https://github.com/honeymessages/honeymessages-framework)
source commit behind a private authenticated gateway. The Python harness delivers a
synthetic honey-message to a chat account, then correlates the canary URL's resolution
and fetch against the account's read state.

Do not call undocumented Honeymessages routes directly from benchmark code, use its
public instance for canonical measurement, or point a scheduled run at a real contact.
Preserve MIT notices when redistributing the upstream framework or modifications.

## Gateway contract

`src/privacy_benchmark/adapters/chat_appium.py` is the only consumer. The gateway must
expose this versioned surface; nothing else about the upstream deployment is
contractual.

| Route | Purpose |
|---|---|
| `POST /v1/honey-messages` | Deliver a synthetic honey-message containing a canary URL. Returns `message_id`, `probe_id`, `delivered_at`, `expires_at`. |
| `GET /v1/honey-messages/{id}/state` | Report `delivered_at`, `displayed_at`, `watchers_healthy`, `window_expires_at`. |
| `GET /v1/honey-messages/{id}/observations` | Return typed observations correlated by `probe_id`. |

Requests carry `Authorization: Bearer <token>`. Redirects are not followed.

`probe_id` is what ties an observation to a run. It is allocated by the gateway before
delivery so that a fetch arriving before the client has even rendered the message is
still attributable, which is the whole point of the check.

## The state route is not optional

`state` exists to separate a client that suppressed link previews from a measurement
that never happened. The adapter will not report `pass` unless the gateway has
positively confirmed all three of:

- **delivery** — the honey-message reached the synthetic account;
- **display** — the client actually rendered the conversation, so link-preview behaviour
  was exercised; and
- **watcher health** — the DNS, TLS, HTTP, and WebSocket watchers were up, so an absence
  of traffic is evidence rather than an artefact.

Without that route the harness cannot distinguish the two cases, and every empty
observation set would be reported as a clean client. A gateway that omits it is not
compatible with canonical measurement.

This matters more in chat than in email. A single delivery attempt has more ways to
silently fail to become a display event:

- Android background restrictions can hold a message in the push queue until the device
  is unlocked and the app is foregrounded, so a correct client looks identical to a
  broken one;
- each of the three subjects fetches previews on a different trigger, and a session that
  is merely logged in is not evidence the conversation was rendered;
- a restricted or rate-limited account can accept delivery and never notify.

An adapter that reports `pass` on an empty observation set would turn any of those into
a published privacy finding about the product rather than about the lab.

## Observations a chat check correlates

Honeymessages observes the full fetch path, and each layer is a separate result detail
because they fail independently:

| Signal | Distinguishes |
|---|---|
| DNS resolution | A suppressed preview resolves nothing at all. |
| TLS / SNI | Which host was actually contacted, and whether the name was sent in clear. |
| HTTP request | The definitive fetch, carrying the client user agent and the reader's IP. |
| WebSocket / WebRTC | Long-lived channels that a preview alone would not reveal. |

`chat.link-preview-fetch` reports the HTTP request as decisive and the rest as
supporting detail. A DNS-only result is a partial observation, not a pass: the name
resolved, so something was attempted, but no content was fetched.

## Anti-abuse controls

The chat lane carries the highest account risk in the project, so these are properties
of the deployment rather than optional hardening:

- **Synthetic contacts only.** The honey-message sender is a lab-controlled account. The
  gateway must refuse to deliver to any recipient not on a checked-in subject list.
- **Rate limiting.** A cap on messages per account per hour, enforced gateway-side. A
  runaway or misconfigured run must degrade into a flagged result, not a burst.
- **A kill switch.** An operator can halt all delivery without a deploy. This is the
  difference between a bad run and a terminated account.
- **Anti-abuse rules upstream.** The framework is a 2024 research artifact; its own
  anti-abuse expectations and the attribution rules for scheduled traffic must be
  written down before any recurring run.

The `operations.toml` provider-terms review governs whether automated interaction is
permitted at all. WhatsApp is the highest-risk subject and the review may conclude that
the subject stays unmeasured. A pending review is not implicit permission.

## Configuration

The gateway URL, bearer token, Appium server address, and the account-slot-to-number
mapping are supplied at run time from a secret store. No phone number is written to a
checked-in definition, and the synthetic numbers are provisioned out of band.
