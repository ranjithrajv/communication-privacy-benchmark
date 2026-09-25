# Webmail lane

The webmail lane renders a synthetic canary message in a webmail product's own UI and
reports what that rendering disclosed. It is built and wired; it cannot run yet, and this
file records exactly why.

## What is built

| Piece | Where | State |
|---|---|---|
| Automation recipe | `WebmailAutomation` in `spec/models.py` | loaded and validated from the subject |
| Adapter | `adapters/webmail_playwright.py` | answers `webmail.remote-content` |
| Check | `checks/webmail/remote-content/1.0.0/check.toml` | `draft`, no suite |
| Canary | reused from the email lane | same gateway, same contract |
| Browser runner | — | does not exist |

There is deliberately no workflow file. A lane that cannot name a subject would queue
against a runner that does not exist and fail on every dispatch, which is noise rather
than signal.

## How it fits the email lane

The webmail lane observes the **same** canary through the **same** gateway. It reuses
`EptGatewayClient`, the gateway's observation models, and `adjudicate` unchanged, because
none of that changes when a browser renders the message instead of a desktop client: the
adversary is the same party, the channel is the same, and a contact is a disclosure for
the same reasons. A webmail row and a desktop row for the same behaviour therefore carry
the same `ept.*` reason codes, which is what makes them comparable.

The adapter supplies the one thing the gateway cannot do for itself — drive the product's
UI and report honestly whether the message was rendered. Upstream EPT has no open signal
at all (`infra/ept/UPSTREAM_FINDINGS.md`); here the open is an action the harness performs
and observes, not a fact it reads off the gateway.

## Why the provider is not in the adapter

Choosing a webmail provider is a decision that has not been made, so the provider is
**data**: a `WebmailAutomation` recipe carried by the subject. Adding a provider means
adding a subject with a recipe, not editing the adapter or adding a branch to it.

That keeps the choice honest in both directions. A reader of the adapter cannot mistake
one provider's behaviour for another's, because there is only one code path; and the
recipe cannot quietly change what is measured, because every selector in it is reviewed
data rather than a call site.

## The recipe contract

```toml
[automation]
entry_url        = "https://…"        # https only; see below
user_field       = "…"                # login form
password_field   = "…"
submit_field     = "…"
message_row      = "…"                # matches message list entries
message_open     = "…"                # the link that opens one
message_body     = "…"                # the rendered body
ready_marker     = "…"
login_timeout_seconds = 60
open_timeout_seconds  = 60
```

Constraints the loader enforces:

- **`entry_url` must be https.** The harness types a synthetic password into this origin.
  Over plain http any network observer reads it, and the subject stops being faithful to
  the product a reader actually uses.
- **`message_row` and `message_open` must differ.** If they were the same element the
  harness could not tell "the list never loaded" from "the message opened", which is the
  one distinction the open signal exists to make.
- **`message_body` must not be the open control**, for the same reason.
- **A recipe requires a named `service`.** A comparison row is meaningless without
  knowing which service it is.

Constraints the loader cannot enforce, stated here instead:

- **`message_row` is assumed to match newest-first.** The harness opens the first match
  and the canary is the message that just arrived. A recipe listing oldest-first would
  open the wrong message — but it would fail loudly, because the canary would record
  nothing, rather than report a false pass.
- **A recipe that stops matching its product raises, it does not return "not opened".**
  This is why `WebmailRecipeError` exists and why a session is only constructed after
  delivery is confirmed. A silently unopenable message would look exactly like a client
  that fetched nothing, which is the one failure mode this benchmark must never have.

## What is still missing

1. **A provider decision.** No subject exists, so no suite exists: a suite must name at
   least one subject, and a subject *is* a product. This is the only blocker that is not
   a task.
2. A browser runner lane in the measurement region, labelled `self_hosted_regional`.
3. A provisioned synthetic mailbox and its credentials in the environment, as
   `PRIVACY_BENCHMARK_WEBMAIL_<SLOT>_USERNAME` and `..._PASSWORD`. Both halves are
   required before a slot is admitted.
4. An approved provider-terms review, which is a different and harder review for webmail
   than for a native client: the provider's own image proxying and server-side rendering
   can disclose to the provider on the reader's behalf, which is a separate adversary
   (`webmail.provider-render-disclosure`) with a separate control.
5. A pinned and deployed canary gateway, as for the email lane.

## A note on provider-side rendering

The second threat model on the check exists because webmail is not just "email in a
browser". A provider that rewrites remote image URLs through its own cache discloses the
open to *the provider*, not to the canary, and reports nothing to the canary at all. A
result of `pass` here therefore means "the canary observed nothing", not "the provider
learned nothing", and the two must not be collapsed into one claim.
