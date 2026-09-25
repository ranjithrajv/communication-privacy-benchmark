# Changelog

All notable changes to this project are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) with `0.x` alpha releases.

## [Unreleased]

### Added

- `gateway/`, the private canary gateway, as a **separate distribution with its own
  lockfile**. Ten checks were wired to a contract that nothing implemented: `infra/` held
  documentation and no service, so every email and webmail measurement was blocked on
  software that did not exist. `TECH_STACK_DECISION.md` sanctions a unified canary service
  "only when the email/chat contracts prove it is needed"; they now do, so the condition
  is met. It is deliberately *not* a uv workspace member, because its dependency set has
  no business changing the lockfile every short-lived Actions job installs.

  It implements the three routes in `infra/ept/README.md` plus the collectors' write path,
  and its models are written independently of the adapter's. That is the point: if the two
  sides shared models they could not disagree, and disagreement is the bug class that
  produces a clean result for a client that was never measured. `tests/test_contract.py`
  therefore runs the benchmark's real `EptGatewayClient` against the real application.

  Three behaviours are load-bearing rather than incidental:

  - **Watcher health is a heartbeat, never a flag.** `watchers_healthy` is computed from
    whether every required collector has checked in inside a grace period, so a collector
    that has stopped stops vouching for the window. A service that hardcoded it would
    report every unwatched window as a clean client. A freshly started service is
    unhealthy until its collectors announce themselves, which is the correct default.
  - **The `Referer` header is recorded verbatim and the capability is declared.** The
    adapter refuses to report a clean client without `referer_captured`, so that flag is a
    promise this service has to keep rather than a value the adapter can assume.
  - **Contacts for an unknown or expired probe are refused**, and an unauthenticated
    contact is refused, because an invented contact is a failed measurement that looks
    like a disclosure.

  Not built yet, and said so in `gateway/README.md`: SMTP delivery, the DNS and SNI
  watchers (so no window can currently be healthy), and persistent storage. The store is
  a `Protocol` with an in-memory reference implementation, so PostgreSQL with SQLAlchemy
  Core is a substitution behind that interface rather than a rewrite. Upstream Email
  Privacy Tester is not embedded, proxied, or wrapped: it is GPL-3.0 and cannot be
  combined into an AGPL-3.0-only distribution, so the contract is implemented from the
  written spec instead.

- `email.referrer-disclosure` is answered by the EPT adapter, which required extending
  the gateway contract rather than the adapter alone. `GatewayTestState` gains
  `referer_captured` and `third_party_hosts`, and `GatewayObservation` gains a declared
  `referrer` field.

  The capability flag is the part that matters. A gateway that does not capture the header
  returns *exactly* the observations a client that leaked nothing would produce, so without
  an explicit declaration the check would report every client as clean — the one failure
  mode this benchmark exists to prevent. Upstream cannot supply the header at all, so the
  private gateway must be changed to send it and to declare `referer_captured`; until it is,
  every run reports `inconclusive` rather than a clean result.

  `referrer` is a declared field rather than a key in the open `detail` map, because a key
  spelled differently is absent rather than wrong, and `extra="forbid"` means a gateway
  sending it to an adapter that does not declare it fails loudly.

  A clean result is `partial` unless the test also ran a third-party canary host. The
  declared threat is a host the reader did not choose to visit, and a run that watched only
  the tracking host never exercised it, so reporting `pass` would claim coverage that was
  not measured. A `Referer` reaching the tracking host and one reaching another host are
  reported under different reason codes, because they are disclosures to different parties.

- The webmail lane: a `WebmailAutomation` recipe on the subject definition, a
  `webmail-playwright` adapter, and the `webmail.remote-content` check. The provider is
  carried as **data** — a recipe of selectors on the subject — rather than compiled into
  the adapter, so choosing a webmail product is a change to a checked-in definition
  instead of a new branch in code, and one code path cannot quietly stand for two
  providers.

  The lane observes the same canary through the same gateway as the email clients and
  reuses that gateway's observation models and `adjudicate` unchanged, because the
  adversary and the channel are identical; what the adapter adds is the one thing the
  gateway cannot do for itself, driving the product's UI and reporting whether the
  message was actually rendered. A webmail row and a desktop row for the same behaviour
  therefore carry the same `ept.*` reason codes, which is what makes them comparable.

  It is registered and deliberately has no suite and no workflow. A suite must name at
  least one subject and a subject *is* a product, so naming the provider is still an open
  decision; a lane that cannot name a subject would queue against a runner that does not
  exist and fail on every dispatch. `infra/webmail/README.md` records the recipe contract,
  what the loader enforces versus what it can only state, and the remaining procurement.

- `pt-bench site` renders a finalized run bundle as a static GitHub Pages site, and
  `github_pages` is now a first-class `PublicationTarget`. The page is a view over a bundle
  that cleared the publication gate, not a second artifact of record: it is regenerated from
  the bundle on every publish, so it cannot drift from the evidence it describes, and the
  release asset and its receipt remain what a reader cites. The two are not treated as
  interchangeable, because a page is indexable, cached indefinitely, and quotable cell by cell
  without its run provenance, so permitting one is not permitting the other.

  The generator re-derives the publication decision itself rather than trusting a caller or a
  receipt, because a page is the artifact most likely to be read without the run that produced
  it. A run that fails the gate still renders a page carrying its refusal — a refused run shown
  is a record, while a refused run that vanished is indistinguishable from one that never ran —
  and the command exits `2` so a scheduled lane can refuse to deploy it. HTML is built from the
  rollup models rather than by converting the markdown report, so no cell is a re-derivation of
  a string; the markdown ships verbatim beside it as the raw artifact. Since pages are static,
  the htmx fragments are pre-rendered at build time and the page works with JavaScript disabled;
  htmx 4 is pinned to an exact version because 4.0 ships under the npm `next` tag while 2.x
  remains `latest`.

- Tests for the published page at the rendered-HTML boundary, since that is the surface a
  reader receives: balanced markup, relative links that survive a project subpath, a rate never
  printed without its interval, the apps-as-columns orientation, and a fragment that is complete
  rather than a patch. The last of these is a htmx 4 requirement specifically — 4.0 re-fetches
  on history restore instead of replaying a stored snapshot, so a fragment carrying only a diff
  would render an empty page on back navigation.


- Tests that the publication gate *opens*. The checked-in policy has
  `publication.target = "github_pages"` and every provider-terms review is pending, so the
  only path reachable here was the refusal. The first time someone clears a review, the
  succeeding path would run for the first time in production, on
  a real weekly run, with a real account behind it. It is now exercised in CI against a
  hand-built satisfying policy that does not weaken the real one.
- Tests that a partly-implemented suite degrades honestly. One of the ten declared
  checks has no adapter on purpose, waiting on a second canary host, and the fixture
  check is non-canonical by construction. The risk is not that they stay unimplemented but
  that a partial suite quietly
  under-reports coverage, so an unimplemented check is now proven to surface as
  `unsupported` through to the roll-up verdict, never as a pass, a missing row, or a
  dropped count.

- Six draft email disclosure checks joining `email.remote-content`, covering DNS and
  SNI resolution, reader identification, remote references in calendar, vCard, SVG and
  nested-message parts, background fetches with no reader interaction,
  `List-Unsubscribe` header fetches, and referrer or identifier disclosure on a followed
  link. They are separate checks because each has a distinct adversary and a distinct
  control: a client that blocks body images while rendering a calendar invite is
  invisible to a body-only test, and folding that into one result would hide it. Only
  `email.remote-content` has an adapter; the rest are `unimplemented` and each
  description states what it is still waiting for.

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
  one provider-terms review per subject.- A canonical-approval gate: `pt-bench plan` refuses a GitHub Actions run for any
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
- Draft `chat.notification-preview` check and a `chat-notification` adapter, covering the
  lock-screen notification surface that the canary-based checks cannot reach. It reads the
  notification shade rather than the network, so an empty reading is never evidence: a
  notification is only read as a disclosure once the shade was readable and a notification
  was positively due. A body in the notification is a `fail`, a named conversation is a
  `partial`, and a body shown against a declared `notification_privacy = "none"` is
  reported as `chat.setting-not-honoured` rather than as a weak default.
- A `notification_shade` evidence kind, so lock-screen findings are queryable in a
  published corpus rather than filed as screenshots or application logs.
- A normalized `notification_privacy` setting (`content`, `sender_only`, `none`) on all
  three chat subjects, so rows compare across apps that name the setting differently.
- First real email, webmail, or messaging subject adapter.
- Pinned Email Privacy Tester gateway and lab deployment.
- Protected physical-device or regional measurement infrastructure.

### Changed

- The chat suite runs three repetitions instead of one, and the chat lane's subject job
  is serialized with `max-parallel: 1` to match. One repetition cannot produce a Wilson
  interval and can never report `flaky`, so the chat lane was structurally unable to use
  the roll-up machinery the rest of the benchmark depends on. The serialization is not a
  side effect: `operations.toml` provisions three devices *one per chat account slot*, and
  a second repetition is a second hand on the *same* slot, so two of them running at once
  would drive one device and one synthetic number with two concurrent sessions. Nothing in
  the matrix can prove which slot a queued job lands on, so the whole matrix is serialized
  rather than trusted to line up — the same tradeoff PrivacyTests.org accepts for its
  mobile pool.
- The chat lane's per-app UI knowledge moved out of the adapter and into the subject, as a
  `ChatAutomation` recipe alongside the webmail one. `AppiumChatSession` previously took a
  single `message_selector` that it used both to open a conversation and to find the
  honey-message bubble, so those were one field doing two unrelated jobs, and a recipe that
  lived in the adapter would have meant a branch per app. The recipe now separates the
  activity to launch, the conversation locator, the bubble, and an optional body locator.
  The invariant that matters is enforced rather than documented: `conversation_selector`
  must contain a `{number}` placeholder, because a recipe that opened whatever thread
  happened to be on screen would produce a canary observation belonging to a conversation
  the reader never entered. A locator that fails *before* the conversation is open now
  raises `RecipeUnavailable` rather than reporting an undisplayed message, since a recipe
  that stopped matching its product would otherwise be indistinguishable from a client
  that showed nothing — the same before/after distinction the webmail recipe already
  draws. The checked-in chat subjects deliberately still carry no recipe, because no
  selector has been verified against a physical device.
- `SubjectDefinition.automation` is now `webmail`, and a sibling `chat` field carries the
  new recipe. The old name implied a single automation concept and would have been
  ambiguous the moment a second kind existed. A subject may carry at most one recipe, and a
  chat recipe requires the client to name a package identifier: the Appium session launches
  by package and the notification shade is read by filtering on it, so a recipe without one
  could only ever report an unavailable device.
- The preflight observation now reaches the run record. `ExecutionManifest` carries
  the `SubjectObservation` that was active for an execution, and `pt-bench execute`
  accepts `--observation`. Preflight was previously standalone: a workflow could run it
  and drop the artifact, but no result named the build it was measured on, which is the
  one thing a longitudinal comparison needs. The observation contracts moved from
  `harness/preflight.py` into `spec/models.py` so the observation is an ordinary public
  contract and the circular import the layering had required is gone.

- Aggregation now validates the repetition axis: a subject-and-repetition position must
  be claimed by exactly one execution, and a repetition outside the planned range is
  refused. Previously two executions claiming the same repetition silently overwrote
  each other's results while `result_count` counted both, so a bundle could report
  `complete` for a repetition that was never measured. The redundant execution-count
  check was removed because these two guards subsume it.
- The gateway contract no longer claims an observation channel or signal that upstream
  cannot produce. There is no TCP channel (preconnect arrives via SNI) and no MIME
  channel, and the open assertion moved from the gateway to the harness, because EPT has
  no open signal. An adapter constructed without an `open_observer` always reports
  `inconclusive`.
- Replaced the separate `pip-audit` development dependency with uv's built-in
  `uv audit --locked --preview-features audit-command` workflow.
- Pinned the uv CLI to 0.12.18 in every workflow.

### Fixed

- The source distribution now includes `infra/`. Three source modules and two test
  modules cite `infra/ept/UPSTREAM_FINDINGS.md` and `infra/chat/README.md` by path as the
  evidence for the adapter design, so excluding the directory left dangling citations for
  anyone installing from an sdist. The build also stopped listing a `/tools` directory
  that does not exist; hatchling ignored it silently, so the entry was a claim about the
  package that was never true.
- `infra/ept/README.md` no longer advertises an `opened_at` field on the gateway state
  route. `UPSTREAM_FINDINGS.md` establishes that upstream EPT sets `Tests.accessed` on
  send and on the first callback of any kind, so it is not an open confirmation and a
  contract requiring it is unsatisfiable. The route now lists only the fields the gateway
  can actually supply, and the "an open" precondition says where the open really comes
  from.
- `operations/1.0.0/operations.toml` no longer names a FairEmail subject in the Gmail
  account procedure. No such subject exists, and a policy file is the one artifact a
  reviewer reads to decide what is actually being measured. The note now describes the
  two subjects that share the slot and records that a third is a roadmap target.
- `GITHUB_ACTIONS_ARCHITECTURE.md` separates the nine checked-in workflows from the two it
  specifies but has not implemented (`full-benchmark.yml`, `maintain-subjects.yml`), and
  corrects the reusable workflow's name to the one on disk. The email lane's header
  comment no longer implies an orchestrator that calls it exists.
- `README.md` documents `preflight`, `publish`, and `verify-shade`, which were reachable
  from the CLI but absent from the command list. It also states their fail-closed exit
  codes, which are the reason to reach for them rather than a detail to discover later.
- Removed an inert `ruff` per-file ignore for `S101`. The `S` (flake8-bandit) rules are not
  in the project's `select` list, so the ignore suppressed nothing while appearing to
  document that asserts are permitted in tests.
- This entry's own section ordering: the `Unreleased` block had two `### Added` headings
  with a `### Changed` between them, and described a `publication.target` and an
  unimplemented-check count that were both out of date.

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
