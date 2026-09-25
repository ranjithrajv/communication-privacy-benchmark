"""Runs the webmail checks a private canary gateway and a Playwright lane can answer.

The division of labour is the whole design. The EPT gateway already decides what a canary
contact *means* -- who made it, whether it is attributable to the client under test, and
whether the probe was sound enough to interpret -- and that adjudication is a pure
function of gateway state, observations, and whether an open happened. None of that
changes because the message was rendered by a browser instead of a desktop client: the
adversary is the same party, the channel is the same, and a contact is a disclosure for
the same reasons. So this adapter reuses that adjudication rather than writing a second
one, and supplies only the one thing the gateway cannot do for itself -- drive the
product's own UI and report honestly whether the message was actually rendered.

The provider is *not* in this module. Which webmail to drive, and how its login and
message views are addressed, is a ``WebmailAutomation`` recipe carried by the subject,
so choosing a provider is a change to a checked-in definition instead of a new branch
here. A recipe that stops matching its product raises rather than returning False,
because a silently unopenable message would look exactly like a client that fetched
nothing.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field
from datetime import timedelta
from enum import StrEnum
from typing import Any, Protocol
from urllib.parse import urlsplit

from privacy_benchmark.adapters.automation import AutomationStack
from privacy_benchmark.adapters.base import AdapterError, AdapterOutcome
from privacy_benchmark.adapters.ept import (
    CLIENT_ATTRIBUTABLE_ORIGINS,
    EptGatewayClient,
    GatewayTestCreated,
    GatewayTestState,
    ObservationOrigin,
    adjudicate,
    await_observations,
)
from privacy_benchmark.harness.context import ExecutionContext
from privacy_benchmark.spec.models import (
    CheckDefinition,
    ResultStatus,
    WebmailAutomation,
    utc_now,
)


class WebmailRecipeError(AdapterError):
    """The subject's recipe could not drive its webmail product.

    Raised only for a selector that does not resolve *before* the open, where the recipe
    is provably the problem. After the open the same symptom is ambiguous -- a client that
    never rendered the body and a recipe that stopped matching look identical -- so that
    case is reported as an unasserted open instead, never as this error.
    """


class Adjudication(StrEnum):
    """The reasons this adapter reaches a verdict that the shared adjudication cannot.

    Everything the measurement itself decides reuses the email adapter's reason codes, so
    a webmail row and a desktop row for the same behaviour carry the same vocabulary. Only
    the reasons specific to *driving a browser* live here; a canary that recorded a
    disclosure is reported with the same ``ept.*`` code a desktop client would use, which
    is what makes the two rows comparable.
    """

    UNSUPPORTED_CHECK = "webmail.unsupported-check"
    LANE_UNAVAILABLE = "webmail.lane-unavailable"
    RECIPE_MISSING = "webmail.recipe-missing"
    CREDENTIALS_MISSING = "webmail.credentials-missing"


class WebmailSession(Protocol):
    """Drives one synthetic webmail account in a real browser.

    Split out as a protocol for the same reason the chat adapter splits out its Appium
    session: the adjudication must be testable without a browser, and the per-provider UI
    work must stay isolated from the reasoning that depends on it.
    """

    async def log_in(self) -> None:
        """Authenticate with the synthetic account's credentials."""

    async def open_message(self) -> bool:
        """Render the delivered message and report whether its body appeared.

        No marker is passed because the harness does not write the canary body -- the
        gateway does -- so a marker the harness chose would not be in the message and
        would silently match nothing. The account is synthetic and dedicated, so after
        confirmed delivery the newest row is the canary.

        Returning False means the harness could not confirm the message was rendered. It
        is not a claim that the client refused: the distinction is not available from
        outside the browser, so the adapter reports an unasserted open instead.
        """

    async def close(self) -> None: ...


@dataclass(frozen=True, slots=True)
class WebmailCredentials:
    """One synthetic account's login. Never serialized, never read from a definition."""

    username: str
    password: str


@dataclass(slots=True)
class PlaywrightWebmailSession:
    """A Playwright-backed session that drives a recipe's webmail product.

    Playwright is imported lazily so that a run which never reaches a browser -- every
    plan-time and schema-checking command, and the account-free smoke lane -- does not
    need a browser installed on the machine doing the importing.
    """

    recipe: WebmailAutomation
    credentials: WebmailCredentials
    headless: bool = True
    browser: str = "chromium"
    _driver: Any = field(default=None, init=False, repr=False)
    _page: Any = field(default=None, init=False, repr=False)

    async def log_in(self) -> None:
        page = await self._ensure_started()
        page.goto(self.recipe.entry_url, wait_until="domcontentloaded")
        self._await(page.locator(self.recipe.user_field))
        page.fill(self.recipe.user_field, self.credentials.username)
        page.fill(self.recipe.password_field, self.credentials.password)
        page.click(self.recipe.submit_field)
        # The message list is the proof the login worked, not the absence of an error
        # page: several products render a sign-in failure in place without changing the
        # URL, so waiting on the form to disappear would accept a failed login.
        self._await(page.locator(self.recipe.message_row))

    async def open_message(self) -> bool:
        page = await self._ensure_started()
        page.goto(self.recipe.entry_url, wait_until="domcontentloaded")
        self._await(page.locator(self.recipe.message_row))
        # ``first`` is the newest row only because the recipe documents newest-first
        # ordering. That is a real constraint on a recipe and it is checked there, not
        # assumed here.
        row = page.locator(self.recipe.message_row).first
        if not await self._visible(row, self.recipe.open_timeout_seconds):
            # No row at all is a measurement about the product or the account, not a
            # broken recipe, so it is not raised.
            return False
        row.click()
        return await self._visible(
            page.locator(self.recipe.message_body), self.recipe.open_timeout_seconds
        )

    async def close(self) -> None:
        if self._driver is not None:
            await self._driver.stop()
            self._driver = None
            self._page = None

    async def _ensure_started(self) -> Any:
        if self._page is None:
            try:
                from playwright.async_api import async_playwright
            except ImportError as error:  # pragma: no cover - environment dependent
                raise AdapterError("playwright is not installed on this runner") from error
            self._driver = await async_playwright().start()
            launcher = getattr(self._driver, self.browser)
            browser = await launcher.launch(headless=self.headless)
            self._page = await browser.new_context().new_page()
        return self._page

    async def _visible(self, locator: Any, timeout_seconds: int) -> bool:
        try:
            await locator.wait_for(state="visible", timeout=timeout_seconds * 1000)
        except Exception:  # absence is the answer here, not a failure
            return False
        return True

    def _await(self, locator: Any) -> None:
        try:
            locator.first.wait_for(
                state="visible", timeout=self.recipe.login_timeout_seconds * 1000
            )
        except Exception as error:  # re-raised below as a recipe failure
            raise WebmailRecipeError(
                f"recipe selector did not resolve at {self.recipe.entry_url}: {error}"
            ) from error


@dataclass(slots=True)
class WebmailPlaywrightAdapter:
    """Runs the webmail checks a pinned canary gateway and a browser lane can answer.

    Synthetic credentials are supplied per account slot at construction and are never read
    from a checked-in definition, so a real password cannot reach the repository.
    """

    client: EptGatewayClient
    credentials: dict[str, WebmailCredentials] = field(default_factory=dict)
    session_factory: Any = None
    adapter_id: str = "webmail-playwright"
    version: str = "1.0.0"
    poll_interval_seconds: float = 5.0
    #: Opening a webmail message is a UI interaction with a small expected latency,
    #: whereas the canary window is the long part. Sharing one bound would let a browser
    #: stuck on a login wall hold the runner for the whole observation window before
    #: reporting ``inconclusive``.
    display_timeout_seconds: int = 120
    supported_checks: frozenset[str] = field(
        default_factory=lambda: frozenset({"webmail.remote-content"})
    )
    redaction_policy_id: str = "evidence-retention-v1"
    raw_retention: str = "30-days-then-delete"
    automation_stack: AutomationStack | None = None

    async def execute_check(
        self, check: CheckDefinition, context: ExecutionContext
    ) -> AdapterOutcome:
        if check.check_id not in self.supported_checks:
            return AdapterOutcome(
                status=ResultStatus.UNSUPPORTED,
                reason_code=Adjudication.UNSUPPORTED_CHECK.value,
                summary=(
                    f"The webmail adapter cannot answer {check.check_id}. Supported checks: "
                    f"{', '.join(sorted(self.supported_checks))}."
                ),
                details={"supported": False},
            )

        if self.session_factory is None:
            return AdapterOutcome(
                status=ResultStatus.INCONCLUSIVE,
                reason_code=Adjudication.LANE_UNAVAILABLE.value,
                summary=(
                    "No browser lane is configured, so this webmail product's behavior on "
                    "message open was not exercised at all."
                ),
                details={"check_id": check.check_id, "session": False},
            )

        recipe = context.subject.automation
        if recipe is None:
            return AdapterOutcome(
                status=ResultStatus.INCONCLUSIVE,
                reason_code=Adjudication.RECIPE_MISSING.value,
                summary=(
                    f"{context.subject.subject_id} carries no webmail automation recipe, so "
                    f"the harness has no way to open a message in this product and "
                    f"{check.check_id} was not measured."
                ),
                details={
                    "check_id": check.check_id,
                    "subject_id": context.subject.subject_id,
                    "recipe": False,
                },
            )

        slot = context.subject.account.slot_id
        credentials = self.credentials.get(slot)
        if credentials is None:
            return AdapterOutcome(
                status=ResultStatus.INCONCLUSIVE,
                reason_code=Adjudication.CREDENTIALS_MISSING.value,
                summary=(
                    f"No synthetic credentials are configured for account slot {slot}, so no "
                    f"webmail session could be opened and {check.check_id} was not measured."
                ),
                details={"check_id": check.check_id, "account_slot": slot},
            )

        created = self.client.create_test(email=context.subject.account.slot_id)
        state = await self._await_delivery(created, check.timeout_seconds)

        # The browser is only driven once the canary is actually in the inbox. Logging in
        # to a product for a probe that will never deliver types a synthetic credential
        # into that product and exercises its login path for no measurement, and it would
        # report an unrendered message for a message that never existed.
        session: WebmailSession | None = None
        open_asserted = False
        if state.delivered_at is not None:
            session = self.session_factory(recipe=recipe, credentials=credentials)
            try:
                open_asserted = await self._open(session)
            finally:
                await session.close()

        observations = await await_observations(
            client=self.client,
            test_id=created.test_id,
            state=state,
            timeout_seconds=check.timeout_seconds,
            poll_interval_seconds=self.poll_interval_seconds,
        )

        status, reason_code, summary = adjudicate(
            state=state, observations=observations, open_asserted=open_asserted
        )
        return AdapterOutcome(
            status=status,
            reason_code=reason_code.value,
            summary=summary,
            details={
                "check_id": check.check_id,
                "adapter": self.adapter_id,
                "probe_id": created.probe_id,
                "test_id": created.test_id,
                "entry_url_host": _host(recipe.entry_url),
                "observation_count": len(observations),
                "client_observation_count": sum(
                    1 for item in observations if item.origin in CLIENT_ATTRIBUTABLE_ORIGINS
                ),
                "provider_observation_count": sum(
                    1 for item in observations if item.origin is ObservationOrigin.PROVIDER
                ),
                "unattributed_observation_count": sum(
                    1 for item in observations if item.origin is ObservationOrigin.UNKNOWN
                ),
                "vectors": ",".join(sorted({item.vector for item in observations})),
                "delivered": state.delivered_at is not None,
                "open_asserted": open_asserted,
                "watchers_healthy": state.watchers_healthy,
                "account_slot": slot,
            },
        )

    async def _await_delivery(
        self, created: GatewayTestCreated, timeout_seconds: int
    ) -> GatewayTestState:
        """Wait for the canary to reach the inbox before touching the browser.

        A webmail message arrives asynchronously, so the open cannot be attempted first
        the way a desktop client can be handed an already-delivered message. Opening
        before delivery would report an unasserted open for a message that simply had not
        arrived yet, which is the same verdict a product that refused to render it would
        get -- two different facts collapsed into one, with the delivery half invisible.

        Returns the last state either way, so the caller adjudicates a probe that never
        delivered through the same ``delivered_at is None`` guard the desktop clients use.
        """

        deadline = min(created.expires_at, utc_now() + timedelta(seconds=timeout_seconds))
        while True:
            state = self.client.get_state(created.test_id)
            if state.delivered_at is not None or utc_now() >= deadline:
                return state
            await asyncio.sleep(self.poll_interval_seconds)

    async def _open(self, session: WebmailSession) -> bool:
        await session.log_in()
        return await session.open_message()


def _host(url: str) -> str:
    return urlsplit(url).hostname or ""


def browser_lane_available(environ: dict[str, str] | None = None) -> bool:
    """Whether this runner has a browser lane the webmail adapter may drive.

    Separate from the gateway check on purpose: a runner with the canary configured but no
    browser must still register the adapter so the routed check reports an unexercised
    result naming the missing lane, rather than failing to resolve an adapter at all.
    """

    env = os.environ if environ is None else environ
    return env.get("PRIVACY_BENCHMARK_BROWSER_LANE", "").strip() in {"1", "true", "yes"}


def webmail_credentials_from_environment(
    environ: dict[str, str] | None = None,
) -> dict[str, WebmailCredentials]:
    """Read synthetic webmail logins from the environment, keyed by account slot.

    Both halves of a login are required before an account is admitted, so a half-configured
    slot fails here rather than producing a session that cannot authenticate and a verdict
    that cannot tell that apart from a refused login. Credentials are deliberately absent
    from checked-in definitions, so a subject can declare which slot it uses without the
    repository ever holding the value for it.
    """

    env = os.environ if environ is None else environ
    prefix = "PRIVACY_BENCHMARK_WEBMAIL_"
    users: dict[str, str] = {}
    passwords: dict[str, str] = {}
    for key, value in env.items():
        if not key.startswith(prefix):
            continue
        slot, _, field_name = key[len(prefix) :].partition("_")
        if field_name == "USERNAME":
            users[slot] = value
        elif field_name == "PASSWORD":
            passwords[slot] = value
    return {
        slot: WebmailCredentials(username=users[slot], password=passwords[slot])
        for slot in sorted(users.keys() & passwords.keys())
        if users[slot] and passwords[slot]
    }
