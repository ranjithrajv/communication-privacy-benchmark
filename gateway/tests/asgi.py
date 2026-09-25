"""A synchronous ASGI transport, so the benchmark's sync client can drive the real app.

``httpx.ASGITransport`` is asynchronous and the benchmark's ``EptGatewayClient`` is a
synchronous client. Rather than rewrite the client under test — which would mean the
contract tests no longer exercise the production code path — this bridges the two.

The bridge is deliberately minimal and lives with the tests, not in the service. It exists
only so the real client can reach the real application without a socket; anything it
smoothed over would be a contract difference the tests could no longer see.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any, cast

import httpx

#: What the app handed back: a status line, its headers, and the body chunks in order.
Response = tuple[int, list[tuple[bytes, bytes]], list[bytes]]


class SyncASGITransport(httpx.BaseTransport):
    """Drive an ASGI application from a synchronous httpx client."""

    def __init__(self, app: Callable[..., Any], *, root_path: str = "") -> None:
        self.app = app
        self.root_path = root_path

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        """Synchronous entry point required by ``httpx.BaseTransport``."""

        body = request.read()
        status, headers, chunks = self._dispatch(self._scope(request), body)
        return httpx.Response(
            status_code=status,
            headers=headers,
            content=b"".join(chunks),
            request=request,
        )

    def _scope(self, request: httpx.Request) -> dict[str, Any]:
        return {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": request.method,
            "scheme": request.url.scheme,
            "path": request.url.path,
            "raw_path": request.url.raw_path.split(b"?")[0],
            "query_string": request.url.query,
            "root_path": self.root_path,
            "headers": [(key.lower(), value) for key, value in request.headers.raw],
            "client": ("127.0.0.1", 12345),
            "server": (request.url.host, request.url.port or 443),
        }

    def _dispatch(self, scope: dict[str, Any], body: bytes) -> Response:
        """Run the app, on its own event loop when one is already running.

        The adapter awaits this synchronous client from inside ``asyncio.run``, so the
        common case here is a nested call. ``asyncio.run`` refuses to nest and the app
        still has to be driven, so the coroutine goes to a worker thread with its own
        loop. The alternative — making the transport async — would mean the contract tests
        no longer exercise the synchronous client the benchmark actually ships.
        """

        coroutine = self._call(scope, body)
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(coroutine)
        with ThreadPoolExecutor(max_workers=1) as pool:
            return cast("Response", pool.submit(asyncio.run, coroutine).result())

    async def _call(self, scope: dict[str, Any], body: bytes) -> Response:
        chunks: list[bytes] = []
        headers: list[tuple[bytes, bytes]] = []
        result = _Status(500)

        async def receive() -> dict[str, Any]:
            if result.request_sent:
                return {"type": "http.disconnect"}
            result.request_sent = True
            return {"type": "http.request", "body": body, "more_body": False}

        async def send(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                result.status = message["status"]
                headers.extend(message.get("headers") or [])
            elif message["type"] == "http.response.body":
                chunks.append(message.get("body") or b"")

        await self.app(scope, receive, send)
        return result.status, headers, chunks


class _Status:
    """Mutable status holder, so the request-sent flag and the code live off one object."""

    __slots__ = ("request_sent", "status")

    def __init__(self, status: int) -> None:
        self.status = status
        self.request_sent = False
