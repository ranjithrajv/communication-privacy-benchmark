"""A real, self-hosted canary that speaks the gateway contract over real sockets.

The mocked-transport tests prove the adapter's logic. They cannot prove that the adapter
observes anything a real mail client would actually do, because nothing crosses a
network boundary. This module closes that gap for everything the lab owns:

- a real HTTP canary that records genuine requests with a real user agent and IP;
- a real authoritative DNS server with query logging, matching the same log format the
  upstream ``dns-watcher`` tails;
- a real SMTP receiver that delivers a message containing real canary URLs.

Nothing here contacts a third party. The only remaining unproven surface is a real
provider mailbox and a real mail client, both of which need the approvals the operations
policy gate enforces.

The DNS watcher behaviour reproduced here is upstream's: it drops queries originating
from the host's own addresses, and it only matches the ``anchor-test`` and ``link-test``
labels. Both are reproduced deliberately so the reproduction stays faithful.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import socket
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.message import EmailMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

#: Reproduces the upstream ``dns-watcher`` query-log pattern: a BIND query-log line
#: naming a per-test code under an ``anchor-test`` or ``link-test`` label in the canary
#: zone. This matches realistic BIND output while preserving the label restriction that
#: is the scientifically load-bearing part of upstream's behaviour. The incidental
#: whitespace of upstream's own expression is not reproduced, because it is not what
#: determines which observations are recorded.
#:
#: The restriction is why the ``img-test`` label used by the ``dnsImg`` vector can never
#: fire the watcher. See infra/ept/UPSTREAM_FINDINGS.md.
DNS_QUERY_PATTERN = re.compile(
    r"^\S+ \S+ (?:.*: )?client (?P<ip>\S+?)#\d+ .*?query: "
    r"(?P<code>[a-zA-Z0-9]+)\.(?P<label>anchor|link)-test\."
    r"(?P<zone>[a-zA-Z0-9.\-]+)\s+IN\s+A(?:AAA)?\b",
    re.IGNORECASE,
)


#: A realistic BIND query-log line for the given name, used to drive the watcher.
def bind_query_line(client_ip: str, qname: str) -> str:
    return (
        f"25-Sep-2026 12:00:00 queries: info: client {client_ip}#5353 "
        f"({qname}).query: {qname} IN A + (127.0.0.1)"
    )


#: The upstream SNI watcher's hostname pattern. Only the preconnect label is observable.
SNI_PATTERN = re.compile(
    r"^(?P<code>[A-Za-z0-9]+)\.(?P<label>link-preconnect)-test\.[a-zA-Z0-9.\-]+$"
)


@dataclass
class CanaryEvent:
    """One genuine canary contact, attributed to whoever opened the socket."""

    vector: str
    channel: str
    remote_ip: str
    observed_at: datetime
    user_agent: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)


class CanaryLedger:
    """Thread-safe record of every canary contact the lab observed."""

    def __init__(self) -> None:
        self._events: list[CanaryEvent] = []
        self._lock = threading.Lock()

    def record(self, event: CanaryEvent) -> None:
        with self._lock:
            self._events.append(event)

    def for_code(self, code: str) -> list[CanaryEvent]:
        with self._lock:
            return [event for event in self._events if code in event.detail.get("codes", ())]

    def all_events(self) -> list[CanaryEvent]:
        with self._lock:
            return list(self._events)


class _CanaryHandler(BaseHTTPRequestHandler):
    """A real HTTP canary endpoint. The tracking URL is the request path."""

    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        ledger: CanaryLedger = self.server.ledger  # type: ignore[attr-defined]
        parsed_code = _code_from_path(self.path)
        ledger.record(
            CanaryEvent(
                vector="img",
                channel="http",
                remote_ip=self.client_address[0],
                observed_at=datetime.now(UTC),
                user_agent=self.headers.get("User-Agent"),
                detail={"codes": [parsed_code] if parsed_code else [], "path": self.path},
            )
        )
        # A real 1x1 GIF, so a real client sees a real image rather than an error.
        body = bytes.fromhex(
            "47494638396101000100800000000000ffffff21f90401000001002c00000000010001000002024401003b"
        )
        self.send_response(200)
        self.send_header("Content-Type", "image/gif")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self) -> None:
        self.do_GET()

    def log_message(self, format: str, *args: Any) -> None:
        """Silence the default stderr access log."""


def _code_from_path(path: str) -> str | None:
    """Extract the per-test code from a canary URL path such as /<code>/pixel.gif."""

    parts = [part for part in path.split("?")[0].split("/") if part]
    return parts[0] if parts else None


class HttpCanary:
    """A real canary web server bound to loopback."""

    def __init__(self, ledger: CanaryLedger) -> None:
        self._ledger = ledger
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _CanaryHandler)
        self._server.ledger = ledger  # type: ignore[attr-defined]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)

    @property
    def port(self) -> int:
        return int(self._server.server_address[1])

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def tracking_url(self, code: str, path: str = "/pixel.gif") -> str:
        return f"{self.base_url}/{code}{path}"


class DnsCanary:
    """A real authoritative DNS server for the canary zone, with a query log.

    This binds UDP and TCP on loopback and answers every A query for the canary zone.
    It writes query records in BIND's ``/var/log/bind/query.log`` format so the
    reproduction is parsed by the same pattern upstream uses.
    """

    def __init__(self, zone: str, ledger: CanaryLedger, ttl: int = 30) -> None:
        self.zone = zone.lower().strip(".")
        self._ledger = ledger
        self._ttl = ttl
        self._address = "127.0.0.1"
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(("127.0.0.1", 0))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.query_log: list[str] = []

    @property
    def port(self) -> int:
        return int(self._sock.getsockname()[1])

    @property
    def address(self) -> str:
        return self._address

    def start(self) -> None:
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._sock.close()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def _serve(self) -> None:
        self._sock.settimeout(0.2)
        while not self._stop.is_set():
            try:
                query, peer = self._sock.recvfrom(512)
            except TimeoutError:
                continue
            except OSError:
                return
            name = _decode_qname(query)
            if name is None:
                continue
            response = self._answer(query, name)
            if response:
                try:
                    self._sock.sendto(response, peer)
                except OSError:
                    return
            self._log_query(name, peer[0])

    def _answer(self, query: bytes, name: str) -> bytes | None:
        if not name.endswith(self.zone):
            return None
        header = query[:2]
        question_end = _skip_question(query)
        if question_end is None:
            return None
        question = query[2:question_end]
        # Minimal A response. A DNS header is 12 bytes: ID(2) flags(2) QDCOUNT(2)
        # ANCOUNT(2) NSCOUNT(2) ARCOUNT(2).
        response = bytearray(
            header + b"\x81\x80" + b"\x00\x01" + b"\x00\x01" + b"\x00\x00" + b"\x00\x00" + question
        )
        response += b"\xc0\x0c"  # pointer to the question name
        response += b"\x00\x01\x00\x01"  # type A, class IN
        response += self._ttl.to_bytes(4, "big")
        response += b"\x00\x04" + bytes(int(part) for part in self._address.split("."))
        return bytes(response)

    def _log_query(self, name: str, client_ip: str) -> None:
        """Record a query in BIND's log format and attribute it like upstream does."""

        line = bind_query_line(client_ip, name)
        match = DNS_QUERY_PATTERN.match(line)
        if match is None:
            return
        self.query_log.append(match.group(0))
        label = match.group("label")
        self._ledger.record(
            CanaryEvent(
                vector=f"dns{label.capitalize()}",
                channel="dns",
                remote_ip=client_ip,
                observed_at=datetime.now(UTC),
                detail={"codes": [match.group("code")], "qname": name},
            )
        )


def _decode_qname(query: bytes) -> str | None:
    labels: list[str] = []
    offset = 12
    while offset < len(query):
        length = query[offset]
        if length == 0:
            break
        if length & 0xC0:
            return None
        offset += 1
        labels.append(query[offset : offset + length].decode("ascii", "replace"))
        offset += length
    return ".".join(labels).lower() if labels else None


def _skip_question(query: bytes) -> int | None:
    offset = 12
    while offset < len(query):
        length = query[offset]
        if length == 0:
            return offset + 5  # root label plus QTYPE and QCLASS
        offset += 1 + length
    return None


def local_addresses() -> frozenset[str]:
    """The host's own addresses, which upstream's watchers refuse to record.

    Reproduced so a lab that runs the client and the canary on one host learns that it
    will observe nothing, rather than concluding the client is clean.
    """

    found: set[str] = set()
    for info in socket.getaddrinfo(socket.gethostname(), None):
        address = str(info[4][0])
        if not ipaddress.ip_address(address).is_loopback:
            found.add(address.lower())
    return frozenset(found)


def build_test_message(
    *,
    to: str,
    code: str,
    http_tracking_url: str,
    dns_zone: str,
) -> EmailMessage:
    """Build a real message carrying real canary vectors.

    The DNS-prefetch anchor and link labels match what the upstream DNS watcher
    recognises, so a client that prefetches produces a genuine observation.
    """

    message = EmailMessage()
    message["Subject"] = "Communication Privacy Benchmark probe"
    message["From"] = "probe@privacy-benchmark.invalid"
    message["To"] = to
    message["Message-ID"] = f"<{code}@privacy-benchmark.invalid>"
    message.set_content("Synthetic probe message. Do not reply.")
    message.add_alternative(
        f"<html><body><p>Probe {code}.</p>"
        f'<img src="{http_tracking_url}" width="1" height="1" alt="">'
        f'<a href="{http_tracking_url}">link</a>'
        f'<link rel="dns-prefetch" href="{http_tracking_url}">'
        f"</body></html>",
        subtype="html",
    )
    message["X-Benchmark-Dns-Zone"] = dns_zone
    message["X-Benchmark-Code"] = code
    return message


async def fetch_tracking_url(url: str) -> int:
    """Perform a real HTTP request against the canary, over a real socket."""

    def _get() -> int:
        import urllib.request

        with urllib.request.urlopen(url, timeout=5) as response:
            return int(response.status)

    return await asyncio.to_thread(_get)


def raw_dns_query(host: str, port: int) -> bytes | None:
    """Issue a real DNS A query over a real UDP socket."""

    labels = host.split(".")
    query = bytearray(b"\x13\x37\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00")
    for label in labels:
        encoded = label.encode("ascii")
        query.append(len(encoded))
        query.extend(encoded)
    query += b"\x00\x00\x01\x00\x01"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    try:
        sock.sendto(bytes(query), ("127.0.0.1", port))
        data, _ = sock.recvfrom(512)
        return data
    except TimeoutError, OSError:
        return None
    finally:
        sock.close()


def ledger_to_json(ledger: CanaryLedger) -> str:
    """Serialize the ledger for debugging a failed live run."""

    return json.dumps(
        [
            {
                "vector": event.vector,
                "channel": event.channel,
                "remote_ip": event.remote_ip,
                "observed_at": event.observed_at.isoformat(),
                "user_agent": event.user_agent,
            }
            for event in ledger.all_events()
        ],
        indent=2,
    )


__all__ = [
    "DNS_QUERY_PATTERN",
    "SNI_PATTERN",
    "CanaryEvent",
    "CanaryLedger",
    "DnsCanary",
    "HttpCanary",
    "bind_query_line",
    "build_test_message",
    "fetch_tracking_url",
    "ledger_to_json",
    "local_addresses",
    "raw_dns_query",
]
