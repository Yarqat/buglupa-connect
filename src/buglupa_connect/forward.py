"""Forward one tunnel stream to the local app: the only place the client opens a connection, always to the one
address the person named.

Each stream is one connection from BugLupa's scope proxy. The client reads HTTP/1.1 requests from it, refuses
anything not meant for this tunnel (another Host, an absolute URL naming another host, CONNECT), rewrites the
request so the app sees its own address, sends it to the local app over a fresh connection, and copies the response
back with the response rewrites. After `101 Switching Protocols` (WebSocket) it copies bytes both ways.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import socket
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from . import http1
from .http1 import HttpError, Origins, TooLarge
from .protocol import MuxStream, StreamClosed

BLOCKED = "X-BugLupa-Blocked"
PROXY_ERROR = "X-BugLupa-Proxy-Error"


class TargetError(ValueError):
    """The local address can't be used (not a local or private address, can't be resolved, bad form)."""


@dataclass(frozen=True)
class ForwardLimits:
    connect_s: float = 10.0
    response_head_s: float = 120.0
    idle_s: float = 120.0
    request_bytes: int = 32 * 1024 * 1024
    response_bytes: int = 256 * 1024 * 1024


@dataclass(frozen=True)
class LocalTarget:
    scheme: str
    host: str  # as named, lowercase, no brackets
    port: int
    addresses: tuple[str, ...] = field(default_factory=tuple)  # resolved once at start (pinned)
    insecure_tls: bool = False

    @property
    def authority(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        default = 443 if self.scheme == "https" else 80
        return host if self.port == default else f"{host}:{self.port}"

    @property
    def display(self) -> str:
        return self.authority if self.scheme == "http" else f"{self.scheme}://{self.authority}"

    def aliases(self) -> frozenset[tuple[str, int]]:
        """The (host, port) pairs that are this same door: the named host, and for a loopback target the other
        loopback names on the same port (an app on localhost:3000 often redirects to 127.0.0.1:3000)."""
        names = {(self.host, self.port)}
        if self.addresses and all(ipaddress.ip_address(a).is_loopback for a in self.addresses):
            names |= {("localhost", self.port), ("127.0.0.1", self.port), ("::1", self.port)}
        return frozenset(names)

    def origins(self, tunnel_host: str) -> Origins:
        return Origins(tunnel_host, self.scheme, self.authority, self.aliases())


def _allowed_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if address.is_loopback:
        return True
    # Link-local covers cloud metadata (169.254.169.254); ::1 counts as "reserved", so loopback goes first.
    if address.is_link_local or address.is_multicast or address.is_unspecified or address.is_reserved:
        return False
    return address.is_private


def parse_target(value: str, insecure_tls: bool = False) -> LocalTarget:
    """`3000`, `localhost:3000`, `127.0.0.1:8080`, `[::1]:3000`, `http://localhost:3000`, `https://localhost:8443`."""
    raw = value.strip()
    scheme = "http"
    if "://" in raw:
        scheme, _, raw = raw.partition("://")
        scheme = scheme.lower()
        if scheme not in ("http", "https"):
            raise TargetError("use an http:// or https:// address")
        raw, _, rest = raw.partition("/")
        if rest.strip("/"):
            raise TargetError("name the app's address without a path (the whole app is reachable)")
    if raw.startswith(":"):
        raw = raw[1:]
    if raw.isdigit():
        raw = f"localhost:{raw}"
    parsed = http1.split_authority(raw)
    if parsed is None or not parsed[0]:
        raise TargetError(f"{value!r} isn't an address like localhost:3000")
    host, port = parsed
    if port is None:
        port = 443 if scheme == "https" else 80
    if host in ("0.0.0.0", "::"):  # noqa: S104 - a bind-all address names this computer; connect to loopback
        host = "127.0.0.1" if host == "0.0.0.0" else "::1"  # noqa: S104
    return LocalTarget(scheme, host, port, insecure_tls=insecure_tls)


def resolve_target(target: LocalTarget) -> LocalTarget:
    """Resolve the name once and pin the addresses. Only loopback and private addresses are allowed: the tunnel is
    for apps on this computer or its private network, never for public sites (add those as website targets)."""
    try:
        found = [ipaddress.ip_address(target.host)]
    except ValueError:
        try:
            infos = socket.getaddrinfo(target.host, target.port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise TargetError(f"can't find {target.host} ({exc.strerror})") from exc
        found = []
        for info in infos:
            with contextlib.suppress(ValueError):
                address = ipaddress.ip_address(str(info[4][0]).split("%", 1)[0])
                if address not in found:
                    found.append(address)
    if not found:
        raise TargetError(f"{target.host} has no addresses")
    refused = [str(a) for a in found if not _allowed_address(a)]
    if refused:
        raise TargetError(
            f"{target.host} is not on this computer or a private network ({', '.join(refused[:3])}). "
            "buglupa connect only forwards to local and private apps; add public sites to BugLupa as a website."
        )
    # IPv4 first: "localhost" apps usually listen on 127.0.0.1.
    ordered = sorted(found, key=lambda a: a.version)
    return LocalTarget(target.scheme, target.host, target.port, tuple(str(a) for a in ordered), target.insecure_tls)


async def open_local(target: LocalTarget, limits: ForwardLimits) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    context: ssl.SSLContext | None = None
    if target.scheme == "https":
        context = ssl.create_default_context()
        if target.insecure_tls:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
    errors = []
    for address in target.addresses:
        try:
            return await asyncio.wait_for(
                asyncio.open_connection(
                    address,
                    target.port,
                    ssl=context,
                    server_hostname=target.host if context else None,
                    limit=2**17,
                ),
                limits.connect_s,
            )
        except (OSError, TimeoutError, ssl.SSLError) as exc:
            errors.append(type(exc).__name__ if not isinstance(exc, OSError) or not exc.strerror else exc.strerror)
    raise ConnectionError("; ".join(dict.fromkeys(errors)) or "no address")


@dataclass
class RequestLog:
    method: str
    path: str
    status: int | None
    ms: int
    note: str = ""


LogFn = Callable[[RequestLog], None]
RETRY = -1


def _display_path(target: str) -> str:
    path, sep, _ = target.partition("?")
    path = path if len(path) <= 60 else path[:57] + "..."
    return path + ("?…" if sep else "")


class Forwarder:
    """Serves one stream (one connection from the scope proxy)."""

    def __init__(
        self, stream: MuxStream, target: LocalTarget, tunnel_host: str, limits: ForwardLimits, log: LogFn
    ) -> None:
        self.stream = stream
        self.target = target
        self.origins = target.origins(tunnel_host)
        self.limits = limits
        self.log = log
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None
        self.used = False

    async def connect(self) -> None:
        """(Re)connect to the local app. ConnectionError when it doesn't answer."""
        self.close_local()
        self.reader, self.writer = await open_local(self.target, self.limits)
        self.used = False

    def close_local(self) -> None:
        if self.writer is not None:
            with contextlib.suppress(Exception):
                self.writer.transport.abort()
        self.reader = self.writer = None

    async def _refuse(self, status: int, reason: str, text: str, header: str, code: str) -> None:
        with contextlib.suppress(StreamClosed):
            await self.stream.write(http1.simple_response(status, reason, f"buglupa connect: {text}", [(header, code)]))
            await self.stream.write_eof()

    async def run(self) -> None:
        try:
            while await self._one():
                pass
        except (StreamClosed, ConnectionError, asyncio.IncompleteReadError, TimeoutError, OSError):
            pass
        finally:
            self.close_local()
            if not self.stream.closed.is_set():
                await self.stream.write_eof()

    async def _one(self) -> bool:
        """Forward one request and its response. False when the connection is done."""
        try:
            raw = await http1.read_head(self.stream, self.limits.idle_s)
        except asyncio.IncompleteReadError:
            return False
        except TooLarge:
            await self._refuse(431, "Request Header Fields Too Large", "request head too large", PROXY_ERROR, "tunnel")
            return False
        started = time.monotonic()
        try:
            head = http1.parse_request(raw)
            framing = http1.request_framing(head)
        except HttpError as exc:
            await self._refuse(400, "Bad Request", str(exc), PROXY_ERROR, "tunnel")
            return False
        method, target, version = head.start
        if method == "CONNECT":
            await self._refuse(405, "Method Not Allowed", "CONNECT isn't forwarded", BLOCKED, "tunnel_one_door")
            self.log(RequestLog(method, target[:60], 405, 0, "refused: CONNECT"))
            return False
        if not (target.startswith("/") or (target == "*" and method == "OPTIONS")):
            # Absolute form: only for this tunnel's own origin (then it becomes a path); never another host.
            local = self.origins.to_local(target)
            if local == target or not target.lower().startswith("http://"):
                await self._refuse(421, "Misdirected Request", "this tunnel only reaches one app", BLOCKED,
                                   "tunnel_one_door")  # fmt: skip
                self.log(RequestLog(method, target[:60], 421, 0, "refused: another address"))
                return False
            rest = target[7:]
            cut = min((i for i in (rest.find("/"), rest.find("?")) if i >= 0), default=len(rest))
            target = rest[cut:] or "/"
            if target.startswith("?"):
                target = "/" + target
            head.start = (method, target, version)
        hosts = head.get_all("host")
        if len(hosts) != 1 or not self.origins.is_tunnel_authority(hosts[0]):
            await self._refuse(
                421, "Misdirected Request", "this tunnel only reaches one app", BLOCKED, "tunnel_one_door"
            )
            self.log(RequestLog(method, _display_path(target), 421, 0, "refused: another Host"))
            return False
        if framing.kind == "length" and framing.length > self.limits.request_bytes:
            await self._refuse(413, "Content Too Large", "request body larger than the tunnel allows", PROXY_ERROR,
                               "tunnel_limit")  # fmt: skip
            self.log(RequestLog(method, _display_path(target), 413, 0, "refused: request too large"))
            return False
        upgrade = "upgrade" in head.tokens("connection") and head.get("upgrade") is not None
        keep = version == "HTTP/1.1" and "close" not in head.tokens("connection")
        http1.rewrite_request(head, self.origins)
        request_head = head.serialize()
        # A kept-alive local connection the app closed while idle is replaced; a request without a body is sent
        # again once when the app closed the connection before answering.
        for attempt in (1, 2):
            if self.reader is None or self.writer is None or self.reader.at_eof():
                try:
                    await self.connect()
                except ConnectionError as exc:
                    await self._refuse(502, "Bad Gateway", f"{self.target.display} isn't answering ({exc})",
                                       PROXY_ERROR, "local_app")  # fmt: skip
                    self.log(RequestLog(method, _display_path(target), 502, 0, "the app isn't answering"))
                    return False
            assert self.reader is not None and self.writer is not None
            reused = self.used
            self.used = True
            try:
                self.writer.write(request_head)
                await self.writer.drain()
                await http1.relay_body(self.stream, self._local_write(self.writer), framing, self.limits.idle_s,
                                       self.limits.request_bytes)  # fmt: skip
            except TooLarge:
                self.log(RequestLog(method, _display_path(target), None, 0, "aborted: request too large"))
                await self.stream.reset("request_too_large")
                return False
            except (ConnectionError, OSError):
                if attempt == 1 and reused and framing.kind == "none":
                    self.close_local()
                    continue
                raise
            retry = attempt == 1 and reused and framing.kind == "none"
            status, keep_response = await self._response(method, upgrade, started, target, retry)
            if status == RETRY:
                self.close_local()
                continue
            return keep and keep_response and status is not None and status != 101
        return False

    @staticmethod
    def _local_write(writer: asyncio.StreamWriter):  # type: ignore[no-untyped-def]
        async def write(data: bytes) -> None:
            writer.write(data)
            await writer.drain()

        return write

    async def _response(
        self, method: str, upgrade: bool, started: float, target: str, retry: bool
    ) -> tuple[int | None, bool]:
        """Copy the response back. (RETRY, False) when `retry` is allowed and the app closed a reused connection
        before sending anything."""
        reader, writer = self.reader, self.writer
        assert reader is not None and writer is not None
        path = _display_path(target)
        first = True
        try:
            while True:
                raw = await http1.read_head(reader, self.limits.response_head_s)
                first = False
                head = http1.parse_response(raw)
                status = int(head.start[1])
                if 100 <= status < 200 and status != 101:
                    await self.stream.write(raw)
                    continue
                break
        except (asyncio.IncompleteReadError, TimeoutError, HttpError, ConnectionError) as exc:
            closed_silently = isinstance(exc, ConnectionError) or (
                isinstance(exc, asyncio.IncompleteReadError) and not exc.partial
            )
            if retry and first and closed_silently:
                return RETRY, False
            note = "the app didn't answer in time" if isinstance(exc, TimeoutError) else "the app closed the connection"
            if isinstance(exc, HttpError):
                note = f"the app sent an invalid response ({exc})"
            await self._refuse(502, "Bad Gateway", note, PROXY_ERROR, "local_app")
            self.log(RequestLog(method, path, 502, int((time.monotonic() - started) * 1000), note))
            return None, False
        try:
            framing = http1.response_framing(head, method)
        except HttpError as exc:
            await self._refuse(502, "Bad Gateway", f"the app sent an invalid response ({exc})", PROXY_ERROR,
                               "local_app")  # fmt: skip
            return None, False
        http1.rewrite_response(head, self.origins)
        await self.stream.write(head.serialize())
        if status == 101:
            self.log(RequestLog(method, path, 101, int((time.monotonic() - started) * 1000), "WebSocket"))
            if upgrade:
                await self._pipe(reader, writer)
            return 101, False
        try:
            await http1.relay_body(reader, self.stream.write, framing, self.limits.idle_s, self.limits.response_bytes)
        except TooLarge:
            self.log(
                RequestLog(method, path, status, int((time.monotonic() - started) * 1000), "cut: response too large")
            )
            await self.stream.reset("response_too_large")
            return status, False
        self.log(RequestLog(method, path, status, int((time.monotonic() - started) * 1000)))
        keep = framing.kind != "close" and "close" not in head.tokens("connection")
        if framing.kind == "close":
            await self.stream.write_eof()
        return status, keep

    async def _pipe(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        async def up() -> None:
            with contextlib.suppress(StreamClosed, ConnectionError, OSError, TimeoutError):
                while chunk := await asyncio.wait_for(self.stream.read(65536), self.limits.idle_s * 5):
                    writer.write(chunk)
                    await writer.drain()
            with contextlib.suppress(Exception):
                if writer.can_write_eof():
                    writer.write_eof()

        async def down() -> None:
            with contextlib.suppress(StreamClosed, ConnectionError, OSError, TimeoutError):
                while chunk := await asyncio.wait_for(reader.read(65536), self.limits.idle_s * 5):
                    await self.stream.write(chunk)
            await self.stream.write_eof()

        await asyncio.gather(up(), down())
