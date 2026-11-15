"""The tunnel session: one outbound WebSocket to BugLupa's tunnel service, streams multiplexed over it.

- Authenticates with the connect token (an `Authorization` header, never in a URL) and a per-process session secret,
  which lets this same process take its tunnel back after a network drop while a second client is refused.
- Opens no listening socket. The service opens streams; for each one the client connects to the local app and
  forwards (forward.py). A stream the service didn't open is never accepted, and at most `max_streams` run at once.
- Reconnects after network drops with exponential backoff and jitter, until the token expires. Expired or revoked
  tokens, a replaced session and protocol errors end the program.
- `stop()` (Ctrl+C) closes the local connections and the WebSocket at once: BugLupa can't reach the app any more.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import platform
import random
import secrets
import ssl
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from . import __version__
from .forward import Forwarder, ForwardLimits, LocalTarget, RequestLog
from .protocol import (
    CLOSE_CONFLICT,
    CLOSE_EXPIRED,
    CLOSE_REPLACED,
    CLOSE_REVOKED,
    CLOSE_STOPPED,
    CLOSE_VIOLATION,
    CREDIT,
    DATA,
    END,
    FINAL_CLOSE_CODES,
    LOCAL_HEADER,
    OPEN,
    OPEN_OK,
    RESET,
    SESSION_HEADER,
    SUBPROTOCOL,
    WINDOW,
    Limits,
    MuxStream,
    ProtocolError,
    decode,
    encode,
    reason_text,
    reset_frame,
)
from .ws import TEXT, ConnectionClosed, HandshakeRejected, WebSocket

PING_INTERVAL_S = 20.0
PING_TIMEOUT_S = 20.0
WELCOME_TIMEOUT_S = 15.0
BACKOFF_MAX_S = 30.0


class Final(Exception):
    """The session ended for good (exit code and message)."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class Event:
    kind: str  # connected, reconnected, lost, retry, request, local_down, stopped, warning
    message: str = ""
    data: dict[str, Any] = field(default_factory=dict)


EventFn = Callable[[Event], None]


@dataclass
class ClientConfig:
    server: str
    token: str = field(repr=False)
    target: LocalTarget
    max_streams: int = 32
    forward: ForwardLimits = field(default_factory=ForwardLimits)
    ssl_context: ssl.SSLContext | None = None
    connect_timeout_s: float = 15.0


class TunnelClient:
    def __init__(self, config: ClientConfig, on_event: EventFn) -> None:
        self.config = config
        self.emit = on_event
        self.session = secrets.token_urlsafe(32)
        self.stopping = asyncio.Event()
        self.ws: WebSocket | None = None
        self.streams: dict[int, MuxStream] = {}
        self.tasks: set[asyncio.Task[Any]] = set()
        self.forwarders: set[Forwarder] = set()
        self.last_id = 0
        self.limits = Limits(max_streams=config.max_streams)
        self.welcome: dict[str, Any] = {}
        self.expires_at: float | None = None
        self.connected_once = False

    # Lifecycle ---------------------------------------------------------------------------------------------------

    def stop(self) -> None:
        """Ctrl+C: end access now. Local connections are cut first, then the WebSocket is closed."""
        if self.stopping.is_set():
            return
        self.stopping.set()
        for forwarder in list(self.forwarders):
            forwarder.close_local()
        for stream in list(self.streams.values()):
            stream.abort("stopped")
        if self.ws is not None:
            task = asyncio.ensure_future(self._stop_ws(self.ws))
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)

    @staticmethod
    async def _stop_ws(ws: WebSocket) -> None:
        """Tell the service first (it cuts access on this message), then close."""
        with contextlib.suppress(ConnectionError, OSError, TimeoutError, RuntimeError):
            await asyncio.wait_for(ws.send_text('{"type":"stop"}'), 0.3)
        await ws.close(CLOSE_STOPPED, "stopped by the user", timeout=0.3)

    async def run(self) -> int:
        """Connect and serve until stopped or a final error. Returns the exit code."""
        attempt = 0
        try:
            while not self.stopping.is_set():
                if self.expires_at is not None and time.time() >= self.expires_at:
                    raise Final(
                        3, "Your connect token has expired. Create a new one in BugLupa and run the command again."
                    )
                try:
                    ws = await self._connect()
                except HandshakeRejected as exc:
                    self._handshake_final(exc)
                    delay = self._backoff(attempt)
                    attempt += 1
                    self.emit(
                        Event("retry", f"BugLupa is busy or restarting ({exc.status}); retrying in {delay:.0f} s")
                    )
                    await self._sleep(delay)
                    continue
                except (OSError, TimeoutError, ConnectionError) as exc:
                    delay = self._backoff(attempt)
                    attempt += 1
                    what = "reach" if not self.connected_once else "reconnect to"
                    self.emit(Event("retry", f"Can't {what} BugLupa ({_why(exc)}); retrying in {delay:.0f} s"))
                    await self._sleep(delay)
                    continue
                attempt = 0
                code, reason = await self._serve(ws)
                if self.stopping.is_set():
                    break
                if code in FINAL_CLOSE_CODES:
                    raise Final(*_final_message(code, reason))
                delay = self._backoff(0)
                self.emit(Event("lost", f"Connection to BugLupa lost; reconnecting in {delay:.0f} s"))
                await self._sleep(delay)
        except Final as final:
            self.emit(Event("final", final.message, {"code": final.code}))
            return final.code
        finally:
            await self._shutdown()
        self.emit(Event("stopped", f"Stopped. BugLupa can no longer reach {self.config.target.display}."))
        return 0

    async def _sleep(self, seconds: float) -> None:
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self.stopping.wait(), seconds)

    @staticmethod
    def _backoff(attempt: int) -> float:
        base = min(BACKOFF_MAX_S, 1.0 * (2**attempt))
        return base * (0.75 + random.random() * 0.5)  # noqa: S311 - jitter, not security

    def _handshake_final(self, exc: HandshakeRejected) -> None:
        message = str(exc.body.get("message") or "")
        if exc.status == 401:
            raise Final(2, message or "BugLupa didn't accept this connect token. Check that you copied all of it.")
        if exc.status == 403:
            raise Final(3, message or "This connect token has expired or was revoked. Create a new one in BugLupa.")
        if exc.status == 409:
            raise Final(4, message or "This project's tunnel is already connected from another computer or terminal.")
        if exc.status in (400, 404, 426):
            raise Final(2, message or f"BugLupa refused the connection (HTTP {exc.status}). Update buglupa-connect.")

    async def _connect(self) -> WebSocket:
        target = self.config.target
        headers = {
            "Authorization": f"Bearer {self.config.token}",
            SESSION_HEADER: self.session,
            LOCAL_HEADER: target.display,
            "User-Agent": f"buglupa-connect/{__version__} (Python {platform.python_version()}; {sys.platform})",
        }
        ws = await WebSocket.connect(
            self.config.server,
            headers=headers,
            subprotocol=SUBPROTOCOL,
            ssl_context=self.config.ssl_context,
            timeout=self.config.connect_timeout_s,
            max_message=self.limits.max_frame + 64 * 1024,
        )
        try:
            kind, payload = await asyncio.wait_for(ws.recv(), WELCOME_TIMEOUT_S)
            welcome = json.loads(payload) if kind == TEXT else {}
            if not isinstance(welcome, dict) or welcome.get("type") != "welcome" or not welcome.get("tunnel"):
                raise ConnectionError("BugLupa didn't send a welcome")
        except BaseException:
            ws.abort()
            raise
        limits = welcome.get("limits") or {}
        self.limits = Limits(
            max_frame=int(limits.get("max_frame", self.limits.max_frame)),
            window=int(limits.get("window", self.limits.window)),
            max_streams=min(self.config.max_streams, int(limits.get("max_streams", self.config.max_streams))),
        )
        self.welcome = welcome
        expires = welcome.get("expires_at")
        self.expires_at = float(expires) if isinstance(expires, (int, float)) else None
        self.ws = ws
        self.last_id = 0
        self.emit(Event("reconnected" if self.connected_once else "connected", "", dict(welcome)))
        self.connected_once = True
        return ws

    # Serving -----------------------------------------------------------------------------------------------------

    async def _send(self, frame: bytes) -> None:
        ws = self.ws
        if ws is None:
            raise ConnectionError("not connected")
        await ws.send_binary(frame)

    async def _serve(self, ws: WebSocket) -> tuple[int | None, str]:
        pinger = asyncio.ensure_future(self._keepalive(ws))
        try:
            while True:
                try:
                    kind, payload = await ws.recv()
                except ConnectionClosed as closed:
                    return closed.code, closed.reason
                if kind == TEXT:
                    self._control(payload)
                    continue
                try:
                    await self._frame(payload)
                except ProtocolError as exc:
                    await ws.close(CLOSE_VIOLATION, str(exc)[:100])
                    return CLOSE_VIOLATION, str(exc)
        finally:
            pinger.cancel()
            for stream in list(self.streams.values()):
                stream.abort("tunnel closed")
            self.streams.clear()
            for forwarder in list(self.forwarders):
                forwarder.close_local()
            self.ws = None
            ws.abort()

    async def _keepalive(self, ws: WebSocket) -> None:
        with contextlib.suppress(ConnectionError, asyncio.CancelledError):
            while True:
                await asyncio.sleep(PING_INTERVAL_S)
                if not await ws.ping(PING_TIMEOUT_S):
                    ws.abort()  # the read loop sees the connection lost and reconnects
                    return

    def _control(self, payload: bytes) -> None:
        with contextlib.suppress(ValueError):
            message = json.loads(payload)
            if isinstance(message, dict) and message.get("type") == "notice":
                self.emit(Event("warning", str(message.get("message", ""))[:300]))

    async def _frame(self, message: bytes) -> None:
        kind, stream_id, payload = decode(message, self.limits.max_frame)
        if kind == OPEN:
            if stream_id <= self.last_id:
                raise ProtocolError("OPEN for a used stream id")
            self.last_id = stream_id
            if self.stopping.is_set() or len(self.streams) >= self.limits.max_streams:
                await self._send(reset_frame(stream_id, "busy"))
                return
            stream = MuxStream(stream_id, self._send, self.limits)
            self.streams[stream_id] = stream
            self._spawn(self._open(stream))
            return
        stream = self.streams.get(stream_id)
        if stream is None:
            if stream_id > self.last_id:
                raise ProtocolError("frame for a stream that was never opened")
            return  # a stream that just ended
        if kind == DATA:
            stream.on_data(payload)
        elif kind == END:
            stream.on_end()
        elif kind == RESET:
            stream.on_reset(reason_text(payload))
        elif kind == WINDOW:
            stream.on_window(CREDIT.unpack(payload)[0])
        else:
            raise ProtocolError("the service sent a client-only frame")

    def _spawn(self, coro: Any) -> None:
        task = asyncio.ensure_future(coro)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def _open(self, stream: MuxStream) -> None:
        forwarder = Forwarder(stream, self.config.target, str(self.welcome["tunnel"]), self.config.forward, self._log)
        self.forwarders.add(forwarder)
        try:
            try:
                await forwarder.connect()
            except ConnectionError as exc:
                self.emit(
                    Event("local_down", f"{self.config.target.display} isn't answering ({exc}). Is your app running?")
                )
                await stream.reset("local_unreachable")
                return
            try:
                await self._send(encode(OPEN_OK, stream.id))
            except ConnectionError:
                return
            await forwarder.run()
        finally:
            forwarder.close_local()
            self.forwarders.discard(forwarder)
            if self.streams.get(stream.id) is stream:
                del self.streams[stream.id]

    def _log(self, entry: RequestLog) -> None:
        self.emit(Event("request", "", {"method": entry.method, "path": entry.path, "status": entry.status,
                                        "ms": entry.ms, "note": entry.note}))  # fmt: skip

    async def _shutdown(self) -> None:
        for stream in list(self.streams.values()):
            stream.abort("stopped")
        for forwarder in list(self.forwarders):
            forwarder.close_local()
        if self.ws is not None:
            await self.ws.close(CLOSE_STOPPED, "stopped by the user", timeout=0.3)
        for task in list(self.tasks):
            task.cancel()
        if self.tasks:
            await asyncio.wait(list(self.tasks), timeout=0.5)


def _why(exc: BaseException) -> str:
    if isinstance(exc, TimeoutError):
        return "timed out"
    if isinstance(exc, ssl.SSLCertVerificationError):
        return "its certificate couldn't be verified"
    if isinstance(exc, OSError) and exc.strerror:
        return exc.strerror
    return type(exc).__name__


def _final_message(code: int | None, reason: str) -> tuple[int, str]:
    if code == CLOSE_EXPIRED:
        return 3, "Your connect token has expired, so BugLupa closed the tunnel. Create a new one and run again."
    if code == CLOSE_REVOKED:
        return 3, "Your connect token was revoked in BugLupa, so the tunnel is closed."
    if code == CLOSE_REPLACED:
        return 4, "This tunnel was taken over by a newer connection from this program; this one stops."
    if code == CLOSE_CONFLICT:
        return 4, "This project's tunnel is already connected from another computer or terminal."
    return 1, f"BugLupa closed the tunnel because of a protocol error ({reason or code})."
