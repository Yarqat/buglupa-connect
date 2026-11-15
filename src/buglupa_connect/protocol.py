"""The tunnel's wire protocol, `buglupa-tunnel.v1`, shared by the client and BugLupa Cloud's tunnel service.

One WebSocket carries many streams. Each stream is one TCP-like byte stream between the scope proxy (on BugLupa's
side) and the client, which forwards it to the customer's app. Only the tunnel service opens streams; the client
never can. Text messages are JSON control messages (`welcome` from the service). Binary messages are frames:

    kind (1 byte) | stream id (4 bytes, big endian) | payload

| Kind | Who sends | Payload |
|---|---|---|
| OPEN | service | JSON metadata (may be empty) |
| OPEN_OK | client | none: the client reached the local app |
| DATA | both | bytes, at most `max_frame` |
| END | both | none: no more data in this direction |
| RESET | both | UTF-8 reason code: the stream is aborted |
| WINDOW | both | 4-byte credit increment |

Flow control: each direction of each stream starts with `window` bytes of credit. A sender may not send more DATA
than the credit the receiver granted; the receiver grants credit as its consumer reads. A receiver never buffers more
than `window` bytes per stream, so a slow or hostile peer can't make the other side hold unbounded data.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import struct
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

SUBPROTOCOL = "buglupa-tunnel.v1"
CONNECT_PATH = "/v1/connect"

OPEN, OPEN_OK, DATA, END, RESET, WINDOW = 1, 2, 3, 4, 5, 6
KINDS = {OPEN: "OPEN", OPEN_OK: "OPEN_OK", DATA: "DATA", END: "END", RESET: "RESET", WINDOW: "WINDOW"}
HEADER = struct.Struct("!BI")
CREDIT = struct.Struct("!I")
MAX_STREAM_ID = 2**32 - 1
MAX_REASON = 200
MAX_WINDOW = 2**30

# WebSocket close codes. 1000 from the client means the person stopped it (Ctrl+C).
CLOSE_STOPPED = 1000
CLOSE_GOING_AWAY = 1001
CLOSE_EXPIRED = 4001
CLOSE_REVOKED = 4003
CLOSE_VIOLATION = 4008
CLOSE_REPLACED = 4009
CLOSE_CONFLICT = 4010
# The client doesn't reconnect after these: a new token or a person's decision is needed.
FINAL_CLOSE_CODES = frozenset({CLOSE_EXPIRED, CLOSE_REVOKED, CLOSE_VIOLATION, CLOSE_REPLACED, CLOSE_CONFLICT})

# Request headers of the WebSocket handshake.
SESSION_HEADER = "X-BugLupa-Session"
LOCAL_HEADER = "X-BugLupa-Local"


class ProtocolError(ValueError):
    """The peer broke the protocol (malformed frame, flow-control violation, frame for a stream it can't use)."""


class StreamClosed(ConnectionError):
    """The stream was reset (by either side) or written after its end."""


@dataclass(frozen=True)
class Limits:
    max_frame: int = 64 * 1024
    window: int = 256 * 1024
    max_streams: int = 32
    head_limit: int = 64 * 1024

    def as_dict(self) -> dict[str, int]:
        return {"max_frame": self.max_frame, "window": self.window, "max_streams": self.max_streams}


def encode(kind: int, stream: int, payload: bytes = b"") -> bytes:
    if kind not in KINDS or not 0 < stream <= MAX_STREAM_ID:
        raise ValueError("invalid frame")
    return HEADER.pack(kind, stream) + payload


def decode(message: bytes, max_payload: int) -> tuple[int, int, bytes]:
    if len(message) < HEADER.size:
        raise ProtocolError("frame too short")
    kind, stream = HEADER.unpack_from(message)
    payload = message[HEADER.size :]
    if kind not in KINDS:
        raise ProtocolError(f"unknown frame kind {kind}")
    if stream == 0:
        raise ProtocolError("stream id 0")
    if len(payload) > max_payload:
        raise ProtocolError("frame payload too large")
    if kind in (OPEN_OK, END) and payload:
        raise ProtocolError(f"{KINDS[kind]} carries no payload")
    if kind == WINDOW and len(payload) != CREDIT.size:
        raise ProtocolError("WINDOW needs a 4-byte increment")
    if kind == RESET and len(payload) > MAX_REASON:
        raise ProtocolError("RESET reason too long")
    return kind, stream, payload


def window_frame(stream: int, increment: int) -> bytes:
    return encode(WINDOW, stream, CREDIT.pack(increment))


def reset_frame(stream: int, reason: str) -> bytes:
    return encode(RESET, stream, reason.encode("utf-8", "replace")[:MAX_REASON])


def open_frame(stream: int, meta: dict[str, Any] | None = None) -> bytes:
    return encode(OPEN, stream, json.dumps(meta or {}, separators=(",", ":")).encode())


def reason_text(payload: bytes) -> str:
    return payload.decode("utf-8", "replace") or "reset"


Send = Callable[[bytes], Awaitable[None]]


class MuxStream:
    """One stream of the tunnel, seen from one side: a reader and a writer with credit-based flow control.

    The side that owns the WebSocket feeds received frames in with `on_*` (never blocking); the consumer reads with
    `read`, `readexactly` or `readuntil` (credit goes back to the peer as data is consumed) and writes with `write`
    (waits for credit). A reset from either side wakes every waiter with `StreamClosed`.
    """

    def __init__(self, stream_id: int, send: Send, limits: Limits) -> None:
        self.id = stream_id
        self._send = send
        self.limits = limits
        self._buffer = bytearray()
        self._eof = False
        self._reset: str | None = None
        self._readable = asyncio.Event()
        self._recv_allowed = limits.window
        self._credit_owed = 0
        self._send_window = limits.window
        self._writable = asyncio.Event()
        self._writable.set()
        self._sent_end = False
        self.closed = asyncio.Event()
        self.bytes_in = 0
        self.bytes_out = 0

    # Frames from the peer --------------------------------------------------------------------------------------

    def on_data(self, payload: bytes) -> None:
        if self._reset is not None:
            return  # in flight when the stream was reset; dropped
        if self._eof:
            raise ProtocolError("DATA after END")
        if len(payload) > self._recv_allowed:
            raise ProtocolError("DATA beyond the flow-control window")
        self._recv_allowed -= len(payload)
        self._buffer += payload
        self.bytes_in += len(payload)
        self._readable.set()

    def on_end(self) -> None:
        if self._reset is not None:
            return
        self._eof = True
        self._readable.set()
        self._check_closed()

    def on_reset(self, reason: str) -> None:
        self._mark_reset(reason or "reset")

    def on_window(self, increment: int) -> None:
        if self._reset is not None:
            return
        if increment <= 0 or self._send_window + increment > MAX_WINDOW:
            raise ProtocolError("invalid WINDOW increment")
        self._send_window += increment
        self._writable.set()

    # Reading ---------------------------------------------------------------------------------------------------

    @property
    def reset_reason(self) -> str | None:
        return self._reset

    def at_eof(self) -> bool:
        return self._eof and not self._buffer

    async def _wait_readable(self) -> None:
        self._readable.clear()
        await self._readable.wait()

    def _raise_if_reset(self) -> None:
        if self._reset is not None:
            raise StreamClosed(self._reset)

    async def _take(self, n: int) -> bytes:
        data = bytes(self._buffer[:n])
        del self._buffer[:n]
        self._credit_owed += len(data)
        if self._credit_owed >= self.limits.window // 2 and not self._eof:
            credit, self._credit_owed = self._credit_owed, 0
            self._recv_allowed += credit
            try:
                await self._send(window_frame(self.id, credit))
            except Exception as exc:
                self._mark_reset("tunnel closed")
                raise StreamClosed("tunnel closed") from exc
        return data

    async def read(self, n: int = 65536) -> bytes:
        """Up to n bytes; b"" at the end of the stream."""
        while not self._buffer:
            self._raise_if_reset()
            if self._eof:
                return b""
            await self._wait_readable()
        self._raise_if_reset()
        return await self._take(n)

    async def readexactly(self, n: int) -> bytes:
        while len(self._buffer) < n:
            self._raise_if_reset()
            if self._eof:
                partial = bytes(self._buffer)
                raise asyncio.IncompleteReadError(partial, n)
            await self._wait_readable()
        self._raise_if_reset()
        return await self._take(n)

    async def readuntil(self, separator: bytes = b"\n") -> bytes:
        """Like asyncio.StreamReader.readuntil, with `limits.head_limit` as the limit."""
        start = 0
        while True:
            self._raise_if_reset()
            index = self._buffer.find(separator, start)
            if index >= 0:
                end = index + len(separator)
                if end > self.limits.head_limit:
                    raise asyncio.LimitOverrunError("separator found beyond the limit", end)
                return await self._take(end)
            if len(self._buffer) > self.limits.head_limit:
                raise asyncio.LimitOverrunError("limit exceeded before the separator", len(self._buffer))
            if self._eof:
                raise asyncio.IncompleteReadError(bytes(self._buffer), None)
            start = max(0, len(self._buffer) - len(separator) + 1)
            await self._wait_readable()

    # Writing ---------------------------------------------------------------------------------------------------

    async def write(self, data: bytes) -> None:
        view = memoryview(data)
        while view:
            self._raise_if_reset()
            if self._sent_end:
                raise StreamClosed("write after END")
            while self._send_window <= 0:
                self._writable.clear()
                await self._writable.wait()
                self._raise_if_reset()
            n = min(len(view), self._send_window, self.limits.max_frame)
            chunk = bytes(view[:n])
            view = view[n:]
            self._send_window -= n
            try:
                await self._send(encode(DATA, self.id, chunk))
            except Exception as exc:
                self._mark_reset("tunnel closed")
                raise StreamClosed("tunnel closed") from exc
            self.bytes_out += n

    async def write_eof(self) -> None:
        if self._sent_end or self._reset is not None:
            return
        self._sent_end = True
        try:
            await self._send(encode(END, self.id))
        except Exception:
            self._mark_reset("tunnel closed")
            return
        self._check_closed()

    async def reset(self, reason: str = "reset") -> None:
        """Abort the stream and tell the peer (once)."""
        if self._reset is not None:
            return
        self._mark_reset(reason)
        with contextlib.suppress(Exception):  # the tunnel is gone; nothing to tell
            await self._send(reset_frame(self.id, reason))

    def abort(self, reason: str) -> None:
        """Mark the stream reset without telling the peer (the tunnel itself is gone)."""
        self._mark_reset(reason)

    def _mark_reset(self, reason: str) -> None:
        if self._reset is None:
            self._reset = reason
        self._readable.set()
        self._writable.set()
        self.closed.set()

    def _check_closed(self) -> None:
        if self._eof and self._sent_end:
            self.closed.set()
