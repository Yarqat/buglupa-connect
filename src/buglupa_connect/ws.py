"""A small WebSocket client (RFC 6455) on asyncio streams: the opening handshake over TCP or TLS, masked frames,
fragmented messages, ping/pong and the closing handshake. No extensions (no compression). Client side only: it
connects out and never listens.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import json
import os
import ssl
import struct
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
CONT, TEXT, BINARY, CLOSE, PING, PONG = 0x0, 0x1, 0x2, 0x8, 0x9, 0xA
MAX_HANDSHAKE = 16 * 1024


class WebSocketError(ConnectionError):
    pass


@dataclass(eq=False)
class HandshakeRejected(WebSocketError):
    """The server answered the opening handshake with an HTTP status instead of switching protocols."""

    status: int
    body: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return f"HTTP {self.status}: {self.body.get('message') or self.body.get('error') or 'refused'}"


class ConnectionClosed(WebSocketError):
    def __init__(self, code: int | None, reason: str = "") -> None:
        super().__init__(f"connection closed ({code}{': ' + reason if reason else ''})")
        self.code = code
        self.reason = reason


def _mask(data: bytes, key: bytes) -> bytes:
    if not data:
        return data
    n = len(data)
    repeated = (key * (n // 4 + 1))[:n]
    return (int.from_bytes(data, "little") ^ int.from_bytes(repeated, "little")).to_bytes(n, "little")


def accept_key(key: str) -> str:
    return base64.b64encode(hashlib.sha1((key + GUID).encode("ascii")).digest()).decode("ascii")  # noqa: S324 - RFC 6455


def split_url(url: str) -> tuple[bool, str, int, str]:
    """(tls, host, port, path) of a ws:// or wss:// URL."""
    parts = urlsplit(url)
    if parts.scheme not in ("ws", "wss") or not parts.hostname:
        raise ValueError("the server must be a ws:// or wss:// URL")
    if parts.username or parts.password:
        raise ValueError("the server URL can't contain credentials")
    tls = parts.scheme == "wss"
    port = parts.port or (443 if tls else 80)
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    return tls, parts.hostname, port, path


class WebSocket:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, max_message: int) -> None:
        self.reader = reader
        self.writer = writer
        self.max_message = max_message
        self.subprotocol: str | None = None
        self.close_code: int | None = None
        self.close_reason = ""
        self._close_sent = False
        self._lock = asyncio.Lock()
        self._pong = asyncio.Event()

    # Opening handshake -----------------------------------------------------------------------------------------

    @classmethod
    async def connect(
        cls,
        url: str,
        *,
        headers: dict[str, str],
        subprotocol: str,
        ssl_context: ssl.SSLContext | None = None,
        timeout: float = 15.0,
        max_message: int = 1024 * 1024,
    ) -> WebSocket:
        tls, host, port, path = split_url(url)
        context = (ssl_context or ssl.create_default_context()) if tls else None
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=context, server_hostname=host if tls else None, limit=2**20),
            timeout,
        )
        try:
            key = base64.b64encode(os.urandom(16)).decode("ascii")
            authority = host if ":" not in host else f"[{host}]"
            if port != (443 if tls else 80):
                authority += f":{port}"
            lines = [
                f"GET {path} HTTP/1.1",
                f"Host: {authority}",
                "Upgrade: websocket",
                "Connection: Upgrade",
                f"Sec-WebSocket-Key: {key}",
                "Sec-WebSocket-Version: 13",
                f"Sec-WebSocket-Protocol: {subprotocol}",
                *(f"{k}: {v}" for k, v in headers.items()),
                "",
                "",
            ]
            if any("\r" in line or "\n" in line for line in lines[:-2]):
                raise ValueError("header values can't contain line breaks")
            writer.write("\r\n".join(lines).encode("latin-1"))
            await writer.drain()
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout)
            if len(head) > MAX_HANDSHAKE:
                raise WebSocketError("handshake response too large")
            status_line, *header_lines = head[:-4].decode("latin-1").split("\r\n")
            parts = status_line.split(" ", 2)
            if len(parts) < 2 or not parts[1].isdigit():
                raise WebSocketError("malformed handshake response")
            status = int(parts[1])
            response: dict[str, str] = {}
            for line in header_lines:
                name, _, value = line.partition(":")
                response[name.strip().lower()] = value.strip()
            if status != 101:
                raise HandshakeRejected(status, await cls._error_body(reader, response, timeout))
            if response.get("upgrade", "").lower() != "websocket" or "upgrade" not in response.get(
                "connection", ""
            ).lower().replace(" ", "").split(","):
                raise WebSocketError("the server didn't switch to WebSocket")
            if response.get("sec-websocket-accept") != accept_key(key):
                raise WebSocketError("the server's handshake key doesn't match")
            if response.get("sec-websocket-protocol") != subprotocol:
                raise WebSocketError("the server didn't accept the tunnel protocol")
            if response.get("sec-websocket-extensions"):
                raise WebSocketError("the server asked for an extension this client doesn't support")
        except BaseException:
            writer.transport.abort()
            raise
        ws = cls(reader, writer, max_message)
        ws.subprotocol = subprotocol
        return ws

    @staticmethod
    async def _error_body(reader: asyncio.StreamReader, headers: dict[str, str], timeout: float) -> dict[str, Any]:
        length = headers.get("content-length", "")
        if not length.isdigit() or int(length) > 4096:
            return {}
        try:
            raw = await asyncio.wait_for(reader.readexactly(int(length)), timeout)
            body = json.loads(raw.decode("utf-8"))
        except (asyncio.IncompleteReadError, TimeoutError, ValueError, UnicodeDecodeError):
            return {}
        return body if isinstance(body, dict) else {}

    # Frames ----------------------------------------------------------------------------------------------------

    async def _send_frame(self, opcode: int, payload: bytes) -> None:
        header = bytearray([0x80 | opcode])
        n = len(payload)
        if n < 126:
            header.append(0x80 | n)
        elif n < 2**16:
            header.append(0x80 | 126)
            header += struct.pack("!H", n)
        else:
            header.append(0x80 | 127)
            header += struct.pack("!Q", n)
        key = os.urandom(4)
        async with self._lock:
            if self.writer.is_closing():
                raise ConnectionClosed(self.close_code, self.close_reason or "connection lost")
            self.writer.write(bytes(header) + key + _mask(payload, key))
            await self.writer.drain()

    async def send_binary(self, data: bytes) -> None:
        if self._close_sent:
            raise ConnectionClosed(self.close_code, "closing")
        await self._send_frame(BINARY, data)

    async def send_text(self, text: str) -> None:
        if self._close_sent:
            raise ConnectionClosed(self.close_code, "closing")
        await self._send_frame(TEXT, text.encode("utf-8"))

    async def ping(self, timeout: float) -> bool:
        """Send a ping and wait for any pong. False when none arrives in time."""
        self._pong.clear()
        await self._send_frame(PING, os.urandom(4))
        try:
            await asyncio.wait_for(self._pong.wait(), timeout)
        except TimeoutError:
            return False
        return True

    async def _read_frame(self) -> tuple[bool, int, bytes]:
        first, second = await self.reader.readexactly(2)
        fin, opcode = bool(first & 0x80), first & 0x0F
        if first & 0x70:
            raise ProtocolViolation(1002, "reserved bits set")
        if second & 0x80:
            raise ProtocolViolation(1002, "the server masked a frame")
        n = second & 0x7F
        if n == 126:
            (n,) = struct.unpack("!H", await self.reader.readexactly(2))
        elif n == 127:
            (n,) = struct.unpack("!Q", await self.reader.readexactly(8))
        if opcode >= 0x8 and (n > 125 or not fin):
            raise ProtocolViolation(1002, "invalid control frame")
        if n > self.max_message:
            raise ProtocolViolation(1009, "message too big")
        payload = await self.reader.readexactly(n) if n else b""
        return fin, opcode, payload

    async def recv(self) -> tuple[int, bytes]:
        """The next whole data message, (TEXT or BINARY, payload). Answers pings; raises ConnectionClosed."""
        message = bytearray()
        kind: int | None = None
        while True:
            try:
                fin, opcode, payload = await self._read_frame()
            except (asyncio.IncompleteReadError, ConnectionError, OSError) as exc:
                self.close_code = self.close_code or 1006
                raise ConnectionClosed(1006, "connection lost") from exc
            except ProtocolViolation as exc:
                await self.close(exc.code, exc.reason)
                raise ConnectionClosed(exc.code, exc.reason) from exc
            if opcode == PING:
                with contextlib.suppress(ConnectionError):
                    await self._send_frame(PONG, payload)
                continue
            if opcode == PONG:
                self._pong.set()
                continue
            if opcode == CLOSE:
                code = struct.unpack("!H", payload[:2])[0] if len(payload) >= 2 else 1005
                reason = payload[2:].decode("utf-8", "replace")
                self.close_code, self.close_reason = code, reason
                if not self._close_sent:
                    self._close_sent = True
                    with contextlib.suppress(ConnectionError, OSError):
                        await self._send_frame(CLOSE, payload[:2])
                self.writer.close()
                raise ConnectionClosed(code, reason)
            if opcode in (TEXT, BINARY):
                if kind is not None:
                    await self.close(1002, "new message inside a fragmented one")
                    raise ConnectionClosed(1002, "protocol error")
                kind = opcode
            elif opcode == CONT:
                if kind is None:
                    await self.close(1002, "continuation without a message")
                    raise ConnectionClosed(1002, "protocol error")
            else:
                await self.close(1002, "unknown opcode")
                raise ConnectionClosed(1002, "protocol error")
            message += payload
            if len(message) > self.max_message:
                await self.close(1009, "message too big")
                raise ConnectionClosed(1009, "message too big")
            if fin:
                if kind == TEXT:
                    try:
                        bytes(message).decode("utf-8")
                    except UnicodeDecodeError:
                        await self.close(1007, "invalid UTF-8")
                        raise ConnectionClosed(1007, "invalid UTF-8") from None
                assert kind is not None
                return kind, bytes(message)

    # Closing ---------------------------------------------------------------------------------------------------

    async def close(self, code: int = 1000, reason: str = "", timeout: float = 0.5) -> None:
        """Send a close frame (once) and close the connection without waiting for the server's answer (Ctrl+C must
        end access at once; the server treats a close frame followed by the end of the connection as a close)."""
        if not self._close_sent:
            self._close_sent = True
            payload = struct.pack("!H", code) + reason.encode("utf-8")[:120]
            with contextlib.suppress(ConnectionError, OSError, TimeoutError, RuntimeError):
                await asyncio.wait_for(self._send_frame(CLOSE, payload), timeout)
        self.writer.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(self.writer.wait_closed(), timeout)
        self.abort()

    def abort(self) -> None:
        with contextlib.suppress(Exception):
            self.writer.transport.abort()


class ProtocolViolation(Exception):
    def __init__(self, code: int, reason: str) -> None:
        super().__init__(reason)
        self.code = code
        self.reason = reason
