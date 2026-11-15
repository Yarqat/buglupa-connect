"""Strict HTTP/1.1 heads and bodies for the client (RFC 9112), and the rewrites that make the app see its own address.

Heads are parsed and checked; bodies are copied byte for byte with size caps. Ambiguous messages are refused rather
than guessed at (both Content-Length and Transfer-Encoding, several lengths, codings other than chunked, line folding,
control characters).

Rewrites: requests arrive for BugLupa's tunnel origin (`http://<tunnel host>`). The client sends them to the local
app with `Host` set to the address the person named (for example `localhost:3000`) and rewrites `Origin` and `Referer`
from the tunnel origin to the local origin. In responses, `Location`, `Content-Location`, `Refresh` and
`Access-Control-Allow-Origin` pointing at the local origin are turned back into the tunnel origin, and a cookie
`Domain` naming the local host is dropped (the cookie becomes host-only). Anything that points elsewhere (another
port, another host) is left as it is, so the scanner sees it as out of scope: the tunnel is one door.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Protocol

MAX_HEADERS = 100
MAX_CHUNK_LINE = 4096
_TOKEN = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
_VERSION = re.compile(r"HTTP/1\.[01]")
_BAD_VALUE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")
_ABSOLUTE = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*):(//[^/?#]*)?(.*)$", re.S)


class HttpError(ValueError):
    pass


class TooLarge(HttpError):
    pass


class Reader(Protocol):
    async def read(self, n: int = ...) -> bytes: ...

    async def readexactly(self, n: int) -> bytes: ...

    async def readuntil(self, separator: bytes = ...) -> bytes: ...


Write = Callable[[bytes], Awaitable[None]]


@dataclass
class Head:
    start: tuple[str, str, str]
    headers: list[tuple[str, str]] = field(default_factory=list)

    def get(self, name: str) -> str | None:
        name = name.lower()
        for key, value in self.headers:
            if key.lower() == name:
                return value
        return None

    def get_all(self, name: str) -> list[str]:
        name = name.lower()
        return [value for key, value in self.headers if key.lower() == name]

    def tokens(self, name: str) -> set[str]:
        return {t.strip().lower() for value in self.get_all(name) for t in value.split(",") if t.strip()}

    def replace(self, name: str, value: str | None) -> None:
        """Drop every field with this name and, unless value is None, add one at the first one's place."""
        lowered = name.lower()
        index = next((i for i, (k, _) in enumerate(self.headers) if k.lower() == lowered), len(self.headers))
        self.headers = [(k, v) for k, v in self.headers if k.lower() != lowered]
        if value is not None:
            self.headers.insert(min(index, len(self.headers)), (name, value))

    def serialize(self) -> bytes:
        lines = [" ".join(self.start).rstrip(), *(f"{k}: {v}" for k, v in self.headers), "", ""]
        return "\r\n".join(lines).encode("latin-1")


def _lines(data: bytes) -> list[str]:
    if not data.endswith(b"\r\n\r\n"):
        raise HttpError("incomplete head")
    text = data[:-4].decode("latin-1")
    if "\n" in text.replace("\r\n", ""):
        raise HttpError("bare LF in the head")
    return text.split("\r\n")


def _headers(lines: list[str]) -> list[tuple[str, str]]:
    if len(lines) > MAX_HEADERS:
        raise HttpError("too many header fields")
    out = []
    for line in lines:
        if not line:
            continue
        if line[0] in " \t":
            raise HttpError("obsolete line folding")
        name, sep, value = line.partition(":")
        if not sep or not _TOKEN.fullmatch(name):
            raise HttpError("malformed header field")
        value = value.strip(" \t")
        if _BAD_VALUE.search(value):
            raise HttpError("control character in a header value")
        out.append((name, value))
    return out


def parse_request(data: bytes) -> Head:
    lines = _lines(data)
    parts = lines[0].split(" ")
    if len(parts) != 3 or not _TOKEN.fullmatch(parts[0]) or not parts[1] or not _VERSION.fullmatch(parts[2]):
        raise HttpError("malformed request line")
    if any(ord(c) <= 0x20 or ord(c) == 0x7F for c in parts[1]):
        raise HttpError("control character in the request target")
    return Head((parts[0], parts[1], parts[2]), _headers(lines[1:]))


def parse_response(data: bytes) -> Head:
    lines = _lines(data)
    version, _, rest = lines[0].partition(" ")
    status, _, reason = rest.partition(" ")
    if not _VERSION.fullmatch(version) or len(status) != 3 or not status.isdigit():
        raise HttpError("malformed status line")
    return Head((version, status, reason), _headers(lines[1:]))


@dataclass(frozen=True)
class Framing:
    kind: str  # none, length, chunked, close
    length: int = 0


def request_framing(head: Head) -> Framing:
    te = head.get_all("transfer-encoding")
    cl = head.get_all("content-length")
    if te:
        if cl:
            raise HttpError("both Content-Length and Transfer-Encoding")
        codings = [t.strip().lower() for value in te for t in value.split(",") if t.strip()]
        if codings != ["chunked"] or head.start[2] == "HTTP/1.0":
            raise HttpError("unsupported transfer coding")
        return Framing("chunked")
    if cl:
        if len(cl) != 1 or not cl[0].isdigit() or len(cl[0]) > 15:
            raise HttpError("invalid Content-Length")
        length = int(cl[0])
        return Framing("length", length) if length else Framing("none")
    return Framing("none")


def response_framing(head: Head, method: str) -> Framing:
    status = int(head.start[1])
    if method == "HEAD" or 100 <= status < 200 or status in (204, 304):
        return Framing("none")
    te = head.get_all("transfer-encoding")
    if te:
        codings = [t.strip().lower() for value in te for t in value.split(",") if t.strip()]
        if head.get_all("content-length"):
            raise HttpError("both Content-Length and Transfer-Encoding in the response")
        return Framing("chunked") if codings and codings[-1] == "chunked" else Framing("close")
    cl = head.get_all("content-length")
    if cl:
        values = {v.strip() for value in cl for v in value.split(",")}
        if len(values) != 1 or not next(iter(values)).isdigit() or len(next(iter(values))) > 15:
            raise HttpError("invalid Content-Length in the response")
        length = int(values.pop())
        return Framing("length", length) if length else Framing("none")
    return Framing("close")


async def read_head(reader: Reader, timeout: float) -> bytes:
    """One head. IncompleteReadError at a clean end, HttpError when too big."""
    try:
        return await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout)
    except asyncio.LimitOverrunError as exc:
        raise TooLarge("head too large") from exc


async def relay_body(reader: Reader, write: Write, framing: Framing, idle: float, cap: int) -> int:
    """Copy one body as is (chunk framing included). TooLarge once more than `cap` body bytes passed."""
    total = 0

    def count(n: int) -> None:
        nonlocal total
        total += n
        if total > cap:
            raise TooLarge("body larger than the limit")

    if framing.kind == "none":
        return 0
    if framing.kind == "length":
        if framing.length > cap:
            raise TooLarge("body larger than the limit")
        remaining = framing.length
        while remaining:
            chunk = await asyncio.wait_for(reader.read(min(65536, remaining)), idle)
            if not chunk:
                raise asyncio.IncompleteReadError(b"", remaining)
            count(len(chunk))
            await write(chunk)
            remaining -= len(chunk)
        return total
    if framing.kind == "close":
        while chunk := await asyncio.wait_for(reader.read(65536), idle):
            count(len(chunk))
            await write(chunk)
        return total
    while True:
        line = await asyncio.wait_for(reader.readuntil(b"\r\n"), idle)
        if len(line) > MAX_CHUNK_LINE:
            raise HttpError("chunk size line too long")
        size_text = line[:-2].split(b";", 1)[0].strip()
        if not size_text or len(size_text) > 15 or any(c not in b"0123456789abcdefABCDEF" for c in size_text):
            raise HttpError("invalid chunk size")
        size = int(size_text, 16)
        count(size)
        await write(line)
        if size == 0:
            while True:
                trailer = await asyncio.wait_for(reader.readuntil(b"\r\n"), idle)
                if len(trailer) > MAX_CHUNK_LINE:
                    raise HttpError("trailer line too long")
                await write(trailer)
                if trailer == b"\r\n":
                    return total
        remaining = size
        while remaining:
            chunk = await asyncio.wait_for(reader.read(min(65536, remaining)), idle)
            if not chunk:
                raise asyncio.IncompleteReadError(b"", remaining)
            await write(chunk)
            remaining -= len(chunk)
        end = await asyncio.wait_for(reader.readexactly(2), idle)
        if end != b"\r\n":
            raise HttpError("chunk data not followed by CRLF")
        await write(end)


def simple_response(status: int, reason: str, text: str, headers: list[tuple[str, str]] | None = None) -> bytes:
    body = (text + "\n").encode("utf-8")
    head = Head(
        ("HTTP/1.1", str(status), reason),
        [
            ("Content-Type", "text/plain; charset=utf-8"),
            ("Content-Length", str(len(body))),
            ("Cache-Control", "no-store"),
            ("Connection", "close"),
            *(headers or []),
        ],
    )
    return head.serialize() + body


# Rewrites ------------------------------------------------------------------------------------------------------


def _default_port(scheme: str) -> int:
    return 443 if scheme.lower() in ("https", "wss") else 80


def split_authority(authority: str) -> tuple[str, int | None] | None:
    """("host", port or None) of an authority, lowercase host without brackets; None if it can't be read."""
    authority = authority.strip()
    if not authority or "@" in authority:
        return None
    if authority.startswith("["):
        end = authority.find("]")
        if end < 0:
            return None
        host, rest = authority[1:end], authority[end + 1 :]
        if rest and not rest.startswith(":"):
            return None
        port_text = rest[1:] if rest else ""
    else:
        host, _, port_text = authority.partition(":")
        if ":" in port_text:
            return None
    if port_text and (not port_text.isdigit() or not 0 < int(port_text) < 65536):
        return None
    return host.lower().rstrip("."), int(port_text) if port_text else None


@dataclass(frozen=True)
class Origins:
    """The tunnel's public side and the local app's side of one tunnel."""

    tunnel_host: str  # e.g. tabcd….tunnel.invalid (always plain HTTP on port 80 for the scanner)
    local_scheme: str  # http or https
    local_authority: str  # what the person named, e.g. localhost:3000
    local_aliases: frozenset[tuple[str, int]]  # (host, port) pairs that are the same door

    @property
    def tunnel_origin(self) -> str:
        return f"http://{self.tunnel_host}"

    @property
    def local_origin(self) -> str:
        return f"{self.local_scheme}://{self.local_authority}"

    def is_tunnel_authority(self, authority: str) -> bool:
        parsed = split_authority(authority)
        return parsed is not None and parsed[0] == self.tunnel_host and parsed[1] in (None, 80)

    def is_local(self, scheme: str, authority: str) -> bool:
        parsed = split_authority(authority)
        if parsed is None or scheme.lower() not in ("http", "https", "ws", "wss"):
            return False
        secure = scheme.lower() in ("https", "wss")
        if secure != (self.local_scheme == "https"):
            return False
        host, port = parsed
        return (host, port or _default_port(scheme)) in self.local_aliases

    def to_local(self, url: str) -> str:
        """A URL on the tunnel origin, as the same URL on the local origin; anything else unchanged."""
        match = _ABSOLUTE.match(url)
        if not match or match.group(1).lower() not in ("http", "ws") or not match.group(2):
            return url
        if not self.is_tunnel_authority(match.group(2)[2:]):
            return url
        scheme = (
            self.local_scheme if match.group(1).lower() == "http" else ("wss" if self.local_scheme == "https" else "ws")
        )
        return f"{scheme}://{self.local_authority}{match.group(3)}"

    def to_tunnel(self, url: str) -> str:
        """A URL on the local origin (or a same-door alias), as the same URL on the tunnel origin; else unchanged."""
        stripped = url.strip()
        if stripped.startswith("//"):
            if self.is_local(self.local_scheme, stripped[2:].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]):
                rest = stripped[2:]
                cut = min((i for i in (rest.find("/"), rest.find("?"), rest.find("#")) if i >= 0), default=len(rest))
                return f"//{self.tunnel_host}{rest[cut:]}"
            return url
        match = _ABSOLUTE.match(stripped)
        if not match or not match.group(2):
            return url
        scheme = match.group(1)
        if not self.is_local(scheme, match.group(2)[2:]):
            return url
        public = "ws" if scheme.lower() in ("ws", "wss") else "http"
        return f"{public}://{self.tunnel_host}{match.group(3)}"


def rewrite_request(head: Head, origins: Origins) -> None:
    head.replace("Host", origins.local_authority)
    origin = head.get("origin")
    if origin is not None and origin.strip().lower() == origins.tunnel_origin:
        head.replace("Origin", origins.local_origin)
    referer = head.get("referer")
    if referer is not None:
        head.replace("Referer", origins.to_local(referer))


_REFRESH = re.compile(r"^(\s*\d+\s*;\s*url\s*=\s*)(.+)$", re.I)
_COOKIE_DOMAIN = re.compile(r";\s*domain\s*=\s*([^;]*)", re.I)


def rewrite_response(head: Head, origins: Origins) -> None:
    for name in ("Location", "Content-Location"):
        value = head.get(name)
        if value is not None:
            head.replace(name, origins.to_tunnel(value))
    refresh = head.get("refresh")
    if refresh is not None:
        match = _REFRESH.match(refresh)
        if match:
            head.replace("Refresh", match.group(1) + origins.to_tunnel(match.group(2).strip("'\" ")))
    acao = head.get("access-control-allow-origin")
    if acao is not None and origins.is_local(*_scheme_and_authority(acao)):
        head.replace("Access-Control-Allow-Origin", origins.tunnel_origin)
    local_hosts = {host for host, _ in origins.local_aliases}
    cookies = []
    for key, value in head.headers:
        if key.lower() == "set-cookie":
            value = _COOKIE_DOMAIN.sub(
                lambda m: "" if m.group(1).strip().lstrip(".").lower() in local_hosts else m.group(0), value
            )
        cookies.append((key, value))
    head.headers = cookies


def _scheme_and_authority(origin: str) -> tuple[str, str]:
    scheme, sep, rest = origin.strip().partition("://")
    return (scheme, rest.split("/", 1)[0]) if sep else ("", "")
