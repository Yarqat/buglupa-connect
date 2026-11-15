"""HTTP parsing and the rewrites that make the app see its own address while the scanner sees the tunnel's."""

from __future__ import annotations

import asyncio

import pytest

from buglupa_connect import http1
from buglupa_connect.forward import LocalTarget
from buglupa_connect.http1 import HttpError, TooLarge

TUNNEL = "t" + "a" * 20 + ".tunnel.invalid"


def origins(host: str = "localhost", port: int = 3000, scheme: str = "http") -> http1.Origins:
    addresses = ("127.0.0.1",) if host in ("localhost", "127.0.0.1") else ("10.0.0.5",)
    return LocalTarget(scheme, host, port, addresses).origins(TUNNEL)


def test_request_rewrites():
    head = http1.parse_request(
        f"POST /x HTTP/1.1\r\nHost: {TUNNEL}\r\nOrigin: http://{TUNNEL}\r\nReferer: http://{TUNNEL}/a?b=1\r\n\r\n".encode()
    )
    http1.rewrite_request(head, origins())
    assert head.get("host") == "localhost:3000"
    assert head.get("origin") == "http://localhost:3000"
    assert head.get("referer") == "http://localhost:3000/a?b=1"
    other = http1.parse_request(b"GET / HTTP/1.1\r\nHost: x\r\nOrigin: http://evil.example\r\n\r\n")
    http1.rewrite_request(other, origins())
    assert other.get("origin") == "http://evil.example"  # not ours: left alone


def test_response_rewrites_stay_on_one_door():
    o = origins()
    assert o.to_tunnel("http://localhost:3000/login?next=/") == f"http://{TUNNEL}/login?next=/"
    assert o.to_tunnel("http://127.0.0.1:3000/x") == f"http://{TUNNEL}/x"  # loopback alias, same port
    assert o.to_tunnel("//localhost:3000/x") == f"//{TUNNEL}/x"
    assert o.to_tunnel("ws://localhost:3000/socket") == f"ws://{TUNNEL}/socket"
    for unchanged in (
        "http://localhost:8080/admin",  # another port
        "https://localhost:3000/",  # another scheme
        "http://evil.example/",
        "/relative",
        "http://localhost:3000@evil.example/",
    ):
        assert o.to_tunnel(unchanged) == unchanged
    lan = origins("10.0.0.5", 8000)
    assert lan.to_tunnel("http://127.0.0.1:8000/") == "http://127.0.0.1:8000/"  # only loopback targets get aliases
    head = http1.parse_response(
        b"HTTP/1.1 302 Found\r\nLocation: http://localhost:3000/next\r\n"
        b"Set-Cookie: sid=1; Domain=localhost; Path=/\r\nSet-Cookie: a=2; domain=.LOCALHOST\r\n"
        b"Set-Cookie: c=3; Domain=example.com\r\nRefresh: 5; url=http://localhost:3000/r\r\n"
        b"Access-Control-Allow-Origin: http://localhost:3000\r\n\r\n"
    )
    http1.rewrite_response(head, o)
    assert head.get("location") == f"http://{TUNNEL}/next"
    assert head.get_all("set-cookie") == ["sid=1; Path=/", "a=2", "c=3; Domain=example.com"]
    assert head.get("refresh") == f"5; url=http://{TUNNEL}/r"
    assert head.get("access-control-allow-origin") == f"http://{TUNNEL}"


def test_ambiguous_messages_are_refused():
    for raw in (
        b"GET / HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"GET / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n",
        b"GET / HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n",
    ):
        with pytest.raises(HttpError):
            http1.request_framing(http1.parse_request(raw))
    for raw in (b"GET / HTTP/1.1\r\n folded\r\n\r\n", b"GET / HTTP/1.1\nHost: x\r\n\r\n", b"GET  / HTTP/1.1\r\n\r\n"):
        with pytest.raises(HttpError):
            http1.parse_request(raw)
    with pytest.raises(HttpError):
        http1.response_framing(http1.parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 1, 2\r\n\r\n"), "GET")


async def test_body_caps():
    async def collect(chunks: list[bytes], data: bytes) -> None:
        chunks.append(data)

    reader = asyncio.StreamReader()
    reader.feed_data(b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
    out: list[bytes] = []
    assert await http1.relay_body(reader, lambda d: collect(out, d), http1.Framing("chunked"), 1, 100) == 11
    assert b"".join(out) == b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
    reader = asyncio.StreamReader()
    reader.feed_data(b"ff\r\n" + b"x" * 255 + b"\r\n0\r\n\r\n")
    with pytest.raises(TooLarge):
        await http1.relay_body(reader, lambda d: collect([], d), http1.Framing("chunked"), 1, 100)
    with pytest.raises(TooLarge):
        await http1.relay_body(asyncio.StreamReader(), lambda d: collect([], d), http1.Framing("length", 101), 1, 100)
