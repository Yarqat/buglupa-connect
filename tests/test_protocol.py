"""The tunnel's frames and per-stream flow control."""

from __future__ import annotations

import asyncio

import pytest

from buglupa_connect.protocol import (
    DATA,
    END,
    OPEN_OK,
    WINDOW,
    Limits,
    MuxStream,
    ProtocolError,
    StreamClosed,
    decode,
    encode,
    reset_frame,
    window_frame,
)


def test_frames_round_trip_and_bad_frames_are_refused():
    assert decode(encode(DATA, 7, b"abc"), 10) == (DATA, 7, b"abc")
    assert decode(window_frame(3, 1024), 10)[0] == WINDOW
    for bad in (
        b"\x03\x00",  # too short
        b"\x09\x00\x00\x00\x01",  # unknown kind
        b"\x03\x00\x00\x00\x00x",  # stream 0
        encode(DATA, 1, b"x" * 11),  # larger than allowed
        encode(OPEN_OK, 1) + b"x",  # OPEN_OK carries nothing
        encode(END, 1) + b"x",
        b"\x06\x00\x00\x00\x01\x00",  # WINDOW without 4 bytes
        reset_frame(1, "r") + b"x" * 300,
    ):
        with pytest.raises(ProtocolError):
            decode(bad, 10)
    with pytest.raises(ValueError):
        encode(DATA, 0)


class Pipe:
    """Two MuxStreams joined back to back, frames delivered in order (what the WebSocket does)."""

    def __init__(self, limits: Limits) -> None:
        self.a = MuxStream(1, self._to_b, limits)
        self.b = MuxStream(1, self._to_a, limits)
        self.sent: list[bytes] = []

    async def _to_b(self, frame: bytes) -> None:
        self.sent.append(frame)
        self._deliver(self.b, frame)

    async def _to_a(self, frame: bytes) -> None:
        self._deliver(self.a, frame)

    @staticmethod
    def _deliver(stream: MuxStream, frame: bytes) -> None:
        kind, _, payload = decode(frame, 1 << 20)
        if kind == DATA:
            stream.on_data(payload)
        elif kind == END:
            stream.on_end()
        elif kind == WINDOW:
            stream.on_window(int.from_bytes(payload, "big"))
        else:
            stream.on_reset(payload.decode())


async def test_a_writer_waits_for_credit_and_the_reader_grants_it():
    pipe = Pipe(Limits(max_frame=1000, window=4000))
    writer = asyncio.ensure_future(pipe.a.write(b"x" * 10_000))
    await asyncio.sleep(0.05)
    assert not writer.done() and pipe.a.bytes_out == 4000  # blocked at the window
    received = b""
    while len(received) < 10_000:
        received += await pipe.b.read(1500)
    await asyncio.wait_for(writer, 2)
    assert received == b"x" * 10_000
    assert max(len(f) for f in pipe.sent if f[0] == DATA) <= 1000 + 5
    await pipe.a.write_eof()
    assert await pipe.b.read() == b""


async def test_data_beyond_the_window_is_a_protocol_error():
    stream = MuxStream(1, _discard, Limits(window=100))
    stream.on_data(b"x" * 100)
    with pytest.raises(ProtocolError):
        stream.on_data(b"y")
    stream.on_end()
    with pytest.raises(ProtocolError):
        MuxStream(1, _discard, Limits()).on_window(0)


async def test_readuntil_respects_the_head_limit_and_reset_wakes_readers():
    stream = MuxStream(1, _discard, Limits(window=1 << 20, head_limit=64))
    stream.on_data(b"GET / HTTP/1.1\r\n\r\nrest")
    assert await stream.readuntil(b"\r\n\r\n") == b"GET / HTTP/1.1\r\n\r\n"
    stream.on_data(b"x" * 100)
    with pytest.raises(asyncio.LimitOverrunError):
        await stream.readuntil(b"\r\n\r\n")
    waiting = MuxStream(2, _discard, Limits())
    reader = asyncio.ensure_future(waiting.read())
    await asyncio.sleep(0)
    waiting.on_reset("gone")
    with pytest.raises(StreamClosed):
        await reader
    with pytest.raises(StreamClosed):
        await waiting.write(b"x")


async def _discard(frame: bytes) -> None:
    return None
