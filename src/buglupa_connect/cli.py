"""`buglupa connect localhost:3000` (also `buglupa-connect localhost:3000`).

The connect token comes from the BUGLUPA_CONNECT_TOKEN environment variable, a file (`--token-file`) or a hidden
prompt; never from the command line, where other users of the computer could see it.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import datetime as dt
import getpass
import ipaddress
import os
import signal
import sys
from pathlib import Path
from typing import TextIO
from urllib.parse import urlsplit

from . import __version__
from .client import ClientConfig, Event, TunnelClient
from .forward import TargetError, parse_target, resolve_target
from .ws import split_url

DEFAULT_SERVER = "wss://tunnel.buglupa.com/v1/connect"
TOKEN_ENV = "BUGLUPA_CONNECT_TOKEN"  # noqa: S105 - the variable's name, not a secret
SERVER_ENV = "BUGLUPA_CONNECT_SERVER"
TOKEN_PREFIX = "blct_"  # noqa: S105 - the token format's prefix


class Output:
    """The terminal view: a short status, then one line per request."""

    def __init__(self, stream: TextIO, color: bool, quiet: bool = False) -> None:
        self.stream = stream
        self.color = color
        self.quiet = quiet
        encoding = (getattr(stream, "encoding", None) or "ascii").lower()
        fancy = encoding.replace("-", "") in ("utf8", "utf16", "utf32")
        self.ok, self.bad, self.warn = ("✓", "✗", "!") if fancy else ("OK", "X", "!")

    def _paint(self, text: str, code: str) -> str:
        return f"\x1b[{code}m{text}\x1b[0m" if self.color else text

    def line(self, text: str = "") -> None:
        with contextlib.suppress(OSError, ValueError):
            print(text, file=self.stream, flush=True)

    def event(self, event: Event, target: str) -> None:
        if event.kind in ("connected", "reconnected"):
            data = event.data
            project = data.get("project") or "your project"
            if event.kind == "connected":
                self.line(f'{self._paint(self.ok, "32")} Connected to BugLupa as "{project}" (project token)')
                self.line("  Only BugLupa's scanner can reach this. Press Ctrl+C to stop.")
                expires = data.get("expires_at")
                if isinstance(expires, (int, float)):
                    until = dt.datetime.fromtimestamp(expires).strftime("%H:%M")
                    self.line(self._paint(f"  Forwarding to {target}. The token is valid until {until}.", "2"))
            else:
                self.line(f"{self._paint(self.ok, '32')} Reconnected to BugLupa")
        elif event.kind == "request":
            if not self.quiet:
                self.request(event.data)
        elif event.kind in ("retry", "lost", "warning", "local_down"):
            self.line(f"{self._paint(self.warn, '33')} {event.message}")
        elif event.kind == "final":
            self.line(f"{self._paint(self.bad, '31')} {event.message}")
        elif event.kind == "stopped":
            self.line(event.message)

    def request(self, data: dict[str, object]) -> None:
        method = str(data.get("method", ""))[:7]
        path = str(data.get("path", ""))
        status = data.get("status")
        ms = data.get("ms", 0)
        shown = f"{status}" if status else "---"
        if self.color and isinstance(status, int):
            code = "32" if status < 300 else "36" if status < 400 else "33" if status < 500 else "31"
            shown = self._paint(shown, code)
        note = f"  {data['note']}" if data.get("note") else ""
        self.line(f"  {method:<5}{path:<12} {shown:>3} {ms:>4} ms{note}")


def read_token(token_file: str | None, stdin_tty: bool) -> str:
    if token_file:
        path = Path(token_file).expanduser()
        try:
            token = path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise SystemExit(f"buglupa connect: can't read the token file {path} ({exc.strerror})") from exc
    elif os.environ.get(TOKEN_ENV, "").strip():
        token = os.environ[TOKEN_ENV].strip()
    elif stdin_tty:
        token = getpass.getpass("Connect token (from BugLupa; hidden): ").strip()
    else:
        raise SystemExit(f"buglupa connect: set {TOKEN_ENV} or use --token-file (the token is never an argument)")
    if not token.startswith(TOKEN_PREFIX) or len(token) < 40 or any(c.isspace() for c in token):
        raise SystemExit("buglupa connect: that isn't a BugLupa connect token (it starts with blct_)")
    return token


def check_server(url: str) -> str:
    try:
        tls, host, _, _ = split_url(url)
    except ValueError as exc:
        raise SystemExit(f"buglupa connect: {exc}") from exc
    if not tls:
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = host == "localhost"
        if not loopback:
            raise SystemExit("buglupa connect: an unencrypted ws:// server is only allowed on this computer")
    return url


def parser(prog: str) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=prog,
        description="Let BugLupa Cloud's scanner test an app on your computer through a private tunnel.",
        epilog=f"The connect token comes from {TOKEN_ENV}, --token-file or a hidden prompt.",
    )
    p.add_argument("target", help="the app's address: 3000, localhost:3000, 127.0.0.1:8080 or https://localhost:8443")
    p.add_argument("--token-file", help="read the connect token from this file")
    p.add_argument("--server", help=f"tunnel server (default {DEFAULT_SERVER}; env {SERVER_ENV})")
    p.add_argument(
        "--insecure-local-tls",
        action="store_true",
        help="for an https:// local app with a self-signed certificate: don't verify its certificate",
    )
    p.add_argument("--max-streams", type=int, default=32, help="most requests forwarded at once (default 32)")
    p.add_argument("--quiet", action="store_true", help="don't print a line per request")
    p.add_argument("--no-color", action="store_true", help="plain output")
    p.add_argument("--version", action="version", version=f"buglupa-connect {__version__}")
    return p


def run(argv: list[str] | None, prog: str) -> int:
    args = parser(prog).parse_args(argv)
    color = sys.stdout.isatty() and not args.no_color and not os.environ.get("NO_COLOR")
    out = Output(sys.stdout, color, args.quiet)
    try:
        target = resolve_target(parse_target(args.target, args.insecure_local_tls))
    except TargetError as exc:
        out.line(f"{out.bad} {exc}")
        return 2
    if not 1 <= args.max_streams <= 256:
        out.line(f"{out.bad} --max-streams must be between 1 and 256")
        return 2
    server = check_server(args.server or os.environ.get(SERVER_ENV) or DEFAULT_SERVER)
    if server != DEFAULT_SERVER:
        out.line(f"{out.warn} Using the tunnel server {urlsplit(server).netloc} (not BugLupa's default).")
    token = read_token(args.token_file, sys.stdin.isatty())
    config = ClientConfig(server=server, token=token, target=target, max_streams=args.max_streams)
    return asyncio.run(_main(config, out))


async def _main(config: ClientConfig, out: Output) -> int:
    client = TunnelClient(config, lambda event: out.event(event, config.target.display))
    loop = asyncio.get_running_loop()
    presses = 0

    def interrupt() -> None:
        nonlocal presses
        presses += 1
        if presses > 1:
            os._exit(130)
        client.stop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError, RuntimeError, ValueError):
            loop.add_signal_handler(sig, interrupt)
    try:
        return await client.run()
    except asyncio.CancelledError:  # Ctrl+C where signal handlers aren't available (Windows)
        client.stop()
        return 0


def main(argv: list[str] | None = None) -> int:
    """`buglupa-connect TARGET`."""
    try:
        return run(argv, "buglupa-connect")
    except KeyboardInterrupt:
        return 130


def buglupa_main(argv: list[str] | None = None) -> int:
    """`buglupa connect TARGET`."""
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] != "connect":
        print("usage: buglupa connect TARGET  (this package only provides `buglupa connect`)", file=sys.stderr)
        return 2
    try:
        return run(args[1:], "buglupa connect")
    except KeyboardInterrupt:
        return 130
