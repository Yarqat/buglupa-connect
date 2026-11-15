"""Which local addresses `buglupa connect` forwards to, and the CLI's input rules."""

from __future__ import annotations

import pytest

from buglupa_connect.cli import check_server, read_token
from buglupa_connect.forward import TargetError, parse_target, resolve_target


@pytest.mark.parametrize(
    ("raw", "scheme", "host", "port", "authority"),
    [
        ("3000", "http", "localhost", 3000, "localhost:3000"),
        (":3000", "http", "localhost", 3000, "localhost:3000"),
        ("localhost:3000", "http", "localhost", 3000, "localhost:3000"),
        ("127.0.0.1:8080", "http", "127.0.0.1", 8080, "127.0.0.1:8080"),
        ("[::1]:3000", "http", "::1", 3000, "[::1]:3000"),
        ("http://LOCALHOST:3000/", "http", "localhost", 3000, "localhost:3000"),
        ("https://localhost:8443", "https", "localhost", 8443, "localhost:8443"),
        ("https://localhost", "https", "localhost", 443, "localhost"),
        ("0.0.0.0:5000", "http", "127.0.0.1", 5000, "127.0.0.1:5000"),
    ],
)
def test_target_forms(raw, scheme, host, port, authority):
    target = parse_target(raw)
    assert (target.scheme, target.host, target.port, target.authority) == (scheme, host, port, authority)


@pytest.mark.parametrize(
    "raw", ["ftp://localhost:21", "localhost:3000/admin", "user@localhost:3000", "localhost:99999"]
)
def test_bad_target_forms(raw):
    with pytest.raises(TargetError):
        parse_target(raw)


@pytest.mark.parametrize("raw", ["127.0.0.1:3000", "[::1]:3000", "10.1.2.3:80", "192.168.1.20:8080", "localhost:3000"])
def test_local_and_private_addresses_are_allowed(raw):
    assert resolve_target(parse_target(raw)).addresses


@pytest.mark.parametrize(
    "raw",
    ["8.8.8.8:80", "169.254.169.254:80", "[fe80::1]:80", "224.0.0.1:80", "[::ffff:8.8.8.8]:80", "100.64.0.1:80"],
)
def test_public_metadata_and_odd_addresses_are_refused(raw):
    with pytest.raises(TargetError):
        resolve_target(parse_target(raw))


def test_loopback_targets_count_loopback_names_as_the_same_door():
    target = resolve_target(parse_target("localhost:3000"))
    assert {("localhost", 3000), ("127.0.0.1", 3000), ("::1", 3000)} <= target.aliases()
    assert ("localhost", 3001) not in target.aliases()


def test_tokens_come_from_the_environment_or_a_file_and_servers_are_encrypted(tmp_path, monkeypatch):
    monkeypatch.delenv("BUGLUPA_CONNECT_TOKEN", raising=False)
    with pytest.raises(SystemExit):
        read_token(None, stdin_tty=False)
    monkeypatch.setenv("BUGLUPA_CONNECT_TOKEN", "blct_" + "x" * 60)
    assert read_token(None, stdin_tty=False).startswith("blct_")
    path = tmp_path / "token"
    path.write_text("not a token\n")
    with pytest.raises(SystemExit):
        read_token(str(path), stdin_tty=False)
    assert check_server("wss://tunnel.buglupa.com/v1/connect")
    assert check_server("ws://127.0.0.1:8504/v1/connect")
    for bad in ("ws://tunnel.buglupa.com/v1/connect", "http://x/", "wss://user:pw@x/"):
        with pytest.raises(SystemExit):
            check_server(bad)
