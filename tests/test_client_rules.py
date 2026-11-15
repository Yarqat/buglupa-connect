"""Rules the `buglupa connect` client is held to.

The client runs on the customer's computer, so it is held to rules of its own:
- standard library only (nothing else to audit; a single-file build stays simple);
- it never listens: no server sockets, no bind/listen;
- it starts no processes;
- it opens connections in exactly two places: ws.py (the tunnel server) and forward.py (the one local address).
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "buglupa_connect"
LISTENING = {"start_server", "start_unix_server", "create_server", "create_unix_server", "bind", "listen", "accept"}
SPAWNING = {"subprocess", "pty", "asyncio.subprocess", "multiprocessing"}
SPAWN_CALLS = {"system", "popen", "spawnv", "spawnvp", "execv", "execvp", "fork", "create_subprocess_exec",
               "create_subprocess_shell"}  # fmt: skip
CONNECTING = {"open_connection", "create_connection", "open_unix_connection", "create_unix_connection"}


def _trees() -> dict[str, ast.Module]:
    return {p.name: ast.parse(p.read_text(), filename=str(p)) for p in SRC.glob("*.py")}


def test_standard_library_only():
    stdlib = set(sys.stdlib_module_names)
    for name, tree in _trees().items():
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots = {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                roots = {node.module.split(".")[0]}
            else:
                continue
            assert roots <= stdlib, (name, roots - stdlib)


def test_never_listens_and_never_starts_processes():
    problems = []
    for name, tree in _trees().items():
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in LISTENING | SPAWN_CALLS:
                problems.append(f"{name}:{node.lineno} .{node.attr}")
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""]
                problems += [f"{name}:{node.lineno} imports {n}" for n in names if n in SPAWNING]
    assert problems == []


def test_connections_are_opened_only_to_the_server_and_the_named_app():
    opened = {
        name
        for name, tree in _trees().items()
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and node.attr in CONNECTING
    }
    assert opened == {"ws.py", "forward.py"}
