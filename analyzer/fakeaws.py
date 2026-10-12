"""A fake ``aws`` executor for tests and the offline demo (no network, no AWS).

Plug it into :class:`AwsCli` as ``executor=FakeAws(...)``. Responses are keyed by
``(service, operation)`` and can be a dict (any region) or a callable
``(region, args) -> dict`` that may raise :class:`FakeError`.
"""

from __future__ import annotations

import json
import threading
from typing import Any, Callable

_OWN_FLAGS_WITH_VALUE = {"--output", "--cli-read-timeout", "--cli-connect-timeout", "--region", "--profile"}


class FakeError(Exception):
    def __init__(self, code: str, message: str = "simulated"):
        super().__init__(message)
        self.code = code
        self.message = message


def _camel(op: str) -> str:
    return "".join(p.capitalize() for p in op.split("-"))


class FakeAws:
    def __init__(self, responses: dict[tuple[str, str], Any] | None = None):
        self.responses = dict(responses or {})
        self.calls: list[tuple[str, str, str | None, tuple[str, ...]]] = []
        self._lock = threading.Lock()

    def set(self, service: str, op: str, response: Any) -> "FakeAws":
        self.responses[(service, op)] = response
        return self

    def __call__(self, argv: list[str], env: dict[str, str], timeout: float):
        if len(argv) >= 3 and argv[1] == "configure":
            return 0, "default\n", ""
        if len(argv) == 2 and argv[1] == "--version":
            return 0, "aws-cli/2.99.0 Python/3.13 FakeAws\n", ""
        service, op = argv[1], argv[2]
        rest = argv[3:]
        args: list[str] = []
        region = profile = None
        i = 0
        while i < len(rest):
            a = rest[i]
            flag, sep, glued = a.partition("=")     # AwsCli passes --region=<r> / --profile=<p> as one token
            if flag in _OWN_FLAGS_WITH_VALUE:
                value = glued if sep else (rest[i + 1] if i + 1 < len(rest) else None)
                if flag == "--region":
                    region = value
                elif flag == "--profile":
                    profile = value
                i += 1 if sep else 2
                continue
            if a == "--no-cli-pager":
                i += 1
                continue
            args.append(a)
            i += 1
        with self._lock:
            self.calls.append((service, op, region, tuple(args)))
        handler = self.responses.get((service, op), {})
        try:
            data = handler(region, args) if callable(handler) else handler
        except FakeError as e:
            return 254, "", (f"\nAn error occurred ({e.code}) when calling the {_camel(op)} "
                             f"operation: {e.message}\n")
        return 0, json.dumps(data), ""

    def ops(self) -> set[tuple[str, str]]:
        return {(s, o) for s, o, _r, _a in self.calls}


def arg_value(args: list[str], flag: str) -> str | None:
    """Value following ``flag`` in an argument list (for fake handlers)."""
    for i, a in enumerate(args):
        if a == flag and i + 1 < len(args):
            return args[i + 1]
        if a.startswith(flag + "="):
            return a.split("=", 1)[1]
    return None
