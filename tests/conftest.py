from __future__ import annotations

import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from pwaudit.hibp import sha1_hex, split_hash


@dataclass
class RangeServer:
    """A stand-in for api.pwnedpasswords.com/range/ serving the passwords it is given."""

    ranges: dict[str, dict[str, int]] = field(default_factory=dict)
    requests: list[tuple[str, str]] = field(default_factory=list)  # (path, Add-Padding header)
    status: int = 200
    base: str = ""

    def add(self, password: str, count: int) -> None:
        prefix, suffix = split_hash(sha1_hex(password))
        self.ranges.setdefault(prefix, {})[suffix] = count


class _Handler(BaseHTTPRequestHandler):
    server_data: RangeServer

    def log_message(self, *args: object) -> None:
        pass

    def do_GET(self) -> None:
        data = self.server_data
        data.requests.append((self.path, self.headers.get("Add-Padding", "")))
        prefix = self.path.rsplit("/", 1)[-1]
        if data.status != 200 or len(prefix) != 5:
            self.send_response(data.status if data.status != 200 else 404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        lines = [f"{s}:{c}" for s, c in data.ranges.get(prefix, {}).items()]
        lines.append("0" * 35 + ":0")  # padding entry
        body = "\r\n".join(lines).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def pwned() -> Iterator[RangeServer]:
    data = RangeServer()
    server = ThreadingHTTPServer(("127.0.0.1", 0), type("H", (_Handler,), {"server_data": data}))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    data.base = f"http://127.0.0.1:{server.server_port}/range/"
    yield data
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)
