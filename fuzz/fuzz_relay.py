# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Fuzzes the reference relay's request handling with raw bytes on the connection.

Whatever a client sends, the handler must not raise. Lists never wait here, so a run does not
stall on a long poll. What is answered is not judged: for a request line without a version,
Python's http.server answers in the style of HTTP/0.9, without a status line.

    uv run python fuzz/fuzz_relay.py -max_total_time=300
"""

import io
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "relay"))

import atheris  # noqa: E402

with atheris.instrument_imports():
    import axt_relay  # type: ignore[import-not-found]  # noqa: E402  # loaded by path, as the relay's tests do


class Connection:
    """What the handler needs of a socket: the request's bytes to read, a place for the answer."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.sent = bytearray()

    def makefile(self, mode: str, buffering: int = -1) -> io.BytesIO:
        return io.BytesIO(self.data)

    def sendall(self, data: bytes) -> None:
        self.sent += data

    def settimeout(self, timeout: float | None) -> None:
        """Nothing to time out: the bytes are all there."""

    def setsockopt(self, *arguments: object) -> None:
        """No socket behind it."""


STORAGE = tempfile.TemporaryDirectory()
STORE = axt_relay.Store(STORAGE.name, axt_relay.Clock(0.0), quota_bytes=1 << 20, max_waiting=0)
SERVER = axt_relay.RelayServer(
    ("127.0.0.1", 0),
    STORE,
    test=True,
    access_log=False,
    requests_per_minute=1 << 40,
    creations_per_hour=1 << 40,
)


def test_one(data: bytes) -> None:
    axt_relay.Handler(Connection(data), ("127.0.0.1", 0), SERVER)


if __name__ == "__main__":
    atheris.Setup(sys.argv, test_one)
    atheris.Fuzz()
