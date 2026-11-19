#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""The relay-server adapter of the reference relay (spec/conformance.md, sections 5.11 and 6).

    python3 conformance/run.py --category relay-server -- python3 relay/adapter.py

For each vector it starts relay/axt_relay.py as a process of its own, on 127.0.0.1 with a port the
system picks, an empty temporary storage directory, the vector's quota and the test mode, and plays
the vector's requests against it over HTTP. Before each request it sets the relay's clock to the
request's `now` with the test hook PUT /_test/now; its rate limits are off, so that
the hook's requests do not count. It sends exactly the vector's headers and a Host
header; a request without Content-Length is sent without a body, since in HTTP/1.1 such a request has
none (RFC 9112, section 6.3). The relay's log goes to a buffer, never to the standard output.

It needs Python 3.11 or later and nothing beyond the standard library.
"""

import collections
import http.client
import json
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import zlib
from pathlib import Path
from typing import IO, Any, cast
from urllib.parse import urlsplit

RELAY = Path(__file__).resolve().parent / "axt_relay.py"
LISTENING = re.compile(r"listening on 127\.0\.0\.1:([0-9]+)/")
HEX = re.compile(r"^(?:[0-9a-f]{2})*$")


def to_bytes(v: Any) -> bytes:
    """The bytes of a hex string or a deflate object (spec/conformance.md, section 3.2)."""
    if isinstance(v, str):
        if not HEX.match(v):
            raise ValueError("not lower-case hex")
        return bytes.fromhex(v)
    data = zlib.decompressobj(-15).decompress(bytes.fromhex(v["deflate"]))
    if len(data) != v["length"]:
        raise ValueError("a deflate object whose length does not match")
    return data


class Relay:
    """A running reference relay in test mode."""

    def __init__(self, base_path: str, quota_bytes: int) -> None:
        self.dir = tempfile.mkdtemp(prefix="axt-relay-")
        self.proc = subprocess.Popen(  # noqa: S603 the adapter builds the arguments itself
            [
                sys.executable,
                str(RELAY),
                "--host",
                "127.0.0.1",
                "--port",
                "0",
                "--storage",
                self.dir,
                "--base-path",
                base_path,
                "--quota-bytes",
                str(quota_bytes),
                "--rate-requests",
                "0",
                "--rate-creations",
                "0",
                "--test",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.log: collections.deque[str] = collections.deque(maxlen=40)
        self.port: int | None = None
        for line in cast(IO[str], self.proc.stderr):  # stderr=PIPE: it is a pipe
            self.log.append(line.rstrip())
            m = LISTENING.search(line)
            if m:
                self.port = int(m.group(1))
                break
        if self.port is None:
            self.close()
            raise RuntimeError("the relay did not start: " + " | ".join(self.log))
        threading.Thread(target=self._drain, daemon=True).start()

    def _drain(self) -> None:
        for line in cast(IO[str], self.proc.stderr):  # stderr=PIPE: it is a pipe
            self.log.append(line.rstrip())

    def request(
        self, method: str, path: str, headers: list[tuple[str, str]], body: bytes
    ) -> tuple[int, bytes]:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=90)
        try:
            conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            for name, value in headers:
                conn.putheader(name, value)
            conn.endheaders()
            if body and any(name.lower() == "content-length" for name, _ in headers):
                conn.send(body)
            response = conn.getresponse()
            return response.status, response.read()
        finally:
            conn.close()

    def set_clock(self, now: int | float) -> None:
        text = repr(now).encode("ascii") if isinstance(now, float) else str(now).encode("ascii")
        status, _ = self.request(
            "PUT", "/_test/now", [("Host", "127.0.0.1"), ("Content-Length", str(len(text)))], text
        )
        if status != 204:
            raise RuntimeError(f"the test hook answered {status}")

    def close(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        shutil.rmtree(self.dir, ignore_errors=True)


def op_relay(i: dict[str, Any]) -> dict[str, Any]:
    base = urlsplit(i["base_url"])
    relay = Relay(base.path, i["quota_bytes"])
    try:
        steps: list[dict[str, Any]] = []
        for r in i["requests"]:
            relay.set_clock(r["now"])
            headers = [("Host", base.netloc)] + list(r["headers"].items())
            status, body = relay.request(r["method"], base.path + r["target"], headers, to_bytes(r["body"]))
            out: dict[str, Any] = {"status": status}
            if status == 200 and r["target"].split("?")[0].endswith("/messages"):
                out["messages"] = json.loads(body)["messages"]
            elif status == 200:
                out["message"] = body.hex()
            steps.append(out)
        return {"steps": steps}
    except Exception as e:
        raise RuntimeError(f"{e!r}; relay log: {' | '.join(relay.log)}") from e
    finally:
        relay.close()


def main() -> None:
    for line in sys.stdin:
        req = json.loads(line)
        rid, op = req["id"], req["op"]
        if op == "hello":
            answer = {
                "id": rid,
                "output": {
                    "name": "AXT reference relay (relay/axt_relay.py)",
                    "categories": ["relay-server"],
                },
            }
        elif op == "relay":
            try:
                answer = {"id": rid, "output": op_relay(req["input"])}
            except Exception as e:
                answer = {"id": rid, "failure": str(e)[:2000]}
        else:
            answer = {"id": rid, "unsupported": True}
        sys.stdout.write(json.dumps(answer) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
