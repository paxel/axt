#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""The AXT reference relay (spec/relay.md).

    python3 relay/axt_relay.py --storage DIR [--host 127.0.0.1] [--port 8080] [--base-path /] ...

A sealed mailbox: it stores the messages that apps put into a mailbox and hands
them to the mailbox's owner, as spec/transports.md, section 5, defines. It sees
neither the content nor the type of a message. It serves plain HTTP and is run
behind a TLS-terminating reverse proxy (relay/README.md).

It needs Python 3.11 or later and nothing beyond the standard library. It is a
reference and a test oracle: a production relay may be written in anything that
passes the relay-server vectors.
"""

import argparse
import hashlib
import hmac
import http.server
import io
import itertools
import json
import logging
import math
import os
import re
import secrets
import shutil
import signal
import socket
import struct
import sys
import threading
import time
from collections.abc import Callable, Iterable
from pathlib import Path
from types import FrameType
from typing import Any, BinaryIO, cast

# --- what spec/transports.md, section 5, fixes ------------------------------------

# The limits of the specification, from types/axt/limits.json in the repository's layout.
LIMITS_FILE = Path(__file__).resolve().parent.parent / "types" / "axt" / "limits.json"
LIMITS: dict[str, int] = {
    k: v["value"] for k, v in json.loads(LIMITS_FILE.read_text(encoding="utf-8"))["limits"].items()
}
HOLDING = LIMITS["transports.holding"]  # seconds a message is held after its put (section 5.5)
MAILBOX_IDLE = LIMITS["transports.mailbox_idle"]  # seconds without an owner request (section 5.5)
MAX_SEALED = LIMITS["transports.sealed_message"]  # the largest sealed message (section 5.6)
MAX_WAIT = LIMITS["transports.list_wait"]  # the longest wait of a list (section 5.4)
MAX_LISTED = LIMITS["transports.list_messages"]  # the most messages in one list (section 5.4)
MAILBOX_PREFIX = b"AXT-v1 mailbox\x00"  # the id is the SHA-256 of this and the secret (section 5.1)

# --- what this relay chooses (spec/relay.md) ----------------------------------------

DEFAULT_QUOTA = 64 * 2**20  # the bytes a mailbox holds, beyond the one message an empty mailbox always takes
SEEN_STEP = 86400  # the time of the last owner request is stored at most once in this many seconds
SWEEP_INTERVAL = 600  # seconds between two sweeps that delete expired messages and idle mailboxes
RETRY_AFTER_STORAGE = 60  # Retry-After of a 503 when the storage fails
CHUNK = 64 * 1024
DRAIN_SECONDS = 2  # how long the relay reads what a client still sends after an early answer
DRAIN_BYTES = 32 * 2**20

HEX64 = re.compile(r"^[0-9a-f]{64}$")
PATH = re.compile(r"^v1/mailboxes/([0-9a-f]{64})(?:/messages(?:/([0-9a-f]{64}))?)?$")
WAIT = re.compile(r"^wait=([0-9]{1,2})$")
DIGITS = re.compile(r"^[0-9]{1,20}$")
TEST_NOW_PATH = "/_test/now"
TEST_NOW = re.compile(r"^[0-9]{1,15}(?:\.[0-9]{1,6})?$")

# A message file: this header, then the sealed message. "AXR1", the time of the put in milliseconds
# of the relay's clock, and a sequence number that orders the puts.
HEADER = struct.Struct(">4sqQ")
MAGIC = b"AXR1"

log = logging.getLogger("axt-relay")


def mailbox_id(secret: bytes) -> str:
    return hashlib.sha256(MAILBOX_PREFIX + secret).hexdigest()


# --- the clock ----------------------------------------------------------------------


class Clock:
    """The relay's clock in seconds: the system's, or in test mode one the test sets."""

    def __init__(self, fixed: float | None = None) -> None:
        self._fixed = fixed

    def now(self) -> float:
        return time.time() if self._fixed is None else self._fixed

    def now_ms(self) -> int:
        return int(round(self.now() * 1000))

    def set(self, seconds: float) -> None:
        self._fixed = seconds


# --- storage ------------------------------------------------------------------------


class StorageError(Exception):
    """The storage failed; the relay answers 503."""


class Message:
    __slots__ = ("put_ms", "seq", "size")

    def __init__(self, put_ms: int, seq: int, size: int) -> None:
        self.put_ms, self.seq, self.size = put_ms, seq, size


class Mailbox:
    def __init__(self, lock: threading.Lock, seen_ms: int) -> None:
        self.messages: dict[str, Message] = {}  # message id -> Message
        self.seen_ms = seen_ms  # the stored time of the last owner request
        self.cond = threading.Condition(lock)  # notified on a put and on removal
        self.gone = False


class Store:
    """The mailboxes on disk, with an index in memory that is read again from disk at start.

    <root>/mailboxes/<mailbox id>/<message id>  the header above, then the sealed message
    <root>/mailboxes/<mailbox id>/seen          the time of the last owner request, in milliseconds
    <root>/tmp/                                 files being written, and mailboxes being removed
    """

    def __init__(
        self, root: str | Path, clock: Clock, quota_bytes: int = DEFAULT_QUOTA, max_waiting: int = 1000
    ) -> None:
        self.root = Path(root)
        self.boxes_dir = self.root / "mailboxes"
        self.tmp_dir = self.root / "tmp"
        self.clock = clock
        self.quota_bytes = quota_bytes
        self.max_waiting = max_waiting
        self.waiting = 0
        self.lock = threading.Lock()
        self.boxes: dict[str, Mailbox] = {}
        self.boxes_dir.mkdir(parents=True, exist_ok=True)
        shutil.rmtree(self.tmp_dir, ignore_errors=True)
        self.tmp_dir.mkdir(parents=True, exist_ok=True)
        self.seq = itertools.count(self._load())

    def _load(self) -> int:
        """Reads the index from disk; returns the next sequence number."""
        top = -1
        now_ms = self.clock.now_ms()
        for d in self.boxes_dir.iterdir():
            if not (d.is_dir() and HEX64.match(d.name)):
                continue
            try:
                seen = int((d / "seen").read_text(encoding="ascii"))
            except (OSError, ValueError):
                seen = now_ms
                self._write_seen(d, seen)
            box = Mailbox(self.lock, seen)
            entries: list[tuple[int, str, Message]] = []
            for f in d.iterdir():
                if not HEX64.match(f.name):
                    continue
                try:
                    with open(f, "rb") as fh:
                        magic, put_ms, seq = HEADER.unpack(fh.read(HEADER.size))
                    size = f.stat().st_size - HEADER.size
                except (OSError, struct.error):
                    continue
                if magic != MAGIC or size < 1:
                    continue
                entries.append((seq, f.name, Message(put_ms, seq, size)))
                top = max(top, seq)
            for _, name, m in sorted(entries):
                box.messages[name] = m
            self.boxes[d.name] = box
        return top + 1

    def _tmp(self) -> Path:
        return self.tmp_dir / secrets.token_hex(16)

    def _write_seen(self, directory: Path, ms: int) -> None:
        tmp = self._tmp()
        tmp.write_text(str(ms), encoding="ascii")
        os.replace(tmp, directory / "seen")

    def _held(self, m: Message, now_ms: int) -> bool:
        return now_ms < m.put_ms + HOLDING * 1000

    def _expire(self, mailbox: str, box: Mailbox, now_ms: int) -> None:
        for mid in [mid for mid, m in box.messages.items() if not self._held(m, now_ms)]:
            del box.messages[mid]
            (self.boxes_dir / mailbox / mid).unlink(missing_ok=True)

    def _touch(self, mailbox: str, box: Mailbox, now_ms: int) -> None:
        """Records an owner request, on disk at most once in SEEN_STEP."""
        if now_ms - box.seen_ms >= SEEN_STEP * 1000 or now_ms < box.seen_ms:
            self._write_seen(self.boxes_dir / mailbox, now_ms)
            box.seen_ms = now_ms

    def _remove(self, mailbox: str) -> Path | None:
        """Removes a mailbox with its messages; call with the lock held. Returns the directory to delete."""
        box = self.boxes.pop(mailbox, None)
        if box is None:
            return None
        box.gone = True
        box.cond.notify_all()
        trash = self._tmp()
        os.replace(self.boxes_dir / mailbox, trash)
        return trash

    def exists(self, mailbox: str) -> bool:
        with self.lock:
            return mailbox in self.boxes

    def create(self, mailbox: str) -> int:
        """201 for a new mailbox, 204 for one that exists."""
        try:
            with self.lock:
                now_ms = self.clock.now_ms()
                box = self.boxes.get(mailbox)
                if box is not None:
                    self._touch(mailbox, box, now_ms)
                    return 204
                directory = self.boxes_dir / mailbox
                directory.mkdir(exist_ok=True)
                self._write_seen(directory, now_ms)
                self.boxes[mailbox] = Mailbox(self.lock, now_ms)
                return 201
        except OSError as e:
            raise StorageError(e) from e

    def remove(self, mailbox: str) -> int:
        try:
            with self.lock:
                trash = self._remove(mailbox)
        except OSError as e:
            raise StorageError(e) from e
        if trash is not None:
            shutil.rmtree(trash, ignore_errors=True)
        return 204

    def receive(
        self,
        rfile: io.BufferedIOBase,
        length: int,
        message: str,
        before_read: Callable[[], None] | None = None,
    ) -> tuple[int | None, Path | None]:
        """Reads a body of `length` bytes into a new file. Returns (status, path): (400, None) for a body
        that is not `message`, (None, path) for one that is. Raises ConnectionError for a short body."""
        if before_read:
            before_read()
        tmp = self._tmp()
        digest = hashlib.sha256()
        try:
            with open(tmp, "wb") as fh:
                fh.write(bytes(HEADER.size))
                left = length
                while left:
                    chunk = rfile.read(min(CHUNK, left))
                    if not chunk:
                        raise ConnectionError("the body ended early")
                    digest.update(chunk)
                    fh.write(chunk)
                    left -= len(chunk)
                if digest.hexdigest() != message:
                    raise ValueError
                fh.flush()
                os.fsync(fh.fileno())
        except ValueError:
            tmp.unlink(missing_ok=True)
            return 400, None
        except OSError as e:
            tmp.unlink(missing_ok=True)
            if isinstance(e, (ConnectionError, TimeoutError)):
                raise
            raise StorageError(e) from e
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
        return None, tmp

    def put(self, mailbox: str, message: str, tmp: Path, size: int) -> int:
        """Holds a received message: 201, 204 if held already, 404 if the mailbox is gone, 507 if full."""
        try:
            put_ms, seq = self.clock.now_ms(), next(self.seq)
            with open(tmp, "r+b") as fh:
                fh.write(HEADER.pack(MAGIC, put_ms, seq))
                fh.flush()
                os.fsync(fh.fileno())
            with self.lock:
                box = self.boxes.get(mailbox)
                if box is None:
                    return 404
                self._expire(mailbox, box, self.clock.now_ms())
                if message in box.messages:
                    return 204
                if box.messages and sum(m.size for m in box.messages.values()) + size > self.quota_bytes:
                    return 507
                os.replace(tmp, self.boxes_dir / mailbox / message)
                box.messages[message] = Message(put_ms, seq, size)
                box.cond.notify_all()
                return 201
        except OSError as e:
            raise StorageError(e) from e
        finally:
            tmp.unlink(missing_ok=True)

    def list(self, mailbox: str, wait: float) -> list[tuple[str, int]] | None:
        """The (id, size) of the messages held, oldest put first, at most MAX_LISTED; None if no mailbox.
        With `wait` and no message, waits up to `wait` seconds of real time for a put."""
        try:
            with self.lock:
                box = self.boxes.get(mailbox)
                if box is None:
                    return None
                now_ms = self.clock.now_ms()
                self._touch(mailbox, box, now_ms)
                self._expire(mailbox, box, now_ms)
                if not box.messages and wait > 0 and self.waiting < self.max_waiting:
                    self.waiting += 1
                    try:
                        deadline = time.monotonic() + wait
                        while not box.messages and not box.gone:
                            remaining = deadline - time.monotonic()
                            if remaining <= 0:
                                break
                            box.cond.wait(remaining)
                    finally:
                        self.waiting -= 1
                    if box.gone:
                        return None
                    self._expire(mailbox, box, self.clock.now_ms())
                held = sorted(box.messages.items(), key=lambda e: e[1].seq)[:MAX_LISTED]
                return [(mid, m.size) for mid, m in held]
        except OSError as e:
            raise StorageError(e) from e

    def open(self, mailbox: str, message: str) -> tuple[BinaryIO, int] | tuple[None, int] | None:
        """(file positioned at the message, size); None if no mailbox, (None, 0) if no such message."""
        try:
            with self.lock:
                box = self.boxes.get(mailbox)
                if box is None:
                    return None
                now_ms = self.clock.now_ms()
                self._touch(mailbox, box, now_ms)
                self._expire(mailbox, box, now_ms)
                m = box.messages.get(message)
                if m is None:
                    return None, 0
                fh = open(self.boxes_dir / mailbox / message, "rb")
                fh.seek(HEADER.size)
                return fh, m.size
        except OSError as e:
            raise StorageError(e) from e

    def delete(self, mailbox: str, message: str) -> int:
        """204, also for a message not held; 404 if no mailbox."""
        try:
            with self.lock:
                box = self.boxes.get(mailbox)
                if box is None:
                    return 404
                self._touch(mailbox, box, self.clock.now_ms())
                if box.messages.pop(message, None) is not None:
                    (self.boxes_dir / mailbox / message).unlink(missing_ok=True)
                return 204
        except OSError as e:
            raise StorageError(e) from e

    def sweep(self) -> None:
        """Deletes the messages past their holding time, and the mailboxes idle for more than 90 days."""
        trash: list[Path | None] = []
        with self.lock:
            now_ms = self.clock.now_ms()
            for mailbox, box in list(self.boxes.items()):
                try:
                    if now_ms >= box.seen_ms + (MAILBOX_IDLE + SEEN_STEP) * 1000:
                        trash.append(self._remove(mailbox))
                    else:
                        self._expire(mailbox, box, now_ms)
                except OSError:
                    log.exception("the sweep failed for a mailbox")
        for t in trash:
            if t is not None:
                shutil.rmtree(t, ignore_errors=True)


# --- rate limits --------------------------------------------------------------------


class RateLimit:
    """A token bucket per client address: `count` requests in `period` seconds, in bursts of up to `count`."""

    def __init__(self, count: int, period: int) -> None:
        self.count, self.rate = count, count / period if count > 0 else 0
        self.buckets: dict[str, tuple[float, float]] = {}
        self.lock = threading.Lock()

    def take(self, key: str) -> int | None:
        """None if the request may go ahead, else the seconds for Retry-After."""
        if self.count <= 0:
            return None
        with self.lock:
            now = time.monotonic()
            tokens, last = self.buckets.get(key, (self.count, now))
            tokens = min(self.count, tokens + (now - last) * self.rate)
            if tokens < 1:
                self.buckets[key] = (tokens, now)
                return max(1, math.ceil((1 - tokens) / self.rate))
            self.buckets[key] = (tokens - 1, now)
            return None

    def prune(self) -> None:
        with self.lock:
            now = time.monotonic()
            for key in [
                k for k, (t, last) in self.buckets.items() if t + (now - last) * self.rate >= self.count
            ]:
                del self.buckets[key]


# --- HTTP ---------------------------------------------------------------------------


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "axt-relay"
    sys_version = ""
    timeout = 60  # seconds a connection may stay silent

    server: "RelayServer"
    client_address: tuple[str, int]
    status: int | None
    action: str
    size: int
    unread: bool
    expect_continue: bool

    def version_string(self) -> str:
        return self.server_version

    # http.server logs the client address with the request line, which holds the mailbox id, and the
    # raw request line of a malformed request: neither is logged here (spec/transports.md, section 5.7).
    def log_request(self, code: int | str = "-", size: int | str = "-") -> None:
        pass

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def log_error(self, format: str, *args: Any) -> None:
        code = args[0] if args and isinstance(args[0], int) else "-"
        if self.server.access_log:
            log.info("%s malformed %s", self.client(), code)

    def handle_expect_100(self) -> bool:
        self.expect_continue = True  # sent only when the relay reads the body
        return True

    def send_continue(self) -> None:
        if getattr(self, "expect_continue", False):
            self.expect_continue = False
            self.send_response_only(100)
            self.end_headers()

    def client(self) -> str:
        name = self.server.address_header
        if name:
            headers = getattr(self, "headers", None)
            values: list[str] | None = headers.get_all(name) if headers else None
            if values:
                return values[-1].split(",")[-1].strip() or self.client_address[0]
        return self.client_address[0]

    def do_GET(self) -> None:
        self.route()

    do_PUT = do_DELETE = do_POST = do_HEAD = do_PATCH = do_OPTIONS = do_GET

    def respond(
        self,
        status: int,
        body: bytes = b"",
        content_type: str | None = None,
        headers: Iterable[tuple[str, str]] = (),
    ) -> None:
        self.status = status
        self.send_response(status)
        if content_type:
            self.send_header("Content-Type", content_type)
        if status != 204:
            self.send_header("Content-Length", str(len(body)))
        for k, v in headers:
            self.send_header(k, v)
        if self.unread:
            self.send_header("Connection", "close")
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)

    def drain(self) -> None:
        """After an answer that leaves a body unread: reads what the client still sends, briefly, so that
        closing the connection does not reset it before the client has read the answer."""
        try:
            self.wfile.flush()
            self.connection.shutdown(socket.SHUT_WR)
            self.connection.settimeout(DRAIN_SECONDS)
            deadline, total = time.monotonic() + DRAIN_SECONDS, 0
            while time.monotonic() < deadline and total < DRAIN_BYTES:
                data = self.rfile.read1(CHUNK) if hasattr(self.rfile, "read1") else self.rfile.read(CHUNK)
                if not data:
                    break
                total += len(data)
        except OSError:
            pass

    def route(self) -> None:
        self.status, self.action, self.size = None, "-", 0
        cl = self.headers.get_all("Content-Length") or []
        self.unread = bool(self.headers.get("Transfer-Encoding")) or any(v.strip() != "0" for v in cl)
        try:
            try:
                self.dispatch()
            except StorageError:
                log.exception("the storage failed")
                if self.status is None:
                    self.unread = True
                    self.respond(503, headers=[("Retry-After", str(RETRY_AFTER_STORAGE))])
            if self.unread:
                self.close_connection = True
                self.drain()
        except (ConnectionError, TimeoutError):
            self.close_connection = True
            return
        finally:
            self.expect_continue = False
        if self.server.access_log:
            log.info("%s %s %s %s", self.client(), self.action, self.status, self.size)

    def dispatch(self) -> None:
        server = self.server
        path, _, query = self.path.partition("?")
        retry = server.requests_limit.take(self.client())
        if retry is not None:
            return self.respond(429, headers=[("Retry-After", str(retry))])
        if server.test and path == TEST_NOW_PATH:
            return self.test_now()
        if not path.startswith(server.base_path):
            return self.respond(404)
        m = PATH.match(path[len(server.base_path) :])
        if not m:
            return self.respond(404)
        mailbox, message = m.group(1), m.group(2)
        is_list = path.endswith("/messages")
        method = self.command
        self.action = {
            ("PUT", "box"): "create",
            ("DELETE", "box"): "remove",
            ("PUT", "msg"): "put",
            ("GET", "list"): "list",
            ("GET", "msg"): "fetch",
            ("DELETE", "msg"): "delete",
        }.get((method, "list" if is_list else "msg" if message else "box"), method.lower())
        if query and not (is_list and method == "GET"):
            return self.respond(400)
        if method == "PUT" and message:
            return self.put(mailbox, message)
        refused = self.owner(mailbox)
        if refused:
            return self.respond(refused)
        store = server.store
        if not message and not is_list:
            if method == "PUT":
                if not store.exists(mailbox):
                    retry = server.creations_limit.take(self.client())
                    if retry is not None:
                        return self.respond(429, headers=[("Retry-After", str(retry))])
                return self.respond(store.create(mailbox))
            if method == "DELETE":
                return self.respond(store.remove(mailbox))
            return self.respond(405)
        if is_list and method == "GET":
            wait = 0
            if query:
                q = WAIT.match(query)
                if not q or int(q.group(1)) > MAX_WAIT:
                    if not store.exists(mailbox):
                        return self.respond(404)
                    return self.respond(400)
                wait = int(q.group(1))
            listed = store.list(mailbox, wait)
            if listed is None:
                return self.respond(404)
            body = json.dumps({"messages": [{"id": i, "size": s} for i, s in listed]}, separators=(",", ":"))
            return self.respond(200, body.encode("ascii"), "application/json")
        if message and method == "GET":
            opened = store.open(mailbox, message)
            if opened is None or opened[0] is None:
                return self.respond(404)
            fh, size = opened
            with fh:
                self.status, self.size = 200, size
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(size))
                if self.unread:
                    self.send_header("Connection", "close")
                self.end_headers()
                if self.command != "HEAD":
                    shutil.copyfileobj(fh, self.wfile, CHUNK)
            return None
        if message and method == "DELETE":
            return self.respond(store.delete(mailbox, message))
        return self.respond(405)

    def owner(self, mailbox: str) -> int | None:
        """None for the mailbox's owner, else 401 or 403 (spec/transports.md, section 5.2)."""
        values = self.headers.get_all("Authorization") or []
        if len(values) != 1 or not values[0].startswith("Bearer ") or not HEX64.match(values[0][7:]):
            return 401
        return None if hmac.compare_digest(mailbox_id(bytes.fromhex(values[0][7:])), mailbox) else 403

    def put(self, mailbox: str, message: str) -> None:
        """The checks of spec/transports.md, section 5.3, in its order."""
        values = self.headers.get_all("Content-Length") or []
        if not values:
            return self.respond(411)
        if len(values) != 1 or not DIGITS.match(values[0].strip()) or self.headers.get("Transfer-Encoding"):
            self.unread = True
            return self.respond(400)
        length = int(values[0].strip())
        if length > MAX_SEALED:
            return self.respond(413)
        store = self.server.store
        if not store.exists(mailbox):
            return self.respond(404)
        if length == 0:
            return self.respond(400)
        status, tmp = store.receive(self.rfile, length, message, before_read=self.send_continue)
        self.unread = False  # the body has been read
        if status:
            return self.respond(status)
        self.size = length
        return self.respond(store.put(mailbox, message, cast(Path, tmp), length))

    def test_now(self) -> None:
        """The test hook: PUT /_test/now with the relay's clock in seconds as the body (--test only)."""
        self.action = "test-clock"
        values = self.headers.get_all("Content-Length") or []
        if (
            self.command != "PUT"
            or len(values) != 1
            or not DIGITS.match(values[0].strip())
            or int(values[0]) > 32
        ):
            return self.respond(400)
        self.send_continue()
        text = self.rfile.read(int(values[0])).decode("ascii", "replace")
        self.unread = False
        if not TEST_NOW.match(text):
            return self.respond(400)
        self.server.store.clock.set(float(text))
        self.server.store.sweep()
        return self.respond(204)


class RelayServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        store: Store,
        base_path: str = "/",
        test: bool = False,
        access_log: bool = True,
        address_header: str | None = None,
        requests_per_minute: int = 600,
        creations_per_hour: int = 20,
    ) -> None:
        if not (base_path.startswith("/") and base_path.endswith("/")):
            raise ValueError("the base path must begin and end with /")
        self.store, self.base_path, self.test, self.access_log = store, base_path, test, access_log
        self.address_header = address_header
        self.requests_limit = RateLimit(requests_per_minute, 60)
        self.creations_limit = RateLimit(creations_per_hour, 3600)
        self.stop_sweeping = threading.Event()
        super().__init__(address, Handler)

    def handle_error(self, request: socket.socket | tuple[bytes, socket.socket], client_address: Any) -> None:
        log.exception("an error while serving a request")  # without the client address

    def sweep_forever(self) -> None:
        while not self.stop_sweeping.wait(SWEEP_INTERVAL):
            try:
                self.store.sweep()
                self.requests_limit.prune()
                self.creations_limit.prune()
            except Exception:
                log.exception("the sweep failed")

    def start_sweeping(self) -> None:
        threading.Thread(target=self.sweep_forever, name="sweep", daemon=True).start()

    def server_close(self) -> None:
        self.stop_sweeping.set()
        super().server_close()


def build(args: argparse.Namespace) -> RelayServer:
    """The server for parsed command-line arguments."""
    clock = Clock(0.0 if args.test else None)
    store = Store(args.storage, clock, quota_bytes=args.quota_bytes, max_waiting=args.max_waiting)
    return RelayServer(
        (args.host, args.port),
        store,
        base_path=args.base_path,
        test=args.test,
        access_log=not args.no_access_log,
        address_header=args.client_address_header,
        requests_per_minute=args.rate_requests,
        creations_per_hour=args.rate_creations,
    )


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="The AXT reference relay (spec/relay.md).")
    ap.add_argument("--storage", required=True, type=Path, help="the directory that holds the mailboxes")
    ap.add_argument("--host", default="127.0.0.1", help="the address to listen on (default: 127.0.0.1)")
    ap.add_argument("--port", type=int, default=8080, help="the port to listen on, 0 for any (default: 8080)")
    ap.add_argument(
        "--base-path", default="/", help="the path of the base URL, beginning and ending with / (default: /)"
    )
    ap.add_argument(
        "--quota-bytes",
        type=int,
        default=DEFAULT_QUOTA,
        help="the bytes a mailbox holds; an empty mailbox always takes one message "
        f"(default: {DEFAULT_QUOTA})",
    )
    ap.add_argument(
        "--max-waiting",
        type=int,
        default=1000,
        help="lists that may wait at the same time; beyond it a list answers at once (default: 1000)",
    )
    ap.add_argument(
        "--rate-requests",
        type=int,
        default=600,
        help="requests per minute per client address, 0 for no limit (default: 600)",
    )
    ap.add_argument(
        "--rate-creations",
        type=int,
        default=20,
        help="mailboxes created per hour per client address, 0 for no limit (default: 20)",
    )
    ap.add_argument(
        "--client-address-header",
        metavar="NAME",
        help="take the client address from the last value of this header, set by the proxy, "
        "such as X-Forwarded-For",
    )
    ap.add_argument("--no-access-log", action="store_true", help="log no line per request")
    ap.add_argument(
        "--test",
        action="store_true",
        help="test mode: a clock that starts at 0 and is set with PUT /_test/now; never in production",
    )
    return ap


def main(argv: list[str] | None = None) -> None:
    args = parser().parse_args(argv)
    if args.quota_bytes < 0 or args.max_waiting < 0:
        raise SystemExit("--quota-bytes and --max-waiting must not be negative")
    logging.basicConfig(
        stream=sys.stderr, level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%Y-%m-%dT%H:%M:%SZ"
    )
    logging.Formatter.converter = time.gmtime
    server = build(args)
    host, port = server.server_address[:2]
    log.info(
        "axt-relay listening on %s:%s%s%s", host, port, args.base_path, " in test mode" if args.test else ""
    )
    server.start_sweeping()

    def stop(signum: int, frame: FrameType | None) -> None:
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        log.info("axt-relay stopped")


if __name__ == "__main__":
    main()
