# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Tests of the reference relay beyond the relay-server vectors.

    python3 -m unittest relay/test_axt_relay.py

Standard library only. The end-to-end test opens the fetched message with the code of
conformance/tools/keys_examples.py and the package cryptography, and skips that step without them.
"""

import hashlib
import importlib.util
import io
import json
import logging
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any, cast

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(HERE))
# E402: the import follows the path entry it needs. import-not-found: mypy checks each directory as
# a base of its own and does not see the sibling module.
import axt_relay  # type: ignore[import-not-found]  # noqa: E402

DAY = 86400
SECRET = hashlib.sha256(b"AXT test key, not for use: Old Brain Fix, mailbox secret").hexdigest()
WRONG = hashlib.sha256(b"AXT test key, not for use: another mailbox secret").hexdigest()
BOX = axt_relay.mailbox_id(bytes.fromhex(SECRET))
OWNER = {"Authorization": "Bearer " + SECRET}
BASE = "/axt/"


def sealed_example() -> bytes:
    """The sealed message of spec/keys.md, section 7.4, as the relay-server vectors hold it."""
    doc = json.loads((REPO / "vectors" / "relay-server" / "relay-server.json").read_text(encoding="utf-8"))
    for r in doc["vectors"][0]["input"]["requests"]:
        if r["method"] == "PUT" and r["target"].endswith(
            "/messages/64a9988bd3e1e8210d592e29115d5b3252d2e75be5c219ca67583608cfdb878a"
        ):
            data = bytes.fromhex(r["body"])
            if hashlib.sha256(data).hexdigest() == r["target"][-64:]:
                return data
    raise AssertionError("the sealed message of spec/keys.md, section 7.4, is not in the vectors")


def message(n: int) -> bytes:
    return bytes([n % 251]) * (1000 + n)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Relay:
    """A relay in this process, on 127.0.0.1 and a port the system picks."""

    def __init__(
        self, directory: str, test: bool = True, quota_bytes: int = axt_relay.DEFAULT_QUOTA, **kw: Any
    ) -> None:
        self.store = axt_relay.Store(
            directory, axt_relay.Clock(0.0 if test else None), quota_bytes=quota_bytes
        )
        self.server = axt_relay.RelayServer(("127.0.0.1", 0), self.store, base_path=BASE, test=test, **kw)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def raw(self, data: bytes, read_until_close: bool = True) -> bytes:
        with socket.create_connection(("127.0.0.1", self.port), timeout=10) as s:
            s.sendall(data)
            out = b""
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    return out
                out += chunk
                if not read_until_close and b"\r\n\r\n" in out:
                    return out

    def request(
        self,
        method: str,
        target: str | None,
        headers: dict[str, str] | None = None,
        body: bytes = b"",
        path: str | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        """(status, headers, body) of one request on a connection of its own."""
        import http.client

        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=90)
        try:
            # target is None only where path is given
            conn.putrequest(method, path or BASE + cast(str, target), skip_accept_encoding=True)
            headers = dict(headers or {})
            if body and "Content-Length" not in headers:
                headers["Content-Length"] = str(len(body))
            for k, v in headers.items():
                conn.putheader(k, v)
            conn.endheaders()
            if body:
                conn.send(body)
            r = conn.getresponse()
            return r.status, dict(r.getheaders()), r.read()
        finally:
            conn.close()

    def now(self, seconds: float) -> None:
        text = str(seconds).encode()
        assert (
            self.request("PUT", None, {"Content-Length": str(len(text))}, text, path="/_test/now")[0] == 204
        )

    def create(self) -> int:
        return self.request("PUT", f"v1/mailboxes/{BOX}", OWNER)[0]

    def put(self, data: bytes) -> int:
        return self.request("PUT", f"v1/mailboxes/{BOX}/messages/{sha(data)}", {}, data)[0]

    def list(self, wait: int | None = None) -> tuple[int, Any]:
        status, _, body = self.request(
            "GET", f"v1/mailboxes/{BOX}/messages" + ("" if wait is None else f"?wait={wait}"), OWNER
        )
        return status, (json.loads(body)["messages"] if status == 200 else None)

    def fetch(self, mid: str) -> tuple[int, bytes]:
        status, _, body = self.request("GET", f"v1/mailboxes/{BOX}/messages/{mid}", OWNER)
        return status, body


class RelayTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp(prefix="axt-relay-test-")
        self.addCleanup(shutil.rmtree, self.dir, True)

    def relay(self, **kw: Any) -> Relay:
        r = Relay(self.dir, **kw)
        self.addCleanup(r.stop)
        return r

    def test_long_poll_answers_when_a_message_is_put(self) -> None:
        r = self.relay()
        r.create()
        result: dict[str, Any] = {}

        def wait() -> None:
            start = time.monotonic()
            result["list"] = r.list(wait=30)
            result["took"] = time.monotonic() - start

        t = threading.Thread(target=wait)
        t.start()
        time.sleep(0.3)
        self.assertEqual(r.put(message(1)), 201)
        t.join(10)
        self.assertEqual(result["list"], (200, [{"id": sha(message(1)), "size": len(message(1))}]))
        self.assertLess(result["took"], 5)

    def test_long_poll_ends_after_its_wait_with_an_empty_list(self) -> None:
        r = self.relay()
        r.create()
        start = time.monotonic()
        self.assertEqual(r.list(wait=1), (200, []))
        self.assertGreaterEqual(time.monotonic() - start, 0.9)

    def test_a_list_does_not_wait_beyond_the_limit_of_waiting_lists(self) -> None:
        r = self.relay()
        r.store.max_waiting = 0
        r.create()
        start = time.monotonic()
        self.assertEqual(r.list(wait=30), (200, []))
        self.assertLess(time.monotonic() - start, 5)

    def test_a_restart_keeps_messages_their_order_and_their_put_times(self) -> None:
        r = self.relay()
        r.create()
        r.now(100)
        for n in (3, 1, 2):  # the same second: the order of the puts holds, not that of the ids
            self.assertEqual(r.put(message(n)), 201)
        r.now(200)
        self.assertEqual(r.put(message(4)), 201)
        r.stop()
        r2 = self.relay()
        self.assertEqual([m["id"] for m in r2.list()[1]], [sha(message(n)) for n in (3, 1, 2, 4)])
        r2.now(100 + 14 * DAY - 1)
        self.assertEqual(r2.fetch(sha(message(3))), (200, message(3)))
        r2.now(100 + 14 * DAY)
        self.assertEqual(r2.fetch(sha(message(3)))[0], 404)
        self.assertEqual([m["id"] for m in r2.list()[1]], [sha(message(4))])
        self.assertEqual(r2.put(message(5)), 201)  # numbered after the messages read from disk
        self.assertEqual([m["id"] for m in r2.list()[1]], [sha(message(4)), sha(message(5))])

    def test_the_test_hook_is_absent_without_the_test_flag(self) -> None:
        r = self.relay(test=False)
        self.assertEqual(r.request("PUT", None, {"Content-Length": "4"}, b"1000", path="/_test/now")[0], 404)
        self.assertGreater(r.store.clock.now(), 1.7e9)  # the system's clock

    def test_the_log_holds_no_secret_and_no_mailbox_or_message_id(self) -> None:
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        logger = logging.getLogger("axt-relay")
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        self.addCleanup(logger.removeHandler, handler)
        r = self.relay()
        r.create()
        r.put(message(1))
        r.list()
        r.fetch(sha(message(1)))
        r.request("DELETE", f"v1/mailboxes/{BOX}/messages/{sha(message(1))}", OWNER)
        r.request("GET", f"v1/mailboxes/{BOX}/messages", {"Authorization": "Bearer " + WRONG})
        r.request("BREW", f"v1/mailboxes/{BOX}", OWNER)
        r.raw(
            f"GET /axt/v1/mailboxes/{BOX} HTTP/1.1 extra\r\nAuthorization: Bearer {SECRET}\r\n\r\n".encode()
        )
        r.raw(b"GET /axt/" + BOX.encode() + b"\r\n\r\n")
        text = stream.getvalue()
        self.assertIn("127.0.0.1 put 201", text)
        self.assertIn("malformed", text)
        for secret in (SECRET, WRONG, BOX, sha(message(1)), "Bearer"):
            self.assertNotIn(secret, text)

    def test_the_sweep_deletes_a_message_file_after_the_holding_time(self) -> None:
        r = self.relay()
        r.create()
        r.put(message(1))
        path = Path(self.dir) / "mailboxes" / BOX / sha(message(1))
        self.assertTrue(path.exists())
        r.now(14 * DAY - 1)
        self.assertTrue(path.exists())
        r.now(14 * DAY)  # the hook sweeps; no request touches the mailbox
        self.assertFalse(path.exists())

    def test_an_idle_mailbox_is_removed_after_90_days_and_not_before(self) -> None:
        r = self.relay()
        r.create()
        r.now(90 * DAY)
        self.assertTrue((Path(self.dir) / "mailboxes" / BOX).exists())
        self.assertEqual(r.list(), (200, []))  # an owner request: idle again from now
        r.now(90 * DAY + 90 * DAY + DAY - 1)
        self.assertTrue((Path(self.dir) / "mailboxes" / BOX).exists())
        r.now(90 * DAY + 90 * DAY + DAY)
        self.assertFalse((Path(self.dir) / "mailboxes" / BOX).exists())
        self.assertEqual(r.list(), (404, None))
        self.assertEqual(r.create(), 201)

    def test_puts_without_a_usable_content_length(self) -> None:
        r = self.relay()
        r.create()
        data = message(1)
        target = f"/axt/v1/mailboxes/{BOX}/messages/{sha(data)}"
        chunked = (
            (
                f"PUT {target} HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n{len(data):x}\r\n"
            ).encode()
            + data
            + b"\r\n0\r\n\r\n"
        )
        self.assertTrue(r.raw(chunked).startswith(b"HTTP/1.1 411 "))
        self.assertEqual(r.request("PUT", target[5:], {"Content-Length": "12x"}, b"")[0], 400)
        self.assertEqual(r.request("PUT", target[5:], {"Content-Length": "0"})[0], 400)
        both = (
            f"PUT {target} HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n"
        ).encode()
        self.assertTrue(r.raw(both).startswith(b"HTTP/1.1 400 "))
        self.assertEqual(r.list(), (200, []))

    def test_a_put_above_the_limit_is_answered_before_its_body(self) -> None:
        r = self.relay()
        r.create()
        head = (
            f"PUT /axt/v1/mailboxes/{BOX}/messages/{'0' * 64} HTTP/1.1\r\nHost: x\r\n"
            f"Content-Length: {axt_relay.MAX_SEALED + 1}\r\n\r\n"
        ).encode()
        start = time.monotonic()
        out = r.raw(head + b"\0" * 100000)
        self.assertTrue(out.startswith(b"HTTP/1.1 413 "))
        self.assertIn(b"Connection: close", out)
        self.assertLess(time.monotonic() - start, 5)

    def test_expect_100_continue_comes_only_when_the_relay_reads_the_body(self) -> None:
        r = self.relay()
        data = message(1)
        head = (
            f"PUT /axt/v1/mailboxes/{BOX}/messages/{sha(data)} HTTP/1.1\r\nHost: x\r\n"
            f"Content-Length: {len(data)}\r\nExpect: 100-continue\r\n\r\n"
        ).encode()
        self.assertTrue(r.raw(head).startswith(b"HTTP/1.1 404 "))  # no mailbox: no 100
        r.create()
        with socket.create_connection(("127.0.0.1", r.port), timeout=10) as s:
            s.sendall(head)
            self.assertTrue(s.recv(1024).startswith(b"HTTP/1.1 100 "))
            s.sendall(data)
            self.assertTrue(s.recv(1024).startswith(b"HTTP/1.1 201 "))

    def test_requests_share_a_connection(self) -> None:
        r = self.relay()
        r.create()
        data = message(1)
        put = (
            f"PUT /axt/v1/mailboxes/{BOX}/messages/{sha(data)} HTTP/1.1\r\nHost: x\r\n"
            f"Content-Length: {len(data)}\r\n\r\n"
        ).encode() + data
        get = (
            f"GET /axt/v1/mailboxes/{BOX}/messages HTTP/1.1\r\nHost: x\r\n"
            f"Authorization: Bearer {SECRET}\r\nConnection: close\r\n\r\n"
        ).encode()
        out = r.raw(put + put + get)
        self.assertEqual(re.findall(rb"HTTP/1.1 ([0-9]{3}) ", out), [b"201", b"204", b"200"])

    def test_rate_limits_answer_429_with_retry_after(self) -> None:
        r = self.relay(requests_per_minute=3, creations_per_hour=1)
        self.assertEqual(r.create(), 201)
        self.assertEqual(r.create(), 204)  # an existing mailbox is no creation
        status, headers, _ = r.request(
            "PUT",
            f"v1/mailboxes/{axt_relay.mailbox_id(bytes.fromhex(WRONG))}",
            {"Authorization": "Bearer " + WRONG},
        )
        self.assertEqual(status, 429)
        self.assertIn(int(headers["Retry-After"]), range(3500, 3601))  # an hour, less the time the test took
        status, headers, _ = r.request("GET", f"v1/mailboxes/{BOX}/messages", OWNER)
        self.assertEqual(status, 429)
        self.assertGreaterEqual(int(headers["Retry-After"]), 1)

    def test_the_room_of_a_mailbox(self) -> None:
        r = self.relay(quota_bytes=2500)
        r.create()
        self.assertEqual(r.put(message(1)), 201)  # 1,001 bytes
        self.assertEqual(r.put(message(2)), 201)  # 2,003 bytes in all
        self.assertEqual(r.put(message(600)), 507)  # 3,603 bytes would be above 2,500
        self.assertEqual(r.put(message(2)), 204)  # held already: no room needed

    def test_room_counts_only_held_messages(self) -> None:
        r = self.relay(quota_bytes=1500)
        r.create()
        self.assertEqual(r.put(message(1)), 201)
        self.assertEqual(r.put(message(2)), 507)
        r.now(14 * DAY)
        self.assertEqual(r.put(message(2)), 201)
        self.assertEqual(r.put(message(1)), 507)
        r.now(28 * DAY)
        self.assertEqual(r.put(message(1)), 201)  # held before, expired since: a new put

    def test_deleting_a_mailbox_ends_a_waiting_list(self) -> None:
        r = self.relay()
        r.create()
        result: dict[str, Any] = {}
        t = threading.Thread(target=lambda: result.setdefault("list", r.list(wait=30)))
        t.start()
        time.sleep(0.3)
        self.assertEqual(r.request("DELETE", f"v1/mailboxes/{BOX}", OWNER)[0], 204)
        t.join(10)
        self.assertEqual(result["list"], (404, None))
        self.assertFalse((Path(self.dir) / "mailboxes" / BOX).exists())


class EndToEndTest(unittest.TestCase):
    """The exchange of spec/transports.md, section 7.5, through the relay run as a program."""

    def test_the_sealed_message_of_keys_md_through_the_running_relay(self) -> None:
        sealed = sealed_example()
        self.assertEqual(
            (len(sealed), sha(sealed)),
            (1073, "64a9988bd3e1e8210d592e29115d5b3252d2e75be5c219ca67583608cfdb878a"),
        )
        directory = tempfile.mkdtemp(prefix="axt-relay-e2e-")
        self.addCleanup(shutil.rmtree, directory, True)
        proc = subprocess.Popen(  # noqa: S603 the test builds the arguments itself
            [
                sys.executable,
                str(HERE / "axt_relay.py"),
                "--storage",
                directory,
                "--port",
                "0",
                "--base-path",
                BASE,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert proc.stderr is not None  # stderr=PIPE: it is a pipe
        self.addCleanup(proc.stderr.close)
        self.addCleanup(proc.wait, 10)
        self.addCleanup(proc.terminate)
        port = None
        for line in proc.stderr:
            m = re.search(r"listening on 127\.0\.0\.1:([0-9]+)/", line)
            if m:
                port = int(m.group(1))
                break
        self.assertIsNotNone(port)
        threading.Thread(target=proc.stderr.read, daemon=True).start()
        r = Relay.__new__(Relay)
        r.port = port
        self.assertEqual(r.create(), 201)
        self.assertEqual(
            r.request(
                "PUT",
                f"v1/mailboxes/{BOX}/messages/{sha(sealed)}",
                {"Content-Type": "application/octet-stream"},
                sealed,
            )[0],
            201,
        )
        status, headers, body = r.request("GET", f"v1/mailboxes/{BOX}/messages?wait=30", OWNER)
        self.assertEqual((status, headers["Content-Type"]), (200, "application/json"))
        self.assertEqual(
            body,
            b'{"messages":[{"id":"64a9988bd3e1e8210d592e29115d5b3252d2e75be5c219ca67583608cfdb878a","size":1073}]}',
        )
        status, headers, fetched = r.request("GET", f"v1/mailboxes/{BOX}/messages/{sha(sealed)}", OWNER)
        self.assertEqual(
            (status, headers["Content-Type"], fetched), (200, "application/octet-stream", sealed)
        )
        self.assertEqual(r.request("DELETE", f"v1/mailboxes/{BOX}/messages/{sha(sealed)}", OWNER)[0], 204)
        self.assertEqual(r.list(), (200, []))
        try:
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        except ImportError:
            self.skipTest("cryptography is not installed: the fetched message is not opened")
        spec = importlib.util.spec_from_file_location(
            "keys_examples", REPO / "conformance" / "tools" / "keys_examples.py"
        )
        if spec is None or spec.loader is None:
            raise ImportError("conformance/tools/keys_examples.py cannot be loaded")
        keys = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(keys)
        obf_x25519 = hashlib.sha256(b"AXT test key, not for use: Old Brain Fix, X25519").digest()
        ctx = keys.hpke_base_context(keys.decap(fetched[1:33], obf_x25519), keys.HPKE_INFO)
        opened = keys.unpad(ChaCha20Poly1305(ctx["key"]).decrypt(ctx["base_nonce"], fetched[33:], b""))
        # the DATA message of spec/keys.md, section 7.2, signed by cat-a-log
        self.assertEqual(
            (len(opened), sha(opened)),
            (210, "68d19c518a50880136a9f7412d3e636b17422c89cf63837b7ae1a22c8abedfc3"),
        )
        cat = keys.public_key(
            hashlib.sha256(b"AXT test key, not for use: cat-a-log, old phone, Ed25519").digest()
        )
        self.assertIsNone(keys.verify_problem(cat, keys.MESSAGE_PREFIX + opened[10:-64], opened[-64:]))


# --- the interface of spec/relay-api.json ---------------------------------------------------------

API = json.loads((REPO / "spec" / "relay-api.json").read_text(encoding="utf-8"))


def resolve(node: Any) -> Any:
    """A node of the OpenAPI document with its local $ref followed."""
    while isinstance(node, dict) and "$ref" in node:
        target: Any = API
        for part in node["$ref"].removeprefix("#/").split("/"):
            target = target[part]
        node = target
    return node


def schema_problems(value: Any, schema: Any, path: str = "$") -> list[str]:
    """The subset of JSON Schema that the document's schemas use."""
    schema = resolve(schema)
    kinds = {"object": dict, "array": list, "string": str}
    t = schema.get("type")
    if t == "integer":
        if not isinstance(value, int) or isinstance(value, bool):
            return [f"{path}: not an integer"]
    elif t is not None and not isinstance(value, kinds[t]):
        return [f"{path}: not of type {t}"]
    problems = []
    if "pattern" in schema and not re.search(schema["pattern"], value):
        problems.append(f"{path}: does not match {schema['pattern']}")
    if "minimum" in schema and value < schema["minimum"]:
        problems.append(f"{path}: below {schema['minimum']}")
    if isinstance(value, dict):
        problems += [f"{path}: lacks {k}" for k in schema.get("required", []) if k not in value]
        for k, sub in schema.get("properties", {}).items():
            if k in value:
                problems += schema_problems(value[k], sub, f"{path}.{k}")
    if isinstance(value, list) and "items" in schema:
        for i, item in enumerate(value):
            problems += schema_problems(item, schema["items"], f"{path}[{i}]")
    return problems


def parse_raw(out: bytes) -> tuple[int, dict[str, str], bytes]:
    head, _, body = out.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    while lines[0].startswith("HTTP/1.1 100 "):  # an interim answer
        lines = lines[lines.index("") + 1 :] if "" in lines else lines[1:]
    headers = dict(line.split(": ", 1) for line in lines[1:])
    return int(lines[0].split(" ")[1]), headers, body


OPERATIONS = {
    "create": ("PUT", "/v1/mailboxes/{mailbox}"),
    "remove": ("DELETE", "/v1/mailboxes/{mailbox}"),
    "list": ("GET", "/v1/mailboxes/{mailbox}/messages"),
    "put": ("PUT", "/v1/mailboxes/{mailbox}/messages/{message}"),
    "fetch": ("GET", "/v1/mailboxes/{mailbox}/messages/{message}"),
    "delete": ("DELETE", "/v1/mailboxes/{mailbox}/messages/{message}"),
}
# Responses the document allows that the reference relay never gives: it answers the deletion of a
# mailbox that does not exist with 204, so that a deletion can be repeated.
NOT_GIVEN = {("remove", "404")}


class InterfaceTest(unittest.TestCase):
    """The reference relay answers every operation of spec/relay-api.json as the document says, and gives
    every response the document lists, but those of NOT_GIVEN."""

    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp(prefix="axt-relay-api-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.seen: set[tuple[str, str]] = set()

    def relay(self, **kw: Any) -> Relay:
        r = Relay(tempfile.mkdtemp(dir=self.dir), **kw)
        self.addCleanup(r.stop)
        return r

    def check(self, op: str, want: int, answer: tuple[int, dict[str, str], bytes]) -> None:
        status, headers, body = answer
        self.assertEqual(status, want, op)
        method, path = OPERATIONS[op]
        operation = API["paths"][path][method.lower()]
        self.assertIn(str(status), operation["responses"], f"{op}: {status} is not in the document")
        response = resolve(operation["responses"][str(status)])
        for name, header in response.get("headers", {}).items():
            if header.get("required"):
                self.assertIn(name, headers, f"{op} {status}")
                self.assertEqual(schema_problems(int(headers[name]), resolve(header)["schema"]), [])
        content = response.get("content")
        if content is None:
            self.assertEqual(body, b"", f"{op} {status} has a body")
        else:
            ((media, spec),) = content.items()
            self.assertEqual(headers.get("Content-Type"), media, f"{op} {status}")
            if media == "application/json":
                self.assertEqual(schema_problems(json.loads(body), spec["schema"]), [], f"{op} {status}")
        self.seen.add((op, str(status)))

    def test_the_document_names_the_operations_of_the_relay(self) -> None:
        self.assertEqual(API["openapi"], "3.1.0")
        found = {
            o["operationId"]: (m.upper(), path)
            for path, item in API["paths"].items()
            for m, o in item.items()
            if m != "parameters"
        }
        self.assertEqual(found, OPERATIONS)

    def test_the_relay_gives_every_response_of_the_document(self) -> None:
        wrong_box = axt_relay.mailbox_id(bytes.fromhex(WRONG))
        wrong = {"Authorization": "Bearer " + WRONG}
        bad = {"Authorization": "Basic " + SECRET}
        data = message(1)
        box, msg = f"v1/mailboxes/{BOX}", f"v1/mailboxes/{BOX}/messages/{sha(data)}"
        r = self.relay(quota_bytes=1500)
        self.check("create", 201, r.request("PUT", box, OWNER))
        self.check("create", 204, r.request("PUT", box, OWNER))
        self.check("put", 201, r.request("PUT", msg, {}, data))
        self.check("put", 204, r.request("PUT", msg, {}, data))
        self.check("put", 507, r.request("PUT", f"{box}/messages/{sha(message(600))}", {}, message(600)))
        self.check("put", 400, r.request("PUT", msg, {"Content-Length": "0"}))
        self.check("put", 404, r.request("PUT", f"v1/mailboxes/{wrong_box}/messages/{sha(data)}", {}, data))
        chunked = f"PUT {BASE}{msg} HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
        self.check("put", 411, parse_raw(r.raw(chunked.encode())))
        large = f"PUT {BASE}{msg} HTTP/1.1\r\nHost: x\r\nContent-Length: {axt_relay.MAX_SEALED + 1}\r\n\r\n"
        self.check("put", 413, parse_raw(r.raw(large.encode())))
        self.check("list", 200, r.request("GET", f"{box}/messages", OWNER))
        self.check("list", 200, r.request("GET", f"{box}/messages?wait=1", OWNER))
        self.check("fetch", 200, r.request("GET", msg, OWNER))
        self.check("fetch", 404, r.request("GET", f"{box}/messages/{'0' * 64}", OWNER))
        self.check("delete", 204, r.request("DELETE", msg, OWNER))
        self.check("delete", 204, r.request("DELETE", msg, OWNER))
        self.check("list", 404, r.request("GET", f"v1/mailboxes/{wrong_box}/messages", wrong))
        self.check(
            "delete", 404, r.request("DELETE", f"v1/mailboxes/{wrong_box}/messages/{sha(data)}", wrong)
        )
        self.check("list", 400, r.request("GET", f"{box}/messages?wait=61", OWNER))
        for op, target in [("create", box), ("remove", box), ("fetch", msg), ("delete", msg)]:
            method = OPERATIONS[op][0]
            self.check(op, 400, r.request(method, target + "?x", OWNER))
        for op, target in [
            ("create", box),
            ("remove", box),
            ("list", f"{box}/messages"),
            ("fetch", msg),
            ("delete", msg),
        ]:
            method = OPERATIONS[op][0]
            self.check(op, 401, r.request(method, target, {}))
            self.check(op, 401, r.request(method, target, bad))
            self.check(op, 403, r.request(method, target, wrong))
        self.check("remove", 204, r.request("DELETE", box, OWNER))
        calls = [
            ("create", box, OWNER, b""),
            ("remove", box, OWNER, b""),
            ("list", f"{box}/messages", OWNER, b""),
            ("put", msg, {}, data),
            ("fetch", msg, OWNER, b""),
            ("delete", msg, OWNER, b""),
        ]
        limited = self.relay(requests_per_minute=1)
        self.assertEqual(limited.create(), 201)
        for op, target, headers, body in calls:
            self.check(op, 429, limited.request(OPERATIONS[op][0], target, headers, body))
        failing = self.relay()

        def fail(*_: Any, **__: Any) -> Any:
            raise axt_relay.StorageError(OSError("the test's storage fails"))

        for name in ("exists", "create", "remove", "list", "open", "delete"):
            setattr(failing.store, name, fail)
        for op, target, headers, body in calls:
            self.check(op, 503, failing.request(OPERATIONS[op][0], target, headers, body))
        documented = {
            (o["operationId"], status)
            for item in API["paths"].values()
            for m, o in item.items()
            if m != "parameters"
            for status in o["responses"]
        }
        self.assertEqual(documented - self.seen, NOT_GIVEN)


if __name__ == "__main__":
    unittest.main()
