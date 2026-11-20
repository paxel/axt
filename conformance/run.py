# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Run the AXT test vectors against a library, through its adapter (spec/conformance.md).

    python3 conformance/run.py [--vectors DIR] [--category NAME ...] [--verbose] -- ADAPTER COMMAND ...

The runner starts the adapter command, asks it which categories it implements,
sends it every vector of those categories as one line of JSON on its standard
input, reads one line of JSON per vector from its standard output, and compares
the answer with the vector's expected result. It never sends the expected
result. It exits with 0 when every vector of every category the adapter
implements passed, and with 1 otherwise.

It needs Python 3.11 or later, fastavro (to decode the messages an adapter
writes) and cryptography (to open what an adapter seals). The Ed25519, X25519
and HPKE code is that of conformance/tools/keys_examples.py.
"""

import argparse
import hashlib
import importlib.util
import io
import json
import re
import subprocess
import sys
import zlib
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
FILE_FORMAT = 1
CATEGORIES = [
    "encoding",
    "types",
    "time",
    "metadata",
    "records",
    "manifest",
    "keys",
    "protocol",
    "file",
    "qr",
    "local",
    "relay",
    "relay-server",
    "sync",
    "shares",
]
HEX = re.compile(r"^(?:[0-9a-f]{2})*$")

_spec = importlib.util.spec_from_file_location("keys_examples", HERE / "tools" / "keys_examples.py")
if _spec is None or _spec.loader is None:
    raise ImportError("keys_examples.py cannot be loaded")
keys = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(keys)  # runs none of that script's checks

# --- bytes (spec/conformance.md, section 3.2) ---------------------------------------


def is_bytes_object(v: Any) -> bool:
    return isinstance(v, dict) and set(v) == {"deflate", "length", "sha256"}


def to_bytes(v: Any) -> bytes:
    """The bytes of a hex string or a deflate object."""
    if isinstance(v, str):
        if not HEX.match(v):
            raise ValueError(f"not lower-case hex: {v[:40]!r}")
        return bytes.fromhex(v)
    if is_bytes_object(v):
        d = zlib.decompressobj(-15)
        data = d.decompress(bytes.fromhex(v["deflate"]), v["length"] + 1)
        if len(data) != v["length"] or hashlib.sha256(data).hexdigest() != v["sha256"]:
            raise ValueError("a deflate object whose length or SHA-256 does not match")
        return data
    raise ValueError(f"not bytes: {v!r}"[:80])


def canonical(v: Any) -> Any:
    """A value with every deflate object replaced by the hex of its bytes, for comparison."""
    if is_bytes_object(v):
        return to_bytes(v).hex()
    if isinstance(v, dict):
        return {k: canonical(x) for k, x in v.items()}
    if isinstance(v, list):
        return [canonical(x) for x in v]
    return v


def strip_notes(v: Any) -> Any:
    if isinstance(v, dict):
        return {k: strip_notes(x) for k, x in v.items() if k != "note"}
    if isinstance(v, list):
        return [strip_notes(x) for x in v]
    return v


def diff(expected: Any, got: Any, path: str = "$") -> str | None:
    """The first difference between two JSON values, or None. Objects compare without regard to order;
    an expected {"one_of": [...]} is met by any of its values (spec/conformance.md, section 4.1)."""
    if isinstance(expected, dict) and set(expected) == {"one_of"}:
        if any(diff(e, got, path) is None for e in expected["one_of"]):
            return None
        return f"{path}: expected one of {short(expected['one_of'])}, got {short(got)}"
    if isinstance(expected, bool) or isinstance(got, bool):
        return None if expected is got else f"{path}: expected {expected!r}, got {got!r}"
    if isinstance(expected, dict) and isinstance(got, dict):
        for k in expected:
            if k not in got:
                return f"{path}: missing {k!r}"
            d = diff(expected[k], got[k], f"{path}.{k}")
            if d:
                return d
        extra = set(got) - set(expected)
        return f"{path}: unexpected {sorted(extra)}" if extra else None
    if isinstance(expected, list) and isinstance(got, list):
        if len(expected) != len(got):
            return f"{path}: expected {len(expected)} items, got {len(got)}"
        for i, (e, g) in enumerate(zip(expected, got, strict=True)):
            d = diff(e, g, f"{path}[{i}]")
            if d:
                return d
        return None
    if type(expected) is not type(got) and not (
        isinstance(expected, (int, float)) and isinstance(got, (int, float))
    ):
        return f"{path}: expected {short(expected)}, got {short(got)}"
    return None if expected == got else f"{path}: expected {short(expected)}, got {short(got)}"


def short(v: Any) -> str:
    t = json.dumps(v, ensure_ascii=False)
    return t if len(t) <= 120 else t[:100] + f"... ({len(t)} characters)"


# --- the vector files and their schema -----------------------------------------------


def validate(value: Any, schema: Any, root: Any, path: str = "$") -> list[str]:
    """The subset of JSON Schema (draft 2020-12) that vectors.schema.json uses; returns a list of problems."""
    if "$ref" in schema:
        name = schema["$ref"].split("/")[-1]
        return validate(value, root["$defs"][name], root, path)
    problems: list[str] = []
    t = schema.get("type")
    if t:
        types = t if isinstance(t, list) else [t]
        ok = any(
            {
                "object": isinstance(value, dict),
                "array": isinstance(value, list),
                "string": isinstance(value, str),
                "boolean": isinstance(value, bool),
                "null": value is None,
                "integer": isinstance(value, int) and not isinstance(value, bool),
                "number": isinstance(value, (int, float)) and not isinstance(value, bool),
            }[x]
            for x in types
        )
        if not ok:
            return [f"{path}: not of type {t}"]
    if "const" in schema and value != schema["const"]:
        problems.append(f"{path}: not {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        problems.append(f"{path}: not one of {schema['enum']}")
    if "pattern" in schema and isinstance(value, str) and not re.search(schema["pattern"], value):
        problems.append(f"{path}: does not match {schema['pattern']}")
    if "minimum" in schema and isinstance(value, (int, float)) and value < schema["minimum"]:
        problems.append(f"{path}: below {schema['minimum']}")
    if isinstance(value, dict):
        for k in schema.get("required", []):
            if k not in value:
                problems.append(f"{path}: lacks {k!r}")
        props = schema.get("properties", {})
        for k, v in value.items():
            if k in props:
                problems += validate(v, props[k], root, f"{path}.{k}")
            elif schema.get("additionalProperties") is False:
                problems.append(f"{path}: has the unknown member {k!r}")
            elif isinstance(schema.get("additionalProperties"), dict):
                problems += validate(v, schema["additionalProperties"], root, f"{path}.{k}")
    if isinstance(value, list) and "items" in schema:
        for i, v in enumerate(value):
            problems += validate(v, schema["items"], root, f"{path}[{i}]")
    if isinstance(value, list) and "minItems" in schema and len(value) < schema["minItems"]:
        problems.append(f"{path}: fewer than {schema['minItems']} items")
    for sub in schema.get("allOf", []):
        problems += validate(value, sub, root, path)
    if "oneOf" in schema:
        matches = [s for s in schema["oneOf"] if not validate(value, s, root, path)]
        if len(matches) != 1:
            problems.append(f"{path}: matches {len(matches)} of the alternatives of oneOf, not 1")
    if "if" in schema and not validate(value, schema["if"], root, path):
        problems += validate(value, schema.get("then", {}), root, path)
    return problems


def load_vectors(directory: Path, wanted: set[str]) -> dict[str, Any]:
    schema = json.loads((directory / "vectors.schema.json").read_text(encoding="utf-8"))
    files: dict[str, Any] = {}
    for name in CATEGORIES:
        if wanted and name not in wanted:
            continue
        path = directory / name / f"{name}.json"
        if not path.exists():
            continue
        doc = json.loads(path.read_text(encoding="utf-8"))
        problems = validate(doc, schema, schema)
        if doc.get("category") != name:
            problems.append(f"$.category is not {name!r}")
        if problems:
            raise SystemExit(f"{path}: not a valid vector file:\n  " + "\n  ".join(problems[:20]))
        files[name] = doc
    return files


# --- the adapter ----------------------------------------------------------------------


class Adapter:
    def __init__(self, command: list[str]) -> None:
        self.proc = subprocess.Popen(  # noqa: S603 the command is the adapter the caller names
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, encoding="utf-8", bufsize=1
        )

    def ask(self, rid: str, op: str, input: Any) -> Any:
        assert self.proc.stdin is not None and self.proc.stdout is not None  # both are pipes
        self.proc.stdin.write(json.dumps({"id": rid, "op": op, "input": input}, ensure_ascii=False) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError("the adapter ended without an answer")
        answer = json.loads(line)
        if answer.get("id") != rid:
            raise RuntimeError(f"the adapter answered {answer.get('id')!r} to {rid!r}")
        return answer

    def close(self) -> None:
        try:
            if self.proc.stdin is None:  # never: the adapter is started with a pipe
                raise RuntimeError("the adapter has no standard input")
            self.proc.stdin.close()
            self.proc.wait(30)
        except Exception:
            self.proc.kill()


# --- checks that need more than a comparison --------------------------------------------


def check_seal(vector: Any, output: Any) -> str | None:
    """A sealed message cannot be compared, since its ephemeral key is random: the runner opens it."""
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    want = vector["expected"]["accept"]["sealed"]
    if "accept" not in output or set(output["accept"]) != {"sealed"}:
        return f"expected accept with sealed, got {short(output)}"
    data = to_bytes(output["accept"]["sealed"])
    if len(data) != want["length"]:
        return f"the sealed message has {len(data)} bytes, not {want['length']}"
    if data[:1] != keys.SEALED_FORMAT:
        return "the sealed message does not begin with 01"
    try:
        shared = keys.decap(data[1:33], bytes.fromhex(want["opens_with"]))
        ctx = keys.hpke_base_context(shared, keys.HPKE_INFO)
        plain = ChaCha20Poly1305(ctx["key"]).decrypt(ctx["base_nonce"], data[33:], b"")
    except Exception as e:
        return f"the sealed message does not open: {e!r}"
    if len(plain) != keys.padded_length(len(to_bytes(want["to"]))):
        return (
            f"the padded message has {len(plain)} bytes, not {keys.padded_length(len(to_bytes(want['to'])))}"
        )
    try:
        message = keys.unpad(plain)
    except ValueError as e:
        return str(e)
    return None if message == to_bytes(want["to"]) else "the sealed message opens to other bytes"


# Replies in a session: the runner decodes and verifies each message the adapter writes (section 5.6).

KINDS = [
    "MANIFEST",
    "OFFER",
    "ACCEPT",
    "DECLINE",
    "DATA",
    "DELETE",
    "ACK",
    "ERROR",
    "DEVICE_JOIN",
    "DEVICE_ADD",
    "DEVICE_REMOVE",
    "CHANGE",
    "RESYNC",
    "FORWARD",
    "WITHDRAW",
    "PROPOSAL",
    "PROPOSAL_REPLY",
]
_schemas: dict[str, Any] = {}


def schema(name: str) -> Any:
    """A schema of the specification, with logical types removed so that ids stay text."""
    import fastavro

    def plain(t: Any) -> Any:
        if isinstance(t, list):
            return [plain(b) for b in t]
        if isinstance(t, dict):
            t = {k: plain(v) for k, v in t.items() if k != "logicalType"}
            return t["type"] if set(t) == {"type"} and isinstance(t["type"], str) else t
        return t

    if name not in _schemas:
        text = (REPO / "types" / "axt" / f"{name}.avsc").read_text(encoding="utf-8")
        _schemas[name] = fastavro.parse_schema(plain(json.loads(text)), _write_hint=False)
    return _schemas[name]


ENVELOPE_FP = bytes.fromhex("16306f71b9ce9ea8")
BODY_FPS = {
    "Offer": "7d687acaca635441",
    "Accept": "ab823d91c34f246b",
    "Decline": "c092548411bdd222",
    "Ack": "5ce076801909dd38",
    "Error": "83f3bc3dd1b3a57c",
}
BODY_OF = {"OFFER": "Offer", "ACCEPT": "Accept", "DECLINE": "Decline", "ACK": "Ack", "ERROR": "Error"}
# Between the devices of one set (spec/sync.md, section 15).
SYNC_FPS = {"Change": "c188f8c5af4d094d", "Resync": "f1fd59d5d92b76e8", "Forward": "ad3b056bbf6a4757"}
SYNC_OF = {"CHANGE": "Change", "RESYNC": "Resync", "FORWARD": "Forward"}


def written(hexed: Any, own: bytes, bodies: dict[str, str], fps: dict[str, str]) -> tuple[Any, Any]:
    """The envelope and the body of a message the adapter wrote; raises ValueError if it is not a valid
    message of its own key, signed, of one of the kinds given. Only a CHANGE, a RESYNC, a FORWARD and a
    PROPOSAL_REPLY name a record."""
    import fastavro

    m = to_bytes(hexed)
    if m[:2] != b"\xc3\x01" or m[2:10] != ENVELOPE_FP:
        raise ValueError("a reply that is not a live message of envelope format 1")
    buf = io.BytesIO(m[10:])
    env: Any = fastavro.schemaless_reader(buf, schema("Envelope"), schema("Envelope"))
    if buf.tell() != len(m) - 10 or env["format"] != 1:
        raise ValueError("a reply with bytes left over or another format")
    if env["sender"] != own:
        raise ValueError("a reply whose sender is not the adapter's key")
    if keys.verify_problem(own, keys.MESSAGE_PREFIX + m[10:-64], m[-64:]):
        raise ValueError("a reply whose signature does not verify")
    name = bodies.get(env["kind"])
    if (
        name is None
        or (env["record"] is None) == (env["kind"] in SYNC_OF or env["kind"] == "PROPOSAL_REPLY")
        or env["body"][:10] != b"\xc3\x01" + bytes.fromhex(fps[name])
    ):
        raise ValueError(f"a reply of kind {env['kind']} that is not a valid reply")
    buf = io.BytesIO(env["body"][10:])
    body: Any = fastavro.schemaless_reader(buf, schema(name), schema(name))
    if buf.tell() != len(env["body"]) - 10:
        raise ValueError("a reply body with bytes left over")
    return env, body


def reply(hexed: Any, own: bytes, peer: bytes) -> tuple[str, Any]:
    """The kind and body of a message the adapter wrote; raises ValueError if it is not a valid message of
    its own key, signed, and addressed to the peer."""
    env, body = written(hexed, own, BODY_OF, BODY_FPS)
    if body["to"] != peer:
        raise ValueError("a reply that is not addressed to the other app")
    return env["kind"], body


def said(hexed: Any, own: bytes) -> list[dict[str, Any]]:
    """What a message says that a device wrote in a `siblings` session (section 5.14): one entry for the
    message, or for an ACK one for each of its entries. Every long is written as a Stamp."""
    env, d = written(
        hexed,
        own,
        {**BODY_OF, **SYNC_OF, "PROPOSAL_REPLY": "ProposalReply"},
        {**BODY_FPS, **SYNC_FPS, "ProposalReply": "c6f8756ee30c6164"},
    )
    kind, rec = env["kind"], env["record"]
    base = {"kind": kind, "to": d["to"].hex()}
    if kind == "FORWARD":
        text = d["schema"]
        forward = {
            "record": {"id": rec["id"], "version": str(rec["version"])},
            "message_hash": hashlib.sha256(d["message"]).hexdigest(),
            "schema_hash": None if text is None else hashlib.sha256(text.encode()).hexdigest(),
        }
        return [{**base, **forward}]
    if kind == "CHANGE":
        if d["origin"] is None and any(f["value"] is None for f in d["fields"]):
            raise ValueError("a CHANGE with a null value and no key in origin")
        if len({f["name"] for f in d["fields"]}) != len(d["fields"]):
            raise ValueError("a CHANGE with a name twice")
        r, k = d["removal"], d["keep"]
        if d["origin"] is None and k is not None:
            raise ValueError("a CHANGE with a keep and no key in origin")
        if d["origin"] is not None:
            keep = k and {
                "stamp": str(k["stamp"]),
                "device": k["device"].hex(),
                "version": str(k["version"]),
                "given_up": k["given_up"],
            }
            base = {**base, "origin": d["origin"].hex(), "keep": keep}
        fields = {
            f["name"]: {
                "value": None if f["value"] is None else f["value"].hex(),
                "schema": f["schema"].hex(),
                "stamp": str(f["stamp"]),
                "device": f["device"].hex(),
            }
            for f in d["fields"]
        }
        change = {
            "record": {"id": rec["id"], "version": str(rec["version"])},
            "type": d["type"],
            "state": str(d["state"]),
            "whole": d["whole"],
            "removal": r and {"stamp": str(r["stamp"]), "device": r["device"].hex(), "stands": r["stands"]},
            "fields": fields,
        }
        return [{**base, **change}]
    if kind == "ACK":
        names = [(int(e["id"].replace("-", ""), 16), e["version"]) for e in d["records"]]
        if len(set(names)) != len(names):
            raise ValueError("an ACK with an id and version twice")
        return [
            {
                **base,
                "id": e["id"],
                "version": str(e["version"]),
                "outcome": e["outcome"],
                "receiver_version": str(e["receiver_version"]),
                "kept_fields": e["kept_fields"],
            }
            for e in d["records"]
        ]
    if kind == "ERROR":
        about = d["record"]
        error = {
            "code": d["code"],
            "message_hash": d["message_hash"].hex(),
            "record": about and {"id": about["id"], "version": str(about["version"])},
            "fingerprint": None if d["fingerprint"] is None else d["fingerprint"].hex(),
            "field": d["field"],
        }
        return [{**base, **error}]
    if kind == "OFFER":
        return [{**base, "offer_id": d["offer_id"], "schemas": [t["schema"] for t in d["types"]]}]
    if kind == "ACCEPT":
        return [{**base, "offer_id": d["offer_id"], "types": sorted(d["types"])}]
    if kind == "RESYNC":
        return [{**base, "record": {"id": rec["id"], "version": str(rec["version"])}}]
    if kind == "PROPOSAL_REPLY":
        record = {"id": rec["id"], "version": str(rec["version"])}
        return [{**base, "record": record, "proposal_id": d["proposal_id"], "answer": d["answer"]}]
    raise ValueError(f"a {kind} in a session of a device with its siblings")


# The messages of the sessions of spec/shares.md, sections 13 to 16 (section 5.15).
SHARES_FPS = {"Proposal": "7902d9122a221225", "ProposalReply": "c6f8756ee30c6164", "Error": BODY_FPS["Error"]}
SHARES_OF = {"PROPOSAL": "Proposal", "PROPOSAL_REPLY": "ProposalReply", "ERROR": "Error"}


def shares_said(hexed: Any, own: bytes) -> dict[str, Any]:
    """What a PROPOSAL, a PROPOSAL_REPLY or an ERROR that the adapter wrote says (section 5.15); raises
    ValueError if it is not a valid message of its own key, signed."""
    import fastavro

    m = to_bytes(hexed)
    if m[:2] != b"\xc3\x01" or m[2:10] != ENVELOPE_FP:
        raise ValueError("a message that is not a live message of envelope format 1")
    buf = io.BytesIO(m[10:])
    env: Any = fastavro.schemaless_reader(buf, schema("Envelope"), schema("Envelope"))
    if buf.tell() != len(m) - 10 or env["format"] != 1 or env["sender"] != own:
        raise ValueError("a message with bytes left over, another format or another sender")
    if keys.verify_problem(own, keys.MESSAGE_PREFIX + m[10:-64], m[-64:]):
        raise ValueError("a message whose signature does not verify")
    kind, rec = env["kind"], env["record"]
    name = SHARES_OF.get(kind)
    if name is None or (rec is None) != (kind == "ERROR"):
        raise ValueError(f"a {kind} that is not valid here")
    if env["body"][:10] != b"\xc3\x01" + bytes.fromhex(SHARES_FPS[name]):
        raise ValueError(f"a {kind} whose body is not its kind's schema")
    buf = io.BytesIO(env["body"][10:])
    d: Any = fastavro.schemaless_reader(buf, schema(name), schema(name))
    if buf.tell() != len(env["body"]) - 10:
        raise ValueError("a body with bytes left over")
    out: dict[str, Any] = {"kind": kind, "to": d["to"].hex()}
    if kind == "ERROR":
        r = d["record"]
        return {
            **out,
            "code": d["code"],
            "message_hash": d["message_hash"].hex(),
            "record": r and {"id": r["id"], "version": r["version"]},
            "fingerprint": None if d["fingerprint"] is None else d["fingerprint"].hex(),
            "field": d["field"],
        }
    out = {**out, "record": {"id": rec["id"], "version": rec["version"]}, "proposal_id": d["proposal_id"]}
    if kind == "PROPOSAL_REPLY":
        return {**out, "answer": d["answer"]}
    fields = {f["name"]: {"schema": f["schema"].hex(), "value": f["value"].hex()} for f in d["fields"]}
    if len(fields) != len(d["fields"]):
        raise ValueError("a PROPOSAL with a field name twice")
    return {**out, "fields": fields}


def check_shares(vector: Any, output: Any) -> str | None:
    """A session of `owner` or `proposer`: the messages the adapter wrote are compared by what they say."""
    own = keys.public_key(bytes.fromhex(vector["input"]["device"]["seed"]))
    want, got = vector["expected"]["steps"], output.get("steps")
    if not isinstance(got, list) or len(got) != len(want):
        return f"expected {len(want)} step results, got {short(got)}"
    problems: list[str] = []
    for n, (w, g) in enumerate(zip(want, got, strict=True)):
        try:
            if isinstance(g, dict) and "replies" in g:
                g = {**g, "replies": [shares_said(m, own) for m in g["replies"]]}
            if isinstance(g, dict) and g.get("message") is not None:
                g = {**g, "message": shares_said(g["message"], own)}
            if isinstance(g, dict) and "messages" in g:
                g = {**g, "messages": [shares_said(m, own) for m in g["messages"]]}
            problem = diff(w, g, f"step {n}")
        except (ValueError, KeyError, TypeError) as e:
            problem = f"step {n}: {e}"
        if problem:
            problems.append(problem)
    return "; ".join(problems) if problems else None


def check_siblings(vector: Any, output: Any) -> str | None:
    """None if every step meets its expected result, else every step that does not. The messages of a
    step are compared by what they say, in any order."""
    own = keys.public_key(bytes.fromhex(vector["input"]["device"]["seed"]))
    want, got = vector["expected"]["steps"], output.get("steps")
    if not isinstance(got, list) or len(got) != len(want):
        return f"expected {len(want)} step results, got {short(got)}"
    problems: list[str] = []
    for n, (w, g) in enumerate(zip(want, got, strict=True)):
        try:
            if "sent" in w:
                entries, place = [], dict[str, int]()
                for m in g["sent"]:
                    for entry in said(m, own):
                        if entry["kind"] == "FORWARD":
                            # The order of the FORWARD messages for one sibling counts (section 5.14).
                            entry["position"] = place.get(entry["to"], 0)
                            place[entry["to"]] = entry["position"] + 1
                        entries.append(entry)
                entries.sort(key=lambda e: json.dumps(e, sort_keys=True))
                passed = [{"to": p["to"], "manifest": to_bytes(p["manifest"]).hex()} for p in g["passed"]]
                passed.sort(key=lambda p: (p["to"], p["manifest"]))
                g = {**g, "sent": entries, "passed": passed}
                w = {**w, "passed": [{**p, "manifest": to_bytes(p["manifest"]).hex()} for p in w["passed"]]}
            problem = diff(w, g, f"step {n}")
        except (ValueError, KeyError, TypeError) as e:
            problem = f"step {n}: {e}"
        if problem:
            problems.append(problem)
    return "; ".join(problems) if problems else None


def check_session(vector: Any, output: Any) -> str | None:
    """None if every step meets its expected result, else every step that does not."""
    app = vector["input"]["app"]
    own, peer = keys.public_key(bytes.fromhex(app["seed"])), bytes.fromhex(app["peer"])
    steps, want = vector["input"]["steps"], vector["expected"]["steps"]
    got = output.get("steps")
    if not isinstance(got, list) or len(got) != len(steps):
        return f"expected {len(steps)} step results, got {short(got)}"
    problems: list[str] = []
    for n, (step, w, g) in enumerate(zip(steps, want, got, strict=False)):
        try:
            problem = check_step(step, w, g, own, peer, f"step {n}")
        except (ValueError, KeyError, TypeError) as e:
            problem = f"step {n}: {e}"
        if problem:
            problems.append(problem)
    return "; ".join(problems) if problems else None


def check_step(step: Any, w: Any, g: Any, own: bytes, peer: bytes, where: str) -> str | None:
    if "receive" in step:
        answers: dict[Any, dict[Any, Any]] = {}
        errors: list[dict[str, Any]] = []
        for r in g["replies"]:
            kind, body = reply(r, own, peer)
            if kind in ("ACCEPT", "DECLINE"):
                for t in body["types"]:
                    name, verdict = (t, "ACCEPT") if kind == "ACCEPT" else (t["type"], t["reason"])
                    if name in answers.get(body["offer_id"], {}):
                        return f"{where}: {name} answered twice"
                    answers.setdefault(body["offer_id"], {})[name] = verdict
            elif kind == "ERROR":
                errors.append(
                    {
                        "code": body["code"],
                        "message_hash": body["message_hash"].hex(),
                        "record": body["record"],
                        "fingerprint": None if body["fingerprint"] is None else body["fingerprint"].hex(),
                        "field": body["field"],
                    }
                )
            else:
                return f"{where}: a reply of kind {kind}"
        d = diff(
            {k: w[k] for k in ("outcome", "close", "answers")},
            {"outcome": g.get("outcome"), "close": g.get("close"), "answers": answers},
            where,
        )
        if d:
            return d
        if len(errors) != len(w["errors"]):
            return f"{where}: expected {len(w['errors'])} ERROR replies, got {len(errors)}"
        for e, x in zip(w["errors"], errors, strict=True):
            d = diff(e, {k: x[k] for k in e}, f"{where}.errors")  # only the members the vector lists
            if d:
                return d
        return None
    if "flush_acks" in step:
        records: list[Any] = []
        for r in g["replies"]:
            kind, body = reply(r, own, peer)
            if kind != "ACK":
                return f"{where}: a reply other than an ACK"
            records += body["records"]

        def order(entries: Any) -> list[Any]:  # in any order (section 5.6)
            return sorted(entries, key=lambda e: json.dumps(e, sort_keys=True))

        return diff(order(w["acks"]), order(records), f"{where}.acks")
    if "offer" in step:
        kind, body = reply(g["message"], own, peer)
        if kind != "OFFER":
            return f"{where}: not an OFFER"
        return diff(
            w["offer"], {"to": body["to"].hex(), "offer_id": body["offer_id"], "types": body["types"]}, where
        )
    return diff(w, g, where)


SPECIAL = {
    "seal": check_seal,
    "session": check_session,
    "siblings": check_siblings,
    "owner": check_shares,
    "proposer": check_shares,
}


def check(vector: Any, output: Any) -> str | None:
    """None if the output meets the vector's expected result, else what differs."""
    special = SPECIAL.get(vector["op"])
    if special:
        return special(vector, output)
    return diff(canonical(strip_notes(vector["expected"])), canonical(strip_notes(output)))


# --- run ---------------------------------------------------------------------------------


def main() -> None:
    ap = argparse.ArgumentParser(description="Run the AXT test vectors against an adapter.")
    ap.add_argument(
        "--vectors", type=Path, default=REPO / "vectors", help="the vector directory (default: vectors/)"
    )
    ap.add_argument("--category", action="append", default=[], help="run only this category (repeatable)")
    ap.add_argument("--verbose", action="store_true", help="name every vector, not only the failures")
    ap.add_argument("command", nargs=argparse.REMAINDER, help="the adapter command, after --")
    args = ap.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        ap.error("no adapter command")
    files = load_vectors(args.vectors, set(args.category))
    adapter = Adapter(command)
    try:
        hello = adapter.ask("hello", "hello", {"format": FILE_FORMAT})
        declared = hello.get("output", {}).get("categories", [])
        unknown = sorted(set(declared) - set(CATEGORIES))
        if unknown:
            raise SystemExit(f"the adapter declares unknown categories: {unknown}")
        print(f"adapter: {hello.get('output', {}).get('name', '?')}; categories: {', '.join(declared)}")
        failures: list[tuple[str, str]] = []
        totals: dict[str, tuple[int, int]] = {}
        for name, doc in files.items():
            if name not in declared:
                print(f"{name}: not implemented by the adapter, {len(doc['vectors'])} vectors not run")
                continue
            passed = 0
            for vector in doc["vectors"]:
                try:
                    answer = adapter.ask(vector["id"], vector["op"], vector["input"])
                    if "output" not in answer:
                        problem: str | None = (
                            "unsupported"
                            if answer.get("unsupported")
                            else f"adapter failure: {answer.get('failure')}"
                        )
                    else:
                        problem = check(vector, answer["output"])
                except (ValueError, KeyError, TypeError) as e:
                    problem = f"malformed answer: {e!r}"
                if problem:
                    failures.append((vector["id"], problem))
                    print(f"FAIL {vector['id']}: {problem}")
                else:
                    passed += 1
                    if args.verbose:
                        print(f"pass {vector['id']}")
            totals[name] = (passed, len(doc["vectors"]))
            print(f"{name}: {passed} of {len(doc['vectors'])} vectors passed")
    finally:
        adapter.close()
    ran = sum(n for _, n in totals.values())
    print(f"total: {ran - len(failures)} of {ran} vectors passed in {len(totals)} categories")
    sys.exit(1 if failures or not totals else 0)


if __name__ == "__main__":
    main()
