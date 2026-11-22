# SPDX-License-Identifier: Apache-2.0 OR MIT
"""The reference adapter of the AXT conformance suite (spec/conformance.md, section 6).

    python3 conformance/run.py -- python3 conformance/reference/adapter.py

It answers every operation of the suite with the code of the example scripts in
conformance/tools/, which check the examples of the specification: the Avro
encoding and the schema checks of example_types.py and manifest_examples.py,
the Ed25519, X25519 and HPKE of keys_examples.py and its model of a receiver
that follows the devices of its senders, the model of an app of
protocol_examples.py, the QR code, frames and relay of
transports_examples.py, the time types of time_examples.py, and the attributes of spec/metadata.md of
metadata_rules.py, and the stamps, the merge and the model of a device with
its siblings of spec/sync.md of sync_examples.py, and the receiver of withdrawals, the sending
device, the owner that takes proposals and the proposer of spec/shares.md of shares_examples.py.
Where those scripts have no model, for a receiver's own changes to records (spec/records.md,
section 6) and for reading a file (spec/transports.md, section 2.2), it has its own code below. That it passes
every vector shows that the vectors agree with the scripts' checks; it is a
test of the vectors, not a library.

It needs what the example scripts need: fastavro, avro (1.12), pynacl,
cryptography, and a time zone database where Python's zoneinfo finds it. Every key it uses comes
from the request; it holds none itself.
"""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import sys
import zlib
from collections.abc import Callable, Iterable
from pathlib import Path
from types import ModuleType
from typing import Any

HERE = Path(__file__).resolve().parent
TOOLS = HERE.parent / "tools"


def load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, TOOLS / f"{name}.py")
    if spec is None or spec.loader is None:
        raise ImportError(f"{name}.py cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    with contextlib.redirect_stdout(io.StringIO()):
        spec.loader.exec_module(module)
    return module


tx = load("transports_examples")
pe, me, keys, rules = tx.pe, tx.me, tx.keys, tx.rules
tm = load("time_examples")
sy = load("sync_examples")
se = load("shares_examples")
mr = rules.mr

import fastavro  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305  # noqa: E402

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
    "bricks",
]
OUT_INLINE = 1 << 20  # bytes above which an answer carries raw DEFLATE rather than hex


# --- bytes ----------------------------------------------------------------------------


def b_in(v: Any) -> Any:
    if v is None:
        return None
    if isinstance(v, str):
        return bytes.fromhex(v)
    data = zlib.decompressobj(-15).decompress(bytes.fromhex(v["deflate"]), v["length"] + 1)
    if len(data) != v["length"] or hashlib.sha256(data).hexdigest() != v["sha256"]:
        raise ValueError("a deflate object whose length or SHA-256 does not match")
    return data


def b_out(data: bytes | None) -> Any:
    if data is None:
        return None
    if len(data) <= OUT_INLINE:
        return data.hex()
    c = zlib.compressobj(6, zlib.DEFLATED, -15)
    return {
        "deflate": (c.compress(data) + c.flush()).hex(),
        "length": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def ok(value: Any = None) -> dict[str, Any]:
    return {"accept": {} if value is None else value}


def no(error: str, note: str | None = None, **members: Any) -> dict[str, Any]:
    return {"reject": dict({"error": error}, **({} if note is None else {"note": note}), **members)}


# --- a strict Avro decoder ----------------------------------------------------------------

MAX_DATA_DEPTH = 32  # spec/types.md, section 5.7
PRIMITIVES = {"null", "boolean", "int", "long", "float", "double", "bytes", "string"}


class Undecodable(Exception):
    pass


class Reader:
    def __init__(self, data: bytes, pos: int = 0) -> None:
        self.data, self.pos = data, pos

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise Undecodable("a length below 0 or beyond the end")
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def long(self, bits: int = 64) -> int:
        shift = result = 0
        for _ in range(10):
            b = self.take(1)[0]
            result |= (b & 0x7F) << shift
            shift += 7
            if not b & 0x80:
                value = (result >> 1) ^ -(result & 1)
                if not -(1 << (bits - 1)) <= value < 1 << (bits - 1):
                    raise Undecodable("an int out of range")
                return value
        raise Undecodable("a varint of more than 10 bytes")


def named(t: dict[str, Any], names: dict[str, Any], namespace: str) -> str:
    """Register a named type under its full name; return the namespace its children inherit."""
    name = t["name"]
    ns: str = name.rpartition(".")[0] if "." in name else t.get("namespace", namespace)
    full = name if "." in name else (f"{ns}.{name}" if ns else name)
    names[full] = t
    names.setdefault(name, t)
    return ns


def all_named(t: Any, names: dict[str, Any], namespace: str = "") -> dict[str, Any]:
    """Register every named type that the schema defines, also those in an empty array or map or in a branch
    a value does not take, which a later reference by name needs."""
    if isinstance(t, list):
        for b in t:
            all_named(b, names, namespace)
    elif isinstance(t, dict):
        if t.get("type") in ("record", "enum", "fixed"):
            namespace = named(t, names, namespace)
        for f in t.get("fields", []):
            all_named(f["type"], names, namespace)
        for member in ("items", "values"):
            if member in t:
                all_named(t[member], names, namespace)
    return names


def branch_name(b: Any, namespace: str) -> str:
    """The full name of a named branch of a union, or "" for another."""
    if isinstance(b, dict):
        if b.get("type") not in ("record", "enum", "fixed"):
            return ""
        name = b["name"]
        ns = name.rpartition(".")[0] if "." in name else b.get("namespace", namespace)
        return name if "." in name else (f"{ns}.{name}" if ns else name)
    if b in PRIMITIVES:
        return ""
    return b if "." in b else (f"{namespace}.{b}" if namespace else b)


# The data depth up to which a body is read: 32 for a record (spec/types.md, section 5.7), more for the
# body of an OFFER, whose descriptions nest deeper (spec/fields.md, section 10.1).
DEPTH_LIMIT = [MAX_DATA_DEPTH]
MAX_OFFER_DEPTH = 256


def read(t: Any, r: Reader, names: dict[str, Any], namespace: str = "", depth: int = 0) -> Any:
    """Decode one value of the schema t, strictly; return its meaning as JSON (spec/conformance.md,
    section 3.3)."""
    if isinstance(t, str):
        if t not in PRIMITIVES:
            ref = names.get(t) or names.get(f"{namespace}.{t}")
            if ref is None:
                raise ValueError(f"unknown type {t}")
            return read(ref, r, names, namespace, depth)
        if t == "null":
            return None
        if t == "boolean":
            b = r.take(1)[0]
            if b > 1:
                raise Undecodable("a boolean other than 0 or 1")
            return b == 1
        if t == "int":
            return r.long(32)
        if t == "long":
            return r.long()
        if t == "float":
            import struct

            return struct.unpack("<f", r.take(4))[0]
        if t == "double":
            import struct

            return struct.unpack("<d", r.take(8))[0]
        data = r.take(r.long())
        if t == "bytes":
            return data.hex()
        try:
            return data.decode("utf-8")  # rejects surrogates and overlong forms (spec/envelope.md, section 7)
        except UnicodeDecodeError:
            raise Undecodable("a string that is not well-formed UTF-8") from None
    if isinstance(t, list):
        i = r.long()
        if not 0 <= i < len(t):
            raise Undecodable("a union index out of range")
        value = read(t[i], r, names, namespace, depth)
        if isinstance(t[0], (dict, str)) and branch_name(t[0], namespace) == "axt.StringField":
            # The union kind of axt.Field: the branch is named (spec/conformance.md, section 3.3).
            return {branch_name(t[i], namespace): value}
        return value
    kind = t["type"]
    if kind in ("record", "enum", "fixed"):
        namespace = named(t, names, namespace)
    if kind == "record":
        if depth + 1 > DEPTH_LIMIT[0]:
            raise Undecodable("a data depth above 32")
        return {f["name"]: read(f["type"], r, names, namespace, depth + 1) for f in t["fields"]}
    if kind == "enum":
        i = r.long()
        if not 0 <= i < len(t["symbols"]):
            raise Undecodable("an enum index out of range")
        return t["symbols"][i]
    if kind == "fixed":
        return r.take(t["size"]).hex()
    if kind in ("array", "map"):
        if depth + 1 > DEPTH_LIMIT[0]:
            raise Undecodable("a data depth above 32")
        out: Any = [] if kind == "array" else {}
        while True:
            n = r.long()
            if n == 0:
                return out
            if n < 0:
                n = -n
                r.long()  # the block's size in bytes
            if n > len(r.data) - r.pos:
                raise Undecodable("a count beyond the end")  # every item takes at least one byte
            for _ in range(n):
                if kind == "array":
                    out.append(read(t["items"], r, names, namespace, depth + 1))
                else:
                    key = read("string", r, names, namespace, depth + 1)
                    out[key] = read(t["values"], r, names, namespace, depth + 1)
    return read(kind, r, names, namespace, depth)


def decode_all(t: Any, data: bytes) -> Any:
    r = Reader(data)
    value = read(t, r, all_named(t, {}))
    if r.pos != len(data):
        raise Undecodable("bytes left over")
    return value


def record_of(t: Any, names: dict[str, Any], namespace: str) -> Any:
    """A record of a union, given in place or by its name."""
    if isinstance(t, str):
        return names.get(t) or names[f"{namespace}.{t}"]
    return t


def json_of(t: Any, value: Any, names: dict[str, Any] | None = None, namespace: str = "") -> Any:
    """The meaning of a value as fastavro decodes it with logical types removed."""
    names = all_named(t, {}) if names is None else names
    if isinstance(t, str):
        if t not in PRIMITIVES:
            return json_of(names.get(t) or names[f"{namespace}.{t}"], value, names, namespace)
        if t == "bytes":
            return (value.encode("latin-1") if isinstance(value, str) else value).hex()
        return value
    if isinstance(t, list):
        if value is None:
            return None
        branches = [b for b in t if b != "null"]
        if len(branches) > 1:  # the targets of axt.Relation: the record whose fields the value has
            branches = [
                b
                for b in branches
                if {f["name"] for f in record_of(b, names, namespace)["fields"]} == set(value)
            ]
        (branch,) = branches
        return json_of(branch, value, names, namespace)
    kind = t["type"]
    if kind in ("record", "enum", "fixed"):
        namespace = named(t, names, namespace)
    if kind == "record":
        return {f["name"]: json_of(f["type"], value[f["name"]], names, namespace) for f in t["fields"]}
    if kind == "fixed":
        return value.hex()
    if kind == "array":
        return [json_of(t["items"], v, names, namespace) for v in value]
    if kind == "map":
        return {k: json_of(t["values"], v, names, namespace) for k, v in value.items()}
    if kind == "enum":
        return value
    return json_of(kind, value, names, namespace)


def plain_schema(text: str) -> Any:
    return pe.without_logical_types(json.loads(text))


# --- encoding (spec/envelope.md) -----------------------------------------------------------

ENVELOPE = plain_schema(pe.texts["Envelope"])
ENVELOPE_FP = pe.fp8(pe.fingerprints["Envelope"][1])
MAX_MESSAGE = pe.MAX_MESSAGE


def decode_envelope(m: bytes) -> tuple[Any, str | None]:
    """The envelope of a live message, or the error code of spec/protocol.md, section 8.2."""
    if len(m) > MAX_MESSAGE:
        return None, "TOO_LARGE"
    if len(m) < 10 or m[:2] != b"\xc3\x01":
        return None, "INVALID_MESSAGE"
    if m[2:10] != ENVELOPE_FP:
        return None, "FORMAT_UNSUPPORTED"
    try:
        d = decode_all(ENVELOPE, m[10:])
    except Undecodable:
        return None, "INVALID_MESSAGE"
    if d["format"] != 1:
        return None, "INVALID_MESSAGE"  # the format of the fingerprint (spec/keys.md, section 2.2)
    return d, None


def op_decode_message(i: Any) -> dict[str, Any]:
    d, error = decode_envelope(b_in(i["message"]))
    if error:
        return no(error)
    return ok(dict(d, body=b_out(bytes.fromhex(d["body"]))))


def op_encode_message(i: Any) -> dict[str, Any]:
    zz = keys.zigzag
    out = b"\xc3\x01" + ENVELOPE_FP + zz(i["format"]) + zz(pe.KINDS.index(i["kind"])) + b_in(i["sender"])
    rec = i["record"]
    if rec is None:
        out += zz(0)
    else:
        rid = rec["id"].encode()
        out += zz(1) + zz(len(rid)) + rid + zz(rec["version"])
    body = b_in(i["body"])
    return ok({"message": b_out(out + zz(len(body)) + body + b_in(i["signature"]))})


def op_decode_body(i: Any) -> dict[str, Any]:
    """The body of a kind whose schema the specification publishes (spec/envelope.md, section 2.3)."""
    name = pe.BODY_SCHEMA[i["kind"]]
    body = b_in(i["body"])
    if body[:10] != b"\xc3\x01" + pe.fp8(pe.fingerprints[name][1]):
        return no("INVALID_MESSAGE", f"not an axt.{name}")
    DEPTH_LIMIT[0] = MAX_OFFER_DEPTH if name == "Offer" else MAX_DATA_DEPTH
    try:
        return ok({"value": decode_all(plain_schema(pe.texts[name]), body[10:])})
    except Undecodable as e:
        return no("INVALID_MESSAGE", str(e))
    finally:
        DEPTH_LIMIT[0] = MAX_DATA_DEPTH


# --- bricks (spec/fields.md) -----------------------------------------------------------------------


def op_derive(i: Any) -> dict[str, Any]:
    """The schema derived from a description, its canonical form and its fingerprint (sections 9.2, 9.3)."""
    fe = pe.fe
    try:
        d = fe.read(b_in(i["description"]), fe.PARSED)
    except Exception as e:
        return no("UNDECODABLE", f"not a datum of axt.Field: {type(e).__name__}")
    problems = fe.description_problems(d)
    if problems:
        where, problem = problems[0]
        return no("DESCRIPTION_INVALID", f"{where or 'the root'}: {problem}")
    text = fe.derived_text(d)
    pcf, fp = me.fingerprint(text)
    return ok({"schema": text, "canonical_form": pcf, "fingerprint": pe.fp8(fp).hex()})


def op_fingerprint(i: Any) -> dict[str, Any]:
    pcf, fp = me.fingerprint(i["schema"])
    return ok({"canonical_form": pcf, "fingerprint": pe.fp8(fp).hex()})


# --- types (spec/types.md) ----------------------------------------------------------------


def decode_value(writer_text: str, body: bytes, reader: Any = None) -> tuple[Any, dict[str, Any] | None]:
    """The value of a single-object encoding with the writer schema, before any check of its values; or a
    rejection. With a reader schema, a writer schema that does not resolve to it is rejected before the
    body is decoded."""
    if body[:2] != b"\xc3\x01" or len(body) < 10:
        return None, no("UNDECODABLE", "not a single-object encoding")
    if body[2:10] != pe.fp8(pe.canonical_fp(writer_text)):
        return None, no("SCHEMA_UNKNOWN")
    if reader is not None and not pe.resolves(json.loads(writer_text), reader):
        return None, no("DOES_NOT_RESOLVE")
    try:
        return decode_all(pe.without_logical_types(json.loads(writer_text)), body[10:]), None
    except Undecodable as e:
        return None, no("UNDECODABLE", str(e))


def op_decode_record(i: Any) -> dict[str, Any]:
    writer_text, reader_text, body = i["writer_schema"], i["reader_schema"], b_in(i["body"])
    writer = json.loads(writer_text)
    reader = None if reader_text is None else json.loads(reader_text)
    value, rejected = decode_value(writer_text, body, reader)
    if rejected:
        return rejected
    # Step 9 of spec/protocol.md, section 6.2: a value that decodes but holds a time value that is not valid.
    broken = tm.value_breaches(pe.without_logical_types(writer), value)
    if broken:
        path, rule, why = broken[0]
        return no("VALUE_INVALID", f"{rule}: {why} (spec/time.md, section 8)", field=mr.error_field(path))
    if reader_text is None:
        return ok({"value": value})
    w, r = pe.without_logical_types(writer), pe.without_logical_types(reader)
    try:
        resolved = fastavro.schemaless_reader(
            io.BytesIO(body[10:]),
            fastavro.parse_schema(w, _write_hint=False),
            fastavro.parse_schema(r, _write_hint=False),
        )
    except Exception as e:
        return no("DOES_NOT_RESOLVE", str(e))
    return ok({"value": json_of(r, resolved)})


# --- metadata (spec/metadata.md) ------------------------------------------------------------


def op_describe(i: Any) -> dict[str, Any]:
    return ok(mr.describe(json.loads(i["schema"]), i["field"], i["languages"]))


def op_check_record(i: Any) -> dict[str, Any]:
    """A receiver that checks the attributes: the first value, in the order of the encoding, that breaks a
    rule, whether a check of an attribute or a rule of a time type (spec/conformance.md, section 5.13)."""
    value, rejected = decode_value(i["schema"], b_in(i["body"]))
    if rejected:
        return rejected
    writer = pe.without_logical_types(json.loads(i["schema"]))
    broken = tm.receiver_breaches(writer, value)
    if broken:
        path, rule, why = broken[0]
        return no("VALUE_INVALID", f"{rule}: {why}", field=mr.error_field(path))
    return ok()


# --- manifest (spec/manifest.md) ------------------------------------------------------------

MANIFEST = plain_schema(pe.texts["Manifest"])
MANIFEST_FP = pe.fp8(pe.fingerprints["Manifest"][1])


def manifest_datum(body: bytes) -> tuple[Any, Any, str | None]:
    """The manifest as fastavro decodes it, after a strict check of its bytes; or an error code."""
    if body[:10] != b"\xc3\x01" + MANIFEST_FP:
        return None, None, "INVALID_MESSAGE"
    try:
        meaning = decode_all(MANIFEST, body[10:])
    except Undecodable:
        return None, None, "INVALID_MESSAGE"
    datum = fastavro.schemaless_reader(io.BytesIO(body[10:]), pe.raw["Manifest"], pe.raw["Manifest"])
    return datum, meaning, None


def op_check_manifest(i: Any) -> dict[str, Any]:
    body = b_in(i["body"])
    datum, meaning, error = manifest_datum(body)
    if error:
        return no(error)
    problems = me.manifest_problems(datum, len(body), i["envelope_format"])
    return no("MANIFEST_INVALID", problems[0]) if problems else ok({"manifest": meaning})


def op_fit(i: Any) -> dict[str, Any]:
    datum, _, error = manifest_datum(b_in(i["manifest"]))
    if error:
        return no(error)
    schema = json.loads(i["schema"])
    entry = me.fit(datum, pe.full_name(schema), me.schema_version(schema))
    return ok(
        {"fits": entry is not None, "purpose": None if entry is None else me.sentence(entry, i["languages"])}
    )


# --- records (spec/records.md) ---------------------------------------------------------------
# protocol_examples.py has no model of a receiver's own changes; this is the adapter's own.


def record_key(rid: str) -> int | None:
    """The id as a 128-bit value, or None if it is not a UUID in text form or is the nil or max UUID."""
    if pe.uuid_problem(rid):
        return None
    return int(rid.replace("-", ""), 16)


class Receiver:
    """The records of one sender at a receiver that lets its user change them (spec/records.md, sections 5
    and 6)."""

    def __init__(
        self, local_changes: str, delete_with_local_changes: str, extensions: Iterable[str] = ()
    ) -> None:
        # None is the key of an id that is not valid; no record is ever stored under it.
        self.records: dict[int | None, dict[str, Any]]
        self.mode, self.keep_on_delete, self.records = local_changes, delete_with_local_changes == "keep", {}
        # The schemas of the extension types the receiver knows, by their fingerprints (fields.md 12.2).
        self.texts = {sy.schema_fingerprint(t): t for t in extensions}

    def result(self, outcome: str, r: dict[str, Any], kept: Iterable[str] = ()) -> dict[str, Any]:
        return {
            "outcome": outcome,
            "receiver_version": r["version"],
            "kept_fields": sorted(kept),
            "state": r["state"],
            "value": None if r["state"] != "there" else dict(r["value"]),
        }

    def message(self, m: Any) -> dict[str, Any]:
        key = record_key(m["id"])
        if key is None:
            return {"error": "RECORD_ID_INVALID"}
        if m["version"] < 1:
            return {"error": "VERSION_INVALID"}
        r = self.records.get(key)
        is_data = m["kind"] == "DATA"
        if is_data and r is not None and r["type"] is not None and r["type"] != m["type"]:
            return {"error": "TYPE_CHANGED"}
        if r is not None and m["version"] <= r["version"]:
            return self.result("DUPLICATE" if m["version"] == r["version"] else "STALE", r)
        if r is None:
            r = self.records[key] = {
                "type": m["type"] if is_data else None,
                "version": m["version"],
                "state": "there" if is_data else "tombstone",
                "value": dict(m["value"]) if is_data else None,
                "changed": set(),
                "taken": dict(m["value"]) if is_data else {},  # the value last taken from the sender
            }
            return self.result("APPLIED", r)
        r["version"] = m["version"]
        if not is_data:
            if r["state"] == "deleted_by_user":
                # The user's deletion goes on standing beside the sender's tombstone (records.md 6.3).
                return self.result("APPLIED", r)
            if r["state"] == "there" and r["changed"] and self.keep_on_delete:
                return self.result("KEPT", r)
            r.update(state="tombstone", value=None, changed=set())
            return self.result("APPLIED", r)
        r["type"] = m["type"]
        if r["state"] == "tombstone":  # the record comes back as a new record under the same id
            r.update(state="there", value=dict(m["value"]), changed=set(), taken=dict(m["value"]))
            return self.result("APPLIED", r)
        if r["state"] == "deleted_by_user":
            return self.result("KEPT", r)
        if not r["changed"] or self.mode == "whole_record_take":
            r.update(value=dict(m["value"]), changed=set(), taken=dict(m["value"]))
            return self.result("APPLIED", r)
        if self.mode == "whole_record_keep":
            return self.result("KEPT", r)
        value = dict(m["value"])
        lists = sy.element_fields(m["type"])
        for f in r["changed"]:
            if f in r["value"]:
                # A list merged per element (records.md, section 6.1).
                mine = r["value"][f]
                value[f] = (
                    sy.merge_elements(r["taken"].get(f, []), mine, value[f], lists[f], self.texts)
                    if f in lists
                    else mine
                )
        kept = [f for f in r["changed"] if f in value and value[f] != m["value"].get(f)]
        r.update(value=value, taken=dict(m["value"]))
        return self.result("MERGED" if kept else "APPLIED", r, kept)

    def local_change(self, rid: str, field: str, value: Any) -> None:
        r = self.records[record_key(rid)]
        r["value"][field] = value
        r["changed"].add(field)

    def local_delete(self, rid: str) -> None:
        self.records[record_key(rid)].update(state="deleted_by_user", value=None)


def op_apply(i: Any) -> dict[str, Any]:
    receiver = Receiver(
        i["policy"]["local_changes"], i["policy"]["delete_with_local_changes"], i.get("extensions", [])
    )
    steps: list[dict[str, Any]] = []
    for e in i["events"]:
        if "message" in e:
            steps.append(receiver.message(e["message"]))
        elif "local_change" in e:
            receiver.local_change(
                e["local_change"]["id"], e["local_change"]["field"], e["local_change"]["value"]
            )
            steps.append({})
        else:
            receiver.local_delete(e["local_delete"]["id"])
            steps.append({})
    return {"steps": steps}


# --- protocol (spec/protocol.md) -----------------------------------------------------------

OUTCOMES = ("APPLIED", "DUPLICATE", "STALE", "WITHDRAWN")


def op_session(i: Any) -> dict[str, Any]:
    """One app in one live connection, as the model of protocol_examples.py plays it."""
    cfg = i["app"]
    manifest, _, error = manifest_datum(b_in(cfg["manifest"]))
    readers = {n: json.loads(t) for n, t in cfg["readers"].items()}
    takes = set(cfg["user_takes"])
    app = pe.App(
        "adapter",
        b_in(cfg["seed"]),
        manifest,
        readers,
        lambda n: n in takes,
        formats=cfg["formats"],
        peer_key=b_in(cfg["peer"]),
    )
    out: list[dict[str, Any]] = []
    for step in i["steps"]:
        if "receive" in step:
            what, replies = app.receive(b_in(step["receive"]))
            out.append(
                {
                    "outcome": what if what in OUTCOMES else None,
                    "close": what.endswith(": close"),
                    "replies": [b_out(r) for r in replies],
                }
            )
        elif "flush_acks" in step:
            m = app.ack()
            out.append({"replies": [] if m is None else [b_out(m)]})
        elif "offer" in step:
            o = step["offer"]
            _, m = app.offer(
                o["offer_id"],
                [(pe.fe.from_json_form(t["description"]), t["count"], None) for t in o["types"]],
                check=False,
            )
            out.append({"message": b_out(m)})
        elif "close" in step:
            app.close()
            out.append({})
        else:
            ((what, arg),) = step["query"].items()
            if what == "accepted":
                out.append({"accepted": app.accepted(arg)})
            elif what == "outcome":
                out.append({"outcome": app.outcomes.get((arg["id"].lower(), arg["version"]))})
            elif what == "record":
                r = app.records.get(arg.lower())
                out.append({"record": None if r is None else {"version": r["version"], "state": r["state"]}})
            else:
                out.append({"errors": list(app.errors)})
    return {"steps": out}


# --- file (spec/transports.md, section 2) -----------------------------------------------------
# The scripts write files but have no reader model; this is the adapter's own reader.

MAX_FILE, MAX_META, MAX_BLOCK, MAX_TOTAL = (
    268435456,
    8388608,
    67108864,
    1073741824,
)  # spec/envelope.md, section 8
ENVELOPE_PCF = pe.fingerprints["Envelope"][0]
LOWER_HEX = __import__("re").compile(r"^[0-9a-f]*$")
CHAIN_SCHEMAS = {"DEVICE_ADD": "DeviceAdd", "DEVICE_REMOVE": "DeviceRemove"}


class FileRejected(Exception):
    pass


def inflate(payload: bytes, limit: int) -> bytes:
    d = zlib.decompressobj(-15)
    out = d.decompress(payload, limit + 1)
    if len(out) > limit:
        raise FileRejected("a block above 64 MiB after decompression")
    if d.unconsumed_tail or not d.eof:
        raise FileRejected("a block that is not complete raw DEFLATE")
    return out


def file_messages(data: bytes) -> tuple[dict[str, bytes], list[bytes]]:
    """The metadata and the datums of an AXT file, after the checks that reject a whole file."""
    if len(data) > MAX_FILE:
        raise FileRejected("above 256 MiB")
    if data[:4] != b"Obj\x01":
        raise FileRejected("not an Avro object container file")
    r = Reader(data, 4)
    try:
        meta = decode_meta(r)
    except Undecodable as e:
        raise FileRejected(str(e)) from e
    if sum(len(k) + len(v) for k, v in meta.items()) > MAX_META:
        raise FileRejected("metadata above 8 MiB")
    sync = r.take(16) if len(data) - r.pos >= 16 else None
    if sync is None:
        raise FileRejected("no sync marker")
    codec = meta.get("avro.codec", b"null")
    if codec not in (b"null", b"deflate"):
        raise FileRejected("a codec other than null or deflate")
    try:
        schema = json.loads(meta["avro.schema"])
        pcf = fastavro.schema.to_parsing_canonical_form(fastavro.parse_schema(schema, _write_hint=False))
    except Exception:
        raise FileRejected("no avro.schema of a schema") from None
    if pcf != ENVELOPE_PCF:
        raise FileRejected("avro.schema is not a supported envelope format")
    datums: list[bytes] = []
    total = 0
    while r.pos < len(data):
        try:
            count, size = r.long(), r.long()
            payload = r.take(size)
        except Undecodable as e:
            raise FileRejected(str(e)) from e
        if r.take(16) != sync if len(data) - r.pos >= 16 else True:
            raise FileRejected("a block without its sync marker")
        block = inflate(payload, MAX_BLOCK) if codec == b"deflate" else payload
        if len(block) > MAX_BLOCK:
            raise FileRejected("a block above 64 MiB")
        total += len(block)
        if total > MAX_TOTAL:
            raise FileRejected("above 1 GiB after decompression")
        at = 0
        for _ in range(count):
            try:
                end = keys.envelope_end(block, at)
            except IndexError:
                raise FileRejected("a datum cut short") from None
            if end > len(block):
                raise FileRejected("a datum cut short")
            datums.append(block[at:end])
            at = end
        if at != len(block) or count < 0:
            raise FileRejected("bytes left over in a block")
    return meta, datums


def decode_meta(r: Reader) -> dict[str, bytes]:
    meta: dict[str, bytes] = {}
    while True:
        n = r.long()
        if n == 0:
            return meta
        if n < 0:
            n = -n
            r.long()
        for _ in range(n):
            key = r.take(r.long()).decode("utf-8", "strict")
            meta[key] = r.take(r.long())


def header_sender(meta: dict[str, bytes]) -> bytes:
    """The file's sender, after the header signature of spec/keys.md, section 2.5, has verified."""
    sender, sig = meta.get("axt.sender"), meta.get("axt.signature")
    for v, n in ((sender, 64), (sig, 128)):
        if v is None or len(v) != n or not LOWER_HEX.match(v.decode("latin-1")):
            raise FileRejected(
                "axt.sender or axt.signature missing or not lower-case hexadecimal of the right length"
            )
    assert sender is not None and sig is not None  # the loop above rejects a missing one
    sender = bytes.fromhex(sender.decode())
    value = meta.get("axt.schemas", b"")
    if keys.key_problem(sender) or keys.verify_problem(
        sender, keys.FILE_HEADER_PREFIX + sender + hashlib.sha256(value).digest(), bytes.fromhex(sig.decode())
    ):
        raise FileRejected("the header signature does not verify")
    return sender


def op_read_file(i: Any) -> dict[str, Any]:
    try:
        return read_file(b_in(i["file"]), i["reader"])
    except FileRejected as e:
        return no("FILE_REJECTED", str(e))


def read_file(data: bytes, reader: Any) -> dict[str, Any]:
    meta, datums = file_messages(data)
    sender = header_sender(meta)
    schemas: dict[int, str] = {}
    if "axt.schemas" in meta:
        try:
            for text in pe.fe.file_schemas(meta["axt.schemas"]):
                fp = pe.canonical_fp(text)
                if fp in schemas:
                    raise FileRejected("two schemas with one fingerprint in axt.schemas")
                schemas[fp] = text
        except FileRejected:
            raise
        except Exception:
            raise FileRejected("axt.schemas is not a JSON array of descriptions and their schemas") from None
    messages: list[tuple[str, Any, bytes]]
    chain: list[tuple[str, bytes, bytes, None]]
    manifests: list[bytes]
    messages, chain, manifests, seen_other, seen_record = [], [], [], False, False
    for d in datums:
        try:
            env = decode_all(ENVELOPE, d)
        except Undecodable as e:
            raise FileRejected(str(e)) from e
        if env["format"] != 1:
            raise FileRejected("a datum whose format is not the file's")
        key = bytes.fromhex(env["sender"])
        if keys.verify_problem(key, keys.MESSAGE_PREFIX + d[:-64], d[-64:]):
            raise FileRejected("a message whose signature does not verify")
        kind, body, record = env["kind"], bytes.fromhex(env["body"]), env["record"]
        if kind not in (*CHAIN_SCHEMAS, "MANIFEST", "DATA", "DELETE", "WITHDRAW"):
            raise FileRejected(f"a {kind} in a file")
        if (record is None) == (kind in ("DATA", "DELETE", "WITHDRAW")):
            raise FileRejected("a record where none belongs, or none where one is required")
        if kind in CHAIN_SCHEMAS:
            name = CHAIN_SCHEMAS[kind]
            if seen_other:
                raise FileRejected(f"a {kind} after another kind of message")
            if body[:10] != b"\xc3\x01" + pe.fp8(pe.fingerprints[name][1]):
                raise FileRejected(f"a {kind} whose body is not an axt.{name}")
            try:
                dm = decode_all(pe.without_logical_types(json.loads(pe.texts[name])), body[10:])
            except Undecodable as e:
                raise FileRejected(str(e)) from e
            device = bytes.fromhex(dm["device"])
            proof = bytes.fromhex(dm["proof"]) if kind == "DEVICE_ADD" else None
            if keys.device_message_problem(kind, key, keys.MESSAGE_PREFIX + d[:-64], d[-64:], device, proof):
                raise FileRejected(f"a {kind} that fails step 2 of keys.md, section 5.5")
            chain.append((kind, key, device, None))
            continue
        seen_other = True
        if key != sender:
            raise FileRejected("a message whose sender is not axt.sender")
        if kind == "MANIFEST":
            if manifests or seen_record:
                raise FileRejected("a second MANIFEST, or one after a record message")
            if body[:10] != b"\xc3\x01" + MANIFEST_FP:
                raise FileRejected("a MANIFEST whose body is not an axt.Manifest")
            manifests.append(body)
            continue
        seen_record = True
        if kind == "DELETE" and body:
            raise FileRejected("a DELETE with a body")
        if kind == "WITHDRAW":
            # A WITHDRAW whose body is not one axt.Withdraw is not a valid message (spec/shares.md, 8.2).
            if body[:10] != b"\xc3\x01" + pe.fp8(pe.fingerprints["Withdraw"][1]) or len(body) != 42:
                raise FileRejected("a WITHDRAW whose body is not an axt.Withdraw")
        if kind == "DATA" and (
            body[:2] != b"\xc3\x01" or int.from_bytes(body[2:10], "little") not in schemas
        ):
            raise FileRejected("a DATA whose fingerprint is not in axt.schemas")
        messages.append((kind, record, body))
    # The reader knows the file's sender by the key in axt.sender alone, and follows the chain from it.
    receiver = keys.DeviceReceiver([keys.KnownSender("sender", [sender])])
    chain_results = receiver.chain(list(chain))
    removed = receiver.key_state(sender)[0] == "removed"
    state = "none"
    for body in manifests:
        datum, _, error = manifest_datum(body)
        state = "invalid" if error or me.manifest_problems(datum, len(body)) else "used"
    own, _, _ = manifest_datum(b_in(reader["manifest"]))
    readers = {n: json.loads(t) for n, t in reader["readers"].items()}
    # The keys of the reader's own set, by which it takes a WITHDRAW (spec/shares.md, section 8.2).
    own_keys = {
        bytes.fromhex(k) for part in ("current", "removed") for k in reader.get("keys", {}).get(part, [])
    }
    kept: dict[int, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for kind, record, body in messages:
        rid, version = record["id"], record["version"]
        out = {"id": rid, "version": version}
        results.append(out)
        if removed:
            out["result"] = "SENDER_REMOVED"
            continue
        if kind == "WITHDRAW" and body[10:] not in own_keys:
            out["result"] = "IGNORED"  # a withdrawal from another app: not applied, the file stands
            continue
        rkey = record_key(rid)
        if rkey is None:
            out["result"] = "RECORD_ID_INVALID"
            continue
        if version < 1:
            out["result"] = "VERSION_INVALID"
            continue
        k = kept.get(rkey)
        if kind == "DATA":
            text = schemas[int.from_bytes(body[2:10], "little")]
            writer = json.loads(text)
            name = pe.full_name(writer)
            if me.fit(own, name, me.schema_version(writer)) is None:
                out["result"] = "DOES_NOT_FIT"
                continue
            if k is not None and k["type"] is not None and k["type"] != name:
                out["result"] = "TYPE_CHANGED"
                continue
        if k is not None and version <= k["version"]:
            out["result"] = "DUPLICATE" if version == k["version"] else "STALE"
            continue
        if kind == "DATA":
            got = op_decode_record(
                {
                    "writer_schema": text,
                    "reader_schema": None if name not in readers else json.dumps(readers[name]),
                    "body": body.hex(),
                }
            )
            if "reject" in got:
                error = got["reject"]["error"]
                out["result"] = error if error in ("DOES_NOT_RESOLVE", "VALUE_INVALID") else "UNDECODABLE"
                continue
            kept[rkey] = {"type": name, "version": version}
        else:
            kept[rkey] = {"type": None if k is None else k["type"], "version": version}
        out["result"] = "WITHDRAWN" if kind == "WITHDRAW" else "APPLIED"
    links = [
        {"kind": kind, "signer": signer.hex(), "device": device.hex(), "result": result}
        for (kind, signer, device, _), result in zip(chain, chain_results, strict=True)
    ]
    return ok({"sender": sender.hex(), "chain": links, "manifest": state, "records": results})


# --- transports (spec/transports.md) -------------------------------------------------------

QR = plain_schema(tx.qr_text_schema)


def op_parse_qr(i: Any) -> dict[str, Any]:
    q = tx.parse_qr(i["text"])
    if isinstance(q, str):
        return no("QR_VERSION_UNSUPPORTED" if "version" in q else "QR_INVALID", q)
    return ok({"payload": json_of(QR, q)})


def op_connection(i: Any) -> dict[str, Any]:
    role = tx.SERVER if i["role"] == "server" else tx.CLIENT
    peer = tx.Peer(role, b_in(i["certificate_sha256"]), b_in(i["expected_key"]))
    steps: list[str] = []
    for f in i["frames"]:
        try:
            steps.append(
                {"open": "open", "message": "message", "ping": "ping", "TOO_LARGE": "too_large"}[
                    peer.receive(b_in(f))
                ]
            )
        except tx.Closed:
            steps.append("close")
            break
    return {"steps": steps}


def op_request(i: Any) -> dict[str, Any]:
    """A request of spec/transports.md, section 5.2, as an app writes it."""
    base, action = i["base_url"], i["action"]
    mailbox = i["mailbox"] if action == "put" else tx.mailbox_id(b_in(i["secret"])).hex()
    url = f"{base}v1/mailboxes/{mailbox}"
    headers: dict[str, str | None] = {"authorization": None, "content_type": None, "content_length": None}
    if action != "put":
        headers["authorization"] = "Bearer " + i["secret"]
    if action in ("create", "remove"):
        return ok({"method": "PUT" if action == "create" else "DELETE", "url": url, "headers": headers})
    if action == "put":
        message = b_in(i["message"])
        headers.update(content_type="application/octet-stream", content_length=str(len(message)))
        return ok(
            {
                "method": "PUT",
                "url": f"{url}/messages/{hashlib.sha256(message).hexdigest()}",
                "headers": headers,
            }
        )
    if action == "list":
        wait = i.get("wait")
        return ok(
            {
                "method": "GET",
                "url": f"{url}/messages" + ("" if wait is None else f"?wait={wait}"),
                "headers": headers,
            }
        )
    return ok(
        {
            "method": "GET" if action == "fetch" else "DELETE",
            "url": f"{url}/messages/{i['message_id']}",
            "headers": headers,
        }
    )


def op_reaction(i: Any) -> dict[str, Any]:
    """What an app does with a response of the relay (spec/transports.md, sections 5.2 to 5.4)."""
    status, retry, attempt, request = i["status"], i["retry_after"], i["attempt"], i["request"]
    backoff = min(2 ** (attempt - 1), 3600)
    if status is None:
        return ok({"action": "repeat", "wait": backoff})
    if 200 <= status < 300:
        return ok({"action": "done", "wait": None})
    if status == 404:
        return ok({"action": "stop" if request == "put" else "create_mailbox", "wait": None})
    if status == 411:
        return ok({"action": "repeat", "wait": 0})
    if status in (429, 503) and retry is not None:
        return ok({"action": "repeat", "wait": retry})
    if status == 507 or 500 <= status < 600:
        return ok({"action": "repeat", "wait": backoff})
    return ok({"action": "stop", "wait": None})


def op_listing(i: Any) -> dict[str, Any]:
    return ok({"messages": [{"id": m["id"], "size": m["size"]} for m in json.loads(i["body"])["messages"]]})


def op_relay(i: Any) -> dict[str, Any]:
    relay = tx.Relay(quota_bytes=i["quota_bytes"])
    steps: list[dict[str, Any]] = []
    for r in i["requests"]:
        status, _, body = relay.handle(r["method"], r["target"], r["headers"], b_in(r["body"]), now=r["now"])
        out: dict[str, Any] = {"status": status}
        if status == 200 and r["target"].split("?")[0].endswith("/messages"):
            out["messages"] = json.loads(body)["messages"]
        elif status == 200:
            out["message"] = b_out(body)
        steps.append(out)
    return {"steps": steps}


# --- keys (spec/keys.md) ----------------------------------------------------------------


def live_parts(m: bytes) -> tuple[bytes, bytes, bytes]:
    """Sender and signed bytes of a live message, found as keys.md, section 2.3, allows before verifying."""
    end = keys.envelope_end(m, 10)
    if end != len(m):
        raise ValueError("bytes left over after the envelope")
    _, pos = keys.read_long(m, 10)
    _, pos = keys.read_long(m, pos)
    return m[pos : pos + 32], keys.MESSAGE_PREFIX + m[10:-64], m[-64:]


def op_verify(i: Any) -> dict[str, Any]:
    problem = keys.verify_problem(b_in(i["public_key"]), b_in(i["data"]), b_in(i["signature"]))
    return ok() if problem is None else no("SIGNATURE_INVALID", problem)


def op_verify_message(i: Any) -> dict[str, Any]:
    sender, signed, sig = live_parts(b_in(i["message"]))
    problem = keys.verify_problem(sender, signed, sig)
    return ok() if problem is None else no("SIGNATURE_INVALID", problem)


def op_device_add(i: Any) -> dict[str, Any]:
    """Steps 1 and 2 of keys.md, section 5.5, for a DEVICE_ADD."""
    kind, member, d, signed, sig = pe.device_parts(b_in(i["message"]))
    problem = keys.device_message_problem(kind, member, signed, sig, d["device"], d["proof"])
    return no(problem) if problem else ok({"member": member.hex(), "device": d["device"].hex()})


def op_device_join(i: Any) -> dict[str, Any]:
    """A DEVICE_JOIN at the device that shows the join code (keys.md, section 5.2)."""
    _, device, d, signed, sig = pe.device_parts(b_in(i["message"]))
    if keys.verify_problem(device, signed, sig):
        return no("SIGNATURE_INVALID")
    who = i["member"]
    action = keys.join_action(
        b_in(who["key"]),
        [b_in(k) for k in who["current"]],
        [b_in(k) for k in who["removed"]],
        d["to"],
        device,
        d["proof"],
        None if i["first"] is None else b_in(i["first"]),
    )
    return no(action) if action == keys.REJECTED else ok({"device": device.hex(), "action": action})


def op_join_chain(i: Any) -> dict[str, Any]:
    """The chain a new device gets in answer to its DEVICE_JOIN (keys.md, section 5.2, step 5)."""
    chain = []
    for m in i["chain"]:
        kind, signer, d, signed, sig = pe.device_parts(b_in(m))
        chain.append(
            (kind, signer, d["device"], d.get("proof"), keys.verify_problem(signer, signed, sig) is None)
        )
    problem = keys.join_chain_problem(chain, b_in(i["member"]), b_in(i["device"]))
    return no("JOIN_INVALID", problem) if problem else ok()


def op_device_sets(i: Any) -> dict[str, Any]:
    """A receiver that follows the devices of its known senders, as the model of keys_examples.py does."""
    receiver = keys.DeviceReceiver(
        [
            keys.KnownSender(
                s["name"],
                [b_in(k) for k in s["current"]],
                [b_in(k) for k in s["removed"]],
                {r["id"]: (r["version"], r["state"]) for r in s["records"]},
            )
            for s in i["senders"]
        ],
        [b_in(k) for k in i["refused"]],
    )
    steps: list[dict[str, Any]] = []
    for step in i["steps"]:
        messages = []
        for m in step["chain"]:
            kind, signer, d, signed, sig = pe.device_parts(b_in(m))
            problem = keys.device_message_problem(kind, signer, signed, sig, d["device"], d.get("proof"))
            messages.append((kind, signer, d["device"], problem))
        results = receiver.chain(messages)
        key = step["key"]
        key_state, key_sender = (None, None) if key is None else receiver.key_state(b_in(key))
        steps.append(
            {
                "results": results,
                "key_state": key_state,
                "key_sender": key_sender,
                "senders": receiver.state(),
            }
        )
    return {"steps": steps}


def op_relations(i: Any) -> dict[str, Any]:
    """A receiver that resolves the relations it holds across senders (records.md, section 10), with the
    model of keys_examples.py, and follows the devices of its known senders as op_device_sets does."""

    def known(s: Any) -> Any:
        return keys.KnownSender(
            s["name"],
            [b_in(k) for k in s["current"]],
            [b_in(k) for k in s["removed"]],
            {r["id"].lower(): (r["version"], r["state"]) for r in s["records"]},
        )

    own, senders = known(i["own"]), [known(s) for s in i["senders"]]
    first = {s.name: s.current[0] for s in [own, *senders]}
    receiver = keys.RelationReceiver(
        own,
        senders,
        [b_in(k) for k in i["refused"]],
        [
            keys.HeldRelation(
                r["id"],
                first[r["holder"]["sender"]],
                r["holder"]["id"].lower(),
                None if r["target"]["sender"] is None else b_in(r["target"]["sender"]),
                r["target"]["id"].lower(),
            )
            for r in i["relations"]
        ],
    )
    steps: list[dict[str, Any]] = []
    for step in i["steps"]:
        if "chain" in step:
            messages = []
            for m in step["chain"]:
                kind, signer, d, signed, sig = pe.device_parts(b_in(m))
                problem = keys.device_message_problem(kind, signer, signed, sig, d["device"], d.get("proof"))
                messages.append((kind, signer, d["device"], problem))
            steps.append({"results": receiver.chain(messages)})
        else:
            steps.append(receiver.lookup())
    return {"steps": steps}


def op_seal(i: Any) -> dict[str, Any]:
    message, key = b_in(i["message"]), b_in(i["encryption_key"])
    if keys.encryption_key_problem(key):
        return no("ENCRYPTION_KEY_INVALID")
    enc, shared = keys.encap(os.urandom(32), key)  # a fresh ephemeral key (spec/keys.md, section 4.3)
    ctx = keys.hpke_base_context(shared, keys.HPKE_INFO)
    sealed = (
        keys.SEALED_FORMAT
        + enc
        + ChaCha20Poly1305(ctx["key"]).encrypt(ctx["base_nonce"], keys.pad(message), b"")
    )
    return ok({"sealed": b_out(sealed)})


def op_open(i: Any) -> dict[str, Any]:
    sealed = b_in(i["sealed"])
    if sealed[:1] != keys.SEALED_FORMAT or len(sealed) < 1 + 32 + 16:
        return no("NOT_OPENED")
    for sk in i["private_keys"]:
        try:
            ctx = keys.hpke_base_context(keys.decap(sealed[1:33], bytes.fromhex(sk)), keys.HPKE_INFO)
            plain = ChaCha20Poly1305(ctx["key"]).decrypt(ctx["base_nonce"], sealed[33:], b"")
        except Exception:  # noqa: S112 a key that does not open the message is no fault; the next is tried
            continue
        try:
            return ok({"message": b_out(keys.unpad(plain))})
        except ValueError as e:
            return no("PADDING_INVALID", str(e))
    return no("NOT_OPENED")


# --- sync (spec/sync.md) -----------------------------------------------------------------


def stamp_in(v: Any) -> int | None:
    return None if v is None else int(v)


def op_change(i: Any) -> dict[str, Any]:
    done = sy.change(
        sy.state_of_json(i["state"]),
        b_in(i["device"]),
        i["action"],
        {name: b_in(value) for name, value in i["values"].items()},
        int(i["now_ms"]),
        int(i["highest"]),
        (i["r"][0], i["r"][1]),
        b_in(i["schema"]),
        int(i["now_ms_state"]),
        stamp_in(i["to_pass"]),
    )
    return ok(
        {
            "made": done.made,
            "state": sy.state_json(done.state),
            "highest": str(done.highest),
            "to_pass": sy.stamp_json(done.to_pass),
        }
    )


def op_merge(i: Any) -> dict[str, Any]:
    done = sy.device_merge(
        sy.state_of_json(i["own"]),
        sy.state_of_json(i["other"]),
        int(i["now_ms"]),
        int(i["highest"]),
        i["r"],
        stamp_in(i["sibling_stamp"]),
        stamp_in(i["to_pass"]),
    )
    layer = "keep" in i["own"] if i["own"] is not None else "keep" in i["other"]
    return ok(
        {
            "state": sy.state_json(done.state, layer),
            "stands": done.merged.stands,
            "removal_taken": done.merged.removal_taken,
            "deleted": done.deleted,
            "highest": str(done.highest),
            "sibling_stamp": sy.stamp_json(done.sibling_stamp),
            "to_pass": sy.stamp_json(done.to_pass),
        }
    )


def op_deleted(i: Any) -> dict[str, Any]:
    state = sy.state_of_json(i["state"])
    versions = {b_in(fp): version for fp, version in i["versions"].items()}
    message = sy.record_message(state, i["writer_fields"], i["writer_version"], versions)
    return ok(
        {
            "deleted": sy.deleted(state.fields, state.removal),
            "message": message and {"kind": message[0], "version": str(message[1])},
        }
    )


def op_begin_stamping(i: Any) -> dict[str, Any]:
    begun, states, highest = sy.begin_stamping(
        b_in(i["device"]),
        [sy.state_of_json(s) for s in i["states"]],
        int(i["now_ms"]),
        int(i["highest"]),
        i["r"],
    )
    return ok({"begun": begun, "states": [sy.state_json(s) for s in states], "highest": str(highest)})


def op_stale(i: Any) -> dict[str, Any]:
    after = sy.stale(
        int(i["receiver_version"]),
        stamp_in(i["state_stamp"]),
        stamp_in(i["sibling_stamp"]),
        stamp_in(i["to_pass"]),
        i["counted"],
        i["sibling"],
        int(i["now_ms"]),
        int(i["highest"]),
        i["r"],
        i["may_send"],
    )
    return ok(
        {
            "highest": str(after.highest),
            "stamps": after.stamps,
            "to_pass": sy.stamp_json(after.to_pass),
            "resend": sy.stamp_json(after.resend),
        }
    )


def op_pass_version(i: Any) -> dict[str, Any]:
    resend, to_pass, highest = sy.pass_version(
        int(i["state_stamp"]), int(i["to_pass"]), i["may_send"], int(i["now_ms"]), int(i["highest"]), i["r"]
    )
    return ok({"resend": sy.stamp_json(resend), "to_pass": sy.stamp_json(to_pass), "highest": str(highest)})


def op_shown(i: Any) -> dict[str, Any]:
    """What a device shows of a received record, from its two layers (spec/sync.md, section 22.1)."""
    sender = i["sender"]
    there = None if sender is None else sender["state"] == "there"
    values = {name: bytes.fromhex(v) for name, v in sender["values"].items()} if there else {}
    schema = bytes.fromhex(sender["schema"]) if there else None
    version, beside = 0, None
    if there is False:
        version, b = int(sender["version"]), sender["beside"]
        if b is not None:
            beside = ({name: bytes.fromhex(v) for name, v in b["values"].items()}, bytes.fromhex(b["schema"]))
    state, fields = sy.shown(
        there, values, schema, sy.state_of_json(i["layer"]), version, beside, sy.SHOWN_TEXTS
    )
    shown = {
        name: {"value": value.hex(), "schema": fp.hex(), "from": source}
        for name, (value, fp, source) in fields.items()
    }
    return ok({"record": state, "fields": shown})


def op_siblings(i: Any) -> dict[str, Any]:
    """One device of a set with its siblings, as the model of sync_examples.py plays it."""
    device = sy.device_of_json(i["device"], b_in)
    out: list[dict[str, Any]] = []
    for step in i["steps"]:
        answer = sy.play(device, step, b_in)
        if "sent" in answer:
            passed = [{"to": p["to"].hex(), "manifest": b_out(p["manifest"])} for p in answer["passed"]]
            answer = {**answer, "sent": [b_out(m) for m in answer["sent"]], "passed": passed}
        out.append(answer)
    return {"steps": out}


# --- shares (spec/shares.md) -------------------------------------------------------------------


def stamp_or_none(v: Any) -> int | None:
    return None if v is None else int(v)


def op_take_version(i: Any) -> dict[str, Any]:
    """The version of a withdrawal or of a sharing again at an installation that counts."""
    version, state, _ = se.take_version(
        i["occasion"], True, int(i["highest_given"]), 0, 0, 0, [], int(i["state_stamp"])
    )
    return ok({"version": sy.stamp_json(version), "state_stamp": str(state)})


def op_withdrawal_stamp(i: Any) -> dict[str, Any]:
    """The same at a device that stamps (spec/sync.md, section 2.2)."""
    version, state, highest = se.take_version(
        i["occasion"],
        False,
        0,
        int(i["now_ms"]),
        int(i["highest"]),
        i["r"],
        [int(w) for w in i["withdrawals"]],
        int(i["state_stamp"]),
    )
    return ok({"version": sy.stamp_json(version), "state_stamp": str(state), "highest": str(highest)})


def op_owed(i: Any) -> dict[str, Any]:
    last = None if i["last"] is None else (i["last"]["kind"], int(i["last"]["version"]))
    owes, version = se.owed(
        i["shared"], i["deleted"], int(i["version"]), stamp_or_none(i["withdrawal"]), last
    )
    return ok({"owes": owes, "version": sy.stamp_json(version)})


def op_pass_withdrawal(i: Any) -> dict[str, Any]:
    then, to_pass = se.pass_withdrawal(
        i["shared"], stamp_or_none(i["withdrawal"]), int(i["to_pass"]), int(i["state_stamp"])
    )
    return ok({"then": then, "to_pass": sy.stamp_json(to_pass)})


def op_join_receivers(i: Any) -> dict[str, Any]:
    a, b = ((r["shared"], stamp_or_none(r["withdrawal"])) for r in i["receivers"])
    shared, withdrawal, new = se.joined(a, b)
    return ok({"shared": shared, "withdrawal": sy.stamp_json(withdrawal), "new_state_stamp": new})


def op_offer_types(i: Any) -> dict[str, Any]:
    types = se.offer([(r["type"], r["owes"], r["delivered"]) for r in i["records"]])
    return ok({"types": [{"type": t, "count": n} for t, n in types]})


def op_acked(i: Any) -> dict[str, Any]:
    held, then, to_pass = se.acked(
        i["sent"],
        i["held"],
        i["outcome"],
        int(i["receiver_version"]),
        i["shared"],
        stamp_or_none(i["withdrawal"]),
        int(i["state_stamp"]),
        stamp_or_none(i["sibling_stamp"]),
        i["sibling"],
    )
    return ok({"outcome": held, "then": then, "to_pass": sy.stamp_json(to_pass)})


def shares_session(steps: list[dict[str, Any]]) -> dict[str, Any]:
    """The steps of an `owner` or a `proposer` session, with each message written as Bytes."""
    out = []
    for answer in steps:
        if "replies" in answer:
            answer = {**answer, "replies": [b_out(m) for m in answer["replies"]]}
        if "message" in answer:
            answer = {**answer, "message": b_out(answer["message"])}
        if "messages" in answer:
            answer = {**answer, "messages": [b_out(m) for m in answer["messages"]]}
        out.append(answer)
    return {"steps": out}


OPS: dict[str, Callable[[Any], dict[str, Any]]] = {
    "owner": lambda i: shares_session(se.owner_session(i, b_in)),
    "proposer": lambda i: shares_session(se.proposer_session(i, b_in)),
    "receive": lambda i: {"steps": se.apply(i["policy"], i["events"])},
    "take_version": op_take_version,
    "withdrawal_stamp": op_withdrawal_stamp,
    "owed": op_owed,
    "pass_withdrawal": op_pass_withdrawal,
    "join_receivers": op_join_receivers,
    "offer_types": op_offer_types,
    "acked": op_acked,
    "decode_body": op_decode_body,
    "read_file": op_read_file,
    "apply": op_apply,
    "relations": op_relations,
    "parse_qr": op_parse_qr,
    "qr_text": lambda i: ok({"text": tx.qr_text(b_in(i["payload"]))}),
    "hello_frame": lambda i: ok(
        {
            "frame": tx.hello(
                b_in(i["seed"]),
                tx.SERVER if i["role"] == "server" else tx.CLIENT,
                b_in(i["certificate_sha256"]),
                check=False,
            ).hex()
        }
    ),
    "connection": op_connection,
    "mailbox_id": lambda i: ok({"mailbox": tx.mailbox_id(b_in(i["secret"])).hex()}),
    "request": op_request,
    "reaction": op_reaction,
    "listing": op_listing,
    "relay": op_relay,
    "choose_format": lambda i: ok({"format": pe.choose_format(i["own"], i["theirs"])}),
    "contact_key": lambda i: ok(
        {
            "keys": [
                k.hex()
                for k in pe.contact_keys(
                    [bytes.fromhex(k) for k in i["current"]],
                    [bytes.fromhex(k) for k in i["manifests"]],
                    [(bytes.fromhex(g["key"]), g["kind"]) for g in i["got"]],
                )
            ]
        }
    ),
    "resend_after_removal": lambda i: ok(
        {
            "ids": pe.resend_after_removal(
                [(r["id"], {bytes.fromhex(k): o for k, o in r["outcomes"].items()}) for r in i["records"]],
                [bytes.fromhex(k) for k in i["removed"]],
            )
        }
    ),
    "session": op_session,
    "fingerprint": op_fingerprint,
    "derive": op_derive,
    "decode_message": op_decode_message,
    "encode_message": op_encode_message,
    "decode_record": op_decode_record,
    "describe": op_describe,
    "check_record": op_check_record,
    "check_manifest": op_check_manifest,
    "fit": op_fit,
    "resolve_date_time": lambda i: ok({"date_time": tm.resolve(i["date_time"], i["anchor"])}),
    "add_duration": lambda i: ok({"date_time": tm.add(i["date_time"], i["duration"])}),
    "public_key": lambda i: ok({"public_key": keys.public_key(b_in(i["seed"])).hex()}),
    "sign": lambda i: ok({"signature": keys.sign(b_in(i["seed"]), b_in(i["data"])).hex()}),
    "verify": op_verify,
    "check_signing_key": lambda i: (lambda p: ok() if p is None else no("KEY_INVALID", p))(
        keys.key_problem(b_in(i["public_key"]))
    ),
    "check_encryption_key": lambda i: (lambda p: ok() if p is None else no("ENCRYPTION_KEY_INVALID", p))(
        keys.encryption_key_problem(b_in(i["encryption_key"]))
    ),
    "short_fingerprint": lambda i: ok({"short_fingerprint": keys.short_fingerprint(b_in(i["public_key"]))}),
    "verify_message": op_verify_message,
    "device_add": op_device_add,
    "device_join": op_device_join,
    "join_chain": op_join_chain,
    "device_sets": op_device_sets,
    "padded_length": lambda i: ok({"padded_length": keys.padded_length(i["length"])}),
    "seal": op_seal,
    "open": op_open,
    "next_stamp": lambda i: ok(
        {"stamp": sy.stamp_json(sy.next_stamp(int(i["now_ms"]), int(i["highest"]), i["r"]))}
    ),
    "change": op_change,
    "shown": op_shown,
    "merge": op_merge,
    "deleted": op_deleted,
    "begin_stamping": op_begin_stamping,
    "stale": op_stale,
    "pass_version": op_pass_version,
    "siblings": op_siblings,
}


def forget_descriptions() -> None:
    """Each vector stands alone: the models keep no description that an earlier vector gave them, and know
    only those of their input (spec/fields.md, section 10.1)."""
    for module in {id(m.fe): m.fe for m in (pe, sy, se) if hasattr(m, "fe")}.values():
        module.REGISTRY.clear()


def main() -> None:
    for line in sys.stdin:
        request = json.loads(line)
        rid, op, i = request["id"], request["op"], request["input"]
        if op == "hello":
            answer: dict[str, Any] = {
                "id": rid,
                "output": {
                    "name": "AXT reference adapter (conformance/reference/adapter.py)",
                    "categories": CATEGORIES,
                },
            }
        elif op not in OPS:
            answer = {"id": rid, "unsupported": True}
        else:
            try:
                forget_descriptions()
                answer = {"id": rid, "output": OPS[op](i)}
            except Exception as e:  # a fault of this adapter, reported as such
                answer = {"id": rid, "failure": f"{type(e).__name__}: {e}"}
        sys.stdout.write(json.dumps(answer, ensure_ascii=False) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
