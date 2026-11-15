# SPDX-License-Identifier: Apache-2.0 OR MIT
"""The reference adapter of the AXT conformance suite (spec/conformance.md, section 6).

    python3 conformance/run.py -- python3 conformance/reference/adapter.py

It answers every operation of the suite with the code of the example scripts in
conformance/tools/, which check the examples of the specification: the Avro
encoding and the schema checks of example_types.py and manifest_examples.py,
the Ed25519, X25519 and HPKE of keys_examples.py, the model of an app of
protocol_examples.py, the QR code, frames and relay of
transports_examples.py, the time types of time_examples.py, and the attributes of spec/metadata.md of
metadata_rules.py. Where those scripts have no model, for a receiver's
own changes to records (spec/records.md, section 6) and for reading a file
(spec/transports.md, section 2.2), it has its own code below. That it passes
every vector shows that the vectors agree with the scripts' checks; it is a
test of the vectors, not a library.

It needs what the example scripts need: fastavro, avro (1.12), pynacl,
cryptography, and a time zone database where Python's zoneinfo finds it. Every key it uses comes from the request; it holds none itself.
"""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import sys
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOLS = HERE.parent / "tools"


def load(name):
    spec = importlib.util.spec_from_file_location(name, TOOLS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    with contextlib.redirect_stdout(io.StringIO()):
        spec.loader.exec_module(module)
    return module


tx = load("transports_examples")
pe, me, keys, rules = tx.pe, tx.me, tx.keys, tx.rules
tm = load("time_examples")
mr = rules.mr

import fastavro  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305  # noqa: E402

CATEGORIES = ["encoding", "types", "time", "metadata", "records", "manifest", "keys", "protocol", "file", "qr", "local", "relay",
              "relay-server"]
OUT_INLINE = 1 << 20  # bytes above which an answer carries raw DEFLATE rather than hex


# --- bytes ----------------------------------------------------------------------------


def b_in(v):
    if v is None:
        return None
    if isinstance(v, str):
        return bytes.fromhex(v)
    data = zlib.decompressobj(-15).decompress(bytes.fromhex(v["deflate"]), v["length"] + 1)
    if len(data) != v["length"] or hashlib.sha256(data).hexdigest() != v["sha256"]:
        raise ValueError("a deflate object whose length or SHA-256 does not match")
    return data


def b_out(data):
    if data is None:
        return None
    if len(data) <= OUT_INLINE:
        return data.hex()
    c = zlib.compressobj(6, zlib.DEFLATED, -15)
    return {"deflate": (c.compress(data) + c.flush()).hex(), "length": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def ok(value=None):
    return {"accept": {} if value is None else value}


def no(error, note=None, **members):
    return {"reject": dict({"error": error}, **({} if note is None else {"note": note}), **members)}


# --- a strict Avro decoder ----------------------------------------------------------------

MAX_DATA_DEPTH = 32  # spec/types.md, section 5.7
PRIMITIVES = {"null", "boolean", "int", "long", "float", "double", "bytes", "string"}


class Undecodable(Exception):
    pass


class Reader:
    def __init__(self, data, pos=0):
        self.data, self.pos = data, pos

    def take(self, n):
        if n < 0 or self.pos + n > len(self.data):
            raise Undecodable("a length below 0 or beyond the end")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def long(self, bits=64):
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


def named(t, names, namespace):
    """Register a named type under its full name; return the namespace its children inherit."""
    name = t["name"]
    ns = name.rpartition(".")[0] if "." in name else t.get("namespace", namespace)
    full = name if "." in name else (f"{ns}.{name}" if ns else name)
    names[full] = t
    names.setdefault(name, t)
    return ns


def read(t, r, names, namespace="", depth=0):
    """Decode one value of the schema t, strictly; return its meaning as JSON (spec/conformance.md, section 3.3)."""
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
            raise Undecodable("a string that is not well-formed UTF-8")
    if isinstance(t, list):
        i = r.long()
        if not 0 <= i < len(t):
            raise Undecodable("a union index out of range")
        return read(t[i], r, names, namespace, depth)
    kind = t["type"]
    if kind in ("record", "enum", "fixed"):
        namespace = named(t, names, namespace)
    if kind == "record":
        if depth + 1 > MAX_DATA_DEPTH:
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
        if depth + 1 > MAX_DATA_DEPTH:
            raise Undecodable("a data depth above 32")
        out = [] if kind == "array" else {}
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


def decode_all(t, data):
    r = Reader(data)
    value = read(t, r, {})
    if r.pos != len(data):
        raise Undecodable("bytes left over")
    return value


def json_of(t, value, names=None, namespace=""):
    """The meaning of a value as fastavro decodes it with logical types removed."""
    names = {} if names is None else names
    if isinstance(t, str):
        if t not in PRIMITIVES:
            return json_of(names.get(t) or names[f"{namespace}.{t}"], value, names, namespace)
        if t == "bytes":
            return (value.encode("latin-1") if isinstance(value, str) else value).hex()
        return value
    if isinstance(t, list):
        if value is None:
            return None
        (branch,) = [b for b in t if b != "null"]
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


def plain_schema(text):
    return pe.without_logical_types(json.loads(text))


# --- encoding (spec/envelope.md) -----------------------------------------------------------

ENVELOPE = plain_schema(pe.texts["Envelope"])
ENVELOPE_FP = pe.fp8(pe.fingerprints["Envelope"][1])
MAX_MESSAGE = pe.MAX_MESSAGE


def decode_envelope(m):
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


def op_decode_message(i):
    d, error = decode_envelope(b_in(i["message"]))
    if error:
        return no(error)
    return ok(dict(d, body=b_out(bytes.fromhex(d["body"]))))


def op_encode_message(i):
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


def op_decode_body(i):
    """The body of a kind whose schema the specification publishes (spec/envelope.md, section 2.3)."""
    name = pe.BODY_SCHEMA[i["kind"]]
    body = b_in(i["body"])
    if body[:10] != b"\xc3\x01" + pe.fp8(pe.fingerprints[name][1]):
        return no("INVALID_MESSAGE", f"not an axt.{name}")
    try:
        return ok({"value": decode_all(plain_schema(pe.texts[name]), body[10:])})
    except Undecodable as e:
        return no("INVALID_MESSAGE", str(e))


def op_fingerprint(i):
    pcf, fp = me.fingerprint(i["schema"])
    return ok({"canonical_form": pcf, "fingerprint": pe.fp8(fp).hex()})


# --- types (spec/types.md) ----------------------------------------------------------------


def op_decode_record(i):
    writer_text, reader_text, body = i["writer_schema"], i["reader_schema"], b_in(i["body"])
    writer = json.loads(writer_text)
    if body[:2] != b"\xc3\x01" or len(body) < 10:
        return no("UNDECODABLE", "not a single-object encoding")
    if body[2:10] != pe.fp8(pe.canonical_fp(writer_text)):
        return no("SCHEMA_UNKNOWN")
    if reader_text is not None:
        reader = json.loads(reader_text)
        if not pe.resolves(writer, reader):
            return no("DOES_NOT_RESOLVE")
    try:
        value = decode_all(pe.without_logical_types(writer), body[10:])
    except Undecodable as e:
        return no("UNDECODABLE", str(e))
    # Step 9 of spec/protocol.md, section 6.2: a value that decodes but holds a time value that is not valid.
    broken = tm.value_breaches(pe.without_logical_types(writer), value)
    if broken:
        path, rule, why = broken[0]
        return no("VALUE_INVALID", f"{rule}: {why} (spec/time.md, section 8)", field=mr.error_field(path))
    if reader_text is None:
        return ok({"value": value})
    w, r = pe.without_logical_types(writer), pe.without_logical_types(reader)
    try:
        resolved = fastavro.schemaless_reader(io.BytesIO(body[10:]), fastavro.parse_schema(w, _write_hint=False),
                                              fastavro.parse_schema(r, _write_hint=False))
    except Exception as e:
        return no("DOES_NOT_RESOLVE", str(e))
    return ok({"value": json_of(r, resolved)})


# --- metadata (spec/metadata.md) ------------------------------------------------------------


def op_describe(i):
    return ok(mr.describe(json.loads(i["schema"]), i["field"], i["languages"]))


def op_check_record(i):
    """A receiver that checks the attributes: the first value, in the order of the encoding, that breaks a rule."""
    got = op_decode_record({"writer_schema": i["schema"], "reader_schema": None, "body": i["body"]})
    if "reject" in got:
        return got
    writer = pe.without_logical_types(json.loads(i["schema"]))
    broken = mr.breaches(writer, got["accept"]["value"], tm.time_check)
    if broken:
        path, rule, why = broken[0]
        return no("VALUE_INVALID", f"{rule}: {why}", field=mr.error_field(path))
    return ok()


# --- manifest (spec/manifest.md) ------------------------------------------------------------

MANIFEST = plain_schema(pe.texts["Manifest"])
MANIFEST_FP = pe.fp8(pe.fingerprints["Manifest"][1])


def manifest_datum(body):
    """The manifest as fastavro decodes it, after a strict check of its bytes; or an error code."""
    if body[:10] != b"\xc3\x01" + MANIFEST_FP:
        return None, None, "INVALID_MESSAGE"
    try:
        meaning = decode_all(MANIFEST, body[10:])
    except Undecodable:
        return None, None, "INVALID_MESSAGE"
    datum = fastavro.schemaless_reader(io.BytesIO(body[10:]), pe.raw["Manifest"], pe.raw["Manifest"])
    return datum, meaning, None


def op_check_manifest(i):
    body = b_in(i["body"])
    datum, meaning, error = manifest_datum(body)
    if error:
        return no(error)
    problems = me.manifest_problems(datum, len(body), i["envelope_format"])
    return no("MANIFEST_INVALID", problems[0]) if problems else ok({"manifest": meaning})


def op_fit(i):
    datum, _, error = manifest_datum(b_in(i["manifest"]))
    if error:
        return no(error)
    schema = json.loads(i["schema"])
    entry = me.fit(datum, pe.full_name(schema), me.schema_version(schema))
    return ok({"fits": entry is not None, "purpose": None if entry is None else me.sentence(entry, i["languages"])})


# --- records (spec/records.md) ---------------------------------------------------------------
# protocol_examples.py has no model of a receiver's own changes; this is the adapter's own.


def record_key(rid):
    """The id as a 128-bit value, or None if it is not a UUID in text form or is the nil or max UUID."""
    if pe.uuid_problem(rid):
        return None
    return int(rid.replace("-", ""), 16)


class Receiver:
    """The records of one sender at a receiver that lets its user change them (spec/records.md, sections 5 and 6)."""

    def __init__(self, local_changes, delete_with_local_changes):
        self.mode, self.keep_on_delete, self.records = local_changes, delete_with_local_changes == "keep", {}

    def result(self, outcome, r, kept=()):
        return {"outcome": outcome, "receiver_version": r["version"], "kept_fields": sorted(kept), "state": r["state"],
                "value": None if r["state"] != "there" else dict(r["value"])}

    def message(self, m):
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
            r = self.records[key] = {"type": m["type"] if is_data else None, "version": m["version"],
                                     "state": "there" if is_data else "tombstone",
                                     "value": dict(m["value"]) if is_data else None, "changed": set()}
            return self.result("APPLIED", r)
        r["version"] = m["version"]
        if not is_data:
            if r["state"] == "there" and r["changed"] and self.keep_on_delete:
                return self.result("KEPT", r)
            r.update(state="tombstone", value=None, changed=set())
            return self.result("APPLIED", r)
        r["type"] = m["type"]
        if r["state"] == "tombstone":  # the record comes back as a new record under the same id
            r.update(state="there", value=dict(m["value"]), changed=set())
            return self.result("APPLIED", r)
        if r["state"] == "deleted_by_user":
            return self.result("KEPT", r)
        if not r["changed"] or self.mode == "whole_record_take":
            r.update(value=dict(m["value"]), changed=set())
            return self.result("APPLIED", r)
        if self.mode == "whole_record_keep":
            return self.result("KEPT", r)
        kept = [f for f in r["changed"] if f in r["value"] and r["value"][f] != m["value"].get(f)]
        value = dict(m["value"])
        for f in r["changed"]:
            if f in r["value"]:
                value[f] = r["value"][f]
        r["value"] = value
        return self.result("MERGED" if kept else "APPLIED", r, kept)

    def local_change(self, rid, field, value):
        r = self.records[record_key(rid)]
        r["value"][field] = value
        r["changed"].add(field)

    def local_delete(self, rid):
        self.records[record_key(rid)].update(state="deleted_by_user", value=None)


def op_apply(i):
    receiver = Receiver(i["policy"]["local_changes"], i["policy"]["delete_with_local_changes"])
    steps = []
    for e in i["events"]:
        if "message" in e:
            steps.append(receiver.message(e["message"]))
        elif "local_change" in e:
            receiver.local_change(e["local_change"]["id"], e["local_change"]["field"], e["local_change"]["value"])
            steps.append({})
        else:
            receiver.local_delete(e["local_delete"]["id"])
            steps.append({})
    return {"steps": steps}


# --- protocol (spec/protocol.md) -----------------------------------------------------------

OUTCOMES = ("APPLIED", "DUPLICATE", "STALE")


def op_session(i):
    """One app in one live connection, as the model of protocol_examples.py plays it."""
    cfg = i["app"]
    manifest, _, error = manifest_datum(b_in(cfg["manifest"]))
    readers = {n: json.loads(t) for n, t in cfg["readers"].items()}
    takes = set(cfg["user_takes"])
    app = pe.App("adapter", b_in(cfg["seed"]), manifest, readers, lambda n: n in takes, formats=cfg["formats"])
    out = []
    for step in i["steps"]:
        if "receive" in step:
            what, replies = app.receive(b_in(step["receive"]))
            out.append({"outcome": what if what in OUTCOMES else None, "close": what == "no common format: close",
                        "replies": [b_out(r) for r in replies]})
        elif "flush_acks" in step:
            m = app.ack()
            out.append({"replies": [] if m is None else [b_out(m)]})
        elif "offer" in step:
            o = step["offer"]
            _, m = app.offer(o["offer_id"], [(t["schema"], t["count"], None) for t in o["types"]], check=False)
            out.append({"message": b_out(m)})
        elif "close" in step:
            app.close()
            out.append({})
        else:
            (what, arg), = step["query"].items()
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

MAX_FILE, MAX_META, MAX_BLOCK, MAX_TOTAL = 268435456, 8388608, 67108864, 1073741824  # spec/envelope.md, section 8
ENVELOPE_PCF = pe.fingerprints["Envelope"][0]
LOWER_HEX = __import__("re").compile(r"^[0-9a-f]*$")
KEY_MOVE_FP = pe.fp8(pe.fingerprints["KeyMove"][1])


class FileRejected(Exception):
    pass


def inflate(payload, limit):
    d = zlib.decompressobj(-15)
    out = d.decompress(payload, limit + 1)
    if len(out) > limit:
        raise FileRejected("a block above 64 MiB after decompression")
    if d.unconsumed_tail or not d.eof:
        raise FileRejected("a block that is not complete raw DEFLATE")
    return out


def file_messages(data):
    """The metadata and the datums of an AXT file, after the checks that reject a whole file."""
    if len(data) > MAX_FILE:
        raise FileRejected("above 256 MiB")
    if data[:4] != b"Obj\x01":
        raise FileRejected("not an Avro object container file")
    r = Reader(data, 4)
    try:
        meta = decode_meta(r)
    except Undecodable as e:
        raise FileRejected(str(e))
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
        raise FileRejected("no avro.schema of a schema")
    if pcf != ENVELOPE_PCF:
        raise FileRejected("avro.schema is not a supported envelope format")
    datums, total = [], 0
    while r.pos < len(data):
        try:
            count, size = r.long(), r.long()
            payload = r.take(size)
        except Undecodable as e:
            raise FileRejected(str(e))
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
                raise FileRejected("a datum cut short")
            if end > len(block):
                raise FileRejected("a datum cut short")
            datums.append(block[at:end])
            at = end
        if at != len(block) or count < 0:
            raise FileRejected("bytes left over in a block")
    return meta, datums


def decode_meta(r):
    meta = {}
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


def header_sender(meta):
    """The file's sender, after the header signature of spec/keys.md, section 2.5, has verified."""
    sender, sig = meta.get("axt.sender"), meta.get("axt.signature")
    for v, n in ((sender, 64), (sig, 128)):
        if v is None or len(v) != n or not LOWER_HEX.match(v.decode("latin-1")):
            raise FileRejected("axt.sender or axt.signature missing or not lower-case hexadecimal of the right length")
    sender = bytes.fromhex(sender.decode())
    value = meta.get("axt.schemas", b"")
    if keys.key_problem(sender) or keys.verify_problem(sender, keys.FILE_HEADER_PREFIX + sender + hashlib.sha256(value).digest(),
                                                       bytes.fromhex(sig.decode())):
        raise FileRejected("the header signature does not verify")
    return sender


def op_read_file(i):
    try:
        return read_file(b_in(i["file"]), i["reader"])
    except FileRejected as e:
        return no("FILE_REJECTED", str(e))


def read_file(data, reader):
    meta, datums = file_messages(data)
    sender = header_sender(meta)
    schemas = {}
    if "axt.schemas" in meta:
        try:
            for t in json.loads(meta["axt.schemas"]):
                text = json.dumps(t, separators=(",", ":"), ensure_ascii=False)
                fp = pe.canonical_fp(text)
                if fp in schemas:
                    raise FileRejected("two schemas with one fingerprint in axt.schemas")
                schemas[fp] = text
        except FileRejected:
            raise
        except Exception:
            raise FileRejected("axt.schemas is not a JSON array of schemas")
    messages, moves, manifests, seen_other, seen_record = [], [], [], False, False
    chain_key = None
    for d in datums:
        try:
            env = decode_all(ENVELOPE, d)
        except Undecodable as e:
            raise FileRejected(str(e))
        if env["format"] != 1:
            raise FileRejected("a datum whose format is not the file's")
        key = bytes.fromhex(env["sender"])
        if keys.verify_problem(key, keys.MESSAGE_PREFIX + d[:-64], d[-64:]):
            raise FileRejected("a message whose signature does not verify")
        kind, body, record = env["kind"], bytes.fromhex(env["body"]), env["record"]
        if kind not in ("KEY_MOVE", "MANIFEST", "DATA", "DELETE"):
            raise FileRejected(f"a {kind} in a file")
        if (record is None) == (kind in ("DATA", "DELETE")):
            raise FileRejected("a record where none belongs, or none where one is required")
        if kind == "KEY_MOVE":
            if seen_other:
                raise FileRejected("a KEY_MOVE after another kind of message")
            if body[:10] != b"\xc3\x01" + KEY_MOVE_FP:
                raise FileRejected("a KEY_MOVE whose body is not an axt.KeyMove")
            km = decode_all(pe.without_logical_types(json.loads(pe.texts["KeyMove"])), body[10:])
            new, enc = bytes.fromhex(km["new_sender"]), km["new_encryption_key"]
            if chain_key is not None and key != chain_key:
                raise FileRejected("a chain of key moves whose links do not join")
            if (keys.key_problem(new) or keys.verify_problem(new, keys.KEY_MOVE_PREFIX + key + new, bytes.fromhex(km["proof"]))
                    or (enc is not None and keys.encryption_key_problem(bytes.fromhex(enc)))):
                raise FileRejected("a KEY_MOVE that fails step 4 of keys.md, section 5.3")
            moves.append({"from": key.hex(), "to": new.hex()})
            chain_key = new
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
        if kind == "DATA" and (body[:2] != b"\xc3\x01" or int.from_bytes(body[2:10], "little") not in schemas):
            raise FileRejected("a DATA whose fingerprint is not in axt.schemas")
        messages.append((kind, record, body))
    if chain_key is not None and chain_key != sender:
        raise FileRejected("a chain of key moves that does not end at axt.sender")
    state = "none"
    for body in manifests:
        datum, _, error = manifest_datum(body)
        state = "invalid" if error or me.manifest_problems(datum, len(body)) else "used"
    own, _, _ = manifest_datum(b_in(reader["manifest"]))
    readers = {n: json.loads(t) for n, t in reader["readers"].items()}
    kept, results = {}, []
    for kind, record, body in messages:
        rid, version = record["id"], record["version"]
        out = {"id": rid, "version": version}
        results.append(out)
        key = record_key(rid)
        if key is None:
            out["result"] = "RECORD_ID_INVALID"
            continue
        if version < 1:
            out["result"] = "VERSION_INVALID"
            continue
        k = kept.get(key)
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
            got = op_decode_record({"writer_schema": text, "reader_schema": None if name not in readers else json.dumps(readers[name]),
                                    "body": body.hex()})
            if "reject" in got:
                error = got["reject"]["error"]
                out["result"] = error if error in ("DOES_NOT_RESOLVE", "VALUE_INVALID") else "UNDECODABLE"
                continue
            kept[key] = {"type": name, "version": version}
        else:
            kept[key] = {"type": None if k is None else k["type"], "version": version}
        out["result"] = "APPLIED"
    return ok({"sender": sender.hex(), "key_moves": moves, "manifest": state, "records": results})


# --- transports (spec/transports.md) -------------------------------------------------------

QR = plain_schema(tx.qr_text_schema)


def op_parse_qr(i):
    q = tx.parse_qr(i["text"])
    if isinstance(q, str):
        return no("QR_VERSION_UNSUPPORTED" if "version" in q else "QR_INVALID", q)
    return ok({"payload": json_of(QR, q)})


def op_connection(i):
    role = tx.SERVER if i["role"] == "server" else tx.CLIENT
    peer = tx.Peer(role, b_in(i["certificate_sha256"]), b_in(i["expected_key"]))
    steps = []
    for f in i["frames"]:
        try:
            steps.append({"open": "open", "message": "message", "ping": "ping", "TOO_LARGE": "too_large"}[peer.receive(b_in(f))])
        except tx.Closed:
            steps.append("close")
            break
    return {"steps": steps}


def op_request(i):
    """A request of spec/transports.md, section 5.2, as an app writes it."""
    base, action = i["base_url"], i["action"]
    mailbox = i["mailbox"] if action == "put" else tx.mailbox_id(b_in(i["secret"])).hex()
    url = f"{base}v1/mailboxes/{mailbox}"
    headers = {"authorization": None, "content_type": None, "content_length": None}
    if action != "put":
        headers["authorization"] = "Bearer " + i["secret"]
    if action in ("create", "remove"):
        return ok({"method": "PUT" if action == "create" else "DELETE", "url": url, "headers": headers})
    if action == "put":
        message = b_in(i["message"])
        headers.update(content_type="application/octet-stream", content_length=str(len(message)))
        return ok({"method": "PUT", "url": f"{url}/messages/{hashlib.sha256(message).hexdigest()}", "headers": headers})
    if action == "list":
        wait = i.get("wait")
        return ok({"method": "GET", "url": f"{url}/messages" + ("" if wait is None else f"?wait={wait}"), "headers": headers})
    return ok({"method": "GET" if action == "fetch" else "DELETE", "url": f"{url}/messages/{i['message_id']}", "headers": headers})


def op_reaction(i):
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


def op_listing(i):
    return ok({"messages": [{"id": m["id"], "size": m["size"]} for m in json.loads(i["body"])["messages"]]})


def op_relay(i):
    relay = tx.Relay(quota_bytes=i["quota_bytes"])
    steps = []
    for r in i["requests"]:
        status, _, body = relay.handle(r["method"], r["target"], r["headers"], b_in(r["body"]), now=r["now"])
        out = {"status": status}
        if status == 200 and r["target"].split("?")[0].endswith("/messages"):
            out["messages"] = json.loads(body)["messages"]
        elif status == 200:
            out["message"] = b_out(body)
        steps.append(out)
    return {"steps": steps}


# --- keys (spec/keys.md) ----------------------------------------------------------------


def live_parts(m):
    """Sender and signed bytes of a live message, found as keys.md, section 2.3, allows before verifying."""
    end = keys.envelope_end(m, 10)
    if end != len(m):
        raise ValueError("bytes left over after the envelope")
    _, pos = keys.read_long(m, 10)
    _, pos = keys.read_long(m, pos)
    return m[pos:pos + 32], keys.MESSAGE_PREFIX + m[10:-64], m[-64:]


def op_verify(i):
    problem = keys.verify_problem(b_in(i["public_key"]), b_in(i["data"]), b_in(i["signature"]))
    return ok() if problem is None else no("SIGNATURE_INVALID", problem)


def op_verify_message(i):
    sender, signed, sig = live_parts(b_in(i["message"]))
    problem = keys.verify_problem(sender, signed, sig)
    return ok() if problem is None else no("SIGNATURE_INVALID", problem)


def op_key_move(i):
    m = b_in(i["message"])
    sender, signed, sig = live_parts(m)
    if keys.verify_problem(sender, signed, sig):
        return no("SIGNATURE_INVALID")
    env = fastavro.schemaless_reader(io.BytesIO(m[10:]), pe.raw["Envelope"], pe.raw["Envelope"])
    body = env["body"]
    if env["kind"] != "KEY_MOVE" or body[:10] != b"\xc3\x01" + pe.fp8(pe.fingerprints["KeyMove"][1]):
        return no("INVALID_MESSAGE")
    km = fastavro.schemaless_reader(io.BytesIO(body[10:]), pe.raw["KeyMove"], pe.raw["KeyMove"])
    new, enc = km["new_sender"], km["new_encryption_key"]
    problem = (keys.key_problem(new)
               or keys.verify_problem(new, keys.KEY_MOVE_PREFIX + sender + new, km["proof"])
               or (enc is not None and keys.encryption_key_problem(enc)))
    if problem:
        return no("KEY_MOVE_REJECTED", problem)
    return ok({"old_key": sender.hex(), "new_key": new.hex(), "new_encryption_key": b_out(enc)})


def op_seal(i):
    message, key = b_in(i["message"]), b_in(i["encryption_key"])
    if keys.encryption_key_problem(key):
        return no("ENCRYPTION_KEY_INVALID")
    enc, shared = keys.encap(os.urandom(32), key)  # a fresh ephemeral key (spec/keys.md, section 4.3)
    ctx = keys.hpke_base_context(shared, keys.HPKE_INFO)
    sealed = keys.SEALED_FORMAT + enc + ChaCha20Poly1305(ctx["key"]).encrypt(ctx["base_nonce"], keys.pad(message), b"")
    return ok({"sealed": b_out(sealed)})


def op_open(i):
    sealed = b_in(i["sealed"])
    if sealed[:1] != keys.SEALED_FORMAT or len(sealed) < 1 + 32 + 16:
        return no("NOT_OPENED")
    for sk in i["private_keys"]:
        try:
            ctx = keys.hpke_base_context(keys.decap(sealed[1:33], bytes.fromhex(sk)), keys.HPKE_INFO)
            plain = ChaCha20Poly1305(ctx["key"]).decrypt(ctx["base_nonce"], sealed[33:], b"")
        except Exception:
            continue
        try:
            return ok({"message": b_out(keys.unpad(plain))})
        except ValueError as e:
            return no("PADDING_INVALID", str(e))
    return no("NOT_OPENED")


OPS = {
    "decode_body": op_decode_body,
    "read_file": op_read_file,
    "apply": op_apply,
    "parse_qr": op_parse_qr,
    "qr_text": lambda i: ok({"text": tx.qr_text(b_in(i["payload"]))}),
    "hello_frame": lambda i: ok({"frame": tx.hello(b_in(i["seed"]), tx.SERVER if i["role"] == "server" else tx.CLIENT,
                                              b_in(i["certificate_sha256"]), check=False).hex()}),
    "connection": op_connection,
    "mailbox_id": lambda i: ok({"mailbox": tx.mailbox_id(b_in(i["secret"])).hex()}),
    "request": op_request,
    "reaction": op_reaction,
    "listing": op_listing,
    "relay": op_relay,
    "choose_format": lambda i: ok({"format": pe.choose_format(i["own"], i["theirs"])}),
    "session": op_session,
    "fingerprint": op_fingerprint,
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
    "check_signing_key": lambda i: (lambda p: ok() if p is None else no("KEY_INVALID", p))(keys.key_problem(b_in(i["public_key"]))),
    "check_encryption_key": lambda i: (lambda p: ok() if p is None else no("ENCRYPTION_KEY_INVALID", p))(
        keys.encryption_key_problem(b_in(i["encryption_key"]))),
    "short_fingerprint": lambda i: ok({"short_fingerprint": keys.short_fingerprint(b_in(i["public_key"]))}),
    "verify_message": op_verify_message,
    "key_move": op_key_move,
    "padded_length": lambda i: ok({"padded_length": keys.padded_length(i["length"])}),
    "seal": op_seal,
    "open": op_open,
}


def main():
    for line in sys.stdin:
        request = json.loads(line)
        rid, op, i = request["id"], request["op"], request["input"]
        if op == "hello":
            answer = {"id": rid, "output": {"name": "AXT reference adapter (conformance/reference/adapter.py)",
                                            "categories": CATEGORIES}}
        elif op not in OPS:
            answer = {"id": rid, "unsupported": True}
        else:
            try:
                answer = {"id": rid, "output": OPS[op](i)}
            except Exception as e:  # a fault of this adapter, reported as such
                answer = {"id": rid, "failure": f"{type(e).__name__}: {e}"}
        sys.stdout.write(json.dumps(answer, ensure_ascii=False) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
