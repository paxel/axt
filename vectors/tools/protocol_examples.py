# SPDX-License-Identifier: CC0-1.0
"""Produce and check the examples of spec/protocol.md.

Checks the schemas of the protocol messages, types/axt/Offer.avsc,
Accept.avsc, Decline.avsc, Ack.avsc and Error.avsc, then plays a live
exchange from cat-a-log to Old Brain Fix with signed messages and prints
each as annotated hex:

- the schema rules of spec/types.md, section 5, with the checks of
  vectors/tools/example_types.py, as spec/manifest.md, section 9, applies
  them to a schema of the specification: a doc everywhere, names in the
  required case and beginning with the type's name, only ["null", T]
  unions with the default null, enum defaults, no recursion, the size and
  depth limits, no axt.version; and every name unique among all schemas
  of the specification;
- the Parsing Canonical Form and the CRC-64-AVRO fingerprint of each,
  against fastavro and the Apache avro package, and that the fingerprints
  of the envelope, the manifest and the key move are those published;
- every default once in schema resolution, with both libraries, and for
  every enum a symbol the reader does not know, which fastavro reads as
  the enum's default (the avro package 1.12.2 raises instead);
- the exchange: both MANIFEST messages (the manifests of spec/manifest.md,
  section 10, now signed), an OFFER of a Pet and an Appointment, an ACCEPT
  of the Appointment, a DECLINE of the Pet, a DATA message with the
  Appointment, the ACK, and the ERROR for a Pet record sent anyway. Each
  is built here field by field, compared with fastavro's encoding,
  decoded with fastavro and avro, signed with the pure-Python Ed25519 of
  keys_examples.py, PyNaCl and cryptography, which give the same
  signature, and verified with all three;
- a model of both apps that processes every message by the rules of
  spec/protocol.md: the order of the first messages, the format choice,
  offers, answers, the version rule, acknowledgements and errors; it
  checks the exchange above and a set of messages that must be ignored,
  answered as before, or reported with a given error code.

The key moves of spec/keys.md are checked by keys_examples.py; this script
checks only how a key move is acknowledged.

Run from anywhere, with fastavro, avro (1.12), pynacl and cryptography
installed:

    python3 vectors/tools/protocol_examples.py

The script imports manifest_examples.py, which runs that script's checks
with its output suppressed, and keys_examples.py, which runs none. Every
key is a TEST KEY of spec/keys.md, section 7.1, and MUST NOT be used
outside tests.
"""

import contextlib
import copy
import datetime
import hashlib
import importlib.util
import io
import json
import re
from pathlib import Path

import avro.errors
import avro.io
import avro.schema
import fastavro
import nacl.signing
from cryptography.hazmat.primitives.asymmetric import ed25519

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
AXT = REPO / "types" / "axt"
EXAMPLES = AXT / "example" / "v1"

_spec = importlib.util.spec_from_file_location("manifest_examples", HERE / "manifest_examples.py")
me = importlib.util.module_from_spec(_spec)
with contextlib.redirect_stdout(io.StringIO()):
    _spec.loader.exec_module(me)
rules, keys = me.rules, me.keys
zigzag = keys.zigzag

PROTOCOL = ["Offer", "Accept", "Decline", "Ack", "Error"]
ALL_SPEC = ["Envelope", "Manifest", "KeyMove"] + PROTOCOL

# --- the limits of spec/protocol.md -------------------------------------------

MAX_OFFER_TYPES = 256  # types of one offer; types of one ACCEPT or DECLINE
MAX_ACK_RECORDS = 4096
MAX_DETAIL = 1024  # bytes
MAX_ERROR_RECORD_ID = 64  # bytes
MAX_MESSAGE = 16777216  # spec/envelope.md, section 8
MAX_DATA_DEPTH = 32  # spec/types.md, section 5.7
UUID_TEXT = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
NIL_UUID, MAX_UUID = "0" * 32, "f" * 32

# --- schemas ------------------------------------------------------------------

texts = {n: (AXT / f"{n}.avsc").read_text(encoding="utf-8") for n in ALL_SPEC}
jsons = {n: json.loads(t) for n, t in texts.items()}
parsed = {n: fastavro.parse_schema(jsons[n]) for n in ALL_SPEC}
apache = {n: avro.schema.parse(texts[n]) for n in ALL_SPEC}


def without_logical_types(t):
    if isinstance(t, list):
        return [without_logical_types(b) for b in t]
    if isinstance(t, dict):
        t = {k: without_logical_types(v) for k, v in t.items() if k != "logicalType"}
        if set(t) == {"type"} and isinstance(t["type"], str):
            return t["type"]
    return t


# The model below reads ids as plain strings, so that it can check them itself (spec/envelope.md, section 7).
raw = {n: fastavro.parse_schema(without_logical_types(jsons[n]), _write_hint=False) for n in ALL_SPEC}

fingerprints = {n: me.fingerprint(texts[n]) for n in ALL_SPEC}  # (canonical form, fingerprint)
assert fingerprints["Envelope"][1] == 0xA2E1E84FE5E40C7D, "the envelope fingerprint is not that of spec/envelope.md"
assert fingerprints["Manifest"][1] == 0x23D471F564DEE5CB, "the manifest fingerprint is not that of spec/manifest.md"
assert fingerprints["KeyMove"][1] == 0xA9E20AFEA72F2876, "the key move fingerprint is not that of spec/keys.md"
assert len({fp for _, fp in fingerprints.values()}) == len(ALL_SPEC)

defined_by = {}
depths = {}
for n in ALL_SPEC:
    defined = me.named_types(jsons[n], [])
    for full in defined:
        assert full not in defined_by, f"{full} is defined in {n}.avsc and {defined_by[full]}.avsc"
        defined_by[full] = n
for n in PROTOCOL:
    s, where = jsons[n], f"types/axt/{n}.avsc"
    assert s["type"] == "record" and s["name"] == n and s["namespace"] == "axt", where
    assert "axt.version" not in s, f"{where}: a schema of the specification carries no axt.version"
    assert len(texts[n].encode("utf-8")) <= rules.MAX_SCHEMA_BYTES and rules.json_depth(s) <= rules.MAX_JSON_DEPTH
    depths[n] = rules.check_type(s, where, s, set(), [])
    assert depths[n] <= rules.MAX_DATA_DEPTH
    assert s["fields"][0]["name"] == "to" and s["fields"][0]["type"]["size"] == 32, f"{where}: to comes first"
if rules.failures:
    raise SystemExit("\n".join(["checks failed:"] + rules.failures))

# --- test keys (spec/keys.md, section 7.1) ------------------------------------


def test_secret(label):
    return hashlib.sha256(b"AXT test key, not for use: " + label.encode()).digest()


CAT_SEED = test_secret("cat-a-log, old phone, Ed25519")
OBF_SEED = test_secret("Old Brain Fix, Ed25519")
CAT = keys.public_key(CAT_SEED)
OBF = keys.public_key(OBF_SEED)
assert CAT.hex() == "1b84a600f3503e22bbcc99e63202a7194bf6bd69aff1471cce6410d53c26ec4a", "not the key of spec/keys.md"
OTHER = keys.public_key(test_secret("cat-a-log, new phone, Ed25519"))  # a third key, for forwarded messages
for k in (CAT, OBF, OTHER):
    assert keys.key_problem(k) is None


def all_sign(seed, data):
    """The signature, the same from keys_examples.py, PyNaCl and cryptography."""
    sig = keys.sign(seed, data)
    assert sig == nacl.signing.SigningKey(seed).sign(data).signature
    assert sig == ed25519.Ed25519PrivateKey.from_private_bytes(seed).sign(data)
    return sig


def all_verify(pub, data, sig):
    problem = keys.verify_problem(pub, data, sig)
    if problem is None:
        nacl.signing.VerifyKey(pub).verify(data, sig)
        ed25519.Ed25519PublicKey.from_public_bytes(pub).verify(sig, data)
    return problem


# --- encoding by hand ---------------------------------------------------------

KINDS = jsons["Envelope"]["fields"][1]["type"]["symbols"]
BODY_SCHEMA = {"MANIFEST": "Manifest", "OFFER": "Offer", "ACCEPT": "Accept", "DECLINE": "Decline",
               "ACK": "Ack", "ERROR": "Error", "KEY_MOVE": "KeyMove"}
RECORD_KINDS = {"DATA", "DELETE"}


def fp8(fp):
    return fp.to_bytes(8, "little")


def header(name):
    return [(b"\xc3\x01", "single-object marker"), (fp8(fingerprints[name][1]), f"fingerprint of axt.{name}, format 1")]


def string_parts(name, text, short=None):
    raw = text.encode("utf-8")
    return [(zigzag(len(raw)), f"{name}: string length {len(raw)}"), (raw, short or f'"{text}"', bool(short))]


def array_parts(name, items, item_parts):
    if not items:
        return [(zigzag(0), f"{name}: end of the array")]
    n = len(items)
    out = [(zigzag(n), f"{name}: array block of {n} item{'s' if n > 1 else ''}")]
    for i, item in enumerate(items):
        out += item_parts(f"{name}[{i}]", item)
    return out + [(zigzag(0), f"{name}: end of the array")]


def null_or(name, value, branch, parts_of):
    if value is None:
        return [(zigzag(0), f"{name}: union index 0, null")]
    return [(zigzag(1), f"{name}: union index 1, {branch}")] + parts_of(value)


def symbol(name, enum_type, value):
    i = enum_type["symbols"].index(value)
    return [(zigzag(i), f"{name}: enum index {i}, {value}")]


def to_parts(who):
    return [(who, f"to: fixed(32), {NAMES[who]}'s test key")]


def offer_type_parts(name, t):
    return string_parts(f"{name}.schema", t["schema"], short=t.get("short")) + [
        (zigzag(t["count"]), f"{name}.count: long {t['count']}")]


REASON = jsons["Decline"]["fields"][2]["type"]["items"]["fields"][1]["type"]
OUTCOME = jsons["Ack"]["fields"][1]["type"]["items"]["fields"][2]["type"]
CODE = jsons["Error"]["fields"][1]["type"]


def body_parts(name, d):
    """The body of a message of the specification, field by field, after its single-object header."""
    if name == "Offer":
        return to_parts(d["to"]) + string_parts("offer_id", d["offer_id"]) + array_parts(
            "types", d["types"], offer_type_parts)
    if name == "Accept":
        return to_parts(d["to"]) + string_parts("offer_id", d["offer_id"]) + array_parts(
            "types", d["types"], lambda n, t: string_parts(n, t))
    if name == "Decline":
        return to_parts(d["to"]) + string_parts("offer_id", d["offer_id"]) + array_parts(
            "types", d["types"], lambda n, t: string_parts(f"{n}.type", t["type"]) + symbol(f"{n}.reason", REASON, t["reason"]))
    if name == "Ack":
        def entry(n, r):
            return (string_parts(f"{n}.id", r["id"]) + [(zigzag(r["version"]), f"{n}.version: long {r['version']}")]
                    + symbol(f"{n}.outcome", OUTCOME, r["outcome"])
                    + [(zigzag(r["receiver_version"]), f"{n}.receiver_version: long {r['receiver_version']}")]
                    + array_parts(f"{n}.kept_fields", r["kept_fields"], lambda m, f: string_parts(m, f)))
        return to_parts(d["to"]) + array_parts("records", d["records"], entry) + null_or(
            "moved_from", d["moved_from"], "AckMovedFrom", lambda k: [(k, "moved_from: fixed(32)")])
    if name == "Error":
        return (to_parts(d["to"]) + symbol("code", CODE, d["code"])
                + [(d["message_hash"], "message_hash: fixed(32), SHA-256 of the reported message")]
                + null_or("record", d["record"], "ErrorRecord", lambda r: string_parts("record.id", r["id"]) + [
                    (zigzag(r["version"]), f"record.version: long {r['version']}")])
                + null_or("fingerprint", d["fingerprint"], "ErrorFingerprint", lambda f: [(f, "fingerprint: fixed(8)")])
                + string_parts("detail", d["detail"]))
    raise ValueError(name)


def library_binary(schema, datum):
    buf = io.BytesIO()
    fastavro.schemaless_writer(buf, schema, datum)
    return buf.getvalue()


def plain(value):
    """A decoded datum with UUIDs as text, for comparison."""
    if isinstance(value, dict):
        return {k: plain(v) for k, v in value.items()}
    if isinstance(value, list):
        return [plain(v) for v in value]
    return str(value) if type(value).__name__ == "UUID" else value


def wire(name, d):
    """The datum as fastavro and avro take it (without the display hints of the parts)."""
    if name == "Offer":
        return dict(d, types=[{"schema": t["schema"], "count": t["count"]} for t in d["types"]])
    return d


def make_body(name, d, check=True):
    parts = header(name) + body_parts(name, d)
    body = b"".join(p[0] for p in parts)
    if check:
        datum = wire(name, d)
        assert body[10:] == library_binary(parsed[name], datum), f"{name}: the body differs from fastavro's encoding"
        assert plain(fastavro.schemaless_reader(io.BytesIO(body[10:]), parsed[name], parsed[name])) == datum
        back = avro.io.DatumReader(apache[name]).read(avro.io.BinaryDecoder(io.BytesIO(body[10:])))
        assert plain(back) == datum, f"{name}: avro decodes another datum"
        out = io.BytesIO()
        avro.io.DatumWriter(apache[name]).write(back, avro.io.BinaryEncoder(out))
        assert out.getvalue() == body[10:], f"{name}: avro encodes the datum to other bytes"
    return parts, body


def make_message(kind, seed, record, body_parts_list, check=True, fmt=1):
    """A signed live message; returns (annotated parts, bytes)."""
    pub = keys.public_key(seed)
    body = b"".join(p[0] for p in body_parts_list)
    parts = header("Envelope") + [
        (zigzag(fmt), f"format: int {fmt}"),
        (zigzag(KINDS.index(kind)), f"kind: enum index {KINDS.index(kind)}, {kind}"),
        (pub, f"sender: fixed(32), {NAMES.get(pub, 'a')}'s test key"),
    ]
    if record is None:
        parts.append((zigzag(0), "record: union index 0, null"))
    else:
        parts += [(zigzag(1), "record: union index 1, axt.RecordRef")] + string_parts("record.id", record[0]) + [
            (zigzag(record[1]), f"record.version: long {record[1]}")]
    parts.append((zigzag(len(body)), f"body: bytes length {len(body)}"))
    parts += [(p[0], "body: " + p[1]) + tuple(p[2:]) for p in body_parts_list]
    unsigned = b"".join(p[0] for p in parts)
    sig = all_sign(seed, keys.MESSAGE_PREFIX + unsigned[10:]) if check else keys.sign(seed, keys.MESSAGE_PREFIX + unsigned[10:])
    parts.append((sig, "signature: fixed(64)"))
    message = unsigned + sig
    if check:
        env = {"format": fmt, "kind": kind, "sender": pub,
               "record": None if record is None else {"id": record[0], "version": record[1]},
               "body": body, "signature": sig}
        assert message[10:] == library_binary(parsed["Envelope"], env), f"{kind}: the envelope differs from fastavro"
        back = avro.io.DatumReader(apache["Envelope"]).read(avro.io.BinaryDecoder(io.BytesIO(message[10:])))
        assert plain(back) == env, f"{kind}: avro decodes another envelope"
        assert all_verify(pub, keys.MESSAGE_PREFIX + message[10:-64], message[-64:]) is None
    return parts, message


NAMES = {CAT: "cat-a-log", OBF: "Old Brain Fix", OTHER: "a third app"}

# --- a model of an app (spec/protocol.md) -------------------------------------


def uuid_problem(text):
    if not UUID_TEXT.match(text) or text.replace("-", "").lower() in (NIL_UUID, MAX_UUID):
        return True
    return False


def full_name(schema):
    return schema["name"] if "." in schema["name"] else f"{schema.get('namespace', '')}.{schema['name']}".lstrip(".")


def canonical_fp(schema_text):
    return rules.crc64_avro(fastavro.schema.to_parsing_canonical_form(
        fastavro.parse_schema(json.loads(schema_text), _write_hint=False)).encode())


def resolves(writer, reader):
    """The part of Avro schema resolution the examples need: the names, and every reader field
    without a default present in the writer."""
    if full_name(writer) != full_name(reader) and full_name(writer) not in reader.get("aliases", []):
        return False
    have = {f["name"] for f in writer["fields"]}
    return all(f["name"] in have or "default" in f for f in reader["fields"])


def data_depth(value):
    """The data depth of spec/types.md, section 5.7, of a decoded value: records, arrays and maps count."""
    if isinstance(value, dict):
        return 1 + max([data_depth(v) for v in value.values()], default=0)
    if isinstance(value, list):
        return 1 + max([data_depth(v) for v in value], default=0)
    return 0


class Rejected(Exception):
    def __init__(self, code, detail="", record=None, fingerprint=None, report=True):
        super().__init__(code)
        self.code, self.detail, self.record, self.fingerprint, self.report = code, detail, record, fingerprint, report


class App:
    """One installation in one live connection with one other app, which its user has accepted."""

    def __init__(self, name, seed, manifest, readers, decide, formats=(1,)):
        self.name, self.seed, self.pub = name, seed, keys.public_key(seed)
        self.manifest, self.readers, self.decide, self.formats = manifest, readers, decide, list(formats)
        self.peer, self.peer_manifest = None, None
        # as receiver
        self.current = {}  # type full name -> the current offer of that type from the peer
        self.answered = {}  # offer id -> the answers given
        self.records = {}  # record id -> {"type", "version", "state"}
        self.pending_acks = []
        # as sender
        self.latest = {}  # type full name -> the id of its latest offer to the peer
        self.offers = {}  # offer id -> {type full name: schema text}
        self.answers = {}  # (offer id, type full name) -> "ACCEPT" or the decline reason
        self.outcomes = {}  # (record id, version) -> the acknowledged outcome
        self.errors = []

    # sending

    def manifest_message(self):
        _, body = make_body_manifest(self.manifest)
        return make_message("MANIFEST", self.seed, None, header("Manifest") + [(body[10:], "the manifest")], check=False)[1]

    def offer(self, offer_id, types, check=True):
        assert self.peer_manifest is not None, "no OFFER before the other app's valid MANIFEST"
        entries = []
        for text, count, short in types:
            schema = json.loads(text)
            assert me.fit(self.peer_manifest, full_name(schema), me.schema_version(schema)) is not None
            entries.append({"schema": text, "count": count, "short": short})
            self.latest[full_name(schema)] = offer_id
        self.offers[offer_id] = {full_name(json.loads(t)): t for t, _, _ in types}
        d = {"to": self.peer, "offer_id": offer_id, "types": entries}
        return make_message("OFFER", self.seed, None, make_body("Offer", d, check)[0], check)

    def accepted(self, type_name):
        offer_id = self.latest.get(type_name)
        return offer_id is not None and self.answers.get((offer_id, type_name)) == "ACCEPT"

    def data(self, record_id, version, type_name, datum, check=True, enforce=True):
        assert not enforce or self.accepted(type_name), "no record message without an accepted offer of its type"
        text = self.offers[self.latest[type_name]][type_name] if type_name in self.latest else None
        schema = fastavro.parse_schema(json.loads(text), _write_hint=False)
        body = b"\xc3\x01" + fp8(canonical_fp(text)) + library_binary(schema, datum)
        return make_message("DATA", self.seed, (record_id, version), [(body, "the record")], check=False)[1]

    def reply(self, kind, d):
        return make_message(kind, self.seed, None, make_body(BODY_SCHEMA[kind], d, check=False)[0], check=False)[1]

    def ack(self):
        if not self.pending_acks:
            return None
        d = {"to": self.peer, "records": self.pending_acks[:MAX_ACK_RECORDS], "moved_from": None}
        self.pending_acks = self.pending_acks[MAX_ACK_RECORDS:]
        return self.reply("ACK", d)

    def close(self):
        """The connection ends: its offers end with it (spec/protocol.md, section 5.3)."""
        self.current, self.latest = {}, {}

    # receiving

    def receive(self, message):
        """Process one live message. Returns (what happened, replies)."""
        self.kind = None
        try:
            return self._receive(message)
        except Rejected as e:
            if not e.report or self.peer is None or self.kind == "ERROR":
                return (f"rejected {e.code}, not reported", [])
            if e.code in ("SIGNATURE_INVALID", "FORMAT_UNSUPPORTED", "INVALID_MESSAGE") and e.record is None:
                record = None
            else:
                record = e.record
            d = {"to": self.peer, "code": e.code, "message_hash": hashlib.sha256(message).digest(),
                 "record": record, "fingerprint": e.fingerprint, "detail": e.detail}
            return (f"rejected {e.code}", [self.reply("ERROR", d)])

    def _receive(self, m):
        if len(m) > MAX_MESSAGE:
            raise Rejected("TOO_LARGE")
        if m[:2] != b"\xc3\x01" or len(m) < 10 + 2 + 32 + 2 + 64:
            raise Rejected("INVALID_MESSAGE", "not a single-object encoding")
        if m[2:10] != fp8(fingerprints["Envelope"][1]):
            raise Rejected("FORMAT_UNSUPPORTED", fingerprint=m[2:10])
        try:
            end = keys.envelope_end(m, 10)
        except IndexError:
            raise Rejected("INVALID_MESSAGE", "truncated envelope")
        if end != len(m):
            raise Rejected("INVALID_MESSAGE", "bytes left over after the envelope")
        env = fastavro.schemaless_reader(io.BytesIO(m[10:]), raw["Envelope"], raw["Envelope"])
        if keys.verify_problem(env["sender"], keys.MESSAGE_PREFIX + m[10:-64], m[-64:]) is not None:
            raise Rejected("SIGNATURE_INVALID")
        kind, rec = env["kind"], env["record"]
        self.kind = kind
        record = None if rec is None else {"id": str(rec["id"]), "version": rec["version"]}
        if record is not None and len(record["id"].encode()) > MAX_ERROR_RECORD_ID:
            record = None
        if env["format"] != 1:
            raise Rejected("INVALID_MESSAGE", "format does not match the envelope fingerprint", record)
        if self.peer is not None and env["sender"] != self.peer:
            raise Rejected("INVALID_MESSAGE", "another sender in this connection", report=False)
        if kind == "ERROR" and self.peer is None:
            raise Rejected("INVALID_MESSAGE", "an ERROR before the MANIFEST", report=False)
        if kind not in ("MANIFEST", "KEY_MOVE", "ERROR") and self.peer_manifest is None:
            raise Rejected("INVALID_MESSAGE", "a message before the MANIFEST", report=False)
        if (rec is None) == (kind in RECORD_KINDS):
            raise Rejected("INVALID_MESSAGE", "record field present or missing", record)
        body = env["body"]
        if kind == "DELETE":
            if body:
                raise Rejected("INVALID_MESSAGE", "a DELETE with a body", record)
            return self._record(kind, record, rec, None)
        if kind == "DATA":
            return self._record(kind, record, rec, body)
        name = BODY_SCHEMA[kind]
        if body[:2] != b"\xc3\x01" or body[2:10] != fp8(fingerprints[name][1]):
            raise Rejected("INVALID_MESSAGE", f"the body is not an axt.{name}", record)
        buf = io.BytesIO(body[10:])
        try:
            d = plain(fastavro.schemaless_reader(buf, raw[name], raw[name]))
        except Exception:
            raise Rejected("INVALID_MESSAGE", f"the body is not an axt.{name}")
        if buf.tell() != len(body) - 10:
            raise Rejected("INVALID_MESSAGE", "bytes left over after the body")
        if kind == "MANIFEST":
            return self._manifest(env["sender"], d, len(body))
        if kind == "ERROR":
            if d["to"] != self.pub:
                return ("ignored: addressed to another key", [])
            return self._error(d)
        if d["to"] != self.pub:
            return ("ignored: addressed to another key", [])
        return {"OFFER": self._offer, "ACCEPT": self._answer, "DECLINE": self._answer, "ACK": self._ack}[kind](kind, d)

    def _manifest(self, sender, d, body_length):
        problems = me.manifest_problems(d, body_length)
        if problems:
            self.peer = self.peer or sender
            raise Rejected("MANIFEST_INVALID", problems[0])
        self.peer, self.peer_manifest = sender, d
        replies = []
        if choose_format(self.formats, d["formats"]) is None:
            return ("no common format: close", [])
        return ("manifest taken", replies)

    def _offer(self, kind, d):
        if uuid_problem(d["offer_id"]):
            raise Rejected("OFFER_INVALID", "offer_id is not a valid UUID")
        if d["offer_id"] in self.answered:
            return ("answered again as before", self.answered[d["offer_id"]])
        if not 1 <= len(d["types"]) <= MAX_OFFER_TYPES:
            raise Rejected("OFFER_INVALID", "not 1 to 256 types")
        entries, names, fps = [], set(), set()
        for t in d["types"]:
            text = t["schema"]
            if len(text.encode("utf-8")) > rules.MAX_SCHEMA_BYTES:
                raise Rejected("TOO_LARGE", "a schema above 256 KiB")
            try:
                schema = json.loads(text)
            except ValueError:
                raise Rejected("OFFER_INVALID", "a schema that is not JSON")
            if rules.json_depth(schema) > rules.MAX_JSON_DEPTH:
                raise Rejected("TOO_LARGE", "a schema nested above 64")
            try:
                fastavro.parse_schema(schema, _write_hint=False)
                avro.schema.parse(text)
            except Exception:
                raise Rejected("OFFER_INVALID", "not an Avro schema")
            if not isinstance(schema, dict) or schema.get("type") != "record":
                raise Rejected("OFFER_INVALID", "not a record schema")
            if t["count"] < 0:
                raise Rejected("OFFER_INVALID", "a count below 0")
            name, fp = full_name(schema), canonical_fp(text)
            if name in names or fp in fps:
                raise Rejected("OFFER_INVALID", "a full name or a fingerprint twice")
            names.add(name)
            fps.add(fp)
            entries.append((name, fp, schema, text))
        accept, decline = [], []
        for name, fp, schema, text in entries:
            self.current[name] = {"offer_id": d["offer_id"], "fp": fp, "schema": text, "accepted": False}
            reader = self.readers.get(name)
            if me.fit(self.manifest, name, me.schema_version(schema)) is None:
                decline.append({"type": name, "reason": "DOES_NOT_FIT"})
            elif reader is not None and not resolves(schema, reader):
                decline.append({"type": name, "reason": "DOES_NOT_RESOLVE"})
            elif not self.decide(name):
                decline.append({"type": name, "reason": "NOT_WANTED"})
            else:
                accept.append(name)
                self.current[name]["accepted"] = True
        replies = []
        if accept:
            replies.append(self.reply("ACCEPT", {"to": self.peer, "offer_id": d["offer_id"], "types": accept}))
        if decline:
            replies.append(self.reply("DECLINE", {"to": self.peer, "offer_id": d["offer_id"], "types": decline}))
        self.answered[d["offer_id"]] = replies
        return ("answered", replies)

    def _answer(self, kind, d):
        offer = self.offers.get(d["offer_id"])
        if offer is None:
            return ("ignored: not an offer of this app", [])
        names = [t if kind == "ACCEPT" else t["type"] for t in d["types"]]
        if not 1 <= len(names) <= MAX_OFFER_TYPES or len(set(names)) != len(names) or not set(names) <= set(offer):
            raise Rejected("INVALID_MESSAGE", "the types are not types of the offer")
        taken = 0
        for t in d["types"]:
            name = t if kind == "ACCEPT" else t["type"]
            if self.latest.get(name) != d["offer_id"] or (d["offer_id"], name) in self.answers:
                continue  # an earlier offer of the type, or answered already: the first answer stands
            self.answers[(d["offer_id"], name)] = "ACCEPT" if kind == "ACCEPT" else t["reason"]
            taken += 1
        return (f"{taken} answers taken", [])

    def _record(self, kind, record, rec, body):
        rid, version = str(rec["id"]), rec["version"]
        if uuid_problem(rid):
            raise Rejected("RECORD_ID_INVALID", record=record)
        if version < 1:
            raise Rejected("VERSION_INVALID", record=record)
        key = rid.lower()
        kept = self.records.get(key)
        if kind == "DATA":
            if body[:2] != b"\xc3\x01" or len(body) < 10:
                raise Rejected("UNDECODABLE", "not a single-object encoding", record)
            fp = int.from_bytes(body[2:10], "little")
            offer = next((o for o in self.current.values() if o["fp"] == fp), None)
            if offer is None:
                raise Rejected("SCHEMA_UNKNOWN", record=record, fingerprint=body[2:10])
            schema = json.loads(offer["schema"])
            name = full_name(schema)
            if not offer["accepted"] or me.fit(self.manifest, name, me.schema_version(schema)) is None:
                raise Rejected("NOT_ACCEPTED", name, record)
            if kept is not None and kept["type"] is not None and kept["type"] != name:
                raise Rejected("TYPE_CHANGED", f"{kept['type']} before, {name} now", record)
        else:
            name = kept["type"] if kept else None
            covered = (self.current.get(name, {}).get("accepted") if name
                       else any(o["accepted"] for o in self.current.values()))
            if not covered:
                raise Rejected("NOT_ACCEPTED", "no accepted offer covers the deletion", record)
        if kept is not None and version <= kept["version"]:
            outcome = "DUPLICATE" if version == kept["version"] else "STALE"
            self.pending_acks.append({"id": rid, "version": version, "outcome": outcome,
                                      "receiver_version": kept["version"], "kept_fields": []})
            return (outcome, [])
        if kind == "DATA":
            writer = fastavro.parse_schema(schema, _write_hint=False)
            reader = self.readers.get(name)
            buf = io.BytesIO(body[10:])
            try:
                value = fastavro.schemaless_reader(buf, writer, fastavro.parse_schema(reader, _write_hint=False) if reader else writer)
            except Exception:
                raise Rejected("UNDECODABLE", "the body does not decode", record)
            if buf.tell() != len(body) - 10:
                raise Rejected("UNDECODABLE", "bytes left over after the record", record)
            if data_depth(value) > MAX_DATA_DEPTH:
                raise Rejected("UNDECODABLE", "data depth above 32", record)
            self.records[key] = {"type": name, "version": version, "state": "there", "value": value}
        else:
            self.records[key] = {"type": name, "version": version, "state": "tombstone", "value": None}
        self.pending_acks.append({"id": rid, "version": version, "outcome": "APPLIED",
                                  "receiver_version": version, "kept_fields": []})
        return ("APPLIED", [])

    def _ack(self, kind, d):
        if not d["records"] and d["moved_from"] is None or len(d["records"]) > MAX_ACK_RECORDS:
            raise Rejected("INVALID_MESSAGE", "not 1 to 4096 records, or 0 with a key move")
        seen = set()
        for r in d["records"]:
            k = (r["id"].lower(), r["version"])
            stale = r["outcome"] == "STALE"
            if (uuid_problem(r["id"]) or r["version"] < 1 or k in seen
                    or (r["receiver_version"] > r["version"]) != stale or r["receiver_version"] < r["version"]
                    or (r["outcome"] == "MERGED") != bool(r["kept_fields"])
                    or len(set(r["kept_fields"])) != len(r["kept_fields"])):
                raise Rejected("INVALID_MESSAGE", "an invalid acknowledgement entry")
            seen.add(k)
        for r in d["records"]:
            k = (r["id"].lower(), r["version"])
            before = self.outcomes.get(k)
            if (before is None or (before == "DUPLICATE" and r["outcome"] != "DUPLICATE")
                    or (r["outcome"] == "APPLIED" and before in ("KEPT", "MERGED"))):
                self.outcomes[k] = r["outcome"]
        return ("acknowledged", [])

    def _error(self, d):
        rec = d["record"]
        if rec is not None and (rec["id"].lower(), rec["version"]) in self.outcomes:
            return ("ignored: the message was acknowledged", [])
        self.errors.append(d["code"])
        return (f"error {d['code']} noted", [])


def make_body_manifest(manifest):
    body = me.encode_body(manifest)
    return None, body


def choose_format(own, theirs):
    """The highest envelope format both apps read, or None (spec/protocol.md, section 3.2)."""
    common = set(own) & set(theirs)
    return max(common) if common else None


# --- the exchange -------------------------------------------------------------


def compact(path):
    """The full JSON text of a schema file, doc attributes included, without whitespace; built from
    the file's text, not from a parsed schema."""
    return json.dumps(json.loads(path.read_text(encoding="utf-8")), separators=(",", ":"), ensure_ascii=False)


PET_TEXT = compact(EXAMPLES / "Pet.1.avsc")
APPOINTMENT_TEXT = compact(EXAMPLES / "Appointment.1.avsc")
APPOINTMENT_READER = json.loads((EXAMPLES / "Appointment.1.avsc").read_text(encoding="utf-8"))
OFFER_ID = "6f1c2b9e-3d4a-4e5f-8a7b-1c2d3e4f5a6b"
APPOINTMENT_ID = "a2d4f6b8-1c3e-4a5b-9d7f-0e2c4a6b8d1f"
PET_ID = "5e8a1f3c-7b2d-4c6e-a9f0-3d5b7c9e1a2f"
APPOINTMENT = rules.DATA["Appointment"]
PET = rules.DATA["Pet"]

obf_decide = {"axt.example.v1.Appointment": True}
cat_app = App("cat-a-log", CAT_SEED, me.CAT_A_LOG, {}, lambda n: True)
obf_app = App("Old Brain Fix", OBF_SEED, me.OLD_BRAIN_FIX, {"axt.example.v1.Appointment": APPOINTMENT_READER},
              lambda n: obf_decide.get(n, False))

shown = []  # (title, parts, message)


def manifest_parts(app, manifest, label):
    _, body = make_body_manifest(manifest)
    expected = next(b for name, _, _, b in me.messages if name == manifest["app_name"])
    assert body == expected, "the manifest's body is not that of spec/manifest.md, section 10.3"
    bparts = [(body[:2], "single-object marker"), (body[2:10], "fingerprint of axt.Manifest, format 1"),
              (body[10:], label, True)]
    parts, message = make_message("MANIFEST", app.seed, None, bparts)
    return parts, message


m1_parts, m1 = manifest_parts(cat_app, me.CAT_A_LOG, f"the manifest of spec/manifest.md, section 10.3, from 0039")
m2_parts, m2 = manifest_parts(obf_app, me.OLD_BRAIN_FIX, f"the manifest of spec/manifest.md, section 10.3, from 0039")
assert cat_app.manifest_message() == m1 and obf_app.manifest_message() == m2

# 1. and 2. The manifests, in both directions; each app chooses the format.
assert obf_app.receive(m1) == ("manifest taken", [])
assert cat_app.receive(m2) == ("manifest taken", [])
assert choose_format(cat_app.formats, obf_app.peer_manifest["formats"]) == 1

# 3. The offer of a Pet and an Appointment.
fits = [(full, me.fit(me.OLD_BRAIN_FIX, full, 1)) for full in ("axt.example.v1.Pet", "axt.example.v1.Appointment")]
assert fits[0][1] is me.OLD_BRAIN_FIX["any_type"] and fits[1][1] is me.OLD_BRAIN_FIX["takes"][0]
o_parts, offer_msg = cat_app.offer(OFFER_ID, [
    (PET_TEXT, 1, f"Pet.1.avsc without whitespace ({len(PET_TEXT.encode())} bytes of UTF-8 JSON)"),
    (APPOINTMENT_TEXT, 1, f"Appointment.1.avsc without whitespace ({len(APPOINTMENT_TEXT.encode())} bytes of UTF-8 JSON)"),
])
for text in (PET_TEXT, APPOINTMENT_TEXT):
    assert canonical_fp(text) == rules.crc64_avro(fastavro.schema.to_parsing_canonical_form(
        fastavro.parse_schema(json.loads(text))).encode())
assert canonical_fp(APPOINTMENT_TEXT) == 0x1B57DE39E9441B59 and canonical_fp(PET_TEXT) == 0x2D9F89A71269EB61

# 4. and 5. Old Brain Fix accepts the Appointment and declines the Pet; cat-a-log takes both answers.
what, replies = obf_app.receive(offer_msg)
assert what == "answered" and len(replies) == 2, what
accept_msg, decline_msg = replies
a_parts, a_check = make_message("ACCEPT", OBF_SEED, None, make_body("Accept", {
    "to": CAT, "offer_id": OFFER_ID, "types": ["axt.example.v1.Appointment"]})[0])
d_parts, d_check = make_message("DECLINE", OBF_SEED, None, make_body("Decline", {
    "to": CAT, "offer_id": OFFER_ID, "types": [{"type": "axt.example.v1.Pet", "reason": "NOT_WANTED"}]})[0])
assert (accept_msg, decline_msg) == (a_check, d_check)
assert cat_app.receive(accept_msg) == ("1 answers taken", [])
assert cat_app.receive(decline_msg) == ("1 answers taken", [])
assert cat_app.accepted("axt.example.v1.Appointment") and not cat_app.accepted("axt.example.v1.Pet")


# 6. The Appointment, version 1.
def local_millis(dt):
    return (dt - datetime.datetime(1970, 1, 1)) // datetime.timedelta(milliseconds=1)


def appointment_parts(a):
    return [
        *string_parts("title", a["title"]),
        (zigzag(local_millis(a["start"])), f"start: long {local_millis(a['start'])} ({a['start']:%Y-%m-%d %H:%M})"),
        (zigzag(1), "end: union index 1, long"),
        (zigzag(local_millis(a["end"])), f"end: long {local_millis(a['end'])} ({a['end']:%Y-%m-%d %H:%M})"),
        (zigzag(1), "time_zone: union index 1, string"),
        *string_parts("time_zone", a["time_zone"]),
        (b"\x01" if a["all_day"] else b"\x00", f"all_day: boolean {str(a['all_day']).lower()}"),
        *string_parts("location", a["location"]),
        *string_parts("notes", a["notes"]),
        *array_parts("reminders", a["reminders"], lambda n, v: [(zigzag(v), f"{n}: int {v}")]),
    ]


ap_body_parts = [(b"\xc3\x01", "single-object marker"),
                 (fp8(0x1B57DE39E9441B59), "fingerprint of axt.example.v1.Appointment, version 1")] + appointment_parts(APPOINTMENT)
ap_body = b"".join(p[0] for p in ap_body_parts)
assert ap_body[10:] == library_binary(fastavro.parse_schema(json.loads(APPOINTMENT_TEXT)), APPOINTMENT)
# avro 1.12.2 reads local-timestamp-millis as a long (spec/types.md, section 5.5).
apache_appointment = avro.schema.parse(APPOINTMENT_TEXT)
back = avro.io.DatumReader(apache_appointment).read(avro.io.BinaryDecoder(io.BytesIO(ap_body[10:])))
assert back == dict(APPOINTMENT, start=local_millis(APPOINTMENT["start"]), end=local_millis(APPOINTMENT["end"]))
out = io.BytesIO()
avro.io.DatumWriter(apache_appointment).write(back, avro.io.BinaryEncoder(out))
assert out.getvalue() == ap_body[10:], "avro encodes the Appointment to other bytes"
data_parts, data_msg = make_message("DATA", CAT_SEED, (APPOINTMENT_ID, 1), ap_body_parts)
assert cat_app.data(APPOINTMENT_ID, 1, "axt.example.v1.Appointment", APPOINTMENT) == data_msg
assert obf_app.receive(data_msg) == ("APPLIED", [])
assert obf_app.records[APPOINTMENT_ID]["value"] == APPOINTMENT

# 7. The acknowledgement.
ack_msg = obf_app.ack()
k_parts, k_check = make_message("ACK", OBF_SEED, None, make_body("Ack", {
    "to": CAT, "records": [{"id": APPOINTMENT_ID, "version": 1, "outcome": "APPLIED", "receiver_version": 1,
                            "kept_fields": []}], "moved_from": None})[0])
assert ack_msg == k_check
assert cat_app.receive(ack_msg) == ("acknowledged", [])
assert cat_app.outcomes == {(APPOINTMENT_ID, 1): "APPLIED"}

# 8. A Pet record sent anyway is not accepted.
pet_msg = cat_app.data(PET_ID, 1, "axt.example.v1.Pet", PET, enforce=False)
what, replies = obf_app.receive(pet_msg)
assert what == "rejected NOT_ACCEPTED" and len(replies) == 1
error_msg = replies[0]
e_parts, e_check = make_message("ERROR", OBF_SEED, None, make_body("Error", {
    "to": CAT, "code": "NOT_ACCEPTED", "message_hash": hashlib.sha256(pet_msg).digest(),
    "record": {"id": PET_ID, "version": 1}, "fingerprint": None, "detail": "axt.example.v1.Pet"})[0])
assert error_msg == e_check
assert cat_app.receive(error_msg) == ("error NOT_ACCEPTED noted", [])
assert PET_ID not in obf_app.records

shown += [
    ("cat-a-log's MANIFEST", m1_parts, m1),
    ("Old Brain Fix's MANIFEST", m2_parts, m2),
    ("cat-a-log's OFFER", o_parts, offer_msg),
    ("Old Brain Fix's ACCEPT", a_parts, accept_msg),
    ("Old Brain Fix's DECLINE", d_parts, decline_msg),
    ("cat-a-log's DATA", data_parts, data_msg),
    ("Old Brain Fix's ACK", k_parts, ack_msg),
    ("Old Brain Fix's ERROR", e_parts, error_msg),
]

# --- repeats, forwarded messages and errors -----------------------------------

checks = []


def expect(label, got, want):
    assert got == want, (label, got, want)
    checks.append(label)


def code_of(result):
    what, replies = result
    if not replies:
        return what
    env = fastavro.schemaless_reader(io.BytesIO(replies[0][10:]), parsed["Envelope"], parsed["Envelope"])
    return KINDS[KINDS.index(env["kind"])] + " " + plain(fastavro.schemaless_reader(
        io.BytesIO(env["body"][10:]), parsed["Error"], parsed["Error"]))["code"] if env["kind"] == "ERROR" else what


def resign(seed, message):
    """The same message with a fresh signature, after its bytes were changed."""
    return message[:-64] + keys.sign(seed, keys.MESSAGE_PREFIX + message[10:-64])


def obf_data(record_id, version, text, datum, seed=CAT_SEED):
    body = b"\xc3\x01" + fp8(canonical_fp(text)) + library_binary(fastavro.parse_schema(json.loads(text), _write_hint=False), datum)
    return make_message("DATA", seed, (record_id, version), [(body, "")], check=False)[1]


# Repeats are safe.
expect("a repeated OFFER is answered as before", obf_app.receive(offer_msg), ("answered again as before", [accept_msg, decline_msg]))
expect("a repeated ACCEPT changes nothing", cat_app.receive(accept_msg), ("0 answers taken", []))
expect("a repeated DATA is a duplicate", obf_app.receive(data_msg), ("DUPLICATE", []))
dup_ack = obf_app.ack()
expect("a repeated ACK changes nothing", (cat_app.receive(ack_msg), cat_app.outcomes[(APPOINTMENT_ID, 1)]), (("acknowledged", []), "APPLIED"))
expect("an ACK of a duplicate keeps the outcome", (cat_app.receive(dup_ack), cat_app.outcomes[(APPOINTMENT_ID, 1)]), (("acknowledged", []), "APPLIED"))
expect("a repeated MANIFEST is taken again", obf_app.receive(m1), ("manifest taken", []))
expect("an ERROR about an acknowledged record is ignored",
       cat_app.receive(obf_app.reply("ERROR", {"to": CAT, "code": "UNDECODABLE", "message_hash": bytes(32),
                                               "record": {"id": APPOINTMENT_ID, "version": 1}, "fingerprint": None, "detail": ""})),
       ("ignored: the message was acknowledged", []))

# The first answer for a type of an offer stands.
late_accept = obf_app.reply("ACCEPT", {"to": CAT, "offer_id": OFFER_ID, "types": ["axt.example.v1.Pet"]})
expect("an ACCEPT after the DECLINE of the same type is ignored", (cat_app.receive(late_accept), cat_app.accepted("axt.example.v1.Pet")),
       (("0 answers taken", []), False))

# Forwarded and unknown answers are ignored.
expect("an ACCEPT addressed to another key is ignored",
       cat_app.receive(obf_app.reply("ACCEPT", {"to": OTHER, "offer_id": OFFER_ID, "types": ["axt.example.v1.Appointment"]})),
       ("ignored: addressed to another key", []))
expect("an ACCEPT of an offer the app did not make is ignored",
       cat_app.receive(obf_app.reply("ACCEPT", {"to": CAT, "offer_id": PET_ID, "types": ["axt.example.v1.Pet"]})),
       ("ignored: not an offer of this app", []))
expect("an ACCEPT naming a type the offer does not have",
       code_of(cat_app.receive(obf_app.reply("ACCEPT", {"to": CAT, "offer_id": OFFER_ID, "types": ["axt.example.v1.Note"]}))),
       "ERROR INVALID_MESSAGE")
fwd = cat_app.reply("OFFER", {"to": OTHER, "offer_id": "7a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d",
                              "types": [{"schema": APPOINTMENT_TEXT, "count": 1}]})
expect("an OFFER addressed to another key is ignored", obf_app.receive(fwd), ("ignored: addressed to another key", []))

# Record messages that cannot be processed.
expect("DATA with version 0", code_of(obf_app.receive(obf_data(APPOINTMENT_ID, 0, APPOINTMENT_TEXT, APPOINTMENT))), "ERROR VERSION_INVALID")
expect("DATA with the nil UUID", code_of(obf_app.receive(obf_data("00000000-0000-0000-0000-000000000000", 1, APPOINTMENT_TEXT, APPOINTMENT))),
       "ERROR RECORD_ID_INVALID")
expect("DATA with an id that is not a UUID", code_of(obf_app.receive(obf_data("vet-appointment", 1, APPOINTMENT_TEXT, APPOINTMENT))),
       "ERROR RECORD_ID_INVALID")
NOTE_TEXT = compact(EXAMPLES / "Note.1.avsc")
what, replies = obf_app.receive(obf_data("c1d2e3f4-a5b6-4c7d-8e9f-0a1b2c3d4e5f", 1, NOTE_TEXT, rules.DATA["Note"]))
err = plain(fastavro.schemaless_reader(io.BytesIO(fastavro.schemaless_reader(
    io.BytesIO(replies[0][10:]), parsed["Envelope"], parsed["Envelope"])["body"][10:]), parsed["Error"], parsed["Error"]))
expect("DATA with a schema that was not offered asks for it",
       (what, err["fingerprint"]), ("rejected SCHEMA_UNKNOWN", fp8(canonical_fp(NOTE_TEXT))))
upper = obf_data(APPOINTMENT_ID.upper(), 2, APPOINTMENT_TEXT, dict(APPOINTMENT, title="Vet: vaccination and check-up"))
expect("DATA with the id in upper case is the same record", (obf_app.receive(upper), obf_app.records[APPOINTMENT_ID]["version"]),
       (("APPLIED", []), 2))
expect("a lower version is stale", obf_app.receive(data_msg), ("STALE", []))
stale_ack = obf_app.ack()
expect("the ACK reports the receiver's version", plain(fastavro.schemaless_reader(io.BytesIO(fastavro.schemaless_reader(
    io.BytesIO(stale_ack[10:]), parsed["Envelope"], parsed["Envelope"])["body"][10:]), parsed["Ack"], parsed["Ack"]))["records"][-1],
    {"id": APPOINTMENT_ID, "version": 1, "outcome": "STALE", "receiver_version": 2, "kept_fields": []})
left = obf_data(APPOINTMENT_ID, 3, APPOINTMENT_TEXT, APPOINTMENT)
env = fastavro.schemaless_reader(io.BytesIO(left[10:]), parsed["Envelope"], parsed["Envelope"])
extra = make_message("DATA", CAT_SEED, (APPOINTMENT_ID, 3), [(env["body"] + b"\x00", "")], check=False)[1]
expect("DATA with a byte left over after the record", code_of(obf_app.receive(extra)), "ERROR UNDECODABLE")
short = make_message("DATA", CAT_SEED, (APPOINTMENT_ID, 3), [(env["body"][:-3], "")], check=False)[1]
expect("DATA cut short", code_of(obf_app.receive(short)), "ERROR UNDECODABLE")
bad_sig = data_msg[:-1] + bytes([data_msg[-1] ^ 1])
expect("a signature that does not verify", code_of(obf_app.receive(bad_sig)), "ERROR SIGNATURE_INVALID")
expect("bytes left over after the envelope", code_of(obf_app.receive(data_msg + b"\x00")), "ERROR INVALID_MESSAGE")
fmt2 = resign(CAT_SEED, data_msg[:10] + zigzag(2) + data_msg[11:])
expect("a format field that is not the envelope's format", code_of(obf_app.receive(fmt2)), "ERROR INVALID_MESSAGE")
expect("an unknown envelope fingerprint", code_of(obf_app.receive(data_msg[:2] + bytes(8) + data_msg[10:])), "ERROR FORMAT_UNSUPPORTED")
expect("a message above 16 MiB", code_of(obf_app.receive(data_msg + bytes(MAX_MESSAGE))), "ERROR TOO_LARGE")
del_unknown = make_message("DELETE", CAT_SEED, ("d4c3b2a1-0f9e-4d8c-b7a6-5f4e3d2c1b0a", 4), [], check=False)[1]
expect("a DELETE of an id the receiver does not have leaves a tombstone",
       (obf_app.receive(del_unknown), obf_app.records["d4c3b2a1-0f9e-4d8c-b7a6-5f4e3d2c1b0a"]["state"]), (("APPLIED", []), "tombstone"))
del_body = make_message("DELETE", CAT_SEED, (APPOINTMENT_ID, 5), [(b"\xc3\x01" + bytes(8), "")], check=False)[1]
expect("a DELETE with a body", code_of(obf_app.receive(del_body)), "ERROR INVALID_MESSAGE")

# A record under another type than before.
TASK_TEXT = compact(EXAMPLES / "Task.1.avsc")
obf_decide["axt.example.v1.Task"] = True
task_offer = cat_app.reply("OFFER", {"to": OBF, "offer_id": "0c9b8a7f-6e5d-4c3b-a291-8f7e6d5c4b3a",
                                     "types": [{"schema": TASK_TEXT, "count": 1}]})
expect("an offer of a Task is accepted", [m[11] for m in obf_app.receive(task_offer)[1]], [zigzag(KINDS.index("ACCEPT"))[0]])
expect("DATA of a Task under the id of the Appointment",
       code_of(obf_app.receive(obf_data(APPOINTMENT_ID, 9, TASK_TEXT, rules.DATA["Task"]))), "ERROR TYPE_CHANGED")

# The data depth limit, with a recursive app type that Old Brain Fix takes as any type.
OUTLINE = {"type": "record", "name": "Outline", "namespace": "org.example.outline", "doc": "An outline item.",
           "fields": [{"name": "text", "type": "string", "doc": "The item's text."},
                      {"name": "children", "type": {"type": "array", "items": "Outline"}, "doc": "The items below it."}]}
OUTLINE_TEXT = json.dumps(OUTLINE, separators=(",", ":"))
outline_offer = cat_app.reply("OFFER", {"to": OBF, "offer_id": "1d2e3f40-5a6b-4c7d-9e8f-a0b1c2d3e4f5",
                                        "types": [{"schema": OUTLINE_TEXT, "count": 2}]})
obf_decide["org.example.outline.Outline"] = True
obf_app.receive(outline_offer)


def outline(levels):
    item = {"text": "x", "children": []}
    for _ in range(levels - 1):
        item = {"text": "x", "children": [item]}
    return item


expect("a record of data depth 32 is taken", (data_depth(outline(16)), obf_app.receive(obf_data(
    "2e3f4051-6b7c-4d8e-8f90-b1c2d3e4f506", 1, OUTLINE_TEXT, outline(16)))), (32, ("APPLIED", [])))
expect("a record of data depth 34 is rejected", (data_depth(outline(17)), code_of(obf_app.receive(obf_data(
    "3f405162-7c8d-4e9f-90a1-c2d3e4f50617", 1, OUTLINE_TEXT, outline(17))))), (34, "ERROR UNDECODABLE"))

# Offers that are invalid, and types that do not fit or do not resolve.
bad = lambda types, oid="4a5b6c7d-8e9f-4a0b-9c1d-2e3f4a5b6c7d": cat_app.reply("OFFER", {"to": OBF, "offer_id": oid, "types": types})
expect("an offer without types", code_of(obf_app.receive(bad([]))), "ERROR OFFER_INVALID")
expect("an offer with a full name twice", code_of(obf_app.receive(bad([{"schema": PET_TEXT, "count": 0}] * 2))), "ERROR OFFER_INVALID")
expect("an offer with an id that is not a UUID", code_of(obf_app.receive(bad([{"schema": PET_TEXT, "count": 0}], oid="offer-1"))),
       "ERROR OFFER_INVALID")
big_doc = json.dumps(dict(json.loads(PET_TEXT), doc="x" * rules.MAX_SCHEMA_BYTES), separators=(",", ":"))
expect("an offer with a schema above 256 KiB", code_of(obf_app.receive(bad([{"schema": big_doc, "count": 0}]))), "ERROR TOO_LARGE")
expect("an offer with a schema that is not a record",
       code_of(obf_app.receive(bad([{"schema": '{"type":"enum","name":"E","symbols":["A"]}', "count": 0}]))), "ERROR OFFER_INVALID")
narrow_reader = dict(APPOINTMENT_READER, fields=APPOINTMENT_READER["fields"] + [
    {"name": "room", "type": "string", "doc": "A field without a default that the writer lacks."}])
strict_obf = App("Old Brain Fix", OBF_SEED, me.OLD_BRAIN_FIX, {"axt.example.v1.Appointment": narrow_reader}, lambda n: True)
strict_obf.receive(m1)
reason = lambda app, message: plain(fastavro.schemaless_reader(io.BytesIO(fastavro.schemaless_reader(
    io.BytesIO(app.receive(message)[1][0][10:]), parsed["Envelope"], parsed["Envelope"])["body"][10:]), parsed["Decline"], parsed["Decline"]))["types"][0]["reason"]
expect("an offer whose schema does not resolve is declined", reason(strict_obf, cat_app.reply("OFFER", {"to": OBF, "offer_id": "5b6c7d8e-9f0a-4b1c-8d2e-3f4a5b6c7d8e",
                                                  "types": [{"schema": APPOINTMENT_TEXT, "count": 1}]})), "DOES_NOT_RESOLVE")
# Old Brain Fix offers a Note to cat-a-log, which takes no Note.
cat_receiver = App("cat-a-log", CAT_SEED, me.CAT_A_LOG, {}, lambda n: True)
cat_receiver.receive(m2)
expect("an offer of a type that does not fit is declined", reason(cat_receiver, obf_app.reply("OFFER", {
    "to": CAT, "offer_id": "6c7d8e9f-0a1b-4c2d-9e3f-4a5b6c7d8e9f", "types": [{"schema": NOTE_TEXT, "count": 1}]})), "DOES_NOT_FIT")

# Manifests and the order of the first messages.
fresh = App("Old Brain Fix", OBF_SEED, me.OLD_BRAIN_FIX, {}, lambda n: True)
expect("an OFFER before the MANIFEST is not processed", fresh.receive(offer_msg), ("rejected INVALID_MESSAGE, not reported", []))
bad_manifest = make_message("MANIFEST", CAT_SEED, None, header("Manifest") + [(me.encode_body(dict(me.CAT_A_LOG, revision=0))[10:], "")],
                            check=False)[1]
expect("an invalid manifest", code_of(fresh.receive(bad_manifest)), "ERROR MANIFEST_INVALID")
expect("a MANIFEST with a record field", code_of(fresh.receive(make_message(
    "MANIFEST", CAT_SEED, (APPOINTMENT_ID, 1), header("Manifest") + [(me.encode_body(me.CAT_A_LOG)[10:], "")], check=False)[1])),
    "ERROR INVALID_MESSAGE")
expect("the highest common format", choose_format([1, 2], [2, 3]), 2)
expect("no common format", choose_format([1], [2]), None)
expect("format 1 between two apps of 0.1.0", choose_format([1], me.OLD_BRAIN_FIX["formats"]), 1)

# A deletion without an accepted offer, and records after the connection ended.
lone = App("Old Brain Fix", OBF_SEED, me.OLD_BRAIN_FIX, {}, lambda n: True)
lone.receive(m1)
expect("a DELETE without any accepted offer", code_of(lone.receive(del_unknown)), "ERROR NOT_ACCEPTED")
obf_app.close()
expect("DATA after the connection's offers ended asks for the schema again",
       code_of(obf_app.receive(obf_data(APPOINTMENT_ID, 10, APPOINTMENT_TEXT, APPOINTMENT))), "ERROR SCHEMA_UNKNOWN")

# Outcomes decided later: APPLIED replaces KEPT, in either order.
for order in (("KEPT", "APPLIED"), ("APPLIED", "KEPT")):
    s = App("cat-a-log", CAT_SEED, me.CAT_A_LOG, {}, lambda n: True)
    s.receive(m2)
    for outcome in order:
        s.receive(obf_app.reply("ACK", {"to": CAT, "records": [
            {"id": APPOINTMENT_ID, "version": 4, "outcome": outcome, "receiver_version": 4, "kept_fields": []}], "moved_from": None}))
    expect(f"APPLIED stands after {order[0]} then {order[1]}", s.outcomes[(APPOINTMENT_ID, 4)], "APPLIED")
for order in (("DUPLICATE", "MERGED"), ("MERGED", "DUPLICATE")):
    s = App("cat-a-log", CAT_SEED, me.CAT_A_LOG, {}, lambda n: True)
    s.receive(m2)
    for outcome in order:
        s.receive(obf_app.reply("ACK", {"to": CAT, "records": [
            {"id": APPOINTMENT_ID, "version": 4, "outcome": outcome, "receiver_version": 4,
             "kept_fields": ["location"] if outcome == "MERGED" else []}], "moved_from": None}))
    expect(f"MERGED stands after {order[0]} then {order[1]}", s.outcomes[(APPOINTMENT_ID, 4)], "MERGED")
invalid_acks = [
    ("an ACK without entries and without a key move", []),
    ("an ACK of STALE without a higher receiver version", [{"id": APPOINTMENT_ID, "version": 2, "outcome": "STALE", "receiver_version": 2, "kept_fields": []}]),
    ("an ACK of MERGED without kept fields", [{"id": APPOINTMENT_ID, "version": 2, "outcome": "MERGED", "receiver_version": 2, "kept_fields": []}]),
    ("an ACK of APPLIED with kept fields", [{"id": APPOINTMENT_ID, "version": 2, "outcome": "APPLIED", "receiver_version": 2, "kept_fields": ["title"]}]),
    ("an ACK with one id and version twice", [{"id": APPOINTMENT_ID, "version": 2, "outcome": "APPLIED", "receiver_version": 2, "kept_fields": []}] * 2),
]
for label, entries in invalid_acks:
    expect(label, code_of(cat_app.receive(obf_app.reply("ACK", {"to": CAT, "records": entries, "moved_from": None}))), "ERROR INVALID_MESSAGE")
key_move_ack = obf_app.reply("ACK", {"to": CAT, "records": [], "moved_from": OTHER})
expect("an ACK of a key move alone", cat_app.receive(key_move_ack), ("acknowledged", []))
broken_error = make_message("ERROR", OBF_SEED, None, header("Error") + [(b"\x00", "")], check=False)[1]
expect("an ERROR that cannot be processed is not answered with an ERROR", cat_app.receive(broken_error),
       ("rejected INVALID_MESSAGE, not reported", []))

# --- schema resolution of every default ---------------------------------------

DATA = {
    "Offer": wire("Offer", {"to": CAT, "offer_id": OFFER_ID, "types": [
        {"schema": PET_TEXT, "count": 1, "short": None}, {"schema": APPOINTMENT_TEXT, "count": 1, "short": None}]}),
    "Accept": {"to": CAT, "offer_id": OFFER_ID, "types": ["axt.example.v1.Appointment"]},
    "Decline": {"to": CAT, "offer_id": OFFER_ID, "types": [{"type": "axt.example.v1.Pet", "reason": "NOT_WANTED"}]},
    "Ack": {"to": CAT, "records": [{"id": APPOINTMENT_ID, "version": 3, "outcome": "MERGED", "receiver_version": 3,
                                    "kept_fields": ["location"]}], "moved_from": OTHER},
    "Error": {"to": CAT, "code": "SCHEMA_UNKNOWN", "message_hash": bytes(range(32)), "record": {"id": APPOINTMENT_ID, "version": 3},
              "fingerprint": fp8(0x1B57DE39E9441B59), "detail": "no schema with this fingerprint"},
}
library_findings = set()
defaults_resolved = {}
for n in PROTOCOL:
    rules.DATA[n] = DATA[n]
    _, checked = rules.check_defaults(n, jsons[n], parsed[n])
    top_enums = sum(isinstance(f["type"], dict) and f["type"]["type"] == "enum" for f in jsons[n]["fields"])
    assert checked - top_enums == me.count_defaults(jsons[n]), f"{n}: not every default was used"
    defaults_resolved[n] = checked - top_enums
library_findings |= rules.findings


def nested_enum_check(n, field, item_field):
    """A symbol the reader does not know, in an enum inside the records of an array."""
    writer = copy.deepcopy(jsons[n])
    f = next(x for x in writer["fields"] if x["name"] == field)
    e = next(x for x in f["type"]["items"]["fields"] if x["name"] == item_field)["type"]
    e["symbols"].append("SYMBOL_OF_A_LATER_FORMAT")
    datum = copy.deepcopy(DATA[n])
    datum[field][0][item_field] = "SYMBOL_OF_A_LATER_FORMAT"
    buf = io.BytesIO()
    fastavro.schemaless_writer(buf, fastavro.parse_schema(writer, _write_hint=False), datum)
    back = fastavro.schemaless_reader(io.BytesIO(buf.getvalue()), fastavro.parse_schema(writer, _write_hint=False), parsed[n])
    assert back[field][0][item_field] == e["default"], (n, field)
    try:
        avro.io.DatumReader(avro.schema.parse(json.dumps(writer)), apache[n]).read(avro.io.BinaryDecoder(io.BytesIO(buf.getvalue())))
    except avro.errors.SchemaResolutionException:
        library_findings.add("avro 1.12.2 raises SchemaResolutionException for an enum symbol the reader does not know, "
                             "instead of reading the enum's default symbol")


nested_enum_check("Decline", "types", "reason")
nested_enum_check("Ack", "records", "outcome")
if rules.failures:
    raise SystemExit("\n".join(["checks failed:"] + rules.failures))

# --- output -------------------------------------------------------------------


def dump(parts):
    """Annotated hex in the layout of spec/envelope.md; long values shortened."""
    offset, lines = 0, []
    for part in parts:
        data, meaning, short = part[0], part[1], len(part) > 2 and part[2]
        if short and len(data) > 8:
            lines.append(f"{offset:04x}  {(data[:4].hex(' ') + ' ... ' + data[-2:].hex(' ')):<23}  {meaning}")
        else:
            for i in range(0, len(data), 8):
                hexs = data[i:i + 8].hex(" ")
                lines.append(f"{offset:04x}  {hexs:<23}  {meaning}".rstrip() if i == 0 else f"      {hexs}")
        offset += len(data)
    lines.append(f"{offset:04x}  end")
    return "\n".join(lines)


print("== Schemas ==")
for n in PROTOCOL:
    pcf, fp = fingerprints[n]
    print(f"axt.{n}: data depth {depths[n]}; defaults resolved: {defaults_resolved[n]}")
    print(f"  canonical form: {pcf}")
print()
print("| Schema | Envelope format | CRC-64-AVRO | As bytes |")
print("| --- | --- | --- | --- |")
for n in PROTOCOL:
    fp = fingerprints[n][1]
    print(f"| `axt.{n}` | 1 | `0x{fp:016x}` | `{fp8(fp).hex(' ')}` |")
print()
print("== Test keys (never use outside tests) ==")
print(f"cat-a-log, old phone, Ed25519 public key  {CAT.hex()}")
print(f"Old Brain Fix, Ed25519 seed               {OBF_SEED.hex()}")
print(f"Old Brain Fix, Ed25519 public key         {OBF.hex()}")
print(f"Old Brain Fix, short fingerprint          {keys.short_fingerprint(OBF)}")
print()
print(f"offered schema texts: Pet {len(PET_TEXT.encode())} bytes, SHA-256 {hashlib.sha256(PET_TEXT.encode()).hexdigest()}; "
      f"Appointment {len(APPOINTMENT_TEXT.encode())} bytes, SHA-256 {hashlib.sha256(APPOINTMENT_TEXT.encode()).hexdigest()}")
for title, parts, message in shown:
    print()
    print(f"== {title}: {len(message)} bytes, SHA-256 {hashlib.sha256(message).hexdigest()} ==")
    print(dump(parts))
    print(f"signed bytes: {len(keys.MESSAGE_PREFIX) + len(message) - 74}, signature {message[-64:].hex()}")
print()
print(f"step 8, the Pet's DATA (not shown): {len(pet_msg)} bytes, SHA-256 {hashlib.sha256(pet_msg).hexdigest()}")
print()
print(f"model checks: {len(checks)}")
for label in checks:
    print(f"  {label}")
for finding in sorted(library_findings):
    print(f"library finding: {finding}")
print("all checks passed")
