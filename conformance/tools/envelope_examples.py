# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Produce and check the examples of spec/envelope.md.

Writes one live data message (an axt.Envelope in Avro single-object
encoding whose body is a com.example.Memo in single-object encoding) and
one AXT file (an Avro object container file of axt.Envelope), prints both
as annotated hex, and checks them:

- the CRC-64-AVRO implementation below against fingerprints published in
  Apache Avro's share/test/data/schema-tests.txt;
- the fingerprints of the envelope and the example schema against
  fastavro's and the Apache avro package's own fingerprint functions;
- the message bytes, built here field by field, against fastavro's binary
  encoding, and decoded back with fastavro;
- the file, written with fastavro, read back with both fastavro and the
  Apache avro package.

Neither library writes single-object framing, so the 10-byte header
(C3 01 and the fingerprint) is assembled here from the fingerprint.

Run from anywhere, with fastavro and avro (1.12) installed:

    python3 conformance/tools/envelope_examples.py

The message and the file's header are signed with cat-a-log's test key of
spec/keys.md, section 7.1, with the Ed25519 implementation of
conformance/tools/keys_examples.py; importing that file runs none of its
checks. The message and the file are then those of spec/keys.md, sections
7.2 and 7.3, which the script checks by their SHA-256. The test key is a
TEST KEY and MUST NOT be used outside tests.
"""

import calendar
import hashlib
import importlib.util
import io
import json
import uuid
from collections.abc import Sequence
from pathlib import Path
from typing import Any, cast

import avro.datafile
import avro.io
import avro.schema
import fastavro
from fastavro.schema import fingerprint as fa_fingerprint
from fastavro.schema import to_parsing_canonical_form

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
ENVELOPE_AVSC = REPO / "types" / "axt" / "Envelope.avsc"

_spec = importlib.util.spec_from_file_location("keys_examples", HERE / "keys_examples.py")
if _spec is None or _spec.loader is None:
    raise ImportError(f"cannot load {HERE / 'keys_examples.py'}")
keys = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(keys)

# The Memo defines axt.DateTime in place, as its published schema (spec/time.md, section 3.1).
DATE_TIME_SCHEMA = json.loads((REPO / "types" / "axt" / "DateTime.avsc").read_text(encoding="utf-8"))
MEMO_SCHEMA: dict[str, Any] = {
    "type": "record",
    "name": "Memo",
    "namespace": "com.example",
    "doc": "An illustration for spec/envelope.md; not an AXT example type.",
    "fields": [
        {"name": "text", "type": "string", "doc": "The memo's text."},
        {
            "name": "written",
            "type": DATE_TIME_SCHEMA,
            "doc": "When the memo was written.",
            "axt.anchor": "instant",
        },
    ],
}

# Values of the examples. The seed is cat-a-log's test key (spec/keys.md, section 7.1): a TEST KEY.
SEED = hashlib.sha256(b"AXT test key, not for use: cat-a-log, old phone, Ed25519").digest()
SENDER = keys.public_key(SEED)
assert SENDER.hex() == "1b84a600f3503e22bbcc99e63202a7194bf6bd69aff1471cce6410d53c26ec4a", (
    "not the key of spec/keys.md"
)
RECORD_ID = "0b5a3c1e-4d2f-4a6b-9c8d-7e6f5a4b3c2d"
RECORD_VERSION = 1
# written: 2025-11-15 11:00 in Europe/Berlin, the offset 3600, the instant 2025-11-15T10:00:00Z.
WRITTEN: dict[str, Any] = {
    "year": 2025,
    "month": 11,
    "day": 15,
    "hour": 11,
    "minute": 0,
    "second": 0,
    "millisecond": 0,
    "zone": "Europe/Berlin",
    "offset_seconds": 3600,
    "instant_ms": 1763200800000,
}
MEMO: dict[str, Any] = {"text": "Vet, Tuesday 10:00", "written": WRITTEN}
SYNC_MARKER = bytes.fromhex("000102030405060708090a0b0c0d0e0f")  # a writer picks 16 random bytes

# --- CRC-64-AVRO, as given in the Avro specification -------------------------

EMPTY = 0xC15D213AA4D7A795
TABLE = []
for i in range(256):
    fp = i
    for _ in range(8):
        fp = (fp >> 1) ^ (EMPTY & -(fp & 1))
    TABLE.append(fp)


def crc64_avro(data: bytes) -> int:
    fp = EMPTY
    for b in data:
        fp = (fp >> 8) ^ TABLE[(fp ^ b) & 0xFF]
    return fp


def signed64(v: int) -> int:
    return v - (1 << 64) if v >= 1 << 63 else v


# Published in Apache Avro, share/test/data/schema-tests.txt (cases 000, 002, 004).
PUBLISHED = {
    '"null"': 7195948357588979594,
    '"boolean"': -6970731678124411036,
    '"int"': 8247732601305521295,
}
for text, expected in PUBLISHED.items():
    assert signed64(crc64_avro(text.encode())) == expected, text

# --- fingerprints -------------------------------------------------------------


def apache_fingerprint(schema_json: str) -> bytes:
    # avro 1.12.2 for Python writes a primitive that carries a logicalType as
    # {"type":"string"} in its canonical form, against the PRIMITIVES rule of
    # the specification, so its fingerprint of such a schema is not the
    # specification's. Parsing the canonical form again drops the logical
    # types; its fingerprint is then the specification's.
    canonical = avro.schema.parse(schema_json).canonical_form
    return avro.schema.parse(canonical).fingerprint("CRC-64-AVRO")


def fingerprint(schema_json: str) -> tuple[str, int]:
    """Parsing Canonical Form and fingerprint, checked against both libraries."""
    pcf = to_parsing_canonical_form(fastavro.parse_schema(json.loads(schema_json)))
    assert avro.schema.parse(pcf).canonical_form == pcf, "the two libraries disagree on the canonical form"
    fp = crc64_avro(pcf.encode())
    # Both libraries return the fingerprint as its 8 bytes in little-endian order.
    assert fa_fingerprint(pcf, "CRC-64-AVRO") == fp.to_bytes(8, "little").hex(), (
        "fastavro fingerprint differs"
    )
    assert apache_fingerprint(schema_json) == fp.to_bytes(8, "little"), "avro fingerprint differs"
    return pcf, fp


envelope_json = ENVELOPE_AVSC.read_text(encoding="utf-8")
memo_json = json.dumps(MEMO_SCHEMA)
envelope_pcf, envelope_fp = fingerprint(envelope_json)
memo_pcf, memo_fp = fingerprint(memo_json)
envelope_schema: Any = fastavro.parse_schema(json.loads(envelope_json))
memo_schema: Any = fastavro.parse_schema(MEMO_SCHEMA)

# --- hand-built encoding ------------------------------------------------------


def zigzag(n: int) -> bytes:
    z = (n << 1) ^ (n >> 63)
    out = bytearray()
    while True:
        b = z & 0x7F
        z >>= 7
        if z:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def avro_bytes(b: bytes) -> bytes:
    return zigzag(len(b)) + b


def single_object_header(fp: int) -> bytes:
    return b"\xc3\x01" + fp.to_bytes(8, "little")


def library_binary(schema: Any, datum: Any) -> bytes:
    buf = io.BytesIO()
    fastavro.schemaless_writer(buf, schema, datum)
    return buf.getvalue()


# The body: the Memo in single-object encoding.
memo_parts = [
    ("C3 01", b"\xc3\x01", "single-object marker"),
    (
        "fingerprint",
        memo_fp.to_bytes(8, "little"),
        f"CRC-64-AVRO of com.example.Memo, 0x{memo_fp:016x}, little-endian",
    ),
    ("text", avro_bytes(MEMO["text"].encode()), f'string, length {len(MEMO["text"])}: "{MEMO["text"]}"'),
]
# written, an axt.DateTime: the wall clock, then the zone, the offset and the instant, each a union index 1
# and its value.
for part in ("year", "month", "day", "hour", "minute", "second", "millisecond"):
    memo_parts.append((f"written.{part}", zigzag(WRITTEN[part]), f"int {WRITTEN[part]}"))
memo_parts += [
    (
        "written.zone",
        zigzag(1) + avro_bytes(WRITTEN["zone"].encode()),
        f'union index 1, string, length {len(WRITTEN["zone"])}: "{WRITTEN["zone"]}"',
    ),
    (
        "written.offset_seconds",
        zigzag(1) + zigzag(WRITTEN["offset_seconds"]),
        f"union index 1, int {WRITTEN['offset_seconds']}",
    ),
    (
        "written.instant_ms",
        zigzag(1) + zigzag(WRITTEN["instant_ms"]),
        f"union index 1, long {WRITTEN['instant_ms']} (2025-11-15T10:00:00Z)",
    ),
]
body = b"".join(p[1] for p in memo_parts)
assert len(body) < 64, "the body length takes one byte, as the offsets of the vectors assume"
assert (
    WRITTEN["instant_ms"]
    == calendar.timegm((2025, 11, 15, 11, 0, 0)) * 1000 - WRITTEN["offset_seconds"] * 1000
)
assert body[10:] == library_binary(memo_schema, MEMO), "Memo encoding differs from fastavro"

kinds = envelope_schema["fields"][1]["type"]["symbols"]
message_parts = [
    ("C3 01", b"\xc3\x01", "single-object marker"),
    (
        "fingerprint",
        envelope_fp.to_bytes(8, "little"),
        f"CRC-64-AVRO of axt.Envelope, 0x{envelope_fp:016x}, little-endian",
    ),
    ("format", zigzag(1), "int 1"),
    ("kind", zigzag(kinds.index("DATA")), f"enum index {kinds.index('DATA')}: DATA"),
    ("sender", SENDER, "fixed(32): Ed25519 public key, cat-a-log's test key"),
    ("record", zigzag(1), "union index 1: RecordRef"),
    ("record.id", avro_bytes(RECORD_ID.encode()), f"string, length 36: {RECORD_ID}"),
    ("record.version", zigzag(RECORD_VERSION), f"long {RECORD_VERSION}"),
    ("body", zigzag(len(body)), f"bytes, length {len(body)}, followed by the body"),
]
message_parts += [("body: " + n, b, m) for n, b, m in memo_parts]
# The signature of spec/keys.md, section 2.2: over the prefix and the envelope's bytes before it.
unsigned = b"".join(p[1] for p in message_parts)
SIGNATURE = keys.sign(SEED, keys.MESSAGE_PREFIX + unsigned[10:])
assert keys.verify_problem(SENDER, keys.MESSAGE_PREFIX + unsigned[10:], SIGNATURE) is None
message_parts.append(("signature", SIGNATURE, "fixed(64): Ed25519 signature"))
message = b"".join(p[1] for p in message_parts)
envelope_datum = {
    "format": 1,
    "kind": "DATA",
    "sender": SENDER,
    "record": {"id": RECORD_ID, "version": RECORD_VERSION},
    "body": body,
    "signature": SIGNATURE,
}
assert (
    hashlib.sha256(message).hexdigest() == "68d19c518a50880136a9f7412d3e636b17422c89cf63837b7ae1a22c8abedfc3"
), "not the message of spec/keys.md, section 7.2"

# Check against the library and decode back.
assert message[:10] == single_object_header(envelope_fp)
assert message[10:] == library_binary(envelope_schema, envelope_datum), (
    "envelope encoding differs from fastavro"
)
decoded: Any = fastavro.schemaless_reader(io.BytesIO(message[10:]), envelope_schema, envelope_schema)
assert decoded["kind"] == "DATA" and decoded["body"] == body
assert isinstance(decoded["record"]["id"], uuid.UUID) and str(decoded["record"]["id"]) == RECORD_ID
assert int.from_bytes(decoded["body"][2:10], "little") == memo_fp
memo_back: Any = fastavro.schemaless_reader(io.BytesIO(decoded["body"][10:]), memo_schema, memo_schema)
assert memo_back["text"] == MEMO["text"]
assert memo_back["written"] == WRITTEN

# --- the file -----------------------------------------------------------------

# fastavro writes as avro.schema the json.dumps of the schema it is given. A
# parsed schema has its field attributes in an order that depends on the
# string hash seed, so the writer gets the schema as read from
# Envelope.avsc, in the file's own order, and the file's bytes are the same
# in every run.
schemas_value = json.dumps([MEMO_SCHEMA], separators=(",", ":"))
# The header signature of spec/keys.md, section 2.5.
HEADER_SIGNATURE = keys.sign(
    SEED, keys.FILE_HEADER_PREFIX + SENDER + hashlib.sha256(schemas_value.encode()).digest()
)
file_buf = io.BytesIO()
fastavro.writer(
    file_buf,
    json.loads(envelope_json),
    [envelope_datum],
    codec="null",
    metadata={
        "axt.schemas": schemas_value,
        "axt.sender": SENDER.hex(),
        "axt.signature": HEADER_SIGNATURE.hex(),
    },
    sync_marker=SYNC_MARKER,
)
axt_file = file_buf.getvalue()
assert (
    hashlib.sha256(axt_file).hexdigest() == "37074c1f86d048a02e906441adc37f41599d1c9776fb2ae594a3f068f257a94c"
), "not the file of spec/keys.md, section 7.3"

# Read back with fastavro.
file_buf.seek(0)
fa_reader = fastavro.reader(file_buf)
assert fa_reader.metadata["avro.codec"] == "null"
assert json.loads(fa_reader.metadata["axt.schemas"])[0]["name"] == "Memo"
fa_records: list[Any] = list(fa_reader)
assert len(fa_records) == 1 and fa_records[0]["body"] == body

# Read back with the Apache avro package.
apache_reader = avro.datafile.DataFileReader(io.BytesIO(axt_file), avro.io.DatumReader())
header_schema = cast(bytes, apache_reader.get_meta("avro.schema")).decode()
assert header_schema == json.dumps(json.loads(envelope_json)), (
    "avro.schema is not Envelope.avsc in its own order"
)
assert apache_fingerprint(header_schema) == envelope_fp.to_bytes(8, "little")
for entry in json.loads(cast(bytes, apache_reader.get_meta("axt.schemas")).decode()):
    assert apache_fingerprint(json.dumps(entry)) == memo_fp.to_bytes(8, "little")
apache_records: list[Any] = list(apache_reader)
assert len(apache_records) == 1 and apache_records[0]["body"] == body
assert apache_records[0]["signature"] == SIGNATURE
assert apache_reader.get_meta("axt.sender") == SENDER.hex().encode()
assert fa_reader.metadata["axt.signature"] == HEADER_SIGNATURE.hex()
assert (
    keys.verify_problem(
        SENDER,
        keys.FILE_HEADER_PREFIX
        + SENDER
        + hashlib.sha256(cast(bytes, apache_reader.get_meta("axt.schemas"))).digest(),
        bytes.fromhex(fa_reader.metadata["axt.signature"]),
    )
    is None
)

# The datum in the file is the message without its 10-byte single-object header.
assert message[10:] in axt_file

# --- output -------------------------------------------------------------------


def dump(parts: Sequence[tuple[str, bytes, str]]) -> None:
    offset = 0
    for name, data, meaning in parts:
        hexs = data.hex(" ")
        print(f"{offset:04x}  {name:<22} {meaning}")
        for i in range(0, len(hexs), 48):
            print(f"      {hexs[i : i + 48]}")
        offset += len(data)
    print(f"{offset:04x}  end, {offset} bytes")


print(f"axt.Envelope canonical form: {envelope_pcf}")
print(f"axt.Envelope CRC-64-AVRO: 0x{envelope_fp:016x}, bytes {envelope_fp.to_bytes(8, 'little').hex(' ')}")
print(f"com.example.Memo canonical form: {memo_pcf}")
print(f"com.example.Memo CRC-64-AVRO: 0x{memo_fp:016x}, bytes {memo_fp.to_bytes(8, 'little').hex(' ')}")
print()
print("== Data message ==")
dump(message_parts)
print()
print("== File ==")
print(f"length {len(axt_file)} bytes, SHA-256 {hashlib.sha256(axt_file).hexdigest()}")
print(f"avro.schema as written: {header_schema}")
print(f"axt.schemas as written: {fa_reader.metadata['axt.schemas']}")
for i in range(0, len(axt_file), 16):
    chunk = axt_file[i : i + 16]
    text = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
    print(f"{i:04x}  {chunk.hex(' '):<47}  {text}")

# The same message and file in the layout of spec/envelope.md, sections 10.2 and 10.3.
SPEC_NAMES = {
    "C3 01": "single-object marker",
    "format": "format: int 1",
    "kind": "kind: enum index 4, DATA",
    "sender": "sender: fixed(32), cat-a-log's test key",
    "record": "record: union index 1, axt.RecordRef",
    "record.version": f"record.version: long {RECORD_VERSION}",
    "body": f"body: bytes length {len(body)}",
    "body: C3 01": "body: single-object marker",
    "body: fingerprint": "body: fingerprint of com.example.Memo",
    "signature": "signature: fixed(64)",
}
spec_parts: list[tuple[bytes, str]] = []
for name, data, meaning in message_parts:
    if name == "fingerprint":
        spec_parts.append((data, "fingerprint of axt.Envelope, format 1"))
    elif name in SPEC_NAMES:
        spec_parts.append((data, SPEC_NAMES[name]))
    elif name in ("record.id", "body: text"):
        text = RECORD_ID if name == "record.id" else MEMO["text"]
        spec_parts += [(data[:1], f"{name}: string length {len(text)}"), (data[1:], f'"{text}"')]
    elif name == "body: written.zone":
        spec_parts += [
            (data[:2], f"body: written.zone: union index 1, string length {len(WRITTEN['zone'])}"),
            (data[2:], f'"{WRITTEN["zone"]}"'),
        ]
    elif name in ("body: written.offset_seconds", "body: written.instant_ms"):
        spec_parts.append(
            (
                data,
                f"{name}: union index 1, {'int' if 'offset' in name else 'long'} "
                f"{WRITTEN[name.split('.')[-1]]}",
            )
        )
    else:
        spec_parts.append((data, f"{name}: {meaning}"))
assert b"".join(d for d, _ in spec_parts) == message
print()
print(f"== Data message, as in spec/envelope.md, section 10.2: {len(message)} bytes ==")
print(keys.dump(spec_parts))


def file_layout(data: bytes) -> list[tuple[int, bytes, str, bool]]:
    """The parts of the file, as (offset, bytes, meaning), with long values shortened in the output."""
    out: list[tuple[int, bytes, str, bool]]
    pos, out = 0, []

    def take(n: int, meaning: str, short: bool = False) -> None:
        nonlocal pos
        out.append((pos, data[pos : pos + n], meaning, short))
        pos += n

    def varint() -> tuple[int, int]:
        n = shift = 0
        start = pos
        while True:
            b = data[start + shift // 7]
            n |= (b & 0x7F) << shift
            shift += 7
            if not b & 0x80:
                return (n >> 1) ^ -(n & 1), shift // 7

    take(4, 'magic "Obj" 01')
    count, n = varint()
    take(n, f"metadata: map block of {count} entries")
    for _ in range(count):
        length, n = varint()
        take(n, f"key: string length {length}")
        key = data[pos : pos + length].decode()
        take(length, f'"{key}"')
        length, n = varint()
        take(n, f"value: bytes length {length}")
        value = data[pos : pos + length].decode()
        take(
            length,
            {
                "axt.schemas": f'[{{"type":"record","name":"Memo", ...}}]  ({length} bytes of UTF-8 JSON)',
                "axt.sender": f'"{value[:6]}...{value[-6:]}"  '
                f"({length} hexadecimal digits, cat-a-log's test key)",
                "axt.signature": f'"{value[:6]}...{value[-6:]}"  '
                f"({length} hexadecimal digits, the header signature)",
                "avro.schema": '{"type": "record", "name": "Envelope", "namespace": "axt", ...}  '
                f"({length} bytes of UTF-8 JSON)",
            }.get(key, f'"{value}"'),
            short=length > 16,
        )
    take(1, "end of the metadata map")
    take(16, "sync marker")
    count, n = varint()
    take(n, f"block: {count} datum")
    size, n = varint()
    take(n, f"block: {size} bytes")
    take(size, f"the datum: bytes 000a to {len(message) - 1:04x} of the message in 10.2", short=True)
    take(16, "sync marker")
    assert pos == len(data)
    return out


print()
print(f"== File, as in spec/envelope.md, section 10.3: {len(axt_file)} bytes ==")
for offset, chunk, meaning, short in file_layout(axt_file):
    if short:
        print(f"{offset:04x}  {chunk[:4].hex(' ') + ' ... ' + chunk[-2:].hex(' '):<23}  {meaning}")
        continue
    for i in range(0, len(chunk), 8):
        hexs = chunk[i : i + 8].hex(" ")
        print(f"{offset:04x}  {hexs:<23}  {meaning}" if i == 0 else f"      {hexs}")
print(f"{len(axt_file):04x}  end")
print(
    f"axt.schemas: {len(schemas_value.encode())} bytes, "
    f"SHA-256 {hashlib.sha256(schemas_value.encode()).hexdigest()}"
)
print(f"axt.signature: {HEADER_SIGNATURE.hex()}")
print("all checks passed")
