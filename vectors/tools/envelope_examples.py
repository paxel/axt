# SPDX-License-Identifier: CC0-1.0
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

    python3 vectors/tools/envelope_examples.py

The sender key and the signature are placeholders until spec/keys.md
defines them.
"""

import hashlib
import io
import json
import uuid
from pathlib import Path

import avro.datafile
import avro.io
import avro.schema
import fastavro
from fastavro.schema import fingerprint as fa_fingerprint
from fastavro.schema import to_parsing_canonical_form

REPO = Path(__file__).resolve().parents[2]
ENVELOPE_AVSC = REPO / "types" / "axt" / "Envelope.avsc"

MEMO_SCHEMA = {
    "type": "record",
    "name": "Memo",
    "namespace": "com.example",
    "doc": "An illustration for spec/envelope.md; not an AXT example type.",
    "fields": [
        {"name": "text", "type": "string", "doc": "The memo's text."},
        {
            "name": "written",
            "type": {"type": "long", "logicalType": "timestamp-millis"},
            "doc": "When the memo was written.",
        },
    ],
}

# Values of the examples.
SENDER = bytes(range(32))  # placeholder until spec/keys.md
SIGNATURE = bytes(64)  # placeholder until spec/keys.md
RECORD_ID = "0b5a3c1e-4d2f-4a6b-9c8d-7e6f5a4b3c2d"
RECORD_VERSION = 1
MEMO = {"text": "Vet, Tuesday 10:00", "written": 1763200800000}  # 2025-11-15T10:00:00Z
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
    assert fa_fingerprint(pcf, "CRC-64-AVRO") == fp.to_bytes(8, "little").hex(), "fastavro fingerprint differs"
    assert apache_fingerprint(schema_json) == fp.to_bytes(8, "little"), "avro fingerprint differs"
    return pcf, fp


envelope_json = ENVELOPE_AVSC.read_text(encoding="utf-8")
memo_json = json.dumps(MEMO_SCHEMA)
envelope_pcf, envelope_fp = fingerprint(envelope_json)
memo_pcf, memo_fp = fingerprint(memo_json)
envelope_schema = fastavro.parse_schema(json.loads(envelope_json))
memo_schema = fastavro.parse_schema(MEMO_SCHEMA)

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


def library_binary(schema, datum) -> bytes:
    buf = io.BytesIO()
    fastavro.schemaless_writer(buf, schema, datum)
    return buf.getvalue()


# The body: the Memo in single-object encoding.
memo_parts = [
    ("C3 01", b"\xc3\x01", "single-object marker"),
    ("fingerprint", memo_fp.to_bytes(8, "little"), f"CRC-64-AVRO of com.example.Memo, 0x{memo_fp:016x}, little-endian"),
    ("text", avro_bytes(MEMO["text"].encode()), f'string, length {len(MEMO["text"])}: "{MEMO["text"]}"'),
    ("written", zigzag(MEMO["written"]), f'timestamp-millis {MEMO["written"]} (2025-11-15T10:00:00Z)'),
]
body = b"".join(p[1] for p in memo_parts)
assert body[10:] == library_binary(memo_schema, MEMO), "Memo encoding differs from fastavro"

kinds = envelope_schema["fields"][1]["type"]["symbols"]
envelope_datum = {
    "format": 1,
    "kind": "DATA",
    "sender": SENDER,
    "record": {"id": RECORD_ID, "version": RECORD_VERSION},
    "body": body,
    "signature": SIGNATURE,
}
message_parts = [
    ("C3 01", b"\xc3\x01", "single-object marker"),
    ("fingerprint", envelope_fp.to_bytes(8, "little"), f"CRC-64-AVRO of axt.Envelope, 0x{envelope_fp:016x}, little-endian"),
    ("format", zigzag(1), "int 1"),
    ("kind", zigzag(kinds.index("DATA")), f'enum index {kinds.index("DATA")}: DATA'),
    ("sender", SENDER, "fixed(32): Ed25519 public key (placeholder)"),
    ("record", zigzag(1), "union index 1: RecordRef"),
    ("record.id", avro_bytes(RECORD_ID.encode()), f"string, length 36: {RECORD_ID}"),
    ("record.version", zigzag(RECORD_VERSION), f"long {RECORD_VERSION}"),
    ("body", zigzag(len(body)), f"bytes, length {len(body)}, followed by the body"),
]
message_parts += [("body: " + n, b, m) for n, b, m in memo_parts]
message_parts.append(("signature", SIGNATURE, "fixed(64): Ed25519 signature (placeholder)"))
message = b"".join(p[1] for p in message_parts)

# Check against the library and decode back.
assert message[:10] == single_object_header(envelope_fp)
assert message[10:] == library_binary(envelope_schema, envelope_datum), "envelope encoding differs from fastavro"
decoded = fastavro.schemaless_reader(io.BytesIO(message[10:]), envelope_schema, envelope_schema)
assert decoded["kind"] == "DATA" and decoded["body"] == body
assert isinstance(decoded["record"]["id"], uuid.UUID) and str(decoded["record"]["id"]) == RECORD_ID
assert int.from_bytes(decoded["body"][2:10], "little") == memo_fp
memo_back = fastavro.schemaless_reader(io.BytesIO(decoded["body"][10:]), memo_schema, memo_schema)
assert memo_back["text"] == MEMO["text"]
assert int(memo_back["written"].timestamp() * 1000) == MEMO["written"]

# --- the file -----------------------------------------------------------------

# fastavro writes as avro.schema the json.dumps of the schema it is given. A
# parsed schema has its field attributes in an order that depends on the
# string hash seed, so the writer gets the schema as read from
# Envelope.avsc, in the file's own order, and the file's bytes are the same
# in every run.
file_buf = io.BytesIO()
fastavro.writer(
    file_buf,
    json.loads(envelope_json),
    [envelope_datum],
    codec="null",
    metadata={"axt.schemas": json.dumps([MEMO_SCHEMA], separators=(",", ":"))},
    sync_marker=SYNC_MARKER,
)
axt_file = file_buf.getvalue()

# Read back with fastavro.
file_buf.seek(0)
fa_reader = fastavro.reader(file_buf)
assert fa_reader.metadata["avro.codec"] == "null"
assert json.loads(fa_reader.metadata["axt.schemas"])[0]["name"] == "Memo"
fa_records = list(fa_reader)
assert len(fa_records) == 1 and fa_records[0]["body"] == body

# Read back with the Apache avro package.
apache_reader = avro.datafile.DataFileReader(io.BytesIO(axt_file), avro.io.DatumReader())
header_schema = apache_reader.get_meta("avro.schema").decode()
assert header_schema == json.dumps(json.loads(envelope_json)), "avro.schema is not Envelope.avsc in its own order"
assert apache_fingerprint(header_schema) == envelope_fp.to_bytes(8, "little")
for entry in json.loads(apache_reader.get_meta("axt.schemas").decode()):
    assert apache_fingerprint(json.dumps(entry)) == memo_fp.to_bytes(8, "little")
apache_records = list(apache_reader)
assert len(apache_records) == 1 and apache_records[0]["body"] == body
assert apache_records[0]["signature"] == SIGNATURE

# The datum in the file is the message without its 10-byte single-object header.
assert message[10:] in axt_file

# --- output -------------------------------------------------------------------


def dump(parts):
    offset = 0
    for name, data, meaning in parts:
        hexs = data.hex(" ")
        print(f"{offset:04x}  {name:<22} {meaning}")
        for i in range(0, len(hexs), 48):
            print(f"      {hexs[i:i + 48]}")
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
    chunk = axt_file[i:i + 16]
    text = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
    print(f"{i:04x}  {chunk.hex(' '):<47}  {text}")
print("all checks passed")
