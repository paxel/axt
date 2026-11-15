# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Produce and check the examples of spec/transports.md.

Checks the schema of the QR payload, types/axt/QrPayload.avsc, and
produces the worked example of spec/transports.md, section 7, in which
cat-a-log scans Old Brain Fix's QR code, connects to it on the local
network and sends it a record, and later sends it a sealed message
through its relay:

- the schema rules of spec/types.md, section 5, with the checks of
  conformance/tools/example_types.py, as spec/manifest.md, section 9, applies
  them to a schema of the specification, and its names unique among all
  schemas of the specification; its Parsing Canonical Form and CRC-64-AVRO
  fingerprint against fastavro and the Apache avro package; every default
  once in schema resolution, with both libraries;
- the QR payload, built here field by field, against fastavro's encoding,
  decoded with fastavro and avro; its text in base32 with the scheme AXT:,
  decoded back strictly; that every character is one of the alphanumeric
  mode of QR codes, and the smallest QR version that holds it at error
  correction level M; the validity rules of section 3.1 on the example and
  on payloads and texts that each break one rule;
- the mailbox id of Old Brain Fix's test mailbox secret;
- Old Brain Fix's TLS certificate, a self-signed X.509 certificate of a
  P-256 test key, signed with deterministic ECDSA (RFC 6979) so that its
  bytes can be reproduced; the HELLO frames of both apps, signed with the
  pure-Python Ed25519 of keys_examples.py, PyNaCl and cryptography, which
  give the same signatures; the MESSAGE frame of the DATA of
  spec/protocol.md, section 17.5, and a PING frame;
- a model of the frames of a connection (section 4) that checks the
  example and a set of frames that must close the connection;
- a TLS 1.3 connection over a local socket pair with Python's ssl module
  (OpenSSL), with the certificate above, ALPN axt/1, both HELLO frames, the
  MESSAGE frame and a PING, and a clean close; and that a client limited
  to TLS 1.2 cannot connect;
- the sealed message of spec/keys.md, section 7.4, built again from the
  helpers of keys_examples.py, against its published SHA-256; a model of
  the relay's interface (section 5) that puts, lists, fetches and deletes
  it and checks the status codes of the cases of section 5.2; and the
  fetched message opened with Old Brain Fix's X25519 test key and its
  signature verified.

Run from anywhere, with fastavro, avro (1.12), pynacl and cryptography
installed:

    python3 conformance/tools/transports_examples.py

The script imports protocol_examples.py, which runs that script's checks
with its output suppressed. Every key, secret and certificate is a TEST
value of spec/keys.md, section 7.1, or derived the same way, and MUST NOT
be used outside tests.
"""

import base64
import contextlib
import datetime
import hashlib
import importlib.util
import io
import ipaddress
import json
import re
import socket
import ssl
import tempfile
import threading
from pathlib import Path
from urllib.parse import urlsplit

import avro.io
import avro.schema
import fastavro
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.x509.oid import NameOID

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
AXT = REPO / "types" / "axt"

_spec = importlib.util.spec_from_file_location("protocol_examples", HERE / "protocol_examples.py")
pe = importlib.util.module_from_spec(_spec)
with contextlib.redirect_stdout(io.StringIO()):
    _spec.loader.exec_module(pe)
me, rules, keys = pe.me, pe.rules, pe.keys
zigzag = keys.zigzag

checks = []


def expect(label, got, want):
    assert got == want, f"{label}: got {got!r}, expected {want!r}"
    checks.append(label)


# --- the schema of the QR payload ---------------------------------------------

qr_text_schema = (AXT / "QrPayload.avsc").read_text(encoding="utf-8")
qr_json = json.loads(qr_text_schema)
qr_schema = fastavro.parse_schema(qr_json)
qr_apache = avro.schema.parse(qr_text_schema)
where = "types/axt/QrPayload.avsc"
assert qr_json["type"] == "record" and qr_json["name"] == "QrPayload" and qr_json["namespace"] == "axt", where
assert "axt.version" not in qr_json, f"{where}: a schema of the specification carries no axt.version"
assert len(qr_text_schema.encode("utf-8")) <= rules.MAX_SCHEMA_BYTES and rules.json_depth(qr_json) <= rules.MAX_JSON_DEPTH
qr_depth = rules.check_type(qr_json, where, qr_json, set(), [])
assert qr_depth <= rules.MAX_DATA_DEPTH
for full in me.named_types(qr_json, []):
    assert full not in pe.defined_by, f"{full} is defined in QrPayload.avsc and {pe.defined_by[full]}.avsc"
qr_pcf, qr_fp = me.fingerprint(qr_text_schema)
assert qr_fp not in {fp for _, fp in pe.fingerprints.values()}
assert pe.fingerprints["Manifest"][1] == 0x6B08ECB5D38003B3, "the manifest fingerprint is not that of spec/manifest.md"

# --- test values (spec/keys.md, section 7.1) ----------------------------------


def test_secret(label):
    return hashlib.sha256(b"AXT test key, not for use: " + label.encode()).digest()


CAT_SEED, OBF_SEED, CAT, OBF = pe.CAT_SEED, pe.OBF_SEED, pe.CAT, pe.OBF
OBF_X25519_SK = test_secret("Old Brain Fix, X25519")
OBF_X25519 = keys.x25519(OBF_X25519_SK, keys.X25519_BASE)
assert OBF_X25519.hex() == "34fa7e71770d8d94c76001ac8d575609f005981f80c115bb7a8fe312687ea40b", "not the key of spec/keys.md"
MAILBOX_SECRET = test_secret("Old Brain Fix, mailbox secret")
TLS_SECRET = test_secret("Old Brain Fix, TLS, P-256")

# --- prefixes (spec/keys.md, section 2.2) -------------------------------------

HELLO_PREFIX = b"AXT-v1 connection\x00"
MAILBOX_PREFIX = b"AXT-v1 mailbox\x00"
PREFIXES = [keys.MESSAGE_PREFIX, keys.FILE_HEADER_PREFIX, keys.KEY_MOVE_PREFIX, keys.FINGERPRINT_PREFIX,
            HELLO_PREFIX, MAILBOX_PREFIX]
for p in PREFIXES:
    assert p.endswith(b"\x00") and p.count(b"\x00") == 1 and p.startswith(b"AXT-v1 ")
    assert all(p == q or not q.startswith(p) for q in PREFIXES), "one prefix begins another"
# What TLS 1.3 signs in a CertificateVerify begins with 64 spaces (RFC 8446, section 4.4.3).
assert all(not p.startswith(b"\x20") for p in PREFIXES)

# --- the mailbox (section 5.1) ------------------------------------------------


def mailbox_id(secret):
    return hashlib.sha256(MAILBOX_PREFIX + secret).digest()


MAILBOX = mailbox_id(MAILBOX_SECRET)
RELAY_URL = "https://relay.example.org/axt/"

# --- the QR payload (section 3) -----------------------------------------------

QR_VERSION = 1
QR_SCHEME = "AXT:"
ADDRESS = ipaddress.ip_address("192.168.1.20")
PORT = 47312
QR = {
    "signing_key": OBF,
    "encryption_key": OBF_X25519,
    "local": {"addresses": [ADDRESS.packed], "port": PORT},
    "relay": {"url": RELAY_URL, "mailbox": MAILBOX},
}
MAX_ADDRESSES = 4
MAX_RELAY_URL = 256
rules.DATA["QrPayload"] = QR
required, defaults_resolved = rules.check_defaults("QrPayload", qr_json, qr_schema)
assert defaults_resolved == 3 and required == ["signing_key"]
if rules.failures:
    raise SystemExit("\n".join(["checks failed:"] + rules.failures))


def null_or(name, value, branch, parts_of):
    if value is None:
        return [(zigzag(0), f"{name}: union index 0, null")]
    return [(zigzag(1), f"{name}: union index 1, {branch}")] + parts_of(value)


def qr_parts(q):
    parts = [(bytes([QR_VERSION]), f"payload version {QR_VERSION}"),
             (q["signing_key"], "signing_key: fixed(32), Old Brain Fix's test key")]
    parts += null_or("encryption_key", q["encryption_key"], "QrPayloadEncryptionKey",
                     lambda k: [(k, "encryption_key: fixed(32), Old Brain Fix's X25519 test key")])

    def local_parts(local):
        out = [(zigzag(len(local["addresses"])), f"local.addresses: array block of {len(local['addresses'])} item")]
        for i, a in enumerate(local["addresses"]):
            out += [(zigzag(len(a)), f"local.addresses[{i}]: bytes length {len(a)}"),
                    (a, f"local.addresses[{i}]: {ipaddress.ip_address(a)}")]
        out += [(zigzag(0), "local.addresses: end of the array"),
                (zigzag(local["port"]), f"local.port: int {local['port']}")]
        return out

    def relay_parts(relay):
        raw = relay["url"].encode()
        return [(zigzag(len(raw)), f"relay.url: string length {len(raw)}"), (raw, f'"{relay["url"]}"'),
                (relay["mailbox"], "relay.mailbox: fixed(32), the test mailbox id")]

    parts += null_or("local", q["local"], "QrPayloadLocal", local_parts)
    parts += null_or("relay", q["relay"], "QrPayloadRelay", relay_parts)
    return parts


def encode_qr(q):
    buf = io.BytesIO()
    fastavro.schemaless_writer(buf, qr_schema, q)
    return bytes([QR_VERSION]) + buf.getvalue()


B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
QR_ALPHANUMERIC = set("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:")


def b32(data):
    return base64.b32encode(data).decode("ascii").rstrip("=")


def unb32(text):
    """Base32 of RFC 4648, section 6, without padding; only the canonical text of some bytes."""
    t = text.upper()
    if any(c not in B32 for c in t) or len(t) % 8 in (1, 3, 6):
        raise ValueError("not base32 without padding")
    data = base64.b32decode(t + "=" * (-len(t) % 8))
    if b32(data) != t:
        raise ValueError("the last character carries bits that are not zero")
    return data


def qr_text(payload):
    return QR_SCHEME + b32(payload)


def relay_url_problem(url):
    parts = urlsplit(url)
    if (len(url.encode("utf-8")) > MAX_RELAY_URL or parts.scheme != "https" or not parts.hostname
            or "@" in parts.netloc or parts.query or parts.fragment or "?" in url or "#" in url
            or not url.endswith("/") or not me.one_line(url) or " " in url):
        return f"relay.url is not an absolute https base URL of up to {MAX_RELAY_URL} bytes"
    return None


def qr_problems(q):
    """Every rule of section 3.1 the decoded payload breaks; empty for a valid one."""
    problems = []
    if keys.key_problem(q["signing_key"]):
        problems.append(f"signing_key: {keys.key_problem(q['signing_key'])}")
    ek = q["encryption_key"]
    if ek is not None and keys.encryption_key_problem(ek):
        problems.append("encryption_key is an X25519 key of small order")
    if (ek is None) != (q["relay"] is None):
        problems.append("relay and encryption_key are not both present or both null")
    if q["local"] is not None:
        a = q["local"]["addresses"]
        if not 1 <= len(a) <= MAX_ADDRESSES or any(len(x) not in (4, 16) for x in a):
            problems.append(f"local.addresses is not 1 to {MAX_ADDRESSES} addresses of 4 or 16 bytes")
        if not 1 <= q["local"]["port"] <= 65535:
            problems.append("local.port is not 1 to 65535")
    if q["relay"] is not None and relay_url_problem(q["relay"]["url"]):
        problems.append(relay_url_problem(q["relay"]["url"]))
    return problems


# The longest valid payload: every field present and at its largest.
LARGEST = {"signing_key": OBF, "encryption_key": OBF_X25519,
           "local": {"addresses": [bytes(16)] * MAX_ADDRESSES, "port": 65535},
           "relay": {"url": "https://relay.example.org/" + "a" * (MAX_RELAY_URL - 27) + "/", "mailbox": MAILBOX}}
assert not qr_problems(LARGEST) and len(LARGEST["relay"]["url"]) == MAX_RELAY_URL
MAX_QR_PAYLOAD = len(encode_qr(LARGEST))
MAX_QR_TEXT = len(QR_SCHEME) + -(-MAX_QR_PAYLOAD * 8 // 5)


def parse_qr(text):
    """The payload of a QR text, or the reason it is rejected."""
    if len(text) > MAX_QR_TEXT:
        return "longer than any valid text"
    if text[:len(QR_SCHEME)].upper() != QR_SCHEME:
        return "not the scheme AXT:"
    try:
        payload = unb32(text[len(QR_SCHEME):])
    except ValueError as e:
        return str(e)
    if payload[:1] != bytes([QR_VERSION]):
        return "a payload version this app does not know"
    if len(payload) > MAX_QR_PAYLOAD:
        return f"a payload above {MAX_QR_PAYLOAD} bytes"
    buf = io.BytesIO(payload[1:])
    try:
        q = fastavro.schemaless_reader(buf, qr_schema, qr_schema)
    except Exception:
        return "not an axt.QrPayload"
    if buf.tell() != len(payload) - 1:
        return "bytes left over"
    problems = qr_problems(q)
    return q if not problems else "; ".join(problems)


# QR codes, ISO/IEC 18004: data codewords of versions 1 to 20 at error correction level M, transcribed from the standard.
DATA_CODEWORDS_M = [16, 28, 44, 64, 86, 108, 124, 154, 182, 216, 254, 290, 334, 365, 415, 453, 507, 563, 627, 669]


def qr_version(n):
    """The smallest QR version that holds n characters in alphanumeric mode at level M."""
    for version, codewords in enumerate(DATA_CODEWORDS_M, 1):
        count_bits = 9 if version <= 9 else 11
        if 4 + count_bits + 11 * (n // 2) + 6 * (n % 2) <= 8 * codewords:
            return version
    raise ValueError("above version 20")


# The alphanumeric capacities at level M of versions 1, 9, 10 and 20, transcribed from ISO/IEC 18004, against the computation.
assert [max(n for n in range(971) if qr_version(n) <= v) for v in (1, 9, 10, 20)] == [20, 262, 311, 970]

qparts = qr_parts(QR)
payload = b"".join(p[0] for p in qparts)
assert payload == encode_qr(QR), "the payload differs from fastavro's encoding"
assert fastavro.schemaless_reader(io.BytesIO(payload[1:]), qr_schema, qr_schema) == QR
assert avro.io.DatumReader(qr_apache).read(avro.io.BinaryDecoder(io.BytesIO(payload[1:]))) == QR
assert not qr_problems(QR) and keys.key_problem(OBF) is None and keys.encryption_key_problem(OBF_X25519) is None
text = qr_text(payload)
assert set(text) <= QR_ALPHANUMERIC, "a character outside the alphanumeric mode"
expect("the QR text decodes to the payload", parse_qr(text), QR)
expect("the QR text in lower case decodes to the payload", parse_qr(text.lower()), QR)
assert len(payload) <= MAX_QR_PAYLOAD and len(text) <= MAX_QR_TEXT


def multi_block_largest():
    """The largest valid payload, with each address in an array block of its own (negative count and size)."""
    big = encode_qr(LARGEST)
    one_block = zigzag(MAX_ADDRESSES) + b"".join(zigzag(16) + bytes(16) for _ in range(MAX_ADDRESSES)) + zigzag(0)
    blocks = b"".join(zigzag(-1) + zigzag(17) + zigzag(16) + bytes(16) for _ in range(MAX_ADDRESSES)) + zigzag(0)
    assert big.count(one_block) == 1
    out = big.replace(one_block, blocks)
    assert fastavro.schemaless_reader(io.BytesIO(out[1:]), qr_schema, qr_schema) == LARGEST and len(out) > MAX_QR_PAYLOAD
    return out


def qr_with(**change):
    return dict(QR, **change)


QR_NEGATIVE = [
    ("another scheme", "HTTPS:" + text[4:], "scheme"),
    ("padding", text + "=" * (-len(text[4:]) % 8 or 8), "base32"),
    ("a character outside base32", text[:10] + "1" + text[11:], "base32"),
    ("bits in the last character that are not zero", text[:-1] + B32[B32.index(text[-1]) | 1], "not zero"),
    ("payload version 2", qr_text(b"\x02" + payload[1:]), "version"),
    ("bytes left over", qr_text(payload + b"\x00"), "left over"),
    ("cut short", qr_text(payload[:-1]), "not an axt.QrPayload"),
    ("a text above the longest", QR_SCHEME + "A" * (MAX_QR_TEXT - 3), "longer"),
    ("the largest payload with its addresses in four array blocks", qr_text(multi_block_largest()), "longer"),
    ("a signing key of small order", qr_text(encode_qr(qr_with(signing_key=(1).to_bytes(32, "little")))), "signing_key"),
    ("an encryption key of small order", qr_text(encode_qr(qr_with(encryption_key=bytes(32)))), "encryption_key"),
    ("a relay without encryption key", qr_text(encode_qr(qr_with(encryption_key=None))), "both"),
    ("an encryption key without relay", qr_text(encode_qr(qr_with(relay=None))), "both"),
    ("no address", qr_text(encode_qr(qr_with(local={"addresses": [], "port": PORT}))), "addresses"),
    ("five addresses", qr_text(encode_qr(qr_with(local={"addresses": [ADDRESS.packed] * 5, "port": PORT}))), "addresses"),
    ("an address of 5 bytes", qr_text(encode_qr(qr_with(local={"addresses": [bytes(5)], "port": PORT}))), "addresses"),
    ("port 0", qr_text(encode_qr(qr_with(local={"addresses": [ADDRESS.packed], "port": 0}))), "port"),
    ("port 65536", qr_text(encode_qr(qr_with(local={"addresses": [ADDRESS.packed], "port": 65536}))), "port"),
    ("a relay URL with http", qr_text(encode_qr(qr_with(relay={"url": "http://relay.example.org/", "mailbox": MAILBOX}))), "relay.url"),
    ("a relay URL without a slash at the end", qr_text(encode_qr(qr_with(relay={"url": "https://relay.example.org", "mailbox": MAILBOX}))), "relay.url"),
]
for label, bad, reason in QR_NEGATIVE:
    got = parse_qr(bad)
    assert isinstance(got, str) and reason in got, (label, got)
    checks.append(f"QR rejected: {label}")
# A code with the signing key alone is valid: it only shows the key, for comparing it in person.
expect("a QR code with the signing key alone", parse_qr(qr_text(encode_qr(
    {"signing_key": OBF, "encryption_key": None, "local": None, "relay": None}))),
    {"signing_key": OBF, "encryption_key": None, "local": None, "relay": None})

# --- the TLS certificate (section 4.3) ----------------------------------------

P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def certificate(secret):
    key = ec.derive_private_key(int.from_bytes(secret, "big") % (P256_ORDER - 1) + 1, ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "axt")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1)
            .not_valid_before(datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc))
            .not_valid_after(datetime.datetime(9999, 12, 31, 23, 59, 59, tzinfo=datetime.timezone.utc))
            .sign(key, hashes.SHA256(), ecdsa_deterministic=True))
    return key, cert


tls_key, tls_cert = certificate(TLS_SECRET)
CERT_DER = tls_cert.public_bytes(serialization.Encoding.DER)
assert certificate(TLS_SECRET)[1].public_bytes(serialization.Encoding.DER) == CERT_DER, "the certificate is not reproducible"
tls_cert.verify_directly_issued_by(tls_cert)
CERT_HASH = hashlib.sha256(CERT_DER).digest()
other_key, other_cert = certificate(test_secret("a machine in the middle, TLS, P-256"))
OTHER_CERT_HASH = hashlib.sha256(other_cert.public_bytes(serialization.Encoding.DER)).digest()

# --- frames and HELLO (sections 4.4 and 4.5) ----------------------------------

HELLO, MESSAGE, PING = 1, 2, 3
FRAME_NAMES = {HELLO: "HELLO", MESSAGE: "MESSAGE", PING: "PING"}
CLIENT, SERVER = 1, 2
MAX_MESSAGE = pe.MAX_MESSAGE


def frame(kind, data):
    return bytes([kind]) + len(data).to_bytes(4, "big") + data


def hello_signed(role, cert_hash):
    return HELLO_PREFIX + bytes([role]) + cert_hash


def hello(seed, role, cert_hash, check=True):
    signed = hello_signed(role, cert_hash)
    sig = pe.all_sign(seed, signed) if check else keys.sign(seed, signed)
    return frame(HELLO, keys.public_key(seed) + sig)


def hello_problem(data, role, cert_hash):
    """Why a HELLO's payload does not authenticate its key for this connection, or None."""
    if len(data) != 96:
        return "a HELLO of another length than 96"
    problem = keys.key_problem(data[:32]) or keys.verify_problem(data[:32], hello_signed(role, cert_hash), data[32:])
    return problem


class Closed(Exception):
    pass


class Peer:
    """One end of a live connection, as far as section 4 goes: frames, HELLO and senders."""

    def __init__(self, role, cert_hash, expected_key=None):
        self.role, self.cert_hash, self.expected_key = role, cert_hash, expected_key
        self.peer_key = None
        self.messages = 0  # messages taken other than KEY_MOVE
        self.taken = []

    def receive(self, data):
        """Take the bytes of one frame; returns what it does with it, or raises Closed."""
        if len(data) < 5:
            raise Closed("a frame cut short")
        kind, length, body = data[0], int.from_bytes(data[1:5], "big"), data[5:]
        if kind not in FRAME_NAMES:
            raise Closed("an unknown frame type")
        if kind == MESSAGE and length > MAX_MESSAGE:
            # The receiver skips the payload as it arrives and reports it (section 4.4).
            return "TOO_LARGE"
        if length != len(body):
            raise Closed("a frame cut short")
        if self.peer_key is None:
            if kind != HELLO:
                raise Closed("a frame before the HELLO")
            problem = hello_problem(body, CLIENT if self.role == SERVER else SERVER, self.cert_hash)
            if problem:
                raise Closed(f"a HELLO that does not verify: {problem}")
            if self.expected_key is not None and body[:32] != self.expected_key:
                raise Closed("a HELLO with another key than the QR code's")
            self.peer_key = body[:32]
            return "open"
        if kind == HELLO:
            raise Closed("a second HELLO")
        if kind == PING:
            if length:
                raise Closed("a PING with a payload")
            return "ping"
        if length == 0:
            raise Closed("an empty MESSAGE")
        kind_index, _ = keys.read_long(body, 11)
        sender = body[12:44]
        if pe.KINDS[kind_index] == "KEY_MOVE" and self.messages == 0:
            self.taken.append(body)
            return "message"  # a KEY_MOVE at the start, signed with an earlier key (section 4.5)
        if sender != self.peer_key:
            raise Closed("a message whose sender is not the key of the HELLO")
        self.messages += 1
        self.taken.append(body)
        return "message"


client_hello = hello(CAT_SEED, CLIENT, CERT_HASH)
server_hello = hello(OBF_SEED, SERVER, CERT_HASH)
data_frame = frame(MESSAGE, pe.data_msg)
ping_frame = frame(PING, b"")
assert hashlib.sha256(pe.data_msg).hexdigest() == "931e6f370f80527bae25f7475aa56e59f9bde6d71a0fe77c3dfad75700786086", \
    "not the DATA of spec/protocol.md, section 17.5"

server = Peer(SERVER, CERT_HASH)
client = Peer(CLIENT, CERT_HASH, expected_key=OBF)
expect("the server takes the client's HELLO", server.receive(client_hello), "open")
expect("the client takes the server's HELLO, with the key of the QR code", client.receive(server_hello), "open")
expect("the server takes the DATA", server.receive(data_frame), "message")
expect("the server takes a PING", server.receive(ping_frame), "ping")
assert server.peer_key == CAT and client.peer_key == OBF and server.taken == [pe.data_msg]


def closes(label, peer, *frames):
    try:
        for f in frames:
            peer.receive(f)
    except Closed as e:
        checks.append(f"closed: {label} ({e})")
        return
    raise AssertionError(f"{label}: the connection stays open")


km_parts, key_move = pe.make_message("KEY_MOVE", test_secret("cat-a-log, older phone, Ed25519"), None,
                                     [(b"", "placeholder")], check=False)
closes("a HELLO for another certificate, passed on by a machine in the middle", Peer(SERVER, OTHER_CERT_HASH), client_hello)
closes("the server's own HELLO sent back to it", Peer(SERVER, CERT_HASH), server_hello)
closes("a HELLO with another key than the QR code's", Peer(CLIENT, CERT_HASH, expected_key=CAT), server_hello)
closes("a HELLO with a changed signature", Peer(SERVER, CERT_HASH), client_hello[:-1] + bytes([client_hello[-1] ^ 1]))
closes("a HELLO with a key of small order", Peer(SERVER, CERT_HASH), frame(HELLO, (1).to_bytes(32, "little") + client_hello[37:]))
closes("a HELLO of 95 bytes", Peer(SERVER, CERT_HASH), frame(HELLO, client_hello[5:-1]))
closes("a MESSAGE before the HELLO", Peer(SERVER, CERT_HASH), data_frame)
closes("a PING before the HELLO", Peer(SERVER, CERT_HASH), ping_frame)
closes("a second HELLO", Peer(SERVER, CERT_HASH), client_hello, client_hello)
closes("a message whose sender is not the key of the HELLO", Peer(CLIENT, CERT_HASH), server_hello, data_frame)
closes("an empty MESSAGE", Peer(SERVER, CERT_HASH), client_hello, frame(MESSAGE, b""))
closes("a PING with a payload", Peer(SERVER, CERT_HASH), client_hello, frame(PING, b"\x00"))
closes("an unknown frame type", Peer(SERVER, CERT_HASH), client_hello, frame(4, b""))
closes("a frame cut short", Peer(SERVER, CERT_HASH), client_hello, data_frame[:-1])
closes("a KEY_MOVE after another message", Peer(SERVER, CERT_HASH), client_hello, data_frame, frame(MESSAGE, key_move))
p = Peer(SERVER, CERT_HASH)
p.receive(client_hello)
expect("a KEY_MOVE signed with an earlier key at the start", p.receive(frame(MESSAGE, key_move)), "message")
expect("then the sender's messages", p.receive(data_frame), "message")
too_large = bytes([MESSAGE]) + (MAX_MESSAGE + 1).to_bytes(4, "big")
p = Peer(SERVER, CERT_HASH)
p.receive(client_hello)
expect("a MESSAGE above 16 MiB is skipped and reported", p.receive(too_large), "TOO_LARGE")

# --- a TLS 1.3 connection over a local socket pair (section 4.3) --------------

ALPN = "axt/1"


def recv_exact(sock, n):
    out = b""
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise EOFError("the connection ended")
        out += chunk
    return out


def recv_frame(sock):
    head = recv_exact(sock, 5)
    return head + recv_exact(sock, int.from_bytes(head[1:5], "big"))


def tls_contexts(directory, client_max=ssl.TLSVersion.TLSv1_3):
    cert_path, key_path = Path(directory) / "cert.pem", Path(directory) / "key.pem"
    cert_path.write_bytes(tls_cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(tls_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.minimum_version = sctx.maximum_version = ssl.TLSVersion.TLSv1_3
    sctx.load_cert_chain(cert_path, key_path)
    sctx.set_alpn_protocols([ALPN])
    cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cctx.check_hostname = False
    cctx.verify_mode = ssl.CERT_NONE  # the HELLO authenticates the server, not a certificate chain
    cctx.maximum_version = client_max
    if client_max == ssl.TLSVersion.TLSv1_3:
        cctx.minimum_version = ssl.TLSVersion.TLSv1_3
    cctx.set_alpn_protocols([ALPN])
    return sctx, cctx


def tls_exchange():
    with tempfile.TemporaryDirectory() as d:
        sctx, cctx = tls_contexts(d)
        a, b = socket.socketpair()
        a.settimeout(20)
        b.settimeout(20)
        result = {}

        def serve():
            try:
                s = sctx.wrap_socket(b, server_side=True)
                result["server tls"] = (s.version(), s.selected_alpn_protocol())
                peer = Peer(SERVER, hashlib.sha256(CERT_DER).digest())  # the server hashes its own certificate
                s.sendall(hello(OBF_SEED, SERVER, CERT_HASH, check=False))
                result["server"] = [peer.receive(recv_frame(s)) for _ in range(3)]
                result["server taken"] = peer.taken
                result["server end"] = s.recv(1)  # b"" once the client's close_notify has arrived
                s.unwrap()
                s.close()
            except Exception as e:  # reported by the main thread
                result["server error"] = repr(e)

        t = threading.Thread(target=serve)
        t.start()
        c = cctx.wrap_socket(a)
        result["client tls"] = (c.version(), c.selected_alpn_protocol())
        der = c.getpeercert(binary_form=True)
        peer = Peer(CLIENT, hashlib.sha256(der).digest(), expected_key=OBF)  # the client hashes the certificate it got
        c.sendall(client_hello)
        result["client"] = peer.receive(recv_frame(c))  # nothing but the HELLO before the server's is verified
        c.sendall(data_frame + ping_frame)
        c.unwrap()
        c.close()
        t.join(30)
        assert not t.is_alive() and "server error" not in result, result.get("server error")
        result["peer certificate"] = der
        return result


r = tls_exchange()
expect("TLS: both ends use TLS 1.3 and ALPN axt/1", (r["client tls"], r["server tls"]), (("TLSv1.3", ALPN),) * 2)
expect("TLS: the client got Old Brain Fix's certificate", r["peer certificate"], CERT_DER)
expect("TLS: the client takes the server's HELLO", r["client"], "open")
expect("TLS: the server takes the HELLO, the DATA and the PING", r["server"], ["open", "message", "ping"])
expect("TLS: the server got the DATA as sent", r["server taken"], [pe.data_msg])
expect("TLS: the client closes with close_notify", r["server end"], b"")


def tls12_refused():
    with tempfile.TemporaryDirectory() as d:
        sctx, cctx = tls_contexts(d, client_max=ssl.TLSVersion.TLSv1_2)
        a, b = socket.socketpair()
        a.settimeout(20)
        b.settimeout(20)
        errors = []

        def serve():
            try:
                sctx.wrap_socket(b, server_side=True)
            except (ssl.SSLError, OSError) as e:
                errors.append(type(e).__name__)
            b.close()

        t = threading.Thread(target=serve)
        t.start()
        try:
            cctx.wrap_socket(a)
            refused = False
        except (ssl.SSLError, OSError):
            refused = True
        a.close()
        t.join(30)
        return refused and bool(errors)


expect("TLS: a client limited to TLS 1.2 cannot connect", tls12_refused(), True)

# --- the sealed message (spec/keys.md, sections 7.2 and 7.4) ------------------

MEMO_FP = 0x37F20E16CADCAC73
# The Memo: its text, then written, an axt.DateTime of 2025-11-15 11:00 in Europe/Berlin with the offset 3600.
memo_written = (b"".join(zigzag(n) for n in (2025, 11, 15, 11, 0, 0, 0)) + zigzag(1) + zigzag(13) + b"Europe/Berlin"
                + zigzag(1) + zigzag(3600) + zigzag(1) + zigzag(1763200800000))
memo_body = b"\xc3\x01" + MEMO_FP.to_bytes(8, "little") + zigzag(18) + b"Vet, Tuesday 10:00" + memo_written
_, memo_msg = pe.make_message("DATA", CAT_SEED, ("0b5a3c1e-4d2f-4a6b-9c8d-7e6f5a4b3c2d", 1), [(memo_body, "the Memo")])
assert hashlib.sha256(memo_msg).hexdigest() == "23fdfeb720ae7a368b936ce9f990039b7472fe7128927da9c3648e9b9ea67f07", \
    "not the message of spec/keys.md, section 7.2"
sk_e, pk_e = keys.derive_key_pair(test_secret("ephemeral key of the sealed message, ikmE"))
enc, shared = keys.encap(sk_e, OBF_X25519)
ctx = keys.hpke_base_context(shared, keys.HPKE_INFO)
SEALED = keys.SEALED_FORMAT + enc + ChaCha20Poly1305(ctx["key"]).encrypt(ctx["base_nonce"], keys.pad(memo_msg), b"")
SEALED_HASH = hashlib.sha256(SEALED).hexdigest()
assert len(SEALED) == 1073 and SEALED_HASH == "7cbe47862344527d93735c97159cc8cf4d3631647233cac735553c968e6c2bc8", \
    "not the sealed message of spec/keys.md, section 7.4"
MAX_SEALED = 1 + 32 + keys.padded_length(MAX_MESSAGE) + 16
assert MAX_SEALED == 17301553

# --- the relay (section 5) ----------------------------------------------------

HOLDING = 14 * 86400  # seconds
GRACE = 86400  # a relay deletes a message within a day after its holding time
MAX_WAIT = 60
MAX_LISTED = 1000
HEX64 = re.compile(r"^[0-9a-f]{64}$")
PATH = re.compile(r"^v1/mailboxes/([0-9a-f]{64})(?:/messages(?:/([0-9a-f]{64}))?)?$")


class Relay:
    """A model of the relay's interface of section 5.2; storage and limits are the reference relay's."""

    def __init__(self, quota_bytes=64 * 2**20):
        self.mailboxes = {}  # id -> {message id: (bytes, time of put)}, in order of put
        self.quota_bytes = quota_bytes

    def expire(self, now):
        for box in self.mailboxes.values():
            for mid in [m for m, (_, t) in box.items() if now >= t + HOLDING + GRACE]:
                del box[mid]

    def owner(self, mailbox, headers):
        auth = headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or not HEX64.match(auth[7:]):
            return 401
        return None if mailbox_id(bytes.fromhex(auth[7:])).hex() == mailbox else 403

    def handle(self, method, target, headers=None, body=b"", now=0):
        """Returns (status, content type or None, body)."""
        headers = headers or {}
        self.expire(now)
        path, _, query = target.partition("?")
        m = PATH.match(path)
        if not m:
            return 404, None, b""
        mailbox, message = m.group(1), m.group(2)
        is_list = path.endswith("/messages")
        if query and not (is_list and method == "GET"):
            return 400, None, b""
        if method == "PUT" and message:  # put a message: no owner needed
            if "Content-Length" not in headers:
                return 411, None, b""
            if int(headers["Content-Length"]) > MAX_SEALED:
                return 413, None, b""
            if mailbox not in self.mailboxes:
                return 404, None, b""
            if len(body) != int(headers["Content-Length"]) or not body or hashlib.sha256(body).hexdigest() != message:
                return 400, None, b""
            box = self.mailboxes[mailbox]
            if message in box:
                return 204, None, b""
            if box and sum(len(b) for b, _ in box.values()) + len(body) > self.quota_bytes:
                return 507, None, b""
            box[message] = (body, now)
            return 201, None, b""
        refused = self.owner(mailbox, headers)
        if refused:
            return refused, None, b""
        if not message and not is_list:
            if method == "PUT":
                if mailbox in self.mailboxes:
                    return 204, None, b""
                self.mailboxes[mailbox] = {}
                return 201, None, b""
            if method == "DELETE":
                self.mailboxes.pop(mailbox, None)
                return 204, None, b""
            return 405, None, b""
        if mailbox not in self.mailboxes:
            return 404, None, b""
        box = self.mailboxes[mailbox]
        if is_list and method == "GET":
            wait = 0
            if query:
                q = re.match(r"^wait=([0-9]{1,2})$", query)
                if not q or int(q.group(1)) > MAX_WAIT:
                    return 400, None, b""
            listed = [{"id": mid, "size": len(b)} for mid, (b, _) in list(box.items())[:MAX_LISTED]]
            return 200, "application/json", json.dumps({"messages": listed}, separators=(",", ":")).encode()
        if message and method == "GET":
            if message not in box:
                return 404, None, b""
            return 200, "application/octet-stream", box[message][0]
        if message and method == "DELETE":
            box.pop(message, None)
            return 204, None, b""
        return 405, None, b""


OWNER = {"Authorization": "Bearer " + MAILBOX_SECRET.hex()}
WRONG = {"Authorization": "Bearer " + test_secret("another mailbox secret").hex()}
BOX = f"v1/mailboxes/{MAILBOX.hex()}"
PUT_PATH = f"{BOX}/messages/{SEALED_HASH}"
relay = Relay()


def put(body, path=PUT_PATH, **kw):
    return relay.handle("PUT", path, {"Content-Length": str(len(body))}, body, **kw)[0]


expect("relay: a put before the mailbox exists", put(SEALED), 404)
expect("relay: creating the mailbox without Authorization", relay.handle("PUT", BOX)[0], 401)
expect("relay: creating it with a malformed Authorization", relay.handle("PUT", BOX, {"Authorization": "Bearer xyz"})[0], 401)
expect("relay: creating it with another mailbox's secret", relay.handle("PUT", BOX, WRONG)[0], 403)
expect("relay: creating the mailbox", relay.handle("PUT", BOX, OWNER)[0], 201)
expect("relay: creating it again", relay.handle("PUT", BOX, OWNER)[0], 204)
expect("relay: a put without Content-Length", relay.handle("PUT", PUT_PATH, {}, SEALED)[0], 411)
expect("relay: a put whose id is not its SHA-256", put(SEALED[:-1] + b"\x00"), 400)
expect("relay: a put above 17,301,553 bytes", relay.handle("PUT", PUT_PATH, {"Content-Length": str(MAX_SEALED + 1)})[0], 413)
expect("relay: the put of the sealed message", put(SEALED, now=1000), 201)
expect("relay: the same put again", put(SEALED, now=2000), 204)
expect("relay: listing with another mailbox's secret", relay.handle("GET", f"{BOX}/messages", WRONG)[0], 403)
expect("relay: listing with a wait above 60 seconds", relay.handle("GET", f"{BOX}/messages?wait=61", OWNER)[0], 400)
listing = relay.handle("GET", f"{BOX}/messages?wait=30", OWNER, now=3000)
expect("relay: the listing", listing, (200, "application/json",
                                         json.dumps({"messages": [{"id": SEALED_HASH, "size": 1073}]}, separators=(",", ":")).encode()))
fetched = relay.handle("GET", PUT_PATH, OWNER, now=3000)
expect("relay: the fetch", fetched, (200, "application/octet-stream", SEALED))
expect("relay: a fetch without the secret", relay.handle("GET", PUT_PATH, now=3000)[0], 401)
expect("relay: a delete without the secret", relay.handle("DELETE", PUT_PATH, WRONG, now=3000)[0], 403)
expect("relay: the delete", relay.handle("DELETE", PUT_PATH, OWNER, now=3000)[0], 204)
expect("relay: the delete again", relay.handle("DELETE", PUT_PATH, OWNER, now=3000)[0], 204)
expect("relay: the listing after the delete", relay.handle("GET", f"{BOX}/messages", OWNER, now=3000)[2], b'{"messages":[]}')
expect("relay: a fetch after the delete", relay.handle("GET", PUT_PATH, OWNER, now=3000)[0], 404)
# Holding time: kept for 14 days after the put, gone a day later.
put(SEALED, now=0)
expect("relay: held 14 days after the put", relay.handle("GET", PUT_PATH, OWNER, now=HOLDING - 1)[0], 200)
expect("relay: gone 15 days after the put", relay.handle("GET", PUT_PATH, OWNER, now=HOLDING + GRACE)[0], 404)
# Order: oldest first.
second = SEALED[:-1] + bytes([SEALED[-1] ^ 1])  # does not open; the relay cannot tell
second_hash = hashlib.sha256(second).hexdigest()
put(SEALED, now=HOLDING + GRACE)
put(second, path=f"{BOX}/messages/{second_hash}", now=HOLDING + GRACE + 1)
expect("relay: the listing in the order of the puts",
       [m["id"] for m in json.loads(relay.handle("GET", f"{BOX}/messages", OWNER, now=HOLDING + GRACE + 2)[2])["messages"]],
       [SEALED_HASH, second_hash])
# An empty mailbox takes a message of the largest size, whatever its quota.
small = Relay(quota_bytes=0)
small.handle("PUT", BOX, OWNER)
largest = bytes(MAX_SEALED)
expect("relay: an empty mailbox takes a message of 17,301,553 bytes", small.handle(
    "PUT", f"{BOX}/messages/{hashlib.sha256(largest).hexdigest()}", {"Content-Length": str(MAX_SEALED)}, largest)[0], 201)
expect("relay: a full mailbox", small.handle("PUT", PUT_PATH, {"Content-Length": "1073"}, SEALED)[0], 507)
expect("relay: deleting the mailbox", relay.handle("DELETE", BOX, OWNER)[0], 204)
expect("relay: a put after the mailbox was deleted", put(SEALED), 404)

# Old Brain Fix opens what it fetched (spec/keys.md, section 4.5).
assert fetched[2][:1] == keys.SEALED_FORMAT
shared_r = keys.decap(fetched[2][1:33], OBF_X25519_SK)
ctx_r = keys.hpke_base_context(shared_r, keys.HPKE_INFO)
opened = keys.unpad(ChaCha20Poly1305(ctx_r["key"]).decrypt(ctx_r["base_nonce"], fetched[2][33:], b""))
expect("relay: the fetched message opens to the DATA of spec/keys.md, section 7.2", opened, memo_msg)
assert pe.all_verify(CAT, keys.MESSAGE_PREFIX + opened[10:-64], opened[-64:]) is None

# --- output -------------------------------------------------------------------


def dump(parts):
    """Annotated hex in the layout of spec/envelope.md; a part with a third element is shown shortened."""
    offset, lines = 0, []
    for part in parts:
        data, meaning = part[0], part[1]
        if len(part) > 2:
            hexs = data[:4].hex(" ") + " ... " + data[-2:].hex(" ")
            lines.append(f"{offset:04x}  {hexs:<23}  {meaning}")
        else:
            for i in range(0, len(data), 8):
                hexs = data[i:i + 8].hex(" ")
                lines.append(f"{offset:04x}  {hexs:<23}  {meaning}".rstrip() if i == 0 else f"      {hexs}")
        offset += len(data)
    lines.append(f"{offset:04x}  end")
    return "\n".join(lines)


def hello_parts(f, who):
    return [(f[:1], "frame type 1, HELLO"), (f[1:5], "length 96"), (f[5:37], f"key: fixed(32), {who}'s test key"),
            (f[37:], "signature: fixed(64)")]


HOST = urlsplit(RELAY_URL).hostname
BASE = urlsplit(RELAY_URL).path


def request(method, path, headers, body_note=None):
    lines = [f"{method} {BASE}{path} HTTP/1.1", f"Host: {HOST}"] + [f"{k}: {v}" for k, v in headers]
    return "\n".join(lines) + ("\n\n" + body_note if body_note else "")


def response(status, reason, headers, body_text=None):
    return "\n".join([f"HTTP/1.1 {status} {reason}"] + [f"{k}: {v}" for k, v in headers]) + (
        "\n\n" + body_text if body_text is not None else "")


auth = ("Authorization", "Bearer " + MAILBOX_SECRET.hex())
http = [
    ("create the mailbox", request("PUT", BOX, [auth, ("Content-Length", "0")]),
     response(201, "Created", [("Content-Length", "0")])),
    ("put", request("PUT", PUT_PATH, [("Content-Type", "application/octet-stream"), ("Content-Length", "1073")],
                    "<the 1,073 bytes of the sealed message>"),
     response(201, "Created", [("Content-Length", "0")])),
    ("list", request("GET", f"{BOX}/messages?wait=30", [auth]),
     response(200, "OK", [("Content-Type", "application/json"), ("Content-Length", str(len(listing[2])))], listing[2].decode())),
    ("fetch", request("GET", PUT_PATH, [auth]),
     response(200, "OK", [("Content-Type", "application/octet-stream"), ("Content-Length", "1073")],
              "<the 1,073 bytes of the sealed message>")),
    ("delete", request("DELETE", PUT_PATH, [auth]), response(204, "No Content", [])),
]

print(f"axt.QrPayload canonical form: {qr_pcf}")
print(f"axt.QrPayload CRC-64-AVRO: 0x{qr_fp:016x}, bytes {qr_fp.to_bytes(8, 'little').hex(' ')}")
print(f"axt.QrPayload: data depth {qr_depth}; defaults resolved: {defaults_resolved}; "
      f"fields without a default: {', '.join(required)}")
print()
print("== Test values (never use outside tests) ==")
print(f"Old Brain Fix, Ed25519 public key   {OBF.hex()}")
print(f"Old Brain Fix, X25519 public key    {OBF_X25519.hex()}")
print(f"Old Brain Fix, mailbox secret       {MAILBOX_SECRET.hex()}")
print(f"Old Brain Fix, mailbox id           {MAILBOX.hex()}")
print(f"Old Brain Fix, TLS P-256 key        {tls_key.private_numbers().private_value:064x}")
print(f"cat-a-log, old phone, Ed25519 key   {CAT.hex()}")
print()
print(f"== QR payload: {len(payload)} bytes, SHA-256 {hashlib.sha256(payload).hexdigest()} ==")
print(dump(qparts))
print()
print(f"QR text: {len(text)} characters, QR version {qr_version(len(text))} at level M in alphanumeric mode")
print(text)
print(f"longest valid payload: {MAX_QR_PAYLOAD} bytes, text {MAX_QR_TEXT} characters, QR version {qr_version(MAX_QR_TEXT)}")
print()
print(f"== Old Brain Fix's TLS certificate: {len(CERT_DER)} bytes, SHA-256 {CERT_HASH.hex()} ==")
print(tls_cert.public_bytes(serialization.Encoding.PEM).decode().rstrip())
print()
for title, f, who in (("cat-a-log's HELLO, as the client", client_hello, "cat-a-log"),
                      ("Old Brain Fix's HELLO, as the server", server_hello, "Old Brain Fix")):
    role = f[5:37] == CAT and CLIENT or SERVER
    print(f"== {title}: {len(f)} bytes ==")
    print(dump(hello_parts(f, who)))
    print(f"signed bytes ({len(hello_signed(role, CERT_HASH))}): {hello_signed(role, CERT_HASH).hex(' ')}")
    print()
print(f"== cat-a-log's DATA in a MESSAGE frame: {len(data_frame)} bytes ==")
print(dump([(data_frame[:1], "frame type 2, MESSAGE"), (data_frame[1:5], f"length {len(pe.data_msg)}"),
            (data_frame[5:], "the DATA of spec/protocol.md, section 17.5", True)]))
print()
print(f"== a PING frame: {len(ping_frame)} bytes ==")
print(dump([(ping_frame[:1], "frame type 3, PING"), (ping_frame[1:5], "length 0")]))
print()
print(f"== relay: the sealed message of spec/keys.md, section 7.4: {len(SEALED)} bytes, SHA-256 {SEALED_HASH} ==")
for title, req, resp in http:
    print(f"-- {title}")
    print(req)
    print()
    print(resp)
    print()
print(f"largest sealed message: {MAX_SEALED} bytes")
print()
print(f"model checks: {len(checks)}")
for label in checks:
    print(f"  {label}")
print("all checks passed")
