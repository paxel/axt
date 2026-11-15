# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Generate the test vectors of spec/conformance.md under vectors/.

Builds every vector from the code of the example scripts in this directory,
which check the examples of the specification, and writes one JSON file per
category, vectors/<category>/<category>.json. The expected result of each
vector is either computed with the scripts' code and models, whose own
checks pin it to the specification's examples, or written out here from a
table of the specification, where the scripts have no model; the reference
adapter, conformance/reference/adapter.py, then has to reach it on its own.

Run from anywhere, with fastavro, avro (1.12), pynacl and cryptography
installed:

    python3 conformance/tools/generate_vectors.py          # write vectors/
    python3 conformance/tools/generate_vectors.py --check  # compare with vectors/
    python3 conformance/tools/generate_vectors.py --out DIR

The output is the same in every run and under every PYTHONHASHSEED. Every
key, secret and certificate is a TEST value of spec/keys.md, section 7.1,
or derived the same way, and MUST NOT be used outside tests.
"""

import argparse
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import re
import sys
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
VECTORS = REPO / "vectors"
FILE_FORMAT = 1  # the version of the vector file format of spec/conformance.md, section 3
SPEC_VERSION = "0.1.0"
INLINE_LIMIT = 65536  # bytes up to which a value is written as hex; above it, as raw DEFLATE


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    with contextlib.redirect_stdout(io.StringIO()):
        spec.loader.exec_module(module)
    return module


# transports_examples imports protocol_examples, which imports manifest_examples, keys_examples and
# example_types; each runs its checks on import. Nothing of the live TLS exchange reaches a vector.
tx = load("transports_examples")
pe, me, keys, rules = tx.pe, tx.me, tx.keys, tx.rules
env = load("envelope_examples")

import fastavro  # noqa: E402  (after the scripts, which check the library versions they were written with)

# --- the bytes of a vector (spec/conformance.md, section 3.2) ---------------------


def B(data):
    """Bytes as lower-case hex, or above INLINE_LIMIT as raw DEFLATE with their length and SHA-256."""
    data = bytes(data)
    if len(data) <= INLINE_LIMIT:
        return data.hex()
    c = zlib.compressobj(9, zlib.DEFLATED, -15, 9)
    packed = c.compress(data) + c.flush()
    return {"deflate": packed.hex(), "length": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def H(data):
    return bytes(data).hex()


def accept(value=None):
    return {"accept": {} if value is None else value}


def reject(error, note=None):
    out = {"error": error}
    if note:
        out["note"] = note
    return {"reject": out}


class Category:
    def __init__(self, name, description):
        self.name, self.description, self.vectors, self.ids = name, description, [], set()

    def add(self, op, description, refs, input, expected):
        slug = re.sub(r"[^a-z0-9]+", "-", description.lower()).strip("-")[:72].strip("-")
        vid = f"{self.name}/{op}/{slug}"
        assert vid not in self.ids, f"two vectors with the id {vid}"
        self.ids.add(vid)
        self.vectors.append({"id": vid, "op": op, "description": description, "refs": refs,
                             "input": input, "expected": expected})

    def document(self):
        return {"format": FILE_FORMAT, "specification": SPEC_VERSION, "category": self.name,
                "description": self.description, "vectors": self.vectors}


def test_secret(label):
    return hashlib.sha256(b"AXT test key, not for use: " + label.encode()).digest()


CAT_SEED, OBF_SEED, CAT, OBF = pe.CAT_SEED, pe.OBF_SEED, pe.CAT, pe.OBF
NEW_SEED = test_secret("cat-a-log, new phone, Ed25519")
NEW = keys.public_key(NEW_SEED)
NEW_X25519_SK = test_secret("cat-a-log, new phone, X25519")
NEW_X25519 = keys.x25519(NEW_X25519_SK, keys.X25519_BASE)
OBF_X25519_SK, OBF_X25519 = tx.OBF_X25519_SK, tx.OBF_X25519
ENVELOPE_FP = pe.fp8(pe.fingerprints["Envelope"][1])

# The DATA message of spec/keys.md, section 7.2 (and spec/envelope.md, section 10.2) and its signed bytes.
MEMO_MSG = env.message
MEMO_SIGNED = keys.MESSAGE_PREFIX + MEMO_MSG[10:-64]
assert hashlib.sha256(MEMO_MSG).hexdigest() == "c6901788f627c534b72f85e50165db1ee77aa89549f9713d5cbb2a2119b1ee83"
assert MEMO_MSG == tx.memo_msg

# --- keys (spec/keys.md) --------------------------------------------------------


def key_move_body(new_seed, old_key, new_encryption_key, proof=None):
    """The body of a KEY_MOVE: axt.KeyMove in single-object encoding (spec/keys.md, section 5.1)."""
    new_key = keys.public_key(new_seed)
    if proof is None:
        proof = keys.sign(new_seed, keys.KEY_MOVE_PREFIX + old_key + new_key)
    datum = new_key + (keys.zigzag(0) if new_encryption_key is None else keys.zigzag(1) + new_encryption_key) + proof
    return b"\xc3\x01" + pe.fp8(pe.fingerprints["KeyMove"][1]) + datum


def key_move(old_seed, new_seed, new_encryption_key, proof=None):
    body = key_move_body(new_seed, keys.public_key(old_seed), new_encryption_key, proof)
    return pe.make_message("KEY_MOVE", old_seed, None, [(body, "")], check=False)[1]


def sealed(message, receiver_key, ikm_label, plaintext=None):
    """A sealed message (spec/keys.md, section 4.3), with an ephemeral key derived from a test label."""
    sk_e, _ = keys.derive_key_pair(test_secret(ikm_label))
    enc, shared = keys.encap(sk_e, receiver_key)
    ctx = keys.hpke_base_context(shared, keys.HPKE_INFO)
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    padded = keys.pad(message) if plaintext is None else plaintext
    return keys.SEALED_FORMAT + enc + ChaCha20Poly1305(ctx["key"]).encrypt(ctx["base_nonce"], padded, b"")


KM_MSG = key_move(CAT_SEED, NEW_SEED, NEW_X25519)
assert hashlib.sha256(KM_MSG).hexdigest() == "a4e2e8662beb27b3b4df70d1840fe8f58cbfac501a8f937a197f729028180bea", \
    "not the KEY_MOVE of spec/keys.md, section 7.5"


def keys_category():
    c = Category("keys", "Signing keys, signatures, short fingerprints, key moves, and sealing for the relay "
                         "(spec/keys.md).")
    rfc_seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    rfc_pub = keys.public_key(rfc_seed)
    assert rfc_pub.hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    seeds = [("RFC 8032, section 7.1, TEST 1", rfc_seed), ("cat-a-log, old phone", CAT_SEED),
             ("cat-a-log, new phone", NEW_SEED), ("Old Brain Fix", OBF_SEED)]
    for label, seed in seeds:
        c.add("public_key", f"the public key of the test seed {label}", ["keys.md 7.1"],
              {"seed": H(seed)}, accept({"public_key": H(keys.public_key(seed))}))

    header_signed = keys.FILE_HEADER_PREFIX + CAT + hashlib.sha256(env.schemas_value.encode()).digest()
    proof_signed = keys.KEY_MOVE_PREFIX + CAT + NEW
    for label, seed, data, refs in [
        ("RFC 8032, section 7.1, TEST 1: the empty message", rfc_seed, b"", ["keys.md 2.2"]),
        ("the DATA message of keys.md, section 7.2", CAT_SEED, MEMO_SIGNED, ["keys.md 2.2", "keys.md 7.2"]),
        ("the file header of keys.md, section 7.3", CAT_SEED, header_signed, ["keys.md 2.5", "keys.md 7.3"]),
        ("the proof of the KEY_MOVE of keys.md, section 7.5", NEW_SEED, proof_signed, ["keys.md 5.1", "keys.md 7.5"]),
    ]:
        c.add("sign", f"sign {label}", refs, {"seed": H(seed), "data": H(data)},
              accept({"signature": H(keys.sign(seed, data))}))
    assert keys.sign(CAT_SEED, MEMO_SIGNED) == MEMO_MSG[-64:]
    assert keys.sign(CAT_SEED, header_signed).hex() == env.HEADER_SIGNATURE.hex()

    # Verification: the RFC 8032 test, and the edges of spec/keys.md, section 7.6.
    rfc_sig = keys.sign(rfc_seed, b"")
    c.add("verify", "the signature of RFC 8032, section 7.1, TEST 1", ["keys.md 2.3"],
          {"public_key": H(rfc_pub), "data": "", "signature": H(rfc_sig)}, accept())
    cases, (identity, identity_nc, mixed_r, mixed_key) = keys.edge_cases(CAT_SEED, OBF, MEMO_SIGNED, MEMO_MSG[-64:])
    assert len(cases) == 10, "spec/keys.md, section 7.6, has ten cases"
    for label, key, data, sig, problem in cases:
        assert keys.verify_problem(key, data, sig) == problem
        c.add("verify", f"keys.md 7.6: {label}", ["keys.md 2.3", "keys.md 7.6"],
              {"public_key": H(key), "data": H(data), "signature": H(sig)},
              accept() if problem is None else reject("SIGNATURE_INVALID", problem))

    # Keys: steps 2 and 3 of spec/keys.md, section 2.3.
    small = keys.small_order_points()
    assert len(small) == 8
    for label, key in [("cat-a-log, old phone", CAT), ("cat-a-log, new phone", NEW), ("Old Brain Fix", OBF)]:
        c.add("check_signing_key", f"the test key {label}", ["keys.md 2.3"], {"public_key": H(key)}, accept())
    sign_bit_identity = bytes([1] + [0] * 30 + [0x80])  # x = 0 with the sign bit set
    not_on_curve = next(y.to_bytes(32, "little") for y in range(2, 100) if keys.decompress(y.to_bytes(32, "little")) is None)
    for label, key in ([(f"the point of small order {e[:4].hex()}...{e[-2:].hex()}", e) for e in small] + [
            ("the neutral element encoded with y = p + 1", identity_nc),
            ("the neutral element with the sign bit set", sign_bit_identity),
            (f"an encoding that is not a point, y = {int.from_bytes(not_on_curve, 'little')}", not_on_curve),
            ("a key with a component of order 8", mixed_key)]):
        problem = keys.key_problem(key)
        assert problem, label
        c.add("check_signing_key", f"reject {label}", ["keys.md 2.3"], {"public_key": H(key)},
              reject("KEY_INVALID", problem))

    # Encryption keys: small order (spec/keys.md, section 4.2).
    p = keys.P
    for label, key in [("Old Brain Fix's X25519 test key", OBF_X25519), ("cat-a-log's new X25519 test key", NEW_X25519)]:
        assert keys.encryption_key_problem(key) is None
        c.add("check_encryption_key", f"accept {label}", ["keys.md 4.2"], {"encryption_key": H(key)}, accept())
    smalls = [
        ("u = 0", (0).to_bytes(32, "little")),
        ("u = 1", (1).to_bytes(32, "little")),
        ("a point of order 8", bytes.fromhex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")),
        ("the other point of order 8", bytes.fromhex("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157")),
        ("u = p - 1", (p - 1).to_bytes(32, "little")),
        ("u = p, non-canonical 0", p.to_bytes(32, "little")),
        ("u = p + 1, non-canonical 1", (p + 1).to_bytes(32, "little")),
        ("u = 0 with the top bit set", bytes(31) + b"\x80"),
    ]
    for label, key in smalls:
        assert keys.encryption_key_problem(key), label
        c.add("check_encryption_key", f"reject {label}", ["keys.md 4.2"], {"encryption_key": H(key)},
              reject("ENCRYPTION_KEY_INVALID", "X25519 gives the all-zero value"))

    for label, key, fp in [("cat-a-log, old phone", CAT, "24773 42899 01908 98427 81734"),
                           ("cat-a-log, new phone", NEW, "09244 67325 13841 38603 74394"),
                           ("Old Brain Fix", OBF, "01399 72263 65477 52894 90179")]:
        assert keys.short_fingerprint(key) == fp
        c.add("short_fingerprint", f"the short fingerprint of {label}", ["keys.md 3.1", "keys.md 7.1"],
              {"public_key": H(key)}, accept({"short_fingerprint": fp}))

    # Messages: the signature over the bytes as received (spec/keys.md, section 2.2).
    upper = MEMO_MSG.replace(env.RECORD_ID.encode(), env.RECORD_ID.upper().encode())
    flipped = MEMO_MSG[:0x60] + bytes([MEMO_MSG[0x60] ^ 1]) + MEMO_MSG[0x61:]
    resigned = pe.resign(OBF_SEED, MEMO_MSG)  # signed by another key, sender unchanged
    for label, message, ok, refs in [
        ("the DATA message of keys.md, section 7.2", MEMO_MSG, True, ["keys.md 7.2"]),
        ("the KEY_MOVE of keys.md, section 7.5, signed with the old key", KM_MSG, True, ["keys.md 5.1", "keys.md 7.5"]),
        ("the MANIFEST of cat-a-log of protocol.md, section 17.2", pe.m1, True, ["protocol.md 17.2"]),
        ("the OFFER of protocol.md, section 17.3", pe.offer_msg, True, ["protocol.md 17.3"]),
        ("the ACK of protocol.md, section 17.5", pe.ack_msg, True, ["protocol.md 17.5"]),
        ("the DATA message with its record id in upper case, signature unchanged", upper, False, ["keys.md 2.2", "keys.md 7.2"]),
        ("the DATA message with one byte of the body changed", flipped, False, ["keys.md 2.3"]),
        ("the DATA message signed with another key than its sender", resigned, False, ["keys.md 2.3"]),
    ]:
        c.add("verify_message", label, ["keys.md 2.2", "keys.md 2.3"] + refs, {"message": B(message)},
              accept() if ok else reject("SIGNATURE_INVALID"))

    # Key moves: the checks of spec/keys.md, section 5.3, steps 1 and 4, that need no known sender.
    c.add("key_move", "the KEY_MOVE of keys.md, section 7.5", ["keys.md 5.1", "keys.md 5.3", "keys.md 7.5"],
          {"message": B(KM_MSG)},
          accept({"old_key": H(CAT), "new_key": H(NEW), "new_encryption_key": H(NEW_X25519)}))
    no_x = key_move(CAT_SEED, NEW_SEED, None)
    c.add("key_move", "a KEY_MOVE without an encryption key", ["keys.md 5.1", "keys.md 5.3"],
          {"message": B(no_x)}, accept({"old_key": H(CAT), "new_key": H(NEW), "new_encryption_key": None}))
    other_old = keys.public_key(test_secret("cat-a-log, older phone, Ed25519"))
    bad = [
        ("a proof made by another key than the new one",
         key_move(CAT_SEED, NEW_SEED, NEW_X25519, keys.sign(OBF_SEED, keys.KEY_MOVE_PREFIX + CAT + NEW)), "the proof does not verify"),
        ("a proof over another old key",
         key_move(CAT_SEED, NEW_SEED, NEW_X25519, keys.sign(NEW_SEED, keys.KEY_MOVE_PREFIX + other_old + NEW)), "the proof does not verify"),
        ("a proof with the prefix of a message signature",
         key_move(CAT_SEED, NEW_SEED, NEW_X25519, keys.sign(NEW_SEED, keys.MESSAGE_PREFIX + CAT + NEW)), "the proof does not verify"),
        ("a new encryption key of small order", key_move(CAT_SEED, NEW_SEED, bytes(32)), "the encryption key is of small order"),
    ]
    for label, message, note in bad:
        c.add("key_move", f"reject {label}", ["keys.md 5.3"], {"message": B(message)},
              reject("KEY_MOVE_REJECTED", note))
    # A new key of small order: its body is built by hand, since no seed gives such a key.
    small_body = b"\xc3\x01" + pe.fp8(pe.fingerprints["KeyMove"][1]) + identity + keys.zigzag(1) + NEW_X25519 + identity + bytes(32)
    c.add("key_move", "reject a new key of small order, with a proof that verifies under a lax rule",
          ["keys.md 2.3", "keys.md 5.3"], {"message": B(pe.make_message("KEY_MOVE", CAT_SEED, None, [(small_body, "")], check=False)[1])},
          reject("KEY_MOVE_REJECTED", "the new key is not of order L"))
    bad_sig = KM_MSG[:-1] + bytes([KM_MSG[-1] ^ 1])
    c.add("key_move", "reject a KEY_MOVE whose signature by the old key does not verify", ["keys.md 5.3"],
          {"message": B(bad_sig)}, reject("SIGNATURE_INVALID"))

    # Padding (spec/keys.md, section 4.4).
    table = {183: 1024, 1023: 1024, 1024: 1088, 4000: 4096, 100000: 100352, 16777216: 17301504}
    for n in [1, 183, 1022, 1023, 1024, 1087, 1088, 4000, 100000, 16777216]:
        got = keys.padded_length(n)
        assert table.get(n, got) == got
        c.add("padded_length", f"the padded length of a message of {n} bytes", ["keys.md 4.4"],
              {"length": n}, accept({"padded_length": got}))

    # Sealing: the runner opens what the library seals, with the receiver's test key.
    for label, message in [("the DATA message of keys.md, section 7.2", MEMO_MSG),
                           ("the KEY_MOVE of keys.md, section 7.5", KM_MSG)]:
        n = len(message)
        c.add("seal", f"seal {label} for Old Brain Fix", ["keys.md 4.3", "keys.md 4.4"],
              {"message": B(message), "encryption_key": H(OBF_X25519)},
              accept({"sealed": {"opens_with": H(OBF_X25519_SK), "to": B(message),
                                 "length": 1 + 32 + keys.padded_length(n) + 16}}))

    # Opening (spec/keys.md, section 4.5).
    published = tx.SEALED
    assert hashlib.sha256(published).hexdigest() == "6be58e45f035eed7f4e3feb8fec0b59f00f74f93122015d22e6133bc65d187e7"
    other_sk = test_secret("cat-a-log, new phone, X25519")
    opens = [
        ("the sealed message of keys.md, section 7.4", published, [OBF_X25519_SK], MEMO_MSG, None),
        ("the sealed message with an earlier key after the current one", published, [other_sk, OBF_X25519_SK], MEMO_MSG, None),
        ("the sealed message with another key only", published, [other_sk], None, "NOT_OPENED"),
        ("a first byte other than 01", b"\x02" + published[1:], [OBF_X25519_SK], None, "NOT_OPENED"),
        ("one byte of the ciphertext changed", published[:-1] + bytes([published[-1] ^ 1]), [OBF_X25519_SK], None, "NOT_OPENED"),
        ("one byte of enc changed", published[:5] + bytes([published[5] ^ 1]) + published[6:], [OBF_X25519_SK], None, "NOT_OPENED"),
        ("an enc of small order, whose X25519 output is all zero", b"\x01" + bytes(32) + published[33:], [OBF_X25519_SK], None, "NOT_OPENED"),
        ("a plaintext without the byte 80", sealed(MEMO_MSG, OBF_X25519, "padding case 1", MEMO_MSG + bytes(841)),
         [OBF_X25519_SK], None, "PADDING_INVALID"),
        ("a plaintext with 80 followed by a byte other than zero",
         sealed(MEMO_MSG, OBF_X25519, "padding case 2", MEMO_MSG + b"\x80" + bytes(839) + b"\x01"), [OBF_X25519_SK], None, "PADDING_INVALID"),
        ("a plaintext of zero bytes only", sealed(MEMO_MSG, OBF_X25519, "padding case 3", bytes(1024)), [OBF_X25519_SK], None, "PADDING_INVALID"),
    ]
    for label, data, sks, message, error in opens:
        c.add("open", ("open " if error is None else "reject ") + label, ["keys.md 4.5"],
              {"sealed": B(data), "private_keys": [H(k) for k in sks]},
              accept({"message": B(message)}) if error is None else reject(error))
    return c


# --- the decoded meaning of an Avro value (spec/conformance.md, section 3.3) -------------


def raw_schema(t):
    return fastavro.parse_schema(pe.without_logical_types(t), _write_hint=False)


def meaning(t, value, names=None):
    """A decoded Avro value as JSON: bytes and fixed as hex, logical types as their underlying values."""
    names = {} if names is None else names
    if isinstance(t, str):
        if t in names:
            return meaning(names[t], value, names)
        if t == "bytes":
            return (value.encode("latin-1") if isinstance(value, str) else value).hex()  # fastavro 1.13.1 and bytes defaults
        return value
    if isinstance(t, list):
        if value is None:
            return None
        branches = [b for b in t if b != "null"]
        assert len(branches) == 1, "the vectors use only unions of null and one type"
        return meaning(branches[0], value, names)
    kind = t["type"]
    if kind in ("record", "enum", "fixed"):
        full = t["name"] if "." in t["name"] else ".".join(x for x in (t.get("namespace", names.get("", "")), t["name"]) if x)
        names[t["name"]] = names[full] = t
        if "namespace" in t:
            names[""] = t["namespace"]
    if kind == "record":
        return {f["name"]: meaning(f["type"], value[f["name"]], names) for f in t["fields"]}
    if kind == "fixed":
        return value.hex()
    if kind == "array":
        return [meaning(t["items"], v, names) for v in value]
    if kind == "map":
        return {k: meaning(t["values"], v, names) for k, v in value.items()}
    if kind == "enum":
        return value
    return meaning(kind, value, names)


def avro_encode(t, datum):
    buf = io.BytesIO()
    fastavro.schemaless_writer(buf, fastavro.parse_schema(t, _write_hint=False), datum)
    return buf.getvalue()


def single_object(text, datum):
    return b"\xc3\x01" + pe.fp8(pe.canonical_fp(text)) + avro_encode(json.loads(text), datum)


def decode_meaning(writer_text, reader_text, data):
    w = json.loads(writer_text)
    r = json.loads(reader_text) if reader_text else w
    value = fastavro.schemaless_reader(io.BytesIO(data), raw_schema(w), raw_schema(r))
    return meaning(r, value)


# --- encoding (spec/envelope.md) ----------------------------------------------------


def envelope(kind, sender, record, body, signature, fmt=1, fp=None):
    """A live message built field by field, without checks: for messages that break a rule."""
    zz = keys.zigzag
    kind_index = pe.KINDS.index(kind) if isinstance(kind, str) else kind
    out = b"\xc3\x01" + (ENVELOPE_FP if fp is None else fp) + zz(fmt) + zz(kind_index) + sender
    if record is None:
        out += zz(0)
    else:
        rid = record[0] if isinstance(record[0], bytes) else record[0].encode()
        out += zz(1) + zz(len(rid)) + rid + zz(record[1])
    return out + zz(len(body)) + body + signature


def signed(seed, kind, record, body, fmt=1, fp=None):
    m = envelope(kind, keys.public_key(seed), record, body, bytes(64), fmt, fp)
    return m[:-64] + keys.sign(seed, keys.MESSAGE_PREFIX + m[10:-64])


def message_meaning(m):
    d = fastavro.schemaless_reader(io.BytesIO(m[10:]), pe.raw["Envelope"], pe.raw["Envelope"])
    rec = d["record"]
    return {"format": d["format"], "kind": d["kind"], "sender": H(d["sender"]),
            "record": None if rec is None else {"id": rec["id"], "version": rec["version"]},
            "body": B(d["body"]), "signature": H(d["signature"])}


MAX_MESSAGE = pe.MAX_MESSAGE


def encoding_category():
    c = Category("encoding", "Fingerprints and canonical forms, and the envelope of every message in a live connection "
                             "(spec/envelope.md).")
    # Fingerprints: Avro's published cases, logical types, the schemas of the specification.
    for text, published in [('"null"', 7195948357588979594), ('"boolean"', -6970731678124411036), ('"int"', 8247732601305521295)]:
        fp = rules.crc64_avro(text.encode())
        assert fp - (1 << 64) * (fp >= 1 << 63) == published
        c.add("fingerprint", f"the published Avro fingerprint of {text}", ["envelope.md 5"],
              {"schema": text}, accept({"canonical_form": text, "fingerprint": H(fp.to_bytes(8, "little"))}))
    for text, pcf in [('{"type":"string","logicalType":"uuid"}', '"string"'),
                      ('{"type":"long","logicalType":"timestamp-millis"}', '"long"'),
                      ('{"type":"int","logicalType":"date"}', '"int"')]:
        got, fp = me.fingerprint(text)
        assert got == pcf
        c.add("fingerprint", f"a primitive with a logical type, {text}, is written as its primitive", ["envelope.md 5"],
              {"schema": text}, accept({"canonical_form": pcf, "fingerprint": H(pe.fp8(fp))}))
    memo_text = json.dumps(env.MEMO_SCHEMA)
    pcf, fp = me.fingerprint(memo_text)
    assert fp == 0xB71CE40C6856B368
    c.add("fingerprint", "com.example.Memo of envelope.md, section 10.1", ["envelope.md 5", "envelope.md 10.1"],
          {"schema": memo_text}, accept({"canonical_form": pcf, "fingerprint": H(pe.fp8(fp))}))
    published = {"Envelope": 0xA2E1E84FE5E40C7D, "Manifest": 0x6B08ECB5D38003B3, "KeyMove": 0xA9E20AFEA72F2876,
                 "Offer": 0x415463CACA7A687D, "Accept": 0x6B244FC3913D82AB, "Decline": 0x22D2BD11845492C0,
                 "Ack": 0xEE25C7CCA8166ED8, "Error": 0x36D44A6DF4E7DED4, "QrPayload": 0x6BBD68FE56640B90}
    sections = {"Envelope": "envelope.md 10.1", "Manifest": "manifest.md 9", "KeyMove": "keys.md 6", "QrPayload": "transports.md 6"}
    for name, want in published.items():
        text = (REPO / "types" / "axt" / f"{name}.avsc").read_text(encoding="utf-8")
        pcf, fp = me.fingerprint(text)
        assert fp == want, name
        c.add("fingerprint", f"axt.{name}, as types/axt/{name}.avsc holds it", ["envelope.md 5", sections.get(name, "protocol.md 16")],
              {"schema": text}, accept({"canonical_form": pcf, "fingerprint": H(pe.fp8(fp))}))

    # Decoding the envelope of a live message.
    upper = MEMO_MSG.replace(env.RECORD_ID.encode(), env.RECORD_ID.upper().encode())
    goods = [
        ("the DATA message of envelope.md, section 10.2", MEMO_MSG, ["envelope.md 10.2", "keys.md 7.2"]),
        ("the DATA message with its record id in upper case, kept as received", upper, ["envelope.md 7"]),
        ("the KEY_MOVE of keys.md, section 7.5", KM_MSG, ["keys.md 7.5"]),
        ("the MANIFEST of cat-a-log of manifest.md, section 10.3", pe.m1, ["manifest.md 10.3"]),
        ("the MANIFEST of Old Brain Fix of manifest.md, section 10.3", pe.m2, ["manifest.md 10.3"]),
        ("the OFFER of protocol.md, section 17.3", pe.offer_msg, ["protocol.md 17.3"]),
        ("the ACCEPT of protocol.md, section 17.4", pe.accept_msg, ["protocol.md 17.4"]),
        ("the DECLINE of protocol.md, section 17.4", pe.decline_msg, ["protocol.md 17.4"]),
        ("the DATA of protocol.md, section 17.5", pe.data_msg, ["protocol.md 17.5"]),
        ("the ACK of protocol.md, section 17.5", pe.ack_msg, ["protocol.md 17.5"]),
        ("the ERROR of protocol.md, section 17.6", pe.error_msg, ["protocol.md 17.6"]),
        ("a DELETE, with an empty body", pe.del_unknown, ["envelope.md 2.2"]),
    ]
    # A message of exactly 16 MiB is received; one byte more is not.
    head = envelope("DATA", CAT, (env.RECORD_ID, 1), b"", bytes(64))
    pad_len = MAX_MESSAGE - len(head)
    while len(envelope("DATA", CAT, (env.RECORD_ID, 1), bytes(pad_len), bytes(64))) > MAX_MESSAGE:
        pad_len -= 1
    at_limit = signed(CAT_SEED, "DATA", (env.RECORD_ID, 1), bytes(pad_len))
    assert len(at_limit) == MAX_MESSAGE
    above = signed(CAT_SEED, "DATA", (env.RECORD_ID, 1), bytes(pad_len + 1))
    assert len(above) == MAX_MESSAGE + 1
    goods.append(("a message of exactly 16 MiB", at_limit, ["envelope.md 8"]))
    for label, m, refs in goods:
        c.add("decode_message", label, ["envelope.md 2", "envelope.md 3"] + refs, {"message": B(m)}, accept(message_meaning(m)))

    m = MEMO_MSG
    sig = m[-64:]
    bads = [
        ("a message of 16 MiB and one byte", above, "TOO_LARGE", ["envelope.md 8"]),
        ("an envelope fingerprint of no format", m[:2] + bytes(8) + m[10:], "FORMAT_UNSUPPORTED", ["envelope.md 3.1"]),
        ("the fingerprint of axt.Manifest in place of the envelope's", m[:2] + pe.fp8(pe.fingerprints["Manifest"][1]) + m[10:],
         "FORMAT_UNSUPPORTED", ["envelope.md 3.1"]),
        ("no single-object marker", b"\xc3\x02" + m[2:], "INVALID_MESSAGE", ["envelope.md 3"]),
        ("fewer than 10 bytes", m[:9], "INVALID_MESSAGE", ["envelope.md 3"]),
        ("a byte left over after the envelope", m + b"\x00", "INVALID_MESSAGE", ["envelope.md 3"]),
        ("the last byte of the signature missing", m[:-1], "INVALID_MESSAGE", ["envelope.md 3"]),
        ("format 2 under the fingerprint of format 1", m[:10] + keys.zigzag(2) + m[11:], "INVALID_MESSAGE", ["envelope.md 2.1", "keys.md 2.2"]),
        ("kind index 9, which format 1 does not have", m[:11] + keys.zigzag(9) + m[12:], "INVALID_MESSAGE", ["envelope.md 2.2"]),
        ("a negative kind index", m[:11] + keys.zigzag(-1) + m[12:], "INVALID_MESSAGE", ["envelope.md 2.2"]),
        ("record union index 2", m[:0x2c] + keys.zigzag(2) + m[0x2d:], "INVALID_MESSAGE", ["envelope.md 2"]),
        ("a negative length of the record id", m[:0x2d] + keys.zigzag(-36) + m[0x2e:], "INVALID_MESSAGE", ["envelope.md 8"]),
        ("a negative length of the body", envelope("DATA", CAT, (env.RECORD_ID, 1), b"", sig)[:0x53] + keys.zigzag(-35) + m[0x54:],
         "INVALID_MESSAGE", ["envelope.md 8"]),
        ("a body length of 2^40, beyond the end", m[:0x53] + keys.zigzag(1 << 40) + m[0x54:], "INVALID_MESSAGE", ["envelope.md 8"]),
        ("a record id that is not UTF-8 (byte ff)", envelope("DATA", CAT, (b"\xff" + env.RECORD_ID.encode()[1:], 1), m[0x54:-64], sig),
         "INVALID_MESSAGE", ["envelope.md 7"]),
        ("a record id with an encoded surrogate (ed a0 80)", envelope("DATA", CAT, (b"\xed\xa0\x80" + env.RECORD_ID.encode()[3:], 1), m[0x54:-64], sig),
         "INVALID_MESSAGE", ["envelope.md 7"]),
        ("a record id with an overlong encoding (c0 af)", envelope("DATA", CAT, (b"\xc0\xaf" + env.RECORD_ID.encode()[2:], 1), m[0x54:-64], sig),
         "INVALID_MESSAGE", ["envelope.md 7"]),
    ]
    for label, msg, error, refs in bads:
        c.add("decode_message", f"reject {label}", refs, {"message": B(msg)}, reject(error))

    # The bodies of the kinds whose schema the specification publishes.
    for label, msg, refs in goods:
        d = fastavro.schemaless_reader(io.BytesIO(msg[10:]), pe.raw["Envelope"], pe.raw["Envelope"])
        if d["kind"] in ("DATA", "DELETE"):
            continue
        name = pe.BODY_SCHEMA[d["kind"]]
        body = d["body"]
        value = meaning(pe.jsons[name], fastavro.schemaless_reader(io.BytesIO(body[10:]), pe.raw[name], pe.raw[name]))
        c.add("decode_body", f"the body of {label}", ["envelope.md 2.3"] + refs, {"kind": d["kind"], "body": B(body)},
              accept({"value": value}))
    ack_body = fastavro.schemaless_reader(io.BytesIO(pe.ack_msg[10:]), pe.raw["Envelope"], pe.raw["Envelope"])["body"]
    outcome_at = ack_body.index(bytes.fromhex("0200"), 10 + 32 + 1 + 1 + 36) + 1  # version 1, then outcome APPLIED
    assert ack_body[outcome_at] == 0
    for label, kind, body in [
        ("an ACK body with a byte left over", "ACK", ack_body + b"\x00"),
        ("an ACK body cut short", "ACK", ack_body[:-1]),
        ("an ACK body with the fingerprint of axt.Error", "ACK", ack_body[:2] + pe.fp8(pe.fingerprints["Error"][1]) + ack_body[10:]),
        ("an ACK body with an outcome index of 5", "ACK", ack_body[:outcome_at] + keys.zigzag(5) + ack_body[outcome_at + 1:]),
        ("an empty body for an ACK", "ACK", b""),
        ("a MANIFEST body of the KEY_MOVE schema", "MANIFEST",
         fastavro.schemaless_reader(io.BytesIO(KM_MSG[10:]), pe.raw["Envelope"], pe.raw["Envelope"])["body"]),
    ]:
        c.add("decode_body", f"reject {label}", ["envelope.md 2.3", "envelope.md 3.1", "protocol.md 8.2"],
              {"kind": kind, "body": B(body)}, reject("INVALID_MESSAGE"))

    for label, msg in [("the DATA message of envelope.md, section 10.2", MEMO_MSG),
                       ("the DATA message with its record id in upper case", upper),
                       ("the KEY_MOVE of keys.md, section 7.5", KM_MSG),
                       ("the MANIFEST of cat-a-log of manifest.md, section 10.3", pe.m1),
                       ("a DELETE, with an empty body", pe.del_unknown)]:
        d = message_meaning(msg)
        c.add("encode_message", label, ["envelope.md 2", "envelope.md 3"], d, accept({"message": B(msg)}))
    return c


# --- types (spec/types.md) -------------------------------------------------------------

EXAMPLES = REPO / "types" / "axt" / "example" / "v1"
TYPE_FPS = {"Appointment": 0x1B57DE39E9441B59, "Car": 0x7277E2001E503F8B, "Document": 0x4EA7ED4FB856C4D3,
            "Measurement": 0xCBC0764900436ED4, "Note": 0x627AB0D4D84FB306, "Person": 0x2BEDD25E9E4558F1,
            "Pet": 0x2D9F89A71269EB61, "Task": 0x88AE7A18288CA463}


def types_category():
    c = Category("types", "The example types: fingerprints, the bytes and meaning of a record of each, and schema "
                          "resolution with defaults, unknown symbols, aliases and the data depth limit (spec/types.md).")
    texts = {}
    for name, want in TYPE_FPS.items():
        path = EXAMPLES / f"{name}.1.avsc"
        text = path.read_text(encoding="utf-8")
        texts[name] = pe.compact(path)
        pcf, fp = me.fingerprint(text)
        assert fp == want and pe.canonical_fp(texts[name]) == want, name
        c.add("fingerprint", f"axt.example.v1.{name}, version 1", ["types.md 3.4", "types.md 7.3"],
              {"schema": text}, accept({"canonical_form": pcf, "fingerprint": H(pe.fp8(fp))}))

    def record_vector(label, refs, writer_text, reader_text, data, expected=None):
        if expected is None:
            expected = accept({"value": decode_meaning(writer_text, reader_text, data[10:])})
        c.add("decode_record", label, refs, {"writer_schema": writer_text, "reader_schema": reader_text, "body": B(data)}, expected)

    for name in TYPE_FPS:
        schema = json.loads(texts[name])
        datum = rules.DATA[name]
        body = single_object(texts[name], datum)
        value = decode_meaning(texts[name], None, body[10:])
        record_vector(f"a record of axt.example.v1.{name}", ["types.md 7", "envelope.md 2.3"], texts[name], None, body)
        # Every default, through schema resolution (spec/types.md, section 5.4).
        reduced = rules.without_defaults(schema)
        if reduced["fields"] != schema["fields"]:
            wtext = json.dumps(reduced, separators=(",", ":"), ensure_ascii=False)
            record_vector(f"axt.example.v1.{name} written without its fields that have a default, read with every default",
                          ["types.md 5.4", "envelope.md 6"], wtext, texts[name], single_object(wtext, rules.project(schema, datum)))
        nested = [f for f in schema["fields"] if isinstance(f["type"], dict) and f["type"]["type"] == "array"
                  and isinstance(f["type"]["items"], dict) and f["type"]["items"]["type"] == "record"]
        if nested:
            ndatum = dict(datum, **{f["name"]: datum[f["name"]][:1] for f in nested})
            wtext = json.dumps(rules.without_defaults(schema, nested_only=True), separators=(",", ":"), ensure_ascii=False)
            record_vector(f"axt.example.v1.{name} written without the defaulted fields of its nested records",
                          ["types.md 5.4", "envelope.md 6"], wtext, texts[name],
                          single_object(wtext, rules.project(schema, ndatum, nested_only=True)))
        for i, f in enumerate(schema["fields"]):
            if isinstance(f["type"], dict) and f["type"]["type"] == "enum":
                writer = copy.deepcopy(schema)
                writer["fields"][i]["type"]["symbols"].append("SYMBOL_OF_A_LATER_VERSION")
                wtext = json.dumps(writer, separators=(",", ":"), ensure_ascii=False)
                data = single_object(wtext, dict(datum, **{f["name"]: "SYMBOL_OF_A_LATER_VERSION"}))
                got = decode_meaning(wtext, texts[name], data[10:])
                assert got[f["name"]] == f["type"]["default"]
                record_vector(f"axt.example.v1.{name}: an unknown symbol of {f['name']} reads as the default {f['type']['default']}",
                              ["types.md 5.4", "envelope.md 6"], wtext, texts[name], data)

    ap_text, ap = texts["Appointment"], rules.DATA["Appointment"]
    ap_body = single_object(ap_text, ap)
    # The reminders in two array blocks, the first with a negative count and its size (Avro 1.12, Arrays).
    one_block = keys.zigzag(2) + keys.zigzag(1440) + keys.zigzag(60) + keys.zigzag(0)
    assert ap_body.count(one_block) == 1
    blocks = keys.zigzag(-1) + keys.zigzag(2) + keys.zigzag(1440) + keys.zigzag(1) + keys.zigzag(60) + keys.zigzag(0)
    record_vector("axt.example.v1.Appointment with its reminders in two array blocks, one with a negative count",
                  ["envelope.md 1"], ap_text, None, ap_body.replace(one_block, blocks),
                  accept({"value": decode_meaning(ap_text, None, ap_body[10:])}))
    title = ap["title"].encode()
    bads = [
        ("a byte left over after the record", ap_body + b"\x00", "UNDECODABLE", ["types.md 5.7", "protocol.md 6.2"]),
        ("the last byte missing", ap_body[:-1], "UNDECODABLE", ["protocol.md 6.2"]),
        ("a title that is not UTF-8", ap_body.replace(title, b"\xff" + title[1:]), "UNDECODABLE", ["envelope.md 7"]),
        ("a title with an encoded surrogate", ap_body.replace(title, b"\xed\xb0\x80" + title[3:]), "UNDECODABLE", ["envelope.md 7"]),
        ("a negative string length", ap_body[:10] + keys.zigzag(-16) + ap_body[11:], "UNDECODABLE", ["envelope.md 8"]),
        ("a string length beyond the end", ap_body[:10] + keys.zigzag(1 << 40) + ap_body[11:], "UNDECODABLE", ["envelope.md 8"]),
        ("an array count of 2^40 beyond the end", ap_body.replace(one_block, keys.zigzag(1 << 40) + one_block[1:]),
         "UNDECODABLE", ["envelope.md 8"]),
        ("a body whose fingerprint is not that of the writer schema", ap_body[:2] + pe.fp8(TYPE_FPS["Task"]) + ap_body[10:],
         "SCHEMA_UNKNOWN", ["envelope.md 3.1"]),
    ]
    for label, data, error, refs in bads:
        record_vector(f"reject axt.example.v1.Appointment with {label}", refs, ap_text, None, data, reject(error))

    # Resolution by name: aliases, other names, fields without a default.
    pet = json.loads(texts["Pet"])
    app_pet = dict(pet, namespace="org.example.catalog")
    app_text = json.dumps(app_pet, separators=(",", ":"), ensure_ascii=False)
    pet_body = single_object(app_text, rules.DATA["Pet"])
    alias_reader = json.dumps(dict(pet, aliases=["org.example.catalog.Pet"]), separators=(",", ":"), ensure_ascii=False)
    record_vector("an app type read as axt.example.v1.Pet through an alias of the reader schema", ["types.md 4", "envelope.md 6"],
                  app_text, alias_reader, pet_body)
    record_vector("reject an app type of the same fields under another name, without an alias", ["types.md 4", "envelope.md 6"],
                  app_text, texts["Pet"], pet_body, reject("DOES_NOT_RESOLVE"))
    narrow = json.loads(ap_text)
    narrow["fields"].append({"name": "room", "type": "string", "doc": "A field without a default that the writer lacks."})
    record_vector("reject a reader schema with a field that has no default and that the writer lacks", ["envelope.md 6"],
                  ap_text, json.dumps(narrow, separators=(",", ":"), ensure_ascii=False), ap_body, reject("DOES_NOT_RESOLVE"))
    wider = json.loads(texts["Pet"])
    wider["fields"].append({"name": "colour", "type": "string", "default": "", "doc": "A field the reader does not have."})
    wtext = json.dumps(wider, separators=(",", ":"), ensure_ascii=False)
    record_vector("a writer field the reader does not have is ignored", ["envelope.md 6", "types.md 3.3"],
                  wtext, texts["Pet"], single_object(wtext, dict(rules.DATA["Pet"], colour="tabby")))

    # The data depth limit, with a recursive app type read with its writer schema alone (spec/types.md, section 5.7).
    for levels, ok in [(16, True), (17, False)]:
        datum = pe.outline(levels)
        depth = pe.data_depth(datum)
        data = single_object(pe.OUTLINE_TEXT, datum)
        record_vector(f"a recursive app type at data depth {depth}", ["types.md 5.7"], pe.OUTLINE_TEXT, None, data,
                      None if ok else reject("UNDECODABLE", f"data depth {depth} above 32"))
    return c


# --- manifest (spec/manifest.md) --------------------------------------------------------


def manifest_meaning(body):
    return meaning(me.manifest_json, fastavro.schemaless_reader(io.BytesIO(body[10:]), pe.raw["Manifest"], pe.raw["Manifest"]))


def manifest_category():
    c = Category("manifest", "The validity and limits of a manifest, and which types fit it, with the language of "
                             "the purpose sentence shown (spec/manifest.md).")
    goods = [
        ("the manifest of cat-a-log of manifest.md, section 10.1", me.CAT_A_LOG),
        ("the manifest of Old Brain Fix of manifest.md, section 10.1", me.OLD_BRAIN_FIX),
        ("Old Brain Fix with an encryption key and a relay", dict(me.OLD_BRAIN_FIX, encryption_key=me.X25519_KEY, relay=me.RELAY)),
        ("a relay URL of 256 bytes", dict(me.OLD_BRAIN_FIX, encryption_key=me.X25519_KEY,
                                          relay=dict(me.RELAY, url="https://relay.example.org/" + "a" * 229 + "/"))),
        ("a manifest that takes nothing", dict(me.CAT_A_LOG, takes=[], sends=None)),
        ("a translation under en-GB", me.broken(lambda d: d["takes"][0]["purpose_translations"].update({"en-GB": "An Appointment becomes a Reminder."}))),
    ]
    for label, datum in goods:
        body = me.encode_body(datum)
        assert not me.manifest_problems(datum, len(body)), label
        c.add("check_manifest", label, ["manifest.md 3", "manifest.md 4"], {"body": B(body), "envelope_format": 1},
              accept({"manifest": manifest_meaning(body)}))
    assert len(me.NEGATIVE) == 43, "spec/manifest.md, section 9, names 43 invalid manifests"
    for label, change, rule in me.NEGATIVE:
        datum = me.broken(change)
        body = me.encode_body(datum)
        problems = me.manifest_problems(datum, len(body))
        assert problems and all(rule in p for p in problems), label
        c.add("check_manifest", f"reject {label}", ["manifest.md 4"], {"body": B(body), "envelope_format": 1},
              reject("MANIFEST_INVALID", problems[0]))
    body = me.encode_body(me.CAT_A_LOG)
    for label, data in [("a byte left over after the manifest", body + b"\x00"), ("the last byte missing", body[:-1]),
                        ("the fingerprint of another schema", body[:2] + ENVELOPE_FP + body[10:])]:
        c.add("check_manifest", f"reject a body with {label}", ["manifest.md 2", "protocol.md 8.2"],
              {"body": B(data), "envelope_format": 1}, reject("INVALID_MESSAGE"))

    def fit_vector(label, refs, manifest, schema_text, languages, entry):
        body = me.encode_body(manifest)
        schema = json.loads(schema_text)
        got = me.fit(manifest, pe.full_name(schema), me.schema_version(schema))
        assert got is entry, label
        c.add("fit", label, refs, {"manifest": B(body), "schema": schema_text, "languages": languages},
              accept({"fits": entry is not None, "purpose": None if entry is None else me.sentence(entry, languages)}))

    obf, cat = me.OLD_BRAIN_FIX, me.CAT_A_LOG
    texts = {n: pe.compact(EXAMPLES / f"{n}.1.avsc") for n in ("Pet", "Appointment", "Measurement", "Document", "Note", "Task")}
    memo_text = json.dumps(env.MEMO_SCHEMA)
    for name, entry in [("Pet", obf["any_type"]), ("Appointment", obf["takes"][0]), ("Measurement", obf["any_type"]),
                        ("Document", obf["any_type"])]:
        fit_vector(f"cat-a-log offers {name} to Old Brain Fix, for a user who reads de-AT", ["manifest.md 5.2", "manifest.md 3.6", "manifest.md 10.2"],
                   obf, texts[name], ["de-AT"], entry)
    fit_vector("the Appointment for a user who reads fr-CH and fr: the English sentence", ["manifest.md 3.6", "manifest.md 10.2"],
               obf, texts["Appointment"], ["fr-CH", "fr"], obf["takes"][0])
    fit_vector("the Appointment for a user who reads DE, in upper case", ["manifest.md 3.6"], obf, texts["Appointment"], ["DE"], obf["takes"][0])
    fit_vector("the Appointment for a user with no language: the English sentence", ["manifest.md 3.6"], obf, texts["Appointment"], [], obf["takes"][0])
    fit_vector("the Appointment for a user who reads en-GB: the English sentence", ["manifest.md 3.6"], obf, texts["Appointment"], ["en-GB"], obf["takes"][0])
    regional = me.broken(lambda d: d["takes"][0]["purpose_translations"].update({"de-CH": "Ein Termin wird zur Erinnerung."}))
    fit_vector("a user who reads de-CH-1996 gets the de-CH sentence", ["manifest.md 3.6"], regional, texts["Appointment"],
               ["de-CH-1996"], regional["takes"][0])
    fit_vector("a Note does not fit cat-a-log, which takes no other type", ["manifest.md 5.2", "manifest.md 10.2"],
               cat, texts["Note"], ["en"], None)
    fit_vector("a Pet fits cat-a-log by its entry", ["manifest.md 5.2", "manifest.md 10.2"], cat, texts["Pet"], ["en"], cat["takes"][0])
    fit_vector("com.example.Memo, without axt.version, fits Old Brain Fix's any type", ["manifest.md 3.4", "manifest.md 10.2"],
               obf, memo_text, ["en"], obf["any_type"])
    fit_vector("com.example.Memo does not fit cat-a-log", ["manifest.md 5.2", "manifest.md 10.2"], cat, memo_text, ["en"], None)
    narrowed = me.broken(lambda d: d["takes"][0].update(min_version=2))
    fit_vector("an Appointment of version 1 does not fit min_version 2, although the manifest takes any type",
               ["manifest.md 3.5", "manifest.md 5.2", "manifest.md 10.2"], narrowed, texts["Appointment"], ["en"], None)
    for label, version in [("the string \"2\"", "2"), ("0", 0)]:
        t = json.dumps(dict(json.loads(texts["Appointment"]), **{"axt.version": version}), separators=(",", ":"), ensure_ascii=False)
        fit_vector(f"a schema whose axt.version is {label} counts as version 1", ["manifest.md 3.4"], narrowed, t, ["en"], None)
    capped = me.broken(lambda d: d["takes"][0].update(max_version=1))
    v2 = json.dumps(dict(json.loads(texts["Appointment"]), **{"axt.version": 2}), separators=(",", ":"), ensure_ascii=False)
    fit_vector("version 2 does not fit max_version 1", ["manifest.md 3.3", "manifest.md 5.2"], capped, v2, ["en"], None)
    fit_vector("version 1 fits max_version 1", ["manifest.md 3.3", "manifest.md 5.2"], capped, texts["Appointment"], ["en"], capped["takes"][0])
    renamed = json.dumps(dict(json.loads(texts["Appointment"]), namespace="org.example.calendar"), separators=(",", ":"), ensure_ascii=False)
    fit_vector("an app type with the fields of an Appointment fits by its own name only", ["manifest.md 3.3", "types.md 4"],
               cat, renamed, ["en"], None)
    return c


# --- protocol (spec/protocol.md) ---------------------------------------------------------


def decode_reply(m):
    d = fastavro.schemaless_reader(io.BytesIO(m[10:]), pe.raw["Envelope"], pe.raw["Envelope"])
    name = pe.BODY_SCHEMA[d["kind"]]
    return d["kind"], fastavro.schemaless_reader(io.BytesIO(d["body"][10:]), pe.raw[name], pe.raw[name])


def normalize_replies(replies):
    """The answers and errors of the replies to one message (spec/conformance.md, section 5.6)."""
    answers, errors = {}, []
    for m in replies:
        kind, b = decode_reply(m)
        if kind in ("ACCEPT", "DECLINE"):
            for t in b["types"]:
                name, verdict = (t, "ACCEPT") if kind == "ACCEPT" else (t["type"], t["reason"])
                answers.setdefault(b["offer_id"], {})[name] = verdict
        elif kind == "ERROR":
            errors.append({"code": b["code"], "message_hash": H(b["message_hash"]), "record": b["record"],
                           "fingerprint": None if b["fingerprint"] is None else H(b["fingerprint"])})
        else:
            raise AssertionError(f"a reply of kind {kind}")
    return answers, errors


def session_config(seed, manifest, readers, takes, peer):
    return {"seed": H(seed), "manifest": B(me.encode_body(manifest)), "formats": [1],
            "readers": {n: json.dumps(r, separators=(",", ":"), ensure_ascii=False) for n, r in readers.items()},
            "user_takes": sorted(takes), "peer": H(peer)}


def run_session(c, label, refs, seed, manifest, readers, takes, peer, steps):
    """Play the steps against a fresh model app of protocol_examples.py; the result of each step is the
    expected one. Each step names what the script itself expects, and the model's result must match it."""
    app = pe.App("app", seed, manifest, readers, lambda n: n in takes)
    inputs, expected = [], []
    for step in steps:
        kind = step[0]
        if kind == "receive":
            _, m, want = step[:3]
            opts = step[3] if len(step) > 3 else {}
            what, replies = app.receive(m)
            answers, errors = normalize_replies(replies)
            outcome = what if what in ("APPLIED", "DUPLICATE", "STALE") else None
            close = what == "no common format: close"
            if want in ("APPLIED", "DUPLICATE", "STALE"):
                assert what == want, (label, what, want)
            elif want == "taken":
                assert not replies and (what.endswith("taken") or what in ("acknowledged",) or what.startswith("error ")), (label, what)
            elif want == "ignored":
                assert not replies and (what.startswith("ignored") or what.endswith("not reported")), (label, what)
            elif want == "answers":
                assert answers == opts["answers"] and not errors, (label, answers)
            elif want.startswith("ERROR "):
                assert what == "rejected " + want[6:] and len(errors) == 1 and errors[0]["code"] == want[6:], (label, what)
                if opts.get("record_ambiguous"):
                    del errors[0]["record"]
            else:
                raise ValueError(want)
            if opts.get("may_close"):
                # spec/protocol.md, section 8.3: the app MAY close the connection after this; nothing follows it.
                assert step is steps[-1], (label, "a step after which the app may close must be the last")
                close = one_of(False, True)
            inputs.append({"receive": B(m)})
            expected.append({"outcome": outcome, "close": close, "answers": answers, "errors": errors})
        elif kind == "flush":
            ack = app.ack()
            records = [] if ack is None else decode_reply(ack)[1]["records"]
            if len(step) > 1:
                assert records == step[1], (label, records)
            inputs.append({"flush_acks": True})
            expected.append({"acks": records})
        elif kind == "offer":
            _, offer_id, types = step
            app.offer(offer_id, [(t, n, None) for t, n in types])
            inputs.append({"offer": {"offer_id": offer_id, "types": [{"schema": t, "count": n} for t, n in types]}})
            expected.append({"offer": {"to": H(app.peer), "offer_id": offer_id,
                                       "types": [{"schema": t, "count": n} for t, n in types]}})
        elif kind == "close":
            app.close()
            inputs.append({"close": True})
            expected.append({})
        elif kind == "query":
            _, what, arg, want = step
            if what == "accepted":
                got = {"accepted": app.accepted(arg)}
            elif what == "outcome":
                got = {"outcome": app.outcomes.get((arg[0].lower(), arg[1]))}
            elif what == "record":
                r = app.records.get(arg.lower())
                got = {"record": None if r is None else {"version": r["version"], "state": r["state"]}}
            elif what == "errors":
                got = {"errors": list(app.errors)}
            assert got == want, (label, what, got, want)
            inputs.append({"query": {what: arg if not isinstance(arg, tuple) else {"id": arg[0], "version": arg[1]}}})
            expected.append(got)
    c.add("session", label, refs, {"app": session_config(seed, manifest, readers, takes, peer), "steps": inputs},
          {"steps": expected})


def protocol_category():
    c = Category("protocol", "The steps of an exchange in a live connection, played against one app: manifests, "
                             "offers, answers, record messages, acknowledgements and errors (spec/protocol.md).")
    assert len(pe.checks) == 58, "spec/protocol.md, section 16, names 58 cases besides the exchange"
    for label, own, theirs, want in [("the highest common format", [1, 2], [2, 3], 2), ("no common format", [1], [2], None),
                                     ("format 1 between two apps of 0.1.0", [1], [1], 1)]:
        assert pe.choose_format(own, theirs) == want
        c.add("choose_format", label, ["protocol.md 3.2"], {"own": own, "theirs": theirs}, accept({"format": want}))

    A, T, P_, N = "axt.example.v1.Appointment", "axt.example.v1.Task", "axt.example.v1.Pet", "axt.example.v1.Note"
    OUT = "org.example.outline.Outline"
    AID, PID, OID = pe.APPOINTMENT_ID, pe.PET_ID, pe.OFFER_ID
    ap, ap_text = pe.APPOINTMENT, pe.APPOINTMENT_TEXT
    obf_readers = {A: pe.APPOINTMENT_READER}
    obf_takes = {A, T, OUT}
    nil_id, del_id = "00000000-0000-0000-0000-000000000000", "d4c3b2a1-0f9e-4d8c-b7a6-5f4e3d2c1b0a"
    note_id = "c1d2e3f4-a5b6-4c7d-8e9f-0a1b2c3d4e5f"
    oversized = pe.data_msg + bytes(pe.MAX_MESSAGE)
    bad_offer = lambda types, oid="4a5b6c7d-8e9f-4a0b-9c1d-2e3f4a5b6c7d": pe.cat_app.reply("OFFER", {"to": OBF, "offer_id": oid, "types": types})
    ambiguous = {"record_ambiguous": True}
    may_close = {"may_close": True}
    r = lambda m, want, **o: ("receive", m, want, o)

    obf_steps = [
        r(pe.m1, "taken"),
        r(pe.offer_msg, "answers", answers={OID: {A: "ACCEPT", P_: "NOT_WANTED"}}),
        r(pe.data_msg, "APPLIED"),
        ("flush", [{"id": AID, "version": 1, "outcome": "APPLIED", "receiver_version": 1, "kept_fields": []}]),
        r(pe.pet_msg, "ERROR NOT_ACCEPTED"),
        r(pe.offer_msg, "answers", answers={OID: {A: "ACCEPT", P_: "NOT_WANTED"}}),
        r(pe.data_msg, "DUPLICATE"),
        ("flush", [{"id": AID, "version": 1, "outcome": "DUPLICATE", "receiver_version": 1, "kept_fields": []}]),
        r(pe.m1, "taken"),
        r(pe.fwd, "ignored"),
        r(pe.obf_data(AID, 0, ap_text, ap), "ERROR VERSION_INVALID"),
        r(pe.obf_data(nil_id, 1, ap_text, ap), "ERROR RECORD_ID_INVALID"),
        r(pe.obf_data("vet-appointment", 1, ap_text, ap), "ERROR RECORD_ID_INVALID"),
        r(pe.obf_data(note_id, 1, pe.NOTE_TEXT, rules.DATA["Note"]), "ERROR SCHEMA_UNKNOWN"),
        r(pe.upper, "APPLIED"),
        ("query", "record", AID, {"record": {"version": 2, "state": "there"}}),
        r(pe.data_msg, "STALE"),
        ("flush", [{"id": AID.upper(), "version": 2, "outcome": "APPLIED", "receiver_version": 2, "kept_fields": []},
                   {"id": AID, "version": 1, "outcome": "STALE", "receiver_version": 2, "kept_fields": []}]),
        r(pe.extra, "ERROR UNDECODABLE"),
        r(pe.short, "ERROR UNDECODABLE"),
        r(pe.data_msg[:2] + bytes(8) + pe.data_msg[10:], "ERROR FORMAT_UNSUPPORTED"),
        r(pe.del_unknown, "APPLIED"),
        ("query", "record", del_id, {"record": {"version": 4, "state": "tombstone"}}),
        r(pe.task_offer, "answers", answers={"0c9b8a7f-6e5d-4c3b-a291-8f7e6d5c4b3a": {T: "ACCEPT"}}),
        r(pe.obf_data(AID, 9, pe.TASK_TEXT, rules.DATA["Task"]), "ERROR TYPE_CHANGED"),
        r(pe.outline_offer, "answers", answers={"1d2e3f40-5a6b-4c7d-9e8f-a0b1c2d3e4f5": {OUT: "ACCEPT"}}),
        r(pe.obf_data("2e3f4051-6b7c-4d8e-8f90-b1c2d3e4f506", 1, pe.OUTLINE_TEXT, pe.outline(16)), "APPLIED"),
        r(pe.obf_data("3f405162-7c8d-4e9f-90a1-c2d3e4f50617", 1, pe.OUTLINE_TEXT, pe.outline(17)), "ERROR UNDECODABLE"),
        r(bad_offer([]), "ERROR OFFER_INVALID"),
        r(bad_offer([{"schema": pe.PET_TEXT, "count": 0}] * 2), "ERROR OFFER_INVALID"),
        r(bad_offer([{"schema": pe.PET_TEXT, "count": 0}], oid="offer-1"), "ERROR OFFER_INVALID"),
        r(bad_offer([{"schema": '{"type":"enum","name":"E","symbols":["A"]}', "count": 0}]), "ERROR OFFER_INVALID"),
        ("flush", [{"id": del_id, "version": 4, "outcome": "APPLIED", "receiver_version": 4, "kept_fields": []},
                   {"id": "2e3f4051-6b7c-4d8e-8f90-b1c2d3e4f506", "version": 1, "outcome": "APPLIED", "receiver_version": 1,
                    "kept_fields": []}]),
        ("close",),
        r(pe.m1, "taken"),
        r(pe.obf_data(AID, 10, ap_text, ap), "ERROR SCHEMA_UNKNOWN"),
    ]
    run_session(c, "Old Brain Fix receives the exchange of protocol.md, section 17, its repeats and the messages it rejects",
                ["protocol.md 3.1", "protocol.md 5.2", "protocol.md 6.2", "protocol.md 7", "protocol.md 8", "protocol.md 9.2",
                 "protocol.md 17"], OBF_SEED, me.OLD_BRAIN_FIX, obf_readers, obf_takes, CAT, obf_steps)
    # The rejections after which an app MAY close the connection (spec/protocol.md, section 8.3), each last in a session.
    for label, m, want, opts in [
        ("a signature that does not verify", pe.bad_sig, "ERROR SIGNATURE_INVALID", {}),
        ("bytes left over after the envelope", pe.data_msg + b"\x00", "ERROR INVALID_MESSAGE", {}),
        ("a format field that is not the envelope's format", pe.fmt2, "ERROR INVALID_MESSAGE", ambiguous),
        ("a message above 16 MiB", oversized, "ERROR TOO_LARGE", {}),
        ("a DELETE with a body", pe.del_body, "ERROR INVALID_MESSAGE", ambiguous),
        ("an offer with a schema above 256 KiB", bad_offer([{"schema": pe.big_doc, "count": 0}]), "ERROR TOO_LARGE", {}),
    ]:
        run_session(c, f"Old Brain Fix reports {label}, and may close the connection", ["protocol.md 8.2", "protocol.md 8.3"],
                    OBF_SEED, me.OLD_BRAIN_FIX, obf_readers, obf_takes, CAT, [r(pe.m1, "taken"), r(m, want, **opts, **may_close)])

    cat_steps = [
        r(pe.m2, "taken"),
        ("offer", OID, [(pe.PET_TEXT, 1), (ap_text, 1)]),
        r(pe.accept_msg, "taken"), r(pe.decline_msg, "taken"),
        ("query", "accepted", A, {"accepted": True}), ("query", "accepted", P_, {"accepted": False}),
        r(pe.ack_msg, "taken"), ("query", "outcome", (AID, 1), {"outcome": "APPLIED"}),
        r(pe.error_msg, "taken"), ("query", "errors", True, {"errors": ["NOT_ACCEPTED"]}),
        r(pe.accept_msg, "taken"),
        r(pe.ack_msg, "taken"), ("query", "outcome", (AID, 1), {"outcome": "APPLIED"}),
        r(pe.dup_ack, "taken"), ("query", "outcome", (AID, 1), {"outcome": "APPLIED"}),
        r(pe.obf_app.reply("ERROR", {"to": CAT, "code": "UNDECODABLE", "message_hash": bytes(32),
                                     "record": {"id": AID, "version": 1}, "fingerprint": None, "detail": ""}), "ignored"),
        ("query", "errors", True, {"errors": ["NOT_ACCEPTED"]}),
        r(pe.late_accept, "taken"), ("query", "accepted", P_, {"accepted": False}),
        r(pe.obf_app.reply("ACCEPT", {"to": pe.OTHER, "offer_id": OID, "types": [A]}), "ignored"),
        r(pe.obf_app.reply("ACCEPT", {"to": CAT, "offer_id": PID, "types": [P_]}), "ignored"),
        r(pe.key_move_ack, "taken"),
    ]
    run_session(c, "cat-a-log offers, takes the answers and acknowledgements, and ignores what is not for it",
                ["protocol.md 4", "protocol.md 5.3", "protocol.md 7.1", "protocol.md 7.4", "protocol.md 8.3", "protocol.md 9",
                 "protocol.md 17"], CAT_SEED, me.CAT_A_LOG, {}, set(), OBF, cat_steps)
    offered = [r(pe.m2, "taken"), ("offer", OID, [(pe.PET_TEXT, 1), (ap_text, 1)])]
    run_session(c, "cat-a-log reports an ACCEPT naming a type the offer does not have, and may close the connection",
                ["protocol.md 5.3", "protocol.md 8.3"], CAT_SEED, me.CAT_A_LOG, {}, set(), OBF, offered + [
                    r(pe.obf_app.reply("ACCEPT", {"to": CAT, "offer_id": OID, "types": [N]}), "ERROR INVALID_MESSAGE", **may_close)])
    for label, entries in pe.invalid_acks:
        run_session(c, f"cat-a-log reports {label}, and may close the connection", ["protocol.md 7.1", "protocol.md 8.3"],
                    CAT_SEED, me.CAT_A_LOG, {}, set(), OBF, offered + [
                        r(pe.obf_app.reply("ACK", {"to": CAT, "records": entries, "moved_from": None}), "ERROR INVALID_MESSAGE", **may_close)])
    run_session(c, "an ERROR that cannot be processed is not answered with an ERROR", ["protocol.md 8.3"],
                CAT_SEED, me.CAT_A_LOG, {}, set(), OBF, [r(pe.m2, "taken"), r(pe.broken_error, "ignored", **may_close)])

    run_session(c, "an offer whose schema does not resolve against the reader schema is declined", ["protocol.md 5.2", "envelope.md 6"],
                OBF_SEED, me.OLD_BRAIN_FIX, {A: pe.narrow_reader}, {A}, CAT, [
                    r(pe.m1, "taken"),
                    r(pe.cat_app.reply("OFFER", {"to": OBF, "offer_id": "5b6c7d8e-9f0a-4b1c-8d2e-3f4a5b6c7d8e",
                                                 "types": [{"schema": ap_text, "count": 1}]}), "answers",
                      answers={"5b6c7d8e-9f0a-4b1c-8d2e-3f4a5b6c7d8e": {A: "DOES_NOT_RESOLVE"}})])
    run_session(c, "an offer of a type that does not fit the receiver's manifest is declined, whatever its user wants",
                ["protocol.md 5.2", "manifest.md 5.4"], CAT_SEED, me.CAT_A_LOG, {}, {N}, OBF, [
                    r(pe.m2, "taken"),
                    r(pe.obf_app.reply("OFFER", {"to": CAT, "offer_id": "6c7d8e9f-0a1b-4c2d-9e3f-4a5b6c7d8e9f",
                                                 "types": [{"schema": pe.NOTE_TEXT, "count": 1}]}), "answers",
                      answers={"6c7d8e9f-0a1b-4c2d-9e3f-4a5b6c7d8e9f": {N: "DOES_NOT_FIT"}})])
    run_session(c, "the first messages: an OFFER before the MANIFEST, an invalid MANIFEST, a MANIFEST with a record",
                ["protocol.md 2", "protocol.md 3.1", "protocol.md 8.3", "manifest.md 4"], OBF_SEED, me.OLD_BRAIN_FIX, {}, {A}, CAT, [
                    r(pe.offer_msg, "ignored"),
                    r(pe.bad_manifest, "ERROR MANIFEST_INVALID"),
                    r(pe.make_message("MANIFEST", CAT_SEED, (AID, 1), pe.header("Manifest") + [(me.encode_body(me.CAT_A_LOG)[10:], "")],
                                      check=False)[1], "ERROR INVALID_MESSAGE", **ambiguous, **may_close)])
    run_session(c, "a DELETE without any accepted offer", ["protocol.md 6.2"], OBF_SEED, me.OLD_BRAIN_FIX, {}, {A}, CAT, [
        r(pe.m1, "taken"), r(pe.del_unknown, "ERROR NOT_ACCEPTED")])
    for first, second, stands in [("KEPT", "APPLIED", "APPLIED"), ("APPLIED", "KEPT", "APPLIED"),
                                  ("DUPLICATE", "MERGED", "MERGED"), ("MERGED", "DUPLICATE", "MERGED")]:
        acks = [pe.obf_app.reply("ACK", {"to": CAT, "records": [{"id": AID, "version": 4, "outcome": o, "receiver_version": 4,
                                                                  "kept_fields": ["location"] if o == "MERGED" else []}],
                                         "moved_from": None}) for o in (first, second)]
        run_session(c, f"{stands} stands after {first} then {second}", ["protocol.md 7.3", "protocol.md 7.4"],
                    CAT_SEED, me.CAT_A_LOG, {}, set(), OBF,
                    [r(pe.m2, "taken"), r(acks[0], "taken"), r(acks[1], "taken"),
                     ("query", "outcome", (AID, 4), {"outcome": stands})])
    return c


# --- QR code (spec/transports.md, section 3) -----------------------------------------------


def one_of(*values):
    """An expected value that a library may meet in more than one way, where the specification leaves the choice."""
    return {"one_of": list(values)}


def qr_category():
    c = Category("qr", "The payload of the QR code and its text (spec/transports.md, section 3).")
    qr_meaning = lambda q: meaning(tx.qr_json, q)
    largest_text = tx.qr_text(tx.encode_qr(tx.LARGEST))
    key_only = {"signing_key": OBF, "encryption_key": None, "local": None, "relay": None}
    key_only_text = tx.qr_text(tx.encode_qr(key_only))
    text = tx.text
    mixed = "axt:" + "".join(ch.lower() if i % 2 else ch for i, ch in enumerate(text[4:]))
    for label, t, q in [("the QR code of transports.md, section 7.2", text, tx.QR),
                        ("the same text in lower case", text.lower(), tx.QR),
                        ("the same text in mixed case", mixed, tx.QR),
                        ("a code with the signing key alone", key_only_text, key_only),
                        ("the largest valid payload, every field at its largest", largest_text, tx.LARGEST)]:
        assert tx.parse_qr(t) == q, label
        c.add("parse_qr", label, ["transports.md 3.1", "transports.md 3.2"], {"text": t}, accept({"payload": qr_meaning(q)}))
    assert len(tx.QR_NEGATIVE) == 20, "spec/transports.md, section 6, names 20 invalid payloads and texts"
    for label, t, reason in tx.QR_NEGATIVE:
        got = tx.parse_qr(t)
        assert isinstance(got, str) and reason in got, label
        error = "QR_VERSION_UNSUPPORTED" if label == "payload version 2" else "QR_INVALID"
        c.add("parse_qr", f"reject {label}", ["transports.md 3.1", "transports.md 3.2"], {"text": t}, reject(error, got))
    for label, payload, t in [("the payload of transports.md, section 7.2", tx.payload, text),
                              ("a payload with the signing key alone", tx.encode_qr(key_only), key_only_text),
                              ("the largest valid payload", tx.encode_qr(tx.LARGEST), largest_text)]:
        assert tx.qr_text(payload) == t and len(t) <= tx.MAX_QR_TEXT
        c.add("qr_text", label, ["transports.md 3.2"], {"payload": B(payload)}, accept({"text": t}))
    assert len(text) == 230 and tx.MAX_QR_TEXT == 694 and tx.MAX_QR_PAYLOAD == 431
    return c


# --- local network (spec/transports.md, section 4) -----------------------------------------

OLDER_SEED = test_secret("cat-a-log, older phone, Ed25519")


def local_category():
    c = Category("local", "Frames and HELLO of a connection on the local network (spec/transports.md, section 4).")
    for label, seed, role, frame in [("cat-a-log's HELLO as the client", CAT_SEED, "client", tx.client_hello),
                                     ("Old Brain Fix's HELLO as the server", OBF_SEED, "server", tx.server_hello)]:
        assert frame == tx.hello(seed, tx.CLIENT if role == "client" else tx.SERVER, tx.CERT_HASH, check=False)
        c.add("hello_frame", label, ["transports.md 4.5", "transports.md 7.3"],
              {"seed": H(seed), "role": role, "certificate_sha256": H(tx.CERT_HASH)}, accept({"frame": H(frame)}))

    names = {tx.SERVER: "server", tx.CLIENT: "client"}

    def connection(label, refs, role, cert_hash, frames, expected_key=None, too_large_last=False):
        peer = tx.Peer(role, cert_hash, expected_key)
        results = []
        for f in frames:
            try:
                got = peer.receive(f)
            except tx.Closed:
                results.append("close")
                break
            results.append({"open": "open", "message": "message", "ping": "ping", "TOO_LARGE": "too_large"}[got])
        if too_large_last:
            assert results[-1] == "too_large"
            results[-1] = one_of("too_large", "close")  # it reports the message, or closes (section 4.4)
        c.add("connection", label, ["transports.md 4.4", "transports.md 4.5"] + refs,
              {"role": names[role], "certificate_sha256": H(cert_hash),
               "expected_key": None if expected_key is None else H(expected_key), "frames": [B(f) for f in frames]},
              {"steps": results})
        return results

    S, C, CH = tx.SERVER, tx.CLIENT, tx.CERT_HASH
    hello_c, hello_s, data, ping, frame = tx.client_hello, tx.server_hello, tx.data_frame, tx.ping_frame, tx.frame
    move = key_move(OLDER_SEED, CAT_SEED, None)  # a key move to the key of the client's HELLO
    assert connection("the server takes the client's HELLO, the DATA of protocol.md, section 17.5, and a PING",
                      ["transports.md 7.3", "transports.md 7.4"], S, CH, [hello_c, data, ping]) == ["open", "message", "ping"]
    assert connection("the client takes the server's HELLO with the key of the QR code", ["transports.md 3.3"],
                      C, CH, [hello_s], expected_key=OBF) == ["open"]
    assert connection("a KEY_MOVE signed with an earlier key at the start, then the sender's messages", ["protocol.md 3.3"],
                      S, CH, [hello_c, frame(tx.MESSAGE, move), data]) == ["open", "message", "message"]
    connection("a MESSAGE above 16 MiB is skipped and reported, or the connection closed", ["envelope.md 8"],
               S, CH, [hello_c, frame(tx.MESSAGE, bytes(MAX_MESSAGE + 1))], too_large_last=True)
    closing = [
        ("a HELLO for another certificate, passed on by a machine in the middle", S, tx.OTHER_CERT_HASH, [hello_c], None),
        ("the server's own HELLO sent back to it", S, CH, [hello_s], None),
        ("a HELLO with another key than the QR code's", C, CH, [hello_s], CAT),
        ("a HELLO with a changed signature", S, CH, [hello_c[:-1] + bytes([hello_c[-1] ^ 1])], None),
        ("a HELLO with a key of small order", S, CH, [frame(tx.HELLO, (1).to_bytes(32, "little") + hello_c[37:])], None),
        ("a HELLO of 95 bytes", S, CH, [frame(tx.HELLO, hello_c[5:-1])], None),
        ("a MESSAGE before the HELLO", S, CH, [data], None),
        ("a PING before the HELLO", S, CH, [ping], None),
        ("a second HELLO", S, CH, [hello_c, hello_c], None),
        ("a message whose sender is not the key of the HELLO", C, CH, [hello_s, data], None),
        ("an empty MESSAGE", S, CH, [hello_c, frame(tx.MESSAGE, b"")], None),
        ("a PING with a payload", S, CH, [hello_c, frame(tx.PING, b"\x00")], None),
        ("an unknown frame type", S, CH, [hello_c, frame(4, b"")], None),
        ("a frame cut short by the end of the connection", S, CH, [hello_c, data[:-1]], None),
        ("a KEY_MOVE after another message", S, CH, [hello_c, data, frame(tx.MESSAGE, move)], None),
    ]
    assert len(closing) == 15 == sum(x.startswith("closed: ") for x in tx.checks), "spec/transports.md, section 6, names 15"
    for label, role, cert_hash, frames, key in closing:
        assert connection(f"close on {label}", [], role, cert_hash, frames, expected_key=key)[-1] == "close", label
    return c


# --- relay, as a client (spec/transports.md, section 5) ---------------------------------------


def relay_category():
    c = Category("relay", "The relay as an app uses it: mailbox ids, requests, what an app does with each response, "
                          "and the list of messages (spec/transports.md, section 5).")
    for label, secret in [("Old Brain Fix's test mailbox secret", tx.MAILBOX_SECRET), ("another test secret", test_secret("another mailbox secret"))]:
        c.add("mailbox_id", f"the mailbox id of {label}", ["transports.md 5.1", "transports.md 7.1"],
              {"secret": H(secret)}, accept({"mailbox": H(tx.mailbox_id(secret))}))
    base, box = tx.RELAY_URL, tx.MAILBOX.hex()
    auth = "Bearer " + tx.MAILBOX_SECRET.hex()
    url = base + f"v1/mailboxes/{box}"
    sealed_id = tx.SEALED_HASH
    requests = [
        ("create the mailbox", {"action": "create", "secret": H(tx.MAILBOX_SECRET)},
         {"method": "PUT", "url": url, "headers": {"authorization": auth, "content_type": None, "content_length": one_of(None, "0")}}),
        ("put the sealed message of keys.md, section 7.4", {"action": "put", "mailbox": box, "message": B(tx.SEALED)},
         {"method": "PUT", "url": f"{url}/messages/{sealed_id}",
          "headers": {"authorization": None, "content_type": "application/octet-stream", "content_length": "1073"}}),
        ("list, waiting up to 30 seconds", {"action": "list", "secret": H(tx.MAILBOX_SECRET), "wait": 30},
         {"method": "GET", "url": f"{url}/messages?wait=30", "headers": {"authorization": auth, "content_type": None, "content_length": None}}),
        ("list without waiting", {"action": "list", "secret": H(tx.MAILBOX_SECRET), "wait": None},
         {"method": "GET", "url": f"{url}/messages", "headers": {"authorization": auth, "content_type": None, "content_length": None}}),
        ("fetch a message", {"action": "fetch", "secret": H(tx.MAILBOX_SECRET), "message_id": sealed_id},
         {"method": "GET", "url": f"{url}/messages/{sealed_id}", "headers": {"authorization": auth, "content_type": None, "content_length": None}}),
        ("delete a message", {"action": "delete", "secret": H(tx.MAILBOX_SECRET), "message_id": sealed_id},
         {"method": "DELETE", "url": f"{url}/messages/{sealed_id}", "headers": {"authorization": auth, "content_type": None, "content_length": None}}),
        ("remove the mailbox", {"action": "remove", "secret": H(tx.MAILBOX_SECRET)},
         {"method": "DELETE", "url": url, "headers": {"authorization": auth, "content_type": None, "content_length": None}}),
    ]
    for label, i, want in requests:
        c.add("request", label, ["transports.md 5.2", "transports.md 5.3", "transports.md 7.5"], dict(i, base_url=base), accept(want))

    backoff = lambda attempt: min(2 ** (attempt - 1), 3600)
    reactions = [
        ("put", 201, None, 1, "done", None), ("put", 204, None, 1, "done", None), ("create", 201, None, 1, "done", None),
        ("create", 204, None, 1, "done", None), ("list", 200, None, 1, "done", None), ("fetch", 200, None, 1, "done", None),
        ("delete", 204, None, 1, "done", None), ("remove", 204, None, 1, "done", None),
        ("put", 400, None, 1, "stop", None), ("list", 400, None, 1, "stop", None), ("list", 401, None, 1, "stop", None),
        ("fetch", 403, None, 1, "stop", None), ("create", 403, None, 1, "stop", None), ("put", 413, None, 1, "stop", None),
        ("put", 404, None, 1, "stop", None), ("list", 404, None, 1, "create_mailbox", None),
        ("put", 411, None, 1, "repeat", 0),
        ("put", 429, 120, 1, "repeat", 120), ("list", 429, 5, 3, "repeat", 5), ("put", 503, 30, 1, "repeat", 30),
        ("put", 503, None, 1, "repeat", backoff(1)), ("put", 503, None, 2, "repeat", backoff(2)),
        ("put", 507, None, 5, "repeat", backoff(5)), ("put", 500, None, 3, "repeat", backoff(3)),
        ("put", 502, None, 12, "repeat", backoff(12)), ("put", 503, None, 13, "repeat", backoff(13)),
        ("put", None, None, 1, "repeat", backoff(1)), ("list", None, None, 20, "repeat", 3600),
    ]
    assert backoff(13) == 3600 and backoff(12) == 2048
    for request, status, retry, attempt, action, wait in reactions:
        what = "a network failure" if status is None else f"{status}" + (f" with Retry-After {retry}" if retry is not None else "")
        c.add("reaction", f"{request} answered with {what}, attempt {attempt}", ["transports.md 5.2", "transports.md 5.3", "transports.md 5.4"],
              {"request": request, "status": status, "retry_after": retry, "attempt": attempt},
              accept({"action": action, "wait": wait}))
    listing = tx.listing[2].decode()
    for label, body, msgs in [
        ("the list of transports.md, section 7.5", listing, [{"id": sealed_id, "size": 1073}]),
        ("an empty list", '{"messages":[]}', []),
        ("a list with members the app does not know", json.dumps({"messages": [{"id": sealed_id, "size": 1073, "put": "2026-11-15"}],
                                                                  "next": None, "relay": "example"}), [{"id": sealed_id, "size": 1073}]),
    ]:
        c.add("listing", label, ["transports.md 5.4"], {"body": body}, accept({"messages": msgs}))
    return c


# --- relay, as a relay (spec/transports.md, section 5; for axt-1008) ---------------------------


def relay_server_category():
    c = Category("relay-server", "The interface of a relay, played as requests against one relay with a clock the test "
                                 "sets (spec/transports.md, section 5). For relays, not for libraries.")
    assert sum(x.startswith("relay: ") and " opens " not in x for x in tx.checks) == 28, "spec/transports.md, section 6, names 28 requests"
    OWNER, WRONG, BOX, PUT_PATH = tx.OWNER, tx.WRONG, tx.BOX, tx.PUT_PATH
    S, H14, G = tx.SEALED, tx.HOLDING, tx.GRACE
    second = tx.second
    put = lambda body, path=PUT_PATH, now=0: ("PUT", path, {"Content-Length": str(len(body))}, body, now)
    labelled = [
        ("a put before the mailbox exists", put(S), 404),
        ("creating the mailbox without Authorization", ("PUT", BOX, {}, b"", 0), 401),
        ("creating it with a malformed Authorization", ("PUT", BOX, {"Authorization": "Bearer xyz"}, b"", 0), 401),
        ("creating it with another mailbox's secret", ("PUT", BOX, WRONG, b"", 0), 403),
        ("creating the mailbox", ("PUT", BOX, OWNER, b"", 0), 201),
        ("creating it again", ("PUT", BOX, OWNER, b"", 0), 204),
        ("a put without Content-Length", ("PUT", PUT_PATH, {}, S, 0), 411),
        ("a put whose id is not its SHA-256", put(S[:-1] + b"\x00"), 400),
        ("a put above 17,301,553 bytes", ("PUT", PUT_PATH, {"Content-Length": str(tx.MAX_SEALED + 1)}, b"", 0), 413),
        ("the put of the sealed message", put(S, now=1000), 201),
        ("the same put again", put(S, now=2000), 204),
        ("listing with another mailbox's secret", ("GET", f"{BOX}/messages", WRONG, b"", 2000), 403),
        ("listing with a wait above 60 seconds", ("GET", f"{BOX}/messages?wait=61", OWNER, b"", 2000), 400),
        ("the listing", ("GET", f"{BOX}/messages?wait=30", OWNER, b"", 3000), 200),
        ("the fetch", ("GET", PUT_PATH, OWNER, b"", 3000), 200),
        ("a fetch without the secret", ("GET", PUT_PATH, {}, b"", 3000), 401),
        ("a delete with another mailbox's secret", ("DELETE", PUT_PATH, WRONG, b"", 3000), 403),
        ("the delete", ("DELETE", PUT_PATH, OWNER, b"", 3000), 204),
        ("the delete again", ("DELETE", PUT_PATH, OWNER, b"", 3000), 204),
        ("the listing after the delete", ("GET", f"{BOX}/messages", OWNER, b"", 3000), 200),
        ("a fetch after the delete", ("GET", PUT_PATH, OWNER, b"", 3000), 404),
        ("a put at time 0", put(S, now=0), 201),
        ("held 14 days after the put", ("GET", PUT_PATH, OWNER, b"", H14 - 1), 200),
        ("gone 15 days after the put", ("GET", PUT_PATH, OWNER, b"", H14 + G), 404),
        ("the put again", put(S, now=H14 + G), 201),
        ("a put of a second message", put(second, path=f"{BOX}/messages/{tx.second_hash}", now=H14 + G + 1), 201),
        ("the listing in the order of the puts", ("GET", f"{BOX}/messages", OWNER, b"", H14 + G + 2), 200),
        ("deleting the mailbox", ("DELETE", BOX, OWNER, b"", H14 + G + 2), 204),
        ("a put after the mailbox was deleted", put(S, now=H14 + G + 2), 404),
    ]
    largest = bytes(tx.MAX_SEALED)
    small = [
        ("creating the mailbox", ("PUT", BOX, OWNER, b"", 0), 201),
        ("an empty mailbox takes a message of 17,301,553 bytes",
         ("PUT", f"{BOX}/messages/{hashlib.sha256(largest).hexdigest()}", {"Content-Length": str(tx.MAX_SEALED)}, largest, 0), 201),
        ("a full mailbox", ("PUT", PUT_PATH, {"Content-Length": "1073"}, S, 0), 507),
    ]
    for label, quota, reqs in [("the requests of transports.md, sections 5.2 to 5.5 and 7.5", 64 * 2 ** 20, labelled),
                               ("a mailbox whose room is used up, with a relay that keeps no room beyond one message", 0, small)]:
        relay = tx.Relay(quota_bytes=quota)
        steps, results = [], []
        for what, (method, target, headers, body, now), status in reqs:
            got = relay.handle(method, target, headers, body, now=now)
            assert got[0] == status, (what, got[0], status)
            r = {"status": got[0]}
            if status == 200 and target.split("?")[0].endswith("/messages"):
                r["messages"] = json.loads(got[2])["messages"]
            elif status == 200:
                r["message"] = B(got[2])
            steps.append({"method": method, "target": target, "headers": headers, "body": B(body), "now": now})
            results.append(r)
        c.add("relay", label, ["transports.md 5.2", "transports.md 5.3", "transports.md 5.4", "transports.md 5.5", "transports.md 5.6"],
              {"base_url": tx.RELAY_URL, "quota_bytes": quota, "requests": steps}, {"steps": results})
    return c


# --- records (spec/records.md) -------------------------------------------------------------
# The scripts have no model of a receiver's own changes; the expected results below are written out from
# spec/records.md, sections 5 to 7, and the worked example of its section 9.

AP_T, TASK_T = "axt.example.v1.Appointment", "axt.example.v1.Task"
REC_ID = "3f2c8a5e-9b1d-4c7e-8a6f-2d4b5c6e7f80"  # spec/records.md, section 9


def data(version, value, rid=REC_ID, type_name=AP_T):
    return {"message": {"kind": "DATA", "id": rid, "version": version, "type": type_name, "value": value}}


def delete(version, rid=REC_ID):
    return {"message": {"kind": "DELETE", "id": rid, "version": version}}


def change(field, value, rid=REC_ID):
    return {"local_change": {"id": rid, "field": field, "value": value}}


def user_delete(rid=REC_ID):
    return {"local_delete": {"id": rid}}


def done(outcome, version, state, value, kept=()):
    return {"outcome": outcome, "receiver_version": version, "kept_fields": sorted(kept), "state": state, "value": value}


def failed(code):
    return {"error": code}


def records_category():
    c = Category("records", "A receiver applying the record messages of one sender: the version rule, deletions and "
                            "tombstones, and its user's own changes (spec/records.md).")

    def scenario(label, refs, policy, steps):
        events, results = [], []
        for e, r in steps:
            events.append(e)
            results.append({} if r is None else r)
        c.add("apply", label, refs, {"policy": policy, "events": events}, {"steps": results})

    per_field_delete = {"local_changes": "per_field", "delete_with_local_changes": "delete"}
    per_field_keep = {"local_changes": "per_field", "delete_with_local_changes": "keep"}
    v1 = {"title": "Vet", "start": "2025-11-18T10:00", "location": "", "notes": ""}
    v3 = {"title": "Vet", "start": "2025-11-18T10:30", "location": "", "notes": "Bring the vaccination card"}
    mine = "Dr. Weber, Hauptstr. 5"
    merged = dict(v3, location=mine)
    head = [
        (data(1, v1), done("APPLIED", 1, "there", v1)),
        (change("location", mine), None),
        (data(3, v3), done("MERGED", 3, "there", merged, ["location"])),
        (data(3, v3), done("DUPLICATE", 3, "there", merged)),
        (data(1, v1), done("STALE", 3, "there", merged)),
    ]
    scenario("the example of records.md, section 9, with a receiver that deletes", ["records.md 5.2", "records.md 6.1", "records.md 9"],
             per_field_delete, head + [
                 (delete(4), done("APPLIED", 4, "tombstone", None)),
                 (data(5, v3), done("APPLIED", 5, "there", v3))])
    scenario("the example of records.md, section 9, with a receiver that keeps its user's changes against a deletion",
             ["records.md 6.4", "records.md 9"], per_field_keep, head + [
                 (delete(4), done("KEPT", 4, "there", merged)),
                 (data(5, v3), done("MERGED", 5, "there", merged, ["location"]))])
    scenario("a DELETE of an unchanged record is applied, also by a receiver that keeps changes", ["records.md 6.4"],
             per_field_keep, [(data(1, v1), done("APPLIED", 1, "there", v1)),
                              (delete(2), done("APPLIED", 2, "tombstone", None))])
    other = "7c9e6679-7425-40de-944b-e07fc1f90ae7"
    scenario("a DELETE of an unknown id leaves a tombstone that older and equal versions do not pass",
             ["records.md 5.2", "records.md 5.3"], per_field_delete, [
                 (delete(4, other), done("APPLIED", 4, "tombstone", None)),
                 (data(3, v1, other), done("STALE", 4, "tombstone", None)),
                 (data(4, v1, other), done("DUPLICATE", 4, "tombstone", None)),
                 (data(5, v1, other, TASK_T), done("APPLIED", 5, "there", v1))])
    scenario("a record its user deleted stays deleted; a later DELETE turns it into a tombstone", ["records.md 6.3"],
             per_field_delete, [
                 (data(1, v1), done("APPLIED", 1, "there", v1)),
                 (user_delete(), None),
                 (data(2, v3), done("KEPT", 2, "deleted_by_user", None)),
                 (data(1, v1), done("STALE", 2, "deleted_by_user", None)),
                 (delete(3), done("APPLIED", 3, "tombstone", None))])
    for policy, outcome, value in [("whole_record_keep", "KEPT", dict(v1, location=mine)), ("whole_record_take", "APPLIED", v3)]:
        scenario(f"a receiver that tracks changes of the whole record, {policy.replace('_', ' ')}", ["records.md 6.2"],
                 {"local_changes": policy, "delete_with_local_changes": "delete"}, [
                     (data(1, v1), done("APPLIED", 1, "there", v1)),
                     (data(2, v1), done("APPLIED", 2, "there", v1)),
                     (change("location", mine), None),
                     (data(3, v3), done(outcome, 3, "there", value))])
    a1 = {"a": 1, "b": 1, "c": 1}
    scenario("only the kept values that differ from the message are named", ["records.md 6.1", "records.md 7"],
             per_field_delete, [
                 (data(1, a1), done("APPLIED", 1, "there", a1)),
                 (change("a", 2), None), (change("b", 2), None),
                 (data(2, {"a": 1, "b": 2, "c": 3}), done("MERGED", 2, "there", {"a": 2, "b": 2, "c": 3}, ["a"]))])
    scenario("a message that brings the value its user set is applied", ["records.md 6.1"], per_field_delete, [
        (data(1, v1), done("APPLIED", 1, "there", v1)),
        (change("location", mine), None),
        (data(2, dict(v3, location=mine)), done("APPLIED", 2, "there", dict(v3, location=mine)))])
    scenario("ids compare as 128-bit values, whatever the case of their digits", ["records.md 2", "envelope.md 7"],
             per_field_delete, [
                 (data(1, v1), done("APPLIED", 1, "there", v1)),
                 (data(2, v3, REC_ID.upper()), done("APPLIED", 2, "there", v3)),
                 (data(2, v3), done("DUPLICATE", 2, "there", v3))])
    scenario("a message that cannot be processed changes nothing", ["records.md 2", "records.md 3", "records.md 7"],
             per_field_delete, [
                 (data(1, v1), done("APPLIED", 1, "there", v1)),
                 (data(2, v3, "vet-appointment"), failed("RECORD_ID_INVALID")),
                 (data(2, v3, "00000000-0000-0000-0000-000000000000"), failed("RECORD_ID_INVALID")),
                 (data(2, v3, "ffffffff-ffff-ffff-ffff-ffffffffffff"), failed("RECORD_ID_INVALID")),
                 (data(2, v3, REC_ID.replace("-", "")), failed("RECORD_ID_INVALID")),
                 (data(0, v3), failed("VERSION_INVALID")),
                 (data(-1, v3), failed("VERSION_INVALID")),
                 (delete(0), failed("VERSION_INVALID")),
                 (data(1, v1), done("DUPLICATE", 1, "there", v1))])
    scenario("a record keeps its type, also through a tombstone", ["records.md 4.3"], per_field_delete, [
        (data(1, v1), done("APPLIED", 1, "there", v1)),
        (data(2, v1, REC_ID, TASK_T), failed("TYPE_CHANGED")),
        (delete(2), done("APPLIED", 2, "tombstone", None)),
        (data(3, v1, REC_ID, TASK_T), failed("TYPE_CHANGED")),
        (data(3, v1), done("APPLIED", 3, "there", v1))])
    return c


# --- file (spec/transports.md, section 2) ---------------------------------------------------
# The scripts write one file; the files below are built by hand, so that each broken one breaks one rule. The
# expected results are written out from the table of spec/transports.md, section 2.2.

SYNC = bytes(range(16))
ENVELOPE_TEXT = (REPO / "types" / "axt" / "Envelope.avsc").read_text(encoding="utf-8")


def avro_map(entries):
    zz = keys.zigzag
    if not entries:
        return zz(0)
    out = zz(len(entries))
    for k, v in entries:
        out += zz(len(k.encode())) + k.encode() + zz(len(v)) + v
    return out + zz(0)


def container(messages, schemas=None, seed=CAT_SEED, codec="null", schema_text=None, meta=None, blocks=None, sync=SYNC):
    """An AXT file: the live messages without their single-object header, in one block (spec/envelope.md, section 4).

    schemas is the list of writer schemas for axt.schemas, or None for a file without it; meta, if given,
    changes the metadata entries after they are computed: a key mapped to None is left out."""
    zz = keys.zigzag
    sender = keys.public_key(seed)
    entries = {}
    value = None
    if schemas is not None:
        value = json.dumps(schemas, separators=(",", ":"), ensure_ascii=False).encode()
        entries["axt.schemas"] = value
    signed_bytes = keys.FILE_HEADER_PREFIX + sender + hashlib.sha256(value or b"").digest()
    entries["axt.sender"] = sender.hex().encode()
    entries["axt.signature"] = keys.sign(seed, signed_bytes).hex().encode()
    entries["avro.codec"] = codec.encode()
    entries["avro.schema"] = (schema_text if schema_text is not None else json.dumps(json.loads(ENVELOPE_TEXT))).encode()
    for k, v in (meta or {}).items():
        if v is None:
            entries.pop(k, None)
        else:
            entries[k] = v
    out = b"Obj\x01" + avro_map(list(entries.items())) + sync
    for count, payload in (blocks if blocks is not None else [(len(messages), b"".join(m[10:] for m in messages))]):
        if codec == "deflate":
            payload = stored_deflate(payload)
        out += zz(count) + zz(len(payload)) + payload + sync
    return out


def stored_deflate(data):
    """Raw DEFLATE of stored blocks (RFC 1951, section 3.2.4): the same bytes from every implementation, where
    compressed blocks depend on the zlib that writes them."""
    out, chunks = bytearray(), [data[i:i + 65535] for i in range(0, len(data), 65535)] or [b""]
    for i, chunk in enumerate(chunks):
        out += bytes([1 if i == len(chunks) - 1 else 0]) + len(chunk).to_bytes(2, "little") + (len(chunk) ^ 0xFFFF).to_bytes(2, "little") + chunk
    return bytes(out)


assert container([MEMO_MSG], [env.MEMO_SCHEMA]) == env.axt_file, "the builder does not give the file of spec/keys.md, section 7.3"


def file_category():
    c = Category("file", "Reading an AXT file: what it holds, in which order, and what rejects the whole file or only "
                         "one record (spec/transports.md, section 2; spec/envelope.md, section 4; spec/keys.md, section 2.5).")
    A_, TK, NT, PT = "Appointment", "Task", "Note", "Pet"
    schema = lambda n: json.loads(pe.compact(EXAMPLES / f"{n}.1.avsc"))
    text = lambda n: pe.compact(EXAMPLES / f"{n}.1.avsc")
    ap_text, ap = text(A_), rules.DATA[A_]
    rid = lambda n: f"{n:08x}-1111-4111-8111-111111111111"
    D = lambda n, v=1, seed=CAT_SEED, t=A_, value=None, record_id=None: pe.obf_data(
        record_id or rid(n), v, text(t), rules.DATA[t] if value is None else value, seed)
    DEL = lambda n, v, seed=CAT_SEED: pe.make_message("DELETE", seed, (rid(n), v), [], check=False)[1]
    MAN = lambda seed=CAT_SEED, m=me.CAT_A_LOG: pe.make_message("MANIFEST", seed, None, pe.header("Manifest") + [
        (me.encode_body(m)[10:], "")], check=False)[1]
    obf_reader = {"manifest": B(me.encode_body(me.OLD_BRAIN_FIX)), "readers": {f"axt.example.v1.{A_}": pe.compact(EXAMPLES / f"{A_}.1.avsc")}}
    rec = lambda n, v, result, record_id=None: {"id": record_id or rid(n), "version": v, "result": result}
    read = lambda sender, records, manifest="none", moves=(): accept({
        "sender": H(sender), "key_moves": [{"from": H(a), "to": H(b)} for a, b in moves], "manifest": manifest, "records": records})
    refs = ["transports.md 2.2"]

    def add(label, data, expected, more=(), reader=None):
        c.add("read_file", label, refs + list(more), {"file": B(data), "reader": reader or obf_reader}, expected)

    memo_id = env.RECORD_ID
    add("the file of keys.md, section 7.3", env.axt_file, read(CAT, [rec(0, 1, "APPLIED", memo_id)]), ["keys.md 7.3", "envelope.md 10.3"])
    add("the same file with the codec deflate", container([MEMO_MSG], [env.MEMO_SCHEMA], codec="deflate"),
        read(CAT, [rec(0, 1, "APPLIED", memo_id)]), ["envelope.md 4.2"])
    add("a file without avro.codec, which is then null", container([MEMO_MSG], [env.MEMO_SCHEMA], meta={"avro.codec": None}),
        read(CAT, [rec(0, 1, "APPLIED", memo_id)]), ["envelope.md 4.1"])
    add("avro.schema in another text with the same canonical form", container([MEMO_MSG], [env.MEMO_SCHEMA],
        schema_text=json.dumps(json.loads(ENVELOPE_TEXT), indent=2)), read(CAT, [rec(0, 1, "APPLIED", memo_id)]), ["envelope.md 4.1"])
    redoc = json.loads(ENVELOPE_TEXT)
    redoc["doc"] = "Another doc, which the canonical form drops."
    add("avro.schema with another doc", container([MEMO_MSG], [env.MEMO_SCHEMA], schema_text=json.dumps(redoc)),
        read(CAT, [rec(0, 1, "APPLIED", memo_id)]), ["envelope.md 4.1"])
    add("a metadata key the reader does not know", container([MEMO_MSG], [env.MEMO_SCHEMA], meta={"org.example.note": b"hello"}),
        read(CAT, [rec(0, 1, "APPLIED", memo_id)]), ["envelope.md 4.1"])

    move1 = key_move(OLDER_SEED, CAT_SEED, None)
    move2 = KM_MSG  # cat-a-log, old phone to new phone (spec/keys.md, section 7.5)
    older = keys.public_key(OLDER_SEED)
    full = container([move1, move2, MAN(NEW_SEED), D(1, seed=NEW_SEED), DEL(2, 3, NEW_SEED)], [schema(A_)], seed=NEW_SEED, codec="deflate")
    add("key moves, a MANIFEST and record messages, in that order", full,
        read(NEW, [rec(1, 1, "APPLIED"), rec(2, 3, "APPLIED")], "used", [(older, CAT), (CAT, NEW)]),
        ["transports.md 2.1", "keys.md 5.2", "manifest.md 7"])
    add("a file that only carries its writer's MANIFEST", container([MAN()], None), read(CAT, [], "used"), ["transports.md 2.1"])
    add("a file without axt.schemas, with a DELETE only", container([DEL(3, 4)], None), read(CAT, [rec(3, 4, "APPLIED")]),
        ["keys.md 2.5", "envelope.md 4.1"])
    bad_manifest = MAN(m=dict(me.CAT_A_LOG, revision=0))
    add("an invalid MANIFEST is not used, and the records are applied", container([bad_manifest, D(4)], [schema(A_)]),
        read(CAT, [rec(4, 1, "APPLIED")], "invalid"), ["manifest.md 4"])
    short = pe.make_message("DATA", CAT_SEED, (rid(9), 1), [(single_object(ap_text, ap)[:-3], "")], check=False)[1]
    add("record messages that fail a step are not applied, the others are",
        container([D(5, record_id="00000000-0000-0000-0000-000000000000"), D(6, v=0), D(7), D(7, v=2, t=TK), short, D(8)],
                  [schema(A_), schema(TK)]),
        read(CAT, [rec(0, 1, "RECORD_ID_INVALID", "00000000-0000-0000-0000-000000000000"), rec(6, 0, "VERSION_INVALID"),
                   rec(7, 1, "APPLIED"), rec(7, 2, "TYPE_CHANGED"), rec(9, 1, "UNDECODABLE"), rec(8, 1, "APPLIED")]),
        ["protocol.md 6.2", "protocol.md 15.2"])
    cat_reader = {"manifest": B(me.encode_body(me.CAT_A_LOG)), "readers": {}}
    add("a record whose type does not fit the reader's manifest is not applied", container([D(10, t=NT), D(11, t=PT)], [schema(NT), schema(PT)]),
        read(CAT, [rec(10, 1, "DOES_NOT_FIT"), rec(11, 1, "APPLIED")]), ["manifest.md 7"], reader=cat_reader)
    add("several messages of one record are applied by the version rule", container([D(12, v=2), D(12, v=1), D(12, v=2)], [schema(A_)]),
        read(CAT, [rec(12, 2, "APPLIED"), rec(12, 1, "STALE"), rec(12, 2, "DUPLICATE")]), ["transports.md 2.3", "records.md 5.2"])
    narrow = schema(A_)
    narrow["fields"].append({"name": "room", "type": "string", "doc": "A field without a default that the writer lacks."})
    add("a record whose schema does not resolve against the reader's is not applied", container([D(13)], [schema(A_)]),
        read(CAT, [rec(13, 1, "DOES_NOT_RESOLVE")]), ["envelope.md 6"],
        reader={"manifest": obf_reader["manifest"], "readers": {f"axt.example.v1.{A_}": json.dumps(narrow, separators=(",", ":"))}})

    good = lambda **kw: container([MEMO_MSG], [env.MEMO_SCHEMA], **kw)
    gf = good()
    memo2 = dict(env.MEMO_SCHEMA, doc="The same Memo with another doc, and so the same fingerprint.")
    reordered = json.loads(ENVELOPE_TEXT)
    reordered["fields"] = reordered["fields"][1:2] + reordered["fields"][:1] + reordered["fields"][2:]
    header_sig = keys.sign(CAT_SEED, keys.FILE_HEADER_PREFIX + CAT + hashlib.sha256(b"[]").digest())
    fmt2 = signed(CAT_SEED, "DATA", (env.RECORD_ID, 1), MEMO_MSG[0x54:-64], fmt=2)
    no_record = signed(CAT_SEED, "DATA", None, MEMO_MSG[0x54:-64])
    man_fp = signed(CAT_SEED, "MANIFEST", None, b"\xc3\x01" + ENVELOPE_FP + me.encode_body(me.CAT_A_LOG)[10:])
    bad_sig = MEMO_MSG[:-1] + bytes([MEMO_MSG[-1] ^ 1])
    ack = pe.make_message("ACK", CAT_SEED, None, pe.make_body("Ack", {"to": OBF, "records": [{"id": env.RECORD_ID, "version": 1,
                          "outcome": "APPLIED", "receiver_version": 1, "kept_fields": []}], "moved_from": None}, check=False)[0], check=False)[1]
    offer = pe.make_message("OFFER", CAT_SEED, None, pe.make_body("Offer", {"to": OBF, "offer_id": pe.OFFER_ID, "types": [
        {"schema": pe.compact(EXAMPLES / "Pet.1.avsc"), "count": 1}]}, check=False)[0], check=False)[1]
    bad_proof = key_move(OLDER_SEED, CAT_SEED, None, keys.sign(OBF_SEED, keys.KEY_MOVE_PREFIX + older + CAT))
    datum = MEMO_MSG[10:]
    rejects = [
        ("bytes that are not an Avro object container file", b"AXT file, not Avro" + bytes(32), ["envelope.md 4"]),
        ("the magic of another Avro version", b"Obj\x02" + gf[4:], ["envelope.md 4"]),
        ("the codec snappy", good(codec="snappy"), ["envelope.md 4.2"]),
        ("avro.schema of axt.Manifest", good(schema_text=pe.texts["Manifest"]), ["envelope.md 4.1"]),
        ("avro.schema with two fields swapped, whose canonical form is another", good(schema_text=json.dumps(reordered)), ["envelope.md 4.1", "keys.md 2.5"]),
        ("no axt.signature", good(meta={"axt.signature": None}), ["keys.md 2.5"]),
        ("no axt.sender", good(meta={"axt.sender": None}), ["keys.md 2.5"]),
        ("axt.signature in upper-case hexadecimal", good(meta={"axt.signature": env.HEADER_SIGNATURE.hex().upper().encode()}), ["keys.md 2.5"]),
        ("axt.sender in upper-case hexadecimal", good(meta={"axt.sender": CAT.hex().upper().encode()}), ["keys.md 2.5"]),
        ("axt.signature of 126 digits", good(meta={"axt.signature": env.HEADER_SIGNATURE.hex()[:126].encode()}), ["keys.md 2.5"]),
        ("a header signature over other schemas", good(meta={"axt.signature": header_sig.hex().encode()}), ["keys.md 2.5"]),
        ("two schemas with one fingerprint in axt.schemas", container([MEMO_MSG], [env.MEMO_SCHEMA, memo2]), ["envelope.md 4.1", "envelope.md 5"]),
        ("a DATA whose fingerprint is not in axt.schemas", container([MEMO_MSG], [schema(NT)]), ["envelope.md 4.3"]),
        ("a DATA in a file without axt.schemas", container([MEMO_MSG], None), ["envelope.md 4.3"]),
        ("a datum whose format is 2", container([fmt2], [env.MEMO_SCHEMA]), ["keys.md 2.2"]),
        ("a DATA without record", container([no_record], [env.MEMO_SCHEMA]), ["protocol.md 2"]),
        ("a MANIFEST whose body has another fingerprint", container([man_fp], None), ["protocol.md 2"]),
        ("a block with a byte left over after its datum", container([], [env.MEMO_SCHEMA], blocks=[(1, datum + b"\x00")]), ["envelope.md 4"]),
        ("a block that claims two datums and holds one", container([], [env.MEMO_SCHEMA], blocks=[(2, datum)]), ["envelope.md 4"]),
        ("a wrong sync marker after the block", good()[:-1] + b"\x00", ["envelope.md 4"]),
        ("a message whose signature does not verify", container([bad_sig], [env.MEMO_SCHEMA]), ["transports.md 2.2"]),
        ("an ACK", container([ack], None), ["transports.md 2.1"]),
        ("an OFFER", container([offer], [schema(PT)]), ["transports.md 2.1"]),
        ("a message of another sender", container([D(14, seed=OBF_SEED)], [schema(A_)]), ["keys.md 2.5"]),
        ("a KEY_MOVE after a record message", container([D(15), move1], [schema(A_)]), ["keys.md 5.2", "transports.md 2.1"]),
        ("a chain of key moves that does not end at axt.sender", container([move2, D(16)], [schema(A_)]), ["keys.md 5.2"]),
        ("a KEY_MOVE whose proof does not verify", container([bad_proof, D(17)], [schema(A_)]), ["keys.md 5.3"]),
        ("a second MANIFEST", container([MAN(), MAN(), D(18)], [schema(A_)]), ["transports.md 2.1"]),
        ("a MANIFEST after a record message", container([D(19), MAN()], [schema(A_)]), ["transports.md 2.1"]),
        ("a block above 64 MiB after decompression", container([], [env.MEMO_SCHEMA], codec="deflate", blocks=[(1, bytes(64 * 2 ** 20 + 1))]),
         ["envelope.md 8"]),
        ("metadata above 8 MiB", good(meta={"org.example.big": bytes(8 * 2 ** 20)}), ["envelope.md 8"]),
    ]
    for label, data, more in rejects:
        add(f"reject {label}", data, reject("FILE_REJECTED"), more)
    # The files the readers of the Python libraries take are taken here as well.
    for data in (env.axt_file, full):
        assert len(list(fastavro.reader(io.BytesIO(data)))) >= 1
    return c


# --- output ---------------------------------------------------------------------

CATEGORIES = [encoding_category, types_category, records_category, manifest_category, keys_category, protocol_category,
              file_category, qr_category, local_category, relay_category, relay_server_category]


def render(value, indent=0):
    """JSON with one key per line, and lists and objects of scalars on one line."""
    pad, inner = " " * indent, " " * (indent + 1)
    flat = lambda v: not isinstance(v, (dict, list)) or (not v) or (
        all(not isinstance(x, (dict, list)) for x in (v.values() if isinstance(v, dict) else v)) and len(
            json.dumps(v, ensure_ascii=False)) <= 100)
    if flat(value):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[\n" + ",\n".join(inner + render(v, indent + 1) for v in value) + "\n" + pad + "]"
    return "{\n" + ",\n".join(inner + json.dumps(k, ensure_ascii=False) + ": " + render(v, indent + 1)
                               for k, v in value.items()) + "\n" + pad + "}"


def same_values(v):
    if isinstance(v, dict):
        if set(v) == {"deflate", "length", "sha256"}:
            return {"length": v["length"], "sha256": v["sha256"]}
        return {k: same_values(x) for k, x in v.items()}
    if isinstance(v, list):
        return [same_values(x) for x in v]
    return v


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="compare with the files under vectors/ instead of writing")
    ap.add_argument("--out", type=Path, default=VECTORS, help="the directory to write to (default: vectors/)")
    args = ap.parse_args()
    differ, counts = [], []
    for build in CATEGORIES:
        c = build()
        text = render(c.document()) + "\n"
        path = (VECTORS if args.check else args.out) / c.name / f"{c.name}.json"
        counts.append((c.name, len(c.vectors)))
        if args.check:
            # The DEFLATE of a large value depends on the zlib that writes it; its length and SHA-256 do not.
            if not path.exists() or same_values(json.loads(path.read_text(encoding="utf-8"))) != same_values(json.loads(text)):
                differ.append(str(path.relative_to(REPO)))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
    for name, n in counts:
        print(f"{name}: {n} vectors")
    print(f"total: {sum(n for _, n in counts)} vectors")
    if differ:
        raise SystemExit("differs from the generator's output: " + ", ".join(differ))


if __name__ == "__main__":
    main()
