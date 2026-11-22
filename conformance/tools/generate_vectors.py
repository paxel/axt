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
installed, and a time zone database where Python's zoneinfo finds it:

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
import types
import zlib
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any, cast

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
VECTORS = REPO / "vectors"
FILE_FORMAT = 1  # the version of the vector file format of spec/conformance.md, section 3
SPEC_VERSION = "0.2.0"
INLINE_LIMIT = 65536  # bytes up to which a value is written as hex; above it, as raw DEFLATE


def load(name: str) -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(name, HERE / f"{name}.py")
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {name}.py")
    module = importlib.util.module_from_spec(spec)
    with contextlib.redirect_stdout(io.StringIO()):
        spec.loader.exec_module(module)
    return module


# transports_examples imports protocol_examples, which imports manifest_examples, keys_examples and
# example_types; each runs its checks on import. Nothing of the live TLS exchange reaches a vector.
tx = load("transports_examples")
pe, me, keys, rules = tx.pe, tx.me, tx.keys, tx.rules
env = load("envelope_examples")
tm = load("time_examples")
mx = load("metadata_examples")
sy = load("sync_examples")
sy.check()  # the examples of spec/sync.md hold; fills its examples, messages and sessions for the vectors
se = load("shares_examples")  # runs none of its checks on import; the receiver and sender of spec/shares.md
se.check()  # the examples of spec/shares.md hold
WITHDRAW_MSG = se.withdraw_message(pe.CAT_SEED, pe.OBF, se.REC_ID, 4)[1]  # spec/shares.md, section 11.2
PROPOSAL_MSG, REPLY_MSG = se.example_proposal()[:2]  # spec/shares.md, sections 11.4 and 11.5
mr = mx.mr
assert mr.LANGTAG.pattern == me.LANGTAG.pattern and mr.LANGTAG.flags == me.LANGTAG.flags, (
    "two language tag rules"
)

import fastavro  # noqa: E402  (after the scripts, which check the library versions they were written with)

# --- the bytes of a vector (spec/conformance.md, section 3.2) ---------------------


def B(data: bytes | bytearray) -> str | dict[str, Any]:
    """Bytes as lower-case hex, or above INLINE_LIMIT as raw DEFLATE with their length and SHA-256."""
    data = bytes(data)
    if len(data) <= INLINE_LIMIT:
        return data.hex()
    c = zlib.compressobj(9, zlib.DEFLATED, -15, 9)
    packed = c.compress(data) + c.flush()
    return {"deflate": packed.hex(), "length": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def H(data: bytes | bytearray) -> str:
    return bytes(data).hex()


def accept(value: Any = None) -> dict[str, Any]:
    return {"accept": {} if value is None else value}


def reject(error: str, note: str | None = None, **members: Any) -> dict[str, Any]:
    out = {"error": error}
    if note:
        out["note"] = note
    out.update(members)  # field, for VALUE_INVALID (spec/conformance.md, section 4)
    return {"reject": out}


class Category:
    vectors: list[dict[str, Any]]
    ids: set[str]

    def __init__(self, name: str, description: str) -> None:
        self.name, self.description, self.vectors, self.ids = name, description, [], set()

    def add(self, op: str, description: str, refs: list[str], input: Any, expected: Any) -> None:
        slug = re.sub(r"[^a-z0-9]+", "-", description.lower()).strip("-")[:72].strip("-")
        vid = f"{self.name}/{op}/{slug}"
        assert vid not in self.ids, f"two vectors with the id {vid}"
        self.ids.add(vid)
        self.vectors.append(
            {
                "id": vid,
                "op": op,
                "description": description,
                "refs": refs,
                "input": input,
                "expected": expected,
            }
        )

    def document(self) -> dict[str, Any]:
        return {
            "format": FILE_FORMAT,
            "specification": SPEC_VERSION,
            "category": self.name,
            "description": self.description,
            "vectors": self.vectors,
        }


def test_secret(label: str) -> bytes:
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
assert MEMO_MSG[0x53] < 0x80 and MEMO_MSG[0x54:0x56] == b"\xc3\x01", (
    "the body begins at 0x54, as the slices below assume"
)
assert (
    hashlib.sha256(MEMO_MSG).hexdigest() == "68d19c518a50880136a9f7412d3e636b17422c89cf63837b7ae1a22c8abedfc3"
)
assert MEMO_MSG == tx.memo_msg

# --- keys (spec/keys.md) --------------------------------------------------------


def sealed(message: bytes, receiver_key: bytes, ikm_label: str, plaintext: bytes | None = None) -> bytes:
    """A sealed message (spec/keys.md, section 4.3), with an ephemeral key derived from a test label."""
    sk_e, _ = keys.derive_key_pair(test_secret(ikm_label))
    enc, shared = keys.encap(sk_e, receiver_key)
    ctx = keys.hpke_base_context(shared, keys.HPKE_INFO)
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    padded = keys.pad(message) if plaintext is None else plaintext
    return cast(
        bytes, keys.SEALED_FORMAT + enc + ChaCha20Poly1305(ctx["key"]).encrypt(ctx["base_nonce"], padded, b"")
    )


ADD_MSG = pe.device_add(CAT_SEED, NEW_SEED)
assert (
    hashlib.sha256(ADD_MSG).hexdigest() == "cfe02dfa2168149a75835448342ec39fd2c95464e22c9d4d1a6666ef4f740bd8"
), "not the DEVICE_ADD of spec/keys.md, section 7.5"
JOIN_MSG = pe.device_join(NEW_SEED, CAT)  # the DEVICE_JOIN that carried its proof
OLDER_SEED = test_secret("cat-a-log, older phone, Ed25519")
OLDER = keys.public_key(OLDER_SEED)
# The neutral element as a key: with it, the signature of the neutral element and S = 0 verifies under
# a lax rule for every message (spec/keys.md, section 7.6).
SMALL_KEY, SMALL_SIGNATURE = (1).to_bytes(32, "little"), (1).to_bytes(32, "little") + bytes(32)


def flip_signature(message: bytes) -> bytes:
    """The message with one bit of its signature changed."""
    return message[:-1] + bytes([message[-1] ^ 1])


# --- device sets (spec/keys.md, section 5.5) ---------------------------------------

RECORD_IDS = {f"r{n}": f"0000000{n}-5e55-4d0e-8a11-00000000000{n}" for n in range(1, 7)}
# The ids of the relations of keys_examples.relation_cases.
RELATION_IDS = {f"q{n}": f"0000000{n}-4e1a-4b0e-9c22-00000000000{n}" for n in range(1, 10)}


def set_seed(letter: str) -> bytes:
    return test_secret(f"device set, key {letter}, Ed25519")


def set_key(letter: str) -> bytes:
    return cast(bytes, keys.public_key(set_seed(letter)))


def set_message(kind: str, signer: str, device: str) -> tuple[bytes, Any]:
    """A message of a case of keys_examples.py with the test keys of its letters, and what the model
    takes of it."""
    base, _, fault = kind.partition("+")
    member, key = set_key(signer), set_key(device)
    if base == keys.REMOVE:
        m = pe.device_remove(set_seed(signer), key)
    elif fault == keys.BAD_DEVICE[1:]:
        key = SMALL_KEY
        m = pe.device_add(set_seed(signer), b"", proof=SMALL_SIGNATURE, device=key)
    elif fault == keys.BAD_PROOF[1:]:
        m = pe.device_add(
            set_seed(signer),
            set_seed(device),
            proof=keys.sign(set_seed(device), keys.proof_bytes(key, member)),
        )
    else:
        m = pe.device_add(set_seed(signer), set_seed(device))
    if fault == keys.BAD_SIGNATURE[1:]:
        m = flip_signature(m)
    proof = m[-128:-64] if base == keys.ADD else None  # the last field of the body of a DEVICE_ADD
    problem = keys.device_message_problem(base, member, keys.MESSAGE_PREFIX + m[10:-64], m[-64:], key, proof)
    if fault:
        assert problem == (keys.SIGNATURE_INVALID if fault == keys.BAD_SIGNATURE[1:] else keys.REJECTED)
    else:
        assert problem == (keys.REJECTED if (base, signer) == (keys.REMOVE, device) else None)
    return m, (base, member, key, problem)


def set_senders(senders: list[Any], records: Any) -> list[Any]:
    return [
        keys.KnownSender(
            name,
            [set_key(k) for k in current],
            [set_key(k) for k in removed],
            {RECORD_IDS[rid]: (version, state) for rid, version, state in records.get(name, [])},
        )
        for name, current, removed in senders
        if name != keys.REFUSED_KEYS
    ]


def set_receiver(senders: list[Any], records: Any) -> Any:
    refused = [set_key(k) for name, letters, _ in senders if name == keys.REFUSED_KEYS for k in letters]
    return keys.DeviceReceiver(set_senders(senders, records), refused)


def device_sets_vectors(c: Category) -> None:
    """The cases of keys_examples.py as sessions: the expected results are those written out there, and
    the model must reach them with signed messages as it does with letters."""
    cases: list[
        tuple[
            str,
            str,
            list[str],
            list[Any],
            Any,
            list[Any],
            Any | None,
        ]
    ]
    cases = [
        (
            f"the table, {label}",
            label,
            ["keys.md 5.5"] + (["keys.md 3.4"] if "refused" in label else []),
            before,
            {},
            [(None, [message], [result], None, after)],
            None,
        )
        for label, before, message, result, after in keys.table_cases()
    ]
    cases += [
        (
            what,
            name,
            ["keys.md 5.5"]
            + (["keys.md 3.3"] if "removed key" in what else [])
            + (["keys.md 3.4"] if "refused" in what else []),
            before,
            records,
            steps,
            records_after,
        )
        for name, what, before, records, steps, records_after in keys.chain_cases()
    ]
    for description, _, refs, before, records, steps, records_after in cases:
        receiver = set_receiver(before, records)
        inputs: list[dict[str, Any]] = []
        expected: list[dict[str, Any]] = []
        for key, messages, results, state, after in steps:
            built = [set_message(*m) for m in messages]
            got = receiver.chain([model for _, model in built])
            assert got == results, (description, got)
            now = receiver.state()
            assert [(s["name"], s["current"], s["removed"]) for s in now] == [
                (name, sorted(H(set_key(k)) for k in current), sorted(H(set_key(k)) for k in removed))
                for name, current, removed in sorted(after)
            ], description
            key_state, key_sender = (None, None) if key is None else receiver.key_state(set_key(key))
            assert state is None or (key_state, key_sender) == state, description
            inputs.append(
                {"chain": [B(m) for m, _ in built], "key": None if key is None else H(set_key(key))}
            )
            expected.append(
                {"results": got, "key_state": key_state, "key_sender": key_sender, "senders": now}
            )
        if records_after is not None:
            assert (
                receiver.state() == keys.DeviceReceiver(set_senders(steps[-1][4], records_after)).state()
            ), description
        c.add(
            "device_sets",
            description,
            refs,
            {
                "senders": set_receiver(before, records).state(),
                "refused": sorted(H(k) for k in receiver.refused),
                "steps": inputs,
            },
            {"steps": expected},
        )


def keys_category() -> Category:
    c = Category(
        "keys",
        "Signing keys, signatures, short fingerprints, the devices of a sender, and sealing for the relay "
        "(spec/keys.md).",
    )
    rfc_seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    rfc_pub = keys.public_key(rfc_seed)
    assert rfc_pub.hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    seeds = [
        ("RFC 8032, section 7.1, TEST 1", rfc_seed),
        ("cat-a-log, old phone", CAT_SEED),
        ("cat-a-log, new phone", NEW_SEED),
        ("Old Brain Fix", OBF_SEED),
    ]
    for label, seed in seeds:
        c.add(
            "public_key",
            f"the public key of the test seed {label}",
            ["keys.md 7.1"],
            {"seed": H(seed)},
            accept({"public_key": H(keys.public_key(seed))}),
        )

    header_signed = keys.FILE_HEADER_PREFIX + CAT + hashlib.sha256(env.schemas_value.encode()).digest()
    proof_signed = keys.proof_bytes(CAT, NEW)
    for label, seed, data, refs in [
        ("RFC 8032, section 7.1, TEST 1: the empty message", rfc_seed, b"", ["keys.md 2.2"]),
        ("the DATA message of keys.md, section 7.2", CAT_SEED, MEMO_SIGNED, ["keys.md 2.2", "keys.md 7.2"]),
        ("the file header of keys.md, section 7.3", CAT_SEED, header_signed, ["keys.md 2.5", "keys.md 7.3"]),
        (
            "the proof of the DEVICE_ADD of keys.md, section 7.5",
            NEW_SEED,
            proof_signed,
            ["keys.md 5.2", "keys.md 7.5"],
        ),
    ]:
        c.add(
            "sign",
            f"sign {label}",
            refs,
            {"seed": H(seed), "data": H(data)},
            accept({"signature": H(keys.sign(seed, data))}),
        )
    assert keys.sign(CAT_SEED, MEMO_SIGNED) == MEMO_MSG[-64:]
    assert keys.sign(CAT_SEED, header_signed).hex() == env.HEADER_SIGNATURE.hex()

    # Verification: the RFC 8032 test, and the edges of spec/keys.md, section 7.6.
    rfc_sig = keys.sign(rfc_seed, b"")
    c.add(
        "verify",
        "the signature of RFC 8032, section 7.1, TEST 1",
        ["keys.md 2.3"],
        {"public_key": H(rfc_pub), "data": "", "signature": H(rfc_sig)},
        accept(),
    )
    cases, (identity, identity_nc, mixed_r, mixed_key) = keys.edge_cases(
        CAT_SEED, OBF, MEMO_SIGNED, MEMO_MSG[-64:]
    )
    assert len(cases) == 10, "spec/keys.md, section 7.6, has ten cases"
    for label, key, data, sig, problem in cases:
        assert keys.verify_problem(key, data, sig) == problem
        c.add(
            "verify",
            f"keys.md 7.6: {label}",
            ["keys.md 2.3", "keys.md 7.6"],
            {"public_key": H(key), "data": H(data), "signature": H(sig)},
            accept() if problem is None else reject("SIGNATURE_INVALID", problem),
        )

    # Keys: steps 2 and 3 of spec/keys.md, section 2.3.
    small = keys.small_order_points()
    assert len(small) == 8
    for label, key in [("cat-a-log, old phone", CAT), ("cat-a-log, new phone", NEW), ("Old Brain Fix", OBF)]:
        c.add("check_signing_key", f"the test key {label}", ["keys.md 2.3"], {"public_key": H(key)}, accept())
    sign_bit_identity = bytes([1] + [0] * 30 + [0x80])  # x = 0 with the sign bit set
    not_on_curve = next(
        y.to_bytes(32, "little") for y in range(2, 100) if keys.decompress(y.to_bytes(32, "little")) is None
    )
    for label, key in [(f"the point of small order {e[:4].hex()}...{e[-2:].hex()}", e) for e in small] + [
        ("the neutral element encoded with y = p + 1", identity_nc),
        ("the neutral element with the sign bit set", sign_bit_identity),
        (f"an encoding that is not a point, y = {int.from_bytes(not_on_curve, 'little')}", not_on_curve),
        ("a key with a component of order 8", mixed_key),
    ]:
        problem = keys.key_problem(key)
        assert problem, label
        c.add(
            "check_signing_key",
            f"reject {label}",
            ["keys.md 2.3"],
            {"public_key": H(key)},
            reject("KEY_INVALID", problem),
        )

    # Encryption keys: small order (spec/keys.md, section 4.2).
    p = keys.P
    for label, key in [
        ("Old Brain Fix's X25519 test key", OBF_X25519),
        ("cat-a-log's new X25519 test key", NEW_X25519),
    ]:
        assert keys.encryption_key_problem(key) is None
        c.add(
            "check_encryption_key", f"accept {label}", ["keys.md 4.2"], {"encryption_key": H(key)}, accept()
        )
    smalls = [
        ("u = 0", (0).to_bytes(32, "little")),
        ("u = 1", (1).to_bytes(32, "little")),
        (
            "a point of order 8",
            bytes.fromhex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
        ),
        (
            "the other point of order 8",
            bytes.fromhex("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
        ),
        ("u = p - 1", (p - 1).to_bytes(32, "little")),
        ("u = p, non-canonical 0", p.to_bytes(32, "little")),
        ("u = p + 1, non-canonical 1", (p + 1).to_bytes(32, "little")),
        ("u = 0 with the top bit set", bytes(31) + b"\x80"),
    ]
    for label, key in smalls:
        assert keys.encryption_key_problem(key), label
        c.add(
            "check_encryption_key",
            f"reject {label}",
            ["keys.md 4.2"],
            {"encryption_key": H(key)},
            reject("ENCRYPTION_KEY_INVALID", "X25519 gives the all-zero value"),
        )

    for label, key, fp in [
        ("cat-a-log, old phone", CAT, "24773 42899 01908 98427 81734"),
        ("cat-a-log, new phone", NEW, "09244 67325 13841 38603 74394"),
        ("Old Brain Fix", OBF, "01399 72263 65477 52894 90179"),
    ]:
        assert keys.short_fingerprint(key) == fp
        c.add(
            "short_fingerprint",
            f"the short fingerprint of {label}",
            ["keys.md 3.1", "keys.md 7.1"],
            {"public_key": H(key)},
            accept({"short_fingerprint": fp}),
        )

    # Messages: the signature over the bytes as received (spec/keys.md, section 2.2).
    upper = MEMO_MSG.replace(env.RECORD_ID.encode(), env.RECORD_ID.upper().encode())
    flipped = MEMO_MSG[:0x60] + bytes([MEMO_MSG[0x60] ^ 1]) + MEMO_MSG[0x61:]
    resigned = pe.resign(OBF_SEED, MEMO_MSG)  # signed by another key, sender unchanged
    for label, message, ok, refs in [
        ("the DATA message of keys.md, section 7.2", MEMO_MSG, True, ["keys.md 7.2"]),
        (
            "the DEVICE_ADD of keys.md, section 7.5, signed with the old phone's key",
            ADD_MSG,
            True,
            ["keys.md 5.2", "keys.md 7.5"],
        ),
        ("the MANIFEST of cat-a-log of protocol.md, section 17.2", pe.m1, True, ["protocol.md 17.2"]),
        ("the OFFER of protocol.md, section 17.3", pe.offer_msg, True, ["protocol.md 17.3"]),
        ("the ACK of protocol.md, section 17.5", pe.ack_msg, True, ["protocol.md 17.5"]),
        (
            "the DATA message with its record id in upper case, signature unchanged",
            upper,
            False,
            ["keys.md 2.2", "keys.md 7.2"],
        ),
        ("the DATA message with one byte of the body changed", flipped, False, ["keys.md 2.3"]),
        ("the DATA message signed with another key than its sender", resigned, False, ["keys.md 2.3"]),
    ]:
        c.add(
            "verify_message",
            label,
            ["keys.md 2.2", "keys.md 2.3"] + refs,
            {"message": B(message)},
            accept() if ok else reject("SIGNATURE_INVALID"),
        )

    # Additions of devices: steps 1 and 2 of spec/keys.md, section 5.5, which need no known sender.
    c.add(
        "device_add",
        "the DEVICE_ADD of keys.md, section 7.5",
        ["keys.md 5.2", "keys.md 5.5", "keys.md 7.5"],
        {"message": B(ADD_MSG)},
        accept({"member": H(CAT), "device": H(NEW)}),
    )
    self_added = pe.device_add(CAT_SEED, CAT_SEED)
    c.add(
        "device_add",
        "a DEVICE_ADD of its signer's own key, which passes steps 1 and 2",
        ["keys.md 5.2", "keys.md 5.5"],
        {"message": B(self_added)},
        accept({"member": H(CAT), "device": H(CAT)}),
    )
    bad_adds = [
        (
            "a proof made by another key than the new device's",
            pe.device_add(CAT_SEED, NEW_SEED, proof=keys.sign(OBF_SEED, proof_signed)),
            "the proof does not verify",
        ),
        (
            "a proof over the key of another member",
            pe.device_add(CAT_SEED, NEW_SEED, proof=keys.sign(NEW_SEED, keys.proof_bytes(OLDER, NEW))),
            "the proof does not verify",
        ),
        (
            "a proof over the two keys in the other order",
            pe.device_add(CAT_SEED, NEW_SEED, proof=keys.sign(NEW_SEED, keys.proof_bytes(NEW, CAT))),
            "the proof does not verify",
        ),
        (
            "a proof with the prefix of a message signature",
            pe.device_add(CAT_SEED, NEW_SEED, proof=keys.sign(NEW_SEED, keys.MESSAGE_PREFIX + CAT + NEW)),
            "the proof does not verify",
        ),
        (
            "a device key of small order, with a proof that verifies under a lax rule",
            pe.device_add(CAT_SEED, b"", proof=SMALL_SIGNATURE, device=SMALL_KEY),
            "the device's key is not of order L",
        ),
    ]
    assert keys.verify_plain(SMALL_KEY, proof_signed, SMALL_SIGNATURE)
    for label, message, note in bad_adds:
        c.add(
            "device_add",
            f"reject {label}",
            ["keys.md 2.3", "keys.md 5.5"],
            {"message": B(message)},
            reject("DEVICE_REJECTED", note),
        )
    c.add(
        "device_add",
        "reject a DEVICE_ADD whose signature by the member does not verify",
        ["keys.md 5.5"],
        {"message": B(flip_signature(ADD_MSG))},
        reject("SIGNATURE_INVALID"),
    )

    # A DEVICE_JOIN at the member whose join code was scanned (spec/keys.md, section 5.2).
    def member(key: bytes, current: Iterable[bytes] = (), removed: Iterable[bytes] = ()) -> dict[str, Any]:
        return {"key": H(key), "current": [H(k) for k in current], "removed": [H(k) for k in removed]}

    joins: list[tuple[str, bytes, dict[str, Any], Any] | tuple[str, bytes, dict[str, Any], Any, bytes]] = [
        (
            "the DEVICE_JOIN of the new phone of keys.md, section 7.5: the member asks its user",
            JOIN_MSG,
            member(CAT),
            accept({"device": H(NEW), "action": "ask"}),
        ),
        (
            "a DEVICE_JOIN of a key that is a current key of the set already: the chain is sent again",
            JOIN_MSG,
            member(CAT, [OLDER, NEW]),
            accept({"device": H(NEW), "action": "send_chain"}),
        ),
        (
            "a DEVICE_JOIN whose to is another key, ignored without a report",
            JOIN_MSG,
            member(OLDER, [CAT]),
            accept({"device": H(NEW), "action": "ignore"}),
        ),
        (
            "reject a DEVICE_JOIN of a removed key of the member's set",
            JOIN_MSG,
            member(CAT, [OLDER], [NEW]),
            reject("DEVICE_REJECTED", "a removed key is never a key of the set again"),
        ),
        (
            "reject a DEVICE_JOIN whose proof was made by another key",
            pe.device_join(NEW_SEED, CAT, proof=keys.sign(OBF_SEED, proof_signed)),
            member(CAT),
            reject("DEVICE_REJECTED", "the proof does not verify"),
        ),
        (
            "reject a DEVICE_JOIN whose proof names another member",
            pe.device_join(NEW_SEED, CAT, proof=keys.sign(NEW_SEED, keys.proof_bytes(OLDER, NEW))),
            member(CAT),
            reject("DEVICE_REJECTED", "the proof does not verify"),
        ),
        (
            "reject a DEVICE_JOIN whose proof has the prefix of a message signature",
            pe.device_join(NEW_SEED, CAT, proof=keys.sign(NEW_SEED, keys.MESSAGE_PREFIX + CAT + NEW)),
            member(CAT),
            reject("DEVICE_REJECTED", "the proof does not verify"),
        ),
        (
            "reject a DEVICE_JOIN whose signature does not verify",
            flip_signature(JOIN_MSG),
            member(CAT),
            reject("SIGNATURE_INVALID"),
        ),
        (
            "a second DEVICE_JOIN from the same key is answered as the first: the question stays",
            JOIN_MSG,
            member(CAT),
            accept({"device": H(NEW), "action": "ask"}),
            NEW,
        ),
        (
            "a second DEVICE_JOIN from the same key, a current key by now: the chain is sent again",
            JOIN_MSG,
            member(CAT, [NEW]),
            accept({"device": H(NEW), "action": "send_chain"}),
            NEW,
        ),
        (
            "a DEVICE_JOIN from another key than the first of the join code, ignored without a report",
            JOIN_MSG,
            member(CAT),
            accept({"device": H(NEW), "action": "ignore"}),
            OBF,
        ),
    ]
    for label, message, who, expected, *more in joins:
        first = more[0] if more else None
        _, new_key, body, signed_bytes, signature = pe.device_parts(message)
        got = (
            keys.SIGNATURE_INVALID
            if keys.verify_problem(new_key, signed_bytes, signature)
            else keys.join_action(
                bytes.fromhex(who["key"]),
                [bytes.fromhex(k) for k in who["current"]],
                [bytes.fromhex(k) for k in who["removed"]],
                body["to"],
                new_key,
                body["proof"],
                first,
            )
        )
        assert got == (
            expected["accept"]["action"] if "accept" in expected else expected["reject"]["error"]
        ), label
        c.add(
            "device_join",
            label,
            ["keys.md 5.2", "transports.md 4.7"],
            {"message": B(message), "member": who, "first": None if first is None else H(first)},
            expected,
        )

    # The chain a new device gets in answer to its DEVICE_JOIN (spec/keys.md, section 5.2, step 5).
    earlier = [pe.device_add(OLDER_SEED, CAT_SEED), pe.device_remove(CAT_SEED, OLDER)]
    no_add = "no DEVICE_ADD of the new device by the scanned key with its proof"
    removed_again = "a DEVICE_REMOVE of the new device"
    chains: list[tuple[str, list[bytes], str | None]] = [
        ("a chain of the DEVICE_ADD of keys.md, section 7.5, alone", [ADD_MSG], None),
        (
            "a chain with earlier messages, signed with keys the new device has not met",
            earlier + [ADD_MSG],
            None,
        ),
        (
            "a chain in which the DEVICE_ADD of the new device is not the last message",
            [earlier[0], ADD_MSG, earlier[1], pe.device_add(CAT_SEED, OBF_SEED)],
            None,
        ),
        (
            "reject a chain with a DEVICE_REMOVE of the new device after its DEVICE_ADD",
            [ADD_MSG, pe.device_remove(CAT_SEED, NEW)],
            removed_again,
        ),
        (
            "reject a chain with a DEVICE_REMOVE of the new device before its DEVICE_ADD",
            [pe.device_remove(CAT_SEED, NEW), ADD_MSG],
            removed_again,
        ),
        ("reject an empty chain", [], no_add),
        (
            "reject a chain with the DEVICE_ADD of another device only",
            [pe.device_add(CAT_SEED, OBF_SEED)],
            no_add,
        ),
        (
            "reject a chain whose DEVICE_ADD of the new device is signed with a key that was not scanned",
            [pe.device_add(OLDER_SEED, NEW_SEED)],
            no_add,
        ),
        (
            "reject a chain whose DEVICE_ADD of the new device carries another proof",
            [pe.device_add(CAT_SEED, NEW_SEED, proof=keys.sign(NEW_SEED, keys.proof_bytes(OLDER, NEW)))],
            no_add,
        ),
        (
            "reject a chain with an earlier message whose signature does not verify",
            [flip_signature(earlier[0]), earlier[1], ADD_MSG],
            "a signature does not verify",
        ),
        (
            "reject a chain whose DEVICE_ADD of the new device has a signature that does not verify",
            [flip_signature(ADD_MSG)],
            "a signature does not verify",
        ),
    ]
    for label, chain, why in chains:
        parts = [pe.device_parts(m) for m in chain]
        assert why == keys.join_chain_problem(
            [
                (
                    kind,
                    signer,
                    d["device"],
                    d.get("proof"),
                    keys.verify_problem(signer, signed_bytes, signature) is None,
                )
                for kind, signer, d, signed_bytes, signature in parts
            ],
            CAT,
            NEW,
        ), label
        c.add(
            "join_chain",
            label,
            ["keys.md 5.2", "transports.md 4.7"],
            {"chain": [B(m) for m in chain], "member": H(CAT), "device": H(NEW)},
            accept() if why is None else reject("JOIN_INVALID", why),
        )

    device_sets_vectors(c)

    # Padding (spec/keys.md, section 4.4).
    table = {len(MEMO_MSG): 1024, 1023: 1024, 1024: 1088, 4000: 4096, 100000: 100352, 16777216: 17301504}
    for n in [1, len(MEMO_MSG), 1022, 1023, 1024, 1087, 1088, 4000, 100000, 16777216]:
        got = keys.padded_length(n)
        assert table.get(n, got) == got
        c.add(
            "padded_length",
            f"the padded length of a message of {n} bytes",
            ["keys.md 4.4"],
            {"length": n},
            accept({"padded_length": got}),
        )

    # Sealing: the runner opens what the library seals, with the receiver's test key.
    for label, message in [
        ("the DATA message of keys.md, section 7.2", MEMO_MSG),
        ("the DEVICE_ADD of keys.md, section 7.5", ADD_MSG),
    ]:
        n = len(message)
        c.add(
            "seal",
            f"seal {label} for Old Brain Fix",
            ["keys.md 4.3", "keys.md 4.4"],
            {"message": B(message), "encryption_key": H(OBF_X25519)},
            accept(
                {
                    "sealed": {
                        "opens_with": H(OBF_X25519_SK),
                        "to": B(message),
                        "length": 1 + 32 + keys.padded_length(n) + 16,
                    }
                }
            ),
        )

    # Opening (spec/keys.md, section 4.5).
    published = tx.SEALED
    assert (
        hashlib.sha256(published).hexdigest()
        == "64a9988bd3e1e8210d592e29115d5b3252d2e75be5c219ca67583608cfdb878a"
    )
    other_sk = test_secret("cat-a-log, new phone, X25519")
    opens = [
        ("the sealed message of keys.md, section 7.4", published, [OBF_X25519_SK], MEMO_MSG, None),
        (
            "the sealed message with an earlier key after the current one",
            published,
            [other_sk, OBF_X25519_SK],
            MEMO_MSG,
            None,
        ),
        ("the sealed message with another key only", published, [other_sk], None, "NOT_OPENED"),
        ("a first byte other than 01", b"\x02" + published[1:], [OBF_X25519_SK], None, "NOT_OPENED"),
        (
            "one byte of the ciphertext changed",
            published[:-1] + bytes([published[-1] ^ 1]),
            [OBF_X25519_SK],
            None,
            "NOT_OPENED",
        ),
        (
            "one byte of enc changed",
            published[:5] + bytes([published[5] ^ 1]) + published[6:],
            [OBF_X25519_SK],
            None,
            "NOT_OPENED",
        ),
        (
            "an enc of small order, whose X25519 output is all zero",
            b"\x01" + bytes(32) + published[33:],
            [OBF_X25519_SK],
            None,
            "NOT_OPENED",
        ),
        (
            "a plaintext without the byte 80",
            sealed(MEMO_MSG, OBF_X25519, "padding case 1", MEMO_MSG + bytes(1024 - len(MEMO_MSG))),
            [OBF_X25519_SK],
            None,
            "PADDING_INVALID",
        ),
        (
            "a plaintext with 80 followed by a byte other than zero",
            sealed(
                MEMO_MSG,
                OBF_X25519,
                "padding case 2",
                MEMO_MSG + b"\x80" + bytes(1022 - len(MEMO_MSG)) + b"\x01",
            ),
            [OBF_X25519_SK],
            None,
            "PADDING_INVALID",
        ),
        (
            "a plaintext of zero bytes only",
            sealed(MEMO_MSG, OBF_X25519, "padding case 3", bytes(1024)),
            [OBF_X25519_SK],
            None,
            "PADDING_INVALID",
        ),
    ]
    for label, data, sks, message, error in opens:
        c.add(
            "open",
            ("open " if error is None else "reject ") + label,
            ["keys.md 4.5"],
            {"sealed": B(data), "private_keys": [H(k) for k in sks]},
            accept({"message": B(message)}) if error is None else reject(error),
        )
    return c


# --- the decoded meaning of an Avro value (spec/conformance.md, section 3.3) -------------


def raw_schema(t: Any) -> Any:
    return fastavro.parse_schema(pe.without_logical_types(t), _write_hint=False)


def name_of(t: dict[str, Any], names: dict[str, Any]) -> None:
    """Enter a named type into names by its name and its full name, as meaning finds it."""
    full = (
        t["name"]
        if "." in t["name"]
        else ".".join(x for x in (t.get("namespace", names.get("", "")), t["name"]) if x)
    )
    names[t["name"]] = names[full] = t
    if "namespace" in t:
        names[""] = t["namespace"]


def names_in(t: Any, names: dict[str, Any]) -> None:
    """Enter every named type that the type defines into names, as meaning would for a value of it."""
    if isinstance(t, list):
        for b in t:
            names_in(b, names)
    elif isinstance(t, dict):
        if t["type"] in ("record", "enum", "fixed"):
            name_of(t, names)
        for f in t.get("fields", []):
            names_in(f["type"], names)
        for member in ("items", "values"):
            if member in t:
                names_in(t[member], names)


def meaning(t: Any, value: Any, names: dict[str, Any] | None = None) -> Any:
    """A decoded Avro value as JSON: bytes and fixed as hex, logical types as their underlying values."""
    names = {} if names is None else names
    if isinstance(t, str):
        if t in names:
            return meaning(names[t], value, names)
        if t == "bytes":
            return (
                value.encode("latin-1") if isinstance(value, str) else value
            ).hex()  # fastavro 1.13.1 and bytes defaults
        return value
    if isinstance(t, list):
        if value is None:
            return None
        branches = [b for b in t if b != "null"]

        def full_of(b: Any) -> str:
            n = b if isinstance(b, str) else b["name"]
            return n if "." in n else f"{names.get('', '')}.{n}"

        if (
            isinstance(value, dict)
            and len(value) == 1
            and next(iter(value)) in {full_of(b) for b in branches}
        ):
            # The bricks of a description, read with their names: the branch is the member's name.
            ((name, inner),) = value.items()
            return {name: meaning(next(b for b in branches if full_of(b) == name), inner, names)}
        if len(branches) > 1:
            # The targets of axt.Relation, the only other union of the vectors: the branch is the record
            # whose fields the value has (spec/conformance.md, section 3.3).
            branches = [
                b
                for b in branches
                if {f["name"] for f in (names[b] if isinstance(b, str) else b)["fields"]} == set(value)
            ]
        assert len(branches) == 1, "the vectors use only unions of null and one type, and the targets"
        return meaning(branches[0], value, names)
    kind = t["type"]
    if kind in ("record", "enum", "fixed"):
        name_of(t, names)
    if kind == "record":
        return {f["name"]: meaning(f["type"], value[f["name"]], names) for f in t["fields"]}
    if kind == "fixed":
        return value.hex()
    if kind == "array":
        if not value:
            names_in(t["items"], names)  # an empty array defines the named types of its items all the same
        return [meaning(t["items"], v, names) for v in value]
    if kind == "map":
        if not value:
            names_in(t["values"], names)
        return {k: meaning(t["values"], v, names) for k, v in value.items()}
    if kind == "enum":
        return value
    return meaning(kind, value, names)


def avro_encode(t: Any, datum: Any) -> bytes:
    buf = io.BytesIO()
    fastavro.schemaless_writer(buf, fastavro.parse_schema(t, _write_hint=False), datum)
    return buf.getvalue()


def single_object(text: str, datum: Any) -> bytes:
    return cast(bytes, b"\xc3\x01" + pe.fp8(pe.canonical_fp(text)) + avro_encode(json.loads(text), datum))


def decode_meaning(writer_text: str, reader_text: str | None, data: bytes) -> Any:
    w = json.loads(writer_text)
    r = json.loads(reader_text) if reader_text else w
    value = fastavro.schemaless_reader(io.BytesIO(data), raw_schema(w), raw_schema(r))
    return meaning(r, value)


# --- encoding (spec/envelope.md) ----------------------------------------------------


def envelope(
    kind: str | int,
    sender: bytes,
    record: Any,
    body: bytes,
    signature: bytes,
    fmt: int = 1,
    fp: bytes | None = None,
) -> bytes:
    """A live message built field by field, without checks: for messages that break a rule."""
    zz: Callable[[int], bytes] = keys.zigzag
    kind_index = pe.KINDS.index(kind) if isinstance(kind, str) else kind
    out = b"\xc3\x01" + (ENVELOPE_FP if fp is None else fp) + zz(fmt) + zz(kind_index) + sender
    if record is None:
        out += zz(0)
    else:
        rid = record[0] if isinstance(record[0], bytes) else record[0].encode()
        out += zz(1) + zz(len(rid)) + rid + zz(record[1])
    return out + zz(len(body)) + body + signature


def signed(
    seed: bytes, kind: str | int, record: Any, body: bytes, fmt: int = 1, fp: bytes | None = None
) -> bytes:
    m = envelope(kind, keys.public_key(seed), record, body, bytes(64), fmt, fp)
    return cast(bytes, m[:-64] + keys.sign(seed, keys.MESSAGE_PREFIX + m[10:-64]))


def message_meaning(m: bytes) -> dict[str, Any]:
    d: Any = fastavro.schemaless_reader(io.BytesIO(m[10:]), pe.raw["Envelope"], pe.raw["Envelope"])
    rec = d["record"]
    return {
        "format": d["format"],
        "kind": d["kind"],
        "sender": H(d["sender"]),
        "record": None if rec is None else {"id": rec["id"], "version": rec["version"]},
        "body": B(d["body"]),
        "signature": H(d["signature"]),
    }


MAX_MESSAGE = pe.MAX_MESSAGE


def encoding_category() -> Category:
    c = Category(
        "encoding",
        "Fingerprints and canonical forms, and the envelope of every message in a live connection "
        "(spec/envelope.md).",
    )
    # Fingerprints: Avro's published cases, logical types, the schemas of the specification.
    published: Any
    for text, published in [
        ('"null"', 7195948357588979594),
        ('"boolean"', -6970731678124411036),
        ('"int"', 8247732601305521295),
    ]:
        fp = rules.crc64_avro(text.encode())
        assert fp - (1 << 64) * (fp >= 1 << 63) == published
        c.add(
            "fingerprint",
            f"the published Avro fingerprint of {text}",
            ["envelope.md 5"],
            {"schema": text},
            accept({"canonical_form": text, "fingerprint": H(fp.to_bytes(8, "little"))}),
        )
    for text, pcf in [
        ('{"type":"string","logicalType":"uuid"}', '"string"'),
        ('{"type":"long","logicalType":"timestamp-millis"}', '"long"'),
        ('{"type":"int","logicalType":"date"}', '"int"'),
    ]:
        got, fp = me.fingerprint(text)
        assert got == pcf
        c.add(
            "fingerprint",
            f"a primitive with a logical type, {text}, is written as its primitive",
            ["envelope.md 5"],
            {"schema": text},
            accept({"canonical_form": pcf, "fingerprint": H(pe.fp8(fp))}),
        )
    memo_text = json.dumps(env.MEMO_SCHEMA)
    pcf, fp = me.fingerprint(memo_text)
    assert fp == 0x37F20E16CADCAC73
    c.add(
        "fingerprint",
        "com.example.Memo of envelope.md, section 10.1",
        ["envelope.md 5", "envelope.md 10.1"],
        {"schema": memo_text},
        accept({"canonical_form": pcf, "fingerprint": H(pe.fp8(fp))}),
    )
    published = {
        "Envelope": 0xA89ECEB9716F3016,
        "Manifest": 0xA59EEB4C88A51F3E,
        "DeviceJoin": 0xDFF876FAB5FECF2F,
        "DeviceAdd": 0xC60D1EF44B7B3131,
        "DeviceRemove": 0xD0F57582AAB2AADC,
        "Offer": 0x8A0DFC77B054B97F,
        "Accept": 0x6B244FC3913D82AB,
        "Decline": 0x70078F60F3BA4953,
        "Ack": 0x38DD09198076E05C,
        "Error": 0x7CA5B3D13DBCF383,
        "QrPayload": 0xDDBCA858F745D131,
        "Change": 0x4D094DAFC5F888C1,
        "Resync": 0xE8762BD9D559FDF1,
        "Forward": 0x57476ABF6B053BAD,
        "Withdraw": se.WITHDRAW_FP,
        "Proposal": 0x2512222A12D90279,
        "ProposalReply": 0x64610CE36E75F8C6,
        "Field": 0xE50FE3675C626251,
    }
    sections = {
        "Envelope": "envelope.md 10.1",
        "Manifest": "manifest.md 9",
        "DeviceJoin": "keys.md 6",
        "DeviceAdd": "keys.md 6",
        "DeviceRemove": "keys.md 6",
        "QrPayload": "transports.md 6",
        "Change": "sync.md 15",
        "Resync": "sync.md 15",
        "Forward": "sync.md 15",
        "Withdraw": "shares.md 10",
        "Proposal": "shares.md 10",
        "ProposalReply": "shares.md 10",
        "Field": "fields.md 2",
    }
    for name, want in published.items():
        text = (REPO / "types" / "axt" / f"{name}.avsc").read_text(encoding="utf-8")
        pcf, fp = me.fingerprint(text)
        assert fp == want, name
        c.add(
            "fingerprint",
            f"axt.{name}, as types/axt/{name}.avsc holds it",
            ["envelope.md 5", sections.get(name, "protocol.md 16")],
            {"schema": text},
            accept({"canonical_form": pcf, "fingerprint": H(pe.fp8(fp))}),
        )

    # Decoding the envelope of a live message.
    upper = MEMO_MSG.replace(env.RECORD_ID.encode(), env.RECORD_ID.upper().encode())
    goods = [
        ("the DATA message of envelope.md, section 10.2", MEMO_MSG, ["envelope.md 10.2", "keys.md 7.2"]),
        ("the DATA message with its record id in upper case, kept as received", upper, ["envelope.md 7"]),
        ("the DEVICE_ADD of keys.md, section 7.5", ADD_MSG, ["keys.md 7.5"]),
        ("the DEVICE_JOIN that carried the proof of keys.md, section 7.5", JOIN_MSG, ["keys.md 5.2"]),
        ("a DEVICE_REMOVE of the old phone by the new one", pe.device_remove(NEW_SEED, CAT), ["keys.md 5.3"]),
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
    # The kinds of spec/shares.md; every kind of format 1 has a document that defines it.
    assert [k for k in pe.KINDS if k not in pe.BODY_SCHEMA and k not in pe.RECORD_KINDS] == []
    goods += [
        ("the WITHDRAW of shares.md, section 11.2", WITHDRAW_MSG, ["shares.md 3.1", "shares.md 11.2"]),
        ("the PROPOSAL of shares.md, section 11.4", PROPOSAL_MSG, ["shares.md 13.1", "shares.md 11.4"]),
        ("the PROPOSAL_REPLY of shares.md, section 11.5", REPLY_MSG, ["shares.md 14.1", "shares.md 11.5"]),
    ]
    # The messages between the devices of one set (spec/sync.md, section 16).
    sync_messages = [
        ("the CHANGE of sync.md, section 16.2", ["sync.md 8.1", "sync.md 16.2"]),
        ("the RESYNC of sync.md, section 16.3", ["sync.md 11.1", "sync.md 16.3"]),
        ("the whole CHANGE of sync.md, section 16.4", ["sync.md 8.1", "sync.md 16.4"]),
        ("the FORWARD of sync.md, section 16.5", ["sync.md 18.1", "sync.md 16.5"]),
        ("the CHANGE of sync.md, section 16.7", ["sync.md 21.3", "sync.md 16.7"]),
    ]
    # The messages of Old Brain Fix that the FORWARD of section 16.5 and the one before it carry are
    # those that the other documents show.
    assert sy.EXAMPLE_OTHERS["the MANIFEST of Old Brain Fix"] == pe.m2
    assert (
        sy.APPOINTMENT_OFFERED == pe.fe.derived_text(pe.offered({"schema": pe.APPOINTMENT_TEXT}))
        and sy.KEY_OBF == OBF
    )
    assert [pe.fp8(pe.fingerprints[n][1]) for n in pe.SYNC] == [sy.SPEC_FP[n] for n in pe.SYNC]
    goods += [(label, sy.EXAMPLE_MESSAGES[label], refs) for label, refs in sync_messages]
    for label, m, refs in goods:
        c.add(
            "decode_message",
            label,
            ["envelope.md 2", "envelope.md 3"] + refs,
            {"message": B(m)},
            accept(message_meaning(m)),
        )

    m = MEMO_MSG
    sig = m[-64:]
    bads = [
        ("a message of 16 MiB and one byte", above, "TOO_LARGE", ["envelope.md 8"]),
        (
            "an envelope fingerprint of no format",
            m[:2] + bytes(8) + m[10:],
            "FORMAT_UNSUPPORTED",
            ["envelope.md 3.1"],
        ),
        (
            "the fingerprint of axt.Manifest in place of the envelope's",
            m[:2] + pe.fp8(pe.fingerprints["Manifest"][1]) + m[10:],
            "FORMAT_UNSUPPORTED",
            ["envelope.md 3.1"],
        ),
        ("no single-object marker", b"\xc3\x02" + m[2:], "INVALID_MESSAGE", ["envelope.md 3"]),
        ("fewer than 10 bytes", m[:9], "INVALID_MESSAGE", ["envelope.md 3"]),
        ("a byte left over after the envelope", m + b"\x00", "INVALID_MESSAGE", ["envelope.md 3"]),
        ("the last byte of the signature missing", m[:-1], "INVALID_MESSAGE", ["envelope.md 3"]),
        (
            "format 2 under the fingerprint of format 1",
            m[:10] + keys.zigzag(2) + m[11:],
            "INVALID_MESSAGE",
            ["envelope.md 2.1", "keys.md 2.2"],
        ),
        (
            "kind index 17, which format 1 does not have",
            m[:11] + keys.zigzag(len(pe.KINDS)) + m[12:],
            "INVALID_MESSAGE",
            ["envelope.md 2.2"],
        ),
        ("a negative kind index", m[:11] + keys.zigzag(-1) + m[12:], "INVALID_MESSAGE", ["envelope.md 2.2"]),
        ("record union index 2", m[:0x2C] + keys.zigzag(2) + m[0x2D:], "INVALID_MESSAGE", ["envelope.md 2"]),
        (
            "a negative length of the record id",
            m[:0x2D] + keys.zigzag(-36) + m[0x2E:],
            "INVALID_MESSAGE",
            ["envelope.md 8"],
        ),
        (
            "a negative length of the body",
            envelope("DATA", CAT, (env.RECORD_ID, 1), b"", sig)[:0x53]
            + keys.zigzag(-(len(m) - 0x54 - 64))
            + m[0x54:],
            "INVALID_MESSAGE",
            ["envelope.md 8"],
        ),
        (
            "a body length of 2^40, beyond the end",
            m[:0x53] + keys.zigzag(1 << 40) + m[0x54:],
            "INVALID_MESSAGE",
            ["envelope.md 8"],
        ),
        (
            "a record id that is not UTF-8 (byte ff)",
            envelope("DATA", CAT, (b"\xff" + env.RECORD_ID.encode()[1:], 1), m[0x54:-64], sig),
            "INVALID_MESSAGE",
            ["envelope.md 7"],
        ),
        (
            "a record id with an encoded surrogate (ed a0 80)",
            envelope("DATA", CAT, (b"\xed\xa0\x80" + env.RECORD_ID.encode()[3:], 1), m[0x54:-64], sig),
            "INVALID_MESSAGE",
            ["envelope.md 7"],
        ),
        (
            "a record id with an overlong encoding (c0 af)",
            envelope("DATA", CAT, (b"\xc0\xaf" + env.RECORD_ID.encode()[2:], 1), m[0x54:-64], sig),
            "INVALID_MESSAGE",
            ["envelope.md 7"],
        ),
    ]
    for label, msg, error, refs in bads:
        c.add("decode_message", f"reject {label}", refs, {"message": B(msg)}, reject(error))

    # The bodies of the kinds whose schema the specification publishes.
    for label, msg, refs in goods:
        d: Any = fastavro.schemaless_reader(io.BytesIO(msg[10:]), pe.raw["Envelope"], pe.raw["Envelope"])
        if d["kind"] not in pe.BODY_SCHEMA:
            continue
        name = pe.BODY_SCHEMA[d["kind"]]
        body = d["body"]
        value = meaning(pe.jsons[name], pe.read_body(body[10:], pe.raw[name]))
        c.add(
            "decode_body",
            f"the body of {label}",
            ["envelope.md 2.3"] + refs,
            {"kind": d["kind"], "body": B(body)},
            accept({"value": value}),
        )
    ack_envelope: Any = fastavro.schemaless_reader(
        io.BytesIO(pe.ack_msg[10:]), pe.raw["Envelope"], pe.raw["Envelope"]
    )
    ack_body: bytes = ack_envelope["body"]
    outcome_at = (
        ack_body.index(bytes.fromhex("0200"), 10 + 32 + 1 + 1 + 36) + 1
    )  # version 1, then outcome APPLIED
    assert ack_body[outcome_at] == 0
    change_body, resync_body = (
        cast(bytes, sy.read_all("Envelope", sy.EXAMPLE_MESSAGES[label][10:])["body"])
        for label in ("the CHANGE of sync.md, section 16.2", "the RESYNC of sync.md, section 16.3")
    )
    assert change_body[10 + 32] == 0  # origin: union index 0, null
    withdraw_body = cast(bytes, sy.read_all("Envelope", WITHDRAW_MSG[10:])["body"])
    proposal_body = cast(bytes, sy.read_all("Envelope", PROPOSAL_MSG[10:])["body"])
    reply_body = cast(bytes, sy.read_all("Envelope", REPLY_MSG[10:])["body"])
    assert reply_body[-1] == 0  # answer: enum index 0, ACCEPTED
    at = proposal_body.index(b"start") + 5  # the fingerprint of the entry, then the value
    proposal_short = proposal_body[:at] + proposal_body[at + 1 :]
    forward: bytes = sy.EXAMPLE_MESSAGES["the FORWARD of sync.md, section 16.5"]
    forward_body = cast(bytes, sy.read_all("Envelope", forward[10:])["body"])
    schema_head = keys.zigzag(1) + keys.zigzag(len(sy.APPOINTMENT_OFFERED.encode()))  # union index, length
    schema_at = len(forward_body) - len(sy.APPOINTMENT_OFFERED.encode()) - len(schema_head)
    assert forward_body[schema_at : schema_at + len(schema_head)] == schema_head
    without_schema = sy.body_of("Forward", {"to": sy.TABLET, "message": pe.m2, "schema": None})
    c.add(
        "decode_body",
        "the body of a FORWARD of a MANIFEST, whose schema is null",
        ["envelope.md 2.3", "sync.md 18.1"],
        {"kind": "FORWARD", "body": B(without_schema)},
        accept({"value": {"to": H(sy.TABLET), "message": H(pe.m2), "schema": None}}),
    )
    for label, kind, body in [
        ("an ACK body with a byte left over", "ACK", ack_body + b"\x00"),
        ("an ACK body cut short", "ACK", ack_body[:-1]),
        (
            "an ACK body with the fingerprint of axt.Error",
            "ACK",
            ack_body[:2] + pe.fp8(pe.fingerprints["Error"][1]) + ack_body[10:],
        ),
        (
            "an ACK body with an outcome index of 6",
            "ACK",
            ack_body[:outcome_at] + keys.zigzag(len(pe.OUTCOME["symbols"])) + ack_body[outcome_at + 1 :],
        ),
        ("an empty body for an ACK", "ACK", b""),
        ("a WITHDRAW body with a byte left over", "WITHDRAW", withdraw_body + b"\x00"),
        ("a WITHDRAW body whose key has 31 bytes", "WITHDRAW", withdraw_body[:-1]),
        (
            "a WITHDRAW body with the fingerprint of axt.Resync",
            "WITHDRAW",
            withdraw_body[:2] + sy.SPEC_FP["Resync"] + withdraw_body[10:],
        ),
        ("a WITHDRAW body of the RESYNC schema", "WITHDRAW", resync_body),
        ("an empty body for a WITHDRAW", "WITHDRAW", b""),
        ("a PROPOSAL body with a byte left over", "PROPOSAL", proposal_body + b"\x00"),
        ("a PROPOSAL body cut short", "PROPOSAL", proposal_body[:-1]),
        (
            "a PROPOSAL body with the fingerprint of axt.ProposalReply",
            "PROPOSAL",
            proposal_body[:2] + sy.SPEC_FP["ProposalReply"] + proposal_body[10:],
        ),
        ("a PROPOSAL body whose schema has 7 bytes", "PROPOSAL", proposal_short),
        ("a PROPOSAL body of the WITHDRAW schema", "PROPOSAL", withdraw_body),
        ("an empty body for a PROPOSAL", "PROPOSAL", b""),
        ("a PROPOSAL_REPLY body with a byte left over", "PROPOSAL_REPLY", reply_body + b"\x00"),
        ("a PROPOSAL_REPLY body cut short", "PROPOSAL_REPLY", reply_body[:-1]),
        (
            "a PROPOSAL_REPLY body with an answer index of 2",
            "PROPOSAL_REPLY",
            reply_body[:-1] + keys.zigzag(2),
        ),
        (
            "a PROPOSAL_REPLY body with the fingerprint of axt.Proposal",
            "PROPOSAL_REPLY",
            reply_body[:2] + sy.SPEC_FP["Proposal"] + reply_body[10:],
        ),
        ("an empty body for a PROPOSAL_REPLY", "PROPOSAL_REPLY", b""),
        ("a CHANGE body with a byte left over", "CHANGE", change_body + b"\x00"),
        ("a CHANGE body cut short", "CHANGE", change_body[:-1]),
        (
            "a CHANGE body with the fingerprint of axt.Resync",
            "CHANGE",
            change_body[:2] + sy.SPEC_FP["Resync"] + change_body[10:],
        ),
        (
            "a CHANGE body with origin union index 2",
            "CHANGE",
            change_body[: 10 + 32] + keys.zigzag(2) + change_body[10 + 33 :],
        ),
        ("a FORWARD body with a byte left over", "FORWARD", forward_body + b"\x00"),
        ("a FORWARD body cut short", "FORWARD", forward_body[:-1]),
        ("a FORWARD body cut within its message", "FORWARD", forward_body[:200]),
        ("a FORWARD body whose key has 31 bytes", "FORWARD", forward_body[:10] + forward_body[11:]),
        (
            "a FORWARD body with the fingerprint of axt.Change",
            "FORWARD",
            forward_body[:2] + sy.SPEC_FP["Change"] + forward_body[10:],
        ),
        (
            "a FORWARD body with schema union index 2",
            "FORWARD",
            forward_body[:schema_at] + keys.zigzag(2) + forward_body[schema_at + 1 :],
        ),
        (
            "a FORWARD body whose schema is no UTF-8",
            "FORWARD",
            forward_body[: schema_at + len(schema_head)]
            + b"\xff"
            + forward_body[schema_at + len(schema_head) + 1 :],
        ),
        ("a FORWARD body of the RESYNC schema", "FORWARD", resync_body),
        ("an empty body for a FORWARD", "FORWARD", b""),
        ("a RESYNC body whose key has 31 bytes", "RESYNC", resync_body[:-1]),
        ("a RESYNC body of the CHANGE schema", "RESYNC", change_body),
        (
            "a MANIFEST body of the DEVICE_ADD schema",
            "MANIFEST",
            cast(
                Any,
                fastavro.schemaless_reader(io.BytesIO(ADD_MSG[10:]), pe.raw["Envelope"], pe.raw["Envelope"]),
            )["body"],
        ),
    ]:
        c.add(
            "decode_body",
            f"reject {label}",
            ["envelope.md 2.3", "envelope.md 3.1", "protocol.md 8.2"],
            {"kind": kind, "body": B(body)},
            reject("INVALID_MESSAGE"),
        )

    for label, msg in [
        ("the DATA message of envelope.md, section 10.2", MEMO_MSG),
        ("the DATA message with its record id in upper case", upper),
        ("the DEVICE_ADD of keys.md, section 7.5", ADD_MSG),
        ("the MANIFEST of cat-a-log of manifest.md, section 10.3", pe.m1),
        ("a DELETE, with an empty body", pe.del_unknown),
        ("the WITHDRAW of shares.md, section 11.2", WITHDRAW_MSG),
        ("the PROPOSAL of shares.md, section 11.4", PROPOSAL_MSG),
        ("the PROPOSAL_REPLY of shares.md, section 11.5", REPLY_MSG),
    ]:
        d = message_meaning(msg)
        c.add("encode_message", label, ["envelope.md 2", "envelope.md 3"], d, accept({"message": B(msg)}))
    return c


# --- types (spec/types.md) -------------------------------------------------------------

EXAMPLES = REPO / "types" / "axt" / "example" / "v1"
# The example types (spec/types.md, section 7.3), each published as its description, with one version.
TYPE_FPS = {
    "Appointment": 0x10D0737094DBAD25,
    "Car": 0x69F6C9B3011D6449,
    "Document": 0xB9B0BF18FAA7A1AE,
    "Measurement": 0xBEC4B5C9BCCD12DA,
    "Note": 0x7CE83C7900093771,
    "Person": 0xF170F92B8540A13F,
    "Pet": 0xB5D0DAB082CB46EA,
    "Task": 0x4E1B59A67C4C64D9,
}
RELATION_FP = 0x190BF11052CF9F10
EXTENSION_FP = 0x636F04D4D973A062


def types_category() -> Category:
    c = Category(
        "types",
        "The example types: fingerprints, the bytes and meaning of a record of each, and schema "
        "resolution with defaults, unknown symbols, aliases and the data depth limit (spec/types.md).",
    )
    texts = {}
    for name, want in TYPE_FPS.items():
        path = EXAMPLES / f"{name}.1.avsc"
        text = path.read_text(encoding="utf-8")
        texts[name] = pe.compact(path)
        pcf, fp = me.fingerprint(text)
        assert fp == want and pe.canonical_fp(texts[name]) == want, name
        c.add(
            "fingerprint",
            f"axt.example.v1.{name}, version 1",
            ["types.md 3.4", "types.md 7.3"],
            {"schema": text},
            accept({"canonical_form": pcf, "fingerprint": H(pe.fp8(fp))}),
        )

    def record_vector(
        label: str,
        refs: list[str],
        writer_text: str,
        reader_text: str | None,
        data: bytes,
        expected: Any = None,
    ) -> None:
        if expected is None:
            expected = accept({"value": decode_meaning(writer_text, reader_text, data[10:])})
        c.add(
            "decode_record",
            label,
            refs,
            {"writer_schema": writer_text, "reader_schema": reader_text, "body": B(data)},
            expected,
        )

    for name in TYPE_FPS:
        schema = json.loads(texts[name])
        datum = rules.DATA[name]
        body = single_object(texts[name], datum)
        decode_meaning(texts[name], None, body[10:])
        record_vector(
            f"a record of axt.example.v1.{name}", ["types.md 7", "envelope.md 2.3"], texts[name], None, body
        )
        # Every default, through schema resolution (spec/types.md, section 5.4).
        reduced = rules.without_defaults(schema)
        if reduced["fields"] != schema["fields"]:
            wtext = json.dumps(reduced, separators=(",", ":"), ensure_ascii=False)
            record_vector(
                f"axt.example.v1.{name} written without its fields that have a default, "
                "read with every default",
                ["types.md 5.4", "envelope.md 6"],
                wtext,
                texts[name],
                single_object(wtext, rules.project(schema, datum)),
            )
        nested = rules.nested_arrays(schema)
        if nested:
            ndatum = dict(datum, **{f["name"]: datum[f["name"]][:1] for f in nested})
            wtext = json.dumps(
                rules.without_defaults(schema, nested_only=True), separators=(",", ":"), ensure_ascii=False
            )
            record_vector(
                f"axt.example.v1.{name} written without the defaulted fields of its nested records",
                ["types.md 5.4", "envelope.md 6"],
                wtext,
                texts[name],
                single_object(wtext, rules.project(schema, ndatum, nested_only=True)),
            )
        for i, f in enumerate(schema["fields"]):
            if isinstance(f["type"], dict) and f["type"]["type"] == "enum":
                writer = copy.deepcopy(schema)
                writer["fields"][i]["type"]["symbols"].append("SYMBOL_OF_A_LATER_VERSION")
                wtext = json.dumps(writer, separators=(",", ":"), ensure_ascii=False)
                data = single_object(wtext, dict(datum, **{f["name"]: "SYMBOL_OF_A_LATER_VERSION"}))
                got = decode_meaning(wtext, texts[name], data[10:])
                assert got[f["name"]] == f["type"]["default"]
                record_vector(
                    f"axt.example.v1.{name}: an unknown symbol of {f['name']} "
                    f"reads as the default {f['type']['default']}",
                    ["types.md 5.4", "envelope.md 6"],
                    wtext,
                    texts[name],
                    data,
                )

    # All-day and floating times, and values that break a rule (example_types.py). decode_record rejects a
    # time value that is not valid; a value that only breaks a check of an attribute is taken
    # (spec/conformance.md, section 5.2).
    assert (len(rules.VALID), len(rules.BREACHES)) == (10, 17)
    for label, name, datum in rules.VALID:
        record_vector(
            f"axt.example.v1.{name}: {label}",
            ["types.md 5.6", "time.md 6", "time.md 8"],
            texts[name],
            None,
            single_object(texts[name], datum),
        )
    for label, name, datum, _path, _rule in rules.BREACHES:
        schema = json.loads(texts[name])
        found = tm.value_breaches(schema, datum)
        expected = reject("VALUE_INVALID", found[0][2], field=found[0][0]) if found else None
        record_vector(
            f"{'reject' if found else 'take'} axt.example.v1.{name}: {label}",
            ["time.md 8", "metadata.md 7.2"] if found else ["metadata.md 7.1", "conformance.md 5.13"],
            texts[name],
            None,
            single_object(texts[name], datum),
            expected,
        )

    ap_text, ap = texts["Appointment"], rules.DATA["Appointment"]
    ap_body = single_object(ap_text, ap)
    # The reminders, two axt.Duration, in two array blocks, the first with a negative count and its size
    # (Avro 1.12, Arrays).
    first, second = (
        b"".join(keys.zigzag(d[k]) for k in ("months", "days", "millis")) for d in ap["reminders"]
    )
    one_block = keys.zigzag(2) + first + second + keys.zigzag(0)
    assert ap_body.count(one_block) == 1
    blocks = keys.zigzag(-1) + keys.zigzag(len(first)) + first + keys.zigzag(1) + second + keys.zigzag(0)
    record_vector(
        "axt.example.v1.Appointment with its reminders in two array blocks, one with a negative count",
        ["envelope.md 1"],
        ap_text,
        None,
        ap_body.replace(one_block, blocks),
        accept({"value": decode_meaning(ap_text, None, ap_body[10:])}),
    )
    title = ap["title"].encode()
    bads = [
        (
            "a byte left over after the record",
            ap_body + b"\x00",
            "UNDECODABLE",
            ["types.md 5.7", "protocol.md 6.2"],
        ),
        ("the last byte missing", ap_body[:-1], "UNDECODABLE", ["protocol.md 6.2"]),
        (
            "a title that is not UTF-8",
            ap_body.replace(title, b"\xff" + title[1:]),
            "UNDECODABLE",
            ["envelope.md 7"],
        ),
        (
            "a title with an encoded surrogate",
            ap_body.replace(title, b"\xed\xb0\x80" + title[3:]),
            "UNDECODABLE",
            ["envelope.md 7"],
        ),
        (
            "a negative string length",
            ap_body[:10] + keys.zigzag(-16) + ap_body[11:],
            "UNDECODABLE",
            ["envelope.md 8"],
        ),
        (
            "a string length beyond the end",
            ap_body[:10] + keys.zigzag(1 << 40) + ap_body[11:],
            "UNDECODABLE",
            ["envelope.md 8"],
        ),
        (
            "an array count of 2^40 beyond the end",
            ap_body.replace(one_block, keys.zigzag(1 << 40) + one_block[1:]),
            "UNDECODABLE",
            ["envelope.md 8"],
        ),
        (
            "a body whose fingerprint is not that of the writer schema",
            ap_body[:2] + pe.fp8(TYPE_FPS["Task"]) + ap_body[10:],
            "SCHEMA_UNKNOWN",
            ["envelope.md 3.1"],
        ),
    ]
    for label, data, error, refs in bads:
        record_vector(
            f"reject axt.example.v1.Appointment with {label}", refs, ap_text, None, data, reject(error)
        )

    # Resolution by name: aliases, other names, fields without a default.
    pet = json.loads(texts["Pet"])
    app_pet = dict(pet, namespace="org.example.catalog")
    app_text = json.dumps(app_pet, separators=(",", ":"), ensure_ascii=False)
    pet_body = single_object(app_text, rules.DATA["Pet"])
    alias_reader = json.dumps(
        dict(pet, aliases=["org.example.catalog.Pet"]), separators=(",", ":"), ensure_ascii=False
    )
    record_vector(
        "an app type read as axt.example.v1.Pet through an alias of the reader schema",
        ["types.md 4", "envelope.md 6"],
        app_text,
        alias_reader,
        pet_body,
    )
    record_vector(
        "reject an app type of the same fields under another name, without an alias",
        ["types.md 4", "envelope.md 6"],
        app_text,
        texts["Pet"],
        pet_body,
        reject("DOES_NOT_RESOLVE"),
    )
    narrow = json.loads(ap_text)
    narrow["fields"].append(
        {"name": "room", "type": "string", "doc": "A field without a default that the writer lacks."}
    )
    record_vector(
        "reject a reader schema with a field that has no default and that the writer lacks",
        ["envelope.md 6"],
        ap_text,
        json.dumps(narrow, separators=(",", ":"), ensure_ascii=False),
        ap_body,
        reject("DOES_NOT_RESOLVE"),
    )
    wider = json.loads(texts["Pet"])
    wider["fields"].append(
        {"name": "colour", "type": "string", "default": "", "doc": "A field the reader does not have."}
    )
    wtext = json.dumps(wider, separators=(",", ":"), ensure_ascii=False)
    record_vector(
        "a writer field the reader does not have is ignored",
        ["envelope.md 6", "types.md 3.3"],
        wtext,
        texts["Pet"],
        single_object(wtext, dict(rules.DATA["Pet"], colour="tabby")),
    )

    # The data depth limit, with an app type of lists in lists read with its writer schema alone
    # (spec/types.md, section 5.7).
    for levels, ok in [(16, True), (17, False)]:
        datum = pe.outline(levels)
        depth = pe.data_depth(datum)
        data = single_object(pe.OUTLINE_TEXT, datum)
        record_vector(
            f"an app type of lists in lists at data depth {depth}",
            ["types.md 5.7"],
            pe.OUTLINE_TEXT,
            None,
            data,
            None if ok else reject("UNDECODABLE", f"data depth {depth} above 32"),
        )
    relation_vectors(c, texts, record_vector)
    return c


def relation_vectors(c: Category, texts: dict[str, str], record_vector: Callable[..., None]) -> None:
    """The relations of the example types (spec/fields.md, section 11): the fingerprint of axt.Relation, and
    the records of example_types.py with relations, those that break a rule of section 11.4 rejected."""
    assert rules.OTHER_SENDER == pe.CAT, "not the test key of spec/keys.md, section 7.1"
    text = (REPO / "types" / "axt" / "Relation.avsc").read_text(encoding="utf-8")
    pcf, fp = me.fingerprint(text)
    assert fp == RELATION_FP, "axt.Relation"
    c.add(
        "fingerprint",
        "axt.Relation",
        ["types.md 7.3", "fields.md 11.1"],
        {"schema": text},
        accept({"canonical_form": pcf, "fingerprint": H(pe.fp8(fp))}),
    )
    text = (REPO / "types" / "axt" / "Extension.avsc").read_text(encoding="utf-8")
    pcf, fp = me.fingerprint(text)
    assert fp == EXTENSION_FP, "axt.Extension"
    c.add(
        "fingerprint",
        "axt.Extension",
        ["types.md 7.3", "fields.md 12.1"],
        {"schema": text},
        accept({"canonical_form": pcf, "fingerprint": H(pe.fp8(fp))}),
    )
    # The further records with relations and those that break a rule (example_types.py). decode_record
    # rejects a relation that breaks a rule of spec/fields.md, section 11.4, as a time value that is not
    # valid; a value that only breaks a check of an attribute is taken (spec/conformance.md, section 5.2).
    assert (len(rules.RELATION_VALID), len(rules.RELATION_BREACHES)) == (6, 18)
    for label, key, datum in rules.RELATION_VALID:
        name = key.split(".")[0]
        record_vector(
            f"axt.example.v1.{name}: {label}",
            ["fields.md 11"],
            texts[name],
            None,
            single_object(texts[name], datum),
        )
    for label, key, datum, _path, _rule in rules.RELATION_BREACHES:
        name = key.split(".")[0]
        found = tm.value_breaches(json.loads(texts[name]), datum)
        expected = reject("VALUE_INVALID", found[0][2], field=found[0][0]) if found else None
        record_vector(
            f"{'reject' if found else 'take'} axt.example.v1.{name}: {label}",
            ["fields.md 11.4", "metadata.md 7.2"] if found else ["metadata.md 7.1", "conformance.md 5.13"],
            texts[name],
            None,
            single_object(texts[name], datum),
            expected,
        )
    # Extensions (spec/fields.md, section 12): the bytes of a type no receiver knows are taken as they are.
    for label, key, datum in rules.EXTENSION_VALID:
        record_vector(
            f"axt.example.v1.{key}: {label}",
            ["fields.md 12"],
            texts[key],
            None,
            single_object(texts[key], datum),
        )
    for label, key, datum, path, rule in rules.EXTENSION_BREACHES:
        found = tm.value_breaches(json.loads(texts[key]), datum)
        assert found and (found[0][0], found[0][1]) == (path, rule), (label, found)
        record_vector(
            f"reject axt.example.v1.{key}: {label}",
            ["fields.md 12.3", "metadata.md 7.2"],
            texts[key],
            None,
            single_object(texts[key], datum),
            reject("VALUE_INVALID", found[0][2], field=found[0][0]),
        )
    # A target whose union index is that of no branch.
    pet, relation = rules.DATA["Pet"], rules.RELATIONS["Pet"][0]
    body = single_object(texts["Pet"], pet)
    head = b"".join(keys.zigzag(len(x.encode())) + x.encode() for x in (relation["id"], relation["kind"]))
    assert body.count(head + b"\x00") == 1
    record_vector(
        "reject axt.example.v1.Pet, with a relation whose target has the union index 2",
        ["envelope.md 1", "fields.md 11.3"],
        texts["Pet"],
        None,
        body.replace(head + b"\x00", head + keys.zigzag(2)),
        reject("UNDECODABLE"),
    )


# --- time (spec/time.md) -----------------------------------------------------------------


def time_category() -> Category:
    c = Category(
        "time",
        "The time types: fingerprints, the bytes and meaning of their values, the values that are not "
        "valid, a type that holds several of them, other zone rules, and the addition of a duration "
        "(spec/time.md).",
    )
    for n in tm.NAMES:
        text = tm.texts[n]
        pcf, fp = me.fingerprint(text)
        assert (pcf, fp) == tm.fingerprints[n], n
        c.add(
            "fingerprint",
            f"axt.{n}",
            ["time.md 2", "time.md 9.1"],
            {"schema": text},
            accept({"canonical_form": pcf, "fingerprint": H(pe.fp8(fp))}),
        )
    # The counts of spec/time.md, section 9.
    assert (len(tm.EDGES), len(tm.INVALID), len(tm.ADDITIONS), len(tm.RESOLUTIONS)) == (22, 45, 22, 10)
    refs = {"Date": "time.md 4", "Time": "time.md 5", "DateTime": "time.md 6.2", "Duration": "time.md 7.1"}

    def record_vector(label: str, refs_: list[str], text: str, data: bytes, expected: Any) -> None:
        c.add(
            "decode_record",
            label,
            refs_,
            {"writer_schema": text, "reader_schema": None, "body": B(data)},
            expected,
        )

    for label, n, v in tm.EXAMPLES + tm.EDGES:
        text = tm.compact(n)
        body = single_object(text, v)
        value = decode_meaning(text, None, body[10:])
        assert value == v and not tm.problems(n, value), label
        record_vector(f"axt.{n}: {label}", [refs[n], "time.md 9.2"], text, body, accept({"value": value}))
    for label, n, v, rule in tm.INVALID:
        assert tm.problems(n, v) == [rule], label
        text = tm.compact(n)
        assert tm.value_breaches(json.loads(text), v) == [("", f"axt.{n}", rule)], label
        record_vector(
            f"reject {label}",
            [refs[n], "time.md 8"],
            text,
            single_object(text, v),
            reject("VALUE_INVALID", rule, field=""),
        )
    host = json.loads(tm.HOST_TEXT)
    body = single_object(tm.HOST_TEXT, tm.HOST_VALUE)
    assert body[10:] == tm.HOST_DATA and pe.canonical_fp(tm.HOST_TEXT) == tm.HOST_FP
    record_vector(
        "a type that defines axt.DateTime in place and refers to it by its full name",
        ["time.md 3.1", "time.md 9.3"],
        tm.HOST_TEXT,
        body,
        accept({"value": decode_meaning(tm.HOST_TEXT, None, body[10:])}),
    )
    broken = dict(
        tm.HOST_VALUE, end=dict(tm.HOST_VALUE["end"], instant_ms=tm.HOST_VALUE["end"]["instant_ms"] + 1)
    )
    problems = tm.time_problems(host, broken)
    assert problems == ["axt.DateTime: instant_ms is not the wall clock minus offset_seconds"]
    assert tm.value_breaches(host, broken)[0][0] == "end"
    record_vector(
        "reject that type when its second DateTime has an instant a millisecond off",
        ["time.md 3.1", "time.md 8", "metadata.md 7.2"],
        tm.HOST_TEXT,
        single_object(tm.HOST_TEXT, broken),
        reject("VALUE_INVALID", problems[0], field="end"),
    )

    for label, v, anchor, want in tm.RESOLUTIONS:
        assert tm.resolve(v, anchor) == want, label
        c.add(
            "resolve_date_time",
            f"{anchor}: {label}",
            ["time.md 6.4"],
            {"date_time": v, "anchor": anchor},
            accept({"date_time": want}),
        )
    for label, v, d, want in tm.ADDITIONS:
        assert tm.add(v, d) == want, label
        c.add(
            "add_duration",
            label,
            ["time.md 7.2"],
            {"date_time": v, "duration": d},
            accept({"date_time": want}),
        )
    return c


# --- metadata (spec/metadata.md) --------------------------------------------------------


def metadata_category() -> Category:
    c = Category(
        "metadata",
        "The attributes of a schema that tell a receiver how to show and check a field: labels, help "
        "and emoji in a language, the order and groups of fields, formats, patterns and limits, and the "
        "field a check names (spec/metadata.md).",
    )
    vet, loose = mx.VET_TEXT, mx.LOOSE_TEXT

    def describe(label: str, text: str, path: Any, languages: list[str], refs: list[str]) -> None:
        got = mr.describe(json.loads(text), path, languages)
        c.add("describe", label, refs, {"schema": text, "field": path, "languages": languages}, accept(got))

    # The type and its fields, in English, German and a language the type has no text in.
    assert mr.describe(mx.VET, None, ["en"])["fields"] == mx.VET_ORDER
    for languages in (["en"], ["de-AT", "en"], ["fr-CH", "fr"]):
        describe(
            f"com.example.Vet for a user who reads {', '.join(languages)}",
            vet,
            None,
            languages,
            ["metadata.md 4", "metadata.md 5.1", "metadata.md 5.2"],
        )
    for path, languages, refs in [
        ("name", ["de"], ["metadata.md 4", "metadata.md 5.3"]),
        ("kind", ["de"], ["metadata.md 4.4"]),
        ("kind", ["en-GB"], ["metadata.md 4.4"]),
        ("phone", ["en"], ["metadata.md 5.3", "metadata.md 6.3"]),
        ("address", ["de"], ["metadata.md 4", "metadata.md 5.1"]),
        ("address.postal_code", ["de"], ["metadata.md 4.2", "metadata.md 5.3"]),
        ("visit_minutes", ["en"], ["metadata.md 2", "types.md 6"]),
        ("iban", ["de"], ["metadata.md 5.4"]),
        ("notes", ["en"], ["metadata.md 5.3", "metadata.md 6.3"]),
        ("website", ["de"], ["metadata.md 5.2"]),
    ]:
        describe(f"com.example.Vet, the field {path}, for {', '.join(languages)}", vet, path, languages, refs)
    # Attributes that break their rules are ignored, each on its own.
    assert len(mx.LOOSE_PROBLEMS) == 20
    describe(
        "attributes that break their rules are ignored: the type",
        loose,
        None,
        ["de"],
        ["metadata.md 3.3", "metadata.md 5.1"],
    )
    for path, why in [
        ("code", "a pattern outside I-Regexp"),
        ("count", "a format on a number, and a minimum above the maximum"),
        ("title", "translations under the tag en"),
        ("mood", "an emoji that is a word, an unknown format and a bad group"),
        ("address", "a format on the field's type and a multiline that is not a boolean"),
        ("size", "an unknown attribute and a maximum that is not a number"),
        ("rank", "a pattern that is not a string"),
        ("level", "entries of symbols with a member that breaks its rules each"),
    ]:
        describe(
            f"attributes that break their rules are ignored: {path}, {why}",
            loose,
            path,
            ["de"],
            ["metadata.md 3.3"],
        )

    def check(label: str, text: str, datum: Any, refs: list[str]) -> None:
        schema = json.loads(text)
        found = tm.receiver_breaches(schema, datum)
        expected = (
            reject("VALUE_INVALID", found[0][2], field=mr.error_field(found[0][0])) if found else accept()
        )
        c.add("check_record", label, refs, {"schema": text, "body": B(single_object(text, datum))}, expected)

    # The counts of spec/metadata.md, section 9.
    assert (len(mx.CHECKS), len(mx.FORMAT_VALUES), len(mx.PATTERNS), len(mx.BAD_PATTERNS)) == (35, 14, 11, 13)
    for label, how, path, attribute in mx.CHECKS:
        datum = how(copy.deepcopy(mx.VET_VALUE))
        assert mx.first(mx.VET, datum) == (path, attribute), label
        check(label, vet, datum, ["metadata.md 6", "metadata.md 7.2"])
    check(
        "a value of attributes that break their rules is not checked by them",
        loose,
        mx.LOOSE_VALUE,
        ["metadata.md 3.3"],
    )
    for name, (good, bad) in mx.FORMAT_VALUES.items():
        text = mx.compact(mx.with_format(name))
        for k, v in enumerate(good, 1):
            check(
                f"the format {name}, value {k}: {json.dumps(v, ensure_ascii=False)}",
                text,
                {"value": v},
                ["metadata.md 6.3"],
            )
        for k, v in enumerate(bad, 1):
            check(
                f"the format {name}, broken value {k}: {json.dumps(v, ensure_ascii=False)}",
                text,
                {"value": v},
                ["metadata.md 6.3"],
            )
    unknown = mx.compact(mx.with_format("zip-code"))
    check(
        "a format the receiver does not know is plain text",
        unknown,
        {"value": "any text"},
        ["metadata.md 6.3"],
    )
    for n, (pattern, good, bad) in enumerate(mx.PATTERNS, 1):
        text = mx.compact(mx.with_pattern(pattern))
        for k, v in enumerate(good + bad, 1):
            check(
                f"pattern {n}, value {k}: {json.dumps(pattern, ensure_ascii=False)} "
                f"and {json.dumps(v, ensure_ascii=False)}",
                text,
                {"code": v},
                ["metadata.md 6.4"],
            )
    for pattern, why in mx.BAD_PATTERNS:
        check(
            f"a pattern that is not an I-Regexp, {why}, is ignored",
            mx.compact(mx.with_pattern(pattern)),
            {"code": "?"},
            ["metadata.md 6.4", "metadata.md 3.3"],
        )
    # The example types: every example datum and the further valid records keep every rule; each record of
    # example_types.py with a time value that is not valid names the first such value. The checks of an
    # example type are in its description (spec/fields.md, section 7), not in its derived schema, so the
    # records that break only a check are not among these.
    examples = {n: pe.compact(EXAMPLES / f"{n}.1.avsc") for n in TYPE_FPS}
    for name in TYPE_FPS:
        check(
            f"the record of axt.example.v1.{name} of types.md keeps every check",
            examples[name],
            rules.DATA[name],
            ["metadata.md 6", "types.md 5.9"],
        )
    for label, name, datum in rules.VALID:
        check(f"axt.example.v1.{name}: {label}", examples[name], datum, ["metadata.md 6", "time.md 6"])
    for label, name, datum, path, rule in rules.BREACHES:
        if rule not in mr.TIME_TYPES:
            continue
        assert tm.receiver_breaches(json.loads(examples[name]), datum)[0][:2] == (path, rule), label
        check(
            f"reject axt.example.v1.{name}: {label}",
            examples[name],
            datum,
            ["metadata.md 7.1", "metadata.md 7.2"],
        )
    # Field paths into a map and above 1,024 bytes, and time values next to the checks.
    due = mx.compact(mx.DUE)
    check(
        "a time value that is not valid in a map is named by its key",
        due,
        mx.DUE_VALUE,
        ["metadata.md 7.2", "time.md 8"],
    )
    long_name = "f" * 1100
    long = {
        "type": "record",
        "name": "Long",
        "namespace": "com.example",
        "doc": "A field with a long name.",
        "fields": [
            {"name": long_name, "type": "string", "default": "", "doc": "A field.", "axt.min_length": 1}
        ],
    }
    check(
        "a path above 1,024 bytes is reported as null",
        mx.compact(long),
        {long_name: ""},
        ["metadata.md 7.2", "protocol.md 8.1"],
    )
    return c


# --- manifest (spec/manifest.md) --------------------------------------------------------


def manifest_meaning(body: bytes) -> Any:
    return meaning(
        me.manifest_json,
        fastavro.schemaless_reader(io.BytesIO(body[10:]), pe.raw["Manifest"], pe.raw["Manifest"]),
    )


def manifest_category() -> Category:
    c = Category(
        "manifest",
        "The validity and limits of a manifest, and which types fit it, with the language of "
        "the purpose sentence shown (spec/manifest.md).",
    )
    goods = [
        ("the manifest of cat-a-log of manifest.md, section 10.1", me.CAT_A_LOG),
        ("the manifest of Old Brain Fix of manifest.md, section 10.1", me.OLD_BRAIN_FIX),
        (
            "Old Brain Fix with an encryption key and a relay",
            dict(me.OLD_BRAIN_FIX, encryption_key=me.X25519_KEY, relay=me.RELAY),
        ),
        (
            "a relay URL of 256 bytes",
            dict(
                me.OLD_BRAIN_FIX,
                encryption_key=me.X25519_KEY,
                relay=dict(me.RELAY, url="https://relay.example.org/" + "a" * 229 + "/"),
            ),
        ),
        ("a manifest that takes nothing", dict(me.CAT_A_LOG, takes=[], sends=None)),
        (
            "a translation under en-GB",
            me.broken(
                lambda d: d["takes"][0]["purpose_translations"].update(
                    {"en-GB": "An Appointment becomes a Reminder."}
                )
            ),
        ),
    ]
    for label, datum in goods:
        body = me.encode_body(datum)
        assert not me.manifest_problems(datum, len(body)), label
        c.add(
            "check_manifest",
            label,
            ["manifest.md 3", "manifest.md 4"],
            {"body": B(body), "envelope_format": 1},
            accept({"manifest": manifest_meaning(body)}),
        )
    assert len(me.NEGATIVE) == 43, "spec/manifest.md, section 9, names 43 invalid manifests"
    for label, change, rule in me.NEGATIVE:
        datum = me.broken(change)
        body = me.encode_body(datum)
        problems = me.manifest_problems(datum, len(body))
        assert problems and all(rule in p for p in problems), label
        c.add(
            "check_manifest",
            f"reject {label}",
            ["manifest.md 4"],
            {"body": B(body), "envelope_format": 1},
            reject("MANIFEST_INVALID", problems[0]),
        )
    body = me.encode_body(me.CAT_A_LOG)
    for label, data in [
        ("a byte left over after the manifest", body + b"\x00"),
        ("the last byte missing", body[:-1]),
        ("the fingerprint of another schema", body[:2] + ENVELOPE_FP + body[10:]),
    ]:
        c.add(
            "check_manifest",
            f"reject a body with {label}",
            ["manifest.md 2", "protocol.md 8.2"],
            {"body": B(data), "envelope_format": 1},
            reject("INVALID_MESSAGE"),
        )

    def fit_vector(
        label: str, refs: list[str], manifest: Any, schema_text: str, languages: Any, entry: Any
    ) -> None:
        body = me.encode_body(manifest)
        schema = json.loads(schema_text)
        got = me.fit(manifest, pe.full_name(schema), me.schema_version(schema))
        assert got is entry, label
        c.add(
            "fit",
            label,
            refs,
            {"manifest": B(body), "schema": schema_text, "languages": languages},
            accept(
                {
                    "fits": entry is not None,
                    "purpose": None if entry is None else me.sentence(entry, languages),
                }
            ),
        )

    obf, cat = me.OLD_BRAIN_FIX, me.CAT_A_LOG
    texts = {
        n: pe.compact(EXAMPLES / f"{n}.1.avsc")
        for n in ("Pet", "Appointment", "Measurement", "Document", "Note", "Task")
    }
    memo_text = json.dumps(env.MEMO_SCHEMA)
    for name, entry in [
        ("Pet", obf["any_type"]),
        ("Appointment", obf["takes"][0]),
        ("Measurement", obf["any_type"]),
        ("Document", obf["any_type"]),
    ]:
        fit_vector(
            f"cat-a-log offers {name} to Old Brain Fix, for a user who reads de-AT",
            ["manifest.md 5.2", "manifest.md 3.6", "manifest.md 10.2"],
            obf,
            texts[name],
            ["de-AT"],
            entry,
        )
    fit_vector(
        "the Appointment for a user who reads fr-CH and fr: the English sentence",
        ["manifest.md 3.6", "manifest.md 10.2"],
        obf,
        texts["Appointment"],
        ["fr-CH", "fr"],
        obf["takes"][0],
    )
    fit_vector(
        "the Appointment for a user who reads DE, in upper case",
        ["manifest.md 3.6"],
        obf,
        texts["Appointment"],
        ["DE"],
        obf["takes"][0],
    )
    fit_vector(
        "the Appointment for a user with no language: the English sentence",
        ["manifest.md 3.6"],
        obf,
        texts["Appointment"],
        [],
        obf["takes"][0],
    )
    fit_vector(
        "the Appointment for a user who reads en-GB: the English sentence",
        ["manifest.md 3.6"],
        obf,
        texts["Appointment"],
        ["en-GB"],
        obf["takes"][0],
    )
    regional = me.broken(
        lambda d: d["takes"][0]["purpose_translations"].update({"de-CH": "Ein Termin wird zur Erinnerung."})
    )
    fit_vector(
        "a user who reads de-CH-1996 gets the de-CH sentence",
        ["manifest.md 3.6"],
        regional,
        texts["Appointment"],
        ["de-CH-1996"],
        regional["takes"][0],
    )
    fit_vector(
        "a Note does not fit cat-a-log, which takes no other type",
        ["manifest.md 5.2", "manifest.md 10.2"],
        cat,
        texts["Note"],
        ["en"],
        None,
    )
    fit_vector(
        "a Pet fits cat-a-log by its entry",
        ["manifest.md 5.2", "manifest.md 10.2"],
        cat,
        texts["Pet"],
        ["en"],
        cat["takes"][0],
    )
    fit_vector(
        "com.example.Memo, without axt.version, fits Old Brain Fix's any type",
        ["manifest.md 3.4", "manifest.md 10.2"],
        obf,
        memo_text,
        ["en"],
        obf["any_type"],
    )
    fit_vector(
        "com.example.Memo does not fit cat-a-log",
        ["manifest.md 5.2", "manifest.md 10.2"],
        cat,
        memo_text,
        ["en"],
        None,
    )
    narrowed = me.broken(lambda d: d["takes"][0].update(min_version=2))
    fit_vector(
        "an Appointment of version 1 does not fit min_version 2, although the manifest takes any type",
        ["manifest.md 3.5", "manifest.md 5.2", "manifest.md 10.2"],
        narrowed,
        texts["Appointment"],
        ["en"],
        None,
    )
    for label, version in [('the string "2"', "2"), ("0", 0)]:
        t = json.dumps(
            dict(json.loads(texts["Appointment"]), **{"axt.version": version}),
            separators=(",", ":"),
            ensure_ascii=False,
        )
        fit_vector(
            f"a schema whose axt.version is {label} counts as version 1",
            ["manifest.md 3.4"],
            narrowed,
            t,
            ["en"],
            None,
        )
    capped = me.broken(lambda d: d["takes"][0].update(max_version=1))
    v2 = json.dumps(
        dict(json.loads(texts["Appointment"]), **{"axt.version": 2}),
        separators=(",", ":"),
        ensure_ascii=False,
    )
    fit_vector(
        "version 2 does not fit max_version 1",
        ["manifest.md 3.3", "manifest.md 5.2"],
        capped,
        v2,
        ["en"],
        None,
    )
    fit_vector(
        "version 1 fits max_version 1",
        ["manifest.md 3.3", "manifest.md 5.2"],
        capped,
        texts["Appointment"],
        ["en"],
        capped["takes"][0],
    )
    renamed = json.dumps(
        dict(json.loads(texts["Appointment"]), namespace="org.example.calendar"),
        separators=(",", ":"),
        ensure_ascii=False,
    )
    fit_vector(
        "an app type with the fields of an Appointment fits by its own name only",
        ["manifest.md 3.3", "types.md 4"],
        cat,
        renamed,
        ["en"],
        None,
    )
    return c


# --- protocol (spec/protocol.md) ---------------------------------------------------------


def decode_reply(m: bytes) -> tuple[Any, Any]:
    d: Any = fastavro.schemaless_reader(io.BytesIO(m[10:]), pe.raw["Envelope"], pe.raw["Envelope"])
    name = pe.BODY_SCHEMA[d["kind"]]
    return d["kind"], pe.read_body(d["body"][10:], pe.raw[name])


def normalize_replies(replies: Any) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """The answers and errors of the replies to one message (spec/conformance.md, section 5.6)."""
    answers: dict[str, Any]
    errors: list[dict[str, Any]]
    answers, errors = {}, []
    for m in replies:
        kind, b = decode_reply(m)
        if kind in ("ACCEPT", "DECLINE"):
            for t in b["types"]:
                name, verdict = (t, "ACCEPT") if kind == "ACCEPT" else (t["type"], t["reason"])
                answers.setdefault(b["offer_id"], {})[name] = verdict
        elif kind == "ERROR":
            errors.append(
                {
                    "code": b["code"],
                    "message_hash": H(b["message_hash"]),
                    "record": b["record"],
                    "fingerprint": None if b["fingerprint"] is None else H(b["fingerprint"]),
                    "field": b["field"],
                }
            )
        else:
            raise AssertionError(f"a reply of kind {kind}")
    return answers, errors


def session_config(
    seed: bytes, manifest: Any, readers: dict[str, Any], takes: set[str], peer: bytes
) -> dict[str, Any]:
    return {
        "seed": H(seed),
        "manifest": B(me.encode_body(manifest)),
        "formats": [1],
        "readers": {n: json.dumps(r, separators=(",", ":"), ensure_ascii=False) for n, r in readers.items()},
        "user_takes": sorted(takes),
        "peer": H(peer),
    }


RECORD_OUTCOMES = ("APPLIED", "DUPLICATE", "STALE", "WITHDRAWN")  # of a record message in a session


def run_session(
    c: Category,
    label: str,
    refs: list[str],
    seed: bytes,
    manifest: Any,
    readers: dict[str, Any],
    takes: set[str],
    peer: bytes,
    steps: list[Any],
) -> None:
    """Play the steps against a fresh model app of protocol_examples.py; the result of each step is the
    expected one. Each step names what the script itself expects, and the model's result must match it."""
    app = pe.App("app", seed, manifest, readers, lambda n: n in takes, peer_key=peer)
    inputs: list[dict[str, Any]]
    expected: list[dict[str, Any]]
    inputs, expected = [], []
    for step in steps:
        kind = step[0]
        if kind == "receive":
            _, m, want = step[:3]
            opts = step[3] if len(step) > 3 else {}
            what, replies = app.receive(m)
            answers, errors = normalize_replies(replies)
            outcome = what if what in RECORD_OUTCOMES else None
            close = what.endswith(": close")
            if want in RECORD_OUTCOMES and not opts.get("device"):
                assert what == want, (label, what, want)
            elif want == "taken":
                assert not replies and (
                    what.endswith("taken") or what in ("acknowledged",) or what.startswith("error ")
                ), (label, what)
            elif want == "ignored":
                assert not replies and (what.startswith("ignored") or what.endswith("not reported")), (
                    label,
                    what,
                )
            elif want == "answers":
                assert answers == opts["answers"] and not errors, (label, answers)
            elif opts.get("device"):
                # An addition or a removal of a device that gets no reply (spec/protocol.md, section 3.3).
                assert not replies and what == f"device message: {want}", (label, what)
                outcome = None
            elif want == "closes":
                assert not replies and what == "the connection key is removed: close", (label, what)
            elif want == "held":
                assert not replies and what == "rejected DEVICE_REJECTED, reported after the MANIFEST", (
                    label,
                    what,
                )
            elif want == "taken, with reports":
                assert what.endswith("taken") and not answers, (label, what)
                assert [(e["code"], e["message_hash"]) for e in errors] == opts["reports"], (label, errors)
            elif want.startswith("ERROR "):
                assert (
                    what == "rejected " + want[6:] and len(errors) == 1 and errors[0]["code"] == want[6:]
                ), (label, what)
                if opts.get("record_ambiguous"):
                    del errors[0]["record"]
            else:
                raise ValueError(want)
            if opts.get("may_close"):
                # spec/protocol.md, section 8.3: the app MAY close the connection after this; nothing follows
                # it.
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
            # The app offers the description of each type (spec/fields.md, section 10.1).
            offered = [
                {"description": pe.fe.json_form(pe.offered({"schema": t})), "count": n} for t, n in types
            ]
            inputs.append({"offer": {"offer_id": offer_id, "types": offered}})
            expected.append({"offer": {"to": H(app.peer), "offer_id": offer_id, "types": offered}})
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
            inputs.append(
                {"query": {what: arg if not isinstance(arg, tuple) else {"id": arg[0], "version": arg[1]}}}
            )
            expected.append(got)
    c.add(
        "session",
        label,
        refs,
        {"app": session_config(seed, manifest, readers, takes, peer), "steps": inputs},
        {"steps": expected},
    )


def protocol_category() -> Category:
    c = Category(
        "protocol",
        "The steps of an exchange in a live connection, played against one app: manifests, "
        "offers, answers, record messages, acknowledgements and errors (spec/protocol.md).",
    )
    assert len(pe.checks) == 71, "spec/protocol.md, section 16, names 71 cases besides the exchange"
    want: Any
    for label, own, theirs, want in [
        ("the highest common format", [1, 2], [2, 3], 2),
        ("no common format", [1], [2], None),
        ("format 1 between two apps of 0.1.0", [1], [1], 1),
    ]:
        assert pe.choose_format(own, theirs) == want
        c.add(
            "choose_format",
            label,
            ["protocol.md 3.2"],
            {"own": own, "theirs": theirs},
            accept({"format": want}),
        )

    # The key to which a sender offers, and what it sends again after a removal at the receiver.
    k1, k2, k3 = (bytes(keys.public_key(sy.test_secret(f"receiver device {n}"))) for n in (1, 2, 3))
    contact: list[tuple[str, list[bytes], list[bytes], list[tuple[bytes, str]], list[bytes]]] = [
        (
            "the key from which the sender last got a record message",
            [k1, k2],
            [k1, k2],
            [(k1, "ACK"), (k2, "DATA")],
            [k2],
        ),
        (
            "a MANIFEST, a DEVICE_ADD and a DEVICE_REMOVE do not move the contact key",
            [k1, k2],
            [k1, k2],
            [(k1, "ACK"), (k2, "MANIFEST"), (k2, "DEVICE_ADD"), (k2, "DEVICE_REMOVE")],
            [k1],
        ),
        (
            "with no other message from any current key, any current key of which it holds a manifest",
            [k1, k2, k3],
            [k1, k3],
            [(k2, "MANIFEST"), (k3, "DEVICE_REMOVE")],
            [k1, k3],
        ),
        (
            "after the removal of the contact key, the current key it last got a message from",
            [k2, k3],
            [k2, k3],
            [(k2, "ACK"), (k1, "ACK"), (k3, "MANIFEST")],
            [k2],
        ),
        (
            "a key of which the sender holds no manifest is not the contact key",
            [k1, k2],
            [k1],
            [(k1, "ACK"), (k2, "ACK")],
            [k1],
        ),
    ]
    for label, current, manifests, got, want_keys in contact:
        assert pe.contact_keys(current, manifests, got) == sorted(want_keys), label
        c.add(
            "contact_key",
            label,
            ["protocol.md 9.1", "sync.md 17.2"],
            {
                "current": [k.hex() for k in current],
                "manifests": [k.hex() for k in manifests],
                "got": [{"key": k.hex(), "kind": kind} for k, kind in got],
            },
            accept({"keys": sorted(k.hex() for k in want_keys)}),
        )
    resend: list[tuple[str, list[tuple[str, dict[bytes, str]]], list[bytes], list[str]]] = [
        (
            "a record whose only outcome is of a removed key is sent again, one with an outcome of a current "
            "key is not",
            [("a", {k1: "APPLIED"}), ("b", {k1: "APPLIED", k2: "DUPLICATE"}), ("c", {})],
            [k1],
            ["a", "c"],
        ),
        (
            "outcomes of two removed keys count for nothing",
            [("a", {k1: "MERGED", k2: "KEPT"}), ("b", {k3: "STALE"})],
            [k1, k2],
            ["a"],
        ),
    ]
    for label, records, removed, want_ids in resend:
        assert pe.resend_after_removal(records, removed) == want_ids, label
        c.add(
            "resend_after_removal",
            label,
            ["protocol.md 7.4", "protocol.md 11", "sync.md 17.2"],
            {
                "records": [
                    {"id": rid, "outcomes": {k.hex(): o for k, o in outcomes.items()}}
                    for rid, outcomes in records
                ],
                "removed": [k.hex() for k in removed],
            },
            accept({"ids": want_ids}),
        )

    A, T, P_, N = (
        "axt.example.v1.Appointment",
        "axt.example.v1.Task",
        "axt.example.v1.Pet",
        "axt.example.v1.Note",
    )
    OUT, VISIT = "org.example.outline.Outline", "com.example.Visit"
    AID, PID, OID = pe.APPOINTMENT_ID, pe.PET_ID, pe.OFFER_ID
    ap, ap_text = pe.APPOINTMENT, pe.APPOINTMENT_TEXT
    obf_readers = {A: pe.APPOINTMENT_READER}
    obf_takes = {A, T, OUT, VISIT}
    nil_id, del_id = "00000000-0000-0000-0000-000000000000", "d4c3b2a1-0f9e-4d8c-b7a6-5f4e3d2c1b0a"
    note_id = "c1d2e3f4-a5b6-4c7d-8e9f-0a1b2c3d4e5f"
    # The appointment of example_types.py with its relations, and one more to a record of the key of
    # cat-a-log's new phone, which Old Brain Fix does not know.
    rel_ap_id = "e5f6a7b8-c9d0-4e1f-8a2b-3c4d5e6f7a8b"
    new_phone = keys.public_key(test_secret("cat-a-log, new phone, Ed25519"))
    rel_ap = dict(
        rules.DATA["Appointment"],
        relations=[
            *rules.RELATIONS["Appointment"],
            rules.relation(
                "b8c9d0e1-f2a3-4b4c-9d5e-6f7a8b9c0d1e",
                rules.record_target(
                    "c3d4e5f6-a7b8-4c9d-8e0f-1a2b3c4d5e6f", "axt.example.v1.Pet", "Felix", new_phone
                ),
            ),
        ],
    )
    oversized = pe.data_msg + bytes(pe.MAX_MESSAGE)

    def bad_offer(types: list[Any], oid: str = "4a5b6c7d-8e9f-4a0b-9c1d-2e3f4a5b6c7d") -> Any:
        return pe.cat_app.reply("OFFER", {"to": OBF, "offer_id": oid, "types": types})

    ambiguous = {"record_ambiguous": True}
    may_close = {"may_close": True}

    def r(m: bytes, want: str, **o: Any) -> tuple[str, bytes, str, dict[str, Any]]:
        return ("receive", m, want, o)

    obf_steps = [
        r(pe.m1, "taken"),
        r(pe.offer_msg, "answers", answers={OID: {A: "ACCEPT", P_: "NOT_WANTED"}}),
        r(pe.data_msg, "APPLIED"),
        (
            "flush",
            [{"id": AID, "version": 1, "outcome": "APPLIED", "receiver_version": 1, "kept_fields": []}],
        ),
        r(pe.pet_msg, "ERROR NOT_ACCEPTED"),
        r(pe.offer_msg, "answers", answers={OID: {A: "ACCEPT", P_: "NOT_WANTED"}}),
        r(pe.data_msg, "DUPLICATE"),
        (
            "flush",
            [{"id": AID, "version": 1, "outcome": "DUPLICATE", "receiver_version": 1, "kept_fields": []}],
        ),
        r(pe.m1, "taken"),
        r(pe.fwd, "ignored"),
        r(pe.obf_data(AID, 0, ap_text, ap), "ERROR VERSION_INVALID"),
        r(pe.obf_data(nil_id, 1, ap_text, ap), "ERROR RECORD_ID_INVALID"),
        r(pe.obf_data("vet-appointment", 1, ap_text, ap), "ERROR RECORD_ID_INVALID"),
        r(pe.obf_data(note_id, 1, pe.NOTE_TEXT, rules.DATA["Note"]), "ERROR SCHEMA_UNKNOWN"),
        r(pe.upper, "APPLIED"),
        ("query", "record", AID, {"record": {"version": 2, "state": "there"}}),
        r(pe.data_msg, "STALE"),
        (
            "flush",
            [
                {
                    "id": AID.upper(),
                    "version": 2,
                    "outcome": "APPLIED",
                    "receiver_version": 2,
                    "kept_fields": [],
                },
                {"id": AID, "version": 1, "outcome": "STALE", "receiver_version": 2, "kept_fields": []},
            ],
        ),
        r(pe.extra, "ERROR UNDECODABLE"),
        r(pe.short, "ERROR UNDECODABLE"),
        r(pe.data_msg[:2] + bytes(8) + pe.data_msg[10:], "ERROR FORMAT_UNSUPPORTED"),
        r(pe.del_unknown, "APPLIED"),
        ("query", "record", del_id, {"record": {"version": 4, "state": "tombstone"}}),
        # Relations that the app cannot resolve: to a record of cat-a-log that has not arrived, by null and
        # by cat-a-log's key, and to a record of a key it does not know (spec/records.md, section 10.3).
        r(pe.obf_data(rel_ap_id, 1, ap_text, rel_ap), "APPLIED"),
        ("query", "record", rel_ap_id, {"record": {"version": 1, "state": "there"}}),
        r(pe.task_offer, "answers", answers={"0c9b8a7f-6e5d-4c3b-a291-8f7e6d5c4b3a": {T: "ACCEPT"}}),
        r(pe.obf_data(AID, 9, pe.TASK_TEXT, rules.DATA["Task"]), "ERROR TYPE_CHANGED"),
        r(pe.outline_offer, "answers", answers={"1d2e3f40-5a6b-4c7d-9e8f-a0b1c2d3e4f5": {OUT: "ACCEPT"}}),
        r(pe.obf_data("2e3f4051-6b7c-4d8e-8f90-b1c2d3e4f506", 1, pe.OUTLINE_TEXT, pe.outline(16)), "APPLIED"),
        r(
            pe.obf_data("3f405162-7c8d-4e9f-90a1-c2d3e4f50617", 1, pe.OUTLINE_TEXT, pe.outline(17)),
            "ERROR UNDECODABLE",
        ),
        r(pe.visit_offer, "answers", answers={"7e8f9a0b-1c2d-4e3f-8a4b-5c6d7e8f9a0b": {VISIT: "ACCEPT"}}),
        r(pe.visit_broken, "ERROR VALUE_INVALID"),
        r(bad_offer([]), "ERROR OFFER_INVALID"),
        r(bad_offer([{"schema": pe.PET_TEXT, "count": 0}] * 2), "ERROR OFFER_INVALID"),
        r(bad_offer([{"schema": pe.PET_TEXT, "count": 0}], oid="offer-1"), "ERROR OFFER_INVALID"),
        r(bad_offer([{"description": pe.NOT_AN_OBJECT, "count": 0}]), "ERROR OFFER_INVALID"),
        r(
            bad_offer([{"description": pe.big_doc, "count": 0}], oid=pe.BIG_OFFER_ID),
            "answers",
            answers={pe.BIG_OFFER_ID: {"axt.example.v1.Pet": "DESCRIPTION_INVALID"}},
        ),
        (
            "flush",
            [
                {"id": del_id, "version": 4, "outcome": "APPLIED", "receiver_version": 4, "kept_fields": []},
                {
                    "id": rel_ap_id,
                    "version": 1,
                    "outcome": "APPLIED",
                    "receiver_version": 1,
                    "kept_fields": [],
                },
                {
                    "id": "2e3f4051-6b7c-4d8e-8f90-b1c2d3e4f506",
                    "version": 1,
                    "outcome": "APPLIED",
                    "receiver_version": 1,
                    "kept_fields": [],
                },
            ],
        ),
        ("close",),
        r(pe.m1, "taken"),
        r(pe.obf_data(AID, 10, ap_text, ap), "ERROR SCHEMA_UNKNOWN"),
    ]
    run_session(
        c,
        "Old Brain Fix receives the exchange of protocol.md, section 17, its repeats and the messages "
        "it rejects",
        [
            "protocol.md 3.1",
            "protocol.md 5.2",
            "protocol.md 6.2",
            "protocol.md 7",
            "protocol.md 8",
            "protocol.md 9.2",
            "protocol.md 17",
            "records.md 10.3",
            "time.md 8",
        ],
        OBF_SEED,
        me.OLD_BRAIN_FIX,
        obf_readers,
        obf_takes,
        CAT,
        obf_steps,
    )
    # The rejections after which an app MAY close the connection (spec/protocol.md, section 8.3), each last in
    # a session.
    for label, m, want, opts in [
        ("a signature that does not verify", pe.bad_sig, "ERROR SIGNATURE_INVALID", {}),
        ("bytes left over after the envelope", pe.data_msg + b"\x00", "ERROR INVALID_MESSAGE", {}),
        ("a format field that is not the envelope's format", pe.fmt2, "ERROR INVALID_MESSAGE", ambiguous),
        ("a message above 16 MiB", oversized, "ERROR TOO_LARGE", {}),
        ("a DELETE with a body", pe.del_body, "ERROR INVALID_MESSAGE", ambiguous),
    ]:
        run_session(
            c,
            f"Old Brain Fix reports {label}, and may close the connection",
            ["protocol.md 8.2", "protocol.md 8.3"],
            OBF_SEED,
            me.OLD_BRAIN_FIX,
            obf_readers,
            obf_takes,
            CAT,
            [r(pe.m1, "taken"), r(m, want, **opts, **may_close)],
        )
    # A CHANGE and a RESYNC travel between the devices of one set only: one of another app is rejected
    # (spec/sync.md, section 7.1), and so is one whose record is missing or does not belong.
    to_obf = {
        "to": OBF,
        "origin": None,
        "type": A,
        "state": 3,
        "whole": True,
        "removal": None,
        "keep": None,
        "fields": [],
    }
    change_body, resync_body = sy.body_of("Change", to_obf), sy.body_of("Resync", {"to": OBF})
    forward_body = sy.body_of("Forward", {"to": OBF, "message": pe.del_unknown, "schema": None})
    for label, m in [
        ("a CHANGE of another app", sy.message(CAT_SEED, "CHANGE", (AID, 3), change_body)),
        ("a RESYNC of another app", sy.message(CAT_SEED, "RESYNC", (sy.REQUEST_ID, 1), resync_body)),
        ("a CHANGE without a record", sy.message(CAT_SEED, "CHANGE", None, change_body)),
        ("a RESYNC without a record", sy.message(CAT_SEED, "RESYNC", None, resync_body)),
        ("a FORWARD of another app", sy.message(CAT_SEED, "FORWARD", (sy.FORWARD_ID, 1), forward_body)),
        ("a FORWARD without a record", sy.message(CAT_SEED, "FORWARD", None, forward_body)),
    ]:
        run_session(
            c,
            f"Old Brain Fix reports {label}, and may close the connection",
            ["protocol.md 2", "protocol.md 8.2", "protocol.md 8.3", "sync.md 7.1"],
            OBF_SEED,
            me.OLD_BRAIN_FIX,
            obf_readers,
            obf_takes,
            CAT,
            [r(pe.m1, "taken"), r(m, "ERROR INVALID_MESSAGE", **may_close)],
        )

    cat_steps = [
        r(pe.m2, "taken"),
        ("offer", OID, [(pe.PET_TEXT, 1), (ap_text, 1)]),
        r(pe.accept_msg, "taken"),
        r(pe.decline_msg, "taken"),
        ("query", "accepted", A, {"accepted": True}),
        ("query", "accepted", P_, {"accepted": False}),
        r(pe.ack_msg, "taken"),
        ("query", "outcome", (AID, 1), {"outcome": "APPLIED"}),
        r(pe.error_msg, "taken"),
        ("query", "errors", True, {"errors": ["NOT_ACCEPTED"]}),
        r(pe.accept_msg, "taken"),
        r(pe.ack_msg, "taken"),
        ("query", "outcome", (AID, 1), {"outcome": "APPLIED"}),
        r(pe.dup_ack, "taken"),
        ("query", "outcome", (AID, 1), {"outcome": "APPLIED"}),
        r(
            pe.obf_app.reply(
                "ERROR",
                {
                    "to": CAT,
                    "code": "UNDECODABLE",
                    "message_hash": bytes(32),
                    "record": {"id": AID, "version": 1},
                    "fingerprint": None,
                    "field": None,
                    "detail": "",
                },
            ),
            "ignored",
        ),
        ("query", "errors", True, {"errors": ["NOT_ACCEPTED"]}),
        r(pe.late_accept, "taken"),
        ("query", "accepted", P_, {"accepted": False}),
        r(pe.obf_app.reply("ACCEPT", {"to": pe.OTHER, "offer_id": OID, "types": [A]}), "ignored"),
        r(pe.obf_app.reply("ACCEPT", {"to": CAT, "offer_id": PID, "types": [P_]}), "ignored"),
    ]
    run_session(
        c,
        "cat-a-log offers, takes the answers and acknowledgements, and ignores what is not for it",
        [
            "protocol.md 4",
            "protocol.md 5.3",
            "protocol.md 7.1",
            "protocol.md 7.4",
            "protocol.md 8.3",
            "protocol.md 9",
            "protocol.md 17",
        ],
        CAT_SEED,
        me.CAT_A_LOG,
        {},
        set(),
        OBF,
        cat_steps,
    )
    offered = [r(pe.m2, "taken"), ("offer", OID, [(pe.PET_TEXT, 1), (ap_text, 1)])]
    run_session(
        c,
        "cat-a-log reports an ACCEPT naming a type the offer does not have, and may close the connection",
        ["protocol.md 5.3", "protocol.md 8.3"],
        CAT_SEED,
        me.CAT_A_LOG,
        {},
        set(),
        OBF,
        offered
        + [
            r(
                pe.obf_app.reply("ACCEPT", {"to": CAT, "offer_id": OID, "types": [N]}),
                "ERROR INVALID_MESSAGE",
                **may_close,
            )
        ],
    )
    for label, entries in pe.invalid_acks:
        run_session(
            c,
            f"cat-a-log reports {label}, and may close the connection",
            ["protocol.md 7.1", "protocol.md 8.3"],
            CAT_SEED,
            me.CAT_A_LOG,
            {},
            set(),
            OBF,
            offered
            + [
                r(
                    pe.obf_app.reply("ACK", {"to": CAT, "records": entries}),
                    "ERROR INVALID_MESSAGE",
                    **may_close,
                )
            ],
        )
    run_session(
        c,
        "an ERROR that cannot be processed is not answered with an ERROR",
        ["protocol.md 8.3"],
        CAT_SEED,
        me.CAT_A_LOG,
        {},
        set(),
        OBF,
        [r(pe.m2, "taken"), r(pe.broken_error, "ignored", **may_close)],
    )

    run_session(
        c,
        "an offer whose schema does not resolve against the reader schema is declined",
        ["protocol.md 5.2", "envelope.md 6"],
        OBF_SEED,
        me.OLD_BRAIN_FIX,
        {A: pe.narrow_reader},
        {A},
        CAT,
        [
            r(pe.m1, "taken"),
            r(
                pe.cat_app.reply(
                    "OFFER",
                    {
                        "to": OBF,
                        "offer_id": "5b6c7d8e-9f0a-4b1c-8d2e-3f4a5b6c7d8e",
                        "types": [{"schema": ap_text, "count": 1}],
                    },
                ),
                "answers",
                answers={"5b6c7d8e-9f0a-4b1c-8d2e-3f4a5b6c7d8e": {A: "DOES_NOT_RESOLVE"}},
            ),
        ],
    )
    run_session(
        c,
        "an offer of a type that does not fit the receiver's manifest is declined, whatever its user wants",
        ["protocol.md 5.2", "manifest.md 5.4"],
        CAT_SEED,
        me.CAT_A_LOG,
        {},
        {N},
        OBF,
        [
            r(pe.m2, "taken"),
            r(
                pe.obf_app.reply(
                    "OFFER",
                    {
                        "to": CAT,
                        "offer_id": "6c7d8e9f-0a1b-4c2d-9e3f-4a5b6c7d8e9f",
                        "types": [{"schema": pe.NOTE_TEXT, "count": 1}],
                    },
                ),
                "answers",
                answers={"6c7d8e9f-0a1b-4c2d-9e3f-4a5b6c7d8e9f": {N: "DOES_NOT_FIT"}},
            ),
        ],
    )
    run_session(
        c,
        "the first messages: an OFFER before the MANIFEST, an invalid MANIFEST, a MANIFEST with a record",
        ["protocol.md 2", "protocol.md 3.1", "protocol.md 8.3", "manifest.md 4"],
        OBF_SEED,
        me.OLD_BRAIN_FIX,
        {},
        {A},
        CAT,
        [
            r(pe.offer_msg, "ignored"),
            r(pe.bad_manifest, "ERROR MANIFEST_INVALID"),
            r(
                pe.make_message(
                    "MANIFEST",
                    CAT_SEED,
                    (AID, 1),
                    pe.header("Manifest") + [(me.encode_body(me.CAT_A_LOG)[10:], "")],
                    check=False,
                )[1],
                "ERROR INVALID_MESSAGE",
                **ambiguous,
                **may_close,
            ),
        ],
    )
    run_session(
        c,
        "a DELETE without any accepted offer",
        ["protocol.md 6.2"],
        OBF_SEED,
        me.OLD_BRAIN_FIX,
        {},
        {A},
        CAT,
        [r(pe.m1, "taken"), r(pe.del_unknown, "ERROR NOT_ACCEPTED")],
    )
    for first, second, stands in [
        ("KEPT", "APPLIED", "APPLIED"),
        ("APPLIED", "KEPT", "APPLIED"),
        ("DUPLICATE", "MERGED", "MERGED"),
        ("MERGED", "DUPLICATE", "MERGED"),
        ("KEPT", "WITHDRAWN", "WITHDRAWN"),
        ("WITHDRAWN", "KEPT", "WITHDRAWN"),
    ]:
        acks = [
            pe.obf_app.reply(
                "ACK",
                {
                    "to": CAT,
                    "records": [
                        {
                            "id": AID,
                            "version": 4,
                            "outcome": o,
                            "receiver_version": 4,
                            "kept_fields": ["location"] if o == "MERGED" else [],
                        }
                    ],
                },
            )
            for o in (first, second)
        ]
        run_session(
            c,
            f"{stands} stands after {first} then {second}",
            ["protocol.md 7.3", "protocol.md 7.4"],
            CAT_SEED,
            me.CAT_A_LOG,
            {},
            set(),
            OBF,
            [
                r(pe.m2, "taken"),
                r(acks[0], "taken"),
                r(acks[1], "taken"),
                ("query", "outcome", (AID, 4), {"outcome": stands}),
            ],
        )

    # Additions and removals of devices in a connection (spec/protocol.md, section 3.3). Old Brain Fix
    # knows cat-a-log by the key of the old phone, the connection key.
    def device(m: bytes, result: str) -> tuple[str, bytes, str, dict[str, Any]]:
        return r(m, result, device=True)

    def rejected(m: bytes) -> tuple[str, str]:
        return ("DEVICE_REJECTED", H(hashlib.sha256(m).digest()))

    remove_new = pe.device_remove(CAT_SEED, pe.OTHER)
    device_refs = ["protocol.md 3.1", "protocol.md 3.3", "keys.md 5.5"]
    device_sessions: list[tuple[str, list[str], list[Any]]] = [
        (
            "a chain before the MANIFEST and a removal after it are applied or ignored without a reply",
            ["protocol.md 9.2"],
            [
                device(pe.add_new, keys.APPLIED),
                device(pe.add_new, keys.IGNORED),
                device(pe.unplaced, keys.NOT_PLACED),
                r(pe.m1, "taken"),
                device(remove_new, keys.APPLIED),
                device(remove_new, keys.IGNORED),
                device(pe.add_new, keys.IGNORED),
            ],
        ),
        (
            "a DEVICE_JOIN in a connection that no join code opened is ignored without a report",
            ["keys.md 5.2"],
            [
                r(pe.device_join(CAT_SEED, OBF), "ignored"),
                r(pe.m1, "taken"),
                r(pe.device_join(CAT_SEED, OBF), "ignored"),
            ],
        ),
        (
            "a rejected DEVICE_ADD before the MANIFEST is reported once the MANIFEST has come",
            ["protocol.md 8.3"],
            [
                r(pe.bad_proof, "held"),
                device(pe.add_new, keys.APPLIED),
                r(pe.m1, "taken, with reports", reports=[rejected(pe.bad_proof)]),
            ],
        ),
        (
            "a DEVICE_REMOVE signed with a removed key, and one of its signer's own key, are reported to "
            "the connection key",
            ["protocol.md 8.3", "protocol.md 9.1"],
            [
                r(pe.m1, "taken"),
                device(pe.add_new, keys.APPLIED),
                device(remove_new, keys.APPLIED),
                r(pe.late_removal, "ERROR DEVICE_REJECTED"),
                r(pe.device_remove(CAT_SEED, CAT), "ERROR DEVICE_REJECTED"),
            ],
        ),
        (
            "the connection key is removed by its set: the connection is closed, and in a new connection "
            "its MANIFEST is rejected without a report",
            ["keys.md 3.3"],
            [
                device(pe.add_new, keys.APPLIED),
                r(pe.device_remove(pe.OTHER_SEED, CAT), "closes"),
                ("close",),
                r(pe.m1, "ignored"),
            ],
        ),
        (
            "a DEVICE_ADD whose signature does not verify is reported, and Old Brain Fix may close the "
            "connection",
            ["keys.md 2.3", "protocol.md 8.3"],
            [r(pe.m1, "taken"), r(pe.broken_add, "ERROR SIGNATURE_INVALID", **may_close)],
        ),
    ]
    for label, refs, steps in device_sessions:
        run_session(c, label, device_refs + refs, OBF_SEED, me.OLD_BRAIN_FIX, {}, set(), CAT, steps)
    # The other way round: cat-a-log has an accepted offer to Old Brain Fix, whose key is then removed.
    run_session(
        c,
        "the offers made to a key end when its sender removes the key, and the connection is closed",
        ["protocol.md 4.3", "keys.md 5.5"],
        CAT_SEED,
        me.CAT_A_LOG,
        {},
        set(),
        OBF,
        [
            r(pe.m2, "taken"),
            ("offer", OID, [(ap_text, 1)]),
            r(pe.accept_msg, "taken"),
            ("query", "accepted", A, {"accepted": True}),
            device(pe.device_add(OBF_SEED, pe.UNKNOWN_SEED), keys.APPLIED),
            r(pe.device_remove(pe.UNKNOWN_SEED, OBF), "closes"),
            ("query", "accepted", A, {"accepted": False}),
        ],
    )
    withdraw_sessions(c, r, OBF_SEED, obf_readers, obf_takes, ambiguous, may_close)
    return c


def withdraw_sessions(
    c: Category,
    r: Callable[..., tuple[str, bytes, str, dict[str, Any]]],
    seed: bytes,
    readers: dict[str, Any],
    takes: set[str],
    ambiguous: dict[str, Any],
    may_close: dict[str, Any],
) -> None:
    """Old Brain Fix gets WITHDRAW messages of cat-a-log (spec/shares.md, sections 3.3 and 4)."""
    rid, A, T = se.REC_ID, "axt.example.v1.Appointment", "axt.example.v1.Task"
    ap, ap_text, OID = pe.APPOINTMENT, pe.APPOINTMENT_TEXT, pe.OFFER_ID
    accepted = [
        r(pe.m1, "taken"),
        r(pe.offer_msg, "answers", answers={OID: {A: "ACCEPT", "axt.example.v1.Pet": "NOT_WANTED"}}),
    ]

    def wd(version: int, to: bytes = OBF, record_id: str = rid) -> bytes:
        return cast(bytes, se.withdraw_message(CAT_SEED, to, record_id, version)[1])

    def broken(record: tuple[str, int] | None, body: bytes) -> bytes:
        return cast(bytes, pe.make_message("WITHDRAW", CAT_SEED, record, [(body, "a body")], check=False)[1])

    body = cast(bytes, sy.read_all("Envelope", WITHDRAW_MSG[10:])["body"])

    def session(label: str, refs: list[str], steps: list[Any]) -> None:
        run_session(c, label, refs, seed, me.OLD_BRAIN_FIX, readers, takes, CAT, steps)

    def ack(version: int, outcome: str, receiver_version: int | None = None) -> dict[str, Any]:
        return {
            "id": rid,
            "version": version,
            "outcome": outcome,
            "receiver_version": version if receiver_version is None else receiver_version,
            "kept_fields": [],
        }

    session(
        "a WITHDRAW through the version rule: an unknown id, repeats, a DATA, a DELETE and a WITHDRAW "
        "after it",
        [
            "shares.md 4.1",
            "shares.md 4.2",
            "shares.md 5.1",
            "shares.md 6.2",
            "shares.md 6.3",
            "records.md 5.2",
        ],
        accepted
        + [
            r(wd(4), "WITHDRAWN"),
            ("query", "record", rid, {"record": {"version": 4, "state": "withdrawn"}}),
            r(wd(4), "DUPLICATE"),
            r(wd(3), "STALE"),
            r(pe.obf_data(rid, 3, ap_text, ap), "STALE"),
            r(pe.obf_data(rid, 4, ap_text, ap), "DUPLICATE"),
            (
                "flush",
                [
                    ack(4, "WITHDRAWN"),
                    ack(4, "DUPLICATE"),
                    ack(3, "STALE", 4),
                    ack(3, "STALE", 4),
                    ack(4, "DUPLICATE"),
                ],
            ),
            r(pe.obf_data(rid, 5, ap_text, ap), "APPLIED"),
            ("query", "record", rid, {"record": {"version": 5, "state": "there"}}),
            r(wd(6), "WITHDRAWN"),
            ("query", "record", rid, {"record": {"version": 6, "state": "withdrawn"}}),
            r(pe.make_message("DELETE", CAT_SEED, (rid, 7), [], check=False)[1], "APPLIED"),
            ("query", "record", rid, {"record": {"version": 7, "state": "tombstone"}}),
            r(wd(8), "WITHDRAWN"),
            ("query", "record", rid, {"record": {"version": 8, "state": "withdrawn"}}),
            ("flush", [ack(5, "APPLIED"), ack(6, "WITHDRAWN"), ack(7, "APPLIED"), ack(8, "WITHDRAWN")]),
        ],
    )
    session(
        "a WITHDRAW whose to is another key is ignored, before its id is checked",
        ["shares.md 3.3", "shares.md 4.1", "protocol.md 9.1"],
        accepted
        + [
            r(wd(4, pe.OTHER), "ignored"),
            r(wd(4, pe.OTHER, "vet-appointment"), "ignored"),
            ("query", "record", rid, {"record": None}),
            ("flush", []),
        ],
    )
    session(
        "a WITHDRAW with an id or a version that is not valid",
        ["shares.md 4.1", "records.md 2", "records.md 3"],
        accepted
        + [
            r(wd(4, OBF, "vet-appointment"), "ERROR RECORD_ID_INVALID"),
            r(wd(4, OBF, "00000000-0000-0000-0000-000000000000"), "ERROR RECORD_ID_INVALID"),
            r(wd(4, OBF, "ffffffff-ffff-ffff-ffff-ffffffffffff"), "ERROR RECORD_ID_INVALID"),
            r(wd(0), "ERROR VERSION_INVALID"),
            r(wd(-1), "ERROR VERSION_INVALID"),
            ("query", "record", rid, {"record": None}),
        ],
    )
    session(
        "a WITHDRAW without any accepted offer",
        ["shares.md 4.1", "shares.md 8.1", "protocol.md 6.2"],
        [r(pe.m1, "taken"), r(wd(4), "ERROR NOT_ACCEPTED")],
    )
    other = "5d6e7f80-91a2-4b3c-8d4e-5f60718293a4"
    third = "6e7f8091-a2b3-4c4d-9e5f-60718293a4b5"
    session(
        "step 5 checks no offer for an id the receiver holds from that sender, and an offer of any type "
        "for an id it does not hold",
        ["shares.md 4.1", "shares.md 8.1", "protocol.md 6.2"],
        accepted
        + [
            r(pe.obf_data(rid, 3, ap_text, ap), "APPLIED"),
            r(wd(4, OBF, third), "WITHDRAWN"),
            ("close",),
            r(pe.m1, "taken"),
            r(wd(5, OBF, other), "ERROR NOT_ACCEPTED"),
            r(wd(4), "WITHDRAWN"),
            r(wd(5, OBF, third), "WITHDRAWN"),
            r(pe.task_offer, "answers", answers={"0c9b8a7f-6e5d-4c3b-a291-8f7e6d5c4b3a": {T: "ACCEPT"}}),
            r(wd(4, OBF, other), "WITHDRAWN"),
            ("query", "record", rid, {"record": {"version": 4, "state": "withdrawn"}}),
            ("query", "record", third, {"record": {"version": 5, "state": "withdrawn"}}),
        ],
    )
    for label, m in [
        ("without a record", broken(None, body)),
        ("with an empty body", broken((rid, 4), b"")),
        (
            "with a body of the fingerprint of axt.Resync",
            broken((rid, 4), body[:2] + sy.SPEC_FP["Resync"] + body[10:]),
        ),
        ("with a byte left over in its body", broken((rid, 4), body + b"\x00")),
        ("whose to has 31 bytes", broken((rid, 4), body[:-1])),
    ]:
        session(
            f"a WITHDRAW {label} is rejected with INVALID_MESSAGE",
            ["shares.md 3.3", "shares.md 4.1", "envelope.md 2.2"],
            accepted + [r(m, "ERROR INVALID_MESSAGE", **may_close)],
        )


# --- QR code (spec/transports.md, section 3) -----------------------------------------------


def one_of(*values: Any) -> dict[str, Any]:
    """An expected value that a library may meet in more than one way, where the specification leaves the choice."""  # noqa: E501 (wrapping would change the docstring)
    return {"one_of": list(values)}


def qr_category() -> Category:
    c = Category("qr", "The payload of the QR code and its text (spec/transports.md, section 3).")

    def qr_meaning(q: Any) -> Any:
        return meaning(tx.qr_json, q)

    largest_text = tx.qr_text(tx.encode_qr(tx.LARGEST))
    key_only = tx.KEY_ALONE
    key_only_text = tx.qr_text(tx.encode_qr(key_only))
    join_text = tx.qr_text(tx.encode_qr(tx.JOIN_QR))
    join_local = dict(tx.JOIN_QR, encryption_key=None, relay=None)
    text = tx.text
    mixed = "axt:" + "".join(ch.lower() if i % 2 else ch for i, ch in enumerate(text[4:]))
    for label, t, q in [
        ("the QR code of transports.md, section 7.2", text, tx.QR),
        ("the same text in lower case", text.lower(), tx.QR),
        ("the same text in mixed case", mixed, tx.QR),
        ("a code with the signing key alone", key_only_text, key_only),
        ("the largest valid payload, every field at its largest", largest_text, tx.LARGEST),
        ("a join code: the code of transports.md, section 7.2, with join true", join_text, tx.JOIN_QR),
        ("a join code with local alone", tx.qr_text(tx.encode_qr(join_local)), join_local),
    ]:
        assert tx.parse_qr(t) == q, label
        c.add(
            "parse_qr",
            label,
            ["transports.md 3.1", "transports.md 3.2"] + (["transports.md 4.7"] if q["join"] else []),
            {"text": t},
            accept({"payload": qr_meaning(q)}),
        )
    assert len(tx.QR_NEGATIVE) == 21, "spec/transports.md, section 6, names 21 invalid payloads and texts"
    for label, t, reason in tx.QR_NEGATIVE:
        got = tx.parse_qr(t)
        assert isinstance(got, str) and reason in got, label
        error = "QR_VERSION_UNSUPPORTED" if label == "payload version 2" else "QR_INVALID"
        c.add(
            "parse_qr",
            f"reject {label}",
            ["transports.md 3.1", "transports.md 3.2"],
            {"text": t},
            reject(error, got),
        )
    for label, payload, t in [
        ("the payload of transports.md, section 7.2", tx.payload, text),
        ("a payload with the signing key alone", tx.encode_qr(key_only), key_only_text),
        ("the largest valid payload", tx.encode_qr(tx.LARGEST), largest_text),
        ("the payload of a join code", tx.encode_qr(tx.JOIN_QR), join_text),
    ]:
        assert tx.qr_text(payload) == t and len(t) <= tx.MAX_QR_TEXT
        c.add("qr_text", label, ["transports.md 3.2"], {"payload": B(payload)}, accept({"text": t}))
    assert len(text) == 232 and tx.MAX_QR_TEXT == 696 and tx.MAX_QR_PAYLOAD == 432
    return c


# --- local network (spec/transports.md, section 4) -----------------------------------------


def local_category() -> Category:
    c = Category(
        "local", "Frames and HELLO of a connection on the local network (spec/transports.md, section 4)."
    )
    for label, seed, role, frame in [
        ("cat-a-log's HELLO as the client", CAT_SEED, "client", tx.client_hello),
        ("Old Brain Fix's HELLO as the server", OBF_SEED, "server", tx.server_hello),
    ]:
        assert frame == tx.hello(
            seed, tx.CLIENT if role == "client" else tx.SERVER, tx.CERT_HASH, check=False
        )
        c.add(
            "hello_frame",
            label,
            ["transports.md 4.5", "transports.md 7.3"],
            {"seed": H(seed), "role": role, "certificate_sha256": H(tx.CERT_HASH)},
            accept({"frame": H(frame)}),
        )

    names = {tx.SERVER: "server", tx.CLIENT: "client"}

    def connection(
        label: str,
        refs: list[str],
        role: Any,
        cert_hash: bytes,
        frames: list[bytes],
        expected_key: bytes | None = None,
        too_large_last: bool = False,
    ) -> list[Any]:
        peer = tx.Peer(role, cert_hash, expected_key)
        results: list[Any] = []
        for f in frames:
            try:
                got = peer.receive(f)
            except tx.Closed:
                results.append("close")
                break
            results.append(
                {"open": "open", "message": "message", "ping": "ping", "TOO_LARGE": "too_large"}[got]
            )
        if too_large_last:
            assert results[-1] == "too_large"
            results[-1] = one_of("too_large", "close")  # it reports the message, or closes (section 4.4)
        c.add(
            "connection",
            label,
            ["transports.md 4.4", "transports.md 4.5"] + refs,
            {
                "role": names[role],
                "certificate_sha256": H(cert_hash),
                "expected_key": None if expected_key is None else H(expected_key),
                "frames": [B(f) for f in frames],
            },
            {"steps": results},
        )
        return results

    S, C, CH = tx.SERVER, tx.CLIENT, tx.CERT_HASH
    hello_c, hello_s, data, ping, frame = (
        tx.client_hello,
        tx.server_hello,
        tx.data_frame,
        tx.ping_frame,
        tx.frame,
    )
    chain = [frame(tx.MESSAGE, tx.chain_add), frame(tx.MESSAGE, tx.chain_remove)]
    assert connection(
        "the server takes the client's HELLO, the DATA of protocol.md, section 17.5, and a PING",
        ["transports.md 7.3", "transports.md 7.4"],
        S,
        CH,
        [hello_c, data, ping],
    ) == ["open", "message", "ping"]
    assert connection(
        "the client takes the server's HELLO with the key of the QR code",
        ["transports.md 3.3"],
        C,
        CH,
        [hello_s],
        expected_key=OBF,
    ) == ["open"]
    assert connection(
        "a chain at the start, with a DEVICE_ADD signed with another key, then the sender's messages",
        ["protocol.md 3.3", "keys.md 5.4"],
        S,
        CH,
        [hello_c, *chain, data],
    ) == ["open", "message", "message", "message"]
    assert connection(
        "a DEVICE_REMOVE signed with another key after another message",
        ["protocol.md 3.3"],
        S,
        CH,
        [hello_c, data, frame(tx.MESSAGE, tx.foreign_remove)],
    ) == ["open", "message", "message"]
    connection(
        "a MESSAGE above 16 MiB is skipped and reported, or the connection closed",
        ["envelope.md 8"],
        S,
        CH,
        [hello_c, frame(tx.MESSAGE, bytes(MAX_MESSAGE + 1))],
        too_large_last=True,
    )
    closing = [
        (
            "a HELLO for another certificate, passed on by a machine in the middle",
            S,
            tx.OTHER_CERT_HASH,
            [hello_c],
            None,
        ),
        ("the server's own HELLO sent back to it", S, CH, [hello_s], None),
        ("a HELLO with another key than the QR code's", C, CH, [hello_s], CAT),
        ("a HELLO with a changed signature", S, CH, [hello_c[:-1] + bytes([hello_c[-1] ^ 1])], None),
        (
            "a HELLO with a key of small order",
            S,
            CH,
            [frame(tx.HELLO, (1).to_bytes(32, "little") + hello_c[37:])],
            None,
        ),
        ("a HELLO of 95 bytes", S, CH, [frame(tx.HELLO, hello_c[5:-1])], None),
        ("a MESSAGE before the HELLO", S, CH, [data], None),
        ("a PING before the HELLO", S, CH, [ping], None),
        ("a second HELLO", S, CH, [hello_c, hello_c], None),
        ("a message whose sender is not the key of the HELLO", C, CH, [hello_s, data], None),
        ("an empty MESSAGE", S, CH, [hello_c, frame(tx.MESSAGE, b"")], None),
        ("a PING with a payload", S, CH, [hello_c, frame(tx.PING, b"\x00")], None),
        ("an unknown frame type", S, CH, [hello_c, frame(4, b"")], None),
        ("a frame cut short by the end of the connection", S, CH, [hello_c, data[:-1]], None),
        (
            "a DEVICE_JOIN whose sender is not the key of the HELLO",
            S,
            CH,
            [hello_c, frame(tx.MESSAGE, tx.foreign_join)],
            None,
        ),
    ]
    assert len(closing) == 15 == sum(x.startswith("closed: ") for x in tx.checks), (
        "spec/transports.md, section 6, names 15"
    )
    for label, role, cert_hash, frames, key in closing:
        assert (
            connection(f"close on {label}", [], role, cert_hash, frames, expected_key=key)[-1] == "close"
        ), label
    return c


# --- relay, as a client (spec/transports.md, section 5) ---------------------------------------


def relay_category() -> Category:
    c = Category(
        "relay",
        "The relay as an app uses it: mailbox ids, requests, what an app does with each response, "
        "and the list of messages (spec/transports.md, section 5).",
    )
    for label, secret in [
        ("Old Brain Fix's test mailbox secret", tx.MAILBOX_SECRET),
        ("another test secret", test_secret("another mailbox secret")),
    ]:
        c.add(
            "mailbox_id",
            f"the mailbox id of {label}",
            ["transports.md 5.1", "transports.md 7.1"],
            {"secret": H(secret)},
            accept({"mailbox": H(tx.mailbox_id(secret))}),
        )
    base, box = tx.RELAY_URL, tx.MAILBOX.hex()
    auth = "Bearer " + tx.MAILBOX_SECRET.hex()
    url = base + f"v1/mailboxes/{box}"
    sealed_id = tx.SEALED_HASH
    requests = [
        (
            "create the mailbox",
            {"action": "create", "secret": H(tx.MAILBOX_SECRET)},
            {
                "method": "PUT",
                "url": url,
                "headers": {"authorization": auth, "content_type": None, "content_length": one_of(None, "0")},
            },
        ),
        (
            "put the sealed message of keys.md, section 7.4",
            {"action": "put", "mailbox": box, "message": B(tx.SEALED)},
            {
                "method": "PUT",
                "url": f"{url}/messages/{sealed_id}",
                "headers": {
                    "authorization": None,
                    "content_type": "application/octet-stream",
                    "content_length": "1073",
                },
            },
        ),
        (
            "list, waiting up to 30 seconds",
            {"action": "list", "secret": H(tx.MAILBOX_SECRET), "wait": 30},
            {
                "method": "GET",
                "url": f"{url}/messages?wait=30",
                "headers": {"authorization": auth, "content_type": None, "content_length": None},
            },
        ),
        (
            "list without waiting",
            {"action": "list", "secret": H(tx.MAILBOX_SECRET), "wait": None},
            {
                "method": "GET",
                "url": f"{url}/messages",
                "headers": {"authorization": auth, "content_type": None, "content_length": None},
            },
        ),
        (
            "fetch a message",
            {"action": "fetch", "secret": H(tx.MAILBOX_SECRET), "message_id": sealed_id},
            {
                "method": "GET",
                "url": f"{url}/messages/{sealed_id}",
                "headers": {"authorization": auth, "content_type": None, "content_length": None},
            },
        ),
        (
            "delete a message",
            {"action": "delete", "secret": H(tx.MAILBOX_SECRET), "message_id": sealed_id},
            {
                "method": "DELETE",
                "url": f"{url}/messages/{sealed_id}",
                "headers": {"authorization": auth, "content_type": None, "content_length": None},
            },
        ),
        (
            "remove the mailbox",
            {"action": "remove", "secret": H(tx.MAILBOX_SECRET)},
            {
                "method": "DELETE",
                "url": url,
                "headers": {"authorization": auth, "content_type": None, "content_length": None},
            },
        ),
    ]
    for label, i, want in requests:
        c.add(
            "request",
            label,
            ["transports.md 5.2", "transports.md 5.3", "transports.md 7.5"],
            dict(i, base_url=base),
            accept(want),
        )

    def backoff(attempt: int) -> int:
        return cast(int, min(2 ** (attempt - 1), 3600))

    reactions = [
        ("put", 201, None, 1, "done", None),
        ("put", 204, None, 1, "done", None),
        ("create", 201, None, 1, "done", None),
        ("create", 204, None, 1, "done", None),
        ("list", 200, None, 1, "done", None),
        ("fetch", 200, None, 1, "done", None),
        ("delete", 204, None, 1, "done", None),
        ("remove", 204, None, 1, "done", None),
        ("put", 400, None, 1, "stop", None),
        ("list", 400, None, 1, "stop", None),
        ("list", 401, None, 1, "stop", None),
        ("fetch", 403, None, 1, "stop", None),
        ("create", 403, None, 1, "stop", None),
        ("put", 413, None, 1, "stop", None),
        ("put", 404, None, 1, "stop", None),
        ("list", 404, None, 1, "create_mailbox", None),
        ("put", 411, None, 1, "repeat", 0),
        ("put", 429, 120, 1, "repeat", 120),
        ("list", 429, 5, 3, "repeat", 5),
        ("put", 503, 30, 1, "repeat", 30),
        ("put", 503, None, 1, "repeat", backoff(1)),
        ("put", 503, None, 2, "repeat", backoff(2)),
        ("put", 507, None, 5, "repeat", backoff(5)),
        ("put", 500, None, 3, "repeat", backoff(3)),
        ("put", 502, None, 12, "repeat", backoff(12)),
        ("put", 503, None, 13, "repeat", backoff(13)),
        ("put", None, None, 1, "repeat", backoff(1)),
        ("list", None, None, 20, "repeat", 3600),
    ]
    assert backoff(13) == 3600 and backoff(12) == 2048
    for request, status, retry, attempt, action, wait in reactions:
        what = (
            "a network failure"
            if status is None
            else f"{status}" + (f" with Retry-After {retry}" if retry is not None else "")
        )
        c.add(
            "reaction",
            f"{request} answered with {what}, attempt {attempt}",
            ["transports.md 5.2", "transports.md 5.3", "transports.md 5.4"],
            {"request": request, "status": status, "retry_after": retry, "attempt": attempt},
            accept({"action": action, "wait": wait}),
        )
    listing = tx.listing[2].decode()
    for label, body, msgs in [
        ("the list of transports.md, section 7.5", listing, [{"id": sealed_id, "size": 1073}]),
        ("an empty list", '{"messages":[]}', []),
        (
            "a list with members the app does not know",
            json.dumps(
                {
                    "messages": [{"id": sealed_id, "size": 1073, "put": "2026-11-15"}],
                    "next": None,
                    "relay": "example",
                }
            ),
            [{"id": sealed_id, "size": 1073}],
        ),
    ]:
        c.add("listing", label, ["transports.md 5.4"], {"body": body}, accept({"messages": msgs}))
    return c


# --- relay, as a relay (spec/transports.md, section 5; for axt-1008) ---------------------------


def relay_server_category() -> Category:
    c = Category(
        "relay-server",
        "The interface of a relay, played as requests against one relay with a clock the test "
        "sets (spec/transports.md, section 5). For relays, not for libraries.",
    )
    assert sum(x.startswith("relay: ") and " opens " not in x for x in tx.checks) == 28, (
        "spec/transports.md, section 6, names 28 requests"
    )
    OWNER, WRONG, BOX, PUT_PATH = tx.OWNER, tx.WRONG, tx.BOX, tx.PUT_PATH
    S, H14, G = tx.SEALED, tx.HOLDING, tx.GRACE
    second = tx.second

    def put(body: bytes, path: str = PUT_PATH, now: int = 0) -> tuple[str, str, dict[str, str], bytes, int]:
        return ("PUT", path, {"Content-Length": str(len(body))}, body, now)

    labelled = [
        ("a put before the mailbox exists", put(S), 404),
        ("creating the mailbox without Authorization", ("PUT", BOX, {}, b"", 0), 401),
        (
            "creating it with a malformed Authorization",
            ("PUT", BOX, {"Authorization": "Bearer xyz"}, b"", 0),
            401,
        ),
        ("creating it with another mailbox's secret", ("PUT", BOX, WRONG, b"", 0), 403),
        ("creating the mailbox", ("PUT", BOX, OWNER, b"", 0), 201),
        ("creating it again", ("PUT", BOX, OWNER, b"", 0), 204),
        ("a put without Content-Length", ("PUT", PUT_PATH, {}, S, 0), 411),
        ("a put whose id is not its SHA-256", put(S[:-1] + b"\x00"), 400),
        (
            "a put above 17,301,553 bytes",
            ("PUT", PUT_PATH, {"Content-Length": str(tx.MAX_SEALED + 1)}, b"", 0),
            413,
        ),
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
        (
            "a put of a second message",
            put(second, path=f"{BOX}/messages/{tx.second_hash}", now=H14 + G + 1),
            201,
        ),
        ("the listing in the order of the puts", ("GET", f"{BOX}/messages", OWNER, b"", H14 + G + 2), 200),
        ("deleting the mailbox", ("DELETE", BOX, OWNER, b"", H14 + G + 2), 204),
        ("a put after the mailbox was deleted", put(S, now=H14 + G + 2), 404),
    ]
    largest = bytes(tx.MAX_SEALED)
    small = [
        ("creating the mailbox", ("PUT", BOX, OWNER, b"", 0), 201),
        (
            "an empty mailbox takes a message of 17,301,553 bytes",
            (
                "PUT",
                f"{BOX}/messages/{hashlib.sha256(largest).hexdigest()}",
                {"Content-Length": str(tx.MAX_SEALED)},
                largest,
                0,
            ),
            201,
        ),
        ("a full mailbox", ("PUT", PUT_PATH, {"Content-Length": "1073"}, S, 0), 507),
    ]
    for label, quota, reqs in [
        ("the requests of transports.md, sections 5.2 to 5.5 and 7.5", 64 * 2**20, labelled),
        ("a mailbox whose room is used up, with a relay that keeps no room beyond one message", 0, small),
    ]:
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
            steps.append(
                {"method": method, "target": target, "headers": headers, "body": B(body), "now": now}
            )
            results.append(r)
        c.add(
            "relay",
            label,
            [
                "transports.md 5.2",
                "transports.md 5.3",
                "transports.md 5.4",
                "transports.md 5.5",
                "transports.md 5.6",
            ],
            {"base_url": tx.RELAY_URL, "quota_bytes": quota, "requests": steps},
            {"steps": results},
        )
    return c


# --- records (spec/records.md) -------------------------------------------------------------
# The scripts have no model of a receiver's own changes; the expected results below are written out from
# spec/records.md, sections 5 to 7, and the worked example of its section 9.

AP_T, TASK_T = "axt.example.v1.Appointment", "axt.example.v1.Task"
REC_ID = "3f2c8a5e-9b1d-4c7e-8a6f-2d4b5c6e7f80"  # spec/records.md, section 9


def data(version: int, value: Any, rid: str = REC_ID, type_name: str = AP_T) -> dict[str, Any]:
    return {"message": {"kind": "DATA", "id": rid, "version": version, "type": type_name, "value": value}}


def delete(version: int, rid: str = REC_ID) -> dict[str, Any]:
    return {"message": {"kind": "DELETE", "id": rid, "version": version}}


def change(field: str, value: Any, rid: str = REC_ID) -> dict[str, Any]:
    return {"local_change": {"id": rid, "field": field, "value": value}}


def user_delete(rid: str = REC_ID) -> dict[str, Any]:
    return {"local_delete": {"id": rid}}


def done(outcome: str, version: int, state: str, value: Any, kept: Iterable[str] = ()) -> dict[str, Any]:
    return {
        "outcome": outcome,
        "receiver_version": version,
        "kept_fields": sorted(kept),
        "state": state,
        "value": value,
    }


def failed(code: str) -> dict[str, Any]:
    return {"error": code}


def records_category() -> Category:
    c = Category(
        "records",
        "A receiver applying the record messages of one sender: the version rule, deletions and "
        "tombstones, and its user's own changes; and the relations it holds, resolved across senders "
        "(spec/records.md).",
    )

    def scenario(
        label: str,
        refs: list[str],
        policy: dict[str, Any],
        steps: list[Any],
        extensions: list[str] | None = None,
    ) -> None:
        events: list[Any]
        results: list[Any]
        events, results = [], []
        for e, r in steps:
            events.append(e)
            results.append({} if r is None else r)
        i = {"policy": policy, "events": events, **({} if extensions is None else {"extensions": extensions})}
        c.add("apply", label, refs, i, {"steps": results})

    per_field_delete = {"local_changes": "per_field", "delete_with_local_changes": "delete"}
    per_field_keep = {"local_changes": "per_field", "delete_with_local_changes": "keep"}
    # The appointment of spec/records.md, section 9, as complete values of axt.example.v1.Appointment: start
    # is an axt.DateTime in Europe/Berlin, the other fields keep their defaults. Version 3 moves start to
    # 10:30.
    v1 = {
        "title": "Vet",
        "start": tm.zoned(2025, 11, 18, 10, 0, tm.BERLIN, tm.CET),
        "end": None,
        "all_day": False,
        "location": "",
        "notes": "",
        "reminders": [],
        "relations": [],
        "extensions": [],
    }
    v3 = dict(v1, start=tm.zoned(2025, 11, 18, 10, 30, tm.BERLIN, tm.CET), notes="Bring the vaccination card")
    task = json.loads(
        json.dumps(rules.DATA["Task"])
    )  # a record of axt.example.v1.Task, for the steps of another type
    mine = "Dr. Weber, Hauptstr. 5"
    merged = dict(v3, location=mine)
    head = [
        (data(1, v1), done("APPLIED", 1, "there", v1)),
        (change("location", mine), None),
        (data(3, v3), done("MERGED", 3, "there", merged, ["location"])),
        (data(3, v3), done("DUPLICATE", 3, "there", merged)),
        (data(1, v1), done("STALE", 3, "there", merged)),
    ]
    scenario(
        "the example of records.md, section 9, with a receiver that deletes",
        ["records.md 5.2", "records.md 6.1", "records.md 9"],
        per_field_delete,
        head
        + [
            (delete(4), done("APPLIED", 4, "tombstone", None)),
            (data(5, v3), done("APPLIED", 5, "there", v3)),
        ],
    )
    scenario(
        "the example of records.md, section 9, with a receiver that keeps its user's changes "
        "against a deletion",
        ["records.md 6.4", "records.md 9"],
        per_field_keep,
        head
        + [
            (delete(4), done("KEPT", 4, "there", merged)),
            (data(5, v3), done("MERGED", 5, "there", merged, ["location"])),
        ],
    )
    scenario(
        "a DELETE of an unchanged record is applied, also by a receiver that keeps changes",
        ["records.md 6.4"],
        per_field_keep,
        [(data(1, v1), done("APPLIED", 1, "there", v1)), (delete(2), done("APPLIED", 2, "tombstone", None))],
    )
    other = "7c9e6679-7425-40de-944b-e07fc1f90ae7"
    scenario(
        "a DELETE of an unknown id leaves a tombstone that older and equal versions do not pass",
        ["records.md 5.2", "records.md 5.3"],
        per_field_delete,
        [
            (delete(4, other), done("APPLIED", 4, "tombstone", None)),
            (data(3, v1, other), done("STALE", 4, "tombstone", None)),
            (data(4, v1, other), done("DUPLICATE", 4, "tombstone", None)),
            (data(5, task, other, TASK_T), done("APPLIED", 5, "there", task)),
        ],
    )
    scenario(
        "a record its user deleted stays deleted, also beside a later DELETE, and a DATA after it is KEPT",
        ["records.md 6.3"],
        per_field_delete,
        [
            (data(1, v1), done("APPLIED", 1, "there", v1)),
            (user_delete(), None),
            (data(2, v3), done("KEPT", 2, "deleted_by_user", None)),
            (data(1, v1), done("STALE", 2, "deleted_by_user", None)),
            (delete(3), done("APPLIED", 3, "deleted_by_user", None)),
            (data(4, v3), done("KEPT", 4, "deleted_by_user", None)),
        ],
    )
    for policy, outcome, value in [
        ("whole_record_keep", "KEPT", dict(v1, location=mine)),
        ("whole_record_take", "APPLIED", v3),
    ]:
        scenario(
            f"a receiver that tracks changes of the whole record, {policy.replace('_', ' ')}",
            ["records.md 6.2"],
            {"local_changes": policy, "delete_with_local_changes": "delete"},
            [
                (data(1, v1), done("APPLIED", 1, "there", v1)),
                (data(2, v1), done("APPLIED", 2, "there", v1)),
                (change("location", mine), None),
                (data(3, v3), done(outcome, 3, "there", value)),
            ],
        )
    card = "Bring the vaccination card"
    v2 = dict(v1, title="Vet: vaccination", notes=card)
    scenario(
        "only the kept values that differ from the message are named",
        ["records.md 6.1", "records.md 7"],
        per_field_delete,
        [
            (data(1, v1), done("APPLIED", 1, "there", v1)),
            (change("location", mine), None),
            (change("notes", card), None),
            (data(2, v2), done("MERGED", 2, "there", dict(v2, location=mine), ["location"])),
        ],
    )
    eleven = tm.zoned(2025, 11, 18, 11, 0, tm.BERLIN, tm.CET)
    scenario(
        "a nested record is one value: the start its user set is kept as a whole",
        ["records.md 6.1", "time.md 6"],
        per_field_delete,
        [
            (data(1, v1), done("APPLIED", 1, "there", v1)),
            (change("start", eleven), None),
            (data(3, v3), done("MERGED", 3, "there", dict(v3, start=eleven), ["start"])),
        ],
    )
    scenario(
        "a message that brings the value its user set is applied",
        ["records.md 6.1"],
        per_field_delete,
        [
            (data(1, v1), done("APPLIED", 1, "there", v1)),
            (change("location", mine), None),
            (data(2, dict(v3, location=mine)), done("APPLIED", 2, "there", dict(v3, location=mine))),
        ],
    )
    scenario(
        "ids compare as 128-bit values, whatever the case of their digits",
        ["records.md 2", "envelope.md 7"],
        per_field_delete,
        [
            (data(1, v1), done("APPLIED", 1, "there", v1)),
            (data(2, v3, REC_ID.upper()), done("APPLIED", 2, "there", v3)),
            (data(2, v3), done("DUPLICATE", 2, "there", v3)),
        ],
    )
    scenario(
        "a message that cannot be processed changes nothing",
        ["records.md 2", "records.md 3", "records.md 7"],
        per_field_delete,
        [
            (data(1, v1), done("APPLIED", 1, "there", v1)),
            (data(2, v3, "vet-appointment"), failed("RECORD_ID_INVALID")),
            (data(2, v3, "00000000-0000-0000-0000-000000000000"), failed("RECORD_ID_INVALID")),
            (data(2, v3, "ffffffff-ffff-ffff-ffff-ffffffffffff"), failed("RECORD_ID_INVALID")),
            (data(2, v3, REC_ID.replace("-", "")), failed("RECORD_ID_INVALID")),
            (data(0, v3), failed("VERSION_INVALID")),
            (data(-1, v3), failed("VERSION_INVALID")),
            (delete(0), failed("VERSION_INVALID")),
            (data(1, v1), done("DUPLICATE", 1, "there", v1)),
        ],
    )
    scenario(
        "a record keeps its type, also through a tombstone",
        ["records.md 4.3"],
        per_field_delete,
        [
            (data(1, v1), done("APPLIED", 1, "there", v1)),
            (data(2, task, REC_ID, TASK_T), failed("TYPE_CHANGED")),
            (delete(2), done("APPLIED", 2, "tombstone", None)),
            (data(3, task, REC_ID, TASK_T), failed("TYPE_CHANGED")),
            (data(3, v1), done("APPLIED", 3, "there", v1)),
        ],
    )

    # The relations of an appointment merge per element (spec/records.md, section 6.1): the user's addition
    # and removal stay, the sender's change of another relation and its addition are taken.
    mimi = rules.RELATIONS["Appointment"][0]
    praxis = rules.RELATIONS["Appointment"][2]  # to a thing outside AXT
    booster = dict(mimi, note="Booster")
    task_link = rules.relation(
        "d2e4f6a8-1b3c-4d5e-9f70-8a1b2c3d4e5f",
        rules.record_target(rules.PET_ID, "axt.example.v1.Task", "Collar"),
    )
    linked = dict(v1, relations=[mimi])
    scenario(
        "relations merge per element: the user's addition and removal stay, also when the sender adds the "
        "same relation again, and the sender's other changes are taken",
        ["records.md 6.1", "sync.md 25.1"],
        per_field_delete,
        [
            (data(1, linked), done("APPLIED", 1, "there", linked)),
            (change("relations", [mimi, praxis]), None),
            (
                data(2, dict(v1, relations=[booster, task_link])),
                done("MERGED", 2, "there", dict(v1, relations=[booster, task_link, praxis]), ["relations"]),
            ),
            (change("relations", [task_link, praxis]), None),
            (
                data(3, dict(v1, relations=[booster, task_link])),
                done("MERGED", 3, "there", dict(v1, relations=[task_link, praxis]), ["relations"]),
            ),
            (
                data(4, dict(v1, relations=[booster, task_link, praxis])),
                done("MERGED", 4, "there", dict(v1, relations=[task_link, praxis]), ["relations"]),
            ),
        ],
    )

    # An extension of a type the receiver does not know is carried as it came, by the user's change of
    # another field and by the sender's update (spec/fields.md, section 12.4), as hex in the values.
    vet_ext = {
        "name": "org.example.vetapp.VetExtension",
        "data": "c3010000000000000000" + "0208" + b"chip".hex(),
    }
    extended = dict(v1, extensions=[vet_ext])
    scenario(
        "an extension of a type the receiver does not know is kept as it came, through local changes and "
        "updates",
        ["records.md 6.1", "fields.md 12.4"],
        per_field_delete,
        [
            (data(1, extended), done("APPLIED", 1, "there", extended)),
            (change("location", mine), None),
            (
                data(2, dict(extended, notes="Bring the vaccination card")),
                done(
                    "MERGED",
                    2,
                    "there",
                    dict(extended, notes="Bring the vaccination card", location=mine),
                    ["location"],
                ),
            ),
        ],
    )

    # The user changes the fur in cat-a-log's extension, the sender the TASSO id and an extension of a type
    # the receiver does not know (spec/records.md, section 6.1): a receiver that holds cat-a-log's schema
    # keeps both changes within the extension, one that does not keeps the user's extension whole; the
    # other extension comes from the message either way.
    def cat(tasso: str, fur: str) -> dict[str, Any]:
        e = rules.extension(tasso_id=tasso, fur=fur)
        return {"name": e["name"], "data": e["data"].hex()}

    vet_2 = dict(vet_ext, data="c3010000000000000000" + "0206" + b"tag".hex())
    first = dict(v1, extensions=[cat("276098100123456", "tabby"), vet_ext])
    second = dict(v1, extensions=[cat("276098100654321", "tabby"), vet_2])
    # A third DATA brings the merged extension: the receiver that knows the type takes it as it came.
    third = dict(v1, extensions=[cat("276098100654321", "black"), vet_2])
    for known, label, kept_cat, last in (
        (
            [sy.CAT_TEXT],
            "the user's change within an extension of a known type merges field by field with the sender's",
            cat("276098100654321", "black"),
            done("APPLIED", 3, "there", third),
        ),
        (
            [],
            "the user's change of an extension of a type the receiver does not know keeps the user's "
            "extension whole",
            cat("276098100123456", "black"),
            done(
                "MERGED",
                3,
                "there",
                dict(v1, extensions=[cat("276098100123456", "black"), vet_2]),
                ["extensions"],
            ),
        ),
    ):
        scenario(
            label,
            ["records.md 6.1", "fields.md 12.2", "fields.md 12.4", "sync.md 25.9"],
            per_field_delete,
            [
                (data(1, first), done("APPLIED", 1, "there", first)),
                (change("extensions", [cat("276098100123456", "black"), vet_ext]), None),
                (
                    data(2, second),
                    done("MERGED", 2, "there", dict(v1, extensions=[kept_cat, vet_2]), ["extensions"]),
                ),
                (data(3, third), last),
            ],
            known,
        )

    # The sender removes the extension that the user changed within: the user's extension stays.
    scenario(
        "an extension that the user changed within stays when the sender removes it",
        ["records.md 6.1", "fields.md 12.4"],
        per_field_delete,
        [
            (data(1, first), done("APPLIED", 1, "there", first)),
            (change("extensions", [cat("276098100123456", "black"), vet_ext]), None),
            (
                data(2, dict(v1, extensions=[vet_ext])),
                done(
                    "MERGED",
                    2,
                    "there",
                    dict(v1, extensions=[vet_ext, cat("276098100123456", "black")]),
                    ["extensions"],
                ),
            ),
        ],
        [sy.CAT_TEXT],
    )

    # Every value in the sessions is a valid record of its type: it encodes with the type's schema, and its
    # time values and the checks of its schema hold (spec/time.md, section 8; spec/metadata.md, section 6).
    schemas = {
        f"axt.example.v1.{n}": json.loads((EXAMPLES / f"{n}.1.avsc").read_text(encoding="utf-8"))
        for n in TYPE_FPS
    }
    for v in c.vectors:
        for event, result in zip(v["input"]["events"], v["expected"]["steps"], strict=True):
            m = event.get("message", {})
            if m.get("kind") != "DATA":
                continue
            for value in (m["value"], result.get("value")):
                if value is not None:
                    schema = schemas[m["type"]]
                    datum = dict(  # the bytes of an extension, which the values hold as hex (section 3.3)
                        value,
                        extensions=[
                            dict(e, data=bytes.fromhex(e["data"])) for e in value.get("extensions", [])
                        ],
                    )
                    assert decode_meaning(json.dumps(schema), None, avro_encode(schema, datum)) == value, v[
                        "id"
                    ]
                    assert tm.receiver_breaches(schema, value) == [], v["id"]
    relation_sessions(c)
    return c


def relation_sessions(c: Category) -> None:
    """The cases of keys_examples.relation_cases as sessions: a receiver that resolves the relations it
    holds across senders (spec/records.md, section 10) and follows the devices of its known senders with
    signed chains (spec/keys.md, section 5.5)."""

    def rid(r: str) -> str:
        return RECORD_IDS[r]

    def qid(q: str) -> str:
        return RELATION_IDS[q]

    for name, what, senders, records, relations, steps in keys.relation_cases():
        receiver = keys.relation_receiver(senders, records, relations, set_key, rid, qid)
        start = receiver.state()
        own = {
            "name": receiver.own.name,
            "current": sorted(k.hex() for k in receiver.own.current),
            "removed": sorted(k.hex() for k in receiver.own.removed),
            "records": [
                {"id": r, "version": receiver.own.records[r][0], "state": receiver.own.records[r][1]}
                for r in sorted(receiver.own.records)
            ],
        }
        held = [
            {
                "id": qid(q),
                "holder": {"sender": holder, "id": rid(r)},
                "target": {"sender": None if k is None else H(set_key(k)), "id": rid(target)},
            }
            for q, holder, r, k, target in relations
        ]
        inputs: list[dict[str, Any]] = []
        expected: list[dict[str, Any]] = []
        for step in steps:
            if step[0] == "chain":
                built = [set_message(*m) for m in step[1]]
                got = receiver.chain([model for _, model in built])
                assert got == step[2], (name, got)
                inputs.append({"chain": [B(m) for m, _ in built]})
                expected.append({"results": got})
            else:
                lookup = receiver.lookup()
                assert lookup == keys.expected_lookup(relations, step, rid, qid), (name, lookup)
                inputs.append({"lookup": True})
                expected.append(lookup)
        c.add(
            "relations",
            what,
            ["records.md 10.1", "records.md 10.2", "records.md 10.3"]
            + (["records.md 10.5"] if name == "own-link" else [])
            + (["keys.md 3.4"] if name == "any-key" else [])
            + (["keys.md 5.5"] if name in ("chain", "join") else []),
            {
                "own": own,
                "senders": start,
                "refused": sorted(H(k) for k in receiver.refused),
                "relations": held,
                "steps": inputs,
            },
            {"steps": expected},
        )


# --- shares (spec/shares.md) ------------------------------------------------------------------
# The expected results are written out from spec/shares.md; the receiver and the sender of
# shares_examples.py must reach each of them.


def withdrawal_versions() -> list[tuple[str, list[str], dict[str, Any], Any]]:
    """The versions of a withdrawal and of a sharing again (spec/shares.md, sections 3.2 and 6.2): the
    cases of an installation that counts go to the category shares, those of a device that stamps,
    which needs the stamps of spec/sync.md, to the category sync."""
    now = 1763459400000  # 2025-11-18 09:50 UTC
    clock = now * 65536
    cases: list[tuple[str, list[str], dict[str, Any], Any]] = [
        (
            "an installation that counts withdraws with the next count, and its state stays",
            ["shares.md 3.2"],
            {"occasion": "withdraw", "counted": True, "highest_given": "3", "state_stamp": "3"},
            ("4", "3"),
        ),
        (
            "an installation that counts shares again with the next count, its new version",
            ["shares.md 6.2"],
            {"occasion": "share_again", "counted": True, "highest_given": "4", "state_stamp": "3"},
            ("5", "5"),
        ),
        (
            "a device that stamps withdraws with the next stamp, which is no state stamp",
            ["shares.md 3.2", "sync.md 2.2"],
            {
                "occasion": "withdraw",
                "counted": False,
                "now_ms": str(now),
                "highest": str(clock - 9),
                "r": 7,
                "withdrawals": [],
                "state_stamp": str(clock - 9),
            },
            (str(clock + 7), str(clock - 9)),
        ),
        (
            "a device that stamps counts the recorded withdrawals as stamps it has seen",
            ["shares.md 3.2", "shares.md 2.1"],
            {
                "occasion": "withdraw",
                "counted": False,
                "now_ms": str(now),
                "highest": str(clock - 9),
                "r": 7,
                "withdrawals": [str(clock + 500), str(clock + 100)],
                "state_stamp": str(clock - 9),
            },
            (str(clock + 508), str(clock - 9)),
        ),
        (
            "a device that stamps shares again with a new state stamp above the withdrawal",
            ["shares.md 6.2", "sync.md 3.3"],
            {
                "occasion": "share_again",
                "counted": False,
                "now_ms": str(now - 1),
                "highest": str(clock - 9),
                "r": 3,
                "withdrawals": [str(clock + 500)],
                "state_stamp": str(clock - 9),
            },
            (str(clock + 504), str(clock + 504)),
        ),
        (
            "a device that can take no stamp sends no WITHDRAW",
            ["shares.md 3.2", "sync.md 2.3"],
            {
                "occasion": "withdraw",
                "counted": False,
                "now_ms": str(now),
                "highest": str(sy.LAST_BASE),
                "r": 0,
                "withdrawals": [],
                "state_stamp": "5",
            },
            (None, "5"),
        ),
    ]
    out: list[tuple[str, list[str], dict[str, Any], Any]] = []
    for label, refs, i, want in cases:
        full = {"highest_given": "0", "now_ms": "0", "highest": "0", "r": 0, "withdrawals": [], **i}
        version, state, highest = se.take_version(
            full["occasion"],
            full["counted"],
            int(full["highest_given"]),
            int(full["now_ms"]),
            int(full["highest"]),
            full["r"],
            [int(w) for w in full["withdrawals"]],
            int(full["state_stamp"]),
        )
        assert (sy.stamp_json(version), str(state)) == want, (label, version, state)
        out.append((label, refs, dict(i), (*want, str(highest))))
    return out


def shares_category() -> Category:
    c = Category(
        "shares",
        "A receiver applying the withdrawals of one sender among its other record messages, and what a "
        "sender does: the version of a withdrawal, what it owes a receiver, what it does with an outcome "
        "(spec/shares.md).",
    )
    rid, other = se.REC_ID, "7c9e6679-7425-40de-944b-e07fc1f90ae7"
    v1 = {
        "title": "Vet",
        "start": tm.zoned(2025, 11, 18, 10, 0, tm.BERLIN, tm.CET),
        "end": None,
        "all_day": False,
        "location": "",
        "notes": "",
        "reminders": [],
        "relations": [],
        "extensions": [],
    }
    v3 = dict(v1, start=tm.zoned(2025, 11, 18, 10, 30, tm.BERLIN, tm.CET), notes="Bring the vaccination card")
    task = json.loads(json.dumps(rules.DATA["Task"]))
    mine = "Dr. Weber, Hauptstr. 5"
    merged = dict(v3, location=mine)

    def withdraw(version: int, record_id: str = rid) -> dict[str, Any]:
        return {"message": {"kind": "WITHDRAW", "id": record_id, "version": version}}

    def take(record_id: str = rid) -> dict[str, Any]:
        return {"local_take": {"id": record_id}}

    def policy(on_delete: str, on_withdraw: str | None) -> dict[str, Any]:
        p = {"local_changes": "per_field", "delete_with_local_changes": on_delete}
        if on_withdraw is not None:
            p["withdraw_with_local_changes"] = on_withdraw
        return p

    def scenario(label: str, refs: list[str], pol: dict[str, Any], steps: list[Any]) -> None:
        events = [e for e, _ in steps]
        results = [{} if r is None else r for _, r in steps]
        assert se.apply(pol, json.loads(json.dumps(events))) == results, label
        c.add("receive", label, refs, {"policy": pol, "events": events}, {"steps": results})

    gone = "withdrawn"
    scenario(
        "the example of shares.md, section 11.1",
        ["shares.md 4.2", "shares.md 4.3", "shares.md 6.2", "shares.md 11.1", "protocol.md 7.3"],
        policy("delete", "keep"),
        [
            (data(3, v3), done("APPLIED", 3, "there", v3)),
            (withdraw(4), done("WITHDRAWN", 4, gone, None)),
            (data(3, v3), done("STALE", 4, gone, None)),
            (data(5, v3), done("APPLIED", 5, "there", v3)),
            (change("location", mine), None),
            (withdraw(6), done("KEPT", 6, "there", merged)),
            (take(), done("WITHDRAWN", 6, gone, None)),
        ],
    )
    scenario(
        "a WITHDRAW of an id the receiver does not have leaves a tombstone that older and equal versions "
        "do not pass, and a later DATA shares the record again",
        ["shares.md 4.2", "shares.md 6.2", "records.md 5.3"],
        policy("delete", None),
        [
            (withdraw(4, other), done("WITHDRAWN", 4, gone, None)),
            (data(3, v1, other), done("STALE", 4, gone, None)),
            (data(4, v1, other), done("DUPLICATE", 4, gone, None)),
            (withdraw(4, other), done("DUPLICATE", 4, gone, None)),
            (data(5, task, other, TASK_T), done("APPLIED", 5, "there", task)),
        ],
    )
    scenario(
        "a WITHDRAW removes a record its user has not changed, also at a receiver that keeps changes",
        ["shares.md 4.2", "shares.md 4.3"],
        policy("keep", "keep"),
        [(data(1, v1), done("APPLIED", 1, "there", v1)), (withdraw(2), done("WITHDRAWN", 2, gone, None))],
    )
    scenario(
        "a WITHDRAW removes a record its user changed at a receiver that removes it",
        ["shares.md 4.3", "records.md 6.4"],
        policy("keep", "delete"),
        [
            (data(1, v1), done("APPLIED", 1, "there", v1)),
            (change("location", mine), None),
            (withdraw(2), done("WITHDRAWN", 2, gone, None)),
            (data(3, v3), done("APPLIED", 3, "there", v3)),
        ],
    )
    scenario(
        "a record its user changed is kept against a WITHDRAW, and a later DATA is merged into it",
        ["shares.md 4.3", "shares.md 6.2"],
        policy("delete", "keep"),
        [
            (data(1, v1), done("APPLIED", 1, "there", v1)),
            (change("location", mine), None),
            (withdraw(2), done("KEPT", 2, "there", dict(v1, location=mine))),
            (data(1, v1), done("STALE", 2, "there", dict(v1, location=mine))),
            (data(3, v3), done("MERGED", 3, "there", merged, ["location"])),
        ],
    )
    scenario(
        "a record kept against a DELETE meets a WITHDRAW, and one kept against a WITHDRAW meets a DELETE",
        ["shares.md 4.2", "shares.md 4.3", "shares.md 6.3"],
        policy("keep", "keep"),
        [
            (data(1, v1), done("APPLIED", 1, "there", v1)),
            (change("location", mine), None),
            (delete(2), done("KEPT", 2, "there", dict(v1, location=mine))),
            (withdraw(3), done("KEPT", 3, "there", dict(v1, location=mine))),
            (delete(4), done("KEPT", 4, "there", dict(v1, location=mine))),
            (take(), done("APPLIED", 4, "tombstone", None)),
        ],
    )
    scenario(
        "a receiver may choose otherwise for a WITHDRAW than for a DELETE",
        ["shares.md 4.3"],
        policy("keep", "delete"),
        [
            (data(1, v1), done("APPLIED", 1, "there", v1)),
            (change("location", mine), None),
            (delete(2), done("KEPT", 2, "there", dict(v1, location=mine))),
            (withdraw(3), done("WITHDRAWN", 3, gone, None)),
        ],
    )
    scenario(
        "a WITHDRAW of a record its user deleted: the user's deletion goes on standing beside it",
        ["shares.md 4.2", "records.md 6.3"],
        policy("delete", None),
        [
            (data(1, v1), done("APPLIED", 1, "there", v1)),
            (user_delete(), None),
            (withdraw(2), done("WITHDRAWN", 2, "deleted_by_user", None)),
            (data(3, v3), done("KEPT", 3, "deleted_by_user", None)),
        ],
    )
    scenario(
        "a WITHDRAW of a record its user changed and then deleted: the deletion decides, WITHDRAWN, never "
        "KEPT",
        ["shares.md 4.2", "records.md 6.3"],
        policy("keep", "keep"),
        [
            (data(1, v1), done("APPLIED", 1, "there", v1)),
            (change("location", mine), None),
            (user_delete(), None),
            (withdraw(2), done("WITHDRAWN", 2, "deleted_by_user", None)),
        ],
    )
    scenario(
        "a WITHDRAW after a DELETE, a DELETE after a WITHDRAW, and a WITHDRAW after a WITHDRAW",
        ["shares.md 4.2", "shares.md 6.3"],
        policy("delete", None),
        [
            (data(1, v1), done("APPLIED", 1, "there", v1)),
            (delete(2), done("APPLIED", 2, "tombstone", None)),
            (withdraw(3), done("WITHDRAWN", 3, gone, None)),
            (delete(2), done("STALE", 3, gone, None)),
            (delete(4), done("APPLIED", 4, "tombstone", None)),
            (withdraw(5), done("WITHDRAWN", 5, gone, None)),
            (withdraw(6), done("WITHDRAWN", 6, gone, None)),
            (data(7, v3), done("APPLIED", 7, "there", v3)),
        ],
    )
    scenario(
        "one version in two kinds: the first that arrives is applied, the second is a duplicate",
        ["shares.md 6.3", "records.md 3"],
        policy("delete", None),
        [
            (data(4, v1), done("APPLIED", 4, "there", v1)),
            (withdraw(4), done("DUPLICATE", 4, "there", v1)),
            (withdraw(5), done("WITHDRAWN", 5, gone, None)),
            (delete(5), done("DUPLICATE", 5, gone, None)),
        ],
    )
    scenario(
        "two devices of the sender send the same withdrawal: the receiver takes the first",
        ["shares.md 7.2"],
        policy("delete", None),
        [
            (data(1, v1), done("APPLIED", 1, "there", v1)),
            (withdraw(2), done("WITHDRAWN", 2, gone, None)),
            (withdraw(2), done("DUPLICATE", 2, gone, None)),
        ],
    )
    scenario(
        "a record keeps its type through a tombstone of a withdrawal",
        ["shares.md 4.2", "records.md 4.3"],
        policy("delete", None),
        [
            (data(1, v1), done("APPLIED", 1, "there", v1)),
            (withdraw(2), done("WITHDRAWN", 2, gone, None)),
            (data(3, task, rid, TASK_T), failed("TYPE_CHANGED")),
            (data(3, v1), done("APPLIED", 3, "there", v1)),
        ],
    )
    scenario(
        "a WITHDRAW that cannot be processed changes nothing",
        ["shares.md 4.1"],
        policy("delete", None),
        [
            (data(1, v1), done("APPLIED", 1, "there", v1)),
            (withdraw(2, "vet-appointment"), failed("RECORD_ID_INVALID")),
            (withdraw(2, "00000000-0000-0000-0000-000000000000"), failed("RECORD_ID_INVALID")),
            (withdraw(0), failed("VERSION_INVALID")),
            (withdraw(-1), failed("VERSION_INVALID")),
            (data(1, v1), done("DUPLICATE", 1, "there", v1)),
        ],
    )
    # The version of a withdrawal and of a sharing again by an installation that counts (sections 3.2 and
    # 6.2); those of a device that stamps are in the category sync.
    for label, refs, i, want in withdrawal_versions():
        if i.pop("counted"):
            c.add("take_version", label, refs, i, accept({"version": want[0], "state_stamp": want[1]}))

    # What a device owes a receiver (sections 5.3 and 6.1).
    def last(kind: str, version: int) -> dict[str, Any]:
        return {"kind": kind, "version": str(version)}

    cases_2: list[tuple[str, list[str], dict[str, Any], Any]] = [
        (
            "a record that is shared: its DATA under its state stamp",
            ["shares.md 5.3"],
            {"shared": True, "deleted": False, "version": "7", "withdrawal": None, "last": None},
            ("DATA", "7"),
        ),
        (
            "a deleted record that is shared: its DELETE",
            ["shares.md 5.3"],
            {"shared": True, "deleted": True, "version": "8", "withdrawal": None, "last": last("DATA", 7)},
            ("DELETE", "8"),
        ),
        (
            "a record that is shared again: its DATA, though a withdrawal is recorded",
            ["shares.md 5.3", "shares.md 6.2"],
            {
                "shared": True,
                "deleted": False,
                "version": "5",
                "withdrawal": "4",
                "last": last("WITHDRAW", 4),
            },
            ("DATA", "5"),
        ),
        (
            "a record withdrawn from the receiver: the WITHDRAW under the recorded version, not its state "
            "stamp",
            ["shares.md 5.3", "shares.md 7.2"],
            {
                "shared": False,
                "deleted": False,
                "version": "7",
                "withdrawal": "6",
                "last": last("WITHDRAW", 6),
            },
            ("WITHDRAW", "6"),
        ),
        (
            "a sibling that got the withdrawal by sibling sync owes the recorded WITHDRAW",
            ["shares.md 6.1", "shares.md 7.2"],
            {"shared": False, "deleted": False, "version": "3", "withdrawal": "4", "last": None},
            ("WITHDRAW", "4"),
        ),
        (
            "a device whose last DATA is below the recorded withdrawal owes the recorded WITHDRAW",
            ["shares.md 6.1", "shares.md 5.3"],
            {"shared": False, "deleted": False, "version": "7", "withdrawal": "6", "last": last("DATA", 5)},
            ("WITHDRAW", "6"),
        ),
        (
            "a record never shared with the receiver: nothing",
            ["shares.md 2.2", "shares.md 5.3"],
            {"shared": False, "deleted": False, "version": "3", "withdrawal": None, "last": None},
            ("nothing", None),
        ),
        (
            "a record whose last message to the receiver was a DELETE, without a recorded withdrawal: "
            "nothing",
            ["shares.md 5.3", "shares.md 6.1"],
            {"shared": False, "deleted": True, "version": "4", "withdrawal": None, "last": last("DELETE", 4)},
            ("nothing", None),
        ),
        (
            "a device that sent a DATA above the recorded withdrawal withdraws the record itself",
            ["shares.md 6.1"],
            {"shared": False, "deleted": False, "version": "9", "withdrawal": "6", "last": last("DATA", 8)},
            ("new_withdrawal", None),
        ),
        (
            "a device whose last message was a DATA and that holds no withdrawal of a record no longer "
            "shared withdraws it",
            ["shares.md 5.3", "shares.md 6.1"],
            {"shared": False, "deleted": False, "version": "3", "withdrawal": None, "last": last("DATA", 3)},
            ("new_withdrawal", None),
        ),
    ]
    for label, refs, i, want in cases_2:
        sent = None if i["last"] is None else (i["last"]["kind"], int(i["last"]["version"]))
        got = se.owed(
            i["shared"],
            i["deleted"],
            int(i["version"]),
            None if i["withdrawal"] is None else int(i["withdrawal"]),
            sent,
        )
        assert (got[0], sy.stamp_json(got[1])) == want, (label, got)
        c.add("owed", label, refs, i, accept({"owes": want[0], "version": want[1]}))

    # What a device does with the version to pass after the wait (section 5.3).
    passes: list[tuple[str, dict[str, Any], str]] = [
        (
            "a withdrawn record whose recorded withdrawal is still below the version to pass: a new "
            "withdrawal, though the state stamp is above it",
            {"shared": False, "withdrawal": "6", "to_pass": "8", "state_stamp": "9"},
            "new_withdrawal",
        ),
        (
            "a withdrawn record whose recorded withdrawal a sibling has taken above the version to pass: "
            "nothing more",
            {"shared": False, "withdrawal": "9", "to_pass": "8", "state_stamp": "7"},
            "nothing",
        ),
        (
            "a withdrawn record with no recorded withdrawal: a new withdrawal",
            {"shared": False, "withdrawal": None, "to_pass": "8", "state_stamp": "9"},
            "new_withdrawal",
        ),
        (
            "a record shared again by the end of the wait, whose state stamp is above the version to pass: "
            "what it owes, under that state stamp",
            {"shared": True, "withdrawal": "6", "to_pass": "8", "state_stamp": "9"},
            "nothing",
        ),
        (
            "a record shared again by the end of the wait, whose state stamp is below the version to pass: "
            "its current state under a new state stamp",
            {"shared": True, "withdrawal": "6", "to_pass": "8", "state_stamp": "7"},
            "send_state",
        ),
    ]
    for label, i, want in passes:
        then, to_pass = se.pass_withdrawal(
            i["shared"],
            None if i["withdrawal"] is None else int(i["withdrawal"]),
            int(i["to_pass"]),
            int(i["state_stamp"]),
        )
        assert (then, to_pass) == (want, None), label
        c.add(
            "pass_withdrawal",
            label,
            ["shares.md 5.3", "sync.md 5.3"],
            i,
            accept({"then": want, "to_pass": None}),
        )

    # Two receivers that join (section 7.3).
    for label, a, b, want in [
        (
            "a record shared with one and withdrawn from the other: shared, sent under a new state stamp",
            (True, None),
            (False, 6),
            (True, "6", True),
        ),
        ("a record shared with both: shared", (True, None), (True, None), (True, None, False)),
        (
            "a record withdrawn from both: withdrawn, with the higher recorded withdrawal",
            (False, 6),
            (False, 9),
            (False, "9", False),
        ),
        (
            "a record withdrawn from one and never shared with the other: withdrawn",
            (False, None),
            (False, 6),
            (False, "6", False),
        ),
        ("a record shared with neither: nothing", (False, None), (False, None), (False, None, False)),
    ]:
        got_j = se.joined(a, b)
        assert (got_j[0], sy.stamp_json(got_j[1]), got_j[2]) == want, label
        side = [{"shared": x[0], "withdrawal": sy.stamp_json(x[1])} for x in (a, b)]
        c.add(
            "join_receivers",
            label,
            ["shares.md 7.3", "sync.md 3.3"],
            {"receivers": side},
            accept({"shared": want[0], "withdrawal": want[1], "new_state_stamp": want[2]}),
        )

    # The offer to an app of another user (section 2.2).
    for label, records, want in [
        (
            "a type is offered for a WITHDRAW still owed, and the count counts it",
            [("Appointment", "WITHDRAW", False), ("Appointment", "DATA", False), ("Pet", "nothing", False)],
            [("Appointment", 2)],
        ),
        (
            "a type whose only record is withdrawn with an outcome, or never shared, is not offered",
            [("Appointment", "WITHDRAW", True), ("Pet", "nothing", False), ("Task", "DELETE", False)],
            [("Task", 1)],
        ),
    ]:
        typed = [(f"axt.example.v1.{t}", o, d) for t, o, d in records]
        assert se.offer(typed) == [(f"axt.example.v1.{t}", n) for t, n in want], label
        c.add(
            "offer_types",
            label,
            ["shares.md 2.2", "protocol.md 4.1"],
            {"records": [{"type": t, "owes": o, "delivered": d} for t, o, d in typed]},
            accept({"types": [{"type": f"axt.example.v1.{t}", "count": n} for t, n in want]}),
        )

    # What a device does with an outcome (sections 5.2 and 5.3).
    base: dict[str, Any] = {
        "held": None,
        "receiver_version": "6",
        "shared": False,
        "withdrawal": "6",
        "state_stamp": "5",
        "sibling_stamp": None,
        "sibling": False,
    }
    cases_3: list[tuple[str, list[str], dict[str, Any], Any]] = [
        (
            "WITHDRAWN delivers a WITHDRAW",
            ["shares.md 5.2"],
            {"sent": "WITHDRAW", "outcome": "WITHDRAWN"},
            ("WITHDRAWN", "nothing", None),
        ),
        (
            "KEPT delivers a WITHDRAW",
            ["shares.md 5.2"],
            {"sent": "WITHDRAW", "outcome": "KEPT"},
            ("KEPT", "nothing", None),
        ),
        (
            "a later WITHDRAWN replaces KEPT",
            ["shares.md 5.2", "protocol.md 7.3"],
            {"sent": "WITHDRAW", "held": "KEPT", "outcome": "WITHDRAWN"},
            ("WITHDRAWN", "nothing", None),
        ),
        (
            "a later KEPT does not replace WITHDRAWN",
            ["shares.md 5.2", "protocol.md 7.4"],
            {"sent": "WITHDRAW", "held": "WITHDRAWN", "outcome": "KEPT"},
            ("WITHDRAWN", "nothing", None),
        ),
        (
            "WITHDRAWN replaces DUPLICATE",
            ["shares.md 5.2", "protocol.md 7.4"],
            {"sent": "WITHDRAW", "held": "DUPLICATE", "outcome": "WITHDRAWN"},
            ("WITHDRAWN", "nothing", None),
        ),
        (
            "APPLIED for a WITHDRAW is taken as DUPLICATE",
            ["shares.md 5.2"],
            {"sent": "WITHDRAW", "outcome": "APPLIED"},
            ("DUPLICATE", "nothing", None),
        ),
        (
            "MERGED for a WITHDRAW is taken as DUPLICATE, and does not replace KEPT",
            ["shares.md 5.2"],
            {"sent": "WITHDRAW", "held": "KEPT", "outcome": "MERGED"},
            ("KEPT", "nothing", None),
        ),
        (
            "WITHDRAWN for a DATA is taken as DUPLICATE",
            ["shares.md 5.2"],
            {"sent": "DATA", "outcome": "WITHDRAWN"},
            ("DUPLICATE", "nothing", None),
        ),
        (
            "WITHDRAWN for a DELETE does not replace KEPT",
            ["shares.md 5.2"],
            {"sent": "DELETE", "held": "KEPT", "outcome": "WITHDRAWN"},
            ("KEPT", "nothing", None),
        ),
        (
            "a DATA sent before the withdrawal and answered with STALE and its version: nothing more",
            ["shares.md 5.3", "shares.md 11.1"],
            {
                "sent": "DATA",
                "held": "APPLIED",
                "outcome": "STALE",
                "receiver_version": "4",
                "withdrawal": "4",
                "state_stamp": "3",
            },
            ("APPLIED", "nothing", None),
        ),
        (
            "STALE for a DATA above every version the device knows: a new withdrawal where it is withdrawn",
            ["shares.md 5.3", "sync.md 5.3"],
            {
                "sent": "DATA",
                "outcome": "STALE",
                "receiver_version": "9",
                "withdrawal": "6",
                "state_stamp": "7",
                "sibling_stamp": "8",
            },
            ("STALE", "new_withdrawal", None),
        ),
        (
            "STALE for a DATA above every version the device knows: the current state where it is shared",
            ["shares.md 5.3", "sync.md 5.3"],
            {
                "sent": "DATA",
                "outcome": "STALE",
                "receiver_version": "9",
                "shared": True,
                "withdrawal": "6",
                "state_stamp": "7",
            },
            ("STALE", "send_state", None),
        ),
        (
            "STALE for a DATA at the version of a sibling's state stamp: nothing more",
            ["shares.md 5.3", "sync.md 5.3"],
            {
                "sent": "DATA",
                "outcome": "STALE",
                "receiver_version": "8",
                "withdrawal": "6",
                "state_stamp": "7",
                "sibling_stamp": "8",
            },
            ("STALE", "nothing", None),
        ),
        (
            "STALE for a WITHDRAW above its version: a new withdrawal, whatever the state stamps",
            ["shares.md 5.3"],
            {
                "sent": "WITHDRAW",
                "outcome": "STALE",
                "receiver_version": "7",
                "withdrawal": "6",
                "state_stamp": "9",
                "sibling_stamp": "9",
            },
            ("STALE", "new_withdrawal", None),
        ),
        (
            "STALE for a WITHDRAW of an older withdrawal: nothing more",
            ["shares.md 5.3"],
            {"sent": "WITHDRAW", "outcome": "STALE", "receiver_version": "6", "withdrawal": "6"},
            ("STALE", "nothing", None),
        ),
        (
            "STALE for a WITHDRAW above its version at a device with siblings: it waits for them",
            ["shares.md 5.3", "sync.md 5.3"],
            {
                "sent": "WITHDRAW",
                "outcome": "STALE",
                "receiver_version": "7",
                "withdrawal": "6",
                "sibling": True,
            },
            ("STALE", "wait", "7"),
        ),
    ]
    for label, refs, i, want in cases_3:
        full = {**base, **i}
        held, then, to_pass = se.acked(
            full["sent"],
            full["held"],
            full["outcome"],
            int(full["receiver_version"]),
            full["shared"],
            None if full["withdrawal"] is None else int(full["withdrawal"]),
            int(full["state_stamp"]),
            None if full["sibling_stamp"] is None else int(full["sibling_stamp"]),
            full["sibling"],
        )
        assert (held, then, sy.stamp_json(to_pass)) == want, (label, held, then, to_pass)
        c.add("acked", label, refs, full, accept({"outcome": want[0], "then": want[1], "to_pass": want[2]}))
    shared_values(c)
    proposal_vectors(c)
    return c


def shared_values(c: Category) -> None:
    """What a sender sends one receiver of a record with relations and an extension (spec/shares.md,
    sections 19.1 and 19.2): the expected values are written out here, from the rules."""
    mimi, vet, praxis = (se.json_form(r) for r in rules.RELATIONS["Appointment"])
    cat_ext = se.json_form(rules.MIMI_CAT)
    value = dict(se.json_form(rules.DATA["Appointment"]), relations=[mimi, vet, praxis], extensions=[cat_ext])
    own = H(CAT)  # the sender's own key, cat-a-log's
    other = rules.OTHER_SENDER.hex()  # the sender of the vet's record
    cases: list[tuple[str, list[str], dict[str, Any], dict[str, Any]]] = [
        (
            "a share that leaves out the links sends the relations to shared records of the own set only, "
            "and no extension",
            ["shares.md 19.1"],
            {"own_user": False, "links": False, "shared": [rules.PET_ID], "own_keys": [own]},
            dict(value, relations=[mimi], extensions=[]),
        ),
        (
            "a relation to a record of the own set that is not shared with the receiver is left out",
            ["shares.md 19.1", "shares.md 19.2"],
            {"own_user": False, "links": False, "shared": [], "own_keys": [own]},
            dict(value, relations=[], extensions=[]),
        ),
        (
            "a relation that names the own set by one of its keys goes along where its target is shared",
            ["shares.md 19.1", "fields.md 11.3"],
            {
                "own_user": False,
                "links": False,
                "shared": [rules.PET_ID, rules.VET_ID],
                "own_keys": [own, other],
            },
            dict(value, relations=[mimi, vet], extensions=[]),
        ),
        (
            "a share that lets the links go along sends the record whole",
            ["shares.md 19.1"],
            {"own_user": False, "links": True, "shared": [], "own_keys": [own]},
            value,
        ),
        (
            "an app of the sender's own user gets the record whole, without a share",
            ["shares.md 19.1", "shares.md 2.3"],
            {"own_user": True, "links": False, "shared": [], "own_keys": [own]},
            value,
        ),
    ]
    for label, refs, i, want in cases:
        full = {"type": se.AP_TYPE, "value": value, **i}
        got = se.shared_value(
            se.AP_TYPE, value, i["own_user"], i["links"], set(i["shared"]), set(i["own_keys"])
        )
        assert got == want, label
        c.add("shared_value", label, refs, full, accept({"value": want}))


def proposal_vectors(c: Category) -> None:
    """The sessions of an owner that takes proposals and of a proposer (spec/shares.md, sections 12 to 18),
    played with the models of shares_examples.py; each step's expected result is written out below and
    checked against the model."""
    obf, cat = H(OBF), H(CAT)
    second_seed = sy.SEEDS["second app"]
    second = H(sy.KEY["second app"])
    sibling_seed = sy.TABLET_SEED
    rid, other_id, pet_id = (
        se.REC_ID,
        "7c9e6679-7425-40de-944b-e07fc1f90ae7",
        "1d2e3f40-5a6b-4c7d-8e9f-0a1b2c3d4e5f",
    )
    gone_id, alone_id = "2e3f4051-6b7c-4d8e-9fa0-1b2c3d4e5f60", "3f405162-7c8d-4e9f-a0b1-2c3d4e5f6071"
    unknown_id = "40516273-8d9e-4fa0-b1c2-3d4e5f607182"
    ap1, ap2 = se.APPOINTMENT_TEXT, sy.APPOINTMENT_2
    fp1, fp2 = se.APPOINTMENT_FP, sy.schema_fingerprint(ap2)
    pet_text = pe.PET_TEXT
    pet_fp = sy.schema_fingerprint(pet_text)
    v3 = se.json_form(se.V3_OWNER)
    pet_value = se.json_form(rules.DATA["Pet"])
    start11 = se.START_VALUE
    start1030 = sy.field_value(se.APPOINTMENT_SCHEMA, "start", se.V3_OWNER["start"])
    start1130 = sy.field_value(se.APPOINTMENT_SCHEMA, "start", se.berlin(11, 30))
    pids = [f"0000000{n}-9e0a-4000-8000-00000000000{n}" for n in range(1, 10)]

    def owner_device(**more: Any) -> dict[str, Any]:
        d = {
            "seed": H(CAT_SEED),
            "siblings": [H(sy.TABLET)],
            "proposals": ["axt.example.v1.Appointment"],
            "schemas": [ap1, pet_text],
            "receivers": [
                {"name": "Old Brain Fix", "current": [obf], "removed": []},
                {"name": "second app", "current": [second], "removed": []},
            ],
            "records": [
                {
                    "id": rid,
                    "type": se.AP_TYPE,
                    "version": "3",
                    "state": "there",
                    "value": v3,
                    "shared": ["Old Brain Fix"],
                },
                {
                    "id": other_id,
                    "type": se.AP_TYPE,
                    "version": "1",
                    "state": "there",
                    "value": v3,
                    "shared": ["Old Brain Fix", "second app"],
                },
                {
                    "id": pet_id,
                    "type": "axt.example.v1.Pet",
                    "version": "1",
                    "state": "there",
                    "value": pet_value,
                    "shared": ["Old Brain Fix"],
                },
                {
                    "id": gone_id,
                    "type": se.AP_TYPE,
                    "version": "2",
                    "state": "deleted",
                    "value": v3,
                    "shared": ["Old Brain Fix"],
                },
                {
                    "id": alone_id,
                    "type": se.AP_TYPE,
                    "version": "1",
                    "state": "there",
                    "value": v3,
                    "shared": [],
                },
            ],
            "open": [],
            "answers": [],
        }
        d.update(more)
        return d

    def P(
        entries: list[tuple[str, bytes, bytes]] | None = None,
        pid: str = se.PROPOSAL_ID,
        record: tuple[str, int] | None = (rid, 3),
        seed: bytes = OBF_SEED,
        to: bytes = CAT,
        body: bytes | None = None,
    ) -> bytes:
        es = [("start", fp1, start11)] if entries is None else entries
        b = se.proposal_body(to, pid, es) if body is None else body
        return cast(bytes, sy.message(seed, "PROPOSAL", record, b))

    def reply(pid: str, answer: str, to: str = obf, record: tuple[str, int] = (rid, 3)) -> dict[str, Any]:
        return {
            "kind": "PROPOSAL_REPLY",
            "to": to,
            "record": {"id": record[0], "version": record[1]},
            "proposal_id": pid,
            "answer": answer,
        }

    def err(
        m: bytes,
        code: str,
        record: tuple[str, int] | None = (rid, 3),
        to: str = obf,
        fingerprint: bytes | None = None,
        field: str | None = None,
    ) -> dict[str, Any]:
        return {
            "kind": "ERROR",
            "to": to,
            "code": code,
            "message_hash": hashlib.sha256(m).hexdigest(),
            "record": record and {"id": record[0], "version": record[1]},
            "fingerprint": None if fingerprint is None else fingerprint.hex(),
            "field": field,
        }

    def got(result: str, *replies: dict[str, Any]) -> dict[str, Any]:
        return {"result": result, "replies": list(replies)}

    def owner(
        label: str, refs: list[str], device: dict[str, Any], steps: list[tuple[dict[str, Any], Any]]
    ) -> None:
        inputs = [
            json.loads(json.dumps({k: (H(v) if isinstance(v, bytes) else v) for k, v in st.items()}))
            for st, _ in steps
        ]
        played = se.owner_session({"device": device, "steps": inputs})
        for n, ((_, want), answer) in enumerate(zip(steps, played, strict=True)):
            if "replies" in answer:
                answer = {**answer, "replies": [se.said(m) for m in answer["replies"]]}
            assert answer == want, (label, n, answer, want)
        c.add(
            "owner",
            label,
            ["shares.md 13.3", *refs],
            {"device": device, "steps": inputs},
            {"steps": [w for _, w in steps]},
        )

    def q(
        open_: list[tuple[str, str, str, bytes | None]],
        answers: list[tuple[str, str, str]],
        records: dict[str, tuple[str, str, Any]] | None = None,
        answered: tuple[str, int] = (rid, 3),
    ) -> dict[str, Any]:
        base = {r["id"]: (r["version"], r["state"], r["value"]) for r in owner_device()["records"]}
        base.update(records or {})
        return {
            "open": [
                {
                    "receiver": a,
                    "proposal_id": b,
                    "id": i,
                    "message_hash": msg and hashlib.sha256(msg).hexdigest(),
                }
                for a, b, i, msg in open_
            ],
            "answers": [
                {"receiver": a, "proposal_id": b, "answer": x, "id": answered[0], "version": answered[1]}
                for a, b, x in answers
            ],
            "records": [
                {"id": i, "version": v, "state": st, "value": val} for i, (v, st, val) in sorted(base.items())
            ],
        }

    v4 = dict(v3, start=se.json_form(se.START_11))
    m = P()
    owner(
        "the example of shares.md, section 11.3: a proposal taken, a "
        "repeat, the answer ACCEPTED and the update",
        ["shares.md 11.3", "shares.md 13.4", "shares.md 15.2"],
        owner_device(),
        [
            ({"receive": m}, got("taken")),
            ({"receive": m}, got("repeat")),
            ({"query": True}, q([("Old Brain Fix", se.PROPOSAL_ID, rid, m)], [])),
            (
                {
                    "answer": {
                        "receiver": "Old Brain Fix",
                        "proposal_id": se.PROPOSAL_ID,
                        "answer": "ACCEPTED",
                    }
                },
                {
                    "made": True,
                    "replies": [reply(se.PROPOSAL_ID, "ACCEPTED")],
                    "update": {"version": "4", "value": v4},
                },
            ),
            ({"receive": m}, got("repeat", reply(se.PROPOSAL_ID, "ACCEPTED"))),
            (
                {"receive": P(pid=se.PROPOSAL_ID, entries=[("title", fp1, sy.encoded("Dentist"))])},
                got("repeat", reply(se.PROPOSAL_ID, "ACCEPTED")),
            ),
            (
                {"query": True},
                q([], [("Old Brain Fix", se.PROPOSAL_ID, "ACCEPTED")], {rid: ("4", "there", v4)}),
            ),
        ],
    )
    owner(
        "a proposal declined: the reply DECLINED, no update, and a repeat gets the reply again",
        ["shares.md 13.4", "shares.md 14.1", "shares.md 15.1"],
        owner_device(),
        [
            ({"receive": m}, got("taken")),
            (
                {
                    "answer": {
                        "receiver": "Old Brain Fix",
                        "proposal_id": se.PROPOSAL_ID,
                        "answer": "DECLINED",
                    }
                },
                {"made": True, "replies": [reply(se.PROPOSAL_ID, "DECLINED")], "update": None},
            ),
            ({"receive": m}, got("repeat", reply(se.PROPOSAL_ID, "DECLINED"))),
            (
                {
                    "answer": {
                        "receiver": "Old Brain Fix",
                        "proposal_id": se.PROPOSAL_ID,
                        "answer": "ACCEPTED",
                    }
                },
                {"made": False, "replies": [], "update": None},
            ),
        ],
    )
    owner(
        "ACCEPTED stamps every proposed value, also those the record holds "
        "already: a new version and an update",
        ["shares.md 15.2"],
        owner_device(),
        [
            ({"receive": P([("start", fp1, start1030), ("title", fp1, sy.encoded("Vet"))])}, got("taken")),
            (
                {
                    "answer": {
                        "receiver": "Old Brain Fix",
                        "proposal_id": se.PROPOSAL_ID,
                        "answer": "ACCEPTED",
                    }
                },
                {
                    "made": True,
                    "replies": [reply(se.PROPOSAL_ID, "ACCEPTED")],
                    "update": {"version": "4", "value": v3},
                },
            ),
        ],
    )
    owner(
        "a proposal for a version that the owner left behind, and one for a version above its own, are taken",
        ["shares.md 13.3", "shares.md 15.3"],
        owner_device(),
        [
            ({"receive": P(pid=pids[0], record=(rid, 2))}, got("taken")),
            ({"receive": P(pid=pids[1], record=(rid, 9))}, got("taken")),
            (
                {"answer": {"receiver": "Old Brain Fix", "proposal_id": pids[0], "answer": "ACCEPTED"}},
                {
                    "made": True,
                    "replies": [reply(pids[0], "ACCEPTED", record=(rid, 2))],
                    "update": {"version": "4", "value": v4},
                },
            ),
        ],
    )
    owner(
        "an open proposal is dropped when its record is deleted, and a later one is not taken",
        ["shares.md 15.4", "shares.md 17.1"],
        owner_device(),
        [
            ({"receive": m}, got("taken")),
            ({"change": {"id": rid, "action": "delete"}}, {}),
            ({"query": True}, q([], [], {rid: ("3", "deleted", v3)})),
            (
                {
                    "answer": {
                        "receiver": "Old Brain Fix",
                        "proposal_id": se.PROPOSAL_ID,
                        "answer": "ACCEPTED",
                    }
                },
                {"made": False, "replies": [], "update": None},
            ),
            ({"receive": P(pid=pids[0])}, got("rejected", err(P(pid=pids[0]), "PROPOSALS_NOT_TAKEN"))),
        ],
    )
    owner(
        "an open proposal is dropped when its record is withdrawn "
        "from the proposer, and a dropped one does not "
        "come back when the record is shared again",
        ["shares.md 15.4", "shares.md 17.1"],
        owner_device(),
        [
            ({"receive": m}, got("taken")),
            ({"change": {"id": rid, "action": "unshare", "receiver": "Old Brain Fix"}}, {}),
            ({"receive": P(pid=pids[0])}, got("rejected", err(P(pid=pids[0]), "PROPOSALS_NOT_TAKEN"))),
            ({"change": {"id": rid, "action": "share", "receiver": "Old Brain Fix"}}, {}),
            ({"query": True}, q([], [])),
            ({"receive": m}, got("taken")),
        ],
    )
    # Step 1, in its order: the envelope and the signature, record, the body, to.
    signed_bad = m[:-1] + bytes([m[-1] ^ 1])
    for label, msg, want in [
        (
            "whose signature does not verify is rejected with SIGNATURE_INVALID",
            signed_bad,
            got("rejected", err(signed_bad, "SIGNATURE_INVALID", None)),
        ),
        (
            "without a record is rejected with INVALID_MESSAGE",
            P(record=None),
            got("rejected", err(P(record=None), "INVALID_MESSAGE", None)),
        ),
        (
            "with an empty body is rejected with INVALID_MESSAGE",
            P(body=b""),
            got("rejected", err(P(body=b""), "INVALID_MESSAGE")),
        ),
        (
            "with the body of a WITHDRAW is rejected with INVALID_MESSAGE",
            P(body=sy.body_of("Withdraw", {"to": CAT})),
            got("rejected", err(P(body=sy.body_of("Withdraw", {"to": CAT})), "INVALID_MESSAGE")),
        ),
        (
            "with a byte left over in its body is rejected with INVALID_MESSAGE",
            P(body=se.proposal_body(CAT, se.PROPOSAL_ID, [("start", fp1, start11)]) + b"\x00"),
            got(
                "rejected",
                err(
                    P(body=se.proposal_body(CAT, se.PROPOSAL_ID, [("start", fp1, start11)]) + b"\x00"),
                    "INVALID_MESSAGE",
                ),
            ),
        ),
        ("addressed to another key is ignored without a report", P(to=OBF), got("ignored")),
        (
            "without a record and addressed to another key is rejected: record comes before to",
            P(record=None, to=OBF),
            got("rejected", err(P(record=None, to=OBF), "INVALID_MESSAGE", None)),
        ),
        ("signed with the owner's own key is ignored", P(seed=CAT_SEED), got("ignored")),
        (
            "with the id vet is rejected with RECORD_ID_INVALID",
            P(record=("vet", 3)),
            got("rejected", err(P(record=("vet", 3)), "RECORD_ID_INVALID", ("vet", 3))),
        ),
        (
            "with the nil UUID as its record id is rejected with RECORD_ID_INVALID",
            P(record=("00000000-0000-0000-0000-000000000000", 3)),
            got(
                "rejected",
                err(
                    P(record=("00000000-0000-0000-0000-000000000000", 3)),
                    "RECORD_ID_INVALID",
                    ("00000000-0000-0000-0000-000000000000", 3),
                ),
            ),
        ),
        (
            "with the version 0 is rejected with VERSION_INVALID",
            P(record=(rid, 0)),
            got("rejected", err(P(record=(rid, 0)), "VERSION_INVALID", (rid, 0))),
        ),
        (
            "with the id vet and the version 0 is rejected with RECORD_ID_INVALID: step 2 comes first",
            P(record=("vet", 0)),
            got("rejected", err(P(record=("vet", 0)), "RECORD_ID_INVALID", ("vet", 0))),
        ),
        (
            "with the version 0 and no entry is rejected with VERSION_INVALID: step 3 comes before step 4",
            P([], record=(rid, 0)),
            got("rejected", err(P([], record=(rid, 0)), "VERSION_INVALID", (rid, 0))),
        ),
    ]:
        owner(
            f"step 1 to 3: a PROPOSAL {label}",
            ["shares.md 13.2", "protocol.md 8.2", "protocol.md 9.1"],
            owner_device(),
            [({"receive": msg}, want)],
        )
    # Step 4: the body is valid. A body that passes it fails step 5 here, for a record that is not shared.
    many = [(f"f{n}", fp1, b"\x00") for n in range(4096)]
    for label, msg, code in [
        ("whose proposal_id is no UUID", P(pid="proposal"), "INVALID_MESSAGE"),
        (
            "whose proposal_id is the nil UUID",
            P(pid="00000000-0000-0000-0000-000000000000"),
            "INVALID_MESSAGE",
        ),
        (
            "whose proposal_id is the max UUID",
            P(pid="ffffffff-ffff-ffff-ffff-ffffffffffff"),
            "INVALID_MESSAGE",
        ),
        ("with no entry", P([]), "INVALID_MESSAGE"),
        ("with 4,097 entries", P([*many, ("g", fp1, b"\x00")], record=(alone_id, 1)), "INVALID_MESSAGE"),
        ("with 4,096 entries passes step 4", P(many, record=(alone_id, 1)), "PROPOSALS_NOT_TAKEN"),
        ("with an empty field name", P([("", fp1, start11)]), "INVALID_MESSAGE"),
        (
            "with a field name of 513 bytes",
            P([("n" * 513, fp1, start11)], record=(alone_id, 1)),
            "INVALID_MESSAGE",
        ),
        (
            "with a field name of 512 bytes passes step 4",
            P([("n" * 512, fp1, start11)], record=(alone_id, 1)),
            "PROPOSALS_NOT_TAKEN",
        ),
        (
            "with a field name twice",
            P([("start", fp1, start11), ("start", fp1, start1030)]),
            "INVALID_MESSAGE",
        ),
        (
            "with two names that differ only in their Unicode normalization passes step 4",
            P([("\u00e9", fp1, b"\x00"), ("e\u0301", fp1, b"\x00")], record=(alone_id, 1)),
            "PROPOSALS_NOT_TAKEN",
        ),
    ]:
        env_rec = sy.read_all("Envelope", msg[10:])["record"]
        owner(
            f"step 4: a PROPOSAL {label}",
            ["shares.md 13.2", "shares.md 18.3"],
            owner_device(),
            [({"receive": msg}, got("rejected", err(msg, code, (env_rec["id"], env_rec["version"]))))],
        )
    # Step 5: one result for every reason.
    full = [
        {"receiver": "Old Brain Fix", "proposal_id": f"{n:08x}-9e0a-4000-8000-000000000000", "id": rid}
        for n in range(1, 17)
    ]
    more_full = [
        {
            "receiver": "Old Brain Fix",
            "proposal_id": f"{n:08x}-9e0a-4000-8000-0000000000ff",
            "id": f"{n:08x}-1111-4000-8000-000000000000",
        }
        for n in range(1, 257)
    ]
    for label, msg, device, rec in [
        ("for an id the owner does not hold", P(record=(unknown_id, 1)), owner_device(), (unknown_id, 1)),
        ("for a record that is deleted", P(record=(gone_id, 2)), owner_device(), (gone_id, 2)),
        (
            "for a record that is not shared with the proposer",
            P(record=(alone_id, 1)),
            owner_device(),
            (alone_id, 1),
        ),
        (
            "for a record shared with another receiver only",
            P(seed=second_seed, record=(rid, 3)),
            owner_device(),
            (rid, 3),
        ),
        (
            "for a type for which the manifest takes no proposals",
            P([("name", pet_fp, sy.encoded("Mia"))], record=(pet_id, 1)),
            owner_device(),
            (pet_id, 1),
        ),
        (
            "after the owner's manifest has stopped taking proposals for the type",
            P(),
            owner_device(proposals=[]),
            (rid, 3),
        ),
        ("of a sibling, which is no receiver", P(seed=sibling_seed), owner_device(), (rid, 3)),
        (
            "beyond the 16 open proposals of one proposer for one record",
            P(pid=pids[0]),
            owner_device(open=full),
            (rid, 3),
        ),
        (
            "beyond the 256 open proposals of one proposer in all",
            P(pid=pids[0], record=(other_id, 1)),
            owner_device(open=more_full),
            (other_id, 1),
        ),
    ]:
        to = H(sy.TABLET) if "sibling" in label else (second if "another receiver" in label else obf)
        owner(
            f"step 5: a PROPOSAL {label} is rejected with PROPOSALS_NOT_TAKEN",
            ["shares.md 12.2", "shares.md 15.4", "shares.md 18.3"],
            device,
            [({"receive": msg}, got("rejected", err(msg, "PROPOSALS_NOT_TAKEN", rec, to)))],
        )
    owner(
        "step 5: a repeat of an open proposal at the limit of 16 is a repeat, not a new proposal",
        ["shares.md 13.4", "shares.md 18.3"],
        owner_device(open=full),
        [({"receive": P(pid=full[0]["proposal_id"])}, got("repeat"))],
    )
    owner(
        "step 5: a second receiver proposes for a record shared with it as well, beside the first",
        ["shares.md 12.2", "shares.md 13.4"],
        owner_device(),
        [
            ({"receive": P(record=(other_id, 1))}, got("taken")),
            ({"receive": P(record=(other_id, 1), seed=second_seed)}, got("taken")),
            (
                {"query": True},
                q(
                    [
                        ("Old Brain Fix", se.PROPOSAL_ID, other_id, P(record=(other_id, 1))),
                        ("second app", se.PROPOSAL_ID, other_id, P(record=(other_id, 1), seed=second_seed)),
                    ],
                    [],
                ),
            ),
        ],
    )
    # Steps 6 to 9.
    nofp = bytes.fromhex("0102030405060708")
    m6 = P([("title", fp1, sy.encoded("Dentist")), ("start", nofp, start11)])
    m67 = P([("nofield", fp1, b"\x00"), ("start", nofp, start11)])
    bad_time = dict(se.START_11, instant_ms=se.START_11["instant_ms"] + 1)
    m9 = P(
        [
            ("title", fp1, sy.encoded("Dentist")),
            ("start", fp1, sy.field_value(se.APPOINTMENT_SCHEMA, "start", bad_time)),
        ]
    )
    for label, msg, want_err in [
        (
            "step 6: an entry whose schema the owner does not hold is rejected with SCHEMA_UNKNOWN and that "
            "fingerprint",
            m6,
            ("SCHEMA_UNKNOWN", nofp, None),
        ),
        (
            "step 6 comes before step 7: a name that is no field, then an unknown schema",
            m67,
            ("SCHEMA_UNKNOWN", nofp, None),
        ),
        (
            "step 7: an entry with the schema of another type is rejected with INVALID_MESSAGE",
            P([("name", pet_fp, sy.encoded("Mia"))]),
            ("INVALID_MESSAGE", None, None),
        ),
        (
            "step 7: an entry whose name is no field of its schema is rejected with INVALID_MESSAGE",
            P([("room", fp1, sy.encoded("2"))]),
            ("INVALID_MESSAGE", None, None),
        ),
        (
            "step 8: a value with a byte left over is rejected with UNDECODABLE",
            P([("start", fp1, start11 + b"\x00")]),
            ("UNDECODABLE", None, None),
        ),
        (
            "step 8: a value cut short is rejected with UNDECODABLE",
            P([("start", fp1, start11[:-1])]),
            ("UNDECODABLE", None, None),
        ),
        (
            "step 8: a string that is not well-formed UTF-8 is rejected with UNDECODABLE",
            P([("title", fp1, b"\x02\xff")]),
            ("UNDECODABLE", None, None),
        ),
        (
            "step 9: a time value that is not valid is rejected with VALUE_INVALID and the path of the first",
            m9,
            ("VALUE_INVALID", None, "start"),
        ),
    ]:
        owner(
            label,
            ["shares.md 13.3"],
            owner_device(),
            [
                (
                    {"receive": msg},
                    got("rejected", err(msg, want_err[0], (rid, 3), obf, want_err[1], want_err[2])),
                )
            ],
        )
    for label, msg in [
        ("an empty message", b""),
        ("a message with the fingerprint of no envelope format", m[:2] + bytes(8) + m[10:]),
        ("a message with a byte after its envelope", m + b"\x00"),
    ]:
        owner(
            f"step 1: {label} is rejected without a report",
            ["shares.md 13.3", "protocol.md 8.2"],
            owner_device(),
            [({"receive": msg}, got("rejected"))],
        )
    owner(
        "a repeat of a proposal whose answer the app's records hold gets the reply again",
        ["shares.md 13.4", "shares.md 15.1"],
        owner_device(
            answers=[
                {
                    "receiver": "Old Brain Fix",
                    "proposal_id": se.PROPOSAL_ID,
                    "answer": "DECLINED",
                    "id": rid,
                    "version": 3,
                }
            ]
        ),
        [({"receive": m}, got("repeat", reply(se.PROPOSAL_ID, "DECLINED")))],
    )
    owner(
        "a manifest that takes no more proposals for the type: a later PROPOSAL fails, an open one stays",
        ["shares.md 18.4", "shares.md 12.2"],
        owner_device(),
        [
            ({"receive": m}, got("taken")),
            ({"manifest": []}, {}),
            ({"receive": P(pid=pids[0])}, got("rejected", err(P(pid=pids[0]), "PROPOSALS_NOT_TAKEN"))),
            ({"query": True}, q([("Old Brain Fix", se.PROPOSAL_ID, rid, m)], [])),
        ],
    )
    owner(
        "step 7: a field that the owner's own schema lacks and the entry's later schema has passes",
        ["shares.md 13.3"],
        owner_device(schemas=[ap1, ap2, pet_text]),
        [({"receive": P([("room", fp2, sy.field_value(json.loads(ap2), "room", "2"))])}, got("taken"))],
    )

    # --- the proposer ---
    v3_bytes = {n: H(sy.field_value(se.APPOINTMENT_SCHEMA, n, v)) for n, v in se.V3_OWNER.items()}

    def proposer_device(**more: Any) -> dict[str, Any]:
        d = {
            "seed": H(OBF_SEED),
            "owner": [cat, H(NEW), H(sy.LAPTOP)],
            "manifests": {
                cat: {"revision": 2, "proposals": [se.AP_TYPE]},
                H(NEW): {"revision": 1, "proposals": []},
            },
            "records": [
                {
                    "id": rid,
                    "type": se.AP_TYPE,
                    "version": "3",
                    "last": "DATA",
                    "schema": ap1,
                    "values": v3_bytes,
                },
                {"id": other_id, "type": se.AP_TYPE, "version": "4", "last": "WITHDRAW", "schema": ap1},
                {
                    "id": gone_id,
                    "type": se.AP_TYPE,
                    "version": "2",
                    "last": "DATA",
                    "schema": ap1,
                    "deleted": True,
                },
            ],
            "proposal_ids": pids,
        }
        d.update(more)
        return d

    def proposal_said(
        pid: str, record: tuple[str, int] = (rid, 3), to: str = cat, values: dict[str, bytes] | None = None
    ) -> dict[str, Any]:
        vs = {"start": start11} if values is None else values
        return {
            "kind": "PROPOSAL",
            "to": to,
            "record": {"id": record[0], "version": record[1]},
            "proposal_id": pid,
            "fields": {n: {"schema": fp1.hex(), "value": v.hex()} for n, v in vs.items()},
        }

    def R(
        pid: str,
        answer: str,
        seed: bytes = CAT_SEED,
        to: bytes = OBF,
        record: tuple[str, int] | None = (rid, 3),
        body: bytes | None = None,
    ) -> bytes:
        b = se.reply_body(to, pid, answer) if body is None else body
        return cast(bytes, sy.message(seed, "PROPOSAL_REPLY", record, b))

    def E(
        pid_message: bytes,
        code: str,
        seed: bytes = CAT_SEED,
        field: str | None = None,
        fingerprint: bytes | None = None,
    ) -> bytes:
        return cast(
            bytes,
            se.error_message(
                seed, OBF, pid_message, se.Failed(code, fingerprint, field), {"id": rid, "version": 3}
            ),
        )

    first = P(pid=pids[0], seed=OBF_SEED)  # the PROPOSAL the proposer's first step sends

    def proposer(
        label: str, refs: list[str], device: dict[str, Any], steps: list[tuple[dict[str, Any], Any]]
    ) -> None:
        inputs = [json.loads(json.dumps(st, default=lambda b: H(b))) for st, _ in steps]
        played = se.proposer_session({"device": device, "steps": inputs})
        for n, ((_, want), answer) in enumerate(zip(steps, played, strict=True)):
            if "replies" in answer:
                answer = {**answer, "replies": [se.said(x) for x in answer["replies"]]}
            if answer.get("message") is not None:
                answer = {"message": se.said(answer["message"])}
            if "messages" in answer:
                answer = {"messages": [se.said(x) for x in answer["messages"]]}
            assert answer == want, (label, n, answer, want)
        c.add("proposer", label, refs, {"device": device, "steps": inputs}, {"steps": [w for _, w in steps]})

    propose = {"propose": {"id": rid, "to": cat, "values": {"start": start11}}}
    sent = {"message": proposal_said(pids[0])}

    def status(st: str, resend: bool) -> dict[str, Any]:
        return {"status": st, "resend": resend}

    assert first == se.Proposer(
        OBF_SEED, [CAT], {CAT: (2, {se.AP_TYPE})}, {rid: se.Got(se.AP_TYPE, 3, "DATA", ap1)}, [pids[0]]
    ).propose(rid, CAT, {"start": start11})
    proposer(
        "a proposal, its reply ACCEPTED, a repeat of the reply and a second reply DECLINED, which is ignored",
        ["shares.md 13.1", "shares.md 14.2", "shares.md 16.2"],
        proposer_device(),
        [
            (propose, sent),
            ({"query": pids[0]}, status("open", True)),
            ({"receive": R(pids[0], "ACCEPTED")}, got("taken")),
            ({"receive": R(pids[0], "ACCEPTED")}, got("ignored")),
            ({"receive": R(pids[0], "DECLINED")}, got("ignored")),
            ({"query": pids[0]}, status("ACCEPTED", False)),
            ({"receive": E(first, "PROPOSALS_NOT_TAKEN")}, got("ignored")),
        ],
    )
    for label, step in [
        ("a record withdrawn from the proposer", {"id": other_id, "to": cat, "values": {"start": start11}}),
        ("a record its own user deleted", {"id": gone_id, "to": cat, "values": {"start": start11}}),
        (
            "a key whose manifest takes no proposals for the type",
            {"id": rid, "to": H(NEW), "values": {"start": start11}},
        ),
        (
            "a key of which it holds no manifest",
            {"id": rid, "to": H(sy.LAPTOP), "values": {"start": start11}},
        ),
        (
            "a value whose change its user discarded, and no other",
            {"id": rid, "to": cat, "values": {"start": None}},
        ),
    ]:
        proposer(
            f"no PROPOSAL for {label}",
            ["shares.md 12.2", "shares.md 13.1"],
            proposer_device(),
            [({"propose": step}, {"message": None})],
        )
    proposer(
        "a PROPOSAL to a key with a manifest that takes proposals, after that manifest arrives",
        ["shares.md 12.2"],
        proposer_device(),
        [
            ({"propose": {"id": rid, "to": H(NEW), "values": {"start": start11}}}, {"message": None}),
            ({"manifest": {"key": H(NEW), "revision": 2, "proposals": [se.AP_TYPE]}}, {}),
            (
                {"propose": {"id": rid, "to": H(NEW), "values": {"start": start11}}},
                {"message": proposal_said(pids[0], to=H(NEW))},
            ),
        ],
    )
    for label, msg, want in [
        ("addressed to another key is ignored", R(pids[0], "ACCEPTED", to=CAT), got("ignored")),
        ("for a proposal the device did not send is ignored", R(pids[5], "ACCEPTED"), got("ignored")),
        (
            "of a key that is no current key of the owner is ignored",
            R(pids[0], "ACCEPTED", seed=sy.SEEDS["second app"]),
            got("ignored"),
        ),
        (
            "with another version in its record is rejected with INVALID_MESSAGE",
            R(pids[0], "ACCEPTED", record=(rid, 4)),
            got("rejected", err(R(pids[0], "ACCEPTED", record=(rid, 4)), "INVALID_MESSAGE", (rid, 4), cat)),
        ),
        (
            "with another id in its record is rejected with INVALID_MESSAGE",
            R(pids[0], "ACCEPTED", record=(other_id, 3)),
            got(
                "rejected",
                err(R(pids[0], "ACCEPTED", record=(other_id, 3)), "INVALID_MESSAGE", (other_id, 3), cat),
            ),
        ),
        (
            "without a record is rejected with INVALID_MESSAGE",
            R(pids[0], "ACCEPTED", record=None),
            got("rejected", err(R(pids[0], "ACCEPTED", record=None), "INVALID_MESSAGE", None, cat)),
        ),
        (
            "with an empty body is rejected with INVALID_MESSAGE",
            R(pids[0], "ACCEPTED", body=b""),
            got("rejected", err(R(pids[0], "ACCEPTED", body=b""), "INVALID_MESSAGE", (rid, 3), cat)),
        ),
    ]:
        proposer(
            f"a PROPOSAL_REPLY {label}",
            ["shares.md 14.1", "shares.md 14.2"],
            proposer_device(),
            [(propose, sent), ({"receive": msg}, want), ({"query": pids[0]}, status("open", True))],
        )
    proposer(
        "an ERROR PROPOSALS_NOT_TAKEN settles the proposal, and no PROPOSAL goes for the record "
        "until a manifest of the owner has a higher revision",
        ["shares.md 16.3"],
        proposer_device(),
        [
            (propose, sent),
            ({"receive": E(first, "PROPOSALS_NOT_TAKEN")}, got("taken")),
            ({"query": pids[0]}, status("PROPOSALS_NOT_TAKEN", False)),
            (propose, {"message": None}),
            ({"manifest": {"key": cat, "revision": 2, "proposals": [se.AP_TYPE]}}, {}),
            (propose, {"message": None}),
            ({"manifest": {"key": cat, "revision": 3, "proposals": [se.AP_TYPE]}}, {}),
            (propose, {"message": proposal_said(pids[1])}),
        ],
    )
    proposer(
        "after PROPOSALS_NOT_TAKEN a record message with a higher version lets a new PROPOSAL go",
        ["shares.md 16.3"],
        proposer_device(),
        [
            (propose, sent),
            ({"receive": E(first, "PROPOSALS_NOT_TAKEN")}, got("taken")),
            ({"record": {"id": rid, "kind": "DATA", "version": "4"}}, {}),
            (propose, {"message": proposal_said(pids[1], record=(rid, 4))}),
        ],
    )
    proposer(
        "after SCHEMA_UNKNOWN a new PROPOSAL waits for a record message with a higher version",
        ["shares.md 16.3"],
        proposer_device(),
        [
            (propose, sent),
            ({"receive": E(first, "SCHEMA_UNKNOWN", fingerprint=fp1)}, got("taken")),
            (propose, {"message": None}),
            ({"record": {"id": rid, "kind": "DATA", "version": "5"}}, {}),
            (propose, {"message": proposal_said(pids[1], record=(rid, 5))}),
        ],
    )
    proposer(
        "after VALUE_INVALID a new PROPOSAL goes only once its user has changed that value",
        ["shares.md 16.3"],
        proposer_device(),
        [
            (propose, sent),
            ({"receive": E(first, "VALUE_INVALID", field="start")}, got("taken")),
            (propose, {"message": None}),
            (
                {"propose": {"id": rid, "to": cat, "values": {"start": start1130}}},
                {"message": proposal_said(pids[1], values={"start": start1130})},
            ),
        ],
    )
    proposer(
        "after FORMAT_UNSUPPORTED the proposal is not settled and goes again",
        ["shares.md 16.3"],
        proposer_device(),
        [
            (propose, sent),
            ({"receive": E(first, "FORMAT_UNSUPPORTED", fingerprint=bytes(8))}, got("taken")),
            ({"query": pids[0]}, status("open", True)),
        ],
    )
    for code in ("INVALID_MESSAGE", "UNDECODABLE"):
        proposer(
            f"an ERROR {code} settles the proposal, which does not go again",
            ["shares.md 16.3"],
            proposer_device(),
            [
                (propose, sent),
                ({"receive": E(first, code)}, got("taken")),
                ({"query": pids[0]}, status(code, False)),
            ],
        )
    proposer(
        "an ERROR about no PROPOSAL of the device, and one of another key, are ignored",
        ["shares.md 16.3"],
        proposer_device(),
        [
            (propose, sent),
            ({"receive": E(R(pids[0], "ACCEPTED"), "PROPOSALS_NOT_TAKEN")}, got("ignored")),
            ({"receive": E(first, "PROPOSALS_NOT_TAKEN", seed=NEW_SEED)}, got("ignored")),
            ({"query": pids[0]}, status("open", True)),
        ],
    )
    other_error = se.error_message(CAT_SEED, CAT, first, se.Failed("PROPOSALS_NOT_TAKEN"), None)
    bad_reply = R(pids[0], "ACCEPTED")
    bad_reply = bad_reply[:-1] + bytes([bad_reply[-1] ^ 1])
    proposer(
        "an ERROR addressed to another key, and a reply whose signature does not verify, change nothing",
        ["shares.md 14.2", "shares.md 16.3", "protocol.md 9.1"],
        proposer_device(),
        [
            (propose, sent),
            ({"receive": other_error}, got("ignored")),
            ({"receive": bad_reply}, got("rejected", err(bad_reply, "SIGNATURE_INVALID", None, cat))),
            ({"query": pids[0]}, status("open", True)),
        ],
    )
    proposer(
        "a proposal stops going again once the owner withdraws the record, or once the key in to is removed",
        ["shares.md 16.2"],
        proposer_device(),
        [
            (propose, sent),
            (
                {"propose": {"id": rid, "to": cat, "values": {"title": sy.encoded("Dentist")}}},
                {"message": proposal_said(pids[1], values={"title": sy.encoded("Dentist")})},
            ),
            ({"remove": cat}, {"messages": []}),
            ({"query": pids[0]}, status("open", False)),
            ({"record": {"id": rid, "kind": "WITHDRAW", "version": "4"}}, {}),
            ({"query": pids[1]}, status("open", False)),
        ],
    )

    # --- the second round of rules (spec/shares.md, sections 12 to 18) ---
    takes_new = {
        cat: {"revision": 2, "proposals": [se.AP_TYPE]},
        H(NEW): {"revision": 1, "proposals": [se.AP_TYPE]},
    }
    proposer(
        "only the fields whose value differs from the DATA of the version go into a PROPOSAL",
        ["shares.md 13.1"],
        proposer_device(),
        [
            ({"propose": {"id": rid, "to": cat, "values": {"start": start1030}}}, {"message": None}),
            (
                {"propose": {"id": rid, "to": cat, "values": {"start": start11, "title": sy.encoded("Vet")}}},
                sent,
            ),
        ],
    )
    proposer(
        "a later ACCEPTED takes the place of a DECLINED, and a later "
        "DECLINED does not take that of an ACCEPTED",
        ["shares.md 14.2"],
        proposer_device(),
        [
            (propose, sent),
            ({"receive": R(pids[0], "DECLINED")}, got("taken")),
            ({"receive": R(pids[0], "ACCEPTED", seed=NEW_SEED)}, got("taken")),
            ({"query": pids[0]}, status("ACCEPTED", False)),
            ({"receive": R(pids[0], "DECLINED")}, got("ignored")),
            ({"query": pids[0]}, status("ACCEPTED", False)),
        ],
    )
    proposer(
        "the block after PROPOSALS_NOT_TAKEN holds for every key of the "
        "owner and ends with a reply for the record",
        ["shares.md 16.3"],
        proposer_device(manifests=takes_new),
        [
            (propose, sent),
            (
                {"propose": {"id": rid, "to": H(NEW), "values": {"title": sy.encoded("Dentist")}}},
                {"message": proposal_said(pids[1], to=H(NEW), values={"title": sy.encoded("Dentist")})},
            ),
            ({"receive": E(first, "PROPOSALS_NOT_TAKEN")}, got("taken")),
            ({"propose": {"id": rid, "to": H(NEW), "values": {"notes": sy.encoded("x")}}}, {"message": None}),
            ({"receive": R(pids[1], "DECLINED", seed=NEW_SEED, to=OBF)}, got("taken")),
            (
                {"propose": {"id": rid, "to": H(NEW), "values": {"notes": sy.encoded("x")}}},
                {"message": proposal_said(pids[2], to=H(NEW), values={"notes": sy.encoded("x")})},
            ),
        ],
    )
    two_records = proposer_device()
    two_records["records"].append(
        {
            "id": alone_id,
            "type": se.AP_TYPE,
            "version": "1",
            "last": "DATA",
            "schema": ap1,
            "values": v3_bytes,
        }
    )
    proposer(
        "the block after PROPOSALS_NOT_TAKEN ends with a reply of the owner about another record, and holds "
        "back no repeat",
        ["shares.md 16.3", "shares.md 16.2"],
        two_records,
        [
            (
                {"propose": {"id": alone_id, "to": cat, "values": {"start": start11}}},
                {"message": proposal_said(pids[0], record=(alone_id, 1))},
            ),
            (
                {"propose": {"id": rid, "to": cat, "values": {"start": start11}}},
                {"message": proposal_said(pids[1])},
            ),
            ({"receive": E(P(pid=pids[1], seed=OBF_SEED), "PROPOSALS_NOT_TAKEN")}, got("taken")),
            ({"connect": cat}, {"messages": [proposal_said(pids[0], record=(alone_id, 1))]}),
            (
                {"propose": {"id": rid, "to": cat, "values": {"title": sy.encoded("Dentist")}}},
                {"message": None},
            ),
            ({"receive": R(pids[0], "DECLINED", record=(alone_id, 1))}, got("taken")),
            (
                {"propose": {"id": rid, "to": cat, "values": {"title": sy.encoded("Dentist")}}},
                {"message": proposal_said(pids[2], values={"title": sy.encoded("Dentist")})},
            ),
        ],
    )
    proposer(
        "the block after PROPOSALS_NOT_TAKEN ends with a manifest of another "
        "key of the owner with a higher revision",
        ["shares.md 16.3"],
        proposer_device(manifests=takes_new),
        [
            (propose, sent),
            ({"receive": E(first, "PROPOSALS_NOT_TAKEN")}, got("taken")),
            ({"manifest": {"key": H(NEW), "revision": 2, "proposals": [se.AP_TYPE]}}, {}),
            (propose, {"message": proposal_said(pids[1])}),
        ],
    )
    proposer(
        "after SCHEMA_UNKNOWN the block also ends with a manifest of the owner with a higher revision",
        ["shares.md 16.3"],
        proposer_device(),
        [
            (propose, sent),
            ({"receive": E(first, "SCHEMA_UNKNOWN", fingerprint=fp1)}, got("taken")),
            (propose, {"message": None}),
            ({"manifest": {"key": cat, "revision": 3, "proposals": [se.AP_TYPE]}}, {}),
            (propose, {"message": proposal_said(pids[1])}),
        ],
    )
    proposer(
        "an open proposal goes again at the start of each live connection with the device of to",
        ["shares.md 16.2"],
        proposer_device(),
        [
            (propose, sent),
            ({"connect": cat}, {"messages": [proposal_said(pids[0])]}),
            ({"connect": H(NEW)}, {"messages": []}),
            ({"connect": cat}, {"messages": [proposal_said(pids[0])]}),
            ({"receive": R(pids[0], "DECLINED")}, got("taken")),
            ({"connect": cat}, {"messages": []}),
        ],
    )
    proposer(
        "an open proposal sent through the relay goes again after the holding time of 14 days, not before",
        ["shares.md 16.2"],
        proposer_device(),
        [
            ({"propose": {"id": rid, "to": cat, "values": {"start": start11}, "relay": True}}, sent),
            ({"days": 13}, {"messages": []}),
            ({"days": 1}, {"messages": [proposal_said(pids[0])]}),
            ({"days": 13}, {"messages": []}),
            ({"days": 1}, {"messages": [proposal_said(pids[0])]}),
        ],
    )
    proposer(
        "after the removal of the key in to the proposal goes to another key of the owner, with the same id",
        ["shares.md 16.2", "shares.md 13.1"],
        proposer_device(manifests=takes_new),
        [
            (propose, sent),
            ({"remove": cat}, {"messages": [proposal_said(pids[0], to=H(NEW))]}),
            ({"query": pids[0]}, status("open", True)),
            ({"connect": H(NEW)}, {"messages": [proposal_said(pids[0], to=H(NEW))]}),
        ],
    )
    # The owner.
    m_other = P(entries=[("start", fp1, start11), ("title", fp1, sy.encoded("Vet"))])
    low, high = sorted((m, m_other), key=lambda x: hashlib.sha256(x).digest())
    owner(
        "a repeat in other bytes with a higher SHA-256 takes the place of "
        "the open proposal, a lower one does not",
        ["shares.md 13.4"],
        owner_device(),
        [
            ({"receive": low}, got("taken")),
            ({"receive": high}, got("replaced")),
            ({"receive": low}, got("repeat")),
            ({"query": True}, q([("Old Brain Fix", se.PROPOSAL_ID, rid, high)], [])),
        ],
    )
    owner(
        "a repeat of an answered proposal gets its reply again, also after the record has been deleted",
        ["shares.md 13.3", "shares.md 13.4"],
        owner_device(),
        [
            ({"receive": m}, got("taken")),
            (
                {
                    "answer": {
                        "receiver": "Old Brain Fix",
                        "proposal_id": se.PROPOSAL_ID,
                        "answer": "DECLINED",
                    }
                },
                {"made": True, "replies": [reply(se.PROPOSAL_ID, "DECLINED")], "update": None},
            ),
            ({"change": {"id": rid, "action": "delete"}}, {}),
            ({"receive": P(record=(rid, 5))}, got("repeat", reply(se.PROPOSAL_ID, "DECLINED"))),
        ],
    )
    own_app = H(NEW)
    own_device = owner_device()
    own_device["receivers"].append({"name": "own app", "current": [own_app], "removed": [], "own_user": True})
    owner(
        "an app of the owner's own user is a receiver of every record of the type, shared with it or not",
        ["shares.md 12.2", "shares.md 2.3"],
        own_device,
        [
            ({"receive": P(record=(alone_id, 1), seed=NEW_SEED)}, got("taken")),
            ({"receive": P(record=(rid, 3), seed=NEW_SEED, pid=pids[0])}, got("taken")),
            (
                {
                    "receive": P(
                        [("name", pet_fp, sy.encoded("Mia"))], record=(pet_id, 1), seed=NEW_SEED, pid=pids[1]
                    )
                },
                got(
                    "rejected",
                    err(
                        P(
                            [("name", pet_fp, sy.encoded("Mia"))],
                            record=(pet_id, 1),
                            seed=NEW_SEED,
                            pid=pids[1],
                        ),
                        "PROPOSALS_NOT_TAKEN",
                        (pet_id, 1),
                        own_app,
                    ),
                ),
            ),
        ],
    )
    owner(
        "a stop of a receiver for all records drops its open proposals and fails its later ones",
        ["shares.md 18.4", "shares.md 13.3"],
        owner_device(),
        [
            ({"receive": m}, got("taken")),
            ({"receive": P(record=(other_id, 1), seed=second_seed)}, got("taken")),
            ({"stop": {"receiver": "Old Brain Fix"}}, {}),
            ({"receive": P(pid=pids[0])}, got("rejected", err(P(pid=pids[0]), "PROPOSALS_NOT_TAKEN"))),
            (
                {"query": True},
                q([("second app", se.PROPOSAL_ID, other_id, P(record=(other_id, 1), seed=second_seed))], []),
            ),
        ],
    )
    for label, stop in [
        ("for one record", {"receiver": "Old Brain Fix", "id": rid}),
        ("for one type", {"receiver": "Old Brain Fix", "type": se.AP_TYPE}),
    ]:
        owner(
            f"a stop of a receiver {label} that the app's records hold fails step 5",
            ["shares.md 18.4", "shares.md 13.3"],
            owner_device(stopped=[stop]),
            [
                ({"receive": m}, got("rejected", err(m, "PROPOSALS_NOT_TAKEN"))),
                (
                    {"receive": P(record=(other_id, 1), pid=pids[0])},
                    got("taken")
                    if "id" in stop
                    else got(
                        "rejected",
                        err(P(record=(other_id, 1), pid=pids[0]), "PROPOSALS_NOT_TAKEN", (other_id, 1)),
                    ),
                ),
            ],
        )
    big = sy.encoded("v" * 65533)
    assert len(big) == 65536
    for size, value, result in [(65536, big, "taken"), (65537, sy.encoded("v" * 65534), "rejected")]:
        msg = P([("title", fp1, value)])
        owner(
            f"step 5: a PROPOSAL with {size:,} value bytes",
            ["shares.md 18.3"],
            owner_device(),
            [
                (
                    {"receive": msg},
                    got("taken") if result == "taken" else got("rejected", err(msg, "PROPOSALS_NOT_TAKEN")),
                )
            ],
        )
    for held, result in [(1048576 - 33, "taken"), (1048576 - 32, "rejected")]:
        opens = [{"receiver": "Old Brain Fix", "proposal_id": pids[8], "id": unknown_id, "value_bytes": held}]
        owner(
            f"step 5: a PROPOSAL of 33 value bytes beside open proposals of "
            f"{held:,} value bytes of that proposer",
            ["shares.md 18.3"],
            owner_device(open=opens),
            [
                (
                    {"receive": m},
                    got("taken") if result == "taken" else got("rejected", err(m, "PROPOSALS_NOT_TAKEN")),
                )
            ],
        )
    for first_answer, later, stands in [
        ("DECLINED", "ACCEPTED", "ACCEPTED"),
        ("ACCEPTED", "DECLINED", "ACCEPTED"),
    ]:
        update = None if first_answer == "DECLINED" else {"version": "4", "value": v4}
        owner(
            f"of two answers that the app's records hold, ACCEPTED stands: "
            f"{first_answer} here, {later} of a sibling",
            ["shares.md 15.1", "shares.md 17.1"],
            owner_device(),
            [
                ({"receive": m}, got("taken")),
                (
                    {
                        "answer": {
                            "receiver": "Old Brain Fix",
                            "proposal_id": se.PROPOSAL_ID,
                            "answer": first_answer,
                        }
                    },
                    {"made": True, "replies": [reply(se.PROPOSAL_ID, first_answer)], "update": update},
                ),
                (
                    {
                        "answered": {
                            "receiver": "Old Brain Fix",
                            "proposal_id": se.PROPOSAL_ID,
                            "answer": later,
                            "id": rid,
                            "version": 3,
                        }
                    },
                    {},
                ),
                (
                    {"query": True},
                    q(
                        [],
                        [("Old Brain Fix", se.PROPOSAL_ID, stands)],
                        {rid: ("4", "there", v4)} if first_answer == "ACCEPTED" else None,
                    ),
                ),
            ],
        )
    room = sy.field_value(json.loads(ap2), "room", "2")
    owner(
        "ACCEPTED is barred for a value of a field that the reader schema lacks, and DECLINED is not",
        ["shares.md 15.1"],
        owner_device(schemas=[ap1, ap2, pet_text], readers={se.AP_TYPE: ap1}),
        [
            ({"receive": P([("room", fp2, room)])}, got("taken")),
            (
                {
                    "answer": {
                        "receiver": "Old Brain Fix",
                        "proposal_id": se.PROPOSAL_ID,
                        "answer": "ACCEPTED",
                    }
                },
                {"made": False, "replies": [], "update": None},
            ),
            (
                {
                    "answer": {
                        "receiver": "Old Brain Fix",
                        "proposal_id": se.PROPOSAL_ID,
                        "answer": "DECLINED",
                    }
                },
                {"made": True, "replies": [reply(se.PROPOSAL_ID, "DECLINED")], "update": None},
            ),
        ],
    )

    # A proposal of the relations that a share without links let through: the owner keeps the relations
    # that the proposer never got (spec/shares.md, section 19.3).
    to_pet = rules.relation(
        "f1b3d5a7-2c4e-4f60-8a1b-3c5d7e9f0a2b", rules.record_target(pet_id, "axt.example.v1.Pet", "Mimi")
    )
    _, vet, praxis = rules.RELATIONS["Appointment"]
    booster = dict(to_pet, note="Booster")
    linked = dict(v3, relations=se.json_form([to_pet, vet, praxis]))
    device = owner_device()
    device["records"][0] = {**device["records"][0], "value": linked}
    proposed = sy.field_value(se.APPOINTMENT_SCHEMA, "relations", [booster])
    owner(
        "a proposal of the relations that the share let through keeps those that it left out",
        ["shares.md 19.3", "shares.md 19.1", "shares.md 15.2"],
        device,
        [
            ({"receive": P([("relations", fp1, proposed)])}, got("taken")),
            (
                {
                    "answer": {
                        "receiver": "Old Brain Fix",
                        "proposal_id": se.PROPOSAL_ID,
                        "answer": "ACCEPTED",
                    }
                },
                {
                    "made": True,
                    "replies": [reply(se.PROPOSAL_ID, "ACCEPTED")],
                    "update": {
                        "version": "4",
                        "value": dict(v3, relations=se.json_form([booster, vet, praxis])),
                    },
                },
            ),
        ],
    )


# --- file (spec/transports.md, section 2) ---------------------------------------------------
# The scripts write one file; the files below are built by hand, so that each broken one breaks one rule. The
# expected results are written out from the table of spec/transports.md, section 2.2.

SYNC = bytes(range(16))
ENVELOPE_TEXT = (REPO / "types" / "axt" / "Envelope.avsc").read_text(encoding="utf-8")


def avro_map(entries: list[tuple[str, bytes]]) -> bytes:
    zz: Callable[[int], bytes] = keys.zigzag
    if not entries:
        return zz(0)
    out = zz(len(entries))
    for k, v in entries:
        out += zz(len(k.encode())) + k.encode() + zz(len(v)) + v
    return out + zz(0)


def container(
    messages: list[bytes],
    schemas: list[Any] | None = None,
    seed: bytes = CAT_SEED,
    codec: str = "null",
    schema_text: str | None = None,
    meta: dict[str, bytes | None] | None = None,
    blocks: list[tuple[int, bytes]] | None = None,
    sync: bytes = SYNC,
    entries_as_given: list[Any] | None = None,
) -> bytes:
    """An AXT file: the live messages without their single-object header, in one block (spec/envelope.md, section 4).

    schemas is the list of writer schemas for axt.schemas, or None for a file without it; meta, if given,
    changes the metadata entries after they are computed: a key mapped to None is left out."""  # noqa: E501 (wrapping would change the docstring)
    zz: Callable[[int], bytes] = keys.zigzag
    sender = keys.public_key(seed)
    entries: dict[str, bytes] = {}
    value: bytes | None = None
    if schemas is not None:
        # Each type as its description and the schema derived from it (spec/fields.md, section 10.2).
        given = pe.fe.file_entries(schemas) if entries_as_given is None else entries_as_given
        value = json.dumps(given, separators=(",", ":"), ensure_ascii=False).encode()
        entries["axt.schemas"] = value
    signed_bytes = keys.FILE_HEADER_PREFIX + sender + hashlib.sha256(value or b"").digest()
    entries["axt.sender"] = sender.hex().encode()
    entries["axt.signature"] = keys.sign(seed, signed_bytes).hex().encode()
    entries["avro.codec"] = codec.encode()
    entries["avro.schema"] = (
        schema_text if schema_text is not None else json.dumps(json.loads(ENVELOPE_TEXT))
    ).encode()
    for k, v in (meta or {}).items():
        if v is None:
            entries.pop(k, None)
        else:
            entries[k] = v
    out = b"Obj\x01" + avro_map(list(entries.items())) + sync
    for count, payload in (
        blocks if blocks is not None else [(len(messages), b"".join(m[10:] for m in messages))]
    ):
        if codec == "deflate":
            payload = stored_deflate(payload)
        out += zz(count) + zz(len(payload)) + payload + sync
    return out


def stored_deflate(data: bytes) -> bytes:
    """Raw DEFLATE of stored blocks (RFC 1951, section 3.2.4): the same bytes from every implementation, where
    compressed blocks depend on the zlib that writes them."""
    out, chunks = bytearray(), [data[i : i + 65535] for i in range(0, len(data), 65535)] or [b""]
    for i, chunk in enumerate(chunks):
        out += (
            bytes([1 if i == len(chunks) - 1 else 0])
            + len(chunk).to_bytes(2, "little")
            + (len(chunk) ^ 0xFFFF).to_bytes(2, "little")
            + chunk
        )
    return bytes(out)


assert container([MEMO_MSG], [env.MEMO_SCHEMA]) == env.axt_file, (
    "the builder does not give the file of spec/keys.md, section 7.3"
)


def file_category() -> Category:
    c = Category(
        "file",
        "Reading an AXT file: what it holds, in which order, and what rejects the whole file or only "
        "one record (spec/transports.md, section 2; spec/envelope.md, section 4; spec/keys.md, section 2.5).",
    )
    A_, TK, NT, PT = "Appointment", "Task", "Note", "Pet"

    def schema(n: str) -> Any:
        return json.loads(pe.compact(EXAMPLES / f"{n}.1.avsc"))

    def text(n: str) -> Any:
        return pe.compact(EXAMPLES / f"{n}.1.avsc")

    ap_text, ap = text(A_), rules.DATA[A_]

    def rid(n: int) -> str:
        return f"{n:08x}-1111-4111-8111-111111111111"

    def D(
        n: int,
        v: int = 1,
        seed: bytes = CAT_SEED,
        t: str = A_,
        value: Any = None,
        record_id: str | None = None,
    ) -> Any:
        return pe.obf_data(record_id or rid(n), v, text(t), rules.DATA[t] if value is None else value, seed)

    def DEL(n: int, v: int, seed: bytes = CAT_SEED) -> Any:
        return pe.make_message("DELETE", seed, (rid(n), v), [], check=False)[1]

    def MAN(seed: bytes = CAT_SEED, m: Any = me.CAT_A_LOG) -> Any:
        return pe.make_message(
            "MANIFEST", seed, None, pe.header("Manifest") + [(me.encode_body(m)[10:], "")], check=False
        )[1]

    obf_reader = {
        "manifest": B(me.encode_body(me.OLD_BRAIN_FIX)),
        "readers": {f"axt.example.v1.{A_}": pe.compact(EXAMPLES / f"{A_}.1.avsc")},
    }

    def rec(n: int, v: int, result: Any, record_id: str | None = None) -> dict[str, Any]:
        return {"id": record_id or rid(n), "version": v, "result": result}

    def read(
        sender: bytes,
        records: list[Any],
        manifest: Any = "none",
        chain: Iterable[tuple[str, bytes, bytes, str]] = (),
    ) -> dict[str, Any]:
        return accept(
            {
                "sender": H(sender),
                "chain": [
                    {"kind": kind, "signer": H(signer), "device": H(device), "result": result}
                    for kind, signer, device, result in chain
                ],
                "manifest": manifest,
                "records": records,
            }
        )

    refs = ["transports.md 2.2"]

    def add(label: str, data: bytes, expected: Any, more: Iterable[str] = (), reader: Any = None) -> None:
        c.add(
            "read_file", label, refs + list(more), {"file": B(data), "reader": reader or obf_reader}, expected
        )

    memo_id = env.RECORD_ID
    add(
        "the file of keys.md, section 7.3",
        env.axt_file,
        read(CAT, [rec(0, 1, "APPLIED", memo_id)]),
        ["keys.md 7.3", "envelope.md 10.3"],
    )
    add(
        "the same file with the codec deflate",
        container([MEMO_MSG], [env.MEMO_SCHEMA], codec="deflate"),
        read(CAT, [rec(0, 1, "APPLIED", memo_id)]),
        ["envelope.md 4.2"],
    )
    add(
        "a file without avro.codec, which is then null",
        container([MEMO_MSG], [env.MEMO_SCHEMA], meta={"avro.codec": None}),
        read(CAT, [rec(0, 1, "APPLIED", memo_id)]),
        ["envelope.md 4.1"],
    )
    add(
        "avro.schema in another text with the same canonical form",
        container([MEMO_MSG], [env.MEMO_SCHEMA], schema_text=json.dumps(json.loads(ENVELOPE_TEXT), indent=2)),
        read(CAT, [rec(0, 1, "APPLIED", memo_id)]),
        ["envelope.md 4.1"],
    )
    redoc = json.loads(ENVELOPE_TEXT)
    redoc["doc"] = "Another doc, which the canonical form drops."
    add(
        "avro.schema with another doc",
        container([MEMO_MSG], [env.MEMO_SCHEMA], schema_text=json.dumps(redoc)),
        read(CAT, [rec(0, 1, "APPLIED", memo_id)]),
        ["envelope.md 4.1"],
    )
    add(
        "a metadata key the reader does not know",
        container([MEMO_MSG], [env.MEMO_SCHEMA], meta={"org.example.note": b"hello"}),
        read(CAT, [rec(0, 1, "APPLIED", memo_id)]),
        ["envelope.md 4.1"],
    )

    # The chain of cat-a-log: an older phone added the old phone, which added the new one (spec/keys.md,
    # section 7.5). The reader knows the file's sender alone, and learns the earlier devices backwards.
    ADD_, REMOVE_ = keys.ADD, keys.REMOVE
    add1 = pe.device_add(OLDER_SEED, CAT_SEED)
    older = OLDER
    full = container(
        [add1, ADD_MSG, MAN(NEW_SEED), D(1, seed=NEW_SEED), DEL(2, 3, NEW_SEED)],
        [schema(A_)],
        seed=NEW_SEED,
        codec="deflate",
    )
    add(
        "a chain, a MANIFEST and record messages, in that order",
        full,
        read(
            NEW,
            [rec(1, 1, "APPLIED"), rec(2, 3, "APPLIED")],
            "used",
            [(ADD_, older, CAT, keys.APPLIED), (ADD_, CAT, NEW, keys.APPLIED)],
        ),
        ["transports.md 2.1", "keys.md 5.4", "keys.md 5.5", "manifest.md 7"],
    )
    unknown = keys.public_key(pe.UNKNOWN_SEED)
    remove_new = pe.device_remove(CAT_SEED, NEW)
    add(
        "a chain with messages that the reader cannot place, ignores or rejects by the table: they are not "
        "applied, and the records are",
        container(
            [
                pe.device_add(pe.UNKNOWN_SEED, OBF_SEED),
                pe.device_remove(CAT_SEED, older),
                ADD_MSG,
                ADD_MSG,
                remove_new,
                pe.device_add(NEW_SEED, OBF_SEED),
                D(20),
            ],
            [schema(A_)],
        ),
        read(
            CAT,
            [rec(20, 1, "APPLIED")],
            "none",
            [
                (ADD_, unknown, OBF, keys.NOT_PLACED),
                (REMOVE_, CAT, older, keys.IGNORED),
                (ADD_, CAT, NEW, keys.APPLIED),
                (ADD_, CAT, NEW, keys.IGNORED),
                (REMOVE_, CAT, NEW, keys.APPLIED),
                (ADD_, NEW, OBF, keys.REJECTED),
            ],
        ),
        ["keys.md 5.5"],
    )
    add(
        "a chain in which a DEVICE_REMOVE stands before the DEVICE_ADD of its device: it is kept and applied",
        container([remove_new, ADD_MSG, D(26)], [schema(A_)]),
        read(
            CAT,
            [rec(26, 1, "APPLIED")],
            "none",
            [(REMOVE_, CAT, NEW, keys.APPLIED), (ADD_, CAT, NEW, keys.APPLIED)],
        ),
        ["keys.md 5.5"],
    )
    add(
        "a chain after which the key in axt.sender is a removed key: no record of the file is applied",
        container([ADD_MSG, pe.device_remove(NEW_SEED, CAT), D(21), DEL(22, 2)], [schema(A_)]),
        read(
            CAT,
            [rec(21, 1, "SENDER_REMOVED"), rec(22, 2, "SENDER_REMOVED")],
            "none",
            [(ADD_, CAT, NEW, keys.APPLIED), (REMOVE_, NEW, CAT, keys.APPLIED)],
        ),
        ["keys.md 3.3", "keys.md 5.5"],
    )
    add(
        "a file that only carries its writer's MANIFEST",
        container([MAN()], None),
        read(CAT, [], "used"),
        ["transports.md 2.1"],
    )
    add(
        "a file without axt.schemas, with a DELETE only",
        container([DEL(3, 4)], None),
        read(CAT, [rec(3, 4, "APPLIED")]),
        ["keys.md 2.5", "envelope.md 4.1"],
    )
    bad_manifest = MAN(m=dict(me.CAT_A_LOG, revision=0))
    add(
        "an invalid MANIFEST is not used, and the records are applied",
        container([bad_manifest, D(4)], [schema(A_)]),
        read(CAT, [rec(4, 1, "APPLIED")], "invalid"),
        ["manifest.md 4"],
    )
    short = pe.make_message(
        "DATA", CAT_SEED, (rid(9), 1), [(single_object(ap_text, ap)[:-3], "")], check=False
    )[1]
    add(
        "record messages that fail a step are not applied, the others are",
        container(
            [
                D(5, record_id="00000000-0000-0000-0000-000000000000"),
                D(6, v=0),
                D(7),
                D(7, v=2, t=TK),
                short,
                D(8),
            ],
            [schema(A_), schema(TK)],
        ),
        read(
            CAT,
            [
                rec(0, 1, "RECORD_ID_INVALID", "00000000-0000-0000-0000-000000000000"),
                rec(6, 0, "VERSION_INVALID"),
                rec(7, 1, "APPLIED"),
                rec(7, 2, "TYPE_CHANGED"),
                rec(9, 1, "UNDECODABLE"),
                rec(8, 1, "APPLIED"),
            ],
        ),
        ["protocol.md 6.2", "protocol.md 15.2"],
    )
    visit = json.loads(tm.HOST_TEXT)
    late = dict(
        tm.HOST_VALUE, end=dict(tm.HOST_VALUE["end"], instant_ms=tm.HOST_VALUE["end"]["instant_ms"] + 1)
    )
    add(
        "a record with a time value that is not valid is not applied, the others are",
        container(
            [
                pe.obf_data(rid(13), 1, tm.HOST_TEXT, tm.HOST_VALUE),
                pe.obf_data(rid(14), 1, tm.HOST_TEXT, late),
            ],
            [visit],
        ),
        read(CAT, [rec(13, 1, "APPLIED"), rec(14, 1, "VALUE_INVALID")]),
        ["time.md 8", "protocol.md 6.2"],
    )
    cat_reader = {"manifest": B(me.encode_body(me.CAT_A_LOG)), "readers": {}}
    add(
        "a record whose type does not fit the reader's manifest is not applied",
        container([D(10, t=NT), D(11, t=PT)], [schema(NT), schema(PT)]),
        read(CAT, [rec(10, 1, "DOES_NOT_FIT"), rec(11, 1, "APPLIED")]),
        ["manifest.md 7"],
        reader=cat_reader,
    )
    add(
        "several messages of one record are applied by the version rule",
        container([D(12, v=2), D(12, v=1), D(12, v=2)], [schema(A_)]),
        read(CAT, [rec(12, 2, "APPLIED"), rec(12, 1, "STALE"), rec(12, 2, "DUPLICATE")]),
        ["transports.md 2.3", "records.md 5.2"],
    )
    narrow = schema(A_)
    narrow["fields"].append(
        {"name": "room", "type": "string", "doc": "A field without a default that the writer lacks."}
    )
    add(
        "a record whose schema does not resolve against the reader's is not applied",
        container([D(13)], [schema(A_)]),
        read(CAT, [rec(13, 1, "DOES_NOT_RESOLVE")]),
        ["envelope.md 6"],
        reader={
            "manifest": obf_reader["manifest"],
            "readers": {f"axt.example.v1.{A_}": json.dumps(narrow, separators=(",", ":"))},
        },
    )

    def good(**kw: Any) -> bytes:
        return container([MEMO_MSG], [env.MEMO_SCHEMA], **kw)

    gf = good()
    memo2 = dict(env.MEMO_SCHEMA, doc="The same Memo with another doc, and so the same fingerprint.")
    reordered = json.loads(ENVELOPE_TEXT)
    reordered["fields"] = reordered["fields"][1:2] + reordered["fields"][:1] + reordered["fields"][2:]
    header_sig = keys.sign(CAT_SEED, keys.FILE_HEADER_PREFIX + CAT + hashlib.sha256(b"[]").digest())
    fmt2 = signed(CAT_SEED, "DATA", (env.RECORD_ID, 1), MEMO_MSG[0x54:-64], fmt=2)
    no_record = signed(CAT_SEED, "DATA", None, MEMO_MSG[0x54:-64])
    man_fp = signed(CAT_SEED, "MANIFEST", None, b"\xc3\x01" + ENVELOPE_FP + me.encode_body(me.CAT_A_LOG)[10:])
    bad_sig = MEMO_MSG[:-1] + bytes([MEMO_MSG[-1] ^ 1])
    ack = pe.make_message(
        "ACK",
        CAT_SEED,
        None,
        pe.make_body(
            "Ack",
            {
                "to": OBF,
                "records": [
                    {
                        "id": env.RECORD_ID,
                        "version": 1,
                        "outcome": "APPLIED",
                        "receiver_version": 1,
                        "kept_fields": [],
                    }
                ],
            },
            check=False,
        )[0],
        check=False,
    )[1]
    # A CHANGE and a RESYNC of the file's sender, for a device of its set: a file holds neither.
    whole_change = {
        "to": NEW,
        "origin": None,
        "type": sy.APPOINTMENT_TYPE,
        "state": 3,
        "whole": True,
        "removal": None,
        "keep": None,
        "fields": [],
    }
    sync_change = sy.message(CAT_SEED, "CHANGE", (RECORD_IDS["r1"], 3), sy.body_of("Change", whole_change))
    sync_resync = sy.message(CAT_SEED, "RESYNC", (sy.REQUEST_ID, 1), sy.body_of("Resync", {"to": NEW}))
    # A FORWARD of the file's sender, with a DATA of Old Brain Fix inside: a file holds none.
    forwarded = {"to": NEW, "message": D(30, seed=OBF_SEED), "schema": text(A_)}
    sync_forward = sy.message(CAT_SEED, "FORWARD", (sy.FORWARD_ID, 1), sy.body_of("Forward", forwarded))
    offer = pe.make_message(
        "OFFER",
        CAT_SEED,
        None,
        pe.make_body(
            "Offer",
            {
                "to": OBF,
                "offer_id": pe.OFFER_ID,
                "types": [{"schema": pe.compact(EXAMPLES / "Pet.1.avsc"), "count": 1}],
            },
            check=False,
        )[0],
        check=False,
    )[1]
    bad_proof = pe.device_add(OLDER_SEED, CAT_SEED, proof=keys.sign(OBF_SEED, keys.proof_bytes(older, CAT)))
    small_device = pe.device_add(CAT_SEED, b"", proof=SMALL_SIGNATURE, device=SMALL_KEY)
    datum = MEMO_MSG[10:]
    rejects = [
        (
            "bytes that are not an Avro object container file",
            b"AXT file, not Avro" + bytes(32),
            ["envelope.md 4"],
        ),
        ("the magic of another Avro version", b"Obj\x02" + gf[4:], ["envelope.md 4"]),
        ("the codec snappy", good(codec="snappy"), ["envelope.md 4.2"]),
        ("avro.schema of axt.Manifest", good(schema_text=pe.texts["Manifest"]), ["envelope.md 4.1"]),
        (
            "avro.schema with two fields swapped, whose canonical form is another",
            good(schema_text=json.dumps(reordered)),
            ["envelope.md 4.1", "keys.md 2.5"],
        ),
        ("no axt.signature", good(meta={"axt.signature": None}), ["keys.md 2.5"]),
        ("no axt.sender", good(meta={"axt.sender": None}), ["keys.md 2.5"]),
        (
            "axt.signature in upper-case hexadecimal",
            good(meta={"axt.signature": env.HEADER_SIGNATURE.hex().upper().encode()}),
            ["keys.md 2.5"],
        ),
        (
            "axt.sender in upper-case hexadecimal",
            good(meta={"axt.sender": CAT.hex().upper().encode()}),
            ["keys.md 2.5"],
        ),
        (
            "axt.signature of 126 digits",
            good(meta={"axt.signature": env.HEADER_SIGNATURE.hex()[:126].encode()}),
            ["keys.md 2.5"],
        ),
        (
            "a header signature over other schemas",
            good(meta={"axt.signature": header_sig.hex().encode()}),
            ["keys.md 2.5"],
        ),
        (
            "two schemas with one fingerprint in axt.schemas",
            container([MEMO_MSG], [env.MEMO_SCHEMA, memo2]),
            ["envelope.md 4.1", "envelope.md 5"],
        ),
        (
            "a DATA whose fingerprint is not in axt.schemas",
            container([MEMO_MSG], [schema(NT)]),
            ["envelope.md 4.3"],
        ),
        ("a DATA in a file without axt.schemas", container([MEMO_MSG], None), ["envelope.md 4.3"]),
        (
            "an entry of axt.schemas whose schema is not the one derived from its description",
            container(
                [MEMO_MSG],
                [env.MEMO_SCHEMA],
                entries_as_given=[
                    {"description": e["description"], "schema": schema(NT)}
                    for e in pe.fe.file_entries([env.MEMO_SCHEMA])
                ],
            ),
            ["envelope.md 4.1", "fields.md 10.2"],
        ),
        (
            "an entry of axt.schemas whose description is not valid",
            container(
                [MEMO_MSG],
                [env.MEMO_SCHEMA],
                entries_as_given=[
                    {"description": dict(e["description"], doc=""), "schema": e["schema"]}
                    for e in pe.fe.file_entries([env.MEMO_SCHEMA])
                ],
            ),
            ["envelope.md 4.1", "fields.md 10.2"],
        ),
        ("a datum whose format is 2", container([fmt2], [env.MEMO_SCHEMA]), ["keys.md 2.2"]),
        ("a DATA without record", container([no_record], [env.MEMO_SCHEMA]), ["protocol.md 2"]),
        ("a MANIFEST whose body has another fingerprint", container([man_fp], None), ["protocol.md 2"]),
        (
            "a block with a byte left over after its datum",
            container([], [env.MEMO_SCHEMA], blocks=[(1, datum + b"\x00")]),
            ["envelope.md 4"],
        ),
        (
            "a block that claims two datums and holds one",
            container([], [env.MEMO_SCHEMA], blocks=[(2, datum)]),
            ["envelope.md 4"],
        ),
        ("a wrong sync marker after the block", good()[:-1] + b"\x00", ["envelope.md 4"]),
        (
            "a message whose signature does not verify",
            container([bad_sig], [env.MEMO_SCHEMA]),
            ["transports.md 2.2"],
        ),
        ("an ACK", container([ack], None), ["transports.md 2.1"]),
        ("an OFFER", container([offer], [schema(PT)]), ["transports.md 2.1"]),
        (
            "a CHANGE",
            container([sync_change, D(28)], [schema(A_)]),
            ["transports.md 2.1", "transports.md 2.2", "sync.md 13.3"],
        ),
        (
            "a RESYNC",
            container([sync_resync, D(29)], [schema(A_)]),
            ["transports.md 2.1", "transports.md 2.2", "sync.md 13.3"],
        ),
        (
            "a FORWARD",
            container([sync_forward, D(31)], [schema(A_)]),
            ["transports.md 2.1", "transports.md 2.2", "sync.md 13.3", "sync.md 24.2"],
        ),
        ("a message of another sender", container([D(14, seed=OBF_SEED)], [schema(A_)]), ["keys.md 2.5"]),
        (
            "a DEVICE_ADD after a record message",
            container([D(15), add1], [schema(A_)]),
            ["keys.md 5.4", "transports.md 2.1"],
        ),
        (
            "a DEVICE_REMOVE after the MANIFEST",
            container([MAN(), pe.device_remove(CAT_SEED, NEW), D(16)], [schema(A_)]),
            ["keys.md 5.4", "transports.md 2.1"],
        ),
        (
            "a DEVICE_ADD whose proof does not verify",
            container([bad_proof, D(17)], [schema(A_)]),
            ["keys.md 5.5"],
        ),
        (
            "a DEVICE_ADD whose device key is of small order",
            container([small_device, D(23)], [schema(A_)]),
            ["keys.md 2.3", "keys.md 5.5"],
        ),
        (
            "a DEVICE_REMOVE of its signer's own key",
            container([pe.device_remove(CAT_SEED, CAT), D(27)], [schema(A_)]),
            ["keys.md 5.3", "keys.md 5.5"],
        ),
        (
            "a DEVICE_REMOVE whose signature does not verify",
            container([flip_signature(pe.device_remove(CAT_SEED, NEW)), D(24)], [schema(A_)]),
            ["keys.md 5.5"],
        ),
        (
            "a DEVICE_JOIN",
            container([JOIN_MSG, D(25, seed=NEW_SEED)], [schema(A_)], seed=NEW_SEED),
            ["transports.md 2.1"],
        ),
        ("a second MANIFEST", container([MAN(), MAN(), D(18)], [schema(A_)]), ["transports.md 2.1"]),
        ("a MANIFEST after a record message", container([D(19), MAN()], [schema(A_)]), ["transports.md 2.1"]),
        (
            "a block above 64 MiB after decompression",
            container([], [env.MEMO_SCHEMA], codec="deflate", blocks=[(1, bytes(64 * 2**20 + 1))]),
            ["envelope.md 8"],
        ),
        ("metadata above 8 MiB", good(meta={"org.example.big": bytes(8 * 2**20)}), ["envelope.md 8"]),
    ]
    for label, data, more in rejects:
        add(f"reject {label}", data, reject("FILE_REJECTED"), more)

    # A WITHDRAW in a file (spec/shares.md, section 8.2): the reader names the keys of its own set.
    def W(n: int, v: int, to: bytes = OBF) -> bytes:
        return cast(bytes, se.withdraw_message(CAT_SEED, to, rid(n), v)[1])

    def keyed(current: list[bytes], removed: list[bytes] = []) -> dict[str, Any]:  # noqa: B006 (never changed)
        return {
            **obf_reader,
            "keys": {"current": [H(k) for k in current], "removed": [H(k) for k in removed]},
        }

    shares_refs = ["shares.md 8.2", "transports.md 2.1"]
    add(
        "a file for its receiver with WITHDRAW messages: applied by the version rule",
        container([D(30, 3), W(30, 4), D(30, 3), W(31, 2), D(31, 1), W(31, 2)], [schema(A_)]),
        read(
            CAT,
            [
                rec(30, 3, "APPLIED"),
                rec(30, 4, "WITHDRAWN"),
                rec(30, 3, "STALE"),
                rec(31, 2, "WITHDRAWN"),
                rec(31, 1, "STALE"),
                rec(31, 2, "DUPLICATE"),
            ],
        ),
        shares_refs + ["shares.md 4.2"],
        keyed([OBF]),
    )
    add(
        "a WITHDRAW whose to is a removed key of the reader's own set is applied",
        container([W(32, 2)], [schema(A_)]),
        read(CAT, [rec(32, 2, "WITHDRAWN")]),
        shares_refs + ["shares.md 7.1"],
        keyed([pe.OTHER], [OBF]),
    )
    add(
        "a WITHDRAW for another app is not applied, and the file stands",
        container([D(33), W(33, 2), W(34, 2, unknown)], [schema(A_)]),
        read(CAT, [rec(33, 1, "APPLIED"), rec(33, 2, "IGNORED"), rec(34, 2, "IGNORED")]),
        shares_refs + ["shares.md 9"],
        keyed([pe.OTHER]),
    )
    add(
        "a WITHDRAW is not held back by the reader's manifest, and is checked like every record message",
        container(
            [
                D(35, t=NT),
                W(35, 2),
                W(36, 0),
                pe.make_message("WITHDRAW", CAT_SEED, ("vet", 1), [(W(36, 1)[0x54:-64], "")], check=False)[1],
            ],
            [schema(A_), schema(NT)],
        ),
        read(
            CAT,
            [
                rec(35, 1, "DOES_NOT_FIT"),
                rec(35, 2, "WITHDRAWN"),
                rec(36, 0, "VERSION_INVALID"),
                rec(0, 1, "RECORD_ID_INVALID", "vet"),
            ],
        ),
        shares_refs + ["manifest.md 7"],
        {**cat_reader, "keys": {"current": [H(OBF)], "removed": []}},
    )
    body = W(37, 1)[0x54:-64]

    def broken(record: tuple[str, int] | None, b: bytes) -> bytes:
        return cast(bytes, pe.make_message("WITHDRAW", CAT_SEED, record, [(b, "")], check=False)[1])

    for label, m in [
        ("without a record", broken(None, body)),
        ("with an empty body", broken((rid(37), 1), b"")),
        (
            "with a body of the fingerprint of axt.Resync",
            broken((rid(37), 1), body[:2] + sy.SPEC_FP["Resync"] + body[10:]),
        ),
        ("with a byte left over in its body", broken((rid(37), 1), body + b"\x00")),
    ]:
        add(
            f"reject a file with a WITHDRAW {label}",
            container([D(38), m], [schema(A_)]),
            reject("FILE_REJECTED"),
            shares_refs,
            keyed([OBF]),
        )
    # No file holds a PROPOSAL or a PROPOSAL_REPLY (spec/shares.md, section 18.2).
    entry = [("start", se.APPOINTMENT_FP, se.START_VALUE)]
    for kind, b in [
        ("PROPOSAL", se.proposal_body(OBF, se.PROPOSAL_ID, entry)),
        ("PROPOSAL_REPLY", se.reply_body(OBF, se.PROPOSAL_ID, "ACCEPTED")),
    ]:
        m = sy.message(CAT_SEED, kind, (rid(39), 1), b)
        add(
            f"reject a file with a {kind}",
            container([D(40), m], [schema(A_)]),
            reject("FILE_REJECTED"),
            ["shares.md 18.2", "transports.md 2.1", "transports.md 2.2"],
            keyed([OBF]),
        )
    # The files the readers of the Python libraries take are taken here as well.
    for data in (env.axt_file, full):
        assert len(list(fastavro.reader(io.BytesIO(data)))) >= 1
    return c


# --- sync (spec/sync.md) ------------------------------------------------------------------


def sync_category() -> Category:
    c = Category(
        "sync",
        "The devices of one owner: the next stamp, what a change stamps, the merge of two states of a "
        "record per field and for the removal, when a record is deleted, the record message of a "
        "state, beginning to stamp, what a device does after STALE, what a device shows of a record "
        "received from another app, and one device with its siblings: the CHANGE, RESYNC and FORWARD "
        "messages it processes and sends, for the records of the set and for what the set got from "
        "other apps (spec/sync.md).",
    )
    S, J = sy.stamp_json, sy.state_json
    # The schemas of the field states: version 1 of the example type, and a version 2 made for the cases.
    assert sy.SCHEMA_1 == pe.fp8(pe.canonical_fp(sy.APPOINTMENT_1)) == pe.fp8(TYPE_FPS["Appointment"])
    assert sy.SCHEMA_2 == pe.fp8(pe.canonical_fp(sy.APPOINTMENT_2)) != sy.SCHEMA_1
    versions = {H(fp): version for fp, version in sy.SCHEMA_VERSIONS.items()}

    def limit(label: str, refs: list[str]) -> list[str]:
        at_limit = "limit" in label or "largest long" in label
        return [*refs, "sync.md 2.3"] if at_limit and "sync.md 2.3" not in refs else refs

    # The next stamp: the 12 cases of spec/sync.md, section 6.1, and the limits.
    assert len(sy.STAMPS) == 12
    stamps = [
        (label.split(". ", 1)[1], n, h, r, want, ["sync.md 2.2", "sync.md 6.1"])
        for label, n, h, r, _, want in sy.STAMPS
    ]
    stamps += [(label, n, h, r, want, ["sync.md 2.2"]) for label, n, h, r, want in sy.MORE_STAMPS]
    for label, now_ms, highest, r, want, refs in stamps:
        assert sy.next_stamp(now_ms, highest, r) == want, label
        c.add(
            "next_stamp",
            label,
            limit(label, refs) if want is not None else limit("limit", refs),
            {"now_ms": S(now_ms), "highest": S(highest), "r": r},
            accept({"stamp": S(want)}),
        )

    # A change: those of the examples, and the cases of the script.
    def change_vector(
        label: str,
        refs: list[str],
        before: Any,
        device: bytes,
        action: str,
        values: Any,
        clock: Any,
        done: Any,
        schema: bytes = sy.SCHEMA_1,
        later_clock: int | None = None,
        to_pass: int | None = None,
    ) -> None:
        now_ms, highest, rr = clock
        c.add(
            "change",
            label,
            refs,
            {
                "state": J(before),
                "device": H(device),
                "action": action,
                "values": {name: H(value) for name, value in values.items()},
                "schema": H(schema),
                "now_ms": S(now_ms),
                "now_ms_state": S(now_ms if later_clock is None else later_clock),
                "highest": S(highest),
                "r": list(rr),
                "to_pass": S(to_pass),
            },
            accept(
                {
                    "made": done.made,
                    "state": J(done.state),
                    "highest": S(done.highest),
                    "to_pass": S(done.to_pass),
                }
            ),
        )

    for label, before, device, action, values, clock, done in sy.EXAMPLE_CHANGES:
        refs = ["sync.md 3.5", f"sync.md {label[:3]}"]
        change_vector(f"section {label}", refs, before, device, action, values, clock, done)
    for label, before, device, action, plain_values, clock, made, after, top in sy.CHANGES:
        values = {name: sy.encoded(value) for name, value in plain_values.items()}
        done = sy.change(before, device, action, values, *clock)
        assert (done.made, done.state, done.highest) == (made, after, top), label
        change_vector(label, limit(label, ["sync.md 3.5"]), before, device, action, values, clock, done)
    for label, before, device, action, plain_values, schema, clock, later, to_pass, want in sy.MORE_CHANGES:
        values = {name: sy.encoded(value) for name, value in plain_values.items()}
        done = sy.change(before, device, action, values, *clock, schema, later, to_pass)
        assert done == want, label
        refs = limit(label, ["sync.md 3.5", "sync.md 3.1", "sync.md 5.3"])
        change_vector(label, refs, before, device, action, values, clock, done, schema, later, to_pass)

    # A merge: those of the examples, and the cases of the script.
    def merge_vector(
        label: str,
        refs: list[str],
        own: Any,
        other: Any,
        clock: Any,
        done: Any,
        sibling_stamp: int | None = None,
        to_pass: int | None = None,
        layer: bool = False,
    ) -> None:
        now_ms, highest, r = clock
        c.add(
            "merge",
            label,
            refs,
            {
                "own": J(own, layer),
                "other": J(other, layer),
                "now_ms": S(now_ms),
                "highest": S(highest),
                "r": r,
                "sibling_stamp": S(sibling_stamp),
                "to_pass": S(to_pass),
            },
            accept(
                {
                    "state": J(done.state, layer),
                    "stands": done.merged.stands,
                    "removal_taken": done.merged.removal_taken,
                    "deleted": done.deleted,
                    "highest": S(done.highest),
                    "sibling_stamp": S(done.sibling_stamp),
                    "to_pass": S(done.to_pass),
                }
            ),
        )

    merge_refs = ["sync.md 4.1", "sync.md 4.2", "sync.md 4.3", "sync.md 4.4"]
    for label, own, other, clock, done in sy.EXAMPLE_MERGES:
        merge_vector(f"section {label}", [*merge_refs, f"sync.md {label[:3]}"], own, other, clock, done)
    for label, own, other, clock, stands, removal_taken, gone, stamp, top in sy.MERGES:
        done = sy.device_merge(own, other, *clock)
        got = (done.merged.stands, done.merged.removal_taken, done.deleted, done.state.state_stamp)
        assert (*got, done.highest) == (stands, removal_taken, gone, stamp, top), label
        refs = [*merge_refs, "sync.md 3.4"] if "never stamped" in label else merge_refs
        merge_vector(label, limit(label, refs), own, other, clock, done)
    for label, own, other, clock, stands, removal_taken, gone, stamp, top in sy.LAYER_MERGES:
        done = sy.device_merge(own, other, *clock)
        got = (done.merged.stands, done.merged.removal_taken, done.deleted, done.state.state_stamp)
        assert (*got, done.highest) == (stands, removal_taken, gone, stamp, top), label
        merge_vector(label, ["sync.md 21.1", "sync.md 4.1", "sync.md 4.3"], own, other, clock, done)
    for label, own_keep, other_keep, _ in sy.KEEP_MERGES:
        own, other = sy.keep_states(own_keep, other_keep)
        done = sy.device_merge(own, other, *sy.KEEP_CLOCK)
        merge_vector(label, ["sync.md 21.1", "sync.md 4.4"], own, other, sy.KEEP_CLOCK, done, layer=True)
    for label, own, other, clock, seen, to_pass, seen_after, pass_after, stamp in sy.KEPT:
        done = sy.device_merge(own, other, *clock, seen, to_pass)
        assert (done.sibling_stamp, done.to_pass, done.state.state_stamp) == (seen_after, pass_after, stamp)
        merge_vector(
            label, ["sync.md 3", "sync.md 4.4", "sync.md 5.3"], own, other, clock, done, seen, to_pass
        )

    # Whether a record is deleted in a state, and the record message of the state.
    sending = [(label, state, sorted(state.fields), 1, gone, m) for label, state, _, gone, m in sy.DELETED]
    for label, state, writer_fields, writer_version, gone, message in [*sending, *sy.SENDING]:
        assert sy.deleted(state.fields, state.removal) == gone, label
        assert sy.record_message(state, writer_fields, writer_version) == message, label
        c.add(
            "deleted",
            label,
            limit(label if state.state_stamp is not None else "limit", ["sync.md 4.3", "sync.md 5.1"]),
            {
                "state": J(state),
                "writer_fields": writer_fields,
                "writer_version": writer_version,
                "versions": versions,
            },
            accept(
                {
                    "deleted": gone,
                    "message": message and {"kind": message[0], "version": S(message[1])},
                }
            ),
        )

    # An installation that counted begins to stamp.
    for label, device, states, (now_ms, highest, rs), begun, after, top in sy.BEGINNINGS:
        assert sy.begin_stamping(device, states, now_ms, highest, rs) == (begun, after, top), label
        c.add(
            "begin_stamping",
            label,
            limit(label, ["sync.md 2.4", "sync.md 3.2"]),
            {
                "device": H(device),
                "states": [J(s) for s in states],
                "now_ms": S(now_ms),
                "highest": S(highest),
                "r": rs,
            },
            accept({"begun": begun, "states": [J(s) for s in after], "highest": S(top)}),
        )

    # After STALE, and the version to pass once the device has merged with its siblings.
    stales = [(*case[:8], True, case[8]) for case in sy.STALES]
    stales += [
        (label, v, own, None, p, False, False, clock, False, want)
        for label, v, own, p, clock, want in sy.BARRED
    ]
    for (
        label,
        version,
        state_stamp,
        sibling_stamp,
        to_pass,
        counted,
        sibling,
        clock,
        may_send,
        want,
    ) in stales:
        now_ms, highest, r = clock
        got_stale = sy.stale(version, state_stamp, sibling_stamp, to_pass, counted, sibling, *clock, may_send)
        assert got_stale == want, label
        c.add(
            "stale",
            label,
            limit(label, ["sync.md 5.3", "sync.md 2.2", "sync.md 2.4"]),
            {
                "receiver_version": S(version),
                "state_stamp": S(state_stamp),
                "sibling_stamp": S(sibling_stamp),
                "to_pass": S(to_pass),
                "counted": counted,
                "sibling": sibling,
                "may_send": may_send,
                "now_ms": S(now_ms),
                "highest": S(highest),
                "r": r,
            },
            accept(
                {
                    "highest": S(want.highest),
                    "stamps": want.stamps,
                    "to_pass": S(want.to_pass),
                    "resend": S(want.resend),
                }
            ),
        )
    for label, state_stamp, to_pass, may_send, (now_ms, highest, r), resend, kept, top in sy.PASSES:
        assert sy.pass_version(state_stamp, to_pass, may_send, now_ms, highest, r) == (resend, kept, top), (
            label
        )
        c.add(
            "pass_version",
            label,
            limit(label, ["sync.md 5.3", "sync.md 3.3"]),
            {
                "state_stamp": S(state_stamp),
                "to_pass": S(to_pass),
                "may_send": may_send,
                "now_ms": S(now_ms),
                "highest": S(highest),
                "r": r,
            },
            accept({"resend": S(resend), "to_pass": S(kept), "highest": S(top)}),
        )

    # What a device shows of a received record, from its two layers.
    for label, there, layer, state, sources in sy.SHOWN:
        got_state, fields = sy.shown(there, sy.SHOWN_VALUES, sy.SCHEMA_1, layer)
        assert (got_state, {n: source for n, (_, _, source) in fields.items()}) == (state, sources), label
        sender: Any = None
        if there:
            values = {name: H(value) for name, value in sy.SHOWN_VALUES.items()}
            sender = {"state": "there", "values": values, "schema": H(sy.SCHEMA_1)}
        c.add(
            "shown",
            label,
            ["sync.md 22.1", "sync.md 21.1", "sync.md 17.1"],
            {"sender": sender, "layer": J(layer, True)},
            accept(
                {
                    "record": state,
                    "fields": {
                        name: {"value": H(value), "schema": H(schema), "from": source}
                        for name, (value, schema, source) in fields.items()
                    },
                }
            ),
        )
    for label, has, layer, state, sources in sy.TOMBSTONES:
        values = {name: H(value) for name, value in sy.SHOWN_VALUES.items()}
        beside = (sy.SHOWN_VALUES, sy.SCHEMA_1) if has else None
        got_state, fields = sy.shown(False, {}, None, layer, sy.TOMBSTONE_VERSION, beside)
        assert (got_state, {n: source for n, (_, _, source) in fields.items()}) == (state, sources), label
        sender = {
            "state": "tombstone",
            "version": S(sy.TOMBSTONE_VERSION),
            "beside": {"values": values, "schema": H(sy.SCHEMA_1)} if has else None,
        }
        c.add(
            "shown",
            label,
            ["sync.md 22.1", "sync.md 21.1", "sync.md 20.1"],
            {"sender": sender, "layer": J(layer, True)},
            accept(
                {
                    "record": state,
                    "fields": {
                        name: {"value": H(value), "schema": H(schema), "from": source}
                        for name, (value, schema, source) in fields.items()
                    },
                }
            ),
        )

    # The extensions of a received record that a device shows, with the owner's parts within one.
    for label, layer, extensions, source in sy.SHOWN_WITHIN:
        got_state, fields = sy.shown(True, sy.SHOWN_EXTENSIONS, sy.SCHEMA_1, layer, texts=sy.SHOWN_TEXTS)
        want = sy.field_value(sy.APPOINTMENT_JSON, "extensions", extensions)
        assert got_state == "there" and fields["extensions"] == (
            want,
            sy.SCHEMA_1,
            source,
        ), label
        values = {name: H(value) for name, value in sy.SHOWN_EXTENSIONS.items()}
        c.add(
            "shown",
            label,
            ["sync.md 25.9", "sync.md 25.7", "sync.md 22.1", "records.md 6.1"],
            {
                "sender": {"state": "there", "values": values, "schema": H(sy.SCHEMA_1)},
                "layer": J(layer, True),
            },
            accept(
                {
                    "record": got_state,
                    "fields": {
                        name: {"value": H(value), "schema": H(schema), "from": from_}
                        for name, (value, schema, from_) in fields.items()
                    },
                }
            ),
        )

    # One device with its siblings: the sessions of the script, which has checked what each step says.
    def wire(v: Any) -> Any:
        """A step as a vector holds it: its messages and values as Bytes."""
        if isinstance(v, bytes):
            return B(v)
        if isinstance(v, dict):
            return {k: wire(x) for k, x in v.items()}
        if isinstance(v, list):
            return [wire(x) for x in v]
        return v

    assert len(sy.PLAYED) == len(sy.SAID)
    for played in sy.PLAYED:
        c.add(
            "siblings",
            played.label,
            played.refs,
            {"device": wire(played.device), "steps": wire(played.steps)},
            {"steps": played.answers},
        )
    # The version of a withdrawal and of a sharing again by a device that stamps (spec/shares.md,
    # sections 3.2 and 6.2).
    for label, refs, inp, want in withdrawal_versions():
        if not inp.pop("counted"):
            inp.pop("highest_given", None)
            result = {"version": want[0], "state_stamp": want[1], "highest": want[2]}
            c.add("withdrawal_stamp", label, refs, inp, accept(result))
    return c


# --- output ---------------------------------------------------------------------


def bricks_category() -> Category:
    c = Category(
        "bricks",
        "Descriptions of types made of typed fields: the schema derived from each, its canonical form and "
        "fingerprint, the descriptions that are not valid, and records of a type with relation fields "
        "(spec/fields.md).",
    )
    fe = pe.fe
    valid, invalid = fe.vector_descriptions()
    for label, d in valid:
        text = fe.derived_text(d)
        pcf, fp = me.fingerprint(text)
        assert pcf == fe.canonical(fe.derive(d))[0]
        c.add(
            "derive",
            f"{label} derives its schema",
            ["fields.md 9.2", "fields.md 9.3", "envelope.md 5"],
            {"description": B(fe.binary(d))},
            accept({"schema": text, "canonical_form": pcf, "fingerprint": H(pe.fp8(fp))}),
        )
    for label, d, where in invalid:
        problem = next(p for w, p in fe.description_problems(d) if w == where)
        c.add(
            "derive",
            f"a description with {label} is not valid",
            ["fields.md 6", "fields.md 9.1"],
            {"description": B(fe.binary(d))},
            reject("DESCRIPTION_INVALID", f"{where or 'the root'}: {problem}"),
        )
    brick_records(c, fe)
    return c


def brick_records(c: Category, fe: Any) -> None:
    """Records of the schema derived from com.example.Links, whose relation fields every receiver checks by
    the rules of spec/fields.md, section 11.4, wherever they are in the type."""
    text = fe.derived_text(fe.links_description())
    mimi, vet, r = rules.MIMI, rules.VET, rules.relation
    one = r("3e8a5b14-7c29-4d6e-a0f3-1b9d2c7e5a46", mimi)
    two = r("f1b3d5a7-2c4e-4f60-8a1b-3c5d7e9f0a2b", vet, kind="org.example.catalog.vet", note="Her vet.")
    site = r("1f2e3d4c-5b6a-4978-8a96-a5b4c3d2e1f0", rules.outside("https://example.org/mimi", "Mimi's page"))
    base = {"links": [one], "seen": None, "sources": [site], "history": [[one, two]], "place": None}
    place = {"name": "Practice", "links": [two]}
    cases: list[tuple[str, dict[str, Any]]] = [
        ("relations in every relation field", dict(base, place=place)),
        ("no relations, also in the field that is required, which only a check names", dict(base, links=[])),
        (
            "a repeated id in a list of relations inside a list",
            dict(base, history=[[one, dict(one, note="x")]]),
        ),
        ("the same relation in two lists, which is no repeated id", dict(base, sources=[one])),
        (
            "a kind without a namespace in a nested object",
            dict(base, place=dict(place, links=[dict(two, kind="vet")])),
        ),
        ("257 relations in the second relation field", dict(base, sources=[site] * 257)),
        (
            "a target's id that is the nil UUID",
            dict(base, links=[dict(one, target=dict(mimi, id="00000000-0000-0000-0000-000000000000"))]),
        ),
    ]
    rejected = 0
    for label, datum in cases:
        found = tm.value_breaches(json.loads(text), datum)
        body = single_object(text, datum)
        if found:
            rejected += 1
            expected = reject("VALUE_INVALID", found[0][2], field=found[0][0])
        else:
            expected = accept({"value": decode_meaning(text, None, body[10:])})
        c.add(
            "decode_record",
            f"{'reject' if found else 'take'} a record of com.example.Links: {label}",
            ["fields.md 11.4", "fields.md 11.6", "metadata.md 7.2"],
            {"writer_schema": text, "reader_schema": None, "body": B(body)},
            expected,
        )
    assert rejected == 4, rejected


CATEGORIES = [
    encoding_category,
    types_category,
    time_category,
    metadata_category,
    records_category,
    manifest_category,
    keys_category,
    protocol_category,
    file_category,
    qr_category,
    local_category,
    relay_category,
    relay_server_category,
    sync_category,
    shares_category,
    bricks_category,
]


def render(value: Any, indent: int = 0) -> str:
    """JSON with one key per line, and lists and objects of scalars on one line."""
    pad, inner = " " * indent, " " * (indent + 1)

    def flat(v: Any) -> bool:
        return (
            not isinstance(v, (dict, list))
            or (not v)
            or (
                all(not isinstance(x, (dict, list)) for x in (v.values() if isinstance(v, dict) else v))
                and len(json.dumps(v, ensure_ascii=False)) <= 100
            )
        )

    if flat(value):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[\n" + ",\n".join(inner + render(v, indent + 1) for v in value) + "\n" + pad + "]"
    return (
        "{\n"
        + ",\n".join(
            inner + json.dumps(k, ensure_ascii=False) + ": " + render(v, indent + 1) for k, v in value.items()
        )
        + "\n"
        + pad
        + "}"
    )


def same_values(v: Any) -> Any:
    if isinstance(v, dict):
        if set(v) == {"deflate", "length", "sha256"}:
            return {"length": v["length"], "sha256": v["sha256"]}
        return {k: same_values(x) for k, x in v.items()}
    if isinstance(v, list):
        return [same_values(x) for x in v]
    return v


# The vectors of each category by operation, and of them the rejected ones, as the table of
# spec/conformance.md, section 7.4, counts them.
COUNTS = {
    "bricks": ({"derive": 64, "decode_record": 7}, {"derive": 51, "decode_record": 4}),
    "encoding": (
        {"fingerprint": 25, "decode_message": 40, "decode_body": 56, "encode_message": 8},
        {"decode_message": 17, "decode_body": 37},
    ),
    # 0.1.0 and the relations of 0.2.0 (spec/conformance.md, section 7.5): 9 + 65 vectors, 18 rejected.
    "types": ({"fingerprint": 10, "decode_record": 101}, {"decode_record": 43}),
    "time": (
        {"fingerprint": 4, "decode_record": 81, "resolve_date_time": 10, "add_duration": 22},
        {"decode_record": 46},
    ),
    "metadata": ({"describe": 22, "check_record": 200}, {"check_record": 104}),
    "records": ({"apply": 18, "relations": 4}, {}),
    "manifest": ({"check_manifest": 52, "fit": 19}, {"check_manifest": 46}),
    "keys": (
        {
            "public_key": 4,
            "sign": 4,
            "verify": 11,
            "check_signing_key": 15,
            "check_encryption_key": 10,
            "short_fingerprint": 3,
            "verify_message": 8,
            "device_add": 8,
            "device_join": 11,
            "join_chain": 11,
            "device_sets": 57,
            "padded_length": 10,
            "seal": 2,
            "open": 10,
        },
        {
            "verify": 9,
            "check_signing_key": 12,
            "check_encryption_key": 8,
            "verify_message": 3,
            "device_add": 6,
            "device_join": 5,
            "join_chain": 8,
            "open": 8,
        },
    ),
    "protocol": ({"choose_format": 3, "contact_key": 5, "resend_after_removal": 2, "session": 47}, {}),
    "file": ({"read_file": 68}, {"read_file": 46}),
    "qr": ({"parse_qr": 28, "qr_text": 4}, {"parse_qr": 21}),
    "local": ({"hello_frame": 2, "connection": 20}, {}),
    "relay": ({"mailbox_id": 2, "request": 7, "reaction": 28, "listing": 3}, {}),
    "relay-server": ({"relay": 2}, {}),
    "sync": (
        {
            "next_stamp": 23,
            "change": 34,
            "merge": 104,
            "deleted": 22,
            "begin_stamping": 3,
            "stale": 10,
            "pass_version": 5,
            "shown": 27,
            "siblings": 488,
            "withdrawal_stamp": 4,
        },
        {},
    ),
    "shares": (
        {
            "receive": 14,
            "take_version": 2,
            "owed": 10,
            "acked": 16,
            "pass_withdrawal": 5,
            "join_receivers": 5,
            "offer_types": 2,
            "shared_value": 5,
            "owner": 69,
            "proposer": 33,
        },
        {},
    ),
}


def op_counts(vectors: list[dict[str, Any]], rejected: bool = False) -> dict[str, int]:
    out: dict[str, int] = {}
    for v in vectors:
        if not rejected or "reject" in v["expected"]:
            out[v["op"]] = out.get(v["op"], 0) + 1
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--check", action="store_true", help="compare with the files under vectors/ instead of writing"
    )
    ap.add_argument("--out", type=Path, default=VECTORS, help="the directory to write to (default: vectors/)")
    args = ap.parse_args()
    differ: list[str]
    counts: list[tuple[str, int]]
    differ, counts = [], []
    for build in CATEGORIES:
        c = build()
        text = render(c.document()) + "\n"
        path = (VECTORS if args.check else args.out) / c.name / f"{c.name}.json"
        counts.append((c.name, len(c.vectors)))
        assert (op_counts(c.vectors), op_counts(c.vectors, rejected=True)) == COUNTS[c.name], (
            f"{c.name}: {op_counts(c.vectors)}, rejected {op_counts(c.vectors, rejected=True)}; "
            "not the counts of spec/conformance.md, sections 7.4 and 7.5"
        )
        if args.check:
            # The DEFLATE of a large value depends on the zlib that writes it; its length and SHA-256 do not.
            if not path.exists() or same_values(json.loads(path.read_text(encoding="utf-8"))) != same_values(
                json.loads(text)
            ):
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
