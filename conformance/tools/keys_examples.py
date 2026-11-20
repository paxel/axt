# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Produce and check the examples of spec/keys.md.

Signs, seals and adds a device with fixed test keys, prints the results as
annotated hex, and checks them:

- a pure-Python Ed25519 (RFC 8032) with the strict verification of
  spec/keys.md, section 2.3, against the RFC 8032 test vector and against
  PyNaCl (libsodium) and cryptography (OpenSSL), for signing and for
  verifying;
- the verification of crafted signatures and keys at the edges of the
  rules (non-canonical S; keys and R that are non-canonical, of small
  order, or with a component of small order), with the strict rule here,
  with the plain RFC 8032 equations with and without the cofactor, and
  with both libraries, so that their differences are on record; and that
  libsodium's crypto_core_ed25519_is_valid_point agrees with steps 2 and 3;
- X25519 (RFC 7748) and HPKE (RFC 9180) in pure Python, against the
  RFC 7748 and RFC 9180 test vectors, and the sealed relay message against
  the HPKE of the cryptography package, which decrypts it;
- a signed DATA message (the Memo of spec/envelope.md), the same message
  in an AXT file with a signed header, read back from the file's block
  bytes and verified, and read with fastavro and the avro package;
- the schemas types/axt/DeviceJoin.avsc, DeviceAdd.avsc and DeviceRemove.avsc,
  checked with the schema rules of conformance/tools/example_types.py, and a
  DEVICE_ADD message, encoded field by field and compared with fastavro,
  decoded with fastavro and avro;
- a model of a receiver that follows the devices of its known senders
  (spec/keys.md, section 5.5), against the result of every cell of the
  section's table and of each of its rules, written out by hand here;
- the short fingerprints of the test keys.

Every key here is a TEST KEY, derived from a published text. It protects
nothing and MUST NOT be used outside tests.

Run from anywhere, with fastavro, avro (1.12), pynacl and cryptography
installed:

    python3 conformance/tools/keys_examples.py

conformance/tools/manifest_examples.py imports the X25519 function from here,
and the vector generator and the reference adapter the model of the receiver;
importing this file runs none of the checks.
"""

import hashlib
import hmac
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]

# --- the constants of spec/keys.md --------------------------------------------

MESSAGE_PREFIX = b"AXT-v1 message\x00"
FILE_HEADER_PREFIX = b"AXT-v1 file header\x00"
DEVICE_ADD_PREFIX = b"AXT-v1 device add\x00"
FINGERPRINT_PREFIX = b"AXT-v1 fingerprint\x00"
HPKE_INFO = b"AXT-v1 relay message"
SEALED_FORMAT = b"\x01"
MIN_PADDED = 1024

# --- Ed25519, after RFC 8032, sections 5.1 and 6 ------------------------------

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
Point = tuple[int, int, int, int]  # extended coordinates X, Y, Z, T
IDENTITY: Point = (0, 1, 1, 0)


def point_add(a: Point, b: Point) -> Point:
    pa, pb = (a[1] - a[0]) * (b[1] - b[0]) % P, (a[1] + a[0]) * (b[1] + b[0]) % P
    c, d = 2 * a[3] * b[3] * D % P, 2 * a[2] * b[2] % P
    e, f, g, h = pb - pa, d - c, d + c, pb + pa
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def point_mul(s: int, point: Point) -> Point:
    q = IDENTITY
    while s > 0:
        if s & 1:
            q = point_add(q, point)
        point = point_add(point, point)
        s >>= 1
    return q


def point_equal(a: Point, b: Point) -> bool:
    return (a[0] * b[2] - b[0] * a[2]) % P == 0 and (a[1] * b[2] - b[1] * a[2]) % P == 0


def recover_x(y: int, sign: int) -> int | None:
    if y >= P:
        return None  # a non-canonical encoding
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        return None if sign else 0  # x = 0 with the sign bit set is non-canonical
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P:
        return None  # not on the curve
    return P - x if (x & 1) != sign else x


BASE_Y = 4 * pow(5, P - 2, P) % P
BASE_X = cast(int, recover_x(BASE_Y, 0))
BASE = (BASE_X, BASE_Y, 1, BASE_X * BASE_Y % P)


def compress(point: Point) -> bytes:
    zinv = pow(point[2], P - 2, P)
    x, y = point[0] * zinv % P, point[1] * zinv % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def decompress(s: bytes) -> Point | None:
    """The point an encoding names, or None if it is not a canonical encoding of a point."""
    y = int.from_bytes(s, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    x = recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % P)


def small_order(point: Point) -> bool:
    return point_equal(point_mul(8, point), IDENTITY)


def order_l(point: Point) -> bool:
    """Whether a point has order L: not the neutral element, and L times it is."""
    return not point_equal(point, IDENTITY) and point_equal(point_mul(L, point), IDENTITY)


def expand(seed: bytes) -> tuple[int, bytes]:
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little") & ((1 << 254) - 8) | (1 << 254)
    return a, h[32:]


def public_key(seed: bytes) -> bytes:
    return compress(point_mul(expand(seed)[0], BASE))


def hash_mod_l(data: bytes) -> int:
    return int.from_bytes(hashlib.sha512(data).digest(), "little") % L


def sign(seed: bytes, message: bytes) -> bytes:
    a, prefix = expand(seed)
    pub = compress(point_mul(a, BASE))
    r = hash_mod_l(prefix + message)
    big_r = compress(point_mul(r, BASE))
    s = (r + hash_mod_l(big_r + pub + message) * a) % L
    return big_r + s.to_bytes(32, "little")


def key_problem(key: bytes) -> str | None:
    """Why an Ed25519 public key is not accepted (spec/keys.md, section 2.3), or None."""
    point = decompress(key)
    if point is None:
        return "key not a canonical encoding of a point"
    if not order_l(point):
        return "key not of order L"
    return None


def verify_problem(key: bytes, message: bytes, signature: bytes) -> str | None:
    """Why a signature does not verify under the strict rule of spec/keys.md, section 2.3, or None."""
    if len(key) != 32 or len(signature) != 64:
        return "wrong length"
    problem = key_problem(key)
    if problem:
        return problem
    big_r, s = signature[:32], int.from_bytes(signature[32:], "little")
    if s >= L:
        return "S not below L"
    r_point = decompress(big_r)
    if r_point is None:
        return "R not a canonical encoding of a point"
    if not order_l(r_point):
        return "R not of order L"
    k = hash_mod_l(big_r + key + message)
    if compress(point_add(point_mul(s, BASE), point_mul(L - k, cast(Point, decompress(key))))) != big_r:
        return "equation does not hold"
    return None


def verify_plain(key: bytes, message: bytes, signature: bytes, cofactor: int = 1) -> bool:
    """RFC 8032, section 5.1.7, without step 3 of spec/keys.md; for comparison only."""
    a_point, r_point = decompress(key), decompress(signature[:32])
    s = int.from_bytes(signature[32:], "little")
    if a_point is None or r_point is None or s >= L:
        return False
    k = hash_mod_l(signature[:32] + key + message)
    return point_equal(
        point_mul(cofactor * s, BASE), point_mul(cofactor, point_add(r_point, point_mul(k, a_point)))
    )


# --- X25519, after RFC 7748, section 5 ----------------------------------------


def x25519(scalar: bytes, u: bytes) -> bytes:
    k = int.from_bytes(scalar, "little") & ((1 << 254) - 8) | (1 << 254)
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in reversed(range(255)):
        bit = (k >> t) & 1
        swap ^= bit
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a, b = (x2 + z2) % P, (x2 - z2) % P
        aa, bb = a * a % P, b * b % P
        e = (aa - bb) % P
        c, d = (x3 + z3) % P, (x3 - z3) % P
        da, cb = d * a % P, c * b % P
        x3, z3 = (da + cb) ** 2 % P, x1 * (da - cb) ** 2 % P
        x2, z2 = aa * bb % P, e * (aa + 121665 * e) % P
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")


X25519_BASE = (9).to_bytes(32, "little")


def encryption_key_problem(key: bytes) -> str | None:
    """Why an X25519 public key is not accepted (spec/keys.md, section 4.2), or None."""
    if len(key) != 32:
        return "wrong length"
    # X25519 of a small-order point is all zero for every private key; any one detects it.
    if x25519(hashlib.sha256(b"AXT small-order check").digest(), key) == bytes(32):
        return "encryption key of small order"
    return None


# --- HPKE, RFC 9180: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305 ---

KEM_SUITE = b"KEM" + (0x0020).to_bytes(2, "big")
HPKE_SUITE = b"HPKE" + (0x0020).to_bytes(2, "big") + (0x0001).to_bytes(2, "big") + (0x0003).to_bytes(2, "big")


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def labeled_extract(suite: bytes, salt: bytes, label: bytes, ikm: bytes) -> bytes:
    return hkdf_extract(salt, b"HPKE-v1" + suite + label + ikm)


def labeled_expand(suite: bytes, prk: bytes, label: bytes, info: bytes, length: int) -> bytes:
    return hkdf_expand(prk, length.to_bytes(2, "big") + b"HPKE-v1" + suite + label + info, length)


def derive_key_pair(ikm: bytes) -> tuple[bytes, bytes]:
    sk = labeled_expand(KEM_SUITE, labeled_extract(KEM_SUITE, b"", b"dkp_prk", ikm), b"sk", b"", 32)
    return sk, x25519(sk, X25519_BASE)


def hpke_base_context(shared_secret: bytes, info: bytes) -> dict[str, bytes]:
    """The key schedule of RFC 9180, section 5.1, in mode_base."""
    ksc = (
        b"\x00"
        + labeled_extract(HPKE_SUITE, b"", b"psk_id_hash", b"")
        + labeled_extract(HPKE_SUITE, b"", b"info_hash", info)
    )
    secret = labeled_extract(HPKE_SUITE, shared_secret, b"secret", b"")
    return {
        "key_schedule_context": ksc,
        "secret": secret,
        "key": labeled_expand(HPKE_SUITE, secret, b"key", ksc, 32),
        "base_nonce": labeled_expand(HPKE_SUITE, secret, b"base_nonce", ksc, 12),
        "exporter_secret": labeled_expand(HPKE_SUITE, secret, b"exp", ksc, 32),
    }


def encap(sk_e: bytes, pk_r: bytes) -> tuple[bytes, bytes]:
    """DHKEM Encap with a given ephemeral private key (RFC 9180, section 4.1)."""
    pk_e = x25519(sk_e, X25519_BASE)
    dh = x25519(sk_e, pk_r)
    if dh == bytes(32):
        raise ValueError("the X25519 output is all zero")
    eae_prk = labeled_extract(KEM_SUITE, b"", b"eae_prk", dh)
    return pk_e, labeled_expand(KEM_SUITE, eae_prk, b"shared_secret", pk_e + pk_r, 32)


def decap(enc: bytes, sk_r: bytes) -> bytes:
    pk_r = x25519(sk_r, X25519_BASE)
    dh = x25519(sk_r, enc)
    if dh == bytes(32):
        raise ValueError("the X25519 output is all zero")
    eae_prk = labeled_extract(KEM_SUITE, b"", b"eae_prk", dh)
    return labeled_expand(KEM_SUITE, eae_prk, b"shared_secret", enc + pk_r, 32)


# --- padding (spec/keys.md, section 4.4) --------------------------------------


def padme(n: int) -> int:
    """Padme (Nikitin et al., 2019): n rounded up so that only its top bits vary."""
    e = n.bit_length() - 1
    s = e.bit_length()
    mask = (1 << (e - s)) - 1
    return (n + mask) & ~mask


def padded_length(n: int) -> int:
    return max(MIN_PADDED, padme(n + 1))


def pad(message: bytes) -> bytes:
    return message + b"\x80" + bytes(padded_length(len(message)) - len(message) - 1)


def unpad(plaintext: bytes) -> bytes:
    stripped = plaintext.rstrip(b"\x00")
    if not stripped.endswith(b"\x80"):
        raise ValueError("the padding is not 80 followed by zero bytes")
    return stripped[:-1]


# --- short fingerprints (spec/keys.md, section 3.1) ---------------------------


def short_fingerprint(key: bytes) -> str:
    h = hashlib.sha256(FINGERPRINT_PREFIX + key).digest()
    return " ".join(f"{int.from_bytes(h[i : i + 5], 'big') % 100000:05d}" for i in range(0, 25, 5))


# --- Avro encoding by hand ----------------------------------------------------


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


def read_long(buf: bytes, pos: int) -> tuple[int, int]:
    shift = result = 0
    while True:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            return (result >> 1) ^ -(result & 1), pos


def envelope_end(buf: bytes, pos: int) -> int:
    """The end of the axt.Envelope (format 1) that starts at pos, found by decoding its fields."""
    _, pos = read_long(buf, pos)  # format
    _, pos = read_long(buf, pos)  # kind
    pos += 32  # sender
    branch, pos = read_long(buf, pos)  # record
    if branch == 1:
        n, pos = read_long(buf, pos)
        pos += n  # id
        _, pos = read_long(buf, pos)  # version
    n, pos = read_long(buf, pos)
    pos += n  # body
    return pos + 64  # signature


def file_datums(data: bytes) -> tuple[dict[str, bytes], list[bytes]]:
    """The metadata and the raw bytes of every datum of an AXT file with the codec null."""
    assert data[:4] == b"Obj\x01"
    pos, meta = 4, {}
    while True:
        count, pos = read_long(data, pos)
        if count == 0:
            break
        if count < 0:
            count = -count
            _, pos = read_long(data, pos)
        for _ in range(count):
            n, pos = read_long(data, pos)
            key = data[pos : pos + n].decode()
            pos += n
            n, pos = read_long(data, pos)
            meta[key] = data[pos : pos + n]
            pos += n
    sync = data[pos : pos + 16]
    pos += 16
    datums = []
    while pos < len(data):
        count, pos = read_long(data, pos)
        size, pos = read_long(data, pos)
        block, pos = data[pos : pos + size], pos + size
        assert data[pos : pos + 16] == sync
        pos += 16
        at = 0
        for _ in range(count):
            end = envelope_end(block, at)
            datums.append(block[at:end])
            at = end
        assert at == len(block)
    return meta, datums


# --- device sets (spec/keys.md, section 5) ------------------------------------

ADD, REMOVE = "DEVICE_ADD", "DEVICE_REMOVE"
# What a receiver does with an addition or a removal (section 5.5).
APPLIED, IGNORED, REJECTED, NOT_PLACED = "APPLIED", "IGNORED", "DEVICE_REJECTED", "NOT_PLACED"
REFUSED = "REFUSED"  # signed with a refused key: rejected without a report (step 3)
SIGNATURE_INVALID = "SIGNATURE_INVALID"


def proof_bytes(member: bytes, device: bytes) -> bytes:
    """The bytes the new device signs as the proof of a DEVICE_JOIN and a DEVICE_ADD (section 5.2)."""
    return DEVICE_ADD_PREFIX + member + device


def device_message_problem(
    kind: str, signer: bytes, signed: bytes, signature: bytes, device: bytes, proof: bytes | None
) -> str | None:
    """Steps 1 and 2 of section 5.5 for a message whose signed bytes (section 2.2) are signed."""
    if verify_problem(signer, signed, signature):
        return SIGNATURE_INVALID
    if kind == ADD and (
        key_problem(device) or proof is None or verify_problem(device, proof_bytes(signer, device), proof)
    ):
        return REJECTED
    if kind == REMOVE and device == signer:
        return REJECTED  # a device does not remove itself (section 5.3)
    return None


def join_action(
    member: bytes,
    current: list[bytes],
    removed: list[bytes],
    to: bytes,
    device: bytes,
    proof: bytes,
    first: bytes | None = None,
) -> str:
    """What a device that shows a join code does with a DEVICE_JOIN whose signature verified (section
    5.2): member is its own key, current and removed the other keys of its set, to and proof the body
    and device the sender of the message; first is the key of the first DEVICE_JOIN it got for the
    code, if this is not the first. It ignores the message, rejects it, sends its chain again or asks
    its user; a repeat from the same key is answered as the first was."""
    if first is not None and device != first:
        return "ignore"
    if to != member:
        return "ignore"
    if key_problem(device) or verify_problem(device, proof_bytes(member, device), proof) or device in removed:
        return REJECTED
    return "send_chain" if device == member or device in current else "ask"


def join_chain_problem(
    chain: list[tuple[str, bytes, bytes, bytes | None, bool]], member: bytes, own: bytes
) -> str | None:
    """Why a new device does not take the chain it gets in answer to its DEVICE_JOIN (section 5.2, step
    5), or None: each message is its kind, signer, device, proof and whether its signature verifies;
    member is the scanned key, own the new device's."""
    if not all(verifies for *_, verifies in chain):
        return "a signature does not verify"
    if any(kind == REMOVE and device == own for kind, _, device, _, _ in chain):
        return "a DEVICE_REMOVE of the new device"
    for kind, signer, device, proof, _ in chain:
        if (
            kind == ADD
            and signer == member
            and device == own
            and proof is not None
            and verify_problem(own, proof_bytes(member, own), proof) is None
        ):
            return None
    return "no DEVICE_ADD of the new device by the scanned key with its proof"


@dataclass
class KnownSender:
    """What a receiver keeps of a sender's keys (section 3.3), and of its records their id, version and
    state."""

    name: str
    current: list[bytes]
    removed: list[bytes] = field(default_factory=list)
    records: dict[str, tuple[int, str]] = field(default_factory=dict)

    def single(self) -> bool:
        """Whether the sender has only one key, current and not removed."""
        return len(self.current) == 1 and not self.removed


# One message of a chain: its kind, its signer, its device, and SIGNATURE_INVALID or DEVICE_REJECTED
# if it fails step 1 or 2.
ChainMessage = tuple[str, bytes, bytes, str | None]


class DeviceReceiver:
    """A receiver that follows the devices of its known senders: steps 3 and 4, the table and the chain
    of section 5.5, with the refused keys of section 3.4. It keeps no manifests and no encryption keys."""

    def __init__(self, senders: list[KnownSender], refused: list[bytes] | None = None) -> None:
        self.senders = senders
        self.refused = refused or []  # the removed keys of senders the receiver has forgotten
        # The chain being read: its messages, the result of each, and those kept.
        self.messages: list[tuple[str, bytes, bytes]] = []
        self.results: list[str] = []
        self.kept: list[int] = []

    def sender_of(self, key: bytes) -> KnownSender | None:
        for s in self.senders:
            if key in s.current or key in s.removed:
                return s
        return None

    def state(self) -> list[dict[str, Any]]:
        """The known senders with their keys in hexadecimal, everything sorted, so that two receivers
        that keep the same hold the same value."""
        return [
            {
                "name": s.name,
                "current": sorted(k.hex() for k in s.current),
                "removed": sorted(k.hex() for k in s.removed),
                "records": [
                    {"id": rid, "version": s.records[rid][0], "state": s.records[rid][1]}
                    for rid in sorted(s.records)
                ],
            }
            for s in sorted(self.senders, key=lambda s: s.name)
        ]

    def key_state(self, key: bytes) -> tuple[str, str | None]:
        """What a key is to the receiver: current, with its sender's name; removed; refused; or
        unknown."""
        if key in self.refused:
            return "refused", None
        s = self.sender_of(key)
        if s is None:
            return "unknown", None
        return ("current", s.name) if key in s.current else ("removed", None)

    def join(self, other: KnownSender, second: KnownSender) -> None:
        """The second sender's key and records become the other's; the version rule decides each record."""
        other.current += second.current
        for rid, (version, state) in second.records.items():
            if rid not in other.records or version > other.records[rid][0]:
                other.records[rid] = (version, state)
        self.senders.remove(second)

    def place(self, kind: str, signer: bytes, device: bytes) -> str:
        """Steps 3 and 4 for a message that passed steps 1 and 2."""
        if signer in self.refused:  # step 3
            return REFUSED
        s, t = self.sender_of(signer), self.sender_of(device)
        if s is None:
            if kind == ADD and t is not None and device in t.current:
                t.current.append(signer)
                return APPLIED
            return NOT_PLACED
        signer_current = signer in s.current
        if t is s:
            if device in s.removed or kind == ADD:
                return IGNORED
            if not signer_current:
                return REJECTED
            s.current.remove(device)
            s.removed.append(device)
            return APPLIED
        if kind == REMOVE:
            return IGNORED if signer_current else REJECTED
        if not signer_current:
            return REJECTED
        if device in self.refused or t is not None and device in t.removed:
            return REJECTED
        if t is None:
            s.current.append(device)
            return APPLIED
        if t.single():
            self.join(s, t)
        elif s.single():
            self.join(t, s)
        else:
            return REJECTED
        return APPLIED

    def take(self, kind: str, signer: bytes, device: bytes, problem: str | None = None) -> str:
        """The next message of a chain; its result for now. A message that step 3 cannot place is kept,
        and so is a removal by a current key whose device is not a key of the signer's sender; a kept
        message is tried again after every applied addition, until it applies."""
        self.messages.append((kind, signer, device))
        result = problem or self.place(kind, signer, device)
        self.results.append(result)
        early = result == IGNORED and kind == REMOVE and self.sender_of(device) is not self.sender_of(signer)
        if result == NOT_PLACED or early:
            self.kept.append(len(self.results) - 1)
        elif result == APPLIED and kind == ADD:
            self.try_kept()
        return result

    def try_kept(self) -> None:
        applied = True
        while applied:
            applied = False
            for i in list(self.kept):
                self.results[i] = self.place(*self.messages[i])
                if self.results[i] == APPLIED:
                    self.kept.remove(i)
                    applied = True

    def end(self) -> list[str]:
        """The end of a chain: the kept messages are tried once more. The result of each message of
        the chain, for a kept one that of its last try: a removal whose device is still not a key of
        the signer's sender is ignored."""
        self.try_kept()
        results = self.results
        self.messages, self.results, self.kept = [], [], []
        return results

    def chain(self, messages: list[ChainMessage]) -> list[str]:
        """The results of the messages of one chain, taken in their order."""
        for message in messages:
            self.take(*message)
        return self.end()


# The cases of section 5.5, with the results the text gives, written out by hand. A key is a letter and
# a sender is its name, its current keys and its removed keys; a record is its id, version and state.
SenderCase = tuple[str, str, str]
RecordCase = dict[str, list[tuple[str, int, str]]]
# A chain: the key that sends it (the connection key or a file's axt.sender; None through a relay), its
# messages as kind, signer and device, the result of each, what the sending key then is, and the
# senders afterwards.
ChainCase = tuple[
    str | None, list[tuple[str, str, str]], list[str], tuple[str, str | None] | None, list[SenderCase]
]
BAD_SIGNATURE, BAD_PROOF, BAD_DEVICE = "+bad signature", "+bad proof", "+device of small order"
# In the senders of a case, the entry of this name holds the receiver's refused keys (section 3.4).
REFUSED_KEYS = "refused keys"


def table_cases() -> list[tuple[str, list[SenderCase], tuple[str, str, str], str, list[SenderCase]]]:
    """Every cell of the table of section 5.5: (label, the senders before, the message, the result, the
    senders after), each message a chain of its own, so that a removal that is kept is ignored at its
    end. Further cases cover both readings of "further keys" and of "the only key", and a refused key."""
    s1, s2 = [("s", "AB", "R")], [("s", "A", "RQ")]
    t3 = [("s", "A", "R"), ("t", "X", "")]
    t4 = [("s", "A", "R"), ("t", "XY", "")]
    t5 = [("s", "A", "R"), ("t", "X", "Z")]
    f5 = [("s", "A", "R"), (REFUSED_KEYS, "F", "")]
    s6 = [("s", "A", "R")]
    rows = [
        "a current key of the signer's sender",
        "a removed key of the signer's sender",
        "the only key of another known sender",
        "a current key of another known sender with further keys",
        "a removed key of another known sender",
        "a key of no known sender",
    ]
    cur, rem = "signer current", "signer removed"

    def cell(row: int, kind: str, signer: str, variant: str = "") -> str:
        return f"row {row}, {kind}, {signer}{variant}: the device is {rows[row - 1]}"

    return [
        (cell(1, ADD, cur), s1, (ADD, "A", "B"), IGNORED, s1),
        (cell(1, ADD, cur, ", the signer's own key"), s1, (ADD, "A", "A"), IGNORED, s1),
        (cell(1, ADD, rem), s1, (ADD, "R", "B"), IGNORED, s1),
        (cell(1, REMOVE, cur), s1, (REMOVE, "A", "B"), APPLIED, [("s", "A", "RB")]),
        (cell(1, REMOVE, rem), s1, (REMOVE, "R", "B"), REJECTED, s1),
        (cell(2, ADD, cur), s2, (ADD, "A", "Q"), IGNORED, s2),
        (cell(2, ADD, rem), s2, (ADD, "R", "Q"), IGNORED, s2),
        (cell(2, REMOVE, cur), s2, (REMOVE, "A", "Q"), IGNORED, s2),
        (cell(2, REMOVE, rem), s2, (REMOVE, "R", "Q"), IGNORED, s2),
        (cell(3, ADD, cur), t3, (ADD, "A", "X"), APPLIED, [("s", "AX", "R")]),
        (cell(3, ADD, rem), t3, (ADD, "R", "X"), REJECTED, t3),
        (cell(3, REMOVE, cur), t3, (REMOVE, "A", "X"), IGNORED, t3),
        (cell(3, REMOVE, rem), t3, (REMOVE, "R", "X"), REJECTED, t3),
        (
            cell(4, ADD, cur, ", the signer the only key of its sender"),
            [("s", "A", ""), ("t", "XY", "")],
            (ADD, "A", "X"),
            APPLIED,
            [("t", "XYA", "")],
        ),
        (cell(4, ADD, cur, ", the signer's sender with a removed key"), t4, (ADD, "A", "X"), REJECTED, t4),
        (
            cell(4, ADD, cur, ", the signer's sender with two current keys"),
            [("s", "AB", ""), ("t", "XY", "")],
            (ADD, "A", "X"),
            REJECTED,
            [("s", "AB", ""), ("t", "XY", "")],
        ),
        (
            cell(4, ADD, cur, ", a removed key at the device's sender, the signer its sender's only key"),
            [("s", "A", ""), ("t", "X", "Z")],
            (ADD, "A", "X"),
            APPLIED,
            [("t", "XA", "Z")],
        ),
        (cell(4, ADD, cur, ", a removed key at both senders"), t5, (ADD, "A", "X"), REJECTED, t5),
        (cell(4, ADD, rem), t4, (ADD, "R", "X"), REJECTED, t4),
        (cell(4, REMOVE, cur), t4, (REMOVE, "A", "X"), IGNORED, t4),
        (cell(4, REMOVE, rem), t4, (REMOVE, "R", "X"), REJECTED, t4),
        (cell(5, ADD, cur), t5, (ADD, "A", "Z"), REJECTED, t5),
        (cell(5, ADD, rem), t5, (ADD, "R", "Z"), REJECTED, t5),
        (cell(5, REMOVE, cur), t5, (REMOVE, "A", "Z"), IGNORED, t5),
        (cell(5, REMOVE, rem), t5, (REMOVE, "R", "Z"), REJECTED, t5),
        (cell(5, ADD, cur, ", a refused key"), f5, (ADD, "A", "F"), REJECTED, s6),
        (cell(5, ADD, rem, ", a refused key"), f5, (ADD, "R", "F"), REJECTED, s6),
        (cell(5, REMOVE, cur, ", a refused key"), f5, (REMOVE, "A", "F"), IGNORED, s6),
        (cell(5, REMOVE, rem, ", a refused key"), f5, (REMOVE, "R", "F"), REJECTED, s6),
        (cell(6, ADD, cur), s6, (ADD, "A", "N"), APPLIED, [("s", "AN", "R")]),
        (cell(6, ADD, rem), s6, (ADD, "R", "N"), REJECTED, s6),
        (cell(6, REMOVE, cur), s6, (REMOVE, "A", "N"), IGNORED, s6),
        (cell(6, REMOVE, rem), s6, (REMOVE, "R", "N"), REJECTED, s6),
    ]


def chain_cases() -> list[tuple[str, str, list[SenderCase], RecordCase, list[ChainCase], RecordCase]]:
    """The steps and rules of section 5.5 beyond the table: (name, what the case shows, the senders
    before, their records, the chains in turn, the records afterwards)."""
    s = [("s", "A", "")]
    ab = [("s", "AB", "")]
    current = ("current", "s")
    return [
        (
            "step-1-signature",
            "step 1: a message whose signature does not verify is not applied, and the next one is taken",
            s,
            {},
            [
                (
                    "A",
                    [(ADD + BAD_SIGNATURE, "A", "B"), (ADD, "A", "C")],
                    [SIGNATURE_INVALID, APPLIED],
                    current,
                    [("s", "AC", "")],
                )
            ],
            {},
        ),
        (
            "step-2-proof",
            "step 2: an addition whose proof does not verify, or whose device is not a point of order L, "
            "is rejected, whoever signs it",
            s,
            {},
            [
                (
                    "A",
                    [(ADD + BAD_PROOF, "A", "B"), (ADD + BAD_DEVICE, "A", "T"), (ADD + BAD_PROOF, "N", "A")],
                    [REJECTED, REJECTED, REJECTED],
                    current,
                    s,
                )
            ],
            {},
        ),
        (
            "step-2-self-removal",
            "step 2: a removal of its signer's own key is rejected, whether the signer is a current "
            "key, a removed key or a key the receiver does not know",
            [("s", "AB", "R")],
            {},
            [
                (
                    "A",
                    [(REMOVE, "A", "A"), (REMOVE, "R", "R"), (REMOVE, "N", "N")],
                    [REJECTED, REJECTED, REJECTED],
                    current,
                    [("s", "AB", "R")],
                )
            ],
            {},
        ),
        (
            "step-3-refused-signer",
            "step 3: a message signed with a refused key is rejected without a report, a known device "
            "does not vouch for a refused key, and a further message of that key is rejected",
            [("s", "A", ""), (REFUSED_KEYS, "F", "")],
            {},
            [
                (None, [(ADD, "F", "A"), (ADD, "F", "N"), (REMOVE, "F", "A")], [REFUSED] * 3, None, s),
                ("F", [], [], ("refused", None), s),
            ],
            {},
        ),
        (
            "refused-device-unknown-signer",
            "an addition of a refused key by a signer the receiver does not know is not placed",
            [("s", "A", ""), (REFUSED_KEYS, "F", "")],
            {},
            [(None, [(ADD, "N", "F")], [NOT_PLACED], None, s)],
            {},
        ),
        (
            "step-3-known-device",
            "step 3: an addition by an unknown signer of a device that is a current key adds the signer",
            s,
            {},
            [("A", [(ADD, "N", "A")], [APPLIED], current, [("s", "AN", "")])],
            {},
        ),
        (
            "step-3-removed-device",
            "step 3: a removed key vouches for no one, so an addition of it by an unknown signer is not "
            "placed, and neither is a removal by an unknown signer",
            [("s", "A", "R")],
            {},
            [
                (
                    None,
                    [(ADD, "N", "R"), (REMOVE, "N", "A"), (ADD, "N", "M")],
                    [NOT_PLACED] * 3,
                    None,
                    [("s", "A", "R")],
                )
            ],
            {},
        ),
        (
            "chain-forwards",
            "a chain read by a receiver that knows the first device: each message applies in its turn, "
            "and the device that sends the chain is then a current key",
            s,
            {},
            [
                (
                    "C",
                    [(ADD, "A", "B"), (ADD, "B", "C"), (REMOVE, "C", "A")],
                    [APPLIED, APPLIED, APPLIED],
                    current,
                    [("s", "BC", "A")],
                )
            ],
            {},
        ),
        (
            "chain-backwards",
            "a chain read by a receiver that knows only the last device: the earlier ones are learnt "
            "link by link, backwards, and the removal that follows meets its keys",
            [("s", "D", "")],
            {},
            [
                (
                    "D",
                    [(ADD, "A", "B"), (ADD, "A", "C"), (REMOVE, "C", "B"), (ADD, "C", "D")],
                    [APPLIED, APPLIED, APPLIED, APPLIED],
                    current,
                    [("s", "DCA", "B")],
                )
            ],
            {},
        ),
        (
            "chain-unplaced",
            "a chain of another set, sent by a key the receiver does not know: nothing is placed, and "
            "the key is a first contact",
            s,
            {},
            [("N", [(ADD, "M", "N"), (REMOVE, "N", "M")], [NOT_PLACED, NOT_PLACED], ("unknown", None), s)],
            {},
        ),
        (
            "chain-with-removed-signer",
            "a repeat is recognised before the signer's removal counts: a chain whose addition was "
            "signed with a key removed later is taken again without an error",
            [("s", "B", "A")],
            {},
            [("B", [(ADD, "A", "B"), (REMOVE, "B", "A")], [IGNORED, IGNORED], current, [("s", "B", "A")])],
            {},
        ),
        (
            "file-of-later-device",
            "a file whose sender is a later device: the chain leads from the key the reader knows to "
            "the key in axt.sender, which is then a current key of that sender",
            s,
            {},
            [("C", [(ADD, "A", "B"), (ADD, "B", "C")], [APPLIED, APPLIED], current, [("s", "ABC", "")])],
            {},
        ),
        (
            "sender-removed",
            "the key of a connection is removed by another device of its set: it is a removed key "
            "afterwards, so its further messages are rejected",
            ab,
            {},
            [("B", [(REMOVE, "A", "B")], [APPLIED], ("removed", None), [("s", "A", "B")])],
            {},
        ),
        (
            "removal-before-addition-in-one-chain",
            "a removal that stands before the addition of its device in one chain is kept, and "
            "applies once the addition is applied",
            s,
            {},
            [(None, [(REMOVE, "A", "B"), (ADD, "A", "B")], [APPLIED, APPLIED], None, [("s", "A", "B")])],
            {},
        ),
        (
            "removal-kept-to-the-end",
            "a kept removal whose device is still not a key of the signer's sender at the end of the "
            "chain is ignored, whatever other addition was applied in between",
            s,
            {},
            [(None, [(REMOVE, "A", "B"), (ADD, "A", "C")], [IGNORED, APPLIED], None, [("s", "AC", "")])],
            {},
        ),
        (
            "addition-after-first-contact",
            "order through a relay: a key that was a first contact is the sender's once its addition arrives",
            s,
            {},
            [
                ("B", [], [], ("unknown", None), s),
                (None, [(ADD, "A", "B")], [APPLIED], None, ab),
                ("B", [], [], current, ab),
            ],
            {},
        ),
        (
            "removal-before-addition",
            "a removal that arrives in a chain of its own before the addition of its device is "
            "ignored, the addition applied, and the removal applies when it is sent again",
            s,
            {},
            [
                (None, [(REMOVE, "A", "B")], [IGNORED], None, s),
                (None, [(ADD, "A", "B")], [APPLIED], None, ab),
                (None, [(ADD, "A", "B"), (REMOVE, "A", "B")], [IGNORED, APPLIED], None, [("s", "A", "B")]),
                (None, [(ADD, "A", "B"), (REMOVE, "A", "B")], [IGNORED, IGNORED], None, [("s", "A", "B")]),
            ],
            {},
        ),
        (
            "removal-not-arrived",
            "a removal that did not arrive: the removed key is taken as a current one by its addition "
            "of a known device, until the whole chain is sent again",
            [("s", "B", "")],
            {},
            [
                (None, [(ADD, "A", "B")], [APPLIED], None, [("s", "BA", "")]),
                ("B", [(ADD, "A", "B"), (REMOVE, "B", "A")], [IGNORED, APPLIED], current, [("s", "B", "A")]),
            ],
            {},
        ),
        (
            "mutual-removal-first",
            "two devices that remove each other: the removal the receiver gets first applies, and the "
            "other is signed with a removed key and rejected; the sender's records and tombstones stay",
            ab,
            {"s": [("r1", 3, "there"), ("r2", 2, "tombstone")]},
            [(None, [(REMOVE, "A", "B"), (REMOVE, "B", "A")], [APPLIED, REJECTED], None, [("s", "A", "B")])],
            {"s": [("r1", 3, "there"), ("r2", 2, "tombstone")]},
        ),
        (
            "mutual-removal-second",
            "two devices that remove each other, in the other order: this receiver keeps the other device",
            ab,
            {},
            [(None, [(REMOVE, "B", "A"), (REMOVE, "A", "B")], [APPLIED, REJECTED], None, [("s", "B", "A")])],
            {},
        ),
        (
            "removed-stays-removed",
            "a removed key is never added again, and a message signed with it adds no device",
            [("s", "A", "B")],
            {},
            [(None, [(ADD, "A", "B"), (ADD, "B", "C")], [IGNORED, REJECTED], None, [("s", "A", "B")])],
            {},
        ),
        (
            "join-device-sender",
            "joining two senders: the device's sender has one key and is the second sender; its "
            "records go to the other by the version rule, and it is forgotten",
            [("s", "A", "R"), ("t", "X", "")],
            {
                "s": [("r1", 3, "there"), ("r2", 2, "there"), ("r3", 5, "tombstone")],
                "t": [("r1", 4, "tombstone"), ("r2", 2, "tombstone"), ("r3", 1, "there"), ("r4", 1, "there")],
            },
            [(None, [(ADD, "A", "X")], [APPLIED], None, [("s", "AX", "R")])],
            {"s": [("r1", 4, "tombstone"), ("r2", 2, "there"), ("r3", 5, "tombstone"), ("r4", 1, "there")]},
        ),
        (
            "join-signer-sender",
            "joining two senders: the device's sender has further keys, so the signer's sender, with "
            "its one key, is the second",
            [("s", "A", ""), ("t", "XY", "")],
            {"s": [("r1", 2, "there")], "t": [("r1", 1, "there"), ("r2", 7, "tombstone")]},
            [("A", [(ADD, "A", "X")], [APPLIED], ("current", "t"), [("t", "XYA", "")])],
            {"t": [("r1", 2, "there"), ("r2", 7, "tombstone")]},
        ),
        (
            "join-rejected",
            "two senders that each have more than one key are not joined, and keep their records",
            [("s", "AB", ""), ("t", "XY", "")],
            {"s": [("r1", 2, "there")], "t": [("r1", 1, "there")]},
            [("A", [(ADD, "A", "X")], [REJECTED], current, [("s", "AB", ""), ("t", "XY", "")])],
            {"s": [("r1", 2, "there")], "t": [("r1", 1, "there")]},
        ),
    ]


def check_device_cases() -> int:
    """Run the model over the cases above with letters as keys; the number of cases."""

    def receiver(senders: list[SenderCase], records: RecordCase) -> DeviceReceiver:
        return DeviceReceiver(
            [
                KnownSender(
                    name,
                    [k.encode() for k in current],
                    [k.encode() for k in removed],
                    {rid: (version, state) for rid, version, state in records.get(name, [])},
                )
                for name, current, removed in senders
                if name != REFUSED_KEYS
            ],
            [k.encode() for name, keys, _ in senders if name == REFUSED_KEYS for k in keys],
        )

    def keys_of(r: DeviceReceiver) -> list[SenderCase]:
        return [(s.name, b"".join(s.current).decode(), b"".join(s.removed).decode()) for s in r.senders]

    def records_of(r: DeviceReceiver) -> RecordCase:
        return {s.name: [(rid, *s.records[rid]) for rid in sorted(s.records)] for s in r.senders if s.records}

    table = table_cases()
    cells = {label.split(":")[0].split(", the ")[0].split(", a re")[0] for label, *_ in table}
    assert len(cells) == 24, "not every cell of the table of section 5.5"
    for label, before, (kind, signer, device), result, after in table:
        r = receiver(before, {})
        assert r.chain([(kind, signer.encode(), device.encode(), None)]) == [result], label
        assert keys_of(r) == after, (label, keys_of(r))
    chains = chain_cases()
    for name, _, before, records, steps, records_after in chains:
        r = receiver(before, records)
        for key, messages, results, state, after in steps:
            got = r.chain(
                [
                    (
                        kind.split("+")[0],
                        signer.encode(),
                        device.encode(),
                        {BAD_SIGNATURE: SIGNATURE_INVALID, BAD_PROOF: REJECTED, BAD_DEVICE: REJECTED}.get(
                            kind[len(kind.split("+")[0]) :],
                            REJECTED if (kind, signer) == (REMOVE, device) else None,
                        ),
                    )
                    for kind, signer, device in messages
                ]
            )
            assert got == results, (name, got)
            assert keys_of(r) == after, (name, keys_of(r))
            assert state is None or key is not None and r.key_state(key.encode()) == state, name
        assert records_of(r) == records_after, (name, records_of(r))
    return len(table) + len(chains)


# --- the edges of verification (spec/keys.md, section 7.6) --------------------


def small_order_points() -> list[bytes]:
    """The canonical encodings of the eight points of small order: [L] times a point of order 8L generates
    them."""
    i = 0
    while True:
        candidate = decompress(hashlib.sha256(b"AXT torsion %d" % i).digest())
        i += 1
        if candidate is not None:
            torsion = point_mul(L, candidate)
            if not point_equal(point_mul(4, torsion), IDENTITY):
                break
    return sorted(compress(point_mul(k, torsion)) for k in range(8))


def edge_cases(
    seed: bytes, other_key: bytes, msg: bytes, sig: bytes
) -> tuple[list[tuple[str, bytes, bytes, bytes, str | None]], tuple[bytes, bytes, bytes, bytes]]:
    """The signatures of spec/keys.md, section 7.6: (label, key, message, signature, why the strict rule
    rejects it or None), for the message msg signed as sig with seed; and the crafted points."""
    pub = public_key(seed)
    a_scalar = expand(seed)[0]
    identity = compress(IDENTITY)  # 01 00 ... 00
    identity_nc = (P + 1).to_bytes(32, "little")  # y = 1 + p: the identity, non-canonical
    s_value = int.from_bytes(sig[32:], "little")
    torsion8 = cast(
        Point, decompress(bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"))
    )
    assert not point_equal(point_mul(4, torsion8), IDENTITY) and small_order(torsion8)

    def crafted_r(r_bytes: bytes) -> bytes:
        k = hash_mod_l(r_bytes + pub + msg)
        return r_bytes + (k * a_scalar % L).to_bytes(32, "little")

    # R with a component of order 8: R = [r]B + T, S = r + k*a.
    r_nonce = hash_mod_l(b"AXT example: R with a component of order 8")
    mixed_r = compress(point_add(point_mul(r_nonce, BASE), torsion8))
    mixed_r_sig = mixed_r + ((r_nonce + hash_mod_l(mixed_r + pub + msg) * a_scalar) % L).to_bytes(
        32, "little"
    )
    # The key with a component of order 8: A = [a]B + T, R = [r]B, S = r + k*a, with k not a multiple of 8.
    mixed_key = compress(point_add(point_mul(a_scalar, BASE), torsion8))
    i = 0
    while True:
        r_nonce = hash_mod_l(b"AXT example: key with a component of order 8 %d" % i)
        big_r = compress(point_mul(r_nonce, BASE))
        k = hash_mod_l(big_r + mixed_key + msg)
        if k % 8:
            break
        i += 1
    mixed_key_sig = big_r + ((r_nonce + k * a_scalar) % L).to_bytes(32, "little")

    cases: list[tuple[str, bytes, bytes, bytes, str | None]] = [
        ("the signature of example 1", pub, msg, sig, None),
        (
            "one byte of the message changed",
            pub,
            msg[:-1] + bytes([msg[-1] ^ 1]),
            sig,
            "equation does not hold",
        ),
        ("another key", other_key, msg, sig, "equation does not hold"),
        ("S + L in place of S", pub, msg, sig[:32] + (s_value + L).to_bytes(32, "little"), "S not below L"),
        ("R of small order (the identity), S = k*a", pub, msg, crafted_r(identity), "R not of order L"),
        ("R with a component of order 8", pub, msg, mixed_r_sig, "R not of order L"),
        (
            "R the identity, non-canonical, S = k*a",
            pub,
            msg,
            crafted_r(identity_nc),
            "R not a canonical encoding of a point",
        ),
        (
            "key the identity, R the identity, S = 0",
            identity,
            msg,
            identity + bytes(32),
            "key not of order L",
        ),
        ("key with a component of order 8", mixed_key, msg, mixed_key_sig, "key not of order L"),
        (
            "key the identity, non-canonical, R the identity, S = 0",
            identity_nc,
            msg,
            identity + bytes(32),
            "key not a canonical encoding of a point",
        ),
    ]
    return cases, (identity, identity_nc, mixed_r, mixed_key)


# --- output -------------------------------------------------------------------


def dump(parts: list[tuple[bytes, str]]) -> str:
    """Annotated hex in the layout of spec/envelope.md."""
    offset, lines = 0, []
    for data, meaning in parts:
        for i in range(0, len(data), 8):
            hexs = data[i : i + 8].hex(" ")
            lines.append(f"{offset:04x}  {hexs:<23}  {meaning}".rstrip() if i == 0 else f"      {hexs}")
        offset += len(data)
    lines.append(f"{offset:04x}  end")
    return "\n".join(lines)


def hex_lines(data: bytes, indent: str = "      ") -> str:
    return "\n".join(indent + data[i : i + 16].hex(" ") for i in range(0, len(data), 16))


def main() -> None:
    import calendar
    import importlib.util
    import io
    import json
    import uuid

    import avro.datafile
    import avro.io
    import avro.schema
    import fastavro
    import nacl
    import nacl.bindings
    import nacl.exceptions
    import nacl.signing
    from cryptography.exceptions import InvalidSignature, InvalidTag
    from cryptography.hazmat.backends.openssl.backend import backend as openssl
    from cryptography.hazmat.primitives import hpke
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives.asymmetric import x25519 as cx25519
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from fastavro.schema import fingerprint as fa_fingerprint
    from fastavro.schema import to_parsing_canonical_form

    spec = importlib.util.spec_from_file_location("example_types", HERE / "example_types.py")
    if spec is None or spec.loader is None:
        raise ImportError("example_types.py cannot be loaded")
    rules = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rules)

    # --- the published test vectors ------------------------------------------

    # RFC 8032, section 7.1, TEST 1.
    rfc_seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    rfc_pub = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    rfc_sig = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    assert public_key(rfc_seed) == rfc_pub and sign(rfc_seed, b"") == rfc_sig
    assert verify_problem(rfc_pub, b"", rfc_sig) is None

    # RFC 7748, section 5.2, the first X25519 vector.
    assert x25519(
        bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
        bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
    ) == bytes.fromhex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")

    # RFC 9180, appendix A.2.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305, mode_base.
    a21 = {
        k: bytes.fromhex(v)
        for k, v in {
            "info": "4f6465206f6e2061204772656369616e2055726e",
            "ikmE": "909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b",
            "pkEm": "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
            "skEm": "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600",
            "ikmR": "1ac01f181fdf9f352797655161c58b75c656a6cc2716dcb66372da835542e1df",
            "pkRm": "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a",
            "skRm": "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb",
            "shared_secret": "0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7",
            "key_schedule_context": "00431df6cd95e11ff49d7013563baf7f11588c75a6611ee2a4404a49306ae4cfc5"
            "b69c5718a60cc5876c358d3f7fc31ddb598503f67be58ea1e798c0bb19eb9796",
            "secret": "5b9cd775e64b437a2335cf499361b2e0d5e444d5cb41a8a53336d8fe402282c6",
            "key": "ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91",
            "base_nonce": "5c4d98150661b848853b547f",
            "exporter_secret": "a3b010d4994890e2c6968a36f64470d3c824c8f5029942feb11e7a74b2921922",
            "pt": "4265617574792069732074727574682c20747275746820626561757479",
            "aad": "436f756e742d30",
            "ct": "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db"
            "21993c62ce81883d2dd1b51a28",
        }.items()
    }
    assert derive_key_pair(a21["ikmE"]) == (a21["skEm"], a21["pkEm"])
    assert derive_key_pair(a21["ikmR"]) == (a21["skRm"], a21["pkRm"])
    enc, shared = encap(a21["skEm"], a21["pkRm"])
    assert enc == a21["pkEm"] and shared == a21["shared_secret"] and decap(enc, a21["skRm"]) == shared
    ctx = hpke_base_context(shared, a21["info"])
    for name in ("key_schedule_context", "secret", "key", "base_nonce", "exporter_secret"):
        assert ctx[name] == a21[name], name
    assert ChaCha20Poly1305(ctx["key"]).encrypt(ctx["base_nonce"], a21["pt"], a21["aad"]) == a21["ct"]

    # --- the test keys --------------------------------------------------------

    def test_secret(label: str) -> bytes:
        return hashlib.sha256(b"AXT test key, not for use: " + label.encode()).digest()

    keys = {}
    for label in ("cat-a-log, old phone", "cat-a-log, new phone", "Old Brain Fix"):
        seed = test_secret(label + ", Ed25519")
        pub = public_key(seed)
        assert pub == bytes(nacl.signing.SigningKey(seed).verify_key)
        assert pub == ed25519.Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
        assert key_problem(pub) is None
        keys[label] = {"seed": seed, "pub": pub}
        if label == "cat-a-log, new phone":
            continue  # no example uses an encryption key of the new phone
        xsk = test_secret(label + ", X25519")
        xpk = x25519(xsk, X25519_BASE)
        assert xpk == nacl.bindings.crypto_scalarmult_base(xsk)
        assert xpk == cx25519.X25519PrivateKey.from_private_bytes(xsk).public_key().public_bytes_raw()
        assert encryption_key_problem(xpk) is None
        keys[label] |= {"xsk": xsk, "xpk": xpk}
    old, new, obf = keys["cat-a-log, old phone"], keys["cat-a-log, new phone"], keys["Old Brain Fix"]
    ikm_e = test_secret("ephemeral key of the sealed message, ikmE")
    sk_e, pk_e = derive_key_pair(ikm_e)

    def all_sign(seed: bytes, data: bytes) -> bytes:
        """The signature, the same from this file, PyNaCl and cryptography."""
        sig = sign(seed, data)
        assert sig == nacl.signing.SigningKey(seed).sign(data).signature
        assert sig == ed25519.Ed25519PrivateKey.from_private_bytes(seed).sign(data)
        return sig

    def all_verify(pub: bytes, data: bytes, sig: bytes) -> None:
        assert verify_problem(pub, data, sig) is None
        nacl.signing.VerifyKey(pub).verify(data, sig)
        ed25519.Ed25519PublicKey.from_public_bytes(pub).verify(sig, data)

    # --- schemas --------------------------------------------------------------

    def fingerprint(text: str) -> tuple[str, int]:
        pcf = to_parsing_canonical_form(fastavro.parse_schema(json.loads(text)))
        assert avro.schema.parse(pcf).canonical_form == pcf
        fp = rules.crc64_avro(pcf.encode())
        assert fa_fingerprint(pcf, "CRC-64-AVRO") == fp.to_bytes(8, "little").hex()
        assert rules.apache_fingerprint(text) == fp.to_bytes(8, "little")
        return pcf, fp

    envelope_text = (REPO / "types" / "axt" / "Envelope.avsc").read_text(encoding="utf-8")
    manifest_text = (REPO / "types" / "axt" / "Manifest.avsc").read_text(encoding="utf-8")
    envelope_pcf, envelope_fp = fingerprint(envelope_text)
    assert envelope_fp == 0xA89ECEB9716F3016, "the envelope fingerprint is not the one of spec/envelope.md"
    envelope_schema = cast(dict[str, Any], fastavro.parse_schema(json.loads(envelope_text)))
    kinds = envelope_schema["fields"][1]["type"]["symbols"]

    def named_types(t: Any, out: list[str]) -> list[str]:
        """Full names of the named types a schema defines, in the namespace axt."""
        if isinstance(t, list):
            for b in t:
                named_types(b, out)
        elif isinstance(t, dict):
            if t["type"] in {"record", "enum", "fixed"}:
                out.append("axt." + t["name"])
            for f in t.get("fields", []):
                named_types(f["type"], out)
            for key in ("items", "values"):
                if key in t:
                    named_types(t[key], out)
        return out

    # The schemas of the device messages, under the rules of spec/types.md, section 5, for a schema of
    # the specification.
    device_names = ("DeviceJoin", "DeviceAdd", "DeviceRemove")
    device_texts = {
        name: (REPO / "types" / "axt" / f"{name}.avsc").read_text(encoding="utf-8") for name in device_names
    }
    device_fps = {name: fingerprint(text) for name, text in device_texts.items()}
    others = named_types(json.loads(envelope_text), []) + named_types(json.loads(manifest_text), [])
    for name in device_names:
        device_json = json.loads(device_texts[name])
        assert device_json["name"] == name and device_json["namespace"] == "axt"
        assert "axt.version" not in device_json
        assert (
            len(device_texts[name].encode()) <= rules.MAX_SCHEMA_BYTES
            and rules.json_depth(device_json) <= rules.MAX_JSON_DEPTH
        )
        defined: list[str] = []
        rules.check_type(device_json, f"types/axt/{name}.avsc", device_json, set(), defined)
        assert len(set(defined)) == len(defined), f"a name is defined twice in {name}.avsc"
        assert all(d == "axt." + name or d.startswith("axt." + name) for d in defined), defined
        assert not set(defined) & set(others), (
            f"a name of {name}.avsc is defined in another schema of the specification"
        )
        others += defined
    device_problems = [f for f in rules.failures if "Device" in f]
    assert not device_problems, device_problems
    add_schema = fastavro.parse_schema(json.loads(device_texts["DeviceAdd"]))
    add_fp = device_fps["DeviceAdd"][1]

    def library_binary(schema: Any, datum: Any) -> bytes:
        buf = io.BytesIO()
        fastavro.schemaless_writer(buf, schema, datum)
        return buf.getvalue()

    def header(fp: int) -> bytes:
        return b"\xc3\x01" + fp.to_bytes(8, "little")

    # --- example 1: a signed DATA message -------------------------------------

    # The Memo defines axt.DateTime in place, as its published schema (spec/time.md, section 3.1).
    date_time_schema = json.loads((REPO / "types" / "axt" / "DateTime.avsc").read_text(encoding="utf-8"))
    memo_schema = {
        "type": "record",
        "name": "Memo",
        "namespace": "com.example",
        "doc": "An illustration for spec/envelope.md; not an AXT example type.",
        "fields": [
            {"name": "text", "type": "string", "doc": "The memo's text."},
            {
                "name": "written",
                "type": date_time_schema,
                "doc": "When the memo was written.",
                "axt.anchor": "instant",
            },
        ],
    }
    memo_fp = fingerprint(json.dumps(memo_schema))[1]
    record_id = "0b5a3c1e-4d2f-4a6b-9c8d-7e6f5a4b3c2d"
    text = "Vet, Tuesday 10:00"
    # written: 2025-11-15 11:00 in Europe/Berlin, the offset 3600 and the instant 2025-11-15T10:00:00Z.
    zone = b"Europe/Berlin"
    written = (
        b"".join(zigzag(n) for n in (2025, 11, 15, 11, 0, 0, 0))
        + zigzag(1)
        + zigzag(len(zone))
        + zone
        + zigzag(1)
        + zigzag(3600)
        + zigzag(1)
        + zigzag(1763200800000)
    )
    body = header(memo_fp) + zigzag(len(text)) + text.encode() + written
    assert len(body) < 64, (
        "the body length takes one byte, as the offsets of spec/keys.md, section 7.3, assume"
    )
    data_parts = [
        (header(envelope_fp)[:2], "single-object marker"),
        (header(envelope_fp)[2:], "fingerprint of axt.Envelope, format 1"),
        (zigzag(1), "format: int 1"),
        (zigzag(kinds.index("DATA")), "kind: enum index 4, DATA"),
        (old["pub"], "sender: fixed(32), cat-a-log's test key"),
        (zigzag(1), "record: union index 1, axt.RecordRef"),
        (zigzag(36), "record.id: string length 36"),
        (record_id.encode(), f'"{record_id}"'),
        (zigzag(1), "record.version: long 1"),
        (zigzag(len(body)), f"body: bytes length {len(body)}"),
        (body, "body: the Memo, as in spec/envelope.md, section 10.2"),
    ]
    unsigned = b"".join(p[0] for p in data_parts)
    data_signed = MESSAGE_PREFIX + unsigned[10:]
    data_sig = all_sign(old["seed"], data_signed)
    data_parts.append((data_sig, "signature: fixed(64)"))
    data_message = unsigned + data_sig
    all_verify(old["pub"], MESSAGE_PREFIX + data_message[10:-64], data_message[-64:])
    datum = {
        "format": 1,
        "kind": "DATA",
        "sender": old["pub"],
        "record": {"id": record_id, "version": 1},
        "body": body,
        "signature": data_sig,
    }
    assert data_message[10:] == library_binary(envelope_schema, datum)
    back = cast(
        dict[str, Any],
        fastavro.schemaless_reader(io.BytesIO(data_message[10:]), envelope_schema, envelope_schema),
    )
    assert (
        back["sender"] == old["pub"]
        and back["signature"] == data_sig
        and str(back["record"]["id"]) == record_id
    )
    memo_value = {
        "text": text,
        "written": {
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
        },
    }
    assert body[10:] == library_binary(fastavro.parse_schema(memo_schema), memo_value), (
        "the Memo differs from fastavro's encoding"
    )
    assert 1763200800000 == calendar.timegm((2025, 11, 15, 11, 0, 0)) * 1000 - 3600 * 1000, (
        "instant is not wall clock minus offset"
    )

    # The same record with its id in upper case is another message: the signature covers the bytes.
    upper = data_message.replace(record_id.encode(), record_id.upper().encode())
    assert verify_problem(old["pub"], MESSAGE_PREFIX + upper[10:-64], upper[-64:]) == "equation does not hold"
    assert uuid.UUID(record_id) == uuid.UUID(record_id.upper())

    # --- example 2: the message in a file -------------------------------------

    schemas_value = json.dumps([memo_schema], separators=(",", ":")).encode()
    header_signed = FILE_HEADER_PREFIX + old["pub"] + hashlib.sha256(schemas_value).digest()
    header_sig = all_sign(old["seed"], header_signed)
    file_buf = io.BytesIO()
    fastavro.writer(
        file_buf,
        json.loads(envelope_text),  # as read, not parsed: see envelope_examples.py
        [datum],
        codec="null",
        metadata={
            "axt.schemas": schemas_value.decode(),
            "axt.sender": old["pub"].hex(),
            "axt.signature": header_sig.hex(),
        },
        sync_marker=bytes(range(16)),
    )
    axt_file = file_buf.getvalue()
    meta, datums = file_datums(axt_file)
    sender = bytes.fromhex(meta["axt.sender"].decode("ascii"))
    all_verify(
        sender,
        FILE_HEADER_PREFIX + sender + hashlib.sha256(meta["axt.schemas"]).digest(),
        bytes.fromhex(meta["axt.signature"].decode("ascii")),
    )
    assert len(datums) == 1 and datums[0] == data_message[10:]
    for d in datums:
        assert d[2:34] == sender  # format and kind take one byte each here
        all_verify(sender, MESSAGE_PREFIX + d[:-64], d[-64:])
    assert to_parsing_canonical_form(fastavro.parse_schema(json.loads(meta["avro.schema"]))) == envelope_pcf
    file_buf.seek(0)
    fa_reader = fastavro.reader(file_buf)
    assert fa_reader.metadata["axt.sender"] == old["pub"].hex() and [
        cast(dict[str, Any], r)["body"] for r in fa_reader
    ] == [body]
    apache_reader = avro.datafile.DataFileReader(io.BytesIO(axt_file), avro.io.DatumReader())
    assert apache_reader.get_meta("axt.signature") == header_sig.hex().encode()
    assert [cast(dict[str, Any], r)["signature"] for r in apache_reader] == [data_sig]

    # --- example 3: the DATA message sealed for the relay ---------------------

    padded = pad(data_message)
    assert len(padded) == MIN_PADDED and unpad(padded) == data_message
    enc, shared = encap(sk_e, obf["xpk"])
    assert enc == pk_e
    ctx = hpke_base_context(shared, HPKE_INFO)
    ciphertext = ChaCha20Poly1305(ctx["key"]).encrypt(ctx["base_nonce"], padded, b"")
    sealed = SEALED_FORMAT + enc + ciphertext
    assert len(sealed) == 1 + 32 + MIN_PADDED + 16
    # Cross-checks: libsodium's ChaCha20-Poly1305 (IETF) and the HPKE of the cryptography package.
    assert (
        nacl.bindings.crypto_aead_chacha20poly1305_ietf_encrypt(padded, b"", ctx["base_nonce"], ctx["key"])
        == ciphertext
    )
    assert nacl.bindings.crypto_scalarmult(obf["xsk"], enc) == x25519(sk_e, obf["xpk"])
    suite = hpke.Suite(hpke.KEM.X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.CHACHA20_POLY1305)
    obf_private = cx25519.X25519PrivateKey.from_private_bytes(obf["xsk"])
    opened = suite.decrypt(sealed[1:], obf_private, info=HPKE_INFO)
    assert unpad(opened) == data_message
    all_verify(old["pub"], MESSAGE_PREFIX + unpad(opened)[10:-64], unpad(opened)[-64:])
    # Another info, or one changed byte, does not open.
    bad_openings: tuple[Callable[[], object], ...] = (
        lambda: suite.decrypt(sealed[1:], obf_private, info=b"AXT-v1 other"),
        lambda: suite.decrypt(sealed[1:-1] + bytes([sealed[-1] ^ 1]), obf_private, info=HPKE_INFO),
    )
    for bad in bad_openings:
        try:
            bad()
            raise AssertionError("a changed sealed message opened")
        except InvalidTag:
            pass
    # A sealed message to a small-order key cannot be made.
    try:
        encap(sk_e, bytes(32))
        raise AssertionError("encap to a small-order key")
    except ValueError:
        pass
    assert encryption_key_problem(bytes(32)) and encryption_key_problem((1).to_bytes(32, "little"))
    # Padding: the sizes of section 4.4.
    sizes = [(n, padded_length(n)) for n in (len(data_message), 1023, 1024, 4000, 100000, 16777216)]
    assert all(padded_length(n) > n for n, _ in sizes)
    # Above the minimum, Padme adds less than 1/16 of the length (spec/keys.md, section 4.4).
    assert all(16 * (padme(x) - x) < x for x in range(MIN_PADDED + 1, 1 << 17))
    assert all(16 * (padme(x) - x) < x for x in (n + 1 for n, _ in sizes) if x > MIN_PADDED)
    max_sealed = 1 + 32 + padded_length(16777216) + 16
    for broken in (b"\x80\x01", b"abc", b"abc\x00\x00"):
        try:
            unpad(broken)
            raise AssertionError("bad padding accepted")
        except ValueError:
            pass

    # --- example 4: a DEVICE_ADD ----------------------------------------------

    proof_signed = proof_bytes(old["pub"], new["pub"])
    assert len(DEVICE_ADD_PREFIX) == 18
    proof = all_sign(new["seed"], proof_signed)
    add_body_parts = [
        (header(add_fp)[:2], "body: single-object marker"),
        (header(add_fp)[2:], "body: fingerprint of axt.DeviceAdd, format 1"),
        (new["pub"], "body: device: fixed(32), the new phone's test key"),
        (proof, "body: proof: fixed(64), signed with the new phone's key"),
    ]
    add_body = b"".join(p[0] for p in add_body_parts)
    add_datum = {"device": new["pub"], "proof": proof}
    assert add_body[10:] == library_binary(add_schema, add_datum)
    assert fastavro.schemaless_reader(io.BytesIO(add_body[10:]), add_schema, add_schema) == add_datum
    apache_add = avro.io.DatumReader(avro.schema.parse(device_texts["DeviceAdd"])).read(
        avro.io.BinaryDecoder(io.BytesIO(add_body[10:]))
    )
    assert apache_add == add_datum
    add_parts = [
        (header(envelope_fp)[:2], "single-object marker"),
        (header(envelope_fp)[2:], "fingerprint of axt.Envelope, format 1"),
        (zigzag(1), "format: int 1"),
        (zigzag(kinds.index(ADD)), f"kind: enum index {kinds.index(ADD)}, {ADD}"),
        (old["pub"], "sender: fixed(32), the old phone's test key"),
        (zigzag(0), "record: union index 0, null"),
        (zigzag(len(add_body)), f"body: bytes length {len(add_body)}"),
    ] + add_body_parts
    add_unsigned = b"".join(p[0] for p in add_parts)
    add_sig = all_sign(old["seed"], MESSAGE_PREFIX + add_unsigned[10:])
    add_parts.append((add_sig, "signature: fixed(64), signed with the old phone's key"))
    add_message = add_unsigned + add_sig
    add_env = {
        "format": 1,
        "kind": ADD,
        "sender": old["pub"],
        "record": None,
        "body": add_body,
        "signature": add_sig,
    }
    assert add_message[10:] == library_binary(envelope_schema, add_env)
    all_verify(old["pub"], MESSAGE_PREFIX + add_message[10:-64], add_message[-64:])
    all_verify(new["pub"], proof_signed, proof)
    assert (
        device_message_problem(
            ADD, old["pub"], MESSAGE_PREFIX + add_message[10:-64], add_sig, new["pub"], proof
        )
        is None
    )
    # The proof does not verify for another member: it names the key that adds the device.
    assert verify_problem(new["pub"], proof_bytes(obf["pub"], new["pub"]), proof) == "equation does not hold"
    assert (
        device_message_problem(
            ADD, obf["pub"], MESSAGE_PREFIX + add_message[10:-64], add_sig, new["pub"], proof
        )
        == SIGNATURE_INVALID
    )
    # A receiver that knows cat-a-log by the old phone's key applies the addition (section 7.5).
    cat_a_log = KnownSender("cat-a-log", [old["pub"]])
    receiver = DeviceReceiver([cat_a_log])
    assert receiver.chain([(ADD, old["pub"], new["pub"], None)]) == [APPLIED]
    assert cat_a_log.current == [old["pub"], new["pub"]] and receiver.key_state(new["pub"]) == (
        "current",
        "cat-a-log",
    )
    device_cases = check_device_cases()
    # The join that led to the addition (section 5.2): the old phone asks its user, and the new phone
    # takes the chain that ends with its addition.
    assert join_action(old["pub"], [], [], old["pub"], new["pub"], proof) == "ask"
    assert join_action(old["pub"], [new["pub"]], [], old["pub"], new["pub"], proof) == "send_chain"
    assert join_action(old["pub"], [], [new["pub"]], old["pub"], new["pub"], proof) == REJECTED
    assert join_action(obf["pub"], [], [], old["pub"], new["pub"], proof) == "ignore"
    assert join_action(obf["pub"], [], [], obf["pub"], new["pub"], proof) == REJECTED
    assert join_chain_problem([(ADD, old["pub"], new["pub"], proof, True)], old["pub"], new["pub"]) is None
    assert join_chain_problem([(ADD, old["pub"], new["pub"], proof, True)], obf["pub"], new["pub"])
    assert join_chain_problem([], old["pub"], new["pub"])
    assert join_action(old["pub"], [], [], old["pub"], new["pub"], proof, first=new["pub"]) == "ask"
    assert join_action(old["pub"], [], [], old["pub"], new["pub"], proof, first=obf["pub"]) == "ignore"
    # A removal of the old phone by itself fails step 2, whoever signed the addition before.
    assert device_message_problem(REMOVE, old["pub"], data_signed, data_sig, old["pub"], None) == REJECTED

    # --- domain separation ----------------------------------------------------

    prefixes = [MESSAGE_PREFIX, FILE_HEADER_PREFIX, DEVICE_ADD_PREFIX, FINGERPRINT_PREFIX]
    for a in prefixes:
        assert a.count(b"\x00") == 1 and a.endswith(b"\x00")
        assert not any(b != a and b.startswith(a) for b in prefixes)
    # A message signature is no header signature and no proof.
    assert (
        verify_problem(old["pub"], FILE_HEADER_PREFIX + unsigned[10:], data_sig) == "equation does not hold"
    )

    # --- the edges of verification --------------------------------------------

    small = small_order_points()
    assert len(set(small)) == 8 and all(key_problem(e) == "key not of order L" for e in small)
    cases, (identity, identity_nc, mixed_r, mixed_key) = edge_cases(
        old["seed"], obf["pub"], data_signed, data_sig
    )
    edge_rows = []
    for label, key, message, sig, expected in cases:
        got = verify_problem(key, message, sig)
        assert got == expected, (label, got)
        try:
            nacl.signing.VerifyKey(key).verify(message, sig)
            sodium = "accepts"
        except (nacl.exceptions.BadSignatureError, nacl.exceptions.ValueError, ValueError):
            sodium = "rejects"
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(key).verify(sig, message)
            ossl = "accepts"
        except (InvalidSignature, ValueError):
            ossl = "rejects"
        plain = "accepts" if verify_plain(key, message, sig) else "rejects"
        cofactored = "accepts" if verify_plain(key, message, sig, cofactor=8) else "rejects"
        edge_rows.append(
            (label, "rejects: " + expected if expected else "accepts", plain, cofactored, sodium, ossl)
        )
    # Steps 2 and 3 for one point are what libsodium's crypto_core_ed25519_is_valid_point checks.
    for point in [
        old["pub"],
        new["pub"],
        obf["pub"],
        mixed_r,
        mixed_key,
        identity,
        identity_nc,
        data_sig[:32],
    ] + small:
        assert nacl.bindings.crypto_core_ed25519_is_valid_point(point) == (key_problem(point) is None), (
            point.hex()
        )

    # --- output ---------------------------------------------------------------

    print("== Test keys (never use outside tests) ==")
    for label, k in keys.items():
        print(f"{label}:")
        print(f"  Ed25519 seed        {k['seed'].hex()}")
        print(f"  Ed25519 public key  {k['pub'].hex()}")
        print(f"  short fingerprint   {short_fingerprint(k['pub'])}")
        if "xsk" in k:
            print(f"  X25519 private key  {k['xsk'].hex()}")
            print(f"  X25519 public key   {k['xpk'].hex()}")
    print(f"ephemeral ikmE        {ikm_e.hex()}")
    print(f"ephemeral skE         {sk_e.hex()}")
    print(f"ephemeral pkE (enc)   {pk_e.hex()}")
    print()
    for name, (pcf, fp) in device_fps.items():
        print(f"axt.{name} canonical form: {pcf}")
        print(f"axt.{name} CRC-64-AVRO: 0x{fp:016x}, bytes {fp.to_bytes(8, 'little').hex(' ')}")
    print()
    print(
        f"== Example 1: DATA message, {len(data_message)} bytes, "
        f"SHA-256 {hashlib.sha256(data_message).hexdigest()} =="
    )
    print(dump(data_parts))
    print(
        f"signed bytes: {len(data_signed)} bytes, the prefix and bytes 000a to {len(data_message) - 65:04x}"
    )
    print(hex_lines(data_signed))
    print()
    print(f"== Example 2: file, {len(axt_file)} bytes, SHA-256 {hashlib.sha256(axt_file).hexdigest()} ==")
    print(f"axt.schemas SHA-256: {hashlib.sha256(schemas_value).hexdigest()}")
    print(f"axt.sender:    {old['pub'].hex()}")
    print(f"axt.signature: {header_sig.hex()}")
    print(f"header signed bytes ({len(header_signed)}):")
    print(hex_lines(header_signed))
    print("metadata keys in the file's order: " + ", ".join(meta))
    print()
    print(
        f"== Example 3: sealed message, {len(sealed)} bytes, SHA-256 {hashlib.sha256(sealed).hexdigest()} =="
    )
    print(f"shared_secret         {shared.hex()}")
    for name in ("key_schedule_context", "secret", "key", "base_nonce"):
        print(f"{name:<21} {ctx[name].hex()}")
    print(
        f"plaintext: the message of example 1, 80, then {len(padded) - len(data_message) - 1} zero bytes: "
        f"{len(padded)} bytes"
    )
    print(f"sealed: format {sealed[:1].hex()}, enc {len(enc)} bytes, ciphertext {len(ciphertext)} bytes")
    print(hex_lines(sealed))
    print("padded lengths: " + ", ".join(f"{n} -> {m}" for n, m in sizes))
    print(f"largest sealed message: {max_sealed} bytes")
    print()
    print(
        f"== Example 4: DEVICE_ADD message, {len(add_message)} bytes, "
        f"SHA-256 {hashlib.sha256(add_message).hexdigest()} =="
    )
    print(dump(add_parts))
    print(f"proof signed bytes ({len(proof_signed)}):")
    print(hex_lines(proof_signed))
    print()
    print(
        f"== Edges of verification: libsodium of PyNaCl {nacl.__version__}, "
        f"{openssl.openssl_version_text()} =="
    )
    print(
        "case | AXT, strict | RFC 8032 without step 3, cofactorless | the same with cofactor | "
        "libsodium | OpenSSL"
    )
    for row in edge_rows:
        print(" | ".join(row))
    print()
    print(f"device sets: {device_cases} cases of section 5.5 hold in the model")
    print()
    print("== The canonical encodings of the eight points of small order ==")
    for e in small:
        print(e.hex())
    if rules.failures:
        raise SystemExit("\n".join(["checks failed:"] + rules.failures))
    print("all checks passed")


if __name__ == "__main__":
    main()
