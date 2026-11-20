# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Produce and check the examples of spec/sync.md.

The examples of sections 2 to 6 of spec/sync.md are numbers: stamps, states of a record
and what a merge makes of them. Those of sections 15 and 16 are the schemas and the bytes
of the CHANGE and RESYNC messages between the devices of a set. This script:

- implements the rules of spec/sync.md from its normative sections: the next stamp and
  where there is none (sections 2.2 and 2.3), what an installation does when it begins
  to stamp (section 2.4), what a change stamps (section 3.5), the merge of two states
  per field and for the removal with its ties by device key, by value and by whether a
  removal stands (sections 4.1 and 4.2), when a record counts as deleted (section 4.3),
  what the merging device does to its clock and its state stamp (section 4.4), the
  record message a state gives toward other apps (section 5.1), and what a device does
  after STALE (section 5.3);
- holds the cases of section 6 as tables, with the numbers written out as the document
  shows them, plays each case with the rules and asserts every number;
- holds further cases, for the limits and the ties, with results written out from the
  rules, which conformance/tools/generate_vectors.py turns into the vectors of the
  category sync;
- encodes the values of the field states in Avro binary encoding with fastavro and with
  the Apache avro package, which give the same bytes;
- implements the next stamp, the order of device keys and of values, and the merge a
  second time, in another way, and checks over many generated cases, which a counter
  and SHA-256 make the same in every run, that both ways agree and that the merge of
  field states and removals is commutative, associative and idempotent (section 4.5);
- checks the Parsing Canonical Forms and the fingerprints of types/axt/Change.avsc and
  Resync.avsc with fastavro and the Apache avro package (section 15), and builds the
  messages of section 16 field by field: each is compared with fastavro's encoding, read
  back with the avro package, and signed and verified with the pure-Python Ed25519 of
  keys_examples.py, PyNaCl and cryptography, which give the same signature;
- holds a model of one device of a set with its siblings (sections 7 to 13): the steps
  in which it processes a CHANGE, the outcome, what it keeps for each sibling, what it
  sends to which sibling, whole or in part and under which state stamp, offers,
  acknowledgements, errors, RESYNC, a restored, a removed and a new device, and a file of
  its own set; it plays the examples of section 16 and the sessions of `sessions` through
  the model and checks every step against what `SAID` writes out for it. The generator
  turns the sessions into the vectors of the operation `siblings`.

The device keys are TEST KEYS, derived as spec/keys.md, section 7.1, says, from the
labels "cat-a-log, phone, Ed25519" and "cat-a-log, tablet, Ed25519", and for the sessions
from further labels in the same way. The keys of the cases about the order of keys are
byte strings chosen for the comparison, not keys.

Run from anywhere, with fastavro, avro (1.12), pynacl and cryptography installed, and a
time zone database where Python's zoneinfo finds it:

    python3 conformance/tools/sync_examples.py

conformance/tools/generate_vectors.py and conformance/reference/adapter.py import this
file; importing it runs none of its checks.
"""

import contextlib
import copy
import dataclasses
import datetime
import hashlib
import importlib.util
import io
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import avro.io
import avro.schema
import fastavro
import nacl.signing
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastavro.schema import fingerprint as fa_fingerprint
from fastavro.schema import to_parsing_canonical_form

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]

_spec = importlib.util.spec_from_file_location("keys_examples", HERE / "keys_examples.py")
if _spec is None or _spec.loader is None:
    raise ImportError("keys_examples.py cannot be loaded")
keys = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(keys)  # runs none of that script's checks
# The validity of the time types, which a device checks in a CHANGE (section 8.3, step 12), and with it
# the field path of an error (spec/metadata.md, section 7.2).
_spec = importlib.util.spec_from_file_location("time_examples", HERE / "time_examples.py")
if _spec is None or _spec.loader is None:
    raise ImportError("time_examples.py cannot be loaded")
tm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tm)  # runs its checks and prints nothing
mr = tm.mr
# The validity of a manifest (spec/manifest.md, section 4), which a device checks in a MANIFEST that
# another device of its set passes on (section 13.2).
_spec = importlib.util.spec_from_file_location("manifest_examples", HERE / "manifest_examples.py")
if _spec is None or _spec.loader is None:
    raise ImportError("manifest_examples.py cannot be loaded")
me = importlib.util.module_from_spec(_spec)
with contextlib.redirect_stdout(io.StringIO()):
    _spec.loader.exec_module(me)  # runs its checks

MAX = 2**63 - 1  # the largest long (section 2.3)
MIN = -(2**63)
R_MAX = 32767  # the largest random part (section 2.2)
LAST_BASE = MAX - R_MAX  # 2^63 - 32,768, the last base from which a stamp can be taken
LAST_CHANGE_BASE = MAX - 65535  # the last base at which a change can begin (section 2.3)


def test_secret(label: str) -> bytes:
    return hashlib.sha256(b"AXT test key, not for use: " + label.encode()).digest()


PHONE = bytes(keys.public_key(test_secret("cat-a-log, phone, Ed25519")))
TABLET = bytes(keys.public_key(test_secret("cat-a-log, tablet, Ed25519")))

# --- stamps (section 2) --------------------------------------------------------------------


def next_stamp(now_ms: int, highest: int, r: int) -> int | None:
    """The next stamp of section 2.2, or None where there is no stamp. Python's integers do not wrap."""
    assert MIN <= now_ms <= MAX and 0 <= highest <= MAX and 0 <= r <= R_MAX, "outside the ranges of 2.2"
    base = max(now_ms * 65536, highest + 1)
    return base + r if base + 32767 <= MAX else None


def next_stamp_by_cases(now_ms: int, highest: int, r: int) -> int | None:
    """The same in the words of sections 2.1 and 2.3: the clock leads or the device counts, and a
    device can take a stamp while the base is at most 2^63 - 32,768. Written without a number above
    the largest long."""
    if now_ms > highest >> 16:  # floor(highest / 65536) < now_ms, that is now_ms * 65536 > highest
        if now_ms >= 1 << 47:  # the product alone is above the largest long
            return None
        base = now_ms << 16  # the clock leads
    elif highest == MAX:
        return None
    else:
        base = highest + 1  # the device counts
    return base + r if base <= LAST_BASE else None


def can_begin_change(now_ms: int, highest: int) -> bool:
    """Whether a device may begin a change, which takes two stamps (section 2.3)."""
    return max(now_ms * 65536, highest + 1) + 65535 <= MAX


# --- values (section 4.1, rule 3) ---------------------------------------------------------------

_AVRO = {name: avro.schema.parse(f'"{name}"') for name in ("string", "long")}


def encoded(value: str | int) -> bytes:
    """A text as an Avro string and a number as an Avro long, in Avro binary encoding: the bytes by
    which rule 3 of section 4.1 compares two values. fastavro and avro give the same bytes."""
    name = "string" if isinstance(value, str) else "long"
    out = io.BytesIO()
    fastavro.schemaless_writer(out, name, value)
    other = io.BytesIO()
    avro.io.DatumWriter(_AVRO[name]).write(value, avro.io.BinaryEncoder(other))
    assert out.getvalue() == other.getvalue(), value
    return out.getvalue()


def text_of(data: bytes) -> str:
    """The text of an Avro string, for the tables this script prints."""
    value = fastavro.schemaless_reader(io.BytesIO(data), "string", "string")
    assert isinstance(value, str) and encoded(value) == data
    return value


def bytes_order(a: bytes, b: bytes) -> int:
    """1 if a is higher than b as unsigned bytes from the first byte on, -1 if lower, 0 if equal; bytes
    that are the beginning of the others are the lower ones (section 4.1, rules 2 and 3)."""
    for x, y in zip(a, b, strict=False):
        if x != y:
            return 1 if x > y else -1
    return (len(a) > len(b)) - (len(a) < len(b))


# --- writer schemas (section 3.1) -----------------------------------------------------------------


def schema_fingerprint(text: str) -> bytes:
    """The fingerprint of a schema as its 8 bytes in little-endian order (spec/envelope.md, section 5)."""
    canonical = to_parsing_canonical_form(json.loads(text))
    return bytes.fromhex(fa_fingerprint(canonical, "CRC-64-AVRO"))  # fastavro gives them in that order


# Version 1 of the appointment is the example type. Version 2 exists for these cases only: it adds a
# field `room`, as a later version of a type may (spec/types.md, section 3.3).
APPOINTMENT_1 = (REPO / "types" / "axt" / "example" / "v1" / "Appointment.1.avsc").read_text(encoding="utf-8")
_later = json.loads(APPOINTMENT_1)
_later["axt.version"] = 2
_later["fields"].append({"name": "room", "type": "string", "default": "", "doc": "The room."})
APPOINTMENT_2 = json.dumps(_later)
SCHEMA_1, SCHEMA_2 = schema_fingerprint(APPOINTMENT_1), schema_fingerprint(APPOINTMENT_2)
SCHEMA_VERSIONS = {SCHEMA_1: 1, SCHEMA_2: 2}  # the axt.version of the schema a fingerprint names

# --- the state of a record (section 3) --------------------------------------------------------


@dataclass(frozen=True)
class FieldState:
    value: bytes  # the value in Avro binary encoding, with the type of the field
    stamp: int  # 0 for a field never stamped (section 3.4)
    device: bytes
    schema: bytes = SCHEMA_1  # the fingerprint of the writer schema the bytes were written with


@dataclass(frozen=True)
class Removal:
    stamp: int
    device: bytes
    stands: bool = True  # False for a removal that was taken back (section 3.2)


@dataclass(frozen=True)
class State:
    fields: dict[str, FieldState]
    removal: Removal | None = None
    state_stamp: int | None = None  # None where the device could take none (section 2.3)


def key_order(a: bytes, b: bytes) -> int:
    """1 if the device key a is higher than b, -1 if lower, 0 if equal (section 4.1, rule 2)."""
    assert len(a) == len(b) == 32, "a device key has 32 bytes"
    return bytes_order(a, b)


def later(a: FieldState | Removal, b: FieldState | Removal) -> bool:
    """Whether a is later than b by its stamp and its device key (section 4.1, rules 1 and 2). This is
    the whole order between a removal and a field state (section 4.3)."""
    if a.stamp != b.stamp:
        return a.stamp > b.stamp
    return key_order(a.device, b.device) > 0


def later_field(a: FieldState, b: FieldState) -> bool:
    """Whether the field state a is later than b (section 4.1, rules 1 to 3)."""
    if (a.stamp, a.device) != (b.stamp, b.device):
        return later(a, b)
    if a.value != b.value:
        return bytes_order(a.value, b.value) > 0  # rule 3: the higher bytes of the value
    return bytes_order(a.schema, b.schema) > 0  # then the higher schema; with all equal, the same field state


def later_removal(a: Removal, b: Removal) -> bool:
    """Whether the removal a is later than b (section 4.2)."""
    if (a.stamp, a.device) != (b.stamp, b.device):
        return later(a, b)
    return a.stands and not b.stands  # the one that stands, over the one that was taken back


# --- merging two states (sections 4.1 to 4.3) --------------------------------------------------


@dataclass(frozen=True)
class Merged:
    fields: dict[str, FieldState]
    removal: Removal | None
    stands: dict[str, str]  # for each field name, "own" or "other" (section 4.1)
    removal_taken: bool  # whether the removal comes from the other state (section 4.2)

    @property
    def took(self) -> bool:
        return self.removal_taken or "other" in self.stands.values()


def merge(own: State | None, other: State) -> Merged:
    """The merge of sections 4.1 and 4.2 on a device whose state is `own`; None for a device that
    holds no state of the record, which takes the other state."""
    mine = own.fields if own else {}
    fields: dict[str, FieldState] = {}
    stands: dict[str, str] = {}
    for name in sorted(set(mine) | set(other.fields)):
        if name not in other.fields:
            side = "own"
        elif name not in mine:
            side = "other"
        else:
            side = "other" if later_field(other.fields[name], mine[name]) else "own"
        stands[name] = side
        fields[name] = mine[name] if side == "own" else other.fields[name]
    removal = own.removal if own else None
    removal_taken = other.removal is not None and (removal is None or later_removal(other.removal, removal))
    if removal_taken:
        removal = other.removal
    return Merged(fields, removal, stands, removal_taken)


def deleted(fields: dict[str, FieldState], removal: Removal | None) -> bool:
    """Whether the record is deleted in a state (section 4.3)."""
    return removal is not None and removal.stands and all(later(removal, f) for f in fields.values())


def merge_latest(states: list[State]) -> tuple[dict[str, FieldState], Removal | None]:
    """Section 4.5 in its own words: for each field name and for the removal, the latest of all the
    states hold. A second way to the result of merging them one after the other; the orders of keys
    and of values are those of Python's bytes here."""
    fields: dict[str, FieldState] = {}
    for name in {n for s in states for n in s.fields}:
        fields[name] = max(
            (s.fields[name] for s in states if name in s.fields),
            key=lambda f: (f.stamp, f.device, f.value, f.schema),
        )
    removals = [s.removal for s in states if s.removal is not None]
    return fields, max(removals, key=lambda x: (x.stamp, x.device, x.stands)) if removals else None


# --- what the merging device does (section 4.4) -------------------------------------------------


def seen(state: State) -> int:
    """The highest stamp of a state: of its field states, its removal and its state stamp; 0 without one."""
    stamps = [f.stamp for f in state.fields.values()]
    if state.removal:
        stamps.append(state.removal.stamp)
    if state.state_stamp is not None:
        stamps.append(state.state_stamp)
    return max(stamps, default=0)


def kept_to_pass(to_pass: int | None, state_stamp: int | None) -> int | None:
    """The version to pass a device keeps for a record: it drops it as soon as its state stamp of the
    record is above it (section 5.3)."""
    if to_pass is not None and state_stamp is not None and state_stamp > to_pass:
        return None
    return to_pass


@dataclass(frozen=True)
class DeviceMerge:
    state: State  # the device's state after the merge, with the state stamp it now holds for it
    merged: Merged
    highest: int
    sibling_stamp: int | None = None  # the highest state stamp of the record seen from a sibling
    to_pass: int | None = None  # the version to pass, while there is one

    @property
    def deleted(self) -> bool:
        return deleted(self.state.fields, self.state.removal)


def device_merge(
    own: State | None,
    other: State,
    now_ms: int,
    highest: int,
    r: int,
    sibling_stamp: int | None = None,
    to_pass: int | None = None,
) -> DeviceMerge:
    """Sections 4.1 to 4.4 on one device: the merge, the stamps counted as seen, and the state stamp.
    The state stamp of the result is a new one if the device took something or held no state, its
    own if it held a state and took nothing, and None if step 3 asks for one and the device can
    take no stamp (section 2.3). `sibling_stamp` and `to_pass` are what the device keeps for the
    record beside its state (section 3)."""
    m = merge(own, other)
    highest = max(highest, seen(other))  # step 1
    if other.state_stamp is not None:
        sibling_stamp = max(sibling_stamp or 0, other.state_stamp)
    if own is not None and not m.took:
        state = State(m.fields, m.removal, own.state_stamp)
        return DeviceMerge(state, m, highest, sibling_stamp, kept_to_pass(to_pass, own.state_stamp))
    stamp = next_stamp(now_ms, highest, r)  # step 3
    if stamp is not None:
        highest = stamp
    return DeviceMerge(
        State(m.fields, m.removal, stamp), m, highest, sibling_stamp, kept_to_pass(to_pass, stamp)
    )


# --- what a change stamps (sections 2.3 and 3.5) --------------------------------------------------


@dataclass(frozen=True)
class Changed:
    made: bool  # False where the device MUST NOT begin the change (section 2.3)
    state: State | None
    highest: int
    to_pass: int | None = None  # the version to pass, while there is one


def change(
    state: State | None,
    device: bytes,
    action: str,
    values: dict[str, bytes],
    now_ms: int,
    highest: int,
    r: tuple[int, int],
    schema: bytes = SCHEMA_1,
    now_ms_state: int | None = None,
    to_pass: int | None = None,
) -> Changed:
    """One change of section 3.5 on the device with the key `device`, which writes with the schema
    `schema`. `action` is "create" (with the values of every field of the record), "set" (with the
    values the change sets), "delete" or "take_back". It takes two stamps, with the random parts `r`,
    the first at the clock `now_ms` and the state stamp at `now_ms_state`, or at the same clock; or
    it is not begun (section 2.3). If the clock moved on so far that the state stamp cannot be
    taken, the state has none."""
    if not can_begin_change(now_ms, highest):
        return Changed(False, state, highest, to_pass)
    first = next_stamp(now_ms, highest, r[0])
    assert first is not None
    if action == "create":
        assert state is None, "a record that is created has no state yet"
        fields = {name: FieldState(value, first, device, schema) for name, value in values.items()}
        removal = None
    else:
        assert state is not None, "only a record the device holds is changed"
        fields, removal = dict(state.fields), state.removal
        if action == "set":
            assert not deleted(fields, removal), "a device changes no field of a deleted record"
            for name, value in values.items():
                fields[name] = FieldState(value, first, device, schema)
        elif action == "delete":
            assert not deleted(fields, removal), "a device deletes only a record that is there"
            removal = Removal(first, device, True)
        else:
            assert action == "take_back" and deleted(fields, removal), "only a deletion is taken back"
            removal = Removal(first, device, False)  # it stamps no field
    second = next_stamp(now_ms if now_ms_state is None else now_ms_state, first, r[1])
    # At one clock both can be taken, whatever is drawn for the first.
    assert now_ms_state is not None or second is not None
    top = first if second is None else second
    return Changed(True, State(fields, removal, second), top, kept_to_pass(to_pass, second))


def begin_stamping(
    device: bytes, states: list[State], now_ms: int, highest: int, r: list[int]
) -> tuple[bool, list[State], int]:
    """What an installation that counted does, when it begins to stamp, with the records it deleted
    while it counted (section 2.4): one stamp for each, in their order, for a removal that stands
    with its own key; the counted version stays in the place of the state stamp. Whether it begins,
    the states and its highest stamp: an installation that can take no stamp for this does not
    begin, and the states stay as they were."""
    assert len(r) == len(states)
    out: list[State] = []
    top = highest
    for state, part in zip(states, r, strict=True):
        assert state.removal is None, "a record of an installation that counted carries no removal"
        stamp = next_stamp(now_ms, top, part)
        if stamp is None:
            return False, states, highest
        top = stamp
        out.append(State(state.fields, Removal(stamp, device, True), state.state_stamp))
    return True, out, top


# --- the version toward other apps (section 5) ------------------------------------------------------


def record_message(
    state: State,
    writer_fields: list[str] | None = None,
    writer_version: int = 1,
    versions: dict[bytes, int] | None = None,
) -> tuple[str, int] | None:
    """The kind and the version of the record message of a state the device holds whole, written with a
    schema of the version `writer_version` that has the fields `writer_fields`, or every field of the
    state; `versions` gives the version of the schema a fingerprint names (section 5.1). None for a
    state for which the device could take no state stamp (section 2.3), and for a record that is there
    with a stamped field state, written with a later version of the type, whose field the schema lacks."""
    if state.state_stamp is None:
        return None
    if deleted(state.fields, state.removal):
        return ("DELETE", state.state_stamp)
    versions = SCHEMA_VERSIONS if versions is None else versions
    for name, field in state.fields.items():
        lacking = writer_fields is not None and name not in writer_fields
        if lacking and field.stamp >= 1 and versions[field.schema] > writer_version:
            return None
    return ("DATA", state.state_stamp)


@dataclass(frozen=True)
class AfterStale:
    highest: int
    stamps: bool  # whether the device stamps from then on
    to_pass: int | None  # the version to pass that the device keeps for the record
    resend: int | None  # the new state stamp under which it sends the record's current state, or None


def stale(
    receiver_version: int,
    state_stamp: int | None,
    sibling_stamp: int | None,
    to_pass: int | None,
    counted: bool,
    sibling: bool,
    now_ms: int,
    highest: int,
    r: int,
    may_send: bool = True,
) -> AfterStale:
    """What a device does after STALE with a receiver's version (section 5.3). `state_stamp`: its
    state stamp of the record, or the version it counted; `sibling_stamp`: the highest state stamp of
    the record it saw from a sibling in a merge, or None; `to_pass`: the version to pass it keeps for
    the record from an earlier STALE, or None; `counted`: whether it counted until now; `sibling`:
    whether its set has other current devices; `may_send`: whether section 5.1 lets it send the
    record."""
    highest = max(highest, receiver_version)  # every such version counts as seen (section 2.2)
    known = max(state_stamp or 0, sibling_stamp or 0)  # the highest version it knows of the record
    if receiver_version <= known:
        return AfterStale(highest, not counted, to_pass, None)
    to_pass = max(to_pass or 0, receiver_version)  # the higher one is kept
    if sibling or not may_send:
        return AfterStale(highest, True, to_pass, None)
    stamp = next_stamp(now_ms, highest, r)  # the only current device of its set: at once
    if stamp is None:
        return AfterStale(highest, True, to_pass, None)  # it sends nothing and keeps the version to pass
    return AfterStale(stamp, True, None, stamp)  # the state stamp is above the version to pass: dropped


def pass_version(
    state_stamp: int, to_pass: int, may_send: bool, now_ms: int, highest: int, r: int
) -> tuple[int | None, int | None, int]:
    """What a device with siblings does once it has, after the STALE, merged the state of the record
    with every other current device of its set, or waited 14 days for those it did not merge with
    (section 5.3): the new state stamp under which it sends the record's current state again if its
    state stamp is still below the version to pass, or None; the version to pass it keeps, or None;
    and its highest stamp."""
    if state_stamp > to_pass:
        return None, None, highest
    stamp = next_stamp(now_ms, highest, r) if may_send else None
    if stamp is None:
        return None, to_pass, highest
    return stamp, None, stamp


# --- the JSON form of the vectors (spec/conformance.md, section 5.14) --------------------------------


def stamp_json(stamp: int | None) -> str | None:
    """A stamp, or another integer of the size of a long, as decimal digits; None stays None."""
    return None if stamp is None else str(stamp)


def state_json(state: State | None) -> dict[str, Any] | None:
    if state is None:
        return None
    r = state.removal
    return {
        "fields": {
            name: {
                "value": f.value.hex(),
                "schema": f.schema.hex(),
                "stamp": str(f.stamp),
                "device": f.device.hex(),
            }
            for name, f in state.fields.items()
        },
        "removal": r and {"stamp": str(r.stamp), "device": r.device.hex(), "stands": r.stands},
        "state_stamp": stamp_json(state.state_stamp),
    }


def state_of_json(v: dict[str, Any] | None) -> State | None:
    if v is None:
        return None
    r = v["removal"]
    return State(
        {
            name: FieldState(
                bytes.fromhex(f["value"]),
                int(f["stamp"]),
                bytes.fromhex(f["device"]),
                bytes.fromhex(f["schema"]),
            )
            for name, f in v["fields"].items()
        },
        r and Removal(int(r["stamp"]), bytes.fromhex(r["device"]), r["stands"]),
        None if v["state_stamp"] is None else int(v["state_stamp"]),
    )


# --- the cases of section 6.1 ----------------------------------------------------------------------

NOW = 1_763_456_400_000  # 2025-11-18 09:00:00.000 UTC
SIBLING = 115_570_114_560_020_000  # the stamp of a sibling whose clock is an hour ahead

# The case, now_ms, highest, r, the base max(now_ms * 65536, highest + 1), and the next stamp, as the
# table of section 6.1 shows them; None for "no stamp".
STAMPS: list[tuple[str, int, int, int, int, int | None]] = [
    ("1. The first stamp of a device", NOW, 0, 12_345, 115_569_878_630_400_000, 115_569_878_630_412_345),
    (
        "2. A second stamp in the same millisecond: the device counts",
        NOW,
        115_569_878_630_412_345,
        7,
        115_569_878_630_412_346,
        115_569_878_630_412_353,
    ),
    (
        "3. A millisecond later: the clock leads again",
        NOW + 1,
        115_569_878_630_412_353,
        30_000,
        115_569_878_630_465_536,
        115_569_878_630_495_536,
    ),
    (
        "4. The device has seen a stamp of a sibling whose clock is an hour ahead",
        NOW + 1,
        SIBLING,
        100,
        115_570_114_560_020_001,
        115_570_114_560_020_101,
    ),
    (
        "5. The clock was set back to 1970",
        0,
        115_570_114_560_020_101,
        32_767,
        115_570_114_560_020_102,
        115_570_114_560_052_869,
    ),
    ("6. A clock before 1970 and no stamp yet", -5, 0, 0, 1, 1),
    (
        "7. highest is one below the clock's value",
        NOW,
        115_569_878_630_399_999,
        0,
        115_569_878_630_400_000,
        115_569_878_630_400_000,
    ),
    (
        "8. The last base from which a stamp can be taken",
        NOW,
        9_223_372_036_854_743_039,
        50,
        9_223_372_036_854_743_040,
        9_223_372_036_854_743_090,
    ),
    (
        "9. The same with the highest random part: the largest long",
        NOW,
        9_223_372_036_854_743_039,
        32_767,
        9_223_372_036_854_743_040,
        9_223_372_036_854_775_807,
    ),
    (
        "10. One above: no stamp, also with the lowest random part",
        NOW,
        9_223_372_036_854_743_040,
        0,
        9_223_372_036_854_743_041,
        None,
    ),
    (
        "11. A clock so far ahead that the product is above the largest long",
        2**47,
        0,
        0,
        9_223_372_036_854_775_808,
        None,
    ),
    ("12. highest is the largest long", NOW, 9_223_372_036_854_775_807, 0, 9_223_372_036_854_775_808, None),
]

# Further cases, for the limits of section 2.2 and for arithmetic that must not wrap around: the
# case, now_ms, highest, r and the next stamp, written out from the formula.
MORE_STAMPS: list[tuple[str, int, int, int, int | None]] = [
    ("the largest random part while the clock leads", NOW, 0, 32_767, 115_569_878_630_432_767),
    ("the clock's value equals highest: the device counts", NOW, NOW * 65536, 0, NOW * 65536 + 1),
    ("one above the last base: no stamp, also with the highest random part", NOW, LAST_BASE, 32_767, None),
    ("highest is one below the largest long: no stamp", NOW, MAX - 1, 0, None),
    ("the last clock from which a stamp can be taken", 2**47 - 1, 0, 32_767, 2**63 - 32_769),
    (
        "the last clock, and highest is its value: the device counts",
        2**47 - 1,
        2**63 - 65_536,
        0,
        2**63 - 65_535,
    ),
    ("a clock of 2^48, whose product is 2^64: no stamp", 2**48, 0, 0, None),
    ("the largest clock: no stamp", MAX, 0, 32_767, None),
    ("the smallest clock and no stamp yet", MIN, 0, 0, 1),
    ("the smallest clock while the device counts", MIN, 41, 0, 42),
    ("a clock before 1970 whose product is below the smallest long", -(2**47) - 1, 100, 5, 106),
]

# --- the cases of sections 6.2 to 6.6 ------------------------------------------------------------------

START = "2025-11-18 10:00"  # the examples show the start as its wall clock
START_2 = "2025-11-18 10:30"
WEBER = "Dr. Weber, Hauptstr. 5"

# The merges and changes of the examples of sections 6.2 to 6.6, as check() plays them, each with its
# inputs and the result the rules give, which the checks compare with the document's numbers:
# conformance/tools/generate_vectors.py makes vectors of them.
EXAMPLE_MERGES: list[tuple[str, State | None, State, tuple[int, int, int], DeviceMerge]] = []
EXAMPLE_CHANGES: list[
    tuple[str, State | None, bytes, str, dict[str, bytes], tuple[int, int, tuple[int, int]], Changed]
] = []


def example_merge(
    label: str, own: State | None, other: State, now_ms: int, highest: int, r: int
) -> DeviceMerge:
    done = device_merge(own, other, now_ms, highest, r)
    if label:
        EXAMPLE_MERGES.append((label, own, other, (now_ms, highest, r), done))
    return done


class Device:
    """A device of the examples: its key, its highest stamp, and its state of the one record. Its clock
    stands at 1970, as section 6.2 says, so each of its stamps is highest + 1 + r."""

    def __init__(self, name: str, key: bytes, highest: int = 0, now_ms: int = 0) -> None:
        self.name, self.key, self.highest, self.now_ms = name, key, highest, now_ms
        self.state: State | None = None

    def r_for(self, stamp: int, highest: int | None = None) -> int:
        """The random part that gives the stamp the document shows. A stamp that no random part gives,
        because it is not above every stamp the device has given or seen, or too far above, is an
        error of the document."""
        base = max(self.now_ms * 65536, (self.highest if highest is None else highest) + 1)
        r = stamp - base
        assert 0 <= r <= R_MAX, (
            f"{self.name}: the document's stamp {stamp} is not {base} plus a random part of 0 to 32,767"
        )
        return r

    def change(self, action: str, values: dict[str, str], first: int, second: int, label: str = "") -> None:
        """A change of section 3.5 that takes the stamps `first` and `second`, as the document shows them."""
        r = (self.r_for(first), self.r_for(second, first))
        coded = {name: encoded(value) for name, value in values.items()}
        done = change(self.state, self.key, action, coded, self.now_ms, self.highest, r)
        if label:
            clock = (self.now_ms, self.highest, r)
            EXAMPLE_CHANGES.append((label, self.state, self.key, action, coded, clock, done))
        assert done.made and done.state is not None
        assert done.state.state_stamp == second and done.highest == second
        self.state, self.highest = done.state, done.highest

    def merge(self, other: State, stamp: int | None, label: str = "") -> DeviceMerge:
        """A merge of section 4 that takes the state stamp `stamp`, or with None takes nothing."""
        highest = max(self.highest, seen(other))
        r = 0 if stamp is None else self.r_for(stamp, highest)
        done = example_merge(label, self.state, other, self.now_ms, self.highest, r)
        if stamp is None:
            assert not done.merged.took and self.state is not None
            assert done.state.state_stamp == self.state.state_stamp
        else:
            assert done.merged.took or self.state is None
            assert done.state.state_stamp == stamp, (done.state.state_stamp, stamp)
        self.state, self.highest = done.state, done.highest
        return done


def held(device: Device) -> State:
    assert device.state is not None
    return device.state


def start_of_6_2(label: bool = False) -> tuple[Device, Device]:
    """Section 6.2: the phone created the record with the stamp 100 and the state stamp 101; the tablet
    took the state from the phone and took the state stamp 105."""
    phone, tablet = Device("phone", PHONE), Device("tablet", TABLET)
    values = {"title": "Vet", "start": START, "location": ""}
    phone.change("create", values, 100, 101, "6.2: the phone creates the record" if label else "")
    done = tablet.merge(held(phone), 105, "6.2: the tablet takes the state from the phone" if label else "")
    assert set(done.merged.stands.values()) == {"other"} and not done.merged.removal_taken
    # The phone has given or seen the stamps up to 101, the tablet those up to 105.
    assert (phone.highest, tablet.highest) == (101, 105)
    return phone, tablet


def row(state: State, name: str) -> tuple[str, int, str]:
    f = state.fields[name]
    return (text_of(f.value), f.stamp, {PHONE: "phone", TABLET: "tablet"}[f.device])


FIELDS = ("title", "start", "location")


def table(state: State) -> list[tuple[str, int, str]]:
    assert tuple(sorted(state.fields)) == tuple(sorted(FIELDS))
    return [row(state, name) for name in FIELDS]


# Section 6.3, the merge of step 4 on the phone: own, other, which side stands.
STEP_4 = [
    ("title", ("Vet", 100, "phone"), ("Vet", 100, "phone"), "own"),
    ("start", (START_2, 110, "phone"), (START, 100, "phone"), "own"),
    ("location", ("", 100, "phone"), (WEBER, 120, "tablet"), "other"),
]
# Section 6.3, the field states of both devices after step 4.
AFTER_STEP_4 = [("Vet", 100, "phone"), (START_2, 110, "phone"), (WEBER, 120, "tablet")]
# Section 6.3, the versions toward another app: version, sender, start, location.
VERSIONS_6_3 = [
    (111, "phone", "10:30", ""),
    (121, "tablet", "10:00", WEBER),
    (127, "tablet", "10:30", WEBER),
    (130, "phone", "10:30", WEBER),
]
HIGHEST_FIELD_STAMPS_6_3 = [110, 120, 120, 120]  # "Were the version the highest field stamp"

# Section 6.4: the case; the phone's field stamp and state stamp; the tablet's; whose change stands;
# the device that takes title, what it has given or seen, its new state stamp; and the state stamp
# the other device keeps.
SAME_FIELD = [
    ("1. The tablet's change is later", (140, 141), (150, 151), "tablet", "phone", 151, 155, 151),
    ("2. The phone's change is later", (160, 161), (150, 151), "phone", "tablet", 161, 165, 161),
    ("3. Equal stamps", (150, 151), (150, 152), "tablet", "phone", 152, 156, 152),
]

# Section 6.5: the case; the tablet's field stamp of `location` and its state stamp; whether the record
# is deleted; what the tablet has given or seen and its new state stamp; the same for the phone; the
# kind each then sends.
DELETION = [
    ("1. The change came before the deletion", 145, 146, True, 151, 155, 151, 153, "DELETE"),
    ("2. The change came after the deletion", 160, 161, False, 161, 165, 161, 163, "DATA"),
    ("3. Equal stamps", 150, 152, False, 152, 156, 152, 154, "DATA"),
]
# Section 6.5, taking the deletion back: the field states and the removal before and after.
TAKEN_BACK_FIELDS = [("Vet", 100, "phone"), (START, 100, "phone"), ("Praxis", 145, "tablet")]


def check_stamps(out: list[str]) -> None:
    """Sections 2 and 6.1."""
    at = datetime.datetime(2025, 11, 18, 9, 0, 0, tzinfo=datetime.UTC)
    assert int(at.timestamp()) * 1000 == NOW
    assert NOW * 65536 == 115_569_878_630_400_000
    assert (NOW + 3_600_000) * 65536 + 20_000 == SIBLING  # case 4
    assert MAX == 9_223_372_036_854_775_807 and 2**47 == 140_737_488_355_328
    assert LAST_BASE == 2**63 - 32_768 == 9_223_372_036_854_743_040  # the last base of cases 8 and 9
    assert LAST_CHANGE_BASE == 9_223_372_036_854_710_272  # "a base of at most"
    assert len(STAMPS) == 12
    out.append("6.1 Stamps: now_ms, highest, r, base, next stamp")
    for label, now_ms, highest, r, base, want in STAMPS:
        got = next_stamp(now_ms, highest, r)
        assert got == want, f"{label}: the rule gives {got}, the document shows {want}"
        assert next_stamp_by_cases(now_ms, highest, r) == want, label
        assert max(now_ms * 65536, highest + 1) == base, (label, max(now_ms * 65536, highest + 1))
        if got is None:
            # In cases 10 to 12, base + 32767 is above 2^63 - 1, so there is no stamp for any r.
            assert base + 32767 > MAX and next_stamp(now_ms, highest, R_MAX) is None
        else:
            assert got > highest
        stamp = "no stamp" if got is None else f"{got:,}"
        out.append(f"  {label}: {now_ms:,} | {highest:,} | {r:,} | {base:,} | {stamp}")
    for label, now_ms, highest, r, want in MORE_STAMPS:
        assert next_stamp(now_ms, highest, r) == want, (label, next_stamp(now_ms, highest, r))
        assert next_stamp_by_cases(now_ms, highest, r) == want, label
    # Section 6.1: the device of case 8 can take one stamp but MUST NOT begin a change.
    assert next_stamp(NOW, STAMPS[7][2], 0) is not None and not can_begin_change(NOW, STAMPS[7][2])
    assert can_begin_change(0, LAST_CHANGE_BASE - 1) and not can_begin_change(0, LAST_CHANGE_BASE)
    # Section 2.3: the highest stamp a device can give is 2^63 - 1, from a base of 2^63 - 32,768 with an
    # r of 32,767; a clock alone stops a device from stamping only for a now_ms of 2^47 or more, a date
    # beyond the year 6000. Section 2.4: for a clock in the year 2025 a stamp is above 10^17.
    assert next_stamp(0, LAST_BASE - 1, R_MAX) == MAX and next_stamp(0, MAX, 0) is None
    assert next_stamp(2**47 - 1, 0, 0) is not None and can_begin_change(2**47 - 1, 0)
    assert next_stamp(2**47, 0, 0) is None
    epoch = datetime.datetime(1970, 1, 1, tzinfo=datetime.UTC)
    far = epoch + datetime.timedelta(milliseconds=2**47)
    assert far.year > 6000, far
    y2025 = int(datetime.datetime(2025, 1, 1, tzinfo=datetime.UTC).timestamp()) * 1000
    assert y2025 * 65536 > 10**17
    out.append(f"  the last base of a stamp is {LAST_BASE:,}, the last base of a change {LAST_CHANGE_BASE:,}")
    out.append(
        f"  2^47 ms after 1970 is in the year {far.year}; the first stamp of 2025 is {y2025 * 65536:,}"
    )


def check_different_fields(out: list[str]) -> None:
    """Sections 6.2 and 6.3."""
    phone, tablet = start_of_6_2(label=True)
    assert key_order(TABLET, PHONE) > 0  # the tablet's device key is the higher of the two
    assert (
        table(held(phone))
        == table(held(tablet))
        == [("Vet", 100, "phone"), (START, 100, "phone"), ("", 100, "phone")]
    )
    assert held(phone).removal is None and held(tablet).removal is None
    assert (held(phone).state_stamp, held(tablet).state_stamp) == (101, 105)
    out.append("6.2 Both devices: " + repr(table(held(phone))) + "; state stamps 101 and 105")

    sent: list[tuple[int, str, str, str, int]] = []

    def send(d: Device) -> None:
        s = held(d)
        message = record_message(s)
        assert message is not None and message[0] == "DATA"
        top = max(f.stamp for f in s.fields.values())
        sent.append((message[1], d.name, row(s, "start")[0][-5:], row(s, "location")[0], top))

    stamps: list[tuple[int | None, int | None]] = []

    def step() -> None:
        stamps.append((held(phone).state_stamp, held(tablet).state_stamp))

    phone.change("set", {"start": START_2}, 110, 111, "6.3, step 1: the phone sets start")
    send(phone)
    step()
    phone_1 = held(phone)
    tablet.change("set", {"location": WEBER}, 120, 121, "6.3, step 2: the tablet sets location")
    send(tablet)
    step()
    tablet_2 = held(tablet)
    # Step 3: the tablet has given 121 and seen 111, and takes 127.
    done = tablet.merge(phone_1, 127, "6.3, step 3: the tablet merges the phone's state and takes start")
    assert done.merged.stands == {"title": "own", "start": "other", "location": "own"}
    assert max(121, seen(phone_1)) == 121 and seen(phone_1) == 111
    send(tablet)
    step()
    # Step 4: the phone has seen the stamps 100, 120 and the tablet's state stamp 121.
    before = held(phone)
    for name, own, other, _ in STEP_4:
        assert row(before, name) == own and row(tablet_2, name) == other, name
    assert seen(tablet_2) == 121 and phone.highest == 111
    done = phone.merge(tablet_2, 130, "6.3, step 4: the phone merges the tablet's state and takes location")
    assert done.merged.stands == {name: stands for name, _, _, stands in STEP_4}
    assert not done.merged.removal_taken
    send(phone)
    step()
    assert table(held(phone)) == table(held(tablet)) == AFTER_STEP_4
    # Step 5: each merges the other's state of steps 3 and 4 and takes nothing.
    phone_4, tablet_3 = held(phone), held(tablet)
    phone.merge(tablet_3, None, "6.3, step 5: the phone merges the tablet's state and takes nothing")
    tablet.merge(phone_4, None, "6.3, step 5: the tablet merges the phone's state and takes nothing")
    step()
    assert stamps == [(111, 105), (111, 121), (111, 127), (130, 127), (130, 127)]
    assert phone.highest == tablet.highest == 130  # each next stamp is above 130
    assert [s[:4] for s in sent] == VERSIONS_6_3
    assert [s[4] for s in sent] == HIGHEST_FIELD_STAMPS_6_3
    # A tablet that sends 127 to a receiver that has 130 gets STALE with 130, a stamp it has seen
    # already, and does nothing: 130 is the phone's state stamp, which it saw in the merge of step 5.
    after = stale(130, 127, 130, None, counted=False, sibling=True, now_ms=0, highest=tablet.highest, r=0)
    assert after == AfterStale(130, True, None, None)
    out.append("6.3 State stamps of phone and tablet after each step: " + repr(stamps))
    out.append("    After step 4, both: " + repr(AFTER_STEP_4))
    out.append("    Versions sent (version, by, start, location, highest field stamp): " + repr(sent))


def check_same_field(out: list[str]) -> None:
    """Section 6.4."""
    out.append(
        "6.4 Two devices change title: phone's stamps, tablet's stamps, who stands, who takes, what it "
        "has given or seen, its new state stamp, the state stamp the other keeps"
    )
    for label, p, t, stands, taker, top, new, kept in SAME_FIELD:
        phone, tablet = start_of_6_2()
        case = f"6.4, case {label[0]}"
        phone.change("set", {"title": "Vet, Mimi"}, *p, f"{case}: the phone sets title")
        tablet.change("set", {"title": "Vet with Mimi"}, *t, f"{case}: the tablet sets title")
        phone_state, tablet_state = held(phone), held(tablet)
        takes, keeps = (phone, tablet) if taker == "phone" else (tablet, phone)
        other, own = held(keeps), held(takes)
        assert max(takes.highest, seen(other)) == top, (label, takes.highest, seen(other))
        on_taker = takes.merge(other, new, f"{case}: the {takes.name} takes title")
        on_keeper = keeps.merge(own, None, f"{case}: the {keeps.name} takes nothing")
        assert on_taker.merged.stands == {"title": "other", "start": "own", "location": "own"}
        assert held(keeps).state_stamp == kept == (t[1] if taker == "phone" else p[1])
        assert held(phone).fields == held(tablet).fields
        assert row(held(phone), "title")[1:] == ((t if stands == "tablet" else p)[0], stands), label
        assert (taker == "phone") == (stands == "tablet") and not on_keeper.merged.took
        assert phone_state.state_stamp == p[1] and tablet_state.state_stamp == t[1]
        out.append(f"  {label}: {p} | {t} | the {stands}'s | the {taker} | {top} | {new} | {kept}")


def check_deletion(out: list[str]) -> None:
    """Section 6.5."""
    out.append(
        "6.5 A deletion and a change: deleted, tablet seen and new state stamp, phone seen and new "
        "state stamp, kind sent"
    )
    for label, field, state, gone, t_seen, t_new, p_seen, p_new, kind in DELETION:
        phone, tablet = start_of_6_2()
        case = f"6.5, case {label[0]}"
        phone.change("delete", {}, 150, 151, "6.5: the phone deletes the record" if label[0] == "1" else "")
        assert record_message(held(phone)) == ("DELETE", 151)
        tablet.change("set", {"location": "Praxis"}, field, state, f"{case}: the tablet sets location")
        phone_state, tablet_state = held(phone), held(tablet)
        assert max(tablet.highest, seen(phone_state)) == t_seen, (label, tablet.highest, seen(phone_state))
        assert max(phone.highest, seen(tablet_state)) == p_seen, (label, phone.highest, seen(tablet_state))
        on_tablet = tablet.merge(phone_state, t_new, f"{case}: the tablet takes the removal")
        on_phone = phone.merge(tablet_state, p_new, f"{case}: the phone takes location")
        assert on_tablet.merged.removal_taken and "other" not in on_tablet.merged.stands.values()
        assert on_phone.merged.stands == {"title": "own", "start": "own", "location": "other"}
        assert not on_phone.merged.removal_taken
        assert held(phone).fields == held(tablet).fields and held(phone).removal == held(tablet).removal
        assert held(phone).removal == Removal(150, PHONE, True)  # the removal stays, standing
        assert on_phone.deleted == on_tablet.deleted == gone, label
        assert record_message(held(phone)) == (kind, p_new) and record_message(held(tablet)) == (kind, t_new)
        if not gone:
            assert [r[0] for r in table(held(phone))] == ["Vet", START, "Praxis"]
        out.append(f"  {label}: {gone} | {t_seen} | {t_new} | {p_seen} | {p_new} | {kind}")
        if label.startswith("1."):
            # Taking the deletion back: the phone has given or seen the stamps up to 153, takes 170 for
            # a removal that was taken back and the state stamp 171, and stamps no field. The tablet,
            # which has given or seen the stamps up to 155, takes the removal, has then seen the stamps
            # up to 171, and takes the state stamp 175.
            assert table(held(phone)) == table(held(tablet)) == TAKEN_BACK_FIELDS
            assert (phone.highest, tablet.highest) == (153, 155)
            phone.change("take_back", {}, 170, 171, "6.5: the phone takes the deletion of case 1 back")
            assert max(tablet.highest, seen(held(phone))) == 171
            back = tablet.merge(held(phone), 175, "6.5: the tablet takes the removal that was taken back")
            assert back.merged.removal_taken and "other" not in back.merged.stands.values()
            for d in (phone, tablet):
                assert table(held(d)) == TAKEN_BACK_FIELDS  # taking back changed no field
                assert held(d).removal == Removal(170, PHONE, False)
            assert record_message(held(phone)) == ("DATA", 171)
            assert record_message(held(tablet)) == ("DATA", 175)
            # A removal that stands with a stamp above 170, from either device, would delete it again.
            assert deleted(held(tablet).fields, Removal(171, PHONE, True))
            out.append(
                "    taken back: removal 170, phone, taken back; state stamps 171 on the phone and 175 "
                "on the tablet; there, with " + repr(TAKEN_BACK_FIELDS)
            )
    # Had the tablet deleted the record and the phone changed a field with the same stamp, the record
    # would be deleted: the removal's key, the tablet's, is the higher one.
    phone, tablet = start_of_6_2()
    case = "6.5, the tablet deletes, the phone changes with its stamp"
    tablet.change("delete", {}, 150, 151, f"{case}: the deletion")
    phone.change("set", {"location": "Praxis"}, 150, 151, f"{case}: the change")
    assert example_merge(f"{case}: on the phone", held(phone), held(tablet), 0, phone.highest, 0).deleted
    assert example_merge(f"{case}: on the tablet", held(tablet), held(phone), 0, tablet.highest, 0).deleted
    out.append("  the tablet deletes and the phone changes with the same stamp: deleted")


def check_counted(out: list[str]) -> None:
    """Section 6.6: an installation that counted begins to stamp."""
    never = {
        "title": FieldState(encoded("Vet"), 0, PHONE),
        "start": FieldState(encoded("10:30"), 0, PHONE),
        "location": FieldState(encoded(""), 0, PHONE),
    }
    phone = Device("phone", PHONE, highest=3, now_ms=NOW)
    phone.state = State(never, None, 3)  # the counted version stands in the place of the state stamp
    assert record_message(held(phone)) == ("DATA", 3)
    assert begin_stamping(PHONE, [], NOW, 3, []) == (True, [], 3)  # it has deleted no record: no stamp
    tablet = Device("tablet", TABLET)
    tablet.merge(held(phone), 4, "6.6: the tablet takes the state of an installation that counted")
    assert held(tablet).fields == never  # with the stamp 0 and the phone's key
    # The two stamps of the change: now_ms, highest, r, base and the stamp, as the document shows them.
    s1, s2 = 115_569_878_630_412_345, 115_569_878_630_412_353
    for highest, r, base, stamp in ((3, 12_345, 115_569_878_630_400_000, s1), (s1, 7, s1 + 1, s2)):
        assert max(NOW * 65536, highest + 1) == base and next_stamp(NOW, highest, r) == stamp
    assert phone.r_for(s1) == 12_345 and phone.r_for(s2, s1) == 7
    phone.change(
        "set", {"location": "Dr. Weber"}, s1, s2, "6.6: the first change after the phone begins to stamp"
    )
    s = held(phone)
    assert table(s) == [("Vet", 0, "phone"), ("10:30", 0, "phone"), ("Dr. Weber", s1, "phone")]
    assert record_message(s) == ("DATA", s2) and s2 > s1 > 3
    # Any stamped change of a field is later than a field state never stamped, and so is every removal.
    assert all(later(FieldState(b"", 1, bytes(32)), f) for f in never.values())
    assert deleted(never, Removal(1, bytes(32)))
    out.append(f"6.6 With highest 3 and the random parts 12,345 and 7: S1 = {s1:,}, S2 = {s2:,}")


# --- further cases, for the vectors ----------------------------------------------------------------------

# Keys for the order of section 4.1, rule 2: unsigned bytes, the first difference decides.
K_7F, K_80 = bytes([0x7F]) + bytes([0xFF]) * 31, bytes([0x80]) + bytes(31)
K_LAST_0, K_LAST_1 = PHONE[:31] + bytes([0x00]), PHONE[:31] + bytes([0x01])
K_MID_LOW, K_MID_HIGH = bytes(15) + bytes([0x01]) + bytes([0xFF]) * 16, bytes(15) + bytes([0x02]) + bytes(16)

# The device key a, the device key b, and the order of a to b.
KEY_ORDERS: list[tuple[str, bytes, bytes, int]] = [
    ("the tablet's key is higher than the phone's", TABLET, PHONE, 1),
    ("80 in the first byte is higher than 7f: the bytes are unsigned", K_80, K_7F, 1),
    ("keys that differ in the last byte only", K_LAST_1, K_LAST_0, 1),
    ("the first byte that differs decides, whatever follows", K_MID_HIGH, K_MID_LOW, 1),
    ("a key is not higher than itself", PHONE, PHONE, 0),
]

# Values for the order of section 4.1, rule 3: the value a, the value b, their bytes in Avro binary
# encoding written out, and the order of a to b.
VALUE_ORDERS: list[tuple[str, str | int, str | int, str, str, int]] = [
    ("two texts of one length: the first character that differs", "Vet, Mimi", "Vet: Mimi", "", "", -1),
    ("the length of a text comes first: the longer text is higher", "aa", "b", "046161", "0262", 1),
    ("a long of 1 is 02, a long of -1 is 01", 1, -1, "02", "01", 1),
    ("a long of -2 is 03 and so higher than a long of 1", -2, 1, "03", "02", 1),
    ("a long of 64 is 80 01, higher than 63, which is 7e: the bytes are unsigned", 64, 63, "8001", "7e", 1),
    ("equal values have equal bytes", "Vet", "Vet", "06566574", "06566574", 0),
]


def f(value: str | int | bytes, stamp: int, device: bytes, schema: bytes = SCHEMA_1) -> FieldState:
    return FieldState(value if isinstance(value, bytes) else encoded(value), stamp, device, schema)


def gone(stamp: int, device: bytes) -> Removal:
    return Removal(stamp, device, True)


def back(stamp: int, device: bytes) -> Removal:
    return Removal(stamp, device, False)


# Merges: the case, the device's own state or None, the other state, now_ms, highest and r, and the
# expected result written out from sections 4.1 to 4.4: which side stands for each field name, whether
# the removal is taken, whether the record is deleted, the state stamp and the device's highest stamp.
MergeCase = tuple[str, State | None, State, tuple[int, int, int], dict[str, str], bool, bool, int | None, int]
MERGES: list[MergeCase] = [
    (
        "a field that only the device's own state holds stays, and one that only the other holds is taken",
        State({"a": f(1, 10, PHONE)}, None, 11),
        State({"b": f(2, 5, TABLET)}, None, 6),
        (0, 11, 0),
        {"a": "own", "b": "other"},
        False,
        False,
        12,
        12,
    ),
    (
        "the higher stamp is later, also against the higher device key",
        State({"a": f("phone", 21, PHONE)}, None, 22),
        State({"a": f("tablet", 20, TABLET)}, None, 23),
        (0, 22, 0),
        {"a": "own"},
        False,
        False,
        22,
        23,
    ),
    (
        "equal stamps, and the other key is higher by its first byte, 80 above 7f",
        State({"a": f("7f", 20, K_7F)}, None, 21),
        State({"a": f("80", 20, K_80)}, None, 21),
        (0, 21, 4),
        {"a": "other"},
        False,
        False,
        26,
        26,
    ),
    (
        "equal stamps, and the own key is higher by its first byte, 80 above 7f",
        State({"a": f("80", 20, K_80)}, None, 21),
        State({"a": f("7f", 20, K_7F)}, None, 21),
        (0, 21, 4),
        {"a": "own"},
        False,
        False,
        21,
        21,
    ),
    (
        "equal stamps, and the other key is higher in its last byte only",
        State({"a": f("0", 20, K_LAST_0)}, None, 21),
        State({"a": f("1", 20, K_LAST_1)}, None, 22),
        (0, 21, 0),
        {"a": "other"},
        False,
        False,
        23,
        23,
    ),
    (
        "equal stamps, and the first byte that differs decides, not the bytes after it",
        State({"a": f("high", 20, K_MID_HIGH)}, None, 21),
        State({"a": f("low", 20, K_MID_LOW)}, None, 22),
        (0, 21, 0),
        {"a": "own"},
        False,
        False,
        21,
        22,
    ),
    (
        "equal stamps, keys and values are the same field state: nothing is taken",
        State({"a": f("x", 20, PHONE)}, None, 30),
        State({"a": f("x", 20, PHONE)}, None, 25),
        (0, 30, 0),
        {"a": "own"},
        False,
        False,
        30,
        30,
    ),
    (
        "equal stamps and keys: the other value is higher by its first byte that differs",
        State({"a": f("Vet, Mimi", 20, PHONE)}, None, 21),
        State({"a": f("Vet: Mimi", 20, PHONE)}, None, 22),
        (0, 21, 0),
        {"a": "other"},
        False,
        False,
        23,
        23,
    ),
    (
        "equal stamps and keys: the own value is higher by its first byte that differs",
        State({"a": f("Vet: Mimi", 20, PHONE)}, None, 22),
        State({"a": f("Vet, Mimi", 20, PHONE)}, None, 21),
        (0, 22, 0),
        {"a": "own"},
        False,
        False,
        22,
        22,
    ),
    (
        "equal stamps and keys: the longer text is higher, since its length comes first in the bytes",
        State({"a": f("b", 20, PHONE)}, None, 21),
        State({"a": f("aa", 20, PHONE)}, None, 22),
        (0, 21, 0),
        {"a": "other"},
        False,
        False,
        23,
        23,
    ),
    (
        "equal stamps and keys: a long of -2 is higher than a long of 1 by its bytes, 03 above 02",
        State({"a": f(1, 20, PHONE)}, None, 21),
        State({"a": f(-2, 20, PHONE)}, None, 22),
        (0, 21, 0),
        {"a": "other"},
        False,
        False,
        23,
        23,
    ),
    (
        "equal stamps and keys: a long of 64 is higher than 63, the byte 80 above 7e",
        State({"a": f(64, 20, PHONE)}, None, 21),
        State({"a": f(63, 20, PHONE)}, None, 22),
        (0, 21, 0),
        {"a": "own"},
        False,
        False,
        21,
        22,
    ),
    (
        "equal stamps and keys: bytes that are the beginning of the others are lower",
        State({"a": f(bytes.fromhex("0261"), 20, PHONE)}, None, 21),
        State({"a": f(bytes.fromhex("026100"), 20, PHONE)}, None, 22),
        (0, 21, 0),
        {"a": "other"},
        False,
        False,
        23,
        23,
    ),
    (
        "equal stamps, keys and bytes under two schemas: the own field state has the higher schema",
        State({"a": f("x", 20, PHONE, SCHEMA_1)}, None, 30),
        State({"a": f("x", 20, PHONE, SCHEMA_2)}, None, 25),
        (0, 30, 0),
        {"a": "own"},
        False,
        False,
        30,
        30,
    ),
    (
        "equal stamps, keys and bytes under two schemas: the other field state has the higher schema",
        State({"a": f("x", 20, PHONE, SCHEMA_2)}, None, 25),
        State({"a": f("x", 20, PHONE, SCHEMA_1)}, None, 30),
        (0, 25, 0),
        {"a": "other"},
        False,
        False,
        31,
        31,
    ),
    (
        "equal stamps, keys, bytes and schemas are the same field state: nothing is taken",
        State({"a": f("x", 20, PHONE, SCHEMA_2)}, None, 25),
        State({"a": f("x", 20, PHONE, SCHEMA_2)}, None, 30),
        (0, 25, 0),
        {"a": "own"},
        False,
        False,
        25,
        30,
    ),
    (
        "the schema is compared only when the bytes are equal: the higher bytes stand, with the lower schema",
        State({"a": f("a", 20, PHONE, SCHEMA_1)}, None, 21),
        State({"a": f("b", 20, PHONE, SCHEMA_2)}, None, 22),
        (0, 21, 0),
        {"a": "other"},
        False,
        False,
        23,
        23,
    ),
    (
        "a field state is taken whole, with the schema its bytes were written with",
        State({"a": f("old", 10, PHONE, SCHEMA_1), "b": f(1, 10, PHONE, SCHEMA_1)}, None, 11),
        State({"a": f("new", 20, TABLET, SCHEMA_2), "room": f("2", 20, TABLET, SCHEMA_2)}, None, 21),
        (0, 11, 0),
        {"a": "other", "b": "own", "room": "other"},
        False,
        False,
        22,
        22,
    ),
    (
        "the values are not looked at when the stamps differ: the later field state has the lower value",
        State({"a": f(9, 20, PHONE)}, None, 21),
        State({"a": f(1, 30, PHONE)}, None, 31),
        (0, 21, 0),
        {"a": "other"},
        False,
        False,
        32,
        32,
    ),
    (
        "the values are not looked at when the keys differ: the higher key has the lower value",
        State({"a": f(9, 20, PHONE)}, None, 21),
        State({"a": f(1, 20, TABLET)}, None, 22),
        (0, 21, 0),
        {"a": "other"},
        False,
        False,
        23,
        23,
    ),
    (
        "two names that differ only in their code points are two fields",
        State({"café": f(1, 10, PHONE)}, None, 11),
        State({"café": f(2, 12, TABLET)}, None, 13),
        (0, 11, 0),
        {"café": "own", "café": "other"},
        False,
        False,
        14,
        14,
    ),
    (
        "a stamped change is later than a field never stamped, whatever the keys",
        State({"a": f("counted", 0, TABLET)}, None, 3),
        State({"a": f("stamped", 1, PHONE)}, None, 2),
        (0, 3, 0),
        {"a": "other"},
        False,
        False,
        4,
        4,
    ),
    (
        "of two fields never stamped, the one with the higher key stands, with its stamp 0 and its key",
        State({"a": f("phone's default", 0, PHONE)}, None, 7),
        State({"a": f("tablet's default", 0, TABLET)}, None, 5),
        (0, 7, 0),
        {"a": "other"},
        False,
        False,
        8,
        8,
    ),
    (
        "a field state of unknown age, with the stamp -1, loses to a field never stamped, whatever the keys",
        State({"a": f("from a file", -1, TABLET)}, None, 7),
        State({"a": f("counted", 0, PHONE)}, None, 5),
        (0, 7, 0),
        {"a": "other"},
        False,
        False,
        8,
        8,
    ),
    (
        "a field state of unknown age loses to a stamped one, and a stamped one stays against it",
        State({"a": f("from a backup", -1, TABLET), "b": f("stamped", 1, PHONE)}, None, 7),
        State({"a": f("stamped", 1, PHONE), "b": f("from a file", -1, TABLET)}, None, 5),
        (0, 7, 0),
        {"a": "other", "b": "own"},
        False,
        False,
        8,
        8,
    ),
    (
        "of two field states of unknown age, the one with the higher key stands, with its stamp -1",
        State({"a": f("tablet's file", -1, TABLET)}, None, 7),
        State({"a": f("phone's file", -1, PHONE)}, None, 9),
        (0, 7, 0),
        {"a": "own"},
        False,
        False,
        7,
        9,
    ),
    (
        "of two field states of unknown age with one key, the one with the higher value stands",
        State({"a": f("file a", -1, PHONE)}, None, 7),
        State({"a": f("file b", -1, PHONE)}, None, 5),
        (0, 7, 0),
        {"a": "other"},
        False,
        False,
        8,
        8,
    ),
    (
        "a device without a state takes a state whose field state is of unknown age, with its stamp -1",
        None,
        State({"a": f("from a file", -1, PHONE)}, None, 3),
        (0, 0, 0),
        {"a": "other"},
        False,
        False,
        4,
        4,
    ),
    (
        "a removal is later than a field state of unknown age",
        State({"a": f("from a file", -1, TABLET)}, None, 7),
        State({}, gone(1, PHONE), 2),
        (0, 7, 0),
        {"a": "own"},
        True,
        True,
        8,
        8,
    ),
    (
        "a device without a state takes the other state and a state stamp",
        None,
        State({"a": f(1, 100, PHONE), "b": f(2, 0, PHONE)}, gone(90, PHONE), 101),
        (0, 0, 3),
        {"a": "other", "b": "other"},
        True,
        False,
        105,
        105,
    ),
    (
        "a device without a state takes a state stamp also for a state without field states and removal",
        None,
        State({}, None, 41),
        (0, 7, 0),
        {},
        False,
        False,
        42,
        42,
    ),
    (
        "a state without field states and removal changes nothing on a device that holds one",
        State({}, None, 41),
        State({}, None, 50),
        (0, 41, 0),
        {},
        False,
        False,
        41,
        50,
    ),
    (
        "the removal that only the other state holds is taken, and the record is deleted",
        State({"a": f(1, 10, PHONE)}, None, 11),
        State({"a": f(1, 10, PHONE)}, gone(20, TABLET), 21),
        (0, 11, 0),
        {"a": "own"},
        True,
        True,
        22,
        22,
    ),
    (
        "the removal that only the own state holds stays",
        State({"a": f(1, 10, PHONE)}, gone(20, PHONE), 21),
        State({"a": f(1, 10, PHONE)}, None, 11),
        (0, 21, 0),
        {"a": "own"},
        False,
        True,
        21,
        21,
    ),
    (
        "a removal that was taken back and that only the other state holds is taken as well",
        State({"a": f(1, 10, PHONE)}, None, 11),
        State({"a": f(1, 10, PHONE)}, back(30, TABLET), 31),
        (0, 11, 0),
        {"a": "own"},
        True,
        False,
        32,
        32,
    ),
    (
        "of two removals, the later one of the other state is taken",
        State({"a": f(1, 10, PHONE)}, gone(20, TABLET), 21),
        State({"a": f(1, 10, PHONE)}, gone(30, PHONE), 31),
        (0, 21, 0),
        {"a": "own"},
        True,
        True,
        32,
        32,
    ),
    (
        "of two removals, the later one of the own state stays",
        State({"a": f(1, 10, PHONE)}, gone(30, PHONE), 31),
        State({"a": f(1, 10, PHONE)}, gone(20, TABLET), 21),
        (0, 31, 0),
        {"a": "own"},
        False,
        True,
        31,
        31,
    ),
    (
        "of two removals with equal stamps, the one with the higher key is taken",
        State({"a": f(1, 10, PHONE)}, gone(20, PHONE), 21),
        State({"a": f(1, 10, PHONE)}, gone(20, TABLET), 22),
        (0, 21, 0),
        {"a": "own"},
        True,
        True,
        23,
        23,
    ),
    (
        "two removals that agree in stamp, key and standing are the same removal: nothing is taken",
        State({"a": f(1, 10, PHONE)}, gone(20, PHONE), 21),
        State({"a": f(1, 10, PHONE)}, gone(20, PHONE), 25),
        (0, 21, 0),
        {"a": "own"},
        False,
        True,
        21,
        25,
    ),
    (
        "a later removal that was taken back replaces the one that stands, and the record is there",
        State({"a": f(1, 10, PHONE)}, gone(20, PHONE), 21),
        State({"a": f(1, 10, PHONE)}, back(30, TABLET), 31),
        (0, 21, 0),
        {"a": "own"},
        True,
        False,
        32,
        32,
    ),
    (
        "a removal that stands is not replaced by an earlier one that was taken back",
        State({"a": f(1, 10, PHONE)}, gone(40, PHONE), 41),
        State({"a": f(1, 10, PHONE)}, back(30, TABLET), 31),
        (0, 41, 0),
        {"a": "own"},
        False,
        True,
        41,
        41,
    ),
    (
        "a later removal that stands deletes a record whose deletion was taken back before",
        State({"a": f(1, 10, PHONE)}, back(30, TABLET), 31),
        State({"a": f(1, 10, PHONE)}, gone(40, PHONE), 41),
        (0, 31, 0),
        {"a": "own"},
        True,
        True,
        42,
        42,
    ),
    (
        "of two removals with equal stamps, the higher key decides, also for the one that was taken back",
        State({"a": f(1, 10, PHONE)}, gone(20, PHONE), 21),
        State({"a": f(1, 10, PHONE)}, back(20, TABLET), 22),
        (0, 21, 0),
        {"a": "own"},
        True,
        False,
        23,
        23,
    ),
    (
        "of two removals with equal stamps and keys, the other one, which stands, is taken",
        State({"a": f(1, 10, PHONE)}, back(20, PHONE), 21),
        State({"a": f(1, 10, PHONE)}, gone(20, PHONE), 22),
        (0, 21, 0),
        {"a": "own"},
        True,
        True,
        23,
        23,
    ),
    (
        "of two removals with equal stamps and keys, the own one, which stands, stays",
        State({"a": f(1, 10, PHONE)}, gone(20, PHONE), 22),
        State({"a": f(1, 10, PHONE)}, back(20, PHONE), 21),
        (0, 22, 0),
        {"a": "own"},
        False,
        True,
        22,
        22,
    ),
    (
        "a record of a type without fields comes back by a removal that was taken back",
        State({}, gone(20, PHONE), 21),
        State({}, back(30, PHONE), 31),
        (0, 21, 0),
        {},
        True,
        False,
        32,
        32,
    ),
    (
        "a change after the deletion brings the record back, and the removal stays",
        State({"a": f(1, 10, PHONE), "b": f(2, 10, PHONE)}, gone(20, PHONE), 21),
        State({"a": f(1, 10, PHONE), "b": f(3, 25, TABLET)}, None, 26),
        (0, 21, 0),
        {"a": "own", "b": "other"},
        False,
        False,
        27,
        27,
    ),
    (
        "a deletion after the record came back deletes it again, in the place of the older removal",
        State({"a": f(1, 10, PHONE), "b": f(3, 25, TABLET)}, gone(20, PHONE), 27),
        State({"a": f(1, 10, PHONE), "b": f(3, 25, TABLET)}, gone(40, TABLET), 41),
        (0, 27, 0),
        {"a": "own", "b": "own"},
        True,
        True,
        42,
        42,
    ),
    (
        "a field state with the stamp of the removal and a higher key: the record is there",
        State({"a": f(1, 10, PHONE)}, gone(20, PHONE), 21),
        State({"a": f(2, 20, TABLET)}, None, 22),
        (0, 21, 0),
        {"a": "other"},
        False,
        False,
        23,
        23,
    ),
    (
        "a field state with the stamp of the removal and a lower key: the record is deleted",
        State({"a": f(1, 10, PHONE)}, gone(20, TABLET), 21),
        State({"a": f(2, 20, PHONE)}, None, 22),
        (0, 21, 0),
        {"a": "other"},
        False,
        True,
        23,
        23,
    ),
    (
        "a field that a sibling changed stays when a deletion is taken back: taking back stamps no field",
        State({"a": f(1, 10, PHONE), "b": f(2, 15, TABLET)}, gone(20, PHONE), 23),
        State({"a": f(1, 10, PHONE), "b": f(0, 10, PHONE)}, back(30, PHONE), 31),
        (0, 23, 0),
        {"a": "own", "b": "own"},
        True,
        False,
        32,
        32,
    ),
    (
        "a device that discarded the field states of a deleted record takes them again",
        State({}, gone(20, PHONE), 21),
        State({"a": f(1, 10, PHONE), "b": f(2, 12, TABLET)}, gone(20, PHONE), 24),
        (0, 21, 0),
        {"a": "other", "b": "other"},
        False,
        True,
        25,
        25,
    ),
    (
        "the new state stamp is above the state stamp of the other state",
        State({"a": f("x", 0, TABLET), "b": f(1, 10, PHONE)}, None, 11),
        State({"a": f("y", 0, PHONE), "b": f(2, 500, TABLET)}, None, 600),
        (0, 11, 0),
        {"a": "own", "b": "other"},
        False,
        False,
        601,
        601,
    ),
    (
        "the own removal stays while a field state of the other state is taken",
        State({"a": f(1, 10, PHONE)}, gone(700, TABLET), 701),
        State({"a": f(1, 10, PHONE), "b": f(2, 30, PHONE)}, gone(700, PHONE), 900),
        (0, 701, 9),
        {"a": "own", "b": "other"},
        False,
        True,
        910,
        910,
    ),
    (
        "the state stamp of the other state counts as seen when nothing is taken",
        State({"a": f(1, 10, PHONE)}, None, 11),
        State({"a": f(1, 10, PHONE)}, None, 5000),
        (0, 11, 0),
        {"a": "own"},
        False,
        False,
        11,
        5000,
    ),
    (
        "the state stamp is taken from the clock when the clock leads",
        State({"a": f(1, 10, PHONE)}, None, 11),
        State({"a": f(2, 12, TABLET)}, None, 13),
        (NOW, 11, 12_345),
        {"a": "other"},
        False,
        False,
        115_569_878_630_412_345,
        115_569_878_630_412_345,
    ),
    (
        "at the limit, the state stamp of a merge can be the largest long, from the last base",
        State({"a": f(1, 10, PHONE)}, None, 11),
        State({"a": f(2, LAST_BASE - 2, TABLET)}, None, LAST_BASE - 1),
        (0, 11, 32_767),
        {"a": "other"},
        False,
        False,
        MAX,
        MAX,
    ),
    (
        "at the limit, one above the last base, the device takes the field state and has no state stamp",
        State({"a": f(1, 10, PHONE)}, None, 11),
        State({"a": f(2, LAST_BASE - 1, TABLET)}, None, LAST_BASE),
        (0, 11, 0),
        {"a": "other"},
        False,
        False,
        None,
        LAST_BASE,
    ),
    (
        "at the limit, a device accepts the largest long as a stamp of a sibling and has no state stamp",
        State({"a": f(1, 10, PHONE)}, None, 11),
        State({"a": f(2, MAX, TABLET)}, None, None),
        (0, 11, 0),
        {"a": "other"},
        False,
        False,
        None,
        MAX,
    ),
    (
        "at the limit, a device that can take no stamp takes the removal and has no state stamp",
        State({"a": f(1, 10, PHONE)}, None, 11),
        State({"a": f(1, 10, PHONE)}, gone(20, TABLET), 21),
        (NOW, MAX, 0),
        {"a": "own"},
        True,
        True,
        None,
        MAX,
    ),
    (
        "at the limit, a device that can take no stamp keeps its state stamp when it takes nothing",
        State({"a": f(1, 10, PHONE)}, None, 11),
        State({"a": f(0, 9, TABLET)}, None, 10),
        (NOW, MAX, 0),
        {"a": "own"},
        False,
        False,
        11,
        MAX,
    ),
    (
        "at the limit, a device without a state that can take no stamp takes the state and no state stamp",
        None,
        State({"a": f(1, 10, PHONE)}, None, 11),
        (2**47, 0, 0),
        {"a": "other"},
        False,
        False,
        None,
        11,
    ),
]

# Whether a record is deleted, and its record message (sections 4.3 and 5.1): the case, the state, the
# field names of the writer schema or None for those of the state, whether the record is deleted, and
# the kind and the version, None where the device sends no record message.
DeletedCase = tuple[str, State, list[str] | None, bool, tuple[str, int] | None]
_TWO = {"start": f("10:30", 110, PHONE), "location": f(WEBER, 120, TABLET)}
DELETED: list[DeletedCase] = [
    ("no removal: there", State({"a": f(1, 10, PHONE)}, None, 11), None, False, ("DATA", 11)),
    (
        "a removal that was taken back: there, whatever the stamps of the field states",
        State({"a": f(1, 10, PHONE)}, back(20, PHONE), 21),
        None,
        False,
        ("DATA", 21),
    ),
    (
        "a removal that was taken back and no field state: there",
        State({}, back(20, PHONE), 21),
        None,
        False,
        ("DATA", 21),
    ),
    (
        "a removal that stands, and no field state: deleted",
        State({}, gone(1, PHONE), 2),
        None,
        True,
        ("DELETE", 2),
    ),
    (
        "a removal that stands and is later than every field state: deleted",
        State({"a": f(1, 10, PHONE), "b": f(2, 19, TABLET)}, gone(20, PHONE), 21),
        None,
        True,
        ("DELETE", 21),
    ),
    (
        "a removal that stands and is not later than one of the field states: there",
        State({"a": f(1, 10, PHONE), "b": f(2, 21, TABLET), "c": f(3, 5, PHONE)}, gone(20, PHONE), 22),
        None,
        False,
        ("DATA", 22),
    ),
    (
        "a removal with the stamp of a field state and the higher key: deleted",
        State({"a": f(1, 20, PHONE)}, gone(20, TABLET), 23),
        None,
        True,
        ("DELETE", 23),
    ),
    (
        "a removal with the stamp of a field state and the lower key: there",
        State({"a": f(1, 20, TABLET)}, gone(20, PHONE), 23),
        None,
        False,
        ("DATA", 23),
    ),
    (
        "a removal with the stamp of a field state and a key that is lower in the first byte, 7f below 80",
        State({"a": f(1, 20, K_80)}, gone(20, K_7F), 23),
        None,
        False,
        ("DATA", 23),
    ),
    (
        "a removal with the stamp and the key of a field state: there",
        State({"a": f(1, 20, PHONE)}, gone(20, PHONE), 23),
        None,
        False,
        ("DATA", 23),
    ),
    (
        "a removal with the stamp 1 is later than fields never stamped, whatever the keys",
        State({"a": f(1, 0, TABLET), "b": f(2, 0, TABLET)}, gone(1, PHONE), 2),
        None,
        True,
        ("DELETE", 2),
    ),
    ("a type without fields and no removal: there", State({}, None, 2), None, False, ("DATA", 2)),
    (
        "the version is the state stamp, not the highest field stamp",
        State(_TWO, None, 127),
        None,
        False,
        ("DATA", 127),
    ),
    (
        "a counted version stands in the place of the state stamp",
        State({"a": f(1, 0, PHONE)}, None, 3),
        None,
        False,
        ("DATA", 3),
    ),
    (
        "a record deleted while the installation counted: the counted version stays below the removal",
        State({"a": f(1, 0, PHONE)}, gone(115_569_878_630_412_345, PHONE), 4),
        None,
        True,
        ("DELETE", 4),
    ),
    (
        "a state for which the device could take no state stamp is not sent",
        State({"a": f(1, MAX, PHONE)}, None, None),
        None,
        False,
        None,
    ),
]

# The sending bar of section 5.1: the case, the state, the field names and the version of the writer
# schema the device writes with, whether the record is deleted, and the kind and the version, None where
# the device sends no record message. The field `room` is one that version 2 of the type adds.
SendingCase = tuple[str, State, list[str], int, bool, tuple[str, int] | None]
_ROOM = dict(_TWO, room=f("2", 125, TABLET, SCHEMA_2))
SENDING: list[SendingCase] = [
    (
        "no DATA with a writer schema that lacks a field whose stamped field state a later version wrote",
        State(_ROOM, None, 127),
        ["start", "location"],
        1,
        False,
        None,
    ),
    (
        "a stamped field state of an earlier version, whose field the writer schema removed, bars nothing",
        State(dict(_TWO, old=f("x", 125, TABLET, SCHEMA_1)), None, 127),
        ["start", "location", "room"],
        2,
        False,
        ("DATA", 127),
    ),
    (
        "a field state of a later version whose field the writer schema has bars nothing",
        State(_ROOM, None, 127),
        ["start", "location", "room"],
        1,
        False,
        ("DATA", 127),
    ),
    (
        "a field never stamped that the writer schema lacks does not hold the record back",
        State(dict(_TWO, room=f("", 0, TABLET, SCHEMA_2)), None, 127),
        ["start", "location"],
        1,
        False,
        ("DATA", 127),
    ),
    (
        "a writer schema with a field of which the device holds no field state",
        State(_TWO, None, 127),
        ["start", "location", "room"],
        2,
        False,
        ("DATA", 127),
    ),
    (
        "a DELETE is sent also with a writer schema that lacks a field of a later version",
        State(_ROOM, gone(126, PHONE), 127),
        ["start", "location"],
        1,
        True,
        ("DELETE", 127),
    ),
]

# Changes (sections 2.3 and 3.5): the case, the state before or None, the device, the action and its
# values, now_ms, highest and the two random parts, and the expected result written out from the
# table of section 3.5: whether the change is made, the state after it, and the highest stamp.
ChangeCase = tuple[
    str,
    State | None,
    bytes,
    str,
    dict[str, str | int],
    tuple[int, int, tuple[int, int]],
    bool,
    State | None,
    int,
]
_START = State({"title": f("Vet", 100, PHONE), "start": f(START, 100, PHONE), "location": f("", 100, PHONE)})
_AT_START = State(_START.fields, None, 101)
_GONE = State(_START.fields, gone(150, PHONE), 151)
_BACK = State(dict(_START.fields, location=f("Praxis", 160, TABLET)), gone(150, PHONE), 163)
_TAKEN_BACK = State(_START.fields, back(170, PHONE), 171)
CHANGES: list[ChangeCase] = [
    (
        "creating a record of a type without fields takes the same two stamps",
        None,
        PHONE,
        "create",
        {},
        (0, 0, (99, 0)),
        True,
        State({}, None, 101),
        101,
    ),
    (
        "a change of several fields in one step gives them one stamp, with the key of the changing device",
        _AT_START,
        TABLET,
        "set",
        {"title": "Vet with Mimi", "location": "Praxis"},
        (0, 105, (14, 3)),
        True,
        State(
            {
                "title": f("Vet with Mimi", 120, TABLET),
                "start": f(START, 100, PHONE),
                "location": f("Praxis", 120, TABLET),
            },
            None,
            124,
        ),
        124,
    ),
    (
        "a change of a field leaves a removal that was taken back as it is",
        _TAKEN_BACK,
        TABLET,
        "set",
        {"title": "Vet, Mimi"},
        (0, 175, (4, 0)),
        True,
        State(dict(_START.fields, title=f("Vet, Mimi", 180, TABLET)), back(170, PHONE), 181),
        181,
    ),
    (
        "a change of a field of a record that came back leaves the removal that stands as it is",
        _BACK,
        PHONE,
        "set",
        {"title": "Vet, Mimi"},
        (0, 163, (6, 0)),
        True,
        State(dict(_BACK.fields, title=f("Vet, Mimi", 170, PHONE)), gone(150, PHONE), 171),
        171,
    ),
    (
        "a deletion of a record that came back by a change replaces the removal",
        _BACK,
        TABLET,
        "delete",
        {},
        (0, 165, (4, 0)),
        True,
        State(_BACK.fields, gone(170, TABLET), 171),
        171,
    ),
    (
        "a deletion of a record whose deletion was taken back replaces the removal by one that stands",
        _TAKEN_BACK,
        TABLET,
        "delete",
        {},
        (0, 175, (4, 0)),
        True,
        State(_START.fields, gone(180, TABLET), 181),
        181,
    ),
    (
        "taking a deletion back on another device than the one that deleted: its key, and no field stamped",
        _GONE,
        TABLET,
        "take_back",
        {},
        (0, 155, (14, 0)),
        True,
        State(_START.fields, back(170, TABLET), 171),
        171,
    ),
    (
        "taking back the deletion of a record of a type without fields",
        State({}, gone(150, PHONE), 151),
        PHONE,
        "take_back",
        {},
        (0, 151, (18, 0)),
        True,
        State({}, back(170, PHONE), 171),
        171,
    ),
    (
        "at the limit, the last base at which a change begins: its state stamp can be the largest long",
        _AT_START,
        PHONE,
        "set",
        {"title": "x"},
        (0, LAST_CHANGE_BASE - 1, (32_767, 32_767)),
        True,
        State(dict(_START.fields, title=f("x", MAX - 32_768, PHONE)), None, MAX),
        MAX,
    ),
    (
        "at the limit, one above that base no change begins, also with the lowest random parts",
        _AT_START,
        PHONE,
        "set",
        {"title": "x"},
        (0, LAST_CHANGE_BASE, (0, 0)),
        False,
        _AT_START,
        LAST_CHANGE_BASE,
    ),
    (
        "at the limit, a device that could take one stamp more begins no deletion",
        _AT_START,
        PHONE,
        "delete",
        {},
        (0, LAST_BASE - 1, (0, 0)),
        False,
        _AT_START,
        LAST_BASE - 1,
    ),
    (
        "at the limit, a device that can take no stamp takes no deletion back",
        _GONE,
        PHONE,
        "take_back",
        {},
        (NOW, MAX, (0, 0)),
        False,
        _GONE,
        MAX,
    ),
    (
        "at the limit, a device whose clock is too far ahead creates no record",
        None,
        PHONE,
        "create",
        {"title": "Vet"},
        (2**47, 0, (0, 0)),
        False,
        None,
        0,
    ),
]

# Further changes: the case, the state before, the device, the action and its values, the schema the
# device writes with, now_ms, highest and the two random parts, the clock at the state stamp or None for
# the same clock, the version to pass the device keeps or None, and the expected result.
MoreChangeCase = tuple[
    str,
    State | None,
    bytes,
    str,
    dict[str, str | int],
    bytes,
    tuple[int, int, tuple[int, int]],
    int | None,
    int | None,
    Changed,
]
MORE_CHANGES: list[MoreChangeCase] = [
    (
        "a changed field carries the schema the changing device writes with, and the others keep theirs",
        _AT_START,
        TABLET,
        "set",
        {"title": "Vet, Mimi", "room": "2"},
        SCHEMA_2,
        (0, 105, (14, 0)),
        None,
        None,
        Changed(
            True,
            State(
                dict(
                    _START.fields,
                    title=f("Vet, Mimi", 120, TABLET, SCHEMA_2),
                    room=f("2", 120, TABLET, SCHEMA_2),
                ),
                None,
                121,
            ),
            121,
            None,
        ),
    ),
    (
        "a change gives the record a state stamp above the version to pass, which is dropped",
        _AT_START,
        PHONE,
        "set",
        {"title": "Vet, Mimi"},
        SCHEMA_1,
        (0, 500, (9, 0)),
        None,
        500,
        Changed(True, State(dict(_START.fields, title=f("Vet, Mimi", 510, PHONE)), None, 511), 511, None),
    ),
    (
        "at the limit, the clock moves on between the two stamps: the field keeps its stamp, no state stamp",
        _AT_START,
        PHONE,
        "set",
        {"title": "x"},
        SCHEMA_1,
        (0, 101, (8, 0)),
        2**47,
        500,
        Changed(True, State(dict(_START.fields, title=f("x", 110, PHONE)), None, None), 110, 500),
    ),
    (
        "at the limit, the clock moves on between the two stamps of a deletion: the removal keeps its stamp",
        _AT_START,
        PHONE,
        "delete",
        {},
        SCHEMA_1,
        (0, 101, (48, 0)),
        2**47,
        None,
        Changed(True, State(_START.fields, gone(150, PHONE), None), 150, None),
    ),
]

# What a device keeps for a record beside its state, in a merge (sections 3 and 5.3): the case, the own
# state, the other state, now_ms, highest and r, the highest sibling state stamp it has seen and the
# version to pass before, and both after the merge, with the state stamp.
KeptCase = tuple[str, State, State, tuple[int, int, int], int | None, int | None, int | None, int | None, int]
_OWN = State({"a": f(1, 10, PHONE)}, None, 130)
KEPT: list[KeptCase] = [
    (
        "the state stamp of the other state is the highest the device has seen from a sibling",
        _OWN,
        State({"a": f(1, 10, PHONE)}, None, 140),
        (0, 130, 0),
        127,
        None,
        140,
        None,
        130,
    ),
    (
        "a lower state stamp of the other state leaves the highest one the device has seen",
        _OWN,
        State({"a": f(1, 10, PHONE)}, None, 120),
        (0, 150, 0),
        140,
        None,
        140,
        None,
        130,
    ),
    (
        "a merge that takes nothing leaves the state stamp below the version to pass, which stays",
        _OWN,
        State({"a": f(1, 10, PHONE)}, None, 120),
        (0, 500, 0),
        None,
        500,
        120,
        500,
        130,
    ),
    (
        "a merge that takes a field state gives a state stamp above the version to pass, which is dropped",
        _OWN,
        State({"a": f(2, 480, TABLET)}, None, 481),
        (0, 500, 0),
        None,
        500,
        481,
        None,
        501,
    ),
]

# Beginning to stamp (section 2.4): the case, the device, the states of the records it deleted while it
# counted, now_ms, highest and the random parts, and the expected states and highest stamp.
BeginCase = tuple[str, bytes, list[State], tuple[int, int, list[int]], bool, list[State], int]
_COUNTED = [State({"a": f(1, 0, PHONE)}, None, 4), State({}, None, 2)]
BEGINNINGS: list[BeginCase] = [
    (
        "an installation that deleted no record while it counted takes no stamp",
        PHONE,
        [],
        (NOW, 3, []),
        True,
        [],
        3,
    ),
    (
        "one stamp for each record deleted while it counted; the counted versions stay",
        PHONE,
        _COUNTED,
        (NOW, 4, [12_345, 7]),
        True,
        [
            State({"a": f(1, 0, PHONE)}, gone(115_569_878_630_412_345, PHONE), 4),
            State({}, gone(115_569_878_630_412_353, PHONE), 2),
        ],
        115_569_878_630_412_353,
    ),
    (
        "at the limit, an installation that can take no stamp for a deleted record does not begin",
        PHONE,
        _COUNTED,
        (2**47, 4, [0, 0]),
        False,
        _COUNTED,
        4,
    ),
]

# After STALE (section 5.3): the case; the receiver's version; the device's state stamp of the record;
# the highest state stamp of the record it saw from a sibling, or None; the version to pass it keeps,
# or None; whether it counted until now; whether its set has other current devices; now_ms, highest
# and r; and the expected result.
StaleCase = tuple[str, int, int, int | None, int | None, bool, bool, tuple[int, int, int], AfterStale]
STALES: list[StaleCase] = [
    (
        "not above the device's own version: nothing more, and a device that counted goes on counting",
        3,
        3,
        None,
        None,
        True,
        False,
        (NOW, 3, 0),
        AfterStale(3, False, None, None),
    ),
    (
        "not above a state stamp the device saw from a sibling in a merge: nothing more",
        130,
        127,
        130,
        None,
        False,
        True,
        (0, 130, 0),
        AfterStale(130, True, None, None),
    ),
    (
        "above, with siblings: the version counts as seen and is kept as the version to pass",
        500,
        130,
        127,
        None,
        False,
        True,
        (0, 130, 0),
        AfterStale(500, True, 500, None),
    ),
    (
        "above, with siblings, below the device's highest stamp: highest stays",
        500,
        130,
        None,
        None,
        False,
        True,
        (0, 900, 0),
        AfterStale(900, True, 500, None),
    ),
    (
        "above, with siblings, and above the version to pass of an earlier STALE: the higher one is kept",
        700,
        130,
        None,
        500,
        False,
        True,
        (0, 500, 0),
        AfterStale(700, True, 700, None),
    ),
    (
        "above, with siblings, and below the version to pass of an earlier STALE: that one is kept",
        400,
        130,
        None,
        500,
        False,
        True,
        (0, 500, 0),
        AfterStale(500, True, 500, None),
    ),
    (
        "above, on the only device of a set, which counted: it stamps and sends again at once",
        9,
        2,
        None,
        None,
        True,
        False,
        (NOW, 4, 12_345),
        AfterStale(115_569_878_630_412_345, True, None, 115_569_878_630_412_345),
    ),
    (
        "above, on the only device of a set whose clock is behind: the new state stamp is above it",
        SIBLING,
        115_569_878_630_412_353,
        None,
        None,
        False,
        False,
        (NOW + 1, 115_569_878_630_412_353, 100),
        AfterStale(115_570_114_560_020_101, True, None, 115_570_114_560_020_101),
    ),
    (
        "at the limit, the largest long as a version: the only device sends nothing and keeps it to pass",
        MAX,
        5,
        None,
        None,
        False,
        False,
        (NOW, 6, 0),
        AfterStale(MAX, True, MAX, None),
    ),
]

# After STALE on the only current device of a set that section 5.1 forbids to send the record: the
# case, the receiver's version, the device's state stamp, the version to pass it keeps, now_ms, highest
# and r, and the expected result: it sends nothing and keeps the version to pass.
BarredCase = tuple[str, int, int, int | None, tuple[int, int, int], AfterStale]
BARRED: list[BarredCase] = [
    (
        "above, on the only device of a set, which may not send the record: nothing is sent",
        500,
        130,
        None,
        (0, 130, 9),
        AfterStale(500, True, 500, None),
    ),
]

# The version to pass, once the device has merged with every other current device of its set, or has
# waited 14 days (section 5.3): the case, its state stamp, the version to pass, whether section 5.1 lets
# it send the record, now_ms, highest and r, and the new state stamp under which it sends again, or
# None, the version to pass it keeps, or None, and its highest stamp.
PassCase = tuple[str, int, int, bool, tuple[int, int, int], int | None, int | None, int]
PASSES: list[PassCase] = [
    (
        "the state stamp is still below the version to pass: a new state stamp, and the record is sent",
        130,
        500,
        True,
        (0, 500, 9),
        510,
        None,
        510,
    ),
    (
        "a merge gave the device a state stamp above the version to pass: no new state stamp",
        520,
        500,
        True,
        (0, 520, 9),
        None,
        None,
        520,
    ),
    (
        "the state stamp is below the version to pass, and the clock leads",
        130,
        500,
        True,
        (NOW, 500, 12_345),
        115_569_878_630_412_345,
        None,
        115_569_878_630_412_345,
    ),
    (
        "below the version to pass on a device that may not send the record: nothing, and it is kept",
        130,
        500,
        False,
        (0, 500, 9),
        None,
        500,
        500,
    ),
    (
        "at the limit, below the version to pass on a device that can take no stamp: it is kept",
        130,
        MAX,
        True,
        (NOW, MAX, 0),
        None,
        MAX,
        MAX,
    ),
]


def check_cases(out: list[str]) -> None:
    """The further cases: the model reaches each result that is written out from the rules."""
    for label, a, b, order in KEY_ORDERS:
        assert key_order(a, b) == order and key_order(b, a) == -order, label
        assert (a > b) - (a < b) == order, label  # Python compares bytes in the same way
    for label, x, y, x_hex, y_hex, order in VALUE_ORDERS:
        assert not x_hex or (encoded(x).hex(), encoded(y).hex()) == (x_hex, y_hex), label
        assert bytes_order(encoded(x), encoded(y)) == order == -bytes_order(encoded(y), encoded(x)), label
    assert bytes_order(b"\x02", b"\x02\x61") == -1 and bytes_order(b"", b"") == 0  # a beginning is lower
    for label, own, other, (now_ms, highest, r), stands, removal_taken, is_gone, stamp, top in MERGES:
        done = device_merge(own, other, now_ms, highest, r)
        got = (done.merged.stands, done.merged.removal_taken, done.deleted, done.state.state_stamp)
        assert (*got, done.highest) == (stands, removal_taken, is_gone, stamp, top), (
            label,
            got,
            done.highest,
        )
        for name, side in stands.items():
            source = own if side == "own" else other
            assert source is not None and done.state.fields[name] is source.fields[name], (label, name)
    for label, state, _, is_gone, message in DELETED:
        assert deleted(state.fields, state.removal) == is_gone, label
        assert record_message(state) == message, label
    for label, state, writer_fields, version, is_gone, message in SENDING:
        assert deleted(state.fields, state.removal) == is_gone, label
        assert record_message(state, writer_fields, version) == message, label
    for label, before, device, action, values, (now_ms, highest, rr), made, after, top in CHANGES:
        coded = {name: encoded(value) for name, value in values.items()}
        changed = change(before, device, action, coded, now_ms, highest, rr)
        assert (changed.made, changed.state, changed.highest) == (made, after, top), (label, changed)
    for (
        label,
        before,
        device,
        action,
        values,
        schema,
        change_clock,
        later_clock,
        to_pass,
        want_change,
    ) in MORE_CHANGES:
        coded = {name: encoded(value) for name, value in values.items()}
        changed = change(before, device, action, coded, *change_clock, schema, later_clock, to_pass)
        assert changed == want_change, (label, changed)
    for label, own, other, clock, seen_before, pass_before, seen_after, pass_after, stamp in KEPT:
        done = device_merge(own, other, *clock, seen_before, pass_before)
        got_kept = (done.sibling_stamp, done.to_pass, done.state.state_stamp)
        assert got_kept == (seen_after, pass_after, stamp), (label, got_kept)
    for label, device, states, (now_ms, highest, rs), begun, after_states, top in BEGINNINGS:
        assert begin_stamping(device, states, now_ms, highest, rs) == (begun, after_states, top), label
    for label, version, own_stamp, sibling_stamp, to_pass, counted, sibling, clock, want in STALES:
        assert stale(version, own_stamp, sibling_stamp, to_pass, counted, sibling, *clock) == want, label
    for label, version, own_stamp, to_pass, clock, want in BARRED:
        assert stale(version, own_stamp, None, to_pass, False, False, *clock, may_send=False) == want, label
    for label, own_stamp, to_pass, may_send, clock, resend, kept, top in PASSES:
        assert pass_version(own_stamp, to_pass, may_send, *clock) == (resend, kept, top), label
        assert resend is None or resend > to_pass  # so the receiver applies the state
    out.append(
        f"Further cases: {len(MORE_STAMPS)} stamps, {len(KEY_ORDERS)} orders of keys, {len(VALUE_ORDERS)} "
        f"orders of values, {len(MERGES) + len(KEPT)} merges, {len(DELETED) + len(SENDING)} states, "
        f"{len(CHANGES) + len(MORE_CHANGES)} changes, {len(BEGINNINGS)} beginnings, "
        f"{len(STALES) + len(BARRED)} cases of STALE, {len(PASSES)} versions to pass"
    )


# --- properties, over generated cases ----------------------------------------------------------------------


class Draw:
    """Numbers from SHA-256 over a seed and a counter: the same in every run, and no random generator."""

    def __init__(self, seed: str) -> None:
        self.seed, self.n = seed.encode(), 0

    def below(self, n: int) -> int:
        """A number from 0 to n - 1."""
        self.n += 1
        digest = hashlib.sha256(self.seed + b"/" + str(self.n).encode()).digest()
        return int.from_bytes(digest, "big") % n


PROPERTY_KEYS = [PHONE, TABLET, K_7F, K_80, K_LAST_0, K_LAST_1]
PROPERTY_NAMES = ["a", "b", "c", "d", "é"]
# Few values, among them one whose bytes begin another's, so that equal stamps and keys meet both
# equal and different values, as after a restore (section 2.4).
PROPERTY_VALUES = [bytes.fromhex(h) for h in ("02", "0261", "026100", "8001", "7e")]


def drawn_state(d: Draw) -> State:
    """A state with few stamps, keys and values, so that every tie of sections 4.1 and 4.2 arises:
    equal stamps, equal stamps and keys, and equal stamps, keys and values or standing."""
    fields: dict[str, FieldState] = {}
    for name in PROPERTY_NAMES:
        if d.below(4):
            key = PROPERTY_KEYS[d.below(len(PROPERTY_KEYS))]
            schema = (SCHEMA_1, SCHEMA_2)[d.below(2)]
            value = PROPERTY_VALUES[d.below(len(PROPERTY_VALUES))]
            fields[name] = FieldState(value, d.below(4), key, schema)
    removal = None
    if d.below(3):
        removal = Removal(1 + d.below(3), PROPERTY_KEYS[d.below(len(PROPERTY_KEYS))], bool(d.below(2)))
    return State(fields, removal, 4 + d.below(20))


def plain(m: Merged) -> State:
    return State(m.fields, m.removal)


def check_properties(out: list[str]) -> None:
    """Section 4.5, the state stamp of section 3.3, and the next stamp of section 2.2."""
    d = Draw("AXT sync_examples, properties of the merge")
    rounds = 6000
    took = value_ties = removal_ties = schema_ties = 0
    for _ in range(rounds):
        a, b, c = drawn_state(d), drawn_state(d), drawn_state(d)
        ab, ba = merge(a, b), merge(b, a)
        for name in set(a.fields) & set(b.fields):
            x, y = a.fields[name], b.fields[name]
            value_ties += (x.stamp, x.device) == (y.stamp, y.device) and x.value != y.value
        if a.removal and b.removal and a.removal != b.removal:
            removal_ties += (a.removal.stamp, a.removal.device) == (b.removal.stamp, b.removal.device)
        # Commutative: whichever of the two states is the device's own.
        # Both hold the same field states, their schemas included, and the same removal.
        assert (ab.fields, ab.removal) == (ba.fields, ba.removal), (a, b)
        for name in set(a.fields) & set(b.fields):
            x, y = a.fields[name], b.fields[name]
            if (x.stamp, x.device, x.value) == (y.stamp, y.device, y.value) and x.schema != y.schema:
                schema_ties += 1  # the last step of rule 3 decides
                assert ab.fields[name].schema == max(x.schema, y.schema) == SCHEMA_1
        assert deleted(ab.fields, ab.removal) == deleted(ba.fields, ba.removal)
        # Associative: the order in which states are merged.
        left, right = merge(plain(ab), c), merge(a, plain(merge(b, c)))
        assert (left.fields, left.removal) == (right.fields, right.removal), (a, b, c)
        # The second way: the latest of all, for each name and for the removal.
        assert (left.fields, left.removal) == merge_latest([a, b, c])
        assert (ab.fields, ab.removal) == merge_latest([b, a])
        # Idempotent: merging a state a second time takes nothing and changes nothing.
        again = merge(plain(ab), b)
        assert not again.took and (again.fields, again.removal) == (ab.fields, ab.removal), (a, b)
        assert not merge(a, a).took and merge(a, a).fields == a.fields
        # A device takes something exactly when the merged state is not its own.
        assert ab.took == ((ab.fields, ab.removal) != (a.fields, a.removal))
        took += ab.took
        # A device without a state ends with the other state.
        assert (merge(None, a).fields, merge(None, a).removal) == (a.fields, a.removal)
        # The exception of section 4.5: a device that discarded the field states of a deleted record
        # holds the same removal after a merge and agrees on whether the record is deleted.
        if deleted(a.fields, a.removal):
            bare = merge(State({}, a.removal), b)
            assert bare.removal == ab.removal
            assert deleted(bare.fields, bare.removal) == deleted(ab.fields, ab.removal), (a, b)
        # Section 3.5: a removal that was taken back has a higher stamp than the one it replaces, so
        # it is the later of the two in every merge, and the record is there.
        if deleted(a.fields, a.removal):
            highest = max(seen(a), d.below(40))
            taken = change(a, PROPERTY_KEYS[d.below(2)], "take_back", {}, 0, highest, (d.below(9), 0))
            assert taken.state is not None and taken.state.removal is not None
            for one, two in ((a, taken.state), (taken.state, a)):
                m = merge(one, two)
                assert m.removal == taken.state.removal and not deleted(m.fields, m.removal)
        # Section 4.4 with section 3.3: a new state stamp is above every stamp of the merged state,
        # above the device's state stamp before and above the other's; no stamp is taken for nothing.
        highest = max(seen(a), d.below(40))
        now_ms = (-1, 0, 0, NOW)[d.below(4)]
        done = device_merge(a, b, now_ms, highest, d.below(R_MAX + 1))
        assert done.merged.took == ab.took and done.highest >= max(highest, seen(b))
        if ab.took:
            new = done.state.state_stamp
            assert new is not None and new == done.highest
            assert new > max(seen(a), seen(b), seen(State(done.state.fields, done.state.removal)))
        else:
            assert done.state.state_stamp == a.state_stamp and done.highest == max(highest, seen(b))
    assert rounds // 4 < took < rounds, took  # the cases are not all of one kind
    assert value_ties > 50 and removal_ties > 50 and schema_ties > 5, (value_ties, removal_ties, schema_ties)
    # The order of bytes: both ways agree.
    for _ in range(rounds):
        p, q = (bytes(d.below(3) for _ in range(d.below(4))) for _ in range(2))
        assert bytes_order(p, q) == (p > q) - (p < q) == -bytes_order(q, p)
    # The next stamp: both ways agree; a stamp is above highest and at most the largest long; whether
    # there is one does not depend on r; a device that can begin a change can take both its stamps.
    d = Draw("AXT sync_examples, properties of the next stamp")
    edges = [MIN, -(2**47) - 1, -1, 0, 1, NOW, 2**47 - 1, 2**47, 2**48, MAX]
    tops = [
        0,
        1,
        NOW * 65536 - 1,
        NOW * 65536,
        (2**47 - 1) * 65536,
        LAST_CHANGE_BASE,
        LAST_BASE,
        MAX - 1,
        MAX,
    ]
    stamped = 0
    for _ in range(rounds):
        now_ms = edges[d.below(len(edges))] + d.below(3) - 1
        highest = tops[d.below(len(tops))] + d.below(3) - 1
        now_ms, highest = min(max(now_ms, MIN), MAX), min(max(highest, 0), MAX)
        r = (0, 1, R_MAX, d.below(R_MAX + 1))[d.below(4)]
        got = next_stamp(now_ms, highest, r)
        assert got == next_stamp_by_cases(now_ms, highest, r), (now_ms, highest, r)
        assert (
            (got is None)
            == (next_stamp(now_ms, highest, 0) is None)
            == (next_stamp(now_ms, highest, R_MAX) is None)
        )
        if got is not None:
            stamped += 1
            assert highest < got <= MAX and got >= 1
            if now_ms < 2**47 and highest < now_ms * 65536:
                assert got == now_ms * 65536 + r  # while the clock leads, the stamp shows the time
        if can_begin_change(now_ms, highest):
            assert got is not None and next_stamp(now_ms, got, R_MAX) is not None
        elif got is not None:
            assert next_stamp(now_ms, max(now_ms * 65536, highest + 1) + R_MAX, 0) is None
    assert rounds // 4 < stamped < rounds, stamped
    out.append(
        f"Properties: {rounds} generated triples of states, of which {took} first merges took something, "
        f"{value_ties} met two values under one stamp and key and {removal_ties} two removals under one "
        f"stamp and key; {rounds} generated next stamps, {stamped} of them a stamp"
    )
    out.append(
        f"  In {schema_ties} merges two field states agreed in stamp, key and bytes and differed in the "
        "schema, and the higher schema stood on both devices"
    )


# --- the schemas of the messages (sections 8.1, 11.1 and 15) -------------------------------------------

AXT = REPO / "types" / "axt"
SPEC_NAMES = ("Envelope", "Manifest", "Offer", "Accept", "Decline", "Ack", "Error", "Change", "Resync")
SPEC_TEXT = {n: (AXT / f"{n}.avsc").read_text(encoding="utf-8") for n in SPEC_NAMES}


def without_logical_types(t: Any) -> Any:
    """A schema without its logical types, so that an id is read as the text it is."""
    if isinstance(t, list):
        return [without_logical_types(b) for b in t]
    if isinstance(t, dict):
        t = {k: without_logical_types(v) for k, v in t.items() if k != "logicalType"}
        if set(t) == {"type"} and isinstance(t["type"], str):
            return t["type"]
    return t


SPEC = {
    n: fastavro.parse_schema(without_logical_types(json.loads(t)), _write_hint=False)
    for n, t in SPEC_TEXT.items()
}
SPEC_FP = {n: schema_fingerprint(t) for n, t in SPEC_TEXT.items()}
KINDS: list[str] = json.loads(SPEC_TEXT["Envelope"])["fields"][1]["type"]["symbols"]
BODY_OF = {
    "OFFER": "Offer",
    "ACCEPT": "Accept",
    "DECLINE": "Decline",
    "ACK": "Ack",
    "ERROR": "Error",
    "CHANGE": "Change",
    "RESYNC": "Resync",
}
MARKER = b"\xc3\x01"  # the marker of a single-object encoding (spec/envelope.md, section 3)
MAX_MESSAGE = 16777216  # spec/envelope.md, section 8
MAX_FIELDS = 4096  # entries of `fields` in one CHANGE (section 14)
MAX_NAME = 512  # bytes of `type` and of one `name` (section 14)
MAX_ACK_RECORDS = 4096
MAX_OFFER_TYPES = 256  # spec/protocol.md, section 4.2
MAX_DATA_DEPTH = 32  # spec/types.md, section 5.7
MAX_ERROR_RECORD_ID = 64  # bytes of the id in the record of an ERROR (spec/protocol.md, section 8.1)
UUID_TEXT = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
FULL_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$")
CHANGE_OUTCOMES = ("APPLIED", "DUPLICATE", "STALE")


def body_of(name: str, datum: dict[str, Any]) -> bytes:
    """A body of the specification in single-object encoding (spec/envelope.md, section 2.3)."""
    out = io.BytesIO()
    fastavro.schemaless_writer(out, SPEC[name], datum)
    return MARKER + SPEC_FP[name] + out.getvalue()


def message(seed: bytes, kind: str, record: tuple[str, int] | None, body: bytes) -> bytes:
    """A live message of envelope format 1, signed with the key of `seed` (spec/keys.md, section 2.2)."""
    envelope = {
        "format": 1,
        "kind": kind,
        "sender": bytes(keys.public_key(seed)),
        "record": None if record is None else {"id": record[0], "version": record[1]},
        "body": body,
        "signature": bytes(64),
    }
    out = io.BytesIO()
    fastavro.schemaless_writer(out, SPEC["Envelope"], envelope)
    unsigned = out.getvalue()[:-64]
    return MARKER + SPEC_FP["Envelope"] + unsigned + bytes(keys.sign(seed, keys.MESSAGE_PREFIX + unsigned))


def read_all(name: str, data: bytes) -> Any:
    """One datum of a schema of the specification, with no bytes left over; ValueError otherwise."""
    buf = io.BytesIO(data)
    try:
        datum = fastavro.schemaless_reader(buf, SPEC[name], SPEC[name])
    except Exception as e:
        raise ValueError(f"not an axt.{name}: {type(e).__name__}") from None
    if buf.tell() != len(data):
        raise ValueError(f"bytes left over after the axt.{name}")
    return datum


def uuid_key(text: str) -> int | None:
    """An id as its 128-bit value (spec/envelope.md, section 7); None for a text that is no UUID, and for
    the nil and the max UUID (spec/records.md, section 2)."""
    if not UUID_TEXT.match(text):
        return None
    value = int(text.replace("-", ""), 16)
    return None if value in (0, 2**128 - 1) else value


def full_name(schema: Any) -> str | None:
    """The full name of a record schema, or None for a schema that is no record."""
    if (
        not isinstance(schema, dict)
        or schema.get("type") != "record"
        or not isinstance(schema.get("name"), str)
    ):
        return None
    name: str = schema["name"]
    return name if "." in name else f"{schema.get('namespace', '')}.{name}".lstrip(".")


# --- the value of one field (sections 3.1, 8.3 and 13.4) ------------------------------------------------

PRIMITIVES = {"null", "boolean", "int", "long", "float", "double", "bytes", "string"}


def _named(t: dict[str, Any], namespace: str) -> tuple[str, str]:
    """The full name of a named type and the namespace it gives to the names inside it."""
    name: str = t["name"]
    if "." in name:
        return name, name.rsplit(".", 1)[0]
    ns: str = t.get("namespace", namespace)
    return (f"{ns}.{name}" if ns else name), ns


def _definitions(t: Any, namespace: str, out: dict[str, tuple[dict[str, Any], str]]) -> None:
    """Every named type that a schema defines, by its full name, with the namespace around it."""
    if isinstance(t, list):
        for branch in t:
            _definitions(branch, namespace, out)
    elif isinstance(t, dict):
        kind = t.get("type")
        if kind in ("record", "enum", "fixed"):
            full, inner = _named(t, namespace)
            out.setdefault(full, (t, namespace))
            for field in t.get("fields", []) if kind == "record" else []:
                _definitions(field["type"], inner, out)
        elif kind == "array":
            _definitions(t["items"], namespace, out)
        elif kind == "map":
            _definitions(t["values"], namespace, out)
        else:
            _definitions(kind, namespace, out)


def _alone(t: Any, namespace: str, defs: dict[str, tuple[dict[str, Any], str]], done: set[str]) -> Any:
    """A type that stands alone: a name that an earlier field of its record defines is replaced by its
    definition, where it first appears."""
    if isinstance(t, list):
        return [_alone(branch, namespace, defs, done) for branch in t]
    if isinstance(t, str):
        if t in PRIMITIVES:
            return t
        full = t if "." in t or not namespace else f"{namespace}.{t}"
        if full in done or full not in defs:
            return full
        definition, around = defs[full]
        return _alone(definition, around, defs, done)
    kind = t.get("type")
    if kind in ("record", "enum", "fixed"):
        full, inner = _named(t, namespace)
        done.add(full)
        out = {**t, "name": full}
        out.pop("namespace", None)
        if kind == "record":
            out["fields"] = [{**f, "type": _alone(f["type"], inner, defs, done)} for f in t["fields"]]
        return out
    if kind == "array":
        return {**t, "items": _alone(t["items"], namespace, defs, done)}
    if kind == "map":
        return {**t, "values": _alone(t["values"], namespace, defs, done)}
    return {**t, "type": _alone(kind, namespace, defs, done)}


def field_schema(schema: dict[str, Any], name: str) -> dict[str, Any] | None:
    """A record schema that holds the top-level field `name` of the record schema alone, with the type
    the field has there; None if the schema has no such field. The Avro binary encoding of a record is
    that of its fields one after the other, so the encoding of this record is the value of the field."""
    field = next((f for f in schema["fields"] if f["name"] == name), None)
    if field is None:
        return None
    defs: dict[str, tuple[dict[str, Any], str]] = {}
    _definitions(schema, "", defs)
    _, inner = _named(schema, "")
    one = {"name": name, "type": _alone(field["type"], inner, defs, set())}
    return {"type": "record", "name": "axt_sync_examples.OneField", "fields": [one]}


def data_depth(value: Any) -> int:
    """The data depth of spec/types.md, section 5.7, of a decoded value: records, arrays and maps count."""
    if isinstance(value, dict):
        return 1 + max([data_depth(v) for v in value.values()], default=0)
    if isinstance(value, list):
        return 1 + max([data_depth(v) for v in value], default=0)
    return 0


def read_field(schema: dict[str, Any], name: str, buf: io.BytesIO) -> tuple[dict[str, Any], Any]:
    """Read the value of the field `name` of the schema from the buffer: the schema of the field alone
    and the record that holds the value. ValueError for bytes that do not decode as one value of the
    field's type, with well-formed strings, or that go deeper than 32 (section 8.3, step 11)."""
    one = field_schema(schema, name)
    assert one is not None, name
    try:
        parsed = fastavro.parse_schema(one, _write_hint=False)
        value = fastavro.schemaless_reader(buf, parsed, parsed)
    except Exception as e:
        raise ValueError(f"{name} does not decode: {type(e).__name__}") from None
    if data_depth(value) > MAX_DATA_DEPTH:
        raise ValueError(f"{name}: data depth above 32")
    return one, value


def field_value(schema: dict[str, Any], name: str, value: Any) -> bytes:
    """The value of one field in Avro binary encoding, under the type the field has in the schema: the
    `value` of a field state (section 3.1). fastavro and the Apache avro package give the same bytes."""
    one = field_schema(schema, name)
    assert one is not None, name
    out = io.BytesIO()
    fastavro.schemaless_writer(out, fastavro.parse_schema(one, _write_hint=False), {name: value})
    other = io.BytesIO()
    avro.io.DatumWriter(avro.schema.parse(json.dumps(one))).write({name: value}, avro.io.BinaryEncoder(other))
    assert out.getvalue() == other.getvalue(), name
    return out.getvalue()


# --- the body of a CHANGE (sections 8.1 and 8.2) ---------------------------------------------------------


def change_version(d: dict[str, Any]) -> int:
    """`record.version` of a CHANGE: the highest stamp in the message (section 8.1)."""
    stamps = [d["state"], *(f["stamp"] for f in d["fields"])]
    if d["removal"] is not None:
        stamps.append(d["removal"]["stamp"])
    return int(max(stamps))


def change_problem(d: dict[str, Any], version: int) -> str | None:
    """The rule of section 8.2 that the body of a CHANGE breaks, or None for a valid body."""
    if d["origin"] is not None:
        return "origin is a key"
    if not FULL_NAME.match(d["type"]) or len(d["type"].encode()) > MAX_NAME:
        return "type is not a full name of at most 512 bytes"
    if d["state"] < 1:
        return "state is below 1"
    if d["removal"] is not None and d["removal"]["stamp"] < 1:
        return "the stamp of the removal is below 1"
    if len(d["fields"]) > MAX_FIELDS:
        return "more than 4,096 entries in fields"
    names = [f["name"] for f in d["fields"]]
    if any(not 1 <= len(n.encode()) <= MAX_NAME for n in names):
        return "a name of 0 or of more than 512 bytes"
    if len(set(names)) != len(names):
        return "a name twice"
    if any(f["value"] is None for f in d["fields"]):
        return "a null value"
    if any(f["stamp"] < -1 for f in d["fields"]):
        return "a stamp of a field state below -1"
    if not d["whole"] and not d["fields"] and d["removal"] is None:
        return "not whole, and the message carries nothing"
    if version != change_version(d):
        return "record.version is not the highest stamp in the message"
    return None


def ack_problem(d: dict[str, Any]) -> str | None:
    """Why the ACK of a sibling is not valid (section 9.1), or None."""
    if not 1 <= len(d["records"]) <= MAX_ACK_RECORDS:
        return "not 1 to 4,096 entries"
    met = set()
    for entry in d["records"]:
        key = uuid_key(entry["id"])
        if key is None or entry["version"] < 1:
            return "an id that is no UUID, or a version below 1"
        if (key, entry["version"]) in met:
            return "an id and version twice"
        met.add((key, entry["version"]))
        if entry["outcome"] not in CHANGE_OUTCOMES:
            return f"the outcome {entry['outcome']} is never that of a CHANGE"
        if entry["receiver_version"] < 1:
            return "a receiver_version below 1"
        if entry["kept_fields"]:
            return "kept fields"
    return None


# --- one device of a set and its siblings (sections 7 to 13) --------------------------------------------

KEEP_DAYS = 15  # how long a device keeps a CHANGE it sent, for its outcome (section 10.1)
HOLDING_DAYS = 14  # the holding time of a relay (spec/transports.md, section 5.5)


@dataclass(frozen=True)
class Content:
    """What a CHANGE of a record carries besides its state stamp (section 10.2)."""

    whole: bool
    removal: Removal | None
    fields: frozenset[tuple[str, FieldState]]

    @property
    def marks(self) -> frozenset[Any]:
        """The parts as a device keeps them for a CHANGE it sent (section 10.1): each field state by all
        it holds, where a device may keep a hash in the place of the value, and the removal."""
        return self.fields if self.removal is None else self.fields | {self.removal}


@dataclass
class Held:
    """A record of the set on a device: the full name of its type, its state, and what the device keeps
    beside the state (section 3)."""

    type: str
    state: State
    sibling_stamp: int | None = None
    to_pass: int | None = None
    incomplete: bool = False  # whether the device holds the record incompletely (section 4.3)
    restored: bool = False  # no CHANGE of it has gone since a restore (section 3.3, occasion 7)
    # The field states never stamped that it held when the device restored a backup (section 12.1).
    unstamped: dict[str, FieldState] = dataclasses.field(default_factory=dict)


@dataclass
class Kept:
    """What a device keeps for one sibling and one record (section 10.1), and what it needs to follow
    sections 10.2 and 10.3."""

    known: bool = False
    delivered: set[Any] = dataclasses.field(default_factory=set)
    last: tuple[int, Content] | None = None  # the CHANGE last sent, with the state stamp it went under
    flight: tuple[int, int] | None = None  # id and version of the CHANGE last sent
    want: bool = True  # whether the device has a reason of section 10.3 to send a CHANGE of the record
    settled: int | None = None  # the state stamp at which an error settled the last CHANGE (section 9.3)
    barred: bool = False  # RECORD_UNKNOWN for a record the device holds incompletely (section 10.2)
    fresh: bool = False  # no CHANGE of it has gone since a RESYNC of the sibling (section 3.3, occasion 6)


class Reject(Exception):
    """A message that fails a check, with the error code that reports it."""

    def __init__(
        self,
        code: str,
        detail: str = "",
        fingerprint: bytes | None = None,
        field: str | None = None,
        report: bool = True,
    ) -> None:
        super().__init__(f"{code}: {detail}")
        self.code, self.detail, self.fingerprint, self.field, self.report = (
            code,
            detail,
            fingerprint,
            field,
            report,
        )


class SetDevice:
    """One device of a device set, with the records of the set, its siblings and what it keeps for each
    of them. It processes the messages of its siblings by sections 7 to 13 and gives back the messages
    it sends. Every sibling has a channel to it, a live connection in which both manifests have been
    exchanged or, for the siblings named so, the relay; the envelope, the size and the signature of a
    message are those of spec/protocol.md, whose model is in protocol_examples.py, so a message that
    fails there is dropped here without a report.

    A device sends a CHANGE of a record to a sibling when one of the reasons of section 10.3 holds, and
    not otherwise. It makes one offer for each schema, with the ids it is given, gives its requests the
    ids it is given, and takes its stamps at the clock and with the random parts it is given, sibling by
    sibling in the order of their keys and record by record in the order of their ids. Its time is
    counted in whole days."""

    def __init__(
        self,
        seed: bytes,
        siblings: list[bytes],
        schemas: list[str],
        highest: int = 0,
        removed: list[bytes] | None = None,
        others: list[bytes] | None = None,
        gone: list[bytes] | None = None,
        offer_ids: list[str] | None = None,
        request_ids: list[str] | None = None,
        relay: list[bytes] | None = None,
    ) -> None:
        self.seed, self.key = seed, bytes(keys.public_key(seed))
        self.siblings = list(siblings)
        self.relay = set(relay or [])  # the siblings it reaches through the relay
        self.removed = set(removed or [])  # the removed keys of the device's own set
        self.others = set(others or [])  # the current keys of the other senders it knows
        self.gone = set(gone or [])  # the removed keys of other senders, and the refused keys
        self.schemas = {
            schema_fingerprint(t): t for t in schemas
        }  # its own, and those kept with field states
        self.offered: dict[bytes, dict[bytes, str]] = {s: {} for s in siblings}  # by the offers of a sibling
        self.accepted: dict[bytes, set[bytes]] = {s: set() for s in siblings}  # its own offers, accepted
        self.declined: dict[bytes, set[bytes]] = {s: set() for s in siblings}
        self.pending: dict[bytes, dict[int, tuple[bytes, str]]] = {s: {} for s in siblings}
        self.offer_ids, self.request_ids = list(offer_ids or []), list(request_ids or [])
        self.highest = highest
        self.records: dict[int, Held] = {}
        self.ids: dict[int, str] = {}  # the id of each record as text
        self.kept: dict[tuple[bytes, int], Kept] = {}
        # The CHANGE messages it sent that have neither an outcome nor a settling error, by id and
        # version: the parts each held, and the day it last went (section 10.1).
        self.sent: dict[bytes, dict[tuple[int, int], tuple[frozenset[Any], int]]] = {s: {} for s in siblings}
        self.acks: dict[bytes, list[dict[str, Any]]] = {s: [] for s in siblings}
        self.requests: dict[bytes, tuple[str, int]] = {}  # its open requests: the id, the day it last went
        self.asked: int | None = None  # the day it opened the first of its open requests (section 5.1)
        self.answered = False  # whether one of its open requests has been acknowledged (section 12.1)
        self.restored = False  # whether it restored a backup (section 12.1)
        self.acted: dict[bytes, dict[int, str]] = {s: {} for s in siblings}  # the requests it acted on
        self.answering: dict[bytes, dict[int, str]] = {s: {} for s in siblings}  # those not yet answered
        self.left: dict[bytes, set[int]] = {s: set() for s in siblings}  # the records an answer still lacks
        self.manifests: dict[
            bytes, tuple[int, bytes]
        ] = {}  # the kept MANIFEST of a sibling, with its revision
        self.passed: dict[bytes, dict[bytes, int]] = {s: {} for s in siblings}  # the revisions passed on
        self.passing: list[
            tuple[bytes, bytes]
        ] = []  # the manifests it passes on in this step, each with its addressee
        self.errors: list[str] = []  # the codes of the errors about its own messages, in order
        self.day, self.now_ms, self.r = 0, 0, list[int]()
        self.what = ""  # what the device did with the last message, for people

    # --- the clock ---

    def at(self, now_ms: int, r: list[int]) -> None:
        """The clock and the random parts of the stamps that the device takes from here on."""
        self.now_ms, self.r = now_ms, list(r)

    def _draw(self) -> int:
        assert self.r, "the step gives no random part for a stamp the device takes"
        return self.r.pop(0)

    # --- schemas (section 7.3) ---

    def schema(self, fp: bytes) -> str | None:
        """The text of a schema the device holds, by its fingerprint."""
        if fp in self.schemas:
            return self.schemas[fp]
        for sibling in sorted(self.offered):
            if fp in self.offered[sibling]:
                return self.offered[sibling][fp]
        return None

    def _keep_schemas(self, state: State) -> None:
        """The text of a schema stays as long as a field state written with it (section 7.3)."""
        for f in state.fields.values():
            text = self.schema(f.schema)
            if text is not None:
                self.schemas.setdefault(f.schema, text)

    # --- records ---

    def hold(
        self, rid: str, held: Held, siblings: dict[bytes, tuple[bool, list[str], bool]] | None = None
    ) -> None:
        """A record the device holds when the session begins, with what it keeps for each sibling: whether
        the record is known to it, the names of the field states delivered to it, and whether the removal
        is. A sibling that is not named has nothing of the record, and the device has sent it nothing."""
        key = uuid_key(rid)
        assert key is not None and key not in self.records
        self.records[key], self.ids[key] = held, rid
        for sibling, (known, names, removal) in (siblings or {}).items():
            parts: set[Any] = {(name, held.state.fields[name]) for name in names}
            if removal:
                assert held.state.removal is not None
                parts.add(held.state.removal)
            # Where nothing is due, the device has no reason to send until one arises.
            self.kept[(sibling, key)] = Kept(known, parts, want=not known or parts != self._parts(held.state))

    @staticmethod
    def _parts(state: State) -> set[Any]:
        parts: set[Any] = set(state.fields.items())
        if state.removal is not None:
            parts.add(state.removal)
        return parts

    def _content(self, held: Held, kept: Kept) -> Content | None:
        """What a CHANGE of the record to a sibling carries (section 10.2), or None if nothing is sent."""
        fields = frozenset(held.state.fields.items())
        whole = not held.incomplete
        if not kept.known:
            return Content(whole, held.state.removal, fields)
        due = frozenset(p for p in fields if p not in kept.delivered)
        removal = held.state.removal
        if removal is not None and removal in kept.delivered:
            removal = None
        if not due and removal is None:
            return None
        return Content(due == fields and whole, removal, due)

    def change_datum(self, sibling: bytes, held: Held, content: Content, stamp: int) -> dict[str, Any]:
        r = content.removal
        return {
            "to": sibling,
            "origin": None,
            "type": held.type,
            "state": stamp,
            "whole": content.whole,
            "removal": r and {"stamp": r.stamp, "device": r.device, "stands": r.stands},
            "fields": [
                {"name": name, "schema": f.schema, "value": f.value, "stamp": f.stamp, "device": f.device}
                for name, f in held.state.fields.items()
                if (name, f) in content.fields
            ],
        }

    def _send_due(self) -> list[bytes]:
        """The offers and the CHANGE messages the device sends now (sections 7.2, 10.2, 10.3 and 11.2). A
        new state stamp that the message to one sibling takes can be the reason to send another sibling
        one (section 10.3), so the device goes on until nothing more is to send."""
        out: list[bytes] = []
        while True:
            sent = self._send_once()
            out += sent
            if not sent:
                return out

    def _send_once(self) -> list[bytes]:
        out: list[bytes] = []
        for sibling in sorted(self.siblings):
            lacking: dict[bytes, int] = {}
            left = self.left[sibling]
            for key in sorted(self.records):
                held = self.records[key]
                kept = self.kept.setdefault((sibling, key), Kept())
                if sibling in self.requests and key not in left:
                    continue  # no CHANGE while its own request is open, apart from an answer (section 11.3)
                stamp = held.state.state_stamp
                if kept.settled is not None and kept.settled != stamp:
                    kept.want, kept.settled = True, None  # the state stamp has changed (section 9.3)
                if not kept.want:
                    continue
                content = (
                    None if stamp is None or (kept.barred and held.incomplete) else self._content(held, kept)
                )
                if content is None or stamp is None:
                    # Nothing is due, or section 10.2 lets the device send nothing of the record: it is no
                    # part of an answer either (section 11.2).
                    left.discard(key)
                    kept.want = kept.want and (held.incomplete or stamp is None)
                    continue
                named = {f.schema for _, f in content.fields}
                if named & self.declined[sibling]:
                    continue  # no CHANGE that names a declined schema under that offer (section 7.2)
                if named - self.accepted[sibling]:
                    for fp in named - self.accepted[sibling]:
                        lacking[fp] = lacking.get(fp, 0) + 1
                    continue
                differs = kept.last is not None and kept.last[0] == stamp and kept.last[1] != content
                if differs or kept.fresh or held.restored:
                    # A new state stamp first (section 3.3, occasions 5, 6 and 7).
                    new = next_stamp(self.now_ms, self.highest, self._draw())
                    if new is None:
                        left.discard(key)
                        continue
                    self.highest = stamp = new
                    held.state = State(held.state.fields, held.state.removal, new)
                    held.to_pass = kept_to_pass(held.to_pass, new)
                datum = self.change_datum(sibling, held, content, stamp)
                version = change_version(datum)
                m = message(self.seed, "CHANGE", (self.ids[key], version), body_of("Change", datum))
                if len(m) > MAX_MESSAGE:
                    left.discard(key)
                    continue  # a record that does not fit is not sent (section 10.2)
                kept.last, kept.flight, kept.want = (stamp, content), (key, version), False
                kept.fresh = held.restored = False
                self.sent[sibling][(key, version)] = (content.marks, self.day)
                left.discard(key)
                out.append(m)
            for fp in sorted(lacking):
                if fp in {p[0] for p in self.pending[sibling].values()}:
                    continue  # offered, and not answered yet
                text = self.schema(fp)
                assert text is not None and self.offer_ids, "a schema to offer, and an id for the offer"
                offer_id = self.offer_ids.pop(0)
                offer_key = uuid_key(offer_id)
                assert offer_key is not None
                self.pending[sibling][offer_key] = (fp, str(full_name(json.loads(text))))
                types = [{"schema": text, "count": lacking[fp]}]
                body = body_of("Offer", {"to": sibling, "offer_id": offer_id, "types": types})
                out.append(message(self.seed, "OFFER", None, body))
            if self.answering[sibling] and not left:
                # The end of the answer: the request is acknowledged after its last CHANGE (section 11.2).
                for request, rid in self.answering[sibling].items():
                    self.acks[sibling].append(self._request_entry(rid, "APPLIED"))
                    self.acted[sibling][request] = "answered"
                self.answering[sibling] = {}
        return out

    @staticmethod
    def _request_entry(rid: str, outcome: str) -> dict[str, Any]:
        return {"id": rid, "version": 1, "outcome": outcome, "receiver_version": 1, "kept_fields": []}

    def _due_for(self, key: int, parts: set[Any], but: bytes | None = None) -> None:
        """Parts that the state of a record has got are due for every sibling to which they are not
        delivered: a reason to send (section 10.3)."""
        for sibling in self.siblings:
            kept = self.kept.setdefault((sibling, key), Kept())
            if sibling != but and not parts <= kept.delivered:
                kept.want = True

    # --- what its user does (section 3.5) ---

    def user_change(
        self, rid: str, type_name: str, action: str, values: dict[str, bytes], schema: bytes
    ) -> tuple[bool, list[bytes]]:
        """A change of the user: whether the device makes it, and what it sends."""
        key = uuid_key(rid)
        assert key is not None, "the id of a record is a UUID"
        held = self.records.get(key)
        done = change(
            held.state if held else None,
            self.key,
            action,
            values,
            self.now_ms,
            self.highest,
            (self._draw(), self._draw()),
            schema,
            None,
            held.to_pass if held else None,
        )
        if not done.made or done.state is None:
            return False, []
        before = self._parts(held.state) if held else set()
        if held is None:
            held = self.records[key] = Held(type_name, done.state)
            self.ids[key] = rid
        held.state, held.to_pass, self.highest = done.state, done.to_pass, done.highest
        self._due_for(key, self._parts(done.state) - before)
        return True, self._send_due()

    # --- requests (section 11.3) ---

    def _ask(self, sibling: bytes) -> list[bytes]:
        """Open a request toward a sibling, unless one is open, and send its RESYNC."""
        if sibling in self.requests:
            return []
        assert self.request_ids, "an id for the request"
        if not self.requests:
            self.asked, self.answered = self.day, False  # the wait begins, or begins anew
        self.requests[sibling] = (self.request_ids.pop(0), self.day)
        return [self._resync(sibling)]

    def _resync(self, sibling: bytes) -> bytes:
        rid = self.requests[sibling][0]
        self.requests[sibling] = (rid, self.day)
        return message(self.seed, "RESYNC", (rid, 1), body_of("Resync", {"to": sibling}))

    # --- manifests (section 13.2) ---

    def _pass_on(self) -> None:
        """Each sibling gets the kept MANIFEST of every other current device of the set, once for each
        kept one: not the device it is of, and not the sibling it came from."""
        for to in sorted(self.siblings):
            for of in sorted(self.manifests):
                revision, m = self.manifests[of]
                if of != to and of in self.siblings and self.passed[to].get(of) != revision:
                    self.passed[to][of] = revision
                    self.passing.append((to, m))

    def take_passed(self) -> list[tuple[bytes, bytes]]:
        """The manifests the device passed on since this was last asked, each with the sibling it is for."""
        passed, self.passing = self.passing, []
        return passed

    def _manifest(self, sender: bytes, m: bytes, body: bytes, connection: bytes) -> None:
        """A MANIFEST of a sibling. One whose sender is the key of the live connection it comes in is
        the sibling's own and applies whatever its revision (spec/manifest.md, section 6); one that
        another device passed on, and every one through the relay, replaces the kept manifest only if
        its revision is higher (section 13.2)."""
        self.what = "ignored"
        if sender not in self.siblings or body[:10] != MARKER + SPEC_FP["Manifest"]:
            return
        try:
            manifest = read_all("Manifest", body[10:])
        except ValueError:
            return
        if me.manifest_problems(manifest, len(body)):
            return  # not valid by spec/manifest.md, section 4
        revision = manifest["revision"]
        own = connection == sender and sender not in self.relay
        kept = self.manifests.get(sender, (0, b""))[0]
        if revision == kept if own else revision <= kept:
            return
        self.manifests[sender] = (revision, m)
        if connection in self.passed and connection != sender:
            self.passed[connection][sender] = revision  # it came from there, and does not go back
        self.what = "taken"
        self._pass_on()

    # --- its siblings (section 12) ---

    def add(self, sibling: bytes) -> list[bytes]:
        """A device has joined the set and has a channel to this one: every record is not known to it
        (section 12.3)."""
        assert sibling not in self.siblings and sibling != self.key
        self.siblings.append(sibling)
        for table in (self.offered, self.pending, self.sent, self.acted, self.answering, self.passed):
            table[sibling] = {}
        self.accepted[sibling], self.declined[sibling], self.left[sibling] = set(), set(), set()
        self.acks[sibling] = []
        asked: list[bytes] = []
        if self.restored:
            # A restored device that learns of a device its backup did not hold acts toward it as after
            # a restore (section 12.1).
            self._unknown_age()
            asked = self._ask(sibling)
        self._pass_on()
        return asked + self._send_due()

    def remove(self, sibling: bytes) -> list[bytes]:
        """The device applies the removal of a sibling (section 12.2): it discards what it kept for that
        key and sends it nothing more."""
        self.siblings.remove(sibling)
        self.removed.add(sibling)
        self.relay.discard(sibling)
        tables: tuple[dict[bytes, Any], ...] = (self.offered, self.pending, self.accepted, self.declined)
        for table in (*tables, self.sent, self.acks, self.acted, self.answering, self.left, self.passed):
            del table[sibling]
        self.requests.pop(sibling, None)
        self.manifests.pop(sibling, None)
        for passed in self.passed.values():
            passed.pop(sibling, None)
        self.kept = {k: v for k, v in self.kept.items() if k[0] != sibling}
        return []

    def reconnect(self, sibling: bytes) -> list[bytes]:
        """The live connection to a sibling ended and a new one stands: the offers of the old one ended
        with it, a CHANGE without an outcome was not delivered, and an open request is sent again
        (sections 7.2, 10.3 and 11.3)."""
        self.offered[sibling], self.pending[sibling] = {}, {}
        self.accepted[sibling], self.declined[sibling] = set(), set()
        for (s, _), kept in self.kept.items():
            if s == sibling and kept.flight is not None and kept.flight in self.sent[sibling]:
                kept.want = True
        first = [self._resync(sibling)] if sibling in self.requests else []
        return first + self._send_due()

    def restore(
        self, highest: int, records: list[tuple[str, Held]], acted: dict[bytes, list[str]] | None = None
    ) -> list[bytes]:
        """The device restored its data from a backup (section 12.1): it holds the records and the highest
        stamp of the backup and none of its bookkeeping, has no offer, gives its field states never stamped
        the stamp -1 if it has a sibling, and opens a new request toward every sibling."""
        self.highest, self.records, self.ids, self.kept = highest, {}, {}, {}
        self.requests, self.asked, self.restored = {}, None, True
        for sibling in self.siblings:
            # Of the requests it acted on, it keeps those of the backup, and none it learned since.
            self.acted[sibling] = dict.fromkeys(
                [uuid_key(rid) or 0 for rid in (acted or {}).get(sibling, [])], "acknowledged"
            )
            self.offered[sibling], self.pending[sibling], self.sent[sibling] = {}, {}, {}
            self.accepted[sibling], self.declined[sibling], self.acks[sibling] = set(), set(), []
            self.answering[sibling], self.left[sibling] = {}, set()
        for rid, held in records:
            held.restored = True
            held.unstamped = {name: f for name, f in held.state.fields.items() if f.stamp == 0}
            self.hold(rid, held)
        if self.siblings:
            self._unknown_age()
        out = [m for sibling in sorted(self.siblings) for m in self._ask(sibling)]
        return out + self._send_due()

    def _unknown_age(self) -> None:
        """The field states never stamped that the device held when it restored, and still holds
        unchanged, get the stamp -1: at the restore if it has a sibling then, or when it learns of one
        that its backup did not hold (sections 4.6 and 12.1)."""
        for key, held in self.records.items():
            fields = dict(held.state.fields)
            for name, f in held.unstamped.items():
                if fields.get(name) == f:
                    fields[name] = dataclasses.replace(f, stamp=-1)
            held.unstamped = {}
            if fields != held.state.fields:
                held.state = State(fields, held.state.removal, held.state.state_stamp)
                self._due_for(key, self._parts(held.state))

    def days(self, n: int) -> list[bytes]:
        """n days pass in which nothing reaches the device (sections 10.1, 10.3 and 11.3)."""
        self.day += n
        for sibling in self.siblings:
            # A CHANGE is kept for 15 days after it last went; an outcome after that is ignored.
            self.sent[sibling] = {
                name: (marks, day)
                for name, (marks, day) in self.sent[sibling].items()
                if self.day - day <= KEEP_DAYS
            }
        out: list[bytes] = []
        for sibling in sorted(self.relay & set(self.siblings)):
            # Through the relay, once the holding time has passed: the request, and each CHANGE that has
            # neither an outcome nor an error that settles it.
            if sibling in self.requests and self.day - self.requests[sibling][1] >= HOLDING_DAYS:
                out.append(self._resync(sibling))
            for (s, _), kept in self.kept.items():
                if s == sibling and kept.flight is not None and kept.flight in self.sent[sibling]:
                    if self.day - self.sent[sibling][kept.flight][1] >= HOLDING_DAYS:
                        kept.want = True
        return out + self._send_due()

    def flush_acks(self) -> list[bytes]:
        """The acknowledgements the device owes, one ACK of up to 4,096 entries at a time (section 9.1)."""
        out = []
        for sibling in sorted(self.acks):
            entries, self.acks[sibling] = self.acks[sibling], []
            for request, state in self.acted[sibling].items():
                if state == "answered":
                    self.acted[sibling][request] = "acknowledged"
            while entries:
                # No id and version twice in one ACK (section 9.1): a CHANGE that was processed twice is
                # acknowledged in two.
                batch, rest, met = (
                    list[dict[str, Any]](),
                    list[dict[str, Any]](),
                    set[tuple[int | None, int]](),
                )
                for e in entries:
                    name = (uuid_key(e["id"]), e["version"])
                    if name in met or len(batch) == MAX_ACK_RECORDS:
                        rest.append(e)
                    else:
                        met.add(name)
                        batch.append(e)
                out.append(message(self.seed, "ACK", None, body_of("Ack", {"to": sibling, "records": batch})))
                entries = rest
        return out

    # --- a file of the device's own set (section 13.4) ---

    def file_record(self, m: bytes, schema_text: str) -> tuple[bool, list[bytes]]:
        """A record message of a file whose sender is the device's own set, which passed the checks of
        spec/transports.md, section 2.2, with the writer schema of the file. Whether the device takes
        the record, and what it sends."""
        envelope = read_all("Envelope", m[10:])
        record, body, sender = envelope["record"], envelope["body"], envelope["sender"]
        assert sender == self.key or sender in self.siblings, "a file of the device's own set"
        self.what = "not applied"
        if envelope["kind"] != "DATA":
            return False, []  # a DELETE carries no removal
        key = uuid_key(record["id"])
        if key is None or record["version"] < 1 or key in self.records:
            return False, []  # steps 2 and 3 of spec/protocol.md, section 6.2; or a record it holds
        schema = json.loads(schema_text)
        fp = schema_fingerprint(schema_text)
        if body[:10] != MARKER + fp:
            return False, []
        buf, fields = io.BytesIO(body[10:]), dict[str, FieldState]()
        for f in schema["fields"]:
            start = buf.tell()
            try:
                one, value = read_field(schema, f["name"], buf)  # step 8
            except ValueError:
                return False, []
            if tm.value_breaches(one, value):  # step 9
                return False, []
            fields[f["name"]] = FieldState(
                body[10 + start : 10 + buf.tell()], -1, sender, fp
            )  # of unknown age
        if buf.tell() != len(body) - 10:
            return False, []
        done = device_merge(
            None, State(fields, None, record["version"]), self.now_ms, self.highest, self._draw()
        )
        # The file's version is a state stamp of the record that the device has seen from a sibling.
        self.records[key] = Held(str(full_name(schema)), done.state, done.sibling_stamp)
        self.ids[key] = record["id"]
        self.highest = done.highest
        self.schemas.setdefault(fp, schema_text)
        self.what = "taken"
        return True, self._send_due()

    # --- receiving ---

    def receive(self, m: bytes, connection: bytes | None = None) -> tuple[str | None, list[bytes]]:
        """One message that reaches the device, in the connection or from the mailbox of `connection`, or
        of its sender: the outcome, if it is a CHANGE processed to one, and the messages the device
        sends, without the acknowledgements, which it holds until `flush_acks`."""
        try:
            outcome, sent = self._receive(m, connection)
        except Reject as e:
            self.what = f"rejected {e.code}" + ("" if e.report else ", not reported")
            return None, [self._report(e, m)] if e.report else []
        return outcome, sent

    def _report(self, e: Reject, m: bytes) -> bytes:
        envelope = read_all("Envelope", m[10:])
        rec = envelope["record"]
        if rec is not None and len(rec["id"].encode()) > MAX_ERROR_RECORD_ID:
            rec = None
        d = {
            "to": envelope["sender"],
            "code": e.code,
            "message_hash": hashlib.sha256(m).digest(),
            "record": rec,
            "fingerprint": e.fingerprint,
            "field": e.field,
            "detail": e.detail,
        }
        return message(self.seed, "ERROR", None, body_of("Error", d))

    def _receive(self, m: bytes, connection: bytes | None) -> tuple[str | None, list[bytes]]:
        # Step 1 of sections 8.3 and 11.1: the message and its envelope, as spec/protocol.md, section 8.2,
        # says.
        if len(m) > MAX_MESSAGE:
            raise Reject("TOO_LARGE", report=False)
        if m[:2] != MARKER or len(m) < 10:
            raise Reject("INVALID_MESSAGE", "not a single-object encoding", report=False)
        if m[2:10] != SPEC_FP["Envelope"]:
            raise Reject("FORMAT_UNSUPPORTED", report=False)
        try:
            envelope = read_all("Envelope", m[10:])
        except ValueError as e:
            raise Reject("INVALID_MESSAGE", str(e), report=False) from None
        sender, kind, rec = envelope["sender"], envelope["kind"], envelope["record"]
        if envelope["format"] != 1:
            raise Reject("INVALID_MESSAGE", "not the format of the fingerprint", report=False)
        if keys.verify_problem(sender, keys.MESSAGE_PREFIX + m[10:-64], m[-64:]) is not None:
            raise Reject("SIGNATURE_INVALID", report=False)
        if kind == "MANIFEST":
            # Of a sibling, from itself or passed on by another; of any other key it is ignored here.
            self._manifest(sender, m, envelope["body"], connection or sender)
            return None, []
        if (rec is None) == (kind in ("CHANGE", "RESYNC", "DATA", "DELETE")):
            # A record where none belongs, or none where one is required: no valid message of its kind.
            # Only a key the device exchanges with gets the report.
            raise Reject(
                "INVALID_MESSAGE",
                "record present or missing",
                report=sender in {*self.siblings, *self.others},
            )
        # Step 2: the sender, by the table of section 7.1. It holds for every kind a sibling sends.
        if sender == self.key:
            self.what = "ignored: the device's own key"
            return None, []
        if sender in self.removed or sender in self.gone:
            self.what = "rejected without a report: a removed or a refused key"
            return None, []
        if sender not in self.siblings:
            assert kind in ("CHANGE", "RESYNC"), "the model takes the other kinds from siblings only"
            if sender in self.others:
                raise Reject("INVALID_MESSAGE", f"a {kind} of another sender")
            self.what = "a message of an unknown key"
            return None, []
        if kind in ("DATA", "DELETE"):
            return self._record_message(sender, kind, rec, envelope["body"])
        # Step 3: the body, and the addressee (spec/protocol.md, section 9.1).
        name, body = BODY_OF[kind], envelope["body"]
        if body[:10] != MARKER + SPEC_FP[name]:
            raise Reject("INVALID_MESSAGE", f"the body is not an axt.{name}")
        try:
            d = read_all(name, body[10:])
        except ValueError as e:
            raise Reject("INVALID_MESSAGE", str(e)) from None
        if d["to"] != self.key:
            self.what = "ignored: for another key"
            return None, []
        if kind == "CHANGE":
            return self._change(sender, rec, d)
        if kind == "RESYNC":
            return None, self._request(sender, rec)
        handler = {
            "ACK": self._ack,
            "ERROR": self._error,
            "OFFER": self._offer,
            "ACCEPT": self._answer,
            "DECLINE": self._answer,
        }[kind]
        return None, handler(sender, d)

    def _record_message(
        self, sender: bytes, kind: str, rec: Any, body: bytes
    ) -> tuple[str | None, list[bytes]]:
        """A DATA or a DELETE of a sibling: no accepted offer between siblings is one for a record
        message, so it fails step 5 of spec/protocol.md, section 6.2, if the steps before it pass
        (section 7.2)."""
        if uuid_key(rec["id"]) is None:
            raise Reject("RECORD_ID_INVALID")
        if rec["version"] < 1:
            raise Reject("VERSION_INVALID")
        if kind == "DATA" and (body[:2] != MARKER or body[2:10] not in self.offered[sender]):
            raise Reject("SCHEMA_UNKNOWN", fingerprint=body[2:10] if len(body) >= 10 else None)  # step 4
        raise Reject("NOT_ACCEPTED", "siblings send each other no record messages")

    def _change(
        self, sender: bytes, rec: dict[str, Any], d: dict[str, Any]
    ) -> tuple[str | None, list[bytes]]:
        """Steps 4 to 13 of section 8.3."""
        key = uuid_key(rec["id"])
        if key is None:
            raise Reject("RECORD_ID_INVALID")  # step 4
        if rec["version"] < 1:
            raise Reject("VERSION_INVALID")  # step 5
        problem = change_problem(d, rec["version"])
        if problem is not None:
            raise Reject("INVALID_MESSAGE", problem)  # step 6
        schemas: dict[bytes, dict[str, Any]] = {}
        for entry in d["fields"]:  # step 7
            text = self.schema(entry["schema"])
            if text is None:
                raise Reject("SCHEMA_UNKNOWN", fingerprint=entry["schema"])
            schemas[entry["schema"]] = json.loads(text)
        for entry in d["fields"]:  # step 8
            schema = schemas[entry["schema"]]
            if full_name(schema) != d["type"] or field_schema(schema, entry["name"]) is None:
                raise Reject("INVALID_MESSAGE", f"{entry['name']}: not a field of a schema of {d['type']}")
        held = self.records.get(key)
        if held is not None and held.type != d["type"]:
            raise Reject("TYPE_CHANGED", f"{held.type} before, {d['type']} now")  # step 9
        if not (d["whole"] or (held is not None and (held.state.fields or held.state.removal is None))):
            raise Reject("RECORD_UNKNOWN")  # step 10
        decoded = []
        for entry in d["fields"]:  # step 11
            buf = io.BytesIO(entry["value"])
            try:
                one, value = read_field(schemas[entry["schema"]], entry["name"], buf)
            except ValueError as e:
                raise Reject("UNDECODABLE", str(e)) from None
            if buf.tell() != len(entry["value"]):
                raise Reject("UNDECODABLE", f"{entry['name']}: bytes left over after the value")
            decoded.append((one, value))
        for one, value in decoded:  # step 12
            broken = tm.value_breaches(one, value)
            if broken:
                path, rule, why = broken[0]
                raise Reject("VALUE_INVALID", f"{rule}: {why}", field=mr.error_field(path))
        # Step 13: the merge and its outcome (section 8.4).
        removal = d["removal"]
        other = State(
            {e["name"]: FieldState(e["value"], e["stamp"], e["device"], e["schema"]) for e in d["fields"]},
            removal and Removal(removal["stamp"], removal["device"], removal["stands"]),
            d["state"],
        )
        own = held.state if held else None
        before = self._parts(own) if own else set()
        took = own is None or merge(own, other).took
        done = device_merge(
            own,
            other,
            self.now_ms,
            self.highest,
            self._draw() if took else 0,
            held.sibling_stamp if held else None,
            held.to_pass if held else None,
        )
        if held is None:
            held = self.records[key] = Held(d["type"], done.state)
            self.ids[key] = rec["id"]
        held.state, held.sibling_stamp, held.to_pass = done.state, done.sibling_stamp, done.to_pass
        self.highest = done.highest
        self._keep_schemas(done.state)
        mine, theirs = self._parts(done.state), self._parts(other)
        if took:
            outcome = "APPLIED"
        else:
            outcome = "DUPLICATE" if theirs <= mine else "STALE"
        # The record is known to the sibling, and every part of the message that the device holds is
        # delivered to it (section 10.1, event 2).
        kept = self.kept.setdefault((sender, key), Kept())
        kept.known = True
        kept.delivered = (kept.delivered | theirs) & mine
        # Every part of its state for which the message carried another, earlier one is due for that
        # sibling again, whatever the outcome: a reason to send (sections 8.4 and 10.3).
        names = {p[0] for p in theirs - mine if not isinstance(p, Removal)}
        again = {p for p in mine if (isinstance(p, Removal) and other.removal not in (None, p))}
        again |= {p for p in mine if not isinstance(p, Removal) and p[0] in names}
        if again:
            kept.delivered -= again
            kept.want = True
        if d["whole"] and held.incomplete:
            held.incomplete = False  # a whole CHANGE completes the record (section 8.4)
            for sibling in self.siblings:
                waiting = self.kept.setdefault((sibling, key), Kept())
                if waiting.barred:
                    waiting.barred, waiting.want = False, True
        stamp = done.state.state_stamp
        self.acks[sender].append(
            {
                "id": rec["id"],
                "version": rec["version"],
                "outcome": outcome,
                "receiver_version": rec["version"] if stamp is None else stamp,
                "kept_fields": [],
            }
        )
        self._due_for(key, mine - before, but=sender)
        self.what = outcome
        return outcome, self._send_due()

    def _ack(self, sender: bytes, d: dict[str, Any]) -> list[bytes]:
        """The acknowledgement of its own request, and the outcomes of a sibling for the CHANGE messages
        the device sent it and still keeps (sections 9.2 and 11.3)."""
        problem = ack_problem(d)
        if problem is not None:
            raise Reject("INVALID_MESSAGE", problem)
        taken = 0
        for entry in d["records"]:
            key = uuid_key(entry["id"])
            assert key is not None
            name = (key, entry["version"])
            request = self.requests.get(sender)
            if request is not None and name == (uuid_key(request[0]), 1) and entry["outcome"] != "STALE":
                # Its request is closed: it has the answer, and sends that sibling what is due for it
                # and what is not known to it.
                del self.requests[sender]
                self.answered = True
                for (s, _), kept in self.kept.items():
                    if s == sender:
                        kept.want = True
                taken += 1
                continue
            if name not in self.sent[sender]:
                continue  # no CHANGE to that sibling that it still keeps
            marks, _ = self.sent[sender].pop(name)  # the first outcome stands
            held, kept = self.records[key], self.kept[(sender, key)]
            kept.known = True
            kept.delivered |= self._parts(held.state) & marks  # only what the state still holds exactly
            self.highest = max(self.highest, entry["receiver_version"])
            held.sibling_stamp = max(held.sibling_stamp or 0, entry["receiver_version"])
            taken += 1
        self.what = f"{taken} entries taken"
        return self._send_due()

    def _error(self, sender: bytes, d: dict[str, Any]) -> list[bytes]:
        """An ERROR of a sibling about a CHANGE or a RESYNC the device sent it, matched by its record
        (sections 9.3 and 11.3)."""
        code, rec = d["code"], d["record"]
        key = None if rec is None else uuid_key(rec["id"])
        self.errors.append(code)
        self.what = f"error {code} noted"
        request = self.requests.get(sender)
        if request is not None and rec is not None and (key, rec["version"]) == (uuid_key(request[0]), 1):
            # About its request, which stays open; after FORMAT_UNSUPPORTED it goes again at once.
            return [self._resync(sender)] if code == "FORMAT_UNSUPPORTED" else []
        if rec is None or key is None or (key, rec["version"]) not in self.sent[sender]:
            return []  # logged, and changes nothing
        held, kept = self.records[key], self.kept[(sender, key)]
        if code == "SCHEMA_UNKNOWN":
            # The schema is offered again, also when an accepted offer of it stood; the message goes
            # again once it is accepted, or at once if the error names no fingerprint.
            if d["fingerprint"] is not None:
                self.accepted[sender].discard(d["fingerprint"])
                self.pending[sender] = {
                    k: v for k, v in self.pending[sender].items() if v[0] != d["fingerprint"]
                }
            kept.want = True
        elif code == "RECORD_UNKNOWN":
            kept.known, kept.delivered, kept.want = False, set(), True
            kept.barred = held.incomplete
        elif code == "FORMAT_UNSUPPORTED":
            kept.want = True
        else:
            # Settled: not again as it is, and not before the state stamp has changed.
            del self.sent[sender][(key, rec["version"])]
            kept.settled, kept.flight = held.state.state_stamp, None
        return self._send_due()

    def _request(self, sender: bytes, rec: dict[str, Any]) -> list[bytes]:
        """Steps 4 to 7 of section 11.1: a RESYNC of a sibling."""
        request = uuid_key(rec["id"])
        if request is None:
            raise Reject("RECORD_ID_INVALID")
        if rec["version"] < 1:
            raise Reject("VERSION_INVALID")
        if rec["version"] != 1:
            raise Reject("INVALID_MESSAGE", "the version of a request is 1")
        state = self.acted[sender].get(request)
        if state is not None:
            # A request it has acted on is not acted on again; once its acknowledgement is sent, a
            # repeat is acknowledged with DUPLICATE (section 11.2).
            self.what = "a repeat"
            if state == "acknowledged":
                self.acks[sender].append(self._request_entry(rec["id"], "DUPLICATE"))
            return []
        # It forgets what it kept for that sibling, keeps none of the CHANGE messages it sent it before,
        # and sends every record whole, each under a new state stamp; then the acknowledgement.
        self.acted[sender][request] = "answering"
        self.answering[sender][request] = rec["id"]
        self.sent[sender] = {}
        self.left[sender] = set(self.records)
        for key in self.records:
            kept = self.kept.setdefault((sender, key), Kept())
            kept.known, kept.delivered, kept.want, kept.fresh = False, set(), True, True
            kept.flight, kept.settled = None, None
        self.what = "acted on"
        return self._send_due()

    def _offer(self, sender: bytes, d: dict[str, Any]) -> list[bytes]:
        """An offer of a sibling: valid by spec/protocol.md, section 4.2, or rejected; every type of a
        valid one is accepted (section 7.2)."""
        names, texts = list[str](), dict[bytes, str]()
        if uuid_key(d["offer_id"]) is None or not 1 <= len(d["types"]) <= MAX_OFFER_TYPES:
            raise Reject("OFFER_INVALID", "the id of the offer, or the number of its types")
        for t in d["types"]:
            if len(t["schema"].encode()) > tm.rules.MAX_SCHEMA_BYTES:
                raise Reject("TOO_LARGE", "a schema above 256 KiB")
            try:
                schema = json.loads(t["schema"])
                if tm.rules.json_depth(schema) > tm.rules.MAX_JSON_DEPTH:
                    raise Reject("TOO_LARGE", "a schema nested deeper than 64")
                name = full_name(schema)
                fastavro.parse_schema(schema, _write_hint=False)
            except (ValueError, RecursionError, fastavro.schema.SchemaParseException):
                name = None
            if name is None:
                raise Reject("OFFER_INVALID", "a schema that is no Avro schema of a record")
            if t["count"] < 0:
                raise Reject("OFFER_INVALID", "a count below 0")
            names.append(name)
            texts[schema_fingerprint(t["schema"])] = t["schema"]
        if len(set(names)) != len(names) or len(texts) != len(names):
            raise Reject("OFFER_INVALID", "a full name or a fingerprint twice")
        for fp, text in texts.items():
            self.offered[sender][fp] = self.schema(fp) or text  # a text it holds stays (section 7.3)
        self.what = "accepted"
        body = body_of("Accept", {"to": sender, "offer_id": d["offer_id"], "types": names})
        return [message(self.seed, "ACCEPT", None, body)]

    def _answer(self, sender: bytes, d: dict[str, Any]) -> list[bytes]:
        """An ACCEPT or a DECLINE of a sibling for the device's latest offer of a schema (section 7.2)."""
        offer_key = uuid_key(d["offer_id"])
        offer = None if offer_key is None else self.pending[sender].get(offer_key)
        if offer is None or offer_key is None:
            self.what = "ignored: not an open offer of this device"
            return []
        fp, name = offer
        if [t if isinstance(t, str) else t["type"] for t in d["types"]] != [name]:
            raise Reject("INVALID_MESSAGE", "the types are not those of the offer")
        del self.pending[sender][offer_key]
        if isinstance(d["types"][0], str):
            self.accepted[sender].add(fp)
            self.what = "accepted"
        else:
            self.declined[sender].add(fp)
            self.what = "declined"
        return self._send_due()

    # --- what the device holds, for the vectors ---

    def held_back(self, held: Held) -> bool:
        """Whether the device must not send a DATA of the record to another app because it holds a field
        state of unknown age of it while a request of its own is open: until the first acknowledgement
        of one of its open requests, for at most 14 days from the opening of the first of them
        (sections 5.1 and 12.1)."""
        unknown = any(f.stamp == -1 for f in held.state.fields.values())
        waiting = bool(self.requests) and not self.answered and self.asked is not None
        return unknown and waiting and self.day - (self.asked or 0) < HOLDING_DAYS

    def query(self, rid: str) -> dict[str, Any]:
        key = uuid_key(rid)
        held = self.records.get(key) if key is not None else None
        requests = {sibling.hex(): self.requests[sibling][0] for sibling in sorted(self.requests)}
        if held is None or key is None:
            return {"record": None, "highest": str(self.highest), "requests": requests}
        siblings = {}
        for sibling in sorted(self.siblings):
            kept = self.kept.get((sibling, key), Kept())
            delivered = kept.delivered & self._parts(held.state)
            siblings[sibling.hex()] = {
                "known": kept.known,
                "delivered": sorted(p[0] for p in delivered if isinstance(p, tuple)),
                "removal": any(isinstance(p, Removal) for p in delivered),
            }
        return {
            "record": {
                "type": held.type,
                "state": state_json(held.state),
                "sibling_stamp": stamp_json(held.sibling_stamp),
                "to_pass": stamp_json(held.to_pass),
                "incomplete": held.incomplete,
                "held_back": self.held_back(held),
                "siblings": siblings,
            },
            "highest": str(self.highest),
            "requests": requests,
        }


# --- the JSON form of a session (spec/conformance.md, section 5.14) -----------------------------------------


def _held_of_json(v: dict[str, Any]) -> tuple[str, Held, dict[bytes, tuple[bool, list[str], bool]]]:
    state = state_of_json(v["state"])
    assert state is not None
    held = Held(
        v["type"],
        state,
        None if v["sibling_stamp"] is None else int(v["sibling_stamp"]),
        None if v["to_pass"] is None else int(v["to_pass"]),
        v["incomplete"],
    )
    siblings = {
        bytes.fromhex(k): (s["known"], list(s["delivered"]), s["removal"]) for k, s in v["siblings"].items()
    }
    return v["id"], held, siblings


def device_of_json(v: dict[str, Any], bytes_in: Callable[[Any], bytes] = bytes.fromhex) -> SetDevice:
    """The device of a `siblings` session, from the `device` of its input."""
    device = SetDevice(
        bytes.fromhex(v["seed"]),
        [bytes.fromhex(k) for k in v["siblings"]],
        v["schemas"],
        int(v["highest"]),
        [bytes.fromhex(k) for k in v["removed"]],
        [bytes.fromhex(k) for k in v["others"]],
        [bytes.fromhex(k) for k in v["gone"]],
        v["offer_ids"],
        v["request_ids"],
        [bytes.fromhex(k) for k in v["relay"]],
    )
    for sibling, fps in v["accepted"].items():
        device.accepted[bytes.fromhex(sibling)] = {bytes.fromhex(fp) for fp in fps}
    for sibling, m in v["manifests"].items():
        raw = bytes_in(m)
        body = read_all("Envelope", raw[10:])["body"]
        device.manifests[bytes.fromhex(sibling)] = (read_all("Manifest", body[10:])["revision"], raw)
    for to, revisions in v["passed"].items():
        device.passed[bytes.fromhex(to)] = {bytes.fromhex(of): revision for of, revision in revisions.items()}
    for record in v["records"]:
        device.hold(*_held_of_json(record))
    return device


def play(
    device: SetDevice, step: dict[str, Any], bytes_in: Callable[[Any], bytes] = bytes.fromhex
) -> dict[str, Any]:
    """One step of a `siblings` session on the device: the answer, with each message it sends and each
    manifest it passes on as bytes."""
    device.at(int(step.get("now_ms", "0")), step.get("r", []))
    if "receive" in step:
        connection = bytes.fromhex(step["from"]) if "from" in step else None
        outcome, sent = device.receive(bytes_in(step["receive"]), connection)
        answer: dict[str, Any] = {"outcome": outcome, "sent": sent}
    elif "change" in step:
        c = step["change"]
        values = {name: bytes_in(value) for name, value in c["values"].items()}
        made, sent = device.user_change(c["id"], c["type"], c["action"], values, bytes.fromhex(c["schema"]))
        answer = {"made": made, "sent": sent}
    elif "file_record" in step:
        taken, sent = device.file_record(bytes_in(step["file_record"]), step["schema"])
        answer = {"taken": taken, "sent": sent}
    elif "flush_acks" in step:
        answer = {"sent": device.flush_acks()}
    elif "add" in step:
        answer = {"sent": device.add(bytes.fromhex(step["add"]))}
    elif "remove" in step:
        answer = {"sent": device.remove(bytes.fromhex(step["remove"]))}
    elif "reconnect" in step:
        answer = {"sent": device.reconnect(bytes.fromhex(step["reconnect"]))}
    elif "days" in step:
        answer = {"sent": device.days(step["days"])}
    elif "restore" in step:
        backup = step["restore"]
        records = [_held_of_json(r)[:2] for r in backup["records"]]
        acted = {bytes.fromhex(sibling): ids for sibling, ids in backup["acted"].items()}
        answer = {"sent": device.restore(int(backup["highest"]), records, acted)}
    else:
        return device.query(step["query"])
    assert not device.r, "the step gives a random part that the device does not draw"
    answer["passed"] = [{"to": to, "manifest": m} for to, m in device.take_passed()]
    return answer


def meaning(m: bytes) -> list[dict[str, Any]]:
    """What a message that a device sends says, as the vectors compare it: one entry for the message,
    or for an ACK one for each of its entries."""
    envelope = read_all("Envelope", m[10:])
    kind, rec = envelope["kind"], envelope["record"]
    d = read_all(BODY_OF[kind], envelope["body"][10:])
    base = {"kind": kind, "to": d["to"].hex()}
    if kind == "CHANGE":
        r = d["removal"]
        assert d["origin"] is None
        return [
            {
                **base,
                "record": {"id": rec["id"], "version": str(rec["version"])},
                "type": d["type"],
                "state": str(d["state"]),
                "whole": d["whole"],
                "removal": r
                and {"stamp": str(r["stamp"]), "device": r["device"].hex(), "stands": r["stands"]},
                "fields": {
                    f["name"]: {
                        "value": f["value"].hex(),
                        "schema": f["schema"].hex(),
                        "stamp": str(f["stamp"]),
                        "device": f["device"].hex(),
                    }
                    for f in d["fields"]
                },
            }
        ]
    if kind == "ACK":
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
        rec = d["record"]
        return [
            {
                **base,
                "code": d["code"],
                "message_hash": d["message_hash"].hex(),
                "record": rec and {"id": rec["id"], "version": str(rec["version"])},
                "fingerprint": None if d["fingerprint"] is None else d["fingerprint"].hex(),
                "field": d["field"],
            }
        ]
    if kind == "OFFER":
        return [{**base, "offer_id": d["offer_id"], "schemas": [t["schema"] for t in d["types"]]}]
    if kind == "ACCEPT":
        return [{**base, "offer_id": d["offer_id"], "types": sorted(d["types"])}]
    assert kind == "RESYNC", kind
    return [{**base, "record": {"id": rec["id"], "version": str(rec["version"])}}]


def meanings(sent: list[bytes]) -> list[dict[str, Any]]:
    """The messages of one step as the vectors hold them: in an order that says nothing."""
    out = [entry for m in sent for entry in meaning(m)]
    return sorted(out, key=lambda e: json.dumps(e, sort_keys=True))


# --- the examples of sections 15 and 16 ----------------------------------------------------------------

PHONE_SEED = test_secret("cat-a-log, phone, Ed25519")
TABLET_SEED = test_secret("cat-a-log, tablet, Ed25519")
DEVICE_NAMES = {PHONE: "phone", TABLET: "tablet"}
RECORD_ID = "3f2c8a5e-9b1d-4c7e-8a6f-2d4b5c6e7f80"  # spec/records.md, section 9
REQUEST_ID = "7c1d9e42-5a3b-4f6c-8d2e-1b0a9c8f7e6d"  # the request of section 16.3
APPOINTMENT_TYPE = "axt.example.v1.Appointment"
APPOINTMENT_JSON: dict[str, Any] = json.loads(APPOINTMENT_1)

# The Parsing Canonical Forms of section 15, as the document shows them.
CHANGE_PCF = (
    '{"name":"axt.Change","type":"record","fields":[{"name":"to","type":{"name":"axt.ChangeTo","type":"fixed",'
    '"size":32}},{"name":"origin","type":["null",{"name":"axt.ChangeOrigin","type":"fixed","size":32}]},'
    '{"name":"type","type":"string"},{"name":"state","type":"long"},{"name":"whole","type":"boolean"},'
    '{"name":"removal","type":["null",{"name":"axt.ChangeRemoval","type":"record","fields":[{"name":"stamp",'
    '"type":"long"},{"name":"device","type":{"name":"axt.ChangeRemovalDevice","type":"fixed","size":32}},'
    '{"name":"stands","type":"boolean"}]}]},{"name":"fields","type":{"type":"array","items":{"name":'
    '"axt.ChangeField","type":"record","fields":[{"name":"name","type":"string"},{"name":"schema","type":'
    '{"name":"axt.ChangeFieldSchema","type":"fixed","size":8}},{"name":"value","type":["null","bytes"]},'
    '{"name":"stamp","type":"long"},{"name":"device","type":{"name":"axt.ChangeFieldDevice","type":"fixed",'
    '"size":32}}]}}}]}'
)
RESYNC_PCF = (
    '{"name":"axt.Resync","type":"record","fields":[{"name":"to","type":{"name":"axt.ResyncTo","type":"fixed",'
    '"size":32}}]}'
)


def date_time(hour: int, minute: int, instant_ms: int) -> dict[str, Any]:
    """An axt.DateTime on 2025-11-18 in Europe/Berlin, with the offset 3600 (spec/time.md, section 6.1)."""
    return {
        "year": 2025,
        "month": 11,
        "day": 18,
        "hour": hour,
        "minute": minute,
        "second": 0,
        "millisecond": 0,
        "zone": "Europe/Berlin",
        "offset_seconds": 3600,
        "instant_ms": instant_ms,
    }


# The appointment of section 16.1, and the two values that the change of section 16.2 sets.
APPOINTMENT: dict[str, Any] = {
    "title": "Vet",
    "start": date_time(10, 0, NOW),
    "end": None,
    "all_day": False,
    "location": "",
    "notes": "",
    "reminders": [],
}
START_1030 = date_time(10, 30, NOW + 1_800_000)
VALUE = {name: field_value(APPOINTMENT_JSON, name, value) for name, value in APPOINTMENT.items()}
VALUE_1030 = field_value(APPOINTMENT_JSON, "start", START_1030)
VALUE_WEBER = field_value(APPOINTMENT_JSON, "location", WEBER)


def all_sign(seed: bytes, data: bytes) -> bytes:
    """The signature, the same from keys_examples.py, PyNaCl and cryptography."""
    signature = bytes(keys.sign(seed, data))
    assert signature == nacl.signing.SigningKey(seed).sign(data).signature
    assert signature == ed25519.Ed25519PrivateKey.from_private_bytes(seed).sign(data)
    public = bytes(keys.public_key(seed))
    assert keys.verify_problem(public, data, signature) is None
    nacl.signing.VerifyKey(public).verify(data, signature)
    ed25519.Ed25519PublicKey.from_public_bytes(public).verify(signature, data)
    return signature


Parts = list[tuple[bytes, str]]


def _text(name: str, text: str) -> Parts:
    raw = text.encode()
    return [(keys.zigzag(len(raw)), f"{name}: string length {len(raw)}"), (raw, f'"{text}"')]


def _key(name: str, key: bytes) -> Parts:
    return [(key, f"{name}: fixed(32), the {DEVICE_NAMES[key]}'s test key")]


def change_parts(d: dict[str, Any], notes: dict[str, str]) -> Parts:
    """The body of a CHANGE field by field, as section 8.1 lists them; `notes` says what each value is."""
    z = keys.zigzag
    parts: Parts = [
        (MARKER, "single-object marker"),
        (SPEC_FP["Change"], "fingerprint of axt.Change, format 1"),
    ]
    parts += _key("to", d["to"])
    assert d["origin"] is None
    parts += [(z(0), "origin: union index 0, null")]
    parts += _text("type", d["type"])
    parts += [(z(d["state"]), f"state: long {d['state']}")]
    parts += [(b"\x01" if d["whole"] else b"\x00", f"whole: boolean {str(d['whole']).lower()}")]
    assert d["removal"] is None, "the examples carry no removal"
    parts += [(z(0), "removal: union index 0, null")]
    n = len(d["fields"])
    parts += [(z(n), f"fields: array block of {n} items")]
    for i, f in enumerate(d["fields"]):
        at = f"fields[{i}]"
        assert f["schema"] == SCHEMA_1
        parts += _text(f"{at}.name", f["name"])
        parts += [(f["schema"], f"{at}.schema: fixed(8), fingerprint of {APPOINTMENT_TYPE}, version 1")]
        parts += [(z(1), f"{at}.value: union index 1, bytes")]
        parts += [(z(len(f["value"])), f"{at}.value: bytes length {len(f['value'])}")]
        if f["value"]:
            parts += [(f["value"], notes[f["name"]])]
        parts += [(z(f["stamp"]), f"{at}.stamp: long {f['stamp']}")]
        parts += _key(f"{at}.device", f["device"])
    return [*parts, (z(0), "fields: end of the array")]


def message_parts(seed: bytes, kind: str, record: tuple[str, int] | None, body: Parts) -> tuple[Parts, bytes]:
    """A live message field by field, signed, with every check of an example: the bytes are those that
    fastavro writes, the Apache avro package reads them as the same envelope, and keys_examples.py,
    PyNaCl and cryptography give and verify the same signature."""
    z = keys.zigzag
    sender = bytes(keys.public_key(seed))
    raw = b"".join(p[0] for p in body)
    parts: Parts = [
        (MARKER, "single-object marker"),
        (SPEC_FP["Envelope"], "fingerprint of axt.Envelope, format 1"),
    ]
    parts += [
        (z(1), "format: int 1"),
        (z(KINDS.index(kind)), f"kind: enum index {KINDS.index(kind)}, {kind}"),
    ]
    parts += _key("sender", sender)
    if record is None:
        parts += [(z(0), "record: union index 0, null")]
    else:
        parts += [(z(1), "record: union index 1, axt.RecordRef"), *_text("record.id", record[0])]
        parts += [(z(record[1]), f"record.version: long {record[1]}")]
    parts += [(z(len(raw)), f"body: bytes length {len(raw)}")]
    parts += [(data, f"body: {note}") for data, note in body]
    unsigned = b"".join(p[0] for p in parts)
    signature = all_sign(seed, keys.MESSAGE_PREFIX + unsigned[10:])
    m = unsigned + signature
    assert m == message(seed, kind, record, raw), f"{kind}: the envelope differs from fastavro"
    back: Any = avro.io.DatumReader(avro.schema.parse(SPEC_TEXT["Envelope"])).read(
        avro.io.BinaryDecoder(io.BytesIO(m[10:]))
    )
    assert (back["kind"], back["sender"], back["body"], back["signature"]) == (kind, sender, raw, signature)
    assert back["record"] == (record and {"id": record[0], "version": record[1]})
    return [*parts, (signature, "signature: fixed(64)")], m


def apache_body(name: str, body: bytes) -> Any:
    """A body read with the Apache avro package, with no bytes left over."""
    assert body[:10] == MARKER + SPEC_FP[name]
    buf = io.BytesIO(body[10:])
    datum = avro.io.DatumReader(avro.schema.parse(SPEC_TEXT[name])).read(avro.io.BinaryDecoder(buf))
    assert buf.tell() == len(body) - 10
    return datum


def entries(state: State, names: list[str]) -> list[dict[str, Any]]:
    """The entries of `fields` for the named field states of a state, in that order."""
    return [
        {"name": n, "schema": f.schema, "value": f.value, "stamp": f.stamp, "device": f.device}
        for n, f in ((n, state.fields[n]) for n in names)
    ]


def example_device(seed: bytes, sibling: bytes, state: State, highest: int) -> SetDevice:
    """A device of section 16.1: it holds the appointment, has its schema accepted by its sibling, and
    every part of the record is delivered to the sibling."""
    device = SetDevice(seed, [sibling], [APPOINTMENT_1], highest, request_ids=[REQUEST_ID])
    device.accepted[sibling].add(SCHEMA_1)
    device.offered[sibling][SCHEMA_1] = APPOINTMENT_1
    device.hold(RECORD_ID, Held(APPOINTMENT_TYPE, state), {sibling: (True, list(state.fields), False)})
    return device


EXAMPLE_MESSAGES: dict[str, bytes] = {}  # the messages of section 16, for the vectors
PLAYED: list["Session"] = []  # the sessions that `check` played, for the vectors


def check_field_values() -> None:
    """The value of one field is its part of the record's encoding, with fastavro and the avro package,
    also for a type that uses a named type of an earlier field, a map, a nested namespace and a type that
    holds itself; and a value deeper than 32 does not decode (section 8.3, step 11)."""
    node = {
        "type": "record",
        "name": "Node",
        "namespace": "com.example.tree",
        "fields": [
            {"name": "kind", "type": {"type": "enum", "name": "Kind", "symbols": ["LEAF", "BRANCH"]}},
            {"name": "children", "type": {"type": "array", "items": "Node"}},
        ],
    }
    schema: dict[str, Any] = {
        "type": "record",
        "name": "com.example.Tree",
        "fields": [
            {"name": "root", "type": node},
            {"name": "tag", "type": {"type": "fixed", "name": "Tag", "size": 2}},
            {"name": "other", "type": ["null", "com.example.tree.Node"]},
            {"name": "kinds", "type": {"type": "map", "values": "com.example.tree.Kind"}},
            {"name": "tags", "type": {"type": "array", "items": "Tag"}},
        ],
    }
    leaf: dict[str, Any] = {"kind": "LEAF", "children": []}
    value = {
        "root": {"kind": "BRANCH", "children": [leaf]},
        "tag": b"ab",
        "other": leaf,
        "kinds": {"a": "LEAF"},
        "tags": [b"cd"],
    }
    whole = io.BytesIO()
    fastavro.schemaless_writer(whole, fastavro.parse_schema(schema, _write_hint=False), value)
    other = io.BytesIO()
    avro.io.DatumWriter(avro.schema.parse(json.dumps(schema))).write(value, avro.io.BinaryEncoder(other))
    parts = [field_value(schema, name, v) for name, v in value.items()]
    assert whole.getvalue() == other.getvalue() == b"".join(parts)
    buf = io.BytesIO(whole.getvalue())
    for name, v in value.items():
        assert read_field(schema, name, buf)[1] == {name: v}
    assert buf.tell() == len(whole.getvalue()) and field_schema(schema, "none") is None
    # The record is depth 1 and each node with its array of children two more.
    deep, too_deep = leaf, 0
    for _ in range(20):
        deep = {"kind": "BRANCH", "children": [deep]}
        try:
            read_field(schema, "root", io.BytesIO(field_value(schema, "root", deep)))
            assert data_depth({"root": deep}) <= MAX_DATA_DEPTH
        except ValueError:
            assert data_depth({"root": deep}) > MAX_DATA_DEPTH
            too_deep += 1
    assert too_deep > 0 and data_depth({"root": leaf}) == 3


def check_envelopes() -> None:
    """Step 1 of section 8.3: a message that is no valid message of envelope format 1 with a signature that
    verifies is not processed. How it is reported is in spec/protocol.md, section 8.3; this model reports
    none of them."""
    m = resync_message("tablet")
    device = SetDevice(PHONE_SEED, [TABLET], [APPOINTMENT_1])
    for broken, code in [
        (bytes(MAX_MESSAGE + 1), "TOO_LARGE"),
        (b"\xc3\x02" + m[2:], "INVALID_MESSAGE"),
        (m[:2] + SPEC_FP["Change"] + m[10:], "FORMAT_UNSUPPORTED"),
        (m + b"\x00", "INVALID_MESSAGE"),
        (m[:10] + keys.zigzag(2) + m[11:], "INVALID_MESSAGE"),
        (m[:-1] + bytes([m[-1] ^ 1]), "SIGNATURE_INVALID"),
    ]:
        assert device.receive(broken) == (None, []) and device.what == f"rejected {code}, not reported", code
    assert device.receive(m) == (None, []) and device.what == "acted on"


def check_schemas(out: list[str]) -> None:
    """Section 15: the canonical forms and the fingerprints of axt.Change and axt.Resync, with fastavro and
    the Apache avro package, and that the three unions have null first and the default null."""
    out.append("== Section 15: schemas ==")
    out.append("| Schema | Envelope format | CRC-64-AVRO | As bytes |")
    for name, pcf in (("Change", CHANGE_PCF), ("Resync", RESYNC_PCF)):
        text = SPEC_TEXT[name]
        assert to_parsing_canonical_form(fastavro.parse_schema(json.loads(text))) == pcf, name
        assert avro.schema.parse(pcf).canonical_form == pcf, f"{name}: the two libraries disagree"
        fp = tm.rules.crc64_avro(pcf.encode())
        assert fp == {"Change": 0xD3849ACAFC9D62E8, "Resync": 0xE8762BD9D559FDF1}[name], (
            f"the fingerprint of axt.{name} is not that of spec/sync.md, section 15"
        )
        assert fp.to_bytes(8, "little") == SPEC_FP[name] == tm.rules.apache_fingerprint(text), name
        out.append(f"axt.{name}: canonical form: {pcf}")
        out.append(f"| `axt.{name}` | 1 | `0x{fp:016x}` | `{SPEC_FP[name].hex(' ')}` |")
    change_fields = {f["name"]: f for f in json.loads(SPEC_TEXT["Change"])["fields"]}
    value = next(f for f in change_fields["fields"]["type"]["items"]["fields"] if f["name"] == "value")
    for f in (change_fields["origin"], change_fields["removal"], value):
        assert f["type"][0] == "null" and f["default"] is None, f["name"]
    # A writer without the three reads as null in each, with both libraries.
    old = json.loads(SPEC_TEXT["Change"])
    old["fields"] = [f for f in old["fields"] if f["name"] not in ("origin", "removal")]
    items = next(f for f in old["fields"] if f["name"] == "fields")["type"]["items"]
    items["fields"] = [f for f in items["fields"] if f["name"] != "value"]
    entry = {"name": "title", "schema": SCHEMA_1, "stamp": 100, "device": PHONE}
    datum = {"to": TABLET, "type": APPOINTMENT_TYPE, "state": 101, "whole": False, "fields": [entry]}
    buf = io.BytesIO()
    fastavro.schemaless_writer(buf, fastavro.parse_schema(old), datum)
    want = {**datum, "origin": None, "removal": None, "fields": [{**entry, "value": None}]}
    assert (
        fastavro.schemaless_reader(io.BytesIO(buf.getvalue()), fastavro.parse_schema(old), SPEC["Change"])
        == want
    )
    reader = avro.io.DatumReader(avro.schema.parse(json.dumps(old)), avro.schema.parse(SPEC_TEXT["Change"]))
    assert reader.read(avro.io.BinaryDecoder(io.BytesIO(buf.getvalue()))) == want


def check_messages(out: list[str]) -> None:
    """Section 16: the CHANGE of two field states, its ACK, the RESYNC, the whole CHANGE and its ACK, built
    field by field and played through the model of a device."""
    z = keys.zigzag
    out.append("== Section 16.1: devices and values ==")
    out.append(f"cat-a-log, phone, Ed25519 public key   {PHONE.hex()}")
    out.append(f"cat-a-log, tablet, Ed25519 public key  {TABLET.hex()}")
    assert key_order(TABLET, PHONE) > 0, "the tablet's key is the higher one"
    fp = int.from_bytes(SCHEMA_1, "little")
    out.append(f"Appointment.1: fingerprint 0x{fp:016x}, as bytes {SCHEMA_1.hex(' ')}")
    assert [f["name"] for f in APPOINTMENT_JSON["fields"]] == list(APPOINTMENT) and len(APPOINTMENT) == 7
    # The values by hand, against the two libraries.
    start = (
        b"".join(z(x) for x in (2025, 11, 18, 10, 0, 0, 0))
        + z(1)
        + z(13)
        + b"Europe/Berlin"
        + z(1)
        + z(3600)
        + z(1)
        + z(NOW)
    )
    by_hand = {
        "title": z(3) + b"Vet",
        "start": start,
        "end": z(0),
        "all_day": b"\x00",
        "location": z(0),
        "notes": z(0),
        "reminders": z(0),
    }
    assert by_hand == VALUE
    assert (
        VALUE_1030 == start[:5] + z(30) + start[6:-6] + z(NOW + 1_800_000)
        and NOW + 1_800_000 == 1_763_458_200_000
    )
    assert VALUE_WEBER == z(22) + WEBER.encode()
    whole_record = io.BytesIO()
    fastavro.schemaless_writer(whole_record, fastavro.parse_schema(APPOINTMENT_JSON), APPOINTMENT)
    assert whole_record.getvalue() == b"".join(VALUE.values()), "a record is its fields one after the other"
    for name, value in [*VALUE.items(), ("start, 10:30", VALUE_1030), ("location, Dr. Weber", VALUE_WEBER)]:
        out.append(f"value of {name}: {len(value)} bytes: {value.hex(' ')}")
    notes = {
        "title": 'the value: "Vet" as an Avro string',
        "start": "the value: an axt.DateTime, 2025-11-18 10:30:00.000 in Europe/Berlin",
        "end": "the value: union index 0, null",
        "all_day": "the value: boolean false",
        "location": f'the value: "{WEBER}" as an Avro string',
        "notes": "the value: a string of length 0",
        "reminders": "the value: an array without items",
    }

    # 16.1: both devices hold the record; every part is delivered in both directions.
    begin = {name: FieldState(value, 100, PHONE) for name, value in VALUE.items()}
    phone = example_device(PHONE_SEED, TABLET, State(begin, None, 101), 101)
    tablet = example_device(TABLET_SEED, PHONE, State(begin, None, 105), 105)
    backup = copy.deepcopy(phone)  # the phone's data before the change of section 16.2

    # 16.2: the phone's user sets start and location in one step, with the stamps 110 and 111.
    phone.at(0, [110 - 102, 111 - 111])
    values = {"start": VALUE_1030, "location": VALUE_WEBER}
    made, sent = phone.user_change(RECORD_ID, APPOINTMENT_TYPE, "set", values, SCHEMA_1)
    assert made and len(sent) == 1 and phone.highest == 111
    state = phone.records[uuid_key(RECORD_ID) or 0].state
    d: dict[str, Any] = {
        "to": TABLET,
        "origin": None,
        "type": APPOINTMENT_TYPE,
        "state": 111,
        "whole": False,
        "removal": None,
        "fields": entries(state, ["start", "location"]),
    }
    assert change_version(d) == 111 and change_problem(d, 111) is None
    body = change_parts(d, notes)
    assert b"".join(p[0] for p in body) == body_of("Change", d), "the body differs from fastavro"
    assert apache_body("Change", body_of("Change", d)) == d
    parts, m = message_parts(PHONE_SEED, "CHANGE", (RECORD_ID, 111), body)
    assert meanings(sent) == meaning(m), "the phone of the model sends this CHANGE"
    show(out, "16.2: the phone's CHANGE", parts, m)
    EXAMPLE_MESSAGES["the CHANGE of sync.md, section 16.2"] = m
    tablet.at(0, [115 - 112])
    assert tablet.receive(m) == ("APPLIED", []), tablet.what
    assert tablet.highest == 115 and tablet.query(RECORD_ID)["record"]["siblings"][PHONE.hex()] == {
        "known": True,
        "delivered": sorted(APPOINTMENT),
        "removal": False,
    }
    (ack,) = tablet.flush_acks()
    entry = {
        "id": RECORD_ID,
        "version": 111,
        "outcome": "APPLIED",
        "receiver_version": 115,
        "kept_fields": [],
    }
    ack_d = {"to": PHONE, "records": [entry]}
    assert ack == message(TABLET_SEED, "ACK", None, body_of("Ack", ack_d))
    assert ack[-64:] == all_sign(TABLET_SEED, keys.MESSAGE_PREFIX + ack[10:-64])
    back = apache_body("Ack", read_all("Envelope", ack[10:])["body"])
    assert back == ack_d
    out.append(f"16.2: the tablet's ACK: {len(ack)} bytes, SHA-256 {hashlib.sha256(ack).hexdigest()}")
    EXAMPLE_MESSAGES["the ACK of sync.md, section 16.2"] = ack
    assert phone.receive(ack) == (None, []) and phone.what == "1 entries taken"
    got = phone.query(RECORD_ID)
    assert got["highest"] == "115" and got["record"]["sibling_stamp"] == "115"
    assert got["record"]["siblings"][TABLET.hex()]["delivered"] == sorted(APPOINTMENT)
    # A STALE of another app with the version 115: the phone knows that version (section 5.3).
    assert stale(115, 111, 115, None, False, True, 0, 115, 0) == AfterStale(115, True, None, None)

    # 16.3: the phone restores the backup made before the change, discards its bookkeeping, and asks.
    key = uuid_key(RECORD_ID) or 0
    restored = copy.deepcopy(backup.records[key])
    before = restored.state
    phone.at(0, [])
    sent = phone.restore(101, [(RECORD_ID, restored)])
    resync_d = {"to": TABLET}
    body = [(MARKER, "single-object marker"), (SPEC_FP["Resync"], "fingerprint of axt.Resync, format 1")]
    body += _key("to", TABLET)
    assert b"".join(p[0] for p in body) == body_of("Resync", resync_d)
    assert apache_body("Resync", body_of("Resync", resync_d)) == resync_d
    parts, m = message_parts(PHONE_SEED, "RESYNC", (REQUEST_ID, 1), body)
    assert sent == [m], "the restored phone sends this RESYNC, and nothing else"
    assert phone.query(RECORD_ID)["requests"] == {TABLET.hex(): REQUEST_ID}
    show(out, "16.3: the phone's RESYNC", parts, m)
    EXAMPLE_MESSAGES["the RESYNC of sync.md, section 16.3"] = resync = m
    tablet.at(0, [117 - 116])
    outcome, sent = tablet.receive(m)
    assert outcome is None and len(sent) == 1 and tablet.what == "acted on"

    # 16.4: the tablet's whole CHANGE, under the new state stamp 117 that it takes for the answer.
    state = tablet.records[key].state
    assert state.state_stamp == 117 and tablet.highest == 117
    d = {
        "to": PHONE,
        "origin": None,
        "type": APPOINTMENT_TYPE,
        "state": 117,
        "whole": True,
        "removal": None,
        "fields": entries(state, list(APPOINTMENT)),
    }
    assert change_version(d) == 117
    assert [f["stamp"] for f in d["fields"]] == [100, 110, 100, 100, 110, 100, 100]
    body = change_parts(d, notes)
    assert b"".join(p[0] for p in body) == body_of("Change", d)
    assert apache_body("Change", body_of("Change", d)) == d
    parts, m = message_parts(TABLET_SEED, "CHANGE", (RECORD_ID, 117), body)
    assert meanings(sent) == meaning(m), "the tablet of the model sends this CHANGE"
    show(out, "16.4: the tablet's whole CHANGE", parts, m)
    EXAMPLE_MESSAGES["the whole CHANGE of sync.md, section 16.4"] = m
    phone.at(0, [118 - 118])
    assert phone.receive(m) == ("APPLIED", []), phone.what
    merged = merge(
        before,
        State({e["name"]: FieldState(e["value"], e["stamp"], e["device"]) for e in d["fields"]}),
    )
    assert [n for n, side in merged.stands.items() if side == "other"] == ["location", "start"]
    assert phone.highest == 118 and phone.records[key].state.state_stamp == 118
    (ack,) = phone.flush_acks()
    entry = {
        "id": RECORD_ID,
        "version": 117,
        "outcome": "APPLIED",
        "receiver_version": 118,
        "kept_fields": [],
    }
    assert ack == message(PHONE_SEED, "ACK", None, body_of("Ack", {"to": TABLET, "records": [entry]}))
    assert ack[-64:] == all_sign(PHONE_SEED, keys.MESSAGE_PREFIX + ack[10:-64])
    out.append(f"16.4: the phone's ACK: {len(ack)} bytes, SHA-256 {hashlib.sha256(ack).hexdigest()}")
    EXAMPLE_MESSAGES["the ACK of sync.md, section 16.4"] = ack
    assert phone.query(RECORD_ID)["record"]["siblings"][TABLET.hex()] == {
        "known": True,
        "delivered": sorted(APPOINTMENT),
        "removal": False,
    }
    assert tablet.receive(ack) == (None, []) and tablet.what == "1 entries taken"
    got = tablet.query(RECORD_ID)
    assert got["highest"] == "118" and got["record"]["state"]["state_stamp"] == "117"
    assert got["record"]["siblings"][PHONE.hex()] == {
        "known": True,
        "delivered": sorted(APPOINTMENT),
        "removal": False,
    }
    # The end of the answer: the tablet acknowledges the request, and the phone's request is closed.
    (done,) = tablet.flush_acks()
    entry = {"id": REQUEST_ID, "version": 1, "outcome": "APPLIED", "receiver_version": 1, "kept_fields": []}
    assert done == message(TABLET_SEED, "ACK", None, body_of("Ack", {"to": PHONE, "records": [entry]}))
    assert done[-64:] == all_sign(TABLET_SEED, keys.MESSAGE_PREFIX + done[10:-64])
    assert apache_body("Ack", read_all("Envelope", done[10:])["body"]) == {"to": PHONE, "records": [entry]}
    out.append(f"16.4: the request's ACK: {len(done)} bytes, SHA-256 {hashlib.sha256(done).hexdigest()}")
    EXAMPLE_MESSAGES["the ACK of the request of sync.md, section 16.4"] = done
    phone.at(0, [])
    assert phone.receive(done) == (None, []), "nothing is due for the tablet"
    assert phone.query(RECORD_ID)["requests"] == {}
    assert phone.records[key].state.fields == tablet.records[key].state.fields
    # The same RESYNC once more: not acted on again, and acknowledged with DUPLICATE.
    assert tablet.receive(resync) == (None, []) and tablet.what == "a repeat"
    (repeat,) = tablet.flush_acks()
    assert meaning(repeat) == [{**meaning(done)[0], "outcome": "DUPLICATE"}]
    assert tablet.records[key].state.state_stamp == 117

    # The last paragraph of 16.4: the same two field states in a message that is not whole.
    part = {**d, "whole": False, "fields": entries(state, ["start", "location"])}
    part_m = message(TABLET_SEED, "CHANGE", (RECORD_ID, 117), body_of("Change", part))
    again = copy.deepcopy(backup)
    again.at(0, [118 - 118])
    assert (
        again.receive(part_m)[0] == "APPLIED"
        and again.records[key].state.fields == phone.records[key].state.fields
    )
    without = SetDevice(PHONE_SEED, [TABLET], [APPOINTMENT_1], 0)
    outcome, sent = without.receive(part_m)
    assert outcome is None and [e["code"] for e in meanings(sent)] == ["RECORD_UNKNOWN"]


def show(out: list[str], title: str, parts: Parts, m: bytes) -> None:
    out.append("")
    out.append(f"== {title}: {len(m)} bytes, SHA-256 {hashlib.sha256(m).hexdigest()} ==")
    out.append(keys.dump(parts))
    out.append(f"signed bytes: {len(keys.MESSAGE_PREFIX) + len(m) - 74}, signature {m[-64:].hex()}")


# --- sessions of one device with its siblings (sections 7 to 13) ---------------------------------------

LAPTOP_SEED = test_secret("cat-a-log, laptop, Ed25519")
SEEDS = {
    "phone": PHONE_SEED,
    "tablet": TABLET_SEED,
    "laptop": LAPTOP_SEED,
    "old phone": test_secret("cat-a-log, old phone, Ed25519"),  # a removed key of the set
    "other app": test_secret("Old Brain Fix, Ed25519"),  # a current key of another known sender
    "refused": test_secret("Old Brain Fix, old device, Ed25519"),  # a removed key of another sender
    "stranger": test_secret("a stranger, Ed25519"),  # a key the device does not know
}
KEY = {name: bytes(keys.public_key(seed)) for name, seed in SEEDS.items()}
LAPTOP = KEY["laptop"]
WHO = {key: name for name, key in KEY.items()}
OFFER_IDS = [f"0000000{n}-0ffe-4000-8000-00000000000{n}" for n in range(1, 7)]
REQUEST_IDS = [f"0000000{n}-a5c0-4000-8000-00000000000{n}" for n in range(1, 4)]  # of the phone's requests
TABLET_REQUEST = "0000000a-a5c0-4000-8000-00000000000a"  # of a request of the tablet
TABLET_REQUEST_2 = "0000000b-a5c0-4000-8000-00000000000b"
OTHER_ID = "7b1e6c2a-4d3f-4a8b-9c5d-0e1f2a3b4c5d"  # a second record
APPOINTMENT_2_JSON: dict[str, Any] = json.loads(APPOINTMENT_2)
PET_1 = (REPO / "types" / "axt" / "example" / "v1" / "Pet.1.avsc").read_text(encoding="utf-8")
PET_TYPE = "axt.example.v1.Pet"
SCHEMA_PET = schema_fingerprint(PET_1)
# A version of the appointment whose title is a number: a schema that does not resolve against version 1.
_other = json.loads(APPOINTMENT_1)
_other["axt.version"] = 3
_other["fields"][0]["type"] = "long"
_other["fields"][0]["default"] = 0
APPOINTMENT_3 = json.dumps(_other)
APPOINTMENT_3_JSON: dict[str, Any] = json.loads(APPOINTMENT_3)
SCHEMA_3 = schema_fingerprint(APPOINTMENT_3)
SCHEMA_NONE = bytes.fromhex("0102030405060708")  # the fingerprint of no schema
SCHEMA_NONE_2 = bytes.fromhex("1112131415161718")
BASE = State({name: FieldState(value, 100, PHONE) for name, value in VALUE.items()}, None, 101)
ROOM = field_value(APPOINTMENT_2_JSON, "room", "2")


def text_value(text: str) -> bytes:
    """A text as the value of a string field."""
    return encoded(text)


def with_fields(state: State, stamp: int | None, **fields: FieldState) -> State:
    return State({**state.fields, **fields}, state.removal, stamp)


def record_json(
    state: State,
    known: dict[str, list[str] | None],
    rid: str = RECORD_ID,
    type_name: str = APPOINTMENT_TYPE,
    sibling_stamp: int | None = None,
    to_pass: int | None = None,
    incomplete: bool = False,
    removal: bool = True,
) -> dict[str, Any]:
    """A record of the `device` of a session. `known` gives, for each sibling to which the record is
    known, the names of the field states delivered to it, or None for all of them; `removal` says
    whether the removal, if the state holds one, is delivered to those siblings."""
    siblings = {
        KEY[sibling].hex(): {
            "known": True,
            "delivered": list(state.fields) if names is None else names,
            "removal": removal and state.removal is not None,
        }
        for sibling, names in known.items()
    }
    return {
        "id": rid,
        "type": type_name,
        "state": state_json(state),
        "sibling_stamp": stamp_json(sibling_stamp),
        "to_pass": stamp_json(to_pass),
        "incomplete": incomplete,
        "siblings": siblings,
    }


def device_json(
    records: list[dict[str, Any]],
    siblings: tuple[str, ...] = ("tablet",),
    highest: int = 101,
    schemas: tuple[str, ...] = (APPOINTMENT_1,),
    accepted: dict[str, list[bytes]] | None = None,
    removed: tuple[str, ...] = (),
    others: tuple[str, ...] = (),
    gone: tuple[str, ...] = (),
    relay: tuple[str, ...] = (),
    manifests: dict[str, bytes] | None = None,
    passed: dict[str, dict[str, int]] | None = None,
) -> dict[str, Any]:
    """The `device` of a session: the phone, with its siblings. Unless `accepted` says otherwise, every
    sibling has accepted an offer of the phone for version 1 of the appointment."""
    if accepted is None:
        accepted = {sibling: [SCHEMA_1] for sibling in siblings}
    return {
        "seed": PHONE_SEED.hex(),
        "highest": str(highest),
        "siblings": [KEY[s].hex() for s in siblings],
        "removed": [KEY[s].hex() for s in removed],
        "others": [KEY[s].hex() for s in others],
        "gone": [KEY[s].hex() for s in gone],
        "schemas": list(schemas),
        "offer_ids": OFFER_IDS,
        "request_ids": REQUEST_IDS,
        "relay": [KEY[s].hex() for s in relay],
        "manifests": {KEY[s].hex(): m.hex() for s, m in (manifests or {}).items()},
        "passed": {
            KEY[to].hex(): {KEY[of].hex(): revision for of, revision in revisions.items()}
            for to, revisions in (passed or {}).items()
        },
        "accepted": {KEY[s].hex(): [fp.hex() for fp in fps] for s, fps in accepted.items()},
        "records": records,
    }


def entry(name: str, f: FieldState) -> dict[str, Any]:
    return {"name": name, "schema": f.schema, "value": f.value, "stamp": f.stamp, "device": f.device}


def change_message(
    sender: str,
    state: int,
    fields: dict[str, FieldState] | list[dict[str, Any]],
    whole: bool = False,
    removal: Removal | None = None,
    to: str = "phone",
    rid: str = RECORD_ID,
    type_name: str = APPOINTMENT_TYPE,
    version: int | None = None,
    origin: bytes | None = None,
) -> bytes:
    """A CHANGE as a sibling writes it, or with a part that breaks a rule."""
    entries = [entry(n, f) for n, f in fields.items()] if isinstance(fields, dict) else fields
    d = {
        "to": KEY[to],
        "origin": origin,
        "type": type_name,
        "state": state,
        "whole": whole,
        "removal": removal and {"stamp": removal.stamp, "device": removal.device, "stands": removal.stands},
        "fields": entries,
    }
    stamps = [state, *(e["stamp"] for e in entries), *([removal.stamp] if removal else [])]
    record = (rid, max(stamps) if version is None else version)
    return message(SEEDS[sender], "CHANGE", record, body_of("Change", d))


def resync_message(
    sender: str,
    to: str = "phone",
    rid: str = TABLET_REQUEST,
    version: int | None = 1,
    body: bytes | None = None,
) -> bytes:
    """A RESYNC as a sibling writes it, or one that breaks a rule; with no version, without `record`."""
    record = None if version is None else (rid, version)
    return message(SEEDS[sender], "RESYNC", record, body or body_of("Resync", {"to": KEY[to]}))


def request_ack(sender: str, rid: str, outcome: str = "APPLIED", to: str = "phone") -> bytes:
    """The acknowledgement of a request: an ACK with the one entry of section 11.2."""
    return ack_message(sender, [(1, outcome, 1)], to, rid)


def manifest_message(sender: str, revision: int, app_name: str = "cat-a-log") -> bytes:
    """The MANIFEST of a device of the set, in the revision given: a message without an addressee."""
    manifest = {
        "revision": revision,
        "app_name": app_name,
        "app_url": None,
        "formats": [1],
        "takes": [],
        "any_type": None,
        "sends": None,
        "encryption_key": None,
        "relay": None,
    }
    return message(SEEDS[sender], "MANIFEST", None, body_of("Manifest", manifest))


def ack_message(
    sender: str,
    entries: list[tuple[int, str, int]],
    to: str = "phone",
    rid: str = RECORD_ID,
    kept_fields: list[str] | None = None,
) -> bytes:
    """An ACK with one entry for each version, outcome and receiver_version."""
    records = [
        {"id": rid, "version": v, "outcome": o, "receiver_version": rv, "kept_fields": kept_fields or []}
        for v, o, rv in entries
    ]
    return message(SEEDS[sender], "ACK", None, body_of("Ack", {"to": KEY[to], "records": records}))


def error_message(
    sender: str,
    code: str,
    about: bytes,
    fingerprint: bytes | None = None,
    field: str | None = None,
    to: str = "phone",
) -> bytes:
    """An ERROR about a message that the device sent, with the record of that message."""
    record = read_all("Envelope", about[10:])["record"]
    d = {
        "to": KEY[to],
        "code": code,
        "message_hash": hashlib.sha256(about).digest(),
        "record": record,
        "fingerprint": fingerprint,
        "field": field,
        "detail": "",
    }
    return message(SEEDS[sender], "ERROR", None, body_of("Error", d))


def offer_message(sender: str, offer_id: str, texts: list[str], to: str = "phone", count: int = 0) -> bytes:
    d = {"to": KEY[to], "offer_id": offer_id, "types": [{"schema": t, "count": count} for t in texts]}
    return message(SEEDS[sender], "OFFER", None, body_of("Offer", d))


def answer_message(
    sender: str, offer_id: str, type_name: str, reason: str | None = None, to: str = "phone"
) -> bytes:
    """An ACCEPT of the type, or with a reason a DECLINE."""
    if reason is None:
        d: dict[str, Any] = {"to": KEY[to], "offer_id": offer_id, "types": [type_name]}
        return message(SEEDS[sender], "ACCEPT", None, body_of("Accept", d))
    d = {"to": KEY[to], "offer_id": offer_id, "types": [{"type": type_name, "reason": reason}]}
    return message(SEEDS[sender], "DECLINE", None, body_of("Decline", d))


def data_message(
    sender: str,
    version: int,
    schema_text: str,
    datum: dict[str, Any],
    rid: str = RECORD_ID,
    more: bytes = b"",
) -> bytes:
    """A DATA with the record under the schema, and `more` after it, or with an empty datum a DELETE."""
    if not datum:
        return message(SEEDS[sender], "DELETE", (rid, version), b"")
    out = io.BytesIO()
    fastavro.schemaless_writer(out, fastavro.parse_schema(json.loads(schema_text)), datum)
    body = MARKER + schema_fingerprint(schema_text) + out.getvalue() + more
    return message(SEEDS[sender], "DATA", (rid, version), body)


def _fields_brief(fields: dict[str, Any]) -> str:
    """The field states of a message or a state, grouped by stamp and device: `start,location@110p`."""
    groups: dict[tuple[int, str], list[str]] = {}
    for name, f in fields.items():
        who = WHO.get(bytes.fromhex(f["device"]), "?")[0]
        groups.setdefault((int(f["stamp"]), who), []).append(name)
    return (
        " ".join(
            f"{','.join(names) if len(names) < 7 else 'all seven'}@{stamp}{who}"
            for (stamp, who), names in sorted(groups.items())
        )
        or "no field"
    )


def _removal_brief(r: dict[str, Any] | None) -> str:
    if r is None:
        return ""
    who = WHO.get(bytes.fromhex(r["device"]), "?")[0]
    return f" removal@{r['stamp']}{who}{'' if r['stands'] else ', taken back'}"


def brief(answer: dict[str, Any]) -> list[str]:
    """The answer of a step in a few words, as the cases below write out what they expect."""
    if "highest" in answer:  # a query
        record = answer["record"]
        asking = ", ".join(WHO[bytes.fromhex(k)] for k in answer["requests"])
        asking = f"; a request open to {asking}" if asking else ""
        if record is None:
            return [f"no record; highest {answer['highest']}{asking}"]
        state = record["state"]
        line = f"state stamp {state['state_stamp']}; {_fields_brief(state['fields'])}"
        line += f"{_removal_brief(state['removal'])}; sibling stamp {record['sibling_stamp']}"
        line += f"; to pass {record['to_pass']}; highest {answer['highest']}"
        line += "; incomplete" if record["incomplete"] else ""
        out = [line + ("; held back from other apps" if record["held_back"] else "") + asking]
        for key, s in record["siblings"].items():
            delivered = (
                "all" if s["delivered"] == sorted(state["fields"]) else ",".join(s["delivered"]) or "nothing"
            )
            what = f"known, delivered: {delivered}{' and the removal' if s['removal'] else ''}"
            out.append(f"{WHO[bytes.fromhex(key)]}: {what if s['known'] else 'not known'}")
        return out
    out = []
    for name in ("outcome", "made", "taken"):
        if name in answer:
            out.append(f"{name}: {answer[name]}")
    for m in answer["sent"]:
        to = WHO[bytes.fromhex(m["to"])]
        if m["kind"] == "CHANGE":
            rid = "" if m["record"]["id"] == RECORD_ID else f" of {m['record']['id'][:8]}"
            text = f"CHANGE{rid} to {to}, version {m['record']['version']}, state {m['state']}, "
            text += f"{'whole' if m['whole'] else 'in part'}: {_fields_brief(m['fields'])}"
            out.append(text + _removal_brief(m["removal"]))
        elif m["kind"] == "ACK":
            rid = "" if m["id"] == RECORD_ID else f" of {m['id'][:8]}"
            out.append(
                f"ACK{rid} to {to}: version {m['version']} {m['outcome']}, receiver {m['receiver_version']}"
            )
        elif m["kind"] == "ERROR":
            more = "".join(f", {k} {m[k]}" for k in ("fingerprint", "field") if m[k] is not None)
            out.append(f"ERROR to {to}: {m['code']}{more}")
        elif m["kind"] == "OFFER":
            schemas = [json.loads(t) for t in m["schemas"]]
            names = ", ".join(f"{full_name(s)} version {s['axt.version']}" for s in schemas)
            out.append(f"OFFER {m['offer_id'][:8]} to {to}: {names}")
        elif m["kind"] == "ACCEPT":
            out.append(f"ACCEPT {m['offer_id'][:8]} to {to}: {', '.join(m['types'])}")
        else:
            version = "" if m["record"]["version"] == "1" else f", version {m['record']['version']}"
            out.append(f"{m['kind']} {m['record']['id'][:8]} to {to}{version}")
    for passed in answer["passed"]:
        envelope = read_all("Envelope", bytes.fromhex(passed["manifest"])[10:])
        revision = read_all("Manifest", envelope["body"][10:])["revision"]
        to = WHO[bytes.fromhex(passed["to"])]
        out.append(f"MANIFEST of the {WHO[envelope['sender']]}, revision {revision}, passed on to {to}")
    return out


@dataclass
class Session:
    """One session of the operation `siblings`: the phone with what it holds, the steps, and for each
    step the answer of the model, which the case has checked against what it expects."""

    label: str
    refs: list[str]
    device: dict[str, Any]
    steps: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    answers: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    said: list[list[str]] = dataclasses.field(default_factory=list)

    def __post_init__(self) -> None:
        self.model = device_of_json(json.loads(json.dumps(self.device)))

    def step(self, step: dict[str, Any]) -> list[bytes]:
        """Play one step; the messages the device sends in it."""
        answer = play(self.model, step, lambda v: v if isinstance(v, bytes) else bytes.fromhex(v))
        sent: list[bytes] = answer.get("sent", [])
        if "sent" in answer:
            passed = [{"to": p["to"].hex(), "manifest": p["manifest"].hex()} for p in answer["passed"]]
            passed.sort(key=lambda p: (p["to"], p["manifest"]))
            answer = {**answer, "sent": meanings(sent), "passed": passed}
        self.steps.append(step)
        self.answers.append(answer)
        self.said.append(brief(answer))
        return sent

    def receive(self, m: bytes, r: tuple[int, ...] = (), via: str | None = None) -> list[bytes]:
        """A message reaches the device; `via` names the sibling in whose connection it comes, where
        that is not its sender."""
        step = {"receive": m, "now_ms": "0", "r": list(r)}
        return self.step(step if via is None else {**step, "from": KEY[via].hex()})

    def change(
        self, action: str, values: dict[str, bytes], r: tuple[int, int], rid: str = RECORD_ID, **more: Any
    ) -> list[bytes]:
        c = {
            "id": rid,
            "type": APPOINTMENT_TYPE,
            "action": action,
            "values": values,
            "schema": SCHEMA_1.hex(),
        }
        return self.step({"change": {**c, **more}, "now_ms": "0", "r": list(r)})

    def acks(self) -> list[bytes]:
        return self.step({"flush_acks": True})

    def query(self, rid: str = RECORD_ID) -> None:
        self.step({"query": rid})

    def nothing(self) -> None:
        """The device owes no acknowledgement, and holds the record as before."""
        self.acks()
        self.query()


def sent_to(sent: list[bytes], sibling: str) -> bytes:
    """The one message among those a device sent that is for the sibling."""
    (m,) = [m for m in sent if meaning(m)[0]["to"] == KEY[sibling].hex()]
    return m


def sessions() -> list[Session]:
    """The sessions of one device, the phone, with its siblings. Each plays the model and writes down
    what it said; `SAID` holds, for each, what the rules of sections 7 to 13 require of every step."""
    out: list[Session] = []
    weber = {"location": FieldState(VALUE_WEBER, 110, TABLET)}  # a change that the tablet made
    two = ("tablet", "laptop")

    def base(siblings: tuple[str, ...] = ("tablet",), **more: Any) -> dict[str, Any]:
        """The phone holds the appointment of section 16.1, and every part is delivered to every sibling."""
        return device_json([record_json(BASE, dict.fromkeys(siblings))], siblings, **more)

    def new(label: str, refs: list[str], device: dict[str, Any] | None = None) -> Session:
        s = Session(label, refs, base() if device is None else device)
        out.append(s)
        return s

    def changed(s: Session) -> bytes:
        """The phone's user sets the location, with the stamps 110 and 111: the CHANGE to the tablet."""
        return sent_to(s.change("set", {"location": VALUE_WEBER}, (8, 0)), "tablet")

    # --- who sent it (section 7.1) ---
    known = {"removed": ("old phone",), "others": ("other app",), "gone": ("refused",)}
    for who, what in [
        ("phone", "the device's own key is ignored"),
        ("old phone", "a removed key of the device's own set is rejected without a report"),
        ("other app", "a current key of another known sender is rejected with INVALID_MESSAGE"),
        ("refused", "a removed key of another sender, or a refused key, is rejected without a report"),
        ("stranger", "a key the device does not know is not processed"),
    ]:
        s = new(f"a CHANGE of {what}", ["sync.md 7.1", "sync.md 8.3"], base(**known))
        s.receive(change_message(who, 111, weber))
        s.nothing()
        s = new(f"a RESYNC of {what}", ["sync.md 7.1", "sync.md 11.1"], base(**known))
        s.receive(resync_message(who))
        s.nothing()

    # --- the addressee (section 8.3, step 3) ---
    s = new(
        "a CHANGE of a sibling for another device is ignored", ["sync.md 8.3", "protocol.md 9.1"], base(two)
    )
    s.receive(change_message("tablet", 111, weber, to="laptop"))
    s.nothing()
    s = new(
        "a RESYNC of a sibling for another device is ignored", ["sync.md 11.1", "protocol.md 9.1"], base(two)
    )
    s.receive(resync_message("tablet", to="laptop"))
    s.nothing()

    # --- the envelope (step 1): a CHANGE names its record, a RESYNC names none ---
    s = new(
        "step 1: a CHANGE without a record is rejected", ["sync.md 8.1", "sync.md 8.3", "protocol.md 8.2"]
    )
    body = read_all("Envelope", change_message("tablet", 111, weber)[10:])["body"]
    s.receive(message(TABLET_SEED, "CHANGE", None, body))
    s.nothing()
    s = new("step 1: a RESYNC without a record is rejected", ["sync.md 11.1", "protocol.md 8.2"])
    s.receive(resync_message("tablet", version=None))
    s.nothing()
    s = new(
        "step 1: a CHANGE without a record is reported to another app, and to no key that is not known",
        ["sync.md 8.3", "sync.md 7.1", "protocol.md 8.2"],
        base(**known),
    )
    for who in ("other app", "stranger", "old phone"):
        s.receive(message(SEEDS[who], "CHANGE", None, body))
    s.nothing()
    s = new("step 3: a CHANGE whose body is no axt.Change is rejected", ["sync.md 8.3", "protocol.md 8.2"])
    s.receive(message(TABLET_SEED, "CHANGE", (RECORD_ID, 111), body + b"\x00"))
    s.receive(message(TABLET_SEED, "CHANGE", (RECORD_ID, 111), body_of("Resync", {"to": PHONE})))
    s.nothing()
    s = new(
        "step 2: the body of a CHANGE of another app is not read",
        ["sync.md 8.3", "sync.md 7.1", "protocol.md 8.2"],
        base(**known),
    )
    s.receive(message(SEEDS["other app"], "CHANGE", (RECORD_ID, 111), b"no body of a CHANGE"))
    s.receive(message(SEEDS["stranger"], "CHANGE", (RECORD_ID, 111), b"no body of a CHANGE"))
    s.nothing()

    # --- the id and the version (steps 4 and 5) ---
    for label, rid in [
        ("an id that is no UUID", "not-a-uuid"),
        ("an id with a letter that is no hexadecimal digit", RECORD_ID[:-1] + "g"),
        ("an id of 65 bytes that the error cannot repeat", "x" * 65),
        ("the nil UUID", "00000000-0000-0000-0000-000000000000"),
        ("the max UUID", "ffffffff-ffff-ffff-ffff-ffffffffffff"),
    ]:
        s = new(f"step 4: a CHANGE with {label} is rejected", ["sync.md 8.3", "records.md 2"])
        s.receive(change_message("tablet", 111, weber, rid=rid))
        s.nothing()
    s = new("step 4: an id in upper case names the same record", ["sync.md 8.3", "envelope.md 7"])
    s.receive(change_message("tablet", 111, weber, rid=RECORD_ID.upper()), (3,))
    s.nothing()
    for label, state in [("0", 0), ("-1", -1)]:
        s = new(f"step 5: a CHANGE with the version {label} is rejected", ["sync.md 8.3"])
        s.receive(change_message("tablet", state, {}, whole=True))
        s.nothing()

    # --- the body (step 6 and section 8.2) ---
    none = FieldState(b"\x00", 1, TABLET, SCHEMA_NONE)
    invalid: list[tuple[str, dict[str, Any]]] = [
        ("a key in origin", {"fields": weber, "origin": KEY["other app"]}),
        ("a type with an empty name between two dots", {"type_name": "axt..Appointment", "whole": True}),
        ("a type that begins with a digit", {"type_name": "9lives.Cat", "whole": True}),
        ("an empty type", {"type_name": "", "whole": True}),
        ("a type with a space at its end", {"type_name": APPOINTMENT_TYPE + " ", "whole": True}),
        ("a type of 513 bytes", {"type_name": "a" * 513, "whole": True}),
        ("a state of 0", {"state": 0, "fields": weber}),
        ("a removal with the stamp 0", {"removal": Removal(0, TABLET)}),
        ("4,097 entries in fields", {"fields": [entry(f"f{i}", none) for i in range(4097)]}),
        ("an empty name", {"fields": [entry("", weber["location"])]}),
        ("a name of 513 bytes", {"fields": [entry("n" * 513, none)]}),
        ("a name twice", {"fields": [entry("location", weber["location"])] * 2}),
        ("a null value", {"fields": [{**entry("location", weber["location"]), "value": None}]}),
        (
            "a field state with the stamp -2",
            {"fields": [{**entry("location", weber["location"]), "stamp": -2}]},
        ),
        ("nothing in it that is not whole", {}),
        ("a version above its highest stamp", {"fields": weber, "version": 112}),
        ("a version below its highest stamp", {"fields": weber, "version": 110}),
    ]
    for label, how in invalid:
        s = new(f"step 6: a CHANGE with {label} is rejected", ["sync.md 8.2", "sync.md 8.3"])
        s.receive(change_message("tablet", **{"state": 111, "fields": {}, "rid": OTHER_ID, **how}))
        s.acks()
        s.query(OTHER_ID)
    within: list[tuple[str, dict[str, Any], tuple[int, ...]]] = [
        ("4,096 entries in fields", {"fields": [entry(f"f{i}", none) for i in range(4096)]}, ()),
        ("a name of 512 bytes", {"fields": [entry("n" * 512, none)]}, ()),
        (
            "two names that differ only in their Unicode normalization",
            {"fields": [entry("café", none), entry("café", none)]},
            (),
        ),
        ("a type of 512 bytes", {"type_name": "a" * 512, "whole": True}, (0,)),
    ]
    for label, how, r in within:
        s = new(f"step 6: a CHANGE with {label} is within the limits", ["sync.md 8.2", "sync.md 14"])
        s.receive(change_message("tablet", **{"state": 111, "fields": {}, "rid": OTHER_ID, **how}), r)
        s.acks()
    s = new(
        "step 6: every stamp up to the largest long is valid, and none is refused",
        ["sync.md 8.2", "sync.md 2.3"],
    )
    top = {"location": FieldState(VALUE_WEBER, MAX, TABLET)}
    s.receive(change_message("tablet", MAX, top, removal=Removal(MAX, TABLET, False)), (0,))
    s.nothing()
    s = new("step 6: the device keys of a removal and of a field state are not checked", ["sync.md 8.2"])
    odd = {"location": FieldState(VALUE_WEBER, 110, bytes(32))}
    s.receive(change_message("tablet", 121, odd, removal=Removal(120, KEY["old phone"], False)), (0,))
    s.nothing()
    s = new(
        "step 6: a field state never stamped is valid, and loses against a stamped one",
        ["sync.md 8.2", "sync.md 3.4"],
    )
    s.receive(change_message("tablet", 105, {"location": FieldState(VALUE_WEBER, 0, TABLET)}))
    s.nothing()

    # --- the schemas (steps 7 and 8) ---
    s = new(
        "step 6: a field state of unknown age, with the stamp -1, is valid, and loses against every other",
        ["sync.md 8.2", "sync.md 4.6", "sync.md 8.4"],
    )
    s.receive(change_message("tablet", 105, {"location": FieldState(VALUE_WEBER, -1, TABLET)}))
    s.nothing()
    s = new(
        "step 7: the error names the first schema, in the order of the message, that the device lacks",
        ["sync.md 8.3", "sync.md 7.3"],
    )
    fields = [
        entry("location", weber["location"]),
        entry("title", FieldState(b"\x00", 110, TABLET, SCHEMA_NONE_2)),
        entry("notes", none),
    ]
    s.receive(change_message("tablet", 111, fields))
    s.nothing()
    s = new(
        "step 7: a schema that another sibling offered is held, whichever sibling names it",
        ["sync.md 7.3", "sync.md 8.3"],
        base(two),
    )
    room = {"room": FieldState(ROOM, 125, TABLET, SCHEMA_2)}
    s.receive(offer_message("laptop", OFFER_IDS[5], [APPOINTMENT_2]))
    s.receive(change_message("tablet", 126, room), (0,))
    s = new(
        "step 7: a schema is not held once the offer that brought it ended, if no field state names it",
        ["sync.md 7.3", "sync.md 8.3"],
        base(two),
    )
    s.receive(offer_message("laptop", OFFER_IDS[5], [APPOINTMENT_2]))
    s.step({"reconnect": LAPTOP.hex()})
    s.receive(change_message("tablet", 126, room))
    s = new("step 8: a schema of another type than the message names is rejected", ["sync.md 8.3"])
    s.receive(change_message("tablet", 111, weber, whole=True, rid=OTHER_ID, type_name=PET_TYPE))
    s.acks()
    s.query(OTHER_ID)
    s = new("step 8: a name that is no field of the schema it names is rejected", ["sync.md 8.3"])
    s.receive(change_message("tablet", 111, {"room": FieldState(ROOM, 110, TABLET)}))
    s.nothing()

    # --- the type and the whole record (steps 9 and 10) ---
    s = new(
        "step 9: a CHANGE that names another type for a record the device holds is rejected",
        ["sync.md 8.3", "records.md 4.3"],
    )
    s.receive(change_message("tablet", 111, {}, whole=True, type_name=PET_TYPE))
    s.nothing()
    s = new(
        "step 10: a CHANGE in part for a record the device lacks is rejected", ["sync.md 8.3", "sync.md 4.3"]
    )
    s.receive(change_message("tablet", 111, weber, rid=OTHER_ID))
    s.acks()
    s.query(OTHER_ID)
    only_removal = device_json([record_json(State({}, gone(150, PHONE), 151), {"tablet": None})], highest=151)
    s = new(
        "step 10: a CHANGE in part for a record of which the device holds only the removal is rejected",
        ["sync.md 8.3", "sync.md 4.3"],
        only_removal,
    )
    s.receive(change_message("tablet", 161, {"location": FieldState(VALUE_WEBER, 160, TABLET)}))
    s.nothing()
    s = new(
        "step 10: a whole CHANGE gives the field states back to a device that holds only the removal",
        ["sync.md 8.3", "sync.md 4.3", "sync.md 8.4"],
        only_removal,
    )
    s.receive(
        change_message(
            "tablet",
            161,
            with_fields(BASE, None, **{"location": FieldState(VALUE_WEBER, 160, TABLET)}).fields,
            whole=True,
        ),
        (0,),
    )
    s.nothing()
    nothing_held = device_json([record_json(State({}, None, 101), {"tablet": None})])
    s = new(
        "step 10: a CHANGE in part passes for a record whose state holds no field state and no removal",
        ["sync.md 8.3", "sync.md 8.4"],
        nothing_held,
    )
    s.receive(change_message("tablet", 151, {}, removal=gone(150, TABLET)), (0,))
    s.nothing()
    s = new(
        "step 10: a whole CHANGE brings a record the device lacks, and the device keeps its type",
        ["sync.md 8.3", "sync.md 8.4", "sync.md 10.1"],
    )
    s.receive(
        change_message("tablet", 111, with_fields(BASE, None, **weber).fields, whole=True, rid=OTHER_ID), (0,)
    )
    s.acks()
    s.query(OTHER_ID)

    # --- the values (steps 11 and 12) ---
    for label, value in [
        ("a string that is cut short", b"\x06ab"),
        ("a byte left over after the value", text_value("x") + b"\x00"),
        ("a string that is not well-formed UTF-8", b"\x02\xff"),
        ("no bytes", b""),
    ]:
        s = new(f"step 11: a value with {label} is rejected", ["sync.md 8.3", "types.md 5.7"])
        s.receive(change_message("tablet", 111, {"location": FieldState(value, 110, TABLET)}))
        s.nothing()
    month_13 = field_value(APPOINTMENT_JSON, "start", {**START_1030, "month": 13})
    mixed = field_value(
        APPOINTMENT_JSON,
        "reminders",
        [{"months": 0, "days": 0, "millis": -900000}, {"months": 1, "days": -1, "millis": 0}],
    )
    # A type whose one field holds arrays inside arrays, 32 deep: the record is depth 1, so a value of 31
    # arrays is at the limit of 32 and one of 32 arrays is above it.
    nested: Any = "long"
    for _ in range(32):
        nested = {"type": "array", "items": nested}
    deep_json = {
        "type": "record",
        "name": "Deep",
        "namespace": "com.example",
        "doc": "A type for the data depth limit, in the vectors only.",
        "axt.version": 1,
        "fields": [{"name": "v", "type": nested, "doc": "Arrays inside arrays."}],
    }
    deep_text = json.dumps(deep_json)
    for arrays, what in [(31, "32 is within the limit"), (32, "33 is rejected")]:
        inside: Any = []
        for _ in range(arrays - 1):
            inside = [inside]
        s = new(
            f"step 11: a value at the data depth {what}",
            ["sync.md 8.3", "types.md 5.7"],
            base(schemas=(APPOINTMENT_1, deep_text)),
        )
        v = FieldState(field_value(deep_json, "v", inside), 110, TABLET, schema_fingerprint(deep_text))
        m = change_message("tablet", 111, {"v": v}, whole=True, rid=OTHER_ID, type_name="com.example.Deep")
        s.receive(m, (0,) if arrays == 31 else ())
        s.acks()
    s = new(
        "step 12: a time value that is not valid is rejected, with the path of the first one",
        ["sync.md 8.3", "time.md 8", "metadata.md 7.2"],
    )
    bad = {
        "location": FieldState(VALUE_WEBER, 110, TABLET),
        "reminders": FieldState(mixed, 110, TABLET),
        "start": FieldState(month_13, 110, TABLET),
    }
    s.receive(change_message("tablet", 111, bad))
    s.nothing()
    s = new(
        "step 12: a time value that is not valid inside a record is named from the field on",
        ["sync.md 8.3", "time.md 8"],
    )
    s.receive(change_message("tablet", 111, {"start": FieldState(month_13, 110, TABLET)}))
    s.nothing()

    # --- the order of the steps ---
    order: list[tuple[str, bytes]] = [
        (
            "an id that is no UUID and a body that is not valid: step 4 comes first",
            change_message("tablet", 111, weber, rid="not-a-uuid", origin=TABLET),
        ),
        (
            "a version of 0 and a body that is not valid: step 5 comes first",
            change_message("tablet", 111, weber, version=0),
        ),
        (
            "a body that is not valid and a schema the device lacks: step 6 comes first",
            change_message("tablet", 111, [entry("notes", none)] * 2),
        ),
        (
            "a schema the device lacks and another type: step 7 comes first",
            change_message("tablet", 111, [entry("notes", none)], type_name=PET_TYPE),
        ),
        (
            "a schema of another type and another type than the device keeps: step 8 comes first",
            change_message("tablet", 111, weber, type_name=PET_TYPE),
        ),
        (
            "a record the device lacks and a value that does not decode: step 10 comes first",
            change_message("tablet", 111, {"location": FieldState(b"\x06ab", 110, TABLET)}, rid=OTHER_ID),
        ),
        (
            "a time value that is not valid and, after it, a value that does not decode: step 11 comes first",
            change_message(
                "tablet",
                111,
                {"start": FieldState(month_13, 110, TABLET), "location": FieldState(b"\x06ab", 110, TABLET)},
            ),
        ),
    ]
    for label, m in order:
        s = new(label, ["sync.md 8.3"])
        s.receive(m)
        s.acks()
    s = new(
        "another type and a CHANGE in part for a record held as its removal alone: step 9 comes first",
        ["sync.md 8.3"],
        only_removal,
    )
    s.receive(change_message("tablet", 161, {}, removal=gone(160, TABLET), type_name=PET_TYPE))
    s.acks()

    # --- the merge and its outcome (section 8.4) ---
    s = new(
        "a CHANGE with a later field state is applied, and the device takes a new state stamp",
        ["sync.md 8.4", "sync.md 9.1", "sync.md 10.1"],
    )
    s.receive(change_message("tablet", 111, weber), (3,))
    s.nothing()
    s = new(
        "a CHANGE whose field state the device holds is a duplicate, and its state stamp still counts",
        ["sync.md 8.4", "sync.md 9.1", "sync.md 2.2"],
    )
    s.receive(change_message("tablet", 105, {"title": BASE.fields["title"]}))
    s.nothing()
    s = new(
        "a whole CHANGE without a field state and a removal, for a record the device holds, is a duplicate",
        ["sync.md 8.4"],
    )
    s.receive(change_message("tablet", 105, {}, whole=True))
    s.nothing()
    later = with_fields(BASE, 121, location=FieldState(text_value("Praxis"), 120, PHONE))
    ahead = device_json([record_json(later, {"tablet": None})], highest=121)
    s = new(
        "a CHANGE with an earlier field state is stale, and the later one is due for the sibling again",
        ["sync.md 8.4", "sync.md 9.1", "sync.md 9.2", "sync.md 10.1", "sync.md 10.3"],
        ahead,
    )
    s.receive(change_message("tablet", 111, weber))
    s.nothing()
    s = new(
        "a CHANGE with one later and one earlier field state is applied",
        ["sync.md 8.4", "sync.md 4.1"],
        ahead,
    )
    both = {**weber, "notes": FieldState(text_value("bring the vaccination card"), 125, TABLET)}
    s.receive(change_message("tablet", 126, both), (0,))
    s.nothing()
    s = new(
        "a CHANGE that is processed a second time is a duplicate",
        ["sync.md 8.4", "sync.md 4.5", "protocol.md 9.2"],
    )
    s.receive(change_message("tablet", 111, weber), (3,))
    s.receive(change_message("tablet", 111, weber))
    s.nothing()
    s = new(
        "a CHANGE that is processed again after the record has moved on is stale",
        ["sync.md 8.4", "sync.md 4.5"],
    )
    s.receive(change_message("tablet", 111, weber), (3,))
    s.acks()
    s.change("set", {"location": text_value("Praxis")}, (0, 0))
    s.receive(change_message("tablet", 111, weber))
    s.nothing()
    s = new(
        "a CHANGE with a removal that stands deletes the record",
        ["sync.md 8.4", "sync.md 4.2", "sync.md 4.3"],
    )
    s.receive(change_message("tablet", 151, {}, removal=gone(150, TABLET)), (0,))
    s.nothing()
    deleted_record = device_json(
        [record_json(State(BASE.fields, gone(150, PHONE), 151), {"tablet": None})], highest=151
    )
    s = new(
        "a CHANGE without a removal leaves the removal, and a later field state brings the record back",
        ["sync.md 8.4", "sync.md 4.3"],
        deleted_record,
    )
    s.receive(change_message("tablet", 161, {"location": FieldState(VALUE_WEBER, 160, TABLET)}), (0,))
    s.nothing()
    s = new(
        "a CHANGE with a removal that was taken back brings the record back",
        ["sync.md 8.4", "sync.md 4.2"],
        deleted_record,
    )
    s.receive(change_message("tablet", 171, {}, removal=back(170, TABLET)), (0,))
    s.nothing()
    s = new(
        "a CHANGE with the removal the device holds is a duplicate",
        ["sync.md 8.4", "sync.md 4.2"],
        deleted_record,
    )
    s.receive(change_message("tablet", 155, {}, removal=gone(150, PHONE)))
    s.nothing()
    s = new("a CHANGE with an earlier removal is stale", ["sync.md 8.4", "sync.md 4.2"], deleted_record)
    s.receive(change_message("tablet", 141, {}, removal=gone(140, TABLET)))
    s.nothing()
    passing = device_json([record_json(BASE, {"tablet": None}, to_pass=120)], highest=120)
    s = new(
        "a CHANGE that gives the device a state stamp above the version to pass drops that version",
        ["sync.md 8.4", "sync.md 5.3"],
        passing,
    )
    s.receive(change_message("tablet", 111, weber), (0,))
    s.nothing()

    # --- fields and types the device does not know (section 8.5) ---
    s = new(
        "a field that the device's schema lacks is kept and passed on, its schema offered first",
        ["sync.md 8.5", "sync.md 7.2", "sync.md 7.3", "sync.md 10.2"],
        base(two),
    )
    s.receive(offer_message("tablet", OFFER_IDS[5], [APPOINTMENT_2]))
    s.receive(change_message("tablet", 126, room), (0,))
    s.receive(answer_message("laptop", OFFER_IDS[0], APPOINTMENT_TYPE))
    s.nothing()
    pet = tm.rules.DATA["Pet"]
    pet_json = json.loads(PET_1)
    pet_fields = {n: FieldState(field_value(pet_json, n, v), 200, TABLET, SCHEMA_PET) for n, v in pet.items()}
    s = new(
        "a record of a type the device does not know is kept whole and passed on",
        ["sync.md 8.5", "sync.md 7.2"],
        base(two),
    )
    s.receive(offer_message("tablet", OFFER_IDS[5], [PET_1]))
    s.receive(change_message("tablet", 201, pet_fields, whole=True, rid=OTHER_ID, type_name=PET_TYPE), (0,))
    s.receive(answer_message("laptop", OFFER_IDS[0], PET_TYPE))
    s.acks()
    s = new(
        "a value written with a schema that does not resolve against the device's own is kept",
        ["sync.md 8.5", "sync.md 7.2"],
    )
    s.receive(offer_message("tablet", OFFER_IDS[5], [APPOINTMENT_3]))
    number = FieldState(field_value(APPOINTMENT_3_JSON, "title", 7), 130, TABLET, SCHEMA_3)
    s.receive(change_message("tablet", 131, {"title": number}), (0,))
    s.nothing()

    # --- offers between siblings (section 7.2) ---
    s = new(
        "a device accepts every type a sibling offers, also one it lacks and one that does not resolve",
        ["sync.md 7.2"],
    )
    s.receive(offer_message("tablet", OFFER_IDS[5], [PET_1, APPOINTMENT_3]))
    s = new(
        "an offer of a sibling that holds one full name twice is rejected", ["sync.md 7.2", "protocol.md 4.2"]
    )
    s.receive(offer_message("tablet", OFFER_IDS[5], [APPOINTMENT_1, APPOINTMENT_2]))
    s = new(
        "an offer of a sibling with a schema that is no record is rejected",
        ["sync.md 7.2", "protocol.md 4.2"],
    )
    s.receive(offer_message("tablet", OFFER_IDS[5], ['"string"']))
    s = new(
        "an offer of a sibling for another device is ignored", ["sync.md 7.2", "protocol.md 9.1"], base(two)
    )
    s.receive(offer_message("tablet", OFFER_IDS[5], [PET_1], to="laptop"))
    s = new(
        "a device sends no CHANGE that names a schema a sibling declined",
        ["sync.md 7.2", "protocol.md 5.3"],
        base(two, accepted={"tablet": [SCHEMA_1]}),
    )
    changed(s)
    s.receive(answer_message("laptop", OFFER_IDS[0], APPOINTMENT_TYPE, "NOT_WANTED"))
    s.change("set", {"notes": text_value("call first")}, (0, 0))
    s = new("a device offers a schema once, and waits for the answer", ["sync.md 7.2"], base(accepted={}))
    changed(s)
    s.change("set", {"notes": text_value("call first")}, (0, 0))
    s.receive(answer_message("tablet", OFFER_IDS[0], APPOINTMENT_TYPE))
    versions = with_fields(BASE, 127, room=FieldState(ROOM, 125, TABLET, SCHEMA_2))
    both_versions = device_json(
        [record_json(versions, {"tablet": None})], highest=127, schemas=(APPOINTMENT_1, APPOINTMENT_2)
    )
    s = new(
        "two schemas of one type are on offer at once, and a CHANGE that names both waits for both",
        ["sync.md 7.2", "protocol.md 4.3", "protocol.md 5.3"],
        both_versions,
    )
    s.step({"add": LAPTOP.hex()})
    s.receive(answer_message("laptop", OFFER_IDS[0], APPOINTMENT_TYPE))
    s.receive(answer_message("laptop", OFFER_IDS[1], APPOINTMENT_TYPE))
    s = new(
        "an answer to an offer that the device did not make is ignored", ["sync.md 7.2", "protocol.md 5.3"]
    )
    s.receive(answer_message("tablet", OFFER_IDS[4], APPOINTMENT_TYPE))
    s = new(
        "an answer that names another type than the offer is rejected",
        ["sync.md 7.2", "protocol.md 5.3"],
        base(accepted={}),
    )
    changed(s)
    s.receive(answer_message("tablet", OFFER_IDS[0], PET_TYPE))

    # --- what the sender does with an outcome (section 9.2) ---
    for outcome, receiver, what in [
        ("APPLIED", 115, "delivers the parts of the message, and the sibling's state stamp counts as seen"),
        ("DUPLICATE", 105, "delivers the parts of the message, also with a state stamp below the version"),
        ("STALE", 130, "delivers the parts of the message, and the device keeps no version to pass"),
    ]:
        s = new(f"the outcome {outcome} of a sibling {what}", ["sync.md 9.2", "sync.md 10.1", "sync.md 2.2"])
        changed(s)
        s.receive(ack_message("tablet", [(111, outcome, receiver)]))
        s.query()
    s = new(
        "an outcome for an id and version that the device did not send to that sibling is ignored",
        ["sync.md 9.2"],
    )
    changed(s)
    s.receive(ack_message("tablet", [(112, "APPLIED", 140)]))
    s.receive(ack_message("tablet", [(111, "APPLIED", 140)], rid=OTHER_ID))
    s.query()
    s = new("the first outcome for an id and version stands", ["sync.md 9.2"])
    changed(s)
    s.receive(ack_message("tablet", [(111, "APPLIED", 115)]))
    s.receive(ack_message("tablet", [(111, "STALE", 140)]))
    s.query()
    s = new(
        "an ACK of a sibling for another device is ignored", ["sync.md 9.2", "protocol.md 9.1"], base(two)
    )
    changed(s)
    s.receive(ack_message("tablet", [(111, "APPLIED", 115)], to="laptop"))
    s.query()
    bad_acks: list[tuple[str, bytes]] = [
        ("the outcome MERGED", ack_message("tablet", [(111, "MERGED", 115)])),
        ("the outcome KEPT", ack_message("tablet", [(111, "KEPT", 115)])),
        ("the outcome WITHDRAWN", ack_message("tablet", [(111, "WITHDRAWN", 115)])),
        ("a kept field", ack_message("tablet", [(111, "APPLIED", 115)], kept_fields=["location"])),
        ("a receiver_version of 0", ack_message("tablet", [(111, "APPLIED", 0)])),
        ("a version of 0", ack_message("tablet", [(111, "APPLIED", 115), (0, "APPLIED", 115)])),
        ("an id and version twice", ack_message("tablet", [(111, "APPLIED", 115), (111, "DUPLICATE", 115)])),
        ("an id that is no UUID", ack_message("tablet", [(111, "APPLIED", 115)], rid="not-a-uuid")),
        ("no entry", ack_message("tablet", [])),
    ]
    for label, m in bad_acks:
        s = new(
            f"an ACK of a sibling with {label} is not valid, and none of its entries is taken",
            ["sync.md 9.1", "protocol.md 8.2"],
        )
        changed(s)
        s.receive(m)
        s.query()

    # --- errors (section 9.3) ---
    s = new(
        "after SCHEMA_UNKNOWN the device offers the schema, and sends the same CHANGE once it is accepted",
        ["sync.md 9.3", "sync.md 10.3", "sync.md 7.2"],
    )
    m = changed(s)
    s.receive(error_message("tablet", "SCHEMA_UNKNOWN", m, fingerprint=SCHEMA_1))
    s.receive(answer_message("tablet", OFFER_IDS[0], APPOINTMENT_TYPE))
    s.query()
    s = new(
        "after SCHEMA_UNKNOWN without a fingerprint the device sends the same CHANGE again at once",
        ["sync.md 9.3"],
    )
    m = changed(s)
    s.receive(error_message("tablet", "SCHEMA_UNKNOWN", m))
    s = new(
        "after RECORD_UNKNOWN the device sends the record whole, under a new state stamp",
        ["sync.md 9.3", "sync.md 10.1", "sync.md 10.2", "sync.md 3.3"],
    )
    m = changed(s)
    s.receive(error_message("tablet", "RECORD_UNKNOWN", m), (2,))
    s.query()
    s = new("after FORMAT_UNSUPPORTED the device sends the CHANGE again", ["sync.md 9.3"])
    m = changed(s)
    s.receive(error_message("tablet", "FORMAT_UNSUPPORTED", m))
    for code in [
        "RECORD_ID_INVALID",
        "VERSION_INVALID",
        "INVALID_MESSAGE",
        "TYPE_CHANGED",
        "UNDECODABLE",
        "VALUE_INVALID",
        "TOO_LARGE",
        "SIGNATURE_INVALID",
        "NOT_ACCEPTED",
    ]:
        s = new(
            f"after {code} the device does not send the CHANGE again; its parts go with the next state",
            ["sync.md 9.3", "sync.md 10.3"],
        )
        m = changed(s)
        s.receive(error_message("tablet", code, m, field="location" if code == "VALUE_INVALID" else None))
        s.step({"reconnect": TABLET.hex()})
        s.query()
        s.change("set", {"notes": text_value("call first")}, (0, 0))
        s.receive(answer_message("tablet", OFFER_IDS[0], APPOINTMENT_TYPE))
    for count, what in [(4096, "is valid, and its entries are taken"), (4097, "is not valid")]:
        s = new(f"an ACK of a sibling with {count:,} entries {what}", ["sync.md 9.1", "sync.md 14"])
        changed(s)
        s.receive(ack_message("tablet", [(v, "APPLIED", 115) for v in range(1, count + 1)]))
        s.query()
    s = new("an ERROR about a CHANGE that has an outcome is ignored", ["sync.md 9.3", "protocol.md 8.3"])
    m = changed(s)
    s.receive(ack_message("tablet", [(111, "APPLIED", 115)]))
    s.receive(error_message("tablet", "RECORD_UNKNOWN", m))
    s.query()
    s = new(
        "an ERROR of a sibling for another device is ignored", ["sync.md 9.3", "protocol.md 9.1"], base(two)
    )
    m = changed(s)
    s.receive(error_message("tablet", "RECORD_UNKNOWN", m, to="laptop"))
    s.query()
    s = new(
        "an ERROR about a message that the device did not send to that sibling changes nothing",
        ["sync.md 9.3"],
    )
    changed(s)
    s.receive(error_message("tablet", "RECORD_UNKNOWN", change_message("phone", 112, weber, to="tablet")))
    s.query()

    # --- what a device sends to which sibling (section 10) ---
    s = new(
        "a change travels in part to every sibling, and an acknowledged part does not go again",
        ["sync.md 10.1", "sync.md 10.2", "sync.md 10.3"],
        base(two),
    )
    changed(s)
    s.receive(ack_message("tablet", [(111, "APPLIED", 115)]))
    s.change("set", {"notes": text_value("call first")}, (0, 0))
    s.query()
    s = new(
        "a part that the device took from one sibling goes to the others, and not back",
        ["sync.md 10.1", "sync.md 10.2"],
        base(two),
    )
    s.receive(change_message("tablet", 111, weber), (3,))
    s.acks()
    s.receive(ack_message("laptop", [(115, "APPLIED", 119)]))
    s.query()
    first = device_json([record_json(BASE, {"tablet": None})], two)
    s = new(
        "a record travels whole on its first transfer to a sibling, and in part to a sibling that knows it",
        ["sync.md 10.2", "sync.md 8.1"],
        first,
    )
    changed(s)
    s.receive(ack_message("laptop", [(111, "APPLIED", 115)]))
    s.query()
    s = new(
        "a new device gets the schemas offered and then every record whole",
        ["sync.md 12.3", "sync.md 10.2", "sync.md 7.2"],
    )
    s.step({"add": LAPTOP.hex()})
    s.receive(answer_message("laptop", OFFER_IDS[0], APPOINTMENT_TYPE))
    s.query()
    s = new(
        "a deletion travels as the removal alone, and a deleted record goes whole to a sibling that lacks it",
        ["sync.md 10.2", "sync.md 3.5"],
        first,
    )
    s.change("delete", {}, (8, 0))
    s.query()
    discarded = device_json([record_json(State({}, gone(150, PHONE), 151), {})], highest=151)
    s = new(
        "a device that discarded the field states of a deleted record sends what it holds, as a whole CHANGE",
        ["sync.md 10.2", "sync.md 8.1", "sync.md 4.3"],
        discarded,
    )
    s.receive(resync_message("tablet"), (0,))
    part = State({"location": FieldState(VALUE_WEBER, 160, TABLET)}, gone(150, PHONE), 165)
    incomplete = device_json([record_json(part, {}, incomplete=True)], highest=165)
    s = new(
        "a record held incompletely travels with whole false, and not again after RECORD_UNKNOWN",
        ["sync.md 10.2", "sync.md 4.3", "sync.md 8.4", "sync.md 11.2"],
        incomplete,
    )
    (m,) = s.receive(resync_message("tablet"), (0,))
    s.acks()
    s.receive(error_message("tablet", "RECORD_UNKNOWN", m))
    s.receive(resync_message("tablet", rid=TABLET_REQUEST_2))
    s.acks()
    s.query()
    complete = with_fields(BASE, None, title=FieldState(text_value("Vet, Mimi"), 170, TABLET))
    s.receive(change_message("tablet", 171, complete.fields, whole=True), (0, 0))
    s.query()
    s = new(
        "a different CHANGE of a record to one sibling takes a new state stamp; nothing becomes due by it",
        ["sync.md 10.2", "sync.md 3.3", "sync.md 10.3"],
        base(two),
    )
    m = changed(s)
    s.receive(error_message("tablet", "RECORD_UNKNOWN", m), (1,))
    s.query()
    s = new(
        "a new state stamp that another sibling caused sends the parts of a settled CHANGE again",
        ["sync.md 9.3", "sync.md 10.3", "sync.md 3.3"],
        base(two),
    )
    sent = s.change("set", {"location": VALUE_WEBER}, (8, 0))
    s.receive(error_message("laptop", "INVALID_MESSAGE", sent_to(sent, "laptop")))
    s.receive(error_message("tablet", "RECORD_UNKNOWN", sent_to(sent, "tablet")), (1,))
    s.query()
    unstamped = State(with_fields(BASE, None, **weber).fields, None, None)
    limit = device_json([record_json(unstamped, {}), record_json(BASE, {}, rid=OTHER_ID)], highest=MAX)
    s = new(
        "a device sends no CHANGE of a record for which it holds no state stamp",
        ["sync.md 10.2", "sync.md 8.1", "sync.md 2.3"],
        limit,
    )
    s.step({"reconnect": TABLET.hex()})
    s.receive(answer_message("tablet", OFFER_IDS[0], APPOINTMENT_TYPE))
    s = new(
        "a CHANGE without an outcome goes again in the next connection, once its schema is accepted there",
        ["sync.md 10.3", "sync.md 7.2", "sync.md 13.1"],
    )
    changed(s)
    s.step({"reconnect": TABLET.hex()})
    s.receive(answer_message("tablet", OFFER_IDS[0], APPOINTMENT_TYPE))
    s.query()
    s = new("a CHANGE with an outcome does not go again in the next connection", ["sync.md 10.3"])
    changed(s)
    s.receive(ack_message("tablet", [(111, "APPLIED", 115)]))
    s.step({"reconnect": TABLET.hex()})
    s = new(
        "a resend after a CHANGE of the sibling delivered a part carries the rest, under a new state stamp",
        ["sync.md 10.1", "sync.md 10.2", "sync.md 10.3"],
    )
    s.change("set", {"location": VALUE_WEBER, "notes": text_value("call first")}, (8, 0))
    s.receive(change_message("tablet", 120, {"location": FieldState(VALUE_WEBER, 110, PHONE)}))
    s.step({"reconnect": TABLET.hex()})
    s.receive(answer_message("tablet", OFFER_IDS[0], APPOINTMENT_TYPE), (0,))
    s.query()
    s = new(
        "a CHANGE of the sibling delivers the parts of a CHANGE on its way, which then does not go again",
        ["sync.md 10.1", "sync.md 10.2", "sync.md 10.3"],
    )
    changed(s)
    s.receive(change_message("tablet", 120, {"location": FieldState(VALUE_WEBER, 110, PHONE)}))
    s.step({"reconnect": TABLET.hex()})
    s.query()
    restored_record = State(BASE.fields, back(170, PHONE), 171)
    s = new(
        "a removal that is delivered does not travel with a field state that is due",
        ["sync.md 10.1", "sync.md 10.2"],
        device_json([record_json(restored_record, {"tablet": None})], highest=171),
    )
    s.change("set", {"location": VALUE_WEBER}, (0, 0))
    s = new(
        "a device that can take no stamp makes no change and sends nothing",
        ["sync.md 2.3", "sync.md 10.2"],
        base(highest=MAX),
    )
    s.change("set", {"location": VALUE_WEBER}, (0, 0))
    s.query()
    s = new("a CHANGE above 16 MiB is not sent", ["sync.md 10.2", "sync.md 14", "envelope.md 8"])
    s.change("set", {"notes": keys.zigzag(MAX_MESSAGE) + bytes(MAX_MESSAGE)}, (8, 0))

    stuck = with_fields(BASE, 111, location=FieldState(VALUE_WEBER, 110, PHONE))
    at_limit = device_json(
        [record_json(stuck, {"tablet": [n for n in BASE.fields if n != "location"]})], highest=MAX
    )
    s = new(
        "a device that can take no stamp does not send a different CHANGE under its state stamp",
        ["sync.md 10.2", "sync.md 2.3"],
        at_limit,
    )
    (m,) = s.receive(change_message("tablet", 105, {"title": BASE.fields["title"]}))
    s.receive(error_message("tablet", "RECORD_UNKNOWN", m), (0,))
    s.query()
    s = new(
        "a record that its user creates travels whole, its deletion and the taking back as the removal alone",
        ["sync.md 3.5", "sync.md 10.2"],
        device_json([], highest=0),
    )
    s.change("create", VALUE, (99, 0), rid=OTHER_ID)
    s.receive(ack_message("tablet", [(101, "APPLIED", 105)], rid=OTHER_ID))
    s.change("delete", {}, (0, 0), rid=OTHER_ID)
    s.receive(ack_message("tablet", [(107, "APPLIED", 110)], rid=OTHER_ID))
    s.change("take_back", {}, (0, 0), rid=OTHER_ID)
    s.query(OTHER_ID)

    # --- RESYNC (section 11) ---
    other = State(with_fields(BASE, None, **weber).fields, gone(150, PHONE), 151)
    held_two = device_json(
        [record_json(BASE, {"tablet": None}), record_json(other, {"tablet": None}, rid=OTHER_ID)], highest=151
    )
    s = new(
        "after a RESYNC the device sends every record whole under a new state stamp, then acknowledges it",
        ["sync.md 11.2", "sync.md 3.3", "sync.md 10.1", "sync.md 10.2", "sync.md 9.1"],
        held_two,
    )
    s.receive(resync_message("tablet"), (0, 0))
    s.query()
    s.acks()
    s.receive(resync_message("tablet"))
    s.acks()
    s.query(OTHER_ID)
    s = new(
        "a repeat of a RESYNC before its acknowledgement is sent changes nothing",
        ["sync.md 11.2", "protocol.md 9.2"],
    )
    s.receive(resync_message("tablet"), (0,))
    s.receive(resync_message("tablet"))
    s.acks()
    s = new("a RESYNC with another id is another request, and is acted on", ["sync.md 11.1", "sync.md 11.2"])
    s.receive(resync_message("tablet"), (0,))
    s.acks()
    s.receive(resync_message("tablet", rid=TABLET_REQUEST_2), (0,))
    s.acks()
    s = new(
        "a device that holds no record sends only the acknowledgement of a RESYNC",
        ["sync.md 11.2"],
        device_json([]),
    )
    s.receive(resync_message("tablet"))
    s.acks()
    s = new(
        "the acknowledgement of a RESYNC follows the last CHANGE of the answer",
        ["sync.md 11.2", "sync.md 7.2"],
        base(accepted={}),
    )
    s.receive(resync_message("tablet"))
    s.acks()
    s.receive(answer_message("tablet", OFFER_IDS[0], APPOINTMENT_TYPE), (0,))
    s.acks()
    s = new(
        "an answer whose connection ends first goes on in the next one, and is acknowledged there",
        ["sync.md 11.2", "sync.md 7.2"],
        base(accepted={}),
    )
    s.receive(resync_message("tablet"))
    s.step({"reconnect": TABLET.hex()})
    s.acks()
    s.receive(answer_message("tablet", OFFER_IDS[1], APPOINTMENT_TYPE), (0,))
    s.acks()
    s = new(
        "a second RESYNC with another id starts the answer anew, and both are acknowledged at its end",
        ["sync.md 11.2", "sync.md 3.3"],
        device_json(
            [record_json(BASE, {"tablet": None}), record_json(versions, {"tablet": None}, rid=OTHER_ID)],
            highest=127,
            schemas=(APPOINTMENT_1, APPOINTMENT_2),
        ),
    )
    s.receive(resync_message("tablet"), (0,))
    s.acks()
    s.receive(resync_message("tablet", rid=TABLET_REQUEST_2), (0,))
    s.receive(answer_message("tablet", OFFER_IDS[0], APPOINTMENT_TYPE), (0,))
    s.acks()
    s = new(
        "a record that the device cannot send is no part of the answer to a RESYNC",
        ["sync.md 11.2", "sync.md 2.3"],
        base(highest=MAX),
    )
    s.receive(resync_message("tablet"), (0,))
    s.acks()
    s = new(
        "an outcome and an error for a CHANGE sent before a RESYNC are ignored",
        ["sync.md 11.2", "sync.md 9.2", "sync.md 10.1"],
    )
    m = changed(s)
    s.receive(resync_message("tablet"), (1,))
    s.receive(ack_message("tablet", [(111, "APPLIED", 115)]))
    s.receive(error_message("tablet", "RECORD_UNKNOWN", m))
    s.query()
    checks: list[tuple[str, dict[str, Any]]] = [
        ("an id that is no UUID", {"rid": "not-a-uuid"}),
        ("the nil UUID as its id", {"rid": "00000000-0000-0000-0000-000000000000"}),
        ("the version 0", {"version": 0}),
        ("the version 2", {"version": 2}),
        ("an id that is no UUID and the version 2: step 4 comes first", {"rid": "not-a-uuid", "version": 2}),
        ("a body that is no axt.Resync", {"body": body_of("Resync", {"to": PHONE}) + b"\x00"}),
    ]
    for label, how in checks:
        s = new(f"a RESYNC with {label} is rejected", ["sync.md 11.1"])
        s.receive(resync_message("tablet", **how))
        s.nothing()

    # --- a device that asks (sections 11.3 and 12.1) ---
    backup: dict[str, Any] = {"highest": "101", "records": [record_json(BASE, {})], "acted": {}}
    s = new(
        "a restored device asks every sibling, and sends none a CHANGE before that sibling acknowledges",
        ["sync.md 11.3", "sync.md 12.1", "sync.md 10.2", "sync.md 3.3", "protocol.md 10"],
        base(two),
    )
    changed(s)
    asked = s.step({"restore": backup})
    of_tablet, of_laptop = (meaning(sent_to(asked, who))[0]["record"]["id"] for who in two)
    s.query()
    s.change("set", {"notes": text_value("call first")}, (0, 0))
    s.step({"reconnect": TABLET.hex()})
    lost = with_fields(BASE, None, location=FieldState(VALUE_WEBER, 110, PHONE))  # the phone's own change
    s.receive(change_message("tablet", 115, lost.fields, whole=True), (0,))
    s.acks()
    s.receive(request_ack("tablet", of_tablet))
    s.receive(answer_message("tablet", OFFER_IDS[0], APPOINTMENT_TYPE), (0,))
    s.query()
    s.receive(error_message("laptop", "FORMAT_UNSUPPORTED", sent_to(asked, "laptop")))
    s.receive(error_message("laptop", "INVALID_MESSAGE", sent_to(asked, "laptop")))
    s.receive(request_ack("laptop", of_laptop, "DUPLICATE"))
    s.query()
    counted = State({name: FieldState(value, 0, PHONE) for name, value in VALUE.items()}, None, 4)
    unstamped_backup = {"highest": "4", "records": [record_json(counted, {})], "acted": {}}
    s = new(
        "a restored device with a sibling gives its field states never stamped the stamp -1",
        ["sync.md 12.1", "sync.md 4.6", "sync.md 5.1", "sync.md 10.2"],
        device_json([], highest=4),
    )
    s.step({"restore": unstamped_backup})
    s.query()
    s.receive(request_ack("tablet", REQUEST_IDS[0]))
    s.query()
    s.receive(answer_message("tablet", OFFER_IDS[0], APPOINTMENT_TYPE), (0,))
    s = new(
        "a record with a field state of unknown age is held back from other apps for at most 14 days",
        ["sync.md 5.1", "sync.md 4.6", "sync.md 12.1"],
        device_json([], highest=4),
    )
    s.step({"restore": unstamped_backup})
    s.step({"days": 13})
    s.query()
    s.step({"days": 1})
    s.query()
    s = new(
        "the hold on a record with a field state of unknown age ends with the first acknowledgement",
        ["sync.md 5.1", "sync.md 12.1", "sync.md 11.3"],
        device_json([], two, highest=4),
    )
    asked = s.step({"restore": unstamped_backup})
    of_tablet, of_laptop = (meaning(sent_to(asked, who))[0]["record"]["id"] for who in two)
    s.receive(request_ack("tablet", of_tablet))
    s.query()
    s.receive(request_ack("laptop", of_laptop))
    s.query()
    s = new(
        "a restored device keeps the requests of its backup that it acted on, and opens its own anew",
        ["sync.md 12.1", "sync.md 11.2", "sync.md 11.3"],
    )
    s.receive(resync_message("tablet"), (0,))
    s.receive(resync_message("tablet", rid=TABLET_REQUEST_2), (0,))
    s.acks()
    of_backup = {**backup, "acted": {TABLET.hex(): [TABLET_REQUEST]}}
    s.step({"restore": of_backup})
    s.receive(resync_message("tablet"))
    s.acks()
    s.receive(resync_message("tablet", rid=TABLET_REQUEST_2))
    s.step({"restore": of_backup})
    s.receive(request_ack("tablet", REQUEST_IDS[0]))
    s.query()
    s.receive(request_ack("tablet", REQUEST_IDS[1]))
    s.query()
    s = new(
        "a restored device that learns of a sibling its backup did not hold acts as after a restore",
        ["sync.md 12.1", "sync.md 4.6", "sync.md 11.3", "sync.md 4.1"],
        device_json([], siblings=(), highest=4),
    )
    s.step({"restore": unstamped_backup})
    s.change("set", {"notes": text_value("call first")}, (0, 0))
    s.step({"add": TABLET.hex()})
    s.query()
    of_sibling = {name: FieldState(value, 0, PHONE) for name, value in VALUE.items()}
    of_sibling["title"] = FieldState(text_value("A"), 0, PHONE)
    s.receive(change_message("tablet", 9, of_sibling, whole=True), (0,))
    s.acks()
    s.query()
    s = new(
        "a device that restores as the only device of its set leaves its field states never stamped",
        ["sync.md 12.1", "sync.md 4.6"],
        device_json([], siblings=(), highest=4),
    )
    s.step({"restore": unstamped_backup})
    s.query()
    s = new(
        "an open request goes again through the relay each time the holding time has passed, not before",
        ["sync.md 11.3", "sync.md 14"],
        base(relay=("tablet",)),
    )
    s.step({"restore": backup})
    for days in (13, 1, 14):
        s.step({"days": days})
    s.query()
    s = new(
        "two devices with requests open toward each other each send their answer",
        ["sync.md 11.3", "sync.md 11.2", "sync.md 3.3"],
    )
    s.step({"restore": backup})
    s.receive(resync_message("tablet"))
    s.receive(answer_message("tablet", OFFER_IDS[0], APPOINTMENT_TYPE), (0,))
    s.acks()
    s.query()
    s = new("a request ends when its sibling is removed", ["sync.md 11.3", "sync.md 12.2"], base(two))
    s.step({"restore": backup})
    s.step({"remove": TABLET.hex()})
    s.query()
    s = new("an entry with the outcome STALE does not acknowledge a request", ["sync.md 11.3", "sync.md 9.2"])
    s.step({"restore": backup})
    s.receive(request_ack("tablet", REQUEST_IDS[0], "STALE"))
    s.query()

    # --- the CHANGE messages a device keeps for their outcome (section 10.1) ---
    s = new(
        "an outcome is taken for a CHANGE last sent 14 days ago, and ignored for one sent 16 days ago",
        ["sync.md 10.1", "sync.md 9.2", "sync.md 9.3", "sync.md 14"],
        base(two),
    )
    sent = s.change("set", {"location": VALUE_WEBER}, (8, 0))
    s.step({"days": 14})
    s.receive(ack_message("tablet", [(111, "APPLIED", 115)]))
    s.step({"days": 2})
    s.receive(ack_message("laptop", [(111, "APPLIED", 116)]))
    s.receive(error_message("laptop", "RECORD_UNKNOWN", sent_to(sent, "laptop")))
    s.query()
    s = new(
        "through the relay a CHANGE without an outcome goes again once the holding time has passed",
        ["sync.md 10.3", "sync.md 10.1", "sync.md 14"],
        base(relay=("tablet",)),
    )
    changed(s)
    for days in (13, 1, 14):
        s.step({"days": days})
    s.receive(ack_message("tablet", [(111, "APPLIED", 115)]))
    s.step({"days": 14})
    s.query()
    a_file = with_fields(BASE, 101, location=FieldState(text_value("a"), -1, TABLET))
    s = new(
        "an outcome delivers a part only if the state still holds it exactly, value and schema included",
        ["sync.md 10.1", "sync.md 9.2", "sync.md 4.1"],
        device_json(
            [record_json(a_file, {"tablet": None, "laptop": [n for n in BASE.fields if n != "location"]})],
            two,
        ),
    )
    s.receive(change_message("tablet", 105, {"title": BASE.fields["title"]}))
    s.receive(change_message("tablet", 106, {"location": FieldState(text_value("b"), -1, TABLET)}), (0,))
    s.receive(ack_message("laptop", [(101, "APPLIED", 110)]))
    s.query()
    s = new(
        "an outcome delivers the parts of its CHANGE that the state still holds, and no later ones",
        ["sync.md 9.2", "sync.md 10.1"],
    )
    changed(s)
    s.change("set", {"location": text_value("Praxis"), "notes": text_value("call first")}, (0, 0))
    s.receive(ack_message("tablet", [(111, "APPLIED", 115)]))
    s.query()
    s.receive(ack_message("tablet", [(113, "APPLIED", 116)]))
    s.query()

    # --- the manifests of the other devices of the set (section 13.2) ---
    s = new(
        "a device takes a sibling's own MANIFEST whatever its revision, and passes it on to the others",
        ["sync.md 13.2", "manifest.md 6", "transports.md 4.5"],
        base(two),
    )
    for who, revision in [("laptop", 3), ("laptop", 3), ("laptop", 2), ("tablet", 1)]:
        s.receive(manifest_message(who, revision))
    s = new(
        "a passed-on MANIFEST replaces the kept one only with a higher revision, and does not go back",
        ["sync.md 13.2", "manifest.md 6", "transports.md 4.5"],
        base(two),
    )
    for revision in (3, 2, 3, 4):
        s.receive(manifest_message("laptop", revision), via="tablet")
    s.receive(manifest_message("laptop", 2))
    s = new(
        "a MANIFEST whose body does not decode as a manifest is ignored, and not passed on",
        ["sync.md 13.2"],
        base(two),
    )
    s.receive(message(LAPTOP_SEED, "MANIFEST", None, MARKER + SPEC_FP["Manifest"] + b"\x02"))
    s.receive(message(LAPTOP_SEED, "MANIFEST", None, body_of("Resync", {"to": PHONE})))
    s = new(
        "a passed-on MANIFEST that is not valid is ignored",
        ["sync.md 13.2", "manifest.md 4"],
        base(two),
    )
    s.receive(manifest_message("laptop", 5, app_name=""), via="tablet")
    s.receive(manifest_message("laptop", 5))
    s = new(
        "through the relay every MANIFEST of a sibling goes by the higher revision",
        ["sync.md 13.2", "manifest.md 6"],
        base(two, relay=("laptop",)),
    )
    for revision in (3, 2, 4):
        s.receive(manifest_message("laptop", revision))
    s = new(
        "a MANIFEST of a key that is no other current device of the set is ignored",
        ["sync.md 13.2", "transports.md 4.5"],
        base(two, **known),
    )
    for who in ("phone", "old phone", "other app", "stranger"):
        s.receive(manifest_message(who, 9))
    kept_manifest = {"tablet": manifest_message("tablet", 5)}
    s = new(
        "a new device gets the kept manifests of the other devices, and not its own",
        ["sync.md 13.2", "sync.md 12.3", "keys.md 5.7"],
        base(manifests=kept_manifest),
    )
    s.step({"add": LAPTOP.hex()})
    s.receive(manifest_message("laptop", 1))
    s.step({"reconnect": LAPTOP.hex()})
    s = new(
        "a manifest that a sibling has got from the device is not passed on to it again",
        ["sync.md 13.2"],
        base(two, manifests=kept_manifest, passed={"laptop": {"tablet": 5}}),
    )
    s.step({"reconnect": LAPTOP.hex()})

    # --- the validity of an offer between siblings (section 7.2) ---
    many = [json.dumps({"type": "record", "name": f"com.example.T{n}", "fields": []}) for n in range(257)]
    large = json.loads(PET_1)
    large["doc"] = "x" * 262144
    offers: list[tuple[str, bytes, str]] = [
        (
            "the nil UUID as its id",
            offer_message("tablet", "0" * 8 + "-0000-0000-0000-" + "0" * 12, [PET_1]),
            "",
        ),
        ("no type", offer_message("tablet", OFFER_IDS[5], []), ""),
        ("257 types", offer_message("tablet", OFFER_IDS[5], many), ""),
        ("a schema that is no JSON text", offer_message("tablet", OFFER_IDS[5], ["{"]), ""),
        ("a count of -1", offer_message("tablet", OFFER_IDS[5], [PET_1], count=-1), ""),
        ("a schema above 256 KiB", offer_message("tablet", OFFER_IDS[5], [json.dumps(large)]), "TOO_LARGE"),
    ]
    for label, m, _ in offers:
        s = new(f"an offer of a sibling with {label} is rejected", ["sync.md 7.2", "protocol.md 4.2"])
        s.receive(m)
    s = new("an offer of a sibling with 256 types is valid", ["sync.md 7.2", "protocol.md 4.2"])
    s.receive(offer_message("tablet", OFFER_IDS[5], many[:256]))

    # --- a removed device (section 12.2) ---
    s = new(
        "a device discards what it kept for a removed sibling, sends it nothing and rejects its messages",
        ["sync.md 12.2", "sync.md 10.1", "keys.md 3.3"],
        base(two),
    )
    changed(s)
    s.receive(
        change_message("tablet", 121, {"notes": FieldState(text_value("call first"), 120, TABLET)}), (0,)
    )
    s.step({"remove": TABLET.hex()})
    s.acks()
    s.receive(ack_message("tablet", [(111, "APPLIED", 130)]))
    s.receive(change_message("tablet", 141, {"title": FieldState(text_value("Vet, Mimi"), 140, TABLET)}))
    s.receive(resync_message("tablet"))
    s.change("set", {"title": text_value("Vet with Mimi")}, (0, 0))
    s.query()

    # --- record messages between siblings (section 7.2) ---
    s = new(
        "a DATA or a DELETE of a sibling is rejected with NOT_ACCEPTED, if the steps before it pass",
        ["sync.md 7.2", "protocol.md 6.2"],
    )
    s.receive(offer_message("tablet", OFFER_IDS[5], [APPOINTMENT_1]))
    s.receive(data_message("tablet", 7, APPOINTMENT_1, APPOINTMENT))
    s.receive(data_message("tablet", 8, APPOINTMENT_1, {}))
    s.receive(data_message("tablet", 7, PET_1, pet, rid=OTHER_ID))
    s.receive(data_message("tablet", 7, APPOINTMENT_1, APPOINTMENT, rid="not-a-uuid"))
    s.receive(data_message("tablet", 0, APPOINTMENT_1, {}))
    s.receive(message(TABLET_SEED, "DELETE", None, b""))
    s.nothing()

    # --- a file of the device's own set (section 13.4) ---
    from_file = device_json([], two, highest=0)
    s = new(
        "a device takes a DATA of a file of its own set with field states of unknown age, which travel",
        ["sync.md 13.4", "sync.md 4.6", "sync.md 4.4", "sync.md 10.2", "sync.md 5.1"],
        from_file,
    )
    s.step(
        {
            "file_record": data_message("tablet", 7, APPOINTMENT_1, APPOINTMENT),
            "schema": APPOINTMENT_1,
            "now_ms": "0",
            "r": [0],
        }
    )
    s.query()
    s.step(
        {
            "file_record": data_message("tablet", 9, APPOINTMENT_1, {**APPOINTMENT, "title": "Vet, Mimi"}),
            "schema": APPOINTMENT_1,
        }
    )
    s.step({"file_record": data_message("tablet", 10, APPOINTMENT_1, {}), "schema": APPOINTMENT_1})
    s.query()
    s = new(
        "a record with field states of unknown age is part of the answer to a RESYNC, like any record",
        ["sync.md 4.6", "sync.md 11.2", "sync.md 13.4"],
        device_json([], highest=0),
    )
    s.step(
        {
            "file_record": data_message("phone", 7, APPOINTMENT_1, APPOINTMENT),
            "schema": APPOINTMENT_1,
            "now_ms": "0",
            "r": [0],
        }
    )
    s.receive(resync_message("tablet"), (0,))
    s.acks()
    s = new(
        "field states of unknown age from a file lose to a sibling's, never stamped or stamped",
        ["sync.md 13.4", "sync.md 4.6", "sync.md 4.1", "sync.md 8.4"],
        from_file,
    )
    taken = {"file_record": data_message("tablet", 7, APPOINTMENT_1, APPOINTMENT), "schema": APPOINTMENT_1}
    s.step({**taken, "now_ms": "0", "r": [0]})
    theirs = {name: FieldState(value, 0, PHONE) for name, value in VALUE.items()}
    theirs["title"] = FieldState(text_value("Vet, Mimi"), 100, TABLET)
    s.receive(change_message("tablet", 105, theirs, whole=True), (0,))
    s.acks()
    s.query()
    s = new(
        "of two field states of unknown age the higher device key stands, then the higher value",
        ["sync.md 4.6", "sync.md 4.1", "sync.md 8.4", "sync.md 10.1"],
        from_file,
    )
    s.step({**taken, "now_ms": "0", "r": [0]})
    lower_key = {"title": FieldState(text_value("Vet, Mimi"), -1, PHONE)}
    s.receive(change_message("laptop", 3, lower_key))
    higher_value = {"title": FieldState(text_value("Vez"), -1, TABLET)}
    s.receive(change_message("laptop", 4, higher_value), (0,))
    s.acks()
    s.query()
    s = new(
        "a device takes from a file of its own set no DELETE, and no DATA that fails as a record message",
        ["sync.md 13.4", "protocol.md 6.2"],
        from_file,
    )
    for m in [
        data_message("phone", 7, APPOINTMENT_1, {}),
        data_message("phone", 0, APPOINTMENT_1, APPOINTMENT),
        data_message("phone", 7, APPOINTMENT_1, APPOINTMENT, rid="not-a-uuid"),
        data_message("phone", 7, APPOINTMENT_1, {**APPOINTMENT, "start": {**START_1030, "month": 13}}),
        data_message("phone", 7, APPOINTMENT_1, APPOINTMENT, more=b"\x00"),
        data_message("phone", 7, PET_1, pet),
        message(PHONE_SEED, "DATA", (RECORD_ID, 7), MARKER + SCHEMA_1 + b"".join(VALUE.values())[:-3]),
    ]:
        s.step({"file_record": m, "schema": APPOINTMENT_1})
    s.query()
    return out


SAID: dict[str, list[list[str]]] = {
    "a CHANGE of the device's own key is ignored": [
        [
            "outcome: None",
        ],
        [],
        [
            "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "a RESYNC of the device's own key is ignored": [
        [
            "outcome: None",
        ],
        [],
        [
            "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "a CHANGE of a removed key of the device's own set is rejected without a report": [
        [
            "outcome: None",
        ],
        [],
        [
            "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "a RESYNC of a removed key of the device's own set is rejected without a report": [
        [
            "outcome: None",
        ],
        [],
        [
            "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "a CHANGE of a current key of another known sender is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to other app: INVALID_MESSAGE",
        ],
        [],
        [
            "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "a RESYNC of a current key of another known sender is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to other app: INVALID_MESSAGE",
        ],
        [],
        [
            "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "a CHANGE of a removed key of another sender, or a refused key, is rejected without a report": [
        [
            "outcome: None",
        ],
        [],
        [
            "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "a RESYNC of a removed key of another sender, or a refused key, is rejected without a report": [
        [
            "outcome: None",
        ],
        [],
        [
            "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "a CHANGE of a key the device does not know is not processed": [
        [
            "outcome: None",
        ],
        [],
        [
            "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "a RESYNC of a key the device does not know is not processed": [
        [
            "outcome: None",
        ],
        [],
        [
            "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "a CHANGE of a sibling for another device is ignored": [
        [
            "outcome: None",
        ],
        [],
        [
            "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101",
            "laptop: known, delivered: all",
            "tablet: known, delivered: all",
        ],
    ],
    "a RESYNC of a sibling for another device is ignored": [
        [
            "outcome: None",
        ],
        [],
        [
            "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101",
            "laptop: known, delivered: all",
            "tablet: known, delivered: all",
        ],
    ],
    "step 1: a CHANGE without a record is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "step 1: a RESYNC without a record is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "step 1: a CHANGE without a record is reported to another app, and to no key that is not known": [
        [
            "outcome: None",
            "ERROR to other app: INVALID_MESSAGE",
        ],
        [
            "outcome: None",
        ],
        [
            "outcome: None",
        ],
        [],
        [
            "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "step 3: a CHANGE whose body is no axt.Change is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "step 2: the body of a CHANGE of another app is not read": [
        [
            "outcome: None",
            "ERROR to other app: INVALID_MESSAGE",
        ],
        [
            "outcome: None",
        ],
        [],
        [
            "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "step 4: a CHANGE with an id that is no UUID is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: RECORD_ID_INVALID",
        ],
        [],
        [
            "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "step 4: a CHANGE with an id with a letter that is no hexadecimal digit is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: RECORD_ID_INVALID",
        ],
        [],
        [
            "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "step 4: a CHANGE with an id of 65 bytes that the error cannot repeat is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: RECORD_ID_INVALID",
        ],
        [],
        [
            "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "step 4: a CHANGE with the nil UUID is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: RECORD_ID_INVALID",
        ],
        [],
        [
            "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "step 4: a CHANGE with the max UUID is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: RECORD_ID_INVALID",
        ],
        [],
        [
            "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "step 4: an id in upper case names the same record": [
        [
            "outcome: APPLIED",
        ],
        [
            "ACK of 3F2C8A5E to tablet: version 111 APPLIED, receiver 115",
        ],
        [
            (
                "state stamp 115; all_day,end,notes,reminders,start,title@100p location@110t; "
                "sibling stamp 111; to pass None; highest 115"
            ),
            "tablet: known, delivered: all",
        ],
    ],
    "step 5: a CHANGE with the version 0 is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: VERSION_INVALID",
        ],
        [],
        [
            "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "step 5: a CHANGE with the version -1 is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: VERSION_INVALID",
        ],
        [],
        [
            "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "step 6: a CHANGE with a key in origin is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no record; highest 101",
        ],
    ],
    "step 6: a CHANGE with a type with an empty name between two dots is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no record; highest 101",
        ],
    ],
    "step 6: a CHANGE with a type that begins with a digit is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no record; highest 101",
        ],
    ],
    "step 6: a CHANGE with an empty type is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no record; highest 101",
        ],
    ],
    "step 6: a CHANGE with a type with a space at its end is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no record; highest 101",
        ],
    ],
    "step 6: a CHANGE with a type of 513 bytes is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no record; highest 101",
        ],
    ],
    "step 6: a CHANGE with a state of 0 is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no record; highest 101",
        ],
    ],
    "step 6: a CHANGE with a removal with the stamp 0 is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no record; highest 101",
        ],
    ],
    "step 6: a CHANGE with 4,097 entries in fields is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no record; highest 101",
        ],
    ],
    "step 6: a CHANGE with an empty name is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no record; highest 101",
        ],
    ],
    "step 6: a CHANGE with a name of 513 bytes is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no record; highest 101",
        ],
    ],
    "step 6: a CHANGE with a name twice is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no record; highest 101",
        ],
    ],
    "step 6: a CHANGE with a null value is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no record; highest 101",
        ],
    ],
    "step 6: a CHANGE with a field state with the stamp -2 is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no record; highest 101",
        ],
    ],
    "step 6: a CHANGE with nothing in it that is not whole is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no record; highest 101",
        ],
    ],
    "step 6: a CHANGE with a version above its highest stamp is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no record; highest 101",
        ],
    ],
    "step 6: a CHANGE with a version below its highest stamp is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no record; highest 101",
        ],
    ],
    "step 6: a CHANGE with 4,096 entries in fields is within the limits": [
        [
            "outcome: None",
            "ERROR to tablet: SCHEMA_UNKNOWN, fingerprint 0102030405060708",
        ],
        [],
    ],
    "step 6: a CHANGE with a name of 512 bytes is within the limits": [
        [
            "outcome: None",
            "ERROR to tablet: SCHEMA_UNKNOWN, fingerprint 0102030405060708",
        ],
        [],
    ],
    "step 6: a CHANGE with two names that differ only in their Unicode normalization is within the limits": [
        [
            "outcome: None",
            "ERROR to tablet: SCHEMA_UNKNOWN, fingerprint 0102030405060708",
        ],
        [],
    ],
    "step 6: a CHANGE with a type of 512 bytes is within the limits": [
        [
            "outcome: APPLIED",
        ],
        [
            "ACK of 7b1e6c2a to tablet: version 111 APPLIED, receiver 112",
        ],
    ],
    "step 6: every stamp up to the largest long is valid, and none is refused": [
        [
            "outcome: APPLIED",
        ],
        [
            "ACK to tablet: version 9223372036854775807 APPLIED, receiver 9223372036854775807",
        ],
        [
            (
                "state stamp None; all_day,end,notes,reminders,start,title@100p "
                "location@9223372036854775807t removal@9223372036854775807t, taken back; sibling "
                "stamp 9223372036854775807; to pass None; highest 9223372036854775807"
            ),
            "tablet: known, delivered: all and the removal",
        ],
    ],
    "step 6: the device keys of a removal and of a field state are not checked": [
        [
            "outcome: APPLIED",
        ],
        [
            "ACK to tablet: version 121 APPLIED, receiver 122",
        ],
        [
            (
                "state stamp 122; all_day,end,notes,reminders,start,title@100p location@110? "
                "removal@120o, taken back; sibling stamp 121; to pass None; highest 122"
            ),
            "tablet: known, delivered: all and the removal",
        ],
    ],
    "step 6: a field state never stamped is valid, and loses against a stamped one": [
        [
            "outcome: STALE",
            "CHANGE to tablet, version 101, state 101, in part: location@100p",
        ],
        [
            "ACK to tablet: version 105 STALE, receiver 101",
        ],
        [
            "state stamp 101; all seven@100p; sibling stamp 105; to pass None; highest 105",
            "tablet: known, delivered: all_day,end,notes,reminders,start,title",
        ],
    ],
    "step 6: a field state of unknown age, with the stamp -1, is valid, and loses against every other": [
        [
            "outcome: STALE",
            "CHANGE to tablet, version 101, state 101, in part: location@100p",
        ],
        [
            "ACK to tablet: version 105 STALE, receiver 101",
        ],
        [
            "state stamp 101; all seven@100p; sibling stamp 105; to pass None; highest 105",
            "tablet: known, delivered: all_day,end,notes,reminders,start,title",
        ],
    ],
    "step 7: the error names the first schema, in the order of the message, that the device lacks": [
        [
            "outcome: None",
            "ERROR to tablet: SCHEMA_UNKNOWN, fingerprint 1112131415161718",
        ],
        [],
        [
            "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "step 7: a schema that another sibling offered is held, whichever sibling names it": [
        [
            "outcome: None",
            "ACCEPT 00000006 to laptop: axt.example.v1.Appointment",
        ],
        [
            "outcome: APPLIED",
            "OFFER 00000001 to laptop: axt.example.v1.Appointment version 2",
        ],
    ],
    "step 7: a schema is not held once the offer that brought it ended, if no field state names it": [
        [
            "outcome: None",
            "ACCEPT 00000006 to laptop: axt.example.v1.Appointment",
        ],
        [],
        [
            "outcome: None",
            "ERROR to tablet: SCHEMA_UNKNOWN, fingerprint 051c22f83081ef02",
        ],
    ],
    "step 8: a schema of another type than the message names is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no record; highest 101",
        ],
    ],
    "step 8: a name that is no field of the schema it names is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "step 9: a CHANGE that names another type for a record the device holds is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: TYPE_CHANGED",
        ],
        [],
        [
            "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "step 10: a CHANGE in part for a record the device lacks is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: RECORD_UNKNOWN",
        ],
        [],
        [
            "no record; highest 101",
        ],
    ],
    "step 10: a CHANGE in part for a record of which the device holds only the removal is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: RECORD_UNKNOWN",
        ],
        [],
        [
            "state stamp 151; no field removal@150p; sibling stamp None; to pass None; highest 151",
            "tablet: known, delivered: all and the removal",
        ],
    ],
    "step 10: a whole CHANGE gives the field states back to a device that holds only the removal": [
        [
            "outcome: APPLIED",
        ],
        [
            "ACK to tablet: version 161 APPLIED, receiver 162",
        ],
        [
            (
                "state stamp 162; all_day,end,notes,reminders,start,title@100p location@160t "
                "removal@150p; sibling stamp 161; to pass None; highest 162"
            ),
            "tablet: known, delivered: all and the removal",
        ],
    ],
    "step 10: a CHANGE in part passes for a record whose state holds no field state and no removal": [
        [
            "outcome: APPLIED",
        ],
        [
            "ACK to tablet: version 151 APPLIED, receiver 152",
        ],
        [
            "state stamp 152; no field removal@150t; sibling stamp 151; to pass None; highest 152",
            "tablet: known, delivered: all and the removal",
        ],
    ],
    "step 10: a whole CHANGE brings a record the device lacks, and the device keeps its type": [
        [
            "outcome: APPLIED",
        ],
        [
            "ACK of 7b1e6c2a to tablet: version 111 APPLIED, receiver 112",
        ],
        [
            (
                "state stamp 112; all_day,end,notes,reminders,start,title@100p location@110t; "
                "sibling stamp 111; to pass None; highest 112"
            ),
            "tablet: known, delivered: all",
        ],
    ],
    "step 11: a value with a string that is cut short is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: UNDECODABLE",
        ],
        [],
        [
            "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "step 11: a value with a byte left over after the value is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: UNDECODABLE",
        ],
        [],
        [
            "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "step 11: a value with a string that is not well-formed UTF-8 is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: UNDECODABLE",
        ],
        [],
        [
            "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "step 11: a value with no bytes is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: UNDECODABLE",
        ],
        [],
        [
            "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "step 11: a value at the data depth 32 is within the limit": [
        [
            "outcome: APPLIED",
        ],
        [
            "ACK of 7b1e6c2a to tablet: version 111 APPLIED, receiver 112",
        ],
    ],
    "step 11: a value at the data depth 33 is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: UNDECODABLE",
        ],
        [],
    ],
    "step 12: a time value that is not valid is rejected, with the path of the first one": [
        [
            "outcome: None",
            "ERROR to tablet: VALUE_INVALID, field reminders[1]",
        ],
        [],
        [
            "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "step 12: a time value that is not valid inside a record is named from the field on": [
        [
            "outcome: None",
            "ERROR to tablet: VALUE_INVALID, field start",
        ],
        [],
        [
            "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "an id that is no UUID and a body that is not valid: step 4 comes first": [
        [
            "outcome: None",
            "ERROR to tablet: RECORD_ID_INVALID",
        ],
        [],
    ],
    "a version of 0 and a body that is not valid: step 5 comes first": [
        [
            "outcome: None",
            "ERROR to tablet: VERSION_INVALID",
        ],
        [],
    ],
    "a body that is not valid and a schema the device lacks: step 6 comes first": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
    ],
    "a schema the device lacks and another type: step 7 comes first": [
        [
            "outcome: None",
            "ERROR to tablet: SCHEMA_UNKNOWN, fingerprint 0102030405060708",
        ],
        [],
    ],
    "a schema of another type and another type than the device keeps: step 8 comes first": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
    ],
    "a record the device lacks and a value that does not decode: step 10 comes first": [
        [
            "outcome: None",
            "ERROR to tablet: RECORD_UNKNOWN",
        ],
        [],
    ],
    "a time value that is not valid and, after it, a value that does not decode: step 11 comes first": [
        [
            "outcome: None",
            "ERROR to tablet: UNDECODABLE",
        ],
        [],
    ],
    "another type and a CHANGE in part for a record held as its removal alone: step 9 comes first": [
        [
            "outcome: None",
            "ERROR to tablet: TYPE_CHANGED",
        ],
        [],
    ],
    "a CHANGE with a later field state is applied, and the device takes a new state stamp": [
        [
            "outcome: APPLIED",
        ],
        [
            "ACK to tablet: version 111 APPLIED, receiver 115",
        ],
        [
            (
                "state stamp 115; all_day,end,notes,reminders,start,title@100p location@110t; "
                "sibling stamp 111; to pass None; highest 115"
            ),
            "tablet: known, delivered: all",
        ],
    ],
    "a CHANGE whose field state the device holds is a duplicate, and its state stamp still counts": [
        [
            "outcome: DUPLICATE",
        ],
        [
            "ACK to tablet: version 105 DUPLICATE, receiver 101",
        ],
        [
            "state stamp 101; all seven@100p; sibling stamp 105; to pass None; highest 105",
            "tablet: known, delivered: all",
        ],
    ],
    "a whole CHANGE without a field state and a removal, for a record the device holds, is a duplicate": [
        [
            "outcome: DUPLICATE",
        ],
        [
            "ACK to tablet: version 105 DUPLICATE, receiver 101",
        ],
        [
            "state stamp 101; all seven@100p; sibling stamp 105; to pass None; highest 105",
            "tablet: known, delivered: all",
        ],
    ],
    "a CHANGE with an earlier field state is stale, and the later one is due for the sibling again": [
        [
            "outcome: STALE",
            "CHANGE to tablet, version 121, state 121, in part: location@120p",
        ],
        [
            "ACK to tablet: version 111 STALE, receiver 121",
        ],
        [
            (
                "state stamp 121; all_day,end,notes,reminders,start,title@100p location@120p; "
                "sibling stamp 111; to pass None; highest 121"
            ),
            "tablet: known, delivered: all_day,end,notes,reminders,start,title",
        ],
    ],
    "a CHANGE with one later and one earlier field state is applied": [
        [
            "outcome: APPLIED",
            "CHANGE to tablet, version 127, state 127, in part: location@120p",
        ],
        [
            "ACK to tablet: version 126 APPLIED, receiver 127",
        ],
        [
            (
                "state stamp 127; all_day,end,reminders,start,title@100p location@120p "
                "notes@125t; sibling stamp 126; to pass None; highest 127"
            ),
            "tablet: known, delivered: all_day,end,notes,reminders,start,title",
        ],
    ],
    "a CHANGE that is processed a second time is a duplicate": [
        [
            "outcome: APPLIED",
        ],
        [
            "outcome: DUPLICATE",
        ],
        [
            "ACK to tablet: version 111 APPLIED, receiver 115",
            "ACK to tablet: version 111 DUPLICATE, receiver 115",
        ],
        [
            (
                "state stamp 115; all_day,end,notes,reminders,start,title@100p location@110t; "
                "sibling stamp 111; to pass None; highest 115"
            ),
            "tablet: known, delivered: all",
        ],
    ],
    "a CHANGE that is processed again after the record has moved on is stale": [
        [
            "outcome: APPLIED",
        ],
        [
            "ACK to tablet: version 111 APPLIED, receiver 115",
        ],
        [
            "made: True",
            "CHANGE to tablet, version 117, state 117, in part: location@116p",
        ],
        [
            "outcome: STALE",
            "CHANGE to tablet, version 117, state 117, in part: location@116p",
        ],
        [
            "ACK to tablet: version 111 STALE, receiver 117",
        ],
        [
            (
                "state stamp 117; all_day,end,notes,reminders,start,title@100p location@116p; "
                "sibling stamp 111; to pass None; highest 117"
            ),
            "tablet: known, delivered: all_day,end,notes,reminders,start,title",
        ],
    ],
    "a CHANGE with a removal that stands deletes the record": [
        [
            "outcome: APPLIED",
        ],
        [
            "ACK to tablet: version 151 APPLIED, receiver 152",
        ],
        [
            "state stamp 152; all seven@100p removal@150t; sibling stamp 151; to pass None; highest 152",
            "tablet: known, delivered: all and the removal",
        ],
    ],
    "a CHANGE without a removal leaves the removal, and a later field state brings the record back": [
        [
            "outcome: APPLIED",
        ],
        [
            "ACK to tablet: version 161 APPLIED, receiver 162",
        ],
        [
            (
                "state stamp 162; all_day,end,notes,reminders,start,title@100p location@160t "
                "removal@150p; sibling stamp 161; to pass None; highest 162"
            ),
            "tablet: known, delivered: all and the removal",
        ],
    ],
    "a CHANGE with a removal that was taken back brings the record back": [
        [
            "outcome: APPLIED",
        ],
        [
            "ACK to tablet: version 171 APPLIED, receiver 172",
        ],
        [
            (
                "state stamp 172; all seven@100p removal@170t, taken back; sibling stamp 171; to "
                "pass None; highest 172"
            ),
            "tablet: known, delivered: all and the removal",
        ],
    ],
    "a CHANGE with the removal the device holds is a duplicate": [
        [
            "outcome: DUPLICATE",
        ],
        [
            "ACK to tablet: version 155 DUPLICATE, receiver 151",
        ],
        [
            "state stamp 151; all seven@100p removal@150p; sibling stamp 155; to pass None; highest 155",
            "tablet: known, delivered: all and the removal",
        ],
    ],
    "a CHANGE with an earlier removal is stale": [
        [
            "outcome: STALE",
            "CHANGE to tablet, version 151, state 151, in part: no field removal@150p",
        ],
        [
            "ACK to tablet: version 141 STALE, receiver 151",
        ],
        [
            "state stamp 151; all seven@100p removal@150p; sibling stamp 141; to pass None; highest 151",
            "tablet: known, delivered: all",
        ],
    ],
    "a CHANGE that gives the device a state stamp above the version to pass drops that version": [
        [
            "outcome: APPLIED",
        ],
        [
            "ACK to tablet: version 111 APPLIED, receiver 121",
        ],
        [
            (
                "state stamp 121; all_day,end,notes,reminders,start,title@100p location@110t; "
                "sibling stamp 111; to pass None; highest 121"
            ),
            "tablet: known, delivered: all",
        ],
    ],
    "a field that the device's schema lacks is kept and passed on, its schema offered first": [
        [
            "outcome: None",
            "ACCEPT 00000006 to tablet: axt.example.v1.Appointment",
        ],
        [
            "outcome: APPLIED",
            "OFFER 00000001 to laptop: axt.example.v1.Appointment version 2",
        ],
        [
            "outcome: None",
            "CHANGE to laptop, version 127, state 127, in part: room@125t",
        ],
        [
            "ACK to tablet: version 126 APPLIED, receiver 127",
        ],
        [
            "state stamp 127; all seven@100p room@125t; sibling stamp 126; to pass None; highest 127",
            "laptop: known, delivered: all_day,end,location,notes,reminders,start,title",
            "tablet: known, delivered: all",
        ],
    ],
    "a record of a type the device does not know is kept whole and passed on": [
        [
            "outcome: None",
            "ACCEPT 00000006 to tablet: axt.example.v1.Pet",
        ],
        [
            "outcome: APPLIED",
            "OFFER 00000001 to laptop: axt.example.v1.Pet version 1",
        ],
        [
            "outcome: None",
            "CHANGE of 7b1e6c2a to laptop, version 202, state 202, whole: all seven@200t",
        ],
        [
            "ACK of 7b1e6c2a to tablet: version 201 APPLIED, receiver 202",
        ],
    ],
    "a value written with a schema that does not resolve against the device's own is kept": [
        [
            "outcome: None",
            "ACCEPT 00000006 to tablet: axt.example.v1.Appointment",
        ],
        [
            "outcome: APPLIED",
        ],
        [
            "ACK to tablet: version 131 APPLIED, receiver 132",
        ],
        [
            (
                "state stamp 132; all_day,end,location,notes,reminders,start@100p title@130t; "
                "sibling stamp 131; to pass None; highest 132"
            ),
            "tablet: known, delivered: all",
        ],
    ],
    "a device accepts every type a sibling offers, also one it lacks and one that does not resolve": [
        [
            "outcome: None",
            "ACCEPT 00000006 to tablet: axt.example.v1.Appointment, axt.example.v1.Pet",
        ],
    ],
    "an offer of a sibling that holds one full name twice is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: OFFER_INVALID",
        ],
    ],
    "an offer of a sibling with a schema that is no record is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: OFFER_INVALID",
        ],
    ],
    "an offer of a sibling for another device is ignored": [
        [
            "outcome: None",
        ],
    ],
    "a device sends no CHANGE that names a schema a sibling declined": [
        [
            "made: True",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
            "OFFER 00000001 to laptop: axt.example.v1.Appointment version 1",
        ],
        [
            "outcome: None",
        ],
        [
            "made: True",
            "CHANGE to tablet, version 113, state 113, in part: location@110p notes@112p",
        ],
    ],
    "a device offers a schema once, and waits for the answer": [
        [
            "made: True",
            "OFFER 00000001 to tablet: axt.example.v1.Appointment version 1",
        ],
        [
            "made: True",
        ],
        [
            "outcome: None",
            "CHANGE to tablet, version 113, state 113, in part: location@110p notes@112p",
        ],
    ],
    "two schemas of one type are on offer at once, and a CHANGE that names both waits for both": [
        [
            "OFFER 00000001 to laptop: axt.example.v1.Appointment version 2",
            "OFFER 00000002 to laptop: axt.example.v1.Appointment version 1",
        ],
        [
            "outcome: None",
        ],
        [
            "outcome: None",
            "CHANGE to laptop, version 127, state 127, whole: all seven@100p room@125t",
        ],
    ],
    "an answer to an offer that the device did not make is ignored": [
        [
            "outcome: None",
        ],
    ],
    "an answer that names another type than the offer is rejected": [
        [
            "made: True",
            "OFFER 00000001 to tablet: axt.example.v1.Appointment version 1",
        ],
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
    ],
    (
        "the outcome APPLIED of a sibling delivers the parts of the message, and the "
        "sibling's state stamp counts as seen"
    ): [
        [
            "made: True",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: None",
        ],
        [
            (
                "state stamp 111; title,start,end,all_day,notes,reminders@100p location@110p; "
                "sibling stamp 115; to pass None; highest 115"
            ),
            "tablet: known, delivered: all",
        ],
    ],
    (
        "the outcome DUPLICATE of a sibling delivers the parts of the message, also with "
        "a state stamp below the version"
    ): [
        [
            "made: True",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: None",
        ],
        [
            (
                "state stamp 111; title,start,end,all_day,notes,reminders@100p location@110p; "
                "sibling stamp 105; to pass None; highest 111"
            ),
            "tablet: known, delivered: all",
        ],
    ],
    (
        "the outcome STALE of a sibling delivers the parts of the message, and the device "
        "keeps no version to pass"
    ): [
        [
            "made: True",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: None",
        ],
        [
            (
                "state stamp 111; title,start,end,all_day,notes,reminders@100p location@110p; "
                "sibling stamp 130; to pass None; highest 130"
            ),
            "tablet: known, delivered: all",
        ],
    ],
    "an outcome for an id and version that the device did not send to that sibling is ignored": [
        [
            "made: True",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: None",
        ],
        [
            "outcome: None",
        ],
        [
            (
                "state stamp 111; title,start,end,all_day,notes,reminders@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,reminders,start,title",
        ],
    ],
    "the first outcome for an id and version stands": [
        [
            "made: True",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: None",
        ],
        [
            "outcome: None",
        ],
        [
            (
                "state stamp 111; title,start,end,all_day,notes,reminders@100p location@110p; "
                "sibling stamp 115; to pass None; highest 115"
            ),
            "tablet: known, delivered: all",
        ],
    ],
    "an ACK of a sibling for another device is ignored": [
        [
            "made: True",
            "CHANGE to laptop, version 111, state 111, in part: location@110p",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: None",
        ],
        [
            (
                "state stamp 111; title,start,end,all_day,notes,reminders@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "laptop: known, delivered: all_day,end,notes,reminders,start,title",
            "tablet: known, delivered: all_day,end,notes,reminders,start,title",
        ],
    ],
    "an ACK of a sibling with the outcome MERGED is not valid, and none of its entries is taken": [
        [
            "made: True",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [
            (
                "state stamp 111; title,start,end,all_day,notes,reminders@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,reminders,start,title",
        ],
    ],
    "an ACK of a sibling with the outcome KEPT is not valid, and none of its entries is taken": [
        [
            "made: True",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [
            (
                "state stamp 111; title,start,end,all_day,notes,reminders@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,reminders,start,title",
        ],
    ],
    "an ACK of a sibling with the outcome WITHDRAWN is not valid, and none of its entries is taken": [
        [
            "made: True",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [
            (
                "state stamp 111; title,start,end,all_day,notes,reminders@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,reminders,start,title",
        ],
    ],
    "an ACK of a sibling with a kept field is not valid, and none of its entries is taken": [
        [
            "made: True",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [
            (
                "state stamp 111; title,start,end,all_day,notes,reminders@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,reminders,start,title",
        ],
    ],
    "an ACK of a sibling with a receiver_version of 0 is not valid, and none of its entries is taken": [
        [
            "made: True",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [
            (
                "state stamp 111; title,start,end,all_day,notes,reminders@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,reminders,start,title",
        ],
    ],
    "an ACK of a sibling with a version of 0 is not valid, and none of its entries is taken": [
        [
            "made: True",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [
            (
                "state stamp 111; title,start,end,all_day,notes,reminders@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,reminders,start,title",
        ],
    ],
    "an ACK of a sibling with an id and version twice is not valid, and none of its entries is taken": [
        [
            "made: True",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [
            (
                "state stamp 111; title,start,end,all_day,notes,reminders@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,reminders,start,title",
        ],
    ],
    "an ACK of a sibling with an id that is no UUID is not valid, and none of its entries is taken": [
        [
            "made: True",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [
            (
                "state stamp 111; title,start,end,all_day,notes,reminders@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,reminders,start,title",
        ],
    ],
    "an ACK of a sibling with no entry is not valid, and none of its entries is taken": [
        [
            "made: True",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [
            (
                "state stamp 111; title,start,end,all_day,notes,reminders@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,reminders,start,title",
        ],
    ],
    "after SCHEMA_UNKNOWN the device offers the schema, and sends the same CHANGE once it is accepted": [
        [
            "made: True",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: None",
            "OFFER 00000001 to tablet: axt.example.v1.Appointment version 1",
        ],
        [
            "outcome: None",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            (
                "state stamp 111; title,start,end,all_day,notes,reminders@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,reminders,start,title",
        ],
    ],
    "after SCHEMA_UNKNOWN without a fingerprint the device sends the same CHANGE again at once": [
        [
            "made: True",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: None",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
    ],
    "after RECORD_UNKNOWN the device sends the record whole, under a new state stamp": [
        [
            "made: True",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: None",
            (
                "CHANGE to tablet, version 114, state 114, whole: "
                "title,start,end,all_day,notes,reminders@100p location@110p"
            ),
        ],
        [
            (
                "state stamp 114; title,start,end,all_day,notes,reminders@100p location@110p; "
                "sibling stamp None; to pass None; highest 114"
            ),
            "tablet: not known",
        ],
    ],
    "after FORMAT_UNSUPPORTED the device sends the CHANGE again": [
        [
            "made: True",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: None",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
    ],
    "after RECORD_ID_INVALID the device does not send the CHANGE again; its parts go with the next state": [
        [
            "made: True",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: None",
        ],
        [],
        [
            (
                "state stamp 111; title,start,end,all_day,notes,reminders@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,reminders,start,title",
        ],
        [
            "made: True",
            "OFFER 00000001 to tablet: axt.example.v1.Appointment version 1",
        ],
        [
            "outcome: None",
            "CHANGE to tablet, version 113, state 113, in part: location@110p notes@112p",
        ],
    ],
    "after VERSION_INVALID the device does not send the CHANGE again; its parts go with the next state": [
        [
            "made: True",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: None",
        ],
        [],
        [
            (
                "state stamp 111; title,start,end,all_day,notes,reminders@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,reminders,start,title",
        ],
        [
            "made: True",
            "OFFER 00000001 to tablet: axt.example.v1.Appointment version 1",
        ],
        [
            "outcome: None",
            "CHANGE to tablet, version 113, state 113, in part: location@110p notes@112p",
        ],
    ],
    "after INVALID_MESSAGE the device does not send the CHANGE again; its parts go with the next state": [
        [
            "made: True",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: None",
        ],
        [],
        [
            (
                "state stamp 111; title,start,end,all_day,notes,reminders@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,reminders,start,title",
        ],
        [
            "made: True",
            "OFFER 00000001 to tablet: axt.example.v1.Appointment version 1",
        ],
        [
            "outcome: None",
            "CHANGE to tablet, version 113, state 113, in part: location@110p notes@112p",
        ],
    ],
    "after TYPE_CHANGED the device does not send the CHANGE again; its parts go with the next state": [
        [
            "made: True",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: None",
        ],
        [],
        [
            (
                "state stamp 111; title,start,end,all_day,notes,reminders@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,reminders,start,title",
        ],
        [
            "made: True",
            "OFFER 00000001 to tablet: axt.example.v1.Appointment version 1",
        ],
        [
            "outcome: None",
            "CHANGE to tablet, version 113, state 113, in part: location@110p notes@112p",
        ],
    ],
    "after UNDECODABLE the device does not send the CHANGE again; its parts go with the next state": [
        [
            "made: True",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: None",
        ],
        [],
        [
            (
                "state stamp 111; title,start,end,all_day,notes,reminders@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,reminders,start,title",
        ],
        [
            "made: True",
            "OFFER 00000001 to tablet: axt.example.v1.Appointment version 1",
        ],
        [
            "outcome: None",
            "CHANGE to tablet, version 113, state 113, in part: location@110p notes@112p",
        ],
    ],
    "after VALUE_INVALID the device does not send the CHANGE again; its parts go with the next state": [
        [
            "made: True",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: None",
        ],
        [],
        [
            (
                "state stamp 111; title,start,end,all_day,notes,reminders@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,reminders,start,title",
        ],
        [
            "made: True",
            "OFFER 00000001 to tablet: axt.example.v1.Appointment version 1",
        ],
        [
            "outcome: None",
            "CHANGE to tablet, version 113, state 113, in part: location@110p notes@112p",
        ],
    ],
    "after TOO_LARGE the device does not send the CHANGE again; its parts go with the next state": [
        [
            "made: True",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: None",
        ],
        [],
        [
            (
                "state stamp 111; title,start,end,all_day,notes,reminders@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,reminders,start,title",
        ],
        [
            "made: True",
            "OFFER 00000001 to tablet: axt.example.v1.Appointment version 1",
        ],
        [
            "outcome: None",
            "CHANGE to tablet, version 113, state 113, in part: location@110p notes@112p",
        ],
    ],
    "after SIGNATURE_INVALID the device does not send the CHANGE again; its parts go with the next state": [
        [
            "made: True",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: None",
        ],
        [],
        [
            (
                "state stamp 111; title,start,end,all_day,notes,reminders@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,reminders,start,title",
        ],
        [
            "made: True",
            "OFFER 00000001 to tablet: axt.example.v1.Appointment version 1",
        ],
        [
            "outcome: None",
            "CHANGE to tablet, version 113, state 113, in part: location@110p notes@112p",
        ],
    ],
    "after NOT_ACCEPTED the device does not send the CHANGE again; its parts go with the next state": [
        [
            "made: True",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: None",
        ],
        [],
        [
            (
                "state stamp 111; title,start,end,all_day,notes,reminders@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,reminders,start,title",
        ],
        [
            "made: True",
            "OFFER 00000001 to tablet: axt.example.v1.Appointment version 1",
        ],
        [
            "outcome: None",
            "CHANGE to tablet, version 113, state 113, in part: location@110p notes@112p",
        ],
    ],
    "an ACK of a sibling with 4,096 entries is valid, and its entries are taken": [
        [
            "made: True",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: None",
        ],
        [
            (
                "state stamp 111; title,start,end,all_day,notes,reminders@100p location@110p; "
                "sibling stamp 115; to pass None; highest 115"
            ),
            "tablet: known, delivered: all",
        ],
    ],
    "an ACK of a sibling with 4,097 entries is not valid": [
        [
            "made: True",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [
            (
                "state stamp 111; title,start,end,all_day,notes,reminders@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,reminders,start,title",
        ],
    ],
    "an ERROR about a CHANGE that has an outcome is ignored": [
        [
            "made: True",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: None",
        ],
        [
            "outcome: None",
        ],
        [
            (
                "state stamp 111; title,start,end,all_day,notes,reminders@100p location@110p; "
                "sibling stamp 115; to pass None; highest 115"
            ),
            "tablet: known, delivered: all",
        ],
    ],
    "an ERROR of a sibling for another device is ignored": [
        [
            "made: True",
            "CHANGE to laptop, version 111, state 111, in part: location@110p",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: None",
        ],
        [
            (
                "state stamp 111; title,start,end,all_day,notes,reminders@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "laptop: known, delivered: all_day,end,notes,reminders,start,title",
            "tablet: known, delivered: all_day,end,notes,reminders,start,title",
        ],
    ],
    "an ERROR about a message that the device did not send to that sibling changes nothing": [
        [
            "made: True",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: None",
        ],
        [
            (
                "state stamp 111; title,start,end,all_day,notes,reminders@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,reminders,start,title",
        ],
    ],
    "a change travels in part to every sibling, and an acknowledged part does not go again": [
        [
            "made: True",
            "CHANGE to laptop, version 111, state 111, in part: location@110p",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: None",
        ],
        [
            "made: True",
            "CHANGE to laptop, version 117, state 117, in part: location@110p notes@116p",
            "CHANGE to tablet, version 117, state 117, in part: notes@116p",
        ],
        [
            (
                "state stamp 117; title,start,end,all_day,reminders@100p location@110p "
                "notes@116p; sibling stamp 115; to pass None; highest 117"
            ),
            "laptop: known, delivered: all_day,end,reminders,start,title",
            "tablet: known, delivered: all_day,end,location,reminders,start,title",
        ],
    ],
    "a part that the device took from one sibling goes to the others, and not back": [
        [
            "outcome: APPLIED",
            "CHANGE to laptop, version 115, state 115, in part: location@110t",
        ],
        [
            "ACK to tablet: version 111 APPLIED, receiver 115",
        ],
        [
            "outcome: None",
        ],
        [
            (
                "state stamp 115; all_day,end,notes,reminders,start,title@100p location@110t; "
                "sibling stamp 119; to pass None; highest 119"
            ),
            "laptop: known, delivered: all",
            "tablet: known, delivered: all",
        ],
    ],
    "a record travels whole on its first transfer to a sibling, and in part to a sibling that knows it": [
        [
            "made: True",
            (
                "CHANGE to laptop, version 111, state 111, whole: "
                "title,start,end,all_day,notes,reminders@100p location@110p"
            ),
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: None",
        ],
        [
            (
                "state stamp 111; title,start,end,all_day,notes,reminders@100p location@110p; "
                "sibling stamp 115; to pass None; highest 115"
            ),
            "laptop: known, delivered: all",
            "tablet: known, delivered: all_day,end,notes,reminders,start,title",
        ],
    ],
    "a new device gets the schemas offered and then every record whole": [
        [
            "OFFER 00000001 to laptop: axt.example.v1.Appointment version 1",
        ],
        [
            "outcome: None",
            "CHANGE to laptop, version 101, state 101, whole: all seven@100p",
        ],
        [
            "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101",
            "laptop: not known",
            "tablet: known, delivered: all",
        ],
    ],
    "a deletion travels as the removal alone, and a deleted record goes whole to a sibling that lacks it": [
        [
            "made: True",
            "CHANGE to laptop, version 111, state 111, whole: all seven@100p removal@110p",
            "CHANGE to tablet, version 111, state 111, in part: no field removal@110p",
        ],
        [
            "state stamp 111; all seven@100p removal@110p; sibling stamp None; to pass None; highest 111",
            "laptop: not known",
            "tablet: known, delivered: all",
        ],
    ],
    "a device that discarded the field states of a deleted record sends what it holds, as a whole CHANGE": [
        [
            "outcome: None",
            "CHANGE to tablet, version 152, state 152, whole: no field removal@150p",
        ],
    ],
    "a record held incompletely travels with whole false, and not again after RECORD_UNKNOWN": [
        [
            "outcome: None",
            "CHANGE to tablet, version 166, state 166, in part: location@160t removal@150p",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            "outcome: None",
        ],
        [
            "outcome: None",
        ],
        [
            "ACK of 0000000b to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            (
                "state stamp 166; location@160t removal@150p; sibling stamp None; to pass None; "
                "highest 166; incomplete"
            ),
            "tablet: not known",
        ],
        [
            "outcome: APPLIED",
            "CHANGE to tablet, version 173, state 173, in part: location@160t removal@150p",
        ],
        [
            (
                "state stamp 173; all_day,end,notes,reminders,start@100p location@160t title@170t "
                "removal@150p; sibling stamp 171; to pass None; highest 173"
            ),
            "tablet: known, delivered: all_day,end,notes,reminders,start,title",
        ],
    ],
    "a different CHANGE of a record to one sibling takes a new state stamp; nothing becomes due by it": [
        [
            "made: True",
            "CHANGE to laptop, version 111, state 111, in part: location@110p",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: None",
            (
                "CHANGE to tablet, version 113, state 113, whole: "
                "title,start,end,all_day,notes,reminders@100p location@110p"
            ),
        ],
        [
            (
                "state stamp 113; title,start,end,all_day,notes,reminders@100p location@110p; "
                "sibling stamp None; to pass None; highest 113"
            ),
            "laptop: known, delivered: all_day,end,notes,reminders,start,title",
            "tablet: not known",
        ],
    ],
    "a new state stamp that another sibling caused sends the parts of a settled CHANGE again": [
        [
            "made: True",
            "CHANGE to laptop, version 111, state 111, in part: location@110p",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: None",
        ],
        [
            "outcome: None",
            (
                "CHANGE to tablet, version 113, state 113, whole: "
                "title,start,end,all_day,notes,reminders@100p location@110p"
            ),
            "CHANGE to laptop, version 113, state 113, in part: location@110p",
        ],
        [
            (
                "state stamp 113; title,start,end,all_day,notes,reminders@100p location@110p; "
                "sibling stamp None; to pass None; highest 113"
            ),
            "laptop: known, delivered: all_day,end,notes,reminders,start,title",
            "tablet: not known",
        ],
    ],
    "a device sends no CHANGE of a record for which it holds no state stamp": [
        [
            "OFFER 00000001 to tablet: axt.example.v1.Appointment version 1",
        ],
        [
            "outcome: None",
            "CHANGE of 7b1e6c2a to tablet, version 101, state 101, whole: all seven@100p",
        ],
    ],
    "a CHANGE without an outcome goes again in the next connection, once its schema is accepted there": [
        [
            "made: True",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "OFFER 00000001 to tablet: axt.example.v1.Appointment version 1",
        ],
        [
            "outcome: None",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            (
                "state stamp 111; title,start,end,all_day,notes,reminders@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,reminders,start,title",
        ],
    ],
    "a CHANGE with an outcome does not go again in the next connection": [
        [
            "made: True",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: None",
        ],
        [],
    ],
    "a resend after a CHANGE of the sibling delivered a part carries the rest, under a new state stamp": [
        [
            "made: True",
            "CHANGE to tablet, version 111, state 111, in part: location,notes@110p",
        ],
        [
            "outcome: DUPLICATE",
        ],
        [
            "OFFER 00000001 to tablet: axt.example.v1.Appointment version 1",
        ],
        [
            "outcome: None",
            "CHANGE to tablet, version 121, state 121, in part: notes@110p",
        ],
        [
            (
                "state stamp 121; all_day,end,reminders,start,title@100p location,notes@110p; "
                "sibling stamp 120; to pass None; highest 121"
            ),
            "tablet: known, delivered: all_day,end,location,reminders,start,title",
        ],
    ],
    "a CHANGE of the sibling delivers the parts of a CHANGE on its way, which then does not go again": [
        [
            "made: True",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: DUPLICATE",
        ],
        [],
        [
            (
                "state stamp 111; all_day,end,notes,reminders,start,title@100p location@110p; "
                "sibling stamp 120; to pass None; highest 120"
            ),
            "tablet: known, delivered: all",
        ],
    ],
    "a removal that is delivered does not travel with a field state that is due": [
        [
            "made: True",
            "CHANGE to tablet, version 173, state 173, in part: location@172p",
        ],
    ],
    "a device that can take no stamp makes no change and sends nothing": [
        [
            "made: False",
        ],
        [
            (
                "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest "
                "9223372036854775807"
            ),
            "tablet: known, delivered: all",
        ],
    ],
    "a CHANGE above 16 MiB is not sent": [
        [
            "made: True",
        ],
    ],
    "a device that can take no stamp does not send a different CHANGE under its state stamp": [
        [
            "outcome: DUPLICATE",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: None",
        ],
        [
            (
                "state stamp 111; all_day,end,notes,reminders,start,title@100p location@110p; "
                "sibling stamp 105; to pass None; highest 9223372036854775807"
            ),
            "tablet: not known",
        ],
    ],
    "a record that its user creates travels whole, its deletion and the taking back as the removal alone": [
        [
            "made: True",
            "CHANGE of 7b1e6c2a to tablet, version 101, state 101, whole: all seven@100p",
        ],
        [
            "outcome: None",
        ],
        [
            "made: True",
            "CHANGE of 7b1e6c2a to tablet, version 107, state 107, in part: no field removal@106p",
        ],
        [
            "outcome: None",
        ],
        [
            "made: True",
            (
                "CHANGE of 7b1e6c2a to tablet, version 112, state 112, in part: no field "
                "removal@111p, taken back"
            ),
        ],
        [
            (
                "state stamp 112; all seven@100p removal@111p, taken back; sibling stamp 110; to "
                "pass None; highest 112"
            ),
            "tablet: known, delivered: all",
        ],
    ],
    "after a RESYNC the device sends every record whole under a new state stamp, then acknowledges it": [
        [
            "outcome: None",
            "CHANGE to tablet, version 152, state 152, whole: all seven@100p",
            (
                "CHANGE of 7b1e6c2a to tablet, version 153, state 153, whole: "
                "title,start,end,all_day,notes,reminders@100p location@110t removal@150p"
            ),
        ],
        [
            "state stamp 152; all seven@100p; sibling stamp None; to pass None; highest 153",
            "tablet: not known",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            "outcome: None",
        ],
        [
            "ACK of 0000000a to tablet: version 1 DUPLICATE, receiver 1",
        ],
        [
            (
                "state stamp 153; title,start,end,all_day,notes,reminders@100p location@110t "
                "removal@150p; sibling stamp None; to pass None; highest 153"
            ),
            "tablet: not known",
        ],
    ],
    "a repeat of a RESYNC before its acknowledgement is sent changes nothing": [
        [
            "outcome: None",
            "CHANGE to tablet, version 102, state 102, whole: all seven@100p",
        ],
        [
            "outcome: None",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
    ],
    "a RESYNC with another id is another request, and is acted on": [
        [
            "outcome: None",
            "CHANGE to tablet, version 102, state 102, whole: all seven@100p",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            "outcome: None",
            "CHANGE to tablet, version 103, state 103, whole: all seven@100p",
        ],
        [
            "ACK of 0000000b to tablet: version 1 APPLIED, receiver 1",
        ],
    ],
    "a device that holds no record sends only the acknowledgement of a RESYNC": [
        [
            "outcome: None",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
    ],
    "the acknowledgement of a RESYNC follows the last CHANGE of the answer": [
        [
            "outcome: None",
            "OFFER 00000001 to tablet: axt.example.v1.Appointment version 1",
        ],
        [],
        [
            "outcome: None",
            "CHANGE to tablet, version 102, state 102, whole: all seven@100p",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
    ],
    "an answer whose connection ends first goes on in the next one, and is acknowledged there": [
        [
            "outcome: None",
            "OFFER 00000001 to tablet: axt.example.v1.Appointment version 1",
        ],
        [
            "OFFER 00000002 to tablet: axt.example.v1.Appointment version 1",
        ],
        [],
        [
            "outcome: None",
            "CHANGE to tablet, version 102, state 102, whole: all seven@100p",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
    ],
    "a second RESYNC with another id starts the answer anew, and both are acknowledged at its end": [
        [
            "outcome: None",
            "CHANGE to tablet, version 128, state 128, whole: all seven@100p",
            "OFFER 00000001 to tablet: axt.example.v1.Appointment version 2",
        ],
        [],
        [
            "outcome: None",
            "CHANGE to tablet, version 129, state 129, whole: all seven@100p",
        ],
        [
            "outcome: None",
            "CHANGE of 7b1e6c2a to tablet, version 130, state 130, whole: all seven@100p room@125t",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
            "ACK of 0000000b to tablet: version 1 APPLIED, receiver 1",
        ],
    ],
    "a record that the device cannot send is no part of the answer to a RESYNC": [
        [
            "outcome: None",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
    ],
    "an outcome and an error for a CHANGE sent before a RESYNC are ignored": [
        [
            "made: True",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: None",
            (
                "CHANGE to tablet, version 113, state 113, whole: "
                "title,start,end,all_day,notes,reminders@100p location@110p"
            ),
        ],
        [
            "outcome: None",
        ],
        [
            "outcome: None",
        ],
        [
            (
                "state stamp 113; title,start,end,all_day,notes,reminders@100p location@110p; "
                "sibling stamp None; to pass None; highest 113"
            ),
            "tablet: not known",
        ],
    ],
    "a RESYNC with an id that is no UUID is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: RECORD_ID_INVALID",
        ],
        [],
        [
            "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "a RESYNC with the nil UUID as its id is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: RECORD_ID_INVALID",
        ],
        [],
        [
            "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "a RESYNC with the version 0 is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: VERSION_INVALID",
        ],
        [],
        [
            "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "a RESYNC with the version 2 is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "a RESYNC with an id that is no UUID and the version 2: step 4 comes first is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: RECORD_ID_INVALID",
        ],
        [],
        [
            "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "a RESYNC with a body that is no axt.Resync is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "a restored device asks every sibling, and sends none a CHANGE before that sibling acknowledges": [
        [
            "made: True",
            "CHANGE to laptop, version 111, state 111, in part: location@110p",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "RESYNC 00000001 to laptop",
            "RESYNC 00000002 to tablet",
        ],
        [
            (
                "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101; "
                "a request open to laptop, tablet"
            ),
            "laptop: not known",
            "tablet: not known",
        ],
        [
            "made: True",
        ],
        [
            "RESYNC 00000002 to tablet",
        ],
        [
            "outcome: APPLIED",
        ],
        [
            "ACK to tablet: version 115 APPLIED, receiver 116",
        ],
        [
            "outcome: None",
            "OFFER 00000001 to tablet: axt.example.v1.Appointment version 1",
        ],
        [
            "outcome: None",
            "CHANGE to tablet, version 117, state 117, in part: notes@102p",
        ],
        [
            (
                "state stamp 117; all_day,end,reminders,start,title@100p notes@102p "
                "location@110p; sibling stamp 115; to pass None; highest 117; a request open to "
                "laptop"
            ),
            "laptop: not known",
            "tablet: known, delivered: all_day,end,location,reminders,start,title",
        ],
        [
            "outcome: None",
            "RESYNC 00000001 to laptop",
        ],
        [
            "outcome: None",
        ],
        [
            "outcome: None",
            "OFFER 00000002 to laptop: axt.example.v1.Appointment version 1",
        ],
        [
            (
                "state stamp 117; all_day,end,reminders,start,title@100p notes@102p "
                "location@110p; sibling stamp 115; to pass None; highest 117"
            ),
            "laptop: not known",
            "tablet: known, delivered: all_day,end,location,reminders,start,title",
        ],
    ],
    "a restored device with a sibling gives its field states never stamped the stamp -1": [
        [
            "RESYNC 00000001 to tablet",
        ],
        [
            (
                "state stamp 4; all seven@-1p; sibling stamp None; to pass None; highest 4; held "
                "back from other apps; a request open to tablet"
            ),
            "tablet: not known",
        ],
        [
            "outcome: None",
            "OFFER 00000001 to tablet: axt.example.v1.Appointment version 1",
        ],
        [
            "state stamp 4; all seven@-1p; sibling stamp None; to pass None; highest 4",
            "tablet: not known",
        ],
        [
            "outcome: None",
            "CHANGE to tablet, version 5, state 5, whole: all seven@-1p",
        ],
    ],
    "a record with a field state of unknown age is held back from other apps for at most 14 days": [
        [
            "RESYNC 00000001 to tablet",
        ],
        [],
        [
            (
                "state stamp 4; all seven@-1p; sibling stamp None; to pass None; highest 4; held "
                "back from other apps; a request open to tablet"
            ),
            "tablet: not known",
        ],
        [],
        [
            (
                "state stamp 4; all seven@-1p; sibling stamp None; to pass None; highest 4; a "
                "request open to tablet"
            ),
            "tablet: not known",
        ],
    ],
    "the hold on a record with a field state of unknown age ends with the first acknowledgement": [
        [
            "RESYNC 00000001 to laptop",
            "RESYNC 00000002 to tablet",
        ],
        [
            "outcome: None",
            "OFFER 00000001 to tablet: axt.example.v1.Appointment version 1",
        ],
        [
            (
                "state stamp 4; all seven@-1p; sibling stamp None; to pass None; highest 4; a "
                "request open to laptop"
            ),
            "laptop: not known",
            "tablet: not known",
        ],
        [
            "outcome: None",
            "OFFER 00000002 to laptop: axt.example.v1.Appointment version 1",
        ],
        [
            "state stamp 4; all seven@-1p; sibling stamp None; to pass None; highest 4",
            "laptop: not known",
            "tablet: not known",
        ],
    ],
    "a restored device keeps the requests of its backup that it acted on, and opens its own anew": [
        [
            "outcome: None",
            "CHANGE to tablet, version 102, state 102, whole: all seven@100p",
        ],
        [
            "outcome: None",
            "CHANGE to tablet, version 103, state 103, whole: all seven@100p",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
            "ACK of 0000000b to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            "RESYNC 00000001 to tablet",
        ],
        [
            "outcome: None",
        ],
        [
            "ACK of 0000000a to tablet: version 1 DUPLICATE, receiver 1",
        ],
        [
            "outcome: None",
            "OFFER 00000001 to tablet: axt.example.v1.Appointment version 1",
        ],
        [
            "RESYNC 00000002 to tablet",
        ],
        [
            "outcome: None",
        ],
        [
            (
                "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101; "
                "a request open to tablet"
            ),
            "tablet: not known",
        ],
        [
            "outcome: None",
            "OFFER 00000002 to tablet: axt.example.v1.Appointment version 1",
        ],
        [
            "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101",
            "tablet: not known",
        ],
    ],
    "a restored device that learns of a sibling its backup did not hold acts as after a restore": [
        [],
        [
            "made: True",
        ],
        [
            "RESYNC 00000001 to tablet",
        ],
        [
            (
                "state stamp 6; title,start,end,all_day,location,reminders@-1p notes@5p; sibling "
                "stamp None; to pass None; highest 6; held back from other apps; a request open "
                "to tablet"
            ),
            "tablet: not known",
        ],
        [
            "outcome: APPLIED",
        ],
        [
            "ACK to tablet: version 9 APPLIED, receiver 10",
        ],
        [
            (
                "state stamp 10; all_day,end,location,reminders,start,title@0p notes@5p; sibling "
                "stamp 9; to pass None; highest 10; a request open to tablet"
            ),
            "tablet: known, delivered: all_day,end,location,reminders,start,title",
        ],
    ],
    "a device that restores as the only device of its set leaves its field states never stamped": [
        [],
        [
            "state stamp 4; all seven@0p; sibling stamp None; to pass None; highest 4",
        ],
    ],
    "an open request goes again through the relay each time the holding time has passed, not before": [
        [
            "RESYNC 00000001 to tablet",
        ],
        [],
        [
            "RESYNC 00000001 to tablet",
        ],
        [
            "RESYNC 00000001 to tablet",
        ],
        [
            (
                "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101; "
                "a request open to tablet"
            ),
            "tablet: not known",
        ],
    ],
    "two devices with requests open toward each other each send their answer": [
        [
            "RESYNC 00000001 to tablet",
        ],
        [
            "outcome: None",
            "OFFER 00000001 to tablet: axt.example.v1.Appointment version 1",
        ],
        [
            "outcome: None",
            "CHANGE to tablet, version 102, state 102, whole: all seven@100p",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            (
                "state stamp 102; all seven@100p; sibling stamp None; to pass None; highest 102; "
                "a request open to tablet"
            ),
            "tablet: not known",
        ],
    ],
    "a request ends when its sibling is removed": [
        [
            "RESYNC 00000001 to laptop",
            "RESYNC 00000002 to tablet",
        ],
        [],
        [
            (
                "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101; "
                "a request open to laptop"
            ),
            "laptop: not known",
        ],
    ],
    "an entry with the outcome STALE does not acknowledge a request": [
        [
            "RESYNC 00000001 to tablet",
        ],
        [
            "outcome: None",
        ],
        [
            (
                "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101; "
                "a request open to tablet"
            ),
            "tablet: not known",
        ],
    ],
    "an outcome is taken for a CHANGE last sent 14 days ago, and ignored for one sent 16 days ago": [
        [
            "made: True",
            "CHANGE to laptop, version 111, state 111, in part: location@110p",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [],
        [
            "outcome: None",
        ],
        [],
        [
            "outcome: None",
        ],
        [
            "outcome: None",
        ],
        [
            (
                "state stamp 111; title,start,end,all_day,notes,reminders@100p location@110p; "
                "sibling stamp 115; to pass None; highest 115"
            ),
            "laptop: known, delivered: all_day,end,notes,reminders,start,title",
            "tablet: known, delivered: all",
        ],
    ],
    "through the relay a CHANGE without an outcome goes again once the holding time has passed": [
        [
            "made: True",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [],
        [
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: None",
        ],
        [],
        [
            (
                "state stamp 111; title,start,end,all_day,notes,reminders@100p location@110p; "
                "sibling stamp 115; to pass None; highest 115"
            ),
            "tablet: known, delivered: all",
        ],
    ],
    "an outcome delivers a part only if the state still holds it exactly, value and schema included": [
        [
            "outcome: DUPLICATE",
            "CHANGE to laptop, version 101, state 101, in part: location@-1t",
        ],
        [
            "outcome: APPLIED",
            "CHANGE to laptop, version 107, state 107, in part: location@-1t",
        ],
        [
            "outcome: None",
        ],
        [
            (
                "state stamp 107; location@-1t all_day,end,notes,reminders,start,title@100p; "
                "sibling stamp 110; to pass None; highest 110"
            ),
            "laptop: known, delivered: all_day,end,notes,reminders,start,title",
            "tablet: known, delivered: all",
        ],
    ],
    "an outcome delivers the parts of its CHANGE that the state still holds, and no later ones": [
        [
            "made: True",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "made: True",
            "CHANGE to tablet, version 113, state 113, in part: location,notes@112p",
        ],
        [
            "outcome: None",
        ],
        [
            (
                "state stamp 113; title,start,end,all_day,reminders@100p location,notes@112p; "
                "sibling stamp 115; to pass None; highest 115"
            ),
            "tablet: known, delivered: all_day,end,reminders,start,title",
        ],
        [
            "outcome: None",
        ],
        [
            (
                "state stamp 113; title,start,end,all_day,reminders@100p location,notes@112p; "
                "sibling stamp 116; to pass None; highest 116"
            ),
            "tablet: known, delivered: all",
        ],
    ],
    "a device takes a sibling's own MANIFEST whatever its revision, and passes it on to the others": [
        [
            "outcome: None",
            "MANIFEST of the laptop, revision 3, passed on to tablet",
        ],
        [
            "outcome: None",
        ],
        [
            "outcome: None",
            "MANIFEST of the laptop, revision 2, passed on to tablet",
        ],
        [
            "outcome: None",
            "MANIFEST of the tablet, revision 1, passed on to laptop",
        ],
    ],
    "a passed-on MANIFEST replaces the kept one only with a higher revision, and does not go back": [
        [
            "outcome: None",
        ],
        [
            "outcome: None",
        ],
        [
            "outcome: None",
        ],
        [
            "outcome: None",
        ],
        [
            "outcome: None",
            "MANIFEST of the laptop, revision 2, passed on to tablet",
        ],
    ],
    "a MANIFEST whose body does not decode as a manifest is ignored, and not passed on": [
        [
            "outcome: None",
        ],
        [
            "outcome: None",
        ],
    ],
    "a passed-on MANIFEST that is not valid is ignored": [
        [
            "outcome: None",
        ],
        [
            "outcome: None",
            "MANIFEST of the laptop, revision 5, passed on to tablet",
        ],
    ],
    "through the relay every MANIFEST of a sibling goes by the higher revision": [
        [
            "outcome: None",
            "MANIFEST of the laptop, revision 3, passed on to tablet",
        ],
        [
            "outcome: None",
        ],
        [
            "outcome: None",
            "MANIFEST of the laptop, revision 4, passed on to tablet",
        ],
    ],
    "a MANIFEST of a key that is no other current device of the set is ignored": [
        [
            "outcome: None",
        ],
        [
            "outcome: None",
        ],
        [
            "outcome: None",
        ],
        [
            "outcome: None",
        ],
    ],
    "a new device gets the kept manifests of the other devices, and not its own": [
        [
            "OFFER 00000001 to laptop: axt.example.v1.Appointment version 1",
            "MANIFEST of the tablet, revision 5, passed on to laptop",
        ],
        [
            "outcome: None",
            "MANIFEST of the laptop, revision 1, passed on to tablet",
        ],
        [
            "OFFER 00000002 to laptop: axt.example.v1.Appointment version 1",
        ],
    ],
    "a manifest that a sibling has got from the device is not passed on to it again": [
        [],
    ],
    "an offer of a sibling with the nil UUID as its id is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: OFFER_INVALID",
        ],
    ],
    "an offer of a sibling with no type is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: OFFER_INVALID",
        ],
    ],
    "an offer of a sibling with 257 types is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: OFFER_INVALID",
        ],
    ],
    "an offer of a sibling with a schema that is no JSON text is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: OFFER_INVALID",
        ],
    ],
    "an offer of a sibling with a count of -1 is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: OFFER_INVALID",
        ],
    ],
    "an offer of a sibling with a schema above 256 KiB is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: TOO_LARGE",
        ],
    ],
    "an offer of a sibling with 256 types is valid": [
        [
            "outcome: None",
            (
                "ACCEPT 00000006 to tablet: com.example.T0, com.example.T1, com.example.T10, "
                "com.example.T100, com.example.T101, com.example.T102, com.example.T103, "
                "com.example.T104, com.example.T105, com.example.T106, com.example.T107, "
                "com.example.T108, com.example.T109, com.example.T11, com.example.T110, "
                "com.example.T111, com.example.T112, com.example.T113, com.example.T114, "
                "com.example.T115, com.example.T116, com.example.T117, com.example.T118, "
                "com.example.T119, com.example.T12, com.example.T120, com.example.T121, "
                "com.example.T122, com.example.T123, com.example.T124, com.example.T125, "
                "com.example.T126, com.example.T127, com.example.T128, com.example.T129, "
                "com.example.T13, com.example.T130, com.example.T131, com.example.T132, "
                "com.example.T133, com.example.T134, com.example.T135, com.example.T136, "
                "com.example.T137, com.example.T138, com.example.T139, com.example.T14, "
                "com.example.T140, com.example.T141, com.example.T142, com.example.T143, "
                "com.example.T144, com.example.T145, com.example.T146, com.example.T147, "
                "com.example.T148, com.example.T149, com.example.T15, com.example.T150, "
                "com.example.T151, com.example.T152, com.example.T153, com.example.T154, "
                "com.example.T155, com.example.T156, com.example.T157, com.example.T158, "
                "com.example.T159, com.example.T16, com.example.T160, com.example.T161, "
                "com.example.T162, com.example.T163, com.example.T164, com.example.T165, "
                "com.example.T166, com.example.T167, com.example.T168, com.example.T169, "
                "com.example.T17, com.example.T170, com.example.T171, com.example.T172, "
                "com.example.T173, com.example.T174, com.example.T175, com.example.T176, "
                "com.example.T177, com.example.T178, com.example.T179, com.example.T18, "
                "com.example.T180, com.example.T181, com.example.T182, com.example.T183, "
                "com.example.T184, com.example.T185, com.example.T186, com.example.T187, "
                "com.example.T188, com.example.T189, com.example.T19, com.example.T190, "
                "com.example.T191, com.example.T192, com.example.T193, com.example.T194, "
                "com.example.T195, com.example.T196, com.example.T197, com.example.T198, "
                "com.example.T199, com.example.T2, com.example.T20, com.example.T200, "
                "com.example.T201, com.example.T202, com.example.T203, com.example.T204, "
                "com.example.T205, com.example.T206, com.example.T207, com.example.T208, "
                "com.example.T209, com.example.T21, com.example.T210, com.example.T211, "
                "com.example.T212, com.example.T213, com.example.T214, com.example.T215, "
                "com.example.T216, com.example.T217, com.example.T218, com.example.T219, "
                "com.example.T22, com.example.T220, com.example.T221, com.example.T222, "
                "com.example.T223, com.example.T224, com.example.T225, com.example.T226, "
                "com.example.T227, com.example.T228, com.example.T229, com.example.T23, "
                "com.example.T230, com.example.T231, com.example.T232, com.example.T233, "
                "com.example.T234, com.example.T235, com.example.T236, com.example.T237, "
                "com.example.T238, com.example.T239, com.example.T24, com.example.T240, "
                "com.example.T241, com.example.T242, com.example.T243, com.example.T244, "
                "com.example.T245, com.example.T246, com.example.T247, com.example.T248, "
                "com.example.T249, com.example.T25, com.example.T250, com.example.T251, "
                "com.example.T252, com.example.T253, com.example.T254, com.example.T255, "
                "com.example.T26, com.example.T27, com.example.T28, com.example.T29, "
                "com.example.T3, com.example.T30, com.example.T31, com.example.T32, "
                "com.example.T33, com.example.T34, com.example.T35, com.example.T36, "
                "com.example.T37, com.example.T38, com.example.T39, com.example.T4, "
                "com.example.T40, com.example.T41, com.example.T42, com.example.T43, "
                "com.example.T44, com.example.T45, com.example.T46, com.example.T47, "
                "com.example.T48, com.example.T49, com.example.T5, com.example.T50, "
                "com.example.T51, com.example.T52, com.example.T53, com.example.T54, "
                "com.example.T55, com.example.T56, com.example.T57, com.example.T58, "
                "com.example.T59, com.example.T6, com.example.T60, com.example.T61, "
                "com.example.T62, com.example.T63, com.example.T64, com.example.T65, "
                "com.example.T66, com.example.T67, com.example.T68, com.example.T69, "
                "com.example.T7, com.example.T70, com.example.T71, com.example.T72, "
                "com.example.T73, com.example.T74, com.example.T75, com.example.T76, "
                "com.example.T77, com.example.T78, com.example.T79, com.example.T8, "
                "com.example.T80, com.example.T81, com.example.T82, com.example.T83, "
                "com.example.T84, com.example.T85, com.example.T86, com.example.T87, "
                "com.example.T88, com.example.T89, com.example.T9, com.example.T90, "
                "com.example.T91, com.example.T92, com.example.T93, com.example.T94, "
                "com.example.T95, com.example.T96, com.example.T97, com.example.T98, "
                "com.example.T99"
            ),
        ],
    ],
    "a device discards what it kept for a removed sibling, sends it nothing and rejects its messages": [
        [
            "made: True",
            "CHANGE to laptop, version 111, state 111, in part: location@110p",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: APPLIED",
            "CHANGE to laptop, version 122, state 122, in part: location@110p notes@120t",
        ],
        [],
        [],
        [
            "outcome: None",
        ],
        [
            "outcome: None",
        ],
        [
            "outcome: None",
        ],
        [
            "made: True",
            "CHANGE to laptop, version 124, state 124, in part: location@110p notes@120t title@123p",
        ],
        [
            (
                "state stamp 124; all_day,end,reminders,start@100p location@110p notes@120t "
                "title@123p; sibling stamp 121; to pass None; highest 124"
            ),
            "laptop: known, delivered: all_day,end,reminders,start",
        ],
    ],
    "a DATA or a DELETE of a sibling is rejected with NOT_ACCEPTED, if the steps before it pass": [
        [
            "outcome: None",
            "ACCEPT 00000006 to tablet: axt.example.v1.Appointment",
        ],
        [
            "outcome: None",
            "ERROR to tablet: NOT_ACCEPTED",
        ],
        [
            "outcome: None",
            "ERROR to tablet: NOT_ACCEPTED",
        ],
        [
            "outcome: None",
            "ERROR to tablet: SCHEMA_UNKNOWN, fingerprint 71105335022c796b",
        ],
        [
            "outcome: None",
            "ERROR to tablet: RECORD_ID_INVALID",
        ],
        [
            "outcome: None",
            "ERROR to tablet: VERSION_INVALID",
        ],
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "state stamp 101; all seven@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "a device takes a DATA of a file of its own set with field states of unknown age, which travel": [
        [
            "taken: True",
            "CHANGE to laptop, version 8, state 8, whole: all seven@-1t",
            "CHANGE to tablet, version 8, state 8, whole: all seven@-1t",
        ],
        [
            "state stamp 8; all seven@-1t; sibling stamp 7; to pass None; highest 8",
            "laptop: not known",
            "tablet: not known",
        ],
        [
            "taken: False",
        ],
        [
            "taken: False",
        ],
        [
            "state stamp 8; all seven@-1t; sibling stamp 7; to pass None; highest 8",
            "laptop: not known",
            "tablet: not known",
        ],
    ],
    "a record with field states of unknown age is part of the answer to a RESYNC, like any record": [
        [
            "taken: True",
            "CHANGE to tablet, version 8, state 8, whole: all seven@-1p",
        ],
        [
            "outcome: None",
            "CHANGE to tablet, version 9, state 9, whole: all seven@-1p",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
    ],
    "field states of unknown age from a file lose to a sibling's, never stamped or stamped": [
        [
            "taken: True",
            "CHANGE to laptop, version 8, state 8, whole: all seven@-1t",
            "CHANGE to tablet, version 8, state 8, whole: all seven@-1t",
        ],
        [
            "outcome: APPLIED",
            (
                "CHANGE to laptop, version 106, state 106, whole: "
                "all_day,end,location,notes,reminders,start@0p title@100t"
            ),
        ],
        [
            "ACK to tablet: version 105 APPLIED, receiver 106",
        ],
        [
            (
                "state stamp 106; all_day,end,location,notes,reminders,start@0p title@100t; "
                "sibling stamp 105; to pass None; highest 106"
            ),
            "laptop: not known",
            "tablet: known, delivered: all",
        ],
    ],
    "of two field states of unknown age the higher device key stands, then the higher value": [
        [
            "taken: True",
            "CHANGE to laptop, version 8, state 8, whole: all seven@-1t",
            "CHANGE to tablet, version 8, state 8, whole: all seven@-1t",
        ],
        [
            "outcome: STALE",
            "CHANGE to laptop, version 8, state 8, whole: all seven@-1t",
        ],
        [
            "outcome: APPLIED",
            "CHANGE to tablet, version 9, state 9, whole: all seven@-1t",
        ],
        [
            "ACK to laptop: version 4 APPLIED, receiver 9",
            "ACK to laptop: version 3 STALE, receiver 8",
        ],
        [
            "state stamp 9; all seven@-1t; sibling stamp 7; to pass None; highest 9",
            "laptop: known, delivered: title",
            "tablet: not known",
        ],
    ],
    "a device takes from a file of its own set no DELETE, and no DATA that fails as a record message": [
        [
            "taken: False",
        ],
        [
            "taken: False",
        ],
        [
            "taken: False",
        ],
        [
            "taken: False",
        ],
        [
            "taken: False",
        ],
        [
            "taken: False",
        ],
        [
            "taken: False",
        ],
        [
            "no record; highest 0",
        ],
    ],
}


def check_sessions(out: list[str]) -> None:
    """Every session says what the rules require of it, step by step."""
    played = sessions()
    assert len({s.label for s in played}) == len(played) == len(SAID), "one expectation for each session"
    for s in played:
        assert s.said == SAID[s.label], (s.label, s.said)
    PLAYED[:] = played
    out.append(
        f"Sessions of a device with its siblings: {len(played)}, of {sum(len(s.steps) for s in played)} steps"
    )


def check() -> list[str]:
    """Run every check; the lines to print. Fills EXAMPLE_MERGES and EXAMPLE_CHANGES."""
    out: list[str] = []
    EXAMPLE_MERGES.clear()
    EXAMPLE_CHANGES.clear()
    check_stamps(out)
    check_different_fields(out)
    check_same_field(out)
    check_deletion(out)
    check_counted(out)
    check_cases(out)
    check_properties(out)
    EXAMPLE_MESSAGES.clear()
    check_field_values()
    check_schemas(out)
    check_messages(out)
    check_envelopes()
    check_sessions(out)
    return out


def main() -> None:
    print("The examples of spec/sync.md: section 6 recomputed with the rules of sections 2 to 5, the")
    print("schemas and messages of sections 15 and 16, and the sessions of a device with its siblings.")
    print(f"Device keys (test keys): phone {PHONE.hex()[:16]}..., tablet {TABLET.hex()[:16]}...")
    for line in check():
        print(line)
    print("All checks passed.")


if __name__ == "__main__":
    main()
