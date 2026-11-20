# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Produce and check the examples of spec/sync.md.

spec/sync.md defines no message and no schema, so its examples are numbers: stamps,
states of a record and what a merge makes of them. This script:

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
  field states and removals is commutative, associative and idempotent (section 4.5).

The device keys are TEST KEYS, derived as spec/keys.md, section 7.1, says, from the
labels "cat-a-log, phone, Ed25519" and "cat-a-log, tablet, Ed25519". The keys of the
cases about the order of keys are byte strings chosen for the comparison, not keys.

Run from anywhere, with what conformance/tools/keys_examples.py needs installed:

    python3 conformance/tools/sync_examples.py

conformance/tools/generate_vectors.py and conformance/reference/adapter.py import this
file; importing it runs none of its checks.
"""

import datetime
import hashlib
import importlib.util
import io
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import avro.io
import avro.schema
import fastavro
from fastavro.schema import fingerprint as fa_fingerprint
from fastavro.schema import to_parsing_canonical_form

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]

_spec = importlib.util.spec_from_file_location("keys_examples", HERE / "keys_examples.py")
if _spec is None or _spec.loader is None:
    raise ImportError("keys_examples.py cannot be loaded")
keys = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(keys)  # runs none of that script's checks

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
    return out


def main() -> None:
    print("The examples of spec/sync.md, section 6, recomputed with the rules of sections 2 to 5.")
    print(f"Device keys (test keys): phone {PHONE.hex()[:16]}..., tablet {TABLET.hex()[:16]}...")
    for line in check():
        print(line)
    print("All checks passed.")


if __name__ == "__main__":
    main()
