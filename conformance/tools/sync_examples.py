# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Produce and check the examples of spec/sync.md.

The examples of sections 2 to 6 of spec/sync.md are numbers: stamps, states of a record
and what a merge makes of them. Those of sections 15 and 16 are the schemas and the bytes
of the CHANGE, RESYNC and FORWARD messages between the devices of a set. This script:

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
- checks the Parsing Canonical Forms and the fingerprints of types/axt/Change.avsc,
  Resync.avsc and Forward.avsc with fastavro and the Apache avro package (section 15), and builds the
  messages of section 16 field by field: each is compared with fastavro's encoding, read
  back with the avro package, and signed and verified with the pure-Python Ed25519 of
  keys_examples.py, PyNaCl and cryptography, which give the same signature;
- holds a model of one device of a set with its siblings (sections 7 to 13): the steps
  in which it processes a CHANGE, the outcome, what it keeps for each sibling, what it
  sends to which sibling, whole or in part and under which state stamp, offers,
  acknowledgements, errors, RESYNC, a restored, a removed and a new device, and a file of
  its own set; it plays the examples of section 16 and the sessions of `sessions` through
  the model and checks every step against what `SAID` writes out for it. The generator
  turns the sessions into the vectors of the operation `siblings`;
- extends that model to what a set got from other apps (sections 17 to 24): the 16 steps in
  which a device checks a FORWARD, a forwarded MANIFEST, DATA, DELETE, WITHDRAW
  (spec/shares.md, section 7.1), DEVICE_ADD and DEVICE_REMOVE by what its sender is to the
  device, the kept messages with what is delivered and due for each sibling, the owner's
  layer of a received record with its CHANGE messages that name the sender in `origin`, what
  a device shows from the two layers, and the answering device, which takes a message from
  the other app itself. It builds the messages of sections 16.5 to 16.7 in the same way. It also
  keeps the PROPOSAL messages of other apps (spec/shares.md, section 17.1): taken by the answering
  device and in a FORWARD, forwarded, shown by the app's shares, dropped, and answered with a
  PROPOSAL_REPLY and, for ACCEPTED, a change of the record. Not
  modelled, because the text of these parts is about to change: ending and completing an
  owner's layer and the later ACK (sections 22.2 and 22.3), a forwarded record message of a
  key removed since (section 19.2), and two senders that join (section 23.4).

The device keys are TEST KEYS, derived as spec/keys.md, section 7.1, says, from the
labels "cat-a-log, phone, Ed25519" and "cat-a-log, tablet, Ed25519", and for the sessions
from further labels in the same way; the other app of sections 16.5 to 16.7 has the test
key "Old Brain Fix, Ed25519" of spec/protocol.md. The keys of the cases about the order of keys are
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
# The descriptions of the offered types (spec/fields.md, section 10): an OFFER carries descriptions, and the
# device keeps the text of the schema derived from each, with the description it got or made for it.
_spec = importlib.util.spec_from_file_location("fields_examples", HERE / "fields_examples.py")
if _spec is None or _spec.loader is None:
    raise ImportError("fields_examples.py cannot be loaded")
fe = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fe)

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
# Each is the text of the schema derived from its description (spec/fields.md, section 9.3).
APPOINTMENT_FILE = (REPO / "types" / "axt" / "example" / "v1" / "Appointment.1.avsc").read_text(
    encoding="utf-8"
)
APPOINTMENT_1 = fe.source(APPOINTMENT_FILE)
_later = json.loads(APPOINTMENT_FILE)
_later["axt.version"] = 2
_later["fields"].append({"name": "room", "type": "string", "default": "", "doc": "The room."})
APPOINTMENT_2 = fe.source(json.dumps(_later))
SCHEMA_1, SCHEMA_2 = schema_fingerprint(APPOINTMENT_1), schema_fingerprint(APPOINTMENT_2)
SCHEMA_VERSIONS = {SCHEMA_1: 1, SCHEMA_2: 2}  # the axt.version of the schema a fingerprint names

# --- the state of a record (section 3) --------------------------------------------------------


@dataclass(frozen=True)
class FieldState:
    # The value in Avro binary encoding, with the type of the field. None only in an owner's layer of a
    # received record: the owner discarded a change of the field (section 21.1).
    value: bytes | None
    stamp: int  # 0 for a field never stamped (section 3.4)
    device: bytes
    schema: bytes = SCHEMA_1  # the fingerprint of the writer schema the bytes were written with


@dataclass(frozen=True)
class Removal:
    stamp: int
    device: bytes
    stands: bool = True  # False for a removal that was taken back (section 3.2)


@dataclass(frozen=True)
class Keep:
    """The keep of an owner's layer (section 21.1): the owner keeps the record against a deletion by its
    sender whose version is not above `version`, or, with `given_up`, has given that keeping up."""

    stamp: int
    device: bytes
    version: int
    given_up: bool = False


@dataclass(frozen=True)
class State:
    fields: dict[str, FieldState]
    removal: Removal | None = None
    state_stamp: int | None = None  # None where the device could take none (section 2.3)
    keep: Keep | None = None  # only an owner's layer of a received record holds one (section 21.1)


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
        if a.value is None or b.value is None:
            return b.value is None  # a null value is lower than every value that is not null (section 21.1)
        return bytes_order(a.value, b.value) > 0  # rule 3: the higher bytes of the value
    return bytes_order(a.schema, b.schema) > 0  # then the higher schema; with all equal, the same field state


def later_removal(a: Removal, b: Removal) -> bool:
    """Whether the removal a is later than b (section 4.2)."""
    if (a.stamp, a.device) != (b.stamp, b.device):
        return later(a, b)
    return a.stands and not b.stands  # the one that stands, over the one that was taken back


def later_keep(a: Keep, b: Keep) -> bool:
    """Whether the keep a is later than b (section 21.1): the higher version, then the higher stamp, then
    the higher device key, then the one that is given up."""
    if a.version != b.version:
        return a.version > b.version
    if a.stamp != b.stamp:
        return a.stamp > b.stamp
    if a.device != b.device:
        return key_order(a.device, b.device) > 0
    return a.given_up and not b.given_up


# --- merging two states (sections 4.1 to 4.3) --------------------------------------------------


@dataclass(frozen=True)
class Merged:
    fields: dict[str, FieldState]
    removal: Removal | None
    stands: dict[str, str]  # for each field name, "own" or "other" (section 4.1)
    removal_taken: bool  # whether the removal comes from the other state (section 4.2)
    keep: Keep | None = None  # of an owner's layer (section 21.1)
    keep_taken: bool = False  # whether the keep comes from the other state

    @property
    def took(self) -> bool:
        return self.removal_taken or self.keep_taken or "other" in self.stands.values()


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
    keep = own.keep if own else None
    keep_taken = other.keep is not None and (keep is None or later_keep(other.keep, keep))
    if keep_taken:
        keep = other.keep
    return Merged(fields, removal, stands, removal_taken, keep, keep_taken)


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
            key=lambda f: (f.stamp, f.device, f.value is not None, f.value or b"", f.schema),
        )
    removals = [s.removal for s in states if s.removal is not None]
    return fields, max(removals, key=lambda x: (x.stamp, x.device, x.stands)) if removals else None


# --- what the merging device does (section 4.4) -------------------------------------------------


def seen(state: State) -> int:
    """The highest stamp of a state: of its field states, its removal and its state stamp; 0 without one."""
    stamps = [f.stamp for f in state.fields.values()]
    if state.removal:
        stamps.append(state.removal.stamp)
    if state.keep:
        stamps.append(state.keep.stamp)
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
        state = State(m.fields, m.removal, own.state_stamp, m.keep)
        return DeviceMerge(state, m, highest, sibling_stamp, kept_to_pass(to_pass, own.state_stamp))
    stamp = next_stamp(now_ms, highest, r)  # step 3
    if stamp is not None:
        highest = stamp
    return DeviceMerge(
        State(m.fields, m.removal, stamp, m.keep), m, highest, sibling_stamp, kept_to_pass(to_pass, stamp)
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


def state_json(state: State | None, layer: bool = False) -> dict[str, Any] | None:
    """A State of spec/conformance.md, section 5.14; that of an owner's layer, with `layer`, has `keep`."""
    if state is None:
        return None
    r, k = state.removal, state.keep
    keep = {
        "keep": k
        and {
            "stamp": str(k.stamp),
            "device": k.device.hex(),
            "version": str(k.version),
            "given_up": k.given_up,
        }
    }
    return {
        "fields": {
            name: {
                "value": None if f.value is None else f.value.hex(),
                "schema": f.schema.hex(),
                "stamp": str(f.stamp),
                "device": f.device.hex(),
            }
            for name, f in state.fields.items()
        },
        "removal": r and {"stamp": str(r.stamp), "device": r.device.hex(), "stands": r.stands},
        **(keep if layer else {}),
        "state_stamp": stamp_json(state.state_stamp),
    }


def state_of_json(v: dict[str, Any] | None) -> State | None:
    if v is None:
        return None
    r, k = v["removal"], v.get("keep")
    return State(
        {
            name: FieldState(
                None if f["value"] is None else bytes.fromhex(f["value"]),
                int(f["stamp"]),
                bytes.fromhex(f["device"]),
                bytes.fromhex(f["schema"]),
            )
            for name, f in v["fields"].items()
        },
        r and Removal(int(r["stamp"]), bytes.fromhex(r["device"]), r["stands"]),
        None if v["state_stamp"] is None else int(v["state_stamp"]),
        k and Keep(int(k["stamp"]), bytes.fromhex(k["device"]), int(k["version"]), k["given_up"]),
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
    assert f.value is not None
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
SPEC_NAMES = (
    "Envelope",
    "Manifest",
    "Offer",
    "Accept",
    "Decline",
    "Ack",
    "Error",
    "Change",
    "Resync",
    "Forward",
    "DeviceAdd",
    "DeviceRemove",
    "Withdraw",
    "Proposal",
    "ProposalReply",
)
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
    "FORWARD": "Forward",
    "PROPOSAL_REPLY": "ProposalReply",
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
    """A body of the specification in single-object encoding (spec/envelope.md, section 2.3). The types of
    an offer may name the text of a schema the device holds: its description is offered."""
    if name == "Offer":
        types = [
            {
                "description": t["description"] if "description" in t else fe.description_of(t["schema"]),
                "count": t["count"],
            }
            for t in datum["types"]
        ]
        datum = fe.avro_form(dict(datum, types=types))
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
        datum = fe.named(
            fastavro.schemaless_reader(
                buf, SPEC[name], SPEC[name], return_record_name=True, return_record_name_override=True
            )
        )
    except Exception as e:
        raise ValueError(f"not an axt.{name}: {type(e).__name__}") from None
    if buf.tell() != len(data):
        raise ValueError(f"bytes left over after the axt.{name}")
    return datum


def _uuid_text(key: int) -> str:
    """A 128-bit value as a UUID in lower-case text form."""
    h = f"{key:032x}"
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


def proposal_problem(d: dict[str, Any]) -> str | None:
    """Why the body of a PROPOSAL, decoded, is not valid (spec/shares.md, section 13.2), or None."""
    if uuid_key(d["proposal_id"]) is None:
        return "proposal_id is no UUID in text form, or the nil or the max UUID"
    if not 1 <= len(d["fields"]) <= MAX_FIELDS:
        return "not 1 to 4,096 entries in fields"
    names = [f["name"] for f in d["fields"]]
    if any(not 1 <= len(n.encode("utf-8")) <= MAX_NAME for n in names):
        return "a field name that is not 1 to 512 bytes of UTF-8"
    if len(set(names)) != len(names):
        return "a field name twice"
    return None


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
    for part in ("removal", "keep"):
        if d[part] is not None:
            stamps.append(d[part]["stamp"])
    return int(max(stamps))


def change_problem(d: dict[str, Any], version: int) -> str | None:
    """The rule of section 8.2 that the body of a CHANGE breaks, or None for a valid body. A key in
    `origin` is valid, and only with one a value may be null (section 21.4)."""
    if not FULL_NAME.match(d["type"]) or len(d["type"].encode()) > MAX_NAME:
        return "type is not a full name of at most 512 bytes"
    if d["state"] < 1:
        return "state is below 1"
    if d["removal"] is not None and d["removal"]["stamp"] < 1:
        return "the stamp of the removal is below 1"
    if d["keep"] is not None and d["origin"] is None:
        return "a keep in a message whose origin is null"
    if d["keep"] is not None and (d["keep"]["stamp"] < 1 or d["keep"]["version"] < 1):
        return "the stamp or the version of the keep is below 1"
    if len(d["fields"]) > MAX_FIELDS:
        return "more than 4,096 entries in fields"
    names = [f["name"] for f in d["fields"]]
    if any(not 1 <= len(n.encode()) <= MAX_NAME for n in names):
        return "a name of 0 or of more than 512 bytes"
    if len(set(names)) != len(names):
        return "a name twice"
    if d["origin"] is None and any(f["value"] is None for f in d["fields"]):
        return "a null value in a message whose origin is null"
    if any(f["stamp"] < -1 for f in d["fields"]):
        return "a stamp of a field state below -1"
    if not d["whole"] and not d["fields"] and d["removal"] is None and d["keep"] is None:
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
    keep: Keep | None = None

    @property
    def marks(self) -> frozenset[Any]:
        """The parts as a device keeps them for a CHANGE it sent (section 10.1): each field state by all
        it holds, where a device may keep a hash in the place of the value, the removal and the keep."""
        return self.fields | {p for p in (self.removal, self.keep) if p is not None}


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
    # RECORD_UNKNOWN for an owner's layer: nothing of it goes to the sibling until the sibling has taken
    # something of the sender, or the layer has a new state stamp (section 21.5).
    waiting: bool = False
    # RECORD_UNKNOWN for an owner's layer in a row, with no outcome of the sibling for a CHANGE of it in
    # between: from the second on, only a new state stamp or a RESYNC ends the wait (section 21.5).
    unknowns: int = 0


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


# --- what a set got from other apps (sections 17 to 22) ---------------------------------------------

FORWARDED = (
    "MANIFEST",
    "DATA",
    "DELETE",
    "WITHDRAW",
    "PROPOSAL",
    "DEVICE_ADD",
    "DEVICE_REMOVE",
)  # of section 18.1
INNER_BODY = {
    "MANIFEST": "Manifest",
    "DEVICE_ADD": "DeviceAdd",
    "DEVICE_REMOVE": "DeviceRemove",
    "WITHDRAW": "Withdraw",
    "PROPOSAL": "Proposal",
}
# A PROPOSAL and a PROPOSAL_REPLY carry `record` and are no record messages (spec/shares.md, section 12.1).
WITH_RECORD = ("DATA", "DELETE", "WITHDRAW", "PROPOSAL", "PROPOSAL_REPLY")
PROPOSAL_DAYS = 14  # how long a device keeps a proposal it does not show (spec/shares.md, section 17.1)
RECORD_MESSAGES = ("DATA", "DELETE", "WITHDRAW")  # spec/records.md, section 1
# A record of the set by its id as a 128-bit value; an owner's layer by its sender and that id.
Ref = int | tuple[int, int]


def sha(data: bytes) -> bytes:
    """The SHA-256 by which a device identifies a kept message (section 20.1)."""
    return hashlib.sha256(data).digest()


def inner_message(d: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Steps 7 to 11 of section 18.3 on the body of a FORWARD: the envelope of the message inside, and
    for a DATA the schema that `schema` holds. Reject with the code of the step that fails."""
    m: bytes = d["message"]
    if len(m) < 10 or m[:2] != MARKER:
        raise Reject("INVALID_MESSAGE", "message is no single-object encoding")  # step 7
    if m[2:10] != SPEC_FP["Envelope"]:
        raise Reject("FORMAT_UNSUPPORTED", fingerprint=m[2:10])  # step 8
    try:  # step 9: the rest of section 18.2
        inner = read_all("Envelope", m[10:])
    except ValueError as e:
        raise Reject("INVALID_MESSAGE", f"message: {e}") from None
    kind, body, text = inner["kind"], inner["body"], d["schema"]
    if inner["format"] != 1:
        raise Reject("INVALID_MESSAGE", "message: not the format of its fingerprint")
    if kind not in FORWARDED:
        raise Reject("INVALID_MESSAGE", f"a {kind} is never forwarded")
    if (inner["record"] is None) == (kind in WITH_RECORD):
        raise Reject("INVALID_MESSAGE", "message: record present or missing")
    if kind == "DELETE":
        if body:
            raise Reject("INVALID_MESSAGE", "message: a DELETE with a body")
    elif kind == "DATA":
        if len(body) < 10 or body[:2] != MARKER:
            raise Reject("INVALID_MESSAGE", "message: the body is no single-object encoding")
    elif body[:10] != MARKER + SPEC_FP[INNER_BODY[kind]]:
        raise Reject("INVALID_MESSAGE", f"message: the body is not an axt.{INNER_BODY[kind]}")
    if (text is None) == (kind == "DATA"):
        raise Reject("INVALID_MESSAGE", "schema is a string for a DATA, and null for every other kind")
    if text is None:
        return inner, None
    if len(text.encode()) > tm.rules.MAX_SCHEMA_BYTES:  # step 10
        raise Reject("TOO_LARGE", "a schema above 256 KiB")
    try:
        schema = json.loads(text)
    except RecursionError:
        raise Reject("TOO_LARGE", "a schema nested deeper than 64") from None
    except ValueError:
        raise Reject("INVALID_MESSAGE", "schema is no JSON text") from None
    if tm.rules.json_depth(schema) > tm.rules.MAX_JSON_DEPTH:
        raise Reject("TOO_LARGE", "a schema nested deeper than 64")
    try:  # step 11
        name = full_name(schema)
        fastavro.parse_schema(schema, _write_hint=False)
        fp = schema_fingerprint(text)
    except Exception:
        name = None
    if name is None or fp != body[2:10]:
        raise Reject("INVALID_MESSAGE", "schema is no schema of a record with the fingerprint of the body")
    return inner, schema


def record_values(schema: dict[str, Any], body: bytes) -> dict[str, bytes]:
    """The bytes of each top-level field in the body of a DATA, which holds the fields of the record one
    after the other, by the names of its writer schema; Reject with UNDECODABLE or VALUE_INVALID for a
    body that fails step 8 or 9 of spec/protocol.md, section 6.2 (section 19.5)."""
    buf, out, found = io.BytesIO(body[10:]), dict[str, bytes](), []
    for f in schema["fields"]:
        start = buf.tell()
        try:
            found.append(read_field(schema, f["name"], buf))
        except ValueError as e:
            raise Reject("UNDECODABLE", str(e)) from None
        out[f["name"]] = body[10 + start : 10 + buf.tell()]
    if buf.tell() != len(body) - 10:
        raise Reject("UNDECODABLE", "bytes left over after the record")
    for one, value in found:
        broken = tm.value_breaches(one, value)
        if broken:
            path, rule, why = broken[0]
            raise Reject("VALUE_INVALID", f"{rule}: {why}", field=mr.error_field(path))
    return out


def same_value(name: str, a: bytes, a_schema: dict[str, Any], b: bytes, b_schema: dict[str, Any]) -> bool:
    """Whether two values of a field are the same value: compared as the values they decode to, each
    with the schema it was written with, not by their bytes (section 22.2)."""
    if field_schema(a_schema, name) is None or field_schema(b_schema, name) is None:
        return False
    one: Any = read_field(a_schema, name, io.BytesIO(a))[1]
    other: Any = read_field(b_schema, name, io.BytesIO(b))[1]
    return bool(one == other)


def owner_values(layer: State | None) -> dict[str, FieldState]:
    """The field states of an owner's layer that hold an owner's value (section 17.1)."""
    return {} if layer is None else {n: f for n, f in layer.fields.items() if f.value is not None}


def owner_deleted(layer: State | None) -> bool:
    """Whether the owner's removal stands (section 21.1): a removal with `stands` true, whatever the
    stamps of the field states."""
    return layer is not None and layer.removal is not None and layer.removal.stands


# What a device shows of a received record (section 22.1).
NOT_THERE, THERE, BY_OWNER, BY_SENDER, AGAINST = (
    "none",
    "there",
    "deleted_by_owner",
    "deleted_by_sender",
    "kept",
)


def shown(
    there: bool | None,
    values: dict[str, bytes],
    schema: bytes | None,
    layer: State | None,
    version: int = 0,
    beside: tuple[dict[str, bytes], bytes] | None = None,
) -> tuple[str, dict[str, tuple[bytes, bytes, str]]]:
    """The record a device shows, from the two layers alone, by the rules 0 to 3b of section 22.1. `there`
    is None for a device that holds no record message of the record, True for a sender's layer that ends
    in a DATA, with the bytes of its fields in `values` and the fingerprint of their schema, and False for
    one that ends in a DELETE of the version `version`, with the values and the fingerprint of the
    schema of the DATA beside the tombstone in `beside`, if the device holds one. For each field that
    has a value: its bytes, the fingerprint of their schema, and the layer it comes from."""
    if there is None:
        return NOT_THERE, {}  # rule 0
    if owner_deleted(layer):
        return BY_OWNER, {}  # rule 1
    if not there:
        keep = None if layer is None else layer.keep
        kept = keep is not None and not keep.given_up and keep.version >= version
        if not kept or beside is None or not owner_values(layer):
            return BY_SENDER, {}  # rule 3b
        values, schema = beside  # rule 3a: the DATA beside the tombstone, with the owner's values
    assert schema is not None
    own = owner_values(layer)
    out: dict[str, tuple[bytes, bytes, str]] = {}
    for name, value in values.items():
        mine = own.get(name)
        if mine is None or mine.value is None:
            out[name] = (value, schema, "sender")
        else:
            out[name] = (mine.value, mine.schema, "owner")
    return (THERE if there else AGAINST), out


def answered(
    kind: str,
    values: dict[str, bytes],
    schema: bytes | None,
    layer: State | None,
    texts: dict[bytes, str],
) -> tuple[str, list[str]]:
    """The outcome that the answering device reports for a record message with a higher version than its
    receiver's version, or for an id it does not have, and the names of the fields it kept (section 22.2;
    spec/records.md, section 6), for a set that merges per field. The message changes nothing in the
    owner's layer. `kind` is DATA, with the bytes of each field of its body in `values` and the
    fingerprint of its writer schema, or DELETE; `texts` holds the schemas by which values are compared.
    A DELETE that meets an owner's layer which is deleted by the owner or holds an owner's value is not
    modelled."""
    own = owner_values(layer)
    assert kind == "DATA" and schema is not None
    if owner_deleted(layer):
        return "KEPT", []  # the record stays deleted (spec/records.md, section 6.3)
    written = json.loads(texts[schema])
    kept_fields = [
        n
        for n in values
        if n in own
        and not same_value(n, own[n].value or b"", json.loads(texts[own[n].schema]), values[n], written)
    ]
    return ("MERGED" if kept_fields else "APPLIED"), kept_fields


def schema_version(text: str | None) -> int:
    """The `axt.version` of a writer schema (spec/types.md, section 3.2), or 0 without one."""
    if text is None:
        return 0
    version = json.loads(text).get("axt.version", 0)
    return version if isinstance(version, int) else 0


def kind_of(raw: bytes) -> str:
    """The kind of a kept message."""
    kind: str = read_all("Envelope", raw[10:])["kind"]
    return kind


def stands_over(raw: bytes, text: str | None, kept: "Received") -> bool:
    """Whether a record message with the id and version of the kept one, in other bytes, stands over it
    (section 20.1): of two DATA messages the one whose writer schema has the higher `axt.version`; with
    equal versions of the schema, and of two DELETE messages, the one with the higher SHA-256."""
    mine, theirs = schema_version(text), schema_version(kept.schema)
    if mine != theirs:
        return mine > theirs
    return sha(raw) > sha(kept.message)


def cast_stamp(stamp: int | None) -> int:
    assert stamp is not None, "the second stamp of a change that could begin can be taken"
    return stamp


@dataclass
class Received:
    """The sender's layer of a received record (section 17.1) and its kept message (section 20.1)."""

    type: str | None  # the full name of its type; a tombstone for an id the device did not have holds none
    version: int  # the receiver's version
    there: bool  # False for a tombstone
    message: bytes  # the record message that brought the receiver's version, as the bytes received
    schema: str | None  # for a DATA, the text of the writer schema of its body
    values: dict[str, bytes] = dataclasses.field(default_factory=dict)  # of a DATA, the bytes of each field
    # For a tombstone: the DATA with the highest version below the DELETE that the device took, the DATA
    # beside the tombstone (sections 17.1 and 20.1), or None.
    beside: Any = None  # a Received, or None; not annotated so, as the loaders of this script need


@dataclass
class Sender:
    """A known sender other than the device's own set, with what the device keeps of it in order to pass
    it on (section 20.1)."""

    serial: int  # its current and its removed keys are with the device, under this number
    first: bytes  # the key by which the device first knew it: the `origin` of its layers (section 21.3)
    chain: list[bytes] = dataclasses.field(default_factory=list)  # the additions and removals applied
    manifests: dict[bytes, tuple[int, bytes]] = dataclasses.field(default_factory=dict)
    records: dict[int, Received] = dataclasses.field(default_factory=dict)
    ids: dict[int, str] = dataclasses.field(default_factory=dict)
    schemas: dict[bytes, str] = dataclasses.field(default_factory=dict)  # kept apart (section 21.4)
    # The keys whose kept manifest the device took from the key itself in a live connection (section 19.4).
    live: set[bytes] = dataclasses.field(default_factory=set)
    # How the device came to know it (section 19.2): None by its own user; otherwise by forwards of these
    # siblings.
    known_by: set[bytes] | None = None
    # The PROPOSAL messages of the sender that the device took and keeps (spec/shares.md, section 17.1), by
    # the proposal id as a 128-bit value: the message, the id of the record of the set, the day it took it,
    # and whether it showed the proposal then or since.
    proposals: dict[int, tuple[bytes, int, int, bool]] = dataclasses.field(default_factory=dict)

    def kept(self) -> list[tuple[bytes, str | None]]:
        """Its kept messages in the order in which they are forwarded (section 20.3): the additions and
        removals in the order in which they were applied, the manifests, the record messages. Each with
        the schema text that goes with a DATA."""
        out: list[tuple[bytes, str | None]] = [(m, None) for m in self.chain]
        out += [(self.manifests[k][1], None) for k in sorted(self.manifests)]
        for k in sorted(self.records):
            beside = self.records[k].beside  # the DATA beside a tombstone goes before the DELETE
            out += [] if beside is None else [(beside.message, beside.schema)]
            out.append((self.records[k].message, self.records[k].schema))
        # The proposals after the record messages: a choice of the device of a session (section 20.3;
        # spec/shares.md, section 17.1).
        out += [(self.proposals[k][0], None) for k in sorted(self.proposals)]
        return out


class SetDevice:
    """One device of a device set, with the records of the set, its siblings and what it keeps for each
    of them, and the senders it knows with what it keeps of them. It processes the messages of its
    siblings by sections 7 to 13 and 17 to 24 and gives back the messages it sends. Every sibling has a
    channel to it, a live connection in which both manifests have been
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
        refused: list[bytes] | None = None,
        forward_ids: list[str] | None = None,
        on_delete: str = "delete",
        on_withdraw: str | None = None,
    ) -> None:
        self.seed, self.key = seed, bytes(keys.public_key(seed))
        self.siblings = list(siblings)
        self.relay = set(relay or [])  # the siblings it reaches through the relay
        self.removed = set(removed or [])  # the removed keys of the device's own set
        # The removed keys of other senders and the refused keys that the device is given as such: a
        # message of one is rejected without a report (section 7.1).
        self.gone = set(gone or [])
        # The senders it knows other than its own set, with their current and their removed keys, and
        # its refused keys (spec/keys.md, sections 3.3, 3.4 and 5.5).
        self.book = keys.DeviceReceiver([], [*(refused or []), *(gone or [])])
        self.senders: dict[int, Sender] = {}
        self.serial = 0
        self.others = list(others or [])
        for other in self.others:
            self._new_sender(other)  # a known sender of which it keeps nothing but that key
        self.forward_ids = list(forward_ids or [])
        # The senders its user forgot (section 20.5): for each, the key it first knew it by, its forgotten
        # keys, which were its current keys, and its refused keys, which were its removed keys.
        self.forgotten: list[tuple[bytes, list[bytes], list[bytes]]] = []
        self.intro_waits: set[int] = set()  # the senders to which its chain and MANIFEST wait (section 17.2)
        # What the set does with a DELETE of another app that meets owner's values: "delete" or "keep"
        # (spec/records.md, section 6.4; section 22.3).
        self.on_delete = on_delete
        # The same for a WITHDRAW (spec/shares.md, section 4.3); as for a DELETE where it is not given.
        self.on_withdraw = on_delete if on_withdraw is None else on_withdraw
        # For each owner's layer, the message of its sender for which the device reported KEPT and owes
        # the further ACK of section 22.3: the signer, the id, the version and the kind.
        self.later: dict[tuple[int, int], tuple[bytes, str, int, str]] = {}
        self.layers: dict[tuple[int, int], Held] = {}  # the owner's layers, by sender and id (section 21.1)
        # The removals of other senders that it keeps to try them again (section 19.3).
        # Each with the signer, the device, the kind and the sibling that forwarded it.
        self.early: list[tuple[bytes, bytes, bytes, str, bytes | None]] = []
        # For each sibling (section 20.2): the kept messages delivered to it; the forwards it sent that
        # have neither an outcome nor a settling error, by their id, each with the kept message, the day
        # it last went, its id as text and its sender; the kept messages for which an error settled a
        # forward; and those that went in the channel and wait for an outcome there.
        self.fdelivered: dict[bytes, set[bytes]] = {s: set() for s in siblings}
        self.forwards: dict[bytes, dict[int, tuple[bytes, int, str, int]]] = {s: {} for s in siblings}
        self.fsettled: dict[bytes, set[bytes]] = {s: set() for s in siblings}
        self.fgone: dict[bytes, set[bytes]] = {s: set() for s in siblings}
        self.fanswer: dict[bytes, bool] = dict.fromkeys(siblings, False)  # forwards of an answer are to go
        # For each sibling (section 20.2): the keys of which it has forwarded a removal whose signature
        # verified; those of which the device acknowledged such a forward; the kept messages for which
        # NOT_ACCEPTED of the sibling settled a forward, and those it forwarded once more after one.
        self.fremovals: dict[bytes, set[bytes]] = {s: set() for s in siblings}
        self.facked: dict[bytes, set[bytes]] = {s: set() for s in siblings}
        self.frefused: dict[bytes, set[bytes]] = {s: set() for s in siblings}
        self.fretried: dict[bytes, set[bytes]] = {s: set() for s in siblings}
        self.after_acks: list[tuple[bytes, bytes]] = []  # due again once the ACK of a removal has gone
        self.app_acks: dict[bytes, list[dict[str, Any]]] = {}  # the entries it owes other apps
        # What the app's own records hold (spec/shares.md, sections 2.1 and 15.1): for each record of the
        # set, by its id as a 128-bit value, the senders it is shared with, by serial; and the answers to
        # proposals, by the serial of the proposer and the proposal id as a 128-bit value.
        self.shares: dict[int, set[int]] = {}
        self.answers: dict[tuple[int, int], str] = {}
        self.stopped: set[tuple[int, int | None]] = set()
        self.answered_records: dict[
            tuple[int, int], tuple[str, int]
        ] = {}  # the stops of receivers, by serial and record
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
        self.kept: dict[tuple[bytes, Ref], Kept] = {}
        # The CHANGE messages it sent that have neither an outcome nor a settling error, by id and
        # version: the parts each held, the day it last went (section 10.1), and the record or layer.
        self.sent: dict[bytes, dict[tuple[int, int], tuple[frozenset[Any], int, Ref]]] = {
            s: {} for s in siblings
        }
        self.acks: dict[bytes, list[dict[str, Any]]] = {s: [] for s in siblings}
        self.requests: dict[bytes, tuple[str, int]] = {}  # its open requests: the id, the day it last went
        self.asked: int | None = None  # the day it opened the first of its open requests (section 5.1)
        self.answered = False  # whether one of its open requests has been acknowledged (section 12.1)
        self.restored = False  # whether it restored a backup (section 12.1)
        self.acted: dict[bytes, dict[int, str]] = {s: {} for s in siblings}  # the requests it acted on
        self.answering: dict[bytes, dict[int, str]] = {s: {} for s in siblings}  # those not yet answered
        self.left: dict[bytes, set[Ref]] = {s: set() for s in siblings}  # the records an answer still lacks
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

    # --- the senders it knows, and the records and layers by their place (sections 17.1 and 21.3) ---

    def _new_sender(self, key: bytes) -> Sender:
        """A key becomes the first key of a new known sender (spec/keys.md, section 3.2; section 19.2)."""
        self.serial += 1
        self.book.senders.append(keys.KnownSender(str(self.serial), [key]))
        self.senders[self.serial] = Sender(self.serial, key)
        return self.senders[self.serial]

    def _sender_of(self, key: bytes) -> Sender | None:
        """The known sender that has the key among its current or its removed keys."""
        known = self.book.sender_of(key)
        return None if known is None else self.senders[int(known.name)]

    def _keys(self, sender: Sender) -> Any:
        """The current and the removed keys of a known sender."""
        return next(k for k in self.book.senders if k.name == str(sender.serial))

    def _ordered(self) -> list[Sender]:
        """The known senders in the order of the keys by which the device first knew them."""
        return sorted(self.senders.values(), key=lambda s: s.first)

    def _refs(self) -> list[Ref]:
        """The records of the set in the order of their ids, then the owner's layers, sender by sender."""
        layers = sorted(self.layers, key=lambda ref: (self.senders[ref[0]].first, ref[1]))
        return [*sorted(self.records), *layers]

    def _held(self, ref: Ref) -> Held | None:
        return self.records.get(ref) if isinstance(ref, int) else self.layers.get(ref)

    def _id(self, ref: Ref) -> str:
        return self.ids[ref] if isinstance(ref, int) else self.senders[ref[0]].ids[ref[1]]

    def _text(self, ref: Ref, fp: bytes) -> str | None:
        """The text of the schema that a field state of the record or layer names."""
        if isinstance(ref, int):
            return self.schema(fp)
        return self.senders[ref[0]].schemas.get(fp)

    def _kept_hashes(self) -> set[bytes]:
        return {sha(m) for sender in self.senders.values() for m, _ in sender.kept()}

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
        if state.keep is not None:
            parts.add(state.keep)
        return parts

    def _content(self, held: Held, kept: Kept) -> Content | None:
        """What a CHANGE of the record to a sibling carries (section 10.2), or None if nothing is sent."""
        fields = frozenset(held.state.fields.items())
        whole = not held.incomplete
        if not kept.known:
            return Content(whole, held.state.removal, fields, held.state.keep)
        due = frozenset(p for p in fields if p not in kept.delivered)
        removal, keep = held.state.removal, held.state.keep
        if removal is not None and removal in kept.delivered:
            removal = None
        if keep is not None and keep in kept.delivered:
            keep = None
        if not due and removal is None and keep is None:
            return None
        return Content(due == fields and whole, removal, due, keep)

    def change_datum(
        self, sibling: bytes, held: Held, content: Content, stamp: int, origin: bytes | None = None
    ) -> dict[str, Any]:
        r, k = content.removal, content.keep
        return {
            "to": sibling,
            "origin": origin,
            "type": held.type,
            "state": stamp,
            "whole": content.whole,
            "removal": r and {"stamp": r.stamp, "device": r.device, "stands": r.stands},
            "keep": k
            and {"stamp": k.stamp, "device": k.device, "version": k.version, "given_up": k.given_up},
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
            lacking: dict[bytes, tuple[int, str]] = {}
            left = self.left[sibling]
            # The messages of other apps go first, so that the sibling knows a sender and holds a record
            # when the owner's layer arrives (sections 20.3, 20.4 and 21.5).
            out += self._forward_due(sibling)
            for key in self._refs():
                held = self._held(key)
                assert held is not None
                kept = self.kept.setdefault((sibling, key), Kept())
                if sibling in self.requests and key not in left:
                    continue  # no CHANGE while its own request is open, apart from an answer (section 11.3)
                stamp = held.state.state_stamp
                if kept.settled is not None and kept.settled != stamp:
                    kept.want, kept.settled = True, None  # the state stamp has changed (section 9.3)
                if not kept.want or kept.waiting:
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
                        text = self._text(key, fp)
                        assert text is not None, "a schema to offer"
                        lacking[fp] = (lacking.get(fp, (0, ""))[0] + 1, text)
                    continue
                differs = kept.last is not None and kept.last[0] == stamp and kept.last[1] != content
                if differs or kept.fresh or held.restored:
                    # A new state stamp first (section 3.3, occasions 5, 6 and 7).
                    new = next_stamp(self.now_ms, self.highest, self._draw())
                    if new is None:
                        left.discard(key)
                        continue
                    self.highest = stamp = new
                    held.state = dataclasses.replace(held.state, state_stamp=new)
                    held.to_pass = kept_to_pass(held.to_pass, new)
                origin = None if isinstance(key, int) else self.senders[key[0]].first
                datum = self.change_datum(sibling, held, content, stamp, origin)
                version = change_version(datum)
                m = message(self.seed, "CHANGE", (self._id(key), version), body_of("Change", datum))
                if len(m) > MAX_MESSAGE:
                    left.discard(key)
                    continue  # a record that does not fit is not sent (section 10.2)
                name = (key if isinstance(key, int) else key[1], version)
                kept.last, kept.flight, kept.want = (stamp, content), name, False
                kept.fresh = held.restored = False
                self.sent[sibling][name] = (content.marks, self.day, key)
                left.discard(key)
                out.append(m)
            for fp in sorted(lacking):
                if fp in {p[0] for p in self.pending[sibling].values()}:
                    continue  # offered, and not answered yet
                count, text = lacking[fp]
                assert self.offer_ids, "an id for the offer"
                offer_id = self.offer_ids.pop(0)
                offer_key = uuid_key(offer_id)
                assert offer_key is not None
                self.pending[sibling][offer_key] = (fp, str(full_name(json.loads(text))))
                types = [{"schema": text, "count": count}]
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

    def _due_for(self, key: Ref, parts: set[Any], but: bytes | None = None) -> None:
        """Parts that the state of a record has got are due for every sibling to which they are not
        delivered: a reason to send (section 10.3)."""
        for sibling in self.siblings:
            kept = self.kept.setdefault((sibling, key), Kept())
            if sibling != but and not parts <= kept.delivered:
                kept.want = True

    # --- forwarding (section 20) ---

    def _forward_due(self, sibling: bytes) -> list[bytes]:
        """The FORWARD messages the device sends a sibling now: one for every kept message that is due
        for it, sender by sender and in the order of section 20.3. A forward that it still keeps goes
        again as the same message; every other is a new forward, with the next id."""
        if sibling in self.requests and not self.fanswer[sibling]:
            return []  # no FORWARD while its own request is open, apart from an answer (section 20.3)
        self.fanswer[sibling] = False
        out: list[bytes] = []
        for sender in self._ordered():
            for raw, text in sender.kept():
                h = sha(raw)
                if h in self.fdelivered[sibling] | self.fsettled[sibling] | self.fgone[sibling]:
                    continue
                if kind_of(raw) == "PROPOSAL" and self._offer_first(sibling, raw, out):
                    continue  # the schemas of its entries are offered first (spec/shares.md, section 17.1)
                again = [f for f in self.forwards[sibling].values() if f[0] == h]
                assert again or self.forward_ids, "an id for the forward"
                fid = again[0][2] if again else self.forward_ids[0]
                body = body_of("Forward", {"to": sibling, "message": raw, "schema": text})
                m = message(self.seed, "FORWARD", (fid, 1), body)
                if len(m) > MAX_MESSAGE:
                    continue  # a message that does not fit is not forwarded (section 20.3)
                if not again:
                    self.forward_ids.pop(0)
                self.forwards[sibling][uuid_key(fid) or 0] = (h, self.day, fid, sender.serial)
                self.fgone[sibling].add(h)
                out.append(m)
        return out

    def _offer_first(self, sibling: bytes, raw: bytes, out: list[bytes]) -> bool:
        """Whether a kept PROPOSAL waits for the sibling's acceptance of the schema of an entry: the device
        offers each such schema whose text it keeps, in an offer of its own, unless one is open."""
        d = read_all("Proposal", read_all("Envelope", raw[10:])["body"][10:])
        waits = False
        for fp in dict.fromkeys(f["schema"] for f in d["fields"]):
            text = self.schemas.get(fp)
            if text is None or fp in self.accepted[sibling] or fp in self.declined[sibling]:
                continue
            waits = True
            if fp in {p[0] for p in self.pending[sibling].values()}:
                continue
            assert self.offer_ids, "an id for the offer"
            offer_id = self.offer_ids.pop(0)
            self.pending[sibling][uuid_key(offer_id) or 0] = (fp, str(full_name(json.loads(text))))
            body = body_of(
                "Offer", {"to": sibling, "offer_id": offer_id, "types": [{"schema": text, "count": 0}]}
            )
            out.append(message(self.seed, "OFFER", None, body))
        return waits

    def _undeliver(self, sibling: bytes, raw: bytes) -> None:
        """A kept message is no longer delivered to a sibling, and so due for it again (section 20.2)."""
        for table in (self.fdelivered, self.fsettled, self.fgone):
            table[sibling].discard(sha(raw))

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
        # No kept message is delivered to a device that joins (section 23.3).
        self.fdelivered[sibling], self.fsettled[sibling], self.fgone[sibling] = set(), set(), set()
        self.forwards[sibling], self.fanswer[sibling] = {}, False
        self.fremovals[sibling], self.facked[sibling] = set(), set()
        self.frefused[sibling], self.fretried[sibling] = set(), set()
        asked: list[bytes] = []
        if self.restored:
            # A restored device that learns of a device its backup did not hold acts toward it as after
            # a restore (section 12.1).
            self._unknown_age()
            asked = self._ask(sibling)
        self._pass_on()
        return asked + self._send_due()

    def remove(self, sibling: bytes, move: bool = False) -> tuple[list[bytes], list[bytes]]:
        """The device applies the removal of a sibling (sections 12.2 and 23.2): it discards what it kept
        for that key and sends it nothing more; the messages it sends, and the origins of the known
        senders to which it sends its chain and its MANIFEST now (section 17.2). It holds them back from
        the senders known only by forwards of the removed sibling, unless the removal ends a move."""
        out = self._remove(sibling)
        now = []
        for serial in sorted(self.senders):
            s = self.senders[serial]
            if s.known_by == {sibling} and not move:
                self.intro_waits.add(serial)
            else:
                now.append(s.first)
        return out, sorted(now)

    def senders_kept(self) -> list[bytes]:
        """Its user has seen the list of the senders known only by forwards of the removed sibling and
        kept those it did not forget: the origins of those to which it now sends its chain and its
        MANIFEST (section 17.2)."""
        held, self.intro_waits = self.intro_waits, set()
        return sorted(self.senders[n].first for n in held if n in self.senders)

    def _remove(self, sibling: bytes) -> list[bytes]:
        self.siblings.remove(sibling)
        self.removed.add(sibling)
        self.relay.discard(sibling)
        tables: tuple[dict[bytes, Any], ...] = (self.offered, self.pending, self.accepted, self.declined)
        for table in (*tables, self.sent, self.acks, self.acted, self.answering, self.left, self.passed):
            del table[sibling]
        # What it kept for that key about the messages of other apps goes as well (section 23.2).
        more: tuple[dict[bytes, Any], ...] = (
            self.fdelivered,
            self.fsettled,
            self.fgone,
            self.forwards,
            self.fremovals,
            self.facked,
            self.frefused,
            self.fretried,
        )
        for table in (*more, self.fanswer):
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
        # A FORWARD without an outcome when its connection ends has not been delivered (section 20.3).
        self.fgone[sibling] = set()
        first = [self._resync(sibling)] if sibling in self.requests else []
        return first + self._send_due()

    def restore(
        self,
        highest: int,
        records: list[tuple[str, Held]],
        acted: dict[bytes, list[str]] | None = None,
        senders: list[dict[str, Any]] | None = None,
        refused: list[bytes] | None = None,
        bytes_in: Callable[[Any], bytes] = bytes.fromhex,
    ) -> list[bytes]:
        """The device restored its data from a backup (sections 12.1 and 23.1): it holds the records, the
        known senders with their kept messages and owner's layers, and the highest stamp of the backup,
        and none of its bookkeeping, has no offer, gives its field states never stamped the stamp -1 if
        it has a sibling, and opens a new request toward every sibling."""
        self.highest, self.records, self.ids, self.kept = highest, {}, {}, {}
        self.requests, self.asked, self.restored = {}, None, True
        self.book = keys.DeviceReceiver([], [*(refused or []), *sorted(self.gone)])
        self.senders, self.layers, self.early, self.app_acks, self.later = {}, {}, [], {}, {}
        for other in self.others:
            self._new_sender(other)
        for sibling in self.siblings:
            self.fdelivered[sibling], self.fsettled[sibling], self.fgone[sibling] = set(), set(), set()
            self.forwards[sibling], self.fanswer[sibling] = {}, False
            self.fremovals[sibling], self.facked[sibling] = set(), set()
            self.frefused[sibling], self.fretried[sibling] = set(), set()
        for sender in senders or []:
            self.know(sender, bytes_in)
        for layer in self.layers.values():
            layer.restored = True
            layer.unstamped = {name: f for name, f in layer.state.fields.items() if f.stamp == 0}
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
        for key in self._refs():
            held = self._held(key)
            assert held is not None
            fields = dict(held.state.fields)
            for name, f in held.unstamped.items():
                if fields.get(name) == f:
                    fields[name] = dataclasses.replace(f, stamp=-1)
            held.unstamped = {}
            if fields != held.state.fields:
                held.state = dataclasses.replace(held.state, fields=fields)
                self._due_for(key, self._parts(held.state))

    def days(self, n: int) -> list[bytes]:
        """n days pass in which nothing reaches the device (sections 10.1, 10.3 and 11.3)."""
        self.day += n
        for sibling in self.siblings:
            # A CHANGE is kept for 15 days after it last went; an outcome after that is ignored.
            self.sent[sibling] = {
                name: (marks, day, ref)
                for name, (marks, day, ref) in self.sent[sibling].items()
                if self.day - day <= KEEP_DAYS
            }
            # A FORWARD is kept for 15 days after it last went as well (section 20.2).
            self.forwards[sibling] = {
                fid: f for fid, f in self.forwards[sibling].items() if self.day - f[1] <= KEEP_DAYS
            }
        out: list[bytes] = []
        for sibling in sorted(self.relay & set(self.siblings)):
            # Through the relay, once the holding time has passed: the request, and each CHANGE and each
            # FORWARD that has neither an outcome nor an error that settles it.
            if sibling in self.requests and self.day - self.requests[sibling][1] >= HOLDING_DAYS:
                out.append(self._resync(sibling))
            for h, day, _, _ in self.forwards[sibling].values():
                if self.day - day >= HOLDING_DAYS:
                    self.fgone[sibling].discard(h)
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
        # What it owes the other apps whose record messages it answered itself (section 17.2).
        for app in sorted(self.app_acks):
            for batch in self._batches(self.app_acks[app]):
                out.append(message(self.seed, "ACK", None, body_of("Ack", {"to": app, "records": batch})))
        self.app_acks = {}
        # Once its acknowledgement of a forwarded removal has gone, what NOT_ACCEPTED of that sibling had
        # settled for the removed key goes again (section 20.2).
        later, self.after_acks = self.after_acks, []
        for sibling, key in later:
            if sibling in self.siblings:
                self._refused_again(sibling, key)
        return out + (self._send_due() if later else [])

    @staticmethod
    def _batches(entries: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
        """The entries of the acknowledgements a device owes one key, in ACK messages of up to 4,096
        entries of which none holds an id and version twice (spec/protocol.md, section 7.1)."""
        out: list[list[dict[str, Any]]] = []
        while entries:
            batch, rest, met = list[dict[str, Any]](), list[dict[str, Any]](), set[tuple[int | None, int]]()
            for e in entries:
                name = (uuid_key(e["id"]), e["version"])
                if name in met or len(batch) == MAX_ACK_RECORDS:
                    rest.append(e)
                else:
                    met.add(name)
                    batch.append(e)
            out.append(batch)
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
            # After NOT_ACCEPTED for a message of a removed key, the device's own removal is due for that
            # sibling and goes to it (section 19.2).
            more = self._send_due() if e.detail.startswith("a removed key") else []
            return None, ([self._report(e, m)] if e.report else []) + more
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
        of_other = self.book.key_state(sender)[0]  # what the key is among the other senders it knows
        if (rec is None) == (kind in ("CHANGE", "RESYNC", "FORWARD", *WITH_RECORD)):
            # A record where none belongs, or none where one is required: no valid message of its kind.
            # Only a key the device exchanges with gets the report.
            raise Reject(
                "INVALID_MESSAGE",
                "record present or missing",
                report=sender in self.siblings or of_other == "current",
            )
        # Step 2: the sender, by the table of section 7.1. It holds for every kind a sibling sends.
        if sender == self.key:
            self.what = "ignored: the device's own key"
            return None, []
        if sender in self.removed or of_other in ("removed", "refused"):
            self.what = "rejected without a report: a removed or a refused key"
            return None, []
        if sender not in self.siblings:
            assert kind in ("CHANGE", "RESYNC", "FORWARD"), (
                "the model takes the other kinds from siblings only"
            )
            if of_other == "current":
                raise Reject("INVALID_MESSAGE", f"a {kind} of another sender")
            self.what = "a message of an unknown key"
            return None, []
        if kind == "WITHDRAW":
            # Step 1 of spec/shares.md, section 4.1: the body and the addressee; then step 5 as for a DELETE.
            try:
                to = read_all("Withdraw", envelope["body"][10:])["to"]
            except ValueError as e:
                raise Reject("INVALID_MESSAGE", str(e)) from None
            if envelope["body"][:10] != MARKER + SPEC_FP["Withdraw"]:
                raise Reject("INVALID_MESSAGE", "the body is not an axt.Withdraw")
            if to != self.key:
                self.what = "ignored: for another key"
                return None, []
        if kind in RECORD_MESSAGES:
            return self._record_message(sender, kind, rec, envelope["body"])
        if kind in ("PROPOSAL", "PROPOSAL_REPLY"):
            return self._proposal_of_sibling(kind, rec, envelope["body"])
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
        if kind == "FORWARD":
            return self._forward(sender, rec, d)
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
        """A DATA, a DELETE or a WITHDRAW of a sibling: no accepted offer between siblings is one for a record
        message, so it fails step 5 of spec/protocol.md, section 6.2, if the steps before it pass
        (section 7.2)."""
        if uuid_key(rec["id"]) is None:
            raise Reject("RECORD_ID_INVALID")
        if rec["version"] < 1:
            raise Reject("VERSION_INVALID")
        if kind == "DATA" and (body[:2] != MARKER or body[2:10] not in self.offered[sender]):
            raise Reject("SCHEMA_UNKNOWN", fingerprint=body[2:10] if len(body) >= 10 else None)  # step 4
        raise Reject("NOT_ACCEPTED", "siblings send each other no record messages")

    def _proposal_of_sibling(self, kind: str, rec: Any, body: bytes) -> tuple[str | None, list[bytes]]:
        """A PROPOSAL of a sibling, which is no receiver: it fails step 5 of spec/shares.md, section 13.3,
        if the steps before it pass. A PROPOSAL_REPLY of a sibling names no proposal that the device sent
        it, and is ignored at step 3 of section 14.2 there."""
        name = "Proposal" if kind == "PROPOSAL" else "ProposalReply"
        if body[:10] != MARKER + SPEC_FP[name]:
            raise Reject("INVALID_MESSAGE", f"the body is not an axt.{name}")
        try:
            d = read_all(name, body[10:])
        except ValueError as e:
            raise Reject("INVALID_MESSAGE", str(e)) from None
        if d["to"] != self.key:
            self.what = "ignored: for another key"
            return None, []
        if kind == "PROPOSAL_REPLY":
            self.what = "ignored: a reply to no proposal of the device"
            return None, []
        if uuid_key(rec["id"]) is None:
            raise Reject("RECORD_ID_INVALID")
        if rec["version"] < 1:
            raise Reject("VERSION_INVALID")
        problem = proposal_problem(d)
        if problem is not None:
            raise Reject("INVALID_MESSAGE", problem)
        raise Reject("PROPOSALS_NOT_TAKEN", "a sibling is no receiver")

    def _change(
        self, sender: bytes, rec: dict[str, Any], d: dict[str, Any]
    ) -> tuple[str | None, list[bytes]]:
        """Steps 4 to 13 of section 8.3, and for a message with a key in `origin`, which carries the
        owner's layer of a received record, with the differences of section 21.4."""
        key = uuid_key(rec["id"])
        if key is None:
            raise Reject("RECORD_ID_INVALID")  # step 4
        if rec["version"] < 1:
            raise Reject("VERSION_INVALID")  # step 5
        problem = change_problem(d, rec["version"])
        if problem is not None:
            raise Reject("INVALID_MESSAGE", problem)  # step 6
        origin: bytes | None = d["origin"]
        of = None if origin is None else self._sender_of(origin)  # the record's sender (section 21.3)
        if origin is not None:
            # Step 10 comes before the steps 7 and 8 for a message with a key in origin: the sender is
            # resolved first (section 21.4).
            if origin == self.key or origin in self.siblings or origin in self.removed:
                raise Reject("INVALID_MESSAGE", "origin is a key of the device's own set")
            if of is None:
                raise Reject("RECORD_UNKNOWN")  # the device does not know the sender of the record
        ref: Ref = key if origin is None else (of.serial if of else 0, key)
        schemas: dict[bytes, dict[str, Any]] = {}
        texts: dict[bytes, str] = {}
        for entry in d["fields"]:  # step 7
            if origin is None:
                text = self.schema(entry["schema"])
            else:
                # Among the schemas kept of the record's sender, then among those of the current offers
                # of the sibling in the channel, and nowhere else (section 21.4).
                text = (of.schemas if of else {}).get(entry["schema"]) or self.offered[sender].get(
                    entry["schema"]
                )
            if text is None:
                raise Reject("SCHEMA_UNKNOWN", fingerprint=entry["schema"])
            schemas[entry["schema"]], texts[entry["schema"]] = json.loads(text), text
        for entry in d["fields"]:  # step 8
            schema = schemas[entry["schema"]]
            if full_name(schema) != d["type"] or field_schema(schema, entry["name"]) is None:
                raise Reject("INVALID_MESSAGE", f"{entry['name']}: not a field of a schema of {d['type']}")
        held = self._held(ref)
        names: set[str | None] = {held.type} if held is not None else set()
        if of is not None and key in of.records:
            names.add(of.records[key].type)  # the sender's layer keeps a full name as well
        if names - {d["type"], None}:
            raise Reject(
                "TYPE_CHANGED", f"{sorted(n for n in names if n)[0]} before, {d['type']} now"
            )  # step 9
        if origin is None:
            if not (d["whole"] or (held is not None and (held.state.fields or held.state.removal is None))):
                raise Reject("RECORD_UNKNOWN")  # step 10
        decoded = []
        for entry in d["fields"]:  # step 11
            if entry["value"] is None:
                continue  # the owner discarded a change of the field (section 21.1)
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
        removal, keep = d["removal"], d["keep"]
        other = State(
            {e["name"]: FieldState(e["value"], e["stamp"], e["device"], e["schema"]) for e in d["fields"]},
            removal and Removal(removal["stamp"], removal["device"], removal["stands"]),
            d["state"],
            keep and Keep(keep["stamp"], keep["device"], keep["version"], keep["given_up"]),
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
            held = Held(d["type"], done.state)
            if isinstance(ref, int):
                self.records[key], self.ids[key] = held, rec["id"]
            else:
                self.layers[ref] = held
                self.senders[ref[0]].ids.setdefault(key, rec["id"])
        held.state, self.highest = done.state, done.highest
        if isinstance(ref, int):
            held.sibling_stamp, held.to_pass = done.sibling_stamp, done.to_pass
            self._keep_schemas(done.state)
        else:
            # A layer keeps neither a state stamp seen from a sibling nor a version to pass (section
            # 21.1); the texts of its schemas stay among those of the sender.
            for f in done.state.fields.values():
                if f.schema in texts:
                    self.senders[ref[0]].schemas.setdefault(f.schema, texts[f.schema])
        mine, theirs = self._parts(done.state), self._parts(other)
        if took:
            outcome = "APPLIED"
        else:
            outcome = "DUPLICATE" if theirs <= mine else "STALE"
        # The record is known to the sibling, and every part of the message that the device holds is
        # delivered to it (section 10.1, event 2).
        kept = self.kept.setdefault((sender, ref), Kept())
        kept.known = True
        kept.delivered = (kept.delivered | theirs) & mine
        # Every part of its state for which the message carried another, earlier one is due for that
        # sibling again, whatever the outcome: a reason to send (sections 8.4 and 10.3).
        names = {p[0] for p in theirs - mine if isinstance(p, tuple)}
        again: set[Any] = {p for p in mine if (isinstance(p, Removal) and other.removal not in (None, p))}
        again |= {p for p in mine if (isinstance(p, Keep) and other.keep not in (None, p))}
        again |= {p for p in mine if isinstance(p, tuple) and p[0] in names}
        if again:
            kept.delivered -= again
            kept.want = True
        if d["whole"] and held.incomplete:
            held.incomplete = False  # a whole CHANGE completes the record (section 8.4)
            for sibling in self.siblings:
                waiting = self.kept.setdefault((sibling, ref), Kept())
                if waiting.barred:
                    waiting.barred, waiting.want = False, True
        if took and not isinstance(ref, int):
            self._layer_moved(ref)
            self._later_ack(ref)
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
        self._due_for(ref, mine - before, but=sender)
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
            if key in self.forwards[sender] and entry["version"] == 1:
                # The outcome of a forward: it settles the forward and delivers its kept message, if the
                # device still keeps it (sections 18.4 and 20.2).
                h, _, _, serial = self.forwards[sender].pop(key)
                if h in self._kept_hashes():
                    self.fdelivered[sender].add(h)
                removal = self._removal_of(h)
                if removal is not None:
                    self._refused_again(sender, removal)  # the sibling now has the removal (section 20.2)
                # An outcome of the sibling for a forward of the sender, APPLIED or DUPLICATE: a layer that
                # waited goes, unless it got RECORD_UNKNOWN twice in a row (section 21.5).
                for (s, ref), kept in self.kept.items():
                    if s == sender and kept.waiting and not isinstance(ref, int) and ref[0] == serial:
                        if kept.unknowns < 2:
                            kept.waiting, kept.want = False, True
                taken += 1
                continue
            if name not in self.sent[sender]:
                continue  # no CHANGE to that sibling that it still keeps
            marks, _, ref = self.sent[sender].pop(name)  # the first outcome stands
            held, kept = self._held(ref), self.kept[(sender, ref)]
            assert held is not None
            kept.known, kept.unknowns = True, 0
            kept.delivered |= self._parts(held.state) & marks  # only what the state still holds exactly
            self.highest = max(self.highest, entry["receiver_version"])
            if isinstance(ref, int):
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
        if rec is not None and key in self.forwards[sender] and rec["version"] == 1:
            # About a forward that it still keeps (section 18.4).
            h = self.forwards[sender][key][0]
            signer = self._signer_of(h)
            if code == "FORMAT_UNSUPPORTED" and d["fingerprint"] == SPEC_FP["Envelope"]:
                self.fgone[sender].discard(h)  # again in the chosen format: the same message
            elif code == "NOT_ACCEPTED" and signer in self.facked[sender] and h not in self.fretried[sender]:
                # After the device acknowledged the sibling's removal of that key: due again, once.
                del self.forwards[sender][key]
                self.fretried[sender].add(h)
                self.fgone[sender].discard(h)
            else:
                if code == "NOT_ACCEPTED":
                    self.frefused[sender].add(h)
                del self.forwards[sender][key]  # settled: that forward is not sent again
                self.fsettled[sender].add(h)
            return self._send_due()
        if rec is None or key is None or (key, rec["version"]) not in self.sent[sender]:
            return []  # logged, and changes nothing
        ref = self.sent[sender][(key, rec["version"])][2]
        held, kept = self._held(ref), self.kept[(sender, ref)]
        assert held is not None
        if code == "SCHEMA_UNKNOWN":
            # The schema is offered again, also when an accepted offer of it stood; the message goes
            # again once it is accepted, or at once if the error names no fingerprint.
            if d["fingerprint"] is not None:
                self.accepted[sender].discard(d["fingerprint"])
                self.pending[sender] = {
                    k: v for k, v in self.pending[sender].items() if v[0] != d["fingerprint"]
                }
            kept.want = True
        elif code == "RECORD_UNKNOWN" and not isinstance(ref, int):
            # For an owner's layer (section 21.5): the layer is not known to the sibling, every kept
            # message of the record's sender is forwarded again, and the layer waits.
            kept.known, kept.delivered, kept.want, kept.waiting = False, set(), True, True
            kept.unknowns += 1
            for raw, _ in self.senders[ref[0]].kept():
                self._undeliver(sender, raw)
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
        self.left[sender] = set(self._refs())
        for key in self._refs():
            kept = self.kept.setdefault((sender, key), Kept())
            kept.known, kept.delivered, kept.want, kept.fresh = False, set(), True, True
            kept.flight, kept.settled, kept.waiting, kept.unknowns = None, None, False, 0
        # What it kept for that sibling about the messages of other apps is forgotten as well, and its
        # answer begins with a new forward of every kept message (section 20.4).
        self.fdelivered[sender], self.fsettled[sender], self.fgone[sender] = set(), set(), set()
        self.forwards[sender], self.fanswer[sender] = {}, True
        self.fremovals[sender], self.facked[sender] = set(), set()
        self.frefused[sender], self.fretried[sender] = set(), set()
        self.what = "acted on"
        return self._send_due()

    def _offer(self, sender: bytes, d: dict[str, Any]) -> list[bytes]:
        """An offer of a sibling: valid by spec/protocol.md, section 4.2, or rejected; every type of a
        valid one is accepted (section 7.2)."""
        names, texts = list[str](), dict[bytes, str]()
        if uuid_key(d["offer_id"]) is None or not 1 <= len(d["types"]) <= MAX_OFFER_TYPES:
            raise Reject("OFFER_INVALID", "the id of the offer, or the number of its types")
        declined: list[str] = []
        for t in d["types"]:
            if t["count"] < 0:
                raise Reject("OFFER_INVALID", "a count below 0")
            brick, b = fe.kind_of(t["description"])
            if brick != "axt.ObjectField":
                raise Reject("OFFER_INVALID", "a description whose root is not an object")
            if fe.description_problems(t["description"]):
                declined.append(b["name"])  # spec/fields.md, section 10.1
                continue
            text = fe.register(t["description"])
            names.append(b["name"])
            texts[schema_fingerprint(text)] = text
        if declined:
            if len(set(declined + names)) != len(declined + names) or len(texts) != len(names):
                raise Reject("OFFER_INVALID", "a full name or a fingerprint twice")
            self.what = "declined"
            reasons = [{"type": n, "reason": "DESCRIPTION_INVALID"} for n in declined]
            out = [
                message(
                    self.seed,
                    "DECLINE",
                    None,
                    body_of("Decline", {"to": sender, "offer_id": d["offer_id"], "types": reasons}),
                )
            ]
            if names:
                out.insert(
                    0,
                    message(
                        self.seed,
                        "ACCEPT",
                        None,
                        body_of("Accept", {"to": sender, "offer_id": d["offer_id"], "types": names}),
                    ),
                )
            for fp, text in texts.items():
                self.offered[sender][fp] = self.schema(fp) or text
            return out
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

    # --- the senders a device knows when a session begins, or in a backup ---

    def know(self, v: dict[str, Any], bytes_in: Callable[[Any], bytes] = bytes.fromhex) -> None:
        """A known sender in the form of spec/conformance.md, section 5.14: its keys, its kept messages
        with the siblings each is delivered to, and the owner's layers of its records."""
        sender = self._new_sender(bytes.fromhex(v["origin"]))
        if v.get("known_by", "user") != "user":
            sender.known_by = {bytes.fromhex(k) for k in v["known_by"]}
        known = self._keys(sender)
        known.current[:] = [bytes.fromhex(k) for k in v["current"]]
        known.removed[:] = [bytes.fromhex(k) for k in v["removed"]]
        for group in ("chain", "manifests", "records"):
            for item in v[group]:
                raw = bytes_in(item["message"])
                envelope = read_all("Envelope", raw[10:])
                for sibling in item["delivered"]:
                    self.fdelivered[bytes.fromhex(sibling)].add(sha(raw))
                if group == "chain":
                    sender.chain.append(raw)
                elif group == "manifests":
                    revision = read_all("Manifest", envelope["body"][10:])["revision"]
                    sender.manifests[envelope["sender"]] = (revision, raw)
                else:
                    rec, text = envelope["record"], item["schema"]
                    key = uuid_key(rec["id"])
                    assert key is not None
                    schema = None if text is None else json.loads(text)
                    values = {} if schema is None else record_values(schema, envelope["body"])
                    name = item["type"] if schema is None else full_name(schema)
                    self._keep_record(sender, key, rec, envelope["kind"], name, raw, text, values)
        for item in v.get("proposals", []):
            raw = bytes_in(item["message"])
            envelope = read_all("Envelope", raw[10:])
            d = read_all("Proposal", envelope["body"][10:])
            for sibling in item["delivered"]:
                self.fdelivered[bytes.fromhex(sibling)].add(sha(raw))
            record_key = uuid_key(envelope["record"]["id"])
            assert record_key is not None
            sender.proposals[uuid_key(d["proposal_id"]) or 0] = (raw, record_key, 0, True)
        for item in v["layers"]:
            state, key = state_of_json(item["state"]), uuid_key(item["id"])
            assert state is not None and key is not None
            ref = (sender.serial, key)
            self.layers[ref] = Held(item["type"], state)
            sender.ids.setdefault(key, item["id"])
            for sibling, s in item["siblings"].items():
                parts: set[Any] = {(name, state.fields[name]) for name in s["delivered"]}
                if s["removal"]:
                    assert state.removal is not None
                    parts.add(state.removal)
                if s["keep"]:
                    assert state.keep is not None
                    parts.add(state.keep)
                want = not s["known"] or parts != self._parts(state)
                self.kept[(bytes.fromhex(sibling), ref)] = Kept(s["known"], parts, want=want)

    def _keep_record(
        self,
        sender: Sender,
        key: int,
        rec: dict[str, Any],
        kind: str,
        name: str | None,
        raw: bytes,
        text: str | None,
        values: dict[str, bytes],
    ) -> None:
        """The message becomes the sender's layer of the record and its kept message (sections 19.5
        and 20.1): a DATA makes the record there, with the full name of its schema as its type, and a
        DELETE leaves a tombstone, which keeps the type the record had."""
        old = sender.records.get(key)
        if kind in ("DELETE", "WITHDRAW") and name is None:
            name = old.type if old else None
        # A DELETE keeps beside the tombstone the DATA with the highest version below it that the device
        # took; a DATA has nothing beside it.
        beside = None if kind == "DATA" or old is None else (old if old.there else old.beside)
        sender.records[key] = Received(name, rec["version"], kind == "DATA", raw, text, values, beside)
        sender.ids.setdefault(key, rec["id"])
        if text is not None:
            sender.schemas.setdefault(schema_fingerprint(text), text)

    # --- a FORWARD of a sibling (sections 18 and 19) ---

    def _forward(
        self, sender: bytes, rec: dict[str, Any], d: dict[str, Any]
    ) -> tuple[str | None, list[bytes]]:
        """Steps 4 to 16 of section 18.3."""
        if uuid_key(rec["id"]) is None:
            raise Reject("RECORD_ID_INVALID")  # step 4
        if rec["version"] < 1:
            raise Reject("VERSION_INVALID")  # step 5
        if rec["version"] != 1:
            raise Reject("INVALID_MESSAGE", "the version of a forward is 1")  # step 6
        inner, schema = inner_message(d)  # steps 7 to 11
        raw: bytes = d["message"]
        signer: bytes = inner["sender"]
        if keys.verify_problem(signer, keys.MESSAGE_PREFIX + raw[10:-64], raw[-64:]) is not None:
            raise Reject("SIGNATURE_INVALID", "the signature of the message inside")  # step 12
        kind = inner["kind"]
        if kind == keys.REMOVE:
            # The sibling has forwarded a removal of that key, whatever the device then does with it.
            try:
                self.fremovals[sender].add(read_all("DeviceRemove", inner["body"][10:])["device"])
            except ValueError:
                pass
        if signer == self.key or signer in self.siblings or signer in self.removed:
            raise Reject("INVALID_MESSAGE", "a message of the device's own set")  # step 13
        named = [signer]
        if kind in (keys.ADD, keys.REMOVE):
            try:
                named.append(read_all(INNER_BODY[kind], inner["body"][10:])["device"])
            except ValueError:
                pass
        before = set(self.senders)
        outcome, sent = self._forward_known(sender, rec, d, inner, schema, raw, signer, kind, named)
        # A sender that a forward made known is known by forwards of that sibling; each sibling that
        # forwards a message of a sender known by forwards is one more (section 19.2).
        for serial in set(self.senders) - before:
            self.senders[serial].known_by = {sender}
        of = self._sender_of(signer)
        if of is not None and of.known_by is not None:
            of.known_by.add(sender)
        return outcome, sent

    def _forward_known(
        self,
        sender: bytes,
        rec: dict[str, Any],
        d: dict[str, Any],
        inner: dict[str, Any],
        schema: dict[str, Any] | None,
        raw: bytes,
        signer: bytes,
        kind: str,
        named: list[bytes],
    ) -> tuple[str | None, list[bytes]]:
        """A forgotten key that the inner message names makes its sender known again (section 20.5)."""
        back = next((f for f in self.forgotten if set(named) & set(f[1])), None)
        if back is not None:
            # A forgotten key: the sender is known again, on the word of the sibling (section 20.5); if a
            # later step fails, it stays forgotten.
            state = (copy.deepcopy(self.book), dict(self.senders), self.serial, list(self.forgotten))
            self.forgotten.remove(back)
            for k in back[2]:
                if k in self.book.refused:
                    self.book.refused.remove(k)
            self.serial += 1
            self.book.senders.append(keys.KnownSender(str(self.serial), list(back[1]), list(back[2])))
            self.senders[self.serial] = Sender(self.serial, back[0])
            try:
                outcome, sent = self._forward_inner(sender, rec, d, inner, schema, raw, signer, kind)
            except Reject:
                self.book, self.senders, self.serial, self.forgotten = state
                raise
            return outcome, sent + self._ask(sender)  # it MUST ask that sibling for everything again
        return self._forward_inner(sender, rec, d, inner, schema, raw, signer, kind)

    def _forward_inner(
        self,
        sender: bytes,
        rec: dict[str, Any],
        d: dict[str, Any],
        inner: dict[str, Any],
        schema: dict[str, Any] | None,
        raw: bytes,
        signer: bytes,
        kind: str,
    ) -> tuple[str | None, list[bytes]]:
        """Steps 14 to 16 of section 18.3."""
        if signer in self.book.refused and kind not in (keys.ADD, keys.REMOVE):
            raise Reject("NOT_ACCEPTED", "a refused key")  # step 14
        of = self._sender_of(signer)
        if kind in RECORD_MESSAGES and of is not None and signer in self._keys(of).removed:
            if not self._has_removal(sender, of, signer):
                # Step 14: the sibling has not shown that it has the removal (section 19.2).
                raise Reject("NOT_ACCEPTED", "a removed key whose removal the sibling has not shown to have")
        # step 15: the rules of its kind
        if kind in (keys.ADD, keys.REMOVE):
            took = self._chain_message(kind, signer, inner["body"], raw, True, sender)
        elif kind == "MANIFEST":
            took = self._manifest_of(signer, inner["body"], raw, sender, False)
        elif kind == "PROPOSAL":
            took = self._forwarded_proposal(signer, inner, raw)
        else:
            took = self._forwarded_record(signer, inner, schema, d["schema"], raw, sender)
        outcome = "APPLIED" if took else "DUPLICATE"  # step 16 and section 18.4
        if kind == keys.REMOVE:
            removed = read_all("DeviceRemove", inner["body"][10:])["device"]
            self.facked[sender].add(removed)
            # The removal that the sibling now has: what NOT_ACCEPTED had settled is due again, after the
            # acknowledgement of this forward (section 20.2).
            self.after_acks += [(sender, removed)]
        if sha(raw) in self._kept_hashes():
            # The device keeps exactly these bytes, so they are delivered to that sibling and do not go
            # back to it (section 20.2, event 2).
            self.fdelivered[sender].add(sha(raw))
        self.acks[sender].append(self._request_entry(rec["id"], outcome))
        self.what = outcome
        return outcome, self._send_due()

    def _has_removal(self, sibling: bytes, sender: Sender, key: bytes) -> bool:
        """Whether the sibling has the removal of that key (section 19.2): the device's kept removal of it
        is delivered to the sibling, or the sibling has forwarded it one whose signature verified."""
        if key in self.fremovals[sibling]:
            return True
        return any(
            self._removal_of(sha(m)) == key and sha(m) in self.fdelivered[sibling] for m in sender.chain
        )

    def _kept_by_hash(self, h: bytes) -> bytes | None:
        for sender in self.senders.values():
            for m, _ in sender.kept():
                if sha(m) == h:
                    return m
        return None

    def _removal_of(self, h: bytes) -> bytes | None:
        """The key that a kept DEVICE_REMOVE with that hash removes, or None."""
        m = self._kept_by_hash(h)
        if m is None:
            return None
        envelope = read_all("Envelope", m[10:])
        if envelope["kind"] != keys.REMOVE:
            return None
        device: bytes = read_all("DeviceRemove", envelope["body"][10:])["device"]
        return device

    def _signer_of(self, h: bytes) -> bytes | None:
        m = self._kept_by_hash(h)
        return None if m is None else bytes(read_all("Envelope", m[10:])["sender"])

    def _refused_again(self, sibling: bytes, key: bytes) -> None:
        """The kept record messages signed with that key for which NOT_ACCEPTED of the sibling had settled
        a forward are due for it again (section 20.2)."""
        for h in list(self.frefused[sibling]):
            if self._signer_of(h) == key:
                self.frefused[sibling].discard(h)
                self.fsettled[sibling].discard(h)
                self.fgone[sibling].discard(h)

    def _chain_message(
        self, kind: str, signer: bytes, body: bytes, raw: bytes, forwarded: bool, sibling: bytes | None = None
    ) -> bool:
        """A DEVICE_ADD or a DEVICE_REMOVE of another app by the steps of spec/keys.md, section 5.5, and
        for a forwarded one with the differences of section 19.3. Whether the device applied it, or
        keeps a forwarded removal to try it again."""
        try:
            d = read_all(INNER_BODY[kind], body[10:])
        except ValueError as e:
            raise Reject("INVALID_MESSAGE", str(e)) from None
        device: bytes = d["device"]
        signed = keys.MESSAGE_PREFIX + raw[10:-64]
        if keys.device_message_problem(kind, signer, signed, raw[-64:], device, d.get("proof")) is not None:
            raise Reject("DEVICE_REJECTED", "step 2 of spec/keys.md, section 5.5")
        # In a forwarded addition or removal a refused key counts as a key of no known sender, and stops
        # being refused when the message is applied or kept (section 19.3).
        was_refused = [k for k in (signer, device) if forwarded and k in self.book.refused]
        for k in was_refused:
            self.book.refused.remove(k)
        before = {s.name for s in self.book.senders}
        result = self.book.place(kind, signer, device)
        fresh = None
        if result == keys.NOT_PLACED and forwarded:
            # No forwarded addition or removal "cannot be placed": the signer becomes the first key of a
            # new known sender, and the table decides.
            fresh = keys.KnownSender(str(self.serial + 1), [signer])
            self.book.senders.append(fresh)
            result = self.book.place(kind, signer, device)
        if result == keys.REJECTED and forwarded and self._signer_removed(kind, signer, device):
            # A chain out of order: kept and tried again like a kept removal (section 19.3).
            self.early.append((raw, signer, device, kind, sibling))
            return True
        if result in (keys.REJECTED, keys.NOT_PLACED, keys.REFUSED):
            if fresh is not None:
                self.book.senders.remove(fresh)  # a step that fails changes nothing (section 18.3)
            self.book.refused += was_refused
            raise Reject("DEVICE_REJECTED", "the table of spec/keys.md, section 5.5")
        self._follow(before)
        sender = self._sender_of(signer)
        assert sender is not None
        if result == keys.APPLIED:
            self._applied(sender, kind, device, raw)
            return True
        early = kind == keys.REMOVE and signer in self._keys(sender).current
        if forwarded and early and self._sender_of(device) is not sender:
            self.early.append((raw, signer, device, kind, sibling))  # kept to be tried again
            return True
        self.book.refused += was_refused
        return False

    def _signer_removed(self, kind: str, signer: bytes, device: bytes) -> bool:
        """Whether the table rejects a DEVICE_ADD only because its signer is a removed key of its sender:
        the column "signer removed", with a device that is a key of no known sender or the only key of
        another known sender (section 19.3)."""
        s, t = self.book.sender_of(signer), self.book.sender_of(device)
        if kind != keys.ADD or s is None or signer not in s.removed or device in self.book.refused:
            return False
        return t is None or (t is not s and t.single())

    def _applied(self, sender: Sender, kind: str, device: bytes, raw: bytes) -> None:
        """An addition or a removal that the device applied is a kept message of its sender (section
        20.1). The kept manifest of a removed key is deleted; after an addition, the removals that the
        device keeps are tried again (section 19.3)."""
        sender.chain.append(raw)
        if kind == keys.REMOVE:
            sender.manifests.pop(device, None)
            sender.live.discard(device)
            return
        again = True
        while again:
            again = False
            for item in list(self.early):
                raw_, signer, device_, kind_, sibling = item
                before = {s.name for s in self.book.senders}
                if self.book.place(kind_, signer, device_) == keys.APPLIED:
                    self.early.remove(item)
                    self._follow(before)
                    of = self._sender_of(signer)
                    assert of is not None
                    of.chain.append(raw_)
                    if kind_ == keys.REMOVE:
                        of.manifests.pop(device_, None)
                    if sibling is not None and sibling in self.fdelivered:
                        # It counts as delivered to the sibling that forwarded it (section 19.3).
                        self.fdelivered[sibling].add(sha(raw_))
                    again = True

    def _follow(self, before: set[str] | None = None) -> None:
        """Bring what the device keeps of each sender in step with their keys: a new known sender, or
        two senders that joined (section 23.4). `before` names the senders before the message."""
        names = {int(k.name): k for k in self.book.senders}
        for serial in sorted(set(names) - set(self.senders)):
            self.serial = max(self.serial, serial)
            self.senders[serial] = Sender(serial, names[serial].current[0])
        for serial in sorted(set(self.senders) - set(names)):
            gone = self.senders.pop(serial)
            (stay,) = [self.senders[n] for n in names if gone.first in names[n].current]
            self._join(stay, gone)

    def _join(self, stay: Sender, gone: Sender) -> None:
        """Two senders join (section 23.4): the kept additions, removals and manifests of the second are
        kept as those of the sender that stays; of a record both hold, the copy with the higher version
        stays, and with equal versions that of the sender that stays; their owner's layers merge, the
        layer of the copy that stays being the device's own state."""
        stay.chain += gone.chain
        stay.manifests.update(gone.manifests)
        stay.live |= gone.live
        for fp, text in gone.schemas.items():
            stay.schemas.setdefault(fp, text)
        for key in sorted(
            set(gone.records) | set(gone.ids) | {r[1] for r in self.layers if r[0] == gone.serial}
        ):
            stay.ids.setdefault(key, gone.ids.get(key, ""))
            mine, theirs = stay.records.get(key), gone.records.get(key)
            if theirs is not None and (mine is None or theirs.version > mine.version):
                stay.records[key] = theirs
            ref, old = (stay.serial, key), (gone.serial, key)
            other = self.layers.pop(old, None)
            for sibling in self.siblings:
                self.kept.pop((sibling, old), None)
            self.later.pop(old, None)
            if other is None:
                continue
            held = self.layers.get(ref)
            own = held.state if held else None
            took = own is None or merge(own, other.state).took
            done = device_merge(own, other.state, self.now_ms, self.highest, self._draw() if took else 0)
            self.highest = done.highest
            if held is None:
                held = self.layers[ref] = Held(other.type, done.state)
            before = self._parts(own) if own else set()
            held.state = done.state
            if took:
                self._due_for(ref, self._parts(done.state) - before)
                self._layer_moved(ref)
        for sibling in self.siblings:
            self.forwards[sibling] = {
                f: (v[0], v[1], v[2], stay.serial if v[3] == gone.serial else v[3])
                for f, v in self.forwards[sibling].items()
            }

    def _manifest_of(self, signer: bytes, body: bytes, raw: bytes, sibling: bytes | None, live: bool) -> bool:
        """A MANIFEST of another app (section 19.4; spec/manifest.md, section 6): whether it becomes the
        kept manifest of its key. One that the app itself sends in a live connection applies whatever
        its revision; every other only with a higher revision than the kept one."""
        try:
            manifest = read_all("Manifest", body[10:])
        except ValueError as e:
            raise Reject("MANIFEST_INVALID", str(e)) from None
        if me.manifest_problems(manifest, len(body)):
            raise Reject("MANIFEST_INVALID", "not valid by spec/manifest.md, section 4")
        sender = self._sender_of(signer)
        if sender is not None and signer in self._keys(sender).removed:
            return False  # a removed key has no kept manifest
        revision: int = manifest["revision"]
        kept = sender.manifests.get(signer) if sender else None
        if kept is not None and (revision == kept[0] if live else revision <= kept[0]):
            if sibling is not None and revision < kept[0]:
                self._undeliver(sibling, kept[1])  # the sibling evidently does not hold the kept one
            return False
        if sibling is not None and sender is not None and signer in sender.live:
            return False  # a forwarded MANIFEST never takes the place of one taken live (section 19.4)
        if sender is None:
            sender = self._new_sender(signer)  # a known sender, without a question (section 19.2)
        sender.manifests[signer] = (revision, raw)
        if live:
            sender.live.add(signer)
        elif sibling is None:
            sender.live.discard(signer)  # a later MANIFEST from the key itself ends the mark
        return True

    def _forwarded_record(
        self,
        signer: bytes,
        inner: dict[str, Any],
        schema: dict[str, Any] | None,
        text: str | None,
        raw: bytes,
        sibling: bytes,
    ) -> bool:
        """A forwarded DATA or DELETE by the steps of section 19.5: whether the device took it into the
        sender's layer. It never changes the owner's layer (section 19.1)."""
        rec, kind = inner["record"], inner["kind"]
        if kind == "WITHDRAW":
            # Before step 2: the body decodes as one axt.Withdraw, and its to is a current or a removed key
            # of the device's own set (section 19.5; spec/shares.md, section 7.1).
            try:
                to = read_all("Withdraw", inner["body"][10:])["to"]
            except ValueError as e:
                raise Reject("INVALID_MESSAGE", f"message: {e}") from None
            if to != self.key and to not in self.siblings and to not in self.removed:
                raise Reject("INVALID_MESSAGE", "a WITHDRAW for a key of no device of the set")
        key = uuid_key(rec["id"])
        if key is None:
            raise Reject("RECORD_ID_INVALID", "the id of the message inside")  # step 2
        if rec["version"] < 1:
            raise Reject("VERSION_INVALID", "the version of the message inside")  # step 3
        sender = self._sender_of(signer)
        held = sender.records.get(key) if sender else None
        layer = self.layers.get((sender.serial, key)) if sender else None
        name = None if schema is None else full_name(schema)
        before = {held.type if held else None, layer.type if layer else None} - {None}
        if kind == "DATA" and before - {name}:
            raise Reject("TYPE_CHANGED", f"{sorted(n for n in before if n)[0]} before, {name} now")  # step 6
        if held is not None and rec["version"] <= held.version:  # step 7
            assert sender is not None
            return self._at_or_below(
                sender, key, held, kind, rec["version"], raw, text, inner["body"], sibling
            )
        values = {} if schema is None else record_values(schema, inner["body"])  # steps 8 and 9
        if sender is None:
            sender = self._new_sender(signer)  # a known sender, without a question (section 19.2)
        self._keep_record(sender, key, rec, kind, name, raw, text, values)  # step 10
        return True

    def _forwarded_proposal(self, signer: bytes, inner: dict[str, Any], raw: bytes) -> bool:
        """A forwarded PROPOSAL (spec/shares.md, section 17.1): the checks of the body, of `to` and of the
        steps 2 to 4 of section 13.3 there, and then whether the device takes it as a new proposal."""
        try:
            d = read_all("Proposal", inner["body"][10:])
        except ValueError as e:
            raise Reject("INVALID_MESSAGE", f"message: {e}") from None
        to = d["to"]
        if to != self.key and to not in self.siblings and to not in self.removed:
            raise Reject("INVALID_MESSAGE", "a PROPOSAL for a key of no device of the set")
        rec = inner["record"]
        key = uuid_key(rec["id"])
        if key is None:
            raise Reject("RECORD_ID_INVALID", "the id of the message inside")
        if rec["version"] < 1:
            raise Reject("VERSION_INVALID", "the version of the message inside")
        problem = proposal_problem(d)
        if problem is not None:
            raise Reject("INVALID_MESSAGE", problem)
        sender = self._sender_of(signer)
        if sender is not None and signer in self._keys(sender).removed:
            return False  # not taken, as a forwarded MANIFEST of such a key
        if sender is None:
            sender = self._new_sender(signer)  # a known sender, without a question (section 19.2)
        return self._keep_proposal(sender, uuid_key(d["proposal_id"]) or 0, raw, key)

    def _keep_proposal(self, sender: Sender, pid: int, raw: bytes, key: int) -> bool:
        """Section 13.4 of spec/shares.md, without a reply: whether the device takes the proposal as new."""
        if (sender.serial, pid) in self.answers or self._stopped(sender, key):
            return False
        held = sender.proposals.get(pid)
        if held is not None:
            # A repeat in other bytes: the one with the higher SHA-256 stands (section 13.4 there).
            if raw == held[0] or sha(raw) < sha(held[0]):
                return False
            sender.proposals[pid] = (raw, key, held[2], held[3])
            return True
        sender.proposals[pid] = (raw, key, self.day, self._shows(sender, key))
        return True

    def _stopped(self, sender: Sender, key: int) -> bool:
        """Whether the app's records hold the proposals of the sender as stopped for the record
        (spec/shares.md, section 18.4)."""
        return (sender.serial, key) in self.stopped or (sender.serial, None) in self.stopped

    def _shows(self, sender: Sender, key: int) -> bool:
        """Whether the device shows a proposal of the sender about the record of the set with that id: the
        record is there on it and shared with the proposer (spec/shares.md, section 17.1)."""
        held = self.records.get(key)
        there = held is not None and not deleted(held.state.fields, held.state.removal)
        return there and sender.serial in self.shares.get(key, set())

    def _tidy_proposals(self) -> None:
        """The kept proposals that end (spec/shares.md, section 17.1): one that the device showed and no
        longer shows, because a change deleted the record or took it out of the shares for the proposer;
        one that it never showed, 14 days after it took it. One that it did not show and shows now is
        shown from now on."""
        for sender in self.senders.values():
            for pid, (raw, key, day, shown_then) in list(sender.proposals.items()):
                now = self._shows(sender, key)
                signer = read_all("Envelope", raw[10:])["sender"]
                if signer not in self._keys(sender).current or self._stopped(sender, key):
                    del sender.proposals[pid]  # the signer is removed, or the receiver is stopped
                elif shown_then and not now:
                    del sender.proposals[pid]
                elif not shown_then and now:
                    sender.proposals[pid] = (raw, key, day, True)
                elif not now and self.day - day >= PROPOSAL_DAYS:
                    del sender.proposals[pid]

    def take_proposal(self, m: bytes, sender: Sender) -> tuple[dict[str, Any], list[bytes]]:
        """A PROPOSAL that the proposer sent the device itself and that passed the steps 1 to 9 of
        spec/shares.md, section 13.3: step 10 (section 13.4 there)."""
        envelope = read_all("Envelope", m[10:])
        d, rec = read_all("Proposal", envelope["body"][10:]), envelope["record"]
        pid, key = uuid_key(d["proposal_id"]) or 0, uuid_key(rec["id"])
        assert key is not None
        answer = self.answers.get((sender.serial, pid))
        if answer is not None:
            # A repeat of an answered proposal: the reply again, to the key that signed the repeat.
            body = body_of(
                "ProposalReply", {"to": envelope["sender"], "proposal_id": d["proposal_id"], "answer": answer}
            )
            # The reply carries the proposal's record, which the app stores with the answer (section 15.1).
            stored = self.answered_records.get((sender.serial, pid), (str(rec["id"]), rec["version"]))
            reply = message(self.seed, "PROPOSAL_REPLY", stored, body)
            return {"taken": False}, [reply, *self._send_due()]
        return {"taken": self._keep_proposal(sender, pid, m, key)}, self._send_due()

    def _proposal_of(self, key: bytes, proposal_id: str) -> tuple[Sender, int, bytes]:
        sender = self._sender_of(key)
        assert sender is not None, "a known sender"
        pid = uuid_key(proposal_id) or 0
        return sender, pid, sender.proposals[pid][0]

    def answer_proposal(self, key: bytes, proposal_id: str, answer: str) -> tuple[bool, list[bytes]]:
        """The user answers on this device a proposal that it shows (spec/shares.md, sections 15 and 17.1):
        the device records the answer, drops the kept PROPOSAL, sends the reply to the key that signed it,
        if that key is not removed, and for ACCEPTED makes the proposed values one change of section 3.5.
        It draws two random parts."""
        sender, pid, raw = self._proposal_of(key, proposal_id)
        envelope = read_all("Envelope", raw[10:])
        d, rec = read_all("Proposal", envelope["body"][10:]), envelope["record"]
        record_key = sender.proposals[pid][1]
        assert self._shows(sender, record_key), "the user answers a proposal that the device shows"
        sent: list[bytes] = []
        r = (self._draw(), self._draw())
        if answer == "ACCEPTED":
            held = self.records[record_key]
            if not all(self._can_show(held.type, f) for f in d["fields"]):
                return False, []  # every proposed value shown, or no ACCEPTED (section 15.1 there)
            # Every proposed field is stamped, also one whose value the record holds already (section 15.2).
            values = {f["name"]: (f["value"], f["schema"]) for f in d["fields"]}
            if values:
                first_schema = next(iter(values.values()))[1]
                done = change(
                    held.state,
                    self.key,
                    "set",
                    {n: v for n, (v, _) in values.items()},
                    self.now_ms,
                    self.highest,
                    r,
                    first_schema,
                    None,
                    held.to_pass,
                )
                if not done.made or done.state is None:
                    return False, []  # no stamp, no ACCEPTED (section 15.2 there)
                fields = dict(done.state.fields)
                for n, (_, fp) in values.items():
                    fields[n] = dataclasses.replace(fields[n], schema=fp)
                state = dataclasses.replace(done.state, fields=fields)
                before = self._parts(held.state)
                held.state, held.to_pass, self.highest = state, done.to_pass, done.highest
                self._due_for(record_key, self._parts(state) - before)
        self.answers[(sender.serial, pid)] = answer
        self.answered_records[(sender.serial, pid)] = (str(rec["id"]), rec["version"])
        del sender.proposals[pid]
        signer = envelope["sender"]
        if signer in self._keys(sender).current:
            body = body_of("ProposalReply", {"to": signer, "proposal_id": d["proposal_id"], "answer": answer})
            sent.append(message(self.seed, "PROPOSAL_REPLY", (rec["id"], rec["version"]), body))
        return True, sent + self._send_due()

    def _can_show(self, type_name: str, f: dict[str, Any]) -> bool:
        """Whether the device can show a proposed value: it holds the schema of the entry, the value decodes
        with it, and a schema of the type that the device holds has the field (spec/shares.md, 15.1)."""
        text = self.schemas.get(f["schema"])
        if text is None:
            return False
        try:
            read_field(json.loads(text), f["name"], io.BytesIO(f["value"]))
        except (ValueError, AssertionError):
            return False
        return any(
            full_name(json.loads(t)) == type_name and field_schema(json.loads(t), f["name"]) is not None
            for t in self.schemas.values()
        )

    def stop(self, key: bytes, rid: str | None) -> list[bytes]:
        """The app's records come to hold the proposals of the sender as stopped, for the record with the id
        or for all records (spec/shares.md, section 18.4): the device drops what they stop."""
        sender = self._sender_of(key)
        assert sender is not None, "a known sender"
        self.stopped.add((sender.serial, None if rid is None else uuid_key(rid)))
        return self._send_due()

    def answered_proposal(self, key: bytes, proposal_id: str, answer: str) -> list[bytes]:
        """The answer to a proposal reaches the device in the app's own records, from a sibling: it drops
        the kept PROPOSAL and sends no reply (spec/shares.md, section 17.1)."""
        sender = self._sender_of(key)
        assert sender is not None, "a known sender"
        pid = uuid_key(proposal_id) or 0
        if self.answers.get((sender.serial, pid)) != "ACCEPTED":
            self.answers[(sender.serial, pid)] = answer  # of two answers, ACCEPTED stands (section 15.1)
        sender.proposals.pop(pid, None)
        return self._send_due()

    def share(self, rid: str, key: bytes, shared: bool) -> list[bytes]:
        """The app's share records change on the device: the record is shared with the sender that has the
        key, or no longer."""
        sender, record_key = self._sender_of(key), uuid_key(rid)
        assert sender is not None and record_key is not None
        serials = self.shares.setdefault(record_key, set())
        if shared:
            serials.add(sender.serial)
        else:
            serials.discard(sender.serial)
        return self._send_due()

    def query_proposals(self, key: bytes) -> dict[str, Any]:
        """The proposals of the sender that has the key that the device keeps, and the answers the app's
        records hold to its proposals."""
        sender = self._sender_of(key)
        assert sender is not None, "a known sender"
        kept = []
        for pid in sorted(sender.proposals):
            raw, record_key, _, _ = sender.proposals[pid]
            d = read_all("Proposal", read_all("Envelope", raw[10:])["body"][10:])
            kept.append(
                {
                    "proposal_id": d["proposal_id"],
                    "id": self.ids.get(record_key) or str(read_all("Envelope", raw[10:])["record"]["id"]),
                    "message_hash": sha(raw).hex(),
                    "shown": self._shows(sender, record_key),
                }
            )
        answers = sorted((pid, a) for (serial, pid), a in self.answers.items() if serial == sender.serial)
        return {
            "proposals": kept,
            "answers": [{"proposal_id": _uuid_text(pid), "answer": a} for pid, a in answers],
        }

    def _at_or_below(
        self,
        sender: Sender,
        key: int,
        held: Received,
        kind: str,
        version: int,
        raw: bytes,
        text: str | None,
        body: bytes,
        sibling: bytes | None,
    ) -> bool:
        """Step 7 of section 19.5 for a record message whose version is equal to or below the receiver's
        version, in a FORWARD of `sibling` or, without one, from the sender itself: whether the device
        takes it all the same, by one of the five cases, after the steps 8 and 9. A message of the sender
        itself that fails those steps is not taken; a forwarded one is rejected."""
        schema = None if text is None else json.loads(text)
        name = None if schema is None else full_name(schema)
        beside = held.beside
        case = None
        if version < held.version:
            if kind == "DATA" and not held.there:
                if beside is None or beside.version < version:
                    case = 1  # a DATA below the tombstone goes beside it
                elif beside.version == version and raw != beside.message and stands_over(raw, text, beside):
                    case = 4  # the DATA beside the tombstone in other bytes
                elif sibling is not None and version < beside.version:
                    self._undeliver(
                        sibling, beside.message
                    )  # an older message: only that DATA (section 20.2)
            elif sibling is not None:
                self._undeliver(sibling, held.message)  # an older message from the sibling (section 20.2)
        elif kind == "DELETE" and held.there:
            case = 3  # a DELETE stands over a DATA of the same version
        elif kind == "WITHDRAW" and kind_of(held.message) != "WITHDRAW":
            case = 5  # a WITHDRAW stands over a DATA or a DELETE of the same version
        elif kind == kind_of(held.message) and raw != held.message and stands_over(raw, text, held):
            case = 2  # the kept message in other bytes
        if case is None:
            return False
        try:
            values = {} if schema is None else record_values(schema, body)  # steps 8 and 9
        except Reject:
            if sibling is not None:
                raise
            return False
        if text is not None:
            sender.schemas.setdefault(schema_fingerprint(text), text)
        if case in (1, 4):
            held.beside = Received(name, version, True, raw, text, values)
        elif case == 3:
            sender.records[key] = Received(held.type, version, False, raw, None, {}, None)
        elif case == 5:
            # In the place of a DATA, that DATA stays beside the tombstone of the withdrawal; in the place of
            # a DELETE, the DATA beside its tombstone does.
            beside_now = held if held.there else held.beside
            sender.records[key] = Received(held.type, version, False, raw, None, {}, beside_now)
        else:
            self._replace_record(sender, key, raw, text, values)
        return True

    def _replace_record(
        self, sender: Sender, key: int, raw: bytes, text: str | None, values: dict[str, bytes]
    ) -> None:
        """A record message with the receiver's version in other bytes that stand over the kept ones takes
        their place, with its schema and its values (section 20.1)."""
        old = sender.records[key]
        sender.records[key] = dataclasses.replace(old, message=raw, schema=text, values=values)
        if text is not None:
            sender.schemas.setdefault(schema_fingerprint(text), text)

    # --- the answering device (sections 17.2, 22.2 and 24.2) ---

    def take(self, m: bytes, text: str | None, file: bool = False) -> tuple[dict[str, Any], list[bytes]]:
        """A message of another app that reaches the device from that app itself, in a live connection
        or, with `file`, in a file of that app, after the checks of spec/protocol.md and
        spec/transports.md; `text` is the writer schema of a DATA. What the device did with it, and
        what it sends its siblings; the outcome it owes the other app goes with `flush_acks`."""
        envelope = read_all("Envelope", m[10:])
        signer, kind, rec, body = envelope["sender"], envelope["kind"], envelope["record"], envelope["body"]
        if kind in (keys.ADD, keys.REMOVE):
            try:
                applied = self._chain_message(kind, signer, body, m, False)
            except Reject:
                applied = False
            return {"taken": applied}, self._send_due()
        sender = self._sender_of(signer)
        assert sender is not None and signer in self._keys(sender).current, "a current key of a known sender"
        if kind == "MANIFEST":
            return {"taken": self._manifest_of(signer, body, m, None, not file)}, self._send_due()
        if kind == "PROPOSAL":
            assert not file, "no file holds a PROPOSAL (spec/shares.md, section 18.2)"
            return self.take_proposal(m, sender)
        assert kind in RECORD_MESSAGES, kind
        key, version = uuid_key(rec["id"]), rec["version"]
        assert key is not None and version >= 1
        held, ref = sender.records.get(key), (sender.serial, key)
        kept_fields: list[str] = []
        if held is not None and version <= held.version:
            outcome = "DUPLICATE" if version == held.version else "STALE"  # spec/records.md, section 5.2
            # The five cases of section 19.5, step 7, hold from the sender itself as well; the outcome is
            # that of the version rule.
            case5 = kind == "WITHDRAW" and version == held.version and kind_of(held.message) != "WITHDRAW"
            self._at_or_below(sender, key, held, kind, version, m, text, body, None)
            if case5:
                # Case 5: the device decides on the owner's changes as for a WITHDRAW with a higher version;
                # the outcome stays DUPLICATE (section 22.2; spec/shares.md, section 6.3).
                layer = self.layers.get(ref)
                own = layer.state if layer else None
                self._owner_decides(ref, sender.records[key], own, self.on_withdraw)
        else:
            schema = None if text is None else json.loads(text)
            values = {} if schema is None else record_values(schema, body)
            fp = None if text is None else schema_fingerprint(text)
            layer = self.layers.get(ref)
            texts = dict(sender.schemas)
            if fp is not None and text is not None:
                texts[fp] = text
            name = None if schema is None else full_name(schema)
            own = layer.state if layer else None
            self.later.pop(ref, None)  # a later message of the sender: no further ACK for an earlier one
            if kind == "DATA":
                # The message goes into the sender's layer and changes nothing in the owner's layer.
                outcome, kept_fields = answered(kind, values, fp, own, texts)
                self._keep_record(sender, key, rec, kind, name, m, text, values)
            else:
                # A DELETE (section 22.2), or a WITHDRAW by the same rows with WITHDRAWN in the place of
                # APPLIED (spec/shares.md, section 7.1): the record is kept against it, or the layer is
                # tidied.
                self._keep_record(sender, key, rec, kind, name, m, text, values)
                outcome = "WITHDRAWN" if kind == "WITHDRAW" else "APPLIED"
                choice = self.on_withdraw if kind == "WITHDRAW" else self.on_delete
                if self._owner_decides(ref, sender.records[key], own, choice):
                    outcome = "KEPT"
            if outcome == "KEPT":
                self.later[ref] = (signer, rec["id"], version, kind)
        if not file:
            entry = {
                "id": rec["id"],
                "version": version,
                "outcome": outcome,
                "receiver_version": sender.records[key].version,
                "kept_fields": kept_fields,
            }
            self.app_acks.setdefault(signer, []).append(entry)
        return {"outcome": outcome, "kept_fields": kept_fields}, self._send_due()

    def _owner_decides(self, ref: tuple[int, int], rec: "Received", own: State | None, choice: str) -> bool:
        """What the answering device does with the owner's changes when a DELETE or a WITHDRAW meets them
        (section 22.2): it sets a keep, or tidies the layer. Whether it set the keep."""
        mine = owner_values(own)
        if not mine or owner_deleted(own):
            return False
        if choice in ("keep", "ask") and rec.beside is not None:
            return self._layer_step(ref, "keep", {})
        self._layer_step(ref, "discard", dict.fromkeys(mine, b""))  # tidying the layer
        return False

    def _layer_moved(self, ref: tuple[int, int]) -> None:
        """A change or a merge has given an owner's layer a new state stamp: a layer that waited for a
        sibling goes again (section 21.5)."""
        for sibling in self.siblings:
            kept = self.kept.setdefault((sibling, ref), Kept())
            if kept.waiting:
                kept.waiting, kept.want, kept.unknowns = False, True, 0

    # --- what its user does to a received record (section 21.2) ---

    def layer_change(
        self, signer: bytes, rid: str, action: str, values: dict[str, bytes]
    ) -> tuple[bool, list[bytes]]:
        """A change of the user to a record of the sender that has the key `signer`: "set", with the
        values it gives; "discard", for the fields named in `values`; "delete"; "take_back"; "keep", a
        keep against the sender's deletion with the version of the DELETE of the sender's layer; or
        "give_up", a keep with the version 0. Whether the device makes it, and what it sends."""
        sender, key = self._sender_of(signer), uuid_key(rid)
        assert sender is not None and key is not None, "a record of a sender the device knows"
        made = self._layer_step((sender.serial, key), action, values)
        return made, (self._send_due() if made else [])

    def _layer_step(self, ref: tuple[int, int], action: str, values: dict[str, bytes]) -> bool:
        """One change of section 21.2 to the owner's layer of a received record, with its two stamps;
        whether the device could make it (section 2.3)."""
        sender = self.senders[ref[0]]
        rec, layer = sender.records.get(ref[1]), self.layers.get(ref)
        state = layer.state if layer else State({}, None, None)
        if action == "keep" and (rec is None or rec.there or rec.beside is None or not owner_values(state)):
            return False  # a keep only beside a DATA, and only with an owner's value (section 21.2)
        if action == "give_up" and (state.keep is None or state.keep.given_up):
            return False  # only a keep that keeps the record is given up
        r = (self._draw(), self._draw())
        if not can_begin_change(self.now_ms, self.highest):
            return False
        first = cast_stamp(next_stamp(self.now_ms, self.highest, r[0]))
        fields, removal, keep = dict(state.fields), state.removal, state.keep
        if action == "set":
            fp = None
            if rec is not None and rec.there and rec.schema is not None:
                fp = schema_fingerprint(rec.schema)  # the writer schema of the kept DATA
            elif rec is not None and rec.beside is not None and rec.beside.schema is not None:
                fp = schema_fingerprint(rec.beside.schema)
            for name, value in values.items():
                fields[name] = FieldState(value, first, self.key, fp or fields[name].schema)
        elif action == "discard":
            for name in values:
                fields[name] = FieldState(None, first, self.key, fields[name].schema)
        elif action == "delete":
            removal = Removal(first, self.key, True)
        elif action == "take_back":
            removal = Removal(first, self.key, False)
        elif action == "keep":
            assert rec is not None
            keep = Keep(first, self.key, max(rec.version, keep.version if keep else 0))
        else:
            assert action == "give_up" and keep is not None, action
            keep = Keep(first, self.key, keep.version, True)
        self.highest = second = cast_stamp(next_stamp(self.now_ms, first, r[1]))
        new = State(fields, removal, second, keep)
        if layer is None:
            assert rec is not None and rec.type is not None, "the user changes a record the device holds"
            layer = self.layers[ref] = Held(rec.type, new)
            sender.ids.setdefault(ref[1], self._id(ref))
        layer.state = new
        self._due_for(ref, self._parts(new) - self._parts(state))
        self._layer_moved(ref)
        self._later_ack(ref)
        return True

    def _later_ack(self, ref: tuple[int, int]) -> None:
        """The further ACK with APPLIED of section 22.3: for a message for which the device reported
        KEPT, once the owner's layer shows that it is taken after all, while the receiver's version of
        the record is still the version of that message."""
        pending = self.later.get(ref)
        if pending is None:
            return
        signer, rid, version, kind = pending
        rec, layer = self.senders[ref[0]].records.get(ref[1]), self.layers.get(ref)
        if rec is None or rec.version != version or layer is None:
            del self.later[ref]  # a later message of the sender has arrived in between
            return
        state = layer.state
        if kind == "DATA":
            taken = state.removal is not None and not state.removal.stands
        else:
            taken = state.keep is not None and state.keep.given_up
        if taken:
            del self.later[ref]
            outcome = "WITHDRAWN" if kind == "WITHDRAW" else "APPLIED"  # spec/shares.md, section 7.1
            entry = {"id": rid, "version": version, "outcome": outcome, "receiver_version": version}
            self.app_acks.setdefault(signer, []).append({**entry, "kept_fields": []})

    def forget(self, key: bytes) -> list[bytes]:
        """The user forgets a known sender (spec/keys.md, section 3.4; section 20.5): the device discards
        its kept messages, its owner's layers and what it kept for each sibling about them, and keeps
        the sender's removed keys as refused keys. Nothing travels to its siblings."""
        sender = self._sender_of(key)
        assert sender is not None, "a sender the device knows"
        known, serial = self._keys(sender), sender.serial
        self.book.senders.remove(known)
        self.book.refused += known.removed
        self.forgotten.append((sender.first, list(known.current), list(known.removed)))
        del self.senders[serial]
        self.layers = {ref: layer for ref, layer in self.layers.items() if ref[0] != serial}
        self.later = {ref: v for ref, v in self.later.items() if ref[0] != serial}
        self.kept = {k: v for k, v in self.kept.items() if isinstance(k[1], int) or k[1][0] != serial}
        self.early = [e for e in self.early if e[1] not in known.current + known.removed]
        kept_now = self._kept_hashes()
        for s in self.siblings:
            self.sent[s] = {
                n: v for n, v in self.sent[s].items() if isinstance(v[2], int) or v[2][0] != serial
            }
            self.left[s] = {ref for ref in self.left[s] if isinstance(ref, int) or ref[0] != serial}
            self.forwards[s] = {f: v for f, v in self.forwards[s].items() if v[3] != serial}
            for table in (self.fdelivered, self.fsettled, self.fgone, self.frefused, self.fretried):
                table[s] &= kept_now
        return []

    def query_received(self, key: bytes, rid: str | None) -> dict[str, Any]:
        """What the device holds of the sender that has the key, and of its record with the id."""
        requests = {sibling.hex(): self.requests[sibling][0] for sibling in sorted(self.requests)}
        out: dict[str, Any] = {
            "sender": None,
            "refused": sorted(k.hex() for k in self.book.refused),
            "forgotten": sorted(
                (
                    {
                        "origin": f[0].hex(),
                        "current": sorted(k.hex() for k in f[1]),
                        "removed": sorted(k.hex() for k in f[2]),
                    }
                    for f in self.forgotten
                ),
                key=lambda f: f["origin"],
            ),
            "highest": str(self.highest),
            "requests": requests,
        }
        sender = self._sender_of(key)
        if sender is None:
            return out
        known = self._keys(sender)
        out["sender"] = {
            "origin": sender.first.hex(),
            "known_by": "user" if sender.known_by is None else sorted(k.hex() for k in sender.known_by),
            "current": sorted(k.hex() for k in known.current),
            "removed": sorted(k.hex() for k in known.removed),
            "kept": [
                {
                    "message_hash": sha(raw).hex(),
                    "delivered": [s.hex() for s in sorted(self.siblings) if sha(raw) in self.fdelivered[s]],
                }
                for raw, _ in sender.kept()
            ],
        }
        record_key = None if rid is None else uuid_key(rid)
        if record_key is None:
            return out
        rec, layer = sender.records.get(record_key), self.layers.get((sender.serial, record_key))
        out["received"] = rec and {
            "type": rec.type,
            "version": str(rec.version),
            "state": "there"
            if rec.there
            else ("withdrawn" if kind_of(rec.message) == "WITHDRAW" else "tombstone"),
            "message_hash": sha(rec.message).hex(),
            "beside": rec.beside
            and {"version": str(rec.beside.version), "message_hash": sha(rec.beside.message).hex()},
        }
        out["layer"] = None
        if layer is not None:
            siblings = {}
            for sibling in sorted(self.siblings):
                kept = self.kept.get((sibling, (sender.serial, record_key)), Kept())
                delivered = kept.delivered & self._parts(layer.state)
                siblings[sibling.hex()] = {
                    "known": kept.known,
                    "delivered": sorted(p[0] for p in delivered if isinstance(p, tuple)),
                    "removal": any(isinstance(p, Removal) for p in delivered),
                    "keep": any(isinstance(p, Keep) for p in delivered),
                }
            state_of = state_json(layer.state, True)
            out["layer"] = {"type": layer.type, "state": state_of, "siblings": siblings}
        fp = None if rec is None or rec.schema is None else schema_fingerprint(rec.schema)
        b = None if rec is None else rec.beside
        beside = None if b is None or b.schema is None else (b.values, schema_fingerprint(b.schema))
        state, fields = shown(
            None if rec is None else rec.there,
            rec.values if rec else {},
            fp,
            layer.state if layer else None,
            rec.version if rec else 0,
            beside,
        )
        out["shown"] = {
            "record": state,
            "fields": {
                name: {"value": value.hex(), "schema": schema.hex(), "from": source}
                for name, (value, schema, source) in fields.items()
            },
        }
        return out

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
        [fe.register(fe.from_json_form(d)) for d in v["descriptions"]],
        int(v["highest"]),
        [bytes.fromhex(k) for k in v["removed"]],
        [bytes.fromhex(k) for k in v["others"]],
        [bytes.fromhex(k) for k in v["gone"]],
        v["offer_ids"],
        v["request_ids"],
        [bytes.fromhex(k) for k in v["relay"]],
        [bytes.fromhex(k) for k in v.get("refused", [])],
        v.get("forward_ids", []),
        v.get("on_delete", "delete"),
        v.get("on_withdraw"),
    )
    for sender in v.get("senders", []):
        device.know(sender, bytes_in)
    for f in v.get("forgotten", []):
        device.forgotten.append(
            (
                bytes.fromhex(f["origin"]),
                [bytes.fromhex(k) for k in f["current"]],
                [bytes.fromhex(k) for k in f["removed"]],
            )
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
    # What the app's own records hold of its shares and of the answers to proposals (spec/shares.md,
    # sections 2.1 and 15.1).
    for rid, senders in v.get("shares", {}).items():
        key = uuid_key(rid)
        assert key is not None
        for k in senders:
            sender = device._sender_of(bytes.fromhex(k))
            assert sender is not None, "a record is shared with a known sender"
            device.shares.setdefault(key, set()).add(sender.serial)
    for st in v.get("stopped", []):
        sender = device._sender_of(bytes.fromhex(st["sender"]))
        assert sender is not None
        device.stopped.add((sender.serial, None if st["id"] is None else uuid_key(st["id"])))
    for a in v.get("answers", []):
        sender = device._sender_of(bytes.fromhex(a["sender"]))
        assert sender is not None
        device.answers[(sender.serial, uuid_key(a["proposal_id"]) or 0)] = a["answer"]
    for sender in device.senders.values():
        for pid, (raw, key, day, _) in list(sender.proposals.items()):
            sender.proposals[pid] = (raw, key, day, device._shows(sender, key))
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
    elif "change" in step and "sender" in step["change"]:
        c = step["change"]  # of a record received from the sender that has that key (section 21.2)
        values = {name: b"" if value is None else bytes_in(value) for name, value in c["values"].items()}
        made, sent = device.layer_change(bytes.fromhex(c["sender"]), c["id"], c["action"], values)
        answer = {"made": made, "sent": sent}
    elif "change" in step:
        c = step["change"]
        values = {name: bytes_in(value) for name, value in c["values"].items()}
        made, sent = device.user_change(c["id"], c["type"], c["action"], values, bytes.fromhex(c["schema"]))
        answer = {"made": made, "sent": sent}
    elif "take" in step:
        did, sent = device.take(bytes_in(step["take"]), step.get("schema"), step.get("file", False))
        answer = {**did, "sent": sent}
    elif "forget" in step:
        answer = {"sent": device.forget(bytes.fromhex(step["forget"]))}
    elif "answer" in step:
        a = step["answer"]  # the user answers a proposal on this device (spec/shares.md, section 17.1)
        made, sent = device.answer_proposal(bytes.fromhex(a["sender"]), a["proposal_id"], a["answer"])
        answer = {"made": made, "sent": sent}
    elif "answered" in step:
        a = step["answered"]  # the answer reaches the device in the app's own records
        answer = {"sent": device.answered_proposal(bytes.fromhex(a["sender"]), a["proposal_id"], a["answer"])}
    elif "stop" in step:
        a = step["stop"]
        answer = {"sent": device.stop(bytes.fromhex(a["sender"]), a["id"])}
    elif "share" in step:
        a = step["share"]
        answer = {"sent": device.share(a["id"], bytes.fromhex(a["sender"]), a["shared"])}
    elif "proposals" in step:
        return device.query_proposals(bytes.fromhex(step["proposals"]))
    elif "file_record" in step:
        taken, sent = device.file_record(bytes_in(step["file_record"]), step["schema"])
        answer = {"taken": taken, "sent": sent}
    elif "flush_acks" in step:
        answer = {"sent": device.flush_acks()}
    elif "add" in step:
        answer = {"sent": device.add(bytes.fromhex(step["add"]))}
    elif "remove" in step:
        sent, now = device.remove(bytes.fromhex(step["remove"]), step.get("move", False))
        answer = {"sent": sent, "introduced": [k.hex() for k in now]}
    elif "senders_kept" in step:
        answer = {"sent": [], "introduced": [k.hex() for k in device.senders_kept()]}
    elif "reconnect" in step:
        answer = {"sent": device.reconnect(bytes.fromhex(step["reconnect"]))}
    elif "days" in step:
        answer = {"sent": device.days(step["days"])}
    elif "restore" in step:
        backup = step["restore"]
        records = [_held_of_json(r)[:2] for r in backup["records"]]
        acted = {bytes.fromhex(sibling): ids for sibling, ids in backup["acted"].items()}
        refused = [bytes.fromhex(k) for k in backup.get("refused", [])]
        sent = device.restore(
            int(backup["highest"]), records, acted, backup.get("senders"), refused, bytes_in
        )
        answer = {"sent": sent}
    elif "sender" in step:
        return device.query_received(bytes.fromhex(step["sender"]), step["query"])
    else:
        return device.query(step["query"])
    assert not device.r, "the step gives a random part that the device does not draw"
    device._tidy_proposals()
    answer["passed"] = [{"to": to, "manifest": m} for to, m in device.take_passed()]
    return answer


def meaning(m: bytes) -> list[dict[str, Any]]:
    """What a message that a device sends says, as the vectors compare it: one entry for the message,
    or for an ACK one for each of its entries."""
    envelope = read_all("Envelope", m[10:])
    kind, rec = envelope["kind"], envelope["record"]
    d = read_all(BODY_OF[kind], envelope["body"][10:])
    base = {"kind": kind, "to": d["to"].hex()}
    if kind == "FORWARD":
        text = d["schema"]
        return [
            {
                **base,
                "record": {"id": rec["id"], "version": str(rec["version"])},
                "message_hash": sha(d["message"]).hex(),
                "schema_hash": None if text is None else sha(text.encode()).hex(),
            }
        ]
    if kind == "CHANGE":
        r, k = d["removal"], d["keep"]
        # A message with a key in `origin` says so, and gives its keep; one of a record of the set has
        # neither member.
        keep = {
            "keep": k
            and {
                "stamp": str(k["stamp"]),
                "device": k["device"].hex(),
                "version": str(k["version"]),
                "given_up": k["given_up"],
            }
        }
        origin = {} if d["origin"] is None else {"origin": d["origin"].hex(), **keep}
        return [
            {
                **base,
                **origin,
                "record": {"id": rec["id"], "version": str(rec["version"])},
                "type": d["type"],
                "state": str(d["state"]),
                "whole": d["whole"],
                "removal": r
                and {"stamp": str(r["stamp"]), "device": r["device"].hex(), "stands": r["stands"]},
                "fields": {
                    f["name"]: {
                        "value": None if f["value"] is None else f["value"].hex(),
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
        return [
            {
                **base,
                "offer_id": d["offer_id"],
                "descriptions": [fe.json_form(t["description"]) for t in d["types"]],
            }
        ]
    if kind == "ACCEPT":
        return [{**base, "offer_id": d["offer_id"], "types": sorted(d["types"])}]
    if kind == "DECLINE":
        reasons = sorted((t["type"], t["reason"]) for t in d["types"])
        return [{**base, "offer_id": d["offer_id"], "types": [{"type": n, "reason": r} for n, r in reasons]}]
    if kind == "PROPOSAL_REPLY":
        record = {"id": rec["id"], "version": str(rec["version"])}
        return [{**base, "record": record, "proposal_id": d["proposal_id"], "answer": d["answer"]}]
    assert kind == "RESYNC", kind
    return [{**base, "record": {"id": rec["id"], "version": str(rec["version"])}}]


def meanings(sent: list[bytes]) -> list[dict[str, Any]]:
    """The messages of one step as the vectors hold them: in an order that says nothing. The order in
    which the FORWARD messages for one sibling are sent does count (section 20.3), so each says its
    place among them, from 0 on."""
    out, place = list[dict[str, Any]](), dict[str, int]()
    for m in sent:
        for entry in meaning(m):
            if entry["kind"] == "FORWARD":
                entry["position"] = place.get(entry["to"], 0)
                place[entry["to"]] = entry["position"] + 1
            out.append(entry)
    return sorted(out, key=lambda e: json.dumps(e, sort_keys=True))


# --- the examples of sections 15 and 16 ----------------------------------------------------------------

PHONE_SEED = test_secret("cat-a-log, phone, Ed25519")
TABLET_SEED = test_secret("cat-a-log, tablet, Ed25519")
DEVICE_NAMES = {PHONE: "phone", TABLET: "tablet"}
# The other app of sections 16.5 to 16.7: Old Brain Fix, with the test key of spec/protocol.md, section 17.1.
OBF_SEED = test_secret("Old Brain Fix, Ed25519")
KEY_OBF = bytes(keys.public_key(OBF_SEED))
FORWARD_ID = "c4a1e2b3-6d7f-4809-9a1b-2c3d4e5f6071"  # the forward of section 16.5
MANIFEST_FORWARD_ID = "b3a0d1c2-5e6f-4708-8192-a3b4c5d6e7f8"  # the forward before it, which is not shown
# The schema of the description Appointment.1.json that Old Brain Fix offered (spec/protocol.md, 17.3).
APPOINTMENT_OFFERED = APPOINTMENT_1
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
    '{"name":"stands","type":"boolean"}]}]},{"name":"keep","type":["null",{"name":"axt.ChangeKeep","type":'
    '"record","fields":[{"name":"stamp","type":"long"},{"name":"device","type":{"name":"axt.ChangeKeepDevice",'
    '"type":"fixed","size":32}},{"name":"version","type":"long"},{"name":"given_up","type":"boolean"}]}]},'
    '{"name":"fields","type":{"type":"array",'
    '"items":{"name":'
    '"axt.ChangeField","type":"record","fields":[{"name":"name","type":"string"},{"name":"schema","type":'
    '{"name":"axt.ChangeFieldSchema","type":"fixed","size":8}},{"name":"value","type":["null","bytes"]},'
    '{"name":"stamp","type":"long"},{"name":"device","type":{"name":"axt.ChangeFieldDevice","type":"fixed",'
    '"size":32}}]}}}]}'
)
FINGERPRINTS = {"Change": 0x4D094DAFC5F888C1, "Resync": 0xE8762BD9D559FDF1, "Forward": 0x57476ABF6B053BAD}
FORWARD_PCF = (
    '{"name":"axt.Forward","type":"record","fields":[{"name":"to","type":{"name":"axt.ForwardTo",'
    '"type":"fixed","size":32}},{"name":"message","type":"bytes"},{"name":"schema","type":["null","string"]}]}'
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
    "relations": [],
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
    whose = "Old Brain Fix's" if key == KEY_OBF else f"the {DEVICE_NAMES[key]}'s"
    return [(key, f"{name}: fixed(32), {whose} test key")]


def change_parts(d: dict[str, Any], notes: dict[str, str]) -> Parts:
    """The body of a CHANGE field by field, as section 8.1 lists them; `notes` says what each value is."""
    z = keys.zigzag
    parts: Parts = [
        (MARKER, "single-object marker"),
        (SPEC_FP["Change"], "fingerprint of axt.Change, format 1"),
    ]
    parts += _key("to", d["to"])
    if d["origin"] is None:
        parts += [(z(0), "origin: union index 0, null")]
    else:
        parts += [(z(1), "origin: union index 1, axt.ChangeOrigin"), *_key("origin", d["origin"])]
    parts += _text("type", d["type"])
    parts += [(z(d["state"]), f"state: long {d['state']}")]
    parts += [(b"\x01" if d["whole"] else b"\x00", f"whole: boolean {str(d['whole']).lower()}")]
    assert d["removal"] is None and d["keep"] is None, "the examples carry no removal and no keep"
    parts += [(z(0), "removal: union index 0, null")]
    parts += [(z(0), "keep: union index 0, null")]
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
EXAMPLE_OTHERS: dict[
    str, bytes
] = {}  # the messages of Old Brain Fix in section 16.5, which other scripts hold
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
    """Section 15: the canonical forms and the fingerprints of axt.Change, axt.Resync and axt.Forward, with
    fastavro and the Apache avro package, and that the five unions have null first and the default null."""
    out.append("== Section 15: schemas ==")
    out.append("| Schema | Envelope format | CRC-64-AVRO | As bytes |")
    for name, pcf in (("Change", CHANGE_PCF), ("Resync", RESYNC_PCF), ("Forward", FORWARD_PCF)):
        text = SPEC_TEXT[name]
        assert to_parsing_canonical_form(fastavro.parse_schema(json.loads(text))) == pcf, name
        assert avro.schema.parse(pcf).canonical_form == pcf, f"{name}: the two libraries disagree"
        fp = tm.rules.crc64_avro(pcf.encode())
        assert fp == FINGERPRINTS[name], (
            f"the fingerprint of axt.{name} is not that of spec/sync.md, section 15"
        )
        assert fp.to_bytes(8, "little") == SPEC_FP[name] == tm.rules.apache_fingerprint(text), name
        out.append(f"axt.{name}: canonical form: {pcf}")
        out.append(f"| `axt.{name}` | 1 | `0x{fp:016x}` | `{SPEC_FP[name].hex(' ')}` |")
    change_fields = {f["name"]: f for f in json.loads(SPEC_TEXT["Change"])["fields"]}
    value = next(f for f in change_fields["fields"]["type"]["items"]["fields"] if f["name"] == "value")
    forward_schema = json.loads(SPEC_TEXT["Forward"])["fields"][2]
    for f in (
        change_fields["origin"],
        change_fields["removal"],
        change_fields["keep"],
        value,
        forward_schema,
    ):
        assert f["type"][0] == "null" and f["default"] is None, f["name"]
    # A writer without the four reads as null in each, with both libraries.
    old = json.loads(SPEC_TEXT["Change"])
    old["fields"] = [f for f in old["fields"] if f["name"] not in ("origin", "removal", "keep")]
    items = next(f for f in old["fields"] if f["name"] == "fields")["type"]["items"]
    items["fields"] = [f for f in items["fields"] if f["name"] != "value"]
    entry = {"name": "title", "schema": SCHEMA_1, "stamp": 100, "device": PHONE}
    datum = {"to": TABLET, "type": APPOINTMENT_TYPE, "state": 101, "whole": False, "fields": [entry]}
    buf = io.BytesIO()
    fastavro.schemaless_writer(buf, fastavro.parse_schema(old), datum)
    want = {**datum, "origin": None, "removal": None, "keep": None, "fields": [{**entry, "value": None}]}
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
    assert [f["name"] for f in APPOINTMENT_JSON["fields"]] == list(APPOINTMENT) and len(APPOINTMENT) == 8
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
        "relations": z(0),
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
        "relations": "the value: an array without items",
    }

    # 16.1: both devices hold the record; every part is delivered in both directions.
    begin = {name: FieldState(value, 100, PHONE) for name, value in VALUE.items()}
    phone = example_device(PHONE_SEED, TABLET, State(begin, None, 101), 101)
    tablet = example_device(TABLET_SEED, PHONE, State(begin, None, 105), 105)
    backup = copy.deepcopy(phone)  # the phone's data before the change of section 16.2

    # 16.2: the phone's user sets start and location in one step, with the stamps 110 and 111.
    phone.at(0, [110 - 102, 0])  # the second stamp has a random part of 0
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
        "keep": None,
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
        "keep": None,
        "fields": entries(state, list(APPOINTMENT)),
    }
    assert change_version(d) == 117
    assert [f["stamp"] for f in d["fields"]] == [100, 110, 100, 100, 110, 100, 100, 100]
    body = change_parts(d, notes)
    assert b"".join(p[0] for p in body) == body_of("Change", d)
    assert apache_body("Change", body_of("Change", d)) == d
    parts, m = message_parts(TABLET_SEED, "CHANGE", (RECORD_ID, 117), body)
    assert meanings(sent) == meaning(m), "the tablet of the model sends this CHANGE"
    show(out, "16.4: the tablet's whole CHANGE", parts, m)
    EXAMPLE_MESSAGES["the whole CHANGE of sync.md, section 16.4"] = m
    phone.at(0, [0])  # a random part of 0: the stamp is the base itself
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
    again.at(0, [0])  # a random part of 0: the stamp is the base itself
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
    out.append(dump(parts))
    out.append(f"signed bytes: {len(keys.MESSAGE_PREFIX) + len(m) - 74}, signature {m[-64:].hex()}")


def dump(parts: Parts) -> str:
    """Annotated hex in the layout of spec/envelope.md; a value of more than 1,024 bytes, the text of a
    schema, is shown shortened, as spec/protocol.md, section 17.3, shows it."""
    offset, lines = 0, list[str]()
    for data, note in parts:
        if len(data) > 1024:
            lines.append(f"{offset:04x}  {(data[:4].hex(' ') + ' ... ' + data[-2:].hex(' ')):<23}  {note}")
        else:
            lines += keys.dump([(bytes(offset), ""), (data, note)]).split("\n")[
                -1 - max(1, -(-len(data) // 8)) : -1
            ]
        offset += len(data)
    return "\n".join([*lines, f"{offset:04x}  end"])


def check_received(out: list[str]) -> None:
    """Sections 16.5 to 16.7, the steps 1 and 2 of section 22.4: the DATA of Old Brain Fix, the phone's
    FORWARD of it and the tablet's ACK, and the tablet's CHANGE of the owner's layer with the phone's ACK,
    built field by field and played through the model of a device."""
    z = keys.zigzag
    assert KEY_OBF.hex() == "da9e54c9aa2db43244df99889d9138c1ca7175d4ca0908168f63530e4a7dedb7"
    assert schema_fingerprint(APPOINTMENT_OFFERED) == SCHEMA_1
    phone = SetDevice(
        PHONE_SEED,
        [TABLET],
        [APPOINTMENT_1],
        195,
        others=[KEY_OBF],
        forward_ids=[MANIFEST_FORWARD_ID, FORWARD_ID],
    )
    tablet = SetDevice(TABLET_SEED, [PHONE], [APPOINTMENT_1], 190)
    for device, sibling in ((phone, TABLET), (tablet, PHONE)):
        device.accepted[sibling].add(SCHEMA_1)  # the offers of section 16.1
        device.offered[sibling][SCHEMA_1] = APPOINTMENT_1
    # Before 16.5: the phone keeps the MANIFEST of Old Brain Fix and forwards it; the tablet so knows the
    # sender, without a question. Nothing of this forward is shown.
    manifest = message(OBF_SEED, "MANIFEST", None, body_of("Manifest", me.OLD_BRAIN_FIX))
    EXAMPLE_OTHERS["the MANIFEST of Old Brain Fix"] = manifest
    did, sent = phone.take(manifest, None)
    assert did == {"taken": True} and len(sent) == 1
    assert tablet._sender_of(KEY_OBF) is None
    assert tablet.receive(sent[0]) == ("APPLIED", []) and tablet.book.key_state(KEY_OBF)[0] == "current"
    assert phone.receive(tablet.flush_acks()[0]) == (None, [])

    # 16.5: the DATA of Old Brain Fix, version 1, and the phone's FORWARD of it.
    record: Parts = [
        (MARKER, "single-object marker"),
        (SCHEMA_1, f"fingerprint of {APPOINTMENT_TYPE}, version 1"),
    ]
    record += [(VALUE[name], f"{name}: the value of section 16.1") for name in APPOINTMENT]
    data_parts, data = message_parts(OBF_SEED, "DATA", (RECORD_ID, 1), record)
    assert data == data_message("other app", 1, APPOINTMENT_1, APPOINTMENT)
    EXAMPLE_OTHERS["the DATA of Old Brain Fix"] = data
    out.append("")
    out.append(
        f"16.5: the DATA of Old Brain Fix: {len(data)} bytes, SHA-256 {hashlib.sha256(data).hexdigest()}, "
        f"signature {data[-64:].hex()}"
    )
    did, sent = phone.take(data, APPOINTMENT_OFFERED)
    assert did == {"outcome": "APPLIED", "kept_fields": []} and len(sent) == 1
    (ack,) = phone.flush_acks()
    assert meaning(ack) == [
        {
            "kind": "ACK",
            "to": KEY_OBF.hex(),
            "id": RECORD_ID,
            "version": "1",
            "outcome": "APPLIED",
            "receiver_version": "1",
            "kept_fields": [],
        }
    ]
    d: dict[str, Any] = {"to": TABLET, "message": data, "schema": APPOINTMENT_OFFERED}
    text = APPOINTMENT_OFFERED.encode()
    body: Parts = [
        (MARKER, "single-object marker"),
        (SPEC_FP["Forward"], "fingerprint of axt.Forward, format 1"),
    ]
    body += _key("to", TABLET)
    body += [(z(len(data)), f"message: bytes length {len(data)}")]
    body += [(part, f"message: {note}") for part, note in data_parts]
    body += [(z(1), "schema: union index 1, string"), (z(len(text)), f"schema: string length {len(text)}")]
    body += [
        (
            text,
            f"the schema derived from the description Appointment.1.json ({len(text)} bytes of UTF-8 JSON)",
        )
    ]
    assert b"".join(p[0] for p in body) == body_of("Forward", d), "the body differs from fastavro"
    assert apache_body("Forward", body_of("Forward", d)) == d
    parts, m = message_parts(PHONE_SEED, "FORWARD", (FORWARD_ID, 1), body)
    assert sent == [m], "the phone of the model sends this FORWARD"
    assert KINDS.index("FORWARD") == 13
    show(out, "16.5: the phone's FORWARD", parts, m)
    EXAMPLE_MESSAGES["the FORWARD of sync.md, section 16.5"] = m
    before = copy.deepcopy(tablet)
    assert tablet.receive(m) == ("APPLIED", []), tablet.what
    got = tablet.query_received(KEY_OBF, RECORD_ID)
    assert got["received"] == {
        "type": APPOINTMENT_TYPE,
        "version": "1",
        "state": "there",
        "message_hash": hashlib.sha256(data).hexdigest(),
        "beside": None,
    }
    # The same bytes are a kept message of the tablet, delivered to the phone: nothing goes back.
    assert got["sender"]["kept"][-1] == {
        "message_hash": hashlib.sha256(data).hexdigest(),
        "delivered": [PHONE.hex()],
    }
    assert got["shown"]["record"] == THERE and got["layer"] is None

    # 16.6: the tablet's ACK for the forward.
    (ack,) = tablet.flush_acks()
    entry = {"id": FORWARD_ID, "version": 1, "outcome": "APPLIED", "receiver_version": 1, "kept_fields": []}
    assert ack == message(TABLET_SEED, "ACK", None, body_of("Ack", {"to": PHONE, "records": [entry]}))
    assert ack[-64:] == all_sign(TABLET_SEED, keys.MESSAGE_PREFIX + ack[10:-64])
    assert apache_body("Ack", read_all("Envelope", ack[10:])["body"]) == {"to": PHONE, "records": [entry]}
    out.append(f"16.6: the tablet's ACK: {len(ack)} bytes, SHA-256 {hashlib.sha256(ack).hexdigest()}")
    EXAMPLE_MESSAGES["the ACK of sync.md, section 16.6"] = ack
    assert phone.receive(ack) == (None, []) and phone.what == "1 entries taken"
    assert phone.query_received(KEY_OBF, RECORD_ID)["sender"]["kept"][-1]["delivered"] == [TABLET.hex()]
    # The same FORWARD once more, and the same DATA in a forward with another id: DUPLICATE.
    assert tablet.receive(m) == ("DUPLICATE", [])
    other = message(PHONE_SEED, "FORWARD", (MANIFEST_FORWARD_ID, 1), body_of("Forward", d))
    assert tablet.receive(other) == ("DUPLICATE", []) and len(meanings(tablet.flush_acks())) == 2
    assert before.receive(other) == ("APPLIED", [])

    # 16.7: the tablet's user sets the location, with the stamps 200 and 201.
    tablet.at(0, [200 - 191, 0])  # the second stamp has a random part of 0
    made, sent = tablet.layer_change(KEY_OBF, RECORD_ID, "set", {"location": VALUE_WEBER})
    assert made and len(sent) == 1 and tablet.highest == 201
    layer = FieldState(VALUE_WEBER, 200, TABLET, SCHEMA_1)
    change_d: dict[str, Any] = {
        "to": PHONE,
        "origin": KEY_OBF,
        "type": APPOINTMENT_TYPE,
        "state": 201,
        "whole": True,
        "removal": None,
        "keep": None,
        "fields": [entry_of("location", layer)],
    }
    assert change_version(change_d) == 201 and change_problem(change_d, 201) is None
    body = change_parts(change_d, {"location": f'the value: "{WEBER}" as an Avro string'})
    assert b"".join(p[0] for p in body) == body_of("Change", change_d), "the body differs from fastavro"
    assert apache_body("Change", body_of("Change", change_d)) == change_d
    parts, m = message_parts(TABLET_SEED, "CHANGE", (RECORD_ID, 201), body)
    assert sent == [m], "the tablet of the model sends this CHANGE, and no FORWARD before it"
    show(out, "16.7: the tablet's CHANGE with a key in origin", parts, m)
    EXAMPLE_MESSAGES["the CHANGE of sync.md, section 16.7"] = m
    phone.at(0, [205 - 202])
    assert phone.receive(m) == ("APPLIED", []), phone.what
    (ack,) = phone.flush_acks()
    entry = {
        "id": RECORD_ID,
        "version": 201,
        "outcome": "APPLIED",
        "receiver_version": 205,
        "kept_fields": [],
    }
    assert ack == message(PHONE_SEED, "ACK", None, body_of("Ack", {"to": TABLET, "records": [entry]}))
    assert ack[-64:] == all_sign(PHONE_SEED, keys.MESSAGE_PREFIX + ack[10:-64])
    out.append(f"16.7: the phone's ACK: {len(ack)} bytes, SHA-256 {hashlib.sha256(ack).hexdigest()}")
    EXAMPLE_MESSAGES["the ACK of sync.md, section 16.7"] = ack
    assert phone.highest == 205
    for device in (phone, tablet):
        got = device.query_received(KEY_OBF, RECORD_ID)
        assert got["layer"]["state"] == state_json(State({"location": layer}, None, device.highest), True)
        fields = got["shown"]["fields"]
        assert fields["location"] == {"value": VALUE_WEBER.hex(), "schema": SCHEMA_1.hex(), "from": "owner"}
        assert fields["start"] == {"value": VALUE["start"].hex(), "schema": SCHEMA_1.hex(), "from": "sender"}
    assert tablet.receive(ack) == (None, []) and tablet.highest == 205


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
    "other app, new": test_secret("Old Brain Fix, new device, Ed25519"),  # a second device of that sender
    "second app": test_secret("a second app, Ed25519"),  # another sender
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
PET_1 = fe.source((REPO / "types" / "axt" / "example" / "v1" / "Pet.1.avsc").read_text(encoding="utf-8"))
PET_TYPE = "axt.example.v1.Pet"
SCHEMA_PET = schema_fingerprint(PET_1)
# A version of the appointment whose title is a number: a schema that does not resolve against version 1.
_other = json.loads(APPOINTMENT_FILE)
_other["axt.version"] = 3
_other["fields"][0]["type"] = "long"
_other["fields"][0]["default"] = 0
_other["axt.title"] = "location"  # its title names a field of text (spec/fields.md, section 9.1)
APPOINTMENT_3 = fe.source(json.dumps(_other))
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
        "descriptions": [fe.json_form(fe.description_of(t)) for t in schemas],
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


entry_of = entry


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
    keep: Keep | None = None,
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
        "keep": keep
        and {"stamp": keep.stamp, "device": keep.device, "version": keep.version, "given_up": keep.given_up},
        "fields": entries,
    }
    stamps = [state, *(e["stamp"] for e in entries), *(p.stamp for p in (removal, keep) if p is not None)]
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


def offer_message(sender: str, offer_id: str, texts: list[Any], to: str = "phone", count: int = 0) -> bytes:
    """An OFFER of the schemas of texts the device holds, or of descriptions given as they are."""
    types = [
        {"schema": t, "count": count} if isinstance(t, str) else {"description": t, "count": count}
        for t in texts
    ]
    d = {"to": KEY[to], "offer_id": offer_id, "types": types}
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
        groups.setdefault((int(f["stamp"]), who), []).append(
            name if f["value"] is not None else f"{name}=null"
        )
    return (
        " ".join(
            f"{','.join(names) if len(names) < len(APPOINTMENT) else 'all eight'}@{stamp}{who}"
            for (stamp, who), names in sorted(groups.items())
        )
        or "no field"
    )


def _removal_brief(r: dict[str, Any] | None) -> str:
    if r is None:
        return ""
    who = WHO.get(bytes.fromhex(r["device"]), "?")[0]
    return f" removal@{r['stamp']}{who}{'' if r['stands'] else ', taken back'}"


def _keep_brief(k: dict[str, Any] | None) -> str:
    if k is None:
        return ""
    who = WHO.get(bytes.fromhex(k["device"]), "?")[0]
    given = ", given up" if k["given_up"] else ""
    return f" keep@{k['stamp']}{who} of version {k['version']}{given}"


def brief(answer: dict[str, Any]) -> list[str]:
    """The answer of a step in a few words, as the cases below write out what they expect."""
    if "proposals" in answer:  # the proposals of a sender
        kept_now = [
            f"proposal {p['proposal_id'][:8]} of {p['id'][:8]}: {'shown' if p['shown'] else 'not shown'}"
            for p in answer["proposals"]
        ]
        answers = [f"answer {a['proposal_id'][:8]}: {a['answer']}" for a in answer["answers"]]
        return [*kept_now, *answers] or ["no proposal"]
    if "refused" in answer:  # a query about a sender, and about a record received from it
        return _received_brief(answer)
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
    if "introduced" in answer:
        names = ", ".join(WHO[bytes.fromhex(k)] for k in answer["introduced"]) or "no sender"
        out.append(f"chain and MANIFEST to: {names}")
    for name in ("outcome", "made", "taken"):
        if name in answer:
            kept = f", kept {answer['kept_fields']}" if answer.get("kept_fields") else ""
            out.append(f"{name}: {answer[name]}{kept}")
    for m in answer["sent"]:
        to = WHO[bytes.fromhex(m["to"])]
        if m["kind"] == "FORWARD":
            what = SAYS.get(m["message_hash"], m["message_hash"][:8])
            schema = "" if m["schema_hash"] is None else f", with {SAYS.get(m['schema_hash'], 'a schema')}"
            version = "" if m["record"]["version"] == "1" else f", version {m['record']['version']}"
            out.append(f"FORWARD {m['record']['id'][:8]} to {to}, #{m['position']}{version}: {what}{schema}")
        elif m["kind"] == "CHANGE":
            rid = "" if m["record"]["id"] == RECORD_ID else f" of {m['record']['id'][:8]}"
            rid += f", origin {WHO[bytes.fromhex(m['origin'])]}," if "origin" in m else ""
            text = f"CHANGE{rid} to {to}, version {m['record']['version']}, state {m['state']}, "
            text += f"{'whole' if m['whole'] else 'in part'}: {_fields_brief(m['fields'])}"
            out.append(text + _removal_brief(m["removal"]) + _keep_brief(m.get("keep")))
        elif m["kind"] == "ACK":
            rid = "" if m["id"] == RECORD_ID else f" of {m['id'][:8]}"
            kept = f", kept {m['kept_fields']}" if m["kept_fields"] else ""
            out.append(
                f"ACK{rid} to {to}: version {m['version']} {m['outcome']}, "
                f"receiver {m['receiver_version']}{kept}"
            )
        elif m["kind"] == "ERROR":
            more = "".join(f", {k} {m[k]}" for k in ("fingerprint", "field") if m[k] is not None)
            out.append(f"ERROR to {to}: {m['code']}{more}")
        elif m["kind"] == "OFFER":
            types = [fe.type_of(fe.from_json_form(d)) for d in m["descriptions"]]
            names = ", ".join(f"{name} version {version}" for name, version in types)
            out.append(f"OFFER {m['offer_id'][:8]} to {to}: {names}")
        elif m["kind"] == "ACCEPT":
            out.append(f"ACCEPT {m['offer_id'][:8]} to {to}: {', '.join(m['types'])}")
        elif m["kind"] == "DECLINE":
            reasons = ", ".join(f"{t['type']} {t['reason']}" for t in m["types"])
            out.append(f"DECLINE {m['offer_id'][:8]} to {to}: {reasons}")
        elif m["kind"] == "PROPOSAL_REPLY":
            version = m["record"]["version"]
            out.append(f"PROPOSAL_REPLY {m['proposal_id'][:8]} to {to}, version {version}: {m['answer']}")
        else:
            version = "" if m["record"]["version"] == "1" else f", version {m['record']['version']}"
            out.append(f"{m['kind']} {m['record']['id'][:8]} to {to}{version}")
    for passed in answer["passed"]:
        envelope = read_all("Envelope", bytes.fromhex(passed["manifest"])[10:])
        revision = read_all("Manifest", envelope["body"][10:])["revision"]
        to = WHO[bytes.fromhex(passed["to"])]
        out.append(f"MANIFEST of the {WHO[envelope['sender']]}, revision {revision}, passed on to {to}")
    return out


SAYS: dict[str, str] = {}  # what a message or a schema text of the sessions is, by its SHA-256, for `brief`


def named(what: str, data: bytes) -> bytes:
    """Give a message of another app, or a schema text, a name for the lines that `brief` writes."""
    SAYS[hashlib.sha256(data).hexdigest()] = what
    return data


def _received_brief(answer: dict[str, Any]) -> list[str]:
    """A query about a sender and one of its records, in a few lines."""

    def who(k: str) -> str:
        return WHO[bytes.fromhex(k)]

    sender = answer["sender"]
    refused = f"; refused: {', '.join(who(k) for k in answer['refused'])}" if answer["refused"] else ""
    for f in answer["forgotten"]:
        refused += f"; forgotten: {', '.join(who(k) for k in f['current'])}"
    asking = ", ".join(who(k) for k in answer["requests"])
    tail = f"; highest {answer['highest']}{refused}" + (f"; a request open to {asking}" if asking else "")
    if sender is None:
        return [f"no known sender{tail}"]
    line = f"sender first known by {who(sender['origin'])}; "
    if sender["known_by"] != "user":
        line += f"known by forwards of {', '.join(who(k) for k in sender['known_by']) or 'no sibling'}; "
    line += f"current: {', '.join(who(k) for k in sender['current'])}"
    line += f"; removed: {', '.join(who(k) for k in sender['removed'])}" if sender["removed"] else ""
    out = [line + tail]
    for kept in sender["kept"]:
        to = ", ".join(who(k) for k in kept["delivered"]) or "no sibling"
        out.append(f"kept: {SAYS.get(kept['message_hash'], kept['message_hash'][:8])}; delivered to {to}")
    if "shown" not in answer:
        return out
    rec, layer, shown_ = answer["received"], answer["layer"], answer["shown"]
    if rec is None:
        out.append("sender's layer: none")
    else:
        what = SAYS.get(rec["message_hash"], rec["message_hash"][:8])
        line = f"sender's layer: {rec['state']}, version {rec['version']}, type {rec['type']}, from {what}"
        if rec["beside"] is not None:
            b = rec["beside"]
            line += f"; beside it {SAYS.get(b['message_hash'], b['message_hash'][:8])}"
        out.append(line)
    if layer is None:
        out.append("owner's layer: none")
    else:
        state = layer["state"]
        line = f"owner's layer: state stamp {state['state_stamp']}; {_fields_brief(state['fields'])}"
        line += _removal_brief(state["removal"]) + _keep_brief(state["keep"])
        out.append(line + f"; type {layer['type']}")
        for key, s in layer["siblings"].items():
            delivered = (
                "all" if s["delivered"] == sorted(state["fields"]) else ",".join(s["delivered"]) or "nothing"
            )
            what = f"known, delivered: {delivered}{' and the removal' if s['removal'] else ''}"
            what += " and the keep" if s["keep"] else ""
            out.append(f"{who(key)}: {what if s['known'] else 'not known'}")
    owner = sorted(n for n, f in shown_["fields"].items() if f["from"] == "owner")
    out.append(f"shows: {shown_['record']}" + (f"; the owner's value in {', '.join(owner)}" if owner else ""))
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

    def take(
        self, m: bytes, schema: str | None = None, r: tuple[int, ...] = (), file: bool = False
    ) -> list[bytes]:
        """A message of another app reaches the device from that app itself, or in a file of it."""
        step: dict[str, Any] = {"take": m, "now_ms": "0", "r": list(r)}
        if schema is not None:
            step["schema"] = schema
        return self.step({**step, "file": True} if file else step)

    def owner(
        self,
        action: str,
        values: dict[str, bytes | None],
        r: tuple[int, ...],
        sender: str = "other app",
        rid: str = RECORD_ID,
    ) -> list[bytes]:
        """The device's user changes a record received from the sender that has that key."""
        c = {"id": rid, "sender": KEY[sender].hex(), "action": action, "values": values}
        return self.step({"change": c, "now_ms": "0", "r": list(r)})

    def about(self, rid: str | None = RECORD_ID, sender: str = "other app") -> None:
        """What the device holds of the sender that has that key, and of its record."""
        self.step({"query": rid, "sender": KEY[sender].hex()})

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
        "fields": [{"name": "v", "type": nested, "default": [], "doc": "Arrays inside arrays."}],
    }
    deep_text = fe.source(json.dumps(deep_json))
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
        "an offer of a sibling with a description whose root is no object is rejected",
        ["sync.md 7.2", "protocol.md 4.2"],
    )
    s.receive(
        offer_message("tablet", OFFER_IDS[5], [fe.field("v", "A text.", fe.brick("StringField"), fe.texts())])
    )
    s = new(
        "a type of a sibling's offer whose description is not valid is declined",
        ["sync.md 7.2", "protocol.md 5.2", "fields.md 10.1"],
    )
    s.receive(offer_message("tablet", OFFER_IDS[5], [PET_1, dict(fe.description_of(APPOINTMENT_1), doc=" ")]))
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
    one = fe.field("text", "A text.", fe.brick("StringField"), fe.texts())
    many = [
        fe.field(
            "t",
            "A type.",
            fe.brick("ObjectField", name=f"com.example.T{n}", fields=[one], version=1),
            fe.texts(),
        )
        for n in range(257)
    ]
    large = dict(fe.description_of(PET_1), doc="x" * 262144)
    offers: list[tuple[str, bytes, str]] = [
        (
            "the nil UUID as its id",
            offer_message("tablet", "0" * 8 + "-0000-0000-0000-" + "0" * 12, [PET_1]),
            "",
        ),
        ("no type", offer_message("tablet", OFFER_IDS[5], []), ""),
        ("257 types", offer_message("tablet", OFFER_IDS[5], many), ""),
        (
            "a description whose root is a list",
            offer_message(
                "tablet",
                OFFER_IDS[5],
                [
                    fe.field(
                        "l",
                        "A list.",
                        fe.brick(
                            "ListField", items=fe.field("l", "A text.", fe.brick("StringField"), fe.texts())
                        ),
                        fe.texts(),
                    )
                ],
            ),
            "",
        ),
        ("a count of -1", offer_message("tablet", OFFER_IDS[5], [PET_1], count=-1), ""),
    ]
    s = new(
        "a type of a sibling's offer with a description above 256 KiB is declined",
        ["sync.md 7.2", "fields.md 9.1"],
    )
    s.receive(offer_message("tablet", OFFER_IDS[5], [large]))
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


# --- the owner's layer without a device: its merge and what it shows (sections 21.1 and 22.1) ----------


def null(stamp: int, device: bytes, schema: bytes = SCHEMA_1) -> FieldState:
    """A field state whose value is null: the owner discarded a change of the field (section 21.1)."""
    return FieldState(None, stamp, device, schema)


assert bytes_order(SCHEMA_1, SCHEMA_2) > 0, "the fingerprint of version 1 is the higher one"
# The merge of section 4 on states that hold null values, with the results that section 21.1 gives.
LAYER_MERGES: list[MergeCase] = [
    (
        "an owner's layer: a later null value is taken over a value",
        State({"a": f(1, 10, PHONE)}, None, 11),
        State({"a": null(20, TABLET)}, None, 21),
        (0, 11, 0),
        {"a": "other"},
        False,
        False,
        22,
        22,
    ),
    (
        "an owner's layer: a later value is taken over a null value",
        State({"a": null(10, PHONE)}, None, 11),
        State({"a": f(1, 20, TABLET)}, None, 21),
        (0, 11, 0),
        {"a": "other"},
        False,
        False,
        22,
        22,
    ),
    (
        "an owner's layer: with equal stamps and device keys the empty bytes are taken over a null value",
        State({"a": null(10, PHONE)}, None, 11),
        State({"a": f(b"", 10, PHONE)}, None, 12),
        (0, 11, 0),
        {"a": "other"},
        False,
        False,
        13,
        13,
    ),
    (
        "an owner's layer: with equal stamps and device keys a null value is not taken over the empty bytes",
        State({"a": f(b"", 10, PHONE)}, None, 11),
        State({"a": null(10, PHONE)}, None, 12),
        (0, 11, 0),
        {"a": "own"},
        False,
        False,
        11,
        12,
    ),
    (
        "an owner's layer: two null values with equal stamps and device keys, the higher schema is taken",
        State({"a": null(10, PHONE, SCHEMA_2)}, None, 11),
        State({"a": null(10, PHONE, SCHEMA_1)}, None, 12),
        (0, 11, 0),
        {"a": "other"},
        False,
        False,
        13,
        13,
    ),
    (
        "an owner's layer: two null values with equal stamps and device keys, the lower schema is not taken",
        State({"a": null(10, PHONE, SCHEMA_1)}, None, 11),
        State({"a": null(10, PHONE, SCHEMA_2)}, None, 12),
        (0, 11, 0),
        {"a": "own"},
        False,
        False,
        11,
        12,
    ),
    (
        "an owner's layer: a removal that is not later than a field state with a null value does not delete",
        State({"a": f(1, 10, PHONE)}, None, 11),
        State({"a": null(30, TABLET)}, gone(20, TABLET), 31),
        (0, 11, 0),
        {"a": "other"},
        True,
        False,
        32,
        32,
    ),
    (
        "an owner's layer: a removal that is later than a field state with a null value deletes",
        State({"a": null(10, PHONE)}, None, 11),
        State({}, gone(20, TABLET), 21),
        (0, 11, 0),
        {"a": "own"},
        True,
        True,
        22,
        22,
    ),
]

# What a device shows of a received record (section 22.1): whether the sender's layer is there (None
# without a record message), the owner's layer, what the record is, and for each field that shows the
# layer its value comes from. The sender's layer holds a title and a location.
SHOWN_VALUES = {"title": encoded("Vet"), "location": encoded("")}
ShownCase = tuple[str, bool | None, State | None, str, dict[str, str]]
_BOTH = {"title": "sender", "location": "sender"}
SHOWN: list[ShownCase] = [
    ("no record message and no owner's layer: the record is not there", None, None, NOT_THERE, {}),
    (
        "no record message: the record is not there, whatever the owner's layer holds",
        None,
        State({"location": f("Praxis", 200, TABLET)}, None, 201),
        NOT_THERE,
        {},
    ),
    (
        "the record is there and has no owner's layer: every field has the sender's value",
        True,
        None,
        THERE,
        _BOTH,
    ),
    (
        "the record is there: a field has the owner's value if the layer holds one for it",
        True,
        State({"location": f("Praxis", 200, TABLET)}, None, 201),
        THERE,
        {"title": "sender", "location": "owner"},
    ),
    (
        "a field state with a null value is no owner's value: the sender's value shows",
        True,
        State({"location": null(210, PHONE)}, None, 211),
        THERE,
        _BOTH,
    ),
    (
        "an owner's value for a field that the kept DATA does not have is not shown",
        True,
        State({"room": f("2", 200, TABLET, SCHEMA_2)}, None, 201),
        THERE,
        _BOTH,
    ),
    (
        "a removal that stands and is later than every field state: deleted by the owner",
        True,
        State({"location": f("Praxis", 200, TABLET)}, gone(210, PHONE), 211),
        BY_OWNER,
        {},
    ),
    (
        "a removal that stands and no field state: deleted by the owner",
        True,
        State({}, gone(210, PHONE), 211),
        BY_OWNER,
        {},
    ),
    (
        "a removal that was taken back: the record is there, with the owner's values",
        True,
        State({"location": f("Praxis", 200, TABLET)}, back(220, PHONE), 221),
        THERE,
        {"title": "sender", "location": "owner"},
    ),
    (
        "a removal that stands and a later owner's value: deleted by the owner, whatever the stamps",
        True,
        State({"location": f("Praxis", 220, TABLET)}, gone(210, PHONE), 221),
        BY_OWNER,
        {},
    ),
    (
        "a removal that stands and a later field state with a null value: deleted by the owner",
        True,
        State({"location": null(220, TABLET)}, gone(210, PHONE), 221),
        BY_OWNER,
        {},
    ),
]

# The merge of two keeps (section 21.1): the label, the keep of the device's own layer and that of the
# other, and whether the other's is taken. The higher version first, then the stamp, then the device key,
# and with all three equal the keep that is given up.
KEEP_MERGES: list[tuple[str, Keep | None, Keep, bool]] = [
    ("a keep: one that the device does not hold is taken", None, Keep(210, TABLET, 4), True),
    (
        "keeps: the higher version stands over a higher stamp, a keep for an older deletion never "
        "takes the place of one for a newer deletion",
        Keep(210, PHONE, 5),
        Keep(300, TABLET, 4),
        False,
    ),
    ("keeps: the higher version is taken", Keep(300, PHONE, 4), Keep(210, TABLET, 5), True),
    ("keeps: with equal versions the higher stamp is taken", Keep(210, PHONE, 4), Keep(220, TABLET, 4), True),
    (
        "keeps: with equal versions and stamps the higher device key is taken",
        Keep(210, PHONE, 4),
        Keep(210, TABLET, 4),
        True,
    ),
    (
        "keeps: with all three equal the keep that is given up is taken",
        Keep(210, PHONE, 4),
        Keep(210, PHONE, 4, True),
        True,
    ),
    (
        "keeps: with all three equal a keep that is not given up is not taken over one that is",
        Keep(210, PHONE, 4, True),
        Keep(210, PHONE, 4),
        False,
    ),
    ("keeps: the same keep is no part taken", Keep(210, PHONE, 4), Keep(210, PHONE, 4), False),
    (
        "keeps: a keep given up for a newer deletion stands over a keep for an older one",
        Keep(300, PHONE, 4),
        Keep(220, TABLET, 5, True),
        True,
    ),
]
KEEP_OWN = State({"location": f("Praxis", 200, TABLET)}, None, 301)
KEEP_CLOCK = (0, 301, 0)


def keep_states(own: Keep | None, other: Keep) -> tuple[State, State]:
    return dataclasses.replace(KEEP_OWN, keep=own), State({}, None, 231, other)


# A sender's layer that ends in a DELETE of the version 4 (section 22.1, rules 3a and 3b): the label,
# whether the device holds the DATA beside the tombstone, the owner's layer, and what the device shows.
TombstoneCase = tuple[str, bool, State | None, str, dict[str, str]]
_PRAXIS = {"location": f("Praxis", 200, TABLET)}
TOMBSTONES: list[TombstoneCase] = [
    ("a tombstone and no owner's layer: deleted by its sender", True, None, BY_SENDER, {}),
    (
        "a tombstone and owner's values without a keep: deleted by its sender, owner's values keep nothing",
        True,
        State(_PRAXIS, None, 201),
        BY_SENDER,
        {},
    ),
    (
        "a keep of the version of the DELETE: kept, the DATA beside the tombstone with the owner's values",
        True,
        State(_PRAXIS, None, 211, Keep(210, PHONE, 4)),
        AGAINST,
        {"title": "sender", "location": "owner"},
    ),
    (
        "a keep of a version above that of the DELETE: kept",
        True,
        State(_PRAXIS, None, 211, Keep(210, PHONE, 5)),
        AGAINST,
        {"title": "sender", "location": "owner"},
    ),
    (
        "a keep without an owner's value keeps nothing: deleted by its sender",
        True,
        State({}, None, 211, Keep(210, PHONE, 4)),
        BY_SENDER,
        {},
    ),
    (
        "a keep whose owner's values were all discarded keeps nothing: deleted by its sender",
        True,
        State({"location": null(212, PHONE)}, None, 213, Keep(210, PHONE, 4)),
        BY_SENDER,
        {},
    ),
    (
        "a keep of a version below that of the DELETE: deleted by its sender",
        True,
        State(_PRAXIS, None, 211, Keep(210, PHONE, 3)),
        BY_SENDER,
        {},
    ),
    (
        "a keep that was given up, of the version of the DELETE: deleted by its sender",
        True,
        State(_PRAXIS, None, 221, Keep(220, TABLET, 4, True)),
        BY_SENDER,
        {},
    ),
    (
        "a keep that was given up, of a version above that of the DELETE: deleted by its sender",
        True,
        State(_PRAXIS, None, 221, Keep(220, TABLET, 5, True)),
        BY_SENDER,
        {},
    ),
    (
        "a keep, but no DATA beside the tombstone: deleted by its sender",
        False,
        State(_PRAXIS, None, 211, Keep(210, PHONE, 4)),
        BY_SENDER,
        {},
    ),
    (
        "a keep and an owner's removal that stands: deleted by the owner",
        True,
        State(_PRAXIS, gone(220, TABLET), 221, Keep(210, PHONE, 4)),
        BY_OWNER,
        {},
    ),
    (
        "a keep and an owner's removal that was taken back: kept",
        True,
        State(_PRAXIS, back(230, TABLET), 231, Keep(210, PHONE, 4)),
        AGAINST,
        {"title": "sender", "location": "owner"},
    ),
]
TOMBSTONE_VERSION = 4


def check_layers(out: list[str]) -> None:
    """The merge of an owner's layer, which can hold null values (section 21.1), and what a device shows
    from the two layers (section 22.1), against the results written out above."""
    for label, own, other, clock, stands, removal_taken, is_gone, stamp, top in LAYER_MERGES:
        done = device_merge(own, other, *clock)
        got = (done.merged.stands, done.merged.removal_taken, done.deleted, done.state.state_stamp)
        assert (*got, done.highest) == (stands, removal_taken, is_gone, stamp, top), label
        # The other way round the same field states and the same removal stand (section 4.5).
        assert own is not None
        back_ = merge(other, own)
        assert (back_.fields, back_.removal) == (done.merged.fields, done.merged.removal), label
    for label, there, layer, state, sources in SHOWN:
        got_state, fields = shown(there, SHOWN_VALUES, SCHEMA_1, layer)
        assert (got_state, {n: source for n, (_, _, source) in fields.items()}) == (state, sources), label
    for label, has, layer, state, sources in TOMBSTONES:
        beside = (SHOWN_VALUES, SCHEMA_1) if has else None
        got_state, fields = shown(False, {}, None, layer, TOMBSTONE_VERSION, beside)
        assert (got_state, {n: source for n, (_, _, source) in fields.items()}) == (state, sources), label
    for label, own_keep, other_keep, taken in KEEP_MERGES:
        own, other = keep_states(own_keep, other_keep)
        done = device_merge(own, other, *KEEP_CLOCK)
        assert done.merged.keep_taken == taken and done.state.keep == (other_keep if taken else own_keep), (
            label
        )
        assert done.state.state_stamp == (302 if taken else 301), label
        back_ = merge(other, own)  # the other way round the same keep stands (section 4.5)
        assert back_.keep == done.state.keep, label
    shown_n = len(SHOWN) + len(TOMBSTONES)
    out.append(f"The owner's layer: {len(LAYER_MERGES)} merges with null values, {shown_n} records shown")


# --- sessions about what the set got from other apps (sections 17 to 24) -------------------------------

FORWARD_IDS = [f"0000000{n}-f0a0-4000-8000-00000000000{n}" for n in range(1, 10)]  # of the phone's forwards
TABLET_FORWARD = "0000000a-f0a0-4000-8000-00000000000a"  # of a forward of the tablet
TABLET_FORWARD_2 = "0000000b-f0a0-4000-8000-00000000000b"
TABLET_FORWARD_3 = "0000000c-f0a0-4000-8000-00000000000c"
TABLET_FORWARD_4 = "0000000d-f0a0-4000-8000-00000000000d"
named("the schema as offered", APPOINTMENT_OFFERED.encode())


def other_data(
    version: int,
    sender: str = "other app",
    rid: str = RECORD_ID,
    schema: str = APPOINTMENT_OFFERED,
    more: bytes = b"",
    **values: Any,
) -> bytes:
    """A DATA of another app with the appointment of section 16.1, or with other values in some fields."""
    what = f"DATA version {version}" + ("" if sender == "other app" else f" of the {sender}")
    what += "" if rid == RECORD_ID else f", id {rid[:8]}"
    what += "".join(
        f", {name} {v!r}" if isinstance(v, (str, int)) and len(str(v)) < 40 else f", {name} changed"
        for name, v in values.items()
    )
    datum = dict(APPOINTMENT) if json.loads(schema)["name"] == "Appointment" else {}
    return named(what, data_message(sender, version, schema, {**datum, **values}, rid, more))


def other_delete(version: int, sender: str = "other app", rid: str = RECORD_ID) -> bytes:
    what = f"DELETE version {version}" + ("" if sender == "other app" else f" of the {sender}")
    return named(what, data_message(sender, version, "", {}, rid))


def other_withdraw(
    version: int, to: str = "phone", sender: str = "other app", rid: str = RECORD_ID, more: bytes = b""
) -> bytes:
    """A WITHDRAW of another app, addressed to the key `to` (spec/shares.md, section 3.1)."""
    what = f"WITHDRAW version {version} to the {to}" + ("" if sender == "other app" else f" of the {sender}")
    what += "" if rid == RECORD_ID else f", id {rid[:8]}"
    body = body_of("Withdraw", {"to": KEY[to]}) + more
    return named(what, message(SEEDS[sender], "WITHDRAW", (rid, version), body))


def other_manifest(revision: int, sender: str = "other app") -> bytes:
    what = f"MANIFEST revision {revision}" + ("" if sender == "other app" else f" of the {sender}")
    return named(what, manifest_message(sender, revision, "Old Brain Fix"))


def chain_message(
    kind: str, signer: str, device: str, proof_by: str | None = None, more: bytes = b""
) -> bytes:
    """A DEVICE_ADD or a DEVICE_REMOVE of another app (spec/keys.md, sections 5.2 and 5.3); `proof_by`
    names another key that signs the proof of an addition, which then does not verify."""
    if kind == keys.ADD:
        proof = keys.sign(SEEDS[proof_by or device], keys.proof_bytes(KEY[signer], KEY[device]))
        body = body_of("DeviceAdd", {"device": KEY[device], "proof": bytes(proof)})
    else:
        body = body_of("DeviceRemove", {"device": KEY[device]})
    what = f"{kind} of the {device} by the {signer}"
    return named(what, message(SEEDS[signer], kind, None, body + more))


def forward_message(
    sender: str,
    inner: bytes,
    schema: str | None = None,
    fid: str = TABLET_FORWARD,
    to: str = "phone",
    version: int | None = 1,
    more: bytes = b"",
) -> bytes:
    """A FORWARD as a sibling writes it, or one that breaks a rule; with no version, without `record`."""
    body = body_of("Forward", {"to": KEY[to], "message": inner, "schema": schema}) + more
    return message(SEEDS[sender], "FORWARD", None if version is None else (fid, version), body)


def forward_id(m: bytes) -> str:
    """The id of the forward of a FORWARD that the device sent."""
    rid: str = read_all("Envelope", m[10:])["record"]["id"]
    return rid


def kept_json(
    m: bytes, delivered: tuple[str, ...] = (), schema: str | None = None, type_name: str | None = None
) -> dict[str, Any]:
    """A kept message of a sender in the `device` of a session, with the siblings it is delivered to."""
    return {
        "message": m.hex(),
        "schema": schema,
        "type": type_name,
        "delivered": [KEY[s].hex() for s in delivered],
    }


def layer_json(
    state: State, known: dict[str, list[str] | None], rid: str = RECORD_ID, type_name: str = APPOINTMENT_TYPE
) -> dict[str, Any]:
    """An owner's layer in the `device` of a session, in the form of a record of the set, with its keep
    in the state and, for each sibling, whether the keep is delivered to it."""
    v = record_json(state, known, rid, type_name)
    v["state"] = state_json(state, True)
    for s in v["siblings"].values():
        s["keep"] = state.keep is not None
    return {name: v[name] for name in ("id", "type", "state", "siblings")}


def sender_json(
    current: tuple[str, ...] = ("other app",),
    removed: tuple[str, ...] = (),
    origin: str | None = None,
    chain: tuple[dict[str, Any], ...] = (),
    manifests: tuple[dict[str, Any], ...] = (),
    records: tuple[dict[str, Any], ...] = (),
    layers: tuple[dict[str, Any], ...] = (),
) -> dict[str, Any]:
    """A known sender in the `device` of a session."""
    return {
        "origin": KEY[origin or current[0]].hex(),
        "current": [KEY[k].hex() for k in current],
        "removed": [KEY[k].hex() for k in removed],
        "chain": list(chain),
        "manifests": list(manifests),
        "records": list(records),
        "layers": list(layers),
    }


def received_device(
    senders: list[dict[str, Any]],
    siblings: tuple[str, ...] = ("tablet",),
    refused: tuple[str, ...] = (),
    records: tuple[dict[str, Any], ...] = (),
    on_delete: str | None = None,
    **more: Any,
) -> dict[str, Any]:
    """The `device` of a session about received records: the phone, which has given or seen the stamps up
    to 195, with the senders it knows and the ids it gives its forwards; with `on_delete`, what its set
    does with a DELETE that meets owner's values."""
    device = device_json(list(records), siblings, **{"highest": 195, **more})
    return {
        **device,
        "refused": [KEY[k].hex() for k in refused],
        "forward_ids": FORWARD_IDS,
        "senders": senders,
        **({} if on_delete is None else {"on_delete": on_delete}),
    }


def received_sessions() -> list[Session]:
    """The sessions of the phone about the messages of other apps and the owner's layers. `SAID_RECEIVED`
    holds what the rules of sections 17 to 24 require of every step."""
    out: list[Session] = []
    z = keys.zigzag
    one, two = ("tablet",), ("tablet", "laptop")
    text = APPOINTMENT_OFFERED
    m1, m2 = other_manifest(1), other_manifest(2)
    d1, d2, d3 = other_data(1), other_data(2), other_data(3)
    # Two titles for a DATA of the same version as d2 in other bytes: the first gives a lower SHA-256 than
    # d2, the second a higher one (section 20.1); each the first of its kind that does.
    doctor_title = next(
        t for t in ("Doctor", *(f"Doctor {i}" for i in range(1, 64))) if sha(other_data(2, title=t)) < sha(d2)
    )
    dentist_title = next(
        t
        for t in ("Dentist", *(f"Dentist {i}" for i in range(1, 64)))
        if sha(other_data(2, title=t)) > sha(d2)
    )
    weber = FieldState(VALUE_WEBER, 200, TABLET)
    obf = KEY["other app"]

    def new(label: str, refs: list[str], device: dict[str, Any]) -> Session:
        s = Session(label, refs, device)
        out.append(s)
        return s

    def empty(siblings: tuple[str, ...] = one, **more: Any) -> dict[str, Any]:
        """The phone knows no other sender."""
        return received_device([], siblings, **more)

    def known(
        siblings: tuple[str, ...] = one,
        delivered: tuple[str, ...] | None = None,
        layer: State | None = None,
        record: bytes = d1,
        **more: Any,
    ) -> dict[str, Any]:
        """The phone knows Old Brain Fix by its one key and keeps its MANIFEST of revision 1 and one DATA
        of the appointment, both delivered to every sibling, or to those named; with `layer`, it holds
        that owner's layer of the record, known and delivered to every sibling."""
        to = siblings if delivered is None else delivered
        layers = () if layer is None else (layer_json(layer, dict.fromkeys(siblings)),)
        if layer is not None:
            more = {"highest": 205, **more}  # it has given or seen the stamps of the layer
        sender = sender_json(
            manifests=(kept_json(m1, to),), records=(kept_json(record, to, text),), layers=layers
        )
        return received_device([sender], siblings, **more)

    def layer_change(state: int, fields: dict[str, FieldState], **more: Any) -> bytes:
        """A CHANGE of the tablet with the key of Old Brain Fix in `origin`."""
        return change_message("tablet", state, fields, **{"origin": obf, **more})

    # --- who sent it (section 18.3, steps 1 to 3) ---
    x1 = other_data(1, "second app")  # a DATA of a key that the phone does not know
    members = {"removed": ("old phone",), "others": ("other app",), "gone": ("refused",)}
    for who, what in [
        ("phone", "the device's own key is ignored"),
        ("old phone", "a removed key of the device's own set is rejected without a report"),
        ("other app", "a current key of another known sender is rejected with INVALID_MESSAGE"),
        ("refused", "a removed key of another sender, or a refused key, is rejected without a report"),
        ("stranger", "a key the device does not know is not processed"),
    ]:
        s = new(f"a FORWARD of {what}", ["sync.md 7.1", "sync.md 18.3"], empty(**members))
        s.receive(forward_message(who, x1, text))
        s.acks()
        s.about(None, "second app")
    s = new(
        "step 1: a FORWARD without a record is reported to a sibling and to another app, and to no other key",
        ["sync.md 18.1", "sync.md 18.3", "protocol.md 8.2"],
        empty(**members),
    )
    for who in ("tablet", "other app", "stranger", "old phone"):
        s.receive(forward_message(who, x1, text, version=None))
    s.acks()
    s.about(None, "second app")
    s = new(
        "step 2: the body of a FORWARD of another app is not read",
        ["sync.md 18.3", "sync.md 7.1"],
        empty(**members),
    )
    s.receive(message(SEEDS["other app"], "FORWARD", (TABLET_FORWARD, 1), b"no body of a FORWARD"))
    s.receive(message(SEEDS["stranger"], "FORWARD", (TABLET_FORWARD, 1), b"no body of a FORWARD"))
    s.acks()
    s = new("step 3: a FORWARD whose body is no axt.Forward is rejected", ["sync.md 18.3"], empty())
    s.receive(forward_message("tablet", x1, text, more=b"\x00"))
    s.receive(message(TABLET_SEED, "FORWARD", (TABLET_FORWARD, 1), body_of("Resync", {"to": PHONE})))
    s.receive(message(TABLET_SEED, "FORWARD", (TABLET_FORWARD, 1), b""))
    s.acks()
    s.about(None, "second app")
    s = new(
        "step 3: a FORWARD of a sibling for another device is ignored",
        ["sync.md 18.3", "protocol.md 9.1"],
        empty(two),
    )
    s.receive(forward_message("tablet", x1, text, to="laptop"))
    s.acks()
    s.about(None, "second app")

    # --- the id and the version of the forward (steps 4 to 6) ---
    for label, fid in [
        ("an id that is no UUID", "not-a-uuid"),
        ("the nil UUID", "00000000-0000-0000-0000-000000000000"),
        ("the max UUID", "ffffffff-ffff-ffff-ffff-ffffffffffff"),
    ]:
        s = new(f"step 4: a FORWARD with {label} is rejected", ["sync.md 18.1", "sync.md 18.3"], empty())
        s.receive(forward_message("tablet", x1, text, fid=fid))
        s.acks()
        s.about(None, "second app")
    for label, version in [("0", 0), ("-1", -1)]:
        s = new(f"step 5: a FORWARD with the version {label} is rejected", ["sync.md 18.3"], empty())
        s.receive(forward_message("tablet", x1, text, version=version))
        s.acks()
    s = new("step 6: a FORWARD with the version 2 is rejected", ["sync.md 18.1", "sync.md 18.3"], empty())
    s.receive(forward_message("tablet", x1, text, version=2))
    s.acks()
    s.about(None, "second app")

    # --- the body (steps 7 to 11 and section 18.2) ---
    def of(kind: str, record: tuple[str, int] | None, body: bytes) -> bytes:
        """A message of the second app, of whatever kind and with whatever body."""
        return message(SEEDS["second app"], kind, record, body)

    x_body: bytes = read_all("Envelope", x1[10:])["body"]
    x_manifest: bytes = read_all("Envelope", other_manifest(1, "second app")[10:])["body"]
    x_add: bytes = read_all("Envelope", chain_message(keys.ADD, "second app", "stranger")[10:])["body"]
    x_delete = other_delete(1, "second app")
    never = ("OFFER", "ACCEPT", "DECLINE", "ACK", "ERROR", "DEVICE_JOIN", "CHANGE", "RESYNC", "FORWARD")
    assert sorted((*never, "PROPOSAL_REPLY", *FORWARDED)) == sorted(KINDS)
    bodies: list[tuple[str, bytes, str | None, str]] = [
        ("step 7: an empty message", b"", text, "INVALID_MESSAGE"),
        ("step 7: a message of 9 bytes", x1[:9], text, "INVALID_MESSAGE"),
        ("step 7: a message that does not begin with C3 01", b"\xc3\x02" + x1[2:], text, "INVALID_MESSAGE"),
        (
            "step 8: a message with the fingerprint of no envelope format",
            x1[:2] + SPEC_FP["Change"] + x1[10:],
            text,
            "FORMAT_UNSUPPORTED",
        ),
        ("step 9: a message with a byte after its envelope", x1 + b"\x00", text, "INVALID_MESSAGE"),
        ("step 9: a message whose envelope is cut short", x1[:-1], text, "INVALID_MESSAGE"),
        ("step 9: a message whose format field is 2", x1[:10] + z(2) + x1[11:], text, "INVALID_MESSAGE"),
        *[
            (
                f"step 9: a forwarded {kind}",
                of(kind, (RECORD_ID, 1) if kind in ("CHANGE", "RESYNC", "FORWARD") else None, b""),
                None,
                "INVALID_MESSAGE",
            )
            # A WITHDRAW and a PROPOSAL without a record, which their kinds require (spec/shares.md, sections
            # 3.3 and 13.2), and a PROPOSAL_REPLY, which is never forwarded (section 18.2).
            for kind in (*never, "WITHDRAW", "PROPOSAL", "PROPOSAL_REPLY")
        ],
        ("step 9: a forwarded DATA without a record", of("DATA", None, x_body), text, "INVALID_MESSAGE"),
        ("step 9: a forwarded DELETE without a record", of("DELETE", None, b""), None, "INVALID_MESSAGE"),
        (
            "step 9: a forwarded MANIFEST with a record",
            of("MANIFEST", (RECORD_ID, 1), x_manifest),
            None,
            "INVALID_MESSAGE",
        ),
        (
            "step 9: a forwarded DELETE with a body",
            of("DELETE", (RECORD_ID, 1), x_body),
            None,
            "INVALID_MESSAGE",
        ),
        (
            "step 9: a forwarded DATA with an empty body",
            of("DATA", (RECORD_ID, 1), b""),
            text,
            "INVALID_MESSAGE",
        ),
        (
            "step 9: a forwarded DATA whose body has 9 bytes",
            of("DATA", (RECORD_ID, 1), x_body[:9]),
            text,
            "INVALID_MESSAGE",
        ),
        (
            "step 9: a forwarded DATA whose body does not begin with C3 01",
            of("DATA", (RECORD_ID, 1), b"\xc3\x02" + x_body[2:]),
            text,
            "INVALID_MESSAGE",
        ),
        (
            "step 9: a forwarded MANIFEST whose body has the fingerprint of axt.DeviceAdd",
            of("MANIFEST", None, MARKER + SPEC_FP["DeviceAdd"] + x_manifest[10:]),
            None,
            "INVALID_MESSAGE",
        ),
        (
            "step 9: a forwarded DEVICE_ADD whose body has the fingerprint of axt.DeviceRemove",
            of("DEVICE_ADD", None, MARKER + SPEC_FP["DeviceRemove"] + x_add[10:]),
            None,
            "INVALID_MESSAGE",
        ),
        (
            "step 9: a forwarded MANIFEST with an empty body",
            of("MANIFEST", None, b""),
            None,
            "INVALID_MESSAGE",
        ),
        ("step 9: a schema with a forwarded DELETE", x_delete, text, "INVALID_MESSAGE"),
        (
            "step 9: a schema with a forwarded MANIFEST",
            other_manifest(1, "second app"),
            text,
            "INVALID_MESSAGE",
        ),
        ("step 9: no schema with a forwarded DATA", x1, None, "INVALID_MESSAGE"),
        ("step 10: a schema of 256 KiB and one byte", x1, padded_schema(262145), "TOO_LARGE"),
        ("step 10: a schema nested to a depth of 65", x1, nested_schema(65), "TOO_LARGE"),
        ("step 10: a text above 256 KiB that is no schema, before step 11", x1, "x" * 262145, "TOO_LARGE"),
        ("step 11: a schema that is no JSON text", x1, text[:-1], "INVALID_MESSAGE"),
        ("step 11: a schema that is no schema of a record", x1, '"string"', "INVALID_MESSAGE"),
        ("step 11: a schema that is no Avro schema", x1, '{"type":"record"}', "INVALID_MESSAGE"),
        ("step 11: a schema with another fingerprint than the body names", x1, PET_1, "INVALID_MESSAGE"),
    ]
    for label, inner, schema, code in bodies:
        refs = ["sync.md 18.2", "sync.md 18.3"] + (
            ["sync.md 24.3", "envelope.md 8"] if "step 10" in label else []
        )
        s = new(f"{label} is rejected with {code}", refs, empty())
        s.receive(forward_message("tablet", inner, schema))
        s.acks()
        s.about(None, "second app")
    within: list[tuple[str, str]] = [
        ("step 10: a schema of exactly 256 KiB", padded_schema(262144)),
        ("step 10: a schema nested to a depth of 64", nested_schema(64)),
        (
            "step 11: the schema with the whitespace of its file, which has the same fingerprint",
            APPOINTMENT_FILE,
        ),
    ]
    for label, schema in within:
        named("a schema with that fingerprint", schema.encode())
        s = new(f"{label} is taken", ["sync.md 18.2", "sync.md 18.3", "sync.md 24.3"], empty())
        s.receive(forward_message("tablet", x1, schema))
        s.acks()
        s.about(sender="second app")

    # --- the signature and the sender of the message inside (steps 12 to 14) ---
    version_at = x1.index(RECORD_ID.encode()) + 36
    assert x1[version_at] == z(1)[0]
    signatures = [
        ("a changed signature", x1[:-1] + bytes([x1[-1] ^ 1])),
        ("a version changed after it was signed", x1[:version_at] + z(2) + x1[version_at + 1 :]),
        ("the signature of another key", x1[:-64] + other_data(1)[-64:]),
    ]
    for label, inner in signatures:
        s = new(
            f"step 12: a forwarded message with {label} is rejected with SIGNATURE_INVALID",
            ["sync.md 18.3", "keys.md 2.3"],
            empty(),
        )
        s.receive(forward_message("tablet", inner, text))
        s.acks()
        s.about(None, "second app")
    small = bytes([1]) + bytes(31)  # a point of small order: no valid key (spec/keys.md, section 2.3)
    sender_at = x1.index(KEY["second app"])
    assert keys.key_problem(small) is not None
    s = new(
        "step 12: a forwarded message whose sender is no valid key is rejected with SIGNATURE_INVALID",
        ["sync.md 18.3", "keys.md 2.3"],
        empty(),
    )
    s.receive(forward_message("tablet", x1[:sender_at] + small + x1[sender_at + 32 :], text))
    s.acks()
    own = other_data(1, "phone")
    s = new(
        "step 12 comes before step 13: a message of the device's own key whose signature does not verify",
        ["sync.md 18.3"],
        empty(),
    )
    s.receive(forward_message("tablet", own[:-1] + bytes([own[-1] ^ 1]), text))
    s.acks()
    for who, what in [
        ("phone", "the device's own key"),
        ("tablet", "the sibling that forwards it"),
        ("laptop", "another sibling"),
        ("old phone", "a removed key of the device's own set"),
    ]:
        s = new(
            f"step 13: a forwarded message of {what} is rejected with INVALID_MESSAGE",
            ["sync.md 18.3", "sync.md 19.2"],
            empty(two, removed=("old phone",)),
        )
        s.receive(forward_message("tablet", other_data(1, who), text))
        s.acks()
        s.about(None, who)
    s = new(
        "step 14: a forwarded message of a refused key is rejected with NOT_ACCEPTED",
        ["sync.md 18.3", "sync.md 19.2", "keys.md 3.4"],
        empty(refused=("refused",)),
    )
    s.receive(forward_message("tablet", other_data(1, "refused"), text))
    s.receive(forward_message("tablet", other_manifest(1, "refused"), fid=TABLET_FORWARD_2))
    s.acks()
    s.about(None, "refused")

    # --- a sender made known, and a message that reaches a third device (sections 19.2 and 20.3) ---
    for label, inner, schema in [
        ("MANIFEST", m1, None),
        ("DATA", d1, text),
        ("DELETE", other_delete(4), None),
    ]:
        s = new(
            f"a forwarded {label} of a key the device does not know makes a known sender, and goes on to "
            "the third device and not back",
            ["sync.md 19.2", "sync.md 18.4", "sync.md 20.1", "sync.md 20.2", "sync.md 20.3"],
            empty(two),
        )
        s.receive(forward_message("tablet", inner, schema))
        s.acks()
        s.about()

    # --- a forwarded MANIFEST (section 19.4) ---
    s = new(
        "a forwarded MANIFEST with a higher revision replaces the kept one; the same again is a duplicate",
        ["sync.md 19.4", "sync.md 18.4", "sync.md 20.1"],
        known(),
    )
    s.receive(forward_message("tablet", m2))
    s.receive(forward_message("tablet", m2))
    s.receive(forward_message("tablet", m2, fid=TABLET_FORWARD_2))
    s.acks()
    s.about(None)
    s = new(
        "a forwarded MANIFEST with a lower revision is a duplicate, and the kept one is due for that "
        "sibling again",
        ["sync.md 19.4", "sync.md 20.2"],
        received_device([sender_json(manifests=(kept_json(m2, one),))]),
    )
    s.receive(forward_message("tablet", m1))
    s.acks()
    s.about(None)
    manifest_body: bytes = read_all("Envelope", m2[10:])["body"]
    for label, inner in [
        ("the revision 0", manifest_message("other app", 0, "Old Brain Fix")),
        ("a body cut short", message(SEEDS["other app"], "MANIFEST", None, manifest_body[:-1])),
        ("a byte after its body", message(SEEDS["other app"], "MANIFEST", None, manifest_body + b"\x00")),
    ]:
        s = new(
            f"a forwarded MANIFEST with {label} is rejected with MANIFEST_INVALID",
            ["sync.md 19.4", "manifest.md 4"],
            known(),
        )
        s.receive(forward_message("tablet", inner))
        s.acks()
        s.about(None)
    s = new(
        "a forwarded MANIFEST that is not valid makes no sender known",
        ["sync.md 19.4", "sync.md 18.3"],
        empty(),
    )
    s.receive(forward_message("tablet", manifest_message("other app", 0, "Old Brain Fix")))
    s.about(None)
    moved = sender_json(("other app, new",), ("other app",), "other app", records=(kept_json(d1, one, text),))
    s = new(
        "a forwarded MANIFEST never takes the place of one that the device took live from the key itself",
        ["sync.md 19.4", "manifest.md 6"],
        known(),
    )
    s.take(other_manifest(3))
    s.receive(forward_message("tablet", other_manifest(4)))
    s.acks()
    s.about(None)
    s = new(
        "a forwarded MANIFEST of a removed key of a known sender is not taken",
        ["sync.md 19.4", "sync.md 19.2"],
        received_device([moved]),
    )
    s.receive(forward_message("tablet", m2))
    s.acks()
    s.about(None)

    # --- a forwarded DATA or DELETE (section 19.5) ---
    s = new(
        "a forwarded DATA with a higher version is taken, the same bytes again are a duplicate, and of "
        "the same version in other bytes the one with the higher SHA-256 stands",
        ["sync.md 19.5", "sync.md 18.4", "sync.md 20.1", "records.md 5.2"],
        known(),
    )
    s.receive(forward_message("tablet", d2, text))
    s.receive(forward_message("tablet", d2, text, fid=TABLET_FORWARD_2))
    dentist, doctor = other_data(2, title=dentist_title), other_data(2, title=doctor_title)
    assert sha(doctor) < sha(d2) < sha(dentist)
    s.receive(forward_message("tablet", dentist, text, fid=TABLET_FORWARD_3))
    s.receive(forward_message("tablet", doctor, text, fid=TABLET_FORWARD_4))
    s.acks()
    s.about()
    s = new(
        "a forwarded DATA with a lower version is a duplicate, and the kept message is due for that "
        "sibling again",
        ["sync.md 19.5", "sync.md 20.2", "sync.md 18.4"],
        known(record=d3),
    )
    s.receive(forward_message("tablet", d2, text))
    s.acks()
    s.about()
    s = new(
        "the version rule comes before the body: a forwarded DATA of the kept version that does not "
        "decode is a duplicate",
        ["sync.md 19.5"],
        known(),
    )
    # A byte left over that gives a lower SHA-256 than d1, so that d1 stands by the bytes as well.
    extra = next(m for m in (bytes([i]) for i in range(256)) if sha(other_data(1, more=m)) < sha(d1))
    s.receive(forward_message("tablet", other_data(1, more=extra), text))
    s.acks()
    for label, rid, version, code in [
        ("an id that is no UUID", "not-a-uuid", 2, "RECORD_ID_INVALID"),
        ("the nil UUID as its id", "00000000-0000-0000-0000-000000000000", 2, "RECORD_ID_INVALID"),
        ("the version 0", RECORD_ID, 0, "VERSION_INVALID"),
    ]:
        s = new(f"a forwarded DATA with {label} is rejected with {code}", ["sync.md 19.5"], known())
        s.receive(forward_message("tablet", other_data(version, rid=rid), text))
        s.acks()
        s.about()
    s = new(
        "a forwarded DELETE with the version 0 is rejected with VERSION_INVALID", ["sync.md 19.5"], known()
    )
    s.receive(forward_message("tablet", other_delete(0)))
    s.acks()
    s.about()
    pet = other_data(2, schema=PET_1, **tm.rules.DATA["Pet"])
    s = new(
        "a forwarded DATA of another type than the record's is rejected with TYPE_CHANGED",
        ["sync.md 19.5", "protocol.md 6.2"],
        known(),
    )
    s.receive(forward_message("tablet", pet, PET_1))
    s.acks()
    s.about()
    lone = sender_json(layers=(layer_json(State({"location": weber}, None, 205), {"tablet": None}),))
    s = new(
        "a forwarded DATA of another type than the owner's layer keeps is rejected with TYPE_CHANGED",
        ["sync.md 19.5", "sync.md 21.1"],
        received_device([lone], highest=205),
    )
    s.receive(forward_message("tablet", other_data(1, schema=PET_1, **tm.rules.DATA["Pet"]), PET_1))
    s.acks()
    s.about()
    cut = message(SEEDS["other app"], "DATA", (RECORD_ID, 2), read_all("Envelope", d2[10:])["body"][:-1])
    start = dict(date_time(10, 0, NOW), month=13)
    for label, inner, code in [
        ("a byte after its record", other_data(2, more=b"\x00"), "UNDECODABLE"),
        ("a body cut short", cut, "UNDECODABLE"),
        ("a start in a thirteenth month", other_data(2, start=start), "VALUE_INVALID"),
    ]:
        s = new(
            f"a forwarded DATA with {label} is rejected with {code}",
            ["sync.md 19.5", "protocol.md 6.2"],
            known(),
        )
        s.receive(forward_message("tablet", inner, text))
        s.acks()
        s.about()
    checked = json.loads(text)
    checked["fields"][0]["axt.pattern"] = "^[A-Z]{10}$"  # a check that the title "Vet" breaks
    checked_text = named(
        "a schema with a check", json.dumps(checked, separators=(",", ":")).encode()
    ).decode()
    assert schema_fingerprint(checked_text) == SCHEMA_1 and not re.match("^[A-Z]{10}$", APPOINTMENT["title"])
    s = new(
        "a forwarded DATA with a value that breaks a check of an attribute is taken all the same",
        ["sync.md 19.5", "metadata.md 7.1"],
        known(),
    )
    s.receive(forward_message("tablet", other_data(2, schema=checked_text), checked_text))
    s.acks()
    s.about()
    s = new(
        "a forwarded DATA of a type the device does not know is taken and kept",
        ["sync.md 19.5", "sync.md 17.2"],
        known(two),
    )
    s.receive(
        forward_message("tablet", other_data(1, rid=OTHER_ID, schema=PET_1, **tm.rules.DATA["Pet"]), PET_1)
    )
    s.acks()
    s.about(OTHER_ID)
    s = new(
        "a forwarded DATA whose schema does not resolve against the device's own is taken",
        ["sync.md 19.5"],
        known(),
    )
    s.receive(forward_message("tablet", other_data(2, schema=APPOINTMENT_3, title=7), APPOINTMENT_3))
    s.acks()
    s.about()
    s = new(
        "a forwarded DELETE leaves a tombstone, an older DATA is kept beside it, and a later DATA brings "
        "the record back",
        ["sync.md 19.5", "sync.md 20.1", "records.md 5.3"],
        known(),
    )
    s.receive(forward_message("tablet", other_delete(3)))
    s.about()
    s.receive(forward_message("tablet", d2, text, fid=TABLET_FORWARD_2))
    s.receive(forward_message("tablet", d1, text, fid=TABLET_FORWARD_4))
    s.about()
    s.receive(forward_message("tablet", other_data(4), text, fid=TABLET_FORWARD_3))
    s.acks()
    s.about()
    # A forwarded record message signed with a key removed since (sections 19.2 and 20.2).
    moved_add = chain_message(keys.ADD, "other app", "other app, new")
    moved_rem = chain_message(keys.REMOVE, "other app, new", "other app")

    def moved_away(delivered: tuple[str, ...], records: tuple[dict[str, Any], ...] = ()) -> dict[str, Any]:
        """The phone knows Old Brain Fix, which moved to a new device and removed the old key, with that
        removal delivered to the siblings named."""
        chain = (kept_json(moved_add, one), kept_json(moved_rem, delivered))
        sender = sender_json(("other app, new",), ("other app",), "other app", chain=chain, records=records)
        return received_device([sender])

    s = new(
        "a forwarded DATA of a removed key is taken when the device's removal of that key is delivered to "
        "the sibling",
        ["sync.md 19.2", "sync.md 18.3", "keys.md 3.3"],
        moved_away(one),
    )
    s.receive(forward_message("tablet", d2, text))
    s.acks()
    s.about()
    s = new(
        "a forwarded DATA of a removed key is rejected with NOT_ACCEPTED when the sibling has not shown "
        "that it has the removal, and the removal goes to it",
        ["sync.md 19.2", "sync.md 18.3", "sync.md 18.4"],
        moved_away(()),
    )
    s.receive(forward_message("tablet", d2, text))
    s.acks()
    s.about()
    s = new(
        "a sibling that has forwarded a removal of that key has it, whatever the device did with it: its "
        "DATA of the removed key is then taken",
        ["sync.md 19.2", "sync.md 20.2"],
        moved_away(()),
    )
    s.receive(forward_message("tablet", moved_rem))
    s.receive(forward_message("tablet", d2, text, fid=TABLET_FORWARD_2))
    s.acks()
    s.about()
    s = new(
        "after NOT_ACCEPTED for a message of a removed key, the sibling's forward of the removal makes it "
        "due again after the ACK; once more, and then it is settled",
        ["sync.md 20.2", "sync.md 19.2", "sync.md 18.4"],
        moved_away(one, (kept_json(d2, (), text),)),
    )
    first = s.step({"reconnect": KEY["tablet"].hex()})
    s.receive(error_message("tablet", "NOT_ACCEPTED", first[0]))
    s.receive(forward_message("tablet", moved_rem))
    again = s.acks()
    once = s.receive(
        error_message("tablet", "NOT_ACCEPTED", [m for m in again if meaning(m)[0]["kind"] == "FORWARD"][0])
    )
    s.receive(error_message("tablet", "NOT_ACCEPTED", once[0]))
    s.about()
    s = new(
        "a removal that the device only keeps to try again does not make the key removed",
        ["sync.md 19.2", "sync.md 19.3"],
        known(),
    )
    s.receive(forward_message("tablet", chain_message(keys.REMOVE, "other app", "other app, new")))
    s.receive(forward_message("tablet", d2, text, fid=TABLET_FORWARD_2))
    s.acks()
    s.about()

    # The four cases of section 19.5, step 7, in a FORWARD and from the sender itself.
    del3, del2 = other_delete(3), other_delete(2)

    def tomb(beside: bytes | None = d2, delete: bytes = del3) -> dict[str, Any]:
        """The phone holds a tombstone of the appointment, with that DATA beside it or none."""
        kept = () if beside is None else (kept_json(beside, one, text),)
        recs = (*kept, kept_json(delete, one, type_name=APPOINTMENT_TYPE))
        return received_device([sender_json(manifests=(kept_json(m1, one),), records=recs)])

    def give(s: Session, how: str, m: bytes, schema: str | None, fid: str = TABLET_FORWARD) -> None:
        """The message reaches the phone in a FORWARD of the tablet, or from the sender itself."""
        if how == "forwarded":
            s.receive(forward_message("tablet", m, schema, fid=fid))
        else:
            s.take(m, schema)

    for how in ("forwarded", "from the sender"):
        tail = "APPLIED" if how == "forwarded" else "the outcome of the version rule"
        s = new(
            f"case 1 of step 7, {how}: a DATA below the tombstone goes beside it; {tail}",
            ["sync.md 19.5", "sync.md 20.1", "records.md 5.2"],
            tomb(None),
        )
        give(s, how, d2, text)
        s.acks()
        s.about()
        s = new(
            f"case 2 of step 7, {how}: the kept message in other bytes that stands replaces it; {tail}",
            ["sync.md 19.5", "sync.md 20.1"],
            known(record=d2),
        )
        give(s, how, other_data(2, title=doctor_title), text)
        give(s, how, other_data(2, title=dentist_title), text, TABLET_FORWARD_2)
        s.acks()
        s.about()
        s = new(
            f"case 3 of step 7, {how}: a DELETE takes the place of a DATA of the same version, and nothing "
            f"stays beside it; {tail}",
            ["sync.md 19.5", "sync.md 20.1"],
            known(record=d2),
        )
        give(s, how, del2, None)
        s.acks()
        s.about()
        s = new(
            f"case 4 of step 7, {how}: the DATA beside the tombstone in other bytes that stands replaces it; "
            f"{tail}",
            ["sync.md 19.5", "sync.md 20.1"],
            tomb(),
        )
        give(s, how, other_data(2, title=doctor_title), text)
        give(s, how, other_data(2, title=dentist_title), text, TABLET_FORWARD_2)
        s.acks()
        s.about()
        s = new(
            f"a DATA below the tombstone, {how}, that does not decode is not taken",
            ["sync.md 19.5", "protocol.md 6.2"],
            tomb(None),
        )
        give(s, how, other_data(2, more=b"\x00"), text)
        s.acks()
        s.about()
    s = new(
        "a DELETE above a DELETE keeps the DATA beside the new tombstone",
        ["sync.md 19.5", "sync.md 20.1"],
        tomb(),
    )
    s.receive(forward_message("tablet", other_delete(5)))
    s.acks()
    s.about()
    s = new(
        "a DATA above the DELETE ends the DATA beside the tombstone",
        ["sync.md 20.1", "records.md 5.3"],
        tomb(),
    )
    s.receive(forward_message("tablet", other_data(4), text))
    s.acks()
    s.about()
    s = new(
        "a forwarded DATA below the DATA beside the tombstone makes only that DATA due again, not the DELETE",
        ["sync.md 20.2", "sync.md 19.5"],
        tomb(),
    )
    s.receive(forward_message("tablet", d1, text))
    s.acks()
    s = new(
        "a forwarded DELETE for an id the device does not have leaves a tombstone without a type",
        ["sync.md 19.5", "records.md 5.1", "records.md 5.3"],
        known(),
    )
    s.receive(forward_message("tablet", other_delete(3, rid=OTHER_ID)))
    s.acks()
    s.about(OTHER_ID)
    s = new(
        "a forwarded DATA changes nothing in the owner's layer, and nothing goes to its sender",
        ["sync.md 19.1", "sync.md 19.5", "sync.md 22.1", "sync.md 17.2"],
        known(layer=State({"location": weber}, None, 205)),
    )
    s.receive(forward_message("tablet", other_data(3, location="Praxis"), text))
    s.acks()
    s.about()

    # --- a forwarded DEVICE_ADD or DEVICE_REMOVE (section 19.3) ---
    add = chain_message(keys.ADD, "other app", "other app, new")
    remove = chain_message(keys.REMOVE, "other app, new", "other app")
    s = new(
        "a forwarded DEVICE_ADD and a forwarded DEVICE_REMOVE are applied and kept, one by one; a repeat "
        "of each is a duplicate",
        ["sync.md 19.3", "sync.md 18.4", "sync.md 20.1", "keys.md 5.5"],
        known(two),
    )
    s.receive(forward_message("tablet", add))
    s.receive(forward_message("tablet", add, fid=TABLET_FORWARD_2))
    s.about(None)
    s.receive(forward_message("tablet", remove, fid=TABLET_FORWARD_3))
    s.receive(forward_message("tablet", remove, fid=TABLET_FORWARD_4))
    s.acks()
    s.about()
    s = new(
        "a forwarded DEVICE_ADD whose signer the device does not know, for a current key of a known "
        "sender, adds the signer to that sender",
        ["sync.md 19.3", "keys.md 5.5"],
        known(),
    )
    s.receive(forward_message("tablet", chain_message(keys.ADD, "other app, new", "other app")))
    s.acks()
    s.about(None)
    s = new(
        "a forwarded DEVICE_ADD whose signer and device the device does not know makes the signer a "
        "known sender with both keys",
        ["sync.md 19.3", "sync.md 19.2"],
        empty(),
    )
    s.receive(forward_message("tablet", add))
    s.acks()
    s.about(None)
    early = chain_message(keys.REMOVE, "other app", "other app, new")
    s = new(
        "a forwarded DEVICE_REMOVE of a key that is not yet a key of the sender is kept and applied "
        "after the addition; it is a kept message only from then on",
        ["sync.md 19.3", "sync.md 20.1", "sync.md 20.3"],
        known(two),
    )
    s.receive(forward_message("tablet", early))
    s.about(None)
    s.receive(forward_message("tablet", add, fid=TABLET_FORWARD_2))
    s.acks()
    s.about(None)
    s = new(
        "a forwarded DEVICE_REMOVE whose signer the device does not know makes the signer a known "
        "sender and is kept to be tried again",
        ["sync.md 19.3", "sync.md 19.2"],
        empty(),
    )
    s.receive(forward_message("tablet", early))
    s.acks()
    s.about(None)
    rejected: list[tuple[str, bytes, dict[str, Any]]] = [
        (
            "a proof that does not verify",
            chain_message(keys.ADD, "other app", "other app, new", proof_by="stranger"),
            known(),
        ),
        ("its own signer as the device", chain_message(keys.REMOVE, "other app", "other app"), known()),
        (
            "a removed key as its signer and a current key as its device",
            chain_message(keys.REMOVE, "other app", "other app, new"),
            received_device([moved]),
        ),
        (
            "a signer the device does not know and a removed key of another known sender as its device",
            chain_message(keys.ADD, "second app", "other app"),
            received_device([moved]),
        ),
    ]
    for label, inner, device in rejected:
        kind = read_all("Envelope", inner[10:])["kind"]
        s = new(
            f"a forwarded {kind} with {label} is rejected with DEVICE_REJECTED",
            ["sync.md 19.3", "sync.md 18.4", "keys.md 5.5"],
            device,
        )
        s.receive(forward_message("tablet", inner))
        s.acks()
        s.about(None)
        s.about(None, "second app")
    for label, inner in [
        (
            "as its device: it counts as a key of no known sender",
            chain_message(keys.ADD, "second app", "refused"),
        ),
        (
            "as its signer: it counts as a key of no known sender",
            chain_message(keys.ADD, "refused", "second app"),
        ),
    ]:
        s = new(
            f"a forwarded DEVICE_ADD with a refused key {label}, and the key stops being refused",
            ["sync.md 19.3", "sync.md 18.3", "sync.md 20.5", "keys.md 3.4"],
            known(refused=("refused",)),
        )
        s.receive(forward_message("tablet", inner))
        s.acks()
        s.about(None, "second app")
    s = new(
        "a forwarded DEVICE_ADD rejected only because its signer is removed by now is kept and tried "
        "again: APPLIED, and no try applies it while the signer stays removed",
        ["sync.md 19.3", "keys.md 5.5"],
        received_device([moved]),
    )
    s.receive(forward_message("tablet", chain_message(keys.ADD, "other app", "second app")))
    s.receive(
        forward_message("tablet", chain_message(keys.ADD, "other app, new", "stranger"), fid=TABLET_FORWARD_2)
    )
    s.acks()
    s.about(None)
    s.about(None, "second app")
    notes = FieldState(text_value("Bring the card"), 190, TABLET)
    first_of = sender_json(
        records=(kept_json(d1, one, text),),
        layers=(layer_json(State({"location": weber}, None, 201), dict.fromkeys(one)),),
    )
    second_of = sender_json(
        ("second app",),
        records=(kept_json(x1, one, text),),
        layers=(layer_json(State({"notes": notes}, None, 191), dict.fromkeys(one)),),
    )
    s = new(
        "a forwarded DEVICE_ADD that joins two senders: one sender, the records by the version rule, "
        "and the owner's layers merged under a new state stamp",
        ["sync.md 23.4", "sync.md 19.3", "keys.md 5.5", "sync.md 21.1"],
        received_device([first_of, second_of], highest=205),
    )
    s.receive(forward_message("tablet", chain_message(keys.ADD, "other app", "second app")), (0,))
    s.acks()
    s.about()
    s.about(None, "second app")
    s = new(
        "a join whose merge takes nothing from the other layer takes no new state stamp",
        ["sync.md 23.4", "sync.md 3.3"],
        received_device(
            [
                first_of,
                sender_json(
                    ("second app",),
                    records=(kept_json(x1, one, text),),
                    layers=(layer_json(State({"location": weber}, None, 191), dict.fromkeys(one)),),
                ),
            ],
            highest=205,
        ),
    )
    s.receive(forward_message("tablet", chain_message(keys.ADD, "other app", "second app")))
    s.acks()
    s.about()
    s = new(
        "a forwarded DEVICE_ADD whose body does not decode is rejected with INVALID_MESSAGE",
        ["sync.md 19.3"],
        known(),
    )
    s.receive(forward_message("tablet", chain_message(keys.ADD, "other app", "other app, new", more=b"\x00")))
    s.acks()
    s.about(None)

    # --- the answering device forwards, and takes the outcomes (sections 17.2, 18.4, 20.2 and 20.3) ---
    s = new(
        "a DATA of another app is answered by the device that got it and forwarded to each sibling; "
        "each outcome delivers it",
        ["sync.md 17.2", "sync.md 18.1", "sync.md 18.4", "sync.md 20.1", "sync.md 20.2", "sync.md 20.3"],
        known(two),
    )
    sent = s.take(d2, text)
    s.acks()
    s.receive(ack_message("tablet", [(1, "APPLIED", 1)], rid=forward_id(sent_to(sent, "tablet"))))
    s.about()
    s.receive(ack_message("laptop", [(1, "DUPLICATE", 1)], rid=forward_id(sent_to(sent, "laptop"))))
    s.about()
    s.step({"reconnect": KEY["tablet"].hex()})
    s = new(
        "STALE for a forward is taken as DUPLICATE; the first outcome stands, and an entry for another "
        "id is ignored",
        ["sync.md 18.4", "sync.md 9.2"],
        known(),
    )
    sent = s.take(d2, text)
    s.receive(ack_message("tablet", [(1, "STALE", 7)], rid=forward_id(sent[0])))
    s.about(None)
    s.receive(ack_message("tablet", [(1, "APPLIED", 1)], rid=forward_id(sent[0])))
    s.receive(ack_message("tablet", [(1, "APPLIED", 1)], rid=FORWARD_IDS[8]))
    s.about(None)
    s = new(
        "an entry with the version 2 is no outcome of a forward",
        ["sync.md 18.4", "sync.md 9.2"],
        known(),
    )
    sent = s.take(d2, text)
    s.receive(ack_message("tablet", [(2, "APPLIED", 1)], rid=forward_id(sent[0])))
    s.about(None)
    s = new(
        "an ACK of a sibling with the outcome MERGED for a forward is not valid, and delivers nothing",
        ["sync.md 18.4", "sync.md 9.1"],
        known(),
    )
    sent = s.take(d2, text)
    s.receive(ack_message("tablet", [(1, "MERGED", 1)], rid=forward_id(sent[0])))
    s.about(None)
    s = new(
        "a later version takes the place of a kept message: it is forwarded anew, and an outcome for "
        "the forward of the earlier one delivers nothing",
        ["sync.md 18.4", "sync.md 20.1", "sync.md 20.2", "sync.md 20.3"],
        known(),
    )
    first = s.take(d2, text)
    s.take(d3, text)
    s.receive(ack_message("tablet", [(1, "APPLIED", 1)], rid=forward_id(first[0])))
    s.about()
    for code, fingerprint, what in [
        (
            "FORMAT_UNSUPPORTED for its own envelope",
            SPEC_FP["Envelope"],
            "the device sends the same FORWARD again",
        ),
        ("FORMAT_UNSUPPORTED for the message inside", SCHEMA_NONE, "the forward is settled"),
        ("NOT_ACCEPTED", None, "the forward is settled"),
        ("DEVICE_REJECTED", None, "the forward is settled"),
        ("INVALID_MESSAGE", None, "the forward is settled"),
        ("SIGNATURE_INVALID", None, "the forward is settled"),
        ("TOO_LARGE", None, "the forward is settled"),
    ]:
        s = new(
            f"after {code} of a sibling for a FORWARD, {what}",
            ["sync.md 18.4", "sync.md 20.2", "sync.md 20.3"],
            known(),
        )
        sent = s.take(d2, text)
        s.receive(error_message("tablet", code.split()[0], sent[0], fingerprint))
        s.step({"reconnect": KEY["tablet"].hex()})
        s.about(None)
    s = new(
        "an ERROR that names no forward the device keeps changes nothing",
        ["sync.md 18.4", "sync.md 9.3"],
        known(),
    )
    sent = s.take(d2, text)
    other = forward_message("phone", d2, text, fid=FORWARD_IDS[8], to="tablet")
    s.receive(error_message("tablet", "NOT_ACCEPTED", other))
    s.receive(ack_message("tablet", [(1, "APPLIED", 1)], rid=forward_id(sent[0])))
    s.about(None)
    s = new(
        "a forward that an error settled is due again after a RESYNC of that sibling, as a new forward",
        ["sync.md 18.4", "sync.md 20.2", "sync.md 20.4"],
        known(),
    )
    sent = s.take(d2, text)
    s.receive(error_message("tablet", "NOT_ACCEPTED", sent[0]))
    s.receive(resync_message("tablet"))
    s.acks()
    s.about(None)

    # --- the order, and when a FORWARD goes again (section 20.3) ---
    m_new = other_manifest(1, "other app, new")
    d_other = other_data(1, rid=OTHER_ID)
    full = sender_json(
        ("other app", "other app, new"),
        chain=(kept_json(add),),
        manifests=(kept_json(m1), kept_json(m_new)),
        records=(kept_json(d1, (), text), kept_json(d_other, (), text)),
    )
    second = sender_json(("second app",), records=(kept_json(x1, (), text),))
    s = new(
        "on the first channel to a sibling every kept message is forwarded, sender by sender: the "
        "additions, then the manifests, then the record messages",
        ["sync.md 20.3", "sync.md 20.1", "sync.md 23.3"],
        received_device([second, full]),
    )
    s.step({"reconnect": KEY["tablet"].hex()})
    s.about(None)
    s.about(None, "second app")
    s = new(
        "a FORWARD without an outcome goes again in a later connection as the same message, and after "
        "15 days as a new forward",
        ["sync.md 20.2", "sync.md 20.3", "sync.md 24.3"],
        known(),
    )
    s.take(d2, text)
    s.step({"reconnect": KEY["tablet"].hex()})
    s.step({"days": 16})
    s.step({"reconnect": KEY["tablet"].hex()})
    s = new(
        "through a relay a FORWARD without an outcome goes again after 14 days, the same message, and "
        "not before",
        ["sync.md 20.3", "sync.md 24.1", "sync.md 24.3"],
        known(relay=("tablet",)),
    )
    s.take(d2, text)
    s.step({"days": 13})
    s.step({"days": 1})
    s.step({"days": 13})
    s.step({"days": 1})
    s = new(
        "an outcome that arrives later than 15 days after the FORWARD last went is ignored",
        ["sync.md 20.2", "sync.md 24.3"],
        known(),
    )
    sent = s.take(d2, text)
    s.step({"days": 15})
    s.about(None)
    s.step({"days": 1})
    s.receive(ack_message("tablet", [(1, "APPLIED", 1)], rid=forward_id(sent[0])))
    s.about(None)
    big = other_data(2, notes="n" * (MAX_MESSAGE - 3000))
    assert len(big) < MAX_MESSAGE < len(forward_message("phone", big, text, to="tablet"))
    s = new(
        "a kept message whose FORWARD would be above 16 MiB is not forwarded; the owner's layer of its "
        "record still travels",
        ["sync.md 20.3", "sync.md 18.2", "sync.md 24.3", "sync.md 21.5"],
        known(),
    )
    s.take(big, text)
    s.owner("set", {"location": VALUE_WEBER}, (4, 0))
    s.about(None)

    # --- the answer to a RESYNC (section 20.4) ---
    layer = State({"location": weber}, None, 205)  # the phone took it from the tablet, as in section 16.7
    s = new(
        "the answer to a RESYNC holds a new forward of every kept message, then the records of the set, "
        "then the owner's layers, and then the acknowledgement",
        ["sync.md 20.4", "sync.md 11.2", "sync.md 21.5", "sync.md 3.3"],
        known(layer=layer, records=(record_json(BASE, {"tablet": None}),)),
    )
    s.receive(resync_message("tablet"), (0, 0))
    s.acks()
    s.about()
    s = new(
        "after a RESYNC the outcome of a forward that the device sent before it is ignored",
        ["sync.md 20.2", "sync.md 20.4"],
        known(),
    )
    sent = s.take(d2, text)
    s.receive(resync_message("tablet"))
    s.receive(ack_message("tablet", [(1, "APPLIED", 1)], rid=forward_id(sent[0])))
    s.about(None)

    # --- forgetting a sender (section 20.5) ---
    s = new(
        "forgetting a sender discards its kept messages and owner's layers and sends nothing; a "
        "forward of a sibling makes it known again",
        ["sync.md 20.5", "sync.md 19.2", "keys.md 3.4"],
        known(layer=layer),
    )
    s.step({"forget": obf.hex()})
    s.acks()
    s.about()
    s.receive(forward_message("tablet", d2, text))
    s.about()
    s = new(
        "after forgetting, a forward of a message signed with a removed key of the sender is rejected "
        "with NOT_ACCEPTED, and one of another key makes the sender known again",
        ["sync.md 20.5", "sync.md 18.3", "keys.md 3.4"],
        received_device([sender_json(("other app, new",), ("other app",), "other app")]),
    )
    s.step({"forget": KEY["other app, new"].hex()})
    s.about(None)
    s.receive(forward_message("tablet", d1, text))
    s.receive(forward_message("tablet", other_data(1, "other app, new"), text, fid=TABLET_FORWARD_2))
    s.acks()
    s.about(None, "other app, new")

    s = new(
        "a forwarded addition that names a forgotten key as its device makes the sender known again, and "
        "the device asks that sibling with RESYNC",
        ["sync.md 20.5", "sync.md 19.3", "keys.md 3.4"],
        known(),
    )
    s.step({"forget": obf.hex()})
    s.receive(forward_message("tablet", chain_message(keys.ADD, "second app", "other app")))
    s.acks()
    s.about(None)
    s = new(
        "a forward of a forgotten key whose message fails a later step leaves the sender forgotten",
        ["sync.md 20.5", "sync.md 18.3"],
        known(),
    )
    s.step({"forget": obf.hex()})
    s.receive(forward_message("tablet", other_data(2, more=b"\x00"), text))
    s.acks()
    s.about(None)

    s = new(
        "an installation without a sibling: the user's deletion goes on standing beside the sender's "
        "tombstone, and a later DATA is KEPT",
        ["records.md 6.3", "sync.md 21.1", "sync.md 22.2"],
        received_device(
            [
                sender_json(
                    manifests=(kept_json(m1),),
                    records=(kept_json(d2, (), text),),
                    layers=(layer_json(State({}, gone(200, PHONE), 201), {}),),
                )
            ],
            (),
        ),
    )
    s.take(other_delete(3))
    s.take(other_data(4), text)
    s.acks()
    s.about()

    # --- the chain and the MANIFEST on the removal of a sibling (sections 17.2, 19.2 and 23.2) ---
    def by(who: tuple[str, ...] | None, *senders: str) -> list[dict[str, Any]]:
        out = []
        for name in senders:
            v = sender_json((name,), records=(kept_json(other_data(1, name), two, text),))
            if who is not None:
                v["known_by"] = [KEY[k].hex() for k in who]
            out.append(v)
        return out

    s = new(
        "on the removal of a sibling the chain and the MANIFEST go at once to a sender known by the user, "
        "and to one known only by forwards of that sibling only once the user has kept it",
        ["sync.md 17.2", "sync.md 19.2", "sync.md 23.2", "keys.md 5.9"],
        received_device([*by(None, "other app"), *by(("laptop",), "second app")], two),
    )
    s.step({"remove": KEY["laptop"].hex()})
    s.about(None, "second app")
    s.step({"senders_kept": True})
    s.step({"senders_kept": True})
    s = new(
        "a sender known by forwards of two siblings is not known only by forwards of the removed one: the "
        "chain and the MANIFEST go at once",
        ["sync.md 17.2", "sync.md 19.2"],
        received_device(by(("laptop", "tablet"), "second app"), two),
    )
    s.step({"remove": KEY["laptop"].hex()})
    s = new(
        "a device that does not show the list, or whose user forgets the sender, sends it nothing because of "
        "the removal",
        ["sync.md 17.2", "sync.md 20.5"],
        received_device(by(("laptop",), "second app"), two),
    )
    s.step({"remove": KEY["laptop"].hex()})
    s.step({"forget": KEY["second app"].hex()})
    s.step({"senders_kept": True})
    s = new(
        "at the end of a move the device holds nothing back",
        ["sync.md 17.2", "keys.md 5.7"],
        received_device(by(("laptop",), "second app"), two),
    )
    s.step({"remove": KEY["laptop"].hex(), "move": True})
    s = new(
        "each sibling that forwards a message of a sender known by forwards is recorded",
        ["sync.md 19.2"],
        received_device([], two),
    )
    s.receive(forward_message("tablet", x1, text))
    s.receive(forward_message("laptop", x1, text, fid=TABLET_FORWARD_2))
    s.acks()
    s.about(None, "second app")

    # --- a removed and a new device (sections 23.2 and 23.3) ---
    s = new(
        "after the removal of a sibling the device keeps nothing for it and takes no outcome and no "
        "FORWARD of it; its kept messages stay",
        ["sync.md 23.2", "sync.md 20.2"],
        known(two),
    )
    sent = s.take(d2, text)
    s.step({"remove": KEY["laptop"].hex()})
    s.receive(ack_message("laptop", [(1, "APPLIED", 1)], rid=forward_id(sent_to(sent, "laptop"))))
    s.receive(forward_message("laptop", d3, text))
    s.acks()
    s.about()
    s = new(
        "a device that joins gets every kept message, and after the offer every owner's layer whole",
        ["sync.md 23.3", "sync.md 20.3", "sync.md 21.5", "sync.md 7.2"],
        known(layer=layer),
    )
    s.step({"add": LAPTOP.hex()})
    s.receive(answer_message("laptop", OFFER_IDS[0], APPOINTMENT_TYPE))
    s.about()

    # --- a restored device (section 23.1) ---
    unstamped = State({"location": FieldState(VALUE_WEBER, 0, PHONE)}, None, 150)
    backup_sender = sender_json(
        manifests=(kept_json(m1),),
        records=(kept_json(d1, (), text),),
        layers=(layer_json(unstamped, {}),),
    )
    s = new(
        "a restored device forwards nothing and sends no layer before its request is acknowledged; "
        "a field never stamped of a layer gets the stamp -1",
        ["sync.md 23.1", "sync.md 12.1", "sync.md 4.6", "sync.md 20.3", "sync.md 3.3"],
        known(layer=layer),
    )
    backup = {"highest": "150", "records": [], "acted": {}, "senders": [backup_sender], "refused": []}
    s.step({"restore": backup, "now_ms": "0", "r": []})
    s.about()
    s.receive(forward_message("tablet", d1, text))
    s.receive(forward_message("tablet", d2, text, fid=TABLET_FORWARD_2))
    s.receive(request_ack("tablet", REQUEST_IDS[0]))
    s.receive(answer_message("tablet", OFFER_IDS[0], APPOINTMENT_TYPE), (0,))
    s.acks()
    s.about()

    # --- a file of another app (section 24.2) ---
    s = new(
        "what a device takes from a file of another app it forwards, and reports to no one",
        ["sync.md 24.2", "sync.md 17.1", "sync.md 22.2", "transports.md 2.2"],
        known(),
    )
    s.take(m2, file=True)
    s.take(d2, text, file=True)
    s.take(d2, text, file=True)
    s.acks()
    s.about()
    s = new(
        "a MANIFEST of a file replaces the kept one only with a higher revision; one that the app sends "
        "in a live connection applies whatever its revision",
        ["sync.md 24.2", "sync.md 20.1", "manifest.md 6"],
        received_device([sender_json(manifests=(kept_json(m2, one),))]),
    )
    s.take(m1, file=True)
    s.take(m1)
    s.about(None)

    # --- the owner's layer: what a change stamps and sends (sections 21.1, 21.2, 21.3 and 21.5) ---
    s = new(
        "a change of a received record goes whole in a CHANGE with the sender's key in origin, and "
        "the next change in part",
        ["sync.md 21.1", "sync.md 21.2", "sync.md 21.3", "sync.md 21.5", "sync.md 16.7"],
        known(),
    )
    s.owner("set", {"location": VALUE_WEBER}, (4, 0))
    s.receive(ack_message("tablet", [(201, "APPLIED", 205)]))
    s.about()
    s.owner("set", {"notes": text_value("bring the vaccination card")}, (4, 0))
    s.about()
    s = new(
        "discarding a change gives the field a null value with the schema of the field state it replaces",
        ["sync.md 21.1", "sync.md 21.2", "sync.md 22.1"],
        known(layer=layer),
    )
    s.owner("discard", {"location": None}, (4, 0))
    s.about()
    s = new(
        "deleting a received record puts a removal into the owner's layer, and taking it again a "
        "removal that was taken back",
        ["sync.md 21.1", "sync.md 21.2", "sync.md 22.1", "records.md 6.3"],
        known(layer=layer),
    )
    s.owner("delete", {}, (4, 0))
    s.about()
    s.owner("take_back", {}, (4, 0))
    s.about()
    s = new(
        "the FORWARD of a record's kept message goes before the CHANGE of its owner's layer",
        ["sync.md 20.3", "sync.md 21.5"],
        known(delivered=()),
    )
    s.owner("set", {"location": VALUE_WEBER}, (4, 0))
    s = new(
        "the schema that a field state of a layer names is offered before the CHANGE",
        ["sync.md 21.5", "sync.md 7.2"],
        known(accepted={}),
    )
    s.owner("set", {"location": VALUE_WEBER}, (4, 0))
    s.receive(answer_message("tablet", OFFER_IDS[0], APPOINTMENT_TYPE))
    s = new(
        "origin is the key by which the device first knew the sender, also when that key is removed",
        ["sync.md 21.3"],
        received_device([moved]),
    )
    s.owner("set", {"location": VALUE_WEBER}, (4, 0), sender="other app, new")
    s.about(sender="other app, new")

    s = new(
        "at the limit of the stamps a device changes no received record",
        ["sync.md 21.1", "sync.md 21.2", "sync.md 2.3"],
        known(highest=LAST_CHANGE_BASE),
    )
    s.owner("set", {"location": VALUE_WEBER}, (0, 0))
    s.about()
    s = new(
        "a device that can take no state stamp for a layer merges it and sends no CHANGE of it",
        ["sync.md 21.5", "sync.md 21.1", "sync.md 2.3", "sync.md 9.1"],
        known(two, highest=MAX - 5),
    )
    s.receive(layer_change(201, {"location": weber}), (0,))
    s.acks()
    s.about()

    # --- a CHANGE with a key in origin: processing (section 21.4) ---
    s = new(
        "a CHANGE with a key in origin is merged into the owner's layer: a device without the layer "
        "takes it, also from a message that is not whole",
        ["sync.md 21.4", "sync.md 21.3", "sync.md 8.4", "sync.md 22.1", "sync.md 16.7"],
        known(),
    )
    s.receive(layer_change(201, {"location": weber}), (3,))
    s.acks()
    s.about()
    s = new(
        "a later field state of a layer is taken, the same is a duplicate, and an earlier one is "
        "stale and makes the device's own due again",
        ["sync.md 21.4", "sync.md 8.4", "sync.md 10.1"],
        known(layer=layer),
    )
    later_ = FieldState(text_value("Praxis"), 210, TABLET)
    s.receive(layer_change(211, {"location": later_}), (0,))
    s.receive(layer_change(211, {"location": later_}))
    s.receive(layer_change(201, {"location": weber}))
    s.acks()
    s.about()
    s = new(
        "a null value in a layer is a field state like any other: a later one is taken, and the "
        "sender's value shows again",
        ["sync.md 21.1", "sync.md 21.4", "sync.md 22.1"],
        known(layer=layer),
    )
    s.receive(layer_change(211, {"location": FieldState(None, 210, TABLET)}), (0,))
    s.acks()
    s.about()
    s = new(
        "with equal stamps and device keys a null value is lower than a value",
        ["sync.md 21.1", "sync.md 4.1"],
        known(layer=layer),
    )
    s.receive(layer_change(201, {"location": FieldState(None, 200, TABLET)}))
    s.acks()
    s.about()
    s = new(
        "with equal stamps and device keys a value is taken over a null value",
        ["sync.md 21.1", "sync.md 4.1"],
        known(layer=State({"location": FieldState(None, 200, TABLET)}, None, 205)),
    )
    s.receive(layer_change(201, {"location": weber}), (0,))
    s.acks()
    s.about()
    s = new(
        "a removal in a layer deletes the record by the owner on the device that merges it, and one "
        "that was taken back brings it back",
        ["sync.md 21.1", "sync.md 21.4", "sync.md 22.1", "sync.md 4.3"],
        known(layer=layer),
    )
    s.receive(layer_change(211, {}, removal=Removal(210, TABLET)), (0,))
    s.about()
    s.receive(layer_change(221, {}, removal=Removal(220, TABLET, False)), (0,))
    s.acks()
    s.about()
    s = new(
        "a layer is held without the record: a CHANGE before the FORWARD of the record is taken, with "
        "the schema of the sibling's offer, and the record shows once its message arrives",
        ["sync.md 21.1", "sync.md 21.4", "sync.md 22.1", "sync.md 20.3"],
        received_device([sender_json()]),
    )
    s.receive(offer_message("tablet", OFFER_IDS[5], [text]))
    s.receive(layer_change(201, {"location": weber}), (3,))
    s.about()
    s.step({"reconnect": KEY["tablet"].hex()})
    s.receive(layer_change(211, {"notes": FieldState(text_value("call first"), 210, TABLET)}), (0,))
    s.receive(forward_message("tablet", d1, text))
    s.acks()
    s.about()
    room = FieldState(ROOM, 200, TABLET, SCHEMA_2)
    s = new(
        "steps 7 and 8: the schema is looked up among those of the record's sender and of the sibling's "
        "offers, not among the device's own",
        ["sync.md 21.4", "keys.md 2.4"],
        known(schemas=(APPOINTMENT_1, APPOINTMENT_2)),
    )
    s.receive(layer_change(201, {"room": room}))
    s.acks()
    s.about()
    x2 = other_data(1, "second app", schema=APPOINTMENT_2, room="2")
    s = new(
        "step 7: a schema that the device keeps of another sender only is not found",
        ["sync.md 21.4", "keys.md 2.4"],
        received_device(
            [
                sender_json(records=(kept_json(d1, one, text),)),
                sender_json(("second app",), records=(kept_json(x2, one, APPOINTMENT_2),)),
            ]
        ),
    )
    s.receive(layer_change(201, {"room": room}))
    s.acks()
    s = new(
        "step 7 holds for an entry with a null value as well",
        ["sync.md 21.4"],
        known(),
    )
    s.receive(layer_change(201, {"room": FieldState(None, 200, TABLET, SCHEMA_2)}))
    s.acks()
    for label, name, value in [
        ("a value", "nowhere", VALUE_WEBER),
        ("a null value", "nowhere", None),
    ]:
        s = new(
            f"step 8: an entry with {label} whose name is no field of its schema is rejected",
            ["sync.md 21.4", "sync.md 8.3"],
            known(),
        )
        s.receive(layer_change(201, {name: FieldState(value, 200, TABLET)}))
        s.acks()
        s.about()
    s = new(
        "step 9: a CHANGE with another type than the sender's layer keeps is rejected with TYPE_CHANGED",
        ["sync.md 21.4"],
        known(),
    )
    s.receive(layer_change(211, {}, removal=Removal(210, TABLET), type_name=PET_TYPE))
    s.acks()
    s.about()
    for who, what, code in [
        ("phone", "the device's own key", "INVALID_MESSAGE"),
        ("tablet", "a sibling", "INVALID_MESSAGE"),
        ("old phone", "a removed key of the device's own set", "INVALID_MESSAGE"),
        ("stranger", "a key of no known sender", "RECORD_UNKNOWN"),
        ("refused", "a refused key", "RECORD_UNKNOWN"),
    ]:
        s = new(
            f"step 10: a CHANGE whose origin is {what} is rejected with {code}",
            ["sync.md 21.4", "sync.md 21.3"],
            known(removed=("old phone",), refused=("refused",)),
        )
        s.receive(layer_change(211, {}, removal=Removal(210, TABLET), origin=KEY[who]))
        s.acks()
    s = new(
        "step 10 comes before step 7: with a schema it does not hold, a CHANGE whose origin is no known "
        "sender is rejected with RECORD_UNKNOWN",
        ["sync.md 21.4"],
        known(),
    )
    s.receive(layer_change(201, {"location": weber}, origin=KEY["stranger"]))
    s.acks()
    s = new(
        "step 10: origin names the sender by a removed key and by a second current key as well",
        ["sync.md 21.4", "sync.md 21.3"],
        received_device(
            [
                sender_json(
                    ("other app, new", "second app"),
                    ("other app",),
                    "other app, new",
                    records=(kept_json(d1, one, text),),
                )
            ]
        ),
    )
    s.receive(layer_change(201, {"location": weber}), (3,))
    s.receive(
        layer_change(
            211, {"notes": FieldState(text_value("call first"), 210, TABLET)}, origin=KEY["second app"]
        ),
        (0,),
    )
    s.acks()
    s.about(sender="other app, new")
    bad_start = FieldState(field_value(APPOINTMENT_JSON, "start", start), 200, TABLET)
    for label, fields, code in [
        ("a value that does not decode", {"location": FieldState(b"\x7f", 200, TABLET)}, "UNDECODABLE"),
        ("a time value that is not valid", {"start": bad_start}, "VALUE_INVALID"),
    ]:
        s = new(
            f"steps 11 and 12: a CHANGE with a key in origin and {label} is rejected with {code}",
            ["sync.md 21.4", "sync.md 8.3"],
            known(),
        )
        s.receive(layer_change(201, fields))
        s.acks()
        s.about()

    # --- RECORD_UNKNOWN for a layer (section 21.5) ---
    s = new(
        "after RECORD_UNKNOWN for a layer the device forwards the sender's kept messages again and "
        "sends the layer only when the sibling has an outcome, APPLIED or DUPLICATE, for one",
        ["sync.md 21.5", "sync.md 20.2", "sync.md 9.3", "sync.md 10.3"],
        known(relay=("tablet",)),
    )
    sent = s.owner("set", {"location": VALUE_WEBER}, (4, 0))
    again = s.receive(error_message("tablet", "RECORD_UNKNOWN", sent[0]))
    s.about()
    s.step({"days": 14})
    s.receive(ack_message("tablet", [(1, "DUPLICATE", 1)], rid=forward_id(again[1])))
    s.receive(ack_message("tablet", [(1, "APPLIED", 1)], rid=forward_id(again[0])))
    s.about()
    s = new(
        "after RECORD_UNKNOWN for a layer a change of the owner sends the layer whole, once",
        ["sync.md 21.5"],
        known(relay=("tablet",)),
    )
    sent = s.owner("set", {"location": VALUE_WEBER}, (4, 0))
    s.receive(error_message("tablet", "RECORD_UNKNOWN", sent[0]))
    s.step({"days": 14})
    sent = s.owner("set", {"notes": text_value("call first")}, (4, 0))
    s.receive(
        error_message(
            "tablet",
            "RECORD_UNKNOWN",
            sent_to([m for m in sent if meaning(m)[0]["kind"] == "CHANGE"], "tablet"),
        )
    )
    s.step({"days": 14})
    s = new(
        "after RECORD_UNKNOWN twice in a row for a layer, an outcome for a forward no longer ends the "
        "wait; a change of the owner does",
        ["sync.md 21.5"],
        known(),
    )
    sent = s.owner("set", {"location": VALUE_WEBER}, (4, 0))
    again = s.receive(error_message("tablet", "RECORD_UNKNOWN", sent[0]))
    layer_again = s.receive(ack_message("tablet", [(1, "APPLIED", 1)], rid=forward_id(again[0])))
    more = s.receive(error_message("tablet", "RECORD_UNKNOWN", sent_to(layer_again, "tablet")))
    s.receive(ack_message("tablet", [(1, "DUPLICATE", 1)], rid=forward_id(more[0])))
    s.owner("set", {"notes": text_value("call first")}, (4, 0))
    s = new(
        "after RECORD_UNKNOWN for a layer a RESYNC of that sibling ends the wait",
        ["sync.md 21.5", "sync.md 20.4"],
        known(),
    )
    sent = s.owner("set", {"location": VALUE_WEBER}, (4, 0))
    s.receive(error_message("tablet", "RECORD_UNKNOWN", sent[0]))
    s.receive(resync_message("tablet"), (0,))
    s.acks()

    # --- what the answering device reports (sections 17.2 and 22.2; spec/records.md, sections 5.2 and 6) ---
    s = new(
        "the steps 1 to 4 of the example of section 22.4, on the phone",
        ["sync.md 22.4", "sync.md 22.2", "sync.md 17.2", "sync.md 16.5", "sync.md 16.6", "sync.md 16.7"],
        received_device([sender_json()]),
    )
    v3 = other_data(3, start=date_time(10, 30, NOW + 1_800_000), notes="Bring the vaccination card")
    sent = s.take(m1)
    s.receive(ack_message("tablet", [(1, "APPLIED", 1)], rid=forward_id(sent[0])))
    sent = s.take(d1, text)
    s.receive(ack_message("tablet", [(1, "APPLIED", 1)], rid=forward_id(sent[0])))
    s.receive(layer_change(201, {"location": weber}, whole=True), (3,))
    s.acks()
    s.about()
    s.take(v3, text)
    s.take(v3, text)
    s.acks()
    s.about()
    # Steps 5 and 6 of section 22.4: a set that deletes, and a set that keeps.
    d4, d5 = other_delete(4), other_data(5)
    weber_v3 = sender_json(
        manifests=(kept_json(m1, one),),
        records=(kept_json(v3, one, text),),
        layers=(layer_json(State({"location": weber}, None, 205), dict.fromkeys(one)),),
    )
    for choice, what in [
        ("delete", "a set that deletes tidies the layer, APPLIED, and the record is deleted by its sender"),
        ("keep", "a set that keeps sets a keep, KEPT, and the record is kept against the deletion"),
    ]:
        s = new(
            f"{what}: the steps 5 and 6 of the example of section 22.4, on the phone",
            ["sync.md 22.4", "sync.md 22.2", "sync.md 22.1", "sync.md 21.2", "records.md 6.4"],
            received_device([weber_v3], highest=205, on_delete=choice),
        )
        s.take(d4, None, (4, 0))
        s.acks()
        s.about()
        s.take(d5, text)
        s.acks()
        s.about()
    s = new(
        "a DELETE that meets an owner's removal that stands changes nothing in the layer: APPLIED",
        ["sync.md 22.2", "sync.md 22.1", "records.md 6.3"],
        received_device(
            [
                sender_json(
                    manifests=(kept_json(m1, one),),
                    records=(kept_json(d2, one, text),),
                    layers=(
                        layer_json(State({"location": weber}, gone(203, TABLET), 205), dict.fromkeys(one)),
                    ),
                )
            ],
            highest=205,
            on_delete="keep",
        ),
    )
    s.take(other_delete(3))
    s.acks()
    s.about()
    s = new(
        "a set that keeps sets no keep for a record of which it holds no DATA: it tidies the layer",
        ["sync.md 22.2", "sync.md 21.1", "sync.md 21.2"],
        received_device(
            [sender_json(layers=(layer_json(State({"location": weber}, None, 205), dict.fromkeys(one)),))],
            highest=205,
            on_delete="keep",
        ),
    )
    s.take(other_delete(3), None, (4, 0))
    s.acks()
    s.about()
    s = new(
        "a device that can take no stamp sets no keep and tidies nothing: APPLIED for the DELETE",
        ["sync.md 22.2", "sync.md 2.3"],
        received_device([weber_v3], highest=LAST_CHANGE_BASE, on_delete="keep"),
    )
    s.take(d4, None, (0, 0))
    s.acks()
    s.about()
    kept_v4 = sender_json(
        manifests=(kept_json(m1, one),),
        records=(kept_json(v3, one, text), kept_json(d4, one)),
        layers=(layer_json(State({"location": weber}, None, 211, Keep(210, PHONE, 4)), dict.fromkeys(one)),),
    )
    s = new(
        "the further ACK: after KEPT for a DELETE, the user gives up the keep and the device sends APPLIED",
        ["sync.md 22.3", "sync.md 21.2", "protocol.md 7.3"],
        received_device([weber_v3], highest=205, on_delete="keep"),
    )
    s.take(d4, None, (4, 0))
    s.acks()
    s.owner("give_up", {}, (1, 0))
    s.acks()
    s.about()
    s = new(
        "the further ACK: a keep given up on the tablet reaches the answering device in a CHANGE",
        ["sync.md 22.3", "sync.md 21.4", "protocol.md 7.3"],
        received_device([weber_v3], highest=205, on_delete="keep"),
    )
    s.take(d4, None, (4, 0))
    s.acks()
    s.receive(layer_change(221, {}, keep=Keep(220, TABLET, 4, True)), (0,))
    s.acks()
    s.about()
    s = new(
        "no further ACK when a later message of the sender has arrived in between",
        ["sync.md 22.3"],
        received_device([weber_v3], highest=205, on_delete="keep"),
    )
    s.take(d4, None, (4, 0))
    s.take(d5, text)
    s.acks()
    s.owner("set", {"location": VALUE_WEBER}, (1, 0))
    s.acks()
    s = new(
        "the further ACK: after KEPT for a DATA of a record the owner deleted, the user takes it again",
        ["sync.md 22.3", "sync.md 22.2", "records.md 6.3", "protocol.md 7.3"],
        known(layer=State({}, Removal(200, TABLET), 205), record=d2),
    )
    s.take(d3, text)
    s.acks()
    s.owner("take_back", {}, (1, 0))
    s.acks()
    s.about()
    s = new(
        "a keep that arrives after APPLIED for the DELETE and the tidying keeps nothing: the layer holds "
        "no owner's value",
        ["sync.md 22.2", "sync.md 22.1", "sync.md 21.4"],
        received_device([weber_v3], highest=205),
    )
    s.take(d4, None, (4, 0))
    s.acks()
    s.receive(layer_change(221, {}, keep=Keep(220, TABLET, 4)), (0,))
    s.acks()
    s.about()
    s = new(
        "a keep with an owner's value that arrives after APPLIED for the DELETE shows the record again and "
        "is not reported",
        ["sync.md 22.3", "sync.md 22.1", "sync.md 21.4"],
        received_device([sender_json(manifests=(kept_json(m1, one),), records=(kept_json(v3, one, text),))]),
    )
    s.take(d4)
    s.acks()
    s.receive(layer_change(221, {"location": weber}, keep=Keep(220, TABLET, 4)), (0,))
    s.acks()
    s.about()
    s = new(
        "the user keeps a record that its sender deleted only with an owner's value, and gives the keep "
        "up again",
        ["sync.md 21.2", "sync.md 21.1", "sync.md 22.1", "sync.md 21.5"],
        received_device(
            [
                sender_json(
                    manifests=(kept_json(m1, one),), records=(kept_json(v3, one, text), kept_json(d4, one))
                )
            ]
        ),
    )
    s.about()
    s.owner("keep", {}, ())
    s.owner("give_up", {}, ())
    s.owner("set", {"location": VALUE_WEBER}, (4, 0))
    s.owner("keep", {}, (4, 0))
    s.about()
    s.owner("give_up", {}, (4, 0))
    s.about()
    s = new(
        "a keep in a CHANGE is a part: an earlier one is STALE and makes the device's keep due again",
        ["sync.md 21.4", "sync.md 21.1", "sync.md 8.4"],
        received_device([kept_v4], highest=211),
    )
    s.receive(layer_change(215, {}, keep=Keep(209, TABLET, 4)))
    s.receive(layer_change(216, {}, keep=Keep(210, PHONE, 4)))
    s.acks()
    s = new(
        "a DATA beside a tombstone travels to a new device, before the DELETE",
        ["sync.md 23.3", "sync.md 20.1", "sync.md 20.3", "sync.md 22.1"],
        received_device([kept_v4], highest=211),
    )
    s.step({"add": KEY["laptop"].hex()})
    s = new(
        "a DATA for a record that the owner deleted stays deleted: KEPT; an older one is STALE",
        ["sync.md 22.2", "sync.md 22.1", "records.md 6.3", "records.md 5.2"],
        known(layer=State({}, Removal(200, TABLET), 205), record=d2),
    )
    s.take(d3, text)
    s.take(d1, text)
    s.acks()
    s.about()
    s = new(
        "a DATA that brings the owner's value is APPLIED, and the owner's layer stays",
        ["sync.md 22.2", "records.md 6.1"],
        known(layer=layer),
    )
    s.take(other_data(2, location=WEBER), text)
    s.acks()
    s.about()
    s = new(
        "a DELETE of a record without an owner's layer leaves a tombstone on the answering device and, "
        "forwarded, on its sibling",
        ["sync.md 22.2", "sync.md 22.1", "records.md 5.3"],
        known(),
    )
    s.take(other_delete(2))
    s.acks()
    s.about()
    withdraw_sessions(new, known, tomb, weber_v3, text, d1, one, moved_away)
    proposal_sessions(new, known)
    return out


PROPOSAL_IDS = [f"0000000{n}-9e0a-4000-8000-00000000000{n}" for n in range(1, 6)]  # of other apps


def other_proposal(
    n: int,
    to: str = "phone",
    sender: str = "other app",
    rid: str = OTHER_ID,
    version: int = 1,
    values: dict[str, bytes] | None = None,
    more: bytes = b"",
    schema: bytes = SCHEMA_1,
) -> bytes:
    """A PROPOSAL of another app with the proposal id PROPOSAL_IDS[n], for the record of the set with the id
    `rid`, addressed to the key `to` (spec/shares.md, section 13.1)."""
    what = f"PROPOSAL {n + 1} to the {to}" + ("" if sender == "other app" else f" of the {sender}")
    vs = {"location": VALUE_WEBER} if values is None else values
    fields = [{"name": k, "schema": schema, "value": v} for k, v in vs.items()]
    body = body_of("Proposal", {"to": KEY[to], "proposal_id": PROPOSAL_IDS[n], "fields": fields}) + more
    return named(what, message(SEEDS[sender], "PROPOSAL", (rid, version), body))


def proposal_sessions(
    new: Callable[[str, list[str], dict[str, Any]], Session], known: Callable[..., dict[str, Any]]
) -> None:
    """The sessions about a PROPOSAL of another app for a record of the set (spec/shares.md, section 17),
    and about the proposer's value as a change of the owner's layer (section 17.2 there)."""
    obf = KEY["other app"].hex()
    refs = ["shares.md 17.1", "sync.md 19.6", "sync.md 20.1"]
    mine = record_json(BASE, {"tablet": None}, OTHER_ID)

    def owner(shared: bool = True, **more: Any) -> dict[str, Any]:
        """The phone holds the appointment of section 16.1 as a record of the set under OTHER_ID, shared
        with Old Brain Fix, which it knows as in the sessions above."""
        d = known(records=(mine,), **more)
        d["shares"] = {OTHER_ID: [obf] if shared else []}
        return d

    def about(s: Session, sender: str = "other app") -> None:
        s.step({"proposals": KEY[sender].hex()})

    p1 = other_proposal(0)
    s = new("the answering device takes a PROPOSAL, keeps it and forwards it with no schema", refs, owner())
    s.take(p1)
    about(s)
    s.take(p1)
    s.acks()
    s.about(None)
    s = new(
        "the answering device answers ACCEPTED: the reply to the key "
        "that signed, and the values as one change",
        [*refs, "shares.md 15.2", "sync.md 3.5"],
        owner(),
    )
    s.take(p1)
    s.step(
        {
            "answer": {"sender": obf, "proposal_id": PROPOSAL_IDS[0], "answer": "ACCEPTED"},
            "now_ms": "0",
            "r": [5, 0],
        }
    )
    about(s)
    s.query(OTHER_ID)
    s.take(p1)
    s = new(
        "ACCEPTED stamps every proposed field, also one whose value the record holds already",
        [*refs, "shares.md 15.2", "sync.md 3.5"],
        owner(),
    )
    s.take(other_proposal(0, values={"location": VALUE["location"]}))
    s.step(
        {
            "answer": {"sender": obf, "proposal_id": PROPOSAL_IDS[0], "answer": "ACCEPTED"},
            "now_ms": "0",
            "r": [5, 0],
        }
    )
    s.query(OTHER_ID)
    s = new("an answer DECLINED: the reply, and nothing changes", [*refs, "shares.md 15.1"], owner())
    s.take(p1)
    s.step(
        {
            "answer": {"sender": obf, "proposal_id": PROPOSAL_IDS[0], "answer": "DECLINED"},
            "now_ms": "0",
            "r": [5, 0],
        }
    )
    s.query(OTHER_ID)
    s = new("a forwarded PROPOSAL is taken and kept without a reply", refs, owner())
    s.receive(forward_message("tablet", other_proposal(0, "tablet"), None))
    s.receive(forward_message("tablet", other_proposal(0, "tablet"), None, fid=TABLET_FORWARD_2))
    s.acks()
    about(s)
    s.about(None)
    for to, what in [("phone", "the device's own key"), ("old phone", "a removed key of the set")]:
        s = new(f"a forwarded PROPOSAL addressed to {what} is taken", refs, owner(removed=("old phone",)))
        s.receive(forward_message("tablet", other_proposal(0, to), None))
        s.acks()
    for label, m in [
        ("addressed to a key of no device of the set", other_proposal(0, "stranger")),
        ("whose body has a byte left over", other_proposal(0, "tablet", more=b"\x00")),
        ("with the id vet", other_proposal(0, "tablet", rid="vet")),
        ("with the version 0", other_proposal(0, "tablet", version=0)),
        ("with no entry", other_proposal(0, "tablet", values={})),
    ]:
        s = new(f"a forwarded PROPOSAL {label} is rejected", refs, owner())
        s.receive(forward_message("tablet", m, None))
        s.acks()
        about(s)
    s = new(
        "a forwarded PROPOSAL of a removed key of its sender is not taken",
        refs,
        owner(),
    )
    s.receive(forward_message("tablet", chain_message(keys.ADD, "other app", "second app"), None))
    s.receive(
        forward_message(
            "tablet", chain_message(keys.REMOVE, "second app", "other app"), None, fid=TABLET_FORWARD_2
        )
    )
    s.receive(forward_message("tablet", other_proposal(0), None, fid=TABLET_FORWARD_3))
    s.acks()
    s = new(
        "a forwarded PROPOSAL of a key of the device's own set is rejected",
        [*refs, "sync.md 18.3", "shares.md 17.2"],
        owner(),
    )
    s.receive(forward_message("tablet", other_proposal(0, sender="tablet"), None))
    s.acks()
    s = new(
        "a forwarded PROPOSAL for a record the device does not show is kept, shown once the share arrives",
        refs,
        owner(shared=False),
    )
    s.receive(forward_message("tablet", other_proposal(0, "tablet"), None))
    about(s)
    s.step({"share": {"id": OTHER_ID, "sender": obf, "shared": True}})
    about(s)
    s = new(
        "a forwarded PROPOSAL that the device never shows ends after 14 days",
        refs,
        owner(shared=False),
    )
    s.receive(forward_message("tablet", other_proposal(0, "tablet"), None))
    s.acks()
    s.step({"days": 13})
    about(s)
    s.step({"days": 1})
    about(s)
    s = new(
        "a kept PROPOSAL ends when the record leaves the shares for the proposer, and when it is deleted",
        [*refs, "shares.md 15.4"],
        owner(),
    )
    s.take(p1)
    s.take(other_proposal(1))
    s.step({"share": {"id": OTHER_ID, "sender": obf, "shared": False}})
    about(s)
    s.step({"share": {"id": OTHER_ID, "sender": obf, "shared": True}})
    about(s)
    s.take(other_proposal(2))
    s.change("delete", {}, (5, 0), OTHER_ID)
    about(s)
    s = new(
        "the answer reaches the device from a sibling: the kept PROPOSAL ends, and no reply goes",
        refs,
        owner(),
    )
    s.take(p1)
    s.step({"answered": {"sender": obf, "proposal_id": PROPOSAL_IDS[0], "answer": "DECLINED"}})
    about(s)
    s.receive(forward_message("tablet", p1, None))
    s.take(p1)
    s.acks()
    s = new(
        "two answers before a merge: a sibling's answer after the device's own sends nothing",
        [*refs, "shares.md 14.2"],
        owner(),
    )
    s.take(p1)
    s.step(
        {
            "answer": {"sender": obf, "proposal_id": PROPOSAL_IDS[0], "answer": "DECLINED"},
            "now_ms": "0",
            "r": [5, 0],
        }
    )
    s.step({"answered": {"sender": obf, "proposal_id": PROPOSAL_IDS[0], "answer": "ACCEPTED"}})
    about(s)
    s = new("a PROPOSAL of a sibling is rejected with PROPOSALS_NOT_TAKEN", ["shares.md 13.3"], owner())
    fields = [{"name": "location", "schema": SCHEMA_1, "value": VALUE_WEBER}]
    body = body_of("Proposal", {"to": PHONE, "proposal_id": PROPOSAL_IDS[0], "fields": fields})
    s.receive(message(TABLET_SEED, "PROPOSAL", (OTHER_ID, 1), body))
    s.receive(
        message(
            TABLET_SEED,
            "PROPOSAL_REPLY",
            (OTHER_ID, 1),
            body_of("ProposalReply", {"to": PHONE, "proposal_id": PROPOSAL_IDS[0], "answer": "ACCEPTED"}),
        )
    )
    s = new(
        "the proposer's value is an owner's change, and the update that brings it is APPLIED",
        ["shares.md 17.2", "sync.md 21.2", "sync.md 22.2"],
        known(),
    )
    s.owner("set", {"location": VALUE_WEBER}, (5, 0))
    s.take(other_data(2, location=WEBER), APPOINTMENT_OFFERED)
    s.acks()
    s.about()

    s = new(
        "a forwarded PROPOSAL in other bytes with a higher SHA-256 takes the place of the one kept",
        [*refs, "shares.md 13.4"],
        owner(),
    )
    low, high = sorted((other_proposal(0, "tablet"), other_proposal(0, "phone")), key=sha)
    s.receive(forward_message("tablet", low, None))
    s.receive(forward_message("tablet", high, None, fid=TABLET_FORWARD_2))
    s.receive(forward_message("tablet", low, None, fid=TABLET_FORWARD_3))
    s.acks()
    s.about(None)
    s = new(
        "two answers before a merge: ACCEPTED on the device stands over a later DECLINED of a sibling",
        [*refs, "shares.md 15.1"],
        owner(),
    )
    s.take(p1)
    s.step(
        {
            "answer": {"sender": obf, "proposal_id": PROPOSAL_IDS[0], "answer": "ACCEPTED"},
            "now_ms": "0",
            "r": [5, 0],
        }
    )
    s.step({"answered": {"sender": obf, "proposal_id": PROPOSAL_IDS[0], "answer": "DECLINED"}})
    about(s)
    s = new(
        "ACCEPTED is barred for a forwarded value whose schema the device lacks, and DECLINED is not",
        [*refs, "shares.md 15.1"],
        owner(),
    )
    s.receive(
        forward_message("tablet", other_proposal(0, "tablet", values={"room": ROOM}, schema=SCHEMA_2), None)
    )
    s.step(
        {
            "answer": {"sender": obf, "proposal_id": PROPOSAL_IDS[0], "answer": "ACCEPTED"},
            "now_ms": "0",
            "r": [5, 0],
        }
    )
    about(s)
    s.step(
        {
            "answer": {"sender": obf, "proposal_id": PROPOSAL_IDS[0], "answer": "DECLINED"},
            "now_ms": "0",
            "r": [5, 0],
        }
    )
    s = new(
        "a stop of the receiver drops its kept proposals, and a forwarded one is not taken",
        [*refs, "shares.md 18.4"],
        owner(),
    )
    s.take(p1)
    s.step({"stop": {"sender": obf, "id": None}})
    about(s)
    s.receive(forward_message("tablet", other_proposal(1, "tablet"), None))
    s.acks()
    s = new(
        "a kept PROPOSAL ends when the key that signed it is removed from the proposer",
        refs,
        owner(),
    )
    s.take(p1)
    s.receive(forward_message("tablet", chain_message(keys.ADD, "other app", "second app"), None))
    s.receive(
        forward_message(
            "tablet", chain_message(keys.REMOVE, "second app", "other app"), None, fid=TABLET_FORWARD_2
        )
    )
    about(s, "second app")
    s = new(
        "the schema of each entry is offered to a sibling before the PROPOSAL is forwarded to it",
        [*refs, "sync.md 7.2", "sync.md 20.3"],
        owner(accepted={"tablet": []}),
    )
    s.take(p1)
    s.receive(answer_message("tablet", OFFER_IDS[0], APPOINTMENT_TYPE))

    held = []
    for n in range(16):
        fields = [{"name": "location", "schema": SCHEMA_1, "value": VALUE_WEBER}]
        body = body_of(
            "Proposal",
            {"to": PHONE, "proposal_id": f"{n + 1:08x}-9e0a-4000-8000-0000000000aa", "fields": fields},
        )
        held.append(
            {
                "message": message(SEEDS["other app"], "PROPOSAL", (OTHER_ID, 1), body).hex(),
                "delivered": [KEY["tablet"].hex()],
            }
        )
    full = owner()
    full["senders"][0]["proposals"] = held
    s = new(
        "a forwarded PROPOSAL beyond the limit of 16 open proposals for one record is kept all the same",
        [*refs, "shares.md 18.3"],
        full,
    )
    s.receive(forward_message("tablet", other_proposal(0, "tablet"), None))
    s.acks()


def withdraw_sessions(
    new: Callable[[str, list[str], dict[str, Any]], Session],
    known: Callable[..., dict[str, Any]],
    tomb: Callable[..., dict[str, Any]],
    weber_v3: dict[str, Any],
    text: str,
    d1: bytes,
    one: tuple[str, ...],
    moved_away: Callable[..., dict[str, Any]],
) -> None:
    """The sessions about a WITHDRAW of another app (spec/shares.md, section 7.1)."""
    w2, w4 = other_withdraw(2, "tablet"), other_withdraw(4)
    refs = ["shares.md 7.1", "sync.md 19.5"]
    s = new(
        "a forwarded WITHDRAW leaves a tombstone of a withdrawal with the DATA beside it",
        [*refs, "sync.md 20.1", "sync.md 22.1"],
        known(),
    )
    s.receive(forward_message("tablet", w2, None))
    s.acks()
    s.about()
    s = new(
        "a forwarded WITHDRAW addressed to a removed key of the set is taken",
        refs,
        known(removed=("old phone",)),
    )
    s.receive(forward_message("tablet", other_withdraw(2, "old phone"), None))
    s.acks()
    s.about()
    for to, what in [("phone", "the device's own key"), ("tablet", "the key of a sibling")]:
        s = new(f"a forwarded WITHDRAW addressed to {what} is taken", refs, known())
        s.receive(forward_message("tablet", other_withdraw(2, to), None))
        s.acks()
    for label, m in [
        ("addressed to a key of no device of the set", other_withdraw(2, "stranger")),
        ("whose body has a byte left over", other_withdraw(2, "tablet", more=b"\x00")),
        (
            "whose body is not an axt.Withdraw",
            named("WITHDRAW with no body", message(SEEDS["other app"], "WITHDRAW", (RECORD_ID, 2), b"")),
        ),
    ]:
        s = new(f"a forwarded WITHDRAW {label} is rejected with INVALID_MESSAGE", refs, known())
        s.receive(forward_message("tablet", m, None))
        s.acks()
        s.about()
    s = new(
        "a forwarded DATA below the tombstone of a withdrawal goes beside it",
        [*refs, "sync.md 20.1"],
        tomb(None, other_withdraw(3, "tablet")),
    )
    s.receive(forward_message("tablet", other_data(2), text))
    s.acks()
    s.about()
    s = new(
        "two WITHDRAW messages of one version in other bytes: the one with the higher SHA-256 stands",
        [*refs, "sync.md 20.1"],
        known(),
    )
    s.receive(forward_message("tablet", other_withdraw(2, "tablet"), None))
    s.receive(forward_message("tablet", other_withdraw(2, "phone"), None, fid=TABLET_FORWARD_2))
    s.acks()
    s.about()
    s = new(
        "two WITHDRAW messages of one version in other bytes: the later one with the higher SHA-256 takes "
        "the place of the kept one",
        [*refs, "sync.md 20.1"],
        known(),
    )
    s.receive(forward_message("tablet", other_withdraw(2, "phone"), None))
    s.receive(forward_message("tablet", other_withdraw(2, "tablet"), None, fid=TABLET_FORWARD_2))
    s.acks()
    s.about()
    keep = {**received_device([weber_v3], highest=205), "on_withdraw": "keep"}
    s = new(
        "a set that keeps: a WITHDRAW that meets an owner's value sets a keep, KEPT, and the record is kept "
        "against the withdrawal",
        [*refs, "shares.md 4.3", "sync.md 22.1", "sync.md 22.2", "sync.md 21.2"],
        keep,
    )
    s.take(w4, None, (4, 0))
    s.acks()
    s.about()
    s.take(other_data(5), text)
    s.acks()
    s.about()
    s = new(
        "the further ACK: after KEPT for a WITHDRAW, the user gives up the keep and the device sends "
        "WITHDRAWN",
        [*refs, "sync.md 22.3", "protocol.md 7.3"],
        keep,
    )
    s.take(w4, None, (4, 0))
    s.acks()
    s.owner("give_up", {}, (1, 0))
    s.acks()
    s.about()
    s = new(
        "a keep against a WITHDRAW does not cover a DELETE with a higher version",
        [*refs, "shares.md 6.3", "sync.md 22.1"],
        keep,
    )
    s.take(w4, None, (4, 0))
    s.take(other_delete(5), None, (2, 0))
    s.acks()
    s.about()
    s = new(
        "a set that keeps against a DELETE may remove against a WITHDRAW: WITHDRAWN, and the layer is tidied",
        [*refs, "shares.md 4.3", "sync.md 22.3"],
        {**received_device([weber_v3], highest=205, on_delete="keep"), "on_withdraw": "delete"},
    )
    s.take(w4, None, (4, 0))
    s.acks()
    s.about()
    s = new(
        "a WITHDRAW of an id the answering device does not have: WITHDRAWN, a tombstone without a type",
        [*refs, "shares.md 4.2"],
        known(),
    )
    s.take(other_withdraw(3, rid=OTHER_ID))
    s.acks()
    s.about(OTHER_ID)
    s = new(
        "a WITHDRAW of another app in a file of that app is taken and forwarded, and nothing is reported",
        [*refs, "shares.md 8.2", "sync.md 24.2"],
        known(),
    )
    s.take(other_withdraw(2, "tablet"), None, (), True)
    s.acks()
    s.about()
    s = new(
        "a WITHDRAW of a sibling is rejected with NOT_ACCEPTED, once its body and addressee pass",
        ["shares.md 4.1", "shares.md 7.2", "sync.md 7.2"],
        known(),
    )
    tablet = SEEDS["tablet"]
    s.receive(message(tablet, "WITHDRAW", (RECORD_ID, 2), body_of("Withdraw", {"to": KEY["phone"]})))
    s.receive(message(tablet, "WITHDRAW", (RECORD_ID, 2), body_of("Withdraw", {"to": KEY["laptop"]})))
    s.receive(message(tablet, "WITHDRAW", (RECORD_ID, 2), b""))
    s.receive(message(tablet, "WITHDRAW", ("not-a-uuid", 2), body_of("Withdraw", {"to": KEY["phone"]})))
    s.receive(message(tablet, "WITHDRAW", None, body_of("Withdraw", {"to": KEY["phone"]})))
    s.acks()
    # Case 5 of section 19.5, step 7: a WITHDRAW over a DATA or a DELETE of the same version.
    for how in ("forwarded", "from the sender"):
        tail = "APPLIED" if how == "forwarded" else "DUPLICATE"
        s = new(
            f"case 5 of step 7, {how}: a WITHDRAW takes the place of a DATA of the same version, which stays "
            f"beside it; {tail}",
            [*refs, "sync.md 20.1", "shares.md 6.3"],
            known(record=other_data(2)),
        )
        if how == "forwarded":
            s.receive(forward_message("tablet", other_withdraw(2, "tablet"), None))
        else:
            s.take(other_withdraw(2))
        s.acks()
        s.about()
    s = new(
        "case 5 of step 7, forwarded: a WITHDRAW takes the place of a DELETE of the same version, and the "
        "DATA beside it stays",
        [*refs, "sync.md 20.1"],
        tomb(),
    )
    s.receive(forward_message("tablet", other_withdraw(3, "tablet"), None))
    s.acks()
    s.about()
    for choice, what in [("keep", "sets a keep"), ("delete", "tidies the layer")]:
        s = new(
            f"case 5 at the answering device, a set that {'keeps' if choice == 'keep' else 'removes'}: a "
            f"WITHDRAW over a DATA of its version meets an owner's value and {what}; DUPLICATE",
            [*refs, "sync.md 22.2", "shares.md 6.3"],
            {**received_device([weber_v3], highest=205), "on_withdraw": choice},
        )
        s.take(other_withdraw(3), None, (4, 0))
        s.acks()
        s.about()
    s = new(
        "a WITHDRAW that meets an owner's removal that stands, with owner's values, at a set that keeps: "
        "WITHDRAWN, and the removal stands",
        [*refs, "shares.md 4.2", "sync.md 22.2", "records.md 6.3"],
        {
            **received_device(
                [
                    sender_json(
                        manifests=(kept_json(other_manifest(1), one),),
                        records=(kept_json(other_data(2), one, text),),
                        layers=(
                            layer_json(
                                State(
                                    {"location": FieldState(VALUE_WEBER, 200, TABLET)}, gone(203, TABLET), 205
                                ),
                                dict.fromkeys(one),
                            ),
                        ),
                    )
                ],
                highest=205,
            ),
            "on_withdraw": "keep",
        },
    )
    s.take(other_withdraw(3))
    s.acks()
    s.about()
    s = new(
        "a forwarded WITHDRAW of a removed key is rejected with NOT_ACCEPTED when the sibling has not shown "
        "that it has the removal",
        [*refs, "sync.md 19.2"],
        moved_away(()),
    )
    s.receive(forward_message("tablet", other_withdraw(2, "tablet"), None))
    s.acks()
    s = new(
        "a WITHDRAW in a file of the device's own set is not applied",
        ["shares.md 8.2", "sync.md 13.4"],
        known(),
    )
    own = named(
        "WITHDRAW of the tablet",
        message(SEEDS["tablet"], "WITHDRAW", (OTHER_ID, 2), body_of("Withdraw", {"to": KEY["other app"]})),
    )
    s.step({"file_record": own, "schema": text, "now_ms": "0", "r": []})
    s.query(OTHER_ID)


def padded_schema(size: int) -> str:
    """The offered schema of the appointment with a longer `doc`, so that its text has `size` bytes; its
    fingerprint stays, since the canonical form holds no `doc`."""
    schema = json.loads(APPOINTMENT_OFFERED)
    schema["doc"] += "x" * (size - len(APPOINTMENT_OFFERED.encode()))
    out = json.dumps(schema, separators=(",", ":"), ensure_ascii=False)
    assert len(out.encode()) == size and schema_fingerprint(out) == SCHEMA_1
    return out


def nested_schema(depth: int) -> str:
    """The offered schema of the appointment with an attribute nested so that its JSON text has that
    depth (spec/envelope.md, section 8); its fingerprint stays."""
    schema = json.loads(APPOINTMENT_OFFERED)
    nest: Any = 0
    while tm.rules.json_depth({**schema, "x-nest": nest}) < depth:
        nest = [nest]
    schema["x-nest"] = nest
    out = json.dumps(schema, separators=(",", ":"), ensure_ascii=False)
    assert tm.rules.json_depth(json.loads(out)) == depth and schema_fingerprint(out) == SCHEMA_1
    return out


SAID: dict[str, list[list[str]]] = {
    "a CHANGE of the device's own key is ignored": [
        [
            "outcome: None",
        ],
        [],
        [
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "a RESYNC of the device's own key is ignored": [
        [
            "outcome: None",
        ],
        [],
        [
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "a CHANGE of a removed key of the device's own set is rejected without a report": [
        [
            "outcome: None",
        ],
        [],
        [
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "a RESYNC of a removed key of the device's own set is rejected without a report": [
        [
            "outcome: None",
        ],
        [],
        [
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101",
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
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101",
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
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "a CHANGE of a removed key of another sender, or a refused key, is rejected without a report": [
        [
            "outcome: None",
        ],
        [],
        [
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "a RESYNC of a removed key of another sender, or a refused key, is rejected without a report": [
        [
            "outcome: None",
        ],
        [],
        [
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "a CHANGE of a key the device does not know is not processed": [
        [
            "outcome: None",
        ],
        [],
        [
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "a RESYNC of a key the device does not know is not processed": [
        [
            "outcome: None",
        ],
        [],
        [
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "a CHANGE of a sibling for another device is ignored": [
        [
            "outcome: None",
        ],
        [],
        [
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101",
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
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101",
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
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101",
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
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101",
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
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101",
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
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101",
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
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101",
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
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101",
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
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101",
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
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101",
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
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101",
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
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101",
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
                "state stamp 115; all_day,end,notes,relations,reminders,start,title@100p location@110t; "
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
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101",
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
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
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
                "state stamp None; all_day,end,notes,relations,reminders,start,title@100p "
                "location@9223372036854775807t removal@9223372036854775807t, taken back; sibling stamp "
                "9223372036854775807; to pass None; highest 9223372036854775807"
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
                "state stamp 122; all_day,end,notes,relations,reminders,start,title@100p location@110? "
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
            "state stamp 101; all eight@100p; sibling stamp 105; to pass None; highest 105",
            "tablet: known, delivered: all_day,end,notes,relations,reminders,start,title",
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
            "state stamp 101; all eight@100p; sibling stamp 105; to pass None; highest 105",
            "tablet: known, delivered: all_day,end,notes,relations,reminders,start,title",
        ],
    ],
    "step 7: the error names the first schema, in the order of the message, that the device lacks": [
        [
            "outcome: None",
            "ERROR to tablet: SCHEMA_UNKNOWN, fingerprint 1112131415161718",
        ],
        [],
        [
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101",
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
            "ERROR to tablet: SCHEMA_UNKNOWN, fingerprint 62231c9093404ed8",
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
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101",
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
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101",
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
                "state stamp 162; all_day,end,notes,relations,reminders,start,title@100p location@160t "
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
                "state stamp 112; all_day,end,notes,relations,reminders,start,title@100p location@110t; "
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
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101",
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
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101",
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
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101",
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
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101",
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
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101",
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
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101",
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
                "state stamp 115; all_day,end,notes,relations,reminders,start,title@100p location@110t; "
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
            "state stamp 101; all eight@100p; sibling stamp 105; to pass None; highest 105",
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
            "state stamp 101; all eight@100p; sibling stamp 105; to pass None; highest 105",
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
                "state stamp 121; all_day,end,notes,relations,reminders,start,title@100p location@120p; "
                "sibling stamp 111; to pass None; highest 121"
            ),
            "tablet: known, delivered: all_day,end,notes,relations,reminders,start,title",
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
                "state stamp 127; all_day,end,relations,reminders,start,title@100p location@120p notes@125t; "
                "sibling stamp 126; to pass None; highest 127"
            ),
            "tablet: known, delivered: all_day,end,notes,relations,reminders,start,title",
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
                "state stamp 115; all_day,end,notes,relations,reminders,start,title@100p location@110t; "
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
                "state stamp 117; all_day,end,notes,relations,reminders,start,title@100p location@116p; "
                "sibling stamp 111; to pass None; highest 117"
            ),
            "tablet: known, delivered: all_day,end,notes,relations,reminders,start,title",
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
            "state stamp 152; all eight@100p removal@150t; sibling stamp 151; to pass None; highest 152",
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
                "state stamp 162; all_day,end,notes,relations,reminders,start,title@100p location@160t "
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
                "state stamp 172; all eight@100p removal@170t, taken back; sibling stamp 171; to pass None; "
                "highest 172"
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
            "state stamp 151; all eight@100p removal@150p; sibling stamp 155; to pass None; highest 155",
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
            "state stamp 151; all eight@100p removal@150p; sibling stamp 141; to pass None; highest 151",
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
                "state stamp 121; all_day,end,notes,relations,reminders,start,title@100p location@110t; "
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
            "state stamp 127; all eight@100p room@125t; sibling stamp 126; to pass None; highest 127",
            "laptop: known, delivered: all_day,end,location,notes,relations,reminders,start,title",
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
            "CHANGE of 7b1e6c2a to laptop, version 202, state 202, whole: all eight@200t",
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
                "state stamp 132; all_day,end,location,notes,relations,reminders,start@100p title@130t; "
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
    "an offer of a sibling for another device is ignored": [
        [
            "outcome: None",
        ],
    ],
    "a device sends no CHANGE that names a schema a sibling declined": [
        [
            "made: True",
            "OFFER 00000001 to laptop: axt.example.v1.Appointment version 1",
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
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
            "CHANGE to laptop, version 127, state 127, whole: all eight@100p room@125t",
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
        "the outcome APPLIED of a sibling delivers the parts of the message, and the sibling's state stamp "
        "counts as seen"
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
                "state stamp 111; title,start,end,all_day,notes,reminders,relations@100p location@110p; "
                "sibling stamp 115; to pass None; highest 115"
            ),
            "tablet: known, delivered: all",
        ],
    ],
    (
        "the outcome DUPLICATE of a sibling delivers the parts of the message, also with a state stamp below "
        "the version"
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
                "state stamp 111; title,start,end,all_day,notes,reminders,relations@100p location@110p; "
                "sibling stamp 105; to pass None; highest 111"
            ),
            "tablet: known, delivered: all",
        ],
    ],
    (
        "the outcome STALE of a sibling delivers the parts of the message, and the device "
        "keeps no version to "
        "pass"
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
                "state stamp 111; title,start,end,all_day,notes,reminders,relations@100p location@110p; "
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
                "state stamp 111; title,start,end,all_day,notes,reminders,relations@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,relations,reminders,start,title",
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
                "state stamp 111; title,start,end,all_day,notes,reminders,relations@100p location@110p; "
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
                "state stamp 111; title,start,end,all_day,notes,reminders,relations@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "laptop: known, delivered: all_day,end,notes,relations,reminders,start,title",
            "tablet: known, delivered: all_day,end,notes,relations,reminders,start,title",
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
                "state stamp 111; title,start,end,all_day,notes,reminders,relations@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,relations,reminders,start,title",
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
                "state stamp 111; title,start,end,all_day,notes,reminders,relations@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,relations,reminders,start,title",
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
                "state stamp 111; title,start,end,all_day,notes,reminders,relations@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,relations,reminders,start,title",
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
                "state stamp 111; title,start,end,all_day,notes,reminders,relations@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,relations,reminders,start,title",
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
                "state stamp 111; title,start,end,all_day,notes,reminders,relations@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,relations,reminders,start,title",
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
                "state stamp 111; title,start,end,all_day,notes,reminders,relations@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,relations,reminders,start,title",
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
                "state stamp 111; title,start,end,all_day,notes,reminders,relations@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,relations,reminders,start,title",
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
                "state stamp 111; title,start,end,all_day,notes,reminders,relations@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,relations,reminders,start,title",
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
                "state stamp 111; title,start,end,all_day,notes,reminders,relations@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,relations,reminders,start,title",
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
                "state stamp 111; title,start,end,all_day,notes,reminders,relations@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,relations,reminders,start,title",
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
                "title,start,end,all_day,notes,reminders,relations@100p location@110p"
            ),
        ],
        [
            (
                "state stamp 114; title,start,end,all_day,notes,reminders,relations@100p location@110p; "
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
                "state stamp 111; title,start,end,all_day,notes,reminders,relations@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,relations,reminders,start,title",
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
                "state stamp 111; title,start,end,all_day,notes,reminders,relations@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,relations,reminders,start,title",
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
                "state stamp 111; title,start,end,all_day,notes,reminders,relations@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,relations,reminders,start,title",
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
                "state stamp 111; title,start,end,all_day,notes,reminders,relations@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,relations,reminders,start,title",
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
                "state stamp 111; title,start,end,all_day,notes,reminders,relations@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,relations,reminders,start,title",
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
                "state stamp 111; title,start,end,all_day,notes,reminders,relations@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,relations,reminders,start,title",
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
                "state stamp 111; title,start,end,all_day,notes,reminders,relations@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,relations,reminders,start,title",
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
                "state stamp 111; title,start,end,all_day,notes,reminders,relations@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,relations,reminders,start,title",
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
                "state stamp 111; title,start,end,all_day,notes,reminders,relations@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,relations,reminders,start,title",
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
                "state stamp 111; title,start,end,all_day,notes,reminders,relations@100p location@110p; "
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
                "state stamp 111; title,start,end,all_day,notes,reminders,relations@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,relations,reminders,start,title",
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
                "state stamp 111; title,start,end,all_day,notes,reminders,relations@100p location@110p; "
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
                "state stamp 111; title,start,end,all_day,notes,reminders,relations@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "laptop: known, delivered: all_day,end,notes,relations,reminders,start,title",
            "tablet: known, delivered: all_day,end,notes,relations,reminders,start,title",
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
                "state stamp 111; title,start,end,all_day,notes,reminders,relations@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,relations,reminders,start,title",
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
                "state stamp 117; title,start,end,all_day,reminders,relations@100p location@110p notes@116p; "
                "sibling stamp 115; to pass None; highest 117"
            ),
            "laptop: known, delivered: all_day,end,relations,reminders,start,title",
            "tablet: known, delivered: all_day,end,location,relations,reminders,start,title",
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
                "state stamp 115; all_day,end,notes,relations,reminders,start,title@100p location@110t; "
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
                "title,start,end,all_day,notes,reminders,relations@100p location@110p"
            ),
            "CHANGE to tablet, version 111, state 111, in part: location@110p",
        ],
        [
            "outcome: None",
        ],
        [
            (
                "state stamp 111; title,start,end,all_day,notes,reminders,relations@100p location@110p; "
                "sibling stamp 115; to pass None; highest 115"
            ),
            "laptop: known, delivered: all",
            "tablet: known, delivered: all_day,end,notes,relations,reminders,start,title",
        ],
    ],
    "a new device gets the schemas offered and then every record whole": [
        [
            "OFFER 00000001 to laptop: axt.example.v1.Appointment version 1",
        ],
        [
            "outcome: None",
            "CHANGE to laptop, version 101, state 101, whole: all eight@100p",
        ],
        [
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101",
            "laptop: not known",
            "tablet: known, delivered: all",
        ],
    ],
    "a deletion travels as the removal alone, and a deleted record goes whole to a sibling that lacks it": [
        [
            "made: True",
            "CHANGE to laptop, version 111, state 111, whole: all eight@100p removal@110p",
            "CHANGE to tablet, version 111, state 111, in part: no field removal@110p",
        ],
        [
            "state stamp 111; all eight@100p removal@110p; sibling stamp None; to pass None; highest 111",
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
                "state stamp 166; location@160t removal@150p; sibling stamp None; to pass None; highest 166; "
                "incomplete"
            ),
            "tablet: not known",
        ],
        [
            "outcome: APPLIED",
            "CHANGE to tablet, version 173, state 173, in part: location@160t removal@150p",
        ],
        [
            (
                "state stamp 173; all_day,end,notes,relations,reminders,start@100p location@160t title@170t "
                "removal@150p; sibling stamp 171; to pass None; highest 173"
            ),
            "tablet: known, delivered: all_day,end,notes,relations,reminders,start,title",
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
                "title,start,end,all_day,notes,reminders,relations@100p location@110p"
            ),
        ],
        [
            (
                "state stamp 113; title,start,end,all_day,notes,reminders,relations@100p location@110p; "
                "sibling stamp None; to pass None; highest 113"
            ),
            "laptop: known, delivered: all_day,end,notes,relations,reminders,start,title",
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
                "title,start,end,all_day,notes,reminders,relations@100p location@110p"
            ),
            "CHANGE to laptop, version 113, state 113, in part: location@110p",
        ],
        [
            (
                "state stamp 113; title,start,end,all_day,notes,reminders,relations@100p location@110p; "
                "sibling stamp None; to pass None; highest 113"
            ),
            "laptop: known, delivered: all_day,end,notes,relations,reminders,start,title",
            "tablet: not known",
        ],
    ],
    "a device sends no CHANGE of a record for which it holds no state stamp": [
        [
            "OFFER 00000001 to tablet: axt.example.v1.Appointment version 1",
        ],
        [
            "outcome: None",
            "CHANGE of 7b1e6c2a to tablet, version 101, state 101, whole: all eight@100p",
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
                "state stamp 111; title,start,end,all_day,notes,reminders,relations@100p location@110p; "
                "sibling stamp None; to pass None; highest 111"
            ),
            "tablet: known, delivered: all_day,end,notes,relations,reminders,start,title",
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
                "state stamp 121; all_day,end,relations,reminders,start,title@100p location,notes@110p; "
                "sibling stamp 120; to pass None; highest 121"
            ),
            "tablet: known, delivered: all_day,end,location,relations,reminders,start,title",
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
                "state stamp 111; all_day,end,notes,relations,reminders,start,title@100p location@110p; "
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
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 9223372036854775807",
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
                "state stamp 111; all_day,end,notes,relations,reminders,start,title@100p location@110p; "
                "sibling stamp 105; to pass None; highest 9223372036854775807"
            ),
            "tablet: not known",
        ],
    ],
    "a record that its user creates travels whole, its deletion and the taking back as the removal alone": [
        [
            "made: True",
            "CHANGE of 7b1e6c2a to tablet, version 101, state 101, whole: all eight@100p",
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
                "CHANGE of 7b1e6c2a to tablet, version 112, state 112, in part: no field removal@111p, taken "
                "back"
            ),
        ],
        [
            (
                "state stamp 112; all eight@100p removal@111p, taken back; sibling stamp 110; to pass None; "
                "highest 112"
            ),
            "tablet: known, delivered: all",
        ],
    ],
    "after a RESYNC the device sends every record whole under a new state stamp, then acknowledges it": [
        [
            "outcome: None",
            "CHANGE to tablet, version 152, state 152, whole: all eight@100p",
            (
                "CHANGE of 7b1e6c2a to tablet, version 153, state 153, whole: "
                "title,start,end,all_day,notes,reminders,relations@100p location@110t removal@150p"
            ),
        ],
        [
            "state stamp 152; all eight@100p; sibling stamp None; to pass None; highest 153",
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
                "state stamp 153; title,start,end,all_day,notes,reminders,relations@100p location@110t "
                "removal@150p; sibling stamp None; to pass None; highest 153"
            ),
            "tablet: not known",
        ],
    ],
    "a repeat of a RESYNC before its acknowledgement is sent changes nothing": [
        [
            "outcome: None",
            "CHANGE to tablet, version 102, state 102, whole: all eight@100p",
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
            "CHANGE to tablet, version 102, state 102, whole: all eight@100p",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            "outcome: None",
            "CHANGE to tablet, version 103, state 103, whole: all eight@100p",
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
            "CHANGE to tablet, version 102, state 102, whole: all eight@100p",
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
            "CHANGE to tablet, version 102, state 102, whole: all eight@100p",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
    ],
    "a second RESYNC with another id starts the answer anew, and both are acknowledged at its end": [
        [
            "outcome: None",
            "OFFER 00000001 to tablet: axt.example.v1.Appointment version 2",
            "CHANGE to tablet, version 128, state 128, whole: all eight@100p",
        ],
        [],
        [
            "outcome: None",
            "CHANGE to tablet, version 129, state 129, whole: all eight@100p",
        ],
        [
            "outcome: None",
            "CHANGE of 7b1e6c2a to tablet, version 130, state 130, whole: all eight@100p room@125t",
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
                "title,start,end,all_day,notes,reminders,relations@100p location@110p"
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
                "state stamp 113; title,start,end,all_day,notes,reminders,relations@100p location@110p; "
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
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101",
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
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101",
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
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101",
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
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101",
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
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101",
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
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101",
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
                "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101; a request "
                "open to laptop, tablet"
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
                "state stamp 117; all_day,end,relations,reminders,start,title@100p notes@102p location@110p; "
                "sibling stamp 115; to pass None; highest 117; a request open to laptop"
            ),
            "laptop: not known",
            "tablet: known, delivered: all_day,end,location,relations,reminders,start,title",
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
                "state stamp 117; all_day,end,relations,reminders,start,title@100p notes@102p location@110p; "
                "sibling stamp 115; to pass None; highest 117"
            ),
            "laptop: not known",
            "tablet: known, delivered: all_day,end,location,relations,reminders,start,title",
        ],
    ],
    "a restored device with a sibling gives its field states never stamped the stamp -1": [
        [
            "RESYNC 00000001 to tablet",
        ],
        [
            (
                "state stamp 4; all eight@-1p; sibling stamp None; to pass None; highest 4; held back from "
                "other apps; a request open to tablet"
            ),
            "tablet: not known",
        ],
        [
            "outcome: None",
            "OFFER 00000001 to tablet: axt.example.v1.Appointment version 1",
        ],
        [
            "state stamp 4; all eight@-1p; sibling stamp None; to pass None; highest 4",
            "tablet: not known",
        ],
        [
            "outcome: None",
            "CHANGE to tablet, version 5, state 5, whole: all eight@-1p",
        ],
    ],
    "a record with a field state of unknown age is held back from other apps for at most 14 days": [
        [
            "RESYNC 00000001 to tablet",
        ],
        [],
        [
            (
                "state stamp 4; all eight@-1p; sibling stamp None; to pass None; highest 4; held back from "
                "other apps; a request open to tablet"
            ),
            "tablet: not known",
        ],
        [],
        [
            (
                "state stamp 4; all eight@-1p; sibling stamp None; to pass None; highest 4; a "
                "request open to "
                "tablet"
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
                "state stamp 4; all eight@-1p; sibling stamp None; to pass None; highest 4; a "
                "request open to "
                "laptop"
            ),
            "laptop: not known",
            "tablet: not known",
        ],
        [
            "outcome: None",
            "OFFER 00000002 to laptop: axt.example.v1.Appointment version 1",
        ],
        [
            "state stamp 4; all eight@-1p; sibling stamp None; to pass None; highest 4",
            "laptop: not known",
            "tablet: not known",
        ],
    ],
    "a restored device keeps the requests of its backup that it acted on, and opens its own anew": [
        [
            "outcome: None",
            "CHANGE to tablet, version 102, state 102, whole: all eight@100p",
        ],
        [
            "outcome: None",
            "CHANGE to tablet, version 103, state 103, whole: all eight@100p",
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
                "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101; a request "
                "open to tablet"
            ),
            "tablet: not known",
        ],
        [
            "outcome: None",
            "OFFER 00000002 to tablet: axt.example.v1.Appointment version 1",
        ],
        [
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101",
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
                "state stamp 6; title,start,end,all_day,location,reminders,relations@-1p notes@5p; sibling "
                "stamp None; to pass None; highest 6; held back from other apps; a request open to tablet"
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
                "state stamp 10; all_day,end,location,relations,reminders,start,title@0p notes@5p; sibling "
                "stamp 9; to pass None; highest 10; a request open to tablet"
            ),
            "tablet: known, delivered: all_day,end,location,relations,reminders,start,title",
        ],
    ],
    "a device that restores as the only device of its set leaves its field states never stamped": [
        [],
        [
            "state stamp 4; all eight@0p; sibling stamp None; to pass None; highest 4",
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
                "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101; a request "
                "open to tablet"
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
            "CHANGE to tablet, version 102, state 102, whole: all eight@100p",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            (
                "state stamp 102; all eight@100p; sibling stamp None; to pass None; highest 102; a request "
                "open to tablet"
            ),
            "tablet: not known",
        ],
    ],
    "a request ends when its sibling is removed": [
        [
            "RESYNC 00000001 to laptop",
            "RESYNC 00000002 to tablet",
        ],
        [
            "chain and MANIFEST to: no sender",
        ],
        [
            (
                "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101; a request "
                "open to laptop"
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
                "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101; a request "
                "open to tablet"
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
                "state stamp 111; title,start,end,all_day,notes,reminders,relations@100p location@110p; "
                "sibling stamp 115; to pass None; highest 115"
            ),
            "laptop: known, delivered: all_day,end,notes,relations,reminders,start,title",
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
                "state stamp 111; title,start,end,all_day,notes,reminders,relations@100p location@110p; "
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
                "state stamp 107; location@-1t all_day,end,notes,relations,reminders,start,title@100p; "
                "sibling stamp 110; to pass None; highest 110"
            ),
            "laptop: known, delivered: all_day,end,notes,relations,reminders,start,title",
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
                "state stamp 113; title,start,end,all_day,reminders,relations@100p location,notes@112p; "
                "sibling stamp 115; to pass None; highest 115"
            ),
            "tablet: known, delivered: all_day,end,relations,reminders,start,title",
        ],
        [
            "outcome: None",
        ],
        [
            (
                "state stamp 113; title,start,end,all_day,reminders,relations@100p location,notes@112p; "
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
    "an offer of a sibling with a count of -1 is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: OFFER_INVALID",
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
        [
            "chain and MANIFEST to: no sender",
        ],
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
                "state stamp 124; all_day,end,relations,reminders,start@100p location@110p notes@120t "
                "title@123p; sibling stamp 121; to pass None; highest 124"
            ),
            "laptop: known, delivered: all_day,end,relations,reminders,start",
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
            "ERROR to tablet: SCHEMA_UNKNOWN, fingerprint 20ff75fd4c93c8f4",
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
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 101",
            "tablet: known, delivered: all",
        ],
    ],
    "a device takes a DATA of a file of its own set with field states of unknown age, which travel": [
        [
            "taken: True",
            "CHANGE to laptop, version 8, state 8, whole: all eight@-1t",
            "CHANGE to tablet, version 8, state 8, whole: all eight@-1t",
        ],
        [
            "state stamp 8; all eight@-1t; sibling stamp 7; to pass None; highest 8",
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
            "state stamp 8; all eight@-1t; sibling stamp 7; to pass None; highest 8",
            "laptop: not known",
            "tablet: not known",
        ],
    ],
    "a record with field states of unknown age is part of the answer to a RESYNC, like any record": [
        [
            "taken: True",
            "CHANGE to tablet, version 8, state 8, whole: all eight@-1p",
        ],
        [
            "outcome: None",
            "CHANGE to tablet, version 9, state 9, whole: all eight@-1p",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
    ],
    "field states of unknown age from a file lose to a sibling's, never stamped or stamped": [
        [
            "taken: True",
            "CHANGE to laptop, version 8, state 8, whole: all eight@-1t",
            "CHANGE to tablet, version 8, state 8, whole: all eight@-1t",
        ],
        [
            "outcome: APPLIED",
            (
                "CHANGE to laptop, version 106, state 106, whole: "
                "all_day,end,location,notes,relations,reminders,start@0p title@100t"
            ),
        ],
        [
            "ACK to tablet: version 105 APPLIED, receiver 106",
        ],
        [
            (
                "state stamp 106; all_day,end,location,notes,relations,reminders,start@0p "
                "title@100t; sibling "
                "stamp 105; to pass None; highest 106"
            ),
            "laptop: not known",
            "tablet: known, delivered: all",
        ],
    ],
    "of two field states of unknown age the higher device key stands, then the higher value": [
        [
            "taken: True",
            "CHANGE to laptop, version 8, state 8, whole: all eight@-1t",
            "CHANGE to tablet, version 8, state 8, whole: all eight@-1t",
        ],
        [
            "outcome: STALE",
            "CHANGE to laptop, version 8, state 8, whole: all eight@-1t",
        ],
        [
            "outcome: APPLIED",
            "CHANGE to tablet, version 9, state 9, whole: all eight@-1t",
        ],
        [
            "ACK to laptop: version 4 APPLIED, receiver 9",
            "ACK to laptop: version 3 STALE, receiver 8",
        ],
        [
            "state stamp 9; all eight@-1t; sibling stamp 7; to pass None; highest 9",
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
    "a FORWARD of the device's own key is ignored": [
        [
            "outcome: None",
        ],
        [],
        [
            "no known sender; highest 195; refused: refused",
        ],
    ],
    "a FORWARD of a removed key of the device's own set is rejected without a report": [
        [
            "outcome: None",
        ],
        [],
        [
            "no known sender; highest 195; refused: refused",
        ],
    ],
    "a FORWARD of a current key of another known sender is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to other app: INVALID_MESSAGE",
        ],
        [],
        [
            "no known sender; highest 195; refused: refused",
        ],
    ],
    "a FORWARD of a removed key of another sender, or a refused key, is rejected without a report": [
        [
            "outcome: None",
        ],
        [],
        [
            "no known sender; highest 195; refused: refused",
        ],
    ],
    "a FORWARD of a key the device does not know is not processed": [
        [
            "outcome: None",
        ],
        [],
        [
            "no known sender; highest 195; refused: refused",
        ],
    ],
    "step 1: a FORWARD without a record is reported to a sibling and to another app, and to no other key": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
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
            "no known sender; highest 195; refused: refused",
        ],
    ],
    "step 2: the body of a FORWARD of another app is not read": [
        [
            "outcome: None",
            "ERROR to other app: INVALID_MESSAGE",
        ],
        [
            "outcome: None",
        ],
        [],
    ],
    "step 3: a FORWARD whose body is no axt.Forward is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
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
            "no known sender; highest 195",
        ],
    ],
    "step 3: a FORWARD of a sibling for another device is ignored": [
        [
            "outcome: None",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 4: a FORWARD with an id that is no UUID is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: RECORD_ID_INVALID",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 4: a FORWARD with the nil UUID is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: RECORD_ID_INVALID",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 4: a FORWARD with the max UUID is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: RECORD_ID_INVALID",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 5: a FORWARD with the version 0 is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: VERSION_INVALID",
        ],
        [],
    ],
    "step 5: a FORWARD with the version -1 is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: VERSION_INVALID",
        ],
        [],
    ],
    "step 6: a FORWARD with the version 2 is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 7: an empty message is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 7: a message of 9 bytes is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 7: a message that does not begin with C3 01 is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 8: a message with the fingerprint of no envelope format is rejected with FORMAT_UNSUPPORTED": [
        [
            "outcome: None",
            "ERROR to tablet: FORMAT_UNSUPPORTED, fingerprint c188f8c5af4d094d",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 9: a message with a byte after its envelope is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 9: a message whose envelope is cut short is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 9: a message whose format field is 2 is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 9: a forwarded OFFER is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 9: a forwarded ACCEPT is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 9: a forwarded DECLINE is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 9: a forwarded ACK is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 9: a forwarded ERROR is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 9: a forwarded DEVICE_JOIN is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 9: a forwarded CHANGE is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 9: a forwarded RESYNC is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 9: a forwarded FORWARD is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 9: a forwarded WITHDRAW is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 9: a forwarded PROPOSAL is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 9: a forwarded PROPOSAL_REPLY is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 9: a forwarded DATA without a record is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 9: a forwarded DELETE without a record is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 9: a forwarded MANIFEST with a record is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 9: a forwarded DELETE with a body is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 9: a forwarded DATA with an empty body is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 9: a forwarded DATA whose body has 9 bytes is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 9: a forwarded DATA whose body does not begin with C3 01 is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    (
        "step 9: a forwarded MANIFEST whose body has the fingerprint of axt.DeviceAdd is "
        "rejected with INVALID_MESSAGE"
    ): [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    (
        "step 9: a forwarded DEVICE_ADD whose body has the fingerprint of "
        "axt.DeviceRemove is rejected with INVALID_MESSAGE"
    ): [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 9: a forwarded MANIFEST with an empty body is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 9: a schema with a forwarded DELETE is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 9: a schema with a forwarded MANIFEST is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 9: no schema with a forwarded DATA is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 10: a schema of 256 KiB and one byte is rejected with TOO_LARGE": [
        [
            "outcome: None",
            "ERROR to tablet: TOO_LARGE",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 10: a schema nested to a depth of 65 is rejected with TOO_LARGE": [
        [
            "outcome: None",
            "ERROR to tablet: TOO_LARGE",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 10: a text above 256 KiB that is no schema, before step 11 is rejected with TOO_LARGE": [
        [
            "outcome: None",
            "ERROR to tablet: TOO_LARGE",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 11: a schema that is no JSON text is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 11: a schema that is no schema of a record is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 11: a schema that is no Avro schema is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 11: a schema with another fingerprint than the body names is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 10: a schema of exactly 256 KiB is taken": [
        [
            "outcome: APPLIED",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            (
                "sender first known by second app; known by forwards of tablet; current: second "
                "app; highest 195"
            ),
            "kept: DATA version 1 of the second app; delivered to tablet",
            (
                "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA "
                "version 1 of the second app"
            ),
            "owner's layer: none",
            "shows: there",
        ],
    ],
    "step 10: a schema nested to a depth of 64 is taken": [
        [
            "outcome: APPLIED",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            (
                "sender first known by second app; known by forwards of tablet; current: second "
                "app; highest 195"
            ),
            "kept: DATA version 1 of the second app; delivered to tablet",
            (
                "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA "
                "version 1 of the second app"
            ),
            "owner's layer: none",
            "shows: there",
        ],
    ],
    "step 11: the schema with the whitespace of its file, which has the same fingerprint is taken": [
        [
            "outcome: APPLIED",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            (
                "sender first known by second app; known by forwards of tablet; current: second "
                "app; highest 195"
            ),
            "kept: DATA version 1 of the second app; delivered to tablet",
            (
                "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA "
                "version 1 of the second app"
            ),
            "owner's layer: none",
            "shows: there",
        ],
    ],
    "step 12: a forwarded message with a changed signature is rejected with SIGNATURE_INVALID": [
        [
            "outcome: None",
            "ERROR to tablet: SIGNATURE_INVALID",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    (
        "step 12: a forwarded message with a version changed after it was signed is "
        "rejected with SIGNATURE_INVALID"
    ): [
        [
            "outcome: None",
            "ERROR to tablet: SIGNATURE_INVALID",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 12: a forwarded message with the signature of another key is rejected with SIGNATURE_INVALID": [
        [
            "outcome: None",
            "ERROR to tablet: SIGNATURE_INVALID",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 12: a forwarded message whose sender is no valid key is rejected with SIGNATURE_INVALID": [
        [
            "outcome: None",
            "ERROR to tablet: SIGNATURE_INVALID",
        ],
        [],
    ],
    "step 12 comes before step 13: a message of the device's own key whose signature does not verify": [
        [
            "outcome: None",
            "ERROR to tablet: SIGNATURE_INVALID",
        ],
        [],
    ],
    "step 13: a forwarded message of the device's own key is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 13: a forwarded message of the sibling that forwards it is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 13: a forwarded message of another sibling is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    (
        "step 13: a forwarded message of a removed key of the device's own set is "
        "rejected with INVALID_MESSAGE"
    ): [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "no known sender; highest 195",
        ],
    ],
    "step 14: a forwarded message of a refused key is rejected with NOT_ACCEPTED": [
        [
            "outcome: None",
            "ERROR to tablet: NOT_ACCEPTED",
        ],
        [
            "outcome: None",
            "ERROR to tablet: NOT_ACCEPTED",
        ],
        [],
        [
            "no known sender; highest 195; refused: refused",
        ],
    ],
    (
        "a forwarded MANIFEST of a key the device does not know makes a known sender, and "
        "goes on to the third device and not back"
    ): [
        [
            "outcome: APPLIED",
            "FORWARD 00000001 to laptop, #0: MANIFEST revision 1",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            "sender first known by other app; known by forwards of tablet; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "sender's layer: none",
            "owner's layer: none",
            "shows: none",
        ],
    ],
    (
        "a forwarded DATA of a key the device does not know makes a known sender, and "
        "goes on to the third device and not back"
    ): [
        [
            "outcome: APPLIED",
            "FORWARD 00000001 to laptop, #0: DATA version 1, with the schema as offered",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            "sender first known by other app; known by forwards of tablet; current: other app; highest 195",
            "kept: DATA version 1; delivered to tablet",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            "owner's layer: none",
            "shows: there",
        ],
    ],
    (
        "a forwarded DELETE of a key the device does not know makes a known sender, and "
        "goes on to the third device and not back"
    ): [
        [
            "outcome: APPLIED",
            "FORWARD 00000001 to laptop, #0: DELETE version 4",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            "sender first known by other app; known by forwards of tablet; current: other app; highest 195",
            "kept: DELETE version 4; delivered to tablet",
            "sender's layer: tombstone, version 4, type None, from DELETE version 4",
            "owner's layer: none",
            "shows: deleted_by_sender",
        ],
    ],
    "a forwarded MANIFEST with a higher revision replaces the kept one; the same again is a duplicate": [
        [
            "outcome: APPLIED",
        ],
        [
            "outcome: DUPLICATE",
        ],
        [
            "outcome: DUPLICATE",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
            "ACK of 0000000a to tablet: version 1 DUPLICATE, receiver 1",
            "ACK of 0000000b to tablet: version 1 DUPLICATE, receiver 1",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 2; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
        ],
    ],
    (
        "a forwarded MANIFEST with a lower revision is a duplicate, and the kept one is "
        "due for that sibling again"
    ): [
        [
            "outcome: DUPLICATE",
            "FORWARD 00000001 to tablet, #0: MANIFEST revision 2",
        ],
        [
            "ACK of 0000000a to tablet: version 1 DUPLICATE, receiver 1",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 2; delivered to no sibling",
        ],
    ],
    "a forwarded MANIFEST with the revision 0 is rejected with MANIFEST_INVALID": [
        [
            "outcome: None",
            "ERROR to tablet: MANIFEST_INVALID",
        ],
        [],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
        ],
    ],
    "a forwarded MANIFEST with a body cut short is rejected with MANIFEST_INVALID": [
        [
            "outcome: None",
            "ERROR to tablet: MANIFEST_INVALID",
        ],
        [],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
        ],
    ],
    "a forwarded MANIFEST with a byte after its body is rejected with MANIFEST_INVALID": [
        [
            "outcome: None",
            "ERROR to tablet: MANIFEST_INVALID",
        ],
        [],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
        ],
    ],
    "a forwarded MANIFEST that is not valid makes no sender known": [
        [
            "outcome: None",
            "ERROR to tablet: MANIFEST_INVALID",
        ],
        [
            "no known sender; highest 195",
        ],
    ],
    "a forwarded MANIFEST never takes the place of one that the device took live from the key itself": [
        [
            "taken: True",
            "FORWARD 00000001 to tablet, #0: MANIFEST revision 3",
        ],
        [
            "outcome: DUPLICATE",
        ],
        [
            "ACK of 0000000a to tablet: version 1 DUPLICATE, receiver 1",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 3; delivered to no sibling",
            "kept: DATA version 1; delivered to tablet",
        ],
    ],
    "a forwarded MANIFEST of a removed key of a known sender is not taken": [
        [
            "outcome: DUPLICATE",
        ],
        [
            "ACK of 0000000a to tablet: version 1 DUPLICATE, receiver 1",
        ],
        [
            "sender first known by other app; current: other app, new; removed: other app; highest 195",
            "kept: DATA version 1; delivered to tablet",
        ],
    ],
    (
        "a forwarded DATA with a higher version is taken, the same bytes again are a "
        "duplicate, and of the same version in other bytes the one with the higher "
        "SHA-256 stands"
    ): [
        [
            "outcome: APPLIED",
        ],
        [
            "outcome: DUPLICATE",
        ],
        [
            "outcome: APPLIED",
        ],
        [
            "outcome: DUPLICATE",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
            "ACK of 0000000b to tablet: version 1 DUPLICATE, receiver 1",
            "ACK of 0000000c to tablet: version 1 APPLIED, receiver 1",
            "ACK of 0000000d to tablet: version 1 DUPLICATE, receiver 1",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 2, title 'Dentist'; delivered to tablet",
            (
                "sender's layer: there, version 2, type axt.example.v1.Appointment, from DATA "
                "version 2, title 'Dentist'"
            ),
            "owner's layer: none",
            "shows: there",
        ],
    ],
    (
        "a forwarded DATA with a lower version is a duplicate, and the kept message is "
        "due for that sibling again"
    ): [
        [
            "outcome: DUPLICATE",
            "FORWARD 00000001 to tablet, #0: DATA version 3, with the schema as offered",
        ],
        [
            "ACK of 0000000a to tablet: version 1 DUPLICATE, receiver 1",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 3; delivered to no sibling",
            "sender's layer: there, version 3, type axt.example.v1.Appointment, from DATA version 3",
            "owner's layer: none",
            "shows: there",
        ],
    ],
    (
        "the version rule comes before the body: a forwarded DATA of the kept version "
        "that does not decode is a duplicate"
    ): [
        [
            "outcome: DUPLICATE",
        ],
        [
            "ACK of 0000000a to tablet: version 1 DUPLICATE, receiver 1",
        ],
    ],
    "a forwarded DATA with an id that is no UUID is rejected with RECORD_ID_INVALID": [
        [
            "outcome: None",
            "ERROR to tablet: RECORD_ID_INVALID",
        ],
        [],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            "owner's layer: none",
            "shows: there",
        ],
    ],
    "a forwarded DATA with the nil UUID as its id is rejected with RECORD_ID_INVALID": [
        [
            "outcome: None",
            "ERROR to tablet: RECORD_ID_INVALID",
        ],
        [],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            "owner's layer: none",
            "shows: there",
        ],
    ],
    "a forwarded DATA with the version 0 is rejected with VERSION_INVALID": [
        [
            "outcome: None",
            "ERROR to tablet: VERSION_INVALID",
        ],
        [],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            "owner's layer: none",
            "shows: there",
        ],
    ],
    "a forwarded DELETE with the version 0 is rejected with VERSION_INVALID": [
        [
            "outcome: None",
            "ERROR to tablet: VERSION_INVALID",
        ],
        [],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            "owner's layer: none",
            "shows: there",
        ],
    ],
    "a forwarded DATA of another type than the record's is rejected with TYPE_CHANGED": [
        [
            "outcome: None",
            "ERROR to tablet: TYPE_CHANGED",
        ],
        [],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            "owner's layer: none",
            "shows: there",
        ],
    ],
    "a forwarded DATA of another type than the owner's layer keeps is rejected with TYPE_CHANGED": [
        [
            "outcome: None",
            "ERROR to tablet: TYPE_CHANGED",
        ],
        [],
        [
            "sender first known by other app; current: other app; highest 205",
            "sender's layer: none",
            "owner's layer: state stamp 205; location@200t; type axt.example.v1.Appointment",
            "tablet: known, delivered: all",
            "shows: none",
        ],
    ],
    "a forwarded DATA with a byte after its record is rejected with UNDECODABLE": [
        [
            "outcome: None",
            "ERROR to tablet: UNDECODABLE",
        ],
        [],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            "owner's layer: none",
            "shows: there",
        ],
    ],
    "a forwarded DATA with a body cut short is rejected with UNDECODABLE": [
        [
            "outcome: None",
            "ERROR to tablet: UNDECODABLE",
        ],
        [],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            "owner's layer: none",
            "shows: there",
        ],
    ],
    "a forwarded DATA with a start in a thirteenth month is rejected with VALUE_INVALID": [
        [
            "outcome: None",
            "ERROR to tablet: VALUE_INVALID, field start",
        ],
        [],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            "owner's layer: none",
            "shows: there",
        ],
    ],
    "a forwarded DATA with a value that breaks a check of an attribute is taken all the same": [
        [
            "outcome: APPLIED",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 2; delivered to tablet",
            "sender's layer: there, version 2, type axt.example.v1.Appointment, from DATA version 2",
            "owner's layer: none",
            "shows: there",
        ],
    ],
    "a forwarded DATA of a type the device does not know is taken and kept": [
        [
            "outcome: APPLIED",
            (
                "FORWARD 00000001 to laptop, #0: DATA version 1, id 7b1e6c2a, name 'Mimi', species 'cat', "
                "breed 'Maine Coon', sex 'FEMALE', neutered True, birthday changed, microchip "
                "'276098100000000', notes '', relations changed, with a schema"
            ),
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to laptop, tablet",
            "kept: DATA version 1; delivered to laptop, tablet",
            (
                "kept: DATA version 1, id 7b1e6c2a, name 'Mimi', species 'cat', breed 'Maine Coon', sex "
                "'FEMALE', neutered True, birthday changed, microchip '276098100000000', notes '', relations "
                "changed; delivered to tablet"
            ),
            (
                "sender's layer: there, version 1, type axt.example.v1.Pet, from DATA version "
                "1, id 7b1e6c2a, "
                "name 'Mimi', species 'cat', breed 'Maine Coon', sex 'FEMALE', neutered True, birthday "
                "changed, microchip '276098100000000', notes '', relations changed"
            ),
            "owner's layer: none",
            "shows: there",
        ],
    ],
    "a forwarded DATA whose schema does not resolve against the device's own is taken": [
        [
            "outcome: APPLIED",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 2, title 7; delivered to tablet",
            (
                "sender's layer: there, version 2, type axt.example.v1.Appointment, from DATA "
                "version 2, title 7"
            ),
            "owner's layer: none",
            "shows: there",
        ],
    ],
    (
        "a forwarded DELETE leaves a tombstone, an older DATA is kept beside it, and a "
        "later DATA brings the record back"
    ): [
        [
            "outcome: APPLIED",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "kept: DELETE version 3; delivered to tablet",
            (
                "sender's layer: tombstone, version 3, type axt.example.v1.Appointment, from "
                "DELETE version 3; beside it DATA version 1"
            ),
            "owner's layer: none",
            "shows: deleted_by_sender",
        ],
        [
            "outcome: APPLIED",
        ],
        [
            "outcome: DUPLICATE",
            "FORWARD 00000001 to tablet, #0: DATA version 2, with the schema as offered",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 2; delivered to no sibling",
            "kept: DELETE version 3; delivered to tablet",
            (
                "sender's layer: tombstone, version 3, type axt.example.v1.Appointment, from "
                "DELETE version 3; beside it DATA version 2"
            ),
            "owner's layer: none",
            "shows: deleted_by_sender",
        ],
        [
            "outcome: APPLIED",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
            "ACK of 0000000b to tablet: version 1 APPLIED, receiver 1",
            "ACK of 0000000c to tablet: version 1 APPLIED, receiver 1",
            "ACK of 0000000d to tablet: version 1 DUPLICATE, receiver 1",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 4; delivered to tablet",
            "sender's layer: there, version 4, type axt.example.v1.Appointment, from DATA version 4",
            "owner's layer: none",
            "shows: there",
        ],
    ],
    (
        "a forwarded DATA of a removed key is taken when the device's removal of that key "
        "is delivered to the sibling"
    ): [
        [
            "outcome: APPLIED",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            "sender first known by other app; current: other app, new; removed: other app; highest 195",
            "kept: DEVICE_ADD of the other app, new by the other app; delivered to tablet",
            "kept: DEVICE_REMOVE of the other app by the other app, new; delivered to tablet",
            "kept: DATA version 2; delivered to tablet",
            "sender's layer: there, version 2, type axt.example.v1.Appointment, from DATA version 2",
            "owner's layer: none",
            "shows: there",
        ],
    ],
    (
        "a forwarded DATA of a removed key is rejected with NOT_ACCEPTED when the sibling "
        "has not shown that it has the removal, and the removal goes to it"
    ): [
        [
            "outcome: None",
            "ERROR to tablet: NOT_ACCEPTED",
            "FORWARD 00000001 to tablet, #0: DEVICE_REMOVE of the other app by the other app, new",
        ],
        [],
        [
            "sender first known by other app; current: other app, new; removed: other app; highest 195",
            "kept: DEVICE_ADD of the other app, new by the other app; delivered to tablet",
            "kept: DEVICE_REMOVE of the other app by the other app, new; delivered to no sibling",
            "sender's layer: none",
            "owner's layer: none",
            "shows: none",
        ],
    ],
    (
        "a sibling that has forwarded a removal of that key has it, whatever the device "
        "did with it: its DATA of the removed key is then taken"
    ): [
        [
            "outcome: DUPLICATE",
        ],
        [
            "outcome: APPLIED",
        ],
        [
            "ACK of 0000000a to tablet: version 1 DUPLICATE, receiver 1",
            "ACK of 0000000b to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            "sender first known by other app; current: other app, new; removed: other app; highest 195",
            "kept: DEVICE_ADD of the other app, new by the other app; delivered to tablet",
            "kept: DEVICE_REMOVE of the other app by the other app, new; delivered to tablet",
            "kept: DATA version 2; delivered to tablet",
            "sender's layer: there, version 2, type axt.example.v1.Appointment, from DATA version 2",
            "owner's layer: none",
            "shows: there",
        ],
    ],
    (
        "after NOT_ACCEPTED for a message of a removed key, the sibling's forward of the "
        "removal makes it due again after the ACK; once more, and then it is settled"
    ): [
        [
            "FORWARD 00000001 to tablet, #0: DATA version 2, with the schema as offered",
        ],
        [
            "outcome: None",
        ],
        [
            "outcome: DUPLICATE",
        ],
        [
            "ACK of 0000000a to tablet: version 1 DUPLICATE, receiver 1",
            "FORWARD 00000002 to tablet, #0: DATA version 2, with the schema as offered",
        ],
        [
            "outcome: None",
            "FORWARD 00000003 to tablet, #0: DATA version 2, with the schema as offered",
        ],
        [
            "outcome: None",
        ],
        [
            "sender first known by other app; current: other app, new; removed: other app; highest 195",
            "kept: DEVICE_ADD of the other app, new by the other app; delivered to tablet",
            "kept: DEVICE_REMOVE of the other app by the other app, new; delivered to tablet",
            "kept: DATA version 2; delivered to no sibling",
            "sender's layer: there, version 2, type axt.example.v1.Appointment, from DATA version 2",
            "owner's layer: none",
            "shows: there",
        ],
    ],
    "a removal that the device only keeps to try again does not make the key removed": [
        [
            "outcome: APPLIED",
        ],
        [
            "outcome: APPLIED",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
            "ACK of 0000000b to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 2; delivered to tablet",
            "sender's layer: there, version 2, type axt.example.v1.Appointment, from DATA version 2",
            "owner's layer: none",
            "shows: there",
        ],
    ],
    "case 1 of step 7, forwarded: a DATA below the tombstone goes beside it; APPLIED": [
        [
            "outcome: APPLIED",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 2; delivered to tablet",
            "kept: DELETE version 3; delivered to tablet",
            (
                "sender's layer: tombstone, version 3, type axt.example.v1.Appointment, from "
                "DELETE version 3; beside it DATA version 2"
            ),
            "owner's layer: none",
            "shows: deleted_by_sender",
        ],
    ],
    "case 2 of step 7, forwarded: the kept message in other bytes that stands replaces it; APPLIED": [
        [
            "outcome: DUPLICATE",
        ],
        [
            "outcome: APPLIED",
        ],
        [
            "ACK of 0000000a to tablet: version 1 DUPLICATE, receiver 1",
            "ACK of 0000000b to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 2, title 'Dentist'; delivered to tablet",
            (
                "sender's layer: there, version 2, type axt.example.v1.Appointment, from DATA "
                "version 2, title 'Dentist'"
            ),
            "owner's layer: none",
            "shows: there",
        ],
    ],
    (
        "case 3 of step 7, forwarded: a DELETE takes the place of a DATA of the same "
        "version, and nothing stays beside it; APPLIED"
    ): [
        [
            "outcome: APPLIED",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DELETE version 2; delivered to tablet",
            "sender's layer: tombstone, version 2, type axt.example.v1.Appointment, from DELETE version 2",
            "owner's layer: none",
            "shows: deleted_by_sender",
        ],
    ],
    (
        "case 4 of step 7, forwarded: the DATA beside the tombstone in other bytes that "
        "stands replaces it; APPLIED"
    ): [
        [
            "outcome: DUPLICATE",
        ],
        [
            "outcome: APPLIED",
        ],
        [
            "ACK of 0000000a to tablet: version 1 DUPLICATE, receiver 1",
            "ACK of 0000000b to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 2, title 'Dentist'; delivered to tablet",
            "kept: DELETE version 3; delivered to tablet",
            (
                "sender's layer: tombstone, version 3, type axt.example.v1.Appointment, from "
                "DELETE version 3; beside it DATA version 2, title 'Dentist'"
            ),
            "owner's layer: none",
            "shows: deleted_by_sender",
        ],
    ],
    "a DATA below the tombstone, forwarded, that does not decode is not taken": [
        [
            "outcome: None",
            "ERROR to tablet: UNDECODABLE",
        ],
        [],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DELETE version 3; delivered to tablet",
            "sender's layer: tombstone, version 3, type axt.example.v1.Appointment, from DELETE version 3",
            "owner's layer: none",
            "shows: deleted_by_sender",
        ],
    ],
    (
        "case 1 of step 7, from the sender: a DATA below the tombstone goes beside it; "
        "the outcome of the version rule"
    ): [
        [
            "outcome: STALE",
            "FORWARD 00000001 to tablet, #0: DATA version 2, with the schema as offered",
        ],
        [
            "ACK to other app: version 2 STALE, receiver 3",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 2; delivered to no sibling",
            "kept: DELETE version 3; delivered to tablet",
            (
                "sender's layer: tombstone, version 3, type axt.example.v1.Appointment, from "
                "DELETE version 3; beside it DATA version 2"
            ),
            "owner's layer: none",
            "shows: deleted_by_sender",
        ],
    ],
    (
        "case 2 of step 7, from the sender: the kept message in other bytes that stands "
        "replaces it; the outcome of the version rule"
    ): [
        [
            "outcome: DUPLICATE",
        ],
        [
            "outcome: DUPLICATE",
            "FORWARD 00000001 to tablet, #0: DATA version 2, title 'Dentist', with the schema as offered",
        ],
        [
            "ACK to other app: version 2 DUPLICATE, receiver 2",
            "ACK to other app: version 2 DUPLICATE, receiver 2",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 2, title 'Dentist'; delivered to no sibling",
            (
                "sender's layer: there, version 2, type axt.example.v1.Appointment, from DATA "
                "version 2, title 'Dentist'"
            ),
            "owner's layer: none",
            "shows: there",
        ],
    ],
    (
        "case 3 of step 7, from the sender: a DELETE takes the place of a DATA of the "
        "same version, and nothing stays beside it; the outcome of the version rule"
    ): [
        [
            "outcome: DUPLICATE",
            "FORWARD 00000001 to tablet, #0: DELETE version 2",
        ],
        [
            "ACK to other app: version 2 DUPLICATE, receiver 2",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DELETE version 2; delivered to no sibling",
            "sender's layer: tombstone, version 2, type axt.example.v1.Appointment, from DELETE version 2",
            "owner's layer: none",
            "shows: deleted_by_sender",
        ],
    ],
    (
        "case 4 of step 7, from the sender: the DATA beside the tombstone in other bytes "
        "that stands replaces it; the outcome of the version rule"
    ): [
        [
            "outcome: STALE",
        ],
        [
            "outcome: STALE",
            "FORWARD 00000001 to tablet, #0: DATA version 2, title 'Dentist', with the schema as offered",
        ],
        [
            "ACK to other app: version 2 STALE, receiver 3",
            "ACK to other app: version 2 STALE, receiver 3",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 2, title 'Dentist'; delivered to no sibling",
            "kept: DELETE version 3; delivered to tablet",
            (
                "sender's layer: tombstone, version 3, type axt.example.v1.Appointment, from "
                "DELETE version 3; beside it DATA version 2, title 'Dentist'"
            ),
            "owner's layer: none",
            "shows: deleted_by_sender",
        ],
    ],
    "a DATA below the tombstone, from the sender, that does not decode is not taken": [
        [
            "outcome: STALE",
        ],
        [
            "ACK to other app: version 2 STALE, receiver 3",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DELETE version 3; delivered to tablet",
            "sender's layer: tombstone, version 3, type axt.example.v1.Appointment, from DELETE version 3",
            "owner's layer: none",
            "shows: deleted_by_sender",
        ],
    ],
    "a DELETE above a DELETE keeps the DATA beside the new tombstone": [
        [
            "outcome: APPLIED",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 2; delivered to tablet",
            "kept: DELETE version 5; delivered to tablet",
            (
                "sender's layer: tombstone, version 5, type axt.example.v1.Appointment, from "
                "DELETE version 5; beside it DATA version 2"
            ),
            "owner's layer: none",
            "shows: deleted_by_sender",
        ],
    ],
    "a DATA above the DELETE ends the DATA beside the tombstone": [
        [
            "outcome: APPLIED",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 4; delivered to tablet",
            "sender's layer: there, version 4, type axt.example.v1.Appointment, from DATA version 4",
            "owner's layer: none",
            "shows: there",
        ],
    ],
    "a forwarded DATA below the DATA beside the tombstone makes only that DATA due again, not the DELETE": [
        [
            "outcome: DUPLICATE",
            "FORWARD 00000001 to tablet, #0: DATA version 2, with the schema as offered",
        ],
        [
            "ACK of 0000000a to tablet: version 1 DUPLICATE, receiver 1",
        ],
    ],
    "a forwarded DELETE for an id the device does not have leaves a tombstone without a type": [
        [
            "outcome: APPLIED",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "kept: DELETE version 3; delivered to tablet",
            "sender's layer: tombstone, version 3, type None, from DELETE version 3",
            "owner's layer: none",
            "shows: deleted_by_sender",
        ],
    ],
    "a forwarded DATA changes nothing in the owner's layer, and nothing goes to its sender": [
        [
            "outcome: APPLIED",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            "sender first known by other app; current: other app; highest 205",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 3, location 'Praxis'; delivered to tablet",
            (
                "sender's layer: there, version 3, type axt.example.v1.Appointment, from DATA "
                "version 3, location 'Praxis'"
            ),
            "owner's layer: state stamp 205; location@200t; type axt.example.v1.Appointment",
            "tablet: known, delivered: all",
            "shows: there; the owner's value in location",
        ],
    ],
    (
        "a forwarded DEVICE_ADD and a forwarded DEVICE_REMOVE are applied and kept, one "
        "by one; a repeat of each is a duplicate"
    ): [
        [
            "outcome: APPLIED",
            "FORWARD 00000001 to laptop, #0: DEVICE_ADD of the other app, new by the other app",
        ],
        [
            "outcome: DUPLICATE",
        ],
        [
            "sender first known by other app; current: other app, new, other app; highest 195",
            "kept: DEVICE_ADD of the other app, new by the other app; delivered to tablet",
            "kept: MANIFEST revision 1; delivered to laptop, tablet",
            "kept: DATA version 1; delivered to laptop, tablet",
        ],
        [
            "outcome: APPLIED",
            "FORWARD 00000002 to laptop, #0: DEVICE_REMOVE of the other app by the other app, new",
        ],
        [
            "outcome: DUPLICATE",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
            "ACK of 0000000b to tablet: version 1 DUPLICATE, receiver 1",
            "ACK of 0000000c to tablet: version 1 APPLIED, receiver 1",
            "ACK of 0000000d to tablet: version 1 DUPLICATE, receiver 1",
        ],
        [
            "sender first known by other app; current: other app, new; removed: other app; highest 195",
            "kept: DEVICE_ADD of the other app, new by the other app; delivered to tablet",
            "kept: DEVICE_REMOVE of the other app by the other app, new; delivered to tablet",
            "kept: DATA version 1; delivered to laptop, tablet",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            "owner's layer: none",
            "shows: there",
        ],
    ],
    (
        "a forwarded DEVICE_ADD whose signer the device does not know, for a current key "
        "of a known sender, adds the signer to that sender"
    ): [
        [
            "outcome: APPLIED",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            "sender first known by other app; current: other app, new, other app; highest 195",
            "kept: DEVICE_ADD of the other app by the other app, new; delivered to tablet",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
        ],
    ],
    (
        "a forwarded DEVICE_ADD whose signer and device the device does not know makes "
        "the signer a known sender with both keys"
    ): [
        [
            "outcome: APPLIED",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            (
                "sender first known by other app; known by forwards of tablet; current: other "
                "app, new, other app; highest 195"
            ),
            "kept: DEVICE_ADD of the other app, new by the other app; delivered to tablet",
        ],
    ],
    (
        "a forwarded DEVICE_REMOVE of a key that is not yet a key of the sender is kept "
        "and applied after the addition; it is a kept message only from then on"
    ): [
        [
            "outcome: APPLIED",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to laptop, tablet",
            "kept: DATA version 1; delivered to laptop, tablet",
        ],
        [
            "outcome: APPLIED",
            "FORWARD 00000001 to laptop, #0: DEVICE_ADD of the other app, new by the other app",
            "FORWARD 00000002 to laptop, #1: DEVICE_REMOVE of the other app, new by the other app",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
            "ACK of 0000000b to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            "sender first known by other app; current: other app; removed: other app, new; highest 195",
            "kept: DEVICE_ADD of the other app, new by the other app; delivered to tablet",
            "kept: DEVICE_REMOVE of the other app, new by the other app; delivered to tablet",
            "kept: MANIFEST revision 1; delivered to laptop, tablet",
            "kept: DATA version 1; delivered to laptop, tablet",
        ],
    ],
    (
        "a forwarded DEVICE_REMOVE whose signer the device does not know makes the signer "
        "a known sender and is kept to be tried again"
    ): [
        [
            "outcome: APPLIED",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            "sender first known by other app; known by forwards of tablet; current: other app; highest 195",
        ],
    ],
    "a forwarded DEVICE_ADD with a proof that does not verify is rejected with DEVICE_REJECTED": [
        [
            "outcome: None",
            "ERROR to tablet: DEVICE_REJECTED",
        ],
        [],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
        ],
        [
            "no known sender; highest 195",
        ],
    ],
    "a forwarded DEVICE_REMOVE with its own signer as the device is rejected with DEVICE_REJECTED": [
        [
            "outcome: None",
            "ERROR to tablet: DEVICE_REJECTED",
        ],
        [],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
        ],
        [
            "no known sender; highest 195",
        ],
    ],
    (
        "a forwarded DEVICE_REMOVE with a removed key as its signer and a current key as "
        "its device is rejected with DEVICE_REJECTED"
    ): [
        [
            "outcome: None",
            "ERROR to tablet: DEVICE_REJECTED",
        ],
        [],
        [
            "sender first known by other app; current: other app, new; removed: other app; highest 195",
            "kept: DATA version 1; delivered to tablet",
        ],
        [
            "no known sender; highest 195",
        ],
    ],
    (
        "a forwarded DEVICE_ADD with a signer the device does not know and a removed key "
        "of another known sender as its device is rejected with DEVICE_REJECTED"
    ): [
        [
            "outcome: None",
            "ERROR to tablet: DEVICE_REJECTED",
        ],
        [],
        [
            "sender first known by other app; current: other app, new; removed: other app; highest 195",
            "kept: DATA version 1; delivered to tablet",
        ],
        [
            "no known sender; highest 195",
        ],
    ],
    (
        "a forwarded DEVICE_ADD with a refused key as its device: it counts as a key of "
        "no known sender, and the key stops being refused"
    ): [
        [
            "outcome: APPLIED",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            (
                "sender first known by second app; known by forwards of tablet; current: second "
                "app, refused; highest 195"
            ),
            "kept: DEVICE_ADD of the refused by the second app; delivered to tablet",
        ],
    ],
    (
        "a forwarded DEVICE_ADD with a refused key as its signer: it counts as a key of "
        "no known sender, and the key stops being refused"
    ): [
        [
            "outcome: APPLIED",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            (
                "sender first known by refused; known by forwards of tablet; current: second app, "
                "refused; highest 195"
            ),
            "kept: DEVICE_ADD of the second app by the refused; delivered to tablet",
        ],
    ],
    (
        "a forwarded DEVICE_ADD rejected only because its signer is removed by now is "
        "kept and tried again: APPLIED, and no try applies it while the signer stays "
        "removed"
    ): [
        [
            "outcome: APPLIED",
        ],
        [
            "outcome: APPLIED",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
            "ACK of 0000000b to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            (
                "sender first known by other app; current: stranger, other app, new; removed: "
                "other app; highest 195"
            ),
            "kept: DEVICE_ADD of the stranger by the other app, new; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
        ],
        [
            "no known sender; highest 195",
        ],
    ],
    (
        "a forwarded DEVICE_ADD that joins two senders: one sender, the records by the "
        "version rule, and the owner's layers merged under a new state stamp"
    ): [
        [
            "outcome: APPLIED",
            "CHANGE, origin other app, to tablet, version 206, state 206, in part: notes@190t",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            "sender first known by other app; current: second app, other app; highest 206",
            "kept: DEVICE_ADD of the second app by the other app; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            "owner's layer: state stamp 206; notes@190t location@200t; type axt.example.v1.Appointment",
            "tablet: known, delivered: location",
            "shows: there; the owner's value in location, notes",
        ],
        [
            "sender first known by other app; current: second app, other app; highest 206",
            "kept: DEVICE_ADD of the second app by the other app; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
        ],
    ],
    "a join whose merge takes nothing from the other layer takes no new state stamp": [
        [
            "outcome: APPLIED",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            "sender first known by other app; current: second app, other app; highest 205",
            "kept: DEVICE_ADD of the second app by the other app; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            "owner's layer: state stamp 201; location@200t; type axt.example.v1.Appointment",
            "tablet: known, delivered: all",
            "shows: there; the owner's value in location",
        ],
    ],
    "a forwarded DEVICE_ADD whose body does not decode is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
        ],
    ],
    (
        "a DATA of another app is answered by the device that got it and forwarded to "
        "each sibling; each outcome delivers it"
    ): [
        [
            "outcome: APPLIED",
            "FORWARD 00000001 to laptop, #0: DATA version 2, with the schema as offered",
            "FORWARD 00000002 to tablet, #0: DATA version 2, with the schema as offered",
        ],
        [
            "ACK to other app: version 2 APPLIED, receiver 2",
        ],
        [
            "outcome: None",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to laptop, tablet",
            "kept: DATA version 2; delivered to tablet",
            "sender's layer: there, version 2, type axt.example.v1.Appointment, from DATA version 2",
            "owner's layer: none",
            "shows: there",
        ],
        [
            "outcome: None",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to laptop, tablet",
            "kept: DATA version 2; delivered to laptop, tablet",
            "sender's layer: there, version 2, type axt.example.v1.Appointment, from DATA version 2",
            "owner's layer: none",
            "shows: there",
        ],
        [],
    ],
    (
        "STALE for a forward is taken as DUPLICATE; the first outcome stands, and an "
        "entry for another id is ignored"
    ): [
        [
            "outcome: APPLIED",
            "FORWARD 00000001 to tablet, #0: DATA version 2, with the schema as offered",
        ],
        [
            "outcome: None",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 2; delivered to tablet",
        ],
        [
            "outcome: None",
        ],
        [
            "outcome: None",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 2; delivered to tablet",
        ],
    ],
    "an entry with the version 2 is no outcome of a forward": [
        [
            "outcome: APPLIED",
            "FORWARD 00000001 to tablet, #0: DATA version 2, with the schema as offered",
        ],
        [
            "outcome: None",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 2; delivered to no sibling",
        ],
    ],
    "an ACK of a sibling with the outcome MERGED for a forward is not valid, and delivers nothing": [
        [
            "outcome: APPLIED",
            "FORWARD 00000001 to tablet, #0: DATA version 2, with the schema as offered",
        ],
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 2; delivered to no sibling",
        ],
    ],
    (
        "a later version takes the place of a kept message: it is forwarded anew, and an "
        "outcome for the forward of the earlier one delivers nothing"
    ): [
        [
            "outcome: APPLIED",
            "FORWARD 00000001 to tablet, #0: DATA version 2, with the schema as offered",
        ],
        [
            "outcome: APPLIED",
            "FORWARD 00000002 to tablet, #0: DATA version 3, with the schema as offered",
        ],
        [
            "outcome: None",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 3; delivered to no sibling",
            "sender's layer: there, version 3, type axt.example.v1.Appointment, from DATA version 3",
            "owner's layer: none",
            "shows: there",
        ],
    ],
    (
        "after FORMAT_UNSUPPORTED for its own envelope of a sibling for a FORWARD, the "
        "device sends the same FORWARD again"
    ): [
        [
            "outcome: APPLIED",
            "FORWARD 00000001 to tablet, #0: DATA version 2, with the schema as offered",
        ],
        [
            "outcome: None",
            "FORWARD 00000001 to tablet, #0: DATA version 2, with the schema as offered",
        ],
        [
            "FORWARD 00000001 to tablet, #0: DATA version 2, with the schema as offered",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 2; delivered to no sibling",
        ],
    ],
    "after FORMAT_UNSUPPORTED for the message inside of a sibling for a FORWARD, the forward is settled": [
        [
            "outcome: APPLIED",
            "FORWARD 00000001 to tablet, #0: DATA version 2, with the schema as offered",
        ],
        [
            "outcome: None",
        ],
        [],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 2; delivered to no sibling",
        ],
    ],
    "after NOT_ACCEPTED of a sibling for a FORWARD, the forward is settled": [
        [
            "outcome: APPLIED",
            "FORWARD 00000001 to tablet, #0: DATA version 2, with the schema as offered",
        ],
        [
            "outcome: None",
        ],
        [],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 2; delivered to no sibling",
        ],
    ],
    "after DEVICE_REJECTED of a sibling for a FORWARD, the forward is settled": [
        [
            "outcome: APPLIED",
            "FORWARD 00000001 to tablet, #0: DATA version 2, with the schema as offered",
        ],
        [
            "outcome: None",
        ],
        [],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 2; delivered to no sibling",
        ],
    ],
    "after INVALID_MESSAGE of a sibling for a FORWARD, the forward is settled": [
        [
            "outcome: APPLIED",
            "FORWARD 00000001 to tablet, #0: DATA version 2, with the schema as offered",
        ],
        [
            "outcome: None",
        ],
        [],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 2; delivered to no sibling",
        ],
    ],
    "after SIGNATURE_INVALID of a sibling for a FORWARD, the forward is settled": [
        [
            "outcome: APPLIED",
            "FORWARD 00000001 to tablet, #0: DATA version 2, with the schema as offered",
        ],
        [
            "outcome: None",
        ],
        [],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 2; delivered to no sibling",
        ],
    ],
    "after TOO_LARGE of a sibling for a FORWARD, the forward is settled": [
        [
            "outcome: APPLIED",
            "FORWARD 00000001 to tablet, #0: DATA version 2, with the schema as offered",
        ],
        [
            "outcome: None",
        ],
        [],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 2; delivered to no sibling",
        ],
    ],
    "an ERROR that names no forward the device keeps changes nothing": [
        [
            "outcome: APPLIED",
            "FORWARD 00000001 to tablet, #0: DATA version 2, with the schema as offered",
        ],
        [
            "outcome: None",
        ],
        [
            "outcome: None",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 2; delivered to tablet",
        ],
    ],
    "a forward that an error settled is due again after a RESYNC of that sibling, as a new forward": [
        [
            "outcome: APPLIED",
            "FORWARD 00000001 to tablet, #0: DATA version 2, with the schema as offered",
        ],
        [
            "outcome: None",
        ],
        [
            "outcome: None",
            "FORWARD 00000003 to tablet, #1: DATA version 2, with the schema as offered",
            "FORWARD 00000002 to tablet, #0: MANIFEST revision 1",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
            "ACK to other app: version 2 APPLIED, receiver 2",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to no sibling",
            "kept: DATA version 2; delivered to no sibling",
        ],
    ],
    (
        "on the first channel to a sibling every kept message is forwarded, sender by sender: the additions, "
        "then the manifests, then the record messages"
    ): [
        [
            "FORWARD 00000002 to tablet, #1: DEVICE_ADD of the other app, new by the other app",
            "FORWARD 00000005 to tablet, #4: DATA version 1, with the schema as offered",
            "FORWARD 00000003 to tablet, #2: MANIFEST revision 1 of the other app, new",
            "FORWARD 00000006 to tablet, #5: DATA version 1, id 7b1e6c2a, with the schema as offered",
            "FORWARD 00000001 to tablet, #0: DATA version 1 of the second app, with the schema as offered",
            "FORWARD 00000004 to tablet, #3: MANIFEST revision 1",
        ],
        [
            "sender first known by other app; current: other app, new, other app; highest 195",
            "kept: DEVICE_ADD of the other app, new by the other app; delivered to no sibling",
            "kept: MANIFEST revision 1 of the other app, new; delivered to no sibling",
            "kept: MANIFEST revision 1; delivered to no sibling",
            "kept: DATA version 1; delivered to no sibling",
            "kept: DATA version 1, id 7b1e6c2a; delivered to no sibling",
        ],
        [
            "sender first known by second app; current: second app; highest 195",
            "kept: DATA version 1 of the second app; delivered to no sibling",
        ],
    ],
    (
        "a FORWARD without an outcome goes again in a later connection as the same "
        "message, and after 15 days as a new forward"
    ): [
        [
            "outcome: APPLIED",
            "FORWARD 00000001 to tablet, #0: DATA version 2, with the schema as offered",
        ],
        [
            "FORWARD 00000001 to tablet, #0: DATA version 2, with the schema as offered",
        ],
        [],
        [
            "FORWARD 00000002 to tablet, #0: DATA version 2, with the schema as offered",
        ],
    ],
    (
        "through a relay a FORWARD without an outcome goes again after 14 days, the same "
        "message, and not before"
    ): [
        [
            "outcome: APPLIED",
            "FORWARD 00000001 to tablet, #0: DATA version 2, with the schema as offered",
        ],
        [],
        [
            "FORWARD 00000001 to tablet, #0: DATA version 2, with the schema as offered",
        ],
        [],
        [
            "FORWARD 00000001 to tablet, #0: DATA version 2, with the schema as offered",
        ],
    ],
    "an outcome that arrives later than 15 days after the FORWARD last went is ignored": [
        [
            "outcome: APPLIED",
            "FORWARD 00000001 to tablet, #0: DATA version 2, with the schema as offered",
        ],
        [],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 2; delivered to no sibling",
        ],
        [],
        [
            "outcome: None",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 2; delivered to no sibling",
        ],
    ],
    (
        "a kept message whose FORWARD would be above 16 MiB is not forwarded; the owner's "
        "layer of its record still travels"
    ): [
        [
            "outcome: APPLIED",
        ],
        [
            "made: True",
            "CHANGE, origin other app, to tablet, version 201, state 201, whole: location@200p",
        ],
        [
            "sender first known by other app; current: other app; highest 201",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 2, notes changed; delivered to no sibling",
        ],
    ],
    (
        "the answer to a RESYNC holds a new forward of every kept message, then the records of the set, then "
        "the owner's layers, and then the acknowledgement"
    ): [
        [
            "outcome: None",
            "CHANGE to tablet, version 206, state 206, whole: all eight@100p",
            "CHANGE, origin other app, to tablet, version 207, state 207, whole: location@200t",
            "FORWARD 00000002 to tablet, #1: DATA version 1, with the schema as offered",
            "FORWARD 00000001 to tablet, #0: MANIFEST revision 1",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            "sender first known by other app; current: other app; highest 207",
            "kept: MANIFEST revision 1; delivered to no sibling",
            "kept: DATA version 1; delivered to no sibling",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            "owner's layer: state stamp 207; location@200t; type axt.example.v1.Appointment",
            "tablet: not known",
            "shows: there; the owner's value in location",
        ],
    ],
    "after a RESYNC the outcome of a forward that the device sent before it is ignored": [
        [
            "outcome: APPLIED",
            "FORWARD 00000001 to tablet, #0: DATA version 2, with the schema as offered",
        ],
        [
            "outcome: None",
            "FORWARD 00000003 to tablet, #1: DATA version 2, with the schema as offered",
            "FORWARD 00000002 to tablet, #0: MANIFEST revision 1",
        ],
        [
            "outcome: None",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to no sibling",
            "kept: DATA version 2; delivered to no sibling",
        ],
    ],
    (
        "forgetting a sender discards its kept messages and owner's layers and sends "
        "nothing; a forward of a sibling makes it known again"
    ): [
        [],
        [],
        [
            "no known sender; highest 205; forgotten: other app",
        ],
        [
            "outcome: APPLIED",
            "RESYNC 00000001 to tablet",
        ],
        [
            (
                "sender first known by other app; known by forwards of tablet; current: other "
                "app; highest 205; a request open to tablet"
            ),
            "kept: DATA version 2; delivered to tablet",
            "sender's layer: there, version 2, type axt.example.v1.Appointment, from DATA version 2",
            "owner's layer: none",
            "shows: there",
        ],
    ],
    (
        "after forgetting, a forward of a message signed with a removed key of the sender "
        "is rejected with NOT_ACCEPTED, and one of another key makes the sender known "
        "again"
    ): [
        [],
        [
            "no known sender; highest 195; refused: other app; forgotten: other app, new",
        ],
        [
            "outcome: None",
            "ERROR to tablet: NOT_ACCEPTED",
        ],
        [
            "outcome: APPLIED",
            "RESYNC 00000001 to tablet",
        ],
        [
            "ACK of 0000000b to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            (
                "sender first known by other app; known by forwards of tablet; current: other "
                "app, new; removed: other app; highest 195; a request open to tablet"
            ),
            "kept: DATA version 1 of the other app, new; delivered to tablet",
        ],
    ],
    (
        "a forwarded addition that names a forgotten key as its device makes the sender "
        "known again, and the device asks that sibling with RESYNC"
    ): [
        [],
        [
            "outcome: APPLIED",
            "RESYNC 00000001 to tablet",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            (
                "sender first known by other app; known by forwards of tablet; current: second "
                "app, other app; highest 195; a request open to tablet"
            ),
            "kept: DEVICE_ADD of the other app by the second app; delivered to tablet",
        ],
    ],
    "a forward of a forgotten key whose message fails a later step leaves the sender forgotten": [
        [],
        [
            "outcome: None",
            "ERROR to tablet: UNDECODABLE",
        ],
        [],
        [
            "no known sender; highest 195; forgotten: other app",
        ],
    ],
    (
        "an installation without a sibling: the user's deletion goes on standing beside "
        "the sender's tombstone, and a later DATA is KEPT"
    ): [
        [
            "outcome: APPLIED",
        ],
        [
            "outcome: KEPT",
        ],
        [
            "ACK to other app: version 3 APPLIED, receiver 3",
            "ACK to other app: version 4 KEPT, receiver 4",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to no sibling",
            "kept: DATA version 4; delivered to no sibling",
            "sender's layer: there, version 4, type axt.example.v1.Appointment, from DATA version 4",
            "owner's layer: state stamp 201; no field removal@200p; type axt.example.v1.Appointment",
            "shows: deleted_by_owner",
        ],
    ],
    (
        "on the removal of a sibling the chain and the MANIFEST go at once to a sender "
        "known by the user, and to one known only by forwards of that sibling only once "
        "the user has kept it"
    ): [
        [
            "chain and MANIFEST to: other app",
        ],
        [
            (
                "sender first known by second app; known by forwards of laptop; current: second "
                "app; highest 195"
            ),
            "kept: DATA version 1 of the second app; delivered to tablet",
        ],
        [
            "chain and MANIFEST to: second app",
        ],
        [
            "chain and MANIFEST to: no sender",
        ],
    ],
    (
        "a sender known by forwards of two siblings is not known only by forwards of the "
        "removed one: the chain and the MANIFEST go at once"
    ): [
        [
            "chain and MANIFEST to: second app",
        ],
    ],
    (
        "a device that does not show the list, or whose user forgets the sender, sends it "
        "nothing because of the removal"
    ): [
        [
            "chain and MANIFEST to: no sender",
        ],
        [],
        [
            "chain and MANIFEST to: no sender",
        ],
    ],
    "at the end of a move the device holds nothing back": [
        [
            "chain and MANIFEST to: second app",
        ],
    ],
    "each sibling that forwards a message of a sender known by forwards is recorded": [
        [
            "outcome: APPLIED",
            "FORWARD 00000001 to laptop, #0: DATA version 1 of the second app, with the schema as offered",
        ],
        [
            "outcome: DUPLICATE",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
            "ACK of 0000000b to laptop: version 1 DUPLICATE, receiver 1",
        ],
        [
            (
                "sender first known by second app; known by forwards of laptop, tablet; current: "
                "second app; highest 195"
            ),
            "kept: DATA version 1 of the second app; delivered to laptop, tablet",
        ],
    ],
    (
        "after the removal of a sibling the device keeps nothing for it and takes no "
        "outcome and no FORWARD of it; its kept messages stay"
    ): [
        [
            "outcome: APPLIED",
            "FORWARD 00000001 to laptop, #0: DATA version 2, with the schema as offered",
            "FORWARD 00000002 to tablet, #0: DATA version 2, with the schema as offered",
        ],
        [
            "chain and MANIFEST to: other app",
        ],
        [
            "outcome: None",
        ],
        [
            "outcome: None",
        ],
        [
            "ACK to other app: version 2 APPLIED, receiver 2",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 2; delivered to no sibling",
            "sender's layer: there, version 2, type axt.example.v1.Appointment, from DATA version 2",
            "owner's layer: none",
            "shows: there",
        ],
    ],
    "a device that joins gets every kept message, and after the offer every owner's layer whole": [
        [
            "OFFER 00000001 to laptop: axt.example.v1.Appointment version 1",
            "FORWARD 00000002 to laptop, #1: DATA version 1, with the schema as offered",
            "FORWARD 00000001 to laptop, #0: MANIFEST revision 1",
        ],
        [
            "outcome: None",
            "CHANGE, origin other app, to laptop, version 205, state 205, whole: location@200t",
        ],
        [
            "sender first known by other app; current: other app; highest 205",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            "owner's layer: state stamp 205; location@200t; type axt.example.v1.Appointment",
            "laptop: not known",
            "tablet: known, delivered: all",
            "shows: there; the owner's value in location",
        ],
    ],
    (
        "a restored device forwards nothing and sends no layer before its request is acknowledged; a field "
        "never stamped of a layer gets the stamp -1"
    ): [
        [
            "RESYNC 00000001 to tablet",
        ],
        [
            "sender first known by other app; current: other app; highest 150; a request open to tablet",
            "kept: MANIFEST revision 1; delivered to no sibling",
            "kept: DATA version 1; delivered to no sibling",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            "owner's layer: state stamp 150; location@-1p; type axt.example.v1.Appointment",
            "tablet: not known",
            "shows: there; the owner's value in location",
        ],
        [
            "outcome: DUPLICATE",
        ],
        [
            "outcome: APPLIED",
        ],
        [
            "outcome: None",
            "OFFER 00000001 to tablet: axt.example.v1.Appointment version 1",
            "FORWARD 00000001 to tablet, #0: MANIFEST revision 1",
        ],
        [
            "outcome: None",
            "CHANGE, origin other app, to tablet, version 151, state 151, whole: location@-1p",
        ],
        [
            "ACK of 0000000a to tablet: version 1 DUPLICATE, receiver 1",
            "ACK of 0000000b to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            "sender first known by other app; current: other app; highest 151",
            "kept: MANIFEST revision 1; delivered to no sibling",
            "kept: DATA version 2; delivered to tablet",
            "sender's layer: there, version 2, type axt.example.v1.Appointment, from DATA version 2",
            "owner's layer: state stamp 151; location@-1p; type axt.example.v1.Appointment",
            "tablet: not known",
            "shows: there; the owner's value in location",
        ],
    ],
    "what a device takes from a file of another app it forwards, and reports to no one": [
        [
            "taken: True",
            "FORWARD 00000001 to tablet, #0: MANIFEST revision 2",
        ],
        [
            "outcome: APPLIED",
            "FORWARD 00000002 to tablet, #0: DATA version 2, with the schema as offered",
        ],
        [
            "outcome: DUPLICATE",
        ],
        [],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 2; delivered to no sibling",
            "kept: DATA version 2; delivered to no sibling",
            "sender's layer: there, version 2, type axt.example.v1.Appointment, from DATA version 2",
            "owner's layer: none",
            "shows: there",
        ],
    ],
    (
        "a MANIFEST of a file replaces the kept one only with a higher revision; one that "
        "the app sends in a live connection applies whatever its revision"
    ): [
        [
            "taken: False",
        ],
        [
            "taken: True",
            "FORWARD 00000001 to tablet, #0: MANIFEST revision 1",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to no sibling",
        ],
    ],
    (
        "a change of a received record goes whole in a CHANGE with the sender's key in "
        "origin, and the next change in part"
    ): [
        [
            "made: True",
            "CHANGE, origin other app, to tablet, version 201, state 201, whole: location@200p",
        ],
        [
            "outcome: None",
        ],
        [
            "sender first known by other app; current: other app; highest 205",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            "owner's layer: state stamp 201; location@200p; type axt.example.v1.Appointment",
            "tablet: known, delivered: all",
            "shows: there; the owner's value in location",
        ],
        [
            "made: True",
            "CHANGE, origin other app, to tablet, version 211, state 211, in part: notes@210p",
        ],
        [
            "sender first known by other app; current: other app; highest 211",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            "owner's layer: state stamp 211; location@200p notes@210p; type axt.example.v1.Appointment",
            "tablet: known, delivered: location",
            "shows: there; the owner's value in location, notes",
        ],
    ],
    "discarding a change gives the field a null value with the schema of the field state it replaces": [
        [
            "made: True",
            "CHANGE, origin other app, to tablet, version 211, state 211, whole: location=null@210p",
        ],
        [
            "sender first known by other app; current: other app; highest 211",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            "owner's layer: state stamp 211; location=null@210p; type axt.example.v1.Appointment",
            "tablet: known, delivered: nothing",
            "shows: there",
        ],
    ],
    (
        "deleting a received record puts a removal into the owner's layer, and taking it "
        "again a removal that was taken back"
    ): [
        [
            "made: True",
            "CHANGE, origin other app, to tablet, version 211, state 211, in part: no field removal@210p",
        ],
        [
            "sender first known by other app; current: other app; highest 211",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            "owner's layer: state stamp 211; location@200t removal@210p; type axt.example.v1.Appointment",
            "tablet: known, delivered: all",
            "shows: deleted_by_owner",
        ],
        [
            "made: True",
            (
                "CHANGE, origin other app, to tablet, version 217, state 217, in part: no field "
                "removal@216p, taken back"
            ),
        ],
        [
            "sender first known by other app; current: other app; highest 217",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            (
                "owner's layer: state stamp 217; location@200t removal@216p, taken back; type "
                "axt.example.v1.Appointment"
            ),
            "tablet: known, delivered: all",
            "shows: there; the owner's value in location",
        ],
    ],
    "the FORWARD of a record's kept message goes before the CHANGE of its owner's layer": [
        [
            "made: True",
            "CHANGE, origin other app, to tablet, version 201, state 201, whole: location@200p",
            "FORWARD 00000002 to tablet, #1: DATA version 1, with the schema as offered",
            "FORWARD 00000001 to tablet, #0: MANIFEST revision 1",
        ],
    ],
    "the schema that a field state of a layer names is offered before the CHANGE": [
        [
            "made: True",
            "OFFER 00000001 to tablet: axt.example.v1.Appointment version 1",
        ],
        [
            "outcome: None",
            "CHANGE, origin other app, to tablet, version 201, state 201, whole: location@200p",
        ],
    ],
    "origin is the key by which the device first knew the sender, also when that key is removed": [
        [
            "made: True",
            "CHANGE, origin other app, to tablet, version 201, state 201, whole: location@200p",
        ],
        [
            "sender first known by other app; current: other app, new; removed: other app; highest 201",
            "kept: DATA version 1; delivered to tablet",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            "owner's layer: state stamp 201; location@200p; type axt.example.v1.Appointment",
            "tablet: not known",
            "shows: there; the owner's value in location",
        ],
    ],
    "at the limit of the stamps a device changes no received record": [
        [
            "made: False",
        ],
        [
            "sender first known by other app; current: other app; highest 9223372036854710272",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            "owner's layer: none",
            "shows: there",
        ],
    ],
    "a device that can take no state stamp for a layer merges it and sends no CHANGE of it": [
        [
            "outcome: APPLIED",
        ],
        [
            "ACK to tablet: version 201 APPLIED, receiver 201",
        ],
        [
            "sender first known by other app; current: other app; highest 9223372036854775802",
            "kept: MANIFEST revision 1; delivered to laptop, tablet",
            "kept: DATA version 1; delivered to laptop, tablet",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            "owner's layer: state stamp None; location@200t; type axt.example.v1.Appointment",
            "laptop: not known",
            "tablet: known, delivered: all",
            "shows: there; the owner's value in location",
        ],
    ],
    (
        "a CHANGE with a key in origin is merged into the owner's layer: a device without "
        "the layer takes it, also from a message that is not whole"
    ): [
        [
            "outcome: APPLIED",
        ],
        [
            "ACK to tablet: version 201 APPLIED, receiver 205",
        ],
        [
            "sender first known by other app; current: other app; highest 205",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            "owner's layer: state stamp 205; location@200t; type axt.example.v1.Appointment",
            "tablet: known, delivered: all",
            "shows: there; the owner's value in location",
        ],
    ],
    (
        "a later field state of a layer is taken, the same is a duplicate, and an earlier "
        "one is stale and makes the device's own due again"
    ): [
        [
            "outcome: APPLIED",
        ],
        [
            "outcome: DUPLICATE",
        ],
        [
            "outcome: STALE",
            "CHANGE, origin other app, to tablet, version 212, state 212, whole: location@210t",
        ],
        [
            "ACK to tablet: version 211 APPLIED, receiver 212",
            "ACK to tablet: version 211 DUPLICATE, receiver 212",
            "ACK to tablet: version 201 STALE, receiver 212",
        ],
        [
            "sender first known by other app; current: other app; highest 212",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            "owner's layer: state stamp 212; location@210t; type axt.example.v1.Appointment",
            "tablet: known, delivered: nothing",
            "shows: there; the owner's value in location",
        ],
    ],
    (
        "a null value in a layer is a field state like any other: a later one is taken, "
        "and the sender's value shows again"
    ): [
        [
            "outcome: APPLIED",
        ],
        [
            "ACK to tablet: version 211 APPLIED, receiver 212",
        ],
        [
            "sender first known by other app; current: other app; highest 212",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            "owner's layer: state stamp 212; location=null@210t; type axt.example.v1.Appointment",
            "tablet: known, delivered: all",
            "shows: there",
        ],
    ],
    "with equal stamps and device keys a null value is lower than a value": [
        [
            "outcome: STALE",
            "CHANGE, origin other app, to tablet, version 205, state 205, whole: location@200t",
        ],
        [
            "ACK to tablet: version 201 STALE, receiver 205",
        ],
        [
            "sender first known by other app; current: other app; highest 205",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            "owner's layer: state stamp 205; location@200t; type axt.example.v1.Appointment",
            "tablet: known, delivered: nothing",
            "shows: there; the owner's value in location",
        ],
    ],
    "with equal stamps and device keys a value is taken over a null value": [
        [
            "outcome: APPLIED",
        ],
        [
            "ACK to tablet: version 201 APPLIED, receiver 206",
        ],
        [
            "sender first known by other app; current: other app; highest 206",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            "owner's layer: state stamp 206; location@200t; type axt.example.v1.Appointment",
            "tablet: known, delivered: all",
            "shows: there; the owner's value in location",
        ],
    ],
    (
        "a removal in a layer deletes the record by the owner on the device that merges "
        "it, and one that was taken back brings it back"
    ): [
        [
            "outcome: APPLIED",
        ],
        [
            "sender first known by other app; current: other app; highest 212",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            "owner's layer: state stamp 212; location@200t removal@210t; type axt.example.v1.Appointment",
            "tablet: known, delivered: all and the removal",
            "shows: deleted_by_owner",
        ],
        [
            "outcome: APPLIED",
        ],
        [
            "ACK to tablet: version 211 APPLIED, receiver 212",
            "ACK to tablet: version 221 APPLIED, receiver 222",
        ],
        [
            "sender first known by other app; current: other app; highest 222",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            (
                "owner's layer: state stamp 222; location@200t removal@220t, taken back; type "
                "axt.example.v1.Appointment"
            ),
            "tablet: known, delivered: all and the removal",
            "shows: there; the owner's value in location",
        ],
    ],
    (
        "a layer is held without the record: a CHANGE before the FORWARD of the record is "
        "taken, with the schema of the sibling's offer, and the record shows once its "
        "message arrives"
    ): [
        [
            "outcome: None",
            "ACCEPT 00000006 to tablet: axt.example.v1.Appointment",
        ],
        [
            "outcome: APPLIED",
        ],
        [
            "sender first known by other app; current: other app; highest 205",
            "sender's layer: none",
            "owner's layer: state stamp 205; location@200t; type axt.example.v1.Appointment",
            "tablet: known, delivered: all",
            "shows: none",
        ],
        [],
        [
            "outcome: APPLIED",
        ],
        [
            "outcome: APPLIED",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
            "ACK to tablet: version 201 APPLIED, receiver 205",
            "ACK to tablet: version 211 APPLIED, receiver 212",
        ],
        [
            "sender first known by other app; current: other app; highest 212",
            "kept: DATA version 1; delivered to tablet",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            "owner's layer: state stamp 212; location@200t notes@210t; type axt.example.v1.Appointment",
            "tablet: known, delivered: all",
            "shows: there; the owner's value in location, notes",
        ],
    ],
    (
        "steps 7 and 8: the schema is looked up among those of the record's sender and of the sibling's "
        "offers, not among the device's own"
    ): [
        [
            "outcome: None",
            "ERROR to tablet: SCHEMA_UNKNOWN, fingerprint 62231c9093404ed8",
        ],
        [],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            "owner's layer: none",
            "shows: there",
        ],
    ],
    "step 7: a schema that the device keeps of another sender only is not found": [
        [
            "outcome: None",
            "ERROR to tablet: SCHEMA_UNKNOWN, fingerprint 62231c9093404ed8",
        ],
        [],
    ],
    "step 7 holds for an entry with a null value as well": [
        [
            "outcome: None",
            "ERROR to tablet: SCHEMA_UNKNOWN, fingerprint 62231c9093404ed8",
        ],
        [],
    ],
    "step 8: an entry with a value whose name is no field of its schema is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            "owner's layer: none",
            "shows: there",
        ],
    ],
    "step 8: an entry with a null value whose name is no field of its schema is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            "owner's layer: none",
            "shows: there",
        ],
    ],
    "step 9: a CHANGE with another type than the sender's layer keeps is rejected with TYPE_CHANGED": [
        [
            "outcome: None",
            "ERROR to tablet: TYPE_CHANGED",
        ],
        [],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            "owner's layer: none",
            "shows: there",
        ],
    ],
    "step 10: a CHANGE whose origin is the device's own key is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
    ],
    "step 10: a CHANGE whose origin is a sibling is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
    ],
    (
        "step 10: a CHANGE whose origin is a removed key of the device's own set is "
        "rejected with INVALID_MESSAGE"
    ): [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
    ],
    "step 10: a CHANGE whose origin is a key of no known sender is rejected with RECORD_UNKNOWN": [
        [
            "outcome: None",
            "ERROR to tablet: RECORD_UNKNOWN",
        ],
        [],
    ],
    "step 10: a CHANGE whose origin is a refused key is rejected with RECORD_UNKNOWN": [
        [
            "outcome: None",
            "ERROR to tablet: RECORD_UNKNOWN",
        ],
        [],
    ],
    (
        "step 10 comes before step 7: with a schema it does not hold, a CHANGE whose "
        "origin is no known sender is rejected with RECORD_UNKNOWN"
    ): [
        [
            "outcome: None",
            "ERROR to tablet: RECORD_UNKNOWN",
        ],
        [],
    ],
    "step 10: origin names the sender by a removed key and by a second current key as well": [
        [
            "outcome: APPLIED",
        ],
        [
            "outcome: APPLIED",
        ],
        [
            "ACK to tablet: version 201 APPLIED, receiver 205",
            "ACK to tablet: version 211 APPLIED, receiver 212",
        ],
        [
            (
                "sender first known by other app, new; current: second app, other app, new; "
                "removed: other app; highest 212"
            ),
            "kept: DATA version 1; delivered to tablet",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            "owner's layer: state stamp 212; location@200t notes@210t; type axt.example.v1.Appointment",
            "tablet: known, delivered: all",
            "shows: there; the owner's value in location, notes",
        ],
    ],
    (
        "steps 11 and 12: a CHANGE with a key in origin and a value that does not decode "
        "is rejected with UNDECODABLE"
    ): [
        [
            "outcome: None",
            "ERROR to tablet: UNDECODABLE",
        ],
        [],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            "owner's layer: none",
            "shows: there",
        ],
    ],
    (
        "steps 11 and 12: a CHANGE with a key in origin and a time value that is not "
        "valid is rejected with VALUE_INVALID"
    ): [
        [
            "outcome: None",
            "ERROR to tablet: VALUE_INVALID, field start",
        ],
        [],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            "owner's layer: none",
            "shows: there",
        ],
    ],
    (
        "after RECORD_UNKNOWN for a layer the device forwards the sender's kept messages "
        "again and sends the layer only when the sibling has an outcome, APPLIED or "
        "DUPLICATE, for one"
    ): [
        [
            "made: True",
            "CHANGE, origin other app, to tablet, version 201, state 201, whole: location@200p",
        ],
        [
            "outcome: None",
            "FORWARD 00000002 to tablet, #1: DATA version 1, with the schema as offered",
            "FORWARD 00000001 to tablet, #0: MANIFEST revision 1",
        ],
        [
            "sender first known by other app; current: other app; highest 201",
            "kept: MANIFEST revision 1; delivered to no sibling",
            "kept: DATA version 1; delivered to no sibling",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            "owner's layer: state stamp 201; location@200p; type axt.example.v1.Appointment",
            "tablet: not known",
            "shows: there; the owner's value in location",
        ],
        [
            "FORWARD 00000002 to tablet, #1: DATA version 1, with the schema as offered",
            "FORWARD 00000001 to tablet, #0: MANIFEST revision 1",
        ],
        [
            "outcome: None",
            "CHANGE, origin other app, to tablet, version 201, state 201, whole: location@200p",
        ],
        [
            "outcome: None",
        ],
        [
            "sender first known by other app; current: other app; highest 201",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            "owner's layer: state stamp 201; location@200p; type axt.example.v1.Appointment",
            "tablet: not known",
            "shows: there; the owner's value in location",
        ],
    ],
    "after RECORD_UNKNOWN for a layer a change of the owner sends the layer whole, once": [
        [
            "made: True",
            "CHANGE, origin other app, to tablet, version 201, state 201, whole: location@200p",
        ],
        [
            "outcome: None",
            "FORWARD 00000002 to tablet, #1: DATA version 1, with the schema as offered",
            "FORWARD 00000001 to tablet, #0: MANIFEST revision 1",
        ],
        [
            "FORWARD 00000002 to tablet, #1: DATA version 1, with the schema as offered",
            "FORWARD 00000001 to tablet, #0: MANIFEST revision 1",
        ],
        [
            "made: True",
            "CHANGE, origin other app, to tablet, version 207, state 207, whole: location@200p notes@206p",
        ],
        [
            "outcome: None",
            "FORWARD 00000002 to tablet, #1: DATA version 1, with the schema as offered",
            "FORWARD 00000001 to tablet, #0: MANIFEST revision 1",
        ],
        [
            "FORWARD 00000002 to tablet, #1: DATA version 1, with the schema as offered",
            "FORWARD 00000001 to tablet, #0: MANIFEST revision 1",
        ],
    ],
    (
        "after RECORD_UNKNOWN twice in a row for a layer, an outcome for a forward no "
        "longer ends the wait; a change of the owner does"
    ): [
        [
            "made: True",
            "CHANGE, origin other app, to tablet, version 201, state 201, whole: location@200p",
        ],
        [
            "outcome: None",
            "FORWARD 00000002 to tablet, #1: DATA version 1, with the schema as offered",
            "FORWARD 00000001 to tablet, #0: MANIFEST revision 1",
        ],
        [
            "outcome: None",
            "CHANGE, origin other app, to tablet, version 201, state 201, whole: location@200p",
        ],
        [
            "outcome: None",
            "FORWARD 00000002 to tablet, #1: DATA version 1, with the schema as offered",
            "FORWARD 00000003 to tablet, #0: MANIFEST revision 1",
        ],
        [
            "outcome: None",
        ],
        [
            "made: True",
            "CHANGE, origin other app, to tablet, version 207, state 207, whole: location@200p notes@206p",
        ],
    ],
    "after RECORD_UNKNOWN for a layer a RESYNC of that sibling ends the wait": [
        [
            "made: True",
            "CHANGE, origin other app, to tablet, version 201, state 201, whole: location@200p",
        ],
        [
            "outcome: None",
            "FORWARD 00000002 to tablet, #1: DATA version 1, with the schema as offered",
            "FORWARD 00000001 to tablet, #0: MANIFEST revision 1",
        ],
        [
            "outcome: None",
            "CHANGE, origin other app, to tablet, version 202, state 202, whole: location@200p",
            "FORWARD 00000004 to tablet, #1: DATA version 1, with the schema as offered",
            "FORWARD 00000003 to tablet, #0: MANIFEST revision 1",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
    ],
    "the steps 1 to 4 of the example of section 22.4, on the phone": [
        [
            "taken: True",
            "FORWARD 00000001 to tablet, #0: MANIFEST revision 1",
        ],
        [
            "outcome: None",
        ],
        [
            "outcome: APPLIED",
            "FORWARD 00000002 to tablet, #0: DATA version 1, with the schema as offered",
        ],
        [
            "outcome: None",
        ],
        [
            "outcome: APPLIED",
        ],
        [
            "ACK to other app: version 1 APPLIED, receiver 1",
            "ACK to tablet: version 201 APPLIED, receiver 205",
        ],
        [
            "sender first known by other app; current: other app; highest 205",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            "owner's layer: state stamp 205; location@200t; type axt.example.v1.Appointment",
            "tablet: known, delivered: all",
            "shows: there; the owner's value in location",
        ],
        [
            "outcome: MERGED, kept ['location']",
            (
                "FORWARD 00000003 to tablet, #0: DATA version 3, start changed, notes 'Bring the "
                "vaccination card', with the schema as offered"
            ),
        ],
        [
            "outcome: DUPLICATE",
        ],
        [
            "ACK to other app: version 3 MERGED, receiver 3, kept ['location']",
            "ACK to other app: version 3 DUPLICATE, receiver 3",
        ],
        [
            "sender first known by other app; current: other app; highest 205",
            "kept: MANIFEST revision 1; delivered to tablet",
            (
                "kept: DATA version 3, start changed, notes 'Bring the vaccination card'; "
                "delivered to no sibling"
            ),
            (
                "sender's layer: there, version 3, type axt.example.v1.Appointment, from DATA "
                "version 3, start changed, notes 'Bring the vaccination card'"
            ),
            "owner's layer: state stamp 205; location@200t; type axt.example.v1.Appointment",
            "tablet: known, delivered: all",
            "shows: there; the owner's value in location",
        ],
    ],
    (
        "a set that deletes tidies the layer, APPLIED, and the record is deleted by its "
        "sender: the steps 5 and 6 of the example of section 22.4, on the phone"
    ): [
        [
            "outcome: APPLIED",
            "CHANGE, origin other app, to tablet, version 211, state 211, whole: location=null@210p",
            "FORWARD 00000001 to tablet, #0: DELETE version 4",
        ],
        [
            "ACK to other app: version 4 APPLIED, receiver 4",
        ],
        [
            "sender first known by other app; current: other app; highest 211",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 3, start changed, notes 'Bring the vaccination card'; delivered to tablet",
            "kept: DELETE version 4; delivered to no sibling",
            (
                "sender's layer: tombstone, version 4, type axt.example.v1.Appointment, from "
                "DELETE version 4; beside it DATA version 3, start changed, notes 'Bring the "
                "vaccination card'"
            ),
            "owner's layer: state stamp 211; location=null@210p; type axt.example.v1.Appointment",
            "tablet: known, delivered: nothing",
            "shows: deleted_by_sender",
        ],
        [
            "outcome: APPLIED",
            "FORWARD 00000002 to tablet, #0: DATA version 5, with the schema as offered",
        ],
        [
            "ACK to other app: version 5 APPLIED, receiver 5",
        ],
        [
            "sender first known by other app; current: other app; highest 211",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 5; delivered to no sibling",
            "sender's layer: there, version 5, type axt.example.v1.Appointment, from DATA version 5",
            "owner's layer: state stamp 211; location=null@210p; type axt.example.v1.Appointment",
            "tablet: known, delivered: nothing",
            "shows: there",
        ],
    ],
    (
        "a set that keeps sets a keep, KEPT, and the record is kept against the deletion: "
        "the steps 5 and 6 of the example of section 22.4, on the phone"
    ): [
        [
            "outcome: KEPT",
            (
                "CHANGE, origin other app, to tablet, version 211, state 211, in part: no field "
                "keep@210p of version 4"
            ),
            "FORWARD 00000001 to tablet, #0: DELETE version 4",
        ],
        [
            "ACK to other app: version 4 KEPT, receiver 4",
        ],
        [
            "sender first known by other app; current: other app; highest 211",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 3, start changed, notes 'Bring the vaccination card'; delivered to tablet",
            "kept: DELETE version 4; delivered to no sibling",
            (
                "sender's layer: tombstone, version 4, type axt.example.v1.Appointment, from "
                "DELETE version 4; beside it DATA version 3, start changed, notes 'Bring the "
                "vaccination card'"
            ),
            (
                "owner's layer: state stamp 211; location@200t keep@210p of version 4; type "
                "axt.example.v1.Appointment"
            ),
            "tablet: known, delivered: all",
            "shows: kept; the owner's value in location",
        ],
        [
            "outcome: MERGED, kept ['location']",
            "FORWARD 00000002 to tablet, #0: DATA version 5, with the schema as offered",
        ],
        [
            "ACK to other app: version 5 MERGED, receiver 5, kept ['location']",
        ],
        [
            "sender first known by other app; current: other app; highest 211",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 5; delivered to no sibling",
            "sender's layer: there, version 5, type axt.example.v1.Appointment, from DATA version 5",
            (
                "owner's layer: state stamp 211; location@200t keep@210p of version 4; type "
                "axt.example.v1.Appointment"
            ),
            "tablet: known, delivered: all",
            "shows: there; the owner's value in location",
        ],
    ],
    "a DELETE that meets an owner's removal that stands changes nothing in the layer: APPLIED": [
        [
            "outcome: APPLIED",
            "FORWARD 00000001 to tablet, #0: DELETE version 3",
        ],
        [
            "ACK to other app: version 3 APPLIED, receiver 3",
        ],
        [
            "sender first known by other app; current: other app; highest 205",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 2; delivered to tablet",
            "kept: DELETE version 3; delivered to no sibling",
            (
                "sender's layer: tombstone, version 3, type axt.example.v1.Appointment, from "
                "DELETE version 3; beside it DATA version 2"
            ),
            "owner's layer: state stamp 205; location@200t removal@203t; type axt.example.v1.Appointment",
            "tablet: known, delivered: all and the removal",
            "shows: deleted_by_owner",
        ],
    ],
    "a set that keeps sets no keep for a record of which it holds no DATA: it tidies the layer": [
        [
            "outcome: APPLIED",
            "CHANGE, origin other app, to tablet, version 211, state 211, whole: location=null@210p",
            "FORWARD 00000001 to tablet, #0: DELETE version 3",
        ],
        [
            "ACK to other app: version 3 APPLIED, receiver 3",
        ],
        [
            "sender first known by other app; current: other app; highest 211",
            "kept: DELETE version 3; delivered to no sibling",
            "sender's layer: tombstone, version 3, type None, from DELETE version 3",
            "owner's layer: state stamp 211; location=null@210p; type axt.example.v1.Appointment",
            "tablet: known, delivered: nothing",
            "shows: deleted_by_sender",
        ],
    ],
    "a device that can take no stamp sets no keep and tidies nothing: APPLIED for the DELETE": [
        [
            "outcome: APPLIED",
            "FORWARD 00000001 to tablet, #0: DELETE version 4",
        ],
        [
            "ACK to other app: version 4 APPLIED, receiver 4",
        ],
        [
            "sender first known by other app; current: other app; highest 9223372036854710272",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 3, start changed, notes 'Bring the vaccination card'; delivered to tablet",
            "kept: DELETE version 4; delivered to no sibling",
            (
                "sender's layer: tombstone, version 4, type axt.example.v1.Appointment, from "
                "DELETE version 4; beside it DATA version 3, start changed, notes 'Bring the "
                "vaccination card'"
            ),
            "owner's layer: state stamp 205; location@200t; type axt.example.v1.Appointment",
            "tablet: known, delivered: all",
            "shows: deleted_by_sender",
        ],
    ],
    "the further ACK: after KEPT for a DELETE, the user gives up the keep and the device sends APPLIED": [
        [
            "outcome: KEPT",
            (
                "CHANGE, origin other app, to tablet, version 211, state 211, in part: no field "
                "keep@210p of version 4"
            ),
            "FORWARD 00000001 to tablet, #0: DELETE version 4",
        ],
        [
            "ACK to other app: version 4 KEPT, receiver 4",
        ],
        [
            "made: True",
            (
                "CHANGE, origin other app, to tablet, version 214, state 214, in part: no field "
                "keep@213p of version 4, given up"
            ),
        ],
        [
            "ACK to other app: version 4 APPLIED, receiver 4",
        ],
        [
            "sender first known by other app; current: other app; highest 214",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 3, start changed, notes 'Bring the vaccination card'; delivered to tablet",
            "kept: DELETE version 4; delivered to no sibling",
            (
                "sender's layer: tombstone, version 4, type axt.example.v1.Appointment, from "
                "DELETE version 4; beside it DATA version 3, start changed, notes 'Bring the "
                "vaccination card'"
            ),
            (
                "owner's layer: state stamp 214; location@200t keep@213p of version 4, given up; "
                "type axt.example.v1.Appointment"
            ),
            "tablet: known, delivered: all",
            "shows: deleted_by_sender",
        ],
    ],
    "the further ACK: a keep given up on the tablet reaches the answering device in a CHANGE": [
        [
            "outcome: KEPT",
            (
                "CHANGE, origin other app, to tablet, version 211, state 211, in part: no field "
                "keep@210p of version 4"
            ),
            "FORWARD 00000001 to tablet, #0: DELETE version 4",
        ],
        [
            "ACK to other app: version 4 KEPT, receiver 4",
        ],
        [
            "outcome: APPLIED",
        ],
        [
            "ACK to tablet: version 221 APPLIED, receiver 222",
            "ACK to other app: version 4 APPLIED, receiver 4",
        ],
        [
            "sender first known by other app; current: other app; highest 222",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 3, start changed, notes 'Bring the vaccination card'; delivered to tablet",
            "kept: DELETE version 4; delivered to no sibling",
            (
                "sender's layer: tombstone, version 4, type axt.example.v1.Appointment, from "
                "DELETE version 4; beside it DATA version 3, start changed, notes 'Bring the "
                "vaccination card'"
            ),
            (
                "owner's layer: state stamp 222; location@200t keep@220t of version 4, given up; "
                "type axt.example.v1.Appointment"
            ),
            "tablet: known, delivered: all and the keep",
            "shows: deleted_by_sender",
        ],
    ],
    "no further ACK when a later message of the sender has arrived in between": [
        [
            "outcome: KEPT",
            (
                "CHANGE, origin other app, to tablet, version 211, state 211, in part: no field "
                "keep@210p of version 4"
            ),
            "FORWARD 00000001 to tablet, #0: DELETE version 4",
        ],
        [
            "outcome: MERGED, kept ['location']",
            "FORWARD 00000002 to tablet, #0: DATA version 5, with the schema as offered",
        ],
        [
            "ACK to other app: version 5 MERGED, receiver 5, kept ['location']",
            "ACK to other app: version 4 KEPT, receiver 4",
        ],
        [
            "made: True",
            (
                "CHANGE, origin other app, to tablet, version 214, state 214, whole: "
                "location@213p keep@210p of version 4"
            ),
        ],
        [],
    ],
    "the further ACK: after KEPT for a DATA of a record the owner deleted, the user takes it again": [
        [
            "outcome: KEPT",
            "FORWARD 00000001 to tablet, #0: DATA version 3, with the schema as offered",
        ],
        [
            "ACK to other app: version 3 KEPT, receiver 3",
        ],
        [
            "made: True",
            (
                "CHANGE, origin other app, to tablet, version 208, state 208, whole: no field "
                "removal@207p, taken back"
            ),
        ],
        [
            "ACK to other app: version 3 APPLIED, receiver 3",
        ],
        [
            "sender first known by other app; current: other app; highest 208",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 3; delivered to no sibling",
            "sender's layer: there, version 3, type axt.example.v1.Appointment, from DATA version 3",
            (
                "owner's layer: state stamp 208; no field removal@207p, taken back; type "
                "axt.example.v1.Appointment"
            ),
            "tablet: known, delivered: all",
            "shows: there",
        ],
    ],
    (
        "a keep that arrives after APPLIED for the DELETE and the tidying keeps nothing: "
        "the layer holds no owner's value"
    ): [
        [
            "outcome: APPLIED",
            "CHANGE, origin other app, to tablet, version 211, state 211, whole: location=null@210p",
            "FORWARD 00000001 to tablet, #0: DELETE version 4",
        ],
        [
            "ACK to other app: version 4 APPLIED, receiver 4",
        ],
        [
            "outcome: APPLIED",
        ],
        [
            "ACK to tablet: version 221 APPLIED, receiver 222",
        ],
        [
            "sender first known by other app; current: other app; highest 222",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 3, start changed, notes 'Bring the vaccination card'; delivered to tablet",
            "kept: DELETE version 4; delivered to no sibling",
            (
                "sender's layer: tombstone, version 4, type axt.example.v1.Appointment, from "
                "DELETE version 4; beside it DATA version 3, start changed, notes 'Bring the "
                "vaccination card'"
            ),
            (
                "owner's layer: state stamp 222; location=null@210p keep@220t of version 4; type "
                "axt.example.v1.Appointment"
            ),
            "tablet: known, delivered: nothing and the keep",
            "shows: deleted_by_sender",
        ],
    ],
    (
        "a keep with an owner's value that arrives after APPLIED for the DELETE shows the "
        "record again and is not reported"
    ): [
        [
            "outcome: APPLIED",
            "FORWARD 00000001 to tablet, #0: DELETE version 4",
        ],
        [
            "ACK to other app: version 4 APPLIED, receiver 4",
        ],
        [
            "outcome: APPLIED",
        ],
        [
            "ACK to tablet: version 221 APPLIED, receiver 222",
        ],
        [
            "sender first known by other app; current: other app; highest 222",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 3, start changed, notes 'Bring the vaccination card'; delivered to tablet",
            "kept: DELETE version 4; delivered to no sibling",
            (
                "sender's layer: tombstone, version 4, type axt.example.v1.Appointment, from "
                "DELETE version 4; beside it DATA version 3, start changed, notes 'Bring the "
                "vaccination card'"
            ),
            (
                "owner's layer: state stamp 222; location@200t keep@220t of version 4; type "
                "axt.example.v1.Appointment"
            ),
            "tablet: known, delivered: all and the keep",
            "shows: kept; the owner's value in location",
        ],
    ],
    (
        "the user keeps a record that its sender deleted only with an owner's value, and "
        "gives the keep up again"
    ): [
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 3, start changed, notes 'Bring the vaccination card'; delivered to tablet",
            "kept: DELETE version 4; delivered to tablet",
            (
                "sender's layer: tombstone, version 4, type axt.example.v1.Appointment, from "
                "DELETE version 4; beside it DATA version 3, start changed, notes 'Bring the "
                "vaccination card'"
            ),
            "owner's layer: none",
            "shows: deleted_by_sender",
        ],
        [
            "made: False",
        ],
        [
            "made: False",
        ],
        [
            "made: True",
            "CHANGE, origin other app, to tablet, version 201, state 201, whole: location@200p",
        ],
        [
            "made: True",
            (
                "CHANGE, origin other app, to tablet, version 207, state 207, whole: "
                "location@200p keep@206p of version 4"
            ),
        ],
        [
            "sender first known by other app; current: other app; highest 207",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 3, start changed, notes 'Bring the vaccination card'; delivered to tablet",
            "kept: DELETE version 4; delivered to tablet",
            (
                "sender's layer: tombstone, version 4, type axt.example.v1.Appointment, from "
                "DELETE version 4; beside it DATA version 3, start changed, notes 'Bring the "
                "vaccination card'"
            ),
            (
                "owner's layer: state stamp 207; location@200p keep@206p of version 4; type "
                "axt.example.v1.Appointment"
            ),
            "tablet: not known",
            "shows: kept; the owner's value in location",
        ],
        [
            "made: True",
            (
                "CHANGE, origin other app, to tablet, version 213, state 213, whole: "
                "location@200p keep@212p of version 4, given up"
            ),
        ],
        [
            "sender first known by other app; current: other app; highest 213",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 3, start changed, notes 'Bring the vaccination card'; delivered to tablet",
            "kept: DELETE version 4; delivered to tablet",
            (
                "sender's layer: tombstone, version 4, type axt.example.v1.Appointment, from "
                "DELETE version 4; beside it DATA version 3, start changed, notes 'Bring the "
                "vaccination card'"
            ),
            (
                "owner's layer: state stamp 213; location@200p keep@212p of version 4, given up; "
                "type axt.example.v1.Appointment"
            ),
            "tablet: not known",
            "shows: deleted_by_sender",
        ],
    ],
    "a keep in a CHANGE is a part: an earlier one is STALE and makes the device's keep due again": [
        [
            "outcome: STALE",
            (
                "CHANGE, origin other app, to tablet, version 211, state 211, in part: no field "
                "keep@210p of version 4"
            ),
        ],
        [
            "outcome: DUPLICATE",
        ],
        [
            "ACK to tablet: version 216 DUPLICATE, receiver 211",
            "ACK to tablet: version 215 STALE, receiver 211",
        ],
    ],
    "a DATA beside a tombstone travels to a new device, before the DELETE": [
        [
            "OFFER 00000001 to laptop: axt.example.v1.Appointment version 1",
            "FORWARD 00000003 to laptop, #2: DELETE version 4",
            (
                "FORWARD 00000002 to laptop, #1: DATA version 3, start changed, notes 'Bring the vaccination "
                "card', with the schema as offered"
            ),
            "FORWARD 00000001 to laptop, #0: MANIFEST revision 1",
        ],
    ],
    "a DATA for a record that the owner deleted stays deleted: KEPT; an older one is STALE": [
        [
            "outcome: KEPT",
            "FORWARD 00000001 to tablet, #0: DATA version 3, with the schema as offered",
        ],
        [
            "outcome: STALE",
        ],
        [
            "ACK to other app: version 3 KEPT, receiver 3",
            "ACK to other app: version 1 STALE, receiver 3",
        ],
        [
            "sender first known by other app; current: other app; highest 205",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 3; delivered to no sibling",
            "sender's layer: there, version 3, type axt.example.v1.Appointment, from DATA version 3",
            "owner's layer: state stamp 205; no field removal@200t; type axt.example.v1.Appointment",
            "tablet: known, delivered: all and the removal",
            "shows: deleted_by_owner",
        ],
    ],
    "a DATA that brings the owner's value is APPLIED, and the owner's layer stays": [
        [
            "outcome: APPLIED",
            (
                "FORWARD 00000001 to tablet, #0: DATA version 2, location 'Dr. Weber, Hauptstr. "
                "5', with the schema as offered"
            ),
        ],
        [
            "ACK to other app: version 2 APPLIED, receiver 2",
        ],
        [
            "sender first known by other app; current: other app; highest 205",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 2, location 'Dr. Weber, Hauptstr. 5'; delivered to no sibling",
            (
                "sender's layer: there, version 2, type axt.example.v1.Appointment, from DATA "
                "version 2, location 'Dr. Weber, Hauptstr. 5'"
            ),
            "owner's layer: state stamp 205; location@200t; type axt.example.v1.Appointment",
            "tablet: known, delivered: all",
            "shows: there; the owner's value in location",
        ],
    ],
    (
        "a DELETE of a record without an owner's layer leaves a tombstone on the "
        "answering device and, forwarded, on its sibling"
    ): [
        [
            "outcome: APPLIED",
            "FORWARD 00000001 to tablet, #0: DELETE version 2",
        ],
        [
            "ACK to other app: version 2 APPLIED, receiver 2",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "kept: DELETE version 2; delivered to no sibling",
            (
                "sender's layer: tombstone, version 2, type axt.example.v1.Appointment, from "
                "DELETE version 2; beside it DATA version 1"
            ),
            "owner's layer: none",
            "shows: deleted_by_sender",
        ],
    ],
    "a forwarded WITHDRAW leaves a tombstone of a withdrawal with the DATA beside it": [
        [
            "outcome: APPLIED",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "kept: WITHDRAW version 2 to the tablet; delivered to tablet",
            (
                "sender's layer: withdrawn, version 2, type axt.example.v1.Appointment, from WITHDRAW "
                "version 2 to the tablet; beside it DATA version 1"
            ),
            "owner's layer: none",
            "shows: deleted_by_sender",
        ],
    ],
    "a forwarded WITHDRAW addressed to a removed key of the set is taken": [
        [
            "outcome: APPLIED",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "kept: WITHDRAW version 2 to the old phone; delivered to tablet",
            (
                "sender's layer: withdrawn, version 2, type axt.example.v1.Appointment, from WITHDRAW "
                "version 2 to the old phone; beside it DATA version 1"
            ),
            "owner's layer: none",
            "shows: deleted_by_sender",
        ],
    ],
    "a forwarded WITHDRAW addressed to the device's own key is taken": [
        [
            "outcome: APPLIED",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
    ],
    "a forwarded WITHDRAW addressed to the key of a sibling is taken": [
        [
            "outcome: APPLIED",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
    ],
    "a forwarded WITHDRAW addressed to a key of no device of the set is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            "owner's layer: none",
            "shows: there",
        ],
    ],
    "a forwarded WITHDRAW whose body has a byte left over is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            "owner's layer: none",
            "shows: there",
        ],
    ],
    "a forwarded WITHDRAW whose body is not an axt.Withdraw is rejected with INVALID_MESSAGE": [
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "sender's layer: there, version 1, type axt.example.v1.Appointment, from DATA version 1",
            "owner's layer: none",
            "shows: there",
        ],
    ],
    "a forwarded DATA below the tombstone of a withdrawal goes beside it": [
        [
            "outcome: APPLIED",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 2; delivered to tablet",
            "kept: WITHDRAW version 3 to the tablet; delivered to tablet",
            (
                "sender's layer: withdrawn, version 3, type axt.example.v1.Appointment, from WITHDRAW "
                "version 3 to the tablet; beside it DATA version 2"
            ),
            "owner's layer: none",
            "shows: deleted_by_sender",
        ],
    ],
    "two WITHDRAW messages of one version in other bytes: the one with the higher SHA-256 stands": [
        [
            "outcome: APPLIED",
        ],
        [
            "outcome: DUPLICATE",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
            "ACK of 0000000b to tablet: version 1 DUPLICATE, receiver 1",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "kept: WITHDRAW version 2 to the tablet; delivered to tablet",
            (
                "sender's layer: withdrawn, version 2, type axt.example.v1.Appointment, from WITHDRAW "
                "version 2 to the tablet; beside it DATA version 1"
            ),
            "owner's layer: none",
            "shows: deleted_by_sender",
        ],
    ],
    (
        "two WITHDRAW messages of one version in other bytes: the later one with the higher "
        "SHA-256 takes the place of the kept one"
    ): [
        [
            "outcome: APPLIED",
        ],
        [
            "outcome: APPLIED",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
            "ACK of 0000000b to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "kept: WITHDRAW version 2 to the tablet; delivered to tablet",
            (
                "sender's layer: withdrawn, version 2, type axt.example.v1.Appointment, from WITHDRAW "
                "version 2 to the tablet; beside it DATA version 1"
            ),
            "owner's layer: none",
            "shows: deleted_by_sender",
        ],
    ],
    (
        "a set that keeps: a WITHDRAW that meets an owner's value sets a keep, KEPT, and the "
        "record is kept against the withdrawal"
    ): [
        [
            "outcome: KEPT",
            (
                "CHANGE, origin other app, to tablet, version 211, state 211, in part: no field keep@210p "
                "of version 4"
            ),
            "FORWARD 00000001 to tablet, #0: WITHDRAW version 4 to the phone",
        ],
        [
            "ACK to other app: version 4 KEPT, receiver 4",
        ],
        [
            "sender first known by other app; current: other app; highest 211",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 3, start changed, notes 'Bring the vaccination card'; delivered to tablet",
            "kept: WITHDRAW version 4 to the phone; delivered to no sibling",
            (
                "sender's layer: withdrawn, version 4, type axt.example.v1.Appointment, from WITHDRAW "
                "version 4 to the phone; beside it DATA version 3, start changed, notes 'Bring the "
                "vaccination card'"
            ),
            (
                "owner's layer: state stamp 211; location@200t keep@210p of version 4; type "
                "axt.example.v1.Appointment"
            ),
            "tablet: known, delivered: all",
            "shows: kept; the owner's value in location",
        ],
        [
            "outcome: MERGED, kept ['location']",
            "FORWARD 00000002 to tablet, #0: DATA version 5, with the schema as offered",
        ],
        [
            "ACK to other app: version 5 MERGED, receiver 5, kept ['location']",
        ],
        [
            "sender first known by other app; current: other app; highest 211",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 5; delivered to no sibling",
            "sender's layer: there, version 5, type axt.example.v1.Appointment, from DATA version 5",
            (
                "owner's layer: state stamp 211; location@200t keep@210p of version 4; type "
                "axt.example.v1.Appointment"
            ),
            "tablet: known, delivered: all",
            "shows: there; the owner's value in location",
        ],
    ],
    "the further ACK: after KEPT for a WITHDRAW, the user gives up the keep and the device sends WITHDRAWN": [
        [
            "outcome: KEPT",
            (
                "CHANGE, origin other app, to tablet, version 211, state 211, in part: no field keep@210p "
                "of version 4"
            ),
            "FORWARD 00000001 to tablet, #0: WITHDRAW version 4 to the phone",
        ],
        [
            "ACK to other app: version 4 KEPT, receiver 4",
        ],
        [
            "made: True",
            (
                "CHANGE, origin other app, to tablet, version 214, state 214, in part: no field keep@213p "
                "of version 4, given up"
            ),
        ],
        [
            "ACK to other app: version 4 WITHDRAWN, receiver 4",
        ],
        [
            "sender first known by other app; current: other app; highest 214",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 3, start changed, notes 'Bring the vaccination card'; delivered to tablet",
            "kept: WITHDRAW version 4 to the phone; delivered to no sibling",
            (
                "sender's layer: withdrawn, version 4, type axt.example.v1.Appointment, from WITHDRAW "
                "version 4 to the phone; beside it DATA version 3, start changed, notes 'Bring the "
                "vaccination card'"
            ),
            (
                "owner's layer: state stamp 214; location@200t keep@213p of version 4, given up; type "
                "axt.example.v1.Appointment"
            ),
            "tablet: known, delivered: all",
            "shows: deleted_by_sender",
        ],
    ],
    "a keep against a WITHDRAW does not cover a DELETE with a higher version": [
        [
            "outcome: KEPT",
            (
                "CHANGE, origin other app, to tablet, version 211, state 211, in part: no field keep@210p "
                "of version 4"
            ),
            "FORWARD 00000001 to tablet, #0: WITHDRAW version 4 to the phone",
        ],
        [
            "outcome: APPLIED",
            (
                "CHANGE, origin other app, to tablet, version 215, state 215, whole: location=null@214p "
                "keep@210p of version 4"
            ),
            "FORWARD 00000002 to tablet, #0: DELETE version 5",
        ],
        [
            "ACK to other app: version 5 APPLIED, receiver 5",
            "ACK to other app: version 4 KEPT, receiver 4",
        ],
        [
            "sender first known by other app; current: other app; highest 215",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 3, start changed, notes 'Bring the vaccination card'; delivered to tablet",
            "kept: DELETE version 5; delivered to no sibling",
            (
                "sender's layer: tombstone, version 5, type axt.example.v1.Appointment, from DELETE "
                "version 5; beside it DATA version 3, start changed, notes 'Bring the vaccination card'"
            ),
            (
                "owner's layer: state stamp 215; location=null@214p keep@210p of version 4; type "
                "axt.example.v1.Appointment"
            ),
            "tablet: known, delivered: nothing",
            "shows: deleted_by_sender",
        ],
    ],
    "a set that keeps against a DELETE may remove against a WITHDRAW: WITHDRAWN, and the layer is tidied": [
        [
            "outcome: WITHDRAWN",
            "CHANGE, origin other app, to tablet, version 211, state 211, whole: location=null@210p",
            "FORWARD 00000001 to tablet, #0: WITHDRAW version 4 to the phone",
        ],
        [
            "ACK to other app: version 4 WITHDRAWN, receiver 4",
        ],
        [
            "sender first known by other app; current: other app; highest 211",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 3, start changed, notes 'Bring the vaccination card'; delivered to tablet",
            "kept: WITHDRAW version 4 to the phone; delivered to no sibling",
            (
                "sender's layer: withdrawn, version 4, type axt.example.v1.Appointment, from WITHDRAW "
                "version 4 to the phone; beside it DATA version 3, start changed, notes 'Bring the "
                "vaccination card'"
            ),
            "owner's layer: state stamp 211; location=null@210p; type axt.example.v1.Appointment",
            "tablet: known, delivered: nothing",
            "shows: deleted_by_sender",
        ],
    ],
    "a WITHDRAW of an id the answering device does not have: WITHDRAWN, a tombstone without a type": [
        [
            "outcome: WITHDRAWN",
            "FORWARD 00000001 to tablet, #0: WITHDRAW version 3 to the phone, id 7b1e6c2a",
        ],
        [
            "ACK of 7b1e6c2a to other app: version 3 WITHDRAWN, receiver 3",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "kept: WITHDRAW version 3 to the phone, id 7b1e6c2a; delivered to no sibling",
            (
                "sender's layer: withdrawn, version 3, type None, from WITHDRAW version 3 to the phone, id "
                "7b1e6c2a"
            ),
            "owner's layer: none",
            "shows: deleted_by_sender",
        ],
    ],
    "a WITHDRAW in a file of the device's own set is not applied": [
        [
            "taken: False",
        ],
        [
            "no record; highest 195",
        ],
    ],
    "a WITHDRAW of another app in a file of that app is taken and forwarded, and nothing is reported": [
        [
            "outcome: WITHDRAWN",
            "FORWARD 00000001 to tablet, #0: WITHDRAW version 2 to the tablet",
        ],
        [],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "kept: WITHDRAW version 2 to the tablet; delivered to no sibling",
            (
                "sender's layer: withdrawn, version 2, type axt.example.v1.Appointment, from WITHDRAW "
                "version 2 to the tablet; beside it DATA version 1"
            ),
            "owner's layer: none",
            "shows: deleted_by_sender",
        ],
    ],
    "a WITHDRAW of a sibling is rejected with NOT_ACCEPTED, once its body and addressee pass": [
        [
            "outcome: None",
            "ERROR to tablet: NOT_ACCEPTED",
        ],
        [
            "outcome: None",
        ],
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [
            "outcome: None",
            "ERROR to tablet: RECORD_ID_INVALID",
        ],
        [
            "outcome: None",
            "ERROR to tablet: INVALID_MESSAGE",
        ],
        [],
    ],
    (
        "case 5 of step 7, forwarded: a WITHDRAW takes the place of a DATA of the same version, "
        "which stays beside it; APPLIED"
    ): [
        [
            "outcome: APPLIED",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 2; delivered to tablet",
            "kept: WITHDRAW version 2 to the tablet; delivered to tablet",
            (
                "sender's layer: withdrawn, version 2, type axt.example.v1.Appointment, from WITHDRAW "
                "version 2 to the tablet; beside it DATA version 2"
            ),
            "owner's layer: none",
            "shows: deleted_by_sender",
        ],
    ],
    (
        "case 5 of step 7, from the sender: a WITHDRAW takes the place of a DATA of the same "
        "version, which stays beside it; DUPLICATE"
    ): [
        [
            "outcome: DUPLICATE",
            "FORWARD 00000001 to tablet, #0: WITHDRAW version 2 to the phone",
        ],
        [
            "ACK to other app: version 2 DUPLICATE, receiver 2",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 2; delivered to tablet",
            "kept: WITHDRAW version 2 to the phone; delivered to no sibling",
            (
                "sender's layer: withdrawn, version 2, type axt.example.v1.Appointment, from WITHDRAW "
                "version 2 to the phone; beside it DATA version 2"
            ),
            "owner's layer: none",
            "shows: deleted_by_sender",
        ],
    ],
    (
        "case 5 of step 7, forwarded: a WITHDRAW takes the place of a DELETE of the same version, "
        "and the DATA beside it stays"
    ): [
        [
            "outcome: APPLIED",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 2; delivered to tablet",
            "kept: WITHDRAW version 3 to the tablet; delivered to tablet",
            (
                "sender's layer: withdrawn, version 3, type axt.example.v1.Appointment, from WITHDRAW "
                "version 3 to the tablet; beside it DATA version 2"
            ),
            "owner's layer: none",
            "shows: deleted_by_sender",
        ],
    ],
    (
        "a WITHDRAW that meets an owner's removal that stands, with owner's values, at a set that "
        "keeps: WITHDRAWN, and the removal stands"
    ): [
        [
            "outcome: WITHDRAWN",
            "FORWARD 00000001 to tablet, #0: WITHDRAW version 3 to the phone",
        ],
        [
            "ACK to other app: version 3 WITHDRAWN, receiver 3",
        ],
        [
            "sender first known by other app; current: other app; highest 205",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 2; delivered to tablet",
            "kept: WITHDRAW version 3 to the phone; delivered to no sibling",
            (
                "sender's layer: withdrawn, version 3, type axt.example.v1.Appointment, from WITHDRAW "
                "version 3 to the phone; beside it DATA version 2"
            ),
            "owner's layer: state stamp 205; location@200t removal@203t; type axt.example.v1.Appointment",
            "tablet: known, delivered: all and the removal",
            "shows: deleted_by_owner",
        ],
    ],
    (
        "a forwarded WITHDRAW of a removed key is rejected with NOT_ACCEPTED when the sibling has "
        "not shown that it has the removal"
    ): [
        [
            "outcome: None",
            "ERROR to tablet: NOT_ACCEPTED",
            "FORWARD 00000001 to tablet, #0: DEVICE_REMOVE of the other app by the other app, new",
        ],
        [],
    ],
    (
        "case 5 at the answering device, a set that keeps: a WITHDRAW over a DATA of its version "
        "meets an owner's value and sets a keep; DUPLICATE"
    ): [
        [
            "outcome: DUPLICATE",
            (
                "CHANGE, origin other app, to tablet, version 211, state 211, in part: no field keep@210p "
                "of version 3"
            ),
            "FORWARD 00000001 to tablet, #0: WITHDRAW version 3 to the phone",
        ],
        [
            "ACK to other app: version 3 DUPLICATE, receiver 3",
        ],
        [
            "sender first known by other app; current: other app; highest 211",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 3, start changed, notes 'Bring the vaccination card'; delivered to tablet",
            "kept: WITHDRAW version 3 to the phone; delivered to no sibling",
            (
                "sender's layer: withdrawn, version 3, type axt.example.v1.Appointment, from WITHDRAW "
                "version 3 to the phone; beside it DATA version 3, start changed, notes 'Bring the "
                "vaccination card'"
            ),
            (
                "owner's layer: state stamp 211; location@200t keep@210p of version 3; type "
                "axt.example.v1.Appointment"
            ),
            "tablet: known, delivered: all",
            "shows: kept; the owner's value in location",
        ],
    ],
    (
        "case 5 at the answering device, a set that removes: a WITHDRAW over a DATA of its version "
        "meets an owner's value and tidies the layer; DUPLICATE"
    ): [
        [
            "outcome: DUPLICATE",
            "CHANGE, origin other app, to tablet, version 211, state 211, whole: location=null@210p",
            "FORWARD 00000001 to tablet, #0: WITHDRAW version 3 to the phone",
        ],
        [
            "ACK to other app: version 3 DUPLICATE, receiver 3",
        ],
        [
            "sender first known by other app; current: other app; highest 211",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 3, start changed, notes 'Bring the vaccination card'; delivered to tablet",
            "kept: WITHDRAW version 3 to the phone; delivered to no sibling",
            (
                "sender's layer: withdrawn, version 3, type axt.example.v1.Appointment, from WITHDRAW "
                "version 3 to the phone; beside it DATA version 3, start changed, notes 'Bring the "
                "vaccination card'"
            ),
            "owner's layer: state stamp 211; location=null@210p; type axt.example.v1.Appointment",
            "tablet: known, delivered: nothing",
            "shows: deleted_by_sender",
        ],
    ],
    "the answering device takes a PROPOSAL, keeps it and forwards it with no schema": [
        ["taken: True", "FORWARD 00000001 to tablet, #0: PROPOSAL 1 to the phone"],
        ["proposal 00000001 of 7b1e6c2a: shown"],
        ["taken: False"],
        [],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "kept: PROPOSAL 1 to the phone; delivered to no sibling",
        ],
    ],
    "the answering device answers ACCEPTED: the reply to the key that signed, and the values as one change": [
        [
            "taken: True",
            "FORWARD 00000001 to tablet, #0: PROPOSAL 1 to the phone",
        ],
        [
            "made: True",
            "PROPOSAL_REPLY 00000001 to other app, version 1: ACCEPTED",
            "CHANGE of 7b1e6c2a to tablet, version 202, state 202, in part: location@201p",
        ],
        [
            "answer 00000001: ACCEPTED",
        ],
        [
            (
                "state stamp 202; title,start,end,all_day,notes,reminders,relations@100p location@201p; "
                "sibling stamp None; to pass None; highest 202"
            ),
            "tablet: known, delivered: all_day,end,notes,relations,reminders,start,title",
        ],
        [
            "taken: False",
            "PROPOSAL_REPLY 00000001 to other app, version 1: ACCEPTED",
        ],
    ],
    "an answer DECLINED: the reply, and nothing changes": [
        [
            "taken: True",
            "FORWARD 00000001 to tablet, #0: PROPOSAL 1 to the phone",
        ],
        [
            "made: True",
            "PROPOSAL_REPLY 00000001 to other app, version 1: DECLINED",
        ],
        [
            "state stamp 101; all eight@100p; sibling stamp None; to pass None; highest 195",
            "tablet: known, delivered: all",
        ],
    ],
    "a forwarded PROPOSAL is taken and kept without a reply": [
        ["outcome: APPLIED"],
        ["outcome: DUPLICATE"],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
            "ACK of 0000000b to tablet: version 1 DUPLICATE, receiver 1",
        ],
        ["proposal 00000001 of 7b1e6c2a: shown"],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "kept: PROPOSAL 1 to the tablet; delivered to tablet",
        ],
    ],
    "a forwarded PROPOSAL addressed to the device's own key is taken": [
        ["outcome: APPLIED"],
        ["ACK of 0000000a to tablet: version 1 APPLIED, receiver 1"],
    ],
    "a forwarded PROPOSAL addressed to a removed key of the set is taken": [
        ["outcome: APPLIED"],
        ["ACK of 0000000a to tablet: version 1 APPLIED, receiver 1"],
    ],
    "a forwarded PROPOSAL addressed to a key of no device of the set is rejected": [
        ["outcome: None", "ERROR to tablet: INVALID_MESSAGE"],
        [],
        ["no proposal"],
    ],
    "a forwarded PROPOSAL whose body has a byte left over is rejected": [
        ["outcome: None", "ERROR to tablet: INVALID_MESSAGE"],
        [],
        ["no proposal"],
    ],
    "a forwarded PROPOSAL with the id vet is rejected": [
        ["outcome: None", "ERROR to tablet: RECORD_ID_INVALID"],
        [],
        ["no proposal"],
    ],
    "a forwarded PROPOSAL with the version 0 is rejected": [
        ["outcome: None", "ERROR to tablet: VERSION_INVALID"],
        [],
        ["no proposal"],
    ],
    "a forwarded PROPOSAL with no entry is rejected": [
        ["outcome: None", "ERROR to tablet: INVALID_MESSAGE"],
        [],
        ["no proposal"],
    ],
    "a forwarded PROPOSAL of a removed key of its sender is not taken": [
        ["outcome: APPLIED"],
        ["outcome: APPLIED"],
        ["outcome: DUPLICATE"],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
            "ACK of 0000000b to tablet: version 1 APPLIED, receiver 1",
            "ACK of 0000000c to tablet: version 1 DUPLICATE, receiver 1",
        ],
    ],
    "a forwarded PROPOSAL of a key of the device's own set is rejected": [
        ["outcome: None", "ERROR to tablet: INVALID_MESSAGE"],
        [],
    ],
    "a forwarded PROPOSAL for a record the device does not show is kept, shown once the share arrives": [
        ["outcome: APPLIED"],
        ["proposal 00000001 of 7b1e6c2a: not shown"],
        [],
        ["proposal 00000001 of 7b1e6c2a: shown"],
    ],
    "a forwarded PROPOSAL that the device never shows ends after 14 days": [
        ["outcome: APPLIED"],
        ["ACK of 0000000a to tablet: version 1 APPLIED, receiver 1"],
        [],
        ["proposal 00000001 of 7b1e6c2a: not shown"],
        [],
        ["no proposal"],
    ],
    "a kept PROPOSAL ends when the record leaves the shares for the proposer, and when it is deleted": [
        ["taken: True", "FORWARD 00000001 to tablet, #0: PROPOSAL 1 to the phone"],
        ["taken: True", "FORWARD 00000002 to tablet, #0: PROPOSAL 2 to the phone"],
        [],
        ["no proposal"],
        [],
        ["no proposal"],
        ["taken: True", "FORWARD 00000003 to tablet, #0: PROPOSAL 3 to the phone"],
        [
            "made: True",
            "CHANGE of 7b1e6c2a to tablet, version 202, state 202, in part: no field removal@201p",
        ],
        ["no proposal"],
    ],
    "the answer reaches the device from a sibling: the kept PROPOSAL ends, and no reply goes": [
        ["taken: True", "FORWARD 00000001 to tablet, #0: PROPOSAL 1 to the phone"],
        [],
        ["answer 00000001: DECLINED"],
        ["outcome: DUPLICATE"],
        ["taken: False", "PROPOSAL_REPLY 00000001 to other app, version 1: DECLINED"],
        ["ACK of 0000000a to tablet: version 1 DUPLICATE, receiver 1"],
    ],
    "two answers before a merge: a sibling's answer after the device's own sends nothing": [
        ["taken: True", "FORWARD 00000001 to tablet, #0: PROPOSAL 1 to the phone"],
        ["made: True", "PROPOSAL_REPLY 00000001 to other app, version 1: DECLINED"],
        [],
        ["answer 00000001: ACCEPTED"],
    ],
    "a PROPOSAL of a sibling is rejected with PROPOSALS_NOT_TAKEN": [
        ["outcome: None", "ERROR to tablet: PROPOSALS_NOT_TAKEN"],
        ["outcome: None"],
    ],
    "the proposer's value is an owner's change, and the update that brings it is APPLIED": [
        ["made: True", "CHANGE, origin other app, to tablet, version 202, state 202, whole: location@201p"],
        [
            "outcome: APPLIED",
            "FORWARD 00000001 to tablet, #0: DATA version 2, location 'Dr. "
            "Weber, Hauptstr. 5', with the schema as offered",
        ],
        ["ACK to other app: version 2 APPLIED, receiver 2"],
        [
            "sender first known by other app; current: other app; highest 202",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 2, location 'Dr. Weber, Hauptstr. 5'; delivered to no sibling",
            "sender's layer: there, version 2, type axt.example.v1.Appointment, "
            "from DATA version 2, location 'Dr. Weber, Hauptstr. 5'",
            "owner's layer: state stamp 202; location@201p; type axt.example.v1.Appointment",
            "tablet: not known",
            "shows: there; the owner's value in location",
        ],
    ],
    "ACCEPTED stamps every proposed field, also one whose value the record holds already": [
        [
            "taken: True",
            "FORWARD 00000001 to tablet, #0: PROPOSAL 1 to the phone",
        ],
        [
            "made: True",
            "PROPOSAL_REPLY 00000001 to other app, version 1: ACCEPTED",
            "CHANGE of 7b1e6c2a to tablet, version 202, state 202, in part: location@201p",
        ],
        [
            (
                "state stamp 202; title,start,end,all_day,notes,reminders,relations@100p location@201p; "
                "sibling stamp None; to pass None; highest 202"
            ),
            "tablet: known, delivered: all_day,end,notes,relations,reminders,start,title",
        ],
    ],
    "a forwarded PROPOSAL in other bytes with a higher SHA-256 takes the place of the one kept": [
        [
            "outcome: APPLIED",
        ],
        [
            "outcome: APPLIED",
        ],
        [
            "outcome: DUPLICATE",
        ],
        [
            "ACK of 0000000a to tablet: version 1 APPLIED, receiver 1",
            "ACK of 0000000b to tablet: version 1 APPLIED, receiver 1",
            "ACK of 0000000c to tablet: version 1 DUPLICATE, receiver 1",
        ],
        [
            "sender first known by other app; current: other app; highest 195",
            "kept: MANIFEST revision 1; delivered to tablet",
            "kept: DATA version 1; delivered to tablet",
            "kept: PROPOSAL 1 to the tablet; delivered to tablet",
        ],
    ],
    "two answers before a merge: ACCEPTED on the device stands over a later DECLINED of a sibling": [
        ["taken: True", "FORWARD 00000001 to tablet, #0: PROPOSAL 1 to the phone"],
        [
            "made: True",
            "PROPOSAL_REPLY 00000001 to other app, version 1: ACCEPTED",
            "CHANGE of 7b1e6c2a to tablet, version 202, state 202, in part: location@201p",
        ],
        [],
        ["answer 00000001: ACCEPTED"],
    ],
    "ACCEPTED is barred for a forwarded value whose schema the device lacks, and DECLINED is not": [
        ["outcome: APPLIED"],
        ["made: False"],
        ["proposal 00000001 of 7b1e6c2a: shown"],
        ["made: True", "PROPOSAL_REPLY 00000001 to other app, version 1: DECLINED"],
    ],
    "a stop of the receiver drops its kept proposals, and a forwarded one is not taken": [
        ["taken: True", "FORWARD 00000001 to tablet, #0: PROPOSAL 1 to the phone"],
        [],
        ["no proposal"],
        ["outcome: DUPLICATE"],
        ["ACK of 0000000a to tablet: version 1 DUPLICATE, receiver 1"],
    ],
    "a kept PROPOSAL ends when the key that signed it is removed from the proposer": [
        ["taken: True", "FORWARD 00000001 to tablet, #0: PROPOSAL 1 to the phone"],
        ["outcome: APPLIED"],
        ["outcome: APPLIED"],
        ["no proposal"],
    ],
    "the schema of each entry is offered to a sibling before the PROPOSAL is forwarded to it": [
        ["taken: True", "OFFER 00000001 to tablet: axt.example.v1.Appointment version 1"],
        ["outcome: None", "FORWARD 00000001 to tablet, #0: PROPOSAL 1 to the phone"],
    ],
    "a forwarded PROPOSAL beyond the limit of 16 open proposals for one record is kept all the same": [
        ["outcome: APPLIED"],
        ["ACK of 0000000a to tablet: version 1 APPLIED, receiver 1"],
    ],
    "an offer of a sibling with a description whose root is no object is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: OFFER_INVALID",
        ],
    ],
    "a type of a sibling's offer whose description is not valid is declined": [
        [
            "outcome: None",
            "ACCEPT 00000006 to tablet: axt.example.v1.Pet",
            "DECLINE 00000006 to tablet: axt.example.v1.Appointment DESCRIPTION_INVALID",
        ],
    ],
    "a type of a sibling's offer with a description above 256 KiB is declined": [
        [
            "outcome: None",
            "DECLINE 00000006 to tablet: axt.example.v1.Pet DESCRIPTION_INVALID",
        ],
    ],
    "an offer of a sibling with a description whose root is a list is rejected": [
        [
            "outcome: None",
            "ERROR to tablet: OFFER_INVALID",
        ],
    ],
}


def check_sessions(out: list[str]) -> None:
    """Every session says what the rules require of it, step by step."""
    played = [*sessions(), *received_sessions()]
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
    check_layers(out)
    check_properties(out)
    EXAMPLE_MESSAGES.clear()
    check_field_values()
    check_schemas(out)
    check_messages(out)
    check_received(out)
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
