# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Produce and check the examples of spec/shares.md.

The examples of spec/shares.md are the schema of the body of a WITHDRAW, the steps of a share
and its withdrawal with their versions and outcomes (section 11.1), and the WITHDRAW of step 2
(section 11.2). This script:

- checks types/axt/Withdraw.avsc: the schema rules of spec/types.md, section 5, which
  protocol_examples.py applies to every schema of the specification, its names unique among
  them; its Parsing Canonical Form and CRC-64-AVRO fingerprint with fastavro and the Apache
  avro package, against the form that section 10 shows; and that WITHDRAW is the symbol 14 of
  axt.Kind and WITHDRAWN the symbol 5 of axt.AckOutcome;
- implements the rules of a receiver of one sender that lets its user change records, with
  withdrawals (sections 4 and 5.1, with spec/records.md, sections 5 to 7), and the rules of a
  sender: the version of a withdrawal and of a sharing again (sections 3.2 and 6.2), what a
  device owes a receiver (sections 5.3 and 6.1), what it does with an outcome (sections 5.2
  and 5.3) and with the version to pass after the wait (section 5.3), the shares of two receivers
  that join (section 7.3), and the types it offers with their count (section 2.2).
  conformance/tools/generate_vectors.py turns cases of them into the vectors of the category
  shares, and the reference adapter answers those vectors with them;
- plays the steps of section 11.1 with those rules, a sender that counts and a receiver that
  keeps a record its user changed, and asserts every version and outcome of its table;
- builds the WITHDRAW of section 11.2 field by field, compares it with fastavro's encoding,
  reads it back with the avro package, signs it with the pure-Python Ed25519 of
  keys_examples.py, PyNaCl and cryptography, which give the same signature, verifies it with all
  three, and processes it with the model of an app of protocol_examples.py, as Old Brain Fix after
  the exchange of spec/protocol.md, section 17.

The sender signs with the TEST KEY "cat-a-log, old phone, Ed25519" of spec/keys.md, section 7.1,
and the receiver is the test key "Old Brain Fix, Ed25519" of spec/protocol.md, section 17.1; they
MUST NOT be used outside tests.

Run from anywhere, with fastavro, avro (1.12), pynacl and cryptography installed:

    python3 conformance/tools/shares_examples.py

The script imports protocol_examples.py, which runs that script's checks with its output
suppressed, and sync_examples.py, which runs none. Importing this file runs none of its own
checks.
"""

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

import avro.io
import avro.schema
import fastavro
from fastavro.schema import fingerprint as fa_fingerprint
from fastavro.schema import to_parsing_canonical_form

HERE = Path(__file__).resolve().parent

_spec = importlib.util.spec_from_file_location("protocol_examples", HERE / "protocol_examples.py")
if _spec is None or _spec.loader is None:
    raise ImportError("cannot load protocol_examples.py")
pe = importlib.util.module_from_spec(_spec)
with contextlib.redirect_stdout(io.StringIO()):
    _spec.loader.exec_module(pe)  # runs its checks
_spec = importlib.util.spec_from_file_location("sync_examples", HERE / "sync_examples.py")
if _spec is None or _spec.loader is None:
    raise ImportError("cannot load sync_examples.py")
sy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sy)  # runs none of its checks
keys, rules = pe.keys, pe.rules

# The Parsing Canonical Form of spec/shares.md, section 10, and its fingerprint.
WITHDRAW_PCF = (
    '{"name":"axt.Withdraw","type":"record","fields":[{"name":"to","type":'
    '{"name":"axt.WithdrawTo","type":"fixed","size":32}}]}'
)
WITHDRAW_FP = 0xE355F51523A97DD5
REC_ID = "3f2c8a5e-9b1d-4c7e-8a6f-2d4b5c6e7f80"  # spec/records.md, section 9


# --- the receiver (sections 4 and 5.1) ---------------------------------------------------------


def record_key(rid: str) -> int | None:
    """The id as a 128-bit value, or None if it is not a UUID in text form or is the nil or max UUID."""
    if pe.uuid_problem(rid):
        return None
    return int(rid.replace("-", ""), 16)


@dataclass
class Held:
    """What a receiver keeps of one record of its sender (spec/records.md, section 5.1)."""

    type: str | None
    version: int
    state: str  # there, tombstone (of a deletion), withdrawn (a tombstone of a withdrawal), deleted_by_user
    value: dict[str, Any] | None
    changed: set[str] = field(default_factory=set)
    kept: str | None = None  # the kind of the DELETE or WITHDRAW it reported KEPT for, at `version`


class Receiver:
    """The records of one sender at a receiver that lets its user change them: `local_changes` is
    per_field, whole_record_keep or whole_record_take (spec/records.md, sections 6.1 and 6.2);
    `on_delete` and `on_withdraw` are delete or keep, what it does with a DELETE or a WITHDRAW that
    meets its user's changes (spec/records.md, section 6.4; section 4.3)."""

    def __init__(self, local_changes: str, on_delete: str, on_withdraw: str) -> None:
        self.mode, self.on_delete, self.on_withdraw = local_changes, on_delete, on_withdraw
        self.records: dict[int, Held] = {}

    @staticmethod
    def result(outcome: str, r: Held, kept: list[str] | None = None) -> dict[str, Any]:
        return {
            "outcome": outcome,
            "receiver_version": r.version,
            "kept_fields": sorted(kept or []),
            "state": r.state,
            "value": None if r.state != "there" or r.value is None else dict(r.value),
        }

    def message(self, m: dict[str, Any]) -> dict[str, Any]:
        """One record message, DATA, DELETE or WITHDRAW, by the steps 2, 3, 6, 7 and 10."""
        key = record_key(m["id"])
        if key is None:
            return {"error": "RECORD_ID_INVALID"}
        if m["version"] < 1:
            return {"error": "VERSION_INVALID"}
        kind, r = m["kind"], self.records.get(key)
        if kind == "DATA" and r is not None and r.type is not None and r.type != m["type"]:
            return {"error": "TYPE_CHANGED"}
        if r is not None and m["version"] <= r.version:  # the version rule (spec/records.md, section 5.2)
            return self.result("DUPLICATE" if m["version"] == r.version else "STALE", r)
        if r is None:
            state = {"DATA": "there", "DELETE": "tombstone", "WITHDRAW": "withdrawn"}[kind]
            value = dict(m["value"]) if kind == "DATA" else None
            r = self.records[key] = Held(m["type"] if kind == "DATA" else None, m["version"], state, value)
            return self.result("WITHDRAWN" if kind == "WITHDRAW" else "APPLIED", r)
        r.version, r.kept = m["version"], None
        if kind != "DATA":
            # The table of section 4.2 for a WITHDRAW, and spec/records.md, sections 5.3, 6.3 and 6.4, for
            # a DELETE: the receiver keeps the type it held.
            taken = "WITHDRAWN" if kind == "WITHDRAW" else "APPLIED"
            tombstone = "withdrawn" if kind == "WITHDRAW" else "tombstone"
            if r.state == "deleted_by_user":
                return self.result(taken, r)  # the user's deletion goes on standing beside the tombstone
            keep = (self.on_withdraw if kind == "WITHDRAW" else self.on_delete) == "keep"
            if r.state == "there" and r.changed and keep:
                r.kept = kind
                return self.result("KEPT", r)
            r.state, r.value, r.changed = tombstone, None, set()
            return self.result(taken, r)
        r.type = m["type"]
        if r.state in ("tombstone", "withdrawn"):  # the record comes back as a new record under the same id
            r.state, r.value, r.changed = "there", dict(m["value"]), set()
            return self.result("APPLIED", r)
        if r.state == "deleted_by_user":
            return self.result("KEPT", r)
        assert r.value is not None
        if not r.changed or self.mode == "whole_record_take":
            r.value, r.changed = dict(m["value"]), set()
            return self.result("APPLIED", r)
        if self.mode == "whole_record_keep":
            return self.result("KEPT", r)
        kept = [f for f in r.changed if f in r.value and r.value[f] != m["value"].get(f)]
        value = dict(m["value"])
        for f in r.changed:
            if f in r.value:
                value[f] = r.value[f]
        r.value = value
        return self.result("MERGED" if kept else "APPLIED", r, kept)

    def local_change(self, rid: str, name: str, value: Any) -> None:
        r = self.records[record_key(rid) or 0]
        assert r.state == "there" and r.value is not None, "the user changes a record that is there"
        r.value[name] = value
        r.changed.add(name)

    def local_delete(self, rid: str) -> None:
        r = self.records[record_key(rid) or 0]
        r.state, r.value, r.kept = "deleted_by_user", None, None

    def local_take(self, rid: str) -> dict[str, Any]:
        """The user takes after all the DELETE or the WITHDRAW that the receiver reported as KEPT, while
        its version is the receiver's version: the further outcome (spec/protocol.md, section 7.3)."""
        r = self.records[record_key(rid) or 0]
        assert r.kept is not None, "a DELETE or a WITHDRAW kept against the user's changes"
        withdrawn = r.kept == "WITHDRAW"
        r.state, r.value, r.changed, r.kept = ("withdrawn" if withdrawn else "tombstone"), None, set(), None
        return self.result("WITHDRAWN" if withdrawn else "APPLIED", r)


def apply(policy: dict[str, str], events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """A session of the operation `receive` (spec/conformance.md, section 5.15)."""
    on_delete = policy["delete_with_local_changes"]
    receiver = Receiver(
        policy["local_changes"], on_delete, policy.get("withdraw_with_local_changes", on_delete)
    )
    out: list[dict[str, Any]] = []
    for e in events:
        if "message" in e:
            out.append(receiver.message(e["message"]))
        elif "local_change" in e:
            c = e["local_change"]
            receiver.local_change(c["id"], c["field"], c["value"])
            out.append({})
        elif "local_delete" in e:
            receiver.local_delete(e["local_delete"]["id"])
            out.append({})
        else:
            out.append(receiver.local_take(e["local_take"]["id"]))
    return out


# --- the sender (sections 3.2, 5.2, 5.3, 6.1 and 6.2) --------------------------------------------


def take_version(
    occasion: str,
    counted: bool,
    highest_given: int,
    now_ms: int,
    highest: int,
    r: int,
    withdrawals: list[int],
    state_stamp: int,
) -> tuple[int | None, int, int]:
    """The version of a withdrawal (`withdraw`, section 3.2) or of a sharing again (`share_again`,
    section 6.2): (the version or None, the record's state stamp after it, the device's highest stamp).
    An installation that counts takes one above `highest_given`, the highest version it has given the
    record; a device that stamps counts the versions of the withdrawals as seen and takes the next stamp.
    Only a sharing again gives the record a new state stamp."""
    if counted:
        version: int | None = highest_given + 1
    else:
        highest = max([highest, *withdrawals])
        version = sy.next_stamp(now_ms, highest, r)
        if version is not None:
            highest = version
    if version is not None and occasion == "share_again":
        state_stamp = version
    return version, state_stamp, highest


def owed(
    shared: bool, deleted: bool, version: int, withdrawal: int | None, last: tuple[str, int] | None
) -> tuple[str, int | None]:
    """What a device owes a receiver of one record (section 5.3): DATA or DELETE under `version`, the
    record's state stamp or count, while it is shared; WITHDRAW under the version of `withdrawal`, the
    last withdrawal of the record from that receiver that the app's records hold, while it is withdrawn;
    otherwise nothing. `last` is the kind and the version of the last record message of the record that
    the device sent that receiver: where it is a DATA above every recorded withdrawal, or there is none,
    and the record is not shared, the device withdraws the record itself (section 6.1): new_withdrawal,
    under a version it takes."""
    if shared:
        return ("DELETE" if deleted else "DATA"), version
    if last is not None and last[0] == "DATA" and (withdrawal is None or last[1] > withdrawal):
        return "new_withdrawal", None
    if withdrawal is not None:
        return "WITHDRAW", withdrawal
    return "nothing", None


def pass_withdrawal(
    shared: bool, withdrawal: int | None, to_pass: int, state_stamp: int
) -> tuple[str, int | None]:
    """What a device does with the version to pass toward a receiver once it has waited for its siblings,
    for the record and for the app's share records (section 5.3; spec/sync.md, section 5.3): (what it
    does, the version to pass it keeps). Where the record is withdrawn from that receiver, only the
    version of the last recorded withdrawal drops the version to pass, not the state stamp: a version
    still below it takes a new withdrawal. Where it is shared again, the device sends what it owes, under
    a new state stamp if its state stamp is still below the version to pass."""
    if shared:
        return ("nothing" if state_stamp > to_pass else "send_state"), None
    if withdrawal is not None and withdrawal >= to_pass:
        return "nothing", None
    return "new_withdrawal", None


def joined(a: tuple[bool, int | None], b: tuple[bool, int | None]) -> tuple[bool, int | None, bool]:
    """Two receivers, each with whether the record is shared with it and the version of its last recorded
    withdrawal, join into one (section 7.3): (whether the record is shared with the joined receiver, the
    version of its last withdrawal, whether the device sends the record under a new state stamp)."""
    shared = a[0] or b[0]
    withdrawals = [w for _, w in (a, b) if w is not None]
    last = max(withdrawals) if withdrawals else None
    return shared, last, shared and last is not None


def offer(records: list[tuple[str, str, bool]]) -> list[tuple[str, int]]:
    """The types a device offers a receiver of another user, and their `count` (section 2.2): for each
    record, its type, what the device owes the receiver of it (owed above) and whether that message has
    an outcome of the receiver. A type is offered for the messages it still owes, WITHDRAW among them."""
    counts: dict[str, int] = {}
    for type_name, owes, delivered in records:
        if owes in ("DATA", "DELETE", "WITHDRAW") and not delivered:
            counts[type_name] = counts.get(type_name, 0) + 1
    return sorted(counts.items())


def acked(
    sent: str,
    held: str | None,
    outcome: str,
    receiver_version: int,
    shared: bool,
    withdrawal: int | None,
    state_stamp: int,
    sibling_stamp: int | None,
    sibling: bool,
) -> tuple[str, str, int | None]:
    """What a device does with the entry of a valid ACK for a record message of the kind `sent` that it
    sent (sections 5.2 and 5.3; spec/protocol.md, section 7.4): (the outcome it holds for that id and
    version after the entry, what it does then, the version to pass). `held` is the outcome it held
    before, of the same key; `shared` and `withdrawal` say whether the record is shared with that
    receiver now and the version of its last withdrawal from it; `state_stamp` and `sibling_stamp` are
    its state stamp of the record and the highest one it saw from a sibling; `sibling` whether its set
    has other current devices. What it does: nothing; new_withdrawal, a new withdrawal under a new
    stamp; send_state, the record's current state under a new state stamp; or wait, for its siblings
    (spec/sync.md, section 5.3)."""
    if (sent == "WITHDRAW") == (outcome == "WITHDRAWN") or outcome not in ("APPLIED", "MERGED", "WITHDRAWN"):
        taken = outcome
    else:
        taken = "DUPLICATE"  # an outcome that does not fit the kind (section 5.2)
    if (
        held is None
        or (held == "DUPLICATE" and taken != "DUPLICATE")
        or (taken == "APPLIED" and held in ("KEPT", "MERGED"))
        or (taken == "WITHDRAWN" and held == "KEPT")
    ):
        held = taken
    if taken != "STALE":
        return held, "nothing", None
    if sent == "WITHDRAW":
        known = withdrawal or 0  # its state stamps do not count (section 5.3)
    else:
        known = max(state_stamp, sibling_stamp or 0, withdrawal or 0)
    if receiver_version <= known:
        return held, "nothing", None
    if sibling:
        return held, "wait", receiver_version
    return held, ("send_state" if shared else "new_withdrawal"), None


# --- the example of section 11.1 ------------------------------------------------------------------

V3 = {"title": "Vet", "start": "2025-11-18 10:30", "location": "", "notes": "Bring the vaccination card"}
WEBER = "Dr. Weber, Hauptstr. 5"
# Step, message and its version, the receiver's version before, the outcome, the receiver's version after,
# as the table of section 11.1 writes them.
TABLE = [
    (1, "DATA, 3", "none", "APPLIED", "3"),
    (2, "WITHDRAW, 4", "3", "WITHDRAWN", "4, tombstone of the withdrawal"),
    (3, "DATA, 3", "4, tombstone of the withdrawal", "STALE", "4, tombstone of the withdrawal"),
    (4, "DATA, 5", "4, tombstone of the withdrawal", "APPLIED", "5"),
    (5, "none", "5", "none", "5"),
    (6, "WITHDRAW, 6", "5", "KEPT", "6"),
    (7, "none: no longer shared", "6", "none", "6"),
    (8, "none", "6", "WITHDRAWN, in a further ACK for version 6", "6, tombstone of the withdrawal"),
]


def example_steps() -> list[tuple[int, str, str, str, str]]:
    """The steps of section 11.1, played with the rules above: the sender, one installation that counts
    and holds the appointment at version 3, and the receiver, which merges per field and keeps a record
    its user changed against a withdrawal."""
    receiver = Receiver("per_field", "delete", "keep")
    given, state, withdrawal = 3, 3, None  # the sender's count and its records
    sent: tuple[str, int] | None = None  # the last record message it sent the receiver
    outcomes: dict[tuple[str, int], str] = {}  # the outcomes it holds, by kind and version
    rows: list[tuple[int, str, str, str, str]] = []

    def before() -> str:
        r = receiver.records.get(record_key(REC_ID) or 0)
        if r is None:
            return "none"
        return f"{r.version}, tombstone of the withdrawal" if r.state == "withdrawn" else str(r.version)

    def send(what: str, version: int, value: dict[str, Any] | None = None) -> tuple[str, str]:
        m = {"kind": what, "id": REC_ID, "version": version}
        if what == "DATA":
            m.update(type="axt.example.v1.Appointment", value=value)
        got = receiver.message(m)
        held, then, _ = acked(
            what,
            outcomes.get((what, version)),
            got["outcome"],
            got["receiver_version"],
            shared,
            withdrawal,
            state,
            None,
            False,
        )
        outcomes[(what, version)] = held
        assert then == "nothing", then
        return f"{what}, {version}", got["outcome"]

    # 1: the appointment is shared; the record has version 3 already.
    shared = True
    what, version = owed(shared, False, state, withdrawal, sent)
    assert (what, version) == ("DATA", 3)
    v = before()
    message, outcome = send("DATA", 3, V3)
    rows.append((1, message, v, outcome, before()))
    sent = ("DATA", 3)
    # 2: taken out of the share: the device of the change withdraws it, with the next count.
    shared = False
    assert owed(shared, False, state, withdrawal, sent) == ("new_withdrawal", None)
    withdrawal, state, _ = take_version("withdraw", True, given, 0, 0, 0, [], state)
    assert withdrawal is not None
    given = withdrawal
    assert owed(shared, False, state, withdrawal, sent) == ("WITHDRAW", 4)
    v = before()
    message, outcome = send("WITHDRAW", withdrawal)
    sent = ("WITHDRAW", withdrawal)
    rows.append((2, message, v, outcome, before()))
    # 3: the relay delivers the DATA of step 1 again: STALE with the version of the withdrawal, and
    # nothing more to do.
    v = before()
    message, outcome = send("DATA", 3, V3)
    rows.append((3, message, v, outcome, before()))
    assert outcomes[("DATA", 3)] == "APPLIED", "the first outcome stands"
    # 4: shared again, with the next count, though the record has not changed.
    shared = True
    version, state, _ = take_version("share_again", True, given, 0, 0, 0, [withdrawal], state)
    assert version is not None
    given = version
    what, version = owed(shared, False, state, withdrawal, sent)
    assert (what, version) == ("DATA", 5)
    v = before()
    message, outcome = send("DATA", 5, V3)
    rows.append((4, message, v, outcome, before()))
    sent = ("DATA", 5)
    # 5: the receiver's user changes location.
    v = before()
    receiver.local_change(REC_ID, "location", WEBER)
    rows.append((5, "none", v, "none", before()))
    # 6: the share ends: the device withdraws the record again, above the DATA it sent.
    shared = False
    assert owed(shared, False, state, withdrawal, sent) == ("new_withdrawal", None)
    withdrawal, state, _ = take_version("withdraw", True, given, 0, 0, 0, [], state)
    assert withdrawal is not None
    given = withdrawal
    v = before()
    message, outcome = send("WITHDRAW", withdrawal)
    sent = ("WITHDRAW", withdrawal)
    rows.append((6, message, v, outcome, before()))
    shown = receiver.records[record_key(REC_ID) or 0].value
    assert shown == dict(V3, location=WEBER), "the receiver shows version 5 with its user's location"
    # 7: start moves to 11:00, version 7: the device owes that receiver the WITHDRAW it has delivered.
    given = state = given + 1
    assert state == 7 and owed(shared, False, state, withdrawal, sent) == ("WITHDRAW", 6)
    v = before()
    rows.append((7, "none: no longer shared", v, "none", before()))
    # 8: the receiver's user gives up the kept appointment: a further ACK with WITHDRAWN.
    v = before()
    later = receiver.local_take(REC_ID)
    assert (later["outcome"], later["receiver_version"]) == ("WITHDRAWN", 6)
    held, _, _ = acked("WITHDRAW", outcomes[("WITHDRAW", 6)], "WITHDRAWN", 6, shared, 6, 7, None, False)
    assert (outcomes[("WITHDRAW", 6)], held) == ("KEPT", "WITHDRAWN"), "WITHDRAWN replaces KEPT"
    rows.append((8, "none", v, "WITHDRAWN, in a further ACK for version 6", before()))
    return rows


# --- the WITHDRAW of section 11.2 ----------------------------------------------------------------


def withdraw_message(seed: bytes, to: bytes, rid: str, version: int) -> tuple[list[tuple[Any, ...]], bytes]:
    """A WITHDRAW, field by field, signed with the key of `seed`, its body checked with both libraries."""
    body_parts = pe.header("Withdraw") + [(to, f"to: fixed(32), {pe.NAMES.get(to, 'a')}'s test key")]
    body = b"".join(p[0] for p in body_parts)
    assert body[10:] == pe.library_binary(pe.parsed["Withdraw"], {"to": to}), "the body differs from fastavro"
    back = avro.io.DatumReader(pe.apache["Withdraw"]).read(avro.io.BinaryDecoder(io.BytesIO(body[10:])))
    assert back == {"to": to}, "avro decodes another body"
    return cast(
        tuple[list[tuple[Any, ...]], bytes], pe.make_message("WITHDRAW", seed, (rid, version), body_parts)
    )


def check() -> list[str]:
    out: list[str] = []
    # Section 10: the schema.
    text = pe.texts["Withdraw"]
    pcf = to_parsing_canonical_form(fastavro.parse_schema(json.loads(text)))
    assert pcf == WITHDRAW_PCF, "the canonical form is not that of section 10"
    assert avro.schema.parse(pcf).canonical_form == pcf, "the two libraries disagree on the canonical form"
    fp = rules.crc64_avro(pcf.encode())
    assert fp == WITHDRAW_FP == pe.fingerprints["Withdraw"][1], "the fingerprint is not that of section 10"
    assert fa_fingerprint(pcf, "CRC-64-AVRO") == pe.fp8(fp).hex() == rules.apache_fingerprint(text).hex()
    assert pe.KINDS.index("WITHDRAW") == 14 and pe.OUTCOME["symbols"].index("WITHDRAWN") == 5
    assert pe.defined_by["axt.Withdraw"] == pe.defined_by["axt.WithdrawTo"] == "Withdraw"
    out += ["== Section 10: schema ==", f"axt.Withdraw: canonical form: {pcf}"]
    out += ["| Schema | Envelope format | CRC-64-AVRO | As bytes |"]
    out += [f"| `axt.Withdraw` | 1 | `0x{fp:016x}` | `{pe.fp8(fp).hex(' ')}` |", ""]
    # Section 11.1: the steps.
    rows = example_steps()
    assert rows == TABLE, rows
    out += ["== Section 11.1: the steps =="]
    out += ["| Step | Message | Receiver's version before | Outcome | Receiver's version after |"]
    out += [f"| {s} | {m} | {b} | {o} | {a} |" for s, m, b, o, a in rows] + [""]
    # Section 11.2: the WITHDRAW of step 2, which Old Brain Fix takes after the MANIFEST and the OFFER of
    # spec/protocol.md, section 17, and its ACCEPT of the Appointment: an id it does not have.
    parts, m = withdraw_message(pe.CAT_SEED, pe.OBF, REC_ID, 4)
    readers = {"axt.example.v1.Appointment": pe.APPOINTMENT_READER}
    app = pe.App("Old Brain Fix", pe.OBF_SEED, pe.me.OLD_BRAIN_FIX, readers, lambda n: n in readers)
    assert app.receive(pe.m1)[0] == "manifest taken" and app.receive(pe.offer_msg)[0] == "answered"
    fresh = copy.deepcopy(app)
    assert app.receive(m) == ("WITHDRAWN", [])
    assert app.records[REC_ID] == {"type": None, "version": 4, "state": "withdrawn", "value": None}
    assert app.pending_acks[-1] == {
        "id": REC_ID,
        "version": 4,
        "outcome": "WITHDRAWN",
        "receiver_version": 4,
        "kept_fields": [],
    }
    assert app.receive(m) == ("DUPLICATE", []), "a repeat"
    other = fresh
    other.pub = pe.OTHER
    assert other.receive(m) == ("ignored: addressed to another key", []), "another key in to"
    body: bytes = sy.read_all("Envelope", m[10:])["body"]
    out.append(
        f"== Section 11.2: the WITHDRAW of step 2: {len(m)} bytes, SHA-256 {hashlib.sha256(m).hexdigest()} =="
    )
    out.append(f"body: {len(body)} bytes")
    out.append(pe.dump(parts))
    out.append(f"signed bytes: {len(keys.MESSAGE_PREFIX) + len(m) - 74}, signature {m[-64:].hex()}")
    return out


def main() -> None:
    for line in check():
        print(line)
    print("all checks passed")


if __name__ == "__main__":
    main()
