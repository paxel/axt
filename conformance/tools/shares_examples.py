# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Produce and check the examples of spec/shares.md.

The examples of spec/shares.md are the schemas of the bodies of a WITHDRAW, a PROPOSAL and a
PROPOSAL_REPLY, the steps of a share and its withdrawal with their versions and outcomes (section
11.1), the WITHDRAW of step 2 (section 11.2), the steps of a proposal (section 11.3), and its
PROPOSAL and PROPOSAL_REPLY (sections 11.4 and 11.5). This script:

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
  the exchange of spec/protocol.md, section 17;
- checks types/axt/Proposal.avsc and ProposalReply.avsc as Withdraw.avsc (section 10), with the
  default of axt.ProposalReplyAnswer once in schema resolution, and that PROPOSAL and PROPOSAL_REPLY
  are the symbols 15 and 16 of axt.Kind and PROPOSALS_NOT_TAKEN the symbol 15 of axt.ErrorCode;
- implements an owner, one installation that counts, which takes proposals by the steps of section
  13.3 and 13.4 and makes what its user takes of them a change of the record (section 15), and a
  proposer, which sends proposals and takes replies and errors (sections 13.1, 14.2 and 16); the
  generator turns sessions of both into the vectors of the operations `owner` and `proposer`;
- plays the steps of section 11.3 with them and the receiver above, and builds the PROPOSAL of
  section 11.4, with its axt.DateTime checked by the rules of time_examples.py, and the
  PROPOSAL_REPLY of section 11.5 field by field as the WITHDRAW, signed and verified in the same way.

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
    taken: dict[str, Any] = field(default_factory=dict)  # the value it last took from the sender


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
            r.taken = dict(value or {})
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
            r.state, r.value, r.changed, r.taken = "there", dict(m["value"]), set(), dict(m["value"])
            return self.result("APPLIED", r)
        if r.state == "deleted_by_user":
            return self.result("KEPT", r)
        assert r.value is not None
        if not r.changed or self.mode == "whole_record_take":
            r.value, r.changed, r.taken = dict(m["value"]), set(), dict(m["value"])
            return self.result("APPLIED", r)
        if self.mode == "whole_record_keep":
            return self.result("KEPT", r)
        value = dict(m["value"])
        lists = sy.element_fields(m["type"])
        for f in r.changed:
            if f in r.value:
                # A list merged per element (spec/records.md, section 6.1).
                mine = r.value[f]
                value[f] = (
                    sy.merge_elements(r.taken.get(f, []), mine, value[f], lists[f]) if f in lists else mine
                )
        kept = [f for f in r.changed if f in value and value[f] != m["value"].get(f)]
        r.value, r.taken = value, dict(m["value"])
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


# --- proposals (sections 12 to 18) ----------------------------------------------------------------

PROPOSAL_PCF = (
    '{"name":"axt.Proposal","type":"record","fields":[{"name":"to","type":{"name":"axt.ProposalTo",'
    '"type":"fixed","size":32}},{"name":"proposal_id","type":"string"},{"name":"fields","type":'
    '{"type":"array","items":{"name":"axt.ProposalField","type":"record","fields":[{"name":"name",'
    '"type":"string"},{"name":"schema","type":{"name":"axt.ProposalFieldSchema","type":"fixed","size":8}},'
    '{"name":"value","type":"bytes"}]}}}]}'
)
REPLY_PCF = (
    '{"name":"axt.ProposalReply","type":"record","fields":[{"name":"to","type":{"name":"axt.ProposalReplyTo",'
    '"type":"fixed","size":32}},{"name":"proposal_id","type":"string"},{"name":"answer","type":'
    '{"name":"axt.ProposalReplyAnswer","type":"enum","symbols":["ACCEPTED","DECLINED"]}}]}'
)
PROPOSAL_ID = "7b3e9d21-4c8a-4f6e-9a1b-5d2c8e4f6a70"  # the proposal of section 11.4
MAX_OPEN_RECORD = 16  # open proposals of one proposer for one record, at a device (section 18.3)
MAX_OPEN = 256  # open proposals of one proposer in all, at a device
Entry = tuple[str, bytes, bytes]  # a proposed value: the field's name, the fingerprint, the value bytes


def proposal_body(to: bytes, pid: str, entries: list[Entry]) -> bytes:
    """The body of a PROPOSAL, written by fastavro, whatever its content."""
    fields = [{"name": n, "schema": fp, "value": v} for n, fp, v in entries]
    return cast(bytes, sy.body_of("Proposal", {"to": to, "proposal_id": pid, "fields": fields}))


def reply_body(to: bytes, pid: str, answer: str) -> bytes:
    return cast(bytes, sy.body_of("ProposalReply", {"to": to, "proposal_id": pid, "answer": answer}))


def proposal_message(
    seed: bytes,
    to: bytes,
    record: tuple[str, int],
    pid: str,
    entries: list[Entry],
    shown: dict[str, list[tuple[Any, ...]]] | None = None,
) -> tuple[list[tuple[Any, ...]], bytes]:
    """A PROPOSAL, field by field, signed with the key of `seed`, its body checked with both libraries.
    `shown` gives, by field name, the parts in which the dump shows a value."""
    shown = shown or {}

    def entry(name: str, e: Entry) -> list[tuple[Any, ...]]:
        value_note = f"{name}.value: bytes length {len(e[2])}"
        name_parts: list[tuple[Any, ...]] = pe.string_parts(f"{name}.name", e[0])
        return name_parts + [
            (e[1], f"{name}.schema: fixed(8), the fingerprint of the writer schema"),
            (keys.zigzag(len(e[2])), value_note),
            *(shown.get(e[0]) or [(e[2], f"{name}.value: the value in Avro binary encoding")]),
        ]

    parts = pe.header("Proposal") + [(to, f"to: fixed(32), {pe.NAMES.get(to, 'a')}'s test key")]
    parts += pe.string_parts("proposal_id", pid) + pe.array_parts("fields", entries, entry)
    body = b"".join(p[0] for p in parts)
    assert body == proposal_body(to, pid, entries), "the body differs from fastavro"
    datum = {
        "to": to,
        "proposal_id": pid,
        "fields": [{"name": n, "schema": f, "value": v} for n, f, v in entries],
    }
    back = avro.io.DatumReader(pe.apache["Proposal"]).read(avro.io.BinaryDecoder(io.BytesIO(body[10:])))
    assert pe.plain(back) == datum, "avro decodes another body"
    return cast(tuple[list[tuple[Any, ...]], bytes], pe.make_message("PROPOSAL", seed, record, parts))


def reply_message(
    seed: bytes, to: bytes, record: tuple[str, int], pid: str, answer: str
) -> tuple[list[tuple[Any, ...]], bytes]:
    """A PROPOSAL_REPLY, field by field, signed with the key of `seed`, its body checked with both
    libraries."""
    enum = pe.jsons["ProposalReply"]["fields"][2]["type"]
    parts = pe.header("ProposalReply") + [(to, f"to: fixed(32), {pe.NAMES.get(to, 'a')}'s test key")]
    parts += pe.string_parts("proposal_id", pid) + pe.symbol("answer", enum, answer)
    body = b"".join(p[0] for p in parts)
    assert body == reply_body(to, pid, answer), "the body differs from fastavro"
    back = avro.io.DatumReader(pe.apache["ProposalReply"]).read(avro.io.BinaryDecoder(io.BytesIO(body[10:])))
    assert pe.plain(back) == {"to": to, "proposal_id": pid, "answer": answer}, "avro decodes another body"
    return cast(tuple[list[tuple[Any, ...]], bytes], pe.make_message("PROPOSAL_REPLY", seed, record, parts))


def json_form(value: Any) -> Any:
    """A decoded Avro value in the JSON form of spec/conformance.md, section 3.3."""
    if isinstance(value, dict):
        return {k: json_form(v) for k, v in value.items()}
    if isinstance(value, list):
        return [json_form(v) for v in value]
    if isinstance(value, bytes):
        return value.hex()
    return value


class Failed(Exception):
    """A message that fails a step, with the code that reports it."""

    def __init__(self, code: str, fingerprint: bytes | None = None, field: str | None = None) -> None:
        super().__init__(code)
        self.code, self.fingerprint, self.field = code, fingerprint, field
        self.sender: bytes | None = None


def envelope_of(m: bytes) -> dict[str, Any]:
    """The envelope of a live message whose signature verifies (spec/protocol.md, section 8.2); Failed
    with the code of the check that fails."""
    if len(m) > pe.MAX_MESSAGE:
        raise Failed("TOO_LARGE")
    if len(m) < 10 or m[:2] != b"\xc3\x01":
        raise Failed("INVALID_MESSAGE")
    if m[2:10] != sy.SPEC_FP["Envelope"]:
        raise Failed("FORMAT_UNSUPPORTED", m[2:10])
    try:
        env: dict[str, Any] = sy.read_all("Envelope", m[10:])
    except ValueError:
        raise Failed("INVALID_MESSAGE") from None
    if env["format"] != 1:
        raise Failed("INVALID_MESSAGE")
    if keys.verify_problem(env["sender"], keys.MESSAGE_PREFIX + m[10:-64], m[-64:]) is not None:
        f = Failed("SIGNATURE_INVALID")
        f.sender = env["sender"]  # reported to the key the message names (spec/protocol.md, section 8.2)
        raise f
    return env


def body_of_kind(env: dict[str, Any], name: str) -> dict[str, Any]:
    """Step 1 after the signature: `record`, then the body as one datum of the schema (section 13.3)."""
    if env["record"] is None:
        raise Failed("INVALID_MESSAGE")
    body = env["body"]
    if body[:10] != b"\xc3\x01" + sy.SPEC_FP[name]:
        raise Failed("INVALID_MESSAGE")
    try:
        d: dict[str, Any] = sy.read_all(name, body[10:])
    except ValueError:
        raise Failed("INVALID_MESSAGE") from None
    return d


def error_message(seed: bytes, to: bytes, about: bytes, f: Failed, record: dict[str, Any] | None) -> bytes:
    """The ERROR that reports a message (spec/protocol.md, section 8.1)."""
    if record is not None and len(str(record["id"]).encode()) > pe.MAX_ERROR_RECORD_ID:
        record = None
    d = {
        "to": to,
        "code": f.code,
        "message_hash": hashlib.sha256(about).digest(),
        "record": record,
        "fingerprint": f.fingerprint,
        "field": f.field,
        "detail": "",
    }
    return cast(bytes, sy.message(seed, "ERROR", None, sy.body_of("Error", d)))


MAX_VALUE_BYTES = 65536  # value bytes of one PROPOSAL (section 18.3)
MAX_OPEN_BYTES = 1048576  # value bytes of the open proposals of one proposer in all, at a device


def value_bytes(entries: list[Entry]) -> int:
    """The value bytes of a proposal: the `value` of every entry together (section 18.3)."""
    return sum(len(v) for _, _, v in entries)


@dataclass
class Own:
    """A record of the owner's own set at an installation that counts its versions."""

    type: str
    version: int
    deleted: bool
    value: dict[str, Any]  # in the JSON form of spec/conformance.md, section 3.3
    shared: set[str]  # the names of the receivers with which it is shared


@dataclass
class Open:
    """A proposal that the device took and holds as open (sections 13.4 and 17.1)."""

    receiver: str
    pid: str
    rid: str
    signer: bytes
    record: dict[str, Any]
    entries: list[Entry]
    message: bytes | None = None  # the PROPOSAL as the device got it
    size: int = 0  # its value bytes


class Owner:
    """One installation of the owner of shared records, which counts its versions, takes proposals by
    sections 13.3 and 13.4, and makes what its user takes of them a change of the record (section 15).
    `receivers` are its known senders other than its own set, by name, each with its current keys;
    `siblings` the other keys of its own set; `readers` its reader schemas by full name, with which it
    shows a proposed value (section 15.1)."""

    def __init__(
        self,
        seed: bytes,
        receivers: dict[str, list[bytes]],
        records: dict[str, Own],
        takes: set[str],
        schemas: list[str],
        siblings: list[bytes] | None = None,
        readers: dict[str, Any] | None = None,
    ) -> None:
        self.seed, self.key = seed, bytes(keys.public_key(seed))
        self.receivers, self.records, self.takes = receivers, records, set(takes)
        self.schemas = {sy.schema_fingerprint(t): json.loads(t) for t in schemas}
        self.siblings = list(siblings or [])
        self.readers = dict(readers or {})
        self.open: dict[tuple[str, str], Open] = {}  # by receiver and proposal id
        # What the app's records hold (sections 15.1 and 18.4): each answer with the proposal's record, and
        # the stops of receivers, each for a record id, a type or all records (None).
        self.answers: dict[tuple[str, str], tuple[str, dict[str, Any]]] = {}
        self.stopped: list[tuple[str, str | None, str | None]] = []
        # The receivers it holds as apps of its own user: receivers of every record (sections 2.3 and 12.2).
        self.own_user: set[str] = set()

    def _receiver(self, key: bytes) -> str | None:
        return next((n for n, ks in self.receivers.items() if key in ks), None)

    def _record(self, rid: str) -> Own | None:
        """The record of its own set with that id, found as ids are compared (spec/records.md, section 2)."""
        k = sy.uuid_key(rid)
        return next((r for i, r in self.records.items() if sy.uuid_key(i) == k), None)

    def _rid(self, rid: str) -> str:
        k = sy.uuid_key(rid)
        return next(i for i in self.records if sy.uuid_key(i) == k)

    def is_stopped(self, who: str, rid: str, type_name: str) -> bool:
        """Whether the app's records hold the proposals of the receiver as stopped for the record (18.4)."""
        k = sy.uuid_key(rid)
        return any(
            r == who and (i is None or sy.uuid_key(i) == k) and (t is None or t == type_name)
            for r, i, t in self.stopped
        )

    def receive(self, m: bytes) -> tuple[str, list[bytes]]:
        """A PROPOSAL that reaches the device from the app that sent it: `taken`, `replaced`, `repeat`,
        `ignored` or `rejected`, and the messages the device sends: the reply again, or the ERROR."""
        env: dict[str, Any] | None = None
        try:
            env = envelope_of(m)
            if env["sender"] == self.key:
                return "ignored", []  # before the steps (section 13.3)
            return self._steps(env, m)
        except Failed as f:
            sender = f.sender if env is None else env["sender"]
            rec = None if env is None or f.code == "SIGNATURE_INVALID" else env["record"]
            record = None if rec is None else {"id": str(rec["id"]), "version": rec["version"]}
            if sender is None:
                return "rejected", []  # not reported here: the size, the format, the envelope
            return "rejected", [error_message(self.seed, sender, m, f, record)]

    def _steps(self, env: dict[str, Any], m: bytes) -> tuple[str, list[bytes]]:
        assert env["kind"] == "PROPOSAL", "the owner of this model gets proposals"
        d = body_of_kind(env, "Proposal")  # step 1
        if d["to"] != self.key:
            return "ignored", []
        rec = env["record"]
        rid, version = str(rec["id"]), rec["version"]
        if sy.uuid_key(rid) is None:
            raise Failed("RECORD_ID_INVALID")  # step 2
        if version < 1:
            raise Failed("VERSION_INVALID")  # step 3
        if pe.proposal_problem(d) is not None:
            raise Failed("INVALID_MESSAGE")  # step 4
        who = self._receiver(env["sender"])
        pid = d["proposal_id"]
        entries = [(f["name"], f["schema"], f["value"]) for f in d["fields"]]
        if who is not None and (who, pid) in self.answers:
            # An answered repeat is looked up before step 5: the reply again (section 13.4).
            answer, record = self.answers[(who, pid)]
            body = reply_body(env["sender"], pid, answer)
            return "repeat", [
                sy.message(self.seed, "PROPOSAL_REPLY", (record["id"], record["version"]), body)
            ]
        own = self._record(rid)
        if (  # step 5: one result for every reason (section 13.3)
            who is None
            or own is None
            or own.deleted
            or (who not in own.shared and who not in self.own_user)
            or own.type not in self.takes
            or self.is_stopped(who, rid, own.type)
            or self._beyond(who, rid, pid, entries)
        ):
            raise Failed("PROPOSALS_NOT_TAKEN")
        for _, fp, _ in entries:  # step 6
            if fp not in self.schemas:
                raise Failed("SCHEMA_UNKNOWN", fp)
        for name, fp, _ in entries:  # step 7
            schema = self.schemas[fp]
            if sy.full_name(schema) != own.type or sy.field_schema(schema, name) is None:
                raise Failed("INVALID_MESSAGE")
        decoded = []
        for name, fp, value in entries:  # step 8
            buf = io.BytesIO(value)
            try:
                one, v = sy.read_field(self.schemas[fp], name, buf)
            except ValueError:
                raise Failed("UNDECODABLE") from None
            if buf.tell() != len(value):
                raise Failed("UNDECODABLE")
            decoded.append((one, v))
        for one, v in decoded:  # step 9: the time values; this device checks no attribute
            broken = sy.tm.value_breaches(one, v)
            if broken:
                raise Failed("VALUE_INVALID", field=sy.mr.error_field(broken[0][0]))
        return self._take(who, pid, env, rid, entries, m)  # step 10

    def _beyond(self, who: str, rid: str, pid: str, entries: list[Entry]) -> bool:
        """Whether a new proposal would be beyond the limits of section 18.3."""
        if (who, pid) in self.open:
            return False  # a repeat is no new proposal
        mine = [o for o in self.open.values() if o.receiver == who]
        here = [o for o in mine if sy.uuid_key(o.rid) == sy.uuid_key(rid)]
        size = value_bytes(entries)
        return (
            len(here) >= MAX_OPEN_RECORD
            or len(mine) >= MAX_OPEN
            or size > MAX_VALUE_BYTES
            or sum(o.size for o in mine) + size > MAX_OPEN_BYTES
        )

    def _take(
        self, who: str, pid: str, env: dict[str, Any], rid: str, entries: list[Entry], m: bytes
    ) -> tuple[str, list[bytes]]:
        """Section 13.4: a new proposal, or a repeat of an open one, which in other bytes with a higher
        SHA-256 takes the place of the one held."""
        rec = env["record"]
        record = {"id": str(rec["id"]), "version": rec["version"]}
        held = self.open.get((who, pid))
        new = Open(who, pid, self._rid(rid), env["sender"], record, entries, m, value_bytes(entries))
        if held is not None:
            if held.message is not None and m != held.message and sy.sha(m) > sy.sha(held.message):
                self.open[(who, pid)] = new
                return "replaced", []
            return "repeat", []
        self.open[(who, pid)] = new
        return "taken", []

    def shows(self, o: Open) -> bool:
        """Whether the device can show every proposed value of the proposal, decoded with the schema of its
        entry and resolved against its reader schema of the type (section 15.1)."""
        own = self.records[o.rid]
        reader = self.readers.get(own.type)
        for name, fp, value in o.entries:
            if fp not in self.schemas:
                return False
            writer = self.schemas[fp]
            target = writer if reader is None else reader
            if sy.field_schema(target, name) is None or not pe.resolves(writer, target):
                return False
            try:
                sy.read_field(writer, name, io.BytesIO(value))
            except ValueError:
                return False
        return True

    def answer(
        self, who: str, pid: str, answer: str
    ) -> tuple[bool, list[bytes], tuple[int, dict[str, Any]] | None]:
        """The user answers an open proposal (sections 15.1 and 15.2): whether the device answers, the
        reply, and for ACCEPTED the version and the value of the update it sends. ACCEPTED stamps every
        proposed field, so it always gives a new version; it is barred where the device cannot show every
        proposed value."""
        o = self.open.get((who, pid))
        if o is None or (answer == "ACCEPTED" and not self.shows(o)):
            return False, [], None
        own = self.records[o.rid]
        update = None
        if answer == "ACCEPTED":
            for name, fp, value in o.entries:
                _, v = sy.read_field(self.schemas[fp], name, io.BytesIO(value))
                own.value = {**own.value, name: json_form(v[name])}
            own.version += 1  # the next count (spec/records.md, section 3)
            update = (own.version, dict(own.value))
        del self.open[(who, pid)]
        self.record_answer(who, pid, answer, o.record)
        reply = []
        if o.signer in self.receivers.get(who, []):  # no reply to a key removed since (section 14.1)
            body = reply_body(o.signer, pid, answer)
            reply.append(sy.message(self.seed, "PROPOSAL_REPLY", (o.record["id"], o.record["version"]), body))
        return True, reply, update

    def record_answer(self, who: str, pid: str, answer: str, record: dict[str, Any]) -> None:
        """An answer comes into the app's records, by this device or from a sibling: of two, ACCEPTED stands
        (section 15.1). The open proposal ends with it."""
        held = self.answers.get((who, pid))
        if held is None or (held[0] == "DECLINED" and answer == "ACCEPTED"):
            self.answers[(who, pid)] = (answer, record)
        self.open.pop((who, pid), None)

    def change(self, rid: str, action: str, who: str | None = None) -> None:
        """The record is deleted, or no longer shared with a receiver, or shared again: an open proposal of
        a record that is no longer there or shared with its proposer is dropped (section 15.4)."""
        own = self.records[self._rid(rid)]
        if action == "delete":
            own.deleted = True
        elif action == "unshare":
            own.shared.discard(cast(str, who))
        else:
            own.shared.add(cast(str, who))
        self._tidy()

    def stop(self, who: str, rid: str | None, type_name: str | None) -> None:
        """The user stops the proposals of a receiver, for a record, a type or all records (section 18.4):
        the device drops the kept proposals that the stop holds, without a reply."""
        self.stopped.append((who, rid, type_name))
        self._tidy()

    def _tidy(self) -> None:
        for k, o in list(self.open.items()):
            r = self.records[o.rid]
            if r.deleted or (o.receiver not in r.shared and o.receiver not in self.own_user):
                del self.open[k]
            elif self.is_stopped(o.receiver, o.rid, r.type):
                del self.open[k]


@dataclass
class Sent:
    """A proposal that the proposing device sent, with what it got for it (sections 14.2 and 16)."""

    message: bytes
    to: bytes
    rid: str
    version: int
    entries: list[Entry]
    status: str = "open"  # open, ACCEPTED, DECLINED, or the code of the ERROR that settled it
    relay: bool = False  # whether it went through the relay
    day: int = 0  # the day it last went


@dataclass
class Got:
    """A record of the owner at the proposer: its type, the receiver's version, the kind of the last
    record message, the text of the writer schema of the kept DATA and the bytes of its fields, and
    whether its user deleted it."""

    type: str
    version: int
    last: str
    schema: str | None
    values: dict[str, bytes] = field(default_factory=dict)
    deleted: bool = False


class Proposer:
    """One installation of a receiver that proposes changes of the records of one owner (sections 13.1,
    14.2 and 16): what it sends, what it sends again, and what it does with a reply and with an error."""

    def __init__(
        self,
        seed: bytes,
        current: list[bytes],
        manifests: dict[bytes, tuple[int, set[str]]],
        records: dict[str, Got],
        ids: list[str],
    ) -> None:
        self.seed, self.key = seed, bytes(keys.public_key(seed))
        self.current, self.manifests, self.records, self.ids = list(current), manifests, records, list(ids)
        self.sent: dict[str, Sent] = {}  # by proposal id
        self.day = 0
        # For each record id, the block after PROPOSALS_NOT_TAKEN or SCHEMA_UNKNOWN (section 16.3): the
        # revisions of the owner's manifests then, by key, and the version of the record then.
        self.blocked: dict[str, tuple[dict[bytes, int], int]] = {}
        # For each record id, after VALUE_INVALID: the top-level field and the value proposed last.
        self.invalid: dict[str, tuple[str, bytes]] = {}

    def _takes(self, key: bytes, type_name: str) -> bool:
        manifest = self.manifests.get(key)
        return key in self.current and manifest is not None and type_name in manifest[1]

    def propose(
        self, rid: str, to: bytes, values: dict[str, bytes | None], relay: bool = False
    ) -> bytes | None:
        """The PROPOSAL of the user's values of the record, to the key `to`, or None where the device
        must not send one (sections 12.2, 13.1 and 16.3). Only the fields whose value differs from the DATA
        of the receiver's version go into it."""
        got = self.records.get(rid)
        if got is None or got.deleted or got.last != "DATA" or got.schema is None:
            return None
        schema = json.loads(got.schema)
        entries = [
            (n, v)
            for n, v in sorted(values.items())
            if v is not None and not (n in got.values and sy.same_value(n, v, schema, got.values[n], schema))
        ]
        if not entries or not self._takes(to, got.type) or rid in self.blocked:
            return None
        if rid in self.invalid:
            name, value = self.invalid[rid]
            mine = dict(entries).get(name)
            if mine is not None and sy.same_value(name, mine, schema, value, schema):
                return None
            del self.invalid[rid]
        fp = sy.schema_fingerprint(got.schema)
        pid = self.ids.pop(0)
        es = [(n, fp, v) for n, v in entries]
        m = cast(bytes, sy.message(self.seed, "PROPOSAL", (rid, got.version), proposal_body(to, pid, es)))
        self.sent[pid] = Sent(m, to, rid, got.version, es, relay=relay, day=self.day)
        return m

    def receive(self, m: bytes) -> tuple[str, list[bytes]]:
        """A PROPOSAL_REPLY (section 14.2) or an ERROR (section 16.3) of the owner: `taken`, `ignored` or
        `rejected`, and the ERROR it sends for a reply it rejects."""
        env: dict[str, Any] | None = None
        try:
            env = envelope_of(m)
            if env["kind"] == "ERROR":
                return self._error(env), []
            assert env["kind"] == "PROPOSAL_REPLY", "the proposer of this model gets replies and errors"
            d = body_of_kind(env, "ProposalReply")  # step 1
        except Failed as f:
            sender = f.sender if env is None else env["sender"]
            if sender is None:
                return "rejected", []  # not reported here: the size, the format, the envelope
            rec = None if env is None else env["record"]
            record = None if rec is None else {"id": str(rec["id"]), "version": rec["version"]}
            return "rejected", [error_message(self.seed, sender, m, f, record)]
        if d["to"] != self.key:
            return "ignored", []  # step 2
        sent = self.sent.get(d["proposal_id"])
        if sent is None or env["sender"] not in self.current:
            return "ignored", []  # step 3
        rec = env["record"]
        if sy.uuid_key(str(rec["id"])) != sy.uuid_key(sent.rid) or rec["version"] != sent.version:
            record = {"id": str(rec["id"]), "version": rec["version"]}
            return "rejected", [error_message(self.seed, env["sender"], m, Failed("INVALID_MESSAGE"), record)]
        self.blocked.clear()  # a reply to any proposal to that owner ends every block (section 16.3)
        if sent.status in ("ACCEPTED", "DECLINED"):
            # Step 5: a later ACCEPTED takes the place of a DECLINED; every other reply is ignored.
            if sent.status == "DECLINED" and d["answer"] == "ACCEPTED":
                sent.status = "ACCEPTED"
                return "taken", []
            return "ignored", []
        sent.status = d["answer"]  # step 6
        return "taken", []

    def _error(self, env: dict[str, Any]) -> str:
        """An ERROR about a PROPOSAL that the device sent to the key that sent the ERROR (section 16.3)."""
        body = env["body"]
        if body[:10] != b"\xc3\x01" + sy.SPEC_FP["Error"]:
            raise Failed("INVALID_MESSAGE")
        try:
            d = sy.read_all("Error", body[10:])
        except ValueError:
            raise Failed("INVALID_MESSAGE") from None
        if d["to"] != self.key:
            return "ignored"
        about = next(
            (s for s in self.sent.values() if hashlib.sha256(s.message).digest() == d["message_hash"]), None
        )
        if about is None or about.to != env["sender"]:
            return "ignored"
        if about.status in ("ACCEPTED", "DECLINED"):
            return "ignored"  # a reply stands
        if d["code"] == "FORMAT_UNSUPPORTED":
            return "taken"  # not settled: it goes again in the chosen format, here the same message
        about.status = d["code"]
        if d["code"] in ("PROPOSALS_NOT_TAKEN", "SCHEMA_UNKNOWN"):
            revisions = {k: m[0] for k, m in self.manifests.items()}
            self.blocked[about.rid] = (revisions, self.records[about.rid].version)
        elif d["code"] == "VALUE_INVALID" and d["field"] is not None:
            name = str(d["field"]).split(".")[0].split("[")[0]
            value = dict((n, v) for n, _, v in about.entries).get(name)
            if value is not None:
                self.invalid[about.rid] = (name, value)
        return "taken"

    def record(self, rid: str, kind: str, version: int, values: dict[str, bytes] | None = None) -> None:
        """A record message of the owner that the device applied: its version is the receiver's version. A
        higher version ends the block of the record (section 16.3)."""
        got = self.records[rid]
        blocked = self.blocked.get(rid)
        if blocked is not None and version > blocked[1]:
            del self.blocked[rid]
        got.version, got.last = version, kind
        if values is not None:
            got.values = dict(values)

    def manifest(self, key: bytes, revision: int, takes: set[str]) -> None:
        """A manifest of a key of the owner: one with a higher revision than the device held of that key
        ends every block (section 16.3)."""
        held = self.manifests.get(key)
        for rid, (revisions, _) in list(self.blocked.items()):
            if revision > revisions.get(key, 0):
                del self.blocked[rid]
        if held is None or revision > held[0]:
            self.manifests[key] = (revision, takes)

    def _open(self) -> list[Sent]:
        return [
            s
            for s in self.sent.values()
            if s.status == "open" and self.records[s.rid].last == "DATA" and s.to in self.current
        ]

    def connect(self, key: bytes) -> list[bytes]:
        """A live connection with the device of that key begins: the open proposals to it go again, the same
        messages (section 16.2)."""
        return [s.message for s in self._open() if s.to == key]

    def days(self, n: int) -> list[bytes]:
        """n days pass: the open proposals sent through the relay go again once 14 days have passed since
        they last went (section 16.2)."""
        self.day += n
        out = []
        for s in self._open():
            if s.relay and self.day - s.day >= sy.HOLDING_DAYS:
                s.day = self.day
                out.append(s.message)
        return out

    def remove(self, key: bytes) -> list[bytes]:
        """The key is removed from the owner: each open proposal to it goes to another current key whose
        manifest takes proposals for the type, the first in the order of the keys, with the same id, record
        and fields, signed anew (section 16.2)."""
        self.current.remove(key)
        out = []
        for pid, s in self.sent.items():
            if s.to != key or s.status != "open" or self.records[s.rid].last != "DATA":
                continue
            others = sorted(k for k in self.current if self._takes(k, self.records[s.rid].type))
            if not others:
                continue
            s.to = others[0]
            body = proposal_body(s.to, pid, s.entries)
            s.message = cast(bytes, sy.message(self.seed, "PROPOSAL", (s.rid, s.version), body))
            out.append(s.message)
        return out

    def resend(self, pid: str) -> bool:
        """Whether the device sends the proposal again (section 16.2)."""
        return self.sent[pid] in self._open()


def owner_session(i: dict[str, Any], b_in: Any = bytes.fromhex) -> list[dict[str, Any]]:
    """A session of the operation `owner` (spec/conformance.md, section 5.15), with each message the device
    sends as bytes."""
    d = i["device"]
    receivers = {r["name"]: [bytes.fromhex(k) for k in r["current"]] for r in d["receivers"]}
    records = {
        r["id"]: Own(
            r["type"],
            int(r["version"]),
            r["state"] == "deleted",
            r["value"],
            set(r["shared"]),
        )
        for r in d["records"]
    }
    readers = {name: json.loads(text) for name, text in d.get("readers", {}).items()}
    owner = Owner(
        bytes.fromhex(d["seed"]),
        receivers,
        records,
        set(d["proposals"]),
        d["schemas"],
        [bytes.fromhex(k) for k in d.get("siblings", [])],
        readers,
    )
    for o in d.get("open", []):
        signer = receivers[o["receiver"]][0]
        rec = {"id": o["id"], "version": 1}
        size = int(o.get("value_bytes", 0))
        owner.open[(o["receiver"], o["proposal_id"])] = Open(
            o["receiver"], o["proposal_id"], o["id"], signer, rec, [], None, size
        )
    for a in d.get("answers", []):
        owner.answers[(a["receiver"], a["proposal_id"])] = (
            a["answer"],
            {"id": a["id"], "version": a["version"]},
        )
    owner.own_user = {r["name"] for r in d["receivers"] if r.get("own_user", False)}
    for s in d.get("stopped", []):
        owner.stopped.append((s["receiver"], s.get("id"), s.get("type")))
    out: list[dict[str, Any]] = []
    for step in i["steps"]:
        if "receive" in step:
            result, replies = owner.receive(b_in(step["receive"]))
            out.append({"result": result, "replies": replies})
        elif "answer" in step:
            a = step["answer"]
            made, replies, update = owner.answer(a["receiver"], a["proposal_id"], a["answer"])
            out.append(
                {
                    "made": made,
                    "replies": replies,
                    "update": update and {"version": str(update[0]), "value": update[1]},
                }
            )
        elif "answered" in step:
            a = step["answered"]
            owner.record_answer(
                a["receiver"], a["proposal_id"], a["answer"], {"id": a["id"], "version": a["version"]}
            )
            out.append({})
        elif "change" in step:
            c = step["change"]
            owner.change(c["id"], c["action"], c.get("receiver"))
            out.append({})
        elif "stop" in step:
            s = step["stop"]
            owner.stop(s["receiver"], s.get("id"), s.get("type"))
            out.append({})
        elif "manifest" in step:
            owner.takes = set(step["manifest"])
            out.append({})
        else:
            out.append(
                {
                    "open": sorted(
                        (
                            {
                                "receiver": o.receiver,
                                "proposal_id": o.pid,
                                "id": o.rid,
                                "message_hash": None if o.message is None else sy.sha(o.message).hex(),
                            }
                            for o in owner.open.values()
                        ),
                        key=lambda o: (o["receiver"], o["proposal_id"]),
                    ),
                    "answers": sorted(
                        (
                            {
                                "receiver": r,
                                "proposal_id": p,
                                "answer": a,
                                "id": rec["id"],
                                "version": rec["version"],
                            }
                            for (r, p), (a, rec) in owner.answers.items()
                        ),
                        key=lambda o: (o["receiver"], o["proposal_id"]),
                    ),
                    "records": [
                        {
                            "id": rid,
                            "version": str(r.version),
                            "state": "deleted" if r.deleted else "there",
                            "value": r.value,
                        }
                        for rid, r in sorted(owner.records.items())
                    ],
                }
            )
    return out


def proposer_session(i: dict[str, Any], b_in: Any = bytes.fromhex) -> list[dict[str, Any]]:
    """A session of the operation `proposer` (spec/conformance.md, section 5.15)."""
    d = i["device"]
    manifests = {bytes.fromhex(k): (m["revision"], set(m["proposals"])) for k, m in d["manifests"].items()}
    records = {
        r["id"]: Got(
            r["type"],
            int(r["version"]),
            r["last"],
            r["schema"],
            {n: b_in(v) for n, v in r.get("values", {}).items()},
            r.get("deleted", False),
        )
        for r in d["records"]
    }
    p = Proposer(
        bytes.fromhex(d["seed"]),
        [bytes.fromhex(k) for k in d["owner"]],
        manifests,
        records,
        d["proposal_ids"],
    )
    out: list[dict[str, Any]] = []
    for step in i["steps"]:
        if "propose" in step:
            s = step["propose"]
            values = {n: None if v is None else b_in(v) for n, v in s["values"].items()}
            message = p.propose(s["id"], bytes.fromhex(s["to"]), values, s.get("relay", False))
            out.append({"message": message})
        elif "receive" in step:
            result, replies = p.receive(b_in(step["receive"]))
            out.append({"result": result, "replies": replies})
        elif "record" in step:
            r = step["record"]
            brought = None if "values" not in r else {n: bytes(b_in(v)) for n, v in r["values"].items()}
            p.record(r["id"], r["kind"], int(r["version"]), brought)
            out.append({})
        elif "manifest" in step:
            m = step["manifest"]
            p.manifest(bytes.fromhex(m["key"]), m["revision"], set(m["proposals"]))
            out.append({})
        elif "remove" in step:
            out.append({"messages": p.remove(bytes.fromhex(step["remove"]))})
        elif "connect" in step:
            out.append({"messages": p.connect(bytes.fromhex(step["connect"]))})
        elif "days" in step:
            out.append({"messages": p.days(step["days"])})
        else:
            pid = step["query"]
            s2 = p.sent.get(pid)
            out.append(
                {
                    "status": None if s2 is None else s2.status,
                    "resend": False if s2 is None else p.resend(pid),
                }
            )
    return out


def said(m: bytes) -> dict[str, Any]:
    """What a message that a device of these sessions sends says, as the vectors compare it."""
    env = sy.read_all("Envelope", m[10:])
    kind, rec = env["kind"], env["record"]
    name = {"PROPOSAL": "Proposal", "PROPOSAL_REPLY": "ProposalReply", "ERROR": "Error"}[kind]
    d = sy.read_all(name, env["body"][10:])
    out: dict[str, Any] = {"kind": kind, "to": d["to"].hex()}
    if kind == "ERROR":
        r = d["record"]
        return {
            **out,
            "code": d["code"],
            "message_hash": d["message_hash"].hex(),
            "record": r and {"id": r["id"], "version": r["version"]},
            "fingerprint": None if d["fingerprint"] is None else d["fingerprint"].hex(),
            "field": d["field"],
        }
    out["record"] = {"id": rec["id"], "version": rec["version"]}
    out["proposal_id"] = d["proposal_id"]
    if kind == "PROPOSAL_REPLY":
        return {**out, "answer": d["answer"]}
    return {
        **out,
        "fields": {f["name"]: {"schema": f["schema"].hex(), "value": f["value"].hex()} for f in d["fields"]},
    }


# --- the example of section 11.3 ---------------------------------------------------------------------

AP_TYPE = "axt.example.v1.Appointment"
APPOINTMENT_TEXT: str = pe.APPOINTMENT_TEXT  # version 1, as cat-a-log offers it
APPOINTMENT_FP: bytes = sy.schema_fingerprint(APPOINTMENT_TEXT)
APPOINTMENT_SCHEMA = json.loads(APPOINTMENT_TEXT)


def berlin(hour: int, minute: int) -> dict[str, Any]:
    """An axt.DateTime on 2025-11-18 in Europe/Berlin with the offset 3600, its instant by the rules of
    spec/time.md, which must find it valid."""
    v = {
        "year": 2025,
        "month": 11,
        "day": 18,
        "hour": hour,
        "minute": minute,
        "second": 0,
        "millisecond": 0,
        "zone": "Europe/Berlin",
        "offset_seconds": 3600,
        "instant_ms": 0,
    }
    v["instant_ms"] = sy.tm.local_ms(v) - 3600 * 1000
    assert sy.tm.problems("axt.DateTime", v) == [], "a valid time (spec/time.md, section 8)"
    assert sy.tm.offset_at("Europe/Berlin", v["instant_ms"]) == 3600
    return v


START_11 = berlin(11, 0)
assert START_11["instant_ms"] == 1763460000000 == 20410 * 86_400_000 + 10 * 3_600_000  # the prose of 11.4
V3_OWNER: dict[str, Any] = {
    "title": "Vet",
    "start": berlin(10, 30),
    "end": None,
    "all_day": False,
    "location": "",
    "notes": "Bring the vaccination card",
    "reminders": [],
}
START_VALUE: bytes = sy.field_value(APPOINTMENT_SCHEMA, "start", START_11)
MANIFEST_2 = copy.deepcopy(pe.me.CAT_A_LOG)
MANIFEST_2["revision"] = 2
for _e in MANIFEST_2["sends"]:
    if _e["type"] == "axt.example.v1.Appointment":
        _e["proposals"] = True


def takes_proposals(manifest: dict[str, Any]) -> set[str]:
    """The full names for which a manifest takes proposals (section 12.2; spec/manifest.md, section 3.7)."""
    return {e["type"] for e in manifest["sends"] or [] if e["proposals"]}


def example_proposal() -> tuple[bytes, bytes, Owner, Proposer, Receiver]:
    """The steps of section 11.3: the PROPOSAL and the PROPOSAL_REPLY, with the models of both apps."""
    assert pe.me.manifest_problems(MANIFEST_2, 400) == []
    obf_key, cat_key = bytes(pe.OBF), bytes(pe.CAT)
    # Step 1: the DATA of version 3, which Old Brain Fix applies.
    receiver = Receiver("per_field", "delete", "keep")
    got = receiver.message(
        {"kind": "DATA", "id": REC_ID, "version": 3, "type": "axt.example.v1.Appointment", "value": V3}
    )
    assert (got["outcome"], got["receiver_version"]) == ("APPLIED", 3)
    owner = Owner(
        pe.CAT_SEED,
        {"Old Brain Fix": [obf_key]},
        {REC_ID: Own("axt.example.v1.Appointment", 3, False, json_form(V3_OWNER), {"Old Brain Fix"})},
        takes_proposals(MANIFEST_2),
        [APPOINTMENT_TEXT],
    )
    proposer = Proposer(
        pe.OBF_SEED,
        [cat_key],
        {cat_key: (2, takes_proposals(MANIFEST_2))},
        {REC_ID: Got("axt.example.v1.Appointment", 3, "DATA", APPOINTMENT_TEXT)},
        [PROPOSAL_ID],
    )
    # Step 2: the user's change, and the PROPOSAL.
    receiver.local_change(REC_ID, "start", "2025-11-18 11:00")
    proposal = proposer.propose(REC_ID, cat_key, {"start": START_VALUE})
    assert proposal is not None
    # Step 3: cat-a-log takes it, and sends nothing.
    assert owner.receive(proposal) == ("taken", [])
    assert owner.receive(proposal) == ("repeat", []), "a repeat of an open proposal"
    # Step 4: its user takes it: start becomes 11:00 in version 4, and the reply goes.
    made, replies, update = owner.answer("Old Brain Fix", PROPOSAL_ID, "ACCEPTED")
    assert made and len(replies) == 1 and update is not None and update[0] == 4
    assert update[1]["start"] == START_11 and owner.records[REC_ID].version == 4
    assert proposer.receive(replies[0]) == ("taken", []) and proposer.sent[PROPOSAL_ID].status == "ACCEPTED"
    assert proposer.receive(replies[0]) == ("ignored", []), "the first reply stands"
    assert owner.receive(proposal) == ("repeat", replies), "a repeat of an answered proposal: the reply again"
    # Step 5: the update, which Old Brain Fix applies with no kept field.
    got = receiver.message(
        {
            "kind": "DATA",
            "id": REC_ID,
            "version": 4,
            "type": "axt.example.v1.Appointment",
            "value": dict(V3, start="2025-11-18 11:00"),
        }
    )
    assert (got["outcome"], got["receiver_version"], got["kept_fields"]) == ("APPLIED", 4, [])
    proposer.record(REC_ID, "DATA", 4)
    assert not proposer.resend(PROPOSAL_ID)
    return proposal, replies[0], owner, proposer, receiver


def check_proposals(out: list[str]) -> None:
    """Sections 10, 11.3, 11.4 and 11.5."""
    rows = []
    for n, want in (("Proposal", PROPOSAL_PCF), ("ProposalReply", REPLY_PCF)):
        text = pe.texts[n]
        pcf = to_parsing_canonical_form(fastavro.parse_schema(json.loads(text)))
        assert pcf == want, f"the canonical form of axt.{n} is not that of section 10"
        assert avro.schema.parse(pcf).canonical_form == pcf, (
            "the two libraries disagree on the canonical form"
        )
        fp = rules.crc64_avro(pcf.encode())
        assert fp == pe.fingerprints[n][1]
        assert fa_fingerprint(pcf, "CRC-64-AVRO") == pe.fp8(fp).hex() == rules.apache_fingerprint(text).hex()
        out.append(f"axt.{n}: canonical form: {pcf}")
        rows.append(f"| `axt.{n}` | 1 | `0x{fp:016x}` | `{pe.fp8(fp).hex(' ')}` |")
    assert pe.KINDS.index("PROPOSAL") == 15 and pe.KINDS.index("PROPOSAL_REPLY") == 16
    assert pe.CODE["symbols"].index("PROPOSALS_NOT_TAKEN") == 15
    for full in ("axt.Proposal", "axt.ProposalTo", "axt.ProposalField", "axt.ProposalFieldSchema"):
        assert pe.defined_by[full] == "Proposal"
    for full in ("axt.ProposalReply", "axt.ProposalReplyTo", "axt.ProposalReplyAnswer"):
        assert pe.defined_by[full] == "ProposalReply"
    # The enum's default, once in schema resolution, with both libraries (spec/types.md, section 5.4).
    answer = pe.jsons["ProposalReply"]["fields"][2]["type"]
    assert answer["default"] == "DECLINED" and answer["symbols"] == ["ACCEPTED", "DECLINED"]
    rules.DATA["ProposalReply"] = {"to": bytes(pe.OBF), "proposal_id": PROPOSAL_ID, "answer": "ACCEPTED"}
    _, checked = rules.check_defaults("ProposalReply", pe.jsons["ProposalReply"], pe.parsed["ProposalReply"])
    assert checked == 1, "the default of axt.ProposalReplyAnswer is used once"
    out += ["| Schema | Envelope format | CRC-64-AVRO | As bytes |", *rows, ""]
    proposal, reply, _, _, _ = example_proposal()
    p_parts, p_msg = proposal_message(
        pe.OBF_SEED,
        bytes(pe.CAT),
        (REC_ID, 3),
        PROPOSAL_ID,
        [("start", APPOINTMENT_FP, START_VALUE)],
        {"start": pe.datetime_parts("fields[0].value", START_11)},
    )
    assert b"".join(p[0] for p in pe.datetime_parts("v", START_11)) == START_VALUE
    assert p_msg == proposal, "the PROPOSAL of the model is the one built field by field"
    r_parts, r_msg = reply_message(pe.CAT_SEED, bytes(pe.OBF), (REC_ID, 3), PROPOSAL_ID, "ACCEPTED")
    assert r_msg == reply, "the PROPOSAL_REPLY of the model is the one built field by field"
    # Old Brain Fix of spec/protocol.md takes the reply as one to no proposal of its own, and a PROPOSAL
    # as an app that shares no record of its own.
    readers = {"axt.example.v1.Appointment": pe.APPOINTMENT_READER}
    app = pe.App("Old Brain Fix", pe.OBF_SEED, pe.me.OLD_BRAIN_FIX, readers, lambda n: n in readers)
    assert app.receive(pe.m1)[0] == "manifest taken"
    assert app.receive(r_msg) == ("ignored: a reply to no proposal of this app", [])
    # A PROPOSAL fails at the app of spec/protocol.md by the steps 2 to 5 of section 13.3 (it shares no
    # record of its own).
    entries = [("start", APPOINTMENT_FP, START_VALUE)]
    for record, es, code in [
        (("vet", 3), entries, "RECORD_ID_INVALID"),
        ((REC_ID, 0), entries, "VERSION_INVALID"),
        ((REC_ID, 3), [], "INVALID_MESSAGE"),
        ((REC_ID, 3), entries, "PROPOSALS_NOT_TAKEN"),
    ]:
        m = sy.message(pe.CAT_SEED, "PROPOSAL", record, proposal_body(bytes(pe.OBF), PROPOSAL_ID, es))
        assert app.receive(m)[0] == f"rejected {code}", code
    for title, parts, m in (
        ("Section 11.4: the PROPOSAL of step 2", p_parts, p_msg),
        ("Section 11.5: the PROPOSAL_REPLY of step 4", r_parts, r_msg),
    ):
        body: bytes = sy.read_all("Envelope", m[10:])["body"]
        out.append(f"== {title}: {len(m)} bytes, SHA-256 {hashlib.sha256(m).hexdigest()} ==")
        out.append(f"body: {len(body)} bytes")
        out.append(pe.dump(parts))
        out.append(f"signature {m[-64:].hex()}")
    out.append(f"start: {START_VALUE.hex(' ')}, {len(START_VALUE)} bytes; schema {APPOINTMENT_FP.hex(' ')}")


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
    out.append("== Sections 10 and 11.3 to 11.5: proposals ==")
    check_proposals(out)
    return out


def main() -> None:
    for line in check():
        print(line)
    print("all checks passed")


if __name__ == "__main__":
    main()
