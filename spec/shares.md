# Shares between users

Status: written, 0.1.0. Until 0.1.0 is released, [records.md](records.md), [protocol.md](protocol.md) and [sync.md](sync.md) may still change the details this document leaves to them.

This document defines how an app sends the app of another user only the records its own user chose beforehand, and how it takes a record back from that user: the share, which is a rule inside the sending app; what "only predefined records leave" means for a conforming app; the `WITHDRAW` message, with which a sender withdraws one record from one receiver; how a receiver processes it and what it reports; how a withdrawal meets the receiver's own changes, a deletion and a later update; and how a withdrawal travels between the devices of the receiver and of the sender, through a relay and in a file.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 ([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119), [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)) when, and only when, they appear in all capitals, as shown here.

## 1. Terms

- **Share**: a rule of a sending app that names, for one receiver, records of the app's own set that go to that receiver: single records by their id, or the records that a rule of the app chooses, such as every Appointment of one pet.
- **Shared**: a record is shared with a receiver while at least one share for that receiver names it.
- **Sender** of a shared record: the sender of [records.md](records.md), section 1, whose user shares the record: one installation, or the devices of one set. Only a record of the sender's own set can be shared: a device sends no version of a record it received from another app ([sync.md](sync.md), section 22.1).
- **Receiver**: as in [records.md](records.md), section 1, here the app of another user that a share is for. A share is for one receiver, a known sender of [keys.md](keys.md), section 3, with all its current keys; where that receiver is a device set, the share is for the whole set.
- **Withdrawal**: the sender's taking back of one record from one receiver, sent as a `WITHDRAW` message (section 3). A record is **withdrawn from** a receiver from its withdrawal until it is shared with that receiver again (section 6.2).
- **Tombstone of a withdrawal**: what a receiver keeps of a record that its sender withdrew from it: its id and the version of the withdrawal. It is a tombstone of [records.md](records.md), section 1, of a second kind, beside the tombstone of a deletion, and is kept as long as one ([records.md](records.md), section 5.3).

## 2. Shares

### 2.1 A rule inside the sending app

A share is a rule inside the sending app. This specification defines nothing of how a rule looks, how a user makes one, or how an app decides which records a rule names. The receiver sees no share: it gets offers and record messages as from any sender, and a `WITHDRAW` when a record leaves its shares (section 3).

- **Records of the app's own type.** An app keeps its shares as records of a type in its own namespace ([types.md](types.md), section 2), records of its own set like any other. Sibling sync carries every type, also a type of an app's own namespace that no other app knows ([sync.md](sync.md), section 7.2), so every device of the set holds the same shares once it has merged with its siblings, and a new device gets them with every other record ([sync.md](sync.md), section 12.3).
- **The withdrawals beside them.** In the same records, an app keeps for each withdrawal it made the record's id, the receiver and the version of the withdrawal: for each record and receiver the last withdrawal, which is the one with the highest version (section 6.1). Its devices need these to send a withdrawal again and to share a record again (sections 5.3 and 6.2), and they reach every device of the set as the shares do.
- **What stays on one device.** Which messages a device sent to which receiver, and the outcomes it got for them, stay on that device ([sync.md](sync.md), section 17.3).

An app is not bound to records of one type for this: it may keep shares and withdrawals in one type or in several, under names of its choice.

### 2.2 Only predefined records leave

A sender MUST send a receiver only the records that are shared with it:

- It offers a type to a receiver only for records of that type that are shared with that receiver, and for records of that type that are withdrawn from it and whose `WITHDRAW` it still owes (section 5.3). The `count` of each entry of the offer ([protocol.md](protocol.md), section 4.1) counts only the messages of those records, those withdrawals included.
- It sends a `DATA` or a `DELETE` of a record to a receiver only while the record is shared with that receiver, and a `WITHDRAW` only while it is withdrawn from it.
- This holds for every message of a record, the first one, every update, every deletion and every resend (section 5.3), in a live connection, through a relay and in a file (section 8.2).
- **Files.** A file is written for a receiver or for no particular one. A file for no particular receiver, such as an export, holds only the records that the user chose for it: that choice is its share, and the file is treated as going to an app of another user (section 8.2).

A share names records before they go, as its user set it. A user who wants to send one record to another user puts it into a share for that user's app, which a share of a single record allows; an app MUST NOT send a record to such a receiver in any other way, also not one that its user picks at an offer. Messages that carry no record leave as before: the chain, the `MANIFEST`, offers, answers, `ACK` and `ERROR` messages.

Nothing in the protocol can check this. A receiver sees records, not the rules that chose them, and cannot tell a record that a share names from one that its sender sent against its rules. The rule binds the sending app, and an app that conforms to this specification keeps it.

### 2.3 Receivers of other users

The protocol knows apps by their keys, not their users ([keys.md](keys.md), section 3). An app learns from its own user which of the apps it exchanges with are apps of another user, for example when the user accepts a key at a first contact ([keys.md](keys.md), section 3.2).

- Section 2.2 holds for every receiver that the app holds as an app of another user.
- An app MAY send an app of its own user, such as another app on the same phone, records without a share, as [protocol.md](protocol.md) says, with the answer of its user at each offer.
- An app MAY hold every receiver as an app of another user. An app that cannot tell MUST hold a receiver as an app of another user.

The devices of the app's own set are no receivers: they get every record of the set by sibling sync ([sync.md](sync.md), section 7.2), and shares do not apply to them.

## 3. The `WITHDRAW` message

### 3.1 Content

A `WITHDRAW` message tells one receiver that its sender no longer shares one record with it. It is a record message, the third beside `DATA` and `DELETE` ([records.md](records.md), section 1):

| Field       | Content for a `WITHDRAW`                                                                                                         |
| ----------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `format`    | The envelope format, `1` ([envelope.md](envelope.md), section 2.1)                                                               |
| `kind`      | `WITHDRAW`, the symbol with the index 14 of `axt.Kind`                                                                           |
| `sender`    | The key of the device that sends the withdrawal ([keys.md](keys.md), section 2.1)                                                |
| `record`    | REQUIRED: `id` is the id of the record, `version` the version of the withdrawal (section 3.2)                                    |
| `body`      | One `axt.Withdraw` in single-object encoding, with the schema [types/axt/Withdraw.avsc](../types/axt/Withdraw.avsc) (section 10) |
| `signature` | The sender's signature, as for every message ([keys.md](keys.md), section 2.2)                                                   |

- **The addressee.** The body has one field, `to`, a `fixed` of 32 bytes, `axt.WithdrawTo`: the Ed25519 public key of the receiver's device that the withdrawal is sent to, the key to which the sender offers ([protocol.md](protocol.md), section 9.1). The signature covers it, so a `WITHDRAW` is bound to that receiver, as an `ACK` and an `ERROR` are bound to theirs: another app that gets it passed on ignores it (section 4.1).
- **No type.** A `WITHDRAW` names no type: the receiver knows the type of the record by its id ([records.md](records.md), section 5.1).
- **One receiver key.** One `WITHDRAW` serves exactly one receiver key. A device that withdraws one record from several receivers at the same time MAY take one version for all of them, record it for each of them (section 2.1), and send each its own `WITHDRAW` under it, addressed to that receiver. Each is a `WITHDRAW` of the same record under that version, so one id and version still stand for one kind of message ([records.md](records.md), section 3).

### 3.2 The version

The version of a `WITHDRAW` is the version of the withdrawal:

- **A device that stamps** ([sync.md](sync.md), section 2.4) first counts the version of every withdrawal of the record that the app's records hold as a stamp it has seen ([sync.md](sync.md), section 2.2), and then takes a new stamp for the withdrawal, the next stamp of [sync.md](sync.md), section 2.2, and gives it as the version. It is no state stamp: the state of the record and its state stamp stay as they are, and the record's version toward other apps stays its state stamp ([sync.md](sync.md), section 5.1). The device has given the stamp, so it is above every version of the record that the device has given or seen, and every later stamp of the device, its state stamps included, is above it.
- **An installation that counts** ([records.md](records.md), section 3) takes the next count: one above the highest version it has given the record. The count of the withdrawal is a version it has given, so its next version of the record, toward whatever receiver, is above it.
- **No stamp.** A device that can take no stamp ([sync.md](sync.md), section 2.3) sends no `WITHDRAW` (section 9).

No `DATA` or `DELETE` of the record carries that version: the next state stamp, or the next count, is above it. One id and version so stand for one message, as [records.md](records.md), section 3, requires, also though a withdrawal is sent to some receivers and not to others.

The record's state stamp would not do as the version of a withdrawal: the state stamp is the version of every `DATA` and `DELETE` that the device sends to any app ([sync.md](sync.md), section 5.1), so the next record message to another receiver would carry the version of the withdrawal.

### 3.3 Validity

A `WITHDRAW` is valid when it is a valid message ([protocol.md](protocol.md), section 8.2), it carries `record`, and its body is one `axt.Withdraw` in single-object encoding: the two bytes `C3 01`, the fingerprint of `axt.Withdraw` in its envelope format (section 10) and the 32 bytes of `to`, with no bytes left over. A `WITHDRAW` without `record`, and one with any other body, the empty body included, is not valid and is rejected with `INVALID_MESSAGE` ([protocol.md](protocol.md), section 2; [envelope.md](envelope.md), section 2.2). A valid `WITHDRAW` whose `to` is not the receiver's own key is not for it, and is ignored without a report ([protocol.md](protocol.md), section 9.1). Its id and its version are checked as those of every record message, in the steps of section 4.1.

## 4. Processing

### 4.1 The steps

A receiver processes a `WITHDRAW` by the steps of [protocol.md](protocol.md), section 6.2, as it processes a `DELETE`. The steps keep their numbers there, so that a `WITHDRAW` fails where a `DELETE` would. A step that fails ends the processing: the message has no outcome, the receiver changes nothing, and it reports the failure with the error code named ([protocol.md](protocol.md), section 8.3).

| Step | Check                                                                                                                                                                                                                                                                       | If it fails                                                                                                                                                                                                                    |
| ---- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1    | The message and its envelope are valid, and its signature verifies, as for every message ([protocol.md](protocol.md), section 8.2); it carries `record`, its body is one `axt.Withdraw` (section 3.3), and its `to` is the receiver's own key                               | as [protocol.md](protocol.md), section 8.2, says; `INVALID_MESSAGE` for a missing `record` or a body that is not one `axt.Withdraw`; another key in `to` is ignored without a report ([protocol.md](protocol.md), section 9.1) |
| 2    | The id is a UUID in text form, neither the nil UUID nor the max UUID ([records.md](records.md), section 2)                                                                                                                                                                  | `RECORD_ID_INVALID`                                                                                                                                                                                                            |
| 3    | The version is at least 1 ([records.md](records.md), section 3)                                                                                                                                                                                                             | `VERSION_INVALID`                                                                                                                                                                                                              |
| 4    | does not apply: the body is a schema of the specification, checked in step 1, and no offered schema                                                                                                                                                                         | (no failure)                                                                                                                                                                                                                   |
| 5    | For an id that the receiver holds from that sender, as a record or a tombstone: no check. For an id it does not hold: an accepted offer of any type from the same sender in the channel. A `WITHDRAW` from a device of the receiver's own set fails this step in every case | `NOT_ACCEPTED`                                                                                                                                                                                                                 |
| 6    | does not apply: a `WITHDRAW` names no type                                                                                                                                                                                                                                  | (no failure)                                                                                                                                                                                                                   |
| 7    | The version rule ([records.md](records.md), section 5.2): a version equal to the receiver's version has the outcome `DUPLICATE`, one below it `STALE`, and the processing ends with it                                                                                      | (no failure)                                                                                                                                                                                                                   |
| 8, 9 | do not apply                                                                                                                                                                                                                                                                | (no failure)                                                                                                                                                                                                                   |
| 10   | The receiver applies the withdrawal (sections 4.2 and 4.3)                                                                                                                                                                                                                  | (no failure)                                                                                                                                                                                                                   |

- **Before the steps.** A `WITHDRAW` from a key that the receiver's user has not accepted, or signed with a removed key, is kept, dropped or rejected as every message is ([protocol.md](protocol.md), section 8.2).
- **Step 5.** A withdrawal only removes a record that the sender sent before, so the receiver does not check an accepted offer for an id it holds from that sender; the sender still sends the `WITHDRAW` under an accepted offer (sections 2.2 and 8.1). A `WITHDRAW` for an id the receiver does not hold needs an accepted offer of any type from that sender, as a `DELETE` of such an id does ([protocol.md](protocol.md), section 6.2).
- **From a sibling.** A device that gets a `WITHDRAW` from a device of its own set rejects it with `NOT_ACCEPTED` at step 5, as it does a `DELETE` ([sync.md](sync.md), section 7.2): the devices of one set send each other no record messages.
- **The order of step 1.** After the envelope and the signature, the receiver checks first `record`, then the body, then `to`, as [protocol.md](protocol.md), section 8.2, orders the checks. A missing `record` and a body that is not one `axt.Withdraw` are reported with `INVALID_MESSAGE`; a body that decodes with another key in `to` is ignored without a report. A forwarded `WITHDRAW` is checked in the same order, within the checks of the forward ([sync.md](sync.md), section 19.5).
- **In a file**, the steps 4 and 5 do not apply ([protocol.md](protocol.md), section 15.2), the checks of step 1 are taken in the same order, the addressee is checked as section 8.2 says, and nothing is reported.

### 4.2 Applying a withdrawal

A `WITHDRAW` with a version above the receiver's version of the record, or for an id that the receiver does not have from that sender, is applied by this table. Its rows are taken in order, and the first that applies decides: a record that its user deleted is decided by its own row, before the rows of a record that its user changed, since a deletion by the user is a local change too ([records.md](records.md), section 1), as in [sync.md](sync.md), section 22.2. In every row the receiver's version becomes the version of the withdrawal ([records.md](records.md), section 5.2), also where it keeps the record, and the receiver keeps the full name of the type that it held for the id, if it held one.

| The receiver holds of the record, from that sender                                                                             | The receiver                                                                                                                                  | Outcome               |
| ------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------- | --------------------- |
| nothing under this id                                                                                                          | keeps a tombstone of the withdrawal, which holds no type, so that a `DATA` with a lower version that arrives later does not create the record | `WITHDRAWN`           |
| a record that its user deleted ([records.md](records.md), section 6.3)                                                         | keeps a tombstone of the withdrawal; the user's deletion goes on standing beside it                                                           | `WITHDRAWN`           |
| the record, which its user has not changed                                                                                     | removes its copy and keeps a tombstone of the withdrawal                                                                                      | `WITHDRAWN`           |
| the record, which its user has changed ([records.md](records.md), section 6), also one kept against a deletion or a withdrawal | removes it or keeps it, as section 4.3 says                                                                                                   | `WITHDRAWN` or `KEPT` |
| a tombstone of a deletion or of a withdrawal                                                                                   | keeps a tombstone of the withdrawal in its place; the record stays away                                                                       | `WITHDRAWN`           |

A record that its sender withdrew is not there. The receiver shows it as it shows a record that its sender deleted, and MAY tell its user that the sender no longer shares it. A record message with a version equal to that of the tombstone is a duplicate, and one with a lower version is stale; a `DATA` with a higher version shares the record again (section 6.2), and a `DELETE` with a higher version is a deletion (section 6.3).

### 4.3 The receiver's own changes

A withdrawal that meets a record its user has changed is handled as a deletion is in [records.md](records.md), section 6.4. The receiver either removes the record, outcome `WITHDRAWN`, or keeps it with its user's changes, outcome `KEPT`. It MAY ask its user, and reports `KEPT` until the user has decided ([protocol.md](protocol.md), section 7.3). A receiver whose user has not changed the record MUST remove it. A receiver MAY choose for a withdrawal otherwise than for a deletion; the devices of one set choose alike ([sync.md](sync.md), section 22.3).

- **Kept.** A record kept against a withdrawal stays a record of its sender under the same id, with the user's changes: the receiver's version is the version of the withdrawal, and a later `DATA` with a higher version, when the record is shared again, is merged into it as [records.md](records.md), sections 6.1 and 6.2, say. The sender can take the record no further: what the receiver's user changed stays with that user.
- **Removed.** The user's changes go with the record. A record that is shared again later starts without them, as after a deletion ([records.md](records.md), section 9, step 7).
- **No merge.** A withdrawal carries no fields, so it is never merged: `MERGED` is never its outcome.
- **What the receiver keeps.** To keep a record against a withdrawal, the receiver holds the record as it last took it, with its user's changes over it. A receiver that is a device set keeps the `DATA` beside the tombstone of the withdrawal for this, as beside the tombstone of a deletion (section 7.1).

## 5. Outcomes and the acknowledgement

### 5.1 Outcomes

A `WITHDRAW` that a receiver processes to an outcome has one of these:

| Outcome     | The receiver                                                                             |
| ----------- | ---------------------------------------------------------------------------------------- |
| `WITHDRAWN` | removed its copy of the record, or held no copy, and keeps a tombstone of the withdrawal |
| `KEPT`      | keeps the record with its user's changes (section 4.3)                                   |
| `DUPLICATE` | already had this version of the record and changed nothing                               |
| `STALE`     | already had a higher version of the record and changed nothing                           |

`APPLIED` and `MERGED` are never the outcome of a `WITHDRAW`, and `WITHDRAWN` is the outcome of no other message. In a live connection and through a relay, the receiver acknowledges a `WITHDRAW` as every record message, in an `ACK` ([protocol.md](protocol.md), sections 7.1 and 7.2): the entry carries the id and the version of the `WITHDRAW`, the outcome, the receiver's version after the message as `receiver_version`, which differs from the version only for `STALE`, and an empty `kept_fields`. It SHOULD send the `ACK` within 5 seconds of processing the message. A reader of a file reports nothing ([records.md](records.md), section 7).

### 5.2 What the sender does

A device takes the entries of a valid `ACK` as [protocol.md](protocol.md), section 7.4, says. For an entry whose id and version are those of a `WITHDRAW` that it sent to the receiver whose key sent the `ACK`:

| Outcome     | The device                                                                                                                                                                                                                                              |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `WITHDRAWN` | takes the withdrawal as delivered and does not send it again. It MAY show its user that the receiver removed the record                                                                                                                                 |
| `KEPT`      | takes the withdrawal as delivered and does not send it again: the receiver keeps the record with its user's changes. It MAY show its user so. A later `WITHDRAWN` for the same id and version replaces `KEPT` ([protocol.md](protocol.md), section 7.3) |
| `DUPLICATE` | takes the withdrawal as delivered; every other outcome for the same id and version replaces it ([protocol.md](protocol.md), section 7.4)                                                                                                                |
| `STALE`     | counts `receiver_version` as a stamp it has seen and acts as section 5.3 says                                                                                                                                                                           |

- **An outcome that does not fit the kind.** A device that gets `APPLIED` or `MERGED` for the id and version of a `WITHDRAW` it sent, or `WITHDRAWN` for the id and version of a `DATA` or a `DELETE` it sent, takes it as `DUPLICATE`: the message is delivered, and nothing else follows from it. It MAY log it.

### 5.3 What a device owes a receiver

For each record and each receiver, a device owes the receiver one message, by the shares and the withdrawals that it holds (section 2.1):

| The record, for that receiver                                                            | The device owes it                                                                                                                                                                                                                                                                                                        |
| ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| is shared with it                                                                        | the record message of [sync.md](sync.md), section 5.1: a `DATA` under its state stamp of the record, or a `DELETE` when the record is deleted                                                                                                                                                                             |
| is withdrawn from it                                                                     | the `WITHDRAW` of the last withdrawal of the record from that receiver, under the version that the app's records hold for it                                                                                                                                                                                              |
| is not shared with it, and the app's records hold no withdrawal of it from that receiver | nothing: the record was never shared there, or it left the shares without a withdrawal (section 6.1), or the record of its withdrawal has not reached the device yet (section 7.2). But a device whose last record message of the record to that receiver was a `DATA` takes a new withdrawal (section 6.1) and owes that |

Wherever [records.md](records.md), [protocol.md](protocol.md) and [sync.md](sync.md) have a device send a receiver a record again, or the record's current state, the device sends what it owes that receiver, signed with its own key and, for a `WITHDRAW`, addressed to the receiver's key that it sends to: after `STALE` with a higher version ([records.md](records.md), section 7; [sync.md](sync.md), section 5.3), for a resend ([protocol.md](protocol.md), section 11), and after a removal at the receiver ([protocol.md](protocol.md), section 7.4). Toward a receiver from which the record is withdrawn, two rules differ:

- **The highest version it knows.** For the comparison of [sync.md](sync.md), section 5.3, after `STALE` for a `WITHDRAW`, the highest version the device knows of the record is the version of the last withdrawal of the record from that receiver that the app's records hold; its state stamps do not count, since a `DATA` of a sibling under a higher state stamp may be what the receiver holds. After `STALE` for a `DATA` or a `DELETE`, it is the highest of its state stamp of the record, the highest state stamp of the record that it saw from a sibling, and the version of that last withdrawal. A `DATA` sent before the withdrawal that arrives after it is so answered with `STALE` and the version of the withdrawal, and nothing more needs to be done; a `WITHDRAW` answered with `STALE` and a version above its own leads to a new withdrawal, as below.
- **The version to pass.** The version to pass of [sync.md](sync.md), section 5.3, is compared with, and dropped only by, the version of the last recorded withdrawal of the record from that receiver; the device's state stamp of the record does not drop it. While that version is still below the version to pass, after the wait of [sync.md](sync.md), section 5.3, the device takes a new withdrawal above it.
- **The wait.** Before it takes a new withdrawal after `STALE`, the device waits, beyond what [sync.md](sync.md), section 5.3, says, until it has merged the app's share records with every other current device of its set, as [sync.md](sync.md), section 10.4, says of merging a record, and at most the 14 days of that section. So a sibling that has not yet learned that the record is shared again does not withdraw it.
- **A new withdrawal.** Where [sync.md](sync.md), section 5.3, has the device take a new state stamp and send the record's current state under it, the device takes a new stamp for a new withdrawal instead (section 3.2), records its version as that of the last withdrawal of the record from that receiver (section 2.1), and sends the `WITHDRAW` under it. The new version is above the receiver's version, since the device has seen that version, so the recorded version is now above the version to pass, and the device drops it. If the record is shared with that receiver again by the end of the wait, the device sends what it then owes, as [sync.md](sync.md), section 5.3, says.

A resend without an acknowledgement ([protocol.md](protocol.md), section 11) sends the same `WITHDRAW` again, under the same version. A resend to another key of the receiver, after the key it was sent to was removed ([protocol.md](protocol.md), section 7.4), is a new `WITHDRAW` under the same version, addressed to the new key.

## 6. A record leaves a share, and comes back

### 6.1 Withdrawing

A record leaves the shares for a receiver when it is no longer shared with that receiver: its user takes it out of a share, changes a rule so that the rule no longer names it, or ends a share (section 6.4), or the record changes so that a rule no longer chooses it, such as when its user removes the tag by which a rule chose it.

When a record that was shared with a receiver leaves the shares for that receiver, the app MUST withdraw it from that receiver:

- **The device of the change.** The device on which the change is made that takes the record out of the shares, by its user or by a change of the record on it, takes the version of the withdrawal (section 3.2), records the withdrawal in the app's records (section 2.1) and sends the `WITHDRAW`. A sibling that gets that change by sibling sync takes no version of its own for it: it owes the receiver the recorded withdrawal (section 5.3).
- **When.** The device sends the `WITHDRAW` as soon as it has a channel to the receiver and an accepted offer of the record's type there, as for every record message (section 8.1).
- **A record that was deleted.** The app need not withdraw a record whose last message to that receiver was a `DELETE`. It MAY: a receiver that kept the record against the deletion then decides anew (section 6.3).
- **A record that never reached the receiver.** The app MAY withdraw a record that it does not know to have reached the receiver, since a device cannot know what its siblings sent: the receiver keeps a tombstone of an id it does not have (section 4.2), and so learns that id (section 9). A record of a type that the receiver declined has not reached it, and its withdrawal waits like every record message of that type ([protocol.md](protocol.md), section 5.3).
- **A device that sent the record later.** A device whose last record message of a record to a receiver is a `DATA`, whether it holds an outcome for it or not, whose version is above every withdrawal of that record from that receiver that the app's records hold, or for which the app's records hold none, and that then holds shares under which the record is not shared with that receiver, MUST withdraw the record from that receiver itself, as the device of the change does. This is the case of a sibling that sent the record before the change of the shares reached it by sibling sync (section 7.2): the recorded withdrawal has a lower version than its `DATA` and would be answered with `STALE`.

### 6.2 Sharing again

A record is shared with a receiver again when a share for that receiver names it again. A device that sends it there:

1. counts the version of every withdrawal of the record that the app's records hold, for every receiver, as a stamp it has seen ([sync.md](sync.md), section 2.2), as section 3.2 does;
2. takes a new state stamp of the record ([sync.md](sync.md), section 3.3, occasion 8), also when the record has not changed since the withdrawal; an installation that counts takes the next count;
3. sends the record message it now owes the receiver (section 5.3) under that version: a `DATA`, or a `DELETE` for a record that was deleted in between.

The new version is above the version of the withdrawal, so the receiver applies it by the version rule. A `DATA` over a tombstone of a withdrawal brings the record back as over a tombstone of a deletion ([records.md](records.md), section 5.3): the receiver takes it as a new record under the same id, and the tombstone ends. A `DATA` that reaches a record kept against the withdrawal is merged into it (section 4.3). The new state stamp is the record's version toward every app, as every state stamp is; another receiver that gets it later applies it by the version rule.

### 6.3 A `DELETE` after a `WITHDRAW`, and a `WITHDRAW` after a `DELETE`

Each is a record message of the same record, and the version rule decides between them ([records.md](records.md), section 5.2): as long as the receiver's user changes nothing, a receiver that has got any set of messages about a record ends in the state of the one with the highest version, whatever the order of their arrival.

- **A `DELETE` after a `WITHDRAW`.** A sender sends a receiver no `DELETE` of a record that is withdrawn from it (section 2.2). A receiver can still get one: a `DELETE` sent before the withdrawal that arrives after it, which has a lower version and is `STALE`, or one with a higher version after the record was shared again, or from a sibling of the sender that did not know of the withdrawal. A `DELETE` with a higher version is a deletion: over a tombstone of a withdrawal, the receiver keeps a tombstone of the deletion in its place, with the outcome `APPLIED`; over a record kept against the withdrawal, it deletes or keeps it as [records.md](records.md), section 6.4, says.
- **A `WITHDRAW` after a `DELETE`.** A `WITHDRAW` with a higher version over a tombstone of a deletion leaves a tombstone of the withdrawal in its place, with the outcome `WITHDRAWN` (section 4.2); over a record kept against the deletion, it removes or keeps it as section 4.3 says.
- **One version, two kinds.** One id and version stand for one message ([records.md](records.md), section 3). A `WITHDRAW` and a `DATA` or a `DELETE` with the same version come only from a faulty sender or from two stamps of two devices that happen to be equal ([sync.md](sync.md), section 2.2). A receiver applies the first that arrives by the version rule and reports the second as `DUPLICATE`. A device that keeps the messages of its senders for its siblings keeps the `WITHDRAW` ([sync.md](sync.md), section 20.1). Where the `WITHDRAW` arrives second and takes the place of a `DATA` of the same version, that device keeps the `DATA` beside the tombstone of the withdrawal, and the answering device decides on the owner's changes as for a `WITHDRAW` with a higher version ([sync.md](sync.md), sections 19.5, step 7, case 5, and 22.2), so that a record that its user changed can be kept; the outcome toward the sender stays `DUPLICATE`.

### 6.4 Ending a share

When a share for a receiver ends, every record that it named and that no other share for that receiver names leaves the shares for that receiver, and the app withdraws each of them from it as section 6.1 says, in one `WITHDRAW` for each record. A device cannot know what its siblings sent, so it MAY withdraw records that no device of its set ever sent to that receiver (section 6.1); the receiver then learns the ids and the number of those records (section 9). The receiver gets these withdrawals as ordinary messages and learns nothing of the share. Ending a share forgets no key: the two apps stay known to each other ([keys.md](keys.md), section 3.4), and a receiver for which the app holds no share any more gets no further records (section 2.2).

## 7. Between devices

### 7.1 The receiver's devices

A receiver can be a device set. The device that gets the `WITHDRAW` from its sender is the answering device ([sync.md](sync.md), section 17.1): it processes the message by section 4, reports the outcome, keeps the `WITHDRAW` as the kept message of the record and forwards it to its siblings like a `DATA` or a `DELETE` ([sync.md](sync.md), sections 19.6 and 20). The sender's layer of the record then ends in a `WITHDRAW` ([sync.md](sync.md), section 17.1), which sections 17 to 24 of [sync.md](sync.md) treat as a layer that ends in a `DELETE`, with the version of the `WITHDRAW` and its tombstone, with these differences:

- **The outcome.** Where [sync.md](sync.md), section 22.2, gives the answering device the outcome `APPLIED` for a `DELETE`, it gives `WITHDRAWN` for a `WITHDRAW`; `KEPT` stays `KEPT`. The further `ACK` of [sync.md](sync.md), section 22.3, for a `WITHDRAW` reported as `KEPT` carries `WITHDRAWN`.
- **The `DATA` beside the tombstone.** A device keeps beside the tombstone of a withdrawal the `DATA` with the highest version below it that it took, as beside the tombstone of a deletion ([sync.md](sync.md), section 20.1): when the layer ended in a `DATA`, that `DATA`; when it ended in a `DELETE` or a `WITHDRAW`, the `DATA` beside that tombstone. Where a `WITHDRAW` takes the place of a `DATA` with the same version, that `DATA` stays beside it (section 6.3). A `DELETE` after a `WITHDRAW` keeps it beside its tombstone likewise. So the owner can keep a withdrawn record with its changes over that `DATA` ([sync.md](sync.md), section 22.1, rule 3a).
- **The keep.** A keep against a withdrawal has the version of the `WITHDRAW` ([sync.md](sync.md), section 21.2). A `DELETE` or a `WITHDRAW` with a higher version is not covered by it ([sync.md](sync.md), section 22.1), and the answering device decides on it anew.
- **One version in two forms.** Of a `WITHDRAW` and a `DATA` or a `DELETE` with the same version, the `WITHDRAW` stands; of two `WITHDRAW` messages with the same version, the one whose SHA-256 is the higher ([sync.md](sync.md), sections 19.5 and 20.1).
- **A forwarded `WITHDRAW`** is processed by [sync.md](sync.md), section 19.5, as a forwarded `DELETE`, and its `FORWARD` carries no schema ([sync.md](sync.md), section 18.2). Its body is one `axt.Withdraw`, and its `to` names the answering device, not the sibling: a sibling takes it only if `to` is a current or a removed key of its own set, its own key, a sibling's or that of a device removed since, and rejects the forward with `INVALID_MESSAGE` otherwise ([sync.md](sync.md), section 19.5). A removed key counts, so that a device that joins after the answering device was removed, or that gets the kept message again after a `RESYNC`, still takes the withdrawal. A `WITHDRAW` that a device gets directly from the sender needs its own current key in `to` (section 4.1). The checks of a forwarded `WITHDRAW` are taken in the order of section 4.1: `record`, the body, `to`. One signed with a removed key of its sender gets the check of a forwarded `DATA` or `DELETE` ([sync.md](sync.md), section 19.2). The outcome of the forward is `APPLIED` or `DUPLICATE` ([sync.md](sync.md), section 18.4), and the device sends the record's sender nothing.

### 7.2 The sender's devices

Between the devices of the sender there is nothing to send but the app's own records. A `WITHDRAW` is a message to another app: a device MUST NOT send one to a sibling, and a sibling that gets one rejects it (section 4.1). The shares and the recorded withdrawals travel between the devices as records of the app's own type, in `CHANGE` messages like every record of the set (section 2.1).

- Each device sends a receiver what it owes it (section 5.3), for each id and version of which it holds no outcome of that receiver itself ([sync.md](sync.md), section 17.3). Several devices can so send the same withdrawal: each sends its own `WITHDRAW`, addressed to the receiver's key it sends to and signed with its own key, under the recorded version; the receiver takes the first and reports the others as `DUPLICATE`.
- Until sibling sync has brought a change of the shares to a device, that device holds the shares as they were. It may send a receiver a record that is no longer shared with it, or not send one that is shared again. Once the change reaches it, it acts as sections 6.1 and 6.2 say, and the receiver comes to the state that the shares give.

### 7.3 Two receivers that join

Two receivers that a sender knows apart can turn out to be one device set, when the sender applies an addition that joins them ([keys.md](keys.md), section 5.5). The sender then holds one receiver, and:

- **The shares** of the joined receiver are the union of the shares of the two: a record that was shared with either is shared with it.
- **A withdrawal** recorded for one of the two is no longer owed for a record that is shared with the joined receiver. The sender sends that record's current state to the joined receiver under a new state stamp ([sync.md](sync.md), section 3.3, occasion 8), after it has counted the recorded withdrawals as stamps it has seen (section 6.2), so that the new version is above the withdrawal there.
- **A record withdrawn from both**, or withdrawn from one and never shared with the other, stays withdrawn from the joined receiver. Its last withdrawal is the recorded one with the higher version.

## 8. Transports

### 8.1 Live connection and relay

A `WITHDRAW` travels as a `DELETE` does ([protocol.md](protocol.md), section 6.1): under an accepted offer of the record's type in the channel, and, where the receiver keeps no type for the id, under an accepted offer of any type. Through a relay, an accepted offer covers the record messages that were due when the sender made it ([protocol.md](protocol.md), section 4.3), so a withdrawal takes the three trips of an offer, its answer and the `WITHDRAW`, unless an offer that covers it is already accepted; the `count` of the offer counts it. A receiver that has stored its user's answer for the type answers at once ([protocol.md](protocol.md), section 5.2). The receiver does not check that offer for an id it holds from that sender (section 4.1); the sender sends the `WITHDRAW` under it all the same, and offers the type for it (section 2.2).

A `WITHDRAW` is sealed, padded, repeated and sent again as every record message ([protocol.md](protocol.md), sections 9.2, 11 and 15.1). A repeat has the outcome `DUPLICATE`. Where the receiver no longer takes the type ([manifest.md](manifest.md), section 6), the sender cannot offer it and the withdrawal waits until the type is accepted again; the receiver then keeps the record, as it keeps every record of a type it no longer takes.

### 8.2 File

A file MAY hold a `WITHDRAW` among its record messages ([transports.md](transports.md), section 2.1). A reader applies it by section 4, without the steps 4 and 5 ([protocol.md](protocol.md), section 15.2), and reports nothing.

- **Only for its receiver.** A writer puts a `WITHDRAW` only into a file meant for the receiver from which it withdraws the record, with that receiver's key in `to`. A reader applies it only if `to` is a current or a removed key of its own set, as for a forwarded `WITHDRAW` (section 7.1), since any device of the receiver's set may read the file; a reader of another app does not apply it and does not reject the file for it.
- **What a file for a receiver holds.** A file that a device writes for an app of another user holds what the device owes that receiver (section 5.3), one message for each record ([transports.md](transports.md), section 2.3): a `DATA` or a `DELETE` of each record that is shared with it, and a `WITHDRAW` of each that is withdrawn from it. It holds no other record.
- **A file for no particular receiver**, such as an export, holds only the records that its user chose for it: that choice is the file's share, and the file is treated as going to an app of another user (section 2.2). It holds no `WITHDRAW`, since it has no receiver's key to put in `to`.
- **Not valid.** A `WITHDRAW` in a file without `record`, or with a body that is not one `axt.Withdraw`, is a datum that is not a valid message of its kind, and the reader rejects the whole file ([transports.md](transports.md), section 2.2), as it does for such a `DELETE`.
- **The fit of the type.** A `WITHDRAW` names the schema of no record, so the rule of [manifest.md](manifest.md), section 7, that a reader applies no record whose type does not fit its manifest, does not hold it back: the reader applies it to what it holds under that id from that sender, whatever the type.
- **A file of the reader's own set.** A device that reads a file of its own set does not apply a `WITHDRAW` in it ([sync.md](sync.md), section 13.4): the withdrawal is a message to another app.
- **A receiver that is a device set** forwards the `WITHDRAW` it read in a file to its siblings, as every record message of a file of another app ([sync.md](sync.md), section 24.2).

## 9. Limits

| What                                                  | Limit                                                                                              |
| ----------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| The body of a `WITHDRAW`                              | One `axt.Withdraw`: the single-object header and the 32 bytes of `to`                              |
| One `WITHDRAW`, a live message                        | The envelope with `record` and that body, far below 16 MiB ([envelope.md](envelope.md), section 8) |
| Entries of one `ACK`                                  | 4,096 ([protocol.md](protocol.md), section 7.1)                                                    |
| The `ACK` after processing a `WITHDRAW`               | Within 5 seconds (section 5.1)                                                                     |
| A resend of a `WITHDRAW` through a relay              | After the holding time of 14 days, not before ([protocol.md](protocol.md), section 11)             |
| How long a receiver keeps a tombstone of a withdrawal | As long as it keeps the sender ([records.md](records.md), section 5.3)                             |
| Withdrawals when a share ends                         | One `WITHDRAW` for each record that leaves the shares for that receiver (section 6.4)              |

What a withdrawal cannot do:

- **It is a request.** A receiver that conforms to this specification removes its copy, or keeps it with its user's changes (section 4.3). A withdrawal does not reach what the receiver's user saw, copied into a record of their own ([records.md](records.md), section 1) or passed on outside AXT, and an app that does not conform can keep every record it got.
- **It is bound to its receiver.** A `WITHDRAW` names in `to` the receiver's key it is sent to, and the signature covers it ([keys.md](keys.md), section 2.6). Another app that gets it passed on, through its relay mailbox or in a file, ignores it (section 4.1), so no one can make a third app remove a record that its sender still shares with it. Within the receiver's set it travels on as intended, in a `FORWARD` and in a file the set reads (sections 7.1 and 8.2).
- **It can tell ids.** A withdrawal of a record that never reached the receiver tells the receiver its id, and the withdrawals at the end of a share tell it how many records the share named (sections 6.1 and 6.4).
- **It needs a stamp.** A device that can take no stamp ([sync.md](sync.md), section 2.3) cannot withdraw a record. Only a device of the owner's own set can bring it there.
- **It needs an accepted type.** A receiver that no longer takes the type of a record, or declined it, gets no withdrawal of it until it takes the type again (section 8.1).
- **It needs sibling sync.** A device to which a change of the shares has not yet come acts on the shares it holds (section 7.2).
- **An answer that does not come.** Where the receiver asks its user and its answering device is removed before the user has decided, no further `ACK` comes, and the sender keeps `KEPT` ([sync.md](sync.md), section 22.3).

## 10. Schema and fingerprint

The schema of the body of a `WITHDRAW` is [types/axt/Withdraw.avsc](../types/axt/Withdraw.avsc). It follows the rules that [types.md](types.md), section 5, sets for every example type, where they apply to a schema of the specification, as [manifest.md](manifest.md), section 9, says of the manifest: its nested type is defined in place, with a name that begins with the schema's name, and it carries no `axt.version`, since it changes only with the envelope format. Its one field is `to`.

Its Parsing Canonical Form:

```json
{"name":"axt.Withdraw","type":"record","fields":[{"name":"to","type":{"name":"axt.WithdrawTo","type":"fixed","size":32}}]}
```

| Schema         | Envelope format | CRC-64-AVRO          | As bytes                  |
| -------------- | --------------- | -------------------- | ------------------------- |
| `axt.Withdraw` | 1               | `0xe355f51523a97dd5` | `d5 7d a9 23 15 f5 55 e3` |

The kind is the symbol `WITHDRAW`, with the index 14, of `axt.Kind` in [types/axt/Envelope.avsc](../types/axt/Envelope.avsc), whose canonical form and fingerprint are in [envelope.md](envelope.md), section 10.1. Its outcome `WITHDRAWN` is the symbol with the index 5 of `axt.AckOutcome` in [types/axt/Ack.avsc](../types/axt/Ack.avsc), whose canonical form and fingerprint are in [protocol.md](protocol.md), section 16. Neither of these two schemas changes with this document. The test vectors of [conformance.md](conformance.md) take precedence over the values of this section and of section 11.

## 11. Example

### 11.1 A share and its withdrawal

The appointment of [records.md](records.md), section 9, an `axt.example.v1.Appointment` with the id `3f2c8a5e-9b1d-4c7e-8a6f-2d4b5c6e7f80`, as it stands after step 3 there: version 3, with `title` "Vet", `start` 2025-11-18 10:30, `location` "" and `notes` "Bring the vaccination card". From here on its user does not cancel it, so the steps 6 and 7 there do not happen. The sender is one installation that counts its versions ([records.md](records.md), section 3) and signs with the test key `cat-a-log, old phone, Ed25519` of [keys.md](keys.md), section 7.1. Its user shares the appointment with a second user, whose app is the receiver here, one installation that signs with the test key `Old Brain Fix, Ed25519` of [protocol.md](protocol.md), section 17.1; every `WITHDRAW` carries that key in `to`. The receiver lets its user change received records, merges per field and keeps a record that its user changed against a withdrawal (section 4.3). What the sender sends the receiver of [records.md](records.md), section 9, is not shown. Every message's `record` carries the id above and the version in the table.

| Step | What happens                                                                                                                                                                | Message, `record.version` | Receiver's version before      | Outcome                                       | Receiver's version after       |
| ---- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------- | ------------------------------ | --------------------------------------------- | ------------------------------ |
| 1    | The sender's user puts the appointment into a share for the second user's app. The sender offers `Appointment` there, the receiver accepts, and the sender sends the record | `DATA`, 3                 | none                           | `APPLIED`                                     | 3                              |
| 2    | The sender's user takes the appointment out of the share                                                                                                                    | `WITHDRAW`, 4             | 3                              | `WITHDRAWN`                                   | 4, tombstone of the withdrawal |
| 3    | The relay delivers the message of step 1 a second time                                                                                                                      | `DATA`, 3                 | 4, tombstone of the withdrawal | `STALE`                                       | 4, tombstone of the withdrawal |
| 4    | The sender's user puts the appointment into the share again. It has not changed since version 3                                                                             | `DATA`, 5                 | 4, tombstone of the withdrawal | `APPLIED`                                     | 5                              |
| 5    | The receiver's user sets `location` to "Dr. Weber, Hauptstr. 5"                                                                                                             | none                      | 5                              | none                                          | 5                              |
| 6    | The sender's user ends the share                                                                                                                                            | `WITHDRAW`, 6             | 5                              | `KEPT`                                        | 6                              |
| 7    | The sender's user moves `start` to 11:00 (version 7)                                                                                                                        | none: no longer shared    | 6                              | none                                          | 6                              |
| 8    | The receiver's user gives up the kept appointment                                                                                                                           | none                      | 6                              | `WITHDRAWN`, in a further `ACK` for version 6 | 6, tombstone of the withdrawal |

- **Step 1.** The receiver sees an ordinary offer of one Appointment and an ordinary `DATA`; it does not see the share. The record had version 3 already, so no new version is needed: the receiver holds none.
- **Step 2.** The highest version the sender has given the record is 3, so the withdrawal takes the next count, 4. The receiver's user has changed nothing, so the receiver MUST remove the record. Its `ACK` carries the id, the version 4, `WITHDRAWN`, the `receiver_version` 4 and no kept field. The sender records the withdrawal from the second user's app with the version 4 (section 2.1).
- **Step 3.** The `ACK` reports `STALE` with the `receiver_version` 4. The record is withdrawn from that receiver, so the highest version the sender knows of it there is 4, the version of its own withdrawal (section 5.3). 4 is not above it, and nothing more is done.
- **Step 4.** The record is shared again. The sender has given the version 4 last, so the next count is 5, also though the record is the same as in version 3 (section 6.2). The receiver takes the record anew over the tombstone, as it would after a deletion, and the tombstone ends.
- **Step 6.** The share named only this record, so the appointment leaves the shares for that receiver, and the withdrawal takes the next count, 6. The receiver's user has changed `location`, and this receiver keeps such a record. Its `ACK` carries the id, the version 6, `KEPT`, the `receiver_version` 6 and no kept field. The receiver goes on showing the appointment of version 5 with its user's `location`. A receiver whose user had changed nothing would report `WITHDRAWN`.
- **Step 7.** The record is not shared with the second user's app, so nothing goes there. Version 7 reaches only the receivers with which the record is still shared.
- **Step 8.** The user's decision is taken later ([protocol.md](protocol.md), section 7.3): the receiver removes the record, keeps a tombstone of the withdrawal with the version 6, and sends a further `ACK` with the id, the version 6, `WITHDRAWN` and the `receiver_version` 6. The sender takes `WITHDRAWN` over the `KEPT` it holds for that id and version.

Had the receiver run on two devices, the device that got each message would have forwarded it to the other, which would have taken it into its sender's layer, and the owner's `location` and the keep of step 6 would have travelled in a `CHANGE` with the sender's key in `origin` ([sync.md](sync.md), sections 21 and 22). A sender that stamps would have given stamps in the place of the counts 4 to 7, in the same order.

### 11.2 The `WITHDRAW` of step 2

The `WITHDRAW` of step 2 is a live message in envelope format 1 ([envelope.md](envelope.md), section 3):

| Field            | Value                                                                                                                                                                                                                                                                       |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `format`         | 1                                                                                                                                                                                                                                                                           |
| `kind`           | `WITHDRAW`, enum index 14                                                                                                                                                                                                                                                   |
| `sender`         | The public key of `cat-a-log, old phone, Ed25519` ([keys.md](keys.md), section 7.1)                                                                                                                                                                                         |
| `record`         | Union index 1, `axt.RecordRef`                                                                                                                                                                                                                                              |
| `record.id`      | `"3f2c8a5e-9b1d-4c7e-8a6f-2d4b5c6e7f80"`                                                                                                                                                                                                                                    |
| `record.version` | 4                                                                                                                                                                                                                                                                           |
| `body`           | One `axt.Withdraw` in single-object encoding: `C3 01`, the fingerprint of `axt.Withdraw`, format 1 (`d5 7d a9 23 15 f5 55 e3`), and `to`, the public key of `Old Brain Fix, Ed25519` ([protocol.md](protocol.md), section 17.1), the second user's app here; body length 42 |
| `signature`      | `a99a943361bb465ebc1d2cb554a627ef4eb7787c8a4172218c059e3d5bef0491afad0c3300026421a9c537fbd39aa0544a9a23c1fcb5fd61ac7818fa03980e05`                                                                                                                                          |

The message: 190 bytes, SHA-256 `765153c089b88b370dac48a9baca7abf51d68eea46f496dac348ac0c330b7d6f`. The signature covers the prefix `AXT-v1 message` and its zero byte, and the bytes from offset `000a` to the signature ([keys.md](keys.md), section 2.2).

```text
0000  c3 01                    single-object marker
0002  16 30 6f 71 b9 ce 9e a8  fingerprint of axt.Envelope, format 1
000a  02                       format: int 1
000b  1c                       kind: enum index 14, WITHDRAW
000c  1b 84 a6 00 f3 50 3e 22  sender: fixed(32), cat-a-log's test key
      bb cc 99 e6 32 02 a7 19
      4b f6 bd 69 af f1 47 1c
      ce 64 10 d5 3c 26 ec 4a
002c  02                       record: union index 1, axt.RecordRef
002d  48                       record.id: string length 36
002e  33 66 32 63 38 61 35 65  "3f2c8a5e-9b1d-4c7e-8a6f-2d4b5c6e7f80"
      2d 39 62 31 64 2d 34 63
      37 65 2d 38 61 36 66 2d
      32 64 34 62 35 63 36 65
      37 66 38 30
0052  08                       record.version: long 4
0053  54                       body: bytes length 42
0054  c3 01                    body: single-object marker
0056  d5 7d a9 23 15 f5 55 e3  body: fingerprint of axt.Withdraw, format 1
005e  da 9e 54 c9 aa 2d b4 32  body: to: fixed(32), Old Brain Fix's test key
      44 df 99 88 9d 91 38 c1
      ca 71 75 d4 ca 09 08 16
      8f 63 53 0e 4a 7d ed b7
007e  a9 9a 94 33 61 bb 46 5e  signature: fixed(64)
      bc 1d 2c b5 54 a6 27 ef
      4e b7 78 7c 8a 41 72 21
      8c 05 9e 3d 5b ef 04 91
      af ad 0c 33 00 02 64 21
      a9 c5 37 fb d3 9a a0 54
      4a 9a 23 c1 fc b5 fd 61
      ac 78 18 fa 03 98 0e 05
00be  end
```

## References

- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174): key words for requirement levels
