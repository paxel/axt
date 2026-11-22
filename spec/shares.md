# Shares between users

Status: released in 0.1.0, changed in 0.2.0. A change to this document is a new version of AXT, with its entry in [CHANGELOG.md](../CHANGELOG.md).

This document defines how an app sends the app of another user only the records its own user chose beforehand, how it takes a record back from that user, and how that user suggests a change of a record that it got: the share, which is a rule inside the sending app; what "only predefined records leave" means for a conforming app; the `WITHDRAW` message, with which a sender withdraws one record from one receiver; how a receiver processes it and what it reports; how a withdrawal meets the receiver's own changes, a deletion and a later update; how a withdrawal travels between the devices of the receiver and of the sender, through a relay and in a file; and the `PROPOSAL` and `PROPOSAL_REPLY` messages, with which a receiver proposes changed values of a record to its sender and the sender's user takes or refuses them, with what each side does and how a proposal travels between the devices of either side.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 ([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119), [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)) when, and only when, they appear in all capitals, as shown here.

## 1. Terms

- **Share**: a rule of a sending app that names, for one receiver, records of the app's own set that go to that receiver: single records by their id, or the records that a rule of the app chooses, such as every Appointment of one pet.
- **Shared**: a record is shared with a receiver while at least one share for that receiver names it.
- **Sender** of a shared record: the sender of [records.md](records.md), section 1, whose user shares the record: one installation, or the devices of one set. Only a record of the sender's own set can be shared: a device sends no version of a record it received from another app ([sync.md](sync.md), section 22.1).
- **Receiver**: as in [records.md](records.md), section 1, here the app of another user that a share is for. A share is for one receiver, a known sender of [keys.md](keys.md), section 3, with all its current keys; where that receiver is a device set, the share is for the whole set.
- **Withdrawal**: the sender's taking back of one record from one receiver, sent as a `WITHDRAW` message (section 3). A record is **withdrawn from** a receiver from its withdrawal until it is shared with that receiver again (section 6.2).
- **Tombstone of a withdrawal**: what a receiver keeps of a record that its sender withdrew from it: its id and the version of the withdrawal. It is a tombstone of [records.md](records.md), section 1, of a second kind, beside the tombstone of a deletion, and is kept as long as one ([records.md](records.md), section 5.3).
- **Proposal**: a suggestion of a receiver to the sender of a shared record to change the values of some of the record's fields, sent as a `PROPOSAL` message (section 13). A proposal changes nothing by itself: only the sender's user can take it, and then the sender changes the record (section 15).
- **Proposer**: the receiver that sends a proposal: one installation, or the devices of one set, of which the device on which its user proposes sends the proposal (section 17.2).
- **Owner of the record**, or **owner**, in sections 12 to 18: the sender of the record that a proposal is about, with its user and its devices. It is not the owner of [sync.md](sync.md), section 21: on the proposer's devices, the owner's layer of that section holds what the proposer's user did with the received record (section 17.2).
- **Reply** to a proposal: a `PROPOSAL_REPLY` message (section 14), in which a device of the owner tells the proposer whether the owner's user took the proposal. It is a reply of [protocol.md](protocol.md), section 1: it is about a message of the app it goes to.
- **Open proposal**: a proposal that a device of the owner has taken (section 13.3) and holds (section 17.1), and to which the owner's app holds no answer (section 15.1).

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

A share names records before they go, as its user set it. A user who wants to send one record to another user puts it into a share for that user's app, which a share of a single record allows; an app MUST NOT send a record to such a receiver in any other way, also not one that its user picks at an offer. Messages that carry no record leave as before: the chain, the `MANIFEST`, offers, answers, `ACK` and `ERROR` messages, and the replies to proposals (section 14).

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

The schemas of the bodies of a `PROPOSAL` and a `PROPOSAL_REPLY` are [types/axt/Proposal.avsc](../types/axt/Proposal.avsc) and [types/axt/ProposalReply.avsc](../types/axt/ProposalReply.avsc). They follow the same rules: their nested types are defined in place, with names that begin with the schema's name, and neither carries `axt.version`. The first field of each is `to`. The enum `axt.ProposalReplyAnswer` has the default symbol `DECLINED`, as [types.md](types.md), section 5.4, requires; within one envelope format every symbol is known, and the default, the answer with which the proposer changes nothing (section 14.2), only takes effect in schema resolution with a schema of another format, as [protocol.md](protocol.md), section 16, says of the enums there.

Their Parsing Canonical Forms:

```json
{"name":"axt.Proposal","type":"record","fields":[{"name":"to","type":{"name":"axt.ProposalTo","type":"fixed","size":32}},{"name":"proposal_id","type":"string"},{"name":"fields","type":{"type":"array","items":{"name":"axt.ProposalField","type":"record","fields":[{"name":"name","type":"string"},{"name":"schema","type":{"name":"axt.ProposalFieldSchema","type":"fixed","size":8}},{"name":"value","type":"bytes"}]}}}]}
```

```json
{"name":"axt.ProposalReply","type":"record","fields":[{"name":"to","type":{"name":"axt.ProposalReplyTo","type":"fixed","size":32}},{"name":"proposal_id","type":"string"},{"name":"answer","type":{"name":"axt.ProposalReplyAnswer","type":"enum","symbols":["ACCEPTED","DECLINED"]}}]}
```

| Schema              | Envelope format | CRC-64-AVRO          | As bytes                  |
| ------------------- | --------------- | -------------------- | ------------------------- |
| `axt.Proposal`      | 1               | `0x2512222a12d90279` | `79 02 d9 12 2a 22 12 25` |
| `axt.ProposalReply` | 1               | `0x64610ce36e75f8c6` | `c6 f8 75 6e e3 0c 61 64` |

The kind `WITHDRAW` is the symbol with the index 14 of `axt.Kind` in [types/axt/Envelope.avsc](../types/axt/Envelope.avsc), `PROPOSAL` the one with the index 15 and `PROPOSAL_REPLY` the one with the index 16; the canonical form and the fingerprint of that schema are in [envelope.md](envelope.md), section 10.1. The outcome `WITHDRAWN` is the symbol with the index 5 of `axt.AckOutcome` in [types/axt/Ack.avsc](../types/axt/Ack.avsc), and the error `PROPOSALS_NOT_TAKEN` the symbol with the index 15 of `axt.ErrorCode` in [types/axt/Error.avsc](../types/axt/Error.avsc), whose canonical forms and fingerprints are in [protocol.md](protocol.md), section 16. The field `proposals` of `axt.ManifestSend` is in [types/axt/Manifest.avsc](../types/axt/Manifest.avsc) ([manifest.md](manifest.md), section 9). None of these four schemas changes with this document. The test vectors of [conformance.md](conformance.md) take precedence over the values of this section and of section 11.

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

### 11.3 A proposal, taken

The appointment of section 11.1 as it stands after step 3 of [records.md](records.md), section 9: version 3, `title` "Vet", `start` 2025-11-18 10:30, `location` "" and `notes` "Bring the vaccination card". The owner and the proposer are the sender and the receiver of section 11.1, with the same keys: cat-a-log, one installation that counts its versions and signs with `cat-a-log, old phone, Ed25519`, and the second user's app, one installation that signs with `Old Brain Fix, Ed25519`, lets its user change received records and merges per field. The two meet in a live connection. cat-a-log's manifest is that of [manifest.md](manifest.md), section 10.1, with two differences: its `revision` is 2, and its entry of `sends` for `axt.example.v1.Appointment` has `proposals` `true`. The steps of section 11.1 do not happen here; the appointment is shared with the second user's app from step 1 on and stays shared. The times are `axt.DateTime` values in the zone `Europe/Berlin` with the offset 3600 ([time.md](time.md), section 6), shown by their wall clock. Every message's `record` carries the id of the appointment and the version in the table.

| Step | What happens                                                                                                                                                             | Message, from → to                          | `record.version` | Result                                                                     |
| ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------- | ---------------- | -------------------------------------------------------------------------- |
| 1    | cat-a-log's user puts the appointment into a share for the second user's app. cat-a-log offers `Appointment` there, the receiver accepts, and cat-a-log sends the record | `DATA`, cat-a-log → Old Brain Fix           | 3                | `APPLIED`, receiver's version 3                                            |
| 2    | The second user moves `start` to 11:00 in Old Brain Fix and proposes the change                                                                                          | `PROPOSAL`, Old Brain Fix → cat-a-log       | 3                | Old Brain Fix shows 11:00 as its user's change; the proposal is open there |
| 3    | cat-a-log takes the proposal and shows it to its user, 11:00 beside 10:30                                                                                                | none                                        |                  | the proposal is open at cat-a-log; the record is unchanged, version 3      |
| 4    | cat-a-log's user takes the proposal. `start` becomes 11:00 in the record, version 4                                                                                      | `PROPOSAL_REPLY`, cat-a-log → Old Brain Fix | 3                | `ACCEPTED`; Old Brain Fix shows its user that the proposal was taken       |
| 5    | cat-a-log sends the update, under the offer of step 1                                                                                                                    | `DATA`, cat-a-log → Old Brain Fix           | 4                | `APPLIED`, receiver's version 4; `start` 11:00                             |

- **Step 1.** As step 1 of section 11.1. Old Brain Fix holds cat-a-log's manifest of revision 2 from the `MANIFEST` of the connection, so it knows that cat-a-log takes proposals for appointments (section 12.2).
- **Step 2.** Old Brain Fix changes `start` as a change of its user ([records.md](records.md), section 6): the record shows 11:00, and the field counts as changed by the user. It sends the `PROPOSAL` of section 11.4 to cat-a-log's key, the key from which it got the `DATA`, with its receiver's version 3 in `record` and one entry in `fields`: the name `start`, the fingerprint of the writer schema of the `DATA` of step 1, version 1 of `axt.example.v1.Appointment`, and the value 11:00 in Avro binary encoding under the type of `start` in that schema. No `ACK` answers it (section 16.1).
- **Step 3.** cat-a-log processes the `PROPOSAL` by section 13.3. The record is there and shared with the second user's app, and cat-a-log's manifest takes proposals for its type (step 5); it holds the schema, the schema has a field `start`, the value decodes and is a valid time (steps 6 to 9). It takes the proposal and shows it to its user, applies nothing yet, and sends nothing.
- **Step 4.** The user takes the proposal whole, so the answer is `ACCEPTED` (section 15.1). The value of `start` becomes the record's own change, as a change of its user would (section 15.2): cat-a-log counts, and the highest version it has given the record is 3, so the change takes the version 4. It sends the `PROPOSAL_REPLY` of section 11.5 to the key that signed the proposal, with the `record` of the proposal: the id and the version 3, not 4. Old Brain Fix takes the reply by section 14.2 and shows it as a status; the record does not change with it.
- **Step 5.** The update is an ordinary `DATA` of version 4, the whole record with `start` 11:00, to every receiver with which the appointment is shared ([records.md](records.md), section 4.1). At Old Brain Fix the version 4 is above the receiver's version 3. Its user has changed `start`, and keeps the value 11:00, which is the value the message brings; no kept value differs from the message, so the outcome is `APPLIED`, with no kept field ([records.md](records.md), section 6.1). Its `ACK` carries the id, the version 4, `APPLIED`, the `receiver_version` 4 and no kept field. Old Brain Fix MAY count `start` as no longer changed by its user ([records.md](records.md), section 6.1); until then a later `DATA` with another `start` keeps 11:00, as for every change of its user.

Had cat-a-log's user refused the proposal, the reply would have carried `DECLINED`, no update would have followed, and Old Brain Fix would have gone on showing 11:00 as its user's change, until its user discards it (section 17.2). Had the appointment been withdrawn from the second user's app before step 3, cat-a-log would have rejected the `PROPOSAL` with `PROPOSALS_NOT_TAKEN` (section 15.4).

### 11.4 The `PROPOSAL` of step 2

The `PROPOSAL` of step 2 of section 11.3 is a live message in envelope format 1 ([envelope.md](envelope.md), section 3). Its `proposal_id` is `7b3e9d21-4c8a-4f6e-9a1b-5d2c8e4f6a70`.

| Field                   | Value                                                                                                                                                                                                                                                                                                                                                |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `format`                | 1                                                                                                                                                                                                                                                                                                                                                    |
| `kind`                  | `PROPOSAL`, enum index 15                                                                                                                                                                                                                                                                                                                            |
| `sender`                | The public key of `Old Brain Fix, Ed25519` ([protocol.md](protocol.md), section 17.1), the second user's app                                                                                                                                                                                                                                         |
| `record`                | Union index 1, `axt.RecordRef`                                                                                                                                                                                                                                                                                                                       |
| `record.id`             | `"3f2c8a5e-9b1d-4c7e-8a6f-2d4b5c6e7f80"`                                                                                                                                                                                                                                                                                                             |
| `record.version`        | 3                                                                                                                                                                                                                                                                                                                                                    |
| `body`                  | One `axt.Proposal` in single-object encoding: `C3 01`, the fingerprint of `axt.Proposal`, format 1 (`79 02 d9 12 2a 22 12 25`), and the fields below; body length 129                                                                                                                                                                                |
| `body.to`               | The public key of `cat-a-log, old phone, Ed25519` ([keys.md](keys.md), section 7.1)                                                                                                                                                                                                                                                                  |
| `body.proposal_id`      | `"7b3e9d21-4c8a-4f6e-9a1b-5d2c8e4f6a70"`                                                                                                                                                                                                                                                                                                             |
| `body.fields`           | One entry                                                                                                                                                                                                                                                                                                                                            |
| `body.fields[0].name`   | `"start"`                                                                                                                                                                                                                                                                                                                                            |
| `body.fields[0].schema` | The fingerprint of [Appointment.1.avsc](../types/axt/example/v1/Appointment.1.avsc) ([types.md](types.md)): `25 ad db 94 70 73 d0 10`                                                                                                                                                                                                                |
| `body.fields[0].value`  | The `axt.DateTime` of 2025-11-18 11:00: `year` 2025, `month` 11, `day` 18, `hour` 11, `minute` 0, `second` 0, `millisecond` 0, `zone` `"Europe/Berlin"`, `offset_seconds` 3600, `instant_ms` 1763460000000, in Avro binary encoding: `d2 1f 16 24 16 00 00 00 02 1a 45 75 72 6f 70 65 2f 42 65 72 6c 69 6e 02 a0 38 02 80 a4 c1 e6 d2 66`, length 33 |
| `signature`             | `e55c67f798efc57693d118f8ecf47f7c646381c7717fdb58ca480929ca2d5d752ed9ce53402c9fe2e60b36d6d1c9b28f64e308fdd209ff6af5359841924dfc0b`                                                                                                                                                                                                                   |

The message: 278 bytes, SHA-256 `70e9e60c868c05bd243015c0a38d9a40fde50c7d944c4dcbb80fbae4ee697476`. The signature covers the prefix `AXT-v1 message` and its zero byte, and the bytes from offset `000a` to the signature ([keys.md](keys.md), section 2.2). `instant_ms` is the instant of 2025-11-18 10:00 UTC in milliseconds since 1970-01-01 00:00 UTC: 20,410 days of 86,400,000 milliseconds and 10 hours of 3,600,000.

```text
0000  c3 01                    single-object marker
0002  16 30 6f 71 b9 ce 9e a8  fingerprint of axt.Envelope, format 1
000a  02                       format: int 1
000b  1e                       kind: enum index 15, PROPOSAL
000c  da 9e 54 c9 aa 2d b4 32  sender: fixed(32), Old Brain Fix's test key
      44 df 99 88 9d 91 38 c1
      ca 71 75 d4 ca 09 08 16
      8f 63 53 0e 4a 7d ed b7
002c  02                       record: union index 1, axt.RecordRef
002d  48                       record.id: string length 36
002e  33 66 32 63 38 61 35 65  "3f2c8a5e-9b1d-4c7e-8a6f-2d4b5c6e7f80"
      2d 39 62 31 64 2d 34 63
      37 65 2d 38 61 36 66 2d
      32 64 34 62 35 63 36 65
      37 66 38 30
0052  06                       record.version: long 3
0053  82 02                    body: bytes length 129
0055  c3 01                    body: single-object marker
0057  79 02 d9 12 2a 22 12 25  body: fingerprint of axt.Proposal, format 1
005f  1b 84 a6 00 f3 50 3e 22  body: to: fixed(32), cat-a-log's test key
      bb cc 99 e6 32 02 a7 19
      4b f6 bd 69 af f1 47 1c
      ce 64 10 d5 3c 26 ec 4a
007f  48                       body: proposal_id: string length 36
0080  37 62 33 65 39 64 32 31  body: "7b3e9d21-4c8a-4f6e-9a1b-5d2c8e4f6a70"
      2d 34 63 38 61 2d 34 66
      36 65 2d 39 61 31 62 2d
      35 64 32 63 38 65 34 66
      36 61 37 30
00a4  02                       body: fields: array block of 1 item
00a5  0a                       body: fields[0].name: string length 5
00a6  73 74 61 72 74           body: "start"
00ab  25 ad db 94 70 73 d0 10  body: fields[0].schema: fixed(8), the fingerprint of the writer schema
00b3  42                       body: fields[0].value: bytes length 33
00b4  d2 1f 16 24 16 00 00 00  body: fields[0].value: wall clock 2025-11-18 11:00:00.000, seven ints
00bc  02                       body: fields[0].value.zone: union index 1, string
00bd  1a                       body: fields[0].value.zone: string length 13
00be  45 75 72 6f 70 65 2f 42  body: "Europe/Berlin"
      65 72 6c 69 6e
00cb  02                       body: fields[0].value.offset_seconds: union index 1, int
00cc  a0 38                    body: fields[0].value.offset_seconds: int 3600
00ce  02                       body: fields[0].value.instant_ms: union index 1, long
00cf  80 a4 c1 e6 d2 66        body: fields[0].value.instant_ms: long 1763460000000
00d5  00                       body: fields: end of the array
00d6  47 ad 62 97 a2 28 bf 7b  signature: fixed(64)
      d3 57 1e 56 39 0c 16 8a
      e9 e2 66 d8 84 02 8e 15
      c8 8d ce f1 93 8b fb f8
      57 9d b2 56 dd 59 d3 da
      a7 9a a5 56 f1 a3 b5 71
      2f 02 9f 94 2d 33 8b c6
      fb 4d c6 6b 37 93 b3 07
0116  end
```

### 11.5 The `PROPOSAL_REPLY` of step 4

The `PROPOSAL_REPLY` of step 4 of section 11.3 is a live message in envelope format 1:

| Field              | Value                                                                                                                                                                          |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `format`           | 1                                                                                                                                                                              |
| `kind`             | `PROPOSAL_REPLY`, enum index 16                                                                                                                                                |
| `sender`           | The public key of `cat-a-log, old phone, Ed25519` ([keys.md](keys.md), section 7.1)                                                                                            |
| `record`           | Union index 1, `axt.RecordRef`                                                                                                                                                 |
| `record.id`        | `"3f2c8a5e-9b1d-4c7e-8a6f-2d4b5c6e7f80"`                                                                                                                                       |
| `record.version`   | 3, the version of the proposal                                                                                                                                                 |
| `body`             | One `axt.ProposalReply` in single-object encoding: `C3 01`, the fingerprint of `axt.ProposalReply`, format 1 (`c6 f8 75 6e e3 0c 61 64`), and the fields below; body length 80 |
| `body.to`          | The public key of `Old Brain Fix, Ed25519` ([protocol.md](protocol.md), section 17.1), the key that signed the proposal                                                        |
| `body.proposal_id` | `"7b3e9d21-4c8a-4f6e-9a1b-5d2c8e4f6a70"`                                                                                                                                       |
| `body.answer`      | `ACCEPTED`, enum index 0                                                                                                                                                       |
| `signature`        | `1e572ef7e714ab7c90a59e7eef85338ac5f4f6984098642cc8d97428e9eb528dc1782814327cc355e99ed100e31af86073fa4275c6e59813cc4e2519d81b8c0d`                                             |

The message: 229 bytes, SHA-256 `199a9c5ccf788ba6547d1e862bdfb38aa90a07a136658bee2754228b1ef2158c`. The signature covers the prefix `AXT-v1 message` and its zero byte, and the bytes from offset `000a` to the signature ([keys.md](keys.md), section 2.2).

```text
0000  c3 01                    single-object marker
0002  16 30 6f 71 b9 ce 9e a8  fingerprint of axt.Envelope, format 1
000a  02                       format: int 1
000b  20                       kind: enum index 16, PROPOSAL_REPLY
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
0052  06                       record.version: long 3
0053  a0 01                    body: bytes length 80
0055  c3 01                    body: single-object marker
0057  c6 f8 75 6e e3 0c 61 64  body: fingerprint of axt.ProposalReply, format 1
005f  da 9e 54 c9 aa 2d b4 32  body: to: fixed(32), Old Brain Fix's test key
      44 df 99 88 9d 91 38 c1
      ca 71 75 d4 ca 09 08 16
      8f 63 53 0e 4a 7d ed b7
007f  48                       body: proposal_id: string length 36
0080  37 62 33 65 39 64 32 31  body: "7b3e9d21-4c8a-4f6e-9a1b-5d2c8e4f6a70"
      2d 34 63 38 61 2d 34 66
      36 65 2d 39 61 31 62 2d
      35 64 32 63 38 65 34 66
      36 61 37 30
00a4  00                       body: answer: enum index 0, ACCEPTED
00a5  1e 57 2e f7 e7 14 ab 7c  signature: fixed(64)
      90 a5 9e 7e ef 85 33 8a
      c5 f4 f6 98 40 98 64 2c
      c8 d9 74 28 e9 eb 52 8d
      c1 78 28 14 32 7c c3 55
      e9 9e d1 00 e3 1a f8 60
      73 fa 42 75 c6 e5 98 13
      cc 4e 25 19 d8 1b 8c 0d
00e5  end
```

## 12. Proposals

### 12.1 What a proposal is

A receiver's changes of a received record stay with the receiver: they are not sent back and are never versions of the record ([records.md](records.md), section 1). A receiver whose user wants the owner to change the record, such as to move an appointment to another time, sends a proposal instead:

- **Changed fields only.** A proposal carries new values for some top-level fields of one record, each in the form of a field state of [sync.md](sync.md), section 3.1, without stamp and device: a name, the fingerprint of a writer schema and the value as bytes (section 13.1). It carries no removal: a proposal can neither delete a record nor create one.
- **Nothing without the owner's user.** The owner's app shows the proposal to its user and applies nothing of it unless the user takes it. A proposal that the user takes becomes the owner's own change of the record, which reaches every receiver of the record, the proposer included, as an ordinary update ([records.md](records.md), section 4.1; section 15.2).
- **The answer is a status.** The owner's device tells the proposer in a reply whether the user took the proposal (section 14). The reply changes no record; the proposer's own value stands as its user's change before the answer and after a refusal, until its user discards it (section 17.2).

A `PROPOSAL` and a `PROPOSAL_REPLY` are no record messages. Their `record` names the owner's record, with the version of it that the proposer holds, but no version rule applies to them ([records.md](records.md), section 5.2), and the receiver's version of the record does not change by them.

### 12.2 Who may propose

A receiver may propose a change of a record when:

- **it is a receiver of the record**: the owner shares the record with it (section 2). A device of the owner tells this from the shares that it holds (section 2.1), which every device of the owner's set holds alike once it has merged with its siblings; which messages a device sent to whom does not travel and is not looked at (section 2.1). Every app that the owner's app holds as an app of its own user (section 2.3) counts here as a receiver of every record of the type; this needs nothing that travels between the owner's devices;
- **the owner takes proposals for the type**: the manifest of the owner's device has an entry in `sends` for the full name of the record's type whose `proposals` is `true` ([manifest.md](manifest.md), section 3.7). A manifest whose `sends` is `null`, or has no entry for the type, takes no proposals for it.

Every receiver of a record of such a type may propose: an app that takes proposals for a type takes them from every receiver with which it shares a record of that type, within the limits of section 18.3. The devices of the owner's own set are no receivers (section 2.3); they change the records of the set directly.

Each side judges by a manifest of its own:

- **The proposer** sends a `PROPOSAL` only to a device whose kept manifest ([manifest.md](manifest.md), section 6) takes proposals for the type, the manifest of the key it puts into `to` (section 13.1). It MUST NOT send one to a key of which it holds no manifest or one that takes no proposals for the type.
- **The owner's device** that gets a `PROPOSAL` from the proposer judges by its own current manifest, not by the one it sent: a manifest that changed in between decides (section 13.3, step 5), as for an offer ([manifest.md](manifest.md), section 5.4).

## 13. The `PROPOSAL` message

### 13.1 Content

| Field       | Content for a `PROPOSAL`                                                                                                         |
| ----------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `format`    | The envelope format, `1` ([envelope.md](envelope.md), section 2.1)                                                               |
| `kind`      | `PROPOSAL`, the symbol with the index 15 of `axt.Kind`                                                                           |
| `sender`    | The key of the proposer's device that sends the proposal ([keys.md](keys.md), section 2.1)                                       |
| `record`    | REQUIRED: `id` is the id of the owner's record, `version` the receiver's version of it at the proposer                           |
| `body`      | One `axt.Proposal` in single-object encoding, with the schema [types/axt/Proposal.avsc](../types/axt/Proposal.avsc) (section 10) |
| `signature` | The proposer's signature, as for every message ([keys.md](keys.md), section 2.2)                                                 |

| Field             | Avro type                                     | Content                                                                                                |
| ----------------- | --------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `to`              | `fixed` of 32 bytes, `axt.ProposalTo`         | The Ed25519 public key of the owner's device that the proposal is sent to                              |
| `proposal_id`     | `string`, logical type `uuid`                 | The id of the proposal                                                                                 |
| `fields`          | array of record `axt.ProposalField`           | The proposed values, in any order                                                                      |
| `fields[].name`   | `string`                                      | The name of a top-level field of the record, as the schema of `fields[].schema` names it               |
| `fields[].schema` | `fixed` of 8 bytes, `axt.ProposalFieldSchema` | The fingerprint ([envelope.md](envelope.md), section 5) of the writer schema the value is written with |
| `fields[].value`  | `bytes`                                       | The proposed value, in Avro binary encoding under the type that the field has in that schema           |

- **`record`** names the owner's record by its id and carries the receiver's version of it that the proposing device holds ([records.md](records.md), section 5.1): the version of the `DATA` that its sender's layer ends in ([sync.md](sync.md), section 17.1). A device MUST NOT send a `PROPOSAL` for a record unless the record is there on it and its last record message from the owner is a `DATA`: it sends none for a record that the owner deleted or withdrew from it, also not for one that it keeps against such a message, and none for one that its own user deleted.
- **`to`** is a current key of the owner, chosen as [protocol.md](protocol.md), section 9.1, chooses the key of an `OFFER`, among the keys whose kept manifest takes proposals for the type (section 12.2).
- **`proposal_id`** is a version 4 or version 7 UUID of [RFC 9562](https://www.rfc-editor.org/rfc/rfc9562) in lower-case text form, which the proposing device generates for the proposal. A device MUST NOT use an id for a second proposal, to the same or to another app, and MUST NOT use the id of a record, an offer, a request or a forward ([sync.md](sync.md), sections 11.1 and 18.1) as the id of a proposal. One proposal id always stands for the same proposal: a proposal that is sent again (section 16.2) is the same message, apart from one sent to another key of the owner after the key in `to` was removed, which differs in `to` and its signature.
- **`fields`** holds one entry for each field whose value the proposal changes. An entry is a field whose proposed value differs, compared as decoded values, from the value of that field in the `DATA` that brought the version named in `record`; a proposal holds no other entry. A proposer merges per field (section 17.2), so its owner's layer holds field states only for the fields its user changed. Each entry is the field state that the change of the proposer's user gave the owner's layer of [sync.md](sync.md), section 21.2, on the proposing device, without its stamp and its device key: the field's name, the fingerprint of the writer schema of the record's kept `DATA` with which the device wrote the value, and the bytes of the value, unchanged. A device that keeps no owner's layer writes the same: the user's value in Avro binary encoding under the type that the field has in the writer schema of the `DATA` that brought the receiver's version, with the fingerprint of that schema. A field whose change the user discarded, a field state with the value `null`, is not proposed.

### 13.2 Validity

A `PROPOSAL` is valid when it is a valid message ([protocol.md](protocol.md), section 8.2), it carries `record`, its body is one `axt.Proposal` in single-object encoding, the two bytes `C3 01`, the fingerprint of `axt.Proposal` in its envelope format (section 10) and the datum, with no bytes left over, and the body is valid:

- `proposal_id` is a UUID in text form, neither the nil UUID nor the max UUID;
- `fields` has 1 to 4,096 entries;
- each `name` is 1 to 512 bytes of UTF-8, and no name appears twice; names are compared as sequences of Unicode code points, as in [sync.md](sync.md), section 8.2.

A `PROPOSAL` without `record`, and one whose body is not one `axt.Proposal`, the empty body included, is rejected with `INVALID_MESSAGE` ([protocol.md](protocol.md), section 2), as is one whose body is not valid. One whose `to` is not the receiver's own key is ignored without a report ([protocol.md](protocol.md), section 9.1).

### 13.3 Processing

A device of the owner processes a `PROPOSAL` that it gets from the proposer itself in these steps. A step that fails ends the processing: the device takes nothing, changes nothing, and reports the failure with the error code named ([protocol.md](protocol.md), section 8.3). "Changes nothing" includes its clock: no number in the message counts as a stamp seen ([sync.md](sync.md), section 2.2).

| Step | Check                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | If it fails                                                                                                                                                                                                                    |
| ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1    | The message and its envelope are valid, and its signature verifies, as for every message ([protocol.md](protocol.md), section 8.2); it carries `record`, its body is one `axt.Proposal` with no bytes left over, and its `to` is the device's own key                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | as [protocol.md](protocol.md), section 8.2, says; `INVALID_MESSAGE` for a missing `record` or a body that is not one `axt.Proposal`; another key in `to` is ignored without a report ([protocol.md](protocol.md), section 9.1) |
| 2    | `record.id` is a UUID in text form, neither the nil UUID nor the max UUID ([records.md](records.md), section 2)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | `RECORD_ID_INVALID`                                                                                                                                                                                                            |
| 3    | `record.version` is at least 1                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | `VERSION_INVALID`                                                                                                                                                                                                              |
| 4    | The body is valid (section 13.2)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | `INVALID_MESSAGE`                                                                                                                                                                                                              |
| 5    | Unless the owner's app holds an answer to a proposal of that proposer with that `proposal_id`, for which the device goes on with step 10 at once (section 13.4): the proposer may propose for the record (section 12.2): the `sender` is a current key of a known sender other than the device's own set; the device holds a record of its own set with the id `record.id` that is there, not deleted ([sync.md](sync.md), section 4.3); it is shared with that sender, or the app holds that sender as an app of its own user (sections 2.3 and 12.2); the device's current manifest takes proposals for its type; the app's records do not hold the proposals of that sender as stopped for the record (section 18.4); and the proposal is within the limits of section 18.3 | `PROPOSALS_NOT_TAKEN`                                                                                                                                                                                                          |
| 6    | For every entry of `fields`, the device holds a schema whose fingerprint is the entry's `schema`: one of its own writer schemas of the record's type, or a schema it holds by [sync.md](sync.md), section 7.3                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | `SCHEMA_UNKNOWN`                                                                                                                                                                                                               |
| 7    | For every entry, that schema is the schema of a record whose full name is the full name of the record's type, and it has a top-level field whose name is the entry's `name`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | `INVALID_MESSAGE`                                                                                                                                                                                                              |
| 8    | For every entry, `value` decodes, in Avro binary encoding, as one value of the type that the field `name` has in the entry's schema, with no bytes left over, with well-formed strings, and to a data depth of at most 32 ([types.md](types.md), section 5.7)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | `UNDECODABLE`                                                                                                                                                                                                                  |
| 9    | Every time value in the decoded values is valid ([time.md](time.md), section 8) and every relation keeps the rules of [fields.md](fields.md), section 11.4; and, if the device checks them, every value keeps the checks of the entry's schema ([metadata.md](metadata.md), section 7.1)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | `VALUE_INVALID`                                                                                                                                                                                                                |
| 10   | The device takes the proposal (section 13.4)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | (no failure)                                                                                                                                                                                                                   |

- **Before the steps.** A `PROPOSAL` from a key that the device's user has not accepted, or signed with a removed key, is kept, dropped or rejected as every message is ([protocol.md](protocol.md), section 8.2). In a live connection, one that arrives before the other app's valid `MANIFEST` is not processed ([protocol.md](protocol.md), section 3.1). A `PROPOSAL` whose `sender` is the device's own key is ignored without a report.
- **The order of step 1.** After the envelope and the signature, the device checks first `record`, then the body, then `to`, as for a `WITHDRAW` (section 4.1).
- **Step 5** gives one result for every reason: an id that the device does not hold, a record of another sender with that id, a record that is deleted, a record that is not shared with the proposer, withdrawn from it or never shared, a type for which the manifest takes no proposals, a proposer whose proposals the user stopped, a proposer beyond the limits, and a `PROPOSAL` of a sibling, which is no receiver (section 12.2). So a `PROPOSAL` tells an app that is no receiver of a record nothing of the records the owner holds. The `detail` of the `ERROR` MUST be empty for `PROPOSALS_NOT_TAKEN`, and a device SHOULD answer every reason of step 5 alike, also in the time it takes to answer. A repeat of a proposal whose answer the app holds is looked up before the checks of step 5, so it gets its reply again (section 13.4) and not an error, also where the record has been deleted or withdrawn since. The record is one of the device's own set, found by its id among the records of the set ([records.md](records.md), section 2); a received record with that id is another record and does not count.
- **Steps 6 and 7.** Every device of the owner's set holds the writer schema of every `DATA` that a device of the set sent to a receiver, for as long as the record is shared with that receiver (section 15.1), so a proposal written against that schema can be read. The error's `fingerprint` at step 6 is the `schema` of the first entry, in the order of the message, for which the device holds no schema. The full name and the field name are compared as in [sync.md](sync.md), section 8.3, step 8. A field that the device's own writer schema lacks but the entry's schema has passes; the device keeps the value as it keeps a field of [sync.md](sync.md), section 8.5.
- **Step 8.** The data depth counts the record as depth 1, as in [sync.md](sync.md), section 8.3, step 11. The device decodes with the entry's schema alone.
- **Step 9.** The error's `field` is the path of the first value that fails, in the order of `fields` and within one value in the order of the encoding, by the field names of the entry's schema ([metadata.md](metadata.md), section 7.2); it begins with the entry's `name`. For a time value that is not valid it names the whole value, such as `start`, as [time.md](time.md), section 8, reports it; a relation that breaks a rule is named as [fields.md](fields.md), section 11.4, says.
- **The version** is not compared with anything at these steps: a proposal for a version that the device has left behind, or for a version above its own, is taken like any other (section 15.3). The device does not count it as a stamp seen.
- **No acknowledgement.** The device sends no `ACK` for a `PROPOSAL`, whatever the result (section 16.1).

### 13.4 Taking a proposal, and a repeat

A device identifies a proposal by its proposer and its `proposal_id`. It stores with the proposal a key of the proposer, the `sender` of the `PROPOSAL`, and the app stores the same key with its answer (section 15.1); the device finds the proposer as the known sender that has that key among its current or its removed keys, as [sync.md](sync.md), section 21.3, finds the sender that `origin` names. At step 10:

- **A new proposal.** If the device holds no proposal of that proposer with that id, and the owner's app holds no answer to one (section 15.1), it takes the proposal: it keeps the message (section 17.1) and holds the proposal as open. It shows the proposal to its user as section 15.1 says; it does not wait for its user before it processes the next message.
- **A repeat of an open proposal.** If it holds an open proposal of that proposer with that id, it changes nothing, apart from keeping the copy with the higher SHA-256 (below), and sends nothing.
- **A repeat of an answered proposal.** If the owner's app holds an answer to a proposal of that proposer with that id, the device changes nothing, and sends the proposer a reply with that answer again (section 14.1), to the key that signed the repeat.

A repeat is taken as the proposal it repeats whatever its content: a `PROPOSAL` with the id of a proposal that the device holds or has answered, in other bytes or with other values, is a repeat. Of two `PROPOSAL` messages of one proposer with one `proposal_id` in different bytes that a device holds as an open proposal, the one whose SHA-256 over the bytes of the message is the higher, compared as 32 unsigned bytes from the first byte on, stands on every device, as of two kept messages in [sync.md](sync.md), section 20.1: a device that gets the higher one while it holds the lower keeps the higher one in its place, and the proposal stays open with its values. An answer that the app holds is not changed by a repeat.

## 14. The `PROPOSAL_REPLY` message

### 14.1 Content

| Field       | Content for a `PROPOSAL_REPLY`                                                                                                                  |
| ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `format`    | The envelope format, `1` ([envelope.md](envelope.md), section 2.1)                                                                              |
| `kind`      | `PROPOSAL_REPLY`, the symbol with the index 16 of `axt.Kind`                                                                                    |
| `sender`    | The key of the owner's device that sends the reply ([keys.md](keys.md), section 2.1)                                                            |
| `record`    | REQUIRED: the `record` of the proposal, its `id` and its `version`, as the proposal carried them                                                |
| `body`      | One `axt.ProposalReply` in single-object encoding, with the schema [types/axt/ProposalReply.avsc](../types/axt/ProposalReply.avsc) (section 10) |
| `signature` | The owner's signature, as for every message ([keys.md](keys.md), section 2.2)                                                                   |

| Field         | Avro type                                  | Content                                                                                                                             |
| ------------- | ------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------- |
| `to`          | `fixed` of 32 bytes, `axt.ProposalReplyTo` | The key that signed the proposal ([protocol.md](protocol.md), section 9.1)                                                          |
| `proposal_id` | `string`, logical type `uuid`              | The id of the proposal, as the proposal carried it                                                                                  |
| `answer`      | enum `axt.ProposalReplyAnswer`             | `ACCEPTED`: the owner's user took every proposed value into the record. `DECLINED`: the user did not take the proposal as it stands |

- **Who sends it.** The device on which the owner's user answers the proposal sends the reply (section 17.1), and a device that gets a repeat of an answered proposal sends it again (section 13.4). Each signs its reply with its own key.
- **Where it goes.** A reply carries in `to` the key that signed the `PROPOSAL`, and goes to that device. If that key has been removed from the proposer ([keys.md](keys.md), section 5.5), the owner's device sends no reply: the proposer's set learns that the proposal was taken from the update (section 15.2).
- **Validity.** A `PROPOSAL_REPLY` is valid when it is a valid message ([protocol.md](protocol.md), section 8.2), it carries `record`, and its body is one `axt.ProposalReply` in single-object encoding, the two bytes `C3 01`, the fingerprint of `axt.ProposalReply` in its envelope format (section 10) and the datum, with no bytes left over. One without `record`, and one with any other body, the empty body included, is rejected with `INVALID_MESSAGE`. One whose `to` is not the receiving device's key is ignored without a report ([protocol.md](protocol.md), section 9.1).

### 14.2 What the proposer does with a reply

A device of the proposer processes a `PROPOSAL_REPLY` in these steps; the first that applies decides:

| Step | The reply                                                                                                                                    | The device                                                                                                                                                                                                                                                   |
| ---- | -------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1    | is not valid (section 14.1), or its signature does not verify                                                                                | rejects it as [protocol.md](protocol.md), section 8.2, says, with `INVALID_MESSAGE` for a missing `record` or another body, and with `SIGNATURE_INVALID`, whose `record` is `null`, for a signature that does not verify, as the owner does for a `PROPOSAL` |
| 2    | names another key in `to`                                                                                                                    | ignores it without a report                                                                                                                                                                                                                                  |
| 3    | names in `proposal_id` no proposal that this device sent to the sender of the reply, the known sender of which its `sender` is a current key | ignores it without a report, as an answer to an offer the app did not make ([protocol.md](protocol.md), section 8.2)                                                                                                                                         |
| 4    | carries another `record` than that proposal: another id, or another version                                                                  | rejects it with `INVALID_MESSAGE`                                                                                                                                                                                                                            |
| 5    | is about a proposal for which the device holds a reply already                                                                               | takes `ACCEPTED` in the place of a `DECLINED` that it holds; ignores it otherwise                                                                                                                                                                            |
| 6    | is the first reply for that proposal                                                                                                         | keeps its answer as the status of the proposal, stops sending the proposal again (section 16.2), and MAY show its user the answer                                                                                                                            |

- **A status only.** The device changes no record because of a reply, and the reply ends no change of its user (section 17.2). `ACCEPTED` says that an update is coming (section 15.2); it is applied by the version rule when it arrives, as every `DATA` ([records.md](records.md), section 5.2). `DECLINED` says that none is coming for this proposal.
- **A change that was discarded.** A reply to a proposal whose values the device's user has discarded since is taken all the same, as a status.
- **Two answers.** Two devices of the owner can answer one proposal differently before they have merged (section 17.1). The proposer keeps the first reply it gets, and takes a later `ACCEPTED` in the place of a `DECLINED`; the update of an `ACCEPTED` reaches it in any case, as an ordinary `DATA`.
- **No reply to a reply.** A device sends no `ACK` and no reply for a `PROPOSAL_REPLY`. It reports an invalid one with an `ERROR`, as every message ([protocol.md](protocol.md), section 8.3). The owner's device takes an `ERROR` as one about a reply when its `message_hash` is the SHA-256 of a `PROPOSAL_REPLY` that it sent to the key that sent the `ERROR`, not by the error's `record`, which names a record of its own; it logs it and does not send that reply again.

## 15. The owner's app

### 15.1 Showing and answering

The owner's app shows each open proposal to its user: the proposer, as the app knows it ([keys.md](keys.md), section 3.2), the record, and each proposed value beside the record's current value of that field, read with the schema of its entry, resolved against the app's reader schema, as for a value of a field state ([sync.md](sync.md), section 3.1). It SHOULD gather the open proposals in one place rather than interrupt its user for each.

- **Nothing without the user.** The app MUST NOT take a proposed value into a record unless its user takes the proposal. A device MUST NOT answer `ACCEPTED` unless it has shown its user every proposed value, decoded with the schema of its entry and resolved against its reader schema of the type. A value that it cannot show so, such as one of a field that its reader schema lacks, one that does not decode, or one whose schema does not resolve against its own, bars `ACCEPTED` on that device; its user can still decline there, or take the proposal on a device that can show every value. It MUST NOT answer `ACCEPTED` on its own, and answers `DECLINED` only by its user's decision. A proposal that no one answers stays open; no timer ends it.
- **The answer.** `ACCEPTED` when the user takes the proposal whole, every value as proposed. `DECLINED` when the user refuses it. An app that lets its user take only some of the proposed values, or other values, answers `DECLINED` and makes what its user takes a change of its user like any other, which reaches the proposer as an update.
- **Recording the answer.** The app keeps, for each proposal it answered, the key of the proposer stored with the proposal (section 13.4), the `proposal_id`, the proposal's `record`, its id and version, which the reply to a repeat carries, and the answer, as records of a type in its own namespace, as it keeps its shares (section 2.1). So every device of the owner's set comes to hold the answer once it has merged with its siblings (section 17.1). It MUST keep an answer for as long as the record is shared with the proposer, and at least for the 15 days for which a relay may deliver the proposal again ([transports.md](transports.md), section 5.5). Of two answers to one proposal that the records hold, `ACCEPTED` stands. A device that no longer holds the answer takes a repeat of the proposal as a new proposal (section 13.4).
- **What the device holds.** To show and answer a proposal, a device holds the `PROPOSAL` message as the proposer sent it (section 17.1), and keeps the text of the schema of each entry with it. The app also keeps the text of the writer schema of every `DATA` that any device of its set sent to a receiver, for as long as the record is shared with that receiver, as records of a type in its own namespace, as it keeps its shares (section 2.1), so that every device of the set holds it and can read a proposal written against that schema ([sync.md](sync.md), section 7.3). A device that does not hold the schema of an entry, such as a sibling that got the proposal in a forward (section 17.1), shows that value once it holds the schema, and MUST NOT answer `ACCEPTED` before it holds the schema of every entry.

### 15.2 An accepted proposal

When the owner's user takes a proposal, the device on which the user takes it, which has shown every proposed value (section 15.1):

1. makes the proposed values a change of its user of the record of its set, one change of [sync.md](sync.md), section 3.5, "changes one or several fields of a record": it takes one stamp and gives it, with its own key, to each proposed field, with the entry's value bytes and the entry's `schema` as the field state's value and schema, unchanged; then it takes the state stamp. It stamps every proposed field, also one whose value the record holds already, in place of the rule of [sync.md](sync.md), section 3.5, that leaves such a field unstamped. An installation that counts takes the values into the record and the next count as the record's version ([records.md](records.md), section 3);
2. records the answer `ACCEPTED` (section 15.1) and sends the proposer the reply (section 14);
3. sends the change to its siblings by sibling sync, as every change of the record ([sync.md](sync.md), section 10), and the record to every receiver with which it is shared, the proposer included, as an ordinary `DATA` under the new state stamp or count ([sync.md](sync.md), section 5.1; section 5.3).

A list that leaves out links of the record keeps them (section 19.3). The order of the reply and the update is free. Wherever this document compares two values, it compares them as the values they decode to, each with the schema it was written with, not by their bytes. A value accepted from an entry whose schema is a later version of the type than the one the device writes with, of a field that its own writer schema lacks, holds the record back from other apps by [sync.md](sync.md), section 5.1: the device does not send the update itself, and leaves it to a sibling whose schema has the field. A device that can take no stamp ([sync.md](sync.md), section 2.3) cannot make the change: it records no answer and sends none until it can. A device on which the record is not there, because it is deleted, cannot take the proposal (section 15.4).

### 15.3 A version that the owner left behind

The `record.version` of a proposal is the version of the record that the proposer held when it proposed. A device of the owner compares it with its own state stamp of the record, or its count, only to tell its user:

- **The same version.** The proposal is about the record as the device holds it.
- **A lower version.** The record has changed since the proposer saw it. The device takes and shows the proposal all the same, and SHOULD tell its user that the record has changed since; it MAY show the current value beside each proposed one, as section 15.1 says. Taking the proposal sets the proposed values over whatever the record holds then, as any change of the user does.
- **A higher version.** The proposer holds a version that a sibling gave and this device has not merged yet, or one that this device gave and lost ([protocol.md](protocol.md), section 10). The device takes and shows the proposal as for the same version.

In no case is the version a reason to reject or decline a proposal on its own, and in no case does it count as a stamp seen.

### 15.4 A record withdrawn from the proposer, or deleted

A proposal is about a record that is shared with the proposer and there. For one that is not:

- **When it arrives.** A `PROPOSAL` for a record that is withdrawn from the proposer, no longer shared with it, or deleted, fails step 5 of section 13.3 and is rejected with `PROPOSALS_NOT_TAKEN`. It gets an error and not a reply `DECLINED`: a reply is the answer of the owner's user, and the proposer shows it as such, while this result needs no user. The proposer gets the `WITHDRAW` or the `DELETE` of the record as well, which says why; and an app from which a record was withdrawn learns from the error no more than an app that never got the record (section 13.3).
- **While it is open.** A device on which the record of an open proposal is deleted, or comes to be no longer shared with the proposer, by its user or by sibling sync, drops the proposal (section 17.1), stops showing it, and sends no reply. The proposer learns of it from the `DELETE` or the `WITHDRAW` that it gets (section 17.2). A record that is taken back, or shared again, later does not bring the dropped proposal back; the proposer may propose again.

## 16. No acknowledgement; repeats and errors

### 16.1 No acknowledgement

A `PROPOSAL` is not acknowledged in an `ACK`. An entry of an `ACK` names the acknowledged message by the `id` and the `version` of its `record` ([protocol.md](protocol.md), section 7.1). For a `PROPOSAL` these are the owner's record and the proposer's version, not the proposal: two proposals for the same version of one record would have the same entry, and the entry would be about a record of the acknowledging app, not of the app it goes to, as every entry of an `ACK` of record messages is. `RESYNC` and `FORWARD` can be acknowledged because their `record` names the request or the forward itself ([sync.md](sync.md), sections 11.1 and 18.1); a `PROPOSAL` names its proposal in its body.

So a device of the owner MUST NOT put an entry for a `PROPOSAL` into an `ACK`. The proposer learns the result of a proposal from the reply, or from an `ERROR` for a proposal that failed a step of section 13.3. A proposal that is taken and open has neither, until the owner's user answers it; the proposer sends it again meanwhile (section 16.2). A `PROPOSAL_REPLY` is not acknowledged either (section 14.2).

### 16.2 Sending a proposal again

A proposal that has neither a reply nor an error may not have arrived, or may be open at the owner. For as long as it has neither, the proposing device sends it again:

- **In a live connection**, at the start of each later live connection with the device of `to`.
- **Through a relay**, each time the holding time of 14 days ([transports.md](transports.md), section 5.5) has passed since it last sent it through the relay without a reply or an error, and not before.

This is intended: an open proposal is repeated until the owner's user answers it. The repeats are bounded by the limits of section 18.3, which bound the open proposals of one proposer, and a repeat counts once there.

It sends the same message again, with the same bytes. It stops when it has a reply or an error for the proposal; when the record's last record message from the owner is no longer a `DATA`, because the owner deleted or withdrew it (section 15.4); and when it forgets the owner. When the key in `to` is removed from the owner ([keys.md](keys.md), section 5.5), the device sends the same proposal, with the same `proposal_id`, `record` and `fields`, to another current key of the owner chosen as in section 13.1: a `PROPOSAL` with that key in `to`, signed anew, which it sends again from then on. A device of the owner that holds the proposal or its answer takes it as a repeat (section 13.4), so this is safe. A user who discards the proposed values does not take back a proposal that was sent: no message takes a proposal back. The device MAY stop sending it again then.

A repeat is safe: the owner's device changes nothing for it, apart from keeping the copy with the higher SHA-256, and sends the reply again for a proposal that is answered (section 13.4).

### 16.3 Errors

An `ERROR` is about a `PROPOSAL` when its `message_hash` is the SHA-256 of a `PROPOSAL` that the device sent to the key that sent the `ERROR` ([protocol.md](protocol.md), section 8.1). A device that holds a reply for a proposal already ignores an `ERROR` about it. Otherwise the error settles the proposal, and the device does not send it again, apart from `FORMAT_UNSUPPORTED`, after which it sends it again in a format the owner reads:

| Code                                                                                           | The proposing device then                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| ---------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PROPOSALS_NOT_TAKEN`                                                                          | MAY show its user that the owner did not take the proposal. It sends no new `PROPOSAL` for that record to any key of the owner, the block holding for the owner as a whole, until it holds a manifest of a key of the owner with a higher revision than it held of that key, a record message of the record with a higher version, or a reply to any proposal of its own to that owner, whichever comes first. The block holds back new proposals only: the repeats of its open proposals (section 16.2), and their sending to another key after the key in `to` was removed, go on |
| `SCHEMA_UNKNOWN`                                                                               | MAY show its user that the proposal did not reach the owner. The owner keeps the schemas of the `DATA` it sent (section 15.1), so this is rare. It sends no further `PROPOSAL` for that record until a record message of the record with a higher version reaches it, or until one of the ends of the block after `PROPOSALS_NOT_TAKEN` above                                                                                                                                                                                                                                       |
| `VALUE_INVALID`                                                                                | SHOULD show its user the field that `field` names. It sends no new proposal for that record while the value of the top-level field that `field` begins with equals, as a decoded value, the one it proposed last                                                                                                                                                                                                                                                                                                                                                                    |
| `FORMAT_UNSUPPORTED`                                                                           | writes in the chosen format ([protocol.md](protocol.md), section 3.2) and sends the proposal again in it, as the same message while there is one format; the proposal is not settled                                                                                                                                                                                                                                                                                                                                                                                                |
| `INVALID_MESSAGE`, `RECORD_ID_INVALID`, `VERSION_INVALID`, `UNDECODABLE`, and every other code | logs it; it is a fault of the proposer's implementation, or of a message that was damaged ([protocol.md](protocol.md), section 8.2)                                                                                                                                                                                                                                                                                                                                                                                                                                                 |

## 17. Between devices

### 17.1 The owner's devices

The owner can be a device set. The proposer sends a proposal to one of its devices (section 13.1), which is the answering device for it ([sync.md](sync.md), section 17.1): it processes the `PROPOSAL` by section 13.3 and alone reports an error to the proposer. A proposal is a message of another app that is forwarded ([sync.md](sync.md), section 19.6), so that every device of the set can show it and the user can answer it on any of them:

- **Kept.** A device keeps each `PROPOSAL` that it took, from the proposer itself at step 10 of section 13.3 or in a `FORWARD`, as the bytes it got, among the kept messages of the proposer ([sync.md](sync.md), section 20.1). It keeps it until the first of these: the owner's app holds an answer to the proposal (section 15.1); a change on the device, of its user or taken in a merge with a sibling, deletes the record or takes it out of the shares for the proposer (section 15.4); the device holds the record as deleted, or as not shared with the proposer, and either has merged the record and the app's share records with every other current device of its set since it took the proposal, as [sync.md](sync.md), section 10.4, says, or took the proposal 14 days ago or longer, the bound of that wait in section 5.3; the app's records hold the proposals of that receiver as stopped for the record (section 18.4); the key that signed the `PROPOSAL` is removed from the proposer, which drops the open proposal on every device; or the device forgets the proposer ([sync.md](sync.md), section 20.5). A device shows a kept proposal only while the record is there on it and shared with the proposer by the shares it holds; a sibling whose sibling sync lags behind the answering device so keeps a forwarded proposal without showing it until the record or the share reaches it. A kept `PROPOSAL` is delivered and due for each sibling as every kept message ([sync.md](sync.md), section 20.2).
- **Forwarded.** A device forwards a kept `PROPOSAL` to each sibling for which it is due, in a `FORWARD` whose `schema` is `null` ([sync.md](sync.md), section 18.1), after the additions, the removals, the manifests and the record messages of the proposer that it forwards to that sibling ([sync.md](sync.md), section 20.3). Before it forwards the proposal, it offers that sibling the schema of each entry that it keeps with the proposal, as it offers a schema before a `CHANGE` ([sync.md](sync.md), section 7.2), so that the sibling can show the values.
- **A forwarded `PROPOSAL`.** A sibling processes it after the steps 1 to 14 of [sync.md](sync.md), section 18.3, with these checks, in this order: the body decodes as one `axt.Proposal`, with no bytes left over, and `to` is a current or a removed key of its own set, its own key, a sibling's or the key of a device removed from the set since, as for a forwarded `WITHDRAW` (section 7.1), else `INVALID_MESSAGE`; the steps 2 to 4 of section 13.3, with their codes. The steps 5 to 9 do not apply: the answering device made them, and the sibling's shares, manifest and schemas can differ from that device's until they have merged. The sibling then takes the proposal by section 13.4, without a reply: a new proposal it keeps and holds as open, and the outcome of the forward is `APPLIED`, as it is for one in other bytes that takes the place of the one it holds by the higher SHA-256 (section 13.4); one that it holds already, or whose answer the owner's app holds, it does not take, and the outcome is `DUPLICATE`. Nor does it take one of a receiver whose proposals the app's records hold as stopped for the record (section 18.4): it drops it, and the outcome is `DUPLICATE`. The limits of section 18.3 do not hold back a forwarded `PROPOSAL`: the answering device took it, and the sibling keeps it. A forwarded `PROPOSAL` whose inner sender is a removed key of the proposer is not taken, with the outcome `DUPLICATE`, as a forwarded `MANIFEST` of such a key ([sync.md](sync.md), section 19.4). The sibling sends the proposer nothing ([sync.md](sync.md), section 19.1), and asks its user nothing while it processes the forward; it shows the proposal among the open proposals as section 15.1 says.
- **One answer, one reply.** The device on which the owner's user answers the proposal records the answer (section 15.1) and sends the reply (section 14.1), and for `ACCEPTED` makes the change (section 15.2). The answer reaches the siblings in the records of the app's own type; a sibling that comes to hold it stops showing the proposal, drops its kept `PROPOSAL` and sends no reply. Only a device that got a repeat of an answered proposal from the proposer itself sends the reply again (section 13.4).
- **Two answers.** A user can answer the same proposal on two devices before they have merged. Each device then records its answer and sends its reply; the proposer keeps the first that it gets, and takes a later `ACCEPTED` in the place of a `DECLINED` (section 14.2). Of the two answers that the app's records then hold, `ACCEPTED` stands on every device (section 15.1). A change that an `ACCEPTED` made stands as every change of the record and merges by [sync.md](sync.md), section 4.
- **The reply needs a channel.** A device that sends a reply to a proposer that it knows only by forwards introduces itself first, with its chain and its `MANIFEST`, as [sync.md](sync.md), section 17.2, says of a message of its own for such an app. It sends the reply in a live connection with the proposer's device of `to`, or through the relay when it holds that key's encryption key and relay ([keys.md](keys.md), section 4.2). A device that has neither channel to that device when its user answers sends the reply as soon as it has one.

### 17.2 The proposer's devices

The proposer can be a device set too. Its devices share the received record, with its sender's layer and its owner's layer ([sync.md](sync.md), sections 17 to 22); on these devices the owner's layer holds what the proposer's user did with the record.

- **The proposer's value is its user's change.** The user's new value is a change of the owner's layer of [sync.md](sync.md), section 21.2, on the device on which the user makes it, and reaches its siblings in a `CHANGE` with a key in `origin`, as every such change ([sync.md](sync.md), section 21.3). It stands there before the answer, after `DECLINED` and after an error, until the user discards it, by a change of that section ([records.md](records.md), section 6.1). A reply changes nothing of it.
- **Per field.** An app that lets its user propose changes to records of a type MUST merge per field for the records of that type ([records.md](records.md), section 6.1; the per-field rows of [sync.md](sync.md), section 22.2). The proposed value is then an ordinary owner's value of the owner's layer, on every device of the proposer's set, and stands against every later `DATA` until the user discards it, whichever device applies the `DATA`. It does not end by itself when an update brings the value.
- **After `ACCEPTED`.** The owner's update brings the proposed value. The answering device applies it by [sync.md](sync.md), section 22.2: the user's value is the value that the message has for the field, so it does not count for `MERGED`. The owner's value stays in the layer: where the set counts a field that a `DATA` brings back to the user's value as no longer changed ([records.md](records.md), section 6.1), it discards the change by a change of [sync.md](sync.md), section 21.2, as that section allows, and the devices of the set choose alike ([sync.md](sync.md), section 22.3); otherwise the value stands until the user discards it.
- **One device proposes.** The device on which the user proposes sends the `PROPOSAL`, and only it sends it again (section 16.2). A `PROPOSAL` is a message of the set itself: a device does not forward it to its siblings ([sync.md](sync.md), section 18.3, step 13), and a sibling that has the same values in its owner's layer does not propose them again on its own.
- **The status is the app's affair.** Which proposals were sent, and the replies and errors they got, stay on the device that sent them ([sync.md](sync.md), section 17.3). An app that shows its user the status on every device keeps it as records of a type in its own namespace, as the owner keeps its answers (section 15.1). A reply goes to the key that signed the proposal (section 14.1), so a sibling that gets one for a proposal that it did not send ignores it at step 3 of section 14.2.
- **A proposing device that is removed.** The owner's devices send no reply to a key removed from the proposer (section 14.1). The remaining devices learn of an accepted proposal from the update.

A `PROPOSAL_REPLY` is no message that is forwarded: a device keeps none, and a `FORWARD` that carries one is not valid ([sync.md](sync.md), section 18.2).

## 18. Transports and limits

### 18.1 Live connection and relay

A `PROPOSAL` and a `PROPOSAL_REPLY` need no offer: their bodies have schemas of the specification, and the values in a proposal name schemas with which the owner wrote the record. A proposing device sends a `PROPOSAL` once it holds a manifest of the device in `to` that takes proposals for the type (section 12.2): in a live connection after both `MANIFEST` messages ([protocol.md](protocol.md), section 3.1), and through the relay to that device's mailbox, sealed for its encryption key ([keys.md](keys.md), section 4). An app that sends a `PROPOSAL` through a relay MUST take messages through it, as for an offer ([protocol.md](protocol.md), section 15.1), since the reply comes back the same way. Both kinds are sealed, padded and repeated as every message ([protocol.md](protocol.md), sections 9.2 and 15.1); a repeat of a `PROPOSAL` is handled by section 13.4, and one of a `PROPOSAL_REPLY` by step 5 of section 14.2.

### 18.2 File

No file holds a `PROPOSAL` or a `PROPOSAL_REPLY`. A proposal needs a way back for its reply and its errors, and goes to one device of the owner; a reply is a reply of [protocol.md](protocol.md), section 1, like the `ACK`, and is for the one device that sent the proposal. A file has no way back and is for any device of its reader ([protocol.md](protocol.md), section 15.2). A reader that finds either kind in a file rejects the whole file ([transports.md](transports.md), section 2.2).

### 18.3 Limits

| What                                                                  | Limit                                                                                        |
| --------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| Entries of `fields` in one `PROPOSAL`                                 | 1 to 4,096 (section 13.2)                                                                    |
| A field name in a `PROPOSAL`                                          | 1 to 512 bytes of UTF-8 (section 13.2)                                                       |
| One `PROPOSAL` or `PROPOSAL_REPLY`                                    | 16 MiB, as every message ([envelope.md](envelope.md), section 8)                             |
| Data depth of a proposed value                                        | 32, the record counted as depth 1 (section 13.3, step 8)                                     |
| Value bytes of one `PROPOSAL`, the `value` of every entry together    | 64 KiB (65,536 bytes)                                                                        |
| Value bytes of the open proposals of one proposer in all, at a device | 1 MiB (1,048,576 bytes)                                                                      |
| Open proposals of one proposer for one record, at a device            | 16                                                                                           |
| Open proposals of one proposer in all, at a device                    | 256                                                                                          |
| Sending a proposal again through a relay                              | After the holding time of 14 days, not before (section 16.2)                                 |
| How long the owner's app keeps an answer                              | MUST: as long as the record is shared with the proposer, and at least 15 days (section 15.1) |

- **Open proposals.** A device of the owner MUST NOT take more open proposals of one proposer than the two count limits of the table, nor a `PROPOSAL` whose value bytes are above 64 KiB, nor one that would bring the value bytes of the open proposals of that proposer that it holds above 1 MiB. A `PROPOSAL` that the device gets from the proposer itself and would take as a new proposal beyond one of these limits fails step 5 of section 13.3 with `PROPOSALS_NOT_TAKEN`. A device MAY set lower limits. The limits hold for the proposals that a device takes from the proposer itself, counted over every open proposal of that proposer that it holds, those it took itself and those forwarded to it. A device keeps every forwarded `PROPOSAL` whatever the limits (section 17.1), so a device can hold more than a limit, and devices that have not yet merged can together hold more than a limit for a while.

### 18.4 Unwanted proposals

Every receiver of a record of a type for which the owner takes proposals can propose (section 12.2), and a proposal costs the owner's user attention. Beyond the limits of section 18.3:

- **Stopping one receiver.** An app MAY let its user stop proposals from one receiver, for one record, for one type or for all records. It keeps the stop, with a key of the receiver as in section 13.4, as records of a type in its own namespace, as it keeps its shares and its answers (sections 2.1 and 15.1), so the stop reaches every device of the set. A `PROPOSAL` that its user has stopped fails step 5 of section 13.3 with `PROPOSALS_NOT_TAKEN`, as for a type that takes no proposals. A device drops the kept proposals of a receiver that its records hold as stopped for their record, without a reply, and does not take a forwarded one (section 17.1). The other receivers go on proposing.
- **Stopping every receiver.** An app that takes no more proposals for a type sends a `MANIFEST` with a higher revision in which `proposals` is `false` for it ([manifest.md](manifest.md), sections 3.8 and 6). Its devices reject every later `PROPOSAL` for the type at step 5. The proposals that are open stay open until they are answered or dropped.
- **No user is asked before.** The device takes or rejects a `PROPOSAL` without asking its user; only the answer to a proposal that it took needs the user (section 15.1).
- **What a proposal tells.** A proposer learns from `PROPOSALS_NOT_TAKEN` nothing of whether the owner holds a record with that id (section 13.3). A receiver learns from the `sends` of the owner's manifest for which types it takes proposals, as every app that holds the manifest does.
- **A proposal is a request.** A proposal binds no one. The owner's user may refuse it, leave it open, or take only part of it as a change of their own (section 15.1), and an app that does not conform to this specification can apply what it likes. The proposed values reach no other receiver unless the owner's user takes them, and then as the owner's change.

## 19. Relations and extensions in a share

A shared record can link to records that its owner did not share with the receiver, and to things outside AXT, and can carry the extensions of apps ([fields.md](fields.md), sections 11 and 12). Their ids, display texts, URIs and values would reach another user with it. Each share therefore says whether they go along.

### 19.1 What goes along

The **links** of a record are its relations to records that are not shared with the receiver, its relations to things outside AXT and its extensions. Each share says, for its receiver, whether the links of the records it names go along; by default they do not. A record goes to a receiver of another user (section 2.3):

- **with its links**, whole, where at least one share for that receiver that names the record lets them go along;
- **otherwise without them**: every list of relations holds only the relations to records of the sender's own set that are shared with that receiver, each with a record target whose `sender` is `null` or a key of the sender's set, current or removed ([fields.md](fields.md), section 11.3), and every list of extensions is empty. The other elements are left out, the rest keep their order, and the rules of [fields.md](fields.md), sections 11.4 and 12.3, hold for what remains.

A relation to a record of another sender is never one to a shared record: a share names only records of the sender's own set (section 1). This holds for every relation field and every extension field of the type, also one nested in an object or in a list. An app of the sender's own user, which needs no share (section 2.3), always gets the record whole, its links included, as do the devices of the sender's own set ([sync.md](sync.md), section 7.2).

### 19.2 A link left out is no removal

What a share leaves out stays in the record. The sender takes no stamp and sets no removal mark for it ([sync.md](sync.md), section 25.3): its devices keep the relation or the extension, and every other receiver gets what its own shares let go along. The receiver gets the record without it, as a `DATA` like any other, and merges that list as [records.md](records.md), section 6.1, says. Which links go along is decided for each record message when it is sent: a change of a share, or of whether a target is shared, takes effect with the record's next version. An app MAY send the record under a new state stamp or count for it ([sync.md](sync.md), section 3.3).

### 19.3 Proposals

A proposer proposes a list as it holds it, without the links that it did not get. When the owner takes such a proposal (section 15.2), the proposed list replaces only what the proposer got: every element that the record holds and the share left out for that proposer stays, after the proposed elements in the record's order, unless the proposal holds an element with its key. A device of a set stamps no removal mark for it ([sync.md](sync.md), section 25.6).

## References

- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174): key words for requirement levels
- [RFC 9562](https://www.rfc-editor.org/rfc/rfc9562): UUIDs
