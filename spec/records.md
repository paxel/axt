# Records

Status: written, 0.1.0. Until 0.1.0 is released, [protocol.md](protocol.md) and [keys.md](keys.md) may still change the details this document leaves to them.

This document defines the stable id and the version every record carries, how a sender sends updates and deletions, how a receiver applies them while keeping what its own user changed, the outcomes a receiver reports for each record, and how one record refers to another.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 ([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119), [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)) when, and only when, they appear in all capitals, as shown here.

## 1. Terms

- **Record**: one datum of a type ([types.md](types.md)), such as one Appointment, together with its id and its version. A record travels in the body of a `DATA` message; its id and version travel in the envelope's `record` field ([envelope.md](envelope.md), section 2).
- **Record message**: a `DATA` or a `DELETE` message.
- **Sender** of a record: the app that created the record and sends its versions: one installation, or the installations of one owner on several devices, which [keys.md](keys.md), section 5, makes one device set. A receiver knows a sender by the first key it accepted from it and by the keys added to it and removed from it since. Where this document says "the same sender", it means any current key of that set.
- **Receiver**: an app that takes records from a sender, through a live connection, a relay or a file: one installation, or the devices of one set, of which the sender has to reach only one ([sync.md](sync.md), section 17.2).
- **Local change**: a change the receiver's user makes to a received record in the receiver, including its deletion there.
- **Tombstone**: what a receiver keeps of a record its sender deleted: its id and the version of the deletion.

A record has one sender. Only its sender sends versions of it; where the sender is a device set, each of its devices does, and [sync.md](sync.md) defines how they change the same record. A receiver's local changes stay in the receiver: they are not sent back to the sender and are never versions of the record. Where the receiver is a device set, the record messages that one of its devices got and the local changes travel between its own devices, and only there ([sync.md](sync.md), sections 17 to 22). A receiver that sends a record of its own, even one copied from a received record, sends it as a new record with an id of its own.

## 2. Record ids

The id of a record is a UUID, carried as a `string` with the logical type `uuid` in the representation of [envelope.md](envelope.md), section 7.

- The sender generates the id when it creates the record, and the record keeps it for its whole life: through every update, a deletion and a return after it (section 5.3), and whichever device of its sender sends it ([keys.md](keys.md), section 5.6).
- A sender MUST generate ids as UUIDs of version 4 (random) or version 7 (time-ordered, with random bits) of [RFC 9562](https://www.rfc-editor.org/rfc/rfc9562). It MUST NOT use the nil UUID or the max UUID.
- An id MUST be unique among all records of the sender, of all types. A sender MUST NOT use an id for a second record, also not after the first one was deleted.
- A sender MUST send a record under the same id to every receiver.
- A receiver MUST identify a record by its sender and its id together. A message from another sender that carries the same id is about another record; it is neither an update nor a deletion of the first. A receiver therefore never applies a message from one sender to a record of another, as [keys.md](keys.md) requires.
- A receiver MUST accept ids of every UUID version and variant. It MUST reject a record message whose id is not a UUID in the text form, or is the nil UUID or the max UUID, with the error `RECORD_ID_INVALID` ([protocol.md](protocol.md), section 8.2).

Random ids let every installation create records without a counter or coordination. Ids of different senders do not collide in practice either; a receiver does not rely on that, because it keeps every sender's records apart.

## 3. Versions

The version of a record is a `long`. It names one state of the record at its sender.

- A version MUST be at least 1.
- Each change of a record on a device of its sender MUST get a version higher than every version of the record that this device has given or has seen from another device of its set. For a sender with one device, that is every version the sender has given the record before. A deletion is a change and takes a version as well.
- Two devices of a set that change a record while apart each give it a version without knowing the other's. Their versions are state stamps ([sync.md](sync.md), section 5), whose random part makes two of them that are taken from the same base differ in all but one of 32,768 cases per pair ([sync.md](sync.md), section 2.2). When the two devices merge, each device that takes something from the other's state gives the merged state a version above both; a device that takes nothing keeps its version ([sync.md](sync.md), section 4.4).
- A sender MAY send the same version again, to the same or to another receiver, for example when a message may have been lost, when a receiver is connected later, or in a file.
- Versions MAY have gaps. A sender that changes a record several times before it can send sends only the last state, under its last version.
- One id and version MUST always stand for the same message: the same kind and, for `DATA`, the same record. A sender MAY encode that record with another compatible writer schema of the same full name.
- An installation that is a set of its own MAY count the versions of each record, from 1, adding one for every change it sends, or give state stamps from its first record on. A device whose set has, or has had, a second device MUST give the state stamp of the record as its version, and so MUST an installation that may have lost versions it gave ([sync.md](sync.md), section 2.4). A state stamp is far above any count, so the versions of a record keep rising when its sender begins to stamp. A plain clock time is no version: it goes back when the clock does, which a stamp does not.
- A receiver MUST accept a first version above 1: a receiver that is connected later, or misses messages, sees a record first at a later version. A receiver MUST reject a record message whose version is below 1, with the error `VERSION_INVALID` ([protocol.md](protocol.md), section 8.2).

A device SHOULD keep the highest version it has given each record through whatever its data goes through, including a move to a new device ([keys.md](keys.md), section 5.7). The devices of one sender give the versions of a record as one sender ([keys.md](keys.md), section 5.6): each gives its state stamp of the record, as [sync.md](sync.md), section 5, defines. A device that may have lost versions it gave, such as after a restore from a backup, would give them a second time if it counted on, and a new version that happens to equal the receiver's version is taken for a duplicate, so that the change is lost at that receiver. [protocol.md](protocol.md), section 10, therefore makes such a device give state stamps from then on, which a clock that is not far behind puts above every version it gave before; a version that is still below the receiver's is answered with `STALE` (section 7).

## 4. Sending records

### 4.1 Data

A `DATA` message carries the whole record, every field, in its body ([envelope.md](envelope.md), section 2.2), and the record's id and version in `record`. The first version of a record and every update have the same form; toward another app there is no message that carries only the changed fields. Only the devices of one sender send each other the changed fields of a record alone, in a `CHANGE` message ([sync.md](sync.md), section 8); a receiver never gets one.

An update does not name the version it is based on. It carries the whole state of the record, and the receiver merges it against what it kept of the record itself (section 6). Neither side needs the other's history for that.

### 4.2 Deletion

A `DELETE` message carries the record's id and the version of the deletion in `record`, and an empty body ([envelope.md](envelope.md), section 2.2). A deletion is a version of the record like an update: a `DATA` with a higher version brings the record back (section 5.3), so a sender can undo a deletion under the same id.

### 4.3 The type of a record

A record keeps the full name of its type for its whole life ([types.md](types.md), section 1). A sender MUST send every version of a record with a writer schema of the same full name; a compatible later version of the type ([types.md](types.md), section 3.3) has the same full name. A receiver MUST NOT apply a `DATA` message whose type has another full name than the one it keeps for that id (section 5.1), also when the message brings the record back from a tombstone, and rejects it with the error `TYPE_CHANGED` ([protocol.md](protocol.md), section 8.2).

## 5. Applying records

### 5.1 What a receiver keeps

For every record of every sender, a receiver keeps:

- the sender and the id;
- the full name of the record's type, once a `DATA` message has brought it; a tombstone that a `DELETE` left for an id the receiver did not have holds none, and the first `DATA` that brings the record back sets it;
- the highest version of the record it has seen in a `DATA` or a `DELETE` message, called the receiver's version below;
- whether the record is there, deleted by its sender (a tombstone), or deleted by the receiver's user;
- for a record that is there, what it needs to tell local changes from values it took from the sender (section 6).

A receiver that is a device set keeps this on each of its devices. The device that gets a record message passes it on to the others, so that all come to the same receiver's version of the record, and the local changes are kept apart from what the sender sent, as a layer that the devices merge among themselves ([sync.md](sync.md), sections 17.1 and 21.1).

### 5.2 The version rule

A receiver compares the version of each record message with its own version of the record:

| Version in the message                   | The receiver                                          | Outcome                     |
| ---------------------------------------- | ----------------------------------------------------- | --------------------------- |
| No record under this id from this sender | Takes the record, or keeps a tombstone for a `DELETE` | `APPLIED`                   |
| Higher than the receiver's version       | Applies the message as sections 5.3 and 6 say         | `APPLIED`, `MERGED`, `KEPT` |
| Equal to the receiver's version          | Changes nothing; the message is a duplicate           | `DUPLICATE`                 |
| Lower than the receiver's version        | Changes nothing; the message is older than its state  | `STALE`                     |

The rule is the same for `DATA` and `DELETE`. Whenever the message's version is higher, the receiver's version becomes the message's version, also when the receiver keeps local changes against it (section 6). A receiver MAY skip decoding the body of a `DATA` message that is a duplicate or stale. A receiver that keeps the messages of its senders for the other devices of its set keeps a few duplicate or stale messages all the same, such as a `DATA` below a deletion, and decodes those; the outcome stays as the table gives it ([sync.md](sync.md), sections 19.5 and 20.1).

Transports may deliver a message twice, late or out of order: a relay holds messages, and a user may open an old file again. The version rule makes the result independent of that order: as long as the receiver's user changes nothing, a receiver that has got any set of messages about a record ends in the state of the one with the highest version.

### 5.3 Deletions and tombstones

- A `DELETE` with a higher version deletes the record at the receiver, and the receiver keeps a tombstone with the deletion's version. Section 6.4 says when the receiver keeps the record instead.
- A `DELETE` for an id the receiver does not have from that sender leaves a tombstone as well, so that a `DATA` with a lower version that arrives later does not create the record.
- A `DATA` with a version higher than the tombstone's brings the record back: the receiver takes it as a new record under the same id, and the tombstone ends. A `DATA` with a lower or equal version is stale or a duplicate.
- A receiver MUST keep a tombstone for as long as it keeps the sender, that is, as long as it would accept messages from one of that sender's keys ([keys.md](keys.md)). A tombstone is an id, a version and the sender; a fixed retention time would let an old file or a delayed message bring a deleted record back after it.
- A receiver that forgets a sender MAY forget its records and tombstones with it.

## 6. The receiver's own changes

A receiver MAY let its user change received records. If it does, it either keeps its user's changes when an update or a deletion arrives, or takes the sender's message over them. It SHOULD keep them, as far as it can per field (section 6.1). This section says how a receiver keeps them; section 7 says how it reports what it did.

Where the receiver runs on several devices of one owner, the devices of the set are one receiver. Wherever this section lets a receiver choose, per field or the whole record in sections 6.1 and 6.2, and to delete or to keep in section 6.4, the devices of one set MUST choose alike. The device that got the message from the sender applies this section and reports the outcome; the user's changes, and the user's decisions where a receiver asks, reach the other devices of the set, so that all of them show the same record ([sync.md](sync.md), section 22).

### 6.1 Per field

A receiver SHOULD merge per field. The fields are the top-level fields of the record's writer schema; a nested record, an array or a map is one value. For each field of a `DATA` message with a higher version:

- if the receiver's user has not changed the field, the receiver takes the value from the message;
- if the user has changed it, the receiver keeps the user's value.

A field counts as changed by the user from the user's first change of it until the user discards that change, for example with an action that takes the sender's value again. A receiver MAY tell changed fields by keeping, for each field, the value it last took from the sender and comparing it with the current value. If a message brings the value the user set, the receiver MAY count the field as no longer changed.

Fields of the writer schema that the receiver does not keep or use are not local changes. A receiver that maps a type into a model of its own, such as an Appointment into a reminder, merges the fields it maps in the same way.

The outcome is `MERGED` if the receiver kept at least one value that differs from the value in the message, and `APPLIED` otherwise.

### 6.2 Whole record

A receiver that does not track changes per field treats any local change as a change of the whole record. It then either takes the whole record from the message, outcome `APPLIED`, or keeps the whole record as its user left it, outcome `KEPT`.

### 6.3 A record the user deleted

A record the receiver's user deleted stays deleted: a `DATA` with a higher version MUST NOT bring it back unless the user agrees, and the outcome is `KEPT`. The receiver MAY offer its user to take the record again. The receiver keeps the id and its version of such a record as long as it would keep a tombstone (section 5.3), so that a later update does not create the record again. A `DELETE` with a higher version has the outcome `APPLIED`: the receiver keeps the sender's tombstone (section 5.3), and the user's deletion goes on standing beside it, so a later `DATA` with a higher version has the outcome `KEPT` again until the user takes the record again. A receiver that keeps an owner's layer of its received records keeps the user's deletion there as a removal that stands, on one device or on several ([sync.md](sync.md), sections 21.1 and 22.2); a record that its user deleted while the installation counted gets such a removal when the installation begins to keep an owner's layer.

### 6.4 A deletion meets local changes

When a `DELETE` with a higher version reaches a record that the receiver's user has changed, the receiver either deletes it, outcome `APPLIED`, or keeps it with the user's changes, outcome `KEPT`. A receiver MAY ask its user; [protocol.md](protocol.md), section 7.3, says how it reports the outcome while the user has not decided. A record kept against a deletion stays a record of the sender under the same id: the receiver's version is the deletion's, and a later `DATA` with a higher version is merged into it as sections 6.1 and 6.2 say.

A receiver whose user has not changed the record MUST delete it.

## 7. Outcomes and the acknowledgement

Every record message a receiver processes has one of these outcomes:

| Outcome     | Meaning                                                                                                          |
| ----------- | ---------------------------------------------------------------------------------------------------------------- |
| `APPLIED`   | The receiver took the record, or deleted it, as the message says                                                 |
| `MERGED`    | The receiver took the record except the fields its user had changed; in those it kept its user's values          |
| `KEPT`      | The receiver took nothing from the message, because its user's change covers the whole record (sections 6.2–6.4) |
| `DUPLICATE` | The receiver already had this version and changed nothing                                                        |
| `STALE`     | The receiver already had a higher version and changed nothing                                                    |

A message the receiver cannot process, such as one with an invalid id or version, a changed type, a body it cannot decode or a value that is not valid, has no outcome; the receiver reports it as an error ([protocol.md](protocol.md), section 8) and does not change its version of the record.

A reader of a file applies the same rules and reaches the same outcomes, but a file has no way back to the sender, so nothing is reported. Which failures reject a whole file, and which only the one message, is in [transports.md](transports.md), section 2.2. In a live connection and through a relay, the receiver reports each outcome in an `ACK` message. [protocol.md](protocol.md), section 7, defines the `ACK`: its body schema `axt.Ack`, when it is sent, and that one `ACK` reports up to 4,096 record messages. For each record message, the `ACK` MUST carry:

- the record's id and the version of the message it acknowledges. These are the sender's id and version, although the `ACK`'s own `sender` is the receiver: an `ACK` is about a record of the party it goes to;
- the outcome;
- the receiver's version of the record after the message, which differs from the acknowledged version only for `STALE`;
- for `MERGED`, the names of the fields whose values the receiver kept and that differ from the values in the message, as the writer schema of the message names them.

A sender MAY show its user that a receiver kept changes of its own.

After `STALE`, a device counts the receiver's version as a stamp it has seen, whatever that version is ([sync.md](sync.md), section 2.2). It then compares the receiver's version with the highest version it knows of the record: the higher of its own current version of the record and the highest state stamp of the record it saw from another device of its set ([sync.md](sync.md), section 5.3). It need not remember the versions it gave before.

- **Not above the highest version it knows.** An older message arrived late, or another device of its set sent a state the device has merged. Nothing more needs to be done.
- **Above it.** Another device of its set has sent the receiver a newer state, or the device has lost versions it gave ([protocol.md](protocol.md), section 10), or a device that was removed since gave the version. The device gives state stamps as versions from then on ([sync.md](sync.md), section 2.4), so every version it gives afterwards is above the receiver's. If it is the only current device of its set, it MUST at once take a new state stamp for the record and send the record's current state under it. If its set has other current devices, it waits for them: once it has merged the state of the record with every other current device of its set, and its version of the record is still below the receiver's, it MUST take a new state stamp for the record and send the record's current state under it ([sync.md](sync.md), section 5.3). The receiver would otherwise stay behind for good where the device that gave the higher version was removed, or lost that state, before any merge.

## 8. References between records

A reference is a field whose value is the id of another record of the same sender, such as a Measurement that names the Pet it was taken of. Its type is a `string` with the logical type `uuid`, or `["null", that]` where the reference may be absent. The field's `doc` SHOULD name the type or types of the records it refers to. A receiver that does not know the type cannot tell a reference from another `uuid` field; 0.1.0 has no attribute that marks references in a schema.

- A reference MUST name a record of the same sender. A sender MUST NOT put the id of a record it received from another app into a reference. References across senders are not defined in 0.1.0.
- A receiver resolves a reference by the sender of the record that holds it and the id in it, among that sender's records of all types.
- A reference may be unresolved: the record it names may not have arrived yet, may be of a type the receiver declined ([protocol.md](protocol.md), section 5), or may be deleted. A receiver MUST NOT reject a record, or hold it back, because a reference in it is unresolved. It keeps the id and resolves it when the record arrives or comes back. It MAY show an unresolved reference as missing.
- The deletion of a record does not change the records that refer to it. If their meaning changes with it, the sender sends new versions of them.
- A reference is a field like any other when the receiver merges (section 6.1).

The example types of version 1 carry no references; Measurement names what was measured as text in `subject` ([types.md](types.md), section 7.1).

## 9. Example

A sender keeps an appointment at the vet as an `axt.example.v1.Appointment` with the id `3f2c8a5e-9b1d-4c7e-8a6f-2d4b5c6e7f80` and sends it to a receiver that lets its user change received records and merges per field. The times are `axt.DateTime` values ([time.md](time.md), section 6), shown by their wall clock; the fields not shown keep their defaults. Every message's `record` carries the id above and the version in the table.

| Step | What happens                                                                                                                                               | Message, `record.version` | Receiver's version before | Outcome                   | Receiver's version after |
| ---- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------- | ------------------------- | ------------------------- | ------------------------ |
| 1    | The sender creates the appointment: `title` "Vet", `start` 2025-11-18 10:00, `location` ""                                                                 | `DATA`, 1                 | none                      | `APPLIED`                 | 1                        |
| 2    | The receiver's user sets `location` to "Dr. Weber, Hauptstr. 5"                                                                                            | none                      | 1                         | none                      | 1                        |
| 3    | The sender moves `start` to 10:30 (version 2, not sent: no connection), then sets `notes` to "Bring the vaccination card" (version 3) and sends the record | `DATA`, 3                 | 1                         | `MERGED`, kept `location` | 3                        |
| 4    | The relay delivers the message of step 3 a second time                                                                                                     | `DATA`, 3                 | 3                         | `DUPLICATE`               | 3                        |
| 5    | The receiver's user opens an old file that holds the message of step 1                                                                                     | `DATA`, 1                 | 3                         | `STALE`, not reported     | 3                        |
| 6    | The sender's user cancels the appointment                                                                                                                  | `DELETE`, 4               | 3                         | `APPLIED`                 | 4, tombstone             |
| 7    | The sender's user undoes the cancellation                                                                                                                  | `DATA`, 5                 | 4, tombstone              | `APPLIED`                 | 5                        |

- In step 3 the receiver takes `start` 10:30 and the `notes` from the message and keeps its user's `location`, since the message still carries "". The `ACK` reports the id, version 3, `MERGED`, the receiver's version 3 and the field `location`.
- In step 5 the message comes from a file, so no `ACK` goes back. Through a relay, the same message would be acknowledged as `STALE` with the receiver's version 3, a version the sender has sent itself, so nothing needs to be done.
- In step 6 this receiver deletes the record although its user had changed `location`. A receiver that keeps it (section 6.4) reports `KEPT`; its version is 4 as well, and in step 7 it would merge version 5 into the kept record and report `MERGED` with the field `location`.
- In step 7 the record comes back under the same id, as the sender sent it. The user's `location` went with the deletion in step 6.

## References

- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174): key words for requirement levels
- [RFC 9562](https://www.rfc-editor.org/rfc/rfc9562): UUIDs
