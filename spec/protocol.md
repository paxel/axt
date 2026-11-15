# Protocol

Status: written, 0.1.0. Until 0.1.0 is released, [transports.md](transports.md) may still change the details this document leaves to it, and the schemas of the protocol messages may still change in place; their fingerprints (section 16) and the example (section 17) are then produced again.

This document defines the steps of an exchange between two apps: the first messages of a live connection and the choice of the envelope format, the offer of types with their schemas, the acceptance or refusal of each type, the record messages, the acknowledgement and the error report. It defines the bodies of the messages `OFFER`, `ACCEPT`, `DECLINE`, `ACK` and `ERROR`, how each message is bound to the app it is for and made safe to repeat, timeouts, resends, what a declined or interrupted exchange leaves behind, and how the same messages behave in a live connection, through a relay and in a file.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 ([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119), [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)) when, and only when, they appear in all capitals, as shown here.

## 1. Terms

- **Sender** and **receiver**: as in [records.md](records.md), section 1. In an exchange between two apps each is the sender of the records it offers and the receiver of the records the other offers.
- **Channel**: the way two apps exchange messages: one live connection ([transports.md](transports.md), section 4), or the relay ([transports.md](transports.md), section 5). Two apps can use several channels one after the other, or at the same time.
- **Exchange**: an offer, its answers, and the record messages and acknowledgements that follow it.
- **Offer**: an `OFFER` message. It names the types whose records the sender wants to send and carries their writer schemas.
- **Answer**: an `ACCEPT` or `DECLINE` message. It names one offer and some of its types.
- **Accepted offer of a type**: an offer that includes the type, that the receiver has accepted for that type, and that has not ended (section 4.3).
- **Record message**: a `DATA` or `DELETE` message ([records.md](records.md), section 1).
- **Reply**: an `ACCEPT`, `DECLINE`, `ACK` or `ERROR` message; it is about messages of the app it goes to.
- **Addressee**: the app a message is for. Its key is in the `to` field of the body (section 9.1).

The receiver's user confirms the other app's key before the two apps exchange records ([keys.md](keys.md), section 3.2). Nothing in this document applies to a message from a key that the receiver's user has not accepted, except that the receiver reads the app name from its `MANIFEST` and MAY keep its messages until the user decides, as [keys.md](keys.md), section 3.2, says.

## 2. Messages

| Kind       | `record` | Body                                               | `to` in the body | Sent by                    | In a file                        |
| ---------- | -------- | -------------------------------------------------- | ---------------- | -------------------------- | -------------------------------- |
| `MANIFEST` | `null`   | `axt.Manifest` ([manifest.md](manifest.md))        | no               | each app, about itself     | at most one, after the key moves |
| `OFFER`    | `null`   | `axt.Offer` (section 4)                            | yes              | the sender                 | no                               |
| `ACCEPT`   | `null`   | `axt.Accept` (section 5)                           | yes              | the receiver               | no                               |
| `DECLINE`  | `null`   | `axt.Decline` (section 5)                          | yes              | the receiver               | no                               |
| `DATA`     | required | the record ([records.md](records.md), section 4.1) | no               | the sender                 | yes                              |
| `DELETE`   | required | empty ([records.md](records.md), section 4.2)      | no               | the sender                 | yes                              |
| `ACK`      | `null`   | `axt.Ack` (section 7)                              | yes              | the receiver               | no                               |
| `ERROR`    | `null`   | `axt.Error` (section 8)                            | yes              | the app that got a message | no                               |
| `KEY_MOVE` | `null`   | `axt.KeyMove` ([keys.md](keys.md), section 5)      | no               | a sender whose key moved   | at the start                     |

The column "In a file" is that of [transports.md](transports.md), section 2.1. The schemas are in [types/axt/](../types/axt/); their fingerprints are in section 16. Each is a schema of the specification and changes only with a new envelope format ([manifest.md](manifest.md), section 2). An app MUST reject a message whose `record` is present where the table says `null` or absent where it is required, and a message whose body fingerprint is not the one of its kind and format ([envelope.md](envelope.md), section 3.1), with the error `INVALID_MESSAGE` (section 8).

`MANIFEST`, `DATA`, `DELETE` and `KEY_MOVE` are the same for every receiver: a manifest says what an app takes, a record message is sent under the same id to every receiver ([records.md](records.md), section 2), and a key move is for every app that knows the key. They carry no addressee, so that they keep their signature when they are passed on or put into a file ([keys.md](keys.md), sections 2.2 and 2.6). An offer depends on the receiver's manifest and the replies on the messages of one app, so their bodies name the app they are for.

## 3. Opening a live connection

### 3.1 The first messages

When a live connection is open, after both apps' `HELLO` ([transports.md](transports.md), section 4.6), each app:

1. sends the `KEY_MOVE` messages of section 3.3, if it has any for the other app;
2. sends its `MANIFEST` ([manifest.md](manifest.md), section 5.1), in the format of section 3.2;
3. waits for a valid `MANIFEST` of the other app.

Neither app waits for the other before it sends these. An app MUST send its `MANIFEST` before any message of another kind except `KEY_MOVE`. An app MUST NOT process a message of another kind than `MANIFEST`, `KEY_MOVE` or `ERROR` that arrives before the other app's valid `MANIFEST`; it MAY close the connection.

An app MUST NOT send an `OFFER` before it has received a valid `MANIFEST` of the other app in the connection ([manifest.md](manifest.md), section 5.1), and before its user has accepted the other app's key ([keys.md](keys.md), section 3.2). It MAY answer offers and send acknowledgements as soon as it has the other app's valid `MANIFEST` and its user has accepted the key. Errors are reported as section 8.3 says.

A `MANIFEST` that is not valid ([manifest.md](manifest.md), section 4) is reported with `MANIFEST_INVALID` (section 8). The app keeps the manifest it had of the other app before, if any, and does not offer by a manifest it has not received in the connection. The other app MAY send a valid `MANIFEST` later in the connection; until then, nothing is offered to it.

### 3.2 The envelope format

A `MANIFEST` is written before an app knows the formats of the other. Each app writes the `MANIFEST` of step 2 in the lowest envelope format it supports. In 0.1.0 there is one format, `1`, and every app supports it.

When an app has the other app's valid `MANIFEST`, it writes every further message to it in the **chosen format**: the highest format that is both one it writes and one in the other app's `formats`. Each direction of a connection has its own chosen format; for two apps of 0.1.0 both are `1`.

- If the format of the app's own `MANIFEST` is not in the other app's `formats`, the other app could not read it. The app sends its `MANIFEST` again, in the chosen format.
- If there is no chosen format, the two apps have no format in common. The app MUST NOT send further messages and closes the connection.
- A later `MANIFEST` of the other app with other `formats` changes the chosen format from its arrival on ([manifest.md](manifest.md), section 6).

A message whose envelope fingerprint is not of a format the receiver supports is rejected without decoding ([envelope.md](envelope.md), section 3.1). Before the receiver has the other app's `MANIFEST`, it does not report it: it cannot verify the message, and the exchange of manifests above resolves a `MANIFEST` in an unread format. After that, it reports it with `FORMAT_UNSUPPORTED` (section 8), whose `fingerprint` is the message's envelope fingerprint.

### 3.3 Key moves in a connection

An installation that has moved its key ([keys.md](keys.md), section 5) sends, as the first messages of every live connection with an app it exchanged with before the move, the chain of its `KEY_MOVE` messages, oldest first, before its `MANIFEST`. It does so until it has an answer from that app:

- **Acknowledged.** The receiver applied the move: it sends an `ACK` whose `to` is the new key and whose `moved_from` is the key it knew the sender by (section 7.1). It sends the same `ACK` again for a repeat of a move it has applied ([keys.md](keys.md), section 5.3, step 2), so that a lost acknowledgement does not leave the sender resending forever.
- **Rejected.** The receiver's user declined the move, or the move fails a check of [keys.md](keys.md), section 5.3, other than step 3. In a live connection, the receiver sends `KEY_MOVE_REJECTED` (section 8) on the connection. Its `to` is the move's old key, the `sender` of the `KEY_MOVE`, which the new installation takes as one of its moved-from keys (section 9.1). The new installation stops sending the move to that app, and the app meets the new key as a first contact ([keys.md](keys.md), section 3.2). Through a relay, the receiver has no encryption key it may use for the new installation ([keys.md](keys.md), section 4.2), so it sends nothing; the bound below ends the resends.
- **No answer.** A receiver that knows neither key ignores the move without a reply ([keys.md](keys.md), section 5.3, step 3). The new installation stops sending the move to an app after it has sent it in three live connections, or three times through the relay (section 11), without an answer.

The receiver asks its user before it applies a move ([keys.md](keys.md), section 5.3, step 6). Until the user decides, the messages signed with the new key are those of an unknown key: the receiver keeps them, and processes them as the sender's once the user confirms the move. Through a relay, the new installation sends the `KEY_MOVE` as its first message ([keys.md](keys.md), section 5.2). The acknowledgement, or the bound of three sends, ends its resends.

## 4. The offer

### 4.1 Content

An `OFFER` message carries `record` `null` and one `axt.Offer` as its body ([types/axt/Offer.avsc](../types/axt/Offer.avsc)):

| Field            | Avro type                     | Content                                                                                            |
| ---------------- | ----------------------------- | -------------------------------------------------------------------------------------------------- |
| `to`             | `fixed` of 32, `axt.OfferTo`  | The Ed25519 public key of the receiver                                                             |
| `offer_id`       | `string`, logical type `uuid` | The id of the offer                                                                                |
| `types`          | array of `axt.OfferType`      | The types offered                                                                                  |
| `types[].schema` | `string`                      | The writer schema of the type, as its full JSON text                                               |
| `types[].count`  | `long`                        | The number of record messages of the type the sender is about to send under the offer, for display |

- `schema` is the schema's full JSON text, with its `doc` attributes, `axt.version` and every other attribute, as the sender writes it. The offer's signature covers it, as [keys.md](keys.md), section 2.4, requires. The type's full name, version ([manifest.md](manifest.md), section 3.4) and fingerprint ([envelope.md](envelope.md), section 5) are those of this schema; the offer does not repeat them.
- `offer_id` is a version 4 or version 7 UUID of [RFC 9562](https://www.rfc-editor.org/rfc/rfc9562) in lower-case text form, which the sender generates for the offer. A sender MUST NOT use an id for a second offer, to the same or another receiver. One offer id always stands for the same offer.
- `count` lets the receiver show its user what is coming, such as "cat-a-log wants to send 1 Appointment". It is `0` when the sender does not say. It does not limit what the sender sends under the offer, and a receiver MUST NOT reject record messages because they exceed it.

The offer does not list the records. Each record message stands for itself ([keys.md](keys.md), section 2.5), the receiver needs no list to apply it, and a list would make an offer grow with every record.

### 4.2 Validity and limits

An offer is valid when:

- `offer_id` is a UUID in text form and neither the nil UUID nor the max UUID;
- `types` has 1 to 256 entries;
- each `schema` is within the schema limits of [envelope.md](envelope.md), section 8: 256 KiB of JSON text, nested to a depth of at most 64;
- each `schema` is a JSON text ([RFC 8259](https://www.rfc-editor.org/rfc/rfc8259)) that is an Avro 1.12 schema of a record;
- no full name and no fingerprint appears twice in `types` ([envelope.md](envelope.md), section 5);
- each `count` is at least 0.

A receiver MUST reject an offer that is not valid, and MUST NOT accept any of its types. It reports a schema above the schema limits with `TOO_LARGE`, as [envelope.md](envelope.md), section 8, requires, and every other breach with `OFFER_INVALID` (section 8). An offer whose `to` is not the receiver's key is not for the receiver: it ignores it without a report (section 9.1).

A type that does not fit the receiver's manifest, or whose schema does not resolve against the receiver's, does not make an offer invalid; the receiver declines the type (section 5.2).

A sender MUST offer only types that fit the receiver's manifest ([manifest.md](manifest.md), section 5.3). A set of types whose schemas do not fit into one message of 16 MiB is offered in several offers.

### 4.3 How long an offer stays open

An offer belongs to the channel it was sent through.

- **Live connection.** An offer made in a live connection ends when the connection ends. A new connection starts again with manifests and offers (section 3.1).
- **Relay.** An offer made through the relay does not end with time; it ends only for one of the reasons below.
- **Both.** An offer also ends for a type when the sender makes a later offer of that type in the same channel, and when the type no longer fits the receiver's manifest ([manifest.md](manifest.md), section 6). It ends for every type when the receiver forgets the sender, or the sender forgets the receiver ([keys.md](keys.md), section 3.4).

An offer that has ended for a type no longer allows record messages of that type. Its schemas are no longer used for decoding (section 6.2); [envelope.md](envelope.md), section 3, keeps a schema for as long as this section keeps the offer open.

Each exchange starts with an offer. The records a sender wants to send, and their updates and deletions, all follow the same steps: offer, answer, record messages, acknowledgement.

- **In a live connection**, an accepted offer covers the record messages of its type for the rest of the connection, including changes the sender's user makes while the connection is open.
- **Through a relay**, an accepted offer covers the record messages that were due when the sender made the offer, and their resends (section 11). For a record that changes after the offer, the sender makes a new offer. Through a relay, an exchange therefore takes three trips before its acknowledgement: the offer, the answer and the records. A receiver that has stored its user's answer can answer at once (section 5.2).

The receiver keeps, for each sender, channel and type, the **current offer**: the last offer of that type it got from the sender in that channel, its schema and its answer. A sender may make offers through the relay faster than they arrive, and a relay may deliver them out of order. A receiver that gets again an offer it has already answered answers it again as before, and the offer does not become current again (section 9.2). A receiver SHOULD keep the ids of the offers it answered through the relay, with their answers, for at least as long as a relay may hold a message: 15 days ([transports.md](transports.md), section 5.5).

## 5. Accept and decline

### 5.1 Content

An `ACCEPT` or `DECLINE` message carries `record` `null` and one `axt.Accept` or `axt.Decline` as its body ([types/axt/Accept.avsc](../types/axt/Accept.avsc), [types/axt/Decline.avsc](../types/axt/Decline.avsc)):

| Field            | In        | Avro type                     | Content                                      |
| ---------------- | --------- | ----------------------------- | -------------------------------------------- |
| `to`             | both      | `fixed` of 32                 | The Ed25519 public key of the offer's sender |
| `offer_id`       | both      | `string`, logical type `uuid` | The id of the offer this message answers     |
| `types`          | `ACCEPT`  | array of `string`             | The full names of the types taken            |
| `types[].type`   | `DECLINE` | `string`                      | The full name of a type not taken            |
| `types[].reason` | `DECLINE` | enum `axt.DeclineReason`      | Why it is not taken                          |

| Reason             | Meaning                                                                                                                      |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------- |
| `NOT_WANTED`       | The receiver, or its user, chose not to take the type                                                                        |
| `DOES_NOT_FIT`     | The type, in the offered version, does not fit the receiver's current manifest ([manifest.md](manifest.md), section 5.2)     |
| `DOES_NOT_RESOLVE` | The offered schema does not resolve against the receiver's reader schema of the type ([envelope.md](envelope.md), section 6) |

`types` has 1 to 256 entries in both messages. Each entry MUST name a type of the offer, and no type appears twice in one message.

### 5.2 Answering

A receiver answers each type of a valid offer once, either in an `ACCEPT` or in a `DECLINE`. It MAY answer the types of one offer in several messages, for example the types it decides on its own at once and the others when its user has chosen. A type that the receiver does not answer is neither accepted nor declined; the sender sends no records of it.

- A receiver MUST decline a type that does not fit its current manifest, with `DOES_NOT_FIT`. It judges by the manifest it has when it answers, not by the one it sent ([manifest.md](manifest.md), section 5.4).
- A receiver that has a reader schema of the type MUST decline it with `DOES_NOT_RESOLVE` when the offered schema does not resolve against it ([envelope.md](envelope.md), section 6). A receiver that takes the type as any type and has no reader schema of it reads its records with the writer schema alone.
- A receiver MAY decline any type with `NOT_WANTED`.
- A receiver MUST NOT accept a type that it has declined for the same offer, and MUST NOT answer a type of an offer differently a second time.

A fit is not an acceptance ([manifest.md](manifest.md), section 5.4): the receiver's user decides whether the records are taken. A receiver MAY keep its user's answer for a sender and a type and give it to later offers of that type from the same sender without asking again. It SHOULD let its user change such an answer, and SHOULD ask again when a later offer has a schema of another version.

### 5.3 What the sender takes

The sender of an offer takes an answer when its `to` is the sender's key (section 9.1), it names an offer the sender made to the app that sent the answer, and each type it names is a type of that offer. An answer whose types are not types of the offer, or that names a type twice, is reported with `INVALID_MESSAGE`. Of each answered type, the sender takes:

- only the answer to its latest offer of that type to that receiver in that channel; it ignores answers to earlier offers of the type, since a later offer replaced them (section 4.3);
- only the first answer for that offer and type. A later `ACCEPT` or `DECLINE` of the same offer and type, a repeat or a reordered message, is ignored.

After an `ACCEPT` of a type, the sender may send the type's record messages (section 6.1). After a `DECLINE`, it sends none, and SHOULD NOT offer the type to that receiver again until the cause has changed. For `NOT_WANTED`, that means its user asks to offer it again. For `DOES_NOT_FIT`, the receiver's manifest has a higher revision. For `DOES_NOT_RESOLVE`, the sender has another schema of the type.

### 5.4 Two kinds

`ACCEPT` and `DECLINE` stay two kinds of the envelope rather than one kind with a field for the decision. A declined type carries a reason and an accepted one carries none, and each kind has one body schema ([envelope.md](envelope.md), section 2.2). An offer of several types that are partly taken is answered with one message of each kind, as in the example of section 17. Keeping both kinds also leaves the envelope schema of [envelope.md](envelope.md), its fingerprint and the examples built on it as they are.

## 6. Records

### 6.1 Sending

- A sender MUST NOT send a record message of a type unless it has an accepted offer of that type in the channel (section 4.3). It writes each `DATA` with the schema that offer carries for the type. A `DATA` message thus uses only a schema its sender offered in a signed `OFFER` ([keys.md](keys.md), section 2.4).
- A `DELETE` is sent under an accepted offer of the type of the record it deletes.
- The sender MAY send the record messages of an offer in any order, and MAY send them without waiting for acknowledgements. Records that refer to each other need not arrive in any order ([records.md](records.md), section 8).
- A sender MUST NOT send a record message of a type whose offer has ended (section 4.3). It offers the type again first.

The steps are the same for a new record, an update and a deletion ([records.md](records.md), section 4; [manifest.md](manifest.md), section 5.3).

### 6.2 Processing

A receiver processes a record message in these steps. A step that fails ends the processing: the message has no outcome, the receiver changes nothing, and it reports the failure with the error code named ([records.md](records.md), section 7).

| Step | Check                                                                                                                                                                                                                     | If it fails         |
| ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------- |
| 1    | The message and its envelope are valid, and its signature verifies, as for every message (section 8.2)                                                                                                                    | as section 8.2 says |
| 2    | The id is a UUID in text form, neither the nil UUID nor the max UUID ([records.md](records.md), section 2)                                                                                                                | `RECORD_ID_INVALID` |
| 3    | The version is at least 1 ([records.md](records.md), section 3)                                                                                                                                                           | `VERSION_INVALID`   |
| 4    | `DATA`: the body is a single-object encoding whose fingerprint is that of the schema of a current offer of the sender in the channel                                                                                      | `SCHEMA_UNKNOWN`    |
| 5    | `DATA`: that offer is accepted for the schema's type, and the type, in the schema's version, still fits the receiver's manifest. `DELETE`: as below                                                                       | `NOT_ACCEPTED`      |
| 6    | `DATA`: the receiver keeps no other full name for the id ([records.md](records.md), section 4.3)                                                                                                                          | `TYPE_CHANGED`      |
| 7    | The version rule ([records.md](records.md), section 5.2): a version equal to or below the receiver's version has the outcome `DUPLICATE` or `STALE`, and the processing ends with it                                      | (no failure)        |
| 8    | `DATA`: the body decodes with the offered schema, resolved against the receiver's reader schema, with no bytes left over, with well-formed strings, and to a data depth of at most 32 ([types.md](types.md), section 5.7) | `UNDECODABLE`       |
| 9    | The receiver applies the message ([records.md](records.md), sections 5 and 6)                                                                                                                                             | (no failure)        |

A `DELETE` has no body and so names no type. The receiver checks step 5 for it by the type it keeps for the id. A `DELETE` of an id whose record or tombstone holds a type needs an accepted offer of that type. A `DELETE` of an id for which the receiver keeps no type, because it does not know the id ([records.md](records.md), section 5.3) or keeps only a tombstone without a type, needs an accepted offer of any type from the same sender in the channel.

The receiver decodes a body only with the schema of the current offer whose fingerprint the body names, and only among that sender's offers ([keys.md](keys.md), section 2.4). It MUST NOT try other schemas in its place ([envelope.md](envelope.md), section 3.1). `SCHEMA_UNKNOWN` is both the rejection and the request for the schema that [envelope.md](envelope.md), section 3.1, names. The error's `fingerprint` is the body's fingerprint, and the sender answers it by offering the type again (section 8.2).

A receiver MAY stop decoding a body as soon as it exceeds the data depth of 32; it MUST NOT apply any part of it.

## 7. Acknowledgement

### 7.1 Content

An `ACK` message carries `record` `null` and one `axt.Ack` as its body ([types/axt/Ack.avsc](../types/axt/Ack.avsc)). One `ACK` reports up to 4,096 record messages:

| Field                        | Avro type                     | Content                                                                                    |
| ---------------------------- | ----------------------------- | ------------------------------------------------------------------------------------------ |
| `to`                         | `fixed` of 32                 | The current key, as the receiver knows it, of the sender of the acknowledged messages      |
| `records`                    | array of `axt.AckRecord`      | The outcomes, 0 to 4,096                                                                   |
| `records[].id`               | `string`, logical type `uuid` | The record's id, as the acknowledged message carried it                                    |
| `records[].version`          | `long`                        | The version of the acknowledged message                                                    |
| `records[].outcome`          | enum `axt.AckOutcome`         | `APPLIED`, `MERGED`, `KEPT`, `DUPLICATE` or `STALE` ([records.md](records.md), section 7)  |
| `records[].receiver_version` | `long`                        | The receiver's version of the record after the message                                     |
| `records[].kept_fields`      | array of `string`             | For `MERGED`, the fields the receiver kept, by the names of the message's writer schema    |
| `moved_from`                 | `null` or `fixed` of 32       | The key the receiver knew the sender by before it applied a key move to `to` (section 3.3) |

An `ACK` is valid when:

- `records` has at most 4,096 entries, and is empty only when `moved_from` is not `null`;
- each `id` is a UUID in text form, neither nil nor max, and each `version` is at least 1;
- no id and version appears twice; ids are compared as 128-bit values ([envelope.md](envelope.md), section 7);
- for `STALE`, `receiver_version` is above `version`, and for every other outcome it is equal to `version`;
- `kept_fields` is not empty for `MERGED` and empty for every other outcome, and names no field twice.

A sender MUST report an `ACK` that is not valid with `INVALID_MESSAGE` and take none of its entries.

### 7.2 When

- A receiver MUST acknowledge every record message it processed to an outcome (section 6.2), and only those. A message that failed a step is reported with an `ERROR`, not acknowledged.
- It SHOULD send the `ACK` within 5 seconds of processing the message, and MAY collect the outcomes of the messages it processed in that time into one `ACK`.
- In a live connection, it SHOULD send the acknowledgements it owes before it closes the connection. A message it processed but did not acknowledge is sent again (section 11) and then gets `DUPLICATE`.
- A reader of a file sends no acknowledgement ([records.md](records.md), section 7).

### 7.3 Outcomes decided later

A receiver MAY ask its user before it takes a record message: when a `DELETE` meets local changes ([records.md](records.md), section 6.4), or when a `DATA` would bring back a record its user deleted ([records.md](records.md), section 6.3). It MUST NOT hold back the acknowledgement until the user decides. It reports what it has done so far, which is `KEPT` or `MERGED`: the record stays as the user left it, and the receiver's version is the message's version.

When the user later decides to take the message, the receiver sends a further `ACK` with the same id and version and the outcome `APPLIED`. A sender that has `KEPT` or `MERGED` for an id and version takes a later `APPLIED` for the same id and version over it, in whatever order the two arrive. This is the only change of an outcome: a decision of the user not to take the message leaves the `KEPT` or `MERGED` it already has.

### 7.4 What the sender does with an acknowledgement

The sender takes the entries of a valid `ACK` whose `to` is its key or one of its moved-from keys ([keys.md](keys.md), section 1). For each id and version:

- The first outcome it gets stands, with two exceptions: `APPLIED` replaces `KEPT` and `MERGED` (section 7.3), and every other outcome replaces `DUPLICATE`, which a resend can bring before the acknowledgement of the first copy. A repeated entry, and `DUPLICATE` for a message it has another outcome for, change nothing.
- It MAY show its user that the receiver kept changes of its own (`MERGED`, `KEPT`).
- After `STALE`, it acts as [records.md](records.md), section 7, says: a `receiver_version` above the highest version it knows of the record means that its versions went back (section 10).
- A message with an outcome is delivered. The sender does not send it again, except for the reasons of section 11.

## 8. Errors

### 8.1 Content

An `ERROR` message carries `record` `null` and one `axt.Error` as its body ([types/axt/Error.avsc](../types/axt/Error.avsc)):

| Field          | Avro type                   | Content                                                                                                                                                                                    |
| -------------- | --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `to`           | `fixed` of 32               | The Ed25519 public key of the app that sent the reported message                                                                                                                           |
| `code`         | enum `axt.ErrorCode`        | Why the message was not processed (section 8.2)                                                                                                                                            |
| `message_hash` | `fixed` of 32               | The SHA-256 of the reported message as received, from its single-object marker to its last byte; through a relay, after opening and removing the padding ([keys.md](keys.md), section 4.5) |
| `record`       | `null` or `axt.ErrorRecord` | The `record` field of the reported message, as it carried it: `id` as a plain string and `version`                                                                                         |
| `fingerprint`  | `null` or `fixed` of 8      | For `SCHEMA_UNKNOWN` the body's fingerprint, for `FORMAT_UNSUPPORTED` the envelope's; `null` otherwise                                                                                     |
| `detail`       | `string`                    | A description for logs, in English, on one line of at most 1,024 bytes; may be empty                                                                                                       |

`record` is present when the reported message's signature verified, it carried a `record`, and its id is at most 64 bytes long; it is `null` otherwise. Its `id` is a plain string, because the id it reports may not be a UUID. `message_hash` names the message exactly, also one that could not be decoded; the sender can match it against the messages it sent. `detail` is for logs and support. An app MUST show it as text only, and MUST NOT show it to its user as the only explanation of an error.

### 8.2 Codes

The receiver checks every message in this order: size, envelope, signature, sender, addressee, body ([keys.md](keys.md), section 2.3, allows reading the format and the end before the signature is verified). The first check that fails gives the code.

| Code                 | The receiver got                                                                                                                                                                                                                                                                                                                                                                                                                                                     | The sender then                                                                          |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `TOO_LARGE`          | A message above 16 MiB, rejected without decoding, or an offer with a schema above the schema limits ([envelope.md](envelope.md), section 8)                                                                                                                                                                                                                                                                                                                         | Stops sending it; a sender that produced it breaks [envelope.md](envelope.md), section 8 |
| `FORMAT_UNSUPPORTED` | A message whose envelope fingerprint is not of a format the receiver supports (section 3.2)                                                                                                                                                                                                                                                                                                                                                                          | Writes in the chosen format                                                              |
| `INVALID_MESSAGE`    | Bytes that are not a valid message of their kind: bytes left over after the envelope or the body, a body that is not the kind's schema, a `record` where none belongs or none where one is required, a `format` field that is not the envelope fingerprint's format ([keys.md](keys.md), section 2.2), a string that is not well-formed UTF-8 in the envelope or a body of this specification, an answer of section 5.3 or an `ACK` of section 7.1 that is not valid | Logs it; it is a fault of the sender's implementation                                    |
| `SIGNATURE_INVALID`  | A message whose signature does not verify ([keys.md](keys.md), section 2.3)                                                                                                                                                                                                                                                                                                                                                                                          | Logs it                                                                                  |
| `MANIFEST_INVALID`   | A `MANIFEST` that is not valid ([manifest.md](manifest.md), section 4)                                                                                                                                                                                                                                                                                                                                                                                               | Sends a valid one; until then the receiver offers it nothing                             |
| `OFFER_INVALID`      | An `OFFER` that is not valid (section 4.2), other than for its size                                                                                                                                                                                                                                                                                                                                                                                                  | Sends no record messages under it                                                        |
| `RECORD_ID_INVALID`  | A record message whose id is not a UUID in text form, or is the nil or the max UUID                                                                                                                                                                                                                                                                                                                                                                                  | Logs it                                                                                  |
| `VERSION_INVALID`    | A record message whose version is below 1                                                                                                                                                                                                                                                                                                                                                                                                                            | Logs it                                                                                  |
| `SCHEMA_UNKNOWN`     | A `DATA` whose body fingerprint is not that of the schema of a current offer of its sender in the channel                                                                                                                                                                                                                                                                                                                                                            | Offers the type again with that schema, and sends the record again once it is accepted   |
| `NOT_ACCEPTED`       | A record message of a type without an accepted offer in the channel, or of a type that no longer fits the receiver's manifest (section 6.2, step 5)                                                                                                                                                                                                                                                                                                                  | Stops sending records of the type there; offers it again if it fits                      |
| `TYPE_CHANGED`       | A `DATA` whose type has another full name than the one the receiver keeps for the id ([records.md](records.md), section 4.3)                                                                                                                                                                                                                                                                                                                                         | Logs it; the record keeps its type                                                       |
| `UNDECODABLE`        | A `DATA` whose body does not decode with its offered schema: cut short, bytes left over, a string that is not well-formed, a data depth above 32 ([types.md](types.md), section 5.7)                                                                                                                                                                                                                                                                                 | Logs it                                                                                  |
| `KEY_MOVE_REJECTED`  | A `KEY_MOVE` the receiver did not apply: its user declined it, or it fails a check of [keys.md](keys.md), section 5.3, except step 3; reported in a live connection only (section 3.3)                                                                                                                                                                                                                                                                               | Stops sending the move to that app (section 3.3)                                         |

A receiver checks the addressee of the replies and the offer after their signature: one with another key in `to` is ignored without a report (section 9.1). A receiver also ignores, without a report:

- a message from a key its user has not accepted, which it keeps or drops as [keys.md](keys.md), section 3.2, says;
- a message signed with a moved-from key, which it rejects as [keys.md](keys.md), section 3.3, says, except the repeat of a key move, which it acknowledges (section 3.3);
- an answer to an offer the app did not make, or to an earlier offer of the type (section 5.3).

### 8.3 Reporting

- **Only to a sender that can be addressed.** In a live connection, an app sends an `ERROR` to the other app once it has a `MANIFEST` of the connection whose signature verified, valid or not, and so knows the formats the other app reads (section 3.2); before that, it reports nothing. The other app's key is the one its `HELLO` proved ([transports.md](transports.md), section 4.5). Through the relay, it sends an `ERROR` only to a known sender whose message verified and whose encryption key it has ([keys.md](keys.md), section 4.2). A message through the relay that fails before its signature is verified is dropped without a report, since its `sender` may be anyone's key. In a live connection the other app is known by the connection, so a message from it that fails those checks is reported to it. In both, the receiver reports nothing to a key its user has not accepted, apart from `MANIFEST_INVALID` and, in a live connection, `KEY_MOVE_REJECTED`, which goes to the move's old key on the connection (section 3.3).
- **Never about an error.** An app MUST NOT send an `ERROR` about an `ERROR`. An `ERROR` that is not valid is dropped.
- **Once.** An app sends at most one `ERROR` for each message it gets; a repeated message MAY be reported again.
- **Closing.** In a live connection, an app MAY close the connection after it has reported `TOO_LARGE` when the transport cannot skip the message ([envelope.md](envelope.md), section 8), after `SIGNATURE_INVALID`, and after `INVALID_MESSAGE`.

A sender that gets an `ERROR` about a record message for whose id and version it already has an outcome ignores it (section 9.2).

## 9. Addressees and repeats

### 9.1 The addressee

A signature names the sender of a message, not its receiver ([keys.md](keys.md), section 2.6). An app that got a reply could pass it on to a third app, which would then hold a genuine message of the first. The bodies of `OFFER`, `ACCEPT`, `DECLINE`, `ACK` and `ERROR` therefore carry `to`, the Ed25519 public key of the app they are for, and the signature covers it:

- An app MUST ignore such a message whose `to` is not its current key or, for an `ACK`, `ERROR`, `ACCEPT` and `DECLINE`, one of its moved-from keys. It sends no report, since the message was not meant for it.
- A sender writes in `to` the current key of the addressee as it knows it ([keys.md](keys.md), section 3.3).

`to` binds a message to its addressee, not to one connection. The same `ACK` is valid in a live connection and through the relay, and an app that uses both reaches the same result whichever way a reply arrives.

### 9.2 Repeats

A message carries no time, and a relay or a user can deliver a message again ([keys.md](keys.md), section 2.6). Every kind is safe to repeat:

| Kind       | A repeat, or a late copy                                                                                                                                                                                                                                  |
| ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `MANIFEST` | Applied in a live connection, where the manifest received last applies; through a relay or in a file ignored unless its revision is higher ([manifest.md](manifest.md), section 6)                                                                        |
| `OFFER`    | Answered again as before, if the receiver still knows the offer; it does not become the current offer again (section 4.3). If the receiver has forgotten it, its answer goes to an offer the sender has replaced, and the sender ignores it (section 5.3) |
| `ACCEPT`   | Ignored: the first answer for an offer and type stands, and only the latest offer of a type counts (section 5.3)                                                                                                                                          |
| `DECLINE`  | Ignored, for the same reasons                                                                                                                                                                                                                             |
| `DATA`     | `DUPLICATE` or `STALE` by the version rule ([records.md](records.md), section 5.2)                                                                                                                                                                        |
| `DELETE`   | The same                                                                                                                                                                                                                                                  |
| `ACK`      | Changes nothing: the first outcome of an id and version stands, except `APPLIED` over `KEPT` and `MERGED`, and any outcome over `DUPLICATE` (section 7.4)                                                                                                 |
| `ERROR`    | The sender acts again only for a message that still has no outcome; what it does then (section 8.2) is itself safe to repeat                                                                                                                              |
| `KEY_MOVE` | Acknowledged again, not applied again ([keys.md](keys.md), section 5.3, step 2; section 3.3)                                                                                                                                                              |

## 10. Versions that went back

The highest version of each record a sender has sent MUST survive whatever the sender's data goes through ([records.md](records.md), section 3). If it does not, for example after a restore from a backup older than the last messages sent, the sender gives versions again that it has given before. A receiver that already has a higher version reports `STALE`, from which the sender learns it ([records.md](records.md), section 7). A version that happens to equal the receiver's is taken for a duplicate, and the change is lost at that receiver.

The rule:

- A sender that restores its data from a backup, or for another reason cannot rule out that it has sent versions higher than those it holds, MUST continue the versions of every record above the version it holds plus a jump.
- The jump is an integer drawn with a cryptographically secure random number generator, uniformly from 2^32 to 2^48 − 1.
- The sender draws it anew for every restore and uses the same jump for all records of that restore.

A jump of at least 2^32 is above any number of changes made since a backup. Drawing it at random keeps two restores of the same backup from giving the same versions again. Two restores collide only if their jumps differ by less than the number of changes made after them, which for about 2^48 possible jumps and a million changes is a chance of about one in a hundred million. A version below the receiver's is answered with `STALE` and corrected as [records.md](records.md), section 7, says. A version long has room for more than 30,000 jumps.

The alternative, a hash of the record's content in each `DUPLICATE`, would make every receiver keep a hash of every record it holds. It would also take a record encoded again with another compatible schema ([records.md](records.md), section 3) for a changed one. The rule above needs nothing from the receiver and leaves the `ACK` as [records.md](records.md), section 7, describes it.

## 11. Resends

A sender sends a record message again:

- **Without an acknowledgement.** A record message with neither an outcome nor an error that settles it has not been delivered. In a live connection, the sender sends the record again in a later connection, under an offer accepted there and in its current state. Through a relay, it sends the same message again under the same offer, once the holding time of 14 days ([transports.md](transports.md), section 5.5) has passed without an outcome, not before. A record that has changed since the offer is offered again instead (section 4.3).
- **For a schema.** After `SCHEMA_UNKNOWN` (section 8.2), once the type is accepted again.
- **When a type is accepted again.** When a type that a receiver had stopped taking ([manifest.md](manifest.md), section 6) fits again and is accepted, the sender SHOULD send the current state of each record of the type it had sent to that receiver before: a `DATA` with the current version of a record that exists, a `DELETE` with the version of the deletion of one deleted in between.
- **After a key move.** As [keys.md](keys.md), section 5.4, says.

A receiver cannot ask for a resend beyond the schema request of `SCHEMA_UNKNOWN`. A record that the receiver could not process for a passing reason, such as a full storage, is neither acknowledged nor reported, and is sent again by the first rule. A receiver that loses records it had acknowledged, for example by restoring an older backup, gets each again when the sender changes it, or when the type is accepted again after it stopped fitting. 0.1.0 has no message for asking for them.

## 12. Timeouts

The protocol relies on few timers. Every step is safe to repeat (section 9.2), so a lost message costs time, not correctness. The transport detects a connection that has died ([transports.md](transports.md), section 4.6).

| What                                                           | Time                                                                                                                                                                                                                                |
| -------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The other app's valid `MANIFEST` after a live connection opens | An app SHOULD close a connection without one after 30 seconds                                                                                                                                                                       |
| An acknowledgement after processing a record message           | Within 5 seconds (section 7.2)                                                                                                                                                                                                      |
| An answer in a live connection                                 | Types the receiver decides on its own SHOULD be answered within 5 seconds. A type whose answer waits for the user has no limit; the sender MAY close a connection in which nothing but unanswered types has happened for 10 minutes |
| A resend through a relay                                       | After the holding time of 14 days ([transports.md](transports.md), section 5.5), not before                                                                                                                                         |
| An unanswered offer through a relay                            | The sender MAY offer again after the same time                                                                                                                                                                                      |
| A key move without an answer                                   | Three connections or three sends through the relay (section 3.3)                                                                                                                                                                    |

## 13. What a declined or interrupted exchange leaves

- **A declined type.** Nothing of it travels. The receiver keeps no record of it, and MUST NOT use the declined schema to decode; it MAY keep the offer's id and answer to answer a repeat (section 4.3). The sender keeps that the type was declined, and why (section 5.3).
- **An unanswered type.** At the end of its offer (section 4.3), an unanswered type is neither accepted nor declined: no records of it have travelled.
- **An interrupted exchange.** When a connection ends in the middle of an exchange, each record message stands for itself. The receiver keeps what it has applied; there is no transaction that undoes it. A reference to a record that has not arrived stays unresolved until it arrives ([records.md](records.md), section 8). The sender knows from the acknowledgements which messages are delivered and sends the others again in a later exchange (section 11). The offers of the connection end with it.
- **After the exchange.** Through a relay, an accepted offer stays open until the sender makes another offer of the type. In a live connection, it ends with the connection. Neither leaves an acceptance that would let later records in without an offer.

## 14. The live connection as a state machine

Each app runs the same machine, as a sender of its records and as a receiver of the other's. The connection has three phases:

| Phase   | The app                                                                                                                                                                                                                               | Leaves the phase                                                                                                                             |
| ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| Opening | sends its `KEY_MOVE` messages (section 3.3), then its `MANIFEST` in its lowest format; takes `KEY_MOVE`, `MANIFEST` and `ERROR`; asks its user about an unknown key or a key move and keeps the other messages until the user decides | to Open with a valid `MANIFEST` of the other app and its key accepted; to Closed after 30 seconds without, or when the user declines the key |
| Open    | writes in the chosen format (section 3.2); offers, answers, sends and acknowledges records, reports errors; takes a new `MANIFEST` of the other app at any time                                                                       | to Closed when either app or the transport closes the connection                                                                             |
| Closed  | ends every offer made in the connection (section 4.3); keeps the outcomes it has; marks record messages without one for a resend (section 11)                                                                                         |                                                                                                                                              |

In the Open phase, each offer the app makes, each type of it, and each record message it sends goes through these states at the sender:

| Object             | States                                                                                                                                                                                                     |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A type of an offer | unanswered → accepted or declined (the first answer, section 5.3) → ended (a later offer of the type, a manifest in which it no longer fits, or the end of the connection)                                 |
| A record message   | due → sent (only while its type is accepted, section 6.1) → acknowledged with an outcome, or reported with an error (section 8.2), or still sent when the connection ends, and then due again (section 11) |

And at the receiver:

| Object                      | States                                                                                                                                                      |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A type of the current offer | received → answered (once, section 5.2) → ended (a later offer of the type, a manifest of its own in which it no longer fits, or the end of the connection) |
| A record message            | received → processed to an outcome and acknowledged (sections 6.2 and 7.2), or rejected and reported (section 8)                                            |

A new `MANIFEST` of the receiver with a higher revision is a transition of both machines. Each type of an accepted offer that no longer fits it ends, at the receiver on sending the manifest and at the sender on receiving it ([manifest.md](manifest.md), section 6). Record messages of such a type that were already on their way get `NOT_ACCEPTED`.

## 15. Through a relay and in a file

### 15.1 Through a relay

Through a relay ([transports.md](transports.md), section 5) the messages and the rules are the same, with these differences:

- **No connection.** There is no Opening phase and no end of a connection. Each app sends its current `MANIFEST` through the relay to every known sender that takes messages through the relay and has not got it there yet: after it has accepted the other app's key, and whenever its manifest changes. This is when [manifest.md](manifest.md), section 5.1, has an app send a `MANIFEST` through the relay. A sender offers by the manifest it keeps of the receiver ([manifest.md](manifest.md), section 6), and an offer stays open until replaced (section 4.3).
- **Replies come back the same way.** An app that sends record messages or offers through a relay MUST take messages through it, that is, have an encryption key in its manifest ([manifest.md](manifest.md), section 3.9). Otherwise its answers and acknowledgements cannot reach it.
- **Order and repeats.** The relay may deliver late, out of order and more than once ([keys.md](keys.md), section 4.6); sections 4.3 and 9.2 make the result the same. A receiver that gets record messages of an offer it has not seen yet answers them with `SCHEMA_UNKNOWN` or `NOT_ACCEPTED`, and the sender sends them again after the offer.
- **Errors.** Only messages whose signature verified are reported (section 8.3).
- **Timers.** Resends follow the time for which the relay holds a message (sections 11 and 12).
- **Encryption.** Every message is sealed for the receiver's encryption key ([keys.md](keys.md), section 4).

### 15.2 In a file

A file has no way back to its sender ([records.md](records.md), section 7). Its header's `axt.schemas`, signed by `axt.signature`, takes the place of the offer ([envelope.md](envelope.md), section 4.1; [keys.md](keys.md), section 2.5). The reader's user, who chooses to open the file, together with the reader's manifest ([manifest.md](manifest.md), section 7), takes the place of the answer. Nothing acknowledges it. Hence:

- `OFFER`, `ACCEPT`, `DECLINE`, `ACK` and `ERROR` are bound to one exchange and need a way back, which a file does not have. A file therefore holds none of them ([transports.md](transports.md), section 2.1).
- A reader applies the record messages of a file by [records.md](records.md), section 5, and reaches the outcomes there, without the steps 4 and 5 of section 6.2. The schemas are those of the header, and a record is taken only if its type fits the reader's manifest ([manifest.md](manifest.md), section 7). A record message that fails another step of section 6.2 is not applied; a `DATA` whose fingerprint is not in `axt.schemas` makes the whole file invalid ([envelope.md](envelope.md), section 4.3).
- Reading a file accepts no offer. Records that the same sender later sends through a relay or a connection need an offer there.

### 15.3 What transports.md settles

- **The boundaries of each live message** are the frames of [transports.md](transports.md), section 4.4 ([envelope.md](envelope.md), section 3), and a connection opens and ends as [transports.md](transports.md), section 4.6, says (section 3.1 and section 14).
- **The other app's key** is authenticated before its `MANIFEST`: each app proves its signing key in a `HELLO` bound to the TLS connection ([transports.md](transports.md), section 4.5), and every message in the connection carries that key as its `sender`, apart from the key moves at its start.
- **A file** holds the key moves at its start, at most one `MANIFEST`, and record messages, and no `OFFER`, `ACCEPT`, `DECLINE`, `ACK` or `ERROR` ([transports.md](transports.md), section 2.1).
- **The holding time** of a relay is 14 days ([transports.md](transports.md), section 5.5). It sets the resends of sections 11 and 12, and how long a receiver keeps the ids of the offers it answered (section 4.3).

## 16. Schemas and fingerprints

The schemas are [types/axt/Offer.avsc](../types/axt/Offer.avsc), [types/axt/Accept.avsc](../types/axt/Accept.avsc), [types/axt/Decline.avsc](../types/axt/Decline.avsc), [types/axt/Ack.avsc](../types/axt/Ack.avsc) and [types/axt/Error.avsc](../types/axt/Error.avsc). Each follows the rules that [types.md](types.md), section 5, sets for every example type, where they apply to a schema of the specification, as [manifest.md](manifest.md), section 9, says of the manifest. Their nested types are defined in place, with names that begin with the schema's name, and none carries `axt.version`. The first field of each is `to`.

Each enum has a default symbol, as [types.md](types.md), section 5.4, requires; within one envelope format every symbol is known, and the default only takes effect in schema resolution with a schema of another format. The defaults are those that make a sender do nothing: `NOT_WANTED`, `DUPLICATE` and `INVALID_MESSAGE`.

Their Parsing Canonical Forms:

```json
{"name":"axt.Offer","type":"record","fields":[{"name":"to","type":{"name":"axt.OfferTo","type":"fixed","size":32}},{"name":"offer_id","type":"string"},{"name":"types","type":{"type":"array","items":{"name":"axt.OfferType","type":"record","fields":[{"name":"schema","type":"string"},{"name":"count","type":"long"}]}}}]}
```

```json
{"name":"axt.Accept","type":"record","fields":[{"name":"to","type":{"name":"axt.AcceptTo","type":"fixed","size":32}},{"name":"offer_id","type":"string"},{"name":"types","type":{"type":"array","items":"string"}}]}
```

```json
{"name":"axt.Decline","type":"record","fields":[{"name":"to","type":{"name":"axt.DeclineTo","type":"fixed","size":32}},{"name":"offer_id","type":"string"},{"name":"types","type":{"type":"array","items":{"name":"axt.DeclineType","type":"record","fields":[{"name":"type","type":"string"},{"name":"reason","type":{"name":"axt.DeclineReason","type":"enum","symbols":["NOT_WANTED","DOES_NOT_FIT","DOES_NOT_RESOLVE"]}}]}}}]}
```

```json
{"name":"axt.Ack","type":"record","fields":[{"name":"to","type":{"name":"axt.AckTo","type":"fixed","size":32}},{"name":"records","type":{"type":"array","items":{"name":"axt.AckRecord","type":"record","fields":[{"name":"id","type":"string"},{"name":"version","type":"long"},{"name":"outcome","type":{"name":"axt.AckOutcome","type":"enum","symbols":["APPLIED","MERGED","KEPT","DUPLICATE","STALE"]}},{"name":"receiver_version","type":"long"},{"name":"kept_fields","type":{"type":"array","items":"string"}}]}}},{"name":"moved_from","type":["null",{"name":"axt.AckMovedFrom","type":"fixed","size":32}]}]}
```

```json
{"name":"axt.Error","type":"record","fields":[{"name":"to","type":{"name":"axt.ErrorTo","type":"fixed","size":32}},{"name":"code","type":{"name":"axt.ErrorCode","type":"enum","symbols":["INVALID_MESSAGE","FORMAT_UNSUPPORTED","TOO_LARGE","SIGNATURE_INVALID","MANIFEST_INVALID","OFFER_INVALID","RECORD_ID_INVALID","VERSION_INVALID","SCHEMA_UNKNOWN","NOT_ACCEPTED","TYPE_CHANGED","UNDECODABLE","KEY_MOVE_REJECTED"]}},{"name":"message_hash","type":{"name":"axt.ErrorMessageHash","type":"fixed","size":32}},{"name":"record","type":["null",{"name":"axt.ErrorRecord","type":"record","fields":[{"name":"id","type":"string"},{"name":"version","type":"long"}]}]},{"name":"fingerprint","type":["null",{"name":"axt.ErrorFingerprint","type":"fixed","size":8}]},{"name":"detail","type":"string"}]}
```

| Schema        | Envelope format | CRC-64-AVRO          | As bytes                  |
| ------------- | --------------- | -------------------- | ------------------------- |
| `axt.Offer`   | 1               | `0x415463caca7a687d` | `7d 68 7a ca ca 63 54 41` |
| `axt.Accept`  | 1               | `0x6b244fc3913d82ab` | `ab 82 3d 91 c3 4f 24 6b` |
| `axt.Decline` | 1               | `0x22d2bd11845492c0` | `c0 92 54 84 11 bd d2 22` |
| `axt.Ack`     | 1               | `0xee25c7cca8166ed8` | `d8 6e 16 a8 cc c7 25 ee` |
| `axt.Error`   | 1               | `0x36d44a6df4e7ded4` | `d4 de e7 f4 6d 4a d4 36` |

The fingerprints and the example of section 17 were produced with [conformance/tools/protocol_examples.py](../conformance/tools/protocol_examples.py). The script:

- checks the rules of [types.md](types.md), section 5, named above, with the checks of [conformance/tools/example_types.py](../conformance/tools/example_types.py), and that no name is defined twice among the schemas of the specification;
- computes the Parsing Canonical Forms and the CRC-64-AVRO fingerprints, compares them with those of the Python libraries fastavro 1.13.1 and `avro` 1.12.2, and checks that the fingerprints of the envelope, the manifest and the key move are those published;
- uses every default of the schemas once in schema resolution, with both libraries, and for each enum a symbol the reader does not know, which fastavro reads as the default; the `avro` package 1.12.2 raises an error instead ([types.md](types.md), section 7.3);
- builds every message of section 17 field by field, compares it with fastavro's encoding, decodes it with fastavro and with `avro`, and checks that `avro` encodes each body to the same bytes;
- signs each message with the Ed25519 implementation of [conformance/tools/keys_examples.py](../conformance/tools/keys_examples.py), with PyNaCl 1.6.2 and with cryptography 50.0.2, which give the same signatures, and verifies them with all three by the strict rule of [keys.md](keys.md), section 2.3;
- runs a model of both apps over the exchange and over 58 further cases: repeats, messages addressed to another key, the first answer standing, outcomes decided later and acknowledgements of a resend in either order, an error never answered with an error, and one case for each error code that a record message, an offer, a manifest or an envelope can cause, among them a recursive app type at data depth 32, which is taken, and at 34, which is rejected.

The test vectors of [conformance.md](conformance.md) take precedence over these values.

## 17. Example

cat-a-log and Old Brain Fix, the apps of [manifest.md](manifest.md), section 10, meet in a live connection. Their users have accepted each other's keys. cat-a-log's user wants to send Mimi's record and her vet appointment; Old Brain Fix's user takes the appointment but not the pet.

### 17.1 Keys and values

The keys are the test keys of [keys.md](keys.md), section 7.1: cat-a-log signs with `cat-a-log, old phone, Ed25519`, Old Brain Fix with `Old Brain Fix, Ed25519`, which [keys.md](keys.md) does not list. **These keys are for tests only and MUST NOT be used outside tests.**

| Label                    | Key               | Hexadecimal                                                        |
| ------------------------ | ----------------- | ------------------------------------------------------------------ |
| `Old Brain Fix, Ed25519` | seed              | `071b538b5d99ab63cc1d39aa21fcc96c3698e2cd0c093baf5fd244af0f813ae7` |
|                          | public key        | `da9e54c9aa2db43244df99889d9138c1ca7175d4ca0908168f63530e4a7dedb7` |
|                          | short fingerprint | `01399 72263 65477 52894 90179`                                    |

| Value                | Content                                                                                                                                                                                                                                                                                                                                                                                                  |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `offer_id`           | `6f1c2b9e-3d4a-4e5f-8a7b-1c2d3e4f5a6b`                                                                                                                                                                                                                                                                                                                                                                   |
| The Appointment's id | `a2d4f6b8-1c3e-4a5b-9d7f-0e2c4a6b8d1f`, version 1                                                                                                                                                                                                                                                                                                                                                        |
| The Pet's id         | `5e8a1f3c-7b2d-4c6e-a9f0-3d5b7c9e1a2f`, version 1                                                                                                                                                                                                                                                                                                                                                        |
| The offered schemas  | [Pet.1.avsc](../types/axt/example/v1/Pet.1.avsc) and [Appointment.1.avsc](../types/axt/example/v1/Appointment.1.avsc), each written as JSON without whitespace, with every attribute and in the order of the file: 1,464 bytes (SHA-256 `747916b489fd5955aa9ce3a15d8353d07444031ae9028ae9946cb74004fdcb5d`) and 1,913 bytes (SHA-256 `85439a43a3ed8ee8c82ce3a1dcaeeb6d4370972d27fe34763ea0b398d4c29825`) |
| The Appointment      | `title` "Vet: vaccination", `start` 2026-11-24 10:00 and `end` 10:30 in `Europe/Berlin`, `location` "Tierarztpraxis, Hauptstraße 1", `notes` "Bring the vaccination certificate.", `reminders` 1440 and 60 minutes before                                                                                                                                                                                |

| Step | Message, from → to                    | What happens                                                                                                                                                                                  |
| ---- | ------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | `MANIFEST`, cat-a-log → Old Brain Fix | Section 3.1; the manifest of [manifest.md](manifest.md), section 10.1. Old Brain Fix's manifest crosses it (step 2); neither waits                                                            |
| 2    | `MANIFEST`, Old Brain Fix → cat-a-log | Both apps read format 1, so the chosen format is 1 (section 3.2)                                                                                                                              |
| 3    | `OFFER`, cat-a-log → Old Brain Fix    | Pet and Appointment, version 1, one record each. Both fit Old Brain Fix's manifest, the Pet by `any_type`, the Appointment by its entry in `takes` ([manifest.md](manifest.md), section 10.2) |
| 4    | `ACCEPT`, Old Brain Fix → cat-a-log   | Old Brain Fix's user takes the Appointment, whose schema resolves against Old Brain Fix's own                                                                                                 |
| 5    | `DECLINE`, Old Brain Fix → cat-a-log  | The Pet, `NOT_WANTED`: its user does not want it, although it fits                                                                                                                            |
| 6    | `DATA`, cat-a-log → Old Brain Fix     | The Appointment, version 1, written with the offered schema                                                                                                                                   |
| 7    | `ACK`, Old Brain Fix → cat-a-log      | `APPLIED`, receiver's version 1: Old Brain Fix had no record under the id ([records.md](records.md), section 5.2)                                                                             |
| 8    | `DATA`, cat-a-log → Old Brain Fix     | Only to show the error: had cat-a-log sent Mimi's record anyway, against section 6.1, its type would have no accepted offer                                                                   |
| 9    | `ERROR`, Old Brain Fix → cat-a-log    | `NOT_ACCEPTED`, with the record's id and version and the hash of the message of step 8                                                                                                        |

The messages are live messages in envelope format 1. Offsets are hexadecimal. Each signature covers the prefix `AXT-v1 message` and its zero byte, and the bytes from offset `000a` to the signature ([keys.md](keys.md), section 2.2).

### 17.2 The manifests

The messages are those of [manifest.md](manifest.md), section 10.3, byte for byte; their bodies are shown shortened here.

cat-a-log's MANIFEST: 315 bytes, SHA-256 `1ee7dfafb7a27b1ba7f1dd7fedb04e822d4cbc3f23033f8908b1b8691a163771`.

```text
0000  c3 01                    single-object marker
0002  7d 0c e4 e5 4f e8 e1 a2  fingerprint of axt.Envelope, format 1
000a  02                       format: int 1
000b  00                       kind: enum index 0, MANIFEST
000c  1b 84 a6 00 f3 50 3e 22  sender: fixed(32), cat-a-log's test key
      bb cc 99 e6 32 02 a7 19
      4b f6 bd 69 af f1 47 1c
      ce 64 10 d5 3c 26 ec 4a
002c  00                       record: union index 0, null
002d  98 03                    body: bytes length 204
002f  c3 01                    body: single-object marker
0031  b3 03 80 d3 b5 ec 08 6b  body: fingerprint of axt.Manifest, format 1
0039  02 12 63 61 ... 00 00    body: the manifest of spec/manifest.md, section 10.3, from 0039
00fb  21 cc f8 c7 3d 1f f7 c7  signature: fixed(64)
      56 20 75 68 0d 2d d2 8f
      db d8 d7 2a 00 fa 89 f8
      76 11 43 de 49 5a d5 bb
      85 33 a6 b5 e5 45 99 2d
      f2 0b a4 cd 86 b9 6e 53
      32 44 54 56 7f fe 19 c2
      f2 a6 f7 8c 46 2e 3a 0a
013b  end
```

Old Brain Fix's MANIFEST: 549 bytes, SHA-256 `d8d61697a0189e3afe3b500901b634a356ac1af1986b42bdf9d62d358e59dcaf`.

```text
0000  c3 01                    single-object marker
0002  7d 0c e4 e5 4f e8 e1 a2  fingerprint of axt.Envelope, format 1
000a  02                       format: int 1
000b  00                       kind: enum index 0, MANIFEST
000c  da 9e 54 c9 aa 2d b4 32  sender: fixed(32), Old Brain Fix's test key
      44 df 99 88 9d 91 38 c1
      ca 71 75 d4 ca 09 08 16
      8f 63 53 0e 4a 7d ed b7
002c  00                       record: union index 0, null
002d  ec 06                    body: bytes length 438
002f  c3 01                    body: single-object marker
0031  b3 03 80 d3 b5 ec 08 6b  body: fingerprint of axt.Manifest, format 1
0039  02 1a 4f 6c ... 00 00    body: the manifest of spec/manifest.md, section 10.3, from 0039
01e5  dc 24 c3 04 4b 0b 8d 06  signature: fixed(64)
      cc 61 3b aa a7 43 6e 26
      ff ca 67 f2 96 2c a1 d4
      c8 46 d8 e1 d4 fc ec 5c
      c5 3f ba e6 d0 3d 50 10
      4d c1 56 38 fd f6 2c 61
      a0 70 f3 41 83 7c 61 b1
      6e b7 df 50 28 0a 95 00
0225  end
```

### 17.3 The offer

The two schema texts are shown shortened; the script prints their SHA-256.

cat-a-log's OFFER: 3,575 bytes, SHA-256 `59128bbdf06413dd21c1d40fbc2f1e670b0c92d64caeb84073f3362c0df1d3cb`.

```text
0000  c3 01                    single-object marker
0002  7d 0c e4 e5 4f e8 e1 a2  fingerprint of axt.Envelope, format 1
000a  02                       format: int 1
000b  02                       kind: enum index 1, OFFER
000c  1b 84 a6 00 f3 50 3e 22  sender: fixed(32), cat-a-log's test key
      bb cc 99 e6 32 02 a7 19
      4b f6 bd 69 af f1 47 1c
      ce 64 10 d5 3c 26 ec 4a
002c  00                       record: union index 0, null
002d  90 36                    body: bytes length 3464
002f  c3 01                    body: single-object marker
0031  7d 68 7a ca ca 63 54 41  body: fingerprint of axt.Offer, format 1
0039  da 9e 54 c9 aa 2d b4 32  body: to: fixed(32), Old Brain Fix's test key
      44 df 99 88 9d 91 38 c1
      ca 71 75 d4 ca 09 08 16
      8f 63 53 0e 4a 7d ed b7
0059  48                       body: offer_id: string length 36
005a  36 66 31 63 32 62 39 65  body: "6f1c2b9e-3d4a-4e5f-8a7b-1c2d3e4f5a6b"
      2d 33 64 34 61 2d 34 65
      35 66 2d 38 61 37 62 2d
      31 63 32 64 33 65 34 66
      35 61 36 62
007e  04                       body: types: array block of 2 items
007f  f0 16                    body: types[0].schema: string length 1464
0081  7b 22 74 79 ... 5d 7d    body: Pet.1.avsc without whitespace (1464 bytes of UTF-8 JSON)
0639  02                       body: types[0].count: long 1
063a  f2 1d                    body: types[1].schema: string length 1913
063c  7b 22 74 79 ... 5d 7d    body: Appointment.1.avsc without whitespace (1913 bytes of UTF-8 JSON)
0db5  02                       body: types[1].count: long 1
0db6  00                       body: types: end of the array
0db7  4f ba 2b 05 5b 51 34 9a  signature: fixed(64)
      a8 b9 44 1a 49 b2 22 09
      f1 85 a8 b5 b8 3b 4c c0
      79 3e 94 48 d0 4f 59 34
      24 06 cf aa 86 13 9b 5c
      83 51 6f 8d c2 0c a6 06
      3a d1 ee a6 db 6c f4 7d
      ac f2 7b e1 7a af e0 06
0df7  end
```

### 17.4 The answers

Old Brain Fix's ACCEPT: 219 bytes, SHA-256 `18858f2bf833ece43cd5b155da19f0e7755457a415268d5200df91b6a4615fc8`.

```text
0000  c3 01                    single-object marker
0002  7d 0c e4 e5 4f e8 e1 a2  fingerprint of axt.Envelope, format 1
000a  02                       format: int 1
000b  04                       kind: enum index 2, ACCEPT
000c  da 9e 54 c9 aa 2d b4 32  sender: fixed(32), Old Brain Fix's test key
      44 df 99 88 9d 91 38 c1
      ca 71 75 d4 ca 09 08 16
      8f 63 53 0e 4a 7d ed b7
002c  00                       record: union index 0, null
002d  d8 01                    body: bytes length 108
002f  c3 01                    body: single-object marker
0031  ab 82 3d 91 c3 4f 24 6b  body: fingerprint of axt.Accept, format 1
0039  1b 84 a6 00 f3 50 3e 22  body: to: fixed(32), cat-a-log's test key
      bb cc 99 e6 32 02 a7 19
      4b f6 bd 69 af f1 47 1c
      ce 64 10 d5 3c 26 ec 4a
0059  48                       body: offer_id: string length 36
005a  36 66 31 63 32 62 39 65  body: "6f1c2b9e-3d4a-4e5f-8a7b-1c2d3e4f5a6b"
      2d 33 64 34 61 2d 34 65
      35 66 2d 38 61 37 62 2d
      31 63 32 64 33 65 34 66
      35 61 36 62
007e  02                       body: types: array block of 1 item
007f  34                       body: types[0]: string length 26
0080  61 78 74 2e 65 78 61 6d  body: "axt.example.v1.Appointment"
      70 6c 65 2e 76 31 2e 41
      70 70 6f 69 6e 74 6d 65
      6e 74
009a  00                       body: types: end of the array
009b  6d 2a 02 d4 36 b1 54 db  signature: fixed(64)
      b3 39 06 11 5b a5 fd fe
      f2 1a 26 c6 8f 04 40 39
      a0 af bf 19 04 6c 09 57
      7b ea 7e a4 6c aa 01 40
      7b a3 62 61 46 05 ce f8
      d5 0e 64 ee 59 0a 0b 4a
      d2 0a 15 62 fc 1e 57 0b
00db  end
```

Old Brain Fix's DECLINE: 212 bytes, SHA-256 `183d7ce9cae4b3130b52a59d2cee78f8a1e9feac4e92a9cb9ac4d8049ac18cc1`.

```text
0000  c3 01                    single-object marker
0002  7d 0c e4 e5 4f e8 e1 a2  fingerprint of axt.Envelope, format 1
000a  02                       format: int 1
000b  06                       kind: enum index 3, DECLINE
000c  da 9e 54 c9 aa 2d b4 32  sender: fixed(32), Old Brain Fix's test key
      44 df 99 88 9d 91 38 c1
      ca 71 75 d4 ca 09 08 16
      8f 63 53 0e 4a 7d ed b7
002c  00                       record: union index 0, null
002d  ca 01                    body: bytes length 101
002f  c3 01                    body: single-object marker
0031  c0 92 54 84 11 bd d2 22  body: fingerprint of axt.Decline, format 1
0039  1b 84 a6 00 f3 50 3e 22  body: to: fixed(32), cat-a-log's test key
      bb cc 99 e6 32 02 a7 19
      4b f6 bd 69 af f1 47 1c
      ce 64 10 d5 3c 26 ec 4a
0059  48                       body: offer_id: string length 36
005a  36 66 31 63 32 62 39 65  body: "6f1c2b9e-3d4a-4e5f-8a7b-1c2d3e4f5a6b"
      2d 33 64 34 61 2d 34 65
      35 66 2d 38 61 37 62 2d
      31 63 32 64 33 65 34 66
      35 61 36 62
007e  02                       body: types: array block of 1 item
007f  24                       body: types[0].type: string length 18
0080  61 78 74 2e 65 78 61 6d  body: "axt.example.v1.Pet"
      70 6c 65 2e 76 31 2e 50
      65 74
0092  00                       body: types[0].reason: enum index 0, NOT_WANTED
0093  00                       body: types: end of the array
0094  5e 48 b1 18 ae 49 3c 5d  signature: fixed(64)
      8d a4 11 fa 97 c1 a3 e8
      d8 60 3c ea 84 f5 6e 14
      35 15 b3 b5 d4 db 0c c9
      45 44 0b 71 7c eb 93 37
      b2 d6 81 9f 66 6e aa 9f
      c1 44 64 a2 14 5b 0c dc
      42 ac b2 1f 93 58 40 04
00d4  end
```

### 17.5 The record and its acknowledgement

The body of the `DATA` names the Appointment's schema by its fingerprint, `0x1b57de39e9441b59` ([types.md](types.md), section 7.3). Old Brain Fix finds it among the schemas of cat-a-log's current offers, and only there.

cat-a-log's DATA: 276 bytes, SHA-256 `77b613c6f7f4f637c55479135122d3b382a2311e96a0db95b524fdd5acf9bbd8`.

```text
0000  c3 01                    single-object marker
0002  7d 0c e4 e5 4f e8 e1 a2  fingerprint of axt.Envelope, format 1
000a  02                       format: int 1
000b  08                       kind: enum index 4, DATA
000c  1b 84 a6 00 f3 50 3e 22  sender: fixed(32), cat-a-log's test key
      bb cc 99 e6 32 02 a7 19
      4b f6 bd 69 af f1 47 1c
      ce 64 10 d5 3c 26 ec 4a
002c  02                       record: union index 1, axt.RecordRef
002d  48                       record.id: string length 36
002e  61 32 64 34 66 36 62 38  "a2d4f6b8-1c3e-4a5b-9d7f-0e2c4a6b8d1f"
      2d 31 63 33 65 2d 34 61
      35 62 2d 39 64 37 66 2d
      30 65 32 63 34 61 36 62
      38 64 31 66
0052  02                       record.version: long 1
0053  fe 01                    body: bytes length 127
0055  c3 01                    body: single-object marker
0057  59 1b 44 e9 39 de 57 1b  body: fingerprint of axt.example.v1.Appointment, version 1
005f  20                       body: title: string length 16
0060  56 65 74 3a 20 76 61 63  body: "Vet: vaccination"
      63 69 6e 61 74 69 6f 6e
0070  80 f4 fb cf c1 68        body: start: long 1795514400000 (2026-11-24 10:00)
0076  02                       body: end: union index 1, long
0077  80 d1 d7 d1 c1 68        body: end: long 1795516200000 (2026-11-24 10:30)
007d  02                       body: time_zone: union index 1, string
007e  1a                       body: time_zone: string length 13
007f  45 75 72 6f 70 65 2f 42  body: "Europe/Berlin"
      65 72 6c 69 6e
008c  00                       body: all_day: boolean false
008d  3c                       body: location: string length 30
008e  54 69 65 72 61 72 7a 74  body: "Tierarztpraxis, Hauptstraße 1"
      70 72 61 78 69 73 2c 20
      48 61 75 70 74 73 74 72
      61 c3 9f 65 20 31
00ac  44                       body: notes: string length 34
00ad  42 72 69 6e 67 20 74 68  body: "Bring the vaccination certificate."
      65 20 76 61 63 63 69 6e
      61 74 69 6f 6e 20 63 65
      72 74 69 66 69 63 61 74
      65 2e
00cf  04                       body: reminders: array block of 2 items
00d0  c0 16                    body: reminders[0]: int 1440
00d2  78                       body: reminders[1]: int 60
00d3  00                       body: reminders: end of the array
00d4  12 49 c2 98 fb c8 0d f9  signature: fixed(64)
      79 b6 0b aa 30 be 22 aa
      a3 aa 4e f9 05 30 18 78
      c2 f7 d7 6f e7 ae 53 ff
      5e 1c 51 5f 08 bf a2 26
      3a 85 c4 43 36 74 40 60
      7b 30 80 bb b2 f6 e9 14
      9d 3c 26 dd 06 bb d1 09
0114  end
```

Old Brain Fix's ACK: 197 bytes, SHA-256 `0f2d0004d3b42c9f4013e6e5ba3d4250dbaffa205b25eb509c974746c22fd9ca`.

```text
0000  c3 01                    single-object marker
0002  7d 0c e4 e5 4f e8 e1 a2  fingerprint of axt.Envelope, format 1
000a  02                       format: int 1
000b  0c                       kind: enum index 6, ACK
000c  da 9e 54 c9 aa 2d b4 32  sender: fixed(32), Old Brain Fix's test key
      44 df 99 88 9d 91 38 c1
      ca 71 75 d4 ca 09 08 16
      8f 63 53 0e 4a 7d ed b7
002c  00                       record: union index 0, null
002d  ac 01                    body: bytes length 86
002f  c3 01                    body: single-object marker
0031  d8 6e 16 a8 cc c7 25 ee  body: fingerprint of axt.Ack, format 1
0039  1b 84 a6 00 f3 50 3e 22  body: to: fixed(32), cat-a-log's test key
      bb cc 99 e6 32 02 a7 19
      4b f6 bd 69 af f1 47 1c
      ce 64 10 d5 3c 26 ec 4a
0059  02                       body: records: array block of 1 item
005a  48                       body: records[0].id: string length 36
005b  61 32 64 34 66 36 62 38  body: "a2d4f6b8-1c3e-4a5b-9d7f-0e2c4a6b8d1f"
      2d 31 63 33 65 2d 34 61
      35 62 2d 39 64 37 66 2d
      30 65 32 63 34 61 36 62
      38 64 31 66
007f  02                       body: records[0].version: long 1
0080  00                       body: records[0].outcome: enum index 0, APPLIED
0081  02                       body: records[0].receiver_version: long 1
0082  00                       body: records[0].kept_fields: end of the array
0083  00                       body: records: end of the array
0084  00                       body: moved_from: union index 0, null
0085  57 42 fa 3f 10 cc 0c 44  signature: fixed(64)
      d9 d7 4e 82 39 67 81 b0
      e8 85 b8 a7 15 76 5d 0c
      48 b4 9c 27 9e 5c 7d 8d
      e7 41 da 4f e6 52 9f ea
      d8 1b b7 61 68 08 c6 e0
      c6 e7 18 ee 95 68 72 54
      5a 5a ce 75 53 d6 d2 0a
00c5  end
```

### 17.6 A record without an accepted offer

The `DATA` of step 8 carries the Pet of [conformance/tools/example_types.py](../conformance/tools/example_types.py) as the record `5e8a1f3c-7b2d-4c6e-a9f0-3d5b7c9e1a2f`, version 1, written with the offered Pet schema. Old Brain Fix knows the fingerprint from the offer, but the Pet's answer was `DECLINE`, so step 5 of section 6.2 fails. The `ERROR` names the message by its hash, `8e31966111b293e62c848b999e1237f6b95795e2603140a2be0fed345932c57c`.

Old Brain Fix's ERROR: 245 bytes, SHA-256 `ea9d029381d3ee27324b191ba8b3e43acf690e0b8ce1bcf6661e831ccae0e379`.

```text
0000  c3 01                    single-object marker
0002  7d 0c e4 e5 4f e8 e1 a2  fingerprint of axt.Envelope, format 1
000a  02                       format: int 1
000b  0e                       kind: enum index 7, ERROR
000c  da 9e 54 c9 aa 2d b4 32  sender: fixed(32), Old Brain Fix's test key
      44 df 99 88 9d 91 38 c1
      ca 71 75 d4 ca 09 08 16
      8f 63 53 0e 4a 7d ed b7
002c  00                       record: union index 0, null
002d  8c 02                    body: bytes length 134
002f  c3 01                    body: single-object marker
0031  d4 de e7 f4 6d 4a d4 36  body: fingerprint of axt.Error, format 1
0039  1b 84 a6 00 f3 50 3e 22  body: to: fixed(32), cat-a-log's test key
      bb cc 99 e6 32 02 a7 19
      4b f6 bd 69 af f1 47 1c
      ce 64 10 d5 3c 26 ec 4a
0059  12                       body: code: enum index 9, NOT_ACCEPTED
005a  8e 31 96 61 11 b2 93 e6  body: message_hash: fixed(32), SHA-256 of the reported message
      2c 84 8b 99 9e 12 37 f6
      b9 57 95 e2 60 31 40 a2
      be 0f ed 34 59 32 c5 7c
007a  02                       body: record: union index 1, ErrorRecord
007b  48                       body: record.id: string length 36
007c  35 65 38 61 31 66 33 63  body: "5e8a1f3c-7b2d-4c6e-a9f0-3d5b7c9e1a2f"
      2d 37 62 32 64 2d 34 63
      36 65 2d 61 39 66 30 2d
      33 64 35 62 37 63 39 65
      31 61 32 66
00a0  02                       body: record.version: long 1
00a1  00                       body: fingerprint: union index 0, null
00a2  24                       body: detail: string length 18
00a3  61 78 74 2e 65 78 61 6d  body: "axt.example.v1.Pet"
      70 6c 65 2e 76 31 2e 50
      65 74
00b5  6f 4c af b5 bb bf 2d 01  signature: fixed(64)
      de 48 c1 2c df 56 c3 27
      98 04 41 1c 0e a4 0f fe
      45 48 0b f2 5f 1e d4 77
      b5 e4 38 2d f9 32 2f c9
      cd 35 02 b7 c3 b5 fa e3
      bf 72 59 88 28 03 af f4
      8e c6 5a 1b 89 dd 3b 0c
00f5  end
```

cat-a-log has no outcome for the Pet, so it takes the error. It sends Mimi's record to Old Brain Fix only after a later offer of the Pet is accepted.

## 18. What other documents define

- [transports.md](transports.md): the live connection, its `HELLO`, its opening and its end (section 4 there); the kinds a file holds (section 2.1 there); the relay and its holding time, which sets the resends through it (section 5 there; section 15.3).
- [conformance.md](conformance.md): test vectors for every message of this document and for the cases of section 16.

## References

- [Apache Avro 1.12 specification](https://avro.apache.org/docs/1.12.0/specification/)
- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174): key words for requirement levels
- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032): Ed25519
- [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259): JSON
- [RFC 9562](https://www.rfc-editor.org/rfc/rfc9562): UUIDs
- [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final): SHA-256
