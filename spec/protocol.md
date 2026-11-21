# Protocol

Status: released in 0.1.0, changed in 0.2.0. A change to this document is a new version of AXT, with its entry in [CHANGELOG.md](../CHANGELOG.md).

This document defines the steps of an exchange between two apps: the first messages of a live connection and the choice of the envelope format, the offer of types with their schemas, the acceptance or refusal of each type, the record messages, the acknowledgement and the error report. It defines the bodies of the messages `OFFER`, `ACCEPT`, `DECLINE`, `ACK` and `ERROR`, how each message is bound to the app it is for and made safe to repeat, timeouts, resends, what a declined or interrupted exchange leaves behind, and how the same messages behave in a live connection, through a relay and in a file.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 ([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119), [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)) when, and only when, they appear in all capitals, as shown here.

## 1. Terms

- **Sender** and **receiver**: as in [records.md](records.md), section 1. In an exchange between two apps each is the sender of the records it offers and the receiver of the records the other offers.
- **Channel**: the way two apps exchange messages: one live connection ([transports.md](transports.md), section 4), or the relay ([transports.md](transports.md), section 5). Two apps can use several channels one after the other, or at the same time.
- **Exchange**: an offer, its answers, and the record messages and acknowledgements that follow it.
- **Offer**: an `OFFER` message. It names the types whose records the sender wants to send and carries their writer schemas.
- **Answer**: an `ACCEPT` or `DECLINE` message. It names one offer and some of its types.
- **Accepted offer of a type**: an offer that includes the type, that the receiver has accepted for that type, and that has not ended (section 4.3).
- **Record message**: a `DATA`, `DELETE` or `WITHDRAW` message ([records.md](records.md), section 1).
- **Reply**: an `ACCEPT`, `DECLINE`, `ACK`, `ERROR` or `PROPOSAL_REPLY` message; it is about messages of the app it goes to.
- **Addressee**: the app a message is for, and of its devices the one whose key is in the `to` field of the body (section 9.1).

The receiver's user confirms the other app's key before the two apps exchange records ([keys.md](keys.md), section 3.2). Nothing in this document applies to a message from a key that the receiver's user has not accepted, except that the receiver reads the app name from its `MANIFEST` and MAY keep its messages until the user decides, as [keys.md](keys.md), section 3.2, says. The key of another device of the app's own device set needs no such confirmation; [sync.md](sync.md), section 7, says how the devices of one set exchange and where their exchange differs from this document.

## 2. Messages

| Kind             | `record` | Body                                                     | `to` in the body | Sent by                              | In a file                    |
| ---------------- | -------- | -------------------------------------------------------- | ---------------- | ------------------------------------ | ---------------------------- |
| `MANIFEST`       | `null`   | `axt.Manifest` ([manifest.md](manifest.md))              | no               | each app, about itself               | at most one, after the chain |
| `OFFER`          | `null`   | `axt.Offer` (section 4)                                  | yes              | the sender                           | no                           |
| `ACCEPT`         | `null`   | `axt.Accept` (section 5)                                 | yes              | the receiver                         | no                           |
| `DECLINE`        | `null`   | `axt.Decline` (section 5)                                | yes              | the receiver                         | no                           |
| `DATA`           | required | the record ([records.md](records.md), section 4.1)       | no               | the sender                           | yes                          |
| `DELETE`         | required | empty ([records.md](records.md), section 4.2)            | no               | the sender                           | yes                          |
| `WITHDRAW`       | required | `axt.Withdraw` ([shares.md](shares.md), section 3)       | yes              | the sender                           | yes                          |
| `ACK`            | `null`   | `axt.Ack` (section 7)                                    | yes              | the receiver                         | no                           |
| `ERROR`          | `null`   | `axt.Error` (section 8)                                  | yes              | the app that got a message           | no                           |
| `DEVICE_JOIN`    | `null`   | `axt.DeviceJoin` ([keys.md](keys.md), section 5.2)       | yes              | a new device                         | no                           |
| `DEVICE_ADD`     | `null`   | `axt.DeviceAdd` ([keys.md](keys.md), section 5.2)        | no               | a device of the sender               | at the start                 |
| `DEVICE_REMOVE`  | `null`   | `axt.DeviceRemove` ([keys.md](keys.md), section 5.3)     | no               | a device of the sender               | at the start                 |
| `CHANGE`         | required | `axt.Change` ([sync.md](sync.md), section 8)             | yes              | a device, to a device of its own set | no                           |
| `RESYNC`         | required | `axt.Resync` ([sync.md](sync.md), section 11)            | yes              | a device, to a device of its own set | no                           |
| `FORWARD`        | required | `axt.Forward` ([sync.md](sync.md), section 18)           | yes              | a device, to a device of its own set | no                           |
| `PROPOSAL`       | required | `axt.Proposal` ([shares.md](shares.md), section 13)      | yes              | a receiver, to the record's sender   | no                           |
| `PROPOSAL_REPLY` | required | `axt.ProposalReply` ([shares.md](shares.md), section 14) | yes              | the record's sender, to the proposer | no                           |

The column "In a file" is that of [transports.md](transports.md), section 2.1. The schemas are in [types/axt/](../types/axt/); their fingerprints are in section 16. Each is a schema of the specification and changes only with a new envelope format ([manifest.md](manifest.md), section 2). An app MUST reject a message whose `record` is present where the table says `null` or absent where it is required, and a message whose body fingerprint is not the one of its kind and format ([envelope.md](envelope.md), section 3.1), with the error `INVALID_MESSAGE` (section 8).

`MANIFEST`, `DATA`, `DELETE`, `DEVICE_ADD` and `DEVICE_REMOVE` are the same for every receiver: a manifest says what an app takes, a record message is sent under the same id to every receiver ([records.md](records.md), section 2), and an addition or a removal of a device is for every app that knows the sender. They carry no addressee, so that they keep their signature when they are passed on or put into a file ([keys.md](keys.md), sections 2.2 and 2.6). A `WITHDRAW` is not the same for every receiver: the sender sends it only to the receivers from which it withdraws a record, so its body names the device it is for ([shares.md](shares.md), section 3.1). An offer depends on the receiver's manifest and the replies on the messages of one app, so their bodies name the device they are for; a `DEVICE_JOIN` is for the one device whose join code was scanned. A `CHANGE` and a `RESYNC` travel only between the devices of one set: each holds what one of them has not acknowledged, or asks one of them, and names that device ([sync.md](sync.md), sections 8 and 11). A `FORWARD` travels between them as well: in it a device passes a message of another app on to a device of its own set, as the signed message it got ([sync.md](sync.md), section 18). No other app sends or takes these three kinds. A `PROPOSAL` is for the one device of the record's sender that the proposer chose, and a `PROPOSAL_REPLY` for the one device that sent the proposal, so both name that device; neither is a record message, although both carry `record` to name the record they are about ([shares.md](shares.md), section 12.1).

## 3. Opening a live connection

### 3.1 The first messages

When a live connection is open, after both apps' `HELLO` ([transports.md](transports.md), section 4.6), each app:

1. sends its chain, the `DEVICE_ADD` and `DEVICE_REMOVE` messages of section 3.3, if it has any to send to the other app;
2. sends its `MANIFEST` ([manifest.md](manifest.md), section 5.1), in the format of section 3.2;
3. waits for a valid `MANIFEST` of the other app.

In a connection that a join code opened, these steps wait: neither app sends its chain or its `MANIFEST` before the `DEVICE_JOIN` is answered (section 3.3).

Neither app waits for the other before it sends these. An app MUST send its `MANIFEST` before any message of another kind except `DEVICE_ADD`, `DEVICE_REMOVE` and `DEVICE_JOIN`. An app MUST NOT process a message of another kind than `MANIFEST`, `DEVICE_ADD`, `DEVICE_REMOVE`, `DEVICE_JOIN` or `ERROR` that arrives before the other app's valid `MANIFEST`; it MAY close the connection.

A `DEVICE_ADD` or a `DEVICE_REMOVE` MAY also come later in the connection, after messages of other kinds, and MAY carry a `sender` other than the connection key; neither closes the connection ([transports.md](transports.md), section 4.5). The same holds for a `MANIFEST` that a device of the app's own set passes on for another device of that set: it MAY come at any time, carries the key of that other device as its `sender`, and is taken or ignored as [sync.md](sync.md), section 13.2, says. It is not the other app's `MANIFEST` of step 3, and it does not make its `sender` the other end of the connection. A `DEVICE_JOIN` is not exempt: one whose `sender` is not the connection key closes the connection, and one in a connection that no join code opened is ignored without an error, before the `MANIFEST` and after it (section 3.3).

An app MUST NOT send an `OFFER` before it has received a valid `MANIFEST` of the other app in the connection ([manifest.md](manifest.md), section 5.1), and before its user has accepted the other app's key ([keys.md](keys.md), section 3.2). It MAY answer offers and send acknowledgements as soon as it has the other app's valid `MANIFEST` and its user has accepted the key. Errors are reported as section 8.3 says.

A `MANIFEST` that is not valid ([manifest.md](manifest.md), section 4) is reported with `MANIFEST_INVALID` (section 8). The app keeps the manifest it had of the other app before, if any, and does not offer by a manifest it has not received in the connection. The other app MAY send a valid `MANIFEST` later in the connection; until then, nothing is offered to it.

### 3.2 The envelope format

A `MANIFEST` is written before an app knows the formats of the other. Each app writes the `MANIFEST` of step 2 in the lowest envelope format it supports. In 0.1.0 there is one format, `1`, and every app supports it.

When an app has the other app's valid `MANIFEST`, it writes every further message to it in the **chosen format**: the highest format that is both one it writes and one in the other app's `formats`. Each direction of a connection has its own chosen format; for two apps of 0.1.0 both are `1`.

- If the format of the app's own `MANIFEST` is not in the other app's `formats`, the other app could not read it. The app sends its `MANIFEST` again, in the chosen format.
- If there is no chosen format, the two apps have no format in common. The app MUST NOT send further messages and closes the connection.
- A later `MANIFEST` of the other app with other `formats` changes the chosen format from its arrival on ([manifest.md](manifest.md), section 6).

A message whose envelope fingerprint is not of a format the receiver supports is rejected without decoding ([envelope.md](envelope.md), section 3.1). Before the receiver has the other app's `MANIFEST`, it does not report it: it cannot verify the message, and the exchange of manifests above resolves a `MANIFEST` in an unread format. After that, it reports it with `FORMAT_UNSUPPORTED` (section 8), whose `fingerprint` is the message's envelope fingerprint.

### 3.3 Additions and removals of devices

A device that has a chain ([keys.md](keys.md), section 5.4) sends it, oldest message first, to each app it exchanges with: as the first messages of each of its next three live connections with the app, before its `MANIFEST`, and, to an app it exchanges with through the relay, three times through the relay: at once, before any other message it sends there, and twice more, each after the holding time has passed (section 11). Then it stops. Whenever its chain grows, by an addition or a removal that it signs or gets of its own set, it counts anew and sends the whole chain three times in each way again. For an app it begins to exchange with later, the count begins then.

The receiver applies a `DEVICE_ADD` and a `DEVICE_REMOVE` by [keys.md](keys.md), section 5.5, without asking its user. Nothing acknowledges them:

- **Applied or ignored.** The receiver sends no reply. When it applies the removal of the connection key, it closes the connection ([keys.md](keys.md), section 5.5). A repeat of an addition or a removal it has applied is ignored without an error, so a chain is safe to send again.
- **Rejected.** For a `DEVICE_ADD` or a `DEVICE_REMOVE` that [keys.md](keys.md), section 5.5, has the receiver reject, and for a `DEVICE_JOIN` that the device it is for rejects or whose user declines it ([keys.md](keys.md), section 5.2), the receiver sends `DEVICE_REJECTED` (section 8) in a live connection, on the connection the message came in. Its `to` is the connection key, as for every `ERROR` in a live connection (section 9.1): the key of the device that sent the message, which for an addition or a removal need not be the key that signed it. Its `message_hash` names the message. For a message of a chain that arrives before the other app's `MANIFEST`, the receiver holds the `DEVICE_REJECTED` and sends it among its replies to that `MANIFEST` (section 8.3). The device stops sending that message to that app. Through a relay, the receiver sends nothing.
- **An unknown signer.** A `DEVICE_ADD` by a key the receiver does not know, for a device that is a current key of a sender it knows, adds the signer to that sender; a message it cannot place is kept until the chain has been read, and gets no reply ([keys.md](keys.md), section 5.5, step 3). A kept message that a later try rejects is not reported either.
- **The rest of the chain.** A message of a chain that fails its signature, its key or its proof is rejected for itself, and reported as section 8.3 allows; the receiver goes on with the messages after it, unless it closes the connection (section 8.3).

**Removals.** A removal makes the chain grow, so the device that signs it, and every device of the set that gets it, sends its whole chain again as above ([keys.md](keys.md), section 5.3). It sends the chain and not the removal alone, since the app may not know the key that signed the removal. A chain is safe to repeat, and no reply ends its sending earlier. A device that applies the removal of another device of its own set holds the chain back from the apps that it knows only by what that device passed on, until its user has kept them ([sync.md](sync.md), section 17.2).

**Joining.** A `DEVICE_JOIN` travels only in the live connection that a join code opened, as the first message of the new device, before its `MANIFEST` ([keys.md](keys.md), section 5.2; [transports.md](transports.md), section 4.7). Until the `DEVICE_JOIN` is answered, neither device sends its chain or its `MANIFEST`. The device that showed the code answers on the connection with its chain, which holds the new device's `DEVICE_ADD`, or with `DEVICE_REJECTED`, after which it closes the connection. Its answer waits for its user and has no time limit: the 30 seconds of section 12 do not run while the user decides, and the `PING` frames keep the connection open ([transports.md](transports.md), section 4.6). After an answer with the chain, the connection goes on as any other, with the steps of section 3.1. A sent `DEVICE_JOIN` binds the new device whatever the answer ([keys.md](keys.md), section 5.2). A repeat of a `DEVICE_JOIN` from the same key is answered as the first was; one from another key is ignored. A `DEVICE_JOIN` anywhere else is ignored without a report, whether it comes before or after the `MANIFEST`.

## 4. The offer

### 4.1 Content

An `OFFER` message carries `record` `null` and one `axt.Offer` as its body ([types/axt/Offer.avsc](../types/axt/Offer.avsc)):

| Field            | Avro type                     | Content                                                                                            |
| ---------------- | ----------------------------- | -------------------------------------------------------------------------------------------------- |
| `to`             | `fixed` of 32, `axt.OfferTo`  | The Ed25519 public key of the receiver, the key of the device the offer goes to (section 9.1)      |
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

A sender MUST offer only types that fit the receiver's manifest ([manifest.md](manifest.md), section 5.3): the manifest of the device whose key is the offer's `to`. A set of types whose schemas do not fit into one message of 16 MiB is offered in several offers.

### 4.3 How long an offer stays open

An offer belongs to the channel it was sent through.

- **Live connection.** An offer made in a live connection ends when the connection ends. A new connection starts again with manifests and offers (section 3.1).
- **Relay.** An offer made through the relay does not end with time; it ends only for one of the reasons below.
- **Both.** An offer also ends for a type when the sender makes a later offer of that type in the same channel, and when the type no longer fits the receiver's manifest ([manifest.md](manifest.md), section 6). It ends for every type when the receiver forgets the sender, or the sender forgets the receiver ([keys.md](keys.md), section 3.4), and when the key that signed it or the key in its `to` is removed from its sender ([keys.md](keys.md), section 5.5).

An offer that has ended for a type no longer allows record messages of that type. Its schemas are no longer used for decoding (section 6.2); [envelope.md](envelope.md), section 3, keeps a schema for as long as this section keeps the offer open.

Each exchange starts with an offer. The records a sender wants to send, and their updates and deletions, all follow the same steps: offer, answer, record messages, acknowledgement.

- **In a live connection**, an accepted offer covers the record messages of its type for the rest of the connection, including changes the sender's user makes while the connection is open.
- **Through a relay**, an accepted offer covers the record messages that were due when the sender made the offer, and their resends (section 11). For a record that changes after the offer, the sender makes a new offer. Through a relay, an exchange therefore takes three trips before its acknowledgement: the offer, the answer and the records. A receiver that has stored its user's answer can answer at once (section 5.2).

The receiver keeps, for each sender, channel and type, the **current offer**: the last offer of that type it got from the sender in that channel, its schema and its answer. A sender may make offers through the relay faster than they arrive, and a relay may deliver them out of order. A receiver that gets again an offer it has already answered answers it again as before, and the offer does not become current again (section 9.2). A receiver SHOULD keep the ids of the offers it answered through the relay, with their answers, for at least as long as a relay may hold a message: 15 days ([transports.md](transports.md), section 5.5).

Between the devices of one set, the current offer is kept for each fingerprint of a schema, not for each type, and a later offer ends an earlier one only for a schema with the same fingerprint ([sync.md](sync.md), section 7.2).

## 5. Accept and decline

### 5.1 Content

An `ACCEPT` or `DECLINE` message carries `record` `null` and one `axt.Accept` or `axt.Decline` as its body ([types/axt/Accept.avsc](../types/axt/Accept.avsc), [types/axt/Decline.avsc](../types/axt/Decline.avsc)):

| Field            | In        | Avro type                     | Content                                      |
| ---------------- | --------- | ----------------------------- | -------------------------------------------- |
| `to`             | both      | `fixed` of 32                 | The Ed25519 public key that signed the offer |
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
- A receiver MUST decline a type whose schema defines a time type or `axt.Relation` other than as published, or another named type in the namespace `axt` than these and the nested types of `axt.Relation`, with `DOES_NOT_RESOLVE` ([time.md](time.md), section 3.1; [types.md](types.md), section 8.6).
- A receiver MAY decline any type with `NOT_WANTED`.
- A receiver MUST NOT accept a type that it has declined for the same offer, and MUST NOT answer a type of an offer differently a second time.

A fit is not an acceptance ([manifest.md](manifest.md), section 5.4): the receiver's user decides whether the records are taken. A receiver MAY keep its user's answer for a sender and a type and give it to later offers of that type from the same sender without asking again. It SHOULD let its user change such an answer, and SHOULD ask again when a later offer has a schema of another version.

### 5.3 What the sender takes

The sender of an offer takes an answer when its `to` is its own key, the key that signed the offer (section 9.1), it names an offer the sender made to the app that sent the answer, and each type it names is a type of that offer. An answer whose types are not types of the offer, or that names a type twice, is reported with `INVALID_MESSAGE`. Of each answered type, the sender takes:

- only the answer to its latest offer of that type to that receiver in that channel; it ignores answers to earlier offers of the type, since a later offer replaced them (section 4.3);
- only the first answer for that offer and type. A later `ACCEPT` or `DECLINE` of the same offer and type, a repeat or a reordered message, is ignored.

Between the devices of one set, "its latest offer of that type" is its latest offer of a schema with that fingerprint: two schemas of one type can be on offer at once ([sync.md](sync.md), section 7.2).

After an `ACCEPT` of a type, the sender may send the type's record messages (section 6.1). After a `DECLINE`, it sends none, and SHOULD NOT offer the type to that receiver again until the cause has changed. For `NOT_WANTED`, that means its user asks to offer it again. For `DOES_NOT_FIT`, the receiver's manifest has a higher revision. For `DOES_NOT_RESOLVE`, the sender has another schema of the type.

### 5.4 Two kinds

`ACCEPT` and `DECLINE` stay two kinds of the envelope rather than one kind with a field for the decision. A declined type carries a reason and an accepted one carries none, and each kind has one body schema ([envelope.md](envelope.md), section 2.2). An offer of several types that are partly taken is answered with one message of each kind, as in the example of section 17. Keeping both kinds also leaves the envelope schema of [envelope.md](envelope.md), its fingerprint and the examples built on it as they are.

## 6. Records

### 6.1 Sending

- A sender MUST NOT send a record message of a type unless it has an accepted offer of that type in the channel (section 4.3). It writes each `DATA` with the schema that offer carries for the type. A `DATA` message thus uses only a schema its sender offered in a signed `OFFER` ([keys.md](keys.md), section 2.4).
- A `DELETE` is sent under an accepted offer of the type of the record it deletes, and so is a `WITHDRAW` ([shares.md](shares.md), section 8.1).
- To an app of another user, a device sends a record message only while the record is shared with that app, or a `WITHDRAW` while it is withdrawn from it ([shares.md](shares.md), section 2.2).
- The sender MAY send the record messages of an offer in any order, and MAY send them without waiting for acknowledgements. Records that refer to each other need not arrive in any order ([records.md](records.md), section 8).
- A sender MUST NOT send a record message of a type whose offer has ended (section 4.3). It offers the type again first.

The steps are the same for a new record, an update and a deletion ([records.md](records.md), section 4; [manifest.md](manifest.md), section 5.3).

### 6.2 Processing

A receiver processes a record message in these steps. A step that fails ends the processing: the message has no outcome, the receiver changes nothing, and it reports the failure with the error code named ([records.md](records.md), section 7).

| Step | Check                                                                                                                                                                                                                                                                     | If it fails         |
| ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------- |
| 1    | The message and its envelope are valid, and its signature verifies, as for every message (section 8.2)                                                                                                                                                                    | as section 8.2 says |
| 2    | The id is a UUID in text form, neither the nil UUID nor the max UUID ([records.md](records.md), section 2)                                                                                                                                                                | `RECORD_ID_INVALID` |
| 3    | The version is at least 1 ([records.md](records.md), section 3)                                                                                                                                                                                                           | `VERSION_INVALID`   |
| 4    | `DATA`: the body is a single-object encoding whose fingerprint is that of the schema of a current offer of the sender in the channel                                                                                                                                      | `SCHEMA_UNKNOWN`    |
| 5    | `DATA`: that offer is accepted for the schema's type, and the type, in the schema's version, still fits the receiver's manifest. `DELETE`, `WITHDRAW`: as below                                                                                                           | `NOT_ACCEPTED`      |
| 6    | `DATA`: the receiver keeps no other full name for the id ([records.md](records.md), section 4.3)                                                                                                                                                                          | `TYPE_CHANGED`      |
| 7    | The version rule ([records.md](records.md), section 5.2): a version equal to or below the receiver's version has the outcome `DUPLICATE` or `STALE`, and the processing ends with it                                                                                      | (no failure)        |
| 8    | `DATA`: the body decodes with the offered schema, resolved against the receiver's reader schema, with no bytes left over, with well-formed strings, and to a data depth of at most 32 ([types.md](types.md), section 5.7)                                                 | `UNDECODABLE`       |
| 9    | `DATA`: every time value is valid ([time.md](time.md), section 8) and every relation keeps the rules of [types.md](types.md), section 8.4; and, if the receiver checks them, every value keeps the checks of the offered schema ([metadata.md](metadata.md), section 7.1) | `VALUE_INVALID`     |
| 10   | The receiver applies the message ([records.md](records.md), sections 5 and 6)                                                                                                                                                                                             | (no failure)        |

A `DELETE` has no body and so names no type. The receiver checks step 5 for it by the type it keeps for the id. A `DELETE` of an id whose record or tombstone holds a type needs an accepted offer of that type. A `DELETE` of an id for which the receiver keeps no type, because it does not know the id ([records.md](records.md), section 5.3) or keeps only a tombstone without a type, needs an accepted offer of any type from the same sender in the channel.

A `WITHDRAW` names no type either. Step 5 does not check it for an id that the receiver holds from that sender, as a record or a tombstone, and checks it as a `DELETE` of an id the receiver does not hold otherwise; a `WITHDRAW` of a device of the receiver's own set fails step 5 in every case ([shares.md](shares.md), section 4.1). In step 1 the receiver checks, after the signature, first `record`, then that the body is one `axt.Withdraw`, then its `to`: a missing `record` or another body fails with `INVALID_MESSAGE`, and another key in `to` is ignored without a report (section 9.1). The steps 4, 6, 8 and 9 do not apply to it, and its step 10 is that of [shares.md](shares.md), section 4.2.

The receiver decodes a body only with the schema of the current offer whose fingerprint the body names, and only among that sender's offers ([keys.md](keys.md), section 2.4). It MUST NOT try other schemas in its place ([envelope.md](envelope.md), section 3.1). `SCHEMA_UNKNOWN` is both the rejection and the request for the schema that [envelope.md](envelope.md), section 3.1, names. The error's `fingerprint` is the body's fingerprint, and the sender answers it by offering the type again (section 8.2).

A receiver MAY stop decoding a body as soon as it exceeds the data depth of 32; it MUST NOT apply any part of it.

The devices of one set send each other no record messages: the records of the set travel between them as `CHANGE` messages, which are processed by the steps of [sync.md](sync.md), section 8.3. An offer that a device accepted from another device of its own set is no accepted offer for a record message, so a `DATA`, a `DELETE` or a `WITHDRAW` of such a device fails step 5 with `NOT_ACCEPTED` ([sync.md](sync.md), section 7.2).

A receiver can itself be a device of a set with other devices. The device that gets a record message from its sender processes it by the steps above and is the only device of its set that answers the sender; it passes the message on to the other devices of its set in a `FORWARD`. A device that gets a record message in a `FORWARD` processes it without the steps 4 and 5, with the schema that the `FORWARD` carries, and sends the sender nothing ([sync.md](sync.md), sections 17.2 and 19.5). A device that keeps the messages of its senders for the other devices of its set ([sync.md](sync.md), section 20.1) takes a few messages that step 7 ends with `DUPLICATE` or `STALE` into what it keeps all the same, after the steps 8 and 9, and the outcome stays ([sync.md](sync.md), section 19.5, step 7). What step 10 does with the changes of the set's user, and which outcome the answering device reports, is in [sync.md](sync.md), section 22.2.

Step 9 checks the value that step 8 decoded, by the rules set for it rather than by its bytes ([metadata.md](metadata.md), section 7.3). Its error's `field` names the first value that fails, in the order of the encoding, by the field names of the offered schema ([metadata.md](metadata.md), section 7.2). Every receiver checks the rules of the time types. A receiver checks the checks of the attributes only if it chooses to; one that does not, or that takes a record which breaks one, goes on to step 10 and keeps the value as received ([metadata.md](metadata.md), section 7.1).

## 7. Acknowledgement

### 7.1 Content

An `ACK` message carries `record` `null` and one `axt.Ack` as its body ([types/axt/Ack.avsc](../types/axt/Ack.avsc)). One `ACK` reports up to 4,096 record messages:

| Field                        | Avro type                     | Content                                                                                                                    |
| ---------------------------- | ----------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `to`                         | `fixed` of 32                 | The key that signed the acknowledged messages, the key of one device of their sender                                       |
| `records`                    | array of `axt.AckRecord`      | The outcomes, 1 to 4,096                                                                                                   |
| `records[].id`               | `string`, logical type `uuid` | The record's id, as the acknowledged message carried it                                                                    |
| `records[].version`          | `long`                        | The version of the acknowledged message                                                                                    |
| `records[].outcome`          | enum `axt.AckOutcome`         | `APPLIED`, `MERGED`, `KEPT`, `DUPLICATE` or `STALE` ([records.md](records.md), section 7), or `WITHDRAWN` for a `WITHDRAW` |
| `records[].receiver_version` | `long`                        | The receiver's version of the record after the message                                                                     |
| `records[].kept_fields`      | array of `string`             | For `MERGED`, the fields the receiver kept, by the names of the message's writer schema                                    |

One `ACK` reports record messages signed with one key. The record messages of two devices of a sender are acknowledged in two messages, each to the key that signed them (section 9.1).

The outcome `WITHDRAWN` is that of a `WITHDRAW` only, whose outcomes are `WITHDRAWN`, `KEPT`, `DUPLICATE` and `STALE`; `APPLIED` and `MERGED` are never the outcome of a `WITHDRAW` ([shares.md](shares.md), section 5.1). [shares.md](shares.md), section 5.2, says what a sender does with an outcome that does not fit the kind of the message it sent.

An `ACK` also reports `CHANGE` messages, the requests made with `RESYNC` and `FORWARD` messages, between the devices of one set. An `ACK` whose `sender` is a device of the app's own set reports these only, a `RESYNC` with the id of the request and a `FORWARD` with the id of the forward, each with the version 1, the outcome `APPLIED` or `DUPLICATE` and the `receiver_version` 1 ([sync.md](sync.md), sections 11.2 and 18.4), and every other `ACK` reports record messages only; [sync.md](sync.md), section 9.1, defines the entries for a `CHANGE`, whose outcome is `APPLIED`, `DUPLICATE` or `STALE` and whose `receiver_version` is, for every outcome, the acknowledging device's state stamp of the record after the message, and when such an `ACK` is valid. The rules below are for an `ACK` of record messages.

An `ACK` of record messages is valid when:

- `records` has 1 to 4,096 entries;
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
- A device acknowledges every `CHANGE` it processed to an outcome in the same way and within the same time ([sync.md](sync.md), section 9.1).
- Of the devices of a set, the one that got a record message from its sender acknowledges it. A device that gets the message in a `FORWARD` of a device of its own set acknowledges the `FORWARD` to that device, within the same time, and sends the sender no `ACK` ([sync.md](sync.md), sections 17.2 and 18.4).

### 7.3 Outcomes decided later

A receiver MAY ask its user before it takes a record message: when a `DELETE` or a `WITHDRAW` meets local changes ([records.md](records.md), section 6.4; [shares.md](shares.md), section 4.3), or when a `DATA` would bring back a record its user deleted ([records.md](records.md), section 6.3). It MUST NOT hold back the acknowledgement until the user decides. It reports what it has done so far, which is `KEPT` or `MERGED`: the record stays as the user left it, and the receiver's version is the message's version.

When the user later decides to take the message, the receiver sends a further `ACK` with the same id and version and the outcome `APPLIED`, or, for a `WITHDRAW`, `WITHDRAWN`. A sender that has `KEPT` or `MERGED` for an id and version takes a later `APPLIED` for the same id and version over it, and one that has `KEPT` takes a later `WITHDRAWN` over it, in whatever order the two arrive. These are the only changes of an outcome: a decision of the user not to take the message leaves the `KEPT` or `MERGED` it already has.

Where the receiver is a device set, the user can decide on another device than the one that reported. The device that reported `KEPT` sends the further `ACK`, once what it holds of the record shows the decision ([sync.md](sync.md), section 22.3).

### 7.4 What the sender does with an acknowledgement

A device takes the entries of a valid `ACK` whose `to` is its own key (section 9.1). What it does with the entries of an `ACK` of a device of its own set, which are about `CHANGE`, `RESYNC` and `FORWARD` messages, is in [sync.md](sync.md), sections 9.2, 11.3 and 18.4. A sender keeps the outcomes of a record message for each key of the receiver that acknowledged it: two devices of a receiver can each report an outcome for one id and version ([sync.md](sync.md), section 17.2), each says what that device did, and the rules below hold among the outcomes of one key only. For each id and version of a record message, and each acknowledging key:

- The first outcome it gets stands, with two exceptions: `APPLIED` replaces `KEPT` and `MERGED`, and `WITHDRAWN` replaces `KEPT` (section 7.3); and every other outcome replaces `DUPLICATE`, which a resend can bring before the acknowledgement of the first copy. A repeated entry, and `DUPLICATE` for a message it has another outcome for, change nothing.
- It MAY show its user that the receiver kept changes of its own (`MERGED`, `KEPT`).
- After `STALE`, it counts the `receiver_version` as a stamp it has seen and acts as [records.md](records.md), section 7, says: a `receiver_version` above the highest version it knows of the record is a version that another device of its set gave, or one it gave itself and lost (section 10), and can make it send the record again ([sync.md](sync.md), section 5.3).
- A message with an outcome is delivered. The sender does not send it again, except for the reasons of section 11.
- Outcomes of a key that was removed from the receiver no longer count. Once the sender has applied the removal ([keys.md](keys.md), section 5.5), a record message whose only outcomes are of removed keys of the receiver counts as one without an outcome, and the sender sends again, to the key that it now uses for that receiver (section 9.1), the current state of each such record, under an offer accepted there: a `DATA` with the current version of a record that exists, a `DELETE` with the version of the deletion of one deleted in between (section 11), and, to an app of another user, what it owes that app of each record ([shares.md](shares.md), section 5.3).

## 8. Errors

### 8.1 Content

An `ERROR` message carries `record` `null` and one `axt.Error` as its body ([types/axt/Error.avsc](../types/axt/Error.avsc)):

| Field          | Avro type                   | Content                                                                                                                                                                                                                            |
| -------------- | --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `to`           | `fixed` of 32               | The Ed25519 public key of the device that sent the reported message: in a live connection the connection key, through a relay the key that signed it                                                                               |
| `code`         | enum `axt.ErrorCode`        | Why the message was not processed (section 8.2)                                                                                                                                                                                    |
| `message_hash` | `fixed` of 32               | The SHA-256 of the reported message as received, from its single-object marker to its last byte; through a relay, after opening and removing the padding ([keys.md](keys.md), section 4.5)                                         |
| `record`       | `null` or `axt.ErrorRecord` | The `record` field of the reported message, as it carried it: `id` as a plain string and `version`                                                                                                                                 |
| `fingerprint`  | `null` or `fixed` of 8      | For `SCHEMA_UNKNOWN` the body's fingerprint, or for a `CHANGE` that of the schema it lacks (section 8.2), or for a `PROPOSAL` that of the first entry's schema it lacks; for `FORMAT_UNSUPPORTED` the envelope's; `null` otherwise |
| `field`        | `null` or `string`          | For `VALUE_INVALID`, the field path of the value that breaks a rule ([metadata.md](metadata.md), section 7.2); `null` otherwise                                                                                                    |
| `detail`       | `string`                    | A description for logs, in English, on one line of at most 1,024 bytes; may be empty, and MUST be empty for `PROPOSALS_NOT_TAKEN` ([shares.md](shares.md), section 13.3)                                                           |

`record` is present when the reported message's signature verified, it carried a `record`, and its id is at most 64 bytes long; it is `null` otherwise. `field` is a string for `VALUE_INVALID` only, the empty string for the record itself; a path above 1,024 bytes is reported as `null`. Its `id` is a plain string, because the id it reports may not be a UUID. `message_hash` names the message exactly, also one that could not be decoded; the sender can match it against the messages it sent. `detail` is for logs and support. An app MUST show it as text only, and MUST NOT show it to its user as the only explanation of an error.

### 8.2 Codes

The receiver checks every message in this order: size, envelope, signature, sender, addressee, body ([keys.md](keys.md), section 2.3, allows reading the format and the end before the signature is verified). The first check that fails gives the code.

| Code                  | The receiver got                                                                                                                                                                                                                                                                                                                                                                                                                                                     | The sender then                                                                                                                                                           |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `TOO_LARGE`           | A message above 16 MiB, rejected without decoding, or an offer with a schema above the schema limits ([envelope.md](envelope.md), section 8)                                                                                                                                                                                                                                                                                                                         | Stops sending it; a sender that produced it breaks [envelope.md](envelope.md), section 8                                                                                  |
| `FORMAT_UNSUPPORTED`  | A message whose envelope fingerprint is not of a format the receiver supports (section 3.2)                                                                                                                                                                                                                                                                                                                                                                          | Writes in the chosen format                                                                                                                                               |
| `INVALID_MESSAGE`     | Bytes that are not a valid message of their kind: bytes left over after the envelope or the body, a body that is not the kind's schema, a `record` where none belongs or none where one is required, a `format` field that is not the envelope fingerprint's format ([keys.md](keys.md), section 2.2), a string that is not well-formed UTF-8 in the envelope or a body of this specification, an answer of section 5.3 or an `ACK` of section 7.1 that is not valid | Logs it; it is a fault of the sender's implementation                                                                                                                     |
| `SIGNATURE_INVALID`   | A message whose signature does not verify ([keys.md](keys.md), section 2.3)                                                                                                                                                                                                                                                                                                                                                                                          | Logs it                                                                                                                                                                   |
| `MANIFEST_INVALID`    | A `MANIFEST` that is not valid ([manifest.md](manifest.md), section 4)                                                                                                                                                                                                                                                                                                                                                                                               | Sends a valid one; until then the receiver offers it nothing                                                                                                              |
| `OFFER_INVALID`       | An `OFFER` that is not valid (section 4.2), other than for its size                                                                                                                                                                                                                                                                                                                                                                                                  | Sends no record messages under it                                                                                                                                         |
| `RECORD_ID_INVALID`   | A record message whose id is not a UUID in text form, or is the nil or the max UUID                                                                                                                                                                                                                                                                                                                                                                                  | Logs it                                                                                                                                                                   |
| `VERSION_INVALID`     | A record message whose version is below 1                                                                                                                                                                                                                                                                                                                                                                                                                            | Logs it                                                                                                                                                                   |
| `SCHEMA_UNKNOWN`      | A `DATA` whose body fingerprint is not that of the schema of a current offer of its sender in the channel                                                                                                                                                                                                                                                                                                                                                            | Offers the type again with that schema, and sends the record again once it is accepted                                                                                    |
| `NOT_ACCEPTED`        | A record message of a type without an accepted offer in the channel, or of a type that no longer fits the receiver's manifest (section 6.2, step 5); or a `FORWARD` whose inner message is signed with a refused key, or with a removed key whose removal the forwarding device has not shown to have ([sync.md](sync.md), sections 18.3 and 19.2)                                                                                                                   | Stops sending records of the type there; offers it again if it fits                                                                                                       |
| `TYPE_CHANGED`        | A `DATA` whose type has another full name than the one the receiver keeps for the id ([records.md](records.md), section 4.3)                                                                                                                                                                                                                                                                                                                                         | Logs it; the record keeps its type                                                                                                                                        |
| `UNDECODABLE`         | A `DATA` whose body does not decode with its offered schema: cut short, bytes left over, a string that is not well-formed, a data depth above 32 ([types.md](types.md), section 5.7)                                                                                                                                                                                                                                                                                 | Logs it                                                                                                                                                                   |
| `VALUE_INVALID`       | A `DATA` whose body decodes but holds a time value that is not valid ([time.md](time.md), section 8) or a relation that breaks a rule of [types.md](types.md), section 8.4, or, at a receiver that checks them, a value that breaks a check of the offered schema ([metadata.md](metadata.md), section 7.1); `field` names the value                                                                                                                                 | Shows its user the record and the field if it can; sends the record again only after it has changed                                                                       |
| `DEVICE_REJECTED`     | A `DEVICE_ADD` or a `DEVICE_REMOVE` that [keys.md](keys.md), section 5.5, has the receiver reject, or a `DEVICE_JOIN` that the device it is for rejects or whose user declines it ([keys.md](keys.md), section 5.2); reported in a live connection only (section 3.3); or a `FORWARD` of such an addition or removal, reported to the forwarding device also through a relay ([sync.md](sync.md), section 19.3)                                                      | Stops sending that message to that app (section 3.3)                                                                                                                      |
| `RECORD_UNKNOWN`      | A `CHANGE` that does not hold the whole record, for a record that the receiving device does not have or of which it holds only the removal ([sync.md](sync.md), section 8.3, step 10); or a `CHANGE` about a record received from another app whose sender the receiving device does not know ([sync.md](sync.md), section 21.4)                                                                                                                                     | Sends the record whole ([sync.md](sync.md), section 9.3); for a record received from another app, forwards the sender's messages first ([sync.md](sync.md), section 21.5) |
| `PROPOSALS_NOT_TAKEN` | A `PROPOSAL` for a record whose sender takes none from the proposer: the record is not there or not shared with the proposer, the receiver's manifest takes no proposals for its type, the receiver's user stopped the proposer's proposals, or the proposer is beyond a limit ([shares.md](shares.md), section 13.3, step 5)                                                                                                                                        | Sends the record's sender no further proposal for the record until its manifest or the record has changed, or a reply arrives ([shares.md](shares.md), section 16.3)      |

A `CHANGE` is checked by the steps of [sync.md](sync.md), section 8.3, in their order. Besides `RECORD_UNKNOWN`, they give `RECORD_ID_INVALID`, `VERSION_INVALID`, `INVALID_MESSAGE`, `SCHEMA_UNKNOWN`, `TYPE_CHANGED`, `UNDECODABLE` and `VALUE_INVALID`, each for the failure that the code stands for in a record message. For `SCHEMA_UNKNOWN`, the error's `fingerprint` is then not that of the body, which is `axt.Change`, but that of the first schema that a field state of the message names and that the device does not hold. [sync.md](sync.md), section 9.3, says what the device that sent the `CHANGE` does with each code. A `RESYNC` is checked by the steps of [sync.md](sync.md), section 11.1. A `FORWARD` is checked by the steps of [sync.md](sync.md), section 18.3, which also check the message inside it. Every error about a `FORWARD`, also one for a failure of the message inside, goes to the device of the set that sent the `FORWARD`, and never to the app that signed the message inside; the steps give `INVALID_MESSAGE`, `RECORD_ID_INVALID`, `VERSION_INVALID`, `FORMAT_UNSUPPORTED`, `TOO_LARGE`, `SIGNATURE_INVALID`, `NOT_ACCEPTED`, `MANIFEST_INVALID`, `DEVICE_REJECTED`, `TYPE_CHANGED`, `UNDECODABLE` and `VALUE_INVALID`, and [sync.md](sync.md), section 18.4, says what the device that sent the `FORWARD` does with each. A `CHANGE`, a `RESYNC` or a `FORWARD` of a key that is no device of the receiver's own set is ignored or rejected as [sync.md](sync.md), section 7.1, says, without its body being read. A `PROPOSAL` is checked by the steps of [shares.md](shares.md), section 13.3; besides `PROPOSALS_NOT_TAKEN`, they give `INVALID_MESSAGE`, `RECORD_ID_INVALID`, `VERSION_INVALID`, `SCHEMA_UNKNOWN`, `UNDECODABLE` and `VALUE_INVALID`, each for the failure that the code stands for in a record message. For `SCHEMA_UNKNOWN`, the error's `fingerprint` is that of the first schema that an entry of the proposal names and that the receiver does not hold, and the proposer offers nothing: [shares.md](shares.md), section 16.3, says what it does with each code. A `PROPOSAL_REPLY` is checked as [shares.md](shares.md), section 14.2, says.

A receiver checks the addressee of the replies and the offer after their signature: one with another key in `to` is ignored without a report (section 9.1). A receiver also ignores, without a report:

- a message from a key its user has not accepted, which it keeps or drops as [keys.md](keys.md), section 3.2, says;
- a message signed with a removed key, which it rejects as [keys.md](keys.md), section 3.3, says; a `DEVICE_ADD` or a `DEVICE_REMOVE` signed with one is ignored or reported as section 3.3 says;
- an answer to an offer the app did not make, or to an earlier offer of the type (section 5.3);
- a `PROPOSAL_REPLY` for a proposal that the app did not send ([shares.md](shares.md), section 14.2).

### 8.3 Reporting

- **Only to a sender that can be addressed.** In a live connection, an app sends an `ERROR` to the other app once it has a `MANIFEST` of the connection whose signature verified, valid or not, and so knows the formats the other app reads (section 3.2); before that, it reports nothing, with two exceptions. It holds the `DEVICE_REJECTED` for a `DEVICE_ADD` or a `DEVICE_REMOVE` that came before the `MANIFEST`, and sends it among its replies to the `MANIFEST`; every other error about a message before the `MANIFEST` is dropped. And in the connection that a join code opened, the device that showed the code answers a `DEVICE_JOIN` with `DEVICE_REJECTED` without a `MANIFEST`, in the format of the `DEVICE_JOIN` ([transports.md](transports.md), section 4.7). The other app's key is the one its `HELLO` proved ([transports.md](transports.md), section 4.5). Through the relay, it sends an `ERROR` only to a current key of a known sender, when the message signed with that key verified and it has that key's encryption key ([keys.md](keys.md), section 4.2). A message through the relay that fails before its signature is verified is dropped without a report, since its `sender` may be anyone's key. In a live connection the other app is known by the connection, so a message from it that fails those checks is reported to it. In both, the receiver reports nothing to a key its user has not accepted, apart from `MANIFEST_INVALID` and, in a live connection, `DEVICE_REJECTED`, which goes to the connection key (section 3.3).
- **Never about an error.** An app MUST NOT send an `ERROR` about an `ERROR`. An `ERROR` that is not valid is dropped.
- **Once.** An app sends at most one `ERROR` for each message it gets; a repeated message MAY be reported again.
- **Closing.** In a live connection, an app MAY close the connection after it has reported `TOO_LARGE` when the transport cannot skip the message ([envelope.md](envelope.md), section 8), after `SIGNATURE_INVALID`, and after `INVALID_MESSAGE`.

A sender that gets an `ERROR` about a record message for whose id and version it already has an outcome of the key that sent the `ERROR` ignores it (section 9.2). The same holds for an `ERROR` about a `CHANGE` ([sync.md](sync.md), section 9.3).

## 9. Addressees and repeats

### 9.1 The addressee

A signature names the sender of a message, not its receiver ([keys.md](keys.md), section 2.6). An app that got a reply could pass it on to a third app, which would then hold a genuine message of the first. The bodies of `OFFER`, `ACCEPT`, `DECLINE`, `ACK`, `ERROR`, `DEVICE_JOIN`, `CHANGE`, `RESYNC`, `FORWARD`, `WITHDRAW`, `PROPOSAL` and `PROPOSAL_REPLY` therefore carry `to`, the Ed25519 public key of the device they are for, and the signature covers it:

- An app MUST ignore such a message whose `to` is not its own signing key. It sends no report, since the message was not meant for it. A message for another device of its set is not meant for it either ([keys.md](keys.md), section 5.6).
- A reply carries in `to` the key that signed the message it is about: an answer the key that signed the offer, an `ACK` the key that signed the record messages, a `PROPOSAL_REPLY` the key that signed the proposal ([shares.md](shares.md), section 14.1). An `ERROR` carries the key of the device that sent the reported message: in a live connection the connection key ([transports.md](transports.md), section 4.5), which is also the key that signed every message but a `DEVICE_ADD` or a `DEVICE_REMOVE` of a chain, and through a relay the key that signed the reported message. The reply goes to that device: on the connection, or into the mailbox of that key.
- An `OFFER` carries in `to` a current key of the receiver ([keys.md](keys.md), section 3.3), and is judged by the manifest of that key (section 4.2). To a receiver with several current keys, a sender offers to the key from which it last got a valid message other than a `DEVICE_ADD`, a `DEVICE_REMOVE` or a `MANIFEST`, or, if it got no such message from any of them, to a current key of its choice of which it holds a manifest, and sends its record messages under the offer that this device accepted. A message of the chain and a `MANIFEST` do not count, so that the chain and the `MANIFEST` that every remaining device of a receiver sends after a removal ([sync.md](sync.md), section 17.2) do not move the key to which every other app offers. It need not reach any other device of the receiver: the device that gets the offer answers it, and passes the record messages it takes on to the other devices of its set ([sync.md](sync.md), section 17.2). When that key is removed from the receiver, the sender sends to another current key of the receiver of which it holds a manifest, chosen by the same rule, offers anew there, and sends again what has no outcome (section 11), where the outcomes of the removed key no longer count (section 7.4); the remaining devices of the receiver send it their chain and their `MANIFEST` when they apply the removal, at once or, where they know the sender only by what the removed device passed on, once their user has kept it ([sync.md](sync.md), section 17.2).
- A `DEVICE_JOIN` carries in `to` the key of the join code it answers ([keys.md](keys.md), section 5.2).
- A `WITHDRAW` carries in `to` the key of the receiver's device that it is sent to, chosen as for an `OFFER` above: the key under whose accepted offer it travels ([shares.md](shares.md), section 3.1). A device of the receiver's set that gets it in a `FORWARD` takes it if `to` is a current or a removed key of its own set, and so does a device that reads it in a file; a `WITHDRAW` that a device gets directly from the sender needs its own current key in `to` ([shares.md](shares.md), sections 7.1 and 8.2).
- A `PROPOSAL` carries in `to` a current key of the record's sender, chosen as for an `OFFER` above among the keys whose manifest takes proposals for the record's type ([shares.md](shares.md), section 13.1). A device of the sender's set that gets it in a `FORWARD` takes it if `to` is a current or a removed key of its own set ([shares.md](shares.md), section 17.1).
- A `CHANGE`, a `RESYNC` and a `FORWARD` carry in `to` the key of the device of the sender's own set that they are for ([sync.md](sync.md), sections 8.1, 11.1 and 18.1). The message inside a `FORWARD` stays as it is: it carries no addressee of its own unless its kind has one. A `MANIFEST` that a device passes on for another device of its set carries none, like every `MANIFEST` ([sync.md](sync.md), section 13.2).

`to` binds a message to its addressee, not to one connection. The same `ACK` is valid in a live connection and through the relay, and an app that uses both reaches the same result whichever way a reply arrives.

### 9.2 Repeats

A message carries no time, and a relay or a user can deliver a message again ([keys.md](keys.md), section 2.6). Every kind is safe to repeat:

| Kind             | A repeat, or a late copy                                                                                                                                                                                                                                  |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `MANIFEST`       | Applied in a live connection, where the manifest received last applies; through a relay or in a file ignored unless its revision is higher ([manifest.md](manifest.md), section 6)                                                                        |
| `OFFER`          | Answered again as before, if the receiver still knows the offer; it does not become the current offer again (section 4.3). If the receiver has forgotten it, its answer goes to an offer the sender has replaced, and the sender ignores it (section 5.3) |
| `ACCEPT`         | Ignored: the first answer for an offer and type stands, and only the latest offer of a type counts (section 5.3)                                                                                                                                          |
| `DECLINE`        | Ignored, for the same reasons                                                                                                                                                                                                                             |
| `DATA`           | `DUPLICATE` or `STALE` by the version rule ([records.md](records.md), section 5.2)                                                                                                                                                                        |
| `DELETE`         | The same                                                                                                                                                                                                                                                  |
| `WITHDRAW`       | The same ([shares.md](shares.md), section 4.1)                                                                                                                                                                                                            |
| `ACK`            | Changes nothing: the first outcome of an id and version from one acknowledging key stands, except `APPLIED` over `KEPT` and `MERGED`, `WITHDRAWN` over `KEPT`, and any outcome over `DUPLICATE` (section 7.4)                                             |
| `ERROR`          | The sender acts again only for a message that still has no outcome of the key that sent the `ERROR`; what it does then (section 8.2) is itself safe to repeat                                                                                             |
| `DEVICE_JOIN`    | Ignored outside the connection its join code opened; in it, a repeat from the same key is answered as the first was, and one from another key is ignored ([keys.md](keys.md), section 5.2)                                                                |
| `DEVICE_ADD`     | Ignored, not applied again and not reported ([keys.md](keys.md), section 5.5; section 3.3)                                                                                                                                                                |
| `DEVICE_REMOVE`  | The same                                                                                                                                                                                                                                                  |
| `CHANGE`         | Merged again, which takes nothing: `DUPLICATE`, or `STALE` if the state of the record has moved on ([sync.md](sync.md), sections 4.5 and 8.4)                                                                                                             |
| `RESYNC`         | Not acted on again: a request whose id the device has acted on is acknowledged again, with `DUPLICATE` once its answer is sent ([sync.md](sync.md), section 11.2)                                                                                         |
| `FORWARD`        | The message inside is processed again, which takes nothing: `DUPLICATE` ([sync.md](sync.md), section 18.4)                                                                                                                                                |
| `PROPOSAL`       | Taken as the proposal of its `proposal_id`: changes nothing, apart from keeping the copy with the higher SHA-256, and for a proposal that is answered the reply is sent again ([shares.md](shares.md), section 13.4)                                      |
| `PROPOSAL_REPLY` | Ignored: the first reply for a proposal stands, apart from an `ACCEPTED` after a `DECLINED` ([shares.md](shares.md), section 14.2)                                                                                                                        |

## 10. Versions that went back

A device SHOULD keep the highest version it has given each record, and the highest stamp it has given or seen, through whatever its data goes through ([records.md](records.md), section 3; [sync.md](sync.md), section 2.2). If it does not, for example after a restore from a backup older than the last messages it sent, it holds lower versions than it gave. A device that counted on from there would give versions a second time, for other states of the record. A receiver that already has a higher version reports `STALE`; a version that happens to equal the receiver's is taken for a duplicate, and the change is lost at that receiver.

The rule:

- A device that restores its data from a backup, or for another reason cannot rule out that it has given versions higher than those it holds, MUST give versions as state stamps from then on ([sync.md](sync.md), sections 2.4 and 5.1), also when it is a set of its own and counted until then. It MUST NOT count on.
- Its stamps come from its clock and from the highest stamp it holds, as for every device ([sync.md](sync.md), section 2.2). It draws no jump and marks nothing: a restored device stamps above what it sees.
- After `STALE`, it counts the receiver's version as a stamp it has seen. If that version is above the highest version it knows of the record, it acts as [records.md](records.md), section 7, says, and in the end sends the record's current state again under a new state stamp, unless a merge with a sibling gave it a version above the receiver's.
- A device with a sibling ([sync.md](sync.md), section 1) SHOULD, after a restore, merge with a sibling before its first change ([sync.md](sync.md), sections 2.4 and 4). It asks its siblings for every record of the set with a `RESYNC` message, which it MUST send to every sibling, again in each connection and through the relay after each holding time until that sibling has acknowledged it, and before which it sends that sibling no `CHANGE` of its own; each sibling then sends it every record whole, and it merges what it gets ([sync.md](sync.md), sections 11 and 12.1). Until it has merged, a restored device whose clock stands behind the highest stamp of its backup can give a stamp again that it gave before, for another value; the merge then decides between the two by their values ([sync.md](sync.md), section 4.1, rule 3).

Why this is enough:

- **The clock leads.** A stamp taken from the clock is the time in milliseconds times 65,536 plus a random part. Every version the device gave before the restore was a count, far below any stamp, or a stamp of an earlier time. Its new versions are above both unless its clock now stands behind the time of a stamp it gave before.
- **The clock is behind.** The device gave stamps while its clock, or a sibling's, ran ahead, lost them, and now takes stamps from a clock that shows less. Its versions are then below the receiver's, and `STALE` shows it: the device counts the receiver's version as seen, and its next stamps are above it. A stamp it takes then can equal one that it gave and lost only where both are taken from the same base and draw the same random part, one case in 32,768 per pair of such stamps.
- **Nothing is needed from the receiver.** The version rule and the `ACK` stay as [records.md](records.md), sections 5.2 and 7, describe them.

A restored device that is the only current device of its set sends the current state of a record again at once after such a `STALE`; one with siblings does so after it has merged with each of them, if its version is then still below the receiver's ([records.md](records.md), section 7). A restored device with a sibling gets from that sibling every state the sibling holds, whichever device made the changes. Changes that the device made after the backup and that reached no sibling before the restore are lost on the devices of the set; another app that got them keeps them until a higher version of the record reaches it.

## 11. Resends

A sender sends a record message again:

- **Without an acknowledgement.** A record message with neither an outcome nor an error that settles it has not been delivered. In a live connection, the sender sends the record again in a later connection, under an offer accepted there and in its current state. Through a relay, it sends the same message again under the same offer, once the holding time of 14 days ([transports.md](transports.md), section 5.5) has passed without an outcome, not before. A record that has changed since the offer is offered again instead (section 4.3).
- **For a schema.** After `SCHEMA_UNKNOWN` (section 8.2), once the type is accepted again.
- **When a type is accepted again.** When a type that a receiver had stopped taking ([manifest.md](manifest.md), section 6) fits again and is accepted, the sender SHOULD send the current state of each record of the type it had sent to that receiver before: a `DATA` with the current version of a record that exists, a `DELETE` with the version of the deletion of one deleted in between, which for a device that stamps is its current state stamp of the record ([sync.md](sync.md), section 5.1), and a `WITHDRAW` of one withdrawn from that receiver, under the version of its withdrawal ([shares.md](shares.md), section 5.3).
- **After a removal.** When a device is removed from its set, the remaining devices send again what has no outcome, as [keys.md](keys.md), section 5.6, says.
- **After a removal at the receiver.** When a key of a receiver is removed, the sender sends the current state of each record whose only outcomes are of removed keys of that receiver to the key it now uses for the receiver, once an offer of the record's type is accepted there, and not by the first rule (section 7.4).
- **Between the devices of one set.** A `CHANGE` is sent again by the rules of [sync.md](sync.md), section 10.3, which stand beside these: what a device of the set has not acknowledged stays due for it, and travels again in a later connection, through the relay after the holding time, and at once after `RECORD_UNKNOWN`, apart from a `CHANGE` about a record received from another app, which waits as [sync.md](sync.md), section 21.5, says. A `FORWARD` is sent again by the rules of [sync.md](sync.md), section 20.3.

Toward an app of another user, every resend sends what the device owes that app ([shares.md](shares.md), section 5.3): no record that is not shared with it, and for a record withdrawn from it the same `WITHDRAW`, under the same version.

A receiver cannot ask for a resend beyond the schema request of `SCHEMA_UNKNOWN`. A record that the receiver could not process for a passing reason, such as a full storage, is neither acknowledged nor reported, and is sent again by the first rule. A receiver that loses records it had acknowledged, for example by restoring an older backup, gets each again when the sender changes it, or when the type is accepted again after it stopped fitting. Between two apps, 0.1.0 has no message for asking for them. A device asks the other devices of its own set for every record of the set with `RESYNC` ([sync.md](sync.md), section 11); their answer also brings it the records that the set received from other apps ([sync.md](sync.md), section 20.4).

## 12. Timeouts

The protocol relies on few timers. Every step is safe to repeat (section 9.2), so a lost message costs time, not correctness. The transport detects a connection that has died ([transports.md](transports.md), section 4.6).

| What                                                           | Time                                                                                                                                                                                                                                |
| -------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The other app's valid `MANIFEST` after a live connection opens | An app SHOULD close a connection without one after 30 seconds; in a connection that a join code opened, the time runs from the answer to the `DEVICE_JOIN` (section 3.3)                                                            |
| An acknowledgement after processing a record message           | Within 5 seconds (section 7.2)                                                                                                                                                                                                      |
| An answer in a live connection                                 | Types the receiver decides on its own SHOULD be answered within 5 seconds. A type whose answer waits for the user has no limit; the sender MAY close a connection in which nothing but unanswered types has happened for 10 minutes |
| A resend through a relay                                       | After the holding time of 14 days ([transports.md](transports.md), section 5.5), not before                                                                                                                                         |
| An unanswered offer through a relay                            | The sender MAY offer again after the same time                                                                                                                                                                                      |
| The chain of a device                                          | Sent in three connections and three times through the relay, counted anew when it grows (section 3.3)                                                                                                                               |
| An acknowledgement after processing a `CHANGE`                 | Within 5 seconds ([sync.md](sync.md), section 9.1)                                                                                                                                                                                  |
| The `ACCEPT` for an offer of a device of the own set           | Within 5 seconds ([sync.md](sync.md), section 7.2)                                                                                                                                                                                  |
| A resend of a `CHANGE` through a relay                         | After the holding time of 14 days, not before ([sync.md](sync.md), section 10.3)                                                                                                                                                    |
| A `CHANGE` that a device sent, kept for its outcome            | 15 days after it was last sent ([sync.md](sync.md), section 10.1)                                                                                                                                                                   |
| A `RESYNC` that is not acknowledged                            | Sent again at the start of each live connection, and through a relay each time the holding time of 14 days has passed ([sync.md](sync.md), section 11.3)                                                                            |
| The acknowledgement of a `RESYNC`                              | After the last `CHANGE` of its answer, with no time limit ([sync.md](sync.md), section 11.2)                                                                                                                                        |
| An acknowledgement after processing a `FORWARD`                | Within 5 seconds ([sync.md](sync.md), section 18.4)                                                                                                                                                                                 |
| A repeat of a `FORWARD` through a relay                        | After the holding time of 14 days, not before ([sync.md](sync.md), section 20.3)                                                                                                                                                    |
| A `FORWARD` that a device sent, kept for its outcome           | 15 days after it was last sent ([sync.md](sync.md), section 20.2)                                                                                                                                                                   |
| The reply to a `PROPOSAL`                                      | No limit: it waits for the user of the record's sender; a `PROPOSAL` gets no acknowledgement ([shares.md](shares.md), sections 15.1 and 16.1)                                                                                       |
| A `PROPOSAL` sent again through a relay                        | After the holding time of 14 days, not before ([shares.md](shares.md), section 16.2)                                                                                                                                                |

## 13. What a declined or interrupted exchange leaves

- **A declined type.** Nothing of it travels. The receiver keeps no record of it, and MUST NOT use the declined schema to decode; it MAY keep the offer's id and answer to answer a repeat (section 4.3). The sender keeps that the type was declined, and why (section 5.3).
- **An unanswered type.** At the end of its offer (section 4.3), an unanswered type is neither accepted nor declined: no records of it have travelled.
- **An interrupted exchange.** When a connection ends in the middle of an exchange, each record message stands for itself. The receiver keeps what it has applied; there is no transaction that undoes it. A reference to a record that has not arrived stays unresolved until it arrives ([records.md](records.md), section 8). The sender knows from the acknowledgements which messages are delivered and sends the others again in a later exchange (section 11). The offers of the connection end with it.
- **After the exchange.** Through a relay, an accepted offer stays open until the sender makes another offer of the type. In a live connection, it ends with the connection. Neither leaves an acceptance that would let later records in without an offer.

## 14. The live connection as a state machine

Each app runs the same machine, as a sender of its records and as a receiver of the other's. The connection has three phases:

| Phase   | The app                                                                                                                                                                                                                                                                                                                                      | Leaves the phase                                                                                                                                                                            |
| ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Opening | in a connection that a join code opened, first sends or answers the `DEVICE_JOIN` (section 3.3); sends its chain (section 3.3), then its `MANIFEST` in its lowest format; takes `DEVICE_ADD`, `DEVICE_REMOVE`, `DEVICE_JOIN`, `MANIFEST` and `ERROR`; asks its user about an unknown key and keeps the other messages until the user decides | to Open with a valid `MANIFEST` of the other app and its key accepted; to Closed after 30 seconds without, when the user declines the key, or after a `DEVICE_REJECTED` for a `DEVICE_JOIN` |
| Open    | writes in the chosen format (section 3.2); offers, answers, sends and acknowledges records, reports errors; takes a new `MANIFEST` of the other app at any time                                                                                                                                                                              | to Closed when either app or the transport closes the connection                                                                                                                            |
| Closed  | ends every offer made in the connection (section 4.3); keeps the outcomes it has; marks record messages without one for a resend (section 11)                                                                                                                                                                                                |                                                                                                                                                                                             |

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

Between two devices of one set, the machine is the same with `CHANGE` messages in the place of record messages: a `CHANGE` goes through the states of a record message above, a type of an offer is always accepted, and a `RESYNC`, which the device that gets it acts on in the Open phase, is acknowledged after the last `CHANGE` of its answer and sent again in each connection until then ([sync.md](sync.md), sections 7.2, 10 and 11). A `FORWARD` goes through the states of a record message as well, and needs no offer ([sync.md](sync.md), sections 18 and 20). The manifest transition below does not apply between them, since no type is held back by a manifest there.

A new `MANIFEST` of the receiver with a higher revision is a transition of both machines. Each type of an accepted offer that no longer fits it ends, at the receiver on sending the manifest and at the sender on receiving it ([manifest.md](manifest.md), section 6). Record messages of such a type that were already on their way get `NOT_ACCEPTED`.

## 15. Through a relay and in a file

### 15.1 Through a relay

Through a relay ([transports.md](transports.md), section 5) the messages and the rules are the same, with these differences:

- **No connection.** There is no Opening phase and no end of a connection. Each app sends its current `MANIFEST` through the relay to every device of a known sender that takes messages through the relay and has not got it there yet: after it has accepted the other app's key, and whenever its manifest changes. This is when [manifest.md](manifest.md), section 5.1, has an app send a `MANIFEST` through the relay. A device to which only a `FORWARD` of a device of its own set has made a sender known sends that sender its chain and its `MANIFEST` when it first has a message of its own for it, or when it applies a removal in its own set, and not before ([sync.md](sync.md), section 17.2). A sender offers by the manifest it keeps of the receiver ([manifest.md](manifest.md), section 6), and an offer stays open until replaced (section 4.3).
- **Replies come back the same way.** An app that sends record messages, offers or proposals through a relay MUST take messages through it, that is, have an encryption key in its manifest ([manifest.md](manifest.md), section 3.9). Otherwise its answers and acknowledgements cannot reach it.
- **Order and repeats.** The relay may deliver late, out of order and more than once ([keys.md](keys.md), section 4.6); sections 4.3 and 9.2 make the result the same. A receiver that gets record messages of an offer it has not seen yet answers them with `SCHEMA_UNKNOWN` or `NOT_ACCEPTED`, and the sender sends them again after the offer.
- **Errors.** Only messages whose signature verified are reported (section 8.3).
- **Timers.** Resends follow the time for which the relay holds a message (sections 11 and 12).
- **Encryption.** Every message is sealed for the receiver's encryption key ([keys.md](keys.md), section 4).
- **Devices of one set.** A `CHANGE`, a `RESYNC` and a `FORWARD` travel through the relay between two devices of a set, each sealed for the other device and put into its mailbox. An accepted offer between them covers every later `CHANGE` that names its schema ([sync.md](sync.md), sections 7.2 and 13.2).

### 15.2 In a file

A file has no way back to its sender ([records.md](records.md), section 7). Its header's `axt.schemas`, signed by `axt.signature`, takes the place of the offer ([envelope.md](envelope.md), section 4.1; [keys.md](keys.md), section 2.5). The reader's user, who chooses to open the file, together with the reader's manifest ([manifest.md](manifest.md), section 7), takes the place of the answer. Nothing acknowledges it. Hence:

- `OFFER`, `ACCEPT`, `DECLINE`, `ACK` and `ERROR` are bound to one exchange and need a way back, which a file does not have. A file therefore holds none of them ([transports.md](transports.md), section 2.1).
- `CHANGE`, `RESYNC` and `FORWARD` are for one device of the sender's own set and belong to the bookkeeping between two devices. A file holds none of them ([sync.md](sync.md), sections 13.3 and 24.2). A device of a set that reads a file of another app passes what it took from it on to the other devices of its set ([sync.md](sync.md), section 24.2).
- A file holds no `PROPOSAL` and no `PROPOSAL_REPLY`: a proposal needs a way back for its reply and its errors, and a reply is for the one device that sent the proposal ([shares.md](shares.md), section 18.2).
- A file MAY hold a `WITHDRAW`. A writer puts one only into a file meant for the receiver from which it withdraws the record, with that receiver's key in `to`; a reader whose own set does not hold that key does not apply it ([shares.md](shares.md), section 8.2).
- A reader applies the record messages of a file by [records.md](records.md), section 5, and reaches the outcomes there, without the steps 4 and 5 of section 6.2. The schemas are those of the header, and a record is taken only if its type fits the reader's manifest ([manifest.md](manifest.md), section 7). A record message that fails another step of section 6.2 is not applied; a `DATA` whose fingerprint is not in `axt.schemas` makes the whole file invalid ([envelope.md](envelope.md), section 4.3).
- Reading a file accepts no offer. Records that the same sender later sends through a relay or a connection need an offer there.

### 15.3 What transports.md settles

- **The boundaries of each live message** are the frames of [transports.md](transports.md), section 4.4 ([envelope.md](envelope.md), section 3), and a connection opens and ends as [transports.md](transports.md), section 4.6, says (section 3.1 and section 14).
- **The other app's key** is authenticated before its `MANIFEST`: each app proves its signing key in a `HELLO` bound to the TLS connection ([transports.md](transports.md), section 4.5), and every message in the connection carries that key as its `sender`, apart from the additions and removals of devices.
- **A file** holds its writer's chain at its start, at most one `MANIFEST`, and record messages, and no `OFFER`, `ACCEPT`, `DECLINE`, `ACK`, `ERROR`, `CHANGE`, `RESYNC`, `FORWARD`, `PROPOSAL` or `PROPOSAL_REPLY` ([transports.md](transports.md), section 2.1).
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
{"name":"axt.Ack","type":"record","fields":[{"name":"to","type":{"name":"axt.AckTo","type":"fixed","size":32}},{"name":"records","type":{"type":"array","items":{"name":"axt.AckRecord","type":"record","fields":[{"name":"id","type":"string"},{"name":"version","type":"long"},{"name":"outcome","type":{"name":"axt.AckOutcome","type":"enum","symbols":["APPLIED","MERGED","KEPT","DUPLICATE","STALE","WITHDRAWN"]}},{"name":"receiver_version","type":"long"},{"name":"kept_fields","type":{"type":"array","items":"string"}}]}}}]}
```

```json
{"name":"axt.Error","type":"record","fields":[{"name":"to","type":{"name":"axt.ErrorTo","type":"fixed","size":32}},{"name":"code","type":{"name":"axt.ErrorCode","type":"enum","symbols":["INVALID_MESSAGE","FORMAT_UNSUPPORTED","TOO_LARGE","SIGNATURE_INVALID","MANIFEST_INVALID","OFFER_INVALID","RECORD_ID_INVALID","VERSION_INVALID","SCHEMA_UNKNOWN","NOT_ACCEPTED","TYPE_CHANGED","UNDECODABLE","DEVICE_REJECTED","VALUE_INVALID","RECORD_UNKNOWN","PROPOSALS_NOT_TAKEN"]}},{"name":"message_hash","type":{"name":"axt.ErrorMessageHash","type":"fixed","size":32}},{"name":"record","type":["null",{"name":"axt.ErrorRecord","type":"record","fields":[{"name":"id","type":"string"},{"name":"version","type":"long"}]}]},{"name":"fingerprint","type":["null",{"name":"axt.ErrorFingerprint","type":"fixed","size":8}]},{"name":"field","type":["null","string"]},{"name":"detail","type":"string"}]}
```

| Schema        | Envelope format | CRC-64-AVRO          | As bytes                  |
| ------------- | --------------- | -------------------- | ------------------------- |
| `axt.Offer`   | 1               | `0x415463caca7a687d` | `7d 68 7a ca ca 63 54 41` |
| `axt.Accept`  | 1               | `0x6b244fc3913d82ab` | `ab 82 3d 91 c3 4f 24 6b` |
| `axt.Decline` | 1               | `0x22d2bd11845492c0` | `c0 92 54 84 11 bd d2 22` |
| `axt.Ack`     | 1               | `0x38dd09198076e05c` | `5c e0 76 80 19 09 dd 38` |
| `axt.Error`   | 1               | `0x7ca5b3d13dbcf383` | `83 f3 bc 3d d1 b3 a5 7c` |

The fingerprints and the example of section 17 were produced with [conformance/tools/protocol_examples.py](../conformance/tools/protocol_examples.py). The script:

- checks the rules of [types.md](types.md), section 5, named above, with the checks of [conformance/tools/example_types.py](../conformance/tools/example_types.py), and that no name is defined twice among the schemas of the specification;
- computes the Parsing Canonical Forms and the CRC-64-AVRO fingerprints, compares them with those of the Python libraries fastavro 1.13.1 and `avro` 1.12.2, and checks that the fingerprints of the envelope, the manifest and the device messages are those published;
- uses every default of the schemas once in schema resolution, with both libraries, and for each enum a symbol the reader does not know, which fastavro reads as the default; the `avro` package 1.12.2 raises an error instead ([types.md](types.md), section 7.3);
- builds every message of section 17 field by field, compares it with fastavro's encoding, decodes it with fastavro and with `avro`, and checks that `avro` encodes each body to the same bytes;
- signs each message with the Ed25519 implementation of [conformance/tools/keys_examples.py](../conformance/tools/keys_examples.py), with PyNaCl 1.6.2 and with cryptography 50.0.2, which give the same signatures, and verifies them with all three by the strict rule of [keys.md](keys.md), section 2.3;
- runs a model of both apps over the exchange and over 71 further cases: repeats, messages addressed to another key, the first answer standing, outcomes decided later and acknowledgements of a resend in either order, an error never answered with an error, the additions and removals of devices before and after the `MANIFEST`, among them a rejected one whose error is held until the `MANIFEST`, a `DEVICE_JOIN` in a connection that no join code opened, and one case for each error code that a record message, an offer, a manifest or an envelope can cause, among them a recursive app type at data depth 32, which is taken, and at 34, which is rejected, and a type that holds a time value that is not valid, which is rejected with `VALUE_INVALID` and the field `end`.

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
| The offered schemas  | [Pet.1.avsc](../types/axt/example/v1/Pet.1.avsc) and [Appointment.1.avsc](../types/axt/example/v1/Appointment.1.avsc), each written as JSON without whitespace, with every attribute and in the order of the file: 4,629 bytes (SHA-256 `019020a619b235bff0a2b006325c47e8792397a4849d014544b5f47bc842a745`) and 6,389 bytes (SHA-256 `d90e32b250cc1cd4bb58b35921261deb18fb03d6e6411fc6248126d54eea84b7`) |
| The Appointment      | `title` "Vet: vaccination", `start` 2026-11-24 10:00 and `end` 10:30 in `Europe/Berlin` with the offset 3600, `location` "Tierarztpraxis, Hauptstraße 1", `notes` "Bring the vaccination certificate.", `reminders` `-P1D` and `-PT1H`                                                                                                                                                                   |

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

cat-a-log's MANIFEST: 319 bytes, SHA-256 `b1305f014fc6a6f5fd33334cb8ecdbe6f7cdaa32b978773f7abcc56cfa45f678`.

```text
0000  c3 01                    single-object marker
0002  16 30 6f 71 b9 ce 9e a8  fingerprint of axt.Envelope, format 1
000a  02                       format: int 1
000b  00                       kind: enum index 0, MANIFEST
000c  1b 84 a6 00 f3 50 3e 22  sender: fixed(32), cat-a-log's test key
      bb cc 99 e6 32 02 a7 19
      4b f6 bd 69 af f1 47 1c
      ce 64 10 d5 3c 26 ec 4a
002c  00                       record: union index 0, null
002d  a0 03                    body: bytes length 208
002f  c3 01                    body: single-object marker
0031  3e 1f a5 88 4c eb 9e a5  body: fingerprint of axt.Manifest, format 1
0039  02 12 63 61 ... 00 00    body: the manifest of spec/manifest.md, section 10.3, from 0039
00ff  08 8e ed db 40 91 7d 25  signature: fixed(64)
      ec 10 32 03 b8 4f 5f 68
      50 0f c0 3c 7a 10 08 8f
      e3 29 d4 e0 4a 68 a3 c3
      33 c0 69 f1 33 e9 2a 5a
      98 d2 96 26 bd 0e 05 23
      22 6e 20 01 e3 d5 9a f3
      bc 9d 97 b5 5b 7e 54 06
013f  end
```

Old Brain Fix's MANIFEST: 549 bytes, SHA-256 `3af8b09e06d556e993c33d1bf00f744645b8eb7e049c2f91c90f8fec96d23f6a`.

```text
0000  c3 01                    single-object marker
0002  16 30 6f 71 b9 ce 9e a8  fingerprint of axt.Envelope, format 1
000a  02                       format: int 1
000b  00                       kind: enum index 0, MANIFEST
000c  da 9e 54 c9 aa 2d b4 32  sender: fixed(32), Old Brain Fix's test key
      44 df 99 88 9d 91 38 c1
      ca 71 75 d4 ca 09 08 16
      8f 63 53 0e 4a 7d ed b7
002c  00                       record: union index 0, null
002d  ec 06                    body: bytes length 438
002f  c3 01                    body: single-object marker
0031  3e 1f a5 88 4c eb 9e a5  body: fingerprint of axt.Manifest, format 1
0039  02 1a 4f 6c ... 00 00    body: the manifest of spec/manifest.md, section 10.3, from 0039
01e5  2a 69 59 e6 3d 0e 2c dd  signature: fixed(64)
      0b 49 f5 bf e8 36 a6 13
      88 3e 04 5c 8e 67 53 6e
      4e 22 ca 6a c9 1b f6 8d
      30 a9 1f 81 e9 29 7a 3d
      f3 22 e7 3c 2a 3b 22 cc
      b9 ae cb 79 5b 2a 3c 86
      75 82 59 b9 eb 93 ac 06
0225  end
```

### 17.3 The offer

The two schema texts are shown shortened; the script prints their SHA-256.

cat-a-log's OFFER: 11,217 bytes, SHA-256 `27b45d6eda52375cd8cff954ae0a27c9f90cf1ed2e21c9833cbaaf3340b1dc26`.

```text
0000  c3 01                    single-object marker
0002  16 30 6f 71 b9 ce 9e a8  fingerprint of axt.Envelope, format 1
000a  02                       format: int 1
000b  02                       kind: enum index 1, OFFER
000c  1b 84 a6 00 f3 50 3e 22  sender: fixed(32), cat-a-log's test key
      bb cc 99 e6 32 02 a7 19
      4b f6 bd 69 af f1 47 1c
      ce 64 10 d5 3c 26 ec 4a
002c  00                       record: union index 0, null
002d  c2 ad 01                 body: bytes length 11105
0030  c3 01                    body: single-object marker
0032  7d 68 7a ca ca 63 54 41  body: fingerprint of axt.Offer, format 1
003a  da 9e 54 c9 aa 2d b4 32  body: to: fixed(32), Old Brain Fix's test key
      44 df 99 88 9d 91 38 c1
      ca 71 75 d4 ca 09 08 16
      8f 63 53 0e 4a 7d ed b7
005a  48                       body: offer_id: string length 36
005b  36 66 31 63 32 62 39 65  body: "6f1c2b9e-3d4a-4e5f-8a7b-1c2d3e4f5a6b"
      2d 33 64 34 61 2d 34 65
      35 66 2d 38 61 37 62 2d
      31 63 32 64 33 65 34 66
      35 61 36 62
007f  04                       body: types: array block of 2 items
0080  aa 48                    body: types[0].schema: string length 4629
0082  7b 22 74 79 ... 5d 7d    body: Pet.1.avsc without whitespace (4629 bytes of UTF-8 JSON)
1297  02                       body: types[0].count: long 1
1298  ea 63                    body: types[1].schema: string length 6389
129a  7b 22 74 79 ... 5d 7d    body: Appointment.1.avsc without whitespace (6389 bytes of UTF-8 JSON)
2b8f  02                       body: types[1].count: long 1
2b90  00                       body: types: end of the array
2b91  fe f0 94 80 c3 7e ce 7d  signature: fixed(64)
      ba 76 61 77 85 e6 37 3e
      10 eb e0 d7 bd 08 7a 33
      85 e4 31 93 88 2a e6 82
      b0 d3 df 4f 97 52 3e d8
      04 11 07 dd bb 91 93 68
      ad 96 db 1c ef 18 ec c6
      00 54 d0 2c 25 f1 19 0a
2bd1  end
```

### 17.4 The answers

Old Brain Fix's ACCEPT: 219 bytes, SHA-256 `655b9a4d2df481925f99d36a1e6442f11285338f5d730365e59abba249962694`.

```text
0000  c3 01                    single-object marker
0002  16 30 6f 71 b9 ce 9e a8  fingerprint of axt.Envelope, format 1
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

Old Brain Fix's DECLINE: 212 bytes, SHA-256 `adbe5b06e8b1e75dc49814feae16579a40c591b7891174f446230b3eb3d54630`.

```text
0000  c3 01                    single-object marker
0002  16 30 6f 71 b9 ce 9e a8  fingerprint of axt.Envelope, format 1
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

The body of the `DATA` names the Appointment's schema by its fingerprint, `0x1af207f82b6430cd` ([types.md](types.md), section 7.3). Old Brain Fix finds it among the schemas of cat-a-log's current offers, and only there.

cat-a-log's DATA: 321 bytes, SHA-256 `c0c852f36d6431ac1043f3b23d610b101b5adeaa88193c223afb6f9af27d0945`.

```text
0000  c3 01                    single-object marker
0002  16 30 6f 71 b9 ce 9e a8  fingerprint of axt.Envelope, format 1
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
0053  d8 02                    body: bytes length 172
0055  c3 01                    body: single-object marker
0057  cd 30 64 2b f8 07 f2 1a  body: fingerprint of axt.example.v1.Appointment, version 1
005f  20                       body: title: string length 16
0060  56 65 74 3a 20 76 61 63  body: "Vet: vaccination"
      63 69 6e 61 74 69 6f 6e
0070  d4 1f 16 30 14 00 00 00  body: start: wall clock 2026-11-24 10:00:00.000, seven ints
0078  02                       body: start.zone: union index 1, string
0079  1a                       body: start.zone: string length 13
007a  45 75 72 6f 70 65 2f 42  body: "Europe/Berlin"
      65 72 6c 69 6e
0087  02                       body: start.offset_seconds: union index 1, int
0088  a0 38                    body: start.offset_seconds: int 3600
008a  02                       body: start.instant_ms: union index 1, long
008b  80 ba c4 cc c1 68        body: start.instant_ms: long 1795510800000
0091  02                       body: end: union index 1, axt.DateTime
0092  d4 1f 16 30 14 3c 00 00  body: end: wall clock 2026-11-24 10:30:00.000, seven ints
009a  02                       body: end.zone: union index 1, string
009b  1a                       body: end.zone: string length 13
009c  45 75 72 6f 70 65 2f 42  body: "Europe/Berlin"
      65 72 6c 69 6e
00a9  02                       body: end.offset_seconds: union index 1, int
00aa  a0 38                    body: end.offset_seconds: int 3600
00ac  02                       body: end.instant_ms: union index 1, long
00ad  80 97 a0 ce c1 68        body: end.instant_ms: long 1795512600000
00b3  00                       body: all_day: boolean false
00b4  3c                       body: location: string length 30
00b5  54 69 65 72 61 72 7a 74  body: "Tierarztpraxis, Hauptstraße 1"
      70 72 61 78 69 73 2c 20
      48 61 75 70 74 73 74 72
      61 c3 9f 65 20 31
00d3  44                       body: notes: string length 34
00d4  42 72 69 6e 67 20 74 68  body: "Bring the vaccination certificate."
      65 20 76 61 63 63 69 6e
      61 74 69 6f 6e 20 63 65
      72 74 69 66 69 63 61 74
      65 2e
00f6  04                       body: reminders: array block of 2 items
00f7  00                       body: reminders[0].months: int 0
00f8  01                       body: reminders[0].days: int -1
00f9  00                       body: reminders[0].millis: long 0
00fa  00                       body: reminders[1].months: int 0
00fb  00                       body: reminders[1].days: int 0
00fc  ff b9 b7 03              body: reminders[1].millis: long -3600000
0100  00                       body: reminders: end of the array
0101  2a 45 f1 d4 10 35 71 58  signature: fixed(64)
      bb c5 c0 6a 18 ee 0d cd
      af 09 67 be 7d 09 62 c1
      68 60 db 2a 91 ce b7 af
      58 0f 71 2a ec b8 d3 e9
      16 f0 e6 aa f2 fb 53 22
      45 41 a3 85 ee 9c c9 ef
      ef 55 5c 9a 9e ce 41 0d
0141  end
```

Old Brain Fix's ACK: 196 bytes, SHA-256 `2a6d038f3ddebf887b598a53edce083e948760476295d58112915222062249c4`.

```text
0000  c3 01                    single-object marker
0002  16 30 6f 71 b9 ce 9e a8  fingerprint of axt.Envelope, format 1
000a  02                       format: int 1
000b  0c                       kind: enum index 6, ACK
000c  da 9e 54 c9 aa 2d b4 32  sender: fixed(32), Old Brain Fix's test key
      44 df 99 88 9d 91 38 c1
      ca 71 75 d4 ca 09 08 16
      8f 63 53 0e 4a 7d ed b7
002c  00                       record: union index 0, null
002d  aa 01                    body: bytes length 85
002f  c3 01                    body: single-object marker
0031  5c e0 76 80 19 09 dd 38  body: fingerprint of axt.Ack, format 1
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
0084  2d 37 91 f7 c1 6e 2e c1  signature: fixed(64)
      19 67 6a d5 c9 ab 38 91
      83 c1 e9 a0 19 2b 41 47
      14 4f c9 c1 ca 5f b2 7b
      a2 c5 7f 8a ac 5a 49 09
      6b 15 1b e4 9e 5c c2 24
      1a 22 83 64 f6 57 59 83
      1b 5b 5b 8c 72 93 a8 0b
00c4  end
```

### 17.6 A record without an accepted offer

The `DATA` of step 8 carries the Pet of [conformance/tools/example_types.py](../conformance/tools/example_types.py) as the record `5e8a1f3c-7b2d-4c6e-a9f0-3d5b7c9e1a2f`, version 1, written with the offered Pet schema. Old Brain Fix knows the fingerprint from the offer, but the Pet's answer was `DECLINE`, so step 5 of section 6.2 fails. The `ERROR` names the message by its hash, `a79bc1f0ac90ceff861c72612016bdbf85386d8db6ad71c42151c4eb197a879d`.

Old Brain Fix's ERROR: 246 bytes, SHA-256 `13dc0504e6ba7eb29a352a477f697e83c28f572424a8ffd5811ac59d597a5255`.

```text
0000  c3 01                    single-object marker
0002  16 30 6f 71 b9 ce 9e a8  fingerprint of axt.Envelope, format 1
000a  02                       format: int 1
000b  0e                       kind: enum index 7, ERROR
000c  da 9e 54 c9 aa 2d b4 32  sender: fixed(32), Old Brain Fix's test key
      44 df 99 88 9d 91 38 c1
      ca 71 75 d4 ca 09 08 16
      8f 63 53 0e 4a 7d ed b7
002c  00                       record: union index 0, null
002d  8e 02                    body: bytes length 135
002f  c3 01                    body: single-object marker
0031  83 f3 bc 3d d1 b3 a5 7c  body: fingerprint of axt.Error, format 1
0039  1b 84 a6 00 f3 50 3e 22  body: to: fixed(32), cat-a-log's test key
      bb cc 99 e6 32 02 a7 19
      4b f6 bd 69 af f1 47 1c
      ce 64 10 d5 3c 26 ec 4a
0059  12                       body: code: enum index 9, NOT_ACCEPTED
005a  a7 9b c1 f0 ac 90 ce ff  body: message_hash: fixed(32), SHA-256 of the reported message
      86 1c 72 61 20 16 bd bf
      85 38 6d 8d b6 ad 71 c4
      21 51 c4 eb 19 7a 87 9d
007a  02                       body: record: union index 1, ErrorRecord
007b  48                       body: record.id: string length 36
007c  35 65 38 61 31 66 33 63  body: "5e8a1f3c-7b2d-4c6e-a9f0-3d5b7c9e1a2f"
      2d 37 62 32 64 2d 34 63
      36 65 2d 61 39 66 30 2d
      33 64 35 62 37 63 39 65
      31 61 32 66
00a0  02                       body: record.version: long 1
00a1  00                       body: fingerprint: union index 0, null
00a2  00                       body: field: union index 0, null
00a3  24                       body: detail: string length 18
00a4  61 78 74 2e 65 78 61 6d  body: "axt.example.v1.Pet"
      70 6c 65 2e 76 31 2e 50
      65 74
00b6  60 bc 9c 94 77 c3 18 d3  signature: fixed(64)
      5b be f1 71 af e2 d6 a6
      52 1f 66 13 52 2f 10 fe
      92 c9 21 79 6a 6d ec ad
      08 ca 9e 7a 16 6e e5 25
      61 1c 2a 86 55 2d 82 15
      bd 9d 0a d1 11 f3 39 26
      2b 7f 33 a8 23 b5 47 07
00f6  end
```

cat-a-log has no outcome for the Pet, so it takes the error. It sends Mimi's record to Old Brain Fix only after a later offer of the Pet is accepted.

## 18. What other documents define

- [transports.md](transports.md): the live connection, its `HELLO`, its opening and its end (section 4 there); the kinds a file holds (section 2.1 there); the relay and its holding time, which sets the resends through it (section 5 there; section 15.3).
- [sync.md](sync.md): the stamps, the state stamp that a device of a set gives a record as its version, and what a device does after `STALE` with a higher version (sections 7.4 and 10; sections 2 and 5 there); and the exchange between the devices of one set, with the messages `CHANGE` and `RESYNC`, their acknowledgement, their errors and their resends, and the manifests that the devices pass on to each other (sections 2, 7, 8.2, 9, 11 and 14; sections 7 to 14 there); and what the devices of one set do with the messages of other apps: which device answers, the message `FORWARD`, and the changes of the set's user to received records (sections 2, 6.2, 7, 8.2, 9, 11 and 15; sections 17 to 24 there).
- [conformance.md](conformance.md): test vectors for every message of this document and for the cases of section 16.

## References

- [Apache Avro 1.12 specification](https://avro.apache.org/docs/1.12.0/specification/)
- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174): key words for requirement levels
- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032): Ed25519
- [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259): JSON
- [RFC 9562](https://www.rfc-editor.org/rfc/rfc9562): UUIDs
- [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final): SHA-256
