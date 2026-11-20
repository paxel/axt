# Context

The vocabulary of this repository. The specification in [spec/](spec/README.md) defines these terms; this file only gathers them.

**Installation**: one copy of an app on one device, with its own data and its own keys.

**Sender**: the app that created a record and sends its versions: one installation, or the installations of one owner on several devices, each with a key of its own, as one **device set**. A receiver knows a sender by the first key it accepted from it and by the keys added to it and removed from it since.

**Receiver**: an app that takes records from a sender, through a live connection, a relay or a file.

**Record**: one datum of a type, such as one Appointment, together with its id and its version.

**Record message**: a `DATA` message, which carries a whole record, or a `DELETE` message.

**Version**: a rising number that names one state of a record at its sender: a count from 1, or the state stamp once the sender stamps.

**Sibling**: another device of the same device set.

**Stamp**: a number a device gives to a change, taken from its clock so that it never goes back. Per field of a record, the change with the higher stamp wins; the device's key breaks a tie.

**State stamp**: the stamp a device takes whenever the state of a record changes on it, by a change of its user or by a merge with a sibling's state. It is the record's version toward other apps.

**Part**: one field state of a record, or its removal, as one device of a set holds it. A part is **delivered** to a sibling once that sibling has acknowledged it or sent it, and **due** for the sibling until then.

**Change message**: a `CHANGE`, in which a device sends a sibling the parts of one record that are due for it: every field state on the first transfer, a **whole** message, and only the changed ones after that.

**Resync**: a `RESYNC` message, with which a device that fell behind, such as after restoring a backup, asks a sibling to send every record whole again.

**Tombstone**: what a receiver keeps of a record its sender deleted: its id and the version of the deletion.

**Local change**: a change the receiver's user makes to a received record in the receiver. It stays there and is not sent back.

**Type**: an Apache Avro schema with a full name. An **example type** is one of the types this repository brings under `axt.example.v1`, so that apps can exchange without agreeing first.

**Envelope**: the signed message every exchange consists of, an `axt.Envelope`. Its body holds the record or the protocol message.

**Fingerprint**: the CRC-64-AVRO of a schema's canonical form, by which a live message names its schema.

**Manifest**: the message in which an app names the types it takes and, in one sentence per type, what it does with them.

**Offer**: the message in which a sender names the types and schemas it wants to send; the receiver answers with accept or decline.

**Outcome**: what a receiver did with a record message: `APPLIED`, `MERGED`, `KEPT`, `DUPLICATE` or `STALE`. It reports outcomes in an `ACK`.

**Transport**: one of the three ways messages travel: a file, the local network, a relay.

**Relay**: a sealed mailbox service that stores and forwards end-to-end encrypted messages and sees neither their content nor their type. The **reference relay** is the one in [relay/](relay/README.md).

**Mailbox**: the place at a relay that holds sealed messages for one installation, its owner.

**Library**: an implementation of AXT that apps use, one per language under [libs/](libs/README.md).

**Vector**: one test: an operation, its input and the result the specification expects. A **category** groups the vectors of one part of the specification.

**Adapter**: a small program, written for one library, that performs the operations of the vectors with that library. The **reference adapter** shows that the vectors are consistent; it is not a library.

**Runner**: the program that sends every vector to an adapter and compares the answers with the expected results.

**Example script**: a script in `conformance/tools/` that rebuilds the examples of one document of the specification and checks them against independent implementations.
