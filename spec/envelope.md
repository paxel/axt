# Envelope and encoding

Status: written, 0.1.0. Until 0.1.0 is released, the later documents of 0.1.0 may still change the envelope schema; the fingerprint and the examples below are then produced again.

This document defines how AXT messages travel as bytes: the envelope every message is wrapped in, its encoding in a live connection and in a file, the fingerprints that name schemas, schema resolution, the representation of strings, times and ids, the size limits, and the media type and file extension.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 ([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119), [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)) when, and only when, they appear in all capitals, as shown here.

## 1. Avro

AXT encodes everything with [Apache Avro 1.12](https://avro.apache.org/docs/1.12.0/specification/) (in this document: the Avro specification). Where this document says "binary encoding", "single-object encoding", "object container file", "Parsing Canonical Form", "CRC-64-AVRO" or "schema resolution", the term has the meaning the Avro specification gives it. An implementation MUST follow the Avro specification wherever this document does not say otherwise.

## 2. The envelope

Every AXT message is one datum of the record `axt.Envelope`. Its schema is [types/axt/Envelope.avsc](../types/axt/Envelope.avsc); the schemas of this specification live in [types/axt/](../types/axt/) under the Avro namespace `axt`. The namespace `axt` and every namespace that begins with `axt.` are reserved for the AXT repository ([types.md](types.md), section 2).

| Field       | Avro type                                  | Content                                                                                   | Defined in                 |
| ----------- | ------------------------------------------ | ----------------------------------------------------------------------------------------- | -------------------------- |
| `format`    | `int`                                      | The envelope format; `1` for the envelope defined here                                    | this document, section 2.1 |
| `kind`      | enum `axt.Kind`                            | What the message is, and so which schema its body has                                     | this document, section 2.2 |
| `sender`    | `fixed` of 32 bytes, `axt.PublicKey`       | The Ed25519 public key of the sending device                                              | [keys.md](keys.md)         |
| `record`    | union of `null` and record `axt.RecordRef` | The id (`uuid` string) and version (`long`) of the record the message is about, or `null` | [records.md](records.md)   |
| `body`      | `bytes`                                    | Empty, or one datum in single-object encoding                                             | this document, section 2.3 |
| `signature` | `fixed` of 64 bytes, `axt.Signature`       | The sender's Ed25519 signature                                                            | [keys.md](keys.md)         |

### 2.1 Format

`format` names the envelope format, that is, one published version of the `axt.Envelope` schema. This document defines format `1`. Each format has its own schema and so its own fingerprint (section 5); a library MUST know the fingerprint of every format it supports.

Every later envelope schema MUST keep `format` as its first field, of type `int`. A receiver that does not know an envelope's fingerprint can therefore still read the format number: in a live message it is the zig-zag varint that starts at byte offset 10. A receiver MAY use it only to report that the message has a format it does not support; it MUST NOT decode the rest.

A sender MUST write each message in a format the receiver supports. In a live connection, the two apps learn each other's formats from their manifests, and [protocol.md](protocol.md), section 3.2, defines the format each writes in. A file has no such step, so a writer SHOULD write a file in the lowest format that can carry its content.

### 2.2 Kind

| Kind             | Purpose                                                               | Defined in                                                      |
| ---------------- | --------------------------------------------------------------------- | --------------------------------------------------------------- |
| `MANIFEST`       | The types an app takes and what it does with them                     | [manifest.md](manifest.md)                                      |
| `OFFER`          | Types and their writer schemas the sender wants to send               | [protocol.md](protocol.md), section 4                           |
| `ACCEPT`         | The receiver takes offered types                                      | [protocol.md](protocol.md), section 5                           |
| `DECLINE`        | The receiver does not take offered types                              | [protocol.md](protocol.md), section 5                           |
| `DATA`           | One record, new or updated                                            | [records.md](records.md), [protocol.md](protocol.md), section 6 |
| `DELETE`         | The deletion of one record                                            | [records.md](records.md), [protocol.md](protocol.md), section 6 |
| `ACK`            | The receiver reports what it did with record messages                 | [protocol.md](protocol.md), section 7                           |
| `ERROR`          | The receiver reports a message it could not process                   | [protocol.md](protocol.md), section 8                           |
| `DEVICE_JOIN`    | A new device asks a device of its owner to add its key                | [keys.md](keys.md), section 5.2                                 |
| `DEVICE_ADD`     | A device adds the key of a new device to its sender                   | [keys.md](keys.md), section 5.2                                 |
| `DEVICE_REMOVE`  | A device removes a key from its sender                                | [keys.md](keys.md), section 5.3                                 |
| `CHANGE`         | Changed fields of one record, between the devices of one sender       | [sync.md](sync.md), section 8                                   |
| `RESYNC`         | A device asks another device of its sender for every record again     | [sync.md](sync.md), section 11                                  |
| `FORWARD`        | A message of another app, passed on between the devices of one sender | [sync.md](sync.md), section 18                                  |
| `WITHDRAW`       | The sender no longer shares one record with the receiver              | [shares.md](shares.md), section 3                               |
| `PROPOSAL`       | A receiver proposes a change of one record to its sender              | [shares.md](shares.md), section 13                              |
| `PROPOSAL_REPLY` | The sender accepts or declines a proposal                             | [shares.md](shares.md), section 14                              |

The document that defines a kind also defines whether its messages carry `record` and which schema their body has. In particular:

- A `DATA` message MUST carry `record`, and its body MUST be the record in single-object encoding with a writer schema the receiver has from an offer (section 3) or the file header (section 4).
- A `DELETE` message MUST carry `record` and MUST have an empty body.
- A `WITHDRAW` message MUST carry `record`, and its body MUST be one `axt.Withdraw` ([shares.md](shares.md), section 3.1).
- A `PROPOSAL` and a `PROPOSAL_REPLY` MUST carry `record`, which names the record they are about, and their bodies MUST be one `axt.Proposal` and one `axt.ProposalReply` ([shares.md](shares.md), sections 13.1 and 14.1). They are no record messages ([shares.md](shares.md), section 12.1).

A `CHANGE`, a `RESYNC` and a `FORWARD` travel only between the devices of one sender; an app rejects one of another app as [sync.md](sync.md), section 7.1, says.

New kinds come only with a new envelope format.

### 2.3 Body

The body is either empty or exactly one datum in single-object encoding: the two bytes `C3 01`, the 8-byte little-endian CRC-64-AVRO fingerprint of the datum's writer schema (section 5), then the datum in binary encoding. A receiver MUST reject a body that is neither empty nor a complete single-object encoding with no bytes left over.

For `DATA`, the writer schema is the record type's schema as offered. The body of a `CHANGE` has a schema of the specification and carries the values of single fields, each as bytes with the fingerprint of the offered schema it was written with ([sync.md](sync.md), section 8.1). The body of a `FORWARD` has a schema of the specification as well and carries one whole message of another app as bytes, signature included, with the text of the writer schema of its body where that message is a `DATA` ([sync.md](sync.md), section 18.1). The body of a `DELETE` is empty. The body of a `PROPOSAL` has a schema of the specification and carries the proposed values of single fields, each as bytes with the fingerprint of the schema it was written with ([shares.md](shares.md), section 13.1). For every other kind with a body, the bodies of a `WITHDRAW` and a `PROPOSAL_REPLY` among them ([shares.md](shares.md), section 10), the schema is the one the defining document publishes under [types/axt/](../types/axt/); those fingerprints are fixed by the specification and are not offered.

### 2.4 Sender and signature

`sender` and `signature` are what [keys.md](keys.md) needs to sign and verify every message. The envelope is laid out for that:

- `signature` is the last field and has a fixed length, so the last 64 bytes of an encoded envelope are the signature, and all bytes before them are the rest of the message.
- The body is carried as bytes, so the record inside it is never encoded again on the way.

What the signature covers, and how a receiver verifies it, is defined in [keys.md](keys.md), sections 2.2 and 2.3: the signed bytes are a fixed prefix and the envelope's bytes before `signature`, as the message was received, not as an encoding the receiver produces again from decoded values, since a decoded value can encode differently, for example a UUID received with upper-case digits (section 7). These bytes are the same in a live message and in a file (section 4).

## 3. Live connection

In a live connection, the schema of each record type is sent in the offer that starts each exchange ([protocol.md](protocol.md), section 4), not with each record. Every message, the offer included, is one envelope in single-object encoding:

1. the marker `C3 01`;
2. the 8-byte little-endian CRC-64-AVRO fingerprint of the envelope schema, which for format 1 is `16 30 6f 71 b9 ce 9e a8` (section 10.1);
3. the envelope in binary encoding.

The envelope carries no length and no terminator; the transport supplies the boundaries of each message, on the local network a frame ([transports.md](transports.md), section 4.4). A receiver MUST reject a message with bytes left over after the envelope.

An offer carries each writer schema as its full JSON text, including `doc` attributes, so that a receiver can show fields it does not know by name and description ([types.md](types.md)). The Parsing Canonical Form is used only to compute the fingerprint. The receiver keeps the offered schemas by fingerprint for as long as the offer stays open ([protocol.md](protocol.md), section 4.3).

Through a relay, the end-to-end encryption defined in [keys.md](keys.md), section 4, wraps the complete encoded message. No envelope field, not even `kind`, is visible to the relay ([transports.md](transports.md), section 5).

### 3.1 Unknown fingerprints

- **Envelope.** A message whose envelope fingerprint is not one of the formats the receiver supports MUST be rejected without decoding it; section 2.1 says how the format number can still be read for the report.
- **Data.** A receiver that gets a `DATA` message whose body fingerprint is not among the schemas offered to it MUST NOT decode the body, and MUST NOT try other schemas in its place. It MUST reject the message with the error `SCHEMA_UNKNOWN`, which also asks the sender for the schema ([protocol.md](protocol.md), sections 6.2 and 8.2).
- **Other kinds.** A message of another kind whose body fingerprint is not the one the defining document publishes for that kind and format MUST be rejected.

## 4. File

An AXT file is an Avro object container file: the magic `Obj` followed by the byte `01`, the file metadata, a 16-byte sync marker, then data blocks. Each datum in it is one `axt.Envelope`. Its bytes are exactly those of a live message without the 10-byte single-object header. With the signed bytes chosen as section 2.4 requires, a message keeps its signature when it moves between a file and a connection.

### 4.1 Metadata

| Key             | Value                                                                                                         | Required                            |
| --------------- | ------------------------------------------------------------------------------------------------------------- | ----------------------------------- |
| `avro.schema`   | The envelope schema as JSON; its Parsing Canonical Form MUST be that of a published envelope format           | yes                                 |
| `avro.codec`    | `null` or `deflate` (section 4.2); if the key is absent, the codec is `null`, as in the Avro specification    | no                                  |
| `axt.schemas`   | A JSON array of the full writer schemas, `doc` attributes included, of the records in the file, as UTF-8 JSON | when the file holds `DATA` messages |
| `axt.sender`    | The Ed25519 public key of the file's sender, as lower-case hexadecimal ([keys.md](keys.md), section 2.5)      | yes                                 |
| `axt.signature` | The sender's signature over the header, as lower-case hexadecimal ([keys.md](keys.md), section 2.5)           | yes                                 |

`axt.schemas` takes the place of the offer: a file is read without a connection, so the record schemas travel in its header. The fingerprints of the schemas in it MUST be distinct, and every `DATA` body in the file MUST name one of them. `avro.schema` holds the envelope schema rather than a record schema, because every record in a file needs the envelope's id, version, key and signature.

A reader identifies the envelope format by the fingerprint of `avro.schema` and MUST reject a file whose envelope fingerprint it does not support. It MUST NOT depend on the exact text of `avro.schema`, since Avro libraries write it in different ways. It MUST compare the Parsing Canonical Form of `avro.schema` byte for byte with that of the format, and MUST decode the file's messages with its own copy of the format's schema, not with the schema from the file ([keys.md](keys.md), section 2.5). Metadata keys that start with `axt.` are reserved for this specification. A reader MUST ignore metadata keys it does not know.

The metadata is not part of any message, so no message signature covers it. `axt.signature` signs the value of `axt.schemas` with the key in `axt.sender`, and every message of a file has that sender, apart from the additions and removals of devices at its start ([keys.md](keys.md), sections 2.5 and 5.4). The fingerprint alone would not protect the schemas (section 5).

A file holds `DEVICE_ADD` and `DEVICE_REMOVE` messages at its start, at most one `MANIFEST` and record messages, and no other kind; [transports.md](transports.md), section 2, defines their order and what a reader rejects.

### 4.2 Codecs

A reader MUST support the codecs `null` and `deflate`. A writer MUST use one of these two. A reader MUST reject a file with any other codec.

These are the two codecs the Avro specification requires of every implementation, so every Avro library can read such a file. `deflate` is raw DEFLATE ([RFC 1951](https://www.rfc-editor.org/rfc/rfc1951)), as in the Avro specification, which zlib, and with it the standard library of nearly every language, provides. The Avro codecs `snappy`, `bzip2`, `xz` and `zstandard` are optional in Avro and need additional native libraries. A file that used them could be unreadable for a conforming Avro reader, and an app on a phone would have to carry extra libraries to read it.

### 4.3 Unknown fingerprints

A `DATA` message in a file whose body fingerprint is not in `axt.schemas` makes the file invalid; there is no sender to ask. A reader MUST reject such a file (section 8).

## 5. Fingerprints

The fingerprint of a schema is the CRC-64-AVRO (Rabin) fingerprint of the schema's Parsing Canonical Form, as an unsigned 64-bit value. Wherever it appears in bytes, it is written as 8 bytes in little-endian order.

- The Parsing Canonical Form keeps only the attributes that matter for decoding: `type`, `name`, `fields`, `symbols`, `items`, `values` and `size`. It drops `doc`, `aliases`, `default` and `logicalType`. A primitive that carries a logical type is therefore written as the plain primitive name, for example `"string"`. At least one Avro library (the Python `avro` package 1.12.2) writes `{"type":"string"}` instead and so computes a different fingerprint. An AXT implementation MUST compute the canonical form as the Avro specification defines it, and MUST be checked against the test vectors ([conformance.md](conformance.md)).
- A fingerprint is an identifier, not a means of authentication. CRC-64-AVRO is not collision resistant: a schema with a given fingerprint can be constructed on purpose. Two schemas that differ only in dropped attributes, such as `doc` or a logical type, have the same fingerprint by design.
- A sender MUST NOT offer, in one offer or one file, two schemas with the same fingerprint. A receiver MUST reject an offer or a file that does.

## 6. Schema resolution

A receiver decodes a record with the writer schema it got from the offer or the file header, and resolves it against its own schema of that type, the reader schema, following the schema resolution of the Avro specification. In particular:

- The full names of the two record schemas MUST match, or the writer's name MUST be one of the reader's aliases.
- Fields are matched by name. A writer field the reader does not have is ignored. A reader field the writer does not have takes the reader's default; if it has no default, the schemas do not resolve.
- An enum symbol the reader does not know takes the reader enum's default; if it has none, the schemas do not resolve.

A receiver SHOULD resolve the schemas once, when it gets the writer schema, rather than for each record. If they do not resolve, the receiver declines the type with `DOES_NOT_RESOLVE` in a live connection and through a relay ([protocol.md](protocol.md), section 5.2), and does not apply the type's records from a file. A receiver that takes any type and has no schema of its own for it ([manifest.md](manifest.md)) reads the record with the writer schema alone.

## 7. Bytes, strings, times and ids

- **Byte order.** Avro writes `int` and `long` as zig-zag varints, which have no byte order, and `float` and `double` as IEEE 754 values in little-endian order. Fingerprints are little-endian (section 5). `fixed` and `bytes` are carried as they are; Ed25519 keys and signatures use the encoding of [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) ([keys.md](keys.md)).
- **Strings.** Avro strings are UTF-8 ([RFC 3629](https://www.rfc-editor.org/rfc/rfc3629)). A string MUST be well-formed UTF-8, without a byte order mark; a receiver MUST reject a message that contains a string that is not well-formed, including one that encodes a surrogate code point. AXT does not normalize strings; a receiver keeps them as received. Schemas and the value of `axt.schemas` are JSON texts in UTF-8 ([RFC 8259](https://www.rfc-editor.org/rfc/rfc8259)).
- **Times.** Dates, times of day, dates and times, and lengths of time are the records `axt.Date`, `axt.Time`, `axt.DateTime` and `axt.Duration` of [time.md](time.md), not Avro's logical types for times. The schemas of this specification and the example types MUST NOT use those logical types; [time.md](time.md), section 3.2, says what that means for other schemas.
- **Ids.** A UUID is a `string` with the logical type `uuid`, written in the 36-character text form of [RFC 9562](https://www.rfc-editor.org/rfc/rfc9562) with lower-case hexadecimal digits. A receiver MUST accept upper-case digits as well and compares UUIDs as 128-bit values. The Avro specification also allows `uuid` on a `fixed` of 16 bytes, but only since 1.12, and not all Avro libraries support it; the string form works in every library that supports the logical type.
- **Unknown logical types.** A reader that does not know a logical type uses the underlying Avro type, as the Avro specification says.

## 8. Size limits

| What                                                    | Maximum                     |
| ------------------------------------------------------- | --------------------------- |
| One message, including its single-object header         | 16 MiB (16,777,216 bytes)   |
| One schema as JSON text                                 | 256 KiB (262,144 bytes)     |
| Nesting depth of a schema's JSON text                   | 64                          |
| The metadata of a file, keys and values together        | 8 MiB (8,388,608 bytes)     |
| One file as stored                                      | 256 MiB (268,435,456 bytes) |
| One data block of a file, after decompression           | 64 MiB (67,108,864 bytes)   |
| All data blocks of a file together, after decompression | 1 GiB (1,073,741,824 bytes) |

A sender MUST NOT produce a message, a schema or a file above these limits. A receiver MUST NOT reject a message, a schema or a file for its size while it is within them.

- **Above a limit in a live connection.** A receiver MUST reject a message above the message limit without decoding it, and reports it with the error `TOO_LARGE` ([protocol.md](protocol.md), section 8.2). If the transport cannot skip the message, the receiver MAY close the connection. An offer with a schema above the schema limits is rejected in the same way.
- **Above a limit in a file.** A reader MUST check the size of a file before reading it, and MUST stop decompressing a block as soon as it exceeds the block limit or the total exceeds the file limit. It MUST then reject the whole file. A reader MUST NOT apply any record from a file it rejects, whatever the reason for the rejection.
- **Declared lengths.** Avro data declares the lengths of strings and bytes and the counts of array and map items before their content. A decoder MUST NOT allocate memory for a declared length or count before it has checked that the remaining input can hold it, and MUST reject a negative length.

The message limit lets a record carry a photo or a scanned document, while keeping what a phone has to hold in memory for one message small. The file limit allows a full export of an app's records, which a messenger or mail can still carry. The decompressed limits keep a small deflated file from expanding without bound.

## 9. Media type and file extension

An AXT file has the media type `application/vnd.axt` and the file extension `.axt`.

The media type has no `+avro` suffix, because `+avro` is not a registered structured syntax suffix ([RFC 6838, section 4.2.8](https://www.rfc-editor.org/rfc/rfc6838#section-4.2.8); [IANA registry](https://www.iana.org/assignments/media-type-structured-suffix/media-type-structured-suffix.xhtml)). `application/vnd.axt` is not registered with IANA yet. Apps use it as defined here until the registration in the vendor tree is done.

Messengers and file shares often change a file's name or drop its media type. A receiver MUST therefore identify an AXT file by its content, the Avro magic and an `avro.schema` of a supported envelope format, and not by its name or media type alone.

## 10. Examples

The bytes below were produced with [conformance/tools/envelope_examples.py](../conformance/tools/envelope_examples.py). The script reads [types/axt/Envelope.avsc](../types/axt/Envelope.avsc), encodes with the Python library fastavro 1.13.1, and checks the result:

- its CRC-64-AVRO implementation against the fingerprints published in the Avro repository's `share/test/data/schema-tests.txt`;
- the fingerprints against fastavro's and the Python `avro` 1.12.2 package's own fingerprint functions;
- the message, built field by field, against fastavro's binary encoding, and by decoding it again;
- the file, by reading it back with both libraries;
- the signatures, made with the Ed25519 implementation of [conformance/tools/keys_examples.py](../conformance/tools/keys_examples.py), by verifying them, and the message and the file by their SHA-256 against those of [keys.md](keys.md), sections 7.2 and 7.3.

The record type `com.example.Memo` is an illustration only, not an example type. Both examples are signed with cat-a-log's test key of [keys.md](keys.md), section 7.1, and are the message and the file of [keys.md](keys.md), sections 7.2 and 7.3, which show what the signatures cover. The test vectors of [conformance.md](conformance.md) take precedence over these examples.

### 10.1 Schemas and fingerprints

`com.example.Memo`, as offered. Its field `written` defines the time type `axt.DateTime` in place ([time.md](time.md), section 3.1); the `…` stand for the `doc` and the fields of the published schema [types/axt/DateTime.avsc](../types/axt/DateTime.avsc), which the schema carries in full:

```json
{"type":"record","name":"Memo","namespace":"com.example","doc":"An illustration for spec/envelope.md; not an AXT example type.","fields":[{"name":"text","type":"string","doc":"The memo's text."},{"name":"written","type":{"type":"record","name":"DateTime","namespace":"axt","doc":"…","fields":[…]},"doc":"When the memo was written.","axt.anchor":"instant"}]}
```

Its Parsing Canonical Form:

```json
{"name":"com.example.Memo","type":"record","fields":[{"name":"text","type":"string"},{"name":"written","type":{"name":"axt.DateTime","type":"record","fields":[{"name":"year","type":"int"},{"name":"month","type":"int"},{"name":"day","type":"int"},{"name":"hour","type":"int"},{"name":"minute","type":"int"},{"name":"second","type":"int"},{"name":"millisecond","type":"int"},{"name":"zone","type":["null","string"]},{"name":"offset_seconds","type":["null","int"]},{"name":"instant_ms","type":["null","long"]}]}}]}
```

The Parsing Canonical Form of `axt.Envelope`, format 1:

```json
{"name":"axt.Envelope","type":"record","fields":[{"name":"format","type":"int"},{"name":"kind","type":{"name":"axt.Kind","type":"enum","symbols":["MANIFEST","OFFER","ACCEPT","DECLINE","DATA","DELETE","ACK","ERROR","DEVICE_JOIN","DEVICE_ADD","DEVICE_REMOVE","CHANGE","RESYNC","FORWARD","WITHDRAW","PROPOSAL","PROPOSAL_REPLY"]}},{"name":"sender","type":{"name":"axt.PublicKey","type":"fixed","size":32}},{"name":"record","type":["null",{"name":"axt.RecordRef","type":"record","fields":[{"name":"id","type":"string"},{"name":"version","type":"long"}]}]},{"name":"body","type":"bytes"},{"name":"signature","type":{"name":"axt.Signature","type":"fixed","size":64}}]}
```

| Schema                   | CRC-64-AVRO          | As bytes                  |
| ------------------------ | -------------------- | ------------------------- |
| `axt.Envelope`, format 1 | `0xa89eceb9716f3016` | `16 30 6f 71 b9 ce 9e a8` |
| `com.example.Memo`       | `0x37f20e16cadcac73` | `73 ac dc ca 16 0e f2 37` |

### 10.2 A data message

A `DATA` message in a live connection that carries the Memo with the text `Vet, Tuesday 10:00`, written at 2025-11-15 11:00 in `Europe/Berlin` with the offset 3600, the instant `1763200800000` (2025-11-15T10:00:00Z), as version 1 of the record `0b5a3c1e-4d2f-4a6b-9c8d-7e6f5a4b3c2d`; 210 bytes. Offsets are hexadecimal.

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
002e  30 62 35 61 33 63 31 65  "0b5a3c1e-4d2f-4a6b-9c8d-7e6f5a4b3c2d"
      2d 34 64 32 66 2d 34 61
      36 62 2d 39 63 38 64 2d
      37 65 36 66 35 61 34 62
      33 63 32 64
0052  02                       record.version: long 1
0053  7c                       body: bytes length 62
0054  c3 01                    body: single-object marker
0056  73 ac dc ca 16 0e f2 37  body: fingerprint of com.example.Memo
005e  24                       body: text: string length 18
005f  56 65 74 2c 20 54 75 65  "Vet, Tuesday 10:00"
      73 64 61 79 20 31 30 3a
      30 30
0071  d2 1f                    body: written.year: int 2025
0073  16                       body: written.month: int 11
0074  1e                       body: written.day: int 15
0075  16                       body: written.hour: int 11
0076  00                       body: written.minute: int 0
0077  00                       body: written.second: int 0
0078  00                       body: written.millisecond: int 0
0079  02 1a                    body: written.zone: union index 1, string length 13
007b  45 75 72 6f 70 65 2f 42  "Europe/Berlin"
      65 72 6c 69 6e
0088  02 a0 38                 body: written.offset_seconds: union index 1, int 3600
008b  02 80 d4 a8 ef d0 66     body: written.instant_ms: union index 1, long 1763200800000
0092  8d de f4 42 9c 18 3d 9c  signature: fixed(64)
      a3 8e 0a 0d 7b 90 08 84
      18 f7 1f e9 43 10 0e a9
      b7 6b 4a 96 5c 60 b0 25
      0d e8 56 1e 84 d1 0c ca
      b3 e2 cb 6c a7 e0 ec a9
      16 92 97 37 c4 fc 26 4c
      5c 6a 52 39 67 df c1 06
00d2  end
```

### 10.3 A file

The same message in an AXT file with the codec `null`; 5,020 bytes, SHA-256 `37074c1f86d048a02e906441adc37f41599d1c9776fb2ae594a3f068f257a94c`. A writer picks the 16-byte sync marker at random; the example uses `00 01 … 0f` so that its bytes can be reproduced. The two JSON values are shown shortened; the first is the Memo schema of section 10.1, the second the envelope schema of [types/axt/Envelope.avsc](../types/axt/Envelope.avsc) with its keys in the file's order, as Python's `json.dumps` writes it. The two hexadecimal texts are shortened as well.

```text
0000  4f 62 6a 01              magic "Obj" 01
0004  0a                       metadata: map block of 5 entries
0005  16                       key: string length 11
0006  61 78 74 2e 73 63 68 65  "axt.schemas"
      6d 61 73
0011  bc 1f                    value: bytes length 2014
0013  5b 7b 22 74 ... 7d 5d    [{"type":"record","name":"Memo", ...}]  (2014 bytes of UTF-8 JSON)
07f1  14                       key: string length 10
07f2  61 78 74 2e 73 65 6e 64  "axt.sender"
      65 72
07fc  80 01                    value: bytes length 64
07fe  31 62 38 34 ... 34 61    "1b84a6...26ec4a"  (64 hexadecimal digits, cat-a-log's test key)
083e  1a                       key: string length 13
083f  61 78 74 2e 73 69 67 6e  "axt.signature"
      61 74 75 72 65
084c  80 02                    value: bytes length 128
084e  38 39 61 30 ... 30 30    "89a017...619300"  (128 hexadecimal digits, the header signature)
08ce  14                       key: string length 10
08cf  61 76 72 6f 2e 63 6f 64  "avro.codec"
      65 63
08d9  08                       value: bytes length 4
08da  6e 75 6c 6c              "null"
08de  16                       key: string length 11
08df  61 76 72 6f 2e 73 63 68  "avro.schema"
      65 6d 61
08ea  88 27                    value: bytes length 2500
08ec  7b 22 74 79 ... 5d 7d    {"type": "record", "name": "Envelope", "namespace": "axt", ...}  (2500 bytes of UTF-8 JSON)
12b0  00                       end of the metadata map
12b1  00 01 02 03 04 05 06 07  sync marker
      08 09 0a 0b 0c 0d 0e 0f
12c1  02                       block: 1 datum
12c2  90 03                    block: 200 bytes
12c4  02 08 1b 84 ... c1 06    the datum: bytes 000a to 00d1 of the message in 10.2
138c  00 01 02 03 04 05 06 07  sync marker
      08 09 0a 0b 0c 0d 0e 0f
139c  end
```

## References

- [Apache Avro 1.12 specification](https://avro.apache.org/docs/1.12.0/specification/)
- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174): key words for requirement levels
- [RFC 1951](https://www.rfc-editor.org/rfc/rfc1951): DEFLATE
- [RFC 3629](https://www.rfc-editor.org/rfc/rfc3629): UTF-8
- [RFC 6838](https://www.rfc-editor.org/rfc/rfc6838): media type registration
- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032): Ed25519
- [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259): JSON
- [RFC 9562](https://www.rfc-editor.org/rfc/rfc9562): UUIDs
