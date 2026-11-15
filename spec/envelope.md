# Envelope and encoding

Status: written, 0.1.0. Until 0.1.0 is released, the later documents of 0.1.0 may still change the envelope schema; the fingerprint and the examples below are then produced again.

This document defines how AXT messages travel as bytes: the envelope every message is wrapped in, its encoding in a live connection and in a file, the fingerprints that name schemas, schema resolution, the representation of strings, times and ids, the size limits, and the media type and file extension.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 ([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119), [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)) when, and only when, they appear in all capitals, as shown here.

## 1. Avro

AXT encodes everything with [Apache Avro 1.12](https://avro.apache.org/docs/1.12.0/specification/) (in this document: the Avro specification). Where this document says "binary encoding", "single-object encoding", "object container file", "Parsing Canonical Form", "CRC-64-AVRO" or "schema resolution", the term has the meaning the Avro specification gives it. An implementation MUST follow the Avro specification wherever this document does not say otherwise.

## 2. The envelope

Every AXT message is one datum of the record `axt.Envelope`. Its schema is [types/axt/Envelope.avsc](../types/axt/Envelope.avsc); the schemas of this specification live in [types/axt/](../types/axt/) under the Avro namespace `axt`, which is reserved for them.

| Field       | Avro type                                  | Content                                                                                   | Defined in                 |
| ----------- | ------------------------------------------ | ----------------------------------------------------------------------------------------- | -------------------------- |
| `format`    | `int`                                      | The envelope format; `1` for the envelope defined here                                    | this document, section 2.1 |
| `kind`      | enum `axt.Kind`                            | What the message is, and so which schema its body has                                     | this document, section 2.2 |
| `sender`    | `fixed` of 32 bytes, `axt.PublicKey`       | The Ed25519 public key of the sending installation                                        | [keys.md](keys.md)         |
| `record`    | union of `null` and record `axt.RecordRef` | The id (`uuid` string) and version (`long`) of the record the message is about, or `null` | [records.md](records.md)   |
| `body`      | `bytes`                                    | Empty, or one datum in single-object encoding                                             | this document, section 2.3 |
| `signature` | `fixed` of 64 bytes, `axt.Signature`       | The sender's Ed25519 signature                                                            | [keys.md](keys.md)         |

### 2.1 Format

`format` names the envelope format, that is, one published version of the `axt.Envelope` schema. This document defines format `1`. Each format has its own schema and so its own fingerprint (section 5); a library MUST know the fingerprint of every format it supports.

Every later envelope schema MUST keep `format` as its first field, of type `int`. A receiver that does not know an envelope's fingerprint can therefore still read the format number: in a live message it is the zig-zag varint that starts at byte offset 10. A receiver MAY use it only to report that the message has a format it does not support; it MUST NOT decode the rest.

A sender MUST write each message in a format the receiver supports. In a live connection, [protocol.md](protocol.md) defines how the two apps learn each other's formats. A file has no such step, so a writer SHOULD write a file in the lowest format that can carry its content.

### 2.2 Kind

| Kind       | Purpose                                                 | Defined in                                           |
| ---------- | ------------------------------------------------------- | ---------------------------------------------------- |
| `MANIFEST` | The types an app takes and what it does with them       | [manifest.md](manifest.md)                           |
| `OFFER`    | Types and their writer schemas the sender wants to send | [protocol.md](protocol.md)                           |
| `ACCEPT`   | The receiver takes an offered type                      | [protocol.md](protocol.md)                           |
| `DECLINE`  | The receiver does not take an offered type              | [protocol.md](protocol.md)                           |
| `DATA`     | One record, new or updated                              | [records.md](records.md), [protocol.md](protocol.md) |
| `DELETE`   | The deletion of one record                              | [records.md](records.md), [protocol.md](protocol.md) |
| `ACK`      | The receiver confirms what it applied                   | [protocol.md](protocol.md)                           |
| `ERROR`    | The receiver reports a message it could not process     | [protocol.md](protocol.md)                           |
| `KEY_MOVE` | The sender's key moves to a new installation            | [keys.md](keys.md)                                   |

The document that defines a kind also defines whether its messages carry `record` and which schema their body has. Two rules hold already:

- A `DATA` message MUST carry `record`, and its body MUST be the record in single-object encoding with a writer schema the receiver has from an offer (section 3) or the file header (section 4).
- A `DELETE` message MUST carry `record` and MUST have an empty body.

New kinds come only with a new envelope format.

### 2.3 Body

The body is either empty or exactly one datum in single-object encoding: the two bytes `C3 01`, the 8-byte little-endian CRC-64-AVRO fingerprint of the datum's writer schema (section 5), then the datum in binary encoding. A receiver MUST reject a body that is neither empty nor a complete single-object encoding with no bytes left over.

For `DATA`, the writer schema is the record type's schema as offered. For every other kind with a body, the schema is the one the defining document publishes under [types/axt/](../types/axt/); those fingerprints are fixed by the specification and are not offered.

### 2.4 Sender and signature

`sender` and `signature` are what [keys.md](keys.md) needs to sign and verify every message. The envelope is laid out for that:

- `signature` is the last field and has a fixed length, so the last 64 bytes of an encoded envelope are the signature, and all bytes before them are the rest of the message.
- The body is carried as bytes, so the record inside it is never encoded again on the way.

What the signature covers, and how a receiver verifies it, is defined in [keys.md](keys.md). keys.md MUST define the signed bytes as bytes of the message as it was received, not as an encoding the receiver produces again from decoded values: a decoded value can encode differently, for example a UUID received with upper-case digits (section 7). keys.md MUST also choose the signed bytes so that they are the same in a live message and in a file (section 4).

## 3. Live connection

In a live connection, the schema of each record type is sent once, in the offer ([protocol.md](protocol.md)). Every message, the offer included, is one envelope in single-object encoding:

1. the marker `C3 01`;
2. the 8-byte little-endian CRC-64-AVRO fingerprint of the envelope schema, which for format 1 is `7d 0c e4 e5 4f e8 e1 a2` (section 10.1);
3. the envelope in binary encoding.

The envelope carries no length and no terminator; the transport supplies the boundaries of each message ([transports.md](transports.md)). A receiver MUST reject a message with bytes left over after the envelope.

An offer carries each writer schema as its full JSON text, including `doc` attributes, so that a receiver can show fields it does not know by name and description ([types.md](types.md)). The Parsing Canonical Form is used only to compute the fingerprint. The receiver keeps the offered schemas by fingerprint for as long as [protocol.md](protocol.md) says the offer is valid.

Through a relay, the end-to-end encryption defined in [keys.md](keys.md) wraps the complete encoded message. No envelope field, not even `kind`, is visible to the relay ([relay.md](relay.md)).

### 3.1 Unknown fingerprints

- **Envelope.** A message whose envelope fingerprint is not one of the formats the receiver supports MUST be rejected without decoding it; section 2.1 says how the format number can still be read for the report.
- **Data.** A receiver that gets a `DATA` message whose body fingerprint is not among the schemas offered to it MUST NOT decode the body, and MUST NOT try other schemas in its place. It MUST either ask the sender for the schema, using the step [protocol.md](protocol.md) defines for that, or reject the message as [protocol.md](protocol.md) describes.
- **Other kinds.** A message of another kind whose body fingerprint is not the one the defining document publishes for that kind and format MUST be rejected.

## 4. File

An AXT file is an Avro object container file: the magic `Obj` followed by the byte `01`, the file metadata, a 16-byte sync marker, then data blocks. Each datum in it is one `axt.Envelope`. Its bytes are exactly those of a live message without the 10-byte single-object header. With the signed bytes chosen as section 2.4 requires, a message keeps its signature when it moves between a file and a connection.

### 4.1 Metadata

| Key           | Value                                                                                                         | Required                            |
| ------------- | ------------------------------------------------------------------------------------------------------------- | ----------------------------------- |
| `avro.schema` | The envelope schema as JSON; its Parsing Canonical Form MUST be that of a published envelope format           | yes                                 |
| `avro.codec`  | `null` or `deflate` (section 4.2); if the key is absent, the codec is `null`, as in the Avro specification    | no                                  |
| `axt.schemas` | A JSON array of the full writer schemas, `doc` attributes included, of the records in the file, as UTF-8 JSON | when the file holds `DATA` messages |

`axt.schemas` takes the place of the offer: a file is read without a connection, so the record schemas travel in its header. The fingerprints of the schemas in it MUST be distinct, and every `DATA` body in the file MUST name one of them. `avro.schema` holds the envelope schema rather than a record schema, because every record in a file needs the envelope's id, version, key and signature.

A reader identifies the envelope format by the fingerprint of `avro.schema` and MUST reject a file whose envelope fingerprint it does not support. It MUST NOT depend on the exact text of `avro.schema`, since Avro libraries write it in different ways. Metadata keys that start with `axt.` are reserved for this specification. A reader MUST ignore metadata keys it does not know.

The metadata is not part of any message, so no message signature covers it. [keys.md](keys.md) defines how the schemas in `axt.schemas` are bound to the sender's key. Until then, the fingerprint alone does not protect them (section 5).

Which kinds a file may hold is defined in [transports.md](transports.md).

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

A receiver SHOULD resolve the schemas once, when it gets the writer schema, rather than for each record. If they do not resolve, the receiver declines the type in a live connection ([protocol.md](protocol.md)) and does not apply the type's records from a file. A receiver that takes any type and has no schema of its own for it ([manifest.md](manifest.md)) reads the record with the writer schema alone.

## 7. Bytes, strings, times and ids

- **Byte order.** Avro writes `int` and `long` as zig-zag varints, which have no byte order, and `float` and `double` as IEEE 754 values in little-endian order. Fingerprints are little-endian (section 5). `fixed` and `bytes` are carried as they are; Ed25519 keys and signatures use the encoding of [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) ([keys.md](keys.md)).
- **Strings.** Avro strings are UTF-8 ([RFC 3629](https://www.rfc-editor.org/rfc/rfc3629)). A string MUST be well-formed UTF-8, without a byte order mark; a receiver MUST reject a message that contains a string that is not well-formed, including one that encodes a surrogate code point. AXT does not normalize strings; a receiver keeps them as received. Schemas and the value of `axt.schemas` are JSON texts in UTF-8 ([RFC 8259](https://www.rfc-editor.org/rfc/rfc8259)).
- **Instants.** A point in time is a `long` with the logical type `timestamp-millis`: milliseconds since 1970-01-01T00:00:00Z. The schemas of this specification and the example types MUST use `timestamp-millis` for points in time and MUST NOT use `timestamp-micros` or `timestamp-nanos`; other schemas used with AXT SHOULD do the same. Because the Parsing Canonical Form drops logical types, a millisecond and a microsecond field have the same fingerprint, and a mix-up would go undetected; one unit for all AXT types rules that out. Milliseconds are fine enough for the records people exchange, and they are the unit of JavaScript's `Date` and of many other platforms' clocks.
- **Dates.** A calendar day without a time, such as a birthday, is an `int` with the logical type `date`: days since 1970-01-01.
- **Local date and time.** A date and time on the wall clock that is not tied to an instant, such as an appointment that stays at 10:00 when daylight saving rules change, is a `long` with the logical type `local-timestamp-millis`. Where the time zone matters, a type carries it in a separate field as an IANA time zone name; the fields themselves are defined in [types.md](types.md).
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

- **Above a limit in a live connection.** A receiver MUST reject a message above the message limit without decoding it, as [protocol.md](protocol.md) describes. If the transport cannot skip the message, the receiver MAY close the connection. An offer with a schema above the schema limits is rejected in the same way.
- **Above a limit in a file.** A reader MUST check the size of a file before reading it, and MUST stop decompressing a block as soon as it exceeds the block limit or the total exceeds the file limit. It MUST then reject the whole file. A reader MUST NOT apply any record from a file it rejects, whatever the reason for the rejection.
- **Declared lengths.** Avro data declares the lengths of strings and bytes and the counts of array and map items before their content. A decoder MUST NOT allocate memory for a declared length or count before it has checked that the remaining input can hold it, and MUST reject a negative length.

The message limit lets a record carry a photo or a scanned document, while keeping what a phone has to hold in memory for one message small. The file limit allows a full export of an app's records, which a messenger or mail can still carry. The decompressed limits keep a small deflated file from expanding without bound.

## 9. Media type and file extension

An AXT file has the media type `application/vnd.axt` and the file extension `.axt`.

The media type has no `+avro` suffix, because `+avro` is not a registered structured syntax suffix ([RFC 6838, section 4.2.8](https://www.rfc-editor.org/rfc/rfc6838#section-4.2.8); [IANA registry](https://www.iana.org/assignments/media-type-structured-suffix/media-type-structured-suffix.xhtml)). `application/vnd.axt` is not registered with IANA yet. Apps use it as defined here until the registration in the vendor tree is done.

Messengers and file shares often change a file's name or drop its media type. A receiver MUST therefore identify an AXT file by its content, the Avro magic and an `avro.schema` of a supported envelope format, and not by its name or media type alone.

## 10. Examples

The bytes below were produced with [vectors/tools/envelope_examples.py](../vectors/tools/envelope_examples.py). The script reads [types/axt/Envelope.avsc](../types/axt/Envelope.avsc), encodes with the Python library fastavro 1.13.1, and checks the result:

- its CRC-64-AVRO implementation against the fingerprints published in the Avro repository's `share/test/data/schema-tests.txt`;
- the fingerprints against fastavro's and the Python `avro` 1.12.2 package's own fingerprint functions;
- the message, built field by field, against fastavro's binary encoding, and by decoding it again;
- the file, by reading it back with both libraries.

The record type `com.example.Memo` is an illustration only, not an example type. `sender` and `signature` are placeholders until [keys.md](keys.md) defines them, so neither example verifies as signed. The test vectors of [conformance.md](conformance.md) take precedence over these examples.

### 10.1 Schemas and fingerprints

`com.example.Memo`, as offered:

```json
{"type":"record","name":"Memo","namespace":"com.example","doc":"An illustration for spec/envelope.md; not an AXT example type.","fields":[{"name":"text","type":"string","doc":"The memo's text."},{"name":"written","type":{"type":"long","logicalType":"timestamp-millis"},"doc":"When the memo was written."}]}
```

Its Parsing Canonical Form:

```json
{"name":"com.example.Memo","type":"record","fields":[{"name":"text","type":"string"},{"name":"written","type":"long"}]}
```

The Parsing Canonical Form of `axt.Envelope`, format 1:

```json
{"name":"axt.Envelope","type":"record","fields":[{"name":"format","type":"int"},{"name":"kind","type":{"name":"axt.Kind","type":"enum","symbols":["MANIFEST","OFFER","ACCEPT","DECLINE","DATA","DELETE","ACK","ERROR","KEY_MOVE"]}},{"name":"sender","type":{"name":"axt.PublicKey","type":"fixed","size":32}},{"name":"record","type":["null",{"name":"axt.RecordRef","type":"record","fields":[{"name":"id","type":"string"},{"name":"version","type":"long"}]}]},{"name":"body","type":"bytes"},{"name":"signature","type":{"name":"axt.Signature","type":"fixed","size":64}}]}
```

| Schema                   | CRC-64-AVRO          | As bytes                  |
| ------------------------ | -------------------- | ------------------------- |
| `axt.Envelope`, format 1 | `0xa2e1e84fe5e40c7d` | `7d 0c e4 e5 4f e8 e1 a2` |
| `com.example.Memo`       | `0xb71ce40c6856b368` | `68 b3 56 68 0c e4 1c b7` |

### 10.2 A data message

A `DATA` message in a live connection that carries the Memo `{"text": "Vet, Tuesday 10:00", "written": 1763200800000}` (2025-11-15T10:00:00Z) as version 1 of the record `0b5a3c1e-4d2f-4a6b-9c8d-7e6f5a4b3c2d`; 183 bytes. Offsets are hexadecimal.

```text
0000  c3 01                    single-object marker
0002  7d 0c e4 e5 4f e8 e1 a2  fingerprint of axt.Envelope, format 1
000a  02                       format: int 1
000b  08                       kind: enum index 4, DATA
000c  00 01 02 03 04 05 06 07  sender: fixed(32), placeholder
      08 09 0a 0b 0c 0d 0e 0f
      10 11 12 13 14 15 16 17
      18 19 1a 1b 1c 1d 1e 1f
002c  02                       record: union index 1, axt.RecordRef
002d  48                       record.id: string length 36
002e  30 62 35 61 33 63 31 65  "0b5a3c1e-4d2f-4a6b-9c8d-7e6f5a4b3c2d"
      2d 34 64 32 66 2d 34 61
      36 62 2d 39 63 38 64 2d
      37 65 36 66 35 61 34 62
      33 63 32 64
0052  02                       record.version: long 1
0053  46                       body: bytes length 35
0054  c3 01                    body: single-object marker
0056  68 b3 56 68 0c e4 1c b7  body: fingerprint of com.example.Memo
005e  24                       body: text, string length 18
005f  56 65 74 2c 20 54 75 65  "Vet, Tuesday 10:00"
      73 64 61 79 20 31 30 3a
      30 30
0071  80 d4 a8 ef d0 66        body: written, long 1763200800000
0077  00 00 00 00 00 00 00 00  signature: fixed(64), placeholder
      ... (64 bytes of 00 in all)
00b7  end
```

### 10.3 A file

The same message in an AXT file with the codec `null`; 2,572 bytes, SHA-256 `2cdaecf3520837e3ba3399cfdd6afd264a3ba7dc792cb37c71b80c47f24f3376`. A writer picks the 16-byte sync marker at random; the example uses `00 01 … 0f` so that its bytes can be reproduced. The two JSON values are shown shortened; the first is the Memo schema of section 10.1, the second the envelope schema as fastavro writes it.

```text
0000  4f 62 6a 01              magic "Obj" 01
0004  06                       metadata: map block of 3 entries
0005  16                       key: string length 11
0006  61 78 74 2e 73 63 68 65  "axt.schemas"
      6d 61 73
0011  e8 04                    value: bytes length 308
0013  5b 7b 22 74 ... 7d 5d    [{"type":"record","name":"Memo", ...}]  (308 bytes of UTF-8 JSON)
0147  14                       key: string length 10
0148  61 76 72 6f 2e 63 6f 64  "avro.codec"
      65 63
0152  08                       value: bytes length 4
0153  6e 75 6c 6c              "null"
0157  16                       key: string length 11
0158  61 76 72 6f 2e 73 63 68  "avro.schema"
      65 6d 61
0163  ac 1f                    value: bytes length 2006
0165  7b 22 74 79 ... 5d 7d    {"type": "record", ..., "name": "axt.Envelope", ...}  (2006 bytes of UTF-8 JSON)
093b  00                       end of the metadata map
093c  00 01 02 03 04 05 06 07  sync marker
      08 09 0a 0b 0c 0d 0e 0f
094c  02                       block: 1 datum
094d  da 02                    block: 173 bytes
094f  02 08 00 01 02 ...       the datum: bytes 000a to 00b6 of the message in 10.2
09fc  00 01 02 03 04 05 06 07  sync marker
      08 09 0a 0b 0c 0d 0e 0f
0a0c  end
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
