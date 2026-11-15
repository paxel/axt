# Conformance

Status: written, 0.1.0. Until 0.1.0 is released, the vectors are produced again whenever another document of 0.1.0 changes a value they hold.

This document defines what it means for a library to conform to AXT. It defines the test vectors (bytes with their expected meaning, and sequences of messages with their expected results), the file format they are kept in, how a result is expressed, and the conformance suite: a runner that drives a library through a small adapter, and a reference adapter that shows the vectors to be consistent.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 ([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119), [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)) when, and only when, they appear in all capitals, as shown here.

## 1. Terms

- **Library**: an implementation of AXT that apps use, such as one of [libs/](../libs/README.md).
- **Vector**: one test: an operation, its input, and the result the specification expects (section 3).
- **Category**: a group of vectors that tests one part of the specification (section 2.1). Each category has one vector file.
- **Operation**: what a vector asks the library to do, such as decoding a message or reading a file (section 5). Each operation belongs to one category.
- **Adapter**: a small program, written for one library, that performs the operations with that library and answers in the protocol of section 6.
- **Runner**: the program [conformance/run.py](../conformance/run.py), which sends every vector to an adapter and compares the answers with the expected results (section 7).
- **Session**: a vector whose input is a sequence of steps, played in order against one fresh state of the library, such as one app in one live connection.

## 2. Conformance

### 2.1 Categories

| Category       | Tests                                                                                                          | Defined in                                                      |
| -------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| `encoding`     | Canonical forms and fingerprints; the envelope of a live message and the bodies of the specification's schemas | [envelope.md](envelope.md)                                      |
| `types`        | The example types: fingerprints, records and their meaning, schema resolution, the data depth limit            | [types.md](types.md)                                            |
| `time`         | The time types: fingerprints, values and their validity, other zone rules, adding a duration                   | [time.md](time.md)                                              |
| `records`      | A receiver applying record messages: the version rule, tombstones, its user's own changes, the outcomes        | [records.md](records.md)                                        |
| `manifest`     | The validity and limits of a manifest, which types fit it, and the language of the purpose sentence            | [manifest.md](manifest.md)                                      |
| `keys`         | Signing keys, strict verification, short fingerprints, key moves, padding, sealing and opening                 | [keys.md](keys.md)                                              |
| `protocol`     | One app in a live connection: manifests, offers, answers, record messages, acknowledgements and errors         | [protocol.md](protocol.md)                                      |
| `file`         | Reading an AXT file: what it holds, in which order, and what rejects the whole file or only one record         | [transports.md](transports.md), section 2                       |
| `qr`           | The QR payload and its text                                                                                    | [transports.md](transports.md), section 3                       |
| `local`        | The frames and the `HELLO` of a connection on the local network                                                | [transports.md](transports.md), section 4                       |
| `relay`        | The relay as an app uses it: mailbox ids, requests, what an app does with each response, the list of messages  | [transports.md](transports.md), section 5                       |
| `relay-server` | The interface of a relay, for relays rather than libraries                                                     | [transports.md](transports.md), section 5; [relay.md](relay.md) |

### 2.2 What a library implements

A library MUST pass every vector of every category it implements. It implements a category when it offers what the category tests to the apps that use it.

- Every library MUST implement `encoding`, `types`, `time`, `records`, `manifest`, `keys` and `protocol`: every transport carries messages, and every app that receives records applies them.
- A library that supports a transport MUST implement its categories: `file` for files; `local` and `qr` for the local network; `relay` for the relay, and `qr` as well if it shows or scans QR codes for it. AXT does not require an app to support every transport ([transports.md](transports.md), section 1), and so does not require it of a library.
- `relay-server` is for relays, such as the reference relay of [relay.md](relay.md). A relay MUST pass it; a library need not implement it.

A category is passed only as a whole: within a category a library implements, a vector that its adapter answers as unsupported fails, and with it the category. A library states the categories it implements; that it conforms to AXT 0.1.0 means that it passes at least the seven categories every library implements.

### 2.3 Precedence

The normative text of the specification governs. The vectors make it testable. They are produced with the code that also produces the examples of the other documents (section 7.3), and where an example and a vector differ, the vector holds, as each of those documents says. A vector that contradicts the normative text is a fault in the vectors: it is reported as an issue and corrected in a later release of the vectors, and a library that follows the text in that point still conforms.

## 3. The vector files

### 3.1 Files

The vectors are in [vectors/](../vectors/README.md), one file per category: `vectors/<category>/<category>.json`. The format of the files is defined here and by the JSON Schema [vectors/vectors.schema.json](../vectors/vectors.schema.json), against which the runner checks every file before it runs. The vectors are data and are published under CC0 1.0, as the specification is ([LICENSING.md](../LICENSING.md)).

A file is a JSON text ([RFC 8259](https://www.rfc-editor.org/rfc/rfc8259)) in UTF-8 that holds one object:

| Member          | Content                                                               |
| --------------- | --------------------------------------------------------------------- |
| `format`        | The version of this file format, `1`                                  |
| `specification` | The version of the specification the vectors are for, such as `0.1.0` |
| `category`      | The category of every vector in the file (section 2.1)                |
| `description`   | What the category tests, for people                                   |
| `vectors`       | The vectors, in the order in which the runner sends them              |

Each vector is an object:

| Member        | Content                                                                                                  |
| ------------- | -------------------------------------------------------------------------------------------------------- |
| `id`          | A name unique among all vectors, `<category>/<operation>/<name>`, by which the runner reports the vector |
| `op`          | The operation (section 5)                                                                                |
| `description` | What the vector tests, for people                                                                        |
| `refs`        | The sections of the specification it tests, each as `<document> <section>`, such as `keys.md 2.3`        |
| `input`       | The input of the operation (section 5)                                                                   |
| `expected`    | The expected result (section 4)                                                                          |

A negative vector breaks one rule. Where a rule can be broken in several ways, such as the steps of the strict verification of [keys.md](keys.md), section 2.3, each way has a vector of its own.

### 3.2 Bytes

Bytes are written in one of two forms, wherever an input, an expected result or an answer holds bytes:

- a JSON string of lower-case hexadecimal digits, two for each byte, such as `"c301"`;
- for large values, an object with the members `deflate`, the bytes compressed with raw DEFLATE ([RFC 1951](https://www.rfc-editor.org/rfc/rfc1951)) in lower-case hexadecimal, `length`, the number of bytes it inflates to, and `sha256`, their SHA-256 in lower-case hexadecimal.

The vector files use the second form above 65,536 bytes, such as for a message of 16 MiB and one byte. Raw DEFLATE is the codec `deflate` of an AXT file ([envelope.md](envelope.md), section 4.2), so every library has it at hand. Two values are equal when their bytes are equal, whatever their form.

### 3.3 Decoded values

Where a result holds a decoded Avro value, such as a record of an example type or a manifest, the value is written in JSON as follows:

| Avro                        | JSON                                                                                                                      |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `null`, `boolean`, `string` | `null`, `true` or `false`, a string                                                                                       |
| `int`, `long`               | A number, the integer exactly; the vectors hold no integer above 2^53 in magnitude                                        |
| `float`, `double`           | A number, the shortest decimal that reads back to the value                                                               |
| `bytes`, `fixed`            | A string of lower-case hexadecimal digits                                                                                 |
| enum                        | The symbol, as a string                                                                                                   |
| array, map                  | An array; an object                                                                                                       |
| record                      | An object with one member for each field of the schema the value was read with                                            |
| union                       | The value of its branch; the vectors use only unions of `null` and one other type, so the branch is never in doubt        |
| a logical type              | The value of the underlying type: `timestamp-millis` as its `long`, `date` as its `int`, `uuid` as its string as received |

A record read through schema resolution has the fields of the reader schema. Objects compare without regard to the order of their members.

## 4. Results

A vector expects one of three results:

- `{"accept": value}`: the operation succeeds, with the value that section 5 defines for it, an empty object where there is nothing to return;
- `{"reject": {"error": code}}`: the operation fails with the error code; only the code is compared;
- `{"steps": [...]}`: the results of the steps of a session, one for each step, in the forms the operation defines.

### 4.1 What is compared

The runner compares the adapter's answer with the expected result as JSON values, with these rules:

- A member `note`, anywhere in an expected result or an answer, is for people and is not compared. The vectors use it to say why a negative vector fails, such as the step of [keys.md](keys.md), section 2.3, or the rule of [manifest.md](manifest.md), section 4, that it breaks.
- An expected value `{"one_of": [a, b, ...]}` is met by an answer equal to any of the values. The vectors use it where the specification leaves a choice, such as whether a request without a body carries `Content-Length: 0`, or whether a receiver reports a `MESSAGE` above 16 MiB or closes the connection ([transports.md](transports.md), section 4.4).
- Where the answer is a message the library writes, such as an `ACCEPT` in a session or a sealed message, the runner decodes it and compares its meaning (sections 5.5 and 5.6), since the specification does not fix the bytes of such a message.

### 4.2 Error codes

The codes of [protocol.md](protocol.md), section 8.2, are used wherever the specification names one, and the reasons `DOES_NOT_RESOLVE` and `DOES_NOT_FIT` of a `DECLINE` ([protocol.md](protocol.md), section 5.1) where a schema does not resolve ([envelope.md](envelope.md), section 6) or, in a file, a type does not fit ([manifest.md](manifest.md), section 7). Where the specification names a rejection but no code, the suite defines one:

| Code                     | The library rejected                                                                 | Specification                               |
| ------------------------ | ------------------------------------------------------------------------------------ | ------------------------------------------- |
| `KEY_INVALID`            | An Ed25519 public key that fails step 2 or 3 of the strict verification              | [keys.md](keys.md), section 2.3             |
| `ENCRYPTION_KEY_INVALID` | An X25519 public key of small order                                                  | [keys.md](keys.md), section 4.2             |
| `NOT_OPENED`             | A sealed message that does not begin with `01`, or that no private key opens         | [keys.md](keys.md), section 4.5             |
| `PADDING_INVALID`        | An opened plaintext that does not end with `80` followed only by zero bytes          | [keys.md](keys.md), section 4.5             |
| `FILE_REJECTED`          | A file rejected as a whole                                                           | [transports.md](transports.md), section 2.2 |
| `QR_INVALID`             | A QR text or payload that breaks a rule of [transports.md](transports.md), section 3 | [transports.md](transports.md), section 3   |
| `QR_VERSION_UNSUPPORTED` | A QR payload whose first byte is not `01`                                            | [transports.md](transports.md), section 3.1 |

## 5. Operations

Each operation is defined by its input and its result; the library performs it as the sections named say. Inputs and results are JSON objects; "Bytes" is a value of section 3.2, a key is Bytes of 32 bytes, and a schema text is the JSON text of an Avro schema, as a string.

### 5.1 encoding

| Operation        | Input                                                        | Result                                                                                                                                                                                                                                                                              |
| ---------------- | ------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `fingerprint`    | `schema`: a schema text                                      | `canonical_form`, the Parsing Canonical Form, and `fingerprint`, the CRC-64-AVRO as its 8 bytes in little-endian order ([envelope.md](envelope.md), section 5)                                                                                                                      |
| `decode_message` | `message`: Bytes of a live message                           | The envelope ([envelope.md](envelope.md), sections 2 and 3): `format`, `kind`, `sender`, `record` (`null`, or `id` and `version`), `body` and `signature`; or `TOO_LARGE`, `FORMAT_UNSUPPORTED` or `INVALID_MESSAGE`. Only the envelope is checked: not the signature, not the body |
| `decode_body`    | `kind`: a kind other than `DATA` and `DELETE`; `body`: Bytes | `value`, the body decoded with its kind's schema of format 1; or `INVALID_MESSAGE` for a body that is not a complete single-object encoding of that schema                                                                                                                          |
| `encode_message` | The members of a result of `decode_message`                  | `message`: the live message                                                                                                                                                                                                                                                         |

### 5.2 types

| Operation       | Input                                                                                                                                                     | Result                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `fingerprint`   | As in `encoding`, for the example types                                                                                                                   | As in `encoding`                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `decode_record` | `writer_schema`: a schema text; `reader_schema`: a schema text, or `null` to read with the writer schema alone; `body`: Bytes of a single-object encoding | `value`, the record read with the reader schema, or with the writer schema alone; or `SCHEMA_UNKNOWN` if the body's fingerprint is not that of the writer schema, `DOES_NOT_RESOLVE`, or `UNDECODABLE` for bytes cut short, bytes left over, a string that is not well-formed, a negative or impossible length, a time value that is not valid ([time.md](time.md), section 8), or a data depth above 32 ([types.md](types.md), section 5.7) |

### 5.3 records

`apply` is a session of one receiver and the records of one sender ([records.md](records.md), sections 5 to 7), starting from an empty state.

- **Input.** `policy`: `local_changes`, one of `per_field` (section 6.1 there), `whole_record_keep` and `whole_record_take` (section 6.2 there); `delete_with_local_changes`, `delete` or `keep` (section 6.4 there). `events`: the steps, each one of these objects:
  - `{"message": {"kind": "DATA", "id", "version", "type", "value"}}` or `{"message": {"kind": "DELETE", "id", "version"}}`: a record message of the sender; `type` is the full name of the record's type, `value` its fields as a JSON object;
  - `{"local_change": {"id", "field", "value"}}`: the receiver's user sets a field of a record;
  - `{"local_delete": {"id"}}`: the receiver's user deletes a record.
- **Result of each step.** For a message: `outcome`; `receiver_version`; `kept_fields`, the fields of `MERGED`, sorted; `state`, one of `there`, `tombstone` and `deleted_by_user`; and `value`, the record as the receiver now holds it, `null` unless `state` is `there`. Or `{"error": code}` with `RECORD_ID_INVALID`, `VERSION_INVALID` or `TYPE_CHANGED`, after which the state is unchanged. For a local change or deletion: `{}`.

A library that implements `records` offers each of these policies to the apps that use it.

### 5.4 manifest

| Operation        | Input                                                                                                                  | Result                                                                                                                                                                                 |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `check_manifest` | `body`: Bytes of the body of a `MANIFEST`; `envelope_format`: the format of the envelope that carries it               | `manifest`, the decoded manifest, if it is valid ([manifest.md](manifest.md), section 4); `MANIFEST_INVALID` if it is not; `INVALID_MESSAGE` for a body that is not an `axt.Manifest`  |
| `fit`            | `manifest`: Bytes of a valid body; `schema`: the schema text of a type; `languages`: the user's language priority list | `fits`, whether the type in its schema's version fits ([manifest.md](manifest.md), sections 3.4 and 5.2); `purpose`, the sentence chosen by the Lookup of section 3.6 there, or `null` |

### 5.5 keys

| Operation              | Input                                                              | Result                                                                                                                                                                                |
| ---------------------- | ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `public_key`           | `seed`: 32 bytes                                                   | `public_key` ([keys.md](keys.md), section 2.1)                                                                                                                                        |
| `sign`                 | `seed`; `data`: Bytes                                              | `signature`, the pure Ed25519 signature of `data` ([keys.md](keys.md), section 2.2)                                                                                                   |
| `verify`               | `public_key`; `data`; `signature`                                  | `{}` if the signature verifies by the strict rule of [keys.md](keys.md), section 2.3; otherwise `SIGNATURE_INVALID`                                                                   |
| `check_signing_key`    | `public_key`                                                       | `{}`, or `KEY_INVALID` for a key that fails step 2 or 3 of [keys.md](keys.md), section 2.3                                                                                            |
| `check_encryption_key` | `encryption_key`                                                   | `{}`, or `ENCRYPTION_KEY_INVALID` ([keys.md](keys.md), section 4.2)                                                                                                                   |
| `short_fingerprint`    | `public_key`                                                       | `short_fingerprint`, the five groups of digits ([keys.md](keys.md), section 3.1)                                                                                                      |
| `verify_message`       | `message`: Bytes of a well-formed live message                     | `{}` if its signature verifies with its `sender` over the bytes as received ([keys.md](keys.md), section 2.2); otherwise `SIGNATURE_INVALID`                                          |
| `key_move`             | `message`: Bytes of a `KEY_MOVE`                                   | `old_key`, `new_key` and `new_encryption_key` (or `null`), after the checks of steps 1 and 4 of [keys.md](keys.md), section 5.3; otherwise `SIGNATURE_INVALID` or `KEY_MOVE_REJECTED` |
| `padded_length`        | `length`: the length of a message                                  | `padded_length`, P(n) of [keys.md](keys.md), section 4.4                                                                                                                              |
| `seal`                 | `message`; `encryption_key`                                        | `sealed`, the message sealed as [keys.md](keys.md), section 4.3, says, with a fresh ephemeral key                                                                                     |
| `open`                 | `sealed`; `private_keys`: the X25519 private keys to try, in order | `message`, opened and unpadded ([keys.md](keys.md), section 4.5); or `NOT_OPENED` or `PADDING_INVALID`                                                                                |

A sealed message holds a random ephemeral key, so the runner does not compare it with fixed bytes. The expected result of `seal` is `{"accept": {"sealed": {"opens_with", "to", "length"}}}`: the runner checks that the answer has `length` bytes, begins with `01`, opens with the private key `opens_with` by HPKE ([RFC 9180](https://www.rfc-editor.org/rfc/rfc9180)) with the parameters of [keys.md](keys.md), section 4.1, to a plaintext of the padded length, and unpads to the message `to`.

### 5.6 protocol

`choose_format` takes `own` and `theirs`, two lists of envelope formats, and returns `format`, the chosen format of [protocol.md](protocol.md), section 3.2, or `null`.

`session` plays one app in one live connection that its user has opened with another app whose key the user has accepted ([protocol.md](protocol.md), sections 3 to 9 and 14). The adapter creates the app afresh for each session.

- **Input.** `app`: `seed`, the app's signing key; `manifest`, the body of its own `MANIFEST`; `formats`, the envelope formats it reads; `readers`, its reader schemas by full name, as schema texts; `user_takes`, the full names of the types its user takes when asked, every other type being `NOT_WANTED`; and `peer`, the key the other app proved in its `HELLO` ([transports.md](transports.md), section 4.5). `steps`: a list of objects of these forms:
  - `{"receive": Bytes}`: the app gets a live message. Answer: `outcome`, the outcome of a record message processed to one, or `null`; `close`, whether the app closes the connection; `replies`, the messages it sends in reply, as Bytes. After a rejection for which [protocol.md](protocol.md), section 8.3, lets an app close the connection, the vector accepts either value of `close`, and that step is the last of its session. The app sends no `ACK` here; it holds the acknowledgements it owes until a `flush_acks` step.
  - `{"flush_acks": true}`: the app sends the acknowledgements it owes. Answer: `replies`, the `ACK` messages.
  - `{"offer": {"offer_id", "types": [{"schema", "count"}]}}`: the app offers the types, with the schema texts as given and in that order. Answer: `message`, the `OFFER`.
  - `{"close": true}`: the connection ends ([protocol.md](protocol.md), section 4.3). Answer: `{}`. The steps after it are those of a new connection between the same two apps, which starts again with the other app's `MANIFEST`; the app keeps what it keeps across connections, such as the records it has taken and the outcomes it has got.
  - `{"query": {"accepted": full name}}`, `{"query": {"outcome": {"id", "version"}}}`, `{"query": {"record": id}}` or `{"query": {"errors": true}}`: what the app holds. Answer: `accepted`, whether it has an accepted offer of the type; `outcome`, the outcome it takes for a record message it sent, or `null`; `record`, the `version` and `state` (`there` or `tombstone`) it keeps of a record of the other app, or `null`; `errors`, the codes of the `ERROR` messages about its own messages that it has taken, in order.
- **Expected result.** For each step, the meaning of the answer. The runner decodes every message in `replies` and `message`, and fails the vector if one is not a live message of envelope format 1 whose `sender` is the key of `seed`, whose signature verifies, whose body is its kind's schema, and whose `to` is `peer`. It then compares:
  - for `receive`: `outcome`; `close`; `answers`, the verdict on each type by offer id, `ACCEPT` or the reason of the `DECLINE`, gathered from all replies, so that a library may answer the types of one offer in one message or in several ([protocol.md](protocol.md), section 5.2); and `errors`, the `ERROR` replies in order, each in the members the vector lists: `code`, `message_hash` and `fingerprint` always, and `record` only where the order of the checks of [protocol.md](protocol.md), section 8.2, fixes whether the signature was verified before the failure;
  - for `flush_acks`: `acks`, the entries of all `ACK` replies, in any order;
  - for `offer`: `offer`, the `to`, `offer_id` and `types` of the `OFFER`;
  - for `close` and `query`: the answer as it is.

### 5.7 file

`read_file` reads an AXT file as [transports.md](transports.md), section 2.2, says, as a reader whose user has accepted the file's sender and that holds no record of it yet.

- **Input.** `file`: Bytes; `reader`: `manifest`, the body of the reader's own `MANIFEST`, and `readers`, its reader schemas by full name.
- **Result.** `FILE_REJECTED` for a file rejected as a whole. Otherwise: `sender`, the key in `axt.sender`; `key_moves`, the key moves at its start, each as `from` and `to`; `manifest`, `none` for a file without a `MANIFEST`, `invalid` for one that is not valid and so not used, `used` otherwise; and `records`, one entry for each `DATA` and `DELETE` in the order of the file, with its `id`, `version` and `result`: the outcome (`APPLIED`, `DUPLICATE` or `STALE`), or why it was not applied (`RECORD_ID_INVALID`, `VERSION_INVALID`, `DOES_NOT_FIT`, `TYPE_CHANGED`, `DOES_NOT_RESOLVE` or `UNDECODABLE`).

### 5.8 qr

| Operation  | Input                         | Result                                                                                                                                     |
| ---------- | ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `parse_qr` | `text`: the text of a QR code | `payload`, the decoded `axt.QrPayload` ([transports.md](transports.md), sections 3.1 and 3.2); or `QR_VERSION_UNSUPPORTED` or `QR_INVALID` |
| `qr_text`  | `payload`: Bytes              | `text`: `AXT:` and the payload in base32, in upper case and without padding                                                                |

### 5.9 local

`hello_frame` takes `seed`, `role` (`client` or `server`) and `certificate_sha256`, the SHA-256 of the server's certificate, and returns `frame`, the `HELLO` frame ([transports.md](transports.md), section 4.5).

`connection` is a session of one end of a connection after its TLS handshake ([transports.md](transports.md), sections 4.4 to 4.6). Its input is `role`, the role of this end; `certificate_sha256`; `expected_key`, the `signing_key` of a scanned QR code, or `null`; and `frames`, the frames the other end sends, each as Bytes, after which it ends the connection. A frame shorter than its length says is one cut short by that end. The result has one entry for each frame until the connection closes: `open` for a `HELLO` that is verified, `message` for a `MESSAGE` taken, `ping`, `too_large` for a `MESSAGE` above 16 MiB that is skipped and reported, and `close` when this end closes the connection or discards the frame, after which no frame is processed and no entry follows.

### 5.10 relay

| Operation    | Input                                                                                                                                                                                                               | Result                                                                                                                                                                                                                                                                     |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mailbox_id` | `secret`: a mailbox secret                                                                                                                                                                                          | `mailbox`, the mailbox id ([transports.md](transports.md), section 5.1)                                                                                                                                                                                                    |
| `request`    | `action`: `create`, `remove`, `put`, `list`, `fetch` or `delete`; `base_url`; `secret` for an owner's action; `mailbox` and `message` for `put`; `message_id` for `fetch` and `delete`; `wait` or `null` for `list` | `method`; `url`, the base URL, the path of [transports.md](transports.md), section 5.2, and the query of a list; `headers`, the values of `authorization`, `content_type` and `content_length`, each `null` where the request does not carry it                            |
| `reaction`   | `request`, an action as above; `status`, the response's status code, or `null` for a network failure; `retry_after`, seconds or `null`; `attempt`, how often the request has been sent                              | `action`: `done`; `stop`, the app does not repeat the request, or stops putting into the mailbox; `repeat`; or `create_mailbox`, the owner creates its mailbox again. `wait`: the seconds before a repeat, or `null` ([transports.md](transports.md), sections 5.2 to 5.4) |
| `listing`    | `body`: the JSON text of the response to a list                                                                                                                                                                     | `messages`: the `id` and `size` of each message, in order, without the members the app does not know                                                                                                                                                                       |

### 5.11 relay-server

`relay` is a session of one relay with empty storage and a clock the test sets. Its input is `base_url`; `quota_bytes`, the room of a mailbox, for the case of a full mailbox; and `requests`, each with `method`, `target` (the path after the base URL, with its query), `headers`, `body` (Bytes) and `now`, the relay's clock in seconds. The result has one entry for each request: `status`, and for a successful list `messages`, for a successful fetch `message`.

### 5.12 time

`fingerprint` and `decode_record` are as in `encoding` and `types`, for the time types and for a type that holds them ([time.md](time.md), section 3.1). A `DateTime` and a `Duration` in the input and the result are values of `axt.DateTime` and `axt.Duration` in the form of section 3.3.

| Operation           | Input                                                           | Result                                                                                                                                           |
| ------------------- | --------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `resolve_date_time` | `date_time`: a valid `DateTime`; `anchor`: `local` or `instant` | `date_time`, the value as a receiver with the zone rules of the vectors takes it, for a field with that anchor ([time.md](time.md), section 6.4) |
| `add_duration`      | `date_time`: a valid `DateTime`; `duration`: a valid `Duration` | `date_time`, the sum ([time.md](time.md), section 7.2)                                                                                           |

The zone rules of the vectors are those of the IANA time zone database 2026e. The vectors that need zone rules use only `Europe/Berlin` in 2026 and 2027, and a zone the database does not have.

## 6. The adapter

An adapter is a program that the runner starts and talks to over its standard input and output: one line of JSON, in UTF-8, in each direction for each request. It writes nothing else to its standard output, and it answers each request before it reads the next.

1. The runner's first request is `{"id": "hello", "op": "hello", "input": {"format": 1}}`, where `format` is the version of the vector file format. The adapter answers `{"id": "hello", "output": {"name": ..., "categories": [...]}}`, with the name of its library and the categories that library implements (section 2.2).
2. For each vector of those categories, the runner sends `{"id": vector id, "op": operation, "input": input}`. It never sends the expected result.
3. The adapter answers `{"id": the same id, "output": result}`, with a result of a form of section 4: `{"accept": ...}`, `{"reject": {"error": ...}}` or `{"steps": [...]}`. An adapter MUST accept both forms of Bytes of section 3.2 in its input, and MAY use either in its answer.
4. An adapter that cannot perform an operation answers `{"id": ..., "unsupported": true}`; one that fails for a fault of its own answers `{"id": ..., "failure": text}`. Both fail the vector.
5. When the runner closes the adapter's standard input, the adapter ends.

An adapter does what an app would do with its library, with the keys and values in the request. It holds no key of its own and keeps no state from one vector to the next.

## 7. The suite

### 7.1 The runner

[conformance/run.py](../conformance/run.py) runs the vectors against an adapter:

```text
python3 conformance/run.py [--vectors DIR] [--category NAME ...] [--verbose] -- ADAPTER COMMAND ...
```

It checks every vector file against the schema, starts the adapter, and sends the vectors of the categories the adapter implements, file by file and in the order of each file. It reports each vector that fails and, for each category, how many vectors passed, and it names the categories the adapter does not implement as not run. It exits with 0 only when every vector it ran passed. It needs Python 3.10 or later, fastavro to decode the messages an adapter writes, and the package cryptography to open what an adapter seals.

### 7.2 The reference adapter

[conformance/reference/adapter.py](../conformance/reference/adapter.py) answers every operation of every category with the code of the scripts in [conformance/tools/](../conformance/tools/), which produce and check the examples of the specification, and, where those scripts have no model, for a receiver's own changes to records and for reading a file, with code of its own. It passes every vector. This shows that the vectors agree with each other and with the scripts' checks of the examples. The reference adapter is not a library and is not meant for apps.

### 7.3 How the vectors are made

[conformance/tools/generate_vectors.py](../conformance/tools/generate_vectors.py) writes the vector files. It builds every vector with the code of the scripts in [conformance/tools/](../conformance/tools/) that produce and check the examples of the other documents, so that a vector and an example are made in the same way:

- Where a script has a model, such as the model of an app of `protocol_examples.py`, the frames and the relay of `transports_examples.py`, the validity rules of `manifest_examples.py`, or the validity, zone rules and addition of `time_examples.py`, the expected result is the model's, and the generator checks it against what the script itself expects of the case.
- Where no script has a model, for the records of section 5.3 and the files of section 5.7, the expected results are written out in the generator from [records.md](records.md), sections 5 to 9, and the table of [transports.md](transports.md), section 2.2, and the reference adapter reaches them with code of its own.
- Every key, secret and certificate is a test value of [keys.md](keys.md), section 7.1, or derived in the same way. **They are for tests only and MUST NOT be used outside tests.**

The generator's output is the same in every run and under every value of Python's `PYTHONHASHSEED`. With `--check`, it compares its output with the files in `vectors/` instead of writing them, so that the committed vectors stay those the code produces; it compares a value in the form of raw DEFLATE by its length and SHA-256, since the compressed bytes depend on the zlib that writes them. The files with the codec `deflate` use stored DEFLATE blocks, which every implementation writes in the same way. It checks the counts that the other documents name: the 10 signatures of [keys.md](keys.md), section 7.6; the 43 invalid manifests of [manifest.md](manifest.md), section 9; the 58 cases of [protocol.md](protocol.md), section 16; the 13 edges, 29 values that are not valid and 16 additions of [time.md](time.md), section 9; and the 20 invalid QR payloads and texts, the 15 frames that close a connection and the 28 requests to a relay of [transports.md](transports.md), section 6.

### 7.4 The vectors of 0.1.0

| Category       | Vectors | Of them                                                                                                                                                                                                                              |
| -------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `encoding`     | 65      | 16 fingerprints; 30 envelopes, 13 that decode, one of each kind among them and one of exactly 16 MiB, and 17 rejected; 14 bodies; 5 encodings                                                                                        |
| `types`        | 44      | 8 fingerprints; 36 records: one of each example type, every default and unknown enum symbol through schema resolution, an alias, array blocks, the data depth limit, and 11 rejected                                                 |
| `time`         | 84      | 4 fingerprints; 56 records: the 12 values of [time.md](time.md), section 9.2, 13 edges, 29 values that are not valid, and a type that holds the time types, once valid and once not; 8 readings under other zone rules; 16 additions |
| `records`      | 12      | Sessions: the example of [records.md](records.md), section 9, with both choices for a deletion; tombstones; a record its user deleted; both whole-record choices; ids; the errors                                                    |
| `manifest`     | 71      | 6 valid manifests, the 43 invalid ones, 3 bodies that are not a manifest, 19 cases of fit and language                                                                                                                               |
| `keys`         | 85      | Test keys and signatures; the 10 edges of [keys.md](keys.md), section 7.6; 15 signing keys and 10 encryption keys checked; messages and key moves verified; padding; sealing; opening                                                |
| `protocol`     | 26      | 3 choices of the format; 23 sessions with the exchange of [protocol.md](protocol.md), section 17, and its 58 further cases, each rejection after which an app may close the connection in a session of its own                       |
| `file`         | 45      | 14 files read and 31 rejected: the rows of the table of [transports.md](transports.md), section 2.2, and each rule of a file's header and structure                                                                                  |
| `qr`           | 28      | 5 texts that decode, the 20 that do not, 3 encodings                                                                                                                                                                                 |
| `local`        | 21      | 2 `HELLO` frames; 4 connections that stay open, and the 15 that close                                                                                                                                                                |
| `relay`        | 40      | 2 mailbox ids, 7 requests, 28 reactions to a response, 3 lists                                                                                                                                                                       |
| `relay-server` | 2       | Sessions of the 28 requests of [transports.md](transports.md), section 6, and of a full mailbox                                                                                                                                      |

## 8. What the vectors do not test

Some rules cannot be tested with bytes and an expected result, and are left to a library's own tests:

- the TLS handshake of [transports.md](transports.md), section 4.3, discovery by DNS-SD (section 4.2 there), and the timers of liveness and of the protocol ([protocol.md](protocol.md), section 12);
- what an app shows its user and asks it, such as a first contact, a key move, or an outcome that waits for the user ([keys.md](keys.md), section 3.2; [protocol.md](protocol.md), section 7.3);
- the state a receiver keeps across connections and through a relay: known senders and their moved-from keys, kept manifests and their revisions, offers that stay open through a relay, and the random jump of versions after a restore ([protocol.md](protocol.md), section 10);
- a file above 256 MiB, and the data of a file above 1 GiB after decompression, which the vector files would have to hold ([envelope.md](envelope.md), section 8).

## References

- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174): key words for requirement levels
- [RFC 1951](https://www.rfc-editor.org/rfc/rfc1951): DEFLATE
- [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259): JSON
- [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180): Hybrid Public Key Encryption
- [JSON Schema 2020-12](https://json-schema.org/draft/2020-12)
