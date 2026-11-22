# Transports

Status: released in 0.1.0. A change to this document is a new version of AXT, with its entry in [CHANGELOG.md](../CHANGELOG.md).

This document defines the three ways in which two apps reach each other: a file sent through any messenger, a connection on the local network, and a relay. For the file, it defines which messages a file holds and in which order, and what a reader rejects. For the local network, it defines the QR code that carries an app's key and address, discovery, the TLS connection, the frames on it, the HELLO that authenticates both apps' keys, liveness and the end of a connection, and the connection in which a new device joins the devices of its owner. For the relay, it defines mailboxes and the relay's HTTP interface, the holding time, limits, and what a relay may log.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 ([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119), [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)) when, and only when, they appear in all capitals, as shown here.

## 1. Terms

- **Transport**: one of the three ways of this document by which messages travel between two apps.
- **Live connection**: a connection on the local network (section 4). It is a channel in the sense of [protocol.md](protocol.md), section 1.
- **Server** and **client**: on the local network, the app that listens and the app that connects to it. The roles matter for TLS and the `HELLO` only; the protocol above them is the same for both apps.
- **Connection key**: the signing key that the other app proved with its `HELLO` (section 4.5).
- **Relay**: an HTTP service that holds sealed messages ([keys.md](keys.md), section 4) in mailboxes until their owners fetch them. It is a channel in the sense of [protocol.md](protocol.md), section 1.
- **Mailbox**: the place at a relay where the messages for one installation, its **owner**, wait (section 5.1).
- **Holding time**: how long a relay holds a message, 14 days (section 5.5).

AXT does not require an app to support every transport. An app that exchanges on the local network shows or scans the QR code of section 3; an app that takes messages through a relay names its relay in its manifest ([manifest.md](manifest.md), section 3.10).

## 2. File

An AXT file is an Avro object container file of `axt.Envelope` datums ([envelope.md](envelope.md), section 4) with a signed header ([keys.md](keys.md), section 2.5). It travels as a file through any messenger, mail or file share. The media type and the file extension are those of [envelope.md](envelope.md), section 9; a reader identifies a file by its content, not by its name.

### 2.1 What a file holds

A file holds, in this order:

1. zero or more `DEVICE_ADD` and `DEVICE_REMOVE` messages: the chain of the device that writes the file ([keys.md](keys.md), section 5.4), oldest first;
2. at most one `MANIFEST`, the writer's own ([manifest.md](manifest.md), section 7);
3. zero or more record messages, `DATA`, `DELETE` and `WITHDRAW`, in any order. A file holds a `WITHDRAW` only when it is meant for the receiver from which its writer withdraws the record, whose key is its `to` ([shares.md](shares.md), section 8.2).

A file MUST NOT hold `OFFER`, `ACCEPT`, `DECLINE`, `ACK`, `ERROR` or `DEVICE_JOIN` messages. They are bound to one exchange or one connection and need a way back to their sender, which a file does not have ([protocol.md](protocol.md), section 15.2). A file MUST NOT hold `CHANGE`, `RESYNC` or `FORWARD` messages either: they travel between the devices of one set, on the local network and through the relay only ([sync.md](sync.md), sections 13.3 and 24.2). Nor does it hold `PROPOSAL` or `PROPOSAL_REPLY` messages: a proposal needs a way back for its reply, and a reply is for the one device that sent the proposal ([shares.md](shares.md), section 18.2). A file holds whole records, also when a device reads a file of its own set ([sync.md](sync.md), section 13.4).

Every message of a file MUST be from the file's sender, the key in `axt.sender`, apart from the `DEVICE_ADD` and `DEVICE_REMOVE` messages at its start ([keys.md](keys.md), section 2.5): one sender per file. A file that only carries its writer's manifest, for example to introduce the writer for exchanges through a relay (section 2.3), holds no record message; a reader MUST NOT reject a file for that.

### 2.2 Reading a file

A reader MUST check the whole file before it applies any record from it, since it MUST NOT apply any record from a file it rejects ([envelope.md](envelope.md), section 8). A failure either rejects the whole file, or only the message that fails:

| The reader finds                                                                                                                                                                                                                                                            | Result                                                           | Rule                                                |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- | --------------------------------------------------- |
| Bytes that are not an Avro object container file, a codec other than `null` or `deflate`, or an `avro.schema` that is not a supported envelope format                                                                                                                       | The whole file is rejected                                       | [envelope.md](envelope.md), sections 4.1 and 4.2    |
| A file, a block or the decompressed data above a size limit                                                                                                                                                                                                                 | The whole file is rejected                                       | [envelope.md](envelope.md), section 8               |
| A header signature that is missing, not lower-case hexadecimal of the right length, or does not verify                                                                                                                                                                      | The whole file is rejected                                       | [keys.md](keys.md), section 2.5                     |
| An entry of `axt.schemas` whose description is not valid or whose schema is not the one derived from it ([fields.md](fields.md), section 10.2), two schemas with one fingerprint in it, or a `DATA` whose body fingerprint is not in it                                     | The whole file is rejected                                       | [envelope.md](envelope.md), sections 4.1 and 4.3    |
| A datum that is not a valid message of its kind: bytes left over, a `format` that is not the file's format, a `record` where none belongs or none where one is required, a body fingerprint that is not its kind's                                                          | The whole file is rejected                                       | this section; [protocol.md](protocol.md), section 2 |
| A message whose signature does not verify                                                                                                                                                                                                                                   | The whole file is rejected                                       | this section                                        |
| An `OFFER`, `ACCEPT`, `DECLINE`, `ACK`, `ERROR`, `DEVICE_JOIN`, `CHANGE`, `RESYNC`, `FORWARD`, `PROPOSAL` or `PROPOSAL_REPLY`                                                                                                                                               | The whole file is rejected                                       | section 2.1                                         |
| A message whose `sender` is not the key in `axt.sender`, other than a `DEVICE_ADD` or a `DEVICE_REMOVE` at the start                                                                                                                                                        | The whole file is rejected                                       | [keys.md](keys.md), section 2.5                     |
| A `DEVICE_ADD` or a `DEVICE_REMOVE` after another kind of message, or a message that fails step 2 of [keys.md](keys.md), section 5.5: a `DEVICE_ADD` with a key of the new device that is not valid or a proof that does not verify, or a `DEVICE_REMOVE` of its own signer | The whole file is rejected                                       | [keys.md](keys.md), sections 5.4 and 5.5            |
| A `DEVICE_ADD` or a `DEVICE_REMOVE` that step 3 or the table of [keys.md](keys.md), section 5.5, has the reader ignore or reject: a repeat, an unknown signer, a signer or a device that the reader's state does not allow                                                  | That message is not applied                                      | [keys.md](keys.md), section 5.5                     |
| A key in `axt.sender` that is, after the chain, a removed key of a known sender                                                                                                                                                                                             | No record of the file is applied, and its `MANIFEST` is not used | [keys.md](keys.md), sections 3.3 and 5.5            |
| A second `MANIFEST`, or a `MANIFEST` after a record message                                                                                                                                                                                                                 | The whole file is rejected                                       | section 2.1                                         |
| A `MANIFEST` that is not valid ([manifest.md](manifest.md), section 4)                                                                                                                                                                                                      | The reader does not use it                                       | this section                                        |
| A record message that fails step 2, 3, 6, 8 or 9 of [protocol.md](protocol.md), section 6.2: an invalid id or version, a changed type, a body that does not decode, a value that is not valid                                                                               | That message is not applied                                      | [protocol.md](protocol.md), section 15.2            |
| A `WITHDRAW` whose `to` is not a current or a removed key of the reader's own set                                                                                                                                                                                           | That message is not applied; the file is not rejected for it     | [shares.md](shares.md), section 8.2                 |
| A `WITHDRAW` in a file whose sender is the reader's own set                                                                                                                                                                                                                 | That message is not applied                                      | [shares.md](shares.md), section 8.2                 |
| A record whose type does not fit the reader's manifest                                                                                                                                                                                                                      | That record is not applied                                       | [manifest.md](manifest.md), section 7               |

What makes a file unreadable as a whole, or what a writer cannot have produced honestly, rejects the whole file: a message whose signature does not verify has been damaged or changed after its writer signed it, and nothing else in the file can be relied on then. A record message that its writer signed but that the reader cannot apply is the writer's fault in that one record; the other records are applied, as [protocol.md](protocol.md), section 15.2, says. An invalid `MANIFEST` is not used, as in a live connection ([protocol.md](protocol.md), section 3.1), and does not keep the records from being applied.

A reader confirms the file's sender before it applies any record ([keys.md](keys.md), section 3.2), unless the key in `axt.sender` is a current key of a sender it knows, as it is or by the chain at the start of the file ([keys.md](keys.md), section 5.5). A file whose sender is the reader's own device set is read as [sync.md](sync.md), section 13.4, says. A reader that is one device of a set passes what it took from a file of another app on to the other devices of its set, so the owner opens the file on one device only ([sync.md](sync.md), section 24.2). It sends nothing back: a file has no acknowledgement and no error report ([records.md](records.md), section 7). A reader SHOULD tell its user how many record messages of a file it did not apply, and why.

### 2.3 Writing a file

- **One record, one message.** A writer MUST put at most one message of each record id into a file: the one with the highest version the writer has given the record, a `DATA` for a record that exists and a `DELETE` for one it deleted. A file meant for an app of another user holds instead what the writer owes that app of each record: a `DATA` or a `DELETE` of a record shared with it, a `WITHDRAW` of one withdrawn from it, and nothing of any other record ([shares.md](shares.md), sections 5.3 and 8.2). A file is written for a receiver or for no particular one. A file for no particular receiver, such as an export, holds only the records that the user chose for it: that choice is its share, the file is treated as going to an app of another user, and it holds no `WITHDRAW` ([shares.md](shares.md), sections 2.2 and 8.2). Older versions of the record would only make the file longer. A reader MUST NOT reject a file because it holds several messages of one id; it applies them by the version rule, which gives the same result in any order ([records.md](records.md), section 5.2).
- **The manifest.** A writer MAY put its `MANIFEST` into any file. It SHOULD do so in a file meant for an app it wants to exchange with afterwards, since the reader needs the writer's manifest to send anything back ([manifest.md](manifest.md), section 7). It SHOULD NOT put a `MANIFEST` that names a relay into a file meant for anyone, such as an export or a file it publishes: everyone who holds the file learns the mailbox and can put messages into it (section 5.6).
- **The chain.** A writer that has a chain MUST begin every file with it, so that a reader that knows the writer's device set by another key takes the file for the same sender's ([keys.md](keys.md), section 5.4).
- **Records.** A writer that knows the manifest of the app a file is meant for puts only types into the file that fit it ([manifest.md](manifest.md), section 7).

## 3. QR code

An app shows a QR code so that another app can learn its signing key in person, and reach it on the local network, through a relay, or both. The code carries a text (section 3.2) that holds a payload (section 3.1).

### 3.1 Payload

The payload is the byte `01`, the payload version, followed by one datum of the record `axt.QrPayload` in Avro binary encoding, with the schema [types/axt/QrPayload.avsc](../types/axt/QrPayload.avsc):

| Field             | Avro type                                                   | Content                                                                                                                |
| ----------------- | ----------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `signing_key`     | `fixed` of 32 bytes, `axt.QrPayloadSigningKey`              | The Ed25519 public key of the installation that shows the code ([keys.md](keys.md), section 2.1)                       |
| `encryption_key`  | `null` or `fixed` of 32 bytes, `axt.QrPayloadEncryptionKey` | Its X25519 public key for messages through a relay ([keys.md](keys.md), section 4.2), or `null`                        |
| `local`           | `null` or `axt.QrPayloadLocal`                              | Where it listens on the local network while it shows the code (section 4.1), or `null`                                 |
| `local.addresses` | array of `bytes`                                            | One to four IP addresses, 4 bytes for IPv4 or 16 bytes for IPv6, in network byte order, in the order to try            |
| `local.port`      | `int`                                                       | The TCP port, 1 to 65535                                                                                               |
| `relay`           | `null` or `axt.QrPayloadRelay`                              | The relay and the mailbox for messages to it (section 5.1), as in the manifest's `relay`, or `null`                    |
| `relay.url`       | `string`                                                    | The base URL of the relay (section 5.2), at most 256 bytes                                                             |
| `relay.mailbox`   | `fixed` of 32 bytes, `axt.QrPayloadRelayMailbox`            | The mailbox id (section 5.1)                                                                                           |
| `join`            | `boolean`                                                   | `true` for a join code, shown to a new device of the same owner (section 4.7); `false` for a code shown to another app |

A payload is valid when:

- the first byte is `01`, and the rest is exactly one `axt.QrPayload` datum, with no bytes left over;
- `signing_key` passes steps 2 and 3 of [keys.md](keys.md), section 2.3;
- `encryption_key` is `null` or an X25519 key that is not of small order ([keys.md](keys.md), section 4.2);
- `encryption_key` and `relay` are both present or both `null`, as in a manifest ([manifest.md](manifest.md), section 3.10);
- `local`, if present, has 1 to 4 addresses of 4 or 16 bytes each and a port from 1 to 65535;
- `relay.url`, if present, meets the rule of section 5.2;
- `local` is present if `join` is `true`: a device joins on the local network (section 4.7);
- the payload has at most 432 bytes, the length of a payload with every field present and at its largest and its array in one block; the length limit of the text (section 3.2) ensures it. Avro lets an array be written in several blocks, so a payload of valid fields could otherwise be longer.

A code with the signing key alone, without `local` and `relay`, is valid: it serves to compare a key in person.

- **Versions.** A scanner that finds another first byte than `01` MUST NOT decode the rest, and SHOULD tell its user that the code is from a later version of AXT. A later payload schema comes with a new payload version.
- **Not signed.** The payload carries no signature. Whoever shows a code could sign it with its own key, so a signature would prove nothing about the key. What makes a scanned key trustworthy is that the user scans the code in person from the other device ([keys.md](keys.md), section 3.2).
- **Avro and one byte.** Every AXT app has an Avro decoder already. A version byte takes less room in the code than the 10 bytes of a single-object header, and the payload is not a message, so its schema need not be named by a fingerprint.

### 3.2 Text

The text of the code is `AXT:` followed by the payload in base32 ([RFC 4648, section 6](https://www.rfc-editor.org/rfc/rfc4648#section-6)), with upper-case letters and without padding. Every character of it, the letters A to Z, the digits 2 to 7 and the colon, is one of the alphanumeric mode of QR codes (ISO/IEC 18004). An app SHOULD encode the text in alphanumeric mode with the error correction level M.

A scanner:

- MUST accept the scheme and the letters of base32 in either case, since URI schemes are case-insensitive ([RFC 3986, section 3.1](https://www.rfc-editor.org/rfc/rfc3986#section-3.1));
- MUST reject a text with any other character, with padding, with a length that base32 cannot produce, or whose last character carries bits that are not zero, so that every payload has exactly one text;
- MUST reject a text longer than 696 characters, the text of the largest valid payload, before it decodes it.

The text is a URI with the scheme `axt`, so that a phone's camera can hand it to the app registered for the scheme. [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986) recommends lower-case schemes; `AXT:` is written in upper case because lower-case letters are not in the alphanumeric mode. Base32 in alphanumeric mode takes 8.8 bits of the code for each byte of the payload; base64 would need the byte mode and 10.7 bits. The payload of section 7.2 gives a text of 232 characters, which fits a code of version 9. The scheme `axt` is not registered with IANA ([RFC 7595](https://www.rfc-editor.org/rfc/rfc7595)) yet; apps use it as defined here until it is.

### 3.3 Scanning

An app that scans a valid code whose `join` is `false`:

- takes `signing_key` as the other app's key, confirmed by its user in person; it MAY remember the key without asking again ([keys.md](keys.md), section 3.2);
- takes `encryption_key` and `relay`, if present, as the other app's until a valid `MANIFEST` of that app brings its own, by the rule that the latest source wins ([keys.md](keys.md), section 4.2);
- connects to `local`, if present, as the client (section 4.1), and MUST close the connection unless the server's `HELLO` carries `signing_key` (section 4.5);
- otherwise, if `relay` is present, sends its `MANIFEST` through the relay ([protocol.md](protocol.md), section 15.1).

The app that showed the code learns the scanner's key from the scanner's `HELLO` or from its first message through the relay, and meets it as a first contact ([keys.md](keys.md), section 3.2). An app SHOULD show its code only while its user asks for it. A code shows the mailbox id, so a photo of it lets anyone put messages into the mailbox (section 5.6).

A code whose `join` is `true` is a join code: it is not for another app, but for a new device of the same owner (section 4.7). An app acts on a join code only when its user has asked it to join the devices of the app that shows the code. An app that scans one otherwise MUST NOT connect and MUST NOT take the key as another app's, and SHOULD tell its user that the code adds a device.

## 4. Local network

### 4.1 Listening and connecting

An app that shows a code with `local`, or advertises itself (section 4.2), listens on a TCP port of its choice on its addresses in the local network; it is the server. The app that connects to it is the client.

- An app SHOULD listen only while its user has asked to exchange on the local network, such as while it shows its code, and SHOULD NOT listen on an address that is reachable from outside the local network.
- A client that scans a code tries its addresses in their order and uses the first connection that opens (section 4.6).
- A client MAY also connect without a code, to an address found by discovery (section 4.2) or entered by its user. It then meets the server's key from the server's `HELLO` as a known sender or as a first contact ([keys.md](keys.md), section 3.2).

### 4.2 Discovery

An app MAY advertise itself with DNS-Based Service Discovery ([RFC 6763](https://www.rfc-editor.org/rfc/rfc6763)) over Multicast DNS ([RFC 6762](https://www.rfc-editor.org/rfc/rfc6762)):

- The service type is `_axt._tcp`. The SRV record gives the port; the TXT record holds the single entry `txtvers=1`.
- The instance name is chosen by the app. Everyone on the network sees it, so it SHOULD NOT name the user or the device unless the user has chosen it, and MUST NOT carry the signing key or anything derived from it, which would let an observer follow the device from network to network.
- An app SHOULD advertise only while its user has asked to exchange on the local network.
- A browsing app MUST identify the app it connects to by the key of its `HELLO` alone, never by the instance name.

Discovery is not needed for a first contact, which the code provides. It lets two apps that know each other's keys find each other again after an address has changed, without a new code. The service name `axt` is not registered with IANA ([RFC 6335](https://www.rfc-editor.org/rfc/rfc6335)) yet.

### 4.3 TLS

The connection is TLS 1.3 ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)) over TCP.

- **Version.** Both apps MUST use TLS 1.3 and MUST NOT negotiate an earlier version. TLS 1.3 encrypts the server's certificate, completes its handshake in one round trip, and uses an ephemeral key exchange in every full handshake.
- **ALPN.** The client MUST offer the protocol id `axt/1` in Application-Layer Protocol Negotiation ([RFC 7301](https://www.rfc-editor.org/rfc/rfc7301)), and the server MUST select it. Either app closes a connection in which `axt/1` was not selected. A later version of section 4 comes with another id.
- **Server name.** The client sends no Server Name Indication: it connects to an IP address, which SNI cannot carry ([RFC 6066, section 3](https://www.rfc-editor.org/rfc/rfc6066#section-3)).
- **The server's certificate.** The server presents a self-signed X.509 certificate ([RFC 5280](https://www.rfc-editor.org/rfc/rfc5280)) of an ECDSA key on the curve P-256, generated with a cryptographically secure random number generator, and signs the handshake with `ecdsa_secp256r1_sha256`. It SHOULD generate a new key and certificate each time it starts to listen, and SHOULD NOT store the private key. The key serves the connection only; it is not the signing key.
- **What the client checks.** The client MUST NOT validate the certificate against any trust anchor, and MUST NOT reject it for its names, dates or extensions. It takes the end-entity certificate, the first of the server's Certificate message, as received; only its SHA-256 matters (section 4.5). The TLS handshake itself proves that the server holds the certificate's private key.
- **No client certificate.** The server MUST NOT request a client certificate. The client is authenticated by its `HELLO`.
- **No resumption.** Both apps MUST NOT resume a session and MUST NOT send 0-RTT data. Every connection has a full handshake, in which the server presents its certificate.

**Why a key of its own.** [RFC 8446, section 9.1](https://www.rfc-editor.org/rfc/rfc8446#section-9.1), requires every TLS 1.3 implementation to support certificates and handshake signatures with ECDSA on P-256; Ed25519 is optional there. A certificate of the signing key would also need a TLS library that can sign with the signing key, also where it is kept in a device's protected key store ([keys.md](keys.md), section 5.8). With a key of its own, the connection works with any TLS 1.3 library, and the signing key signs nothing but the prefixed bytes of [keys.md](keys.md), section 2.2, and of section 4.5. The `HELLO` binds the signing keys of both apps to the connection.

### 4.4 Frames

After the TLS handshake, each direction of the connection is a sequence of frames. A frame is a type of one byte, a length of 4 bytes as an unsigned integer in big-endian order, and a payload of that length:

| Type | Name      | Payload                                                                         |
| ---- | --------- | ------------------------------------------------------------------------------- |
| `01` | `HELLO`   | 96 bytes: a signing key and a signature (section 4.5)                           |
| `02` | `MESSAGE` | One live message ([envelope.md](envelope.md), section 3), 1 to 16,777,216 bytes |
| `03` | `PING`    | Empty (section 4.6)                                                             |

- An app MUST close the connection when it gets a frame of another type, a `HELLO` whose length is not 96, a `PING` with a payload, or a `MESSAGE` of length 0.
- A `MESSAGE` whose length is above the message limit of 16 MiB ([envelope.md](envelope.md), section 8) is not held in memory. The receiver either discards its payload as it arrives and reports it with `TOO_LARGE` ([protocol.md](protocol.md), section 8.2), whose `message_hash` is the SHA-256 of the discarded payload, or closes the connection.
- The frame is what [envelope.md](envelope.md), section 3, leaves to the transport: the boundaries of each message. A `MESSAGE` carries exactly one message.
- Frames are not messages. They are not signed, have no envelope, and are never answered. TLS protects them.

The type tells the `HELLO` and the `PING` apart from messages without a new envelope kind, which only a new envelope format could bring ([envelope.md](envelope.md), section 2.2). The length is in network byte order, as in TLS records; the little-endian order of AXT's fingerprints is Avro's, and a frame is not Avro.

### 4.5 HELLO

The first frame in each direction is a `HELLO`. Both apps send it as soon as the TLS handshake has completed, without waiting for the other's. Its payload is:

1. the 32 bytes of the sending installation's signing key;
2. the 64 bytes of the Ed25519 signature by that key, pure Ed25519 as in [keys.md](keys.md), section 2.2, over:
   1. the 18 bytes of the ASCII text `AXT-v1 connection` followed by one zero byte;
   2. one byte for the role of the sender of the `HELLO`: `01` for the client, `02` for the server;
   3. the 32 bytes of the SHA-256 of the server's certificate, its DER bytes as they travel in the TLS Certificate message. The client hashes the certificate it received, the server its own.

An app that gets the other app's `HELLO`:

1. checks the key by steps 2 and 3 of [keys.md](keys.md), section 2.3;
2. verifies the signature by [keys.md](keys.md), section 2.3, over the bytes above, with the other app's role and its own view of the certificate;
3. as a client that scanned a code, checks that the key is the code's `signing_key` (section 3.3), and tells its user if it is not.

If any check fails, it MUST close the connection without sending any further frame. An app MUST NOT send any frame but its `HELLO` before it has verified the other app's `HELLO`. After that, the key of the other app's `HELLO` is the connection key.

Every message the other app sends in the connection MUST have the connection key as its `sender`, except `DEVICE_ADD` and `DEVICE_REMOVE` messages ([protocol.md](protocol.md), section 3.3) and a `MANIFEST` that a device passes on for another device of its own set ([sync.md](sync.md), section 13.2): each is signed with a key of a device set, which need not be the connection key, and is the same whoever sends it ([keys.md](keys.md), section 5.4). They MAY come at any time in the connection, also after messages of other kinds, and do not close it ([protocol.md](protocol.md), section 3.1). A `MANIFEST` with another `sender` than the connection key is taken only if that `sender` is another current device of the app's own set, and is ignored without a report otherwise ([sync.md](sync.md), section 13.2). An app that gets a message of any other kind with another `sender`, a `DEVICE_JOIN` included, MUST close the connection without processing it.

**What the HELLO proves.** The signature covers the server's certificate, whose private key the server proved in the TLS handshake. A machine in the middle has to present a certificate of its own to each app. A `HELLO` it gets is bound to its own certificate, and fails at the other app, which sees another certificate. The role keeps a server's `HELLO` from being sent back to it as a client's. The prefix keeps the signature apart from every other signature of the key ([keys.md](keys.md), section 2.2). The server's `HELLO` is the same for every client for as long as the server keeps its certificate, and with the certificate's private key it would let another machine pose as the server; a new key for each time the server listens, never stored, keeps this to the time it listens (section 4.3).

**Before the manifest.** A live connection therefore authenticates the other app's key before its `MANIFEST`. A `MANIFEST` carries no addressee and no time, and anyone can pass on another app's signed `MANIFEST` ([protocol.md](protocol.md), section 2). Without the `HELLO`, an app could not know whether the other end of the connection holds the key of the manifests and records it receives, and could send records in clear to whoever connected. With it, every message in the connection comes from the other end, before its `MANIFEST` as after it.

### 4.6 Opening, liveness and closing

- **Opening.** A connection is open when both `HELLO` frames have been verified. The steps of [protocol.md](protocol.md), section 3.1, start then. An app SHOULD close a connection that is not open within 10 seconds of the TCP connection.
- **Liveness.** An app MUST send a `PING` whenever it has sent no frame for 30 seconds, and SHOULD close a connection on which it has received no frame for 90 seconds. `PING` frames are the only sign of life; a connection in which an answer waits for the user ([protocol.md](protocol.md), section 12) stays open by them.
- **Closing.** An app closes a connection by sending the TLS alert `close_notify` ([RFC 8446, section 6.1](https://www.rfc-editor.org/rfc/rfc8446#section-6.1)) and then closing the TCP connection. An app that gets `close_notify` processes no further frame, sends its own `close_notify`, and closes. Before it closes a connection of its own accord, an app SHOULD send the acknowledgements it owes ([protocol.md](protocol.md), section 7.2).
- **The end.** A connection ends when either app sends or gets `close_notify`, when the TCP connection is closed or reset, on a TLS alert, and when the liveness time runs out. A frame cut short by the end is discarded, and the message in it is not processed. The connection is then in the phase Closed of [protocol.md](protocol.md), section 14, in which the offers made in it end.

Two apps MAY hold several connections at the same time; each is a channel of its own ([protocol.md](protocol.md), section 1).

### 4.7 Joining a device set

A device adds a new device of its owner to its device set in a live connection that a join code opens ([keys.md](keys.md), section 5.2). The device that shows the code is the member and the server; the new installation is the client:

1. The member's user asks it to add a device. The member shows a code whose `join` is `true` and whose `local` is present (section 3.1), and listens (section 4.1).
2. The user of the new installation asks it to join and scans the code. The new installation connects to `local` as the client. TLS, the frames and the `HELLO` are those of sections 4.3 to 4.5; the new installation MUST close the connection unless the server's `HELLO` carries the code's `signing_key`.
3. When the connection is open (section 4.6), the new installation sends a `DEVICE_JOIN` as its first `MESSAGE` ([protocol.md](protocol.md), section 3.3).
4. The member asks its user whether to add the device whose key the client's `HELLO` proved, and shows that key's short fingerprint ([keys.md](keys.md), section 3.1). The connection stays open by its `PING` frames while the question waits (section 4.6).
5. The member answers with its chain, which holds the `DEVICE_ADD` of the new device, or with the error `DEVICE_REJECTED`, after which it closes the connection. The new installation checks the chain by step 5 of [keys.md](keys.md), section 5.2. It sends this error although it has no `MANIFEST` of the connection, the exception of [protocol.md](protocol.md), section 8.3.

- **Only by the code.** The member acts on a `DEVICE_JOIN` only in a connection that was opened to the address and port of the join code while it showed the code, and for one new device for each code it shows ([keys.md](keys.md), section 5.2). It SHOULD stop showing the code when it has a `DEVICE_JOIN`. A `DEVICE_JOIN` in a connection found by discovery (section 4.2), in any other connection, or through a relay is ignored without an error, before the `MANIFEST` and after it.
- **Two confirmations.** The scan confirms the member's key to the new installation, and the member's user confirms the new installation's key by the question. Whoever photographs a join code and reaches the local network can send a `DEVICE_JOIN`; the question, with the short fingerprint, keeps a stranger out. A member SHOULD show a join code only while its user asks for it.
- **Before the answer.** Neither device sends its chain or its `MANIFEST` before the member has answered the `DEVICE_JOIN`, and the 30 seconds of [protocol.md](protocol.md), section 12, do not run while the member's user decides.
- **Afterwards.** After an answer with the chain, the connection goes on as a live connection between two devices of one set, with the first messages of [protocol.md](protocol.md), section 3.1. A sent `DEVICE_JOIN` binds the new installation whatever the answer, also when the connection breaks off ([keys.md](keys.md), section 5.2). What the devices of a set exchange then is in [sync.md](sync.md), sections 7 and 12.3.

## 5. Relay

The relay is a sealed mailbox: it stores the messages that apps put into a mailbox, hands them to the mailbox's owner, and sees neither their content nor their type ([keys.md](keys.md), section 4.6). AXT has no default relay operator. Each app chooses its relay and names it in its manifest ([manifest.md](manifest.md), section 3.10); which relay, and whether its user chooses one, is up to the app. Anyone can run a relay; the repository's reference relay is described in [relay.md](relay.md).

### 5.1 Mailboxes

A mailbox holds sealed messages ([keys.md](keys.md), section 4.3) for one installation, its owner.

- **Secret.** The owner generates a mailbox secret of 32 bytes with a cryptographically secure random number generator, and keeps it with the app's data. It MUST NOT give the secret to any other app.
- **Id.** The mailbox id is the SHA-256 of the 15 bytes of the ASCII text `AXT-v1 mailbox` followed by one zero byte, then the 32 bytes of the secret. In a URL it is written as 64 lower-case hexadecimal digits.
- **Who may do what.** The id travels in the manifest's `relay` ([manifest.md](manifest.md), section 3.10) and in the QR code (section 3.1). Whoever knows the id can put messages into the mailbox. Only the holder of the secret can create the mailbox, list, fetch and delete its messages, and delete it.
- **What the relay keeps.** The relay keeps the id, not the secret: it checks a secret by computing the id from it. A copy of a relay's storage gives away no secret.
- **Not bound to a key.** The mailbox is not bound to the encryption key or to the signing key, and the relay learns neither. The mailbox and the encryption key can therefore be replaced independently of each other ([keys.md](keys.md), section 4.2).

An installation has one mailbox at a time, the same for every app that sends to it; each device of a device set has a mailbox of its own. Section 5.8 says how an installation moves to another mailbox.

### 5.2 Interface

The relay is an HTTP service ([RFC 9110](https://www.rfc-editor.org/rfc/rfc9110)), reached over HTTP/1.1 ([RFC 9112](https://www.rfc-editor.org/rfc/rfc9112)) or HTTP/2 ([RFC 9113](https://www.rfc-editor.org/rfc/rfc9113)) with TLS (section 5.7).

**The base URL.** A relay is named by its base URL: an absolute URL with the scheme `https`, a host, and a path that ends with `/`, without user information, query, fragment, spaces or control characters, at most 256 bytes, such as `https://relay.example.org/axt/`. The paths of the table below are appended to it.

In the paths, `{mailbox}` is a mailbox id and `{message}` the SHA-256 of a sealed message, each as 64 lower-case hexadecimal digits. "Owner" means that the request carries the header `Authorization`, with the value `Bearer`, one space and the mailbox secret as 64 lower-case hexadecimal digits, in the syntax of [RFC 6750, section 2.1](https://www.rfc-editor.org/rfc/rfc6750#section-2.1).

| Request                                            | By     | Body               | Success                                                                          |
| -------------------------------------------------- | ------ | ------------------ | -------------------------------------------------------------------------------- |
| `PUT v1/mailboxes/{mailbox}`                       | owner  | none               | `201 Created` for a new mailbox, `204 No Content` for one that exists            |
| `DELETE v1/mailboxes/{mailbox}`                    | owner  | none               | `204 No Content`; the mailbox and its messages are gone                          |
| `PUT v1/mailboxes/{mailbox}/messages/{message}`    | anyone | the sealed message | `201 Created`, or `204 No Content` if the relay holds the message already        |
| `GET v1/mailboxes/{mailbox}/messages`              | owner  | none               | `200 OK` with the list of the messages held (section 5.4); optional query `wait` |
| `GET v1/mailboxes/{mailbox}/messages/{message}`    | owner  | none               | `200 OK` with the sealed message as `application/octet-stream`                   |
| `DELETE v1/mailboxes/{mailbox}/messages/{message}` | owner  | none               | `204 No Content`, also for a message the relay does not hold                     |

The relay answers a request that fails with one of these codes:

| Code                       | When                                                                                                                    | The app                                                      |
| -------------------------- | ----------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| `400 Bad Request`          | A put whose body is empty or whose SHA-256 is not `{message}`; a `wait` that is not 0 to 60; a query on another request | Does not repeat the request; it is a fault of the app        |
| `401 Unauthorized`         | An owner request without `Authorization`, or with one that is not a secret in the form above                            | Does not repeat the request                                  |
| `403 Forbidden`            | An owner request whose secret is not the mailbox's; a mailbox the relay does not create for this app (section 5.6)      | Does not repeat the request                                  |
| `404 Not Found`            | A mailbox that does not exist; a message the mailbox does not hold                                                      | As section 5.3 says for a put, and section 5.4 for the owner |
| `411 Length Required`      | A put without `Content-Length`                                                                                          | Sends `Content-Length`                                       |
| `413 Content Too Large`    | A put above 17,301,553 bytes (section 5.6)                                                                              | Does not repeat the request                                  |
| `429 Too Many Requests`    | A request above the relay's rate limits (section 5.6)                                                                   | Waits as `Retry-After` says, then repeats it                 |
| `503 Service Unavailable`  | The relay cannot serve the request now                                                                                  | Waits as `Retry-After` or section 5.3 says, then repeats it  |
| `507 Insufficient Storage` | A put into a mailbox that has no room (section 5.6)                                                                     | Waits as section 5.3 says, then repeats it                   |

Only the list and the fetch have a body in their response. An app MUST ignore the body of every other response, and MUST NOT send cookies. A relay MUST NOT require cookies or any header that this section does not name.

### 5.3 Putting

To send a message through the relay, an app seals it for the receiver ([keys.md](keys.md), section 4.3), computes the SHA-256 of the sealed message, and puts it into the receiver's mailbox, the one in the receiver's manifest or QR code, with the headers `Content-Type: application/octet-stream` and `Content-Length`. A message sealed for two receivers is two sealed messages with two ids.

The relay checks a put in this order: `Content-Length` is present (`411`) and at most 17,301,553 (`413`), which it knows before it reads the body; the mailbox exists (`404`); the body is not empty and its SHA-256 is `{message}` (`400`); it holds the message already (`204`, and nothing changes); the mailbox has room (`507`). It then holds the message (`201`).

- **Repeats.** A put is safe to repeat: the relay holds a message once, however often it is put. An app that gets no response, such as after a network failure, repeats the same put.
- **Waiting.** After `429` or `503` with `Retry-After`, the app waits as long as it says. After a network failure, a `503` without `Retry-After`, a `507` or another `5xx` code, it waits 1 second before the first repeat and doubles the wait for each further one, up to 1 hour.
- **A mailbox that is gone.** After `404`, the app stops putting into the mailbox. The receiver has moved to another mailbox, or its mailbox was removed (section 5.5). The app puts again when a manifest of the receiver names a mailbox that exists, and its messages without an outcome are then sent again ([protocol.md](protocol.md), section 11).

### 5.4 Fetching and deleting

- **Creating.** The owner creates its mailbox before it gives the id to any other app, and creates it again whenever an owner request gets `404` for the mailbox itself. Creating a mailbox that exists changes nothing.
- **Listing.** The response to a list is a JSON object ([RFC 8259](https://www.rfc-editor.org/rfc/rfc8259)) with the media type `application/json`. Its member `messages` is an array of the messages held, oldest put first, at most 1,000, each an object with the members `id`, the message's SHA-256 as 64 lower-case hexadecimal digits, and `size`, its length in bytes. An app MUST ignore members it does not know.
- **Waiting for messages.** With `wait` from 1 to 60 and no message in the mailbox, the relay holds the response for up to that many seconds until a message is put, and then answers with the list. It MAY answer sooner. Without `wait`, or with 0, it answers at once.
- **Fetching and deleting.** The owner fetches each listed message, opens it and processes it ([keys.md](keys.md), section 4.5), and then deletes it. It deletes a message that does not open as well. A message it fetched but did not delete, for example because the app stopped, is fetched again and processed as a repeat ([protocol.md](protocol.md), section 9.2). After a list of 1,000 messages, it lists again.
- **How often.** An app SHOULD have at most one list of a mailbox waiting at a time, and SHOULD NOT list a mailbox more than once a minute without `wait`. It lists when it starts and while it runs; 0.1.0 has no push notification. An app away for longer than the holding time loses the messages put before; their senders send them again ([protocol.md](protocol.md), section 11).

### 5.5 Holding time

The holding time is 14 days.

- A relay MUST hold each message for 14 days after its put, unless the owner deletes it first, and MUST delete it within one day after that. A repeated put of a message it holds does not extend the time.
- A relay MAY remove a mailbox, with its messages, when its owner has made no request for 90 days, and MUST NOT remove it before. Its owner creates it again (section 5.4).

The holding time is the same for every relay, because the protocol depends on it and a sender cannot ask a relay for it:

- a sender sends a message without an outcome again after the holding time, not before ([protocol.md](protocol.md), section 11), and MAY offer again after it when an offer has no answer ([protocol.md](protocol.md), section 12);
- a receiver keeps the ids of the offers it answered through the relay, with their answers, for at least 15 days, the longest a relay holds a message ([protocol.md](protocol.md), section 4.3);
- an app keeps its old encryption private key for 15 days after it has sent the manifest with the new one ([keys.md](keys.md), section 4.2).

A longer holding time would let an app stay away longer without losing messages, at the cost of more storage at the relay and of a later resend of a message that was lost: a lost message waits for the holding time before its sender sends it again. 14 days cover two weeks without the app, such as a holiday, and keep what a relay stores to two weeks of messages.

### 5.6 Limits and unwanted messages

- **Size.** A relay MUST accept sealed messages up to 17,301,553 bytes, the largest message sealed and padded ([keys.md](keys.md), section 4.4), and MUST reject a larger one with `413`.
- **Room.** A relay MAY limit the number and the bytes of the messages a mailbox holds, and answers a put above its limit with `507`. It MUST accept a message of any size it accepts into an empty mailbox.
- **Rates.** A relay MAY limit the requests per client address and per mailbox, and the mailboxes created per client address, and answers a request above a limit with `429` and `Retry-After`.
- **Who may have a mailbox.** A relay MAY create mailboxes only for the apps it serves, such as the users of one operator, and answers other creations with `403`. How it tells them apart is not defined here.

Whoever knows a mailbox id can put messages into the mailbox: every app that has the owner's manifest or QR code, and everyone who has a file with the manifest. Against messages the owner does not want:

- A message that does not open is discarded ([keys.md](keys.md), section 4.5), and a message from an unknown key MAY be ignored ([keys.md](keys.md), section 3.2). The owner deletes both, so they do not fill its mailbox.
- The relay's limits bound what one sender can put.
- An owner whose mailbox gets unwanted messages moves to a new mailbox (section 5.8). The apps it exchanges with learn the new id from its manifest; others do not.

A put token separate from the mailbox id would travel the same way, in the manifest and the code, and would keep out no one the id does not; AXT defines none.

### 5.7 TLS, logs and what the relay learns

- **TLS.** An app reaches a relay only over HTTPS, with TLS 1.3 or TLS 1.2 as [RFC 9325](https://www.rfc-editor.org/rfc/rfc9325) recommends them, and checks the relay's certificate as for any HTTPS server ([RFC 9110, section 4.3.4](https://www.rfc-editor.org/rfc/rfc9110#section-4.3.4)). The relay is not trusted with the content, which is sealed; TLS keeps mailbox ids and secrets from others on the network.
- **Logs.** A relay MUST NOT log mailbox secrets or the value of `Authorization` headers, and MUST NOT keep a message beyond section 5.5, also not in a backup. It SHOULD NOT log mailbox ids together with client addresses, and MUST delete every log entry that holds both within 7 days.
- **What it learns.** A relay learns the mailbox ids, the size of each message, when it is put, fetched and deleted, and the addresses of the clients that do so ([keys.md](keys.md), section 4.6). From the addresses it can tell which client puts into which mailbox, and which client fetches from it. It learns neither the signing key nor the encryption key of a mailbox's owner or of a sender. An app that wants to hide its address from the relay needs a means outside this specification, such as an anonymizing network.

### 5.8 Changing the relay, and device sets

- **Another relay or mailbox.** An app that moves to another relay or another mailbox creates the new mailbox and puts it into a manifest with a higher revision ([manifest.md](manifest.md), section 3.10). It sends that manifest to every app it exchanges with through the relay, into their mailboxes, and in every live connection. It keeps fetching the old mailbox for 15 days after it has sent the manifest to all of them, and then deletes the old mailbox.
- **A device set.** Each device of a set has a mailbox secret, a mailbox and an encryption key of its own, and names its mailbox in its own `MANIFEST` ([keys.md](keys.md), section 5.6). A device MUST NOT give its mailbox secret to another device of its set (section 5.1). A message is sealed for one device and put into that device's mailbox.
- **A new device.** A device that joins a set, also one that takes the place of an old device ([keys.md](keys.md), section 5.7), creates a mailbox of its own and names it in its `MANIFEST`, which it sends after its chain. Nothing of another device's mailbox moves to it.
- **A removed device.** An app puts no further message into the mailbox of a removed key ([keys.md](keys.md), section 5.5). Messages that wait there get no outcome; their senders send them again to a remaining device ([keys.md](keys.md), section 5.6; [protocol.md](protocol.md), section 11).
- **Restoring.** An app that restores its signing key ([keys.md](keys.md), section 5.8) restores the mailbox secret with it.

## 6. Schema and fingerprint

The schema of the QR payload is [types/axt/QrPayload.avsc](../types/axt/QrPayload.avsc). It follows the rules that [types.md](types.md), section 5, sets for every example type, where they apply to a schema of the specification, as [manifest.md](manifest.md), section 9, says of the manifest: its nested types begin with `QrPayload`, and it carries no `axt.version`. It is not the body of any message, and changes only with a new payload version (section 3.1).

Its Parsing Canonical Form:

```json
{"name":"axt.QrPayload","type":"record","fields":[{"name":"signing_key","type":{"name":"axt.QrPayloadSigningKey","type":"fixed","size":32}},{"name":"encryption_key","type":["null",{"name":"axt.QrPayloadEncryptionKey","type":"fixed","size":32}]},{"name":"local","type":["null",{"name":"axt.QrPayloadLocal","type":"record","fields":[{"name":"addresses","type":{"type":"array","items":"bytes"}},{"name":"port","type":"int"}]}]},{"name":"relay","type":["null",{"name":"axt.QrPayloadRelay","type":"record","fields":[{"name":"url","type":"string"},{"name":"mailbox","type":{"name":"axt.QrPayloadRelayMailbox","type":"fixed","size":32}}]}]},{"name":"join","type":"boolean"}]}
```

| Schema          | Payload version | CRC-64-AVRO          | As bytes                  |
| --------------- | --------------- | -------------------- | ------------------------- |
| `axt.QrPayload` | 1               | `0xddbca858f745d131` | `31 d1 45 f7 58 a8 bc dd` |

The fingerprint and the examples of section 7 were produced with [conformance/tools/transports_examples.py](../conformance/tools/transports_examples.py). The script:

- checks the rules of [types.md](types.md), section 5, named above, with the checks of [conformance/tools/example_types.py](../conformance/tools/example_types.py), and that no name of the schema is defined in another schema of the specification;
- computes the Parsing Canonical Form and the CRC-64-AVRO fingerprint, compares them with those of the Python libraries fastavro 1.13.1 and `avro` 1.12.2, and uses every default of the schema once in schema resolution, with both libraries;
- builds the payload field by field, compares it with fastavro's encoding, decodes it with fastavro and with `avro`, and checks the validity rules of section 3.1 and the text of section 3.2 on the example and on 21 payloads and texts that each break one rule; it computes the QR version from the numbers of data codewords at level M, transcribed from ISO/IEC 18004;
- builds the server's certificate with the Python package cryptography 50.0.2, with deterministic ECDSA ([RFC 6979](https://www.rfc-editor.org/rfc/rfc6979)) so that its bytes can be reproduced; signs both `HELLO` frames with the Ed25519 implementation of [conformance/tools/keys_examples.py](../conformance/tools/keys_examples.py), with PyNaCl 1.6.2 and with cryptography 50.0.2, which give the same signatures; and frames the `DATA` of [protocol.md](protocol.md), section 17.5;
- runs a model of the frames of section 4 over the example, over 15 cases that must close the connection, and over a chain at the start and a `MESSAGE` above 16 MiB, which must not;
- opens a TLS 1.3 connection over a local socket pair with Python's `ssl` module and OpenSSL 3.5, with the certificate, ALPN `axt/1`, both `HELLO` frames, the `MESSAGE` and a `PING`, and closes it with `close_notify`; and checks that a client limited to TLS 1.2 cannot connect;
- seals the message of [keys.md](keys.md), section 7.2, again and checks it against the sealed message of [keys.md](keys.md), section 7.4; runs a model of the relay's interface over 28 requests, among them those of section 7.5, and checks their status codes; and opens the fetched message with Old Brain Fix's X25519 test key and verifies its signature.

The test vectors of [conformance.md](conformance.md) take precedence over these values.

## 7. Examples

cat-a-log scans the QR code of Old Brain Fix, the apps of [manifest.md](manifest.md), section 10, and connects to it on the local network; later, it sends a message to Old Brain Fix through Old Brain Fix's relay. Offsets are hexadecimal.

### 7.1 Test values

The keys are the test keys of [keys.md](keys.md), section 7.1, and of [protocol.md](protocol.md), section 17.1. The values below are derived the same way: each is the SHA-256 of the ASCII text `AXT test key, not for use: ` followed by the label. The P-256 private key is that value read as a big-endian integer, modulo the order of the group minus 1, plus 1. **These values are for tests only and MUST NOT be used outside tests.**

| Label                           | Value             | Hexadecimal                                                        |
| ------------------------------- | ----------------- | ------------------------------------------------------------------ |
| `Old Brain Fix, mailbox secret` | mailbox secret    | `72a36fdb88d435e53e3576b0c25662e14c9e4fba632cdda6019acbb851861441` |
|                                 | mailbox id        | `b3774fffae905d5721a9b398cd04f6d400afb09cb8cff3e216c3a3ba77c60063` |
| `Old Brain Fix, TLS, P-256`     | P-256 private key | `8ae1f9ea6dc6b0fb09e9691e0fd0758859deb859c3bdc5ad9faa3f55bcaa16ff` |

Old Brain Fix's signing key is `da9e54c9aa2db43244df99889d9138c1ca7175d4ca0908168f63530e4a7dedb7` and its encryption key `34fa7e71770d8d94c76001ac8d575609f005981f80c115bb7a8fe312687ea40b`. The relay is `https://relay.example.org/axt/`; Old Brain Fix listens on `192.168.1.20`, port 47312.

### 7.2 The QR code

Old Brain Fix's payload: 142 bytes, SHA-256 `84ae530c880870eac0e3010a9f220bbd08c836409ec0dfaa5335f92cea1aa30b`.

```text
0000  01                       payload version 1
0001  da 9e 54 c9 aa 2d b4 32  signing_key: fixed(32), Old Brain Fix's test key
      44 df 99 88 9d 91 38 c1
      ca 71 75 d4 ca 09 08 16
      8f 63 53 0e 4a 7d ed b7
0021  02                       encryption_key: union index 1, QrPayloadEncryptionKey
0022  34 fa 7e 71 77 0d 8d 94  encryption_key: fixed(32), Old Brain Fix's X25519 test key
      c7 60 01 ac 8d 57 56 09
      f0 05 98 1f 80 c1 15 bb
      7a 8f e3 12 68 7e a4 0b
0042  02                       local: union index 1, QrPayloadLocal
0043  02                       local.addresses: array block of 1 item
0044  08                       local.addresses[0]: bytes length 4
0045  c0 a8 01 14              local.addresses[0]: 192.168.1.20
0049  00                       local.addresses: end of the array
004a  a0 e3 05                 local.port: int 47312
004d  02                       relay: union index 1, QrPayloadRelay
004e  3c                       relay.url: string length 30
004f  68 74 74 70 73 3a 2f 2f  "https://relay.example.org/axt/"
      72 65 6c 61 79 2e 65 78
      61 6d 70 6c 65 2e 6f 72
      67 2f 61 78 74 2f
006d  b3 77 4f ff ae 90 5d 57  relay.mailbox: fixed(32), the test mailbox id
      21 a9 b3 98 cd 04 f6 d4
      00 af b0 9c b8 cf f3 e2
      16 c3 a3 ba 77 c6 00 63
008d  00                       join: boolean false
008e  end
```

Its text, 232 characters, which fits a QR code of version 9 at the error correction level M in alphanumeric mode:

```text
AXT:AHNJ4VGJVIW3IMSE36MYRHMRHDA4U4LV2TFASCAWR5RVGDSKPXW3OARU7J7HC5YNRWKMOYABVSGVOVQJ6ACZQH4AYEK3W6UP4MJGQ7VEBMBAECGAVAARIAFA4MCQEPDIOR2HA4Z2F4XXEZLMMF4S4ZLYMFWXA3DFFZXXEZZPMF4HIL5TO5H77LUQLVLSDKNTTDGQJ5WUACX3BHFYZ7Z6EFWDUO5HPRQAMMAA
```

### 7.3 The connection

Old Brain Fix's certificate, 269 bytes, SHA-256 `9f72c64e8b1e4aac1b1259229b070f18b687c2ffa71448ec3f3dd9ac01e4d7b9`:

```text
-----BEGIN CERTIFICATE-----
MIIBCTCBsaADAgECAgEBMAoGCCqGSM49BAMCMA4xDDAKBgNVBAMMA2F4dDAgFw0y
NjAxMDEwMDAwMDBaGA85OTk5MTIzMTIzNTk1OVowDjEMMAoGA1UEAwwDYXh0MFkw
EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPPDFzWSLF/7CuSjstJN4zWXkAHeIKrch
QcuyRqGmkH4IDgB0NIcrnpG4xLvrpGuaBjN33PYuEdE6b4J/7ZWfvjAKBggqhkjO
PQQDAgNHADBEAiBCXhpD3Y2e+lgJ0kN39BJH+IhlS10Fgi/AjSMy42coxgIgUW+F
hYIOt65jL6+IQRTAyg195pxGaswmU0gae55xQN8=
-----END CERTIFICATE-----
```

After the TLS handshake, both apps send their `HELLO` at once. cat-a-log's, as the client:

```text
0000  01                       frame type 1, HELLO
0001  00 00 00 60              length 96
0005  1b 84 a6 00 f3 50 3e 22  key: fixed(32), cat-a-log's test key
      bb cc 99 e6 32 02 a7 19
      4b f6 bd 69 af f1 47 1c
      ce 64 10 d5 3c 26 ec 4a
0025  20 30 93 5a 51 56 9c b5  signature: fixed(64)
      d1 43 ed d6 e1 1a e1 24
      2a 4c 3b d2 c2 dd a4 05
      1d 95 2e bf e8 a4 fa 41
      93 ec f5 d1 e1 d1 fb c0
      01 a9 23 24 de 6e 5e 4f
      92 bc 57 9a dc 91 f5 61
      fa 22 05 dd 72 e0 fc 0f
0065  end
```

Its signed bytes, 51 of them: the prefix `AXT-v1 connection` and its zero byte, the role `01`, and the SHA-256 of the certificate:

```text
41 58 54 2d 76 31 20 63 6f 6e 6e 65 63 74 69 6f
6e 00 01 9f 72 c6 4e 8b 1e 4a ac 1b 12 59 22 9b
07 0f 18 b6 87 c2 ff a7 14 48 ec 3f 3d d9 ac 01
e4 d7 b9
```

Old Brain Fix's, as the server, signed over the same bytes with the role `02`:

```text
0000  01                       frame type 1, HELLO
0001  00 00 00 60              length 96
0005  da 9e 54 c9 aa 2d b4 32  key: fixed(32), Old Brain Fix's test key
      44 df 99 88 9d 91 38 c1
      ca 71 75 d4 ca 09 08 16
      8f 63 53 0e 4a 7d ed b7
0025  78 50 8b 1d dd 42 e5 3d  signature: fixed(64)
      c5 a0 a0 97 c0 98 df fb
      02 a8 01 00 33 18 af ed
      f0 b8 8f 54 40 2d fc 7d
      48 52 97 5c d1 a4 4f 2b
      a7 c7 eb 4b 08 50 04 e9
      4b 20 6c d5 28 1b 1a b7
      a6 68 3f 32 17 49 db 02
0065  end
```

cat-a-log checks that the key in Old Brain Fix's `HELLO` is the code's `signing_key`; Old Brain Fix meets cat-a-log's key as a first contact. The connection is open, and the steps of [protocol.md](protocol.md), section 17, follow.

### 7.4 A message on the stream

The `DATA` of [protocol.md](protocol.md), section 17.5, 323 bytes, in a `MESSAGE` frame:

```text
0000  02                       frame type 2, MESSAGE
0001  00 00 01 43              length 323
0005  c3 01 16 30 ... 06 05    the DATA of spec/protocol.md, section 17.5
0148  end
```

A `PING`:

```text
0000  03                       frame type 3, PING
0001  00 00 00 00              length 0
0005  end
```

### 7.5 Through the relay

Old Brain Fix creates its mailbox. cat-a-log puts the sealed message of [keys.md](keys.md), section 7.4, 1,073 bytes with the SHA-256 `64a9988bd3e1e8210d592e29115d5b3252d2e75be5c219ca67583608cfdb878a`, into it. Old Brain Fix lists its mailbox, fetches the message and deletes it. The requests are shown in HTTP/1.1 with the headers this document names; the body of the put and of the fetch is shown as a note.

Old Brain Fix creates its mailbox:

```text
PUT /axt/v1/mailboxes/b3774fffae905d5721a9b398cd04f6d400afb09cb8cff3e216c3a3ba77c60063 HTTP/1.1
Host: relay.example.org
Authorization: Bearer 72a36fdb88d435e53e3576b0c25662e14c9e4fba632cdda6019acbb851861441
Content-Length: 0
```

```text
HTTP/1.1 201 Created
Content-Length: 0
```

cat-a-log puts the sealed message:

```text
PUT /axt/v1/mailboxes/b3774fffae905d5721a9b398cd04f6d400afb09cb8cff3e216c3a3ba77c60063/messages/64a9988bd3e1e8210d592e29115d5b3252d2e75be5c219ca67583608cfdb878a HTTP/1.1
Host: relay.example.org
Content-Type: application/octet-stream
Content-Length: 1073

<the 1,073 bytes of the sealed message>
```

```text
HTTP/1.1 201 Created
Content-Length: 0
```

Old Brain Fix lists its mailbox, waiting up to 30 seconds:

```text
GET /axt/v1/mailboxes/b3774fffae905d5721a9b398cd04f6d400afb09cb8cff3e216c3a3ba77c60063/messages?wait=30 HTTP/1.1
Host: relay.example.org
Authorization: Bearer 72a36fdb88d435e53e3576b0c25662e14c9e4fba632cdda6019acbb851861441
```

```text
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 100

{"messages":[{"id":"64a9988bd3e1e8210d592e29115d5b3252d2e75be5c219ca67583608cfdb878a","size":1073}]}
```

It fetches the message:

```text
GET /axt/v1/mailboxes/b3774fffae905d5721a9b398cd04f6d400afb09cb8cff3e216c3a3ba77c60063/messages/64a9988bd3e1e8210d592e29115d5b3252d2e75be5c219ca67583608cfdb878a HTTP/1.1
Host: relay.example.org
Authorization: Bearer 72a36fdb88d435e53e3576b0c25662e14c9e4fba632cdda6019acbb851861441
```

```text
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Length: 1073

<the 1,073 bytes of the sealed message>
```

It deletes the message:

```text
DELETE /axt/v1/mailboxes/b3774fffae905d5721a9b398cd04f6d400afb09cb8cff3e216c3a3ba77c60063/messages/64a9988bd3e1e8210d592e29115d5b3252d2e75be5c219ca67583608cfdb878a HTTP/1.1
Host: relay.example.org
Authorization: Bearer 72a36fdb88d435e53e3576b0c25662e14c9e4fba632cdda6019acbb851861441
```

```text
HTTP/1.1 204 No Content
```

Old Brain Fix opens the fetched message with its X25519 key and gets the `DATA` of [keys.md](keys.md), section 7.2, whose signature verifies with cat-a-log's key.

## 8. What other documents define

- [envelope.md](envelope.md): the live message that a `MESSAGE` frame carries (section 3 there), and the file (section 4 there).
- [keys.md](keys.md): the signatures the `HELLO` and the file use, the confirmation of a scanned key (section 3.2 there), and the sealed messages the relay holds (section 4 there).
- [protocol.md](protocol.md): what happens in a live connection after the `HELLO`, and through the relay (sections 3, 14 and 15 there).
- [sync.md](sync.md): the messages `CHANGE`, `RESYNC` and `FORWARD` between the devices of one set, which travel on the local network and through the relay and never in a file (sections 13 and 24 there), and what a device of a set does with a file of another app that it read (section 24.2 there).
- [relay.md](relay.md): the reference relay of the repository, its storage, its limits and how it is run. Apps depend only on section 5 of this document; [relay.md](relay.md) adds nothing that an app needs.
- [conformance.md](conformance.md): test vectors for the QR payload, the frames and the relay's interface.

## References

- [Apache Avro 1.12 specification](https://avro.apache.org/docs/1.12.0/specification/)
- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174): key words for requirement levels
- [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986): URIs
- [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648): base32
- [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280): X.509 certificates
- [RFC 6066](https://www.rfc-editor.org/rfc/rfc6066): TLS extensions, Server Name Indication
- [RFC 6335](https://www.rfc-editor.org/rfc/rfc6335): service names
- [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750): bearer tokens
- [RFC 6762](https://www.rfc-editor.org/rfc/rfc6762): Multicast DNS
- [RFC 6763](https://www.rfc-editor.org/rfc/rfc6763): DNS-Based Service Discovery
- [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979): deterministic ECDSA
- [RFC 7301](https://www.rfc-editor.org/rfc/rfc7301): Application-Layer Protocol Negotiation
- [RFC 7595](https://www.rfc-editor.org/rfc/rfc7595): URI schemes
- [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259): JSON
- [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446): TLS 1.3
- [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110), [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112) and [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113): HTTP, HTTP/1.1 and HTTP/2
- [RFC 9325](https://www.rfc-editor.org/rfc/rfc9325): recommendations for TLS
- ISO/IEC 18004: QR Code bar code symbology specification
