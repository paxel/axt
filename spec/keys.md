# Keys, signatures and encryption

Status: written, 0.1.0. Until 0.1.0 is released, [protocol.md](protocol.md) and [transports.md](transports.md) may still change the details this document leaves to them, and the schemas of `axt.DeviceJoin`, `axt.DeviceAdd` and `axt.DeviceRemove` may still change in place; their fingerprints (section 6) and the examples (section 7) are then produced again.

This document defines the keys of an installation, how every message is signed and verified, how the schemas a message uses are bound to its sender, how an app meets and remembers another app's key, how messages through a relay are encrypted, and how the devices of one owner, each with a key of its own, count as one sender.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 ([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119), [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)) when, and only when, they appear in all capitals, as shown here.

## 1. Terms

- **Installation**: one copy of an app on one device, with its own data.
- **Signing key**: the Ed25519 key pair ([RFC 8032](https://www.rfc-editor.org/rfc/rfc8032)) of an installation. Its public key is the `sender` of every message the installation sends ([envelope.md](envelope.md), section 2).
- **Encryption key**: the X25519 key pair ([RFC 7748](https://www.rfc-editor.org/rfc/rfc7748)) of an installation, with which other apps encrypt messages to it through a relay (section 4).
- **Device set**: the installations of one owner's app that count as one sender, each with a signing key of its own (section 5). A **device** of a set is one of these installations; an installation on its own is a set of one device.
- **Sender**: as in [records.md](records.md), section 1: a device set, which a receiver knows by the first key it accepted from it and by the keys added to it and removed from it since (section 5).
- **Known sender**: a sender of which an app has accepted a key (section 3.2) and which it has not forgotten (section 3.4). Its **current keys** are the first key the app accepted for it and every key that a valid `DEVICE_ADD` added, without its **removed keys**, the keys that a valid `DEVICE_REMOVE` named (section 5.5).
- **Refused key**: a removed key of a sender that an app has forgotten; the app goes on rejecting it (section 3.4).
- **First contact**: an app gets a message signed with a key that is neither a current key nor a removed key of any known sender, and not a refused key.
- **Chain**: the additions and removals of a device set, as the signed messages they are, oldest first (section 5.4).
- **Short fingerprint**: the 25 digits by which a user compares a key (section 3.1).

## 2. Signatures

### 2.1 The signing key

Every installation has one signing key. It generates the key with a cryptographically secure random number generator, as [RFC 8032, section 5.1.5](https://www.rfc-editor.org/rfc/rfc8032#section-5.1.5) describes, when it first needs one, and keeps the private key on the device.

- An installation MUST sign every message it sends with its signing key, and MUST put the public key in the message's `sender`.
- It MUST use the same key for every receiver. Receivers identify its records by the sender this key belongs to and the record id ([records.md](records.md), section 2), and a record has the same id at every receiver.
- Two installations MUST NOT use one signing key at the same time. A receiver could not tell them apart: it keeps one manifest and one encryption key for each key (section 3.3), and could not remove one of the two (section 5.3). The devices of one owner each have a key of their own, and section 5 makes them one sender.

### 2.2 The signed bytes

The signature of a message is the Ed25519 signature of [RFC 8032, section 5.1.6](https://www.rfc-editor.org/rfc/rfc8032#section-5.1.6) (pure Ed25519, not Ed25519ph and not Ed25519ctx) by the sender's private key over these bytes:

1. the 15 bytes `41 58 54 2d 76 31 20 6d 65 73 73 61 67 65 00`, the ASCII text `AXT-v1 message` followed by one zero byte;
2. the envelope in binary encoding without its last 64 bytes, that is, every field from `format` to `body`, as the message carries them.

In a live message, the second part is the bytes from offset 10, after the single-object marker and the envelope fingerprint, up to the last 64 bytes ([envelope.md](envelope.md), section 3). In a file, it is the datum's bytes in the decompressed data block, without its last 64 bytes ([envelope.md](envelope.md), section 4). Both are the same bytes, so a message keeps its signature between a connection, a relay and a file. The signature is the `signature` field, the last 64 bytes.

- A receiver MUST verify a signature over the bytes as it received them. It MUST NOT encode decoded values again to verify them: a decoded value can encode differently, as a UUID received with upper-case digits does ([envelope.md](envelope.md), section 7). An Avro library's file reader returns decoded values; a reader of a file therefore takes the datum's bytes from the block itself. Every field of the envelope is either of fixed length or carries its length in front, so the end of each datum follows from its bytes (section 7.3).
- The single-object marker and the envelope fingerprint of a live message, and the `avro.schema` of a file, are not signed. The `format` field is. A receiver MUST reject a message whose `format` is not the format named by its envelope fingerprint, or in a file by the file's `avro.schema` ([envelope.md](envelope.md), section 2.1).

The prefix separates signatures over AXT messages from every other signature the same key makes: over a file header (section 2.5), in the proof of an added device (section 5.2), in the `HELLO` of a live connection ([transports.md](transports.md), section 4.5), or in another protocol. The TLS connection on the local network uses a key of its own, not the signing key ([transports.md](transports.md), section 4.3). Every prefix of this document ends with the only zero byte in it, so none is the beginning of another. Ed25519ctx would do the same with a context string, but not every library implements it; Apple CryptoKit, for example, offers pure Ed25519 only.

### 2.3 Verification

A receiver MUST verify the signature of every message before it uses any field of the message, except to find the message's format and its end. It MUST reject a message whose signature does not verify, reported as [protocol.md](protocol.md), section 8.3, describes, and MUST NOT apply any part of it.

Verification is strict. With A the 32 bytes of `sender`, R the first and S the last 32 bytes of `signature`, M the signed bytes of section 2.2, B the base point, L the order of the base point and p = 2^255 − 19, as in [RFC 8032, section 5.1](https://www.rfc-editor.org/rfc/rfc8032#section-5.1):

1. Read S as a little-endian integer. If S ≥ L, reject.
2. Decode A and R as points, as [RFC 8032, section 5.1.3](https://www.rfc-editor.org/rfc/rfc8032#section-5.1.3) says. If either decoding fails, reject. This rejects every encoding whose y coordinate is p or above, and the encodings with x = 0 and the sign bit set.
3. If A or R is not a point of order L, that is, if it is the neutral element or [L] times it is not the neutral element, reject. This rejects the points of small order and every point with a component of small order.
4. Compute k = SHA-512(R ‖ A ‖ M), read as a little-endian integer, modulo L.
5. Accept if and only if [S]B = R + [k]A. With A and R of order L, this equation holds exactly when the equation with the cofactor, [8][S]B = [8]R + [8][k]A, holds; an implementation MAY check either, and MAY check the first by comparing the encoding of [S]B − [k]A with the 32 bytes of R.

An app MUST also reject a public key that fails step 2 or 3 wherever it gets one: in a QR code, as the `device` of a `DEVICE_ADD`, or as the `sender` of a first contact.

The points of small order have these eight canonical encodings, in hexadecimal. A key or an R that is one of them fails step 3; one whose y is p or above fails step 2. A point with a component of small order is the sum of a point of order L and one of these points, and fails step 3 as well.

```text
0000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000080
0100000000000000000000000000000000000000000000000000000000000000
26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05
26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85
c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a
c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa
ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f
```

RFC 8032 leaves two choices to the verifier: whether to check the equation with the cofactor 8 or without it, and which keys and R to accept. Ed25519 libraries choose differently, and some have changed their choice between releases, so the same signature can verify in one library and fail in another (section 7.6). This document fixes both choices, so that every conforming library gives the same answer for every message, and the test vectors of [conformance.md](conformance.md) have one expected result:

- With A and R of order L, the two equations agree, so the answer does not depend on which equation a library checks. An implementation cannot change the equation inside its library, but it can always check A and R before it calls the library.
- A key of small order verifies signatures that do not depend on the message: with the neutral element as key, the signature with R the neutral element and S = 0 verifies for every message (section 7.6). Rejecting such keys keeps a key bound to the messages its holder signed.
- An honest key [a]B and an honest R = [r]B are points of order L, an honest S is below L, and an honest signer encodes every point canonically, so the rule rejects no honest signature.

Step 3 costs one scalar multiplication for each point. For A it is needed once, when the app first accepts the key; for R on every message. libsodium's `crypto_core_ed25519_is_valid_point` performs steps 2 and 3 for one point, and the script of section 7 checks that it agrees with this document on every point it uses. With a library that checks less, an implementation adds steps 1 to 3 before it calls the library's verification.

### 2.4 The schemas of a connection

A `DATA` message names its writer schema only by fingerprint, and a fingerprint is not collision resistant ([envelope.md](envelope.md), section 5); it also leaves out `doc` and every other attribute a receiver shows its user. The schemas themselves are therefore bound to the sender by a signature. In a live connection and through a relay, the `OFFER` ([protocol.md](protocol.md), section 4) is that signature. This document requires of it:

- An `OFFER` MUST carry each writer schema as its full JSON text in its body, so that the offer's signature covers every attribute of the schema, its `doc` attributes and `axt.version` included ([envelope.md](envelope.md), section 3).
- A receiver MUST keep the schemas it was offered per sender, and MUST decode the body of a `DATA` message only with a schema that the same sender offered. It looks up the body's fingerprint among that sender's schemas alone; a schema with the same fingerprint that another sender offered MUST NOT be used.
- [protocol.md](protocol.md) MUST NOT let a `DATA` message use a schema that its sender has not offered in a signed `OFFER`, or, in a file, in a signed header (section 2.5).

### 2.5 Files

A file's metadata is not part of any message, so no message signature covers it ([envelope.md](envelope.md), section 4.1). Every AXT file therefore carries a signature of its header in two metadata entries:

| Key             | Value                                                                                                                    |
| --------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `axt.sender`    | The Ed25519 public key of the file's sender, as 64 lower-case hexadecimal digits in ASCII                                |
| `axt.signature` | The Ed25519 signature of the file's sender over the header's signed bytes, as 128 lower-case hexadecimal digits in ASCII |

The header's signed bytes are:

1. the 19 bytes of the ASCII text `AXT-v1 file header` followed by one zero byte;
2. the 32 bytes of the sender's public key;
3. the 32 bytes of the SHA-256 ([FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)) of the value of `axt.schemas`, as stored in the file; for a file without `axt.schemas`, the SHA-256 of zero bytes.

A writer MUST write both entries in every file. A reader:

- MUST verify the header's signature by section 2.3, with the key in `axt.sender`, before it uses `axt.schemas`, and MUST reject a file whose header signature does not verify, that lacks either entry, or whose entries are not lower-case hexadecimal text of the right length;
- MUST reject a file that holds a message whose `sender` is not the key in `axt.sender`, except the `DEVICE_ADD` and `DEVICE_REMOVE` messages at the start of the file that section 5.4 allows;
- applies section 2.4 to the file: the schemas in a file's `axt.schemas` are the schemas its sender offered for that file.

The values are hexadecimal text because Avro libraries handle metadata values differently: the Python library fastavro 1.13.1, for example, writes only metadata given as text. A text of 64 or 128 ASCII digits passes through every library unchanged.

**One sender per file.** Every message of a file is from the file's sender, the key in `axt.sender`, apart from the `DEVICE_ADD` and `DEVICE_REMOVE` messages of section 5.4. A file is written by one installation, as an export or for one receiver; a relay and a connection carry the messages of one sender each as well, so the rule constrains no transport ([transports.md](transports.md), section 2.1). It lets a reader confirm one key for the whole file (section 3.2).

**The envelope schema.** `avro.schema` is not signed. A reader MUST compare the Parsing Canonical Form of `avro.schema` byte for byte with the Parsing Canonical Form of a published envelope format, not only its fingerprint, and MUST decode the file's messages with its own copy of that format's schema, never with the schema from the file ([envelope.md](envelope.md), section 4.1). Together with the signed `format` field (section 2.2), the envelope schema is then fixed by this specification, and a forged `avro.schema` with a matching CRC-64-AVRO cannot change how a message is read. `avro.codec` is not signed either; it selects only how blocks are decompressed, and a wrong codec yields bytes whose signatures fail.

**What the header signature does not cover.** A file is not signed as a whole. Messages can be removed from it, repeated, reordered, or put into another file of the same key with another signed header. Each message stands for itself, and the version rule ([records.md](records.md), section 5.2) gives the same result in any order. A reader MUST NOT conclude from a file that it holds every record of its sender, and MUST NOT take a record that is missing from a file for deleted.

### 2.6 What a signature does not say

- **Whom a message is for.** A signature names the sender, not the receiver. A receiver can pass a signed message on, and the third app then holds a genuine message of the sender. For records this is intended: a sender sends a record under the same id to every receiver, and a file can be forwarded. [protocol.md](protocol.md) MUST bind to their receiver or their connection, in their body, the messages whose replay to another app would matter, such as `ACCEPT`, `DECLINE`, `ACK` and `ERROR`. It does so with the field `to` in their bodies ([protocol.md](protocol.md), section 9.1).
- **When it was sent.** A message carries no time. A relay or a user can deliver a message again. Record messages and manifests are safe to repeat by their versions and revisions ([records.md](records.md), section 5.2; [manifest.md](manifest.md), section 6); [protocol.md](protocol.md) MUST make every other kind safe to repeat, and does so in its section 9.2.
- **Secrecy.** A signature hides nothing. A live connection is encrypted by TLS ([transports.md](transports.md), section 4.3), a message through a relay as section 4 says, and a file is readable by whoever holds it.

## 3. Trust

### 3.1 The short fingerprint

The short fingerprint of an Ed25519 public key is computed as follows:

1. H = SHA-256 of the 19 bytes of the ASCII text `AXT-v1 fingerprint` followed by one zero byte, then the 32 bytes of the key.
2. Take the first 25 bytes of H as five groups of 5 bytes. Read each group as a big-endian integer, take it modulo 100000, and write it as five decimal digits with leading zeros.
3. Join the five groups with one space each.

The result looks like `24773 42899 01908 98427 81734` (section 7.1). It carries about 83 bits: finding another key with the same short fingerprint takes about 2^83 attempts. Digits can be read aloud and compared in any language, and none of them looks like another.

An app MUST show the short fingerprint of its own signing key where its user can find it, such as in its settings, so that the user can compare it with what another app shows. An app MAY also show the full key in hexadecimal.

### 3.2 First contact

An app meets another app's key in one of these ways:

- **QR code.** A QR code that the other app shows carries its signing key and, for the relay, its encryption key and its mailbox; [transports.md](transports.md), section 3, defines the payload. Scanning it in person is the user's confirmation of the key: the app MAY remember the key without asking again. It MUST check that the messages it then gets from that app are signed with the scanned key; on the local network the `HELLO` of [transports.md](transports.md), section 4.5, binds the connection to the scanned key. The app that showed the code learns the scanner's key from the connection and meets it as a first contact by the next rule. A code marked as a join code is not a first contact between two apps: it adds a device to the set of the device that shows it (section 5.2).
- **Any other way**: the first message of a file, a connection without a QR code, or a relay message from an unknown key. This is trust on first use. The app MUST verify the message's signature first (section 2.3), and then MUST ask its user before it remembers the key. It shows the app name from a valid `MANIFEST` signed with that key if it has one ([manifest.md](manifest.md), section 3.1), or says that the app has not named itself, and the short fingerprint of the key. The user SHOULD compare the short fingerprint with the one the other app shows.

Until its user accepts the key, the app MUST NOT apply any record signed with it and MUST NOT use a manifest signed with it, except to show the app name. It MAY keep the messages until the user decides, and processes them once the user accepts. If the user declines, it discards them; it MAY remember the key as declined, so that it does not ask again.

A file is confirmed once, for its sender in `axt.sender` (section 2.5). An app MAY ignore relay messages from unknown keys without asking its user, for example when the user expects no new contact; anyone who knows an app's encryption key and mailbox can put messages there.

### 3.3 Known senders

To remember a key, an app keeps for each known sender:

- its current keys and its removed keys (section 5.5);
- for each current key, its encryption key and its relay and mailbox ([manifest.md](manifest.md), section 3.10), if it has them, and where they came from: a QR code or a manifest of a given revision (section 4.2);
- for each current key, the kept manifest ([manifest.md](manifest.md), section 6);
- its records and tombstones, one copy of each for the sender, whichever of its keys signed them ([records.md](records.md), section 5.1).

A message is from a known sender only if its signature verifies (section 2.3) and its `sender` is one of that sender's current keys. An app:

- MUST apply an update or a deletion of a record only from the record's sender, that is, from a message signed with one of the sender's current keys, whichever of them signed the versions before; [records.md](records.md), section 2, identifies a record by its sender and its id;
- MUST reject a message signed with a removed key, and reports nothing; for a `DEVICE_ADD` or a `DEVICE_REMOVE` signed with one, section 5.5 says which it ignores as a repeat and which it reports;
- treats a message with a key it does not know as a first contact (section 3.2), never as an update or a deletion of a record it has.

### 3.4 Forgetting a sender

An app MAY let its user forget a known sender. It then deletes the sender's current keys and the encryption key and the kept manifest of each. It MUST keep the sender's removed keys, as refused keys: it rejects every message signed with a refused key, without a report, and never takes a refused key as the signer that a known device vouches for (section 5.5, step 3). Otherwise whoever holds a removed key could send an old addition again after the sender was forgotten, and become a current key of it. It MAY delete the sender's records and tombstones with them ([records.md](records.md), section 5.3). Records it keeps are no longer records of that sender: no message can update or delete them, and the app treats them as its user's own.

A later message signed with one of the keys that were current is a first contact (section 3.2), and the sender starts again with that key alone and with no records. A file of the sender opened again can then bring back records the sender had deleted, because the tombstones are gone. An app SHOULD tell its user this before it forgets a sender.

## 4. Encryption for the relay

### 4.1 The construction

A message through a relay is encrypted with HPKE, the Hybrid Public Key Encryption of [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180), in its base mode and with its single-shot interface ([RFC 9180, section 6](https://www.rfc-editor.org/rfc/rfc9180#section-6)), with this cipher suite:

| HPKE part | Algorithm                  | Identifier |
| --------- | -------------------------- | ---------- |
| KEM       | DHKEM(X25519, HKDF-SHA256) | `0x0020`   |
| KDF       | HKDF-SHA256                | `0x0001`   |
| AEAD      | ChaCha20-Poly1305          | `0x0003`   |

The `info` is the 20 bytes of the ASCII text `AXT-v1 relay message`; the associated data is empty.

- **HPKE.** It is X25519 key agreement, a key derivation with HKDF-SHA256 ([RFC 5869](https://www.rfc-editor.org/rfc/rfc5869)) and an AEAD, put together as a published standard with test vectors. Libraries that provide it include OpenSSL from 3.2, BoringSSL, Apple CryptoKit and the Python package cryptography. Where none is at hand, it is built from X25519, HKDF-SHA256 and ChaCha20-Poly1305 as RFC 9180, sections 4 and 5, describe, as [conformance/tools/keys_examples.py](../conformance/tools/keys_examples.py) does.
- **Base mode, a sealed box.** Only the receiver's key goes into the encryption; the sender's key does not. The relay therefore learns nothing about the sender from the ciphertext, and the receiver learns the sender from the signature inside (section 4.3). HPKE's authenticated mode would bind the sender's X25519 key as well, which adds nothing to the signature, and the receiver would need to know which sender's key to use before it could open the message.
- **ChaCha20-Poly1305** ([RFC 8439](https://www.rfc-editor.org/rfc/rfc8439)). HPKE derives the key and the nonce of every message from a fresh ephemeral key, so no nonce is chosen at random, and the 96-bit nonce of ChaCha20-Poly1305 is enough. XChaCha20-Poly1305, whose 192-bit nonce makes random nonces safe, is not an HPKE AEAD and is missing from several platform libraries, among them Apple CryptoKit and the Java standard library. ChaCha20-Poly1305 runs in constant time in software, also on phones without AES instructions, where AES-GCM does not.

### 4.2 The encryption key

Every installation that takes messages through a relay has an encryption key: an X25519 key pair of its own, generated with a cryptographically secure random number generator, separate from its signing key.

The encryption key is not derived from the signing key. An Ed25519 key can be converted into an X25519 key, as libsodium does, but most platform libraries do not offer the conversion, and one key used in two algorithms needs a security analysis of its own that two keys do not. A separate key can also be replaced without changing the signing key.

An app takes another app's encryption key only from a source bound to that app's signing key:

- a QR code scanned in person (section 3.2);
- the field `encryption_key` of a valid `MANIFEST` signed with that same signing key, a current key of a known sender ([manifest.md](manifest.md), section 3.9).

It MUST NOT use an encryption key from any other source. Of these, the latest wins: a manifest replaces the encryption key under the revision rule of [manifest.md](manifest.md), section 6. A manifest whose `encryption_key` is `null` means that the installation takes no messages through a relay.

Each device of a sender has an encryption key of its own, bound to its signing key. An app seals a message for the device it sends it to, with that device's encryption key, and MUST NOT seal a message for one device with the encryption key of another (section 5.6).

An app MUST reject an encryption key of small order: one for which X25519 gives the all-zero value with every private key. Computing X25519 with any one private key, such as the app's own, and comparing the result with 32 zero bytes detects it. A manifest with such a key is invalid ([manifest.md](manifest.md), section 4).

An installation MAY replace its encryption key, by a manifest with a higher revision. It SHOULD keep the old private key for as long as a relay may hold messages sealed to it: 15 days after it has sent the manifest with the new key ([transports.md](transports.md), section 5.5).

### 4.3 Sealing

A message is signed first and encrypted second:

1. The sender signs the message as section 2.2 says, and encodes it as a live message: single-object marker, envelope fingerprint and envelope ([envelope.md](envelope.md), section 3).
2. It pads the message as section 4.4 says.
3. It generates a fresh ephemeral X25519 key pair and encrypts the padded message to the receiver's encryption key, with the single-shot `Seal` of HPKE and the parameters of section 4.1. The result is the encapsulated key `enc` (32 bytes) and the ciphertext (the padded message and a 16-byte tag).
4. The sealed message is the byte `01`, then `enc`, then the ciphertext.

The byte `01` names the construction of this section. Signing inside the encryption keeps the signature verifiable after opening and the same as in a live message and in a file (section 2.2), and keeps the sender's key, which the envelope carries, away from the relay.

The nonce rules follow from HPKE's single-shot interface. The sender:

- MUST generate the ephemeral key pair for each sealed message anew from a cryptographically secure random number generator (`GenerateKeyPair` of RFC 9180), and MUST NOT use it again;
- MUST seal exactly one plaintext with each HPKE context, so that the nonce is the context's `base_nonce` with sequence number 0; the same message sealed for two receivers is two sealed messages;
- MUST abort if the X25519 output is the all-zero value ([RFC 9180, section 7.1.4](https://www.rfc-editor.org/rfc/rfc9180#section-7.1.4)).

An ephemeral key used twice for the same receiver gives the same key and nonce twice, which breaks both the secrecy and the integrity of both messages.

### 4.4 Padding

The padded message is the message, the byte `80`, and as many zero bytes as bring it to the padded length P(n) for a message of n bytes:

- P(n) = max(1024, Padmé(n + 1));
- Padmé(x), after Nikitin and others (2019): with E = ⌊log₂ x⌋, S = ⌊log₂ E⌋ + 1 and the mask m = 2^(E − S) − 1, Padmé(x) is x + m with its lowest E − S bits cleared.

A sender MUST pad to exactly P(n). Some lengths:

| Message, bytes        | Padded, bytes |
| --------------------- | ------------- |
| 210 (section 7.2)     | 1,024         |
| 1,023                 | 1,024         |
| 1,024                 | 1,088         |
| 4,000                 | 4,096         |
| 100,000               | 100,352       |
| 16,777,216, the limit | 17,301,504    |

The sealed message is 49 bytes longer than the padded message, so the largest is 17,301,553 bytes; a relay MUST accept sealed messages up to that size ([transports.md](transports.md), section 5.6).

The length is what the relay sees of a message besides its mailbox and its time (section 4.6). The minimum of 1,024 bytes gives the small messages, such as an `ACK`, a `DELETE`, a short `DATA` and most manifests, one length; above it, Padmé leaves only the top bits of the length visible and adds less than a sixteenth of the length, 6.25 %.

### 4.5 Opening

A receiver opens a sealed message as follows:

1. If the first byte is not `01`, it rejects the message.
2. It splits the rest into `enc`, the first 32 bytes, and the ciphertext, and opens it with the single-shot `Open` of HPKE, an encryption private key of its own and the parameters of section 4.1, trying its current key first and earlier keys after it (section 4.2). It MUST abort if the X25519 output is the all-zero value. If no key opens the message, it discards it.
3. It removes the zero bytes at the end and the byte `80` before them. It MUST reject a plaintext that does not end with `80` followed only by zero bytes. It need not check the padded length.
4. It processes the result as a live message ([envelope.md](envelope.md), section 3), with the signature verification of section 2.3 and the rules of section 3.

A message that cannot be opened has no sender a receiver could report to; a message that opens but fails later is reported as [protocol.md](protocol.md), section 8.3, describes.

### 4.6 What the relay sees

The relay sees, of each sealed message, the mailbox it is put into ([transports.md](transports.md), section 5.1), its length, when it is put and fetched, and the network addresses of the apps that put and fetch it, unless they hide them. It does not see the kind, the sender's key, the record, the type, the schema or the content.

The relay can drop, delay, reorder and repeat messages. It cannot read or change one, or make a new one in a sender's name: the AEAD tag fails for a changed message, and the signature for a message made by anyone else. Section 2.6 says how repeats are handled. The relay does not learn which encryption key a mailbox belongs to: a mailbox is not bound to a key ([transports.md](transports.md), section 5.1).

## 5. Device sets

### 5.1 The set

An owner who runs an app on several devices, such as a phone and a tablet, has several installations. Each has its own signing key, its own encryption key, its own mailbox and its own manifest. Together they are one device set, and another app takes the set for one sender:

- **No owner key.** A set is its first key, the keys added to it (section 5.2) and the keys removed from it (section 5.3). No key stands above the devices, and nothing has to be kept apart from them.
- **Equal devices.** Every device of a set may add a new device, and may remove any other device of the set. No device removes itself.
- **Never empty.** A set keeps at least one key: a removal is signed by another device than the one it removes, so the last key of a set cannot be removed (section 5.3).
- **One set.** An installation belongs to one set. An installation that never added a device and never joined one is a set of its own with one key, and nothing in sections 2 to 4 changes for it. An installation whose set has, or has had, another device MUST NOT join another set. A receiver that knows both sets, each by more than one key or by a removed key, rejects the addition, and so does one that knows the installation's key as a removed or a refused key (section 5.5).
- **One sender.** For a receiver, all current keys of a set sign for the same sender. It keeps one copy of each record of the set, whichever device sent it (section 5.6).

A device applies the additions and removals of its own set by the rules of section 5.5, as a receiver does. How the devices of a set exchange their records and what they know of other apps is defined with [axt-1024](https://github.com/paxel/axt/issues/26) and [axt-1025](https://github.com/paxel/axt/issues/27), to come; this section defines only how the set is formed and how other apps follow it.

### 5.2 Adding a device

A device of the set, the member, signs the key of a new device into the set. The two devices meet in person, by a QR code on the local network, as two apps do (section 3.2), with the code marked as a join code:

1. The member's user asks it to add a device. The member shows a QR code whose `join` is `true` and listens on the local network ([transports.md](transports.md), sections 3.1 and 4.7).
2. The user of the new installation asks it to join and scans the code. The scan confirms the member's key in person. The new installation connects to the member, and the `HELLO` binds the connection to the scanned key ([transports.md](transports.md), section 4.5).
3. The new installation sends a `DEVICE_JOIN` as its first message in the connection.
4. The member asks its user whether to add the device, and shows the short fingerprint of the new installation's key, which the user SHOULD compare with the one the new installation shows. When the user confirms, the member signs a `DEVICE_ADD` with the proof of the `DEVICE_JOIN`, and sends its chain (section 5.4), which now holds that `DEVICE_ADD`, on the connection.
5. The new installation checks that the chain holds a `DEVICE_ADD` signed with the scanned key, whose `device` is its own key and whose `proof` verifies with its own key over the bytes below, and no `DEVICE_REMOVE` of its own key after it, and verifies the signature of every message of the chain (section 2.3). The `DEVICE_ADD` need not be the last message: the member's chain may have grown since it signed the addition, as when the connection broke off and the new installation asks again. If one of these checks fails, it takes nothing of the chain and tells its user; it sends no `ERROR`, since no code of [protocol.md](protocol.md), section 8.2, is for this case. Otherwise it keeps the chain as its own, and is a device of the set. Every other message of the chain it takes as the history of its set on the word of the member, whose key its user confirmed by the scan; many are signed with keys it has not met.

Both users confirm the addition: the one by scanning, the other by answering the member's question.

A `DEVICE_JOIN` message asks the member to add its sender:

- Its `sender` is the key of the new installation, and it is signed with that key like every message (section 2.2).
- Its `record` MUST be `null`.
- Its body MUST be one `axt.DeviceJoin` in single-object encoding, with the schema [types/axt/DeviceJoin.avsc](../types/axt/DeviceJoin.avsc) and, in envelope format 1, the fingerprint of section 6.

| Field   | Avro type                                  | Content                                                            |
| ------- | ------------------------------------------ | ------------------------------------------------------------------ |
| `to`    | `fixed` of 32 bytes, `axt.DeviceJoinTo`    | The Ed25519 public key of the member, as the join code carried it  |
| `proof` | `fixed` of 64 bytes, `axt.DeviceJoinProof` | The signature of the new key over the member's key and the new key |

A `DEVICE_ADD` message adds a key to the sender's set:

- Its `sender` is the key of the member, a current key of the set, and it is signed with that key like every message.
- Its `record` MUST be `null`.
- Its body MUST be one `axt.DeviceAdd` in single-object encoding, with the schema [types/axt/DeviceAdd.avsc](../types/axt/DeviceAdd.avsc) and, in envelope format 1, the fingerprint of section 6.

| Field    | Avro type                                  | Content                                                            |
| -------- | ------------------------------------------ | ------------------------------------------------------------------ |
| `device` | `fixed` of 32 bytes, `axt.DeviceAddDevice` | The Ed25519 public key of the new device                           |
| `proof`  | `fixed` of 64 bytes, `axt.DeviceAddProof`  | The signature of the new key over the member's key and the new key |

`proof` is, in both messages, the Ed25519 signature of the new installation's private key over:

1. the 18 bytes of the ASCII text `AXT-v1 device add` followed by one zero byte;
2. the 32 bytes of the member's key, the `to` of the `DEVICE_JOIN` and the `sender` of the `DEVICE_ADD`;
3. the 32 bytes of the new key, the `sender` of the `DEVICE_JOIN` and the `device` of the `DEVICE_ADD`.

The proof shows that the new installation holds the new key and joins this member's set. Without it, a member could add the key of another app, and so join that app's records to its own sender (section 5.5). It names the member's key, so that it cannot be used for an addition by any other key. A `DEVICE_ADD` carries no encryption key: the new device sends its own `MANIFEST`, with its own encryption key, relay and mailbox (section 5.6).

A device that gets a `DEVICE_JOIN`:

- MUST act on it only while it shows a join code, only in a live connection that was opened to the address of that code while it showed it, and for at most one new device for each code it shows. It ignores every other `DEVICE_JOIN` without a report: one through a relay, one in a connection that no join code opened, whether it comes before or after the `MANIFEST` of that connection, and one from another key than the first of that code. A repeat from the same key is answered as the first was: the question stays if it is still open, and the chain is sent again if the key is a current key by now. A file never holds a `DEVICE_JOIN` ([transports.md](transports.md), section 2.1);
- ignores it without a report if its `to` is not the device's own key ([protocol.md](protocol.md), section 9.1), before it looks at the proof;
- rejects it if the proof does not verify by section 2.3 over the bytes above, with the message's `sender` as the new key, or if that key is a removed key of the device's set (section 5.3);
- if the key is a current key of its set already, its own key included, answers with its chain and asks no one;
- otherwise MUST ask its user before it signs the `DEVICE_ADD` (step 4). It MUST NOT sign a `DEVICE_ADD` without a `DEVICE_JOIN` it has checked in this way.

The member reports a `DEVICE_JOIN` it rejects, and one its user declines, with the error `DEVICE_REJECTED` on the connection, and then closes the connection ([protocol.md](protocol.md), section 3.3).

**A sent `DEVICE_JOIN` is binding.** The proof is made before the member decides, names no time, and stays valid whatever answer follows: a `DEVICE_REJECTED`, a connection that breaks off, or none.

- From the moment it sends a `DEVICE_JOIN`, an installation MUST reckon with being added by that member at any time. A receiver applies a `DEVICE_ADD` with that proof whenever it gets it (section 5.5), also after the join was declined or failed.
- The installation is a device of the set from the moment it holds a valid `DEVICE_ADD` of its own key, with a proof that verifies with its own key, signed with the key it sent the `DEVICE_JOIN` to, however that message reaches it: in the joining connection, in a later connection, or through a relay. It then asks that member, or another device of the set, for the chain.
- An installation whose join was not completed and whose user no longer wants it MUST take a new signing key before it sends any further message. The new key makes it a new sender, which no proof names. This costs a new installation nothing, since no app knows its key yet; it is why a join belongs at the start of an installation's life.
- A member MUST NOT sign a `DEVICE_ADD` for a join its user declined, and SHOULD discard the proof. The new installation cannot rely on that, which is why the rule above binds it.

### 5.3 Removing a device

A `DEVICE_REMOVE` message removes a key from the sender's set:

- Its `sender` is a current key of the set, and it is signed with that key like every message. It MUST NOT be the key that is removed: a device removes another device, never itself.
- Its `record` MUST be `null`.
- Its body MUST be one `axt.DeviceRemove` in single-object encoding, with the schema [types/axt/DeviceRemove.avsc](../types/axt/DeviceRemove.avsc) and, in envelope format 1, the fingerprint of section 6.

| Field    | Avro type                                     | Content                                      |
| -------- | --------------------------------------------- | -------------------------------------------- |
| `device` | `fixed` of 32 bytes, `axt.DeviceRemoveDevice` | The Ed25519 public key of the removed device |

A removal needs no proof and no consent of the removed device: it serves when a device is lost (section 5.9).

- A device MUST NOT sign the removal of its own key; a receiver rejects it (section 5.5, step 2). An owner who gives up a device removes it with another one, and the only device of a set cannot be removed.
- A removed key is never a key of the set again. An installation that was removed and is to come back generates a new signing key and joins by section 5.2.
- The device that signs a removal, and every device of the set that gets it, keeps it in its chain (section 5.4) and sends its chain again to every app it exchanges with and to the other devices of its set, within the bounds of [protocol.md](protocol.md), section 3.3.
- A device that gets a valid removal of its own key MUST NOT sign any further message with that key, and SHOULD tell its user. What it does with its data is up to the app.

A removal changes who may sign for the sender, and nothing else. The records the removed device sent stay records of the sender (section 5.6). The removed device keeps what it holds: its copy of the data and its own mailbox.

### 5.4 The chain

Each device keeps the additions and removals of its set that it has applied, as the signed messages they are, in the order in which it applied them: its **chain**. A new device takes over the member's chain, which holds its own addition (section 5.2). The chain of an installation that never added a device and was never added is empty.

A receiver that knows a set by one key learns the others from the chain (section 5.5). A device with a chain therefore sends it to each app it exchanges with, oldest message first:

- **In a live connection**, as its first messages, before its `MANIFEST` ([protocol.md](protocol.md), section 3.1), in each of its next three live connections with the app.
- **Through a relay**, three times: at once, before any other message it sends to the app there, and twice more, each after the holding time has passed ([protocol.md](protocol.md), section 3.3).
- **Counted anew when the chain grows.** Whenever a device adds a message to its chain, an addition or a removal that it signs or gets of its own set, it sends the whole chain again, three times in each way, to every app. For an app it begins to exchange with later, the count begins then.
- **No answer ends it.** Nothing acknowledges an addition or a removal, and a device cannot tell from the messages of an app which keys of its set the app knows. It therefore sends the chain the stated number of times and then stops. An app that misses all three sends does not learn the new device from them: it meets the device's key as a first contact and keeps it as a separate sender, until the chain grows and is sent again or a file of the set brings it (section 5.5).

A device sends its whole chain, since it does not know which of its set's keys an app knows. The messages of a chain carry no addressee and are the same for every receiver, so they keep their signatures when another device sends them or a file carries them (section 2.6). They are safe to repeat (section 5.5).

**In a file.** Every file that a device with a chain writes MUST begin with its chain. These `DEVICE_ADD` and `DEVICE_REMOVE` messages are the exception to one sender per file (section 2.5): each is signed with a key of the set, which need not be the key in `axt.sender`. A file MUST NOT hold a `DEVICE_ADD` or a `DEVICE_REMOVE` anywhere but at its start, before every message of another kind, and MUST NOT hold a `DEVICE_JOIN` ([transports.md](transports.md), section 2.1).

### 5.5 Receiving additions and removals

A receiver that gets a `DEVICE_ADD` or a `DEVICE_REMOVE` takes these steps. Below, the signer is the message's `sender` and the device is the key in the body's `device`.

1. It verifies the message's signature with the signer's key (section 2.3).
2. For a `DEVICE_ADD`, it checks the device's key and verifies the proof with it over the bytes of section 5.2, both by section 2.3. If either fails, it rejects the message. It rejects a `DEVICE_REMOVE` whose device is the signer's own key: a device does not remove itself (section 5.3).
3. If the signer is a refused key (section 3.4), it rejects the message without a report. Otherwise, if the signer is not a key of any known sender:
   - a `DEVICE_ADD` whose device is a current key of a known sender adds the signer to that sender: the signer becomes one of its current keys. The proof is the known device's own signature over the signer's key and its own key, so the known device itself vouches that this signer added it. A device that is a removed key vouches for no one: whoever holds a removed key could make such a proof for any key;
   - every other message cannot be placed: an addition or a removal by a key the receiver does not know, about a key that vouches for no one, introduces no one. The receiver does not apply it. Within a chain, it keeps the message and tries it again as the paragraph on a chain below says. Otherwise, and at the end of the chain, it treats the message as any message of an unknown key (section 3.2): it MAY keep it, and takes these steps again if its user accepts the signer's key. An addition or a removal that cannot be placed never makes the receiver ask its user about a first contact; only a message of another kind signed with that key does.
4. Otherwise the signer is a current or a removed key of one known sender, and the table below gives the result.

| The device, for a `DEVICE_REMOVE` another key than the signer (step 2), is  | `DEVICE_ADD`, signer current                                                                                                 | `DEVICE_ADD`, signer removed | `DEVICE_REMOVE`, signer current                   | `DEVICE_REMOVE`, signer removed |
| --------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- | ---------------------------- | ------------------------------------------------- | ------------------------------- |
| a current key of the signer's sender                                        | ignored: a repeat                                                                                                            | ignored: a repeat            | applied                                           | rejected                        |
| a removed key of the signer's sender                                        | ignored: it is not added again                                                                                               | ignored: a repeat            | ignored: a repeat                                 | ignored: a repeat               |
| the only key, current and not removed, of another known sender              | applied; the two senders join                                                                                                | rejected                     | kept within a chain, as below; ignored at its end | rejected                        |
| a current key of another known sender with further keys, current or removed | applied, and the two senders join, if the signer is the only key, current and not removed, of its sender; rejected otherwise | rejected                     | kept within a chain, as below; ignored at its end | rejected                        |
| a removed key of another known sender, or a refused key                     | rejected                                                                                                                     | rejected                     | kept within a chain, as below; ignored at its end | rejected                        |
| a key of no known sender                                                    | applied                                                                                                                      | rejected                     | kept within a chain, as below; ignored at its end | rejected                        |

A receiver MUST NOT ask its user before it applies an addition or a removal. It MAY show a notice, such as that cat-a-log now also runs on another device, or that a device of cat-a-log was removed.

- **Applied addition.** The device becomes a current key of the signer's sender; by step 3, the signer becomes a current key of the device's sender. Everything the receiver keeps of the sender stays as it is. The new key has no encryption key and no manifest until a QR code or a `MANIFEST` signed with it brings them (section 4.2).
- **Applied removal.** The device becomes a removed key of the signer's sender. From then on, the receiver MUST reject every message signed with that key, also one that the removed device sent before the removal and that arrives after it; the repeats of the table are ignored instead. It deletes the kept manifest, the encryption key and the relay of the removed key, MUST NOT send any further message to it, and ends the offers it had from it and made to it ([protocol.md](protocol.md), section 4.3). If the removed key is the connection key of a live connection it is in, it closes that connection. The sender's records, tombstones and versions stay (section 5.6).
- **Removal of a key the sender does not have.** A sender removes only its own keys, and cannot bar a key of another sender or a key the receiver has not met. The removal can, however, have arrived before the addition of its device. Within a chain, the receiver therefore keeps it and tries it again whenever an addition is applied, as the paragraph on a chain below says; through a relay it does so as far as it keeps messages. If the device is still not a key of the signer's sender at the end of the chain, the removal is ignored, whatever else the receiver knows of the key, and applies when the chain is sent again (section 5.3).
- **Ignored.** The receiver does not apply the message, reports no error, and does not reject a file for it. A chain is sent many times, and after a removal it holds messages signed with the removed key; these are the repeats.
- **Rejected.** The receiver does not apply the message. In a live connection it reports it with the error `DEVICE_REJECTED` ([protocol.md](protocol.md), section 3.3); through a relay it sends nothing. In a file, a message rejected by step 2 rejects the whole file; one rejected by the table is not applied, and the reader goes on ([transports.md](transports.md), section 2.2).

The order of the steps matters: a repeat is recognised by the table before the signer's removal counts, so a chain that holds an addition signed with a key removed later is taken without an error, in a connection, through a relay and in a file.

- **A chain.** For a receiver, a chain is a run of `DEVICE_ADD` and `DEVICE_REMOVE` messages, which a message of any other kind ends: in a connection the messages up to the next message of another kind, in a file those at its start, and through a relay those that arrive together, up to the first of another kind. A receiver takes the messages of a chain in their order, each by the steps above with those before it applied. A message that fails step 1 or 2 is rejected for itself; in a connection and through a relay the receiver goes on with the messages after it, and in a file it rejects the whole file. A message that step 3 cannot place is kept, and so is a `DEVICE_REMOVE` by a current key whose device is not a key of the signer's sender. Whenever an addition of the chain is applied, the receiver tries the kept messages again, in their order and until none of them applies, before it takes the next message of the chain; a removal among them applies once its signer and its device are current keys of one sender. A kept message stays kept until it is applied: a try that ignores or rejects it does not end its keeping, and a later try can still apply it. Its result is that of its last try, and a rejection by a later try is not reported ([protocol.md](protocol.md), section 3.3). So a receiver that knows only a later device of a set learns the earlier ones link by link, backwards from the key it knows, and a removal that follows in the chain meets the keys it needs. At the end of the chain it tries the kept messages once more; those it still cannot place are messages of an unknown key (step 3), and a kept removal whose device is still not a key of the signer's sender is ignored. Afterwards, the key that sent the chain, the connection key or the `axt.sender` of a file, is a current key of a known sender, and its further messages are that sender's; or it is a key of no known sender, and the receiver meets it as a first contact (section 3.2); or it is a removed key, and its further messages are rejected (section 3.3).
- **A file whose sender is a later device.** A reader that knows the set by an earlier key follows the chain at the start of the file to the key in `axt.sender`, does not ask its user, and applies the file's records to the sender it knows. Without the chain, it would meet `axt.sender` as a first contact.
- **Order through a relay.** A relay can deliver the messages of a new device before its addition. A receiver SHOULD keep messages from a key it does not know that arrive through a relay for a while before it asks its user about a first contact, so that an addition that arrives later is applied first; once the addition is applied, it drops the question and processes the kept messages as the sender's.
- **Joining two senders.** If the receiver's user has accepted the device's key and the signer's key as first contacts of their own before the addition arrived, the receiver knows one set as two senders; the member's signature and the proof show that they are one. The second sender is the one of the two that has only one key, current and not removed: the device's sender, or, where that has further keys, the signer's. The receiver applies each record and tombstone of the second sender to the other as if a message with that record's version had brought it ([records.md](records.md), sections 5 and 6); a record the other sender does not have becomes one of its records, and of a record that both hold at the same version, the copy of the sender that stays is kept. The sender that stays keeps the app name the receiver shows for it. The second sender's key keeps its kept manifest and its encryption key as a current key of the other sender, and the receiver then forgets the second sender. Local changes its user made to the second sender's copy of a record MAY be lost. Two senders that each have more than one key, or a removed key, are not joined: the addition is rejected, since an installation whose set has, or has had, another device does not join another set (section 5.1).
- **Two devices that remove each other.** Each removal is valid when it is signed. A receiver applies the one it gets first; the other is then signed with a removed key and rejected. Two receivers that get them in different orders keep different devices, and each rejects the messages of the device the other kept. This follows from the rule that every device may remove every other and that the first valid removal a receiver sees applies; no later message brings the two receivers together. A receiver that rejects a removal signed with a removed key SHOULD tell its user.
- **A removal that did not arrive.** A receiver that has not got a removal goes on taking the messages of the removed key, and by step 3 takes a removed key that it has not met as a current one when it gets that key's addition of a device it knows without the removal that followed. The remaining devices therefore send their whole chain again after a removal, as section 5.3 says.

### 5.6 Records, versions and manifests of a set

A set is one sender, so what [records.md](records.md) says of a sender holds for the set as a whole:

- Record ids and versions belong to the set. An id is unique among all records of the set, and one id and version stand for the same message, whichever device signs it ([records.md](records.md), sections 2 and 3). An addition and a removal therefore carry no versions: nothing starts again.
- A receiver applies a record message signed with any current key of the sender to the sender's records by the version rule ([records.md](records.md), section 5.2), and keeps one copy of each record. A record that one device sent is updated or deleted by a message of another device of the set.
- How the devices of a set keep their records and versions in step is defined with [axt-1023](https://github.com/paxel/axt/issues/25) and [axt-1024](https://github.com/paxel/axt/issues/26), to come.

What belongs to one device stays with its key:

- A receiver keeps one manifest for each current key of a sender, each with its own revisions ([manifest.md](manifest.md), section 6), and with it that key's encryption key, relay and mailbox (section 4.2).
- A reply carries in `to` the key that signed the message it answers, and goes to that device ([protocol.md](protocol.md), section 9.1).
- A message that the removed device sent before its removal and that arrives after it is rejected (section 5.5). The remaining devices SHOULD send again the current state of every record for which they have no outcome from that receiver.

### 5.7 Moving to a new device

A move to a new device, such as a new phone, is an addition followed by a removal:

1. The old device adds the new one (section 5.2).
2. The new device takes over what it needs of the app's data. How the data moves is up to the app until [axt-1024](https://github.com/paxel/axt/issues/26) defines the exchange between the devices of a set; it includes the highest version of every record ([records.md](records.md), section 3) and the known senders with their keys.
3. The new device removes the old one (section 5.3). The old device then signs nothing more, and SHOULD delete its private keys.

A receiver applies both steps without asking its user (section 5.5), and the sender's records stay under their ids and versions (section 5.6). The new device has a signing key, an encryption key, a mailbox and manifest revisions of its own; it sends its `MANIFEST` after its chain. Between the two steps both devices are devices of the set, so the owner need not hurry the second.

### 5.8 Restoring the same key

An app MAY carry the signing key itself to a new installation, for example in an encrypted backup that the new installation restores. The new installation is then the same device, with the same key, and no addition is needed. The old installation MUST NOT use the key again (section 2.1). The addition of section 5.2 is for the case in which the key does not leave its device, such as a key kept in a device's protected key store.

### 5.9 A lost device

If a device is lost, stolen, broken or wiped:

- **Another device of the set remains.** The owner removes the lost device with a remaining one (section 5.3). A receiver rejects the lost device's key from the first valid removal it gets. Until then, whoever holds the lost device can sign for the sender, and can remove the remaining devices in turn: every device may remove every other, and a receiver applies the first valid removal it gets (section 5.5). An owner SHOULD therefore remove a lost device at once. A removal also does not undo what the lost device did before it: a key that the lost device added before a receiver got the removal stays a current key at that receiver. The owner's other devices may never learn of such a key, and a receiver that got the removal first rejects the same addition, since it is then signed with a removed key, so receivers can differ here as well. The owner removes such a key with a remaining device once it shows up, in a chain or as the signer of a message. An owner who cannot be sure of the set any more gives it up: new installations with new keys, which every receiver meets as first contacts, as when no device remains. The sender's records stay at every receiver, and the remaining devices go on updating them.
- **No device remains.** If the lost device was the only one of its set, and its key was not restored (section 5.8), nothing can sign for the sender any more. This is by design; an addition without a key of the set would let anyone who claims to be the new phone take over a sender. A new installation is a new sender with a new key, and every receiver meets it as a first contact (section 3.2). The records the old key sent stay with the old sender at every receiver, and no message can update or delete them any more. The new installation MAY send its records again as its own. A receiver identifies records by sender and id ([records.md](records.md), section 2), so they are other records, even under the same ids, and the receiver then holds both. Its user MAY forget the old sender (section 3.4) to remove the old copies.

## 6. Schemas and fingerprints

The schemas of the bodies of `DEVICE_JOIN`, `DEVICE_ADD` and `DEVICE_REMOVE` are [types/axt/DeviceJoin.avsc](../types/axt/DeviceJoin.avsc), [types/axt/DeviceAdd.avsc](../types/axt/DeviceAdd.avsc) and [types/axt/DeviceRemove.avsc](../types/axt/DeviceRemove.avsc). Each follows the rules that [types.md](types.md), section 5, sets for every example type, where they apply to a schema of the specification, as [manifest.md](manifest.md), section 9, says of the manifest: its nested types begin with the schema's name, and it carries no `axt.version`, since it changes only with the envelope format.

Their Parsing Canonical Forms:

```json
{"name":"axt.DeviceJoin","type":"record","fields":[{"name":"to","type":{"name":"axt.DeviceJoinTo","type":"fixed","size":32}},{"name":"proof","type":{"name":"axt.DeviceJoinProof","type":"fixed","size":64}}]}
```

```json
{"name":"axt.DeviceAdd","type":"record","fields":[{"name":"device","type":{"name":"axt.DeviceAddDevice","type":"fixed","size":32}},{"name":"proof","type":{"name":"axt.DeviceAddProof","type":"fixed","size":64}}]}
```

```json
{"name":"axt.DeviceRemove","type":"record","fields":[{"name":"device","type":{"name":"axt.DeviceRemoveDevice","type":"fixed","size":32}}]}
```

| Schema             | Envelope format | CRC-64-AVRO          | As bytes                  |
| ------------------ | --------------- | -------------------- | ------------------------- |
| `axt.DeviceJoin`   | 1               | `0xdff876fab5fecf2f` | `2f cf fe b5 fa 76 f8 df` |
| `axt.DeviceAdd`    | 1               | `0xc60d1ef44b7b3131` | `31 31 7b 4b f4 1e 0d c6` |
| `axt.DeviceRemove` | 1               | `0xd0f57582aab2aadc` | `dc aa b2 aa 82 75 f5 d0` |

## 7. Examples

The values below were produced with [conformance/tools/keys_examples.py](../conformance/tools/keys_examples.py). The script:

- implements Ed25519 with the verification of section 2.3, X25519 and HPKE in Python, and checks them against the test vectors of RFC 8032 (section 7.1, TEST 1), RFC 7748 (section 5.2) and RFC 9180 (appendix A.2.1);
- signs every example with this implementation, with PyNaCl 1.6.2 (libsodium) and with cryptography 50.0.2 (OpenSSL), which give the same signatures, and verifies them with all three;
- builds the messages field by field, compares them with fastavro 1.13.1, and decodes them with fastavro and the Python `avro` package 1.12.2;
- writes the file with fastavro, reads the datum's bytes from its block by hand and verifies them, and reads the file with fastavro and with `avro`;
- opens the sealed message with the HPKE of cryptography 50.0.2, and checks that another `info` or a changed byte does not open;
- checks `axt.DeviceJoin`, `axt.DeviceAdd` and `axt.DeviceRemove` with the schema rules of [conformance/tools/example_types.py](../conformance/tools/example_types.py), and that their names are not defined in another schema of the specification.

The test vectors of [conformance.md](conformance.md) take precedence over these examples.

### 7.1 Test keys

**These keys are for tests only. They are derived from published texts, protect nothing, and MUST NOT be used outside tests.** Each private key, an Ed25519 seed or an X25519 private key, is the SHA-256 of the ASCII text `AXT test key, not for use: ` followed by the label in the table, such as `cat-a-log, old phone, Ed25519`.

| Label                                       | Key                            | Hexadecimal                                                        |
| ------------------------------------------- | ------------------------------ | ------------------------------------------------------------------ |
| `cat-a-log, old phone, Ed25519`             | seed                           | `2b4515a86ea2f9e9948bbb1b38ceb8726df536c021da2c54b91b1288fa2ac24e` |
|                                             | public key                     | `1b84a600f3503e22bbcc99e63202a7194bf6bd69aff1471cce6410d53c26ec4a` |
|                                             | short fingerprint              | `24773 42899 01908 98427 81734`                                    |
| `cat-a-log, new phone, Ed25519`             | seed                           | `daeb74626747506147fb64a839a74b170d7819e7bfaf2ce8dc348a9e5139a8dc` |
|                                             | public key                     | `bc8213b9e5a1325c8ac9877a72555aa19f7b8b6841cbffb9345aad04328e1f7b` |
|                                             | short fingerprint              | `09244 67325 13841 38603 74394`                                    |
| `Old Brain Fix, X25519`                     | private key                    | `8a5e1abca252aefadec7cf0764f52c64b587cdbef900ea3d9046cbf51bc6ed97` |
|                                             | public key                     | `34fa7e71770d8d94c76001ac8d575609f005981f80c115bb7a8fe312687ea40b` |
| `ephemeral key of the sealed message, ikmE` | `ikmE` of HPKE `DeriveKeyPair` | `b134375e247ec8038bc2fb1571a70df4c933a83022c70d19080bc5ce89de8311` |
|                                             | `skE`, derived                 | `4ccbb85253cbd95b84478d2edb1194aaaf35f1a1753721114884779049287323` |
|                                             | `pkE`, derived                 | `ed7a4a213ac37cdffc78372805f51ea53b592174ea7bd2bceacf6b359438b336` |

The script prints further test keys that the examples do not use. The ephemeral key of section 7.4 is derived with HPKE's `DeriveKeyPair` ([RFC 9180, section 7.1.3](https://www.rfc-editor.org/rfc/rfc9180#section-7.1.3)), as in the test vectors of RFC 9180, so that HPKE libraries with a deterministic test interface can reproduce the sealed message. A real sender generates it at random (section 4.3).

### 7.2 A signed DATA message

The `DATA` message of [envelope.md](envelope.md), section 10.2: the Memo with the text `Vet, Tuesday 10:00`, written at 2025-11-15 11:00 in `Europe/Berlin`, as version 1 of the record `0b5a3c1e-4d2f-4a6b-9c8d-7e6f5a4b3c2d`, sent by cat-a-log on the old phone and signed with its key; 210 bytes, SHA-256 `68d19c518a50880136a9f7412d3e636b17422c89cf63837b7ae1a22c8abedfc3`.

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
0054  c3 01 73 ac dc ca 16 0e  body: the Memo, as in spec/envelope.md, section 10.2
      f2 37 24 56 65 74 2c 20
      54 75 65 73 64 61 79 20
      31 30 3a 30 30 d2 1f 16
      1e 16 00 00 00 02 1a 45
      75 72 6f 70 65 2f 42 65
      72 6c 69 6e 02 a0 38 02
      80 d4 a8 ef d0 66
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

The signed bytes, 151 of them, are the prefix of section 2.2 and the bytes `000a` to `0091` of the message:

```text
41 58 54 2d 76 31 20 6d 65 73 73 61 67 65 00 02
08 1b 84 a6 00 f3 50 3e 22 bb cc 99 e6 32 02 a7
19 4b f6 bd 69 af f1 47 1c ce 64 10 d5 3c 26 ec
4a 02 48 30 62 35 61 33 63 31 65 2d 34 64 32 66
2d 34 61 36 62 2d 39 63 38 64 2d 37 65 36 66 35
61 34 62 33 63 32 64 02 7c c3 01 73 ac dc ca 16
0e f2 37 24 56 65 74 2c 20 54 75 65 73 64 61 79
20 31 30 3a 30 30 d2 1f 16 1e 16 00 00 00 02 1a
45 75 72 6f 70 65 2f 42 65 72 6c 69 6e 02 a0 38
02 80 d4 a8 ef d0 66
```

The same message with the record id in upper-case digits names the same record ([envelope.md](envelope.md), section 7), but its bytes differ, and the signature does not verify for them; the script checks this.

### 7.3 The message in a file

The same message in an AXT file with the codec `null` and the sync marker `00 01 … 0f`, as in [envelope.md](envelope.md), section 10.3; 5,112 bytes, SHA-256 `3112dfd846a5bd572299ff9a0be0e42d5cd9aa55ab47d83834b85484a90e5f71`. The metadata holds, in this order, `axt.schemas` (the Memo schema of [envelope.md](envelope.md), section 10.1, as a JSON array without spaces, 2,014 bytes), `axt.sender`, `axt.signature`, `avro.codec` and `avro.schema`.

| What                     | Value                                                                                                                              |
| ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------- |
| SHA-256 of `axt.schemas` | `1108ad5b1f5911e6938b8cdb27db54767aa486d3302ed9c2fea3162b5c8d2385`                                                                 |
| `axt.sender`             | `1b84a600f3503e22bbcc99e63202a7194bf6bd69aff1471cce6410d53c26ec4a`                                                                 |
| `axt.signature`          | `89a017b974a85e6d6d4bff3efe19de530fc27767cb2b67848c53cb8fcec4c1df48ca7a8724d588cb9fe5ebcbc78abf710fbd113bda6a170176f59632f3619300` |

The header's signed bytes, 83 of them: the prefix `AXT-v1 file header` and its zero byte, the key, and the SHA-256 of `axt.schemas`:

```text
41 58 54 2d 76 31 20 66 69 6c 65 20 68 65 61 64
65 72 00 1b 84 a6 00 f3 50 3e 22 bb cc 99 e6 32
02 a7 19 4b f6 bd 69 af f1 47 1c ce 64 10 d5 3c
26 ec 4a 11 08 ad 5b 1f 59 11 e6 93 8b 8c db 27
db 54 76 7a a4 86 d3 30 2e d9 c2 fe a3 16 2b 5c
8d 23 85
```

The file's one block holds one datum, the bytes `000a` to `00d1` of the message of section 7.2. A reader finds its end by reading the envelope's fields in turn: `format` and `kind`, one byte each here; 32 bytes of `sender`; the union index `02`, the id with its length `48` and the version; the body with its length `7c`; and 64 bytes of `signature`. It verifies the signature over the prefix and the datum without its last 64 bytes, the same 151 bytes as in section 7.2.

### 7.4 The message sealed for the relay

The message of section 7.2, sealed for Old Brain Fix's encryption key with the ephemeral key of section 7.1. Old Brain Fix would publish the key in its manifest's `encryption_key` ([manifest.md](manifest.md), section 3.9).

| Value                  | Hexadecimal                                                                                                                          |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `enc`, which is `pkE`  | `ed7a4a213ac37cdffc78372805f51ea53b592174ea7bd2bceacf6b359438b336`                                                                   |
| `shared_secret`        | `39da902e661e8410c3ce9a69037c3f67f82d1c7de7d5a58792baca43bcda2bc4`                                                                   |
| `key_schedule_context` | `00431df6cd95e11ff49d7013563baf7f11588c75a6611ee2a4404a49306ae4cfc51a0cf21422e64d5930d577d298cb7f3ade21cd0a8b48d24bb222eebebf0571fc` |
| `secret`               | `05870c86bd379cad528b54868d12433063d1df2b9a87eadbdf5c3368f209c625`                                                                   |
| `key`                  | `c06224435dd8746e228c29cb8398d7fa42733ef05ebadf09281080ed7caddbaa`                                                                   |
| `base_nonce`           | `7a348d859da32b0b186b5b9b`                                                                                                           |

The plaintext is the 210 bytes of the message, the byte `80` and 813 zero bytes: 1,024 bytes (section 4.4). The sealed message is the byte `01`, the 32 bytes of `enc` and 1,040 bytes of ciphertext: 1,073 bytes, SHA-256 `64a9988bd3e1e8210d592e29115d5b3252d2e75be5c219ca67583608cfdb878a`. Its first and last bytes:

```text
0000  01 ed 7a 4a 21 3a c3 7c df fc 78 37 28 05 f5 1e
0010  a5 3b 59 21 74 ea 7b d2 bc ea cf 6b 35 94 38 b3
0020  36 3d 9d 93 82 94 d6 e9 b9 ff 2e 00 66 51 92 51
      ...
0420  87 7d aa a1 9d f8 bd e3 e1 12 13 73 0b df 59 70
0430  6a
```

The script prints the whole sealed message.

### 7.5 A DEVICE_ADD

cat-a-log's owner adds a new phone to the old one. The new phone's `DEVICE_JOIN` carried the proof; the old phone signs the `DEVICE_ADD` with its key, the test key `cat-a-log, old phone, Ed25519`, and puts the new phone's signing key, the test key `cat-a-log, new phone, Ed25519`, and the proof into it. The message has the kind `DEVICE_ADD`, the old phone's key as its `sender`, no `record`, and as its body one `axt.DeviceAdd` in single-object encoding: the new phone's key in `device` and the proof, signed with the new phone's key. Its length is 217 bytes, its SHA-256 `cfe02dfa2168149a75835448342ec39fd2c95464e22c9d4d1a6666ef4f740bd8`.

```text
0000  c3 01                    single-object marker
0002  16 30 6f 71 b9 ce 9e a8  fingerprint of axt.Envelope, format 1
000a  02                       format: int 1
000b  12                       kind: enum index 9, DEVICE_ADD
000c  1b 84 a6 00 f3 50 3e 22  sender: fixed(32), the old phone's test key
      bb cc 99 e6 32 02 a7 19
      4b f6 bd 69 af f1 47 1c
      ce 64 10 d5 3c 26 ec 4a
002c  00                       record: union index 0, null
002d  d4 01                    body: bytes length 106
002f  c3 01                    body: single-object marker
0031  31 31 7b 4b f4 1e 0d c6  body: fingerprint of axt.DeviceAdd, format 1
0039  bc 82 13 b9 e5 a1 32 5c  body: device: fixed(32), the new phone's test key
      8a c9 87 7a 72 55 5a a1
      9f 7b 8b 68 41 cb ff b9
      34 5a ad 04 32 8e 1f 7b
0059  ee 8c 71 c1 3d 21 cf 98  body: proof: fixed(64), signed with the new phone's key
      2e 63 28 30 a7 1c 37 48
      f7 48 8b 19 23 e3 72 df
      e4 f4 dc 00 ed 6c 15 ac
      43 f2 58 0e d0 34 15 88
      67 63 ef 1c f7 48 dc df
      84 2d fa 19 da 2a e8 b1
      95 71 d1 a4 13 1a b6 0f
0099  ca 99 2f c5 13 50 62 31  signature: fixed(64), signed with the old phone's key
      03 9e 35 d9 32 a4 71 d0
      1b 55 f7 08 cb b6 53 55
      5c 10 22 84 b1 94 1a 63
      0a 76 a6 35 1b 24 4c f2
      95 07 10 2b 01 c3 a0 b5
      ab 23 b1 44 24 df c7 bc
      26 27 d8 61 b2 ed a6 09
00d9  end
```

The proof's signed bytes, 82 of them: the prefix `AXT-v1 device add` and its zero byte, the old phone's key and the new phone's key:

```text
41 58 54 2d 76 31 20 64 65 76 69 63 65 20 61 64
64 00 1b 84 a6 00 f3 50 3e 22 bb cc 99 e6 32 02
a7 19 4b f6 bd 69 af f1 47 1c ce 64 10 d5 3c 26
ec 4a bc 82 13 b9 e5 a1 32 5c 8a c9 87 7a 72 55
5a a1 9f 7b 8b 68 41 cb ff b9 34 5a ad 04 32 8e
1f 7b
```

A receiver that knows cat-a-log by the old phone's key, short fingerprint `24773 42899 01908 98427 81734`, applies the addition without asking its user (section 5.5). From then on it takes messages signed with the new phone's key, short fingerprint `09244 67325 13841 38603 74394`, as cat-a-log's as well. The record of section 7.2 stays with cat-a-log under the same id and version, and either phone can send its next version.

### 7.6 The edges of verification

The script verifies the signatures below with the rule of section 2.3; with the equation of RFC 8032, section 5.1.7, without step 3, once without and once with the cofactor; with libsodium through PyNaCl 1.6.2; and with OpenSSL 4.0.3 through cryptography 50.0.2. The message is the signed bytes of section 7.2. In the signatures with S = k·a or S = r + k·a, k is the hash of step 4 and a the private scalar of the key of cat-a-log's old phone, so only the holder of that key can make them; T is the point of order 8 with the encoding `c7176a70…ac037a` of section 2.3.

| Signature                                                                    | Section 2.3                         | Without step 3, without cofactor | Without step 3, with cofactor | libsodium | OpenSSL |
| ---------------------------------------------------------------------------- | ----------------------------------- | -------------------------------- | ----------------------------- | --------- | ------- |
| The signature of section 7.2                                                 | accepts                             | accepts                          | accepts                       | accepts   | accepts |
| One byte of the message changed                                              | rejects, step 5                     | rejects                          | rejects                       | rejects   | rejects |
| Verified with another key                                                    | rejects, step 5                     | rejects                          | rejects                       | rejects   | rejects |
| S + L in place of S                                                          | rejects, step 1                     | rejects                          | rejects                       | rejects   | rejects |
| R the neutral element, S = k·a                                               | rejects, step 3: R not of order L   | accepts                          | accepts                       | rejects   | accepts |
| R = [r]B + T, S = r + k·a                                                    | rejects, step 3: R not of order L   | rejects                          | accepts                       | rejects   | rejects |
| R the neutral element encoded with y = p + 1, S = k·a                        | rejects, step 2: R not canonical    | rejects                          | rejects                       | rejects   | rejects |
| Key and R the neutral element, S = 0                                         | rejects, step 3: key not of order L | accepts                          | accepts                       | rejects   | accepts |
| Key [a]B + T, R = [r]B, S = r + k·a, k not a multiple of 8                   | rejects, step 3: key not of order L | rejects                          | accepts                       | rejects   | rejects |
| Key the neutral element encoded with y = p + 1, R the neutral element, S = 0 | rejects, step 2: key not canonical  | rejects                          | rejects                       | rejects   | accepts |

The two signatures with the neutral element as key verify for every message under a verifier that accepts them, as OpenSSL does. The two with a component T separate the equation with the cofactor from the one without it. The libsodium of PyNaCl 1.6.2 rejects both; the source of libsodium on its main branch at the time of writing accepts a signature when R − ([S]B − [k]A) has small order, which is the equation with the cofactor. Step 3 makes the answer the same for every library.

## 8. What other documents define

- [protocol.md](protocol.md): the `OFFER` as section 2.4 requires it (section 4 there); the binding of `ACCEPT`, `DECLINE`, `ACK` and `ERROR` to their receiver, and how every kind is made safe to repeat (section 2.6; section 9 there); how a message whose signature does not verify is reported (section 8.3 there); where the chain stands in a connection, how often it is sent, and the error `DEVICE_REJECTED` (sections 5.3 to 5.5; section 3.3 there); the addressee of a reply, which is the key of one device (section 5.6; section 9.1 there).
- [transports.md](transports.md): the QR payload with the signing key, the encryption key, the mailbox and the mark of a join code (sections 3.2 and 5.2; section 3 there); the connection in which a device joins a set (section 5.2; section 4.7 there); the TLS connection on the local network, whose certificate has a key of its own, and the `HELLO` that binds it to the signing key (section 2.2; sections 4.3 and 4.5 there); the chain at the start of a file (section 5.4; section 2.1 there); the mailbox, which is bound to no key (section 4.6; section 5.1 there); the size limit of the relay, which accepts sealed messages up to 17,301,553 bytes (section 4.4; section 5.6 there); the holding time of 14 days (section 4.2; section 5.5 there); and the mailbox of each device of a set (section 5.6; section 5.8 there).

## References

- [Apache Avro 1.12 specification](https://avro.apache.org/docs/1.12.0/specification/)
- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174): key words for requirement levels
- [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869): HKDF
- [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748): X25519
- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032): Ed25519
- [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439): ChaCha20 and Poly1305
- [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180): Hybrid Public Key Encryption
- [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final): SHA-256 and SHA-512
- Kirill Nikitin, Ludovic Barman, Wouter Lueks, Matthew Underwood, Jean-Pierre Hubaux and Bryan Ford: [Reducing Metadata Leakage from Encrypted Files and Communication with PURBs](https://petsymposium.org/popets/2019/popets-2019-0056.php), Proceedings on Privacy Enhancing Technologies, 2019 (4); defines Padmé
