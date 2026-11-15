# Keys, signatures and encryption

Status: written, 0.1.0. Until 0.1.0 is released, [protocol.md](protocol.md), [transports.md](transports.md) and [relay.md](relay.md) may still change the details this document leaves to them, and the schema of `axt.KeyMove` may still change in place; its fingerprint (section 6) and the examples (section 7) are then produced again.

This document defines the keys of an installation, how every message is signed and verified, how the schemas a message uses are bound to its sender, how an app meets and remembers another app's key, how messages through a relay are encrypted, and how a key moves to a new installation.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 ([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119), [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)) when, and only when, they appear in all capitals, as shown here.

## 1. Terms

- **Installation**: one copy of an app on one device, with its own data.
- **Signing key**: the Ed25519 key pair ([RFC 8032](https://www.rfc-editor.org/rfc/rfc8032)) of an installation. Its public key is the `sender` of every message the installation sends ([envelope.md](envelope.md), section 2).
- **Encryption key**: the X25519 key pair ([RFC 7748](https://www.rfc-editor.org/rfc/rfc7748)) of an installation, with which other apps encrypt messages to it through a relay (section 4).
- **Sender**: as in [records.md](records.md), section 1: the installation a receiver knows by the key it saw first from it, followed through the key moves of section 5.
- **Known sender**: a sender whose key an app has accepted (section 3.2) and not forgotten (section 3.4). Its **current key** is the key the app accepted last for it; the keys before it are its **moved-from keys**.
- **First contact**: an app gets a message signed with a key that is neither the current key nor a moved-from key of any known sender.
- **Key move**: the change of a sender's signing key to the key of a new installation, announced in a `KEY_MOVE` message signed with the old key (section 5).
- **Short fingerprint**: the 25 digits by which a user compares a key (section 3.1).

## 2. Signatures

### 2.1 The signing key

Every installation has one signing key. It generates the key with a cryptographically secure random number generator, as [RFC 8032, section 5.1.5](https://www.rfc-editor.org/rfc/rfc8032#section-5.1.5) describes, when it first needs one, and keeps the private key on the device.

- An installation MUST sign every message it sends with its signing key, and MUST put the public key in the message's `sender`.
- It MUST use the same key for every receiver. Receivers identify its records by this key and the record id ([records.md](records.md), section 2), and a record has the same id at every receiver.
- Two installations MUST NOT use one signing key at the same time. Both would count as the same sender, and their versions of a record would collide ([records.md](records.md), section 3).

### 2.2 The signed bytes

The signature of a message is the Ed25519 signature of [RFC 8032, section 5.1.6](https://www.rfc-editor.org/rfc/rfc8032#section-5.1.6) (pure Ed25519, not Ed25519ph and not Ed25519ctx) by the sender's private key over these bytes:

1. the 15 bytes `41 58 54 2d 76 31 20 6d 65 73 73 61 67 65 00`, the ASCII text `AXT-v1 message` followed by one zero byte;
2. the envelope in binary encoding without its last 64 bytes, that is, every field from `format` to `body`, as the message carries them.

In a live message, the second part is the bytes from offset 10, after the single-object marker and the envelope fingerprint, up to the last 64 bytes ([envelope.md](envelope.md), section 3). In a file, it is the datum's bytes in the decompressed data block, without its last 64 bytes ([envelope.md](envelope.md), section 4). Both are the same bytes, so a message keeps its signature between a connection, a relay and a file. The signature is the `signature` field, the last 64 bytes.

- A receiver MUST verify a signature over the bytes as it received them. It MUST NOT encode decoded values again to verify them: a decoded value can encode differently, as a UUID received with upper-case digits does ([envelope.md](envelope.md), section 7). An Avro library's file reader returns decoded values; a reader of a file therefore takes the datum's bytes from the block itself. Every field of the envelope is either of fixed length or carries its length in front, so the end of each datum follows from its bytes (section 7.3).
- The single-object marker and the envelope fingerprint of a live message, and the `avro.schema` of a file, are not signed. The `format` field is. A receiver MUST reject a message whose `format` is not the format named by its envelope fingerprint, or in a file by the file's `avro.schema` ([envelope.md](envelope.md), section 2.1).

The prefix separates signatures over AXT messages from every other signature the same key makes: over a file header (section 2.5), in a key move (section 5.1), or in another protocol, such as a TLS handshake if [transports.md](transports.md) uses the key there. Every prefix of this document ends with the only zero byte in it, so none is the beginning of another. Ed25519ctx would do the same with a context string, but not every library implements it; Apple CryptoKit, for example, offers pure Ed25519 only.

### 2.3 Verification

A receiver MUST verify the signature of every message before it uses any field of the message, except to find the message's format and its end. It MUST reject a message whose signature does not verify, as [protocol.md](protocol.md) describes for a message it cannot process, and MUST NOT apply any part of it.

Verification is strict. With A the 32 bytes of `sender`, R the first and S the last 32 bytes of `signature`, M the signed bytes of section 2.2, B the base point, L the order of the base point and p = 2^255 − 19, as in [RFC 8032, section 5.1](https://www.rfc-editor.org/rfc/rfc8032#section-5.1):

1. Read S as a little-endian integer. If S ≥ L, reject.
2. Decode A and R as points, as [RFC 8032, section 5.1.3](https://www.rfc-editor.org/rfc/rfc8032#section-5.1.3) says. If either decoding fails, reject. This rejects every encoding whose y coordinate is p or above, and the encodings with x = 0 and the sign bit set.
3. If A or R is not a point of order L, that is, if it is the neutral element or [L] times it is not the neutral element, reject. This rejects the points of small order and every point with a component of small order.
4. Compute k = SHA-512(R ‖ A ‖ M), read as a little-endian integer, modulo L.
5. Accept if and only if [S]B = R + [k]A. With A and R of order L, this equation holds exactly when the equation with the cofactor, [8][S]B = [8]R + [8][k]A, holds; an implementation MAY check either, and MAY check the first by comparing the encoding of [S]B − [k]A with the 32 bytes of R.

An app MUST also reject a public key that fails step 2 or 3 wherever it gets one: in a QR code, as the new key of a key move, or as the `sender` of a first contact.

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

A `DATA` message names its writer schema only by fingerprint, and a fingerprint is not collision resistant ([envelope.md](envelope.md), section 5); it also leaves out `doc` and every other attribute a receiver shows its user. The schemas themselves are therefore bound to the sender by a signature. In a live connection and through a relay, the `OFFER` ([protocol.md](protocol.md)) is that signature. This document requires of it:

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
- MUST reject a file that holds a message whose `sender` is not the key in `axt.sender`, except the `KEY_MOVE` messages at the start of the file that section 5.2 allows;
- applies section 2.4 to the file: the schemas in a file's `axt.schemas` are the schemas its sender offered for that file.

The values are hexadecimal text because Avro libraries handle metadata values differently: the Python library fastavro 1.13.1, for example, writes only metadata given as text. A text of 64 or 128 ASCII digits passes through every library unchanged.

**One sender per file.** Every message of a file is from the file's sender, the key in `axt.sender`, apart from the `KEY_MOVE` messages of section 5.2. A file is written by one installation, as an export or for one receiver; a relay and a connection carry the messages of one sender each as well, so the rule constrains no transport ([transports.md](transports.md)). It lets a reader confirm one key for the whole file (section 3.2).

**The envelope schema.** `avro.schema` is not signed. A reader MUST compare the Parsing Canonical Form of `avro.schema` byte for byte with the Parsing Canonical Form of a published envelope format, not only its fingerprint, and MUST decode the file's messages with its own copy of that format's schema, never with the schema from the file ([envelope.md](envelope.md), section 4.1). Together with the signed `format` field (section 2.2), the envelope schema is then fixed by this specification, and a forged `avro.schema` with a matching CRC-64-AVRO cannot change how a message is read. `avro.codec` is not signed either; it selects only how blocks are decompressed, and a wrong codec yields bytes whose signatures fail.

**What the header signature does not cover.** A file is not signed as a whole. Messages can be removed from it, repeated, reordered, or put into another file of the same sender with another signed header. Each message stands for itself, and the version rule ([records.md](records.md), section 5.2) gives the same result in any order. A reader MUST NOT conclude from a file that it holds every record of its sender, and MUST NOT take a record that is missing from a file for deleted.

### 2.6 What a signature does not say

- **Whom a message is for.** A signature names the sender, not the receiver. A receiver can pass a signed message on, and the third app then holds a genuine message of the sender. For records this is intended: a sender sends a record under the same id to every receiver, and a file can be forwarded. [protocol.md](protocol.md) MUST bind to their receiver or their connection, in their body, the messages whose replay to another app would matter, such as `ACCEPT`, `DECLINE`, `ACK` and `ERROR`.
- **When it was sent.** A message carries no time. A relay or a user can deliver a message again. Record messages and manifests are safe to repeat by their versions and revisions ([records.md](records.md), section 5.2; [manifest.md](manifest.md), section 6); [protocol.md](protocol.md) MUST make every other kind safe to repeat.
- **Secrecy.** A signature hides nothing. A live connection is encrypted by its transport ([transports.md](transports.md)), a message through a relay as section 4 says, and a file is readable by whoever holds it.

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

- **QR code.** A QR code that the other app shows carries its signing key and, for the relay, its encryption key; [transports.md](transports.md) defines the payload. Scanning it in person is the user's confirmation of the key: the app MAY remember the key without asking again. It MUST check that the messages it then gets from that app are signed with the scanned key; on the local network the pinned TLS key of [transports.md](transports.md) does the same for the connection. The app that showed the code learns the scanner's key from the connection and meets it as a first contact by the next rule.
- **Any other way**: the first message of a file, a connection without a QR code, or a relay message from an unknown key. This is trust on first use. The app MUST verify the message's signature first (section 2.3), and then MUST ask its user before it remembers the key. It shows the app name from a valid `MANIFEST` signed with that key if it has one ([manifest.md](manifest.md), section 3.1), or says that the app has not named itself, and the short fingerprint of the key. The user SHOULD compare the short fingerprint with the one the other app shows.

Until its user accepts the key, the app MUST NOT apply any record signed with it and MUST NOT use a manifest signed with it, except to show the app name. It MAY keep the messages until the user decides, and processes them once the user accepts. If the user declines, it discards them; it MAY remember the key as declined, so that it does not ask again.

A file is confirmed once, for its sender in `axt.sender` (section 2.5). An app MAY ignore relay messages from unknown keys without asking its user, for example when the user expects no new contact; anyone who knows an app's encryption key and mailbox can put messages there.

### 3.3 Known senders

To remember a key, an app keeps for each known sender:

- its current key, and its moved-from keys, each with the key it moved to (section 5);
- its encryption key, if it has one, and where it came from: a QR code, a manifest of a given revision, or a key move (section 4.2);
- the kept manifest ([manifest.md](manifest.md), section 6);
- its records and tombstones ([records.md](records.md), section 5.1).

A message is from a known sender only if its signature verifies (section 2.3) and its `sender` is that sender's current key. An app:

- MUST apply an update or a deletion of a record only from the record's sender, that is, from a message signed with the sender's current key; [records.md](records.md), section 2, identifies a record by its sender and its id;
- MUST reject a message signed with a moved-from key, except the repeat of a key move it has applied, which it ignores (section 5.3);
- treats a message with a key it does not know as a first contact (section 3.2), never as an update or a deletion of a record it has.

### 3.4 Forgetting a sender

An app MAY let its user forget a known sender. It then deletes the sender's keys, its encryption key and its kept manifest. It MAY delete the sender's records and tombstones with them ([records.md](records.md), section 5.3). Records it keeps are no longer records of that sender: no message can update or delete them, and the app treats them as its user's own.

A later message signed with the same key is a first contact (section 3.2), and the sender starts again with no records. A file of the sender opened again can then bring back records the sender had deleted, because the tombstones are gone. An app SHOULD tell its user this before it forgets a sender.

## 4. Encryption for the relay

### 4.1 The construction

A message through a relay is encrypted with HPKE, the Hybrid Public Key Encryption of [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180), in its base mode and with its single-shot interface ([RFC 9180, section 6](https://www.rfc-editor.org/rfc/rfc9180#section-6)), with this cipher suite:

| HPKE part | Algorithm                  | Identifier |
| --------- | -------------------------- | ---------- |
| KEM       | DHKEM(X25519, HKDF-SHA256) | `0x0020`   |
| KDF       | HKDF-SHA256                | `0x0001`   |
| AEAD      | ChaCha20-Poly1305          | `0x0003`   |

The `info` is the 20 bytes of the ASCII text `AXT-v1 relay message`; the associated data is empty.

- **HPKE.** It is X25519 key agreement, a key derivation with HKDF-SHA256 ([RFC 5869](https://www.rfc-editor.org/rfc/rfc5869)) and an AEAD, put together as a published standard with test vectors. Libraries that provide it include OpenSSL from 3.2, BoringSSL, Apple CryptoKit and the Python package cryptography. Where none is at hand, it is built from X25519, HKDF-SHA256 and ChaCha20-Poly1305 as RFC 9180, sections 4 and 5, describe, as [vectors/tools/keys_examples.py](../vectors/tools/keys_examples.py) does.
- **Base mode, a sealed box.** Only the receiver's key goes into the encryption; the sender's key does not. The relay therefore learns nothing about the sender from the ciphertext, and the receiver learns the sender from the signature inside (section 4.3). HPKE's authenticated mode would bind the sender's X25519 key as well, which adds nothing to the signature, and the receiver would need to know which sender's key to use before it could open the message.
- **ChaCha20-Poly1305** ([RFC 8439](https://www.rfc-editor.org/rfc/rfc8439)). HPKE derives the key and the nonce of every message from a fresh ephemeral key, so no nonce is chosen at random, and the 96-bit nonce of ChaCha20-Poly1305 is enough. XChaCha20-Poly1305, whose 192-bit nonce makes random nonces safe, is not an HPKE AEAD and is missing from several platform libraries, among them Apple CryptoKit and the Java standard library. ChaCha20-Poly1305 runs in constant time in software, also on phones without AES instructions, where AES-GCM does not.

### 4.2 The encryption key

Every installation that takes messages through a relay has an encryption key: an X25519 key pair of its own, generated with a cryptographically secure random number generator, separate from its signing key.

The encryption key is not derived from the signing key. An Ed25519 key can be converted into an X25519 key, as libsodium does, but most platform libraries do not offer the conversion, and one key used in two algorithms needs a security analysis of its own that two keys do not. A separate key can also be replaced without changing the sender.

An app takes another app's encryption key only from a source bound to that app's signing key:

- a QR code scanned in person (section 3.2);
- the field `encryption_key` of a valid `MANIFEST` signed with the sender's current key ([manifest.md](manifest.md), section 3.9);
- the field `new_encryption_key` of a confirmed `KEY_MOVE` (section 5.3).

It MUST NOT use an encryption key from any other source. Of these, the latest wins: a manifest replaces the encryption key under the revision rule of [manifest.md](manifest.md), section 6, and a key move replaces it until a manifest of the new installation arrives. A manifest whose `encryption_key` is `null` means that the sender takes no messages through a relay.

An app MUST reject an encryption key of small order: one for which X25519 gives the all-zero value with every private key. Computing X25519 with any one private key, such as the app's own, and comparing the result with 32 zero bytes detects it. A manifest with such a key is invalid ([manifest.md](manifest.md), section 4), and a key move with one is rejected (section 5.3).

An installation MAY replace its encryption key, by a manifest with a higher revision. It SHOULD keep the old private key for as long as the relay may hold messages sealed to it ([relay.md](relay.md)).

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
| 183 (section 7.2)     | 1,024         |
| 1,023                 | 1,024         |
| 1,024                 | 1,088         |
| 4,000                 | 4,096         |
| 100,000               | 100,352       |
| 16,777,216, the limit | 17,301,504    |

The sealed message is 49 bytes longer than the padded message, so the largest is 17,301,553 bytes; [relay.md](relay.md) MUST accept sealed messages up to that size.

The length is what the relay sees of a message besides its mailbox and its time (section 4.6). The minimum of 1,024 bytes gives the small messages, such as an `ACK`, a `DELETE`, a short `DATA` and most manifests, one length; above it, Padmé leaves only the top bits of the length visible and adds less than a sixteenth of the length, 6.25 %.

### 4.5 Opening

A receiver opens a sealed message as follows:

1. If the first byte is not `01`, it rejects the message.
2. It splits the rest into `enc`, the first 32 bytes, and the ciphertext, and opens it with the single-shot `Open` of HPKE, an encryption private key of its own and the parameters of section 4.1, trying its current key first and earlier keys after it (section 4.2). It MUST abort if the X25519 output is the all-zero value. If no key opens the message, it discards it.
3. It removes the zero bytes at the end and the byte `80` before them. It MUST reject a plaintext that does not end with `80` followed only by zero bytes. It need not check the padded length.
4. It processes the result as a live message ([envelope.md](envelope.md), section 3), with the signature verification of section 2.3 and the rules of section 3.

A message that cannot be opened has no sender a receiver could report to; a message that opens but fails later is reported as [protocol.md](protocol.md) describes.

### 4.6 What the relay sees

The relay sees, of each sealed message, the mailbox it is put into ([relay.md](relay.md)), its length, when it is put and fetched, and the network addresses of the apps that put and fetch it, unless they hide them. It does not see the kind, the sender's key, the record, the type, the schema or the content.

The relay can drop, delay, reorder and repeat messages. It cannot read or change one, or make a new one in a sender's name: the AEAD tag fails for a changed message, and the signature for a message made by anyone else. Section 2.6 says how repeats are handled. Whether the relay learns which encryption key a mailbox belongs to is for [relay.md](relay.md) to decide.

## 5. Moving a key

### 5.1 The KEY_MOVE message

A `KEY_MOVE` message announces that the sender's signing key moves to a new installation:

- Its `sender` is the old key, and it is signed with the old key like every message (section 2.2).
- Its `record` MUST be `null`.
- Its body MUST be one `axt.KeyMove` in single-object encoding, with the schema [types/axt/KeyMove.avsc](../types/axt/KeyMove.avsc) and, in envelope format 1, the fingerprint of section 6.

| Field                | Avro type                                                 | Content                                                                 |
| -------------------- | --------------------------------------------------------- | ----------------------------------------------------------------------- |
| `new_sender`         | `fixed` of 32 bytes, `axt.KeyMoveSigningKey`              | The Ed25519 public key of the new installation                          |
| `new_encryption_key` | `null` or `fixed` of 32 bytes, `axt.KeyMoveEncryptionKey` | The X25519 public key of the new installation, or `null` if it has none |
| `proof`              | `fixed` of 64 bytes, `axt.KeyMoveProof`                   | The signature of the new key over the old key and the new key           |

`proof` is the Ed25519 signature of the new installation's private key over:

1. the 16 bytes of the ASCII text `AXT-v1 key move` followed by one zero byte;
2. the 32 bytes of the old key;
3. the 32 bytes of the new key.

The proof shows that the new installation holds the new key, so that a key move cannot name another app's key as its successor. It names the old key, so that it cannot be used for a move from any other key.

### 5.2 Sending a key move

When its user moves the app to a new installation, such as a new phone:

1. The new installation generates its own signing key and encryption key, and makes the proof.
2. The old installation signs the `KEY_MOVE` with its key and hands it to the new installation together with the app's data. How the data moves, such as through a backup or a transfer between the devices, is up to the app. The data includes the highest version of every record and the highest manifest revision ([records.md](records.md), section 3; [manifest.md](manifest.md), section 3.8), and the known senders with their keys.
3. After it has signed the `KEY_MOVE`, the old installation MUST NOT sign any further message with the old key, MUST NOT sign a second `KEY_MOVE`, and MUST delete its private keys.

The new installation sends the `KEY_MOVE` to every app it exchanges with, before any other message signed with the new key: in a live connection where [protocol.md](protocol.md) puts it, and through a relay as the first message. Through a relay it SHOULD send the `KEY_MOVE` again until the receiver has acknowledged it ([protocol.md](protocol.md)).

A key that has moved more than once has a chain of `KEY_MOVE` messages, each signed with the key before. A file signed with the new key SHOULD begin with the chain, oldest first, so that a reader that knows any earlier key can follow it. These `KEY_MOVE` messages are the exception to one sender per file (section 2.5): each is signed with a key of the chain, and the last moves to the key in `axt.sender`. A file MUST NOT hold a `KEY_MOVE` anywhere but at its start, and its chain MUST end at `axt.sender`. Whether a file may hold `KEY_MOVE` messages at all is for [transports.md](transports.md) to decide.

### 5.3 Receiving a key move

A receiver that gets a `KEY_MOVE`:

1. verifies its signature with its `sender`, the old key (section 2.3);
2. if the old key is a moved-from key of a known sender and `new_sender` is the key that sender moved to from it, the message repeats a move the receiver has applied: it ignores the message, without asking its user and without reporting an error, and does not reject a file for it. It rejects a `KEY_MOVE` from a moved-from key to any other key;
3. if the old key is not a key of any known sender, ignores the message: a key move from a key it does not know introduces no one;
4. checks the new key and verifies the proof with it over the bytes of section 5.1, both by section 2.3, and checks the encryption key (section 4.2); it rejects the message if one of them fails;
5. rejects the message if the new key is a moved-from key of any sender, or the current key of a known sender that has moved-from keys of its own. If the new key is the current key of a known sender without moved-from keys, the move joins the two senders (below);
6. MUST ask its user before it applies the move. It shows the sender's app name, says that the app has moved to a new installation, and shows the short fingerprints of the old and the new key; when the move joins two senders, it says so.

When the user confirms, the new key becomes the sender's current key and the old key one of its moved-from keys, and the sender's encryption key becomes `new_encryption_key`; if that is `null`, the sender has no encryption key until a manifest brings one. Everything else the receiver keeps of the sender stays with it: its records, tombstones and versions, and its kept manifest ([manifest.md](manifest.md), section 6).

From then on, the receiver MUST reject every message signed with the old key, except the repeat of the move itself (step 2). A message the old installation sent before the move and that arrives after it is rejected as well; section 5.4 says how the new installation makes up for it.

When the user declines, nothing changes: the sender keeps the old key, and messages signed with the new key are a first contact (section 3.2), which the receiver MAY decline without asking again.

- **A chain.** A reader of a file that begins with a chain of `KEY_MOVE` messages (section 5.2) checks each move by steps 1 to 5 as if the moves before it were applied, and asks its user once, for the move from the key it knows to the last key of the chain. If no move of the chain starts from a key of a known sender, it meets the file's sender as a first contact (section 3.2).
- **Order through a relay.** A relay can deliver messages signed with the new key before the `KEY_MOVE`. A receiver SHOULD keep messages from a key it does not know that arrive through a relay for a while before it asks its user about a first contact, so that a `KEY_MOVE` that arrives later is applied first; once the move is confirmed, it processes them as the sender's.
- **Joining two senders.** If the receiver's user has accepted the new key as a first contact before the move arrived, the receiver knows one installation as two senders; the old key's signature and the proof show that they are one. When its user confirms the move, the receiver applies each record and tombstone of the second sender, the one with the new key, to the moving sender as if a message with that record's version had brought it ([records.md](records.md), sections 5 and 6); a record the moving sender does not have becomes one of its records. It keeps the manifest with the higher revision, with its encryption key (section 4.2), and then forgets the second sender. Local changes its user made to the second sender's copy of a record MAY be lost. Without the join, the old records could not be updated any more, as with a lost key (section 5.6).
- **Two moves from one key.** An old installation that breaks section 5.2 can sign two moves to different keys, and so can a thief of the old device. A confirmed move makes the old key a moved-from key, so a later move from it to another key is rejected (step 2). A receiver that has two different moves from the same key before its user has confirmed either MUST NOT apply either of them, and SHOULD tell its user that the sender's key was moved twice.

### 5.4 Records, versions and manifests after a move

A key move changes the sender's key and nothing else:

- Record ids and versions stay as they are. The new installation continues each record's versions above the highest version the old installation sent ([records.md](records.md), section 3), and its manifest revisions above the highest revision ([manifest.md](manifest.md), section 3.8). A `KEY_MOVE` therefore carries no versions: nothing starts again.
- A receiver keeps its versions and tombstones of the sender's records, and applies the new installation's messages to them by the version rule ([records.md](records.md), section 5.2).
- The new installation SHOULD send again the current state of every record whose last message the receiver has not acknowledged, since a message of the old installation that was still on its way is rejected after the move.
- The kept manifest follows the move ([manifest.md](manifest.md), section 6); its encryption key is replaced by the move's (section 4.2). The new installation SHOULD send its `MANIFEST`, with its encryption key and a higher revision, soon after the `KEY_MOVE`.

### 5.5 Restoring the same key

An app MAY carry the signing key itself to a new installation, for example in an encrypted backup that the new installation restores. The new installation is then the same sender, and no `KEY_MOVE` is needed. The old installation MUST NOT use the key again (section 2.1). A `KEY_MOVE` is for the case in which the key does not leave the old installation, such as a key kept in a device's protected key store.

### 5.6 A lost key

If the old installation is lost, broken or wiped, and its key was neither moved nor restored, no key move is possible: nothing can sign a `KEY_MOVE` with the old key. This is by design; a move without the old key would let anyone who claims to be the new phone take over a sender.

- The new installation is a new sender with a new key, and every receiver meets it as a first contact (section 3.2).
- The records the old key sent stay with the old sender at every receiver, and no message can update or delete them any more.
- The new installation MAY send its records again as its own. A receiver identifies records by sender and id ([records.md](records.md), section 2), so they are other records, even under the same ids, and the receiver then holds both. Its user MAY forget the old sender (section 3.4) to remove the old copies.

## 6. Schema and fingerprint

The schema of the body of a `KEY_MOVE` is [types/axt/KeyMove.avsc](../types/axt/KeyMove.avsc). It follows the rules that [types.md](types.md), section 5, sets for every example type, where they apply to a schema of the specification, as [manifest.md](manifest.md), section 9, says of the manifest: its nested types begin with `KeyMove`, and it carries no `axt.version`, since it changes only with the envelope format.

Its Parsing Canonical Form:

```json
{"name":"axt.KeyMove","type":"record","fields":[{"name":"new_sender","type":{"name":"axt.KeyMoveSigningKey","type":"fixed","size":32}},{"name":"new_encryption_key","type":["null",{"name":"axt.KeyMoveEncryptionKey","type":"fixed","size":32}]},{"name":"proof","type":{"name":"axt.KeyMoveProof","type":"fixed","size":64}}]}
```

| Schema        | Envelope format | CRC-64-AVRO          | As bytes                  |
| ------------- | --------------- | -------------------- | ------------------------- |
| `axt.KeyMove` | 1               | `0xa9e20afea72f2876` | `76 28 2f a7 fe 0a e2 a9` |

## 7. Examples

The values below were produced with [vectors/tools/keys_examples.py](../vectors/tools/keys_examples.py). The script:

- implements Ed25519 with the verification of section 2.3, X25519 and HPKE in Python, and checks them against the test vectors of RFC 8032 (section 7.1, TEST 1), RFC 7748 (section 5.2) and RFC 9180 (appendix A.2.1);
- signs every example with this implementation, with PyNaCl 1.6.2 (libsodium) and with cryptography 50.0.2 (OpenSSL), which give the same signatures, and verifies them with all three;
- builds the messages field by field, compares them with fastavro 1.13.1, and decodes them with fastavro and the Python `avro` package 1.12.2;
- writes the file with fastavro, reads the datum's bytes from its block by hand and verifies them, and reads the file with fastavro and with `avro`;
- opens the sealed message with the HPKE of cryptography 50.0.2, and checks that another `info` or a changed byte does not open;
- checks `axt.KeyMove` with the schema rules of [vectors/tools/example_types.py](../vectors/tools/example_types.py), and that its names are not defined in the envelope or the manifest schema.

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
| `cat-a-log, new phone, X25519`              | private key                    | `1ccea4e9796a140cb9470852567f73767674b3e7d40c1a802f6094bdd55fc4b3` |
|                                             | public key                     | `04c3ae114f9673fe61354502d8d7d646fa37cef5e5900e00ef17808cd15a2355` |
| `Old Brain Fix, X25519`                     | private key                    | `8a5e1abca252aefadec7cf0764f52c64b587cdbef900ea3d9046cbf51bc6ed97` |
|                                             | public key                     | `34fa7e71770d8d94c76001ac8d575609f005981f80c115bb7a8fe312687ea40b` |
| `ephemeral key of the sealed message, ikmE` | `ikmE` of HPKE `DeriveKeyPair` | `b134375e247ec8038bc2fb1571a70df4c933a83022c70d19080bc5ce89de8311` |
|                                             | `skE`, derived                 | `4ccbb85253cbd95b84478d2edb1194aaaf35f1a1753721114884779049287323` |
|                                             | `pkE`, derived                 | `ed7a4a213ac37cdffc78372805f51ea53b592174ea7bd2bceacf6b359438b336` |

The script prints further test keys that the examples do not use. The ephemeral key of section 7.4 is derived with HPKE's `DeriveKeyPair` ([RFC 9180, section 7.1.3](https://www.rfc-editor.org/rfc/rfc9180#section-7.1.3)), as in the test vectors of RFC 9180, so that HPKE libraries with a deterministic test interface can reproduce the sealed message. A real sender generates it at random (section 4.3).

### 7.2 A signed DATA message

The `DATA` message of [envelope.md](envelope.md), section 10.2: the Memo `{"text": "Vet, Tuesday 10:00", "written": 1763200800000}` as version 1 of the record `0b5a3c1e-4d2f-4a6b-9c8d-7e6f5a4b3c2d`, sent by cat-a-log on the old phone and signed with its key; 183 bytes, SHA-256 `c6901788f627c534b72f85e50165db1ee77aa89549f9713d5cbb2a2119b1ee83`. Offsets are hexadecimal.

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
002e  30 62 35 61 33 63 31 65  "0b5a3c1e-4d2f-4a6b-9c8d-7e6f5a4b3c2d"
      2d 34 64 32 66 2d 34 61
      36 62 2d 39 63 38 64 2d
      37 65 36 66 35 61 34 62
      33 63 32 64
0052  02                       record.version: long 1
0053  46                       body: bytes length 35
0054  c3 01 68 b3 56 68 0c e4  body: the Memo, as in spec/envelope.md, section 10.2
      1c b7 24 56 65 74 2c 20
      54 75 65 73 64 61 79 20
      31 30 3a 30 30 80 d4 a8
      ef d0 66
0077  33 87 5e 5e 5b 36 d7 df  signature: fixed(64)
      ac ea 9f e1 83 e4 11 8b
      2b ef f6 e6 1e b1 36 7e
      53 a3 3c 74 d3 2e 20 53
      9e 2e c5 15 ee 75 d9 66
      52 8e b6 8f bc 88 d4 09
      4c fa 1f 48 2f eb 6c 24
      ce 1e 5c 2f f6 c1 50 03
00b7  end
```

The signed bytes, 124 of them, are the prefix of section 2.2 and the bytes `000a` to `0076` of the message:

```text
41 58 54 2d 76 31 20 6d 65 73 73 61 67 65 00 02
08 1b 84 a6 00 f3 50 3e 22 bb cc 99 e6 32 02 a7
19 4b f6 bd 69 af f1 47 1c ce 64 10 d5 3c 26 ec
4a 02 48 30 62 35 61 33 63 31 65 2d 34 64 32 66
2d 34 61 36 62 2d 39 63 38 64 2d 37 65 36 66 35
61 34 62 33 63 32 64 02 46 c3 01 68 b3 56 68 0c
e4 1c b7 24 56 65 74 2c 20 54 75 65 73 64 61 79
20 31 30 3a 30 30 80 d4 a8 ef d0 66
```

The same message with the record id in upper-case digits names the same record ([envelope.md](envelope.md), section 7), but its bytes differ, and the signature does not verify for them; the script checks this.

### 7.3 The message in a file

The same message in an AXT file with the codec `null` and the sync marker `00 01 … 0f`, as in [envelope.md](envelope.md), section 10.3; 2,793 bytes, SHA-256 `c19b87302bdea31721a5dc5247effbaa57feb1289f74a5d77ec233f0e6796fa4`. The metadata holds, in this order, `axt.schemas` (the Memo schema of [envelope.md](envelope.md), section 10.1, as a JSON array without spaces, 308 bytes), `axt.sender`, `axt.signature`, `avro.codec` and `avro.schema`.

| What                     | Value                                                                                                                              |
| ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------- |
| SHA-256 of `axt.schemas` | `a4f86183d65632511014faa8d89bdb4a12e911d1e0a160affe9da4e30017b188`                                                                 |
| `axt.sender`             | `1b84a600f3503e22bbcc99e63202a7194bf6bd69aff1471cce6410d53c26ec4a`                                                                 |
| `axt.signature`          | `edd02ed03eea22c8586d1dddf330cd88edc1abf3c2664941cde1cb7fad1126ec811a9908a25ae76d02235fc8495f6c9b9bf3dec86dd443d1bf77e03d9d355506` |

The header's signed bytes, 83 of them: the prefix `AXT-v1 file header` and its zero byte, the key, and the SHA-256 of `axt.schemas`:

```text
41 58 54 2d 76 31 20 66 69 6c 65 20 68 65 61 64
65 72 00 1b 84 a6 00 f3 50 3e 22 bb cc 99 e6 32
02 a7 19 4b f6 bd 69 af f1 47 1c ce 64 10 d5 3c
26 ec 4a a4 f8 61 83 d6 56 32 51 10 14 fa a8 d8
9b db 4a 12 e9 11 d1 e0 a1 60 af fe 9d a4 e3 00
17 b1 88
```

The file's one block holds one datum, the bytes `000a` to `00b6` of the message of section 7.2. A reader finds its end by reading the envelope's fields in turn: `format` and `kind`, one byte each here; 32 bytes of `sender`; the union index `02`, the id with its length `48` and the version; the body with its length `46`; and 64 bytes of `signature`. It verifies the signature over the prefix and the datum without its last 64 bytes, the same 124 bytes as in section 7.2.

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

The plaintext is the 183 bytes of the message, the byte `80` and 840 zero bytes: 1,024 bytes (section 4.4). The sealed message is the byte `01`, the 32 bytes of `enc` and 1,040 bytes of ciphertext: 1,073 bytes, SHA-256 `6be58e45f035eed7f4e3feb8fec0b59f00f74f93122015d22e6133bc65d187e7`. Its first and last bytes:

```text
0000  01 ed 7a 4a 21 3a c3 7c df fc 78 37 28 05 f5 1e
0010  a5 3b 59 21 74 ea 7b d2 bc ea cf 6b 35 94 38 b3
0020  36 3d 9d f8 be 1f 42 1f 9f 80 24 00 66 51 92 51
      ...
0420  87 85 f7 81 93 1b 9c a7 65 4e bb ba 57 5f 24 cd
0430  29
```

The script prints the whole sealed message.

### 7.5 A KEY_MOVE

cat-a-log moves from the old phone to the new one. The message is signed with the old key and carries the new phone's signing key, its encryption key and the proof; 250 bytes, SHA-256 `a4e2e8662beb27b3b4df70d1840fe8f58cbfac501a8f937a197f729028180bea`.

```text
0000  c3 01                    single-object marker
0002  7d 0c e4 e5 4f e8 e1 a2  fingerprint of axt.Envelope, format 1
000a  02                       format: int 1
000b  10                       kind: enum index 8, KEY_MOVE
000c  1b 84 a6 00 f3 50 3e 22  sender: fixed(32), the old key
      bb cc 99 e6 32 02 a7 19
      4b f6 bd 69 af f1 47 1c
      ce 64 10 d5 3c 26 ec 4a
002c  00                       record: union index 0, null
002d  96 02                    body: bytes length 139
002f  c3 01                    body: single-object marker
0031  76 28 2f a7 fe 0a e2 a9  body: fingerprint of axt.KeyMove, format 1
0039  bc 82 13 b9 e5 a1 32 5c  body: new_sender: fixed(32), the new installation's test key
      8a c9 87 7a 72 55 5a a1
      9f 7b 8b 68 41 cb ff b9
      34 5a ad 04 32 8e 1f 7b
0059  02                       body: new_encryption_key: union index 1, axt.KeyMoveEncryptionKey
005a  04 c3 ae 11 4f 96 73 fe  body: new_encryption_key: fixed(32)
      61 35 45 02 d8 d7 d6 46
      fa 37 ce f5 e5 90 0e 00
      ef 17 80 8c d1 5a 23 55
007a  4b 98 c1 12 63 9c 50 f3  body: proof: fixed(64), signed with the new key
      51 b2 c5 8f f6 e4 95 c8
      e2 0e 7a 1b 74 1d 12 3e
      2b d7 6d eb f3 05 68 b8
      f1 04 5c 1d 36 9d bb 9f
      6d 30 6f 6e 13 d3 da d8
      72 c9 38 57 85 f6 a4 65
      27 ae 72 9b d8 1d 8d 0f
00ba  7b cf 5a 34 f7 f5 5f 06  signature: fixed(64), signed with the old key
      7f 7a fb 08 7b bb bd b1
      cb 96 2c 7a f8 54 05 c6
      ac cf ac eb 9b 76 07 70
      d0 de f5 74 0f 01 ae 96
      b2 8a 9a 64 77 e7 5b 58
      2c 58 50 13 62 e9 f2 5c
      3c 41 3a 98 17 92 7f 0c
00fa  end
```

The proof's signed bytes, 80 of them: the prefix `AXT-v1 key move` and its zero byte, the old key and the new key:

```text
41 58 54 2d 76 31 20 6b 65 79 20 6d 6f 76 65 00
1b 84 a6 00 f3 50 3e 22 bb cc 99 e6 32 02 a7 19
4b f6 bd 69 af f1 47 1c ce 64 10 d5 3c 26 ec 4a
bc 82 13 b9 e5 a1 32 5c 8a c9 87 7a 72 55 5a a1
9f 7b 8b 68 41 cb ff b9 34 5a ad 04 32 8e 1f 7b
```

A receiver that knows cat-a-log by the old key shows its user the app name, `24773 42899 01908 98427 81734` as the old and `09244 67325 13841 38603 74394` as the new short fingerprint, and on confirmation takes the new key and the new encryption key (section 5.3). The record of section 7.2 stays with cat-a-log under the same id and version.

### 7.6 The edges of verification

The script verifies the signatures below with the rule of section 2.3; with the equation of RFC 8032, section 5.1.7, without step 3, once without and once with the cofactor; with libsodium through PyNaCl 1.6.2; and with OpenSSL 4.0.3 through cryptography 50.0.2. The message is the signed bytes of section 7.2. In the signatures with S = k·a or S = r + k·a, k is the hash of step 4 and a the private scalar of cat-a-log's old key, so only the holder of that key can make them; T is the point of order 8 with the encoding `c7176a70…ac037a` of section 2.3.

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

- [protocol.md](protocol.md): the `OFFER` as section 2.4 requires it; the binding of `ACCEPT`, `DECLINE`, `ACK` and `ERROR` to their receiver, and how every kind is made safe to repeat (section 2.6); how a message whose signature does not verify is reported; where a `KEY_MOVE` stands in a connection, and its acknowledgement (section 5.2).
- [transports.md](transports.md): the QR payload with the signing key and the encryption key (section 3.2); the TLS connection on the local network with the pinned key, and whether its certificate uses the signing key (section 2.2); whether a file may hold `KEY_MOVE` messages (section 5.2).
- [relay.md](relay.md): the mailbox, and whether it is bound to an encryption key (section 4.6); the size limit, which accepts sealed messages up to 17,301,553 bytes (section 4.4); how long the relay holds messages (section 4.2).

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
