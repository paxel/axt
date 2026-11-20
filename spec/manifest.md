# Manifest

Status: written, 0.1.0. Until 0.1.0 is released, [protocol.md](protocol.md), [keys.md](keys.md) and [transports.md](transports.md) may still change the details this document leaves to them, and the manifest's schema may still change in place; its fingerprint (section 9) and the examples (section 10) are then produced again.

This document defines the manifest: the message in which an app states which types it takes, in which versions, and what it does with their records, or that it takes any type. It defines the manifest's content and schema, its limits, how a sender uses the other app's manifest to choose what it offers, what happens when a manifest changes, and what a file needs to carry one.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 ([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119), [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)) when, and only when, they appear in all capitals, as shown here.

## 1. Terms

- **Manifest**: one datum of the record `axt.Manifest`, carried in the body of a `MANIFEST` message ([envelope.md](envelope.md), section 2.2). It is the statement of one installation, the one whose key is the message's `sender`; the devices of one sender each have a manifest of their own ([keys.md](keys.md), section 5.6).
- **Take**: an app takes a type when it accepts records of that type and does something with them. The manifest names the types an app takes by full name and a range of versions ([types.md](types.md), sections 1 and 3), or states that the app takes any type.
- **Fit**: a type in one version fits a manifest when section 5.2 says so.
- **Purpose sentence**: the sentence an app gives for each type it takes, and for any type, on what it does with the records, such as "An Appointment becomes a Reminder."
- **Sender** and **receiver**: as in [records.md](records.md). In a connection both apps send their manifests, and each is the sender of the records it offers and the receiver of the records the other offers.

## 2. The manifest message

A manifest travels as a `MANIFEST` message:

- Its `record` MUST be `null`: a manifest is not about one record.
- Its body MUST be one `axt.Manifest` in single-object encoding, with the schema [types/axt/Manifest.avsc](../types/axt/Manifest.avsc) and, in envelope format 1, the fingerprint given in section 9.
- An app MUST reject a `MANIFEST` message that carries a `record`, that has an empty body, or whose body has another fingerprint ([envelope.md](envelope.md), section 3.1).

`axt.Manifest` is a schema of the specification, not a type: it is neither offered nor listed in a file's `axt.schemas` ([envelope.md](envelope.md), section 2.3). Each envelope format has exactly one manifest schema, and the schema changes only with a new envelope format. That is why it carries no `axt.version`.

A `MANIFEST` message is signed like every message, as [keys.md](keys.md) defines. An app MUST NOT use a manifest whose signature does not verify. A manifest belongs to the key in its `sender`; the app name and the purpose sentences in it are what that installation says about itself, and an app MUST NOT take the app name as proof of which app sent it.

## 3. Content

| Field            | Avro type                             | Content                                                                        | Section |
| ---------------- | ------------------------------------- | ------------------------------------------------------------------------------ | ------- |
| `revision`       | `long`                                | The revision of the manifest, rising with every change                         | 3.8     |
| `app_name`       | `string`                              | The name the app gives itself                                                  | 3.1     |
| `app_url`        | `["null", "string"]`                  | An https URL of a page about the app, or `null`                                | 3.1     |
| `formats`        | array of `int`                        | The envelope formats the app reads                                             | 3.2     |
| `takes`          | array of `axt.ManifestTake`           | The types the app takes: full name, version range, purpose sentence            | 3.3     |
| `any_type`       | `null` or `axt.ManifestAnyType`       | Whether the app takes every type not in `takes`, with its own purpose sentence | 3.5     |
| `sends`          | `null` or array of `axt.ManifestSend` | The types the app may send, for display; `null` when the app does not say      | 3.7     |
| `encryption_key` | `null` or `axt.ManifestEncryptionKey` | The X25519 public key for messages through a relay, or `null`                  | 3.9     |
| `relay`          | `null` or `axt.ManifestRelay`         | The relay and the mailbox for messages through a relay, or `null`              | 3.10    |

`axt.ManifestTake` has the fields `type`, `min_version`, `max_version`, `purpose` and `purpose_translations`; `axt.ManifestAnyType` has `purpose` and `purpose_translations`; `axt.ManifestSend` has `type`, `min_version`, `max_version` and `proposals`; `axt.ManifestEncryptionKey` is a `fixed` of 32 bytes; `axt.ManifestRelay` has `url` and `mailbox`, a `fixed` of 32 bytes named `axt.ManifestRelayMailbox`. Each field's meaning is also in its `doc` in the schema.

### 3.1 The app

`app_name` is the name the app gives itself, such as `Old Brain Fix`, as plain text on one line (section 4). The other app MAY show it to its user, for example next to the purpose sentences. It does not identify the app; the key does ([keys.md](keys.md)).

`app_url` is `null` or an absolute URL ([RFC 3986](https://www.rfc-editor.org/rfc/rfc3986)) with the scheme `https`, of a page about the app. An app MAY show it to its user; it MUST NOT open it without an action of its user.

### 3.2 Formats

`formats` lists the envelope formats ([envelope.md](envelope.md), section 2.1) in which the app reads messages. It MUST include the format of the envelope that carries the manifest. The other app writes every further message to this app in one of the listed formats; which one is defined in [protocol.md](protocol.md), section 3.2.

A `MANIFEST` is written before the app knows the other's formats. It SHOULD be written in the lowest format the app supports. [protocol.md](protocol.md), section 3.2, defines what happens when the other app cannot read it.

### 3.3 Types taken

Each entry of `takes` names one type the app takes:

- `type` is the type's full name, such as `axt.example.v1.Appointment`. It is matched exactly, as [types.md](types.md), section 4, requires: never through aliases, a similar name or similar fields. An app that takes an app type through an alias of its own reader schema, or through a converter, lists that app type's full name as an entry of its own. The major version is part of the full name, so `axt.example.v1.Note` and `axt.example.v2.Note` are two entries.
- `min_version` and `max_version` give the versions the app takes, both included; `max_version` `null` means every version from `min_version` on. Versions are numbered as section 3.4 says.
- `purpose` and `purpose_translations` say what the app does with the records (section 3.6).

A manifest MUST NOT name a full name twice in `takes`.

The range states which versions the app wants, not which it can decode: every version within a major version resolves against every other ([types.md](types.md), section 3.3). An app sets `min_version` above 1 when it needs a field that earlier versions lack. It SHOULD leave `max_version` `null`, since a later version within the major version only adds fields with defaults, removes fields with defaults, or adds enum symbols, and still resolves against the versions it knows.

### 3.4 The version of a type

The version of a writer schema is the value of its `axt.version` attribute ([types.md](types.md), section 3.2). A schema without `axt.version`, or with an `axt.version` that is not an integer of at least 1, counts as version 1. This is the assumption [types.md](types.md), section 3.2, leaves to this document.

Version 1 is the conservative choice: an app that needs a field added in version 2 sets `min_version` to 2, and a schema that does not say its version, and may lack that field, does not fit. The consequences are that an app type without `axt.version` fits every range that includes 1, and that a receiver cannot tell its versions apart; this is why app types SHOULD carry `axt.version` ([types.md](types.md), section 3.2).

The sender knows the version of each schema it writes. The receiver learns it from the schema JSON in the offer or in the file header ([types.md](types.md), section 3.4).

### 3.5 Any type

When `any_type` is not `null`, the app takes every type whose full name is not in `takes`, in every version, and `any_type`'s purpose sentence says what it does with their records. A receiver that takes any type shows records of a type it does not know from their schema ([types.md](types.md), section 6; [metadata.md](metadata.md)) and reads them with the writer schema alone ([envelope.md](envelope.md), section 6).

`any_type` covers only full names that `takes` does not name. A type named in `takes` in a version outside its range does not fit, even when `any_type` is present (section 5.2): the entry states what the app does with that type, and the app has left out those versions on purpose.

When `any_type` is `null`, the app takes only the types in `takes`.

### 3.6 Purpose sentences and languages

`purpose` is one sentence in English on what the app does with the records. It SHOULD name the type and what the app makes of it, so that it reads on its own, such as "An Appointment becomes a Reminder." or "Any other type becomes a searchable Note."

`purpose_translations` gives the same sentence in other languages: each key is a language tag of [BCP 47](https://www.rfc-editor.org/info/bcp47) ([RFC 5646](https://www.rfc-editor.org/rfc/rfc5646)), such as `de` or `pt-BR`, and each value the sentence in that language.

- A key MUST be a well-formed tag in the `langtag` form of [RFC 5646, section 2.1](https://www.rfc-editor.org/rfc/rfc5646#section-2.1): a language subtag, then optional script, region, variant, extension and private use subtags. Grandfathered tags and tags that consist of private use subtags alone are not allowed.
- A key MUST NOT be `en`, in any case: the English sentence is `purpose`. Regional variants such as `en-GB` are allowed.
- Two keys MUST NOT be equal when compared without regard to case.

The English sentence is a field of its own, not an entry of the map, so that every manifest has a sentence every app can show.

An app that shows a purpose sentence to its user chooses the language by the Lookup scheme of [RFC 4647, section 3.4](https://www.rfc-editor.org/rfc/rfc4647#section-3.4): it matches its user's language priority list against the keys of `purpose_translations` and the tag `en` for `purpose`, without regard to case, and takes `purpose` when nothing matches. A user who reads `de-AT` gets the `de` sentence; a user who reads `fr-CH` and `fr` gets the English one if there is no `fr` sentence.

The app name and the sentences are plain text. An app MUST show them as text and MUST NOT interpret markup in them.

### 3.7 Types sent

`sends` lists the types the app may send, each with the versions it writes. `null` means that the app does not say; an empty array means that it sends no type. A manifest MUST NOT name a full name twice in `sends`. `max_version` `null` means that the app does not say up to which version it writes.

`proposals` says whether the app takes proposals of changes to the records of the type that it sends. Proposals come with [axt-1027](https://github.com/paxel/axt/issues/29); until then an app writes `false`, the field's default, and ignores the field in a manifest it receives.

`sends` is for display only. An app MAY show its user what the other app can send. It does not limit what the app offers: a receiver MUST NOT decline an offer only because its type is not in the sender's `sends`.

### 3.8 Revision

`revision` numbers the states of an app's manifest, as a version numbers the states of a record ([records.md](records.md), section 3):

- A revision MUST be at least 1.
- Each change of the manifest's content MUST get a revision higher than every revision the app has sent before. The app SHOULD add one for each change.
- One revision MUST always stand for the same content.
- The highest revision an app has sent MUST survive what the app's data goes through, including a restore from a backup. Each device of a sender numbers the revisions of its own manifest ([keys.md](keys.md), section 5.6).

Section 6 says how an app uses the revisions of the manifests it receives.

### 3.9 Encryption key

`encryption_key` is the X25519 public key of the installation, with which other apps encrypt the messages they send to it through a relay ([keys.md](keys.md), section 4). It is `null` when the app takes no messages through a relay.

- An app that takes messages through a relay MUST put its current encryption key in its manifest. A new encryption key is a change of the manifest's content and takes a higher revision (section 3.8).
- The manifest is signed with the sender's signing key (section 2), and this binds the encryption key to it. An app takes the encryption key of another app's device from that device's manifest or from a QR code, as [keys.md](keys.md), section 4.2, says.

### 3.10 Relay

`relay` says where other apps put the messages they send to the installation through a relay ([transports.md](transports.md), section 5): `url` is the base URL of the relay, and `mailbox` the id of the installation's mailbox there. It is `null` when the app takes no messages through a relay.

- `relay` and `encryption_key` are both present or both `null`. A sender needs both: the mailbox to put a message into, and the key to seal it for.
- An app that changes its relay or its mailbox puts the new one in a manifest with a higher revision (section 3.8), as it does a new encryption key, and sends that manifest to the apps it exchanges with through the relay ([transports.md](transports.md), section 5.8).
- The manifest is signed with the sender's signing key, so the relay and the mailbox are bound to it as the encryption key is. An app takes the relay and the mailbox of another app from its manifest or from a QR code ([transports.md](transports.md), section 3).

A manifest is the same for every receiver, so every app that holds it, or a file that carries it, knows the mailbox and can put messages into it. [transports.md](transports.md), section 5.6, says what limits this.

## 4. Validity and limits

A manifest is valid when it meets the rules of sections 2 and 3 and these limits:

| What                                                            | Maximum                 |
| --------------------------------------------------------------- | ----------------------- |
| The body of a `MANIFEST` message, single-object header included | 1 MiB (1,048,576 bytes) |
| Entries of `formats`                                            | 16                      |
| Entries of `takes`                                              | 256                     |
| Entries of `sends`                                              | 256                     |
| A full name in `takes` or `sends`                               | 512 bytes               |
| `app_name`                                                      | 256 bytes               |
| `app_url`                                                       | 2,048 bytes             |
| `relay.url`                                                     | 256 bytes               |
| One purpose sentence, in English or another language            | 512 bytes               |
| Entries of one `purpose_translations`                           | 64                      |
| A language tag                                                  | 35 characters           |

The limits of lengths are in bytes of UTF-8, except the language tag, which is ASCII. In addition:

- `revision` is at least 1 (section 3.8).
- `app_name`, every purpose sentence and every value of `purpose_translations` are one line of plain text: not empty, without control characters (Unicode general category Cc, which includes LF and CR), and without the line and paragraph separators U+2028 and U+2029.
- `app_url` is `null` or an absolute URL with the scheme `https` and a host, without spaces or control characters (section 3.1).
- `formats` has at least one entry; its entries are distinct and at least 1, and include the format of the carrying envelope (section 3.2).
- Every `type` in `takes` and `sends` is an Avro full name: names of the form `[A-Za-z_][A-Za-z0-9_]*` joined by dots. No full name appears twice in `takes`, nor twice in `sends`.
- Every `min_version` is at least 1, and every `max_version` is `null` or at least its `min_version`.
- `encryption_key` is `null` or an X25519 key that is not of small order ([keys.md](keys.md), section 4.2).
- `relay` is `null` exactly when `encryption_key` is `null` (section 3.10). Its `url` is an absolute URL with the scheme `https`, a host and a path that ends with `/`, without user information, query, fragment, spaces or control characters ([transports.md](transports.md), section 5.2).
- The keys of every `purpose_translations` meet section 3.6.

An app MUST reject an invalid manifest it receives, with the error `MANIFEST_INVALID` ([protocol.md](protocol.md), section 8.2), and MUST NOT use any part of it. It keeps the manifest it had of the other app before, if any. It MAY check the length of the body before it decodes the body.

The limits are rules of a manifest's content. [envelope.md](envelope.md), section 8, sets the size up to which every message is received and decoded, 16 MiB; this section sets which manifests are valid. A sentence is shown in a list, so 512 bytes are enough for one sentence in any script. The body limit keeps what an app holds of the other apps' manifests small; the manifests of section 10 have bodies of 204 and 438 bytes, and 256 types with ten translations of 100 bytes each come to about 300 KB.

## 5. Using a manifest

### 5.1 When an app sends its manifest

- **Live connection.** Each app MUST send its `MANIFEST` in every live connection, also an app that takes no type: its manifest then has an empty `takes` and `any_type` `null`, and still carries its formats. A sender MUST NOT send an `OFFER` in a connection before it has received a valid `MANIFEST` of the other app in that connection. An app MAY send a new `MANIFEST` with a higher revision during the connection when what it takes changes; it applies from its arrival on. [protocol.md](protocol.md), section 3.1, defines the order of the first messages of a connection.
- **Relay.** Through a relay there is no live connection. An app SHOULD send a `MANIFEST` through the relay whenever its manifest changes, and when [protocol.md](protocol.md), section 15.1, asks for one. A sender offers through the relay by the manifest it keeps of the receiver (section 6).
- **File.** Section 7.

### 5.2 Which types fit

A type with the full name N, in a writer schema of version V (section 3.4), fits a manifest as follows:

1. If `takes` has an entry for N, the type fits when V is at least its `min_version` and, unless its `max_version` is `null`, at most its `max_version`. Its purpose sentence is the entry's. `any_type` is not considered.
2. Otherwise, if `any_type` is not `null`, the type fits, and its purpose sentence is `any_type`'s.
3. Otherwise, the type does not fit.

### 5.3 Offering only what fits

- A sender MUST NOT offer a type in a version that does not fit the receiver's manifest. Updates and deletions follow the same steps as new records ([protocol.md](protocol.md), section 4.3), so this holds for them as well.
- A sender that has several writer schemas of a type's full name MAY pick one whose version fits, such as an older version for a receiver whose `max_version` is below the sender's own. [records.md](records.md), section 3, allows a record to be encoded with another compatible writer schema of the same full name; the fields that version does not have are then not sent.
- A sender SHOULD show its user, for each type it would send, the receiver's purpose sentence in the user's language (section 3.6), before the user chooses what to send.
- What fits is the most a sender may offer. It MAY offer less, for example only the types its user chose.

These rules are about two apps. Between the devices of one device set no type is held back by a manifest: a device offers another device of its set the schemas of every type ([sync.md](sync.md), section 7.2).

### 5.4 The receiver confirms each offer

A fit is not an acceptance. The receiver confirms or declines each offer ([protocol.md](protocol.md), section 5). It MAY decline an offer that fits, for example when the schemas do not resolve ([envelope.md](envelope.md), section 6) or when its user does not want the records.

A receiver judges each offer by the manifest it has at that moment, not by the one it sent: through a relay an offer can arrive after the receiver's manifest has changed. It MUST decline an offer whose type, in the offered version, does not fit its current manifest.

This section is about two apps as well: a device accepts every type that another device of its own set offers, whatever its manifest says ([sync.md](sync.md), section 7.2).

## 6. Changes between connections

An app's manifest changes when what the app takes changes: an update of the app adds a type, its user turns a type off, or the app adds a language.

A sender MAY keep the last valid manifest it has of each app, under that app's key, to use it outside a live connection: to show its user what the other app takes, to write a file for it, or to offer through a relay. It keeps one manifest for each current key of a known sender: each device of a sender has a manifest of its own, with its own revisions, its own `encryption_key` and its own `relay` ([keys.md](keys.md), section 5.6). A manifest signed with one key never replaces the kept manifest of another key, also not of another key of the same sender. A key added to a sender has no kept manifest until a `MANIFEST` signed with it arrives, and the kept manifest of a key is deleted when the key is removed ([keys.md](keys.md), section 5.5). A sender offers to a device by the manifest of that device's key ([protocol.md](protocol.md), section 9.1). The devices of one set pass the kept manifests of their set on to each other, each as the signed message it is, and take a passed-on manifest, one whose `sender` is not the connection key, like one that comes through a relay, only if its revision is higher than that of the kept one; a manifest that a device of the set sends itself in a live connection applies as below, whatever its revision ([sync.md](sync.md), section 13.2). A device also passes the kept manifests of other apps on to the devices of its own set, each as the message it got, inside a `FORWARD` message. A device takes such a manifest as one received outside a live connection, only if its revision is higher than that of the manifest it keeps of that key and it did not take the kept one from that key itself in a live connection, so every device of a set comes to keep the manifest of each device of another app that one of them got ([sync.md](sync.md), sections 19.4 and 20.1).

Which manifest of a key applies:

- **In a live connection**, the manifest received in that connection applies, whatever its revision, and replaces the kept one.
- **Outside a live connection**, through a relay or in a file, a received manifest replaces the kept one only if its revision is higher. One with a lower or equal revision is ignored.

A relay may deliver messages late or out of order, and a user may open an old file again ([records.md](records.md), section 5.2); the revision keeps an older manifest from replacing a newer one in either case. A manifest received in a live connection is current by its nature, so it applies even after the app's revisions went back. Between two apps that exchange only through a relay, revisions that went back would leave the older manifest in place until the revision rises above the kept one; this is why the highest revision MUST survive a restore (section 3.8).

When the manifest of the receiver changes, the sender compares the types that fit before and after:

- **A type no longer fits.** The sender stops offering it, updates and deletions included. The records it has sent stay at the receiver, and [records.md](records.md) still applies to them; what the receiver does with records of a type it no longer takes is up to the receiver. When the type fits again and a new offer of it is accepted ([protocol.md](protocol.md), section 11), the sender SHOULD send the current state of each record of the type that it sent before: a `DATA` with the current version of a record that exists, a `DELETE` with the version of the deletion of one it deleted in between, and, to an app of another user, what it owes that app of each record: nothing of a record that is not shared with it, and a `WITHDRAW` under the version of its withdrawal for one withdrawn from it ([shares.md](shares.md), section 5.3). The version rule ([records.md](records.md), section 5.2) then brings the receiver to the current state.
- **A type now fits.** The sender MAY offer it, as section 5.3 says.
- **A purpose sentence changed.** The sender SHOULD show the new sentence the next time its user chooses what to send.
- **The formats changed.** The sender writes its further messages in a format of the new list ([envelope.md](envelope.md), section 2.1).

## 7. Files

A file has no connection: its reader cannot tell the writer which types it takes before the file is written.

- **Writing.** A writer that keeps a manifest of the app a file is meant for (section 6) SHOULD put only types that fit that manifest into the file, as it would offer them. A file meant for any reader, such as an export, is not filtered.
- **Reading.** A reader MUST NOT apply a record whose type, in the version of its writer schema in `axt.schemas`, does not fit its own current manifest (section 5.2). Like a receiver in a live connection, it MAY take fewer than fit.

A file can also be the first contact between two apps that exchange through a relay afterwards ([keys.md](keys.md), section 3.2). The app that reads such a file needs the writer's manifest to send anything back. Every file may therefore hold a `MANIFEST` message, right after the chain at its start ([transports.md](transports.md), section 2.1); [transports.md](transports.md), section 2.3, says when a writer puts one in. Where a file holds a `MANIFEST`:

- It holds at most one, and it is the writer's own: its `sender` is the key of the file's other messages.
- It is a manifest received outside a live connection, so the revision rule of section 6 applies to it.
- It does not filter or change how the reader applies the file's records; it says what the writer takes, for what the reader sends back.
- Its schema is not in `axt.schemas` (section 2).

The reading rule above is about a file of another app. A device that reads a file of its own device set does not look at whether a type fits its manifest ([sync.md](sync.md), section 13.4).

A file without a `MANIFEST` is complete as far as this document is concerned. A reader MUST NOT reject a file because it holds no `MANIFEST`.

## 8. What other documents define

- [protocol.md](protocol.md): the order of the first messages of a connection (section 3.1 there), how a manifest that cannot be read or is invalid is reported (sections 3.2 and 8.2 there), the `OFFER`, `ACCEPT` and `DECLINE` messages (sections 4 and 5 there), and the choice of the envelope format from the two apps' `formats` (section 3.2 there).
- [keys.md](keys.md): the signature of the `MANIFEST` message, the devices of a sender, each of which has a manifest of its own, and the use of the encryption key.
- [transports.md](transports.md): where a file holds a `MANIFEST` and when a writer puts one in (sections 2.1 and 2.3 there), and the relay and the mailbox that `relay` names (section 5 there). It adds no case to those of section 5.1 in which an app sends a `MANIFEST` through a relay.

## 9. Schema and fingerprint

The schema is [types/axt/Manifest.avsc](../types/axt/Manifest.avsc). It follows the rules that [types.md](types.md), section 5, sets for every example type, where they apply to a schema of the specification: a `doc` on the record, every nested type and every field; names in the required case; nested types defined in place, with names that begin with `Manifest`; only `["null", T]` unions, with the default `null`; and the size and depth limits. Its file name and namespace are those of the schemas of the specification, `types/axt/Manifest.avsc` and `axt`, and it carries no `axt.version` (section 2).

Its Parsing Canonical Form:

```json
{"name":"axt.Manifest","type":"record","fields":[{"name":"revision","type":"long"},{"name":"app_name","type":"string"},{"name":"app_url","type":["null","string"]},{"name":"formats","type":{"type":"array","items":"int"}},{"name":"takes","type":{"type":"array","items":{"name":"axt.ManifestTake","type":"record","fields":[{"name":"type","type":"string"},{"name":"min_version","type":"int"},{"name":"max_version","type":["null","int"]},{"name":"purpose","type":"string"},{"name":"purpose_translations","type":{"type":"map","values":"string"}}]}}},{"name":"any_type","type":["null",{"name":"axt.ManifestAnyType","type":"record","fields":[{"name":"purpose","type":"string"},{"name":"purpose_translations","type":{"type":"map","values":"string"}}]}]},{"name":"sends","type":["null",{"type":"array","items":{"name":"axt.ManifestSend","type":"record","fields":[{"name":"type","type":"string"},{"name":"min_version","type":"int"},{"name":"max_version","type":["null","int"]},{"name":"proposals","type":"boolean"}]}}]},{"name":"encryption_key","type":["null",{"name":"axt.ManifestEncryptionKey","type":"fixed","size":32}]},{"name":"relay","type":["null",{"name":"axt.ManifestRelay","type":"record","fields":[{"name":"url","type":"string"},{"name":"mailbox","type":{"name":"axt.ManifestRelayMailbox","type":"fixed","size":32}}]}]}]}
```

| Schema         | Envelope format | CRC-64-AVRO          | As bytes                  |
| -------------- | --------------- | -------------------- | ------------------------- |
| `axt.Manifest` | 1               | `0xa59eeb4c88a51f3e` | `3e 1f a5 88 4c eb 9e a5` |

The fingerprint and the examples of section 10 were produced with [conformance/tools/manifest_examples.py](../conformance/tools/manifest_examples.py). The script:

- checks the rules of [types.md](types.md), section 5, named above, with the checks of [conformance/tools/example_types.py](../conformance/tools/example_types.py), and that the schema's names are not also defined in [types/axt/Envelope.avsc](../types/axt/Envelope.avsc);
- computes the Parsing Canonical Form and the CRC-64-AVRO fingerprint, and compares them with those of the Python libraries fastavro 1.13.1 and `avro` 1.12.2;
- uses every default of the schema once in schema resolution, with both libraries;
- checks both example manifests against the rules of section 4, and checks that 43 manifests are invalid, each of which breaks one rule or limit and is reported for that alone, among them one within every count and length whose body exceeds 1 MiB;
- checks which types fit (section 5.2), with the language lookup of section 3.6, for each case of section 10.2;
- builds both messages field by field and compares them with fastavro's encoding, decodes both with fastavro and with `avro`, and checks that `avro` encodes the decoded manifests to the same bytes;
- signs both messages with the Ed25519 implementation of [conformance/tools/keys_examples.py](../conformance/tools/keys_examples.py), verifies them, and checks them by their SHA-256 against the messages of [protocol.md](protocol.md), section 17.2.

The test vectors of [conformance.md](conformance.md) take precedence over these values.

## 10. Example

The apps of the example in [README.md](../README.md): cat-a-log, a pet log, sends a vet appointment and the records around it to Old Brain Fix, which turns the appointment into a reminder. The two manifests below illustrate this document; what each app takes in practice is up to the app.

### 10.1 The manifests

cat-a-log takes Pets from other apps and says what it sends. It names no URL and gives its sentence in English only:

```json
{
  "revision": 1,
  "app_name": "cat-a-log",
  "app_url": null,
  "formats": [1],
  "takes": [
    {"type": "axt.example.v1.Pet", "min_version": 1, "max_version": null,
     "purpose": "A Pet becomes an animal in the pet log.", "purpose_translations": {}}
  ],
  "any_type": null,
  "sends": [
    {"type": "axt.example.v1.Pet", "min_version": 1, "max_version": 1, "proposals": false},
    {"type": "axt.example.v1.Appointment", "min_version": 1, "max_version": 1, "proposals": false},
    {"type": "axt.example.v1.Measurement", "min_version": 1, "max_version": 1, "proposals": false},
    {"type": "axt.example.v1.Document", "min_version": 1, "max_version": 1, "proposals": false}
  ],
  "encryption_key": null,
  "relay": null
}
```

Old Brain Fix takes Appointments, Tasks and Notes by name, and any other type. It gives its sentences in English and German and does not say what it sends:

```json
{
  "revision": 1,
  "app_name": "Old Brain Fix",
  "app_url": null,
  "formats": [1],
  "takes": [
    {"type": "axt.example.v1.Appointment", "min_version": 1, "max_version": null,
     "purpose": "An Appointment becomes a Reminder.",
     "purpose_translations": {"de": "Ein Termin wird zu einer Erinnerung."}},
    {"type": "axt.example.v1.Task", "min_version": 1, "max_version": null,
     "purpose": "A Task becomes a Note with a Reminder.",
     "purpose_translations": {"de": "Eine Aufgabe wird zu einer Notiz mit Erinnerung."}},
    {"type": "axt.example.v1.Note", "min_version": 1, "max_version": null,
     "purpose": "A Note becomes a Note.",
     "purpose_translations": {"de": "Eine Notiz wird zu einer Notiz."}}
  ],
  "any_type": {
    "purpose": "Any other type becomes a searchable Note.",
    "purpose_translations": {"de": "Jeder andere Typ wird zu einer durchsuchbaren Notiz."}
  },
  "sends": null,
  "encryption_key": null,
  "relay": null
}
```

### 10.2 What fits

cat-a-log offers to Old Brain Fix. All four types it sends fit, and cat-a-log shows its user Old Brain Fix's sentence for each, here for a user who reads `de-AT`:

| Type                         | Version | Fits by              | Sentence shown                                       |
| ---------------------------- | ------- | -------------------- | ---------------------------------------------------- |
| `axt.example.v1.Pet`         | 1       | `any_type`           | Jeder andere Typ wird zu einer durchsuchbaren Notiz. |
| `axt.example.v1.Appointment` | 1       | the entry in `takes` | Ein Termin wird zu einer Erinnerung.                 |
| `axt.example.v1.Measurement` | 1       | `any_type`           | Jeder andere Typ wird zu einer durchsuchbaren Notiz. |
| `axt.example.v1.Document`    | 1       | `any_type`           | Jeder andere Typ wird zu einer durchsuchbaren Notiz. |

A user who reads `fr-CH` and `fr` sees the English sentences, since there is no `fr` sentence. The user chooses to send only the appointments; cat-a-log offers `axt.example.v1.Appointment`, and Old Brain Fix still accepts or declines the offer (section 5.4).

Old Brain Fix offers to cat-a-log. An `axt.example.v1.Pet` would fit by cat-a-log's entry. An `axt.example.v1.Note` does not fit: cat-a-log names no Note and takes no other type, so Old Brain Fix does not offer it. Neither does a `com.example.Memo` ([envelope.md](envelope.md), section 10.1) fit, whose schema carries no `axt.version` and so counts as version 1 (section 3.4); the same Memo would fit Old Brain Fix's `any_type`.

Had Old Brain Fix listed `axt.example.v1.Appointment` with `min_version` 2, cat-a-log's appointments in version 1 would not fit, although Old Brain Fix takes any type (section 5.2).

### 10.3 The messages

Both messages are `MANIFEST` messages in a live connection, in envelope format 1. cat-a-log signs with its test key of [keys.md](keys.md), section 7.1, Old Brain Fix with its test key of [protocol.md](protocol.md), section 17.1; the messages are those of the exchange in [protocol.md](protocol.md), section 17.2. Offsets are hexadecimal.

cat-a-log's manifest: 319 bytes, of which 208 are the body; SHA-256 `b1305f014fc6a6f5fd33334cb8ecdbe6f7cdaa32b978773f7abcc56cfa45f678`.

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
0039  02                       body: revision: long 1
003a  12                       body: app_name: string length 9
003b  63 61 74 2d 61 2d 6c 6f  body: "cat-a-log"
      67
0044  00                       body: app_url: union index 0, null
0045  02                       body: formats: array block of 1 item
0046  02                       body: formats[0]: int 1
0047  00                       body: formats: end of the array
0048  02                       body: takes: array block of 1 item
0049  24                       body: takes[0].type: string length 18
004a  61 78 74 2e 65 78 61 6d  body: "axt.example.v1.Pet"
      70 6c 65 2e 76 31 2e 50
      65 74
005c  02                       body: takes[0].min_version: int 1
005d  00                       body: takes[0].max_version: union index 0, null
005e  4e                       body: takes[0].purpose: string length 39
005f  41 20 50 65 74 20 62 65  body: "A Pet becomes an animal in the pet log."
      63 6f 6d 65 73 20 61 6e
      20 61 6e 69 6d 61 6c 20
      69 6e 20 74 68 65 20 70
      65 74 20 6c 6f 67 2e
0086  00                       body: takes[0].purpose_translations: end of the map
0087  00                       body: takes: end of the array
0088  00                       body: any_type: union index 0, null
0089  02                       body: sends: union index 1, array
008a  08                       body: sends: array block of 4 items
008b  24                       body: sends[0].type: string length 18
008c  61 78 74 2e 65 78 61 6d  body: "axt.example.v1.Pet"
      70 6c 65 2e 76 31 2e 50
      65 74
009e  02                       body: sends[0].min_version: int 1
009f  02                       body: sends[0].max_version: union index 1, int
00a0  02                       body: sends[0].max_version: int 1
00a1  00                       body: sends[0].proposals: boolean false
00a2  34                       body: sends[1].type: string length 26
00a3  61 78 74 2e 65 78 61 6d  body: "axt.example.v1.Appointment"
      70 6c 65 2e 76 31 2e 41
      70 70 6f 69 6e 74 6d 65
      6e 74
00bd  02                       body: sends[1].min_version: int 1
00be  02                       body: sends[1].max_version: union index 1, int
00bf  02                       body: sends[1].max_version: int 1
00c0  00                       body: sends[1].proposals: boolean false
00c1  34                       body: sends[2].type: string length 26
00c2  61 78 74 2e 65 78 61 6d  body: "axt.example.v1.Measurement"
      70 6c 65 2e 76 31 2e 4d
      65 61 73 75 72 65 6d 65
      6e 74
00dc  02                       body: sends[2].min_version: int 1
00dd  02                       body: sends[2].max_version: union index 1, int
00de  02                       body: sends[2].max_version: int 1
00df  00                       body: sends[2].proposals: boolean false
00e0  2e                       body: sends[3].type: string length 23
00e1  61 78 74 2e 65 78 61 6d  body: "axt.example.v1.Document"
      70 6c 65 2e 76 31 2e 44
      6f 63 75 6d 65 6e 74
00f8  02                       body: sends[3].min_version: int 1
00f9  02                       body: sends[3].max_version: union index 1, int
00fa  02                       body: sends[3].max_version: int 1
00fb  00                       body: sends[3].proposals: boolean false
00fc  00                       body: sends: end of the array
00fd  00                       body: encryption_key: union index 0, null
00fe  00                       body: relay: union index 0, null
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

Old Brain Fix's manifest: 549 bytes, of which 438 are the body; SHA-256 `3af8b09e06d556e993c33d1bf00f744645b8eb7e049c2f91c90f8fec96d23f6a`.

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
0039  02                       body: revision: long 1
003a  1a                       body: app_name: string length 13
003b  4f 6c 64 20 42 72 61 69  body: "Old Brain Fix"
      6e 20 46 69 78
0048  00                       body: app_url: union index 0, null
0049  02                       body: formats: array block of 1 item
004a  02                       body: formats[0]: int 1
004b  00                       body: formats: end of the array
004c  06                       body: takes: array block of 3 items
004d  34                       body: takes[0].type: string length 26
004e  61 78 74 2e 65 78 61 6d  body: "axt.example.v1.Appointment"
      70 6c 65 2e 76 31 2e 41
      70 70 6f 69 6e 74 6d 65
      6e 74
0068  02                       body: takes[0].min_version: int 1
0069  00                       body: takes[0].max_version: union index 0, null
006a  44                       body: takes[0].purpose: string length 34
006b  41 6e 20 41 70 70 6f 69  body: "An Appointment becomes a Reminder."
      6e 74 6d 65 6e 74 20 62
      65 63 6f 6d 65 73 20 61
      20 52 65 6d 69 6e 64 65
      72 2e
008d  02                       body: takes[0].purpose_translations: map block of 1 entry
008e  04                       body: takes[0].purpose_translations key: string length 2
008f  64 65                    body: "de"
0091  48                       body: takes[0].purpose_translations[de]: string length 36
0092  45 69 6e 20 54 65 72 6d  body: "Ein Termin wird zu einer Erinnerung."
      69 6e 20 77 69 72 64 20
      7a 75 20 65 69 6e 65 72
      20 45 72 69 6e 6e 65 72
      75 6e 67 2e
00b6  00                       body: takes[0].purpose_translations: end of the map
00b7  26                       body: takes[1].type: string length 19
00b8  61 78 74 2e 65 78 61 6d  body: "axt.example.v1.Task"
      70 6c 65 2e 76 31 2e 54
      61 73 6b
00cb  02                       body: takes[1].min_version: int 1
00cc  00                       body: takes[1].max_version: union index 0, null
00cd  4c                       body: takes[1].purpose: string length 38
00ce  41 20 54 61 73 6b 20 62  body: "A Task becomes a Note with a Reminder."
      65 63 6f 6d 65 73 20 61
      20 4e 6f 74 65 20 77 69
      74 68 20 61 20 52 65 6d
      69 6e 64 65 72 2e
00f4  02                       body: takes[1].purpose_translations: map block of 1 entry
00f5  04                       body: takes[1].purpose_translations key: string length 2
00f6  64 65                    body: "de"
00f8  60                       body: takes[1].purpose_translations[de]: string length 48
00f9  45 69 6e 65 20 41 75 66  body: "Eine Aufgabe wird zu einer Notiz mit Erinnerung."
      67 61 62 65 20 77 69 72
      64 20 7a 75 20 65 69 6e
      65 72 20 4e 6f 74 69 7a
      20 6d 69 74 20 45 72 69
      6e 6e 65 72 75 6e 67 2e
0129  00                       body: takes[1].purpose_translations: end of the map
012a  26                       body: takes[2].type: string length 19
012b  61 78 74 2e 65 78 61 6d  body: "axt.example.v1.Note"
      70 6c 65 2e 76 31 2e 4e
      6f 74 65
013e  02                       body: takes[2].min_version: int 1
013f  00                       body: takes[2].max_version: union index 0, null
0140  2c                       body: takes[2].purpose: string length 22
0141  41 20 4e 6f 74 65 20 62  body: "A Note becomes a Note."
      65 63 6f 6d 65 73 20 61
      20 4e 6f 74 65 2e
0157  02                       body: takes[2].purpose_translations: map block of 1 entry
0158  04                       body: takes[2].purpose_translations key: string length 2
0159  64 65                    body: "de"
015b  3e                       body: takes[2].purpose_translations[de]: string length 31
015c  45 69 6e 65 20 4e 6f 74  body: "Eine Notiz wird zu einer Notiz."
      69 7a 20 77 69 72 64 20
      7a 75 20 65 69 6e 65 72
      20 4e 6f 74 69 7a 2e
017b  00                       body: takes[2].purpose_translations: end of the map
017c  00                       body: takes: end of the array
017d  02                       body: any_type: union index 1, ManifestAnyType
017e  52                       body: any_type.purpose: string length 41
017f  41 6e 79 20 6f 74 68 65  body: "Any other type becomes a searchable Note."
      72 20 74 79 70 65 20 62
      65 63 6f 6d 65 73 20 61
      20 73 65 61 72 63 68 61
      62 6c 65 20 4e 6f 74 65
      2e
01a8  02                       body: any_type.purpose_translations: map block of 1 entry
01a9  04                       body: any_type.purpose_translations key: string length 2
01aa  64 65                    body: "de"
01ac  68                       body: any_type.purpose_translations[de]: string length 52
01ad  4a 65 64 65 72 20 61 6e  body: "Jeder andere Typ wird zu einer durchsuchbaren Notiz."
      64 65 72 65 20 54 79 70
      20 77 69 72 64 20 7a 75
      20 65 69 6e 65 72 20 64
      75 72 63 68 73 75 63 68
      62 61 72 65 6e 20 4e 6f
      74 69 7a 2e
01e1  00                       body: any_type.purpose_translations: end of the map
01e2  00                       body: sends: union index 0, null
01e3  00                       body: encryption_key: union index 0, null
01e4  00                       body: relay: union index 0, null
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

## References

- [Apache Avro 1.12 specification](https://avro.apache.org/docs/1.12.0/specification/)
- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174): key words for requirement levels
- [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986): URIs
- [RFC 4647](https://www.rfc-editor.org/rfc/rfc4647): matching of language tags
- [RFC 5646](https://www.rfc-editor.org/rfc/rfc5646) ([BCP 47](https://www.rfc-editor.org/info/bcp47)): language tags
