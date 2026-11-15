# AXT: Avro eXchange Transfer

AXT is an open standard that lets small, independent apps exchange typed records with each other.

Status: draft, 0.1.0 in progress. The documents in [spec/](spec/README.md) are stubs or drafts and may still change in incompatible ways. See [CHANGELOG.md](CHANGELOG.md).

## Why

Most small apps are islands. They keep their data in their own format, and the only way to move it into another app is to type it again or to write a converter for that one pair of apps. AXT gives such apps a common way to hand records to each other, so that data entered in one app can be used in another.

An example: an appointment kept in cat-a-log, such as a visit to the vet, is sent to Old Brain Fix, which turns it into a reminder, and to a second-brain app, which makes it findable in its search. None of the three apps needs to know the others' internals; they only need to agree on the record's type.

## How it works

- Every record type is an [Apache Avro](https://avro.apache.org/) schema. Avro 1.12 schema resolution applies: fields are matched by name, and a field the receiver's version of a type adds takes its default.
- In a live connection the schema is sent once with the offer; each record after it carries only a fingerprint of its schema. A file is an Avro object container file with the schema in its header.
- When two apps connect, each sends a manifest of the types it takes and one sentence per type on what it does with them. The sender offers only what fits, and the receiver confirms each offer.
- Every record has a stable id and a version. The sender can send updates and deletions later; the receiver applies them or keeps what its user changed there.
- Every message is signed with the sending app's Ed25519 key. The receiver accepts updates and deletions of a record only with the key it saw first. A key can be moved to a new installation.
- The repository brings example types (Note, Task, Appointment, Person and more) that work without prior agreement. Anyone may evolve or replace them, at the cost of compatibility.

## Three ways to exchange

1. **File**: an AXT file sent through any messenger, mail or file share.
2. **Local network**: a QR code carries the other app's address and public key; the connection is TLS pinned to that key.
3. **Relay**: a sealed mailbox that stores and forwards end-to-end encrypted messages and sees neither their content nor their type. There is no default operator; each app chooses its relay, and anyone can run the reference relay.

## Repository layout

| Path                                  | Content                                        |
| ------------------------------------- | ---------------------------------------------- |
| [spec/](spec/README.md)               | The specification documents                    |
| [types/](types/README.md)             | The example types as Avro schemas              |
| [vectors/](vectors/README.md)         | Test vectors: bytes and their expected meaning |
| [conformance/](conformance/README.md) | The conformance suite every library must pass  |
| [relay/](relay/README.md)             | The reference relay                            |
| [libs/](libs/README.md)               | Libraries, one directory per language          |

## Specification

- [Envelope and encoding](spec/envelope.md)
- [Example types](spec/types.md)
- [Time](spec/time.md)
- [Field metadata](spec/metadata.md)
- [Records](spec/records.md)
- [Manifest](spec/manifest.md)
- [Protocol](spec/protocol.md)
- [Keys, signatures and encryption](spec/keys.md)
- [Transports](spec/transports.md)
- [Relay](spec/relay.md)
- [Conformance](spec/conformance.md)

## Licences

The specification, the example types and the test vectors are published under [CC0 1.0 Universal](LICENSE-CC0). Code (libraries, the reference relay and the conformance suite) is licensed under the [Apache License 2.0](LICENSE-APACHE) or the [MIT License](LICENSE-MIT), at your option. Details are in [LICENSING.md](LICENSING.md).

## Contributing

How to propose types, changes to the specification and libraries is described in [CONTRIBUTING.md](CONTRIBUTING.md).
