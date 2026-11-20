# AXT: Avro eXchange Transfer

[![CI](https://github.com/paxel/axt/actions/workflows/ci.yml/badge.svg?branch=summer)](https://github.com/paxel/axt/actions/workflows/ci.yml)
[![Security](https://github.com/paxel/axt/actions/workflows/security.yml/badge.svg?branch=summer)](https://github.com/paxel/axt/actions/workflows/security.yml)
[![CodeQL](https://github.com/paxel/axt/actions/workflows/codeql.yml/badge.svg?branch=summer)](https://github.com/paxel/axt/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/paxel/axt/badge)](https://scorecard.dev/viewer/?uri=github.com/paxel/axt)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=paxel_axt&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=paxel_axt)
[![Coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fpaxel%2Faxt%2Fsummer%2F.github%2Fbadges%2Fcoverage-python.json)](coverage-floors.toml)
[![Fuzz](https://github.com/paxel/axt/actions/workflows/fuzz.yml/badge.svg?branch=summer)](https://github.com/paxel/axt/actions/workflows/fuzz.yml)
[![Release](https://img.shields.io/github/v/release/paxel/axt)](https://github.com/paxel/axt/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT%20%C2%B7%20CC0--1.0-blue)](LICENSING.md)

AXT is an open standard that lets small, independent apps exchange typed records with each other.

Status: draft, 0.1.0 in progress. The documents in [spec/](spec/README.md) are stubs or drafts and may still change in incompatible ways. See [CHANGELOG.md](CHANGELOG.md).

## Why

Most small apps are islands. They keep their data in their own format, and the only way to move it into another app is to type it again or to write a converter for that one pair of apps. AXT gives such apps a common way to hand records to each other, so that data entered in one app can be used in another.

An example: an appointment kept in cat-a-log, such as a visit to the vet, is sent to Old Brain Fix, which turns it into a reminder, and to a second-brain app, which makes it findable in its search. None of the three apps needs to know the others' internals; they only need to agree on the record's type.

## How it works

- Every record type is an [Apache Avro](https://avro.apache.org/) schema. Avro 1.12 schema resolution applies: fields are matched by name, and a field the receiver's version of a type adds takes its default.
- In a live connection the schema is sent once with the offer; each record after it carries only a fingerprint of its schema. A file is an Avro object container file with the schema in its header.
- When two apps connect, each sends a manifest of the types it takes and one sentence per type on what it does with them. The sender offers only what fits, and the receiver confirms each offer.
- Every record has a stable id and a version. The sender can send updates and deletions later; the receiver applies them or keeps what its user changed there. An owner can change a record on any of their devices: each change carries a stamp from a clock that never runs backwards, and per field the later change wins. Between the owner's devices only the changed fields travel, and each device sends another what that one has not acknowledged. Another app has to reach only one of the owner's devices: that device passes the record on to the others, and what the owner changes in it shows on all of them.
- To another user, only what the owner chose beforehand leaves: the owner shares single records, or the records a rule of the app picks, with each other user's app, and can withdraw a record again. The other app removes its copy, or keeps it if its user changed it.
- Every message is signed with the sending app's Ed25519 key. The receiver accepts updates and deletions of a record only from the sender it has the record from. The devices of one owner each have a key of their own and count as one sender: a device adds a new one, and any device can remove another, such as a lost one.
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
- [Sync between the devices of one owner](spec/sync.md)
- [Shares between users](spec/shares.md)
- [Transports](spec/transports.md)
- [Relay](spec/relay.md)
- [Conformance](spec/conformance.md)

## Licences

The specification, the example types and the test vectors are published under [CC0 1.0 Universal](LICENSE-CC0). Code (libraries, the reference relay and the conformance suite) is licensed under the [Apache License 2.0](LICENSE-APACHE) or the [MIT License](LICENSE-MIT), at your option. Details are in [LICENSING.md](LICENSING.md).

## Contributing

How to propose types, changes to the specification and libraries is described in [CONTRIBUTING.md](CONTRIBUTING.md).
