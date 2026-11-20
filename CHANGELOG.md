# Changelog

All notable changes to AXT are documented in this file.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [0.1.0]

### Added

- The repository skeleton with its licences, contribution rules and spec index. ([axt-1000](https://github.com/paxel/axt/issues/1))
- The envelope: every message is a signed `axt.Envelope`, sent live in single-object encoding and in files as an Avro container. ([axt-1001](https://github.com/paxel/axt/issues/2))
- Eight example types under `axt.example.v1`, with the rules for naming, versioning and replacing types. ([axt-1002](https://github.com/paxel/axt/issues/3))
- The time types `axt.Date`, `axt.Time`, `axt.DateTime` and `axt.Duration`, with time zones, partial dates and duration arithmetic. ([axt-1016](https://github.com/paxel/axt/issues/17))
- Field metadata: translated labels, help, emoji, formats, I-Regexp patterns and limits, with the error `VALUE_INVALID` naming the field. ([axt-1017](https://github.com/paxel/axt/issues/18))
- The example types hold their times in the time types and carry labels, help, emoji and checks in English and German. ([axt-1018](https://github.com/paxel/axt/issues/19))
- Records with a stable id and a rising version, sent whole, with updates, deletions and the receiver's own changes. ([axt-1003](https://github.com/paxel/axt/issues/4))
- The manifest, in which an app names the types it takes and what it does with them. ([axt-1004](https://github.com/paxel/axt/issues/5))
- Ed25519 signatures, relay encryption with HPKE and trust on first use. ([axt-1006](https://github.com/paxel/axt/issues/7))
- The protocol of offer, accept, decline, data, acknowledgement and errors. ([axt-1005](https://github.com/paxel/axt/issues/6))
- Three transports: a file, the local network found by QR code, and a relay. ([axt-1007](https://github.com/paxel/axt/issues/8))
- Test vectors for every category, the time types and invalid values among them, and a conformance runner with a reference adapter. ([axt-1009](https://github.com/paxel/axt/issues/10), [axt-1019](https://github.com/paxel/axt/issues/20))
- The reference relay, a sealed mailbox anyone can run. ([axt-1008](https://github.com/paxel/axt/issues/9))
- Device sets: an owner's devices, each with its own key, count as one sender, joined by QR code and removable by any other. ([axt-1022](https://github.com/paxel/axt/issues/24))
- Stamps: every device of an owner changes every record, the later change wins per field, and a record's version is its state stamp. ([axt-1023](https://github.com/paxel/axt/issues/25))
- Sibling sync: an owner's devices send each other only the changed fields of a record, track acknowledgements, and can ask for everything again. ([axt-1024](https://github.com/paxel/axt/issues/26))

---

Historical changes have been moved to [OLDER_CHANGES.md](OLDER_CHANGES.md).
