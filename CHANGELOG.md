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
- Ed25519 signatures, relay encryption with HPKE, trust on first use and moving a key to a new installation. ([axt-1006](https://github.com/paxel/axt/issues/7))
- The protocol of offer, accept, decline, data, acknowledgement and errors. ([axt-1005](https://github.com/paxel/axt/issues/6))
- Three transports: a file, the local network found by QR code, and a relay. ([axt-1007](https://github.com/paxel/axt/issues/8))
- Test vectors for every category and a conformance runner with a reference adapter. ([axt-1009](https://github.com/paxel/axt/issues/10))
- The reference relay, a sealed mailbox anyone can run. ([axt-1008](https://github.com/paxel/axt/issues/9))
