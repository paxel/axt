# Changelog

All notable changes to AXT are documented in this file.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [0.1.0]

### Added

- The repository skeleton: the directories for the specification, the example types, the test vectors, the conformance suite, the reference relay and the libraries, each with a README; an index of the specification documents as drafts; the licences (CC0 1.0 for the specification, types and vectors; Apache-2.0 OR MIT for code) and the rules for proposing types, specification changes and libraries. ([axt-1000](https://github.com/paxel/axt/issues/1))
- The envelope and encoding: every message is an `axt.Envelope` (format version, kind, sender key, record id and version, body, signature), sent in a live connection in Avro single-object encoding with the schema once in the offer, and stored in a file as an Avro object container file (codec `null` or `deflate`) with the record schemas in its header; the CRC-64-AVRO fingerprints, Avro 1.12 schema resolution, the representation of strings, times and UUIDs, size limits, the media type `application/vnd.axt` and the extension `.axt`, and annotated example bytes. ([axt-1001](https://github.com/paxel/axt/issues/2))
