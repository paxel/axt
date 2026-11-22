# Changelog

All notable changes to AXT are documented in this file.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [0.2.0]

### Added

- A documentation site on GitHub Pages with five tracks: Start, Design an app, Implement a library, Run a relay and Specification. ([axt-1029](https://github.com/paxel/axt/issues/37))
- The specification on the site, every section reference linked to its section. ([axt-1030](https://github.com/paxel/axt/issues/38))
- Reference pages for every schema and example type with fingerprints, the glossary, and the error codes and outcomes. ([axt-1031](https://github.com/paxel/axt/issues/39))
- The Start track: what AXT is, how an exchange goes, its concepts, the libraries and what is new. ([axt-1032](https://github.com/paxel/axt/issues/40))
- The Design an app track: types and their versions, field metadata, the manifest, records, devices, shares and proposals. ([axt-1033](https://github.com/paxel/axt/issues/41))
- The Implement a library track: what a library implements and in what order, the adapter, the suite and the library's repository. ([axt-1034](https://github.com/paxel/axt/issues/42))
- The Run a relay track: running the reference relay behind a proxy, its logs and limits, and a relay of one's own. ([axt-1035](https://github.com/paxel/axt/issues/43))
- Relations on every example type, with the published type `axt.Relation`, and their cases in the `types` vectors. ([axt-1037](https://github.com/paxel/axt/issues/45))
- Typed fields as Avro bricks, `axt.Field` with one brick per value kind and per format, each with its checks. ([axt-1043](https://github.com/paxel/axt/issues/51))
- Offers and files carry each type as a description of bricks, from which its schema is derived; the new vector category `bricks` tests it. ([axt-1044](https://github.com/paxel/axt/issues/52))
- The relation brick `axt.RelationField`: a field of relations, each an `axt.Relation`, in any type, with its rules and limits and `bricks` vectors. ([axt-1046](https://github.com/paxel/axt/issues/54))
- Each example type is published as its description of bricks, one version each, with its derived schema and fingerprint generated beside it. ([axt-1045](https://github.com/paxel/axt/issues/53))
- Relations to records of other senders, named by any key of the sender's set and shown as linked from, with the `records` operation `relations`. ([axt-1038](https://github.com/paxel/axt/issues/46))

### Changed

- The test vectors are those of specification 0.2.0. ([axt-1036](https://github.com/paxel/axt/issues/44))

---

Historical changes have been moved to [OLDER_CHANGES.md](OLDER_CHANGES.md).
