# 2. Libraries in their own repositories

Date: 2026-11-20

## Status

Accepted. Replaces the sentence on `libs/` in [ADR 1](0001-gates-and-python-stack.md).

## Context

The repository was laid out with one directory per library under `libs/`. A library is only useful to an app when it is maintained, versioned, tagged and published where its language looks for packages; a directory in the specification's repository gives none of that, and six libraries in one repository would tie six release cycles and six stacks to one.

## Decision

- Each library lives in a repository of its own, `paxel/axt-<language>`, with its own gates and tags, and is published to its language's registry ([axt-1028](https://github.com/paxel/axt/issues/33)).
- Each library has its own SemVer and states the AXT version it conforms to in its README and package metadata.
- A library's CI pins an AXT release and the SHA-256 of its archive, checks the release's attestation, and runs the conformance suite from it against its own adapter.
- The Dart library comes first, for cat-a-log, as `axt_protocol` on pub.dev ([axt-1011](https://github.com/paxel/axt/issues/12)); the other five follow once its API has been proven there.

## Consequences

- This repository holds the specification, the types, the vectors, the conformance suite and the reference relay, and no library.
- Moving a library to a new AXT version is a deliberate change of its pin.
- README.md lists the libraries with the AXT version each conforms to.
