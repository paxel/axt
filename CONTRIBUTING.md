# Contributing to AXT

AXT is a draft. Proposals are discussed in [GitHub issues](https://github.com/paxel/axt/issues) before anything is changed, so open an issue first and a pull request after the issue is agreed.

## Changes to the specification

An issue proposing a change to a document in [spec/](spec/README.md) states:

- the problem the change solves;
- the proposed change, as text for the document concerned;
- a compatibility note: what happens to apps and libraries that implement the current text. A change that existing implementations cannot read or produce is marked as incompatible.

## Example types

The example types in [types/](types/README.md) are there so that apps can work together without agreeing first. Anyone may propose a new one or a change to an existing one.

- **A new type**: the issue gives the type's full name, its fields with a `doc` on every field, and the apps that would send or take it.
- **A change to a type**: a change to an example type is a new version of that type. A published version is never edited in place. The issue gives the fields added, removed or changed.
- **Compatibility note**: every change states, under Avro 1.12 schema resolution, whether a receiver that knows only the old version can read records of the new one, and the other way round. Under that resolution fields are matched by name, and a field the receiver's version has but the record lacks takes the receiver's default.

Types that only one app uses belong under that app's own namespace and are not added here.

The rules for the types are in [spec/types.md](spec/types.md).

## Libraries

A library lives in a repository of its own, `axt-<language>`, with its own gates, versions and tags, and is published to its language's registry. Before starting one, open an issue here naming the language and who maintains the library.

The bar for a library is the [conformance suite](conformance/README.md): a library is accepted as an AXT library when it passes the whole suite, and it keeps passing it with every change to the library or the specification. A library that passes only part of the suite is not listed as conforming. A library has its own SemVer and states the AXT version it conforms to in its README and package metadata; its CI proves it by running the suite of that AXT release ([conformance/README.md](conformance/README.md)). Library code is licensed under Apache-2.0 OR MIT, see [LICENSING.md](LICENSING.md).

## The reference relay and the conformance suite

Changes to [relay/](relay/README.md) and [conformance/](conformance/README.md) follow the same rule: an issue first, then a pull request. A change to the conformance suite that a conforming library no longer passes is a change to the specification and needs a compatibility note.
