# 1. The gates of paxel/gates, with axt as a Python stack

Date: 2026-11-19

## Status

Accepted.

## Context

The repository is a specification first, but it holds about 16,000 lines of Python: the example scripts, the vector generator, the conformance runner with its reference adapter, and the reference relay. Until now it had no manifest, so the packages the scripts need were named only in a README, and CI ran the changelog check and nothing else. The weekly audit of [paxel/gates](https://github.com/paxel/gates) reported the repository as drifting from the standard in 13 checks (issue 21). A rework of the specification for device sets, sibling sync, shares and proposals was about to regenerate every example and every vector.

## Decision

- axt is a Python stack of the standard ([axt-1020](https://github.com/paxel/axt/issues/22)): `pyproject.toml`, `uv.lock` and `.python-version`, with the shared Python gate (ruff with the strict rule set, mypy in strict mode, the tests with a coverage ratchet). The lock file pins the packages the specification's examples were checked with.
- The tests run what a reader of the READMEs runs: the conformance suite against the reference adapter and the reference relay, the comparison of the committed vectors with the generator's output, every example script and the changelog check.
- The reference relay stays on the standard library only; the packages are the scripts' dependencies, not the relay's.
- Everything the standard asks of a code repository is met, with no exception for a specification ([axt-1021](https://github.com/paxel/axt/issues/23)). The default branch takes changes only by pull request.
- The gates come before the rework of the specification, so that the rework runs under CI from its first commit.

## Consequences

- Python 3.11 is the oldest version the scripts run on, since the pinned fastavro needs it.
- The scripts keep loading each other by path and are not a package; mypy checks each directory as a base of its own.
- A release is an archive of the tagged tree, with the provenance the standard asks for.
- A library that joins under `libs/` brings its own stack and its own gate.
