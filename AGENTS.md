Instructions for AI coding agents working in this repository.

## Agent skills

### Issue tracker

Issues live as GitHub Issues (`gh` CLI). See `docs/agents/issue-tracker.md`.

### Triage labels

Default five-role vocabulary plus `implemented`, label string equals role name. See `docs/agents/triage-labels.md`.

### Ticket IDs

Implementation tickets carry an ID with the prefix `axt`. See `docs/agents/ticket-ids.md`.

### Domain docs

Single-context: `CONTEXT.md` and `docs/adr/` at the repo root. See `docs/agents/domain.md`.

## What this repository is

AXT (Avro eXchange Transfer) is a draft open standard, 0.1.0 released, for exchanging typed records between small apps. The repository is specification first: the documents in `spec/` are the product, and all code is Python that checks the specification, produces its test vectors or serves as a reference. There is no build step. The repository is a Python stack of the [paxel/gates](https://github.com/paxel/gates) standard: `pyproject.toml` and `uv.lock` pin what the scripts need, and CI runs the standard's gates. Libraries live in repositories of their own (`axt-<language>`, listed in README.md); a library runs the conformance suite of the AXT release it conforms to, as conformance/README.md describes.

## Commands

All commands run from the repository root. [uv](https://docs.astral.sh/uv/) installs the pinned Python and packages (`uv sync`); Python 3.11 is the oldest version the scripts run on.

What CI runs, in the order of the Python gate:

```text
uv run ruff format --check .
uv run ruff check .
uv run mypy .
uv run pytest --cov
```

`uv run pytest` runs the conformance suite against the reference adapter and the reference relay, compares the committed vectors with the generator's output, runs every example script, the relay's tests and the changelog check (`tests/test_conformance.py`). Single parts:

```text
uv run pytest tests/test_conformance.py -k vectors                           # the tests whose name matches
uv run pytest relay/test_axt_relay.py -k long_poll
uv run python conformance/run.py -- python conformance/reference/adapter.py  # the whole suite against the reference adapter
uv run python conformance/run.py --category time --verbose -- <adapter command>  # one category; --category is repeatable
uv run python conformance/tools/generate_vectors.py --check                  # the committed vectors are the generator's output
uv run python conformance/tools/generate_vectors.py                          # write vectors/ again
uv run python conformance/tools/<name>_examples.py                           # produce and check one spec document's examples
uv run python conformance/tools/example_types.py                             # check the example types, print their fingerprints
uv run python fuzz/fuzz_relay.py -max_total_time=60                          # one fuzz target for a minute
python3 tools/changelog_check.py CHANGELOG.md                                # the changelog rule alone; standard library only
```

The runner has no filter finer than a category. The relay, its adapter and its tests need the standard library only.

The coverage ratchet (`coverage-floors.toml`) fails CI when line coverage falls below the floor. After a rise, the ratchet of paxel/gates raises the floor and rewrites `.github/badges/coverage-python.json`; both are committed with the change that earned them.

## Architecture

The repository is a chain in which each stage is checked against the one before it:

1. **`spec/*.md`** states the behaviour and shows examples as bytes and values. `spec/README.md` is the index, with the ticket of each document. The definitions are normative and the documents point to them without restating them: the bricks `types/axt/Field.avsc`, the limits `types/axt/limits.json` (with `limits.schema.json`), the relay interface `spec/relay-api.json` (OpenAPI 3.1, as JSON) and the adapter protocol `vectors/adapter.schema.json`.
2. **`types/axt/*.avsc`** holds the schemas of the specification itself (namespace `axt`), among them `Field.avsc`, which `conformance/tools/field_schema.py` writes (`--check` runs under pytest), and `types/axt/limits.json` every limit by name; **`types/axt/example/v1/`** holds the example types, one version each: the description `<Type>.<version>.json`, the source, and the schema derived from it, `<Type>.<version>.avsc`, which `conformance/tools/example_schemas.py` writes (`--check` runs under pytest).
3. **`conformance/tools/*_examples.py`** and `example_types.py` (for `spec/types.md`) each rebuild one spec document's examples from the descriptions and the `.avsc` files and check them against independent implementations (fastavro and the Apache avro package, PyNaCl and cryptography). The scripts print the examples; they do not read or write the Markdown, so the bytes shown in a spec document are kept in step by hand. `fields_examples.py` holds the rules of `spec/fields.md`: the bricks, valid descriptions, the derived schema, relations and extensions, what a receiver shows of a description and the checks of its values. `metadata_rules.py` holds the rules of `spec/metadata.md` that the bricks use, the texts, formats, I-Regexp and field paths, and the walk of a writer schema for the rules every receiver checks; it imports no other script. A schema carries no `axt.*` attribute but `axt.version` (and those of the published `axt.Relation` and `axt.Extension`); the members `axt.*` that some scripts write into a model's schema only feed `fields_examples.describe_schema`. Every script reads the limits it needs from `types/axt/limits.json` rather than keeping its own numbers. `sync_examples.py` holds the rules of `spec/sync.md`: it recomputes the numbers of the examples of its section 6, checks the merge's properties over generated cases, rebuilds the `CHANGE`, `RESYNC` and `FORWARD` messages of its section 16, and has a model of one device with its siblings, for the records of the set and for what the set got from other apps, whose sessions it checks against results written out in the script. `shares_examples.py` holds the rules of `spec/shares.md`: a receiver of withdrawals among its other record messages and the rules of a sending device, with which it plays the example of its section 11.1, and builds the `WITHDRAW` of its section 11.2; and an owner that takes proposals and a proposer, with which it plays the example of its section 11.3 and builds the `PROPOSAL` and the `PROPOSAL_REPLY` of its sections 11.4 and 11.5. The device model of `sync_examples.py` keeps, forwards and answers the proposals of other apps. `keys_examples.py` also resolves the relations of `spec/records.md`, section 10, on its model of a receiver of device sets. Otherwise `records.md`, `relay.md` and `conformance.md` have no script; the reference adapter has its own code for records.
4. **`conformance/tools/generate_vectors.py`** builds the test vectors from the code and models of those scripts and writes `vectors/<category>/<category>.json`. The vector files are committed as data and never edited by hand.
5. **`conformance/run.py`** sends each vector to an adapter, a program that reads one JSON request per line on its standard input and writes one JSON answer per line (`spec/conformance.md`, section 6), checks every request and answer against `vectors/adapter.schema.json`, and compares the answers.
6. **`conformance/reference/adapter.py`** answers with the same scripts' code. It shows that the vectors are consistent; it is not a library.

A change to a rule therefore runs through the whole chain: the spec document, the definition if one is concerned (a schema, a description, `limits.json`, `relay-api.json`, `adapter.schema.json`), the document's example script, the generator, the regenerated vectors, and the reference adapter until the suite passes again.

The scripts in `conformance/tools/` are not a package. They load each other with `importlib.util.spec_from_file_location`, in a chain: `transports_examples` loads `protocol_examples`, which loads `time_examples` and `manifest_examples`, which in turn loads `keys_examples` and `example_types`; `sync_examples` loads `keys_examples`, `time_examples` and `manifest_examples`, and not `protocol_examples`: it reads the schemas of the messages it builds itself; `shares_examples` loads `protocol_examples` and `sync_examples`; `fields_examples` and `example_types` load `metadata_rules`, and `time_examples` reaches it through `example_types`. `envelope_examples`, `manifest_examples`, `protocol_examples` and `transports_examples` run their checks and print at module level, so loading them runs them, and their loaders redirect standard output; `example_types`, `fields_examples`, `keys_examples`, `time_examples`, `sync_examples` and `shares_examples` guard theirs with `__main__`. The generator's output must be the same in every run and under every `PYTHONHASHSEED`.

**`relay/`** stands apart: `axt_relay.py` is the reference relay, one program on the standard library only, and must stay free of third-party packages. It reads `../types/axt/limits.json`, so its container image is built from the repository root. `relay/adapter.py` starts it in test mode (`--test`, which lets a client set the relay's clock) for each `relay-server` vector and drives it over HTTP. The interface every relay offers is defined by `spec/relay-api.json` and explained in `spec/transports.md`, section 5; `relay/test_axt_relay.py` checks the reference relay against the document. The reference relay's own behaviour is in `spec/relay.md`.

## Rules that are easy to break

- An example type is published as its description, `<Type>.<version>.json`, one version of each type; its `.avsc` is derived by `example_schemas.py` and never edited by hand. Compatibility with 0.1.0 is not kept: a change edits the description and regenerates the schema, the fingerprints, the examples and the vectors. The namespace `axt` and every namespace beginning with `axt.` are reserved for this repository.
- A number that a definition holds, such as a limit, is not restated in a spec document or a script: it is named (`envelope.message`) and read from its definition.
- Every field of a type carries a `doc`; `example_types.py` checks this and the other rules of `spec/types.md`, section 5.
- Each entry of the changelog's current section is one sentence of at most 25 words, the ticket link at its end not counted; CI enforces it. It says what changed for the user, not how or why.
- Every key, secret and certificate in the scripts and vectors is a test value of `spec/keys.md`, section 7.1.
- A change to the conformance suite that a conforming library no longer passes is a change to the specification and needs a compatibility note. Changes are agreed in a GitHub issue before a pull request (`CONTRIBUTING.md`).
- The specification uses the key words of BCP 14 (MUST, SHOULD, MAY) in capitals only where they are meant normatively.
- Licences differ by directory: `spec/`, `types/` and `vectors/` are CC0 1.0; code is Apache-2.0 OR MIT and carries the line `# SPDX-License-Identifier: Apache-2.0 OR MIT` at its top.
- Lint and types are strict: ruff with the rule set of paxel/gates (`ruff.toml`) and `mypy --strict`. Asserts are allowed in `conformance/`, where every check of the specification's examples is one.
- `summer` takes changes only by pull request with green CI. The standard asks for `CLAUDE.md` to hold only `@AGENTS.md`, so guidance for agents goes into this file.
- The subject of a commit for a ticket begins with the ticket in brackets, such as `[axt-1019] Regenerate the examples, vectors and conformance cases`.
