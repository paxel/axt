# Conformance suite

This directory holds the conformance suite that every AXT library must pass: a runner that sends the [test vectors](../vectors/README.md) to a library through a small adapter and compares its answers, a reference adapter, and the scripts that produce the vectors and the examples of the specification. [spec/conformance.md](../spec/conformance.md) defines what a library must pass and the adapter's protocol.

## Running the suite

A library brings an adapter: a program that reads one JSON request per line on its standard input, performs it with the library, and writes one JSON answer per line ([spec/conformance.md](../spec/conformance.md), section 6). The runner starts it:

```text
python3 conformance/run.py -- <the adapter's command>
```

`--category NAME` runs one category, `--vectors DIR` another set of vector files, and `--verbose` names every vector. The runner needs Python 3.10 or later with fastavro and cryptography.

The reference adapter passes every vector:

```text
python3 conformance/run.py -- python3 conformance/reference/adapter.py
```

## Layout

| Path                                                         | Content                                                                                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------ |
| [run.py](run.py)                                             | The runner                                                                                                               |
| [reference/adapter.py](reference/adapter.py)                 | The reference adapter, built on the scripts below; it shows that the vectors are consistent, and is not a library        |
| [tools/generate_vectors.py](tools/generate_vectors.py)       | Writes the files under [vectors/](../vectors/README.md); `--check` compares them with its output                         |
| [tools/envelope_examples.py](tools/envelope_examples.py)     | Produces and checks the examples of [spec/envelope.md](../spec/envelope.md)                                              |
| [tools/example_types.py](tools/example_types.py)             | Checks the example types of [spec/types.md](../spec/types.md) and prints their fingerprints                              |
| [tools/time_examples.py](tools/time_examples.py)             | Produces and checks the examples of [spec/time.md](../spec/time.md), with zone rules from Python's `zoneinfo`            |
| [tools/metadata_rules.py](tools/metadata_rules.py)           | The rules of [spec/metadata.md](../spec/metadata.md): attributes, formats, I-Regexp and checks; imports no other script  |
| [tools/metadata_examples.py](tools/metadata_examples.py)     | Produces and checks the examples of [spec/metadata.md](../spec/metadata.md)                                              |
| [tools/keys_examples.py](tools/keys_examples.py)             | Produces and checks the examples of [spec/keys.md](../spec/keys.md), with Ed25519, X25519 and HPKE in Python             |
| [tools/manifest_examples.py](tools/manifest_examples.py)     | Produces and checks the examples of [spec/manifest.md](../spec/manifest.md)                                              |
| [tools/protocol_examples.py](tools/protocol_examples.py)     | Produces and checks the examples of [spec/protocol.md](../spec/protocol.md), with a model of an app                      |
| [tools/transports_examples.py](tools/transports_examples.py) | Produces and checks the examples of [spec/transports.md](../spec/transports.md), with models of the frames and the relay |

The scripts and the reference adapter need Python 3.10 or later with fastavro 1.13.1, avro 1.12.2, PyNaCl 1.6.2 and cryptography 50.0.2, the versions the specification's examples were checked with, and a time zone database that Python's `zoneinfo` finds, such as the system's or the package `tzdata`.

Licence: Apache-2.0 OR MIT, see [LICENSING.md](../LICENSING.md).
