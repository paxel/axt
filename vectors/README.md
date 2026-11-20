# Test vectors

This directory holds the test vectors of AXT: bytes with their expected meaning, and sequences of messages with their expected results, for every message, every example type and every transport. A library runs them with the [conformance suite](../conformance/README.md) to check that it encodes, decodes, signs, verifies and processes exactly as the specification says. [spec/conformance.md](../spec/conformance.md) defines the vectors, their format and what a library must pass.

## Layout

| Path                                                             | Content                                                                                               |
| ---------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| [vectors.schema.json](vectors.schema.json)                       | The JSON Schema of the vector files                                                                   |
| [encoding/encoding.json](encoding/encoding.json)                 | Canonical forms, fingerprints, envelopes and bodies ([spec/envelope.md](../spec/envelope.md))         |
| [types/types.json](types/types.json)                             | The example types and schema resolution ([spec/types.md](../spec/types.md))                           |
| [time/time.json](time/time.json)                                 | The time types, zone rules and durations ([spec/time.md](../spec/time.md))                            |
| [metadata/metadata.json](metadata/metadata.json)                 | Labels, formats, patterns and limits of fields ([spec/metadata.md](../spec/metadata.md))              |
| [records/records.json](records/records.json)                     | Applying record messages ([spec/records.md](../spec/records.md))                                      |
| [manifest/manifest.json](manifest/manifest.json)                 | Validity of a manifest and which types fit ([spec/manifest.md](../spec/manifest.md))                  |
| [keys/keys.json](keys/keys.json)                                 | Signatures, device sets, sealing ([spec/keys.md](../spec/keys.md))                                    |
| [protocol/protocol.json](protocol/protocol.json)                 | One app in a live connection ([spec/protocol.md](../spec/protocol.md))                                |
| [file/file.json](file/file.json)                                 | Reading a file ([spec/transports.md](../spec/transports.md), section 2)                               |
| [qr/qr.json](qr/qr.json)                                         | The QR code ([spec/transports.md](../spec/transports.md), section 3)                                  |
| [local/local.json](local/local.json)                             | Frames and `HELLO` ([spec/transports.md](../spec/transports.md), section 4)                           |
| [relay/relay.json](relay/relay.json)                             | The relay as an app uses it ([spec/transports.md](../spec/transports.md), section 5)                  |
| [relay-server/relay-server.json](relay-server/relay-server.json) | The interface of a relay, for relays ([spec/transports.md](../spec/transports.md), section 5)         |
| [sync/sync.json](sync/sync.json)                                 | Stamps, the merge, the messages between the devices of one owner and what they do with the messages of other apps ([spec/sync.md](../spec/sync.md)) |

The files are produced by [conformance/tools/generate_vectors.py](../conformance/tools/generate_vectors.py) and committed as data; they are not edited by hand. After a change of the specification, the generator writes them again, and `generate_vectors.py --check` confirms that the committed files are its output.

Every key, secret and certificate in the vectors is a test value of [spec/keys.md](../spec/keys.md), section 7.1, and MUST NOT be used outside tests.

Licence: CC0 1.0, see [LICENSING.md](../LICENSING.md).
