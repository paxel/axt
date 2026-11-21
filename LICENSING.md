# Licensing

AXT uses two licensing schemes: one for the standard itself and one for code.

| Path           | Content                                                                          | Licence                                   | SPDX                |
| -------------- | -------------------------------------------------------------------------------- | ----------------------------------------- | ------------------- |
| `spec/`        | The specification                                                                | CC0 1.0 Universal                         | `CC0-1.0`           |
| `types/`       | The example types                                                                | CC0 1.0 Universal                         | `CC0-1.0`           |
| `vectors/`     | The test vectors                                                                 | CC0 1.0 Universal                         | `CC0-1.0`           |
| `conformance/` | The conformance suite, and the scripts that produce the vectors and the examples | Apache License 2.0 or MIT, at your option | `Apache-2.0 OR MIT` |
| `tools/` | The repository's own checks, such as the changelog check | Apache License 2.0 or MIT, at your option | `Apache-2.0 OR MIT` |
| `relay/`       | The reference relay                                                              | Apache License 2.0 or MIT, at your option | `Apache-2.0 OR MIT` |

The licence texts:

- [LICENSE-CC0](LICENSE-CC0): CC0 1.0 Universal
- [LICENSE-APACHE](LICENSE-APACHE): Apache License, Version 2.0
- [LICENSE-MIT](LICENSE-MIT): MIT License

The specification, the types and the vectors are dedicated to the public domain, so that anyone can implement AXT, copy the schemas into an app, or publish a changed version without asking. Code may be used under either the Apache License 2.0 or the MIT License, at the user's choice.

The scripts that produce the test vectors and the examples of the specification are code, and live under `conformance/tools/` with the conformance suite; what they produce, the files under `vectors/` and the examples in `spec/`, is data and stays under CC0 1.0.
