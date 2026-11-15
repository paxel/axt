# AXT specification

The specification of AXT, Avro eXchange Transfer, as separate documents. Each document is a stub until its ticket fills it.

| Document                      | Purpose                                                               | Status         | Ticket                                             |
| ----------------------------- | --------------------------------------------------------------------- | -------------- | -------------------------------------------------- |
| [Envelope](envelope.md)       | How records travel as bytes, in a live connection and in a file       | written, 0.1.0 | [axt-1001](https://github.com/paxel/axt/issues/2)  |
| [Types](types.md)             | The example types and the rules for evolving or replacing them        | written, 0.1.0 | [axt-1002](https://github.com/paxel/axt/issues/3)  |
| [Records](records.md)         | Record id and version, updates and deletions                          | written, 0.1.0 | [axt-1003](https://github.com/paxel/axt/issues/4)  |
| [Manifest](manifest.md)       | Which types an app takes and what it does with them                   | written, 0.1.0 | [axt-1004](https://github.com/paxel/axt/issues/5)  |
| [Protocol](protocol.md)       | The steps of an exchange: offer, accept or decline, data, acknowledge | written, 0.1.0 | [axt-1005](https://github.com/paxel/axt/issues/6)  |
| [Keys](keys.md)               | Signatures, encryption and moving a key to a new installation         | written, 0.1.0 | [axt-1006](https://github.com/paxel/axt/issues/7)  |
| [Transports](transports.md)   | File, local network and relay                                         | written, 0.1.0 | [axt-1007](https://github.com/paxel/axt/issues/8)  |
| [Relay](relay.md)             | The reference relay; the relay's interface is in Transports           | draft          | [axt-1008](https://github.com/paxel/axt/issues/9)  |
| [Conformance](conformance.md) | Test vectors and the conformance suite every library must pass        | draft          | [axt-1009](https://github.com/paxel/axt/issues/10) |

The specification is published under CC0 1.0; see [LICENSING.md](../LICENSING.md).
