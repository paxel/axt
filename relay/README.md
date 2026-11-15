# Reference relay

This directory holds the reference relay: a sealed mailbox that stores and forwards end-to-end encrypted messages and sees neither their content nor their type. Anyone can run it. AXT has no default relay operator; each app chooses its relay.

The relay is added in [axt-1008](https://github.com/paxel/axt/issues/9). The interface every relay offers is defined in [spec/transports.md](../spec/transports.md), section 5; the reference relay's own document is [spec/relay.md](../spec/relay.md).

Licence: Apache-2.0 OR MIT, see [LICENSING.md](../LICENSING.md).
