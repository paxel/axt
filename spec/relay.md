# Relay

Status: draft. This document is not written yet.

Purpose: the reference relay of the repository, in [relay/](../relay/README.md): how it implements the relay's interface, how it stores messages, the limits and rate limits it sets, and how it is run.

The interface that every relay offers, and on which apps depend, is defined in [transports.md](transports.md), section 5: mailboxes, the HTTP requests and their status codes, the holding time of 14 days, the size limit, and what a relay may log. This document adds nothing that an app needs.

To be written in [axt-1008](https://github.com/paxel/axt/issues/9).
