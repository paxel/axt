# Relay

Status: written, 0.1.0.

This document describes the reference relay of the repository, [relay/axt_relay.py](../relay/axt_relay.py): how it implements the relay's interface, the limits it chooses within the specification, how it stores messages, what it logs, how it is run, and its test mode.

The interface that every relay offers, and on which apps depend, is defined in [transports.md](transports.md), section 5: mailboxes, the HTTP requests and their status codes, the holding time of 14 days, the size limit, and what a relay may log. That section is the wire contract. This document adds nothing that an app needs: the limits and behaviour that only this document names are those of the reference relay, and other relays choose their own.

The reference relay is a reference and a test oracle, not a production server. It is written in Python 3.10 or later with the standard library only, so that it runs wherever Python runs and can be read in one sitting. A production relay MAY be written in any language and MAY store messages in any way; it is a relay of AXT when it follows [transports.md](transports.md), section 5, and passes the `relay-server` vectors ([conformance.md](conformance.md), section 2.2).

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 ([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119), [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)) when, and only when, they appear in all capitals, as shown here.

## 1. Terms

- **Operator**: whoever runs a relay.
- **Proxy**: the reverse proxy in front of the reference relay that terminates TLS (section 7.2).
- **Relay's clock**: the time the relay uses for the holding time and for the idle time of a mailbox: the system's clock, or in test mode a clock the test sets (section 8).
- **Sweep**: the relay's pass over all mailboxes that deletes what is past its time (section 4.2).

## 2. Design

- One program, [relay/axt_relay.py](../relay/axt_relay.py), with no dependency beyond the Python standard library. It serves HTTP/1.1 with `http.server`, one thread per connection.
- It serves plain HTTP and relies on a proxy for TLS (section 7.2). The proxy also offers HTTP/2 to apps where it supports it.
- It keeps every message in a file of its own, named by the message's SHA-256, in a directory per mailbox (section 5). An index of the mailboxes and their messages is kept in memory and read again from disk at each start.
- It sees, of each message, only what [transports.md](transports.md), section 5.7, says a relay learns. It never decodes a message and does not check that a body is a sealed message: it holds any body of 1 byte or more whose SHA-256 is its id.

## 3. Requests

The relay serves the requests of [transports.md](transports.md), section 5.2, under its base path, such as `/axt/` for the base URL `https://relay.example.org/axt/`.

### 3.1 Order of the checks

The relay answers each request with the first of these checks that fails, in this order. It is the order of the model of a relay in [conformance/tools/transports_examples.py](../conformance/tools/transports_examples.py), from which the `relay-server` vectors are made.

1. A request above the rate limit of its client address: `429` (section 4.3).
2. A path that is not one of [transports.md](transports.md), section 5.2, under the base path: `404`.
3. A query on a request other than a list: `400`.
4. A put of a message, which needs no owner, in the order of [transports.md](transports.md), section 5.3: no `Content-Length` (`411`); a `Content-Length` that is not one decimal number, or one together with `Transfer-Encoding` (`400`); above 17,301,553 (`413`); no such mailbox (`404`); an empty body, or one whose SHA-256 is not the id in the path (`400`); a message held already (`204`); no room (`507`). It then holds the message (`201`).
5. Every other request is an owner request: no `Authorization`, more than one, or one that is not `Bearer`, one space and 64 lower-case hexadecimal digits (`401`); a secret whose mailbox id is not the one in the path (`403`).
6. Creating (`201`, `204` for a mailbox that exists, or `429` above the creation limit of section 4.3) and removing (`204`, also for a mailbox that does not exist) need no existing mailbox.
7. A list, a fetch or a delete of a mailbox that does not exist: `404`.
8. A list with a query other than `wait=` and 0 to 60: `400`.
9. A fetch of a message not held: `404`. A delete of a message not held: `204`.
10. Another method on one of the paths, `HEAD` among them: `405`. A method that the relay does not serve on any path, other than `GET`, `PUT`, `DELETE`, `POST`, `HEAD`, `PATCH` and `OPTIONS`: `501`.

The relay answers `503` with `Retry-After: 60` when its storage fails, such as when the disk is full.

### 3.2 HTTP

- A response without a body carries `Content-Length: 0`, except `204`, which carries no `Content-Length` ([RFC 9110, section 8.6](https://www.rfc-editor.org/rfc/rfc9110#section-8.6)).
- The list is the JSON object of [transports.md](transports.md), section 5.4, without spaces, such as `{"messages":[{"id":"6be5…","size":1073}]}`, with the messages held in the order of their puts. It holds at most 1,000 messages, the oldest.
- A connection stays open for further requests unless the client asks to close it or the relay answers a request without reading its body. The relay answers a put that fails before its body is read (`411`, `413`, `404`) without reading the body, then closes the connection, after reading for up to 2 seconds what the client still sends, so that the client can read the answer. A request other than a put that carries a body is answered and its connection closed in the same way.
- A request without `Content-Length` and without `Transfer-Encoding` has no body ([RFC 9112, section 6.3](https://www.rfc-editor.org/rfc/rfc9112#section-6.3)); a put of this kind gets `411`. A put with `Transfer-Encoding` and no `Content-Length` also gets `411`, since [transports.md](transports.md), section 5.3, requires `Content-Length`.
- The relay sends `100 Continue` to a request with `Expect: 100-continue` only when it starts to read the body, so that a put that fails before is answered without its body being sent.
- A connection on which nothing moves for 60 seconds is closed. The relay requires no cookies and no header that [transports.md](transports.md), section 5.2, does not name; besides those, it reads `Transfer-Encoding` and `Expect` as above, and the client address header an operator names (section 7.1).
- `Server` is `axt-relay`, without a version.

### 3.3 Waiting lists

A list with `wait` from 1 to 60, of a mailbox with no message, waits on the system's monotonic clock until a message is put into the mailbox or the wait is over, and then answers with the list. It answers `404` at once when the mailbox is removed while it waits. At most 1,000 lists wait at the same time (`--max-waiting`); a further list answers at once, which [transports.md](transports.md), section 5.4, allows.

## 4. Limits

### 4.1 Size and room

| Limit                    | Value                                                                                                                                                       |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A message                | 1 to 17,301,553 bytes; a larger `Content-Length` gets `413` ([transports.md](transports.md), section 5.6)                                                   |
| The room of a mailbox    | 64 MiB of held messages by default (`--quota-bytes`); a put that would go above it gets `507`, except into an empty mailbox, which always takes one message |
| The number of messages   | No limit beyond the room; a list shows the oldest 1,000                                                                                                     |
| Who may create a mailbox | Every client, within the rate limits; the relay answers no creation with `403`                                                                              |

The room counts the bytes of the messages held, without the header of section 5.2. A message past its holding time does not count.

### 4.2 Times

| Time            | Value                                                                                                                                                                         |
| --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Holding time    | A message is held from its put until 14 days later on the relay's clock. From then on it is neither listed nor fetched nor counted, and a put of it is a new put (`201`)      |
| Deleting it     | At the next sweep, at most 10 minutes later, or earlier when a put, list or fetch touches its mailbox: well within the one day of [transports.md](transports.md), section 5.5 |
| A repeated put  | Changes nothing: it does not extend the holding time                                                                                                                          |
| An idle mailbox | Removed with its messages at the first sweep at least 91 days after the stored time of its owner's last request (section 5.1), so never before 90 days                        |
| The sweep       | Every 10 minutes, and in test mode also each time the test sets the clock (section 8)                                                                                         |

### 4.3 Rate limits

Each client address has two token buckets, which refill evenly over their period and hold at most their count:

| Limit                                     | Default | Option             |
| ----------------------------------------- | ------- | ------------------ |
| Requests per minute, of every kind        | 600     | `--rate-requests`  |
| Mailboxes created per hour, only new ones | 20      | `--rate-creations` |

A request above a limit gets `429` with `Retry-After`, the whole seconds until the bucket holds a token again. `0` turns a limit off. The relay sets no limit per mailbox beyond its room: whoever knows the id can put messages into a mailbox ([transports.md](transports.md), section 5.6), and the room bounds what they can put.

Behind a proxy, every request comes from the proxy's address. An operator then names the header in which the proxy passes the client address, such as `X-Forwarded-For` (section 7.1); the relay takes the last value of that header, the one the proxy added.

## 5. Storage

### 5.1 Layout

The storage directory (`--storage`) holds:

| Path                                  | Content                                                                                           |
| ------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `mailboxes/<mailbox id>/`             | One directory per mailbox, named by its id in 64 lower-case hexadecimal digits                    |
| `mailboxes/<mailbox id>/<message id>` | One file per message held, named by its SHA-256 in 64 lower-case hexadecimal digits (section 5.2) |
| `mailboxes/<mailbox id>/seen`         | The time of the owner's last request on the relay's clock, in milliseconds, as decimal text       |
| `tmp/`                                | Files being written, and mailboxes being removed; emptied at each start                           |

The relay writes `seen` when a mailbox is created and then at most once a day, so that a list every minute does not write to the disk. The relay keeps no mailbox secret: it checks a secret by computing the mailbox id from it.

### 5.2 A message file

A message file is a header of 20 bytes followed by the sealed message as it was put:

| Bytes | Content                                                                                                  |
| ----- | -------------------------------------------------------------------------------------------------------- |
| 0–3   | `AXR1` in ASCII, the version of this format                                                              |
| 4–11  | The time of the put on the relay's clock, in milliseconds since 1970-01-01T00:00:00Z, signed, big-endian |
| 12–19 | A sequence number, unsigned, big-endian, that rises with each put across all mailboxes                   |

The list orders the messages by their sequence number, so that puts in the same millisecond, or in the same second of the test clock, keep their order. At start, the relay continues the sequence above the highest number on disk. It skips a file whose header does not begin with `AXR1` or that holds no message.

### 5.3 Writing

A put is written so that a stop at any point, such as a crash or a full disk, leaves either the whole message or none:

1. The relay streams the body into a new file under `tmp/`, behind 20 zero bytes, and computes its SHA-256 while it reads.
2. If the SHA-256 is the id in the path, it writes the header and flushes the file to the disk (`fsync`).
3. It then checks, under the lock of the relay's index, that the mailbox still exists, that the message is not held already and that the mailbox has room, and renames the file to `mailboxes/<mailbox id>/<message id>` (`os.replace`), which is atomic within one file system.

A removed mailbox is first renamed into `tmp/` and then deleted, so that a put cannot write into a mailbox that is gone. `seen` is written to `tmp/` and renamed in the same way.

### 5.4 Copies and backups

A copy of the storage gives away the mailbox ids, the sealed messages, their sizes, and the times of their puts and of the owners' last requests; it gives away no secret and no content. An operator MUST NOT keep a message beyond the times of [transports.md](transports.md), section 5.5, also not in a backup. The storage needs no backup: a lost storage loses messages that their senders send again after the holding time ([protocol.md](protocol.md), section 11), and owners create their mailboxes again after a `404` ([transports.md](transports.md), section 5.4).

## 6. Logs

The relay logs to its standard error, one line per event, with the time in UTC:

- at start, the address, the port and the base path it listens on;
- for each request, unless `--no-access-log`: the client address, the action (`create`, `remove`, `put`, `list`, `fetch`, `delete`, or the method), the status code, and the bytes of the message put or fetched;
- for a request that `http.server` cannot parse, or that times out: the client address, `malformed` and the status code;
- for a failure of the storage or of the program: the error with its traceback, without a client address.

It never logs the value of `Authorization`, a mailbox secret, the request line, or any content, and never a mailbox id or a message id in a line with a client address. A traceback MAY name a path in the storage, and with it a mailbox id, but never with a client address. No line of the relay holds both a mailbox id and a client address, so the 7-day rule of [transports.md](transports.md), section 5.7, applies to none of them.

An operator's proxy MUST NOT log `Authorization`. A proxy that logs request paths together with client addresses writes lines with both, and the operator MUST delete those lines within 7 days. Many proxies do so by default in their access log, and in their error log for a request that fails, as nginx and Caddy do. Turning off the access log, or logging no path, and keeping the error log for at most 7 days are RECOMMENDED (section 7.2).

## 7. Running

### 7.1 Options

```text
python3 relay/axt_relay.py --storage DIR [options]
```

| Option                         | Default    | Meaning                                                                                                 |
| ------------------------------ | ---------- | ------------------------------------------------------------------------------------------------------- |
| `--storage DIR`                | (required) | The storage directory of section 5; created if missing                                                  |
| `--host HOST`                  | 127.0.0.1  | The address to listen on                                                                                |
| `--port PORT`                  | 8080       | The port to listen on; `0` for one the system picks, which the start line names                         |
| `--base-path PATH`             | `/`        | The path of the base URL, beginning and ending with `/`, such as `/axt/`                                |
| `--quota-bytes N`              | 67108864   | The room of a mailbox (section 4.1)                                                                     |
| `--max-waiting N`              | 1000       | Lists that may wait at the same time (section 3.3)                                                      |
| `--rate-requests N`            | 600        | Requests per minute per client address; `0` for no limit (section 4.3)                                  |
| `--rate-creations N`           | 20         | Mailboxes created per hour per client address; `0` for no limit (section 4.3)                           |
| `--client-address-header NAME` | none       | Take the client address from the last value of this header, set by the proxy, such as `X-Forwarded-For` |
| `--no-access-log`              | off        | Log no line per request                                                                                 |
| `--test`                       | off        | Test mode (section 8); never in production                                                              |

The relay stops on `SIGTERM` and `SIGINT`. Since every write is atomic (section 5.3), it can be stopped at any time.

### 7.2 TLS

[transports.md](transports.md), section 5.7, requires that apps reach a relay only over HTTPS. The reference relay serves plain HTTP and MUST be run behind a proxy that terminates TLS; it MUST NOT be reachable by apps without it. The proxy:

- MUST serve TLS 1.3 or TLS 1.2 as [RFC 9325](https://www.rfc-editor.org/rfc/rfc9325) recommends them, with a certificate that apps can check as for any HTTPS server;
- MUST accept request bodies of at least 17,301,553 bytes, and MUST pass `Content-Length` and `Authorization` to the relay unchanged;
- MUST wait more than 60 seconds for the relay's response, for a list that waits (section 3.3);
- MUST follow the rule on logs of section 6;
- when the relay takes the client address from a header (section 7.1), MUST set that header itself, and the relay MUST then be reachable only through the proxy, since a client could otherwise set the header.

[relay/README.md](../relay/README.md) shows a configuration for Caddy and for nginx. A proxy also keeps the relay's own HTTP server, which is not hardened against slow or many clients, away from the network.

### 7.3 Container

[relay/Containerfile](../relay/Containerfile) builds an image from `python:3.13.18-slim-trixie`, pinned by its digest. The relay runs as the user 10001, listens on port 8080 on every address of the container, and keeps its storage in the volume `/data`. Further options follow the image name.

## 8. Test mode and conformance

With `--test`, the relay has a clock that starts at 0 and that a test sets:

- `PUT /_test/now`, outside the base path, with `Content-Length` and as the body the time in seconds as a decimal number, such as `1209599`, sets the relay's clock, runs a sweep and answers `204`. The clock may go back. It stays at the time set until the next `PUT /_test/now`.
- The clock gives the time of each put and of each owner request, and decides the holding time and the idle time of a mailbox. A list waits in real time (section 3.3).

Without `--test`, the relay uses the system's clock, and `/_test/now` is a path like any other that is not of the interface: `404`. An operator MUST NOT run a relay in test mode, since anyone could then set its clock and have it delete every message.

The room of a mailbox, which the `relay-server` vectors set in `quota_bytes` ([conformance.md](conformance.md), section 5.11), is the ordinary option `--quota-bytes`.

[relay/adapter.py](../relay/adapter.py) is the relay's adapter for [conformance/run.py](../conformance/run.py) ([conformance.md](conformance.md), section 6). For each `relay-server` vector it starts the relay as a process of its own, on 127.0.0.1 with a port the system picks, with an empty temporary storage directory, the vector's quota, no rate limits and `--test`; sets the clock before each request; sends each request with exactly the vector's headers and a `Host`; and stops the relay. A request without `Content-Length` is sent without a body, since in HTTP/1.1 it has none. The reference relay passes both `relay-server` vectors:

```text
python3 conformance/run.py --category relay-server -- python3 relay/adapter.py
```

[relay/test_axt_relay.py](../relay/test_axt_relay.py) tests what the vectors do not: a list that waits until a put and one whose wait ends, a restart on the same storage, the sweep and the removal of an idle mailbox, the test hook without `--test`, the log, early answers before a body, `Expect: 100-continue`, several requests on one connection, the rate limits and the room. Its end-to-end test runs the relay as a program, plays the exchange of [transports.md](transports.md), section 7.5, with the sealed message of [keys.md](keys.md), section 7.4, and opens the fetched message to the `DATA` message of [keys.md](keys.md), section 7.2:

```text
python3 -m unittest relay/test_axt_relay.py
```

## References

- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174): key words for requirement levels
- [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110): HTTP semantics
- [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112): HTTP/1.1
- [RFC 9325](https://www.rfc-editor.org/rfc/rfc9325): recommendations for the secure use of TLS
