# Reference relay

This directory holds the reference relay: a sealed mailbox that stores and forwards end-to-end encrypted messages and sees neither their content nor their type. Anyone can run it. AXT has no default relay operator; each app chooses its relay.

The interface every relay offers is defined in [spec/transports.md](../spec/transports.md), section 5. The reference relay's own document, with its storage, limits, logs and test mode, is [spec/relay.md](../spec/relay.md).

The reference relay is written in Python 3.10 or later with the standard library only. It is a reference and a test oracle, not a production server. A production relay may be written in any language and store messages in any way, as long as it follows [spec/transports.md](../spec/transports.md), section 5, and passes the `relay-server` vectors ([spec/conformance.md](../spec/conformance.md), section 2.2).

## Files

| Path                                   | Content                                                                       |
| -------------------------------------- | ----------------------------------------------------------------------------- |
| [axt_relay.py](axt_relay.py)           | The relay, one program                                                        |
| [adapter.py](adapter.py)               | Its adapter for the conformance runner, which drives the relay over HTTP      |
| [test_axt_relay.py](test_axt_relay.py) | Its tests beyond the vectors, with an end-to-end exchange of a sealed message |
| [Containerfile](Containerfile)         | A container image of the relay                                                |

## Running it

```text
python3 relay/axt_relay.py --storage /var/lib/axt-relay --base-path /axt/ --client-address-header X-Forwarded-For
```

The relay listens on 127.0.0.1, port 8080, and serves plain HTTP to the proxy in front of it (below). `--client-address-header` takes each client's address from the header the proxy sets; without it, every client has the proxy's address and shares one rate limit. `--help` lists the options; [spec/relay.md](../spec/relay.md), section 7.1, explains them. It logs to its standard error, never a secret and never a mailbox id together with a client address.

### In a container

```text
podman build -t axt-relay relay/
podman run -d --name axt-relay -p 127.0.0.1:8080:8080 -v axt-relay:/data \
    axt-relay --base-path /axt/ --client-address-header X-Forwarded-For
```

With Docker, build with `docker build -t axt-relay -f relay/Containerfile relay/`. The image is based on `python:3.13.18-slim-trixie`, pinned by its digest; the relay runs as the user 10001 and keeps its mailboxes in the volume `/data`. A directory mounted at `/data` instead of a volume must be writable by the user 10001. Options after the image name are passed to the relay.

### TLS

Apps reach a relay only over HTTPS ([spec/transports.md](../spec/transports.md), section 5.7). The reference relay does not do TLS itself: it runs behind a reverse proxy that terminates TLS, and must not be reachable without it. The proxy must accept bodies of at least 17,301,553 bytes, wait more than 60 seconds for a response, and pass `Authorization` unchanged without logging it; log lines that hold a request path and a client address must be deleted within 7 days. The access log of a proxy holds both, and so does its error log for a request that fails, in nginx and in Caddy: turn the access log off and keep the error log for at most 7 days ([spec/relay.md](../spec/relay.md), sections 6 and 7.2).

With [Caddy](https://caddyserver.com/), which obtains the certificate itself and writes no access log unless told to:

```text
relay.example.org {
	reverse_proxy /axt/* 127.0.0.1:8080
}
```

With [nginx](https://nginx.org/):

```text
server {
    listen 443 ssl;
    http2 on;                        # nginx 1.25.1 or later
    server_name relay.example.org;
    ssl_certificate     /etc/ssl/relay.example.org.crt;
    ssl_certificate_key /etc/ssl/relay.example.org.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    access_log off;

    location /axt/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header X-Forwarded-For $remote_addr;
        client_max_body_size 17m;
        proxy_read_timeout 75s;
    }
}
```

Both pass the client address in `X-Forwarded-For`, which the relay reads with `--client-address-header X-Forwarded-For` for its rate limits. The relay's base URL is then `https://relay.example.org/axt/`.

## Conformance and tests

The relay passes the `relay-server` vectors through its adapter, which starts the relay in test mode for each vector:

```text
python3 conformance/run.py --category relay-server -- python3 relay/adapter.py
```

Its own tests use the standard library only; the end-to-end test also opens the fetched message when the package cryptography is installed:

```text
python3 -m unittest relay/test_axt_relay.py
```

The test mode (`--test`) lets anyone set the relay's clock and is never used in production ([spec/relay.md](../spec/relay.md), section 8).

Licence: Apache-2.0 OR MIT, see [LICENSING.md](../LICENSING.md).
