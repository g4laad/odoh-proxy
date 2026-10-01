# ODoH relay

An RFC 9230 oblivious proxy, not an ODoH target. It forwards encrypted DNS messages to HTTPS targets chosen by clients without reading DNS questions.

## Build and install

Requires Rust 1.85+. Public access requires TLS termination; the relay itself serves plaintext HTTP.

```sh
cargo test --all-targets
cargo build --release
sudo install -m 0755 target/release/odoh-proxy /usr/local/bin/odoh-proxy
sudo install -m 0644 deploy/odoh-proxy.service /etc/systemd/system/
```

The unit uses `DynamicUser=yes`, no capabilities, and binds HTTP to `127.0.0.1:8053` by default. `--listen` also accepts non-loopback addresses (for example, `0.0.0.0:8053`); adjust the service's `ExecStart` or invoke the binary directly when deploying behind a remote TLS terminator. **Never expose the HTTP listener directly to the public internet:** restrict access to the trusted terminator with firewall rules or a private network. Configure the terminator with a trusted certificate for a public DNS name, routing both `/dns-query` and `/{targethost}/{targetpath}` requests to the relay. Ensure the terminator and any external CDN or logging infrastructure meet your privacy policy; avoid logging client addresses or DNS payloads.

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now odoh-proxy.service
sudo systemctl status odoh-proxy.service
```

For a private target CA, invoke `odoh-proxy --target-ca-cert /path/to/ca.pem` (add the option to the unit and ensure the dynamic user can read the PEM). Certificate and hostname validation remain enabled. The proxy makes HTTPS requests to the client-selected target; client headers and addresses are not sent to targets. Redirects are returned, not followed. **Without an allowlist, the relay can reach any HTTPS host, including internal services:** constrain outbound network access at the deployment boundary and consider whether public proxying fits your threat model. Avoid co-locating/colluding proxy and target: privacy requires separation.

Clients need the target public key and either RFC 9230 proxy URI template: `https://odoh.example.com/dns-query{?targethost,targetpath}` or `https://odoh.example.com/{targethost}/{targetpath}`. Both use POST with `Content-Type: application/oblivious-dns-message`. The first route reads variables from the query; the second reads them from the path (including percent-encoded path segments). The proxy constructs `https://targethost/targetpath` and forwards the encrypted body without decrypting it. Other methods receive 405; unmatched paths receive 404.

The binary prints `LISTENING <bound-address>` to stdout once bound. Diagnostics go to stderr without client addresses or payloads. Ctrl-C/SIGTERM stops it; bind/configuration errors exit nonzero. Request and response bodies are limited to 256 KiB.

Responses include `Cache-Control: no-store` and a `Proxy-Status` identifying `odoh-proxy`. Forwarded responses report `received-status`; relay-generated failures (including malformed query parameters) report an `error` code with an empty body.
