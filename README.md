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

The standard test suite uses a local HTTPS target. To additionally verify a real encrypted DNS round trip through the proxy to Cloudflare's ODoH target, run `cargo test --test cloudflare_odoh -- --ignored`. This opt-in test fetches live ODoH key configuration, requires outbound HTTPS to `odoh.cloudflare-dns.com`, and depends on the target's availability.

The unit uses `DynamicUser=yes`, no capabilities, and binds HTTP to `127.0.0.1:8053` by default. `--listen` also accepts non-loopback addresses (for example, `0.0.0.0:8053`); adjust the service's `ExecStart` or invoke the binary directly when deploying behind a remote TLS terminator. **Never expose the HTTP listener directly to the public internet:** restrict access to the trusted terminator with firewall rules or a private network. Configure the terminator with a trusted certificate for a public DNS name, routing both `/dns-query` and `/{targethost}/{targetpath}` requests to the relay. Ensure the terminator and any external CDN or logging infrastructure meet your privacy policy; avoid logging client addresses or DNS payloads.

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now odoh-proxy.service
sudo systemctl status odoh-proxy.service
```

For a private target CA, invoke `odoh-proxy --target-ca-cert /path/to/ca.pem` (add the option to the unit and ensure the dynamic user can read the PEM). Certificate and hostname validation remain enabled. The proxy makes HTTPS requests to the client-selected target using one shared connection pool; only the encrypted body and ODoH `Content-Type`/`Accept` are sent, never client headers, credentials, addresses, or incoming `Proxy-Status`. Target-generated 401 responses retain their status and body; the proxy does not authenticate to targets or decrypt ODoH messages. Redirects are returned, not followed. **Without an allowlist, the relay can reach any HTTPS host, including internal services:** constrain outbound network access at the deployment boundary and consider whether public proxying fits your threat model. Avoid co-locating/colluding proxy and target: privacy requires separation and cannot be enforced by this proxy.

Pass `--allowed-target HOST[:PORT]` repeatedly to opt into exact HTTPS target authorities (for example, `--allowed-target dns.example:443 --allowed-target alternate.example`). Hostnames are case-normalized and omitted ports mean 443; both proxy URI templates enforce the policy before reading a body. Without this flag, client-selected HTTPS targets remain unrestricted. A disallowed host or port returns 403. This is not DNS-resolution-based trust: even an allowed hostname can resolve to private networks or be DNS-rebound. Apply outbound firewall/egress restrictions where private-network isolation matters, especially for open-target deployments.

Global admission limits default to `--max-requests-per-second 100` (token bucket, initially full with a burst of 100) and `--max-in-flight 128`. Both require positive integers. Requests over the rate return 429; requests over concurrent capacity return 503. Neither is sent upstream, and both return empty bodies with `Cache-Control: no-store` and `Proxy-Status` errors. Limits are global, not per-client: `Forwarded` and `X-Forwarded-For` cannot establish client identity behind a TLS terminator. The relay still caps each request and response body at 256 KiB and applies upstream timeouts. Target-side throttling and ODoH ciphertext decryption remain the target's responsibility.

Clients need the target public key and either RFC 9230 proxy URI template: `https://odoh.example.com/dns-query{?targethost,targetpath}` or `https://odoh.example.com/{targethost}/{targetpath}`. Both use POST with `Content-Type: application/oblivious-dns-message`. The first route reads variables from the query; the second reads them from the path (including percent-encoded path segments). The proxy constructs `https://targethost/targetpath` and forwards the encrypted body without decrypting it. Other methods receive 405; unmatched paths receive 404.

The binary prints `LISTENING <bound-address>` to stdout once bound. Diagnostics go to stderr without client addresses or payloads. Ctrl-C/SIGTERM stops it; bind/configuration errors exit nonzero. Request and response bodies are limited to 256 KiB.

Responses include `Cache-Control: no-store` and a `Proxy-Status` identifying `odoh-proxy`. Forwarded responses report `received-status`; relay-generated failures (including malformed query parameters) report an `error` code with an empty body.

## GitHub CI and releases

Every push and pull request runs formatting, Clippy, and the local test suite with the committed `Cargo.lock`. The live Cloudflare test remains opt-in and is not run in CI.

To publish a release, update the version in `Cargo.toml` and push a matching `v<version>` tag (for example, `v0.1.0`). After the checks pass, GitHub Actions builds the release binary on Ubuntu 24.04 x86-64 and publishes a Linux x86-64 GNU tarball and `SHA256SUMS` to a GitHub Release. Verify a downloaded tarball with `sha256sum -c SHA256SUMS` from the download directory. The archive contains the binary; install it and the systemd unit using the commands above. Releases do not deploy to a server automatically: TLS termination, egress restrictions, and the service configuration remain operator-managed. The binary is dynamically linked against the Ubuntu 24.04 system libraries; use `cargo build --release` on other platforms or older Linux distributions.

