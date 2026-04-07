# gomim

[![ci](https://github.com/rdmnl/gomim/actions/workflows/ci.yml/badge.svg)](https://github.com/rdmnl/gomim/actions/workflows/ci.yml)
[![release](https://github.com/rdmnl/gomim/actions/workflows/release.yml/badge.svg)](https://github.com/rdmnl/gomim/actions/workflows/release.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/rdmnl/gomim)](https://goreportcard.com/report/github.com/rdmnl/gomim)
[![Go Reference](https://pkg.go.dev/badge/github.com/rdmnl/gomim.svg)](https://pkg.go.dev/github.com/rdmnl/gomim)
[![Latest release](https://img.shields.io/github/v/release/rdmnl/gomim?sort=semver)](https://github.com/rdmnl/gomim/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A small, general-purpose MITM proxy in Go for inspecting HTTPS traffic from any local client you operate - CLIs, SDKs, build tools, browsers, mobile simulators, server-to-server jobs. Useful for debugging API integrations, auditing what a third-party tool sends home, mocking or replaying upstream services, or just building intuition for how a protocol behaves on the wire.

Same category as Charles, Proxyman, mitmproxy, Burp, Fiddler - minus the GUI and the install footprint. Single Go binary, JSONL logs, optional embedded live viewer.

**Common use cases**

- Debugging your own API clients and SDKs (REST, GraphQL, JSON-RPC, webhooks).
- Watching what `npm`, `pip`, `cargo`, `apt`, `terraform`, `helm`, etc. fetch from their registries.
- Inspecting outbound traffic from a backend service in development.
- Logging requests from headless browser automation (Playwright, Puppeteer, Selenium).
- Pointing a mobile simulator/emulator at a proxy to see what an app phones home.
- Fronting a third-party API as a reverse proxy to add observability without instrumenting the client.

- HTTP + HTTPS via `CONNECT` interception (forward-proxy mode)
- Reverse-proxy mode for clients that ignore `HTTPS_PROXY` (e.g. compiled binaries with their own HTTP stack)
- On-the-fly per-host leaf certs signed by a local root CA
- HTTP/1.1 and HTTP/2 (ALPN-negotiated) on both client and upstream sides
- Streaming-safe forwarding (works with SSE / `text/event-stream`)
- JSONL request/response logs with bounded body capture
- Built-in live web viewer (SSE-streamed)
- Single small Go module, only `golang.org/x/net/http2` as a dep
- Runs on macOS and Linux

> **Disclaimer.** gomim is a debugging tool for inspecting traffic from clients you own and operate against services you are authorized to access. Treat captured logs as sensitive - they contain auth tokens and request bodies.

## Layout

```sh
cmd/gomim/         # CLI entrypoint
internal/ca/       # Root CA load/generate + leaf cert minting
internal/proxy/    # HTTP + CONNECT MITM handler, reverse-proxy mode
internal/logger/   # Streaming JSONL logger with pub/sub
internal/ui/       # Embedded HTML live viewer + SSE endpoint
scripts/install-ca.sh
```

## Install

Download the archive for your platform from the [latest release](https://github.com/rdmnl/gomim/releases/latest) and extract `gomim` onto your `$PATH`.

Pick the archive for your platform from the [releases page](https://github.com/rdmnl/gomim/releases/latest), extract `gomim` onto your `$PATH`, then run `gomim install-ca` once to trust the local root CA.

**macOS (Apple Silicon):**

```sh
curl -LO https://github.com/rdmnl/gomim/releases/latest/download/gomim_<version>_macos_arm64.tar.gz
tar -xzf gomim_<version>_macos_arm64.tar.gz
sudo mv gomim /usr/local/bin/
gomim install-ca
```

**macOS (Intel):** same, but use `gomim_<version>_macos_x86_64.tar.gz`.

**Linux (x86_64):**

```sh
curl -LO https://github.com/rdmnl/gomim/releases/latest/download/gomim_<version>_linux_x86_64.tar.gz
tar -xzf gomim_<version>_linux_x86_64.tar.gz
sudo mv gomim /usr/local/bin/
gomim install-ca   # uses sudo to write into the system trust store
```

`gomim install-ca` works on Debian/Ubuntu/Alpine (`update-ca-certificates`) and Fedora/RHEL/Arch (`update-ca-trust`). To remove the CA later: `gomim uninstall-ca`.

**Windows:** download `gomim_<version>_windows_x86_64.zip` from the releases page, unzip, and add `gomim.exe` to your `PATH`. (Trust-store install is not yet automated on Windows - import `%USERPROFILE%\.gomim\ca.pem` into "Trusted Root Certification Authorities" via `certmgr.msc`.)

**From source** (requires Go 1.26+):

```sh
go install github.com/rdmnl/gomim/cmd/gomim@latest
```

## First run

1. Start the proxy. On the first run it generates a root CA at `~/.gomim/ca.pem` (key in `ca.key`, mode 0600):

   ```sh
   go run ./cmd/gomim
   # gomim listening on 127.0.0.1:8080
   # CA at /Users/you/.gomim/ca.pem - install via scripts/install-ca.sh
   ```

2. Trust the root CA in your system trust store (one-time):

   ```sh
   gomim install-ca
   ```

   Works on macOS (login keychain) and Linux (Debian/Ubuntu/Alpine or Fedora/RHEL/Arch - auto-detected). Run `gomim uninstall-ca` to remove it.

3. Point a client at the proxy and make a request:

   ```sh
   HTTPS_PROXY=http://127.0.0.1:8080 HTTP_PROXY=http://127.0.0.1:8080 \
     curl https://api.github.com/zen
   ```

   You should see a JSONL request and response line in the proxy's stdout.

## Reverse-proxy mode (clients that ignore `HTTPS_PROXY`)

Some clients ship as a single compiled binary (Bun, Deno compile, Node SEA, Go, Rust) and embed their own HTTP stack. These often have **two code paths**: a "control plane" using a conventional HTTP client that honors `HTTPS_PROXY`, and a "data plane" (long-lived streams, websockets, large uploads) using a native fetch implementation with per-request options that **override** env vars.

Symptom: warm-up requests show up in the log, but the actual interesting calls don't.

When this happens, forward-proxy mode is useless. Use **reverse-proxy mode** instead, leveraging whatever `*_BASE_URL` / `*_API_HOST` / `*_ENDPOINT` env var the client exposes for pointing at a custom backend (most SDK-style tools have one - that's how they support self-hosted or staging environments).

```sh
# terminal 1: proxy fronts the real upstream
go run ./cmd/gomim -reverse https://api.example.com -log /tmp/gomim.jsonl

# terminal 2: tell the client to talk to the proxy instead of the real host
EXAMPLE_API_BASE_URL=http://127.0.0.1:8080 example-cli do-something
```

In this mode:

- No CONNECT, no MITM, no CA install required - the client makes plain HTTP to `127.0.0.1:8080` and the proxy forwards over TLS to `api.example.com`.
- Both control-plane and data-plane requests flow through the same code path and end up in the log.
- Only traffic to the configured upstream is intercepted; calls to unrelated hosts bypass the proxy entirely.

Filter the log to one path family:

```sh
jq -c 'select(.path | startswith("/v1/"))' /tmp/gomim.jsonl
```

## Forward-proxy mode (clients that honor `HTTPS_PROXY`)

For tools that honor `HTTPS_PROXY` (curl, most axios/requests/Go clients), use the original forward-proxy mode with the installed CA:

```sh
HTTPS_PROXY=http://127.0.0.1:8080 HTTP_PROXY=http://127.0.0.1:8080 \
  curl https://api.github.com/zen
```

HTTP/2 and streaming responses (SSE, long-poll, chunked) are handled in either mode.

## Flags

| flag       | default            | description                              |
|------------|--------------------|------------------------------------------|
| `-addr`    | `127.0.0.1:8080`   | listen address                           |
| `-ca-dir`  | `~/.gomim`         | directory for root CA cert/key           |
| `-log`     | (stdout)           | append JSONL records to this file        |
| `-reverse` | (off)              | reverse-proxy mode: forward all requests to this upstream URL (e.g. `https://api.example.com`) |
| `-ui`      | (off)              | live web viewer listen address (e.g. `127.0.0.1:8081`) |
| `-no-redact` | (off)            | log sensitive headers (Authorization, Cookie, X-Api-Key, …) in plaintext |
| `-version` | -                  | print version and exit                   |

Example:

```sh
go run ./cmd/gomim -addr 127.0.0.1:9000 -log /tmp/gomim.jsonl -ui 127.0.0.1:8081
```

## Live viewer

Pass `-ui 127.0.0.1:8081` and open <http://127.0.0.1:8081> in a browser. You'll get a two-pane viewer (request list + headers/body detail) that streams new records over SSE in real time. Filter by host or path, pause/resume, clear. JSON bodies are pretty-printed automatically. The HTML is embedded in the binary - no external assets.

## Log format

One JSON object per line. Two record kinds:

```json
{"time":"2026-04-07T12:00:00Z","kind":"request","method":"POST","host":"api.example.com","path":"/v1/widgets","headers":{"Content-Type":"application/json","Authorization":"Bearer …"},"body":"{…}"}
{"time":"2026-04-07T12:00:00Z","kind":"response","host":"api.example.com","path":"/v1/widgets","status":201,"headers":{"Content-Type":"application/json"},"body":"{…}","duration_ms":42}
```

Bodies are captured up to 64 KB; `body_truncated: true` indicates the wire payload was larger. Truncation only affects logs - the full body is always streamed to the client unmodified.

## Caveats

- **Certificate pinning** breaks MITM. Apps that pin (most mobile SDKs, some desktop apps) will fail. `curl` and standard Go/Node/Python HTTP clients do not pin and work fine.
- **HTTP/3 (QUIC)** is not intercepted. Out of scope.
- **Process scoping** is via env var only. Anything that ignores `HTTPS_PROXY` (or sets it explicitly) bypasses the proxy. PF-based redirection is left as future work.
- **Sensitive headers** (`Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, …) are redacted by default; pass `-no-redact` to disable. Request/response **bodies** are still captured in plaintext - treat the log file as secret.
- **Upstream verification** uses Go defaults - invalid upstream certs cause a 502.

## Uninstall

```sh
gomim uninstall-ca   # removes the trusted root from your system store
rm -rf ~/.gomim      # deletes the generated CA cert + key
sudo rm /usr/local/bin/gomim
```

## License

MIT - see [LICENSE](LICENSE).