# curl-impersonate-cli

**Async Rust wrapper around the [curl-impersonate](https://github.com/lexiforest/curl-impersonate) CLI — make HTTP requests with a byte-exact Chrome TLS + HTTP/2 fingerprint, from a safe builder API.**

[![crates.io](https://img.shields.io/crates/v/curl-impersonate-cli.svg)](https://crates.io/crates/curl-impersonate-cli)
[![docs.rs](https://img.shields.io/docsrs/curl-impersonate-cli)](https://docs.rs/curl-impersonate-cli)
[![CI](https://github.com/TurtIeSocks/curl-impersonate-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/TurtIeSocks/curl-impersonate-cli/actions/workflows/ci.yml)
[![license](https://img.shields.io/crates/l/curl-impersonate-cli.svg)](./LICENSE)

## What & why

`curl-impersonate-cli` spawns the [lexiforest/curl-impersonate](https://github.com/lexiforest/curl-impersonate) `curl_chromeNNN` wrapper binaries as a subprocess, one process per request, and parses the response back into a typed `Response`.

curl-impersonate links a **patched BoringSSL + nghttp2**, so its wrappers emit a *byte-exact* Chrome TLS ClientHello and HTTP/2 `SETTINGS`/pseudo-header order — the exact fingerprint that anti-bot vendors (Imperva, Akamai, DataDome, …) cross-check against the `User-Agent`. Pure-Rust and emulating HTTP stacks (`reqwest`, and even BoringSSL-backed clients like `wreq`/`rquest`) only *approximate* it; the wrapper *is* the browser's stack.

This crate owns none of the fingerprint. The `curl_chromeNNN` wrapper sets every TLS/HTTP2 flag; we override only the request-level inputs — method, URL, headers, cookies, body, proxy — and read back status, cookies, headers, and body.

**The model, honestly:**

- **It shells out.** Every `.send()` spawns the `curl_chromeNNN` binary, writes any body to its stdin, and reads its stdout. The subprocess is OS-isolated — no native code is linked into your process, so there are **zero native build dependencies** (no BoringSSL to compile, no `*-sys` crate, no `cc`).
- **It therefore requires a curl-impersonate install on the host.** No binary, no requests. See [Requirements](#requirements).
- **One process per request.** Fine for auth flows, scrapers, and token mints where fingerprint parity is the whole point. If you need thousands of requests/sec in-process with connection pooling, an in-process client is the better tool — see [How it compares](#how-it-compares).

Reach for this when a target *actively fingerprints TLS/HTTP2* and an emulated client gets blocked. Reach for an in-process client (`reqwest`, `wreq`) when it doesn't.

## Requirements

You need the curl-impersonate `curl_chromeNNN` wrapper binaries on the host. Two ways:

**(a) Install it yourself** (recommended for production — you control the version):

- Prebuilt releases: <https://github.com/lexiforest/curl-impersonate/releases> (Linux + macOS).
- Distro / package managers ship it too, e.g. the community `curl-impersonate` packages on the AUR, Homebrew taps, and various Docker images. Check the [upstream README](https://github.com/lexiforest/curl-impersonate) for the current list.

After installing, confirm a wrapper is on your `PATH`:

```sh
curl_chrome146 --version
```

**(b) Enable the `download` feature** to fetch a prebuilt release into a cache dir at runtime:

```rust,ignore
use curl_impersonate_cli::{Request, download::{ensure_binary, DownloadOptions}};

// Enabled only with `--features download`. Returns the path to a usable
// `curl_chromeNNN` wrapper, downloading + extracting a prebuilt release on
// first use and caching it thereafter. The returned PathBuf flows straight
// into `Request::get`.
let bin = ensure_binary("chrome146", &DownloadOptions::default()).await?;
let resp = Request::get(bin, "https://example.com/").send().await?;
```

The `download` feature targets **Linux and macOS** — upstream ships **no prebuilt Windows CLI**, so on Windows you must supply the binary yourself (e.g. via WSL or a self-built wrapper).

## Install

```sh
cargo add curl-impersonate-cli
```

With the runtime downloader:

```sh
cargo add curl-impersonate-cli --features download
```

> The crate is published as `curl-impersonate-cli`; the library imports as `curl_impersonate_cli`.

## Quick start

### GET

```rust,no_run
use curl_impersonate_cli::Request;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let resp = Request::get("curl_chrome146", "https://example.com/")
        .header("Accept", "text/html")
        .timeout_secs(20.0)
        .send()
        .await?;

    println!("status: {}", resp.status);           // u16
    for cookie in &resp.set_cookies {              // Vec<String>, raw Set-Cookie lines
        println!("set-cookie: {cookie}");
    }
    println!("body:\n{}", resp.body);              // String (curl-decompressed)
    Ok(())
}
```

### POST with a body

```rust,no_run
use curl_impersonate_cli::Request;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let resp = Request::post("curl_chrome146", "https://httpbin.org/post")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(b"user=comrade&note=solidarity".to_vec())
        .follow_redirects(true) // POST -> 30x downgrades to a bodyless GET, like a browser
        .send()
        .await?;

    println!("status: {}", resp.status);
    if let Some(url) = &resp.final_url {
        println!("final url: {url}"); // %{url_effective} after -L
    }
    println!("body:\n{}", resp.body);
    Ok(())
}
```

Both are runnable from the repo (they need a `curl_chrome146` on `PATH`):

```sh
cargo run --example get
cargo run --example post
```

## Header semantics

The whole point of the crate is to override request-level inputs **without disturbing the fingerprint**. Headers follow curl's `-H` rules exactly:

- **`.header("Name", "value")`** emits `-H 'Name: value'`, which *replaces* the impersonation's default header of that name (matching is case-insensitive).
- **`.remove_header("Name")`** emits `-H 'Name:'` (empty value), which *removes* a header the wrapper would otherwise send.

That pairing is how you turn the wrapper's default *navigation* headers into a `fetch()`/CORS set — drop `Sec-Fetch-User`, flip `Sec-Fetch-Mode`, add `Origin`, etc. — while the TLS/HTTP2 fingerprint underneath stays byte-identical to Chrome.

```rust,no_run
use curl_impersonate_cli::Request;

# async fn f() -> Result<(), Box<dyn std::error::Error>> {
let resp = Request::get("curl_chrome146", "https://api.example.com/data")
    .header("Sec-Fetch-Mode", "cors")
    .header("Sec-Fetch-Dest", "empty")
    .header("Origin", "https://example.com")
    .remove_header("Sec-Fetch-User")   // navigation-only, not sent by fetch()
    .send()
    .await?;
# let _ = resp;
# Ok(()) }
```

## Proxy

Proxies are passed as a single URL via `ProxySpec`:

```rust,no_run
use curl_impersonate_cli::{ProxySpec, Request};

# async fn f() -> Result<(), Box<dyn std::error::Error>> {
let proxy = ProxySpec {
    url: "http://enc_user:enc_pass@proxy.example.com:8080".into(),
};

let resp = Request::get("curl_chrome146", "https://example.com/")
    .proxy(Some(proxy))
    .send()
    .await?;
# let _ = resp;
# Ok(()) }
```

Credentials are handed to curl through the **`ALL_PROXY` environment variable, not argv** — so they never land in world-readable `/proc/<pid>/cmdline`; the process environment is owner-only. The caller is responsible for **percent-encoding** the userinfo (`user`/`pass`) in the URL.

## Feature flags

| Feature    | Default | Description                                                                                                 |
| ---------- | :-----: | ----------------------------------------------------------------------------------------------------------- |
| `download` |    no   | Adds `download::ensure_binary` to fetch + cache a prebuilt curl-impersonate release at runtime (Linux/macOS). Pulls in `reqwest` (rustls), `flate2`, `tar`, and `dirs`. |

## How it compares

| Approach                                     | Fingerprint fidelity                        | Native build deps          | Model                          |
| -------------------------------------------- | ------------------------------------------- | -------------------------- | ------------------------------ |
| `reqwest`                                    | rustls/native-tls — clearly *not* a browser | none / system TLS          | in-process, pooled             |
| `wreq` / `rquest` (BoringSSL)                | close — BoringSSL, browser-*like* presets   | compiles BoringSSL (`cc`)  | in-process, pooled             |
| **`curl-impersonate-cli`** (this crate)      | **byte-exact** — the patched curl stack     | **none** (subprocess)      | subprocess, one per request    |

No Rust HTTP client reaches byte-parity without BoringSSL, because the ClientHello (extension order, GREASE, ALPS, compressed-cert, key-share) and the HTTP/2 layer (`SETTINGS` values, `WINDOW_UPDATE`, header order/priority) all have to match *exactly*. `wreq`/`rquest` link BoringSSL directly and get *very* close with curated presets — often close enough, in-process, with pooling, and they're excellent for that. curl-impersonate links a *patched* BoringSSL + nghttp2 tuned to reproduce a specific browser build down to the byte, which is why this crate wraps it verbatim rather than reimplementing the stack. Pick the in-process clients when they clear your target; reach for this when only byte-parity gets through.

## Credits

This crate is a thin wrapper — all of the hard fingerprinting work lives in **[lexiforest/curl-impersonate](https://github.com/lexiforest/curl-impersonate)** (MIT), the maintained fork of the original `curl-impersonate` project. It depends on curl-impersonate at runtime and is nothing without it. Please star and support the upstream project.

## License

Licensed under the [MIT License](./LICENSE).
