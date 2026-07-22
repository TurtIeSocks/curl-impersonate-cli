# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- The raw `curl-impersonate` binary path (custom [`Fingerprint`]) now passes
  `--compressed`, so `gzip`/`br`/`zstd` responses are decoded. The `--impersonate`
  baseline advertises `Accept-Encoding` (a real browser does), so the server
  compresses; without `--compressed` the returned body was raw compressed bytes.
  The `curl_chromeNNN` wrapper scripts already pass it — the raw binary had no
  wrapper to, so `build_argv` now adds it unconditionally (a duplicate is
  idempotent to curl).

## [0.2.0] - 2026-07-16

### Added

- Optional `mcp` cargo feature building a `curl-impersonate-mcp` binary — a
  stdio [Model Context Protocol](https://modelcontextprotocol.io) server (built
  on the `rmcp` SDK) that exposes the request API as tools for LLM agents:
  - `curl_impersonate_fetch` — GET/POST with a byte-exact browser fingerprint,
    overriding headers/cookies/body/proxy; returns typed status, cookies,
    headers, body (context-capped via `max_body_chars`), and `final_url`.
  - `curl_impersonate_ensure_browser` — download + cache a `curl_<browser>`
    wrapper and return its path.

  The `mcp` feature implies `download`, so `fetch` self-bootstraps a missing
  wrapper on first use. Kept off the default library build.

## [0.1.0] - 2026-07-11

Initial release.

### Added

- Async subprocess wrapper around the [lexiforest/curl-impersonate](https://github.com/lexiforest/curl-impersonate)
  `curl_chromeNNN` CLI wrappers, for HTTP requests with a byte-exact Chrome
  TLS ClientHello + HTTP/2 fingerprint. One process per request; no native
  build dependencies.
- Builder API: `Request::get` / `Request::post`, with chainable setters
  `header`, `headers`, `remove_header`, `cookies`, `body`, `proxy`,
  `timeout_secs`, `insecure`, `max_filesize`, `follow_redirects`, and
  `max_redirs`, terminated by `.send().await`.
- Typed `Response` with `status`, `set_cookies` (raw `Set-Cookie` lines
  accumulated across the redirect/`CONNECT` chain), `headers` (the final
  response block), `body`, and `final_url` (`%{url_effective}`).
- Header override semantics mirroring curl's `-H`: `header` *replaces* an
  impersonation default of the same name; `remove_header` *drops* one — the
  mechanism for turning navigation headers into a `fetch()`/CORS set without
  disturbing the fingerprint.
- `ProxySpec` proxy support with credentials passed via the `ALL_PROXY`
  environment variable (owner-only) rather than argv (world-readable).
- Argument-injection hardening: `--` terminates option parsing so a
  caller-controlled URL cannot be interpreted as a curl flag (CWE-88).
- Browser-faithful redirect handling: `follow_redirects` is opt-in, and a
  POST that hits a 301/302/303 downgrades to a bodyless GET (no re-POST of
  credentials across hops).
- Optional `download` cargo feature exposing `download::ensure_binary` to
  fetch + cache a prebuilt curl-impersonate release at runtime (Linux/macOS).

[Unreleased]: https://github.com/TurtIeSocks/curl-impersonate-cli/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/TurtIeSocks/curl-impersonate-cli/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/TurtIeSocks/curl-impersonate-cli/releases/tag/v0.1.0
