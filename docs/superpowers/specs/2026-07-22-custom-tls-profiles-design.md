# Design: Custom TLS/HTTP2 fingerprint profiles

**Date:** 2026-07-22
**Status:** Approved (design), pre-implementation
**Crate:** `curl-impersonate-cli`

## Goal

Let a caller impersonate an **arbitrary captured fingerprint** — not just the
pre-compiled `curl_chromeNNN` wrapper for one browser version. A caller supplies
a profile (JA3 + Akamai H2 + user-agent, and optionally the richer raw
ClientHello arrays), and the crate synthesizes a `curl-impersonate` invocation
whose emitted fingerprint matches the target.

Concretely, this must accept a capture like the `android-chrome-149-s10lite`
profile (Chrome 149 on Android, a version with no pre-built wrapper) and
reproduce it from the `chrome146` baseline.

## Fidelity target (honest)

Byte-exact *per-connection* JA3 is **impossible and not the target** — real
Chrome permutes TLS extensions and GREASEs every connection, so its own raw JA3
md5 varies per connection (the capture's own note says so). The achievable,
correct target is **JA4 / Akamai-H2 / peetprint parity plus reproduction of the
randomization behavior** (`--tls-grease`, `--tls-permute-extensions`). This is
exactly what the capture's `exactTo` / `note` fields claim, so we are aligned.

## The core model: baseline + overlay (not from-scratch)

This is the load-bearing design decision, forced by how curl-impersonate works.

`--tls-extension-order` only **reorders extensions curl already emits** — it
cannot *add* ALPS (17613), ECH (65037), certificate compression, application
settings, etc. A bare `curl-impersonate` invoked with a handful of TLS flags
sends BoringSSL defaults for everything unset, so a Chrome capture will **not**
reproduce from scratch.

Therefore, matching the proven reference implementation (`curl_cffi`), a custom
profile is applied as **baseline + overlay**:

1. **Baseline:** `--impersonate <base>` establishes the full browser ClientHello
   (every extension, GREASE, permute, ALPS, cert-compression, session ticket,
   SCT, …). The base comes from the capture's `tlsProfile` field
   (`"Chrome_146"` → `chrome146`).
2. **Overlay:** the profile's ciphers / curves / extension-order / signature
   algorithms / HTTP-2 (and optional HTTP-3) flags **override** the baseline to
   match the specific capture. Impersonating "chrome149" = `chrome146` baseline
   + UA / `sec-ch-ua` swap + any cipher/order deltas.

`base_target: None` still permits true from-scratch synthesis (no
`--impersonate`) for simple non-browser targets (e.g. okhttp); that is the
caller's risk and explicitly not the browser-fidelity path.

This is also *why* `bin` changes: a custom request runs the **raw
`curl-impersonate` binary**, not a `curl_chromeNNN` wrapper (the wrapper
hard-codes one browser's flags and would double up with the overlay).

## Non-goals (YAGNI)

- **No live fingerprint harvesting.** The crate stays provider-agnostic; the
  caller supplies the capture. `impersonate.pro` / the `pro` API is out of scope.
- **No fields the CLI cannot set.** `CURLOPT_FORM_BOUNDARY` and
  `CURLOPT_TLS_STATUS_REQUEST` exist in libcurl-impersonate but have **no CLI
  flag** (per the upstream API reference), so a subprocess wrapper cannot set
  them. Documented as a known limitation; they come from the baseline.
- **No change to the preset path.** `Request::get(curl_chrome146, url)` behaves
  byte-for-byte as today.

## Architecture & module layout

```
src/
  lib.rs          + Request.fingerprint: Option<Fingerprint>
                  + Request::fingerprint(fp) setter
                  + build_argv splices fp.to_args() before `--`
  fingerprint.rs  NEW — Fingerprint struct + builder, ID→name tables,
                        ja3/akamai/perk parsers, to_args(), CertComp/Alps enums
  download.rs     + ensure_impersonate_binary() → raw `curl-impersonate` path
```

**Dependency policy (default build stays tokio + thiserror only):**

- **Default feature:** the entire `Fingerprint` builder, ID→name tables,
  ja3/akamai/perk **string parsers**, and `to_args()`. Pure Rust, **zero new
  deps** — string/int parsing needs no serde. A caller can build a `Fingerprint`
  from a JA3 string, an Akamai string, and `Vec<u16>` arrays with no features on.
- **New `serde` feature:** `#[derive(Deserialize)]` on the schema plus
  `Fingerprint::from_capture_json(&str)`. Only the JSON-file path pulls
  `serde` + `serde_json`. Mirrors the existing opt-in `download` / `mcp` model.

## The `Fingerprint` schema

The crate's own clean type (not the harvester's nesting). Canonical form is
**decomposed numeric IDs**, so it is source-agnostic. Every field maps to a
verified curl-impersonate CLI flag.

```rust
pub struct Fingerprint {
    // --- Baseline ---
    /// `--impersonate <base>`. From the capture's `tlsProfile` (normalized).
    /// `None` = from-scratch (no baseline; simple/non-browser targets only).
    pub base_target: Option<String>,
    /// `--impersonate <base>` vs `<base>:no`. Default true (keep browser
    /// default headers + order; UA is overridden separately).
    pub default_headers: bool,
    /// User-Agent override, applied as a `-H` header (composes with the
    /// existing header override/remove semantics).
    pub user_agent: Option<String>,

    // --- TLS overlay (from ja3 / raw arrays) ---
    pub tls_version_min: Option<u16>,     // 771→--tlsv1.2, 772→--tlsv1.3
    pub ciphers: Vec<u16>,               // → --ciphers  (names, ':'-joined)
    pub curves: Vec<u16>,                // → --curves   (names, ':'-joined)
    pub extension_order: Vec<u16>,        // → --tls-extension-order (SKIP if permute)
    pub sig_hash_algs: Vec<u16>,          // → --signature-hashes (names, ','-joined)
    pub cert_compression: Vec<CertComp>,  // → --cert-compression (','-joined)
    pub grease: bool,                    // → --tls-grease
    pub permute_extensions: bool,         // → --tls-permute-extensions

    // --- extra_fp advanced (default none; overlay only when set) ---
    pub record_size_limit: Option<u16>,   // → --tls-record-size-limit
    pub delegated_credentials: Option<String>, // → --tls-delegated-credentials
    pub key_shares_limit: Option<u8>,     // → --tls-key-shares-limit
    pub alps: Option<AlpsMode>,           // → --alps [+ --tls-use-new-alps-codepoint]
    pub session_ticket: Option<bool>,     // → --tls-session-ticket / --no-tls-session-ticket
    pub signed_cert_timestamps: bool,     // → --tls-signed-cert-timestamps
    pub no_npn: bool,                    // → --no-npn
    pub no_alpn: bool,                   // → --no-alpn

    // --- HTTP/2 overlay (from akamai) ---
    pub h2_settings: Vec<(u16, u32)>,     // → --http2-settings 1:v;2:v;...
    pub h2_window_update: Option<u32>,    // → --http2-window-update
    pub h2_streams: Option<String>,       // → --http2-streams  (SKIP if "0")
    pub h2_pseudo_order: Option<String>,  // → --http2-pseudo-headers-order (masp)
    pub h2_stream_exclusive: Option<u8>,  // → --http2-stream-exclusive
    pub h2_no_priority: bool,             // → --http2-no-priority
    pub split_cookies: Option<bool>,      // → --split-cookies / --no-split-cookies

    // --- HTTP/3 overlay (from perk) — full support ---
    pub enable_http3: bool,               // → --http3
    pub h3_settings: Option<String>,      // → --http3-settings
    pub h3_pseudo_order: Option<String>,  // → --http3-pseudo-headers-order (masp)
    pub h3_sig_hash_algs: Option<String>, // → --http3-sig-hash-algs
    pub h3_tls_extension_order: Option<String>, // → --http3-tls-extension-order
    pub quic_transport_params: Option<String>,  // → --quic-transport-params

    // --- headers / proxy ---
    pub header_order: Vec<String>,        // → --http-header-order (comma-joined names)
    pub proxy_credential_no_reuse: bool,  // → --proxy-credential-no-reuse
}

pub enum CertComp { Zlib, Brotli, Zstd }
pub enum AlpsMode { Legacy, NewCodepoint } // 17513 vs 17613
```

Note: `--http2-stream-weight` has **no standalone CLI flag** — stream weight is
encoded inside the `--http2-streams` priority tuple (e.g. `1:0:0:201`), so there
is no separate schema field for it.

### Constructors

- **Builder (default feature):**
  `Fingerprint::builder().base_target("chrome146").ja3(s).akamai(s).user_agent(s).build()`.
  The `.ja3()` / `.akamai()` / `.perk()` setters run the parsers below.
- **JSON (`serde` feature):** `Fingerprint::from_capture_json(&str)` reads the
  common capture fields (`ua`, `tls.tlsProfile`, `tls.captured.ja3`,
  `tls.captured.akamai`) and, when present, the richer
  `tls.captured.raw.raw.*` arrays. It **prefers the raw arrays** (they carry
  signature algorithms, key shares, GREASE, and cert compression that JA3 lacks)
  and falls back to the JA3/Akamai strings for anything absent. It is lenient
  about the exact nesting depth so it survives minor harvester changes.

## `to_args()` synthesis rules (ported verbatim from `curl_cffi`)

Emitted in a stable order; all values below are **confirmed against
`curl_cffi`'s unit tests**.

1. **Baseline first:** if `base_target = Some(t)` → `--impersonate t` (or
   `--impersonate t:no` when `default_headers = false`).
2. **TLS version:** `tls_version_min` → `--tlsv1.2` (771) / `--tlsv1.3` (772).
   No `--tls-max` (let it negotiate up, matching `MAX_DEFAULT`).
3. **Ciphers:** map each id → BoringSSL name via `TLS_CIPHER_NAME_MAP`, join with
   `:`, emit `--ciphers <names>`. **All ciphers go in one `--ciphers` list**
   (TLS 1.3 suites included — no split into `--tls13-ciphers`). Unknown id →
   hard error naming the hex id.
4. **Curves:** map each id → name via `TLS_EC_CURVES_MAP`, join `:`, emit
   `--curves <names>`. Unknown id → hard error.
5. **Extension order:** `--tls-extension-order <a-b-c>` **only if
   `permute_extensions == false`**. When permuting, curl randomizes order and
   setting an explicit order is wrong (matches `curl_cffi`).
6. **Signature algorithms:** map each id → name via `SIG_HASH_ALG_MAP`, join with
   `,`, emit `--signature-hashes <names>`.
7. **extra_fp flags:** `--tls-grease` (if `grease`), `--tls-permute-extensions`
   (if `permute_extensions`), `--cert-compression <list>`,
   `--tls-record-size-limit`, `--tls-delegated-credentials`,
   `--tls-key-shares-limit`, `--alps` (+ `--tls-use-new-alps-codepoint` for
   `NewCodepoint`), `--tls-session-ticket`/`--no-tls-session-ticket`,
   `--tls-signed-cert-timestamps`, `--no-npn`, `--no-alpn`.
8. **HTTP/2:** `--http2-settings` (semicolon-joined `id:value`),
   `--http2-window-update`, `--http2-streams` (**omit if the value is `"0"`**),
   `--http2-pseudo-headers-order <masp>` (commas stripped),
   `--http2-stream-exclusive`, `--http2-no-priority`,
   `--split-cookies`/`--no-split-cookies`.
9. **HTTP/3:** `--http3`, `--http3-settings`, `--http3-pseudo-headers-order`,
   `--http3-sig-hash-algs`, `--http3-tls-extension-order`,
   `--quic-transport-params`.
10. **Headers:** `--http-header-order <comma,list>`;
    `--proxy-credential-no-reuse`.

### Parser rules

- **JA3** `version,ciphers,extensions,curves,curve_formats`:
  - `version` → `tls_version_min` (asserts 771 for now, as `curl_cffi` does).
  - `ciphers` (dash-split) → `ciphers`.
  - `extensions` (dash-split) → `extension_order`; if it ends with `-21`
    (padding), strip the trailing `21` (SSL engine manages padding).
  - `curves` (dash-split) → `curves`. `curve_formats` must be `0`.
- **Akamai** `settings|window_update|streams|pseudo_order`:
  - `settings`: replace `,` with `;` → `h2_settings` (peet.ws compat).
  - `window_update` → `h2_window_update`.
  - `streams` → `h2_streams` (kept as-is; `to_args` omits it when `"0"`).
  - `pseudo_order` `m,a,s,p` → strip commas → `h2_pseudo_order = "masp"`.
- **perk (HTTP/3)** `settings|pseudo_order|quic_transport_params` → the three
  `h3_*` / `quic_*` fields.

### GREASE handling (raw-array path only)

JA3 strings are GREASE-free by convention, so the string parsers need no GREASE
handling. When building from **raw arrays**, values matching the GREASE pattern
(`0x0A0A, 0x1A1A, … 0xFAFA` — i.e. `(v & 0x0F0F) == 0x0A0A`) are **stripped**
from the cipher/curve/extension/version/sigalg lists before name-mapping, and
any GREASE seen sets `grease = true`. Verified against the target capture:
cipher `64250` (`0xFAFA`), group `14906` (`0x3A3A`), extensions `39578`
(`0x9A9A`) and `35466` (`0x8A8A`), version `43690` (`0xAAAA`) all strip cleanly.

## ID → name tables to port

From `curl_cffi/requests/impersonate.py` (verbatim, keep source comment):

- `TLS_CIPHER_NAME_MAP` — ~40 entries (IANA id → BoringSSL cipher name).
- `TLS_EC_CURVES_MAP` — id → curve name, incl. `4588 → "X25519MLKEM768"`,
  `29 → "X25519"`, `23 → "P-256"`, `24 → "P-384"`.
- `SIG_HASH_ALG_MAP` — **built for this crate** from RFC 8446 §4.2.3 (curl_cffi
  expects the caller to pass names, so it has no such map). Needed for the
  raw-array path. Entries the target capture needs:
  `0x0403 ecdsa_secp256r1_sha256`, `0x0804 rsa_pss_rsae_sha256`,
  `0x0401 rsa_pkcs1_sha256`, `0x0503 ecdsa_secp384r1_sha384`,
  `0x0805 rsa_pss_rsae_sha384`, `0x0501 rsa_pkcs1_sha384`,
  `0x0806 rsa_pss_rsae_sha512`, `0x0601 rsa_pkcs1_sha512`, plus the rest of the
  registry (`ecdsa_secp521r1_sha512`, `ed25519`, `rsa_pss_pss_*`,
  `rsa_pkcs1_sha1`, `ecdsa_sha1`).

## `download::ensure_impersonate_binary`

The `download` feature already extracts the whole CLI tarball, which **includes
the base `curl-impersonate` binary** next to the wrappers. The new function
reuses `ensure_binary`'s download/extract/atomic-place logic and only differs in
the final filename lookup (`curl-impersonate` instead of `curl_<browser>`).
Returns the canonicalized absolute path to pass as `bin`.

## `Request` integration

- New field `fingerprint: Option<Fingerprint>`; setter
  `Request::fingerprint(mut self, fp: Fingerprint) -> Self`.
- `build_argv`: when `Some(fp)`, splice `fp.to_args()` **after** the existing
  `-sS -i --max-time … -w …` and redirect/method flags, **before** the closing
  `--`/URL. Header (`-H` override/remove), cookie (`-b`), proxy (env), and body
  (stdin) handling are unchanged; a profile's `--http-header-order` composes
  with the caller's explicit `-H` overrides.
- **Wrapper-vs-raw is a documented contract, not enforced.** We cannot reliably
  detect a wrapper path, so the docs state: a `Fingerprint` expects the raw
  `curl-impersonate` binary; combining it with a `curl_chromeNNN` wrapper would
  double the impersonation flags. Same spirit as the existing `bin` doc.

## Errors

New variants (on `CurlError` or a dedicated `FingerprintError` folded into it):

- `UnknownCipher { id: u16 }`, `UnknownCurve { id: u16 }`,
  `UnknownSigAlg { id: u16 }` — strict-error policy on unmapped ids.
- `MalformedJa3 { input, reason }`, `MalformedAkamai { input, reason }`.
- (`serde` feature) `InvalidCaptureJson(String)`.

## Testing

- **Pure unit tests (bulk, CI-safe, no network/binary):** each parser →
  expected fields; each field → expected flag; the golden `curl_cffi` output
  formats (`--ciphers` `:`-joined, `--signature-hashes` `,`-joined, permute
  skips extension-order, streams `"0"` omitted, `masp`); GREASE strip;
  unknown-id → error.
- **Golden test from the target capture JSON:** feed the
  `android-chrome-149-s10lite` capture through `from_capture_json` and assert
  the synthesized argv contains `--impersonate chrome146`, the expected cipher
  names, `--curves` incl. `X25519MLKEM768`,
  `--http2-settings 1:65536;2:0;4:6291456;6:262144`,
  `--http2-window-update 15663105`, `--http2-pseudo-headers-order masp`,
  `--tls-grease`, `--tls-permute-extensions`, and the decoded
  `--signature-hashes` list.
- **Ignored integration test (opt-in, like `ensures_binary_downloads`):** run
  the real binary against a JA4/H2 echo endpoint and assert `ja4` /
  `akamai_hash` match the target. `#[ignore]` — needs network + binary.

## Assumptions

- The installed `curl-impersonate` build supports the required flags (it is the
  lexiforest fork; the flags are verified against its API reference).
- The base target named by a capture's `tlsProfile` exists in the installed
  binary's native list. If not, `to_args` still emits `--impersonate <name>` and
  the binary errors — surfaced as a normal `CurlError::NonZero`. (A future
  refinement could validate against the known native list.)
- HTTP/3 requires an H3-capable `curl-impersonate` build and a reachable QUIC
  endpoint; flags are emitted regardless, and transport failures surface
  normally.
- `docs.rs` builds with `download` (unchanged); the new `serde` feature is added
  to the docs feature set so the JSON path is documented.
