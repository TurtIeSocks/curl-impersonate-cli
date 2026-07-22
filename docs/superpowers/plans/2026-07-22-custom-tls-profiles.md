# Custom TLS/HTTP2 Fingerprint Profiles — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a caller impersonate an arbitrary captured fingerprint (JA3 + Akamai H2 + UA + raw ClientHello arrays) by driving the raw `curl-impersonate` binary with a `--impersonate <base>` baseline plus a synthesized granular-flag overlay.

**Architecture:** A new `Fingerprint` type holds a decomposed profile (numeric cipher/curve/sigalg ids, HTTP/2 & HTTP/3 strings, toggles). `to_args()` maps it to verified curl-impersonate CLI flags using ported id→name tables. `Request` gains a `.fingerprint()` setter; `run()` computes the flags (propagating a strict error on any unmapped id) and `build_argv` splices them before the URL. A `serde`-gated `from_capture_json` reads a capture, preferring the richer raw arrays over the JA3/Akamai strings.

**Tech Stack:** Rust 2024, tokio (process), thiserror. Optional: serde + serde_json (`json` feature), reqwest/flate2/tar/dirs (`download` feature, already present).

## Global Constraints

- **Rust edition 2024, rust-version 1.85** — match `Cargo.toml`.
- **Default build stays `tokio` + `thiserror` only.** The whole `Fingerprint` builder + parsers + `to_args` + tables are pure Rust with **zero new default deps**. Only the JSON path pulls serde; it lives behind a new opt-in `json` feature (`json = ["dep:serde", "dep:serde_json"]`).
- **Preset path is untouched.** `Request::get(curl_chrome146, url)` must behave byte-for-byte as today.
- **Baseline + overlay model.** A custom profile runs the raw `curl-impersonate` binary with `--impersonate <base>` first, then overlay flags. `base_target: None` = from-scratch (no baseline), the caller's risk.
- **Strict unknown-id policy.** An unmapped cipher/curve/sigalg id is a hard error naming the hex id — never silently dropped.
- **Golden output formats (verified against curl_cffi unit tests):** `--ciphers` = names joined by `:` (all suites, no tls13 split); `--curves` = names joined by `:`; `--signature-hashes` = names joined by `,`; `--tls-extension-order` is **omitted when permuting**; `--http2-settings` uses `;` separators; `--http2-streams` is **omitted when the value is `"0"`**; pseudo-header order `m,a,s,p` → `masp` (commas stripped).
- **Commit after every task.** Conventional commit messages. End bodies with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` only if the repo convention wants it (match existing history — it does not, so a plain trailer-free body is fine).

---

## File Structure

- **Create `src/fingerprint.rs`** — the `Fingerprint` struct + builder, `CertComp`/`AlpsMode` enums, `FingerprintError`, id→name tables (`cipher_name`/`curve_name`/`sig_hash_name`/`is_grease`), the `ja3`/`akamai`/`perk` parsers, `from_raw_arrays`, `to_args()`, and (behind `#[cfg(feature = "json")]`) serde derives + `from_capture_json`. Single file, matching the crate's existing flat-file convention (`download.rs` is ~780 lines). Tables use `match` (zero-alloc, no HashMap).
- **Modify `src/lib.rs`** — `pub mod fingerprint;` + re-exports; add `fingerprint: Option<Fingerprint>` to `Request`; add `.fingerprint()` setter; change `build_argv` to take `fp_args: &[String]`; compute `fp.to_args()?` in `run`; add `CurlError::Fingerprint`.
- **Modify `src/download.rs`** — add `ensure_impersonate_binary()` returning the raw `curl-impersonate` path from the same extracted release.
- **Modify `Cargo.toml`** — add `json` feature + optional `serde_json`; add `json` to `docs.rs` features.
- **Modify `README.md`** — a "Custom fingerprint profiles" section.

---

### Task 1: Scaffold the `fingerprint` module

**Files:**
- Create: `src/fingerprint.rs`
- Modify: `src/lib.rs` (add `pub mod fingerprint;` + re-exports)

**Interfaces:**
- Produces: `Fingerprint` (all public fields per the schema), `CertComp { Zlib, Brotli, Zstd }`, `AlpsMode { Legacy, NewCodepoint }`, `FingerprintError`, `Fingerprint::builder() -> FingerprintBuilder`, `FingerprintBuilder::build() -> Fingerprint`.

- [ ] **Step 1: Write the failing test** — append to `src/fingerprint.rs` (create the file with just this test module for now):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_fingerprint_is_empty_overlay() {
        let fp = Fingerprint::default();
        assert!(fp.base_target.is_none());
        assert!(fp.default_headers, "default_headers defaults true");
        assert!(fp.ciphers.is_empty());
        assert!(!fp.grease);
    }

    #[test]
    fn builder_sets_base_target_and_ua() {
        let fp = Fingerprint::builder()
            .base_target("chrome146")
            .user_agent("UA/1.0")
            .build();
        assert_eq!(fp.base_target.as_deref(), Some("chrome146"));
        assert_eq!(fp.user_agent.as_deref(), Some("UA/1.0"));
        assert!(fp.default_headers);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib fingerprint::tests`
Expected: FAIL — `Fingerprint` / `FingerprintBuilder` not found (won't compile).

- [ ] **Step 3: Write minimal implementation** — prepend to `src/fingerprint.rs`:

```rust
//! Build an arbitrary captured fingerprint into curl-impersonate CLI flags.
//!
//! A [`Fingerprint`] is a decomposed profile (numeric cipher/curve/sigalg ids,
//! HTTP/2 & HTTP/3 strings, TLS toggles). [`Fingerprint::to_args`] maps it to the
//! curl-impersonate flags that reproduce it, applied as an overlay on a
//! `--impersonate <base>` baseline (see the crate docs on the baseline+overlay
//! model). Ported from the reference decomposition in `lexiforest/curl_cffi`.

/// TLS certificate-compression algorithm (`--cert-compression`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertComp {
    Zlib,
    Brotli,
    Zstd,
}

impl CertComp {
    fn as_str(self) -> &'static str {
        match self {
            CertComp::Zlib => "zlib",
            CertComp::Brotli => "brotli",
            CertComp::Zstd => "zstd",
        }
    }
}

/// ALPS codepoint variant. `Legacy` = extension 17513, `NewCodepoint` = 17613
/// (`--tls-use-new-alps-codepoint`), used by recent Chrome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlpsMode {
    Legacy,
    NewCodepoint,
}

/// Everything that can go wrong turning a [`Fingerprint`] into CLI flags.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum FingerprintError {
    #[error("cipher id {0:#06x} has no known BoringSSL name")]
    UnknownCipher(u16),
    #[error("curve/group id {0:#06x} has no known name")]
    UnknownCurve(u16),
    #[error("signature-algorithm id {0:#06x} has no known name")]
    UnknownSigAlg(u16),
    #[error("malformed JA3 {input:?}: {reason}")]
    MalformedJa3 { input: String, reason: String },
    #[error("malformed Akamai fingerprint {input:?}: {reason}")]
    MalformedAkamai { input: String, reason: String },
}

/// A decomposed browser/target fingerprint. Build with [`Fingerprint::builder`]
/// or (with the `json` feature) [`Fingerprint::from_capture_json`], then attach
/// via `Request::fingerprint`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    // Baseline
    pub base_target: Option<String>,
    pub default_headers: bool,
    pub user_agent: Option<String>,
    // TLS overlay
    pub tls_version_min: Option<u16>,
    pub ciphers: Vec<u16>,
    pub curves: Vec<u16>,
    pub extension_order: Vec<u16>,
    pub sig_hash_algs: Vec<u16>,
    pub cert_compression: Vec<CertComp>,
    pub grease: bool,
    pub permute_extensions: bool,
    // extra_fp advanced
    pub record_size_limit: Option<u16>,
    pub delegated_credentials: Option<String>,
    pub key_shares_limit: Option<u8>,
    pub alps: Option<AlpsMode>,
    pub session_ticket: Option<bool>,
    pub signed_cert_timestamps: bool,
    pub no_npn: bool,
    pub no_alpn: bool,
    // HTTP/2 overlay
    pub h2_settings: Vec<(u16, u32)>,
    pub h2_window_update: Option<u32>,
    pub h2_streams: Option<String>,
    pub h2_pseudo_order: Option<String>,
    pub h2_stream_exclusive: Option<u8>,
    pub h2_no_priority: bool,
    pub split_cookies: Option<bool>,
    // HTTP/3 overlay
    pub enable_http3: bool,
    pub h3_settings: Option<String>,
    pub h3_pseudo_order: Option<String>,
    pub h3_sig_hash_algs: Option<String>,
    pub h3_tls_extension_order: Option<String>,
    pub quic_transport_params: Option<String>,
    // headers / proxy
    pub header_order: Vec<String>,
    pub proxy_credential_no_reuse: bool,
}

impl Default for Fingerprint {
    fn default() -> Self {
        Self {
            base_target: None,
            default_headers: true,
            user_agent: None,
            tls_version_min: None,
            ciphers: Vec::new(),
            curves: Vec::new(),
            extension_order: Vec::new(),
            sig_hash_algs: Vec::new(),
            cert_compression: Vec::new(),
            grease: false,
            permute_extensions: false,
            record_size_limit: None,
            delegated_credentials: None,
            key_shares_limit: None,
            alps: None,
            session_ticket: None,
            signed_cert_timestamps: false,
            no_npn: false,
            no_alpn: false,
            h2_settings: Vec::new(),
            h2_window_update: None,
            h2_streams: None,
            h2_pseudo_order: None,
            h2_stream_exclusive: None,
            h2_no_priority: false,
            split_cookies: None,
            enable_http3: false,
            h3_settings: None,
            h3_pseudo_order: None,
            h3_sig_hash_algs: None,
            h3_tls_extension_order: None,
            quic_transport_params: None,
            header_order: Vec::new(),
            proxy_credential_no_reuse: false,
        }
    }
}

impl Fingerprint {
    pub fn builder() -> FingerprintBuilder {
        FingerprintBuilder {
            fp: Fingerprint::default(),
        }
    }
}

/// Builder for [`Fingerprint`]. Setters that parse fingerprint strings
/// (`ja3`/`akamai`/`perk`) are added in later tasks and return `Result`.
#[derive(Debug, Clone)]
pub struct FingerprintBuilder {
    fp: Fingerprint,
}

impl FingerprintBuilder {
    pub fn base_target(mut self, t: impl Into<String>) -> Self {
        self.fp.base_target = Some(t.into());
        self
    }

    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.fp.user_agent = Some(ua.into());
        self
    }

    pub fn default_headers(mut self, yes: bool) -> Self {
        self.fp.default_headers = yes;
        self
    }

    pub fn build(self) -> Fingerprint {
        self.fp
    }
}
```

Then add to `src/lib.rs` after the existing `#[cfg(feature = "download")] pub mod download;` block:

```rust
pub mod fingerprint;
pub use fingerprint::{AlpsMode, CertComp, Fingerprint, FingerprintError};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib fingerprint::tests`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add src/fingerprint.rs src/lib.rs
git commit -m "feat(fingerprint): scaffold Fingerprint schema, enums, builder, error type"
```

---

### Task 2: ID→name tables + GREASE detection

**Files:**
- Modify: `src/fingerprint.rs` (add table functions + tests)

**Interfaces:**
- Produces: `fn cipher_name(id: u16) -> Option<&'static str>`, `fn curve_name(id: u16) -> Option<&'static str>`, `fn sig_hash_name(id: u16) -> Option<&'static str>`, `fn is_grease(v: u16) -> bool`. All module-private (`pub(crate)` not needed; used only within the module).

- [ ] **Step 1: Write the failing test** — add to the `tests` module:

```rust
#[test]
fn cipher_names_map_known_ids() {
    assert_eq!(cipher_name(0x1301), Some("TLS_AES_128_GCM_SHA256"));
    assert_eq!(cipher_name(0xC02B), Some("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"));
    assert_eq!(cipher_name(0x002F), Some("TLS_RSA_WITH_AES_128_CBC_SHA"));
    assert_eq!(cipher_name(0xDEAD), None);
}

#[test]
fn curve_names_map_known_ids() {
    assert_eq!(curve_name(29), Some("X25519"));
    assert_eq!(curve_name(23), Some("P-256"));
    assert_eq!(curve_name(24), Some("P-384"));
    assert_eq!(curve_name(4588), Some("X25519MLKEM768"));
    assert_eq!(curve_name(9999), None);
}

#[test]
fn sig_hash_names_map_known_ids() {
    assert_eq!(sig_hash_name(0x0403), Some("ecdsa_secp256r1_sha256"));
    assert_eq!(sig_hash_name(0x0804), Some("rsa_pss_rsae_sha256"));
    assert_eq!(sig_hash_name(0x0601), Some("rsa_pkcs1_sha512"));
    assert_eq!(sig_hash_name(0xFFFF), None);
}

#[test]
fn grease_detection_matches_pattern() {
    for g in [0x0A0Au16, 0x1A1A, 0x2A2A, 0x3A3A, 0x8A8A, 0x9A9A, 0xFAFA, 0xAAAA] {
        assert!(is_grease(g), "{g:#06x} should be GREASE");
    }
    for real in [0x1301u16, 23, 4588, 0x002F, 771, 0xC02B] {
        assert!(!is_grease(real), "{real:#06x} should not be GREASE");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib fingerprint::tests`
Expected: FAIL — `cipher_name` etc. not defined.

- [ ] **Step 3: Write minimal implementation** — add to `src/fingerprint.rs` (before the `tests` module). The cipher table is ported verbatim from `curl_cffi/requests/impersonate.py::TLS_CIPHER_NAME_MAP`; keep that attribution comment.

```rust
// Ported verbatim from curl_cffi/requests/impersonate.py::TLS_CIPHER_NAME_MAP
// (IANA cipher id -> BoringSSL cipher name). All suites go in one `--ciphers`
// list; BoringSSL accepts TLS 1.3 suite names there too.
fn cipher_name(id: u16) -> Option<&'static str> {
    Some(match id {
        0x000A => "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        0x002F => "TLS_RSA_WITH_AES_128_CBC_SHA",
        0x0033 => "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA",
        0x0039 => "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        0x003C => "TLS_RSA_WITH_AES_128_CBC_SHA256",
        0x003D => "TLS_RSA_WITH_AES_256_CBC_SHA256",
        0x0067 => "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
        0x006B => "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
        0x008C => "TLS_PSK_WITH_AES_128_CBC_SHA",
        0x008D => "TLS_PSK_WITH_AES_256_CBC_SHA",
        0x009C => "TLS_RSA_WITH_AES_128_GCM_SHA256",
        0x009D => "TLS_RSA_WITH_AES_256_GCM_SHA384",
        0x009E => "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        0x009F => "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        0xC008 => "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
        0xC009 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        0xC00A => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        0xC012 => "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
        0xC013 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        0xC014 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        0xC023 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        0xC024 => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        0xC027 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        0xC028 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        0xC02B => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xC02C => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        0xC02F => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xC030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0xC035 => "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
        0xC036 => "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",
        0xCCA8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        0xCCA9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        0xCCAC => "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
        _ => return None,
    })
}

// Ported from curl_cffi TLS_EC_CURVES_MAP (supported-group id -> name).
fn curve_name(id: u16) -> Option<&'static str> {
    Some(match id {
        19 => "P-192",
        21 => "P-224",
        23 => "P-256",
        24 => "P-384",
        25 => "P-521",
        29 => "X25519",
        256 => "ffdhe2048",
        257 => "ffdhe3072",
        4588 => "X25519MLKEM768",
        25497 => "X25519Kyber768Draft00",
        _ => return None,
    })
}

// RFC 8446 §4.2.3 SignatureScheme id -> name accepted by
// `--signature-hashes`. curl_cffi has no such map (it takes names from the
// caller); built here for the raw-array path.
fn sig_hash_name(id: u16) -> Option<&'static str> {
    Some(match id {
        0x0201 => "rsa_pkcs1_sha1",
        0x0203 => "ecdsa_sha1",
        0x0401 => "rsa_pkcs1_sha256",
        0x0403 => "ecdsa_secp256r1_sha256",
        0x0501 => "rsa_pkcs1_sha384",
        0x0503 => "ecdsa_secp384r1_sha384",
        0x0601 => "rsa_pkcs1_sha512",
        0x0603 => "ecdsa_secp521r1_sha512",
        0x0804 => "rsa_pss_rsae_sha256",
        0x0805 => "rsa_pss_rsae_sha384",
        0x0806 => "rsa_pss_rsae_sha512",
        0x0807 => "ed25519",
        0x0808 => "ed448",
        0x0809 => "rsa_pss_pss_sha256",
        0x080A => "rsa_pss_pss_sha384",
        0x080B => "rsa_pss_pss_sha512",
        _ => return None,
    })
}

/// True for TLS GREASE values (`0x0A0A, 0x1A1A, … 0xFAFA`): both bytes equal
/// and the low nibble is `0xA`. JA3 strings omit GREASE by convention; raw
/// capture arrays include it and must be stripped (see `from_raw_arrays`).
fn is_grease(v: u16) -> bool {
    (v & 0xFF) == (v >> 8) && (v & 0x0F) == 0x0A
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib fingerprint::tests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/fingerprint.rs
git commit -m "feat(fingerprint): port cipher/curve/sig-hash id->name tables + GREASE detection"
```

---

### Task 3: JA3 parser

**Files:**
- Modify: `src/fingerprint.rs`

**Interfaces:**
- Produces: `FingerprintBuilder::ja3(self, ja3: &str) -> Result<Self, FingerprintError>`. Fills `tls_version_min`, `ciphers`, `extension_order`, `curves`. Padding (`21`) trailing the extension list is stripped.

- [ ] **Step 1: Write the failing test** — add to `tests`:

```rust
#[test]
fn ja3_parser_fills_tls_fields() {
    let fp = Fingerprint::builder()
        .ja3("771,4865-4866,0-11-10,29-23,0")
        .unwrap()
        .build();
    assert_eq!(fp.tls_version_min, Some(771));
    assert_eq!(fp.ciphers, vec![0x1301, 0x1302]);
    assert_eq!(fp.extension_order, vec![0, 11, 10]);
    assert_eq!(fp.curves, vec![29, 23]);
}

#[test]
fn ja3_parser_strips_trailing_padding_extension() {
    // extensions ending in `-21` (padding): the SSL engine manages padding.
    let fp = Fingerprint::builder()
        .ja3("771,4865,0-11-21,29,0")
        .unwrap()
        .build();
    assert_eq!(fp.extension_order, vec![0, 11]);
}

#[test]
fn ja3_parser_rejects_malformed() {
    let err = Fingerprint::builder().ja3("771,4865,0-11").unwrap_err();
    assert!(matches!(err, FingerprintError::MalformedJa3 { .. }));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib fingerprint::tests`
Expected: FAIL — `ja3` method missing.

- [ ] **Step 3: Write minimal implementation** — add to `impl FingerprintBuilder`:

```rust
/// Parse a JA3 string `version,ciphers,extensions,curves,curve_formats` into
/// the TLS overlay fields. Ported from curl_cffi `set_ja3_options`. GREASE is
/// absent from JA3 by convention, so no stripping happens here.
pub fn ja3(mut self, ja3: &str) -> Result<Self, FingerprintError> {
    let malformed = |reason: &str| FingerprintError::MalformedJa3 {
        input: ja3.to_string(),
        reason: reason.to_string(),
    };
    let parts: Vec<&str> = ja3.split(',').collect();
    if parts.len() != 5 {
        return Err(malformed("expected 5 comma-separated fields"));
    }
    let parse_u16 = |s: &str| s.parse::<u16>().map_err(|_| malformed("non-numeric field"));
    let parse_list = |s: &str| -> Result<Vec<u16>, FingerprintError> {
        if s.is_empty() {
            return Ok(Vec::new());
        }
        s.split('-').map(parse_u16).collect()
    };

    self.fp.tls_version_min = Some(parse_u16(parts[0])?);
    self.fp.ciphers = parse_list(parts[1])?;

    let mut exts = parse_list(parts[2])?;
    if exts.last() == Some(&21) {
        exts.pop(); // padding: managed by the SSL engine
    }
    self.fp.extension_order = exts;

    self.fp.curves = parse_list(parts[3])?;
    // curve_formats (parts[4]) is only ever `0`; ignored.
    Ok(self)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib fingerprint::tests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/fingerprint.rs
git commit -m "feat(fingerprint): JA3 string parser"
```

---

### Task 4: Akamai (HTTP/2) parser

**Files:**
- Modify: `src/fingerprint.rs`

**Interfaces:**
- Produces: `FingerprintBuilder::akamai(self, akamai: &str) -> Result<Self, FingerprintError>`. Fills `h2_settings`, `h2_window_update`, `h2_streams`, `h2_pseudo_order`.

- [ ] **Step 1: Write the failing test** — add to `tests`:

```rust
#[test]
fn akamai_parser_fills_http2_fields() {
    let fp = Fingerprint::builder()
        .akamai("1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p")
        .unwrap()
        .build();
    assert_eq!(
        fp.h2_settings,
        vec![(1, 65536), (2, 0), (4, 6291456), (6, 262144)]
    );
    assert_eq!(fp.h2_window_update, Some(15663105));
    assert_eq!(fp.h2_streams.as_deref(), Some("0"));
    assert_eq!(fp.h2_pseudo_order.as_deref(), Some("masp"));
}

#[test]
fn akamai_parser_accepts_comma_settings_separator() {
    // tls.peet.ws uses commas between settings; treat as semicolons.
    let fp = Fingerprint::builder()
        .akamai("1:65536,2:0|15663105|1:0:0:201|m,a,s,p")
        .unwrap()
        .build();
    assert_eq!(fp.h2_settings, vec![(1, 65536), (2, 0)]);
    assert_eq!(fp.h2_streams.as_deref(), Some("1:0:0:201"));
}

#[test]
fn akamai_parser_rejects_malformed() {
    let err = Fingerprint::builder().akamai("1:65536|15663105").unwrap_err();
    assert!(matches!(err, FingerprintError::MalformedAkamai { .. }));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib fingerprint::tests`
Expected: FAIL — `akamai` missing.

- [ ] **Step 3: Write minimal implementation** — add to `impl FingerprintBuilder`:

```rust
/// Parse an Akamai HTTP/2 fingerprint
/// `settings|window_update|streams|pseudo_order`. Ported from curl_cffi
/// `set_akamai_options`. Settings may use `,` or `;` between pairs; pseudo
/// order `m,a,s,p` becomes `masp`.
pub fn akamai(mut self, akamai: &str) -> Result<Self, FingerprintError> {
    let malformed = |reason: &str| FingerprintError::MalformedAkamai {
        input: akamai.to_string(),
        reason: reason.to_string(),
    };
    let parts: Vec<&str> = akamai.split('|').collect();
    if parts.len() != 4 {
        return Err(malformed("expected 4 pipe-separated fields"));
    }

    let mut settings = Vec::new();
    if !parts[0].is_empty() {
        for pair in parts[0].replace(',', ";").split(';') {
            let (k, v) = pair
                .split_once(':')
                .ok_or_else(|| malformed("settings pair missing ':'"))?;
            let k = k.parse::<u16>().map_err(|_| malformed("non-numeric setting id"))?;
            let v = v.parse::<u32>().map_err(|_| malformed("non-numeric setting value"))?;
            settings.push((k, v));
        }
    }
    self.fp.h2_settings = settings;

    self.fp.h2_window_update = Some(
        parts[1]
            .parse::<u32>()
            .map_err(|_| malformed("non-numeric window_update"))?,
    );
    self.fp.h2_streams = Some(parts[2].to_string());
    self.fp.h2_pseudo_order = Some(parts[3].replace(',', ""));
    Ok(self)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib fingerprint::tests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/fingerprint.rs
git commit -m "feat(fingerprint): Akamai HTTP/2 fingerprint parser"
```

---

### Task 5: perk (HTTP/3) parser

**Files:**
- Modify: `src/fingerprint.rs`

**Interfaces:**
- Produces: `FingerprintBuilder::perk(self, perk: &str) -> Result<Self, FingerprintError>`. Fills `enable_http3`, `h3_settings`, `h3_pseudo_order`, `quic_transport_params`.

- [ ] **Step 1: Write the failing test** — add to `tests`:

```rust
#[test]
fn perk_parser_fills_http3_fields() {
    let fp = Fingerprint::builder().perk("1:2|m,a,s,p|3:4").unwrap().build();
    assert!(fp.enable_http3);
    assert_eq!(fp.h3_settings.as_deref(), Some("1:2"));
    assert_eq!(fp.h3_pseudo_order.as_deref(), Some("masp"));
    assert_eq!(fp.quic_transport_params.as_deref(), Some("3:4"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib fingerprint::tests`
Expected: FAIL — `perk` missing.

- [ ] **Step 3: Write minimal implementation** — add to `impl FingerprintBuilder`:

```rust
/// Parse an HTTP/3 "perk" fingerprint
/// `settings|pseudo_order|quic_transport_params`. Ported from curl_cffi
/// `set_perk_options`. Sets `enable_http3`.
pub fn perk(mut self, perk: &str) -> Result<Self, FingerprintError> {
    let parts: Vec<&str> = perk.split('|').collect();
    if parts.len() != 3 {
        return Err(FingerprintError::MalformedAkamai {
            input: perk.to_string(),
            reason: "perk expected 3 pipe-separated fields".to_string(),
        });
    }
    self.fp.enable_http3 = true;
    self.fp.h3_settings = Some(parts[0].to_string());
    self.fp.h3_pseudo_order = Some(parts[1].replace(',', ""));
    self.fp.quic_transport_params = Some(parts[2].to_string());
    Ok(self)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib fingerprint::tests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/fingerprint.rs
git commit -m "feat(fingerprint): HTTP/3 perk fingerprint parser"
```

---

### Task 6: `to_args()` — TLS flags

**Files:**
- Modify: `src/fingerprint.rs`

**Interfaces:**
- Produces: `Fingerprint::to_args(&self) -> Result<Vec<String>, FingerprintError>`. This task emits the baseline + all TLS flags; Task 7 extends the same method with HTTP/2, HTTP/3, and header flags.

- [ ] **Step 1: Write the failing test** — add to `tests`:

```rust
// Helper: find the value following a flag in an argv vec.
fn arg_after<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).map(|s| s.as_str())
}

#[test]
fn to_args_emits_baseline_and_tls() {
    let fp = Fingerprint::builder()
        .base_target("chrome146")
        .ja3("771,4865-4866-49195,0-11-10,29-23,0")
        .unwrap()
        .build();
    let args = fp.to_args().unwrap();
    assert_eq!(arg_after(&args, "--impersonate"), Some("chrome146"));
    assert_eq!(
        arg_after(&args, "--ciphers"),
        Some("TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256")
    );
    assert_eq!(arg_after(&args, "--curves"), Some("X25519:P-256"));
    assert_eq!(arg_after(&args, "--tls-extension-order"), Some("0-11-10"));
    assert!(args.iter().any(|a| a == "--tlsv1.2"));
}

#[test]
fn to_args_baseline_no_default_headers() {
    let fp = Fingerprint::builder().base_target("chrome146").default_headers(false).build();
    let args = fp.to_args().unwrap();
    assert_eq!(arg_after(&args, "--impersonate"), Some("chrome146:no"));
}

#[test]
fn to_args_permute_skips_extension_order() {
    let mut fp = Fingerprint::builder()
        .ja3("771,4865,0-11-10,29,0")
        .unwrap()
        .build();
    fp.permute_extensions = true;
    let args = fp.to_args().unwrap();
    assert!(!args.iter().any(|a| a == "--tls-extension-order"));
    assert!(args.iter().any(|a| a == "--tls-permute-extensions"));
}

#[test]
fn to_args_signature_hashes_comma_joined() {
    let mut fp = Fingerprint::default();
    fp.sig_hash_algs = vec![0x0804, 0x0403];
    let args = fp.to_args().unwrap();
    assert_eq!(
        arg_after(&args, "--signature-hashes"),
        Some("rsa_pss_rsae_sha256,ecdsa_secp256r1_sha256")
    );
}

#[test]
fn to_args_unknown_cipher_errors() {
    let mut fp = Fingerprint::default();
    fp.ciphers = vec![0xDEAD];
    assert_eq!(fp.to_args().unwrap_err(), FingerprintError::UnknownCipher(0xDEAD));
}

#[test]
fn to_args_emits_extra_fp_tls_toggles() {
    let mut fp = Fingerprint::default();
    fp.grease = true;
    fp.cert_compression = vec![CertComp::Brotli];
    fp.alps = Some(AlpsMode::NewCodepoint);
    fp.session_ticket = Some(false);
    fp.signed_cert_timestamps = true;
    fp.record_size_limit = Some(16385);
    fp.key_shares_limit = Some(3);
    let args = fp.to_args().unwrap();
    assert!(args.iter().any(|a| a == "--tls-grease"));
    assert_eq!(arg_after(&args, "--cert-compression"), Some("brotli"));
    assert!(args.iter().any(|a| a == "--alps"));
    assert!(args.iter().any(|a| a == "--tls-use-new-alps-codepoint"));
    assert!(args.iter().any(|a| a == "--no-tls-session-ticket"));
    assert!(args.iter().any(|a| a == "--tls-signed-cert-timestamps"));
    assert_eq!(arg_after(&args, "--tls-record-size-limit"), Some("16385"));
    assert_eq!(arg_after(&args, "--tls-key-shares-limit"), Some("3"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib fingerprint::tests`
Expected: FAIL — `to_args` missing.

- [ ] **Step 3: Write minimal implementation** — add to `impl Fingerprint`:

```rust
/// Synthesize the curl-impersonate CLI flags that reproduce this fingerprint,
/// applied as an overlay on the `--impersonate <base>` baseline. Returns the
/// argv fragment spliced before the URL by `build_argv`. Strict: an unmapped
/// cipher/curve/sig-alg id is a hard error.
pub fn to_args(&self) -> Result<Vec<String>, FingerprintError> {
    let mut a: Vec<String> = Vec::new();

    // 1. Baseline.
    if let Some(base) = &self.base_target {
        a.push("--impersonate".into());
        a.push(if self.default_headers {
            base.clone()
        } else {
            format!("{base}:no")
        });
    }

    // UA override (replaces the baseline's User-Agent header).
    if let Some(ua) = &self.user_agent {
        a.push("-H".into());
        a.push(format!("User-Agent: {ua}"));
    }

    // 2. TLS min version (no --tls-max: negotiate up, matching MAX_DEFAULT).
    match self.tls_version_min {
        Some(772) => a.push("--tlsv1.3".into()),
        Some(_) => a.push("--tlsv1.2".into()),
        None => {}
    }

    // 3. Ciphers (all suites, ':'-joined names).
    if !self.ciphers.is_empty() {
        let names = self
            .ciphers
            .iter()
            .map(|&id| cipher_name(id).ok_or(FingerprintError::UnknownCipher(id)))
            .collect::<Result<Vec<_>, _>>()?;
        a.push("--ciphers".into());
        a.push(names.join(":"));
    }

    // 4. Curves.
    if !self.curves.is_empty() {
        let names = self
            .curves
            .iter()
            .map(|&id| curve_name(id).ok_or(FingerprintError::UnknownCurve(id)))
            .collect::<Result<Vec<_>, _>>()?;
        a.push("--curves".into());
        a.push(names.join(":"));
    }

    // 5. Extension order — only when NOT permuting.
    if !self.permute_extensions && !self.extension_order.is_empty() {
        a.push("--tls-extension-order".into());
        a.push(
            self.extension_order
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("-"),
        );
    }

    // 6. Signature algorithms (','-joined names).
    if !self.sig_hash_algs.is_empty() {
        let names = self
            .sig_hash_algs
            .iter()
            .map(|&id| sig_hash_name(id).ok_or(FingerprintError::UnknownSigAlg(id)))
            .collect::<Result<Vec<_>, _>>()?;
        a.push("--signature-hashes".into());
        a.push(names.join(","));
    }

    // 7. extra_fp TLS toggles.
    if self.grease {
        a.push("--tls-grease".into());
    }
    if self.permute_extensions {
        a.push("--tls-permute-extensions".into());
    }
    if !self.cert_compression.is_empty() {
        a.push("--cert-compression".into());
        a.push(
            self.cert_compression
                .iter()
                .map(|c| c.as_str())
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    if let Some(v) = self.record_size_limit {
        a.push("--tls-record-size-limit".into());
        a.push(v.to_string());
    }
    if let Some(dc) = &self.delegated_credentials {
        a.push("--tls-delegated-credentials".into());
        a.push(dc.clone());
    }
    if let Some(n) = self.key_shares_limit {
        a.push("--tls-key-shares-limit".into());
        a.push(n.to_string());
    }
    match self.alps {
        Some(AlpsMode::Legacy) => a.push("--alps".into()),
        Some(AlpsMode::NewCodepoint) => {
            a.push("--alps".into());
            a.push("--tls-use-new-alps-codepoint".into());
        }
        None => {}
    }
    match self.session_ticket {
        Some(true) => a.push("--tls-session-ticket".into()),
        Some(false) => a.push("--no-tls-session-ticket".into()),
        None => {}
    }
    if self.signed_cert_timestamps {
        a.push("--tls-signed-cert-timestamps".into());
    }
    if self.no_npn {
        a.push("--no-npn".into());
    }
    if self.no_alpn {
        a.push("--no-alpn".into());
    }

    Ok(a)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib fingerprint::tests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/fingerprint.rs
git commit -m "feat(fingerprint): to_args baseline + TLS flag synthesis"
```

---

### Task 7: `to_args()` — HTTP/2, HTTP/3, headers

**Files:**
- Modify: `src/fingerprint.rs`

**Interfaces:**
- Consumes: `Fingerprint::to_args` from Task 6 (extends the same method).
- Produces: the same `to_args` now also emitting HTTP/2, HTTP/3, header, and proxy flags.

- [ ] **Step 1: Write the failing test** — add to `tests`:

```rust
#[test]
fn to_args_emits_http2_flags() {
    let fp = Fingerprint::builder()
        .akamai("1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p")
        .unwrap()
        .build();
    let args = fp.to_args().unwrap();
    assert_eq!(arg_after(&args, "--http2-settings"), Some("1:65536;2:0;4:6291456;6:262144"));
    assert_eq!(arg_after(&args, "--http2-window-update"), Some("15663105"));
    assert_eq!(arg_after(&args, "--http2-pseudo-headers-order"), Some("masp"));
    // streams == "0" is omitted.
    assert!(!args.iter().any(|a| a == "--http2-streams"));
}

#[test]
fn to_args_nonzero_streams_and_exclusive() {
    let mut fp = Fingerprint::builder()
        .akamai("1:65536|15663105|1:0:0:201|m,a,s,p")
        .unwrap()
        .build();
    fp.h2_stream_exclusive = Some(1);
    fp.h2_no_priority = true;
    fp.split_cookies = Some(true);
    let args = fp.to_args().unwrap();
    assert_eq!(arg_after(&args, "--http2-streams"), Some("1:0:0:201"));
    assert_eq!(arg_after(&args, "--http2-stream-exclusive"), Some("1"));
    assert!(args.iter().any(|a| a == "--http2-no-priority"));
    assert!(args.iter().any(|a| a == "--split-cookies"));
}

#[test]
fn to_args_emits_http3_and_headers() {
    let mut fp = Fingerprint::builder().perk("1:2|m,a,s,p|3:4").unwrap().build();
    fp.header_order = vec!["host".into(), "user-agent".into()];
    fp.proxy_credential_no_reuse = true;
    let args = fp.to_args().unwrap();
    assert!(args.iter().any(|a| a == "--http3"));
    assert_eq!(arg_after(&args, "--http3-settings"), Some("1:2"));
    assert_eq!(arg_after(&args, "--http3-pseudo-headers-order"), Some("masp"));
    assert_eq!(arg_after(&args, "--quic-transport-params"), Some("3:4"));
    assert_eq!(arg_after(&args, "--http-header-order"), Some("host,user-agent"));
    assert!(args.iter().any(|a| a == "--proxy-credential-no-reuse"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib fingerprint::tests`
Expected: FAIL — the new flags aren't emitted yet.

- [ ] **Step 3: Write minimal implementation** — insert the following into `to_args`, **before the final `Ok(a)`**:

```rust
    // 8. HTTP/2 overlay.
    if !self.h2_settings.is_empty() {
        a.push("--http2-settings".into());
        a.push(
            self.h2_settings
                .iter()
                .map(|(k, v)| format!("{k}:{v}"))
                .collect::<Vec<_>>()
                .join(";"),
        );
    }
    if let Some(w) = self.h2_window_update {
        a.push("--http2-window-update".into());
        a.push(w.to_string());
    }
    if let Some(s) = &self.h2_streams {
        if s != "0" {
            a.push("--http2-streams".into());
            a.push(s.clone());
        }
    }
    if let Some(p) = &self.h2_pseudo_order {
        a.push("--http2-pseudo-headers-order".into());
        a.push(p.clone());
    }
    if let Some(e) = self.h2_stream_exclusive {
        a.push("--http2-stream-exclusive".into());
        a.push(e.to_string());
    }
    if self.h2_no_priority {
        a.push("--http2-no-priority".into());
    }
    match self.split_cookies {
        Some(true) => a.push("--split-cookies".into()),
        Some(false) => a.push("--no-split-cookies".into()),
        None => {}
    }

    // 9. HTTP/3 overlay.
    if self.enable_http3 {
        a.push("--http3".into());
    }
    if let Some(s) = &self.h3_settings {
        a.push("--http3-settings".into());
        a.push(s.clone());
    }
    if let Some(p) = &self.h3_pseudo_order {
        a.push("--http3-pseudo-headers-order".into());
        a.push(p.clone());
    }
    if let Some(s) = &self.h3_sig_hash_algs {
        a.push("--http3-sig-hash-algs".into());
        a.push(s.clone());
    }
    if let Some(o) = &self.h3_tls_extension_order {
        a.push("--http3-tls-extension-order".into());
        a.push(o.clone());
    }
    if let Some(q) = &self.quic_transport_params {
        a.push("--quic-transport-params".into());
        a.push(q.clone());
    }

    // 10. Headers / proxy.
    if !self.header_order.is_empty() {
        a.push("--http-header-order".into());
        a.push(self.header_order.join(","));
    }
    if self.proxy_credential_no_reuse {
        a.push("--proxy-credential-no-reuse".into());
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib fingerprint::tests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/fingerprint.rs
git commit -m "feat(fingerprint): to_args HTTP/2, HTTP/3, and header flag synthesis"
```

---

### Task 8: `from_raw_arrays` — GREASE-aware constructor

**Files:**
- Modify: `src/fingerprint.rs`

**Interfaces:**
- Produces: `Fingerprint::from_raw_arrays(input: RawArrays) -> Fingerprint` and a plain `RawArrays` struct of `Vec<u16>` fields. GREASE values are stripped from every list and set `grease = true`.

- [ ] **Step 1: Write the failing test** — add to `tests`:

```rust
#[test]
fn from_raw_arrays_strips_grease_and_sets_fields() {
    // Values taken from the android-chrome-149 capture.
    let raw = RawArrays {
        ciphers: vec![64250, 4865, 4866, 4867, 49195],       // 64250 = 0xFAFA GREASE
        extensions: vec![39578, 0, 43, 35466],                // 39578/35466 GREASE
        supported_groups: vec![14906, 4588, 29, 23, 24],      // 14906 GREASE
        signature_algorithms: vec![1027, 2052],               // 0x0403, 0x0804
        supported_versions: vec![43690, 772, 771],            // 43690 GREASE
    };
    let fp = Fingerprint::from_raw_arrays(raw);
    assert!(fp.grease);
    assert_eq!(fp.ciphers, vec![4865, 4866, 4867, 49195]);
    assert_eq!(fp.extension_order, vec![0, 43]);
    assert_eq!(fp.curves, vec![4588, 29, 23, 24]);
    assert_eq!(fp.sig_hash_algs, vec![1027, 2052]);
    // lowest non-GREASE supported version wins as the min (771 = TLS 1.2).
    assert_eq!(fp.tls_version_min, Some(771));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib fingerprint::tests`
Expected: FAIL — `RawArrays` / `from_raw_arrays` missing.

- [ ] **Step 3: Write minimal implementation** — add to `src/fingerprint.rs`:

```rust
/// Decomposed raw ClientHello arrays (numeric ids, GREASE included) as captured
/// by a harvester. Feed to [`Fingerprint::from_raw_arrays`]; it is the
/// high-fidelity path (carries sig-algs and key shares that JA3 lacks).
#[derive(Debug, Clone, Default)]
pub struct RawArrays {
    pub ciphers: Vec<u16>,
    pub extensions: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
    pub supported_versions: Vec<u16>,
}

impl Fingerprint {
    /// Build a fingerprint from raw ClientHello arrays, stripping GREASE from
    /// every list and setting `grease` when any is seen. Other fields keep their
    /// defaults; set the baseline via `base_target` and any extra_fp toggles
    /// afterwards.
    pub fn from_raw_arrays(raw: RawArrays) -> Fingerprint {
        let mut grease = false;
        let mut strip = |v: &[u16]| -> Vec<u16> {
            v.iter()
                .copied()
                .filter(|&x| {
                    let g = is_grease(x);
                    grease |= g;
                    !g
                })
                .collect()
        };

        let ciphers = strip(&raw.ciphers);
        let extension_order = strip(&raw.extensions);
        let curves = strip(&raw.supported_groups);
        let sig_hash_algs = strip(&raw.signature_algorithms);
        let versions = strip(&raw.supported_versions);
        // Min TLS version = lowest advertised (non-GREASE) supported_version.
        let tls_version_min = versions.iter().copied().min();

        Fingerprint {
            ciphers,
            extension_order,
            curves,
            sig_hash_algs,
            tls_version_min,
            grease,
            ..Fingerprint::default()
        }
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib fingerprint::tests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/fingerprint.rs
git commit -m "feat(fingerprint): from_raw_arrays GREASE-stripping constructor"
```

---

### Task 9: Wire `Fingerprint` into `Request`

**Files:**
- Modify: `src/lib.rs` (`Request` struct, `new`, `build_argv`, `run`, `CurlError`, one existing test signature per changed call)

**Interfaces:**
- Consumes: `Fingerprint::to_args`.
- Produces: `Request::fingerprint(self, fp: Fingerprint) -> Self`; `build_argv(req: &Request, fp_args: &[String]) -> Vec<String>`; `CurlError::Fingerprint(FingerprintError)`.

- [ ] **Step 1: Write the failing test** — add to the `tests` module in `src/lib.rs`:

```rust
#[test]
fn fingerprint_flags_spliced_before_url() {
    let fp = crate::Fingerprint::builder()
        .base_target("chrome146")
        .ja3("771,4865-4866,0-11-10,29-23,0")
        .unwrap()
        .build();
    let req = Request::get("curl-impersonate", "https://example.com/").fingerprint(fp);
    let fp_args = req.fingerprint.as_ref().unwrap().to_args().unwrap();
    let argv = build_argv(&req, &fp_args);

    let imp = argv.iter().position(|a| a == "--impersonate").expect("--impersonate present");
    let url = argv.iter().position(|a| a == "https://example.com/").unwrap();
    let dashdash = argv.iter().position(|a| a == "--").unwrap();
    assert!(imp < dashdash, "fingerprint flags come before `--`");
    assert!(dashdash < url);
    assert!(argv.iter().any(|a| a == "--ciphers"));
}

#[test]
fn no_fingerprint_argv_unchanged() {
    let req = Request::get("curl_chrome146", "https://example.com/");
    let argv = build_argv(&req, &[]);
    assert!(!argv.iter().any(|a| a == "--impersonate"));
    assert_eq!(argv.last().unwrap(), "https://example.com/");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib`
Expected: FAIL — `fingerprint` field/method missing; `build_argv` arity wrong.

- [ ] **Step 3: Write minimal implementation** in `src/lib.rs`:

3a. Add the field to `Request` (after `max_redirs: u32,`):

```rust
    fingerprint: Option<Fingerprint>,
```

3b. Initialize it in `Request::new` (after `max_redirs: DEFAULT_MAX_REDIRS,`):

```rust
            fingerprint: None,
```

3c. Add the setter to `impl Request` (near the other setters):

```rust
    /// Attach a custom [`Fingerprint`]. `bin` must be the raw `curl-impersonate`
    /// binary (not a `curl_chromeNNN` wrapper); its `to_args()` are spliced into
    /// the argv. Combining this with a wrapper binary double-applies the
    /// impersonation and is unsupported.
    pub fn fingerprint(mut self, fp: Fingerprint) -> Self {
        self.fingerprint = Some(fp);
        self
    }
```

3d. Add the import at the top and the error variant. Add to imports:

```rust
use crate::fingerprint::Fingerprint;
```

Add to `CurlError` (a new variant):

```rust
    #[error("fingerprint: {0}")]
    Fingerprint(#[from] crate::fingerprint::FingerprintError),
```

3e. Change `build_argv` signature and splice. Replace the signature line and the initial `let mut a` seed:

```rust
fn build_argv(req: &Request, fp_args: &[String]) -> Vec<String> {
    let mut a: Vec<String> = vec![
        "-sS".into(),
        "-i".into(),
        "--max-time".into(),
        format!("{}", req.timeout_secs),
        "-w".into(),
        format!("%{{stderr}}{FINAL_URL_SENTINEL}%{{url_effective}}\\n"),
    ];
    a.extend(fp_args.iter().cloned());
```

(The rest of `build_argv` is unchanged; the `fp_args` land right after the base flags and well before the closing `--`/URL.)

3f. Compute the args in `run` and pass them. Replace the two opening lines of `run`:

```rust
async fn run(req: Request) -> Result<Response, CurlError> {
    let fp_args = match &req.fingerprint {
        Some(fp) => fp.to_args()?,
        None => Vec::new(),
    };
    let mut cmd = Command::new(&req.bin);
    cmd.args(build_argv(&req, &fp_args));
```

3g. Update the **existing** `build_argv` call sites in `src/lib.rs` tests to pass `&[]`. There are 4 (`follow_redirects_adds_dash_l_and_max_redirs`, `post_with_body_omits_dash_x_so_redirects_downgrade_to_get`, `bodyless_post_forces_dash_x_post`, and the new negative test already uses `&[]`). Change each `build_argv(&Request::...)` / `build_argv(&argv_req)` to `build_argv(&<same>, &[])`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib`
Expected: PASS (all lib tests, including the pre-existing argv tests).

- [ ] **Step 5: Commit**

```bash
git add src/lib.rs
git commit -m "feat: Request::fingerprint setter, splice overlay flags into argv"
```

---

### Task 10: `download::ensure_impersonate_binary`

**Files:**
- Modify: `src/download.rs`

**Interfaces:**
- Consumes: existing `download.rs` internals (`target_triple`, `asset_name`, `download_url`, `extract_and_place`, `finalize`, `DownloadOptions`, `DownloadError`).
- Produces: `pub async fn ensure_impersonate_binary(opts: &DownloadOptions) -> Result<PathBuf, DownloadError>` returning the canonicalized path to the raw `curl-impersonate` binary.

- [ ] **Step 1: Write the failing test** — add to the `tests` module in `src/download.rs`:

```rust
#[test]
fn base_binary_file_name_is_curl_impersonate() {
    assert_eq!(base_binary_file_name(), "curl-impersonate");
}

/// Network integration: downloads the release and returns the base binary.
/// Ignored by default. Run with:
/// `cargo test --features download -- --ignored ensures_impersonate_binary`.
#[tokio::test]
#[ignore = "network: downloads a real curl-impersonate release"]
async fn ensures_impersonate_binary() {
    let cache = std::env::temp_dir().join(format!("cimp-base-{}", unique_suffix()));
    let opts = DownloadOptions { cache_dir: Some(cache.clone()), ..Default::default() };
    let path = ensure_impersonate_binary(&opts).await.expect("download base binary");
    assert!(path.is_file());
    assert_eq!(path.file_name().unwrap(), "curl-impersonate");
    let _ = std::fs::remove_dir_all(&cache);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --features download --lib download::tests::base_binary_file_name_is_curl_impersonate`
Expected: FAIL — `base_binary_file_name` / `ensure_impersonate_binary` missing.

- [ ] **Step 3: Write minimal implementation** — add to `src/download.rs`. Refactor the shared download/extract flow used by `ensure_binary` into a helper, then add the base-binary entry point. The simplest non-invasive form reuses `ensure_binary`'s body by extracting a private `ensure_extracted` that returns the `extract_dir`, but to keep the diff small, add a parallel function that mirrors the fast-path + download + extract, differing only in the final filename:

```rust
/// File name of the raw base binary inside the extracted CLI release.
fn base_binary_file_name() -> &'static str {
    "curl-impersonate"
}

/// Ensure the raw `curl-impersonate` binary exists locally; download + extract
/// the release for the current platform if missing. Returns the canonicalized
/// path to pass as `bin` to a request that carries a custom
/// [`crate::Fingerprint`]. Idempotent, like [`ensure_binary`].
pub async fn ensure_impersonate_binary(
    opts: &DownloadOptions,
) -> Result<PathBuf, DownloadError> {
    let extract_dir = ensure_extracted(opts).await?;
    let base = extract_dir.join(base_binary_file_name());
    if base.is_file() {
        Ok(finalize(base))
    } else {
        Err(DownloadError::WrapperNotFound {
            browser: "impersonate (base binary)".to_string(),
            dir: extract_dir,
        })
    }
}
```

Then extract the shared logic. Refactor `ensure_binary` so its download+extract body becomes `ensure_extracted`, returning `extract_dir: PathBuf`:

```rust
/// Ensure the release for the current platform is extracted; return its
/// extract dir. Shared by `ensure_binary` (wrappers) and
/// `ensure_impersonate_binary` (base binary).
async fn ensure_extracted(opts: &DownloadOptions) -> Result<PathBuf, DownloadError> {
    let version = opts.version.as_deref().unwrap_or(DEFAULT_VERSION);
    validate_version(version)?;
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    let triple = target_triple(os, arch, opts.libc)
        .ok_or(DownloadError::UnsupportedPlatform { os, arch })?;

    let cache_root = match &opts.cache_dir {
        Some(p) => p.clone(),
        None => dirs::cache_dir().ok_or(DownloadError::NoCacheDir)?.join(CACHE_SUBDIR),
    };
    let release_dir = cache_root.join(version);
    let extract_dir = release_dir.join(&triple);

    if extract_dir.is_dir() {
        return Ok(extract_dir);
    }

    fs::create_dir_all(&release_dir).await.map_err(io_err("create cache directory"))?;
    let suffix = unique_suffix();
    let tarball = release_dir.join(format!(".dl-{triple}-{suffix}.tar.gz"));
    let staging = release_dir.join(format!(".staging-{triple}-{suffix}"));
    let asset = asset_name(version, &triple);
    let url = download_url(version, &asset);
    if let Err(e) = download_to_file(&url, &tarball).await {
        let _ = fs::remove_file(&tarball).await;
        return Err(e);
    }
    let (t, s, f) = (tarball.clone(), staging.clone(), extract_dir.clone());
    let placed = tokio::task::spawn_blocking(move || extract_and_place(&t, &s, &f))
        .await
        .map_err(|e| DownloadError::Join(e.to_string()));
    let _ = fs::remove_file(&tarball).await;
    placed??;
    Ok(extract_dir)
}
```

And rewrite `ensure_binary` to use it (replacing its inline download body):

```rust
pub async fn ensure_binary(
    browser: &str,
    opts: &DownloadOptions,
) -> Result<PathBuf, DownloadError> {
    validate_browser(browser)?;
    let extract_dir = ensure_extracted(opts).await?;
    let wrapper = extract_dir.join(wrapper_file_name(browser));
    if wrapper.is_file() {
        Ok(finalize(wrapper))
    } else {
        Err(DownloadError::WrapperNotFound {
            browser: browser.to_string(),
            dir: extract_dir,
        })
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --features download --lib download::tests`
Expected: PASS (the pure tests; the two `#[ignore]` network tests stay ignored).

- [ ] **Step 5: Commit**

```bash
git add src/download.rs
git commit -m "feat(download): ensure_impersonate_binary for the raw base binary"
```

---

### Task 11: `json` feature — `from_capture_json`

**Files:**
- Modify: `Cargo.toml` (add `json` feature + optional `serde_json`)
- Modify: `src/fingerprint.rs` (feature-gated serde + `from_capture_json` + golden test)

**Interfaces:**
- Consumes: `Fingerprint::from_raw_arrays`, `FingerprintBuilder::{ja3,akamai}`.
- Produces: (feature `json`) `Fingerprint::from_capture_json(json: &str) -> Result<Fingerprint, FingerprintError>`.

- [ ] **Step 1: Add the feature + dep to `Cargo.toml`.** Under `[features]` add:

```toml
# Opt-in JSON capture parsing: `Fingerprint::from_capture_json`. Pulls serde +
# serde_json; off the default build.
json = ["dep:serde", "dep:serde_json"]
```

Under `[dependencies]` (near the other optional deps) add:

```toml
serde_json = { version = "1", optional = true }
```

And extend the docs.rs feature set:

```toml
[package.metadata.docs.rs]
features = ["download", "json"]
```

- [ ] **Step 2: Write the failing test** — add to `src/fingerprint.rs`, gated on the feature. This uses the real target capture (trimmed to the fields `from_capture_json` reads):

```rust
#[cfg(all(test, feature = "json"))]
mod json_tests {
    use super::*;

    const CAPTURE: &str = r#"{
      "ua": "Mozilla/5.0 (Linux; Android 10; K) Chrome/149.0.0.0 Mobile Safari/537.36",
      "tls": {
        "tlsProfile": "Chrome_146",
        "captured": {
          "akamai": "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
          "ja3": "771,4865-4866-4867-49195,65037-35-23-10,4588-29-23-24,0",
          "raw": { "raw": {
            "ciphers": [64250, 4865, 4866, 4867, 49195],
            "extensions": [39578, 65037, 35, 23, 10],
            "supported_groups": [14906, 4588, 29, 23, 24],
            "signature_algorithms": [1027, 2052, 1025],
            "supported_versions": [43690, 772, 771]
          }}
        }
      }
    }"#;

    #[test]
    fn from_capture_json_prefers_raw_arrays_and_maps_all() {
        let fp = Fingerprint::from_capture_json(CAPTURE).unwrap();
        assert_eq!(fp.base_target.as_deref(), Some("chrome146"));
        assert!(fp.user_agent.as_deref().unwrap().contains("Chrome/149"));
        assert!(fp.grease, "GREASE seen in raw arrays");
        // raw arrays win (GREASE stripped), not the JA3 string.
        assert_eq!(fp.curves, vec![4588, 29, 23, 24]);
        assert_eq!(fp.sig_hash_algs, vec![1027, 2052, 1025]);

        let args = fp.to_args().unwrap();
        assert!(args.windows(2).any(|w| w[0] == "--impersonate" && w[1] == "chrome146"));
        assert!(args.iter().any(|a| a == "--tls-grease"));
        assert_eq!(
            args.iter().position(|a| a == "--curves").and_then(|i| args.get(i + 1)).map(|s| s.as_str()),
            Some("X25519MLKEM768:X25519:P-256:P-384")
        );
        assert!(args.windows(2).any(|w| w[0] == "--http2-settings"
            && w[1] == "1:65536;2:0;4:6291456;6:262144"));
        assert!(args.windows(2).any(|w| w[0] == "--http2-window-update" && w[1] == "15663105"));
    }

    #[test]
    fn from_capture_json_falls_back_to_ja3_without_raw() {
        let json = r#"{"ua":"UA","tls":{"tlsProfile":"Chrome_146",
          "captured":{"ja3":"771,4865-4866,0-11-10,29-23,0",
          "akamai":"1:65536|15663105|0|m,a,s,p"}}}"#;
        let fp = Fingerprint::from_capture_json(json).unwrap();
        assert_eq!(fp.ciphers, vec![4865, 4866]); // from JA3, no raw arrays
        assert_eq!(fp.curves, vec![29, 23]);
    }
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test --features json --lib fingerprint::json_tests`
Expected: FAIL — `from_capture_json` missing.

- [ ] **Step 4: Write minimal implementation** — add to `src/fingerprint.rs`, feature-gated. Uses `serde_json::Value` for lenient, nesting-tolerant reads (no rigid structs that break on harvester changes):

```rust
#[cfg(feature = "json")]
impl Fingerprint {
    /// Parse a captured profile JSON into a [`Fingerprint`]. Reads `ua`,
    /// `tls.tlsProfile`, `tls.captured.ja3`, `tls.captured.akamai`, and (when
    /// present) the richer `tls.captured.raw.raw.*` arrays — **preferring the
    /// raw arrays**, which carry signature algorithms and key shares JA3 omits.
    /// Available with the `json` feature.
    pub fn from_capture_json(json: &str) -> Result<Fingerprint, FingerprintError> {
        use serde_json::Value;
        let v: Value = serde_json::from_str(json).map_err(|e| {
            FingerprintError::MalformedJa3 {
                input: "<capture json>".to_string(),
                reason: format!("invalid JSON: {e}"),
            }
        })?;

        let tls = v.get("tls").unwrap_or(&Value::Null);
        let captured = tls.get("captured").unwrap_or(&Value::Null);
        let str_at = |val: &Value, key: &str| {
            val.get(key).and_then(|x| x.as_str()).map(str::to_string)
        };

        // Base target from `tlsProfile` (e.g. "Chrome_146" -> "chrome146").
        let base_target = str_at(tls, "tlsProfile").map(|p| normalize_base_target(&p));
        let user_agent = str_at(&v, "ua");
        let ja3 = str_at(captured, "ja3");
        let akamai = str_at(captured, "akamai");

        // Prefer raw arrays under captured.raw.raw.*
        let raw_root = captured.get("raw").and_then(|r| r.get("raw"));
        let arr = |key: &str| -> Vec<u16> {
            raw_root
                .and_then(|r| r.get(key))
                .and_then(|x| x.as_array())
                .map(|a| a.iter().filter_map(|n| n.as_u64().map(|n| n as u16)).collect())
                .unwrap_or_default()
        };

        let mut fp = if raw_root.is_some() {
            Fingerprint::from_raw_arrays(RawArrays {
                ciphers: arr("ciphers"),
                extensions: arr("extensions"),
                supported_groups: arr("supported_groups"),
                signature_algorithms: arr("signature_algorithms"),
                supported_versions: arr("supported_versions"),
            })
        } else {
            let mut b = Fingerprint::builder();
            if let Some(j) = &ja3 {
                b = b.ja3(j)?;
            }
            b.build()
        };

        // HTTP/2 always comes from the akamai string.
        if let Some(ak) = &akamai {
            let h2 = Fingerprint::builder().akamai(ak)?.build();
            fp.h2_settings = h2.h2_settings;
            fp.h2_window_update = h2.h2_window_update;
            fp.h2_streams = h2.h2_streams;
            fp.h2_pseudo_order = h2.h2_pseudo_order;
        }

        fp.base_target = base_target;
        fp.user_agent = user_agent;
        Ok(fp)
    }
}

/// Normalize a capture's `tlsProfile` (e.g. `"Chrome_146"`) to a
/// curl-impersonate target name (`"chrome146"`): lowercased, `_`/spaces/dots
/// removed.
#[cfg(feature = "json")]
fn normalize_base_target(profile: &str) -> String {
    profile
        .chars()
        .filter(|c| !matches!(c, '_' | ' ' | '.'))
        .flat_map(|c| c.to_lowercase())
        .collect()
}
```

Also add a unit test for the normalizer (not feature-gated on json is fine, but the fn is; gate it):

```rust
#[cfg(all(test, feature = "json"))]
#[test]
fn normalize_base_target_examples() {
    assert_eq!(normalize_base_target("Chrome_146"), "chrome146");
    assert_eq!(normalize_base_target("Safari_18.4"), "safari184");
}
```

(Place this test inside `json_tests` or its own `#[cfg(all(test, feature = "json"))] mod`.)

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test --features json --lib`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml src/fingerprint.rs
git commit -m "feat(fingerprint): json feature + from_capture_json (raw-array preferred)"
```

---

### Task 12: Docs — README section + crate docs + example

**Files:**
- Modify: `README.md`
- Modify: `src/lib.rs` (crate-level doc note on the baseline+overlay model)
- Create: `examples/custom_fingerprint.rs`

**Interfaces:**
- Consumes: the public API from Tasks 1–11.

- [ ] **Step 1: Write the example** — create `examples/custom_fingerprint.rs`:

```rust
//! Impersonate an arbitrary captured profile via a custom Fingerprint.
//!
//! Run with: `cargo run --features json --example custom_fingerprint`
//! (needs a raw `curl-impersonate` binary on PATH, or use
//! `download::ensure_impersonate_binary`).

#[cfg(feature = "json")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use curl_impersonate_cli::{Fingerprint, Request};

    let capture = r#"{
      "ua": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Mobile Safari/537.36",
      "tls": { "tlsProfile": "Chrome_146", "captured": {
        "akamai": "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
        "ja3": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,65037-35-23-10-17613-5-45-16-13-51-11-0-43-65281-27-18,4588-29-23-24,0"
      }}
    }"#;

    let fp = Fingerprint::from_capture_json(capture)?;
    // `bin` is the RAW curl-impersonate binary (not a curl_chromeNNN wrapper).
    let resp = Request::get("curl-impersonate", "https://tls.peet.ws/api/all")
        .fingerprint(fp)
        .send()
        .await?;
    println!("status {}\n{}", resp.status, resp.body);
    Ok(())
}

#[cfg(not(feature = "json"))]
fn main() {
    eprintln!("run with --features json");
}
```

Register it in `Cargo.toml` under the examples:

```toml
[[example]]
name = "custom_fingerprint"
required-features = ["json"]
```

- [ ] **Step 2: Verify the example compiles**

Run: `cargo build --features json --example custom_fingerprint`
Expected: builds cleanly.

- [ ] **Step 3: Add the README section** — insert after the existing usage/requirements content (a new `## Custom fingerprint profiles` section):

```markdown
## Custom fingerprint profiles

Beyond the pre-built `curl_chromeNNN` wrappers, you can impersonate an
**arbitrary captured profile** — including browser versions with no pre-built
wrapper. Supply a `Fingerprint` (JA3 + Akamai H2 + user-agent, or the richer raw
ClientHello arrays) and the crate synthesizes the curl-impersonate flags.

```rust,ignore
use curl_impersonate_cli::{Fingerprint, Request};

// With the `json` feature, from a captured profile:
let fp = Fingerprint::from_capture_json(capture_json)?;

// Or build it directly:
let fp = Fingerprint::builder()
    .base_target("chrome146")
    .ja3("771,4865-4866-…,…,4588-29-23-24,0")?
    .akamai("1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p")?
    .user_agent("Mozilla/5.0 … Chrome/149.0.0.0 Mobile Safari/537.36")
    .build();

// `bin` is the RAW `curl-impersonate` binary, NOT a `curl_chromeNNN` wrapper.
let resp = Request::get("curl-impersonate", "https://example.com/")
    .fingerprint(fp)
    .send()
    .await?;
```

**How it works — baseline + overlay.** curl-impersonate's `--tls-extension-order`
can only *reorder* extensions the ClientHello already emits; it can't add ALPS,
ECH, or cert-compression. So a custom profile runs as `--impersonate <base>`
(the full browser baseline, from the capture's `tlsProfile`) plus a granular
overlay (`--ciphers`, `--curves`, `--signature-hashes`, `--http2-settings`, …)
that shifts it to match your exact capture.

**Fidelity, honestly.** Byte-exact *per-connection* JA3 is impossible — real
Chrome permutes extensions and GREASEs every connection, so its own raw JA3
varies per connection. The target is **JA4 / Akamai-H2 / peetprint parity plus
the randomization** (`--tls-grease`, `--tls-permute-extensions`).
```

- [ ] **Step 4: Add a crate-doc note** — in `src/lib.rs`, append to the module-level `//!` docs a short paragraph pointing at `Fingerprint`:

```rust
//! ## Custom fingerprints
//!
//! Beyond the preset wrappers, [`Fingerprint`] drives the raw `curl-impersonate`
//! binary with an arbitrary captured profile (`--impersonate <base>` baseline +
//! granular overlay). See [`Request::fingerprint`] and, with the `json` feature,
//! [`Fingerprint::from_capture_json`].
```

- [ ] **Step 5: Run the humanizer over the README prose**

The README section is public-facing copy. Per the project's writing rules, invoke the `humanizer` skill on the new `## Custom fingerprint profiles` prose and apply its edits (kill any rule-of-three stacking, mechanical boldface, AI tells) before finalizing. Keep code blocks unchanged.

- [ ] **Step 6: Full verification + commit**

Run these in parallel:
```bash
cargo test --all-features
cargo clippy --all-features --all-targets -- -D warnings
cargo fmt --check
```
Expected: all green (the two `#[ignore]` network tests stay ignored).

```bash
git add README.md src/lib.rs examples/custom_fingerprint.rs Cargo.toml
git commit -m "docs: custom fingerprint profiles — README, crate docs, example"
```

---

## Self-Review

**1. Spec coverage:**
- Baseline+overlay model → Task 6 (`--impersonate` + `:no`), README/crate docs (Task 12). ✅
- Clean schema + converter → Task 1 (schema), Task 11 (`from_capture_json`). ✅
- Full extra_fp + all remaining flags incl. HTTP/3 → Tasks 6–7 (every flag from the api reference, minus the two with no CLI equivalent, which the spec calls out). ✅
- Setter API, preset path untouched → Task 9 (`fingerprint()`, `build_argv(&req, &[])` keeps old behavior). ✅
- Strict unknown-id → Task 6 tests (`UnknownCipher(0xDEAD)`). ✅
- Base target from `tlsProfile`, overridable, `None`=from-scratch → Task 11 (`normalize_base_target`), Task 1 (`base_target` builder setter). ✅
- Raw-array-preferred, GREASE strip → Task 8, Task 11. ✅
- `ensure_impersonate_binary` → Task 10. ✅
- Zero new default deps; `json` opt-in → Task 11 Cargo changes. ✅
- Golden formats (`:`/`,` joins, permute-skip, streams-`0`, `masp`) → Tasks 6–7 tests. ✅
- Tests: unit + golden capture + ignored integration → Tasks 2–11 unit, Task 11 golden, Task 10 ignored. ✅

**2. Placeholder scan:** No TBD/TODO; every code step has full code; every test has real assertions. ✅

**3. Type consistency:** `Fingerprint`, `FingerprintBuilder`, `RawArrays`, `CertComp`, `AlpsMode`, `FingerprintError`, `to_args() -> Result<Vec<String>, FingerprintError>`, `build_argv(&Request, &[String]) -> Vec<String>`, `ensure_impersonate_binary`/`ensure_extracted` are used consistently across tasks. `from_capture_json` returns `Result<Fingerprint, FingerprintError>` in both Task 11 impl and the Task 11 tests. ✅

**Known deliberate simplifications (ponytail):**
- Base target existence is not validated against the native list — an invalid name surfaces as `curl` non-zero at send time (spec assumption). Upgrade path: validate against a `NATIVE_TARGETS` const if it matters.
- `from_capture_json` uses `serde_json::Value` (lenient) rather than rigid structs, deliberately, to survive harvester nesting changes.
