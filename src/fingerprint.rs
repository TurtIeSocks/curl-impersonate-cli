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
    // Used by `Fingerprint::to_args` (added in a later, out-of-scope task); not
    // yet called by Task 1/2, so silence the dead-code lint until it lands.
    #[allow(dead_code)]
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
