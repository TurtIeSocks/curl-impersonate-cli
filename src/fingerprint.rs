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
                let k = k
                    .parse::<u16>()
                    .map_err(|_| malformed("non-numeric setting id"))?;
                let v = v
                    .parse::<u32>()
                    .map_err(|_| malformed("non-numeric setting value"))?;
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
}

// Ported verbatim from curl_cffi/requests/impersonate.py::TLS_CIPHER_NAME_MAP
// (IANA cipher id -> BoringSSL cipher name). All suites go in one `--ciphers`
// list; BoringSSL accepts TLS 1.3 suite names there too.
//
// Only exercised by tests until `Fingerprint::to_args` (a later, out-of-scope
// task) calls it; `#[allow(dead_code)]` silences the lint until it lands.
#[allow(dead_code)]
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
// Only exercised by tests until `to_args` (later task) calls it.
#[allow(dead_code)]
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
// Only exercised by tests until `to_args` (later task) calls it.
#[allow(dead_code)]
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
/// Only exercised by tests until `from_raw_arrays` (later task) calls it.
#[allow(dead_code)]
fn is_grease(v: u16) -> bool {
    (v & 0xFF) == (v >> 8) && (v & 0x0F) == 0x0A
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

    #[test]
    fn cipher_names_map_known_ids() {
        assert_eq!(cipher_name(0x1301), Some("TLS_AES_128_GCM_SHA256"));
        assert_eq!(
            cipher_name(0xC02B),
            Some("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256")
        );
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
        for g in [
            0x0A0Au16, 0x1A1A, 0x2A2A, 0x3A3A, 0x8A8A, 0x9A9A, 0xFAFA, 0xAAAA,
        ] {
            assert!(is_grease(g), "{g:#06x} should be GREASE");
        }
        for real in [0x1301u16, 23, 4588, 0x002F, 771, 0xC02B] {
            assert!(!is_grease(real), "{real:#06x} should not be GREASE");
        }
    }

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
        let err = Fingerprint::builder()
            .akamai("1:65536|15663105")
            .unwrap_err();
        assert!(matches!(err, FingerprintError::MalformedAkamai { .. }));
    }

    #[test]
    fn perk_parser_fills_http3_fields() {
        let fp = Fingerprint::builder()
            .perk("1:2|m,a,s,p|3:4")
            .unwrap()
            .build();
        assert!(fp.enable_http3);
        assert_eq!(fp.h3_settings.as_deref(), Some("1:2"));
        assert_eq!(fp.h3_pseudo_order.as_deref(), Some("masp"));
        assert_eq!(fp.quic_transport_params.as_deref(), Some("3:4"));
    }
}
