//! Opt-in runtime download of a prebuilt `curl-impersonate` CLI release.
//!
//! Enable the `download` feature, then call [`ensure_binary`] to fetch the
//! prebuilt release for the current platform, extract it into a cache dir, and
//! get back the filesystem path to a `curl_<browser>` wrapper — ready to pass as
//! `bin` to [`crate::Request::get`]/[`crate::Request::post`]. The call is
//! idempotent ("ensure"): a second call for an already-extracted release returns
//! the cached path without touching the network.
//!
//! # Which asset
//!
//! Each [lexiforest/curl-impersonate release] ships two asset families:
//!
//! * `curl-impersonate-<version>.<target>.tar.gz` — the **CLI** bundle: the
//!   `curl-impersonate` executable, the `curl_chromeNNN` / `curl_ffNNN` wrapper
//!   **shell scripts**, and the libraries they need. This crate downloads *this*
//!   one, because it shells out to the wrappers as subprocesses.
//! * `libcurl-impersonate-<version>.<target>.tar.gz` — the shared library, for
//!   linking. Not what a subprocess wrapper needs; never downloaded here.
//!
//! # Platform support
//!
//! Prebuilt CLI tarballs exist for Linux (`gnu` and `musl`) and macOS on x86-64
//! and ARM64. **There is no prebuilt Windows CLI** (only the *shared library* has
//! `win32` assets). On Windows — or any arch without a matching asset —
//! [`ensure_binary`] returns [`DownloadError::UnsupportedPlatform`] telling the
//! caller to build from source or use WSL, rather than attempting a download that
//! would 404.
//!
//! | `std::env::consts` (OS, ARCH) | [`Libc`] | asset target triple  |
//! |-------------------------------|----------|----------------------|
//! | `macos`, `x86_64`             | (n/a)    | `x86_64-macos`       |
//! | `macos`, `aarch64`            | (n/a)    | `arm64-macos`        |
//! | `linux`, `x86_64`             | `Gnu`    | `x86_64-linux-gnu`   |
//! | `linux`, `x86_64`             | `Musl`   | `x86_64-linux-musl`  |
//! | `linux`, `aarch64`            | `Gnu`    | `aarch64-linux-gnu`  |
//! | `linux`, `aarch64`            | `Musl`   | `aarch64-linux-musl` |
//!
//! Note that Rust reports Apple Silicon as `aarch64`, but the release names it
//! `arm64`; the mapping bridges that. [`Libc`] is ignored on macOS.
//!
//! # Integrity
//!
//! The release does **not** publish a standalone checksums file. GitHub exposes a
//! per-asset SHA-256 `digest` through its REST API, but verifying it would need a
//! JSON parser plus a hashing crate — both intentionally outside this feature's
//! minimal dependency set (`reqwest`, `flate2`, `tar`, `dirs`). Integrity
//! therefore rests on: HTTPS transport (rustls) to an exact, hard-coded
//! `github.com` release URL, the gzip member's CRC-32, and the tar structural
//! checks — any truncated or corrupted archive fails to decompress/unpack and is
//! reported as an error. See [`DownloadError`] (there is deliberately no
//! `ChecksumMismatch` variant, since no checksum is verified).
//!
//! # Layout & safety
//!
//! Files land under `<cache>/curl-impersonate-cli/<version>/<target>/`. The
//! archive is streamed to a temp file, extracted into a sibling staging
//! directory, then atomically `rename`d into place, so a concurrent or crashed
//! run never exposes a half-written release dir. Tar extraction is guarded
//! against path traversal (zip-slip): every entry path is rejected unless all its
//! components are plain names, *and* `tar`'s own bounded `unpack_in` is used.
//!
//! [lexiforest/curl-impersonate release]: https://github.com/lexiforest/curl-impersonate/releases
//! [`ensure_binary`]: crate::download::ensure_binary
//! [`Libc`]: crate::download::Libc
//! [`DownloadError`]: crate::download::DownloadError
//! [`DownloadError::UnsupportedPlatform`]: crate::download::DownloadError::UnsupportedPlatform

use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use tokio::fs;
use tokio::io::AsyncWriteExt;

/// Default `curl-impersonate` release tag used when
/// [`DownloadOptions::version`] is `None`.
///
/// Pinned to the latest stable at the time of writing (published 2026-05-02).
/// Override per-call via [`DownloadOptions::version`] to track a newer release.
pub const DEFAULT_VERSION: &str = "v1.5.6";

/// Sub-directory created under [`dirs::cache_dir`] for the default cache root.
const CACHE_SUBDIR: &str = "curl-impersonate-cli";

/// Base URL for release download assets (no trailing slash).
const RELEASE_BASE: &str = "https://github.com/lexiforest/curl-impersonate/releases/download";

/// `User-Agent` sent with the download request. Identifies this crate + version;
/// carries no secret.
const USER_AGENT: &str = concat!("curl-impersonate-cli/", env!("CARGO_PKG_VERSION"));

/// libc flavor of the prebuilt Linux CLI to fetch. Ignored on macOS.
///
/// Default is [`Libc::Gnu`] — the glibc build, correct for mainstream desktop and
/// server distributions. Pick [`Libc::Musl`] for static/musl environments such as
/// Alpine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Libc {
    /// glibc build (`*-linux-gnu`). The default.
    #[default]
    Gnu,
    /// musl build (`*-linux-musl`), for Alpine and other musl distros.
    Musl,
}

impl Libc {
    /// The token used in the asset's target triple (`"gnu"` / `"musl"`).
    fn as_str(self) -> &'static str {
        match self {
            Libc::Gnu => "gnu",
            Libc::Musl => "musl",
        }
    }
}

/// Options controlling the download.
#[derive(Debug, Clone, Default)]
pub struct DownloadOptions {
    /// curl-impersonate release tag, e.g. `"v1.5.6"`. `None` selects
    /// [`DEFAULT_VERSION`]. The value is used verbatim as the git tag and inside
    /// the asset filename, so it must include the leading `v`.
    pub version: Option<String>,
    /// Cache root. `None` selects `dirs::cache_dir()/curl-impersonate-cli`.
    pub cache_dir: Option<PathBuf>,
    /// On Linux, pick the libc flavor of the prebuilt (default [`Libc::Gnu`]).
    /// Ignored on macOS.
    pub libc: Libc,
}

/// Everything that can go wrong while ensuring a prebuilt binary is present.
///
/// There is intentionally no `ChecksumMismatch` variant: the release publishes no
/// standalone checksum file, and this feature's dependency set excludes a hashing
/// crate, so no checksum is verified (see the [module docs](self#integrity)).
/// Integrity is enforced by HTTPS plus gzip/tar structural validation, whose
/// failures surface as [`DownloadError::Io`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DownloadError {
    /// No prebuilt CLI asset exists for this OS/arch (e.g. Windows, or an
    /// unsupported architecture).
    #[error(
        "no prebuilt curl-impersonate CLI for this platform (os={os}, arch={arch}); \
         build it from source (https://github.com/lexiforest/curl-impersonate) \
         or, on Windows, use WSL"
    )]
    UnsupportedPlatform {
        /// `std::env::consts::OS` of the host.
        os: &'static str,
        /// `std::env::consts::ARCH` of the host.
        arch: &'static str,
    },

    /// The caller-supplied `version` was empty or contained characters that
    /// could escape the cache directory (path separators / `..`). Since
    /// `version` becomes a cache path component, it is validated like `browser`.
    #[error("invalid version {version:?}; expected a release tag like \"v1.5.6\"")]
    InvalidVersion {
        /// The rejected version.
        version: String,
    },

    /// The caller-supplied `browser` id was empty or contained characters other
    /// than ASCII alphanumerics and `_` (which could otherwise smuggle path
    /// separators into the wrapper lookup).
    #[error(
        "invalid browser id {browser:?}; expected an alphanumeric/underscore wrapper suffix like \"chrome146\""
    )]
    InvalidBrowser {
        /// The rejected id.
        browser: String,
    },

    /// No cache directory could be determined and none was provided.
    #[error("could not determine a cache directory; set DownloadOptions::cache_dir explicitly")]
    NoCacheDir,

    /// Transport/network failure building the client or fetching the asset.
    #[error("http request failed: {0}")]
    Http(#[from] reqwest::Error),

    /// The download responded with a non-success HTTP status (e.g. 404 for a
    /// wrong version or target). The URL carries no credentials.
    #[error("download returned HTTP {status} for {url}")]
    HttpStatus {
        /// The HTTP status code received.
        status: u16,
        /// The requested URL (a public `github.com` release URL; no secrets).
        url: String,
    },

    /// A filesystem or archive (gzip/tar) I/O error, with a describing context.
    #[error("{context}: {source}")]
    Io {
        /// What was being attempted.
        context: String,
        /// The underlying OS/archive error.
        #[source]
        source: std::io::Error,
    },

    /// An archive entry's path would escape the extraction directory
    /// (path traversal / zip-slip). The entry is refused.
    #[error("archive entry escapes the extraction directory: {path}")]
    UnsafeEntry {
        /// The offending entry path as stored in the archive.
        path: String,
    },

    /// The archive extracted cleanly but did not contain the requested
    /// `curl_<browser>` wrapper (e.g. that browser isn't shipped in this release).
    #[error("wrapper `curl_{browser}` not found in extracted release at {}", .dir.display())]
    WrapperNotFound {
        /// The requested browser suffix.
        browser: String,
        /// The extraction directory that was searched.
        dir: PathBuf,
    },

    /// The background extraction task panicked or was cancelled.
    #[error("extraction task failed: {0}")]
    Join(String),
}

/// Build a `map_err` closure that wraps a [`std::io::Error`] with `context`.
fn io_err<S: Into<String>>(context: S) -> impl FnOnce(std::io::Error) -> DownloadError {
    move |source| DownloadError::Io {
        context: context.into(),
        source,
    }
}

/// Ensure a `curl_<browser>` wrapper exists locally; download + extract the
/// release for the current platform if it is missing.
///
/// `browser` is the wrapper suffix, e.g. `"chrome146"` → the returned path's file
/// name is `curl_chrome146`. Pass that path as `bin` to
/// [`crate::Request::get`]/[`crate::Request::post`].
///
/// The returned path is absolute (canonicalized). This matters: the wrapper is a
/// shell script that locates the `curl-impersonate` binary *relative to its own
/// directory* (`dir=${0%/*}`), so it must be invoked via a path containing a
/// separator — a bare name resolved through `PATH` would break that lookup.
///
/// # Idempotency
///
/// If the wrapper already exists in the cache for the requested version and
/// target, it is returned immediately without any network access.
///
/// # Errors
///
/// See [`DownloadError`] — notably [`DownloadError::UnsupportedPlatform`] on
/// Windows / unsupported arches, and [`DownloadError::WrapperNotFound`] when the
/// release does not ship the requested browser.
pub async fn ensure_binary(
    browser: &str,
    opts: &DownloadOptions,
) -> Result<PathBuf, DownloadError> {
    validate_browser(browser)?;

    let version = opts.version.as_deref().unwrap_or(DEFAULT_VERSION);
    validate_version(version)?;
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    let triple = target_triple(os, arch, opts.libc)
        .ok_or(DownloadError::UnsupportedPlatform { os, arch })?;

    let cache_root = match &opts.cache_dir {
        Some(p) => p.clone(),
        None => dirs::cache_dir()
            .ok_or(DownloadError::NoCacheDir)?
            .join(CACHE_SUBDIR),
    };

    let release_dir = cache_root.join(version);
    let extract_dir = release_dir.join(&triple);
    let wrapper = extract_dir.join(wrapper_file_name(browser));

    // Fast path: the release is already extracted.
    if extract_dir.is_dir() {
        return if wrapper.is_file() {
            Ok(finalize(wrapper))
        } else {
            Err(DownloadError::WrapperNotFound {
                browser: browser.to_string(),
                dir: extract_dir,
            })
        };
    }

    // Download into the cache root (create it first so temp files share the
    // filesystem with the final dir → atomic rename works).
    fs::create_dir_all(&release_dir)
        .await
        .map_err(io_err("create cache directory"))?;

    let suffix = unique_suffix();
    let tarball = release_dir.join(format!(".dl-{triple}-{suffix}.tar.gz"));
    let staging = release_dir.join(format!(".staging-{triple}-{suffix}"));

    let asset = asset_name(version, &triple);
    let url = download_url(version, &asset);
    let dl = download_to_file(&url, &tarball).await;
    if let Err(e) = dl {
        let _ = fs::remove_file(&tarball).await;
        return Err(e);
    }

    // Extraction (gzip/tar) is blocking; run it off the async runtime. It also
    // chmods the wrapper + binary executable and atomically places the result.
    let (t, s, f) = (tarball.clone(), staging.clone(), extract_dir.clone());
    let placed = tokio::task::spawn_blocking(move || extract_and_place(&t, &s, &f))
        .await
        .map_err(|e| DownloadError::Join(e.to_string()));
    // Best-effort cleanup of the temp tarball regardless of outcome.
    let _ = fs::remove_file(&tarball).await;
    placed??;

    if wrapper.is_file() {
        Ok(finalize(wrapper))
    } else {
        Err(DownloadError::WrapperNotFound {
            browser: browser.to_string(),
            dir: extract_dir,
        })
    }
}

/// Reject browser ids that are empty or contain anything other than ASCII
/// alphanumerics and `_`, so they can never inject path separators into the
/// wrapper filename lookup.
fn validate_browser(browser: &str) -> Result<(), DownloadError> {
    let ok = !browser.is_empty()
        && browser
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_');
    if ok {
        Ok(())
    } else {
        Err(DownloadError::InvalidBrowser {
            browser: browser.to_string(),
        })
    }
}

/// Reject versions that are empty, `.`/`..`, or contain anything but ASCII
/// alphanumerics and `.-_`. `version` becomes a cache path component (and part
/// of the asset filename), so this keeps a caller-supplied tag from escaping the
/// cache directory via a separator or parent reference. Permits real tags like
/// `v1.5.6`, `v2.0.0a1`, `v2.0.0-rc.5`.
fn validate_version(version: &str) -> Result<(), DownloadError> {
    let ok = !version.is_empty()
        && version != "."
        && version != ".."
        && version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
    if ok {
        Ok(())
    } else {
        Err(DownloadError::InvalidVersion {
            version: version.to_string(),
        })
    }
}

/// The wrapper script's file name for a given browser suffix.
fn wrapper_file_name(browser: &str) -> String {
    format!("curl_{browser}")
}

/// Map `std::env::consts::{OS, ARCH}` (+ chosen [`Libc`]) to a release asset
/// target triple, or `None` if no prebuilt CLI asset exists for it.
fn target_triple(os: &str, arch: &str, libc: Libc) -> Option<String> {
    match (os, arch) {
        // macOS: single build per arch; libc is irrelevant. Rust's `aarch64`
        // maps to the release's `arm64`.
        ("macos", "x86_64") => Some("x86_64-macos".to_string()),
        ("macos", "aarch64") => Some("arm64-macos".to_string()),
        // Linux: glibc or musl, per `libc`.
        ("linux", "x86_64") => Some(format!("x86_64-linux-{}", libc.as_str())),
        ("linux", "aarch64") => Some(format!("aarch64-linux-{}", libc.as_str())),
        _ => None,
    }
}

/// The CLI asset filename for a version + target triple.
fn asset_name(version: &str, triple: &str) -> String {
    format!("curl-impersonate-{version}.{triple}.tar.gz")
}

/// The full release download URL for an asset filename.
fn download_url(version: &str, asset: &str) -> String {
    format!("{RELEASE_BASE}/{version}/{asset}")
}

/// A per-process-unique suffix for temp file/dir names (pid + monotonic
/// counter), so concurrent `ensure_binary` calls never collide.
fn unique_suffix() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(0);
    let n = CTR.fetch_add(1, Ordering::Relaxed);
    format!("{}-{}", std::process::id(), n)
}

/// Canonicalize `wrapper` to an absolute, symlink-resolved path so the wrapper's
/// `$0`-relative binary lookup works from any CWD. Falls back to the input on the
/// (unexpected) canonicalize failure.
fn finalize(wrapper: PathBuf) -> PathBuf {
    std::fs::canonicalize(&wrapper).unwrap_or(wrapper)
}

/// Stream a URL to `dest`, checking the HTTP status first. Streams in chunks so
/// the whole archive is never buffered in memory.
async fn download_to_file(url: &str, dest: &Path) -> Result<(), DownloadError> {
    let client = reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .connect_timeout(Duration::from_secs(30))
        // Bound inactivity between reads so a stalled/black-holed mirror errors
        // out instead of hanging `ensure_binary` forever. Per-read (not total)
        // so genuinely slow links can still complete a large download.
        .read_timeout(Duration::from_secs(60))
        .build()?;

    let mut resp = client.get(url).send().await?;
    let status = resp.status();
    if !status.is_success() {
        return Err(DownloadError::HttpStatus {
            status: status.as_u16(),
            url: url.to_string(),
        });
    }

    let mut file = fs::File::create(dest)
        .await
        .map_err(io_err("create download temp file"))?;
    while let Some(chunk) = resp.chunk().await? {
        file.write_all(&chunk)
            .await
            .map_err(io_err("write download temp file"))?;
    }
    file.flush()
        .await
        .map_err(io_err("flush download temp file"))?;
    Ok(())
}

/// Blocking: extract `tarball` into a fresh `staging` dir (traversal-guarded),
/// make its files executable, then atomically move `staging` → `final_dir`.
fn extract_and_place(
    tarball: &Path,
    staging: &Path,
    final_dir: &Path,
) -> Result<(), DownloadError> {
    // Start from a clean staging dir.
    if staging.exists() {
        let _ = std::fs::remove_dir_all(staging);
    }
    std::fs::create_dir_all(staging).map_err(io_err("create staging directory"))?;

    // Extract + chmod; on any failure, remove the partial staging dir.
    if let Err(e) = extract_archive(tarball, staging)
        .and_then(|()| make_executable(staging).map_err(io_err("chmod extracted files")))
    {
        let _ = std::fs::remove_dir_all(staging);
        return Err(e);
    }

    // Atomically place. If another process won the race, `rename` onto its
    // non-empty dir fails — treat an already-present `final_dir` as success.
    match std::fs::rename(staging, final_dir) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_dir_all(staging);
            if final_dir.is_dir() {
                Ok(())
            } else {
                Err(DownloadError::Io {
                    context: "place extracted release".to_string(),
                    source: e,
                })
            }
        }
    }
}

/// Extract a gzip'd tar into `dest`, refusing any entry whose path is not
/// contained within `dest` (path traversal / zip-slip).
fn extract_archive(tarball: &Path, dest: &Path) -> Result<(), DownloadError> {
    let file = std::fs::File::open(tarball).map_err(io_err("open downloaded archive"))?;
    let gz = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(gz);

    let entries = archive.entries().map_err(io_err("read archive entries"))?;
    for entry in entries {
        let mut entry = entry.map_err(io_err("read archive entry"))?;
        let path = entry
            .path()
            .map_err(io_err("read archive entry path"))?
            .into_owned();

        // Belt: reject `..`, absolute, or otherwise non-plain component paths.
        if !entry_path_is_safe(&path) {
            return Err(DownloadError::UnsafeEntry {
                path: path.display().to_string(),
            });
        }

        // Suspenders: `unpack_in` is itself bounded to `dest`; `Ok(false)` means
        // it refused the entry as unsafe.
        let unpacked = entry
            .unpack_in(dest)
            .map_err(io_err("unpack archive entry"))?;
        if !unpacked {
            return Err(DownloadError::UnsafeEntry {
                path: path.display().to_string(),
            });
        }
    }
    Ok(())
}

/// True if every component of `path` is a plain name (or `.`), i.e. it cannot
/// escape the extraction root.
fn entry_path_is_safe(path: &Path) -> bool {
    path.components()
        .all(|c| matches!(c, Component::Normal(_) | Component::CurDir))
}

/// Mark every regular file directly under `dir` as executable (`0o755`). The CLI
/// bundle is flat — the `curl-impersonate` binary plus the wrapper scripts — and
/// all must be executable for the wrapper's relative exec to work. No-op on
/// non-unix (the download path is unreachable there anyway).
#[cfg(unix)]
fn make_executable(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            std::fs::set_permissions(entry.path(), std::fs::Permissions::from_mode(0o755))?;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn make_executable(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- target-triple mapping (pure, no network) ---

    #[test]
    fn maps_macos_targets_ignoring_libc() {
        assert_eq!(
            target_triple("macos", "x86_64", Libc::Gnu).as_deref(),
            Some("x86_64-macos")
        );
        // Apple Silicon: Rust says aarch64, asset says arm64. libc irrelevant.
        assert_eq!(
            target_triple("macos", "aarch64", Libc::Gnu).as_deref(),
            Some("arm64-macos")
        );
        assert_eq!(
            target_triple("macos", "aarch64", Libc::Musl).as_deref(),
            Some("arm64-macos"),
            "macOS ignores the libc flavor"
        );
    }

    #[test]
    fn maps_linux_targets_by_libc() {
        assert_eq!(
            target_triple("linux", "x86_64", Libc::Gnu).as_deref(),
            Some("x86_64-linux-gnu")
        );
        assert_eq!(
            target_triple("linux", "x86_64", Libc::Musl).as_deref(),
            Some("x86_64-linux-musl")
        );
        assert_eq!(
            target_triple("linux", "aarch64", Libc::Gnu).as_deref(),
            Some("aarch64-linux-gnu")
        );
        assert_eq!(
            target_triple("linux", "aarch64", Libc::Musl).as_deref(),
            Some("aarch64-linux-musl")
        );
    }

    #[test]
    fn unsupported_platforms_map_to_none() {
        // No prebuilt CLI for Windows...
        assert_eq!(target_triple("windows", "x86_64", Libc::Gnu), None);
        // ...nor for exotic arches we don't map...
        assert_eq!(target_triple("linux", "riscv64", Libc::Gnu), None);
        assert_eq!(target_triple("linux", "x86", Libc::Gnu), None);
        // ...nor other operating systems.
        assert_eq!(target_triple("freebsd", "x86_64", Libc::Gnu), None);
    }

    // --- asset name + URL construction (matches confirmed v1.5.6 ground truth) ---

    #[test]
    fn builds_confirmed_asset_names() {
        assert_eq!(
            asset_name("v1.5.6", "x86_64-macos"),
            "curl-impersonate-v1.5.6.x86_64-macos.tar.gz"
        );
        assert_eq!(
            asset_name("v1.5.6", "arm64-macos"),
            "curl-impersonate-v1.5.6.arm64-macos.tar.gz"
        );
        assert_eq!(
            asset_name("v1.5.6", "x86_64-linux-gnu"),
            "curl-impersonate-v1.5.6.x86_64-linux-gnu.tar.gz"
        );
    }

    #[test]
    fn builds_confirmed_download_urls() {
        // Full (os, arch, libc) → URL paths, each verified against the live
        // release's `browser_download_url`.
        let cases = [
            (
                ("macos", "x86_64", Libc::Gnu),
                "https://github.com/lexiforest/curl-impersonate/releases/download/v1.5.6/curl-impersonate-v1.5.6.x86_64-macos.tar.gz",
            ),
            (
                ("linux", "x86_64", Libc::Gnu),
                "https://github.com/lexiforest/curl-impersonate/releases/download/v1.5.6/curl-impersonate-v1.5.6.x86_64-linux-gnu.tar.gz",
            ),
            (
                ("linux", "aarch64", Libc::Musl),
                "https://github.com/lexiforest/curl-impersonate/releases/download/v1.5.6/curl-impersonate-v1.5.6.aarch64-linux-musl.tar.gz",
            ),
        ];
        for ((os, arch, libc), want) in cases {
            let triple = target_triple(os, arch, libc).expect("supported target");
            let url = download_url("v1.5.6", &asset_name("v1.5.6", &triple));
            assert_eq!(url, want, "for ({os}, {arch}, {libc:?})");
        }
    }

    #[test]
    fn default_version_is_v_prefixed_stable() {
        assert_eq!(DEFAULT_VERSION, "v1.5.6");
        assert!(DEFAULT_VERSION.starts_with('v'));
    }

    // --- browser id validation + wrapper naming ---

    #[test]
    fn wrapper_file_name_prefixes_curl() {
        assert_eq!(wrapper_file_name("chrome146"), "curl_chrome146");
        assert_eq!(wrapper_file_name("safari180_ios"), "curl_safari180_ios");
    }

    #[test]
    fn browser_validation_rejects_separators_and_empty() {
        for good in ["chrome146", "firefox144", "safari2601", "tor145", "edge101"] {
            assert!(validate_browser(good).is_ok(), "{good} should be valid");
        }
        for bad in [
            "",
            "chrome/../..",
            "chrome 146",
            "a/b",
            "..",
            "chrome146;rm",
        ] {
            assert!(
                matches!(
                    validate_browser(bad),
                    Err(DownloadError::InvalidBrowser { .. })
                ),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn version_validation_allows_real_tags_rejects_traversal() {
        for good in ["v1.5.6", "v2.0.0a1", "v2.0.0-rc.5", "v1.2.3_patch"] {
            assert!(validate_version(good).is_ok(), "{good} should be valid");
        }
        for bad in [
            "",
            ".",
            "..",
            "/etc/cron.d",
            "../../tmp/x",
            "v1/../..",
            "v 1.5",
        ] {
            assert!(
                matches!(
                    validate_version(bad),
                    Err(DownloadError::InvalidVersion { .. })
                ),
                "{bad:?} should be rejected"
            );
        }
    }

    // --- zip-slip guard (pure) ---

    #[test]
    fn entry_path_safety() {
        for safe in ["curl-impersonate", "curl_chrome146", "sub/dir/file", "./ok"] {
            assert!(entry_path_is_safe(Path::new(safe)), "{safe} should be safe");
        }
        for unsafe_ in ["../evil", "/etc/passwd", "a/../../b", "../../x"] {
            assert!(
                !entry_path_is_safe(Path::new(unsafe_)),
                "{unsafe_} should be rejected"
            );
        }
    }

    // --- error surfaces ---

    #[test]
    fn unsupported_platform_error_mentions_wsl_and_source() {
        let e = DownloadError::UnsupportedPlatform {
            os: "windows",
            arch: "x86_64",
        };
        let msg = e.to_string();
        assert!(msg.contains("windows") && msg.contains("x86_64"));
        assert!(msg.contains("WSL"));
        assert!(msg.contains("build it from source"));
    }

    #[test]
    fn wrapper_not_found_error_names_browser_and_dir() {
        let e = DownloadError::WrapperNotFound {
            browser: "chrome146".to_string(),
            dir: PathBuf::from("/cache/v1.5.6/x86_64-macos"),
        };
        let msg = e.to_string();
        assert!(msg.contains("curl_chrome146"));
        assert!(msg.contains("/cache/v1.5.6/x86_64-macos"));
    }

    #[test]
    fn libc_default_is_gnu() {
        assert_eq!(Libc::default(), Libc::Gnu);
        assert_eq!(Libc::Gnu.as_str(), "gnu");
        assert_eq!(Libc::Musl.as_str(), "musl");
    }

    // --- network integration test (opt-in) ---

    /// Actually downloads + extracts the release for the *current* platform into a
    /// throwaway cache dir and checks the wrapper landed. Ignored by default (hits
    /// the network + writes to disk); run with:
    /// `cargo test --features download -- --ignored ensures_binary_downloads`.
    #[tokio::test]
    #[ignore = "network: downloads a real curl-impersonate release"]
    async fn ensures_binary_downloads() {
        let cache = std::env::temp_dir().join(format!("cimp-test-{}", unique_suffix()));
        let opts = DownloadOptions {
            cache_dir: Some(cache.clone()),
            ..Default::default()
        };
        let path = ensure_binary("chrome146", &opts)
            .await
            .expect("download + extract");
        assert!(path.is_file(), "wrapper should exist at {path:?}");
        assert_eq!(path.file_name().unwrap(), "curl_chrome146");

        // Second call is idempotent and returns the same path with no network.
        let again = ensure_binary("chrome146", &opts).await.expect("cached");
        assert_eq!(again, path);

        let _ = std::fs::remove_dir_all(&cache);
    }
}
