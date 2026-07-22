//! Thin async wrapper around the curl-impersonate CLI (lexiforest fork).
//!
//! curl-impersonate links a patched BoringSSL + nghttp2, so its `curl_chromeNNN`
//! wrappers emit a *byte-exact* Chrome TLS ClientHello + HTTP/2 SETTINGS — the
//! fingerprint Imperva/Akamai cross-check and that emulating HTTP stacks (wreq,
//! reqwest, …) can only approximate. We shell out to the wrapper (it owns every
//! fingerprint flag) and override only the request-level inputs: method, URL,
//! headers, cookies, body, proxy.
//!
//! Header semantics: an externally-supplied `-H 'Name: value'` *replaces* the
//! impersonation's internal header of the same name; `-H 'Name:'` (empty value)
//! *removes* one. That's how a caller turns the wrapper's default navigation
//! headers into a `fetch()`/CORS set without disturbing the fingerprint.
//!
//! This crate is provider-agnostic — it knows nothing about any specific site,
//! anti-bot vendor, or token format. Callers parse the returned body/cookies
//! themselves.
//!
//! Requires a `curl-impersonate` build on the host (the `curl_chromeNNN`
//! wrapper scripts / binary). Install it yourself, or enable the `download`
//! feature to fetch a prebuilt release into a cache dir at runtime. See
//! <https://github.com/lexiforest/curl-impersonate>.

use std::ffi::OsString;
use std::process::Stdio;

use tokio::{io::AsyncWriteExt, process::Command};

/// Fetch a prebuilt `curl-impersonate` release at runtime (opt-in). Enable the
/// `download` feature. See [`download::ensure_binary`].
#[cfg(feature = "download")]
pub mod download;

pub mod fingerprint;
pub use fingerprint::{AlpsMode, CertComp, Fingerprint, FingerprintError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
}

/// Proxy as a single URL with percent-encoded inline credentials. Passed to
/// curl via the `ALL_PROXY` env var, NOT argv — so the credentials never land in
/// world-readable `/proc/<pid>/cmdline` (env is owner-only). The caller is
/// responsible for percent-encoding userinfo.
#[derive(Debug, Clone)]
pub struct ProxySpec {
    /// `scheme://[enc_user[:enc_pass]@]host:port`.
    pub url: String,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CurlError {
    #[error("spawn {bin}: {source}")]
    Spawn {
        bin: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{bin} exited {code:?}: {stderr}")]
    NonZero {
        bin: String,
        code: Option<i32>,
        stderr: String,
    },
    #[error("io: {0}")]
    Io(String),
    #[error("no HTTP status block in curl output")]
    NoStatus,
    #[error("unparsable status line: {0:?}")]
    BadStatus(String),
}

/// Parsed HTTP response: status code, raw `Set-Cookie` header lines, the final
/// response's header block, the (curl-decompressed) body, and the effective URL
/// after any `-L` redirects.
///
/// `#[non_exhaustive]`: read its fields, but construct it only via [`Request::send`].
/// New fields may be added in a minor release.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct Response {
    pub status: u16,
    pub set_cookies: Vec<String>,
    /// `(name, value)` of every header on the FINAL response block. Lets callers
    /// tell an origin response from an intermediary's (e.g. `X-Iinfo`/`X-CDN`
    /// mark an Imperva-served page vs a pass-through origin one).
    pub headers: Vec<(String, String)>,
    pub body: String,
    /// `%{url_effective}` — the URL curl actually ended on after `-L`. `None`
    /// when the write-out line wasn't captured.
    pub final_url: Option<String>,
}

/// One curl-impersonate request. Build with [`Request::get`]/[`Request::post`],
/// chain the optional setters, then `.send().await`.
#[derive(Debug, Clone)]
pub struct Request {
    bin: OsString,
    method: Method,
    url: String,
    headers: Vec<(String, String)>,
    remove_headers: Vec<String>,
    cookies: Vec<(String, String)>,
    body: Option<Vec<u8>>,
    proxy: Option<ProxySpec>,
    timeout_secs: f64,
    insecure: bool,
    max_filesize: Option<u64>,
    follow_redirects: bool,
    max_redirs: u32,
}

/// Default response-size cap (`--max-filesize`): a hostile target/proxy can't
/// OOM us by streaming an unbounded body. Generous vs any real API JSON / HTML
/// page; override with [`Request::max_filesize`].
const DEFAULT_MAX_FILESIZE: u64 = 16 * 1024 * 1024;

/// Default `--max-redirs` when redirect-following is enabled. Matches reqwest's
/// default redirect budget (10), so a curl hop follows a chain the same depth an
/// emulated (wreq) client would.
const DEFAULT_MAX_REDIRS: u32 = 10;

/// Prefix of the `-w %{url_effective}` line curl writes to stderr. `run` reads
/// the effective URL from it, then strips any such line before surfacing stderr
/// to the caller so this internal marker never leaks.
const FINAL_URL_SENTINEL: &str = "curl-impersonate-cli-final-url=";

impl Request {
    /// `bin` is the `curl_chromeNNN` wrapper — a name resolved via `PATH`, or an
    /// absolute path (e.g. the one returned by the `download` feature). Accepts
    /// anything path-like (`&str`, `String`, `PathBuf`, …) losslessly.
    pub fn new(bin: impl Into<OsString>, method: Method, url: impl Into<String>) -> Self {
        Self {
            bin: bin.into(),
            method,
            url: url.into(),
            headers: Vec::new(),
            remove_headers: Vec::new(),
            cookies: Vec::new(),
            body: None,
            proxy: None,
            timeout_secs: 30.0,
            insecure: false,
            max_filesize: Some(DEFAULT_MAX_FILESIZE),
            follow_redirects: false,
            max_redirs: DEFAULT_MAX_REDIRS,
        }
    }

    pub fn get(bin: impl Into<OsString>, url: impl Into<String>) -> Self {
        Self::new(bin, Method::Get, url)
    }

    pub fn post(bin: impl Into<OsString>, url: impl Into<String>) -> Self {
        Self::new(bin, Method::Post, url)
    }

    /// Override/add a request header (replaces the impersonation default of the
    /// same name).
    pub fn header(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.headers.push((k.into(), v.into()));
        self
    }

    pub fn headers<I, K, V>(mut self, iter: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        self.headers
            .extend(iter.into_iter().map(|(k, v)| (k.into(), v.into())));
        self
    }

    /// Remove a header the impersonation would otherwise send (empty `-H`).
    pub fn remove_header(mut self, name: impl Into<String>) -> Self {
        self.remove_headers.push(name.into());
        self
    }

    /// Cookies sent via `-b "k=v; k2=v2"`. Replaces any prior set.
    pub fn cookies(mut self, cookies: Vec<(String, String)>) -> Self {
        self.cookies = cookies;
        self
    }

    /// Request body, streamed from stdin (`--data-binary @-`): binary-safe, no
    /// arg-length limit. Only sent on `POST` — a body on a `GET` is ignored
    /// (sending it would silently flip curl to a POST).
    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }

    pub fn proxy(mut self, proxy: Option<ProxySpec>) -> Self {
        self.proxy = proxy;
        self
    }

    pub fn timeout_secs(mut self, secs: f64) -> Self {
        self.timeout_secs = secs;
        self
    }

    /// `-k` — skip TLS cert verification (parity with the emulated clients that
    /// run `verify=False`).
    pub fn insecure(mut self, insecure: bool) -> Self {
        self.insecure = insecure;
        self
    }

    /// `--max-filesize` cap in bytes (`None` disables). Defaults to 16 MiB.
    pub fn max_filesize(mut self, bytes: Option<u64>) -> Self {
        self.max_filesize = bytes;
        self
    }

    /// `-L` — follow HTTP 3xx redirects (up to [`Request::max_redirs`]). Off by
    /// default: curl otherwise returns the 3xx itself, so a caller that expects a
    /// browser-like GET must opt in. On a 301/302/303 after a POST, curl (like a
    /// browser) re-issues the follow-up as a bodyless GET.
    pub fn follow_redirects(mut self, yes: bool) -> Self {
        self.follow_redirects = yes;
        self
    }

    /// `--max-redirs` — max redirects to follow when [`Request::follow_redirects`]
    /// is on. Defaults to 10.
    pub fn max_redirs(mut self, n: u32) -> Self {
        self.max_redirs = n;
        self
    }

    pub async fn send(self) -> Result<Response, CurlError> {
        run(self).await
    }
}

/// Build the curl argv (everything after the binary, up to and including
/// `-- <url>`). Pure over the request so it is unit-testable without spawning:
/// proxy credentials (env `ALL_PROXY`) and the request body (stdin) are handled
/// separately in [`run`] and deliberately never appear here.
fn build_argv(req: &Request) -> Vec<String> {
    let mut a: Vec<String> = vec![
        "-sS".into(), // silent, but surface transport errors on stderr
        "-i".into(),  // include response headers in stdout for cookie/status parsing
        "--max-time".into(),
        format!("{}", req.timeout_secs),
        // Emit the final effective URL (after -L) to STDERR via write-out, so it
        // never pollutes the -i stdout we parse; `run` reads it back and strips
        // this line before surfacing any stderr to the caller.
        "-w".into(),
        format!("%{{stderr}}{FINAL_URL_SENTINEL}%{{url_effective}}\\n"),
    ];
    if req.follow_redirects {
        a.push("-L".into());
        a.push("--max-redirs".into());
        a.push(req.max_redirs.to_string());
    }
    if req.insecure {
        a.push("-k".into());
    }
    if let Some(max) = req.max_filesize {
        a.push("--max-filesize".into());
        a.push(max.to_string());
    }
    // Method selection is deliberately entangled with redirect semantics:
    //  * With a body, `--data-binary @-` (below) already makes the FIRST request
    //    a POST, and — crucially — leaving `-X` OFF lets curl downgrade to GET on
    //    a 301/302/303 while following `-L`, exactly as a browser / reqwest does.
    //    Forcing `-X POST` would make curl re-POST the form body to every redirect
    //    hop (curl(1): "-X ... is used for all requests, which if you use -L may
    //    cause unintended side-effects when curl does not change request method
    //    according to the HTTP 30x response codes"). That would re-submit
    //    credentials to a verifier endpoint — wrong.
    //  * Without a body there is nothing to imply POST, so force it explicitly.
    if req.method == Method::Post && req.body.is_none() {
        a.push("-X".into());
        a.push("POST".into());
    }
    if !req.cookies.is_empty() {
        let jar = req
            .cookies
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ");
        a.push("-b".into());
        a.push(jar);
    }
    for (k, v) in &req.headers {
        a.push("-H".into());
        a.push(format!("{k}: {v}"));
    }
    for name in &req.remove_headers {
        a.push("-H".into());
        a.push(format!("{name}:"));
    }
    // A body only makes sense on POST; a GET body would silently flip the method.
    if req.method == Method::Post && req.body.is_some() {
        a.push("--data-binary".into());
        a.push("@-".into());
    }
    // `--` terminates option parsing: a URL value starting with `-` (e.g. a
    // caller-controlled `-K<file>`) is then treated as a host, NOT a curl flag
    // (CWE-88 argument injection).
    a.push("--".into());
    a.push(req.url.clone());
    a
}

async fn run(req: Request) -> Result<Response, CurlError> {
    let mut cmd = Command::new(&req.bin);
    cmd.args(build_argv(&req));

    match &req.proxy {
        Some(p) => {
            // Credentials live in the URL but go via env (owner-only
            // /proc/<pid>/environ), never argv (world-readable /proc/<pid>/cmdline).
            cmd.env("ALL_PROXY", &p.url);
        }
        None => {
            // No proxy requested → make that explicit rather than silently
            // inheriting the process's ambient proxy env, which would route the
            // "direct" request through an unexpected exit.
            for var in [
                "ALL_PROXY",
                "all_proxy",
                "HTTP_PROXY",
                "http_proxy",
                "HTTPS_PROXY",
                "https_proxy",
                "NO_PROXY",
                "no_proxy",
            ] {
                cmd.env_remove(var);
            }
        }
    }

    // A body only makes sense on POST; a GET body would silently flip the method.
    let body = if req.method == Method::Post {
        req.body
    } else {
        None
    };
    let has_body = body.is_some();
    cmd.stdin(if has_body {
        Stdio::piped()
    } else {
        Stdio::null()
    })
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());

    let mut child = cmd.spawn().map_err(|e| CurlError::Spawn {
        bin: req.bin.to_string_lossy().into_owned(),
        source: e,
    })?;

    // Write stdin from a concurrent task so a large body can't deadlock against
    // an unread stdout pipe (wait_with_output drains stdout/stderr).
    let writer = body.map(|body| {
        let mut stdin = child.stdin.take().expect("stdin piped when body set");
        tokio::spawn(async move {
            let _ = stdin.write_all(&body).await;
            // stdin dropped here -> EOF
        })
    });

    let out = child
        .wait_with_output()
        .await
        .map_err(|e| CurlError::Io(e.to_string()))?;
    if let Some(w) = writer {
        let _ = w.await;
    }

    let stderr = String::from_utf8_lossy(&out.stderr);

    if !out.status.success() {
        // Drop our internal write-out marker line before surfacing stderr.
        let cleaned = stderr
            .lines()
            .filter(|l| !l.starts_with(FINAL_URL_SENTINEL))
            .collect::<Vec<_>>()
            .join("\n");
        return Err(CurlError::NonZero {
            bin: req.bin.to_string_lossy().into_owned(),
            code: out.status.code(),
            stderr: cleaned.trim().to_string(),
        });
    }
    // The `-w %{url_effective}` marker line carries the final URL after `-L`.
    let final_url = stderr
        .lines()
        .rev()
        .find_map(|l| {
            l.strip_prefix(FINAL_URL_SENTINEL)
                .map(|s| s.trim().to_string())
        })
        .filter(|s| !s.is_empty());
    let mut resp = parse_response(&out.stdout)?;
    resp.final_url = final_url;
    Ok(resp)
}

/// Parse curl `-i` output into status + Set-Cookie lines + body.
///
/// curl emits one or more `HTTP/x NNN\r\n<headers>\r\n\r\n` blocks before the
/// body — a proxy `CONNECT` 200 preamble and/or (`-L`) redirect hops prepend
/// extra blocks. We consume every leading `HTTP/`-prefixed block, take the LAST
/// as the real response status + body, and accumulate `Set-Cookie` from EVERY
/// block. Collecting cookies across the whole chain matters because a redirect
/// hop can set a session cookie the final response does not repeat: curl carries
/// it internally for the rest of THIS transfer, but the caller threads cookies
/// by hand into the NEXT hop, so the mid-chain `Set-Cookie` must survive here
/// (this mirrors an emulated client's persistent jar).
///
/// # Limitation
///
/// The header/body split is found by scanning leading `HTTP/`-prefixed blocks,
/// so a response whose **body** begins with the literal text `HTTP/` followed by
/// a blank line would have that leading slice mis-attributed to the headers.
/// This is vanishingly rare for real page/API bodies and is accepted for now; a
/// future version may split on curl's exact header byte count instead.
fn parse_response(stdout: &[u8]) -> Result<Response, CurlError> {
    let text = String::from_utf8_lossy(stdout);
    let mut rest: &str = &text;
    let mut last_head = "";
    let mut set_cookies: Vec<String> = Vec::new();
    while rest.starts_with("HTTP/") {
        let Some(end) = block_end(rest) else { break };
        let head = &rest[..end];
        set_cookies.extend(
            head.lines()
                .filter_map(|l| l.split_once(':'))
                .filter(|(k, _)| k.trim().eq_ignore_ascii_case("set-cookie"))
                .map(|(_, v)| v.trim().to_string()),
        );
        last_head = head;
        rest = &rest[end..];
    }
    if last_head.is_empty() {
        return Err(CurlError::NoStatus);
    }

    let status_line = last_head.lines().next().unwrap_or_default();
    let status = status_line
        .split_whitespace()
        .find_map(|tok| tok.parse::<u16>().ok())
        .ok_or_else(|| CurlError::BadStatus(status_line.to_string()))?;

    // All headers on the final block (skip the status line). `split_once(':')`
    // keeps the first colon as the separator, so `https://…` values survive.
    let headers: Vec<(String, String)> = last_head
        .lines()
        .skip(1)
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();

    Ok(Response {
        status,
        set_cookies,
        headers,
        body: rest.to_string(),
        final_url: None,
    })
}

/// Byte offset just past the blank line ending a header block (`\r\n\r\n` or
/// `\n\n`), or `None` if absent.
fn block_end(s: &str) -> Option<usize> {
    match (s.find("\r\n\r\n"), s.find("\n\n")) {
        (Some(a), Some(b)) => Some(if a <= b { a + 4 } else { b + 2 }),
        (Some(a), None) => Some(a + 4),
        (None, Some(b)) => Some(b + 2),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_block_with_cookies() {
        let raw = "HTTP/2 200 \r\n\
                   content-type: application/json\r\n\
                   set-cookie: session=ABC; path=/; Domain=.example.com\r\n\
                   set-cookie: csrf=XYZ; path=/\r\n\
                   \r\n\
                   {\"token\":\"abc\"}";
        let r = parse_response(raw.as_bytes()).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.set_cookies.len(), 2);
        assert!(r.set_cookies[0].starts_with("session=ABC"));
        assert_eq!(r.body, "{\"token\":\"abc\"}");
        // Non-status headers are captured (content-type + the set-cookies).
        assert!(
            r.headers
                .iter()
                .any(|(k, v)| k == "content-type" && v == "application/json")
        );
    }

    #[test]
    fn skips_proxy_connect_preamble() {
        // curl can prepend the CONNECT tunnel response when proxying https.
        let raw = "HTTP/1.1 200 Connection established\r\n\r\n\
                   HTTP/2 403 \r\n\
                   set-cookie: a=b\r\n\
                   \r\n\
                   denied";
        let r = parse_response(raw.as_bytes()).unwrap();
        assert_eq!(r.status, 403); // final block wins, not the CONNECT 200
        assert_eq!(r.set_cookies, vec!["a=b".to_string()]);
        assert_eq!(r.body, "denied");
    }

    #[test]
    fn errors_when_no_status_block() {
        assert!(matches!(
            parse_response(b"garbage without http prefix"),
            Err(CurlError::NoStatus)
        ));
    }

    #[test]
    fn accumulates_set_cookies_across_redirect_chain() {
        // `-L` output: a 302 that Set-Cookies, then the final 200. Both cookies
        // must survive so the caller can thread them into the next manual hop.
        let raw = "HTTP/2 302 \r\n\
                   location: https://example.com/login\r\n\
                   set-cookie: session=SES; path=/\r\n\
                   \r\n\
                   HTTP/2 200 \r\n\
                   set-cookie: csrf=TOK; path=/\r\n\
                   \r\n\
                   <html>login form</html>";
        let r = parse_response(raw.as_bytes()).unwrap();
        assert_eq!(r.status, 200); // final block wins
        assert_eq!(r.body, "<html>login form</html>");
        assert!(r.set_cookies.iter().any(|c| c.starts_with("session=SES")));
        assert!(r.set_cookies.iter().any(|c| c.starts_with("csrf=TOK")));
    }

    #[test]
    fn follow_redirects_adds_dash_l_and_max_redirs() {
        // Off by default → no -L.
        let argv = build_argv(&Request::get("curl_chrome146", "https://example.com/auth"));
        assert!(
            !argv.iter().any(|a| a == "-L"),
            "no -L unless opted in: {argv:?}"
        );

        // Opt in → -L --max-redirs 10, and the URL still trails after `--`.
        let argv = build_argv(
            &Request::get("curl_chrome146", "https://example.com/auth").follow_redirects(true),
        );
        let l = argv.iter().position(|a| a == "-L").expect("expected -L");
        assert_eq!(argv[l + 1], "--max-redirs");
        assert_eq!(argv[l + 2], "10");
        assert_eq!(argv.last().unwrap(), "https://example.com/auth");
        assert_eq!(argv[argv.len() - 2], "--");

        // Custom budget honored.
        let argv = build_argv(
            &Request::get("curl_chrome146", "https://example.com")
                .follow_redirects(true)
                .max_redirs(3),
        );
        let l = argv.iter().position(|a| a == "-L").unwrap();
        assert_eq!(argv[l + 2], "3");
    }

    #[test]
    fn post_with_body_omits_dash_x_so_redirects_downgrade_to_get() {
        let argv = build_argv(
            &Request::post("curl_chrome146", "https://example.com/login")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(b"a=1".to_vec())
                .follow_redirects(true),
        );
        // `--data-binary @-` implies POST for the first request; NO `-X POST`, so
        // curl downgrades a 30x follow-up to GET (matches wreq/browser) instead of
        // re-POSTing the form body across the redirect.
        assert!(
            argv.windows(2)
                .any(|w| w[0] == "--data-binary" && w[1] == "@-")
        );
        assert!(
            !argv.iter().any(|a| a == "-X"),
            "a body POST must not force -X (would re-POST across -L redirects): {argv:?}"
        );
        assert_eq!(argv.last().unwrap(), "https://example.com/login");
    }

    #[test]
    fn bodyless_post_forces_dash_x_post() {
        let argv = build_argv(&Request::post("curl_chrome146", "https://example.com/ping"));
        // No body to imply the method, so POST is forced explicitly.
        assert!(argv.windows(2).any(|w| w[0] == "-X" && w[1] == "POST"));
        assert!(!argv.iter().any(|a| a == "--data-binary"));
    }
}
