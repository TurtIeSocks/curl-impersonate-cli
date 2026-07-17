//! `curl-impersonate-mcp` — a stdio [Model Context Protocol] server exposing the
//! curl-impersonate request API as tools for LLM agents.
//!
//! Build/run it with the `mcp` feature:
//!
//! ```sh
//! cargo run --features mcp --bin curl-impersonate-mcp
//! ```
//!
//! It speaks MCP over stdio, so wire it into an agent as a local server, e.g.
//! for Claude Code:
//!
//! ```sh
//! claude mcp add curl-impersonate -- curl-impersonate-mcp
//! ```
//!
//! Two tools are exposed:
//!
//! * `curl_impersonate_fetch` — make a GET/POST request with a byte-exact
//!   browser TLS/HTTP2 fingerprint, overriding request-level inputs (headers,
//!   cookies, body, proxy) without disturbing that fingerprint. If the wrapper
//!   is missing it is downloaded + cached on first use.
//! * `curl_impersonate_ensure_browser` — download + cache a `curl_<browser>`
//!   wrapper and return its path, to reuse as the `bin` of later fetches.
//!
//! Logging goes to **stderr** only: a stdio MCP server must keep stdout clean
//! for the protocol.
//!
//! [Model Context Protocol]: https://modelcontextprotocol.io

use std::collections::HashMap;
use std::ffi::OsString;

use curl_impersonate_cli::{
    CurlError, Method, ProxySpec, Request, Response,
    download::{self, DownloadOptions},
};
use rmcp::{
    ErrorData as McpError, ServerHandler, ServiceExt,
    handler::server::wrapper::{Json, Parameters},
    model::{Implementation, ServerCapabilities, ServerInfo},
    schemars, tool, tool_handler, tool_router,
    transport::stdio,
};
use serde::{Deserialize, Serialize};

/// Default browser wrapper suffix when the caller doesn't pick one — a current
/// Chrome build shipped by every curl-impersonate release.
const DEFAULT_BROWSER: &str = "chrome146";

/// Default cap on the number of characters of the response body returned to the
/// agent. The full body is still downloaded (so status/cookies are correct);
/// only what is handed back is truncated, to protect the agent's context. The
/// result reports `body_truncated` and the full `body_char_len`.
const DEFAULT_MAX_BODY_CHARS: usize = 100_000;

const INSTRUCTIONS: &str = "\
Make HTTP requests with a byte-exact browser TLS/HTTP2 fingerprint via \
curl-impersonate. Use `curl_impersonate_fetch` for GET/POST. Header overrides \
follow curl's `-H` rules: setting a header REPLACES the impersonation default of \
that name; listing it in `remove_headers` DROPS one — that pair turns the \
wrapper's default navigation headers into a fetch()/CORS set without changing \
the fingerprint. A non-2xx status is returned normally (not an error); only \
transport/spawn failures error. The `curl_<browser>` wrapper is downloaded and \
cached automatically on first use; call `curl_impersonate_ensure_browser` to \
pre-warm it or pin a version.";

#[derive(Clone)]
struct CurlImpersonateServer;

/// Input for `curl_impersonate_fetch`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct FetchParams {
    /// Absolute request URL, e.g. `https://example.com/api`.
    url: String,
    /// Browser to impersonate, as the wrapper suffix (`chrome146`, `firefox144`,
    /// `safari180`, …). Selects the `curl_<browser>` wrapper. Defaults to
    /// `chrome146`. Ignored when `bin` is set.
    #[serde(default)]
    browser: Option<String>,
    /// Explicit wrapper to run: an absolute/relative path (e.g. one returned by
    /// `curl_impersonate_ensure_browser`) or a command name on `PATH`. Overrides
    /// `browser`. Auto-download only applies when this is unset.
    #[serde(default)]
    bin: Option<String>,
    /// HTTP method: `GET` (default) or `POST`. Providing `body` with no method
    /// implies `POST`.
    #[serde(default)]
    method: Option<String>,
    /// Headers to add/override, as a name→value map. Each REPLACES the
    /// impersonation's default header of that name (case-insensitive).
    #[serde(default)]
    headers: Option<HashMap<String, String>>,
    /// Header names to REMOVE from what the wrapper would otherwise send (curl
    /// `-H 'Name:'`). Use to strip navigation-only headers for a fetch() request.
    #[serde(default)]
    remove_headers: Option<Vec<String>>,
    /// Request cookies, as a name→value map, sent as a single `Cookie` header.
    #[serde(default)]
    cookies: Option<HashMap<String, String>>,
    /// Request body (UTF-8), sent on `POST`. Set an appropriate `Content-Type`
    /// header yourself.
    #[serde(default)]
    body: Option<String>,
    /// Proxy URL `scheme://[user:pass@]host:port`. Credentials must be
    /// percent-encoded; they are passed to curl via the environment, never argv.
    #[serde(default)]
    proxy_url: Option<String>,
    /// Overall timeout in seconds (curl `--max-time`). Defaults to 30.
    #[serde(default)]
    timeout_secs: Option<f64>,
    /// Skip TLS certificate verification (curl `-k`). Defaults to false.
    #[serde(default)]
    insecure: Option<bool>,
    /// Follow 3xx redirects (curl `-L`). Off by default; a POST that hits a
    /// 301/302/303 downgrades to a bodyless GET, like a browser.
    #[serde(default)]
    follow_redirects: Option<bool>,
    /// Max redirects to follow when `follow_redirects` is on. Defaults to 10.
    #[serde(default)]
    max_redirs: Option<u32>,
    /// Abort if the response exceeds this many bytes (curl `--max-filesize`).
    /// Defaults to 16 MiB. This bounds the download; `max_body_chars` bounds only
    /// what is returned.
    #[serde(default)]
    max_filesize: Option<u64>,
    /// Truncate the returned `body` to this many characters (default 100000). The
    /// full body is still fetched; `body_truncated`/`body_char_len` report the cut.
    #[serde(default)]
    max_body_chars: Option<usize>,
}

/// A single response header.
#[derive(Debug, Serialize, schemars::JsonSchema)]
struct HeaderKV {
    name: String,
    value: String,
}

/// Output of `curl_impersonate_fetch`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
struct FetchResult {
    /// HTTP status code of the final response.
    status: u16,
    /// Raw `Set-Cookie` header lines, accumulated across the redirect/CONNECT
    /// chain so a mid-chain session cookie survives for the next request.
    set_cookies: Vec<String>,
    /// Headers on the final response block.
    headers: Vec<HeaderKV>,
    /// Response body (curl-decompressed), possibly truncated — see
    /// `body_truncated`.
    body: String,
    /// True if `body` was cut to `max_body_chars`.
    body_truncated: bool,
    /// Full body length in characters, before truncation.
    body_char_len: usize,
    /// Effective URL after any followed redirects (`%{url_effective}`).
    final_url: Option<String>,
    /// The wrapper actually invoked (useful when it was auto-downloaded — reuse
    /// this path as `bin` to skip the lookup next time).
    used_bin: String,
}

/// Input for `curl_impersonate_ensure_browser`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct EnsureParams {
    /// Browser wrapper suffix to ensure (`chrome146`, `firefox144`, …). Defaults
    /// to `chrome146`.
    #[serde(default)]
    browser: Option<String>,
    /// curl-impersonate release tag to fetch, e.g. `v1.5.6`. Defaults to the
    /// version pinned by this crate.
    #[serde(default)]
    version: Option<String>,
}

/// Output of `curl_impersonate_ensure_browser`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
struct EnsureResult {
    /// Browser wrapper suffix that was ensured.
    browser: String,
    /// Absolute path to the ready `curl_<browser>` wrapper. Pass as `bin` to
    /// `curl_impersonate_fetch`.
    bin_path: String,
}

#[tool_router]
impl CurlImpersonateServer {
    #[tool(
        name = "curl_impersonate_fetch",
        description = "Make an HTTP GET/POST request with a byte-exact browser TLS/HTTP2 \
                       fingerprint (curl-impersonate). Override headers, cookies, body, and \
                       proxy without disturbing the fingerprint. A non-2xx status is returned \
                       normally; only transport/spawn failures error. The wrapper is \
                       downloaded and cached on first use if missing.",
        annotations(
            read_only_hint = false,
            open_world_hint = true,
            idempotent_hint = false
        )
    )]
    async fn fetch(
        &self,
        Parameters(params): Parameters<FetchParams>,
    ) -> Result<Json<FetchResult>, McpError> {
        let browser = params
            .browser
            .clone()
            .unwrap_or_else(|| DEFAULT_BROWSER.to_string());
        let explicit_bin = params.bin.is_some();
        let mut bin: OsString = match &params.bin {
            Some(b) => b.into(),
            None => format!("curl_{browser}").into(),
        };

        let method = resolve_method(params.method.as_deref(), params.body.is_some())?;

        let resp = match send_once(&bin, &params, method).await {
            Ok(resp) => resp,
            // Derived-wrapper not on PATH → download it once, then retry.
            Err(CurlError::Spawn { source, .. })
                if !explicit_bin && source.kind() == std::io::ErrorKind::NotFound =>
            {
                let path = download::ensure_binary(&browser, &DownloadOptions::default())
                    .await
                    .map_err(|e| {
                        McpError::internal_error(
                            format!(
                                "wrapper `curl_{browser}` is not on PATH and auto-download \
                                 failed: {e}"
                            ),
                            None,
                        )
                    })?;
                bin = path.into_os_string();
                send_once(&bin, &params, method).await.map_err(to_mcp_err)?
            }
            Err(e) => return Err(to_mcp_err(e)),
        };

        Ok(Json(build_result(resp, &params, bin)))
    }

    #[tool(
        name = "curl_impersonate_ensure_browser",
        description = "Download and cache a `curl_<browser>` curl-impersonate wrapper for this \
                       platform and return its absolute path. Idempotent; hits the network only \
                       on a cache miss. Use to pre-warm a wrapper or pin a release version.",
        annotations(read_only_hint = false, open_world_hint = true, idempotent_hint = true)
    )]
    async fn ensure_browser(
        &self,
        Parameters(params): Parameters<EnsureParams>,
    ) -> Result<Json<EnsureResult>, McpError> {
        let browser = params.browser.as_deref().unwrap_or(DEFAULT_BROWSER);
        let opts = DownloadOptions {
            version: params.version.clone(),
            ..Default::default()
        };
        let path = download::ensure_binary(browser, &opts)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(Json(EnsureResult {
            browser: browser.to_string(),
            bin_path: path.to_string_lossy().into_owned(),
        }))
    }
}

#[tool_handler]
impl ServerHandler for CurlImpersonateServer {
    fn get_info(&self) -> ServerInfo {
        // `ServerInfo` is `#[non_exhaustive]`, so it can't be built with a struct
        // literal from here — start from its default and set the fields we care
        // about.
        #[allow(clippy::field_reassign_with_default)]
        let mut info = ServerInfo::default();
        // `Implementation::from_build_env()` bakes in rmcp's own package
        // name/version (its `env!` expands inside the rmcp crate), so override
        // with this binary's identity.
        let mut server_info = Implementation::from_build_env();
        server_info.name = env!("CARGO_PKG_NAME").to_string();
        server_info.version = env!("CARGO_PKG_VERSION").to_string();
        info.server_info = server_info;
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info.instructions = Some(INSTRUCTIONS.to_string());
        info
    }
}

/// Resolve the request method from the caller's string + whether a body is set.
/// A body implies POST; an explicit `GET` with a body is a contradiction (curl
/// would silently drop the body), so it is rejected.
fn resolve_method(method: Option<&str>, has_body: bool) -> Result<Method, McpError> {
    match method.map(|m| m.trim().to_ascii_uppercase()).as_deref() {
        None | Some("") => Ok(if has_body { Method::Post } else { Method::Get }),
        Some("GET") if has_body => Err(McpError::invalid_params(
            "a request body requires method POST; GET cannot carry a body".to_string(),
            None,
        )),
        Some("GET") => Ok(Method::Get),
        Some("POST") => Ok(Method::Post),
        Some(other) => Err(McpError::invalid_params(
            format!("unsupported method {other:?}; use \"GET\" or \"POST\""),
            None,
        )),
    }
}

/// Build and send one request for the given wrapper. Split out so the caller can
/// retry with a downloaded wrapper on a PATH miss.
async fn send_once(
    bin: &OsString,
    params: &FetchParams,
    method: Method,
) -> Result<Response, CurlError> {
    let mut req = Request::new(bin.clone(), method, params.url.clone());

    if let Some(headers) = &params.headers {
        req = req.headers(headers.iter().map(|(k, v)| (k.clone(), v.clone())));
    }
    if let Some(names) = &params.remove_headers {
        for name in names {
            req = req.remove_header(name.clone());
        }
    }
    if let Some(cookies) = &params.cookies {
        req = req.cookies(
            cookies
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        );
    }
    if method == Method::Post {
        if let Some(body) = &params.body {
            req = req.body(body.clone().into_bytes());
        }
    }
    if let Some(url) = &params.proxy_url {
        req = req.proxy(Some(ProxySpec { url: url.clone() }));
    }
    if let Some(secs) = params.timeout_secs {
        req = req.timeout_secs(secs);
    }
    if let Some(insecure) = params.insecure {
        req = req.insecure(insecure);
    }
    if let Some(follow) = params.follow_redirects {
        req = req.follow_redirects(follow);
    }
    if let Some(n) = params.max_redirs {
        req = req.max_redirs(n);
    }
    if let Some(max) = params.max_filesize {
        req = req.max_filesize(Some(max));
    }

    req.send().await
}

/// Map a request outcome into the tool's structured result, truncating the body
/// to `max_body_chars` for the agent's context.
fn build_result(resp: Response, params: &FetchParams, bin: OsString) -> FetchResult {
    let max = params.max_body_chars.unwrap_or(DEFAULT_MAX_BODY_CHARS);
    let body_char_len = resp.body.chars().count();
    let body_truncated = body_char_len > max;
    let body = if body_truncated {
        resp.body.chars().take(max).collect()
    } else {
        resp.body
    };

    FetchResult {
        status: resp.status,
        set_cookies: resp.set_cookies,
        headers: resp
            .headers
            .into_iter()
            .map(|(name, value)| HeaderKV { name, value })
            .collect(),
        body,
        body_truncated,
        body_char_len,
        final_url: resp.final_url,
        used_bin: bin.to_string_lossy().into_owned(),
    }
}

/// Turn a [`CurlError`] into an agent-facing MCP error with a next step where one
/// exists (notably: how to get the wrapper when spawning it failed).
fn to_mcp_err(err: CurlError) -> McpError {
    match err {
        CurlError::Spawn { bin, source } => McpError::internal_error(
            format!(
                "failed to spawn `{bin}`: {source}. Install curl-impersonate so `{bin}` is on \
                 PATH, or call curl_impersonate_ensure_browser to download it and pass the \
                 returned path as `bin`."
            ),
            None,
        ),
        other => McpError::internal_error(other.to_string(), None),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let service = CurlImpersonateServer.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_defaults_get_body_implies_post() {
        assert_eq!(resolve_method(None, false).unwrap(), Method::Get);
        assert_eq!(resolve_method(None, true).unwrap(), Method::Post);
        assert_eq!(resolve_method(Some("post"), false).unwrap(), Method::Post);
        assert_eq!(resolve_method(Some(" GET "), false).unwrap(), Method::Get);
    }

    #[test]
    fn method_rejects_get_with_body_and_unknown_verbs() {
        assert!(resolve_method(Some("GET"), true).is_err());
        assert!(resolve_method(Some("DELETE"), false).is_err());
    }

    #[test]
    fn build_result_truncates_body_and_reports_length() {
        // `Response` is `#[non_exhaustive]`; build it from its default.
        #[allow(clippy::field_reassign_with_default)]
        let mut resp = Response::default();
        resp.status = 200;
        resp.body = "abcdef".to_string();
        resp.headers = vec![("content-type".to_string(), "text/plain".to_string())];
        let params = FetchParams {
            url: "https://example.com".to_string(),
            browser: None,
            bin: None,
            method: None,
            headers: None,
            remove_headers: None,
            cookies: None,
            body: None,
            proxy_url: None,
            timeout_secs: None,
            insecure: None,
            follow_redirects: None,
            max_redirs: None,
            max_filesize: None,
            max_body_chars: Some(3),
        };
        let out = build_result(resp, &params, OsString::from("curl_chrome146"));
        assert_eq!(out.body, "abc");
        assert!(out.body_truncated);
        assert_eq!(out.body_char_len, 6);
        assert_eq!(out.headers.len(), 1);
        assert_eq!(out.used_bin, "curl_chrome146");
    }
}
