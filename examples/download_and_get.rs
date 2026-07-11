//! Fetch a prebuilt curl-impersonate release at runtime, then make a request
//! with it — no manual install needed. Requires the `download` feature:
//!
//! ```sh
//! cargo run --example download_and_get --features download
//! ```
//!
//! Linux/macOS only (there is no prebuilt Windows CLI). The first run downloads
//! + extracts into a cache dir; subsequent runs reuse it.

use curl_impersonate_cli::{
    Request,
    download::{DownloadOptions, ensure_binary},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Ensure a `curl_chrome146` wrapper exists locally (download if missing).
    let bin = ensure_binary("chrome146", &DownloadOptions::default()).await?;
    println!("using wrapper: {}", bin.display());

    // Hit a TLS-fingerprint echo service to see the impersonated ClientHello.
    // `bin` is a PathBuf and flows straight in (Request::get takes any path-like).
    let resp = Request::get(bin, "https://tls.peet.ws/api/all")
        .send()
        .await?;

    println!("status = {}", resp.status);
    println!("{}", resp.body);
    Ok(())
}
