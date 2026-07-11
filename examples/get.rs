//! GET example.
//!
//! Requires a `curl_chrome146` wrapper binary on your `PATH` (from a
//! curl-impersonate install; see the README "Requirements" section).
//!
//! Run with:
//!
//! ```sh
//! cargo run --example get
//! ```

use curl_impersonate_cli::Request;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let resp = Request::get("curl_chrome146", "https://example.com/")
        .header("Accept", "text/html")
        .timeout_secs(20.0)
        .send()
        .await?;

    println!("status: {}", resp.status);
    if let Some(url) = &resp.final_url {
        println!("final url: {url}");
    }
    for cookie in &resp.set_cookies {
        println!("set-cookie: {cookie}");
    }
    println!("\nbody ({} bytes):\n{}", resp.body.len(), resp.body);

    Ok(())
}
