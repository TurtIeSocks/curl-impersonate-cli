//! POST example (form-encoded body).
//!
//! Requires a `curl_chrome146` wrapper binary on your `PATH` (from a
//! curl-impersonate install; see the README "Requirements" section).
//!
//! Run with:
//!
//! ```sh
//! cargo run --example post
//! ```

use curl_impersonate_cli::Request;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let body = b"user=comrade&note=solidarity".to_vec();

    let resp = Request::post("curl_chrome146", "https://httpbin.org/post")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        // Follow the 30x a login/redirect flow returns; on a POST->30x, curl
        // (like a browser) re-issues the follow-up as a bodyless GET.
        .follow_redirects(true)
        .send()
        .await?;

    println!("status: {}", resp.status);
    println!("body:\n{}", resp.body);

    Ok(())
}
