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
