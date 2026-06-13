//! Minimal end-to-end example: sync one year of CVEs from NVD, then run a
//! description search against the local cache.
//!
//! Run with an NVD API key for a much faster sync:
//!
//! ```sh
//! NVD_API_KEY=… cargo run --example sync_and_search
//! ```

use nvd_cve::cache::{search_by_id, search_description, sync_blocking, CacheConfig};
use nvd_cve::client::ReqwestBlockingClient;
use nvd_cve::feed::Feed;

fn main() {
    let mut config = CacheConfig::new();
    config.feeds = Feed::parse("2019").expect("year token parses");

    let api_key = std::env::var("NVD_API_KEY").ok();
    let client = match ReqwestBlockingClient::new(api_key) {
        Ok(c) => c,
        Err(error) => {
            eprintln!("Failed to build HTTP client: {error}");
            std::process::exit(1);
        }
    };

    if let Err(error) = sync_blocking(&config, &client) {
        eprintln!("Fatal Error while syncing feeds: {error}");
        std::process::exit(1);
    }

    // 2019 had some wild CVEs…
    if let Ok(cves) = search_description(
        &config,
        "unintended temperature in the victim's mouth and throat",
    ) {
        println!("\n\nFound {} matching CVE(s): ", cves.len());
        for cve in cves {
            let cve_result = search_by_id(&config, &cve).expect("cached id resolves");
            println!(
                "{}: {}",
                cve,
                cve_result
                    .description_en()
                    .unwrap_or("(no English description)")
            );
        }
    }
}
