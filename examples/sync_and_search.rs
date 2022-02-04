use nvd_cve::cache::{search_by_id, search_description, sync_blocking, CacheConfig};

use nvd_cve::client::{BlockingHttpClient, ReqwestBlockingClient};

pub fn main() {
    let mut config = CacheConfig::new();

    config.feeds = vec!["2019".to_string()];

    let client = ReqwestBlockingClient::new(&config.url, None, None, None);

    if let Err(error) = sync_blocking(&config, client) {
        eprintln!("Fatal Error while syncing feeds: {:?}", error);
        std::process::exit(1);
    }

    // 2019 had some wild CVEs...
    if let Ok(cves) = search_description(
        &config,
        "unintended temperature in the victim's mouth and throat",
    ) {
        println!("\n\nFound {} matching CVE(s): ", cves.len());
        for cve in cves {
            let cve_result = search_by_id(&config, &cve).unwrap();
            println!(
                "{}: {}",
                cve, &cve_result.description.description_data[0].value
            );
        }
    }
}
