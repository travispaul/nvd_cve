use clap::ArgMatches;
use nvd_cve::cache::{search_by_id, CacheConfig};
use nvd_cve::cache::{search_description, sync_blocking};
use nvd_cve::client::{BlockingHttpClient, ReqwestBlockingClient};

pub fn sync(matches: &ArgMatches) {
    let mut config = CacheConfig::new();

    if matches.is_present("show") {
        println!("Default Config Values:\n{}", config);
        return;
    }

    if let Some(url) = matches.value_of("url") {
        config.url = String::from(url);
    }

    if let Some(feeds) = matches.value_of("feeds") {
        config.feeds = feeds.split(',').map(|feed| feed.to_string()).collect();
    }

    if let Some(db) = matches.value_of("db") {
        config.db = String::from(db);
    }

    if matches.is_present("no_progress") {
        config.show_progress = false;
    }

    if matches.is_present("force") {
        config.force_update = true;
    }

    if matches.is_present("verbose") {
        env_logger::init();
    }

    let client = ReqwestBlockingClient::new(&config.url, None, None, None);

    if let Err(error) = sync_blocking(&config, client) {
        eprintln!("Fatal Error: {:?}", error);
        std::process::exit(1);
    }
}

pub fn search(matches: &ArgMatches) {
    let mut config = CacheConfig::new();

    if let Some(db) = matches.value_of("db") {
        config.db = String::from(db);
    }

    if let Some(text) = matches.value_of("text") {
        match search_description(&config, text) {
            Ok(cves) => {
                if cves.len() == 0 {
                    eprintln!("No results found");
                    std::process::exit(1);
                } else {
                    for cve in cves {
                        println!("{}", cve);
                    }
                }
            }
            Err(error) => {
                eprintln!("Fatal Error: {:?}", error);
                std::process::exit(2);
            }
        }
    } else if let Some(cve) = matches.value_of("CVE") {
        match search_by_id(&config, cve) {
            Ok(cve_result) => println!("{}", serde_json::to_string_pretty(&cve_result).unwrap()),
            Err(error) => {
                eprintln!("Fatal Error: {:?}", error);
                std::process::exit(3);
            }
        }
    }
}
