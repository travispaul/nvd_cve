use clap::ArgMatches;
use nvd_cve::cache::{search_by_id, search_description, sync_blocking, CacheConfig};
use nvd_cve::client::ReqwestBlockingClient;
use nvd_cve::feed::Feed;

pub fn sync(matches: &ArgMatches) {
    let mut config = CacheConfig::new();

    if matches.is_present("show") {
        println!("Default Config Values:\n{}", config);
        return;
    }

    if let Some(raw) = matches.value_of("feeds") {
        let mut parsed = Vec::new();
        for token in raw.split(',') {
            match Feed::parse(token.trim()) {
                Ok(mut feeds) => parsed.append(&mut feeds),
                Err(err) => {
                    eprintln!("Invalid --feeds token `{token}`: {err}");
                    std::process::exit(2);
                }
            }
        }
        config.feeds = parsed;
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

    let api_key = matches
        .value_of("api_key")
        .map(str::to_string)
        .or_else(|| std::env::var("NVD_API_KEY").ok());

    let client = match ReqwestBlockingClient::new(api_key) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("Failed to build HTTP client: {err}");
            std::process::exit(1);
        }
    };

    if let Err(error) = sync_blocking(&config, &client) {
        eprintln!("Fatal Error: {error}");
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
                if cves.is_empty() {
                    eprintln!("No results found");
                    std::process::exit(1);
                } else {
                    for cve in cves {
                        println!("{cve}");
                    }
                }
            }
            Err(error) => {
                eprintln!("Fatal Error: {error}");
                std::process::exit(2);
            }
        }
    } else if let Some(cve) = matches.value_of("CVE") {
        match search_by_id(&config, cve) {
            Ok(cve_result) => println!("{}", serde_json::to_string_pretty(&cve_result).unwrap()),
            Err(error) => {
                eprintln!("Fatal Error: {error}");
                std::process::exit(3);
            }
        }
    }
}
