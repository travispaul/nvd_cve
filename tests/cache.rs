use nvd_cve::cache::{search_by_id, CacheConfig};
use std::fs;
mod util;
use home::home_dir;
use nvd_cve::cache::sync_blocking;
use nvd_cve::cve::CveFeed;
use std::env;
use std::path::PathBuf;
use util::MockBlockingClient;

#[test]
fn test_sync_config_defaults() {
    env::set_var("XDG_CACHE_HOME", "./tests/files/.cache");
    let config = CacheConfig::default();
    let mut db_path = PathBuf::from("./tests/files/.cache");
    db_path.push("nvd");
    db_path.push("nvd.sqlite3");
    assert_eq!(config.db.as_str(), db_path.to_str().unwrap());

    env::remove_var("XDG_CACHE_HOME");
    env::set_var("HOME", "./tests/files");
    let config = CacheConfig::default();
    let mut db_path = home_dir().unwrap();
    db_path.push(".cache");
    db_path.push("nvd");
    db_path.push("nvd.sqlite3");
    assert_eq!(config.db.as_str(), db_path.to_str().unwrap());
}

#[test]
fn test_sync_blocking() {
    // Set location of test cache DB:
    let mut config = CacheConfig::default();
    config.db = "./tests/files/.cache/nvd/nvd2.sqlite3".to_string();
    config.url = "http://nowhere.nope".to_string();

    // Remove any existing DB
    fs::remove_file(&config.db).ok();

    config.feeds = vec![String::from("recent")];

    let mut client = MockBlockingClient::default();

    let metafile = fs::read_to_string("./tests/files/nvdcve-1.1-recent.meta")
        .expect("Failed reading metafile");

    client.get_metafile_response = Ok(metafile);

    let body = fs::read_to_string("./tests/files/nvdcve-1.1-recent.json")
        .expect("Failed reading feed json");

    let cve_feed: CveFeed = serde_json::from_str(&*body).expect("Failed parsing cve feed json");
    client.get_feed_response = Ok(cve_feed);

    sync_blocking(&config, client).expect("Failed to sync to local cache");

    if let Err(error) = search_by_id(&config, "CVE-2021-43437") {
        assert!(false, "failed to find CVE: {:?}", error);
    }

    // Cleanup
    if let Err(e) = fs::remove_file(&config.db) {
        assert!(false, "{:?}", e);
    }
}
