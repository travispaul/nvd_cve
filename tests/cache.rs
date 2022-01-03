use nvd_cve::cache::{search_by_id, CacheConfig, SqliteCache};
use nvd_cve::feed::Metafile;
use std::fs::{self, File};
mod util;
use nvd_cve::cache::sync_blocking;
use nvd_cve::cve::CveFeed;
use std::env;
use util::MockBlockingClient;

#[test]
fn test_sync_config_defaults() {
    env::set_var("XDG_CACHE_HOME", "./tests/files/.cache");
    let config = CacheConfig::default();
    assert_eq!(config.db, "./tests/files/.cache/nvd/nvd.sqlite3");

    env::remove_var("XDG_CACHE_HOME");
    env::set_var("HOME", "./tests/files");
    let config = CacheConfig::default();
    assert_eq!(config.db, "./tests/files/.cache/nvd/nvd.sqlite3");
}

#[test]
fn test_creating_schema_for_new_cache_insert_metafile() {
    // Set location of test cache DB:
    let mut config = CacheConfig::default();
    config.db = "./tests/files/.cache/nvd/nvd.sqlite3".to_string();

    // Remove any existing DB
    fs::remove_file(&config.db).ok();

    // create an SqliteCache and initialize the schema
    let cache = SqliteCache::new(&config.db);
    if let Err(e) = cache.create_schema() {
        assert!(false, "{:?}", e);
    }

    // Confirm file exists
    match File::open(&config.db) {
        Ok(f) => drop(f),
        Err(e) => assert!(false, "{:?}", e),
    }

    config.feeds = vec![String::from("recent")];

    // Attach any existing metafiles to feed list
    let feeds = cache
        .get_metafiles(&config.feeds)
        .expect("get_metafiles failed");

    if let Some(mf) = &feeds[0].metafile {
        assert!(
            false,
            "Metafile {:?} shouldn't exit exist on feed {:?}",
            mf, feeds[0]
        );
    }

    let mut client = MockBlockingClient::default();

    let body = fs::read_to_string("./tests/files/nvdcve-1.1-recent.meta")
        .expect("Failed reading metafile");

    client.get_metafile_response = Ok(body);

    let metafile =
        Metafile::from_blocking_http_client(&client, "recent").expect("Failed to parse metafile");

    cache
        .set_metafile(&feeds[0].name, &metafile)
        .expect("Failed to insert metafile");

    println!("Metafile: {:?}", metafile);

    // Fetch feeds again
    let feeds = cache
        .get_metafiles(&config.feeds)
        .expect("get_metafiles failed");

    if let None = &feeds[0].metafile {
        assert!(
            false,
            "Metafile {:?} should exist on feed {:?}",
            metafile, feeds[0]
        );
    }

    // Cleanup
    if let Err(e) = fs::remove_file(&config.db) {
        assert!(false, "{:?}", e);
    }
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
