//! Local SQLite cache of NVD CVE records, with sync orchestration on top of
//! the NVD 2.0 REST API.
//!
//! Schema:
//!
//! - `cve(id PK, description, data)` — one row per CVE, `data` is the full
//!   `Cve` struct serialized as JSON. Carried over verbatim from the legacy
//!   1.1 schema so the search and lookup code does not change.
//! - `sync_state(feed PK, last_modified_date, total_records)` — per-feed
//!   bookkeeping; replaces the 1.1 `metafile` table.
//! - `migration(schema_version PK, app_version, status)` — schema versioning;
//!   on open, an old 1.1 schema (detected by the `metafile` table) is dropped
//!   and recreated, since the data shape is incompatible.

use crate::client::{BlockingHttpClient, HttpError, MAX_PAGE_SIZE};
use crate::cve::{Cve, Vulnerability};
use crate::feed::{format_nvd, parse_nvd, Feed, FeedError};
use chrono::{NaiveDateTime, Utc};
use log::{debug, info, warn};
use progress::Bar;
use rusqlite::{params, Connection, Transaction, TransactionBehavior};
use std::fmt;
use std::path::PathBuf;
use std::{env, fs, io};

/// Current schema marker. Bumped when the table layout or data format
/// changes incompatibly with prior caches.
pub const SCHEMA_VERSION: &str = "2.0.0";

/// Sentinel for old 1.1 caches that must be wiped before reuse.
const LEGACY_TABLE: &str = "metafile";

/// Configuration for [`sync_blocking`] and the lookup helpers in this module.
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Feeds to sync. Use [`Feed::parse`] to build this list from CLI tokens.
    pub feeds: Vec<Feed>,
    /// Path to the SQLite database file.
    pub db: String,
    /// Print a progress bar to stdout while syncing.
    pub show_progress: bool,
    /// Re-fetch feeds even when the cache already has a recent
    /// `sync_state` entry for them.
    pub force_update: bool,
}

impl CacheConfig {
    /// XDG-compliant default location for the cache file
    /// (`$XDG_CACHE_HOME/nvd/nvd.sqlite3`, falling back to `~/.cache/...`).
    pub fn default_db_path() -> String {
        let mut path = PathBuf::new();
        let cache_namespace = "nvd";
        let db_name = "nvd.sqlite3";

        if let Ok(xdg_cache_home) = env::var("XDG_CACHE_HOME") {
            path.push(xdg_cache_home);
        } else if let Some(home_dir) = home::home_dir() {
            path.push(home_dir);
            path.push(".cache");
        } else {
            path.push(env::temp_dir());
        }
        path.push(cache_namespace);
        path.push(db_name);

        if let Some(string_path) = path.to_str() {
            return string_path.to_string();
        }

        let mut fallback = PathBuf::from(cache_namespace);
        fallback.push(db_name);
        fallback.to_str().unwrap().to_string()
    }

    /// Sensible defaults: years 2002–current, plus `recent` and `modified`.
    pub fn new() -> Self {
        let current_year = Utc::now().date_naive().format("%Y").to_string();
        let range = format!("2002:{current_year}");
        let mut feeds = Feed::parse(&range).expect("static range parses");
        feeds.extend(Feed::parse("recent").expect("static token"));
        feeds.extend(Feed::parse("modified").expect("static token"));
        Self {
            feeds,
            db: Self::default_db_path(),
            show_progress: true,
            force_update: false,
        }
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for CacheConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<&str> = self.feeds.iter().map(|f| f.name.as_str()).collect();
        write!(
            f,
            "Feeds: {}\nDB Path: {}\nProgress: {}\nForce update: {}\n",
            names.join(","),
            self.db,
            self.show_progress,
            self.force_update,
        )
    }
}

#[derive(Debug)]
pub enum CacheError {
    Rusqlite(rusqlite::Error),
    Io(io::Error),
    Http(HttpError),
    Json(serde_json::Error),
    Feed(FeedError),
}

impl fmt::Display for CacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CacheError::Rusqlite(e) => write!(f, "sqlite error: {e}"),
            CacheError::Io(e) => write!(f, "I/O error: {e}"),
            CacheError::Http(e) => write!(f, "NVD HTTP error: {e}"),
            CacheError::Json(e) => write!(f, "JSON error: {e}"),
            CacheError::Feed(e) => write!(f, "feed error: {e}"),
        }
    }
}

impl std::error::Error for CacheError {}

impl From<io::Error> for CacheError {
    fn from(e: io::Error) -> Self {
        CacheError::Io(e)
    }
}
impl From<rusqlite::Error> for CacheError {
    fn from(e: rusqlite::Error) -> Self {
        CacheError::Rusqlite(e)
    }
}
impl From<HttpError> for CacheError {
    fn from(e: HttpError) -> Self {
        CacheError::Http(e)
    }
}
impl From<serde_json::Error> for CacheError {
    fn from(e: serde_json::Error) -> Self {
        CacheError::Json(e)
    }
}
impl From<FeedError> for CacheError {
    fn from(e: FeedError) -> Self {
        CacheError::Feed(e)
    }
}

/// Create / reset the cache schema, returning an open connection. If the
/// database already exists with a 1.1 layout (`metafile` table present),
/// drop everything and rebuild: the 2.0 record shape is not compatible
/// with the 1.1 serialized blobs.
fn open_schema(path: &str) -> Result<Connection, CacheError> {
    let mut db_path = PathBuf::from(path);
    db_path.pop();
    if !db_path.as_os_str().is_empty() {
        fs::create_dir_all(&db_path)?;
    }

    let conn = Connection::open(path)?;

    // Detect legacy schema (1.1 had a `metafile` table). Drop and recreate.
    let legacy_exists: bool = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
            [LEGACY_TABLE],
            |row| row.get::<_, i64>(0),
        )
        .map(|v| v == 1)
        .unwrap_or(false);
    if legacy_exists {
        warn!("legacy 1.1 cache schema detected — recreating");
        for table in ["cve", "metafile", "migration", "sync_state"] {
            let stmt = format!("DROP TABLE IF EXISTS {table}");
            conn.execute(&stmt, [])?;
        }
    }

    conn.execute(
        "CREATE TABLE IF NOT EXISTS cve (
            id          VARCHAR PRIMARY KEY,
            description TEXT,
            data        TEXT NOT NULL
         )",
        [],
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS sync_state (
            feed               VARCHAR PRIMARY KEY,
            last_modified_date VARCHAR NOT NULL,
            total_records      INTEGER NOT NULL
         )",
        [],
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS migration (
            schema_version VARCHAR PRIMARY KEY,
            app_version    VARCHAR NOT NULL,
            status         INTEGER NOT NULL
         )",
        [],
    )?;
    conn.execute(
        "INSERT OR REPLACE INTO migration (schema_version, app_version, status)
         VALUES (?1, ?2, 1)",
        [
            SCHEMA_VERSION,
            option_env!("CARGO_PKG_VERSION").unwrap_or("?.?.?"),
        ],
    )?;

    Ok(conn)
}

/// Read the last-sync timestamp recorded for a feed, if any.
fn get_sync_state(conn: &Connection, feed: &str) -> Option<NaiveDateTime> {
    conn.query_row(
        "SELECT last_modified_date FROM sync_state WHERE feed=?1",
        [feed],
        |row| row.get::<_, String>(0),
    )
    .ok()
    .and_then(|raw| parse_nvd(&raw))
}

fn upsert_sync_state(
    conn: &Connection,
    feed: &str,
    last_modified: NaiveDateTime,
    total: u32,
) -> Result<(), CacheError> {
    conn.execute(
        "INSERT INTO sync_state (feed, last_modified_date, total_records)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(feed) DO UPDATE
            SET last_modified_date = excluded.last_modified_date,
                total_records      = excluded.total_records",
        params![feed, format_nvd(last_modified), total],
    )?;
    Ok(())
}

/// Insert/update one page worth of vulnerabilities atomically.
fn upsert_vulnerabilities(conn: &Connection, vulns: &[Vulnerability]) -> Result<(), CacheError> {
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)?;
    {
        let mut stmt = tx.prepare(
            "INSERT INTO cve (id, description, data)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE
                SET description = excluded.description,
                    data        = excluded.data",
        )?;
        for v in vulns {
            let description = v.cve.description_en().map(str::to_string);
            let blob = serde_json::to_string(&v.cve)?;
            stmt.execute(params![v.cve.id, description, blob])?;
        }
    }
    tx.commit()?;
    Ok(())
}

/// Sync every configured feed into the local cache.
///
/// For each feed: builds one or more date-range queries (see
/// [`Feed::to_queries`]), paginates through NVD, and upserts each page in
/// its own SQLite transaction. The progress bar (when enabled) shows
/// per-feed status; the granularity is coarse on purpose — fine-grained
/// per-page updates would create more redraw flicker than they help.
pub fn sync_blocking<C: BlockingHttpClient>(
    config: &CacheConfig,
    client: &C,
) -> Result<(), CacheError> {
    let conn = open_schema(&config.db)?;
    let now = Utc::now();
    let mut bar = Bar::new();
    if config.show_progress {
        bar.set_job_title("Syncing CVE Data");
    }

    let total_feeds = config.feeds.len().max(1);
    for (idx, feed) in config.feeds.iter().enumerate() {
        if !config.force_update && get_sync_state(&conn, &feed.name).is_some() {
            debug!(
                "feed `{}` already synced — skipping (use --force-update to refetch)",
                feed.name
            );
            if config.show_progress {
                let pct = ((idx + 1) as f32 / total_feeds as f32 * 100.0).round() as i32;
                bar.set_job_title(&format!("[{}] cached", feed.name));
                bar.reach_percent(pct);
            }
            continue;
        }

        let queries = feed.to_queries(now);
        let mut feed_total: u32 = 0;
        for (slice_idx, query) in queries.iter().enumerate() {
            let mut start_index: u32 = 0;
            loop {
                if config.show_progress {
                    bar.set_job_title(&format!(
                        "[{}] slice {}/{} offset {}",
                        feed.name,
                        slice_idx + 1,
                        queries.len(),
                        start_index
                    ));
                }
                let page = client.fetch_page(query, start_index, MAX_PAGE_SIZE)?;
                if page.vulnerabilities.is_empty() && start_index == 0 {
                    debug!("[{}] slice {} returned 0 results", feed.name, slice_idx + 1);
                    break;
                }
                let received = page.vulnerabilities.len() as u32;
                upsert_vulnerabilities(&conn, &page.vulnerabilities)?;
                feed_total = feed_total.max(page.total_results);
                start_index += received;
                if start_index >= page.total_results {
                    break;
                }
                if received == 0 {
                    // Defensive: NVD reported more results than it served; stop
                    // rather than loop forever.
                    warn!(
                        "[{}] page returned 0 rows but total_results={}, stopping",
                        feed.name, page.total_results
                    );
                    break;
                }
            }
        }
        upsert_sync_state(&conn, &feed.name, now.naive_utc(), feed_total)?;
        info!("[{}] synced {} CVE(s)", feed.name, feed_total);

        if config.show_progress {
            let pct = ((idx + 1) as f32 / total_feeds as f32 * 100.0).round() as i32;
            bar.reach_percent(pct);
        }
    }

    if config.show_progress {
        bar.reach_percent(100);
        bar.jobs_done();
    }
    Ok(())
}

/// Return every cached CVE (full structs, deserialized).
pub fn get_all(config: &CacheConfig) -> Result<Vec<Cve>, CacheError> {
    let conn = Connection::open(&config.db)?;
    let mut stmt = conn.prepare("SELECT data FROM cve")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    let mut out = Vec::new();
    for row in rows {
        let blob = row?;
        out.push(serde_json::from_str::<Cve>(&blob)?);
    }
    Ok(out)
}

/// Fetch one CVE by its ID.
pub fn search_by_id(config: &CacheConfig, cve: &str) -> Result<Cve, CacheError> {
    let conn = Connection::open(&config.db)?;
    let blob: String =
        conn.query_row("SELECT data FROM cve WHERE id=?1", [cve], |row| row.get(0))?;
    Ok(serde_json::from_str(&blob)?)
}

/// Full-text-ish search across cached descriptions.
pub fn search_description(config: &CacheConfig, text: &str) -> Result<Vec<String>, CacheError> {
    let conn = Connection::open(&config.db)?;
    let mut stmt = conn.prepare("SELECT id FROM cve WHERE description LIKE '%' || ?1 || '%'")?;
    let rows = stmt.query_map(params![text], |row| row.get::<_, String>(0))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{BlockingHttpClient, CveQuery};
    use crate::cve::CveResponse;
    use crate::feed::Feed;
    use std::cell::RefCell;

    /// Tiny in-memory fake of the NVD API for tests. Returns the same
    /// fixture response regardless of `query` — sufficient to exercise
    /// the cache write/read path without hitting the network.
    struct FakeClient {
        body: String,
        calls: RefCell<Vec<(u32, u32)>>,
    }

    impl FakeClient {
        fn new(body: &str) -> Self {
            Self {
                body: body.to_string(),
                calls: RefCell::new(Vec::new()),
            }
        }
    }

    impl BlockingHttpClient for FakeClient {
        fn fetch_page(
            &self,
            _query: &CveQuery,
            start_index: u32,
            page_size: u32,
        ) -> Result<CveResponse, HttpError> {
            self.calls.borrow_mut().push((start_index, page_size));
            // Only return data on the first call to short-circuit pagination.
            if start_index == 0 {
                Ok(serde_json::from_str::<CveResponse>(&self.body)?)
            } else {
                Ok(CveResponse {
                    results_per_page: 0,
                    start_index,
                    total_results: 1,
                    format: "NVD_CVE".into(),
                    version: "2.0".into(),
                    timestamp: String::new(),
                    vulnerabilities: vec![],
                })
            }
        }
    }

    const FIXTURE: &str = r#"{
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": "2026-06-09T10:45:24.150",
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2024-1234",
                "sourceIdentifier": "test@example.com",
                "published": "2024-01-15T00:00:00.000",
                "lastModified": "2024-02-01T00:00:00.000",
                "vulnStatus": "Analyzed",
                "descriptions": [{"lang": "en", "value": "stack overflow in widget parser"}],
                "references": [{"url": "https://example.com/advisory", "source": "test@example.com", "tags": []}]
            }
        }]
    }"#;

    fn tmp_db() -> String {
        // Use process id + nanos to give each test its own DB and avoid
        // cross-test contamination.
        let mut path = env::temp_dir();
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!(
            "nvd_cve_test_{}_{stamp}.sqlite3",
            std::process::id()
        ));
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn sync_then_read_back() {
        let db = tmp_db();
        let config = CacheConfig {
            feeds: Feed::parse("2024").unwrap(),
            db: db.clone(),
            show_progress: false,
            force_update: false,
        };
        let client = FakeClient::new(FIXTURE);
        sync_blocking(&config, &client).expect("sync");

        let all = get_all(&config).expect("get_all");
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].id, "CVE-2024-1234");

        let by_id = search_by_id(&config, "CVE-2024-1234").expect("search_by_id");
        assert_eq!(
            by_id.description_en(),
            Some("stack overflow in widget parser")
        );

        let hits = search_description(&config, "overflow").expect("search_description");
        assert_eq!(hits, vec!["CVE-2024-1234".to_string()]);

        let _ = fs::remove_file(&db);
    }

    #[test]
    fn second_sync_skips_when_state_present() {
        let db = tmp_db();
        let config = CacheConfig {
            feeds: Feed::parse("2024").unwrap(),
            db: db.clone(),
            show_progress: false,
            force_update: false,
        };
        let client = FakeClient::new(FIXTURE);
        sync_blocking(&config, &client).unwrap();
        let first_calls = client.calls.borrow().len();
        sync_blocking(&config, &client).unwrap();
        let second_calls = client.calls.borrow().len();
        assert_eq!(
            first_calls, second_calls,
            "without --force-update, a feed already in sync_state should not be refetched"
        );

        let _ = fs::remove_file(&db);
    }

    #[test]
    fn force_update_refetches() {
        let db = tmp_db();
        let mut config = CacheConfig {
            feeds: Feed::parse("2024").unwrap(),
            db: db.clone(),
            show_progress: false,
            force_update: false,
        };
        let client = FakeClient::new(FIXTURE);
        sync_blocking(&config, &client).unwrap();
        let first_calls = client.calls.borrow().len();
        config.force_update = true;
        sync_blocking(&config, &client).unwrap();
        let second_calls = client.calls.borrow().len();
        assert!(
            second_calls > first_calls,
            "force_update should re-issue at least one fetch_page call"
        );

        let _ = fs::remove_file(&db);
    }

    #[test]
    fn legacy_schema_is_recreated() {
        let db = tmp_db();
        // Plant a 1.1-style cache.
        {
            let conn = Connection::open(&db).unwrap();
            conn.execute("CREATE TABLE metafile (feed VARCHAR PRIMARY KEY)", [])
                .unwrap();
            conn.execute("INSERT INTO metafile (feed) VALUES ('2002')", [])
                .unwrap();
            conn.execute("CREATE TABLE cve (id VARCHAR PRIMARY KEY, x TEXT)", [])
                .unwrap();
            conn.execute(
                "INSERT INTO cve (id, x) VALUES ('CVE-OLD', 'legacy blob')",
                [],
            )
            .unwrap();
        }
        let _ = open_schema(&db).expect("open_schema must succeed after wiping 1.1 layout");
        // Old cve row must be gone, schema must match 2.0.
        let conn = Connection::open(&db).unwrap();
        let row_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM cve", [], |row| row.get(0))
            .unwrap();
        assert_eq!(row_count, 0, "legacy CVE rows must be wiped");
        let has_sync_state: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='sync_state'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            has_sync_state, 1,
            "sync_state table must exist after migration"
        );

        let _ = fs::remove_file(&db);
    }
}
