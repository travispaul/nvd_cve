use crate::client::{BlockingHttpClient, HttpError};
use crate::cve::{Cve, CveContainer, CveFeed};
use crate::feed::{Feed, Metafile, MetafileError};
use chrono::NaiveDateTime;
use humansize::{file_size_opts as options, FileSize};
use log::debug;
use rusqlite::{params, Connection, Result, Transaction, TransactionBehavior};
use std::fmt;
use std::path::PathBuf;
use std::{env, fs, io};

#[derive(Debug)]
pub struct CacheConfig {
    pub url: String,
    pub feeds: Vec<String>,
    pub db: String,
    pub show_progress: bool,
    pub force_update: bool,
}

impl CacheConfig {
    /// If a full path wasn't supplied for the local database, then try to pick something reasonable based on:
    /// https://standards.freedesktop.org/basedir-spec/basedir-spec-latest.html
    ///
    /// $XDG_CACHE_HOME defines the base directory relative to which user specific
    /// non-essential data files should be stored.
    ///
    /// If $XDG_CACHE_HOME is either not set or empty, a default equal to
    /// $HOME/.cache should be used.
    ///
    /// If $HOME can't be determined, stray from the basedir spec and try the OS's temporary directory
    /// Failing that, set a relative path.
    pub fn default_db_path() -> String {
        let mut path = std::path::PathBuf::new();
        let cache_namespace = "nvd";
        let db_name = "nvd.sqlite3";

        // Try $XDG_CACHE_HOME
        if let Ok(xdg_cache_home) = env::var("XDG_CACHE_HOME") {
            path.push(xdg_cache_home);
        } else if let Some(home_dir) = home::home_dir() {
            // Try ~/.cache
            path.push(home_dir);
            path.push(".cache");
        } else {
            // Use $TMP
            path.push(env::temp_dir());
        }

        path.push(cache_namespace);
        path.push(db_name);

        // Try converting path to string though not all paths may be UTF-8 safe
        if let Some(string_path) = path.to_str() {
            return string_path.to_string();
        }

        // failing all else, try relative path
        let mut fallback = std::path::PathBuf::from(cache_namespace);
        fallback.push(db_name);
        fallback.to_str().unwrap().to_string()
    }

    pub fn new() -> Self {
        let mut feeds: Vec<String> = (2002..2022).into_iter().map(|x| x.to_string()).collect();
        feeds.push("recent".to_string());
        feeds.push("modified".to_string());
        Self {
            url: "https://nvd.nist.gov/feeds/json/cve/1.1/".to_string(),
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
        write!(
            f,
            "Url: {}\nFeeds: {}\nDB Path: {}\nProgress Bar: {}\n",
            self.url,
            self.feeds.join(","),
            self.db,
            self.show_progress
        )
    }
}

#[derive(Debug)]
pub enum CacheError {
    RusqliteError(rusqlite::Error),
    IOError(io::Error),
    MetafileError(MetafileError),
    HttpError(HttpError),
    JsonError(serde_json::Error),
}

impl From<io::Error> for CacheError {
    fn from(error: io::Error) -> Self {
        CacheError::IOError(error)
    }
}

impl From<rusqlite::Error> for CacheError {
    fn from(error: rusqlite::Error) -> Self {
        CacheError::RusqliteError(error)
    }
}

impl From<MetafileError> for CacheError {
    fn from(error: MetafileError) -> Self {
        CacheError::MetafileError(error)
    }
}

impl From<HttpError> for CacheError {
    fn from(error: HttpError) -> Self {
        CacheError::HttpError(error)
    }
}

impl From<serde_json::Error> for CacheError {
    fn from(error: serde_json::Error) -> Self {
        CacheError::JsonError(error)
    }
}

pub struct SqliteCache {
    path: String,
}

impl SqliteCache {
    pub fn new<S: Into<String>>(path: S) -> Self {
        Self { path: path.into() }
    }

    pub fn create_schema(&self) -> Result<(), CacheError> {
        let mut db_path = PathBuf::from(&self.path);
        db_path.pop();
        fs::create_dir_all(db_path)?;

        let conn = Connection::open(&self.path)?;

        let mut tbl_stmt =
            conn.prepare("SELECT name FROM sqlite_master where type = 'table' and name = ?;")?;

        if !tbl_stmt.exists(["cve"])? {
            conn.execute(
                "CREATE TABLE cve (
               id VARCHAR PRIMARY KEY,
               description TEXT,
               data TEXT NOT NULL)",
                [],
            )?;
        }

        if !tbl_stmt.exists(["metafile"])? {
            conn.execute(
                "CREATE TABLE metafile (
                feed VARCHAR PRIMARY KEY,
                last_modified_date VARCHAR NOT NULL,
                size INTEGER NOT NULL,
                zip_size INTEGER NOT NULL,
                gz_size INTEGER NOT NULL,
                sha256 VARCHAR NOT NULL)",
                [],
            )?;
        }

        tbl_stmt.finalize()?;

        match conn.close() {
            Ok(_) => Ok(()),
            Err((_, error)) => Err(CacheError::RusqliteError(error)),
        }
    }

    pub fn get_metafiles(&self, feeds: &[String]) -> Result<Vec<Feed>, CacheError> {
        let conn = Connection::open(&self.path)?;

        let mut stmt = conn.prepare("SELECT * FROM metafile where feed=?1")?;

        let cached_feeds = feeds
            .iter()
            .map(|name| {
                let meta = stmt
                    .query_row([&name], |row| {
                        let last_modified_row: String =
                            row.get("last_modified_date").unwrap_or_default();
                        let last_modified_date =
                            Metafile::parse_datetime(last_modified_row.as_str());
                        let metafile = Metafile {
                            last_modified_date,
                            size: row.get("size").unwrap_or_default(),
                            zip_size: row.get("zip_size").unwrap_or_default(),
                            gz_size: row.get("gz_size").unwrap_or_default(),
                            sha256: row.get("sha256").unwrap_or_default(),
                        };
                        Ok(metafile)
                    })
                    .ok();
                Feed {
                    name: name.clone(),
                    metafile: meta,
                }
            })
            .collect();

        stmt.finalize()?;

        match conn.close() {
            Ok(_) => Ok(cached_feeds),
            Err((_, error)) => Err(CacheError::RusqliteError(error)),
        }
    }

    pub fn set_metafile(&self, feed: &str, metafile: &Metafile) -> Result<(), CacheError> {
        let conn = Connection::open(&self.path)?;
        let upsert_sql = "
        insert into
        metafile (
            feed,
            last_modified_date,
            size,
            zip_size,
            gz_size,
            sha256
        )
        values
            (?1, ?2, ?3, ?4, ?5, ?6) on conflict(feed) do
        update
        set
            last_modified_date = ?2,
            size = ?3,
            zip_size = ?4,
            gz_size = ?5,
            sha256 = ?6;";

        let mut stmt = conn.prepare(upsert_sql)?;
        stmt.insert(params![
            feed,
            metafile.format_last_modified_date(),
            metafile.size,
            metafile.zip_size,
            metafile.gz_size,
            metafile.sha256
        ])?;
        stmt.finalize()?;
        match conn.close() {
            Ok(_) => Ok(()),
            Err((_, error)) => Err(CacheError::RusqliteError(error)),
        }
    }

    pub fn set_cves(
        &self,
        cve_feed: &[CveContainer],
        last_modified_date: Option<&NaiveDateTime>,
    ) -> Result<(), CacheError> {
        let conn = Connection::open(&self.path)?;
        let upsert_sql = "
        insert into
        cve (
            id,
            description,
            data
        )
        values
            (?1, ?2, ?3) on conflict(id) do
        update
        set
            description=?2,
            data=?3;";

        let mut stmt = conn.prepare(upsert_sql)?;
        let mut unecessary = 0;

        // We can't borrow conn immutably for the prepared statement AND mutably for a transaction
        // Transaction::new_unchecked() allows for an immutable borrow of the connection
        // see: https://github.com/rusqlite/rusqlite/pull/693
        let tx = Transaction::new_unchecked(&conn, TransactionBehavior::Exclusive)?;

        for cve in cve_feed {
            let mut skip = false;

            if let Some(metafile_datetime) = last_modified_date {
                if let Ok(cve_datetime) =
                    NaiveDateTime::parse_from_str(&cve.last_modified_date, "%Y-%m-%dT%H:%M%Z")
                {
                    if cve_datetime > *metafile_datetime {
                        skip = true;
                    }
                }
            }

            if skip {
                unecessary += 1;
            } else {
                let mut description = None;
                if !cve.cve.description.description_data.is_empty() {
                    for d in &cve.cve.description.description_data {
                        if d.lang == "en" {
                            description = Some(String::from(&d.value));
                        }
                    }
                }
                stmt.insert(params![
                    cve.cve.cve_data_meta.id,
                    description,
                    serde_json::to_string(&cve.cve).unwrap_or_else(|_| { "{}".to_string() })
                ])?;
            }
        }

        tx.commit()?;

        debug!("Skipped {} unnecessary inserts", unecessary);
        stmt.finalize()?;
        match conn.close() {
            Ok(_) => Ok(()),
            Err((_, error)) => Err(CacheError::RusqliteError(error)),
        }
    }

    pub fn get_cve(&self, cve: &str) -> Result<Cve, CacheError> {
        let conn = Connection::open(&self.path)?;

        let mut stmt = conn.prepare("SELECT * FROM cve where id=?1")?;

        let data = stmt.query_row([&cve], |row| {
            let data: String = row.get("data")?;
            Ok(data)
        })?;

        stmt.finalize()?;

        let result: Cve = serde_json::from_str(data.as_str())?;

        match conn.close() {
            Ok(_) => Ok(result),
            Err((_, error)) => Err(CacheError::RusqliteError(error)),
        }
    }

    pub fn search_cve_description(&self, text: &str) -> Result<usize, CacheError> {
        let conn = Connection::open(&self.path)?;

        let mut count = 0;

        let mut stmt =
            conn.prepare("SELECT id FROM cve where description like '%' || ?1 || '%'")?;

        let cves = stmt.query_map(params![text], |row| {
            let id: String = row.get("id")?;
            Ok(id)
        })?;

        for cve in cves {
            count += 1;
            println!("{}", cve?.as_str());
        }

        stmt.finalize()?;

        match conn.close() {
            Ok(_) => Ok(count),
            Err((_, error)) => Err(CacheError::RusqliteError(error)),
        }
    }
}

pub fn sync_blocking<C: BlockingHttpClient>(
    config: &CacheConfig,
    client: C,
) -> Result<(), CacheError> {
    let mut bar = progress::Bar::new();
    let cache = SqliteCache::new(&config.db);

    let mut synced = 0;

    // Each operation is a progress point: fetch metafile, insert metafile, fetch feeds, insert CVEs
    let to_sync = config.feeds.len() * 4;

    if config.show_progress {
        bar.set_job_title("Syncing CVE Data");
        bar.reach_percent((synced as f32 / to_sync as f32 * 100.0).round() as i32);
    }

    cache.create_schema()?;

    let feeds = cache.get_metafiles(&config.feeds)?;

    for feed in feeds {
        let mut last_modified = None;
        if config.show_progress {
            bar.set_job_title(format!("[Feed: {}] Fetching Metafile", feed.name).as_str());
        }

        let metafile = Metafile::from_blocking_http_client(&client, &feed.name)?;

        if config.show_progress {
            synced += 1;
            bar.set_job_title(
                format!(
                    "[Feed: {}] Fetching feed ({})",
                    feed.name,
                    metafile
                        .gz_size
                        .file_size(options::CONVENTIONAL)
                        .unwrap_or_default()
                )
                .as_str(),
            );
            bar.reach_percent((synced as f32 / to_sync as f32 * 100.0).round() as i32);
        }

        if let Some(db_metafile) = feed.metafile {
            last_modified = Some(&metafile.last_modified_date);
            if !config.force_update
                && (db_metafile.last_modified_date >= metafile.last_modified_date)
            {
                debug!(
                    "Cached Metafile: {} is the latest ({})",
                    feed.name, metafile.last_modified_date
                );
                // Skip insert metafile, fetch feeds, insert CVEs
                synced += 3;
                continue;
            }
        }

        let cve_feed = CveFeed::from_blocking_http_client(&client, &feed.name)?;

        if config.show_progress {
            synced += 1;
            bar.set_job_title(
                format!(
                    "[Feed: {}] Syncing {} CVEs",
                    feed.name,
                    cve_feed.cve_items.len()
                )
                .as_str(),
            );
            bar.reach_percent((synced as f32 / to_sync as f32 * 100.0).round() as i32);
        }

        cache.set_cves(&cve_feed.cve_items, last_modified)?;

        if config.show_progress {
            synced += 1;
            bar.reach_percent((synced as f32 / to_sync as f32 * 100.0).round() as i32);
        }

        cache.set_metafile(&feed.name, &metafile)?;

        if config.show_progress {
            synced += 1;
            bar.reach_percent((synced as f32 / to_sync as f32 * 100.0).round() as i32);
        }
    }

    Ok(())
}

pub fn search_by_id(config: &CacheConfig, cve: &str) -> Result<Cve, CacheError> {
    let cache = SqliteCache::new(&config.db);
    cache.get_cve(cve)
}

pub fn search_description(config: &CacheConfig, text: &str) -> Result<usize, CacheError> {
    let cache = SqliteCache::new(&config.db);
    cache.search_cve_description(text)
}