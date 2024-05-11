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

const SCHEMA_VERSION: &str = "0.1.0";

/// Configuration details about how to sync remote feeds to a local cache.
#[derive(Debug)]
pub struct CacheConfig {
    /// A URL where  NIST CVE 1.1  feeds can be found. This can be your own mirror but it must have the
    /// same file and directory structure as served by the official NIST feeds.
    pub url: String,

    /// All feeds that are to be synced. They are synced in the order provided so if you intend to
    /// sync the``recent`` or ``modified`` feeds, they should always be provided last or else it is
    /// possible to overwrite a newer ``modified`` version of a CVE record with stale data.
    pub feeds: Vec<String>,

    /// Path to the SQLite database used to store the synced CVE data.
    pub db: String,

    /// If ``True`` the status of the sync process will be displayed.
    pub show_progress: bool,

    /// If ``True`` the ``last_modified_date`` provided by the feed's ``Metafile`` will be ignored
    /// and the feed will always be fetched.
    pub force_update: bool,
}

impl CacheConfig {
    /// If a full path wasn't supplied for the local database, then try to pick something reasonable
    /// based on the
    /// [XDG Base Directory Spec](https://standards.freedesktop.org/basedir-spec/basedir-spec-latest.html).
    ///
    /// > _`$XDG_CACHE_HOME` defines the base directory relative to which user specific
    /// > non-essential data files should be stored._
    ///
    /// > _If `$XDG_CACHE_HOME` is either not set or empty, a default equal to
    /// > `$HOME/.cache` should be used._
    ///
    /// If `$HOME` can't be determined, stray from the basedir spec and try the OS's temporary
    /// directory. Failing that, set a relative path.
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

    /// Create a new ``CacheConfig`` with some reasonable defaults.
    pub fn new() -> Self {
        let mut feeds: Vec<String> = (2002..=2024).into_iter().map(|x| x.to_string()).collect();
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

/// Errors related to Cache
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

/// Create ``Metafile`` and CVE tables for local cache
fn create_schema(path: &str) -> Result<(), CacheError> {
    let mut db_path = PathBuf::from(&path);
    db_path.pop();
    fs::create_dir_all(db_path)?;

    let conn = Connection::open(path)?;

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

    if !tbl_stmt.exists(["migration"])? {
        conn.execute(
            "CREATE TABLE migration (
                schema_version VARCHAR PRIMARY KEY,
                app_version VARCHAR NOT NULL,
                status INTEGER NOT NULL)",
            [],
        )?;
        conn.execute(
            "INSERT into migration (schema_version, app_version, status) values (?1, ?2, 0)",
            [
                SCHEMA_VERSION,
                option_env!("CARGO_PKG_VERSION").unwrap_or("?.?.?"),
            ],
        )?;
    }

    tbl_stmt.finalize()?;

    match conn.close() {
        Ok(_) => Ok(()),
        Err((_, error)) => Err(CacheError::RusqliteError(error)),
    }
}

/// Get all cached ``Metafiles``
fn get_metafiles(config: &CacheConfig) -> Result<Vec<Feed>, CacheError> {
    let conn = Connection::open(&config.db)?;

    let mut stmt = conn.prepare("SELECT * FROM metafile where feed=?1")?;

    let cached_feeds = config
        .feeds
        .iter()
        .map(|name| {
            let meta = stmt
                .query_row([&name], |row| {
                    let last_modified_row: String =
                        row.get("last_modified_date").unwrap_or_default();
                    let last_modified_date = Metafile::parse_datetime(last_modified_row.as_str());
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

/// Update or insert ``Metafile``
fn update_metafile(
    config: &CacheConfig,
    feed: &str,
    metafile: &Metafile,
) -> Result<(), CacheError> {
    let conn = Connection::open(&config.db)?;
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

/// Update or insert CVEs from a ``CVEContainer``
fn update_cves(
    config: &CacheConfig,
    cve_feed: &[CveContainer],
    last_modified_date: Option<&NaiveDateTime>,
) -> Result<(), CacheError> {
    let conn = Connection::open(&config.db)?;
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

/// Syncs the remote feeds to the local cache using the provided ``BlockingHttpClient``
///
/// ## Example:
/// ```no_run
/// use nvd_cve::cache::{CacheConfig, sync_blocking};
/// use nvd_cve::client::{ReqwestBlockingClient, BlockingHttpClient};
///
/// let mut config = CacheConfig::new();
///
/// let client = ReqwestBlockingClient::new(&config.url, None, None, None);
///
/// if let Err(error) = sync_blocking(&config, client) {
///     eprintln!("Fatal Error while syncing feeds: {:?}", error);
///     std::process::exit(1);
/// }
/// ```
pub fn sync_blocking<C: BlockingHttpClient>(
    config: &CacheConfig,
    client: C,
) -> Result<(), CacheError> {
    let mut bar = progress::Bar::new();

    let mut synced = 0;

    // Each operation is a progress point: fetch metafile, insert metafile, fetch feeds, insert CVEs
    let to_sync = config.feeds.len() * 4;

    if config.show_progress {
        bar.set_job_title("Syncing CVE Data");
        bar.reach_percent((synced as f32 / to_sync as f32 * 100.0).round() as i32);
    }

    create_schema(&config.db)?;

    let feeds = get_metafiles(config)?;

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

        update_cves(config, &cve_feed.cve_items, last_modified)?;

        if config.show_progress {
            synced += 1;
            bar.reach_percent((synced as f32 / to_sync as f32 * 100.0).round() as i32);
        }

        update_metafile(config, &feed.name, &metafile)?;

        if config.show_progress {
            synced += 1;
            bar.reach_percent((synced as f32 / to_sync as f32 * 100.0).round() as i32);
        }
    }

    Ok(())
}

/// Returns all the CVEs available in the database.
///
/// ## Example:
/// ```no_run
/// use nvd_cve::cache::{CacheConfig, get_all};
///
/// let config = CacheConfig::new();
///
/// let all_cves = get_all(&config).unwrap();
/// println!("{:?}", &all_cves);
/// ```
pub fn get_all(config: &CacheConfig) -> Result<Vec<Cve>, CacheError> {
    let conn = Connection::open(&config.db)?;
    let mut stmt = conn.prepare("SELECT * FROM cve")?;

    let cves = stmt.query_map(params![], |row| {
        let data: String = row.get("data")?;
        Ok(data)
    })?;

    let mut cve_list = vec![];
    for cve in cves {
        let result: Cve = serde_json::from_str(cve?.as_str())?;
        cve_list.push(result);
    }
    stmt.finalize()?;

    match conn.close() {
        Ok(_) => Ok(cve_list),
        Err((_, error)) => Err(CacheError::RusqliteError(error)),
    }
}

/// Returns the full CVE object that is extracted from the feed for the provided CVE ID.
///
/// ## Example:
/// ```no_run
/// use nvd_cve::cache::{CacheConfig, search_by_id};
///
/// let config = CacheConfig::new();
///
/// let cve_result = search_by_id(&config, "CVE-2019-18254").unwrap();
/// println!("{:?}", &cve_result);
/// ```
pub fn search_by_id(config: &CacheConfig, cve: &str) -> Result<Cve, CacheError> {
    let conn = Connection::open(&config.db)?;

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

/// Searches all local CVE descriptions for the provided ``text`` string, and returns a Vec of CVE ID Strings for any matches.
///
/// ## Example:
/// ```no_run
/// use nvd_cve::cache::{CacheConfig, search_description};
///
/// let config = CacheConfig::new();
///
/// if let Ok(cves) = search_description(&config, "implanted cardiac device") {
///     for cve_id in cves {
///         println!("{}", cve_id);
///     }
/// }
/// ```

pub fn search_description(config: &CacheConfig, text: &str) -> Result<Vec<String>, CacheError> {
    let conn = Connection::open(&config.db)?;

    let mut stmt = conn.prepare("SELECT id FROM cve where description like '%' || ?1 || '%'")?;

    let cves = stmt.query_map(params![text], |row| {
        let id: String = row.get("id")?;
        Ok(id)
    })?;

    let mut cve_list = vec![];

    for cve in cves {
        cve_list.push(cve?);
    }

    stmt.finalize()?;

    match conn.close() {
        Ok(_) => Ok(cve_list),
        Err((_, error)) => Err(CacheError::RusqliteError(error)),
    }
}
