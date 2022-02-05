/// A Metafile is a small text file containing metadata about a compressed JSON CVE feed.
/// Every CVE feed file has an associated Metafile.
use crate::client::{BlockingHttpClient, HttpError};
use chrono::{DateTime, NaiveDateTime, ParseError};
use log::warn;
use std::fs;
use std::io::Error;
use std::num::ParseIntError;
use std::path::Path;
use std::str::FromStr;

/// CVE JSON feed and associated Metafile data.
#[derive(Debug)]
pub struct Feed {
    pub name: String,
    pub metafile: Option<Metafile>,
}

/// Errors related to parsing a JSON feed's Metafile
#[derive(Debug)]
pub enum MetafileError {
    /// File IO Error when reading Metafile
    FileError(Error),
    /// Incorrect number of lines in Metafile
    LineError,
    /// Failure to split Metafile fields as expected
    SplitError,
    /// Failed to parse Metafile values as u64
    ParseIntError(ParseIntError),
    /// Failed parsing Metafile last_modified_date
    ParseDateTimeError(ParseError),
    /// Failed fetching metafile from HTTP Client
    FetchError(HttpError),
}

impl From<Error> for MetafileError {
    fn from(error: Error) -> Self {
        MetafileError::FileError(error)
    }
}

impl From<ParseIntError> for MetafileError {
    fn from(error: ParseIntError) -> Self {
        MetafileError::ParseIntError(error)
    }
}

/// Metafile describing a CVE JSON feed
#[derive(Debug)]
pub struct Metafile {
    /// Last modified date of JSON feed.
    pub last_modified_date: NaiveDateTime,

    /// Size of feed in bytes.
    pub size: u64,

    /// Size of zip feed in bytes.
    pub zip_size: u64,

    /// Size of gzip feed in bytes.
    pub gz_size: u64,

    /// SHA256 sum of uncompressed feed JSON file.
    pub sha256: String,
}

/// A parse feed Metafile
impl Metafile {
    pub fn from_blocking_http_client<C: BlockingHttpClient>(
        client: &C,
        name: &str,
    ) -> Result<Self, MetafileError> {
        match client.get_metafile(name) {
            Ok(metafile_text) => Self::from_string(metafile_text),
            Err(error) => Err(MetafileError::FetchError(error)),
        }
    }

    /// Parse Metafile from a local file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, MetafileError> {
        Self::from_string(fs::read_to_string(path)?)
    }

    /// Parse Metafile from a String
    pub fn from_string(contents: String) -> Result<Self, MetafileError> {
        macro_rules! next {
            ($lines:expr) => {
                $lines
                    .next()
                    .ok_or(MetafileError::LineError)?
                    .split_once(':')
                    .ok_or(MetafileError::SplitError)?
                    .1
            };
        }

        let mut lines = contents.lines();

        Ok(Self {
            last_modified_date: Self::parse_datetime(next!(lines)),
            size: u64::from_str(next!(lines))?,
            zip_size: u64::from_str(next!(lines))?,
            gz_size: u64::from_str(next!(lines))?,
            sha256: next!(lines).to_string(),
        })
    }

    /// Parse date from either a metafile or from a record in the local cache
    pub fn parse_datetime(datetime: &str) -> NaiveDateTime {
        match DateTime::parse_from_rfc3339(datetime) {
            Ok(parsed_dt) => parsed_dt.naive_utc(),
            Err(_) => match NaiveDateTime::parse_from_str(datetime, "%Y-%m-%dT%H:%M:%S") {
                Ok(parsed_ndt) => parsed_ndt,
                Err(_) => {
                    warn!("Failed parsing datetime: {:?}", datetime);
                    NaiveDateTime::from_timestamp(0, 0)
                }
            },
        }
    }

    /// Format NaiveDate to a string for storing in local cache
    pub fn format_last_modified_date(&self) -> String {
        self.last_modified_date
            .format("%Y-%m-%dT%H:%M:%S")
            .to_string()
    }
}
