use crate::cve::CveFeed;
use flate2::read::MultiGzDecoder;
use reqwest::Url;
use std::io::Read;
use std::time::Duration;
use url::ParseError;

/// Errors related to HTTP clients
#[derive(Debug, Clone)]
pub enum HttpError {
    ParseError,
    ReqwestError,
    JsonError,
    IOError,
}

impl From<ParseError> for HttpError {
    fn from(_: ParseError) -> Self {
        HttpError::ParseError
    }
}

impl From<reqwest::Error> for HttpError {
    fn from(_: reqwest::Error) -> Self {
        HttpError::ReqwestError
    }
}

impl From<serde_json::Error> for HttpError {
    fn from(_: serde_json::Error) -> Self {
        HttpError::JsonError
    }
}

impl From<std::io::Error> for HttpError {
    fn from(_: std::io::Error) -> Self {
        HttpError::IOError
    }
}

/// Trait for fetching CVE feed and Metafiles
pub trait BlockingHttpClient {
    fn new<S: Into<String>>(
        base_url: S,
        connection_timeout: Option<Duration>,
        pool_idle_timeout: Option<Duration>,
        keepalive: Option<Duration>,
    ) -> Self;
    fn get_metafile(&self, metafile: &str) -> Result<String, HttpError>;
    fn get_feed(&self, name: &str) -> Result<CveFeed, HttpError>;
}

/// HTTP Client for Reqwest's Blocking API
pub struct ReqwestBlockingClient {
    client: reqwest::blocking::Client,
    base_url: String,
}

impl BlockingHttpClient for ReqwestBlockingClient {
    fn new<S: Into<String>>(
        base_url: S,
        connection_timeout: Option<Duration>,
        pool_idle_timeout: Option<Duration>,
        keepalive: Option<Duration>,
    ) -> Self {
        let client = reqwest::blocking::Client::builder()
            .user_agent(concat!(
                env!("CARGO_PKG_NAME"),
                "/",
                env!("CARGO_PKG_VERSION")
            ))
            .connect_timeout(connection_timeout)
            .pool_idle_timeout(pool_idle_timeout)
            .tcp_keepalive(keepalive)
            .build()
            .expect("Failed to build Reqwest Blocking Client");
        Self {
            base_url: base_url.into(),
            client,
        }
    }

    /// Fetches a Metafile text file
    // XXX Should this parse the Metafile too?
    fn get_metafile(&self, name: &str) -> Result<String, HttpError> {
        let filename = format!("nvdcve-1.1-{}.meta", name);
        let url = Url::parse(self.base_url.as_str())?.join(filename.as_str())?;
        Ok(self.client.get(url).send()?.text()?)
    }

    /// Fetches a GZipped CVE JSON feed
    fn get_feed(&self, name: &str) -> Result<CveFeed, HttpError> {
        let filename = format!("nvdcve-1.1-{}.json.gz", name);

        let url = Url::parse(self.base_url.as_str())?.join(filename.as_str())?;

        let response = self.client.get(url).send()?;

        let mut decoder = MultiGzDecoder::new(response);

        let mut decompressed_bytes = vec![];

        std::io::copy(&mut decoder, &mut decompressed_bytes)?;

        decoder
            .read_to_end(&mut decompressed_bytes)
            .expect("Failed to read to end of GZipped data.");

        Ok(serde_json::from_slice::<CveFeed>(&decompressed_bytes)?)
    }
}
