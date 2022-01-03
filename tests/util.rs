use nvd_cve::client::{BlockingHttpClient, HttpError};
use nvd_cve::cve::CveFeed;
use std::time::Duration;

pub struct MockBlockingClient {
    pub get_metafile_response: Result<String, HttpError>,
    pub get_feed_response: Result<CveFeed, HttpError>,
}

impl BlockingHttpClient for MockBlockingClient {
    fn new<S: Into<String>>(
        _: S,
        _: Option<Duration>,
        _: Option<Duration>,
        _: Option<Duration>,
    ) -> Self {
        Self {
            get_metafile_response: Err(HttpError::ParseError),
            get_feed_response: Err(HttpError::ParseError),
        }
    }
    fn get_metafile(&self, _: &str) -> Result<String, HttpError> {
        self.get_metafile_response.clone()
    }
    fn get_feed(&self, _: &str) -> Result<CveFeed, HttpError> {
        self.get_feed_response.clone()
    }
}

impl Default for MockBlockingClient {
    fn default() -> Self {
        Self::new("http://127.0.0.1/nvd/feeds/json/cve/1.1/", None, None, None)
    }
}
