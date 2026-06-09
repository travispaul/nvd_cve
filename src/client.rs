//! HTTP client for the NVD 2.0 REST API.
//!
//! Endpoint reference: <https://nvd.nist.gov/developers/vulnerabilities>
//!
//! Practical constraints baked in here:
//!
//! - **Rate limits.** NVD allows 5 requests per 30 seconds without an API key
//!   and 50 per 30 seconds with one. The client tracks request timestamps in a
//!   sliding window and sleeps before exceeding the budget.
//! - **Date span ≤ 120 days.** When a date filter is supplied, NVD rejects
//!   ranges wider than 120 consecutive days. The client itself does *not* slice
//!   ranges — that is the caller's job (see [`crate::feed`]). Slicing belongs at
//!   the feed layer because it interacts with per-feed sync state.
//! - **Pagination.** `resultsPerPage` is capped at 2000 (NVD's max).
//! - **Retries on transient failures.** 429 / 5xx responses are retried with
//!   exponential backoff a small number of times before bubbling up.

use crate::cve::CveResponse;
use reqwest::blocking::Client;
use reqwest::StatusCode;
use std::collections::VecDeque;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

/// Maximum `resultsPerPage` accepted by NVD.
pub const MAX_PAGE_SIZE: u32 = 2000;

/// NVD's date-range cap (`pubStartDate`/`pubEndDate` and the mod variants).
pub const MAX_RANGE_DAYS: i64 = 120;

const ENDPOINT: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(30);
const RATE_LIMIT_NO_KEY: usize = 5;
const RATE_LIMIT_WITH_KEY: usize = 50;
const RETRY_ATTEMPTS: u32 = 4;
const RETRY_BASE_BACKOFF: Duration = Duration::from_secs(2);

/// Errors raised by the HTTP layer.
#[derive(Debug)]
pub enum HttpError {
    /// Underlying transport error (timeout, DNS, TLS, …).
    Transport(reqwest::Error),
    /// NVD returned a non-success status after retries were exhausted.
    Status { status: StatusCode, body: String },
    /// Response body did not parse as a CVE 2.0 envelope.
    Json(serde_json::Error),
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpError::Transport(e) => write!(f, "transport error: {e}"),
            HttpError::Status { status, body } => {
                let snippet: String = body.chars().take(200).collect();
                write!(f, "NVD returned {status}: {snippet}")
            }
            HttpError::Json(e) => write!(f, "failed to parse NVD response: {e}"),
        }
    }
}

impl std::error::Error for HttpError {}

impl From<reqwest::Error> for HttpError {
    fn from(error: reqwest::Error) -> Self {
        HttpError::Transport(error)
    }
}

impl From<serde_json::Error> for HttpError {
    fn from(error: serde_json::Error) -> Self {
        HttpError::Json(error)
    }
}

/// Query parameters for one call to `/rest/json/cves/2.0`.
///
/// All fields are optional. NVD rejects a request that mixes `cve_id` with
/// date ranges, so callers should populate either one or the other.
///
/// Dates are passed through as already-formatted strings (NVD expects
/// `yyyy-MM-ddTHH:mm:ss.SSS`). Building them as strings keeps this crate's
/// public API free of a date-library dependency.
#[derive(Debug, Clone, Default)]
pub struct CveQuery {
    pub pub_start_date: Option<String>,
    pub pub_end_date: Option<String>,
    pub last_mod_start_date: Option<String>,
    pub last_mod_end_date: Option<String>,
    pub cve_id: Option<String>,
    /// Free-text keyword filter (server-side substring match).
    pub keyword_search: Option<String>,
}

impl CveQuery {
    fn append_params<'a>(&'a self, params: &mut Vec<(&'static str, &'a str)>) {
        if let Some(v) = &self.cve_id {
            params.push(("cveId", v));
        }
        if let Some(v) = &self.pub_start_date {
            params.push(("pubStartDate", v));
        }
        if let Some(v) = &self.pub_end_date {
            params.push(("pubEndDate", v));
        }
        if let Some(v) = &self.last_mod_start_date {
            params.push(("lastModStartDate", v));
        }
        if let Some(v) = &self.last_mod_end_date {
            params.push(("lastModEndDate", v));
        }
        if let Some(v) = &self.keyword_search {
            params.push(("keywordSearch", v));
        }
    }
}

/// Abstract HTTP client. Defined as a trait so tests can swap a fake in.
pub trait BlockingHttpClient {
    /// Fetch one page of results. `start_index` is 0-based.
    fn fetch_page(
        &self,
        query: &CveQuery,
        start_index: u32,
        page_size: u32,
    ) -> Result<CveResponse, HttpError>;
}

/// Concrete client backed by `reqwest::blocking`.
pub struct ReqwestBlockingClient {
    client: Client,
    endpoint: String,
    api_key: Option<String>,
    limiter: Mutex<RateLimiter>,
}

impl ReqwestBlockingClient {
    /// Builds a client that talks to NVD directly.
    ///
    /// `api_key` is optional but strongly recommended — without it a full sync
    /// takes about 10× longer because of the stricter 5-per-30s rate budget.
    pub fn new(api_key: Option<String>) -> Result<Self, HttpError> {
        Self::with_endpoint(ENDPOINT, api_key)
    }

    /// Same as [`new`](Self::new) but pointed at a custom endpoint (used by
    /// tests against a local mock server).
    pub fn with_endpoint<S: Into<String>>(
        endpoint: S,
        api_key: Option<String>,
    ) -> Result<Self, HttpError> {
        let budget = if api_key.is_some() {
            RATE_LIMIT_WITH_KEY
        } else {
            RATE_LIMIT_NO_KEY
        };
        let client = Client::builder()
            .user_agent(concat!(
                env!("CARGO_PKG_NAME"),
                "/",
                env!("CARGO_PKG_VERSION"),
            ))
            .timeout(Duration::from_secs(60))
            .build()?;
        Ok(Self {
            client,
            endpoint: endpoint.into(),
            api_key,
            limiter: Mutex::new(RateLimiter::new(budget, RATE_LIMIT_WINDOW)),
        })
    }
}

impl BlockingHttpClient for ReqwestBlockingClient {
    fn fetch_page(
        &self,
        query: &CveQuery,
        start_index: u32,
        page_size: u32,
    ) -> Result<CveResponse, HttpError> {
        let page_size = page_size.min(MAX_PAGE_SIZE);
        let start_index_s = start_index.to_string();
        let page_size_s = page_size.to_string();

        let mut params: Vec<(&'static str, &str)> = vec![
            ("startIndex", start_index_s.as_str()),
            ("resultsPerPage", page_size_s.as_str()),
        ];
        query.append_params(&mut params);

        let mut last_status: Option<(StatusCode, String)> = None;
        for attempt in 0..RETRY_ATTEMPTS {
            if attempt > 0 {
                // Exponential backoff: 2s, 4s, 8s, 16s.
                thread::sleep(RETRY_BASE_BACKOFF * (1u32 << (attempt - 1)));
            }
            self.limiter.lock().expect("rate limiter poisoned").wait();

            let mut req = self.client.get(&self.endpoint).query(&params);
            if let Some(key) = &self.api_key {
                req = req.header("apiKey", key);
            }
            let response = req.send()?;
            let status = response.status();

            if status.is_success() {
                return Ok(response.json::<CveResponse>()?);
            }

            // 403 from NVD usually means rate-limit (no Retry-After header
            // either, so we just back off). 429 / 5xx are also transient.
            let retryable = matches!(
                status,
                StatusCode::FORBIDDEN
                    | StatusCode::TOO_MANY_REQUESTS
                    | StatusCode::SERVICE_UNAVAILABLE
                    | StatusCode::BAD_GATEWAY
                    | StatusCode::GATEWAY_TIMEOUT
            );
            let body = response.text().unwrap_or_default();
            last_status = Some((status, body));
            if !retryable {
                break;
            }
        }
        let (status, body) = last_status.expect("loop ran at least once");
        Err(HttpError::Status { status, body })
    }
}

/// Sliding-window rate limiter. Cheap to implement against NVD's quota since
/// the budget is small enough (≤50 entries) that a `VecDeque` is fine.
struct RateLimiter {
    max_requests: usize,
    window: Duration,
    history: VecDeque<Instant>,
}

impl RateLimiter {
    fn new(max_requests: usize, window: Duration) -> Self {
        Self {
            max_requests,
            window,
            history: VecDeque::with_capacity(max_requests),
        }
    }

    /// Block until issuing a new request would not exceed the budget, then
    /// record the new request.
    fn wait(&mut self) {
        let now = Instant::now();
        while let Some(&oldest) = self.history.front() {
            if now.duration_since(oldest) >= self.window {
                self.history.pop_front();
            } else {
                break;
            }
        }
        if self.history.len() >= self.max_requests {
            let oldest = *self.history.front().expect("front exists when len >= cap");
            let wait = self.window.saturating_sub(now.duration_since(oldest));
            if !wait.is_zero() {
                thread::sleep(wait);
            }
            self.history.pop_front();
        }
        self.history.push_back(Instant::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_admits_up_to_budget_without_sleeping() {
        // The whole sequence must finish well under the 30s window — proves
        // the limiter does not block when we stay under the cap.
        let mut limiter = RateLimiter::new(5, Duration::from_secs(30));
        let start = Instant::now();
        for _ in 0..5 {
            limiter.wait();
        }
        assert!(start.elapsed() < Duration::from_millis(100));
    }

    #[test]
    fn rate_limiter_sleeps_when_budget_exhausted() {
        // Window of 200ms, budget of 2: the 3rd call must wait until the
        // oldest entry ages out of the window.
        let mut limiter = RateLimiter::new(2, Duration::from_millis(200));
        limiter.wait();
        limiter.wait();
        let before_third = Instant::now();
        limiter.wait();
        let waited = before_third.elapsed();
        assert!(
            waited >= Duration::from_millis(150),
            "third call should block for ~window, waited {waited:?}"
        );
    }

    #[test]
    fn query_serializes_all_provided_params() {
        let query = CveQuery {
            cve_id: Some("CVE-2014-0160".to_string()),
            pub_start_date: Some("2024-01-01T00:00:00.000".to_string()),
            pub_end_date: Some("2024-04-30T23:59:59.999".to_string()),
            last_mod_start_date: None,
            last_mod_end_date: None,
            keyword_search: Some("overflow".to_string()),
        };
        let mut params: Vec<(&'static str, &str)> = Vec::new();
        query.append_params(&mut params);
        let pairs: Vec<_> = params.iter().map(|(k, _)| *k).collect();
        assert!(pairs.contains(&"cveId"));
        assert!(pairs.contains(&"pubStartDate"));
        assert!(pairs.contains(&"pubEndDate"));
        assert!(pairs.contains(&"keywordSearch"));
        // Unset fields must not leak.
        assert!(!pairs.contains(&"lastModStartDate"));
    }
}
