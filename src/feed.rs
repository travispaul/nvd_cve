//! Feed selection and date-range slicing.
//!
//! A *feed* is a named bucket of CVEs to sync: a year (`"2024"`), the last
//! week of new publications (`"recent"`), or the last week of modifications
//! (`"modified"`). Each feed turns into one or more [`CveQuery`] slices —
//! sliced so that no single slice spans more than 120 days, which is NVD's
//! cap on `pubStart/EndDate` and `lastModStart/EndDate` filters.

use crate::client::CveQuery;
use chrono::{DateTime, Duration, NaiveDate, NaiveDateTime, NaiveTime, Utc};

/// Default lookback used by the `recent` and `modified` shortcuts (matches the
/// span of the retired NVD 1.1 `nvdcve-1.1-recent.json.gz` / `-modified.json.gz`
/// feeds, which covered ~8 days).
pub const RECENT_LOOKBACK_DAYS: i64 = 8;

#[derive(Debug, Clone)]
pub enum FeedError {
    /// A `YYYY:YYYY` range had malformed or reversed bounds.
    BadRange(String),
    /// A token did not match any known feed shape.
    Unknown(String),
}

impl std::fmt::Display for FeedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FeedError::BadRange(token) => {
                write!(
                    f,
                    "invalid year range `{token}`: expected `YYYY:YYYY` with start ≤ end"
                )
            }
            FeedError::Unknown(token) => write!(f, "unknown feed token `{token}`"),
        }
    }
}

impl std::error::Error for FeedError {}

/// Kind of feed bucket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeedKind {
    /// All CVEs published in a given calendar year (UTC).
    Year(i32),
    /// CVEs published in the last `RECENT_LOOKBACK_DAYS` days.
    Recent,
    /// CVEs modified in the last `RECENT_LOOKBACK_DAYS` days.
    Modified,
}

/// A named sync target. The `name` is what users typed (`"2024"`, `"recent"`,
/// `"modified"`) — kept verbatim so cache state and progress bars stay
/// human-readable.
#[derive(Debug, Clone)]
pub struct Feed {
    pub name: String,
    pub kind: FeedKind,
}

impl Feed {
    /// Parse a single CLI token into one or more feeds.
    ///
    /// - `"2024"` → `[Feed { Year(2024) }]`
    /// - `"2002:2024"` → 23 yearly feeds
    /// - `"recent"` / `"modified"` → the matching shortcut
    ///
    /// Unknown tokens return `FeedError::Unknown`. Reversed ranges return
    /// `FeedError::BadRange`.
    pub fn parse(token: &str) -> Result<Vec<Feed>, FeedError> {
        let trimmed = token.trim();
        if trimmed.eq_ignore_ascii_case("recent") {
            return Ok(vec![Feed {
                name: "recent".into(),
                kind: FeedKind::Recent,
            }]);
        }
        if trimmed.eq_ignore_ascii_case("modified") {
            return Ok(vec![Feed {
                name: "modified".into(),
                kind: FeedKind::Modified,
            }]);
        }
        if let Some((lhs, rhs)) = trimmed.split_once(':') {
            let start: i32 = lhs
                .parse()
                .map_err(|_| FeedError::BadRange(token.to_string()))?;
            let end: i32 = rhs
                .parse()
                .map_err(|_| FeedError::BadRange(token.to_string()))?;
            if start > end {
                return Err(FeedError::BadRange(token.to_string()));
            }
            return Ok((start..=end)
                .map(|y| Feed {
                    name: y.to_string(),
                    kind: FeedKind::Year(y),
                })
                .collect());
        }
        if let Ok(year) = trimmed.parse::<i32>() {
            return Ok(vec![Feed {
                name: year.to_string(),
                kind: FeedKind::Year(year),
            }]);
        }
        Err(FeedError::Unknown(token.to_string()))
    }

    /// Build the list of NVD queries needed to fetch this feed, given the
    /// current wall clock. Each returned [`CveQuery`] is guaranteed to span
    /// at most [`MAX_RANGE_DAYS`](crate::client::MAX_RANGE_DAYS) days.
    pub fn to_queries(&self, now: DateTime<Utc>) -> Vec<CveQuery> {
        match &self.kind {
            FeedKind::Year(year) => {
                let start = NaiveDate::from_ymd_opt(*year, 1, 1).expect("valid Jan 1");
                // Clamp the end to "now" so we don't ask for the future when
                // syncing the current year.
                let raw_end = NaiveDate::from_ymd_opt(*year, 12, 31).expect("valid Dec 31");
                let end = std::cmp::min(raw_end, now.date_naive());
                slice_published(start, end)
            }
            FeedKind::Recent => {
                let end = now.naive_utc();
                let start = end - Duration::days(RECENT_LOOKBACK_DAYS);
                vec![CveQuery {
                    pub_start_date: Some(format_nvd(start)),
                    pub_end_date: Some(format_nvd(end)),
                    ..CveQuery::default()
                }]
            }
            FeedKind::Modified => {
                let end = now.naive_utc();
                let start = end - Duration::days(RECENT_LOOKBACK_DAYS);
                vec![CveQuery {
                    last_mod_start_date: Some(format_nvd(start)),
                    last_mod_end_date: Some(format_nvd(end)),
                    ..CveQuery::default()
                }]
            }
        }
    }
}

/// Slice an inclusive published-date range into ≤120-day chunks.
fn slice_published(start: NaiveDate, end: NaiveDate) -> Vec<CveQuery> {
    let mut out = Vec::new();
    let mut cursor = start;
    while cursor <= end {
        // -1 because both endpoints are inclusive — a span of 120 days means
        // 120 calendar days, i.e. cursor + 119 days.
        let chunk_end = std::cmp::min(
            cursor + Duration::days(crate::client::MAX_RANGE_DAYS - 1),
            end,
        );
        let start_dt = NaiveDateTime::new(cursor, NaiveTime::from_hms_opt(0, 0, 0).unwrap());
        let end_dt = NaiveDateTime::new(
            chunk_end,
            NaiveTime::from_hms_milli_opt(23, 59, 59, 999).unwrap(),
        );
        out.push(CveQuery {
            pub_start_date: Some(format_nvd(start_dt)),
            pub_end_date: Some(format_nvd(end_dt)),
            ..CveQuery::default()
        });
        cursor = chunk_end + Duration::days(1);
    }
    out
}

/// NVD's preferred date format: `yyyy-MM-ddTHH:mm:ss.SSS`.
pub fn format_nvd(dt: NaiveDateTime) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S%.3f").to_string()
}

/// Parse a date string produced by [`format_nvd`] (or any ISO-8601 / RFC-3339
/// timestamp NVD might return).
pub fn parse_nvd(value: &str) -> Option<NaiveDateTime> {
    if let Ok(parsed) = NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S%.f") {
        return Some(parsed);
    }
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|d| d.naive_utc())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(year: i32, month: u32, day: u32) -> DateTime<Utc> {
        NaiveDate::from_ymd_opt(year, month, day)
            .unwrap()
            .and_hms_opt(12, 0, 0)
            .unwrap()
            .and_utc()
    }

    #[test]
    fn parses_single_year_and_range_and_shortcuts() {
        assert!(matches!(
            Feed::parse("2024").unwrap()[..],
            [Feed {
                kind: FeedKind::Year(2024),
                ..
            }]
        ));
        let range = Feed::parse("2002:2005").unwrap();
        let years: Vec<_> = range
            .iter()
            .filter_map(|f| match f.kind {
                FeedKind::Year(y) => Some(y),
                _ => None,
            })
            .collect();
        assert_eq!(years, vec![2002, 2003, 2004, 2005]);
        assert!(matches!(
            Feed::parse("RECENT").unwrap()[..],
            [Feed {
                kind: FeedKind::Recent,
                ..
            }]
        ));
        assert!(matches!(
            Feed::parse("modified").unwrap()[..],
            [Feed {
                kind: FeedKind::Modified,
                ..
            }]
        ));
    }

    #[test]
    fn rejects_bad_tokens() {
        assert!(matches!(
            Feed::parse("twenty24"),
            Err(FeedError::Unknown(_))
        ));
        assert!(matches!(
            Feed::parse("2024:2002"),
            Err(FeedError::BadRange(_))
        ));
        assert!(matches!(
            Feed::parse("abc:def"),
            Err(FeedError::BadRange(_))
        ));
    }

    #[test]
    fn year_feed_slices_into_four_chunks_under_120_days() {
        let feed = Feed {
            name: "2024".into(),
            kind: FeedKind::Year(2024),
        };
        let queries = feed.to_queries(at(2025, 6, 1));
        // 366 days (leap year) / 120-day windows → 4 slices.
        assert_eq!(queries.len(), 4);
        // Each slice must declare a published-date window and nothing else.
        for q in &queries {
            assert!(q.pub_start_date.is_some());
            assert!(q.pub_end_date.is_some());
            assert!(q.last_mod_start_date.is_none());
            assert!(q.cve_id.is_none());
        }
        // The slices must cover Jan 1 and Dec 31.
        let first_start = queries.first().unwrap().pub_start_date.as_deref().unwrap();
        let last_end = queries.last().unwrap().pub_end_date.as_deref().unwrap();
        assert!(first_start.starts_with("2024-01-01T00:00:00"));
        assert!(last_end.starts_with("2024-12-31T23:59:59"));
    }

    #[test]
    fn current_year_is_clamped_to_today() {
        // Asking for year 2025 mid-year should not request future dates.
        let feed = Feed {
            name: "2025".into(),
            kind: FeedKind::Year(2025),
        };
        let queries = feed.to_queries(at(2025, 3, 15));
        let last_end = queries.last().unwrap().pub_end_date.as_deref().unwrap();
        assert!(last_end.starts_with("2025-03-15"));
    }

    #[test]
    fn recent_uses_pub_dates_modified_uses_lastmod_dates() {
        let now = at(2026, 6, 9);
        let recent = Feed {
            name: "recent".into(),
            kind: FeedKind::Recent,
        }
        .to_queries(now);
        assert_eq!(recent.len(), 1);
        assert!(recent[0].pub_start_date.is_some());
        assert!(recent[0].last_mod_start_date.is_none());

        let modified = Feed {
            name: "modified".into(),
            kind: FeedKind::Modified,
        }
        .to_queries(now);
        assert_eq!(modified.len(), 1);
        assert!(modified[0].last_mod_start_date.is_some());
        assert!(modified[0].pub_start_date.is_none());
    }

    #[test]
    fn nvd_date_round_trip() {
        let now = NaiveDate::from_ymd_opt(2024, 7, 4)
            .unwrap()
            .and_hms_milli_opt(12, 34, 56, 789)
            .unwrap();
        let formatted = format_nvd(now);
        assert_eq!(formatted, "2024-07-04T12:34:56.789");
        assert_eq!(parse_nvd(&formatted), Some(now));
    }
}
