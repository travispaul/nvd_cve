//! End-to-end sync test for the NVD 2.0 pipeline.
//!
//! Uses a fake HTTP client backed by a real NVD 2.0 response fixture (the
//! infamous xz / liblzma backdoor, `CVE-2024-3094`). This exercises the full
//! flow `client → cache → search`, including pagination short-circuiting,
//! description extraction and round-tripping through SQLite.

use nvd_cve::cache::{get_all, search_by_id, search_description, sync_blocking, CacheConfig};
use nvd_cve::client::{BlockingHttpClient, CveQuery, HttpError};
use nvd_cve::cve::CveResponse;
use nvd_cve::feed::Feed;
use std::cell::RefCell;
use std::{env, fs};

const FIXTURE: &str = include_str!("files/nvdcve-2.0-xz.json");

/// In-memory NVD stand-in: returns the fixture once on `start_index == 0`
/// then an empty page, so pagination terminates after one call regardless
/// of the date slicing scheme the cache uses.
struct FakeNvd {
    body: String,
    calls: RefCell<u32>,
}

impl FakeNvd {
    fn new(body: &str) -> Self {
        Self {
            body: body.to_string(),
            calls: RefCell::new(0),
        }
    }
}

impl BlockingHttpClient for FakeNvd {
    fn fetch_page(
        &self,
        _query: &CveQuery,
        start_index: u32,
        _page_size: u32,
    ) -> Result<CveResponse, HttpError> {
        *self.calls.borrow_mut() += 1;
        if start_index == 0 {
            Ok(serde_json::from_str::<CveResponse>(&self.body).expect("fixture parses"))
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

fn tmp_db(label: &str) -> String {
    let mut path = env::temp_dir();
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    path.push(format!(
        "nvd_cve_it_{label}_{}_{stamp}.sqlite3",
        std::process::id()
    ));
    path.to_string_lossy().into_owned()
}

#[test]
fn full_sync_with_real_2_0_fixture() {
    let db = tmp_db("xz");
    let config = CacheConfig {
        feeds: Feed::parse("2024").expect("year token"),
        db: db.clone(),
        show_progress: false,
        force_update: false,
    };
    let client = FakeNvd::new(FIXTURE);

    sync_blocking(&config, &client).expect("sync");

    let all = get_all(&config).expect("get_all");
    assert_eq!(all.len(), 1, "exactly one CVE in fixture");
    assert_eq!(all[0].id, "CVE-2024-3094");
    assert!(
        all[0]
            .description_en()
            .unwrap()
            .to_lowercase()
            .contains("liblzma"),
        "description should mention liblzma"
    );

    // Lookups by ID and substring should both find the record.
    let by_id = search_by_id(&config, "CVE-2024-3094").expect("by id");
    assert_eq!(by_id.id, "CVE-2024-3094");
    // NVD's official description for the xz backdoor uses "Malicious code"
    // and "liblzma" rather than the colloquial "backdoor".
    let hits = search_description(&config, "Malicious code").expect("description search");
    assert_eq!(hits, vec!["CVE-2024-3094".to_string()]);

    // CVSS metric extraction should pick a real score (xz backdoor is rated
    // 10.0 critical on v3.1 by NVD).
    assert_eq!(all[0].severity(), Some("CRITICAL"));
    assert!(all[0].base_score().unwrap() > 9.0);

    // The fixture is the whole year's worth so the year feed should resolve
    // to four 120-day slices, each issuing one fetch_page (the FakeNvd
    // returns one empty follow-up but pagination terminates on size 0).
    assert!(
        *client.calls.borrow() >= 4,
        "year feed should hit at least 4 slices"
    );

    let _ = fs::remove_file(&db);
}
