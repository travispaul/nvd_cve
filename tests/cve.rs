use std::fs;

mod util;

use nvd_cve::cve::CveFeed;
use util::MockBlockingClient;

#[test]
fn test_get_feed_from_client() {
    let mut client = MockBlockingClient::default();

    let body = fs::read_to_string("./tests/files/nvdcve-1.1-recent.json")
        .expect("Failed reading feed json");

    let cve_feed: CveFeed = serde_json::from_str(&*body).expect("Failed parsing cve feed json");
    client.get_feed_response = Ok(cve_feed);

    if let Err(error) = CveFeed::from_blocking_http_client(&client, "recent") {
        assert!(false, "Failed fetching CveFeed: {:?}", error);
    }
}
