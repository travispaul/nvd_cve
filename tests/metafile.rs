use nvd_cve::feed::{Metafile, MetafileError};
use std::fs;

mod util;

use util::MockBlockingClient;

#[test]
fn test_parsing_metafile_from_file() {
    let metafile = Metafile::from_file("./tests/files/nvdcve-1.1-recent.meta")
        .expect("Failed to parse metafile");
    assert_eq!(metafile.format_last_modified_date(), "2021-12-18T19:00:00");
    assert_eq!(metafile.size, 1744779);
    assert_eq!(metafile.zip_size, 116171);
    assert_eq!(metafile.gz_size, 116031);
    assert_eq!(
        metafile.sha256,
        "0EA38A9771747DD51A3E009FB8738732144266C4EF4EDC548B70F33555CC1586"
    );
}

#[test]
fn test_parsing_metafile_from_file_split_error() {
    if let Err(e) = Metafile::from_file("./tests/files/nvdcve-1.1-recent.meta.broken_split") {
        match e {
            MetafileError::SplitError => (),
            _ => assert!(false, "Should have returned SplitError"),
        }
    } else {
        assert!(false, "Splitting line should have failed");
    }
}

#[test]
fn test_parsing_metafile_from_file_line_error() {
    if let Err(e) = Metafile::from_file("./tests/files/nvdcve-1.1-recent.meta.broken_line") {
        match e {
            MetafileError::LineError => (),
            _ => assert!(false, "Should have returned LineError"),
        }
    } else {
        assert!(false, "Parsing file should have failed");
    }
}

#[test]
fn test_parsing_metafile_from_file_parse_error() {
    if let Err(e) = Metafile::from_file("./tests/files/nvdcve-1.1-recent.meta.broken_parse") {
        match e {
            MetafileError::ParseIntError(_) => (),
            _ => assert!(false, "Should have returned ParseIntError"),
        }
    } else {
        assert!(false, "Parsing Int should have failed");
    }
}

#[test]
fn test_parsing_metafile_from_file_parse_file_error() {
    if let Err(e) = Metafile::from_file("./tests/files/nope") {
        match e {
            MetafileError::FileError(_) => (),
            _ => assert!(false, "Should have returned FileError"),
        }
    } else {
        assert!(false, "Opening file should have failed");
    }
}

#[test]
fn test_parsing_metafile_from_url_blocking() {
    let mut client = MockBlockingClient::default();

    let body = fs::read_to_string("./tests/files/nvdcve-1.1-recent.meta")
        .expect("Failed reading metafile");

    client.get_metafile_response = Ok(body);

    let metafile =
        Metafile::from_blocking_http_client(&client, "recent").expect("Failed to parse metafile");

    assert_eq!(metafile.format_last_modified_date(), "2021-12-18T19:00:00");
    assert_eq!(metafile.size, 1744779);
    assert_eq!(metafile.zip_size, 116171);
    assert_eq!(metafile.gz_size, 116031);
    assert_eq!(
        metafile.sha256,
        "0EA38A9771747DD51A3E009FB8738732144266C4EF4EDC548B70F33555CC1586"
    );
}
