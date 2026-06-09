//! Data model for NVD CVE records (NVD JSON 2.0 API).
//!
//! Schema reference: <https://nvd.nist.gov/developers/vulnerabilities>

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Top-level envelope returned by `GET /rest/json/cves/2.0`.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CveResponse {
    pub results_per_page: u32,
    pub start_index: u32,
    pub total_results: u32,
    #[serde(default)]
    pub format: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub timestamp: String,
    #[serde(default)]
    pub vulnerabilities: Vec<Vulnerability>,
}

/// Per-CVE wrapper inside the `vulnerabilities` array.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Vulnerability {
    pub cve: Cve,
}

/// A single CVE record (NVD 2.0 format).
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Cve {
    pub id: String,

    /// Email or UUID of the source that submitted the record (replaces
    /// `cve_data_meta.assigner` from the legacy 1.1 schema).
    #[serde(default)]
    pub source_identifier: String,

    /// ISO-8601 publication timestamp, e.g. `2014-04-07T22:55:03.893`.
    #[serde(default)]
    pub published: String,

    /// ISO-8601 last-modification timestamp.
    #[serde(default)]
    pub last_modified: String,

    /// Analysis state: `Received`, `Awaiting Analysis`, `Undergoing Analysis`,
    /// `Analyzed`, `Modified`, `Deferred`, `Rejected`.
    #[serde(default)]
    pub vuln_status: String,

    #[serde(default)]
    pub descriptions: Vec<LocalizedString>,

    #[serde(default)]
    pub references: Vec<Reference>,

    #[serde(default)]
    pub weaknesses: Vec<Weakness>,

    #[serde(default)]
    pub metrics: Metrics,

    /// CPE configurations are kept as raw JSON: the tree (operators, version
    /// ranges, vendor/product matching) is deep and rarely needed in a TUI.
    /// Consumers that want typed access can deserialize further.
    #[serde(default)]
    pub configurations: Vec<Value>,

    /// Free-form tags introduced in NVD 2.0 (e.g. `disputed`, `unsupported-when-assigned`).
    #[serde(default)]
    pub cve_tags: Vec<Value>,
}

/// A `{lang, value}` pair used for descriptions and weakness names.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LocalizedString {
    pub lang: String,
    pub value: String,
}

/// External reference URL with the source that supplied it and optional tags
/// (`Patch`, `Exploit`, `Third Party Advisory`, …).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Reference {
    pub url: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// CWE / weakness association attached to a CVE.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Weakness {
    #[serde(default)]
    pub source: String,
    /// Renamed to avoid shadowing Rust's `type` keyword.
    #[serde(default, rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub description: Vec<LocalizedString>,
}

/// Collection of CVSS scores; a CVE can carry multiple entries per scoring
/// system (typically one `Primary` and zero-or-more `Secondary`).
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct Metrics {
    #[serde(default)]
    pub cvss_metric_v40: Vec<MetricEntry>,
    #[serde(default)]
    pub cvss_metric_v31: Vec<MetricEntry>,
    #[serde(default)]
    pub cvss_metric_v30: Vec<MetricEntry>,
    #[serde(default)]
    pub cvss_metric_v2: Vec<MetricEntry>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MetricEntry {
    #[serde(default)]
    pub source: String,
    #[serde(default, rename = "type")]
    pub kind: String,
    pub cvss_data: CvssData,
    /// Present only on CVSS v2 entries (where NVD places `baseSeverity`
    /// alongside `cvssData` rather than inside it).
    #[serde(default)]
    pub base_severity: Option<String>,
    #[serde(default)]
    pub exploitability_score: Option<f32>,
    #[serde(default)]
    pub impact_score: Option<f32>,
}

impl MetricEntry {
    /// Severity label, looking at both NVD placements:
    /// `cvssData.baseSeverity` (v3.x / v4.0) or the entry-level fallback (v2).
    pub fn severity(&self) -> Option<&str> {
        self.cvss_data
            .base_severity
            .as_deref()
            .or(self.base_severity.as_deref())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CvssData {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub vector_string: String,
    pub base_score: f32,
    /// `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` on CVSS v3.x and v4.0.
    /// NVD omits this in v2 entries — see `MetricEntry::severity()`.
    #[serde(default)]
    pub base_severity: Option<String>,
}

impl Cve {
    /// First English description, or `None` if no `en` entry exists.
    pub fn description_en(&self) -> Option<&str> {
        self.descriptions
            .iter()
            .find(|d| d.lang == "en")
            .map(|d| d.value.as_str())
    }

    /// Highest-precedence CVSS base score: v4.0 → v3.1 → v3.0 → v2.0.
    pub fn base_score(&self) -> Option<f32> {
        self.primary_metric().map(|m| m.cvss_data.base_score)
    }

    /// Highest-precedence severity label, matching `base_score()` ordering.
    pub fn severity(&self) -> Option<&str> {
        self.primary_metric().and_then(|m| m.severity())
    }

    fn primary_metric(&self) -> Option<&MetricEntry> {
        self.metrics
            .cvss_metric_v40
            .first()
            .or_else(|| self.metrics.cvss_metric_v31.first())
            .or_else(|| self.metrics.cvss_metric_v30.first())
            .or_else(|| self.metrics.cvss_metric_v2.first())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Trimmed NVD 2.0 response covering the field placements that differ
    /// from the legacy 1.1 schema (camelCase keys, severity at two depths,
    /// optional metric scoring systems).
    const SAMPLE: &str = r#"{
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": "2026-06-09T10:45:24.150",
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2014-0160",
                "sourceIdentifier": "secalert@redhat.com",
                "published": "2014-04-07T22:55:03.893",
                "lastModified": "2026-04-21T20:07:16.693",
                "vulnStatus": "Analyzed",
                "descriptions": [
                    {"lang": "en", "value": "Heartbleed"},
                    {"lang": "es", "value": "Heartbleed (es)"}
                ],
                "metrics": {
                    "cvssMetricV31": [{
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/...", "baseScore": 7.5, "baseSeverity": "HIGH"},
                        "exploitabilityScore": 3.9,
                        "impactScore": 3.6
                    }],
                    "cvssMetricV2": [{
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "cvssData": {"version": "2.0", "vectorString": "AV:N/...", "baseScore": 5.0},
                        "baseSeverity": "MEDIUM",
                        "exploitabilityScore": 10.0,
                        "impactScore": 2.9
                    }]
                },
                "weaknesses": [{
                    "source": "nvd@nist.gov", "type": "Primary",
                    "description": [{"lang": "en", "value": "CWE-125"}]
                }],
                "references": [
                    {"url": "https://heartbleed.com/", "source": "secalert@redhat.com", "tags": ["Third Party Advisory"]}
                ]
            }
        }]
    }"#;

    #[test]
    fn parses_2_0_response_envelope() {
        let resp: CveResponse = serde_json::from_str(SAMPLE).expect("parse envelope");
        assert_eq!(resp.results_per_page, 1);
        assert_eq!(resp.total_results, 1);
        assert_eq!(resp.format, "NVD_CVE");
        assert_eq!(resp.vulnerabilities.len(), 1);
    }

    #[test]
    fn maps_core_cve_fields() {
        let resp: CveResponse = serde_json::from_str(SAMPLE).unwrap();
        let cve = &resp.vulnerabilities[0].cve;
        assert_eq!(cve.id, "CVE-2014-0160");
        assert_eq!(cve.source_identifier, "secalert@redhat.com");
        assert_eq!(cve.vuln_status, "Analyzed");
        assert_eq!(cve.description_en(), Some("Heartbleed"));
        assert_eq!(cve.references.len(), 1);
        assert_eq!(cve.references[0].url, "https://heartbleed.com/");
        assert_eq!(cve.references[0].tags, vec!["Third Party Advisory"]);
    }

    #[test]
    fn picks_highest_precedence_score_and_severity() {
        let resp: CveResponse = serde_json::from_str(SAMPLE).unwrap();
        let cve = &resp.vulnerabilities[0].cve;
        // v3.1 wins over v2 even though both are present.
        assert_eq!(cve.base_score(), Some(7.5));
        assert_eq!(cve.severity(), Some("HIGH"));
    }

    #[test]
    fn handles_v2_severity_placement() {
        let resp: CveResponse = serde_json::from_str(SAMPLE).unwrap();
        let v2 = &resp.vulnerabilities[0].cve.metrics.cvss_metric_v2[0];
        assert!(v2.cvss_data.base_severity.is_none());
        assert_eq!(v2.base_severity.as_deref(), Some("MEDIUM"));
        assert_eq!(v2.severity(), Some("MEDIUM"));
    }

    #[test]
    fn round_trips_via_serde_json() {
        // The cache stores `serde_json::to_string(&cve)`; deserializing back
        // must preserve fields, otherwise sync→read would silently drop data.
        let resp: CveResponse = serde_json::from_str(SAMPLE).unwrap();
        let cve = &resp.vulnerabilities[0].cve;
        let json = serde_json::to_string(cve).unwrap();
        let back: Cve = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, cve.id);
        assert_eq!(back.base_score(), cve.base_score());
        assert_eq!(back.severity(), cve.severity());
        assert_eq!(back.description_en(), cve.description_en());
    }

    #[test]
    fn tolerates_sparse_records() {
        // Rejected / placeholder CVEs sometimes carry only id + status.
        let bare = r#"{"id":"CVE-2099-0001","vulnStatus":"Rejected"}"#;
        let cve: Cve = serde_json::from_str(bare).unwrap();
        assert_eq!(cve.id, "CVE-2099-0001");
        assert_eq!(cve.description_en(), None);
        assert_eq!(cve.base_score(), None);
        assert!(cve.references.is_empty());
    }
}
