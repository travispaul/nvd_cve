use crate::client::{BlockingHttpClient, HttpError};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CveMeta {
    #[serde(alias = "ID")]
    pub id: String,
    #[serde(alias = "ASSIGNER")]
    pub assigner: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProblemTypeData {
    pub description: Vec<Value>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProblemType {
    #[serde(alias = "problemtype_data")]
    pub problem_type_data: Vec<ProblemTypeData>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct References {
    pub reference_data: Vec<ReferenceData>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ReferenceData {
    pub url: String,
    pub name: String,

    #[serde(alias = "refsource")]
    pub ref_source: String,
    pub tags: Vec<Value>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Description {
    pub description_data: Vec<DescriptionData>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DescriptionData {
    pub lang: String,
    pub value: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Configuration {
    #[serde(alias = "CVE_data_version")]
    pub cve_data_version: String,
    pub nodes: Vec<Value>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Cve {
    pub data_type: String,
    pub data_format: String,
    pub data_version: String,

    #[serde(alias = "CVE_data_meta")]
    pub cve_data_meta: CveMeta,

    #[serde(alias = "problemtype")]
    pub problem_type: ProblemType,

    pub references: References,
    pub description: Description,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CveContainer {
    pub cve: Cve,
    pub configurations: Configuration,
    pub impact: Value,

    #[serde(alias = "publishedDate")]
    pub published_date: String,

    #[serde(alias = "lastModifiedDate")]
    pub last_modified_date: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CveFeed {
    #[serde(alias = "CVE_data_type")]
    pub cve_data_type: String,

    #[serde(alias = "CVE_data_format")]
    pub cve_data_format: String,

    #[serde(alias = "CVE_data_version")]
    pub cve_data_version: String,

    #[serde(alias = "CVE_data_numberOfCVEs")]
    pub cve_data_number_of_cves: String,

    #[serde(alias = "CVE_data_timestamp")]
    pub cve_data_timestamp: String,

    #[serde(alias = "CVE_Items")]
    pub cve_items: Vec<CveContainer>,
}

/// Errors related to parsing a CVE Feed
#[derive(Debug)]
pub enum CveFeedError {
    FetchError(HttpError),
}

impl CveFeed {
    pub fn from_blocking_http_client<C: BlockingHttpClient>(
        client: &C,
        name: &str,
    ) -> Result<Self, HttpError> {
        client.get_feed(name)
    }
}
