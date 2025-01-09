use serde::{Deserialize, Serialize};

#[derive(Deserialize, Debug, Clone)]
pub struct CveData {
    pub vulnerabilities: Vec<Vulnerability>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Vulnerability {
    pub cve: CveDetails,
}

#[derive(Deserialize, Debug, Serialize, Clone)]
pub struct CveDetails {
    pub id: String,
    pub descriptions: Vec<Description>,
    pub metrics: Metrics,
}

#[derive(Deserialize, Debug, Serialize, Clone)]
pub struct Description {
    pub lang: String,
    pub value: String,
}

#[derive(Deserialize, Debug, Serialize, Clone)]
pub struct Metrics {
    #[serde(rename = "cvssMetricV31")]
    pub cvss_metric_v31: Option<Vec<CvssMetric>>,
}

#[derive(Deserialize, Debug, Serialize, Clone)]
pub struct CvssMetric {
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(rename = "cvssData")]
    pub cvss_data: CvssData,
}

#[derive(Deserialize, Debug, Serialize, Clone)]
pub struct CvssData {
    #[serde(rename = "baseScore")]
    pub base_score: f32,
    #[serde(rename = "baseSeverity")]
    pub base_severity: Option<String>,
}

#[derive(Deserialize, Debug, Serialize, Clone)]
pub struct KevVulnerability {
    #[serde(rename = "cveID")]
    pub cve_id: String,
    #[serde(rename = "dateAdded")]
    pub date_added: String,
    #[serde(rename = "shortDescription")]
    pub short_description: String,
    #[serde(rename = "requiredAction")]
    pub required_action: String,
}

#[derive(Serialize, Clone)]
pub struct CveResult {
    pub cve_id: String,
    pub descriptions: Vec<Description>,
    pub cvss_scores: Vec<CvssScore>,
    pub epss_data: Option<EpssResponse>,
    pub kev_data: Option<KevVulnerability>,
}

#[derive(Serialize, Clone)]
pub struct CvssScore {
    pub score: f32,
    pub severity: Option<String>,
}

#[derive(Deserialize, Debug, Serialize, Clone)]
pub struct EpssResponse {
    pub status: String,
    pub data: Vec<EpssData>,
}

#[derive(Deserialize, Debug, Serialize, Clone)]
pub struct EpssData {
    pub epss: String,
    pub percentile: String,
    pub date: String,
}

#[derive(Deserialize, Debug, Serialize, Clone)]
pub struct KevResponse {
    pub vulnerabilities: Vec<KevVulnerability>,
}