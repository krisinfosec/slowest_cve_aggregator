use reqwest::Error;
use crate::models::{CveData, CveResult, CvssScore};
use crate::epss::fetch_epss_data;
use crate::kev::fetch_kev_data;

pub async fn process_cve(cve_id: &str) -> Result<CveResult, Error> {
    let url = format!("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}", cve_id);
    let response = reqwest::get(&url).await?;
    
    let cve_data: CveData = response.json().await?;

    let mut result = CveResult {
        cve_id: cve_id.to_string(),
        descriptions: Vec::new(),
        cvss_scores: Vec::new(),
        epss_data: None,
        kev_data: None,
    };

    if let Some(vuln) = cve_data.vulnerabilities.get(0) {
        result.descriptions = vuln.cve.descriptions.clone();
        if let Some(cvss_metrics) = &vuln.cve.metrics.cvss_metric_v31 {
            for metric in cvss_metrics {
                let cvss_data = &metric.cvss_data;
                result.cvss_scores.push(CvssScore {
                    score: cvss_data.base_score,
                    severity: cvss_data.base_severity.clone(),
                });
            }
        }
    }

    if let Some(epss) = fetch_epss_data(cve_id).await? {
        result.epss_data = Some(epss);
    }

    if let Some(kev_data) = fetch_kev_data().await? {
        result.kev_data = kev_data.vulnerabilities.iter().find(|vuln| vuln.cve_id == *cve_id).cloned();
    }

    Ok(result)
}