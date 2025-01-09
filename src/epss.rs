use reqwest::Error;
use crate::models::{EpssResponse};

pub async fn fetch_epss_data(cve_id: &str) -> Result<Option<EpssResponse>, Error> {
    let epss_url = format!("https://api.first.org/data/v1/epss?cve={}", cve_id);
    let epss_response = reqwest::get(&epss_url).await?;

    if epss_response.status().is_success() {
        let epss_data: EpssResponse = epss_response.json().await?;
        Ok(Some(epss_data))
    } else {
        Ok(None)
    }
}