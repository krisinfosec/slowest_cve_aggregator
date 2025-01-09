use reqwest::Error;
use std::fs;
use std::path::Path;
use crate::models::KevResponse;

const KEV_FILE: &str = "known_exploited_vulnerabilities.json";

pub async fn download_kev_file() -> Result<(), Error> {
    let kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    let response = reqwest::get(kev_url).await?;
    let kev_content = response.text().await?;
    fs::write(KEV_FILE, kev_content).expect("Failed to save KEV JSON file");
    println!("Downloaded the latest KEV JSON file.");
    Ok(())
}

fn is_kev_file_outdated() -> bool {
    let path = Path::new(KEV_FILE);
    if !path.exists() {
        return true;
    }

    if let Ok(metadata) = fs::metadata(path) {
        if let Ok(modified) = metadata.modified() {
            if let Ok(elapsed) = modified.elapsed() {
                return elapsed > std::time::Duration::from_secs(24 * 60 * 60);
            }
        }
    }
    true
}

pub async fn fetch_kev_data() -> Result<Option<KevResponse>, Error> {
    if is_kev_file_outdated() {
        download_kev_file().await?;
    }

    let kev_content = fs::read_to_string(KEV_FILE).expect("Failed to read KEV JSON file");
    let kev_data: KevResponse = serde_json::from_str(&kev_content).expect("Failed to parse KEV JSON file");

    Ok(Some(kev_data))
}