use std::env;
use crate::cve::process_cve;
use crate::utils::save_to_json;

mod models;
mod epss;
mod cve;
mod kev;
mod utils;

#[tokio::main]
async fn main() -> Result<(), reqwest::Error> { 
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Usage: cve_aggregator <CVE-ID> [CVE-ID ...]");
        return Ok(());
    }

    let mut tasks = Vec::new();
    for cve_id in &args[1..] {
        let cve_id = cve_id.clone();
        tasks.push(tokio::spawn(async move {
            match process_cve(&cve_id).await {
                Ok(result) => Some(result),
                Err(e) => {
                    eprintln!("Error processing {}: {}", cve_id, e);
                    None
                }
            }
        }));
    }

    let mut results = Vec::new();
    for task in tasks {
        if let Some(result) = task.await.unwrap() {
            // Clone the result before pushing to avoid moving it
            results.push(result.clone());

            // Print result to console
            println!("\n--------------------------------------");
            println!("CVE ID: {}", result.cve_id);
            println!("Descriptions:");
            for desc in &result.descriptions {
                println!("- [{}] {}", desc.lang, desc.value);
            }

            println!("CVSS Scores:");
            for score in &result.cvss_scores {
                println!("- Score: {}, Severity: {}", score.score, score.severity.as_deref().unwrap_or("N/A"));
            }

            if let Some(epss) = &result.epss_data {
                println!("EPSS Data:");
                for epss_data in &epss.data {
                    println!("- EPSS: {}, Percentile: {}, Date: {}", epss_data.epss, epss_data.percentile, epss_data.date);
                }
            }

            if let Some(kev) = &result.kev_data {
                println!("KEV Data:");
                println!("- CVE ID: {}", kev.cve_id);
                println!("- Date Added: {}", kev.date_added);
                println!("- Short Description: {}", kev.short_description);
                println!("- Required Action: {}", kev.required_action);
            }

            println!("--------------------------------------");
        }
    }

    if !results.is_empty() {
        match save_to_json(&results) {
            Ok(_) => println!("Results saved to JSON file."),
            Err(e) => eprintln!("Error saving results to JSON: {}", e),
        }
    }

    Ok(())
}
