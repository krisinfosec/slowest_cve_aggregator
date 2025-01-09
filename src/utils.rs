use crate::models::CveResult;  // Importing CveResult from models.rs
use std::fs::File;
use std::io::{self};

pub fn save_to_json(results: &[CveResult]) -> io::Result<()> {
    let filename = format!(
        "{}.json",
        results.iter().map(|r| r.cve_id.clone()).collect::<Vec<_>>().join("_")
    );
    let file = File::create(&filename)?;
    serde_json::to_writer_pretty(file, &results)?;
    Ok(())
}
