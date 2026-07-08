use std::path::Path;

use crate::error::Result;
use crate::models::Finding;

pub fn generate(findings: &[Finding], output_path: &Path) -> Result<()> {
    let json_path = output_path.join("findings.json");
    let json_content = serde_json::to_string_pretty(findings)?;
    std::fs::write(&json_path, json_content)?;
    Ok(())
}
