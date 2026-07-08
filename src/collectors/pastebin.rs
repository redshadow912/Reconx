use async_trait::async_trait;
use chrono::Utc;

use crate::collectors::{Collector, CollectorCategory};
use crate::config::Config;
use crate::error::Result;
use crate::models::{CredentialFinding, Finding, Target};
use crate::models::finding::Severity;

pub struct PastebinCollector;

#[async_trait]
impl Collector for PastebinCollector {
    fn name(&self) -> &str {
        "pastebin"
    }

    fn category(&self) -> CollectorCategory {
        CollectorCategory::CodeDocLeaks
    }

    fn requires_api_key(&self) -> bool {
        false
    }

    async fn collect(&self, target: &Target, _config: &Config) -> Result<Vec<Finding>> {
        let url = format!(
            "https://psbdmp.ws/api/search/{}",
            target.domain
        );

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let resp = client.get(&url).send().await?;
        if !resp.status().is_success() {
            return Ok(Vec::new());
        }

        let body: serde_json::Value = resp.json().await?;
        let mut findings = Vec::new();

        if let Some(data) = body.get("data").and_then(|d| d.as_array()) {
            for item in data {
                let paste_id = item
                    .get("id")
                    .and_then(|i| i.as_str())
                    .unwrap_or("unknown");

                let mut f = CredentialFinding::new(
                    target.domain.clone(),
                    format!("pastebin:{}", paste_id),
                    "pastebin".to_string(),
                );
                f.severity = Severity::Medium;
                f.details = Some(format!("https://pastebin.com/{}", paste_id));
                f.data_types = vec!["paste_leak".to_string()];
                f.discovered_at = Utc::now();
                findings.push(Finding::Credential(f));
            }
        }

        Ok(findings)
    }
}
