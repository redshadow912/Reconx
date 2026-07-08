use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;

use crate::collectors::{Collector, CollectorCategory};
use crate::config::Config;
use crate::error::{ReconxError, Result};
use crate::models::{CredentialFinding, Finding, SubdomainFinding, Target};
use crate::models::finding::Severity;

pub struct IntelXCollector;

#[derive(Debug, Deserialize)]
struct IntelXSearchResponse {
    #[serde(default)]
    id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IntelXResultResponse {
    #[serde(default)]
    records: Vec<IntelXRecord>,
}

#[derive(Debug, Deserialize)]
struct IntelXRecord {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    type_field: Option<u32>,
}

#[async_trait]
impl Collector for IntelXCollector {
    fn name(&self) -> &str {
        "intelx"
    }

    fn category(&self) -> CollectorCategory {
        CollectorCategory::ThreatIntel
    }

    fn requires_api_key(&self) -> bool {
        true
    }

    async fn collect(&self, target: &Target, config: &Config) -> Result<Vec<Finding>> {
        let api_key = config
            .get_api_key("intelx")
            .ok_or(ReconxError::MissingApiKey {
                collector: "intelx".to_string(),
            })?
            .clone();

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let search_url = format!(
            "https://2.intelx.io/phonebook/search?k={}",
            api_key
        );

        let body = serde_json::json!({
            "term": target.domain,
            "buckets": ["pastes", "darknet", "leaks.public", "leaks.private"],
            "lookuplevel": 0,
            "maxresults": 100,
            "timeout": 5,
            "datefrom": "",
            "dateto": "",
            "sort": 4,
            "media": 0
        });

        let resp = client
            .post(&search_url)
            .header("x-key", &api_key)
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            return Ok(Vec::new());
        }

        let search_data: IntelXSearchResponse = resp.json().await?;
        let search_id = match search_data.id {
            Some(id) => id,
            None => return Ok(Vec::new()),
        };

        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        let results_url = format!(
            "https://2.intelx.io/phonebook/search/result?id={}&k={}&limit=100",
            search_id, api_key
        );

        let resp = client.get(&results_url).send().await?;
        if !resp.status().is_success() {
            return Ok(Vec::new());
        }

        let results: IntelXResultResponse = resp.json().await?;
        let mut findings = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for record in results.records {
            if let Some(name) = record.name {
                let name_lower = name.to_lowercase();
                if name_lower.ends_with(&target.domain) && !seen.contains(&name_lower) {
                    seen.insert(name_lower.clone());

                    if name_lower.contains("@") {
                        let mut f = CredentialFinding::new(
                            name_lower,
                            "intelx".to_string(),
                            "intelx".to_string(),
                        );
                        f.severity = Severity::High;
                        f.discovered_at = Utc::now();
                        findings.push(Finding::Credential(f));
                    } else {
                        let mut f = SubdomainFinding::new(name_lower, "intelx".to_string());
                        f.discovered_at = Utc::now();
                        findings.push(Finding::Subdomain(f));
                    }
                }
            }
        }

        Ok(findings)
    }
}
