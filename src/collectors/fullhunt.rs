use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;

use crate::collectors::{Collector, CollectorCategory};
use crate::config::Config;
use crate::error::{ReconxError, Result};
use crate::models::{Finding, SubdomainFinding, Target};

pub struct FullHuntCollector;

#[derive(Debug, Deserialize)]
struct FullHuntResponse {
    #[serde(default)]
    hosts: Vec<String>,
}

#[async_trait]
impl Collector for FullHuntCollector {
    fn name(&self) -> &str {
        "fullhunt"
    }

    fn category(&self) -> CollectorCategory {
        CollectorCategory::ThreatIntel
    }

    fn requires_api_key(&self) -> bool {
        true
    }

    async fn collect(&self, target: &Target, config: &Config) -> Result<Vec<Finding>> {
        let api_key = config
            .get_api_key("fullhunt")
            .ok_or(ReconxError::MissingApiKey {
                collector: "fullhunt".to_string(),
            })?
            .clone();

        let url = format!(
            "https://fullhunt.io/api/v1/domain/{}/subdomains",
            target.domain
        );

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let resp = client
            .get(&url)
            .header("X-API-KEY", &api_key)
            .send()
            .await?;

        if !resp.status().is_success() {
            return Ok(Vec::new());
        }

        let data: FullHuntResponse = resp.json().await?;
        let findings: Vec<Finding> = data
            .hosts
            .into_iter()
            .filter(|s| s.ends_with(&target.domain))
            .map(|s| {
                let mut f = SubdomainFinding::new(s.to_lowercase(), "fullhunt".to_string());
                f.discovered_at = Utc::now();
                Finding::Subdomain(f)
            })
            .collect();

        Ok(findings)
    }
}
