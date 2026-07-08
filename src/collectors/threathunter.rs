use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;

use crate::collectors::{Collector, CollectorCategory};
use crate::config::Config;
use crate::error::Result;
use crate::models::{Finding, SubdomainFinding, Target};

pub struct ThreatHunterCollector;

#[derive(Debug, Deserialize)]
struct ThreatHunterResponse {
    #[serde(default)]
    subdomains: Vec<String>,
}

#[async_trait]
impl Collector for ThreatHunterCollector {
    fn name(&self) -> &str {
        "threathunter"
    }

    fn category(&self) -> CollectorCategory {
        CollectorCategory::ThreatIntel
    }

    fn requires_api_key(&self) -> bool {
        false
    }

    async fn collect(&self, target: &Target, _config: &Config) -> Result<Vec<Finding>> {
        let url = format!(
            "https://api.threathunter.io/v1/subdomains/{}",
            target.domain
        );

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let resp = client.get(&url).send().await?;
        if !resp.status().is_success() {
            return Ok(Vec::new());
        }

        let data: ThreatHunterResponse = match resp.json().await {
            Ok(d) => d,
            Err(_) => return Ok(Vec::new()),
        };

        let findings: Vec<Finding> = data
            .subdomains
            .into_iter()
            .filter(|s| s.ends_with(&target.domain))
            .map(|s| {
                let mut f = SubdomainFinding::new(s.to_lowercase(), "threathunter".to_string());
                f.discovered_at = Utc::now();
                Finding::Subdomain(f)
            })
            .collect();

        Ok(findings)
    }
}
