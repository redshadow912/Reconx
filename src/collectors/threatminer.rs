use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;

use crate::collectors::{Collector, CollectorCategory};
use crate::config::Config;
use crate::error::Result;
use crate::models::{Finding, SubdomainFinding, Target};

pub struct ThreatMinerCollector;

#[derive(Debug, Deserialize)]
struct ThreatMinerResponse {
    #[serde(default)]
    results: Option<Vec<String>>,
    #[serde(default)]
    status_code: Option<String>,
}

#[async_trait]
impl Collector for ThreatMinerCollector {
    fn name(&self) -> &str {
        "threatminer"
    }

    fn category(&self) -> CollectorCategory {
        CollectorCategory::ThreatIntel
    }

    fn requires_api_key(&self) -> bool {
        false
    }

    async fn collect(&self, target: &Target, _config: &Config) -> Result<Vec<Finding>> {
        let url = format!(
            "https://api.threatminer.org/v2/domain.php?q={}&api=True&rt=5",
            target.domain
        );

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let resp = client.get(&url).send().await?;
        if !resp.status().is_success() {
            return Ok(Vec::new());
        }

        let data: ThreatMinerResponse = match resp.json().await {
            Ok(d) => d,
            Err(_) => return Ok(Vec::new()),
        };

        let findings: Vec<Finding> = data
            .results
            .unwrap_or_default()
            .into_iter()
            .filter(|s| s.ends_with(&target.domain))
            .map(|s| {
                let mut f = SubdomainFinding::new(s.to_lowercase(), "threatminer".to_string());
                f.discovered_at = Utc::now();
                Finding::Subdomain(f)
            })
            .collect();

        Ok(findings)
    }
}
