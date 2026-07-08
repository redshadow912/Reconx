use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;

use crate::collectors::{Collector, CollectorCategory};
use crate::config::Config;
use crate::error::Result;
use crate::models::{Finding, SubdomainFinding, Target};

pub struct AnubisCollector;

#[derive(Debug, Deserialize)]
struct AnubisResponse {
    #[serde(default)]
    subdomains: Vec<String>,
}

#[async_trait]
impl Collector for AnubisCollector {
    fn name(&self) -> &str {
        "anubis"
    }

    fn category(&self) -> CollectorCategory {
        CollectorCategory::DnsSubdomain
    }

    fn requires_api_key(&self) -> bool {
        false
    }

    async fn collect(&self, target: &Target, _config: &Config) -> Result<Vec<Finding>> {
        let url = format!(
            "https://jldc.me/anubis/subdomains/{}",
            target.domain
        );

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let resp = client.get(&url).send().await?;
        if !resp.status().is_success() {
            return Ok(Vec::new());
        }

        let subdomains: Vec<String> = match resp.json().await {
            Ok(s) => s,
            Err(_) => return Ok(Vec::new()),
        };

        let findings: Vec<Finding> = subdomains
            .into_iter()
            .filter(|s| s.ends_with(&target.domain))
            .map(|s| {
                let mut f = SubdomainFinding::new(s.to_lowercase(), "anubis".to_string());
                f.discovered_at = Utc::now();
                Finding::Subdomain(f)
            })
            .collect();

        Ok(findings)
    }
}
