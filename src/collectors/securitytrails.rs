use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;

use crate::collectors::{Collector, CollectorCategory};
use crate::config::Config;
use crate::error::{ReconxError, Result};
use crate::models::{Finding, SubdomainFinding, Target};

pub struct SecurityTrailsCollector;

#[derive(Debug, Deserialize)]
struct StResponse {
    #[serde(default)]
    subdomains: Vec<String>,
}

#[async_trait]
impl Collector for SecurityTrailsCollector {
    fn name(&self) -> &str {
        "securitytrails"
    }

    fn category(&self) -> CollectorCategory {
        CollectorCategory::DnsSubdomain
    }

    fn requires_api_key(&self) -> bool {
        true
    }

    async fn collect(&self, target: &Target, config: &Config) -> Result<Vec<Finding>> {
        let api_key = config
            .get_api_key("securitytrails")
            .ok_or(ReconxError::MissingApiKey {
                collector: "securitytrails".to_string(),
            })?
            .clone();

        let url = format!(
            "https://api.securitytrails.com/v1/domain/{}/subdomains",
            target.domain
        );

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let resp = client
            .get(&url)
            .header("APIKEY", &api_key)
            .send()
            .await?;

        if !resp.status().is_success() {
            return Ok(Vec::new());
        }

        let data: StResponse = resp.json().await?;
        let findings: Vec<Finding> = data
            .subdomains
            .into_iter()
            .map(|s| {
                let subdomain = format!("{}.{}", s.to_lowercase(), target.domain);
                let mut f = SubdomainFinding::new(subdomain, "securitytrails".to_string());
                f.discovered_at = Utc::now();
                Finding::Subdomain(f)
            })
            .collect();

        Ok(findings)
    }
}
