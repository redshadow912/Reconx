use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;

use crate::collectors::{Collector, CollectorCategory};
use crate::config::Config;
use crate::error::{ReconxError, Result};
use crate::models::{Finding, SubdomainFinding, Target};

pub struct ChaosCollector;

#[derive(Debug, Deserialize)]
struct ChaosResponse {
    #[serde(default)]
    domain: String,
    #[serde(default)]
    subdomains: Vec<String>,
    #[serde(default)]
    count: u32,
}

#[async_trait]
impl Collector for ChaosCollector {
    fn name(&self) -> &str {
        "chaos"
    }

    fn category(&self) -> CollectorCategory {
        CollectorCategory::DnsSubdomain
    }

    fn requires_api_key(&self) -> bool {
        true
    }

    fn config_key(&self) -> &str {
        "chaos"
    }

    async fn collect(&self, target: &Target, config: &Config) -> Result<Vec<Finding>> {
        let api_key = config
            .get_api_key("chaos")
            .ok_or(ReconxError::MissingApiKey {
                collector: "chaos".to_string(),
            })?
            .clone();

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let url = format!(
            "https://dns.projectdiscovery.io/dns/{}/subdomains",
            target.domain
        );

        let resp = match client
            .get(&url)
            .header("Authorization", &api_key)
            .header("Connection", "close")
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => return Ok(Vec::new()),
        };

        if !resp.status().is_success() {
            return Ok(Vec::new());
        }

        let data: ChaosResponse = match resp.json().await {
            Ok(d) => d,
            Err(_) => return Ok(Vec::new()),
        };

        let mut findings = Vec::new();

        for sub in data.subdomains {
            // Chaos returns partial names, need to prepend domain
            let full_subdomain = if sub.starts_with("*.") {
                format!("{}.{}", &sub[2..], target.domain)
            } else {
                format!("{}.{}", sub, target.domain)
            };

            let sub_lower = full_subdomain.to_lowercase();
            let mut finding = SubdomainFinding::new(sub_lower, "chaos".to_string());
            finding.is_wildcard = sub.starts_with("*.");
            finding.discovered_at = Utc::now();
            findings.push(Finding::Subdomain(finding));
        }

        Ok(findings)
    }
}
