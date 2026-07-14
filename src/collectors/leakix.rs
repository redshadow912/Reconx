use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;

use crate::collectors::{Collector, CollectorCategory};
use crate::config::Config;
use crate::error::{ReconxError, Result};
use crate::models::{Finding, SubdomainFinding, Target};

pub struct LeakIxCollector;

#[derive(Debug, Deserialize)]
struct LeakIxSubdomain {
    #[serde(default)]
    subdomain: String,
    #[serde(default)]
    distinct_ips: Option<u32>,
    #[serde(default)]
    last_seen: Option<String>,
}

#[async_trait]
impl Collector for LeakIxCollector {
    fn name(&self) -> &str {
        "leakix"
    }

    fn category(&self) -> CollectorCategory {
        CollectorCategory::DnsSubdomain
    }

    fn requires_api_key(&self) -> bool {
        true
    }

    fn config_key(&self) -> &str {
        "leakix"
    }

    async fn collect(&self, target: &Target, config: &Config) -> Result<Vec<Finding>> {
        let api_key = config
            .get_api_key("leakix")
            .ok_or(ReconxError::MissingApiKey {
                collector: "leakix".to_string(),
            })?
            .clone();

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let url = format!("https://leakix.net/api/subdomains/{}", target.domain);

        let resp = match client
            .get(&url)
            .header("api-key", &api_key)
            .header("accept", "application/json")
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => return Ok(Vec::new()),
        };

        if !resp.status().is_success() {
            return Ok(Vec::new());
        }

        let subdomains: Vec<LeakIxSubdomain> = match resp.json().await {
            Ok(s) => s,
            Err(_) => return Ok(Vec::new()),
        };

        let mut findings = Vec::new();

        for sub in subdomains {
            let sub_lower = sub.subdomain.to_lowercase();
            if sub_lower.ends_with(&target.domain) {
                let mut finding = SubdomainFinding::new(sub_lower, "leakix".to_string());
                finding.discovered_at = Utc::now();
                findings.push(Finding::Subdomain(finding));
            }
        }

        Ok(findings)
    }
}
