use async_trait::async_trait;
use chrono::Utc;

use crate::collectors::{Collector, CollectorCategory};
use crate::config::Config;
use crate::error::Result;
use crate::models::{Finding, SubdomainFinding, Target};

pub struct HackerTargetCollector;

#[async_trait]
impl Collector for HackerTargetCollector {
    fn name(&self) -> &str {
        "hackertarget"
    }

    fn category(&self) -> CollectorCategory {
        CollectorCategory::DnsSubdomain
    }

    fn requires_api_key(&self) -> bool {
        false
    }

    async fn collect(&self, target: &Target, _config: &Config) -> Result<Vec<Finding>> {
        let url = format!(
            "https://api.hackertarget.com/hostsearch/?q={}",
            target.domain
        );

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let resp = client.get(&url).send().await?;
        if !resp.status().is_success() {
            return Ok(Vec::new());
        }

        let body = resp.text().await?;
        let mut findings = Vec::new();

        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("error") {
                continue;
            }

            let parts: Vec<&str> = line.split(',').collect();
            if parts.is_empty() {
                continue;
            }

            let subdomain = parts[0].trim().to_lowercase();
            if !subdomain.ends_with(&target.domain) {
                continue;
            }

            let mut f = SubdomainFinding::new(subdomain, self.name().to_string());
            if parts.len() > 1 {
                f.ip_addresses.push(parts[1].trim().to_string());
            }
            f.discovered_at = Utc::now();
            findings.push(Finding::Subdomain(f));
        }

        Ok(findings)
    }
}
