use async_trait::async_trait;
use chrono::Utc;

use crate::collectors::{Collector, CollectorCategory};
use crate::config::Config;
use crate::error::Result;
use crate::models::{Finding, SubdomainFinding, Target};

pub struct SubdomainCenterCollector;

#[async_trait]
impl Collector for SubdomainCenterCollector {
    fn name(&self) -> &str {
        "subdomaincenter"
    }

    fn category(&self) -> CollectorCategory {
        CollectorCategory::DnsSubdomain
    }

    fn requires_api_key(&self) -> bool {
        false
    }

    async fn collect(&self, target: &Target, _config: &Config) -> Result<Vec<Finding>> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let url = format!("https://api.subdomain.center/?domain={}", target.domain);

        let resp = match client.get(&url).send().await {
            Ok(r) => r,
            Err(_) => return Ok(Vec::new()),
        };

        if !resp.status().is_success() {
            return Ok(Vec::new());
        }

        let subdomains: Vec<String> = match resp.json().await {
            Ok(s) => s,
            Err(_) => return Ok(Vec::new()),
        };

        let mut findings = Vec::new();

        for subdomain in subdomains {
            let sub_lower = subdomain.to_lowercase();
            if sub_lower.ends_with(&target.domain) {
                let mut finding = SubdomainFinding::new(sub_lower, "subdomaincenter".to_string());
                finding.discovered_at = Utc::now();
                findings.push(Finding::Subdomain(finding));
            }
        }

        Ok(findings)
    }
}
