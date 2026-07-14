use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;

use crate::collectors::{Collector, CollectorCategory};
use crate::config::Config;
use crate::error::Result;
use crate::models::{Finding, SubdomainFinding, Target};

pub struct ThreatCrowdCollector;

#[derive(Debug, Deserialize)]
struct ThreatCrowdResponse {
    #[serde(default)]
    response_code: String,
    #[serde(default)]
    subdomains: Vec<String>,
}

#[async_trait]
impl Collector for ThreatCrowdCollector {
    fn name(&self) -> &str {
        "threatcrowd"
    }

    fn category(&self) -> CollectorCategory {
        CollectorCategory::ThreatIntel
    }

    fn requires_api_key(&self) -> bool {
        false
    }

    async fn collect(&self, target: &Target, _config: &Config) -> Result<Vec<Finding>> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let url = format!(
            "https://www.threatcrowd.org/api/v2/domain/report/?domain={}",
            target.domain
        );

        let resp = match client.get(&url).send().await {
            Ok(r) => r,
            Err(_) => return Ok(Vec::new()),
        };

        if !resp.status().is_success() {
            return Ok(Vec::new());
        }

        let data: ThreatCrowdResponse = match resp.json().await {
            Ok(d) => d,
            Err(_) => return Ok(Vec::new()),
        };

        if data.response_code != "1" {
            return Ok(Vec::new());
        }

        let mut findings = Vec::new();

        for subdomain in data.subdomains {
            let sub_lower = subdomain.to_lowercase();
            if sub_lower.ends_with(&target.domain) {
                let mut finding = SubdomainFinding::new(sub_lower, "threatcrowd".to_string());
                finding.discovered_at = Utc::now();
                findings.push(Finding::Subdomain(finding));
            }
        }

        Ok(findings)
    }
}
