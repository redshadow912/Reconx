use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;

use crate::collectors::{Collector, CollectorCategory};
use crate::config::Config;
use crate::error::{ReconxError, Result};
use crate::models::{Finding, SubdomainFinding, Target};

pub struct AlienVaultCollector;

#[derive(Debug, Deserialize)]
struct OtxResponse {
    #[serde(default)]
    passive_dns: Vec<OtxDnsRecord>,
}

#[derive(Debug, Deserialize)]
struct OtxDnsRecord {
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    record_type: Option<String>,
}

#[async_trait]
impl Collector for AlienVaultCollector {
    fn name(&self) -> &str {
        "alienvault"
    }

    fn category(&self) -> CollectorCategory {
        CollectorCategory::ThreatIntel
    }

    fn requires_api_key(&self) -> bool {
        true
    }

    async fn collect(&self, target: &Target, config: &Config) -> Result<Vec<Finding>> {
        let api_key = config
            .get_api_key("alienvault")
            .ok_or(ReconxError::MissingApiKey {
                collector: "alienvault".to_string(),
            })?
            .clone();

        let url = format!(
            "https://otx.alienvault.com/api/v1/indicators/domain/{}/passive_dns",
            target.domain
        );

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let resp = client
            .get(&url)
            .header("X-OTX-API-KEY", &api_key)
            .send()
            .await?;

        if !resp.status().is_success() {
            return Ok(Vec::new());
        }

        let data: OtxResponse = resp.json().await?;
        let mut findings = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for record in data.passive_dns {
            if let Some(hostname) = record.hostname {
                let hostname = hostname.to_lowercase();
                if hostname.ends_with(&target.domain) && !seen.contains(&hostname) {
                    seen.insert(hostname.clone());
                    let mut f = SubdomainFinding::new(hostname, "alienvault".to_string());
                    if let Some(addr) = record.address {
                        f.ip_addresses.push(addr);
                    }
                    f.discovered_at = Utc::now();
                    findings.push(Finding::Subdomain(f));
                }
            }
        }

        Ok(findings)
    }
}
