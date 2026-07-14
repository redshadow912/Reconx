use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;

use crate::collectors::{Collector, CollectorCategory};
use crate::config::Config;
use crate::error::{ReconxError, Result};
use crate::models::{Finding, SubdomainFinding, Target};

pub struct NetlasCollector;

#[derive(Debug, Deserialize)]
struct NetlasResponse {
    #[serde(default)]
    items: Vec<NetlasItem>,
}

#[derive(Debug, Deserialize)]
struct NetlasItem {
    #[serde(default)]
    data: Option<NetlasData>,
}

#[derive(Debug, Deserialize)]
struct NetlasData {
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    ip: Option<String>,
}

#[async_trait]
impl Collector for NetlasCollector {
    fn name(&self) -> &str {
        "netlas"
    }

    fn category(&self) -> CollectorCategory {
        CollectorCategory::DnsSubdomain
    }

    fn requires_api_key(&self) -> bool {
        true
    }

    fn config_key(&self) -> &str {
        "netlas"
    }

    async fn collect(&self, target: &Target, config: &Config) -> Result<Vec<Finding>> {
        let api_key = config
            .get_api_key("netlas")
            .ok_or(ReconxError::MissingApiKey {
                collector: "netlas".to_string(),
            })?
            .clone();

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let url = format!(
            "https://app.netlas.io/api/domains/?q=*.{}&fields=domain,ip",
            target.domain
        );

        let resp = match client
            .get(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => return Ok(Vec::new()),
        };

        if !resp.status().is_success() {
            return Ok(Vec::new());
        }

        let data: NetlasResponse = match resp.json().await {
            Ok(d) => d,
            Err(_) => return Ok(Vec::new()),
        };

        let mut findings = Vec::new();

        for item in data.items {
            if let Some(netlas_data) = item.data {
                if let Some(domain) = netlas_data.domain {
                    let sub_lower = domain.to_lowercase();
                    if sub_lower.ends_with(&target.domain) {
                        let mut finding = SubdomainFinding::new(sub_lower, "netlas".to_string());
                        if let Some(ip) = netlas_data.ip {
                            finding.ip_addresses.push(ip);
                        }
                        finding.discovered_at = Utc::now();
                        findings.push(Finding::Subdomain(finding));
                    }
                }
            }
        }

        Ok(findings)
    }
}
