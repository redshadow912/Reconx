use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;

use crate::collectors::{Collector, CollectorCategory};
use crate::config::Config;
use crate::error::{ReconxError, Result};
use crate::models::{Finding, SubdomainFinding, Target};

pub struct ZoomEyeCollector;

#[derive(Debug, Deserialize)]
struct ZoomEyeResponse {
    #[serde(default)]
    status: u32,
    #[serde(default)]
    total: u32,
    #[serde(default)]
    list: Vec<ZoomEyeItem>,
}

#[derive(Debug, Deserialize)]
struct ZoomEyeItem {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    timestamp: Option<String>,
    #[serde(default)]
    ip: Option<Vec<ZoomEyeIp>>,
}

#[derive(Debug, Deserialize)]
struct ZoomEyeIp {
    #[serde(default, rename = "A")]
    a_records: Option<Vec<String>>,
}

#[async_trait]
impl Collector for ZoomEyeCollector {
    fn name(&self) -> &str {
        "zoomeye"
    }

    fn category(&self) -> CollectorCategory {
        CollectorCategory::DnsSubdomain
    }

    fn requires_api_key(&self) -> bool {
        true
    }

    fn config_key(&self) -> &str {
        "zoomeye"
    }

    async fn collect(&self, target: &Target, config: &Config) -> Result<Vec<Finding>> {
        let api_key = config
            .get_api_key("zoomeye")
            .ok_or(ReconxError::MissingApiKey {
                collector: "zoomeye".to_string(),
            })?
            .clone();

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let url = format!(
            "https://api.zoomeye.org/domain/search?q={}&type=0",
            target.domain
        );

        let resp = match client
            .get(&url)
            .header("API-KEY", &api_key)
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => return Ok(Vec::new()),
        };

        if !resp.status().is_success() {
            return Ok(Vec::new());
        }

        let data: ZoomEyeResponse = match resp.json().await {
            Ok(d) => d,
            Err(_) => return Ok(Vec::new()),
        };

        let mut findings = Vec::new();

        for item in data.list {
            if let Some(name) = item.name {
                let sub_lower = name.to_lowercase();
                if sub_lower.ends_with(&target.domain) {
                    let mut finding = SubdomainFinding::new(sub_lower, "zoomeye".to_string());
                    
                    // Extract IPs if available
                    if let Some(ips) = item.ip {
                        for ip_entry in ips {
                            if let Some(a_records) = ip_entry.a_records {
                                for ip in a_records {
                                    finding.ip_addresses.push(ip);
                                }
                            }
                        }
                    }
                    
                    finding.discovered_at = Utc::now();
                    findings.push(Finding::Subdomain(finding));
                }
            }
        }

        Ok(findings)
    }
}
