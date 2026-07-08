use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;

use crate::collectors::{Collector, CollectorCategory};
use crate::config::Config;
use crate::error::{ReconxError, Result};
use crate::models::{AssetFinding, Finding, Target};

pub struct IpInfoCollector;

#[derive(Debug, Deserialize)]
struct IpInfoResponse {
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    org: Option<String>,
    #[serde(default)]
    asn: Option<IpInfoAsn>,
}

#[derive(Debug, Deserialize)]
struct IpInfoAsn {
    #[serde(default)]
    asn: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

#[async_trait]
impl Collector for IpInfoCollector {
    fn name(&self) -> &str {
        "ipinfo"
    }

    fn category(&self) -> CollectorCategory {
        CollectorCategory::WhoisAsn
    }

    fn requires_api_key(&self) -> bool {
        true
    }

    async fn collect(&self, target: &Target, config: &Config) -> Result<Vec<Finding>> {
        let api_key = config
            .get_api_key("ipinfo")
            .ok_or(ReconxError::MissingApiKey {
                collector: "ipinfo".to_string(),
            })?
            .clone();

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let url = format!(
            "https://ipinfo.io/{}/json?token={}",
            target.domain, api_key
        );

        let resp = client.get(&url).send().await?;
        if !resp.status().is_success() {
            return Ok(Vec::new());
        }

        let data: IpInfoResponse = resp.json().await?;
        let mut findings = Vec::new();

        if let Some(ip) = data.ip {
            let mut f = AssetFinding::new(
                data.hostname.unwrap_or_else(|| target.domain.clone()),
                ip,
                "ipinfo".to_string(),
            );
            f.org = data.org;
            f.country = data.country;
            f.asn = data.asn.and_then(|a| a.asn);
            f.discovered_at = Utc::now();
            findings.push(Finding::Asset(f));
        }

        Ok(findings)
    }
}
