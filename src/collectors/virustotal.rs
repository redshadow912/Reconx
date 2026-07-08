use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;

use crate::collectors::{Collector, CollectorCategory};
use crate::config::Config;
use crate::error::{ReconxError, Result};
use crate::models::{Finding, SubdomainFinding, Target};

pub struct VirusTotalCollector;

#[derive(Debug, Deserialize)]
struct VtResponse {
    #[serde(default)]
    data: Option<VtData>,
}

#[derive(Debug, Deserialize)]
struct VtData {
    #[serde(default)]
    attributes: Option<VtAttributes>,
}

#[derive(Debug, Deserialize)]
struct VtAttributes {
    #[serde(default)]
    last_dns_records: Option<Vec<VtDnsRecord>>,
}

#[derive(Debug, Deserialize)]
struct VtDnsRecord {
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    r#type: Option<String>,
    #[serde(default)]
    value: Option<String>,
}

#[async_trait]
impl Collector for VirusTotalCollector {
    fn name(&self) -> &str {
        "virustotal"
    }

    fn category(&self) -> CollectorCategory {
        CollectorCategory::DnsSubdomain
    }

    fn requires_api_key(&self) -> bool {
        true
    }

    async fn collect(&self, target: &Target, config: &Config) -> Result<Vec<Finding>> {
        let api_key = config
            .get_api_key("virustotal")
            .ok_or(ReconxError::MissingApiKey {
                collector: "virustotal".to_string(),
            })?
            .clone();

        let url = format!(
            "https://www.virustotal.com/api/v3/domains/{}/subdomains?limit=40",
            target.domain
        );

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let resp = client
            .get(&url)
            .header("x-apikey", &api_key)
            .send()
            .await?;

        if !resp.status().is_success() {
            return Ok(Vec::new());
        }

        let body: serde_json::Value = resp.json().await?;
        let mut findings = Vec::new();

        if let Some(data) = body.get("data").and_then(|d| d.as_array()) {
            for item in data {
                if let Some(id) = item.get("id").and_then(|i| i.as_str()) {
                    let subdomain = id.to_lowercase();
                    if subdomain.ends_with(&target.domain) {
                        let mut f = SubdomainFinding::new(subdomain, "virustotal".to_string());
                        f.discovered_at = Utc::now();
                        findings.push(Finding::Subdomain(f));
                    }
                }
            }
        }

        Ok(findings)
    }
}
