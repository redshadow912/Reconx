use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;

use crate::collectors::{Collector, CollectorCategory};
use crate::config::Config;
use crate::error::{ReconxError, Result};
use crate::models::{Finding, SubdomainFinding, Target};

pub struct UrlScanCollector;

#[derive(Debug, Deserialize)]
struct UrlScanResponse {
    #[serde(default)]
    results: Vec<UrlScanResult>,
}

#[derive(Debug, Deserialize)]
struct UrlScanResult {
    #[serde(default)]
    page: Option<UrlScanPage>,
}

#[derive(Debug, Deserialize)]
struct UrlScanPage {
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    ip: Option<String>,
}

#[async_trait]
impl Collector for UrlScanCollector {
    fn name(&self) -> &str {
        "urlscan"
    }

    fn category(&self) -> CollectorCategory {
        CollectorCategory::ThreatIntel
    }

    fn requires_api_key(&self) -> bool {
        true
    }

    async fn collect(&self, target: &Target, config: &Config) -> Result<Vec<Finding>> {
        let api_key = config
            .get_api_key("urlscan")
            .ok_or(ReconxError::MissingApiKey {
                collector: "urlscan".to_string(),
            })?
            .clone();

        let url = format!(
            "https://urlscan.io/api/v1/search/?q=domain:{}",
            target.domain
        );

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let resp = client
            .get(&url)
            .header("API-Key", &api_key)
            .send()
            .await?;

        if !resp.status().is_success() {
            return Ok(Vec::new());
        }

        let data: UrlScanResponse = resp.json().await?;
        let mut findings = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for result in data.results {
            if let Some(page) = result.page {
                if let Some(domain) = page.domain {
                    let domain = domain.to_lowercase();
                    if domain.ends_with(&target.domain) && !seen.contains(&domain) {
                        seen.insert(domain.clone());
                        let mut f = SubdomainFinding::new(domain, "urlscan".to_string());
                        if let Some(ip) = page.ip {
                            f.ip_addresses.push(ip);
                        }
                        f.discovered_at = Utc::now();
                        findings.push(Finding::Subdomain(f));
                    }
                }
            }
        }

        Ok(findings)
    }
}
