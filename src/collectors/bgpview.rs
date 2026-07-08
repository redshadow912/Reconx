use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;

use crate::collectors::{Collector, CollectorCategory};
use crate::config::Config;
use crate::error::Result;
use crate::models::{AssetFinding, Finding, Target};

pub struct BgpViewCollector;

#[derive(Debug, Deserialize)]
struct BgpViewResponse {
    #[serde(default)]
    data: Option<BgpViewData>,
}

#[derive(Debug, Deserialize)]
struct BgpViewData {
    #[serde(default)]
    prefixes: Vec<BgpPrefix>,
}

#[derive(Debug, Deserialize)]
struct BgpPrefix {
    #[serde(default)]
    prefix: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
}

#[async_trait]
impl Collector for BgpViewCollector {
    fn name(&self) -> &str {
        "bgpview"
    }

    fn category(&self) -> CollectorCategory {
        CollectorCategory::WhoisAsn
    }

    fn requires_api_key(&self) -> bool {
        false
    }

    async fn collect(&self, target: &Target, _config: &Config) -> Result<Vec<Finding>> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let dns_url = format!(
            "https://api.bgpview.io/dns/{}/A",
            target.domain
        );

        let resp = client.get(&dns_url).send().await?;
        if !resp.status().is_success() {
            return Ok(Vec::new());
        }

        let body: serde_json::Value = match resp.json().await {
            Ok(b) => b,
            Err(_) => return Ok(Vec::new()),
        };

        let mut findings = Vec::new();

        if let Some(records) = body.get("data").and_then(|d| d.as_array()) {
            for record in records {
                if let Some(ip) = record.get("answer").and_then(|a| a.as_str()) {
                    let mut f = AssetFinding::new(
                        target.domain.clone(),
                        ip.to_string(),
                        "bgpview".to_string(),
                    );
                    f.discovered_at = Utc::now();
                    findings.push(Finding::Asset(f));
                }
            }
        }

        Ok(findings)
    }
}
