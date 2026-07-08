use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;

use crate::collectors::{Collector, CollectorCategory};
use crate::config::Config;
use crate::error::Result;
use crate::models::{Finding, SubdomainFinding, Target};

pub struct DuckDuckGoCollector;

#[derive(Debug, Deserialize)]
struct DuckDuckGoResponse {
    #[serde(default)]
    results: Vec<DuckDuckGoResult>,
}

#[derive(Debug, Deserialize)]
struct DuckDuckGoResult {
    #[serde(default)]
    u: Option<String>,
}

#[async_trait]
impl Collector for DuckDuckGoCollector {
    fn name(&self) -> &str {
        "duckduckgo"
    }

    fn category(&self) -> CollectorCategory {
        CollectorCategory::SearchEngine
    }

    fn requires_api_key(&self) -> bool {
        false
    }

    async fn collect(&self, target: &Target, _config: &Config) -> Result<Vec<Finding>> {
        let url = format!(
            "https://html.duckduckgo.com/html/?q=site%3A{}",
            target.domain
        );

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            .build()?;

        let resp = client.get(&url).send().await?;
        if !resp.status().is_success() {
            return Ok(Vec::new());
        }

        let body = resp.text().await?;
        let mut findings = Vec::new();
        let mut seen = std::collections::HashSet::new();

        let re = regex::Regex::new(&format!(
            r"([a-zA-Z0-9][a-zA-Z0-9\-\.]*\.{})",
            regex::escape(&target.domain)
        ))
        .unwrap();

        for cap in re.captures_iter(&body) {
            let host = cap[1].to_lowercase();
            if !seen.contains(&host) {
                seen.insert(host.clone());
                let mut f = SubdomainFinding::new(host, "duckduckgo".to_string());
                f.discovered_at = Utc::now();
                findings.push(Finding::Subdomain(f));
            }
        }

        Ok(findings)
    }
}
