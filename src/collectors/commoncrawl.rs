use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;

use crate::collectors::{Collector, CollectorCategory};
use crate::config::Config;
use crate::error::Result;
use crate::models::{Finding, SubdomainFinding, Target};

pub struct CommonCrawlCollector;

#[derive(Debug, Deserialize)]
struct CommonCrawlIndex {
    id: String,
}

#[async_trait]
impl Collector for CommonCrawlCollector {
    fn name(&self) -> &str {
        "commoncrawl"
    }

    fn category(&self) -> CollectorCategory {
        CollectorCategory::WebArchives
    }

    fn requires_api_key(&self) -> bool {
        false
    }

    async fn collect(&self, target: &Target, _config: &Config) -> Result<Vec<Finding>> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let index_url = "https://index.commoncrawl.org/collinfo.json";
        let resp = client.get(index_url).send().await?;
        if !resp.status().is_success() {
            return Ok(Vec::new());
        }

        let indices: Vec<CommonCrawlIndex> = match resp.json().await {
            Ok(i) => i,
            Err(_) => return Ok(Vec::new()),
        };

        let latest = match indices.first() {
            Some(idx) => &idx.id,
            None => return Ok(Vec::new()),
        };

        let search_url = format!(
            "https://index.commoncrawl.org/{}-index?url=*.{}&output=json",
            latest, target.domain
        );

        let resp = client.get(&search_url).send().await?;
        if !resp.status().is_success() {
            return Ok(Vec::new());
        }

        let body = resp.text().await?;
        let mut findings = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for line in body.lines() {
            if let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) {
                if let Some(url) = entry.get("url").and_then(|u| u.as_str()) {
                    if let Ok(parsed) = url::Url::parse(url) {
                        if let Some(host) = parsed.host_str() {
                            let host = host.to_lowercase();
                            if host.ends_with(&target.domain) && !seen.contains(&host) {
                                seen.insert(host.clone());
                                let mut f = SubdomainFinding::new(host, "commoncrawl".to_string());
                                f.discovered_at = Utc::now();
                                findings.push(Finding::Subdomain(f));
                            }
                        }
                    }
                }
            }
        }

        Ok(findings)
    }
}
