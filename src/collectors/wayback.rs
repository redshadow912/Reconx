use async_trait::async_trait;
use chrono::Utc;

use crate::collectors::{Collector, CollectorCategory};
use crate::config::Config;
use crate::error::Result;
use crate::models::{Finding, SubdomainFinding, Target};

pub struct WaybackCollector;

#[async_trait]
impl Collector for WaybackCollector {
    fn name(&self) -> &str {
        "wayback"
    }

    fn category(&self) -> CollectorCategory {
        CollectorCategory::WebArchives
    }

    fn requires_api_key(&self) -> bool {
        false
    }

    async fn collect(&self, target: &Target, _config: &Config) -> Result<Vec<Finding>> {
        let url = format!(
            "https://web.archive.org/cdx/search/cdx?url=*.{}/*&output=json&fl=original&collapse=urlkey",
            target.domain
        );

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()?;

        let resp = client.get(&url).send().await?;
        if !resp.status().is_success() {
            return Ok(Vec::new());
        }

        let entries: Vec<Vec<String>> = match resp.json().await {
            Ok(e) => e,
            Err(_) => return Ok(Vec::new()),
        };

        let mut findings = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for entry in entries.iter().skip(1) {
            if entry.is_empty() {
                continue;
            }

            let original_url = &entry[0];
            if let Ok(parsed) = url::Url::parse(original_url) {
                if let Some(host) = parsed.host_str() {
                    let host = host.to_lowercase();
                    if host.ends_with(&target.domain) && !seen.contains(&host) {
                        seen.insert(host.clone());
                        let mut f = SubdomainFinding::new(host, "wayback".to_string());
                        f.discovered_at = Utc::now();
                        findings.push(Finding::Subdomain(f));
                    }
                }
            }
        }

        Ok(findings)
    }
}
