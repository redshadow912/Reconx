use async_trait::async_trait;
use chrono::Utc;
use regex::Regex;

use crate::collectors::{Collector, CollectorCategory};
use crate::config::Config;
use crate::error::Result;
use crate::models::{Finding, SubdomainFinding, Target};

pub struct RapidDnsCollector;

#[async_trait]
impl Collector for RapidDnsCollector {
    fn name(&self) -> &str {
        "rapiddns"
    }

    fn category(&self) -> CollectorCategory {
        CollectorCategory::DnsSubdomain
    }

    fn requires_api_key(&self) -> bool {
        false
    }

    async fn collect(&self, target: &Target, _config: &Config) -> Result<Vec<Finding>> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            .build()?;

        let url = format!("https://rapiddns.io/subdomain/{}", target.domain);

        let resp = match client.get(&url).send().await {
            Ok(r) => r,
            Err(_) => return Ok(Vec::new()),
        };

        if !resp.status().is_success() {
            return Ok(Vec::new());
        }

        let body = match resp.text().await {
            Ok(b) => b,
            Err(_) => return Ok(Vec::new()),
        };

        let re = Regex::new(&format!(
            r"([a-zA-Z0-9][a-zA-Z0-9\-\.]*\.{})",
            regex::escape(&target.domain)
        ))
        .unwrap();

        let mut findings = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for cap in re.captures_iter(&body) {
            let subdomain = cap[1].to_lowercase();
            if !seen.contains(&subdomain) && subdomain.ends_with(&target.domain) {
                seen.insert(subdomain.clone());
                let mut finding = SubdomainFinding::new(subdomain, "rapiddns".to_string());
                finding.discovered_at = Utc::now();
                findings.push(Finding::Subdomain(finding));
            }
        }

        Ok(findings)
    }
}
