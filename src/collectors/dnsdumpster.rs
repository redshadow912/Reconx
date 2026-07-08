use async_trait::async_trait;
use serde::Deserialize;

use crate::collectors::{Collector, CollectorCategory};
use crate::config::Config;
use crate::error::Result;
use crate::models::{Finding, SubdomainFinding, Target};

pub struct DnsDumpsterCollector;

#[derive(Debug, Deserialize)]
struct DnsDumpsterResponse {
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    dns_records: Option<Vec<DnsDumpsterRecord>>,
}

#[derive(Debug, Deserialize)]
struct DnsDumpsterRecord {
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    ip: Option<String>,
}

#[async_trait]
impl Collector for DnsDumpsterCollector {
    fn name(&self) -> &str {
        "dnsdumpster"
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
            .build()?;

        let page = client
            .get("https://dnsdumpster.com")
            .send()
            .await?;

        let body = page.text().await?;
        let csrf = extract_csrf(&body).unwrap_or_default();

        let resp = client
            .post("https://dnsdumpster.com")
            .form(&[
                ("csrfmiddlewaretoken", csrf.as_str()),
                ("targetip", &target.domain),
            ])
            .header("Referer", "https://dnsdumpster.com")
            .send()
            .await?;

        if !resp.status().is_success() {
            return Ok(Vec::new());
        }

        let result_body = resp.text().await?;
        let mut findings = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for line in result_body.lines() {
            let line = line.trim();
            if line.contains(&target.domain) {
                if let Some(subdomain) = extract_domain(line, &target.domain) {
                    if seen.contains(&subdomain) {
                        continue;
                    }
                    seen.insert(subdomain.clone());

                    let f = SubdomainFinding::new(subdomain, self.name().to_string());
                    findings.push(Finding::Subdomain(f));
                }
            }
        }

        Ok(findings)
    }
}

fn extract_csrf(html: &str) -> Option<String> {
    let re = regex::Regex::new(r#"name="csrfmiddlewaretoken" value="([^"]+)""#).ok()?;
    re.captures(html).map(|c| c[1].to_string())
}

fn extract_domain(line: &str, base_domain: &str) -> Option<String> {
    let re = regex::Regex::new(&format!(r"([a-zA-Z0-9\-\.]+\.{})", regex::escape(base_domain))).ok()?;
    re.captures(line).map(|c| c[1].to_lowercase())
}
