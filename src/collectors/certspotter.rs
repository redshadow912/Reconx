use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;

use crate::collectors::{Collector, CollectorCategory};
use crate::config::Config;
use crate::error::Result;
use crate::models::{Finding, SubdomainFinding, Target};

pub struct CertSpotterCollector;

#[derive(Debug, Deserialize)]
struct CertSpotterIssuance {
    #[serde(default)]
    id: String,
    #[serde(default)]
    dns_names: Vec<String>,
    #[serde(default)]
    not_before: Option<String>,
    #[serde(default)]
    not_after: Option<String>,
}

#[async_trait]
impl Collector for CertSpotterCollector {
    fn name(&self) -> &str {
        "certspotter"
    }

    fn category(&self) -> CollectorCategory {
        CollectorCategory::CertificateTransparency
    }

    fn requires_api_key(&self) -> bool {
        false
    }

    async fn collect(&self, target: &Target, _config: &Config) -> Result<Vec<Finding>> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let mut findings = Vec::new();
        let mut seen_subdomains = std::collections::HashSet::new();
        let mut after_id: Option<String> = None;

        // Paginate through results
        loop {
            let mut url = format!(
                "https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names",
                target.domain
            );

            if let Some(ref id) = after_id {
                url.push_str(&format!("&after={}", id));
            }

            let resp = match client.get(&url).send().await {
                Ok(r) => r,
                Err(_) => break,
            };

            if !resp.status().is_success() {
                break;
            }

            let issuances: Vec<CertSpotterIssuance> = match resp.json().await {
                Ok(i) => i,
                Err(_) => break,
            };

            if issuances.is_empty() {
                break;
            }

            // Extract subdomains from dns_names
            for issuance in &issuances {
                for dns_name in &issuance.dns_names {
                    let name = dns_name.to_lowercase();
                    
                    // Remove wildcard prefix
                    let clean_name = name.trim_start_matches("*.");
                    
                    if clean_name.ends_with(&target.domain) && !seen_subdomains.contains(clean_name) {
                        seen_subdomains.insert(clean_name.to_string());
                        
                        let mut sub = SubdomainFinding::new(clean_name.to_string(), "certspotter".to_string());
                        sub.is_wildcard = name.starts_with("*.");
                        sub.discovered_at = Utc::now();
                        findings.push(Finding::Subdomain(sub));
                    }
                }
            }

            // Update pagination cursor
            after_id = issuances.last().map(|i| i.id.clone());
            
            // Limit to prevent excessive requests (free tier: 100 queries/hour)
            if findings.len() > 500 {
                break;
            }
        }

        Ok(findings)
    }
}
