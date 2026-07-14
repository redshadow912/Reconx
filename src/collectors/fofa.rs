use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose};
use chrono::Utc;
use serde::Deserialize;

use crate::collectors::{Collector, CollectorCategory};
use crate::config::Config;
use crate::error::{ReconxError, Result};
use crate::models::{Finding, SubdomainFinding, Target};

pub struct FofaCollector;

#[derive(Debug, Deserialize)]
struct FofaResponse {
    #[serde(default)]
    error: bool,
    #[serde(default)]
    size: u32,
    #[serde(default)]
    results: Vec<Vec<String>>,
}

#[async_trait]
impl Collector for FofaCollector {
    fn name(&self) -> &str {
        "fofa"
    }

    fn category(&self) -> CollectorCategory {
        CollectorCategory::DnsSubdomain
    }

    fn requires_api_key(&self) -> bool {
        true
    }

    fn config_key(&self) -> &str {
        "fofa"
    }

    async fn collect(&self, target: &Target, config: &Config) -> Result<Vec<Finding>> {
        let api_key = config
            .get_api_key("fofa")
            .ok_or(ReconxError::MissingApiKey {
                collector: "fofa".to_string(),
            })?
            .clone();

        // FOFA key format: email:key
        let parts: Vec<&str> = api_key.split(':').collect();
        if parts.len() != 2 {
            return Err(ReconxError::Config(
                "FOFA API key should be in format 'email:key'".to_string(),
            ));
        }

        let email = parts[0];
        let key = parts[1];

        // Base64 encode the query
        let query = format!("domain=\"{}\"", target.domain);
        let query_b64 = general_purpose::STANDARD.encode(query.as_bytes());

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let url = format!(
            "https://fofa.info/api/v1/search/all?email={}&key={}&qbase64={}&size=100&page=1&fields=host,ip,domain",
            email, key, query_b64
        );

        let resp = match client.get(&url).send().await {
            Ok(r) => r,
            Err(_) => return Ok(Vec::new()),
        };

        if !resp.status().is_success() {
            return Ok(Vec::new());
        }

        let data: FofaResponse = match resp.json().await {
            Ok(d) => d,
            Err(_) => return Ok(Vec::new()),
        };

        if data.error {
            return Ok(Vec::new());
        }

        let mut findings = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for result in data.results {
            if result.len() >= 3 {
                let domain = &result[2];
                let sub_lower = domain.to_lowercase();
                
                if sub_lower.ends_with(&target.domain) && !seen.contains(&sub_lower) {
                    seen.insert(sub_lower.clone());
                    let mut finding = SubdomainFinding::new(sub_lower, "fofa".to_string());
                    
                    // Add IP if available
                    if !result[1].is_empty() {
                        finding.ip_addresses.push(result[1].clone());
                    }
                    
                    finding.discovered_at = Utc::now();
                    findings.push(Finding::Subdomain(finding));
                }
            }
        }

        Ok(findings)
    }
}
