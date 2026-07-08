use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;

use crate::collectors::{Collector, CollectorCategory};
use crate::config::Config;
use crate::error::{ReconxError, Result};
use crate::models::{Finding, SubdomainFinding, Target};

pub struct CensysCollector;

#[derive(Debug, Deserialize)]
struct CensysSearchResponse {
    #[serde(default)]
    result: Option<CensysResult>,
}

#[derive(Debug, Deserialize)]
struct CensysResult {
    #[serde(default)]
    hits: Vec<CensysHit>,
}

#[derive(Debug, Deserialize)]
struct CensysHit {
    #[serde(default)]
    names: Option<Vec<String>>,
    #[serde(default)]
    parsed: Option<CensysParsed>,
}

#[derive(Debug, Deserialize)]
struct CensysParsed {
    #[serde(default)]
    subject_dn: Option<String>,
}

#[async_trait]
impl Collector for CensysCollector {
    fn name(&self) -> &str {
        "censys"
    }

    fn category(&self) -> CollectorCategory {
        CollectorCategory::HostService
    }

    fn requires_api_key(&self) -> bool {
        true
    }

    async fn collect(&self, target: &Target, config: &Config) -> Result<Vec<Finding>> {
        let api_key = config
            .get_api_key("censys")
            .ok_or(ReconxError::MissingApiKey {
                collector: "censys".to_string(),
            })?
            .clone();

        let parts: Vec<&str> = api_key.split(':').collect();
        if parts.len() != 2 {
            return Err(ReconxError::Config(
                "Censys API key should be in format 'id:secret'".to_string(),
            ));
        }

        let url = "https://search.censys.io/api/v2/certificates/search";

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let body = serde_json::json!({
            "q": format!("names: {}", target.domain),
            "per_page": 100
        });

        let resp = client
            .post(url)
            .basic_auth(parts[0], Some(parts[1]))
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            return Ok(Vec::new());
        }

        let data: CensysSearchResponse = resp.json().await?;
        let mut findings = Vec::new();
        let mut seen = std::collections::HashSet::new();

        if let Some(result) = data.result {
            for hit in result.hits {
                if let Some(names) = hit.names {
                    for name in names {
                        let name = name.to_lowercase();
                        if name.ends_with(&target.domain) && !seen.contains(&name) {
                            seen.insert(name.clone());
                            let mut f = SubdomainFinding::new(name, "censys".to_string());
                            f.discovered_at = Utc::now();
                            findings.push(Finding::Subdomain(f));
                        }
                    }
                }
            }
        }

        Ok(findings)
    }
}
