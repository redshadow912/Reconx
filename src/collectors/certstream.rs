use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;

use crate::collectors::{Collector, CollectorCategory};
use crate::config::Config;
use crate::error::Result;
use crate::models::{Finding, SubdomainFinding, Target};

pub struct CertStreamCollector;

#[derive(Debug, Deserialize)]
struct CertStreamMessage {
    #[serde(default)]
    message_type: Option<String>,
    #[serde(default)]
    data: Option<CertStreamData>,
}

#[derive(Debug, Deserialize)]
struct CertStreamData {
    #[serde(default)]
    leaf_cert: Option<LeafCert>,
}

#[derive(Debug, Deserialize)]
struct LeafCert {
    #[serde(default)]
    all_domains: Vec<String>,
}

#[async_trait]
impl Collector for CertStreamCollector {
    fn name(&self) -> &str {
        "certstream"
    }

    fn category(&self) -> CollectorCategory {
        CollectorCategory::CertificateTransparency
    }

    fn requires_api_key(&self) -> bool {
        false
    }

    async fn collect(&self, target: &Target, _config: &Config) -> Result<Vec<Finding>> {
        let url = format!(
            "https://certstream.calidog.io/full-historical/{}",
            target.domain
        );

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let resp = client.get(&url).send().await?;
        if !resp.status().is_success() {
            return Ok(Vec::new());
        }

        let body = resp.text().await?;
        let mut findings = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for line in body.lines() {
            if let Ok(msg) = serde_json::from_str::<CertStreamMessage>(line) {
                if let Some(data) = msg.data {
                    if let Some(leaf) = data.leaf_cert {
                        for domain in leaf.all_domains {
                            let domain = domain.to_lowercase();
                            if domain.ends_with(&target.domain) && !seen.contains(&domain) {
                                seen.insert(domain.clone());
                                let mut f = SubdomainFinding::new(domain, "certstream".to_string());
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
