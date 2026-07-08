use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;

use crate::collectors::{Collector, CollectorCategory};
use crate::config::Config;
use crate::error::Result;
use crate::models::{Finding, SubdomainFinding, Target};

pub struct CrtShCollector;

#[derive(Debug, Deserialize)]
struct CrtShEntry {
    name_value: String,
}

#[async_trait]
impl Collector for CrtShCollector {
    fn name(&self) -> &str {
        "crt.sh"
    }

    fn category(&self) -> CollectorCategory {
        CollectorCategory::CertificateTransparency
    }

    fn requires_api_key(&self) -> bool {
        false
    }

    async fn collect(&self, target: &Target, _config: &Config) -> Result<Vec<Finding>> {
        let url = format!(
            "https://crt.sh/?q=%25.{}&output=json",
            target.domain
        );

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let resp = client.get(&url).send().await?;

        if !resp.status().is_success() {
            return Ok(Vec::new());
        }

        let entries: Vec<CrtShEntry> = match resp.json().await {
            Ok(e) => e,
            Err(_) => return Ok(Vec::new()),
        };

        let mut findings = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for entry in entries {
            for name in entry.name_value.split('\n') {
                let name = name.trim().to_lowercase();
                if name.is_empty() || !name.ends_with(&target.domain) || seen.contains(&name) {
                    continue;
                }
                seen.insert(name.clone());

                let mut f = SubdomainFinding::new(name, self.name().to_string());
                f.discovered_at = Utc::now();
                findings.push(Finding::Subdomain(f));
            }
        }

        Ok(findings)
    }
}
