use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;

use crate::collectors::{Collector, CollectorCategory};
use crate::config::Config;
use crate::error::{ReconxError, Result};
use crate::models::{CredentialFinding, Finding, Target};
use crate::models::finding::Severity;

pub struct HibpCollector;

#[derive(Debug, Deserialize)]
struct HibpBreach {
    #[serde(rename = "Name")]
    name: Option<String>,
    #[serde(rename = "BreachDate")]
    breach_date: Option<String>,
    #[serde(rename = "DataClasses")]
    data_classes: Option<Vec<String>>,
}

#[async_trait]
impl Collector for HibpCollector {
    fn name(&self) -> &str {
        "hibp"
    }

    fn category(&self) -> CollectorCategory {
        CollectorCategory::CredentialBreaches
    }

    fn requires_api_key(&self) -> bool {
        true
    }

    async fn collect(&self, target: &Target, config: &Config) -> Result<Vec<Finding>> {
        let api_key = config
            .get_api_key("hibp")
            .ok_or(ReconxError::MissingApiKey {
                collector: "hibp".to_string(),
            })?
            .clone();

        let url = format!(
            "https://haveibeenpwned.com/api/v3/breachedaccount/{}",
            target.domain
        );

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let resp = client
            .get(&url)
            .header("hibp-api-key", &api_key)
            .header("User-Agent", "reconx/0.1.0")
            .send()
            .await?;

        if resp.status().as_u16() == 404 {
            return Ok(Vec::new());
        }

        if !resp.status().is_success() {
            return Ok(Vec::new());
        }

        let breaches: Vec<HibpBreach> = resp.json().await?;
        let mut findings = Vec::new();

        for breach in breaches {
            let breach_name = breach.name.unwrap_or_else(|| "Unknown".to_string());
            let mut f = CredentialFinding::new(
                format!("@{}", target.domain),
                breach_name,
                "hibp".to_string(),
            );
            f.data_types = breach.data_classes.unwrap_or_default();
            f.severity = Severity::High;
            f.discovered_at = Utc::now();
            findings.push(Finding::Credential(f));
        }

        Ok(findings)
    }
}
