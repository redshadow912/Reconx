use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;

use crate::collectors::{Collector, CollectorCategory};
use crate::config::Config;
use crate::error::{ReconxError, Result};
use crate::models::{EmailFinding, Finding, Target};

pub struct HunterIoCollector;

#[derive(Debug, Deserialize)]
struct HunterResponse {
    #[serde(default)]
    data: Option<HunterData>,
}

#[derive(Debug, Deserialize)]
struct HunterData {
    #[serde(default)]
    emails: Vec<HunterEmail>,
}

#[derive(Debug, Deserialize)]
struct HunterEmail {
    #[serde(default)]
    value: String,
    #[serde(default)]
    first_name: Option<String>,
    #[serde(default)]
    last_name: Option<String>,
    #[serde(default)]
    position: Option<String>,
    #[serde(default)]
    confidence: Option<u8>,
}

#[async_trait]
impl Collector for HunterIoCollector {
    fn name(&self) -> &str {
        "hunter"
    }

    fn category(&self) -> CollectorCategory {
        CollectorCategory::EmailHarvesting
    }

    fn requires_api_key(&self) -> bool {
        true
    }

    async fn collect(&self, target: &Target, config: &Config) -> Result<Vec<Finding>> {
        let api_key = config
            .get_api_key("hunter")
            .ok_or(ReconxError::MissingApiKey {
                collector: "hunter".to_string(),
            })?
            .clone();

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let url = format!(
            "https://api.hunter.io/v2/domain-search?domain={}&api_key={}",
            target.domain, api_key
        );

        let resp = client.get(&url).send().await?;

        if !resp.status().is_success() {
            return Ok(Vec::new());
        }

        let data: HunterResponse = resp.json().await?;

        let mut findings = Vec::new();

        if let Some(hunter_data) = data.data {
            for email in hunter_data.emails {
                let mut finding = EmailFinding::new(email.value, "hunter".to_string());
                
                if let (Some(first), Some(last)) = (email.first_name, email.last_name) {
                    finding.name = Some(format!("{} {}", first, last));
                }
                
                finding.position = email.position;
                finding.confidence = email.confidence;
                finding.discovered_at = Utc::now();

                findings.push(Finding::Email(finding));
            }
        }

        Ok(findings)
    }
}
