use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;

use crate::collectors::{Collector, CollectorCategory};
use crate::config::Config;
use crate::error::{ReconxError, Result};
use crate::models::{CredentialFinding, Finding, Target};
use crate::models::finding::Severity;

pub struct GithubDorksCollector;

#[derive(Debug, Deserialize)]
struct GithubSearchResponse {
    #[serde(default)]
    items: Vec<GithubItem>,
    #[serde(default)]
    total_count: u64,
}

#[derive(Debug, Deserialize)]
struct GithubItem {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    html_url: Option<String>,
    #[serde(default)]
    repository: Option<GithubRepo>,
}

#[derive(Debug, Deserialize)]
struct GithubRepo {
    #[serde(default)]
    full_name: Option<String>,
}

#[async_trait]
impl Collector for GithubDorksCollector {
    fn name(&self) -> &str {
        "github_dorks"
    }

    fn category(&self) -> CollectorCategory {
        CollectorCategory::CodeDocLeaks
    }

    fn requires_api_key(&self) -> bool {
        true
    }

    async fn collect(&self, target: &Target, config: &Config) -> Result<Vec<Finding>> {
        let api_key = config
            .get_api_key("github")
            .ok_or(ReconxError::MissingApiKey {
                collector: "github".to_string(),
            })?
            .clone();

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let dorks = vec![
            format!("\"{}\" password", target.domain),
            format!("\"{}\" api_key", target.domain),
            format!("\"{}\" secret", target.domain),
            format!("\"{}\" token", target.domain),
            format!("\"{}\" credentials", target.domain),
        ];

        let mut findings = Vec::new();

        for dork in dorks {
            let url = format!(
                "https://api.github.com/search/code?q={}&per_page=10",
                urlencoding::encode(&dork)
            );

            let resp = client
                .get(&url)
                .header("Authorization", format!("token {}", api_key))
                .header("Accept", "application/vnd.github.v3+json")
                .header("User-Agent", "reconx/0.1.0")
                .send()
                .await?;

            if !resp.status().is_success() {
                continue;
            }

            let data: GithubSearchResponse = resp.json().await?;

            for item in data.items {
                let mut f = CredentialFinding::new(
                    target.domain.clone(),
                    item.repository
                        .and_then(|r| r.full_name)
                        .unwrap_or_else(|| "unknown".to_string()),
                    "github_dorks".to_string(),
                );
                f.severity = Severity::Medium;
                f.details = item.html_url;
                f.data_types = vec!["code_leak".to_string()];
                f.discovered_at = Utc::now();
                findings.push(Finding::Credential(f));
            }

            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }

        Ok(findings)
    }
}
