use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;

use crate::collectors::{Collector, CollectorCategory};
use crate::config::Config;
use crate::error::{ReconxError, Result};
use crate::models::{AssetFinding, Finding, ServiceInfo, Target};

pub struct ShodanCollector;

#[derive(Debug, Deserialize)]
struct ShodanHostResponse {
    #[serde(default)]
    data: Option<Vec<ShodanService>>,
    #[serde(default)]
    ports: Option<Vec<u16>>,
    #[serde(default)]
    vulns: Option<Vec<String>>,
    #[serde(default)]
    os: Option<String>,
    #[serde(default)]
    asn: Option<String>,
    #[serde(default)]
    org: Option<String>,
    #[serde(default)]
    country_code: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ShodanService {
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    transport: Option<String>,
    #[serde(default)]
    product: Option<String>,
    #[serde(default)]
    version: Option<String>,
}

#[async_trait]
impl Collector for ShodanCollector {
    fn name(&self) -> &str {
        "shodan"
    }

    fn category(&self) -> CollectorCategory {
        CollectorCategory::HostService
    }

    fn requires_api_key(&self) -> bool {
        true
    }

    async fn collect(&self, target: &Target, config: &Config) -> Result<Vec<Finding>> {
        let api_key = config
            .get_api_key("shodan")
            .ok_or(ReconxError::MissingApiKey {
                collector: "shodan".to_string(),
            })?
            .clone();

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let search_url = format!(
            "https://api.shodan.io/shodan/host/search?key={}&query=hostname:{}",
            api_key, target.domain
        );

        let resp = client.get(&search_url).send().await?;
        if !resp.status().is_success() {
            return Ok(Vec::new());
        }

        let body: serde_json::Value = resp.json().await?;
        let mut findings = Vec::new();

        if let Some(matches) = body.get("matches").and_then(|m| m.as_array()) {
            for m in matches {
                let ip = m
                    .get("ip_str")
                    .and_then(|i| i.as_str())
                    .unwrap_or("")
                    .to_string();
                let host = m
                    .get("hostnames")
                    .and_then(|h| h.as_array())
                    .and_then(|a| a.first())
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let mut f = AssetFinding::new(host, ip, "shodan".to_string());

                if let Some(port) = m.get("port").and_then(|p| p.as_u64()) {
                    f.ports.push(port as u16);
                    f.services.push(ServiceInfo {
                        port: port as u16,
                        protocol: m
                            .get("transport")
                            .and_then(|t| t.as_str())
                            .unwrap_or("tcp")
                            .to_string(),
                        service_name: m.get("product").and_then(|p| p.as_str()).map(|s| s.to_string()),
                        version: m.get("version").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        banner: m.get("data").and_then(|d| d.as_str()).map(|s| s.to_string()),
                    });
                }

                f.asn = m.get("asn").and_then(|a| a.as_str()).map(|s| s.to_string());
                f.org = m.get("org").and_then(|o| o.as_str()).map(|s| s.to_string());
                f.country = m
                    .get("location")
                    .and_then(|l| l.get("country_code"))
                    .and_then(|c| c.as_str())
                    .map(|s| s.to_string());

                f.discovered_at = Utc::now();
                findings.push(Finding::Asset(f));
            }
        }

        Ok(findings)
    }
}
