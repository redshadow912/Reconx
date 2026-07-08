use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;

use crate::collectors::{Collector, CollectorCategory};
use crate::config::Config;
use crate::error::{ReconxError, Result};
use crate::models::{Finding, Target, WirelessFinding};

pub struct WigleCollector;

#[derive(Debug, Deserialize)]
struct WigleResponse {
    #[serde(default)]
    results: Vec<WigleResult>,
}

#[derive(Debug, Deserialize)]
struct WigleResult {
    #[serde(default)]
    ssid: Option<String>,
    #[serde(default)]
    netid: Option<String>,
    #[serde(default)]
    encryption: Option<String>,
    #[serde(default)]
    channel: Option<u32>,
    #[serde(default)]
    trilat: Option<f64>,
    #[serde(default)]
    trilong: Option<f64>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    lastupdt: Option<String>,
}

#[async_trait]
impl Collector for WigleCollector {
    fn name(&self) -> &str {
        "wigle"
    }

    fn category(&self) -> CollectorCategory {
        CollectorCategory::Wireless
    }

    fn requires_api_key(&self) -> bool {
        true
    }

    async fn collect(&self, target: &Target, config: &Config) -> Result<Vec<Finding>> {
        let api_key = config
            .get_api_key("wigle")
            .ok_or(ReconxError::MissingApiKey {
                collector: "wigle".to_string(),
            })?
            .clone();

        let search_term = target
            .org_name
            .as_deref()
            .unwrap_or(&target.domain);

        let url = format!(
            "https://api.wigle.net/api/v2/network/search?ssid={}&freenet=false&paynet=false",
            urlencoding::encode(search_term)
        );

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let resp = client
            .get(&url)
            .basic_auth(&api_key, None::<&str>)
            .send()
            .await?;

        if !resp.status().is_success() {
            return Ok(Vec::new());
        }

        let data: WigleResponse = resp.json().await?;
        let mut findings = Vec::new();

        for result in data.results {
            let ssid = result.ssid.unwrap_or_default();
            let bssid = result.netid.unwrap_or_default();
            let encryption = result.encryption.unwrap_or_else(|| "unknown".to_string());

            let mut f = WirelessFinding::new(ssid, bssid, encryption, "wigle".to_string());
            f.channel = result.channel;

            if let (Some(lat), Some(lon)) = (result.trilat, result.trilong) {
                f.location = Some(crate::models::wireless::GeoLocation {
                    latitude: lat,
                    longitude: lon,
                    city: result.city,
                    country: result.country,
                });
            }

            f.discovered_at = Utc::now();
            findings.push(Finding::Wireless(f));
        }

        Ok(findings)
    }
}
