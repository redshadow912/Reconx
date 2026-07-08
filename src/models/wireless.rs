use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    pub latitude: f64,
    pub longitude: f64,
    pub city: Option<String>,
    pub country: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WirelessFinding {
    pub ssid: String,
    pub bssid: String,
    pub encryption: String,
    pub channel: Option<u32>,
    pub location: Option<GeoLocation>,
    pub last_seen: Option<DateTime<Utc>>,
    pub source: String,
    pub discovered_at: DateTime<Utc>,
}

impl WirelessFinding {
    pub fn new(ssid: String, bssid: String, encryption: String, source: String) -> Self {
        Self {
            ssid,
            bssid,
            encryption,
            channel: None,
            location: None,
            last_seen: None,
            source,
            discovered_at: Utc::now(),
        }
    }
}
