use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub port: u16,
    pub protocol: String,
    pub service_name: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetFinding {
    pub host: String,
    pub ip: String,
    pub ports: Vec<u16>,
    pub services: Vec<ServiceInfo>,
    pub technologies: Vec<String>,
    pub source: String,
    pub asn: Option<String>,
    pub org: Option<String>,
    pub country: Option<String>,
    pub discovered_at: DateTime<Utc>,
}

impl AssetFinding {
    pub fn new(host: String, ip: String, source: String) -> Self {
        Self {
            host,
            ip,
            ports: Vec::new(),
            services: Vec::new(),
            technologies: Vec::new(),
            source,
            asn: None,
            org: None,
            country: None,
            discovered_at: Utc::now(),
        }
    }
}
