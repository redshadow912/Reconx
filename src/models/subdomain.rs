use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub record_type: String,
    pub value: String,
    pub ttl: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainFinding {
    pub subdomain: String,
    pub source: String,
    pub ip_addresses: Vec<String>,
    pub cname: Option<String>,
    pub dns_records: Vec<DnsRecord>,
    pub first_seen: Option<DateTime<Utc>>,
    pub is_wildcard: bool,
    pub confidence: u8,
    pub discovered_at: DateTime<Utc>,
}

impl SubdomainFinding {
    pub fn new(subdomain: String, source: String) -> Self {
        Self {
            subdomain,
            source,
            ip_addresses: Vec::new(),
            cname: None,
            dns_records: Vec::new(),
            first_seen: None,
            is_wildcard: false,
            confidence: 1,
            discovered_at: Utc::now(),
        }
    }
}
