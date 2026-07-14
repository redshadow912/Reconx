use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::finding::Severity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslFinding {
    pub host: String,
    pub port: u16,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub sans: Vec<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub days_until_expiry: Option<i64>,
    pub is_expired: bool,
    pub is_self_signed: bool,
    pub is_wildcard: bool,
    pub key_algorithm: Option<String>,
    pub key_size: Option<u32>,
    pub signature_algorithm: Option<String>,
    pub serial_number: Option<String>,
    pub severity: Severity,
    pub source: String,
    pub discovered_at: DateTime<Utc>,
}

impl SslFinding {
    pub fn new(host: String, source: String) -> Self {
        Self {
            host,
            port: 443,
            subject: None,
            issuer: None,
            sans: Vec::new(),
            not_before: None,
            not_after: None,
            days_until_expiry: None,
            is_expired: false,
            is_self_signed: false,
            is_wildcard: false,
            key_algorithm: None,
            key_size: None,
            signature_algorithm: None,
            serial_number: None,
            severity: Severity::Info,
            source,
            discovered_at: Utc::now(),
        }
    }
}
