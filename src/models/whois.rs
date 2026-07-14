use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoisFinding {
    pub domain: String,
    pub registrar: Option<String>,
    pub creation_date: Option<String>,
    pub expiration_date: Option<String>,
    pub updated_date: Option<String>,
    pub nameservers: Vec<String>,
    pub registrant_org: Option<String>,
    pub registrant_country: Option<String>,
    pub dnssec: Option<String>,
    pub status: Vec<String>,
    pub days_until_expiry: Option<i64>,
    pub domain_age_days: Option<i64>,
    pub is_privacy_protected: bool,
    pub source: String,
    pub discovered_at: DateTime<Utc>,
}

impl WhoisFinding {
    pub fn new(domain: String, source: String) -> Self {
        Self {
            domain,
            registrar: None,
            creation_date: None,
            expiration_date: None,
            updated_date: None,
            nameservers: Vec::new(),
            registrant_org: None,
            registrant_country: None,
            dnssec: None,
            status: Vec::new(),
            days_until_expiry: None,
            domain_age_days: None,
            is_privacy_protected: false,
            source,
            discovered_at: Utc::now(),
        }
    }
}
