use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::finding::Severity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialFinding {
    pub email: String,
    pub breach_source: String,
    pub breach_date: Option<DateTime<Utc>>,
    pub data_types: Vec<String>,
    pub severity: Severity,
    pub source: String,
    pub details: Option<String>,
    pub discovered_at: DateTime<Utc>,
}

impl CredentialFinding {
    pub fn new(email: String, breach_source: String, source: String) -> Self {
        Self {
            email,
            breach_source,
            breach_date: None,
            data_types: Vec::new(),
            severity: Severity::High,
            source,
            details: None,
            discovered_at: Utc::now(),
        }
    }
}
