use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailFinding {
    pub email: String,
    pub source: String,
    pub name: Option<String>,
    pub position: Option<String>,
    pub confidence: Option<u8>,
    pub discovered_at: DateTime<Utc>,
}

impl EmailFinding {
    pub fn new(email: String, source: String) -> Self {
        Self {
            email,
            source,
            name: None,
            position: None,
            confidence: None,
            discovered_at: Utc::now(),
        }
    }
}
