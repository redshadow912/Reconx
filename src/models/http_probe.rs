use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpProbeFinding {
    pub url: String,
    pub final_url: String,
    pub status_code: u16,
    pub title: Option<String>,
    pub content_type: Option<String>,
    pub content_length: usize,
    pub server: Option<String>,
    pub technologies: Vec<String>,
    pub cdn: Option<String>,
    pub waf: Option<String>,
    pub redirects: Vec<String>,
    pub discovered_at: DateTime<Utc>,
}

impl HttpProbeFinding {
    pub fn new(url: String) -> Self {
        Self {
            url,
            final_url: String::new(),
            status_code: 0,
            title: None,
            content_type: None,
            content_length: 0,
            server: None,
            technologies: Vec::new(),
            cdn: None,
            waf: None,
            redirects: Vec::new(),
            discovered_at: Utc::now(),
        }
    }
}
