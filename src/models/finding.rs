use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub domain: String,
    pub org_name: Option<String>,
    pub include_subdomains: bool,
}

impl Target {
    pub fn new(domain: String) -> Self {
        Self {
            domain,
            org_name: None,
            include_subdomains: true,
        }
    }

    pub fn with_org(mut self, org_name: Option<String>) -> Self {
        self.org_name = org_name;
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Finding {
    Subdomain(super::SubdomainFinding),
    Asset(super::AssetFinding),
    Credential(super::CredentialFinding),
    Wireless(super::WirelessFinding),
    Vulnerability(super::VulnFinding),
}

impl Finding {
    pub fn source(&self) -> &str {
        match self {
            Finding::Subdomain(f) => &f.source,
            Finding::Asset(f) => &f.source,
            Finding::Credential(f) => &f.source,
            Finding::Wireless(f) => &f.source,
            Finding::Vulnerability(f) => &f.source,
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            Finding::Subdomain(_) => Severity::Info,
            Finding::Asset(_) => Severity::Info,
            Finding::Credential(f) => f.severity,
            Finding::Wireless(_) => Severity::Low,
            Finding::Vulnerability(f) => f.severity,
        }
    }

    pub fn timestamp(&self) -> DateTime<Utc> {
        match self {
            Finding::Subdomain(f) => f.discovered_at,
            Finding::Asset(f) => f.discovered_at,
            Finding::Credential(f) => f.discovered_at,
            Finding::Wireless(f) => f.discovered_at,
            Finding::Vulnerability(f) => f.discovered_at,
        }
    }
}
