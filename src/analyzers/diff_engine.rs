use std::collections::HashSet;
use std::path::Path;

use crate::models::Finding;

#[derive(Debug, Clone)]
pub struct DiffResult {
    pub new_subdomains: Vec<String>,
    pub removed_subdomains: Vec<String>,
    pub new_assets: Vec<String>,
    pub removed_assets: Vec<String>,
    pub new_credentials: Vec<String>,
    pub new_vulnerabilities: Vec<String>,
    pub new_emails: Vec<String>,
    pub total_new: usize,
    pub total_removed: usize,
    pub previous_scan_date: Option<String>,
}

pub struct DiffEngine;

impl DiffEngine {
    /// Load previous findings from a JSON file
    pub fn load_previous(path: &Path) -> Option<Vec<Finding>> {
        let content = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&content).ok()
    }

    /// Compare current findings against previous ones
    pub fn diff(previous: &[Finding], current: &[Finding]) -> DiffResult {
        let prev_subdomains: HashSet<String> = previous
            .iter()
            .filter_map(|f| {
                if let Finding::Subdomain(s) = f {
                    Some(s.subdomain.clone())
                } else {
                    None
                }
            })
            .collect();

        let curr_subdomains: HashSet<String> = current
            .iter()
            .filter_map(|f| {
                if let Finding::Subdomain(s) = f {
                    Some(s.subdomain.clone())
                } else {
                    None
                }
            })
            .collect();

        let prev_assets: HashSet<String> = previous
            .iter()
            .filter_map(|f| {
                if let Finding::Asset(a) = f {
                    Some(format!("{}:{}", a.host, a.ip))
                } else {
                    None
                }
            })
            .collect();

        let curr_assets: HashSet<String> = current
            .iter()
            .filter_map(|f| {
                if let Finding::Asset(a) = f {
                    Some(format!("{}:{}", a.host, a.ip))
                } else {
                    None
                }
            })
            .collect();

        let prev_creds: HashSet<String> = previous
            .iter()
            .filter_map(|f| {
                if let Finding::Credential(c) = f {
                    Some(format!("{}:{}", c.email, c.breach_source))
                } else {
                    None
                }
            })
            .collect();

        let curr_creds: HashSet<String> = current
            .iter()
            .filter_map(|f| {
                if let Finding::Credential(c) = f {
                    Some(format!("{}:{}", c.email, c.breach_source))
                } else {
                    None
                }
            })
            .collect();

        let prev_vulns: HashSet<String> = previous
            .iter()
            .filter_map(|f| {
                if let Finding::Vulnerability(v) = f {
                    Some(format!("{}:{}", v.host, v.cve_id.as_deref().unwrap_or(&v.vulnerability_type)))
                } else {
                    None
                }
            })
            .collect();

        let curr_vulns: HashSet<String> = current
            .iter()
            .filter_map(|f| {
                if let Finding::Vulnerability(v) = f {
                    Some(format!("{}:{}", v.host, v.cve_id.as_deref().unwrap_or(&v.vulnerability_type)))
                } else {
                    None
                }
            })
            .collect();

        let prev_emails: HashSet<String> = previous
            .iter()
            .filter_map(|f| {
                if let Finding::Email(e) = f {
                    Some(e.email.clone())
                } else {
                    None
                }
            })
            .collect();

        let curr_emails: HashSet<String> = current
            .iter()
            .filter_map(|f| {
                if let Finding::Email(e) = f {
                    Some(e.email.clone())
                } else {
                    None
                }
            })
            .collect();

        let new_subdomains: Vec<String> = curr_subdomains.difference(&prev_subdomains).cloned().collect();
        let removed_subdomains: Vec<String> = prev_subdomains.difference(&curr_subdomains).cloned().collect();
        let new_assets: Vec<String> = curr_assets.difference(&prev_assets).cloned().collect();
        let removed_assets: Vec<String> = prev_assets.difference(&curr_assets).cloned().collect();
        let new_credentials: Vec<String> = curr_creds.difference(&prev_creds).cloned().collect();
        let new_vulnerabilities: Vec<String> = curr_vulns.difference(&prev_vulns).cloned().collect();
        let new_emails: Vec<String> = curr_emails.difference(&prev_emails).cloned().collect();

        let total_new = new_subdomains.len() + new_assets.len() + new_credentials.len()
            + new_vulnerabilities.len() + new_emails.len();
        let total_removed = removed_subdomains.len() + removed_assets.len();

        // Try to get timestamp from previous findings
        let previous_scan_date = previous.first().map(|f| f.timestamp().to_rfc3339());

        DiffResult {
            new_subdomains,
            removed_subdomains,
            new_assets,
            removed_assets,
            new_credentials,
            new_vulnerabilities,
            new_emails,
            total_new,
            total_removed,
            previous_scan_date,
        }
    }
}
