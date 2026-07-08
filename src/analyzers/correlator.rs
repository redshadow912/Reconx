use std::collections::HashMap;

use crate::models::Finding;

#[derive(Debug, Clone)]
pub struct CorrelatedSubdomain {
    pub subdomain: String,
    pub sources: Vec<String>,
    pub ip_addresses: Vec<String>,
    pub confidence: u8,
    pub is_wildcard: bool,
}

pub struct Correlator;

impl Correlator {
    pub fn correlate(findings: &[Finding]) -> Vec<CorrelatedSubdomain> {
        let mut subdomain_map: HashMap<String, CorrelatedSubdomain> = HashMap::new();

        for finding in findings {
            if let Finding::Subdomain(sub) = finding {
                let entry = subdomain_map
                    .entry(sub.subdomain.clone())
                    .or_insert_with(|| CorrelatedSubdomain {
                        subdomain: sub.subdomain.clone(),
                        sources: Vec::new(),
                        ip_addresses: Vec::new(),
                        confidence: 0,
                        is_wildcard: sub.is_wildcard,
                    });

                if !entry.sources.contains(&sub.source) {
                    entry.sources.push(sub.source.clone());
                }

                for ip in &sub.ip_addresses {
                    if !entry.ip_addresses.contains(ip) {
                        entry.ip_addresses.push(ip.clone());
                    }
                }

                entry.confidence = (entry.sources.len() as u8).min(10);
            }
        }

        let mut results: Vec<CorrelatedSubdomain> = subdomain_map.into_values().collect();
        results.sort_by(|a, b| b.confidence.cmp(&a.confidence));
        results
    }

    pub fn dedup_findings(findings: Vec<Finding>) -> Vec<Finding> {
        let mut seen_subdomains = std::collections::HashSet::new();
        let mut seen_assets = std::collections::HashSet::new();
        let mut seen_creds = std::collections::HashSet::new();
        let mut seen_wireless = std::collections::HashSet::new();

        let mut deduped = Vec::new();

        for finding in findings {
            match &finding {
                Finding::Subdomain(s) => {
                    if seen_subdomains.insert(s.subdomain.clone()) {
                        deduped.push(finding);
                    }
                }
                Finding::Asset(a) => {
                    let key = format!("{}:{}", a.host, a.ip);
                    if seen_assets.insert(key) {
                        deduped.push(finding);
                    }
                }
                Finding::Credential(c) => {
                    let key = format!("{}:{}", c.email, c.breach_source);
                    if seen_creds.insert(key) {
                        deduped.push(finding);
                    }
                }
                Finding::Wireless(w) => {
                    let key = format!("{}:{}", w.ssid, w.bssid);
                    if seen_wireless.insert(key) {
                        deduped.push(finding);
                    }
                }
                Finding::Vulnerability(_) => {
                    deduped.push(finding);
                }
            }
        }

        deduped
    }
}
