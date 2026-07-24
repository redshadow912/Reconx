use std::collections::HashMap;

use crate::models::Finding;

#[derive(Debug, Clone)]
#[allow(dead_code)]
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
        let mut seen_emails = std::collections::HashSet::new();
        let mut seen_probes = std::collections::HashSet::new();
        let mut seen_whois = std::collections::HashSet::new();
        let mut seen_ssl = std::collections::HashSet::new();

        // First pass: collect all sources per subdomain for confidence scoring
        let mut subdomain_sources: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        for finding in &findings {
            if let Finding::Subdomain(s) = finding {
                subdomain_sources
                    .entry(s.subdomain.clone())
                    .or_default()
                    .push(s.source.clone());
            }
        }

        let mut deduped = Vec::new();

        for finding in findings {
            match &finding {
                Finding::Subdomain(s) => {
                    if seen_subdomains.insert(s.subdomain.clone()) {
                        // Enrich the first occurrence with multi-source confidence
                        let mut enriched = s.clone();
                        if let Some(sources) = subdomain_sources.get(&s.subdomain) {
                            enriched.confidence = (sources.len() as u8).min(10);
                        }
                        deduped.push(Finding::Subdomain(enriched));
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
                Finding::Email(e) => {
                    if seen_emails.insert(e.email.clone()) {
                        deduped.push(finding);
                    }
                }
                Finding::HttpProbe(p) => {
                    if seen_probes.insert(p.url.clone()) {
                        deduped.push(finding);
                    }
                }
                Finding::Whois(w) => {
                    if seen_whois.insert(w.domain.clone()) {
                        deduped.push(finding);
                    }
                }
                Finding::Ssl(s) => {
                    let key = format!("{}:{}", s.host, s.port);
                    if seen_ssl.insert(key) {
                        deduped.push(finding);
                    }
                }
            }
        }

        deduped
    }
}
