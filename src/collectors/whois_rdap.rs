use async_trait::async_trait;
use chrono::Utc;

use crate::collectors::{Collector, CollectorCategory};
use crate::config::Config;
use crate::error::Result;
use crate::models::{Finding, WhoisFinding, Target};

pub struct WhoisRdapCollector;

#[async_trait]
impl Collector for WhoisRdapCollector {
    fn name(&self) -> &str {
        "whois_rdap"
    }

    fn category(&self) -> CollectorCategory {
        CollectorCategory::WhoisAsn
    }

    fn requires_api_key(&self) -> bool {
        false
    }

    async fn collect(&self, target: &Target, _config: &Config) -> Result<Vec<Finding>> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()?;

        let mut finding = WhoisFinding::new(target.domain.clone(), "whois_rdap".to_string());

        // Try RDAP (Registration Data Access Protocol) - the modern replacement for WHOIS
        // RDAP is fully passive and standardized
        let rdap_url = format!("https://rdap.org/domain/{}", target.domain);

        let resp = match client
            .get(&rdap_url)
            .header("Accept", "application/rdap+json")
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => return Ok(Vec::new()),
        };

        if !resp.status().is_success() {
            return Ok(Vec::new());
        }

        let body: serde_json::Value = match resp.json().await {
            Ok(v) => v,
            Err(_) => return Ok(Vec::new()),
        };

        // Extract registrar
        if let Some(entities) = body.get("entities").and_then(|e| e.as_array()) {
            for entity in entities {
                if let Some(roles) = entity.get("roles").and_then(|r| r.as_array()) {
                    let role_strs: Vec<&str> = roles
                        .iter()
                        .filter_map(|r| r.as_str())
                        .collect();

                    if role_strs.contains(&"registrar") {
                        // Get registrar name from vcardArray
                        if let Some(vcard) = entity.get("vcardArray").and_then(|v| v.as_array()) {
                            if let Some(entries) = vcard.get(1).and_then(|e| e.as_array()) {
                                for entry in entries {
                                    if let Some(arr) = entry.as_array() {
                                        if arr.first().and_then(|v| v.as_str()) == Some("fn") {
                                            if let Some(name) = arr.last().and_then(|v| v.as_str()) {
                                                finding.registrar = Some(name.to_string());
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        // Fallback to handle field
                        if finding.registrar.is_none() {
                            if let Some(handle) = entity.get("handle").and_then(|h| h.as_str()) {
                                finding.registrar = Some(handle.to_string());
                            }
                        }
                    }

                    if role_strs.contains(&"registrant") {
                        // Extract registrant info
                        if let Some(vcard) = entity.get("vcardArray").and_then(|v| v.as_array()) {
                            if let Some(entries) = vcard.get(1).and_then(|e| e.as_array()) {
                                for entry in entries {
                                    if let Some(arr) = entry.as_array() {
                                        let field_name = arr.first().and_then(|v| v.as_str()).unwrap_or("");
                                        match field_name {
                                            "org" => {
                                                if let Some(org) = arr.last().and_then(|v| v.as_str()) {
                                                    finding.registrant_org = Some(org.to_string());
                                                }
                                            }
                                            "fn" => {
                                                if finding.registrant_org.is_none() {
                                                    if let Some(name) = arr.last().and_then(|v| v.as_str()) {
                                                        finding.registrant_org = Some(name.to_string());
                                                    }
                                                }
                                            }
                                            "adr" => {
                                                // Try to extract country from address
                                                if let Some(last) = arr.last() {
                                                    let _addr_str = last.to_string();
                                                    // Country is typically the last field in a vCard address
                                                    if let Some(parts) = last.as_array() {
                                                        if let Some(country) = parts.last().and_then(|c| c.as_str()) {
                                                            if !country.is_empty() {
                                                                finding.registrant_country = Some(country.to_string());
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                            }
                        }

                        // Check for privacy protection
                        if let Some(vcard) = entity.get("vcardArray").and_then(|v| v.as_array()) {
                            let vcard_str = serde_json::to_string(vcard).unwrap_or_default().to_lowercase();
                            if vcard_str.contains("privacy")
                                || vcard_str.contains("redacted")
                                || vcard_str.contains("whoisguard")
                                || vcard_str.contains("domains by proxy")
                                || vcard_str.contains("contact privacy")
                                || vcard_str.contains("withheld")
                            {
                                finding.is_privacy_protected = true;
                            }
                        }
                    }
                }
            }
        }

        // Extract events (dates)
        if let Some(events) = body.get("events").and_then(|e| e.as_array()) {
            for event in events {
                let action = event.get("eventAction").and_then(|a| a.as_str()).unwrap_or("");
                let date = event.get("eventDate").and_then(|d| d.as_str()).unwrap_or("");

                match action {
                    "registration" => {
                        finding.creation_date = Some(date.to_string());
                        // Calculate domain age
                        if let Ok(created) = chrono::DateTime::parse_from_rfc3339(date) {
                            let age = Utc::now().signed_duration_since(created);
                            finding.domain_age_days = Some(age.num_days());
                        }
                    }
                    "expiration" => {
                        finding.expiration_date = Some(date.to_string());
                        // Calculate days until expiry
                        if let Ok(expires) = chrono::DateTime::parse_from_rfc3339(date) {
                            let days = expires.signed_duration_since(Utc::now()).num_days();
                            finding.days_until_expiry = Some(days);
                        }
                    }
                    "last changed" | "last update of RDAP database" => {
                        if action == "last changed" {
                            finding.updated_date = Some(date.to_string());
                        }
                    }
                    _ => {}
                }
            }
        }

        // Extract nameservers
        if let Some(nameservers) = body.get("nameservers").and_then(|n| n.as_array()) {
            for ns in nameservers {
                if let Some(name) = ns.get("ldhName").and_then(|n| n.as_str()) {
                    finding.nameservers.push(name.to_lowercase());
                }
            }
        }

        // Extract status
        if let Some(statuses) = body.get("status").and_then(|s| s.as_array()) {
            for status in statuses {
                if let Some(s) = status.as_str() {
                    finding.status.push(s.to_string());
                }
            }
        }

        // Extract DNSSEC
        if let Some(dnssec) = body.get("secureDNS") {
            if let Some(delegation_signed) = dnssec.get("delegationSigned").and_then(|d| d.as_bool()) {
                finding.dnssec = Some(if delegation_signed { "signed".to_string() } else { "unsigned".to_string() });
            }
        }

        finding.discovered_at = Utc::now();
        Ok(vec![Finding::Whois(finding)])
    }
}
