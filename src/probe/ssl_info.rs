use chrono::Utc;

use crate::models::SslFinding;
use crate::models::finding::Severity;

/// Passive SSL certificate intelligence.
/// Uses the crt.sh API to get certificate info without connecting to the target.
pub struct SslProber;

impl SslProber {
    pub async fn probe_passive(domain: &str) -> Vec<SslFinding> {
        let client = match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
        {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        // Use crt.sh to get certificate details passively
        let url = format!(
            "https://crt.sh/?q={}&output=json",
            domain
        );

        let resp = match client.get(&url).send().await {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };

        if !resp.status().is_success() {
            return Vec::new();
        }

        let entries: Vec<serde_json::Value> = match resp.json().await {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };

        let mut findings = Vec::new();
        let mut seen = std::collections::HashSet::new();

        // Get the most recent certificate entry for the domain
        for entry in entries.iter().take(5) {
            let issuer = entry
                .get("issuer_name")
                .and_then(|i| i.as_str())
                .unwrap_or("")
                .to_string();

            let common_name = entry
                .get("common_name")
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string();

            let not_before = entry
                .get("not_before")
                .and_then(|d| d.as_str())
                .unwrap_or("")
                .to_string();

            let not_after = entry
                .get("not_after")
                .and_then(|d| d.as_str())
                .unwrap_or("")
                .to_string();

            // Extract SANs from name_value
            let name_value = entry
                .get("name_value")
                .and_then(|n| n.as_str())
                .unwrap_or("");

            let sans: Vec<String> = name_value
                .split('\n')
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect();

            // Deduplicate by common_name
            if !seen.insert(common_name.clone()) {
                continue;
            }

            let mut finding = SslFinding::new(domain.to_string(), "crt.sh".to_string());
            finding.subject = Some(common_name.clone());
            finding.issuer = Some(issuer.clone());
            finding.not_before = Some(not_before.clone());
            finding.not_after = Some(not_after.clone());
            finding.sans = sans;
            finding.is_wildcard = common_name.starts_with('*');

            // Check self-signed
            if issuer.contains(&common_name) || issuer.to_lowercase().contains("self-signed") {
                finding.is_self_signed = true;
                finding.severity = Severity::High;
            }

            // Calculate days until expiry
            if let Ok(expiry) = chrono::NaiveDateTime::parse_from_str(&not_after, "%Y-%m-%dT%H:%M:%S") {
                let expiry_utc = expiry.and_utc();
                let days = (expiry_utc - Utc::now()).num_days();
                finding.days_until_expiry = Some(days);

                if days < 0 {
                    finding.is_expired = true;
                    finding.severity = Severity::High;
                } else if days < 30 {
                    finding.severity = Severity::Medium;
                }
            }

            finding.discovered_at = Utc::now();
            findings.push(finding);
        }

        findings
    }
}
