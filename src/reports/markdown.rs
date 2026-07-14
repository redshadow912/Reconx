use std::path::Path;

use crate::analyzers::risk_scorer::RiskScore;
use crate::analyzers::takeover_detector::TakeoverResult;
use crate::analyzers::diff_engine::DiffResult;
use crate::error::Result;
use crate::models::Finding;

pub fn generate(
    findings: &[Finding],
    domain: &str,
    risk: &RiskScore,
    takeovers: &[TakeoverResult],
    diff: Option<&DiffResult>,
    output_path: &Path,
) -> Result<()> {
    let mut md = String::new();

    md.push_str(&format!("# 🔍 Reconx Intelligence Report — `{}`\n\n", domain));
    md.push_str(&format!("**Generated:** {} UTC  \n", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S")));
    md.push_str(&format!("**Tool:** Reconx v0.1.0 (Passive OSINT)  \n\n"));

    md.push_str("---\n\n");

    // Executive Summary
    md.push_str("## 📊 Executive Summary\n\n");
    md.push_str(&format!("| Metric | Value |\n"));
    md.push_str(&format!("|--------|-------|\n"));
    md.push_str(&format!("| **Risk Score** | **{:.1}/10** ({}) |\n", risk.overall_score, risk.risk_level));
    md.push_str(&format!("| Subdomains | {} |\n", risk.subdomain_count));
    md.push_str(&format!("| Assets | {} |\n", risk.asset_count));
    md.push_str(&format!("| Credentials | {} |\n", risk.credential_count));
    md.push_str(&format!("| Emails | {} |\n", risk.email_count));
    md.push_str(&format!("| Vulnerabilities | {} |\n", risk.vulnerability_count));
    md.push_str(&format!("| Takeover Candidates | {} |\n", risk.takeover_count));
    md.push_str(&format!("| Wireless Networks | {} |\n", risk.wireless_count));
    md.push_str(&format!("| **Total Findings** | **{}** |\n\n", findings.len()));

    // Top Risk Factors
    if !risk.top_factors.is_empty() {
        md.push_str("### ⚠️ Top Risk Factors\n\n");
        for factor in risk.top_factors.iter().take(10) {
            let emoji = match factor.severity {
                crate::models::finding::Severity::Critical => "🔴",
                crate::models::finding::Severity::High => "🟠",
                crate::models::finding::Severity::Medium => "🟡",
                crate::models::finding::Severity::Low => "🟢",
                crate::models::finding::Severity::Info => "🔵",
            };
            md.push_str(&format!("- {} **{}** — {}\n", emoji, factor.category, factor.description));
        }
        md.push_str("\n");
    }

    // Diff Report
    if let Some(diff) = diff {
        md.push_str("---\n\n## 🔄 Changes Since Last Scan\n\n");
        if let Some(ref date) = diff.previous_scan_date {
            md.push_str(&format!("**Previous scan:** {}  \n\n", date));
        }
        md.push_str(&format!("| Change | Count |\n"));
        md.push_str(&format!("|--------|-------|\n"));
        md.push_str(&format!("| New subdomains | +{} |\n", diff.new_subdomains.len()));
        md.push_str(&format!("| Removed subdomains | -{} |\n", diff.removed_subdomains.len()));
        md.push_str(&format!("| New assets | +{} |\n", diff.new_assets.len()));
        md.push_str(&format!("| New credentials | +{} |\n", diff.new_credentials.len()));
        md.push_str(&format!("| New vulnerabilities | +{} |\n\n", diff.new_vulnerabilities.len()));

        if !diff.new_subdomains.is_empty() {
            md.push_str("**New subdomains discovered:**\n");
            for sub in &diff.new_subdomains {
                md.push_str(&format!("- `{}`\n", sub));
            }
            md.push_str("\n");
        }
        if !diff.removed_subdomains.is_empty() {
            md.push_str("**Subdomains no longer found:**\n");
            for sub in &diff.removed_subdomains {
                md.push_str(&format!("- ~~`{}`~~\n", sub));
            }
            md.push_str("\n");
        }
    }

    // Subdomain Takeover
    if !takeovers.is_empty() {
        md.push_str("---\n\n## 🚨 Subdomain Takeover Candidates\n\n");
        md.push_str("| Subdomain | CNAME | Service | Severity |\n");
        md.push_str("|-----------|-------|---------|----------|\n");
        for t in takeovers {
            md.push_str(&format!("| `{}` | `{}` | {} | **{}** |\n",
                t.subdomain, t.cname, t.service, t.severity));
        }
        md.push_str("\n");
    }

    // Subdomains
    let subdomains: Vec<&crate::models::SubdomainFinding> = findings
        .iter()
        .filter_map(|f| if let Finding::Subdomain(s) = f { Some(s) } else { None })
        .collect();

    if !subdomains.is_empty() {
        md.push_str("---\n\n## 🌐 Subdomains\n\n");
        md.push_str(&format!("**Total:** {}  \n\n", subdomains.len()));
        md.push_str("| Subdomain | Source | IPs | Confidence |\n");
        md.push_str("|-----------|--------|-----|------------|\n");
        for sub in &subdomains {
            md.push_str(&format!("| `{}` | {} | {} | {} |\n",
                sub.subdomain, sub.source,
                if sub.ip_addresses.is_empty() { "-".to_string() } else { sub.ip_addresses.join(", ") },
                sub.confidence));
        }
        md.push_str("\n");
    }

    // Assets
    let assets: Vec<&crate::models::AssetFinding> = findings
        .iter()
        .filter_map(|f| if let Finding::Asset(a) = f { Some(a) } else { None })
        .collect();

    if !assets.is_empty() {
        md.push_str("---\n\n## 🖥️ Assets & Services\n\n");
        md.push_str("| Host | IP | Ports | Services | Technologies |\n");
        md.push_str("|------|----|-------|----------|--------------|\n");
        for a in &assets {
            let ports: Vec<String> = a.ports.iter().map(|p| p.to_string()).collect();
            let services: Vec<String> = a.services.iter()
                .map(|s| s.service_name.as_deref().unwrap_or("unknown").to_string())
                .collect();
            md.push_str(&format!("| `{}` | {} | {} | {} | {} |\n",
                a.host, a.ip,
                if ports.is_empty() { "-".to_string() } else { ports.join(", ") },
                if services.is_empty() { "-".to_string() } else { services.join(", ") },
                if a.technologies.is_empty() { "-".to_string() } else { a.technologies.join(", ") }));
        }
        md.push_str("\n");
    }

    // Credentials
    let creds: Vec<&crate::models::CredentialFinding> = findings
        .iter()
        .filter_map(|f| if let Finding::Credential(c) = f { Some(c) } else { None })
        .collect();

    if !creds.is_empty() {
        md.push_str("---\n\n## 🔑 Credential Leaks\n\n");
        md.push_str("| Email | Breach Source | Data Types | Severity |\n");
        md.push_str("|-------|-------------|------------|----------|\n");
        for c in &creds {
            md.push_str(&format!("| `{}` | {} | {} | **{}** |\n",
                c.email, c.breach_source, c.data_types.join(", "), c.severity));
        }
        md.push_str("\n");
    }

    // Vulnerabilities
    let vulns: Vec<&crate::models::VulnFinding> = findings
        .iter()
        .filter_map(|f| if let Finding::Vulnerability(v) = f { Some(v) } else { None })
        .collect();

    if !vulns.is_empty() {
        md.push_str("---\n\n## 🛡️ Vulnerabilities\n\n");
        md.push_str("| Host | Type | CVE | Severity | Source |\n");
        md.push_str("|------|------|-----|----------|--------|\n");
        for v in &vulns {
            md.push_str(&format!("| `{}` | {} | {} | **{}** | {} |\n",
                v.host, v.vulnerability_type,
                v.cve_id.as_deref().unwrap_or("-"),
                v.severity, v.source));
        }
        md.push_str("\n");
    }

    // WHOIS
    let whois: Vec<&crate::models::WhoisFinding> = findings
        .iter()
        .filter_map(|f| if let Finding::Whois(w) = f { Some(w) } else { None })
        .collect();

    if !whois.is_empty() {
        md.push_str("---\n\n## 📋 WHOIS Intelligence\n\n");
        for w in &whois {
            md.push_str(&format!("| Property | Value |\n"));
            md.push_str(&format!("|----------|-------|\n"));
            md.push_str(&format!("| Domain | `{}` |\n", w.domain));
            if let Some(ref r) = w.registrar { md.push_str(&format!("| Registrar | {} |\n", r)); }
            if let Some(ref d) = w.creation_date { md.push_str(&format!("| Created | {} |\n", d)); }
            if let Some(ref d) = w.expiration_date { md.push_str(&format!("| Expires | {} |\n", d)); }
            if let Some(days) = w.days_until_expiry { md.push_str(&format!("| Days Until Expiry | **{}** |\n", days)); }
            if let Some(age) = w.domain_age_days { md.push_str(&format!("| Domain Age | {} days |\n", age)); }
            if let Some(ref org) = w.registrant_org { md.push_str(&format!("| Registrant Org | {} |\n", org)); }
            if let Some(ref c) = w.registrant_country { md.push_str(&format!("| Registrant Country | {} |\n", c)); }
            if !w.nameservers.is_empty() { md.push_str(&format!("| Nameservers | {} |\n", w.nameservers.join(", "))); }
            if let Some(ref d) = w.dnssec { md.push_str(&format!("| DNSSEC | {} |\n", d)); }
            md.push_str(&format!("| Privacy Protected | {} |\n\n", if w.is_privacy_protected { "Yes" } else { "No" }));
        }
    }

    // SSL
    let ssl: Vec<&crate::models::SslFinding> = findings
        .iter()
        .filter_map(|f| if let Finding::Ssl(s) = f { Some(s) } else { None })
        .collect();

    if !ssl.is_empty() {
        md.push_str("---\n\n## 🔒 SSL/TLS Certificates\n\n");
        md.push_str("| Host | Subject | Issuer | Expires | Status |\n");
        md.push_str("|------|---------|--------|---------|--------|\n");
        for s in &ssl {
            let status = if s.is_expired { "❌ EXPIRED" }
                else if s.is_self_signed { "⚠️ Self-signed" }
                else if s.days_until_expiry.map_or(false, |d| d < 30) { "⚠️ Expiring soon" }
                else { "✅ Valid" };
            md.push_str(&format!("| `{}` | {} | {} | {} | {} |\n",
                s.host,
                s.subject.as_deref().unwrap_or("-"),
                s.issuer.as_deref().unwrap_or("-"),
                s.not_after.as_deref().unwrap_or("-"),
                status));
        }
        if ssl.iter().any(|s| !s.sans.is_empty()) {
            md.push_str("\n**Subject Alternative Names discovered:**\n");
            for s in &ssl {
                if !s.sans.is_empty() {
                    for san in &s.sans {
                        md.push_str(&format!("- `{}`\n", san));
                    }
                }
            }
        }
        md.push_str("\n");
    }

    // Emails
    let emails: Vec<&crate::models::EmailFinding> = findings
        .iter()
        .filter_map(|f| if let Finding::Email(e) = f { Some(e) } else { None })
        .collect();

    if !emails.is_empty() {
        md.push_str("---\n\n## 📧 Email Addresses\n\n");
        md.push_str("| Email | Name | Position | Source |\n");
        md.push_str("|-------|------|----------|--------|\n");
        for e in &emails {
            md.push_str(&format!("| `{}` | {} | {} | {} |\n",
                e.email,
                e.name.as_deref().unwrap_or("-"),
                e.position.as_deref().unwrap_or("-"),
                e.source));
        }
        md.push_str("\n");
    }

    // Wireless
    let wireless: Vec<&crate::models::WirelessFinding> = findings
        .iter()
        .filter_map(|f| if let Finding::Wireless(w) = f { Some(w) } else { None })
        .collect();

    if !wireless.is_empty() {
        md.push_str("---\n\n## 📡 Wireless Networks\n\n");
        md.push_str("| SSID | BSSID | Encryption | Channel | Location |\n");
        md.push_str("|------|-------|------------|---------|----------|\n");
        for w in &wireless {
            let loc = w.location.as_ref()
                .map(|l| format!("{:.4}, {:.4}", l.latitude, l.longitude))
                .unwrap_or_else(|| "-".to_string());
            md.push_str(&format!("| {} | `{}` | {} | {} | {} |\n",
                w.ssid, w.bssid, w.encryption,
                w.channel.map(|c| c.to_string()).unwrap_or_else(|| "-".to_string()),
                loc));
        }
        md.push_str("\n");
    }

    md.push_str("---\n\n");
    md.push_str("*Generated by **Reconx** v0.1.0 — Passive OSINT Reconnaissance Tool*\n");

    let md_path = output_path.join("report.md");
    std::fs::write(&md_path, md)?;

    Ok(())
}
