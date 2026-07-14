use std::path::Path;

use crate::analyzers::risk_scorer::RiskScore;
use crate::error::Result;
use crate::models::Finding;

pub fn generate(findings: &[Finding], domain: &str, risk: &RiskScore, output_path: &Path) -> Result<()> {    let subdomains: Vec<&crate::models::SubdomainFinding> = findings
        .iter()
        .filter_map(|f| {
            if let Finding::Subdomain(s) = f {
                Some(s)
            } else {
                None
            }
        })
        .collect();

    let assets: Vec<&crate::models::AssetFinding> = findings
        .iter()
        .filter_map(|f| {
            if let Finding::Asset(a) = f {
                Some(a)
            } else {
                None
            }
        })
        .collect();

    let credentials: Vec<&crate::models::CredentialFinding> = findings
        .iter()
        .filter_map(|f| {
            if let Finding::Credential(c) = f {
                Some(c)
            } else {
                None
            }
        })
        .collect();

    let wireless: Vec<&crate::models::WirelessFinding> = findings
        .iter()
        .filter_map(|f| {
            if let Finding::Wireless(w) = f {
                Some(w)
            } else {
                None
            }
        })
        .collect();

    let html = build_html(domain, &risk, &subdomains, &assets, &credentials, &wireless);

    let html_path = output_path.join("report.html");
    std::fs::write(&html_path, html)?;

    Ok(())
}

fn build_html(
    domain: &str,
    risk: &RiskScore,
    subdomains: &[&crate::models::SubdomainFinding],
    assets: &[&crate::models::AssetFinding],
    credentials: &[&crate::models::CredentialFinding],
    wireless: &[&crate::models::WirelessFinding],
) -> String {
    let mut html = String::new();

    html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
    html.push_str("<meta charset=\"UTF-8\">\n");
    html.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
    html.push_str(&format!("<title>Reconx Report - {}</title>\n", domain));
    html.push_str(STYLE);
    html.push_str("</head>\n<body>\n");

    html.push_str("<div class=\"container\">\n");
    html.push_str("<h1>Reconx Intelligence Report</h1>\n");
    html.push_str(&format!("<p class=\"meta\">Target: <strong>{}</strong> | Generated: {}</p>\n",
        domain, chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")));

    html.push_str("<div class=\"summary\">\n");
    html.push_str("<h2>Executive Summary</h2>\n");
    html.push_str("<div class=\"metrics\">\n");
    html.push_str(&format!("<div class=\"metric\"><span class=\"value\">{:.1}</span><span class=\"label\">Risk Score</span><span class=\"badge badge-{}\">{}</span></div>\n",
        risk.overall_score, severity_class(&risk.risk_level), risk.risk_level));
    html.push_str(&format!("<div class=\"metric\"><span class=\"value\">{}</span><span class=\"label\">Subdomains</span></div>\n", risk.subdomain_count));
    html.push_str(&format!("<div class=\"metric\"><span class=\"value\">{}</span><span class=\"label\">Assets</span></div>\n", risk.asset_count));
    html.push_str(&format!("<div class=\"metric\"><span class=\"value\">{}</span><span class=\"label\">Credentials</span></div>\n", risk.credential_count));
    html.push_str(&format!("<div class=\"metric\"><span class=\"value\">{}</span><span class=\"label\">Wireless</span></div>\n", risk.wireless_count));
    html.push_str("</div>\n</div>\n");

    html.push_str("<details open>\n<summary><h2>Subdomains</h2></summary>\n");
    if subdomains.is_empty() {
        html.push_str("<p>No subdomains found.</p>\n");
    } else {
        html.push_str("<table>\n<thead><tr><th>Subdomain</th><th>Source</th><th>IPs</th><th>Confidence</th></tr></thead>\n<tbody>\n");
        for sub in subdomains {
            html.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                sub.subdomain, sub.source, sub.ip_addresses.join(", "), sub.confidence));
        }
        html.push_str("</tbody>\n</table>\n");
    }
    html.push_str("</details>\n");

    html.push_str("<details open>\n<summary><h2>Assets</h2></summary>\n");
    if assets.is_empty() {
        html.push_str("<p>No assets found.</p>\n");
    } else {
        html.push_str("<table>\n<thead><tr><th>Host</th><th>IP</th><th>Ports</th><th>Services</th><th>Technologies</th></tr></thead>\n<tbody>\n");
        for asset in assets {
            let ports: Vec<String> = asset.ports.iter().map(|p| p.to_string()).collect();
            let services: Vec<String> = asset.services.iter()
                .map(|s| s.service_name.as_deref().unwrap_or("unknown").to_string())
                .collect();
            html.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                asset.host, asset.ip, ports.join(", "), services.join(", "), asset.technologies.join(", ")));
        }
        html.push_str("</tbody>\n</table>\n");
    }
    html.push_str("</details>\n");

    html.push_str("<details open>\n<summary><h2>Credentials & Breaches</h2></summary>\n");
    if credentials.is_empty() {
        html.push_str("<p>No credential leaks found.</p>\n");
    } else {
        html.push_str("<table>\n<thead><tr><th>Email</th><th>Breach Source</th><th>Data Types</th><th>Severity</th></tr></thead>\n<tbody>\n");
        for cred in credentials {
            html.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{}</td><td><span class=\"badge badge-{}\">{}</span></td></tr>\n",
                cred.email, cred.breach_source, cred.data_types.join(", "), severity_class(&cred.severity), cred.severity));
        }
        html.push_str("</tbody>\n</table>\n");
    }
    html.push_str("</details>\n");

    html.push_str("<details open>\n<summary><h2>Wireless Networks</h2></summary>\n");
    if wireless.is_empty() {
        html.push_str("<p>No wireless networks found.</p>\n");
    } else {
        html.push_str("<table>\n<thead><tr><th>SSID</th><th>BSSID</th><th>Encryption</th><th>Channel</th><th>Location</th></tr></thead>\n<tbody>\n");
        for w in wireless {
            let location = w.location.as_ref()
                .map(|l| format!("{:.4}, {:.4}", l.latitude, l.longitude))
                .unwrap_or_else(|| "N/A".to_string());
            html.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                w.ssid, w.bssid, w.encryption, w.channel.map(|c| c.to_string()).unwrap_or_default(), location));
        }
        html.push_str("</tbody>\n</table>\n");
    }
    html.push_str("</details>\n");

    html.push_str("<footer><p>Generated by <strong>reconx</strong> v0.1.0 | Passive OSINT Reconnaissance</p></footer>\n");
    html.push_str("</div>\n</body>\n</html>");

    html
}

fn severity_class(severity: &crate::models::finding::Severity) -> &'static str {
    match severity {
        crate::models::finding::Severity::Critical => "critical",
        crate::models::finding::Severity::High => "high",
        crate::models::finding::Severity::Medium => "medium",
        crate::models::finding::Severity::Low => "low",
        crate::models::finding::Severity::Info => "info",
    }
}

const STYLE: &str = r#"<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; }
.container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
h1 { color: #58a6ff; margin-bottom: 0.5rem; font-size: 2rem; }
h2 { color: #58a6ff; margin: 1rem 0; }
.meta { color: #8b949e; margin-bottom: 2rem; }
.summary { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1.5rem; margin-bottom: 2rem; }
.metrics { display: flex; gap: 2rem; flex-wrap: wrap; }
.metric { text-align: center; }
.metric .value { display: block; font-size: 2rem; font-weight: bold; color: #f0f6fc; }
.metric .label { color: #8b949e; font-size: 0.875rem; }
.badge { display: inline-block; padding: 0.25rem 0.75rem; border-radius: 12px; font-size: 0.75rem; font-weight: bold; }
.badge-critical { background: #da3633; color: #fff; }
.badge-high { background: #f85149; color: #fff; }
.badge-medium { background: #d29922; color: #fff; }
.badge-low { background: #3fb950; color: #fff; }
.badge-info { background: #58a6ff; color: #fff; }
details { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1rem; margin-bottom: 1rem; }
summary { cursor: pointer; }
table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid #21262d; }
th { background: #0d1117; color: #58a6ff; font-weight: 600; }
tr:hover { background: #1c2128; }
footer { text-align: center; color: #8b949e; margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #30363d; }
</style>
"#;
