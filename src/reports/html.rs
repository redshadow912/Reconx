use std::path::Path;

use crate::analyzers::risk_scorer::RiskScore;
use crate::error::Result;
use crate::models::Finding;

pub fn generate(findings: &[Finding], domain: &str, risk: &RiskScore, output_path: &Path) -> Result<()> {
    let subdomains: Vec<&crate::models::SubdomainFinding> = findings
        .iter()
        .filter_map(|f| if let Finding::Subdomain(s) = f { Some(s) } else { None })
        .collect();

    let assets: Vec<&crate::models::AssetFinding> = findings
        .iter()
        .filter_map(|f| if let Finding::Asset(a) = f { Some(a) } else { None })
        .collect();

    let credentials: Vec<&crate::models::CredentialFinding> = findings
        .iter()
        .filter_map(|f| if let Finding::Credential(c) = f { Some(c) } else { None })
        .collect();

    let wireless: Vec<&crate::models::WirelessFinding> = findings
        .iter()
        .filter_map(|f| if let Finding::Wireless(w) = f { Some(w) } else { None })
        .collect();

    let vulnerabilities: Vec<&crate::models::VulnFinding> = findings
        .iter()
        .filter_map(|f| if let Finding::Vulnerability(v) = f { Some(v) } else { None })
        .collect();

    let emails: Vec<&crate::models::EmailFinding> = findings
        .iter()
        .filter_map(|f| if let Finding::Email(e) = f { Some(e) } else { None })
        .collect();

    let whois: Vec<&crate::models::WhoisFinding> = findings
        .iter()
        .filter_map(|f| if let Finding::Whois(w) = f { Some(w) } else { None })
        .collect();

    let html = build_html(domain, &risk, &subdomains, &assets, &credentials, &wireless, &vulnerabilities, &emails, &whois);

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
    vulnerabilities: &[&crate::models::VulnFinding],
    emails: &[&crate::models::EmailFinding],
    whois: &[&crate::models::WhoisFinding],
) -> String {
    let mut html = String::new();

    html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
    html.push_str("<meta charset=\"UTF-8\">\n");
    html.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
    html.push_str(&format!("<title>RECONX // {} — Intel Report</title>\n", domain));
    html.push_str(STYLE);
    html.push_str("</head>\n<body>\n");

    // Scanline overlay
    html.push_str("<div class=\"scanline\"></div>\n");

    // Header
    html.push_str("<header>\n");
    html.push_str("<div class=\"container\">\n");
    html.push_str("<div class=\"logo-block\">\n");
    html.push_str("<pre class=\"ascii-logo\">\n");
    html.push_str("  ____\n");
    html.push_str(" |  _ \\ ___  ___ ___  _ __ __  __\n");
    html.push_str(" | |_) / _ \\/ __/ _ \\| '_ \\\\ \\/ /\n");
    html.push_str(" |  _ &lt;  __/ (_| (_) | | | |&gt;  &lt;\n");
    html.push_str(" |_| \\_\\___|\\___\\___/|_| |_/_/\\_\\\n");
    html.push_str("</pre>\n");
    html.push_str("<p class=\"tagline\">PASSIVE OSINT RECONNAISSANCE</p>\n");
    html.push_str("</div>\n");
    html.push_str(&format!("<div class=\"target-info\">\n<span class=\"label\">TARGET</span>\n<span class=\"target-domain\">{}</span>\n<span class=\"timestamp\">{}</span>\n</div>\n",
        domain, chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")));
    html.push_str("</div>\n</header>\n");

    // Main container
    html.push_str("<main class=\"container\">\n");

    // Risk Score Hero
    let risk_class = severity_class(&risk.risk_level);
    html.push_str("<section class=\"risk-hero\">\n");
    html.push_str(&format!("<div class=\"risk-score risk-{}\">\n", risk_class));
    html.push_str(&format!("<span class=\"score-value\">{:.1}</span>\n", risk.overall_score));
    html.push_str("<span class=\"score-max\">/10</span>\n");
    html.push_str(&format!("<span class=\"risk-label\">{}</span>\n", risk.risk_level));
    html.push_str("</div>\n");

    // Stats grid
    html.push_str("<div class=\"stats-grid\">\n");
    let stats = vec![
        ("SUBDOMAINS", risk.subdomain_count, "◆"),
        ("ASSETS", risk.asset_count, "▣"),
        ("CREDENTIALS", risk.credential_count, "⚿"),
        ("EMAILS", risk.email_count, "✉"),
        ("VULNS", risk.vulnerability_count, "⚠"),
        ("TAKEOVERS", risk.takeover_count, "☠"),
        ("WIRELESS", risk.wireless_count, "◎"),
    ];
    for (label, count, icon) in stats {
        let glow = if count > 0 { "has-data" } else { "" };
        html.push_str(&format!(
            "<div class=\"stat-card {}\">\n<span class=\"stat-icon\">{}</span>\n<span class=\"stat-value\">{}</span>\n<span class=\"stat-label\">{}</span>\n</div>\n",
            glow, icon, count, label
        ));
    }
    html.push_str("</div>\n");
    html.push_str("</section>\n");

    // Top Risk Factors
    if !risk.top_factors.is_empty() {
        html.push_str("<section class=\"panel\">\n");
        html.push_str("<h2><span class=\"section-icon\">⚡</span> TOP RISK FACTORS</h2>\n");
        html.push_str("<div class=\"risk-factors\">\n");
        for factor in risk.top_factors.iter().take(8) {
            let sev = severity_class(&factor.severity);
            html.push_str(&format!(
                "<div class=\"risk-factor\">\n<span class=\"factor-severity sev-{}\">{}</span>\n<div class=\"factor-details\">\n<span class=\"factor-category\">{}</span>\n<span class=\"factor-desc\">{}</span>\n</div>\n</div>\n",
                sev, factor.severity, factor.category, factor.description
            ));
        }
        html.push_str("</div>\n</section>\n");
    }

    // WHOIS Intelligence
    if !whois.is_empty() {
        html.push_str("<section class=\"panel\">\n");
        html.push_str("<h2><span class=\"section-icon\">🔍</span> WHOIS INTELLIGENCE</h2>\n");
        for w in whois {
            html.push_str("<div class=\"whois-grid\">\n");
            let fields: Vec<(&str, String)> = vec![
                ("Domain", w.domain.clone()),
                ("Registrar", w.registrar.clone().unwrap_or_else(|| "—".to_string())),
                ("Created", w.creation_date.clone().unwrap_or_else(|| "—".to_string())),
                ("Expires", w.expiration_date.clone().unwrap_or_else(|| "—".to_string())),
                ("Days Until Expiry", w.days_until_expiry.map(|d| d.to_string()).unwrap_or_else(|| "—".to_string())),
                ("Domain Age", w.domain_age_days.map(|d| format!("{} days", d)).unwrap_or_else(|| "—".to_string())),
                ("Registrant", w.registrant_org.clone().unwrap_or_else(|| "—".to_string())),
                ("Nameservers", if w.nameservers.is_empty() { "—".to_string() } else { w.nameservers.join(", ") }),
                ("DNSSEC", w.dnssec.clone().unwrap_or_else(|| "—".to_string())),
                ("Privacy", if w.is_privacy_protected { "Protected".to_string() } else { "Not Protected".to_string() }),
            ];
            for (label, value) in fields {
                html.push_str(&format!(
                    "<div class=\"whois-field\"><span class=\"wf-label\">{}</span><span class=\"wf-value\">{}</span></div>\n",
                    label, value
                ));
            }
            html.push_str("</div>\n");
        }
        html.push_str("</section>\n");
    }

    // Subdomains
    html.push_str("<section class=\"panel\">\n");
    html.push_str(&format!("<h2><span class=\"section-icon\">◆</span> SUBDOMAINS <span class=\"count\">{}</span></h2>\n", subdomains.len()));
    if subdomains.is_empty() {
        html.push_str("<p class=\"empty\">No subdomains discovered.</p>\n");
    } else {
        html.push_str("<div class=\"table-wrap\">\n<table>\n<thead><tr><th>Subdomain</th><th>Source</th><th>IPs</th><th>Confidence</th></tr></thead>\n<tbody>\n");
        for sub in subdomains {
            // Clickable link to the subdomain
            let link = format!("https://{}", sub.subdomain);
            let conf_class = if sub.confidence >= 3 { "conf-high" } else if sub.confidence >= 2 { "conf-med" } else { "conf-low" };
            html.push_str(&format!(
                "<tr><td><a href=\"{}\" target=\"_blank\" rel=\"noopener\" class=\"sub-link\">{}</a></td><td><span class=\"source-badge\">{}</span></td><td class=\"mono\">{}</td><td><span class=\"conf {}\">{}</span></td></tr>\n",
                link, sub.subdomain, sub.source,
                if sub.ip_addresses.is_empty() { "—".to_string() } else { sub.ip_addresses.join(", ") },
                conf_class, sub.confidence
            ));
        }
        html.push_str("</tbody>\n</table>\n</div>\n");
    }
    html.push_str("</section>\n");

    // Assets
    if !assets.is_empty() {
        html.push_str("<section class=\"panel\">\n");
        html.push_str(&format!("<h2><span class=\"section-icon\">▣</span> ASSETS & SERVICES <span class=\"count\">{}</span></h2>\n", assets.len()));
        html.push_str("<div class=\"table-wrap\">\n<table>\n<thead><tr><th>Host</th><th>IP</th><th>Ports</th><th>Services</th><th>Technologies</th></tr></thead>\n<tbody>\n");
        for asset in assets {
            let ports: Vec<String> = asset.ports.iter().map(|p| p.to_string()).collect();
            let services: Vec<String> = asset.services.iter()
                .map(|s| s.service_name.as_deref().unwrap_or("unknown").to_string())
                .collect();
            let host_link = format!("https://{}", asset.host);
            html.push_str(&format!(
                "<tr><td><a href=\"{}\" target=\"_blank\" rel=\"noopener\" class=\"sub-link\">{}</a></td><td class=\"mono\">{}</td><td class=\"mono\">{}</td><td>{}</td><td>{}</td></tr>\n",
                host_link, asset.host, asset.ip,
                if ports.is_empty() { "—".to_string() } else { ports.join(", ") },
                if services.is_empty() { "—".to_string() } else { services.join(", ") },
                if asset.technologies.is_empty() { "—".to_string() } else { asset.technologies.join(", ") }
            ));
        }
        html.push_str("</tbody>\n</table>\n</div>\n</section>\n");
    }

    // Vulnerabilities
    if !vulnerabilities.is_empty() {
        html.push_str("<section class=\"panel\">\n");
        html.push_str(&format!("<h2><span class=\"section-icon\">⚠</span> VULNERABILITIES <span class=\"count\">{}</span></h2>\n", vulnerabilities.len()));
        html.push_str("<div class=\"table-wrap\">\n<table>\n<thead><tr><th>Host</th><th>Type</th><th>CVE</th><th>Severity</th><th>Description</th></tr></thead>\n<tbody>\n");
        for v in vulnerabilities {
            let sev = severity_class(&v.severity);
            let cve_cell = if let Some(ref cve) = v.cve_id {
                format!("<a href=\"https://nvd.nist.gov/vuln/detail/{}\" target=\"_blank\" rel=\"noopener\" class=\"cve-link\">{}</a>", cve, cve)
            } else {
                "—".to_string()
            };
            html.push_str(&format!(
                "<tr><td class=\"mono\">{}</td><td>{}</td><td>{}</td><td><span class=\"sev-badge sev-{}\">{}</span></td><td class=\"desc-cell\">{}</td></tr>\n",
                v.host, v.vulnerability_type, cve_cell, sev, v.severity, v.description
            ));
        }
        html.push_str("</tbody>\n</table>\n</div>\n</section>\n");
    }

    // Credentials
    if !credentials.is_empty() {
        html.push_str("<section class=\"panel\">\n");
        html.push_str(&format!("<h2><span class=\"section-icon\">⚿</span> CREDENTIAL LEAKS <span class=\"count\">{}</span></h2>\n", credentials.len()));
        html.push_str("<div class=\"table-wrap\">\n<table>\n<thead><tr><th>Target</th><th>Source</th><th>Data Types</th><th>Severity</th></tr></thead>\n<tbody>\n");
        for cred in credentials {
            let sev = severity_class(&cred.severity);
            // Make breach source clickable — detect GitHub repos
            let source_cell = if cred.breach_source.contains('/') && !cred.breach_source.contains(' ') {
                format!("<a href=\"https://github.com/{}\" target=\"_blank\" rel=\"noopener\" class=\"source-link\">{}</a>",
                    cred.breach_source, cred.breach_source)
            } else {
                cred.breach_source.clone()
            };
            html.push_str(&format!(
                "<tr><td class=\"mono\">{}</td><td>{}</td><td>{}</td><td><span class=\"sev-badge sev-{}\">{}</span></td></tr>\n",
                cred.email, source_cell, cred.data_types.join(", "), sev, cred.severity
            ));
        }
        html.push_str("</tbody>\n</table>\n</div>\n</section>\n");
    }

    // Emails
    if !emails.is_empty() {
        html.push_str("<section class=\"panel\">\n");
        html.push_str(&format!("<h2><span class=\"section-icon\">✉</span> EMAILS <span class=\"count\">{}</span></h2>\n", emails.len()));
        html.push_str("<div class=\"table-wrap\">\n<table>\n<thead><tr><th>Email</th><th>Name</th><th>Position</th><th>Source</th></tr></thead>\n<tbody>\n");
        for e in emails {
            html.push_str(&format!(
                "<tr><td class=\"mono\">{}</td><td>{}</td><td>{}</td><td><span class=\"source-badge\">{}</span></td></tr>\n",
                e.email, e.name.as_deref().unwrap_or("—"), e.position.as_deref().unwrap_or("—"), e.source
            ));
        }
        html.push_str("</tbody>\n</table>\n</div>\n</section>\n");
    }

    // Wireless
    if !wireless.is_empty() {
        html.push_str("<section class=\"panel\">\n");
        html.push_str(&format!("<h2><span class=\"section-icon\">◎</span> WIRELESS NETWORKS <span class=\"count\">{}</span></h2>\n", wireless.len()));
        html.push_str("<div class=\"table-wrap\">\n<table>\n<thead><tr><th>SSID</th><th>BSSID</th><th>Encryption</th><th>Channel</th><th>Location</th></tr></thead>\n<tbody>\n");
        for w in wireless {
            let location = w.location.as_ref()
                .map(|l| format!("{:.4}, {:.4}", l.latitude, l.longitude))
                .unwrap_or_else(|| "—".to_string());
            html.push_str(&format!(
                "<tr><td>{}</td><td class=\"mono\">{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                w.ssid, w.bssid, w.encryption,
                w.channel.map(|c| c.to_string()).unwrap_or_else(|| "—".to_string()),
                location
            ));
        }
        html.push_str("</tbody>\n</table>\n</div>\n</section>\n");
    }

    // Footer
    html.push_str("<footer>\n");
    html.push_str("<div class=\"footer-ascii\">[ RECONX v0.1.0 // PASSIVE OSINT ]</div>\n");
    html.push_str(&format!("<p>Report generated for <strong>{}</strong></p>\n", domain));
    html.push_str("<p class=\"footer-sub\">All data collected from passive, publicly-available sources.</p>\n");
    html.push_str("</footer>\n");

    html.push_str("</main>\n</body>\n</html>");

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

const STYLE: &str = r#"<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Geist+Pixel:ELSH@22&display=swap" rel="stylesheet">
<style>
:root {
  --bg: #050508;
  --surface: #0c0c12;
  --surface-2: #12121c;
  --border: #1a1a2e;
  --border-glow: #2a2a4a;
  --text: #c8c8e0;
  --text-dim: #6a6a8a;
  --accent: #00ff9d;
  --accent-dim: #00cc7d;
  --accent-glow: rgba(0,255,157,0.15);
  --red: #ff3355;
  --orange: #ff8833;
  --yellow: #ffcc00;
  --green: #00ff9d;
  --blue: #3388ff;
  --purple: #aa55ff;
}

* { margin: 0; padding: 0; box-sizing: border-box; }

body {
  font-family: 'Geist Pixel', monospace;
  background: var(--bg);
  color: var(--text);
  line-height: 1.7;
  min-height: 100vh;
  position: relative;
  overflow-x: hidden;
}

/* CRT scanline overlay */
.scanline {
  position: fixed;
  top: 0; left: 0; right: 0; bottom: 0;
  pointer-events: none;
  z-index: 9999;
  background: repeating-linear-gradient(
    0deg,
    transparent,
    transparent 2px,
    rgba(0,0,0,0.03) 2px,
    rgba(0,0,0,0.03) 4px
  );
}

.container {
  max-width: 1280px;
  margin: 0 auto;
  padding: 0 2rem;
}

/* HEADER */
header {
  border-bottom: 1px solid var(--border);
  padding: 2rem 0;
  background: linear-gradient(180deg, rgba(0,255,157,0.03) 0%, transparent 100%);
}

header .container {
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 2rem;
}

.ascii-logo {
  font-family: 'Geist Pixel', monospace;
  color: var(--accent);
  font-size: 0.7rem;
  line-height: 1.3;
  text-shadow: 0 0 20px var(--accent-glow), 0 0 40px rgba(0,255,157,0.05);
  letter-spacing: 0;
}

.tagline {
  font-size: 0.55rem;
  color: var(--text-dim);
  letter-spacing: 0.3em;
  margin-top: 0.5rem;
}

.target-info {
  text-align: right;
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.target-info .label {
  font-size: 0.5rem;
  color: var(--text-dim);
  letter-spacing: 0.3em;
}

.target-domain {
  font-size: 1.2rem;
  color: var(--accent);
  text-shadow: 0 0 15px var(--accent-glow);
}

.timestamp {
  font-size: 0.55rem;
  color: var(--text-dim);
}

/* MAIN */
main { padding: 2rem 0 4rem; }

/* RISK HERO */
.risk-hero {
  display: grid;
  grid-template-columns: auto 1fr;
  gap: 2rem;
  margin-bottom: 2rem;
  align-items: center;
}

.risk-score {
  width: 160px;
  height: 160px;
  border-radius: 50%;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  border: 2px solid var(--border);
  position: relative;
  background: var(--surface);
}

.risk-score::before {
  content: '';
  position: absolute;
  inset: -4px;
  border-radius: 50%;
  padding: 2px;
  background: conic-gradient(var(--accent) 0%, transparent 70%);
  -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
  -webkit-mask-composite: xor;
  mask-composite: exclude;
  opacity: 0.4;
}

.risk-critical::before { background: conic-gradient(var(--red) 0%, transparent 90%); }
.risk-high::before { background: conic-gradient(var(--orange) 0%, transparent 75%); }
.risk-medium::before { background: conic-gradient(var(--yellow) 0%, transparent 55%); }
.risk-low::before { background: conic-gradient(var(--green) 0%, transparent 35%); }
.risk-info::before { background: conic-gradient(var(--blue) 0%, transparent 15%); }

.score-value { font-size: 2.5rem; font-weight: 700; color: #fff; }
.score-max { font-size: 0.7rem; color: var(--text-dim); margin-top: -0.3rem; }
.risk-label { font-size: 0.5rem; letter-spacing: 0.2em; color: var(--text-dim); margin-top: 0.3rem; }

.risk-critical .score-value { color: var(--red); text-shadow: 0 0 20px rgba(255,51,85,0.4); }
.risk-high .score-value { color: var(--orange); text-shadow: 0 0 20px rgba(255,136,51,0.4); }
.risk-medium .score-value { color: var(--yellow); text-shadow: 0 0 20px rgba(255,204,0,0.3); }
.risk-low .score-value { color: var(--green); }
.risk-info .score-value { color: var(--blue); }

/* STATS GRID */
.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
  gap: 0.75rem;
}

.stat-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1rem;
  text-align: center;
  transition: all 0.3s ease;
}

.stat-card.has-data {
  border-color: var(--border-glow);
  box-shadow: 0 0 15px rgba(0,255,157,0.03);
}

.stat-card:hover {
  border-color: var(--accent);
  transform: translateY(-2px);
  box-shadow: 0 4px 20px rgba(0,255,157,0.08);
}

.stat-icon { font-size: 1.2rem; display: block; margin-bottom: 0.3rem; opacity: 0.6; }
.stat-value { font-size: 1.5rem; font-weight: 700; color: #fff; display: block; }
.stat-label { font-size: 0.45rem; color: var(--text-dim); letter-spacing: 0.15em; display: block; margin-top: 0.2rem; }

.has-data .stat-icon { opacity: 1; color: var(--accent); }
.has-data .stat-value { color: var(--accent); }

/* PANELS */
.panel {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 1.5rem;
  margin-bottom: 1.5rem;
  overflow: hidden;
}

.panel h2 {
  font-size: 0.65rem;
  letter-spacing: 0.15em;
  color: var(--accent);
  margin-bottom: 1rem;
  padding-bottom: 0.75rem;
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.section-icon { font-size: 0.8rem; }

.count {
  background: var(--accent-glow);
  color: var(--accent);
  padding: 0.15rem 0.5rem;
  border-radius: 10px;
  font-size: 0.5rem;
  margin-left: auto;
}

/* RISK FACTORS */
.risk-factors { display: flex; flex-direction: column; gap: 0.5rem; }

.risk-factor {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.6rem 0.8rem;
  background: var(--surface-2);
  border-radius: 6px;
  border-left: 3px solid var(--border);
  transition: border-color 0.2s;
}

.risk-factor:hover { border-left-color: var(--accent); }

.factor-severity {
  font-size: 0.45rem;
  font-weight: 700;
  letter-spacing: 0.1em;
  padding: 0.2rem 0.5rem;
  border-radius: 4px;
  min-width: 70px;
  text-align: center;
}

.sev-critical { background: rgba(255,51,85,0.15); color: var(--red); border: 1px solid rgba(255,51,85,0.3); }
.sev-high { background: rgba(255,136,51,0.15); color: var(--orange); border: 1px solid rgba(255,136,51,0.3); }
.sev-medium { background: rgba(255,204,0,0.12); color: var(--yellow); border: 1px solid rgba(255,204,0,0.25); }
.sev-low { background: rgba(0,255,157,0.1); color: var(--green); border: 1px solid rgba(0,255,157,0.2); }
.sev-info { background: rgba(51,136,255,0.1); color: var(--blue); border: 1px solid rgba(51,136,255,0.2); }

.factor-details { display: flex; flex-direction: column; gap: 0.15rem; }
.factor-category { font-size: 0.55rem; color: #fff; font-weight: 600; }
.factor-desc { font-size: 0.5rem; color: var(--text-dim); }

/* WHOIS */
.whois-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: 0.5rem;
}

.whois-field {
  background: var(--surface-2);
  border-radius: 6px;
  padding: 0.6rem 0.8rem;
  display: flex;
  flex-direction: column;
  gap: 0.15rem;
}

.wf-label { font-size: 0.4rem; color: var(--text-dim); letter-spacing: 0.15em; text-transform: uppercase; }
.wf-value { font-size: 0.55rem; color: #fff; }

/* TABLES */
.table-wrap { overflow-x: auto; }

table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.55rem;
}

thead th {
  background: var(--surface-2);
  color: var(--accent);
  font-size: 0.45rem;
  letter-spacing: 0.1em;
  font-weight: 600;
  padding: 0.6rem 0.75rem;
  text-align: left;
  border-bottom: 1px solid var(--border-glow);
  position: sticky;
  top: 0;
  z-index: 1;
}

td {
  padding: 0.5rem 0.75rem;
  border-bottom: 1px solid var(--border);
  vertical-align: middle;
}

tr:hover td { background: rgba(0,255,157,0.02); }

.mono { font-family: 'Geist Pixel', monospace; font-size: 0.5rem; }

/* LINKS */
a { color: var(--accent); text-decoration: none; transition: all 0.2s; }
a:hover { color: #fff; text-shadow: 0 0 8px var(--accent-glow); }

.sub-link {
  color: var(--text);
  border-bottom: 1px solid transparent;
  transition: all 0.2s;
}
.sub-link:hover {
  color: var(--accent);
  border-bottom-color: var(--accent);
}

.source-link {
  color: var(--purple);
  font-size: 0.5rem;
}
.source-link:hover { color: #cc88ff; }

.cve-link { color: var(--red); font-weight: 600; }
.cve-link:hover { text-shadow: 0 0 10px rgba(255,51,85,0.4); }

.source-badge {
  display: inline-block;
  background: var(--surface-2);
  border: 1px solid var(--border);
  padding: 0.1rem 0.4rem;
  border-radius: 4px;
  font-size: 0.45rem;
  color: var(--text-dim);
}

/* CONFIDENCE */
.conf {
  display: inline-block;
  min-width: 22px;
  text-align: center;
  padding: 0.1rem 0.3rem;
  border-radius: 4px;
  font-size: 0.5rem;
  font-weight: 700;
}

.conf-high { background: rgba(0,255,157,0.15); color: var(--green); }
.conf-med { background: rgba(255,204,0,0.12); color: var(--yellow); }
.conf-low { background: rgba(51,136,255,0.1); color: var(--blue); }

/* SEVERITY BADGES */
.sev-badge {
  display: inline-block;
  padding: 0.15rem 0.5rem;
  border-radius: 4px;
  font-size: 0.45rem;
  font-weight: 700;
  letter-spacing: 0.05em;
}

.desc-cell { max-width: 300px; font-size: 0.45rem; color: var(--text-dim); }

.empty { color: var(--text-dim); font-size: 0.55rem; font-style: italic; }

/* FOOTER */
footer {
  text-align: center;
  padding: 2rem 0;
  border-top: 1px solid var(--border);
  margin-top: 2rem;
}

.footer-ascii {
  font-size: 0.55rem;
  color: var(--accent);
  letter-spacing: 0.2em;
  margin-bottom: 0.5rem;
  text-shadow: 0 0 15px var(--accent-glow);
}

footer p { font-size: 0.5rem; color: var(--text-dim); }
.footer-sub { font-size: 0.4rem !important; margin-top: 0.25rem; }

/* ANIMATIONS */
@keyframes fadeIn {
  from { opacity: 0; transform: translateY(10px); }
  to { opacity: 1; transform: translateY(0); }
}

.panel, .risk-hero, header {
  animation: fadeIn 0.4s ease-out forwards;
}

.panel:nth-child(2) { animation-delay: 0.05s; }
.panel:nth-child(3) { animation-delay: 0.1s; }
.panel:nth-child(4) { animation-delay: 0.15s; }

/* RESPONSIVE */
@media (max-width: 768px) {
  .risk-hero { grid-template-columns: 1fr; justify-items: center; }
  header .container { flex-direction: column; text-align: center; }
  .target-info { text-align: center; }
  .stats-grid { grid-template-columns: repeat(3, 1fr); }
  .whois-grid { grid-template-columns: 1fr; }
}
</style>
"#;
