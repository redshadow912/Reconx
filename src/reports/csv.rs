use std::path::Path;

use crate::error::Result;
use crate::models::Finding;

pub fn generate(findings: &[Finding], output_path: &Path) -> Result<()> {
    let subdomains_path = output_path.join("subdomains.csv");
    let mut wtr = csv::Writer::from_path(&subdomains_path)?;
    wtr.write_record(&["subdomain", "source", "ip_addresses", "confidence", "discovered_at"])?;

    for finding in findings {
        if let Finding::Subdomain(sub) = finding {
            wtr.write_record(&[
                &sub.subdomain,
                &sub.source,
                &sub.ip_addresses.join(", "),
                &sub.confidence.to_string(),
                &sub.discovered_at.to_rfc3339(),
            ])?;
        }
    }
    wtr.flush()?;

    let assets_path = output_path.join("assets.csv");
    let mut wtr = csv::Writer::from_path(&assets_path)?;
    wtr.write_record(&["host", "ip", "ports", "services", "technologies", "source", "discovered_at"])?;

    for finding in findings {
        if let Finding::Asset(asset) = finding {
            let ports: Vec<String> = asset.ports.iter().map(|p| p.to_string()).collect();
            let services: Vec<String> = asset
                .services
                .iter()
                .map(|s| {
                    s.service_name
                        .as_deref()
                        .unwrap_or("unknown")
                        .to_string()
                })
                .collect();

            wtr.write_record(&[
                &asset.host,
                &asset.ip,
                &ports.join(", "),
                &services.join(", "),
                &asset.technologies.join(", "),
                &asset.source,
                &asset.discovered_at.to_rfc3339(),
            ])?;
        }
    }
    wtr.flush()?;

    let creds_path = output_path.join("credentials.csv");
    let mut wtr = csv::Writer::from_path(&creds_path)?;
    wtr.write_record(&["email", "breach_source", "data_types", "severity", "source", "discovered_at"])?;

    for finding in findings {
        if let Finding::Credential(cred) = finding {
            wtr.write_record(&[
                &cred.email,
                &cred.breach_source,
                &cred.data_types.join(", "),
                &cred.severity.to_string(),
                &cred.source,
                &cred.discovered_at.to_rfc3339(),
            ])?;
        }
    }
    wtr.flush()?;

    let wireless_path = output_path.join("wireless.csv");
    let mut wtr = csv::Writer::from_path(&wireless_path)?;
    wtr.write_record(&["ssid", "bssid", "encryption", "channel", "source", "discovered_at"])?;

    for finding in findings {
        if let Finding::Wireless(w) = finding {
            wtr.write_record(&[
                &w.ssid,
                &w.bssid,
                &w.encryption,
                &w.channel.map(|c| c.to_string()).unwrap_or_default(),
                &w.source,
                &w.discovered_at.to_rfc3339(),
            ])?;
        }
    }
    wtr.flush()?;

    let emails_path = output_path.join("emails.csv");
    let mut wtr = csv::Writer::from_path(&emails_path)?;
    wtr.write_record(&["email", "name", "position", "confidence", "source", "discovered_at"])?;

    for finding in findings {
        if let Finding::Email(e) = finding {
            wtr.write_record(&[
                &e.email,
                &e.name.clone().unwrap_or_default(),
                &e.position.clone().unwrap_or_default(),
                &e.confidence.map(|c| c.to_string()).unwrap_or_default(),
                &e.source,
                &e.discovered_at.to_rfc3339(),
            ])?;
        }
    }
    wtr.flush()?;

    let probes_path = output_path.join("probes.csv");
    let mut wtr = csv::Writer::from_path(&probes_path)?;
    wtr.write_record(&["url", "status_code", "title", "server", "technologies", "cdn", "waf", "discovered_at"])?;

    for finding in findings {
        if let Finding::HttpProbe(p) = finding {
            wtr.write_record(&[
                &p.url,
                &p.status_code.to_string(),
                &p.title.clone().unwrap_or_default(),
                &p.server.clone().unwrap_or_default(),
                &p.technologies.join(", "),
                &p.cdn.clone().unwrap_or_default(),
                &p.waf.clone().unwrap_or_default(),
                &p.discovered_at.to_rfc3339(),
            ])?;
        }
    }
    wtr.flush()?;

    // WHOIS CSV
    let whois_path = output_path.join("whois.csv");
    let mut wtr = csv::Writer::from_path(&whois_path)?;
    wtr.write_record(&["domain", "registrar", "created", "expires", "days_until_expiry", "domain_age_days", "registrant_org", "nameservers", "privacy_protected", "discovered_at"])?;

    for finding in findings {
        if let Finding::Whois(w) = finding {
            wtr.write_record(&[
                &w.domain,
                &w.registrar.clone().unwrap_or_default(),
                &w.creation_date.clone().unwrap_or_default(),
                &w.expiration_date.clone().unwrap_or_default(),
                &w.days_until_expiry.map(|d| d.to_string()).unwrap_or_default(),
                &w.domain_age_days.map(|d| d.to_string()).unwrap_or_default(),
                &w.registrant_org.clone().unwrap_or_default(),
                &w.nameservers.join(", "),
                &if w.is_privacy_protected { "Yes" } else { "No" }.to_string(),
                &w.discovered_at.to_rfc3339(),
            ])?;
        }
    }
    wtr.flush()?;

    // SSL CSV
    let ssl_path = output_path.join("ssl.csv");
    let mut wtr = csv::Writer::from_path(&ssl_path)?;
    wtr.write_record(&["host", "subject", "issuer", "not_after", "days_until_expiry", "is_expired", "is_self_signed", "sans", "discovered_at"])?;

    for finding in findings {
        if let Finding::Ssl(s) = finding {
            wtr.write_record(&[
                &s.host,
                &s.subject.clone().unwrap_or_default(),
                &s.issuer.clone().unwrap_or_default(),
                &s.not_after.clone().unwrap_or_default(),
                &s.days_until_expiry.map(|d| d.to_string()).unwrap_or_default(),
                &s.is_expired.to_string(),
                &s.is_self_signed.to_string(),
                &s.sans.join(", "),
                &s.discovered_at.to_rfc3339(),
            ])?;
        }
    }
    wtr.flush()?;

    Ok(())
}
