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

    Ok(())
}
