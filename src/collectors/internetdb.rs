use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;

use crate::collectors::{Collector, CollectorCategory};
use crate::config::Config;
use crate::error::Result;
use crate::models::{AssetFinding, Finding, ServiceInfo, SubdomainFinding, Target, VulnFinding};
use crate::models::finding::Severity;

pub struct InternetDbCollector;

#[derive(Debug, Deserialize)]
struct InternetDbResponse {
    #[serde(default)]
    ip: String,
    #[serde(default)]
    ports: Vec<u16>,
    #[serde(default)]
    cpes: Vec<String>,
    #[serde(default)]
    hostnames: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    vulns: Vec<String>,
}

#[async_trait]
impl Collector for InternetDbCollector {
    fn name(&self) -> &str {
        "internetdb"
    }

    fn category(&self) -> CollectorCategory {
        CollectorCategory::HostService
    }

    fn requires_api_key(&self) -> bool {
        false
    }

    async fn collect(&self, target: &Target, _config: &Config) -> Result<Vec<Finding>> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        // First, resolve the domain to get IPs
        let ips = resolve_domain_to_ips(&target.domain).await?;
        
        let mut findings = Vec::new();

        for ip in ips {
            let url = format!("https://internetdb.shodan.io/{}", ip);
            
            let resp = match client.get(&url).send().await {
                Ok(r) => r,
                Err(_) => continue,
            };

            if !resp.status().is_success() {
                continue;
            }

            let data: InternetDbResponse = match resp.json().await {
                Ok(d) => d,
                Err(_) => continue,
            };

            // Create AssetFinding with ports and services
            if !data.ports.is_empty() {
                let mut asset = AssetFinding::new(
                    target.domain.clone(),
                    data.ip.clone(),
                    "internetdb".to_string(),
                );
                
                asset.ports = data.ports.clone();
                
                // Create service info for each port
                for port in &data.ports {
                    asset.services.push(ServiceInfo {
                        port: *port,
                        protocol: "tcp".to_string(),
                        service_name: None,
                        version: None,
                        banner: None,
                    });
                }

                // Add CPEs as technologies
                asset.technologies = data.cpes.clone();
                asset.discovered_at = Utc::now();
                
                findings.push(Finding::Asset(asset));
            }

            // Create SubdomainFinding for each hostname
            for hostname in &data.hostnames {
                let hostname_lower = hostname.to_lowercase();
                if hostname_lower.ends_with(&target.domain) {
                    let mut sub = SubdomainFinding::new(hostname_lower, "internetdb".to_string());
                    sub.ip_addresses.push(data.ip.clone());
                    sub.discovered_at = Utc::now();
                    findings.push(Finding::Subdomain(sub));
                }
            }

            // Create VulnFinding for each CVE
            for cve in &data.vulns {
                let mut vuln = VulnFinding::new(
                    data.ip.clone(),
                    "CVE".to_string(),
                    format!("Vulnerability detected: {}", cve),
                    "internetdb".to_string(),
                );
                vuln.cve_id = Some(cve.clone());
                vuln.severity = Severity::High;
                vuln.discovered_at = Utc::now();
                findings.push(Finding::Vulnerability(vuln));
            }
        }

        Ok(findings)
    }
}

async fn resolve_domain_to_ips(domain: &str) -> Result<Vec<String>> {
    use std::net::ToSocketAddrs;
    
    let addr = format!("{}:0", domain);
    match addr.to_socket_addrs() {
        Ok(addrs) => {
            let ips: Vec<String> = addrs
                .map(|a| a.ip().to_string())
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect();
            Ok(ips)
        }
        Err(_) => Ok(vec![]),
    }
}
