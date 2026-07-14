use crate::models::{Finding, finding::Severity};
use crate::analyzers::takeover_detector::TakeoverResult;

#[derive(Debug, Clone)]
pub struct RiskFactor {
    pub category: String,
    pub description: String,
    pub score_contribution: f64,
    pub severity: Severity,
}

#[derive(Debug, Clone)]
pub struct RiskScore {
    pub domain: String,
    pub overall_score: f64,
    pub subdomain_count: usize,
    pub asset_count: usize,
    pub credential_count: usize,
    pub wireless_count: usize,
    pub vulnerability_count: usize,
    pub email_count: usize,
    pub takeover_count: usize,
    pub risk_level: Severity,
    pub top_factors: Vec<RiskFactor>,
}

/// High-risk ports commonly targeted in pentests
const HIGH_RISK_PORTS: &[u16] = &[
    21,    // FTP
    22,    // SSH
    23,    // Telnet
    25,    // SMTP
    110,   // POP3
    135,   // MSRPC
    139,   // NetBIOS
    445,   // SMB
    1433,  // MSSQL
    1521,  // Oracle
    3306,  // MySQL
    3389,  // RDP
    5432,  // PostgreSQL
    5900,  // VNC
    6379,  // Redis
    8080,  // HTTP-Alt
    8443,  // HTTPS-Alt
    9200,  // Elasticsearch
    27017, // MongoDB
    11211, // Memcached
];

pub struct RiskScorer;

impl RiskScorer {
    pub fn score(domain: &str, findings: &[Finding], takeovers: &[TakeoverResult]) -> RiskScore {
        let mut factors = Vec::new();
        let mut total_score = 0.0;

        let subdomain_count = findings
            .iter()
            .filter(|f| matches!(f, Finding::Subdomain(_)))
            .count();

        let asset_count = findings
            .iter()
            .filter(|f| matches!(f, Finding::Asset(_)))
            .count();

        let credential_count = findings
            .iter()
            .filter(|f| matches!(f, Finding::Credential(_)))
            .count();

        let wireless_count = findings
            .iter()
            .filter(|f| matches!(f, Finding::Wireless(_)))
            .count();

        let vulnerability_count = findings
            .iter()
            .filter(|f| matches!(f, Finding::Vulnerability(_)))
            .count();

        let email_count = findings
            .iter()
            .filter(|f| matches!(f, Finding::Email(_)))
            .count();

        let takeover_count = takeovers.len();

        // --- Subdomain exposure ---
        if subdomain_count > 0 {
            let sub_score = (subdomain_count as f64 * 0.3).min(15.0);
            total_score += sub_score;
            if subdomain_count > 50 {
                factors.push(RiskFactor {
                    category: "Subdomain Exposure".to_string(),
                    description: format!("{} subdomains — large attack surface", subdomain_count),
                    score_contribution: sub_score,
                    severity: Severity::Medium,
                });
            }
        }

        // --- Subdomain Takeover (Critical) ---
        if takeover_count > 0 {
            let takeover_score = takeover_count as f64 * 25.0;
            total_score += takeover_score;
            let critical_count = takeovers.iter().filter(|t| t.severity == Severity::Critical).count();
            factors.push(RiskFactor {
                category: "Subdomain Takeover".to_string(),
                description: format!(
                    "{} takeover candidates ({} critical) — immediate action required",
                    takeover_count, critical_count
                ),
                score_contribution: takeover_score,
                severity: if critical_count > 0 { Severity::Critical } else { Severity::High },
            });
        }

        // --- Exposed Assets with high-risk ports ---
        let mut high_risk_port_count = 0;
        let mut db_ports = Vec::new();
        for finding in findings {
            if let Finding::Asset(a) = finding {
                for port in &a.ports {
                    if HIGH_RISK_PORTS.contains(port) {
                        high_risk_port_count += 1;
                        match port {
                            3306 | 5432 | 27017 | 1433 | 1521 | 6379 | 9200 | 11211 => {
                                db_ports.push(format!("{}:{}", a.host, port));
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        if asset_count > 0 {
            let asset_score = asset_count as f64 * 2.0;
            total_score += asset_score;
        }

        if high_risk_port_count > 0 {
            let port_score = high_risk_port_count as f64 * 8.0;
            total_score += port_score;
            factors.push(RiskFactor {
                category: "High-Risk Ports".to_string(),
                description: format!(
                    "{} high-risk ports exposed (databases: {})",
                    high_risk_port_count,
                    if db_ports.is_empty() { "none".to_string() } else { db_ports.join(", ") }
                ),
                score_contribution: port_score,
                severity: if !db_ports.is_empty() { Severity::Critical } else { Severity::High },
            });
        }

        // --- Credential Leaks ---
        if credential_count > 0 {
            let cred_score = credential_count as f64 * 12.0;
            total_score += cred_score;
            let password_leaks = findings.iter().filter(|f| {
                if let Finding::Credential(c) = f {
                    c.data_types.iter().any(|d| {
                        let dl = d.to_lowercase();
                        dl.contains("password") || dl.contains("hash") || dl.contains("plaintext")
                    })
                } else { false }
            }).count();

            factors.push(RiskFactor {
                category: "Credential Leaks".to_string(),
                description: format!(
                    "{} credential leaks ({} with passwords/hashes)",
                    credential_count, password_leaks
                ),
                score_contribution: cred_score,
                severity: if password_leaks > 0 { Severity::Critical } else { Severity::High },
            });
        }

        // --- Vulnerabilities ---
        if vulnerability_count > 0 {
            let critical_vulns = findings.iter().filter(|f| {
                matches!(f, Finding::Vulnerability(v) if v.severity == Severity::Critical)
            }).count();
            let vuln_score = vulnerability_count as f64 * 15.0 + critical_vulns as f64 * 10.0;
            total_score += vuln_score;
            factors.push(RiskFactor {
                category: "Vulnerabilities".to_string(),
                description: format!(
                    "{} vulnerabilities ({} critical)",
                    vulnerability_count, critical_vulns
                ),
                score_contribution: vuln_score,
                severity: if critical_vulns > 0 { Severity::Critical } else { Severity::High },
            });
        }

        // --- Email Harvesting ---
        if email_count > 0 {
            let email_score = email_count as f64 * 1.5;
            total_score += email_score;
            if email_count > 10 {
                factors.push(RiskFactor {
                    category: "Email Exposure".to_string(),
                    description: format!("{} employee emails discoverable — phishing risk", email_count),
                    score_contribution: email_score,
                    severity: Severity::Medium,
                });
            }
        }

        // --- Wireless Networks ---
        if wireless_count > 0 {
            let wireless_score = wireless_count as f64 * 3.0;
            total_score += wireless_score;
            factors.push(RiskFactor {
                category: "Wireless Exposure".to_string(),
                description: format!("{} wireless networks publicly cataloged", wireless_count),
                score_contribution: wireless_score,
                severity: Severity::Low,
            });
        }

        // --- SSL Issues ---
        let ssl_issues: Vec<&str> = findings.iter().filter_map(|f| {
            if let Finding::Ssl(s) = f {
                if s.is_expired { return Some("expired cert"); }
                if s.is_self_signed { return Some("self-signed cert"); }
                if let Some(days) = s.days_until_expiry {
                    if days < 30 { return Some("cert expiring soon"); }
                }
            }
            None
        }).collect();

        if !ssl_issues.is_empty() {
            let ssl_score = ssl_issues.len() as f64 * 5.0;
            total_score += ssl_score;
            factors.push(RiskFactor {
                category: "SSL/TLS Issues".to_string(),
                description: format!("{} SSL issues: {}", ssl_issues.len(), ssl_issues.join(", ")),
                score_contribution: ssl_score,
                severity: Severity::High,
            });
        }

        // --- WHOIS warnings ---
        for finding in findings {
            if let Finding::Whois(w) = finding {
                if let Some(days) = w.days_until_expiry {
                    if days < 30 {
                        let whois_score = 8.0;
                        total_score += whois_score;
                        factors.push(RiskFactor {
                            category: "Domain Expiry".to_string(),
                            description: format!("Domain expires in {} days — lapse-takeover risk", days),
                            score_contribution: whois_score,
                            severity: Severity::High,
                        });
                    }
                }
                if let Some(age) = w.domain_age_days {
                    if age < 90 {
                        let whois_score = 5.0;
                        total_score += whois_score;
                        factors.push(RiskFactor {
                            category: "New Domain".to_string(),
                            description: format!("Domain is only {} days old — potentially suspicious", age),
                            score_contribution: whois_score,
                            severity: Severity::Medium,
                        });
                    }
                }
            }
        }

        // Normalize score to 0-10 scale
        let overall_score = (total_score / 100.0).min(10.0);

        let risk_level = if overall_score >= 8.0 {
            Severity::Critical
        } else if overall_score >= 6.0 {
            Severity::High
        } else if overall_score >= 4.0 {
            Severity::Medium
        } else if overall_score >= 2.0 {
            Severity::Low
        } else {
            Severity::Info
        };

        // Sort factors by contribution (highest first)
        factors.sort_by(|a, b| b.score_contribution.partial_cmp(&a.score_contribution).unwrap_or(std::cmp::Ordering::Equal));

        RiskScore {
            domain: domain.to_string(),
            overall_score,
            subdomain_count,
            asset_count,
            credential_count,
            wireless_count,
            vulnerability_count,
            email_count,
            takeover_count,
            risk_level,
            top_factors: factors,
        }
    }
}
