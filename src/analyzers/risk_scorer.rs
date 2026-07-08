use crate::models::{Finding, finding::Severity};

#[derive(Debug, Clone)]
pub struct RiskScore {
    pub domain: String,
    pub overall_score: f64,
    pub subdomain_count: usize,
    pub asset_count: usize,
    pub credential_count: usize,
    pub wireless_count: usize,
    pub vulnerability_count: usize,
    pub risk_level: Severity,
}

pub struct RiskScorer;

impl RiskScorer {
    pub fn score(domain: &str, findings: &[Finding]) -> RiskScore {
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

        let mut score = 0.0;
        score += subdomain_count as f64 * 0.5;
        score += asset_count as f64 * 2.0;
        score += credential_count as f64 * 10.0;
        score += wireless_count as f64 * 3.0;
        score += vulnerability_count as f64 * 15.0;

        let score = (score / 100.0).min(10.0);

        let risk_level = if score >= 8.0 {
            Severity::Critical
        } else if score >= 6.0 {
            Severity::High
        } else if score >= 4.0 {
            Severity::Medium
        } else if score >= 2.0 {
            Severity::Low
        } else {
            Severity::Info
        };

        RiskScore {
            domain: domain.to_string(),
            overall_score: score,
            subdomain_count,
            asset_count,
            credential_count,
            wireless_count,
            vulnerability_count,
            risk_level,
        }
    }
}
