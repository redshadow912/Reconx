use reconx::analyzers::risk_scorer::RiskScorer;
use reconx::models::{Finding, SubdomainFinding, CredentialFinding, AssetFinding};
use reconx::models::finding::Severity;

fn make_subdomain(name: &str) -> Finding {
    Finding::Subdomain(SubdomainFinding::new(name.to_string(), "test".to_string()))
}

fn make_credential(email: &str, source: &str) -> Finding {
    Finding::Credential(CredentialFinding::new(
        email.to_string(),
        source.to_string(),
        "test".to_string(),
    ))
}

#[test]
fn test_risk_score_empty_findings() {
    let score = RiskScorer::score("example.com", &[], &[]);
    assert_eq!(score.overall_score, 0.0);
    assert_eq!(score.subdomain_count, 0);
    assert_eq!(score.credential_count, 0);
    assert!(matches!(score.risk_level, Severity::Info));
}

#[test]
fn test_risk_score_subdomain_exposure() {
    let findings: Vec<Finding> = (0..100)
        .map(|i| make_subdomain(&format!("sub{}.example.com", i)))
        .collect();

    let score = RiskScorer::score("example.com", &findings, &[]);
    assert_eq!(score.subdomain_count, 100);
    assert!(score.overall_score > 0.0);
    // 100 subdomains should generate a risk factor
    assert!(score.top_factors.iter().any(|f| f.category == "Subdomain Exposure"));
}

#[test]
fn test_risk_score_credentials_increase_score() {
    let findings = vec![
        make_credential("user@example.com", "breach1"),
        make_credential("admin@example.com", "breach2"),
    ];

    let score = RiskScorer::score("example.com", &findings, &[]);
    assert_eq!(score.credential_count, 2);
    assert!(score.overall_score > 0.0);
    assert!(score.top_factors.iter().any(|f| f.category == "Credential Leaks"));
}

#[test]
fn test_risk_score_domain_name_preserved() {
    let score = RiskScorer::score("test.com", &[], &[]);
    assert_eq!(score.domain, "test.com");
}

#[test]
fn test_risk_score_capped_at_10() {
    // Create a huge number of credentials to try to exceed the cap
    let findings: Vec<Finding> = (0..1000)
        .map(|i| make_credential(&format!("user{}@example.com", i), &format!("breach{}", i)))
        .collect();

    let score = RiskScorer::score("example.com", &findings, &[]);
    assert!(score.overall_score <= 10.0, "Score should be capped at 10.0, got {}", score.overall_score);
}

#[test]
fn test_risk_level_thresholds() {
    // Info: 0-2
    let score = RiskScorer::score("example.com", &[], &[]);
    assert!(matches!(score.risk_level, Severity::Info));
}
