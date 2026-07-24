use reconx::analyzers::correlator::Correlator;
use reconx::models::{Finding, SubdomainFinding, CredentialFinding};

fn make_subdomain(name: &str, source: &str) -> Finding {
    let mut sub = SubdomainFinding::new(name.to_string(), source.to_string());
    sub.confidence = 1;
    Finding::Subdomain(sub)
}

#[test]
fn test_dedup_removes_duplicate_subdomains() {
    let findings = vec![
        make_subdomain("a.example.com", "crtsh"),
        make_subdomain("a.example.com", "hackertarget"),
        make_subdomain("b.example.com", "crtsh"),
    ];

    let deduped = Correlator::dedup_findings(findings);
    let subs: Vec<&str> = deduped
        .iter()
        .filter_map(|f| if let Finding::Subdomain(s) = f { Some(s.subdomain.as_str()) } else { None })
        .collect();

    assert_eq!(subs.len(), 2);
    assert!(subs.contains(&"a.example.com"));
    assert!(subs.contains(&"b.example.com"));
}

#[test]
fn test_dedup_sets_confidence_from_source_count() {
    let findings = vec![
        make_subdomain("multi.example.com", "crtsh"),
        make_subdomain("multi.example.com", "hackertarget"),
        make_subdomain("multi.example.com", "virustotal"),
        make_subdomain("single.example.com", "crtsh"),
    ];

    let deduped = Correlator::dedup_findings(findings);

    let multi = deduped.iter().find_map(|f| {
        if let Finding::Subdomain(s) = f {
            if s.subdomain == "multi.example.com" { Some(s) } else { None }
        } else { None }
    }).unwrap();

    let single = deduped.iter().find_map(|f| {
        if let Finding::Subdomain(s) = f {
            if s.subdomain == "single.example.com" { Some(s) } else { None }
        } else { None }
    }).unwrap();

    assert_eq!(multi.confidence, 3);
    assert_eq!(single.confidence, 1);
}

#[test]
fn test_correlate_groups_sources() {
    let findings = vec![
        make_subdomain("test.example.com", "source_a"),
        make_subdomain("test.example.com", "source_b"),
    ];

    let correlated = Correlator::correlate(&findings);
    assert_eq!(correlated.len(), 1);
    assert_eq!(correlated[0].sources.len(), 2);
    assert_eq!(correlated[0].confidence, 2);
}

#[test]
fn test_dedup_preserves_different_finding_types() {
    let mut findings = vec![
        make_subdomain("a.example.com", "crtsh"),
    ];
    let cred = CredentialFinding::new(
        "user@example.com".to_string(),
        "breach1".to_string(),
        "github_dorks".to_string(),
    );
    findings.push(Finding::Credential(cred));

    let deduped = Correlator::dedup_findings(findings);
    assert_eq!(deduped.len(), 2);
}

#[test]
fn test_dedup_empty_input() {
    let deduped = Correlator::dedup_findings(Vec::new());
    assert!(deduped.is_empty());
}
