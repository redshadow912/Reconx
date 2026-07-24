use reconx::analyzers::takeover_detector::{TakeoverDetector, TakeoverResult};
use reconx::models::{Finding, SubdomainFinding};
use reconx::models::finding::Severity;

fn make_subdomain_with_cname(name: &str, cname: &str) -> Finding {
    let mut sub = SubdomainFinding::new(name.to_string(), "test".to_string());
    sub.cname = Some(cname.to_string());
    Finding::Subdomain(sub)
}

fn make_subdomain_with_cname_and_ips(name: &str, cname: &str, ips: Vec<String>) -> Finding {
    let mut sub = SubdomainFinding::new(name.to_string(), "test".to_string());
    sub.cname = Some(cname.to_string());
    sub.ip_addresses = ips;
    Finding::Subdomain(sub)
}

#[test]
fn test_detects_aws_s3_takeover() {
    let findings = vec![
        make_subdomain_with_cname("cdn.example.com", "mybucket.s3.amazonaws.com"),
    ];
    let results = TakeoverDetector::detect(&findings);
    assert_eq!(results.len(), 1);
    assert!(results[0].service.contains("S3"));
    assert!(matches!(results[0].severity, Severity::Critical));
}

#[test]
fn test_detects_heroku_takeover() {
    let findings = vec![
        make_subdomain_with_cname("app.example.com", "myapp.herokuapp.com"),
    ];
    let results = TakeoverDetector::detect(&findings);
    assert_eq!(results.len(), 1);
    assert!(results[0].service.contains("Heroku"));
}

#[test]
fn test_detects_github_pages_takeover() {
    let findings = vec![
        make_subdomain_with_cname("docs.example.com", "myorg.github.io"),
    ];
    let results = TakeoverDetector::detect(&findings);
    assert_eq!(results.len(), 1);
    assert!(results[0].service.contains("GitHub Pages"));
}

#[test]
fn test_detects_azure_takeover() {
    let findings = vec![
        make_subdomain_with_cname("portal.example.com", "myapp.azurewebsites.net"),
    ];
    let results = TakeoverDetector::detect(&findings);
    assert_eq!(results.len(), 1);
    assert!(results[0].service.contains("Azure"));
    assert!(matches!(results[0].severity, Severity::Critical));
}

#[test]
fn test_detects_dangling_cname() {
    let findings = vec![
        make_subdomain_with_cname("old.example.com", "removed-service.somedomain.com"),
    ];
    let results = TakeoverDetector::detect(&findings);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].service, "Unknown");
    assert!(matches!(results[0].severity, Severity::Medium));
}

#[test]
fn test_no_false_positive_with_resolved_ips() {
    let findings = vec![
        make_subdomain_with_cname_and_ips(
            "safe.example.com",
            "internal.somedomain.com",
            vec!["1.2.3.4".to_string()],
        ),
    ];
    let results = TakeoverDetector::detect(&findings);
    // Should not flag as dangling since it has IPs
    assert!(results.is_empty());
}

#[test]
fn test_no_detection_without_cname() {
    let findings = vec![
        Finding::Subdomain(SubdomainFinding::new("normal.example.com".to_string(), "test".to_string())),
    ];
    let results = TakeoverDetector::detect(&findings);
    assert!(results.is_empty());
}

#[test]
fn test_results_sorted_by_severity() {
    let findings = vec![
        make_subdomain_with_cname("medium.example.com", "removed.somedomain.com"),  // Medium (dangling)
        make_subdomain_with_cname("critical.example.com", "bucket.s3.amazonaws.com"), // Critical
    ];
    let results = TakeoverDetector::detect(&findings);
    assert_eq!(results.len(), 2);
    // Critical should be first
    assert!(matches!(results[0].severity, Severity::Critical));
}

#[test]
fn test_to_findings_converts_to_vulns() {
    let findings = vec![
        make_subdomain_with_cname("cdn.example.com", "mybucket.s3.amazonaws.com"),
    ];
    let takeover_results = TakeoverDetector::detect(&findings);
    let vuln_findings = TakeoverDetector::to_findings(&takeover_results);

    assert_eq!(vuln_findings.len(), 1);
    assert!(matches!(vuln_findings[0], Finding::Vulnerability(_)));
}
