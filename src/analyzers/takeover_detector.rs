use crate::models::{Finding, VulnFinding};
use crate::models::finding::Severity;

/// Known fingerprints for services vulnerable to subdomain takeover.
/// Each entry: (CNAME pattern, service name, severity).
const TAKEOVER_FINGERPRINTS: &[(&str, &str, Severity)] = &[
    // Cloud Hosting
    (".s3.amazonaws.com", "AWS S3 Bucket", Severity::Critical),
    (".s3-website", "AWS S3 Website", Severity::Critical),
    (".elasticbeanstalk.com", "AWS Elastic Beanstalk", Severity::High),
    (".cloudfront.net", "AWS CloudFront", Severity::High),
    
    // PaaS
    (".herokuapp.com", "Heroku", Severity::Critical),
    (".herokudns.com", "Heroku DNS", Severity::Critical),
    (".pantheonsite.io", "Pantheon", Severity::High),
    (".ghost.io", "Ghost", Severity::High),
    (".myshopify.com", "Shopify", Severity::High),
    (".surge.sh", "Surge.sh", Severity::High),
    (".fly.dev", "Fly.io", Severity::High),
    
    // Microsoft Azure
    (".azurewebsites.net", "Azure App Service", Severity::Critical),
    (".cloudapp.net", "Azure Cloud App", Severity::High),
    (".cloudapp.azure.com", "Azure Cloud App", Severity::High),
    (".azurefd.net", "Azure Front Door", Severity::High),
    (".blob.core.windows.net", "Azure Blob Storage", Severity::Critical),
    (".azure-api.net", "Azure API Management", Severity::High),
    (".azurecontainer.io", "Azure Container", Severity::High),
    (".database.windows.net", "Azure SQL", Severity::Critical),
    (".azureedge.net", "Azure CDN", Severity::High),
    (".trafficmanager.net", "Azure Traffic Manager", Severity::High),
    
    // Google Cloud
    (".appspot.com", "Google App Engine", Severity::High),
    (".firebaseapp.com", "Firebase Hosting", Severity::High),
    (".web.app", "Firebase Hosting", Severity::High),
    (".run.app", "Google Cloud Run", Severity::High),
    
    // Git Hosting
    (".github.io", "GitHub Pages", Severity::High),
    (".gitlab.io", "GitLab Pages", Severity::High),
    (".bitbucket.io", "Bitbucket", Severity::High),
    
    // CDN / Edge
    (".netlify.app", "Netlify", Severity::High),
    (".netlify.com", "Netlify", Severity::High),
    (".vercel.app", "Vercel", Severity::High),
    (".now.sh", "Vercel (legacy)", Severity::High),
    (".render.com", "Render", Severity::High),
    (".onrender.com", "Render", Severity::High),
    
    // Marketing / CMS
    (".wordpress.com", "WordPress.com", Severity::Medium),
    (".tumblr.com", "Tumblr", Severity::Medium),
    (".squarespace.com", "Squarespace", Severity::Medium),
    (".wixsite.com", "Wix", Severity::Medium),
    (".webflow.io", "Webflow", Severity::Medium),
    (".cargocollective.com", "Cargo", Severity::Medium),
    (".strikingly.com", "Strikingly", Severity::Medium),
    (".launchrock.com", "LaunchRock", Severity::Medium),
    (".hubspot.net", "HubSpot", Severity::Medium),
    (".hs-sites.com", "HubSpot Sites", Severity::Medium),
    
    // Support / SaaS
    (".zendesk.com", "Zendesk", Severity::High),
    (".freshdesk.com", "Freshdesk", Severity::High),
    (".helpjuice.com", "Helpjuice", Severity::Medium),
    (".helpscoutdocs.com", "Help Scout", Severity::Medium),
    (".statuspage.io", "Statuspage", Severity::Medium),
    (".tilda.ws", "Tilda", Severity::Medium),
    (".tictail.com", "Tictail", Severity::Medium),
    (".campaignmonitor.com", "Campaign Monitor", Severity::Medium),
    (".desk.com", "Desk.com", Severity::Medium),
    (".teamwork.com", "Teamwork", Severity::Medium),
    (".thinkific.com", "Thinkific", Severity::Medium),
    (".aftership.com", "AfterShip", Severity::Medium),
    (".readthedocs.io", "ReadTheDocs", Severity::Medium),
    (".readme.io", "ReadMe", Severity::Medium),
    (".smartjob.com", "SmartJob", Severity::Low),
    (".canny.io", "Canny", Severity::Medium),
    (".feedpress.me", "FeedPress", Severity::Medium),
    (".pingdom.com", "Pingdom", Severity::Medium),
    (".bigcartel.com", "Big Cartel", Severity::Medium),
    (".uservoice.com", "UserVoice", Severity::Medium),
];

pub struct TakeoverDetector;

#[derive(Debug, Clone)]
pub struct TakeoverResult {
    pub subdomain: String,
    pub cname: String,
    pub service: String,
    pub severity: Severity,
    pub reason: String,
}

impl TakeoverDetector {
    /// Analyze findings for potential subdomain takeover vulnerabilities.
    /// Checks CNAME records against known vulnerable service fingerprints.
    pub fn detect(findings: &[Finding]) -> Vec<TakeoverResult> {
        let mut results = Vec::new();

        for finding in findings {
            if let Finding::Subdomain(sub) = finding {
                // Check CNAME for takeover fingerprints
                if let Some(ref cname) = sub.cname {
                    let cname_lower = cname.to_lowercase();
                    for (pattern, service, severity) in TAKEOVER_FINGERPRINTS {
                        if cname_lower.contains(pattern) {
                            results.push(TakeoverResult {
                                subdomain: sub.subdomain.clone(),
                                cname: cname.clone(),
                                service: service.to_string(),
                                severity: *severity,
                                reason: format!(
                                    "CNAME '{}' points to {} — potential takeover if the resource is unclaimed",
                                    cname, service
                                ),
                            });
                            break;
                        }
                    }
                }

                // Check for dangling CNAMEs (no resolved IPs but has CNAME)
                if sub.cname.is_some() && sub.ip_addresses.is_empty() {
                    let cname = sub.cname.as_ref().unwrap();
                    // Only flag if not already matched by fingerprints above
                    if !results.iter().any(|r| r.subdomain == sub.subdomain) {
                        results.push(TakeoverResult {
                            subdomain: sub.subdomain.clone(),
                            cname: cname.clone(),
                            service: "Unknown".to_string(),
                            severity: Severity::Medium,
                            reason: format!(
                                "Dangling CNAME '{}' — resolves to no IP, possible abandoned resource",
                                cname
                            ),
                        });
                    }
                }
            }
        }

        // Sort by severity (Critical first)
        results.sort_by(|a, b| b.severity.cmp(&a.severity));
        results
    }

    /// Convert takeover results into VulnFinding entries
    pub fn to_findings(results: &[TakeoverResult]) -> Vec<Finding> {
        results
            .iter()
            .map(|r| {
                let mut vuln = VulnFinding::new(
                    r.subdomain.clone(),
                    "Subdomain Takeover".to_string(),
                    r.reason.clone(),
                    "takeover_detector".to_string(),
                );
                vuln.severity = r.severity;
                vuln.references = vec![
                    format!("CNAME: {}", r.cname),
                    format!("Service: {}", r.service),
                ];
                Finding::Vulnerability(vuln)
            })
            .collect()
    }
}
