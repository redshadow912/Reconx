pub mod crtsh;
pub mod hackertarget;
pub mod dnsdumpster;
pub mod anubis;
pub mod threathunter;
pub mod threatminer;
pub mod wayback;
pub mod commoncrawl;
pub mod duckduckgo;
pub mod bgpview;
pub mod virustotal;
pub mod shodan;
pub mod securitytrails;
pub mod alienvault;
pub mod urlscan;
pub mod fullhunt;
pub mod censys;
pub mod intelx;
pub mod hibp;
pub mod github_dorks;
pub mod pastebin;
pub mod wigle;
pub mod ipinfo;
pub mod certstream;
pub mod internetdb;
pub mod certspotter;
pub mod hunter;
pub mod subdomaincenter;
pub mod threatcrowd;
pub mod rapiddns;
pub mod leakix;
pub mod chaos;
pub mod netlas;
pub mod zoomeye;
pub mod fofa;
pub mod whois_rdap;

use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};

use crate::config::Config;
use crate::error::Result;
use crate::models::{Finding, Target};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectorCategory {
    CertificateTransparency,
    DnsSubdomain,
    SearchEngine,
    ThreatIntel,
    CodeDocLeaks,
    CredentialBreaches,
    WebArchives,
    HostService,
    Wireless,
    WhoisAsn,
    EmailHarvesting,
}

impl std::fmt::Display for CollectorCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CertificateTransparency => write!(f, "Certificate Transparency"),
            Self::DnsSubdomain => write!(f, "DNS/Subdomain"),
            Self::SearchEngine => write!(f, "Search Engine"),
            Self::ThreatIntel => write!(f, "Threat Intel"),
            Self::CodeDocLeaks => write!(f, "Code/Doc Leaks"),
            Self::CredentialBreaches => write!(f, "Credential Breaches"),
            Self::WebArchives => write!(f, "Web Archives"),
            Self::HostService => write!(f, "Host/Service"),
            Self::Wireless => write!(f, "Wireless"),
            Self::WhoisAsn => write!(f, "WHOIS/ASN"),
            Self::EmailHarvesting => write!(f, "Email Harvesting"),
        }
    }
}

#[async_trait]
pub trait Collector: Send + Sync {
    fn name(&self) -> &str;
    fn config_key(&self) -> &str { self.name() }
    fn category(&self) -> CollectorCategory;
    fn requires_api_key(&self) -> bool;
    async fn collect(&self, target: &Target, config: &Config) -> Result<Vec<Finding>>;
}

pub struct CollectorRegistry {
    collectors: Vec<Arc<dyn Collector>>,
}

impl CollectorRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            collectors: Vec::new(),
        };
        registry.register_defaults();
        registry
    }

    fn register_defaults(&mut self) {
        self.collectors.push(Arc::new(crtsh::CrtShCollector));
        self.collectors.push(Arc::new(hackertarget::HackerTargetCollector));
        self.collectors.push(Arc::new(dnsdumpster::DnsDumpsterCollector));
        self.collectors.push(Arc::new(anubis::AnubisCollector));
        self.collectors.push(Arc::new(threathunter::ThreatHunterCollector));
        self.collectors.push(Arc::new(threatminer::ThreatMinerCollector));
        self.collectors.push(Arc::new(wayback::WaybackCollector));
        self.collectors.push(Arc::new(commoncrawl::CommonCrawlCollector));
        self.collectors.push(Arc::new(duckduckgo::DuckDuckGoCollector));
        self.collectors.push(Arc::new(bgpview::BgpViewCollector));
        self.collectors.push(Arc::new(virustotal::VirusTotalCollector));
        self.collectors.push(Arc::new(shodan::ShodanCollector));
        self.collectors.push(Arc::new(securitytrails::SecurityTrailsCollector));
        self.collectors.push(Arc::new(alienvault::AlienVaultCollector));
        self.collectors.push(Arc::new(urlscan::UrlScanCollector));
        self.collectors.push(Arc::new(fullhunt::FullHuntCollector));
        self.collectors.push(Arc::new(censys::CensysCollector));
        self.collectors.push(Arc::new(intelx::IntelXCollector));
        self.collectors.push(Arc::new(hibp::HibpCollector));
        self.collectors.push(Arc::new(github_dorks::GithubDorksCollector));
        self.collectors.push(Arc::new(pastebin::PastebinCollector));
        self.collectors.push(Arc::new(wigle::WigleCollector));
        self.collectors.push(Arc::new(ipinfo::IpInfoCollector));
        self.collectors.push(Arc::new(certstream::CertStreamCollector));
        self.collectors.push(Arc::new(internetdb::InternetDbCollector));
        self.collectors.push(Arc::new(certspotter::CertSpotterCollector));
        self.collectors.push(Arc::new(hunter::HunterIoCollector));
        self.collectors.push(Arc::new(subdomaincenter::SubdomainCenterCollector));
        self.collectors.push(Arc::new(threatcrowd::ThreatCrowdCollector));
        self.collectors.push(Arc::new(rapiddns::RapidDnsCollector));
        self.collectors.push(Arc::new(leakix::LeakIxCollector));
        self.collectors.push(Arc::new(chaos::ChaosCollector));
        self.collectors.push(Arc::new(netlas::NetlasCollector));
        self.collectors.push(Arc::new(zoomeye::ZoomEyeCollector));
        self.collectors.push(Arc::new(fofa::FofaCollector));
        self.collectors.push(Arc::new(whois_rdap::WhoisRdapCollector));
    }

    pub fn get_collectors(
        &self,
        include: &Option<Vec<String>>,
        exclude: &Option<Vec<String>>,
    ) -> Vec<Arc<dyn Collector>> {
        self.collectors
            .iter()
            .filter(|c| {
                if let Some(ref inc) = include {
                    return inc.iter().any(|s| s == c.name());
                }
                true
            })
            .filter(|c| {
                if let Some(ref exc) = exclude {
                    return !exc.iter().any(|s| s == c.name());
                }
                true
            })
            .cloned()
            .collect()
    }

    pub fn all_collectors(&self) -> Vec<Arc<dyn Collector>> {
        self.collectors.clone()
    }
}

#[derive(Debug)]
pub struct CollectorResult {
    pub collector_name: String,
    pub findings: Vec<Finding>,
    pub error: Option<String>,
    pub duration_ms: u64,
}

pub async fn run_collectors(
    collectors: Vec<Arc<dyn Collector>>,
    target: &Target,
    config: &Config,
    concurrency: usize,
) -> Vec<CollectorResult> {
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let results = Arc::new(Mutex::new(Vec::new()));
    let target = Arc::new(target.clone());
    let config = Arc::new(config.clone());

    let mut handles = Vec::new();

    for collector in collectors {
        let sem = semaphore.clone();
        let results = results.clone();
        let target = target.clone();
        let config = config.clone();
        let name = collector.name().to_string();

        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let start = std::time::Instant::now();

            let result = collector.collect(&target, &config).await;
            let duration_ms = start.elapsed().as_millis() as u64;

            let collector_result = match result {
                Ok(findings) => CollectorResult {
                    collector_name: name,
                    findings,
                    error: None,
                    duration_ms,
                },
                Err(e) => CollectorResult {
                    collector_name: name,
                    findings: Vec::new(),
                    error: Some(e.to_string()),
                    duration_ms,
                },
            };

            results.lock().await.push(collector_result);
        });

        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }

    let results = Arc::try_unwrap(results).unwrap().into_inner();
    results
}
