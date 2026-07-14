use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::models::subdomain::DnsRecord;

pub struct DnsResolver {
    concurrency: usize,
    timeout_secs: u64,
}

impl DnsResolver {
    pub fn new(concurrency: usize, timeout_secs: u64) -> Self {
        Self {
            concurrency,
            timeout_secs,
        }
    }

    pub async fn resolve_subdomain(&self, subdomain: &str) -> Option<ResolvedSubdomain> {
        let subdomain = subdomain.to_string();
        let timeout_duration = Duration::from_secs(self.timeout_secs);

        let result = timeout(timeout_duration, async move {
            let mut resolved = ResolvedSubdomain {
                subdomain: subdomain.clone(),
                ips: Vec::new(),
                cnames: Vec::new(),
                mx_records: Vec::new(),
                txt_records: Vec::new(),
                dns_records: Vec::new(),
            };

            // Use tokio's blocking task for DNS resolution
            let subdomain_clone = subdomain.clone();
            let lookup_result = tokio::task::spawn_blocking(move || {
                let addr = format!("{}:0", subdomain_clone);
                addr.to_socket_addrs()
            })
            .await;

            if let Ok(Ok(addrs)) = lookup_result {
                for addr in addrs {
                    let ip_str = addr.ip().to_string();
                    if !resolved.ips.contains(&ip_str) {
                        resolved.ips.push(ip_str.clone());
                        resolved.dns_records.push(DnsRecord {
                            record_type: "A".to_string(),
                            value: ip_str,
                            ttl: None,
                        });
                    }
                }
            }

            if resolved.ips.is_empty() {
                None
            } else {
                Some(resolved)
            }
        })
        .await;

        result.ok().flatten()
    }

    pub async fn resolve_many(&self, subdomains: Vec<String>) -> Vec<ResolvedSubdomain> {
        let semaphore = Arc::new(Semaphore::new(self.concurrency));
        let mut handles = Vec::new();

        for subdomain in subdomains {
            let sem = semaphore.clone();
            let resolver = self.clone();
            
            let handle = tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                resolver.resolve_subdomain(&subdomain).await
            });
            
            handles.push(handle);
        }

        let mut results = Vec::new();
        for handle in handles {
            if let Ok(Some(resolved)) = handle.await {
                results.push(resolved);
            }
        }

        results
    }
}

impl Clone for DnsResolver {
    fn clone(&self) -> Self {
        Self {
            concurrency: self.concurrency,
            timeout_secs: self.timeout_secs,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedSubdomain {
    pub subdomain: String,
    pub ips: Vec<String>,
    pub cnames: Vec<String>,
    pub mx_records: Vec<String>,
    pub txt_records: Vec<String>,
    pub dns_records: Vec<DnsRecord>,
}
