use rand::Rng;
use std::collections::HashSet;

use super::resolver::DnsResolver;

pub struct WildcardDetector {
    resolver: DnsResolver,
}

impl WildcardDetector {
    pub fn new(resolver: DnsResolver) -> Self {
        Self { resolver }
    }

    pub async fn detect_wildcard(&self, domain: &str) -> Option<WildcardInfo> {
        let mut rng = rand::thread_rng();
        let mut wildcard_ips: HashSet<String> = HashSet::new();

        // Generate 3 random subdomains to test for wildcards
        for _ in 0..3 {
            let random_prefix: String = (0..12)
                .map(|_| {
                    let idx = rng.gen_range(0..36);
                    if idx < 10 {
                        (b'0' + idx) as char
                    } else {
                        (b'a' + idx - 10) as char
                    }
                })
                .collect();

            let random_subdomain = format!("{}.{}", random_prefix, domain);
            
            if let Some(resolved) = self.resolver.resolve_subdomain(&random_subdomain).await {
                for ip in resolved.ips {
                    wildcard_ips.insert(ip);
                }
            }
        }

        if wildcard_ips.is_empty() {
            None
        } else {
            Some(WildcardInfo {
                wildcard_ips: wildcard_ips.into_iter().collect(),
            })
        }
    }

    pub fn is_wildcard_match(&self, wildcard_info: &WildcardInfo, ips: &[String]) -> bool {
        for ip in ips {
            if wildcard_info.wildcard_ips.contains(ip) {
                return true;
            }
        }
        false
    }
}

#[derive(Debug, Clone)]
pub struct WildcardInfo {
    pub wildcard_ips: Vec<String>,
}
