use regex::Regex;
use reqwest::Client;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::models::http_probe::HttpProbeFinding;
use super::tech_detect::TechDetector;
use super::cdn_detect::CdnWafDetector;

pub struct HttpProber {
    client: Client,
    concurrency: usize,
    timeout_secs: u64,
    tech_detector: TechDetector,
    cdn_detector: CdnWafDetector,
}

impl HttpProber {
    pub fn new(concurrency: usize, timeout_secs: u64) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .danger_accept_invalid_certs(true)
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
            .redirect(reqwest::redirect::Policy::limited(10))
            .build()
            .expect("Failed to build HTTP client");

        Self {
            client,
            concurrency,
            timeout_secs,
            tech_detector: TechDetector::new(),
            cdn_detector: CdnWafDetector::new(),
        }
    }

    pub async fn probe_url(&self, url: &str) -> Option<HttpProbeFinding> {
        let timeout_duration = Duration::from_secs(self.timeout_secs);

        let result = timeout(timeout_duration, async {
            let mut finding = HttpProbeFinding::new(url.to_string());

            let resp = match self.client.get(url).send().await {
                Ok(r) => r,
                Err(_) => return None,
            };

            finding.status_code = resp.status().as_u16();
            finding.final_url = resp.url().to_string();

            // Extract headers (clone before consuming resp)
            let headers = resp.headers().clone();
            
            if let Some(server) = headers.get("server") {
                if let Ok(s) = server.to_str() {
                    finding.server = Some(s.to_string());
                }
            }

            if let Some(content_type) = headers.get("content-type") {
                if let Ok(ct) = content_type.to_str() {
                    finding.content_type = Some(ct.to_string());
                }
            }

            // Detect CDN/WAF
            let (cdn, waf) = self.cdn_detector.detect(&headers, &finding.server);
            finding.cdn = cdn;
            finding.waf = waf;

            // Get response body
            let body = match resp.text().await {
                Ok(b) => b,
                Err(_) => return Some(finding),
            };

            finding.content_length = body.len();

            // Extract title
            finding.title = self.extract_title(&body);

            // Detect technologies
            finding.technologies = self.tech_detector.detect(&headers, &body);

            // --- UPGRADE 5: Sensitive Path Detection ---
            let sensitive_paths = vec![
                "/.env", "/.git/config", "/wp-config.php", "/.DS_Store",
                "/admin", "/login", "/swagger-ui/", "/api-docs",
                "/server-status", "/phpinfo.php"
            ];
            
            let mut found_paths = Vec::new();
            for path in sensitive_paths {
                let check_url = format!("{}{}", finding.url, path);
                if let Ok(path_resp) = self.client.get(&check_url).send().await {
                    if path_resp.status().is_success() {
                        found_paths.push(path.to_string());
                        finding.technologies.push(format!("Exposed Path: {}", path));
                    }
                }
            }
            
            Some(finding)
        })
        .await;

        result.ok().flatten()
    }

    pub async fn probe_many(&self, urls: Vec<String>) -> Vec<HttpProbeFinding> {
        let semaphore = Arc::new(Semaphore::new(self.concurrency));
        let mut handles = Vec::new();

        for url in urls {
            let sem = semaphore.clone();
            let prober = self.clone();
            
            let handle = tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                prober.probe_url(&url).await
            });
            
            handles.push(handle);
        }

        let mut results = Vec::new();
        for handle in handles {
            if let Ok(Some(finding)) = handle.await {
                results.push(finding);
            }
        }

        results
    }

    fn extract_title(&self, html: &str) -> Option<String> {
        let re = Regex::new(r"(?i)<title[^>]*>(.*?)</title>").ok()?;
        re.captures(html)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().trim().to_string())
    }
}

impl Clone for HttpProber {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            concurrency: self.concurrency,
            timeout_secs: self.timeout_secs,
            tech_detector: self.tech_detector.clone(),
            cdn_detector: self.cdn_detector.clone(),
        }
    }
}
