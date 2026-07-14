use reqwest::header::HeaderMap;

#[derive(Clone)]
pub struct CdnWafDetector;

impl CdnWafDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, headers: &HeaderMap, server: &Option<String>) -> (Option<String>, Option<String>) {
        let mut cdn = None;
        let mut waf = None;

        // Check headers for CDN indicators
        if headers.get("cf-ray").is_some() || headers.get("cf-cache-status").is_some() {
            cdn = Some("Cloudflare".to_string());
        }

        if headers.get("x-amz-cf-id").is_some() || headers.get("x-amz-cf-pop").is_some() {
            cdn = Some("AWS CloudFront".to_string());
        }

        if headers.get("x-akamai-transformed").is_some() || headers.get("x-akamai-request-id").is_some() {
            cdn = Some("Akamai".to_string());
        }

        if headers.get("x-fastly-request-id").is_some() {
            cdn = Some("Fastly".to_string());
        }

        if let Some(served_by) = headers.get("x-served-by") {
            if let Ok(sb) = served_by.to_str() {
                if sb.starts_with("cache-") {
                    cdn = Some("Fastly".to_string());
                }
            }
        }

        if headers.get("x-azure-ref").is_some() {
            cdn = Some("Azure Front Door".to_string());
        }

        // Check headers for WAF indicators
        if headers.get("x-iinfo").is_some() || headers.get("x-cdn").is_some() {
            if let Some(x_cdn) = headers.get("x-cdn") {
                if let Ok(val) = x_cdn.to_str() {
                    if val.contains("Imperva") || val.contains("Incapsula") {
                        waf = Some("Imperva".to_string());
                    }
                }
            } else {
                waf = Some("Imperva".to_string());
            }
        }

        if headers.get("x-sucuri-id").is_some() || headers.get("x-sucuri-cache").is_some() {
            waf = Some("Sucuri".to_string());
        }

        // Check server header
        if let Some(ref srv) = server {
            let srv_lower = srv.to_lowercase();
            if srv_lower.contains("cloudflare") && cdn.is_none() {
                cdn = Some("Cloudflare".to_string());
            }
            if srv_lower.contains("akamaighost") || srv_lower.contains("akamai") {
                if cdn.is_none() {
                    cdn = Some("Akamai".to_string());
                }
            }
            if srv_lower.contains("amazons3") {
                cdn = Some("AWS S3".to_string());
            }
            if srv_lower.contains("cloudfront") {
                if cdn.is_none() {
                    cdn = Some("AWS CloudFront".to_string());
                }
            }
        }

        (cdn, waf)
    }
}
