use regex::Regex;
use reqwest::header::HeaderMap;

#[derive(Clone)]
pub struct TechDetector;

impl TechDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, headers: &HeaderMap, body: &str) -> Vec<String> {
        let mut techs = Vec::new();

        // Header-based detection
        self.detect_from_headers(headers, &mut techs);

        // HTML-based detection
        self.detect_from_html(body, &mut techs);

        // Meta tag detection
        self.detect_from_meta(body, &mut techs);

        // Deduplicate
        techs.sort();
        techs.dedup();
        techs
    }

    fn detect_from_headers(&self, headers: &HeaderMap, techs: &mut Vec<String>) {
        // Server header
        if let Some(server) = headers.get("server") {
            if let Ok(s) = server.to_str() {
                let s_lower = s.to_lowercase();
                if s_lower.contains("nginx") {
                    techs.push("Nginx".to_string());
                }
                if s_lower.contains("apache") {
                    techs.push("Apache".to_string());
                }
                if s_lower.contains("iis") {
                    techs.push("Microsoft IIS".to_string());
                }
                if s_lower.contains("cloudflare") {
                    techs.push("Cloudflare".to_string());
                }
                if s_lower.contains("gws") || s_lower.contains("google") {
                    techs.push("Google Web Server".to_string());
                }
                if s_lower.contains("akamai") {
                    techs.push("Akamai".to_string());
                }
            }
        }

        // X-Powered-By
        if let Some(powered_by) = headers.get("x-powered-by") {
            if let Ok(pb) = powered_by.to_str() {
                let pb_lower = pb.to_lowercase();
                if pb_lower.contains("php") {
                    techs.push("PHP".to_string());
                }
                if pb_lower.contains("asp.net") {
                    techs.push("ASP.NET".to_string());
                }
                if pb_lower.contains("express") {
                    techs.push("Express.js".to_string());
                }
                if pb_lower.contains("next.js") {
                    techs.push("Next.js".to_string());
                }
                if pb_lower.contains("nuxt") {
                    techs.push("Nuxt.js".to_string());
                }
            }
        }

        // X-Generator
        if let Some(gen) = headers.get("x-generator") {
            if let Ok(g) = gen.to_str() {
                let g_lower = g.to_lowercase();
                if g_lower.contains("wordpress") {
                    techs.push("WordPress".to_string());
                }
                if g_lower.contains("drupal") {
                    techs.push("Drupal".to_string());
                }
                if g_lower.contains("joomla") {
                    techs.push("Joomla".to_string());
                }
            }
        }

        // X-AspNet-Version
        if headers.get("x-aspnet-version").is_some() {
            techs.push("ASP.NET".to_string());
        }

        // X-Vercel-Id
        if headers.get("x-vercel-id").is_some() {
            techs.push("Vercel".to_string());
        }

        // X-NF-Request-ID (Netlify)
        if headers.get("x-nf-request-id").is_some() {
            techs.push("Netlify".to_string());
        }
    }

    fn detect_from_html(&self, body: &str, techs: &mut Vec<String>) {
        let lower = body.to_lowercase();

        // WordPress
        if lower.contains("wp-content") || lower.contains("wp-includes") {
            techs.push("WordPress".to_string());
        }

        // Drupal
        if lower.contains("drupal.settings") || lower.contains("sites/default/files") {
            techs.push("Drupal".to_string());
        }

        // Joomla
        if lower.contains("/media/jui/") || lower.contains("joomla!") {
            techs.push("Joomla".to_string());
        }

        // React
        if lower.contains("reactroot") || lower.contains("__next") || lower.contains("_next/static") {
            techs.push("React".to_string());
        }

        // Next.js
        if lower.contains("__next") && lower.contains("_next/static") {
            techs.push("Next.js".to_string());
        }

        // Angular
        if lower.contains("ng-version") || lower.contains("ng-app") {
            techs.push("Angular".to_string());
        }

        // Vue.js
        if lower.contains("vue.js") || lower.contains("vue-app") || lower.contains("__nuxt") {
            techs.push("Vue.js".to_string());
        }

        // Nuxt.js
        if lower.contains("__nuxt") || lower.contains("_nuxt/") {
            techs.push("Nuxt.js".to_string());
        }

        // jQuery
        if lower.contains("jquery") || lower.contains("jquery.min.js") {
            techs.push("jQuery".to_string());
        }

        // Bootstrap
        if lower.contains("bootstrap.css") || lower.contains("bootstrap.min.css") {
            techs.push("Bootstrap".to_string());
        }

        // Google Tag Manager
        if lower.contains("googletagmanager.com") {
            techs.push("Google Tag Manager".to_string());
        }

        // Google Analytics
        if lower.contains("google-analytics.com") || lower.contains("gtag") {
            techs.push("Google Analytics".to_string());
        }

        // Shopify
        if lower.contains("cdn.shopify.com") || lower.contains("shopify.com") {
            techs.push("Shopify".to_string());
        }

        // Laravel
        if lower.contains("laravel_session") {
            techs.push("Laravel".to_string());
        }
    }

    fn detect_from_meta(&self, html: &str, techs: &mut Vec<String>) {
        let re = Regex::new(r#"(?i)<meta\s+name=["']generator["']\s+content=["']([^"']+)["']"#).unwrap();
        if let Some(caps) = re.captures(html) {
            let content = caps[1].to_lowercase();
            if content.contains("wordpress") {
                techs.push("WordPress".to_string());
            }
            if content.contains("drupal") {
                techs.push("Drupal".to_string());
            }
            if content.contains("joomla") {
                techs.push("Joomla".to_string());
            }
            if content.contains("hugo") {
                techs.push("Hugo".to_string());
            }
            if content.contains("gatsby") {
                techs.push("Gatsby".to_string());
            }
            if content.contains("ghost") {
                techs.push("Ghost".to_string());
            }
        }
    }
}
