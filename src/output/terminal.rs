use colored::Colorize;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};

use crate::collectors::CollectorResult;
use crate::models::Finding;
use crate::models::finding::Severity;

pub struct TerminalOutput {
    multi: MultiProgress,
    quiet: bool,
    no_color: bool,
}

impl TerminalOutput {
    pub fn new(quiet: bool, no_color: bool) -> Self {
        Self {
            multi: MultiProgress::new(),
            quiet,
            no_color,
        }
    }

    pub fn print_banner(&self) {
        if self.quiet {
            return;
        }

        let banner = r#"
  ____
 |  _ \ ___  ___ ___  _ __ __  __
 | |_) / _ \/ __/ _ \| '_ \\ \/ /
 |  _ <  __/ (_| (_) | | | |>  <
 |_| \_\___|\___\___/|_| |_/_/\_\

 Passive OSINT Reconnaissance Tool
"#;

        if self.no_color {
            println!("{}", banner);
        } else {
            println!("{}", banner.cyan().bold());
        }
    }

    pub fn print_target(&self, domain: &str) {
        if self.quiet {
            return;
        }

        if self.no_color {
            println!("Target: {}", domain);
            println!("{}", "-".repeat(50));
        } else {
            println!("{} {}", "Target:".bold(), domain.yellow());
            println!("{}", "-".repeat(50).dimmed());
        }
    }

    pub fn create_progress(&self, total: u64) -> ProgressBar {
        let pb = self.multi.add(ProgressBar::new(total));
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} collectors")
                .unwrap()
                .progress_chars("=>-"),
        );
        pb
    }

    pub fn print_collector_result(&self, result: &CollectorResult) {
        if self.quiet {
            return;
        }

        let status = if result.error.is_some() {
            if self.no_color {
                "FAIL".to_string()
            } else {
                "FAIL".red().to_string()
            }
        } else if result.findings.is_empty() {
            if self.no_color {
                "EMPTY".to_string()
            } else {
                "EMPTY".yellow().to_string()
            }
        } else {
            if self.no_color {
                format!("OK ({})", result.findings.len())
            } else {
                format!("OK ({})", result.findings.len()).green().to_string()
            }
        };

        let duration = format!("{}ms", result.duration_ms);

        if self.no_color {
            println!("  [{}] {} ({})", status, result.collector_name, duration);
        } else {
            println!(
                "  [{}] {} ({})",
                status,
                result.collector_name.bold(),
                duration.dimmed()
            );
        }

        if let Some(ref err) = result.error {
            if !self.no_color {
                println!("    {}", err.red());
            }
        }
    }

    pub fn print_finding(&self, finding: &Finding) {
        if self.quiet {
            return;
        }

        let (icon, text) = match finding {
            Finding::Subdomain(s) => ("SUB", &s.subdomain),
            Finding::Asset(a) => ("AST", &format!("{} ({})", a.host, a.ip)),
            Finding::Credential(c) => ("CRD", &c.email),
            Finding::Wireless(w) => ("WFI", &format!("{} [{}]", w.ssid, w.encryption)),
            Finding::Vulnerability(v) => ("VLN", &v.description),
        };

        let severity = finding.severity();
        let colored_icon = if self.no_color {
            format!("[{}]", icon)
        } else {
            match severity {
                Severity::Critical => format!("[{}]", icon).red().bold().to_string(),
                Severity::High => format!("[{}]", icon).red().to_string(),
                Severity::Medium => format!("[{}]", icon).yellow().to_string(),
                Severity::Low => format!("[{}]", icon).green().to_string(),
                Severity::Info => format!("[{}]", icon).blue().to_string(),
            }
        };

        println!("  {} {}", colored_icon, text);
    }

    pub fn print_summary(&self, findings: &[Finding], duration_ms: u64) {
        if self.quiet {
            return;
        }

        println!();
        if self.no_color {
            println!("{}", "=".repeat(50));
        } else {
            println!("{}", "=".repeat(50).dimmed());
        }

        let subdomains = findings.iter().filter(|f| matches!(f, Finding::Subdomain(_))).count();
        let assets = findings.iter().filter(|f| matches!(f, Finding::Asset(_))).count();
        let credentials = findings.iter().filter(|f| matches!(f, Finding::Credential(_))).count();
        let wireless = findings.iter().filter(|f| matches!(f, Finding::Wireless(_))).count();
        let vulns = findings.iter().filter(|f| matches!(f, Finding::Vulnerability(_))).count();

        let summary = format!(
            "Total: {} findings | Subdomains: {} | Assets: {} | Credentials: {} | Wireless: {} | Vulnerabilities: {}",
            findings.len(), subdomains, assets, credentials, wireless, vulns
        );

        if self.no_color {
            println!("{}", summary);
            println!("Completed in {}ms", duration_ms);
        } else {
            println!("{}", summary.bold());
            println!("{} {}", "Completed in".dimmed(), format!("{}ms", duration_ms).green());
        }
    }
}
