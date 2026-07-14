#![allow(dead_code)]

mod analyzers;
mod cli;
mod collectors;
mod config;
mod dns;
mod error;
mod models;
mod output;
mod probe;
mod reports;

use std::path::PathBuf;

use clap::Parser;
use colored::Colorize;

use cli::{Cli, Commands, ConfigAction, ReportFormat};
use collectors::{CollectorRegistry, run_collectors};
use config::Config;
use models::{Finding, Target};
use output::terminal::TerminalOutput;
use output::writer::OutputWriter;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Enum {
            domain,
            output,
            format,
            concurrency,
            timeout,
            sources,
            exclude,
            resolve,
            no_wildcard,
            diff,
            no_color,
            quiet,
            verbose,
        } => {
            run_scan(
                &domain,
                None,
                output,
                format,
                concurrency,
                timeout,
                sources,
                exclude,
                resolve,
                no_wildcard,
                diff,
                no_color,
                quiet,
                verbose,
                ScanMode::Enum,
            )
            .await;
        }
        Commands::Assets {
            domain,
            output,
            format,
            concurrency,
            timeout,
            no_color,
            quiet,
            verbose,
        } => {
            run_scan(
                &domain,
                None,
                output,
                format,
                concurrency,
                timeout,
                None,
                None,
                false,
                false,
                None,
                no_color,
                quiet,
                verbose,
                ScanMode::Assets,
            )
            .await;
        }
        Commands::Creds {
            domain,
            name,
            output,
            format,
            no_color,
            quiet,
            verbose,
        } => {
            run_scan(
                &domain,
                name,
                output,
                format,
                10,
                30,
                None,
                None,
                false,
                false,
                None,
                no_color,
                quiet,
                verbose,
                ScanMode::Creds,
            )
            .await;
        }
        Commands::Wireless {
            name,
            output,
            format,
            no_color,
            quiet,
            verbose,
        } => {
            run_scan(
                &name,
                Some(name.clone()),
                output,
                format,
                10,
                30,
                Some(vec!["wigle".to_string()]),
                None,
                false,
                false,
                None,
                no_color,
                quiet,
                verbose,
                ScanMode::Wireless,
            )
            .await;
        }
        Commands::Intel {
            domain,
            name,
            output,
            format,
            concurrency,
            timeout,
            sources,
            exclude,
            resolve,
            no_wildcard,
            diff,
            no_color,
            quiet,
            verbose,
        } => {
            run_scan(
                &domain,
                name,
                output,
                format,
                concurrency,
                timeout,
                sources,
                exclude,
                resolve,
                no_wildcard,
                diff,
                no_color,
                quiet,
                verbose,
                ScanMode::Intel,
            )
            .await;
        }
        Commands::Probe {
            domain,
            input,
            output,
            format,
            concurrency,
            timeout,
            no_color,
            quiet,
            verbose,
        } => {
            run_probe(
                domain,
                input,
                output,
                format,
                concurrency,
                timeout,
                no_color,
                quiet,
                verbose,
            )
            .await;
        }
        Commands::Report {
            input,
            output,
            format,
        } => {
            generate_report(&input, output, format);
        }
        Commands::Config { action } => {
            handle_config(action);
        }
    }
}

#[derive(Debug)]
enum ScanMode {
    Enum,
    Assets,
    Creds,
    Wireless,
    Intel,
}

fn sanitize_domain(input: &str) -> String {
    let mut domain = input.trim().to_lowercase();
    domain = domain.replace("https://", "").replace("http://", "");
    if domain.starts_with("www.") {
        domain = domain[4..].to_string();
    }
    domain = domain.trim_end_matches('/').to_string();
    domain = domain.split('/').next().unwrap_or(&domain).to_string();
    domain
}

async fn run_scan(
    domain: &str,
    org_name: Option<String>,
    output: Option<String>,
    format: Option<Vec<ReportFormat>>,
    concurrency: usize,
    timeout: u64,
    sources: Option<Vec<String>>,
    exclude: Option<Vec<String>>,
    resolve: bool,
    no_wildcard: bool,
    diff_path: Option<String>,
    no_color: bool,
    quiet: bool,
    verbose: bool,
    mode: ScanMode,
) {
    let domain = sanitize_domain(domain);
    let terminal = TerminalOutput::new(quiet, no_color);
    terminal.print_banner();
    terminal.print_target(&domain);

    let mut config = Config::load().unwrap_or_default();
    config.concurrency = concurrency;
    config.timeout_secs = timeout;

    let target = Target::new(domain.to_string()).with_org(org_name);

    let registry = CollectorRegistry::new();
    let all_collectors = registry.get_collectors(&sources, &exclude);

    let filtered_collectors: Vec<std::sync::Arc<dyn collectors::Collector>> = all_collectors
        .into_iter()
        .filter(|c| {
            if c.requires_api_key() && config.get_api_key(c.config_key()).is_none() {
                if verbose {
                    println!(
                        "  {} {} (no API key configured)",
                        "[SKIP]".yellow(),
                        c.name()
                    );
                }
                return false;
            }
            match mode {
                ScanMode::Enum => matches!(
                    c.category(),
                    collectors::CollectorCategory::CertificateTransparency
                        | collectors::CollectorCategory::DnsSubdomain
                        | collectors::CollectorCategory::SearchEngine
                        | collectors::CollectorCategory::WebArchives
                ),
                ScanMode::Assets => matches!(
                    c.category(),
                    collectors::CollectorCategory::HostService
                        | collectors::CollectorCategory::WhoisAsn
                        | collectors::CollectorCategory::DnsSubdomain
                ),
                ScanMode::Creds => matches!(
                    c.category(),
                    collectors::CollectorCategory::CredentialBreaches
                        | collectors::CollectorCategory::CodeDocLeaks
                ),
                ScanMode::Wireless => {
                    matches!(c.category(), collectors::CollectorCategory::Wireless)
                }
                ScanMode::Intel => true,
            }
        })
        .collect();

    let total = filtered_collectors.len() as u64;
    if total == 0 {
        println!("No collectors available for this scan mode.");
        return;
    }

    let progress = terminal.create_progress(total);
    let start = std::time::Instant::now();

    let results = run_collectors(filtered_collectors, &target, &config, concurrency).await;

    let mut all_findings: Vec<Finding> = Vec::new();

    for result in &results {
        terminal.print_collector_result(result);
        progress.inc(1);

        for finding in &result.findings {
            terminal.print_finding(finding);
        }

        all_findings.extend(result.findings.clone());
    }

    progress.finish();

    let mut all_findings = analyzers::correlator::Correlator::dedup_findings(all_findings);
    
    // DNS Resolution
    if resolve {
        if !quiet {
            println!("\n{} Resolving subdomains...", "DNS:".cyan());
        }
        
        let resolver = dns::DnsResolver::new(concurrency, timeout);
        let subdomains: Vec<String> = all_findings
            .iter()
            .filter_map(|f| {
                if let Finding::Subdomain(s) = f {
                    Some(s.subdomain.clone())
                } else {
                    None
                }
            })
            .collect();

        let resolved = resolver.resolve_many(subdomains).await;
        
        // Update findings with resolved IPs
        for resolved_sub in &resolved {
            for finding in &mut all_findings {
                if let Finding::Subdomain(s) = finding {
                    if s.subdomain == resolved_sub.subdomain {
                        s.ip_addresses = resolved_sub.ips.clone();
                        s.dns_records = resolved_sub.dns_records.clone();
                        if !resolved_sub.cnames.is_empty() {
                            s.cname = Some(resolved_sub.cnames[0].clone());
                        }
                        break;
                    }
                }
            }
        }
        
        if !quiet {
            let resolved_count = resolved.len();
            println!("  {} {}/{} subdomains resolved", 
                "✓".green(), resolved_count, 
                all_findings.iter().filter(|f| matches!(f, Finding::Subdomain(_))).count());
        }
    }
    
    // Wildcard Detection
    if no_wildcard {
        if !quiet {
            println!("\n{} Detecting wildcards...", "DNS:".cyan());
        }
        
        let resolver = dns::DnsResolver::new(concurrency, timeout);
        let wildcard_detector = dns::WildcardDetector::new(resolver);
        
        if let Some(wildcard_info) = wildcard_detector.detect_wildcard(&domain).await {
            let mut filtered = Vec::new();
            let mut wildcard_count = 0;
            
            for finding in all_findings {
                if let Finding::Subdomain(ref s) = finding {
                    if wildcard_detector.is_wildcard_match(&wildcard_info, &s.ip_addresses) {
                        wildcard_count += 1;
                        continue;
                    }
                }
                filtered.push(finding);
            }
            
            all_findings = filtered;
            
            if !quiet {
                println!("  {} {} wildcard subdomains filtered", 
                    "✓".green(), wildcard_count);
            }
        }
    }
    
    // Run subdomain takeover detection
    let takeovers = analyzers::takeover_detector::TakeoverDetector::detect(&all_findings);
    
    // Add takeover findings as vulnerabilities
    if !takeovers.is_empty() {
        let takeover_findings = analyzers::takeover_detector::TakeoverDetector::to_findings(&takeovers);
        all_findings.extend(takeover_findings);
        
        if !quiet {
            println!("\n{} {} subdomain takeover candidates detected!", 
                "TAKEOVER:".red().bold(), takeovers.len());
            for t in &takeovers {
                let sev_color = match t.severity {
                    models::finding::Severity::Critical => t.severity.to_string().red().bold().to_string(),
                    models::finding::Severity::High => t.severity.to_string().red().to_string(),
                    _ => t.severity.to_string().yellow().to_string(),
                };
                println!("  [{}] {} → {} ({})", sev_color, t.subdomain, t.cname, t.service);
            }
        }
    }

    // Run analyzers
    let correlated = analyzers::correlator::Correlator::correlate(&all_findings);
    let tech_profiles = analyzers::tech_fingerprint::TechFingerprinter::fingerprint(&all_findings);
    let attack_surface = analyzers::attack_surface::AttackSurfaceMapper::map(&domain, &all_findings);
    let risk = analyzers::risk_scorer::RiskScorer::score(&domain, &all_findings, &takeovers);
    
    // Historical diff
    let diff_result = diff_path.as_ref().and_then(|path| {
        let prev = analyzers::diff_engine::DiffEngine::load_previous(std::path::Path::new(path))?;
        Some(analyzers::diff_engine::DiffEngine::diff(&prev, &all_findings))
    });
    
    let duration_ms = start.elapsed().as_millis() as u64;

    terminal.print_summary(&all_findings, duration_ms);
    
    // Print analysis results
    if !quiet {
        // Risk Score
        let risk_color = match risk.risk_level {
            models::finding::Severity::Critical => format!("{:.1}/10", risk.overall_score).red().bold().to_string(),
            models::finding::Severity::High => format!("{:.1}/10", risk.overall_score).red().to_string(),
            models::finding::Severity::Medium => format!("{:.1}/10", risk.overall_score).yellow().to_string(),
            _ => format!("{:.1}/10", risk.overall_score).green().to_string(),
        };
        println!("\n{} {} ({})", "Risk Score:".cyan().bold(), risk_color, risk.risk_level);
        
        // Top risk factors
        for factor in risk.top_factors.iter().take(5) {
            let emoji = match factor.severity {
                models::finding::Severity::Critical => "🔴",
                models::finding::Severity::High => "🟠",
                models::finding::Severity::Medium => "🟡",
                _ => "🟢",
            };
            println!("  {} {}: {}", emoji, factor.category, factor.description);
        }

        if !correlated.is_empty() {
            println!("\n{} {} correlated subdomains with confidence scores", 
                "Analysis:".cyan(), correlated.len());
            for sub in correlated.iter().take(5) {
                println!("  {} (confidence: {}, sources: {})", 
                    sub.subdomain, sub.confidence, sub.sources.len());
            }
            if correlated.len() > 5 {
                println!("  ... and {} more", correlated.len() - 5);
            }
        }
        
        if !tech_profiles.is_empty() {
            println!("\n{} {} technology profiles detected", 
                "Tech Stack:".cyan(), tech_profiles.len());
            for profile in tech_profiles.iter().take(3) {
                println!("  {}: {}", profile.host, profile.technologies.join(", "));
            }
        }
        
        if attack_surface.total_ips > 0 || attack_surface.total_ports > 0 {
            println!("\n{} {} IPs, {} ports, {} services", 
                "Attack Surface:".cyan(), 
                attack_surface.total_ips, 
                attack_surface.total_ports,
                attack_surface.total_services);
        }
        
        // Diff results
        if let Some(ref diff) = diff_result {
            println!("\n{} +{} new, -{} removed since last scan",
                "Changes:".cyan().bold(), diff.total_new, diff.total_removed);
            if !diff.new_subdomains.is_empty() {
                println!("  New subdomains: {}", diff.new_subdomains.iter().take(5).cloned().collect::<Vec<_>>().join(", "));
            }
        }
        
        // WHOIS info
        for finding in &all_findings {
            if let Finding::Whois(w) = finding {
                println!("\n{}", "WHOIS Intelligence:".cyan());
                if let Some(ref r) = w.registrar { println!("  Registrar: {}", r); }
                if let Some(ref d) = w.creation_date { println!("  Created: {}", d); }
                if let Some(ref d) = w.expiration_date { println!("  Expires: {}", d); }
                if let Some(days) = w.days_until_expiry { 
                    let days_str = if days < 30 { format!("{} days", days).red().to_string() } 
                                   else { format!("{} days", days).green().to_string() };
                    println!("  Days Until Expiry: {}", days_str);
                }
                if let Some(age) = w.domain_age_days { println!("  Domain Age: {} days", age); }
                if let Some(ref org) = w.registrant_org { println!("  Registrant: {}", org); }
                if !w.nameservers.is_empty() { println!("  Nameservers: {}", w.nameservers.join(", ")); }
                println!("  Privacy Protected: {}", if w.is_privacy_protected { "Yes" } else { "No" });
            }
        }
    }

    let formats = format.unwrap_or_else(|| {
        vec![
            ReportFormat::Html,
            ReportFormat::Json,
            ReportFormat::Csv,
            ReportFormat::Markdown,
        ]
    });

    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let output_dir = output
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("./reconx-output/{}/{}", domain, timestamp)));

    let writer = OutputWriter::new(output_dir, formats);
    match writer.write_all(&all_findings, &domain, &risk, &takeovers, diff_result.as_ref()) {
        Ok(()) => {
            if !quiet {
                println!(
                    "\n{} {}",
                    "Reports saved to:".green(),
                    writer.output_path().display()
                );
            }
        }
        Err(e) => {
            eprintln!("Failed to write reports: {}", e);
        }
    }
}

async fn run_probe(
    domain: Option<String>,
    input: Option<String>,
    output: Option<String>,
    format: Option<Vec<ReportFormat>>,
    concurrency: usize,
    timeout: u64,
    no_color: bool,
    quiet: bool,
    verbose: bool,
) {
    let terminal = TerminalOutput::new(quiet, no_color);
    terminal.print_banner();

    // Get subdomains to probe
    let urls: Vec<String> = if let Some(input_file) = input {
        // Load from previous scan
        let content = match std::fs::read_to_string(&input_file) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Failed to read input file: {}", e);
                return;
            }
        };

        let findings: Vec<Finding> = match serde_json::from_str(&content) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("Failed to parse JSON: {}", e);
                return;
            }
        };

        findings
            .iter()
            .filter_map(|f| {
                if let Finding::Subdomain(s) = f {
                    Some(format!("https://{}", s.subdomain))
                } else {
                    None
                }
            })
            .collect()
    } else if let Some(ref d) = domain {
        // Run enum first to get subdomains
        let domain = sanitize_domain(d);
        println!("{} Running subdomain enumeration for {}...", "Probe:".cyan(), domain);
        
        let mut config = Config::load().unwrap_or_default();
        config.concurrency = concurrency;
        config.timeout_secs = timeout;

        let target = Target::new(domain.clone());
        let registry = CollectorRegistry::new();
        let all_collectors = registry.get_collectors(&None, &None);

        let filtered_collectors: Vec<std::sync::Arc<dyn collectors::Collector>> = all_collectors
            .into_iter()
            .filter(|c| {
                if c.requires_api_key() && config.get_api_key(c.config_key()).is_none() {
                    return false;
                }
                matches!(
                    c.category(),
                    collectors::CollectorCategory::CertificateTransparency
                        | collectors::CollectorCategory::DnsSubdomain
                        | collectors::CollectorCategory::SearchEngine
                        | collectors::CollectorCategory::WebArchives
                )
            })
            .collect();

        let results = run_collectors(filtered_collectors, &target, &config, concurrency).await;
        
        let mut all_findings: Vec<Finding> = Vec::new();
        for result in results {
            all_findings.extend(result.findings);
        }

        let all_findings = analyzers::correlator::Correlator::dedup_findings(all_findings);

        all_findings
            .iter()
            .filter_map(|f| {
                if let Finding::Subdomain(s) = f {
                    Some(format!("https://{}", s.subdomain))
                } else {
                    None
                }
            })
            .collect()
    } else {
        eprintln!("Error: Either --domain or --input must be specified");
        return;
    };

    if urls.is_empty() {
        println!("No subdomains found to probe.");
        return;
    }

    println!("\n{} Probing {} URLs...", "Probe:".cyan(), urls.len());

    let prober = probe::HttpProber::new(concurrency, timeout);
    let start = std::time::Instant::now();
    
    let results = prober.probe_many(urls).await;
    let _duration_ms = start.elapsed().as_millis() as u64;

    // Convert to findings
    let findings: Vec<Finding> = results
        .into_iter()
        .map(|r| Finding::HttpProbe(r))
        .collect();

    // Print results
    if !quiet {
        println!("\n{} {} URLs probed successfully", "✓".green(), findings.len());
        
        if verbose {
            for finding in &findings {
                if let Finding::HttpProbe(p) = finding {
                    let status_color = if p.status_code >= 200 && p.status_code < 300 {
                        p.status_code.to_string().green()
                    } else if p.status_code >= 300 && p.status_code < 400 {
                        p.status_code.to_string().yellow()
                    } else {
                        p.status_code.to_string().red()
                    };

                    println!("  [{}] {} - {}", 
                        status_color,
                        p.url,
                        p.title.as_deref().unwrap_or("No title"));
                    
                    if !p.technologies.is_empty() {
                        println!("    Tech: {}", p.technologies.join(", "));
                    }
                    if let Some(ref cdn) = p.cdn {
                        println!("    CDN: {}", cdn);
                    }
                    if let Some(ref waf) = p.waf {
                        println!("    WAF: {}", waf);
                    }
                }
            }
        }
    }

    // Save reports
    let formats = format.unwrap_or_else(|| {
        vec![
            ReportFormat::Html,
            ReportFormat::Json,
            ReportFormat::Csv,
            ReportFormat::Markdown,
        ]
    });

    let domain_name = if let Some(d) = domain {
        sanitize_domain(&d)
    } else {
        "probe-results".to_string()
    };

    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let output_dir = output
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("./reconx-output/{}/probe-{}", domain_name, timestamp)));

    let risk = analyzers::risk_scorer::RiskScorer::score(&domain_name, &findings, &[]);
    let writer = OutputWriter::new(output_dir, formats);
    match writer.write_all(&findings, &domain_name, &risk, &[], None) {
        Ok(()) => {
            if !quiet {
                println!(
                    "\n{} {}",
                    "Reports saved to:".green(),
                    writer.output_path().display()
                );
            }
        }
        Err(e) => {
            eprintln!("Failed to write reports: {}", e);
        }
    }
}

fn generate_report(input: &str, output: Option<String>, format: Option<Vec<ReportFormat>>) {
    let content = match std::fs::read_to_string(input) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to read input file: {}", e);
            return;
        }
    };

    let findings: Vec<Finding> = match serde_json::from_str(&content) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to parse JSON: {}", e);
            return;
        }
    };

    let domain = findings
        .iter()
        .find_map(|f| match f {
            Finding::Subdomain(s) => {
                let parts: Vec<&str> = s.subdomain.splitn(2, '.').collect();
                if parts.len() == 2 {
                    Some(parts[1].to_string())
                } else {
                    Some(s.subdomain.clone())
                }
            }
            _ => None,
        })
        .unwrap_or_else(|| "unknown".to_string());

    let formats = format.unwrap_or_else(|| {
        vec![
            ReportFormat::Html,
            ReportFormat::Json,
            ReportFormat::Csv,
            ReportFormat::Markdown,
        ]
    });

    let output_dir = output
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("./reconx-output/{}", domain)));

    let risk = analyzers::risk_scorer::RiskScorer::score(&domain, &findings, &[]);
    let writer = OutputWriter::new(output_dir, formats);
    match writer.write_all(&findings, &domain, &risk, &[], None) {
        Ok(()) => {
            println!(
                "{} {}",
                "Reports generated:".green(),
                writer.output_path().display()
            );
        }
        Err(e) => {
            eprintln!("Failed to generate reports: {}", e);
        }
    }
}

fn handle_config(action: ConfigAction) {
    let mut config = Config::load().unwrap_or_default();

    match action {
        ConfigAction::Set { source, key } => {
            config.set_api_key(source.clone(), key);
            match config.save() {
                Ok(()) => println!("{} API key for '{}' saved.", "OK".green(), source),
                Err(e) => eprintln!("Failed to save config: {}", e),
            }
        }
        ConfigAction::Get { source } => {
            match config.get_api_key(&source) {
                Some(key) => {
                    let masked = if key.len() > 8 {
                        format!("{}...{}", &key[..4], &key[key.len() - 4..])
                    } else {
                        "****".to_string()
                    };
                    println!("{}: {}", source, masked);
                }
                None => println!("No API key configured for '{}'", source),
            }
        }
        ConfigAction::List => {
            if config.api_keys.is_empty() {
                println!("No API keys configured.");
            } else {
                println!("Configured API keys:");
                for (source, key) in &config.api_keys {
                    let masked = if key.len() > 8 {
                        format!("{}...{}", &key[..4], &key[key.len() - 4..])
                    } else {
                        "****".to_string()
                    };
                    println!("  {}: {}", source, masked);
                }
            }
        }
        ConfigAction::Path => {
            let config_dir = dirs::config_dir()
                .map(|d| d.join("reconx").join("config.toml"))
                .unwrap_or_else(|| PathBuf::from("~/.config/reconx/config.toml"));
            println!("{}", config_dir.display());
        }
    }
}
