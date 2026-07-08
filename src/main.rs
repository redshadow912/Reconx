#![allow(dead_code)]

mod analyzers;
mod cli;
mod collectors;
mod config;
mod error;
mod models;
mod output;
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
                no_color,
                quiet,
                verbose,
                ScanMode::Intel,
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

async fn run_scan(
    domain: &str,
    org_name: Option<String>,
    output: Option<String>,
    format: Option<Vec<ReportFormat>>,
    concurrency: usize,
    timeout: u64,
    sources: Option<Vec<String>>,
    exclude: Option<Vec<String>>,
    no_color: bool,
    quiet: bool,
    verbose: bool,
    mode: ScanMode,
) {
    let terminal = TerminalOutput::new(quiet, no_color);
    terminal.print_banner();
    terminal.print_target(domain);

    let mut config = Config::load().unwrap_or_default();
    config.concurrency = concurrency;
    config.timeout_secs = timeout;

    let target = Target::new(domain.to_string()).with_org(org_name);

    let registry = CollectorRegistry::new();
    let all_collectors = registry.get_collectors(&sources, &exclude);

    let filtered_collectors: Vec<std::sync::Arc<dyn collectors::Collector>> = all_collectors
        .into_iter()
        .filter(|c| {
            if c.requires_api_key() && config.get_api_key(c.name()).is_none() {
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

    let all_findings = analyzers::correlator::Correlator::dedup_findings(all_findings);
    let duration_ms = start.elapsed().as_millis() as u64;

    terminal.print_summary(&all_findings, duration_ms);

    let formats = format.unwrap_or_else(|| {
        vec![
            ReportFormat::Html,
            ReportFormat::Json,
            ReportFormat::Csv,
        ]
    });

    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let output_dir = output
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("./reconx-output/{}/{}", domain, timestamp)));

    let writer = OutputWriter::new(output_dir, formats);
    match writer.write_all(&all_findings, domain) {
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
        ]
    });

    let output_dir = output
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("./reconx-output/{}", domain)));

    let writer = OutputWriter::new(output_dir, formats);
    match writer.write_all(&findings, &domain) {
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
