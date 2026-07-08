use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(name = "reconx")]
#[command(author = "Reconx Contributors")]
#[command(version = "0.1.0")]
#[command(about = "Fast, passive-only OSINT reconnaissance tool", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    #[command(about = "Subdomain enumeration from passive sources")]
    Enum {
        #[arg(short, long, help = "Target domain")]
        domain: String,

        #[arg(short, long, help = "Output directory")]
        output: Option<String>,

        #[arg(short, long, value_delimiter = ',', help = "Report formats: html,json,csv")]
        format: Option<Vec<ReportFormat>>,

        #[arg(short = 'c', long, default_value = "10", help = "Max parallel collectors")]
        concurrency: usize,

        #[arg(short, long, default_value = "30", help = "Per-source timeout in seconds")]
        timeout: u64,

        #[arg(long, value_delimiter = ',', help = "Run only specific sources")]
        sources: Option<Vec<String>>,

        #[arg(long, value_delimiter = ',', help = "Exclude specific sources")]
        exclude: Option<Vec<String>>,

        #[arg(long, help = "Disable colored output")]
        no_color: bool,

        #[arg(short, long, help = "Suppress progress output")]
        quiet: bool,

        #[arg(short, long, help = "Show detailed collector logs")]
        verbose: bool,
    },

    #[command(about = "Discover public-facing assets (IPs, services, technologies)")]
    Assets {
        #[arg(short, long, help = "Target domain")]
        domain: String,

        #[arg(short, long, help = "Output directory")]
        output: Option<String>,

        #[arg(short, long, value_delimiter = ',', help = "Report formats: html,json,csv")]
        format: Option<Vec<ReportFormat>>,

        #[arg(short = 'c', long, default_value = "10", help = "Max parallel collectors")]
        concurrency: usize,

        #[arg(short, long, default_value = "30", help = "Per-source timeout in seconds")]
        timeout: u64,

        #[arg(long, help = "Disable colored output")]
        no_color: bool,

        #[arg(short, long, help = "Suppress progress output")]
        quiet: bool,

        #[arg(short, long, help = "Show detailed collector logs")]
        verbose: bool,
    },

    #[command(about = "Find leaked credentials and breach data")]
    Creds {
        #[arg(short, long, help = "Target domain")]
        domain: String,

        #[arg(short, long, help = "Organization name for broader search")]
        name: Option<String>,

        #[arg(short, long, help = "Output directory")]
        output: Option<String>,

        #[arg(short, long, value_delimiter = ',', help = "Report formats: html,json,csv")]
        format: Option<Vec<ReportFormat>>,

        #[arg(long, help = "Disable colored output")]
        no_color: bool,

        #[arg(short, long, help = "Suppress progress output")]
        quiet: bool,

        #[arg(short, long, help = "Show detailed collector logs")]
        verbose: bool,
    },

    #[command(about = "Search for wireless networks via Wigle.net")]
    Wireless {
        #[arg(short, long, help = "Organization name to search for")]
        name: String,

        #[arg(short, long, help = "Output directory")]
        output: Option<String>,

        #[arg(short, long, value_delimiter = ',', help = "Report formats: html,json,csv")]
        format: Option<Vec<ReportFormat>>,

        #[arg(long, help = "Disable colored output")]
        no_color: bool,

        #[arg(short, long, help = "Suppress progress output")]
        quiet: bool,

        #[arg(short, long, help = "Show detailed collector logs")]
        verbose: bool,
    },

    #[command(about = "Full intelligence gathering (runs all modules)")]
    Intel {
        #[arg(short, long, help = "Target domain")]
        domain: String,

        #[arg(short, long, help = "Organization name for broader search")]
        name: Option<String>,

        #[arg(short, long, help = "Output directory")]
        output: Option<String>,

        #[arg(short, long, value_delimiter = ',', help = "Report formats: html,json,csv")]
        format: Option<Vec<ReportFormat>>,

        #[arg(short = 'c', long, default_value = "10", help = "Max parallel collectors")]
        concurrency: usize,

        #[arg(short, long, default_value = "30", help = "Per-source timeout in seconds")]
        timeout: u64,

        #[arg(long, value_delimiter = ',', help = "Run only specific sources")]
        sources: Option<Vec<String>>,

        #[arg(long, value_delimiter = ',', help = "Exclude specific sources")]
        exclude: Option<Vec<String>>,

        #[arg(long, help = "Disable colored output")]
        no_color: bool,

        #[arg(short, long, help = "Suppress progress output")]
        quiet: bool,

        #[arg(short, long, help = "Show detailed collector logs")]
        verbose: bool,
    },

    #[command(about = "Generate reports from previous scan results")]
    Report {
        #[arg(short, long, help = "Input JSON file from previous scan")]
        input: String,

        #[arg(short, long, help = "Output directory")]
        output: Option<String>,

        #[arg(short, long, value_delimiter = ',', help = "Report formats: html,json,csv")]
        format: Option<Vec<ReportFormat>>,
    },

    #[command(about = "Manage API keys and settings")]
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
}

#[derive(Subcommand, Debug)]
pub enum ConfigAction {
    #[command(about = "Set an API key for a data source")]
    Set {
        #[arg(help = "Source name (e.g., shodan, virustotal)")]
        source: String,

        #[arg(help = "API key value")]
        key: String,
    },

    #[command(about = "Get the API key for a data source")]
    Get {
        #[arg(help = "Source name")]
        source: String,
    },

    #[command(about = "List all configured API keys (masked)")]
    List,

    #[command(about = "Show config file path")]
    Path,
}

#[derive(Debug, Clone, ValueEnum, PartialEq)]
pub enum ReportFormat {
    Html,
    Json,
    Csv,
}
