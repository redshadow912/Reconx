use thiserror::Error;

#[derive(Error, Debug)]
pub enum ReconxError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("API key not configured for {collector}")]
    MissingApiKey { collector: String },

    #[error("Collector {name} failed: {reason}")]
    CollectorFailed { name: String, reason: String },

    #[error("Report generation failed: {0}")]
    ReportGeneration(String),

    #[error("DNS resolution failed: {0}")]
    DnsResolution(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("CSV error: {0}")]
    Csv(#[from] csv::Error),

    #[error("Template error: {0}")]
    Template(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, ReconxError>;
