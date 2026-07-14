use std::path::{Path, PathBuf};

use crate::analyzers::risk_scorer::RiskScore;
use crate::analyzers::takeover_detector::TakeoverResult;
use crate::analyzers::diff_engine::DiffResult;
use crate::cli::ReportFormat;
use crate::error::Result;
use crate::models::Finding;
use crate::reports;

pub struct OutputWriter {
    output_dir: PathBuf,
    formats: Vec<ReportFormat>,
}

impl OutputWriter {
    pub fn new(output_dir: PathBuf, formats: Vec<ReportFormat>) -> Self {
        Self { output_dir, formats }
    }

    pub fn ensure_dir(&self) -> Result<()> {
        std::fs::create_dir_all(&self.output_dir)?;
        Ok(())
    }

    pub fn write_all(
        &self,
        findings: &[Finding],
        domain: &str,
        risk: &RiskScore,
        takeovers: &[TakeoverResult],
        diff: Option<&DiffResult>,
    ) -> Result<()> {
        self.ensure_dir()?;

        for format in &self.formats {
            match format {
                ReportFormat::Json => {
                    reports::json::generate(findings, &self.output_dir)?;
                }
                ReportFormat::Csv => {
                    reports::csv::generate(findings, &self.output_dir)?;
                }
                ReportFormat::Html => {
                    reports::html::generate(findings, domain, risk, &self.output_dir)?;
                }
                ReportFormat::Markdown => {
                    reports::markdown::generate(findings, domain, risk, takeovers, diff, &self.output_dir)?;
                }
            }
        }

        Ok(())
    }

    pub fn output_path(&self) -> &Path {
        &self.output_dir
    }
}
