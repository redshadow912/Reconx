use crate::error::{ReconxError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub api_keys: HashMap<String, String>,

    #[serde(default = "default_concurrency")]
    pub concurrency: usize,

    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,

    #[serde(default)]
    pub output_dir: Option<String>,
}

fn default_concurrency() -> usize {
    10
}

fn default_timeout() -> u64 {
    30
}

impl Config {
    pub fn load() -> Result<Self> {
        let config_path = Self::config_path()?;

        if config_path.exists() {
            let content = std::fs::read_to_string(&config_path)?;
            let config: Config = toml::from_str(&content)
                .map_err(|e| ReconxError::Config(format!("Failed to parse config: {}", e)))?;
            Ok(config)
        } else {
            Ok(Config::default())
        }
    }

    pub fn save(&self) -> Result<()> {
        let config_path = Self::config_path()?;

        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let content = toml::to_string_pretty(self)
            .map_err(|e| ReconxError::Config(format!("Failed to serialize config: {}", e)))?;
        std::fs::write(&config_path, content)?;
        Ok(())
    }

    pub fn get_api_key(&self, source: &str) -> Option<&String> {
        self.api_keys.get(source)
    }

    pub fn set_api_key(&mut self, source: String, key: String) {
        self.api_keys.insert(source, key);
    }

    fn config_path() -> Result<PathBuf> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| ReconxError::Config("Could not determine config directory".into()))?;
        Ok(config_dir.join("reconx").join("config.toml"))
    }
}
