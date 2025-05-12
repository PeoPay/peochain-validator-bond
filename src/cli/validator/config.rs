use serde::{Deserialize, Serialize};
use std::{fs, io, path::PathBuf};

/// Configuration for the validator CLI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Default node URL
    pub default_node_url: Option<String>,
    /// Default keys directory
    pub default_keys_dir: Option<PathBuf>,
    /// Minimum bond amount
    pub minimum_bond: u128,
    /// Default timelock period in blocks
    pub default_timelock_period: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            default_node_url: Some("ws://127.0.0.1:9944".to_string()),
            default_keys_dir: Some(dirs::home_dir().unwrap_or_default().join(".peochain").join("validator")),
            minimum_bond: 1000,
            default_timelock_period: 14400, // ~1 day with 6-second blocks
        }
    }
}

impl Config {
    /// Load configuration from file
    pub fn load() -> Result<Self, io::Error> {
        let config_dir = dirs::config_dir()
            .unwrap_or_default()
            .join("peochain")
            .join("validator");
            
        let config_path = config_dir.join("config.toml");
        
        if !config_path.exists() {
            // Create default config if it doesn't exist
            fs::create_dir_all(&config_dir)?;
            let default_config = Self::default();
            let toml = toml::to_string_pretty(&default_config)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            fs::write(&config_path, toml)?;
            return Ok(default_config);
        }
        
        // Load existing config
        let config_str = fs::read_to_string(&config_path)?;
        let config = toml::from_str::<Config>(&config_str)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            
        Ok(config)
    }
    
    /// Save configuration to file
    pub fn save(&self) -> Result<(), io::Error> {
        let config_dir = dirs::config_dir()
            .unwrap_or_default()
            .join("peochain")
            .join("validator");
            
        let config_path = config_dir.join("config.toml");
        
        fs::create_dir_all(&config_dir)?;
        let toml = toml::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        fs::write(&config_path, toml)?;
        
        Ok(())
    }
}
