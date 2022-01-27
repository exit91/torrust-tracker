pub use crate::tracker::TrackerMode;
use config::{Config, ConfigError, File};
use serde::{Deserialize, Serialize, Serializer};
use std;
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;
use toml;

#[derive(Serialize, Deserialize)]
pub struct UdpTrackerConfig {
    pub bind_address: String,
    pub announce_interval: u32,
}

#[derive(Serialize, Deserialize)]
pub struct HttpTrackerConfig {
    pub enabled: bool,
    pub bind_address: String,
    pub announce_interval: u32,
    pub ssl_enabled: bool,
    #[serde(serialize_with = "none_as_empty_string")]
    pub ssl_cert_path: Option<String>,
    #[serde(serialize_with = "none_as_empty_string")]
    pub ssl_key_path: Option<String>,
}

impl HttpTrackerConfig {
    pub fn is_ssl_enabled(&self) -> bool {
        self.ssl_enabled && self.ssl_cert_path.is_some() && self.ssl_key_path.is_some()
    }
}

#[derive(Serialize, Deserialize)]
pub struct HttpApiConfig {
    pub enabled: bool,
    pub bind_address: String,
    pub access_tokens: HashMap<String, String>,
}

#[derive(Deserialize, Serialize, Copy, Clone, Debug)]
pub enum LogLevel {
    #[serde(rename = "off")]
    Off,
    #[serde(rename = "trace")]
    Trace,
    #[serde(rename = "debug")]
    Debug,
    #[serde(rename = "info")]
    Info,
    #[serde(rename = "warn")]
    Warn,
    #[serde(rename = "error")]
    Error,
}

impl Into<log::LevelFilter> for LogLevel {
    fn into(self) -> log::LevelFilter {
        match self {
            LogLevel::Off => log::LevelFilter::Off,
            LogLevel::Trace => log::LevelFilter::Trace,
            LogLevel::Debug => log::LevelFilter::Debug,
            LogLevel::Info => log::LevelFilter::Info,
            LogLevel::Warn => log::LevelFilter::Warn,
            LogLevel::Error => log::LevelFilter::Error,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Configuration {
    pub log_level: Option<LogLevel>,
    pub mode: TrackerMode,
    pub db_path: String,
    pub cleanup_interval: Option<u64>,
    pub external_ip: Option<String>,
    pub udp_tracker: UdpTrackerConfig,
    pub http_tracker: Option<HttpTrackerConfig>,
    pub http_api: Option<HttpApiConfig>,
}

#[derive(Debug)]
pub enum ConfigurationError {
    IOError(std::io::Error),
    ParseError(toml::de::Error),
}

impl std::fmt::Display for ConfigurationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ConfigurationError::IOError(e) => e.fmt(formatter),
            ConfigurationError::ParseError(e) => e.fmt(formatter),
        }
    }
}

impl std::error::Error for ConfigurationError {}

pub fn none_as_empty_string<T, S>(option: &Option<T>, serializer: S) -> Result<S::Ok, S::Error>
where
    T: Serialize,
    S: Serializer,
{
    if let Some(value) = option {
        value.serialize(serializer)
    } else {
        "".serialize(serializer)
    }
}

impl Configuration {
    pub fn load(data: &[u8]) -> Result<Configuration, toml::de::Error> {
        toml::from_slice(data)
    }

    pub fn load_file(path: &str) -> Result<Configuration, ConfigurationError> {
        match std::fs::read(path) {
            Err(e) => Err(ConfigurationError::IOError(e)),
            Ok(data) => match Self::load(data.as_slice()) {
                Ok(cfg) => Ok(cfg),
                Err(e) => Err(ConfigurationError::ParseError(e)),
            },
        }
    }

    pub fn get_ext_ip(&self) -> Option<IpAddr> {
        match &self.external_ip {
            None => None,
            Some(external_ip) => match IpAddr::from_str(external_ip) {
                Ok(external_ip) => Some(external_ip),
                Err(_) => None,
            },
        }
    }
}

impl Configuration {
    pub fn default() -> Configuration {
        Configuration {
            log_level: Some(LogLevel::Info),
            mode: TrackerMode::PublicMode,
            db_path: String::from("data.db"),
            cleanup_interval: Some(600),
            external_ip: Some(String::from("0.0.0.0")),
            udp_tracker: UdpTrackerConfig {
                bind_address: String::from("0.0.0.0:6969"),
                announce_interval: 120,
            },
            http_tracker: Option::from(HttpTrackerConfig {
                enabled: false,
                bind_address: String::from("0.0.0.0:7878"),
                announce_interval: 120,
                ssl_enabled: false,
                ssl_cert_path: None,
                ssl_key_path: None,
            }),
            http_api: Option::from(HttpApiConfig {
                enabled: true,
                bind_address: String::from("127.0.0.1:1212"),
                access_tokens: [(String::from("admin"), String::from("MyAccessToken"))]
                    .iter()
                    .cloned()
                    .collect(),
            }),
        }
    }

    pub fn load_from_file() -> Result<Configuration, ConfigError> {
        let mut config = Config::new();

        const CONFIG_PATH: &str = "config.toml";

        if Path::new(CONFIG_PATH).exists() {
            config.merge(File::with_name(CONFIG_PATH))?;
        } else {
            eprintln!("No config file found.");
            eprintln!("Creating config file..");
            let config = Configuration::default();
            let _ = config.save_to_file();
            return Err(ConfigError::Message(format!(
                "Please edit the config.TOML in the root folder and restart the tracker."
            )));
        }

        match config.try_into() {
            Ok(data) => Ok(data),
            Err(e) => Err(ConfigError::Message(format!(
                "Errors while processing config: {}.",
                e
            ))),
        }
    }

    pub fn save_to_file(&self) -> Result<(), ()> {
        let toml_string = toml::to_string(self).expect("Could not encode TOML value");
        fs::write("config.toml", toml_string).expect("Could not write to file!");
        Ok(())
    }
}
