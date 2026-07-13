use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize, Clone)]
pub struct FrequencyLimit {
    pub min_hz: f64,
    pub max_hz: f64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SecurityPolicy {
    pub allowed_guid_prefixes: Vec<String>,
    pub topic_publishers: HashMap<String, Vec<String>>,
    pub frequency_limits: HashMap<String, FrequencyLimit>,
}

impl SecurityPolicy {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let policy: SecurityPolicy = toml::from_str(&content)?;
        Ok(policy)
    }

    pub fn is_guid_prefix_allowed(&self, guid_prefix: &str) -> bool {
        self.allowed_guid_prefixes.iter().any(|prefix| prefix.eq_ignore_ascii_case(guid_prefix))
    }

    pub fn is_publisher_authorized(&self, topic: &str, guid_prefix: &str) -> bool {
        if let Some(authorized_prefixes) = self.topic_publishers.get(topic) {
            authorized_prefixes.iter().any(|prefix| prefix.eq_ignore_ascii_case(guid_prefix))
        } else {
            // If topic is not restricted, allow
            true
        }
    }
}
