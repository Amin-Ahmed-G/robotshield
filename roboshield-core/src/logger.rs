use crate::detector::SecurityAnomaly;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Debug, Serialize)]
pub struct JsonAlert {
    pub timestamp: String,
    pub anomaly_type: String,
    pub description: String,
    pub guid_prefix: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub measured_value: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold_value: Option<f64>,
}

#[derive(Clone)]
pub struct SecurityLogger {
    file_path: PathBuf,
    // Thread-safe handles to prevent log interleaving
    lock: Arc<Mutex<()>>,
}

impl SecurityLogger {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            file_path: path.as_ref().to_path_buf(),
            lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn log_anomaly(&self, anomaly: &SecurityAnomaly) {
        let timestamp: DateTime<Utc> = Utc::now();
        let alert = JsonAlert {
            timestamp: timestamp.to_rfc3339(),
            anomaly_type: anomaly.anomaly_type.as_str().to_string(),
            description: anomaly.description.clone(),
            guid_prefix: anomaly.guid_prefix.clone(),
            topic: anomaly.topic.clone(),
            measured_value: anomaly.measured_value,
            threshold_value: anomaly.threshold_value,
        };

        if let Ok(json_str) = serde_json::to_string(&alert) {
            // Write payload synchronously to prevent file races
            let _guard = self.lock.lock().unwrap();
            if let Ok(mut file) = OpenOptions::new()
                .create(true)
                .write(true)
                .append(true)
                .open(&self.file_path)
            {
                let _ = writeln!(file, "{}", json_str);
            }
        }
    }
}
