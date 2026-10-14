//! Gateway configuration. Reads the same `firewall_params.yaml` as the Python
//! firewall (`firewall_gateway: ros__parameters: ...`), so deployments can
//! switch implementation without touching config. Configuration only ever
//! comes from this file and the command line, never from the network.

use std::collections::HashMap;
use std::path::Path;

use fw_core::{FirewallConfig, JointLimits};
use serde::Deserialize;

fn default_joints() -> Vec<String> {
    ["joint_1", "joint_2", "joint_3", "joint_4"].map(String::from).to_vec()
}

/// Per-joint override; missing fields fall back to the global limits.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointOverride {
    pub position_min: Option<f64>,
    pub position_max: Option<f64>,
    pub velocity: Option<f64>,
    pub effort: Option<f64>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Params {
    pub joint_names: Vec<String>,
    pub position_min: f64,
    pub position_max: f64,
    /// Negative = disabled.
    pub velocity_limit: f64,
    /// Negative = disabled.
    pub effort_limit: f64,
    pub limits: HashMap<String, JointOverride>,

    pub limit_action: String,
    pub max_step: f64,
    pub max_rate_hz: f64,
    pub burst: f64,
    pub max_age_s: f64,
    pub max_future_s: f64,
    pub require_stamp: bool,
    pub lockdown_threshold: usize,
    pub lockdown_window_s: f64,
    pub report_interval_s: f64,
    pub start_locked: bool,
    pub state_margin: f64,
    pub state_timeout_s: f64,
    pub expected_state_publishers: usize,

    pub command_topic: String,
    pub state_topic: String,
    pub output_topic: String,
    /// "joint_state" or "float64_multi_array".
    pub output_type: String,

    /// Node names allowed to publish commands on the untrusted side ('' = any).
    pub allowed_publishers: Vec<String>,
    /// Python gateway only (it cannot attribute individual messages). The Rust
    /// gateway drops unauthorized messages individually; set true to also
    /// lock down whenever an unauthorized publisher appears.
    pub unauthorized_lockdown: bool,

    pub input_queue_depth: u32,
    pub hold_rate_hz: f64,
    pub watch_period_s: f64,
    pub incident_log_path: String,
    pub nft_counters_file: String,
    pub hardware_id: String,
    /// SIEM export target, e.g. udp://10.0.0.5:514 ('' = disabled).
    pub siem_syslog: String,
    /// "cef" (Splunk, Sentinel, QRadar, ArcSight) or "json" (Elastic).
    pub siem_format: String,
}

impl Default for Params {
    fn default() -> Self {
        Self {
            joint_names: default_joints(),
            position_min: -1.0,
            position_max: 1.0,
            velocity_limit: 1.0,
            effort_limit: -1.0,
            limits: HashMap::new(),
            limit_action: "clamp".into(),
            max_step: 0.2,
            max_rate_hz: 50.0,
            burst: 10.0,
            max_age_s: 0.5,
            max_future_s: 0.2,
            require_stamp: true,
            lockdown_threshold: 20,
            lockdown_window_s: 2.0,
            report_interval_s: 1.0,
            start_locked: true,
            state_margin: 0.05,
            state_timeout_s: 0.5,
            expected_state_publishers: 1,
            command_topic: "joint_commands".into(),
            state_topic: "joint_states".into(),
            output_topic: "joint_commands".into(),
            output_type: "joint_state".into(),
            allowed_publishers: Vec::new(),
            unauthorized_lockdown: false,
            input_queue_depth: 100,
            hold_rate_hz: 10.0,
            watch_period_s: 1.0,
            incident_log_path: String::new(),
            nft_counters_file: String::new(),
            hardware_id: String::new(),
            siem_syslog: String::new(),
            siem_format: "cef".into(),
        }
    }
}

impl Params {
    /// Load from a ROS params YAML (`firewall_gateway.ros__parameters`) or a
    /// flat YAML map, then apply `key=value` overrides.
    pub fn load(path: Option<&Path>, overrides: &[String]) -> Result<Self, String> {
        let mut value = match path {
            Some(p) => {
                let text = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
                let doc: serde_yaml::Value = serde_yaml::from_str(&text).map_err(|e| format!("{}: {e}", p.display()))?;
                match doc.get("firewall_gateway").and_then(|n| n.get("ros__parameters")) {
                    Some(inner) => inner.clone(),
                    None => doc,
                }
            }
            None => serde_yaml::Value::Mapping(Default::default()),
        };
        if value.is_null() {
            value = serde_yaml::Value::Mapping(Default::default());
        }
        for kv in overrides {
            let (key, raw) = kv.split_once('=').ok_or_else(|| format!("--set expects key=value, got {kv:?}"))?;
            let parsed: serde_yaml::Value = serde_yaml::from_str(raw).unwrap_or(serde_yaml::Value::String(raw.into()));
            value
                .as_mapping_mut()
                .ok_or("config root must be a mapping")?
                .insert(serde_yaml::Value::String(key.into()), parsed);
        }
        let mut params: Params = serde_yaml::from_value(value).map_err(|e| format!("invalid config: {e}"))?;
        params.allowed_publishers.retain(|n| !n.is_empty());
        params.validate()?;
        Ok(params)
    }

    fn validate(&self) -> Result<(), String> {
        if self.joint_names.is_empty() {
            return Err("joint_names must not be empty".into());
        }
        if !matches!(self.limit_action.as_str(), "clamp" | "drop") {
            return Err("limit_action must be 'clamp' or 'drop'".into());
        }
        if !matches!(self.output_type.as_str(), "joint_state" | "float64_multi_array") {
            return Err("output_type must be 'joint_state' or 'float64_multi_array'".into());
        }
        if let Some(unknown) = self.limits.keys().find(|j| !self.joint_names.contains(j)) {
            return Err(format!("limits.{unknown}: not in joint_names"));
        }
        if !matches!(self.siem_format.as_str(), "cef" | "json") {
            return Err("siem_format must be 'cef' or 'json'".into());
        }
        if !self.siem_syslog.is_empty() && !self.siem_syslog.starts_with("udp://") {
            return Err("siem_syslog must look like udp://host:514".into());
        }
        if self.max_rate_hz <= 0.0 || self.hold_rate_hz <= 0.0 || self.watch_period_s <= 0.0 {
            return Err("rates and periods must be positive".into());
        }
        Ok(())
    }

    pub fn firewall_config(&self) -> FirewallConfig {
        let disabled_if_negative = |v: f64| if v < 0.0 { f64::INFINITY } else { v };
        let limits = self
            .joint_names
            .iter()
            .map(|joint| {
                let o = self.limits.get(joint).cloned().unwrap_or_default();
                let lim = JointLimits {
                    position_min: o.position_min.unwrap_or(self.position_min),
                    position_max: o.position_max.unwrap_or(self.position_max),
                    velocity: disabled_if_negative(o.velocity.unwrap_or(self.velocity_limit)),
                    effort: disabled_if_negative(o.effort.unwrap_or(self.effort_limit)),
                };
                (joint.clone(), lim)
            })
            .collect();
        let mut cfg = FirewallConfig::new(self.joint_names.clone());
        cfg.limits = limits;
        cfg.max_step = self.max_step;
        cfg.max_rate_hz = self.max_rate_hz;
        cfg.burst = self.burst;
        cfg.max_age_s = self.max_age_s;
        cfg.max_future_s = self.max_future_s;
        cfg.require_stamp = self.require_stamp;
        cfg.limit_action = self.limit_action.clone();
        cfg.lockdown_threshold = self.lockdown_threshold;
        cfg.lockdown_window_s = self.lockdown_window_s;
        cfg.report_interval_s = self.report_interval_s;
        cfg.state_margin = self.state_margin;
        cfg.state_timeout_s = self.state_timeout_s;
        cfg.start_locked = self.start_locked;
        cfg
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_the_shared_python_params_file() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../src/monitor_py/config/firewall_params.yaml");
        let p = Params::load(Some(&path), &[]).unwrap();
        assert_eq!(p.joint_names.len(), 4);
        assert_eq!(p.allowed_publishers, vec!["attack_sim_node"]);
        let cfg = p.firewall_config();
        assert!(cfg.limits["joint_1"].effort.is_infinite());
        assert_eq!(cfg.limits["joint_1"].position_max, 1.0);
    }

    #[test]
    fn overrides_and_per_joint_limits() {
        let p = Params::load(None, &[
            "joint_names=[a, b]".into(),
            "limits={b: {position_max: 2.5}}".into(),
            "incident_log_path=/tmp/x.jsonl".into(),
        ])
        .unwrap();
        let cfg = p.firewall_config();
        assert_eq!(cfg.limits["a"].position_max, 1.0);
        assert_eq!(cfg.limits["b"].position_max, 2.5);
        assert_eq!(p.incident_log_path, "/tmp/x.jsonl");
    }

    #[test]
    fn rejects_bad_values() {
        assert!(Params::load(None, &["limit_action=explode".into()]).is_err());
        assert!(Params::load(None, &["no_such_param=1".into()]).is_err());
        assert!(Params::load(None, &["limits={ghost: {velocity: 1.0}}".into()]).is_err());
    }
}
