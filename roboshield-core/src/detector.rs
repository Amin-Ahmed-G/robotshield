use crate::config::SecurityPolicy;
use crate::parser::{ParsedSubmessage, RtpsMessage};
use std::collections::{HashMap, VecDeque};
use std::time::Instant;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnomalyType {
    UnauthorizedGuidPrefix,
    UnauthorizedTopicPublisher,
    TopicFrequencyFlood,
    ProtocolViolation,
}

impl AnomalyType {
    pub fn as_str(&self) -> &'static str {
        match self {
            AnomalyType::UnauthorizedGuidPrefix => "UNAUTHORIZED_GUID_PREFIX",
            AnomalyType::UnauthorizedTopicPublisher => "UNAUTHORIZED_TOPIC_PUBLISHER",
            AnomalyType::TopicFrequencyFlood => "TOPIC_FREQUENCY_FLOOD",
            AnomalyType::ProtocolViolation => "PROTOCOL_VIOLATION",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SecurityAnomaly {
    pub anomaly_type: AnomalyType,
    pub description: String,
    pub guid_prefix: String,
    pub topic: Option<String>,
    pub measured_value: Option<f64>,
    pub threshold_value: Option<f64>,
}

pub struct DetectionEngine {
    policy: SecurityPolicy,
    // Tracks message timestamps per topic to evaluate frequency limits
    // Map of topic -> deque of message receipt instants
    topic_timestamps: HashMap<String, VecDeque<Instant>>,
}

impl DetectionEngine {
    pub fn new(policy: SecurityPolicy) -> Self {
        Self {
            policy,
            topic_timestamps: HashMap::new(),
        }
    }

    /// Evaluates a parsed RTPS message against safety and security rules.
    /// Returns a list of anomalies found.
    pub fn analyze_message(&mut self, message: &RtpsMessage) -> Vec<SecurityAnomaly> {
        let mut anomalies = Vec::new();
        let guid_prefix_str = message.header.guid_prefix_str();

        // 1. Verify Guid Prefix Whitelist
        if !self.policy.is_guid_prefix_allowed(&guid_prefix_str) {
            anomalies.push(SecurityAnomaly {
                anomaly_type: AnomalyType::UnauthorizedGuidPrefix,
                description: format!("DDS Participant GUID prefix '{}' is not whitelisted", guid_prefix_str),
                guid_prefix: guid_prefix_str.clone(),
                topic: None,
                measured_value: None,
                threshold_value: None,
            });
        }

        // Parse submessages
        for submsg in &message.submessages {
            match submsg {
                ParsedSubmessage::Data(data_sub) => {
                    if let Some(ref topic) = data_sub.topic_name {
                        // 2. Verify Publisher Authorization for this Topic
                        if !self.policy.is_publisher_authorized(topic, &guid_prefix_str) {
                            anomalies.push(SecurityAnomaly {
                                anomaly_type: AnomalyType::UnauthorizedTopicPublisher,
                                description: format!(
                                    "Participant '{}' is not authorized to publish on topic '{}'",
                                    guid_prefix_str, topic
                                ),
                                guid_prefix: guid_prefix_str.clone(),
                                topic: Some(topic.clone()),
                                measured_value: None,
                                threshold_value: None,
                            });
                        }

                        // 3. Track Frequency & Flood Check
                        if let Some(anomaly) = self.track_and_check_frequency(topic, &guid_prefix_str) {
                            anomalies.push(anomaly);
                        }
                    }
                }
                _ => {}
            }
        }

        anomalies
    }

    fn track_and_check_frequency(&mut self, topic: &str, guid_prefix: &str) -> Option<SecurityAnomaly> {
        let limits = self.policy.frequency_limits.get(topic)?;
        let now = Instant::now();
        let timestamps = self.topic_timestamps.entry(topic.to_string()).or_insert_with(VecDeque::new);

        timestamps.push_back(now);

        // Keep a 1-second sliding window
        while let Some(&first) = timestamps.front() {
            if now.duration_since(first).as_secs_f64() > 1.0 {
                timestamps.pop_front();
            } else {
                break;
            }
        }

        // We need at least 5 messages to make a reliable estimate of frequency
        if timestamps.len() < 5 {
            return None;
        }

        let duration = now.duration_since(*timestamps.front().unwrap()).as_secs_f64();
        if duration <= 0.05 {
            return None;
        }

        let calculated_hz = (timestamps.len() - 1) as f64 / duration;

        if calculated_hz > limits.max_hz {
            Some(SecurityAnomaly {
                anomaly_type: AnomalyType::TopicFrequencyFlood,
                description: format!(
                    "Topic '{}' frequency breach: {:.2} Hz (limit is {:.2} Hz)",
                    topic, calculated_hz, limits.max_hz
                ),
                guid_prefix: guid_prefix.to_string(),
                topic: Some(topic.to_string()),
                measured_value: Some(calculated_hz),
                threshold_value: Some(limits.max_hz),
            })
        } else {
            None
        }
    }
}
