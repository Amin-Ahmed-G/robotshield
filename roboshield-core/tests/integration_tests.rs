#[cfg(test)]
mod tests {
    use roboshield_core::config::SecurityPolicy;
    use roboshield_core::parser::{self, ParsedSubmessage};
    use roboshield_core::detector::{AnomalyType, DetectionEngine};
    use std::fs;
    use std::io::Write;

    #[test]
    fn test_policy_load() {
        let policy_content = r#"
            allowed_guid_prefixes = [
                "01:0f:a5:bc:de:f0:12:34:56:78:90:ab"
            ]
            [topic_publishers]
            "/cmd_vel" = ["01:0f:a5:bc:de:f0:12:34:56:78:90:ab"]
            [frequency_limits]
            "/cmd_vel" = { min_hz = 1.0, max_hz = 60.0 }
        "#;

        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        write!(temp_file, "{}", policy_content).unwrap();

        let policy = SecurityPolicy::load_from_file(temp_file.path()).unwrap();
        assert!(policy.is_guid_prefix_allowed("01:0f:a5:bc:de:f0:12:34:56:78:90:ab"));
        assert!(!policy.is_guid_prefix_allowed("ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff"));
        assert!(policy.is_publisher_authorized("/cmd_vel", "01:0f:a5:bc:de:f0:12:34:56:78:90:ab"));
    }

    #[test]
    fn test_rtps_parser_data() {
        // Build a mock packet representation using the binary format parsed by parser.rs
        // Header: Magic "RTPS" (4) + Version 2.3 (2) + Vendor 01:0f (2) + GUID Prefix (12)
        // Submsg: ID 0x15 (1) + Flags 0x05 (1) + Len (2) + Body payload
        let mut mock_payload = Vec::new();
        mock_payload.extend_from_slice(b"RTPS");
        mock_payload.extend_from_slice(&[2, 3, 0x01, 0x0f]);
        let guid = [0x01, 0x0f, 0xa5, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab];
        mock_payload.extend_from_slice(&guid);

        // Append mock DATA submessage header: ID=0x15, Flags=0x05 (LE, Data present), Length=24
        mock_payload.push(0x15);
        mock_payload.push(0x05);
        mock_payload.extend_from_slice(&[24, 0x00]); // Little Endian length

        // DATA payload: flags(2), inline_qos_offset(2), reader_id(4), writer_id(4), seq_num(8), data encapsulation(4)
        mock_payload.extend_from_slice(&[0x00, 0x00]);
        mock_payload.extend_from_slice(&[0x00, 0x00]);
        mock_payload.extend_from_slice(&[0x00, 0x00, 0x01, 0xc1]); // reader
        mock_payload.extend_from_slice(&[0x00, 0x00, 0x01, 0x02]); // writer
        mock_payload.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // seq = 1
        
        // CDR/PL encapsulation containing dummy bytes
        mock_payload.extend_from_slice(&[0x00, 0x03, 0x00, 0x00]);

        let parsed = parser::parse_rtps_packet(&mock_payload).unwrap();
        assert_eq!(parsed.header.guid_prefix, guid);
        assert_eq!(parsed.submessages.len(), 1);
        match &parsed.submessages[0] {
            ParsedSubmessage::Data(data) => {
                assert_eq!(data.writer_seq_number, 1);
            }
            _ => panic!("Expected parsed submessage to be DATA"),
        }
    }

    #[test]
    fn test_detection_engine() {
        let policy_content = r#"
            allowed_guid_prefixes = [
                "01:0f:a5:bc:de:f0:12:34:56:78:90:ab"
            ]
            [topic_publishers]
            "/cmd_vel" = ["01:0f:a5:bc:de:f0:12:34:56:78:90:ab"]
            [frequency_limits]
            "/cmd_vel" = { min_hz = 1.0, max_hz = 60.0 }
        "#;

        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        write!(temp_file, "{}", policy_content).unwrap();

        let policy = SecurityPolicy::load_from_file(temp_file.path()).unwrap();
        let mut detector = DetectionEngine::new(policy);

        // 1. Authorized message test
        let mut mock_payload = Vec::new();
        mock_payload.extend_from_slice(b"RTPS");
        mock_payload.extend_from_slice(&[2, 3, 0x01, 0x0f]);
        let auth_guid = [0x01, 0x0f, 0xa5, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab];
        mock_payload.extend_from_slice(&auth_guid);

        // Add submessage DATA representing topic /cmd_vel
        mock_payload.push(0x15);
        mock_payload.push(0x05); // Data present
        mock_payload.extend_from_slice(&[44, 0x00]); // length (44 bytes payload)
        
        mock_payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // extra flags, inline qos
        mock_payload.extend_from_slice(&[0x00, 0x00, 0x01, 0xc1]); // reader
        mock_payload.extend_from_slice(&[0x00, 0x00, 0x01, 0x02]); // writer
        mock_payload.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // seq = 1
        mock_payload.extend_from_slice(&[0x00, 0x03, 0x00, 0x00]); // PL_CDR_LE

        // PID_TOPIC_NAME = 0x0005, Len=13
        mock_payload.extend_from_slice(&[0x05, 0x00, 0x0d, 0x00]); 
        mock_payload.extend_from_slice(&[0x09, 0x00, 0x00, 0x00]); // Str length = 9 (including null)
        mock_payload.extend_from_slice(b"/cmd_vel\0"); // topic name + null
        mock_payload.extend_from_slice(&[0x00, 0x00, 0x00]); // alignment padding
        mock_payload.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // PID_SENTINEL

        let msg = parser::parse_rtps_packet(&mock_payload).unwrap();
        let anomalies = detector.analyze_message(&msg);
        assert!(anomalies.is_empty());

        // 2. Unauthorized GUID test
        let mut unauth_payload = Vec::new();
        unauth_payload.extend_from_slice(b"RTPS");
        unauth_payload.extend_from_slice(&[2, 3, 0x01, 0x0f]);
        let unauth_guid = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        unauth_payload.extend_from_slice(&unauth_guid);
        
        let unauth_msg = parser::parse_rtps_packet(&unauth_payload).unwrap();
        let anomalies = detector.analyze_message(&unauth_msg);
        assert_eq!(anomalies.len(), 1);
        assert_eq!(anomalies[0].anomaly_type, AnomalyType::UnauthorizedGuidPrefix);
    }
}
