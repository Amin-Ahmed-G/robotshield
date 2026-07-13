use roboshield_core::config::SecurityPolicy;
use roboshield_core::detector::DetectionEngine;
use roboshield_core::logger::SecurityLogger;
use roboshield_core::parser;
use pcap::{Capture, Linktype};
use std::env;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    log::info!("=========================================");
    log::info!("RoboShield RTPS Security Watchdog Starting");
    log::info!("=========================================");

    let args: Vec<String> = env::args().collect();
    
    // Default configs
    let mut config_path = "config/policies.toml".to_string();
    let mut pcap_file: Option<String> = None;
    let mut interface_name: Option<String> = None;
    let log_file = "alerts.json".to_string();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" | "-c" => {
                if i + 1 < args.len() {
                    config_path = args[i + 1].clone();
                    i += 2;
                } else {
                    return Err("Missing argument for --config".into());
                }
            }
            "--pcap" | "-p" => {
                if i + 1 < args.len() {
                    pcap_file = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    return Err("Missing argument for --pcap".into());
                }
            }
            "--interface" | "-i" => {
                if i + 1 < args.len() {
                    interface_name = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    return Err("Missing argument for --interface".into());
                }
            }
            _ => {
                println!("Usage: roboshield-core [options]");
                println!("Options:");
                println!("  -c, --config <file>     Path to policies.toml configuration file");
                println!("  -p, --pcap <file>       Read packets from local .pcap capture file");
                println!("  -i, --interface <name>  Sniff live traffic from the specified network interface");
                return Ok(());
            }
        }
    }

    if !Path::new(&config_path).exists() {
        log::error!("Policy configuration file not found at: {}", config_path);
        log::info!("Please ensure config/policies.toml is present or specify a custom path using --config");
        return Err("Configuration file not found".into());
    }

    log::info!("Loading security policies from: {}", config_path);
    let policy = SecurityPolicy::load_from_file(&config_path)?;
    log::info!("Successfully loaded {} GUID prefixes", policy.allowed_guid_prefixes.len());

    let mut detector = DetectionEngine::new(policy);
    let logger = SecurityLogger::new(&log_file);
    log::info!("JSON alerts logger output target: {}", log_file);

    if let Some(ref pcap_path) = pcap_file {
        log::info!("Reading offline packets from pcap file: {}", pcap_path);
        let mut cap = Capture::from_file(pcap_path)?;
        process_loop(&mut cap, &mut detector, &logger)?;
    } else {
        let interface = match interface_name {
            Some(name) => name,
            None => {
                log::warn!("No interface or pcap file specified. Defaulting to loopback ('lo') interface.");
                "lo".to_string()
            }
        };

        let mut cap = Capture::from_device(interface.as_str())?
            .promisc(true)
            .snaplen(65535)
            .timeout(1000)
            .open()?;

        process_loop(&mut cap, &mut detector, &logger)?;
    }

    log::info!("RoboShield Watchdog stopped.");
    Ok(())
}

fn process_loop<T: pcap::Activated>(
    cap: &mut Capture<T>,
    detector: &mut DetectionEngine,
    logger: &SecurityLogger,
) -> Result<(), Box<dyn std::error::Error>> {
    let datalink = cap.get_datalink();
    
    log::info!("Packet sniffing loop started. Press Ctrl+C to exit.");
    loop {
        match cap.next_packet() {
            Ok(packet) => {
                if let Some(udp_payload) = extract_udp_payload(packet.data, datalink) {
                    if let Ok(rtps_msg) = parser::parse_rtps_packet(udp_payload) {
                        let anomalies = detector.analyze_message(&rtps_msg);
                        for anomaly in anomalies {
                            log::warn!("[NIDS ALERT] [{}] {}", anomaly.anomaly_type.as_str(), anomaly.description);
                            logger.log_anomaly(&anomaly);
                        }
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                // Live capture timeout, continue sniffing
                continue;
            }
            Err(pcap::Error::NoMorePackets) => {
                // Offline PCAP file finished
                log::info!("Reached end of PCAP file.");
                break;
            }
            Err(e) => {
                log::error!("PCAP Capture loop error: {:?}", e);
                break;
            }
        }
    }
    Ok(())
}

/// Helper function to extract UDP payload based on link type
fn extract_udp_payload(packet_data: &[u8], datalink: Linktype) -> Option<&[u8]> {
    let ip_offset = match datalink {
        Linktype::ETHERNET => 14,
        Linktype::NULL => 4, // Loopback null encapsulation on BSD/Mac
        Linktype::RAW => 0,
        _ => 14, // Default to Ethernet
    };

    if packet_data.len() < ip_offset + 20 {
        return None;
    }

    let ip_header = &packet_data[ip_offset..];
    let ip_version = ip_header[0] >> 4;

    if ip_version == 4 {
        // IPv4 Header
        let ip_proto = ip_header[9];
        let ihl = (ip_header[0] & 0x0F) as usize * 4;
        
        if ip_proto == 17 { // UDP
            let udp_header = &ip_header[ihl..];
            if udp_header.len() >= 8 {
                let payload = &udp_header[8..];
                return Some(payload);
            }
        }
    } else if ip_version == 6 {
        // IPv6 Header
        let ip_proto = ip_header[6];
        if ip_proto == 17 { // UDP
            let udp_header = &ip_header[40..];
            if udp_header.len() >= 8 {
                let payload = &udp_header[8..];
                return Some(payload);
            }
        }
    }

    None
}
