mod rtps_builder;

use clap::Parser;
use rtps_builder::RtpsMessageBuilder;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{SocketAddr, UdpSocket};
use std::thread;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(name = "roboshield-simulator", about = "Synthetic RTPS Traffic Generator and Intrusion Injector")]
struct Args {
    /// Operation mode: normal, flood, spoof
    #[arg(short, long, default_value = "normal")]
    mode: String,

    /// Destination port
    #[arg(short, long, default_value_t = 7412)]
    port: u16,

    /// Broadcast interface/IP address
    #[arg(short, long, default_value = "127.0.0.1")]
    address: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    println!("=========================================");
    println!("RoboShield RTPS Traffic Simulator Starting");
    println!("Mode        : {}", args.mode);
    println!("Target Host : {}:{}", args.address, args.port);
    println!("=========================================");

    // Whitelisted GUID prefix from config/policies.toml
    let authorized_guid: [u8; 12] = [
        0x01, 0x0f, 0xa5, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab
    ];

    // Unauthorized rogue GUID prefix (triggers alert)
    let unauthorized_guid: [u8; 12] = [
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55
    ];

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    let socket: UdpSocket = socket.into();

    let dest_addr: SocketAddr = format!("{}:{}", args.address, args.port).parse()?;

    let mut seq: i64 = 1;

    match args.mode.as_str() {
        "normal" => {
            println!("Sending authorized RTPS telemetry (10 Hz) to {dest_addr}...");
            let builder = RtpsMessageBuilder::new(authorized_guid, true);

            loop {
                // Topic: "/cmd_vel"
                let packet = builder.build_data_msg("/cmd_vel", seq);
                socket.send_to(&packet, dest_addr)?;

                seq += 1;
                thread::sleep(Duration::from_millis(100)); // 10 Hz
            }
        }
        "flood" => {
            println!("Sending high-rate RTPS data flood (> 100 Hz)...");
            let builder = RtpsMessageBuilder::new(authorized_guid, true);

            loop {
                // Topic: "/cmd_vel"
                let packet = builder.build_data_msg("/cmd_vel", seq);
                socket.send_to(&packet, dest_addr)?;

                seq += 1;
                thread::sleep(Duration::from_millis(5)); // ~200 Hz
            }
        }
        "spoof" => {
            println!("Sending unauthorized / spoofed RTPS node publications...");
            // Use unauthorized GUID prefix
            let builder = RtpsMessageBuilder::new(unauthorized_guid, true);

            loop {
                // Topic: "/cmd_vel"
                let packet = builder.build_data_msg("/cmd_vel", seq);
                socket.send_to(&packet, dest_addr)?;

                seq += 1;
                thread::sleep(Duration::from_millis(1000)); // 1 Hz
            }
        }
        other => {
            eprintln!("Unknown simulator mode: {}. Supported modes are: normal, flood, spoof.", other);
        }
    }

    Ok(())
}
