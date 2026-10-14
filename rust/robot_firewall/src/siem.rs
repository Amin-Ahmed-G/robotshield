//! Streams incidents to a SIEM over syslog (RFC 5424 over UDP).
//!
//! `siem_syslog: udp://<host>:<port>` with `siem_format: cef` (Splunk,
//! Microsoft Sentinel, QRadar, ArcSight) or `json` (Elastic, Splunk HEC via a
//! syslog input). UDP never blocks the firewall: a down collector loses
//! events, never commands.

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};

use fw_core::siem::{syslog_frame, to_cef};
use fw_core::Incident;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Cef,
    Json,
}

pub struct SiemExporter {
    socket: UdpSocket,
    target: SocketAddr,
    format: Format,
    host: String,
}

impl SiemExporter {
    /// `url` is `udp://host:port`; returns None when export is disabled ("").
    pub fn new(url: &str, format: &str, host: &str) -> Result<Option<Self>, String> {
        if url.is_empty() {
            return Ok(None);
        }
        let addr = url
            .strip_prefix("udp://")
            .ok_or_else(|| format!("siem_syslog must look like udp://host:514, got {url:?}"))?;
        let target = addr
            .to_socket_addrs()
            .map_err(|e| format!("siem_syslog {addr}: {e}"))?
            .next()
            .ok_or_else(|| format!("siem_syslog {addr}: no address"))?;
        let format = match format {
            "cef" => Format::Cef,
            "json" => Format::Json,
            other => return Err(format!("siem_format must be 'cef' or 'json', got {other:?}")),
        };
        let bind = if target.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let socket = UdpSocket::bind(bind).map_err(|e| format!("siem socket: {e}"))?;
        socket.set_nonblocking(true).map_err(|e| format!("siem socket: {e}"))?;
        Ok(Some(Self { socket, target, format, host: host.to_string() }))
    }

    pub fn describe(&self) -> String {
        format!("{} via syslog/udp to {}", match self.format { Format::Cef => "CEF", Format::Json => "JSON" }, self.target)
    }

    pub fn send(&self, inc: &Incident) {
        let ms = (inc.time * 1000.0) as i64;
        let ts = chrono::DateTime::from_timestamp_millis(ms)
            .unwrap_or_default()
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let msg = match self.format {
            Format::Cef => to_cef(inc, &self.host, env!("CARGO_PKG_VERSION"), ms),
            Format::Json => inc.to_json(),
        };
        let datagram = syslog_frame(inc, &ts, &self.host, &msg);
        // Best effort by design (see module docs).
        let _ = self.socket.send_to(datagram.as_bytes(), self.target);
    }
}
