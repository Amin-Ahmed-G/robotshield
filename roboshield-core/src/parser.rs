use byteorder::{BigEndian, ByteOrder, LittleEndian};
use std::fmt;

// RTPS Protocol constants
pub const RTPS_HEADER_SIZE: usize = 20;
pub const RTPS_MAGIC: [u8; 4] = [0x52, 0x54, 0x50, 0x53]; // "RTPS"

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpsHeader {
    pub version_major: u8,
    pub version_minor: u8,
    pub vendor_id: [u8; 2],
    pub guid_prefix: [u8; 12],
}

impl RtpsHeader {
    pub fn guid_prefix_str(&self) -> String {
        self.guid_prefix.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<String>>()
            .join(":")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SubmessageKind {
    Pad = 0x01,
    AckNack = 0x06,
    Heartbeat = 0x07,
    Gap = 0x08,
    InfoTs = 0x09,
    InfoSrc = 0x0c,
    InfoReply = 0x0d,
    InfoDst = 0x0e,
    Data = 0x15,
    DataFrag = 0x16,
    NackFrag = 0x12,
    HeartbeatFrag = 0x13,
    Unknown = 0xff,
}

impl From<u8> for SubmessageKind {
    fn from(val: u8) -> Self {
        match val {
            0x01 => SubmessageKind::Pad,
            0x06 => SubmessageKind::AckNack,
            0x07 => SubmessageKind::Heartbeat,
            0x08 => SubmessageKind::Gap,
            0x09 => SubmessageKind::InfoTs,
            0x0c => SubmessageKind::InfoSrc,
            0x0d => SubmessageKind::InfoReply,
            0x0e => SubmessageKind::InfoDst,
            0x15 => SubmessageKind::Data,
            0x16 => SubmessageKind::DataFrag,
            0x12 => SubmessageKind::NackFrag,
            0x13 => SubmessageKind::HeartbeatFrag,
            _ => SubmessageKind::Unknown,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SubmessageHeader {
    pub kind: SubmessageKind,
    pub flags: u8,
    pub length: u16,
}

impl SubmessageHeader {
    pub fn is_little_endian(&self) -> bool {
        (self.flags & 0x01) != 0
    }
}

#[derive(Debug, Clone)]
pub struct DataSubmessage {
    pub extra_flags: u16,
    pub octets_to_inline_qos: u16,
    pub reader_id: [u8; 4],
    pub writer_id: [u8; 4],
    pub writer_seq_number: i64,
    pub topic_name: Option<String>,
}

#[derive(Debug, Clone)]
pub enum ParsedSubmessage {
    Data(DataSubmessage),
    Heartbeat {
        reader_id: [u8; 4],
        writer_id: [u8; 4],
        first_seq: i64,
        last_seq: i64,
        count: i32,
    },
    AckNack {
        reader_id: [u8; 4],
        writer_id: [u8; 4],
        count: i32,
    },
    InfoTs {
        seconds: i32,
        fraction: u32,
    },
    Other(SubmessageKind),
}

#[derive(Debug, Clone)]
pub struct RtpsMessage {
    pub header: RtpsHeader,
    pub submessages: Vec<ParsedSubmessage>,
}

#[derive(Debug)]
pub enum ParserError {
    InvalidMagic,
    TooShort,
    MalformedSubmessage,
}

impl fmt::Display for ParserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParserError::InvalidMagic => write!(f, "Invalid RTPS magic identifier"),
            ParserError::TooShort => write!(f, "Payload is too short to parse"),
            ParserError::MalformedSubmessage => write!(f, "Submessage length constraints violated"),
        }
    }
}

impl std::error::Error for ParserError {}

pub fn parse_rtps_packet(payload: &[u8]) -> Result<RtpsMessage, ParserError> {
    if payload.len() < RTPS_HEADER_SIZE {
        return Err(ParserError::TooShort);
    }

    // Check RTPS magic ID
    if payload[0..4] != RTPS_MAGIC {
        return Err(ParserError::InvalidMagic);
    }

    let header = RtpsHeader {
        version_major: payload[4],
        version_minor: payload[5],
        vendor_id: [payload[6], payload[7]],
        guid_prefix: {
            let mut prefix = [0u8; 12];
            prefix.copy_from_slice(&payload[8..20]);
            prefix
        },
    };

    let mut submessages = Vec::new();
    let mut offset = RTPS_HEADER_SIZE;

    while offset < payload.len() {
        if payload.len() - offset < 4 {
            // Remaining padding is too small, break
            break;
        }

        let kind_byte = payload[offset];
        let flags = payload[offset + 1];
        
        let little_endian = (flags & 0x01) != 0;
        let submsg_len = if little_endian {
            LittleEndian::read_u16(&payload[offset + 2..offset + 4])
        } else {
            BigEndian::read_u16(&payload[offset + 2..offset + 4])
        };

        // Note: RTPS length 0 means it extends to the end of the packet, except for PAD.
        let actual_len = if submsg_len == 0 && offset + 4 < payload.len() {
            (payload.len() - offset - 4) as usize
        } else {
            submsg_len as usize
        };

        if offset + 4 + actual_len > payload.len() {
            return Err(ParserError::MalformedSubmessage);
        }

        let submsg_payload = &payload[offset + 4..offset + 4 + actual_len];
        let kind = SubmessageKind::from(kind_byte);

        match kind {
            SubmessageKind::Data => {
                if let Ok(data_sub) = parse_data_submessage(submsg_payload, little_endian) {
                    submessages.push(ParsedSubmessage::Data(data_sub));
                } else {
                    submessages.push(ParsedSubmessage::Other(kind));
                }
            }
            SubmessageKind::Heartbeat => {
                if submsg_payload.len() >= 28 {
                    let (reader_id, writer_id, first, last, count) = if little_endian {
                        (
                            [submsg_payload[0], submsg_payload[1], submsg_payload[2], submsg_payload[3]],
                            [submsg_payload[4], submsg_payload[5], submsg_payload[6], submsg_payload[7]],
                            LittleEndian::read_i64(&submsg_payload[8..16]),
                            LittleEndian::read_i64(&submsg_payload[16..24]),
                            LittleEndian::read_i32(&submsg_payload[24..28]),
                        )
                    } else {
                        (
                            [submsg_payload[0], submsg_payload[1], submsg_payload[2], submsg_payload[3]],
                            [submsg_payload[4], submsg_payload[5], submsg_payload[6], submsg_payload[7]],
                            BigEndian::read_i64(&submsg_payload[8..16]),
                            BigEndian::read_i64(&submsg_payload[16..24]),
                            BigEndian::read_i32(&submsg_payload[24..28]),
                        )
                    };
                    submessages.push(ParsedSubmessage::Heartbeat {
                        reader_id,
                        writer_id,
                        first_seq: first,
                        last_seq: last,
                        count,
                    });
                } else {
                    submessages.push(ParsedSubmessage::Other(kind));
                }
            }
            SubmessageKind::AckNack => {
                if submsg_payload.len() >= 16 {
                    let reader_id = [submsg_payload[0], submsg_payload[1], submsg_payload[2], submsg_payload[3]];
                    let writer_id = [submsg_payload[4], submsg_payload[5], submsg_payload[6], submsg_payload[7]];
                    // Remaining fields are bitmap and count, we parse count from the end of minimum acknack size
                    // Since it has a variable sequence number set, we extract count safely if payload is large enough
                    let count_offset = submsg_payload.len() - 4;
                    let count = if little_endian {
                        LittleEndian::read_i32(&submsg_payload[count_offset..count_offset + 4])
                    } else {
                        BigEndian::read_i32(&submsg_payload[count_offset..count_offset + 4])
                    };
                    submessages.push(ParsedSubmessage::AckNack { reader_id, writer_id, count });
                } else {
                    submessages.push(ParsedSubmessage::Other(kind));
                }
            }
            SubmessageKind::InfoTs => {
                if submsg_payload.len() >= 8 {
                    let (sec, frac) = if little_endian {
                        (
                            LittleEndian::read_i32(&submsg_payload[0..4]),
                            LittleEndian::read_u32(&submsg_payload[4..8]),
                        )
                    } else {
                        (
                            BigEndian::read_i32(&submsg_payload[0..4]),
                            BigEndian::read_u32(&submsg_payload[4..8]),
                        )
                    };
                    submessages.push(ParsedSubmessage::InfoTs { seconds: sec, fraction: frac });
                } else {
                    submessages.push(ParsedSubmessage::Other(kind));
                }
            }
            _ => {
                submessages.push(ParsedSubmessage::Other(kind));
            }
        }

        offset += 4 + actual_len;
    }

    Ok(RtpsMessage { header, submessages })
}

fn parse_data_submessage(payload: &[u8], little_endian: bool) -> Result<DataSubmessage, ParserError> {
    if payload.len() < 24 {
        return Err(ParserError::MalformedSubmessage);
    }

    let extra_flags = if little_endian {
        LittleEndian::read_u16(&payload[0..2])
    } else {
        BigEndian::read_u16(&payload[0..2])
    };

    let octets_to_inline_qos = if little_endian {
        LittleEndian::read_u16(&payload[2..4])
    } else {
        BigEndian::read_u16(&payload[2..4])
    };

    let reader_id = [payload[4], payload[5], payload[6], payload[7]];
    let writer_id = [payload[8], payload[9], payload[10], payload[11]];

    let writer_seq_number = if little_endian {
        LittleEndian::read_i64(&payload[12..20])
    } else {
        BigEndian::read_i64(&payload[12..20])
    };

    // Attempt to extract the topic name from the serialized data payload if available.
    // DDS Discovery messages (ParameterList) are sent on special entity IDs (e.g. SEDP/SPDP).
    // Specifically, for ROS 2 discovery, topic names can be extracted from the topic parameters if mapped.
    // As a simple heuristic for user data packets, we check for ASCII strings in the serialized data.
    let topic_name = extract_topic_name(payload, octets_to_inline_qos as usize);

    Ok(DataSubmessage {
        extra_flags,
        octets_to_inline_qos,
        reader_id,
        writer_id,
        writer_seq_number,
        topic_name,
    })
}

// Simple heuristic parser for DDS ParameterList to find topic names or inline QoS
fn extract_topic_name(payload: &[u8], start_offset: usize) -> Option<String> {
    let data_offset = 20 + start_offset; // Reader, Writer and Seq Num is 20 bytes.
    if data_offset >= payload.len() {
        return None;
    }

    let search_slice = &payload[data_offset..];
    if search_slice.len() < 8 {
        return None;
    }

    // Standard encapsulation header (e.g. CDR_BE = 0x0002 or CDR_LE = 0x0003)
    let format = &search_slice[0..2];
    if format != [0x00, 0x02] && format != [0x00, 0x03] && format != [0x00, 0x00] && format != [0x00, 0x01] {
        return None;
    }

    let little_endian = format[1] == 0x03 || format[1] == 0x01;
    let mut cursor = 4; // Skip encapsulation header (4 bytes)

    // Look for DDS Parameter ID for Topic Name (PID_TOPIC_NAME = 0x0005) or search for known strings.
    // In ROS 2, topic names are often part of SEDP parameter lists.
    // For normal user data (non-discovery), the topic name is implicit from the Writer Entity ID.
    // We scan parameter lists which are present in Discovery SPDP/SEDP packets.
    while cursor + 4 < search_slice.len() {
        let pid = if little_endian {
            LittleEndian::read_u16(&search_slice[cursor..cursor + 2])
        } else {
            BigEndian::read_u16(&search_slice[cursor..cursor + 2])
        };
        let length = if little_endian {
            LittleEndian::read_u16(&search_slice[cursor + 2..cursor + 4])
        } else {
            BigEndian::read_u16(&search_slice[cursor + 2..cursor + 4])
        } as usize;

        if pid == 0x0001 { // PID_SENTINEL
            break;
        }

        if cursor + 4 + length > search_slice.len() {
            break;
        }

        // PID_TOPIC_NAME = 0x0005, PID_TYPE_NAME = 0x0007
        if pid == 0x0005 && length > 4 {
            let str_len = if little_endian {
                LittleEndian::read_u32(&search_slice[cursor + 4..cursor + 8])
            } else {
                BigEndian::read_u32(&search_slice[cursor + 4..cursor + 8])
            } as usize;

            if str_len > 0 && cursor + 8 + str_len <= search_slice.len() {
                let name_bytes = &search_slice[cursor + 8..cursor + 8 + str_len - 1]; // strip null terminator
                if let Ok(name) = String::from_utf8(name_bytes.to_vec()) {
                    return Some(name);
                }
            }
        }

        // Round length to 4-byte alignment
        let aligned_length = (length + 3) & !3;
        cursor += 4 + aligned_length;
    }

    // Heuristic: If we couldn't parse as parameter list (e.g. it's standard topic data),
    // we map known writer entity IDs to topics. For example, in a configured network,
    // we can associate writer entity keys with specific topics, or scan ASCII strings matching ROS topic path patterns.
    // Here we perform a quick ASCII search for string matching standard ROS 2 prefix (rt/ or /rt/).
    for i in 0..(search_slice.len().saturating_sub(10)) {
        if (search_slice[i] == b'r' && search_slice[i+1] == b't' && search_slice[i+2] == b'/') ||
           (search_slice[i] == b'/' && search_slice[i+1] == b'r' && search_slice[i+2] == b't' && search_slice[i+3] == b'/') {
            // Candidate string found, parse length
            if i >= 4 {
                let len = if little_endian {
                    LittleEndian::read_u32(&search_slice[i-4..i])
                } else {
                    BigEndian::read_u32(&search_slice[i-4..i])
                } as usize;
                if len > 3 && len < 128 && i + len <= search_slice.len() {
                    let raw_bytes = &search_slice[i..i + len - 1]; // strip null terminator
                    if let Ok(name) = String::from_utf8(raw_bytes.to_vec()) {
                        // strip "rt" or "/rt" prefix to get standard topic name
                        let cleaned = if name.starts_with("rt/") {
                            name.replacen("rt", "", 1)
                        } else if name.starts_with("/rt/") {
                            name.replacen("/rt", "", 1)
                        } else {
                            name
                        };
                        return Some(cleaned);
                    }
                }
            }
        }
    }

    None
}
