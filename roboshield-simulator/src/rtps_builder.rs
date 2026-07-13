use byteorder::{BigEndian, ByteOrder, LittleEndian};

pub struct RtpsMessageBuilder {
    guid_prefix: [u8; 12],
    little_endian: bool,
}

impl RtpsMessageBuilder {
    pub fn new(guid_prefix: [u8; 12], little_endian: bool) -> Self {
        Self {
            guid_prefix,
            little_endian,
        }
    }

    /// Serializes a complete RTPS message containing a single Data submessage
    pub fn build_data_msg(&self, topic_name: &str, seq_num: i64) -> Vec<u8> {
        let mut packet = Vec::new();

        // 1. Build Header (20 bytes)
        packet.extend_from_slice(b"RTPS"); // Magic
        packet.push(2); // Major Version
        packet.push(3); // Minor Version
        packet.extend_from_slice(&[0x01, 0x0f]); // Vendor ID (e.g. eProsima FastDDS vendor code)
        packet.extend_from_slice(&self.guid_prefix);

        // 2. Build Submessage Header
        // ID = 0x15 (DATA)
        packet.push(0x15);
        // Flags: Bit 0 = Endianness (1 = Little Endian, 0 = Big Endian)
        // Bit 1 = Inline Qos
        // Bit 2 = Data (payload present)
        let flags = if self.little_endian { 0x01 | 0x04 } else { 0x04 };
        packet.push(flags);

        // Calculate Data submessage body length:
        // Extra flags (2) + octets to inline qos (2) + reader entity id (4) + writer entity id (4)
        // + sequence number (8) + CDR serialization header (4) + string length prefix (4) + string bytes
        let mut string_bytes = topic_name.as_bytes().to_vec();
        string_bytes.push(0); // Null terminator
        let str_aligned_len = (string_bytes.len() + 3) & !3; // Align to 4-byte boundary
        
        // Body payload length: 2 + 2 + 4 + 4 + 8 + 4 + 4 + str_aligned_len + sentinel parameter (4)
        // We write topic name using Parameter List style (PID_TOPIC_NAME = 0x0005)
        let parameter_list_len = 4 + 4 + str_aligned_len + 4; // Parameter header + string + sentinel
        let data_body_len = 20 + 4 + parameter_list_len;

        if self.little_endian {
            let mut len_buf = [0u8; 2];
            LittleEndian::write_u16(&mut len_buf, data_body_len as u16);
            packet.extend_from_slice(&len_buf);
        } else {
            let mut len_buf = [0u8; 2];
            BigEndian::write_u16(&mut len_buf, data_body_len as u16);
            packet.extend_from_slice(&len_buf);
        }

        // 3. Build DATA Submessage Body
        packet.extend_from_slice(&[0x00, 0x00]); // Extra flags
        packet.extend_from_slice(&[0x00, 0x00]); // Octets to inline QoS

        packet.extend_from_slice(&[0x00, 0x00, 0x01, 0xc1]); // Reader entity ID (e.g. ENTITYID_UNKNOWN)
        packet.extend_from_slice(&[0x00, 0x00, 0x01, 0x02]); // Writer entity ID (e.g. ENTITYID_WRITER)

        let mut seq_buf = [0u8; 8];
        if self.little_endian {
            LittleEndian::write_i64(&mut seq_buf, seq_num);
        } else {
            BigEndian::write_i64(&mut seq_buf, seq_num);
        }
        packet.extend_from_slice(&seq_buf);

        // CDR Encapsulation header
        packet.extend_from_slice(&[0x00, 0x03, 0x00, 0x00]); // PL_CDR_LE format (Parameter List CDR Little Endian)

        // PID_TOPIC_NAME = 0x0005
        let mut pid_buf = [0u8; 2];
        let mut p_len_buf = [0u8; 2];
        if self.little_endian {
            LittleEndian::write_u16(&mut pid_buf, 0x0005);
            LittleEndian::write_u16(&mut p_len_buf, (4 + string_bytes.len()) as u16);
        } else {
            BigEndian::write_u16(&mut pid_buf, 0x0005);
            BigEndian::write_u16(&mut p_len_buf, (4 + string_bytes.len()) as u16);
        }
        packet.extend_from_slice(&pid_buf);
        packet.extend_from_slice(&p_len_buf);

        // Topic String Length
        let mut str_len_buf = [0u8; 4];
        if self.little_endian {
            LittleEndian::write_u32(&mut str_len_buf, string_bytes.len() as u32);
        } else {
            BigEndian::write_u32(&mut str_len_buf, string_bytes.len() as u32);
        }
        packet.extend_from_slice(&str_len_buf);

        // Topic String Content
        packet.extend_from_slice(&string_bytes);

        // Padding to align parameter string
        let pad_len = str_aligned_len - string_bytes.len();
        for _ in 0..pad_len {
            packet.push(0);
        }

        // PID_SENTINEL = 0x0001
        packet.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);

        packet
    }
}
