use super::{Address, StreamOperation};

/// SOCKS5 UDP packet header
///
/// ```plain
/// +-----+------+------+----------+----------+----------+
/// | RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
/// +-----+------+------+----------+----------+----------+
/// |  2  |  1   |  1   | Variable |    2     | Variable |
/// +-----+------+------+----------+----------+----------+
/// ```
#[derive(Clone, Debug)]
pub struct UdpHeader {
    pub frag: u8,
    pub address: Address,
}

impl UdpHeader {
    /// Create a new [`UdpHeader`] instance.
    #[inline]
    pub fn new(frag: u8, address: Address) -> Self {
        Self { frag, address }
    }

    /// Decodes one RFC 1928 UDP header and returns its serialized length.
    pub fn decode(packet: &[u8]) -> std::io::Result<(Self, usize)> {
        let mut packet = std::io::Cursor::new(packet);
        let header = Self::retrieve_from_stream(&mut packet)?;
        Ok((header, packet.position() as usize))
    }
}

impl StreamOperation for UdpHeader {
    fn retrieve_from_stream<R: std::io::Read>(stream: &mut R) -> std::io::Result<Self> {
        let mut buf = [0; 3];
        stream.read_exact(&mut buf)?;
        if buf[..2] != [0, 0] {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "SOCKS5 UDP reserved field must be zero",
            ));
        }
        let frag = buf[2];

        let address = Address::retrieve_from_stream(stream)?;
        Ok(Self { frag, address })
    }

    fn write_to_buf<B: bytes::BufMut>(&self, buf: &mut B) -> std::io::Result<()> {
        self.address.validate_for_serialization()?;
        buf.put_bytes(0x00, 2);
        buf.put_u8(self.frag);
        self.address.write_to_buf(buf)
    }

    fn len(&self) -> usize {
        3 + self.address.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_nonzero_rfc1928_reserved_field() {
        let packet = [0x00, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 53];
        assert_eq!(
            UdpHeader::decode(&packet).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn rejects_oversized_domain_without_writing_udp_header() {
        let header = UdpHeader::new(
            0,
            Address::DomainAddress("a".repeat(u8::MAX as usize + 1), 53),
        );
        let mut buffer = Vec::new();

        let error = header.write_to_buf(&mut buffer).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(buffer.is_empty());
    }
}
