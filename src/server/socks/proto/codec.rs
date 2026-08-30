use std::io::{Error, ErrorKind};

use bytes::{Buf, BufMut, BytesMut};
use smallvec::SmallVec;
use tokio_util::codec::{Decoder, Encoder};

use super::{
    Address, Command, Method, Reply, StreamOperation, UsernamePassword, Version,
    handshake::password::{SUBNEGOTIATION_VERSION, Status},
};

/// RFC 1929 has the largest client frame: VER, ULEN, UNAME, PLEN, and PASSWD.
pub const MAX_CLIENT_FRAME_LEN: usize = 3 + 2 * u8::MAX as usize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientFrameKind {
    Methods,
    Password,
    Request,
    Done,
}

#[derive(Debug)]
pub enum ClientFrame {
    Methods(SmallVec<[Method; 8]>),
    Password(UsernamePassword),
    Request { command: Command, address: Address },
    RequestRejected(Reply),
}

#[derive(Debug)]
pub enum ServerFrame {
    Method(Method),
    Password(Status),
    Reply(Reply, Address),
}

#[derive(Debug)]
pub struct SocksCodec {
    next: ClientFrameKind,
}

impl Default for SocksCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl SocksCodec {
    #[inline]
    pub const fn new() -> Self {
        Self {
            next: ClientFrameKind::Methods,
        }
    }

    #[inline]
    pub fn expect(&mut self, next: ClientFrameKind) {
        self.next = next;
    }

    fn invalid(message: impl Into<String>) -> Error {
        Error::new(ErrorKind::InvalidData, message.into())
    }

    fn decode_methods(src: &mut BytesMut) -> std::io::Result<Option<ClientFrame>> {
        if src.len() < 2 {
            src.reserve(2 - src.len());
            return Ok(None);
        }
        if src[0] != Version::V5 as u8 {
            return Err(Self::invalid(format!(
                "unsupported SOCKS version {:#x}",
                src[0]
            )));
        }

        let count = src[1] as usize;
        // RFC 1928 section 3 defines METHODS as 1 to 255 octets.
        // https://www.rfc-editor.org/rfc/rfc1928.html#section-3
        if count == 0 {
            return Err(Self::invalid("SOCKS5 method list cannot be empty"));
        }
        let frame_len = 2 + count;
        if src.len() < frame_len {
            src.reserve(frame_len - src.len());
            return Ok(None);
        }

        let mut frame = src.split_to(frame_len);
        frame.advance(2);
        let methods = frame.iter().copied().map(Method::from).collect();
        Ok(Some(ClientFrame::Methods(methods)))
    }

    fn decode_password(src: &mut BytesMut) -> std::io::Result<Option<ClientFrame>> {
        if src.len() < 2 {
            src.reserve(2 - src.len());
            return Ok(None);
        }
        if src[0] != SUBNEGOTIATION_VERSION {
            return Err(Self::invalid(format!(
                "unsupported password subnegotiation version {:#x}",
                src[0]
            )));
        }

        let username_len = src[1] as usize;
        // RFC 1929 section 2 requires both ULEN and PLEN to be in 1..=255.
        // https://www.rfc-editor.org/rfc/rfc1929.html#section-2
        if username_len == 0 {
            return Err(Self::invalid("SOCKS5 username cannot be empty"));
        }
        let password_len_offset = 2 + username_len;
        if src.len() <= password_len_offset {
            src.reserve(password_len_offset + 1 - src.len());
            return Ok(None);
        }
        let password_len = src[password_len_offset] as usize;
        if password_len == 0 {
            return Err(Self::invalid("SOCKS5 password cannot be empty"));
        }
        let frame_len = password_len_offset + 1 + password_len;
        if src.len() < frame_len {
            src.reserve(frame_len - src.len());
            return Ok(None);
        }

        let frame = src.split_to(frame_len).freeze();
        let username = frame.slice(2..password_len_offset);
        let password = frame.slice(password_len_offset + 1..);
        Ok(Some(ClientFrame::Password(UsernamePassword::from_bytes(
            username, password,
        ))))
    }

    fn decode_request(src: &mut BytesMut) -> std::io::Result<Option<ClientFrame>> {
        if src.len() < 4 {
            src.reserve(4 - src.len());
            return Ok(None);
        }
        if src[0] != Version::V5 as u8 {
            return Err(Self::invalid(format!(
                "unsupported SOCKS version {:#x}",
                src[0]
            )));
        }
        // RFC 1928 section 6 requires every reserved field to be zero.
        // https://www.rfc-editor.org/rfc/rfc1928.html#section-6
        if src[2] != 0 {
            src.advance(4);
            return Ok(Some(ClientFrame::RequestRejected(Reply::GeneralFailure)));
        }

        let address_len = match src[3] {
            0x01 => 1 + 4 + 2,
            0x03 => {
                if src.len() < 5 {
                    src.reserve(5 - src.len());
                    return Ok(None);
                }
                if src[4] == 0 {
                    src.advance(5);
                    return Ok(Some(ClientFrame::RequestRejected(Reply::GeneralFailure)));
                }
                1 + 1 + src[4] as usize + 2
            }
            0x04 => 1 + 16 + 2,
            _ => {
                src.advance(4);
                return Ok(Some(ClientFrame::RequestRejected(
                    Reply::AddressTypeNotSupported,
                )));
            }
        };
        let frame_len = 3 + address_len;
        if frame_len > MAX_CLIENT_FRAME_LEN {
            return Err(Self::invalid("SOCKS5 request exceeds maximum frame size"));
        }
        if src.len() < frame_len {
            src.reserve(frame_len - src.len());
            return Ok(None);
        }

        let frame = src.split_to(frame_len);
        let command = match Command::try_from(frame[1]) {
            Ok(command) => command,
            Err(_) => {
                return Ok(Some(ClientFrame::RequestRejected(
                    Reply::CommandNotSupported,
                )));
            }
        };
        let address = match Address::try_from(&frame[3..]) {
            Ok(address) => address,
            Err(_) => return Ok(Some(ClientFrame::RequestRejected(Reply::GeneralFailure))),
        };
        Ok(Some(ClientFrame::Request { command, address }))
    }
}

impl Decoder for SocksCodec {
    type Item = ClientFrame;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> std::io::Result<Option<Self::Item>> {
        match self.next {
            ClientFrameKind::Methods => Self::decode_methods(src),
            ClientFrameKind::Password => Self::decode_password(src),
            ClientFrameKind::Request => Self::decode_request(src),
            ClientFrameKind::Done => Ok(None),
        }
    }
}

impl Encoder<ServerFrame> for SocksCodec {
    type Error = Error;

    fn encode(&mut self, item: ServerFrame, dst: &mut BytesMut) -> std::io::Result<()> {
        match item {
            ServerFrame::Method(method) => {
                dst.reserve(2);
                dst.put_u8(Version::V5.into());
                dst.put_u8(method.into());
            }
            ServerFrame::Password(status) => {
                dst.reserve(2);
                dst.put_u8(SUBNEGOTIATION_VERSION);
                dst.put_u8(status.into());
            }
            ServerFrame::Reply(reply, address) => {
                address.validate_for_serialization()?;
                dst.reserve(3 + address.len());
                dst.put_u8(Version::V5.into());
                dst.put_u8(reply.into());
                dst.put_u8(0);
                address.write_to_buf(dst)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use bytes::BytesMut;
    use tokio_util::codec::{Decoder, Encoder};

    use super::*;

    #[test]
    fn decodes_fragmented_method_negotiation_without_consuming_partial_data() {
        let mut codec = SocksCodec::new();
        let mut buffer = BytesMut::from(&[0x05, 0x02, 0x00][..]);

        assert!(codec.decode(&mut buffer).unwrap().is_none());
        assert_eq!(&buffer[..], &[0x05, 0x02, 0x00]);

        buffer.extend_from_slice(&[0x02]);
        let ClientFrame::Methods(methods) = codec.decode(&mut buffer).unwrap().unwrap() else {
            panic!("expected method negotiation frame");
        };
        assert_eq!(&methods[..], &[Method::NoAuth, Method::Password]);
        assert!(buffer.is_empty());
    }

    #[test]
    fn preserves_pipelined_application_data_after_connect_request() {
        let mut codec = SocksCodec::new();
        codec.expect(ClientFrameKind::Request);
        let mut buffer = BytesMut::from(
            &[
                0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90, b'G', b'E', b'T',
            ][..],
        );

        let ClientFrame::Request { command, address } = codec.decode(&mut buffer).unwrap().unwrap()
        else {
            panic!("expected command request");
        };
        assert_eq!(command, Command::Connect);
        assert_eq!(
            address,
            Address::SocketAddress(SocketAddr::from((Ipv4Addr::LOCALHOST, 8080)))
        );
        assert_eq!(&buffer[..], b"GET");
    }

    #[test]
    fn maps_unsupported_command_and_address_type_to_rfc_reply_codes() {
        let mut codec = SocksCodec::new();
        codec.expect(ClientFrameKind::Request);
        let mut command = BytesMut::from(&[0x05, 0x7f, 0x00, 0x01, 0, 0, 0, 0, 0, 0][..]);
        assert!(matches!(
            codec.decode(&mut command).unwrap(),
            Some(ClientFrame::RequestRejected(Reply::CommandNotSupported))
        ));

        let mut address = BytesMut::from(&[0x05, 0x01, 0x00, 0x7f][..]);
        assert!(matches!(
            codec.decode(&mut address).unwrap(),
            Some(ClientFrame::RequestRejected(Reply::AddressTypeNotSupported))
        ));

        let mut invalid_domain =
            BytesMut::from(&[0x05, 0x01, 0x00, 0x03, 0x01, 0xff, 0x01, 0xbb][..]);
        assert!(matches!(
            codec.decode(&mut invalid_domain).unwrap(),
            Some(ClientFrame::RequestRejected(Reply::GeneralFailure))
        ));
    }

    #[test]
    fn rejects_nonzero_reserved_byte_and_empty_rfc1929_fields() {
        let mut codec = SocksCodec::new();
        codec.expect(ClientFrameKind::Request);
        let mut request = BytesMut::from(&[0x05, 0x01, 0x01, 0x01][..]);
        assert!(matches!(
            codec.decode(&mut request).unwrap(),
            Some(ClientFrame::RequestRejected(Reply::GeneralFailure))
        ));

        codec.expect(ClientFrameKind::Password);
        let mut password = BytesMut::from(&[0x01, 0x00][..]);
        assert_eq!(
            codec.decode(&mut password).unwrap_err().kind(),
            ErrorKind::InvalidData
        );
    }

    #[test]
    fn encodes_rfc1928_reply() {
        let mut codec = SocksCodec::new();
        let mut buffer = BytesMut::new();
        codec
            .encode(
                ServerFrame::Reply(
                    Reply::Succeeded,
                    Address::SocketAddress(SocketAddr::from((Ipv4Addr::LOCALHOST, 1080))),
                ),
                &mut buffer,
            )
            .unwrap();
        assert_eq!(
            &buffer[..],
            &[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38]
        );
    }

    #[test]
    fn accepts_maximum_length_rfc1928_domain() {
        let mut codec = SocksCodec::new();
        codec.expect(ClientFrameKind::Request);
        let mut buffer = BytesMut::with_capacity(262);
        buffer.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, 0xff]);
        buffer.extend(std::iter::repeat_n(b'a', u8::MAX as usize));
        buffer.extend_from_slice(&[0x01, 0xbb]);

        let ClientFrame::Request { address, .. } = codec.decode(&mut buffer).unwrap().unwrap()
        else {
            panic!("expected maximum-length domain request");
        };
        assert!(matches!(
            address,
            Address::DomainAddress(domain, 443) if domain.len() == u8::MAX as usize
        ));
    }

    #[test]
    fn decodes_rfc1929_credentials_as_octets() {
        let mut codec = SocksCodec::new();
        codec.expect(ClientFrameKind::Password);
        let mut buffer = BytesMut::from(&[0x01, 0x02, 0xff, 0x80, 0x02, 0xfe, 0x81][..]);

        let ClientFrame::Password(credentials) = codec.decode(&mut buffer).unwrap().unwrap() else {
            panic!("expected password frame");
        };
        assert_eq!(credentials.username.as_ref(), &[0xff, 0x80]);
        assert_eq!(credentials.password.as_ref(), &[0xfe, 0x81]);
        assert!(buffer.is_empty());
    }

    #[test]
    fn rejects_oversized_domain_before_encoding_reply() {
        let mut codec = SocksCodec::new();
        let mut buffer = BytesMut::new();
        let error = codec
            .encode(
                ServerFrame::Reply(
                    Reply::Succeeded,
                    Address::DomainAddress("a".repeat(u8::MAX as usize + 1), 443),
                ),
                &mut buffer,
            )
            .unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert!(buffer.is_empty());
    }
}
