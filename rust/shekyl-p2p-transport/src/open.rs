// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The unbudgeted peer side of the clearnet handshake.
//!
//! [`Initiator::open`] and [`Responder::accept`] write one flight and read
//! one flight on a [`std::io::Read`] + [`std::io::Write`] stream. The node's
//! handshake does not call them: it writes the same flight bytes under the
//! link budget and the handshake deadline.

use std::io::{Read, Write};

use crate::flight::{InitiatorFlight, ResponderFlight};
use crate::noise::{HandshakeError, Initiator, Responder};
use crate::prefix::NetworkId;
use crate::{RecvHalf, SendHalf, INITIATOR_FLIGHT_LEN, RESPONDER_FLIGHT_LEN};

/// Why [`Initiator::open`] or [`Responder::accept`] did not finish.
#[derive(Debug)]
pub enum OpenError {
    /// The stream failed.
    Io(std::io::Error),
    /// Message 1 or message 2 did not verify.
    Handshake(HandshakeError),
    /// The peer's flight named another network.
    Prefix,
}

impl From<std::io::Error> for OpenError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<HandshakeError> for OpenError {
    fn from(error: HandshakeError) -> Self {
        Self::Handshake(error)
    }
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "the channel's socket failed: {error}"),
            Self::Handshake(error) => write!(f, "the handshake was refused: {error}"),
            Self::Prefix => write!(f, "the peer answered another network's prefix"),
        }
    }
}

impl std::error::Error for OpenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Handshake(error) => Some(error),
            Self::Prefix => None,
        }
    }
}

impl Initiator {
    /// Write this initiator's flight and read the responder's.
    ///
    /// # Errors
    ///
    /// The stream's, a handshake that does not verify, or a flight whose
    /// prefix is not `network_id`'s. A prefix mismatch does not run message 2.
    pub fn open<S: Read + Write>(
        stream: &mut S,
        network_id: &NetworkId,
    ) -> Result<(SendHalf, RecvHalf), OpenError> {
        let (initiator, flight) = Self::new(network_id)?;
        stream.write_all(flight.as_bytes())?;
        let mut bytes = [0u8; RESPONDER_FLIGHT_LEN];
        stream.read_exact(&mut bytes)?;
        let reply = ResponderFlight::from_bytes(bytes);
        if !reply.for_network(network_id) {
            return Err(OpenError::Prefix);
        }
        let (send, recv) = initiator.read_message2(reply.message())?.split();
        Ok((send, recv))
    }
}

impl Responder {
    /// Read the initiator's flight and write this responder's.
    ///
    /// # Errors
    ///
    /// The stream's, a handshake that does not verify, or a flight whose
    /// prefix is not `network_id`'s. A prefix mismatch does not run message 1.
    pub fn accept<S: Read + Write>(
        stream: &mut S,
        network_id: &NetworkId,
    ) -> Result<(SendHalf, RecvHalf), OpenError> {
        let mut bytes = [0u8; INITIATOR_FLIGHT_LEN];
        stream.read_exact(&mut bytes)?;
        let flight = InitiatorFlight::from_bytes(bytes);
        if !flight.for_network(network_id) {
            return Err(OpenError::Prefix);
        }
        let ready = Self::new(network_id).read_message1(flight.message())?;
        let (established, reply) = ready.write_message2()?;
        stream.write_all(reply.as_bytes())?;
        let (send, recv) = established.split();
        Ok((send, recv))
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, TcpListener, TcpStream};
    use std::time::Duration;

    use super::*;
    use crate::RecvHalf;

    fn exchange(
        send: &mut SendHalf,
        recv: &mut RecvHalf,
        sock: &mut TcpStream,
        plain: &[u8],
    ) -> Vec<u8> {
        sock.write_all(&send.seal(plain).expect("seal"))
            .expect("write");
        let mut pending = Vec::new();
        let mut buf = [0u8; 256];
        loop {
            if let Some(opened) = recv.take_one(&mut pending).expect("record") {
                return opened;
            }
            let n = sock.read(&mut buf).expect("read");
            assert_ne!(n, 0, "the socket closed inside a record");
            pending.extend_from_slice(&buf[..n]);
        }
    }

    #[test]
    fn open_and_accept_carry_one_record_each_way() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let addr = listener.local_addr().expect("addr");
        let network = [0x11u8; 16];
        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            sock.set_read_timeout(Some(Duration::from_secs(2)))
                .expect("timeout");
            let (mut send, mut recv) = Responder::accept(&mut sock, &network).expect("accept");
            let got = exchange(&mut send, &mut recv, &mut sock, b"back");
            assert_eq!(got, b"out");
        });
        let mut sock = TcpStream::connect(addr).expect("connect");
        sock.set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        let (mut send, mut recv) = Initiator::open(&mut sock, &network).expect("open");
        let got = exchange(&mut send, &mut recv, &mut sock, b"out");
        server.join().expect("server");
        assert_eq!(got, b"back");
    }

    /// Red edit: accept message 2 when the prefix names another network.
    #[test]
    fn a_flight_for_another_network_is_refused_before_message_2() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            let mut flight = [0u8; INITIATOR_FLIGHT_LEN];
            sock.read_exact(&mut flight).expect("flight");
            sock.write_all(&[0u8; RESPONDER_FLIGHT_LEN]).expect("reply");
        });
        let mut sock = TcpStream::connect(addr).expect("connect");
        sock.set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        match Initiator::open(&mut sock, &[0x11; 16]) {
            Err(OpenError::Prefix) => {}
            Err(error) => panic!("a foreign prefix must be refused before message 2: {error}"),
            Ok(_) => panic!("a foreign prefix opened a channel"),
        }
        server.join().expect("server");
    }
}
