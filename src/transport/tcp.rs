//! Raw TCP transport for HWP protocol.
//!
//! Connects to a virtual device or any HWP-speaking TCP server.
//! Semantically identical to serial: ordered byte stream with HWP framing.
//! The device sends PING on connect, so `requires_handshake()` returns `true`.

use crate::error::{HwSignerError, Result};
use crate::transport::Transport;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Raw TCP transport for HWP devices.
pub struct TcpTransport {
    stream: TcpStream,
}

impl TcpTransport {
    /// Connect to an HWP device at the given address (e.g., "127.0.0.1:9999").
    pub fn connect(addr: &str) -> Result<Self> {
        let stream = TcpStream::connect(addr)
            .map_err(|e| HwSignerError::ConnectionFailed(format!("TCP: {}", e)))?;
        stream.set_nodelay(true).ok();
        stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
        Ok(Self { stream })
    }
}

impl Transport for TcpTransport {
    fn send(&mut self, data: &[u8]) -> Result<()> {
        self.stream
            .write_all(data)
            .map_err(|e| HwSignerError::TransportError(format!("TCP write: {}", e)))
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.stream.read(buf).map_err(|e| {
            if e.kind() == std::io::ErrorKind::TimedOut {
                HwSignerError::Timeout
            } else {
                HwSignerError::TransportError(format!("TCP read: {}", e))
            }
        })
    }

    fn requires_handshake(&self) -> bool {
        true
    }
}
