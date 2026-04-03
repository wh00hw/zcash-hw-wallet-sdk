//! Transport layer abstractions for communicating with hardware wallets.
//!
//! The SDK ships with two transport implementations:
//! - [`SerialTransport`] — USB CDC serial (for microcontrollers, Arduino, ESP32, etc.)
//! - [`QrTransport`] — animated QR codes (for air-gapped devices)

#[cfg(feature = "serial")]
mod serial;
#[cfg(feature = "serial")]
pub use serial::SerialTransport;

#[cfg(feature = "ledger")]
mod ledger;
#[cfg(feature = "ledger")]
pub use ledger::LedgerTransport;

#[cfg(feature = "ledger")]
mod speculos;
#[cfg(feature = "ledger")]
pub use speculos::SpeculosTransport;

#[cfg(feature = "tcp")]
mod tcp;
#[cfg(feature = "tcp")]
pub use tcp::TcpTransport;

#[cfg(feature = "qr")]
pub mod qr;
#[cfg(feature = "qr")]
pub use qr::QrTransport;

use crate::error::Result;

/// Trait for sending and receiving raw byte frames to/from a hardware device.
///
/// Transport implementations handle the physical communication channel.
/// The [`crate::protocol::HwpCodec`] sits on top to handle framing and CRC.
pub trait Transport {
    /// Send raw bytes to the device.
    fn send(&mut self, data: &[u8]) -> Result<()>;

    /// Receive raw bytes from the device.
    ///
    /// Blocks until at least one byte is available or a timeout occurs.
    /// Returns the bytes read.
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize>;

    /// Whether this transport requires an initial handshake (PING/PONG).
    ///
    /// Serial devices send a PING on boot and expect PONG before accepting commands.
    /// Ledger devices are passive (APDU request-response) and don't need handshake.
    fn requires_handshake(&self) -> bool {
        true
    }

    /// Read exactly `buf.len()` bytes from the device.
    fn recv_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        let mut offset = 0;
        while offset < buf.len() {
            let n = self.recv(&mut buf[offset..])?;
            if n == 0 {
                return Err(crate::error::HwSignerError::Timeout);
            }
            offset += n;
        }
        Ok(())
    }
}
