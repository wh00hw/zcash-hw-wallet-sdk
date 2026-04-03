use crate::error::{HwSignerError, Result};
use crate::transport::Transport;
use std::time::Duration;
use tracing::{info, trace};

/// USB CDC serial transport for hardware wallets.
///
/// Connects to hardware signing devices (microcontrollers, Arduino, ESP32, etc.)
/// over a serial port (e.g., `/dev/ttyACM0` on Linux, `COM3` on Windows).
///
/// # Example
///
/// ```rust,ignore
/// use zcash_hw_wallet::transport::SerialTransport;
///
/// let transport = SerialTransport::new("/dev/ttyACM0", 115200)?;
/// ```
pub struct SerialTransport {
    port: Box<dyn serialport::SerialPort>,
}

impl SerialTransport {
    /// Open a serial port with the given path and baud rate.
    ///
    /// Default timeout is 300 seconds (allows time for user confirmation
    /// on the device).
    pub fn new(path: &str, baud_rate: u32) -> Result<Self> {
        Self::with_timeout(path, baud_rate, Duration::from_secs(300))
    }

    /// Open a serial port with a custom timeout.
    pub fn with_timeout(path: &str, baud_rate: u32, timeout: Duration) -> Result<Self> {
        info!("Serial: opening {} @ {} baud (timeout={}s)", path, baud_rate, timeout.as_secs());
        let port = serialport::new(path, baud_rate)
            .timeout(timeout)
            .open()
            .map_err(|e| HwSignerError::ConnectionFailed(format!("{}: {}", path, e)))?;
        info!("Serial: connected to {}", path);
        Ok(Self { port })
    }
}

impl Transport for SerialTransport {
    fn send(&mut self, data: &[u8]) -> Result<()> {
        info!("HWP >> {} bytes", data.len());
        trace!(
            "HWP >> {}",
            data.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("")
        );
        // Write in 64-byte chunks with 5ms delays to avoid CDC buffer overflow on constrained devices
        const CHUNK_SIZE: usize = 64;
        let mut offset = 0;
        while offset < data.len() {
            let end = (offset + CHUNK_SIZE).min(data.len());
            self.port
                .write_all(&data[offset..end])
                .map_err(|e| HwSignerError::TransportError(e.to_string()))?;
            self.port
                .flush()
                .map_err(|e| HwSignerError::TransportError(e.to_string()))?;
            offset = end;
            if offset < data.len() {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        Ok(())
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        let n = self.port
            .read(buf)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::TimedOut {
                    HwSignerError::Timeout
                } else {
                    HwSignerError::TransportError(e.to_string())
                }
            })?;
        if n > 0 {
            trace!(
                "HWP << {} bytes: {}",
                n,
                buf[..n].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("")
            );
        }
        Ok(n)
    }
}
