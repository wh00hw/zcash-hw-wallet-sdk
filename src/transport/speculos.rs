//! Speculos TCP transport for testing Ledger apps on the emulator.
//!
//! Speaks the Speculos APDU TCP protocol (port 9999):
//! - Send: [4-byte BE length][APDU bytes]
//! - Recv: [4-byte BE length][response data][2-byte BE SW]

use crate::error::{HwSignerError, Result};
use crate::transport::Transport;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use tracing::{debug, info, trace};

const CLA: u8 = 0xE0;
const INS_HWP_DATA: u8 = 0x40;
const APDU_CHUNK_SIZE: usize = 250;

/// TCP transport for Speculos emulator.
pub struct SpeculosTransport {
    stream: TcpStream,
    response_buf: Vec<u8>,
    response_pos: usize,
}

impl SpeculosTransport {
    /// Connect to Speculos at the given address (e.g., "127.0.0.1:9999").
    pub fn open(addr: &str) -> Result<Self> {
        info!("Speculos: connecting to {}...", addr);
        let stream = TcpStream::connect(addr)
            .map_err(|e| HwSignerError::ConnectionFailed(format!("Speculos TCP: {}", e)))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(300)))
            .ok();
        info!("Speculos: connected to {}", addr);
        Ok(Self {
            stream,
            response_buf: Vec::new(),
            response_pos: 0,
        })
    }

    fn apdu_exchange(&mut self, cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Result<Vec<u8>> {
        let mut apdu = Vec::with_capacity(5 + data.len());
        apdu.push(cla);
        apdu.push(ins);
        apdu.push(p1);
        apdu.push(p2);
        apdu.push(data.len() as u8);
        apdu.extend_from_slice(data);

        debug!(
            "APDU >> CLA=0x{:02X} INS=0x{:02X} P1=0x{:02X} P2=0x{:02X} Lc={} data={}",
            cla, ins, p1, p2, data.len(),
            data.iter().take(32).map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("")
        );

        // Send: 4-byte BE length + APDU
        let len = (apdu.len() as u32).to_be_bytes();
        self.stream
            .write_all(&len)
            .map_err(|e| HwSignerError::TransportError(format!("TCP write: {}", e)))?;
        self.stream
            .write_all(&apdu)
            .map_err(|e| HwSignerError::TransportError(format!("TCP write: {}", e)))?;

        // Recv: 4-byte BE length + data + 2-byte BE SW
        let mut len_buf = [0u8; 4];
        self.stream
            .read_exact(&mut len_buf)
            .map_err(|e| HwSignerError::TransportError(format!("TCP read len: {}", e)))?;
        let resp_len = u32::from_be_bytes(len_buf) as usize;

        let mut resp_data = vec![0u8; resp_len];
        if resp_len > 0 {
            self.stream
                .read_exact(&mut resp_data)
                .map_err(|e| HwSignerError::TransportError(format!("TCP read data: {}", e)))?;
        }

        let mut sw_buf = [0u8; 2];
        self.stream
            .read_exact(&mut sw_buf)
            .map_err(|e| HwSignerError::TransportError(format!("TCP read SW: {}", e)))?;
        let sw = u16::from_be_bytes(sw_buf);

        debug!(
            "APDU << SW=0x{:04X} data={} bytes{}",
            sw,
            resp_data.len(),
            if resp_data.is_empty() { String::new() } else {
                format!(": {}", resp_data.iter().take(32).map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(""))
            }
        );

        if sw != 0x9000 {
            return Err(HwSignerError::TransportError(format!(
                "APDU error: SW=0x{:04X}",
                sw
            )));
        }

        Ok(resp_data)
    }
}

impl Transport for SpeculosTransport {
    fn requires_handshake(&self) -> bool {
        false
    }

    fn send(&mut self, data: &[u8]) -> Result<()> {
        self.response_buf.clear();
        self.response_pos = 0;

        let total = data.len();
        let num_chunks = (total + APDU_CHUNK_SIZE - 1) / APDU_CHUNK_SIZE;
        info!(
            "HWP >> {} bytes ({}chunk{})",
            total,
            if num_chunks > 1 { format!("{} ", num_chunks) } else { String::new() },
            if num_chunks > 1 { "s" } else { "" }
        );
        trace!(
            "HWP >> {}",
            data.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("")
        );

        let mut offset = 0;
        while offset < total {
            let chunk_end = (offset + APDU_CHUNK_SIZE).min(total);
            let is_last = chunk_end == total;
            let p1 = if is_last { 0x00 } else { 0x80 };

            let resp =
                self.apdu_exchange(CLA, INS_HWP_DATA, p1, 0x00, &data[offset..chunk_end])?;

            if is_last && !resp.is_empty() {
                info!("HWP << {} bytes response", resp.len());
                trace!(
                    "HWP << {}",
                    resp.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("")
                );
                self.response_buf = resp;
                self.response_pos = 0;
            }

            offset = chunk_end;
        }

        Ok(())
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.response_pos >= self.response_buf.len() {
            return Ok(0);
        }

        let available = self.response_buf.len() - self.response_pos;
        let n = buf.len().min(available);
        buf[..n].copy_from_slice(&self.response_buf[self.response_pos..self.response_pos + n]);
        self.response_pos += n;
        Ok(n)
    }
}
