//! Ledger HID transport for communicating with Ledger Nano S+/X/Stax/Flex.
//!
//! Wraps HWP frame bytes into Ledger APDU commands (CLA=0xE0, INS=0x40)
//! and sends them over USB HID using the Ledger HID framing protocol.
//!
//! # Example
//!
//! ```rust,ignore
//! use zcash_hw_wallet_sdk::transport::LedgerTransport;
//!
//! let transport = LedgerTransport::open()?;
//! let mut signer = DeviceSigner::new(transport)?;
//! ```

use crate::error::{HwSignerError, Result};
use crate::transport::Transport;
use std::time::Duration;
use tracing::{debug, info, trace};

/// Ledger vendor ID.
const LEDGER_VID: u16 = 0x2c97;

/// HID packet size (USB HID report).
const HID_PACKET_SIZE: usize = 64;

/// Ledger HID framing: channel ID.
const CHANNEL: u16 = 0x0101;

/// Ledger HID framing: command tag.
const TAG_APDU: u8 = 0x05;

/// Ledger APDU constants for the Zcash Orchard app.
const CLA: u8 = 0xE0;
const INS_HWP_DATA: u8 = 0x40;

/// Maximum APDU data size per chunk.
const APDU_CHUNK_SIZE: usize = 250;

/// USB HID transport for Ledger hardware wallets.
///
/// Implements the [`Transport`] trait by wrapping raw bytes into
/// Ledger APDU commands (CLA=0xE0, INS=0x40) fragmented over
/// 64-byte USB HID packets.
pub struct LedgerTransport {
    device: hidapi::HidDevice,
    timeout_ms: i32,
    /// Buffer for reassembling HWP response data from APDU responses.
    response_buf: Vec<u8>,
    response_pos: usize,
}

impl LedgerTransport {
    /// Open the first available Ledger device.
    pub fn open() -> Result<Self> {
        // Long timeout: cx_bn Pallas scalar multiplication on Cortex-M33 takes ~90s,
        // and signing involves 2 multiplications + key derivation + nonce generation.
        // Total can be ~250s. Use 600s to be safe.
        Self::open_with_timeout(Duration::from_secs(600))
    }

    /// Open the first available Ledger device with a custom timeout.
    pub fn open_with_timeout(timeout: Duration) -> Result<Self> {
        let api = hidapi::HidApi::new()
            .map_err(|e| HwSignerError::ConnectionFailed(format!("HID init: {}", e)))?;

        // Find the Ledger device (interface 0 = APDU, interface 2 = FIDO)
        let device_info = api
            .device_list()
            .find(|d| d.vendor_id() == LEDGER_VID && d.interface_number() == 0)
            .ok_or_else(|| {
                HwSignerError::ConnectionFailed("No Ledger device found".to_string())
            })?;

        info!(
            "Ledger found: VID=0x{:04X} PID=0x{:04X} interface={}",
            device_info.vendor_id(),
            device_info.product_id(),
            device_info.interface_number()
        );

        let device = device_info
            .open_device(&api)
            .map_err(|e| HwSignerError::ConnectionFailed(format!("HID open: {}", e)))?;

        info!("Ledger HID opened (timeout={}ms)", timeout.as_millis());
        Ok(Self {
            device,
            timeout_ms: timeout.as_millis() as i32,
            response_buf: Vec::new(),
            response_pos: 0,
        })
    }

    /// Send a single APDU command and return the response data.
    ///
    /// Handles Ledger HID framing: fragments the APDU into 64-byte
    /// HID packets with channel/tag/sequence headers.
    pub fn apdu_exchange(&self, cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Result<Vec<u8>> {
        // Build APDU: [CLA, INS, P1, P2, Lc, Data...]
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

        // Fragment APDU into HID packets and send
        self.hid_send(&apdu)?;

        // Read HID response packets and reassemble
        let response = self.hid_recv()?;

        // Response format: [data...][SW1][SW2]
        if response.len() < 2 {
            return Err(HwSignerError::TransportError(
                "APDU response too short".to_string(),
            ));
        }

        let sw = u16::from_be_bytes([response[response.len() - 2], response[response.len() - 1]]);
        let resp_data = &response[..response.len() - 2];

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

        Ok(resp_data.to_vec())
    }

    /// Fragment and send an APDU over HID packets.
    fn hid_send(&self, apdu: &[u8]) -> Result<()> {
        trace!("HID send: {} byte APDU", apdu.len());
        let mut offset = 0;
        let mut seq: u16 = 0;

        while offset < apdu.len() {
            let mut packet = [0u8; 1 + HID_PACKET_SIZE]; // +1 for HID report ID
            packet[0] = 0x00; // HID report ID
            packet[1] = (CHANNEL >> 8) as u8;
            packet[2] = (CHANNEL & 0xFF) as u8;
            packet[3] = TAG_APDU;
            packet[4] = (seq >> 8) as u8;
            packet[5] = (seq & 0xFF) as u8;

            let header_len = if seq == 0 {
                // First packet includes APDU length
                packet[6] = ((apdu.len() >> 8) & 0xFF) as u8;
                packet[7] = (apdu.len() & 0xFF) as u8;
                8 // report_id(1) + channel(2) + tag(1) + seq(2) + len(2)
            } else {
                6 // report_id(1) + channel(2) + tag(1) + seq(2)
            };

            let data_space = 1 + HID_PACKET_SIZE - header_len;
            let chunk_end = (offset + data_space).min(apdu.len());
            let chunk_len = chunk_end - offset;
            packet[header_len..header_len + chunk_len]
                .copy_from_slice(&apdu[offset..chunk_end]);

            self.device
                .write(&packet)
                .map_err(|e| HwSignerError::TransportError(format!("HID write: {}", e)))?;

            trace!("HID packet #{}: {} bytes data", seq, chunk_len);
            offset = chunk_end;
            seq += 1;
        }

        trace!("HID send complete: {} packet(s)", seq);
        Ok(())
    }

    /// Read HID packets and reassemble the APDU response.
    fn hid_recv(&self) -> Result<Vec<u8>> {
        trace!("HID recv: waiting for response...");
        let mut response = Vec::new();
        let mut expected_len: Option<usize> = None;
        let mut seq: u16 = 0;

        loop {
            let mut packet = [0u8; HID_PACKET_SIZE];
            let n = self
                .device
                .read_timeout(&mut packet, self.timeout_ms)
                .map_err(|e| HwSignerError::TransportError(format!("HID read: {}", e)))?;

            if n == 0 {
                return Err(HwSignerError::Timeout);
            }

            // Verify header
            let pkt_channel = u16::from_be_bytes([packet[0], packet[1]]);
            let pkt_tag = packet[2];
            let pkt_seq = u16::from_be_bytes([packet[3], packet[4]]);

            if pkt_channel != CHANNEL || pkt_tag != TAG_APDU || pkt_seq != seq {
                trace!("HID skip packet: ch=0x{:04X} tag=0x{:02X} seq={}", pkt_channel, pkt_tag, pkt_seq);
                continue;
            }

            let data_offset = if seq == 0 {
                // First packet has response length
                let resp_len = u16::from_be_bytes([packet[5], packet[6]]) as usize;
                expected_len = Some(resp_len);
                7 // channel(2) + tag(1) + seq(2) + len(2)
            } else {
                5 // channel(2) + tag(1) + seq(2)
            };

            let total_len = expected_len.unwrap_or(0);
            let remaining = total_len - response.len();
            let available = (HID_PACKET_SIZE - data_offset).min(remaining);
            response.extend_from_slice(&packet[data_offset..data_offset + available]);

            if response.len() >= total_len {
                break;
            }
            seq += 1;
        }

        trace!("HID recv complete: {} bytes in {} packet(s)", response.len(), seq + 1);
        Ok(response)
    }
}

impl Transport for LedgerTransport {
    fn requires_handshake(&self) -> bool {
        false
    }

    /// Send HWP frame bytes to the Ledger device.
    ///
    /// Wraps the data in APDU commands (CLA=0xE0, INS=0x40).
    /// Large frames are chunked into 250-byte APDU segments
    /// (P1=0x80 for continuation, P1=0x00 for the last chunk).
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

            let resp = self.apdu_exchange(CLA, INS_HWP_DATA, p1, 0x00, &data[offset..chunk_end])?;

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

    /// Read HWP response bytes from the last APDU exchange.
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
