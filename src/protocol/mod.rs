//! Hardware Wallet Protocol (HWP) v2 — Binary framed serial protocol.
//!
//! This module implements the HWP wire protocol used for communication
//! between companion software and hardware signing devices.
//!
//! The protocol is transport-agnostic and designed for constrained devices.
//! It supports staged transaction verification inspired by zcash-ledger's
//! Merkle proof approach — outputs are sent individually and hashed
//! incrementally on-device to verify sighash integrity.
//!
//! Frame format: `[MAGIC:1][VERSION:1][SEQ:1][TYPE:1][LENGTH:2 LE][PAYLOAD:N][CRC16:2 LE]`

pub mod hwp;
pub mod hanh;

pub use hwp::{
    ErrorCode, HwpCodec, Frame, MsgType, HWP_HEADER_SIZE, HWP_MAGIC, HWP_MAX_PAYLOAD,
    HWP_VERSION,
};
