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
// `hanh` (legacy hhanh00 Ledger app protocol stub) removed in audit follow-up:
// the implementation had unresolved endianness issues in the action encoder
// and was never wire-compatible with the upstream Ledger app. See
// docs/security-audit/04-host-sdk-rust.md L1.

pub use hwp::{
    ErrorCode, HwpCodec, Frame, MsgType, HWP_HEADER_SIZE, HWP_MAGIC, HWP_MAX_PAYLOAD,
    HWP_VERSION,
};
