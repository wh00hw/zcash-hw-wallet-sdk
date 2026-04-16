//! Native APDU definitions for Hahn's zcash-ledger app.
//!
//! This module defines the raw APDU constants and structures expected by
//! the Ledger app developed on the `hanh` branch of `zcash-ledger`.

pub const CLA: u8 = 0xE0;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    GetVersion = 0x03,
    GetAppName = 0x04,
    Initialize = 0x05,
    GetPubkey = 0x06,
    GetFvk = 0x07,
    GetOfvk = 0x08,
    GetProofgenKey = 0x09,
    HasOrchard = 0x0A,
    InitTx = 0x10,
    ChangeStage = 0x11,
    AddTIn = 0x12,
    AddTOut = 0x13,
    AddSOut = 0x14,
    AddOAction = 0x15,
    SetSNet = 0x16,
    SetONet = 0x17,
    SetHeaderDigest = 0x18,
    SetTMerkleProof = 0x19,
    SetSMerkleProof = 0x1A,
    SetOMerkleProof = 0x1B,
    ConfirmFee = 0x1C,
    SignTransparent = 0x21,
    SignSapling = 0x22,
    SignOrchard = 0x23,
    GetSSighash = 0x24,
    EndTx = 0x30,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningStage {
    Idle = 0,
    TIn = 1,
    TOut = 2,
    SOut = 3,
    OAction = 4,
    Fee = 5,
    Sign = 6,
}
