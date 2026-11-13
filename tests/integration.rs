//! Integration tests — validate SDK against the virtual device (libzcash-ironwood-c).
//!
//! v6-only (NU6.3 / NU7): the strict device accepts only the 170-byte v6
//! TxMeta and the pool-tagged 1416-byte memo-carrying action payload:
//! every output — zero-value padding included — must arrive with its memo
//! and pass the on-device note re-encryption. Transparent inputs are
//! refused (transparent outputs are fine). The fixtures are REAL transactions, built
//! with `zcash_primitives` / `orchard` for the virtual device's own full
//! viewing key (so that "change" really is the device's change), and turned
//! into PCZTs. Nothing here is hand-filled filler bytes any more.
//!
//! Two ways of driving the device:
//!
//!   * the whole production workflow (`PcztHardwareSigning`), which also
//!     proves the bundle — slow in the test profile, so only the two
//!     end-to-end tests (Ironwood -> Ironwood, turnstile) do it;
//!   * the public device API one level down (`DeviceSigner::
//!     verify_transaction` / `sign_action`), fed with exactly what the
//!     workflow derives from a PCZT (see `wire_from_pczt`), or raw HWP
//!     frames through `HwpCodec` where a well-behaved host cannot express
//!     the attack. No proof is needed there: the sighash does not cover it.
//!
//! What the "user" was shown is read back from the virtual device's control
//! port (the same `[ui] ...` lines it prints on stdout), and the simulated
//! user is told there to refuse a given screen.
//!
//! Requires the virtual device running on TCP (default: 127.0.0.1:9999,
//! control port = that port + 1).
//! Set VIRTUAL_DEVICE_ADDR (and, if moved, VIRTUAL_DEVICE_CTRL_ADDR) to
//! override.
//!
//! Run: VIRTUAL_DEVICE_ADDR=127.0.0.1:9999 cargo test --test integration --features tcp -- --test-threads=1
//!
//! A test named `device_bug_*` asserts behaviour the device SHOULD have and
//! currently does not: it is expected to fail until the C library is fixed,
//! and is not to be "fixed" here.

#![cfg(feature = "tcp")]

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};

use ff::PrimeField;
use incrementalmerkletree::{Hashable, Level};
use orchard::keys::{FullViewingKey, OutgoingViewingKey, Scope};
use orchard::note::{ExtractedNoteCommitment, NoteVersion, RandomSeed, Rho};
use orchard::tree::{MerkleHashOrchard, MerklePath};
use pczt::roles::{creator::Creator, io_finalizer::IoFinalizer};
use rand::rngs::SysRng;
use rand_core::{Rng, UnwrapErr};
use zcash_address::unified::{self, Encoding};
use zcash_hw_wallet_sdk::error::HwSignerError;
use zcash_hw_wallet_sdk::protocol::hwp::encode_frame;
use zcash_hw_wallet_sdk::protocol::{HwpCodec, MsgType};
use zcash_hw_wallet_sdk::signer::DeviceSigner;
use zcash_hw_wallet_sdk::traits::HardwareSigner;
use zcash_hw_wallet_sdk::transport::{TcpTransport, Transport};
use zcash_hw_wallet_sdk::types::{
    ActionData, ShieldedPoolKind, SignRequest, TransparentInputData, TransparentOutputData,
    TxDetails, TxMeta, COIN_TYPE_MAINNET, COIN_TYPE_TESTNET,
};
use zcash_hw_wallet_sdk::PcztHardwareSigning;
use zcash_primitives::transaction::{
    builder::{BuildConfig, Builder, BundlePadding, PcztResult},
    fees::zip317,
};
use zcash_protocol::consensus::{BlockHeight, BranchId, NetworkType, MAIN_NETWORK};
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;
use zcash_transparent::address::TransparentAddress;

/// Expected FVK components for coin_type=133 (mainnet), "abandon...about" mnemonic.
/// From libzcash-ironwood-c/tests/test_vectors.h
const EXPECTED_AK: [u8; 32] = [
    0x4c, 0x9c, 0x06, 0x6f, 0x08, 0x1a, 0x62, 0xec, 0xeb, 0x7b, 0xf8, 0x19, 0x5e, 0x44, 0x23,
    0x52, 0xfa, 0xb1, 0xfd, 0xbe, 0x57, 0x74, 0xb3, 0xfc, 0xe5, 0xee, 0x63, 0x57, 0xe2, 0x01,
    0x79, 0x0c,
];
const EXPECTED_NK: [u8; 32] = [
    0xc5, 0x9c, 0x63, 0xef, 0x35, 0x13, 0x79, 0xe9, 0x43, 0x86, 0x26, 0xc1, 0xce, 0x72, 0x0f,
    0x32, 0x33, 0xaf, 0x7a, 0x3b, 0xef, 0x8c, 0x2f, 0x2a, 0x7f, 0xc7, 0x44, 0x71, 0xdd, 0x5b,
    0x13, 0x3a,
];
const EXPECTED_RIVK: [u8; 32] = [
    0x99, 0x45, 0xa0, 0x45, 0xcd, 0x6e, 0x9c, 0xa8, 0xd8, 0x27, 0xd0, 0x39, 0xa5, 0x9a, 0x6d,
    0xc3, 0x3d, 0x19, 0x95, 0xcc, 0x42, 0x9b, 0x3d, 0xe8, 0x87, 0xd4, 0x76, 0x94, 0xa4, 0x9f,
    0x88, 0x3e,
];

/// Consensus branch IDs of the two upgrades that use the v6 format.
const BRANCH_NU6_3: u32 = 0x37a5_165b;
const BRANCH_NU7: u32 = 0x7719_0ad9;

/// Mainnet heights at which each of them is the active branch
/// (NU6.3 activates at 3,428,143, NU7 at 3,543,405).
const HEIGHT_NU6_3: u32 = 3_500_000;
const HEIGHT_NU7: u32 = 3_600_000;

// ── Connecting ───────────────────────────────────────────────────────

fn device_addr() -> String {
    std::env::var("VIRTUAL_DEVICE_ADDR").unwrap_or_else(|_| "127.0.0.1:9999".to_string())
}

/// The virtual device's control port: HWP port + 1 unless overridden.
fn control_addr() -> String {
    if let Ok(a) = std::env::var("VIRTUAL_DEVICE_CTRL_ADDR") {
        return a;
    }
    let addr = device_addr();
    let (host, port) = addr.rsplit_once(':').expect("VIRTUAL_DEVICE_ADDR must be host:port");
    let port: u16 = port.parse().expect("VIRTUAL_DEVICE_ADDR port");
    format!("{}:{}", host, port + 1)
}

fn connect_signer(coin_type: u32) -> DeviceSigner<TcpTransport> {
    ui_defaults();
    let transport =
        TcpTransport::connect(&device_addr()).expect("Failed to connect to virtual device");
    DeviceSigner::new(transport, coin_type).expect("Handshake failed")
}

fn connect_codec() -> HwpCodec<TcpTransport> {
    ui_defaults();
    let transport =
        TcpTransport::connect(&device_addr()).expect("Failed to connect to virtual device");
    let mut codec = HwpCodec::new(transport);
    codec.handshake().expect("Handshake failed");
    codec
}

// ── The device's screen, read back over the control port ─────────────

/// One command to the virtual device's control port; returns its reply
/// lines (`LOG`: the transcript, without the terminating "."; anything
/// else: the single status line).
fn control(cmd: &str) -> Vec<String> {
    let addr = control_addr();
    let stream = std::net::TcpStream::connect(&addr).unwrap_or_else(|e| {
        panic!(
            "cannot reach the virtual device's control port at {} ({}): \
             start it without --no-control, or set VIRTUAL_DEVICE_CTRL_ADDR",
            addr, e
        )
    });
    let mut w = stream.try_clone().expect("clone control stream");
    writeln!(w, "{}", cmd).expect("control write");
    let mut out = Vec::new();
    for line in BufReader::new(stream).lines() {
        let line = line.expect("control read");
        if cmd == "LOG" {
            if line == "." {
                break;
            }
            out.push(line);
        } else {
            out.push(line);
            break;
        }
    }
    out
}

fn control_ok(cmd: &str) {
    assert_eq!(control(cmd), vec!["OK".to_string()], "control command {:?}", cmd);
}

/// Every test starts with a user who approves everything, and a device that
/// does not linger on its "done" screen (the dispatcher asks for 2.5 s).
fn ui_defaults() {
    control_ok("REJECT none");
    control_ok("MAXSLEEP 50");
}

/// Forget what was shown so far.
fn ui_clear() {
    control_ok("CLEAR");
}

/// Make the simulated user refuse one screen, once:
/// `output:N`, `memo:N`, `totals` or `confirm`.
fn ui_reject_at(step: &str) {
    control_ok(&format!("REJECT {}", step));
}

/// One `[ui] <name> key=value ...` line of the device's screen transcript.
#[derive(Debug, Clone)]
struct Screen {
    name: String,
    fields: HashMap<String, String>,
}

impl Screen {
    fn parse(line: &str) -> Screen {
        let rest = line.strip_prefix("[ui] ").unwrap_or_else(|| panic!("not a ui line: {}", line));
        let (name, mut rest) = rest.split_once(' ').unwrap_or((rest, ""));
        let mut fields = HashMap::new();
        while !rest.is_empty() {
            let (key, after) = rest.split_once('=').unwrap_or_else(|| panic!("bad ui line: {}", line));
            let (value, tail) = if let Some(quoted) = after.strip_prefix('"') {
                let end = quoted.find('"').unwrap_or_else(|| panic!("bad ui line: {}", line));
                (&quoted[..end], quoted[end + 1..].trim_start())
            } else {
                after.split_once(' ').unwrap_or((after, ""))
            };
            fields.insert(key.to_string(), value.to_string());
            rest = tail;
        }
        Screen { name: name.to_string(), fields }
    }

    fn get(&self, key: &str) -> &str {
        self.fields
            .get(key)
            .unwrap_or_else(|| panic!("screen {:?} has no field {}", self, key))
    }

    fn num(&self, key: &str) -> u64 {
        self.get(key).parse().unwrap_or_else(|_| panic!("{}: not a number in {:?}", key, self))
    }

    fn approved(&self) -> bool {
        self.get("decision") == "ok"
    }
}

/// What the device has shown since the last `ui_clear()`, without the
/// session open/close markers.
fn ui_screens() -> Vec<Screen> {
    control("LOG")
        .iter()
        .map(|l| Screen::parse(l))
        .filter(|s| s.name != "session")
        .collect()
}

fn screens_named<'a>(screens: &'a [Screen], name: &str) -> Vec<&'a Screen> {
    screens.iter().filter(|s| s.name == name).collect()
}

/// The output screens shown, as (kind, address, value), after checking
/// that they are numbered 1..=n of n.
fn shown_outputs(screens: &[Screen]) -> Vec<(String, String, u64)> {
    let outs = screens_named(screens, "review_output");
    for (i, o) in outs.iter().enumerate() {
        assert_eq!(o.num("index"), i as u64 + 1, "output numbering: {:?}", outs);
        assert_eq!(o.num("total"), outs.len() as u64, "output total: {:?}", outs);
    }
    outs.iter()
        .map(|o| (o.get("kind").to_string(), o.get("address").to_string(), o.num("value")))
        .collect()
}

/// The single totals screen of a review.
fn shown_totals(screens: &[Screen]) -> Screen {
    let t = screens_named(screens, "review_totals");
    assert_eq!(t.len(), 1, "expected exactly one totals screen: {:?}", screens);
    t[0].clone()
}

/// Assert the device showed nothing at all (no output, memo, totals or
/// confirmation screen).
fn assert_nothing_shown(context: &str) {
    let screens = ui_screens();
    assert!(screens.is_empty(), "{}: the device showed {:?}", context, screens);
}

// ── Keys and addresses ───────────────────────────────────────────────

/// The virtual device's own Orchard full viewing key.
fn device_fvk(signer: &mut DeviceSigner<TcpTransport>) -> FullViewingKey {
    signer
        .export_fvk()
        .expect("FVK export failed")
        .to_orchard_fvk()
        .expect("valid Orchard FVK")
}

/// Somebody else's wallet.
fn foreign_fvk(tag: u8) -> FullViewingKey {
    let mut bytes = [0u8; 32];
    for b in tag..=255 {
        bytes[0] = b;
        bytes[31] = 0x07;
        if let Some(sk) = Option::<orchard::keys::SpendingKey>::from(
            orchard::keys::SpendingKey::from_bytes(bytes),
        ) {
            return FullViewingKey::from(&sk);
        }
    }
    unreachable!("no valid spending key found");
}

fn foreign_address(tag: u8) -> orchard::Address {
    foreign_fvk(tag).address_at(0u32, Scope::External)
}

/// Orchard-only unified address (mainnet), the form the device renders.
fn ua(addr: &orchard::Address) -> String {
    unified::Address::try_from_items(
        unified::Revision::R0,
        vec![unified::Uitem::Data(unified::Receiver::Orchard(
            addr.to_raw_address_bytes(),
        ))],
    )
    .expect("orchard-only UA")
    .encode(&NetworkType::Main)
}

/// Mainnet P2PKH t-address for a public key hash.
fn taddr(pkh: [u8; 20]) -> String {
    use zcash_address::{ToAddress, ZcashAddress};
    ZcashAddress::from_transparent_p2pkh(NetworkType::Main, pkh).encode()
}

fn text_memo(text: &str) -> MemoBytes {
    MemoBytes::from_bytes(text.as_bytes()).expect("memo")
}

// ── Real transactions ────────────────────────────────────────────────

/// One Ironwood output of a transaction under construction.
#[derive(Clone)]
struct Out {
    to: orchard::Address,
    value: u64,
    memo: MemoBytes,
    /// The outgoing viewing key the output is encrypted to. A wallet uses
    /// its external OVK for payments and its internal OVK for change.
    ovk: Option<OutgoingViewingKey>,
}

/// A transaction that spends one note of the device's wallet.
struct TxSpec {
    /// Target height: selects the consensus branch (NU6.3 or NU7).
    height: u32,
    /// Pool of the spent note: `Orchard` makes it a turnstile transaction
    /// (sealed Orchard pool -> Ironwood), `Ironwood` an Ironwood -> Ironwood.
    spend_pool: ShieldedPoolKind,
    note_value: u64,
    outputs: Vec<Out>,
    /// Transparent P2PKH outputs: (public key hash, value).
    t_outputs: Vec<([u8; 20], u64)>,
    /// A transparent P2PKH coin of this value to spend as well.
    t_input: Option<u64>,
}

impl TxSpec {
    fn ironwood(height: u32, note_value: u64, outputs: Vec<Out>) -> TxSpec {
        TxSpec {
            height,
            spend_pool: ShieldedPoolKind::Ironwood,
            note_value,
            outputs,
            t_outputs: Vec::new(),
            t_input: None,
        }
    }
}

/// A payment to `to`, encrypted to the wallet's external OVK.
fn pay(fvk: &FullViewingKey, to: orchard::Address, value: u64, memo: MemoBytes) -> Out {
    Out { to, value, memo, ovk: Some(fvk.to_ovk(Scope::External)) }
}

/// Change to the wallet's internal address, encrypted to its internal OVK
/// (`OvkPolicy::Sender`), exactly as a wallet builds it.
fn change(fvk: &FullViewingKey, value: u64) -> Out {
    Out {
        to: fvk.address_at(0u32, Scope::Internal),
        value,
        memo: MemoBytes::empty(),
        ovk: Some(fvk.to_ovk(Scope::Internal)),
    }
}

/// Build the transaction with the upstream builder and turn it into a PCZT
/// (Creator + IO finalizer), unproven and without spend authorization.
///
/// The spent note pays the device's default address and is the only leaf
/// of its pool's note commitment tree (position 0: every sibling on the
/// path is an empty subtree root).
fn build_pczt(fvk: &FullViewingKey, spec: &TxSpec) -> pczt::Pczt {
    let mut rng = UnwrapErr(SysRng);
    let version = match spec.spend_pool {
        ShieldedPoolKind::Orchard => NoteVersion::V2,
        ShieldedPoolKind::Ironwood => NoteVersion::V3,
    };
    let owner = fvk.address_at(0u32, Scope::External);
    let note: orchard::Note = loop {
        let mut rho_bytes = [0u8; 32];
        let mut rseed_bytes = [0u8; 32];
        rng.fill_bytes(&mut rho_bytes);
        rng.fill_bytes(&mut rseed_bytes);
        let Some(rho) = Option::<Rho>::from(Rho::from_bytes(&rho_bytes)) else {
            continue;
        };
        let Some(rseed) = Option::<RandomSeed>::from(RandomSeed::from_bytes(rseed_bytes, &rho))
        else {
            continue;
        };
        if let Some(note) = Option::<orchard::Note>::from(orchard::Note::from_parts(
            owner,
            orchard::value::NoteValue::from_raw(spec.note_value),
            rho,
            rseed,
            version,
        )) {
            break note;
        }
    };
    let cmx: ExtractedNoteCommitment = note.commitment().into();
    let mut auth_path = [MerkleHashOrchard::empty_leaf(); 32];
    for (level, sibling) in auth_path.iter_mut().enumerate() {
        *sibling = MerkleHashOrchard::empty_root(Level::from(level as u8));
    }
    let merkle_path = MerklePath::from_parts(0, auth_path);
    let anchor = merkle_path.root(cmx);

    let (orchard_anchor, ironwood_anchor) = match spec.spend_pool {
        ShieldedPoolKind::Orchard => (Some(anchor), Some(orchard::Anchor::empty_tree())),
        ShieldedPoolKind::Ironwood => (None, Some(anchor)),
    };
    let mut builder = Builder::new(
        MAIN_NETWORK,
        BlockHeight::from_u32(spec.height),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor,
            ironwood_anchor,
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    match spec.spend_pool {
        ShieldedPoolKind::Orchard => builder
            .add_orchard_spend::<zip317::FeeRule>(fvk.clone(), note, merkle_path)
            .expect("add_orchard_spend"),
        ShieldedPoolKind::Ironwood => builder
            .add_ironwood_spend::<zip317::FeeRule>(fvk.clone(), note, merkle_path)
            .expect("add_ironwood_spend"),
    }
    for out in &spec.outputs {
        builder
            .add_ironwood_output::<zip317::FeeRule>(
                out.ovk.clone(),
                out.to,
                Zatoshis::const_from_u64(out.value),
                out.memo.clone(),
            )
            .expect("add_ironwood_output");
    }
    for (pkh, value) in &spec.t_outputs {
        builder
            .add_transparent_output(
                &TransparentAddress::PublicKeyHash(*pkh),
                Zatoshis::const_from_u64(*value),
            )
            .expect("add_transparent_output");
    }
    if let Some(value) = spec.t_input {
        // A coin of an unrelated key (the secp256k1 generator as the public
        // key): the shielded sighash only depends on the coin's outpoint,
        // value and script.
        let pubkey = secp256k1::PublicKey::from_slice(&[
            0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce,
            0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81,
            0x5b, 0x16, 0xf8, 0x17, 0x98,
        ])
        .expect("generator pubkey");
        let coin = zcash_transparent::bundle::TxOut::new(
            Zatoshis::const_from_u64(value),
            TransparentAddress::from_pubkey(&pubkey).script().into(),
        );
        builder
            .add_transparent_p2pkh_input(
                pubkey,
                zcash_transparent::bundle::OutPoint::new([0x42; 32], 1),
                coin,
            )
            .expect("add_transparent_p2pkh_input");
    }
    let PcztResult { pczt_parts, .. } = builder
        .build_for_pczt(&mut rng, &zip317::FeeRule::standard())
        .expect("build_for_pczt");
    IoFinalizer::new(Creator::build_from_parts(pczt_parts).expect("creator"))
        .finalize_io(&mut rng)
        .expect("io finalizer")
}

/// A spend the device has to authorize.
#[derive(Clone)]
struct SpendToSign {
    alpha: [u8; 32],
    rk: [u8; 32],
}

/// What the host sends the device for one PCZT: exactly what
/// `PcztHardwareSigning` derives (TxMeta from the transaction effects,
/// one `ActionData` per action with the note plaintext rebuilt from the
/// PCZT, the shielded sighash from `pczt`, the transparent outputs) —
/// minus the proof, which no device check depends on. (Transparent inputs
/// are carried too, for the tests that check they are refused.)
#[derive(Clone)]
struct Wire {
    meta: TxMeta,
    /// Sealed-Orchard actions first, then Ironwood, as the host sends them.
    actions: Vec<ActionData>,
    sighash: [u8; 32],
    t_inputs: Vec<TransparentInputData>,
    t_outputs: Vec<TransparentOutputData>,
    spends: Vec<SpendToSign>,
}

fn wire_from_pczt(pczt: &pczt::Pczt, _fvk: &FullViewingKey) -> Wire {
    fn collect(
        pool: ShieldedPoolKind,
        bundle: &orchard::pczt::Bundle,
        pczt_actions: &[pczt::orchard::Action],
        actions: &mut Vec<ActionData>,
        spends: &mut Vec<SpendToSign>,
    ) {
        use orchard::note_encryption::{IronwoodDomain, OrchardDomain};
        use zcash_note_encryption::{try_output_recovery_with_pkd_esk, Domain};
        for (i, action) in bundle.actions().iter().enumerate() {
            let spend = action.spend();
            let rk = <[u8; 32]>::from(spend.rk().clone());
            if let (Some(alpha), None) = (spend.alpha(), spend.spend_auth_sig()) {
                spends.push(SpendToSign { alpha: alpha.to_repr(), rk });
            }
            let out = pczt_actions[i].output();
            let recipient: [u8; 43] = out.recipient().expect("PCZT output recipient");
            let value: u64 = out.value().expect("PCZT output value");
            let rseed: [u8; 32] = out.rseed().expect("PCZT output rseed");
            let enc_note = action.output().encrypted_note();

            // The note the PCZT describes, its esk (from rseed and rho), and
            // with (pk_d, esk) the plaintext — memo included — of every
            // output that has one: payment, change and zero-value padding.
            let rho = Option::<Rho>::from(Rho::from_bytes(&spend.nullifier().to_bytes())).unwrap();
            let note = Option::<orchard::Note>::from(orchard::Note::from_parts(
                Option::from(orchard::Address::from_raw_address_bytes(&recipient)).unwrap(),
                orchard::value::NoteValue::from_raw(value),
                rho,
                Option::from(RandomSeed::from_bytes(rseed, &rho)).unwrap(),
                match pool {
                    ShieldedPoolKind::Orchard => NoteVersion::V2,
                    ShieldedPoolKind::Ironwood => NoteVersion::V3,
                },
            ))
            .expect("PCZT note");
            let memo: [u8; 512] = match pool {
                ShieldedPoolKind::Orchard => try_output_recovery_with_pkd_esk(
                    &OrchardDomain::for_pczt_action(action),
                    OrchardDomain::get_pk_d(&note),
                    OrchardDomain::derive_esk(&note).unwrap(),
                    action,
                )
                .map(|(_, _, memo)| memo),
                ShieldedPoolKind::Ironwood => try_output_recovery_with_pkd_esk(
                    &IronwoodDomain::for_pczt_action(action),
                    IronwoodDomain::get_pk_d(&note),
                    IronwoodDomain::derive_esk(&note).unwrap(),
                    action,
                )
                .map(|(_, _, memo)| memo),
            }
            // The one exception, by upstream design: in the sealed Orchard
            // pool the zero-value output the builder pairs with an
            // external-scope spend has a RANDOM enc_ciphertext
            // (orchard::builder `fabricated_for_spend`). Nobody can open or
            // reproduce it; host and tests declare 512 zero bytes of memo,
            // and the device tolerates the mismatch under narrow conditions
            // (see `sec_randomized_ciphertext_exception_cannot_be_abused`).
            .unwrap_or_else(|| {
                assert_eq!((pool, value), (ShieldedPoolKind::Orchard, 0), "unopenable output");
                [0u8; 512]
            });
            actions.push(ActionData {
                pool,
                cv_net: action.cv_net().to_bytes(),
                nullifier: spend.nullifier().to_bytes(),
                rk,
                cmx: action.output().cmx().to_bytes(),
                ephemeral_key: enc_note.epk_bytes,
                enc_ciphertext: enc_note.enc_ciphertext.0.to_vec(),
                out_ciphertext: enc_note.out_ciphertext.to_vec(),
                recipient,
                value,
                rseed,
                memo: Some(memo),
            });
        }
    }

    let mut actions = Vec::new();
    let mut spends = Vec::new();
    let orchard_actions = pczt.orchard().actions().clone();
    let ironwood_actions = pczt.ironwood().actions().clone();
    let low = pczt::roles::low_level_signer::Signer::new(pczt.clone());
    let low = low
        .sign_orchard_with(|_, bundle, _| -> Result<(), HwSignerError> {
            collect(ShieldedPoolKind::Orchard, bundle, &orchard_actions, &mut actions, &mut spends);
            Ok(())
        })
        .expect("orchard bundle");
    let _ = low
        .sign_ironwood_with(|_, bundle, _| -> Result<(), HwSignerError> {
            collect(ShieldedPoolKind::Ironwood, bundle, &ironwood_actions, &mut actions, &mut spends);
            Ok(())
        })
        .expect("ironwood bundle");

    let t = pczt.transparent();
    Wire {
        meta: TxMeta::from_pczt(pczt, COIN_TYPE_MAINNET).expect("TxMeta"),
        actions,
        sighash: pczt::roles::signer::Signer::new(pczt.clone())
            .expect("signer role")
            .shielded_sighash(),
        t_inputs: t
            .inputs()
            .iter()
            .map(|i| TransparentInputData {
                prevout_hash: *i.prevout_txid(),
                prevout_index: *i.prevout_index(),
                sequence: i.sequence().unwrap_or(0xFFFF_FFFF),
                value: *i.value(),
                script_pubkey: i.script_pubkey().clone(),
            })
            .collect(),
        t_outputs: t
            .outputs()
            .iter()
            .map(|o| TransparentOutputData {
                value: *o.value(),
                script_pubkey: o.script_pubkey().clone(),
            })
            .collect(),
        spends,
    }
}

impl Wire {
    fn n(&self) -> u16 {
        self.actions.len() as u16
    }

    /// Index (in wire order) of the action whose output pays `addr`.
    fn index_of(&self, addr: &orchard::Address) -> usize {
        let raw = addr.to_raw_address_bytes();
        self.actions
            .iter()
            .position(|a| a.recipient == raw)
            .expect("no action pays that address")
    }

    /// Hand the whole transaction to the device the way the workflow does.
    fn verify(&self, signer: &mut DeviceSigner<TcpTransport>) -> Result<(), HwSignerError> {
        signer.verify_transaction(
            &self.meta,
            &self.actions,
            &self.sighash,
            &self.t_inputs,
            &self.t_outputs,
        )
    }

    /// RAW FRAMES: metadata, transparent inputs, transparent outputs,
    /// transparent digest sentinel, actions, sighash sentinel, written
    /// through the codec. For transactions with transparent INPUTS, which
    /// `DeviceSigner` refuses to send (`TransparentInputsNotSupported`) and
    /// the device refuses to take.
    fn verify_raw(&self, codec: &mut HwpCodec<TcpTransport>) -> Result<(), HwSignerError> {
        self.send_meta(codec)?;
        if !self.t_inputs.is_empty() || !self.t_outputs.is_empty() {
            let n_in = self.t_inputs.len() as u16;
            for (i, input) in self.t_inputs.iter().enumerate() {
                codec.send_transparent_input(i as u16, n_in, &input.serialize())?;
            }
            for (i, output) in self.t_outputs.iter().enumerate() {
                codec.send_transparent_output(i as u16, self.t_outputs.len() as u16, &output.serialize())?;
            }
            codec.send_transparent_input(n_in, n_in, &self.meta.transparent_sig_digest)?;
        }
        for i in 0..self.actions.len() {
            self.send_action(codec, i)?;
        }
        self.send_sentinel(codec)
    }

    fn sign_request(&self, spend: usize, recipient: &str) -> SignRequest {
        SignRequest {
            sighash: self.sighash,
            alpha: self.spends[spend].alpha,
            // Deliberately absurd: the device ignores the amount, the fee
            // and the recipient of SIGN_REQ.
            amount: 21_000_000 * 100_000_000,
            fee: 1,
            recipient: recipient.to_string(),
            action_index: spend,
            total_actions: self.spends.len(),
        }
    }

    /// Ask for every spend authorization and check each signature against
    /// the sighash and the PCZT's rk. Returns how many were signed.
    fn sign_all(
        &self,
        signer: &mut DeviceSigner<TcpTransport>,
        recipient: &str,
    ) -> Result<usize, HwSignerError> {
        assert!(!self.spends.is_empty(), "nothing to sign in this fixture");
        for (i, spend) in self.spends.iter().enumerate() {
            let rsp = signer.sign_action(&self.sign_request(i, recipient))?;
            assert_eq!(rsp.rk, spend.rk, "device rk != PCZT rk");
            let rk = reddsa::VerificationKey::<reddsa::orchard::SpendAuth>::try_from(rsp.rk)
                .expect("rk should be a valid SpendAuth key");
            let sig = reddsa::Signature::<reddsa::orchard::SpendAuth>::from(rsp.signature);
            assert!(
                rk.verify(&self.sighash, &sig).is_ok(),
                "device signature does not verify against the sighash and rk"
            );
        }
        Ok(self.spends.len())
    }

    // Raw-frame pieces, for the tests that send what a well-behaved host
    // would not.
    fn send_meta(&self, codec: &mut HwpCodec<TcpTransport>) -> Result<(), HwSignerError> {
        codec.send_tx_output(0xFFFF, self.n(), &self.meta.serialize())
    }
    fn send_action(&self, codec: &mut HwpCodec<TcpTransport>, i: usize) -> Result<(), HwSignerError> {
        codec.send_tx_output(i as u16, self.n(), &self.actions[i].serialize_v6())
    }
    fn send_sentinel(&self, codec: &mut HwpCodec<TcpTransport>) -> Result<(), HwSignerError> {
        codec.send_tx_output(self.n(), self.n(), &self.sighash)
    }
}

/// The session holds no verified transaction: a SIGN_REQ is refused and
/// nothing is put on the screen for it.
fn assert_nothing_signable(signer: &mut DeviceSigner<TcpTransport>, w: &Wire, recipient: &str) {
    ui_clear();
    match signer.sign_action(&w.sign_request(0, recipient)) {
        Err(HwSignerError::DeviceError(msg)) => {
            assert!(msg.starts_with("InvalidState"), "unexpected refusal: {}", msg)
        }
        other => panic!("SIGN_REQ on a reset session must be refused, got {:?}", other),
    }
    assert_nothing_shown("SIGN_REQ on a reset session");
}

/// The standard fixture: an Ironwood -> Ironwood payment of 500,000 zat to
/// somebody else, with a text memo, and 490,000 zat of change back to the
/// device's wallet (fee 10,000: two logical actions).
const NOTE_VALUE: u64 = 1_000_000;
const PAY_VALUE: u64 = 500_000;
const FEE_2: u64 = 10_000;
const CHANGE_VALUE: u64 = NOTE_VALUE - PAY_VALUE - FEE_2;
const PAY_MEMO: &str = "invoice 42";

fn payment_with_change(fvk: &FullViewingKey, height: u32) -> (Wire, orchard::Address) {
    let to = foreign_address(1);
    let spec = TxSpec::ironwood(
        height,
        NOTE_VALUE,
        vec![pay(fvk, to, PAY_VALUE, text_memo(PAY_MEMO)), change(fvk, CHANGE_VALUE)],
    );
    (wire_from_pczt(&build_pczt(fvk, &spec), fvk), to)
}

/// BLAKE2b-256 with a 16-byte personalization.
fn blake2b_personal(personal: &[u8; 16], data: &[u8]) -> [u8; 32] {
    let h = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(personal)
        .hash(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    out
}

/// The ZIP-244 v6 (NU6.3 / NU7) five-leaf shielded sighash, computed here
/// from TxMeta + actions. Independent of both `zcash_primitives` and the C
/// library; used where a test changes the transaction after the PCZT was
/// built (a different branch ID, a synthetic transparent bundle).
fn compute_zip244_sighash(meta: &TxMeta, actions: &[ActionData]) -> [u8; 32] {
    compute_zip244_sighash_with(meta, actions, &meta.transparent_sig_digest)
}

/// Same, with the transparent leaf given explicitly (for the signature
/// hash of a transparent input, whose transparent leaf is not the txid
/// digest carried in TxMeta).
fn compute_zip244_sighash_with(
    meta: &TxMeta,
    actions: &[ActionData],
    transparent_digest: &[u8; 32],
) -> [u8; 32] {
    // 1. Header digest
    let mut hdr_data = Vec::new();
    hdr_data.extend_from_slice(&meta.version.to_le_bytes());
    hdr_data.extend_from_slice(&meta.version_group_id.to_le_bytes());
    hdr_data.extend_from_slice(&meta.consensus_branch_id.to_le_bytes());
    hdr_data.extend_from_slice(&meta.lock_time.to_le_bytes());
    hdr_data.extend_from_slice(&meta.expiry_height.to_le_bytes());
    let header_digest = blake2b_personal(b"ZTxIdHeadersHash", &hdr_data);

    // 2. One bundle digest per pool. The action-level personalizations of
    //    the sealed Orchard pool are the v5 ones; Ironwood has its own.
    //    Under v6 the anchor is not part of the bundle effects digest.
    fn pool_digest(
        actions: &[&ActionData],
        personal: [&[u8; 16]; 4],
        flags: u8,
        value_balance: i64,
    ) -> [u8; 32] {
        if actions.is_empty() {
            return blake2b_personal(personal[3], &[]);
        }
        let state = |p: &[u8; 16]| blake2b_simd::Params::new().hash_length(32).personal(p).to_state();
        let (mut compact, mut memos, mut noncompact) =
            (state(personal[0]), state(personal[1]), state(personal[2]));
        for a in actions {
            compact.update(&a.nullifier);
            compact.update(&a.cmx);
            compact.update(&a.ephemeral_key);
            compact.update(&a.enc_ciphertext[..52]);
            memos.update(&a.enc_ciphertext[52..564]);
            noncompact.update(&a.cv_net);
            noncompact.update(&a.rk);
            noncompact.update(&a.enc_ciphertext[564..580]);
            noncompact.update(&a.out_ciphertext);
        }
        let mut input = Vec::new();
        input.extend_from_slice(compact.finalize().as_bytes());
        input.extend_from_slice(memos.finalize().as_bytes());
        input.extend_from_slice(noncompact.finalize().as_bytes());
        input.push(flags);
        input.extend_from_slice(&value_balance.to_le_bytes());
        blake2b_personal(personal[3], &input)
    }
    let of_pool = |pool: ShieldedPoolKind| -> Vec<&ActionData> {
        actions.iter().filter(|a| a.pool == pool).collect()
    };
    let orchard_digest = pool_digest(
        &of_pool(ShieldedPoolKind::Orchard),
        [b"ZTxIdOrcActCHash", b"ZTxIdOrcActMHash", b"ZTxIdOrcActNHash", b"ZTxIdOrchardH_v6"],
        meta.orchard_flags,
        meta.value_balance,
    );
    let ironwood_digest = pool_digest(
        &of_pool(ShieldedPoolKind::Ironwood),
        [b"ZTxIdIrnActCH_v6", b"ZTxIdIrnActMH_v6", b"ZTxIdIrnActNH_v6", b"ZTxIdIronwd_H_v6"],
        meta.ironwood_flags,
        meta.ironwood_value_balance,
    );

    // 3. Root = BLAKE2b("ZcashTxHash_" || branch_id[4 LE],
    //        header || transparent || sapling || orchard || ironwood)
    let mut root_personal = [0u8; 16];
    root_personal[..12].copy_from_slice(b"ZcashTxHash_");
    root_personal[12..].copy_from_slice(&meta.consensus_branch_id.to_le_bytes());
    let mut root_input = Vec::new();
    root_input.extend_from_slice(&header_digest);
    root_input.extend_from_slice(transparent_digest);
    root_input.extend_from_slice(&meta.sapling_digest);
    root_input.extend_from_slice(&orchard_digest);
    root_input.extend_from_slice(&ironwood_digest);
    blake2b_personal(&root_personal, &root_input)
}

/// A synthetic v6 TxMeta for the tests that never get past the metadata or
/// the transparent digest (no shielded action is fed with it).
///
/// The strict v6-only device enforces the v6 header constants at
/// feed_meta time: version 0x80000006, version_group_id 0xD884B698,
/// orchard_flags with bit 2 clear, ironwood_flags within bits 0..2, and a
/// consensus branch ID from its allow-list.
fn build_test_tx_meta(coin_type: u32) -> TxMeta {
    TxMeta {
        version: 0x8000_0006,
        version_group_id: 0xD884B698,
        consensus_branch_id: BRANCH_NU6_3,
        lock_time: 0,
        expiry_height: 0,
        orchard_flags: 0x03, // spends + outputs enabled (no cross-address)
        value_balance: 0,
        anchor: [0xAA; 32],
        ironwood_flags: 0,
        ironwood_value_balance: 0,
        ironwood_anchor: [0u8; 32],
        transparent_sig_digest: blake2b_personal(b"ZTxIdTranspaHash", &[]),
        sapling_digest: blake2b_personal(b"ZTxIdSaplingHash", &[]),
        coin_type,
    }
}

// ── Group 1: Handshake ───────────────────────────────────────────────

#[test]
fn test_handshake() {
    let _signer = connect_signer(COIN_TYPE_MAINNET);
    // If we get here, PING/PONG succeeded
}

// ── Group 2: FVK Export ──────────────────────────────────────────────

#[test]
fn test_fvk_export_mainnet() {
    let mut signer = connect_signer(COIN_TYPE_MAINNET);
    let fvk = signer
        .export_fvk()
        .expect("FVK export failed");

    assert_eq!(fvk.ak, EXPECTED_AK, "ak mismatch");
    assert_eq!(fvk.nk, EXPECTED_NK, "nk mismatch");
    assert_eq!(fvk.rivk, EXPECTED_RIVK, "rivk mismatch");

    // Verify it parses as a valid Orchard FVK
    assert!(
        fvk.to_orchard_fvk().is_some(),
        "FVK should parse as valid Orchard FullViewingKey"
    );
}

/// The shipped virtual-device is single-network (mainnet by default,
/// `--coin 1` for testnet). The dispatcher's network check is enforced
/// at FVK_REQ time and a dispatcher instance can only serve one
/// network — switching mid-session would require either a key-
/// resolution callback in the HwpDispatcherKeys (so the device picks
/// the right pre-derived key set based on the request's coin_type) or
/// a second listening port + per-network worker thread. Both are
/// reasonable follow-ups; for now spawn a second virtual-device with
/// `--coin 1` on a different port and point this test at it.
#[test]
#[ignore = "needs dual-network virtual-device (--coin 1 on a 2nd port)"]
fn test_fvk_export_testnet() {
    let mut signer = connect_signer(COIN_TYPE_TESTNET);
    let fvk_testnet = signer
        .export_fvk()
        .expect("FVK export failed");

    assert_ne!(
        fvk_testnet.ak, EXPECTED_AK,
        "testnet ak should differ from mainnet"
    );
}

#[test]
fn test_fvk_export_twice_same_result() {
    let mut signer = connect_signer(COIN_TYPE_MAINNET);
    let fvk1 = signer
        .export_fvk()
        .expect("FVK export 1 failed");
    let fvk2 = signer
        .export_fvk()
        .expect("FVK export 2 failed");
    assert_eq!(fvk1.ak, fvk2.ak, "FVK should be deterministic");
}

// ── Group 3: ZIP-244 Sighash Verification ────────────────────────────

/// The test-side ZIP-244 implementation agrees with `zcash_primitives` on a
/// real transaction of each pool shape (host-only cross-check of the helper
/// the tests below rely on).
#[test]
fn test_sighash_helper_matches_zcash_primitives() {
    let mut signer = connect_signer(COIN_TYPE_MAINNET);
    let fvk = device_fvk(&mut signer);
    let (w, _) = payment_with_change(&fvk, HEIGHT_NU7);
    assert_eq!(compute_zip244_sighash(&w.meta, &w.actions), w.sighash);

    let turnstile = turnstile_spec(&fvk, HEIGHT_NU6_3, foreign_address(1));
    let w = wire_from_pczt(&build_pczt(&fvk, &turnstile), &fvk);
    assert_eq!(compute_zip244_sighash(&w.meta, &w.actions), w.sighash);
}

#[test]
fn test_sighash_valid() {
    let mut signer = connect_signer(COIN_TYPE_MAINNET);
    let fvk = device_fvk(&mut signer);
    let (w, _) = payment_with_change(&fvk, HEIGHT_NU6_3);
    assert_eq!(w.meta.consensus_branch_id, BRANCH_NU6_3);
    let codec = signer.codec_mut();

    // Metadata (index=0xFFFF), each action (memo-carrying body), then the
    // sentinel sighash (index == total).
    w.send_meta(codec).expect("TxMeta send failed");
    for i in 0..w.actions.len() {
        assert_eq!(w.actions[i].serialize_v6().len(), 1416);
        w.send_action(codec, i).expect("Action send failed");
    }
    w.send_sentinel(codec)
        .expect("Sighash sentinel failed — zcash_primitives and the device computed different sighashes!");
}

#[test]
fn test_sighash_mismatch() {
    let mut signer = connect_signer(COIN_TYPE_MAINNET);
    let fvk = device_fvk(&mut signer);
    let (w, to) = payment_with_change(&fvk, HEIGHT_NU6_3);
    let codec = signer.codec_mut();

    w.send_meta(codec).expect("TxMeta send failed");
    for i in 0..w.actions.len() {
        w.send_action(codec, i).expect("Action send failed");
    }

    // Send WRONG sighash
    let result = codec.send_tx_output(w.n(), w.n(), &[0xFF; 32]);
    assert!(
        matches!(result, Err(HwSignerError::SignatureVerificationFailed { .. })),
        "Wrong sighash should be rejected as a sighash mismatch, got {:?}",
        result
    );
    assert_nothing_signable(&mut signer, &w, &ua(&to));
}

#[test]
fn test_sighash_multi_action() {
    let mut signer = connect_signer(COIN_TYPE_MAINNET);
    let fvk = device_fvk(&mut signer);

    // Three real outputs (two payments + change) -> three actions, one real
    // spend and two dummy spends. Fee: 3 logical actions.
    let (a, b) = (foreign_address(1), foreign_address(2));
    let spec = TxSpec::ironwood(
        HEIGHT_NU6_3,
        NOTE_VALUE,
        vec![
            pay(&fvk, a, 300_000, MemoBytes::empty()),
            pay(&fvk, b, 200_000, MemoBytes::empty()),
            change(&fvk, NOTE_VALUE - 500_000 - 15_000),
        ],
    );
    let w = wire_from_pczt(&build_pczt(&fvk, &spec), &fvk);
    assert_eq!(w.actions.len(), 3);

    ui_clear();
    w.verify(&mut signer).expect("Multi-action sighash verification failed");

    let screens = ui_screens();
    let mut outs = shown_outputs(&screens);
    outs.sort();
    let mut expected = vec![
        ("external".to_string(), ua(&a), 300_000),
        ("external".to_string(), ua(&b), 200_000),
        ("own-change".to_string(), ua(&fvk.address_at(0u32, Scope::Internal)), 485_000),
    ];
    expected.sort();
    assert_eq!(outs, expected);
    let totals = shown_totals(&screens);
    assert_eq!(totals.num("total_leaving"), 500_000 + 15_000);
    assert_eq!(totals.num("fee"), 15_000);
    assert_eq!(totals.num("n_external"), 2);
}

// ── Group 4: Full Signing Flow ───────────────────────────────────────

#[test]
fn test_full_sign_flow() {
    let mut signer = connect_signer(COIN_TYPE_MAINNET);

    // 1. Export FVK
    let exported = signer.export_fvk().expect("FVK failed");
    assert_eq!(exported.ak, EXPECTED_AK);
    let fvk = exported.to_orchard_fvk().expect("valid FVK");

    // 2. Sighash verification
    let (w, to) = payment_with_change(&fvk, HEIGHT_NU6_3);
    w.verify(&mut signer).expect("Sighash verification failed");

    // 3. Sign: the signature verifies against the sighash and the rk of
    //    the PCZT's real spend (checked in sign_all).
    assert_eq!(w.spends.len(), 1, "one real spend");
    assert_eq!(w.sign_all(&mut signer, &ua(&to)).expect("Signing failed"), 1);
}

// ── Group 5: Network Discrimination ──────────────────────────────────

#[test]
fn test_network_mismatch() {
    let mut codec = connect_codec();

    // FvkReq with mainnet
    codec.request_fvk(COIN_TYPE_MAINNET).expect("FVK failed");

    // TxMeta with testnet coin_type — should trigger mismatch
    let meta = build_test_tx_meta(COIN_TYPE_TESTNET); // coin_type=1 vs session=133
    let meta_bytes = meta.serialize();

    let result = codec.send_tx_output(0xFFFF, 1, &meta_bytes);
    assert!(
        result.is_err(),
        "Network mismatch should be rejected by device"
    );
}

// ── Group 6: Error Handling ──────────────────────────────────────────

#[test]
fn test_sign_without_verification_rejected() {
    let mut codec = connect_codec();

    let sign_req = SignRequest {
        sighash: [0u8; 32],
        alpha: [0u8; 32],
        amount: 0,
        fee: 0,
        recipient: String::new(),
        action_index: 0,
        total_actions: 1,
    };

    let result = codec.sign(&sign_req);
    assert!(result.is_err(), "Sign without verification should fail");
}

#[test]
fn test_crc_error_recovery() {
    let transport =
        TcpTransport::connect(&device_addr()).expect("Failed to connect to virtual device");
    let mut codec = HwpCodec::new(transport);
    codec.handshake().expect("Handshake failed");

    // Send a frame with corrupted CRC by writing raw bytes
    let mut corrupt_frame = encode_frame(0x10, MsgType::Ping, &[]);
    // Flip CRC bytes
    let len = corrupt_frame.len();
    corrupt_frame[len - 1] ^= 0xFF;
    corrupt_frame[len - 2] ^= 0xFF;
    codec
        .transport_mut()
        .send(&corrupt_frame)
        .expect("Raw send failed");

    // Read error response
    let frame = codec.read_frame().expect("Should get error frame back");
    assert_eq!(frame.msg_type, MsgType::Error, "Expected error response");

    // Now send a valid FvkReq — device should have recovered
    let fvk = codec.request_fvk(COIN_TYPE_MAINNET);
    assert!(fvk.is_ok(), "Device should recover after CRC error");
}

#[test]
fn test_abort_resets_session() {
    let mut signer = connect_signer(COIN_TYPE_MAINNET);
    let fvk = device_fvk(&mut signer);
    let (w, _) = payment_with_change(&fvk, HEIGHT_NU6_3);
    let codec = signer.codec_mut();

    // Start a transaction: metadata and the first action.
    w.send_meta(codec).expect("TxMeta failed");
    w.send_action(codec, 0).expect("Action failed");

    // Abort the session
    codec
        .write_frame(0x50, MsgType::Abort, &[])
        .expect("Abort send failed");

    // Start a fresh verification — should work from clean state
    w.send_meta(codec).expect("TxMeta after abort should work");
    for i in 0..w.actions.len() {
        w.send_action(codec, i).expect("Action after abort should work");
    }
    w.send_sentinel(codec).expect("Sighash after abort should work");
}

#[test]
fn test_invalid_state_action_without_metadata() {
    let mut signer = connect_signer(COIN_TYPE_MAINNET);
    let fvk = device_fvk(&mut signer);
    let (w, _) = payment_with_change(&fvk, HEIGHT_NU6_3);

    // Send action data without prior metadata — should fail
    ui_clear();
    let result = w.send_action(signer.codec_mut(), 0);
    assert!(
        matches!(&result, Err(HwSignerError::DeviceError(m)) if m.starts_with("InvalidState")),
        "Action without metadata should be rejected, got {:?}",
        result
    );
    assert_nothing_shown("action without metadata");
}

// ── Group 6b: v6-only strict-tier enforcement ────────────────────────

/// The strict post-NU6.3 device rejects the legacy 129-byte v5 TxMeta
/// layout outright (Error/BAD_META — the parse accepts only 166/170 B).
/// The SDK can no longer produce this layout; hand-craft it the way a
/// legacy host would have.
#[test]
fn test_legacy_v5_tx_meta_rejected() {
    let mut codec = connect_codec();
    codec.request_fvk(COIN_TYPE_MAINNET).expect("FVK failed");

    // 129-byte v5 layout = v6 layout minus the 41-byte Ironwood section.
    let meta = build_test_tx_meta(COIN_TYPE_MAINNET);
    let v6_bytes = meta.serialize();
    assert_eq!(v6_bytes.len(), 170);
    let mut v5_bytes = Vec::with_capacity(129);
    v5_bytes.extend_from_slice(&v6_bytes[..61]); // header + Orchard section
    v5_bytes.extend_from_slice(&v6_bytes[102..]); // digests + coin_type
    assert_eq!(v5_bytes.len(), 129);
    // Legacy v5 header constants, as a pre-NU6.3 host would send them.
    v5_bytes[..4].copy_from_slice(&0x8000_0005u32.to_le_bytes());
    v5_bytes[4..8].copy_from_slice(&0x26A7270Au32.to_le_bytes());
    v5_bytes[8..12].copy_from_slice(&0xc2d6d0b4u32.to_le_bytes()); // Nu5

    let result = codec.send_tx_output(0xFFFF, 1, &v5_bytes);
    assert!(
        result.is_err(),
        "129-byte v5 TxMeta must be rejected by the strict v6-only device"
    );
}

/// Untagged (legacy v4/v5) 1415-byte action payloads are rejected after a
/// valid v6 meta — the pool tag is mandatory on this tier.
#[test]
fn test_untagged_legacy_action_rejected() {
    let mut signer = connect_signer(COIN_TYPE_MAINNET);
    let fvk = device_fvk(&mut signer);
    let (w, _) = payment_with_change(&fvk, HEIGHT_NU6_3);
    let codec = signer.codec_mut();
    w.send_meta(codec).expect("v6 TxMeta send failed");

    // Strip the pool tag → the untagged legacy body.
    let tagged = w.actions[0].serialize_v6();
    assert_eq!(tagged.len(), 1416);
    let result = codec.send_tx_output(0, w.n(), &tagged[1..]);
    assert!(
        matches!(&result, Err(HwSignerError::DeviceError(m)) if m.starts_with("BadFrame")),
        "untagged action must be rejected by the strict v6-only device, got {:?}",
        result
    );
}

// ── Group 7: Connection Lifecycle ────────────────────────────────────

#[test]
fn test_reconnect_clean_session() {
    {
        let mut signer = connect_signer(COIN_TYPE_MAINNET);
        let _ = signer
            .export_fvk()
            .expect("FVK 1 failed");
    }
    {
        let mut signer = connect_signer(COIN_TYPE_MAINNET);
        let fvk = signer
            .export_fvk()
            .expect("FVK 2 failed");
        assert_eq!(fvk.ak, EXPECTED_AK, "FVK should match after reconnect");
    }
}

// ── Transparent helpers ─────────────────────────────────────────────

/// Write a CompactSize-encoded length (Bitcoin-style variable-length integer).
fn compact_size(val: usize) -> Vec<u8> {
    if val < 253 {
        vec![val as u8]
    } else if val <= 0xFFFF {
        let mut buf = vec![0xFD];
        buf.extend_from_slice(&(val as u16).to_le_bytes());
        buf
    } else {
        let mut buf = vec![0xFE];
        buf.extend_from_slice(&(val as u32).to_le_bytes());
        buf
    }
}

/// Build synthetic transparent input data for testing.
fn build_test_transparent_input(index: u8) -> TransparentInputData {
    TransparentInputData {
        prevout_hash: [0x10 + index; 32],
        prevout_index: index as u32,
        sequence: 0xFFFFFFFF,
        value: 50_000 * (index as u64 + 1),
        // P2PKH script_pubkey: OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
        script_pubkey: {
            let mut s = vec![0x76, 0xA9, 0x14]; // OP_DUP OP_HASH160 PUSH20
            s.extend_from_slice(&[0x20 + index; 20]); // fake pubkey hash
            s.extend_from_slice(&[0x88, 0xAC]); // OP_EQUALVERIFY OP_CHECKSIG
            s
        },
    }
}

/// Build synthetic transparent output data for testing.
fn build_test_transparent_output(index: u8) -> TransparentOutputData {
    TransparentOutputData {
        value: 40_000 * (index as u64 + 1),
        script_pubkey: {
            let mut s = vec![0x76, 0xA9, 0x14];
            s.extend_from_slice(&[0x80 + index; 20]);
            s.extend_from_slice(&[0x88, 0xAC]);
            s
        },
    }
}

/// Compute the ZIP-244 transparent txid digest from inputs and outputs (Rust-side).
/// Must produce the same result as the C library's zip244_transparent_digest().
fn compute_transparent_digest(
    inputs: &[TransparentInputData],
    outputs: &[TransparentOutputData],
) -> [u8; 32] {
    // prevouts_digest = BLAKE2b-256("ZTxIdPrevoutHash", for each: prevout_hash[32] || prevout_index[4 LE])
    let mut prevouts = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"ZTxIdPrevoutHash")
        .to_state();
    for inp in inputs {
        prevouts.update(&inp.prevout_hash);
        prevouts.update(&inp.prevout_index.to_le_bytes());
    }
    let prevouts_digest: [u8; 32] = prevouts.finalize().as_bytes().try_into().unwrap();

    // sequence_digest = BLAKE2b-256("ZTxIdSequencHash", for each: sequence[4 LE])
    let mut sequences = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"ZTxIdSequencHash")
        .to_state();
    for inp in inputs {
        sequences.update(&inp.sequence.to_le_bytes());
    }
    let sequence_digest: [u8; 32] = sequences.finalize().as_bytes().try_into().unwrap();

    // outputs_digest = BLAKE2b-256("ZTxIdOutputsHash", for each: value[8 LE] || CompactSize(script_len) || script)
    let mut outputs_h = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"ZTxIdOutputsHash")
        .to_state();
    for out in outputs {
        outputs_h.update(&(out.value as i64).to_le_bytes());
        outputs_h.update(&compact_size(out.script_pubkey.len()));
        outputs_h.update(&out.script_pubkey);
    }
    let outputs_digest: [u8; 32] = outputs_h.finalize().as_bytes().try_into().unwrap();

    // transparent_digest = BLAKE2b-256("ZTxIdTranspaHash", prevouts || sequences || outputs)
    let mut root_input = Vec::new();
    root_input.extend_from_slice(&prevouts_digest);
    root_input.extend_from_slice(&sequence_digest);
    root_input.extend_from_slice(&outputs_digest);

    blake2b_personal(b"ZTxIdTranspaHash", &root_input)
}

// ── Group 8: Transparent Digest Verification (v3) ───────────────────

/// Transparent OUTPUTS only: the device recomputes the transparent digest
/// from the streamed outputs and accepts the sentinel (TX_TRANSPARENT_INPUT
/// with index = total = 0 carrying the digest).
#[test]
fn test_transparent_digest_valid() {
    let mut codec = connect_codec();
    codec.request_fvk(COIN_TYPE_MAINNET).expect("FVK failed");

    let outputs = vec![build_test_transparent_output(0), build_test_transparent_output(1)];
    let digest = compute_transparent_digest(&[], &outputs);
    let mut meta = build_test_tx_meta(COIN_TYPE_MAINNET);
    meta.transparent_sig_digest = digest;
    codec
        .send_tx_output(0xFFFF, 1, &meta.serialize())
        .expect("TxMeta send failed");
    for (i, out) in outputs.iter().enumerate() {
        codec
            .send_transparent_output(i as u16, outputs.len() as u16, &out.serialize())
            .unwrap_or_else(|e| panic!("Transparent output {} failed: {:?}", i, e));
    }
    codec
        .send_transparent_input(0, 0, &digest)
        .expect("Transparent digest verification failed — Rust and C computed different digest!");
}

#[test]
fn test_transparent_digest_mismatch() {
    let mut codec = connect_codec();
    codec.request_fvk(COIN_TYPE_MAINNET).expect("FVK failed");

    let outputs = vec![build_test_transparent_output(0)];
    let mut meta = build_test_tx_meta(COIN_TYPE_MAINNET);
    meta.transparent_sig_digest = compute_transparent_digest(&[], &outputs);
    codec
        .send_tx_output(0xFFFF, 1, &meta.serialize())
        .expect("TxMeta send failed");
    codec
        .send_transparent_output(0, 1, &outputs[0].serialize())
        .expect("Transparent output failed");

    // Send WRONG digest as sentinel
    let result = codec.send_transparent_input(0, 0, &[0xFF; 32]);
    assert!(
        matches!(result, Err(HwSignerError::TransparentSighashMismatch)),
        "Wrong transparent digest should be rejected, got {:?}",
        result
    );
}

/// RAW FRAMES. The device does not take transparent inputs: an input frame
/// and a TRANSPARENT_SIGN_REQ are both answered with
/// TRANSPARENT_INPUTS_UNSUPPORTED (0x18), whatever came before, and no
/// TRANSPARENT_SIGN_RSP (which used to carry a public key) is ever sent.
#[test]
fn sec_transparent_inputs_and_transparent_sign_req_are_refused() {
    let input = build_test_transparent_input(0);
    let outputs = vec![build_test_transparent_output(0)];
    let mut meta = build_test_tx_meta(COIN_TYPE_MAINNET);
    meta.transparent_sig_digest = compute_transparent_digest(std::slice::from_ref(&input), &outputs);

    // An input right after the metadata; an input after an output.
    for outputs_first in [false, true] {
        let mut codec = connect_codec();
        codec.request_fvk(COIN_TYPE_MAINNET).expect("FVK failed");
        ui_clear();
        codec.send_tx_output(0xFFFF, 1, &meta.serialize()).expect("TxMeta");
        if outputs_first {
            codec
                .send_transparent_output(0, 1, &outputs[0].serialize())
                .expect("transparent output");
        }
        let result = codec.send_transparent_input(0, 1, &input.serialize());
        assert!(
            matches!(result, Err(HwSignerError::TransparentInputsNotSupported { inputs: 0 })),
            "transparent input (outputs first: {}): {:?}",
            outputs_first,
            result
        );
        // The session is over: the digest sentinel has nothing to check.
        assert!(codec.send_transparent_input(0, 0, &meta.transparent_sig_digest).is_err());
        assert_nothing_shown("transparent input");
    }

    // TRANSPARENT_SIGN_REQ: with no transaction, and with a verified one.
    let mut signer = connect_signer(COIN_TYPE_MAINNET);
    let fvk = device_fvk(&mut signer);
    let (w, to) = payment_with_change(&fvk, HEIGHT_NU7);
    for verified in [false, true] {
        if verified {
            w.verify(&mut signer).expect("verify");
        }
        ui_clear();
        let codec = signer.codec_mut();
        let mut payload = vec![0u8, 0, 1, 0];
        payload.extend_from_slice(&input.serialize());
        codec
            .write_frame(0x33, MsgType::TransparentSignReq, &payload)
            .expect("send TRANSPARENT_SIGN_REQ");
        let frame = codec.read_frame().expect("reply");
        assert_eq!(frame.msg_type, MsgType::Error, "verified: {}", verified);
        assert_eq!(frame.payload[0], 0x18, "TRANSPARENT_INPUTS_UNSUPPORTED");
        assert_nothing_shown("TRANSPARENT_SIGN_REQ");
        // Every Error ends the session, a verified one included.
        assert_nothing_signable(&mut signer, &w, &ua(&to));
    }
}


// ── Group 10: NU7 (consensus branch 0x77190ad9) ──────────────────────
//
// NU7 keeps the v6 transaction format and the ZIP-244 five-leaf digest
// tree; only the consensus branch ID (header digest + root
// personalization) differs from NU6.3. These tests check that the device
// agrees on real transactions built by zcash_primitives / pczt for a
// post-NU7 height.

/// The device accepts the five-leaf sighash of a real NU7 transaction, and
/// rejects the NU6.3 sighash of the very same transaction (i.e. the branch
/// ID it is given really is bound into what it signs).
#[test]
fn test_nu7_sighash_valid_and_branch_bound() {
    let mut signer = connect_signer(COIN_TYPE_MAINNET);
    let fvk = device_fvk(&mut signer);
    let (w, to) = payment_with_change(&fvk, HEIGHT_NU7);
    assert_eq!(w.meta.consensus_branch_id, BRANCH_NU7);

    let mut as_nu6_3 = w.meta.clone();
    as_nu6_3.consensus_branch_id = BRANCH_NU6_3;
    let nu6_3_sighash = compute_zip244_sighash(&as_nu6_3, &w.actions);
    assert_ne!(nu6_3_sighash, w.sighash);

    // NU7 meta + NU7 sighash: accepted.
    w.verify(&mut signer).expect("device must accept the NU7 five-leaf sighash");
    drop(signer);

    // NU7 meta + NU6.3 sighash of the same transaction: rejected.
    let mut signer = connect_signer(COIN_TYPE_MAINNET);
    let mut wrong = w.clone();
    wrong.sighash = nu6_3_sighash;
    let result = wrong.verify(&mut signer);
    assert!(
        matches!(result, Err(HwSignerError::SignatureVerificationFailed { .. })),
        "device must reject a sighash computed for another branch, got {:?}",
        result
    );
    assert_nothing_signable(&mut signer, &wrong, &ua(&to));
}

/// Sign flow under the NU7 branch ID: the signature the device returns
/// verifies against the NU7 sighash.
#[test]
fn test_nu7_full_sign_flow() {
    let mut signer = connect_signer(COIN_TYPE_MAINNET);
    let fvk = device_fvk(&mut signer);
    let (w, to) = payment_with_change(&fvk, HEIGHT_NU7);
    assert_eq!(w.meta.consensus_branch_id, BRANCH_NU7);
    w.verify(&mut signer).expect("Sighash verification failed");
    assert_eq!(w.sign_all(&mut signer, &ua(&to)).expect("Signing failed"), 1);
}

/// Finalize a device-signed PCZT and extract the transaction: re-verifies
/// the proof(s), every spend-auth signature and the binding signature. A
/// device signature over the wrong sighash dies here.
fn finalize_and_extract(signed_pczt: &[u8]) -> zcash_primitives::transaction::Transaction {
    use pczt::roles::{spend_finalizer::SpendFinalizer, tx_extractor::TransactionExtractor};
    let signed = pczt::Pczt::parse(signed_pczt).expect("parse signed PCZT");
    let finalized = SpendFinalizer::new(signed)
        .finalize_spends()
        .expect("spend finalizer");
    let vk = orchard::circuit::VerifyingKey::build(
        orchard::circuit::OrchardCircuitVersion::PostNu6_3,
    );
    TransactionExtractor::new(finalized)
        .with_orchard(&vk)
        .extract(&mut UnwrapErr(SysRng))
        .expect("transaction extraction (proof + signature verification) failed")
}

/// End to end on a real NU7 transaction, and the reference "legitimate
/// send": a payment to somebody else plus change to the device's own
/// wallet.
///
/// Builds a v6 Ironwood -> Ironwood transfer for a post-NU7 mainnet height
/// with `zcash_primitives` (spending a note addressed to the device's own
/// key, anchored in a one-leaf tree), turns it into a PCZT, and runs the
/// production workflow against the device:
///
///   * `PcztHardwareSigning` proves the bundle, takes the shielded sighash
///     from `pczt` (i.e. `zcash_primitives`' ZIP-244 implementation), and
///     streams TxMeta + actions (with memo plaintext) to the device;
///   * the device recomputes cmx, the ZIP-2005 note ciphertext (payment and
///     change, both sent with the 1416-byte memo-carrying body) and the
///     five-leaf sighash on its own, decides from its own keys which output
///     is the wallet's change, shows the user the payment (external), the
///     memo, the change (own change) and the totals, and only then signs;
///   * the host verifies the RedPallas signature against the PCZT's rk;
///   * the signed PCZT is finalized and extracted into a transaction, which
///     re-verifies the proof, the spend-auth signature and the binding
///     signature under the NU7 branch ID.
///
/// Nothing is broadcast. Proving runs in the test profile, so this and the
/// turnstile test below are by far the slowest of the suite.
#[test]
fn test_nu7_real_pczt_sign_and_extract() {
    use zcash_primitives::transaction::TxVersion;

    assert_eq!(
        BranchId::for_height(&MAIN_NETWORK, BlockHeight::from_u32(HEIGHT_NU7)),
        BranchId::Nu7
    );

    let mut signer = connect_signer(COIN_TYPE_MAINNET);
    let fvk = device_fvk(&mut signer);
    let to = foreign_address(1);
    let spec = TxSpec::ironwood(
        HEIGHT_NU7,
        NOTE_VALUE,
        vec![
            pay(&fvk, to, PAY_VALUE, text_memo("NU7 test")),
            // Change back to the account's internal address, encrypted
            // under the internal OVK exactly as a wallet does. The workflow
            // must open it with the internal OVK and send the device the
            // memo-carrying body for it too.
            change(&fvk, CHANGE_VALUE),
        ],
    );
    let pczt = build_pczt(&fvk, &spec);

    // What the builder produced is a v6 transaction under the NU7 branch.
    assert_eq!(*pczt.global().consensus_branch_id(), BRANCH_NU7);
    assert_eq!(*pczt.global().tx_version(), 6);
    assert_eq!(*pczt.global().version_group_id(), 0xD884_B698);
    assert_eq!(*pczt.global().coin_type(), COIN_TYPE_MAINNET);
    // NU7 default expiry: target height + 120 blocks (was + 40).
    assert_eq!(*pczt.global().expiry_height(), HEIGHT_NU7 + 120);
    assert!(pczt.orchard().actions().is_empty());
    assert_eq!(pczt.ironwood().actions().len(), 2);
    let expected_sighash = pczt::roles::signer::Signer::new(pczt.clone())
        .expect("signer")
        .shielded_sighash();

    // The production signing workflow, against the device.
    ui_clear();
    let mut workflow = PcztHardwareSigning::new(signer);
    let result = workflow
        .sign_with_details(
            pczt.serialize().expect("serialize"),
            Some(TxDetails {
                send_amount: PAY_VALUE,
                fee: FEE_2,
                recipient: ua(&to),
                num_actions: 0,
                memo: Some("NU7 test".to_string()),
            }),
        )
        .expect("hardware signing of a real NU7 PCZT failed");
    assert_eq!(result.actions_signed, 1, "exactly the one real spend");
    assert_eq!(result.transparent_inputs_signed, 0);

    // What the user saw on the device: the payment as an external output,
    // its memo, the change as the wallet's own, and totals = payment + fee.
    let screens = ui_screens();
    let mut outs = shown_outputs(&screens);
    outs.sort();
    assert_eq!(
        outs,
        vec![
            ("external".to_string(), ua(&to), PAY_VALUE),
            ("own-change".to_string(), ua(&fvk.address_at(0u32, Scope::Internal)), CHANGE_VALUE),
        ]
    );
    let memos = screens_named(&screens, "review_memo");
    assert_eq!(memos.len(), 1, "one memo to read: {:?}", screens);
    assert_eq!(memos[0].get("address"), ua(&to));
    assert_eq!(memos[0].get("type"), "text");
    assert_eq!(memos[0].get("text"), "NU7 test");
    let totals = shown_totals(&screens);
    assert_eq!(totals.num("total_leaving"), PAY_VALUE + FEE_2);
    assert_eq!(totals.num("fee"), FEE_2);
    assert_eq!(totals.num("external_shielded"), PAY_VALUE);
    assert_eq!(totals.num("own_internal"), CHANGE_VALUE);
    assert_eq!(totals.num("own_external"), 0);
    assert_eq!(totals.num("transparent_out"), 0);
    assert_eq!(
        (totals.num("n_external"), totals.num("n_own_internal"), totals.num("n_own_external"), totals.num("n_zero_value")),
        (1, 1, 0, 0)
    );
    let confirms = screens_named(&screens, "confirm_tx");
    assert_eq!(confirms.len(), 1, "one final confirmation: {:?}", screens);
    assert_eq!(confirms[0].num("total_leaving"), PAY_VALUE + FEE_2);
    assert_eq!(confirms[0].num("fee"), FEE_2);
    assert_eq!(confirms[0].num("n_external"), 1);
    assert!(!confirms[0].fields.contains_key("host_recipient"), "nothing from the host");
    // The payment's memo status and the change's are explicit.
    for o in screens_named(&screens, "review_output") {
        assert_eq!(o.get("memo"), if o.get("kind") == "external" { "present" } else { "none" });
    }
    // Order: every output (and memo), then the totals, then the final OK.
    let names: Vec<&str> = screens.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names[names.len() - 2..], ["review_totals", "confirm_tx"]);
    assert!(screens.iter().all(|s| s.approved()));

    // The device-signed PCZT: same sighash, a spend-auth signature on the
    // real spend, still NU7.
    let signed = pczt::Pczt::parse(&result.signed_pczt).expect("parse signed PCZT");
    assert_eq!(*signed.global().consensus_branch_id(), BRANCH_NU7);
    assert_eq!(
        pczt::roles::signer::Signer::new(signed.clone())
            .expect("signer")
            .shielded_sighash(),
        expected_sighash
    );
    assert_eq!(
        signed
            .ironwood()
            .actions()
            .iter()
            .filter(|a| a.spend().spend_auth_sig().is_some())
            .count(),
        2,
        "the real spend is device-signed, the dummy spend by the IO finalizer"
    );

    let tx = finalize_and_extract(&result.signed_pczt);
    assert_eq!(tx.version(), TxVersion::V6);
    assert_eq!(tx.consensus_branch_id(), BranchId::Nu7);
    assert_eq!(u32::from(tx.expiry_height()), HEIGHT_NU7 + 120);
    assert!(tx.orchard_bundle().is_none());
    let ironwood = tx.ironwood_bundle().expect("ironwood bundle");
    assert_eq!(ironwood.actions().len(), 2);
    // Net value leaving the Ironwood pool is exactly the fee.
    assert_eq!(i64::from(*ironwood.value_balance()), FEE_2 as i64);

    // Serialized form starts with the v6 header and carries the NU7
    // branch ID.
    let mut raw = Vec::new();
    tx.write(&mut raw).expect("serialize tx");
    assert_eq!(&raw[0..4], &0x8000_0006u32.to_le_bytes());
    assert_eq!(&raw[4..8], &0xD884_B698u32.to_le_bytes());
    assert_eq!(&raw[8..12], &BRANCH_NU7.to_le_bytes());
}

// ── Group 11: what the device decides, shows and refuses ─────────────
//
// The device is the only party the user can trust: these tests play a
// hostile or merely sloppy host against it and check both its verdict and
// what it put on its screen. Unless a test says otherwise the transactions
// are built with the upstream builder and handed over through
// `DeviceSigner::verify_transaction`; where the attack is something the
// SDK would never send, the frames are written by hand through `HwpCodec`
// and the test says so.

/// A sealed-Orchard -> Ironwood (turnstile) transaction, as the upstream
/// builder makes it for a note received at an external address.
fn turnstile_spec(fvk: &FullViewingKey, height: u32, to: orchard::Address) -> TxSpec {
    TxSpec {
        height,
        spend_pool: ShieldedPoolKind::Orchard,
        note_value: NOTE_VALUE,
        outputs: vec![
            pay(fvk, to, PAY_VALUE, text_memo("out of the old pool")),
            change(fvk, NOTE_VALUE - PAY_VALUE - 20_000), // fee: 2 + 2 actions
        ],
        t_outputs: Vec::new(),
        t_input: None,
    }
}

/// The host fails early, with a typed error, when it cannot give the
/// device the plaintext of an output: `OutputNotRecoverable`, before any
/// proof and before anything is sent. Here an Ironwood output of a real
/// PCZT has one ciphertext byte altered (in the serialized PCZT), so the
/// note the PCZT describes no longer opens it. (The only unopenable output
/// the host lets through is the sealed-Orchard zero-value one of a
/// turnstile transaction, see the tests below.)
#[test]
fn sec_host_reports_an_unopenable_output_before_proving() {
    let mut signer = connect_signer(COIN_TYPE_MAINNET);
    let fvk = device_fvk(&mut signer);
    let to = foreign_address(1);
    let spec = TxSpec::ironwood(
        HEIGHT_NU7,
        NOTE_VALUE,
        vec![pay(&fvk, to, PAY_VALUE, text_memo(PAY_MEMO)), change(&fvk, CHANGE_VALUE)],
    );
    let pczt = build_pczt(&fvk, &spec);
    let w = wire_from_pczt(&pczt, &fvk);

    for (what, idx, value) in [
        ("payment", w.index_of(&to), PAY_VALUE),
        ("change", w.index_of(&fvk.address_at(0u32, Scope::Internal)), CHANGE_VALUE),
    ] {
        let mut bytes = pczt.clone().serialize().expect("serialize");
        let needle = &w.actions[idx].enc_ciphertext[..64];
        let pos = bytes
            .windows(needle.len())
            .position(|win| win == needle)
            .expect("enc_ciphertext in the serialized PCZT");
        bytes[pos + 300] ^= 0x01; // inside the memo part of the ciphertext
        pczt::Pczt::parse(&bytes).expect("still a well-formed PCZT");

        ui_clear();
        let started = std::time::Instant::now();
        let mut workflow = PcztHardwareSigning::new(signer);
        match workflow.sign(bytes) {
            Err(HwSignerError::OutputNotRecoverable { pool, value: v, reason, .. }) => {
                assert_eq!((pool, v), ("Ironwood", value), "{}", what);
                assert!(reason.contains("enc_ciphertext"), "{}", reason);
            }
            other => panic!("{}: expected OutputNotRecoverable, got {:?}", what, other.map(|_| ())),
        }
        assert!(started.elapsed().as_secs() < 5, "refused before proving");
        assert_nothing_shown("PCZT with an unopenable output");
        signer = workflow.into_signer();
    }
}

/// End to end on real turnstile transactions, under NU6.3 and under NU7: a
/// note of the sealed Orchard pool, received at an external address, is
/// spent into Ironwood (payment + change). Full workflow with proofs for
/// both bundles, finalized and extracted.
///
/// The sealed-Orchard bundle's two outputs are zero-value: the builder's
/// padding (opens normally) and the output paired with the real spend,
/// whose enc_ciphertext is random by upstream design. The host sends both
/// with the full body (512 zero bytes of memo for the one it cannot open);
/// the device verifies what can be verified, tolerates the random
/// ciphertext because it is a zero-value sealed-Orchard output to its own
/// address with the expected epk and no memo, shows neither, and the totals
/// are payment + fee.
#[test]
fn sec_turnstile_orchard_to_ironwood_sign_and_extract() {
    const FEE: u64 = 20_000; // 2 Orchard-pool actions + 2 Ironwood actions
    for (height, branch, branch_id) in [
        (HEIGHT_NU6_3, BRANCH_NU6_3, BranchId::Nu6_3),
        (HEIGHT_NU7, BRANCH_NU7, BranchId::Nu7),
    ] {
        let mut signer = connect_signer(COIN_TYPE_MAINNET);
        let fvk = device_fvk(&mut signer);
        let to = foreign_address(1);
        let change_value = NOTE_VALUE - PAY_VALUE - FEE;
        let pczt = build_pczt(&fvk, &turnstile_spec(&fvk, height, to));
        assert_eq!(*pczt.global().consensus_branch_id(), branch);
        assert_eq!(pczt.orchard().actions().len(), 2);
        assert_eq!(pczt.ironwood().actions().len(), 2);

        ui_clear();
        let mut workflow = PcztHardwareSigning::new(signer);
        let result = workflow
            .sign(pczt.serialize().expect("serialize"))
            .unwrap_or_else(|e| panic!("turnstile PCZT, branch {:#x}: {:?}", branch, e));
        assert_eq!(result.actions_signed, 1, "the one real Orchard-pool spend");

        let screens = ui_screens();
        let mut outs = shown_outputs(&screens);
        outs.sort();
        assert_eq!(
            outs,
            vec![
                ("external".to_string(), ua(&to), PAY_VALUE),
                ("own-change".to_string(), ua(&fvk.address_at(0u32, Scope::Internal)), change_value),
            ],
            "the sealed pool's zero-value outputs are not shown"
        );
        let memos = screens_named(&screens, "review_memo");
        assert_eq!(memos.len(), 1);
        assert_eq!(memos[0].get("text"), "out of the old pool");
        let totals = shown_totals(&screens);
        assert_eq!(totals.num("total_leaving"), PAY_VALUE + FEE);
        assert_eq!(totals.num("fee"), FEE);
        assert_eq!(totals.num("own_internal"), change_value);
        assert_eq!(totals.num("n_zero_value"), 2);
        let confirms = screens_named(&screens, "confirm_tx");
        assert_eq!(confirms.len(), 1);
        assert_eq!(confirms[0].num("total_leaving"), PAY_VALUE + FEE);

        let tx = finalize_and_extract(&result.signed_pczt);
        assert_eq!(tx.consensus_branch_id(), branch_id);
        let orchard = tx.orchard_bundle().expect("orchard bundle");
        let ironwood = tx.ironwood_bundle().expect("ironwood bundle");
        // The whole note leaves the sealed pool; everything but the fee
        // enters Ironwood.
        assert_eq!(i64::from(*orchard.value_balance()), NOTE_VALUE as i64);
        assert_eq!(i64::from(*ironwood.value_balance()), -((NOTE_VALUE - FEE) as i64));
    }
}

/// RAW FRAMES, hand-made notes. The tolerance for a ciphertext that does
/// not match exists for exactly one output shape: sealed Orchard pool,
/// value zero (proved by the commitment), recipient one of the device
/// wallet's own addresses, the expected epk, and no memo declared. With a
/// random enc_ciphertext, that shape is accepted; change any one of the
/// five conditions and it is MEMO_MISMATCH, with nothing shown.
#[test]
fn sec_randomized_ciphertext_exception_cannot_be_abused() {
    let mut signer = connect_signer(COIN_TYPE_MAINNET);
    let fvk = device_fvk(&mut signer);
    let own = fvk.address_at(0u32, Scope::External);
    let own_internal = fvk.address_at(3u32, Scope::Internal);
    let foreign = foreign_address(1);
    let mut text = [0u8; 512];
    text[..5].copy_from_slice(b"hello");
    let mut odd_no_memo = [0u8; 512];
    odd_no_memo[0] = 0xF6;
    odd_no_memo[511] = 1;

    // (description, pool, recipient, value, declared memo, alter epk, accepted)
    type Case<'a> = (&'a str, ShieldedPoolKind, orchard::Address, u64, [u8; 512], bool, bool);
    let orchard_pool = ShieldedPoolKind::Orchard;
    let cases: Vec<Case> = vec![
        ("the builder's shape (own external address)", orchard_pool, own, 0, [0u8; 512], false, true),
        // The builder randomizes only for external-scope spends: an internal
        // (change) address never takes the exception.
        ("own internal address", orchard_pool, own_internal, 0, [0u8; 512], false, false),
        ("(a) foreign recipient", orchard_pool, foreign, 0, [0u8; 512], false, false),
        ("(b) Ironwood pool", ShieldedPoolKind::Ironwood, own, 0, [0u8; 512], false, false),
        ("(c) value 1", orchard_pool, own, 1, [0u8; 512], false, false),
        ("(d) epk altered", orchard_pool, own, 0, [0u8; 512], true, false),
        ("(e) a declared text memo", orchard_pool, own, 0, text, false, false),
        ("(e) 0xF6 followed by data", orchard_pool, own, 0, odd_no_memo, false, false),
    ];
    for (what, pool, recipient, value, memo, alter_epk, accepted) in cases {
        let mut action = handmade_action(pool, recipient, value);
        UnwrapErr(SysRng).fill_bytes(&mut action.enc_ciphertext); // random, as the builder does
        action.memo = Some(memo);
        if alter_epk {
            // Another valid epk: the one of a different hand-made note.
            action.ephemeral_key = handmade_action(pool, recipient, value).ephemeral_key;
        }
        let mut meta = build_test_tx_meta(COIN_TYPE_MAINNET);
        meta.ironwood_flags = 0x03;

        ui_clear();
        let codec = signer.codec_mut();
        codec.send_tx_output(0xFFFF, 1, &meta.serialize()).expect("meta");
        let result = codec.send_tx_output(0, 1, &action.serialize_v6());
        if accepted {
            result.unwrap_or_else(|e| panic!("{}: must be tolerated, got {:?}", what, e));
            // Not shown, counted as padding; the transaction verifies.
            codec
                .send_tx_output(1, 1, &compute_zip244_sighash(&meta, std::slice::from_ref(&action)))
                .unwrap_or_else(|e| panic!("{}: sentinel: {:?}", what, e));
            let screens = ui_screens();
            assert!(shown_outputs(&screens).is_empty(), "{}: {:?}", what, screens);
            assert_eq!(shown_totals(&screens).num("n_zero_value"), 1);
            assert_eq!(shown_totals(&screens).num("total_leaving"), 0);
        } else {
            assert!(
                matches!(&result, Err(HwSignerError::DeviceError(m)) if m.starts_with("MemoMismatch")),
                "{}: expected MemoMismatch, got {:?}",
                what,
                result
            );
            assert_nothing_shown(what);
            assert!(codec.send_tx_output(1, 1, &[0u8; 32]).is_err(), "{}: session must be over", what);
        }
    }
}

/// The turnstile shape without proofs, through the device API, under both
/// branches: reviewed (payment external, change own, the Orchard pool's two
/// zero-value outputs not shown), totals = payment + fee, signed. (Against
/// library 17d4ee0 this was refused with MEMO_MISMATCH: the output the
/// builder pairs with the real spend has a random enc_ciphertext.)
#[test]
fn sec_turnstile_spend_is_reviewed_and_signed() {
    for (height, branch) in [(HEIGHT_NU6_3, BRANCH_NU6_3), (HEIGHT_NU7, BRANCH_NU7)] {
        let mut signer = connect_signer(COIN_TYPE_MAINNET);
        let fvk = device_fvk(&mut signer);
        let to = foreign_address(1);
        let w = wire_from_pczt(&build_pczt(&fvk, &turnstile_spec(&fvk, height, to)), &fvk);
        assert_eq!(w.meta.consensus_branch_id, branch);
        assert_eq!(w.actions.iter().filter(|a| a.pool == ShieldedPoolKind::Orchard).count(), 2);
        assert_eq!(w.meta.value_balance, NOTE_VALUE as i64);
        assert_eq!(w.meta.ironwood_value_balance, -((NOTE_VALUE - 20_000) as i64));

        ui_clear();
        let result = w.verify(&mut signer);
        assert!(
            result.is_ok(),
            "a turnstile transaction built by the upstream builder (branch {:#x}) is refused: {:?}",
            branch,
            result
        );
        let screens = ui_screens();
        let mut outs = shown_outputs(&screens);
        outs.sort();
        assert_eq!(
            outs,
            vec![
                ("external".to_string(), ua(&to), PAY_VALUE),
                (
                    "own-change".to_string(),
                    ua(&fvk.address_at(0u32, Scope::Internal)),
                    NOTE_VALUE - PAY_VALUE - 20_000
                ),
            ]
        );
        let totals = shown_totals(&screens);
        assert_eq!(totals.num("total_leaving"), PAY_VALUE + 20_000);
        assert_eq!(totals.num("n_zero_value"), 2);
        assert_eq!(w.sign_all(&mut signer, "").expect("sign"), 1);
    }
}

/// Ironwood -> Ironwood under both branches (NU6.3 and NU7), without
/// proofs: reviewed with the right kinds and totals, and signed. (The
/// sealed Orchard -> Ironwood shape is
/// `sec_turnstile_spend_is_reviewed_and_signed`.)
#[test]
fn sec_ironwood_to_ironwood_under_both_branches() {
    for (height, branch) in [(HEIGHT_NU6_3, BRANCH_NU6_3), (HEIGHT_NU7, BRANCH_NU7)] {
        for (pool, fee, zero_value) in [
            (ShieldedPoolKind::Ironwood, 10_000u64, 0u64),
        ] {
            let ctx = format!("{:?} spend, branch {:#x}", pool, branch);
            let mut signer = connect_signer(COIN_TYPE_MAINNET);
            let fvk = device_fvk(&mut signer);
            let to = foreign_address(1);
            let change_value = NOTE_VALUE - PAY_VALUE - fee;
            let spec = TxSpec {
                height,
                spend_pool: pool,
                note_value: NOTE_VALUE,
                outputs: vec![
                    pay(&fvk, to, PAY_VALUE, MemoBytes::empty()),
                    change(&fvk, change_value),
                ],
                t_outputs: Vec::new(),
                t_input: None,
            };
            let w = wire_from_pczt(&build_pczt(&fvk, &spec), &fvk);
            assert_eq!(w.meta.consensus_branch_id, branch, "{}", ctx);
            match pool {
                ShieldedPoolKind::Ironwood => {
                    assert!(w.actions.iter().all(|a| a.pool == ShieldedPoolKind::Ironwood));
                    assert_eq!(w.meta.ironwood_value_balance, fee as i64);
                }
                ShieldedPoolKind::Orchard => {
                    assert_eq!(w.actions.iter().filter(|a| a.pool == ShieldedPoolKind::Orchard).count(), 2);
                    assert_eq!(w.meta.value_balance, NOTE_VALUE as i64, "{}", ctx);
                    assert_eq!(w.meta.ironwood_value_balance, -((NOTE_VALUE - fee) as i64));
                }
            }

            ui_clear();
            w.verify(&mut signer).unwrap_or_else(|e| panic!("{}: verify: {:?}", ctx, e));
            let screens = ui_screens();
            let mut outs = shown_outputs(&screens);
            outs.sort();
            assert_eq!(
                outs,
                vec![
                    ("external".to_string(), ua(&to), PAY_VALUE),
                    ("own-change".to_string(), ua(&fvk.address_at(0u32, Scope::Internal)), change_value),
                ],
                "{}",
                ctx
            );
            assert!(screens_named(&screens, "review_memo").is_empty(), "{}: empty memos are not shown", ctx);
            let totals = shown_totals(&screens);
            assert_eq!(totals.num("total_leaving"), PAY_VALUE + fee, "{}", ctx);
            assert_eq!(totals.num("fee"), fee, "{}", ctx);
            assert_eq!(totals.num("own_internal"), change_value, "{}", ctx);
            assert_eq!(totals.num("n_zero_value"), zero_value, "{}", ctx);

            assert_eq!(w.sign_all(&mut signer, &ua(&to)).unwrap_or_else(|e| panic!("{}: sign: {:?}", ctx, e)), 1);
            let confirm = ui_screens().into_iter().find(|s| s.name == "confirm_tx").expect("confirm_tx");
            // The device's own numbers, not the absurd ones in SIGN_REQ.
            assert_eq!(confirm.num("total_leaving"), PAY_VALUE + fee, "{}", ctx);
            assert_eq!(confirm.num("fee"), fee, "{}", ctx);
        }
    }
}

/// A host that sends the "change" to an address of its own: the device,
/// which decides ownership from its own keys, shows it as an external
/// output and counts it in the total leaving the wallet.
#[test]
fn sec_change_redirected_to_foreign_address_is_shown_as_leaving() {
    let mut signer = connect_signer(COIN_TYPE_MAINNET);
    let fvk = device_fvk(&mut signer);
    let (to, thief) = (foreign_address(1), foreign_address(9));
    let spec = TxSpec::ironwood(
        HEIGHT_NU7,
        NOTE_VALUE,
        vec![
            pay(&fvk, to, PAY_VALUE, MemoBytes::empty()),
            // Looks like change in every way the host controls (encrypted
            // to the wallet's internal OVK, empty memo) — but pays the thief.
            Out {
                to: thief,
                value: CHANGE_VALUE,
                memo: MemoBytes::empty(),
                ovk: Some(fvk.to_ovk(Scope::Internal)),
            },
        ],
    );
    let w = wire_from_pczt(&build_pczt(&fvk, &spec), &fvk);

    ui_clear();
    w.verify(&mut signer).expect("the transaction itself is well-formed");
    let screens = ui_screens();
    let mut outs = shown_outputs(&screens);
    outs.sort();
    let mut expected = vec![
        ("external".to_string(), ua(&to), PAY_VALUE),
        ("external".to_string(), ua(&thief), CHANGE_VALUE),
    ];
    expected.sort();
    assert_eq!(outs, expected, "the redirected change must be shown as an external output");
    let totals = shown_totals(&screens);
    assert_eq!(totals.num("total_leaving"), NOTE_VALUE, "payment + redirected change + fee");
    assert_eq!(totals.num("external_shielded"), PAY_VALUE + CHANGE_VALUE);
    assert_eq!(totals.num("own_internal"), 0);
    assert_eq!((totals.num("n_external"), totals.num("n_own_internal")), (2, 0));
}

/// Payments to the wallet's own receiving addresses — the default one and
/// two non-default diversifiers — are recognised as the wallet's own and do
/// not count as leaving it.
#[test]
fn sec_payment_to_own_receiving_addresses_is_shown_as_own_address() {
    let mut signer = connect_signer(COIN_TYPE_MAINNET);
    let fvk = device_fvk(&mut signer);
    let own0 = fvk.address_at(0u32, Scope::External);
    let own7 = fvk.address_at(7u32, Scope::External);
    let own_far = fvk.address_at(1_000_003u32, Scope::External);
    let fee = 20_000; // four outputs
    let change_value = NOTE_VALUE - 600_000 - fee;
    let spec = TxSpec::ironwood(
        HEIGHT_NU7,
        NOTE_VALUE,
        vec![
            pay(&fvk, own0, 100_000, MemoBytes::empty()),
            pay(&fvk, own7, 200_000, MemoBytes::empty()),
            pay(&fvk, own_far, 300_000, MemoBytes::empty()),
            change(&fvk, change_value),
        ],
    );
    let w = wire_from_pczt(&build_pczt(&fvk, &spec), &fvk);

    ui_clear();
    w.verify(&mut signer).expect("verify");
    let screens = ui_screens();
    let mut outs = shown_outputs(&screens);
    outs.sort();
    let mut expected = vec![
        ("own-address".to_string(), ua(&own0), 100_000),
        ("own-address".to_string(), ua(&own7), 200_000),
        ("own-address".to_string(), ua(&own_far), 300_000),
        ("own-change".to_string(), ua(&fvk.address_at(0u32, Scope::Internal)), change_value),
    ];
    expected.sort();
    assert_eq!(outs, expected);
    let totals = shown_totals(&screens);
    assert_eq!(totals.num("total_leaving"), fee, "only the fee leaves the wallet");
    assert_eq!(totals.num("own_external"), 600_000);
    assert_eq!(totals.num("own_internal"), change_value);
    assert_eq!((totals.num("n_external"), totals.num("n_own_external"), totals.num("n_own_internal")), (0, 3, 1));

    assert_eq!(w.sign_all(&mut signer, &ua(&own7)).expect("sign"), 1);
}

/// The compact (no-memo, 904-byte) action body no longer exists for the
/// device: a payment, the wallet's own change and a zero-value padding
/// output sent that way are all refused with MEMO_REQUIRED.
/// (`ActionData { memo: None, .. }` is what an SDK that could not rebuild
/// the plaintext would have sent; the workflow refuses such a PCZT itself,
/// see `OutputNotRecoverable`.)
#[test]
fn sec_compact_body_is_memo_required_for_every_output() {
    let mut signer = connect_signer(COIN_TYPE_MAINNET);
    let fvk = device_fvk(&mut signer);
    let (w, to) = payment_with_change(&fvk, HEIGHT_NU7);
    // One payment, no change: the second action is the builder's padding.
    let padded = wire_from_pczt(
        &build_pczt(
            &fvk,
            &TxSpec::ironwood(
                HEIGHT_NU7,
                NOTE_VALUE,
                vec![pay(&fvk, to, NOTE_VALUE - FEE_2, MemoBytes::empty())],
            ),
        ),
        &fvk,
    );
    let padding_idx = padded.actions.iter().position(|a| a.value == 0).expect("padding");
    let targets = [
        ("payment", &w, w.index_of(&to)),
        ("own change", &w, w.index_of(&fvk.address_at(0u32, Scope::Internal))),
        ("zero-value padding", &padded, padding_idx),
    ];
    for (what, wire, idx) in targets {
        let mut bad = wire.clone();
        bad.actions[idx].memo = None;
        assert_eq!(bad.actions[idx].serialize_v6().len(), 904);
        ui_clear();
        match bad.verify(&mut signer) {
            Err(HwSignerError::MemoRequired { reason }) => {
                assert!(reason.to_lowercase().contains("memo"), "{}", reason)
            }
            other => panic!("{} sent compact: expected MemoRequired, got {:?}", what, other),
        }
        assert_nothing_shown(what);
        assert_nothing_signable(&mut signer, &bad, &ua(&to));
    }
}

/// The memo the host declares must be the one inside the ciphertext: a
/// substituted (or dropped) memo is refused, and on an honest run the
/// device shows the memo that is really in the transaction.
#[test]
fn sec_substituted_memo_is_rejected() {
    let mut signer = connect_signer(COIN_TYPE_MAINNET);
    let fvk = device_fvk(&mut signer);
    let (w, to) = payment_with_change(&fvk, HEIGHT_NU7);
    let idx = w.index_of(&to);

    let mut other_text = [0u8; 512];
    other_text[..10].copy_from_slice(b"invoice 43");
    let mut no_memo = [0u8; 512];
    no_memo[0] = 0xF6;
    for (what, memo) in [("another text", other_text), ("an empty memo", no_memo)] {
        let mut bad = w.clone();
        bad.actions[idx].memo = Some(memo);
        ui_clear();
        let result = bad.verify(&mut signer);
        assert!(
            matches!(&result, Err(HwSignerError::DeviceError(m)) if m.starts_with("MemoMismatch")),
            "memo replaced by {}: expected MemoMismatch, got {:?}",
            what,
            result
        );
        assert_nothing_shown(what);
        assert_nothing_signable(&mut signer, &bad, &ua(&to));
    }

    // Honest: the memo on the screen is the one in the transaction.
    ui_clear();
    w.verify(&mut signer).expect("honest transaction");
    let screens = ui_screens();
    let memos = screens_named(&screens, "review_memo");
    assert_eq!(memos.len(), 1);
    assert_eq!(memos[0].get("text"), PAY_MEMO);
    assert_eq!(memos[0].get("address"), ua(&to));
    assert_eq!(memos[0].get("hex"), hex::encode(w.actions[idx].memo.unwrap()));
    let pay_screen = screens
        .iter()
        .find(|s| s.name == "review_output" && s.get("address") == ua(&to))
        .expect("payment screen");
    assert_eq!(pay_screen.get("has_memo"), "1");
}

/// The note the host describes must be the note the action commits to and
/// encrypts: a tampered ciphertext or ephemeral key (here on the wallet's
/// own change, which would make it undecryptable), or a lie about the
/// recipient or the value, is refused before anything is shown.
#[test]
fn sec_tampered_ciphertext_or_note_is_rejected() {
    let mut signer = connect_signer(COIN_TYPE_MAINNET);
    let fvk = device_fvk(&mut signer);
    let (w, to) = payment_with_change(&fvk, HEIGHT_NU7);
    let change_addr = fvk.address_at(0u32, Scope::Internal);
    let (pay_idx, change_idx) = (w.index_of(&to), w.index_of(&change_addr));

    let tamper: Vec<(&str, Box<dyn Fn(&mut Wire)>, &str)> = vec![
        (
            "change enc_ciphertext, note part",
            Box::new(move |w: &mut Wire| w.actions[change_idx].enc_ciphertext[20] ^= 0x01),
            "MemoMismatch",
        ),
        (
            "change enc_ciphertext, memo part",
            Box::new(move |w: &mut Wire| w.actions[change_idx].enc_ciphertext[300] ^= 0x80),
            "MemoMismatch",
        ),
        (
            "change enc_ciphertext, tag",
            Box::new(move |w: &mut Wire| w.actions[change_idx].enc_ciphertext[579] ^= 0x01),
            "MemoMismatch",
        ),
        (
            "change ephemeral key",
            Box::new(move |w: &mut Wire| w.actions[change_idx].ephemeral_key = w.actions[pay_idx].ephemeral_key),
            "MemoMismatch",
        ),
        (
            "payment claimed to be the wallet's change address",
            Box::new(move |w: &mut Wire| w.actions[pay_idx].recipient = w.actions[change_idx].recipient),
            "NoteCommitment",
        ),
        (
            "payment value understated",
            Box::new(move |w: &mut Wire| w.actions[pay_idx].value -= 1),
            "NoteCommitment",
        ),
    ];
    for (what, f, expected) in tamper {
        let mut bad = w.clone();
        f(&mut bad);
        ui_clear();
        let result = bad.verify(&mut signer);
        let ok = match (&result, expected) {
            (Err(HwSignerError::DeviceError(m)), "MemoMismatch") => m.starts_with("MemoMismatch"),
            (Err(HwSignerError::NoteCommitmentMismatch { .. }), "NoteCommitment") => true,
            _ => false,
        };
        assert!(ok, "{}: expected {}, got {:?}", what, expected, result);
        assert_nothing_shown(what);
        assert_nothing_signable(&mut signer, &bad, &ua(&to));
    }
}

/// A zero-value padding output (what the builder adds to reach two
/// actions: random recipient, no OVK, 512 zero bytes of memo) goes out with
/// the full body like every other output, passes the on-device
/// re-encryption, is not put on the screen, and does not get in the way of
/// signing.
#[test]
fn sec_zero_value_padding_is_not_shown() {
    let mut signer = connect_signer(COIN_TYPE_MAINNET);
    let fvk = device_fvk(&mut signer);
    let to = foreign_address(1);
    // The whole note minus the fee to one recipient: no change output.
    let spec = TxSpec::ironwood(
        HEIGHT_NU7,
        NOTE_VALUE,
        vec![pay(&fvk, to, NOTE_VALUE - FEE_2, MemoBytes::empty())],
    );
    let w = wire_from_pczt(&build_pczt(&fvk, &spec), &fvk);
    assert_eq!(w.actions.len(), 2);
    let padding: Vec<&ActionData> = w.actions.iter().filter(|a| a.value == 0).collect();
    assert_eq!(padding.len(), 1, "one padding output");
    assert_eq!(padding[0].memo, Some([0u8; 512]), "the builder's padding memo is all zeroes");
    assert_eq!(padding[0].serialize_v6().len(), 1416, "sent with the full body");

    ui_clear();
    w.verify(&mut signer).expect("padding with the full body is accepted");
    let screens = ui_screens();
    assert_eq!(
        shown_outputs(&screens),
        vec![("external".to_string(), ua(&to), NOTE_VALUE - FEE_2)],
        "only the payment is shown (as output 1 of 1)"
    );
    let totals = shown_totals(&screens);
    assert_eq!(totals.num("n_zero_value"), 1);
    assert_eq!(totals.num("total_leaving"), NOTE_VALUE);
    assert_eq!(totals.num("fee"), FEE_2);

    assert_eq!(w.sign_all(&mut signer, &ua(&to)).expect("signing proceeds"), 1);
}

/// A zero-value output that carries a memo, sent with the full body, is
/// shown — as a message (value 0, memo to read), not hidden as padding.
#[test]
fn sec_zero_value_output_with_memo_is_shown_as_a_message() {
    let mut signer = connect_signer(COIN_TYPE_MAINNET);
    let fvk = device_fvk(&mut signer);
    let (to, pen_pal) = (foreign_address(1), foreign_address(2));
    let fee = 15_000;
    let spec = TxSpec::ironwood(
        HEIGHT_NU7,
        NOTE_VALUE,
        vec![
            pay(&fvk, to, PAY_VALUE, MemoBytes::empty()),
            pay(&fvk, pen_pal, 0, text_memo("hello from the device owner")),
            change(&fvk, NOTE_VALUE - PAY_VALUE - fee),
        ],
    );
    let w = wire_from_pczt(&build_pczt(&fvk, &spec), &fvk);
    assert!(w.actions[w.index_of(&pen_pal)].memo.is_some());

    ui_clear();
    w.verify(&mut signer).expect("verify");
    let screens = ui_screens();
    let outs = shown_outputs(&screens);
    assert_eq!(outs.len(), 3, "payment, message and change are all shown: {:?}", outs);
    assert!(outs.contains(&("external".to_string(), ua(&pen_pal), 0)));
    let memos = screens_named(&screens, "review_memo");
    assert_eq!(memos.len(), 1);
    assert_eq!(memos[0].get("address"), ua(&pen_pal));
    assert_eq!(memos[0].get("text"), "hello from the device owner");
    let totals = shown_totals(&screens);
    assert_eq!(totals.num("total_leaving"), PAY_VALUE + fee);
    assert_eq!(totals.num("n_zero_value"), 1);
    assert_eq!(totals.num("n_external"), 1, "only outputs with value are counted as payments");
}

/// A zero-value output cannot smuggle a memo past the user: sent with the
/// compact body it is refused (MEMO_REQUIRED), and sent with the full body
/// but a memo other than the one in the ciphertext (claiming "padding, no
/// memo") it fails the re-encryption (MEMO_MISMATCH). Either way nothing is
/// shown and nothing can be signed.
#[test]
fn sec_zero_value_output_cannot_hide_its_memo() {
    let mut signer = connect_signer(COIN_TYPE_MAINNET);
    let fvk = device_fvk(&mut signer);
    let (to, pen_pal) = (foreign_address(1), foreign_address(2));
    let fee = 15_000;
    let spec = TxSpec::ironwood(
        HEIGHT_NU7,
        NOTE_VALUE,
        vec![
            pay(&fvk, to, PAY_VALUE, MemoBytes::empty()),
            pay(&fvk, pen_pal, 0, text_memo("a message the user must see")),
            change(&fvk, NOTE_VALUE - PAY_VALUE - fee),
        ],
    );
    let w = wire_from_pczt(&build_pczt(&fvk, &spec), &fvk);
    let idx = w.index_of(&pen_pal);

    let mut compact = w.clone();
    compact.actions[idx].memo = None;
    ui_clear();
    let result = compact.verify(&mut signer);
    assert!(matches!(result, Err(HwSignerError::MemoRequired { .. })), "compact: {:?}", result);
    assert_nothing_shown("zero-value message sent compact");
    assert_nothing_signable(&mut signer, &compact, &ua(&to));

    let mut no_memo = [0u8; 512];
    no_memo[0] = 0xF6;
    for (what, memo) in [("ZIP-302 no-memo", no_memo), ("all zeroes", [0u8; 512])] {
        let mut lied = w.clone();
        lied.actions[idx].memo = Some(memo);
        ui_clear();
        let result = lied.verify(&mut signer);
        assert!(
            matches!(&result, Err(HwSignerError::DeviceError(m)) if m.starts_with("MemoMismatch")),
            "message declared as {}: {:?}",
            what,
            result
        );
        assert_nothing_shown(what);
        assert_nothing_signable(&mut signer, &lied, &ua(&to));
    }
}

/// The device has its own consensus-branch allow-list. `PcztHardwareSigning`
/// refuses a PCZT for any other branch before talking to the device (see
/// the unit tests of `check_branch`); here the host gate is bypassed and a
/// TxMeta for a pre-NU6.3, unknown or zero branch is sent straight to the
/// device, with a sighash that is correct for that branch.
#[test]
fn sec_branch_allow_list_is_enforced_by_the_device() {
    let mut signer = connect_signer(COIN_TYPE_MAINNET);
    let fvk = device_fvk(&mut signer);
    let (w, to) = payment_with_change(&fvk, HEIGHT_NU7);

    for branch in [
        0xC8E7_1055u32, // NU6
        0x4DEC_4DF0,    // NU6.1
        0xC2D6_D0B4,    // NU5
        0x76B8_09BB,    // Sapling
        0xDEAD_BEEF,    // not a branch
        0,
        BRANCH_NU7 + 1,
    ] {
        let mut bad = w.clone();
        bad.meta.consensus_branch_id = branch;
        bad.sighash = compute_zip244_sighash(&bad.meta, &bad.actions);
        ui_clear();

        // Raw frame.
        match bad.send_meta(signer.codec_mut()) {
            Err(HwSignerError::BranchNotAllowed { reason }) => {
                assert!(reason.contains("branch"), "{}", reason)
            }
            other => panic!("branch {:#010x}: expected BranchNotAllowed, got {:?}", branch, other),
        }
        // And through the device API.
        let result = bad.verify(&mut signer);
        assert!(
            matches!(result, Err(HwSignerError::BranchNotAllowed { .. })),
            "branch {:#010x}: {:?}",
            branch,
            result
        );
        assert_nothing_shown("refused branch");
        assert_nothing_signable(&mut signer, &bad, &ua(&to));
    }

    // NU6.3 and NU7 are both accepted (same actions, sighash recomputed
    // for each branch), reviewed and signed.
    for branch in [BRANCH_NU6_3, BRANCH_NU7] {
        let mut ok = w.clone();
        ok.meta.consensus_branch_id = branch;
        ok.sighash = compute_zip244_sighash(&ok.meta, &ok.actions);
        ok.verify(&mut signer)
            .unwrap_or_else(|e| panic!("branch {:#010x} must be accepted: {:?}", branch, e));
        assert_eq!(ok.sign_all(&mut signer, &ua(&to)).expect("sign"), 1);
        // sign_all asked for the only real spend of a two-action bundle;
        // start the next transaction from a clean session.
        signer.codec_mut().abort().expect("abort");
    }
}

/// RAW FRAMES. Actions must arrive in order, once each, with the total the
/// TxMeta announced, and all of them before the sighash sentinel. Anything
/// else ends the session before the user is asked anything.
#[test]
fn sec_action_stream_must_be_in_order_and_complete() {
    let mut signer = connect_signer(COIN_TYPE_MAINNET);
    let fvk = device_fvk(&mut signer);
    let (w, to) = payment_with_change(&fvk, HEIGHT_NU7);
    assert_eq!(w.n(), 2);
    let a0 = w.actions[0].serialize_v6();
    let a1 = w.actions[1].serialize_v6();

    type Step<'a> = (u16, u16, &'a [u8]);
    let invalid_state = "InvalidState";
    let cases: Vec<(&str, Vec<Step>, Step, &str)> = vec![
        ("out of order: action 1 first", vec![], (1, 2, &a1), invalid_state),
        ("repeated: action 0 twice", vec![(0, 2, &a0)], (0, 2, &a0), invalid_state),
        ("skipped: action 0 then index 2 of 3", vec![(0, 2, &a0)], (2, 3, &a1), invalid_state),
        ("wrong total on an action", vec![], (0, 3, &a0), invalid_state),
        ("missing: sentinel after one of two actions", vec![(0, 2, &a0)], (2, 2, &w.sighash), invalid_state),
        ("missing: sentinel right after the metadata", vec![], (2, 2, &w.sighash), invalid_state),
        ("missing: sentinel claiming a total of one", vec![(0, 2, &a0)], (1, 1, &w.sighash), invalid_state),
        ("surplus: a third action", vec![(0, 2, &a0), (1, 2, &a1)], (2, 2, &a0), "BadSighash"),
    ];
    for (what, prefix, offending, expected) in cases {
        ui_clear();
        let codec = signer.codec_mut();
        w.send_meta(codec).unwrap_or_else(|e| panic!("{}: meta: {:?}", what, e));
        for (index, total, data) in prefix {
            codec
                .send_tx_output(index, total, data)
                .unwrap_or_else(|e| panic!("{}: prefix frame {}: {:?}", what, index, e));
        }
        let result = codec.send_tx_output(offending.0, offending.1, offending.2);
        assert!(
            matches!(&result, Err(HwSignerError::DeviceError(m)) if m.starts_with(expected)),
            "{}: expected {}, got {:?}",
            what,
            expected,
            result
        );
        assert_nothing_shown(what);
        assert_nothing_signable(&mut signer, &w, &ua(&to));
    }

    // The same action in both slots is a different transaction: the device
    // reviews what it was given and then finds the sighash does not match.
    ui_clear();
    let codec = signer.codec_mut();
    w.send_meta(codec).expect("meta");
    codec.send_tx_output(0, 2, &a0).expect("action 0");
    codec.send_tx_output(1, 2, &a0).expect("action 0 again, as action 1");
    let result = w.send_sentinel(codec);
    assert!(
        matches!(result, Err(HwSignerError::SignatureVerificationFailed { .. })),
        "duplicated action: expected a sighash mismatch, got {:?}",
        result
    );
    assert_nothing_signable(&mut signer, &w, &ua(&to));
}

/// RAW FRAMES. Once the totals have been computed and the transaction
/// verified, nothing more can be fed into it: any further transaction data
/// ends the session, and nothing can be signed afterwards.
#[test]
fn sec_nothing_is_accepted_after_the_totals() {
    let mut signer = connect_signer(COIN_TYPE_MAINNET);
    let fvk = device_fvk(&mut signer);
    let (w, to) = payment_with_change(&fvk, HEIGHT_NU7);
    let a0 = w.actions[0].serialize_v6();
    let t_out = build_test_transparent_output(0).serialize();
    let t_in = build_test_transparent_input(0).serialize();
    let meta = w.meta.serialize();

    let late: Vec<(&str, MsgType, u16, u16, &[u8])> = vec![
        ("an action in slot 0", MsgType::TxOutput, 0, 2, &a0),
        ("an action in slot 1", MsgType::TxOutput, 1, 2, &a0),
        ("an action in the sentinel slot", MsgType::TxOutput, 2, 2, &a0),
        ("the sentinel again", MsgType::TxOutput, 2, 2, &w.sighash),
        ("a transparent output", MsgType::TxTransparentOutput, 0, 1, &t_out),
        ("a transparent input", MsgType::TxTransparentInput, 0, 1, &t_in),
    ];
    for (what, msg, index, total, data) in late {
        w.verify(&mut signer).unwrap_or_else(|e| panic!("{}: verify: {:?}", what, e));
        let codec = signer.codec_mut();
        let result = match msg {
            MsgType::TxOutput => codec.send_tx_output(index, total, data),
            MsgType::TxTransparentOutput => codec.send_transparent_output(index, total, data),
            _ => codec.send_transparent_input(index, total, data),
        };
        assert!(result.is_err(), "{} after the totals must be refused", what);
        assert_nothing_signable(&mut signer, &w, &ua(&to));
    }

    // A new TxMeta is not refused: it starts a new transaction, and the
    // verified one — with its approvals — is gone.
    w.verify(&mut signer).expect("verify");
    signer
        .codec_mut()
        .send_tx_output(0xFFFF, 2, &meta)
        .expect("a new TxMeta starts a new transaction");
    assert_nothing_signable(&mut signer, &w, &ua(&to));
}

/// The session ends with the last signature of a transaction; the next
/// transaction on the same connection gets its own review and its own
/// final confirmation.
///
/// RAW FRAMES for the second SIGN_REQ of transaction A: the device counts
/// SIGN_REQs against the number of actions (two here), while a real host
/// only asks for the real spends (one). See
/// `sec_second_transaction_after_signing_only_the_real_spends` for what a
/// real host does.
#[test]
fn sec_second_transaction_in_the_same_session_is_confirmed_again() {
    let mut signer = connect_signer(COIN_TYPE_MAINNET);
    let fvk = device_fvk(&mut signer);
    let (a, to_a) = payment_with_change(&fvk, HEIGHT_NU7);
    let to_b = foreign_address(2);
    let b = wire_from_pczt(
        &build_pczt(
            &fvk,
            &TxSpec::ironwood(
                HEIGHT_NU7,
                NOTE_VALUE,
                vec![pay(&fvk, to_b, 123_456, MemoBytes::empty()), change(&fvk, NOTE_VALUE - 123_456 - FEE_2)],
            ),
        ),
        &fvk,
    );

    ui_clear();
    a.verify(&mut signer).expect("A: verify");
    assert_eq!(a.sign_all(&mut signer, &ua(&to_a)).expect("A: sign"), 1);
    // One SIGN_REQ per action completes A on the device.
    let mut second = a.sign_request(0, &ua(&to_a));
    second.alpha = [0x01; 32];
    signer.sign_action(&second).expect("A: second SIGN_REQ");
    assert_eq!(screens_named(&ui_screens(), "confirm_tx").len(), 1, "one confirmation covers A");

    // A is done: its sighash is no longer signable, and B's never was.
    assert_nothing_signable(&mut signer, &a, &ua(&to_a));
    assert_nothing_signable(&mut signer, &b, &ua(&to_b));

    // B gets a complete review of its own...
    ui_clear();
    b.verify(&mut signer).expect("B: verify in the same session");
    let screens = ui_screens();
    assert_eq!(shown_outputs(&screens).len(), 2);
    assert_eq!(shown_totals(&screens).num("total_leaving"), 123_456 + FEE_2);
    assert!(screens_named(&screens, "confirm_tx").is_empty());
    // ...and its own final confirmation, with its own numbers.
    assert_eq!(b.sign_all(&mut signer, &ua(&to_b)).expect("B: sign"), 1);
    let confirms: Vec<Screen> = ui_screens().into_iter().filter(|s| s.name == "confirm_tx").collect();
    assert_eq!(confirms.len(), 1, "B must be confirmed again");
    assert_eq!(confirms[0].num("total_leaving"), 123_456 + FEE_2);
}

/// What `PcztHardwareSigning` does on one connection: it asks for the real
/// spends only (one, in a two-action bundle) and then starts the next
/// transaction. The device closes the first transaction when the next
/// TxMeta arrives; the second one gets a review and a confirmation of its
/// own, and the first one's sighash is no longer signable.
#[test]
fn sec_second_transaction_after_signing_only_the_real_spends() {
    let mut signer = connect_signer(COIN_TYPE_MAINNET);
    let fvk = device_fvk(&mut signer);
    let (a, to_a) = payment_with_change(&fvk, HEIGHT_NU7);
    let (b, to_b) = payment_with_change(&fvk, HEIGHT_NU7);

    a.verify(&mut signer).expect("A: verify");
    assert_eq!(a.sign_all(&mut signer, &ua(&to_a)).expect("A: sign"), 1);

    ui_clear();
    b.verify(&mut signer)
        .expect("B: the next transaction on the same connection must be accepted");
    assert_eq!(b.sign_all(&mut signer, &ua(&to_b)).expect("B: sign"), 1);
    let screens = ui_screens();
    assert_eq!(shown_outputs(&screens).len(), 2, "B is reviewed");
    assert_eq!(screens_named(&screens, "review_totals").len(), 1);
    assert_eq!(screens_named(&screens, "confirm_tx").len(), 1, "B is confirmed again");
}

/// The user says no at an output screen, at a memo, or at the totals: the
/// host gets `UserCancelled`, no later screen is shown, nothing can be
/// signed, and the session is back to idle (the same transaction can be
/// submitted again and is reviewed from the start).
#[test]
fn sec_user_rejects_during_review() {
    let mut signer = connect_signer(COIN_TYPE_MAINNET);
    let fvk = device_fvk(&mut signer);
    let (w, to) = payment_with_change(&fvk, HEIGHT_NU7);

    // (step, screens expected up to and including the refused one)
    let payment_first = w.index_of(&to) == 0;
    let cases: Vec<(&str, Vec<&str>)> = vec![
        ("output:1", vec!["review_output"]),
        (
            "output:2",
            if payment_first {
                vec!["review_output", "review_memo", "review_output"]
            } else {
                vec!["review_output", "review_output"]
            },
        ),
        (
            "memo:1",
            if payment_first {
                vec!["review_output", "review_memo"]
            } else {
                vec!["review_output", "review_output", "review_memo"]
            },
        ),
        (
            "totals",
            if payment_first {
                vec!["review_output", "review_memo", "review_output", "review_totals"]
            } else {
                vec!["review_output", "review_output", "review_memo", "review_totals"]
            },
        ),
    ];
    for (step, expected_screens) in cases {
        ui_clear();
        ui_reject_at(step);
        let result = w.verify(&mut signer);
        assert!(
            matches!(result, Err(HwSignerError::UserCancelled)),
            "refusal at {}: expected UserCancelled, got {:?}",
            step,
            result
        );
        let screens = ui_screens();
        let names: Vec<&str> = screens.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, expected_screens, "refusal at {}", step);
        let (last, before) = screens.split_last().unwrap();
        assert!(!last.approved(), "refusal at {}: {:?}", step, last);
        assert!(before.iter().all(|s| s.approved()));
        assert_nothing_signable(&mut signer, &w, &ua(&to));
    }

    // Back to idle: the same transaction, submitted again, is reviewed from
    // the first screen and signed.
    ui_clear();
    w.verify(&mut signer).expect("resubmission after a refusal");
    assert_eq!(shown_outputs(&ui_screens()).len(), 2);
    assert_eq!(w.sign_all(&mut signer, &ua(&to)).expect("sign"), 1);
}

/// The user approves the whole review and says no at the final
/// confirmation: no signature is returned, and the refusal ends the
/// session — the host cannot simply ask again.
#[test]
fn sec_user_rejects_final_confirmation() {
    let mut signer = connect_signer(COIN_TYPE_MAINNET);
    let fvk = device_fvk(&mut signer);
    let (w, to) = payment_with_change(&fvk, HEIGHT_NU7);

    ui_clear();
    w.verify(&mut signer).expect("verify");
    ui_reject_at("confirm");
    let result = signer.sign_action(&w.sign_request(0, &ua(&to)));
    assert!(
        matches!(result, Err(HwSignerError::UserCancelled)),
        "expected UserCancelled, got {:?}",
        result
    );
    let screens = ui_screens();
    let confirms = screens_named(&screens, "confirm_tx");
    assert_eq!(confirms.len(), 1);
    assert!(!confirms[0].approved());
    assert_eq!(confirms[0].num("total_leaving"), PAY_VALUE + FEE_2);

    // Asking again does not bring the prompt back.
    assert_nothing_signable(&mut signer, &w, &ua(&to));
}

/// The recipient, amount and fee a host puts in SIGN_REQ are ignored: an
/// empty recipient, an address that is not in the transaction, and nonsense
/// numbers all get the same final screen — the device's own totals, with no
/// host-supplied string on it — and at most one signature per action.
#[test]
fn sec_sign_req_recipient_amount_and_fee_are_ignored() {
    let mut signer = connect_signer(COIN_TYPE_MAINNET);
    let fvk = device_fvk(&mut signer);
    let (w, to) = payment_with_change(&fvk, HEIGHT_NU7);
    assert_eq!(w.n(), 2);

    w.verify(&mut signer).expect("verify");
    ui_clear();
    // First signature: SIGN_REQ names an address that is not in the
    // transaction (and absurd numbers, see sign_request()).
    assert_eq!(w.sign_all(&mut signer, &ua(&foreign_address(5))).expect("sign"), 1);
    let screens = ui_screens();
    let confirms = screens_named(&screens, "confirm_tx");
    assert_eq!(confirms.len(), 1);
    assert_eq!(confirms[0].num("total_leaving"), PAY_VALUE + FEE_2);
    assert_eq!(confirms[0].num("fee"), FEE_2);
    let mut keys: Vec<&str> = confirms[0].fields.keys().map(|k| k.as_str()).collect();
    keys.sort();
    assert_eq!(
        keys,
        ["decision", "fee", "n_external", "n_transparent_out", "total_leaving"],
        "the final screen carries device-computed numbers only"
    );

    // Second (and last: two actions) signature: empty recipient. No second
    // prompt.
    let mut second = w.sign_request(0, "");
    second.alpha = [0x01; 32];
    signer.sign_action(&second).expect("SIGN_REQ with an empty recipient");
    assert_eq!(screens_named(&ui_screens(), "confirm_tx").len(), 1);

    // One signature per action: a third request is refused.
    assert_nothing_signable(&mut signer, &w, &ua(&to));

    // The public workflow call without TxDetails (empty recipient) is
    // covered by the unit tests; here through the device API.
    w.verify(&mut signer).expect("verify again");
    assert_eq!(w.sign_all(&mut signer, "").expect("sign with an empty recipient"), 1);
}

/// A shielded -> transparent send: the transparent output is the payment.
/// It is shown first, as a t-address, and counted as leaving the wallet.
/// Built with the upstream builder, driven through the device API.
#[test]
fn sec_transparent_output_is_shown_and_counted_as_leaving() {
    let mut signer = connect_signer(COIN_TYPE_MAINNET);
    let fvk = device_fvk(&mut signer);
    let pkh = [0x33u8; 20];
    let fee = 15_000; // 2 Ironwood actions + 1 transparent output
    let change_value = NOTE_VALUE - 400_000 - fee;
    let spec = TxSpec {
        height: HEIGHT_NU7,
        spend_pool: ShieldedPoolKind::Ironwood,
        note_value: NOTE_VALUE,
        outputs: vec![change(&fvk, change_value)],
        t_outputs: vec![(pkh, 400_000)],
        t_input: None,
    };
    let w = wire_from_pczt(&build_pczt(&fvk, &spec), &fvk);
    assert_eq!(w.t_outputs.len(), 1);
    assert!(w.t_inputs.is_empty());

    ui_clear();
    w.verify(&mut signer).expect("verify");
    let screens = ui_screens();
    let outs = shown_outputs(&screens);
    assert_eq!(
        outs,
        vec![
            ("transparent".to_string(), taddr(pkh), 400_000),
            ("own-change".to_string(), ua(&fvk.address_at(0u32, Scope::Internal)), change_value),
        ]
    );
    let totals = shown_totals(&screens);
    assert_eq!(totals.num("total_leaving"), 400_000 + fee);
    assert_eq!(totals.num("transparent_out"), 400_000);
    assert_eq!(totals.num("n_transparent_out"), 1);
    assert_eq!(totals.num("fee"), fee);

    let t_screen = &screens_named(&screens, "review_output")[0];
    assert_eq!(t_screen.get("memo"), "n/a", "a transparent output has no memo field");

    assert_eq!(w.sign_all(&mut signer, &taddr(pkh)).expect("sign"), 1);
    let confirm = ui_screens().into_iter().find(|s| s.name == "confirm_tx").expect("confirm_tx");
    assert_eq!(confirm.num("total_leaving"), 400_000 + fee);
    assert_eq!((confirm.num("n_external"), confirm.num("n_transparent_out")), (0, 1));
}

/// The fee on the screen is the device's own arithmetic over the value
/// balances it hashed into the sighash — a host that inflates the fee sees
/// the inflated number on the device, and an unbalanced transaction
/// (negative fee) is refused before any screen. (Sighash recomputed here
/// for the altered TxMeta: this is a hostile host with a consistent lie.)
#[test]
fn sec_fee_is_computed_by_the_device() {
    let mut signer = connect_signer(COIN_TYPE_MAINNET);
    let fvk = device_fvk(&mut signer);
    let (w, to) = payment_with_change(&fvk, HEIGHT_NU7);

    let mut inflated = w.clone();
    inflated.meta.ironwood_value_balance += 250_000;
    inflated.sighash = compute_zip244_sighash(&inflated.meta, &inflated.actions);
    ui_clear();
    inflated.verify(&mut signer).expect("consistent, if expensive");
    let totals = shown_totals(&ui_screens());
    assert_eq!(totals.num("fee"), FEE_2 + 250_000);
    assert_eq!(totals.num("total_leaving"), PAY_VALUE + FEE_2 + 250_000);
    signer.codec_mut().abort().expect("abort");

    let mut negative = w.clone();
    negative.meta.ironwood_value_balance = -1;
    negative.sighash = compute_zip244_sighash(&negative.meta, &negative.actions);
    ui_clear();
    let result = negative.verify(&mut signer);
    assert!(
        matches!(&result, Err(HwSignerError::DeviceError(m)) if m.starts_with("FeeNegative")),
        "expected FeeNegative, got {:?}",
        result
    );
    assert_nothing_shown("negative fee");
    assert_nothing_signable(&mut signer, &negative, &ua(&to));
}

/// RAW FRAME. A TxMeta announcing more actions than the device can review
/// (16 by default) is refused with LIMIT_EXCEEDED at once.
#[test]
fn sec_too_many_actions_is_limit_exceeded() {
    let mut signer = connect_signer(COIN_TYPE_MAINNET);
    let fvk = device_fvk(&mut signer);
    let (w, _) = payment_with_change(&fvk, HEIGHT_NU7);
    ui_clear();
    let result = signer.codec_mut().send_tx_output(0xFFFF, 17, &w.meta.serialize());
    match result {
        Err(HwSignerError::DeviceLimitExceeded { reason }) => {
            assert!(reason.contains("device can review"), "{}", reason)
        }
        other => panic!("expected DeviceLimitExceeded, got {:?}", other),
    }
    assert_nothing_shown("too many actions");
    // 16 is within the limit.
    signer
        .codec_mut()
        .send_tx_output(0xFFFF, 16, &w.meta.serialize())
        .expect("16 actions are accepted");
}

/// Memos that are not text are shown too, as bytes: an arbitrary-data memo
/// (lead byte 0xFF) and a "no memo" lead byte (0xF6) followed by data,
/// which is not an empty memo.
#[test]
fn sec_non_text_memos_are_shown_as_bytes() {
    let mut signer = connect_signer(COIN_TYPE_MAINNET);
    let fvk = device_fvk(&mut signer);
    let (a, b) = (foreign_address(1), foreign_address(2));
    let fee = 15_000;
    let spec = TxSpec::ironwood(
        HEIGHT_NU7,
        NOTE_VALUE,
        vec![
            pay(&fvk, a, 100_000, MemoBytes::from_bytes(&[0xFF, 0xDE, 0xAD, 0xBE, 0xEF]).unwrap()),
            pay(&fvk, b, 200_000, MemoBytes::from_bytes(&[0xF6, 0x00, 0x01]).unwrap()),
            change(&fvk, NOTE_VALUE - 300_000 - fee),
        ],
    );
    let w = wire_from_pczt(&build_pczt(&fvk, &spec), &fvk);

    ui_clear();
    w.verify(&mut signer).expect("verify");
    let screens = ui_screens();
    let memos = screens_named(&screens, "review_memo");
    assert_eq!(memos.len(), 2, "both memos must be shown: {:?}", memos);
    for (addr, prefix) in [(a, "ffdeadbeef00"), (b, "f6000100")] {
        let m = memos
            .iter()
            .find(|m| m.get("address") == ua(&addr))
            .unwrap_or_else(|| panic!("no memo screen for {}", ua(&addr)));
        assert_eq!(m.get("type"), "binary");
        assert!(m.get("hex").starts_with(prefix), "{}", m.get("hex"));
        assert_eq!(m.get("hex").len(), 1024);
    }
}

/// A hand-made action of either pool (the builder cannot produce these values):
/// a real note of `value` zatoshis to `to`, correctly committed and
/// encrypted with an empty memo. Spend side and out_ciphertext are filler,
/// which no device check covers except through the sighash.
fn handmade_action(pool: ShieldedPoolKind, to: orchard::Address, value: u64) -> ActionData {
    use orchard::note_encryption::{IronwoodDomain, IronwoodNoteEncryption};
    use zcash_note_encryption::Domain;

    let mut rng = UnwrapErr(SysRng);
    let mut no_memo = [0u8; 512];
    no_memo[0] = 0xF6;
    loop {
        let mut rho_bytes = [0u8; 32];
        let mut rseed_bytes = [0u8; 32];
        rng.fill_bytes(&mut rho_bytes);
        rng.fill_bytes(&mut rseed_bytes);
        let Some(rho) = Option::<Rho>::from(Rho::from_bytes(&rho_bytes)) else { continue };
        let Some(rseed) = Option::<RandomSeed>::from(RandomSeed::from_bytes(rseed_bytes, &rho))
        else {
            continue;
        };
        let Some(note) = Option::<orchard::Note>::from(orchard::Note::from_parts(
            to,
            orchard::value::NoteValue::from_raw(value),
            rho,
            rseed,
            match pool {
                ShieldedPoolKind::Orchard => NoteVersion::V2,
                ShieldedPoolKind::Ironwood => NoteVersion::V3,
            },
        )) else {
            continue;
        };
        // The two encryptor aliases share behaviour; the note's version
        // selects the plaintext lead byte.
        let enc = IronwoodNoteEncryption::new(None, note, no_memo);
        return ActionData {
            pool,
            cv_net: [0x01; 32],
            nullifier: rho.to_bytes(),
            rk: [0x03; 32],
            cmx: ExtractedNoteCommitment::from(note.commitment()).to_bytes(),
            ephemeral_key: IronwoodDomain::epk_bytes(enc.epk()).0,
            enc_ciphertext: enc.encrypt_note_plaintext().0.to_vec(),
            out_ciphertext: vec![0x07; 80],
            recipient: to.to_raw_address_bytes(),
            value,
            rseed: *rseed.as_bytes(),
            memo: Some(no_memo),
        };
    }
}

/// RAW FRAMES, hand-made notes: two real Ironwood notes, correctly
/// committed and encrypted, to a foreign address, whose values are
/// impossible together — 2^63 zatoshis each (the sum does not fit in 64
/// bits; each one is already above MAX_MONEY and is refused where it
/// enters), and 15,000,000 ZEC each (each one valid, the total above
/// MAX_MONEY: refused at the totals). VALUE_OVERFLOW either way, before any
/// screen.
#[test]
fn sec_output_values_overflowing_u64_are_refused() {
    let to = foreign_address(1);
    for value in [1u64 << 63, 15_000_000 * 100_000_000] {
        let actions = vec![
            handmade_action(ShieldedPoolKind::Ironwood, to, value),
            handmade_action(ShieldedPoolKind::Ironwood, to, value),
        ];
        let mut meta = build_test_tx_meta(COIN_TYPE_MAINNET);
        meta.ironwood_flags = 0x03;

        let mut signer = connect_signer(COIN_TYPE_MAINNET);
        signer.export_fvk().expect("FVK");
        ui_clear();
        let codec = signer.codec_mut();
        codec.send_tx_output(0xFFFF, 2, &meta.serialize()).expect("meta");
        let mut result = Ok(());
        for (i, a) in actions.iter().enumerate() {
            result = result.and_then(|_| codec.send_tx_output(i as u16, 2, &a.serialize_v6()));
        }
        let result =
            result.and_then(|_| codec.send_tx_output(2, 2, &compute_zip244_sighash(&meta, &actions)));
        assert!(
            matches!(result, Err(HwSignerError::ValueOverflow { .. })),
            "2 x {} zat: expected ValueOverflow, got {:?}",
            value,
            result
        );
        assert_nothing_shown("value overflow");
    }
}

/// RAW FRAMES, hand-made note: a single output of MAX_MONEY + 1 zatoshis
/// (21,000,000 ZEC + 1 zat), or of 2^64 - 1 — values no valid Zcash
/// transaction can carry — correctly committed and encrypted, with a
/// sighash that matches. The device refuses it where it enters, before any
/// screen. (Library 17d4ee0 reviewed and verified it.)
#[test]
fn sec_output_value_above_max_money_is_refused() {
    const MAX_MONEY: u64 = 21_000_000 * 100_000_000;
    let to = foreign_address(1);
    for value in [MAX_MONEY + 1, u64::MAX] {
        let actions = vec![handmade_action(ShieldedPoolKind::Ironwood, to, value), handmade_action(ShieldedPoolKind::Ironwood, to, 0)];
        let mut meta = build_test_tx_meta(COIN_TYPE_MAINNET);
        meta.ironwood_flags = 0x03;
        let sighash = compute_zip244_sighash(&meta, &actions);

        let mut signer = connect_signer(COIN_TYPE_MAINNET);
        signer.export_fvk().expect("FVK");
        ui_clear();
        let codec = signer.codec_mut();
        codec.send_tx_output(0xFFFF, 2, &meta.serialize()).expect("meta");
        let mut result = Ok(());
        for (i, a) in actions.iter().enumerate() {
            result = result.and_then(|_| codec.send_tx_output(i as u16, 2, &a.serialize_v6()));
        }
        let result = result.and_then(|_| codec.send_tx_output(2, 2, &sighash));
        let screens = ui_screens();
        assert!(
            result.is_err(),
            "an output of {} zat (> MAX_MONEY = {}) was accepted and verified; \
             the device showed: {:?}",
            value,
            MAX_MONEY,
            screens
        );
        assert!(screens.is_empty(), "refused, but only after showing {:?}", screens);
    }
}

/// The host does not attempt transparent inputs with the HWP device: a
/// PCZT that spends a transparent coin is refused with a typed error before
/// any proof is made and before anything is sent — by the workflow and by
/// `DeviceSigner` itself. (A transparent OUTPUT is fine: see
/// `sec_transparent_output_is_shown_and_counted_as_leaving`.)
#[test]
fn sec_host_refuses_transparent_inputs_before_touching_the_device() {
    let mut signer = connect_signer(COIN_TYPE_MAINNET);
    let fvk = device_fvk(&mut signer);
    let to = foreign_address(1);
    let spec = TxSpec {
        height: HEIGHT_NU7,
        spend_pool: ShieldedPoolKind::Ironwood,
        note_value: NOTE_VALUE,
        outputs: vec![
            pay(&fvk, to, PAY_VALUE, MemoBytes::empty()),
            change(&fvk, NOTE_VALUE + 50_000 - PAY_VALUE - 15_000),
        ],
        t_outputs: Vec::new(),
        t_input: Some(50_000),
    };
    let pczt = build_pczt(&fvk, &spec);
    let w = wire_from_pczt(&pczt, &fvk);
    assert!(!signer.supports_transparent_inputs());

    ui_clear();
    let result = w.verify(&mut signer);
    assert!(
        matches!(result, Err(HwSignerError::TransparentInputsNotSupported { inputs: 1 })),
        "DeviceSigner::verify_transaction: {:?}",
        result
    );

    let started = std::time::Instant::now();
    let mut workflow = PcztHardwareSigning::new(signer);
    let result = workflow.sign_with_details(
        pczt.serialize().expect("serialize"),
        Some(TxDetails {
            send_amount: PAY_VALUE,
            fee: 15_000,
            recipient: ua(&to),
            num_actions: 0,
            memo: None,
        }),
    );
    match result {
        Err(e @ HwSignerError::TransparentInputsNotSupported { inputs: 1 }) => {
            assert!(e.to_string().contains("not supported by this device"), "{}", e)
        }
        other => panic!("expected TransparentInputsNotSupported, got {:?}", other.map(|_| ())),
    }
    assert!(started.elapsed().as_secs() < 5, "refused before proving");
    assert_nothing_shown("PCZT with a transparent input");

    // The session was never started: an ordinary transaction goes through.
    let mut signer = workflow.into_signer();
    let (ok, to) = payment_with_change(&fvk, HEIGHT_NU7);
    ok.verify(&mut signer).expect("verify");
    assert_eq!(ok.sign_all(&mut signer, &ua(&to)).expect("sign"), 1);
}

// ── Group 12: defects found against earlier library revisions ────────
//
// Each of these was a failing `device_bug_*` test against an earlier
// library revision; they now assert the fixed behaviour.


/// A real transaction with a transparent INPUT, sent straight to the
/// device (RAW FRAMES — `DeviceSigner` and the workflow refuse it first,
/// see `sec_host_refuses_transparent_inputs_before_touching_the_device`):
/// the device refuses at the first input frame with
/// TRANSPARENT_INPUTS_UNSUPPORTED, before showing anything. (Earlier
/// revisions went through a review and then failed on a sighash that was
/// not the ZIP 244 one.)
#[test]
fn sec_device_refuses_a_real_transaction_with_a_transparent_input() {
    let mut signer = connect_signer(COIN_TYPE_MAINNET);
    let fvk = device_fvk(&mut signer);
    let to = foreign_address(1);
    let fee = 15_000; // 2 Ironwood actions + 1 transparent input
    let spec = TxSpec {
        height: HEIGHT_NU7,
        spend_pool: ShieldedPoolKind::Ironwood,
        note_value: NOTE_VALUE,
        outputs: vec![
            pay(&fvk, to, PAY_VALUE, MemoBytes::empty()),
            change(&fvk, NOTE_VALUE + 50_000 - PAY_VALUE - fee),
        ],
        t_outputs: Vec::new(),
        t_input: Some(50_000),
    };
    let w = wire_from_pczt(&build_pczt(&fvk, &spec), &fvk);
    assert_eq!(w.t_inputs.len(), 1);

    ui_clear();
    let result = w.verify_raw(signer.codec_mut());
    assert!(
        matches!(result, Err(HwSignerError::TransparentInputsNotSupported { inputs: 0 })),
        "expected the device's TRANSPARENT_INPUTS_UNSUPPORTED, got {:?}",
        result
    );
    assert_nothing_shown("transaction with a transparent input");
    assert_nothing_signable(&mut signer, &w, &ua(&to));
}

/// The final confirmation cannot be made to name an address the user never
/// reviewed. A hostile host pays its own address, adds a zero-value output
/// to the address the user MEANT to pay (padding: not shown) and names that
/// one in SIGN_REQ. Earlier revisions put that string on the final screen;
/// now the device ignores it: the review shows the thief's address as the
/// only payment and the final screen shows the device's totals and nothing
/// else.
#[test]
fn sec_final_confirmation_shows_nothing_from_the_host() {
    let mut signer = connect_signer(COIN_TYPE_MAINNET);
    let fvk = device_fvk(&mut signer);
    let (thief, intended) = (foreign_address(9), foreign_address(1));
    let fee = 15_000;
    let spec = TxSpec::ironwood(
        HEIGHT_NU7,
        NOTE_VALUE,
        vec![
            pay(&fvk, thief, PAY_VALUE, MemoBytes::empty()),
            pay(&fvk, intended, 0, MemoBytes::empty()), // decoy: zero value
            change(&fvk, NOTE_VALUE - PAY_VALUE - fee),
        ],
    );
    let w = wire_from_pczt(&build_pczt(&fvk, &spec), &fvk);

    ui_clear();
    w.verify(&mut signer).expect("verify");
    let reviewed = shown_outputs(&ui_screens());
    assert!(
        !reviewed.iter().any(|(_, addr, _)| *addr == ua(&intended)),
        "the zero-value decoy is not reviewed: {:?}",
        reviewed
    );
    assert!(reviewed.contains(&("external".to_string(), ua(&thief), PAY_VALUE)));

    ui_clear();
    w.sign_all(&mut signer, &ua(&intended)).expect("the recipient string is ignored");
    let transcript = control("LOG").join("\n");
    assert!(
        !transcript.contains(&ua(&intended)),
        "the decoy address reached the screen: {}",
        transcript
    );
    let screens = ui_screens();
    let confirms = screens_named(&screens, "confirm_tx");
    assert_eq!(confirms.len(), 1);
    assert_eq!(confirms[0].num("total_leaving"), PAY_VALUE + fee);
    assert_eq!(confirms[0].num("n_external"), 1);
}




/// RAW FRAMES. More transparent outputs than the device reviews (eight):
/// refused with LIMIT_EXCEEDED on the first output frame, which announces
/// the count. Eight are accepted.
#[test]
fn sec_too_many_transparent_outputs_is_limit_exceeded() {
    let mut codec = connect_codec();
    codec.request_fvk(COIN_TYPE_MAINNET).expect("FVK failed");
    let meta = build_test_tx_meta(COIN_TYPE_MAINNET).serialize();
    codec.send_tx_output(0xFFFF, 1, &meta).expect("TxMeta send failed");
    let result = codec.send_transparent_output(0, 9, &build_test_transparent_output(0).serialize());
    assert!(
        matches!(result, Err(HwSignerError::DeviceLimitExceeded { .. })),
        "nine transparent outputs should be LIMIT_EXCEEDED, got {:?}",
        result
    );

    codec.send_tx_output(0xFFFF, 1, &meta).expect("TxMeta send failed");
    for i in 0..8u8 {
        codec
            .send_transparent_output(i as u16, 8, &build_test_transparent_output(i).serialize())
            .unwrap_or_else(|e| panic!("transparent output {} of 8: {:?}", i + 1, e));
    }
    // In order only: a ninth frame, or a repeated index, is refused.
    assert!(codec
        .send_transparent_output(8, 8, &build_test_transparent_output(8).serialize())
        .is_err());
}

/// A pool with ZERO actions must have a zero value balance in TxMeta.
///
/// The sighash commits to an action-less pool through its empty-bundle
/// digest, which does not cover that pool's value balance. Earlier
/// revisions added that balance into the fee they showed, so a host could
/// hide part of the fee (declare -5,000 for the empty sealed-Orchard pool:
/// fee shown 5,000, real fee 10,000) without invalidating the signature.
/// The device now refuses such a TxMeta — in either direction — with
/// EMPTY_POOL_BALANCE, before any screen.
///
/// RAW: TxMeta altered by hand (the SDK derives it from the PCZT, where an
/// absent bundle has balance zero); the sighash is the real one.
#[test]
fn sec_value_balance_of_a_pool_without_actions_is_refused() {
    let mut signer = connect_signer(COIN_TYPE_MAINNET);
    let fvk = device_fvk(&mut signer);
    let (w, to) = payment_with_change(&fvk, HEIGHT_NU7);
    assert!(w.actions.iter().all(|a| a.pool == ShieldedPoolKind::Ironwood));
    assert_eq!(w.meta.value_balance, 0);

    const MAX_MONEY: i64 = 21_000_000 * 100_000_000;
    for delta in [-5_000i64, 250_000, -MAX_MONEY, MAX_MONEY, i64::MIN, i64::MAX] {
        let mut bad = w.clone();
        bad.meta.value_balance = delta; // sealed Orchard pool: no actions
        // The real sighash still matches: the empty-bundle digest ignores it.
        assert_eq!(compute_zip244_sighash(&bad.meta, &bad.actions), w.sighash);

        ui_clear();
        let result = bad.verify(&mut signer);
        // A balance beyond +-MAX_MONEY is refused as such (VALUE_OVERFLOW),
        // already with the metadata; anything else non-zero as
        // EMPTY_POOL_BALANCE.
        let ok = if delta.unsigned_abs() > MAX_MONEY as u64 {
            matches!(result, Err(HwSignerError::ValueOverflow { .. }))
        } else {
            matches!(result, Err(HwSignerError::EmptyPoolBalance { .. }))
        };
        assert!(
            ok,
            "Orchard value_balance {} with no Orchard action: got {:?}",
            delta,
            result
        );
        assert_nothing_shown("value balance of an empty pool");
        assert_nothing_signable(&mut signer, &bad, &ua(&to));
    }

    // The other way round (RAW, hand-made zero-value notes): two
    // sealed-Orchard actions, no Ironwood action, and an Ironwood balance.
    let orchard_only = vec![
        handmade_action(ShieldedPoolKind::Orchard, to, 0),
        handmade_action(ShieldedPoolKind::Orchard, to, 0),
    ];
    let mut meta = build_test_tx_meta(COIN_TYPE_MAINNET);
    meta.ironwood_value_balance = 5_000;
    ui_clear();
    let codec = signer.codec_mut();
    codec.send_tx_output(0xFFFF, 2, &meta.serialize()).expect("meta");
    let mut result = Ok(());
    for (i, a) in orchard_only.iter().enumerate() {
        result = result.and_then(|_| codec.send_tx_output(i as u16, 2, &a.serialize_v6()));
    }
    let result =
        result.and_then(|_| codec.send_tx_output(2, 2, &compute_zip244_sighash(&meta, &orchard_only)));
    assert!(
        matches!(result, Err(HwSignerError::EmptyPoolBalance { .. })),
        "Ironwood balance with no Ironwood action: {:?}",
        result
    );
    assert_nothing_shown("value balance of an empty Ironwood pool");
}

/// RAW FRAME. A transaction with no shielded action has nothing for the
/// device to authorize: a TxMeta announcing zero actions is refused.
#[test]
fn sec_zero_action_transaction_is_refused() {
    let mut codec = connect_codec();
    codec.request_fvk(COIN_TYPE_MAINNET).expect("FVK failed");
    ui_clear();
    let meta = build_test_tx_meta(COIN_TYPE_MAINNET);
    let result = codec.send_tx_output(0xFFFF, 0, &meta.serialize());
    assert!(result.is_err(), "TxMeta with zero actions must be refused");
    // Nor can a sentinel-shaped frame (index = total = 0) get anywhere.
    assert!(codec.send_tx_output(0, 0, &compute_zip244_sighash(&meta, &[])).is_err());
    assert_nothing_shown("zero-action transaction");
}
