// Copyright (c) 2026 prt1sn. All rights reserved.
//! Shared LiteSVM helpers of the emergency-recovery tests (`tests/recovery/`,
//! SPEC §5.6, §9.11): accounts, clock and `LastRestartSlot`, transactions,
//! event decoding, the tag 50 / 51 instruction builders, byte patches of
//! Phoenix `GlobalConfig` / `PerpAssetMap`, mainnet account snapshots and a
//! bare-SVM environment for the venue verdict.
//!
//! Real Phoenix state comes from two sources:
//! - mainnet snapshots of `GlobalConfig`, `PerpAssetMap`, the Phoenix program
//!   account and its `ProgramData`, fetched in CI by
//!   `tests/fixtures/fetch-recovery-mainnet.sh` (`SIJKA_RECOVERY_MAINNET_DIR`);
//! - the Rise localnet fixture run on the mainnet Phoenix / Ember / Hawkeye
//!   binaries (`recovery_vault.rs`).
//!
//! Without the artifacts the tests are skipped, unless
//! `RISE_SDK_LOCALNET_REQUIRE_PROGRAMS=1` / `SIJKA_REQUIRE_SO=1` is set (CI).

#![allow(dead_code)]

use std::path::PathBuf;

use litesvm::LiteSVM;
use litesvm::types::{FailedTransactionMetadata, TransactionMetadata};
use phoenix_rise_litesvm_test::sdk_localnet_vm_required;
use sijka_vault::constants as k;
use sijka_vault::error::SijkaError;
use sijka_vault::state::config::{CONFIG_LEN, Config, ConfigMut};
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

pub type TxResult = Result<TransactionMetadata, FailedTransactionMetadata>;

// ------------------------------------------------------------------ gating

fn env_on(k: &str) -> bool {
    matches!(std::env::var(k).as_deref(), Ok("1") | Ok("true"))
}

/// Missing artifacts fail the run instead of skipping it (CI).
pub fn required() -> bool {
    env_on("SIJKA_REQUIRE_SO") || sdk_localnet_vm_required()
}

/// Skip (return `None`) or panic when an artifact is missing.
pub fn need<T>(v: Option<T>, what: &str) -> Option<T> {
    match v {
        Some(v) => Some(v),
        None if required() => panic!("missing test artifact: {what}"),
        None => {
            eprintln!("skipping: {what} missing");
            None
        }
    }
}

pub fn program_so() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("SIJKA_VAULT_SO") {
        return Some(PathBuf::from(p)).filter(|p| p.exists());
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    [manifest.join("../../target/deploy/sijka_vault.so"), manifest.join("target/deploy/sijka_vault.so")]
        .into_iter()
        .find(|p| p.exists())
}

// -------------------------------------------------------------------- keys

pub fn pk(b: [u8; 32]) -> Pubkey {
    Pubkey::new_from_array(b)
}

pub fn phoenix_id() -> Pubkey {
    pk(k::PHOENIX_PROGRAM_ID)
}
pub fn phoenix_program_data() -> Pubkey {
    pk(k::PHOENIX_PROGRAM_DATA)
}
pub fn global_config_key() -> Pubkey {
    pk(k::PHOENIX_GLOBAL_CONFIG)
}
pub fn log_authority() -> Pubkey {
    pk(k::PHOENIX_LOG_AUTHORITY)
}
pub fn hawkeye_id() -> Pubkey {
    pk(k::HAWKEYE_PROGRAM_ID)
}
pub fn ember_id() -> Pubkey {
    pk(k::EMBER_PROGRAM_ID)
}
pub fn token_program() -> Pubkey {
    pk(k::SPL_TOKEN_PROGRAM_ID)
}
pub fn ata_program() -> Pubkey {
    pk(k::ATA_PROGRAM_ID)
}
pub fn system_program() -> Pubkey {
    pk(k::SYSTEM_PROGRAM_ID)
}
pub fn loader_v3() -> Pubkey {
    pk(k::BPF_LOADER_UPGRADEABLE_ID)
}
pub fn wsol_mint() -> Pubkey {
    pk(k::WSOL_MINT)
}

pub const CLOCK_SYSVAR: Pubkey = Pubkey::from_str_const("SysvarC1ock11111111111111111111111111111111");
pub const LAST_RESTART_SLOT_SYSVAR: Pubkey = Pubkey::from_str_const("SysvarLastRestartS1ot1111111111111111111111");
pub const SYSVAR_OWNER: Pubkey = Pubkey::from_str_const("Sysvar1111111111111111111111111111111111111");
pub const RENT_SYSVAR: Pubkey = Pubkey::from_str_const("SysvarRent111111111111111111111111111111111");
pub const COMPUTE_BUDGET: Pubkey = Pubkey::from_str_const("ComputeBudget111111111111111111111111111111");
/// Hawkeye's ProgramData (TR-8: a foreign ProgramData key).
pub const HAWKEYE_PROGRAM_DATA: Pubkey = Pubkey::from_str_const("Gv1WgG864CQqF5vedJVbpnhpRpRbTW1A7SyARzSw9B4Y");
/// Live mainnet `acknowledged_restart_slot` (appendix F §1.4).
pub const MAINNET_RESTART_SLOT: u64 = 246_464_040;

pub fn ata(owner: &Pubkey, mint: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[owner.as_ref(), token_program().as_ref(), mint.as_ref()], &ata_program()).0
}

pub fn phoenix_trader_pda(authority: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[k::SEED_PHOENIX_TRADER, authority.as_ref(), &[0, 0]], &phoenix_id())
}

pub fn spline_pda(orderbook: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"spline", orderbook.as_ref()], &phoenix_id()).0
}

/// All PDAs of our program (SPEC §2.1) and the ATAs `initialize` records.
#[derive(Clone, Copy, Debug)]
pub struct Pdas {
    pub config: Pubkey,
    pub buyback_state: Pubkey,
    pub bb_unwrap: Pubkey,
    pub fee_inbox: Pubkey,
    pub phx_authority: Pubkey,
    pub swap_authority: Pubkey,
    pub buyback_authority: Pubkey,
    pub rent_payer: Pubkey,
    pub creator_escrow: Pubkey,
}

impl Pdas {
    pub fn derive(program_id: &Pubkey) -> Self {
        let f = |seed: &[u8]| Pubkey::find_program_address(&[seed], program_id).0;
        Self {
            config: f(k::SEED_CONFIG),
            buyback_state: f(k::SEED_BUYBACK_STATE),
            bb_unwrap: f(k::SEED_BB_UNWRAP),
            fee_inbox: f(k::SEED_FEE_INBOX),
            phx_authority: f(k::SEED_PHX_AUTHORITY),
            swap_authority: f(k::SEED_SWAP_AUTHORITY),
            buyback_authority: f(k::SEED_BUYBACK_AUTHORITY),
            rent_payer: f(k::SEED_RENT_PAYER),
            creator_escrow: f(k::SEED_CREATOR_ESCROW),
        }
    }
}

// ---------------------------------------------------------------- accounts

/// Create or replace an account. `solana_account::Account` is not a direct
/// dependency, so an existing sysvar account serves as the value template.
pub fn put(svm: &mut LiteSVM, key: Pubkey, owner: Pubkey, lamports: u64, data: Vec<u8>, executable: bool) {
    let mut acc = svm.get_account(&RENT_SYSVAR).expect("rent sysvar");
    acc.lamports = lamports;
    acc.data = data;
    acc.owner = owner;
    acc.executable = executable;
    acc.rent_epoch = 0;
    svm.set_account(key, acc).expect("set_account");
}

/// Rent-exempt account with `data`.
pub fn put_rent_exempt(svm: &mut LiteSVM, key: Pubkey, owner: Pubkey, data: Vec<u8>) {
    let lamports = svm.minimum_balance_for_rent_exemption(data.len());
    put(svm, key, owner, lamports, data, false);
}

/// Remove an account (0 lamports): the runtime then sees owner System, no data.
pub fn remove(svm: &mut LiteSVM, key: Pubkey) {
    if let Some(mut acc) = svm.get_account(&key) {
        acc.lamports = 0;
        acc.data = vec![];
        acc.owner = system_program();
        acc.executable = false;
        svm.set_account(key, acc).expect("remove account");
    }
}

pub fn data_of(svm: &LiteSVM, key: &Pubkey) -> Vec<u8> {
    svm.get_account(key).map(|a| a.data).unwrap_or_default()
}

pub fn lamports(svm: &LiteSVM, key: &Pubkey) -> u64 {
    svm.get_account(key).map(|a| a.lamports).unwrap_or(0)
}

/// Rewrite the data of an existing account (owner and lamports unchanged).
pub fn patch(svm: &mut LiteSVM, key: &Pubkey, f: impl FnOnce(&mut Vec<u8>)) {
    let mut acc = svm.get_account(key).unwrap_or_else(|| panic!("missing account {key}"));
    f(&mut acc.data);
    svm.set_account(*key, acc).expect("patch account");
}

pub fn set_owner(svm: &mut LiteSVM, key: &Pubkey, owner: Pubkey) {
    let mut acc = svm.get_account(key).unwrap_or_else(|| panic!("missing account {key}"));
    acc.owner = owner;
    svm.set_account(*key, acc).expect("set owner");
}

/// SPL token amount (`@64`), 0 for a missing account.
pub fn token_amount(svm: &LiteSVM, key: &Pubkey) -> u64 {
    let d = data_of(svm, key);
    if d.len() < 72 { 0 } else { u64::from_le_bytes(d[64..72].try_into().unwrap()) }
}

pub fn rd_u8(d: &[u8], o: usize) -> u8 {
    d[o]
}
pub fn rd_u16(d: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(d[o..o + 2].try_into().unwrap())
}
pub fn rd_u32(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(d[o..o + 4].try_into().unwrap())
}
pub fn rd_u64(d: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(d[o..o + 8].try_into().unwrap())
}
pub fn rd_i64(d: &[u8], o: usize) -> i64 {
    i64::from_le_bytes(d[o..o + 8].try_into().unwrap())
}
pub fn rd_key(d: &[u8], o: usize) -> Pubkey {
    Pubkey::new_from_array(d[o..o + 32].try_into().unwrap())
}
pub fn wr_u16(d: &mut [u8], o: usize, v: u16) {
    d[o..o + 2].copy_from_slice(&v.to_le_bytes());
}
pub fn wr_u32(d: &mut [u8], o: usize, v: u32) {
    d[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
pub fn wr_u64(d: &mut [u8], o: usize, v: u64) {
    d[o..o + 8].copy_from_slice(&v.to_le_bytes());
}
pub fn wr_i64(d: &mut [u8], o: usize, v: i64) {
    d[o..o + 8].copy_from_slice(&v.to_le_bytes());
}

// ------------------------------------------------------ clock / restart slot

/// `(slot, unix_timestamp)` of the Clock sysvar.
pub fn clock(svm: &LiteSVM) -> (u64, i64) {
    let d = data_of(svm, &CLOCK_SYSVAR);
    (rd_u64(&d, 0), rd_i64(&d, 32))
}

/// Set `Clock.slot` and `Clock.unix_timestamp` (bincode layout: slot,
/// epoch_start_timestamp, epoch, leader_schedule_epoch, unix_timestamp).
pub fn set_clock(svm: &mut LiteSVM, slot: u64, ts: i64) {
    let mut d = data_of(svm, &CLOCK_SYSVAR);
    assert_eq!(d.len(), 40, "Clock sysvar layout");
    wr_u64(&mut d, 0, slot);
    wr_i64(&mut d, 32, ts);
    put(svm, CLOCK_SYSVAR, SYSVAR_OWNER, 1_169_280, d, false);
}

/// `sol_get_last_restart_slot()` as seen by programs.
pub fn set_last_restart_slot(svm: &mut LiteSVM, lrs: u64) {
    put(svm, LAST_RESTART_SLOT_SYSVAR, SYSVAR_OWNER, 946_560, lrs.to_le_bytes().to_vec(), false);
}

// ------------------------------------------------------------ transactions

pub fn cu_limit_ix(units: u32) -> Instruction {
    let mut data = vec![2u8];
    data.extend_from_slice(&units.to_le_bytes());
    Instruction { program_id: COMPUTE_BUDGET, accounts: vec![], data }
}

/// Sign and send `ixs` (with a 1.4M CU limit) paid by `payer`.
pub fn send(svm: &mut LiteSVM, payer: &Keypair, signers: &[&Keypair], ixs: Vec<Instruction>) -> TxResult {
    let mut all = vec![cu_limit_ix(1_400_000)];
    all.extend(ixs);
    let mut s: Vec<&Keypair> = vec![payer];
    s.extend_from_slice(signers);
    svm.expire_blockhash();
    let tx = Transaction::new_signed_with_payer(&all, Some(&payer.pubkey()), &s, svm.latest_blockhash());
    svm.send_transaction(tx)
}

pub fn code(e: SijkaError) -> u32 {
    e.code()
}

pub fn err_text(r: &TxResult) -> String {
    match r {
        Ok(_) => "ok".to_string(),
        Err(f) => format!("{:?}", f.err),
    }
}

/// Program log lines of a result (success or failure).
pub fn logs(r: &TxResult) -> &[String] {
    match r {
        Ok(m) => &m.logs,
        Err(f) => &f.meta.logs,
    }
}

/// Assert a failure with our error `e` (code and log line).
#[track_caller]
pub fn assert_err(r: &TxResult, e: SijkaError) {
    match r {
        Ok(m) => panic!("expected {e:?}, got success; logs:\n{}", m.logs.join("\n")),
        Err(f) => {
            let s = format!("{:?}", f.err);
            assert!(
                s.contains(&format!("Custom({})", e.code())),
                "expected {e:?} ({}), got {s}; logs:\n{}",
                e.code(),
                f.meta.logs.join("\n")
            );
            assert!(f.meta.logs.iter().any(|l| l.contains(e.log_line())), "log line {} missing", e.log_line());
        }
    }
}

#[track_caller]
pub fn assert_ok(r: &TxResult) -> &TransactionMetadata {
    match r {
        Ok(m) => m,
        Err(f) => panic!("expected success, got {:?}; logs:\n{}", f.err, f.meta.logs.join("\n")),
    }
}

// ----------------------------------------------------------------- events

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn b64_decode(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        if c == b'=' {
            break;
        }
        let Some(v) = B64.iter().position(|&x| x == c) else { continue };
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

/// Every `sol_log_data` record of our program (`SJKEV…` tag), in order.
pub fn events(log: &[String]) -> Vec<Vec<u8>> {
    log.iter()
        .filter_map(|l| l.strip_prefix("Program data: "))
        .map(|s| b64_decode(s.split_whitespace().next().unwrap_or("")))
        .filter(|d| d.len() >= 17 && d.starts_with(b"SJKEV"))
        .collect()
}

pub fn event(log: &[String], tag: &[u8; 8]) -> Option<Vec<u8>> {
    events(log).into_iter().find(|d| d.starts_with(tag))
}

/// `SJKEVVOB` (SPEC §7, 76 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vob {
    pub ts: i64,
    pub verdict: u8,
    pub reason: u8,
    pub exchange_status: u8,
    pub majors_open: u8,
    pub majors_closed: u8,
    pub majors_unknown: u8,
    pub flags: u8,
    pub slot: u64,
    pub ack: u64,
    pub lrs: u64,
    pub live: u32,
    pub down_since: i64,
    pub last_down_obs_ts: i64,
    pub obs_count: u64,
}

pub const UP: u8 = 1;
pub const DOWN: u8 = 2;
pub const UNKNOWN: u8 = 3;

impl Vob {
    pub fn parse(d: &[u8]) -> Self {
        assert_eq!(d.len(), 76, "SJKEVVOB length");
        assert_eq!(&d[0..8], b"SJKEVVOB");
        assert_eq!(d[8], 1, "event version");
        Self {
            ts: rd_i64(d, 9),
            verdict: d[17],
            reason: d[18],
            exchange_status: d[19],
            majors_open: d[20],
            majors_closed: d[21],
            majors_unknown: d[22],
            flags: d[23],
            slot: rd_u64(d, 24),
            ack: rd_u64(d, 32),
            lrs: rd_u64(d, 40),
            live: rd_u32(d, 48),
            down_since: rd_i64(d, 52),
            last_down_obs_ts: rd_i64(d, 60),
            obs_count: rd_u64(d, 68),
        }
    }

    /// From a successful tag 50 / op 0: the event (and, for tag 50, the
    /// return data, which must be the same 76 bytes).
    #[track_caller]
    pub fn from_meta(m: &TransactionMetadata) -> Self {
        let ev = event(&m.logs, b"SJKEVVOB").expect("SJKEVVOB event");
        let v = Self::parse(&ev);
        if v.flags & 1 == 0 {
            assert_eq!(m.return_data.data, ev, "tag 50 return data = SJKEVVOB payload");
        }
        v
    }
}

// ------------------------------------------------- our instruction builders

pub fn observe_metas(config: Pubkey, gc: Pubkey, pam: Pubkey) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new(config, false),
        AccountMeta::new_readonly(gc, false),
        AccountMeta::new_readonly(pam, false),
        AccountMeta::new_readonly(phoenix_id(), false),
        AccountMeta::new_readonly(phoenix_program_data(), false),
    ]
}

pub fn observe_ix(program_id: Pubkey, config: Pubkey, pam: Pubkey) -> Instruction {
    Instruction { program_id, accounts: observe_metas(config, global_config_key(), pam), data: vec![50] }
}

pub fn latch_ix(program_id: Pubkey, config: Pubkey, pam: Pubkey) -> Instruction {
    Instruction { program_id, accounts: observe_metas(config, global_config_key(), pam), data: vec![51, 0] }
}

// ------------------------------------------------------------ Config access

pub fn cfg_bytes(svm: &LiteSVM, config: &Pubkey) -> Vec<u8> {
    let d = data_of(svm, config);
    assert_eq!(d.len(), CONFIG_LEN, "config account");
    d
}

pub fn with_cfg<T>(svm: &LiteSVM, config: &Pubkey, f: impl FnOnce(&Config<'_>) -> T) -> T {
    let d = cfg_bytes(svm, config);
    f(&Config::new(&d).expect("config view"))
}

/// Direct state edit of `Config` (test-only injection, documented at each use).
pub fn edit_cfg(svm: &mut LiteSVM, config: &Pubkey, f: impl FnOnce(&mut ConfigMut<'_>)) {
    patch(svm, config, |d| f(&mut ConfigMut::new(d).expect("config view")));
}

/// The venue part of `Config@1400..1472` (for "state unchanged" checks).
pub fn venue_state(svm: &LiteSVM, config: &Pubkey) -> Vec<u8> {
    cfg_bytes(svm, config)[1400..1472].to_vec()
}

// ------------------------------------------------ GlobalConfig / PAM bytes

pub mod gcx {
    pub const DISC: usize = 0;
    pub const KEY: usize = 8;
    pub const AUTHORITIES: usize = 40;
    pub const PHUSD: usize = 296;
    pub const GLOBAL_VAULT: usize = 328;
    pub const PAM: usize = 360;
    pub const GTI: usize = 392;
    pub const ATB: usize = 424;
    pub const WQ: usize = 472;
    pub const STATUS: usize = 504;
    pub const QUOTE_DECIMALS: usize = 505;
    pub const COOLDOWN: usize = 512;
    pub const ACK: usize = 1096;
    pub const PREFIX: usize = 1104;
}

pub mod pamx {
    pub const NUM_ASSETS: usize = 24;
    pub const SLOTS_USED: usize = 32;
    pub const TOMBSTONES: usize = 36;
    pub const CAPACITY: usize = 40;
    pub const HEADER: usize = 48;
    pub const ENTRY: usize = 1584;
    pub const E_SYMBOL: usize = 0;
    pub const E_MARK_SLOT: usize = 32;
    pub const E_MARK: usize = 40;
    pub const E_MARKET: usize = 920;
    pub const E_TICK: usize = 952;
    pub const E_AID_LO: usize = 960;
    pub const E_AID_HI: usize = 964;
    pub const E_ISOLATED: usize = 1224;
    pub const E_FINAL: usize = 1456;
    pub const E_INDEX_NUM: usize = 1464;
    pub const E_TOMB: usize = 1466;

    pub fn e(i: usize) -> usize {
        HEADER + ENTRY * i
    }
}

pub fn sym16(s: &str) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[..s.len()].copy_from_slice(s.as_bytes());
    b
}

/// One live-or-not PAM entry, decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PamEntry {
    pub slot: usize,
    pub symbol: String,
    pub asset_id: u32,
    pub market: Pubkey,
    pub finalized: u64,
    pub tombstoned: u8,
    pub index_num: u16,
    pub mark_slot: u64,
    pub mark: u64,
}

pub fn pam_header(p: &[u8]) -> (u16, u32, u32, u64) {
    (rd_u16(p, pamx::NUM_ASSETS), rd_u32(p, pamx::SLOTS_USED), rd_u32(p, pamx::TOMBSTONES), rd_u64(p, pamx::CAPACITY))
}

pub fn pam_entry(p: &[u8], i: usize) -> PamEntry {
    let e = pamx::e(i);
    let raw = &p[e..e + 16];
    let end = raw.iter().position(|&b| b == 0).unwrap_or(16);
    PamEntry {
        slot: i,
        symbol: String::from_utf8_lossy(&raw[..end]).into_owned(),
        asset_id: u32::from(rd_u16(p, e + pamx::E_AID_LO)) | (u32::from(rd_u16(p, e + pamx::E_AID_HI)) << 16),
        market: rd_key(p, e + pamx::E_MARKET),
        finalized: rd_u64(p, e + pamx::E_FINAL),
        tombstoned: p[e + pamx::E_TOMB],
        index_num: rd_u16(p, e + pamx::E_INDEX_NUM),
        mark_slot: rd_u64(p, e + pamx::E_MARK_SLOT),
        mark: rd_u64(p, e + pamx::E_MARK),
    }
}

/// Entries `0..slots_used`.
pub fn pam_entries(p: &[u8]) -> Vec<PamEntry> {
    let su = rd_u32(p, pamx::SLOTS_USED) as usize;
    (0..su).map(|i| pam_entry(p, i)).collect()
}

/// Slot of the live entry with `symbol`.
pub fn pam_find(p: &[u8], symbol: &str) -> Option<usize> {
    pam_entries(p).into_iter().find(|e| e.tombstoned == 0 && e.symbol == symbol).map(|e| e.slot)
}

// ------------------------------------------------------- mainnet snapshots

/// Mainnet account snapshots (raw account data), see
/// `tests/fixtures/fetch-recovery-mainnet.sh`.
pub struct MainnetSnap {
    pub gc: Vec<u8>,
    pub pam_key: Pubkey,
    pub pam: Vec<u8>,
    pub program: Vec<u8>,
    pub program_data: Vec<u8>,
    pub fetched_slot: String,
}

pub fn mainnet_dir() -> PathBuf {
    std::env::var("SIJKA_RECOVERY_MAINNET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/recovery-mainnet"))
}

impl MainnetSnap {
    pub fn load() -> Option<Self> {
        let dir = mainnet_dir();
        let read = |f: &str| std::fs::read(dir.join(f)).ok().filter(|d| !d.is_empty());
        let gc = read("global_config.bin")?;
        let pam = read("perp_asset_map.bin")?;
        let program = read("phoenix_program.bin")?;
        let program_data = read("phoenix_program_data.bin")?;
        let pam_key = rd_key(&gc, gcx::PAM);
        let fetched_slot = std::fs::read_to_string(dir.join("slot.txt")).unwrap_or_default().trim().to_string();
        Some(Self { gc, pam_key, pam, program, program_data, fetched_slot })
    }
}

// ------------------------------------------------ bare venue environment

/// First clock value of every environment (below the fixture's oracle
/// timestamps, 1.9e9).
pub const T0: i64 = 1_700_000_000;

/// Our program in a bare LiteSVM with a synthetic `Config` (only the fields
/// the verdict and the latch read) and the Phoenix accounts of tag 50 at
/// their pinned keys: the verdict path of tags 50 / 51 op 0 on real mainnet
/// bytes, without the Phoenix binary.
pub struct VenueEnv {
    pub svm: LiteSVM,
    pub program_id: Pubkey,
    pub config: Pubkey,
    pub payer: Keypair,
    pub pam: Pubkey,
    pub admin: Pubkey,
    pub slot: u64,
    pub ts: i64,
    pub snap_slot: String,
}

impl VenueEnv {
    /// Mainnet copies of GC, PAM, the Phoenix program account and its
    /// ProgramData; `LastRestartSlot` = the live acknowledged slot.
    pub fn mainnet() -> Option<Self> {
        let snap = need(MainnetSnap::load(), "mainnet account snapshots (SIJKA_RECOVERY_MAINNET_DIR)")?;
        let so = need(program_so(), "sijka_vault.so")?;
        let mut svm = LiteSVM::new();
        svm.warp_to_slot(0);
        let program_id = Keypair::new().pubkey();
        svm.add_program(program_id, &std::fs::read(so).unwrap()).unwrap();
        let payer = Keypair::new();
        svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();
        let pdas = Pdas::derive(&program_id);
        let admin = Keypair::new().pubkey();
        // Non-executable copies: the verdict reads owner and data only, and
        // tag 50 never invokes Phoenix.
        put(&mut svm, phoenix_id(), loader_v3(), 1_141_440, snap.program.clone(), false);
        put_rent_exempt(&mut svm, phoenix_program_data(), loader_v3(), snap.program_data.clone());
        put_rent_exempt(&mut svm, global_config_key(), phoenix_id(), snap.gc.clone());
        put_rent_exempt(&mut svm, snap.pam_key, phoenix_id(), snap.pam.clone());
        let ack = rd_u64(&snap.gc, gcx::ACK);
        set_last_restart_slot(&mut svm, ack);
        let phusd = rd_key(&snap.gc, gcx::PHUSD);
        let cfg = synthetic_config(&pdas, &admin, &phusd);
        put_rent_exempt(&mut svm, pdas.config, program_id, cfg);
        let mut env = Self {
            svm,
            program_id,
            config: pdas.config,
            payer,
            pam: snap.pam_key,
            admin,
            slot: 1_000,
            ts: T0,
            snap_slot: snap.fetched_slot,
        };
        env.sync_clock();
        Some(env)
    }

    pub fn sync_clock(&mut self) {
        set_clock(&mut self.svm, self.slot, self.ts);
    }

    /// Advance the clock by `secs` (≈ 2.5 slots per second, at least 1 slot).
    pub fn tick(&mut self, secs: i64) {
        self.ts += secs;
        self.slot += u64::try_from((secs * 5 / 2).max(1)).unwrap();
        self.sync_clock();
    }

    pub fn send(&mut self, ixs: Vec<Instruction>) -> TxResult {
        let payer = self.payer.insecure_clone();
        send(&mut self.svm, &payer, &[], ixs)
    }

    pub fn observe(&mut self) -> TxResult {
        let ix = observe_ix(self.program_id, self.config, self.pam);
        self.send(vec![ix])
    }

    #[track_caller]
    pub fn observe_ok(&mut self) -> Vob {
        let r = self.observe();
        Vob::from_meta(assert_ok(&r))
    }

    /// Tick then observe.
    #[track_caller]
    pub fn observe_after(&mut self, secs: i64) -> Vob {
        self.tick(secs);
        self.observe_ok()
    }

    pub fn latch(&mut self) -> TxResult {
        let ix = latch_ix(self.program_id, self.config, self.pam);
        self.send(vec![ix])
    }

    pub fn cfg<T>(&self, f: impl FnOnce(&Config<'_>) -> T) -> T {
        with_cfg(&self.svm, &self.config, f)
    }

    pub fn venue_state(&self) -> Vec<u8> {
        venue_state(&self.svm, &self.config)
    }

    pub fn gc(&self) -> Vec<u8> {
        data_of(&self.svm, &global_config_key())
    }

    pub fn pam_data(&self) -> Vec<u8> {
        data_of(&self.svm, &self.pam)
    }

    pub fn patch_gc(&mut self, f: impl FnOnce(&mut Vec<u8>)) {
        patch(&mut self.svm, &global_config_key(), f);
    }

    pub fn patch_pam(&mut self, f: impl FnOnce(&mut Vec<u8>)) {
        let key = self.pam;
        patch(&mut self.svm, &key, f);
    }

    /// DOWN observations every `step` seconds until `total` seconds after
    /// the first one (the first observation included). Returns the last.
    #[track_caller]
    pub fn down_series(&mut self, step: i64, total: i64) -> Vob {
        let mut v = self.observe_after(step);
        assert_eq!(v.verdict, DOWN, "series needs a DOWN verdict: {v:?}");
        let start = self.ts;
        while self.ts - start < total {
            v = self.observe_after(step);
            assert_eq!(v.verdict, DOWN, "{v:?}");
        }
        v
    }
}

/// `Config` of the bare environment: header, admin / recipient, PhUSD anchor
/// (G5) and the destination keys the latch event reports.
pub fn synthetic_config(p: &Pdas, admin: &Pubkey, phusd: &Pubkey) -> Vec<u8> {
    let mut b = vec![0u8; CONFIG_LEN];
    {
        let mut m = ConfigMut::new(&mut b).unwrap();
        m.set_discriminator(&k::DISC_CONFIG);
        m.set_version(1);
        m.set_admin(&admin.to_bytes());
        m.set_emergency_recipient(&admin.to_bytes());
        m.set_phusd_mint(&phusd.to_bytes());
        m.set_phx_authority(&p.phx_authority.to_bytes());
        m.set_fee_inbox(&p.fee_inbox.to_bytes());
        m.set_buyback_authority(&p.buyback_authority.to_bytes());
        m.set_buyback_state(&p.buyback_state.to_bytes());
        m.set_emergency_recipient_usdc(&Pubkey::new_from_array([0x51; 32]).to_bytes());
        m.set_buyback_usdc(&Pubkey::new_from_array([0x52; 32]).to_bytes());
    }
    b
}
