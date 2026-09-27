// Copyright (c) 2026 prt1sn. All rights reserved.
//! LiteSVM environment for the phoenix-core tests: the Rise localnet fixture
//! with the mainnet Phoenix / Ember / Hawkeye binaries, our `.so` loaded as an
//! upgradeable program whose ProgramData names a test upgrade authority
//! (SPEC §9.1), deterministic role keys, clock control and small SPL / System
//! helpers. Everything the tests assert on is read back from LiteSVM.

use std::path::PathBuf;

use litesvm::types::{FailedTransactionMetadata, TransactionMetadata};
use phoenix_rise_litesvm_test::{
    SdkLocalnetContext, SdkLocalnetProgram, default_sdk_localnet_fixture, find_sdk_localnet_program_paths,
    mainnet_bpf_programs_enabled, parse_pubkey, parse_pubkeys, sdk_localnet_vm_required,
};
use sha2::{Digest, Sha256};
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;

use crate::abi;

pub type TxResult = Result<TransactionMetadata, FailedTransactionMetadata>;

pub const SYSTEM_PROGRAM: Pubkey = solana_pubkey::pubkey!("11111111111111111111111111111111");
pub const SPL_TOKEN: Pubkey = solana_pubkey::pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
pub const TOKEN_2022: Pubkey = solana_pubkey::pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
pub const ATA_PROGRAM: Pubkey = solana_pubkey::pubkey!("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
pub const COMPUTE_BUDGET: Pubkey = solana_pubkey::pubkey!("ComputeBudget111111111111111111111111111111");
pub const BPF_LOADER_UPGRADEABLE: Pubkey = solana_pubkey::pubkey!("BPFLoaderUpgradeab1e11111111111111111111111");
pub const CLOCK_SYSVAR: Pubkey = solana_pubkey::pubkey!("SysvarC1ock11111111111111111111111111111111");
pub const WSOL_MINT: Pubkey = solana_pubkey::pubkey!("So11111111111111111111111111111111111111112");
pub const PHOENIX: Pubkey = solana_pubkey::pubkey!("EtrnLzgbS7nMMy5fbD42kXiUzGg8XQzJ972Xtk1cjWih");
pub const PHOENIX_LOG: Pubkey = solana_pubkey::pubkey!("GdxfTLSsdSY37G6fZoYtdGDSfgFnbT2EmRpuePZxWShS");
pub const PHOENIX_GC: Pubkey = solana_pubkey::pubkey!("2zskx2iyCvb6Stg7RBZkt1f6MrF4dpYtMG3yMvKwqtUZ");
pub const HAWKEYE: Pubkey = solana_pubkey::pubkey!("RiSeVw3ZjNfsaXPRb4mgaqYaEEt41pNNJoDvVh7pgQj");
pub const EMBER: Pubkey = solana_pubkey::pubkey!("EMBERpYNE6ehWmXymZZS2skiFmCa9V5dp14e1iduM5qy");
pub const EMBER_STATE: Pubkey = solana_pubkey::pubkey!("6ur7v6AXNpnHeEb6xuk7PyezvZ1i5GrgYyWZkNCpzbRz");
pub const EMBER_VAULT: Pubkey = solana_pubkey::pubkey!("FKcEb4TdPDTRuMnQDpSEPQBcrm15S73xiUD6Qf8ZLUkq");
pub const PUMP_FEES: Pubkey = solana_pubkey::pubkey!("pfeeUxB6jkeY1Hxd7CsFCAjcbHA9rWtchMGdZ6VojVZ");

/// Rise localnet fixture base slot for our tests: past the tag 21 quiet window
/// for any fixture cooldown below ~10k slots (SPEC §5.3.5 step 3).
pub const BASE_SLOT: u64 = 20_000;
pub const CU_LIMIT: u32 = 1_400_000;

// Signer seeds (deterministic keys known to the fixture context).
pub const S_UPGRADE: &str = "pc-upgrade-authority";
pub const S_ADMIN: &str = "pc-admin";
pub const S_BOT: &str = "pc-bot";
pub const S_CREATOR: &str = "pc-creator";
pub const S_ONBOARDER: &str = "pc-onboarder";
pub const S_ATTACKER: &str = "pc-attacker";
pub const S_PAYER: &str = "payer";

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Anchor-style discriminator `sha256(name)[..8]`.
pub fn disc(name: &str) -> [u8; 8] {
    sha256(name.as_bytes())[..8].try_into().unwrap()
}

pub fn find_pda(seeds: &[&[u8]], program: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(seeds, program)
}

pub fn ata(owner: &Pubkey, mint: &Pubkey, token_program: &Pubkey) -> Pubkey {
    find_pda(&[owner.as_ref(), token_program.as_ref(), mint.as_ref()], &ATA_PROGRAM).0
}

pub fn env_on(k: &str) -> bool {
    matches!(std::env::var(k).as_deref(), Ok("1") | Ok("true"))
}

fn artifact_required() -> bool {
    env_on("SIJKA_REQUIRE_SO") || sdk_localnet_vm_required()
}

fn program_so() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("SIJKA_VAULT_SO") {
        return Some(PathBuf::from(p)).filter(|p| p.exists());
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    [manifest.join("../../target/deploy/sijka_vault.so"), manifest.join("target/deploy/sijka_vault.so")]
        .into_iter()
        .find(|p| p.exists())
}

/// The test-only mock program of `tests/mock-jupiter` (built by the CI sbf
/// job into `target/deploy-mocks`); its `SJKCALL | data` entry CPIs
/// `accounts[0]` with the other accounts, flags preserved. `None` when it
/// is missing and artifacts are not required.
pub fn mock_program_so() -> Option<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let found = std::env::var("SIJKA_MOCK_JUPITER_SO")
        .ok()
        .map(PathBuf::from)
        .into_iter()
        .chain([
            manifest.join("../../target/deploy-mocks/sijka_mock_jupiter.so"),
            manifest.join("tests/mock-jupiter/target/deploy/sijka_mock_jupiter.so"),
        ])
        .find(|p| p.exists());
    if found.is_none() {
        assert!(!artifact_required(), "sijka_mock_jupiter.so not found (set SIJKA_MOCK_JUPITER_SO)");
        eprintln!("skipping: sijka_mock_jupiter.so not built");
    }
    found
}

/// All PDAs of the program (SPEC §2.1), derived off chain.
#[derive(Clone, Copy, Debug)]
pub struct Pdas {
    pub config: (Pubkey, u8),
    pub buyback_state: (Pubkey, u8),
    pub fee_inbox: (Pubkey, u8),
    pub phx_authority: (Pubkey, u8),
    pub swap_authority: (Pubkey, u8),
    pub buyback_authority: (Pubkey, u8),
    pub rent_payer: (Pubkey, u8),
    pub creator_escrow: (Pubkey, u8),
    pub bb_unwrap: (Pubkey, u8),
    pub program_data: Pubkey,
    pub trader: (Pubkey, u8),
}

impl Pdas {
    pub fn derive(program: &Pubkey) -> Self {
        let f = |s: &[u8]| find_pda(&[s], program);
        let phx = f(b"phx_authority");
        let trader = find_pda(&[b"trader", phx.0.as_ref(), &[0u8, 0u8]], &PHOENIX);
        Self {
            config: f(b"config"),
            buyback_state: f(b"buyback_state"),
            fee_inbox: f(b"fee_inbox"),
            phx_authority: phx,
            swap_authority: f(b"swap"),
            buyback_authority: f(b"buyback"),
            rent_payer: f(b"rent_payer"),
            creator_escrow: f(b"creator_escrow"),
            bb_unwrap: f(b"bb_unwrap"),
            program_data: find_pda(&[program.as_ref()], &BPF_LOADER_UPGRADEABLE).0,
            trader,
        }
    }

    /// The nine program PDAs (roles may not be any of them, SPEC §5.1.0 step 5).
    pub fn program_pdas(&self) -> [Pubkey; 9] {
        [
            self.config.0,
            self.buyback_state.0,
            self.bb_unwrap.0,
            self.fee_inbox.0,
            self.phx_authority.0,
            self.swap_authority.0,
            self.buyback_authority.0,
            self.rent_payer.0,
            self.creator_escrow.0,
        ]
    }
}

/// Fixture addresses used everywhere.
#[derive(Clone, Debug)]
pub struct Fx {
    pub usdc: Pubkey,
    pub phusd: Pubkey,
    pub pam: Pubkey,
    pub withdraw_queue: Pubkey,
    pub global_vault: Pubkey,
    pub gti: Vec<Pubkey>,
    pub atb: Vec<Pubkey>,
}

pub struct Env {
    pub ctx: SdkLocalnetContext,
    pub program: Pubkey,
    pub pdas: Pdas,
    pub fx: Fx,
    pub upgrade_authority: Pubkey,
    pub admin: Pubkey,
    pub bot: Pubkey,
    pub creator: Pubkey,
    pub onboarder: Pubkey,
    pub attacker: Pubkey,
    /// Current fixture prices (milli-USD per base unit), re-published by
    /// `refresh_prices` after slot warps.
    pub prices: Vec<(&'static str, u64)>,
}

impl Env {
    /// Fixture + protocol programs + our program (upgradeable, authority
    /// `S_UPGRADE`). `None` when the artifacts are missing and not required
    /// (host job without `cargo build-sbf`).
    pub fn new() -> Option<Self> {
        let Some(paths) = find_sdk_localnet_program_paths() else {
            if sdk_localnet_vm_required() {
                panic!("missing Phoenix/Ember/Hawkeye SBF artifacts (RISE_SDK_LOCALNET_*_SO)");
            }
            eprintln!("skipping: Phoenix protocol artifacts missing");
            return None;
        };
        if paths.hawkeye.is_none() && !mainnet_bpf_programs_enabled() {
            if sdk_localnet_vm_required() {
                panic!("missing Hawkeye SBF artifact");
            }
            eprintln!("skipping: Hawkeye artifact missing");
            return None;
        }
        let so = match program_so() {
            Some(p) => p,
            None if artifact_required() => {
                panic!("sijka_vault.so not found; run cargo build-sbf or set SIJKA_VAULT_SO")
            }
            None => {
                eprintln!("skipping: sijka_vault.so not built");
                return None;
            }
        };
        let fixture = default_sdk_localnet_fixture().expect("fixture parses");
        let program = Keypair::new_from_array(sha256(b"sijka-phoenix-core-test-program")).pubkey();
        let mut ctx = SdkLocalnetContext::new_with_programs(fixture, paths, [SdkLocalnetProgram::new(program, so)]);
        ctx.execute_setup();

        let upgrade_authority = ctx.add_signer(S_UPGRADE, 100_000_000_000);
        let admin = ctx.add_signer(S_ADMIN, 100_000_000_000);
        let bot = ctx.add_signer(S_BOT, 100_000_000_000);
        let creator = ctx.add_signer(S_CREATOR, 1_000_000_000);
        let onboarder = ctx.add_signer(S_ONBOARDER, 10_000_000_000);
        let attacker = ctx.add_signer(S_ATTACKER, 100_000_000_000);
        let a = &ctx.fixture.addresses;
        let fx = Fx {
            usdc: ctx.fake_usdc_mint(),
            phusd: ctx.phoenix_collateral_mint(),
            pam: parse_pubkey(&a.perp_asset_map).unwrap(),
            withdraw_queue: parse_pubkey(&a.withdraw_queue).unwrap(),
            global_vault: parse_pubkey(&a.global_vault).unwrap(),
            gti: parse_pubkeys(&a.global_trader_index),
            atb: parse_pubkeys(&a.active_trader_buffer),
        };
        let mut env = Self {
            ctx,
            program,
            pdas: Pdas::derive(&program),
            fx,
            upgrade_authority,
            admin,
            bot,
            creator,
            onboarder,
            attacker,
            prices: vec![("BTC", 100_000_000), ("ETH", 3_500_000), ("SOL", 150_000)],
        };
        env.set_upgrade_authority(Some(upgrade_authority));
        let ts = env.clock().1;
        env.set_clock(BASE_SLOT, ts);
        env.refresh_prices();
        Some(env)
    }

    // ------------------------------------------------------------ program ----

    /// Rewrite our ProgramData header: `Some(authority)` or `None` (SPEC §9.1:
    /// the program is loaded as upgradeable so `NotUpgradeAuthority` is testable).
    pub fn set_upgrade_authority(&mut self, authority: Option<Pubkey>) {
        let pd = self.pdas.program_data;
        let mut acc = self.ctx.svm.get_account(&pd).expect("ProgramData");
        assert_eq!(u32::from_le_bytes(acc.data[0..4].try_into().unwrap()), 3, "ProgramData state tag");
        match authority {
            Some(k) => {
                acc.data[12] = 1;
                acc.data[13..45].copy_from_slice(k.as_ref());
            }
            None => {
                acc.data[12] = 0;
                acc.data[13..45].fill(0);
            }
        }
        self.ctx.svm.set_account(pd, acc).unwrap();
    }

    // -------------------------------------------------------------- sends ----

    pub fn send(&mut self, ixs: Vec<Instruction>, payer_seed: &str) -> TxResult {
        let mut all = vec![compute_limit_ix(CU_LIMIT)];
        all.extend(ixs);
        self.ctx.try_send_instructions_with_metadata(all, payer_seed)
    }

    pub fn send1(&mut self, ix: Instruction, payer_seed: &str) -> TxResult {
        self.send(vec![ix], payer_seed)
    }

    // ---------------------------------------------------------- accounts ----

    pub fn data(&self, key: &Pubkey) -> Vec<u8> {
        self.ctx.svm.get_account(key).map(|a| a.data).unwrap_or_default()
    }

    pub fn exists(&self, key: &Pubkey) -> bool {
        self.ctx.svm.get_account(key).is_some_and(|a| a.lamports > 0)
    }

    pub fn lamports(&self, key: &Pubkey) -> u64 {
        self.ctx.svm.get_account(key).map_or(0, |a| a.lamports)
    }

    pub fn owner(&self, key: &Pubkey) -> Option<Pubkey> {
        self.ctx.svm.get_account(key).map(|a| a.owner)
    }

    /// Patch bytes of an existing account in place.
    pub fn patch(&mut self, key: &Pubkey, f: impl FnOnce(&mut Vec<u8>)) {
        let mut acc = self.ctx.svm.get_account(key).unwrap_or_else(|| panic!("patch: missing {key}"));
        f(&mut acc.data);
        self.ctx.svm.set_account(*key, acc).unwrap();
    }

    /// Install an account with the given owner and data (lamports: rent-exempt).
    pub fn install(&mut self, key: &Pubkey, owner: &Pubkey, data: Vec<u8>) {
        // Clone the shape of any existing account and overwrite every field.
        let mut acc = self.ctx.svm.get_account(&self.admin).expect("template account");
        acc.lamports = self.ctx.svm.minimum_balance_for_rent_exemption(data.len()).max(1);
        acc.data = data;
        acc.owner = *owner;
        acc.executable = false;
        self.ctx.svm.set_account(*key, acc).unwrap();
    }

    pub fn config(&self) -> Vec<u8> {
        self.data(&self.pdas.config.0)
    }

    pub fn cfg_u64(&self, field: &str) -> u64 {
        abi::config().u64(&self.config(), field)
    }

    pub fn cfg_i64(&self, field: &str) -> i64 {
        abi::config().i64(&self.config(), field)
    }

    pub fn cfg_u8(&self, field: &str) -> u8 {
        abi::config().u8(&self.config(), field)
    }

    pub fn cfg_key(&self, field: &str) -> Pubkey {
        Pubkey::new_from_array(abi::config().key(&self.config(), field))
    }

    /// Field of `Config.harvest_params` (nested `HarvestParams`).
    pub fn cfg_harvest_u64(&self, field: &str) -> u64 {
        let base = abi::config().field("harvest_params").offset;
        let f = abi::harvest_params().field(field);
        let d = self.config();
        let mut b = [0u8; 8];
        b[..f.size].copy_from_slice(&d[base + f.offset..base + f.offset + f.size]);
        u64::from_le_bytes(b)
    }

    // ------------------------------------------------------------- clock ----

    /// `(slot, unix_timestamp)` from the Clock sysvar.
    pub fn clock(&self) -> (u64, i64) {
        let d = self.data(&CLOCK_SYSVAR);
        (u64::from_le_bytes(d[0..8].try_into().unwrap()), i64::from_le_bytes(d[32..40].try_into().unwrap()))
    }

    pub fn set_clock(&mut self, slot: u64, ts: i64) {
        self.patch(&CLOCK_SYSVAR, |d| {
            d[0..8].copy_from_slice(&slot.to_le_bytes());
            d[32..40].copy_from_slice(&ts.to_le_bytes());
        });
    }

    /// Advance slot and time, then refresh the fixture oracle / spline prices
    /// so marks are fresh at the new slot.
    pub fn advance(&mut self, slots: u64, secs: i64) {
        let (s, t) = self.clock();
        self.set_clock(s + slots, t + secs);
        self.refresh_prices();
    }

    /// Re-publish the current oracle marks (keeps the current prices).
    pub fn refresh_prices(&mut self) {
        for (sym, usd_milli) in self.prices.clone() {
            self.set_price_milli(sym, usd_milli);
        }
    }

    // ------------------------------------------------------------ tokens ----

    pub fn token_amount(&self, key: &Pubkey) -> u64 {
        let d = self.data(key);
        if d.len() < 72 { 0 } else { u64::from_le_bytes(d[64..72].try_into().unwrap()) }
    }

    pub fn create_ata(&mut self, owner: &Pubkey, mint: &Pubkey, token_program: &Pubkey) -> Pubkey {
        let a = ata(owner, mint, token_program);
        let payer = self.ctx.signer_pubkey(S_PAYER);
        let ix = Instruction {
            program_id: ATA_PROGRAM,
            accounts: vec![
                AccountMeta::new(payer, true),
                AccountMeta::new(a, false),
                AccountMeta::new_readonly(*owner, false),
                AccountMeta::new_readonly(*mint, false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
                AccountMeta::new_readonly(*token_program, false),
            ],
            data: vec![1],
        };
        ok(self.send1(ix, S_PAYER), "create ATA");
        a
    }

    pub fn mint_usdc(&mut self, to: &Pubkey, amount: u64) {
        self.ctx.mint_fake_usdc_to_token_account(*to, amount);
    }

    pub fn transfer_lamports(&mut self, from_seed: &str, to: &Pubkey, lamports: u64) -> TxResult {
        let from = self.ctx.signer_pubkey(from_seed);
        let mut data = vec![2, 0, 0, 0];
        data.extend_from_slice(&lamports.to_le_bytes());
        let ix = Instruction {
            program_id: SYSTEM_PROGRAM,
            accounts: vec![AccountMeta::new(from, true), AccountMeta::new(*to, false)],
            data,
        };
        self.send1(ix, from_seed)
    }

    /// SPL Token `Transfer` (tag 3) signed by `authority_seed`.
    pub fn spl_transfer(&mut self, src: &Pubkey, dst: &Pubkey, authority_seed: &str, amount: u64) -> TxResult {
        let authority = self.ctx.signer_pubkey(authority_seed);
        let mut data = vec![3];
        data.extend_from_slice(&amount.to_le_bytes());
        let ix = Instruction {
            program_id: SPL_TOKEN,
            accounts: vec![
                AccountMeta::new(*src, false),
                AccountMeta::new(*dst, false),
                AccountMeta::new_readonly(authority, true),
            ],
            data,
        };
        self.send1(ix, authority_seed)
    }

    pub fn rent(&self, len: usize) -> u64 {
        self.ctx.svm.minimum_balance_for_rent_exemption(len)
    }
}

pub fn compute_limit_ix(units: u32) -> Instruction {
    let mut data = vec![2];
    data.extend_from_slice(&units.to_le_bytes());
    Instruction { program_id: COMPUTE_BUDGET, accounts: vec![], data }
}

// ---------------------------------------------------------------- results ----

pub fn logs_of(r: &TxResult) -> &[String] {
    match r {
        Ok(m) => &m.logs,
        Err(e) => &e.meta.logs,
    }
}

pub fn ok(r: TxResult, label: &str) -> TransactionMetadata {
    match r {
        Ok(m) => m,
        Err(e) => panic!("{label}: transaction failed: {:?}\n{}", e.err, e.meta.logs.join("\n")),
    }
}

/// The transaction failed with our error `name` (code and log line, SPEC §5.0.8).
pub fn expect_err(r: TxResult, name: &str, label: &str) -> FailedTransactionMetadata {
    let code = abi::err(name);
    match r {
        Ok(m) => panic!("{label}: expected {name}, got success\n{}", m.logs.join("\n")),
        Err(e) => {
            let s = format!("{:?}", e.err);
            assert!(
                s.contains(&format!("Custom({code})")),
                "{label}: expected {name} ({code:#x}), got {s}\n{}",
                e.meta.logs.join("\n")
            );
            let line = format!("Sijka: {name}");
            assert!(e.meta.logs.iter().any(|l| l.contains(&line)), "{label}: log line {line:?} missing");
            e
        }
    }
}

/// Failed in another program (Phoenix, Ember, …), not with a Sijka error.
pub fn expect_foreign_err(r: TxResult, label: &str) -> FailedTransactionMetadata {
    match r {
        Ok(m) => panic!("{label}: expected failure, got success\n{}", m.logs.join("\n")),
        Err(e) => {
            assert!(!e.meta.logs.iter().any(|l| l.contains("Sijka: ")), "{label}: unexpected Sijka error line");
            e
        }
    }
}

pub fn log_contains(logs: &[String], needle: &str) -> bool {
    logs.iter().any(|l| l.contains(needle))
}

// ------------------------------------------------------------------ events ----

pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => u32::from(c - b'A'),
            b'a'..=b'z' => u32::from(c - b'a') + 26,
            b'0'..=b'9' => u32::from(c - b'0') + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        })
    }
    let bytes: Vec<u8> = s.bytes().filter(|c| *c != b'=').collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut acc = 0u32;
        for (i, c) in chunk.iter().enumerate() {
            acc |= val(*c)? << (18 - 6 * i);
        }
        let n = chunk.len();
        if n >= 2 {
            out.push((acc >> 16) as u8);
        }
        if n >= 3 {
            out.push((acc >> 8) as u8);
        }
        if n == 4 {
            out.push(acc as u8);
        }
    }
    Some(out)
}

/// All `sol_log_data` payloads of the transaction that start with `tag`.
pub fn events(logs: &[String], tag: &str) -> Vec<Vec<u8>> {
    logs.iter()
        .filter_map(|l| l.strip_prefix("Program data: "))
        .filter_map(|b| b64_decode(b.split_whitespace().next()?))
        .filter(|p| p.starts_with(tag.as_bytes()))
        .collect()
}

/// Exactly one event `tag`, with the SPEC §7 length.
pub fn one_event(logs: &[String], tag: &str) -> Vec<u8> {
    let evs = events(logs, tag);
    assert_eq!(evs.len(), 1, "expected one {tag} event, got {}\n{}", evs.len(), logs.join("\n"));
    let e = evs.into_iter().next().unwrap();
    assert_eq!(e.len(), abi::event(tag).size, "{tag} length");
    e
}

pub fn key_of(bytes: [u8; 32]) -> Pubkey {
    Pubkey::new_from_array(bytes)
}
