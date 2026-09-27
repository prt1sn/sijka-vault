// Copyright (c) 2026 prt1sn. All rights reserved.
//! LiteSVM harness of the inflow tests: the real sijka-vault `.so`, the real
//! Phoenix / Ember / Hawkeye mainnet binaries through `phoenix-rise-litesvm-test`,
//! the test-only Jupiter mock at `JUP6…`, and helpers that read state through
//! the ABI manifest (`abi/sijka-vault.json`, generated from SPEC), not through
//! the program's own layout code.

use std::path::PathBuf;
use std::str::FromStr;
use std::sync::OnceLock;

use litesvm::types::{FailedTransactionMetadata, TransactionMetadata};
use phoenix_rise_litesvm_test::{
    FixturePrice, SdkLocalnetContext, SdkLocalnetProgram, decode_fixture_instruction, default_sdk_localnet_fixture,
    find_sdk_localnet_program_paths, parse_pubkey, parse_pubkeys, sdk_localnet_vm_required,
};
use serde_json::Value;
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

// ---------------------------------------------------------------- keys ----

pub fn pk(s: &str) -> Pubkey {
    Pubkey::from_str(s).unwrap_or_else(|e| panic!("bad pubkey {s}: {e:?}"))
}

pub fn jup6() -> Pubkey {
    pk("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4")
}
pub fn token_program() -> Pubkey {
    pk("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
}
pub fn token_2022() -> Pubkey {
    pk("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")
}
pub fn ata_program() -> Pubkey {
    pk("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
}
pub fn system_program() -> Pubkey {
    Pubkey::default()
}
pub fn wsol_mint() -> Pubkey {
    pk("So11111111111111111111111111111111111111112")
}
pub fn phoenix_program() -> Pubkey {
    pk("EtrnLzgbS7nMMy5fbD42kXiUzGg8XQzJ972Xtk1cjWih")
}
pub fn phoenix_log_authority() -> Pubkey {
    pk("GdxfTLSsdSY37G6fZoYtdGDSfgFnbT2EmRpuePZxWShS")
}
pub fn phoenix_global_config() -> Pubkey {
    pk("2zskx2iyCvb6Stg7RBZkt1f6MrF4dpYtMG3yMvKwqtUZ")
}
pub fn ember_program() -> Pubkey {
    pk("EMBERpYNE6ehWmXymZZS2skiFmCa9V5dp14e1iduM5qy")
}
pub fn ember_state() -> Pubkey {
    pk("6ur7v6AXNpnHeEb6xuk7PyezvZ1i5GrgYyWZkNCpzbRz")
}
pub fn ember_vault() -> Pubkey {
    pk("FKcEb4TdPDTRuMnQDpSEPQBcrm15S73xiUD6Qf8ZLUkq")
}
pub fn bpf_loader_upgradeable() -> Pubkey {
    pk("BPFLoaderUpgradeab1e11111111111111111111111")
}
pub fn compute_budget_program() -> Pubkey {
    pk("ComputeBudget111111111111111111111111111111")
}
pub fn sysvar_owner() -> Pubkey {
    pk("Sysvar1111111111111111111111111111111111111")
}
pub fn clock_sysvar() -> Pubkey {
    pk("SysvarC1ock11111111111111111111111111111111")
}

/// The vault's program id in these tests (any key works: every address is
/// derived from it).
pub fn vault_program_id() -> Pubkey {
    Pubkey::new_from_array([0x51; 32])
}
/// A second instance of the Jupiter mock, deployed at another address (TC-12).
pub fn mock_elsewhere() -> Pubkey {
    Pubkey::new_from_array([0x4d; 32])
}

pub fn ata(owner: &Pubkey, mint: &Pubkey) -> Pubkey {
    ata_with(owner, mint, &token_program())
}
pub fn ata_with(owner: &Pubkey, mint: &Pubkey, program: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[owner.as_ref(), program.as_ref(), mint.as_ref()], &ata_program()).0
}

/// All vault addresses (SPEC §2.1, §2.2), derived independently of the program.
#[derive(Clone, Debug)]
pub struct Keys {
    pub program: Pubkey,
    pub config: Pubkey,
    pub buyback_state: Pubkey,
    pub fee_inbox: Pubkey,
    pub phx_authority: Pubkey,
    pub swap_authority: Pubkey,
    pub buyback_authority: Pubkey,
    pub rent_payer: Pubkey,
    pub creator_escrow: Pubkey,
    pub bb_unwrap: Pubkey,
    pub program_data: Pubkey,
    pub usdc_mint: Pubkey,
    pub phusd_mint: Pubkey,
    pub vault_usdc: Pubkey,
    pub vault_phusd: Pubkey,
    pub swap_wsol: Pubkey,
    pub swap_usdc: Pubkey,
    pub buyback_usdc: Pubkey,
    pub creator_escrow_usdc: Pubkey,
    pub phoenix_trader: Pubkey,
    pub phoenix_trader_bump: u8,
}

impl Keys {
    pub fn derive(program: Pubkey, usdc_mint: Pubkey, phusd_mint: Pubkey) -> Self {
        let p = |s: &[u8]| Pubkey::find_program_address(&[s], &program).0;
        let phx_authority = p(b"phx_authority");
        let swap_authority = p(b"swap");
        let buyback_authority = p(b"buyback");
        let creator_escrow = p(b"creator_escrow");
        let (phoenix_trader, phoenix_trader_bump) =
            Pubkey::find_program_address(&[b"trader", phx_authority.as_ref(), &[0u8, 0u8]], &phoenix_program());
        Keys {
            program,
            config: p(b"config"),
            buyback_state: p(b"buyback_state"),
            fee_inbox: p(b"fee_inbox"),
            phx_authority,
            swap_authority,
            buyback_authority,
            rent_payer: p(b"rent_payer"),
            creator_escrow,
            bb_unwrap: p(b"bb_unwrap"),
            program_data: Pubkey::find_program_address(&[program.as_ref()], &bpf_loader_upgradeable()).0,
            usdc_mint,
            phusd_mint,
            vault_usdc: ata(&phx_authority, &usdc_mint),
            vault_phusd: ata(&phx_authority, &phusd_mint),
            swap_wsol: ata(&swap_authority, &wsol_mint()),
            swap_usdc: ata(&swap_authority, &usdc_mint),
            buyback_usdc: ata(&buyback_authority, &usdc_mint),
            creator_escrow_usdc: ata(&creator_escrow, &usdc_mint),
            phoenix_trader,
            phoenix_trader_bump,
        }
    }
}

// ----------------------------------------------------------------- ABI ----

pub struct Abi {
    v: Value,
}

pub fn abi() -> &'static Abi {
    static ABI: OnceLock<Abi> = OnceLock::new();
    ABI.get_or_init(|| Abi {
        v: serde_json::from_str(include_str!("../../../../abi/sijka-vault.json")).expect("abi json parses"),
    })
}

impl Abi {
    /// Custom error code of `name` (`errorBase + offset`).
    pub fn err(&self, name: &str) -> u32 {
        let e = self.v["errors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["name"] == name)
            .unwrap_or_else(|| panic!("no error {name} in abi"));
        u32::try_from(e["code"].as_u64().unwrap()).unwrap()
    }

    fn fields(&self, account: &str) -> &Vec<Value> {
        self.v["accounts"][account]["fields"].as_array().unwrap_or_else(|| panic!("no account {account}"))
    }

    /// `(offset, size)` of a field of an account / struct layout.
    pub fn field(&self, account: &str, name: &str) -> (usize, usize) {
        let f = self
            .fields(account)
            .iter()
            .find(|f| f["name"] == name)
            .unwrap_or_else(|| panic!("no field {account}.{name}"));
        (f["offset"].as_u64().unwrap() as usize, f["size"].as_u64().unwrap() as usize)
    }

    pub fn size(&self, account: &str) -> usize {
        self.v["accounts"][account]["size"]
            .as_u64()
            .map(|s| s as usize)
            .unwrap_or_else(|| self.fields(account).iter().map(|f| f["size"].as_u64().unwrap() as usize).sum())
    }

    /// `(offset, size)` of a field of event `tag`.
    pub fn ev_field(&self, tag: &str, name: &str) -> (usize, usize) {
        let ev = self.v["events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["tag"] == tag)
            .unwrap_or_else(|| panic!("no event {tag}"));
        let f = ev["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["name"] == name)
            .unwrap_or_else(|| panic!("no field {tag}.{name}"));
        (f["offset"].as_u64().unwrap() as usize, f["size"].as_u64().unwrap() as usize)
    }

    pub fn ev_size(&self, tag: &str) -> usize {
        let ev = self.v["events"].as_array().unwrap().iter().find(|e| e["tag"] == tag).unwrap();
        ev["size"].as_u64().unwrap() as usize
    }

    /// Pack a struct layout (`InflowParams`, …) from `(field, value)` pairs;
    /// unnamed fields stay zero. Integers are little-endian of the field size.
    pub fn pack(&self, account: &str, values: &[(&str, u64)]) -> Vec<u8> {
        let mut out = vec![0u8; self.size(account)];
        for (name, v) in values {
            let (off, size) = self.field(account, name);
            out[off..off + size].copy_from_slice(&v.to_le_bytes()[..size]);
        }
        out
    }
}

pub fn le(d: &[u8], off: usize, size: usize) -> u64 {
    let mut b = [0u8; 8];
    b[..size].copy_from_slice(&d[off..off + size]);
    u64::from_le_bytes(b)
}

pub fn u64_at(d: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(d[off..off + 8].try_into().unwrap())
}
pub fn i64_at(d: &[u8], off: usize) -> i64 {
    i64::from_le_bytes(d[off..off + 8].try_into().unwrap())
}
pub fn key_at(d: &[u8], off: usize) -> Pubkey {
    Pubkey::new_from_array(d[off..off + 32].try_into().unwrap())
}

// -------------------------------------------------------------- events ----

fn b64_decode(s: &str) -> Vec<u8> {
    fn val(c: u8) -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a' + 26) as u32,
            b'0'..=b'9' => (c - b'0' + 52) as u32,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        })
    }
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;
    for c in s.bytes() {
        let Some(v) = val(c) else { continue };
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

/// All `sol_log_data` records with the 8-byte tag `tag`.
pub fn events(logs: &[String], tag: &str) -> Vec<Vec<u8>> {
    logs.iter()
        .filter_map(|l| l.strip_prefix("Program data: "))
        .map(|rest| rest.split_whitespace().next().map(b64_decode).unwrap_or_default())
        .filter(|d| d.len() >= 8 && &d[..8] == tag.as_bytes())
        .collect()
}

/// The single event `tag` of a transaction, with its size checked against the ABI.
pub fn event(logs: &[String], tag: &str) -> Event {
    let evs = events(logs, tag);
    assert_eq!(evs.len(), 1, "expected one {tag} event, logs:\n{}", logs.join("\n"));
    let d = evs.into_iter().next().unwrap();
    assert_eq!(d.len(), abi().ev_size(tag), "{tag} size");
    Event { tag: tag.to_string(), d }
}

pub struct Event {
    tag: String,
    pub d: Vec<u8>,
}
impl Event {
    pub fn u(&self, name: &str) -> u64 {
        let (off, size) = abi().ev_field(&self.tag, name);
        le(&self.d, off, size)
    }
    pub fn i(&self, name: &str) -> i64 {
        let (off, size) = abi().ev_field(&self.tag, name);
        assert_eq!(size, 8);
        i64_at(&self.d, off)
    }
}

// ------------------------------------------------------------ results ----

pub type TxResult = Result<TransactionMetadata, FailedTransactionMetadata>;

pub fn logs_of(r: &TxResult) -> &[String] {
    match r {
        Ok(m) => &m.logs,
        Err(f) => &f.meta.logs,
    }
}

#[track_caller]
pub fn expect_ok(r: TxResult) -> TransactionMetadata {
    match r {
        Ok(m) => m,
        Err(f) => panic!("transaction failed: {:?}\n{}", f.err, f.meta.logs.join("\n")),
    }
}

/// The transaction failed with the vault's error `name` (ABI code).
#[track_caller]
pub fn expect_err(r: TxResult, name: &str) -> FailedTransactionMetadata {
    let code = abi().err(name);
    match r {
        Ok(m) => panic!("expected {name} ({code:#x}), got success\n{}", m.logs.join("\n")),
        Err(f) => {
            let s = format!("{:?}", f.err);
            assert!(
                s.contains(&format!("Custom({code})")),
                "expected {name} ({code:#x}), got {s}\n{}",
                f.meta.logs.join("\n")
            );
            f
        }
    }
}

/// The transaction failed with a runtime error whose Debug form contains `needle`.
#[track_caller]
pub fn expect_runtime_err(r: TxResult, needle: &str) -> FailedTransactionMetadata {
    match r {
        Ok(m) => panic!("expected {needle}, got success\n{}", m.logs.join("\n")),
        Err(f) => {
            let s = format!("{:?}", f.err);
            assert!(s.contains(needle), "expected {needle}, got {s}\n{}", f.meta.logs.join("\n"));
            f
        }
    }
}

/// CU consumed by the top-level invocation of `program` per the runtime log
/// line `Program <id> consumed N of M compute units` (the first at depth 1
/// that matches when `depth1` is set).
pub fn consumed_by(logs: &[String], program: &Pubkey) -> Vec<u64> {
    let needle = format!("Program {program} consumed ");
    logs.iter()
        .filter_map(|l| l.strip_prefix(&needle))
        .filter_map(|rest| rest.split_whitespace().next()?.parse().ok())
        .collect()
}

// ----------------------------------------------------------------- env ----

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn required() -> bool {
    let on = |k: &str| matches!(std::env::var(k).as_deref(), Ok("1") | Ok("true"));
    on("SIJKA_REQUIRE_SO") || sdk_localnet_vm_required()
}

fn find_file(env: &str, candidates: &[PathBuf], what: &str) -> Option<PathBuf> {
    if let Ok(p) = std::env::var(env) {
        let p = PathBuf::from(p);
        if p.exists() {
            return Some(p);
        }
    }
    if let Some(p) = candidates.iter().find(|p| p.exists()) {
        return Some(p.clone());
    }
    if required() {
        panic!("{what} not found (set {env}); candidates: {candidates:?}");
    }
    eprintln!("skipping: {what} not found");
    None
}

pub fn vault_so() -> Option<PathBuf> {
    let r = repo_root();
    find_file("SIJKA_VAULT_SO", &[r.join("target/deploy/sijka_vault.so")], "sijka_vault.so")
}

pub fn mock_jupiter_so() -> Option<PathBuf> {
    let r = repo_root();
    find_file(
        "SIJKA_MOCK_JUPITER_SO",
        &[
            r.join("target/deploy-mocks/sijka_mock_jupiter.so"),
            r.join("programs/sijka-vault/tests/mock-jupiter/target/deploy/sijka_mock_jupiter.so"),
        ],
        "sijka_mock_jupiter.so (cargo build-sbf --manifest-path programs/sijka-vault/tests/mock-jupiter/Cargo.toml)",
    )
}

/// Mainnet fixtures fetched by `tests/fixtures/inflow-fetch.sh`.
pub fn fixture_dir() -> Option<PathBuf> {
    let r = repo_root();
    let dir = std::env::var("SIJKA_INFLOW_FIXTURES")
        .map(PathBuf::from)
        .unwrap_or_else(|_| r.join("target/deploy/.cache-inflow"));
    let probe = dir.join("jupiter_v6-mainnet.so");
    find_file("SIJKA_INFLOW_FIXTURES_PROBE", &[probe], "inflow mainnet fixtures (tests/fixtures/inflow-fetch.sh)")
        .map(|_| dir)
}

/// Options of [`Env::new`].
#[derive(Clone, Copy)]
pub struct Opts {
    /// `quote_mint = usdc_mint` (USDC pair) instead of wSOL.
    pub usdc_pair: bool,
    /// Register the Phoenix trader (tag 2) and enable its capabilities.
    pub trader: bool,
    /// Enable the trader capabilities after registration.
    pub capabilities: bool,
    /// Liquidity for the Jupiter mock (fixture fake USDC).
    pub mock_pools: bool,
}

impl Default for Opts {
    fn default() -> Self {
        Opts { usdc_pair: false, trader: false, capabilities: true, mock_pools: true }
    }
}

/// First slot after the fixture setup. The fixture sets the Phoenix deposit→withdraw
/// cooldown `GC@512` to 150 slots, so tag 21 has a quiet window (review ACC-6)
/// of `slot % 216 000 < 150 + 9 000`; the tests start just after it.
pub const START_SLOT: u64 = 9_200;

/// The keeper's default slippage for tag 20 (SPEC v4, §5.3.4: the keeper
/// passes `min_out` = quote minus 50 bps). The program reads no oracle; the
/// tests quote at the fixture SOL mark, like a keeper quoting Jupiter.
pub const KEEPER_SLIPPAGE_BPS: u64 = 50;
pub const SWAP_MAX: u64 = 100_000_000_000;
pub const SWAP_MIN: u64 = 10_000_000;
pub const DEPOSIT_MIN: u64 = 1_000_000;
/// Fixture SOL mark: 150.000 USD = 150 000 000 USDC atoms per SOL.
pub const FIXTURE_SOL_PX: u64 = 150_000_000;

pub struct Env {
    pub ctx: SdkLocalnetContext,
    pub k: Keys,
    pub admin: Keypair,
    pub keeper: Keypair,
    pub attacker: Keypair,
    pub attacker_usdc: Pubkey,
    pub pool_authority: Pubkey,
    pub pool_wsol: Pubkey,
    pub pool_usdc: Pubkey,
    pub pam: Pubkey,
    pub gti: Vec<Pubkey>,
    pub atb: Vec<Pubkey>,
    pub global_vault: Pubkey,
    pub creator_payout: Pubkey,
    pub opts: Opts,
    /// Timestamp of the last fixture oracle update (strictly increasing).
    pub oracle_ts: u64,
    /// CU of the last oracle update.
    pub oracle_cu: u64,
}

pub fn default_inflow_params() -> Vec<u8> {
    abi().pack(
        "InflowParams",
        &[
            ("swap_min_interval_s", 0),
            ("swap_max_lamports", SWAP_MAX),
            ("swap_min_lamports", SWAP_MIN),
            ("deposit_min_atoms", DEPOSIT_MIN),
        ],
    )
}

fn default_harvest_params() -> Vec<u8> {
    abi().pack(
        "HarvestParams",
        &[
            ("epsilon", 1_000_000),
            ("d_min", 1_000_000),
            ("margin_buffer_abs", 0),
            ("max_harvest_per_call", 1_000_000_000_000),
            ("t_min_secs", 3_600),
            ("margin_buffer_im_bps", 0),
            ("max_buyback_backlog", u64::MAX / 4),
            ("harvest_mark_max_age_slots", 150),
        ],
    )
}

impl Env {
    /// Full environment, or `None` when an artifact is missing outside CI.
    pub fn new(opts: Opts) -> Option<Env> {
        Self::with_programs(opts, &[], |_| {})
    }

    /// Like [`Env::new`] with extra programs loaded and a hook that runs on
    /// the LiteSVM instance before `initialize` (e.g. to patch `ember_state`).
    pub fn with_programs(
        opts: Opts,
        extra: &[(Pubkey, PathBuf)],
        before_init: impl FnOnce(&mut SdkLocalnetContext),
    ) -> Option<Env> {
        let Some(paths) = find_sdk_localnet_program_paths() else {
            if required() {
                panic!("missing Phoenix/Ember/Hawkeye SBF artifacts (RISE_SDK_LOCALNET_*_SO)");
            }
            eprintln!("skipping: Phoenix protocol artifacts missing");
            return None;
        };
        let vault = vault_so()?;
        let mock = mock_jupiter_so()?;
        let fixture = default_sdk_localnet_fixture().expect("fixture parses");
        let program = vault_program_id();
        let mut programs =
            vec![SdkLocalnetProgram::new(program, vault), SdkLocalnetProgram::new(mock_elsewhere(), mock.clone())];
        let jup_loaded = extra.iter().any(|(id, _)| *id == jup6());
        if !jup_loaded {
            programs.push(SdkLocalnetProgram::new(jup6(), mock));
        }
        for (id, path) in extra {
            programs.push(SdkLocalnetProgram::new(*id, path.clone()));
        }
        let mut ctx = SdkLocalnetContext::new_with_programs(fixture, paths, programs);
        ctx.execute_setup();
        // The clock's unix_timestamp stays where the fixture left it (0):
        // Phoenix's oracle update works through the elapsed time, and a jump
        // to a realistic timestamp exhausts even 1.4M CU. Tests that need time
        // move it by seconds (`set_now`).
        ctx.svm.warp_to_slot(START_SLOT);
        before_init(&mut ctx);

        let a = &ctx.fixture.addresses;
        let pam = parse_pubkey(&a.perp_asset_map).unwrap();
        let gti = parse_pubkeys(&a.global_trader_index);
        let atb = parse_pubkeys(&a.active_trader_buffer);
        let global_vault = parse_pubkey(&a.global_vault).unwrap();
        let es = ctx.svm.get_account(&ember_state()).expect("ember state");
        let usdc_mint = key_at(&es.data, 40);
        let phusd_mint = key_at(&es.data, 72);
        let k = Keys::derive(program, usdc_mint, phusd_mint);

        let admin = Keypair::new_from_array([0xA1; 32]);
        let keeper = Keypair::new_from_array([0xA2; 32]);
        let attacker = Keypair::new_from_array([0xA3; 32]);
        for kp in [&admin, &keeper, &attacker] {
            ctx.svm.airdrop(&kp.pubkey(), 10_000 * 1_000_000_000).unwrap();
        }
        let (pool_authority, _) = Pubkey::find_program_address(&[b"pool"], &jup6());
        let mut env = Env {
            ctx,
            k,
            admin,
            keeper,
            attacker,
            attacker_usdc: Pubkey::new_from_array([0xA4; 32]),
            pool_authority,
            pool_wsol: Pubkey::new_from_array([0xA5; 32]),
            pool_usdc: Pubkey::new_from_array([0xA6; 32]),
            pam,
            gti,
            atb,
            global_vault,
            creator_payout: Pubkey::new_from_array([0xC7; 32]),
            opts,
            oracle_ts: 1_900_000_100,
            oracle_cu: 0,
        };
        env.ensure_native_mint();
        env.set_upgrade_authority();
        expect_ok(env.initialize());
        // SPEC v4: tag 20 is signed by the keeper key only (tag 28 by the admin).
        let keeper = env.keeper.pubkey();
        expect_ok(env.set_keeper(&keeper));
        env.create_vault_atas();
        if opts.mock_pools {
            env.setup_mock_pools();
        }
        env.refresh_oracle();
        if opts.trader {
            env.register_trader();
            if opts.capabilities {
                env.enable_trader_capabilities();
            }
        }
        Some(env)
    }

    pub fn svm(&mut self) -> &mut litesvm::LiteSVM {
        &mut self.ctx.svm
    }

    pub fn slot(&self) -> u64 {
        u64_at(&self.ctx.svm.get_account(&clock_sysvar()).unwrap().data, 0)
    }
    pub fn now(&self) -> i64 {
        i64_at(&self.ctx.svm.get_account(&clock_sysvar()).unwrap().data, 32)
    }
    pub fn warp(&mut self, slot: u64) {
        self.ctx.svm.warp_to_slot(slot);
    }
    pub fn set_now(&mut self, ts: i64) {
        set_clock_ts(&mut self.ctx, ts);
    }

    pub fn rent(&self, len: usize) -> u64 {
        self.ctx.svm.minimum_balance_for_rent_exemption(len)
    }

    // ---- raw accounts

    pub fn account(&self, key: &Pubkey) -> Option<Account> {
        self.ctx.svm.get_account(key)
    }
    pub fn lamports(&self, key: &Pubkey) -> u64 {
        self.ctx.svm.get_account(key).map(|a| a.lamports).unwrap_or(0)
    }
    pub fn set(&mut self, key: Pubkey, acc: Account) {
        self.ctx.svm.set_account(key, acc).unwrap();
    }
    pub fn token_amount(&self, key: &Pubkey) -> u64 {
        self.account(key).map(|a| u64_at(&a.data, 64)).unwrap_or(0)
    }

    /// Write an SPL token account (165 bytes) directly.
    pub fn set_token(&mut self, key: Pubkey, mint: Pubkey, owner: Pubkey, amount: u64, native: bool) {
        let rent = self.rent(165);
        let mut d = vec![0u8; 165];
        d[0..32].copy_from_slice(mint.as_ref());
        d[32..64].copy_from_slice(owner.as_ref());
        d[64..72].copy_from_slice(&amount.to_le_bytes());
        d[108] = 1;
        let mut lamports = rent;
        if native {
            d[109..113].copy_from_slice(&1u32.to_le_bytes());
            d[113..121].copy_from_slice(&rent.to_le_bytes());
            lamports = rent + amount;
        }
        self.set(key, Account { lamports, data: d, owner: token_program(), executable: false, rent_epoch: 0 });
    }

    /// Change bytes of an existing account (owner kept).
    pub fn patch(&mut self, key: &Pubkey, off: usize, bytes: &[u8]) {
        let mut a = self.account(key).unwrap_or_else(|| panic!("missing {key}"));
        a.data[off..off + bytes.len()].copy_from_slice(bytes);
        self.set(*key, a);
    }

    // ---- Config through the ABI

    pub fn config(&self) -> Vec<u8> {
        self.account(&self.k.config).expect("config").data
    }
    pub fn cfg(&self, name: &str) -> u64 {
        let (off, size) = abi().field("Config", name);
        le(&self.config(), off, size)
    }
    pub fn cfg_key(&self, name: &str) -> Pubkey {
        let (off, size) = abi().field("Config", name);
        assert_eq!(size, 32);
        key_at(&self.config(), off)
    }
    pub fn set_cfg(&mut self, name: &str, v: u64) {
        let (off, size) = abi().field("Config", name);
        let k = self.k.config;
        self.patch(&k, off, &v.to_le_bytes()[..size]);
    }
    pub fn set_cfg_bytes(&mut self, name: &str, bytes: &[u8]) {
        let (off, size) = abi().field("Config", name);
        assert_eq!(size, bytes.len());
        let k = self.k.config;
        self.patch(&k, off, bytes);
    }

    // ---- sending

    pub fn send(&mut self, ixs: Vec<Instruction>, signers: &[&Keypair]) -> TxResult {
        self.send_as(&self.keeper.insecure_clone(), ixs, signers)
    }

    pub fn send_as(&mut self, payer: &Keypair, ixs: Vec<Instruction>, signers: &[&Keypair]) -> TxResult {
        self.ctx.svm.expire_blockhash();
        let mut all: Vec<&Keypair> = vec![payer];
        for s in signers {
            if s.pubkey() != payer.pubkey() {
                all.push(s);
            }
        }
        let tx = Transaction::new_signed_with_payer(&ixs, Some(&payer.pubkey()), &all, self.ctx.svm.latest_blockhash());
        self.ctx.svm.send_transaction(tx)
    }

    /// One instruction with a 1.4M CU limit.
    pub fn send1(&mut self, ix: Instruction) -> TxResult {
        self.send(vec![cu_limit(1_400_000), ix], &[])
    }

    pub fn transfer_lamports(&mut self, to: &Pubkey, lamports: u64) {
        let from = self.keeper.insecure_clone();
        let mut data = vec![2, 0, 0, 0];
        data.extend_from_slice(&lamports.to_le_bytes());
        let ix = Instruction {
            program_id: system_program(),
            accounts: vec![AccountMeta::new(from.pubkey(), true), AccountMeta::new(*to, false)],
            data,
        };
        expect_ok(self.send(vec![ix], &[]));
    }

    /// Mint fixture fake USDC (the vault's `usdc_mint`) to a token account.
    pub fn mint_usdc(&mut self, to: Pubkey, amount: u64) {
        self.ctx.mint_fake_usdc_to_token_account(to, amount);
    }

    /// Put `amount` PhUSD on a token account (the fixture PhUSD mint is owned
    /// by Ember; the balance is written directly, supply is not used by the
    /// flows under test).
    pub fn give_phusd(&mut self, to: Pubkey, amount: u64) {
        let cur = self.token_amount(&to);
        self.patch(&to, 64, &(cur + amount).to_le_bytes());
    }

    // ---- setup steps

    fn ensure_native_mint(&mut self) {
        if self.account(&wsol_mint()).is_some() {
            return;
        }
        let mut d = vec![0u8; 82];
        d[44] = 9;
        d[45] = 1;
        let lamports = self.rent(82);
        self.set(wsol_mint(), Account { lamports, data: d, owner: token_program(), executable: false, rent_epoch: 0 });
    }

    /// LiteSVM deploys with no upgrade authority; `initialize` requires the
    /// payer to be the upgrade authority (SPEC §5.1.0 #3).
    fn set_upgrade_authority(&mut self) {
        let pd = self.k.program_data;
        let mut a = self.account(&pd).expect("program data");
        assert_eq!(u32::from_le_bytes(a.data[0..4].try_into().unwrap()), 3);
        a.data[12] = 1;
        a.data[13..45].copy_from_slice(self.admin.pubkey().as_ref());
        self.set(pd, a);
    }

    /// Tag 0 `initialize` (SPEC §5.1.0): 6 accounts, 201 bytes (SPEC v2/v3:
    /// no `TradeConfig`, no trader; the trading key is set by tag 3).
    pub fn initialize_ix(&self, quote_mint: Pubkey) -> Instruction {
        let mut data = vec![0u8];
        data.extend_from_slice(self.admin.pubkey().as_ref());
        data.extend_from_slice(self.creator_payout.as_ref());
        data.extend_from_slice(quote_mint.as_ref());
        data.extend_from_slice(&default_harvest_params());
        data.extend_from_slice(&default_inflow_params());
        assert_eq!(data.len(), 201);
        Instruction {
            program_id: self.k.program,
            accounts: vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.k.config, false),
                AccountMeta::new_readonly(self.k.program_data, false),
                AccountMeta::new_readonly(system_program(), false),
                AccountMeta::new_readonly(phoenix_global_config(), false),
                AccountMeta::new_readonly(ember_state(), false),
            ],
            data,
        }
    }

    /// Tag 28 `set_keeper` (SPEC §5.1.10), signed by `signer`.
    pub fn set_keeper_ix(&self, signer: &Pubkey, key: &Pubkey) -> Instruction {
        let mut data = vec![28u8];
        data.extend_from_slice(key.as_ref());
        Instruction {
            program_id: self.k.program,
            accounts: vec![AccountMeta::new_readonly(*signer, true), AccountMeta::new(self.k.config, false)],
            data,
        }
    }

    /// The admin sets the keeper key.
    pub fn set_keeper(&mut self, key: &Pubkey) -> TxResult {
        let admin = self.admin.insecure_clone();
        let ix = self.set_keeper_ix(&admin.pubkey(), key);
        self.send_as(&admin, vec![ix], &[])
    }

    fn initialize(&mut self) -> TxResult {
        let quote = if self.opts.usdc_pair { self.k.usdc_mint } else { wsol_mint() };
        let ix = self.initialize_ix(quote);
        let admin = self.admin.insecure_clone();
        self.send_as(&admin, vec![cu_limit(400_000), ix], &[])
    }

    pub fn create_ata_ix(&self, owner: &Pubkey, mint: &Pubkey) -> Instruction {
        Instruction {
            program_id: ata_program(),
            accounts: vec![
                AccountMeta::new(self.keeper.pubkey(), true),
                AccountMeta::new(ata(owner, mint), false),
                AccountMeta::new_readonly(*owner, false),
                AccountMeta::new_readonly(*mint, false),
                AccountMeta::new_readonly(system_program(), false),
                AccountMeta::new_readonly(token_program(), false),
            ],
            data: vec![1], // CreateIdempotent
        }
    }

    pub fn create_ata(&mut self, owner: &Pubkey, mint: &Pubkey) -> Pubkey {
        let ix = self.create_ata_ix(owner, mint);
        expect_ok(self.send(vec![ix], &[]));
        ata(owner, mint)
    }

    /// The ATAs the launch scripts create after `initialize` (SPEC §2.2).
    fn create_vault_atas(&mut self) {
        let k = self.k.clone();
        let wsol = wsol_mint();
        for (owner, mint) in [
            (k.phx_authority, k.usdc_mint),
            (k.phx_authority, k.phusd_mint),
            (k.swap_authority, wsol),
            (k.swap_authority, k.usdc_mint),
            (k.buyback_authority, k.usdc_mint),
            (k.creator_escrow, k.usdc_mint),
        ] {
            self.create_ata(&owner, &mint);
        }
        assert_eq!(self.cfg_key("vault_usdc"), k.vault_usdc);
        assert_eq!(self.cfg_key("vault_phusd"), k.vault_phusd);
        assert_eq!(self.cfg_key("swap_wsol"), k.swap_wsol);
        assert_eq!(self.cfg_key("swap_usdc"), k.swap_usdc);
        assert_eq!(self.cfg_key("fee_inbox"), k.fee_inbox);
        assert_eq!(self.cfg_key("swap_authority"), k.swap_authority);
        assert_eq!(self.cfg_key("usdc_mint"), k.usdc_mint);
        assert_eq!(self.cfg_key("phusd_mint"), k.phusd_mint);
    }

    /// Liquidity of the mock "AMM": wSOL and USDC owned by `PDA(mock, ["pool"])`.
    fn setup_mock_pools(&mut self) {
        let (pa, usdc) = (self.pool_authority, self.k.usdc_mint);
        let (pw, pu) = (self.pool_wsol, self.pool_usdc);
        self.set_token(pw, wsol_mint(), pa, 1_000_000_000_000, true);
        self.set_token(pu, usdc, pa, 0, false);
        self.mint_usdc(pu, 100_000_000_000_000);
        let (au, att) = (self.attacker_usdc, self.attacker.pubkey());
        self.set_token(au, usdc, att, 0, false);
    }

    /// Fresh SOL mark at the current slot through the fixture oracle (Phoenix
    /// writes the PAM itself).
    pub fn refresh_oracle(&mut self) {
        self.set_sol_price_usd(150.0);
    }

    /// New SOL mark / spot through the fixture price oracle, one slot later
    /// (so every update lands in its own slot).
    ///
    /// Same instruction as `SdkLocalnetContext::update_oracle_prices` (Phoenix
    /// `UpdateOraclePricesWithOrdering` signed by the fixture `priceOracle`),
    /// but with a 1.4M CU limit: after a warp Phoenix spends more than the
    /// default 200k on it.
    pub fn set_sol_price_usd(&mut self, usd: f64) {
        let next = self.slot() + 1;
        self.warp(next);
        let tpl = self
            .ctx
            .fixture
            .action_templates
            .iter()
            .find(|t| t.name == "oracleSetPrices")
            .expect("oracleSetPrices template")
            .instructions
            .iter()
            .find(|i| i.name == "updateOraclePrices")
            .expect("updateOraclePrices")
            .clone();
        let mut ix = decode_fixture_instruction(&tpl).expect("fixture oracle instruction");
        let price = FixturePrice::from_usd(usd);
        self.oracle_ts += 1;
        let mut data = ix.data[..8].to_vec();
        data.extend_from_slice(&self.oracle_ts.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(b"SOL\0\0\0\0\0\0\0\0\0\0\0\0\0");
        data.push(1);
        data.extend_from_slice(&price.value.to_le_bytes());
        data.push(price.expo);
        data.extend_from_slice(&price.value.to_le_bytes());
        data.push(price.expo);
        data.push(0);
        ix.data = data;
        let r = self.ctx.try_send_instructions_with_metadata(vec![cu_limit(1_400_000), ix], "price-oracle");
        let m = expect_ok(r);
        self.oracle_cu = m.compute_units_consumed;
    }

    /// `(slot, entry offset)` of the active SOL entry, found by the SPEC §3.9
    /// layout (independent of the program).
    pub fn pam_sol_entry(&self) -> (u32, usize) {
        let d = self.account(&self.pam).expect("pam").data;
        let slots_used = u32::from_le_bytes(d[32..36].try_into().unwrap());
        for s in 0..slots_used {
            let e = 48 + s as usize * 1584;
            if &d[e..e + 16] == b"SOL\0\0\0\0\0\0\0\0\0\0\0\0\0" && d[e + 1466] == 0 {
                return (s, e);
            }
        }
        panic!("no SOL entry in the PAM");
    }

    /// `px = mark·tick·10^bld` from the PAM bytes (SPEC §5.3.2 step 5).
    pub fn pam_px(&self) -> u64 {
        let d = self.account(&self.pam).unwrap().data;
        let (_, e) = self.pam_sol_entry();
        let mark = u64_at(&d, e + 40);
        let tick = u64_at(&d, e + 952);
        let bld = d[e + 962] as i8;
        assert!((0..=9).contains(&bld));
        mark * tick * 10u64.pow(bld as u32)
    }
    pub fn pam_mark_slot(&self) -> u64 {
        let d = self.account(&self.pam).unwrap().data;
        let (_, e) = self.pam_sol_entry();
        u64_at(&d, e + 32)
    }

    // ---- Phoenix trader (tag 2 + capabilities)

    pub fn register_trader(&mut self) {
        let rent = self.rent(5360) + self.rent(0);
        let rp = self.k.rent_payer;
        self.transfer_lamports(&rp, rent);
        let ix = Instruction {
            program_id: self.k.program,
            accounts: vec![
                AccountMeta::new_readonly(self.admin.pubkey(), true),
                AccountMeta::new(self.k.config, false),
                AccountMeta::new_readonly(self.k.phx_authority, false),
                AccountMeta::new(self.k.rent_payer, false),
                AccountMeta::new_readonly(phoenix_program(), false),
                AccountMeta::new_readonly(phoenix_log_authority(), false),
                AccountMeta::new_readonly(phoenix_global_config(), false),
                AccountMeta::new(self.k.phoenix_trader, false),
                AccountMeta::new_readonly(system_program(), false),
            ],
            data: vec![2, self.k.phoenix_trader_bump],
        };
        let admin = self.admin.insecure_clone();
        expect_ok(self.send(vec![cu_limit(400_000), ix], &[&admin]));
        assert_eq!(self.cfg_key("phoenix_trader"), self.k.phoenix_trader);
    }

    /// Same instruction the fixture uses for its actors: `payer` (risk
    /// authority of the fixture exchange) in both the authority and the
    /// permission slot (research 03 §12).
    pub fn enable_trader_capabilities(&mut self) {
        let payer = self.ctx.signer_pubkey("payer");
        let mut accounts = vec![
            AccountMeta::new_readonly(phoenix_program(), false),
            AccountMeta::new_readonly(phoenix_log_authority(), false),
            AccountMeta::new_readonly(phoenix_global_config(), false),
            AccountMeta::new_readonly(payer, true),
            AccountMeta::new(payer, false),
            AccountMeta::new(self.k.phoenix_trader, false),
        ];
        accounts.extend(self.gti.iter().chain(self.atb.iter()).map(|k| AccountMeta::new(*k, false)));
        let data = b64_decode("z6oRFTUjWJcGAAAAAAEBAQMBAgEEAQUB");
        let ix = Instruction { program_id: phoenix_program(), accounts, data };
        expect_ok(self.ctx.try_send_instructions_with_metadata(vec![cu_limit(1_400_000), ix], "payer"));
    }

    pub fn trader_collateral(&self) -> i64 {
        i64_at(&self.account(&self.k.phoenix_trader).expect("trader").data, 88)
    }
}

pub fn cu_limit(units: u32) -> Instruction {
    let mut data = vec![2u8];
    data.extend_from_slice(&units.to_le_bytes());
    Instruction { program_id: compute_budget_program(), accounts: vec![], data }
}

/// Clock sysvar layout: slot, epoch_start_timestamp, epoch,
/// leader_schedule_epoch, unix_timestamp (all 8 bytes).
pub fn set_clock_ts(ctx: &mut SdkLocalnetContext, ts: i64) {
    let mut a = ctx.svm.get_account(&clock_sysvar()).expect("clock");
    a.data[32..40].copy_from_slice(&ts.to_le_bytes());
    a.lamports = a.lamports.max(1);
    ctx.svm.set_account(clock_sysvar(), a).unwrap();
}

/// The keeper's `min_out` for tag 20 (SPEC v4, §5.3.4): its quote at `px`
/// atoms USDC per SOL minus `slippage_bps`, rounded up:
/// `⌈amount·px·(10 000 − slippage) / (10⁹·10 000)⌉`.
pub fn keeper_min_out(amount: u64, px: u64, slippage_bps: u64) -> u64 {
    let num = amount as u128 * px as u128 * (10_000 - slippage_bps as u128);
    let den = 1_000_000_000u128 * 10_000;
    num.div_ceil(den) as u64
}
