// Copyright (c) 2026 prt1sn. All rights reserved.
//! Test vault on LiteSVM: our program deployed as upgradeable (upgrade
//! authority = `payer`), the mainnet pump binaries (or builtin mocks),
//! mainnet account snapshots, and the setup chain `initialize` →
//! `set_token_mint` → `bb_init` → ATAs → `bb_pin` (SPEC §5.1.0, §5.1.1,
//! §5.5.4, §5.5.5). Everything a test observes is read back from accounts,
//! logs and events.

use litesvm::LiteSVM;
use litesvm::types::{FailedTransactionMetadata, TransactionMetadata, TransactionResult};
use sijka_vault::constants as c;
use sijka_vault::error::SijkaError;
use sijka_vault::state::buyback_state::BuybackState;
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

use crate::fixtures::{Fixtures, fx};

// ------------------------------------------------------------- keys ----

pub fn pk(a: [u8; 32]) -> Pubkey {
    Pubkey::new_from_array(a)
}

pub fn key(s: &str) -> Pubkey {
    s.parse().unwrap()
}

pub fn pda(seeds: &[&[u8]], program: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(seeds, program).0
}

pub fn ata(owner: &Pubkey, token_program: &Pubkey, mint: &Pubkey) -> Pubkey {
    pda(&[owner.as_ref(), token_program.as_ref(), mint.as_ref()], &pk(c::ATA_PROGRAM_ID))
}

pub fn pump() -> Pubkey {
    pk(c::PUMP_PROGRAM)
}
pub fn pump_amm() -> Pubkey {
    pk(c::PUMP_AMM_PROGRAM)
}
pub fn pump_fees() -> Pubkey {
    pk(c::PUMP_FEES_PROGRAM)
}
pub fn tokenkeg() -> Pubkey {
    pk(c::SPL_TOKEN_PROGRAM_ID)
}
pub fn t22() -> Pubkey {
    pk(c::TOKEN_2022_PROGRAM_ID)
}
pub fn wsol() -> Pubkey {
    pk(c::WSOL_MINT)
}
pub fn system() -> Pubkey {
    pk(c::SYSTEM_PROGRAM_ID)
}
pub fn usdc() -> Pubkey {
    key("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
}
pub fn ix_sysvar() -> Pubkey {
    pk(c::INSTRUCTIONS_SYSVAR)
}
pub fn clock_sysvar() -> Pubkey {
    key("SysvarC1ock11111111111111111111111111111111")
}
pub fn sysvar_owner() -> Pubkey {
    key("Sysvar1111111111111111111111111111111111111")
}
pub fn bpf_loader2() -> Pubkey {
    key("BPFLoader2111111111111111111111111111111111")
}
pub fn upgradeable_loader() -> Pubkey {
    pk(c::BPF_LOADER_UPGRADEABLE_ID)
}
pub fn compute_budget_program() -> Pubkey {
    pk(c::COMPUTE_BUDGET_PROGRAM_ID)
}
pub fn dont_front() -> Pubkey {
    pk(c::JITO_DONT_FRONT)
}
pub fn jup_program() -> Pubkey {
    pk(c::JUPITER_V6)
}

pub const LAMPORTS_PER_SOL: u64 = 1_000_000_000;
/// Unix time used as "now" at the start of every test (2026-09-26).
pub const T0: i64 = 1_790_400_000;

// ------------------------------------------------------------- errors ----

/// `Custom(code)` of one of our errors, and the matching log line.
pub fn assert_sijka(res: &TransactionResult, e: SijkaError) {
    match res {
        Ok(m) => panic!("expected {e:?}, transaction succeeded; logs:\n{}", m.logs.join("\n")),
        Err(f) => {
            let s = format!("{:?}", f.err);
            let code = e.code();
            assert!(
                s.contains(&format!("Custom({code})")),
                "expected {e:?} (Custom({code})), got {s}; logs:\n{}",
                f.meta.logs.join("\n")
            );
            let line = e.log_line();
            assert!(
                f.meta.logs.iter().any(|l| l.contains(line)),
                "log line {line:?} missing:\n{}",
                f.meta.logs.join("\n")
            );
        }
    }
}

/// `Custom(code)` raised by an external program (pump error codes).
pub fn assert_custom(res: &TransactionResult, code: u32) {
    match res {
        Ok(m) => panic!("expected Custom({code}), transaction succeeded; logs:\n{}", m.logs.join("\n")),
        Err(f) => {
            let s = format!("{:?}", f.err);
            assert!(
                s.contains(&format!("Custom({code})")),
                "expected Custom({code}), got {s}; logs:\n{}",
                f.meta.logs.join("\n")
            );
        }
    }
}

/// Custom error code of a failed transaction, if any.
pub fn custom_code(f: &FailedTransactionMetadata) -> Option<u32> {
    let s = format!("{:?}", f.err);
    let i = s.find("Custom(")?;
    s[i + 7..].split(')').next()?.parse().ok()
}

pub fn ok(res: TransactionResult) -> TransactionMetadata {
    match res {
        Ok(m) => m,
        Err(f) => panic!("transaction failed: {:?}\nlogs:\n{}", f.err, f.meta.logs.join("\n")),
    }
}

pub fn logs_of(res: &TransactionResult) -> &[String] {
    match res {
        Ok(m) => &m.logs,
        Err(f) => &f.meta.logs,
    }
}

// ------------------------------------------------------------- events ----

/// Our events (SPEC §7): `Program data:` lines whose payload starts with
/// `SJKEV`. Returns `(tag, payload)`.
pub fn events(logs: &[String]) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for l in logs {
        let Some(rest) = l.strip_prefix("Program data: ") else { continue };
        for part in rest.split(' ') {
            let Ok(b) = crate::fixtures::b64decode(part) else { continue };
            if b.len() >= 17 && b.starts_with(b"SJKEV") {
                out.push((String::from_utf8_lossy(&b[..8]).to_string(), b));
            }
        }
    }
    out
}

pub fn event(logs: &[String], tag: &str) -> Vec<u8> {
    let all = events(logs);
    let hits: Vec<_> = all.iter().filter(|(t, _)| t == tag).collect();
    assert_eq!(hits.len(), 1, "expected exactly one {tag}, got {:?}", all.iter().map(|e| &e.0).collect::<Vec<_>>());
    let e = hits[0].1.clone();
    assert_eq!(e[8], 1, "{tag}: ver");
    e
}

pub fn u16_at(d: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(d[o..o + 2].try_into().unwrap())
}
pub fn u32_at(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(d[o..o + 4].try_into().unwrap())
}
pub fn u64_at(d: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(d[o..o + 8].try_into().unwrap())
}
pub fn i64_at(d: &[u8], o: usize) -> i64 {
    i64::from_le_bytes(d[o..o + 8].try_into().unwrap())
}
pub fn u128_at(d: &[u8], o: usize) -> u128 {
    u128::from_le_bytes(d[o..o + 16].try_into().unwrap())
}
pub fn key_at(d: &[u8], o: usize) -> Pubkey {
    Pubkey::new_from_array(d[o..o + 32].try_into().unwrap())
}

// ------------------------------------------------------------ coin keys ----

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Quote {
    Sol,
    Usdc,
}

/// Addresses of a pump.fun coin, derived independently of the program
/// (IDL seeds, research 07 appendix A).
#[derive(Clone, Debug)]
pub struct CoinKeys {
    pub label: String,
    pub quote: Quote,
    pub mint: Pubkey,
    pub token_program: Pubkey,
    pub quote_mint: Pubkey,
    pub curve: Pubkey,
    pub curve_base_ata: Pubkey,
    pub curve_quote_ata: Pubkey,
    pub sharing_config: Pubkey,
    pub creator_vault: Pubkey,
    pub creator_vault_ata: Pubkey,
    pub pool_authority: Pubkey,
    pub pool: Pubkey,
    pub pool_base_ta: Pubkey,
    pub pool_quote_ta: Pubkey,
    pub pool_v2: Pubkey,
    pub coin_creator_vault_authority: Pubkey,
    pub coin_creator_vault_ata: Pubkey,
}

impl CoinKeys {
    pub fn derive(label: &str, mint: Pubkey, token_program: Pubkey, quote: Quote) -> Self {
        let quote_mint = match quote {
            Quote::Sol => wsol(),
            Quote::Usdc => usdc(),
        };
        let curve = pda(&[b"bonding-curve", mint.as_ref()], &pump());
        let sc = pda(&[b"sharing-config", mint.as_ref()], &pump_fees());
        let cv = pda(&[b"creator-vault", sc.as_ref()], &pump());
        let pa = pda(&[b"pool-authority", mint.as_ref()], &pump());
        let pool = pda(&[b"pool", &[0, 0], pa.as_ref(), mint.as_ref(), quote_mint.as_ref()], &pump_amm());
        let ccva = pda(&[b"creator_vault", sc.as_ref()], &pump_amm());
        CoinKeys {
            label: label.to_string(),
            quote,
            mint,
            token_program,
            quote_mint,
            curve,
            curve_base_ata: ata(&curve, &token_program, &mint),
            curve_quote_ata: ata(&curve, &tokenkeg(), &quote_mint),
            sharing_config: sc,
            creator_vault: cv,
            creator_vault_ata: ata(&cv, &tokenkeg(), &quote_mint),
            pool_authority: pa,
            pool,
            pool_base_ta: ata(&pool, &token_program, &mint),
            pool_quote_ta: ata(&pool, &tokenkeg(), &quote_mint),
            pool_v2: pda(&[b"pool-v2", mint.as_ref()], &pump_amm()),
            coin_creator_vault_authority: ccva,
            coin_creator_vault_ata: ata(&ccva, &tokenkeg(), &quote_mint),
        }
    }

    /// pump creator vault and its quote ATA for a given `creator` (after CTO).
    pub fn creator_vault_for(&self, creator: &Pubkey) -> (Pubkey, Pubkey) {
        let cv = pda(&[b"creator-vault", creator.as_ref()], &pump());
        (cv, ata(&cv, &tokenkeg(), &self.quote_mint))
    }

    /// pump_amm coin creator vault authority and ATA for `coin_creator`.
    pub fn coin_creator_vault_for(&self, coin_creator: &Pubkey) -> (Pubkey, Pubkey) {
        let a = pda(&[b"creator_vault", coin_creator.as_ref()], &pump_amm());
        (a, ata(&a, &tokenkeg(), &self.quote_mint))
    }
}

/// Our PDAs and ATAs (SPEC §2.1, §2.2), derived from the program id.
#[derive(Clone, Debug)]
pub struct VaultKeys {
    pub config: Pubkey,
    pub buyback_state: Pubkey,
    pub bb_unwrap: Pubkey,
    pub fee_inbox: Pubkey,
    pub phx_authority: Pubkey,
    pub swap_authority: Pubkey,
    pub buyback_authority: Pubkey,
    pub rent_payer: Pubkey,
    pub creator_escrow: Pubkey,
    pub buyback_usdc: Pubkey,
    pub swap_usdc: Pubkey,
    pub swap_wsol: Pubkey,
    pub bb_wsol: Pubkey,
    pub program_data: Pubkey,
}

impl VaultKeys {
    pub fn derive(program_id: &Pubkey) -> Self {
        let p = |s: &[u8]| pda(&[s], program_id);
        let swap = p(b"swap");
        let bb = p(b"buyback");
        VaultKeys {
            config: p(b"config"),
            buyback_state: p(b"buyback_state"),
            bb_unwrap: p(b"bb_unwrap"),
            fee_inbox: p(b"fee_inbox"),
            phx_authority: p(b"phx_authority"),
            swap_authority: swap,
            buyback_authority: bb,
            rent_payer: p(b"rent_payer"),
            creator_escrow: p(b"creator_escrow"),
            buyback_usdc: ata(&bb, &tokenkeg(), &usdc()),
            swap_usdc: ata(&swap, &tokenkeg(), &usdc()),
            swap_wsol: ata(&swap, &tokenkeg(), &wsol()),
            bb_wsol: ata(&bb, &tokenkeg(), &wsol()),
            program_data: pda(&[program_id.as_ref()], &upgradeable_loader()),
        }
    }
}

// ------------------------------------------------------------- params ----

pub fn harvest_params() -> [u8; 64] {
    let mut d = [0u8; 64];
    d[0..8].copy_from_slice(&1_000_000u64.to_le_bytes());
    d[8..16].copy_from_slice(&25_000_000u64.to_le_bytes());
    d[16..24].copy_from_slice(&5_000_000u64.to_le_bytes());
    d[24..32].copy_from_slice(&250_000_000_000u64.to_le_bytes());
    // @32..40 and @56..58: the retired withdraw tolerance (SPEC v4), zeros.
    d[40..44].copy_from_slice(&604_800u32.to_le_bytes());
    d[44..48].copy_from_slice(&5_000u32.to_le_bytes());
    d[48..56].copy_from_slice(&50_000_000_000u64.to_le_bytes());
    d[58..60].copy_from_slice(&150u16.to_le_bytes());
    d
}

pub fn inflow_params() -> [u8; 40] {
    let mut d = [0u8; 40];
    // @0..4 (the retired oracle band / mark age) and @32..40 (the retired
    // Ember tolerance): reserved zeros (SPEC v4).
    d[4..8].copy_from_slice(&0u32.to_le_bytes());
    d[8..16].copy_from_slice(&10_000_000_000u64.to_le_bytes());
    d[16..24].copy_from_slice(&50_000_000u64.to_le_bytes());
    d[24..32].copy_from_slice(&1_000_000u64.to_le_bytes());
    d
}

/// `BuybackParams` field offsets (SPEC §3.8). SPEC v4: `@2..6` (the former
/// `max_dev_bps`, `fee_cap_bps`), `@8` (`swap_band_bps`) and `@24`
/// (`mark_max_age_slots`) are reserved zeros.
pub mod bp {
    pub const CHUNK_BPS: usize = 0;
    pub const RESERVED0: usize = 2;
    pub const OBS_CLAMP_BPS: usize = 6;
    pub const RESERVED1: usize = 8;
    pub const WARMUP_OBS: usize = 10;
    pub const BUY_MIN_INTERVAL_S: usize = 12;
    pub const OBS_MAX_AGE_S: usize = 16;
    pub const SWAP_MIN_INTERVAL_S: usize = 20;
    pub const RESERVED2: usize = 24;
    pub const CHUNK_MAX_QUOTE: usize = 32;
    pub const CHUNK_MIN_QUOTE: usize = 40;
    pub const SWAP_MAX_USDC: usize = 48;
    pub const SOL_BUDGET_CAP: usize = 56;
}

// ------------------------------------------------------------ programs ----

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PumpMode {
    /// Mainnet pump / pump_amm / pump_fees binaries.
    Real,
    /// Builtin mocks at the pump / pump_amm addresses (`mocks.rs`).
    Mock,
}

/// Fresh SVM with our program and the external programs.
fn new_svm(f: &Fixtures, program_id: &Pubkey, authority: &Pubkey, mode: PumpMode) -> LiteSVM {
    let mut svm = LiteSVM::new().with_transaction_history(0).with_log_bytes_limit(None);
    // Token programs and ATA from mainnet (Tokenkeg and ATA are BPFLoader2
    // programs on mainnet; Token-2022 is upgradeable).
    svm.add_program_with_loader(tokenkeg(), f.program("spl_token"), bpf_loader2()).unwrap();
    svm.add_program_with_loader(pk(c::ATA_PROGRAM_ID), f.program("associated_token"), bpf_loader2()).unwrap();
    svm.add_program(t22(), f.program("token_2022")).unwrap();
    match mode {
        PumpMode::Real => {
            svm.add_program(pump(), f.program("pump")).unwrap();
            svm.add_program(pump_amm(), f.program("pump_amm")).unwrap();
            svm.add_program(pump_fees(), f.program("pump_fees")).unwrap();
        }
        PumpMode::Mock => {
            crate::mocks::install_pump_mocks(&mut svm);
            svm.add_program(pump_fees(), f.program("pump_fees")).unwrap();
        }
    }
    crate::mocks::install_jupiter_mock(&mut svm);
    crate::mocks::install_cpi_wrapper(&mut svm);
    // Our program, upgradeable, upgrade authority = `authority` (SPEC §9.1).
    svm.add_program(*program_id, &f.sijka_so).unwrap();
    let pd = pda(&[program_id.as_ref()], &upgradeable_loader());
    let mut acc = svm.get_account(&pd).unwrap();
    acc.data[12] = 1;
    acc.data[13..45].copy_from_slice(authority.as_ref());
    svm.set_account(pd, acc).unwrap();
    svm
}

// --------------------------------------------------------------- vault ----

pub struct Vault {
    pub svm: LiteSVM,
    pub fx: &'static Fixtures,
    pub program_id: Pubkey,
    /// Upgrade authority, pays for setup.
    pub payer: Keypair,
    pub admin: Keypair,
    /// Caller of the cranks and `config.keeper` (SPEC v4: the only signer of
    /// tags 43, 44, 45), set by the admin right after `initialize`.
    pub keeper: Keypair,
    pub creator_payout: Pubkey,
    pub quote: Quote,
    pub mode: PumpMode,
    pub k: VaultKeys,
    pub coin: Option<CoinKeys>,
    /// Compute units of the last successful transaction.
    pub last_cu: u64,
}

pub struct Setup {
    pub quote: Quote,
    pub mode: PumpMode,
    /// Coin whose snapshot accounts are loaded.
    pub coin: Option<&'static str>,
    /// Run `set_token_mint` (tag 1) for the coin.
    pub set_mint: bool,
    /// Run `bb_init` (tag 40).
    pub bb_init: bool,
    /// Run `bb_pin` (tag 41).
    pub pin: bool,
}

impl Setup {
    pub fn sol(coin: &'static str) -> Self {
        Setup { quote: Quote::Sol, mode: PumpMode::Real, coin: Some(coin), set_mint: true, bb_init: true, pin: true }
    }
    pub fn usdc(coin: &'static str) -> Self {
        Setup { quote: Quote::Usdc, ..Setup::sol(coin) }
    }
    /// Only `initialize` (and the coin's accounts, if any).
    pub fn bare(quote: Quote, coin: Option<&'static str>) -> Self {
        Setup { quote, mode: PumpMode::Real, coin, set_mint: false, bb_init: false, pin: false }
    }
    pub fn mock(mut self) -> Self {
        self.mode = PumpMode::Mock;
        self
    }
    pub fn no_pin(mut self) -> Self {
        self.pin = false;
        self
    }
}

impl Vault {
    /// New vault, or `None` if the fixtures are missing (test skipped).
    pub fn try_new(s: Setup) -> Option<Vault> {
        let f = fx()?;
        let payer = Keypair::new();
        let admin = Keypair::new();
        let keeper = Keypair::new();
        let program_id = Keypair::new().pubkey();
        let mut svm = new_svm(f, &program_id, &payer.pubkey(), s.mode);
        for kp in [&payer, &admin, &keeper] {
            svm.airdrop(&kp.pubkey(), 1_000 * LAMPORTS_PER_SOL).unwrap();
        }
        let mut v = Vault {
            svm,
            fx: f,
            program_id,
            payer,
            admin,
            keeper,
            creator_payout: Keypair::new().pubkey(),
            quote: s.quote,
            mode: s.mode,
            k: VaultKeys::derive(&program_id),
            coin: None,
            last_cu: 0,
        };
        v.load_common();
        v.set_clock(f.slot + 2, T0);
        ok(v.initialize());
        let keeper = v.keeper.pubkey();
        ok(v.set_keeper(&keeper));
        if let Some(label) = s.coin {
            v.load_coin(label);
            if s.set_mint {
                ok(v.set_token_mint());
            }
        }
        if s.bb_init {
            ok(v.bb_init());
        }
        if s.coin.is_some() && s.set_mint {
            v.create_bb_atas();
            if s.pin {
                ok(v.bb_pin());
            }
        }
        Some(v)
    }

    pub fn coin(&self) -> &CoinKeys {
        self.coin.as_ref().expect("coin loaded")
    }

    // ------------------------------------------------------- accounts

    pub fn load_common(&mut self) {
        let skip_prefixes = ["solcurve ", "solamm ", "usdccurve ", "usdcamm "];
        for s in &self.fx.accounts {
            if skip_prefixes.iter().any(|p| s.label.starts_with(p)) {
                continue;
            }
            self.svm.set_account(s.pubkey, s.account.clone()).unwrap();
        }
    }

    /// Load every snapshot account of coin `label` and point its sharing
    /// config's single shareholder at our `fee_inbox` (SPEC §5.1.1 step 3).
    pub fn load_coin(&mut self, label: &str) {
        let prefix = format!("{label} ");
        for s in &self.fx.accounts {
            if s.label.starts_with(&prefix) {
                self.svm.set_account(s.pubkey, s.account.clone()).unwrap();
            }
        }
        let mint = self.fx.key(&format!("{label} mint"));
        let tp = self.fx.by_label(&format!("{label} mint")).unwrap().account.owner;
        let quote = if label.starts_with("usdc") { Quote::Usdc } else { Quote::Sol };
        let ck = CoinKeys::derive(label, mint, tp, quote);
        assert_eq!(ck.curve, self.fx.key(&format!("{label} bonding_curve")));
        assert_eq!(ck.sharing_config, self.fx.key(&format!("{label} sharing_config")));
        let fee_inbox = self.k.fee_inbox;
        self.patch(&ck.sharing_config, |d| {
            assert_eq!(u32_at(d, 76), 1, "live sharing config has one shareholder");
            d[80..112].copy_from_slice(fee_inbox.as_ref());
            d[112..114].copy_from_slice(&10_000u16.to_le_bytes());
        });
        self.coin = Some(ck);
    }

    pub fn account(&self, k: &Pubkey) -> Option<Account> {
        self.svm.get_account(k).filter(|a| a.lamports > 0 || !a.data.is_empty())
    }

    pub fn data(&self, k: &Pubkey) -> Vec<u8> {
        self.account(k).map(|a| a.data).unwrap_or_default()
    }

    pub fn lamports(&self, k: &Pubkey) -> u64 {
        self.svm.get_account(k).map(|a| a.lamports).unwrap_or(0)
    }

    pub fn exists(&self, k: &Pubkey) -> bool {
        self.account(k).is_some()
    }

    pub fn set(&mut self, k: Pubkey, a: Account) {
        self.svm.set_account(k, a).unwrap();
    }

    /// Edit an existing account's data in place.
    pub fn patch(&mut self, k: &Pubkey, f: impl FnOnce(&mut Vec<u8>)) {
        let mut a = self.svm.get_account(k).unwrap_or_else(|| panic!("patch: no account {k}"));
        f(&mut a.data);
        self.svm.set_account(*k, a).unwrap();
    }

    pub fn set_lamports(&mut self, k: &Pubkey, lamports: u64) {
        let mut a = self.svm.get_account(k).unwrap_or(Account {
            lamports: 0,
            data: vec![],
            owner: system(),
            executable: false,
            rent_epoch: u64::MAX,
        });
        a.lamports = lamports;
        self.svm.set_account(*k, a).unwrap();
    }

    pub fn rent(&self, len: usize) -> u64 {
        self.svm.minimum_balance_for_rent_exemption(len)
    }

    /// Token account amount (`u64@64`), 0 if absent.
    pub fn token_amount(&self, k: &Pubkey) -> u64 {
        let d = self.data(k);
        if d.len() < 72 { 0 } else { u64_at(&d, 64) }
    }

    pub fn mint_supply(&self, mint: &Pubkey) -> u64 {
        u64_at(&self.data(mint), 36)
    }

    /// Write a token account (165 bytes; Token-2022 accounts get the 170-byte
    /// ATA layout with ImmutableOwner) with `amount`.
    pub fn set_token_account(&mut self, k: Pubkey, program: Pubkey, mint: Pubkey, owner: Pubkey, amount: u64) {
        let native = mint == wsol();
        let len = if program == t22() { 170 } else { 165 };
        let mut d = vec![0u8; len];
        d[0..32].copy_from_slice(mint.as_ref());
        d[32..64].copy_from_slice(owner.as_ref());
        d[64..72].copy_from_slice(&amount.to_le_bytes());
        d[108] = 1;
        let rent = self.rent(len);
        let mut lamports = rent;
        if native {
            d[109..113].copy_from_slice(&1u32.to_le_bytes());
            d[113..121].copy_from_slice(&rent.to_le_bytes());
            lamports += amount;
        }
        if len == 170 {
            // AccountType::Account, then ImmutableOwner (type 7, len 0).
            d[165] = 2;
            d[166..168].copy_from_slice(&7u16.to_le_bytes());
        }
        self.set(k, Account { lamports, data: d, owner: program, executable: false, rent_epoch: u64::MAX });
    }

    /// Change the amount of an existing token account (native: lamports too).
    pub fn set_token_amount(&mut self, k: &Pubkey, amount: u64) {
        let mut a = self.svm.get_account(k).unwrap();
        let old = u64_at(&a.data, 64);
        a.data[64..72].copy_from_slice(&amount.to_le_bytes());
        if u32_at(&a.data, 109) == 1 {
            a.lamports = a.lamports - old + amount;
        }
        self.svm.set_account(*k, a).unwrap();
    }

    // ---------------------------------------------------------- clock

    pub fn clock(&self) -> (u64, i64) {
        let d = self.svm.get_account(&clock_sysvar()).unwrap().data;
        (u64_at(&d, 0), i64_at(&d, 32))
    }

    pub fn set_clock(&mut self, slot: u64, ts: i64) {
        let mut d = vec![0u8; 40];
        d[0..8].copy_from_slice(&slot.to_le_bytes());
        d[8..16].copy_from_slice(&ts.to_le_bytes());
        d[16..24].copy_from_slice(&(slot / 432_000).to_le_bytes());
        d[24..32].copy_from_slice(&(slot / 432_000 + 1).to_le_bytes());
        d[32..40].copy_from_slice(&ts.to_le_bytes());
        let lamports = self.rent(40);
        self.svm
            .set_account(
                clock_sysvar(),
                Account { lamports, data: d, owner: sysvar_owner(), executable: false, rent_epoch: 0 },
            )
            .unwrap();
    }

    /// Advance the clock by `secs` seconds and `slots` slots.
    pub fn tick(&mut self, secs: i64, slots: u64) {
        let (s, t) = self.clock();
        self.set_clock(s + slots, t + secs);
    }

    pub fn now(&self) -> i64 {
        self.clock().1
    }

    pub fn slot(&self) -> u64 {
        self.clock().0
    }

    // ------------------------------------------------------------- txs

    /// Send `ixs` after a ComputeBudget limit of 1.4M CU; fee payer = first signer.
    pub fn send(&mut self, ixs: Vec<Instruction>, signers: &[&Keypair]) -> TransactionResult {
        let mut all = vec![cu_limit(1_400_000)];
        all.extend(ixs);
        self.send_raw(all, signers)
    }

    /// Send exactly `ixs` (no ComputeBudget instruction added).
    pub fn send_raw(&mut self, ixs: Vec<Instruction>, signers: &[&Keypair]) -> TransactionResult {
        let payer = signers[0].pubkey();
        let bh = self.svm.latest_blockhash();
        let tx = Transaction::new_signed_with_payer(&ixs, Some(&payer), signers, bh);
        let res = self.svm.send_transaction(tx);
        self.svm.expire_blockhash();
        if let Ok(m) = &res {
            self.last_cu = m.compute_units_consumed;
        }
        res
    }

    /// Our instruction, sent by the keeper.
    pub fn call(&mut self, ix: Instruction) -> TransactionResult {
        let kp = self.keeper.insecure_clone();
        self.send(vec![ix], &[&kp])
    }

    pub fn ix(&self, data: Vec<u8>, accounts: Vec<AccountMeta>) -> Instruction {
        Instruction { program_id: self.program_id, accounts, data }
    }

    // ----------------------------------------------------------- setup

    pub fn initialize(&mut self) -> TransactionResult {
        let quote_mint = match self.quote {
            Quote::Sol => wsol(),
            Quote::Usdc => usdc(),
        };
        let mut d = vec![0u8];
        d.extend_from_slice(self.admin.pubkey().as_ref());
        d.extend_from_slice(self.creator_payout.as_ref());
        d.extend_from_slice(quote_mint.as_ref());
        d.extend_from_slice(&harvest_params());
        d.extend_from_slice(&inflow_params());
        let ix = self.ix(
            d,
            vec![
                AccountMeta::new(self.payer.pubkey(), true),
                AccountMeta::new(self.k.config, false),
                AccountMeta::new_readonly(self.k.program_data, false),
                AccountMeta::new_readonly(system(), false),
                AccountMeta::new_readonly(pk(c::PHOENIX_GLOBAL_CONFIG), false),
                AccountMeta::new_readonly(pk(c::EMBER_STATE), false),
            ],
        );
        let p = self.payer.insecure_clone();
        self.send(vec![ix], &[&p])
    }

    /// Tag 28 `set_keeper` (SPEC §5.1.10), signed by the admin.
    pub fn set_keeper(&mut self, key: &Pubkey) -> TransactionResult {
        let mut d = vec![28u8];
        d.extend_from_slice(key.as_ref());
        let ix = self
            .ix(d, vec![AccountMeta::new_readonly(self.admin.pubkey(), true), AccountMeta::new(self.k.config, false)]);
        let a = self.admin.insecure_clone();
        self.send(vec![ix], &[&a])
    }

    pub fn set_token_mint(&mut self) -> TransactionResult {
        let ck = self.coin().clone();
        let ix = self.ix(
            vec![1],
            vec![
                AccountMeta::new_readonly(self.admin.pubkey(), true),
                AccountMeta::new(self.k.config, false),
                AccountMeta::new_readonly(ck.mint, false),
                AccountMeta::new_readonly(ck.sharing_config, false),
            ],
        );
        let a = self.admin.insecure_clone();
        self.send(vec![ix], &[&a])
    }

    pub fn bb_init(&mut self) -> TransactionResult {
        let ix = self.ix(
            vec![40],
            vec![
                AccountMeta::new(self.keeper.pubkey(), true),
                AccountMeta::new_readonly(self.k.config, false),
                AccountMeta::new(self.k.buyback_state, false),
                AccountMeta::new_readonly(self.k.buyback_authority, false),
                AccountMeta::new_readonly(self.k.swap_authority, false),
                AccountMeta::new_readonly(self.k.bb_unwrap, false),
                AccountMeta::new_readonly(system(), false),
            ],
        );
        self.call(ix)
    }

    /// `buyback_token`, `bb_wsol` (SOL pair) / `buyback_usdc` (USDC pair) and
    /// `swap_usdc` via the ATA program (`CreateIdempotent`), as the keeper
    /// script does after `bb_init` (SPEC §5.1.0).
    pub fn create_bb_atas(&mut self) {
        let ck = self.coin().clone();
        let bb = self.k.buyback_authority;
        let mut ixs = vec![create_ata_ix(&self.keeper.pubkey(), &bb, &ck.mint, &ck.token_program)];
        match self.quote {
            Quote::Sol => ixs.push(create_ata_ix(&self.keeper.pubkey(), &bb, &wsol(), &tokenkeg())),
            Quote::Usdc => ixs.push(create_ata_ix(&self.keeper.pubkey(), &bb, &usdc(), &tokenkeg())),
        }
        ixs.push(create_ata_ix(&self.keeper.pubkey(), &bb, &usdc(), &tokenkeg()));
        ixs.push(create_ata_ix(&self.keeper.pubkey(), &self.k.swap_authority, &usdc(), &tokenkeg()));
        let kp = self.keeper.insecure_clone();
        ok(self.send(ixs, &[&kp]));
    }

    pub fn buyback_token(&self) -> Pubkey {
        let ck = self.coin();
        ata(&self.k.buyback_authority, &ck.token_program, &ck.mint)
    }

    /// `bb_quote` (k10): `bb_wsol` for SOL, `buyback_usdc` for USDC.
    pub fn bb_quote(&self) -> Pubkey {
        match self.quote {
            Quote::Sol => self.k.bb_wsol,
            Quote::Usdc => self.k.buyback_usdc,
        }
    }

    pub fn bb_pin_ix(&self) -> Instruction {
        let ck = self.coin();
        self.ix(
            vec![41],
            vec![
                AccountMeta::new(self.k.buyback_state, false),
                AccountMeta::new_readonly(self.k.config, false),
                AccountMeta::new_readonly(ck.mint, false),
                AccountMeta::new_readonly(ck.curve, false),
                AccountMeta::new_readonly(ck.pool, false),
                AccountMeta::new_readonly(ck.pool_base_ta, false),
                AccountMeta::new_readonly(ck.pool_quote_ta, false),
            ],
        )
    }

    pub fn bb_pin(&mut self) -> TransactionResult {
        let ix = self.bb_pin_ix();
        self.call(ix)
    }

    pub fn observe_ix(&self) -> Instruction {
        let ck = self.coin();
        self.ix(
            vec![42],
            vec![
                AccountMeta::new(self.k.buyback_state, false),
                AccountMeta::new_readonly(ix_sysvar(), false),
                AccountMeta::new_readonly(ck.curve, false),
                AccountMeta::new_readonly(ck.pool, false),
                AccountMeta::new_readonly(ck.pool_base_ta, false),
                AccountMeta::new_readonly(ck.pool_quote_ta, false),
            ],
        )
    }

    pub fn observe(&mut self) -> TransactionResult {
        let ix = self.observe_ix();
        self.call(ix)
    }

    /// `n` observations 15 s and 1 slot apart (the first one right now).
    pub fn warm_up(&mut self, n: usize) {
        for i in 0..n {
            if i > 0 || self.bs().flags() & 2 != 0 {
                self.tick(15, 1);
            }
            ok(self.observe());
        }
    }

    /// Warm-up to `warmup_obs`, then one more second and slot for the chunk.
    pub fn warm(&mut self) {
        let n = usize::from(self.bs().buyback_params().warmup_obs());
        self.warm_up(n);
        self.tick(1, 1);
    }

    pub fn bb_burn_ix(&self) -> Instruction {
        let ck = self.coin();
        self.ix(
            vec![46],
            vec![
                AccountMeta::new(self.k.buyback_state, false),
                AccountMeta::new_readonly(self.k.buyback_authority, false),
                AccountMeta::new(self.buyback_token(), false),
                AccountMeta::new(ck.mint, false),
                AccountMeta::new_readonly(ck.token_program, false),
            ],
        )
    }

    /// Test-only: overwrite `BuybackState.params@232` (SPEC v4: the buyback
    /// parameters are the `bb_init` defaults for good; tag 47 is retired).
    pub fn set_params(&mut self, f: impl FnOnce(&mut [u8; 80])) {
        let mut p = self.params();
        f(&mut p);
        let k = self.k.buyback_state;
        self.patch(&k, |d| d[232..312].copy_from_slice(&p));
    }

    // ----------------------------------------------------------- state

    pub fn state_data(&self) -> Vec<u8> {
        self.data(&self.k.buyback_state)
    }

    /// Owned snapshot of `BuybackState` with the lib's read view.
    pub fn bs(&self) -> Bs {
        Bs(self.state_data())
    }

    pub fn params(&self) -> [u8; 80] {
        self.state_data()[232..312].try_into().unwrap()
    }

    pub fn pinned(&self, i: usize) -> Pubkey {
        key_at(&self.state_data(), 312 + 32 * i)
    }

    pub fn config_data(&self) -> Vec<u8> {
        self.data(&self.k.config)
    }

    /// `RESERVE = rent(0) + MAX_RENT_EXTRA` (SPEC §5.5.1).
    pub fn reserve(&self) -> u64 {
        self.rent(0) + c::MAX_RENT_EXTRA
    }

    /// Give `buyback_authority` exactly `RESERVE + budget` lamports.
    pub fn fund_authority(&mut self, budget: u64) {
        let r = self.reserve();
        let k = self.k.buyback_authority;
        self.set_lamports(&k, r + budget);
    }
}

/// Owned `BuybackState` bytes with typed getters through the lib's view.
pub struct Bs(pub Vec<u8>);

impl Bs {
    pub fn view(&self) -> BuybackState<'_> {
        BuybackState::new(&self.0).expect("BuybackState layout")
    }
}

impl std::ops::Deref for Bs {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

macro_rules! bs_getters {
    ($($name:ident: $t:ty),* $(,)?) => {
        impl Bs {
            $(pub fn $name(&self) -> $t { self.view().$name() })*
        }
    };
}
bs_getters!(
    flags: u8,
    venue: u8,
    quote_kind: u8,
    base_decimals: u8,
    base_tp_kind: u8,
    last_obs_ts: i64,
    last_obs_slot: u64,
    ema_price_x64: u128,
    last_obs_price_x64: u128,
    last_obs_quote: u64,
    q_ema: u64,
    fresh_obs: u16,
    last_buy_ts: i64,
    last_buy_slot: u64,
    last_swap_ts: i64,
    venue_since_slot: u64,
    n_obs: u64,
    n_chunks: u64,
    cum_payout_buyback_spent: u64,
    cum_usdc_swapped: u64,
    cum_sol_from_swaps: u64,
    cum_quote_spent_curve: u64,
    cum_quote_spent_amm: u64,
    cum_rent_spent: u64,
    cum_bought_tokens: u64,
    cum_burned_tokens: u64,
    n_swaps: u64,
    next_buy_ts: i64,
    next_swap_ts: i64,
);

impl Bs {
    pub fn buyback_params(&self) -> Params {
        Params(self.0[232..312].try_into().unwrap())
    }
    pub fn pinned(&self, i: usize) -> Pubkey {
        key_at(&self.0, 312 + 32 * i)
    }
}

/// `BuybackParams` bytes (SPEC §3.8).
pub struct Params(pub [u8; 80]);

impl Params {
    pub fn chunk_bps(&self) -> u16 {
        u16_at(&self.0, bp::CHUNK_BPS)
    }
    pub fn obs_clamp_bps(&self) -> u16 {
        u16_at(&self.0, bp::OBS_CLAMP_BPS)
    }
    pub fn warmup_obs(&self) -> u16 {
        u16_at(&self.0, bp::WARMUP_OBS)
    }
    pub fn buy_min_interval_s(&self) -> u32 {
        u32_at(&self.0, bp::BUY_MIN_INTERVAL_S)
    }
    pub fn obs_max_age_s(&self) -> u32 {
        u32_at(&self.0, bp::OBS_MAX_AGE_S)
    }
    pub fn chunk_max_quote(&self) -> u64 {
        u64_at(&self.0, bp::CHUNK_MAX_QUOTE)
    }
    pub fn chunk_min_quote(&self) -> u64 {
        u64_at(&self.0, bp::CHUNK_MIN_QUOTE)
    }
    pub fn swap_max_usdc(&self) -> u64 {
        u64_at(&self.0, bp::SWAP_MAX_USDC)
    }
    pub fn sol_budget_cap(&self) -> u64 {
        u64_at(&self.0, bp::SOL_BUDGET_CAP)
    }
    pub fn swap_min_interval_s(&self) -> u32 {
        u32_at(&self.0, bp::SWAP_MIN_INTERVAL_S)
    }
}

pub fn put_u16(p: &mut [u8; 80], off: usize, v: u16) {
    p[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
pub fn put_u32(p: &mut [u8; 80], off: usize, v: u32) {
    p[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
pub fn put_u64(p: &mut [u8; 80], off: usize, v: u64) {
    p[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

// ------------------------------------------------------- instructions ----

pub fn cu_limit(units: u32) -> Instruction {
    let mut d = vec![2u8];
    d.extend_from_slice(&units.to_le_bytes());
    Instruction { program_id: compute_budget_program(), accounts: vec![], data: d }
}

pub fn create_ata_ix(payer: &Pubkey, owner: &Pubkey, mint: &Pubkey, token_program: &Pubkey) -> Instruction {
    Instruction {
        program_id: pk(c::ATA_PROGRAM_ID),
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(ata(owner, token_program, mint), false),
            AccountMeta::new_readonly(*owner, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(system(), false),
            AccountMeta::new_readonly(*token_program, false),
        ],
        data: vec![1],
    }
}

pub fn system_transfer_ix(from: &Pubkey, to: &Pubkey, lamports: u64) -> Instruction {
    let mut d = vec![2, 0, 0, 0];
    d.extend_from_slice(&lamports.to_le_bytes());
    Instruction {
        program_id: system(),
        accounts: vec![AccountMeta::new(*from, true), AccountMeta::new(*to, false)],
        data: d,
    }
}

pub fn sync_native_ix(account: &Pubkey) -> Instruction {
    Instruction { program_id: tokenkeg(), accounts: vec![AccountMeta::new(*account, false)], data: vec![17] }
}

/// SPL Memo v2 is not loaded; a System transfer of 0 lamports stands in for
/// "any other instruction" in the same transaction.
pub fn foreign_ix(from: &Pubkey) -> Instruction {
    system_transfer_ix(from, from, 0)
}

/// `price_x64(q, b) = (q << 64) / b` (SPEC §5.5.2).
pub fn price_x64(q: u64, b: u64) -> u128 {
    (u128::from(q) << 64) / u128::from(b)
}
