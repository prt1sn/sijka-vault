// Copyright (c) 2026 prt1sn. All rights reserved.
//! Host tests of the buyback instruction flows (tags 40–46) on `TestAccount`s:
//! everything up to each CPI runs on the host (pinocchio's CPI is a no-op
//! there, so a fully valid chunk stops right after the CPI at `bought ≥
//! min_out`). The end-to-end behaviour with the real pump / Jupiter programs is
//! covered by the LiteSVM tests (SPEC §9.7, TD-*).

use pinocchio::ProgramResult;
use pinocchio::account_info::AccountInfo;
use pinocchio::program_error::ProgramError;
use pinocchio::pubkey::Pubkey;
use solana_pubkey::Pubkey as SPubkey;

use crate::buyback::default_params;
use crate::buyback::math::price_x64;
use crate::constants::*;
use crate::error::SijkaError;
use crate::external::pump_accounts::PoolPins;
use crate::external::pump_accounts::tests::{curve_bytes, pool_bytes, token_bytes};
use crate::instructions::buyback::{
    Env, bb_burn_with, bb_chunk_with, bb_init_with, bb_observe_with, bb_pin_with, bb_swap_with,
};
use crate::state::buyback_state::{BuybackState, BuybackStateMut, bb_flags, bb_venue, quote_kind};
use crate::state::config::{CONFIG_LEN, ConfigMut};
use crate::util::runtime::tests::build_sysvar;
use crate::util::test_utils::TestAccount;

const PROGRAM: Pubkey = [0x11; 32];
const ADMIN: Pubkey = [0xAD; 32];
/// `config.keeper`: the only signer of tags 43, 44 and 45 (SPEC v4).
const KEEPER: Pubkey = [0x4B; 32];
const STATE: Pubkey = [0xBB; 32];
const CONFIG: Pubkey = [0xCF; 32];
const K0: Pubkey = [0xB0; 32];
const K1: Pubkey = [0xB1; 32];
const K2: Pubkey = [0xB2; 32];
const USDC: Pubkey = [0x0C; 32];
const MINT: Pubkey = [0x5E; 32];
const T22: Pubkey = TOKEN_2022_PROGRAM_ID;
const SPL: Pubkey = SPL_TOKEN_PROGRAM_ID;
const RENT0: u64 = 890_880;
/// `Rent::minimum_balance(165)`: the temporary `bb_unwrap` of tag 43.
const RENT_TA: u64 = 2_039_280;
const SOL: u64 = 1_000_000_000;
/// Curve at pin time: vQ = 40 SOL, vT = 800M tokens (6 decimals).
const VQ: u64 = 40 * SOL;
const VT: u64 = 800_000_000_000_000;
const T0: i64 = 1_000_000;
const S0: u64 = 100;

fn pda(seeds: &[&[u8]], program: &Pubkey) -> Pubkey {
    SPubkey::find_program_address(seeds, &SPubkey::new_from_array(*program)).0.to_bytes()
}

fn ata(owner: &Pubkey, tp: &Pubkey, mint: &Pubkey) -> Pubkey {
    pda(&[owner, tp, mint], &ATA_PROGRAM_ID)
}

/// k0–k26 derived independently (literal seeds, `solana-pubkey`), TU-D10.
fn keys(sol: bool) -> [Pubkey; 27] {
    let q = if sol { WSOL_MINT } else { USDC };
    let mut k = [[0u8; 32]; 27];
    k[0] = K0;
    k[1] = K1;
    k[2] = K2;
    k[3] = ata(&K0, &SPL, &USDC);
    k[4] = ata(&K1, &SPL, &USDC);
    k[5] = if sol { ata(&K0, &SPL, &WSOL_MINT) } else { [0; 32] };
    k[6] = MINT;
    k[7] = T22;
    k[8] = q;
    k[9] = ata(&K0, &T22, &MINT);
    k[10] = if sol { k[5] } else { k[3] };
    k[11] = pda(&[b"bonding-curve", &MINT], &PUMP_PROGRAM);
    k[12] = ata(&k[11], &T22, &MINT);
    k[13] = ata(&k[11], &SPL, &q);
    k[14] = pda(&[b"sharing-config", &MINT], &PUMP_FEES_PROGRAM);
    k[15] = pda(&[b"creator-vault", &k[14]], &PUMP_PROGRAM);
    k[16] = ata(&k[15], &SPL, &q);
    k[17] = pda(&[b"user_volume_accumulator", &K0], &PUMP_PROGRAM);
    k[18] = ata(&k[17], &SPL, &q);
    k[19] = pda(&[b"pool-authority", &MINT], &PUMP_PROGRAM);
    k[20] = pda(&[b"pool", &[0, 0], &k[19], &MINT, &q], &PUMP_AMM_PROGRAM);
    k[21] = ata(&k[20], &T22, &MINT);
    k[22] = ata(&k[20], &SPL, &q);
    k[23] = pda(&[b"creator_vault", &k[14]], &PUMP_AMM_PROGRAM);
    k[24] = ata(&k[23], &SPL, &q);
    k[25] = pda(&[b"user_volume_accumulator", &K0], &PUMP_AMM_PROGRAM);
    k[26] = pda(&[b"pool-v2", &MINT], &PUMP_AMM_PROGRAM);
    k
}

fn config_bytes(sol: bool, k: &[Pubkey; 27]) -> Vec<u8> {
    let mut b = vec![0u8; CONFIG_LEN];
    let mut m = ConfigMut::new(&mut b).unwrap();
    m.set_discriminator(&DISC_CONFIG);
    m.set_version(1);
    m.set_admin(&ADMIN);
    m.set_keeper(&KEEPER);
    m.set_quote_mint(if sol { &WSOL_MINT } else { &USDC });
    m.set_usdc_mint(&USDC);
    m.set_token_mint(&MINT);
    m.set_token_program(&T22);
    m.set_token_decimals(6);
    m.set_buyback_state(&STATE);
    m.set_buyback_authority(&K0);
    m.set_swap_authority(&K1);
    m.set_bb_unwrap(&K2);
    m.set_buyback_usdc(&k[3]);
    m.set_swap_usdc(&k[4]);
    m.set_buyback_token(&k[9]);
    m.set_buyback_state_bump(254);
    m.set_buyback_authority_bump(253);
    m.set_swap_authority_bump(252);
    m.set_bb_unwrap_bump(251);
    b
}

/// `BuybackState` as tag 40 writes it (tag 40 needs the Rent sysvar, which the
/// host does not have).
fn state_bytes(sol: bool, k: &[Pubkey; 27]) -> Vec<u8> {
    let mut b = vec![0u8; BUYBACK_STATE_LEN];
    let mut m = BuybackStateMut::new(&mut b).unwrap();
    let kind = if sol { quote_kind::SOL } else { quote_kind::USDC };
    m.set_discriminator(&DISC_BUYBACK_STATE);
    m.set_version(1);
    m.set_quote_kind(kind);
    m.set_bump_buyback_state(254);
    m.set_bump_buyback_authority(253);
    m.set_bump_swap_authority(252);
    m.set_bump_bb_unwrap(251);
    m.set_params(&default_params(kind));
    for (i, key) in k.iter().enumerate().take(6) {
        assert!(m.set_pinned(i, key));
    }
    m.set_usdc_mint(&USDC);
    b
}

fn acct(key: Pubkey, owner: Pubkey, data: &[u8], writable: bool) -> TestAccount {
    TestAccount::new(key, owner, 2_039_280, data, false, writable, false)
}

fn prog(key: Pubkey) -> TestAccount {
    TestAccount::new(key, [0x99; 32], 1, &[], false, false, true)
}

fn missing(key: Pubkey) -> TestAccount {
    TestAccount::new(key, SYSTEM_PROGRAM_ID, 0, &[], false, true, false)
}

/// The keeper as the fee payer: signer and writable.
fn keeper() -> TestAccount {
    TestAccount::new(KEEPER, SYSTEM_PROGRAM_ID, SOL, &[], true, true, false)
}

/// Signers that are not the keeper, and the keeper without its signature.
fn not_keepers() -> Vec<(&'static str, TestAccount)> {
    vec![
        ("unsigned keeper", TestAccount::new(KEEPER, SYSTEM_PROGRAM_ID, SOL, &[], false, true, false)),
        ("admin", TestAccount::new(ADMIN, SYSTEM_PROGRAM_ID, SOL, &[], true, true, false)),
        ("stranger", TestAccount::new([0x99; 32], SYSTEM_PROGRAM_ID, SOL, &[], true, true, false)),
        ("zero key", TestAccount::new([0; 32], SYSTEM_PROGRAM_ID, SOL, &[], true, true, false)),
    ]
}

fn sysvar(tag: u8) -> TestAccount {
    TestAccount::plain(INSTRUCTIONS_SYSVAR, [0x5F; 32], &build_sysvar(&[(PROGRAM, vec![tag])], 0))
}

fn infos_of(a: &[&TestAccount]) -> Vec<AccountInfo> {
    a.iter().map(|t| t.info()).collect()
}

fn set_config(w: &mut World, f: impl FnOnce(&mut ConfigMut<'_>)) {
    let mut m = ConfigMut::new(w.config.data_mut()).unwrap();
    f(&mut m);
}

/// Shared accounts of one vault.
struct World {
    sol: bool,
    k: [Pubkey; 27],
    state: TestAccount,
    config: TestAccount,
    curve: TestAccount,
    pool: TestAccount,
    pool_base: TestAccount,
    pool_quote: TestAccount,
    now: i64,
    slot: u64,
}

impl World {
    fn new(sol: bool) -> Self {
        let k = keys(sol);
        let mut curve = curve_bytes(VT, VQ, VT - 279_900_000_000_000, &k[14]);
        if !sol {
            curve[83..115].copy_from_slice(&USDC);
        }
        World {
            sol,
            state: acct(STATE, PROGRAM, &state_bytes(sol, &k), true),
            config: acct(CONFIG, PROGRAM, &config_bytes(sol, &k), true),
            curve: acct(k[11], PUMP_PROGRAM, &curve, true),
            pool: missing(k[20]),
            pool_base: missing(k[21]),
            pool_quote: missing(k[22]),
            k,
            now: T0,
            slot: S0,
        }
    }

    fn env(&self) -> Env {
        Env { now: self.now, slot: self.slot }
    }

    fn pin(&self) -> ProgramResult {
        let mint = acct(MINT, T22, &[0; 82], false);
        bb_pin_with(
            &PROGRAM,
            &infos_of(&[&self.state, &self.config, &mint, &self.curve, &self.pool, &self.pool_base, &self.pool_quote]),
            self.env(),
        )
    }

    fn observe(&self) -> ProgramResult {
        let sv = sysvar(42);
        bb_observe_with(
            &PROGRAM,
            &infos_of(&[&self.state, &sv, &self.curve, &self.pool, &self.pool_base, &self.pool_quote]),
            self.env(),
        )
    }

    /// `n` observations 15 s / 1 slot apart, starting at the current clock.
    fn warm(&mut self, n: usize) {
        for i in 0..n {
            if i > 0 {
                self.now += 15;
                self.slot += 1;
            }
            self.observe().unwrap();
        }
    }

    /// Complete the curve and create the canonical pool with effective quote
    /// `q` and base `b`.
    fn graduate(&mut self, q: u64, b: u64, coin_creator: &Pubkey) {
        self.curve.data_mut()[48] = 1;
        let pins = PoolPins {
            pool_authority: &self.k[19],
            mint: &MINT,
            base_token_program: &T22,
            quote_mint: &self.k[8],
            base_ta: &self.k[21],
            quote_ta: &self.k[22],
            sharing_config: &self.k[14],
        };
        self.pool = acct(self.k[20], PUMP_AMM_PROGRAM, &pool_bytes(&pins, coin_creator, 0), true);
        self.pool_base = acct(self.k[21], T22, &token_bytes(&MINT, &self.k[20], b, false), true);
        self.pool_quote = acct(self.k[22], SPL, &token_bytes(&self.k[8], &self.k[20], q, self.sol), true);
    }

    /// Synthetic post-v2-trade accounting: fees stay in the vault but are
    /// excluded from effective liquidity by negative virtual quote reserves.
    fn retain_pool_fees(&mut self, protocol_fees: u64, creator_fees: u64) {
        let fees = protocol_fees + creator_fees;
        let mut pool = self.pool.data_mut().to_vec();
        pool.resize(287, 0);
        pool[245..261].copy_from_slice(&(-i128::from(fees)).to_le_bytes());
        pool[271..279].copy_from_slice(&protocol_fees.to_le_bytes());
        pool[279..287].copy_from_slice(&creator_fees.to_le_bytes());
        self.pool = acct(self.k[20], PUMP_AMM_PROGRAM, &pool, true);
        let quote = u64::from_le_bytes(self.pool_quote.data_mut()[64..72].try_into().unwrap());
        self.pool_quote.data_mut()[64..72].copy_from_slice(&(quote + fees).to_le_bytes());
    }

    fn state(&mut self) -> BuybackState<'_> {
        BuybackState::new(self.state.data_mut()).unwrap()
    }
}

// ------------------------------------------------------------- tag 41

#[test]
fn pin_derives_every_key_on_chain() {
    for sol in [true, false] {
        let mut w = World::new(sol);
        w.pin().unwrap();
        let k = w.k;
        let s = w.state();
        for (i, want) in k.iter().enumerate() {
            assert_eq!(
                s.pinned(i).unwrap(),
                want,
                "sol {sol} k{i} ({})",
                crate::state::buyback_state::pinned::NAMES[i]
            );
        }
        assert!(s.is_pinned());
        assert_eq!(s.flags() & bb_flags::OBS_INIT, 0);
        assert_eq!((s.venue(), s.base_decimals(), s.base_tp_kind(), s.venue_since_slot()), (bb_venue::CURVE, 6, 2, S0));
        // Once only.
        assert_eq!(w.pin(), Err(SijkaError::BbAlreadyPinned.into()));
    }
}

#[test]
fn pin_rejections() {
    // Mint not set (TD-4).
    let mut w = World::new(true);
    set_config(&mut w, |m| m.set_token_mint(&[0; 32]));
    assert_eq!(w.pin(), Err(SijkaError::BbMintNotSet.into()));
    // Strict coin checks: creator is the sharing config (TD-5), no holder rewards.
    let mut w = World::new(true);
    w.curve.data_mut()[49..81].copy_from_slice(&[0x77; 32]);
    assert_eq!(w.pin(), Err(SijkaError::BbCreatorNotSharing.into()));
    let mut w = World::new(true);
    w.curve.data_mut()[124] = 1;
    assert_eq!(w.pin(), Err(SijkaError::BbCoinFlagsUnexpected.into()));
    // USDC quote field on a SOL-pair vault.
    let mut w = World::new(true);
    w.curve.data_mut()[83..115].copy_from_slice(&USDC);
    assert_eq!(w.pin(), Err(SijkaError::BbWrongQuote.into()));
    // A curve at another address.
    let mut w = World::new(true);
    w.curve = acct([0x42; 32], PUMP_PROGRAM, &curve_bytes(VT, VQ, 1, &w.k[14]), true);
    assert_eq!(w.pin(), Err(SijkaError::BbPinnedAccountMismatch.into()));
    // buyback_token in Config differs from the derived ATA.
    let mut w = World::new(true);
    set_config(&mut w, |m| m.set_buyback_token(&[0x42; 32]));
    assert_eq!(w.pin(), Err(SijkaError::BbPinnedAccountMismatch.into()));
    // Complete curve without a pool: retry later (TD-34).
    let mut w = World::new(true);
    w.curve.data_mut()[48] = 1;
    assert_eq!(w.pin(), Err(SijkaError::BbPoolNotReady.into()));
    // Complete curve with the canonical pool: AMM right away.
    let mut w = World::new(true);
    let sc = w.k[14];
    w.graduate(VQ, VT, &sc);
    w.pin().unwrap();
    assert_eq!(w.state().venue(), bb_venue::AMM);
    // A pool after a CTO fails the strict check → not ready.
    let mut w = World::new(true);
    w.graduate(VQ, VT, &[0x77; 32]);
    assert_eq!(w.pin(), Err(SijkaError::BbPoolNotReady.into()));
}

// ------------------------------------------------------------- tag 42

#[test]
fn observe_first_rate_limit_and_gap() {
    let mut w = World::new(true);
    assert_eq!(w.observe(), Err(SijkaError::BbNotPinned.into()));
    w.pin().unwrap();
    w.observe().unwrap();
    let p = price_x64(VQ, VT).unwrap();
    {
        let s = w.state();
        assert_eq!((s.ema_price_x64(), s.q_ema(), s.fresh_obs(), s.n_obs()), (p, VQ, 1, 1));
        assert_ne!(s.flags() & bb_flags::OBS_INIT, 0);
    }
    // < 15 s, or the same slot (TD-8).
    w.now += 14;
    w.slot += 1;
    assert_eq!(w.observe(), Err(SijkaError::BbObserveTooSoon.into()));
    w.now += 1;
    w.slot -= 1;
    assert_eq!(w.observe(), Err(SijkaError::BbObserveTooSoon.into()));
    w.slot += 1;
    w.observe().unwrap();
    assert_eq!(w.state().fresh_obs(), 2);
    // A gap > 120 s restarts the warm-up counter, the EMA stays (TD-10).
    w.now += 121;
    w.slot += 1;
    w.observe().unwrap();
    assert_eq!((w.state().fresh_obs(), w.state().ema_price_x64()), (1, p));
}

#[test]
fn observe_price_spike_is_clamped() {
    // TD-9: "the market" triples the price: the EMA moves ≤ 0.25% per 15 s.
    let mut w = World::new(true);
    w.pin().unwrap();
    w.warm(40);
    let before = w.state().ema_price_x64();
    w.curve.data_mut()[16..24].copy_from_slice(&(3 * VQ).to_le_bytes());
    w.now += 15;
    w.slot += 1;
    w.observe().unwrap();
    let after = w.state().ema_price_x64();
    assert!(after > before && after <= before + before / 400);
}

#[test]
fn observe_rejects_foreign_instruction_and_wrong_accounts() {
    let mut w = World::new(true);
    w.pin().unwrap();
    let run = |sv: &TestAccount, curve: &TestAccount, w: &World| {
        bb_observe_with(&PROGRAM, &infos_of(&[&w.state, sv, curve, &w.pool, &w.pool_base, &w.pool_quote]), w.env())
    };
    // TD-11: another program's instruction in the same transaction.
    let bad = TestAccount::plain(
        INSTRUCTIONS_SYSVAR,
        [0x5F; 32],
        &build_sysvar(&[(PUMP_PROGRAM, vec![1]), (PROGRAM, vec![42])], 1),
    );
    assert_eq!(run(&bad, &w.curve, &w), Err(SijkaError::ForeignInstruction.into()));
    // TD-13: another curve.
    let other = acct([0x42; 32], PUMP_PROGRAM, &curve_bytes(VT, VQ, 1, &w.k[14]), false);
    assert_eq!(run(&sysvar(42), &other, &w), Err(SijkaError::BbPinnedAccountMismatch.into()));
    // The current instruction must be tag 42 of this program.
    assert_eq!(run(&sysvar(44), &w.curve, &w), Err(SijkaError::NotTopLevel.into()));
    // Wrong sysvar key.
    let fake = TestAccount::plain([0x42; 32], [0x5F; 32], &build_sysvar(&[(PROGRAM, vec![42])], 0));
    assert_eq!(run(&fake, &w.curve, &w), Err(SijkaError::InvalidExternalAccount.into()));
    // Read-only state.
    let ro = acct(STATE, PROGRAM, &state_bytes(true, &w.k), false);
    let sv = sysvar(42);
    assert_eq!(
        bb_observe_with(&PROGRAM, &infos_of(&[&ro, &sv, &w.curve, &w.pool, &w.pool_base, &w.pool_quote]), w.env()),
        Err(SijkaError::AccountNotWritable.into())
    );
    w.now += 1;
}

#[test]
fn observe_switches_venue_and_keeps_ema() {
    // TD-33 / TD-68: the switch keeps OBS_INIT and the EMA, Q_ema ≤ pool Q, a
    // new warm-up starts, and a ×2 pool price moves the EMA only by the clamp.
    let mut w = World::new(true);
    w.pin().unwrap();
    w.warm(40);
    let ema_before = w.state().ema_price_x64();
    assert_eq!(w.state().fresh_obs(), 40);
    // Complete without the pool: not ready, nothing changes.
    w.curve.data_mut()[48] = 1;
    w.now += 15;
    w.slot += 1;
    assert_eq!(w.observe(), Err(SijkaError::BbPoolNotReady.into()));
    assert_eq!(w.state().venue(), bb_venue::CURVE);
    // Pool at twice the price with a smaller Q.
    let sc = w.k[14];
    w.graduate(VQ / 2, VT / 4, &sc);
    w.observe().unwrap();
    let slot = w.slot;
    let s = w.state();
    assert_eq!((s.venue(), s.venue_since_slot()), (bb_venue::AMM, slot));
    assert_ne!(s.flags() & bb_flags::OBS_INIT, 0);
    assert_eq!(s.fresh_obs(), 1);
    assert!(s.q_ema() <= VQ / 2);
    let ema = s.ema_price_x64();
    assert!(ema > ema_before && ema <= ema_before + ema_before / 400, "EMA rises by ≤ 0.25%");
}

#[test]
fn observe_after_cto_pool_uses_working_mode() {
    // TD-62: coin_creator ≠ sharing_config after a CTO still switches.
    let mut w = World::new(true);
    w.pin().unwrap();
    w.observe().unwrap();
    w.graduate(VQ, VT, &[0x77; 32]);
    w.now += 15;
    w.slot += 1;
    w.observe().unwrap();
    assert_eq!(w.state().venue(), bb_venue::AMM);
    // A zero coin_creator is refused.
    let mut w = World::new(true);
    w.pin().unwrap();
    w.graduate(VQ, VT, &[0; 32]);
    assert_eq!(w.observe(), Err(SijkaError::BbPoolNotReady.into()));
}

#[test]
fn observe_is_permissionless_and_ignores_retired_bytes() {
    // SPEC v4: no buyback pause; the former `pause_until@24` byte is ignored,
    // and no keeper is needed (tag 42 has no signer).
    let mut w = World::new(true);
    w.pin().unwrap();
    BuybackStateMut::new(w.state.data_mut()).unwrap().bytes_mut()[24..32].copy_from_slice(&[0xFF; 8]);
    set_config(&mut w, |m| m.set_keeper(&[0; 32]));
    w.observe().unwrap();
}

// ---------------------------------------------------------- tags 44, 45

const FEE_RECIPIENT: Pubkey = [0xF1; 32];

/// The 32 accounts of tag 44; `a` holds all but the shared state (0), config
/// (1) and curve (14). The keeper signer is the last one (#31, SPEC v4).
struct CurveChunk {
    a: Vec<TestAccount>,
}

impl CurveChunk {
    fn new(w: &World, user_lamports: u64) -> Self {
        let k = &w.k;
        let quote =
            if w.sol { missing(k[10]) } else { acct(k[10], SPL, &token_bytes(&USDC, &K0, 500_000_000, false), true) };
        let a = vec![
            sysvar(44),
            TestAccount::plain(JITO_DONT_FRONT, SYSTEM_PROGRAM_ID, &[]),
            TestAccount::plain(PUMP_GLOBAL, PUMP_PROGRAM, &[]),
            acct(MINT, T22, &[0; 82], true),
            TestAccount::plain(k[8], SPL, &[]),
            prog(T22),
            prog(SPL),
            prog(ATA_PROGRAM_ID),
            acct(FEE_RECIPIENT, SYSTEM_PROGRAM_ID, &[], true),
            acct([0xF2; 32], SYSTEM_PROGRAM_ID, &[], true),
            acct([0xF3; 32], SYSTEM_PROGRAM_ID, &[], true),
            acct([0xF4; 32], SYSTEM_PROGRAM_ID, &[], true),
            acct(k[12], T22, &[], true),
            acct(k[13], SYSTEM_PROGRAM_ID, &[], true),
            TestAccount::new(K0, SYSTEM_PROGRAM_ID, user_lamports, &[], false, true, false),
            acct(k[9], T22, &token_bytes(&MINT, &K0, 0, false), true),
            quote,
            acct(k[15], SYSTEM_PROGRAM_ID, &[], true),
            acct(k[16], SYSTEM_PROGRAM_ID, &[], true),
            TestAccount::plain(k[14], PUMP_FEES_PROGRAM, &[]),
            TestAccount::plain(PUMP_GVA, PUMP_PROGRAM, &[]),
            acct(k[17], PUMP_PROGRAM, &[], true),
            acct(k[18], SYSTEM_PROGRAM_ID, &[], true),
            TestAccount::plain(PUMP_FEE_CONFIG, PUMP_FEES_PROGRAM, &[]),
            prog(PUMP_FEES_PROGRAM),
            prog(SYSTEM_PROGRAM_ID),
            TestAccount::plain(PUMP_EVENT_AUTHORITY, SYSTEM_PROGRAM_ID, &[]),
            prog(PUMP_PROGRAM),
            keeper(),
        ];
        Self { a }
    }

    /// Outer index → position in `a`.
    fn pos(outer: usize) -> usize {
        match outer {
            2..=13 => outer - 2,
            15..=31 => outer - 3,
            _ => panic!("shared account {outer}"),
        }
    }

    fn set(&mut self, outer: usize, t: TestAccount) {
        self.a[Self::pos(outer)] = t;
    }

    fn run_with(&self, w: &World, max_quote_in: u64, min_out: u64) -> ProgramResult {
        let mut v: Vec<AccountInfo> = vec![w.state.info(), w.config.info()];
        v.extend(self.a[..12].iter().map(|t| t.info()));
        v.push(w.curve.info());
        v.extend(self.a[12..].iter().map(|t| t.info()));
        assert_eq!(v.len(), 32);
        bb_chunk_with(&PROGRAM, &v, &chunk_data(44, max_quote_in, min_out), w.env(), RENT0, false)
    }

    /// The keeper's floor 1 (the host CPI buys nothing, so any floor ≥ 1
    /// ends at the post-CPI `bought ≥ min_out` check).
    fn run(&self, w: &World) -> ProgramResult {
        self.run_with(w, 0, 1)
    }
}

fn chunk_data(tag: u8, max_quote_in: u64, min_out: u64) -> Vec<u8> {
    let mut d = vec![tag];
    d.extend_from_slice(&max_quote_in.to_le_bytes());
    d.extend_from_slice(&min_out.to_le_bytes());
    d
}

/// A pinned, warm vault, one slot and 5 s after its last observation.
fn warm_curve(sol: bool) -> World {
    let mut w = World::new(sol);
    w.pin().unwrap();
    w.warm(40);
    w.now += 5;
    w.slot += 1;
    w
}

#[test]
fn curve_chunk_reaches_the_pump_cpi() {
    // The host CPI is a no-op, so a valid chunk stops right after it at
    // `bought ≥ min_out`: every check before the CPI passed.
    let w = warm_curve(true);
    assert_eq!(CurveChunk::new(&w, 10 * SOL).run(&w), Err(SijkaError::BbSlippage.into()));
    let w = warm_curve(false);
    assert_eq!(CurveChunk::new(&w, SOL).run(&w), Err(SijkaError::BbSlippage.into()));
    // The caller may shrink the chunk down to chunk_min_quote but not below.
    let w = warm_curve(true);
    let c = CurveChunk::new(&w, 10 * SOL);
    assert_eq!(c.run_with(&w, 10_000_000, 1), Err(SijkaError::BbSlippage.into()));
    assert_eq!(c.run_with(&w, 9_999_999, 1), Err(SijkaError::BbChunkBelowMin.into()));
    // SPEC v4 (DECISIONS §23 item 6, TD-29): the keeper's floor is passed to
    // pump as is, even one pump cannot give; no program-side floor or early
    // check from the pump fees.
    assert_eq!(c.run_with(&w, 0, u64::MAX), Err(SijkaError::BbSlippage.into()));
    // A keeper floor of zero is not a floor (SPEC v4).
    assert_eq!(c.run_with(&w, 0, 0), Err(SijkaError::InvalidInstructionData.into()));
}

/// SPEC v4 (DECISIONS §23 item 3): tags 44 and 45 are keeper-signed. Any
/// other signer, the keeper without its signature, and `keeper == 0` are
/// refused before anything else is read; after `set_keeper` the old key fails.
#[test]
fn chunks_only_by_the_keeper() {
    let e = Err(SijkaError::UnauthorizedKeeper.into());
    let w = warm_curve(true);
    for (name, k) in not_keepers() {
        let mut c = CurveChunk::new(&w, 10 * SOL);
        c.set(31, k);
        assert_eq!(c.run(&w), e, "curve, {name}");
        // Even with a missing dont-front account the keeper check decides first.
        c.set(3, TestAccount::plain([0x33; 32], SYSTEM_PROGRAM_ID, &[]));
        assert_eq!(c.run(&w), e, "curve junk, {name}");
    }
    let a = warm_amm(true);
    for (name, k) in not_keepers() {
        let mut v = amm_accounts(&a, 10 * SOL, SOL);
        *v.last_mut().unwrap() = k;
        assert_eq!(run_amm(&a, &v), e, "amm, {name}");
    }
    // keeper == 0: chunks are off for everybody.
    let mut w0 = warm_curve(true);
    set_config(&mut w0, |m| m.set_keeper(&[0; 32]));
    assert_eq!(CurveChunk::new(&w0, 10 * SOL).run(&w0), e);
    // Rotation: the old keeper is refused, the new one passes.
    let mut w1 = warm_curve(true);
    set_config(&mut w1, |m| m.set_keeper(&[0x4C; 32]));
    assert_eq!(CurveChunk::new(&w1, 10 * SOL).run(&w1), e);
    let mut c = CurveChunk::new(&w1, 10 * SOL);
    c.set(31, TestAccount::new([0x4C; 32], SYSTEM_PROGRAM_ID, SOL, &[], true, false, false));
    assert_eq!(c.run(&w1), Err(SijkaError::BbSlippage.into()));
}

#[test]
fn curve_chunk_account_checks() {
    let w = warm_curve(true);
    let k = w.k;
    let mut dirty = token_bytes(&MINT, &K0, 0, false);
    dirty[72] = 1;
    let cases: Vec<(usize, TestAccount, SijkaError)> = vec![
        (3, TestAccount::plain([0x33; 32], SYSTEM_PROGRAM_ID, &[]), SijkaError::BbMissingDontFront),
        // Pump-checked slots may not alias our accounts (buyback_usdc, config, bb_wsol).
        (10, acct(k[3], SPL, &[], true), SijkaError::BbPinnedAccountMismatch),
        (11, acct(CONFIG, PROGRAM, &[], true), SijkaError::BbPinnedAccountMismatch),
        (13, acct(k[5], SPL, &[], true), SijkaError::BbPinnedAccountMismatch),
        (12, acct(STATE, PROGRAM, &[], true), SijkaError::BbPinnedAccountMismatch),
        // Pinned slots and pump constants.
        (15, acct([0x42; 32], T22, &[], true), SijkaError::BbPinnedAccountMismatch),
        (18, acct([0x42; 32], T22, &token_bytes(&MINT, &K0, 0, false), true), SijkaError::BbPinnedAccountMismatch),
        (4, TestAccount::plain([0x42; 32], PUMP_PROGRAM, &[]), SijkaError::BbPinnedAccountMismatch),
        (22, TestAccount::plain([0x42; 32], PUMP_FEES_PROGRAM, &[]), SijkaError::BbPinnedAccountMismatch),
        // Writability required by the pump CPI.
        (15, acct(k[12], T22, &[], false), SijkaError::AccountNotWritable),
        (5, acct(MINT, T22, &[0; 82], false), SijkaError::AccountNotWritable),
        (
            17,
            TestAccount::new(K0, SYSTEM_PROGRAM_ID, 10 * SOL, &[], false, false, false),
            SijkaError::AccountNotWritable,
        ),
        // Programs must be executable.
        (30, TestAccount::plain(PUMP_PROGRAM, [0; 32], &[]), SijkaError::InvalidProgramId),
        (7, TestAccount::plain(T22, [0; 32], &[]), SijkaError::InvalidProgramId),
        // Creator vault follows the live creator (k15 while creator == k14).
        (20, acct([0x42; 32], SYSTEM_PROGRAM_ID, &[], true), SijkaError::BbPinnedAccountMismatch),
        (21, acct([0x42; 32], SYSTEM_PROGRAM_ID, &[], true), SijkaError::BbPinnedAccountMismatch),
        // Our SIJKA account must exist and be clean.
        (18, missing(k[9]), SijkaError::BbBaseAtaMissing),
        (18, acct(k[9], T22, &dirty, true), SijkaError::InvalidTokenAccount),
        // buyback_authority must be a clean System account.
        (17, TestAccount::new(K0, [3; 32], 10 * SOL, &[], false, true, false), SijkaError::InvalidExternalAccount),
        // bb_wsol on the SOL curve: if it exists, it must be clean.
        (19, acct(k[5], SPL, &dirty, true), SijkaError::InvalidTokenAccount),
        // Base mint under another program.
        (5, acct(MINT, SPL, &[0; 82], true), SijkaError::InvalidTokenMint),
        // A foreign instruction in the transaction (TD-21).
        (
            2,
            TestAccount::plain(
                INSTRUCTIONS_SYSVAR,
                [0x5F; 32],
                &build_sysvar(&[(PROGRAM, vec![44]), (PUMP_PROGRAM, vec![1])], 0),
            ),
            SijkaError::ForeignInstruction,
        ),
    ];
    for (outer, account, e) in cases {
        let mut c = CurveChunk::new(&w, 10 * SOL);
        c.set(outer, account);
        assert_eq!(c.run(&w), Err(e.into()), "outer {outer}");
    }
    // bb_wsol that exists and is clean is fine on the SOL curve.
    let mut c = CurveChunk::new(&w, 10 * SOL);
    c.set(19, acct(k[5], SPL, &token_bytes(&WSOL_MINT, &K0, 3, true), true));
    assert_eq!(c.run(&w), Err(SijkaError::BbSlippage.into()));
}

#[test]
fn curve_chunk_creator_vault_after_cto() {
    // TD-61: after a CTO the creator vault is derived from the live creator.
    let mut w = warm_curve(true);
    let x = [0x77u8; 32];
    w.curve.data_mut()[49..81].copy_from_slice(&x);
    w.curve.data_mut()[124] = 1; // holder rewards: not checked in working mode
    let mut c = CurveChunk::new(&w, 10 * SOL);
    assert_eq!(c.run(&w), Err(SijkaError::BbPinnedAccountMismatch.into()));
    let v = pda(&[b"creator-vault", &x], &PUMP_PROGRAM);
    c.set(20, acct(v, SYSTEM_PROGRAM_ID, &[], true));
    c.set(21, acct(ata(&v, &SPL, &WSOL_MINT), SYSTEM_PROGRAM_ID, &[], true));
    assert_eq!(c.run(&w), Err(SijkaError::BbSlippage.into()));
    // Mayhem and cashback are still refused.
    for off in [81usize, 82] {
        let mut w2 = warm_curve(true);
        w2.curve.data_mut()[49..81].copy_from_slice(&x);
        w2.curve.data_mut()[off] = 1;
        assert_eq!(c.run(&w2), Err(SijkaError::BbCoinFlagsUnexpected.into()), "offset {off}");
    }
    // SPEC v4 (DECISIONS §23 item 6, closes O-11): the coin's own
    // creator_fee_bps (@115) no longer stops the chunk; the run reaches the
    // pump CPI (a slippage failure of the host mock, as above).
    let mut w3 = warm_curve(true);
    w3.curve.data_mut()[49..81].copy_from_slice(&x);
    w3.curve.data_mut()[124] = 1;
    w3.curve.data_mut()[115..123].copy_from_slice(&300u64.to_le_bytes());
    assert_eq!(c.run(&w3), Err(SijkaError::BbSlippage.into()));
}

#[test]
fn curve_chunk_guards() {
    // Warm-up (TD-16).
    let mut w = World::new(true);
    w.pin().unwrap();
    w.warm(39);
    w.now += 5;
    w.slot += 1;
    assert_eq!(CurveChunk::new(&w, 10 * SOL).run(&w), Err(SijkaError::BbWarmup.into()));
    // Same slot as the observation (TD-18).
    let mut w = warm_curve(true);
    w.slot -= 1;
    assert_eq!(CurveChunk::new(&w, 10 * SOL).run(&w), Err(SijkaError::BbSameSlot.into()));
    // Stale observation (TD-17).
    let mut w = warm_curve(true);
    w.now += 200;
    assert_eq!(CurveChunk::new(&w, 10 * SOL).run(&w), Err(SijkaError::BbStaleObservation.into()));
    // SPEC v4 (TD-20): no spot guard. Spot pumped ×1.5 above the reference
    // after the last observation: the chunk still reaches the pump CPI with
    // the keeper's floor as is (the LiteSVM test TD-20 shows pump refusing a
    // floor quoted before the pump).
    let mut w = warm_curve(true);
    w.curve.data_mut()[16..24].copy_from_slice(&(VQ / 2 * 3).to_le_bytes());
    let c = CurveChunk::new(&w, 10 * SOL);
    for floor in [1u64, VT / 1_000, u64::MAX] {
        assert_eq!(c.run_with(&w, 0, floor), Err(SijkaError::BbSlippage.into()), "floor {floor}");
    }
    // Budget below chunk_min_quote: RESERVE is never spent (TD-26).
    let w = warm_curve(true);
    let low = RENT0 + MAX_RENT_EXTRA + 9_999_999;
    assert_eq!(CurveChunk::new(&w, low).run(&w), Err(SijkaError::BbChunkBelowMin.into()));
    assert_eq!(CurveChunk::new(&w, low + 1).run(&w), Err(SijkaError::BbSlippage.into()));
    // USDC pair: lamports below rent(0) (TD-31); below RESERVE is fine, pump
    // rent is bounded after the CPI (audit EA-1, TD-69).
    let w = warm_curve(false);
    assert_eq!(CurveChunk::new(&w, RENT0 - 1).run(&w), Err(SijkaError::BbFloatLow.into()));
    assert_eq!(CurveChunk::new(&w, RENT0).run(&w), Err(SijkaError::BbSlippage.into()));
    assert_eq!(CurveChunk::new(&w, RENT0 + MAX_RENT_EXTRA - 1).run(&w), Err(SijkaError::BbSlippage.into()));
    // USDC pair: buyback_usdc must exist.
    let w = warm_curve(false);
    let mut c = CurveChunk::new(&w, SOL);
    c.set(19, missing(w.k[10]));
    assert_eq!(c.run(&w), Err(SijkaError::BbQuoteAtaMissing.into()));
    // Complete curve: observe must switch first (TD-34).
    let mut w = warm_curve(true);
    w.curve.data_mut()[48] = 1;
    assert_eq!(CurveChunk::new(&w, 10 * SOL).run(&w), Err(SijkaError::BbVenueSwitchPending.into()));
    // Nothing left on the curve (TD-27, TD-63).
    let mut w = warm_curve(true);
    w.curve.data_mut()[24..32].copy_from_slice(&1_000u64.to_le_bytes());
    assert_eq!(CurveChunk::new(&w, 10 * SOL).run(&w), Err(SijkaError::BbCurveNearComplete.into()));
    // Cool-down (RT-6): `next_buy_ts` in the future, or the slot of the last chunk.
    let mut w = warm_curve(true);
    let (now, slot) = (w.now, w.slot);
    BuybackStateMut::new(w.state.data_mut()).unwrap().set_next_buy_ts(now + 1);
    assert_eq!(CurveChunk::new(&w, 10 * SOL).run(&w), Err(SijkaError::BbBuyTooSoon.into()));
    let mut m = BuybackStateMut::new(w.state.data_mut()).unwrap();
    m.set_next_buy_ts(now);
    m.set_last_buy_slot(slot);
    assert_eq!(CurveChunk::new(&w, 10 * SOL).run(&w), Err(SijkaError::BbBuyTooSoon.into()));
}

#[test]
fn curve_chunk_has_no_pause() {
    let mut w = warm_curve(true);
    // No buyback pause since SPEC v4 (TD-30): the former `pause_until@24` is ignored.
    BuybackStateMut::new(w.state.data_mut()).unwrap().bytes_mut()[24..32].copy_from_slice(&i64::MAX.to_le_bytes());
    assert_eq!(CurveChunk::new(&w, 10 * SOL).run(&w), Err(SijkaError::BbSlippage.into()));
    // No global admin pause since SPEC v2: the retired byte @10 is ignored.
    set_config(&mut w, |m| m.bytes_mut()[10] = 2);
    assert_eq!(CurveChunk::new(&w, 10 * SOL).run(&w), Err(SijkaError::BbSlippage.into()));
    // Recovery mode does not stop the buyback (SPEC §5.5).
    set_config(&mut w, |m| {
        m.bytes_mut()[10] = 0;
        m.set_recovery_mode(1);
    });
    assert_eq!(CurveChunk::new(&w, 10 * SOL).run(&w), Err(SijkaError::BbSlippage.into()));
}

/// The 31 accounts of tag 45 minus the shared ones (0 state, 1 config, 4 pool,
/// 11/12 pool vaults). The keeper signer is the last one (#30, SPEC v4).
fn amm_accounts(w: &World, user_lamports: u64, wsol: u64) -> Vec<TestAccount> {
    let k = &w.k;
    let quote = if w.sol {
        acct(k[10], SPL, &token_bytes(&WSOL_MINT, &K0, wsol, true), true)
    } else {
        acct(k[10], SPL, &token_bytes(&USDC, &K0, 500_000_000, false), true)
    };
    vec![
        sysvar(45),
        TestAccount::plain(JITO_DONT_FRONT, SYSTEM_PROGRAM_ID, &[]),
        TestAccount::new(K0, SYSTEM_PROGRAM_ID, user_lamports, &[], false, true, false),
        TestAccount::plain(AMM_GLOBAL_CONFIG, PUMP_AMM_PROGRAM, &[]),
        acct(MINT, T22, &[0; 82], true),
        TestAccount::plain(k[8], SPL, &[]),
        acct(k[9], T22, &token_bytes(&MINT, &K0, 0, false), true),
        quote,
        TestAccount::plain([0xF5; 32], SYSTEM_PROGRAM_ID, &[]),
        acct([0xF6; 32], SPL, &[], true),
        prog(T22),
        prog(SPL),
        prog(SYSTEM_PROGRAM_ID),
        prog(ATA_PROGRAM_ID),
        TestAccount::plain(AMM_EVENT_AUTHORITY, SYSTEM_PROGRAM_ID, &[]),
        prog(PUMP_AMM_PROGRAM),
        acct(k[24], SPL, &[], true),
        TestAccount::plain(k[23], SYSTEM_PROGRAM_ID, &[]),
        TestAccount::plain(AMM_GVA, PUMP_AMM_PROGRAM, &[]),
        acct(k[25], PUMP_AMM_PROGRAM, &[], true),
        TestAccount::plain(AMM_FEE_CONFIG, PUMP_FEES_PROGRAM, &[]),
        prog(PUMP_FEES_PROGRAM),
        TestAccount::plain(k[26], PUMP_AMM_PROGRAM, &[]),
        TestAccount::plain([0xF7; 32], SYSTEM_PROGRAM_ID, &[]),
        acct([0xF8; 32], SPL, &[], true),
        keeper(),
    ]
}

fn run_amm(w: &World, a: &[TestAccount]) -> ProgramResult {
    let mut v: Vec<AccountInfo> = vec![w.state.info(), w.config.info(), a[0].info(), a[1].info(), w.pool.info()];
    v.extend(a[2..8].iter().map(|t| t.info()));
    v.push(w.pool_base.info());
    v.push(w.pool_quote.info());
    v.extend(a[8..].iter().map(|t| t.info()));
    assert_eq!(v.len(), 31);
    bb_chunk_with(&PROGRAM, &v, &chunk_data(45, 0, 1), w.env(), RENT0, true)
}

fn warm_amm(sol: bool) -> World {
    let mut w = World::new(sol);
    let sc = w.k[14];
    w.graduate(VQ, VT, &sc);
    w.pin().unwrap();
    w.warm(40);
    w.now += 5;
    w.slot += 1;
    w
}

#[test]
fn amm_chunk_reaches_the_pump_cpi() {
    // bb_wsol already holds the chunk, so no wrap is needed; the host CPI is a no-op.
    let w = warm_amm(true);
    assert_eq!(run_amm(&w, &amm_accounts(&w, 10 * SOL, SOL)), Err(SijkaError::BbSlippage.into()));
    let w = warm_amm(false);
    assert_eq!(run_amm(&w, &amm_accounts(&w, SOL, 0)), Err(SijkaError::BbSlippage.into()));
}

#[test]
fn graduated_pin_observe_and_chunk_accept_retained_pool_fees() {
    for sol in [true, false] {
        let mut w = World::new(sol);
        let sc = w.k[14];
        w.graduate(VQ, VT, &sc);
        w.retain_pool_fees(SOL, SOL / 2);
        w.pin().unwrap();
        assert_eq!(w.state().venue(), bb_venue::AMM);
        w.warm(40);
        assert_eq!(w.state().last_obs_quote(), VQ, "retained fees are not liquidity");
        assert_eq!(w.state().q_ema(), VQ);
        assert_eq!(w.state().last_obs_price_x64(), price_x64(VQ, VT).unwrap());
        w.now += 5;
        w.slot += 1;
        // Host CPI does not buy tokens: BbSlippage proves reserve validation,
        // observation warm-up and chunk planning all reached the PumpSwap CPI.
        assert_eq!(run_amm(&w, &amm_accounts(&w, 10 * SOL, SOL)), Err(SijkaError::BbSlippage.into()));
    }
}

#[test]
fn curve_switch_accepts_negative_vqr_and_fee_sweep_preserves_price() {
    for sol in [true, false] {
        let mut w = World::new(sol);
        w.pin().unwrap();
        w.warm(40);
        let sc = w.k[14];
        w.graduate(VQ, VT, &sc);
        w.retain_pool_fees(SOL, SOL / 2);
        w.now += 15;
        w.slot += 1;
        w.observe().unwrap();
        assert_eq!(w.state().venue(), bb_venue::AMM);
        assert_eq!(w.state().fresh_obs(), 1);
        assert_eq!(w.state().last_obs_quote(), VQ);
        let price_before_sweep = w.state().last_obs_price_x64();
        assert_eq!(price_before_sweep, price_x64(VQ, VT).unwrap());
        w.now += 15;
        w.slot += 1;
        w.warm(39);
        w.now += 5;
        w.slot += 1;
        assert_eq!(run_amm(&w, &amm_accounts(&w, 10 * SOL, SOL)), Err(SijkaError::BbSlippage.into()));

        // Equivalent post-sweep state has the same effective reserves.
        w.pool.data_mut()[245..261].copy_from_slice(&0i128.to_le_bytes());
        w.pool.data_mut()[271..287].fill(0);
        w.pool_quote.data_mut()[64..72].copy_from_slice(&VQ.to_le_bytes());
        w.now += 15;
        w.slot += 1;
        w.observe().unwrap();
        assert_eq!(w.state().last_obs_quote(), VQ);
        assert_eq!(w.state().last_obs_price_x64(), price_before_sweep);
        assert_eq!(w.state().q_ema(), VQ);
    }
}

#[test]
fn amm_chunk_checks() {
    let w = warm_amm(true);
    // Venue mismatch both ways (TD-33).
    assert_eq!(CurveChunk::new(&w, 10 * SOL).run(&w), Err(SijkaError::BbVenueMismatch.into()));
    let c = warm_curve(true);
    assert_eq!(run_amm(&c, &amm_accounts(&c, 10 * SOL, SOL)), Err(SijkaError::BbVenueMismatch.into()));
    let with = |i: usize, t: TestAccount| {
        let mut a = amm_accounts(&w, 10 * SOL, SOL);
        a[i] = t;
        run_amm(&w, &a)
    };
    // bb_wsol must exist on PumpSwap.
    assert_eq!(with(7, missing(w.k[10])), Err(SijkaError::BbQuoteAtaMissing.into()));
    // r1 pool_v2 pinned; r3 writable; r2 / protocol fee slots may not alias our accounts.
    assert_eq!(
        with(22, TestAccount::plain([0x42; 32], PUMP_AMM_PROGRAM, &[])),
        Err(SijkaError::BbPinnedAccountMismatch.into())
    );
    assert_eq!(with(24, TestAccount::plain([0xF8; 32], SPL, &[])), Err(SijkaError::AccountNotWritable.into()));
    assert_eq!(with(23, TestAccount::plain(w.k[9], T22, &[])), Err(SijkaError::BbPinnedAccountMismatch.into()));
    assert_eq!(with(9, acct(w.k[3], SPL, &[], true)), Err(SijkaError::BbPinnedAccountMismatch.into()));
    // Coin creator vault must follow the live coin_creator (TD-62).
    assert_eq!(with(16, acct([0x42; 32], SPL, &[], true)), Err(SijkaError::BbPinnedAccountMismatch.into()));
    assert_eq!(
        with(17, TestAccount::plain([0x42; 32], SYSTEM_PROGRAM_ID, &[])),
        Err(SijkaError::BbPinnedAccountMismatch.into())
    );
    // Pool reserves moved far above the EMA after the observation: no spot
    // guard since SPEC v4, the chunk reaches the CPI.
    let mut w2 = warm_amm(true);
    w2.pool_quote.data_mut()[64..72].copy_from_slice(&(VQ * 2).to_le_bytes());
    assert_eq!(run_amm(&w2, &amm_accounts(&w2, 10 * SOL, SOL)), Err(SijkaError::BbSlippage.into()));
    // The keeper account is outside the pump block: a 30-account tag 45
    // (pre-v4 shape) is refused.
    let mut short = amm_accounts(&w, 10 * SOL, SOL);
    short.pop();
    let mut v: Vec<AccountInfo> =
        vec![w.state.info(), w.config.info(), short[0].info(), short[1].info(), w.pool.info()];
    v.extend(short[2..8].iter().map(|t| t.info()));
    v.push(w.pool_base.info());
    v.push(w.pool_quote.info());
    v.extend(short[8..].iter().map(|t| t.info()));
    assert_eq!(
        bb_chunk_with(&PROGRAM, &v, &chunk_data(45, 0, 1), w.env(), RENT0, true),
        Err(SijkaError::InvalidAccountCount.into())
    );
    // JIT deposit into the pool (TD-36): Q_ref stays at the observed Q.
    let mut w3 = warm_amm(true);
    w3.pool_quote.data_mut()[64..72].copy_from_slice(&(3 * VQ).to_le_bytes());
    w3.pool_base.data_mut()[64..72].copy_from_slice(&(3 * VT).to_le_bytes());
    assert_eq!(run_amm(&w3, &amm_accounts(&w3, 10 * SOL, SOL)), Err(SijkaError::BbSlippage.into()));
}

// ------------------------------------------------------------- tag 43

fn swap_accounts(w: &World, lamports: u64, usdc: u64, wsol: u64) -> Vec<TestAccount> {
    let k = &w.k;
    vec![
        sysvar(43),
        TestAccount::new(K0, SYSTEM_PROGRAM_ID, lamports, &[], false, true, false),
        acct(k[3], SPL, &token_bytes(&USDC, &K0, usdc, false), true),
        TestAccount::new(K1, SYSTEM_PROGRAM_ID, 0, &[], false, false, false),
        acct(k[4], SPL, &token_bytes(&USDC, &K1, 0, false), true),
        missing(K2),
        TestAccount::plain(WSOL_MINT, SPL, &[0; 82]),
        TestAccount::plain(USDC, SPL, &[0; 82]),
        prog(SPL),
        prog(SYSTEM_PROGRAM_ID),
        keeper(),
        prog(JUPITER_V6),
        acct(k[5], SPL, &token_bytes(&WSOL_MINT, &K0, wsol, true), false),
        TestAccount::plain([0x21; 32], SYSTEM_PROGRAM_ID, &[]),
    ]
}

fn run_swap(w: &World, a: &[TestAccount], amount_in: u64) -> ProgramResult {
    run_swap_min(w, a, amount_in, 1)
}

fn run_swap_min(w: &World, a: &[TestAccount], amount_in: u64, min_out: u64) -> ProgramResult {
    let mut v: Vec<AccountInfo> = vec![w.state.info(), w.config.info()];
    v.extend(a.iter().map(|t| t.info()));
    let mut d = vec![43u8];
    d.extend_from_slice(&amount_in.to_le_bytes());
    d.extend_from_slice(&min_out.to_le_bytes());
    d.extend_from_slice(&8u16.to_le_bytes());
    d.extend_from_slice(&[0u8; 8]);
    bb_swap_with(&PROGRAM, &v, &d, w.env(), RENT0, RENT_TA)
}

#[test]
fn swap_pre_route_checks() {
    let mut w = World::new(true);
    w.pin().unwrap();
    let usdc = 1_000_000_000;
    let ok = |w: &World| swap_accounts(w, SOL, usdc, 0);
    // All checks before the route pass; the zero route data is then refused by the Jupiter validator.
    assert_eq!(run_swap(&w, &ok(&w), usdc), Err(SijkaError::JupiterIxForbidden.into()));
    // Amount: 0, above the balance, above swap_max_usdc.
    assert_eq!(run_swap(&w, &ok(&w), 0), Err(SijkaError::BbSwapAmountInvalid.into()));
    assert_eq!(run_swap(&w, &ok(&w), usdc + 1), Err(SijkaError::BbSwapAmountInvalid.into()));
    assert_eq!(
        run_swap(&w, &swap_accounts(&w, SOL, 2 * usdc, 0), usdc + 1),
        Err(SijkaError::BbSwapAmountInvalid.into())
    );
    // SOL budget full; float below rent(0) + rent(165) (TD-47, audit EA-1).
    assert_eq!(run_swap(&w, &swap_accounts(&w, 25 * SOL, usdc, 0), usdc), Err(SijkaError::BbSolBudgetFull.into()));
    let float = RENT0 + RENT_TA;
    assert_eq!(run_swap(&w, &swap_accounts(&w, RENT0, usdc, 0), usdc), Err(SijkaError::BbFloatLow.into()));
    assert_eq!(run_swap(&w, &swap_accounts(&w, float - 1, usdc, 0), usdc), Err(SijkaError::BbFloatLow.into()));
    // TD-69 (EA-1): pump took rent out of RESERVE in the last chunk (k0 below
    // RESERVE, SOL budget 0): tag 43 still refills k0.
    assert_eq!(run_swap(&w, &swap_accounts(&w, float, usdc, 0), usdc), Err(SijkaError::JupiterIxForbidden.into()));
    let below = RENT0 + MAX_RENT_EXTRA - 1_000_000;
    assert_eq!(run_swap(&w, &swap_accounts(&w, below, usdc, 0), usdc), Err(SijkaError::JupiterIxForbidden.into()));
    // TD-64 / RT-7: wSOL on bb_wsol does not count on the curve.
    assert_eq!(run_swap(&w, &swap_accounts(&w, SOL, usdc, 25 * SOL), usdc), Err(SijkaError::JupiterIxForbidden.into()));
    let with = |i: usize, t: TestAccount| {
        let mut a = ok(&w);
        a[i] = t;
        run_swap(&w, &a, usdc)
    };
    assert_eq!(with(12, missing(w.k[5])), Err(SijkaError::BbQuoteAtaMissing.into()));
    // swap_authority read-only and data-less; buyback_usdc / swap_usdc clean (RT-1).
    assert_eq!(
        with(3, TestAccount::new(K1, SYSTEM_PROGRAM_ID, 0, &[], false, true, false)),
        Err(SijkaError::AccountMustBeReadonly.into())
    );
    assert_eq!(
        with(3, TestAccount::new(K1, [3; 32], 0, &[], false, false, false)),
        Err(SijkaError::InvalidExternalAccount.into())
    );
    let mut d = token_bytes(&USDC, &K0, usdc, false);
    d[72] = 1;
    assert_eq!(with(2, acct(w.k[3], SPL, &d, true)), Err(SijkaError::InvalidTokenAccount.into()));
    let mut d = token_bytes(&USDC, &K1, 0, false);
    d[129] = 1;
    assert_eq!(with(4, acct(w.k[4], SPL, &d, true)), Err(SijkaError::InvalidTokenAccount.into()));
    // Pinned keys and constants.
    assert_eq!(with(5, missing([0x42; 32])), Err(SijkaError::BbPinnedAccountMismatch.into()));
    assert_eq!(with(6, TestAccount::plain([0x42; 32], SPL, &[0; 82])), Err(SijkaError::InvalidExternalAccount.into()));
    assert_eq!(with(11, prog([0x42; 32])), Err(SijkaError::InvalidProgramId.into()));
    assert_eq!(
        with(1, TestAccount::new(K0, SYSTEM_PROGRAM_ID, SOL, &[], false, false, false)),
        Err(SijkaError::AccountNotWritable.into())
    );
    // The keeper's min_out: zero is refused (SPEC v4, no oracle floor).
    assert_eq!(run_swap_min(&w, &ok(&w), usdc, 0), Err(SijkaError::BbSwapAmountInvalid.into()));
    assert_eq!(run_swap_min(&w, &ok(&w), usdc, u64::MAX), Err(SijkaError::JupiterIxForbidden.into()));
    // Cool-down; no pause since SPEC v4 (the former `pause_until@24` is ignored).
    BuybackStateMut::new(w.state.data_mut()).unwrap().bytes_mut()[24..32].copy_from_slice(&i64::MAX.to_le_bytes());
    assert_eq!(run_swap(&w, &ok(&w), usdc), Err(SijkaError::JupiterIxForbidden.into()));
    BuybackStateMut::new(w.state.data_mut()).unwrap().set_next_swap_ts(T0 + 1);
    assert_eq!(run_swap(&w, &ok(&w), usdc), Err(SijkaError::BbSwapTooSoon.into()));
    BuybackStateMut::new(w.state.data_mut()).unwrap().set_next_swap_ts(0);
}

/// SPEC v4 (DECISIONS §23 item 4): tag 43 is keeper-signed (account #12);
/// every other signer and `keeper == 0` are refused first, recovery mode
/// included (the buyback goes on in recovery, by the keeper only).
#[test]
fn swap_only_by_the_keeper() {
    let mut w = World::new(true);
    w.pin().unwrap();
    let usdc = 1_000_000_000;
    let e = Err(SijkaError::UnauthorizedKeeper.into());
    for (name, k) in not_keepers() {
        let mut a = swap_accounts(&w, SOL, usdc, 0);
        a[10] = k;
        assert_eq!(run_swap(&w, &a, usdc), e, "{name}");
        // The keeper check comes before the amount and account checks.
        a[2] = missing([0x42; 32]);
        assert_eq!(run_swap(&w, &a, 0), e, "{name}, junk");
    }
    set_config(&mut w, |m| m.set_recovery_mode(1));
    assert_eq!(run_swap(&w, &swap_accounts(&w, SOL, usdc, 0), usdc), Err(SijkaError::JupiterIxForbidden.into()));
    set_config(&mut w, |m| m.set_keeper(&[0; 32]));
    assert_eq!(run_swap(&w, &swap_accounts(&w, SOL, usdc, 0), usdc), e);
}

#[test]
fn swap_counts_bb_wsol_on_amm_and_refuses_usdc_pair() {
    let mut w = World::new(true);
    let sc = w.k[14];
    w.graduate(VQ, VT, &sc);
    w.pin().unwrap();
    assert_eq!(
        run_swap(&w, &swap_accounts(&w, SOL, 1_000_000, 25 * SOL), 1_000_000),
        Err(SijkaError::BbSolBudgetFull.into())
    );
    let u = World::new(false);
    u.pin().unwrap();
    assert_eq!(run_swap(&u, &swap_accounts(&u, SOL, 1_000_000, 0), 1_000_000), Err(SijkaError::BbNotSolPair.into()));
    let fresh = World::new(true);
    assert_eq!(
        run_swap(&fresh, &swap_accounts(&fresh, SOL, 1_000_000, 0), 1_000_000),
        Err(SijkaError::BbNotPinned.into())
    );
}

// ------------------------------------------------------------- tag 46

#[test]
fn burn_zero_and_account_checks() {
    let mut w = World::new(true);
    let k = w.k;
    let run = |w: &World, tok: &TestAccount, tp: &TestAccount| {
        let a = TestAccount::new(K0, SYSTEM_PROGRAM_ID, SOL, &[], false, false, false);
        let mint = acct(MINT, T22, &[0; 82], true);
        bb_burn_with(&PROGRAM, &infos_of(&[&w.state, &a, tok, &mint, tp]), w.env())
    };
    let empty = acct(k[9], T22, &token_bytes(&MINT, &K0, 0, false), true);
    assert_eq!(run(&w, &empty, &prog(T22)), Err(SijkaError::BbNotPinned.into()));
    w.pin().unwrap();
    // Zero balance: Ok, no CPI, no event, counter unchanged (TD-52).
    assert_eq!(run(&w, &empty, &prog(T22)), Ok(()));
    assert_eq!(w.state().cum_burned_tokens(), 0);
    // Non-zero: the host burn CPI is a no-op, so the balance stays → BbBurnIncomplete.
    let full = acct(k[9], T22, &token_bytes(&MINT, &K0, 5, false), true);
    assert_eq!(run(&w, &full, &prog(T22)), Err(SijkaError::BbBurnIncomplete.into()));
    // Wrong token program, foreign or read-only token account.
    assert_eq!(run(&w, &full, &prog(SPL)), Err(SijkaError::BbPinnedAccountMismatch.into()));
    let foreign = acct(k[9], T22, &token_bytes(&MINT, &[0x42; 32], 5, false), true);
    assert_eq!(run(&w, &foreign, &prog(T22)), Err(SijkaError::InvalidTokenAccount.into()));
    let ro = acct(k[9], T22, &token_bytes(&MINT, &K0, 5, false), false);
    assert_eq!(run(&w, &ro, &prog(T22)), Err(SijkaError::AccountNotWritable.into()));
    // Tag 46 stays permissionless: no keeper needed (TD-60).
    set_config(&mut w, |m| m.set_keeper(&[0; 32]));
    assert_eq!(run(&w, &empty, &prog(T22)), Ok(()));
}

// ------------------------------------------------------------- tag 40

#[test]
fn init_checks_before_create() {
    let mut w = World::new(true);
    let payer = TestAccount::new([0x9A; 32], SYSTEM_PROGRAM_ID, 10 * SOL, &[], true, true, false);
    let run = |w: &World, payer: &TestAccount, state: &TestAccount, auth: Pubkey| {
        let a = TestAccount::plain(auth, SYSTEM_PROGRAM_ID, &[]);
        let s = TestAccount::plain(K1, SYSTEM_PROGRAM_ID, &[]);
        let u = TestAccount::plain(K2, SYSTEM_PROGRAM_ID, &[]);
        let sys = prog(SYSTEM_PROGRAM_ID);
        bb_init_with(&PROGRAM, &infos_of(&[payer, &w.config, state, &a, &s, &u, &sys]), w.env())
    };
    let fresh = missing(STATE);
    // Already initialized: refused before any CPI (TD-2).
    assert_eq!(run(&w, &payer, &w.state, K0), Err(SijkaError::BbAlreadyInitialized.into()));
    // Wrong PDA, unsigned payer.
    assert_eq!(run(&w, &payer, &fresh, [0x42; 32]), Err(SijkaError::InvalidPda.into()));
    let unsigned = TestAccount::new([0x9A; 32], SYSTEM_PROGRAM_ID, 10 * SOL, &[], false, true, false);
    assert_eq!(run(&w, &unsigned, &fresh, K0), Err(SijkaError::InvalidExternalAccount.into()));
    // Valid accounts reach the Rent sysvar (not available on the host).
    assert_eq!(run(&w, &payer, &fresh, K0), Err(ProgramError::UnsupportedSysvar));
    // Quote mint neither wSOL nor USDC.
    set_config(&mut w, |m| m.set_quote_mint(&[0x42; 32]));
    assert_eq!(run(&w, &payer, &fresh, K0), Err(SijkaError::InvalidQuoteMint.into()));
}
