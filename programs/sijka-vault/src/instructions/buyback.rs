// Copyright (c) 2026 prt1sn. All rights reserved.
//! Buyback and burn instructions, tags 40–46 (SPEC §5.5). SPEC v4 (DECISIONS
//! §23): the buyback parameters are the `bb_init` defaults for good (tags 47,
//! 48 retired, no pause); the USDC → SOL swap (tag 43) is signed by the keeper
//! key `config.keeper` and bounded by the keeper's `min_out`, not by an oracle.
//! The chunk cranks 44 / 45 are keeper-signed too, without the spot guard: the
//! keeper's `min_out` is the only price limit (DECISIONS §23 items 3 and 6).
//! Tags 40, 41, 42 and 46 stay permissionless.
//!
//! Every handler first runs the SPEC §4 shape check (`check_shape`: exact data
//! length, then exact account count), then reads the clock (and rent where
//! needed) and calls a `*_with` function that takes them as arguments, so the
//! flow up to each CPI is testable on the host.
//!
//! Security notes (DECISIONS §14, SPEC §1.5):
//! - no instruction here takes a destination for funds: USDC moves only
//!   between `buyback_usdc` and `swap_usdc`, SOL only from `buyback_authority`
//!   to pump / `bb_wsol` / the temporary `bb_unwrap`, SIJKA is only burned;
//! - every pump account is compared with a pinned key, a pump constant or a key
//!   derived on chain; the fee-recipient slots that pump checks itself may not
//!   be any of our accounts;
//! - `buyback_authority` signs only CPIs built here; right after the pump CPI
//!   its owner / data and our token accounts are re-checked (review RT-2), and
//!   the Jupiter route of tag 43 is checked once by `validate_route` and then
//!   only a `ValidatedRoute` reaches `invoke_route`, which re-checks the swap
//!   accounts right after the CPI (RT-1);
//! - tags 42–45 must be the only non-ComputeBudget instruction of the
//!   transaction (`require_sole_top_level`).

use pinocchio::ProgramResult;
use pinocchio::account_info::AccountInfo;
use pinocchio::instruction::Signer;
use pinocchio::program_error::ProgramError;
use pinocchio::pubkey::{Pubkey, pubkey_eq};

use crate::buyback::math::{
    ChunkInputs, ChunkPlan, CurveReserves, ObsPrev, next_ts, observe_step, plan_chunk, price_x64, settle_sol_curve,
    settle_token_quote,
};
use crate::buyback::ops::{
    QuoteSnap, account_missing, burn_all, check_after_pump, create_bb_unwrap, expect_authority_clean,
};
use crate::buyback::{USDC_DECIMALS, default_params, reserve};
use crate::constants::{
    AMM_EVENT_AUTHORITY, AMM_FEE_CONFIG, AMM_GLOBAL_CONFIG, AMM_GVA, ATA_PROGRAM_ID, BUYBACK_STATE_LEN,
    DISC_BUYBACK_STATE, JITO_DONT_FRONT, JUPITER_V6, MAX_RENT_EXTRA, OBS_MIN_INTERVAL_S, PUMP_AMM_PROGRAM,
    PUMP_EVENT_AUTHORITY, PUMP_FEE_CONFIG, PUMP_FEES_PROGRAM, PUMP_GLOBAL, PUMP_GVA, PUMP_PROGRAM,
    SEED_AMM_CREATOR_VAULT, SEED_AMM_POOL, SEED_AMM_POOL_V2, SEED_BUYBACK_AUTHORITY, SEED_BUYBACK_STATE,
    SEED_PUMP_BONDING_CURVE, SEED_PUMP_CREATOR_VAULT, SEED_PUMP_POOL_AUTHORITY, SEED_PUMP_SHARING_CONFIG,
    SEED_SWAP_AUTHORITY, SEED_USER_VOLUME_ACCUMULATOR, SPL_TOKEN_PROGRAM_ID, SYSTEM_PROGRAM_ID, TOKEN_2022_PROGRAM_ID,
    TOKEN_ACCOUNT_LEN, WSOL_MINT,
};
use crate::cpi::PdaSeeds;
use crate::cpi::jupiter::{RoutePolicy, SwapAcc, invoke_route, validate_route};
use crate::cpi::pump::buy_exact_quote_in_v2;
use crate::cpi::pump_amm::buy_exact_quote_in;
use crate::cpi::system::{create_pda_account, transfer as system_transfer};
use crate::cpi::token::{close_account, sync_native, transfer_checked};
use crate::error::SijkaError;
use crate::events::{EvBurn, EvBuybackInit, EvBuybackPin, EvBuybackSwap, EvChunk, EvObserve, EvVenueSwitch};
use crate::external::pump_accounts::{
    CoinCheck, PoolPins, check_curve_coin, coin_creator_vault_for, creator_vault_for, read_curve, read_pool,
};
use crate::instructions::{
    BB_BURN, BB_CHUNK_AMM, BB_CHUNK_CURVE, BB_INIT, BB_OBSERVE, BB_PIN, BB_SWAP_USDC_TO_SOL, check_keeper, check_shape,
};
use crate::state::buyback_state::buyback_params::{BUYBACK_PARAMS_LEN, BuybackParams};
use crate::state::buyback_state::{
    BuybackState, BuybackStateMut, bb_flags, bb_venue, load_buyback_state_mut, pinned as k, quote_kind,
};
use crate::state::config::{config_view, load_config};
use crate::util::accounts::{
    check_token, expect_key, expect_not_in, expect_owner, expect_program, expect_readonly, expect_system_empty,
    expect_writable,
};
use crate::util::bytes::{ZERO_KEY, is_zero_key, read_u64};
use crate::util::math::rent_exempt_minimum;
use crate::util::pda::{find, find_ata};
use crate::util::runtime::{clock, require_sole_top_level};

// ------------------------------------------------------------ helpers ----

/// Clock values used by the handlers.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Env {
    pub now: i64,
    pub slot: u64,
}

#[inline(never)]
fn load_env() -> Result<Env, ProgramError> {
    let c = clock()?;
    Ok(Env { now: c.unix_timestamp, slot: c.slot })
}

#[inline(always)]
fn fail(e: SijkaError) -> ProgramError {
    e.fail()
}

#[inline]
fn acc(accounts: &[AccountInfo], i: usize) -> Result<&AccountInfo, ProgramError> {
    accounts.get(i).ok_or_else(|| SijkaError::InvalidAccountCount.fail())
}

#[inline]
fn bad_data() -> ProgramError {
    SijkaError::InvalidInstructionData.fail()
}

#[inline]
fn data_u64(data: &[u8], off: usize) -> Result<u64, ProgramError> {
    read_u64(data, off).ok_or_else(bad_data)
}

#[inline]
fn view(d: &[u8]) -> Result<BuybackState<'_>, ProgramError> {
    BuybackState::new(d).ok_or_else(|| SijkaError::InvalidBuybackState.fail())
}

#[inline]
fn view_mut(d: &mut [u8]) -> Result<BuybackStateMut<'_>, ProgramError> {
    BuybackStateMut::new(d).ok_or_else(|| SijkaError::InvalidBuybackState.fail())
}

/// Pinned key `k` (always present for `k < 27`).
#[inline]
fn pin<'a>(bs: &BuybackState<'a>, i: usize) -> Result<&'a Pubkey, ProgramError> {
    bs.pinned(i).ok_or_else(|| SijkaError::InvariantViolated.fail())
}

/// Account key equals a pinned / derived key, else `BbPinnedAccountMismatch`.
#[inline]
fn expect_pinned(ai: &AccountInfo, key: &Pubkey) -> ProgramResult {
    expect_key(ai, key, SijkaError::BbPinnedAccountMismatch)
}

/// Write pinned key `i` into the state.
#[inline]
fn put(m: &mut BuybackStateMut<'_>, i: usize, key: &Pubkey) -> ProgramResult {
    if m.set_pinned(i, key) { Ok(()) } else { Err(SijkaError::InvariantViolated.fail()) }
}

#[inline]
fn add(a: u64, b: u64) -> Result<u64, ProgramError> {
    a.checked_add(b).ok_or_else(|| SijkaError::MathOverflow.fail())
}

/// Quote mint `k8` for the pair (SOL → wSOL, USDC → cached `usdc_mint`) and the
/// expected coin quote field (`None` = zero for SOL coins).
fn quote_of(bs: &BuybackState<'_>) -> Result<(Pubkey, bool), ProgramError> {
    match bs.quote_kind() {
        quote_kind::SOL => Ok((WSOL_MINT, true)),
        quote_kind::USDC => Ok((*bs.usdc_mint(), false)),
        _ => Err(SijkaError::InvalidBuybackState.fail()),
    }
}

// --------------------------------------------------------- tag 40 ----

/// Tag 40 `bb_init` (SPEC §5.5.4): create `BuybackState` with the default
/// parameters of the pair, the bumps and k0–k5 from `Config`. Permissionless,
/// once.
#[inline(never)]
pub fn bb_init(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    check_shape(&BB_INIT, accounts, data)?;
    let env = load_env()?;
    bb_init_with(program_id, accounts, env)
}

struct InitSnap {
    kind: u8,
    usdc_mint: Pubkey,
    buyback_usdc: Pubkey,
    swap_usdc: Pubkey,
    state_bump: u8,
    authority_bump: u8,
    swap_bump: u8,
    unwrap_bump: u8,
}

pub(crate) fn bb_init_with(program_id: &Pubkey, accounts: &[AccountInfo], env: Env) -> ProgramResult {
    let [payer, config, state, authority, swap_authority, bb_unwrap, system_program] = accounts else {
        return Err(SijkaError::InvalidAccountCount.fail());
    };
    if !payer.is_signer() {
        return Err(SijkaError::InvalidExternalAccount.fail());
    }
    expect_writable(payer)?;
    expect_owner(payer, &SYSTEM_PROGRAM_ID, SijkaError::InvalidExternalAccount)?;
    expect_program(system_program, &SYSTEM_PROGRAM_ID)?;
    let c = {
        let d = load_config(config, program_id)?;
        let cfg = config_view(&d)?;
        expect_key(state, cfg.buyback_state(), SijkaError::InvalidPda)?;
        expect_key(authority, cfg.buyback_authority(), SijkaError::InvalidPda)?;
        expect_key(swap_authority, cfg.swap_authority(), SijkaError::InvalidPda)?;
        expect_key(bb_unwrap, cfg.bb_unwrap(), SijkaError::InvalidPda)?;
        let kind = if pubkey_eq(cfg.quote_mint(), &WSOL_MINT) {
            quote_kind::SOL
        } else if !is_zero_key(cfg.usdc_mint()) && pubkey_eq(cfg.quote_mint(), cfg.usdc_mint()) {
            quote_kind::USDC
        } else {
            return Err(SijkaError::InvalidQuoteMint.fail());
        };
        InitSnap {
            kind,
            usdc_mint: *cfg.usdc_mint(),
            buyback_usdc: *cfg.buyback_usdc(),
            swap_usdc: *cfg.swap_usdc(),
            state_bump: cfg.buyback_state_bump(),
            authority_bump: cfg.buyback_authority_bump(),
            swap_bump: cfg.swap_authority_bump(),
            unwrap_bump: cfg.bb_unwrap_bump(),
        }
    };
    expect_writable(state)?;
    let bb_wsol = if c.kind == quote_kind::SOL {
        find_ata(authority.key(), &SPL_TOKEN_PROGRAM_ID, &WSOL_MINT)?
    } else {
        ZERO_KEY
    };

    let pda = PdaSeeds::new(SEED_BUYBACK_STATE, c.state_bump);
    let seeds = pda.seeds();
    let signer = [Signer::from(&seeds)];
    create_pda_account(payer, state, BUYBACK_STATE_LEN, program_id, &signer, SijkaError::BbAlreadyInitialized)?;

    {
        let mut d = state.try_borrow_mut_data()?;
        let mut m = view_mut(&mut d)?;
        m.set_discriminator(&DISC_BUYBACK_STATE);
        m.set_version(1);
        m.set_flags(0);
        m.set_venue(bb_venue::NONE);
        m.set_quote_kind(c.kind);
        m.set_bump_buyback_state(c.state_bump);
        m.set_bump_buyback_authority(c.authority_bump);
        m.set_bump_swap_authority(c.swap_bump);
        m.set_bump_bb_unwrap(c.unwrap_bump);
        m.set_params(&default_params(c.kind));
        put(&mut m, k::BUYBACK_AUTHORITY, authority.key())?;
        put(&mut m, k::SWAP_AUTHORITY, swap_authority.key())?;
        put(&mut m, k::BB_UNWRAP, bb_unwrap.key())?;
        put(&mut m, k::BB_USDC, &c.buyback_usdc)?;
        put(&mut m, k::SWAP_USDC, &c.swap_usdc)?;
        put(&mut m, k::BB_WSOL, &bb_wsol)?;
        m.set_usdc_mint(&c.usdc_mint);
    }
    EvBuybackInit {
        ts: env.now,
        quote_kind: c.kind,
        bb_usdc: &c.buyback_usdc,
        swap_usdc: &c.swap_usdc,
        bb_wsol: &bb_wsol,
    }
    .emit()
}

// --------------------------------------------------------- tag 41 ----

/// Tag 41 `bb_pin` (SPEC §5.5.5): check the coin in strict mode, derive and
/// pin k6–k26 on chain (canonical bumps, none taken from input), choose the
/// venue. Permissionless, once, after `set_token_mint`.
#[inline(never)]
pub fn bb_pin(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    check_shape(&BB_PIN, accounts, data)?;
    let env = load_env()?;
    bb_pin_with(program_id, accounts, env)
}

pub(crate) fn bb_pin_with(program_id: &Pubkey, accounts: &[AccountInfo], env: Env) -> ProgramResult {
    let [state, config, mint, curve, pool, pool_base_ta, pool_quote_ta] = accounts else {
        return Err(SijkaError::InvalidAccountCount.fail());
    };
    let (token_mint, token_program, decimals, buyback_token, bs_key) = {
        let d = load_config(config, program_id)?;
        let cfg = config_view(&d)?;
        (*cfg.token_mint(), *cfg.token_program(), cfg.token_decimals(), *cfg.buyback_token(), *cfg.buyback_state())
    };
    let mut sd = load_buyback_state_mut(state, program_id, Some(&bs_key))?;
    let (k0, k3, k5, usdc_mint, k8, is_sol) = {
        let bs = view(&sd)?;
        if bs.is_pinned() {
            return Err(SijkaError::BbAlreadyPinned.fail());
        }
        let (k8, is_sol) = quote_of(&bs)?;
        (*pin(&bs, k::BUYBACK_AUTHORITY)?, *pin(&bs, k::BB_USDC)?, *pin(&bs, k::BB_WSOL)?, *bs.usdc_mint(), k8, is_sol)
    };
    if is_zero_key(&token_mint) {
        return Err(SijkaError::BbMintNotSet.fail());
    }
    expect_pinned(mint, &token_mint)?;
    if !mint.is_owned_by(&token_program) {
        return Err(SijkaError::InvalidTokenMint.fail());
    }
    let tp_kind = if pubkey_eq(&token_program, &SPL_TOKEN_PROGRAM_ID) {
        crate::state::buyback_state::base_tp_kind::SPL_TOKEN
    } else if pubkey_eq(&token_program, &TOKEN_2022_PROGRAM_ID) {
        crate::state::buyback_state::base_tp_kind::TOKEN_2022
    } else {
        return Err(SijkaError::InvalidTokenMint.fail());
    };

    // k6–k26 (SPEC §3.7.1), written as they are derived.
    let mut m = view_mut(&mut sd)?;
    let k9 = find_ata(&k0, &token_program, &token_mint)?;
    if !pubkey_eq(&k9, &buyback_token) {
        return Err(SijkaError::BbPinnedAccountMismatch.fail());
    }
    put(&mut m, k::MINT, &token_mint)?;
    put(&mut m, k::BASE_TOKEN_PROGRAM, &token_program)?;
    put(&mut m, k::QUOTE_MINT, &k8)?;
    put(&mut m, k::BB_SIJKA, &k9)?;
    put(&mut m, k::BB_QUOTE, if is_sol { &k5 } else { &k3 })?;
    let (k11, _) = find(&[SEED_PUMP_BONDING_CURVE, &token_mint], &PUMP_PROGRAM)?;
    put(&mut m, k::BONDING_CURVE, &k11)?;
    put(&mut m, k::ASSOC_BASE_BONDING_CURVE, &find_ata(&k11, &token_program, &token_mint)?)?;
    put(&mut m, k::ASSOC_QUOTE_BONDING_CURVE, &find_ata(&k11, &SPL_TOKEN_PROGRAM_ID, &k8)?)?;
    let (k14, _) = find(&[SEED_PUMP_SHARING_CONFIG, &token_mint], &PUMP_FEES_PROGRAM)?;
    put(&mut m, k::SHARING_CONFIG, &k14)?;
    let (k15, _) = find(&[SEED_PUMP_CREATOR_VAULT, &k14], &PUMP_PROGRAM)?;
    put(&mut m, k::CREATOR_VAULT, &k15)?;
    put(&mut m, k::ASSOC_CREATOR_VAULT, &find_ata(&k15, &SPL_TOKEN_PROGRAM_ID, &k8)?)?;
    let (k17, _) = find(&[SEED_USER_VOLUME_ACCUMULATOR, &k0], &PUMP_PROGRAM)?;
    put(&mut m, k::PUMP_USER_VOLUME_ACC, &k17)?;
    put(&mut m, k::PUMP_ASSOC_USER_VOLUME_ACC, &find_ata(&k17, &SPL_TOKEN_PROGRAM_ID, &k8)?)?;
    let (k19, _) = find(&[SEED_PUMP_POOL_AUTHORITY, &token_mint], &PUMP_PROGRAM)?;
    put(&mut m, k::POOL_AUTHORITY, &k19)?;
    let (k20, _) = find(&[SEED_AMM_POOL, &0u16.to_le_bytes(), &k19, &token_mint, &k8], &PUMP_AMM_PROGRAM)?;
    put(&mut m, k::POOL, &k20)?;
    let k21 = find_ata(&k20, &token_program, &token_mint)?;
    put(&mut m, k::POOL_BASE_TA, &k21)?;
    let k22 = find_ata(&k20, &SPL_TOKEN_PROGRAM_ID, &k8)?;
    put(&mut m, k::POOL_QUOTE_TA, &k22)?;
    let (k23, _) = find(&[SEED_AMM_CREATOR_VAULT, &k14], &PUMP_AMM_PROGRAM)?;
    put(&mut m, k::COIN_CREATOR_VAULT_AUTHORITY, &k23)?;
    put(&mut m, k::COIN_CREATOR_VAULT_ATA, &find_ata(&k23, &SPL_TOKEN_PROGRAM_ID, &k8)?)?;
    let (k25, _) = find(&[SEED_USER_VOLUME_ACCUMULATOR, &k0], &PUMP_AMM_PROGRAM)?;
    put(&mut m, k::AMM_USER_VOLUME_ACC, &k25)?;
    let (k26, _) = find(&[SEED_AMM_POOL_V2, &token_mint], &PUMP_AMM_PROGRAM)?;
    put(&mut m, k::POOL_V2, &k26)?;

    expect_pinned(curve, &k11)?;
    expect_pinned(pool, &k20)?;
    expect_pinned(pool_base_ta, &k21)?;
    expect_pinned(pool_quote_ta, &k22)?;
    let usdc_quote = if is_sol { None } else { Some(&usdc_mint) };
    let f = read_curve(curve, CoinCheck::Strict, &k14, usdc_quote).map_err(fail)?;
    let venue = if f.is_complete() {
        let pins = PoolPins {
            pool_authority: &k19,
            mint: &token_mint,
            base_token_program: &token_program,
            quote_mint: &k8,
            base_ta: &k21,
            quote_ta: &k22,
            sharing_config: &k14,
        };
        read_pool(pool, pool_base_ta, pool_quote_ta, &pins, CoinCheck::Strict)
            .map_err(|_| SijkaError::BbPoolNotReady.fail())?;
        bb_venue::AMM
    } else {
        bb_venue::CURVE
    };
    m.set_base_decimals(decimals);
    m.set_base_tp_kind(tp_kind);
    m.set_venue(venue);
    m.set_venue_since_slot(env.slot);
    let flags = (m.view().flags() | bb_flags::PINNED) & !bb_flags::OBS_INIT;
    m.set_flags(flags);
    drop(sd);
    EvBuybackPin {
        ts: env.now,
        mint: &token_mint,
        base_tp: &token_program,
        venue,
        bonding_curve: &k11,
        pool: &k20,
        slot: env.slot,
    }
    .emit()
}

// --------------------------------------------------------- tag 42 ----

/// Tag 42 `bb_observe` (SPEC §5.5.6): one price observation for the EMA, at
/// most every 15 s, and the switch from the curve to PumpSwap once the curve
/// is complete and the canonical pool passes the working checks.
#[inline(never)]
pub fn bb_observe(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    check_shape(&BB_OBSERVE, accounts, data)?;
    let env = load_env()?;
    bb_observe_with(program_id, accounts, env)
}

pub(crate) fn bb_observe_with(program_id: &Pubkey, accounts: &[AccountInfo], env: Env) -> ProgramResult {
    let [state, ix_sysvar, curve, pool, pool_base_ta, pool_quote_ta] = accounts else {
        return Err(SijkaError::InvalidAccountCount.fail());
    };
    let mut sd = load_buyback_state_mut(state, program_id, None)?;
    let bs = view(&sd)?;
    if !bs.is_pinned() {
        return Err(SijkaError::BbNotPinned.fail());
    }
    expect_pinned(curve, pin(&bs, k::BONDING_CURVE)?)?;
    expect_pinned(pool, pin(&bs, k::POOL)?)?;
    expect_pinned(pool_base_ta, pin(&bs, k::POOL_BASE_TA)?)?;
    expect_pinned(pool_quote_ta, pin(&bs, k::POOL_QUOTE_TA)?)?;
    require_sole_top_level(ix_sysvar, program_id, BB_OBSERVE.tag)?;

    let init = bs.flags() & bb_flags::OBS_INIT != 0;
    if init {
        let dt = env.now.checked_sub(bs.last_obs_ts()).ok_or_else(|| SijkaError::MathOverflow.fail())?;
        if dt < OBS_MIN_INTERVAL_S || env.slot <= bs.last_obs_slot() {
            return Err(SijkaError::BbObserveTooSoon.fail());
        }
    }
    let (k8, is_sol) = quote_of(&bs)?;
    let usdc_mint = *bs.usdc_mint();
    let usdc_quote = if is_sol { None } else { Some(&usdc_mint) };
    let k14 = pin(&bs, k::SHARING_CONFIG)?;
    let pins = PoolPins {
        pool_authority: pin(&bs, k::POOL_AUTHORITY)?,
        mint: pin(&bs, k::MINT)?,
        base_token_program: pin(&bs, k::BASE_TOKEN_PROGRAM)?,
        quote_mint: &k8,
        base_ta: pin(&bs, k::POOL_BASE_TA)?,
        quote_ta: pin(&bs, k::POOL_QUOTE_TA)?,
        sharing_config: k14,
    };
    let old_venue = bs.venue();
    let (q, b, switched) = match old_venue {
        bb_venue::CURVE => {
            let f = read_curve(curve, CoinCheck::Basic, k14, usdc_quote).map_err(fail)?;
            if f.is_complete() {
                check_curve_coin(&f, CoinCheck::Working, k14, usdc_quote).map_err(fail)?;
                let r = read_pool(pool, pool_base_ta, pool_quote_ta, &pins, CoinCheck::Working)
                    .map_err(|_| SijkaError::BbPoolNotReady.fail())?;
                (r.quote, r.base, true)
            } else {
                (f.virtual_quote_reserves, f.virtual_token_reserves, false)
            }
        }
        bb_venue::AMM => {
            let r = read_pool(pool, pool_base_ta, pool_quote_ta, &pins, CoinCheck::Working).map_err(fail)?;
            (r.quote, r.base, false)
        }
        _ => return Err(SijkaError::InvariantViolated.fail()),
    };
    let p = price_x64(q, b).map_err(fail)?;
    let mut prev = ObsPrev {
        init,
        ema: bs.ema_price_x64(),
        q_ema: bs.q_ema(),
        fresh_obs: bs.fresh_obs(),
        last_obs_ts: bs.last_obs_ts(),
    };
    if switched && init {
        // Review RT-8: the EMA survives the switch (same units); Q_ema can only
        // go down (virtual vQ of the curve is above the pool's Q); a new warm-up
        // starts, and this observation already goes through the clamp.
        prev.q_ema = prev.q_ema.min(q);
        prev.fresh_obs = 0;
    }
    let params = bs.buyback_params();
    let next = observe_step(&prev, env.now, p, q, params.obs_clamp_bps(), params.warmup_obs()).map_err(fail)?;
    let n_obs = add(bs.n_obs(), 1)?;
    let flags = bs.flags() | bb_flags::OBS_INIT;

    let mut m = view_mut(&mut sd)?;
    m.set_ema_price_x64(next.ema);
    m.set_q_ema(next.q_ema);
    m.set_fresh_obs(next.fresh_obs);
    m.set_last_obs_price_x64(p);
    m.set_last_obs_quote(q);
    m.set_last_obs_ts(env.now);
    m.set_last_obs_slot(env.slot);
    m.set_n_obs(n_obs);
    m.set_flags(flags);
    let venue = if switched { bb_venue::AMM } else { old_venue };
    if switched {
        m.set_venue(bb_venue::AMM);
        m.set_venue_since_slot(env.slot);
    }
    drop(sd);
    if switched {
        EvVenueSwitch { ts: env.now, old_value: old_venue, new_value: bb_venue::AMM, slot: env.slot, p, q }.emit()?;
    }
    EvObserve {
        ts: env.now,
        venue,
        slot: env.slot,
        q,
        b,
        p_raw: p,
        ema: next.ema,
        q_ema: next.q_ema,
        fresh_obs: next.fresh_obs,
        clamped: next.clamped,
    }
    .emit()
}

// --------------------------------------------------------- tag 43 ----

/// Tag 43 `bb_swap_usdc_to_sol` (SPEC §5.5.7): USDC of `buyback_usdc` → SOL on
/// `buyback_authority` through a Jupiter route chosen by the keeper, the only
/// signer (`config.keeper`, SPEC v4), bounded by the keeper's `min_out` (no
/// oracle). SOL pair only; works in recovery mode too (the buyback goes on).
#[inline(never)]
pub fn bb_swap_usdc_to_sol(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    check_shape(&BB_SWAP_USDC_TO_SOL, accounts, data)?;
    let env = load_env()?;
    let rent0 = rent_exempt_minimum(0)?;
    let rent_unwrap = rent_exempt_minimum(TOKEN_ACCOUNT_LEN)?;
    bb_swap_with(program_id, accounts, data, env, rent0, rent_unwrap)
}

/// Values of `BuybackState` used by tag 43 (copied so no borrow is held
/// across the CPIs).
struct SwapSnap {
    k0: Pubkey,
    k1: Pubkey,
    k2: Pubkey,
    k3: Pubkey,
    k4: Pubkey,
    k5: Pubkey,
    k9: Pubkey,
    usdc_mint: Pubkey,
    venue: u8,
    next_swap_ts: i64,
    bump_k0: u8,
    bump_k1: u8,
    bump_unwrap: u8,
    params: [u8; BUYBACK_PARAMS_LEN],
}

const SWAP_FIXED: usize = 15;

/// `rent0 = Rent::minimum_balance(0)`, `rent_unwrap =
/// Rent::minimum_balance(165)` (the temporary `bb_unwrap`).
pub(crate) fn bb_swap_with(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    env: Env,
    rent0: u64,
    rent_unwrap: u64,
) -> ProgramResult {
    let (fixed, route) = accounts.split_at_checked(SWAP_FIXED).ok_or_else(|| SijkaError::InvalidAccountCount.fail())?;
    let [
        state,
        config,
        ix_sysvar,
        authority,
        bb_usdc,
        swap_authority,
        swap_usdc,
        bb_unwrap,
        native_mint,
        usdc_mint,
        token_program,
        system_program,
        keeper,
        jupiter,
        bb_wsol,
    ] = fixed
    else {
        return Err(SijkaError::InvalidAccountCount.fail());
    };
    let amount_in = data_u64(data, 1)?;
    let min_out = data_u64(data, 9)?;
    let jup_data = data.get(19..).ok_or_else(bad_data)?;

    // 0. Only the keeper key signs this swap (SPEC v4, account #12).
    let bs_key = {
        let d = load_config(config, program_id)?;
        let cfg = config_view(&d)?;
        check_keeper(keeper, &cfg)?;
        *cfg.buyback_state()
    };
    let s = {
        let sd = load_buyback_state_mut(state, program_id, Some(&bs_key))?;
        let bs = view(&sd)?;
        if !bs.is_pinned() {
            return Err(SijkaError::BbNotPinned.fail());
        }
        if bs.quote_kind() != quote_kind::SOL {
            return Err(SijkaError::BbNotSolPair.fail());
        }
        SwapSnap {
            k0: *pin(&bs, k::BUYBACK_AUTHORITY)?,
            k1: *pin(&bs, k::SWAP_AUTHORITY)?,
            k2: *pin(&bs, k::BB_UNWRAP)?,
            k3: *pin(&bs, k::BB_USDC)?,
            k4: *pin(&bs, k::SWAP_USDC)?,
            k5: *pin(&bs, k::BB_WSOL)?,
            k9: *pin(&bs, k::BB_SIJKA)?,
            usdc_mint: *bs.usdc_mint(),
            venue: bs.venue(),
            next_swap_ts: bs.next_swap_ts(),
            bump_k0: bs.bump_buyback_authority(),
            bump_k1: bs.bump_swap_authority(),
            bump_unwrap: bs.bump_bb_unwrap(),
            params: *bs.params(),
        }
    };
    let p = BuybackParams::from_array(&s.params);

    // Fixed accounts (SPEC §5.5.7 table).
    expect_pinned(authority, &s.k0)?;
    expect_writable(authority)?;
    expect_authority_clean(authority, SijkaError::InvalidExternalAccount)?;
    expect_pinned(bb_usdc, &s.k3)?;
    expect_writable(bb_usdc)?;
    let usdc_balance =
        check_token(bb_usdc, &SPL_TOKEN_PROGRAM_ID, &s.usdc_mint, &s.k0, false, SijkaError::InvalidTokenAccount)?;
    expect_pinned(swap_authority, &s.k1)?;
    expect_readonly(swap_authority)?;
    expect_system_empty(swap_authority, SijkaError::InvalidExternalAccount)?;
    expect_pinned(swap_usdc, &s.k4)?;
    expect_writable(swap_usdc)?;
    check_token(swap_usdc, &SPL_TOKEN_PROGRAM_ID, &s.usdc_mint, &s.k1, false, SijkaError::InvalidTokenAccount)?;
    expect_pinned(bb_unwrap, &s.k2)?;
    expect_writable(bb_unwrap)?;
    expect_key(native_mint, &WSOL_MINT, SijkaError::InvalidExternalAccount)?;
    expect_pinned(usdc_mint, &s.usdc_mint)?;
    expect_program(token_program, &SPL_TOKEN_PROGRAM_ID)?;
    expect_program(system_program, &SYSTEM_PROGRAM_ID)?;
    expect_program(jupiter, &JUPITER_V6)?;
    expect_pinned(bb_wsol, &s.k5)?;
    let wsol_balance =
        check_token(bb_wsol, &SPL_TOKEN_PROGRAM_ID, &WSOL_MINT, &s.k0, true, SijkaError::BbQuoteAtaMissing)?;

    // 1–2.
    require_sole_top_level(ix_sysvar, program_id, BB_SWAP_USDC_TO_SOL.tag)?;
    if env.now < s.next_swap_ts {
        return Err(SijkaError::BbSwapTooSoon.fail());
    }
    // 3. SOL budget (bb_wsol only on the AMM venue, reviews ACC-13, RT-7).
    let res = reserve(rent0).map_err(fail)?;
    let lamports = authority.lamports();
    let wsol_budget = if s.venue == bb_venue::AMM { wsol_balance } else { 0 };
    let sol_avail = add(lamports.saturating_sub(res), wsol_budget)?;
    if sol_avail >= p.sol_budget_cap() {
        return Err(SijkaError::BbSolBudgetFull.fail());
    }
    if amount_in == 0 || amount_in > usdc_balance.min(p.swap_max_usdc()) {
        return Err(SijkaError::BbSwapAmountInvalid.fail());
    }
    // The keeper's `min_out` (no oracle, SPEC v4); zero would accept any output.
    if min_out == 0 {
        return Err(SijkaError::BbSwapAmountInvalid.fail());
    }
    // Float (audit EA-1): this instruction spends from k0 only the rent of
    // the temporary bb_unwrap, and `close_account` returns it. Pump may have
    // taken rent out of RESERVE in the last chunk (`lam_after ≥ rent0`), and
    // this swap is what refills k0, so RESERVE itself is not required here.
    if lamports < add(rent0, rent_unwrap)? {
        return Err(SijkaError::BbFloatLow.fail());
    }
    // 4. Route policy (SPEC §5.3.3, §11.3 #30); `config` is protected too.
    let allowed = [
        SwapAcc { info: swap_usdc, mint: &s.usdc_mint, native: false },
        SwapAcc { info: bb_unwrap, mint: &WSOL_MINT, native: true },
    ];
    let protected: [&Pubkey; 6] = [state.key(), &s.k0, &s.k3, &s.k5, &s.k9, config.key()];
    let policy = RoutePolicy {
        swap_authority,
        swap_bump: s.bump_k1,
        expect_in_amount: amount_in,
        src: &s.k4,
        dst: &s.k2,
        src_mint: &s.usdc_mint,
        dst_mint: &WSOL_MINT,
        allowed_swap_accounts: &allowed,
        protected_keys: &protected,
    };
    let validated = validate_route(jupiter, route, jup_data, &policy)?;
    // 5. (SPEC v4: no oracle read.)
    // 6. buyback_usdc → swap_usdc, signed by buyback_authority.
    let k0_pda = PdaSeeds::new(SEED_BUYBACK_AUTHORITY, s.bump_k0);
    let k0_seeds = k0_pda.seeds();
    let k0_signer = [Signer::from(&k0_seeds)];
    transfer_checked(token_program, bb_usdc, usdc_mint, swap_usdc, authority, amount_in, USDC_DECIMALS, &k0_signer)?;
    // 7. Snapshots, temporary wSOL output account.
    let s0 = check_token(swap_usdc, &SPL_TOKEN_PROGRAM_ID, &s.usdc_mint, &s.k1, false, SijkaError::InvariantViolated)?;
    create_bb_unwrap(authority, bb_unwrap, native_mint, token_program, &s.k1, s.bump_k0, s.bump_unwrap)?;
    let out0 = check_token(bb_unwrap, &SPL_TOKEN_PROGRAM_ID, &WSOL_MINT, &s.k1, true, SijkaError::InvariantViolated)?;
    // 8. Route; `invoke_route` runs `post_route_check` right after the CPI (RT-1).
    invoke_route(validated)?;
    // 9. Results. `out` counts only what the route delivered (lamports sent to
    // the address beforehand are not counted as output).
    let s1 =
        check_token(swap_usdc, &SPL_TOKEN_PROGRAM_ID, &s.usdc_mint, &s.k1, false, SijkaError::SwapAccountTampered)?;
    let spent = s0.checked_sub(s1).ok_or_else(|| SijkaError::SwapAccountTampered.fail())?;
    if spent > amount_in {
        return Err(SijkaError::SwapInputExceeded.fail());
    }
    if spent == 0 {
        return Err(SijkaError::SwapNoop.fail());
    }
    let out1 = check_token(bb_unwrap, &SPL_TOKEN_PROGRAM_ID, &WSOL_MINT, &s.k1, true, SijkaError::SwapAccountTampered)?;
    let out = out1.checked_sub(out0).ok_or_else(|| SijkaError::SwapAccountTampered.fail())?;
    if out < min_out {
        return Err(SijkaError::SwapOutputBelowMin.fail());
    }
    // 10–11. Unspent USDC back, bb_unwrap closed into buyback_authority.
    let k1_pda = PdaSeeds::new(SEED_SWAP_AUTHORITY, s.bump_k1);
    let k1_seeds = k1_pda.seeds();
    let k1_signer = [Signer::from(&k1_seeds)];
    let unspent = amount_in.checked_sub(spent).ok_or_else(|| SijkaError::MathOverflow.fail())?;
    if unspent > 0 {
        transfer_checked(
            token_program,
            swap_usdc,
            usdc_mint,
            bb_usdc,
            swap_authority,
            unspent,
            USDC_DECIMALS,
            &k1_signer,
        )?;
    }
    close_account(token_program, bb_unwrap, authority, swap_authority, &k1_signer)?;
    if bb_unwrap.lamports() != 0 {
        return Err(SijkaError::InvariantViolated.fail());
    }
    // 12. State.
    let next_swap = next_ts(env.now, p.swap_min_interval_s(), amount_in, p.swap_max_usdc()).map_err(fail)?;
    let (cum_usdc, cum_sol) = {
        let mut sd = state.try_borrow_mut_data()?;
        let mut m = view_mut(&mut sd)?;
        let v = m.view();
        let n_swaps = add(v.n_swaps(), 1)?;
        let cum_usdc = add(v.cum_usdc_swapped(), spent)?;
        let cum_spent = add(v.cum_payout_buyback_spent(), spent)?;
        let cum_sol = add(v.cum_sol_from_swaps(), out)?;
        m.set_last_swap_ts(env.now);
        m.set_next_swap_ts(next_swap);
        m.set_n_swaps(n_swaps);
        m.set_cum_usdc_swapped(cum_usdc);
        m.set_cum_payout_buyback_spent(cum_spent);
        m.set_cum_sol_from_swaps(cum_sol);
        (cum_usdc, cum_sol)
    };
    // 13.
    EvBuybackSwap {
        ts: env.now,
        amount_in,
        spent,
        out,
        min_out,
        cum_usdc_swapped: cum_usdc,
        cum_sol_from_swaps: cum_sol,
    }
    .emit()
}

// ------------------------------------------------------ tags 44, 45 ----

/// What one slot of the pump account list must be.
#[derive(Clone, Copy)]
enum Want {
    /// Pinned key `k` (`BbPinnedAccountMismatch`).
    Pin(usize),
    /// Pinned token program `k`: key, then `executable` (`InvalidProgramId`).
    PinProg(usize),
    /// pump constant (`BbPinnedAccountMismatch`).
    Key(&'static Pubkey),
    /// External program: key and `executable` (`InvalidProgramId`).
    Prog(&'static Pubkey),
    /// Checked by pump itself (fee recipients, U-29); must not be one of our
    /// accounts (`BbPinnedAccountMismatch`).
    Free,
    /// Creator vault: compared after reading the curve / pool (ACC-2).
    Late,
}

/// One slot: expectation and whether the outer instruction must mark it
/// writable (SPEC §5.0.3: a CPI cannot raise privileges).
#[derive(Clone, Copy)]
struct Slot(Want, bool);

/// Tag 44, outer accounts 4..=30 (SPEC §5.5.3, curve).
const CURVE_TABLE: [Slot; 27] = [
    Slot(Want::Key(&PUMP_GLOBAL), false),
    Slot(Want::Pin(k::MINT), true),
    Slot(Want::Pin(k::QUOTE_MINT), false),
    Slot(Want::PinProg(k::BASE_TOKEN_PROGRAM), false),
    Slot(Want::Prog(&SPL_TOKEN_PROGRAM_ID), false),
    Slot(Want::Prog(&ATA_PROGRAM_ID), false),
    Slot(Want::Free, true),
    Slot(Want::Free, true),
    Slot(Want::Free, true),
    Slot(Want::Free, true),
    Slot(Want::Pin(k::BONDING_CURVE), true),
    Slot(Want::Pin(k::ASSOC_BASE_BONDING_CURVE), true),
    Slot(Want::Pin(k::ASSOC_QUOTE_BONDING_CURVE), true),
    Slot(Want::Pin(k::BUYBACK_AUTHORITY), true),
    Slot(Want::Pin(k::BB_SIJKA), true),
    Slot(Want::Pin(k::BB_QUOTE), true),
    Slot(Want::Late, true),
    Slot(Want::Late, true),
    Slot(Want::Pin(k::SHARING_CONFIG), false),
    Slot(Want::Key(&PUMP_GVA), false),
    Slot(Want::Pin(k::PUMP_USER_VOLUME_ACC), true),
    Slot(Want::Pin(k::PUMP_ASSOC_USER_VOLUME_ACC), true),
    Slot(Want::Key(&PUMP_FEE_CONFIG), false),
    Slot(Want::Prog(&PUMP_FEES_PROGRAM), false),
    Slot(Want::Prog(&SYSTEM_PROGRAM_ID), false),
    Slot(Want::Key(&PUMP_EVENT_AUTHORITY), false),
    Slot(Want::Prog(&PUMP_PROGRAM), false),
];

/// Tag 45, outer accounts 4..=29 (SPEC §5.5.3, PumpSwap + r1–r3).
const AMM_TABLE: [Slot; 26] = [
    Slot(Want::Pin(k::POOL), true),
    Slot(Want::Pin(k::BUYBACK_AUTHORITY), true),
    Slot(Want::Key(&AMM_GLOBAL_CONFIG), false),
    Slot(Want::Pin(k::MINT), true),
    Slot(Want::Pin(k::QUOTE_MINT), false),
    Slot(Want::Pin(k::BB_SIJKA), true),
    Slot(Want::Pin(k::BB_QUOTE), true),
    Slot(Want::Pin(k::POOL_BASE_TA), true),
    Slot(Want::Pin(k::POOL_QUOTE_TA), true),
    Slot(Want::Free, false),
    Slot(Want::Free, true),
    Slot(Want::PinProg(k::BASE_TOKEN_PROGRAM), false),
    Slot(Want::Prog(&SPL_TOKEN_PROGRAM_ID), false),
    Slot(Want::Prog(&SYSTEM_PROGRAM_ID), false),
    Slot(Want::Prog(&ATA_PROGRAM_ID), false),
    Slot(Want::Key(&AMM_EVENT_AUTHORITY), false),
    Slot(Want::Prog(&PUMP_AMM_PROGRAM), false),
    Slot(Want::Late, true),
    Slot(Want::Late, false),
    Slot(Want::Key(&AMM_GVA), false),
    Slot(Want::Pin(k::AMM_USER_VOLUME_ACC), true),
    Slot(Want::Key(&AMM_FEE_CONFIG), false),
    Slot(Want::Prog(&PUMP_FEES_PROGRAM), false),
    Slot(Want::Pin(k::POOL_V2), false),
    Slot(Want::Free, false),
    Slot(Want::Free, true),
];

/// Outer indices used by the chunk flow.
struct ChunkIdx {
    user: usize,
    base_mint: usize,
    quote_mint: usize,
    base_tp: usize,
    quote_tp: usize,
    bb_token: usize,
    bb_quote: usize,
    /// Curve: bonding curve; AMM: pool.
    market: usize,
    /// AMM: pool token accounts (unused on the curve).
    pool_base_ta: usize,
    pool_quote_ta: usize,
    /// Creator vault slots: curve (vault, ata); AMM (ata, authority).
    vault_a: usize,
    vault_b: usize,
}

const CURVE_IDX: ChunkIdx = ChunkIdx {
    user: 17,
    base_mint: 5,
    quote_mint: 6,
    base_tp: 7,
    quote_tp: 8,
    bb_token: 18,
    bb_quote: 19,
    market: 14,
    pool_base_ta: 0,
    pool_quote_ta: 0,
    vault_a: 20,
    vault_b: 21,
};

const AMM_IDX: ChunkIdx = ChunkIdx {
    user: 5,
    base_mint: 7,
    quote_mint: 8,
    base_tp: 15,
    quote_tp: 16,
    bb_token: 9,
    bb_quote: 10,
    market: 4,
    pool_base_ta: 11,
    pool_quote_ta: 12,
    vault_a: 21,
    vault_b: 22,
};

/// First outer index of the pump accounts.
const PUMP_FIRST: usize = 4;

/// The pump accounts of a chunk (outer `4..4 + table.len()`) and the keeper
/// signer right after them (SPEC v4: #31 on the curve, #30 on PumpSwap). The
/// keeper is never passed to pump.
fn chunk_split(accounts: &[AccountInfo], table_len: usize) -> Result<(&[AccountInfo], &AccountInfo), ProgramError> {
    let end = PUMP_FIRST.checked_add(table_len).ok_or_else(|| SijkaError::InvalidAccountCount.fail())?;
    let pump = accounts.get(PUMP_FIRST..end).ok_or_else(|| SijkaError::InvalidAccountCount.fail())?;
    let keeper = acc(accounts, end)?;
    if accounts.len() != end.checked_add(1).ok_or_else(|| SijkaError::InvalidAccountCount.fail())? {
        return Err(SijkaError::InvalidAccountCount.fail());
    }
    Ok((pump, keeper))
}

/// Check the pump slots against the table (keys, programs, writability).
fn check_table(pump: &[AccountInfo], table: &[Slot], bs: &BuybackState<'_>, ours: &[&Pubkey]) -> ProgramResult {
    if pump.len() != table.len() {
        return Err(SijkaError::InvalidAccountCount.fail());
    }
    for (a, slot) in pump.iter().zip(table) {
        match slot.0 {
            Want::Pin(i) => expect_pinned(a, pin(bs, i)?)?,
            Want::PinProg(i) => {
                expect_pinned(a, pin(bs, i)?)?;
                if !a.executable() {
                    return Err(SijkaError::InvalidProgramId.fail());
                }
            }
            Want::Key(c) => expect_pinned(a, c)?,
            Want::Prog(c) => expect_program(a, c)?,
            Want::Free => expect_not_in(a.key(), ours, SijkaError::BbPinnedAccountMismatch)?,
            Want::Late => {}
        }
        if slot.1 {
            expect_writable(a)?;
        }
    }
    Ok(())
}

/// Everything the chunk flow keeps across the pump CPI.
struct ChunkPrep {
    plan: ChunkPlan,
    p_now: u128,
    is_sol: bool,
    decimals: u8,
    bump_k0: u8,
    buy_min_interval_s: u32,
    lam_before: u64,
    quote: QuoteSnap,
    base_before: u64,
}

/// Tag 44 `bb_chunk_curve` (SPEC §5.5.8): one chunk on the bonding curve
/// (`buy_exact_quote_in_v2`), then burn the whole SIJKA balance. Keeper only
/// (SPEC v4, DECISIONS §23 item 3).
#[inline(never)]
pub fn bb_chunk_curve(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    check_shape(&BB_CHUNK_CURVE, accounts, data)?;
    let env = load_env()?;
    let rent0 = rent_exempt_minimum(0)?;
    bb_chunk_with(program_id, accounts, data, env, rent0, false)
}

/// Tag 45 `bb_chunk_amm` (SPEC §5.5.9): one chunk in the canonical PumpSwap
/// pool (`buy_exact_quote_in`), then burn the whole SIJKA balance. Keeper only
/// (SPEC v4, DECISIONS §23 item 3).
#[inline(never)]
pub fn bb_chunk_amm(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    check_shape(&BB_CHUNK_AMM, accounts, data)?;
    let env = load_env()?;
    let rent0 = rent_exempt_minimum(0)?;
    bb_chunk_with(program_id, accounts, data, env, rent0, true)
}

pub(crate) fn bb_chunk_with(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    env: Env,
    rent0: u64,
    amm: bool,
) -> ProgramResult {
    let prep = chunk_prepare(program_id, accounts, data, env, rent0, amm)?;
    let (pump, _keeper) = chunk_split(accounts, if amm { AMM_TABLE.len() } else { CURVE_TABLE.len() })?;
    let pda = PdaSeeds::new(SEED_BUYBACK_AUTHORITY, prep.bump_k0);
    let seeds = pda.seeds();
    let signer = [Signer::from(&seeds)];
    if amm {
        buy_exact_quote_in(pump, prep.plan.v, prep.plan.min_out, &signer)?;
    } else {
        buy_exact_quote_in_v2(pump, prep.plan.v, prep.plan.min_out, &signer)?;
    }
    chunk_finish(accounts, env, rent0, amm, &prep)
}

#[inline(never)]
fn chunk_prepare(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    env: Env,
    rent0: u64,
    amm: bool,
) -> Result<ChunkPrep, ProgramError> {
    let (idx, table, tag, want_venue): (&ChunkIdx, &[Slot], u8, u8) = if amm {
        (&AMM_IDX, AMM_TABLE.as_slice(), BB_CHUNK_AMM.tag, bb_venue::AMM)
    } else {
        (&CURVE_IDX, CURVE_TABLE.as_slice(), BB_CHUNK_CURVE.tag, bb_venue::CURVE)
    };
    let state = acc(accounts, 0)?;
    let config = acc(accounts, 1)?;
    let ix_sysvar = acc(accounts, 2)?;
    let dont_front = acc(accounts, 3)?;
    let (pump, keeper) = chunk_split(accounts, table.len())?;
    let max_quote_in = data_u64(data, 1)?;
    let min_out_keeper = data_u64(data, 9)?;

    let bs_key = {
        let d = load_config(config, program_id)?;
        let cfg = config_view(&d)?;
        // SPEC v4 (DECISIONS §23 items 3 and 6): only the keeper key runs a
        // chunk, with its own floor from its quote at the live price (a floor
        // of zero is not a floor).
        check_keeper(keeper, &cfg)?;
        if min_out_keeper == 0 {
            return Err(bad_data());
        }
        *cfg.buyback_state()
    };
    let sd = load_buyback_state_mut(state, program_id, Some(&bs_key))?;
    let bs = view(&sd)?;
    if !bs.is_pinned() {
        return Err(SijkaError::BbNotPinned.fail());
    }
    if bs.venue() != want_venue {
        return Err(SijkaError::BbVenueMismatch.fail());
    }
    expect_key(dont_front, &JITO_DONT_FRONT, SijkaError::BbMissingDontFront)?;
    let k0 = pin(&bs, k::BUYBACK_AUTHORITY)?;
    let k5 = pin(&bs, k::BB_WSOL)?;
    // Our accounts that no pump-checked slot may alias.
    let ours: [&Pubkey; 9] = [
        state.key(),
        config.key(),
        k0,
        pin(&bs, k::SWAP_AUTHORITY)?,
        pin(&bs, k::BB_UNWRAP)?,
        pin(&bs, k::BB_USDC)?,
        pin(&bs, k::SWAP_USDC)?,
        if is_zero_key(k5) { k0 } else { k5 },
        pin(&bs, k::BB_SIJKA)?,
    ];
    check_table(pump, table, &bs, &ours)?;
    let at = |i: usize| acc(accounts, i);
    let user = at(idx.user)?;
    expect_authority_clean(user, SijkaError::InvalidExternalAccount)?;
    let k6 = pin(&bs, k::MINT)?;
    let k7 = pin(&bs, k::BASE_TOKEN_PROGRAM)?;
    if !at(idx.base_mint)?.is_owned_by(k7) {
        return Err(SijkaError::InvalidTokenMint.fail());
    }
    require_sole_top_level(ix_sysvar, program_id, tag)?;

    // Our token accounts (full check_token, review RT-2).
    let (k8, is_sol) = quote_of(&bs)?;
    let bb_token = at(idx.bb_token)?;
    if account_missing(bb_token) {
        return Err(SijkaError::BbBaseAtaMissing.fail());
    }
    let base_before = check_token(bb_token, k7, k6, k0, false, SijkaError::InvalidTokenAccount)?;
    let bb_quote = at(idx.bb_quote)?;
    let quote = if account_missing(bb_quote) {
        // Only the SOL curve may run without bb_wsol (pump spends lamports there).
        if amm || !is_sol {
            return Err(SijkaError::BbQuoteAtaMissing.fail());
        }
        QuoteSnap { existed: false, amount: 0 }
    } else {
        let amount = check_token(bb_quote, &SPL_TOKEN_PROGRAM_ID, &k8, k0, is_sol, SijkaError::InvalidTokenAccount)?;
        QuoteSnap { existed: true, amount }
    };

    // Market: working-mode coin checks, creator vault from the live creator (ACC-2).
    let usdc_mint = *bs.usdc_mint();
    let usdc_quote = if is_sol { None } else { Some(&usdc_mint) };
    let k14 = pin(&bs, k::SHARING_CONFIG)?;
    // `p_now` goes to the event only (SPEC v4: no spot guard).
    let (p_now, q_now, curve) = if amm {
        let pins = PoolPins {
            pool_authority: pin(&bs, k::POOL_AUTHORITY)?,
            mint: k6,
            base_token_program: k7,
            quote_mint: &k8,
            base_ta: pin(&bs, k::POOL_BASE_TA)?,
            quote_ta: pin(&bs, k::POOL_QUOTE_TA)?,
            sharing_config: k14,
        };
        let r = read_pool(at(idx.market)?, at(idx.pool_base_ta)?, at(idx.pool_quote_ta)?, &pins, CoinCheck::Working)
            .map_err(fail)?;
        let (authority, ata) = coin_creator_vault_for(
            &r.fields.coin_creator,
            k14,
            pin(&bs, k::COIN_CREATOR_VAULT_AUTHORITY)?,
            pin(&bs, k::COIN_CREATOR_VAULT_ATA)?,
            &k8,
        )?;
        expect_pinned(at(idx.vault_a)?, &ata)?;
        expect_pinned(at(idx.vault_b)?, &authority)?;
        (price_x64(r.quote, r.base).map_err(fail)?, r.quote, None)
    } else {
        let f = read_curve(at(idx.market)?, CoinCheck::Basic, k14, usdc_quote).map_err(fail)?;
        if f.is_complete() {
            return Err(SijkaError::BbVenueSwitchPending.fail());
        }
        check_curve_coin(&f, CoinCheck::Working, k14, usdc_quote).map_err(fail)?;
        let (vault, ata) =
            creator_vault_for(&f.creator, k14, pin(&bs, k::CREATOR_VAULT)?, pin(&bs, k::ASSOC_CREATOR_VAULT)?, &k8)?;
        expect_pinned(at(idx.vault_a)?, &vault)?;
        expect_pinned(at(idx.vault_b)?, &ata)?;
        let c = CurveReserves {
            virtual_token: f.virtual_token_reserves,
            virtual_quote: f.virtual_quote_reserves,
            real_token: f.real_token_reserves,
        };
        (price_x64(f.virtual_quote_reserves, f.virtual_token_reserves).map_err(fail)?, c.virtual_quote, Some(c))
    };

    // Budget (SPEC §5.5.2 table `avail`).
    let res = reserve(rent0).map_err(fail)?;
    let lamports = user.lamports();
    let (avail, float_ok) = if !is_sol {
        // Audit EA-1: rent(0) only. Pump's rent is bounded after the CPI
        // (`≤ MAX_RENT_EXTRA`, `lam_after ≥ rent0`) and a CPI short of
        // lamports reverts; requiring RESERVE would stop every chunk for good
        // once pump rent has eaten the float above it.
        (quote.amount, lamports >= rent0)
    } else if amm {
        (add(lamports, quote.amount)?.saturating_sub(res), true)
    } else {
        (lamports.saturating_sub(res), true)
    };
    let params = bs.buyback_params();
    let inputs = ChunkInputs {
        obs_init: bs.flags() & bb_flags::OBS_INIT != 0,
        fresh_obs: bs.fresh_obs(),
        last_obs_ts: bs.last_obs_ts(),
        last_obs_slot: bs.last_obs_slot(),
        ema: bs.ema_price_x64(),
        last_obs_price: bs.last_obs_price_x64(),
        last_obs_quote: bs.last_obs_quote(),
        q_ema: bs.q_ema(),
        next_buy_ts: bs.next_buy_ts(),
        last_buy_slot: bs.last_buy_slot(),
        warmup_obs: params.warmup_obs(),
        obs_max_age_s: params.obs_max_age_s(),
        chunk_bps: params.chunk_bps(),
        chunk_max_quote: params.chunk_max_quote(),
        chunk_min_quote: params.chunk_min_quote(),
        now: env.now,
        slot: env.slot,
        q_now,
        curve,
        avail,
        float_ok,
        max_quote_in,
        min_out_keeper,
    };
    let plan = plan_chunk(&inputs).map_err(fail)?;
    let decimals = bs.base_decimals();
    let bump_k0 = bs.bump_buyback_authority();
    let buy_min_interval_s = params.buy_min_interval_s();
    let k0_key = *k0;
    drop(sd);

    // SOL on PumpSwap: wrap exactly the shortfall into bb_wsol.
    let mut quote = quote;
    if amm && is_sol {
        let need = plan.v.saturating_sub(quote.amount);
        if need > 0 {
            let pda = PdaSeeds::new(SEED_BUYBACK_AUTHORITY, bump_k0);
            let seeds = pda.seeds();
            let signer = [Signer::from(&seeds)];
            system_transfer(user, bb_quote, need, &signer)?;
            sync_native(at(idx.quote_tp)?, bb_quote)?;
        }
        quote.amount =
            check_token(bb_quote, &SPL_TOKEN_PROGRAM_ID, &WSOL_MINT, &k0_key, true, SijkaError::InvariantViolated)?;
        if quote.amount < plan.v {
            return Err(SijkaError::InvariantViolated.fail());
        }
    }
    Ok(ChunkPrep {
        plan,
        p_now,
        is_sol,
        decimals,
        bump_k0,
        buy_min_interval_s,
        lam_before: user.lamports(),
        quote,
        base_before,
    })
}

#[inline(never)]
fn chunk_finish(accounts: &[AccountInfo], env: Env, rent0: u64, amm: bool, prep: &ChunkPrep) -> ProgramResult {
    let idx = if amm { &AMM_IDX } else { &CURVE_IDX };
    let at = |i: usize| acc(accounts, i);
    let state = at(0)?;
    let user = at(idx.user)?;
    let bb_token = at(idx.bb_token)?;
    let bb_quote = at(idx.bb_quote)?;
    let mint = at(idx.base_mint)?;
    let base_tp = at(idx.base_tp)?;
    let sol_curve = !amm && prep.is_sol;
    // Tamper checks first (review RT-2), then balances, then the burn.
    let after = check_after_pump(
        user,
        bb_token,
        base_tp.key(),
        mint.key(),
        bb_quote,
        at(idx.quote_mint)?.key(),
        prep.is_sol,
        prep.quote,
        sol_curve,
    )?;
    let lam_after = user.lamports();
    let v = prep.plan.v;
    let (quote_spent, rent_extra) = if sol_curve {
        settle_sol_curve(v, prep.lam_before, lam_after, MAX_RENT_EXTRA)
    } else {
        settle_token_quote(v, prep.quote.amount, after.quote, prep.lam_before, lam_after, MAX_RENT_EXTRA)
    }
    .map_err(fail)?;
    if lam_after < rent0 {
        return Err(SijkaError::BbOverspend.fail());
    }
    let bought = after.base.checked_sub(prep.base_before).ok_or_else(|| SijkaError::InvariantViolated.fail())?;
    if bought < prep.plan.min_out {
        return Err(SijkaError::BbSlippage.fail());
    }
    let burned = burn_all(base_tp, bb_token, mint, user, prep.decimals, prep.bump_k0)?;
    let next_buy = next_ts(env.now, prep.buy_min_interval_s, quote_spent, prep.plan.v_cap).map_err(fail)?;

    let (cum_burned, cum_payout, n_chunks) = {
        let mut sd = state.try_borrow_mut_data()?;
        let mut m = view_mut(&mut sd)?;
        let s = m.view();
        let n_chunks = add(s.n_chunks(), 1)?;
        let cum_rent = add(s.cum_rent_spent(), rent_extra)?;
        let cum_bought = add(s.cum_bought_tokens(), bought)?;
        let cum_burned = add(s.cum_burned_tokens(), burned)?;
        let cum_payout =
            if prep.is_sol { s.cum_payout_buyback_spent() } else { add(s.cum_payout_buyback_spent(), quote_spent)? };
        let cum_venue =
            if amm { add(s.cum_quote_spent_amm(), quote_spent)? } else { add(s.cum_quote_spent_curve(), quote_spent)? };
        m.set_last_buy_ts(env.now);
        m.set_next_buy_ts(next_buy);
        m.set_last_buy_slot(env.slot);
        m.set_n_chunks(n_chunks);
        if amm {
            m.set_cum_quote_spent_amm(cum_venue);
        } else {
            m.set_cum_quote_spent_curve(cum_venue);
        }
        m.set_cum_rent_spent(cum_rent);
        m.set_cum_bought_tokens(cum_bought);
        m.set_cum_burned_tokens(cum_burned);
        m.set_cum_payout_buyback_spent(cum_payout);
        (cum_burned, cum_payout, n_chunks)
    };
    EvChunk {
        ts: env.now,
        venue: if amm { bb_venue::AMM } else { bb_venue::CURVE },
        v,
        quote_spent,
        rent_extra,
        min_out: prep.plan.min_out,
        bought,
        burned,
        p_now: prep.p_now,
        p_ref: prep.plan.p_ref,
        q_ref: prep.plan.q_ref,
        slot: env.slot,
        cum_burned_tokens: cum_burned,
        cum_payout_buyback_spent: cum_payout,
        n_chunks,
    }
    .emit()
}

// --------------------------------------------------------- tag 46 ----

/// Tag 46 `bb_burn` (SPEC §5.5.10): burn the whole SIJKA balance of
/// `buyback_token` (donations, leftovers). Zero balance: Ok without event.
#[inline(never)]
pub fn bb_burn(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    check_shape(&BB_BURN, accounts, data)?;
    let env = load_env()?;
    bb_burn_with(program_id, accounts, env)
}

pub(crate) fn bb_burn_with(program_id: &Pubkey, accounts: &[AccountInfo], env: Env) -> ProgramResult {
    let [state, authority, bb_token, mint, token_program] = accounts else {
        return Err(SijkaError::InvalidAccountCount.fail());
    };
    let (decimals, bump) = {
        let sd = load_buyback_state_mut(state, program_id, None)?;
        let bs = view(&sd)?;
        if !bs.is_pinned() {
            return Err(SijkaError::BbNotPinned.fail());
        }
        let k0 = pin(&bs, k::BUYBACK_AUTHORITY)?;
        let k6 = pin(&bs, k::MINT)?;
        let k7 = pin(&bs, k::BASE_TOKEN_PROGRAM)?;
        expect_pinned(authority, k0)?;
        expect_authority_clean(authority, SijkaError::InvalidExternalAccount)?;
        expect_pinned(bb_token, pin(&bs, k::BB_SIJKA)?)?;
        expect_writable(bb_token)?;
        check_token(bb_token, k7, k6, k0, false, SijkaError::InvalidTokenAccount)?;
        expect_pinned(mint, k6)?;
        expect_writable(mint)?;
        if !mint.is_owned_by(k7) {
            return Err(SijkaError::InvalidTokenMint.fail());
        }
        expect_pinned(token_program, k7)?;
        if !token_program.executable() {
            return Err(SijkaError::InvalidProgramId.fail());
        }
        (bs.base_decimals(), bs.bump_buyback_authority())
    };
    let burned = burn_all(token_program, bb_token, mint, authority, decimals, bump)?;
    if burned == 0 {
        return Ok(());
    }
    let cum = {
        let mut sd = state.try_borrow_mut_data()?;
        let mut m = view_mut(&mut sd)?;
        let cum = add(m.view().cum_burned_tokens(), burned)?;
        m.set_cum_burned_tokens(cum);
        cum
    };
    EvBurn { ts: env.now, amount: burned, cum_burned_tokens: cum }.emit()
}
