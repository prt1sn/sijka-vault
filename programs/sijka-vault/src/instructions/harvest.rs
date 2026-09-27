// Copyright (c) 2026 prt1sn. All rights reserved.
//! Profit accounting instructions, tags 30–32 (SPEC §5.4).
//!
//! - Tag 30 `harvest` (permissionless): pays the realized profit above the
//!   high-water mark, `D = min(D* − ε, W − buf, max_harvest_per_call, Q)`
//!   with `D* = C − I + min(0, U + F)` (pure math in `crate::accounting`).
//!   Money path: trader collateral →(`withdraw_funds(D)`)→ `vault_phusd` (Δ r)
//!   →(Ember `withdraw(Some(r))`)→ `vault_usdc` (Δ u) → 20% `creator_escrow_usdc`
//!   and 80% `buyback_usdc`. Every delta is verified in the same instruction;
//!   `vault_phusd` / `vault_usdc` end at their starting balances, so donations
//!   there are neither paid out nor taken.
//! - Tag 31 `harvest_preview` (permissionless, read-only): the same
//!   computation, status and numbers in 168 bytes of return data.
//! - Tag 32 `pay_creator` (permissionless): moves the whole escrow balance to
//!   the fixed `creator_usdc` (review ACC-3). Nothing else can move it.
//!
//! No path here sends funds anywhere but `creator_escrow_usdc`, `buyback_usdc`
//! and `creator_usdc`, all pinned in `Config` at `initialize`
//! (DECISIONS §2.1). `creator_payout` is only read.
//!
//! Every handler runs `check_shape` first. Account checks owned by this module
//! run before the shared Phoenix checks, so each of them is host-testable.

use pinocchio::ProgramResult;
use pinocchio::account_info::AccountInfo;
use pinocchio::instruction::Signer;
use pinocchio::program_error::ProgramError;
use pinocchio::pubkey::{Pubkey, pubkey_eq};

use crate::accounting::preview::{HarvestPreviewData, bits};
use crate::accounting::{
    GateInputs, HarvestCalc, HarvestStatus, Ledger, MarkScan, Payout, QueueState, check_ember_arrival,
    check_nothing_queued, check_withdraw_arrival, compute_harvest, early_gate, parse_withdraw_queue, preview_status,
    risk_ok, scan_position_marks, split_payout,
};
use crate::constants::{
    EMBER_PROGRAM_ID, GC_MIN_LEN_WITH_COOLDOWN, HAWKEYE_PROGRAM_ID, PHOENIX_LOG_AUTHORITY, PHOENIX_PROGRAM_ID,
    SEED_CREATOR_ESCROW, SEED_PHX_AUTHORITY, SPL_TOKEN_PROGRAM_ID, TOKEN_ACCOUNT_LEN,
};
use crate::cpi::PdaSeeds;
use crate::cpi::ember::EmberAccounts;
use crate::cpi::hawkeye::{HawkeyeAccounts, MarginView, view_margin};
use crate::cpi::phoenix_withdraw::{
    WithdrawAccounts, check_ember_state, check_ember_vault, ember_withdraw, withdraw_funds,
};
use crate::cpi::token;
use crate::error::SijkaError;
use crate::events::{EvHarvest, EvPayCreator};
use crate::external::layout::{global_config as gcl, token_account as ta};
use crate::external::phoenix_accounts::{
    PamCheck, TraderCheck, check_arenas, check_global_config, check_perp_asset_map, check_trader_account, trader_header,
};
use crate::instructions::{HARVEST, HARVEST_PREVIEW, PAY_CREATOR, ShapeInfo, check_shape};
use crate::state::config::harvest_params::HarvestParams;
use crate::state::config::{Config, ConfigMut, config_view, config_view_mut, load_config, load_config_mut};
use crate::util::accounts::{
    check_token, expect_key, expect_program, expect_system_empty, expect_writable, token_account_fields_ok,
};
use crate::util::bytes::{is_zero_key, read_u64};
use crate::util::math::{add_u64, i128_to_u64, saturate_i64, saturate_u64};
use crate::util::runtime::{clock, emit, set_return_data};

// ------------------------------------------------------ token checks ----

/// A vault token account of `phx_authority` (`vault_phusd`, `vault_usdc`):
/// key from `Config` (`InvalidPda`), writable, SPEC §3.9 `check_token`
/// under Tokenkeg (`InvalidTokenAccount`). Returns the balance.
fn check_vault_token(ai: &AccountInfo, key: &Pubkey, mint: &Pubkey, authority: &Pubkey) -> Result<u64, ProgramError> {
    expect_key(ai, key, SijkaError::InvalidPda)?;
    expect_writable(ai)?;
    vault_amount(ai, mint, authority)
}

/// Balance of an already checked vault token account, re-validated (used
/// after each CPI).
#[inline]
fn vault_amount(ai: &AccountInfo, mint: &Pubkey, authority: &Pubkey) -> Result<u64, ProgramError> {
    check_token(ai, &SPL_TOKEN_PROGRAM_ID, mint, authority, false, SijkaError::InvalidTokenAccount)
}

/// A payout token account (`creator_escrow_usdc`, `buyback_usdc`): every
/// check of the row, including the key, gives `e` (SPEC §5.4.2 #18/#19,
/// TH-8): key from `Config`, owner Tokenkeg, length 165, `mint`, `owner@32 ==
/// authority`, no delegate, no close authority, initialized (not frozen).
/// Writable (`AccountNotWritable`). Returns the balance.
fn check_payout_token(
    ai: &AccountInfo,
    key: &Pubkey,
    mint: &Pubkey,
    authority: &Pubkey,
    e: SijkaError,
) -> Result<u64, ProgramError> {
    expect_key(ai, key, e)?;
    expect_writable(ai)?;
    check_token(ai, &SPL_TOKEN_PROGRAM_ID, mint, authority, false, e)
}

/// Tag 32 `creator_usdc` (SPEC §5.4.5 #3): key `cfg.creator_usdc`, owner
/// Tokenkeg, length 165, `mint == usdc_mint`, `owner@32 == creator_payout`,
/// initialized; else `CreatorAtaInvalid`. Delegate / close authority are the
/// recipient's business and not checked. Writable. Returns the balance.
fn check_creator_usdc(ai: &AccountInfo, key: &Pubkey, mint: &Pubkey, payout: &Pubkey) -> Result<u64, ProgramError> {
    let e = SijkaError::CreatorAtaInvalid;
    expect_key(ai, key, e)?;
    expect_writable(ai)?;
    if !ai.is_owned_by(&SPL_TOKEN_PROGRAM_ID) || ai.data_len() != TOKEN_ACCOUNT_LEN {
        return Err(e.fail());
    }
    let data = ai.try_borrow_data()?;
    token_account_fields_ok(&data, mint, Some(payout), false, false).ok_or_else(|| e.fail())
}

/// Preview only (tag 31 #7): balance of `buyback_usdc` if it is a Tokenkeg
/// account of the right size, else 0 (a missing account reads as 0, SPEC §5.4.3).
fn lenient_amount(ai: &AccountInfo) -> Result<u64, ProgramError> {
    if !ai.is_owned_by(&SPL_TOKEN_PROGRAM_ID) || ai.data_len() != TOKEN_ACCOUNT_LEN {
        return Ok(0);
    }
    let data = ai.try_borrow_data()?;
    Ok(read_u64(&data, ta::AMOUNT).unwrap_or(0))
}

#[inline]
fn fail(e: SijkaError) -> ProgramError {
    e.fail()
}

// --------------------------------------------------- shared computation ----

/// Phoenix-side inputs read after the account checks (SPEC §5.4.2 steps 2–5, 7).
struct PhoenixState {
    gates: GateInputs,
    /// `C_hdr = trader i64@88`.
    c_hdr: i64,
}

/// `WithdrawQueueHeader` of `withdraw_queue` (key checked by the caller).
/// The borrow is released on return.
#[inline(never)]
fn read_queue(withdraw_queue: &AccountInfo, slot: u64) -> Result<QueueState, ProgramError> {
    let wq = withdraw_queue.try_borrow_data()?;
    Ok(parse_withdraw_queue(withdraw_queue.owner(), &wq, slot))
}

/// Read the gate inputs (GC cooldown `@512`, trader `@192`, the
/// withdraw-queue header) and `C_hdr`. Borrows are released on return.
#[allow(clippy::too_many_arguments)]
fn read_phoenix_state(
    cfg: &Config<'_>,
    p: &HarvestParams<'_>,
    global_config: &AccountInfo,
    trader_account: &AccountInfo,
    withdraw_queue: &AccountInfo,
    buyback_usdc: u64,
    now: i64,
    slot: u64,
) -> Result<PhoenixState, ProgramError> {
    let cooldown_slots = {
        let gc = global_config.try_borrow_data()?;
        read_u64(&gc, gcl::DEPOSIT_COOLDOWN_SLOTS).ok_or_else(|| fail(SijkaError::InvalidPhoenixGlobalConfig))?
    };
    let queue = read_queue(withdraw_queue, slot)?;
    let hdr = {
        let trader = trader_account.try_borrow_data()?;
        trader_header(&trader).ok_or_else(|| fail(SijkaError::InvalidPhoenixTraderAccount))?
    };
    let gates = GateInputs {
        recovery_mode: cfg.recovery_mode(),
        now,
        last_harvest_ts: cfg.last_harvest_ts(),
        t_min_secs: p.t_min_secs(),
        max_buyback_backlog: p.max_buyback_backlog(),
        buyback_usdc,
        cooldown_slots,
        last_deposit_slot: hdr.last_deposit_slot,
        slot,
        queue,
    };
    Ok(PhoenixState { gates, c_hdr: hdr.collateral })
}

/// Step 6 (review ACC-9): mark scan of the position map, `None` when
/// `harvest_mark_max_age_slots == 0` (check disabled).
fn scan_marks(
    trader_account: &AccountInfo,
    perp_asset_map: &AccountInfo,
    slot: u64,
    max_age: u64,
) -> Result<Option<MarkScan>, ProgramError> {
    if max_age == 0 {
        return Ok(None);
    }
    let trader = trader_account.try_borrow_data()?;
    let pam = perp_asset_map.try_borrow_data()?;
    scan_position_marks(&trader, &pam, slot, max_age).map(Some).map_err(fail)
}

/// Hawkeye counts more markets (positions or resting orders) than the map
/// scan found (review RT-3): bit2 of the event and the preview (reference
/// only; step 8a checks the flat records in every case, full audit FA-4).
#[inline]
fn pc_above_scan(scan: &Option<MarkScan>, m: &MarginView) -> bool {
    scan.is_some_and(|s| u32::from(m.position_count) > s.positions)
}

/// Step 8a (review RT-3, SPEC §5.4.2): map records counted as stale because
/// a position the map does not show yet may sit there
/// ([`MarkScan::hidden_stale`]); 0 when the mark check is off.
#[inline]
fn hidden_stale(scan: &Option<MarkScan>, m: &MarginView) -> u32 {
    scan.map_or(0, |s| s.hidden_stale(m.position_count))
}

/// `bits` of the event and the preview.
#[inline]
fn calc_bits(calc: &HarvestCalc, pc_above_scan: bool) -> u8 {
    let mut b = 0u8;
    if calc.queue_limited() {
        b |= bits::QUEUE_LIMITED;
    }
    if calc.timer_held {
        b |= bits::TIMER_HELD;
    }
    if pc_above_scan {
        b |= bits::PC_ABOVE_SCAN;
    }
    b
}

// --------------------------------------------------------------- tag 30 ----

/// Accounts of tag 30 (SPEC §5.4.2 table).
struct HarvestAccounts<'a> {
    config: &'a AccountInfo,
    phx_authority: &'a AccountInfo,
    phoenix_program: &'a AccountInfo,
    hawkeye_program: &'a AccountInfo,
    ember_program: &'a AccountInfo,
    log_authority: &'a AccountInfo,
    global_config: &'a AccountInfo,
    trader_account: &'a AccountInfo,
    perp_asset_map: &'a AccountInfo,
    global_vault: &'a AccountInfo,
    withdraw_queue: &'a AccountInfo,
    usdc_mint: &'a AccountInfo,
    phusd_mint: &'a AccountInfo,
    vault_phusd: &'a AccountInfo,
    vault_usdc: &'a AccountInfo,
    ember_state: &'a AccountInfo,
    ember_vault: &'a AccountInfo,
    token_program: &'a AccountInfo,
    creator_escrow_usdc: &'a AccountInfo,
    buyback_usdc: &'a AccountInfo,
    /// `[GTI…, ATB…]`.
    arenas: &'a [AccountInfo],
    gti: &'a [AccountInfo],
    atb: &'a [AccountInfo],
}

impl<'a> HarvestAccounts<'a> {
    fn parse(accounts: &'a [AccountInfo], info: ShapeInfo) -> Result<Self, ProgramError> {
        let [
            config,
            phx_authority,
            phoenix_program,
            hawkeye_program,
            ember_program,
            log_authority,
            global_config,
            trader_account,
            perp_asset_map,
            global_vault,
            withdraw_queue,
            usdc_mint,
            phusd_mint,
            vault_phusd,
            vault_usdc,
            ember_state,
            ember_vault,
            token_program,
            creator_escrow_usdc,
            buyback_usdc,
            arenas @ ..,
        ] = accounts
        else {
            return Err(fail(SijkaError::InvalidAccountCount));
        };
        let (gti, atb) = arenas.split_at_checked(info.gti).ok_or_else(|| fail(SijkaError::InvalidAccountCount))?;
        Ok(Self {
            config,
            phx_authority,
            phoenix_program,
            hawkeye_program,
            ember_program,
            log_authority,
            global_config,
            trader_account,
            perp_asset_map,
            global_vault,
            withdraw_queue,
            usdc_mint,
            phusd_mint,
            vault_phusd,
            vault_usdc,
            ember_state,
            ember_vault,
            token_program,
            creator_escrow_usdc,
            buyback_usdc,
            arenas,
            gti,
            atb,
        })
    }
}

/// Everything tag 30 needs after the pre-CPI phase (copied out of `Config`,
/// so no borrow is held across the CPIs except the `config` RefMut, which is
/// not passed to any CPI).
struct HarvestPlan {
    now: i64,
    slot: u64,
    phx_authority_bump: u8,
    phx_authority: Pubkey,
    usdc_mint: Pubkey,
    phusd_mint: Pubkey,
    i: u64,
    ledger: Ledger,
    m: MarginView,
    c_hdr: i64,
    calc: HarvestCalc,
    /// Queue header before the CPI (step 5; step 13a compares).
    queue: QueueState,
    bits: u8,
    /// Requested amount `D` (≥ `d_min` ≥ 1).
    d: u64,
}

/// Account checks owned by this module (step 1, first part). They run
/// before the shared Phoenix checks. Returns the `buyback_usdc` balance.
fn check_own_accounts_30(a: &HarvestAccounts<'_>, cfg: &Config<'_>) -> Result<u64, ProgramError> {
    expect_key(a.phx_authority, cfg.phx_authority(), SijkaError::InvalidPda)?;
    expect_program(a.phoenix_program, &PHOENIX_PROGRAM_ID)?;
    expect_program(a.hawkeye_program, &HAWKEYE_PROGRAM_ID)?;
    expect_program(a.ember_program, &EMBER_PROGRAM_ID)?;
    expect_key(a.log_authority, &PHOENIX_LOG_AUTHORITY, SijkaError::InvalidExternalAccount)?;
    expect_key(a.usdc_mint, cfg.usdc_mint(), SijkaError::InvalidExternalAccount)?;
    // PhUSD mint: `== cfg.phusd_mint` here, `== GC@296` after the GC check;
    // writable (Ember burns PhUSD).
    expect_key(a.phusd_mint, cfg.phusd_mint(), SijkaError::InvalidPhoenixGlobalConfig)?;
    expect_writable(a.phusd_mint)?;
    check_vault_token(a.vault_phusd, cfg.vault_phusd(), cfg.phusd_mint(), cfg.phx_authority())?;
    check_vault_token(a.vault_usdc, cfg.vault_usdc(), cfg.usdc_mint(), cfg.phx_authority())?;
    check_ember_state(a.ember_state, cfg.usdc_mint(), cfg.phusd_mint())?;
    check_ember_vault(a.ember_vault)?;
    expect_key(a.token_program, &SPL_TOKEN_PROGRAM_ID, SijkaError::InvalidProgramId)?;
    check_payout_token(
        a.creator_escrow_usdc,
        cfg.creator_escrow_usdc(),
        cfg.usdc_mint(),
        cfg.creator_escrow(),
        SijkaError::CreatorEscrowInvalid,
    )?;
    let bb = check_payout_token(
        a.buyback_usdc,
        cfg.buyback_usdc(),
        cfg.usdc_mint(),
        cfg.buyback_authority(),
        SijkaError::BuybackAtaInvalid,
    )?;
    if is_zero_key(cfg.phoenix_trader()) {
        return Err(fail(SijkaError::TraderNotRegistered));
    }
    Ok(bb)
}

/// Steps 1–11: all checks and gates, the Hawkeye view and the amount `D`.
/// No state is written and no funds move here.
#[inline(never)]
fn harvest_plan(a: &HarvestAccounts<'_>, cfg_bytes: &[u8]) -> Result<HarvestPlan, ProgramError> {
    let cfg = config_view(cfg_bytes)?;

    // Step 1: accounts (own checks first, then the shared Phoenix checks).
    let bb_usdc = check_own_accounts_30(a, &cfg)?;
    let gc = check_global_config(a.global_config, GC_MIN_LEN_WITH_COOLDOWN, true)?;
    if !pubkey_eq(&gc.canonical_mint, cfg.phusd_mint()) {
        return Err(fail(SijkaError::InvalidPhoenixGlobalConfig));
    }
    check_trader_account(a.trader_account, cfg.phoenix_trader(), cfg.phx_authority(), TraderCheck::Full, true)?;
    check_perp_asset_map(a.perp_asset_map, &gc.perp_asset_map, PamCheck::Full, true)?;
    expect_key(a.global_vault, &gc.global_vault, SijkaError::InvalidPhoenixGlobalConfig)?;
    expect_writable(a.global_vault)?;
    expect_key(a.withdraw_queue, &gc.withdraw_queue, SijkaError::InvalidPhoenixGlobalConfig)?;
    expect_writable(a.withdraw_queue)?;
    check_arenas(a.arenas, a.gti.len(), &gc, true)?;

    let params = *cfg.harvest_params();
    let p = HarvestParams::from_array(&params);
    let clk = clock()?;
    let (now, slot) = (clk.unix_timestamp, clk.slot);

    // Steps 1 (recovery) to 5 (T_min, backlog, cooldown, queue); C_hdr (7).
    let st = read_phoenix_state(&cfg, &p, a.global_config, a.trader_account, a.withdraw_queue, bb_usdc, now, slot)?;
    early_gate(&st.gates).check().map_err(fail)?;
    // Step 6: mark freshness of every open position in the map.
    let max_age = u64::from(p.harvest_mark_max_age_slots());
    let scan = scan_marks(a.trader_account, a.perp_asset_map, slot, max_age)?;
    if let Some(e) = scan.and_then(|s| s.first_failure) {
        return Err(fail(e));
    }

    // Step 8: Hawkeye ViewMargin (read-only CPI; magic, version and length
    // are checked by the decoder). Hawkeye itself may also refuse an old
    // position mark (its own per-market rules, U-52).
    let m = view_margin(&HawkeyeAccounts {
        hawkeye_program: a.hawkeye_program,
        phoenix_program: a.phoenix_program,
        global_config: a.global_config,
        gti: a.gti,
        atb: a.atb,
        perp_asset_map: a.perp_asset_map,
        trader_account: a.trader_account,
    })?;
    // Step 8a: a position the map does not show yet must not hide behind an
    // old mark of a flat record either, whatever pc is (full audit FA-4).
    if hidden_stale(&scan, &m) > 0 {
        return Err(fail(SijkaError::HarvestMarkStale));
    }

    // Step 9: risk state.
    if !risk_ok(&m) {
        return Err(fail(SijkaError::HarvestRiskState));
    }
    let pc_above = pc_above_scan(&scan, &m);

    // Step 10: the amount.
    let i = cfg.cum_inflow_usdc();
    let q = st.gates.queue;
    let calc = compute_harvest(&m, st.c_hdr, i, &p, q.q_perm, q.q_tmp).map_err(fail)?;
    if calc.d < i128::from(p.d_min()) {
        return Err(fail(SijkaError::HarvestBelowMinimum));
    }
    let d = i128_to_u64(calc.d)?;
    Ok(HarvestPlan {
        now,
        slot,
        phx_authority_bump: cfg.phx_authority_bump(),
        phx_authority: *cfg.phx_authority(),
        usdc_mint: *cfg.usdc_mint(),
        phusd_mint: *cfg.phusd_mint(),
        i,
        ledger: Ledger {
            o: cfg.cum_payout_usdc(),
            cum_payout_creator: cfg.cum_payout_creator(),
            cum_payout_buyback: cfg.cum_payout_buyback(),
            cum_withdraw_fees: cfg.cum_withdraw_fees(),
            harvest_count: cfg.harvest_count(),
            last_harvest_ts: cfg.last_harvest_ts(),
            last_harvest_slot: cfg.last_harvest_slot(),
            last_harvest_amount: cfg.last_harvest_amount(),
        },
        m,
        c_hdr: st.c_hdr,
        calc,
        queue: q,
        bits: calc_bits(&calc, pc_above),
        d,
    })
}

/// Step 18: write the counters (all other `Config` bytes untouched).
fn write_ledger(m: &mut ConfigMut<'_>, l: &Ledger) {
    m.set_cum_payout_usdc(l.o);
    m.set_cum_payout_creator(l.cum_payout_creator);
    m.set_cum_payout_buyback(l.cum_payout_buyback);
    m.set_cum_withdraw_fees(l.cum_withdraw_fees);
    m.set_harvest_count(l.harvest_count);
    m.set_last_harvest_ts(l.last_harvest_ts);
    m.set_last_harvest_slot(l.last_harvest_slot);
    m.set_last_harvest_amount(l.last_harvest_amount);
}

/// `SJKEVHRV` payload (also the tag 30 return data).
fn harvest_event(plan: &HarvestPlan, pay: &Payout, next: &Ledger) -> EvHarvest {
    EvHarvest {
        ts: plan.now,
        slot: plan.slot,
        i: plan.i,
        o_after: next.o,
        c_hk: plan.m.collateral,
        c_hdr: plan.c_hdr,
        u: plan.m.unrealized_pnl,
        f: plan.m.unsettled_funding,
        d_star: saturate_i64(plan.calc.d_star),
        w: saturate_u64(u128::try_from(plan.calc.w).unwrap_or(0)),
        buf: saturate_u64(u128::try_from(plan.calc.buf).unwrap_or(0)),
        im: plan.m.initial_margin,
        d: pay.d,
        r: pay.r,
        creator: pay.creator,
        buyback: pay.buyback,
        harvest_count: next.harvest_count,
        position_count: plan.m.position_count,
        usdc_received: pay.u,
        queue_cap: plan.queue.cap(),
        bits: plan.bits,
    }
}

/// Emit the event and set it as return data (step 19).
#[inline(never)]
fn emit_harvest(ev: &EvHarvest) -> ProgramResult {
    let payload = ev.encode()?;
    emit(&payload);
    set_return_data(&payload);
    Ok(())
}

/// Tag 30 `harvest` (SPEC §5.4.2).
#[inline(never)]
pub fn harvest(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let info = check_shape(&HARVEST, accounts, data)?;
    let a = HarvestAccounts::parse(accounts, info)?;
    let mut cfg_data = load_config_mut(a.config, program_id)?;
    let plan = harvest_plan(&a, &cfg_data)?;

    // Step 11: balances before (donations included; only deltas count).
    let phusd0 = vault_amount(a.vault_phusd, &plan.phusd_mint, &plan.phx_authority)?;
    let usdc0 = vault_amount(a.vault_usdc, &plan.usdc_mint, &plan.phx_authority)?;
    let pda = PdaSeeds::new(SEED_PHX_AUTHORITY, plan.phx_authority_bump);
    let seeds = pda.seeds();
    let signer = [Signer::from(&seeds)];

    // Step 12: Phoenix withdraw_funds(D) to vault_phusd.
    withdraw_funds(
        &WithdrawAccounts {
            phoenix_program: a.phoenix_program,
            log_authority: a.log_authority,
            global_config: a.global_config,
            trader: a.phx_authority,
            trader_account: a.trader_account,
            perp_asset_map: a.perp_asset_map,
            global_vault: a.global_vault,
            trader_token_account: a.vault_phusd,
            token_program: a.token_program,
            gti: a.gti,
            atb: a.atb,
            withdraw_queue: a.withdraw_queue,
        },
        plan.d,
        &signer,
    )?;

    // Step 13: r arrived now, 0 < r ≤ D (a queued request is rolled back);
    // any Phoenix holdback D − r is booked (SPEC v4, DECISIONS §23 item 6).
    let phusd1 = vault_amount(a.vault_phusd, &plan.phusd_mint, &plan.phx_authority)?;
    let r = check_withdraw_arrival(phusd0, phusd1, plan.d).map_err(fail)?;
    // Step 13a: no part of D went into the Phoenix queue.
    check_nothing_queued(&plan.queue, &read_queue(a.withdraw_queue, plan.slot)?).map_err(fail)?;

    // Step 14: Ember withdraw(Some(r)): PhUSD → USDC.
    let ember = EmberAccounts {
        ember_program: a.ember_program,
        trader: a.phx_authority,
        ember_state: a.ember_state,
        usdc_mint: a.usdc_mint,
        canonical_mint: a.phusd_mint,
        trader_usdc_account: a.vault_usdc,
        trader_phoenix_account: a.vault_phusd,
        ember_vault: a.ember_vault,
        token_program: a.token_program,
    };
    ember_withdraw(&ember, r, &signer)?;

    // Step 15: vault_phusd back to its start, 0 < u ≤ r USDC arrived.
    let phusd2 = vault_amount(a.vault_phusd, &plan.phusd_mint, &plan.phx_authority)?;
    let usdc1 = vault_amount(a.vault_usdc, &plan.usdc_mint, &plan.phx_authority)?;
    let u = check_ember_arrival(phusd0, phusd2, usdc0, usdc1, r).map_err(fail)?;

    // Step 16: 20% to the creator escrow, the rest to the buyback.
    let (creator, buyback) = split_payout(u).map_err(fail)?;
    if creator > 0 {
        token::transfer(a.token_program, a.vault_usdc, a.creator_escrow_usdc, a.phx_authority, creator, &signer)?;
    }
    token::transfer(a.token_program, a.vault_usdc, a.buyback_usdc, a.phx_authority, buyback, &signer)?;

    // Step 17: nothing left behind, nothing foreign taken.
    if vault_amount(a.vault_usdc, &plan.usdc_mint, &plan.phx_authority)? != usdc0 {
        return Err(fail(SijkaError::InvariantViolated));
    }

    // Step 18: counters (checked, O += u exactly).
    let pay = Payout { d: plan.d, r, u, creator, buyback };
    let next = plan.ledger.apply(&pay, plan.calc.timer_held, plan.now, plan.slot).map_err(fail)?;
    write_ledger(&mut config_view_mut(&mut cfg_data)?, &next);
    drop(cfg_data);

    // Step 19.
    emit_harvest(&harvest_event(&plan, &pay, &next))
}

// --------------------------------------------------------------- tag 31 ----

/// Tag 31 `harvest_preview` (SPEC §5.4.3). Read-only; the result is the
/// 168-byte return data.
#[inline(never)]
pub fn harvest_preview(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let info = check_shape(&HARVEST_PREVIEW, accounts, data)?;
    let [
        config,
        phoenix_program,
        hawkeye_program,
        global_config,
        trader_account,
        perp_asset_map,
        withdraw_queue,
        buyback_usdc,
        arenas @ ..,
    ] = accounts
    else {
        return Err(fail(SijkaError::InvalidAccountCount));
    };
    let (gti, atb) = arenas.split_at_checked(info.gti).ok_or_else(|| fail(SijkaError::InvalidAccountCount))?;
    let payload = {
        let cfg_data = load_config(config, program_id)?;
        let cfg = config_view(&cfg_data)?;

        // Own checks first.
        expect_program(phoenix_program, &PHOENIX_PROGRAM_ID)?;
        expect_program(hawkeye_program, &HAWKEYE_PROGRAM_ID)?;
        expect_key(buyback_usdc, cfg.buyback_usdc(), SijkaError::BuybackAtaInvalid)?;
        let bb_usdc = lenient_amount(buyback_usdc)?;
        if is_zero_key(cfg.phoenix_trader()) {
            return Err(fail(SijkaError::TraderNotRegistered));
        }
        // Shared Phoenix checks (read-only).
        let gc = check_global_config(global_config, GC_MIN_LEN_WITH_COOLDOWN, false)?;
        check_trader_account(trader_account, cfg.phoenix_trader(), cfg.phx_authority(), TraderCheck::Full, false)?;
        check_perp_asset_map(perp_asset_map, &gc.perp_asset_map, PamCheck::Full, false)?;
        expect_key(withdraw_queue, &gc.withdraw_queue, SijkaError::InvalidPhoenixGlobalConfig)?;
        check_arenas(arenas, gti.len(), &gc, false)?;

        let params = *cfg.harvest_params();
        let p = HarvestParams::from_array(&params);
        let clk = clock()?;
        let (now, slot) = (clk.unix_timestamp, clk.slot);
        // The numbers are always computed, whatever the status (SPEC §5.4.3);
        // a position outside the PAM counts as stale, not as an error.
        let st = read_phoenix_state(&cfg, &p, global_config, trader_account, withdraw_queue, bb_usdc, now, slot)?;
        let max_age = u64::from(p.harvest_mark_max_age_slots());
        let scan = scan_marks(trader_account, perp_asset_map, slot, max_age)?;
        let map_stale = scan.map_or(0u32, |s| s.stale);
        let q = st.gates.queue;
        // A stale position found by the map scan (step 6) stops tag 30 before
        // Hawkeye, and Hawkeye itself refuses `ViewMargin` once a position
        // mark is older than its own limit (test finding BUG-phoenix-core-2).
        // So the preview does not call it either: status 8 with the Hawkeye
        // fields and the amounts zero, instead of a failed simulation. In
        // recovery mode status 9 is final and Phoenix marks may be stale, so
        // Hawkeye is skipped the same way (review accounting-2).
        let skip_hawkeye = map_stale > 0 || st.gates.recovery_mode != 0;
        let (m, calc, pc_above, hidden) = if skip_hawkeye {
            (MarginView::default(), HarvestCalc::default(), false, 0)
        } else {
            let m = view_margin(&HawkeyeAccounts {
                hawkeye_program,
                phoenix_program,
                global_config,
                gti,
                atb,
                perp_asset_map,
                trader_account,
            })?;
            let calc = compute_harvest(&m, st.c_hdr, cfg.cum_inflow_usdc(), &p, q.q_perm, q.q_tmp).map_err(fail)?;
            (m, calc, pc_above_scan(&scan, &m), hidden_stale(&scan, &m))
        };
        // Step 8a counts as MarkStale too (status 8).
        let stale = map_stale.saturating_add(hidden);
        let status: HarvestStatus = preview_status(&st.gates, stale, &m, &calc, p.d_min());
        HarvestPreviewData {
            status: status.code(),
            now,
            next_allowed_ts: st.gates.next_allowed_ts(),
            i: cfg.cum_inflow_usdc(),
            o: cfg.cum_payout_usdc(),
            c_hk: m.collateral,
            c_hdr: st.c_hdr,
            u: m.unrealized_pnl,
            f: m.unsettled_funding,
            d_star: saturate_i64(calc.d_star),
            w: saturate_i64(calc.w),
            buf: saturate_u64(u128::try_from(calc.buf).unwrap_or(0)),
            d: saturate_i64(calc.d),
            im: m.initial_margin,
            position_count: m.position_count,
            risk_tier: m.risk_tier,
            is_liquidatable: m.is_liquidatable,
            buyback_usdc: bb_usdc,
            queue_cap: q.cap(),
            total_queued: q.total_queued,
            cooldown_until_slot: st.gates.cooldown_until_slot(),
            stale_positions: u16::try_from(stale).unwrap_or(u16::MAX),
            bits: calc_bits(&calc, pc_above),
        }
        .encode()
        .ok_or_else(|| fail(SijkaError::InvariantViolated))?
    };
    set_return_data(&payload);
    Ok(())
}

// --------------------------------------------------------------- tag 32 ----

/// Tag 32 `pay_creator` (SPEC §5.4.5): the whole `creator_escrow_usdc`
/// balance to `creator_usdc` (the ATA of the immutable `creator_payout`).
#[inline(never)]
pub fn pay_creator(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    check_shape(&PAY_CREATOR, accounts, data)?;
    let [config, creator_escrow, creator_escrow_usdc, creator_usdc, token_program] = accounts else {
        return Err(fail(SijkaError::InvalidAccountCount));
    };
    let mut cfg_data = load_config_mut(config, program_id)?;
    let (bump, amount, to_before, usdc_mint, escrow, creator_payout, escrow_usdc_key, creator_usdc_key) = {
        let cfg = config_view(&cfg_data)?;
        expect_key(creator_escrow, cfg.creator_escrow(), SijkaError::InvalidPda)?;
        expect_system_empty(creator_escrow, SijkaError::InvalidExternalAccount)?;
        let amount = check_payout_token(
            creator_escrow_usdc,
            cfg.creator_escrow_usdc(),
            cfg.usdc_mint(),
            cfg.creator_escrow(),
            SijkaError::CreatorEscrowInvalid,
        )?;
        let to_before = check_creator_usdc(creator_usdc, cfg.creator_usdc(), cfg.usdc_mint(), cfg.creator_payout())?;
        expect_key(token_program, &SPL_TOKEN_PROGRAM_ID, SijkaError::InvalidProgramId)?;
        // Step 1 (no admin pause since SPEC v2; recovery mode does not stop
        // it either, SPEC §5.6.5).
        if amount == 0 {
            return Err(fail(SijkaError::CreatorPayNothing));
        }
        (
            cfg.creator_escrow_bump(),
            amount,
            to_before,
            *cfg.usdc_mint(),
            *cfg.creator_escrow(),
            *cfg.creator_payout(),
            *cfg.creator_escrow_usdc(),
            *cfg.creator_usdc(),
        )
    };

    // Step 3: escrow → creator_usdc, signed by the escrow PDA.
    let pda = PdaSeeds::new(SEED_CREATOR_ESCROW, bump);
    let seeds = pda.seeds();
    let signer = [Signer::from(&seeds)];
    token::transfer(token_program, creator_escrow_usdc, creator_usdc, creator_escrow, amount, &signer)?;

    // Step 4: escrow empty, and exactly `amount` reached creator_usdc.
    let left = check_payout_token(
        creator_escrow_usdc,
        &escrow_usdc_key,
        &usdc_mint,
        &escrow,
        SijkaError::CreatorEscrowInvalid,
    )?;
    let to_after = check_creator_usdc(creator_usdc, &creator_usdc_key, &usdc_mint, &creator_payout)?;
    if left != 0 || Some(to_after) != to_before.checked_add(amount) {
        return Err(fail(SijkaError::InvariantViolated));
    }

    // Step 5: counters; O and cum_payout_creator do not change.
    let clk = clock()?;
    let (paid_out, cum_payout_creator) = {
        let cfg = config_view(&cfg_data)?;
        let paid_out = add_u64(cfg.cum_creator_paid_out(), amount)?;
        let count = add_u64(cfg.creator_pay_count(), 1)?;
        let cum = cfg.cum_payout_creator();
        let mut m = config_view_mut(&mut cfg_data)?;
        m.set_cum_creator_paid_out(paid_out);
        m.set_creator_pay_count(count);
        (paid_out, cum)
    };
    drop(cfg_data);

    // Step 6.
    EvPayCreator { ts: clk.unix_timestamp, slot: clk.slot, amount, cum_creator_paid_out: paid_out, cum_payout_creator }
        .emit()
}

#[cfg(test)]
mod tests {
    //! Host tests of the account checks and the paths that do not need the
    //! runtime. On the host `Clock::get` fails and every CPI is a no-op, so:
    //! tag 30 / 31 are exercised up to the shared Phoenix checks (all checks of
    //! this module run before them), and tag 32 runs to its post-transfer
    //! invariant (a token program that moved nothing must be caught). The
    //! money flow itself is covered by the LiteSVM suite (SPEC §9.6).

    use super::*;
    use crate::constants::{DISC_CONFIG, EMBER_STATE, EMBER_VAULT, SYSTEM_PROGRAM_ID};
    use crate::cpi::phoenix_withdraw::ember_state_fields_ok;
    use crate::state::config::CONFIG_LEN;
    use crate::util::test_utils::TestAccount;

    const PROGRAM: Pubkey = [0x51; 32];

    fn k(n: u8) -> Pubkey {
        let mut key = [0u8; 32];
        key[0] = 0xC0;
        key[1] = n;
        key
    }

    // Keys stored in Config.
    const PHX_AUTHORITY: u8 = 1;
    const USDC_MINT: u8 = 2;
    const PHUSD_MINT: u8 = 3;
    const VAULT_PHUSD: u8 = 4;
    const VAULT_USDC: u8 = 5;
    const CREATOR_ESCROW: u8 = 6;
    const CREATOR_ESCROW_USDC: u8 = 7;
    const BUYBACK_AUTHORITY: u8 = 8;
    const BUYBACK_USDC: u8 = 9;
    const PHOENIX_TRADER: u8 = 11;
    const CREATOR_PAYOUT: u8 = 12;
    const CREATOR_USDC: u8 = 13;

    fn config_bytes() -> Vec<u8> {
        let mut b = vec![0u8; CONFIG_LEN];
        let mut m = ConfigMut::new(&mut b).unwrap();
        m.set_discriminator(&DISC_CONFIG);
        m.set_version(1);
        m.set_creator_share_bps(2000);
        m.set_admin(&k(99));
        m.set_phx_authority(&k(PHX_AUTHORITY));
        m.set_usdc_mint(&k(USDC_MINT));
        m.set_phusd_mint(&k(PHUSD_MINT));
        m.set_vault_phusd(&k(VAULT_PHUSD));
        m.set_vault_usdc(&k(VAULT_USDC));
        m.set_creator_escrow(&k(CREATOR_ESCROW));
        m.set_creator_escrow_usdc(&k(CREATOR_ESCROW_USDC));
        m.set_buyback_authority(&k(BUYBACK_AUTHORITY));
        m.set_buyback_usdc(&k(BUYBACK_USDC));
        m.set_phoenix_trader(&k(PHOENIX_TRADER));
        m.set_creator_payout(&k(CREATOR_PAYOUT));
        m.set_creator_usdc(&k(CREATOR_USDC));
        m.set_phx_authority_bump(254);
        m.set_creator_escrow_bump(253);
        m.set_cum_payout_creator(40);
        m.set_cum_creator_paid_out(10);
        b
    }

    fn token_bytes(mint: &Pubkey, owner: &Pubkey, amount: u64) -> Vec<u8> {
        let mut d = vec![0u8; TOKEN_ACCOUNT_LEN];
        d[0..32].copy_from_slice(mint);
        d[32..64].copy_from_slice(owner);
        d[64..72].copy_from_slice(&amount.to_le_bytes());
        d[108] = 1;
        d
    }

    fn ember_state_bytes() -> Vec<u8> {
        let mut d = vec![0u8; 136];
        d[0..8].copy_from_slice(&crate::constants::DISC_EMBER_STATE);
        d[40..72].copy_from_slice(&k(USDC_MINT));
        d[72..104].copy_from_slice(&k(PHUSD_MINT));
        d[104..136].copy_from_slice(&PHOENIX_PROGRAM_ID);
        assert!(ember_state_fields_ok(&d, &k(USDC_MINT), &k(PHUSD_MINT)));
        d
    }

    fn rw(key: Pubkey, owner: Pubkey, data: &[u8]) -> TestAccount {
        TestAccount::new(key, owner, 1_000_000, data, false, true, false)
    }
    fn ro(key: Pubkey, owner: Pubkey, data: &[u8]) -> TestAccount {
        TestAccount::new(key, owner, 1_000_000, data, false, false, false)
    }
    fn prog(key: Pubkey) -> TestAccount {
        TestAccount::new(key, [0xBB; 32], 1, &[], false, false, true)
    }

    /// The 20 fixed accounts of tag 30 plus one GTI and one ATB.
    fn harvest_accounts() -> Vec<TestAccount> {
        let spl = SPL_TOKEN_PROGRAM_ID;
        vec![
            rw([0x77; 32], PROGRAM, &config_bytes()),
            ro(k(PHX_AUTHORITY), SYSTEM_PROGRAM_ID, &[]),
            prog(PHOENIX_PROGRAM_ID),
            prog(HAWKEYE_PROGRAM_ID),
            prog(EMBER_PROGRAM_ID),
            ro(PHOENIX_LOG_AUTHORITY, SYSTEM_PROGRAM_ID, &[]),
            rw(k(40), PHOENIX_PROGRAM_ID, &[]), // global_config (checked by the shared code)
            rw(k(41), PHOENIX_PROGRAM_ID, &[]), // trader_account
            rw(k(42), PHOENIX_PROGRAM_ID, &[]), // perp_asset_map
            rw(k(43), spl, &[]),                // global_vault
            rw(k(44), PHOENIX_PROGRAM_ID, &[]), // withdraw_queue
            ro(k(USDC_MINT), spl, &[0u8; 82]),
            rw(k(PHUSD_MINT), spl, &[0u8; 82]),
            rw(k(VAULT_PHUSD), spl, &token_bytes(&k(PHUSD_MINT), &k(PHX_AUTHORITY), 7)),
            rw(k(VAULT_USDC), spl, &token_bytes(&k(USDC_MINT), &k(PHX_AUTHORITY), 9)),
            ro(EMBER_STATE, EMBER_PROGRAM_ID, &ember_state_bytes()),
            rw(EMBER_VAULT, spl, &[]),
            prog(SPL_TOKEN_PROGRAM_ID),
            rw(k(CREATOR_ESCROW_USDC), spl, &token_bytes(&k(USDC_MINT), &k(CREATOR_ESCROW), 3)),
            rw(k(BUYBACK_USDC), spl, &token_bytes(&k(USDC_MINT), &k(BUYBACK_AUTHORITY), 5)),
            rw(k(45), PHOENIX_PROGRAM_ID, &[]), // GTI[0]
            rw(k(46), PHOENIX_PROGRAM_ID, &[]), // ATB[0]
        ]
    }

    const HARVEST_DATA: [u8; 3] = [30, 1, 1];

    fn run30(accts: &[TestAccount]) -> ProgramResult {
        let infos: Vec<AccountInfo> = accts.iter().map(TestAccount::info).collect();
        crate::process_instruction(&PROGRAM, &infos, &HARVEST_DATA)
    }

    fn with(mut v: Vec<TestAccount>, i: usize, a: TestAccount) -> Vec<TestAccount> {
        v[i] = a;
        v
    }

    fn e(x: SijkaError) -> ProgramResult {
        Err(x.into())
    }

    #[test]
    fn harvest_rejects_bad_own_accounts_before_any_cpi() {
        let spl = SPL_TOKEN_PROGRAM_ID;
        let base = harvest_accounts;
        // config: owner, writable.
        assert_eq!(
            run30(&with(base(), 0, rw([0x77; 32], [9; 32], &config_bytes()))),
            e(SijkaError::InvalidConfigAccount)
        );
        assert_eq!(
            run30(&with(base(), 0, ro([0x77; 32], PROGRAM, &config_bytes()))),
            e(SijkaError::AccountNotWritable)
        );
        // phx_authority key.
        assert_eq!(run30(&with(base(), 1, ro(k(60), SYSTEM_PROGRAM_ID, &[]))), e(SijkaError::InvalidPda));
        // Programs: key and executable.
        assert_eq!(run30(&with(base(), 2, prog(k(61)))), e(SijkaError::InvalidProgramId));
        assert_eq!(run30(&with(base(), 3, ro(HAWKEYE_PROGRAM_ID, [0xBB; 32], &[]))), e(SijkaError::InvalidProgramId));
        assert_eq!(run30(&with(base(), 4, prog(HAWKEYE_PROGRAM_ID))), e(SijkaError::InvalidProgramId));
        // log authority, usdc mint.
        assert_eq!(run30(&with(base(), 5, ro(k(62), SYSTEM_PROGRAM_ID, &[]))), e(SijkaError::InvalidExternalAccount));
        assert_eq!(run30(&with(base(), 11, ro(k(63), spl, &[0u8; 82]))), e(SijkaError::InvalidExternalAccount));
        // PhUSD mint: key and writable.
        assert_eq!(run30(&with(base(), 12, rw(k(64), spl, &[0u8; 82]))), e(SijkaError::InvalidPhoenixGlobalConfig));
        assert_eq!(run30(&with(base(), 12, ro(k(PHUSD_MINT), spl, &[0u8; 82]))), e(SijkaError::AccountNotWritable));
        // vault_phusd: key, writable, token fields.
        let vp = |key: Pubkey, mint: u8, owner: u8| rw(key, spl, &token_bytes(&k(mint), &k(owner), 7));
        assert_eq!(run30(&with(base(), 13, vp(k(65), PHUSD_MINT, PHX_AUTHORITY))), e(SijkaError::InvalidPda));
        assert_eq!(
            run30(&with(base(), 13, vp(k(VAULT_PHUSD), USDC_MINT, PHX_AUTHORITY))),
            e(SijkaError::InvalidTokenAccount)
        );
        assert_eq!(run30(&with(base(), 13, vp(k(VAULT_PHUSD), PHUSD_MINT, 66))), e(SijkaError::InvalidTokenAccount));
        let ro_vault = ro(k(VAULT_PHUSD), spl, &token_bytes(&k(PHUSD_MINT), &k(PHX_AUTHORITY), 7));
        assert_eq!(run30(&with(base(), 13, ro_vault)), e(SijkaError::AccountNotWritable));
        // vault_usdc under Token-2022 is rejected.
        let t22 = rw(
            k(VAULT_USDC),
            crate::constants::TOKEN_2022_PROGRAM_ID,
            &token_bytes(&k(USDC_MINT), &k(PHX_AUTHORITY), 9),
        );
        assert_eq!(run30(&with(base(), 14, t22)), e(SijkaError::InvalidTokenAccount));
        // Ember state and vault.
        let mut bad_state = ember_state_bytes();
        bad_state[104] ^= 1;
        assert_eq!(
            run30(&with(base(), 15, ro(EMBER_STATE, EMBER_PROGRAM_ID, &bad_state))),
            e(SijkaError::InvalidEmberAccount)
        );
        assert_eq!(run30(&with(base(), 16, ro(EMBER_VAULT, spl, &[]))), e(SijkaError::AccountNotWritable));
        assert_eq!(run30(&with(base(), 16, rw(k(67), spl, &[]))), e(SijkaError::InvalidEmberAccount));
        // Token program must be Tokenkeg.
        assert_eq!(
            run30(&with(base(), 17, prog(crate::constants::TOKEN_2022_PROGRAM_ID))),
            e(SijkaError::InvalidProgramId)
        );
        // Trader not registered.
        let mut cfg = config_bytes();
        ConfigMut::new(&mut cfg).unwrap().set_phoenix_trader(&[0; 32]);
        assert_eq!(run30(&with(base(), 0, rw([0x77; 32], PROGRAM, &cfg))), e(SijkaError::TraderNotRegistered));
    }

    #[test]
    fn harvest_payout_accounts_are_strict() {
        // TH-8 / TH-26: the escrow and the buyback ATA must be exactly ours,
        // initialized, without delegate or close authority.
        let spl = SPL_TOKEN_PROGRAM_ID;
        let esc = CREATOR_ESCROW_USDC;
        let cases: [(usize, u8, u8, SijkaError); 2] = [
            (18, esc, CREATOR_ESCROW, SijkaError::CreatorEscrowInvalid),
            (19, BUYBACK_USDC, BUYBACK_AUTHORITY, SijkaError::BuybackAtaInvalid),
        ];
        for (slot, key, owner, err) in cases {
            let good = token_bytes(&k(USDC_MINT), &k(owner), 5);
            let mutate = |f: &dyn Fn(&mut Vec<u8>)| {
                let mut d = good.clone();
                f(&mut d);
                run30(&with(harvest_accounts(), slot, rw(k(key), spl, &d)))
            };
            assert_eq!(run30(&with(harvest_accounts(), slot, rw(k(70), spl, &good))), e(err), "foreign key");
            assert_eq!(mutate(&|d| d[72] = 1), e(err), "delegate");
            assert_eq!(mutate(&|d| d[129] = 1), e(err), "close authority");
            assert_eq!(mutate(&|d| d[108] = 2), e(err), "frozen");
            assert_eq!(mutate(&|d| d[108] = 0), e(err), "uninitialized");
            assert_eq!(mutate(&|d| d[0] ^= 1), e(err), "mint");
            assert_eq!(mutate(&|d| d[32] ^= 1), e(err), "owner field");
            assert_eq!(mutate(&|d| d.push(0)), e(err), "length");
            assert_eq!(run30(&with(harvest_accounts(), slot, rw(k(key), [3; 32], &good))), e(err), "program owner");
            assert_eq!(
                run30(&with(harvest_accounts(), slot, ro(k(key), spl, &good))),
                e(SijkaError::AccountNotWritable)
            );
        }
        // A missing buyback ATA (System-owned, no data) is BuybackAtaInvalid.
        let missing = rw(k(BUYBACK_USDC), SYSTEM_PROGRAM_ID, &[]);
        assert_eq!(run30(&with(harvest_accounts(), 19, missing)), e(SijkaError::BuybackAtaInvalid));
    }

    #[test]
    fn harvest_does_not_depend_on_creator_usdc() {
        // Review ACC-3: tag 30 has no creator_usdc slot at all.
        assert_eq!(HARVEST.accounts, 20);
        assert!(harvest_accounts().iter().all(|a| a.info().key() != &k(CREATOR_USDC)));
    }

    // ---------------------------------------------------------- preview ----

    fn preview_accounts() -> Vec<TestAccount> {
        vec![
            ro([0x77; 32], PROGRAM, &config_bytes()),
            prog(PHOENIX_PROGRAM_ID),
            prog(HAWKEYE_PROGRAM_ID),
            ro(k(40), PHOENIX_PROGRAM_ID, &[]),
            ro(k(41), PHOENIX_PROGRAM_ID, &[]),
            ro(k(42), PHOENIX_PROGRAM_ID, &[]),
            ro(k(44), PHOENIX_PROGRAM_ID, &[]),
            ro(k(BUYBACK_USDC), SPL_TOKEN_PROGRAM_ID, &token_bytes(&k(USDC_MINT), &k(BUYBACK_AUTHORITY), 5)),
            ro(k(45), PHOENIX_PROGRAM_ID, &[]),
            ro(k(46), PHOENIX_PROGRAM_ID, &[]),
        ]
    }

    fn run31(accts: &[TestAccount]) -> ProgramResult {
        let infos: Vec<AccountInfo> = accts.iter().map(TestAccount::info).collect();
        crate::process_instruction(&PROGRAM, &infos, &[31, 1, 1])
    }

    #[test]
    fn preview_checks() {
        let p = preview_accounts;
        assert_eq!(run31(&with(p(), 0, ro([0x77; 32], [1; 32], &config_bytes()))), e(SijkaError::InvalidConfigAccount));
        assert_eq!(run31(&with(p(), 1, prog(k(80)))), e(SijkaError::InvalidProgramId));
        assert_eq!(run31(&with(p(), 2, prog(PHOENIX_PROGRAM_ID))), e(SijkaError::InvalidProgramId));
        assert_eq!(run31(&with(p(), 7, ro(k(81), SPL_TOKEN_PROGRAM_ID, &[]))), e(SijkaError::BuybackAtaInvalid));
        let mut cfg = config_bytes();
        ConfigMut::new(&mut cfg).unwrap().set_phoenix_trader(&[0; 32]);
        assert_eq!(run31(&with(p(), 0, ro([0x77; 32], PROGRAM, &cfg))), e(SijkaError::TraderNotRegistered));
    }

    #[test]
    fn preview_buyback_balance_is_lenient() {
        let good = ro(k(BUYBACK_USDC), SPL_TOKEN_PROGRAM_ID, &token_bytes(&k(USDC_MINT), &k(BUYBACK_AUTHORITY), 42));
        assert_eq!(lenient_amount(&good.info()), Ok(42));
        let missing = ro(k(BUYBACK_USDC), SYSTEM_PROGRAM_ID, &[]);
        assert_eq!(lenient_amount(&missing.info()), Ok(0));
        let short = ro(k(BUYBACK_USDC), SPL_TOKEN_PROGRAM_ID, &[1u8; 100]);
        assert_eq!(lenient_amount(&short.info()), Ok(0));
    }

    // ------------------------------------------------------ pay_creator ----

    fn pay_accounts(cfg: &[u8], escrow_amount: u64) -> Vec<TestAccount> {
        let spl = SPL_TOKEN_PROGRAM_ID;
        vec![
            rw([0x77; 32], PROGRAM, cfg),
            ro(k(CREATOR_ESCROW), SYSTEM_PROGRAM_ID, &[]),
            rw(k(CREATOR_ESCROW_USDC), spl, &token_bytes(&k(USDC_MINT), &k(CREATOR_ESCROW), escrow_amount)),
            rw(k(CREATOR_USDC), spl, &token_bytes(&k(USDC_MINT), &k(CREATOR_PAYOUT), 1)),
            prog(SPL_TOKEN_PROGRAM_ID),
        ]
    }

    fn run32(accts: &[TestAccount]) -> ProgramResult {
        let infos: Vec<AccountInfo> = accts.iter().map(TestAccount::info).collect();
        crate::process_instruction(&PROGRAM, &infos, &[32])
    }

    #[test]
    fn pay_creator_post_transfer_invariant() {
        // On the host the SPL transfer is a no-op: the escrow still holds its
        // balance afterwards, which must fail closed (InvariantViolated), never
        // count as paid. This also shows the handler reaches the transfer.
        let cfg = config_bytes();
        assert_eq!(run32(&pay_accounts(&cfg, 100)), e(SijkaError::InvariantViolated));
        // Recovery mode does not stop tag 32 (SPEC §5.6.5).
        let mut rec = config_bytes();
        ConfigMut::new(&mut rec).unwrap().set_recovery_mode(1);
        assert_eq!(run32(&pay_accounts(&rec, 100)), e(SijkaError::InvariantViolated));
        // Counters untouched on failure.
        let accts = pay_accounts(&cfg, 100);
        let _ = run32(&accts);
        let infos: Vec<AccountInfo> = accts.iter().map(TestAccount::info).collect();
        let data = infos[0].try_borrow_data().unwrap();
        let c = Config::new(&data).unwrap();
        assert_eq!((c.cum_creator_paid_out(), c.creator_pay_count(), c.cum_payout_creator()), (10, 0, 40));
    }

    #[test]
    fn pay_creator_gates() {
        let cfg = config_bytes();
        assert_eq!(run32(&pay_accounts(&cfg, 0)), e(SijkaError::CreatorPayNothing));
        // No admin pause (SPEC v2): a non-zero retired byte @10 changes nothing.
        let mut p = config_bytes();
        p[10] = 1;
        assert_eq!(run32(&pay_accounts(&p, 100)), e(SijkaError::InvariantViolated), "reaches the transfer");
    }

    #[test]
    fn pay_creator_account_checks() {
        let spl = SPL_TOKEN_PROGRAM_ID;
        let cfg = config_bytes();
        let base = || pay_accounts(&cfg, 100);
        // Escrow PDA: key, System-owned without data.
        assert_eq!(run32(&with(base(), 1, ro(k(90), SYSTEM_PROGRAM_ID, &[]))), e(SijkaError::InvalidPda));
        assert_eq!(
            run32(&with(base(), 1, ro(k(CREATOR_ESCROW), SYSTEM_PROGRAM_ID, &[0]))),
            e(SijkaError::InvalidExternalAccount)
        );
        assert_eq!(run32(&with(base(), 1, ro(k(CREATOR_ESCROW), PROGRAM, &[]))), e(SijkaError::InvalidExternalAccount));
        // Escrow token account.
        let esc = |d: Vec<u8>| rw(k(CREATOR_ESCROW_USDC), spl, &d);
        let good = token_bytes(&k(USDC_MINT), &k(CREATOR_ESCROW), 100);
        let mut delegate = good.clone();
        delegate[72] = 1;
        assert_eq!(run32(&with(base(), 2, esc(delegate))), e(SijkaError::CreatorEscrowInvalid));
        assert_eq!(run32(&with(base(), 2, rw(k(91), spl, &good))), e(SijkaError::CreatorEscrowInvalid));
        assert_eq!(run32(&with(base(), 2, ro(k(CREATOR_ESCROW_USDC), spl, &good))), e(SijkaError::AccountNotWritable));
        // creator_usdc: key, owner field, frozen, mint, length; a delegate is allowed.
        let cu = |d: Vec<u8>| rw(k(CREATOR_USDC), spl, &d);
        let to = token_bytes(&k(USDC_MINT), &k(CREATOR_PAYOUT), 1);
        assert_eq!(run32(&with(base(), 3, rw(k(92), spl, &to))), e(SijkaError::CreatorAtaInvalid));
        let mut moved = to.clone();
        moved[32] ^= 1; // SetAuthority(AccountOwner → X), review ACC-3
        assert_eq!(run32(&with(base(), 3, cu(moved))), e(SijkaError::CreatorAtaInvalid));
        let mut frozen = to.clone();
        frozen[108] = 2;
        assert_eq!(run32(&with(base(), 3, cu(frozen))), e(SijkaError::CreatorAtaInvalid));
        let mut mint = to.clone();
        mint[0] ^= 1;
        assert_eq!(run32(&with(base(), 3, cu(mint))), e(SijkaError::CreatorAtaInvalid));
        assert_eq!(
            run32(&with(base(), 3, rw(k(CREATOR_USDC), SYSTEM_PROGRAM_ID, &[]))),
            e(SijkaError::CreatorAtaInvalid)
        );
        assert_eq!(run32(&with(base(), 3, ro(k(CREATOR_USDC), spl, &to))), e(SijkaError::AccountNotWritable));
        let mut delegated = to.clone();
        delegated[72] = 1;
        assert_eq!(run32(&with(base(), 3, cu(delegated))), e(SijkaError::InvariantViolated), "delegate allowed");
        // Token program.
        assert_eq!(
            run32(&with(base(), 4, prog(crate::constants::TOKEN_2022_PROGRAM_ID))),
            e(SijkaError::InvalidProgramId)
        );
    }

    // ------------------------------------------------------------ event ----

    #[test]
    fn harvest_event_fields() {
        let calc = HarvestCalc {
            c: 5,
            d_star: i128::from(i64::MAX) + 7,
            w: 11,
            buf: i128::from(u64::MAX) + 1,
            d_pre: 100,
            d_perm: 90,
            d: 80,
            timer_held: true,
        };
        let plan = HarvestPlan {
            now: 1_700_000_000,
            slot: 42,
            phx_authority_bump: 254,
            phx_authority: k(PHX_AUTHORITY),
            usdc_mint: k(USDC_MINT),
            phusd_mint: k(PHUSD_MINT),
            i: 1_000,
            ledger: Ledger::default(),
            m: MarginView {
                collateral: -3,
                unrealized_pnl: -4,
                unsettled_funding: 5,
                initial_margin: 6,
                position_count: 2,
                ..MarginView::default()
            },
            c_hdr: 7,
            calc,
            queue: QueueState { parsed: true, q_perm: 90, q_tmp: 100, total_queued: 0 },
            bits: calc_bits(&calc, true),
            d: 80,
        };
        let pay = Payout { d: 80, r: 80, u: 79, creator: 15, buyback: 64 };
        let next = Ledger::default().apply(&pay, true, 1, 1).unwrap();
        let ev = harvest_event(&plan, &pay, &next).encode().unwrap();
        assert_eq!(ev.len(), EvHarvest::LEN);
        assert_eq!(&ev[0..8], b"SJKEVHRV");
        let u64_at = |o: usize| u64::from_le_bytes(ev[o..o + 8].try_into().unwrap());
        let i64_at = |o: usize| i64::from_le_bytes(ev[o..o + 8].try_into().unwrap());
        assert_eq!(i64_at(9), 1_700_000_000);
        assert_eq!(u64_at(25), 1_000);
        assert_eq!(u64_at(33), 79, "O_after");
        assert_eq!(i64_at(41), -3);
        assert_eq!(i64_at(73), i64::MAX, "D_star saturates");
        assert_eq!(u64_at(89), u64::MAX, "buf saturates");
        assert_eq!(u64_at(105), 80);
        assert_eq!((u64_at(121), u64_at(129)), (15, 64));
        assert_eq!(u64_at(137), 1, "harvest_count after");
        assert_eq!(u16::from_le_bytes(ev[145..147].try_into().unwrap()), 2);
        assert_eq!(u64_at(147), 79, "usdc_received = u");
        assert_eq!(u64_at(155), 90);
        assert_eq!(ev[163], bits::QUEUE_LIMITED | bits::TIMER_HELD | bits::PC_ABOVE_SCAN);
    }

    #[test]
    fn pc_above_scan_bit() {
        let m = MarginView { position_count: 3, ..MarginView::default() };
        assert!(!pc_above_scan(&None, &m), "check disabled");
        let s = Some(MarkScan { positions: 3, records: 3, ..MarkScan::default() });
        assert!(!pc_above_scan(&s, &m));
        let s = Some(MarkScan { positions: 2, records: 3, ..MarkScan::default() });
        assert!(pc_above_scan(&s, &m));
    }

    /// Step 8a (RT-3, FA-4): off with the mark check; otherwise stale flat
    /// records and markets missing from the map count, whatever `pc` is.
    #[test]
    fn step_8a_hidden_positions() {
        let m = MarginView { position_count: 3, ..MarginView::default() };
        assert_eq!(hidden_stale(&None, &m), 0, "check disabled (parameter 0)");
        let synced = MarkScan { positions: 3, records: 3, ..MarkScan::default() };
        assert_eq!(hidden_stale(&Some(synced), &m), 0, "pc == n_scan, no flat record");
        // FA-4: pc == n_scan, but one map position may be closed in the ATB
        // already while the stale flat record hides the live one.
        let lagging = MarkScan { positions: 3, records: 4, flat_stale: 1, ..MarkScan::default() };
        assert_eq!(hidden_stale(&Some(lagging), &m), 1);
        let fewer = MarginView { position_count: 1, ..MarginView::default() };
        assert_eq!(hidden_stale(&Some(lagging), &fewer), 1, "pc < n_scan too");
        let fresh = MarkScan { positions: 1, records: 3, ..MarkScan::default() };
        assert_eq!(hidden_stale(&Some(fresh), &m), 0, "orders-only markets with fresh marks");
        let old = MarkScan { flat_stale: 1, ..fresh };
        assert_eq!(hidden_stale(&Some(old), &m), 1);
        let missing = MarkScan { positions: 1, records: 2, ..MarkScan::default() };
        assert_eq!(hidden_stale(&Some(missing), &m), 1, "a market the map has no record for");
    }
}
