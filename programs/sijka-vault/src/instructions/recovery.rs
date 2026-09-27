// Copyright (c) 2026 prt1sn. All rights reserved.
//! Venue observation and emergency recovery, tags 50–51 (SPEC §5.6,
//! DECISIONS §17).
//!
//! The only exception to "nobody can withdraw" (DECISIONS §2.1): if Phoenix's
//! own on-chain state says the venue is down for 10 days in a row, the vault
//! latches an irreversible recovery mode and its capital can be moved to the
//! destinations fixed in `Config` at `initialize` (`emergency_recipient*`, the
//! admin wallet). SPEC v4 (DECISIONS §23): the admin exists for good (no
//! `renounce_admin`), so there is exactly one route, RECIPIENT; the former
//! route BUYBACK is gone.
//!
//! - Tag 50 `observe_venue` and tag 51 op 0 (latch) compute the verdict
//!   (`venue::status`) from accounts at pinned keys only; a wrong key or flag
//!   is an instruction error, never a verdict, so nobody can reset the
//!   countdown with a junk account.
//! - Op 1 / op 6 withdraw collateral from Phoenix to `vault_phusd`; op 4
//!   unwraps PhUSD (of `vault_phusd` or any other PhUSD account of
//!   `phx_authority`, full audit FA-3) to `vault_usdc`. They never move funds
//!   out of the vault.
//! - Op 2, 3, 5 are the only transfers out, and only to the recipients of
//!   SPEC §5.6.0, read from `Config` at every call. Nothing is an argument.
//! - Nobody trades or cancels through this tag. The trading key closes
//!   positions and cancels orders with tag 10 `trade`, which does not check
//!   the recovery mode (SPEC §5.2.3 T13, §5.6.5); Phoenix settles positions
//!   on its closed markets itself (O-16). Ops 7 and 8 do not exist
//!   (`InvalidInstructionData`, deny-by-default).
//! - The buyback escrow (`buyback_usdc`, SOL budget, `bb_wsol`,
//!   `buyback_token`) and the unpaid creator share (`creator_escrow_usdc`) are
//!   never touched (SPEC §5.6.6).
//!
//! Every handler performs the SPEC §4 shape check (data length, then account
//! count) first. No pause applies to tags 50 and 51 (SPEC §5.6.5).

use pinocchio::ProgramResult;
use pinocchio::account_info::AccountInfo;
use pinocchio::instruction::Signer;
use pinocchio::program_error::ProgramError;
use pinocchio::pubkey::{Pubkey, pubkey_eq};

use crate::constants::{
    EMBER_PROGRAM_ID, GC_MIN_LEN_WITH_COOLDOWN, HAWKEYE_PROGRAM_ID, PHOENIX_GLOBAL_CONFIG, PHOENIX_LOG_AUTHORITY,
    PHOENIX_PROGRAM_DATA, PHOENIX_PROGRAM_ID, RECOVERY_SHAVE_ABS, RECOVERY_SHAVE_BPS, SEED_FEE_INBOX,
    SEED_PHX_AUTHORITY, SPL_TOKEN_PROGRAM_ID, SYSTEM_PROGRAM_ID, TOKEN_ACCOUNT_LEN, VENUE_OBS_MIN_INTERVAL_S,
};
use crate::cpi::PdaSeeds;
use crate::cpi::ember::EmberAccounts;
use crate::cpi::hawkeye::{HawkeyeAccounts, view_margin};
use crate::cpi::phoenix_withdraw::{
    WithdrawAccounts, check_ember_state, check_ember_vault, ember_withdraw, withdraw_funds,
};
use crate::cpi::{system, token};
use crate::error::SijkaError;
use crate::events::{EvRecoveryLatch, EvRecoverySend, EvRecoveryWithdraw, EvVenueObservation};
use crate::external::layout::{global_config as gcl, trader as trl};
use crate::external::phoenix_accounts::{
    PamCheck, TraderCheck, check_arenas, check_arenas_disjoint, check_global_config, check_perp_asset_map,
    check_trader_account, has_open_position,
};
use crate::instructions::{
    OBSERVE_VENUE, RECOVER_LATCH, RECOVER_SEND_PHUSD, RECOVER_SEND_SOL, RECOVER_SEND_USDC, RECOVER_UNWRAP,
    RECOVER_WITHDRAW, RECOVER_WITHDRAW_FLAT, check_shape, read_op,
};
use crate::state::config::{Config, config_view_mut, load_config_mut};
use crate::util::accounts::{
    check_token, expect_key, expect_owner, expect_program, expect_readonly, expect_system_empty, expect_writable,
    read_token_account,
};
use crate::util::bytes::{is_zero_key, read_i64, read_u64};
use crate::util::math::{add_u64, rent_exempt_minimum, saturate_u64, sub_u64};
use crate::util::runtime::{clock, emit, last_restart_slot, set_return_data};
use crate::venue::status::{AccountView, MajorMemory, apply_observation, recovery_ready, venue_verdict};
use crate::venue::withdraw::{
    PlanParams, QueueScan, enqueue_too_soon, plan_withdraw, read_queue_header, unwrap_outcome, walk_queue,
    withdraw_outcome, withdraw_room,
};

/// Clock values used by a handler.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Env {
    pub now: i64,
    pub slot: u64,
}

#[inline(always)]
fn env() -> Result<Env, ProgramError> {
    let c = clock()?;
    Ok(Env { now: c.unix_timestamp, slot: c.slot })
}

/// Event field `route` of `SJKEVRCL` / `SJKEVRCS` (SPEC §7): always 0
/// (RECIPIENT). The value 1 (BUYBACK, after `renounce_admin`) is retired with
/// SPEC v4 and never written.
pub const ROUTE_RECIPIENT: u8 = 0;

#[inline(always)]
fn err<T>(e: SijkaError) -> Result<T, ProgramError> {
    Err(e.fail())
}

/// Checked `a + b` for a `Config` counter.
#[inline(always)]
fn inc(a: u64, b: u64) -> Result<u64, ProgramError> {
    add_u64(a, b)
}

// ============================================================ tag 50 / op 0

/// Tag 50 `observe_venue` (SPEC §5.6.3).
#[inline(never)]
pub fn observe_venue(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    check_shape(&OBSERVE_VENUE, accounts, data)?;
    observe_core(program_id, accounts, env()?, last_restart_slot()?, false)
}

/// Tag 51 (SPEC §5.6.4): dispatch by `op = data[1]`; unknown op → `InvalidInstructionData`.
#[inline(never)]
pub fn emergency_recover(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    match read_op(data, 1)? {
        0 => recover_latch(program_id, accounts, data),
        1 => recover_withdraw(program_id, accounts, data),
        2 => recover_send_usdc(program_id, accounts, data),
        3 => recover_send_sol(program_id, accounts, data),
        4 => recover_unwrap(program_id, accounts, data),
        5 => recover_send_phusd(program_id, accounts, data),
        6 => recover_withdraw_flat(program_id, accounts, data),
        _ => err(SijkaError::InvalidInstructionData),
    }
}

/// Tag 51 op 0 (SPEC §5.6.4): latch the recovery mode.
#[inline(never)]
fn recover_latch(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    check_shape(&RECOVER_LATCH, accounts, data)?;
    observe_core(program_id, accounts, env()?, last_restart_slot()?, true)
}

#[inline(always)]
fn view<'a>(ai: &'a AccountInfo, data: &'a [u8]) -> AccountView<'a> {
    AccountView { key: ai.key(), owner: ai.owner(), data }
}

/// Shared body of tag 50 (`latch = false`) and tag 51 op 0 (`latch = true`).
/// `lrs` is `sol_get_last_restart_slot()`.
#[inline(never)]
pub(crate) fn observe_core(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    env: Env,
    lrs: u64,
    latch: bool,
) -> ProgramResult {
    let [config, gc, pam, prog, pd] = accounts else {
        return err(SijkaError::InvalidAccountCount);
    };
    let mut cfg_data = load_config_mut(config, program_id)?;
    let mut cfg = config_view_mut(&mut cfg_data)?;
    // Op 0 step 1.
    if latch && cfg.view().in_recovery() {
        return err(SijkaError::RecoveryAlreadyActive);
    }
    // Accounts (§5.6.3): pinned keys, all read-only. Owner, length and data are
    // part of the verdict, not account checks.
    expect_key(gc, &PHOENIX_GLOBAL_CONFIG, SijkaError::InvalidPhoenixGlobalConfig)?;
    expect_readonly(gc)?;
    expect_readonly(pam)?;
    expect_key(prog, &PHOENIX_PROGRAM_ID, SijkaError::InvalidProgramId)?;
    expect_readonly(prog)?;
    expect_key(pd, &PHOENIX_PROGRAM_DATA, SijkaError::InvalidExternalAccount)?;
    expect_readonly(pd)?;
    // Tag 50 step 2: rate limit (op 0 is not limited).
    if !latch {
        let c = cfg.view();
        let last_slot = c.last_venue_obs_slot();
        if last_slot != 0 {
            let next = c
                .last_venue_obs_ts()
                .checked_add(VENUE_OBS_MIN_INTERVAL_S)
                .ok_or_else(|| SijkaError::MathOverflow.fail())?;
            if env.slot <= last_slot || env.now < next {
                return err(SijkaError::VenueObserveTooSoon);
            }
        }
    }
    // Verdict (§5.6.1).
    let (v, det) = {
        let c = cfg.view();
        let memory = MajorMemory::from_config(&c);
        let (gd, pmd, prd, pdd) =
            (gc.try_borrow_data()?, pam.try_borrow_data()?, prog.try_borrow_data()?, pd.try_borrow_data()?);
        venue_verdict(
            &view(prog, &prd),
            &view(pd, &pdd),
            &view(gc, &gd),
            &view(pam, &pmd),
            lrs,
            &memory,
            c.phusd_mint(),
        )?
    };
    // Countdown (§5.6.2). On op 0 an error below rolls the observation back too.
    let outcome = apply_observation(&mut cfg, &v, &det, env.now, env.slot)?;
    if latch {
        if !v.is_down() {
            return err(SijkaError::VenueNotDown);
        }
        if !recovery_ready(&cfg.view(), &v, env.now) {
            return err(SijkaError::VenueDownTooShort);
        }
        cfg.set_recovery_mode(1);
        cfg.set_recovery_latched_ts(env.now);
        cfg.set_recovery_latched_slot(env.slot);
    }

    let c = cfg.view();
    let mut flags = 0u8;
    if latch {
        flags |= 0x01;
    }
    if outcome.streak_restarted {
        flags |= 0x02;
    }
    if outcome.reset {
        flags |= 0x04;
    }
    if c.in_recovery() {
        flags |= 0x08;
    }
    if det.program_signal_off {
        flags |= 0x10;
    }
    let payload = EvVenueObservation {
        ts: env.now,
        verdict: v.kind(),
        reason: v.reason(),
        exchange_status: det.exchange_status,
        majors_open: det.majors_open,
        majors_closed: det.majors_closed,
        majors_unknown: det.majors_unknown,
        flags,
        slot: env.slot,
        ack: det.ack,
        lrs: det.lrs,
        live: det.live,
        down_since: c.venue_down_since_ts(),
        last_down_obs_ts: c.venue_last_down_obs_ts(),
        obs_count: c.venue_obs_count(),
    }
    .encode()?;
    emit(&payload);
    if latch {
        let down_since = c.venue_down_since_ts();
        EvRecoveryLatch {
            ts: env.now,
            reason: v.reason(),
            route: ROUTE_RECIPIENT,
            slot: env.slot,
            down_since,
            down_secs: env.now.checked_sub(down_since).ok_or_else(|| SijkaError::MathOverflow.fail())?,
            emergency_recipient: c.emergency_recipient(),
            usdc_destination: c.emergency_recipient_usdc(),
        }
        .emit()?;
    } else {
        set_return_data(&payload);
    }
    Ok(())
}

// ============================================================ op 1 / op 6

/// Accounts shared by op 1 and op 6 (op 6 has no `hawkeye_program`).
struct WithdrawCtx<'a> {
    config: &'a AccountInfo,
    phx_authority: &'a AccountInfo,
    phoenix_program: &'a AccountInfo,
    hawkeye_program: Option<&'a AccountInfo>,
    log_authority: &'a AccountInfo,
    global_config: &'a AccountInfo,
    trader_account: &'a AccountInfo,
    perp_asset_map: &'a AccountInfo,
    global_vault: &'a AccountInfo,
    withdraw_queue: &'a AccountInfo,
    vault_phusd: &'a AccountInfo,
    token_program: &'a AccountInfo,
    arenas: &'a [AccountInfo],
    gti_count: usize,
}

/// `max_amount u64 @4` of op 1 / op 6.
#[inline(always)]
fn max_amount(data: &[u8]) -> Result<u64, ProgramError> {
    read_u64(data, 4).ok_or_else(|| SijkaError::InvalidInstructionData.fail())
}

/// Tag 51 op 1 (SPEC §5.6.4): withdraw collateral (amount from Hawkeye) to `vault_phusd`.
#[inline(never)]
fn recover_withdraw(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let info = check_shape(&RECOVER_WITHDRAW, accounts, data)?;
    let (fixed, arenas) =
        accounts.split_at_checked(RECOVER_WITHDRAW.accounts).ok_or_else(|| SijkaError::InvalidAccountCount.fail())?;
    let [config, phx_authority, phoenix, hawkeye, log, gc, trader, pam, gvault, wq, vault_phusd, token_program] = fixed
    else {
        return err(SijkaError::InvalidAccountCount);
    };
    let ctx = WithdrawCtx {
        config,
        phx_authority,
        phoenix_program: phoenix,
        hawkeye_program: Some(hawkeye),
        log_authority: log,
        global_config: gc,
        trader_account: trader,
        perp_asset_map: pam,
        global_vault: gvault,
        withdraw_queue: wq,
        vault_phusd,
        token_program,
        arenas,
        gti_count: info.gti,
    };
    withdraw_core(program_id, &ctx, max_amount(data)?, env()?)
}

/// Tag 51 op 6 (SPEC §5.6.4, review REC-10): withdraw without Hawkeye, only
/// for an account without positions.
#[inline(never)]
fn recover_withdraw_flat(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let info = check_shape(&RECOVER_WITHDRAW_FLAT, accounts, data)?;
    let (fixed, arenas) = accounts
        .split_at_checked(RECOVER_WITHDRAW_FLAT.accounts)
        .ok_or_else(|| SijkaError::InvalidAccountCount.fail())?;
    let [config, phx_authority, phoenix, log, gc, trader, pam, gvault, wq, vault_phusd, token_program] = fixed else {
        return err(SijkaError::InvalidAccountCount);
    };
    let ctx = WithdrawCtx {
        config,
        phx_authority,
        phoenix_program: phoenix,
        hawkeye_program: None,
        log_authority: log,
        global_config: gc,
        trader_account: trader,
        perp_asset_map: pam,
        global_vault: gvault,
        withdraw_queue: wq,
        vault_phusd,
        token_program,
        arenas,
        gti_count: info.gti,
    };
    withdraw_core(program_id, &ctx, max_amount(data)?, env()?)
}

/// Body of op 1 (`hawkeye_program` present) and op 6 (absent).
#[inline(never)]
fn withdraw_core(program_id: &Pubkey, a: &WithdrawCtx<'_>, max_amount: u64, env: Env) -> ProgramResult {
    let flat = a.hawkeye_program.is_none();
    let mut cfg_data = load_config_mut(a.config, program_id)?;
    let mut cfg = config_view_mut(&mut cfg_data)?;
    let c = cfg.view();

    // Step 1 (live venue status is NOT checked: Phoenix itself refuses while inactive).
    if !c.in_recovery() {
        return err(SijkaError::RecoveryNotActive);
    }
    let phoenix_trader = *c.phoenix_trader();
    if is_zero_key(&phoenix_trader) {
        return err(SijkaError::TraderNotRegistered);
    }
    let phx_authority = *c.phx_authority();
    let phusd_mint = *c.phusd_mint();
    let vault_phusd_key = *c.vault_phusd();
    let bump = c.phx_authority_bump();
    let last_enqueue = c.recovery_last_enqueue_slot();
    let hp = c.harvest();
    // SPEC v4 (DECISIONS §23 item 6): the shave width is a constant (the
    // former launch values of the retired withdraw tolerance).
    let plan_params = PlanParams { d_min: hp.d_min(), shave_abs: RECOVERY_SHAVE_ABS, shave_bps: RECOVERY_SHAVE_BPS };
    let (q_fallback, buf_abs, buf_bps) = (hp.max_harvest_per_call(), hp.margin_buffer_abs(), hp.margin_buffer_im_bps());

    // Step 2: accounts.
    expect_key(a.phx_authority, &phx_authority, SijkaError::InvalidPda)?;
    expect_program(a.phoenix_program, &PHOENIX_PROGRAM_ID)?;
    if let Some(h) = a.hawkeye_program {
        expect_program(h, &HAWKEYE_PROGRAM_ID)?;
    }
    expect_key(a.log_authority, &PHOENIX_LOG_AUTHORITY, SijkaError::InvalidExternalAccount)?;
    let gk = check_global_config(a.global_config, GC_MIN_LEN_WITH_COOLDOWN, true)?;
    // Op 1 reads only `@192` of the trader (REC-9); op 6 reads `@88` and the positions.
    let trader_mode = if flat { TraderCheck::Full } else { TraderCheck::WithdrawOnly };
    check_trader_account(a.trader_account, &phoenix_trader, &phx_authority, trader_mode, true)?;
    check_perp_asset_map(a.perp_asset_map, &gk.perp_asset_map, PamCheck::KeyAndOwner, true)?;
    expect_key(a.global_vault, &gk.global_vault, SijkaError::InvalidPhoenixGlobalConfig)?;
    expect_writable(a.global_vault)?;
    expect_key(a.withdraw_queue, &gk.withdraw_queue, SijkaError::InvalidPhoenixGlobalConfig)?;
    expect_writable(a.withdraw_queue)?;
    expect_key(a.vault_phusd, &vault_phusd_key, SijkaError::InvalidPda)?;
    expect_writable(a.vault_phusd)?;
    check_token(
        a.vault_phusd,
        &SPL_TOKEN_PROGRAM_ID,
        &phusd_mint,
        &phx_authority,
        false,
        SijkaError::InvalidTokenAccount,
    )?;
    if !pubkey_eq(&phusd_mint, &gk.canonical_mint) {
        return err(SijkaError::InvalidPhoenixGlobalConfig);
    }
    expect_program(a.token_program, &SPL_TOKEN_PROGRAM_ID)?;
    check_arenas(a.arenas, a.gti_count, &gk, true)?;
    check_arenas_disjoint(a.arenas, &[a.trader_account.key(), a.global_vault.key(), a.withdraw_queue.key()])?;
    let (gti, atb) = a.arenas.split_at_checked(a.gti_count).ok_or_else(|| SijkaError::InvalidArenaAccounts.fail())?;

    // Step 3: Phoenix deposit cooldown.
    let cd = read_u64(&a.global_config.try_borrow_data()?, gcl::DEPOSIT_COOLDOWN_SLOTS)
        .ok_or_else(|| SijkaError::InvalidPhoenixGlobalConfig.fail())?;
    let (lds, c_hdr) = {
        let t = a.trader_account.try_borrow_data()?;
        (read_u64(&t, trl::LAST_DEPOSIT_SLOT), read_i64(&t, trl::COLLATERAL))
    };
    let lds = lds.ok_or_else(|| SijkaError::InvalidPhoenixTraderAccount.fail())?;
    if cd > 0 && env.slot < lds.saturating_add(cd) {
        return err(SijkaError::WithdrawCooldown);
    }

    // Step 4: withdraw queue header.
    let wq_phoenix = a.withdraw_queue.is_owned_by(&PHOENIX_PROGRAM_ID);
    let q = read_queue_header(wq_phoenix, &a.withdraw_queue.try_borrow_data()?, env.slot, q_fallback);

    // Steps 5–7 (op 1) / 2–3 (op 6).
    let (d_room, buf, margin) = match a.hawkeye_program {
        Some(h) => {
            let m = view_margin(&HawkeyeAccounts {
                hawkeye_program: h,
                phoenix_program: a.phoenix_program,
                global_config: a.global_config,
                gti,
                atb,
                perp_asset_map: a.perp_asset_map,
                trader_account: a.trader_account,
            })?;
            // Fail closed: a risky account has no free collateral.
            if m.risk_tier != 0 || m.is_liquidatable != 0 {
                return err(SijkaError::HarvestRiskState);
            }
            let (room, buf) =
                withdraw_room(m.free_collateral, m.withdrawable_collateral, m.initial_margin, buf_abs, buf_bps)
                    .map_err(SijkaError::fail)?;
            (room, buf, Some(m))
        }
        None => {
            let c_hdr = c_hdr.ok_or_else(|| SijkaError::InvalidPhoenixTraderAccount.fail())?;
            if c_hdr <= 0 {
                return err(SijkaError::RecoveryNothing);
            }
            (i128::from(c_hdr), 0, None)
        }
    };
    let plan = plan_withdraw(d_room, &q, max_amount, &plan_params, flat).map_err(SijkaError::fail)?;

    // Step 8: QUEUE mode only (REC-4): one request of ours, not too often.
    if plan.queued {
        if enqueue_too_soon(last_enqueue, env.slot) {
            return err(SijkaError::RecoveryEnqueueTooSoon);
        }
        match walk_queue(&a.withdraw_queue.try_borrow_data()?, &phoenix_trader) {
            QueueScan::Clear => {}
            QueueScan::OurActive => return err(SijkaError::RecoveryAlreadyQueued),
            QueueScan::Broken => return err(SijkaError::WithdrawQueueBusy),
        }
    }

    // Steps 9–10: withdraw D to vault_phusd (every borrow of CPI accounts released).
    let phusd0 = check_token(
        a.vault_phusd,
        &SPL_TOKEN_PROGRAM_ID,
        &phusd_mint,
        &phx_authority,
        false,
        SijkaError::InvalidTokenAccount,
    )?;
    let seeds = PdaSeeds::new(SEED_PHX_AUTHORITY, bump);
    let s = seeds.seeds();
    let signer = [Signer::from(&s)];
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
            gti,
            atb,
            withdraw_queue: a.withdraw_queue,
        },
        plan.d,
        &signer,
    )?;

    // Step 11: what arrived.
    let phusd1 = check_token(
        a.vault_phusd,
        &SPL_TOKEN_PROGRAM_ID,
        &phusd_mint,
        &phx_authority,
        false,
        SijkaError::InvalidTokenAccount,
    )?;
    let q_after = read_queue_header(wq_phoenix, &a.withdraw_queue.try_borrow_data()?, env.slot, q_fallback);
    let (r, queued) = withdraw_outcome(&plan, q.total_queued, phusd0, phusd1, &q_after).map_err(SijkaError::fail)?;
    // Op 6 step 5: the map is reliable right after our own CPI (§3.9).
    if flat && has_open_position(&a.trader_account.try_borrow_data()?) != Some(false) {
        return err(SijkaError::RecoveryNotFlat);
    }

    // Step 12: Config (checked). I, O and the harvest counters are untouched.
    let c = cfg.view();
    let (mut withdrawn, mut fees, mut queued_sum) =
        (c.cum_recovery_withdrawn(), c.cum_recovery_fees(), c.cum_recovery_queued());
    let op_count = inc(c.recovery_op_count(), 1)?;
    if r > 0 {
        withdrawn = inc(withdrawn, r)?;
        fees = inc(fees, sub_u64(plan.d, r)?)?;
    }
    if queued {
        queued_sum = inc(queued_sum, plan.d)?;
        cfg.set_recovery_last_enqueue_slot(env.slot);
    }
    cfg.set_cum_recovery_withdrawn(withdrawn);
    cfg.set_cum_recovery_fees(fees);
    cfg.set_cum_recovery_queued(queued_sum);
    cfg.set_recovery_op_count(op_count);

    // Step 13: event and return data.
    let mut bits = 0u8;
    if plan.budget_limited {
        bits |= 0x01;
    }
    if buf == 0 {
        bits |= 0x02;
    }
    if queued {
        bits |= 0x04;
    }
    if plan.amount_limited {
        bits |= 0x08;
    }
    if !q.hdr_ok {
        bits |= 0x10;
    }
    let payload = EvRecoveryWithdraw {
        ts: env.now,
        op: if flat { 6 } else { 1 },
        bits,
        slot: env.slot,
        d: plan.d,
        r,
        max_amount,
        free: margin.map_or(0, |m| m.free_collateral),
        wd: margin.map_or(0, |m| m.withdrawable_collateral),
        im: margin.map_or(0, |m| m.initial_margin),
        buf: saturate_u64(buf),
        c_hdr: if flat { c_hdr.unwrap_or(0) } else { 0 },
        q_tmp: q.q_tmp,
        total_queued_after: if q_after.hdr_ok { q_after.total_queued } else { 0 },
        cum_withdrawn_after: withdrawn,
        cum_queued_after: queued_sum,
    }
    .encode()?;
    emit(&payload);
    set_return_data(&payload);
    Ok(())
}

// ================================================================= op 4

/// Tag 51 op 4 (SPEC §5.6.4, review REC-2): unwrap all PhUSD on
/// `vault_phusd` (or another clean PhUSD account of `phx_authority`, full
/// audit FA-3) into USDC on `vault_usdc` through Ember.
#[inline(never)]
fn recover_unwrap(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    check_shape(&RECOVER_UNWRAP, accounts, data)?;
    unwrap_core(program_id, accounts, env()?)
}

fn unwrap_core(program_id: &Pubkey, accounts: &[AccountInfo], env: Env) -> ProgramResult {
    let [
        config,
        phx_authority,
        vault_phusd,
        vault_usdc,
        usdc_mint,
        phusd_mint,
        ember_program,
        ember_state,
        ember_vault,
        token_program,
    ] = accounts
    else {
        return err(SijkaError::InvalidAccountCount);
    };
    let mut cfg_data = load_config_mut(config, program_id)?;
    let mut cfg = config_view_mut(&mut cfg_data)?;
    let c = cfg.view();
    if !c.in_recovery() {
        return err(SijkaError::RecoveryNotActive);
    }
    let (auth, usdc, phusd) = (*c.phx_authority(), *c.usdc_mint(), *c.phusd_mint());
    let bump = c.phx_authority_bump();

    expect_key(phx_authority, &auth, SijkaError::InvalidPda)?;
    // Source: `vault_phusd` or any other clean SPL Token PhUSD account of
    // `phx_authority` (full audit FA-3). Phoenix's permissionless
    // `consume_withdraw_queue` takes the destination from its caller, and
    // anyone can `InitializeAccount3` a PhUSD account owned by our PDA; such a
    // delivery must still reach `vault_usdc`. Only our PDA can move tokens off
    // it, so everything on it is capital like `vault_phusd` (SPEC §5.6.4).
    expect_writable(vault_phusd)?;
    let p = check_token(vault_phusd, &SPL_TOKEN_PROGRAM_ID, &phusd, &auth, false, SijkaError::InvalidTokenAccount)?;
    expect_key(vault_usdc, c.vault_usdc(), SijkaError::InvalidPda)?;
    expect_writable(vault_usdc)?;
    let usdc0 = check_token(vault_usdc, &SPL_TOKEN_PROGRAM_ID, &usdc, &auth, false, SijkaError::InvalidTokenAccount)?;
    expect_key(usdc_mint, &usdc, SijkaError::InvalidExternalAccount)?;
    expect_owner(usdc_mint, &SPL_TOKEN_PROGRAM_ID, SijkaError::InvalidExternalAccount)?;
    // Ember burns PhUSD: the mint is written.
    expect_key(phusd_mint, &phusd, SijkaError::InvalidExternalAccount)?;
    expect_owner(phusd_mint, &SPL_TOKEN_PROGRAM_ID, SijkaError::InvalidExternalAccount)?;
    expect_writable(phusd_mint)?;
    expect_program(ember_program, &EMBER_PROGRAM_ID)?;
    check_ember_state(ember_state, &usdc, &phusd)?;
    check_ember_vault(ember_vault)?;
    expect_program(token_program, &SPL_TOKEN_PROGRAM_ID)?;

    // Everything on the source is capital (withdrawals, queue deliveries, donations).
    if p == 0 {
        return err(SijkaError::RecoveryNothing);
    }
    let seeds = PdaSeeds::new(SEED_PHX_AUTHORITY, bump);
    let s = seeds.seeds();
    let signer = [Signer::from(&s)];
    ember_withdraw(
        &EmberAccounts {
            ember_program,
            trader: phx_authority,
            ember_state,
            usdc_mint,
            canonical_mint: phusd_mint,
            trader_usdc_account: vault_usdc,
            trader_phoenix_account: vault_phusd,
            ember_vault,
            token_program,
        },
        p,
        &signer,
    )?;
    let phusd_left =
        check_token(vault_phusd, &SPL_TOKEN_PROGRAM_ID, &phusd, &auth, false, SijkaError::InvalidTokenAccount)?;
    let usdc1 = check_token(vault_usdc, &SPL_TOKEN_PROGRAM_ID, &usdc, &auth, false, SijkaError::InvalidTokenAccount)?;
    // No lower bound on u (REC-8); the shortfall is recorded in cum_recovery_fees.
    let u = unwrap_outcome(p, phusd_left, usdc0, usdc1).map_err(SijkaError::fail)?;

    let c = cfg.view();
    let unwrapped = inc(c.cum_recovery_unwrapped(), p)?;
    let fees = inc(c.cum_recovery_fees(), sub_u64(p, u)?)?;
    let op_count = inc(c.recovery_op_count(), 1)?;
    cfg.set_cum_recovery_unwrapped(unwrapped);
    cfg.set_cum_recovery_fees(fees);
    cfg.set_recovery_op_count(op_count);
    EvRecoverySend {
        ts: env.now,
        op: 4,
        route: ROUTE_RECIPIENT,
        slot: env.slot,
        phusd_unwrapped: p,
        usdc_from_ember: u,
        amount: u,
        destination: vault_usdc.key(),
        cum_after: unwrapped,
    }
    .emit()
}

// ======================================================== op 2 / op 5

/// Destination check for USDC (SPEC §5.6.0 table): `emergency_recipient_usdc`.
fn check_usdc_destination(dest: &AccountInfo, cfg: &Config<'_>) -> ProgramResult {
    let e = SijkaError::RecoveryRecipientInvalid;
    expect_key(dest, cfg.emergency_recipient_usdc(), e)?;
    // The recipient's own account: delegate / close authority are not checked.
    if !dest.is_writable() || dest.data_len() != TOKEN_ACCOUNT_LEN {
        return err(e);
    }
    read_token_account(dest, &SPL_TOKEN_PROGRAM_ID, cfg.usdc_mint(), Some(cfg.emergency_recipient()), e).map(|_| ())
}

/// Destination check for PhUSD (SPEC §5.6.0): `emergency_recipient_phusd`.
fn check_phusd_destination(dest: &AccountInfo, cfg: &Config<'_>) -> ProgramResult {
    let e = SijkaError::RecoveryRecipientInvalid;
    expect_key(dest, cfg.emergency_recipient_phusd(), e)?;
    if !dest.is_writable() || dest.data_len() != TOKEN_ACCOUNT_LEN {
        return err(e);
    }
    read_token_account(dest, &SPL_TOKEN_PROGRAM_ID, cfg.phusd_mint(), Some(cfg.emergency_recipient()), e).map(|_| ())
}

/// Tag 51 op 2 (SPEC §5.6.4): all USDC on `vault_usdc` → `emergency_recipient_usdc`.
#[inline(never)]
fn recover_send_usdc(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    check_shape(&RECOVER_SEND_USDC, accounts, data)?;
    send_token_core(program_id, accounts, env()?, false)
}

/// Tag 51 op 5 (SPEC §5.6.4): all PhUSD on `vault_phusd` (or another clean
/// PhUSD account of `phx_authority`, full audit FA-3) → `emergency_recipient_phusd`.
#[inline(never)]
fn recover_send_phusd(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    check_shape(&RECOVER_SEND_PHUSD, accounts, data)?;
    send_token_core(program_id, accounts, env()?, true)
}

/// Body of op 2 (`phusd = false`) and op 5 (`phusd = true`):
/// `[config W, phx_authority, source W, token_program, destination W]`.
#[inline(never)]
fn send_token_core(program_id: &Pubkey, accounts: &[AccountInfo], env: Env, phusd: bool) -> ProgramResult {
    let [config, phx_authority, source, token_program, dest] = accounts else {
        return err(SijkaError::InvalidAccountCount);
    };
    let mut cfg_data = load_config_mut(config, program_id)?;
    let mut cfg = config_view_mut(&mut cfg_data)?;
    let c = cfg.view();
    if !c.in_recovery() {
        return err(SijkaError::RecoveryNotActive);
    }
    let mint = if phusd { *c.phusd_mint() } else { *c.usdc_mint() };
    let auth = *c.phx_authority();
    expect_key(phx_authority, &auth, SijkaError::InvalidPda)?;
    // Op 2: `vault_usdc` only (op 4 always unwraps into it). Op 5: any clean
    // SPL Token PhUSD account of `phx_authority`, as op 4 (full audit FA-3).
    if !phusd {
        expect_key(source, c.vault_usdc(), SijkaError::InvalidPda)?;
    }
    expect_writable(source)?;
    let amount = check_token(source, &SPL_TOKEN_PROGRAM_ID, &mint, &auth, false, SijkaError::InvalidTokenAccount)?;
    expect_program(token_program, &SPL_TOKEN_PROGRAM_ID)?;
    if phusd {
        check_phusd_destination(dest, &c)?;
    } else {
        check_usdc_destination(dest, &c)?;
    }
    if amount == 0 {
        return err(SijkaError::RecoveryNothing);
    }
    let bump = c.phx_authority_bump();
    let seeds = PdaSeeds::new(SEED_PHX_AUTHORITY, bump);
    let s = seeds.seeds();
    let signer = [Signer::from(&s)];
    token::transfer(token_program, source, dest, phx_authority, amount, &signer)?;
    let left = check_token(source, &SPL_TOKEN_PROGRAM_ID, &mint, &auth, false, SijkaError::InvalidTokenAccount)?;
    if left != 0 {
        return err(SijkaError::InvariantViolated);
    }

    let c = cfg.view();
    let op_count = inc(c.recovery_op_count(), 1)?;
    let cum = if phusd {
        let v = inc(c.cum_recovered_phusd(), amount)?;
        cfg.set_cum_recovered_phusd(v);
        v
    } else {
        let v = inc(c.cum_recovered_usdc(), amount)?;
        cfg.set_cum_recovered_usdc(v);
        v
    };
    cfg.set_recovery_op_count(op_count);
    EvRecoverySend {
        ts: env.now,
        op: if phusd { 5 } else { 2 },
        route: ROUTE_RECIPIENT,
        slot: env.slot,
        phusd_unwrapped: 0,
        usdc_from_ember: 0,
        amount,
        destination: dest.key(),
        cum_after: cum,
    }
    .emit()
}

// ================================================================= op 3

/// Tag 51 op 3 (SPEC §5.6.4): SOL above rent on `fee_inbox` → `emergency_recipient`.
#[inline(never)]
fn recover_send_sol(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    check_shape(&RECOVER_SEND_SOL, accounts, data)?;
    send_sol_core(program_id, accounts, env()?, rent_exempt_minimum(0)?)
}

/// `rent0 = Rent::get()?.minimum_balance(0)` (the `fee_inbox` reserve `R`).
fn send_sol_core(program_id: &Pubkey, accounts: &[AccountInfo], env: Env, rent0: u64) -> ProgramResult {
    let [config, fee_inbox, dest, system_program] = accounts else {
        return err(SijkaError::InvalidAccountCount);
    };
    let mut cfg_data = load_config_mut(config, program_id)?;
    let mut cfg = config_view_mut(&mut cfg_data)?;
    let c = cfg.view();
    if !c.in_recovery() {
        return err(SijkaError::RecoveryNotActive);
    }
    expect_key(fee_inbox, c.fee_inbox(), SijkaError::InvalidPda)?;
    expect_system_empty(fee_inbox, SijkaError::InvalidExternalAccount)?;
    expect_writable(fee_inbox)?;
    {
        let e = SijkaError::RecoveryRecipientInvalid;
        expect_key(dest, c.emergency_recipient(), e)?;
        if !dest.is_writable() {
            return err(e);
        }
    }
    expect_program(system_program, &SYSTEM_PROGRAM_ID)?;
    let amount = fee_inbox.lamports().saturating_sub(rent0);
    if amount == 0 {
        return err(SijkaError::RecoveryNothing);
    }
    let seeds = PdaSeeds::new(SEED_FEE_INBOX, c.fee_inbox_bump());
    let s = seeds.seeds();
    let signer = [Signer::from(&s)];
    system::transfer(fee_inbox, dest, amount, &signer)?;
    // The fee_inbox reserve invariant (§5.3.1) holds exactly.
    if fee_inbox.lamports() != rent0 {
        return err(SijkaError::InvariantViolated);
    }

    let c = cfg.view();
    let op_count = inc(c.recovery_op_count(), 1)?;
    let cum = inc(c.cum_recovered_lamports(), amount)?;
    cfg.set_cum_recovered_lamports(cum);
    cfg.set_recovery_op_count(op_count);
    EvRecoverySend {
        ts: env.now,
        op: 3,
        route: ROUTE_RECIPIENT,
        slot: env.slot,
        phusd_unwrapped: 0,
        usdc_from_ember: 0,
        amount,
        destination: dest.key(),
        cum_after: cum,
    }
    .emit()
}

#[cfg(test)]
mod tests {
    //! Handler tests on host `AccountInfo`s. On the host every CPI is a no-op
    //! (pinocchio still checks borrows), so a path that passes every check
    //! before the CPI ends in its post-CPI invariant (for example
    //! `InvariantViolated`: nothing was transferred). Post-CPI arithmetic is
    //! tested on the pure functions in `venue::*`; LiteSVM tests (Linux CI)
    //! cover the real CPIs.

    use super::*;
    use crate::constants::{
        BPF_LOADER_UPGRADEABLE_ID, DISC_CONFIG, DISC_EMBER_STATE, DISC_TRADER, EMBER_STATE, EMBER_VAULT,
        RECOVERY_DOWN_SECS, TOKEN_2022_PROGRAM_ID, WSOL_MINT,
    };
    use crate::state::config::harvest_params::HarvestParamsMut;
    use crate::state::config::{CONFIG_LEN, ConfigMut};
    use crate::util::test_utils::{TestAccount, infos};
    use crate::venue::status::reason;
    use crate::venue::status::tests::{Fixture, LIVE_ACK, PAM_KEY, PHUSD, live_pam};
    use crate::venue::withdraw::tests::{Q, queue_bytes};

    const PID: Pubkey = [0x11; 32];
    const CFG: Pubkey = [0x12; 32];
    const ADMIN: Pubkey = [0x21; 32];
    const ER_USDC: Pubkey = [0x22; 32];
    const ER_PHUSD: Pubkey = [0x23; 32];
    const USDC: Pubkey = [0x24; 32];
    const PHX: Pubkey = [0x25; 32];
    const VUSDC: Pubkey = [0x26; 32];
    const VPHUSD: Pubkey = [0x27; 32];
    const FEE: Pubkey = [0x28; 32];
    const BBA: Pubkey = [0x29; 32];
    const BBU: Pubkey = [0x2A; 32];
    const TRADER: Pubkey = [0x2B; 32];
    /// Keys in `status::tests::gc_bytes`.
    const GVAULT: Pubkey = [0x41; 32];
    const GTI0: Pubkey = [0x42; 32];
    const ATB0: Pubkey = [0x43; 32];
    const WQ: Pubkey = [0x44; 32];
    const T0: i64 = 1_800_000_000;
    const RENT0: u64 = 890_880;
    /// Two days after the latch at `T0`.
    const E: Env = Env { now: T0 + 2 * 86_400, slot: 5_000 };

    fn cfg_bytes(recovery: bool, admin: bool, sol_pair: bool) -> Vec<u8> {
        let mut b = vec![0u8; CONFIG_LEN];
        let mut m = ConfigMut::new(&mut b).unwrap();
        m.set_discriminator(&DISC_CONFIG);
        m.set_version(1);
        m.set_admin(if admin { &ADMIN } else { &[0; 32] });
        m.set_emergency_recipient(&ADMIN);
        m.set_emergency_recipient_usdc(&ER_USDC);
        m.set_emergency_recipient_phusd(&ER_PHUSD);
        m.set_quote_mint(if sol_pair { &WSOL_MINT } else { &USDC });
        m.set_usdc_mint(&USDC);
        m.set_phusd_mint(&PHUSD);
        m.set_phx_authority(&PHX);
        m.set_phx_authority_bump(250);
        m.set_vault_usdc(&VUSDC);
        m.set_vault_phusd(&VPHUSD);
        m.set_fee_inbox(&FEE);
        m.set_fee_inbox_bump(251);
        m.set_buyback_authority(&BBA);
        m.set_buyback_usdc(&BBU);
        m.set_phoenix_trader(&TRADER);
        let mut hp = [0u8; 64];
        {
            let mut h = HarvestParamsMut::from_array(&mut hp);
            h.set_d_min(1_000);
            h.set_max_harvest_per_call(1_000_000_000_000);

            h.set_margin_buffer_abs(500);
            h.set_margin_buffer_im_bps(1_000);
        }
        m.set_harvest_params(&hp);
        if recovery {
            m.set_recovery_mode(1);
            m.set_recovery_latched_ts(T0);
            m.set_recovery_latched_slot(1_000);
        }
        b
    }

    fn edit_cfg(b: &mut [u8], f: impl FnOnce(&mut ConfigMut<'_>)) {
        f(&mut ConfigMut::new(b).unwrap());
    }

    fn acc(key: Pubkey, owner: Pubkey, data: &[u8], writable: bool) -> TestAccount {
        TestAccount::new(key, owner, 1_000_000, data, false, writable, false)
    }

    fn program(key: Pubkey) -> TestAccount {
        TestAccount::new(key, BPF_LOADER_UPGRADEABLE_ID, 1, &[], false, false, true)
    }

    fn token_data(mint: &Pubkey, owner: &Pubkey, amount: u64) -> Vec<u8> {
        let mut d = vec![0u8; TOKEN_ACCOUNT_LEN];
        d[0..32].copy_from_slice(mint);
        d[32..64].copy_from_slice(owner);
        d[64..72].copy_from_slice(&amount.to_le_bytes());
        d[108] = 1;
        d
    }

    fn token(key: Pubkey, mint: &Pubkey, owner: &Pubkey, amount: u64) -> TestAccount {
        acc(key, SPL_TOKEN_PROGRAM_ID, &token_data(mint, owner, amount), true)
    }

    fn config_of(a: &mut TestAccount) -> Vec<u8> {
        a.data_mut().to_vec()
    }

    fn e(x: SijkaError) -> ProgramResult {
        Err(x.into())
    }

    /// SPEC v4: there is one route, RECIPIENT, whatever the `Config` holds (a
    /// zeroed admin, which the program can no longer produce, changes nothing).
    #[test]
    fn route_is_always_the_recipient() {
        assert_eq!(ROUTE_RECIPIENT, 0);
        for admin in [true, false] {
            let cfg = cfg_bytes(true, admin, true);
            let src = || token(VUSDC, &USDC, &PHX, 99);
            // USDC only to emergency_recipient_usdc, never to buyback_usdc.
            assert_eq!(
                send(&send_accs(&cfg, src(), token(BBU, &USDC, &BBA, 0)), false),
                e(SijkaError::RecoveryRecipientInvalid)
            );
            assert_eq!(
                send(&send_accs(&cfg, src(), token(ER_USDC, &USDC, &ADMIN, 0)), false),
                e(SijkaError::InvariantViolated)
            );
            // PhUSD as is to emergency_recipient_phusd.
            let phusd_src = token(VPHUSD, &PHUSD, &PHX, 5);
            assert_eq!(
                send(&send_accs(&cfg, phusd_src, token(ER_PHUSD, &PHUSD, &ADMIN, 0)), true),
                e(SijkaError::InvariantViolated)
            );
            // SOL only to emergency_recipient, never to buyback_authority.
            for sol_pair in [true, false] {
                let cfg = cfg_bytes(true, admin, sol_pair);
                let budget = acc(BBA, SYSTEM_PROGRAM_ID, &[], true);
                assert_eq!(send_sol(&sol_accs(&cfg, RENT0 + 5, budget)), e(SijkaError::RecoveryRecipientInvalid));
                let wallet = acc(ADMIN, SYSTEM_PROGRAM_ID, &[], true);
                assert_eq!(send_sol(&sol_accs(&cfg, RENT0 + 5, wallet)), e(SijkaError::InvariantViolated));
            }
        }
    }

    // ------------------------------------------------------ tag 50, op 0

    fn venue_accs(cfg: &[u8], f: &Fixture) -> Vec<TestAccount> {
        vec![
            acc(CFG, PID, cfg, true),
            acc(PHOENIX_GLOBAL_CONFIG, f.gc_owner, &f.gc, false),
            acc(f.pam_key, f.pam_owner, &f.pam, false),
            TestAccount::new(PHOENIX_PROGRAM_ID, f.prog_owner, 1, &f.prog, false, false, true),
            acc(PHOENIX_PROGRAM_DATA, f.pd_owner, &f.pd, false),
        ]
    }

    fn observe(accs: &[TestAccount], env: Env, latch: bool) -> ProgramResult {
        observe_core(&PID, &infos(accs), env, LIVE_ACK, latch)
    }

    #[test]
    fn observe_records_up_and_rate_limits() {
        let f = Fixture::live();
        let mut accs = venue_accs(&cfg_bytes(false, true, true), &f);
        assert_eq!(observe(&accs, Env { now: T0, slot: 100 }, false), Ok(()));
        let b = config_of(&mut accs[0]);
        let c = Config::new(&b).unwrap();
        assert_eq!((c.venue_last_verdict(), c.venue_last_reason()), (1, reason::UP));
        assert_eq!(MajorMemory::from_config(&c), MajorMemory { seen: 0b111, asset_ids: [0, 1, 2] });
        assert_eq!((c.last_venue_obs_ts(), c.last_venue_obs_slot(), c.venue_obs_count()), (T0, 100, 1));
        assert_eq!(c.venue_down_since_ts(), 0);
        // Same slot, or 29 s later: too soon; 30 s and a new slot: fine.
        assert_eq!(observe(&accs, Env { now: T0 + 60, slot: 100 }, false), e(SijkaError::VenueObserveTooSoon));
        assert_eq!(observe(&accs, Env { now: T0 + 29, slot: 101 }, false), e(SijkaError::VenueObserveTooSoon));
        assert_eq!(observe(&accs, Env { now: T0 + 30, slot: 101 }, false), Ok(()));
        // Op 0 is not rate limited: it reaches the verdict (UP → VenueNotDown).
        assert_eq!(observe(&accs, Env { now: T0 + 30, slot: 101 }, true), e(SijkaError::VenueNotDown));
    }

    #[test]
    fn observe_account_checks() {
        let f = Fixture::live();
        let cfg = cfg_bytes(false, true, true);
        let env = Env { now: T0, slot: 100 };
        type Mutation = fn(&mut Vec<TestAccount>, &Fixture);
        let cases: [(Mutation, SijkaError); 11] = [
            (|a, f| a[1] = acc([9; 32], PHOENIX_PROGRAM_ID, &f.gc, false), SijkaError::InvalidPhoenixGlobalConfig),
            (
                |a, f| a[1] = acc(PHOENIX_GLOBAL_CONFIG, PHOENIX_PROGRAM_ID, &f.gc, true),
                SijkaError::AccountMustBeReadonly,
            ),
            (|a, f| a[2] = acc(PAM_KEY, PHOENIX_PROGRAM_ID, &f.pam, true), SijkaError::AccountMustBeReadonly),
            (|a, f| a[2] = acc([0x52; 32], PHOENIX_PROGRAM_ID, &f.pam, false), SijkaError::InvalidPerpAssetMap),
            (|a, f| a[3] = acc([9; 32], f.prog_owner, &f.prog, false), SijkaError::InvalidProgramId),
            (|a, f| a[3] = acc(PHOENIX_PROGRAM_ID, f.prog_owner, &f.prog, true), SijkaError::AccountMustBeReadonly),
            (|a, f| a[4] = acc([7; 32], f.pd_owner, &f.pd, false), SijkaError::InvalidExternalAccount),
            (|a, f| a[4] = acc(PHOENIX_PROGRAM_DATA, f.pd_owner, &f.pd, true), SijkaError::AccountMustBeReadonly),
            (|a, _| a[0] = acc(CFG, PID, &cfg_bytes(false, true, true), false), SijkaError::AccountNotWritable),
            (|a, _| a[0] = acc(CFG, [3; 32], &cfg_bytes(false, true, true), true), SijkaError::InvalidConfigAccount),
            (|a, _| a.truncate(4), SijkaError::InvalidAccountCount),
        ];
        for (i, (mutate, want)) in cases.iter().enumerate() {
            let mut accs = venue_accs(&cfg, &f);
            mutate(&mut accs, &f);
            assert_eq!(observe(&accs, env, false), e(*want), "case {i}");
            // Nothing was written.
            assert_eq!(config_of(&mut accs[0])[1401..1456], cfg[1401..1456], "case {i}");
        }
        // PAM owned by System at the GC@360 key: a FORMAT verdict (DOWN since
        // SPEC v4, DECISIONS §23 item 5), not an error.
        let mut accs = venue_accs(&cfg, &f);
        accs[2] = acc(PAM_KEY, SYSTEM_PROGRAM_ID, &[], false);
        assert_eq!(observe(&accs, env, false), Ok(()));
        let b = config_of(&mut accs[0]);
        let c = Config::new(&b).unwrap();
        assert_eq!((c.venue_last_verdict(), c.venue_last_reason()), (2, reason::PAM_OWNER));
        assert_eq!(c.venue_down_since_ts(), env.now);
    }

    /// Observe DOWN every 50 minutes from `T0` up to `until` (inclusive).
    fn observe_down_until(accs: &[TestAccount], until: i64) -> u64 {
        let (mut t, mut slot) = (T0, 1_000u64);
        loop {
            assert_eq!(observe(accs, Env { now: t, slot }, false), Ok(()));
            if t >= until {
                return slot;
            }
            t = (t + 3_000).min(until);
            slot += 7_500;
        }
    }

    #[test]
    fn latch_after_ten_days_of_down() {
        let mut f = Fixture::live();
        f.gc[504] = 0x85; // maintenance
        let mut accs = venue_accs(&cfg_bytes(false, true, true), &f);
        let slot = observe_down_until(&accs, T0 + RECOVERY_DOWN_SECS - 3_000);
        // One second short.
        let short = Env { now: T0 + RECOVERY_DOWN_SECS - 1, slot: slot + 1 };
        assert_eq!(observe(&accs, short, true), e(SijkaError::VenueDownTooShort));
        let at = Env { now: T0 + RECOVERY_DOWN_SECS, slot: slot + 2 };
        assert_eq!(observe(&accs, at, true), Ok(()));
        let b = config_of(&mut accs[0]);
        let c = Config::new(&b).unwrap();
        assert!(c.in_recovery());
        assert_eq!((c.recovery_latched_ts(), c.recovery_latched_slot()), (at.now, at.slot));
        assert_eq!((c.venue_last_verdict(), c.venue_last_reason()), (2, reason::EXCH_MAINTENANCE));
        assert_eq!(c.venue_down_since_ts(), T0);
        // Irreversible: op 0 again fails; Phoenix "coming back" changes nothing.
        let later = Env { now: at.now + 100, slot: at.slot + 100 };
        assert_eq!(observe(&accs, later, true), e(SijkaError::RecoveryAlreadyActive));
        let mut accs = venue_accs(&b, &Fixture::live());
        assert_eq!(observe(&accs, later, false), Ok(()));
        let b = config_of(&mut accs[0]);
        let c = Config::new(&b).unwrap();
        assert!(c.in_recovery());
        assert_eq!(c.venue_last_verdict(), 1);
    }

    #[test]
    fn latch_needs_live_down_and_continuity() {
        // GC deleted: DOWN(GC_ABSENT), and the latch needs no Phoenix CPI.
        let mut f = Fixture::live();
        f.gc_owner = SYSTEM_PROGRAM_ID;
        f.gc = vec![];
        let accs = venue_accs(&cfg_bytes(false, true, true), &f);
        let slot = observe_down_until(&accs, T0 + RECOVERY_DOWN_SECS);
        assert_eq!(observe(&accs, Env { now: T0 + RECOVERY_DOWN_SECS, slot: slot + 1 }, true), Ok(()));

        // Ten days of DOWN, but UP right now: VenueNotDown (and the countdown resets).
        let mut f = Fixture::live();
        f.gc[504] = 0x80;
        let mut accs = venue_accs(&cfg_bytes(false, true, true), &f);
        let slot = observe_down_until(&accs, T0 + RECOVERY_DOWN_SECS);
        accs[1] = acc(PHOENIX_GLOBAL_CONFIG, PHOENIX_PROGRAM_ID, &Fixture::live().gc, false);
        let now = Env { now: T0 + RECOVERY_DOWN_SECS + 10, slot: slot + 1 };
        assert_eq!(observe(&accs, now, true), e(SijkaError::VenueNotDown));

        // A 61-minute gap restarts the series.
        let mut f = Fixture::live();
        f.gc[504] = 0x80;
        let accs = venue_accs(&cfg_bytes(false, true, true), &f);
        assert_eq!(observe(&accs, Env { now: T0, slot: 1 }, false), Ok(()));
        assert_eq!(observe(&accs, Env { now: T0 + 3_660, slot: 2 }, false), Ok(()));
        let slot = 3;
        let mut t = T0 + 3_660;
        let mut s = slot;
        while t < T0 + RECOVERY_DOWN_SECS {
            t += 3_000;
            s += 1;
            assert_eq!(observe(&accs, Env { now: t, slot: s }, false), Ok(()));
        }
        assert_eq!(observe(&accs, Env { now: t, slot: s + 1 }, true), e(SijkaError::VenueDownTooShort));
        // SPEC v4 (DECISIONS §23 item 5): an unrecognized format (status bits
        // 3–6 set, reason GC_STATUS_BITS) is DOWN and counts: it latches.
        let mut f = Fixture::live();
        f.gc[504] = 0x88;
        let mut accs = venue_accs(&cfg_bytes(false, true, true), &f);
        observe_down_until(&accs, T0 + RECOVERY_DOWN_SECS);
        let at = Env { now: T0 + RECOVERY_DOWN_SECS + 30, slot: 10_000_000 };
        assert_eq!(observe(&accs, at, true), Ok(()));
        let b = config_of(&mut accs[0]);
        let c = Config::new(&b).unwrap();
        assert!(c.in_recovery());
        assert_eq!((c.venue_last_verdict(), c.venue_last_reason()), (2, reason::GC_STATUS_BITS));
        // A transient UNKNOWN (restart anomaly: ack > lrs) never counts.
        let mut f = Fixture::live();
        f.gc[1096..1104].copy_from_slice(&(LIVE_ACK + 1).to_le_bytes());
        let accs = venue_accs(&cfg_bytes(false, true, true), &f);
        observe_down_until(&accs, T0 + RECOVERY_DOWN_SECS);
        let at = Env { now: T0 + RECOVERY_DOWN_SECS + 30, slot: 10_000_000 };
        assert_eq!(observe(&accs, at, true), e(SijkaError::VenueNotDown));
    }

    /// SPEC v4 (DECISIONS §23 item 5): FORMAT verdicts continue a DOWN series
    /// started by any other DOWN reason (and vice versa); a transient UNKNOWN
    /// in between resets it. The hourly gap rule applies to FORMAT too.
    #[test]
    fn format_down_joins_the_series_and_unknown_resets_it() {
        let mut maint = Fixture::live();
        maint.gc[504] = 0x85;
        let mut disc = Fixture::live();
        disc.gc[0] ^= 1; // GC_DISC: FORMAT
        let mut anomaly = Fixture::live();
        anomaly.gc[1096..1104].copy_from_slice(&(LIVE_ACK + 1).to_le_bytes());
        // One observation (tag 50) of fixture `f` on the stored Config bytes.
        fn step(cfg: &mut Vec<u8>, f: &Fixture, now: i64, slot: u64) -> ProgramResult {
            let mut a = venue_accs(cfg, f);
            let r = observe(&a, Env { now, slot }, false);
            *cfg = config_of(&mut a[0]);
            r
        }
        let mut cfg = cfg_bytes(false, true, true);
        assert_eq!(step(&mut cfg, &maint, T0, 1), Ok(()));
        assert_eq!(step(&mut cfg, &disc, T0 + 3_000, 2), Ok(()));
        assert_eq!(step(&mut cfg, &maint, T0 + 6_000, 3), Ok(()));
        assert_eq!(
            Config::new(&cfg).unwrap().venue_down_since_ts(),
            T0,
            "maintenance, format, maintenance: one series"
        );
        // A transient UNKNOWN resets.
        assert_eq!(step(&mut cfg, &anomaly, T0 + 9_000, 4), Ok(()));
        let v = Config::new(&cfg).unwrap();
        assert_eq!((v.venue_last_verdict(), v.venue_last_reason()), (3, reason::GC_RESTART_ANOMALY));
        assert_eq!(v.venue_down_since_ts(), 0);
        // FORMAT after a gap of more than an hour restarts the series.
        assert_eq!(step(&mut cfg, &disc, T0 + 12_000, 5), Ok(()));
        assert_eq!(step(&mut cfg, &disc, T0 + 12_000 + 3_601, 6), Ok(()));
        let c = cfg.clone();
        assert_eq!(Config::new(&c).unwrap().venue_down_since_ts(), T0 + 12_000 + 3_601);
    }

    // ---------------------------------------------------------- op 2, op 5

    fn send_accs(cfg: &[u8], source: TestAccount, dest: TestAccount) -> Vec<TestAccount> {
        vec![
            acc(CFG, PID, cfg, true),
            acc(PHX, SYSTEM_PROGRAM_ID, &[], false),
            source,
            program(SPL_TOKEN_PROGRAM_ID),
            dest,
        ]
    }

    fn send(accs: &[TestAccount], phusd: bool) -> ProgramResult {
        send_token_core(&PID, &infos(accs), E, phusd)
    }

    #[test]
    fn send_usdc_to_recipient() {
        let cfg = cfg_bytes(true, true, true);
        let src = || token(VUSDC, &USDC, &PHX, 1_234);
        let ok_dest = || token(ER_USDC, &USDC, &ADMIN, 0);
        // All checks pass; the host CPI moves nothing, so the post-transfer invariant trips.
        assert_eq!(send(&send_accs(&cfg, src(), ok_dest()), false), e(SijkaError::InvariantViolated));
        // A delegate on the recipient's own account is allowed.
        let mut d = token_data(&USDC, &ADMIN, 0);
        d[72] = 1;
        assert_eq!(
            send(&send_accs(&cfg, src(), acc(ER_USDC, SPL_TOKEN_PROGRAM_ID, &d, true)), false),
            e(SijkaError::InvariantViolated)
        );
        let bad = SijkaError::RecoveryRecipientInvalid;
        let mut frozen = token_data(&USDC, &ADMIN, 0);
        frozen[108] = 2;
        let long = [token_data(&USDC, &ADMIN, 0), vec![0]].concat();
        for (i, dest) in [
            token([0x33; 32], &USDC, &ADMIN, 0),
            acc(ER_USDC, SPL_TOKEN_PROGRAM_ID, &token_data(&USDC, &ADMIN, 0), false),
            acc(ER_USDC, SPL_TOKEN_PROGRAM_ID, &frozen, true),
            token(ER_USDC, &PHUSD, &ADMIN, 0),
            token(ER_USDC, &USDC, &[0x34; 32], 0),
            acc(ER_USDC, TOKEN_2022_PROGRAM_ID, &token_data(&USDC, &ADMIN, 0), true),
            acc(ER_USDC, SPL_TOKEN_PROGRAM_ID, &long, true),
            acc(ER_USDC, SYSTEM_PROGRAM_ID, &[], true), // closed ATA
            token(BBU, &USDC, &BBA, 0),                 // the buyback is never a destination
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(send(&send_accs(&cfg, src(), dest), false), e(bad), "dest {i}");
        }
        // Source checks.
        assert_eq!(
            send(&send_accs(&cfg, token(VUSDC, &USDC, &PHX, 0), ok_dest()), false),
            e(SijkaError::RecoveryNothing)
        );
        assert_eq!(send(&send_accs(&cfg, token(BBU, &USDC, &PHX, 5), ok_dest()), false), e(SijkaError::InvalidPda));
        assert_eq!(
            send(&send_accs(&cfg, token(VUSDC, &USDC, &ADMIN, 5), ok_dest()), false),
            e(SijkaError::InvalidTokenAccount)
        );
        assert_eq!(
            send(
                &send_accs(&cfg, acc(VUSDC, SPL_TOKEN_PROGRAM_ID, &token_data(&USDC, &PHX, 5), false), ok_dest()),
                false
            ),
            e(SijkaError::AccountNotWritable)
        );
        let mut accs = send_accs(&cfg, src(), ok_dest());
        accs[1] = acc([0x35; 32], SYSTEM_PROGRAM_ID, &[], false);
        assert_eq!(send(&accs, false), e(SijkaError::InvalidPda));
        let mut accs = send_accs(&cfg, src(), ok_dest());
        accs[3] = program(TOKEN_2022_PROGRAM_ID);
        assert_eq!(send(&accs, false), e(SijkaError::InvalidProgramId));
        // Before the latch: nothing.
        let cfg0 = cfg_bytes(false, true, true);
        assert_eq!(send(&send_accs(&cfg0, src(), ok_dest()), false), e(SijkaError::RecoveryNotActive));
        // The retired inflow pause byte (@1152) is ignored.
        let mut paused = cfg.clone();
        edit_cfg(&mut paused, |m| {
            m.bytes_mut()[1152] = 3;
        });
        assert_eq!(send(&send_accs(&paused, src(), ok_dest()), false), e(SijkaError::InvariantViolated));
    }

    #[test]
    fn send_phusd_as_is() {
        let cfg = cfg_bytes(true, true, true);
        let src = || token(VPHUSD, &PHUSD, &PHX, 7);
        assert_eq!(
            send(&send_accs(&cfg, src(), token(ER_PHUSD, &PHUSD, &ADMIN, 0)), true),
            e(SijkaError::InvariantViolated)
        );
        let bad = SijkaError::RecoveryRecipientInvalid;
        assert_eq!(send(&send_accs(&cfg, src(), token(ER_USDC, &USDC, &ADMIN, 0)), true), e(bad));
        assert_eq!(send(&send_accs(&cfg, src(), token(ER_PHUSD, &USDC, &ADMIN, 0)), true), e(bad));
        assert_eq!(send(&send_accs(&cfg, src(), token(ER_PHUSD, &PHUSD, &BBA, 0)), true), e(bad));
        // The USDC vault is not the PhUSD source.
        assert_eq!(
            send(&send_accs(&cfg, token(VUSDC, &USDC, &PHX, 7), token(ER_PHUSD, &PHUSD, &ADMIN, 0)), true),
            e(SijkaError::InvalidTokenAccount)
        );
        assert_eq!(
            send(&send_accs(&cfg, token(VPHUSD, &PHUSD, &PHX, 0), token(ER_PHUSD, &PHUSD, &ADMIN, 0)), true),
            e(SijkaError::RecoveryNothing)
        );
        // Full audit FA-3: any clean PhUSD account of phx_authority is a source
        // (a queue delivery into a non-ATA account); others' accounts are not.
        let er = || token(ER_PHUSD, &PHUSD, &ADMIN, 0);
        assert_eq!(
            send(&send_accs(&cfg, token([0x4A; 32], &PHUSD, &PHX, 7), er()), true),
            e(SijkaError::InvariantViolated)
        );
        assert_eq!(
            send(&send_accs(&cfg, token([0x4A; 32], &PHUSD, &ADMIN, 7), er()), true),
            e(SijkaError::InvalidTokenAccount)
        );
        let mut delegated = token_data(&PHUSD, &PHX, 7);
        delegated[72] = 1;
        assert_eq!(
            send(&send_accs(&cfg, acc([0x4A; 32], SPL_TOKEN_PROGRAM_ID, &delegated, true), er()), true),
            e(SijkaError::InvalidTokenAccount)
        );
        // Op 2 stays pinned to vault_usdc.
        let ok_usdc = || token(ER_USDC, &USDC, &ADMIN, 0);
        assert_eq!(
            send(&send_accs(&cfg, token([0x4A; 32], &USDC, &PHX, 7), ok_usdc()), false),
            e(SijkaError::InvalidPda)
        );
    }

    // ---------------------------------------------------------------- op 3

    fn sol_accs(cfg: &[u8], fee_lamports: u64, dest: TestAccount) -> Vec<TestAccount> {
        vec![
            acc(CFG, PID, cfg, true),
            TestAccount::new(FEE, SYSTEM_PROGRAM_ID, fee_lamports, &[], false, true, false),
            dest,
            program(SYSTEM_PROGRAM_ID),
        ]
    }

    fn send_sol(accs: &[TestAccount]) -> ProgramResult {
        send_sol_core(&PID, &infos(accs), E, RENT0)
    }

    #[test]
    fn send_sol_routes() {
        let wallet = || acc(ADMIN, SYSTEM_PROGRAM_ID, &[], true);
        let budget = || acc(BBA, SYSTEM_PROGRAM_ID, &[], true);
        // RECIPIENT on both pairs (the only route since SPEC v4): checks pass
        // (host transfer is a no-op → invariant).
        for sol_pair in [true, false] {
            let cfg = cfg_bytes(true, true, sol_pair);
            assert_eq!(send_sol(&sol_accs(&cfg, RENT0 + 5, wallet())), e(SijkaError::InvariantViolated));
            assert_eq!(send_sol(&sol_accs(&cfg, RENT0, wallet())), e(SijkaError::RecoveryNothing));
            assert_eq!(send_sol(&sol_accs(&cfg, RENT0 - 1, wallet())), e(SijkaError::RecoveryNothing));
            let ro = acc(ADMIN, SYSTEM_PROGRAM_ID, &[], false);
            assert_eq!(send_sol(&sol_accs(&cfg, RENT0 + 5, ro)), e(SijkaError::RecoveryRecipientInvalid));
            assert_eq!(send_sol(&sol_accs(&cfg, RENT0 + 5, budget())), e(SijkaError::RecoveryRecipientInvalid));
        }
        // fee_inbox and system program checks.
        let cfg = cfg_bytes(true, true, true);
        let mut a = sol_accs(&cfg, RENT0 + 5, wallet());
        a[1] = TestAccount::new([0x36; 32], SYSTEM_PROGRAM_ID, RENT0 + 5, &[], false, true, false);
        assert_eq!(send_sol(&a), e(SijkaError::InvalidPda));
        a[1] = TestAccount::new(FEE, SYSTEM_PROGRAM_ID, RENT0 + 5, &[0], false, true, false);
        assert_eq!(send_sol(&a), e(SijkaError::InvalidExternalAccount));
        a[1] = TestAccount::new(FEE, SYSTEM_PROGRAM_ID, RENT0 + 5, &[], false, false, false);
        assert_eq!(send_sol(&a), e(SijkaError::AccountNotWritable));
        let mut a = sol_accs(&cfg, RENT0 + 5, wallet());
        a[3] = program([0x37; 32]);
        assert_eq!(send_sol(&a), e(SijkaError::InvalidProgramId));
        assert_eq!(
            send_sol(&sol_accs(&cfg_bytes(false, true, true), RENT0 + 5, wallet())),
            e(SijkaError::RecoveryNotActive)
        );
    }

    // ---------------------------------------------------------------- op 4

    fn ember_state_bytes(usdc: &Pubkey, phusd: &Pubkey) -> Vec<u8> {
        let mut d = vec![0u8; 136];
        d[0..8].copy_from_slice(&DISC_EMBER_STATE);
        d[40..72].copy_from_slice(usdc);
        d[72..104].copy_from_slice(phusd);
        d[104..136].copy_from_slice(&PHOENIX_PROGRAM_ID);
        d
    }

    fn unwrap_accs(cfg: &[u8], phusd_amount: u64) -> Vec<TestAccount> {
        vec![
            acc(CFG, PID, cfg, true),
            acc(PHX, SYSTEM_PROGRAM_ID, &[], false),
            token(VPHUSD, &PHUSD, &PHX, phusd_amount),
            token(VUSDC, &USDC, &PHX, 7),
            acc(USDC, SPL_TOKEN_PROGRAM_ID, &[0; 82], false),
            acc(PHUSD, SPL_TOKEN_PROGRAM_ID, &[0; 82], true),
            program(EMBER_PROGRAM_ID),
            acc(EMBER_STATE, EMBER_PROGRAM_ID, &ember_state_bytes(&USDC, &PHUSD), false),
            token(EMBER_VAULT, &USDC, &[0x38; 32], 1_000_000),
            program(SPL_TOKEN_PROGRAM_ID),
        ]
    }

    fn unwrap(accs: &[TestAccount]) -> ProgramResult {
        unwrap_core(&PID, &infos(accs), E)
    }

    #[test]
    fn unwrap_checks() {
        // The host CPI unwraps nothing → invariant.
        let cfg = cfg_bytes(true, true, true);
        assert_eq!(unwrap(&unwrap_accs(&cfg, 1_005)), e(SijkaError::InvariantViolated));
        assert_eq!(unwrap(&unwrap_accs(&cfg, 0)), e(SijkaError::RecoveryNothing));
        assert_eq!(unwrap(&unwrap_accs(&cfg_bytes(false, true, true), 5)), e(SijkaError::RecoveryNotActive));
        type Mutation = fn(&mut Vec<TestAccount>);
        let cases: [(Mutation, SijkaError); 9] = [
            (|a| a[2] = token(VPHUSD, &USDC, &PHX, 5), SijkaError::InvalidTokenAccount),
            (|a| a[3] = token(VUSDC, &USDC, &ADMIN, 5), SijkaError::InvalidTokenAccount),
            (|a| a[4] = acc(USDC, SYSTEM_PROGRAM_ID, &[], false), SijkaError::InvalidExternalAccount),
            (|a| a[5] = acc(PHUSD, SPL_TOKEN_PROGRAM_ID, &[0; 82], false), SijkaError::AccountNotWritable),
            (|a| a[5] = acc([0x39; 32], SPL_TOKEN_PROGRAM_ID, &[0; 82], true), SijkaError::InvalidExternalAccount),
            (|a| a[6] = acc(EMBER_PROGRAM_ID, SYSTEM_PROGRAM_ID, &[], false), SijkaError::InvalidProgramId),
            (
                |a| a[7] = acc(EMBER_STATE, EMBER_PROGRAM_ID, &ember_state_bytes(&USDC, &[0x3A; 32]), false),
                SijkaError::InvalidEmberAccount,
            ),
            (|a| a[8] = token([0x3B; 32], &USDC, &[0x38; 32], 1), SijkaError::InvalidEmberAccount),
            (|a| a[9] = program([0x3C; 32]), SijkaError::InvalidProgramId),
        ];
        for (i, (mutate, want)) in cases.iter().enumerate() {
            let mut a = unwrap_accs(&cfg, 5);
            mutate(&mut a);
            assert_eq!(unwrap(&a), e(*want), "case {i}");
        }
    }

    /// Full audit FA-3: op 4 unwraps PhUSD from any clean SPL Token PhUSD
    /// account of `phx_authority` (e.g. a non-ATA account a stranger created
    /// and had `consume_withdraw_queue` deliver into); nothing else.
    #[test]
    fn unwrap_source_is_any_phusd_account_of_phx_authority() {
        let cfg = cfg_bytes(true, true, true);
        let with_source = |src: TestAccount| {
            let mut a = unwrap_accs(&cfg, 5);
            a[2] = src;
            unwrap(&a)
        };
        // Non-canonical account of our PDA: all checks pass (the host CPI unwraps nothing).
        assert_eq!(with_source(token([0x49; 32], &PHUSD, &PHX, 5)), e(SijkaError::InvariantViolated));
        assert_eq!(with_source(token([0x49; 32], &PHUSD, &PHX, 0)), e(SijkaError::RecoveryNothing));
        let mut delegated = token_data(&PHUSD, &PHX, 5);
        delegated[72] = 1;
        let mut closable = token_data(&PHUSD, &PHX, 5);
        closable[129] = 1;
        let mut native = token_data(&PHUSD, &PHX, 5);
        native[109] = 1;
        let bad = SijkaError::InvalidTokenAccount;
        for (i, src) in [
            token([0x49; 32], &PHUSD, &ADMIN, 5), // someone else's PhUSD
            token([0x49; 32], &USDC, &PHX, 5),    // our USDC (vault_usdc's mint)
            token(ER_PHUSD, &PHUSD, &ADMIN, 5),   // the recipient's ATA
            acc([0x49; 32], SPL_TOKEN_PROGRAM_ID, &delegated, true),
            acc([0x49; 32], SPL_TOKEN_PROGRAM_ID, &closable, true),
            acc([0x49; 32], SPL_TOKEN_PROGRAM_ID, &native, true),
            acc([0x49; 32], TOKEN_2022_PROGRAM_ID, &token_data(&PHUSD, &PHX, 5), true),
            acc([0x49; 32], SYSTEM_PROGRAM_ID, &[], true),
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(with_source(src), e(bad), "source {i}");
        }
        let ro = acc([0x49; 32], SPL_TOKEN_PROGRAM_ID, &token_data(&PHUSD, &PHX, 5), false);
        assert_eq!(with_source(ro), e(SijkaError::AccountNotWritable));
    }

    // --------------------------------------------------------- op 1, op 6

    fn trader_data(c_hdr: i64, lds: u64, flags: u32, records: &[(u64, i64)]) -> Vec<u8> {
        let cap = records.len().max(4);
        let mut d = vec![0u8; 240 + 40 * cap];
        d[0..8].copy_from_slice(&DISC_TRADER);
        d[24..56].copy_from_slice(&TRADER);
        d[56..88].copy_from_slice(&PHX);
        d[88..96].copy_from_slice(&c_hdr.to_le_bytes());
        d[96..100].copy_from_slice(&flags.to_le_bytes());
        d[120..152].copy_from_slice(&PHX);
        d[192..200].copy_from_slice(&lds.to_le_bytes());
        d[224..232].copy_from_slice(&(records.len() as u64).to_le_bytes());
        d[232..240].copy_from_slice(&(cap as u64).to_le_bytes());
        for (j, (idx, base)) in records.iter().enumerate() {
            let o = 240 + 40 * j;
            d[o..o + 8].copy_from_slice(&idx.to_le_bytes());
            d[o + 8..o + 16].copy_from_slice(&base.to_le_bytes());
        }
        d
    }

    struct WFix {
        cfg: Vec<u8>,
        gc: Vec<u8>,
        trader: Vec<u8>,
        queue: Vec<u8>,
    }

    impl WFix {
        fn new() -> Self {
            Self {
                cfg: cfg_bytes(true, true, true),
                gc: Fixture::live().gc,
                trader: trader_data(5_000, 0, 63, &[]),
                queue: queue_bytes(&Q::default(), &[]),
            }
        }

        fn accounts(&self, hawkeye: bool) -> Vec<TestAccount> {
            let mut v = vec![
                acc(CFG, PID, &self.cfg, true),
                acc(PHX, SYSTEM_PROGRAM_ID, &[], false),
                program(PHOENIX_PROGRAM_ID),
            ];
            if hawkeye {
                v.push(program(HAWKEYE_PROGRAM_ID));
            }
            v.extend([
                acc(PHOENIX_LOG_AUTHORITY, SYSTEM_PROGRAM_ID, &[], false),
                acc(PHOENIX_GLOBAL_CONFIG, PHOENIX_PROGRAM_ID, &self.gc, true),
                acc(TRADER, PHOENIX_PROGRAM_ID, &self.trader, true),
                acc(PAM_KEY, PHOENIX_PROGRAM_ID, &live_pam(8, 3), true),
                acc(GVAULT, SPL_TOKEN_PROGRAM_ID, &token_data(&PHUSD, &[0x45; 32], 1 << 40), true),
                acc(WQ, PHOENIX_PROGRAM_ID, &self.queue, true),
                token(VPHUSD, &PHUSD, &PHX, 3),
                program(SPL_TOKEN_PROGRAM_ID),
                acc(GTI0, PHOENIX_PROGRAM_ID, &[0; 16], true),
                acc(ATB0, PHOENIX_PROGRAM_ID, &[0; 16], true),
            ]);
            v
        }
    }

    fn withdraw(accs: &[TestAccount], max_amount: u64, env: Env) -> ProgramResult {
        let a = infos(accs);
        let hawkeye = a.len() == 14;
        let o = usize::from(hawkeye);
        let ctx = WithdrawCtx {
            config: &a[0],
            phx_authority: &a[1],
            phoenix_program: &a[2],
            hawkeye_program: hawkeye.then(|| &a[3]),
            log_authority: &a[3 + o],
            global_config: &a[4 + o],
            trader_account: &a[5 + o],
            perp_asset_map: &a[6 + o],
            global_vault: &a[7 + o],
            withdraw_queue: &a[8 + o],
            vault_phusd: &a[9 + o],
            token_program: &a[10 + o],
            arenas: &a[11 + o..],
            gti_count: 1,
        };
        withdraw_core(&PID, &ctx, max_amount, env)
    }

    #[test]
    fn withdraw_flat_paths() {
        let w = WFix::new();
        // Immediate: all checks pass; nothing arrives on the host → WithdrawNotImmediate.
        assert_eq!(withdraw(&w.accounts(false), 0, E), e(SijkaError::WithdrawNotImmediate));
        // max_amount may go down to d_min (1 000), not below.
        assert_eq!(withdraw(&w.accounts(false), 1_000, E), e(SijkaError::WithdrawNotImmediate));
        assert_eq!(withdraw(&w.accounts(false), 999, E), e(SijkaError::RecoveryBelowMinimum));
        // Nothing on the header.
        for c_hdr in [0i64, -5] {
            let mut w = WFix::new();
            w.trader = trader_data(c_hdr, 0, 63, &[]);
            assert_eq!(withdraw(&w.accounts(false), 0, E), e(SijkaError::RecoveryNothing));
        }
        // Phoenix deposit cooldown.
        let mut w = WFix::new();
        w.gc[512..520].copy_from_slice(&100u64.to_le_bytes());
        w.trader = trader_data(5_000, E.slot - 99, 63, &[]);
        assert_eq!(withdraw(&w.accounts(false), 0, E), e(SijkaError::WithdrawCooldown));
        w.trader = trader_data(5_000, E.slot - 100, 63, &[]);
        assert_eq!(withdraw(&w.accounts(false), 0, E), e(SijkaError::WithdrawNotImmediate));
        // Mode and registration.
        let mut w = WFix::new();
        w.cfg = cfg_bytes(false, true, true);
        assert_eq!(withdraw(&w.accounts(false), 0, E), e(SijkaError::RecoveryNotActive));
        let mut w = WFix::new();
        edit_cfg(&mut w.cfg, |m| m.set_phoenix_trader(&[0; 32]));
        assert_eq!(withdraw(&w.accounts(false), 0, E), e(SijkaError::TraderNotRegistered));
    }

    #[test]
    fn withdraw_queue_mode() {
        let other = [0x71; 32];
        let busy = Q { total_queued: 5, ..Q::default() };
        // Busy queue: a request joins it; the host CPI enqueues nothing → WithdrawNotImmediate.
        let mut w = WFix::new();
        w.queue = queue_bytes(&busy, &[(other, 1)]);
        assert_eq!(withdraw(&w.accounts(false), 0, E), e(SijkaError::WithdrawNotImmediate));
        // Our request is already queued (any active state): do not replace it.
        w.queue = queue_bytes(&busy, &[(other, 1), (TRADER, 3)]);
        assert_eq!(withdraw(&w.accounts(false), 0, E), e(SijkaError::RecoveryAlreadyQueued));
        // Not more often than RECOVERY_ENQUEUE_MIN_SLOTS.
        let mut w = WFix::new();
        w.queue = queue_bytes(&busy, &[(other, 1)]);
        edit_cfg(&mut w.cfg, |m| m.set_recovery_last_enqueue_slot(E.slot - 10));
        assert_eq!(withdraw(&w.accounts(false), 0, E), e(SijkaError::RecoveryEnqueueTooSoon));
        // Broken list, or only the header: busy without a parseable queue.
        let mut w = WFix::new();
        let mut q = queue_bytes(&busy, &[(other, 1)]);
        q[128..136].copy_from_slice(&2u64.to_le_bytes());
        w.queue = q;
        assert_eq!(withdraw(&w.accounts(false), 0, E), e(SijkaError::WithdrawQueueBusy));
        let mut w = WFix::new();
        w.queue = queue_bytes(&busy, &[])[..200].to_vec();
        assert_eq!(withdraw(&w.accounts(false), 0, E), e(SijkaError::WithdrawQueueBusy));
        // Unparsed header (foreign discriminator): clamp, immediate.
        let mut w = WFix::new();
        w.queue[0] ^= 1;
        assert_eq!(withdraw(&w.accounts(false), 0, E), e(SijkaError::WithdrawNotImmediate));
    }

    #[test]
    fn withdraw_account_checks() {
        type Mutation = fn(&mut Vec<TestAccount>);
        let cases: [(Mutation, SijkaError); 12] = [
            (|a| a[1] = acc([0x3D; 32], SYSTEM_PROGRAM_ID, &[], false), SijkaError::InvalidPda),
            (|a| a[2] = acc(PHOENIX_PROGRAM_ID, SYSTEM_PROGRAM_ID, &[], false), SijkaError::InvalidProgramId),
            (|a| a[3] = acc([0x3E; 32], SYSTEM_PROGRAM_ID, &[], false), SijkaError::InvalidExternalAccount),
            // GlobalConfig closed after the latch (TR-21).
            (
                |a| a[4] = acc(PHOENIX_GLOBAL_CONFIG, SYSTEM_PROGRAM_ID, &[], true),
                SijkaError::InvalidPhoenixGlobalConfig,
            ),
            (
                |a| a[5] = acc(TRADER, PHOENIX_PROGRAM_ID, &trader_data(5_000, 0, 63, &[])[..239], true),
                SijkaError::InvalidPhoenixTraderAccount,
            ),
            (|a| a[6] = acc([0x3F; 32], PHOENIX_PROGRAM_ID, &[], true), SijkaError::InvalidPerpAssetMap),
            (|a| a[7] = acc([0x40; 32], SPL_TOKEN_PROGRAM_ID, &[], true), SijkaError::InvalidPhoenixGlobalConfig),
            (|a| a[8] = acc([0x46; 32], PHOENIX_PROGRAM_ID, &[], true), SijkaError::InvalidPhoenixGlobalConfig),
            (|a| a[8] = acc(WQ, PHOENIX_PROGRAM_ID, &[], false), SijkaError::AccountNotWritable),
            (|a| a[9] = token([0x47; 32], &PHUSD, &PHX, 3), SijkaError::InvalidPda),
            (|a| a[9] = token(VPHUSD, &PHUSD, &ADMIN, 3), SijkaError::InvalidTokenAccount),
            (|a| a[11] = acc([0x48; 32], PHOENIX_PROGRAM_ID, &[], true), SijkaError::InvalidArenaAccounts),
        ];
        let w = WFix::new();
        for (i, (mutate, want)) in cases.iter().enumerate() {
            let mut a = w.accounts(false);
            mutate(&mut a);
            assert_eq!(withdraw(&a, 0, E), e(*want), "case {i}");
        }
        // PhUSD in Config must still be GC@296.
        let mut w = WFix::new();
        w.gc[296] ^= 1;
        assert_eq!(withdraw(&w.accounts(false), 0, E), e(SijkaError::InvalidPhoenixGlobalConfig));
    }

    #[test]
    fn withdraw_with_hawkeye() {
        // All checks pass up to the Hawkeye view; the host has no return data.
        let w = WFix::new();
        assert_eq!(withdraw(&w.accounts(true), 0, E), e(SijkaError::HawkeyeReturnInvalid));
        // Op 1 checks only what it reads of the trader (REC-9): another disc passes.
        let mut w = WFix::new();
        w.trader[0] ^= 1;
        assert_eq!(withdraw(&w.accounts(true), 0, E), e(SijkaError::HawkeyeReturnInvalid));
        // …which op 6 rejects (full checks).
        assert_eq!(withdraw(&w.accounts(false), 0, E), e(SijkaError::InvalidPhoenixTraderAccount));
        // Too short for `@192`, or a foreign authority.
        let mut w = WFix::new();
        w.trader.truncate(199);
        assert_eq!(withdraw(&w.accounts(true), 0, E), e(SijkaError::InvalidPhoenixTraderAccount));
        let mut w = WFix::new();
        w.trader[56] ^= 1;
        assert_eq!(withdraw(&w.accounts(true), 0, E), e(SijkaError::InvalidPhoenixTraderAccount));
        // Position authority other than phx_authority (SPEC v3 §5.0.5: the
        // program never appoints a delegate).
        let mut w = WFix::new();
        w.trader[120] ^= 1;
        assert_eq!(withdraw(&w.accounts(true), 0, E), e(SijkaError::InvalidPhoenixTraderAccount));
        // Hawkeye program slot.
        let w = WFix::new();
        let mut a = w.accounts(true);
        a[3] = program([0x49; 32]);
        assert_eq!(withdraw(&a, 0, E), e(SijkaError::InvalidProgramId));
        // Cooldown comes before the Hawkeye CPI.
        let mut w = WFix::new();
        w.gc[512..520].copy_from_slice(&100u64.to_le_bytes());
        w.trader = trader_data(5_000, E.slot, 63, &[]);
        assert_eq!(withdraw(&w.accounts(true), 0, E), e(SijkaError::WithdrawCooldown));
    }

    /// The whole tag 51 surface before the latch (TR-20).
    #[test]
    fn nothing_moves_before_the_latch() {
        let cfg = cfg_bytes(false, true, true);
        let w = WFix { cfg: cfg.clone(), ..WFix::new() };
        assert_eq!(withdraw(&w.accounts(true), 0, E), e(SijkaError::RecoveryNotActive));
        assert_eq!(withdraw(&w.accounts(false), 0, E), e(SijkaError::RecoveryNotActive));
        let src = token(VUSDC, &USDC, &PHX, 5);
        assert_eq!(
            send(&send_accs(&cfg, src, token(ER_USDC, &USDC, &ADMIN, 0)), false),
            e(SijkaError::RecoveryNotActive)
        );
        let src = token(VPHUSD, &PHUSD, &PHX, 5);
        assert_eq!(
            send(&send_accs(&cfg, src, token(ER_PHUSD, &PHUSD, &ADMIN, 0)), true),
            e(SijkaError::RecoveryNotActive)
        );
        assert_eq!(unwrap(&unwrap_accs(&cfg, 5)), e(SijkaError::RecoveryNotActive));
        assert_eq!(
            send_sol(&sol_accs(&cfg, RENT0 + 5, acc(ADMIN, SYSTEM_PROGRAM_ID, &[], true))),
            e(SijkaError::RecoveryNotActive)
        );
    }
}
