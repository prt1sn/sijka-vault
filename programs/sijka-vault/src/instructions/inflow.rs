// Copyright (c) 2026 prt1sn. All rights reserved.
//! Inflow instructions, tags 20–23 (SPEC §5.3): swap, deposit and sweeps.
//! SPEC v4 (DECISIONS §23): the inflow parameters are fixed at `initialize`
//! (tags 25, 26 retired, no pause); the swap (tag 20) is signed by the keeper
//! key `config.keeper` and bounded by the keeper's `min_out`, not by an oracle.
//!
//! Accounting rule (DECISIONS §2.2): everything that reaches `deposit_usdc`
//! is capital `I`; `I` is written only by tag 21 and grows by exactly the
//! PhUSD that reached Phoenix.
//!
//! Every handler starts with the SPEC §4 shape check (data length, then
//! account count), then validates every account, then runs its steps. `Config`
//! is never passed to a CPI; it is read before the CPIs and written only after
//! the last one (SPEC §5.0.6).

use pinocchio::ProgramResult;
use pinocchio::account_info::AccountInfo;
use pinocchio::instruction::Signer;
use pinocchio::program_error::ProgramError;
use pinocchio::pubkey::{Pubkey, pubkey_eq};

use crate::constants::{
    DEPOSIT_QUIET_HARVEST_SLOTS, DEPOSIT_QUIET_MIN_PERIOD_SLOTS, DISC_EMBER_STATE, EMBER_PROGRAM_ID, EMBER_STATE,
    EMBER_VAULT, GC_MIN_LEN_WITH_COOLDOWN, JUPITER_V6, PHOENIX_LOG_AUTHORITY, PHOENIX_PROGRAM_ID, SEED_FEE_INBOX,
    SEED_PHX_AUTHORITY, SEED_SWAP_AUTHORITY, SPL_TOKEN_PROGRAM_ID, SYSTEM_PROGRAM_ID, WSOL_MINT,
};
use crate::cpi::ember::{EmberAccounts, ember_deposit};
use crate::cpi::jupiter::{RoutePolicy, SwapAcc, invoke_route, validate_route};
use crate::cpi::phoenix_deposit::{DepositAccounts, deposit_funds};
use crate::cpi::{PdaSeeds, system, token};
use crate::error::SijkaError;
use crate::events::{EvDeposit, EvSwapIn, EvSweepFeeInbox, EvSweepSwapUsdc};
use crate::external::layout::{ember_state as esl, global_config as gcl, token_account as ta, trader as trl};
use crate::external::phoenix_accounts::{
    TraderCheck, check_arenas, check_arenas_disjoint, check_global_config, check_trader_account,
};
use crate::instructions::{
    DEPOSIT_USDC, SWAP_SOL_TO_USDC, SWEEP_FEE_INBOX_USDC, SWEEP_SWAP_USDC, check_keeper, check_shape,
};
use crate::state::config::{config_view, config_view_mut, load_config, load_config_mut};
use crate::util::accounts::{
    check_token, expect_key, expect_owner, expect_program, expect_readonly, expect_system_empty, expect_writable,
};
use crate::util::bytes::{array_ref, read_i64, read_key, read_u64};
use crate::util::math::{add_u64, div_ceil_u128, mul_u128, rent_exempt_minimum, sub_u64, u64_to_i64};
use crate::util::runtime::{clock, require_top_level};

#[inline(always)]
fn bad_data() -> ProgramError {
    SijkaError::InvalidInstructionData.fail()
}

// =================================================================== 20 ====

/// Tag 20 data offsets (SPEC §5.3.4): `tag`, `amount_in u64`,
/// `min_out u64`, `jup_len u16`, then `jup_len` bytes of Jupiter data.
const SWAP_AMOUNT_IN: usize = 1;
const SWAP_MIN_OUT: usize = 9;
const SWAP_JUP_DATA: usize = 19;

/// Tag 20 `swap_sol_to_usdc` (SPEC §5.3.4), keeper only (SPEC v4).
///
/// The `fee_inbox` surplus (above `rent(0)`) plus any wSOL already on
/// `swap_wsol` is swapped to USDC through a keeper-built Jupiter route signed
/// by `swap_authority` only; the program checks the keeper signature, the
/// route, the input spent, the output against the keeper's `min_out` and the
/// integrity of every swap account after the CPI, then moves exactly the
/// output to `vault_usdc`. There is no oracle (DECISIONS §23 item 4).
#[inline(never)]
pub fn swap_sol_to_usdc(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    check_shape(&SWAP_SOL_TO_USDC, accounts, data)?;
    let [
        config,
        fee_inbox,
        swap_authority,
        swap_wsol,
        swap_usdc,
        vault_usdc,
        keeper,
        token_program,
        system_program,
        jupiter_program,
        route @ ..,
    ] = accounts
    else {
        return Err(SijkaError::InvalidAccountCount.fail());
    };
    let amount_in = read_u64(data, SWAP_AMOUNT_IN).ok_or_else(bad_data)?;
    let min_out = read_u64(data, SWAP_MIN_OUT).ok_or_else(bad_data)?;
    let jup_data = data.get(SWAP_JUP_DATA..).ok_or_else(bad_data)?;

    // Config is read-only until the last CPI (it is never an account of any
    // CPI here: the route may not contain it, protected key).
    let cfg_data = load_config(config, program_id)?;
    expect_writable(config)?;
    let cfg = config_view(&cfg_data)?;
    // ---- step 0: only the keeper key signs a swap (SPEC v4, account #6).
    check_keeper(keeper, &cfg)?;
    let sa_key = cfg.swap_authority();
    let usdc_mint = cfg.usdc_mint();

    // ---- accounts (SPEC §5.3.4 table)
    expect_key(fee_inbox, cfg.fee_inbox(), SijkaError::InvalidPda)?;
    expect_writable(fee_inbox)?;
    expect_system_empty(fee_inbox, SijkaError::InvalidExternalAccount)?;
    expect_key(swap_authority, sa_key, SijkaError::InvalidPda)?;
    expect_readonly(swap_authority)?;
    expect_system_empty(swap_authority, SijkaError::InvalidExternalAccount)?;
    expect_key(swap_wsol, cfg.swap_wsol(), SijkaError::InvalidPda)?;
    expect_writable(swap_wsol)?;
    check_token(swap_wsol, &SPL_TOKEN_PROGRAM_ID, &WSOL_MINT, sa_key, true, SijkaError::InvalidTokenAccount)?;
    expect_key(swap_usdc, cfg.swap_usdc(), SijkaError::InvalidPda)?;
    expect_writable(swap_usdc)?;
    check_token(swap_usdc, &SPL_TOKEN_PROGRAM_ID, usdc_mint, sa_key, false, SijkaError::InvalidTokenAccount)?;
    expect_key(vault_usdc, cfg.vault_usdc(), SijkaError::InvalidPda)?;
    expect_writable(vault_usdc)?;
    check_token(
        vault_usdc,
        &SPL_TOKEN_PROGRAM_ID,
        usdc_mint,
        cfg.phx_authority(),
        false,
        SijkaError::InvalidTokenAccount,
    )?;
    expect_key(token_program, &SPL_TOKEN_PROGRAM_ID, SijkaError::InvalidProgramId)?;
    expect_key(system_program, &SYSTEM_PROGRAM_ID, SijkaError::InvalidProgramId)?;
    expect_program(jupiter_program, &JUPITER_V6)?;

    // ---- step 1: top level, volume-proportional cooldown (RT-6)
    require_top_level()?;
    let clk = clock()?;
    let now = clk.unix_timestamp;
    let ip = cfg.inflow();
    if ip.swap_min_interval_s() > 0 && now < cfg.next_swap_ts() {
        return Err(SijkaError::SwapTooSoon.fail());
    }

    // ---- step 2: amount bounds
    if amount_in < ip.swap_min_lamports() || amount_in > ip.swap_max_lamports() {
        return Err(SijkaError::SwapAmountInvalid.fail());
    }

    // ---- step 3: the keeper's `min_out` (no oracle, SPEC v4). Zero would
    // accept any output, so it is refused.
    if min_out == 0 {
        return Err(SijkaError::SwapAmountInvalid.fail());
    }
    let recovery = cfg.in_recovery();

    // ---- step 4: route validation (once; `invoke_route` takes the token)
    let protected: [&Pubkey; 14] = [
        config.key(),
        cfg.buyback_state(),
        cfg.fee_inbox(),
        cfg.phx_authority(),
        cfg.rent_payer(),
        cfg.buyback_authority(),
        cfg.phoenix_trader(),
        cfg.vault_usdc(),
        cfg.vault_phusd(),
        cfg.buyback_usdc(),
        cfg.buyback_token(),
        cfg.bb_unwrap(),
        cfg.creator_escrow(),
        cfg.creator_escrow_usdc(),
    ];
    let allowed = [
        SwapAcc { info: swap_wsol, mint: &WSOL_MINT, native: true },
        SwapAcc { info: swap_usdc, mint: usdc_mint, native: false },
    ];
    let policy = RoutePolicy {
        swap_authority,
        swap_bump: cfg.swap_authority_bump(),
        expect_in_amount: amount_in,
        src: swap_wsol.key(),
        dst: swap_usdc.key(),
        src_mint: &WSOL_MINT,
        dst_mint: usdc_mint,
        allowed_swap_accounts: &allowed,
        protected_keys: &protected,
    };
    let validated = validate_route(jupiter_program, route, jup_data, &policy)?;
    let kind = validated.kind();

    // ---- step 5: top up swap_wsol from the fee_inbox surplus, sync, snapshots
    let rent0 = rent_exempt_minimum(0)?;
    let native_reserve = {
        let d = swap_wsol.try_borrow_data()?;
        read_u64(&d, ta::NATIVE_RESERVE).ok_or_else(|| SijkaError::InvalidTokenAccount.fail())?
    };
    let shortfall = wsol_shortfall(swap_wsol.lamports(), native_reserve, amount_in);
    let mut topup = 0u64;
    if shortfall > 0 {
        // REC-11: in recovery mode the fee_inbox surplus goes to the recipient
        // lamport for lamport (op 3), never through a swap (SPEC v4: there is
        // no route BUYBACK any more).
        if recovery {
            return Err(SijkaError::RecoverySwapRestricted.fail());
        }
        let avail = fee_inbox.lamports().saturating_sub(rent0);
        if shortfall > avail {
            return Err(SijkaError::FeeInboxInsufficient.fail());
        }
        let pda = PdaSeeds::new(SEED_FEE_INBOX, cfg.fee_inbox_bump());
        let seeds = pda.seeds();
        system::transfer(fee_inbox, swap_wsol, shortfall, &[Signer::from(&seeds)])?;
        topup = shortfall;
    }
    token::sync_native(token_program, swap_wsol)?;
    let w0 = check_token(swap_wsol, &SPL_TOKEN_PROGRAM_ID, &WSOL_MINT, sa_key, true, SijkaError::InvariantViolated)?;
    if w0 < amount_in {
        return Err(SijkaError::InvariantViolated.fail());
    }
    let u0 = check_token(swap_usdc, &SPL_TOKEN_PROGRAM_ID, usdc_mint, sa_key, false, SijkaError::InvariantViolated)?;

    // ---- step 6: Jupiter CPI with post_route_check inside (RT-1)
    invoke_route(validated)?;

    // ---- step 7: balance deltas on input and output
    let w1 = check_token(swap_wsol, &SPL_TOKEN_PROGRAM_ID, &WSOL_MINT, sa_key, true, SijkaError::SwapAccountTampered)?;
    let u1 = check_token(swap_usdc, &SPL_TOKEN_PROGRAM_ID, usdc_mint, sa_key, false, SijkaError::SwapAccountTampered)?;
    let (spent, received) = swap_deltas(w0, w1, u0, u1, amount_in, min_out).map_err(SijkaError::fail)?;
    if topup > 0 && fee_inbox.lamports() < rent0 {
        return Err(SijkaError::InvariantViolated.fail());
    }

    // ---- step 8: exactly `received` to vault_usdc (donations stay for tag 23)
    {
        let pda = PdaSeeds::new(SEED_SWAP_AUTHORITY, cfg.swap_authority_bump());
        let seeds = pda.seeds();
        token::transfer(token_program, swap_usdc, vault_usdc, swap_authority, received, &[Signer::from(&seeds)])?;
    }
    let u2 = check_token(swap_usdc, &SPL_TOKEN_PROGRAM_ID, usdc_mint, sa_key, false, SijkaError::InvariantViolated)?;
    if u2 != u0 {
        return Err(SijkaError::InvariantViolated.fail());
    }
    let interval = ip.swap_min_interval_s();
    let max_lamports = ip.swap_max_lamports();
    drop(cfg_data);

    // ---- step 9: Config (I unchanged)
    let swap_count = {
        let mut cfg_data = load_config_mut(config, program_id)?;
        let mut m = config_view_mut(&mut cfg_data)?;
        let v = m.view();
        let cum_spent = add_u64(v.cum_swap_lamports_spent(), spent)?;
        let cum_received = add_u64(v.cum_swap_usdc_received(), received)?;
        let swap_count = add_u64(v.swap_count(), 1)?;
        let next = if interval > 0 { Some(next_swap_ts(now, interval, amount_in, max_lamports)?) } else { None };
        m.set_cum_swap_lamports_spent(cum_spent);
        m.set_cum_swap_usdc_received(cum_received);
        m.set_swap_count(swap_count);
        m.set_last_swap_ts(now);
        m.set_last_swap_slot(clk.slot);
        if let Some(t) = next {
            m.set_next_swap_ts(t);
        }
        swap_count
    };

    // ---- step 10: event
    EvSwapIn {
        ts: now,
        jup_kind: kind as u8,
        slot: clk.slot,
        amount_in,
        spent,
        received,
        min_out,
        topup,
        fee_inbox_after: fee_inbox.lamports(),
        wsol_left: w1,
        swap_count,
    }
    .emit()
}

/// SPEC §5.3.4 step 5: `pending = lamports − native_reserve` (saturating; it
/// includes unsynced lamports), `shortfall = amount_in − pending` (saturating).
pub fn wsol_shortfall(wsol_lamports: u64, native_reserve: u64, amount_in: u64) -> u64 {
    let pending = wsol_lamports.saturating_sub(native_reserve);
    amount_in.saturating_sub(pending)
}

/// SPEC §5.3.4 step 7: `w1 ≤ w0` and `u1 ≥ u0` (`SwapAccountTampered`),
/// `0 < spent` (`SwapNoop`), `spent ≤ amount_in` (`SwapInputExceeded`),
/// `received ≥ min_out` (`SwapOutputBelowMin`; the keeper's `min_out` is for
/// `amount_in`, not `spent`). Returns `(spent, received)`.
pub fn swap_deltas(w0: u64, w1: u64, u0: u64, u1: u64, amount_in: u64, min_out: u64) -> Result<(u64, u64), SijkaError> {
    let spent = w0.checked_sub(w1).ok_or(SijkaError::SwapAccountTampered)?;
    if spent == 0 {
        return Err(SijkaError::SwapNoop);
    }
    if spent > amount_in {
        return Err(SijkaError::SwapInputExceeded);
    }
    let received = u1.checked_sub(u0).ok_or(SijkaError::SwapAccountTampered)?;
    if received < min_out {
        return Err(SijkaError::SwapOutputBelowMin);
    }
    Ok((spent, received))
}

/// Review RT-6: `next_swap_ts = now + ⌈swap_min_interval_s·amount_in /
/// swap_max_lamports⌉` (a dust swap takes only its share of the interval).
pub fn next_swap_ts(now: i64, interval_s: u32, amount_in: u64, max_lamports: u64) -> Result<i64, ProgramError> {
    let wait = div_ceil_u128(mul_u128(u128::from(interval_s), u128::from(amount_in))?, u128::from(max_lamports))?;
    let wait = u64::try_from(wait).map_err(|_| SijkaError::MathOverflow.fail())?;
    now.checked_add(u64_to_i64(wait)?).ok_or_else(|| SijkaError::MathOverflow.fail())
}

// =================================================================== 21 ====

/// Tag 21 data offsets (SPEC §5.3.5): `tag`, `gti_count`, `atb_count`,
/// `max_amount u64`.
const DEP_MAX_AMOUNT: usize = 3;

/// Tag 21 `deposit_usdc` (SPEC §5.3.5), permissionless.
///
/// USDC on `vault_usdc` is wrapped by Ember into PhUSD (whatever Ember
/// delivers, SPEC v4), then PhUSD on `vault_phusd` goes to Phoenix
/// `deposit_funds` (all of it, or at most `max_amount`); `I += dep` exactly,
/// the PhUSD that actually reached Phoenix.
#[inline(never)]
pub fn deposit_usdc(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let info = check_shape(&DEPOSIT_USDC, accounts, data)?;
    let [
        config,
        phx_authority,
        vault_usdc,
        vault_phusd,
        usdc_mint,
        phusd_mint,
        ember_program,
        ember_state,
        ember_vault,
        phoenix_program,
        log_authority,
        global_config,
        trader_account,
        global_vault,
        token_program,
        arenas @ ..,
    ] = accounts
    else {
        return Err(SijkaError::InvalidAccountCount.fail());
    };
    let max_amount = read_u64(data, DEP_MAX_AMOUNT).ok_or_else(bad_data)?;
    // check_shape fixed `accounts.len() == 15 + g + a`.
    let (gti, atb) = arenas.split_at_checked(info.gti).ok_or_else(|| SijkaError::InvalidArenaAccounts.fail())?;
    if atb.len() != info.atb {
        return Err(SijkaError::InvalidAccountCount.fail());
    }

    let cfg_data = load_config(config, program_id)?;
    expect_writable(config)?;
    let cfg = config_view(&cfg_data)?;

    // ---- step 1: recovery mode (no pause since SPEC v4)
    if cfg.in_recovery() {
        return Err(SijkaError::RecoveryActive.fail());
    }

    // ---- accounts (SPEC §5.3.5 table, §5.0.5)
    let auth_key = cfg.phx_authority();
    let usdc_key = cfg.usdc_mint();
    let phusd_key = cfg.phusd_mint();
    expect_key(phx_authority, auth_key, SijkaError::InvalidPda)?;
    expect_key(vault_usdc, cfg.vault_usdc(), SijkaError::InvalidPda)?;
    expect_writable(vault_usdc)?;
    let usdc =
        check_token(vault_usdc, &SPL_TOKEN_PROGRAM_ID, usdc_key, auth_key, false, SijkaError::InvalidTokenAccount)?;
    expect_key(vault_phusd, cfg.vault_phusd(), SijkaError::InvalidPda)?;
    expect_writable(vault_phusd)?;
    let phusd0 =
        check_token(vault_phusd, &SPL_TOKEN_PROGRAM_ID, phusd_key, auth_key, false, SijkaError::InvalidTokenAccount)?;
    expect_key(usdc_mint, usdc_key, SijkaError::InvalidExternalAccount)?;
    expect_owner(usdc_mint, &SPL_TOKEN_PROGRAM_ID, SijkaError::InvalidExternalAccount)?;
    expect_program(ember_program, &EMBER_PROGRAM_ID)?;
    check_ember_state(ember_state, usdc_key, phusd_key)?;
    expect_key(ember_vault, &EMBER_VAULT, SijkaError::InvalidEmberAccount)?;
    expect_writable(ember_vault)?;
    expect_program(phoenix_program, &PHOENIX_PROGRAM_ID)?;
    expect_key(log_authority, &PHOENIX_LOG_AUTHORITY, SijkaError::InvalidExternalAccount)?;
    let gc = check_global_config(global_config, GC_MIN_LEN_WITH_COOLDOWN, true)?;
    let cd = {
        let d = global_config.try_borrow_data()?;
        read_u64(&d, gcl::DEPOSIT_COOLDOWN_SLOTS).ok_or_else(|| SijkaError::InvalidPhoenixGlobalConfig.fail())?
    };
    if !pubkey_eq(phusd_mint.key(), &gc.canonical_mint) || !pubkey_eq(phusd_mint.key(), phusd_key) {
        return Err(SijkaError::InvalidPhoenixGlobalConfig.fail());
    }
    expect_writable(phusd_mint)?;
    check_trader_account(trader_account, cfg.phoenix_trader(), auth_key, TraderCheck::Full, true)?;
    let collateral_before = trader_collateral(trader_account, SijkaError::InvalidPhoenixTraderAccount)?;
    expect_key(global_vault, &gc.global_vault, SijkaError::InvalidPhoenixGlobalConfig)?;
    expect_writable(global_vault)?;
    check_arenas(arenas, info.gti, &gc, true)?;
    check_arenas_disjoint(arenas, &[trader_account.key(), global_vault.key()])?;
    expect_key(token_program, &SPL_TOKEN_PROGRAM_ID, SijkaError::InvalidProgramId)?;

    // ---- step 3: quiet window while Phoenix has a deposit cooldown (ACC-6)
    let clk = clock()?;
    if deposit_quiet_window(clk.slot, cd)? {
        return Err(SijkaError::DepositQuietWindow.fail());
    }

    // ---- step 4: amounts (before any CPI)
    let ip = cfg.inflow();
    let (want, wrap) = plan_deposit(usdc, phusd0, max_amount, ip.deposit_min_atoms())?;

    let pda = PdaSeeds::new(SEED_PHX_AUTHORITY, cfg.phx_authority_bump());
    let seeds = pda.seeds();
    let signer = [Signer::from(&seeds)];

    // ---- step 5: Ember wrap (USDC → PhUSD) of what the PhUSD balance lacks
    let (phusd1, g) = if wrap > 0 {
        let ember = EmberAccounts {
            ember_program,
            trader: phx_authority,
            ember_state,
            usdc_mint,
            canonical_mint: phusd_mint,
            trader_usdc_account: vault_usdc,
            trader_phoenix_account: vault_phusd,
            ember_vault,
            token_program,
        };
        ember_deposit(&ember, wrap, &signer)?;
        let usdc_after =
            check_token(vault_usdc, &SPL_TOKEN_PROGRAM_ID, usdc_key, auth_key, false, SijkaError::InvariantViolated)?;
        let phusd1 =
            check_token(vault_phusd, &SPL_TOKEN_PROGRAM_ID, phusd_key, auth_key, false, SijkaError::InvariantViolated)?;
        let g = check_wrap(usdc, usdc_after, phusd0, phusd1, wrap).map_err(SijkaError::fail)?;
        (phusd1, g)
    } else {
        (phusd0, 0)
    };

    // ---- step 6: Phoenix deposit_funds
    let dep = phusd1.min(want);
    if dep == 0 {
        return Err(SijkaError::DepositNothing.fail());
    }
    let phx = DepositAccounts {
        phoenix_program,
        log_authority,
        global_config,
        trader: phx_authority,
        trader_token_account: vault_phusd,
        trader_account,
        global_vault,
        token_program,
        gti,
        atb,
    };
    deposit_funds(&phx, dep, &signer)?;

    // ---- step 7: settled exactly
    let phusd2 =
        check_token(vault_phusd, &SPL_TOKEN_PROGRAM_ID, phusd_key, auth_key, false, SijkaError::InvariantViolated)?;
    if Some(phusd2) != phusd1.checked_sub(dep) {
        return Err(SijkaError::DepositNotSettled.fail());
    }
    let collateral_after = trader_collateral(trader_account, SijkaError::InvariantViolated)?;
    drop(cfg_data);

    // ---- step 8: Config — I += dep (the only place)
    let fee = sub_u64(wrap, g)?;
    let direct = sub_u64(dep, dep.min(g))?;
    let (i_after, count) = {
        let mut cfg_data = load_config_mut(config, program_id)?;
        let mut m = config_view_mut(&mut cfg_data)?;
        let v = m.view();
        let i_after = add_u64(v.cum_inflow_usdc(), dep)?;
        let count = add_u64(v.inflow_count(), 1)?;
        let wrapped = add_u64(v.cum_ember_wrapped(), wrap)?;
        let fees = add_u64(v.cum_ember_wrap_fees(), fee)?;
        let direct_total = add_u64(v.cum_phusd_direct(), direct)?;
        m.set_cum_inflow_usdc(i_after);
        m.set_inflow_count(count);
        m.set_cum_ember_wrapped(wrapped);
        m.set_cum_ember_wrap_fees(fees);
        m.set_cum_phusd_direct(direct_total);
        m.set_last_deposit_slot(clk.slot);
        m.set_last_deposit_amount(dep);
        (i_after, count)
    };

    // ---- step 9: event
    EvDeposit {
        ts: clk.unix_timestamp,
        slot: clk.slot,
        usdc_wrapped: wrap,
        phusd_direct: direct,
        deposited: dep,
        i_after,
        collateral_before,
        collateral_after,
        deposit_count: count,
        ember_fee: fee,
        max_amount,
    }
    .emit()
}

/// SPEC §5.0.5 `ember_state`: key, owner Ember, disc, `data_len ≥ 136`,
/// `@40 == usdc_mint`, `@72 == phusd_mint`, `@104 == PHOENIX_PROGRAM_ID`.
/// Error `InvalidEmberAccount`.
fn check_ember_state(ember_state: &AccountInfo, usdc_mint: &Pubkey, phusd_mint: &Pubkey) -> ProgramResult {
    let e = || SijkaError::InvalidEmberAccount.fail();
    if !pubkey_eq(ember_state.key(), &EMBER_STATE)
        || !ember_state.is_owned_by(&EMBER_PROGRAM_ID)
        || ember_state.data_len() < esl::MIN_LEN
    {
        return Err(e());
    }
    let d = ember_state.try_borrow_data()?;
    if ember_state_fields_ok(&d, usdc_mint, phusd_mint) { Ok(()) } else { Err(e()) }
}

/// Pure part of [`check_ember_state`] (discriminator and the three keys).
fn ember_state_fields_ok(d: &[u8], usdc_mint: &Pubkey, phusd_mint: &Pubkey) -> bool {
    array_ref::<8>(d, esl::DISCRIMINATOR) == Some(&DISC_EMBER_STATE)
        && read_key(d, esl::INPUT_MINT).is_some_and(|k| pubkey_eq(k, usdc_mint))
        && read_key(d, esl::OUTPUT_MINT).is_some_and(|k| pubkey_eq(k, phusd_mint))
        && read_key(d, esl::PHOENIX_PROGRAM).is_some_and(|k| pubkey_eq(k, &PHOENIX_PROGRAM_ID))
}

/// Trader `quote_lot_collateral` (`C_hdr`, `i64@88`), for the event only.
fn trader_collateral(trader: &AccountInfo, e: SijkaError) -> Result<i64, ProgramError> {
    let d = trader.try_borrow_data()?;
    read_i64(&d, trl::COLLATERAL).ok_or_else(|| e.fail())
}

/// Review ACC-6 quiet window: with `cd > 0`,
/// `P = max(DEPOSIT_QUIET_MIN_PERIOD_SLOTS, 2·(cd + DEPOSIT_QUIET_HARVEST_SLOTS))`
/// and deposits are refused while `slot % P < cd + DEPOSIT_QUIET_HARVEST_SLOTS`.
pub fn deposit_quiet_window(slot: u64, cd: u64) -> Result<bool, ProgramError> {
    if cd == 0 {
        return Ok(false);
    }
    let busy = add_u64(cd, DEPOSIT_QUIET_HARVEST_SLOTS)?;
    let period =
        busy.checked_mul(2).ok_or_else(|| SijkaError::MathOverflow.fail())?.max(DEPOSIT_QUIET_MIN_PERIOD_SLOTS);
    let phase = slot.checked_rem(period).ok_or_else(|| SijkaError::MathOverflow.fail())?;
    Ok(phase < busy)
}

/// SPEC §5.3.5 step 4–5: `total = usdc + phusd0`, `want = min(total, cap)`
/// (`cap = u64::MAX` for `max_amount == 0`), `want ≥ deposit_min_atoms`
/// (`DepositNothing`), `wrap = min(usdc, want − phusd0)` (saturating).
/// Returns `(want, wrap)`.
pub fn plan_deposit(usdc: u64, phusd0: u64, max_amount: u64, min_atoms: u64) -> Result<(u64, u64), ProgramError> {
    let total = add_u64(usdc, phusd0)?;
    let cap = if max_amount == 0 { u64::MAX } else { max_amount };
    let want = total.min(cap);
    if want < min_atoms || want == 0 {
        return Err(SijkaError::DepositNothing.fail());
    }
    let wrap = usdc.min(want.saturating_sub(phusd0));
    Ok((want, wrap))
}

/// SPEC §5.3.5 step 5: after Ember `deposit(wrap)`, `vault_usdc == usdc −
/// wrap` (exactly `wrap` of our USDC left), `phusd1 ≥ phusd0` and
/// `g = phusd1 − phusd0 ≤ wrap`; else `EmberWrapMismatch`. Any Ember holdback
/// `wrap − g` is accepted (SPEC v4, DECISIONS §23 item 6: the former
/// tolerance of review ACC-7 is retired; `I` only counts what reaches
/// Phoenix). Returns `g`.
pub fn check_wrap(usdc: u64, usdc_after: u64, phusd0: u64, phusd1: u64, wrap: u64) -> Result<u64, SijkaError> {
    const E: SijkaError = SijkaError::EmberWrapMismatch;
    if usdc.checked_sub(wrap) != Some(usdc_after) {
        return Err(E);
    }
    let g = phusd1.checked_sub(phusd0).ok_or(E)?;
    if g > wrap {
        return Err(E);
    }
    Ok(g)
}

// ============================================================== 22, 23 ====

/// Which authority a sweep uses.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Sweep {
    /// Tag 22: any USDC account of `fee_inbox`.
    FeeInbox,
    /// Tag 23: any USDC account of `swap_authority` (donations).
    SwapAuthority,
}

/// Tag 22 `sweep_fee_inbox_usdc` (SPEC §5.3.6), permissionless.
#[inline(never)]
pub fn sweep_fee_inbox_usdc(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    check_shape(&SWEEP_FEE_INBOX_USDC, accounts, data)?;
    sweep(program_id, accounts, Sweep::FeeInbox)
}

/// Tag 23 `sweep_swap_usdc` (SPEC §5.3.6), permissionless.
#[inline(never)]
pub fn sweep_swap_usdc(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    check_shape(&SWEEP_SWAP_USDC, accounts, data)?;
    sweep(program_id, accounts, Sweep::SwapAuthority)
}

/// Shared body of tags 22 and 23: the whole balance of `source` (a USDC
/// account whose authority is the PDA) goes to `vault_usdc`. No pause: it
/// only moves money inside the program (and works in recovery mode, §5.6.5).
fn sweep(program_id: &Pubkey, accounts: &[AccountInfo], kind: Sweep) -> ProgramResult {
    let [config, authority, source, vault_usdc, token_program] = accounts else {
        return Err(SijkaError::InvalidAccountCount.fail());
    };
    let cfg_data = load_config(config, program_id)?;
    expect_writable(config)?;
    let cfg = config_view(&cfg_data)?;
    let (auth_key, seed, bump) = match kind {
        Sweep::FeeInbox => (cfg.fee_inbox(), SEED_FEE_INBOX, cfg.fee_inbox_bump()),
        Sweep::SwapAuthority => (cfg.swap_authority(), SEED_SWAP_AUTHORITY, cfg.swap_authority_bump()),
    };
    let usdc_key = cfg.usdc_mint();

    expect_key(authority, auth_key, SijkaError::InvalidPda)?;
    match kind {
        Sweep::FeeInbox => expect_system_empty(authority, SijkaError::InvalidExternalAccount)?,
        Sweep::SwapAuthority => expect_readonly(authority)?,
    }
    expect_writable(source)?;
    let amt = check_token(source, &SPL_TOKEN_PROGRAM_ID, usdc_key, auth_key, false, SijkaError::InvalidTokenAccount)?;
    expect_key(vault_usdc, cfg.vault_usdc(), SijkaError::InvalidPda)?;
    expect_writable(vault_usdc)?;
    check_token(
        vault_usdc,
        &SPL_TOKEN_PROGRAM_ID,
        usdc_key,
        cfg.phx_authority(),
        false,
        SijkaError::InvalidTokenAccount,
    )?;
    if pubkey_eq(source.key(), vault_usdc.key()) {
        return Err(SijkaError::InvalidTokenAccount.fail());
    }
    expect_key(token_program, &SPL_TOKEN_PROGRAM_ID, SijkaError::InvalidProgramId)?;

    if amt == 0 {
        return Err(SijkaError::SweepNothing.fail());
    }
    let clk = clock()?;
    {
        let pda = PdaSeeds::new(seed, bump);
        let seeds = pda.seeds();
        token::transfer(token_program, source, vault_usdc, authority, amt, &[Signer::from(&seeds)])?;
    }
    let left = check_token(source, &SPL_TOKEN_PROGRAM_ID, usdc_key, auth_key, false, SijkaError::InvariantViolated)?;
    if left != 0 {
        return Err(SijkaError::InvariantViolated.fail());
    }
    drop(cfg_data);

    {
        let mut cfg_data = load_config_mut(config, program_id)?;
        let mut m = config_view_mut(&mut cfg_data)?;
        let v = m.view();
        match kind {
            Sweep::FeeInbox => {
                let t = add_u64(v.cum_fee_usdc_swept(), amt)?;
                m.set_cum_fee_usdc_swept(t);
            }
            Sweep::SwapAuthority => {
                let t = add_u64(v.cum_swap_usdc_swept(), amt)?;
                m.set_cum_swap_usdc_swept(t);
            }
        }
    }
    match kind {
        Sweep::FeeInbox => {
            EvSweepFeeInbox { ts: clk.unix_timestamp, slot: clk.slot, source: source.key(), amount: amt }.emit()
        }
        Sweep::SwapAuthority => {
            EvSweepSwapUsdc { ts: clk.unix_timestamp, slot: clk.slot, source: source.key(), amount: amt }.emit()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{DISC_CONFIG, PHOENIX_PROGRAM_ID};
    use crate::state::config::{CONFIG_LEN, ConfigMut};
    use crate::util::test_utils::TestAccount;

    const PROGRAM: Pubkey = [0x11; 32];
    const ADMIN: Pubkey = [0xAD; 32];
    const FEE_INBOX: Pubkey = [0xFE; 32];
    const SWAP_AUTH: Pubkey = [0x5A; 32];
    const PHX_AUTH: Pubkey = [0xA7; 32];
    const USDC: Pubkey = [0x0C; 32];
    const VAULT_USDC: Pubkey = [0xB1; 32];
    const SWAP_USDC: Pubkey = [0xB2; 32];
    const KEEPER: Pubkey = [0x4B; 32];

    fn config_bytes(edit: impl FnOnce(&mut ConfigMut)) -> Vec<u8> {
        let mut buf = vec![0u8; CONFIG_LEN];
        {
            let mut m = ConfigMut::new(&mut buf).unwrap();
            m.set_discriminator(&DISC_CONFIG);
            m.set_version(1);
            m.set_admin(&ADMIN);
            m.set_keeper(&KEEPER);
            m.set_fee_inbox(&FEE_INBOX);
            m.set_swap_authority(&SWAP_AUTH);
            m.set_phx_authority(&PHX_AUTH);
            m.set_usdc_mint(&USDC);
            m.set_vault_usdc(&VAULT_USDC);
            m.set_swap_usdc(&SWAP_USDC);
            edit(&mut m);
        }
        buf
    }

    fn config_acc(edit: impl FnOnce(&mut ConfigMut)) -> TestAccount {
        TestAccount::new([0xC0; 32], PROGRAM, 1, &config_bytes(edit), false, true, false)
    }

    fn token(mint: &Pubkey, owner: &Pubkey, amount: u64) -> Vec<u8> {
        let mut d = vec![0u8; 165];
        d[0..32].copy_from_slice(mint);
        d[32..64].copy_from_slice(owner);
        d[64..72].copy_from_slice(&amount.to_le_bytes());
        d[108] = 1;
        d
    }

    fn tok(key: Pubkey, mint: &Pubkey, owner: &Pubkey, amount: u64) -> TestAccount {
        TestAccount::new(key, SPL_TOKEN_PROGRAM_ID, 2_039_280, &token(mint, owner, amount), false, true, false)
    }

    // ---- pure helpers

    #[test]
    fn shortfall_rules() {
        // pending = 3_000_000 − 2_039_280 = 960_720.
        assert_eq!(wsol_shortfall(3_000_000, 2_039_280, 1_000_000_000), 999_039_280);
        assert_eq!(wsol_shortfall(3_000_000, 2_039_280, 960_720), 0);
        assert_eq!(wsol_shortfall(3_000_000, 2_039_280, 1), 0);
        // Reserve above lamports saturates (pending = 0).
        assert_eq!(wsol_shortfall(1, 2_039_280, 5), 5);
    }

    #[test]
    fn swap_delta_rules() {
        let ok = swap_deltas(1_000, 0, 5, 125, 1_000, 120);
        assert_eq!(ok, Ok((1_000, 120)));
        // Leftover input stays (spent < amount_in is fine).
        assert_eq!(swap_deltas(1_500, 600, 0, 200, 1_000, 120), Ok((900, 200)));
        // Input grew (w1 > w0) or output shrank (u1 < u0).
        assert_eq!(swap_deltas(1_000, 1_001, 0, 200, 1_000, 1), Err(SijkaError::SwapAccountTampered));
        assert_eq!(swap_deltas(1_000, 0, 10, 9, 1_000, 0), Err(SijkaError::SwapAccountTampered));
        // Nothing spent; overspend (TC-5); below floor by one (TC-3, TC-7).
        assert_eq!(swap_deltas(1_000, 1_000, 0, 200, 1_000, 1), Err(SijkaError::SwapNoop));
        assert_eq!(swap_deltas(2_000, 999, 0, 200, 1_000, 1), Err(SijkaError::SwapInputExceeded));
        assert_eq!(swap_deltas(1_000, 0, 5, 124, 1_000, 120), Err(SijkaError::SwapOutputBelowMin));
        assert_eq!(swap_deltas(1_000, 0, 5, 125, 1_000, 120), Ok((1_000, 120)));
    }

    #[test]
    fn min_out_is_for_amount_in_not_spent() {
        // SPEC v4: the keeper's `min_out` bounds the output of the whole
        // `amount_in`. Half the input spent for half the output fails.
        let min_out = 120_000_000u64;
        assert_eq!(
            swap_deltas(1_000_000_000, 500_000_000, 0, min_out / 2, 1_000_000_000, min_out),
            Err(SijkaError::SwapOutputBelowMin)
        );
        assert_eq!(
            swap_deltas(1_000_000_000, 500_000_000, 0, min_out, 1_000_000_000, min_out),
            Ok((500_000_000, min_out))
        );
    }

    #[test]
    fn next_swap_ts_proportional() {
        // TC-21: full swap waits the whole interval; dust waits ⌈60·min/max⌉.
        assert_eq!(next_swap_ts(1_000, 60, 10_000_000_000, 10_000_000_000), Ok(1_060));
        assert_eq!(next_swap_ts(1_000, 60, 50_000_000, 10_000_000_000), Ok(1_001));
        assert_eq!(next_swap_ts(1_000, 60, 1, 10_000_000_000), Ok(1_001));
        assert!(next_swap_ts(1_000, 60, 1, 0).is_err());
        assert!(next_swap_ts(i64::MAX, 60, 1, 1).is_err());
    }

    #[test]
    fn quiet_window_rules() {
        assert_eq!(deposit_quiet_window(12_345, 0), Ok(false));
        // cd = 1500 (TC-32): busy = 10 500, P = max(216 000, 21 000) = 216 000.
        assert_eq!(deposit_quiet_window(216_000 * 7, 1_500), Ok(true));
        assert_eq!(deposit_quiet_window(216_000 * 7 + 10_499, 1_500), Ok(true));
        assert_eq!(deposit_quiet_window(216_000 * 7 + 10_500, 1_500), Ok(false));
        assert_eq!(deposit_quiet_window(216_000 * 8 - 1, 1_500), Ok(false));
        // Large cd: P = 2·(cd + 9000).
        let cd = 200_000u64;
        let p = 2 * (cd + 9_000);
        assert_eq!(deposit_quiet_window(p + cd + 8_999, cd), Ok(true));
        assert_eq!(deposit_quiet_window(p + cd + 9_000, cd), Ok(false));
        assert!(deposit_quiet_window(1, u64::MAX).is_err());
    }

    #[test]
    fn plan_rules() {
        // TC-23: all USDC.
        assert_eq!(plan_deposit(100_000_000, 0, 0, 1_000_000), Ok((100_000_000, 100_000_000)));
        // TC-24: 5 PhUSD + 10 USDC; only PhUSD (no wrap).
        assert_eq!(plan_deposit(10_000_000, 5_000_000, 0, 1), Ok((15_000_000, 10_000_000)));
        assert_eq!(plan_deposit(0, 5_000_000, 0, 1), Ok((5_000_000, 0)));
        // TC-25: below minimum.
        assert_eq!(plan_deposit(400_000, 500_000, 0, 1_000_000), Err(SijkaError::DepositNothing.into()));
        // TC-33: max_amount below the balances (PhUSD first, then USDC).
        assert_eq!(plan_deposit(10, 3, 5, 1), Ok((5, 2)));
        assert_eq!(plan_deposit(10, 7, 5, 1), Ok((5, 0)));
        assert_eq!(plan_deposit(10, 3, 5, 6), Err(SijkaError::DepositNothing.into()));
        assert_eq!(plan_deposit(0, 0, 0, 0), Err(SijkaError::DepositNothing.into()));
        assert!(plan_deposit(u64::MAX, 1, 0, 1).is_err());
    }

    #[test]
    fn wrap_rules() {
        // 1:1.
        assert_eq!(check_wrap(100, 0, 5, 105, 100), Ok(100));
        // Wrong USDC debit (our own account: exact).
        assert_eq!(check_wrap(100, 1, 5, 105, 100), Err(SijkaError::EmberWrapMismatch));
        assert_eq!(check_wrap(100, 0, 5, 105, 99), Err(SijkaError::EmberWrapMismatch));
        // PhUSD fell, or more PhUSD than wrapped.
        assert_eq!(check_wrap(100, 0, 5, 4, 100), Err(SijkaError::EmberWrapMismatch));
        assert_eq!(check_wrap(100, 0, 5, 106, 100), Err(SijkaError::EmberWrapMismatch));
        // TC-33 (SPEC v4, DECISIONS §23 item 6): any Ember fee is accepted,
        // g is what counts (I grows by the PhUSD that reaches Phoenix).
        assert_eq!(check_wrap(1_000_000, 0, 0, 1_000_000 - 1_001, 1_000_000), Ok(998_999));
        assert_eq!(check_wrap(1_000, 0, 0, 1, 1_000), Ok(1));
        assert_eq!(check_wrap(1_000, 0, 0, 0, 1_000), Ok(0));
    }

    #[test]
    fn ember_state_rules() {
        let phusd = [0x0D; 32];
        let mut d = vec![0u8; 136];
        d[0..8].copy_from_slice(&DISC_EMBER_STATE);
        d[40..72].copy_from_slice(&USDC);
        d[72..104].copy_from_slice(&phusd);
        d[104..136].copy_from_slice(&PHOENIX_PROGRAM_ID);
        assert!(ember_state_fields_ok(&d, &USDC, &phusd));
        for off in [0usize, 40, 72, 104] {
            let mut bad = d.clone();
            bad[off] ^= 1;
            assert!(!ember_state_fields_ok(&bad, &USDC, &phusd), "byte {off}");
        }
        let ok = TestAccount::plain(EMBER_STATE, EMBER_PROGRAM_ID, &d);
        assert_eq!(check_ember_state(&ok.info(), &USDC, &phusd), Ok(()));
        let wrong_owner = TestAccount::plain(EMBER_STATE, [1; 32], &d);
        assert_eq!(check_ember_state(&wrong_owner.info(), &USDC, &phusd), Err(SijkaError::InvalidEmberAccount.into()));
        let wrong_key = TestAccount::plain([2; 32], EMBER_PROGRAM_ID, &d);
        assert_eq!(check_ember_state(&wrong_key.info(), &USDC, &phusd), Err(SijkaError::InvalidEmberAccount.into()));
        let short = TestAccount::plain(EMBER_STATE, EMBER_PROGRAM_ID, &d[..135]);
        assert_eq!(check_ember_state(&short.info(), &USDC, &phusd), Err(SijkaError::InvalidEmberAccount.into()));
    }

    // ---- handler checks that fail before the clock (host has no sysvars)

    fn sweep_accounts(
        authority: TestAccount,
        source: TestAccount,
        vault: TestAccount,
        token_program: Pubkey,
    ) -> (TestAccount, [TestAccount; 4]) {
        (config_acc(|_| {}), [authority, source, vault, TestAccount::plain(token_program, [0; 32], &[])])
    }

    fn run_sweep(tag: u8, parts: (TestAccount, [TestAccount; 4])) -> ProgramResult {
        let (cfg, rest) = parts;
        let mut infos = vec![cfg.info()];
        infos.extend(rest.iter().map(TestAccount::info));
        crate::process_instruction(&PROGRAM, &infos, &[tag])
    }

    fn fee_inbox_acc() -> TestAccount {
        TestAccount::new(FEE_INBOX, SYSTEM_PROGRAM_ID, 5_000_000, &[], false, false, false)
    }

    fn swap_auth_acc(writable: bool) -> TestAccount {
        TestAccount::new(SWAP_AUTH, SYSTEM_PROGRAM_ID, 0, &[], false, writable, false)
    }

    #[test]
    fn sweep_account_checks() {
        let vault = || tok(VAULT_USDC, &USDC, &PHX_AUTH, 0);
        let e = |x: SijkaError| Err(x.into());
        // Tag 22: wrong authority PDA; fee_inbox with data.
        let wrong = TestAccount::new([1; 32], SYSTEM_PROGRAM_ID, 1, &[], false, false, false);
        assert_eq!(
            run_sweep(22, sweep_accounts(wrong, tok([3; 32], &USDC, &FEE_INBOX, 7), vault(), SPL_TOKEN_PROGRAM_ID)),
            e(SijkaError::InvalidPda)
        );
        let with_data = TestAccount::new(FEE_INBOX, SYSTEM_PROGRAM_ID, 1, &[0], false, false, false);
        assert_eq!(
            run_sweep(22, sweep_accounts(with_data, tok([3; 32], &USDC, &FEE_INBOX, 7), vault(), SPL_TOKEN_PROGRAM_ID)),
            e(SijkaError::InvalidExternalAccount)
        );
        // Source: other authority, other mint, delegate set (TC-30).
        assert_eq!(
            run_sweep(
                22,
                sweep_accounts(fee_inbox_acc(), tok([3; 32], &USDC, &[9; 32], 7), vault(), SPL_TOKEN_PROGRAM_ID)
            ),
            e(SijkaError::InvalidTokenAccount)
        );
        assert_eq!(
            run_sweep(
                22,
                sweep_accounts(fee_inbox_acc(), tok([3; 32], &[8; 32], &FEE_INBOX, 7), vault(), SPL_TOKEN_PROGRAM_ID)
            ),
            e(SijkaError::InvalidTokenAccount)
        );
        let mut delegated = tok([3; 32], &USDC, &FEE_INBOX, 7);
        delegated.data_mut()[72] = 1;
        assert_eq!(
            run_sweep(22, sweep_accounts(fee_inbox_acc(), delegated, vault(), SPL_TOKEN_PROGRAM_ID)),
            e(SijkaError::InvalidTokenAccount)
        );
        // Read-only source.
        let ro = TestAccount::new([3; 32], SPL_TOKEN_PROGRAM_ID, 1, &token(&USDC, &FEE_INBOX, 7), false, false, false);
        assert_eq!(
            run_sweep(22, sweep_accounts(fee_inbox_acc(), ro, vault(), SPL_TOKEN_PROGRAM_ID)),
            e(SijkaError::AccountNotWritable)
        );
        // Wrong vault, wrong token program, empty source (TC-30).
        assert_eq!(
            run_sweep(
                22,
                sweep_accounts(
                    fee_inbox_acc(),
                    tok([3; 32], &USDC, &FEE_INBOX, 7),
                    tok([4; 32], &USDC, &PHX_AUTH, 0),
                    SPL_TOKEN_PROGRAM_ID
                )
            ),
            e(SijkaError::InvalidPda)
        );
        assert_eq!(
            run_sweep(22, sweep_accounts(fee_inbox_acc(), tok([3; 32], &USDC, &FEE_INBOX, 7), vault(), [5; 32])),
            e(SijkaError::InvalidProgramId)
        );
        assert_eq!(
            run_sweep(
                22,
                sweep_accounts(fee_inbox_acc(), tok([3; 32], &USDC, &FEE_INBOX, 0), vault(), SPL_TOKEN_PROGRAM_ID)
            ),
            e(SijkaError::SweepNothing)
        );
        // Tag 23: swap_authority must be read-only; a fee_inbox account is not its source.
        assert_eq!(
            run_sweep(
                23,
                sweep_accounts(
                    swap_auth_acc(true),
                    tok(SWAP_USDC, &USDC, &SWAP_AUTH, 7),
                    vault(),
                    SPL_TOKEN_PROGRAM_ID
                )
            ),
            e(SijkaError::AccountMustBeReadonly)
        );
        assert_eq!(
            run_sweep(
                23,
                sweep_accounts(swap_auth_acc(false), tok([3; 32], &USDC, &FEE_INBOX, 7), vault(), SPL_TOKEN_PROGRAM_ID)
            ),
            e(SijkaError::InvalidTokenAccount)
        );
        assert_eq!(
            run_sweep(
                23,
                sweep_accounts(
                    swap_auth_acc(false),
                    tok(SWAP_USDC, &USDC, &SWAP_AUTH, 0),
                    vault(),
                    SPL_TOKEN_PROGRAM_ID
                )
            ),
            e(SijkaError::SweepNothing)
        );
    }

    #[test]
    fn sweep_config_must_be_writable_and_ours() {
        let cfg_ro = TestAccount::new([0xC0; 32], PROGRAM, 1, &config_bytes(|_| {}), false, false, false);
        let rest = [
            fee_inbox_acc(),
            tok([3; 32], &USDC, &FEE_INBOX, 7),
            tok(VAULT_USDC, &USDC, &PHX_AUTH, 0),
            TestAccount::plain(SPL_TOKEN_PROGRAM_ID, [0; 32], &[]),
        ];
        assert_eq!(run_sweep(22, (cfg_ro, rest)), Err(SijkaError::AccountNotWritable.into()));
        let cfg_foreign = TestAccount::new([0xC0; 32], [0x22; 32], 1, &config_bytes(|_| {}), false, true, false);
        let rest = [
            fee_inbox_acc(),
            tok([3; 32], &USDC, &FEE_INBOX, 7),
            tok(VAULT_USDC, &USDC, &PHX_AUTH, 0),
            TestAccount::plain(SPL_TOKEN_PROGRAM_ID, [0; 32], &[]),
        ];
        assert_eq!(run_sweep(22, (cfg_foreign, rest)), Err(SijkaError::InvalidConfigAccount.into()));
    }

    fn good_params() -> [u8; 40] {
        let mut b = [0u8; 40];
        {
            let mut m = crate::state::config::inflow_params::InflowParamsMut::from_array(&mut b);
            m.set_swap_max_lamports(10_000_000_000);
            m.set_swap_min_lamports(50_000_000);
            m.set_deposit_min_atoms(1_000_000);
        }
        b
    }

    #[test]
    fn swap_account_checks_before_clock() {
        // Tag 20 with a writable swap_authority (TC-8) or a foreign fee_inbox.
        let mk = |fee_key: Pubkey, sa_writable: bool| -> ProgramResult {
            let cfg = config_acc(|m| m.set_swap_wsol(&[0x51; 32]));
            let fee = TestAccount::new(fee_key, SYSTEM_PROGRAM_ID, 5_000_000, &[], false, true, false);
            let sa = swap_auth_acc(sa_writable);
            // Slot 6 is the keeper signer (SPEC v4); the others are junk.
            let rest: Vec<TestAccount> = (0..8)
                .map(|i| if i == 3 { keeper_acc() } else { TestAccount::plain([0x60 + i as u8; 32], [0; 32], &[]) })
                .collect();
            let mut infos = vec![cfg.info(), fee.info(), sa.info()];
            infos.extend(rest.iter().map(TestAccount::info));
            let mut data = vec![20u8];
            data.extend_from_slice(&1_000_000_000u64.to_le_bytes());
            data.extend_from_slice(&1u64.to_le_bytes());
            data.extend_from_slice(&8u16.to_le_bytes());
            data.extend_from_slice(&[0u8; 8]);
            crate::process_instruction(&PROGRAM, &infos, &data)
        };
        assert_eq!(mk([1; 32], false), Err(SijkaError::InvalidPda.into()));
        assert_eq!(mk(FEE_INBOX, true), Err(SijkaError::AccountMustBeReadonly.into()));
    }

    // ---- tag 21 account set (TC-26): every check up to the Clock sysvar

    const VAULT_PHUSD: Pubkey = [0xB3; 32];
    const PHUSD: Pubkey = [0x0D; 32];
    const TRADER: Pubkey = [0x7A; 32];
    const GV: Pubkey = [0x6A; 32];
    const GTI0: Pubkey = [0x61; 32];
    const ATB0: Pubkey = [0x62; 32];

    fn ember_state_bytes() -> Vec<u8> {
        let mut d = vec![0u8; 136];
        d[0..8].copy_from_slice(&DISC_EMBER_STATE);
        d[40..72].copy_from_slice(&USDC);
        d[72..104].copy_from_slice(&PHUSD);
        d[104..136].copy_from_slice(&PHOENIX_PROGRAM_ID);
        d
    }

    fn gc_bytes(len: usize) -> Vec<u8> {
        let mut d = vec![0u8; len];
        d[0..8].copy_from_slice(&crate::constants::DISC_GLOBAL_CONFIG);
        d[296..328].copy_from_slice(&PHUSD);
        d[328..360].copy_from_slice(&GV);
        d[392..424].copy_from_slice(&GTI0);
        d[424..456].copy_from_slice(&ATB0);
        d
    }

    fn trader_bytes(authority: &Pubkey) -> Vec<u8> {
        let mut d = vec![0u8; 240 + 40 * 128];
        d[0..8].copy_from_slice(&crate::constants::DISC_TRADER);
        d[56..88].copy_from_slice(authority);
        d[88..96].copy_from_slice(&7i64.to_le_bytes());
        d[120..152].copy_from_slice(authority);
        d[232..240].copy_from_slice(&128u64.to_le_bytes());
        d
    }

    fn w(key: Pubkey, owner: Pubkey, data: &[u8]) -> TestAccount {
        TestAccount::new(key, owner, 1, data, false, true, false)
    }

    fn exe(key: Pubkey) -> TestAccount {
        TestAccount::new(key, [3; 32], 1, &[], false, false, true)
    }

    fn dep_accounts(edit: fn(&mut ConfigMut)) -> Vec<TestAccount> {
        let cfg = config_acc(|m| {
            m.set_vault_phusd(&VAULT_PHUSD);
            m.set_phusd_mint(&PHUSD);
            m.set_phoenix_trader(&TRADER);
            m.set_inflow_params(&good_params());
            edit(m);
        });
        vec![
            cfg,
            TestAccount::plain(PHX_AUTH, SYSTEM_PROGRAM_ID, &[]),
            tok(VAULT_USDC, &USDC, &PHX_AUTH, 100_000_000),
            tok(VAULT_PHUSD, &PHUSD, &PHX_AUTH, 5),
            TestAccount::plain(USDC, SPL_TOKEN_PROGRAM_ID, &[0u8; 82]),
            w(PHUSD, SPL_TOKEN_PROGRAM_ID, &[0u8; 82]),
            exe(EMBER_PROGRAM_ID),
            TestAccount::plain(EMBER_STATE, EMBER_PROGRAM_ID, &ember_state_bytes()),
            w(EMBER_VAULT, SPL_TOKEN_PROGRAM_ID, &[]),
            exe(PHOENIX_PROGRAM_ID),
            TestAccount::plain(PHOENIX_LOG_AUTHORITY, SYSTEM_PROGRAM_ID, &[]),
            w(crate::constants::PHOENIX_GLOBAL_CONFIG, PHOENIX_PROGRAM_ID, &gc_bytes(1104)),
            w(TRADER, PHOENIX_PROGRAM_ID, &trader_bytes(&PHX_AUTH)),
            w(GV, SPL_TOKEN_PROGRAM_ID, &[]),
            TestAccount::plain(SPL_TOKEN_PROGRAM_ID, [3; 32], &[]),
            w(GTI0, PHOENIX_PROGRAM_ID, &[]),
            w(ATB0, PHOENIX_PROGRAM_ID, &[]),
        ]
    }

    fn run_dep(accs: &[TestAccount], gti: u8) -> ProgramResult {
        let infos: Vec<AccountInfo> = accs.iter().map(TestAccount::info).collect();
        let mut data = vec![21u8, gti, 1];
        data.extend_from_slice(&0u64.to_le_bytes());
        crate::process_instruction(&PROGRAM, &infos, &data)
    }

    #[test]
    fn deposit_account_set() {
        // A valid set passes every account check; the host then stops at the
        // Clock sysvar (no syscalls off-chain).
        assert_eq!(run_dep(&dep_accounts(|_| {}), 1), Err(ProgramError::UnsupportedSysvar));
        let e = |x: SijkaError| Err(x.into());
        let cases: Vec<(usize, TestAccount, ProgramResult)> = vec![
            (1, TestAccount::plain([1; 32], SYSTEM_PROGRAM_ID, &[]), e(SijkaError::InvalidPda)),
            (2, tok(VAULT_USDC, &USDC, &[9; 32], 1), e(SijkaError::InvalidTokenAccount)),
            (
                2,
                TestAccount::plain(VAULT_USDC, SPL_TOKEN_PROGRAM_ID, &token(&USDC, &PHX_AUTH, 1)),
                e(SijkaError::AccountNotWritable),
            ),
            (3, tok(VAULT_PHUSD, &USDC, &PHX_AUTH, 1), e(SijkaError::InvalidTokenAccount)),
            (4, TestAccount::plain(USDC, [9; 32], &[0u8; 82]), e(SijkaError::InvalidExternalAccount)),
            (5, w([9; 32], SPL_TOKEN_PROGRAM_ID, &[]), e(SijkaError::InvalidPhoenixGlobalConfig)),
            (5, TestAccount::plain(PHUSD, SPL_TOKEN_PROGRAM_ID, &[]), e(SijkaError::AccountNotWritable)),
            (6, TestAccount::plain(EMBER_PROGRAM_ID, [3; 32], &[]), e(SijkaError::InvalidProgramId)),
            (
                7,
                TestAccount::plain(EMBER_STATE, EMBER_PROGRAM_ID, &ember_state_bytes()[..135]),
                e(SijkaError::InvalidEmberAccount),
            ),
            (7, TestAccount::plain(EMBER_STATE, [9; 32], &ember_state_bytes()), e(SijkaError::InvalidEmberAccount)),
            (8, w([9; 32], SPL_TOKEN_PROGRAM_ID, &[]), e(SijkaError::InvalidEmberAccount)),
            (9, exe([9; 32]), e(SijkaError::InvalidProgramId)),
            (10, TestAccount::plain([9; 32], SYSTEM_PROGRAM_ID, &[]), e(SijkaError::InvalidExternalAccount)),
            // TC-32: a GlobalConfig shorter than 520 bytes.
            (
                11,
                w(crate::constants::PHOENIX_GLOBAL_CONFIG, PHOENIX_PROGRAM_ID, &gc_bytes(519)),
                e(SijkaError::InvalidPhoenixGlobalConfig),
            ),
            (11, w([9; 32], PHOENIX_PROGRAM_ID, &gc_bytes(1104)), e(SijkaError::InvalidPhoenixGlobalConfig)),
            (12, w(TRADER, PHOENIX_PROGRAM_ID, &trader_bytes(&[9; 32])), e(SijkaError::InvalidPhoenixTraderAccount)),
            (12, w([9; 32], PHOENIX_PROGRAM_ID, &trader_bytes(&PHX_AUTH)), e(SijkaError::InvalidPhoenixTraderAccount)),
            (13, w([9; 32], SPL_TOKEN_PROGRAM_ID, &[]), e(SijkaError::InvalidPhoenixGlobalConfig)),
            (13, TestAccount::plain(GV, SPL_TOKEN_PROGRAM_ID, &[]), e(SijkaError::AccountNotWritable)),
            (14, TestAccount::plain([9; 32], [3; 32], &[]), e(SijkaError::InvalidProgramId)),
            (15, w([9; 32], PHOENIX_PROGRAM_ID, &[]), e(SijkaError::InvalidArenaAccounts)),
            (16, TestAccount::plain(ATB0, PHOENIX_PROGRAM_ID, &[]), e(SijkaError::InvalidArenaAccounts)),
        ];
        for (i, acc, want) in cases {
            let mut accs = dep_accounts(|_| {});
            accs[i] = acc;
            assert_eq!(run_dep(&accs, 1), want, "slot {i}");
        }
        // Trader not registered.
        assert_eq!(run_dep(&dep_accounts(|m| m.set_phoenix_trader(&[0; 32])), 1), e(SijkaError::TraderNotRegistered));
        // An extra GTI arena aliasing the trader account.
        let mut accs = dep_accounts(|_| {});
        accs.insert(16, w(TRADER, PHOENIX_PROGRAM_ID, &[]));
        assert_eq!(run_dep(&accs, 2), e(SijkaError::InvalidArenaAccounts));
    }

    /// The keeper key as the fee payer: signer and writable.
    fn keeper_acc() -> TestAccount {
        TestAccount::new(KEEPER, SYSTEM_PROGRAM_ID, 1_000_000_000, &[], true, true, false)
    }

    fn swap_accounts() -> Vec<TestAccount> {
        const SWAP_WSOL: Pubkey = [0x51; 32];
        let mut wsol = token(&WSOL_MINT, &SWAP_AUTH, 0);
        wsol[109..113].copy_from_slice(&1u32.to_le_bytes());
        vec![
            config_acc(|m| {
                m.set_swap_wsol(&SWAP_WSOL);
                m.set_inflow_params(&good_params());
            }),
            TestAccount::new(FEE_INBOX, SYSTEM_PROGRAM_ID, 5_000_000_000, &[], false, true, false),
            swap_auth_acc(false),
            w(SWAP_WSOL, SPL_TOKEN_PROGRAM_ID, &wsol),
            tok(SWAP_USDC, &USDC, &SWAP_AUTH, 0),
            tok(VAULT_USDC, &USDC, &PHX_AUTH, 0),
            keeper_acc(),
            TestAccount::plain(SPL_TOKEN_PROGRAM_ID, [3; 32], &[]),
            TestAccount::plain(SYSTEM_PROGRAM_ID, [3; 32], &[]),
            exe(JUPITER_V6),
            TestAccount::plain([0x0B; 32], [3; 32], &[]),
        ]
    }

    fn run_swap(accs: &[TestAccount]) -> ProgramResult {
        let infos: Vec<AccountInfo> = accs.iter().map(TestAccount::info).collect();
        let mut data = vec![20u8];
        data.extend_from_slice(&1_000_000_000u64.to_le_bytes());
        data.extend_from_slice(&1u64.to_le_bytes());
        data.extend_from_slice(&8u16.to_le_bytes());
        data.extend_from_slice(&crate::constants::JUP_ROUTE_V2);
        crate::process_instruction(&PROGRAM, &infos, &data)
    }

    #[test]
    fn swap_account_set() {
        // A valid set passes every account check; the host then stops at the Clock sysvar.
        assert_eq!(run_swap(&swap_accounts()), Err(ProgramError::UnsupportedSysvar));
        let e = |x: SijkaError| Err(x.into());
        let mut wsol_not_native = token(&WSOL_MINT, &SWAP_AUTH, 0);
        wsol_not_native[109] = 0;
        let cases: Vec<(usize, TestAccount, ProgramResult)> = vec![
            (1, TestAccount::plain(FEE_INBOX, SYSTEM_PROGRAM_ID, &[]), e(SijkaError::AccountNotWritable)),
            (1, w(FEE_INBOX, [9; 32], &[]), e(SijkaError::InvalidExternalAccount)),
            (2, TestAccount::plain(SWAP_AUTH, [9; 32], &[]), e(SijkaError::InvalidExternalAccount)),
            (3, w([0x51; 32], SPL_TOKEN_PROGRAM_ID, &wsol_not_native), e(SijkaError::InvalidTokenAccount)),
            (3, w([0x50; 32], SPL_TOKEN_PROGRAM_ID, &wsol_not_native), e(SijkaError::InvalidPda)),
            (4, tok(SWAP_USDC, &USDC, &PHX_AUTH, 0), e(SijkaError::InvalidTokenAccount)),
            (5, tok(VAULT_USDC, &USDC, &SWAP_AUTH, 0), e(SijkaError::InvalidTokenAccount)),
            (7, TestAccount::plain([9; 32], [3; 32], &[]), e(SijkaError::InvalidProgramId)),
            (8, TestAccount::plain([9; 32], [3; 32], &[]), e(SijkaError::InvalidProgramId)),
            (9, TestAccount::plain(JUPITER_V6, [3; 32], &[]), e(SijkaError::InvalidProgramId)),
        ];
        for (i, acc, want) in cases {
            let mut accs = swap_accounts();
            accs[i] = acc;
            assert_eq!(run_swap(&accs), want, "slot {i}");
        }
    }

    /// SPEC v4 (DECISIONS §23 item 4): only `config.keeper`, signed, reaches
    /// the swap; `keeper == 0` turns the swap off. The keeper check comes
    /// before every other account check and before the clock.
    #[test]
    fn swap_only_by_the_keeper() {
        let e = Err(SijkaError::UnauthorizedKeeper.into());
        let signer = |key: Pubkey| TestAccount::new(key, SYSTEM_PROGRAM_ID, 1, &[], true, true, false);
        let unsigned = TestAccount::new(KEEPER, SYSTEM_PROGRAM_ID, 1, &[], false, true, false);
        for (name, acc) in [
            ("unsigned keeper", unsigned),
            ("admin", signer(ADMIN)),
            ("stranger", signer([0x99; 32])),
            ("zero key", signer([0; 32])),
        ] {
            let mut accs = swap_accounts();
            accs[6] = acc;
            assert_eq!(run_swap(&accs), e, "{name}");
            // Even with every other account wrong, the keeper check decides first.
            accs[1] = TestAccount::plain([1; 32], [9; 32], &[]);
            assert_eq!(run_swap(&accs), e, "{name}, junk accounts");
        }
        // Keeper not set (0): nobody swaps, the old keeper included.
        let mut accs = swap_accounts();
        accs[0] = config_acc(|m| {
            m.set_swap_wsol(&[0x51; 32]);
            m.set_inflow_params(&good_params());
            m.set_keeper(&[0; 32]);
        });
        assert_eq!(run_swap(&accs), e);
        // Rotation: a new keeper passes, the old one is refused.
        let mut accs = swap_accounts();
        accs[0] = config_acc(|m| {
            m.set_swap_wsol(&[0x51; 32]);
            m.set_inflow_params(&good_params());
            m.set_keeper(&[0x4C; 32]);
        });
        assert_eq!(run_swap(&accs), e, "old keeper after rotation");
        accs[6] = signer([0x4C; 32]);
        assert_eq!(run_swap(&accs), Err(ProgramError::UnsupportedSysvar), "new keeper");
        // A read-only keeper (not the fee payer) is fine too.
        let mut accs = swap_accounts();
        accs[6] = TestAccount::new(KEEPER, SYSTEM_PROGRAM_ID, 1, &[], true, false, false);
        assert_eq!(run_swap(&accs), Err(ProgramError::UnsupportedSysvar));
    }

    #[test]
    fn sweep_valid_set_reaches_clock() {
        let parts = sweep_accounts(
            fee_inbox_acc(),
            tok([3; 32], &USDC, &FEE_INBOX, 7),
            tok(VAULT_USDC, &USDC, &PHX_AUTH, 0),
            SPL_TOKEN_PROGRAM_ID,
        );
        assert_eq!(run_sweep(22, parts), Err(ProgramError::UnsupportedSysvar));
        let parts = sweep_accounts(
            swap_auth_acc(false),
            tok(SWAP_USDC, &USDC, &SWAP_AUTH, 7),
            tok(VAULT_USDC, &USDC, &PHX_AUTH, 0),
            SPL_TOKEN_PROGRAM_ID,
        );
        assert_eq!(run_sweep(23, parts), Err(ProgramError::UnsupportedSysvar));
    }

    #[test]
    fn deposit_mode_checks_before_accounts() {
        let run = |edit: fn(&mut ConfigMut)| -> ProgramResult {
            let cfg = config_acc(edit);
            let rest: Vec<TestAccount> =
                (0..16).map(|i| TestAccount::plain([0x70 + i as u8; 32], [0; 32], &[])).collect();
            let mut infos = vec![cfg.info()];
            infos.extend(rest.iter().map(TestAccount::info));
            let mut data = vec![21u8, 1, 1];
            data.extend_from_slice(&0u64.to_le_bytes());
            crate::process_instruction(&PROGRAM, &infos, &data)
        };
        // Recovery mode first (TR: deposits are off forever); no pause since
        // SPEC v4: any byte at the former `inflow_pause_mask@1152` is ignored.
        assert_eq!(run(|m| m.set_recovery_mode(1)), Err(SijkaError::RecoveryActive.into()));
        assert_eq!(run(|m| m.bytes_mut()[1152] = 3), Err(SijkaError::InvalidPda.into()));
        assert_eq!(run(|_| {}), Err(SijkaError::InvalidPda.into()));
    }
}
