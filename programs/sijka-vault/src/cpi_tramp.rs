// Copyright (c) 2026 prt1sn. All rights reserved.
//! CPI trampolines (SPEC §5.0.6, review CPI-2).
//!
//! This is the only module that calls `pinocchio::cpi::slice_invoke_signed`,
//! `invoke_signed_with_bounds` or the `invoke` / `invoke_signed` methods of the
//! typed `phoenix_rise` wrappers (CI greps for it, TE-14). Every function is
//! `#[inline(never)]` and takes large buffers by reference, so pinocchio's
//! `[Account; 64]` (3584 bytes) lives only in the trampoline's own 4 KiB frame
//! while `CpiScratch`, id arrays and meta arrays stay in the caller's frame.
//!
//! Scratch sizes are sized for `MAX_GTI = MAX_ATB = 8` (review CPI-1, RT-10) and
//! checked at compile time against the SDK minimums below. Small fixed-size
//! Token / System CPIs (≤ 4 accounts) are the documented exception and live
//! in `cpi/token.rs` and `cpi/system.rs`.

use phoenix_rise::cpi::{CpiScratch, ember, hawkeye, phoenix};
use pinocchio::ProgramResult;
use pinocchio::account_info::AccountInfo;
use pinocchio::instruction::{Instruction, Signer};

use crate::constants::{MAX_ATB, MAX_GTI};

// ------------------------------------------------------ scratch sizes ----

/// Hawkeye `ViewMargin`: `4 + g + a` accounts, 8 bytes of data.
pub const SCRATCH_VIEW_MARGIN_ACCOUNTS: usize = 20;
pub const SCRATCH_VIEW_MARGIN_DATA: usize = 8;
/// Phoenix `deposit_funds`: `8 + g + a` accounts (no permission account), 16 bytes.
pub const SCRATCH_DEPOSIT_ACCOUNTS: usize = 24;
pub const SCRATCH_DEPOSIT_DATA: usize = 16;
/// Phoenix `withdraw_funds`: `10 + g + a` accounts, 16 bytes.
pub const SCRATCH_WITHDRAW_ACCOUNTS: usize = 26;
pub const SCRATCH_WITHDRAW_DATA: usize = 16;
/// Ember `deposit` / `withdraw`: 8 accounts; withdraw data `8 + 1 + 8` for `Some(r)`.
pub const SCRATCH_EMBER_ACCOUNTS: usize = 8;
pub const SCRATCH_EMBER_DEPOSIT_DATA: usize = 16;
pub const SCRATCH_EMBER_WITHDRAW_DATA: usize = 17;
/// Phoenix `RegisterTrader`: 7 accounts, 18 bytes.
pub const SCRATCH_REGISTER_ACCOUNTS: usize = 7;
pub const SCRATCH_REGISTER_DATA: usize = 18;

const ARENAS_MAX: usize = MAX_GTI + MAX_ATB;

const _: () = {
    assert!(SCRATCH_VIEW_MARGIN_ACCOUNTS >= hawkeye::VIEW_MARGIN_MIN_ACCOUNT_COUNT + ARENAS_MAX);
    assert!(SCRATCH_VIEW_MARGIN_DATA >= hawkeye::VIEW_MARGIN_DATA_LEN);
    assert!(SCRATCH_DEPOSIT_ACCOUNTS >= phoenix::PHOENIX_DEPOSIT_MIN_ACCOUNT_COUNT + ARENAS_MAX);
    assert!(SCRATCH_DEPOSIT_DATA >= phoenix::PHOENIX_DEPOSIT_DATA_LEN);
    assert!(SCRATCH_WITHDRAW_ACCOUNTS >= phoenix::PHOENIX_WITHDRAW_MIN_ACCOUNT_COUNT + ARENAS_MAX);
    assert!(SCRATCH_WITHDRAW_DATA >= phoenix::PHOENIX_WITHDRAW_DATA_LEN);
    assert!(SCRATCH_EMBER_ACCOUNTS >= ember::EMBER_DEPOSIT_ACCOUNT_COUNT);
    assert!(SCRATCH_EMBER_ACCOUNTS >= ember::EMBER_WITHDRAW_ACCOUNT_COUNT);
    assert!(SCRATCH_EMBER_DEPOSIT_DATA >= ember::EMBER_DEPOSIT_DATA_LEN);
    assert!(SCRATCH_EMBER_WITHDRAW_DATA >= ember::EMBER_WITHDRAW_MAX_DATA_LEN);
    assert!(SCRATCH_REGISTER_ACCOUNTS >= phoenix::REGISTER_TRADER_ACCOUNT_COUNT);
    assert!(SCRATCH_REGISTER_DATA >= phoenix::REGISTER_TRADER_DATA_LEN);
};

// ---------------------------------------------------------- generic ----

/// Hand-built CPI (tag 10 `trade` pass-through to Phoenix, Jupiter, pump).
/// Account metas are built by the caller with explicit
/// `AccountMeta::new(key, w, s)`; our PDAs get their signature only through
/// `s`.
#[inline(never)]
pub fn cpi_signed(ix: &Instruction, infos: &[&AccountInfo], s: &[Signer]) -> ProgramResult {
    pinocchio::cpi::slice_invoke_signed(ix, infos, s)
}

// ----------------------------------------------------------- Phoenix ----

#[inline(never)]
pub fn phx_register<'a>(
    w: &phoenix::RegisterTrader<'a>,
    args: phoenix::RegisterTraderArgs,
    s: &[Signer],
    scratch: &mut CpiScratch<'a, SCRATCH_REGISTER_ACCOUNTS, SCRATCH_REGISTER_DATA>,
) -> ProgramResult {
    w.invoke_signed(args, s, scratch)
}

#[inline(never)]
pub fn phx_deposit<'a>(
    w: &phoenix::PhoenixDeposit<'a>,
    args: phoenix::PhoenixDepositArgs,
    s: &[Signer],
    scratch: &mut CpiScratch<'a, SCRATCH_DEPOSIT_ACCOUNTS, SCRATCH_DEPOSIT_DATA>,
) -> ProgramResult {
    w.invoke_signed(args, s, scratch)
}

#[inline(never)]
pub fn phx_withdraw<'a>(
    w: &phoenix::PhoenixWithdraw<'a>,
    args: phoenix::PhoenixWithdrawArgs,
    s: &[Signer],
    scratch: &mut CpiScratch<'a, SCRATCH_WITHDRAW_ACCOUNTS, SCRATCH_WITHDRAW_DATA>,
) -> ProgramResult {
    w.invoke_signed(args, s, scratch)
}

// ------------------------------------------------------------- Ember ----

#[inline(never)]
pub fn ember_deposit<'a>(
    w: &ember::EmberDeposit<'a>,
    args: ember::EmberDepositArgs,
    s: &[Signer],
    scratch: &mut CpiScratch<'a, SCRATCH_EMBER_ACCOUNTS, SCRATCH_EMBER_DEPOSIT_DATA>,
) -> ProgramResult {
    w.invoke_signed(args, s, scratch)
}

#[inline(never)]
pub fn ember_withdraw<'a>(
    w: &ember::EmberWithdraw<'a>,
    args: ember::EmberWithdrawArgs,
    s: &[Signer],
    scratch: &mut CpiScratch<'a, SCRATCH_EMBER_ACCOUNTS, SCRATCH_EMBER_WITHDRAW_DATA>,
) -> ProgramResult {
    w.invoke_signed(args, s, scratch)
}

// ----------------------------------------------------------- Hawkeye ----

/// Hawkeye `ViewMargin`: all accounts read-only, no signers. The caller parses
/// the return data itself (magic and version, SPEC §5.2.9), not
/// `invoke_and_decode`.
#[inline(never)]
pub fn hk_view_margin<'a>(
    w: &hawkeye::ViewMargin<'a>,
    scratch: &mut CpiScratch<'a, SCRATCH_VIEW_MARGIN_ACCOUNTS, SCRATCH_VIEW_MARGIN_DATA>,
) -> ProgramResult {
    w.invoke(hawkeye::ViewMarginArgs, scratch)
}
