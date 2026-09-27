// Copyright (c) 2026 prt1sn. All rights reserved.
//! LiteSVM integration tests of the buyback (SPEC §5.5, tags 40–48) on the
//! real mainnet pump / pump_amm / pump_fees / Token-2022 / SPL Token / ATA
//! binaries and mainnet snapshots of live pump.fun coins (a bonding-curve coin
//! and a graduated PumpSwap coin, SOL and USDC pairs), fetched by
//! `tests/fixtures/buyback/fetch.mjs` (CI: once a day, cached).
//!
//! Negative paths that need a misbehaving counterparty (tag 43 routes, pump
//! CPIs that abuse the `buyback_authority` signature) use builtin mock
//! programs at the Jupiter / pump addresses (`mocks.rs`), in their own SVM.
//!
//! Without the fixtures or `sijka_vault.so` the tests are skipped, unless
//! `RISE_SDK_LOCALNET_REQUIRE_PROGRAMS=1` or `SIJKA_REQUIRE_SO=1` (CI), in
//! which case they fail. Not built on Windows hosts (litesvm needs a MinGW
//! `dlltool` there).

#![cfg(not(windows))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::float_arithmetic,
    clippy::too_many_arguments,
    clippy::type_complexity,
    clippy::result_large_err,
    dead_code
)]

/// A fresh test vault, or return (test skipped) without fixtures.
macro_rules! vault {
    ($s:expr) => {
        match crate::harness::Vault::try_new($s) {
            Some(v) => v,
            None => return,
        }
    };
}

mod fixtures;
mod harness;
mod mocks;
mod pumpix;

mod t_amm;
mod t_curve;
mod t_errors;
mod t_fuzz;
mod t_graduation;
mod t_guards;
mod t_observe;
mod t_pin;
mod t_swap;
mod t_tamper;
mod t_uchecks;
