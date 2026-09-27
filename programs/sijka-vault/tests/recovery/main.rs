// Copyright (c) 2026 prt1sn. All rights reserved.
//! LiteSVM integration tests of the emergency recovery (SPEC §5.6, §9.11,
//! DECISIONS §17, §18): the venue verdict of tag 50 / tag 51 op 0 over real
//! mainnet and fixture Phoenix state (and byte-level mutations of it), the
//! 10-day window, the latch, the withdraw / unwrap / send ops against the
//! mainnet Phoenix / Ember / Hawkeye binaries, the single route to the admin
//! (SPEC v4: no `renounce_admin`), the FORMAT verdicts that count toward the
//! 10 days (SPEC v4, DECISIONS §23 item 5), trading in recovery mode, and that
//! no op touches the buyback escrow or the unpaid creator share.
//!
//! Runs in CI (Linux) after `cargo build-sbf`; without the artifacts the
//! tests skip unless `RISE_SDK_LOCALNET_REQUIRE_PROGRAMS=1`. Not built on
//! Windows hosts (litesvm needs a MinGW `dlltool` there).

#![cfg(not(windows))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::too_many_arguments,
    clippy::result_large_err,
    clippy::type_complexity
)]

#[path = "../common/recovery_harness.rs"]
mod harness;
#[path = "../common/recovery_vault.rs"]
mod vault;

mod phoenix_states;
mod routing;
mod trading;
mod venue_mainnet;
mod window;
mod withdraw;
