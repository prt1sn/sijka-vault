// Copyright (c) 2026 prt1sn. All rights reserved.
//! LiteSVM integration tests, area "phoenix-core": `initialize` (all PDAs,
//! front-running), `set_token_mint`, `register_phoenix_trader` through the
//! mainnet Phoenix binary (prefs `0b11`), capability activation the way the
//! Phoenix onboarder does it, `deposit_usdc`, `harvest` end to end (profit
//! from a real trade against a fixture counterparty), `pay_creator`,
//! `set_trader` and pass-through trading with tag 10 `trade` (SPEC v3,
//! §9.4 TT-*: each of the 14 allowlisted Phoenix instructions, each of the
//! 99 others, account substitution in every slot, the delegate-bypass
//! regression), and the SPEC v4 admin surface: tag 28 `set_keeper` and the
//! retired admin tags 7, 8, 25, 26, 47, 48 (SPEC §9.3, §9.5, §9.6).
//!
//! The programs are the mainnet Phoenix / Ember / Hawkeye binaries loaded by
//! `phoenix-rise-litesvm-test` (CI dumps them; `PHOENIX_MAINNET_BPF_PROGRAMS=1`
//! fetches them locally), and our `sijka_vault.so` (`SIJKA_VAULT_SO`). Without
//! the artifacts every test is skipped, unless `RISE_SDK_LOCALNET_REQUIRE_PROGRAMS=1`
//! or `SIJKA_REQUIRE_SO=1`. Not built on Windows hosts.

#![cfg(not(windows))]
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::float_arithmetic,
    clippy::too_many_arguments,
    clippy::result_large_err
)]

mod abi;
mod harness;
mod ixs;
mod phx;
mod phx_trade;

mod accounts;
mod admin_v4;
mod deposit;
mod harvest;
mod initialize;
mod positions;
mod register;
mod token_mint;
mod trade;
mod trade_allowed;
mod trade_denied;
