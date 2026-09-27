// Copyright (c) 2026 prt1sn. All rights reserved.
//! LiteSVM integration tests of the inflow section (SPEC §5.3, §9.5): tag 20
//! `swap_sol_to_usdc` against a Jupiter mock at `JUP6…` with honest and
//! malicious behaviours and against the real Jupiter v6 binary, signed by the
//! keeper key with its own `min_out` (SPEC v4: no oracle), `fee_inbox` and its
//! reserve, tag 21 `deposit_usdc` on the real Phoenix / Ember binaries
//! (capital `I`), the sweeps (22, 23), the inflow parameters fixed at
//! `initialize` (tags 25, 26 retired), and the runtime limits behind U-25 /
//! U-28.
//!
//! Runs in CI on Linux (litesvm job). Artifacts:
//! - `SIJKA_VAULT_SO` or `target/deploy/sijka_vault.so`;
//! - `SIJKA_MOCK_JUPITER_SO` or `target/deploy-mocks/sijka_mock_jupiter.so`
//!   (`cargo build-sbf --manifest-path programs/sijka-vault/tests/mock-jupiter/Cargo.toml`);
//! - Phoenix / Ember / Hawkeye via `RISE_SDK_LOCALNET_*_SO`;
//! - mainnet fixtures of `tests/fixtures/inflow-fetch.sh` (Jupiter v6, SPL
//!   token-swap and a live SOL/USDC pool) in `target/deploy/.cache-inflow`.
//!
//! Missing artifacts skip the tests unless `SIJKA_REQUIRE_SO=1` or
//! `RISE_SDK_LOCALNET_REQUIRE_PROGRAMS=1` (CI), which makes them fail.

#![cfg(not(windows))]
#![allow(
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
    clippy::result_large_err,
    clippy::type_complexity,
    dead_code
)]

mod capital;
mod deposit;
mod fee_inbox;
mod harness;
mod keeper;
mod limits;
mod malicious;
mod params;
mod real_jupiter;
mod route;
mod swap;
mod sweep;
