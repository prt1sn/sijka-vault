// Copyright (c) 2026 prt1sn. All rights reserved.
//! Sijka vault program (Pinocchio 0.9, `phoenix-rise` CPI).
//!
//! The vault collects the coin's creator fees, converts them to USDC, keeps
//! them as margin on one Phoenix Perpetuals trading account, pays out realized
//! profit above the high-water mark (20% to the fixed `creator_payout`, 80% to
//! buy back and burn the coin), and has no withdrawal path for anyone except
//! the emergency recovery that Phoenix's own on-chain state can trigger.
//!
//! Trading is unrestricted but goes through one pass-through instruction,
//! tag 10 `trade` (SPEC §5.2, DECISIONS §19): the trading key `config.trader`
//! (set by the admin with tag 3 `set_trader`) signs, and the program forwards
//! only Phoenix trading instructions (orders of every kind, cancels,
//! stop-loss and conditional orders) for its own trader account, signed by
//! the `phx_authority` PDA. No market whitelist, price band, size or leverage
//! limit and no pause; everything that is not a trading instruction is
//! rejected. The position authority of the account stays `phx_authority`.
//!
//! SPEC v4 (DECISIONS §23): no admin parameter or pause instructions and no
//! `renounce_admin`; parameters are fixed at `initialize` / `bb_init`. The two
//! swaps (tags 20 and 43) and the buyback chunks (tags 44 and 45) are signed by
//! the keeper key `config.keeper` (tag 28 `set_keeper`) with its own `min_out`;
//! there is no oracle and no spot guard in the program. Every other crank stays
//! permissionless.
//!
//! Dispatch: `data[0]` is the instruction tag (SPEC §4). Unknown and reserved
//! tags are rejected with `UnknownInstruction`; every handler checks the exact
//! data length and account count first (`instructions::check_shape`).
//!
//! `unsafe` is denied crate-wide. Exceptions, each documented at the site:
//! the entrypoint / security.txt macros (below), two runtime syscalls in
//! `util::runtime`, and the host-only `util::test_utils`.

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::float_arithmetic,
        clippy::print_stdout,
        clippy::print_stderr
    )
)]

pub mod accounting;
pub mod buyback;
pub mod constants;
pub mod cpi;
pub mod cpi_tramp;
pub mod error;
pub mod events;
pub mod external;
pub mod instructions;
pub mod state;
pub mod util;
pub mod venue;

#[cfg(test)]
mod abi_check;

use pinocchio::ProgramResult;
use pinocchio::account_info::AccountInfo;
use pinocchio::pubkey::Pubkey;

use crate::error::SijkaError;
use crate::instructions as ix;

/// Program entrypoint and embedded security.txt (SPEC §1.8). The macros emit
/// `#[no_mangle]` items (and pinocchio's `unsafe extern "C" fn entrypoint`
/// that deserializes the runtime input), hence the local `allow(unsafe_code)`.
#[cfg(not(feature = "no-entrypoint"))]
#[allow(unsafe_code)]
mod entrypoint {
    pinocchio::entrypoint!(crate::process_instruction);

    solana_security_txt::security_txt! {
        name: "Sijka Vault",
        project_url: env!("SIJKA_PROJECT_URL"),
        contacts: env!("SIJKA_CONTACTS"),
        policy: env!("SIJKA_POLICY_URL"),
        preferred_languages: "en,ru",
        source_code: env!("SIJKA_SOURCE_CODE_URL"),
        source_release: env!("SIJKA_SOURCE_RELEASE"),
        source_revision: env!("SIJKA_SOURCE_REVISION"),
        auditors: env!("SIJKA_AUDITORS")
    }
}

/// Instruction dispatch by tag (SPEC §4). Deny by default.
pub fn process_instruction(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let Some(&tag) = data.first() else {
        return Err(SijkaError::InvalidInstructionData.fail());
    };
    match tag {
        // Setup and admin (§5.1).
        0 => ix::setup::initialize(program_id, accounts, data),
        1 => ix::setup::set_token_mint(program_id, accounts, data),
        2 => ix::setup::register_phoenix_trader(program_id, accounts, data),
        3 => ix::setup::set_trader(program_id, accounts, data),
        // Trading (§5.2).
        10 => ix::trade::trade(program_id, accounts, data),
        // Inflows (§5.3).
        20 => ix::inflow::swap_sol_to_usdc(program_id, accounts, data),
        21 => ix::inflow::deposit_usdc(program_id, accounts, data),
        22 => ix::inflow::sweep_fee_inbox_usdc(program_id, accounts, data),
        23 => ix::inflow::sweep_swap_usdc(program_id, accounts, data),
        // Keeper key of tags 20, 43, 44 and 45 (§5.1.10).
        28 => ix::setup::set_keeper(program_id, accounts, data),
        // Profit accounting (§5.4).
        30 => ix::harvest::harvest(program_id, accounts, data),
        31 => ix::harvest::harvest_preview(program_id, accounts, data),
        32 => ix::harvest::pay_creator(program_id, accounts, data),
        // Buyback and burn (§5.5).
        40 => ix::buyback::bb_init(program_id, accounts, data),
        41 => ix::buyback::bb_pin(program_id, accounts, data),
        42 => ix::buyback::bb_observe(program_id, accounts, data),
        43 => ix::buyback::bb_swap_usdc_to_sol(program_id, accounts, data),
        44 => ix::buyback::bb_chunk_curve(program_id, accounts, data),
        45 => ix::buyback::bb_chunk_amm(program_id, accounts, data),
        46 => ix::buyback::bb_burn(program_id, accounts, data),
        // Emergency recovery (§5.6).
        50 => ix::recovery::observe_venue(program_id, accounts, data),
        51 => ix::recovery::emergency_recover(program_id, accounts, data),
        // Reserved (4–6 retired with SPEC v2, 9 with SPEC v3, 7, 8, 25, 26,
        // 47, 48 with SPEC v4, 11–19, 24, 27, 29, 33–39, 49, 52–59) and ≥ 60.
        _ => Err(SijkaError::UnknownInstruction.fail()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_and_reserved_tags_are_rejected() {
        let program = [1u8; 32];
        let reserved = [
            4u8, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15, 16, 17, 18, 19, 24, 25, 26, 27, 29, 33, 34, 35, 36, 37, 38, 39, 47,
            48, 49, 52, 53, 54, 55, 56, 57, 58, 59, 60, 128, 255,
        ];
        for tag in reserved {
            assert_eq!(
                process_instruction(&program, &[], &[tag]),
                Err(SijkaError::UnknownInstruction.into()),
                "tag {tag}"
            );
        }
        assert_eq!(process_instruction(&program, &[], &[]), Err(SijkaError::InvalidInstructionData.into()));
    }

    /// SPEC v4 (DECISIONS §23): the admin parameter / pause instructions and
    /// `renounce_admin` are gone. Their tags fail before any account is read,
    /// whatever the data and accounts (even the old exact shapes).
    #[test]
    fn retired_v4_tags_are_rejected_with_any_shape() {
        let program = [1u8; 32];
        let pool = crate::util::test_utils::dummy_accounts(4);
        let accounts = crate::util::test_utils::infos(&pool);
        for (tag, len, n) in [(7u8, 65usize, 2usize), (8, 65, 3), (25, 41, 2), (26, 2, 2), (47, 81, 3), (48, 2, 3)] {
            let mut data = vec![0u8; len];
            data[0] = tag;
            assert_eq!(
                process_instruction(&program, &accounts[..n], &data),
                Err(SijkaError::UnknownInstruction.into()),
                "tag {tag}"
            );
        }
    }

    #[test]
    fn unknown_ops_are_rejected() {
        let program = [1u8; 32];
        // Tag 51 has ops 0–6 only (SPEC §5.6.4).
        for op in [7u8, 8, 9, 0xFF] {
            let data = [51, op, 1, 1];
            assert_eq!(process_instruction(&program, &[], &data), Err(SijkaError::InvalidInstructionData.into()));
        }
        assert_eq!(process_instruction(&program, &[], &[51]), Err(SijkaError::InvalidInstructionData.into()));
    }
}
