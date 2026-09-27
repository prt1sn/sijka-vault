// Copyright (c) 2026 prt1sn. All rights reserved.
//! PumpSwap `buy_exact_quote_in(spendable_quote_in, min_base_amount_out,
//! track_volume)` (SPEC §5.5.3, tag 45).
//!
//! 23 IDL accounts + 3 remaining (`pool_v2`, `buyback_fee_recipient`, its
//! quote ATA), data 25 bytes `IX_AMM_BUY_EXACT_QUOTE_IN ‖ v ‖ min_out ‖ 0`
//! (`track_volume` is a one-byte `OptionBool`, U-33). Metas carry the IDL
//! flags; only `r2` copies its writable flag from the outer instruction (the
//! keeper passes it read-only, as the TS SDK and pump docs do). The call goes
//! through `crate::cpi_tramp::cpi_signed` with `["buyback", bump]`.
//! U-32: fallback `pump_amm::buy` would take tag 49.

use pinocchio::ProgramResult;
use pinocchio::account_info::AccountInfo;
use pinocchio::instruction::Signer;

use crate::constants::{IX_AMM_BUY_EXACT_QUOTE_IN, PUMP_AMM_PROGRAM};
use crate::cpi::pump::invoke_pump;

/// Number of pump_amm accounts (23 + 3 remaining).
pub const AMM_BUY_ACCOUNTS: usize = 26;
/// Instruction data length.
pub const AMM_BUY_DATA_LEN: usize = 25;

/// `(writable, signer)` of each account, IDL order plus remaining (SPEC §5.5.3).
pub const AMM_BUY_FLAGS: [(bool, bool); AMM_BUY_ACCOUNTS] = [
    (true, false),  // 1 pool
    (true, true),   // 2 user = buyback_authority
    (false, false), // 3 global_config
    (false, false), // 4 base_mint (outer W for the burn)
    (false, false), // 5 quote_mint
    (true, false),  // 6 user_base_token_account = buyback_token
    (true, false),  // 7 user_quote_token_account = bb_quote
    (true, false),  // 8 pool_base_token_account
    (true, false),  // 9 pool_quote_token_account
    (false, false), // 10 protocol_fee_recipient
    (true, false),  // 11 protocol_fee_recipient_token_account
    (false, false), // 12 base_token_program
    (false, false), // 13 quote_token_program
    (false, false), // 14 system_program
    (false, false), // 15 associated_token_program
    (false, false), // 16 event_authority
    (false, false), // 17 program
    (true, false),  // 18 coin_creator_vault_ata
    (false, false), // 19 coin_creator_vault_authority
    (false, false), // 20 global_volume_accumulator
    (true, false),  // 21 user_volume_accumulator
    (false, false), // 22 fee_config
    (false, false), // 23 fee_program
    (false, false), // r1 pool_v2
    (false, false), // r2 buyback_fee_recipient (writable copied from the outer instruction)
    (true, false),  // r3 its quote ATA
];

/// Index of `user` (the only signer).
pub const AMM_USER: usize = 1;
/// Index of `r2` (`buyback_fee_recipient`).
pub const AMM_R2: usize = 24;

/// Instruction data `disc ‖ v ‖ min_out ‖ track_volume = 0`.
pub fn amm_buy_data(v: u64, min_out: u64) -> [u8; AMM_BUY_DATA_LEN] {
    let mut d = [0u8; AMM_BUY_DATA_LEN];
    let (disc, rest) = d.split_at_mut(8);
    disc.copy_from_slice(&IX_AMM_BUY_EXACT_QUOTE_IN);
    let (a, rest) = rest.split_at_mut(8);
    a.copy_from_slice(&v.to_le_bytes());
    let (b, _track_volume) = rest.split_at_mut(8);
    b.copy_from_slice(&min_out.to_le_bytes());
    d
}

/// CPI `buy_exact_quote_in(v, min_out, track_volume = 0)` with the 26 accounts
/// of tag 45 (outer accounts 4..=29, already checked by the caller).
pub fn buy_exact_quote_in(amm_accounts: &[AccountInfo], v: u64, min_out: u64, signer: &[Signer]) -> ProgramResult {
    let data = amm_buy_data(v, min_out);
    invoke_pump(&PUMP_AMM_PROGRAM, amm_accounts, &AMM_BUY_FLAGS, Some(AMM_R2), &data, signer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::SijkaError;

    #[test]
    fn flags_match_idl() {
        // IDL pump_amm.json `buy_exact_quote_in`: writable 1, 2, 6..=9, 11, 18, 21; r3 writable.
        let writable: Vec<usize> = AMM_BUY_FLAGS.iter().enumerate().filter(|(_, f)| f.0).map(|(i, _)| i + 1).collect();
        assert_eq!(writable, vec![1, 2, 6, 7, 8, 9, 11, 18, 21, 26]);
        let signers: Vec<usize> = AMM_BUY_FLAGS.iter().enumerate().filter(|(_, f)| f.1).map(|(i, _)| i).collect();
        assert_eq!(signers, vec![AMM_USER]);
    }

    #[test]
    fn data_layout() {
        let d = amm_buy_data(5, 6);
        assert_eq!(&d[..8], &IX_AMM_BUY_EXACT_QUOTE_IN);
        assert_eq!(&d[8..16], &5u64.to_le_bytes());
        assert_eq!(&d[16..24], &6u64.to_le_bytes());
        assert_eq!(d[24], 0);
    }

    #[test]
    fn wrong_account_count_is_rejected() {
        assert_eq!(buy_exact_quote_in(&[], 1, 1, &[]), Err(SijkaError::InvalidAccountCount.into()));
    }
}
