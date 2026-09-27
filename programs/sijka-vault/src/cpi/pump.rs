// Copyright (c) 2026 prt1sn. All rights reserved.
//! pump bonding curve `buy_exact_quote_in_v2(spendable_quote_in, min_tokens_out)`
//! (SPEC §5.5.3, tag 44).
//!
//! 27 accounts in IDL order (`pump.json`), data 24 bytes
//! `IX_BUY_EXACT_QUOTE_IN_V2 ‖ v ‖ min_out`. Metas are built by hand with the
//! IDL flags (`AccountMeta::new(key, writable, signer)`), never copied from
//! the outer `AccountInfo`: `user = buyback_authority` is W+S in the CPI only,
//! its signature comes from `["buyback", bump]`. `base_mint` is read-only in
//! the CPI (writable in the outer instruction only for the burn). The call
//! goes through `crate::cpi_tramp::cpi_signed`; the meta array lives in this
//! function's frame.

use pinocchio::ProgramResult;
use pinocchio::account_info::AccountInfo;
use pinocchio::instruction::{AccountMeta, Instruction, Signer};
use pinocchio::pubkey::Pubkey;

use crate::constants::{IX_BUY_EXACT_QUOTE_IN_V2, PUMP_PROGRAM};
use crate::error::SijkaError;

/// Number of pump accounts for `buy_exact_quote_in_v2`.
pub const CURVE_BUY_ACCOUNTS: usize = 27;
/// Instruction data length.
pub const CURVE_BUY_DATA_LEN: usize = 24;

/// `(writable, signer)` of each account, IDL order (SPEC §5.5.3 table).
pub const CURVE_BUY_FLAGS: [(bool, bool); CURVE_BUY_ACCOUNTS] = [
    (false, false), // 1 global
    (false, false), // 2 base_mint (outer W for the burn)
    (false, false), // 3 quote_mint
    (false, false), // 4 base_token_program
    (false, false), // 5 quote_token_program
    (false, false), // 6 associated_token_program
    (true, false),  // 7 fee_recipient
    (true, false),  // 8 associated_quote_fee_recipient
    (true, false),  // 9 buyback_fee_recipient
    (true, false),  // 10 associated_quote_buyback_fee_recipient
    (true, false),  // 11 bonding_curve
    (true, false),  // 12 associated_base_bonding_curve
    (true, false),  // 13 associated_quote_bonding_curve
    (true, true),   // 14 user = buyback_authority
    (true, false),  // 15 associated_base_user = buyback_token
    (true, false),  // 16 associated_quote_user = bb_quote
    (true, false),  // 17 creator_vault
    (true, false),  // 18 associated_creator_vault
    (false, false), // 19 sharing_config
    (false, false), // 20 global_volume_accumulator
    (true, false),  // 21 user_volume_accumulator
    (true, false),  // 22 associated_user_volume_accumulator
    (false, false), // 23 fee_config
    (false, false), // 24 fee_program
    (false, false), // 25 system_program
    (false, false), // 26 event_authority
    (false, false), // 27 program
];

/// Index of `user` in the pump account list (the only signer).
pub const CURVE_USER: usize = 13;

/// Instruction data `disc ‖ v ‖ min_out`.
pub fn curve_buy_data(v: u64, min_out: u64) -> [u8; CURVE_BUY_DATA_LEN] {
    let mut d = [0u8; CURVE_BUY_DATA_LEN];
    let (disc, rest) = d.split_at_mut(8);
    disc.copy_from_slice(&IX_BUY_EXACT_QUOTE_IN_V2);
    let (a, b) = rest.split_at_mut(8);
    a.copy_from_slice(&v.to_le_bytes());
    b.copy_from_slice(&min_out.to_le_bytes());
    d
}

/// Build the metas (explicit IDL flags) and infos of a hand-built pump /
/// pump_amm CPI and invoke it through the trampoline. `mirror_writable`: index
/// whose writable flag is copied from the outer instruction (PumpSwap `r2`,
/// SPEC §5.5.3); the signer flag is never copied from the outer instruction.
#[inline(never)]
pub(crate) fn invoke_pump<const N: usize>(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    flags: &[(bool, bool); N],
    mirror_writable: Option<usize>,
    data: &[u8],
    signer: &[Signer],
) -> ProgramResult {
    if accounts.len() != N {
        return Err(SijkaError::InvalidAccountCount.fail());
    }
    let first = accounts.first().ok_or_else(|| SijkaError::InvalidAccountCount.fail())?;
    let mut metas: [AccountMeta; N] = [const { AccountMeta::readonly(&PUMP_PROGRAM) }; N];
    let mut infos: [&AccountInfo; N] = [first; N];
    for (k, (((m, info), a), f)) in metas.iter_mut().zip(infos.iter_mut()).zip(accounts).zip(flags).enumerate() {
        let w = if mirror_writable == Some(k) { a.is_writable() } else { f.0 };
        *m = AccountMeta::new(a.key(), w, f.1);
        *info = a;
    }
    let ix = Instruction { program_id, accounts: &metas, data };
    crate::cpi_tramp::cpi_signed(&ix, &infos, signer)
}

/// CPI `buy_exact_quote_in_v2(v, min_out)` with the 27 pump accounts of tag 44
/// (outer accounts 4..=30, already checked against the pinned keys and flags
/// by the caller). `signer` must be `["buyback", bump]`.
pub fn buy_exact_quote_in_v2(pump_accounts: &[AccountInfo], v: u64, min_out: u64, signer: &[Signer]) -> ProgramResult {
    let data = curve_buy_data(v, min_out);
    invoke_pump(&PUMP_PROGRAM, pump_accounts, &CURVE_BUY_FLAGS, None, &data, signer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_match_idl() {
        // IDL pump.json `buy_exact_quote_in_v2`: writable 7..=18 and 21, 22; only `user` signs.
        let writable: Vec<usize> =
            CURVE_BUY_FLAGS.iter().enumerate().filter(|(_, f)| f.0).map(|(i, _)| i + 1).collect();
        assert_eq!(writable, vec![7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 21, 22]);
        let signers: Vec<usize> = CURVE_BUY_FLAGS.iter().enumerate().filter(|(_, f)| f.1).map(|(i, _)| i).collect();
        assert_eq!(signers, vec![CURVE_USER]);
    }

    #[test]
    fn data_layout() {
        let d = curve_buy_data(0x0102_0304_0506_0708, 9);
        assert_eq!(&d[..8], &IX_BUY_EXACT_QUOTE_IN_V2);
        assert_eq!(&d[8..16], &0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(&d[16..], &9u64.to_le_bytes());
    }

    #[test]
    fn wrong_account_count_is_rejected() {
        assert_eq!(buy_exact_quote_in_v2(&[], 1, 1, &[]), Err(SijkaError::InvalidAccountCount.into()));
    }
}
