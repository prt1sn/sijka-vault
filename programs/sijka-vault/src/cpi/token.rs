// Copyright (c) 2026 prt1sn. All rights reserved.
//! SPL Token / Token-2022 CPIs (SPEC §5.5.2 "Мелкие CPI").
//!
//! Every helper checks the token program account it is given: Tokenkeg for
//! USDC, wSOL and PhUSD operations; Tokenkeg or Token-2022 for `burn_checked`
//! (the SIJKA mint). Fixed 2–4 account CPIs via pinocchio's fixed-size
//! `invoke_signed` are allowed outside `cpi_tramp.rs` (SPEC §5.0.6 rule 1).
//! Our PDA authorities sign only through `signers`.

use pinocchio::ProgramResult;
use pinocchio::account_info::AccountInfo;
use pinocchio::instruction::{AccountMeta, Instruction, Signer};
use pinocchio::pubkey::{Pubkey, pubkey_eq};

use crate::constants::{SPL_TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID};
use crate::error::SijkaError;

/// `token_program` must be Tokenkeg (key only; the runtime resolves the
/// program by id).
#[inline]
fn expect_spl_token(token_program: &AccountInfo) -> ProgramResult {
    if !pubkey_eq(token_program.key(), &SPL_TOKEN_PROGRAM_ID) {
        return Err(SijkaError::InvalidProgramId.fail());
    }
    Ok(())
}

/// `token_program` must be Tokenkeg or Token-2022.
#[inline]
fn expect_any_token(token_program: &AccountInfo) -> Result<&Pubkey, pinocchio::program_error::ProgramError> {
    let k = token_program.key();
    if pubkey_eq(k, &SPL_TOKEN_PROGRAM_ID) || pubkey_eq(k, &TOKEN_2022_PROGRAM_ID) {
        Ok(k)
    } else {
        Err(SijkaError::InvalidProgramId.fail())
    }
}

/// SPL `Transfer` (`[3] ‖ amount`), Tokenkeg only.
pub fn transfer(
    token_program: &AccountInfo,
    from: &AccountInfo,
    to: &AccountInfo,
    authority: &AccountInfo,
    amount: u64,
    signers: &[Signer],
) -> ProgramResult {
    expect_spl_token(token_program)?;
    pinocchio_token::instructions::Transfer { from, to, authority, amount }.invoke_signed(signers)
}

/// SPL `TransferChecked` (`[12] ‖ amount ‖ decimals`), Tokenkeg only.
#[allow(clippy::too_many_arguments)]
pub fn transfer_checked(
    token_program: &AccountInfo,
    from: &AccountInfo,
    mint: &AccountInfo,
    to: &AccountInfo,
    authority: &AccountInfo,
    amount: u64,
    decimals: u8,
    signers: &[Signer],
) -> ProgramResult {
    expect_spl_token(token_program)?;
    pinocchio_token::instructions::TransferChecked { from, mint, to, authority, amount, decimals }
        .invoke_signed(signers)
}

/// `BurnChecked` (`[15] ‖ amount ‖ decimals`) under Tokenkeg or Token-2022:
/// the instruction is addressed to `token_program.key()` (pinocchio-token
/// hard-codes Tokenkeg, so this one is built here).
pub fn burn_checked(
    token_program: &AccountInfo,
    account: &AccountInfo,
    mint: &AccountInfo,
    authority: &AccountInfo,
    amount: u64,
    decimals: u8,
    signers: &[Signer],
) -> ProgramResult {
    let program_id = expect_any_token(token_program)?;
    let mut data = [0u8; 10];
    data[0] = 15;
    data[1..9].copy_from_slice(&amount.to_le_bytes());
    data[9] = decimals;
    let metas = [
        AccountMeta::writable(account.key()),
        AccountMeta::writable(mint.key()),
        AccountMeta::readonly_signer(authority.key()),
    ];
    let ix = Instruction { program_id, accounts: &metas, data: &data };
    pinocchio::cpi::invoke_signed(&ix, &[account, mint, authority], signers)
}

/// SPL `SyncNative` (`[17]`), Tokenkeg only.
pub fn sync_native(token_program: &AccountInfo, native_token: &AccountInfo) -> ProgramResult {
    expect_spl_token(token_program)?;
    pinocchio_token::instructions::SyncNative { native_token }.invoke()
}

/// SPL `CloseAccount` (`[9]`), Tokenkeg only. SPEC §1.5: used only for the
/// temporary `bb_unwrap` account of tag 43.
pub fn close_account(
    token_program: &AccountInfo,
    account: &AccountInfo,
    destination: &AccountInfo,
    authority: &AccountInfo,
    signers: &[Signer],
) -> ProgramResult {
    expect_spl_token(token_program)?;
    pinocchio_token::instructions::CloseAccount { account, destination, authority }.invoke_signed(signers)
}

/// SPL `InitializeAccount3` (`[18] ‖ owner`), Tokenkeg only (tag 43 `bb_unwrap`).
pub fn initialize_account3(
    token_program: &AccountInfo,
    account: &AccountInfo,
    mint: &AccountInfo,
    owner: &Pubkey,
) -> ProgramResult {
    expect_spl_token(token_program)?;
    pinocchio_token::instructions::InitializeAccount3 { account, mint, owner }.invoke()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::test_utils::TestAccount;

    #[test]
    fn wrong_token_program_is_rejected_before_cpi() {
        let bad = TestAccount::plain([9; 32], [0; 32], &[]);
        let a = TestAccount::plain([1; 32], SPL_TOKEN_PROGRAM_ID, &[]);
        let b = a.info();
        let bi = bad.info();
        let e = Err(SijkaError::InvalidProgramId.into());
        assert_eq!(transfer(&bi, &b, &b, &b, 1, &[]), e);
        assert_eq!(transfer_checked(&bi, &b, &b, &b, &b, 1, 6, &[]), e);
        assert_eq!(burn_checked(&bi, &b, &b, &b, 1, 6, &[]), e);
        assert_eq!(sync_native(&bi, &b), e);
        assert_eq!(close_account(&bi, &b, &b, &b, &[]), e);
        assert_eq!(initialize_account3(&bi, &b, &b, &[0; 32]), e);
        // Token-2022 is accepted only by burn_checked.
        let t22 = TestAccount::plain(TOKEN_2022_PROGRAM_ID, [0; 32], &[]);
        assert_eq!(transfer(&t22.info(), &b, &b, &b, 1, &[]), e);
        assert!(expect_any_token(&t22.info()).is_ok());
    }
}
