// Copyright (c) 2026 prt1sn. All rights reserved.
//! System program CPIs and `create_pda_account` (SPEC §5.0.10, §5.5.2).
//!
//! Fixed 1–2 account CPIs through `pinocchio-system` (allowed outside
//! `cpi_tramp.rs`, SPEC §5.0.6 rule 1). Our PDAs sign only through `signers`.

use pinocchio::ProgramResult;
use pinocchio::account_info::AccountInfo;
use pinocchio::instruction::Signer;
use pinocchio::pubkey::Pubkey;

use crate::constants::SYSTEM_PROGRAM_ID;
use crate::error::SijkaError;
use crate::util::math::{rent_exempt_minimum, sub_u64, usize_to_u64};

/// System `Transfer` (`[2,0,0,0] ‖ lamports`).
pub fn transfer(from: &AccountInfo, to: &AccountInfo, lamports: u64, signers: &[Signer]) -> ProgramResult {
    pinocchio_system::instructions::Transfer { from, to, lamports }.invoke_signed(signers)
}

/// System `CreateAccount` (`[0,0,0,0] ‖ lamports ‖ space ‖ owner`).
pub fn create_account(
    from: &AccountInfo,
    to: &AccountInfo,
    lamports: u64,
    space: u64,
    owner: &Pubkey,
    signers: &[Signer],
) -> ProgramResult {
    pinocchio_system::instructions::CreateAccount { from, to, lamports, space, owner }.invoke_signed(signers)
}

/// System `Allocate` (`[8,0,0,0] ‖ space`).
pub fn allocate(account: &AccountInfo, space: u64, signers: &[Signer]) -> ProgramResult {
    pinocchio_system::instructions::Allocate { account, space }.invoke_signed(signers)
}

/// System `Assign` (`[1,0,0,0] ‖ owner`).
pub fn assign(account: &AccountInfo, owner: &Pubkey, signers: &[Signer]) -> ProgramResult {
    pinocchio_system::instructions::Assign { account, owner }.invoke_signed(signers)
}

/// `create_pda_account(payer, target, seeds, space, owner)` (SPEC §5.0.10):
///
/// - `target` must be owned by System with no data, else `busy`
///   (`ConfigAlreadyInitialized`, `BbAlreadyInitialized`, `BbUnwrapAccountBusy`);
/// - `lamports == 0`: `CreateAccount(payer → target, rent(space), space, owner)`;
/// - otherwise (someone pre-funded the address, which would make
///   `CreateAccount` fail): top up to `rent(space)` if needed, then `Allocate`
///   and `Assign`.
///
/// `signers` must contain the target's seeds (and the payer's, if the payer is
/// one of our PDAs). The caller checks the target key and the result.
pub fn create_pda_account(
    payer: &AccountInfo,
    target: &AccountInfo,
    space: usize,
    owner: &Pubkey,
    signers: &[Signer],
    busy: SijkaError,
) -> ProgramResult {
    if !target.is_owned_by(&SYSTEM_PROGRAM_ID) || target.data_len() != 0 {
        return Err(busy.fail());
    }
    let rent = rent_exempt_minimum(space)?;
    let space_u64 = usize_to_u64(space)?;
    let have = target.lamports();
    if have == 0 {
        return create_account(payer, target, rent, space_u64, owner, signers);
    }
    if have < rent {
        transfer(payer, target, sub_u64(rent, have)?, signers)?;
    }
    allocate(target, space_u64, signers)?;
    assign(target, owner, signers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::test_utils::TestAccount;

    #[test]
    fn busy_target_is_rejected_before_any_cpi() {
        let payer = TestAccount::new([1; 32], SYSTEM_PROGRAM_ID, 10, &[], true, true, false);
        let taken = TestAccount::new([2; 32], [7; 32], 10, &[], false, true, false);
        let with_data = TestAccount::new([3; 32], SYSTEM_PROGRAM_ID, 10, &[0], false, true, false);
        for t in [&taken, &with_data] {
            assert_eq!(
                create_pda_account(&payer.info(), &t.info(), 10, &[9; 32], &[], SijkaError::ConfigAlreadyInitialized),
                Err(SijkaError::ConfigAlreadyInitialized.into())
            );
        }
    }
}
