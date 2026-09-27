// Copyright (c) 2026 prt1sn. All rights reserved.
//! Ember CPIs (SPEC §5.3.5). This file: the shared account set and the
//! deposit (USDC → PhUSD, tag 21). The withdraw (PhUSD → USDC, tags 30 and
//! 51 op 4) lives in `phoenix_withdraw.rs` (owner: harvest) and reuses
//! [`EmberAccounts`].
//!
//! Typed wrapper `phoenix_rise::cpi::ember::EmberDeposit` through
//! `crate::cpi_tramp::ember_deposit` (`CpiScratch<8, 16>`), signed by
//! `phx_authority`. The wrapper fixes the signer / writable flags
//! (`trader` S; `canonical_mint`, both trader token accounts and the Ember
//! vault W). The caller validates every account (SPEC §5.0.5); this module
//! re-checks only the program ids it hands the signature to.

use phoenix_rise::cpi::{CpiScratch, ember};
use pinocchio::ProgramResult;
use pinocchio::account_info::AccountInfo;
use pinocchio::instruction::Signer;

use crate::constants::{EMBER_PROGRAM_ID, SPL_TOKEN_PROGRAM_ID};
use crate::cpi_tramp::{SCRATCH_EMBER_ACCOUNTS, SCRATCH_EMBER_DEPOSIT_DATA};
use crate::error::SijkaError;
use crate::util::accounts::{expect_key, expect_program};

/// Ember accounts in CPI order (`cpi.rs` `EmberDeposit` / `EmberWithdraw`).
pub struct EmberAccounts<'a> {
    pub ember_program: &'a AccountInfo,
    /// `phx_authority` (Ember `trader`), signs via seeds.
    pub trader: &'a AccountInfo,
    pub ember_state: &'a AccountInfo,
    pub usdc_mint: &'a AccountInfo,
    /// PhUSD mint (writable: Ember mints/burns it).
    pub canonical_mint: &'a AccountInfo,
    /// `vault_usdc`.
    pub trader_usdc_account: &'a AccountInfo,
    /// `vault_phusd`.
    pub trader_phoenix_account: &'a AccountInfo,
    pub ember_vault: &'a AccountInfo,
    pub token_program: &'a AccountInfo,
}

impl EmberAccounts<'_> {
    /// Program ids the CPI is addressed to / relies on: Ember (key and
    /// executable) and SPL Token (key). Error `InvalidProgramId`.
    pub fn check_programs(&self) -> ProgramResult {
        expect_program(self.ember_program, &EMBER_PROGRAM_ID)?;
        expect_key(self.token_program, &SPL_TOKEN_PROGRAM_ID, SijkaError::InvalidProgramId)
    }
}

/// Ember `deposit{amount}` (USDC on `vault_usdc` → PhUSD on `vault_phusd`,
/// 1:1 today), tag 21. `signer` must be the `phx_authority` seeds.
#[inline(never)]
pub fn ember_deposit<'a>(acc: &EmberAccounts<'a>, amount: u64, signer: &[Signer]) -> ProgramResult {
    acc.check_programs()?;
    let w = ember::EmberDeposit {
        ember_program: acc.ember_program,
        trader: acc.trader,
        ember_state: acc.ember_state,
        usdc_mint: acc.usdc_mint,
        canonical_mint: acc.canonical_mint,
        trader_usdc_account: acc.trader_usdc_account,
        trader_phoenix_account: acc.trader_phoenix_account,
        ember_vault: acc.ember_vault,
        token_program: acc.token_program,
    };
    let mut scratch = CpiScratch::<'a, SCRATCH_EMBER_ACCOUNTS, SCRATCH_EMBER_DEPOSIT_DATA>::new(acc.trader);
    crate::cpi_tramp::ember_deposit(&w, ember::EmberDepositArgs { amount }, signer, &mut scratch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::test_utils::TestAccount;

    fn mk<'a>(ember: &'a AccountInfo, token: &'a AccountInfo, any: &'a AccountInfo) -> EmberAccounts<'a> {
        EmberAccounts {
            ember_program: ember,
            trader: any,
            ember_state: any,
            usdc_mint: any,
            canonical_mint: any,
            trader_usdc_account: any,
            trader_phoenix_account: any,
            ember_vault: any,
            token_program: token,
        }
    }

    #[test]
    fn wrong_programs_are_rejected_before_cpi() {
        let any = TestAccount::plain([1; 32], [2; 32], &[]);
        let ember_ok = TestAccount::new(EMBER_PROGRAM_ID, [3; 32], 1, &[], false, false, true);
        let ember_not_exec = TestAccount::new(EMBER_PROGRAM_ID, [3; 32], 1, &[], false, false, false);
        let token_ok = TestAccount::plain(SPL_TOKEN_PROGRAM_ID, [3; 32], &[]);
        let (a, e, ne, t) = (any.info(), ember_ok.info(), ember_not_exec.info(), token_ok.info());
        let bad = Err(SijkaError::InvalidProgramId.into());
        assert_eq!(ember_deposit(&mk(&a, &t, &a), 1, &[]), bad);
        assert_eq!(ember_deposit(&mk(&ne, &t, &a), 1, &[]), bad);
        assert_eq!(ember_deposit(&mk(&e, &a, &a), 1, &[]), bad);
        assert_eq!(mk(&e, &t, &a).check_programs(), Ok(()));
        // Host: the CPI itself is a no-op.
        assert_eq!(ember_deposit(&mk(&e, &t, &a), 1, &[]), Ok(()));
    }
}
