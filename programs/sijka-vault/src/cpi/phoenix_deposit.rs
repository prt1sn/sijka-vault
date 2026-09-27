// Copyright (c) 2026 prt1sn. All rights reserved.
//! Phoenix `deposit_funds` (SPEC §5.3.5 step 6): typed
//! `phoenix_rise::cpi::phoenix::PhoenixDeposit` with `permission_account: None`
//! through `crate::cpi_tramp::phx_deposit` (`CpiScratch<24, 16>`), signed by
//! `phx_authority`.
//!
//! The wrapper fixes the flags (`cpi.rs:1170-1203`): `global_config` W,
//! `trader` (= `phx_authority`) S, `trader_token_account` (= `vault_phusd`) W,
//! `trader_account` W, `global_vault` W, every GTI / ATB arena W. The caller
//! validates every account (SPEC §5.0.5); this module re-checks the program
//! ids and the arena counts (`1..=MAX_GTI`, `1..=MAX_ATB`).

use phoenix_rise::cpi::{CpiScratch, phoenix};
use pinocchio::ProgramResult;
use pinocchio::account_info::AccountInfo;
use pinocchio::instruction::Signer;

use crate::constants::{MAX_ATB, MAX_GTI, PHOENIX_PROGRAM_ID, SPL_TOKEN_PROGRAM_ID};
use crate::cpi_tramp::{SCRATCH_DEPOSIT_ACCOUNTS, SCRATCH_DEPOSIT_DATA};
use crate::error::SijkaError;
use crate::util::accounts::{expect_key, expect_program};

/// Accounts of `deposit_funds` in CPI order (`cpi.rs:1170-1203`).
pub struct DepositAccounts<'a> {
    pub phoenix_program: &'a AccountInfo,
    pub log_authority: &'a AccountInfo,
    pub global_config: &'a AccountInfo,
    /// `phx_authority`, signs via seeds.
    pub trader: &'a AccountInfo,
    /// `vault_phusd`.
    pub trader_token_account: &'a AccountInfo,
    pub trader_account: &'a AccountInfo,
    pub global_vault: &'a AccountInfo,
    pub token_program: &'a AccountInfo,
    pub gti: &'a [AccountInfo],
    pub atb: &'a [AccountInfo],
}

/// `deposit_funds{amount}` of PhUSD from `vault_phusd` to the trader.
/// `signer` must be the `phx_authority` seeds.
#[inline(never)]
pub fn deposit_funds<'a>(acc: &DepositAccounts<'a>, amount: u64, signer: &[Signer]) -> ProgramResult {
    expect_program(acc.phoenix_program, &PHOENIX_PROGRAM_ID)?;
    expect_key(acc.token_program, &SPL_TOKEN_PROGRAM_ID, SijkaError::InvalidProgramId)?;
    if !(1..=MAX_GTI).contains(&acc.gti.len()) || !(1..=MAX_ATB).contains(&acc.atb.len()) {
        return Err(SijkaError::InvalidArenaAccounts.fail());
    }
    let w = phoenix::PhoenixDeposit {
        phoenix_program: acc.phoenix_program,
        log_authority: acc.log_authority,
        global_config: acc.global_config,
        trader: acc.trader,
        trader_token_account: acc.trader_token_account,
        trader_account: acc.trader_account,
        global_vault: acc.global_vault,
        token_program: acc.token_program,
        global_trader_index: acc.gti,
        active_trader_buffer: acc.atb,
        permission_account: None,
    };
    let mut scratch = CpiScratch::<'a, SCRATCH_DEPOSIT_ACCOUNTS, SCRATCH_DEPOSIT_DATA>::new(acc.trader);
    crate::cpi_tramp::phx_deposit(&w, phoenix::PhoenixDepositArgs { amount }, signer, &mut scratch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::test_utils::{TestAccount, dummy_accounts, infos};

    fn mk<'a>(
        program: &'a AccountInfo,
        token_program: &'a AccountInfo,
        other: &'a AccountInfo,
        arenas: &'a [AccountInfo],
        g: usize,
        a: usize,
    ) -> DepositAccounts<'a> {
        DepositAccounts {
            phoenix_program: program,
            log_authority: other,
            global_config: other,
            trader: other,
            trader_token_account: other,
            trader_account: other,
            global_vault: other,
            token_program,
            gti: &arenas[..g],
            atb: &arenas[g..g + a],
        }
    }

    #[test]
    fn checks_before_cpi() {
        let phx = TestAccount::new(PHOENIX_PROGRAM_ID, [3; 32], 1, &[], false, false, true);
        let not_exec = TestAccount::new(PHOENIX_PROGRAM_ID, [3; 32], 1, &[], false, false, false);
        let token = TestAccount::plain(SPL_TOKEN_PROGRAM_ID, [3; 32], &[]);
        let other = TestAccount::plain([7; 32], [3; 32], &[]);
        let pool = dummy_accounts(20);
        let arenas = infos(&pool);
        let (p, ne, t, o) = (phx.info(), not_exec.info(), token.info(), other.info());
        assert_eq!(deposit_funds(&mk(&ne, &t, &o, &arenas, 1, 1), 1, &[]), Err(SijkaError::InvalidProgramId.into()));
        assert_eq!(deposit_funds(&mk(&p, &o, &o, &arenas, 1, 1), 1, &[]), Err(SijkaError::InvalidProgramId.into()));
        assert_eq!(deposit_funds(&mk(&p, &t, &o, &arenas, 0, 1), 1, &[]), Err(SijkaError::InvalidArenaAccounts.into()));
        assert_eq!(deposit_funds(&mk(&p, &t, &o, &arenas, 1, 9), 1, &[]), Err(SijkaError::InvalidArenaAccounts.into()));
        // Host: the CPI itself is a no-op, so a well-formed call returns Ok.
        assert_eq!(deposit_funds(&mk(&p, &t, &o, &arenas, 8, 8), 1, &[]), Ok(()));
    }
}
