// Copyright (c) 2026 prt1sn. All rights reserved.
//! Account-level buyback helpers (SPEC §5.5.2): `burn_all`, `create_bb_unwrap`,
//! the tamper checks after the pump CPI (review RT-2) and small token-account
//! readers for our own accounts.

use pinocchio::ProgramResult;
use pinocchio::account_info::AccountInfo;
use pinocchio::instruction::Signer;
use pinocchio::program_error::ProgramError;
use pinocchio::pubkey::Pubkey;

use crate::constants::{
    SEED_BB_UNWRAP, SEED_BUYBACK_AUTHORITY, SPL_TOKEN_PROGRAM_ID, SYSTEM_PROGRAM_ID, TOKEN_ACCOUNT_LEN,
};
use crate::cpi::PdaSeeds;
use crate::cpi::system::create_pda_account;
use crate::cpi::token::{burn_checked, initialize_account3};
use crate::error::SijkaError;
use crate::external::layout::token_account as ta;
use crate::util::accounts::check_token;
use crate::util::bytes::read_u64;

/// `true` if the address holds no account data and belongs to System (an ATA
/// that was never created, or was closed). Lamports alone do not create it.
#[inline]
pub fn account_missing(ai: &AccountInfo) -> bool {
    ai.is_owned_by(&SYSTEM_PROGRAM_ID) && ai.data_len() == 0
}

/// `amount@64` of a token account that has already passed `check_token`.
pub fn token_amount_unchecked(ai: &AccountInfo) -> Result<u64, ProgramError> {
    let data = ai.try_borrow_data()?;
    if data.len() < TOKEN_ACCOUNT_LEN {
        return Err(SijkaError::InvalidTokenAccount.fail());
    }
    read_u64(&data, ta::AMOUNT).ok_or_else(|| SijkaError::InvalidTokenAccount.fail())
}

/// `buyback_authority` (k0) is a System account without data and is not
/// executable; else `e`. Checked before we sign with it and, as review RT-2
/// requires, right after the pump CPI (`BbAccountTampered`).
#[inline]
pub fn expect_authority_clean(k0: &AccountInfo, e: SijkaError) -> ProgramResult {
    if !k0.is_owned_by(&SYSTEM_PROGRAM_ID) || k0.data_len() != 0 || k0.executable() {
        return Err(e.fail());
    }
    Ok(())
}

/// State of `bb_quote` (k10) before the pump CPI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuoteSnap {
    pub existed: bool,
    pub amount: u64,
}

/// Our token accounts after the pump CPI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AfterPump {
    /// `buyback_token.amount`.
    pub base: u64,
    /// `bb_quote.amount` (0 if it does not exist).
    pub quote: u64,
}

/// Tamper checks right after the pump CPI (SPEC §5.5.2, review RT-2), before
/// any balance check and before `burn_all`; any failure is `BbAccountTampered`:
///
/// 1. k0: owner System, no data, not executable;
/// 2. k9 (`buyback_token`): full `check_token(k7, k6, k0)`;
/// 3. k10 (`bb_quote`): if it existed, it still exists and passes
///    `check_token(Tokenkeg, k8, k0, native)`, and on the SOL curve (where pump
///    does not spend it) its amount is unchanged; if it did not exist, it still
///    does not, or passes `check_token` with amount 0.
#[allow(clippy::too_many_arguments)]
pub fn check_after_pump(
    k0: &AccountInfo,
    bb_token: &AccountInfo,
    base_program: &Pubkey,
    mint: &Pubkey,
    bb_quote: &AccountInfo,
    quote_mint: &Pubkey,
    quote_native: bool,
    snap: QuoteSnap,
    quote_must_be_unchanged: bool,
) -> Result<AfterPump, ProgramError> {
    const E: SijkaError = SijkaError::BbAccountTampered;
    expect_authority_clean(k0, E)?;
    let base = check_token(bb_token, base_program, mint, k0.key(), false, E)?;
    let quote = if snap.existed {
        let q = check_token(bb_quote, &SPL_TOKEN_PROGRAM_ID, quote_mint, k0.key(), quote_native, E)?;
        if quote_must_be_unchanged && q != snap.amount {
            return Err(E.fail());
        }
        q
    } else if account_missing(bb_quote) {
        0
    } else {
        let q = check_token(bb_quote, &SPL_TOKEN_PROGRAM_ID, quote_mint, k0.key(), quote_native, E)?;
        if q != 0 {
            return Err(E.fail());
        }
        q
    };
    Ok(AfterPump { base, quote })
}

/// `burn_all()` (SPEC §5.5.2): burn the whole balance of `buyback_token` with
/// `burn_checked` signed by `buyback_authority`, then require a zero balance
/// (`BbBurnIncomplete`). Returns the amount burned (0: nothing to do, no CPI).
/// `bb_token` must already have passed `check_token(k7, k6, k0)`.
pub fn burn_all(
    token_program: &AccountInfo,
    bb_token: &AccountInfo,
    mint: &AccountInfo,
    authority: &AccountInfo,
    decimals: u8,
    authority_bump: u8,
) -> Result<u64, ProgramError> {
    let amount = token_amount_unchecked(bb_token)?;
    if amount == 0 {
        return Ok(0);
    }
    let pda = PdaSeeds::new(SEED_BUYBACK_AUTHORITY, authority_bump);
    let seeds = pda.seeds();
    let signer = [Signer::from(&seeds)];
    burn_checked(token_program, bb_token, mint, authority, amount, decimals, &signer)?;
    if token_amount_unchecked(bb_token)? != 0 {
        return Err(SijkaError::BbBurnIncomplete.fail());
    }
    Ok(amount)
}

/// `create_bb_unwrap()` (SPEC §5.5.2): create the temporary wSOL account
/// `bb_unwrap` (165 bytes, Tokenkeg) paid by `buyback_authority`, robust to
/// lamports sent to the address in advance (`create_pda_account`), then
/// `InitializeAccount3(bb_unwrap, WSOL, owner = swap_authority)`. An address
/// that already holds data or belongs to another program is
/// `BbUnwrapAccountBusy`.
#[allow(clippy::too_many_arguments)]
pub fn create_bb_unwrap(
    k0: &AccountInfo,
    bb_unwrap: &AccountInfo,
    native_mint: &AccountInfo,
    token_program: &AccountInfo,
    swap_authority: &Pubkey,
    k0_bump: u8,
    bb_unwrap_bump: u8,
) -> ProgramResult {
    let payer = PdaSeeds::new(SEED_BUYBACK_AUTHORITY, k0_bump);
    let target = PdaSeeds::new(SEED_BB_UNWRAP, bb_unwrap_bump);
    let ps = payer.seeds();
    let ts = target.seeds();
    let signers = [Signer::from(&ps), Signer::from(&ts)];
    create_pda_account(
        k0,
        bb_unwrap,
        TOKEN_ACCOUNT_LEN,
        &SPL_TOKEN_PROGRAM_ID,
        &signers,
        SijkaError::BbUnwrapAccountBusy,
    )?;
    initialize_account3(token_program, bb_unwrap, native_mint, swap_authority)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{TOKEN_2022_PROGRAM_ID, WSOL_MINT};
    use crate::external::pump_accounts::tests::token_bytes;
    use crate::util::test_utils::TestAccount;

    const K0: Pubkey = [0xB0; 32];
    const MINT: Pubkey = [6; 32];

    fn k0() -> TestAccount {
        TestAccount::new(K0, SYSTEM_PROGRAM_ID, 50_000_000, &[], false, true, false)
    }

    fn check(
        k0: &TestAccount,
        base: &TestAccount,
        quote: &TestAccount,
        snap: QuoteSnap,
        unchanged: bool,
    ) -> Result<AfterPump, ProgramError> {
        check_after_pump(
            &k0.info(),
            &base.info(),
            &TOKEN_2022_PROGRAM_ID,
            &MINT,
            &quote.info(),
            &WSOL_MINT,
            true,
            snap,
            unchanged,
        )
    }

    #[test]
    fn tamper_checks_after_pump() {
        let tampered = Err(SijkaError::BbAccountTampered.into());
        let a = k0();
        let base = TestAccount::new(
            [9; 32],
            TOKEN_2022_PROGRAM_ID,
            1,
            &token_bytes(&MINT, &K0, 77, false),
            false,
            true,
            false,
        );
        let quote = TestAccount::new(
            [10; 32],
            SPL_TOKEN_PROGRAM_ID,
            1,
            &token_bytes(&WSOL_MINT, &K0, 5, true),
            false,
            true,
            false,
        );
        let snap = QuoteSnap { existed: true, amount: 5 };
        assert_eq!(check(&a, &base, &quote, snap, true), Ok(AfterPump { base: 77, quote: 5 }));
        // SOL curve: bb_wsol must not change.
        assert_eq!(check(&a, &base, &quote, QuoteSnap { existed: true, amount: 6 }, true), tampered);
        assert!(check(&a, &base, &quote, QuoteSnap { existed: true, amount: 6 }, false).is_ok());
        // k0 assigned to another program or given data.
        let assigned = TestAccount::new(K0, [3; 32], 50_000_000, &[], false, true, false);
        assert_eq!(check(&assigned, &base, &quote, snap, true), tampered);
        let allocated = TestAccount::new(K0, SYSTEM_PROGRAM_ID, 50_000_000, &[0; 8], false, true, false);
        assert_eq!(check(&allocated, &base, &quote, snap, true), tampered);
        // Delegate / close authority / new owner on buyback_token.
        for (off, v) in [(72usize, 1u8), (129, 1), (32, 0x55)] {
            let mut d = token_bytes(&MINT, &K0, 77, false);
            d[off] = v;
            let t = TestAccount::new([9; 32], TOKEN_2022_PROGRAM_ID, 1, &d, false, true, false);
            assert_eq!(check(&a, &t, &quote, snap, true), tampered, "base offset {off}");
        }
        // Same on bb_quote, plus closing it.
        for (off, v) in [(72usize, 1u8), (129, 1), (32, 0x55), (108, 2)] {
            let mut d = token_bytes(&WSOL_MINT, &K0, 5, true);
            d[off] = v;
            let q = TestAccount::new([10; 32], SPL_TOKEN_PROGRAM_ID, 1, &d, false, true, false);
            assert_eq!(check(&a, &base, &q, snap, true), tampered, "quote offset {off}");
        }
        let closed = TestAccount::new([10; 32], SYSTEM_PROGRAM_ID, 0, &[], false, true, false);
        assert_eq!(check(&a, &base, &closed, snap, true), tampered);
        // Did not exist before: may stay missing, or appear empty and clean.
        let none = QuoteSnap { existed: false, amount: 0 };
        assert_eq!(check(&a, &base, &closed, none, true), Ok(AfterPump { base: 77, quote: 0 }));
        let appeared = TestAccount::new(
            [10; 32],
            SPL_TOKEN_PROGRAM_ID,
            1,
            &token_bytes(&WSOL_MINT, &K0, 0, true),
            false,
            true,
            false,
        );
        assert!(check(&a, &base, &appeared, none, true).is_ok());
        assert_eq!(check(&a, &base, &quote, none, false), tampered);
    }

    #[test]
    fn burn_all_zero_is_noop_and_nonzero_must_reach_zero() {
        let a = k0();
        let mint = TestAccount::new(MINT, TOKEN_2022_PROGRAM_ID, 1, &[0; 82], false, true, false);
        let tp = TestAccount::new(TOKEN_2022_PROGRAM_ID, [0; 32], 1, &[], false, false, true);
        let empty =
            TestAccount::new([9; 32], TOKEN_2022_PROGRAM_ID, 1, &token_bytes(&MINT, &K0, 0, false), false, true, false);
        assert_eq!(burn_all(&tp.info(), &empty.info(), &mint.info(), &a.info(), 6, 255), Ok(0));
        // On the host the CPI is a no-op, so a non-zero balance stays: BbBurnIncomplete.
        let full = TestAccount::new(
            [9; 32],
            TOKEN_2022_PROGRAM_ID,
            1,
            &token_bytes(&MINT, &K0, 10, false),
            false,
            true,
            false,
        );
        assert_eq!(
            burn_all(&tp.info(), &full.info(), &mint.info(), &a.info(), 6, 255),
            Err(SijkaError::BbBurnIncomplete.into())
        );
        // A non-token program is refused before any CPI.
        let bad = TestAccount::new([1; 32], [0; 32], 1, &[], false, false, true);
        assert_eq!(
            burn_all(&bad.info(), &full.info(), &mint.info(), &a.info(), 6, 255),
            Err(SijkaError::InvalidProgramId.into())
        );
    }

    #[test]
    fn bb_unwrap_busy_is_rejected() {
        let a = k0();
        let busy = TestAccount::new([2; 32], SPL_TOKEN_PROGRAM_ID, 2_039_280, &[0; 165], false, true, false);
        let mint = TestAccount::plain(WSOL_MINT, SPL_TOKEN_PROGRAM_ID, &[0; 82]);
        let tp = TestAccount::new(SPL_TOKEN_PROGRAM_ID, [0; 32], 1, &[], false, false, true);
        assert_eq!(
            create_bb_unwrap(&a.info(), &busy.info(), &mint.info(), &tp.info(), &[1; 32], 255, 254),
            Err(SijkaError::BbUnwrapAccountBusy.into())
        );
        assert!(account_missing(&a.info()));
        assert!(!account_missing(&busy.info()));
    }
}
