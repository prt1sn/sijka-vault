// Copyright (c) 2026 prt1sn. All rights reserved.
//! Account validation helpers (SPEC §5.0.3, §3.9 `check_token`).
//!
//! Every helper logs `Sijka: <Name>` and returns the program error on failure
//! (fail closed). Callers pass the SPEC error for the slot being checked.

use pinocchio::ProgramResult;
use pinocchio::account_info::AccountInfo;
use pinocchio::program_error::ProgramError;
use pinocchio::pubkey::{Pubkey, pubkey_eq};

use crate::constants::{SPL_TOKEN_PROGRAM_ID, SYSTEM_PROGRAM_ID, TOKEN_2022_PROGRAM_ID, TOKEN_ACCOUNT_LEN};
use crate::error::SijkaError;
use crate::external::layout::token_account as ta;
use crate::util::bytes::{read_key, read_u8, read_u32, read_u64};

/// `accounts.len() == n` exactly (SPEC §5.0.3: extra accounts are rejected).
#[inline]
pub fn expect_account_count(accounts: &[AccountInfo], n: usize) -> ProgramResult {
    if accounts.len() != n {
        return Err(SijkaError::InvalidAccountCount.fail());
    }
    Ok(())
}

/// `ai.key() == key`, else `e`.
#[inline]
pub fn expect_key(ai: &AccountInfo, key: &Pubkey, e: SijkaError) -> ProgramResult {
    if !pubkey_eq(ai.key(), key) {
        return Err(e.fail());
    }
    Ok(())
}

/// `ai.owner() == owner`, else `e`.
#[inline]
pub fn expect_owner(ai: &AccountInfo, owner: &Pubkey, e: SijkaError) -> ProgramResult {
    if !ai.is_owned_by(owner) {
        return Err(e.fail());
    }
    Ok(())
}

/// `ai.is_signer()`, else `e`.
#[inline]
pub fn expect_signer(ai: &AccountInfo, e: SijkaError) -> ProgramResult {
    if !ai.is_signer() {
        return Err(e.fail());
    }
    Ok(())
}

/// `ai.is_writable()`, else `AccountNotWritable`.
#[inline]
pub fn expect_writable(ai: &AccountInfo) -> ProgramResult {
    if !ai.is_writable() {
        return Err(SijkaError::AccountNotWritable.fail());
    }
    Ok(())
}

/// `!ai.is_writable()`, else `AccountMustBeReadonly`.
#[inline]
pub fn expect_readonly(ai: &AccountInfo) -> ProgramResult {
    if ai.is_writable() {
        return Err(SijkaError::AccountMustBeReadonly.fail());
    }
    Ok(())
}

/// External program slot: key and `executable` (SPEC §5.0.3), else `InvalidProgramId`.
#[inline]
pub fn expect_program(ai: &AccountInfo, id: &Pubkey) -> ProgramResult {
    if !pubkey_eq(ai.key(), id) || !ai.executable() {
        return Err(SijkaError::InvalidProgramId.fail());
    }
    Ok(())
}

/// System-owned account without data (our data-less PDAs: `fee_inbox`,
/// `swap_authority`, `buyback_authority`, `rent_payer`, `creator_escrow`), else `e`.
#[inline]
pub fn expect_system_empty(ai: &AccountInfo, e: SijkaError) -> ProgramResult {
    if !ai.is_owned_by(&SYSTEM_PROGRAM_ID) || ai.data_len() != 0 {
        return Err(e.fail());
    }
    Ok(())
}

/// No two keys in `keys` are equal (aliasing guard for slots whose keys are
/// not individually pinned), else `e`. O(n²); intended for small n.
pub fn expect_distinct(keys: &[&Pubkey], e: SijkaError) -> ProgramResult {
    for (i, a) in keys.iter().enumerate() {
        for b in keys.iter().skip(i.saturating_add(1)) {
            if pubkey_eq(a, b) {
                return Err(e.fail());
            }
        }
    }
    Ok(())
}

/// `key` is not one of `protected`, else `e`.
pub fn expect_not_in(key: &Pubkey, protected: &[&Pubkey], e: SijkaError) -> ProgramResult {
    if protected.iter().any(|p| pubkey_eq(p, key)) {
        return Err(e.fail());
    }
    Ok(())
}

/// Checks of an SPL Token / Token-2022 account per SPEC §3.9 `check_token`:
/// owner is `program`, length 165 (Token-2022: at least 165), `mint`,
/// `authority` (field `owner@32`), no delegate, state Initialized, no close
/// authority, and `is_native` set exactly when `native`. Returns `amount`.
///
/// The account data is borrowed only inside this call.
pub fn check_token(
    ai: &AccountInfo,
    program: &Pubkey,
    mint: &Pubkey,
    authority: &Pubkey,
    native: bool,
    e: SijkaError,
) -> Result<u64, ProgramError> {
    if !ai.is_owned_by(program) {
        return Err(e.fail());
    }
    let len_ok = if pubkey_eq(program, &TOKEN_2022_PROGRAM_ID) {
        ai.data_len() >= TOKEN_ACCOUNT_LEN
    } else if pubkey_eq(program, &SPL_TOKEN_PROGRAM_ID) {
        ai.data_len() == TOKEN_ACCOUNT_LEN
    } else {
        false
    };
    if !len_ok {
        return Err(e.fail());
    }
    let data = ai.try_borrow_data()?;
    token_account_fields_ok(&data, mint, Some(authority), native, true).ok_or_else(|| e.fail())
}

/// Weaker read for accounts owned by someone else (pool / curve vaults,
/// SPEC §5.5.2 `read_token_account`): owner program, length ≥ 165, mint,
/// optional authority, state Initialized. Delegate and close authority are not
/// checked. Returns `amount`.
pub fn read_token_account(
    ai: &AccountInfo,
    program: &Pubkey,
    mint: &Pubkey,
    authority: Option<&Pubkey>,
    e: SijkaError,
) -> Result<u64, ProgramError> {
    if !ai.is_owned_by(program) || ai.data_len() < TOKEN_ACCOUNT_LEN {
        return Err(e.fail());
    }
    let data = ai.try_borrow_data()?;
    let mint_ok = read_key(&data, ta::MINT).is_some_and(|m| pubkey_eq(m, mint));
    let auth_ok = match authority {
        Some(a) => read_key(&data, ta::OWNER).is_some_and(|o| pubkey_eq(o, a)),
        None => true,
    };
    let state_ok = read_u8(&data, ta::STATE) == Some(ta::STATE_INITIALIZED);
    match (mint_ok && auth_ok && state_ok, read_u64(&data, ta::AMOUNT)) {
        (true, Some(amount)) => Ok(amount),
        _ => Err(e.fail()),
    }
}

/// Pure check of token-account bytes (used by [`check_token`] and by tests).
/// `strict` adds the delegate / close-authority / native checks.
pub fn token_account_fields_ok(
    data: &[u8],
    mint: &Pubkey,
    authority: Option<&Pubkey>,
    native: bool,
    strict: bool,
) -> Option<u64> {
    if data.len() < TOKEN_ACCOUNT_LEN {
        return None;
    }
    if !pubkey_eq(read_key(data, ta::MINT)?, mint) {
        return None;
    }
    if let Some(a) = authority
        && !pubkey_eq(read_key(data, ta::OWNER)?, a)
    {
        return None;
    }
    if read_u8(data, ta::STATE)? != ta::STATE_INITIALIZED {
        return None;
    }
    if strict {
        if read_u32(data, ta::DELEGATE_TAG)? != 0 {
            return None;
        }
        if read_u32(data, ta::CLOSE_AUTHORITY_TAG)? != 0 {
            return None;
        }
        let native_tag = read_u32(data, ta::IS_NATIVE_TAG)?;
        if native_tag != u32::from(native) {
            return None;
        }
    }
    read_u64(data, ta::AMOUNT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::WSOL_MINT;
    use crate::util::test_utils::TestAccount;

    fn token_bytes(mint: &Pubkey, owner: &Pubkey, amount: u64, native: bool) -> Vec<u8> {
        let mut d = vec![0u8; TOKEN_ACCOUNT_LEN];
        d[0..32].copy_from_slice(mint);
        d[32..64].copy_from_slice(owner);
        d[64..72].copy_from_slice(&amount.to_le_bytes());
        d[108] = 1;
        if native {
            d[109..113].copy_from_slice(&1u32.to_le_bytes());
        }
        d
    }

    #[test]
    fn key_owner_signer_writable() {
        let a = TestAccount::new([1; 32], [2; 32], 5, &[], true, false, false);
        let ai = a.info();
        assert!(expect_key(&ai, &[1; 32], SijkaError::InvalidPda).is_ok());
        assert_eq!(expect_key(&ai, &[3; 32], SijkaError::InvalidPda), Err(SijkaError::InvalidPda.into()));
        assert!(expect_owner(&ai, &[2; 32], SijkaError::InvalidExternalAccount).is_ok());
        assert!(expect_owner(&ai, &[1; 32], SijkaError::InvalidExternalAccount).is_err());
        assert!(expect_signer(&ai, SijkaError::Unauthorized).is_ok());
        assert_eq!(expect_writable(&ai), Err(SijkaError::AccountNotWritable.into()));
        assert!(expect_readonly(&ai).is_ok());
        assert_eq!(expect_program(&ai, &[1; 32]), Err(SijkaError::InvalidProgramId.into()));
        let p = TestAccount::new([1; 32], [2; 32], 5, &[], false, false, true);
        assert!(expect_program(&p.info(), &[1; 32]).is_ok());
    }

    #[test]
    fn system_empty_and_distinct() {
        let s = TestAccount::new([1; 32], SYSTEM_PROGRAM_ID, 5, &[], false, true, false);
        assert!(expect_system_empty(&s.info(), SijkaError::InvalidExternalAccount).is_ok());
        let d = TestAccount::new([1; 32], SYSTEM_PROGRAM_ID, 5, &[0], false, true, false);
        assert!(expect_system_empty(&d.info(), SijkaError::InvalidExternalAccount).is_err());
        assert!(expect_distinct(&[&[1; 32], &[2; 32], &[3; 32]], SijkaError::InvalidExternalAccount).is_ok());
        assert!(expect_distinct(&[&[1; 32], &[2; 32], &[1; 32]], SijkaError::InvalidExternalAccount).is_err());
        assert!(expect_not_in(&[1; 32], &[&[2; 32]], SijkaError::JupiterAccountForbidden).is_ok());
        assert!(expect_not_in(&[2; 32], &[&[2; 32]], SijkaError::JupiterAccountForbidden).is_err());
    }

    #[test]
    fn check_token_rules() {
        let mint = [7u8; 32];
        let auth = [8u8; 32];
        let good = token_bytes(&mint, &auth, 42, false);
        let a = TestAccount::new([1; 32], SPL_TOKEN_PROGRAM_ID, 1, &good, false, true, false);
        assert_eq!(
            check_token(&a.info(), &SPL_TOKEN_PROGRAM_ID, &mint, &auth, false, SijkaError::InvalidTokenAccount),
            Ok(42)
        );
        // Wrong program, native flag, delegate, close authority, frozen, wrong length.
        assert!(
            check_token(&a.info(), &TOKEN_2022_PROGRAM_ID, &mint, &auth, false, SijkaError::InvalidTokenAccount)
                .is_err()
        );
        assert!(
            check_token(&a.info(), &SPL_TOKEN_PROGRAM_ID, &mint, &auth, true, SijkaError::InvalidTokenAccount).is_err()
        );
        let mut d = good.clone();
        d[72] = 1;
        assert!(token_account_fields_ok(&d, &mint, Some(&auth), false, true).is_none());
        assert!(token_account_fields_ok(&d, &mint, Some(&auth), false, false).is_some());
        let mut d = good.clone();
        d[129] = 1;
        assert!(token_account_fields_ok(&d, &mint, Some(&auth), false, true).is_none());
        let mut d = good.clone();
        d[108] = 2;
        assert!(token_account_fields_ok(&d, &mint, Some(&auth), false, false).is_none());
        let long = [good.clone(), vec![0u8; 10]].concat();
        let l = TestAccount::new([1; 32], SPL_TOKEN_PROGRAM_ID, 1, &long, false, true, false);
        assert!(
            check_token(&l.info(), &SPL_TOKEN_PROGRAM_ID, &mint, &auth, false, SijkaError::InvalidTokenAccount)
                .is_err()
        );
        let t22 = TestAccount::new([1; 32], TOKEN_2022_PROGRAM_ID, 1, &long, false, true, false);
        assert_eq!(
            check_token(&t22.info(), &TOKEN_2022_PROGRAM_ID, &mint, &auth, false, SijkaError::InvalidTokenAccount),
            Ok(42)
        );
        let wsol = token_bytes(&WSOL_MINT, &auth, 9, true);
        let w = TestAccount::new([1; 32], SPL_TOKEN_PROGRAM_ID, 1, &wsol, false, true, false);
        assert_eq!(
            check_token(&w.info(), &SPL_TOKEN_PROGRAM_ID, &WSOL_MINT, &auth, true, SijkaError::InvalidTokenAccount),
            Ok(9)
        );
        assert_eq!(
            read_token_account(&a.info(), &SPL_TOKEN_PROGRAM_ID, &mint, None, SijkaError::BbBadPumpAccount),
            Ok(42)
        );
    }
}
