// Copyright (c) 2026 prt1sn. All rights reserved.
//! PDA and ATA derivation (SPEC §2.1, §2.2).
//!
//! On chain these use the runtime syscalls. On the host (unit tests) they use
//! `solana-pubkey`; host builds that are not tests return `InvalidPda` instead
//! of panicking (pinocchio's host stubs panic).
//!
//! `find` never panics: a missing bump is `InvalidPda`. Bumps are canonical
//! (`find_program_address`) and are stored in `Config` at `initialize`; later
//! instructions compare keys with `Config` instead of re-deriving.

use pinocchio::ProgramResult;
use pinocchio::account_info::AccountInfo;
use pinocchio::program_error::ProgramError;
use pinocchio::pubkey::{Pubkey, pubkey_eq};

use crate::constants::ATA_PROGRAM_ID;
use crate::error::SijkaError;

/// `find_program_address(seeds, program_id)`; `InvalidPda` if no bump exists.
pub fn find(seeds: &[&[u8]], program_id: &Pubkey) -> Result<(Pubkey, u8), ProgramError> {
    imp::try_find(seeds, program_id).ok_or_else(|| SijkaError::InvalidPda.fail())
}

/// `create_program_address(seeds, program_id)` (seeds include the bump);
/// `InvalidPda` if the seeds do not give a valid off-curve address.
pub fn create(seeds: &[&[u8]], program_id: &Pubkey) -> Result<Pubkey, ProgramError> {
    imp::create(seeds, program_id).ok_or_else(|| SijkaError::InvalidPda.fail())
}

/// Canonical associated token account of `(owner, token_program, mint)`.
pub fn find_ata(owner: &Pubkey, token_program: &Pubkey, mint: &Pubkey) -> Result<Pubkey, ProgramError> {
    find(&[owner, token_program, mint], &ATA_PROGRAM_ID).map(|(k, _)| k)
}

/// `ai.key() == create_program_address(seeds, program_id)`, else `e`.
pub fn expect_pda(ai: &AccountInfo, seeds: &[&[u8]], program_id: &Pubkey, e: SijkaError) -> ProgramResult {
    match imp::create(seeds, program_id) {
        Some(k) if pubkey_eq(&k, ai.key()) => Ok(()),
        _ => Err(e.fail()),
    }
}

/// `ai.key()` is the canonical ATA of `(owner, token_program, mint)`, else `e`.
pub fn expect_ata(
    ai: &AccountInfo,
    owner: &Pubkey,
    token_program: &Pubkey,
    mint: &Pubkey,
    e: SijkaError,
) -> ProgramResult {
    match imp::try_find(&[owner, token_program, mint], &ATA_PROGRAM_ID) {
        Some((k, _)) if pubkey_eq(&k, ai.key()) => Ok(()),
        _ => Err(e.fail()),
    }
}

#[cfg(target_os = "solana")]
mod imp {
    use pinocchio::pubkey::Pubkey;

    #[inline(always)]
    pub fn try_find(seeds: &[&[u8]], program_id: &Pubkey) -> Option<(Pubkey, u8)> {
        pinocchio::pubkey::try_find_program_address(seeds, program_id)
    }

    #[inline(always)]
    pub fn create(seeds: &[&[u8]], program_id: &Pubkey) -> Option<Pubkey> {
        pinocchio::pubkey::checked_create_program_address(seeds, program_id).ok()
    }
}

#[cfg(all(not(target_os = "solana"), test))]
mod imp {
    use pinocchio::pubkey::Pubkey;
    use solana_pubkey::Pubkey as SPubkey;

    pub fn try_find(seeds: &[&[u8]], program_id: &Pubkey) -> Option<(Pubkey, u8)> {
        SPubkey::try_find_program_address(seeds, &SPubkey::new_from_array(*program_id)).map(|(k, b)| (k.to_bytes(), b))
    }

    pub fn create(seeds: &[&[u8]], program_id: &Pubkey) -> Option<Pubkey> {
        SPubkey::create_program_address(seeds, &SPubkey::new_from_array(*program_id)).ok().map(|k| k.to_bytes())
    }
}

#[cfg(all(not(target_os = "solana"), not(test)))]
mod imp {
    use pinocchio::pubkey::Pubkey;

    pub fn try_find(_seeds: &[&[u8]], _program_id: &Pubkey) -> Option<(Pubkey, u8)> {
        None
    }

    pub fn create(_seeds: &[&[u8]], _program_id: &Pubkey) -> Option<Pubkey> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::*;
    use crate::util::test_utils::TestAccount;

    #[test]
    fn find_and_create_agree() {
        let program = [42u8; 32];
        let (k, bump) = find(&[SEED_CONFIG], &program).unwrap();
        assert_eq!(create(&[SEED_CONFIG, &[bump]], &program).unwrap(), k);
        let a = TestAccount::new(k, program, 0, &[], false, false, false);
        assert!(expect_pda(&a.info(), &[SEED_CONFIG, &[bump]], &program, SijkaError::InvalidPda).is_ok());
        assert!(expect_pda(&a.info(), &[SEED_BUYBACK_STATE, &[bump]], &program, SijkaError::InvalidPda).is_err());
    }

    #[test]
    fn phoenix_trader_seed_forms_agree() {
        // SPEC §2.1: ["trader", A, [0, 0]] and ["trader", A, [0], [0]] give the same address.
        let a = [5u8; 32];
        let (k1, b1) = find(&[SEED_PHOENIX_TRADER, &a, &[0, 0]], &PHOENIX_PROGRAM_ID).unwrap();
        let (k2, b2) = find(&[SEED_PHOENIX_TRADER, &a, &[0], &[0]], &PHOENIX_PROGRAM_ID).unwrap();
        assert_eq!((k1, b1), (k2, b2));
    }

    #[test]
    fn ata_matches_known_derivation() {
        let owner = [3u8; 32];
        let k = find_ata(&owner, &SPL_TOKEN_PROGRAM_ID, &WSOL_MINT).unwrap();
        let (expected, _) = solana_pubkey::Pubkey::find_program_address(
            &[&owner, &SPL_TOKEN_PROGRAM_ID, &WSOL_MINT],
            &solana_pubkey::Pubkey::new_from_array(ATA_PROGRAM_ID),
        );
        assert_eq!(k, expected.to_bytes());
        let a = TestAccount::new(k, SPL_TOKEN_PROGRAM_ID, 0, &[], false, false, false);
        assert!(expect_ata(&a.info(), &owner, &SPL_TOKEN_PROGRAM_ID, &WSOL_MINT, SijkaError::InvalidPda).is_ok());
        assert!(expect_ata(&a.info(), &owner, &TOKEN_2022_PROGRAM_ID, &WSOL_MINT, SijkaError::InvalidPda).is_err());
    }
}
