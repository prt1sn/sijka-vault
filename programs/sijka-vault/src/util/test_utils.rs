// Copyright (c) 2026 prt1sn. All rights reserved.
//! Host-only test helper: builds a real `pinocchio::account_info::AccountInfo`
//! over a heap buffer laid out like the runtime input (pinocchio 0.9 `Account`
//! header followed by the data), so handlers and validators can be unit-tested
//! without the SBF runtime.
//!
//! Only compiled for `cfg(test)`. Uses `unsafe` to create the `AccountInfo`
//! from a raw pointer, because pinocchio does not expose a constructor; the
//! layout is asserted by the tests below.

#![allow(unsafe_code)]

use pinocchio::account_info::AccountInfo;
use pinocchio::pubkey::Pubkey;

/// Size of pinocchio 0.9's `Account` header: borrow_state, is_signer,
/// is_writable, executable (u8 each), resize_delta (i32), key, owner,
/// lamports (u64), data_len (u64).
const HEADER_LEN: usize = 88;
/// Slack after the data (the runtime reserves 10 KiB for reallocs; tests never
/// resize, a little room keeps accidental reads in bounds).
const TAIL_LEN: usize = 64;
/// "Not borrowed" marker (all borrow bits available).
const NOT_BORROWED: u8 = 0xFF;

/// Owns the backing memory of one test account. Keep it alive while the
/// `AccountInfo` from [`TestAccount::info`] is used.
pub struct TestAccount {
    buf: Vec<u64>,
}

impl TestAccount {
    pub fn new(
        key: Pubkey,
        owner: Pubkey,
        lamports: u64,
        data: &[u8],
        is_signer: bool,
        is_writable: bool,
        executable: bool,
    ) -> Self {
        let bytes = HEADER_LEN + data.len() + TAIL_LEN;
        let mut buf = vec![0u64; bytes.div_ceil(8)];
        {
            let b = Self::bytes_of(&mut buf);
            b[0] = NOT_BORROWED;
            b[1] = u8::from(is_signer);
            b[2] = u8::from(is_writable);
            b[3] = u8::from(executable);
            b[8..40].copy_from_slice(&key);
            b[40..72].copy_from_slice(&owner);
            b[72..80].copy_from_slice(&lamports.to_le_bytes());
            b[80..88].copy_from_slice(&(data.len() as u64).to_le_bytes());
            b[HEADER_LEN..HEADER_LEN + data.len()].copy_from_slice(data);
        }
        Self { buf }
    }

    /// Plain read-only, non-signer account.
    pub fn plain(key: Pubkey, owner: Pubkey, data: &[u8]) -> Self {
        Self::new(key, owner, 1_000_000, data, false, false, false)
    }

    fn bytes_of(buf: &mut [u64]) -> &mut [u8] {
        let len = buf.len() * 8;
        // SAFETY: reinterpreting an owned, initialized u64 buffer as bytes.
        unsafe { core::slice::from_raw_parts_mut(buf.as_mut_ptr().cast::<u8>(), len) }
    }

    /// The `AccountInfo` view. Valid while `self` is alive and not moved.
    pub fn info(&self) -> AccountInfo {
        let ptr = self.buf.as_ptr().cast_mut().cast::<u8>();
        // SAFETY: `AccountInfo` is `#[repr(C)]` with a single `*mut Account`
        // field; `ptr` points to an 8-aligned buffer holding a valid `Account`
        // header followed by `data_len` bytes of data.
        unsafe { core::mem::transmute::<*mut u8, AccountInfo>(ptr) }
    }

    /// Data bytes (for editing between calls).
    pub fn data_mut(&mut self) -> &mut [u8] {
        let len = u64::from_le_bytes(Self::bytes_of(&mut self.buf)[80..88].try_into().unwrap()) as usize;
        &mut Self::bytes_of(&mut self.buf)[HEADER_LEN..HEADER_LEN + len]
    }
}

/// Build `n` dummy accounts (distinct keys, owned by the system program).
pub fn dummy_accounts(n: usize) -> Vec<TestAccount> {
    (0..n)
        .map(|i| {
            let mut key = [0u8; 32];
            key[0] = 0xA0;
            key[1..9].copy_from_slice(&(i as u64).to_le_bytes());
            TestAccount::plain(key, crate::constants::SYSTEM_PROGRAM_ID, &[])
        })
        .collect()
}

/// `AccountInfo`s of a slice of test accounts.
pub fn infos(accounts: &[TestAccount]) -> Vec<AccountInfo> {
    accounts.iter().map(TestAccount::info).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_layout_matches_pinocchio() {
        assert_eq!(core::mem::size_of::<AccountInfo>(), core::mem::size_of::<*mut u8>());
        let mut a = TestAccount::new([1; 32], [2; 32], 77, &[5, 6, 7], true, true, true);
        {
            let ai = a.info();
            assert_eq!(ai.key(), &[1; 32]);
            assert_eq!(ai.owner(), &[2; 32]);
            assert_eq!(ai.lamports(), 77);
            assert_eq!(ai.data_len(), 3);
            assert!(ai.is_signer() && ai.is_writable() && ai.executable());
            assert_eq!(&*ai.try_borrow_data().unwrap(), &[5, 6, 7]);
            ai.try_borrow_mut_data().unwrap()[0] = 9;
        }
        assert_eq!(a.data_mut(), &[9, 6, 7]);
        let b = TestAccount::plain([3; 32], [4; 32], &[]);
        let bi = b.info();
        assert!(!bi.is_signer() && !bi.is_writable() && !bi.executable());
        assert!(bi.data_is_empty());
    }
}
