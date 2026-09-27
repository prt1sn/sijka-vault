// Copyright (c) 2026 prt1sn. All rights reserved.
//! Phoenix `withdraw_funds` and Ember `withdraw` (SPEC §5.4.2 steps 12 and 14;
//! also used by tag 51 op 1/6 and op 4), plus the Ember account checks of
//! SPEC §5.0.5 shared by every Ember caller.
//!
//! - `withdraw_funds`: typed `phoenix::PhoenixWithdraw` through
//!   `crate::cpi_tramp::phx_withdraw` (`CpiScratch<26, 16>`, `10 + g + a`
//!   accounts). The wrapper hard-codes the metas: `[phoenix, log, gc W,
//!   phx_authority S, trader W, pam W, global_vault W, vault_phusd W,
//!   token_program, GTI… W, ATB… W, withdraw_queue W]`, data
//!   `f1241d6fd01f68d9 ‖ u64 amount`. The destination is whatever the caller
//!   passes as `trader_token_account`; callers pass only `vault_phusd`
//!   (checked against `Config`).
//! - Ember `withdraw`: typed `ember::EmberWithdraw` with `Some(amount)` (never
//!   `None`: that would also unwrap PhUSD donated to `vault_phusd`) through
//!   `crate::cpi_tramp::ember_withdraw` (`CpiScratch<8, 17>`), data
//!   `b712469c946da122 ‖ 01 ‖ u64 amount`.
//!
//! Both are `#[inline(never)]` so that the scratch buffers live in their own
//! frame, not in the calling handler's (SPEC §5.0.6, review CPI-2). The
//! caller releases every borrow of the passed accounts first and verifies the
//! token deltas afterwards (the CPI result alone proves nothing about amounts).

use phoenix_rise::cpi::{CpiScratch, ember, phoenix};
use pinocchio::ProgramResult;
use pinocchio::account_info::AccountInfo;
use pinocchio::instruction::Signer;
use pinocchio::pubkey::{Pubkey, pubkey_eq};

use crate::constants::{DISC_EMBER_STATE, EMBER_PROGRAM_ID, EMBER_STATE, EMBER_VAULT, PHOENIX_PROGRAM_ID};
use crate::cpi::ember::EmberAccounts;
use crate::cpi_tramp::{
    SCRATCH_EMBER_ACCOUNTS, SCRATCH_EMBER_WITHDRAW_DATA, SCRATCH_WITHDRAW_ACCOUNTS, SCRATCH_WITHDRAW_DATA,
};
use crate::error::SijkaError;
use crate::external::layout::ember_state as esl;
use crate::util::accounts::{expect_key, expect_owner, expect_writable};
use crate::util::bytes::{array_ref, read_key};

/// Accounts of `withdraw_funds` in CPI order (`cpi.rs:1280-1310`):
/// `[phoenix, log, gc W, phx_authority S, trader W, pam W, global_vault W,
/// vault_phusd W, token_program, GTI… W, ATB… W, withdraw_queue W]`.
pub struct WithdrawAccounts<'a> {
    pub phoenix_program: &'a AccountInfo,
    pub log_authority: &'a AccountInfo,
    pub global_config: &'a AccountInfo,
    /// `phx_authority`, signs via seeds.
    pub trader: &'a AccountInfo,
    pub trader_account: &'a AccountInfo,
    pub perp_asset_map: &'a AccountInfo,
    pub global_vault: &'a AccountInfo,
    /// `vault_phusd`.
    pub trader_token_account: &'a AccountInfo,
    pub token_program: &'a AccountInfo,
    pub gti: &'a [AccountInfo],
    pub atb: &'a [AccountInfo],
    pub withdraw_queue: &'a AccountInfo,
}

impl<'a> WithdrawAccounts<'a> {
    /// The typed wrapper over the same accounts.
    #[inline(always)]
    fn wrapper(&self) -> phoenix::PhoenixWithdraw<'a> {
        phoenix::PhoenixWithdraw {
            phoenix_program: self.phoenix_program,
            log_authority: self.log_authority,
            global_config: self.global_config,
            trader: self.trader,
            trader_account: self.trader_account,
            perp_asset_map: self.perp_asset_map,
            global_vault: self.global_vault,
            trader_token_account: self.trader_token_account,
            token_program: self.token_program,
            global_trader_index: self.gti,
            active_trader_buffer: self.atb,
            withdraw_queue: self.withdraw_queue,
        }
    }
}

/// Phoenix `withdraw_funds{amount}` to `acc.trader_token_account`
/// (`vault_phusd`), signed by `phx_authority` through `signer`. A zero amount
/// is a caller bug (`InvariantViolated`); the SDK wrapper would reject it too.
#[inline(never)]
pub fn withdraw_funds<'a>(acc: &WithdrawAccounts<'a>, amount: u64, signer: &[Signer]) -> ProgramResult {
    if amount == 0 {
        return Err(SijkaError::InvariantViolated.fail());
    }
    let w = acc.wrapper();
    let mut scratch = CpiScratch::<'a, SCRATCH_WITHDRAW_ACCOUNTS, SCRATCH_WITHDRAW_DATA>::new(acc.phoenix_program);
    crate::cpi_tramp::phx_withdraw(&w, phoenix::PhoenixWithdrawArgs { amount }, signer, &mut scratch)
}

/// The typed Ember withdraw wrapper over `acc`.
#[inline(always)]
fn ember_withdraw_wrapper<'a>(acc: &EmberAccounts<'a>) -> ember::EmberWithdraw<'a> {
    ember::EmberWithdraw {
        ember_program: acc.ember_program,
        trader: acc.trader,
        ember_state: acc.ember_state,
        usdc_mint: acc.usdc_mint,
        canonical_mint: acc.canonical_mint,
        trader_usdc_account: acc.trader_usdc_account,
        trader_phoenix_account: acc.trader_phoenix_account,
        ember_vault: acc.ember_vault,
        token_program: acc.token_program,
    }
}

/// Ember `withdraw{Some(amount)}`: PhUSD on `vault_phusd` → USDC on
/// `vault_usdc`, signed by `phx_authority`. Only `amount` is unwrapped, so
/// donated PhUSD stays where it is. A zero amount is `InvariantViolated`.
#[inline(never)]
pub fn ember_withdraw<'a>(acc: &EmberAccounts<'a>, amount: u64, signer: &[Signer]) -> ProgramResult {
    if amount == 0 {
        return Err(SijkaError::InvariantViolated.fail());
    }
    let w = ember_withdraw_wrapper(acc);
    let mut scratch = CpiScratch::<'a, SCRATCH_EMBER_ACCOUNTS, SCRATCH_EMBER_WITHDRAW_DATA>::new(acc.ember_program);
    crate::cpi_tramp::ember_withdraw(&w, ember::EmberWithdrawArgs { amount: Some(amount) }, signer, &mut scratch)
}

// ------------------------------------------------------ Ember accounts ----

/// Pure check of the Ember state bytes (SPEC §5.0.5 / §3.9): discriminator,
/// length ≥ 136, `@40 == usdc_mint`, `@72 == phusd_mint`, `@104 ==
/// PHOENIX_PROGRAM_ID`.
pub fn ember_state_fields_ok(data: &[u8], usdc_mint: &Pubkey, phusd_mint: &Pubkey) -> bool {
    let key_at = |o: usize, want: &Pubkey| read_key(data, o).is_some_and(|k| pubkey_eq(k, want));
    data.len() >= esl::MIN_LEN
        && array_ref::<8>(data, esl::DISCRIMINATOR) == Some(&DISC_EMBER_STATE)
        && key_at(esl::INPUT_MINT, usdc_mint)
        && key_at(esl::OUTPUT_MINT, phusd_mint)
        && key_at(esl::PHOENIX_PROGRAM, &PHOENIX_PROGRAM_ID)
}

/// SPEC §5.0.5 `ember_state`: key `EMBER_STATE`, owner Ember, fields as in
/// [`ember_state_fields_ok`]. Error `InvalidEmberAccount`. Read-only (Ember
/// does not write it).
pub fn check_ember_state(ai: &AccountInfo, usdc_mint: &Pubkey, phusd_mint: &Pubkey) -> ProgramResult {
    expect_key(ai, &EMBER_STATE, SijkaError::InvalidEmberAccount)?;
    expect_owner(ai, &EMBER_PROGRAM_ID, SijkaError::InvalidEmberAccount)?;
    let data = ai.try_borrow_data()?;
    if !ember_state_fields_ok(&data, usdc_mint, phusd_mint) {
        return Err(SijkaError::InvalidEmberAccount.fail());
    }
    Ok(())
}

/// SPEC §5.0.5 `ember_vault`: key `EMBER_VAULT` (`InvalidEmberAccount`) and
/// writable (Ember moves USDC in or out of it; `AccountNotWritable`).
pub fn check_ember_vault(ai: &AccountInfo) -> ProgramResult {
    expect_key(ai, &EMBER_VAULT, SijkaError::InvalidEmberAccount)?;
    expect_writable(ai)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{MAX_ATB, MAX_GTI};
    use crate::util::test_utils::TestAccount;
    use pinocchio::instruction::AccountMeta;

    fn key(n: u8) -> Pubkey {
        let mut k = [n; 32];
        k[31] = 0xEE;
        k
    }

    #[test]
    fn withdraw_wrapper_writes_accounts_and_data() {
        // TU-X5 for the withdraw row: g = a = 8 fits the scratch, metas and data
        // are exactly the SPEC ones.
        let fixed: Vec<TestAccount> = (0..10u8).map(|i| TestAccount::plain(key(i), [0; 32], &[])).collect();
        let arenas: Vec<TestAccount> =
            (0..(MAX_GTI + MAX_ATB) as u8).map(|i| TestAccount::plain(key(100 + i), [0; 32], &[])).collect();
        let f: Vec<AccountInfo> = fixed.iter().map(TestAccount::info).collect();
        let ar: Vec<AccountInfo> = arenas.iter().map(TestAccount::info).collect();
        let (gti, atb) = ar.split_at(MAX_GTI);
        let acc = WithdrawAccounts {
            phoenix_program: &f[0],
            log_authority: &f[1],
            global_config: &f[2],
            trader: &f[3],
            trader_account: &f[4],
            perp_asset_map: &f[5],
            global_vault: &f[6],
            trader_token_account: &f[7],
            token_program: &f[8],
            gti,
            atb,
            withdraw_queue: &f[9],
        };
        let w = acc.wrapper();
        let mut infos: [&AccountInfo; SCRATCH_WITHDRAW_ACCOUNTS] = [&f[0]; SCRATCH_WITHDRAW_ACCOUNTS];
        let mut metas: [AccountMeta; SCRATCH_WITHDRAW_ACCOUNTS] =
            core::array::from_fn(|_| AccountMeta::readonly(f[0].key()));
        let mut data = [0u8; SCRATCH_WITHDRAW_DATA];
        let mut bufs =
            phoenix_rise::cpi::CpiBuffers { account_infos: &mut infos, account_metas: &mut metas, data: &mut data };
        // Host: the invoke itself is a no-op, the buffers are filled for real.
        w.invoke_signed_with_buffers(phoenix::PhoenixWithdrawArgs { amount: 0x0102_0304_0506_0708 }, &[], &mut bufs)
            .unwrap();
        assert_eq!(&data[..8], &crate::constants::IX_PHX_WITHDRAW_FUNDS);
        assert_eq!(&data[..8], &[0xf1, 0x24, 0x1d, 0x6f, 0xd0, 0x1f, 0x68, 0xd9]);
        assert_eq!(u64::from_le_bytes(data[8..16].try_into().unwrap()), 0x0102_0304_0506_0708);
        // (key, writable, signer) per SPEC §5.4.2 step 12.
        let mut want: Vec<(Pubkey, bool, bool)> = vec![
            (key(0), false, false),
            (key(1), false, false),
            (key(2), true, false),
            (key(3), false, true),
            (key(4), true, false),
            (key(5), true, false),
            (key(6), true, false),
            (key(7), true, false),
            (key(8), false, false),
        ];
        for i in 0..(MAX_GTI + MAX_ATB) as u8 {
            want.push((key(100 + i), true, false));
        }
        want.push((key(9), true, false));
        assert_eq!(want.len(), SCRATCH_WITHDRAW_ACCOUNTS);
        for (j, (k, wr, s)) in want.iter().enumerate() {
            assert_eq!(metas[j].pubkey, k, "meta {j}");
            assert_eq!((metas[j].is_writable, metas[j].is_signer), (*wr, *s), "meta {j}");
            assert_eq!(infos[j].key(), k, "info {j}");
        }
        // Through the real entry (scratch inside, trampoline): ok on the host.
        assert_eq!(withdraw_funds(&acc, 5, &[]), Ok(()));
        assert_eq!(withdraw_funds(&acc, 0, &[]), Err(SijkaError::InvariantViolated.into()));
    }

    #[test]
    fn ember_withdraw_uses_some_amount() {
        let a: Vec<TestAccount> = (0..9u8).map(|i| TestAccount::plain(key(i), [0; 32], &[])).collect();
        let f: Vec<AccountInfo> = a.iter().map(TestAccount::info).collect();
        let acc = EmberAccounts {
            ember_program: &f[0],
            trader: &f[1],
            ember_state: &f[2],
            usdc_mint: &f[3],
            canonical_mint: &f[4],
            trader_usdc_account: &f[5],
            trader_phoenix_account: &f[6],
            ember_vault: &f[7],
            token_program: &f[8],
        };
        let w = ember_withdraw_wrapper(&acc);
        let mut infos: [&AccountInfo; SCRATCH_EMBER_ACCOUNTS] = [&f[0]; SCRATCH_EMBER_ACCOUNTS];
        let mut metas: [AccountMeta; SCRATCH_EMBER_ACCOUNTS] =
            core::array::from_fn(|_| AccountMeta::readonly(f[0].key()));
        let mut data = [0u8; SCRATCH_EMBER_WITHDRAW_DATA];
        let mut bufs =
            phoenix_rise::cpi::CpiBuffers { account_infos: &mut infos, account_metas: &mut metas, data: &mut data };
        w.invoke_signed_with_buffers(ember::EmberWithdrawArgs { amount: Some(u64::MAX) }, &[], &mut bufs).unwrap();
        assert_eq!(&data[..8], &crate::constants::IX_EMBER_WITHDRAW);
        assert_eq!(data[8], 1, "Some(amount), never None");
        assert_eq!(u64::from_le_bytes(data[9..17].try_into().unwrap()), u64::MAX);
        let want: [(Pubkey, bool, bool); 8] = [
            (key(1), false, true),
            (key(2), false, false),
            (key(3), false, false),
            (key(4), true, false),
            (key(5), true, false),
            (key(6), true, false),
            (key(7), true, false),
            (key(8), false, false),
        ];
        for (j, (k, wr, s)) in want.iter().enumerate() {
            assert_eq!(metas[j].pubkey, k, "meta {j}");
            assert_eq!((metas[j].is_writable, metas[j].is_signer), (*wr, *s), "meta {j}");
        }
        assert_eq!(ember_withdraw(&acc, 17, &[]), Ok(()));
        assert_eq!(ember_withdraw(&acc, 0, &[]), Err(SijkaError::InvariantViolated.into()));
    }

    pub(crate) fn ember_state_bytes(usdc: &Pubkey, phusd: &Pubkey) -> Vec<u8> {
        let mut d = vec![0u8; 136];
        d[0..8].copy_from_slice(&DISC_EMBER_STATE);
        d[40..72].copy_from_slice(usdc);
        d[72..104].copy_from_slice(phusd);
        d[104..136].copy_from_slice(&PHOENIX_PROGRAM_ID);
        d
    }

    #[test]
    fn ember_account_checks() {
        let (usdc, phusd) = (key(1), key(2));
        let good = ember_state_bytes(&usdc, &phusd);
        assert!(ember_state_fields_ok(&good, &usdc, &phusd));
        assert!(!ember_state_fields_ok(&good[..135], &usdc, &phusd));
        assert!(!ember_state_fields_ok(&good, &phusd, &usdc));
        for o in [0usize, 40, 72, 104] {
            let mut b = good.clone();
            b[o] ^= 1;
            assert!(!ember_state_fields_ok(&b, &usdc, &phusd), "byte {o}");
        }
        let e = Err(SijkaError::InvalidEmberAccount.into());
        let ok = TestAccount::plain(EMBER_STATE, EMBER_PROGRAM_ID, &good);
        assert_eq!(check_ember_state(&ok.info(), &usdc, &phusd), Ok(()));
        let wrong_key = TestAccount::plain(key(9), EMBER_PROGRAM_ID, &good);
        assert_eq!(check_ember_state(&wrong_key.info(), &usdc, &phusd), e);
        let wrong_owner = TestAccount::plain(EMBER_STATE, key(9), &good);
        assert_eq!(check_ember_state(&wrong_owner.info(), &usdc, &phusd), e);
        let vault_rw = TestAccount::new(EMBER_VAULT, key(0), 1, &[], false, true, false);
        assert_eq!(check_ember_vault(&vault_rw.info()), Ok(()));
        let vault_ro = TestAccount::plain(EMBER_VAULT, key(0), &[]);
        assert_eq!(check_ember_vault(&vault_ro.info()), Err(SijkaError::AccountNotWritable.into()));
        let other = TestAccount::new(key(9), key(0), 1, &[], false, true, false);
        assert_eq!(check_ember_vault(&other.info()), e);
    }
}
