// Copyright (c) 2026 prt1sn. All rights reserved.
//! Test-only mock of Jupiter v6 (LiteSVM, loaded at `JUP6…`).
//!
//! It understands the fixed account layouts and fixed arguments of the four
//! exact-in instructions the vault allows (`route`, `shared_accounts_route`,
//! `route_v2`, `shared_accounts_route_v2`, SPEC §5.3.3) and ignores the rest
//! of the route plan. The first bytes of the route plan select a behaviour
//! (the vault never parses the route plan):
//!
//! ```text
//! step = mode u8 | out u64 | arg u64          (17 bytes)
//! v2:  data[34..] (route_v2), data[35..] (shared_accounts_route_v2)
//! v1:  data[12..] (route),    data[13..] (shared_accounts_route); the fixed
//!      arguments follow the step (in_amount = u64 @ len − 19)
//! ```
//!
//! Remaining accounts (after the fixed ones):
//! `[pool_authority, pool_wsol W, pool_usdc W, attacker_usdc W, attacker W,
//!   system_program, token_program, extra…]`, where `pool_authority =
//! PDA(mock, ["pool"])` owns both pool token accounts.
//!
//! Two more entry points, selected by an 8-byte tag instead of a Jupiter
//! discriminator:
//! - `SJKCALL\0 | inner data`: CPI into `accounts[0]` with `accounts[1..]`
//!   (flags preserved) and the inner data (a program calling the vault);
//! - `SJKCHAIN | depth u8 | amount u64`: pays `amount` from `accounts[1]` to
//!   `accounts[2]` signed by the pool PDA after `depth` nested self-CPIs
//!   (accounts `[self, src, dst, pool_authority, token_program]`); used to
//!   measure the CPI depth an AMM may use under the vault.

use pinocchio::account_info::AccountInfo;
use pinocchio::cpi::slice_invoke_signed;
use pinocchio::instruction::{AccountMeta, Instruction, Seed, Signer};
use pinocchio::program_error::ProgramError;
use pinocchio::pubkey::{find_program_address, Pubkey};
use pinocchio::ProgramResult;

pinocchio::entrypoint!(process_instruction);

const TOKEN_PROGRAM: Pubkey = [
    6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172, 28, 180, 133, 237, 95, 91, 55, 145,
    58, 140, 245, 133, 126, 255, 0, 169,
];
const SYSTEM_PROGRAM: Pubkey = [0u8; 32];

const DISC_ROUTE: [u8; 8] = [0xe5, 0x17, 0xcb, 0x97, 0x7a, 0xe3, 0xad, 0x2a];
const DISC_SHARED: [u8; 8] = [0xc1, 0x20, 0x9b, 0x33, 0x41, 0xd6, 0x9c, 0x81];
const DISC_ROUTE_V2: [u8; 8] = [0xbb, 0x64, 0xfa, 0xcc, 0x31, 0xc4, 0xaf, 0x14];
const DISC_SHARED_V2: [u8; 8] = [0xd1, 0x98, 0x53, 0x93, 0x7c, 0xfe, 0xd8, 0xe9];
const TAG_CALL: [u8; 8] = *b"SJKCALL\0";
const TAG_CHAIN: [u8; 8] = *b"SJKCHAIN";

/// Behaviours (first byte of the route plan).
pub mod mode {
    pub const HONEST: u8 = 0;
    pub const OVERSPEND: u8 = 1;
    pub const PAY_TO_OTHER: u8 = 2;
    pub const APPROVE_DELEGATE: u8 = 3;
    pub const SET_OWNER: u8 = 4;
    pub const SET_CLOSE_AUTHORITY: u8 = 5;
    pub const CLOSE_SRC: u8 = 6;
    pub const DRAIN_AUTHORITY: u8 = 7;
    pub const NOOP: u8 = 8;
    pub const CREDIT_SRC: u8 = 9;
    pub const STEAL_DST: u8 = 10;
    pub const REENTER: u8 = 11;
    pub const ASSIGN_AUTHORITY: u8 = 12;
    pub const PARTIAL: u8 = 13;
    pub const CHAIN: u8 = 14;
    pub const CREDIT_EXTRA: u8 = 15;
    pub const SYNC_SRC: u8 = 16;
    pub const WRITE_FOREIGN: u8 = 17;
}

/// Error codes of the mock itself (Custom).
const E_DATA: u32 = 0x4d4a_0001;
const E_ACCOUNTS: u32 = 0x4d4a_0002;
const E_MODE: u32 = 0x4d4a_0003;

fn err(code: u32) -> ProgramError {
    ProgramError::Custom(code)
}

struct Layout {
    fixed: usize,
    authority: usize,
    src: usize,
    dst: usize,
    step: usize,
    v1: bool,
    in_off: usize,
}

fn layout(data: &[u8]) -> Option<Layout> {
    let disc: [u8; 8] = data.get(..8)?.try_into().ok()?;
    let len = data.len();
    Some(match disc {
        DISC_ROUTE => {
            Layout { fixed: 9, authority: 1, src: 2, dst: 3, step: 12, v1: true, in_off: len.checked_sub(19)? }
        }
        DISC_SHARED => {
            Layout { fixed: 13, authority: 2, src: 3, dst: 6, step: 13, v1: true, in_off: len.checked_sub(19)? }
        }
        DISC_ROUTE_V2 => Layout { fixed: 10, authority: 0, src: 1, dst: 2, step: 34, v1: false, in_off: 8 },
        DISC_SHARED_V2 => Layout { fixed: 12, authority: 1, src: 2, dst: 5, step: 35, v1: false, in_off: 9 },
        _ => return None,
    })
}

fn read_u64(data: &[u8], off: usize) -> Option<u64> {
    let b: [u8; 8] = data.get(off..off.checked_add(8)?)?.try_into().ok()?;
    Some(u64::from_le_bytes(b))
}

pub fn process_instruction(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let tag: [u8; 8] = data.get(..8).and_then(|d| d.try_into().ok()).ok_or_else(|| err(E_DATA))?;
    if tag == TAG_CALL {
        return forward(accounts, data.get(8..).ok_or_else(|| err(E_DATA))?);
    }
    if tag == TAG_CHAIN {
        return chain(program_id, accounts, data);
    }
    let l = layout(data).ok_or_else(|| err(E_DATA))?;
    let in_amount = read_u64(data, l.in_off).ok_or_else(|| err(E_DATA))?;
    let step_mode = *data.get(l.step).ok_or_else(|| err(E_DATA))?;
    let out = read_u64(data, l.step + 1).ok_or_else(|| err(E_DATA))?;
    let arg = read_u64(data, l.step + 9).ok_or_else(|| err(E_DATA))?;
    if l.v1 && l.step + 17 > l.in_off {
        return Err(err(E_DATA));
    }
    let acc = |i: usize| accounts.get(i).ok_or_else(|| err(E_ACCOUNTS));
    let authority = acc(l.authority)?;
    let src = acc(l.src)?;
    let dst = acc(l.dst)?;
    let rem = accounts.get(l.fixed..).ok_or_else(|| err(E_ACCOUNTS))?;
    let r = |i: usize| rem.get(i).ok_or_else(|| err(E_ACCOUNTS));
    let pool_authority = r(0)?;
    let pool_wsol = r(1)?;
    let pool_usdc = r(2)?;
    let (pool_key, bump) = find_program_address(&[b"pool"], program_id);
    if pool_authority.key() != &pool_key {
        return Err(err(E_ACCOUNTS));
    }
    let bump_ref = [bump];
    let seeds = [Seed::from(b"pool"), Seed::from(&bump_ref)];
    let pool_signer = [Signer::from(&seeds)];

    let take = |amount: u64| token_transfer(src, pool_wsol, authority, amount, &[]);
    let pay = |to: &AccountInfo, amount: u64| token_transfer(pool_usdc, to, pool_authority, amount, &pool_signer);

    match step_mode {
        mode::HONEST => {
            take(in_amount)?;
            pay(dst, out)
        }
        mode::OVERSPEND => {
            take(in_amount.checked_add(arg).ok_or_else(|| err(E_DATA))?)?;
            pay(dst, out)
        }
        mode::PAY_TO_OTHER => {
            take(in_amount)?;
            pay(r(3)?, out)
        }
        mode::APPROVE_DELEGATE => {
            take(in_amount)?;
            pay(dst, out)?;
            let target = if arg == 0 { src } else { dst };
            let mut d = [0u8; 9];
            d[0] = 4;
            d[1..9].copy_from_slice(&1u64.to_le_bytes());
            let metas = [
                AccountMeta::writable(target.key()),
                AccountMeta::readonly(r(4)?.key()),
                AccountMeta::readonly_signer(authority.key()),
            ];
            cpi(&TOKEN_PROGRAM, &metas, &d, &[target, r(4)?, authority], &[])
        }
        mode::SET_OWNER | mode::SET_CLOSE_AUTHORITY => {
            take(in_amount)?;
            pay(dst, out)?;
            let target = if arg == 0 { src } else { dst };
            let kind = if step_mode == mode::SET_OWNER { 2u8 } else { 3u8 };
            let mut d = [0u8; 35];
            d[0] = 6;
            d[1] = kind;
            d[2] = 1;
            d[3..35].copy_from_slice(r(4)?.key());
            let metas = [AccountMeta::writable(target.key()), AccountMeta::readonly_signer(authority.key())];
            cpi(&TOKEN_PROGRAM, &metas, &d, &[target, authority], &[])
        }
        mode::CLOSE_SRC => {
            take(in_amount)?;
            pay(dst, out)?;
            let attacker = r(4)?;
            let metas = [
                AccountMeta::writable(src.key()),
                AccountMeta::writable(attacker.key()),
                AccountMeta::readonly_signer(authority.key()),
            ];
            cpi(&TOKEN_PROGRAM, &metas, &[9], &[src, attacker, authority], &[])
        }
        mode::DRAIN_AUTHORITY => {
            take(in_amount)?;
            pay(dst, out)?;
            let attacker = r(4)?;
            let mut d = [0u8; 12];
            d[0] = 2;
            d[4..12].copy_from_slice(&arg.to_le_bytes());
            // `authority` is read-only in the vault's CPI: the runtime refuses
            // to escalate it to writable.
            let metas = [AccountMeta::writable_signer(authority.key()), AccountMeta::writable(attacker.key())];
            cpi(&SYSTEM_PROGRAM, &metas, &d, &[authority, attacker], &[])
        }
        mode::ASSIGN_AUTHORITY => {
            take(in_amount)?;
            pay(dst, out)?;
            let mut d = [0u8; 36];
            d[0] = 1;
            d[4..36].copy_from_slice(program_id);
            let metas = [AccountMeta::writable_signer(authority.key())];
            cpi(&SYSTEM_PROGRAM, &metas, &d, &[authority], &[])
        }
        mode::NOOP => Ok(()),
        mode::CREDIT_SRC => {
            take(in_amount)?;
            pay(dst, out)?;
            token_transfer(pool_wsol, src, pool_authority, arg, &pool_signer)
        }
        mode::STEAL_DST => {
            take(in_amount)?;
            pay(dst, out)?;
            token_transfer(dst, r(3)?, authority, arg, &[])
        }
        mode::REENTER => {
            take(in_amount)?;
            pay(dst, out)?;
            // CPI into rem[7] (the vault) with rem[8..] and the tag in `arg`.
            let target = r(7)?;
            let rest = rem.get(8..).unwrap_or(&[]);
            let tag = [arg as u8];
            let mut metas: [AccountMeta; 16] = core::array::from_fn(|_| AccountMeta::readonly(&SYSTEM_PROGRAM));
            let mut infos: [&AccountInfo; 16] = [target; 16];
            let n = rest.len().min(16);
            for (i, a) in rest.iter().take(n).enumerate() {
                metas[i] = AccountMeta::new(a.key(), a.is_writable(), a.is_signer());
                infos[i] = a;
            }
            cpi(target.key(), &metas[..n], &tag, &infos[..n], &[])
        }
        mode::PARTIAL => {
            take(arg)?;
            pay(dst, out)
        }
        mode::CHAIN => {
            take(in_amount)?;
            // Pay through `arg` nested self-CPIs (depth measurement).
            let me = r(7)?;
            let token = r(6)?;
            let mut d = [0u8; 17];
            d[..8].copy_from_slice(&TAG_CHAIN);
            d[8] = arg as u8;
            d[9..17].copy_from_slice(&out.to_le_bytes());
            let metas = [
                AccountMeta::readonly(me.key()),
                AccountMeta::writable(pool_usdc.key()),
                AccountMeta::writable(dst.key()),
                AccountMeta::readonly(pool_authority.key()),
                AccountMeta::readonly(token.key()),
            ];
            cpi(program_id, &metas, &d, &[me, pool_usdc, dst, pool_authority, token], &[])
        }
        mode::CREDIT_EXTRA => {
            take(in_amount)?;
            pay(dst, out.checked_add(arg).ok_or_else(|| err(E_DATA))?)
        }
        mode::SYNC_SRC => {
            take(in_amount)?;
            pay(dst, out)?;
            let metas = [AccountMeta::writable(src.key())];
            cpi(&TOKEN_PROGRAM, &metas, &[17], &[src], &[])
        }
        mode::WRITE_FOREIGN => {
            take(in_amount)?;
            pay(dst, out)?;
            // Try to change the data of an account the mock does not own
            // (rem[7]); the runtime rejects this at the end of the CPI.
            let target = r(7)?;
            let mut d = target.try_borrow_mut_data()?;
            if let Some(b) = d.first_mut() {
                *b ^= 0xff;
            }
            Ok(())
        }
        _ => Err(err(E_MODE)),
    }
}

fn token_transfer(
    from: &AccountInfo,
    to: &AccountInfo,
    authority: &AccountInfo,
    amount: u64,
    signers: &[Signer],
) -> ProgramResult {
    let mut d = [0u8; 9];
    d[0] = 3;
    d[1..9].copy_from_slice(&amount.to_le_bytes());
    let metas = [
        AccountMeta::writable(from.key()),
        AccountMeta::writable(to.key()),
        AccountMeta::readonly_signer(authority.key()),
    ];
    cpi(&TOKEN_PROGRAM, &metas, &d, &[from, to, authority], signers)
}

/// Every CPI goes through here: `slice_invoke_signed` keeps its
/// `[Account; 64]` (3.5 KB) in this frame, apart from the callers' arrays
/// (4 KB SBF frame limit).
#[inline(never)]
fn cpi(
    program: &Pubkey,
    metas: &[AccountMeta],
    data: &[u8],
    infos: &[&AccountInfo],
    signers: &[Signer],
) -> ProgramResult {
    let ix = Instruction { program_id: program, accounts: metas, data };
    slice_invoke_signed(&ix, infos, signers)
}

/// `SJKCALL`: CPI into `accounts[0]` with `accounts[1..]` (flags preserved).
#[inline(never)]
fn forward(accounts: &[AccountInfo], inner: &[u8]) -> ProgramResult {
    let (target, rest) = accounts.split_first().ok_or_else(|| err(E_ACCOUNTS))?;
    const N: usize = 40;
    if rest.len() > N {
        return Err(err(E_ACCOUNTS));
    }
    let mut metas: [AccountMeta; N] = core::array::from_fn(|_| AccountMeta::readonly(&SYSTEM_PROGRAM));
    let mut infos: [&AccountInfo; N] = [target; N];
    for (i, a) in rest.iter().enumerate() {
        metas[i] = AccountMeta::new(a.key(), a.is_writable(), a.is_signer());
        infos[i] = a;
    }
    cpi(target.key(), &metas[..rest.len()], inner, &infos[..rest.len()], &[])
}

/// `SJKCHAIN | depth | amount`: accounts `[self, src, dst, pool_authority,
/// token_program]`. At depth 0 pays `amount` from `src` to `dst` signed by
/// the pool PDA; otherwise calls itself with `depth − 1`.
#[inline(never)]
fn chain(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [me, src, dst, pool_authority, token, ..] = accounts else {
        return Err(err(E_ACCOUNTS));
    };
    let depth = *data.get(8).ok_or_else(|| err(E_DATA))?;
    let amount = read_u64(data, 9).ok_or_else(|| err(E_DATA))?;
    if depth == 0 {
        let (pool_key, bump) = find_program_address(&[b"pool"], program_id);
        if pool_authority.key() != &pool_key {
            return Err(err(E_ACCOUNTS));
        }
        let bump_ref = [bump];
        let seeds = [Seed::from(b"pool"), Seed::from(&bump_ref)];
        return token_transfer(src, dst, pool_authority, amount, &[Signer::from(&seeds)]);
    }
    let mut d = [0u8; 17];
    d.copy_from_slice(data.get(..17).ok_or_else(|| err(E_DATA))?);
    d[8] = depth - 1;
    let metas = [
        AccountMeta::readonly(me.key()),
        AccountMeta::writable(src.key()),
        AccountMeta::writable(dst.key()),
        AccountMeta::readonly(pool_authority.key()),
        AccountMeta::readonly(token.key()),
    ];
    cpi(program_id, &metas, &d, &[me, src, dst, pool_authority, token], &[])
}
