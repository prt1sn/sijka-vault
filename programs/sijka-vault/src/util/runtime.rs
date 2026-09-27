// Copyright (c) 2026 prt1sn. All rights reserved.
//! Runtime queries: stack height, top-level checks (SPEC §5.0.11), the
//! LastRestartSlot syscall (§2.3, §5.6.1), clock, events and return data.
//!
//! Syscalls exist only on `target_os = "solana"`; host builds get fixed values
//! so that pure logic can be unit-tested.

use pinocchio::ProgramResult;
use pinocchio::account_info::AccountInfo;
use pinocchio::program_error::ProgramError;
use pinocchio::pubkey::{Pubkey, pubkey_eq};
use pinocchio::sysvars::clock::Clock;

use crate::constants::{COMPUTE_BUDGET_PROGRAM_ID, INSTRUCTIONS_SYSVAR};
use crate::error::SijkaError;
use crate::util::bytes::{read_key, read_u8, read_u16};

/// Stack height of a top-level instruction.
pub const TRANSACTION_LEVEL_STACK_HEIGHT: u64 = 1;

/// Current invocation stack height (1 = top level).
#[inline]
pub fn stack_height() -> u64 {
    #[cfg(target_os = "solana")]
    {
        // SAFETY: syscall without arguments; returns the current stack height.
        #[allow(unsafe_code)]
        let h = unsafe { pinocchio::syscalls::sol_get_stack_height() };
        h
    }
    #[cfg(not(target_os = "solana"))]
    {
        TRANSACTION_LEVEL_STACK_HEIGHT
    }
}

/// `require_top_level()` (SPEC §5.0.11): the instruction is not a CPI.
#[inline]
pub fn require_top_level() -> ProgramResult {
    if stack_height() != TRANSACTION_LEVEL_STACK_HEIGHT {
        return Err(SijkaError::NotTopLevel.fail());
    }
    Ok(())
}

/// `LastRestartSlot` via `sol_get_last_restart_slot` (SPEC §2.3). The caller
/// cannot substitute it (no account is passed). Host builds return 0.
pub fn last_restart_slot() -> Result<u64, ProgramError> {
    #[cfg(target_os = "solana")]
    {
        let mut buf = [0u8; 8];
        // SAFETY: the syscall writes exactly 8 bytes (u64 LE) into `buf`, which
        // is a valid, writable 8-byte buffer on our stack.
        #[allow(unsafe_code)]
        let rc = unsafe { pinocchio::syscalls::sol_get_last_restart_slot(buf.as_mut_ptr()) };
        if rc != 0 {
            return Err(SijkaError::InvariantViolated.fail());
        }
        Ok(u64::from_le_bytes(buf))
    }
    #[cfg(not(target_os = "solana"))]
    {
        Ok(0)
    }
}

/// `Clock::get()`.
#[inline]
pub fn clock() -> Result<Clock, ProgramError> {
    use pinocchio::sysvars::Sysvar;
    Clock::get()
}

/// Log one ASCII line (`sol_log_`), used for the `Sijka: <Name>` error line
/// (SPEC §5.0.8). Takes bytes so the caller needs no UTF-8 validation code.
#[inline]
pub fn log_bytes(line: &[u8]) {
    #[cfg(target_os = "solana")]
    {
        // SAFETY: `sol_log_` reads exactly `len` bytes from `ptr`; both come
        // from one valid slice that outlives the call. The runtime copies the
        // bytes and never writes through the pointer.
        #[allow(unsafe_code)]
        unsafe {
            pinocchio::syscalls::sol_log_(line.as_ptr(), line.len() as u64)
        };
    }
    #[cfg(not(target_os = "solana"))]
    {
        core::hint::black_box(line);
    }
}

/// Emit one event record (SPEC §5.0.9): a single `sol_log_data` slice.
#[inline]
pub fn emit(payload: &[u8]) {
    pinocchio::log::sol_log_data(&[payload]);
}

/// Set our return data (SPEC §5.2.10: the last action where required).
#[inline]
pub fn set_return_data(data: &[u8]) {
    pinocchio::cpi::set_return_data(data);
}

/// `require_sole_top_level(ix_sysvar, tag)` (SPEC §5.0.11, tags 42–45): this
/// instruction is top level, and every other instruction of the transaction is
/// a ComputeBudget instruction. The current instruction must be ours with
/// `data[0] == tag`.
pub fn require_sole_top_level(ix_sysvar: &AccountInfo, program_id: &Pubkey, tag: u8) -> ProgramResult {
    require_top_level()?;
    if !pubkey_eq(ix_sysvar.key(), &INSTRUCTIONS_SYSVAR) {
        return Err(SijkaError::InvalidExternalAccount.fail());
    }
    let data = ix_sysvar.try_borrow_data()?;
    check_sole_top_level(&data, program_id, tag).map_err(SijkaError::fail)
}

/// Pure check over the Instructions sysvar bytes. Layout (Solana):
/// `u16 n`, `u16 offsets[n]`, per instruction at its offset: `u16 num_accounts`,
/// `num_accounts × (u8 flags, [u8;32] key)`, `[u8;32] program_id`,
/// `u16 data_len`, `data`; the last two bytes are the current index (u16).
pub fn check_sole_top_level(sysvar: &[u8], program_id: &Pubkey, tag: u8) -> Result<(), SijkaError> {
    let n = read_u16(sysvar, 0).ok_or(SijkaError::InvalidExternalAccount)?;
    let cur_off = sysvar.len().checked_sub(2).ok_or(SijkaError::InvalidExternalAccount)?;
    let current = read_u16(sysvar, cur_off).ok_or(SijkaError::InvalidExternalAccount)?;
    if current >= n {
        return Err(SijkaError::InvalidExternalAccount);
    }
    for i in 0..n {
        let ix = parse_instruction(sysvar, usize::from(i)).ok_or(SijkaError::InvalidExternalAccount)?;
        if i == current {
            if !pubkey_eq(ix.program_id, program_id) || ix.first_data_byte != Some(tag) {
                return Err(SijkaError::NotTopLevel);
            }
        } else if !pubkey_eq(ix.program_id, &COMPUTE_BUDGET_PROGRAM_ID) {
            return Err(SijkaError::ForeignInstruction);
        }
    }
    Ok(())
}

struct ParsedIx<'a> {
    program_id: &'a Pubkey,
    first_data_byte: Option<u8>,
}

/// Size of one serialized account meta in the Instructions sysvar.
const IX_SYSVAR_META_LEN: usize = 33;

fn parse_instruction(sysvar: &[u8], index: usize) -> Option<ParsedIx<'_>> {
    let off_pos = index.checked_mul(2)?.checked_add(2)?;
    let start = usize::from(read_u16(sysvar, off_pos)?);
    let num_accounts = usize::from(read_u16(sysvar, start)?);
    let pid_off = start.checked_add(2)?.checked_add(num_accounts.checked_mul(IX_SYSVAR_META_LEN)?)?;
    let program_id = read_key(sysvar, pid_off)?;
    let len_off = pid_off.checked_add(32)?;
    let data_len = usize::from(read_u16(sysvar, len_off)?);
    let data_off = len_off.checked_add(2)?;
    // The whole data region must be inside the sysvar.
    if data_len > 0 {
        let last = data_off.checked_add(data_len)?.checked_sub(1)?;
        read_u8(sysvar, last)?;
    }
    let first_data_byte = if data_len > 0 { read_u8(sysvar, data_off) } else { None };
    Some(ParsedIx { program_id, first_data_byte })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Serialize instructions the way the runtime does (test helper).
    pub fn build_sysvar(ixs: &[(Pubkey, Vec<u8>)], current: u16) -> Vec<u8> {
        let n = ixs.len();
        let mut out = vec![0u8; 2 + 2 * n];
        out[0..2].copy_from_slice(&(n as u16).to_le_bytes());
        for (i, (pid, data)) in ixs.iter().enumerate() {
            let off = out.len() as u16;
            out[2 + 2 * i..4 + 2 * i].copy_from_slice(&off.to_le_bytes());
            out.extend_from_slice(&1u16.to_le_bytes()); // one account meta
            out.push(0b01);
            out.extend_from_slice(&[9u8; 32]);
            out.extend_from_slice(pid);
            out.extend_from_slice(&(data.len() as u16).to_le_bytes());
            out.extend_from_slice(data);
        }
        out.extend_from_slice(&current.to_le_bytes());
        out
    }

    #[test]
    fn sole_top_level_rules() {
        let me = [7u8; 32];
        let ok = build_sysvar(&[(COMPUTE_BUDGET_PROGRAM_ID, vec![2, 0]), (me, vec![44, 1, 2])], 1);
        assert_eq!(check_sole_top_level(&ok, &me, 44), Ok(()));
        assert_eq!(check_sole_top_level(&ok, &me, 45), Err(SijkaError::NotTopLevel));
        let foreign = build_sysvar(&[([1u8; 32], vec![1]), (me, vec![44])], 1);
        assert_eq!(check_sole_top_level(&foreign, &me, 44), Err(SijkaError::ForeignInstruction));
        let twice = build_sysvar(&[(me, vec![44]), (me, vec![44])], 1);
        assert_eq!(check_sole_top_level(&twice, &me, 44), Err(SijkaError::ForeignInstruction));
        let bad_index = build_sysvar(&[(me, vec![44])], 3);
        assert_eq!(check_sole_top_level(&bad_index, &me, 44), Err(SijkaError::InvalidExternalAccount));
        let mut truncated = ok.clone();
        truncated.truncate(10);
        assert!(check_sole_top_level(&truncated, &me, 44).is_err());
        assert!(check_sole_top_level(&[], &me, 44).is_err());
    }

    #[test]
    fn host_stubs() {
        assert_eq!(stack_height(), TRANSACTION_LEVEL_STACK_HEIGHT);
        assert!(require_top_level().is_ok());
        assert_eq!(last_restart_slot(), Ok(0));
    }
}
