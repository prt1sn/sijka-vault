// Copyright (c) 2026 prt1sn. All rights reserved.
//! Builtin mock programs (SPEC §9.1), native Rust run by LiteSVM:
//!
//! - **mock Jupiter** at `JUP6…`: understands the `route_v2` account layout of
//!   SPEC §5.3.3 (authority 0, source 1, destination 2, mints 3–4, token
//!   programs 5–6, optional destination 7, event authority 8, program 9) plus
//!   three accounts of its own (10 USDC reserve, 11 wSOL reserve, 12 its
//!   reserve authority PDA). It takes `in_amount` (`data@8`) from the source
//!   with the signature of slot 0 and pays `out` wSOL from its reserve into the
//!   destination. "Evil" modes (`JupMode`) use the same signatures.
//! - **mock pump / pump_amm** at their program ids (tamper tests, review
//!   RT-2): an honest constant-product buy on the account layout of SPEC
//!   §5.5.3, then optionally one abuse of the `user` signature (`PumpEvil`).
//!   Being at pump's address, the mock signs for pump's own PDAs (bonding
//!   curve, pool).
//! - **CPI wrapper**: calls `accounts[0]` with the remaining accounts and its
//!   own data, to run our instructions below top level.
//!
//! Mode and amounts are per test thread (`thread_local!`): LiteSVM executes
//! builtins on the thread that sends the transaction.

use std::cell::{Cell, RefCell};

use litesvm::LiteSVM;
use solana_instruction::{AccountMeta, Instruction};
use solana_program_runtime::__private::InstructionError;
use solana_program_runtime::declare_process_instruction;
use solana_program_runtime::invoke_context::InvokeContext;
use solana_program_runtime::solana_sbpf::program::BuiltinFunctionDefinition;
use solana_pubkey::Pubkey;

use crate::harness::{jup_program, pda, pk, system, tokenkeg};

// -------------------------------------------------------------- modes ----

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JupMode {
    /// Spend `in_amount`, pay `out`.
    Honest,
    /// Spend `in_amount + extra` from the source (SwapInputExceeded).
    Overspend,
    /// Spend `in_amount / 2`, pay `out` (unspent USDC goes back).
    SpendHalf,
    /// Pay to the mock's own reserve instead of the destination.
    PayToOther,
    /// Approve a delegate on the source (swap_usdc).
    ApproveDelegateSrc,
    /// SetAuthority(AccountOwner) on the source / destination.
    SetOwnerSrc,
    SetOwnerDst,
    /// SetAuthority(CloseAccount) on the source / destination.
    SetCloseAuthoritySrc,
    SetCloseAuthorityDst,
    /// CloseAccount on the (emptied) source.
    CloseSrc,
    /// System transfer of all lamports of slot 0 (swap_authority) out.
    DrainAuthority,
    /// System Assign of slot 0 (swap_authority) to the Jupiter id.
    AssignAuthority,
}

#[derive(Clone, Copy, Debug)]
pub struct JupCfg {
    pub mode: JupMode,
    /// wSOL lamports paid for the whole `in_amount`.
    pub out: u64,
    /// Extra USDC taken in `Overspend`.
    pub extra: u64,
}

impl Default for JupCfg {
    fn default() -> Self {
        JupCfg { mode: JupMode::Honest, out: 0, extra: 0 }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PumpEvil {
    Honest,
    AssignUser,
    AllocateUser,
    ApproveBase,
    ApproveQuote,
    SetOwnerQuote,
    SetCloseAuthorityBase,
    SetCloseAuthorityQuote,
    CloseQuote,
    TransferQuoteOut,
}

thread_local! {
    pub static JUP: RefCell<JupCfg> = RefCell::new(JupCfg::default());
    pub static PUMP_EVIL: Cell<PumpEvil> = const { Cell::new(PumpEvil::Honest) };
}

pub fn set_jup(cfg: JupCfg) {
    JUP.with(|j| *j.borrow_mut() = cfg);
}

pub fn set_pump_evil(m: PumpEvil) {
    PUMP_EVIL.with(|p| p.set(m));
}

/// Mock Jupiter reserve authority (PDA of the Jupiter id).
pub fn jup_reserve_authority() -> Pubkey {
    pda(&[b"mock-reserve"], &jup_program())
}

/// Key of the CPI wrapper builtin.
pub fn cpi_wrapper_id() -> Pubkey {
    Pubkey::new_from_array([0xC9; 32])
}

// ----------------------------------------------------- install helpers ----

pub fn install_jupiter_mock(svm: &mut LiteSVM) {
    svm.add_builtin(jup_program(), MockJupiter::register);
}

pub fn install_pump_mocks(svm: &mut LiteSVM) {
    svm.add_builtin(pk(sijka_vault::constants::PUMP_PROGRAM), MockPump::register);
    svm.add_builtin(pk(sijka_vault::constants::PUMP_AMM_PROGRAM), MockPumpAmm::register);
}

pub fn install_cpi_wrapper(svm: &mut LiteSVM) {
    svm.add_builtin(cpi_wrapper_id(), CpiWrapper::register);
}

// ------------------------------------------------------------ plumbing ----

/// Keys, flags, data and account bytes of the current instruction.
struct Ix {
    keys: Vec<Pubkey>,
    signer: Vec<bool>,
    writable: Vec<bool>,
    data: Vec<u8>,
    acc_data: Vec<Vec<u8>>,
    lamports: Vec<u64>,
    program: Pubkey,
}

fn read_ix(ic: &InvokeContext) -> Result<Ix, InstructionError> {
    let ixc = ic.transaction_context.get_current_instruction_context()?;
    let n = ixc.get_number_of_instruction_accounts();
    let mut out = Ix {
        keys: Vec::new(),
        signer: Vec::new(),
        writable: Vec::new(),
        data: ixc.get_instruction_data().to_vec(),
        acc_data: Vec::new(),
        lamports: Vec::new(),
        program: *ixc.get_program_key()?,
    };
    for i in 0..n {
        out.keys.push(*ixc.get_key_of_instruction_account(i)?);
        out.signer.push(ixc.is_instruction_account_signer(i)?);
        out.writable.push(ixc.is_instruction_account_writable(i)?);
        let a = ixc.try_borrow_instruction_account(i)?;
        out.acc_data.push(a.get_data().to_vec());
        out.lamports.push(a.get_lamports());
    }
    Ok(out)
}

fn u64_le(d: &[u8], o: usize) -> u64 {
    d.get(o..o + 8).map(|b| u64::from_le_bytes(b.try_into().unwrap())).unwrap_or(0)
}

fn err(code: u32) -> InstructionError {
    InstructionError::Custom(code)
}

fn invoke(ic: &mut InvokeContext, ix: Instruction, seeds: &[&[&[u8]]]) -> Result<(), InstructionError> {
    ic.native_invoke_signed(ix, seeds)
}

fn meta(k: Pubkey, w: bool, s: bool) -> AccountMeta {
    AccountMeta { pubkey: k, is_writable: w, is_signer: s }
}

fn transfer_checked(
    program: Pubkey,
    src: Pubkey,
    mint: Pubkey,
    dst: Pubkey,
    auth: Pubkey,
    amount: u64,
    decimals: u8,
) -> Instruction {
    let mut d = vec![12u8];
    d.extend_from_slice(&amount.to_le_bytes());
    d.push(decimals);
    Instruction {
        program_id: program,
        accounts: vec![
            meta(src, true, false),
            meta(mint, false, false),
            meta(dst, true, false),
            meta(auth, false, true),
        ],
        data: d,
    }
}

fn token_transfer(program: Pubkey, src: Pubkey, dst: Pubkey, auth: Pubkey, amount: u64) -> Instruction {
    let mut d = vec![3u8];
    d.extend_from_slice(&amount.to_le_bytes());
    Instruction {
        program_id: program,
        accounts: vec![meta(src, true, false), meta(dst, true, false), meta(auth, false, true)],
        data: d,
    }
}

fn approve(program: Pubkey, src: Pubkey, delegate: Pubkey, owner: Pubkey, amount: u64) -> Instruction {
    let mut d = vec![4u8];
    d.extend_from_slice(&amount.to_le_bytes());
    Instruction {
        program_id: program,
        accounts: vec![meta(src, true, false), meta(delegate, false, false), meta(owner, false, true)],
        data: d,
    }
}

/// SetAuthority: 2 = AccountOwner, 3 = CloseAccount.
fn set_authority(program: Pubkey, account: Pubkey, current: Pubkey, kind: u8, new: Pubkey) -> Instruction {
    let mut d = vec![6u8, kind, 1];
    d.extend_from_slice(new.as_ref());
    Instruction { program_id: program, accounts: vec![meta(account, true, false), meta(current, false, true)], data: d }
}

fn close_account(program: Pubkey, account: Pubkey, dst: Pubkey, owner: Pubkey) -> Instruction {
    Instruction {
        program_id: program,
        accounts: vec![meta(account, true, false), meta(dst, true, false), meta(owner, false, true)],
        data: vec![9],
    }
}

fn sys_transfer(from: Pubkey, to: Pubkey, lamports: u64) -> Instruction {
    let mut d = vec![2u8, 0, 0, 0];
    d.extend_from_slice(&lamports.to_le_bytes());
    Instruction { program_id: system(), accounts: vec![meta(from, true, true), meta(to, true, false)], data: d }
}

fn sys_assign(acc: Pubkey, owner: Pubkey) -> Instruction {
    let mut d = vec![1u8, 0, 0, 0];
    d.extend_from_slice(owner.as_ref());
    Instruction { program_id: system(), accounts: vec![meta(acc, true, true)], data: d }
}

fn sys_allocate(acc: Pubkey, space: u64) -> Instruction {
    let mut d = vec![8u8, 0, 0, 0];
    d.extend_from_slice(&space.to_le_bytes());
    Instruction { program_id: system(), accounts: vec![meta(acc, true, true)], data: d }
}

// -------------------------------------------------------- mock Jupiter ----

declare_process_instruction!(MockJupiter, 1_000, |invoke_context| { mock_jupiter(invoke_context) });

fn mock_jupiter(ic: &mut InvokeContext) -> Result<(), InstructionError> {
    let x = read_ix(ic)?;
    if x.keys.len() < 13 {
        return Err(InstructionError::MissingAccount);
    }
    let cfg = JUP.with(|j| *j.borrow());
    let (auth, src, dst, usdc_mint, wsol_mint) = (x.keys[0], x.keys[1], x.keys[2], x.keys[3], x.keys[4]);
    let (res_usdc, res_wsol, res_auth) = (x.keys[10], x.keys[11], x.keys[12]);
    let in_amount = u64_le(&x.data, 8);
    let (_, bump) = Pubkey::find_program_address(&[b"mock-reserve"], &x.program);
    let seeds: &[&[u8]] = &[b"mock-reserve", &[bump]];
    let tk = tokenkeg();
    let spend = match cfg.mode {
        JupMode::Overspend => in_amount + cfg.extra,
        JupMode::SpendHalf => in_amount / 2,
        _ => in_amount,
    };
    invoke(ic, transfer_checked(tk, src, usdc_mint, res_usdc, auth, spend, 6), &[])?;
    let pay_to = if cfg.mode == JupMode::PayToOther { res_wsol } else { dst };
    if pay_to != res_wsol && cfg.out > 0 {
        invoke(ic, transfer_checked(tk, res_wsol, wsol_mint, pay_to, res_auth, cfg.out, 9), &[seeds])?;
    }
    match cfg.mode {
        JupMode::ApproveDelegateSrc => invoke(ic, approve(tk, src, res_auth, auth, 1), &[])?,
        JupMode::SetOwnerSrc => invoke(ic, set_authority(tk, src, auth, 2, res_auth), &[])?,
        JupMode::SetOwnerDst => invoke(ic, set_authority(tk, dst, auth, 2, res_auth), &[])?,
        JupMode::SetCloseAuthoritySrc => invoke(ic, set_authority(tk, src, auth, 3, res_auth), &[])?,
        JupMode::SetCloseAuthorityDst => invoke(ic, set_authority(tk, dst, auth, 3, res_auth), &[])?,
        JupMode::CloseSrc => invoke(ic, close_account(tk, src, res_usdc, auth), &[])?,
        JupMode::DrainAuthority => {
            let lamports = x.lamports[0];
            if lamports == 0 {
                return Err(err(0x4D4A_0001));
            }
            invoke(ic, sys_transfer(auth, res_usdc, lamports), &[])?;
        }
        JupMode::AssignAuthority => invoke(ic, sys_assign(auth, x.program), &[])?,
        _ => {}
    }
    Ok(())
}

// ----------------------------------------------------------- mock pump ----

declare_process_instruction!(MockPump, 1_000, |invoke_context| { mock_pump(invoke_context) });
declare_process_instruction!(MockPumpAmm, 1_000, |invoke_context| { mock_pump_amm(invoke_context) });

/// Constant product with a 1.25% fee: tokens for `v` against `(q, b)`.
fn cp_out(v: u64, q: u64, b: u64) -> u64 {
    let net = u128::from(v) * 10_000 / 10_125;
    (net * u128::from(b) / (u128::from(q) + net)) as u64
}

fn quote_decimals(mint: &Pubkey) -> u8 {
    if *mint == pk(sijka_vault::constants::WSOL_MINT) { 9 } else { 6 }
}

/// pump `buy_exact_quote_in_v2`: 27 accounts (SPEC §5.5.3). Honest part:
/// quote from `user` (#14) to the curve, tokens from the curve's base ATA to
/// `associated_base_user` (#15).
fn mock_pump(ic: &mut InvokeContext) -> Result<(), InstructionError> {
    let x = read_ix(ic)?;
    if x.keys.len() != 27 {
        return Err(InstructionError::MissingAccount);
    }
    let v = u64_le(&x.data, 8);
    let (mint, quote_mint, base_tp) = (x.keys[1], x.keys[2], x.keys[3]);
    let (curve, curve_base, curve_quote, user, user_base, user_quote) =
        (x.keys[10], x.keys[11], x.keys[12], x.keys[13], x.keys[14], x.keys[15]);
    let cd = &x.acc_data[10];
    let (vt, vq) = (u64_le(cd, 8), u64_le(cd, 16));
    let tokens = cp_out(v, vq, vt);
    let is_sol = quote_mint == pk(sijka_vault::constants::WSOL_MINT);
    if is_sol {
        invoke(ic, sys_transfer(user, curve, v), &[])?;
    } else {
        invoke(ic, transfer_checked(tokenkeg(), user_quote, quote_mint, curve_quote, user, v, 6), &[])?;
    }
    let (_, bump) = Pubkey::find_program_address(&[b"bonding-curve", mint.as_ref()], &x.program);
    let seeds: &[&[u8]] = &[b"bonding-curve", mint.as_ref(), &[bump]];
    invoke(ic, transfer_checked(base_tp, curve_base, mint, user_base, curve, tokens, 6), &[seeds])?;
    // fee_recipient (#7, W) and its quote ATA (#8, W).
    evil(ic, &x, user, user_base, user_quote, base_tp, x.keys[6], x.keys[6], x.keys[7])
}

/// pump_amm `buy_exact_quote_in`: 26 accounts (SPEC §5.5.3). Honest part:
/// quote from `user_quote_token_account` (#7) to the pool, tokens from the
/// pool's base account to `user_base_token_account` (#6).
fn mock_pump_amm(ic: &mut InvokeContext) -> Result<(), InstructionError> {
    let x = read_ix(ic)?;
    if x.keys.len() != 26 {
        return Err(InstructionError::MissingAccount);
    }
    let v = u64_le(&x.data, 8);
    let (pool, user, mint, quote_mint, user_base, user_quote, pool_base, pool_quote) =
        (x.keys[0], x.keys[1], x.keys[3], x.keys[4], x.keys[5], x.keys[6], x.keys[7], x.keys[8]);
    let base_tp = x.keys[11];
    let b = u64_le(&x.acc_data[7], 64);
    let q = u64_le(&x.acc_data[8], 64);
    let tokens = cp_out(v, q, b);
    invoke(
        ic,
        transfer_checked(tokenkeg(), user_quote, quote_mint, pool_quote, user, v, quote_decimals(&quote_mint)),
        &[],
    )?;
    let pool_authority = Pubkey::find_program_address(&[b"pool-authority", mint.as_ref()], &crate::harness::pump()).0;
    let (_, bump) = Pubkey::find_program_address(
        &[b"pool", &[0, 0], pool_authority.as_ref(), mint.as_ref(), quote_mint.as_ref()],
        &x.program,
    );
    let seeds: &[&[u8]] = &[b"pool", &[0, 0], pool_authority.as_ref(), mint.as_ref(), quote_mint.as_ref(), &[bump]];
    invoke(ic, transfer_checked(base_tp, pool_base, mint, user_base, pool, tokens, 6), &[seeds])?;
    // protocol_fee_recipient (#10, R) and its token account (#11, W).
    evil(ic, &x, user, user_base, user_quote, base_tp, x.keys[9], x.keys[10], x.keys[10])
}

/// One abuse of the `user` signature after the honest buy (review RT-2).
/// `other`: an unrelated key of the instruction (delegate / new authority);
/// `close_dest`: a writable account for lamports; `quote_dest`: a token
/// account of the quote mint to move funds to.
fn evil(
    ic: &mut InvokeContext,
    x: &Ix,
    user: Pubkey,
    user_base: Pubkey,
    user_quote: Pubkey,
    base_tp: Pubkey,
    other: Pubkey,
    close_dest: Pubkey,
    quote_dest: Pubkey,
) -> Result<(), InstructionError> {
    let tk = tokenkeg();
    match PUMP_EVIL.with(|p| p.get()) {
        PumpEvil::Honest => Ok(()),
        PumpEvil::AssignUser => invoke(ic, sys_assign(user, x.program), &[]),
        PumpEvil::AllocateUser => invoke(ic, sys_allocate(user, 8), &[]),
        PumpEvil::ApproveBase => invoke(ic, approve(base_tp, user_base, other, user, 1), &[]),
        PumpEvil::ApproveQuote => invoke(ic, approve(tk, user_quote, other, user, 1), &[]),
        PumpEvil::SetOwnerQuote => invoke(ic, set_authority(tk, user_quote, user, 2, other), &[]),
        PumpEvil::SetCloseAuthorityBase => invoke(ic, set_authority(base_tp, user_base, user, 3, other), &[]),
        PumpEvil::SetCloseAuthorityQuote => invoke(ic, set_authority(tk, user_quote, user, 3, other), &[]),
        PumpEvil::CloseQuote => invoke(ic, close_account(tk, user_quote, close_dest, user), &[]),
        PumpEvil::TransferQuoteOut => invoke(ic, token_transfer(tk, user_quote, quote_dest, user, 1), &[]),
    }
}

// --------------------------------------------------------- CPI wrapper ----

declare_process_instruction!(CpiWrapper, 1_000, |invoke_context| { cpi_wrapper(invoke_context) });

fn cpi_wrapper(ic: &mut InvokeContext) -> Result<(), InstructionError> {
    let x = read_ix(ic)?;
    let program = *x.keys.first().ok_or(InstructionError::MissingAccount)?;
    let accounts = x.keys.iter().zip(&x.signer).zip(&x.writable).skip(1).map(|((k, s), w)| meta(*k, *w, *s)).collect();
    invoke(ic, Instruction { program_id: program, accounts, data: x.data.clone() }, &[])
}

/// Wrap `ix` into a call through the CPI wrapper (stack height 2).
pub fn wrap_cpi(ix: Instruction) -> Instruction {
    let mut accounts = vec![AccountMeta::new_readonly(ix.program_id, false)];
    accounts.extend(ix.accounts);
    Instruction { program_id: cpi_wrapper_id(), accounts, data: ix.data }
}
