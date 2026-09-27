// Copyright (c) 2026 prt1sn. All rights reserved.
//! Builders of Jupiter route data / accounts for the mock (and the same
//! layouts for the real Jupiter binary) and of the vault's tag 20 instruction.

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use solana_signer::Signer;

use crate::harness::{Env, KEEPER_SLIPPAGE_BPS, jup6, keeper_min_out, system_program, token_program, wsol_mint};

pub const DISC_ROUTE: [u8; 8] = [0xe5, 0x17, 0xcb, 0x97, 0x7a, 0xe3, 0xad, 0x2a];
pub const DISC_SHARED: [u8; 8] = [0xc1, 0x20, 0x9b, 0x33, 0x41, 0xd6, 0x9c, 0x81];
pub const DISC_ROUTE_V2: [u8; 8] = [0xbb, 0x64, 0xfa, 0xcc, 0x31, 0xc4, 0xaf, 0x14];
pub const DISC_SHARED_V2: [u8; 8] = [0xd1, 0x98, 0x53, 0x93, 0x7c, 0xfe, 0xd8, 0xe9];

/// Mock behaviours (must match `tests/mock-jupiter/src/lib.rs`).
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Route,
    Shared,
    RouteV2,
    SharedV2,
}

pub const ALL_KINDS: [Kind; 4] = [Kind::RouteV2, Kind::SharedV2, Kind::Route, Kind::Shared];

impl Kind {
    /// `jup_kind` of `SJKEVSWI`.
    pub fn code(self) -> u64 {
        match self {
            Kind::Route => 0,
            Kind::Shared => 1,
            Kind::RouteV2 => 2,
            Kind::SharedV2 => 3,
        }
    }
    pub fn fixed(self) -> usize {
        match self {
            Kind::Route => 9,
            Kind::Shared => 13,
            Kind::RouteV2 => 10,
            Kind::SharedV2 => 12,
        }
    }
}

/// Fixed arguments of the Jupiter instruction.
#[derive(Clone, Copy, Debug)]
pub struct Args {
    pub in_amount: u64,
    pub quoted_out: u64,
    pub slippage_bps: u16,
    /// v2: u16; v1: the u8 at the end.
    pub platform_fee_bps: u16,
    pub positive_slippage_bps: u16,
}

impl Args {
    pub fn new(in_amount: u64) -> Self {
        Args { in_amount, quoted_out: 1, slippage_bps: 50, platform_fee_bps: 0, positive_slippage_bps: 0 }
    }
}

/// Mock step: `mode u8 | out u64 | arg u64`.
pub fn mock_step(mode: u8, out: u64, arg: u64) -> Vec<u8> {
    let mut s = vec![mode];
    s.extend_from_slice(&out.to_le_bytes());
    s.extend_from_slice(&arg.to_le_bytes());
    s
}

/// Jupiter instruction data with `steps` as the (opaque) route plan body.
pub fn jup_data(kind: Kind, a: &Args, steps: &[u8]) -> Vec<u8> {
    let mut d = Vec::new();
    match kind {
        Kind::RouteV2 | Kind::SharedV2 => {
            d.extend_from_slice(if kind == Kind::RouteV2 { &DISC_ROUTE_V2 } else { &DISC_SHARED_V2 });
            if kind == Kind::SharedV2 {
                d.push(3); // id
            }
            d.extend_from_slice(&a.in_amount.to_le_bytes());
            d.extend_from_slice(&a.quoted_out.to_le_bytes());
            d.extend_from_slice(&a.slippage_bps.to_le_bytes());
            d.extend_from_slice(&a.platform_fee_bps.to_le_bytes());
            d.extend_from_slice(&a.positive_slippage_bps.to_le_bytes());
            d.extend_from_slice(&1u32.to_le_bytes());
            d.extend_from_slice(steps);
        }
        Kind::Route | Kind::Shared => {
            d.extend_from_slice(if kind == Kind::Route { &DISC_ROUTE } else { &DISC_SHARED });
            if kind == Kind::Shared {
                d.push(3);
            }
            d.extend_from_slice(&1u32.to_le_bytes());
            d.extend_from_slice(steps);
            d.extend_from_slice(&a.in_amount.to_le_bytes());
            d.extend_from_slice(&a.quoted_out.to_le_bytes());
            d.extend_from_slice(&a.slippage_bps.to_le_bytes());
            d.push(u8::try_from(a.platform_fee_bps).unwrap());
        }
    }
    d
}

/// Keys that stand for Jupiter's own accounts in the mock routes.
pub fn event_authority() -> Pubkey {
    Pubkey::find_program_address(&[b"__event_authority"], &jup6()).0
}
pub fn program_authority() -> Pubkey {
    Pubkey::new_from_array([0x70; 32])
}
pub fn program_src() -> Pubkey {
    Pubkey::new_from_array([0x71; 32])
}
pub fn program_dst() -> Pubkey {
    Pubkey::new_from_array([0x72; 32])
}

/// Route accounts: the fixed slots of `kind` for `src → dst` (+ mints) plus
/// the mock's remaining accounts `[pool_authority, pool_wsol, pool_usdc,
/// attacker_usdc, attacker, system, token]` and `extra`.
pub fn route_accounts(env: &Env, kind: Kind, extra: &[AccountMeta]) -> Vec<AccountMeta> {
    let k = &env.k;
    let sa = AccountMeta::new_readonly(k.swap_authority, false);
    let src = AccountMeta::new(k.swap_wsol, false);
    let dst = AccountMeta::new(k.swap_usdc, false);
    let ro = AccountMeta::new_readonly;
    let none = ro(jup6(), false);
    let mut v = match kind {
        Kind::RouteV2 => vec![
            sa,
            src,
            dst,
            ro(wsol_mint(), false),
            ro(k.usdc_mint, false),
            ro(token_program(), false),
            ro(token_program(), false),
            none,
            ro(event_authority(), false),
            ro(jup6(), false),
        ],
        Kind::SharedV2 => vec![
            ro(program_authority(), false),
            sa,
            src,
            AccountMeta::new(program_src(), false),
            AccountMeta::new(program_dst(), false),
            dst,
            ro(wsol_mint(), false),
            ro(k.usdc_mint, false),
            ro(token_program(), false),
            ro(token_program(), false),
            ro(event_authority(), false),
            ro(jup6(), false),
        ],
        Kind::Route => vec![
            ro(token_program(), false),
            sa,
            src,
            dst,
            none.clone(),
            ro(k.usdc_mint, false),
            none,
            ro(event_authority(), false),
            ro(jup6(), false),
        ],
        Kind::Shared => vec![
            ro(token_program(), false),
            ro(program_authority(), false),
            sa,
            src,
            AccountMeta::new(program_src(), false),
            AccountMeta::new(program_dst(), false),
            dst,
            ro(wsol_mint(), false),
            ro(k.usdc_mint, false),
            none.clone(),
            none,
            ro(event_authority(), false),
            ro(jup6(), false),
        ],
    };
    v.extend([
        ro(env.pool_authority, false),
        AccountMeta::new(env.pool_wsol, false),
        AccountMeta::new(env.pool_usdc, false),
        AccountMeta::new(env.attacker_usdc, false),
        AccountMeta::new(env.attacker.pubkey(), false),
        ro(system_program(), false),
        ro(token_program(), false),
    ]);
    v.extend_from_slice(extra);
    v
}

/// The 10 fixed accounts of tag 20 (SPEC §5.3.4). SPEC v4: #6 is the keeper
/// signer (it was the oracle); the keeper is also the fee payer of `send`.
pub fn swap_fixed(env: &Env, keeper: Pubkey) -> Vec<AccountMeta> {
    let k = &env.k;
    vec![
        AccountMeta::new(k.config, false),
        AccountMeta::new(k.fee_inbox, false),
        AccountMeta::new_readonly(k.swap_authority, false),
        AccountMeta::new(k.swap_wsol, false),
        AccountMeta::new(k.swap_usdc, false),
        AccountMeta::new(k.vault_usdc, false),
        AccountMeta::new_readonly(keeper, true),
        AccountMeta::new_readonly(token_program(), false),
        AccountMeta::new_readonly(system_program(), false),
        AccountMeta::new_readonly(jup6(), false),
    ]
}

/// Tag 20 data: `tag | amount_in | min_out | jup_len | jup data` (SPEC v4:
/// `min_out` is the keeper's, the only price limit).
pub fn swap_data(amount_in: u64, min_out: u64, jup: &[u8]) -> Vec<u8> {
    let mut d = vec![20u8];
    d.extend_from_slice(&amount_in.to_le_bytes());
    d.extend_from_slice(&min_out.to_le_bytes());
    d.extend_from_slice(&u16::try_from(jup.len()).unwrap().to_le_bytes());
    d.extend_from_slice(jup);
    d
}

/// A complete tag 20 instruction.
pub struct Swap {
    pub fixed: Vec<AccountMeta>,
    pub route: Vec<AccountMeta>,
    pub amount_in: u64,
    pub min_out: u64,
    pub jup: Vec<u8>,
}

impl Swap {
    /// Mock route of `kind` in `mode` paying `out` (`arg` per mode), signed
    /// by the keeper with the keeper's default `min_out` (quote at the fixture
    /// SOL mark minus `KEEPER_SLIPPAGE_BPS`).
    pub fn mock(env: &Env, kind: Kind, amount_in: u64, mode: u8, out: u64, arg: u64) -> Swap {
        Swap {
            fixed: swap_fixed(env, env.keeper.pubkey()),
            route: route_accounts(env, kind, &[]),
            amount_in,
            min_out: keeper_min_out(amount_in, env.pam_px(), KEEPER_SLIPPAGE_BPS),
            jup: jup_data(kind, &Args::new(amount_in), &mock_step(mode, out, arg)),
        }
    }

    pub fn ix(&self, env: &Env) -> Instruction {
        let mut accounts = self.fixed.clone();
        accounts.extend_from_slice(&self.route);
        Instruction { program_id: env.k.program, accounts, data: swap_data(self.amount_in, self.min_out, &self.jup) }
    }
}
