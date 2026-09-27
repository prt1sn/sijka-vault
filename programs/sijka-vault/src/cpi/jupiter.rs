// Copyright (c) 2026 prt1sn. All rights reserved.
//! Jupiter v6 CPI (SPEC §5.3.3), shared by tags 20 (inflow) and 43 (buyback).
//!
//! - Only exact-in `route`, `shared_accounts_route`, `route_v2`,
//!   `shared_accounts_route_v2` (discriminators in `crate::constants`).
//! - [`validate_route`] runs before the CPI: tail size, discriminator, argument
//!   checks, slot pinning, swap-authority token account scan, protected keys.
//!   It returns a [`ValidatedRoute`], which only it can build and which holds
//!   exactly the accounts, data and policy it checked.
//! - [`invoke_route`] takes that token (by value, so once): a caller cannot
//!   reach the CPI with an unvalidated or different route. The validation runs
//!   once per call (test finding BUG-inflow-1: the second pass cost ≈ 10.5k
//!   CU). Between the two, callers only move amounts on the allowed swap
//!   accounts or create one of them (tag 43 `bb_unwrap`), which cannot change
//!   the validation result. `invoke_route` builds metas in the original tail order
//!   (`is_signer = key == swap_authority`, `is_writable` from the outer
//!   instruction), signs only `["swap", bump]`, calls
//!   `crate::cpi_tramp::cpi_signed`, and runs `post_route_check` immediately
//!   after the CPI (review RT-1): full `check_token` of every allowed swap
//!   account and `swap_authority` lamports / owner System / no data, else
//!   `SwapAccountTampered`. Callers cannot skip it.
//!
//! Balance checks (input spent, output received against the keeper's
//! `min_out`, SPEC v4) are the caller's job and must come after `invoke_route`
//! returns.

use pinocchio::ProgramResult;
use pinocchio::account_info::AccountInfo;
use pinocchio::instruction::{AccountMeta, Instruction, Signer};
use pinocchio::program_error::ProgramError;
use pinocchio::pubkey::{Pubkey, pubkey_eq};

use crate::constants::{
    JUP_ROUTE, JUP_ROUTE_V2, JUP_SHARED_ACCOUNTS_ROUTE, JUP_SHARED_ACCOUNTS_ROUTE_V2, JUPITER_V6, MAX_ROUTE_ACCOUNTS,
    SEED_SWAP_AUTHORITY, SPL_TOKEN_PROGRAM_ID, SYSTEM_PROGRAM_ID, TOKEN_2022_PROGRAM_ID, TOKEN_ACCOUNT_LEN,
};
use crate::cpi::PdaSeeds;
use crate::cpi_tramp::cpi_signed;
use crate::error::SijkaError;
use crate::external::layout::token_account as ta;
use crate::util::accounts::{check_token, expect_program};
use crate::util::bytes::{array_ref, is_zero_key, read_key, read_u8, read_u16, read_u64};

/// Which Jupiter instruction the route uses (event field `jup_kind`).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JupKind {
    Route = 0,
    SharedAccountsRoute = 1,
    RouteV2 = 2,
    SharedAccountsRouteV2 = 3,
}

impl JupKind {
    /// Kind from the first 8 bytes of the Jupiter instruction data; `None` for
    /// anything outside the four allowed exact-in instructions.
    pub fn from_data(data: &[u8]) -> Option<Self> {
        let d = array_ref::<8>(data, 0)?;
        if d == &JUP_ROUTE {
            Some(Self::Route)
        } else if d == &JUP_SHARED_ACCOUNTS_ROUTE {
            Some(Self::SharedAccountsRoute)
        } else if d == &JUP_ROUTE_V2 {
            Some(Self::RouteV2)
        } else if d == &JUP_SHARED_ACCOUNTS_ROUTE_V2 {
            Some(Self::SharedAccountsRouteV2)
        } else {
            None
        }
    }

    /// Fixed-slot indices of this instruction (SPEC §5.3.3 step 4 table).
    const fn pins(self) -> &'static Pins {
        match self {
            Self::Route => &PINS_ROUTE,
            Self::SharedAccountsRoute => &PINS_SHARED,
            Self::RouteV2 => &PINS_ROUTE_V2,
            Self::SharedAccountsRouteV2 => &PINS_SHARED_V2,
        }
    }
}

/// Slot indices pinned by SPEC §5.3.3 step 4 ("None" = `JUPITER_V6`).
struct Pins {
    authority: usize,
    src: usize,
    dst: usize,
    /// `destination_token_account` (optional): None or `dst`.
    dst_opt: Option<usize>,
    src_mint: Option<usize>,
    dst_mint: usize,
    /// Token program slots, all `== Tokenkeg`.
    token_programs: &'static [usize],
    /// `platform_fee_account` (v1): must be None.
    fee_none: Option<usize>,
    /// `program` slot `== JUPITER_V6`; the largest pinned index.
    program: usize,
}

const PINS_ROUTE: Pins = Pins {
    authority: 1,
    src: 2,
    dst: 3,
    dst_opt: Some(4),
    src_mint: None,
    dst_mint: 5,
    token_programs: &[0],
    fee_none: Some(6),
    program: 8,
};
const PINS_SHARED: Pins = Pins {
    authority: 2,
    src: 3,
    dst: 6,
    dst_opt: None,
    src_mint: Some(7),
    dst_mint: 8,
    token_programs: &[0],
    fee_none: Some(9),
    program: 12,
};
const PINS_ROUTE_V2: Pins = Pins {
    authority: 0,
    src: 1,
    dst: 2,
    dst_opt: Some(7),
    src_mint: Some(3),
    dst_mint: 4,
    token_programs: &[5, 6],
    fee_none: None,
    program: 9,
};
const PINS_SHARED_V2: Pins = Pins {
    authority: 1,
    src: 2,
    dst: 5,
    dst_opt: None,
    src_mint: Some(6),
    dst_mint: 7,
    token_programs: &[8, 9],
    fee_none: None,
    program: 11,
};

/// v1 fixed arguments sit after the variable `route_plan`: `in_amount u64`,
/// `quoted_out u64`, `slippage_bps u16`, `platform_fee_bps u8` = 19 bytes.
const V1_TAIL: usize = 19;
/// Minimal data lengths (SPEC §5.3.3 step 3).
const MIN_LEN_ROUTE: usize = 8 + 4 + V1_TAIL;
const MIN_LEN_SHARED: usize = 8 + 1 + 4 + V1_TAIL;
const MIN_LEN_ROUTE_V2: usize = 34;
const MIN_LEN_SHARED_V2: usize = 35;

/// A token account the route may use, with its expected mint and native flag
/// (review RT-1). Always an SPL Token (Tokenkeg) account owned by
/// `swap_authority`.
pub struct SwapAcc<'a> {
    pub info: &'a AccountInfo,
    pub mint: &'a Pubkey,
    pub native: bool,
}

/// What the program allows the route to do.
pub struct RoutePolicy<'a> {
    pub swap_authority: &'a AccountInfo,
    pub swap_bump: u8,
    pub expect_in_amount: u64,
    pub src: &'a Pubkey,
    pub dst: &'a Pubkey,
    pub src_mint: &'a Pubkey,
    pub dst_mint: &'a Pubkey,
    /// Tag 20: `[swap_wsol (WSOL, native), swap_usdc (usdc)]`;
    /// tag 43: `[swap_usdc (usdc), bb_unwrap (WSOL, native)]`.
    pub allowed_swap_accounts: &'a [SwapAcc<'a>],
    /// Keys that must not appear anywhere in the route. All-zero entries
    /// ("not set", e.g. `buyback_token` before `set_token_mint`) are ignored:
    /// the zero key is the System program, which routes legitimately contain.
    pub protected_keys: &'a [&'a Pubkey],
}

/// A route that passed [`validate_route`]. The fields are private, so only
/// `validate_route` builds it; it is neither `Clone` nor `Copy`, and
/// [`invoke_route`] consumes it.
pub struct ValidatedRoute<'r, 'p> {
    jup: &'r AccountInfo,
    route: &'r [AccountInfo],
    data: &'r [u8],
    policy: &'r RoutePolicy<'p>,
    kind: JupKind,
}

impl ValidatedRoute<'_, '_> {
    /// The Jupiter instruction of the route (event field `jup_kind`).
    pub fn kind(&self) -> JupKind {
        self.kind
    }
}

/// Pre-CPI route validation (SPEC §5.3.3 steps 1–6). Also checks the program
/// account (`JUPITER_V6`, executable) and that `swap_authority` is read-only.
pub fn validate_route<'r, 'p>(
    jup: &'r AccountInfo,
    route: &'r [AccountInfo],
    data: &'r [u8],
    p: &'r RoutePolicy<'p>,
) -> Result<ValidatedRoute<'r, 'p>, ProgramError> {
    // 1. Tail size.
    if route.is_empty() || route.len() > MAX_ROUTE_ACCOUNTS {
        return Err(SijkaError::JupiterTooManyAccounts.fail());
    }
    expect_program(jup, &JUPITER_V6)?;
    if p.swap_authority.is_writable() {
        return Err(SijkaError::AccountMustBeReadonly.fail());
    }
    // 2. Discriminator.
    let kind = JupKind::from_data(data).ok_or_else(|| SijkaError::JupiterIxForbidden.fail())?;
    // 3. Arguments.
    check_args(kind, data, p.expect_in_amount).map_err(SijkaError::fail)?;
    // 4. Pinned slots.
    check_pins(kind, route, p).map_err(SijkaError::fail)?;
    // 5. + 6. Token accounts of swap_authority must be allowed; no protected key.
    let sa = p.swap_authority.key();
    for a in route {
        let k = a.key();
        if p.protected_keys.iter().any(|pk| !is_zero_key(pk) && pubkey_eq(pk, k)) {
            return Err(SijkaError::JupiterAccountForbidden.fail());
        }
        if is_token_account_of(a, sa)? && !p.allowed_swap_accounts.iter().any(|s| pubkey_eq(s.info.key(), k)) {
            return Err(SijkaError::JupiterAccountForbidden.fail());
        }
    }
    Ok(ValidatedRoute { jup, route, data, policy: p, kind })
}

/// SPEC §5.3.3 step 3: v2 arguments are parsed from the front and checked
/// strictly; v1 arguments are parsed from the tail as a sanity check only (the
/// v1 fee is excluded by the fee-account slot pin, U-21/U-22).
fn check_args(kind: JupKind, data: &[u8], expect_in: u64) -> Result<(), SijkaError> {
    let v2 = |min: usize, off: usize| {
        let pf = off.checked_add(18);
        let pos = off.checked_add(20);
        data.len() >= min
            && read_u64(data, off) == Some(expect_in)
            && pf.and_then(|o| read_u16(data, o)) == Some(0)
            && pos.and_then(|o| read_u16(data, o)) == Some(0)
    };
    let v1 = |min: usize| {
        let len = data.len();
        len >= min
            && len.checked_sub(V1_TAIL).and_then(|o| read_u64(data, o)) == Some(expect_in)
            && len.checked_sub(1).and_then(|o| read_u8(data, o)) == Some(0)
    };
    let ok = match kind {
        // in @8, quoted @16, slippage @24, platform_fee_bps @26, positive_slippage_bps @28.
        JupKind::RouteV2 => v2(MIN_LEN_ROUTE_V2, 8),
        // id @8, then the same fields shifted by one.
        JupKind::SharedAccountsRouteV2 => v2(MIN_LEN_SHARED_V2, 9),
        JupKind::Route => v1(MIN_LEN_ROUTE),
        JupKind::SharedAccountsRoute => v1(MIN_LEN_SHARED),
    };
    if ok { Ok(()) } else { Err(SijkaError::JupiterArgsMismatch) }
}

/// SPEC §5.3.3 step 4: authority, src, dst, optional destination, mints,
/// token programs, fee account and program in their slots.
fn check_pins(kind: JupKind, route: &[AccountInfo], p: &RoutePolicy<'_>) -> Result<(), SijkaError> {
    const E: SijkaError = SijkaError::JupiterRoutePinMismatch;
    let pins = kind.pins();
    if route.len() <= pins.program {
        return Err(E);
    }
    let key = |i: usize| route.get(i).map(AccountInfo::key).ok_or(E);
    let eq = |i: usize, want: &Pubkey| if pubkey_eq(key(i)?, want) { Ok(()) } else { Err(E) };
    eq(pins.authority, p.swap_authority.key())?;
    eq(pins.src, p.src)?;
    eq(pins.dst, p.dst)?;
    if let Some(i) = pins.dst_opt {
        let k = key(i)?;
        if !pubkey_eq(k, &JUPITER_V6) && !pubkey_eq(k, p.dst) {
            return Err(E);
        }
    }
    if let Some(i) = pins.src_mint {
        eq(i, p.src_mint)?;
    }
    eq(pins.dst_mint, p.dst_mint)?;
    for i in pins.token_programs {
        eq(*i, &SPL_TOKEN_PROGRAM_ID)?;
    }
    if let Some(i) = pins.fee_none {
        eq(i, &JUPITER_V6)?;
    }
    eq(pins.program, &JUPITER_V6)
}

/// SPEC §5.3.3 step 5: owner Tokenkeg or Token-2022, `data_len ≥ 165` and
/// `owner@32 == swap_authority`.
fn is_token_account_of(a: &AccountInfo, authority: &Pubkey) -> Result<bool, ProgramError> {
    if !(a.is_owned_by(&SPL_TOKEN_PROGRAM_ID) || a.is_owned_by(&TOKEN_2022_PROGRAM_ID))
        || a.data_len() < TOKEN_ACCOUNT_LEN
    {
        return Ok(false);
    }
    let data = a.try_borrow_data()?;
    Ok(read_key(&data, ta::OWNER).is_some_and(|o| pubkey_eq(o, authority)))
}

/// CPI into Jupiter with the mandatory `post_route_check` inside.
///
/// Only a [`ValidatedRoute`] can be invoked. Metas keep the outer order and
/// writability; only `swap_authority` is marked signer (its signature comes
/// from `["swap", bump]`), every other account is passed as non-signer.
#[inline(never)]
pub fn invoke_route(v: ValidatedRoute<'_, '_>) -> ProgramResult {
    let ValidatedRoute { jup, route, data, policy: p, .. } = v;
    let n = route.len();
    let first = route.first().ok_or_else(|| SijkaError::JupiterTooManyAccounts.fail())?;
    let sa = p.swap_authority.key();
    // Fixed-size buffers in this frame (1024 + 512 bytes); only `..n` is used.
    let mut metas = [const { AccountMeta::readonly(&JUPITER_V6) }; MAX_ROUTE_ACCOUNTS];
    let mut infos: [&AccountInfo; MAX_ROUTE_ACCOUNTS] = [first; MAX_ROUTE_ACCOUNTS];
    for ((m, slot), a) in metas.iter_mut().zip(infos.iter_mut()).zip(route) {
        *m = AccountMeta::new(a.key(), a.is_writable(), pubkey_eq(a.key(), sa));
        *slot = a;
    }
    let (Some(metas), Some(infos)) = (metas.get(..n), infos.get(..n)) else {
        return Err(SijkaError::JupiterTooManyAccounts.fail());
    };
    let ix = Instruction { program_id: jup.key(), accounts: metas, data };
    let a0 = p.swap_authority.lamports();
    let pda = PdaSeeds::new(SEED_SWAP_AUTHORITY, p.swap_bump);
    let seeds = pda.seeds();
    let signer = [Signer::from(&seeds)];
    cpi_signed(&ix, infos, &signer)?;
    post_route_check(p, a0)
}

/// Review RT-1: right after the Jupiter CPI and before any balance check,
/// every allowed swap account passes the full `check_token` again (no
/// delegate, no close authority, Initialized, native flag, Tokenkeg, 165
/// bytes, mint, authority), and `swap_authority` still has `a0` lamports,
/// owner System and no data. Else `SwapAccountTampered`.
pub(crate) fn post_route_check(p: &RoutePolicy<'_>, a0: u64) -> ProgramResult {
    let sa = p.swap_authority;
    for s in p.allowed_swap_accounts {
        check_token(s.info, &SPL_TOKEN_PROGRAM_ID, s.mint, sa.key(), s.native, SijkaError::SwapAccountTampered)?;
    }
    if sa.lamports() != a0 || !sa.is_owned_by(&SYSTEM_PROGRAM_ID) || sa.data_len() != 0 {
        return Err(SijkaError::SwapAccountTampered.fail());
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::constants::WSOL_MINT;
    use crate::util::test_utils::TestAccount;

    pub const SA: Pubkey = [0x5A; 32];
    pub const WSOL_ACC: Pubkey = [0x51; 32];
    pub const USDC_ACC: Pubkey = [0x52; 32];
    pub const USDC: Pubkey = [0x0C; 32];
    const EVENT_AUTH: Pubkey = [0xEE; 32];
    const AMM: Pubkey = [0xA1; 32];
    const PROTECTED: Pubkey = [0x99; 32];

    pub fn token(mint: &Pubkey, owner: &Pubkey, amount: u64, native: bool) -> Vec<u8> {
        let mut d = vec![0u8; TOKEN_ACCOUNT_LEN];
        d[0..32].copy_from_slice(mint);
        d[32..64].copy_from_slice(owner);
        d[64..72].copy_from_slice(&amount.to_le_bytes());
        d[108] = 1;
        if native {
            d[109..113].copy_from_slice(&1u32.to_le_bytes());
            d[113..121].copy_from_slice(&2_039_280u64.to_le_bytes());
        }
        d
    }

    /// Test accounts of a route; `accs[i]` backs `route[i]`.
    pub struct World {
        pub sa: TestAccount,
        pub wsol: TestAccount,
        pub usdc: TestAccount,
        pub jup: TestAccount,
        pub route: Vec<TestAccount>,
    }

    fn plain(k: Pubkey) -> TestAccount {
        TestAccount::plain(k, [0x77; 32], &[])
    }

    pub fn world(keys: &[Pubkey]) -> World {
        let route = keys
            .iter()
            .map(|k| match *k {
                WSOL_ACC => TestAccount::new(
                    *k,
                    SPL_TOKEN_PROGRAM_ID,
                    3_000_000,
                    &token(&WSOL_MINT, &SA, 1_000, true),
                    false,
                    true,
                    false,
                ),
                USDC_ACC => TestAccount::new(
                    *k,
                    SPL_TOKEN_PROGRAM_ID,
                    2_000_000,
                    &token(&USDC, &SA, 5, false),
                    false,
                    true,
                    false,
                ),
                SA => TestAccount::new(SA, SYSTEM_PROGRAM_ID, 0, &[], false, false, false),
                _ => plain(*k),
            })
            .collect();
        World {
            sa: TestAccount::new(SA, SYSTEM_PROGRAM_ID, 0, &[], false, false, false),
            wsol: TestAccount::new(
                WSOL_ACC,
                SPL_TOKEN_PROGRAM_ID,
                3_000_000,
                &token(&WSOL_MINT, &SA, 1_000, true),
                false,
                true,
                false,
            ),
            usdc: TestAccount::new(
                USDC_ACC,
                SPL_TOKEN_PROGRAM_ID,
                2_000_000,
                &token(&USDC, &SA, 5, false),
                false,
                true,
                false,
            ),
            jup: TestAccount::new(JUPITER_V6, [0x33; 32], 1, &[], false, false, true),
            route,
        }
    }

    pub fn route_v2_keys() -> Vec<Pubkey> {
        vec![
            SA,
            WSOL_ACC,
            USDC_ACC,
            WSOL_MINT,
            USDC,
            SPL_TOKEN_PROGRAM_ID,
            SPL_TOKEN_PROGRAM_ID,
            JUPITER_V6,
            EVENT_AUTH,
            JUPITER_V6,
            AMM,
            SA,
            WSOL_ACC,
            USDC_ACC,
        ]
    }

    fn shared_v2_keys() -> Vec<Pubkey> {
        vec![
            [0x70; 32],
            SA,
            WSOL_ACC,
            [0x71; 32],
            [0x72; 32],
            USDC_ACC,
            WSOL_MINT,
            USDC,
            SPL_TOKEN_PROGRAM_ID,
            SPL_TOKEN_PROGRAM_ID,
            EVENT_AUTH,
            JUPITER_V6,
            AMM,
        ]
    }

    fn route_v1_keys() -> Vec<Pubkey> {
        vec![SPL_TOKEN_PROGRAM_ID, SA, WSOL_ACC, USDC_ACC, JUPITER_V6, USDC, JUPITER_V6, EVENT_AUTH, JUPITER_V6, AMM]
    }

    fn shared_v1_keys() -> Vec<Pubkey> {
        vec![
            SPL_TOKEN_PROGRAM_ID,
            [0x70; 32],
            SA,
            WSOL_ACC,
            [0x71; 32],
            [0x72; 32],
            USDC_ACC,
            WSOL_MINT,
            USDC,
            JUPITER_V6,
            JUPITER_V6,
            EVENT_AUTH,
            JUPITER_V6,
            AMM,
        ]
    }

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace() && *c != '|').collect();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// Live `route_v2` sample (appendix C §5.3): in = 1e9, 40 bytes.
    pub fn route_v2_data() -> Vec<u8> {
        hex("bb64facc31c4af14 | 00ca9a3b00000000 | cfa31a0700000000 | 3200 | 0000 | 0000 | 01000000 | b501 1027 00 01")
    }

    fn shared_v2_data() -> Vec<u8> {
        let mut d = JUP_SHARED_ACCOUNTS_ROUTE_V2.to_vec();
        d.push(3); // id
        d.extend_from_slice(&1_000_000_000u64.to_le_bytes());
        d.extend_from_slice(&119_186_383u64.to_le_bytes());
        d.extend_from_slice(&50u16.to_le_bytes());
        d.extend_from_slice(&[0, 0, 0, 0]);
        d.extend_from_slice(&1u32.to_le_bytes());
        d.extend_from_slice(&hex("b501 1027 00 01"));
        d
    }

    /// v1 layout (appendix C §5.3): disc | vec len | step | in | quoted | slippage | pf.
    fn v1_data(disc: [u8; 8], shared: bool, in_amount: u64, pf: u8) -> Vec<u8> {
        let mut d = disc.to_vec();
        if shared {
            d.push(3);
        }
        d.extend_from_slice(&1u32.to_le_bytes());
        d.extend_from_slice(&hex("b5 01 64 00 01"));
        d.extend_from_slice(&in_amount.to_le_bytes());
        d.extend_from_slice(&119_186_383u64.to_le_bytes());
        d.extend_from_slice(&50u16.to_le_bytes());
        d.push(pf);
        d
    }

    pub fn policy<'a>(w: &'a World, allowed: &'a [SwapAcc<'a>], protected: &'a [&'a Pubkey]) -> RoutePolicy<'a> {
        let sa = Box::leak(Box::new(w.sa.info()));
        RoutePolicy {
            swap_authority: sa,
            swap_bump: 255,
            expect_in_amount: 1_000_000_000,
            src: &WSOL_ACC,
            dst: &USDC_ACC,
            src_mint: &WSOL_MINT,
            dst_mint: &USDC,
            allowed_swap_accounts: allowed,
            protected_keys: protected,
        }
    }

    fn run(keys: &[Pubkey], data: &[u8]) -> Result<JupKind, ProgramError> {
        run_with(keys, data, |_| {})
    }

    fn run_with(keys: &[Pubkey], data: &[u8], edit: impl FnOnce(&mut World)) -> Result<JupKind, ProgramError> {
        let mut w = world(keys);
        edit(&mut w);
        let wsol = w.wsol.info();
        let usdc = w.usdc.info();
        let allowed = [
            SwapAcc { info: &wsol, mint: &WSOL_MINT, native: true },
            SwapAcc { info: &usdc, mint: &USDC, native: false },
        ];
        let protected: [&Pubkey; 2] = [&PROTECTED, &[0u8; 32]];
        let p = policy(&w, &allowed, &protected);
        let route: Vec<AccountInfo> = w.route.iter().map(TestAccount::info).collect();
        validate_route(&w.jup.info(), &route, data, &p).map(|v| v.kind())
    }

    fn err(e: SijkaError) -> Result<JupKind, ProgramError> {
        Err(e.into())
    }

    #[test]
    fn four_variants_pass() {
        assert_eq!(route_v2_data().len(), 40);
        assert_eq!(run(&route_v2_keys(), &route_v2_data()), Ok(JupKind::RouteV2));
        assert_eq!(run(&shared_v2_keys(), &shared_v2_data()), Ok(JupKind::SharedAccountsRouteV2));
        assert_eq!(run(&route_v1_keys(), &v1_data(JUP_ROUTE, false, 1_000_000_000, 0)), Ok(JupKind::Route));
        assert_eq!(
            run(&shared_v1_keys(), &v1_data(JUP_SHARED_ACCOUNTS_ROUTE, true, 1_000_000_000, 0)),
            Ok(JupKind::SharedAccountsRoute)
        );
        // route_v2 with destination_token_account = dst instead of None.
        let mut k = route_v2_keys();
        k[7] = USDC_ACC;
        assert_eq!(run(&k, &route_v2_data()), Ok(JupKind::RouteV2));
        // The System program (zero key) may appear although a zero protected entry exists.
        k.push(SYSTEM_PROGRAM_ID);
        assert_eq!(run(&k, &route_v2_data()), Ok(JupKind::RouteV2));
    }

    #[test]
    fn forbidden_instructions() {
        // exact_out_route, route_with_token_ledger, claim, close_token-like: any other disc.
        for disc in [hex("d033ef977b2bed5c"), hex("96564774a75d0e68"), hex("3ec6d6c1d59f6cd2"), [0u8; 8].to_vec()] {
            let mut d = route_v2_data();
            d[..8].copy_from_slice(&disc);
            assert_eq!(run(&route_v2_keys(), &d), err(SijkaError::JupiterIxForbidden));
        }
        assert_eq!(run(&route_v2_keys(), &route_v2_data()[..7]), err(SijkaError::JupiterIxForbidden));
    }

    #[test]
    fn argument_mismatches() {
        let k = route_v2_keys();
        let d = route_v2_data();
        assert_eq!(run(&k, &d[..33]), err(SijkaError::JupiterArgsMismatch));
        assert_eq!(run(&k, &d[..34]), Ok(JupKind::RouteV2));
        let mut pf = d.clone();
        pf[26] = 5;
        assert_eq!(run(&k, &pf), err(SijkaError::JupiterArgsMismatch));
        let mut pos = d.clone();
        pos[28] = 1;
        assert_eq!(run(&k, &pos), err(SijkaError::JupiterArgsMismatch));
        let mut amt = d.clone();
        amt[8] = 1;
        assert_eq!(run(&k, &amt), err(SijkaError::JupiterArgsMismatch));
        // shared v2 fields are shifted by one.
        let sk = shared_v2_keys();
        let sd = shared_v2_data();
        assert_eq!(run(&sk, &sd[..34]), err(SijkaError::JupiterArgsMismatch));
        let mut spf = sd.clone();
        spf[27] = 1;
        assert_eq!(run(&sk, &spf), err(SijkaError::JupiterArgsMismatch));
        let mut spos = sd.clone();
        spos[30] = 1;
        assert_eq!(run(&sk, &spos), err(SijkaError::JupiterArgsMismatch));
        // v1: tail in_amount and platform fee byte.
        let vk = route_v1_keys();
        assert_eq!(run(&vk, &v1_data(JUP_ROUTE, false, 999, 0)), err(SijkaError::JupiterArgsMismatch));
        assert_eq!(run(&vk, &v1_data(JUP_ROUTE, false, 1_000_000_000, 1)), err(SijkaError::JupiterArgsMismatch));
        let short = v1_data(JUP_ROUTE, false, 1_000_000_000, 0);
        assert_eq!(run(&vk, &short[..8 + 4 + 19 - 1]), err(SijkaError::JupiterArgsMismatch));
    }

    #[test]
    fn pin_mismatches() {
        let d = route_v2_data();
        let base = route_v2_keys();
        let bad: [(usize, Pubkey); 9] = [
            (0, [1; 32]),               // authority
            (1, USDC_ACC),              // src
            (2, WSOL_ACC),              // dst
            (3, USDC),                  // src mint
            (4, WSOL_MINT),             // dst mint
            (5, TOKEN_2022_PROGRAM_ID), // token program
            (6, [2; 32]),               // token program
            (7, [3; 32]),               // destination_token_account neither None nor dst
            (9, [4; 32]),               // program
        ];
        for (i, k) in bad {
            let mut keys = base.clone();
            keys[i] = k;
            assert_eq!(run(&keys, &d), err(SijkaError::JupiterRoutePinMismatch), "slot {i}");
        }
        // Tail shorter than the program slot.
        assert_eq!(run(&base[..9], &d), err(SijkaError::JupiterRoutePinMismatch));
        // v1 platform_fee_account must be None.
        let mut v1 = route_v1_keys();
        v1[6] = [5; 32];
        assert_eq!(run(&v1, &v1_data(JUP_ROUTE, false, 1_000_000_000, 0)), err(SijkaError::JupiterRoutePinMismatch));
        let mut sh = shared_v1_keys();
        sh[9] = [5; 32];
        assert_eq!(
            run(&sh, &v1_data(JUP_SHARED_ACCOUNTS_ROUTE, true, 1_000_000_000, 0)),
            err(SijkaError::JupiterRoutePinMismatch)
        );
        // Kind decided by data, keys by another layout.
        assert_eq!(run(&route_v1_keys(), &d), err(SijkaError::JupiterRoutePinMismatch));
    }

    #[test]
    fn forbidden_accounts() {
        let d = route_v2_data();
        // Protected key anywhere in the tail (TC-9).
        let mut k = route_v2_keys();
        k.push(PROTECTED);
        assert_eq!(run(&k, &d), err(SijkaError::JupiterAccountForbidden));
        // A third token account of swap_authority (TC-10), SPL and Token-2022.
        for program in [SPL_TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID] {
            let mut k = route_v2_keys();
            k.push([0x53; 32]);
            let r = run_with(&k, &d, |w| {
                let t = token(&USDC, &SA, 1, false);
                *w.route.last_mut().unwrap() = TestAccount::new([0x53; 32], program, 1, &t, false, true, false);
            });
            assert_eq!(r, err(SijkaError::JupiterAccountForbidden));
        }
        // A token account of someone else is fine.
        let mut k = route_v2_keys();
        k.push([0x54; 32]);
        let r = run_with(&k, &d, |w| {
            let t = token(&USDC, &[0x01; 32], 1, false);
            *w.route.last_mut().unwrap() =
                TestAccount::new([0x54; 32], SPL_TOKEN_PROGRAM_ID, 1, &t, false, true, false);
        });
        assert_eq!(r, Ok(JupKind::RouteV2));
    }

    #[test]
    fn tail_size_program_and_authority_flags() {
        let d = route_v2_data();
        assert_eq!(run(&[], &d), err(SijkaError::JupiterTooManyAccounts));
        let mut k = route_v2_keys();
        k.resize(MAX_ROUTE_ACCOUNTS + 1, AMM);
        assert_eq!(run(&k, &d), err(SijkaError::JupiterTooManyAccounts));
        k.truncate(MAX_ROUTE_ACCOUNTS);
        assert_eq!(run(&k, &d), Ok(JupKind::RouteV2));
        // Jupiter program by another address or not executable (TC-12).
        let r = run_with(&route_v2_keys(), &d, |w| {
            w.jup = TestAccount::new([0x34; 32], [0x33; 32], 1, &[], false, false, true)
        });
        assert_eq!(r, err(SijkaError::InvalidProgramId));
        let r = run_with(&route_v2_keys(), &d, |w| {
            w.jup = TestAccount::new(JUPITER_V6, [0x33; 32], 1, &[], false, false, false)
        });
        assert_eq!(r, err(SijkaError::InvalidProgramId));
        // swap_authority writable (TC-8).
        let r = run_with(&route_v2_keys(), &d, |w| {
            w.sa = TestAccount::new(SA, SYSTEM_PROGRAM_ID, 0, &[], false, true, false)
        });
        assert_eq!(r, err(SijkaError::AccountMustBeReadonly));
    }

    fn post(edit: impl FnOnce(&mut World), a0: u64) -> ProgramResult {
        let mut w = world(&route_v2_keys());
        edit(&mut w);
        let wsol = w.wsol.info();
        let usdc = w.usdc.info();
        let allowed = [
            SwapAcc { info: &wsol, mint: &WSOL_MINT, native: true },
            SwapAcc { info: &usdc, mint: &USDC, native: false },
        ];
        let p = policy(&w, &allowed, &[]);
        post_route_check(&p, a0)
    }

    #[test]
    fn post_route_check_catches_tampering() {
        let tampered = Err(SijkaError::SwapAccountTampered.into());
        assert_eq!(post(|_| {}, 0), Ok(()));
        // approve_delegate / set_close_authority / set_owner / freeze on swap_usdc.
        for (off, v) in [(72usize, 1u8), (129, 1), (32, 0x66), (108, 2)] {
            assert_eq!(post(|w| w.usdc.data_mut()[off] = v, 0), tampered, "usdc byte {off}");
            assert_eq!(post(|w| w.wsol.data_mut()[off] = v, 0), tampered, "wsol byte {off}");
        }
        // close_src: account now owned by System with no data.
        assert_eq!(
            post(|w| w.usdc = TestAccount::new(USDC_ACC, SYSTEM_PROGRAM_ID, 0, &[], false, true, false), 0),
            tampered
        );
        // native flag lost on swap_wsol.
        assert_eq!(post(|w| w.wsol.data_mut()[109] = 0, 0), tampered);
        // drain_authority / assign_authority / allocate on swap_authority.
        assert_eq!(post(|_| {}, 1), tampered);
        assert_eq!(post(|w| w.sa = TestAccount::new(SA, [0x44; 32], 0, &[], false, false, false), 0), tampered);
        assert_eq!(post(|w| w.sa = TestAccount::new(SA, SYSTEM_PROGRAM_ID, 0, &[0], false, false, false), 0), tampered);
    }

    #[test]
    fn invoke_route_needs_a_validated_route() {
        // On the host the CPI is a no-op: a valid route passes validation, the
        // (empty) CPI and post_route_check; an invalid one never reaches the CPI
        // (no `ValidatedRoute` is built).
        let invoke = |keys: &[Pubkey], data: &[u8], edit: fn(&mut World)| -> ProgramResult {
            let mut w = world(keys);
            edit(&mut w);
            let wsol = w.wsol.info();
            let usdc = w.usdc.info();
            let allowed = [
                SwapAcc { info: &wsol, mint: &WSOL_MINT, native: true },
                SwapAcc { info: &usdc, mint: &USDC, native: false },
            ];
            let protected: [&Pubkey; 1] = [&PROTECTED];
            let p = policy(&w, &allowed, &protected);
            let route: Vec<AccountInfo> = w.route.iter().map(TestAccount::info).collect();
            let jup = w.jup.info();
            let v = validate_route(&jup, &route, data, &p)?;
            assert_eq!(v.kind(), JupKind::from_data(data).unwrap());
            invoke_route(v)
        };
        assert_eq!(invoke(&route_v2_keys(), &route_v2_data(), |_| {}), Ok(()));
        let mut k = route_v2_keys();
        k.push(PROTECTED);
        assert_eq!(invoke(&k, &route_v2_data(), |_| {}), Err(SijkaError::JupiterAccountForbidden.into()));
        let mut d = route_v2_data();
        d[8] ^= 1;
        assert_eq!(invoke(&route_v2_keys(), &d, |_| {}), Err(SijkaError::JupiterArgsMismatch.into()));
        // A swap account already tampered before the call is caught after it.
        assert_eq!(
            invoke(&route_v2_keys(), &route_v2_data(), |w| w.usdc.data_mut()[72] = 1),
            Err(SijkaError::SwapAccountTampered.into())
        );
    }

    #[test]
    fn kind_from_data() {
        assert_eq!(JupKind::from_data(&JUP_ROUTE), Some(JupKind::Route));
        assert_eq!(JupKind::from_data(&JUP_SHARED_ACCOUNTS_ROUTE), Some(JupKind::SharedAccountsRoute));
        assert_eq!(JupKind::from_data(&JUP_ROUTE_V2), Some(JupKind::RouteV2));
        assert_eq!(JupKind::from_data(&JUP_SHARED_ACCOUNTS_ROUTE_V2), Some(JupKind::SharedAccountsRouteV2));
        assert_eq!(JupKind::from_data(&JUP_ROUTE[..7]), None);
        assert_eq!(JupKind::SharedAccountsRouteV2 as u8, 3);
        // The largest pinned index of each layout is the program slot.
        for p in [&PINS_ROUTE, &PINS_SHARED, &PINS_ROUTE_V2, &PINS_SHARED_V2] {
            let mut all = vec![p.authority, p.src, p.dst, p.dst_mint];
            all.extend(p.dst_opt);
            all.extend(p.src_mint);
            all.extend(p.fee_none);
            all.extend_from_slice(p.token_programs);
            assert!(all.iter().all(|i| *i < p.program));
        }
    }
}
