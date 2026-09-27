// Copyright (c) 2026 prt1sn. All rights reserved.
//! Hawkeye margin view (SPEC §5.4.2 step 8, §3.9 `ViewMarginReturn`). Used by
//! tags 30/31 (harvest) and 51 op 1 (recovery).
//!
//! - `ViewMargin`: typed wrapper through `crate::cpi_tramp::hk_view_margin`
//!   (`CpiScratch<20, 8>`), all accounts read-only, no signers; not
//!   `invoke_and_decode` (it does not check magic and version).
//! - Return data: `Some`, `program_id == HAWKEYE_PROGRAM_ID`, exact length
//!   112, magic, `version == 1`, else `HawkeyeReturnInvalid`.
//!
//! The view checks the Hawkeye and Phoenix program keys itself (defence in
//! depth: a caller that forgot the slot check still cannot point the view at
//! another program). The return data is read in a separate
//! `#[inline(never)]` function so its 1 KiB buffer stays out of the caller's
//! frame (SPEC §5.0.6 rule 2).

use phoenix_rise::cpi::{CpiScratch, hawkeye};
use pinocchio::account_info::AccountInfo;
use pinocchio::program_error::ProgramError;
use pinocchio::pubkey::{Pubkey, pubkey_eq};

use crate::constants::{
    HAWKEYE_MARGIN_MAGIC, HAWKEYE_MARGIN_RETURN_LEN, HAWKEYE_PROGRAM_ID, HAWKEYE_RETURN_VERSION, MAX_ATB, MAX_GTI,
    PHOENIX_PROGRAM_ID,
};
use crate::cpi_tramp::{SCRATCH_VIEW_MARGIN_ACCOUNTS, SCRATCH_VIEW_MARGIN_DATA};
use crate::error::SijkaError;
use crate::external::layout::hawkeye_margin as hm;
use crate::util::bytes::{array_ref, read_i64, read_u8, read_u16, read_u64};

/// Accounts of a Hawkeye view (all read-only).
pub struct HawkeyeAccounts<'a> {
    pub hawkeye_program: &'a AccountInfo,
    pub phoenix_program: &'a AccountInfo,
    pub global_config: &'a AccountInfo,
    pub gti: &'a [AccountInfo],
    pub atb: &'a [AccountInfo],
    pub perp_asset_map: &'a AccountInfo,
    pub trader_account: &'a AccountInfo,
}

/// Decoded `ViewMarginReturn` fields the program uses.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MarginView {
    pub position_count: u16,
    pub risk_state: u8,
    pub risk_tier: u8,
    pub is_liquidatable: u8,
    /// `C_hk` (USDC only).
    pub collateral: i64,
    pub effective_collateral: i64,
    pub free_collateral: i64,
    pub withdrawable_collateral: u64,
    pub initial_margin: u64,
    /// `U`.
    pub unrealized_pnl: i64,
    /// `F`.
    pub unsettled_funding: i64,
}

/// Program keys and arena counts (the arena keys themselves are checked by
/// the caller against GlobalConfig and by Hawkeye).
fn check_view_accounts(acc: &HawkeyeAccounts<'_>) -> Result<usize, ProgramError> {
    if !pubkey_eq(acc.hawkeye_program.key(), &HAWKEYE_PROGRAM_ID)
        || !pubkey_eq(acc.phoenix_program.key(), &PHOENIX_PROGRAM_ID)
    {
        return Err(SijkaError::InvalidProgramId.fail());
    }
    let (g, a) = (acc.gti.len(), acc.atb.len());
    if !(1..=MAX_GTI).contains(&g) || !(1..=MAX_ATB).contains(&a) {
        return Err(SijkaError::InvalidArenaAccounts.fail());
    }
    // 4 + g + a ≤ 20 by the bounds above.
    Ok(g.saturating_add(a).saturating_add(4))
}

/// CPI `ViewMargin` and decode (SPEC §5.2.9).
#[inline(never)]
pub fn view_margin(acc: &HawkeyeAccounts<'_>) -> Result<MarginView, ProgramError> {
    check_view_accounts(acc)?;
    invoke_view_margin(acc)?;
    read_margin_return()
}

#[inline(never)]
fn invoke_view_margin(acc: &HawkeyeAccounts<'_>) -> Result<(), ProgramError> {
    let vm = hawkeye::ViewMargin {
        hawkeye_program: acc.hawkeye_program,
        phoenix_program: acc.phoenix_program,
        global_config: acc.global_config,
        global_trader_index: acc.gti,
        active_trader_buffer: acc.atb,
        perp_asset_map: acc.perp_asset_map,
        trader: acc.trader_account,
    };
    let mut scratch =
        CpiScratch::<'_, SCRATCH_VIEW_MARGIN_ACCOUNTS, SCRATCH_VIEW_MARGIN_DATA>::new(acc.hawkeye_program);
    crate::cpi_tramp::hk_view_margin(&vm, &mut scratch)
}

#[inline(never)]
fn read_margin_return() -> Result<MarginView, ProgramError> {
    let rd = pinocchio::cpi::get_return_data().ok_or_else(|| SijkaError::HawkeyeReturnInvalid.fail())?;
    parse_margin_return(rd.program_id(), rd.as_slice()).map_err(SijkaError::fail)
}

/// Pure decoder of `ViewMarginReturn`: program id, length 112, magic,
/// `version == 1`. Error `HawkeyeReturnInvalid`.
pub fn parse_margin_return(program_id: &Pubkey, data: &[u8]) -> Result<MarginView, SijkaError> {
    const E: SijkaError = SijkaError::HawkeyeReturnInvalid;
    if !pubkey_eq(program_id, &HAWKEYE_PROGRAM_ID) || data.len() != HAWKEYE_MARGIN_RETURN_LEN {
        return Err(E);
    }
    if array_ref::<8>(data, hm::MAGIC) != Some(&HAWKEYE_MARGIN_MAGIC)
        || read_u16(data, hm::VERSION) != Some(HAWKEYE_RETURN_VERSION)
    {
        return Err(E);
    }
    Ok(MarginView {
        position_count: read_u16(data, hm::POSITION_COUNT).ok_or(E)?,
        risk_state: read_u8(data, hm::RISK_STATE).ok_or(E)?,
        risk_tier: read_u8(data, hm::RISK_TIER).ok_or(E)?,
        is_liquidatable: read_u8(data, hm::IS_LIQUIDATABLE).ok_or(E)?,
        collateral: read_i64(data, hm::COLLATERAL).ok_or(E)?,
        effective_collateral: read_i64(data, hm::EFFECTIVE_COLLATERAL).ok_or(E)?,
        free_collateral: read_i64(data, hm::FREE_COLLATERAL).ok_or(E)?,
        withdrawable_collateral: read_u64(data, hm::WITHDRAWABLE_COLLATERAL).ok_or(E)?,
        initial_margin: read_u64(data, hm::INITIAL_MARGIN).ok_or(E)?,
        unrealized_pnl: read_i64(data, hm::UNREALIZED_PNL).ok_or(E)?,
        unsettled_funding: read_i64(data, hm::UNSETTLED_FUNDING).ok_or(E)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::test_utils::TestAccount;
    use phoenix_rise::ix::hawkeye::{ViewMarginReturn, decode_hawkeye_return};

    fn put(d: &mut [u8], off: usize, v: &[u8]) {
        d[off..off + v.len()].copy_from_slice(v);
    }

    fn margin_bytes() -> Vec<u8> {
        let mut d = vec![0u8; 112];
        put(&mut d, 0, &HAWKEYE_MARGIN_MAGIC);
        put(&mut d, 8, &1u16.to_le_bytes());
        put(&mut d, 10, &3u16.to_le_bytes());
        d[13] = 2;
        d[14] = 1;
        for (off, v) in [(16usize, -11i64), (24, 22), (32, -33), (88, -77), (96, 88), (104, -99)] {
            put(&mut d, off, &v.to_le_bytes());
        }
        for (off, v) in [(40usize, 44u64), (48, 55), (56, 66), (64, 1), (72, 2), (80, 3)] {
            put(&mut d, off, &v.to_le_bytes());
        }
        d
    }

    /// Our offsets agree with the SDK's `repr(C)` return structs (the SDK
    /// decodes the same bytes).
    #[test]
    fn margin_return_parity() {
        let d = margin_bytes();
        let sdk: ViewMarginReturn = decode_hawkeye_return(&d, "view_margin").unwrap();
        let m = parse_margin_return(&HAWKEYE_PROGRAM_ID, &d).unwrap();
        assert_eq!(sdk.magic.to_le_bytes(), HAWKEYE_MARGIN_MAGIC);
        assert_eq!(sdk.version, 1);
        assert_eq!(m.position_count, sdk.position_count);
        assert_eq!(m.risk_state, sdk.risk_state);
        assert_eq!(m.risk_tier, sdk.risk_tier);
        assert_eq!(m.is_liquidatable, sdk.is_liquidatable);
        assert_eq!(m.collateral, sdk.collateral_quote_lots);
        assert_eq!(m.effective_collateral, sdk.effective_collateral_quote_lots);
        assert_eq!(m.free_collateral, sdk.free_collateral_quote_lots);
        assert_eq!(m.withdrawable_collateral, sdk.withdrawable_collateral_quote_lots);
        assert_eq!(m.initial_margin, sdk.initial_margin_quote_lots);
        assert_eq!(m.unrealized_pnl, sdk.unrealized_pnl_quote_lots);
        assert_eq!(m.unsettled_funding, sdk.unsettled_funding_quote_lots);
        assert_eq!((m.position_count, m.risk_tier, m.collateral, m.unsettled_funding), (3, 2, -11, -99));
        let e = Err(SijkaError::HawkeyeReturnInvalid);
        assert_eq!(parse_margin_return(&[1; 32], &d), e);
        assert_eq!(parse_margin_return(&HAWKEYE_PROGRAM_ID, &d[..111]), e);
        let mut long = d.clone();
        long.push(0);
        assert_eq!(parse_margin_return(&HAWKEYE_PROGRAM_ID, &long), e);
        let mut magic = d.clone();
        magic[0] ^= 1;
        assert_eq!(parse_margin_return(&HAWKEYE_PROGRAM_ID, &magic), e);
        let mut ver = d.clone();
        ver[8] = 2;
        assert_eq!(parse_margin_return(&HAWKEYE_PROGRAM_ID, &ver), e);
        // The `ViewMarginForAsset` magic is not accepted as a margin return.
        let mut other = d.clone();
        other[..8].copy_from_slice(&[0xb9, 0x1d, 0x5e, 0x28, 0xf8, 0xff, 0x58, 0xdb]);
        assert_eq!(parse_margin_return(&HAWKEYE_PROGRAM_ID, &other), e);
    }

    /// Host run: the CPI is a no-op and there is no return data, so the view
    /// fails closed with `HawkeyeReturnInvalid`; wrong program keys are
    /// rejected before the CPI.
    #[test]
    fn views_fail_closed_without_return_data() {
        let hk = TestAccount::new(HAWKEYE_PROGRAM_ID, [0; 32], 1, &[], false, false, true);
        let phx = TestAccount::new(PHOENIX_PROGRAM_ID, [0; 32], 1, &[], false, false, true);
        let other = TestAccount::new([3; 32], [0; 32], 1, &[], false, false, true);
        let gc = TestAccount::plain([4; 32], PHOENIX_PROGRAM_ID, &[]);
        let arenas = [
            TestAccount::plain([5; 32], PHOENIX_PROGRAM_ID, &[]),
            TestAccount::plain([6; 32], PHOENIX_PROGRAM_ID, &[]),
        ];
        let ai: Vec<AccountInfo> = arenas.iter().map(TestAccount::info).collect();
        let pam = TestAccount::plain([7; 32], PHOENIX_PROGRAM_ID, &[]);
        let tr = TestAccount::plain([8; 32], PHOENIX_PROGRAM_ID, &[]);
        let (hki, phxi, gci, pami, tri, oi) = (hk.info(), phx.info(), gc.info(), pam.info(), tr.info(), other.info());
        let acc = HawkeyeAccounts {
            hawkeye_program: &hki,
            phoenix_program: &phxi,
            global_config: &gci,
            gti: &ai[..1],
            atb: &ai[1..],
            perp_asset_map: &pami,
            trader_account: &tri,
        };
        assert_eq!(view_margin(&acc), Err(SijkaError::HawkeyeReturnInvalid.into()));
        let bad = HawkeyeAccounts { hawkeye_program: &oi, ..acc };
        assert_eq!(view_margin(&bad), Err(SijkaError::InvalidProgramId.into()));
        let bad2 = HawkeyeAccounts { hawkeye_program: &hki, phoenix_program: &oi, ..bad };
        assert_eq!(view_margin(&bad2), Err(SijkaError::InvalidProgramId.into()));
        let no_atb = HawkeyeAccounts { hawkeye_program: &hki, phoenix_program: &phxi, atb: &ai[..0], ..bad2 };
        assert_eq!(view_margin(&no_atb), Err(SijkaError::InvalidArenaAccounts.into()));
    }
}
