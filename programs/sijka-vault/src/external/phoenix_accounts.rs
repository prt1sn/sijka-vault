// Copyright (c) 2026 prt1sn. All rights reserved.
//! Read-only views and account checks of the Phoenix accounts the program
//! reads (SPEC §3.9, §5.0.5): GlobalConfig, PerpAssetMap, Trader, GTI/ATB
//! arenas.
//!
//! Shared by setup (2), inflow (21), harvest (30/31) and recovery (51). Tag
//! 10 `trade` does not read Phoenix accounts: it checks keys only (SPEC
//! §5.2.3 T5–T8) and Phoenix checks the rest.
//! Every check fails closed with the SPEC error of its slot; a writable slot
//! passed read-only is `AccountNotWritable` (SPEC §5.0.3), except the arenas
//! (`InvalidArenaAccounts`, SPEC §6.2).
//!
//! Not parsed by design (review RT-3, rejected part): the Active Trader Buffer
//! and GTI internals. The trader's position map can lag the live buffer
//! (§3.9), so harvest uses it only as a first mark check and relies on
//! Hawkeye for the rest. Arenas are checked by key (`[0]` against GC), owner
//! and distinctness; Phoenix checks the rest.
//!
//! Authority `@56` and position authority `@120` of our trader must both be
//! `phx_authority` (SPEC v3, §5.0.5): the program never appoints a delegate,
//! so a different position authority means Phoenix changed its semantics.

use pinocchio::ProgramResult;
use pinocchio::account_info::AccountInfo;
use pinocchio::program_error::ProgramError;
use pinocchio::pubkey::{Pubkey, pubkey_eq};

use crate::constants::{
    DISC_GLOBAL_CONFIG, DISC_PAM, DISC_TRADER, GC_MIN_LEN, MAX_ATB, MAX_GTI, PAM_ENTRY, PAM_HEADER,
    PHOENIX_GLOBAL_CONFIG, PHOENIX_PROGRAM_ID,
};
use crate::error::SijkaError;
use crate::external::layout::{global_config as gcl, perp_asset_map as paml, trader as trl};
use crate::util::bytes::{array_ref, is_zero_key, read_i8, read_i64, read_key, read_u8, read_u16, read_u32, read_u64};

/// Fail with `e` (logged) unless `ok`.
#[inline(always)]
fn ensure(ok: bool, e: SijkaError) -> ProgramResult {
    if ok { Ok(()) } else { Err(e.fail()) }
}

/// `writable` requested and the slot is read-only → `AccountNotWritable`.
#[inline(always)]
fn ensure_writable(ai: &AccountInfo, writable: bool) -> ProgramResult {
    ensure(!writable || ai.is_writable(), SijkaError::AccountNotWritable)
}

// ------------------------------------------------------- GlobalConfig ----

/// Keys and fields of a recognized GlobalConfig (SPEC §3.9).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GlobalConfigKeys {
    pub canonical_mint: Pubkey,
    pub global_vault: Pubkey,
    pub perp_asset_map: Pubkey,
    pub gti_header: Pubkey,
    pub atb_header: Pubkey,
    pub withdraw_queue: Pubkey,
    /// `@504`; 0 if the account is exactly 504 bytes (no instruction outside
    /// the venue verdict, which reads GC itself, uses it).
    pub exchange_status: u8,
}

/// Pure read of the GlobalConfig fields (`data.len() ≥ 504`).
pub fn read_global_config(data: &[u8]) -> Option<GlobalConfigKeys> {
    Some(GlobalConfigKeys {
        canonical_mint: *read_key(data, gcl::CANONICAL_MINT)?,
        global_vault: *read_key(data, gcl::GLOBAL_VAULT)?,
        perp_asset_map: *read_key(data, gcl::PERP_ASSET_MAP)?,
        gti_header: *read_key(data, gcl::GTI_HEADER)?,
        atb_header: *read_key(data, gcl::ATB_HEADER)?,
        withdraw_queue: *read_key(data, gcl::WITHDRAW_QUEUE)?,
        exchange_status: read_u8(data, gcl::EXCHANGE_STATUS).unwrap_or(0),
    })
}

/// SPEC §5.0.5 `global_config`: key `PHOENIX_GLOBAL_CONFIG`, owner Phoenix,
/// disc, `data_len ≥ max(504, min_len)` (520 where `@512` is read); writable
/// if `writable` (`AccountNotWritable`). Returns the keys. Other failures:
/// `InvalidPhoenixGlobalConfig`. (Tags 50 / 51 op 0 check only the key; the
/// rest is the venue verdict, not this function.)
pub fn check_global_config(gc: &AccountInfo, min_len: usize, writable: bool) -> Result<GlobalConfigKeys, ProgramError> {
    const E: SijkaError = SijkaError::InvalidPhoenixGlobalConfig;
    ensure(pubkey_eq(gc.key(), &PHOENIX_GLOBAL_CONFIG), E)?;
    ensure(gc.is_owned_by(&PHOENIX_PROGRAM_ID), E)?;
    ensure(gc.data_len() >= min_len.max(GC_MIN_LEN), E)?;
    ensure_writable(gc, writable)?;
    let data = gc.try_borrow_data()?;
    ensure(array_ref::<8>(&data, gcl::DISCRIMINATOR) == Some(&DISC_GLOBAL_CONFIG), E)?;
    read_global_config(&data).ok_or_else(|| E.fail())
}

// ------------------------------------------------------ PerpAssetMap ----

/// PAM header fields (SPEC §3.9).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PamHeader {
    pub num_assets: u16,
    pub slots_used: u32,
    pub tombstones: u32,
    pub capacity: u64,
}

pub fn pam_header(data: &[u8]) -> Option<PamHeader> {
    Some(PamHeader {
        num_assets: read_u16(data, paml::NUM_ASSETS)?,
        slots_used: read_u32(data, paml::SLOTS_USED)?,
        tombstones: read_u32(data, paml::TOMBSTONES)?,
        capacity: read_u64(data, paml::CAPACITY)?,
    })
}

/// `pam_layout_ok` (SPEC §3.9, review RT-9): discriminator not included.
/// `cap = u64@40`, `1 ≤ cap`, `slots_used ≤ cap`, `tombstones ≤ slots_used`,
/// `data_len == 48 + cap·1584` (checked; equality, so a changed entry size is
/// fail-closed).
pub fn pam_layout_ok(data: &[u8]) -> bool {
    let Some(h) = pam_header(data) else {
        return false;
    };
    if h.capacity < 1 || u64::from(h.slots_used) > h.capacity || h.tombstones > h.slots_used {
        return false;
    }
    let expected =
        usize::try_from(h.capacity).ok().and_then(|c| c.checked_mul(PAM_ENTRY)).and_then(|b| b.checked_add(PAM_HEADER));
    expected == Some(data.len())
}

/// PAM discriminator present.
pub fn pam_disc_ok(data: &[u8]) -> bool {
    array_ref::<8>(data, paml::DISCRIMINATOR) == Some(&DISC_PAM)
}

/// Offset of entry `slot` (`48 + slot·1584`), if the whole entry is inside `data`.
pub fn pam_entry_offset(data: &[u8], slot: u32) -> Option<usize> {
    let e = usize::try_from(slot).ok()?.checked_mul(PAM_ENTRY)?.checked_add(PAM_HEADER)?;
    let end = e.checked_add(PAM_ENTRY)?;
    (end <= data.len()).then_some(e)
}

/// Fields of one PAM entry (SPEC §3.9).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PamEntry {
    pub offset: usize,
    pub symbol: [u8; 16],
    pub mark_slot: u64,
    pub mark_ticks: u64,
    pub market_account: Pubkey,
    pub tick_size: u64,
    /// `asset_id_lo | asset_id_hi << 16`.
    pub asset_id: u32,
    pub base_lot_decimals: i8,
    pub isolated_only: u8,
    pub finalized_mark_price: u64,
    pub is_tombstoned: u8,
}

/// Read entry `slot`; `None` if the entry is not fully inside `data`. Does not
/// check `slot < slots_used` (callers do, per SPEC).
pub fn pam_entry(data: &[u8], slot: u32) -> Option<PamEntry> {
    let e = pam_entry_offset(data, slot)?;
    let at = |o: usize| e.checked_add(o);
    let lo = u32::from(read_u16(data, at(paml::E_ASSET_ID_LO)?)?);
    let hi = u32::from(read_u16(data, at(paml::E_ASSET_ID_HI)?)?);
    Some(PamEntry {
        offset: e,
        symbol: *array_ref::<16>(data, at(paml::E_SYMBOL)?)?,
        mark_slot: read_u64(data, at(paml::E_MARK_SLOT)?)?,
        mark_ticks: read_u64(data, at(paml::E_MARK_TICKS)?)?,
        market_account: *read_key(data, at(paml::E_MARKET_ACCOUNT)?)?,
        tick_size: read_u64(data, at(paml::E_TICK_SIZE)?)?,
        asset_id: lo | hi.checked_shl(16)?,
        base_lot_decimals: read_i8(data, at(paml::E_BASE_LOT_DECIMALS)?)?,
        isolated_only: read_u8(data, at(paml::E_ISOLATED_ONLY)?)?,
        finalized_mark_price: read_u64(data, at(paml::E_FINALIZED_MARK_PRICE)?)?,
        is_tombstoned: read_u8(data, at(paml::E_IS_TOMBSTONED)?)?,
    })
}

/// How strictly to check the PAM account (SPEC §5.0.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PamCheck {
    /// Key `== GC@360`, owner Phoenix, disc, `pam_layout_ok`.
    Full,
    /// Tag 51 op 1, 6: key `== GC@360` and owner only.
    KeyAndOwner,
}

/// SPEC §5.0.5 `perp_asset_map`. Error `InvalidPerpAssetMap` (writable:
/// `AccountNotWritable`).
pub fn check_perp_asset_map(pam: &AccountInfo, gc_pam_key: &Pubkey, mode: PamCheck, writable: bool) -> ProgramResult {
    const E: SijkaError = SijkaError::InvalidPerpAssetMap;
    ensure(pubkey_eq(pam.key(), gc_pam_key), E)?;
    ensure(pam.is_owned_by(&PHOENIX_PROGRAM_ID), E)?;
    ensure_writable(pam, writable)?;
    if mode == PamCheck::Full {
        let data = pam.try_borrow_data()?;
        ensure(pam_disc_ok(&data) && pam_layout_ok(&data), E)?;
    }
    Ok(())
}

// ------------------------------------------------------------- Trader ----

/// Trader header fields (SPEC §3.9).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TraderHeader {
    pub trader_key: Pubkey,
    pub authority: Pubkey,
    pub collateral: i64,
    pub flags: u32,
    pub max_positions: u32,
    pub preference_bits: u32,
    pub position_authority: Pubkey,
    pub pda_index: u8,
    pub subaccount_index: u8,
    pub funding_key: Pubkey,
    pub last_deposit_slot: u64,
    pub len: u64,
    pub cap: u64,
}

pub fn trader_header(data: &[u8]) -> Option<TraderHeader> {
    Some(TraderHeader {
        trader_key: *read_key(data, trl::TRADER_KEY)?,
        authority: *read_key(data, trl::AUTHORITY)?,
        collateral: read_i64(data, trl::COLLATERAL)?,
        flags: read_u32(data, trl::FLAGS)?,
        max_positions: read_u32(data, trl::MAX_POSITIONS)?,
        preference_bits: read_u32(data, trl::PREFERENCE_BITS)?,
        position_authority: *read_key(data, trl::POSITION_AUTHORITY)?,
        pda_index: read_u8(data, trl::PDA_INDEX)?,
        subaccount_index: read_u8(data, trl::SUBACCOUNT_INDEX)?,
        funding_key: *read_key(data, trl::FUNDING_KEY)?,
        last_deposit_slot: read_u64(data, trl::LAST_DEPOSIT_SLOT)?,
        len: read_u64(data, trl::LEN)?,
        cap: read_u64(data, trl::CAP)?,
    })
}

/// How strictly to check the trader account (SPEC §5.0.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TraderCheck {
    /// Key, owner Phoenix, disc, authority and position authority
    /// `== phx_authority`, indices 0/0, `len ≤ cap`, `data_len ≥ 240 + 40·cap`.
    Full,
    /// Tag 51 op 1 (review REC-9): key, owner, `data_len ≥ 200`, both
    /// authority fields `== phx_authority`.
    WithdrawOnly,
}

/// Number of position records `len` if the map header is consistent:
/// `len ≤ cap` and `240 + 40·cap ≤ data.len()` (no upper bound on `cap`).
pub fn position_map_len(data: &[u8]) -> Option<usize> {
    let len = read_u64(data, trl::LEN)?;
    let cap = read_u64(data, trl::CAP)?;
    if len > cap {
        return None;
    }
    let need = usize::try_from(cap).ok()?.checked_mul(trl::POSITION_LEN)?.checked_add(trl::POSITIONS)?;
    if need > data.len() {
        return None;
    }
    usize::try_from(len).ok()
}

/// Pure form of the `Full` trader check over the account bytes.
pub fn trader_layout_ok(data: &[u8], phx_authority: &Pubkey) -> bool {
    let Some(h) = trader_header(data) else {
        return false;
    };
    array_ref::<8>(data, trl::DISCRIMINATOR) == Some(&DISC_TRADER)
        && pubkey_eq(&h.authority, phx_authority)
        && pubkey_eq(&h.position_authority, phx_authority)
        && h.pda_index == 0
        && h.subaccount_index == 0
        && position_map_len(data).is_some()
}

/// SPEC §5.0.5 `trader_account`. `cfg.phoenix_trader == 0` →
/// `TraderNotRegistered`; writable requested but read-only →
/// `AccountNotWritable`; otherwise `InvalidPhoenixTraderAccount`.
pub fn check_trader_account(
    trader: &AccountInfo,
    phoenix_trader: &Pubkey,
    phx_authority: &Pubkey,
    mode: TraderCheck,
    writable: bool,
) -> ProgramResult {
    const E: SijkaError = SijkaError::InvalidPhoenixTraderAccount;
    ensure(!is_zero_key(phoenix_trader), SijkaError::TraderNotRegistered)?;
    ensure(pubkey_eq(trader.key(), phoenix_trader), E)?;
    ensure(trader.is_owned_by(&PHOENIX_PROGRAM_ID), E)?;
    ensure_writable(trader, writable)?;
    match mode {
        TraderCheck::WithdrawOnly => {
            ensure(trader.data_len() >= trl::MIN_LEN_WITHDRAW_ONLY, E)?;
            let data = trader.try_borrow_data()?;
            let auth_ok = read_key(&data, trl::AUTHORITY).is_some_and(|k| pubkey_eq(k, phx_authority))
                && read_key(&data, trl::POSITION_AUTHORITY).is_some_and(|k| pubkey_eq(k, phx_authority));
            ensure(auth_ok, E)
        }
        TraderCheck::Full => {
            let data = trader.try_borrow_data()?;
            ensure(trader_layout_ok(&data, phx_authority), E)
        }
    }
}

/// One record of the trader position map: `asset_index` (low 32 bits) and
/// `base_lot_position`. Header extensions are returned too.
#[inline]
fn position_record(data: &[u8], j: usize) -> Option<(u32, i64)> {
    let o = j.checked_mul(trl::POSITION_LEN)?.checked_add(trl::POSITIONS)?;
    // Little-endian: the low 32 bits of the u64 index are its first 4 bytes.
    let idx = read_u32(data, o.checked_add(trl::POS_ASSET_INDEX)?)?;
    let base = read_i64(data, o.checked_add(trl::POS_BASE_LOTS)?)?;
    Some((idx, base))
}

/// `true` if any position record (header extensions skipped) has
/// `base_lot_position ≠ 0` (tag 51 op 6 step 5). `None` if the map header is
/// inconsistent or a record does not fit: the caller fails closed.
pub fn has_open_position(trader_data: &[u8]) -> Option<bool> {
    let len = position_map_len(trader_data)?;
    for j in 0..len {
        let (idx, base) = position_record(trader_data, j)?;
        if idx < trl::EXTENSION_ASSET_INDEX_MIN && base != 0 {
            return Some(true);
        }
    }
    Some(false)
}

// ------------------------------------------------------------ Arenas ----

/// SPEC §5.0.5 `GTI[0..g]`, `ATB[0..a]`: `1 ≤ g, a ≤ 8`, `GTI[0] == GC@392`,
/// `ATB[0] == GC@424`, all owned by Phoenix, writable if `writable`, all keys
/// distinct and none equal to the GlobalConfig or the PAM (no aliasing).
/// Error `InvalidArenaAccounts`. `arenas` is the tail `[GTI…, ATB…]`.
pub fn check_arenas(arenas: &[AccountInfo], gti_count: usize, gc: &GlobalConfigKeys, writable: bool) -> ProgramResult {
    const E: SijkaError = SijkaError::InvalidArenaAccounts;
    let (gti, atb) = arenas.split_at_checked(gti_count).ok_or_else(|| E.fail())?;
    ensure((1..=MAX_GTI).contains(&gti.len()) && (1..=MAX_ATB).contains(&atb.len()), E)?;
    let gti0 = gti.first().ok_or_else(|| E.fail())?;
    let atb0 = atb.first().ok_or_else(|| E.fail())?;
    ensure(pubkey_eq(gti0.key(), &gc.gti_header) && pubkey_eq(atb0.key(), &gc.atb_header), E)?;
    for (i, a) in arenas.iter().enumerate() {
        ensure(a.is_owned_by(&PHOENIX_PROGRAM_ID), E)?;
        ensure(!writable || a.is_writable(), E)?;
        ensure(!pubkey_eq(a.key(), &PHOENIX_GLOBAL_CONFIG) && !pubkey_eq(a.key(), &gc.perp_asset_map), E)?;
        for b in arenas.iter().skip(i.saturating_add(1)) {
            ensure(!pubkey_eq(a.key(), b.key()), E)?;
        }
    }
    Ok(())
}

/// No arena key equals one of `others` (e.g. the trader account): aliasing
/// guard for account lists with arenas. `InvalidArenaAccounts`.
pub fn check_arenas_disjoint(arenas: &[AccountInfo], others: &[&Pubkey]) -> ProgramResult {
    let clash = arenas.iter().any(|a| others.iter().any(|o| pubkey_eq(a.key(), o)));
    ensure(!clash, SijkaError::InvalidArenaAccounts)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::util::test_utils::TestAccount;

    pub fn pam(cap: u64, slots_used: u32, tombstones: u32) -> Vec<u8> {
        let mut d = vec![0u8; PAM_HEADER + (cap as usize) * PAM_ENTRY];
        d[0..8].copy_from_slice(&DISC_PAM);
        d[24..26].copy_from_slice(&3u16.to_le_bytes());
        d[32..36].copy_from_slice(&slots_used.to_le_bytes());
        d[36..40].copy_from_slice(&tombstones.to_le_bytes());
        d[40..48].copy_from_slice(&cap.to_le_bytes());
        d
    }

    /// Write one PAM entry (test helper).
    #[allow(clippy::too_many_arguments)]
    pub fn put_entry(d: &mut [u8], slot: usize, asset_id: u32, market: &Pubkey, mark: u64, mark_slot: u64, tick: u64) {
        let e = PAM_HEADER + slot * PAM_ENTRY;
        d[e + 32..e + 40].copy_from_slice(&mark_slot.to_le_bytes());
        d[e + 40..e + 48].copy_from_slice(&mark.to_le_bytes());
        d[e + 920..e + 952].copy_from_slice(market);
        d[e + 952..e + 960].copy_from_slice(&tick.to_le_bytes());
        d[e + 960..e + 962].copy_from_slice(&((asset_id & 0xFFFF) as u16).to_le_bytes());
        d[e + 964..e + 966].copy_from_slice(&((asset_id >> 16) as u16).to_le_bytes());
        for k in 0..4 {
            let t = e + 1032 + 24 * k;
            d[t + 8..t + 16].copy_from_slice(&(if k == 0 { 25u64 } else { 1 }).to_le_bytes());
            d[t + 16..t + 24].copy_from_slice(&10_000u64.to_le_bytes());
        }
    }

    /// A trader account with the given records (test helper).
    pub fn trader(auth: &Pubkey, cap: u64, records: &[(u64, i64)]) -> Vec<u8> {
        let mut d = vec![0u8; 240 + 40 * cap as usize];
        d[0..8].copy_from_slice(&DISC_TRADER);
        d[56..88].copy_from_slice(auth);
        d[96..100].copy_from_slice(&63u32.to_le_bytes());
        d[120..152].copy_from_slice(auth);
        d[224..232].copy_from_slice(&(records.len() as u64).to_le_bytes());
        d[232..240].copy_from_slice(&cap.to_le_bytes());
        for (j, (idx, base)) in records.iter().enumerate() {
            let o = 240 + 40 * j;
            d[o..o + 8].copy_from_slice(&idx.to_le_bytes());
            d[o + 8..o + 16].copy_from_slice(&base.to_le_bytes());
        }
        d
    }

    // ---- Live mainnet PerpAssetMap excerpt (slot 450 470 761, account
    // 2nHGAa…). Header and, for slots 0 (SOL), 1 (BTC), 2 (ETH) and 5 (an
    // isolated-only market), the byte ranges the program reads. The rest of
    // the 1 622 064-byte account is zero here.
    const LIVE_HDR: &str =
        "8e3673df7cef6c2601000000000000005f85b216000000005a000000000000005a000000000000000004000000000000";
    const LIVE_ENTRIES: &[(usize, usize, &str)] = &[
        (0, 0, "534f4c0000000000000000000000000070c9c2040000000069a3d91a0000000069a3d91a000000004c2f000000000000"),
        (0, 920, "59433054c5b24ba8eaa8217fdff9036fb99c4bc19119a971aa4833ec604c231f64000000000000000000020000000000"),
        (
            0,
            1032,
            "4ccbea0100000000190000000000000010270000000000004dcbea0100000000010000000000000010270000000000004ecbea0100000000010000000000000010270000000000004fcbea010000000001000000000000001027000000000000",
        ),
        (1, 0, "425443000000000000000000000000006d76b7040000000069a3d91a0000000069a3d91a000000000c47010000000000"),
        (1, 920, "8d798c3bf3d27d90cf9f08f11559d1c19a97f2c22a042c9155ede88977cb7e1864000000000000000100040000000000"),
        (
            1,
            1032,
            "902970000000000028000000000000001027000000000000912970000000000001000000000000001027000000000000922970000000000001000000000000001027000000000000932970000000000001000000000000001027000000000000",
        ),
        (2, 0, "4554480000000000000000000000000078c88a040000000069a3d91a0000000069a3d91a00000000af68000000000000"),
        (2, 920, "84372435ddebd555ac48709753d7f90993a171ce34f952305522687862410a5564000000000000000200030000000000"),
        (
            2,
            1032,
            "f87170010000000019000000000000001027000000000000f97170010000000001000000000000001027000000000000fa7170010000000001000000000000001027000000000000fb7170010000000001000000000000001027000000000000",
        ),
        (5, 0, "534b5200000000000000000000000000ab2778020000000069a3d91a0000000069a3d91a00000000354f000000000000"),
        (5, 920, "f9570373fa621af38011f47e51d62dfb7e337056506965ee1dbf499fd795651001000000000000000500000000000000"),
        (
            5,
            1032,
            "809fd5000000000003000000000000001027000000000000c1e1e4000000000001000000000000001027000000000000c2e1e4000000000001000000000000001027000000000000c3e1e4000000000001000000000000001027000000000000",
        ),
        (5, 1224, "0100"),
    ];

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// Live PAM excerpt as a full-size account (capacity 1024).
    pub fn live_pam() -> Vec<u8> {
        let mut d = vec![0u8; PAM_HEADER + 1024 * PAM_ENTRY];
        d[..48].copy_from_slice(&hex(LIVE_HDR));
        for (slot, off, h) in LIVE_ENTRIES {
            let b = hex(h);
            let e = PAM_HEADER + slot * PAM_ENTRY + off;
            d[e..e + b.len()].copy_from_slice(&b);
        }
        d
    }

    #[test]
    fn pam_layout_rules() {
        let d = pam(4, 3, 0);
        assert!(pam_disc_ok(&d));
        assert!(pam_layout_ok(&d));
        assert!(!pam_layout_ok(&d[..d.len() - 1]));
        assert!(!pam_layout_ok(&pam(4, 5, 0)));
        assert!(!pam_layout_ok(&pam(4, 3, 4)));
        let mut zero_cap = pam(1, 0, 0);
        zero_cap[40..48].copy_from_slice(&0u64.to_le_bytes());
        assert!(!pam_layout_ok(&zero_cap));
        let mut huge = pam(1, 0, 0);
        huge[40..48].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(!pam_layout_ok(&huge));
    }

    /// TU-B9 (review RT-9): live PAM (cap 1024) ok; synthetic cap 2048 ok;
    /// cap 1024 with another length fails.
    #[test]
    fn pam_layout_live_and_capacity_2048() {
        let live = live_pam();
        assert!(pam_disc_ok(&live) && pam_layout_ok(&live));
        let h = pam_header(&live).unwrap();
        assert_eq!((h.num_assets, h.slots_used, h.tombstones, h.capacity), (90, 90, 0, 1024));
        assert!(pam_layout_ok(&pam(2048, 90, 0)));
        let mut longer = live.clone();
        longer.push(0);
        assert!(!pam_layout_ok(&longer));
        assert!(!pam_layout_ok(&live[..live.len() - PAM_ENTRY]));
    }

    #[test]
    fn pam_entry_fields() {
        let mut d = pam(2, 2, 0);
        let e = PAM_HEADER + PAM_ENTRY;
        d[e..e + 3].copy_from_slice(b"SOL");
        d[e + 32..e + 40].copy_from_slice(&7u64.to_le_bytes());
        d[e + 40..e + 48].copy_from_slice(&12_061u64.to_le_bytes());
        d[e + 920..e + 952].copy_from_slice(&[5u8; 32]);
        d[e + 952..e + 960].copy_from_slice(&100u64.to_le_bytes());
        d[e + 960..e + 962].copy_from_slice(&23u16.to_le_bytes());
        d[e + 962] = 2;
        d[e + 964..e + 966].copy_from_slice(&1u16.to_le_bytes());
        d[e + 1466] = 1;
        let p = pam_entry(&d, 1).unwrap();
        assert_eq!(p.offset, e);
        assert_eq!(&p.symbol[..3], b"SOL");
        assert_eq!(p.mark_slot, 7);
        assert_eq!(p.mark_ticks, 12_061);
        assert_eq!(p.market_account, [5u8; 32]);
        assert_eq!(p.tick_size, 100);
        assert_eq!(p.asset_id, 65_559);
        assert_eq!(p.base_lot_decimals, 2);
        assert_eq!(p.is_tombstoned, 1);
        assert!(pam_entry(&d, 2).is_none());
        assert!(pam_entry(&d, u32::MAX).is_none());
    }

    /// TU-B1: our PAM offsets agree with the SDK view
    /// (`phoenix_rise::accounts::perp_asset_map`) on the live excerpt and on
    /// synthetic entries, including tombstone, isolated flag, final price.
    #[test]
    fn pam_offsets_match_sdk_view() {
        use phoenix_rise::accounts::perp_asset_map::PerpAssetMap;
        let mut d = live_pam();
        // Synthetic slot 3 with every field distinct.
        let e = PAM_HEADER + 3 * PAM_ENTRY;
        d[e..e + 4].copy_from_slice(b"TEST");
        put_entry(&mut d, 3, 0x0002_0003, &[9u8; 32], 777, 555, 42);
        d[e + 962] = 0xFE; // bld −2
        d[e + 1456..e + 1464].copy_from_slice(&31_337u64.to_le_bytes());
        let view = PerpAssetMap::try_from_account_bytes(&d).unwrap();
        assert_eq!(view.slots_used(), 90);
        assert_eq!(view.capacity(), 1024);
        let mut seen = 0;
        for (slot, sdk) in view.iter().enumerate().take(6) {
            let sdk = sdk.unwrap();
            let ours = pam_entry(&d, slot as u32).unwrap();
            let sm = sdk.metadata.static_market_params();
            assert_eq!(sdk.symbol.as_bytes(), &ours.symbol[..sdk.symbol.as_bytes().len()]);
            assert_eq!(sm.market_account, ours.market_account, "slot {slot}");
            assert_eq!(sm.asset_id(), ours.asset_id, "slot {slot}");
            assert_eq!(sm.tick_size.as_inner(), ours.tick_size, "slot {slot}");
            assert_eq!(sm.base_lot_decimals, ours.base_lot_decimals, "slot {slot}");
            let mp = sdk.metadata.oracle_price().mark_price.price;
            assert_eq!(mp.slot, ours.mark_slot, "slot {slot}");
            assert_eq!(mp.ticks.as_inner(), ours.mark_ticks, "slot {slot}");
            assert_eq!(sdk.metadata.risk_params().isolated_only, ours.isolated_only, "slot {slot}");
            assert_eq!(sdk.metadata.finalized_mark_price().as_inner(), ours.finalized_mark_price);
            seen += 1;
        }
        assert_eq!(seen, 6);
        // Live values (SPEC §2.3 MAJOR_SYMBOLS, §3.9).
        let sol = pam_entry(&d, 0).unwrap();
        assert_eq!((&sol.symbol[..4], sol.asset_id, sol.tick_size, sol.mark_ticks), (&b"SOL\0"[..], 0, 100, 12_108));
        assert_eq!(pam_entry(&d, 1).unwrap().asset_id, 1);
        assert_eq!(pam_entry(&d, 2).unwrap().asset_id, 2);
        assert_eq!(pam_entry(&d, 5).unwrap().isolated_only, 1);
        let t = pam_entry(&d, 3).unwrap();
        assert_eq!((t.asset_id, t.base_lot_decimals, t.finalized_mark_price), (0x0002_0003, -2, 31_337));
        // Tombstone flag agrees with the SDK (tombstoned entries are skipped by its iterator).
        d[e + 1466] = 1;
        let view = PerpAssetMap::try_from_account_bytes(&d).unwrap();
        assert_eq!(view.iter().count(), 89);
        assert_eq!(pam_entry(&d, 3).unwrap().is_tombstoned, 1);
    }

    #[test]
    fn trader_header_fields() {
        let mut d = vec![0u8; 240];
        d[88..96].copy_from_slice(&(-5i64).to_le_bytes());
        d[96..100].copy_from_slice(&63u32.to_le_bytes());
        d[192..200].copy_from_slice(&42u64.to_le_bytes());
        d[232..240].copy_from_slice(&128u64.to_le_bytes());
        let h = trader_header(&d).unwrap();
        assert_eq!(h.collateral, -5);
        assert_eq!(h.flags, 63);
        assert_eq!(h.last_deposit_slot, 42);
        assert_eq!(h.cap, 128);
        assert!(trader_header(&d[..239]).is_none());
    }

    /// TU-B1 (trader part): header and position records agree with the SDK
    /// `Trader` view, including the native-SOL header extension.
    #[test]
    fn trader_offsets_match_sdk_view() {
        use phoenix_rise::accounts::trader::Trader;
        let auth = [7u8; 32];
        let mut d = trader(&auth, 4, &[(3, -70), (0xFFFF_0000, 9), (0x0001_0005, 12)]);
        d[24..56].copy_from_slice(&[4u8; 32]);
        d[88..96].copy_from_slice(&1_234i64.to_le_bytes());
        d[112..116].copy_from_slice(&128u32.to_le_bytes());
        d[116..120].copy_from_slice(&3u32.to_le_bytes());
        d[156..188].copy_from_slice(&[6u8; 32]);
        d[192..200].copy_from_slice(&99u64.to_le_bytes());
        let t = Trader::try_from_account_bytes(&d).unwrap();
        let h = trader_header(&d).unwrap();
        assert_eq!(t.header.key, h.trader_key);
        assert_eq!(t.header.authority, h.authority);
        assert_eq!(t.header.position_authority, h.position_authority);
        assert_eq!(t.header.trader_state.quote_lot_collateral.as_inner(), h.collateral);
        assert_eq!(t.header.trader_state.flags, h.flags);
        assert_eq!(t.header.max_positions, h.max_positions);
        assert_eq!(t.header.trader_preference_bits, h.preference_bits);
        assert_eq!(t.header.funding_key, h.funding_key);
        assert_eq!(t.header.last_deposit_slot, h.last_deposit_slot);
        assert_eq!(t.header.trader_pda_index, h.pda_index);
        assert_eq!(t.header.trader_subaccount_index, h.subaccount_index);
        assert!(t.header.is_hot());
        assert_eq!((t.raw_len(), t.capacity()), (h.len, h.cap));
        let sdk: Vec<(u64, i64)> = t.positions().map(|(a, p)| (a, p.base_lot_position().as_inner())).collect();
        assert_eq!(sdk, vec![(3, -70), (0x0001_0005, 12)]);
        // The extension payload shares the base-lot slot (+8): the scan must skip it.
        assert_eq!(t.native_sol_collateral(), 9);
        assert_eq!(has_open_position(&d), Some(true));
        assert!(trader_layout_ok(&d, &auth));
        assert!(!trader_layout_ok(&d, &[8u8; 32]));
        // Position authority other than phx_authority (SPEC v3: no delegate).
        let mut delegated = d.clone();
        delegated[120..152].copy_from_slice(&[9u8; 32]);
        assert!(!trader_layout_ok(&delegated, &auth));
    }

    /// Tag 51 op 6 step 5 (TU-R5): flat means no record with a non-zero base,
    /// header extensions skipped; an inconsistent map fails closed.
    #[test]
    fn open_position_scan() {
        let auth = [7u8; 32];
        assert_eq!(has_open_position(&trader(&auth, 4, &[])), Some(false));
        assert_eq!(has_open_position(&trader(&auth, 4, &[(0xFFFF_0000, 5), (3, 0)])), Some(false));
        assert_eq!(has_open_position(&trader(&auth, 4, &[(0xFFFF_0000, 5), (3, 0), (7, -4)])), Some(true));
        // Only the low 32 bits of asset_index are used.
        assert_eq!(has_open_position(&trader(&auth, 4, &[(0x1_0000_0007, 2)])), Some(true));
        let mut bad = trader(&auth, 2, &[(1, 0)]);
        bad[224..232].copy_from_slice(&3u64.to_le_bytes()); // len > cap
        assert_eq!(has_open_position(&bad), None);
        assert_eq!(has_open_position(&trader(&auth, 2, &[])[..100]), None);
    }

    #[test]
    fn position_map_bounds() {
        let auth = [7u8; 32];
        let d = trader(&auth, 2, &[(1, 5)]);
        assert_eq!(position_map_len(&d), Some(1));
        let mut bad = d.clone();
        bad[224..232].copy_from_slice(&3u64.to_le_bytes()); // len > cap
        assert_eq!(position_map_len(&bad), None);
        assert!(!trader_layout_ok(&bad, &auth));
        let mut short = d.clone();
        short.truncate(240 + 40); // cap 2 needs 320 bytes
        assert_eq!(position_map_len(&short), None);
        // cap = 129 (ReallocTrader) is accepted (TB-37).
        let big = trader(&auth, 129, &[(1, 5)]);
        assert!(trader_layout_ok(&big, &auth));
        let mut idx = d.clone();
        idx[154] = 1;
        assert!(!trader_layout_ok(&idx, &auth));
        let mut disc = d.clone();
        disc[0] ^= 1;
        assert!(!trader_layout_ok(&disc, &auth));
    }

    const PHX: Pubkey = PHOENIX_PROGRAM_ID;

    fn gc_bytes(len: usize) -> Vec<u8> {
        let mut d = vec![0u8; len];
        d[0..8].copy_from_slice(&DISC_GLOBAL_CONFIG);
        d[296..328].copy_from_slice(&[0x11; 32]);
        d[328..360].copy_from_slice(&[0x12; 32]);
        d[360..392].copy_from_slice(&[0x13; 32]);
        d[392..424].copy_from_slice(&[0x14; 32]);
        d[424..456].copy_from_slice(&[0x15; 32]);
        if len >= 504 {
            d[472..504].copy_from_slice(&[0x16; 32]);
        }
        if len > 504 {
            d[504] = 0x83;
        }
        d
    }

    #[test]
    fn global_config_checks() {
        let ok = TestAccount::new(PHOENIX_GLOBAL_CONFIG, PHX, 1, &gc_bytes(2560), false, true, false);
        let k = check_global_config(&ok.info(), 504, true).unwrap();
        assert_eq!(k.perp_asset_map, [0x13; 32]);
        assert_eq!(k.gti_header, [0x14; 32]);
        assert_eq!(k.atb_header, [0x15; 32]);
        assert_eq!(k.exchange_status, 0x83);
        let e = Err(SijkaError::InvalidPhoenixGlobalConfig.into());
        let wrong_key = TestAccount::new([1; 32], PHX, 1, &gc_bytes(2560), false, true, false);
        assert_eq!(check_global_config(&wrong_key.info(), 504, false), e);
        let wrong_owner = TestAccount::new(PHOENIX_GLOBAL_CONFIG, [1; 32], 1, &gc_bytes(2560), false, true, false);
        assert_eq!(check_global_config(&wrong_owner.info(), 504, false), e);
        let short = TestAccount::new(PHOENIX_GLOBAL_CONFIG, PHX, 1, &gc_bytes(503), false, true, false);
        assert_eq!(check_global_config(&short.info(), 0, false), e);
        let exact = TestAccount::new(PHOENIX_GLOBAL_CONFIG, PHX, 1, &gc_bytes(504), false, true, false);
        assert_eq!(check_global_config(&exact.info(), 504, false).unwrap().exchange_status, 0);
        assert_eq!(check_global_config(&exact.info(), 520, false), e);
        let mut bad_disc = gc_bytes(2560);
        bad_disc[3] ^= 1;
        let bd = TestAccount::new(PHOENIX_GLOBAL_CONFIG, PHX, 1, &bad_disc, false, true, false);
        assert_eq!(check_global_config(&bd.info(), 504, false), e);
        let ro = TestAccount::new(PHOENIX_GLOBAL_CONFIG, PHX, 1, &gc_bytes(2560), false, false, false);
        assert_eq!(check_global_config(&ro.info(), 504, true), Err(SijkaError::AccountNotWritable.into()));
        assert!(check_global_config(&ro.info(), 504, false).is_ok());
    }

    #[test]
    fn pam_account_checks() {
        let key = [0x13u8; 32];
        let d = pam(4, 2, 0);
        let ok = TestAccount::new(key, PHX, 1, &d, false, true, false);
        assert!(check_perp_asset_map(&ok.info(), &key, PamCheck::Full, true).is_ok());
        let e = Err(SijkaError::InvalidPerpAssetMap.into());
        assert_eq!(check_perp_asset_map(&ok.info(), &[1; 32], PamCheck::Full, true), e);
        let ro = TestAccount::new(key, PHX, 1, &d, false, false, false);
        assert_eq!(
            check_perp_asset_map(&ro.info(), &key, PamCheck::Full, true),
            Err(SijkaError::AccountNotWritable.into())
        );
        let mut bad = d.clone();
        bad.push(0);
        let b = TestAccount::new(key, PHX, 1, &bad, false, true, false);
        assert_eq!(check_perp_asset_map(&b.info(), &key, PamCheck::Full, true), e);
        // Tag 51 op 1, 6: key and owner only (review REC-9) — a changed layout still passes.
        assert!(check_perp_asset_map(&b.info(), &key, PamCheck::KeyAndOwner, true).is_ok());
        let other = TestAccount::new(key, [2; 32], 1, &d, false, true, false);
        assert_eq!(check_perp_asset_map(&other.info(), &key, PamCheck::KeyAndOwner, true), e);
    }

    #[test]
    fn trader_account_checks() {
        let auth = [7u8; 32];
        let key = [0x21u8; 32];
        let d = trader(&auth, 4, &[(0, 1)]);
        let ok = TestAccount::new(key, PHX, 1, &d, false, true, false);
        assert!(check_trader_account(&ok.info(), &key, &auth, TraderCheck::Full, true).is_ok());
        assert_eq!(
            check_trader_account(&ok.info(), &[0; 32], &auth, TraderCheck::WithdrawOnly, true),
            Err(SijkaError::TraderNotRegistered.into())
        );
        let e = Err(SijkaError::InvalidPhoenixTraderAccount.into());
        assert_eq!(check_trader_account(&ok.info(), &[1; 32], &auth, TraderCheck::WithdrawOnly, false), e);
        assert_eq!(check_trader_account(&ok.info(), &key, &[8; 32], TraderCheck::Full, false), e);
        assert_eq!(check_trader_account(&ok.info(), &key, &[8; 32], TraderCheck::WithdrawOnly, false), e);
        assert!(check_trader_account(&ok.info(), &key, &auth, TraderCheck::WithdrawOnly, false).is_ok());
        // A position authority other than phx_authority fails both modes
        // (SPEC v3 §5.0.5: the program never appoints a delegate).
        let mut dd = d.clone();
        dd[120..152].copy_from_slice(&[0x33; 32]);
        let deleg = TestAccount::new(key, PHX, 1, &dd, false, true, false);
        assert_eq!(check_trader_account(&deleg.info(), &key, &auth, TraderCheck::Full, true), e);
        assert_eq!(check_trader_account(&deleg.info(), &key, &auth, TraderCheck::WithdrawOnly, true), e);
        let ro = TestAccount::new(key, PHX, 1, &d, false, false, false);
        assert_eq!(
            check_trader_account(&ro.info(), &key, &auth, TraderCheck::Full, true),
            Err(SijkaError::AccountNotWritable.into())
        );
        let foreign = TestAccount::new(key, [3; 32], 1, &d, false, true, false);
        assert_eq!(check_trader_account(&foreign.info(), &key, &auth, TraderCheck::WithdrawOnly, false), e);
        // Changed layout after @232: the full check rejects, the withdraw-only
        // check (reads only @192) accepts (review REC-9).
        let mut changed = d.clone();
        changed[232..240].copy_from_slice(&1_000u64.to_le_bytes());
        let c = TestAccount::new(key, PHX, 1, &changed, false, true, false);
        assert_eq!(check_trader_account(&c.info(), &key, &auth, TraderCheck::Full, true), e);
        assert!(check_trader_account(&c.info(), &key, &auth, TraderCheck::WithdrawOnly, true).is_ok());
    }

    #[test]
    fn arena_checks() {
        let gc = GlobalConfigKeys {
            gti_header: [0x14; 32],
            atb_header: [0x15; 32],
            perp_asset_map: [0x13; 32],
            ..Default::default()
        };
        let acc = |k: u8, w: bool| TestAccount::new([k; 32], PHX, 1, &[], false, w, false);
        let set = [acc(0x14, true), acc(0x30, true), acc(0x15, true)];
        let infos: Vec<AccountInfo> = set.iter().map(TestAccount::info).collect();
        assert!(check_arenas(&infos, 2, &gc, true).is_ok());
        let e = Err(SijkaError::InvalidArenaAccounts.into());
        assert_eq!(check_arenas(&infos, 1, &gc, true), e); // ATB[0] would be 0x30
        assert_eq!(check_arenas(&infos, 0, &gc, true), e);
        assert_eq!(check_arenas(&infos, 3, &gc, true), e);
        assert_eq!(check_arenas(&infos, 4, &gc, true), e);
        let dup = [acc(0x14, true), acc(0x14, true), acc(0x15, true)];
        let di: Vec<AccountInfo> = dup.iter().map(TestAccount::info).collect();
        assert_eq!(check_arenas(&di, 2, &gc, true), e);
        let alias = [acc(0x14, true), acc(0x13, true), acc(0x15, true)];
        let ai: Vec<AccountInfo> = alias.iter().map(TestAccount::info).collect();
        assert_eq!(check_arenas(&ai, 2, &gc, true), e);
        let ro = [acc(0x14, true), acc(0x15, false)];
        let ri: Vec<AccountInfo> = ro.iter().map(TestAccount::info).collect();
        assert_eq!(check_arenas(&ri, 1, &gc, true), e);
        assert!(check_arenas(&ri, 1, &gc, false).is_ok());
        let foreign = [acc(0x14, true), TestAccount::new([0x15; 32], [1; 32], 1, &[], false, true, false)];
        let fi: Vec<AccountInfo> = foreign.iter().map(TestAccount::info).collect();
        assert_eq!(check_arenas(&fi, 1, &gc, true), e);
        assert!(check_arenas_disjoint(&infos, &[&[0x40; 32]]).is_ok());
        assert_eq!(check_arenas_disjoint(&infos, &[&[0x30; 32]]), e);
        // g = a = 8 accepted, 9 rejected.
        let mut many = vec![acc(0x14, true)];
        many.extend((1..8).map(|i| acc(0x40 + i, true)));
        many.push(acc(0x15, true));
        many.extend((1..8).map(|i| acc(0x60 + i, true)));
        let mi: Vec<AccountInfo> = many.iter().map(TestAccount::info).collect();
        assert!(check_arenas(&mi, 8, &gc, true).is_ok());
        let mut nine = vec![acc(0x14, true)];
        nine.extend((1..9).map(|i| acc(0x40 + i, true)));
        nine.push(acc(0x15, true));
        let ni: Vec<AccountInfo> = nine.iter().map(TestAccount::info).collect();
        assert_eq!(check_arenas(&ni, 9, &gc, true), e);
    }
}
