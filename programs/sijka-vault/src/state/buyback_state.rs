// Copyright (c) 2026 prt1sn. All rights reserved.
//! `BuybackState` — PDA `["buyback_state"]`, 1304 bytes (SPEC §3.7), with the
//! pinned pump addresses k0–k26 (§3.7.1) and `BuybackParams` (§3.8).
//!
//! SPEC §3.0: this layout contains u128 fields, so it is only ever accessed by
//! offsets (no pointer casts).

use pinocchio::account_info::{AccountInfo, Ref, RefMut};
use pinocchio::program_error::ProgramError;
use pinocchio::pubkey::Pubkey;

use crate::constants::DISC_BUYBACK_STATE;
use crate::error::SijkaError;
use crate::state::{borrow_checked, borrow_mut_checked, check_stored_key, layout};
use crate::util::bytes::{array_ref, write_bytes};

layout! {
    /// Read view over the 1304 bytes of `BuybackState`.
    view BuybackState, BuybackStateMut, BUYBACK_STATE_LEN = 1304;
    bytes(8) discriminator set_discriminator DISCRIMINATOR @ 0;
    u8 version set_version VERSION @ 8;
    u8 flags set_flags FLAGS @ 9;
    u8 venue set_venue VENUE @ 10;
    u8 quote_kind set_quote_kind QUOTE_KIND @ 11;
    u8 base_decimals set_base_decimals BASE_DECIMALS @ 12;
    u8 base_tp_kind set_base_tp_kind BASE_TP_KIND @ 13;
    u8 bump_buyback_state set_bump_buyback_state BUMP_BUYBACK_STATE @ 14;
    u8 bump_buyback_authority set_bump_buyback_authority BUMP_BUYBACK_AUTHORITY @ 15;
    u8 bump_swap_authority set_bump_swap_authority BUMP_SWAP_AUTHORITY @ 16;
    u8 bump_bb_unwrap set_bump_bb_unwrap BUMP_BB_UNWRAP @ 17;
    raw(6) _pad0 set_pad0 PAD0 @ 18;
    raw(8) _reserved1 set_reserved1 RESERVED1 @ 24;
    i64 last_obs_ts set_last_obs_ts LAST_OBS_TS @ 32;
    u64 last_obs_slot set_last_obs_slot LAST_OBS_SLOT @ 40;
    u128 ema_price_x64 set_ema_price_x64 EMA_PRICE_X64 @ 48;
    u128 last_obs_price_x64 set_last_obs_price_x64 LAST_OBS_PRICE_X64 @ 64;
    u64 last_obs_quote set_last_obs_quote LAST_OBS_QUOTE @ 80;
    u64 q_ema set_q_ema Q_EMA @ 88;
    u16 fresh_obs set_fresh_obs FRESH_OBS @ 96;
    raw(6) _pad1 set_pad1 PAD1 @ 98;
    i64 last_buy_ts set_last_buy_ts LAST_BUY_TS @ 104;
    u64 last_buy_slot set_last_buy_slot LAST_BUY_SLOT @ 112;
    i64 last_swap_ts set_last_swap_ts LAST_SWAP_TS @ 120;
    u64 venue_since_slot set_venue_since_slot VENUE_SINCE_SLOT @ 128;
    u64 n_obs set_n_obs N_OBS @ 136;
    u64 n_chunks set_n_chunks N_CHUNKS @ 144;
    u64 cum_payout_buyback_spent set_cum_payout_buyback_spent CUM_PAYOUT_BUYBACK_SPENT @ 152;
    u64 cum_usdc_swapped set_cum_usdc_swapped CUM_USDC_SWAPPED @ 160;
    u64 cum_sol_from_swaps set_cum_sol_from_swaps CUM_SOL_FROM_SWAPS @ 168;
    u64 cum_quote_spent_curve set_cum_quote_spent_curve CUM_QUOTE_SPENT_CURVE @ 176;
    u64 cum_quote_spent_amm set_cum_quote_spent_amm CUM_QUOTE_SPENT_AMM @ 184;
    u64 cum_rent_spent set_cum_rent_spent CUM_RENT_SPENT @ 192;
    u64 cum_bought_tokens set_cum_bought_tokens CUM_BOUGHT_TOKENS @ 200;
    u64 cum_burned_tokens set_cum_burned_tokens CUM_BURNED_TOKENS @ 208;
    u64 n_swaps set_n_swaps N_SWAPS @ 216;
    raw(8) _reserved0 set_reserved0 RESERVED0 @ 224;
    sub(80) params set_params PARAMS @ 232;
    raw(864) pinned set_pinned PINNED @ 312;
    key usdc_mint set_usdc_mint USDC_MINT @ 1176;
    i64 next_buy_ts set_next_buy_ts NEXT_BUY_TS @ 1208;
    i64 next_swap_ts set_next_swap_ts NEXT_SWAP_TS @ 1216;
    raw(80) _reserved_tail set_reserved_tail RESERVED_TAIL @ 1224;
}

/// `flags` bits (SPEC §3.7).
pub mod bb_flags {
    pub const PINNED: u8 = 1 << 0;
    pub const OBS_INIT: u8 = 1 << 1;
    pub const ALL: u8 = PINNED | OBS_INIT;
}

/// `venue` values.
pub mod bb_venue {
    pub const NONE: u8 = 0;
    pub const CURVE: u8 = 1;
    pub const AMM: u8 = 2;
}

/// `quote_kind` values.
pub mod quote_kind {
    pub const SOL: u8 = 1;
    pub const USDC: u8 = 2;
}

/// `base_tp_kind` values.
pub mod base_tp_kind {
    pub const SPL_TOKEN: u8 = 1;
    pub const TOKEN_2022: u8 = 2;
}

/// Number of pinned addresses (k0..k26).
pub const PINNED_COUNT: usize = 27;

/// Indices of the pinned addresses (SPEC §3.7.1).
pub mod pinned {
    pub const BUYBACK_AUTHORITY: usize = 0;
    pub const SWAP_AUTHORITY: usize = 1;
    pub const BB_UNWRAP: usize = 2;
    pub const BB_USDC: usize = 3;
    pub const SWAP_USDC: usize = 4;
    pub const BB_WSOL: usize = 5;
    pub const MINT: usize = 6;
    pub const BASE_TOKEN_PROGRAM: usize = 7;
    pub const QUOTE_MINT: usize = 8;
    pub const BB_SIJKA: usize = 9;
    pub const BB_QUOTE: usize = 10;
    pub const BONDING_CURVE: usize = 11;
    pub const ASSOC_BASE_BONDING_CURVE: usize = 12;
    pub const ASSOC_QUOTE_BONDING_CURVE: usize = 13;
    pub const SHARING_CONFIG: usize = 14;
    pub const CREATOR_VAULT: usize = 15;
    pub const ASSOC_CREATOR_VAULT: usize = 16;
    pub const PUMP_USER_VOLUME_ACC: usize = 17;
    pub const PUMP_ASSOC_USER_VOLUME_ACC: usize = 18;
    pub const POOL_AUTHORITY: usize = 19;
    pub const POOL: usize = 20;
    pub const POOL_BASE_TA: usize = 21;
    pub const POOL_QUOTE_TA: usize = 22;
    pub const COIN_CREATOR_VAULT_AUTHORITY: usize = 23;
    pub const COIN_CREATOR_VAULT_ATA: usize = 24;
    pub const AMM_USER_VOLUME_ACC: usize = 25;
    pub const POOL_V2: usize = 26;

    /// Names as in SPEC §3.7.1, indexed by k.
    pub const NAMES: [&str; super::PINNED_COUNT] = [
        "buyback_authority",
        "swap_authority",
        "bb_unwrap",
        "bb_usdc",
        "swap_usdc",
        "bb_wsol",
        "mint",
        "base_token_program",
        "quote_mint",
        "bb_sijka",
        "bb_quote",
        "bonding_curve",
        "assoc_base_bonding_curve",
        "assoc_quote_bonding_curve",
        "sharing_config",
        "creator_vault",
        "assoc_creator_vault",
        "pump_user_volume_acc",
        "pump_assoc_user_volume_acc",
        "pool_authority",
        "pool",
        "pool_base_ta",
        "pool_quote_ta",
        "coin_creator_vault_authority",
        "coin_creator_vault_ata",
        "amm_user_volume_acc",
        "pool_v2",
    ];
}

/// Offset of pinned key `k` (`312 + 32·k`), if `k < 27`.
#[inline]
pub fn pinned_offset(k: usize) -> Option<usize> {
    if k >= PINNED_COUNT {
        return None;
    }
    k.checked_mul(32)?.checked_add(off::PINNED)
}

impl<'a> BuybackState<'a> {
    /// Discriminator `SIJKABBS` and `version == 1` (SPEC §3.0).
    #[inline]
    pub fn header_ok(&self) -> bool {
        self.discriminator() == &DISC_BUYBACK_STATE && self.version() == 1
    }

    /// Pinned key `k`; `None` if `k ≥ 27`.
    #[inline]
    pub fn pinned(&self, k: usize) -> Option<&'a Pubkey> {
        array_ref::<32>(self.bytes(), pinned_offset(k)?)
    }

    /// Typed view of `params`.
    #[inline]
    pub fn buyback_params(&self) -> buyback_params::BuybackParams<'a> {
        buyback_params::BuybackParams::from_array(self.params())
    }

    #[inline]
    pub fn is_pinned(&self) -> bool {
        self.flags() & bb_flags::PINNED != 0
    }
}

impl BuybackStateMut<'_> {
    /// Write pinned key `k`; `false` if `k ≥ 27`.
    #[inline]
    pub fn set_pinned(&mut self, k: usize, key: &Pubkey) -> bool {
        match pinned_offset(k) {
            Some(o) => write_bytes(self.bytes_mut(), o, key).is_some(),
            None => false,
        }
    }
}

/// Standard `buyback_state` check and read-only borrow (SPEC §3.0): key equal
/// to `cfg.buyback_state` when `Config` is available (`expected_key = Some`),
/// otherwise owner + discriminator only (tags 42–46); length 1304, version 1.
/// Error: `InvalidBuybackState`.
pub fn load_buyback_state<'a>(
    ai: &'a AccountInfo,
    program_id: &Pubkey,
    expected_key: Option<&Pubkey>,
) -> Result<Ref<'a, [u8]>, ProgramError> {
    if let Some(k) = expected_key {
        check_stored_key(ai, k, SijkaError::InvalidBuybackState)?;
    }
    let data = borrow_checked(ai, program_id, BUYBACK_STATE_LEN, SijkaError::InvalidBuybackState)?;
    match BuybackState::new(&data) {
        Some(b) if b.header_ok() => {}
        _ => return Err(SijkaError::InvalidBuybackState.fail()),
    }
    Ok(data)
}

/// As [`load_buyback_state`], plus `is_writable` (`AccountNotWritable`).
pub fn load_buyback_state_mut<'a>(
    ai: &'a AccountInfo,
    program_id: &Pubkey,
    expected_key: Option<&Pubkey>,
) -> Result<RefMut<'a, [u8]>, ProgramError> {
    if let Some(k) = expected_key {
        check_stored_key(ai, k, SijkaError::InvalidBuybackState)?;
    }
    let data = borrow_mut_checked(
        ai,
        program_id,
        BUYBACK_STATE_LEN,
        SijkaError::InvalidBuybackState,
        SijkaError::AccountNotWritable,
    )?;
    match BuybackState::new(&data) {
        Some(b) if b.header_ok() => {}
        _ => return Err(SijkaError::InvalidBuybackState.fail()),
    }
    Ok(data)
}

/// `BuybackParams` (`BuybackState@232`, 80 bytes, SPEC §3.8).
pub mod buyback_params {
    use crate::error::SijkaError;
    use crate::state::layout;

    layout! {
        /// Buyback parameters.
        view BuybackParams, BuybackParamsMut, BUYBACK_PARAMS_LEN = 80;
        u16 chunk_bps set_chunk_bps CHUNK_BPS @ 0;
        raw(4) _reserved0 set_reserved0 RESERVED0 @ 2;
        u16 obs_clamp_bps set_obs_clamp_bps OBS_CLAMP_BPS @ 6;
        raw(2) _reserved1 set_reserved1 RESERVED1 @ 8;
        u16 warmup_obs set_warmup_obs WARMUP_OBS @ 10;
        u32 buy_min_interval_s set_buy_min_interval_s BUY_MIN_INTERVAL_S @ 12;
        u32 obs_max_age_s set_obs_max_age_s OBS_MAX_AGE_S @ 16;
        u32 swap_min_interval_s set_swap_min_interval_s SWAP_MIN_INTERVAL_S @ 20;
        raw(4) _reserved2 set_reserved2 RESERVED2 @ 24;
        raw(4) _pad set_pad PAD @ 28;
        u64 chunk_max_quote set_chunk_max_quote CHUNK_MAX_QUOTE @ 32;
        u64 chunk_min_quote set_chunk_min_quote CHUNK_MIN_QUOTE @ 40;
        u64 swap_max_usdc set_swap_max_usdc SWAP_MAX_USDC @ 48;
        u64 sol_budget_cap set_sol_budget_cap SOL_BUDGET_CAP @ 56;
        raw(16) _reserved set_reserved RESERVED @ 64;
    }

    impl BuybackParams<'_> {
        /// Structural check of the parameters written by tag 40 (SPEC §3.8;
        /// SPEC v4: fixed, no admin setter). The former `max_dev_bps` and
        /// `fee_cap_bps` (`_reserved0`: no spot guard, DECISIONS §23 item 3;
        /// no program-side floor with a pump fee cap, item 6), `swap_band_bps`
        /// and `mark_max_age_slots` bytes (`_reserved1`, `_reserved2`: no
        /// oracle, item 4) are zero.
        pub fn validate(&self) -> Result<(), SijkaError> {
            let ok = (1..=10_000).contains(&self.chunk_bps())
                && (1..=10_000).contains(&self.obs_clamp_bps())
                && self.warmup_obs() >= 1
                && self.obs_max_age_s() >= 1
                && self.chunk_min_quote() >= 1
                && self.chunk_min_quote() <= self.chunk_max_quote()
                && self.swap_max_usdc() >= 1
                && self.sol_budget_cap() >= 1
                && crate::util::bytes::is_zero(self.bytes(), off::RESERVED0, 4)
                && crate::util::bytes::is_zero(self.bytes(), off::RESERVED1, 2)
                && crate::util::bytes::is_zero(self.bytes(), off::RESERVED2, 4)
                && crate::util::bytes::is_zero(self.bytes(), off::PAD, 4)
                && crate::util::bytes::is_zero(self.bytes(), off::RESERVED, 16);
            if ok { Ok(()) } else { Err(SijkaError::InvalidParams) }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::tests::assert_tiles;

    #[test]
    fn layouts_tile() {
        assert_tiles(FIELDS, BUYBACK_STATE_LEN);
        assert_tiles(buyback_params::FIELDS, buyback_params::BUYBACK_PARAMS_LEN);
        assert_eq!(BUYBACK_STATE_LEN, crate::constants::BUYBACK_STATE_LEN);
        assert_eq!(off::PINNED + 32 * PINNED_COUNT, off::USDC_MINT);
    }

    #[test]
    fn spot_offsets_from_spec() {
        assert_eq!(off::RESERVED1, 24);
        assert_eq!(buyback_params::off::RESERVED0, 2);
        assert_eq!(buyback_params::off::RESERVED1, 8);
        assert_eq!(buyback_params::off::RESERVED2, 24);
        assert_eq!(off::EMA_PRICE_X64, 48);
        assert_eq!(off::CUM_BURNED_TOKENS, 208);
        assert_eq!(off::PARAMS, 232);
        assert_eq!(off::PINNED, 312);
        assert_eq!(off::USDC_MINT, 1176);
        assert_eq!(off::NEXT_BUY_TS, 1208);
        assert_eq!(off::NEXT_SWAP_TS, 1216);
        assert_eq!(pinned_offset(pinned::POOL_V2), Some(1144));
        assert_eq!(pinned_offset(pinned::BB_SIJKA), Some(600));
        assert_eq!(pinned_offset(27), None);
    }

    #[test]
    fn pinned_round_trip_and_u128() {
        let mut buf = vec![0u8; BUYBACK_STATE_LEN];
        {
            let mut m = BuybackStateMut::new(&mut buf).unwrap();
            m.set_discriminator(&DISC_BUYBACK_STATE);
            m.set_version(1);
            m.set_flags(bb_flags::PINNED);
            m.set_ema_price_x64(u128::MAX - 1);
            assert!(m.set_pinned(26, &[9u8; 32]));
            assert!(!m.set_pinned(27, &[9u8; 32]));
        }
        let b = BuybackState::new(&buf).unwrap();
        assert!(b.header_ok());
        assert!(b.is_pinned());
        assert_eq!(b.ema_price_x64(), u128::MAX - 1);
        assert_eq!(b.pinned(26), Some(&[9u8; 32]));
        assert_eq!(b.pinned(0), Some(&[0u8; 32]));
        assert!(b.pinned(27).is_none());
        assert_eq!(&buf[1144..1176], &[9u8; 32]);
    }

    #[test]
    fn buyback_params_validation_bounds() {
        let mut b = [0u8; 80];
        {
            let mut m = buyback_params::BuybackParamsMut::from_array(&mut b);
            m.set_chunk_bps(10);
            m.set_obs_clamp_bps(1_000);
            m.set_warmup_obs(40);
            m.set_buy_min_interval_s(60);
            m.set_obs_max_age_s(120);
            m.set_swap_min_interval_s(60);
            m.set_chunk_max_quote(1_000_000_000);
            m.set_chunk_min_quote(10_000_000);
            m.set_swap_max_usdc(1_000_000_000);
            m.set_sol_budget_cap(20_000_000_000);
        }
        let ok = |b: &[u8; 80]| buyback_params::BuybackParams::from_array(b).validate().is_ok();
        assert!(ok(&b));
        let mut x = b;
        buyback_params::BuybackParamsMut::from_array(&mut x).set_chunk_min_quote(1_000_000_001);
        assert!(!ok(&x));
        let mut x = b;
        buyback_params::BuybackParamsMut::from_array(&mut x).set_chunk_bps(0);
        assert!(!ok(&x));
        let mut x = b;
        x[79] = 1;
        assert!(!ok(&x));
        // The retired spot guard / fee cap / swap band / mark age bytes must
        // stay zero.
        for i in [2usize, 3, 4, 5, 8, 9, 24, 25, 26, 27] {
            let mut x = b;
            x[i] = 1;
            assert!(!ok(&x), "byte {i}");
        }
    }
}
