// Copyright (c) 2026 prt1sn. All rights reserved.
//! `Config` — PDA `["config"]`, 5144 bytes (SPEC §3.1), with the embedded
//! `HarvestParams` (§3.2) and `InflowParams` (§3.3).

use pinocchio::account_info::{AccountInfo, Ref, RefMut};
use pinocchio::program_error::ProgramError;
use pinocchio::pubkey::Pubkey;

use crate::constants::{DISC_CONFIG, WSOL_MINT};
use crate::error::SijkaError;
use crate::state::{borrow_checked, borrow_mut_checked, layout};
use crate::util::bytes::{read_u32, write_u32};

layout! {
    /// Read view over the 5144 bytes of `Config`.
    view Config, ConfigMut, CONFIG_LEN = 5144;
    bytes(8) discriminator set_discriminator DISCRIMINATOR @ 0;
    u16 version set_version VERSION @ 8;
    raw(1) _reserved6 set_reserved6 RESERVED6 @ 10;
    raw(1) _reserved0 set_reserved0 RESERVED0 @ 11;
    u16 creator_share_bps set_creator_share_bps CREATOR_SHARE_BPS @ 12;
    u8 token_decimals set_token_decimals TOKEN_DECIMALS @ 14;
    u8 trader_registered_by_program set_trader_registered_by_program TRADER_REGISTERED_BY_PROGRAM @ 15;
    key admin set_admin ADMIN @ 16;
    key keeper set_keeper KEEPER @ 48;
    key trader set_trader TRADER @ 80;
    key creator_payout set_creator_payout CREATOR_PAYOUT @ 112;
    key quote_mint set_quote_mint QUOTE_MINT @ 144;
    key usdc_mint set_usdc_mint USDC_MINT @ 176;
    key phusd_mint set_phusd_mint PHUSD_MINT @ 208;
    key token_mint set_token_mint TOKEN_MINT @ 240;
    key token_program set_token_program TOKEN_PROGRAM @ 272;
    key phoenix_trader set_phoenix_trader PHOENIX_TRADER @ 304;
    key fee_inbox set_fee_inbox FEE_INBOX @ 336;
    key phx_authority set_phx_authority PHX_AUTHORITY @ 368;
    key swap_authority set_swap_authority SWAP_AUTHORITY @ 400;
    key buyback_authority set_buyback_authority BUYBACK_AUTHORITY @ 432;
    key rent_payer set_rent_payer RENT_PAYER @ 464;
    key vault_usdc set_vault_usdc VAULT_USDC @ 496;
    key vault_phusd set_vault_phusd VAULT_PHUSD @ 528;
    key creator_usdc set_creator_usdc CREATOR_USDC @ 560;
    key buyback_usdc set_buyback_usdc BUYBACK_USDC @ 592;
    key buyback_token set_buyback_token BUYBACK_TOKEN @ 624;
    u8 config_bump set_config_bump CONFIG_BUMP @ 656;
    u8 fee_inbox_bump set_fee_inbox_bump FEE_INBOX_BUMP @ 657;
    u8 phx_authority_bump set_phx_authority_bump PHX_AUTHORITY_BUMP @ 658;
    u8 swap_authority_bump set_swap_authority_bump SWAP_AUTHORITY_BUMP @ 659;
    u8 buyback_authority_bump set_buyback_authority_bump BUYBACK_AUTHORITY_BUMP @ 660;
    u8 rent_payer_bump set_rent_payer_bump RENT_PAYER_BUMP @ 661;
    u8 phoenix_trader_bump set_phoenix_trader_bump PHOENIX_TRADER_BUMP @ 662;
    raw(1) _pad0 set_pad0 PAD0 @ 663;
    u32 trader_preference_bits set_trader_preference_bits TRADER_PREFERENCE_BITS @ 664;
    u32 trader_max_positions set_trader_max_positions TRADER_MAX_POSITIONS @ 668;
    i64 created_ts set_created_ts CREATED_TS @ 672;
    i64 token_mint_set_ts set_token_mint_set_ts TOKEN_MINT_SET_TS @ 680;
    i64 trader_registered_ts set_trader_registered_ts TRADER_REGISTERED_TS @ 688;
    i64 last_admin_action_ts set_last_admin_action_ts LAST_ADMIN_ACTION_TS @ 696;
    u64 cum_inflow_usdc set_cum_inflow_usdc CUM_INFLOW_USDC @ 704;
    u64 cum_payout_usdc set_cum_payout_usdc CUM_PAYOUT_USDC @ 712;
    u64 cum_payout_creator set_cum_payout_creator CUM_PAYOUT_CREATOR @ 720;
    u64 cum_payout_buyback set_cum_payout_buyback CUM_PAYOUT_BUYBACK @ 728;
    raw(8) _reserved2 set_reserved2 RESERVED2 @ 736;
    u64 cum_withdraw_fees set_cum_withdraw_fees CUM_WITHDRAW_FEES @ 744;
    u64 harvest_count set_harvest_count HARVEST_COUNT @ 752;
    i64 last_harvest_ts set_last_harvest_ts LAST_HARVEST_TS @ 760;
    u64 last_harvest_slot set_last_harvest_slot LAST_HARVEST_SLOT @ 768;
    u64 last_harvest_amount set_last_harvest_amount LAST_HARVEST_AMOUNT @ 776;
    u64 inflow_count set_inflow_count INFLOW_COUNT @ 784;
    u64 cum_creator_paid_out set_cum_creator_paid_out CUM_CREATOR_PAID_OUT @ 792;
    u64 creator_pay_count set_creator_pay_count CREATOR_PAY_COUNT @ 800;
    u64 cum_ember_wrap_fees set_cum_ember_wrap_fees CUM_EMBER_WRAP_FEES @ 808;
    raw(16) _counters_reserved set_counters_reserved COUNTERS_RESERVED @ 816;
    sub(64) harvest_params set_harvest_params HARVEST_PARAMS @ 832;
    raw(32) _reserved7 set_reserved7 RESERVED7 @ 896;
    key buyback_state set_buyback_state BUYBACK_STATE @ 928;
    key bb_unwrap set_bb_unwrap BB_UNWRAP @ 960;
    raw(1) _reserved8 set_reserved8 RESERVED8 @ 992;
    u8 buyback_state_bump set_buyback_state_bump BUYBACK_STATE_BUMP @ 993;
    u8 bb_unwrap_bump set_bb_unwrap_bump BB_UNWRAP_BUMP @ 994;
    u8 creator_escrow_bump set_creator_escrow_bump CREATOR_ESCROW_BUMP @ 995;
    raw(4) _pad1 set_pad1 PAD1 @ 996;
    raw(8) _reserved9 set_reserved9 RESERVED9 @ 1000;
    raw(104) _reserved3 set_reserved3 RESERVED3 @ 1008;
    sub(40) inflow_params set_inflow_params INFLOW_PARAMS @ 1112;
    raw(1) _reserved10 set_reserved10 RESERVED10 @ 1152;
    raw(7) _pad2 set_pad2 PAD2 @ 1153;
    u64 cum_ember_wrapped set_cum_ember_wrapped CUM_EMBER_WRAPPED @ 1160;
    u64 cum_phusd_direct set_cum_phusd_direct CUM_PHUSD_DIRECT @ 1168;
    u64 cum_swap_lamports_spent set_cum_swap_lamports_spent CUM_SWAP_LAMPORTS_SPENT @ 1176;
    u64 cum_swap_usdc_received set_cum_swap_usdc_received CUM_SWAP_USDC_RECEIVED @ 1184;
    u64 cum_fee_usdc_swept set_cum_fee_usdc_swept CUM_FEE_USDC_SWEPT @ 1192;
    u64 cum_swap_usdc_swept set_cum_swap_usdc_swept CUM_SWAP_USDC_SWEPT @ 1200;
    u64 swap_count set_swap_count SWAP_COUNT @ 1208;
    i64 last_swap_ts set_last_swap_ts LAST_SWAP_TS @ 1216;
    u64 last_swap_slot set_last_swap_slot LAST_SWAP_SLOT @ 1224;
    u64 last_deposit_slot set_last_deposit_slot LAST_DEPOSIT_SLOT @ 1232;
    u64 last_deposit_amount set_last_deposit_amount LAST_DEPOSIT_AMOUNT @ 1240;
    key swap_wsol set_swap_wsol SWAP_WSOL @ 1248;
    key swap_usdc set_swap_usdc SWAP_USDC @ 1280;
    key creator_escrow set_creator_escrow CREATOR_ESCROW @ 1312;
    i64 next_swap_ts set_next_swap_ts NEXT_SWAP_TS @ 1344;
    raw(16) _reserved4 set_reserved4 RESERVED4 @ 1352;
    key creator_escrow_usdc set_creator_escrow_usdc CREATOR_ESCROW_USDC @ 1368;
    u8 recovery_mode set_recovery_mode RECOVERY_MODE @ 1400;
    u8 venue_last_verdict set_venue_last_verdict VENUE_LAST_VERDICT @ 1401;
    u8 venue_last_reason set_venue_last_reason VENUE_LAST_REASON @ 1402;
    u8 venue_major_seen set_venue_major_seen VENUE_MAJOR_SEEN @ 1403;
    bytes(12) venue_major_asset_id set_venue_major_asset_id VENUE_MAJOR_ASSET_ID @ 1404;
    i64 venue_down_since_ts set_venue_down_since_ts VENUE_DOWN_SINCE_TS @ 1416;
    i64 venue_last_down_obs_ts set_venue_last_down_obs_ts VENUE_LAST_DOWN_OBS_TS @ 1424;
    i64 last_venue_obs_ts set_last_venue_obs_ts LAST_VENUE_OBS_TS @ 1432;
    u64 last_venue_obs_slot set_last_venue_obs_slot LAST_VENUE_OBS_SLOT @ 1440;
    u64 venue_obs_count set_venue_obs_count VENUE_OBS_COUNT @ 1448;
    i64 recovery_latched_ts set_recovery_latched_ts RECOVERY_LATCHED_TS @ 1456;
    u64 recovery_latched_slot set_recovery_latched_slot RECOVERY_LATCHED_SLOT @ 1464;
    key emergency_recipient set_emergency_recipient EMERGENCY_RECIPIENT @ 1472;
    key emergency_recipient_usdc set_emergency_recipient_usdc EMERGENCY_RECIPIENT_USDC @ 1504;
    u64 cum_recovery_withdrawn set_cum_recovery_withdrawn CUM_RECOVERY_WITHDRAWN @ 1536;
    u64 cum_recovered_usdc set_cum_recovered_usdc CUM_RECOVERED_USDC @ 1544;
    raw(8) _reserved11 set_reserved11 RESERVED11 @ 1552;
    u64 cum_recovered_lamports set_cum_recovered_lamports CUM_RECOVERED_LAMPORTS @ 1560;
    raw(8) _reserved12 set_reserved12 RESERVED12 @ 1568;
    u64 cum_recovery_fees set_cum_recovery_fees CUM_RECOVERY_FEES @ 1576;
    u64 recovery_op_count set_recovery_op_count RECOVERY_OP_COUNT @ 1584;
    key emergency_recipient_phusd set_emergency_recipient_phusd EMERGENCY_RECIPIENT_PHUSD @ 1592;
    u64 recovery_last_enqueue_slot set_recovery_last_enqueue_slot RECOVERY_LAST_ENQUEUE_SLOT @ 1624;
    u64 cum_recovery_queued set_cum_recovery_queued CUM_RECOVERY_QUEUED @ 1632;
    u64 cum_recovery_unwrapped set_cum_recovery_unwrapped CUM_RECOVERY_UNWRAPPED @ 1640;
    u64 cum_recovered_phusd set_cum_recovered_phusd CUM_RECOVERED_PHUSD @ 1648;
    raw(3488) _reserved5 set_reserved5 RESERVED5 @ 1656;
}

/// `venue_last_verdict` values (SPEC §3.1, §5.6.1).
pub mod venue_verdict {
    pub const NONE: u8 = 0;
    pub const UP: u8 = 1;
    pub const DOWN: u8 = 2;
    pub const UNKNOWN: u8 = 3;
}

/// Number of majors tracked in `venue_major_*` (SOL, BTC, ETH).
pub const MAJOR_COUNT: usize = 3;

impl<'a> Config<'a> {
    /// Discriminator `SIJKACFG` and `version == 1` (SPEC §3.0).
    #[inline]
    pub fn header_ok(&self) -> bool {
        self.discriminator() == &DISC_CONFIG && self.version() == 1
    }

    /// `true` for the SOL pair (`quote_mint == WSOL_MINT`).
    #[inline]
    pub fn is_sol_pair(&self) -> bool {
        self.quote_mint() == &WSOL_MINT
    }

    /// `true` after the irreversible recovery latch (tag 51 op 0).
    #[inline]
    pub fn in_recovery(&self) -> bool {
        self.recovery_mode() != 0
    }

    /// `venue_major_asset_id[k]` for k in 0..3; `None` otherwise.
    #[inline]
    pub fn venue_major_asset_id_at(&self, k: usize) -> Option<u32> {
        if k >= MAJOR_COUNT {
            return None;
        }
        read_u32(self.venue_major_asset_id(), k.checked_mul(4)?)
    }

    /// Typed view of `harvest_params`.
    #[inline]
    pub fn harvest(&self) -> harvest_params::HarvestParams<'a> {
        harvest_params::HarvestParams::from_array(self.harvest_params())
    }

    /// Typed view of `inflow_params`.
    #[inline]
    pub fn inflow(&self) -> inflow_params::InflowParams<'a> {
        inflow_params::InflowParams::from_array(self.inflow_params())
    }
}

impl ConfigMut<'_> {
    /// Set `venue_major_asset_id[k]`; `false` if `k` is out of range.
    #[inline]
    pub fn set_venue_major_asset_id_at(&mut self, k: usize, v: u32) -> bool {
        if k >= MAJOR_COUNT {
            return false;
        }
        let Some(o) = k.checked_mul(4).and_then(|x| x.checked_add(off::VENUE_MAJOR_ASSET_ID)) else {
            return false;
        };
        write_u32(self.bytes_mut(), o, v).is_some()
    }
}

/// Standard `config` check and read-only borrow (SPEC §3.0): owner is this
/// program, length 5144, discriminator and version. Error: `InvalidConfigAccount`.
///
/// The key is not compared: only `initialize` creates an account with this
/// owner and discriminator, and only at `PDA(["config"])`.
pub fn load_config<'a>(ai: &'a AccountInfo, program_id: &Pubkey) -> Result<Ref<'a, [u8]>, ProgramError> {
    let data = borrow_checked(ai, program_id, CONFIG_LEN, SijkaError::InvalidConfigAccount)?;
    match Config::new(&data) {
        Some(c) if c.header_ok() => {}
        _ => return Err(SijkaError::InvalidConfigAccount.fail()),
    }
    Ok(data)
}

/// As [`load_config`], plus `is_writable` (`AccountNotWritable`), for
/// instructions that write `Config`.
pub fn load_config_mut<'a>(ai: &'a AccountInfo, program_id: &Pubkey) -> Result<RefMut<'a, [u8]>, ProgramError> {
    let data = borrow_mut_checked(
        ai,
        program_id,
        CONFIG_LEN,
        SijkaError::InvalidConfigAccount,
        SijkaError::AccountNotWritable,
    )?;
    match Config::new(&data) {
        Some(c) if c.header_ok() => {}
        _ => return Err(SijkaError::InvalidConfigAccount.fail()),
    }
    Ok(data)
}

/// View over borrowed `Config` bytes (length already checked by the loaders).
pub fn config_view(data: &[u8]) -> Result<Config<'_>, ProgramError> {
    Config::new(data).ok_or_else(|| SijkaError::InvalidConfigAccount.fail())
}

/// Mutable view over borrowed `Config` bytes.
pub fn config_view_mut(data: &mut [u8]) -> Result<ConfigMut<'_>, ProgramError> {
    ConfigMut::new(data).ok_or_else(|| SijkaError::InvalidConfigAccount.fail())
}

/// `HarvestParams` (`Config@832`, 64 bytes, SPEC §3.2).
pub mod harvest_params {
    use crate::error::SijkaError;
    use crate::state::layout;

    layout! {
        /// Harvest parameters.
        view HarvestParams, HarvestParamsMut, HARVEST_PARAMS_LEN = 64;
        u64 epsilon set_epsilon EPSILON @ 0;
        u64 d_min set_d_min D_MIN @ 8;
        u64 margin_buffer_abs set_margin_buffer_abs MARGIN_BUFFER_ABS @ 16;
        u64 max_harvest_per_call set_max_harvest_per_call MAX_HARVEST_PER_CALL @ 24;
        raw(8) _reserved0 set_reserved0 RESERVED0 @ 32;
        u32 t_min_secs set_t_min_secs T_MIN_SECS @ 40;
        u32 margin_buffer_im_bps set_margin_buffer_im_bps MARGIN_BUFFER_IM_BPS @ 44;
        u64 max_buyback_backlog set_max_buyback_backlog MAX_BUYBACK_BACKLOG @ 48;
        raw(2) _reserved1 set_reserved1 RESERVED1 @ 56;
        u16 harvest_mark_max_age_slots set_harvest_mark_max_age_slots HARVEST_MARK_MAX_AGE_SLOTS @ 58;
        raw(4) _reserved set_reserved RESERVED @ 60;
    }

    impl HarvestParams<'_> {
        /// Structural check (tag 0; the parameters never change afterwards,
        /// SPEC v4): `d_min ≥ 1`, `max_harvest_per_call ≥ d_min`,
        /// `max_buyback_backlog ≥ 1` (the ACC-1 gate cannot be switched on
        /// later), reserved bytes zero. `_reserved0@32` and `_reserved1@56`
        /// held the withdraw tolerance (`withdraw_fee_tolerance`,
        /// `withdraw_fee_tolerance_bps`), retired by DECISIONS §23 item 6:
        /// harvest books whatever Phoenix and Ember deliver.
        pub fn validate(&self) -> Result<(), SijkaError> {
            let ok = self.d_min() >= 1
                && self.max_harvest_per_call() >= self.d_min()
                && self.max_buyback_backlog() >= 1
                && crate::util::bytes::is_zero(self.bytes(), off::RESERVED0, 8)
                && crate::util::bytes::is_zero(self.bytes(), off::RESERVED1, 2)
                && crate::util::bytes::is_zero(self.bytes(), off::RESERVED, 4);
            if ok { Ok(()) } else { Err(SijkaError::InvalidParams) }
        }
    }
}

/// `InflowParams` (`Config@1112`, 40 bytes, SPEC §3.3).
pub mod inflow_params {
    use crate::error::SijkaError;
    use crate::state::layout;

    layout! {
        /// Inflow (swap and deposit) parameters.
        view InflowParams, InflowParamsMut, INFLOW_PARAMS_LEN = 40;
        raw(4) _reserved0 set_reserved0 RESERVED0 @ 0;
        u32 swap_min_interval_s set_swap_min_interval_s SWAP_MIN_INTERVAL_S @ 4;
        u64 swap_max_lamports set_swap_max_lamports SWAP_MAX_LAMPORTS @ 8;
        u64 swap_min_lamports set_swap_min_lamports SWAP_MIN_LAMPORTS @ 16;
        u64 deposit_min_atoms set_deposit_min_atoms DEPOSIT_MIN_ATOMS @ 24;
        raw(8) _reserved1 set_reserved1 RESERVED1 @ 32;
    }

    impl InflowParams<'_> {
        /// Structural check (tag 0; SPEC v4, fixed for good):
        /// `1 ≤ swap_min_lamports ≤ swap_max_lamports`, `deposit_min_atoms ≥ 1`,
        /// reserved bytes zero. `_reserved0@0` held the oracle band and mark
        /// age (`swap_band_bps`, `mark_max_age_slots`; no oracle, DECISIONS
        /// §23 item 4), `_reserved1@32` the Ember wrap tolerance
        /// (`ember_tolerance_bps`, `_pad`, `ember_tolerance_abs`; retired by
        /// §23 item 6: `I` grows by what actually reached Phoenix).
        pub fn validate(&self) -> Result<(), SijkaError> {
            let ok = crate::util::bytes::is_zero(self.bytes(), off::RESERVED0, 4)
                && self.swap_min_lamports() >= 1
                && self.swap_min_lamports() <= self.swap_max_lamports()
                && self.deposit_min_atoms() >= 1
                && crate::util::bytes::is_zero(self.bytes(), off::RESERVED1, 8);
            if ok { Ok(()) } else { Err(SijkaError::InvalidParams) }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::tests::{assert_natural_alignment, assert_tiles};

    #[test]
    fn config_layout_tiles_and_is_aligned() {
        assert_tiles(FIELDS, CONFIG_LEN);
        assert_natural_alignment(FIELDS);
        assert_eq!(CONFIG_LEN, crate::constants::CONFIG_LEN);
    }

    #[test]
    fn config_spot_offsets_from_spec_3_1() {
        assert_eq!(off::RESERVED6, 10);
        assert_eq!(off::ADMIN, 16);
        assert_eq!(off::KEEPER, 48);
        assert_eq!(off::TRADER, 80);
        assert_eq!(off::CREATOR_PAYOUT, 112);
        assert_eq!(off::PHOENIX_TRADER, 304);
        assert_eq!(off::PHX_AUTHORITY_BUMP, 658);
        assert_eq!(off::CUM_INFLOW_USDC, 704);
        assert_eq!(off::CUM_PAYOUT_USDC, 712);
        assert_eq!(off::HARVEST_PARAMS, 832);
        assert_eq!(off::RESERVED7, 896);
        assert_eq!(off::RESERVED8, 992);
        assert_eq!(off::RESERVED9, 1000);
        assert_eq!(off::INFLOW_PARAMS, 1112);
        assert_eq!(off::RESERVED10, 1152);
        assert_eq!(off::RESERVED11, 1552);
        assert_eq!(off::RESERVED12, 1568);
        assert_eq!(off::NEXT_SWAP_TS, 1344);
        assert_eq!(off::CREATOR_ESCROW_USDC, 1368);
        assert_eq!(off::RECOVERY_MODE, 1400);
        assert_eq!(off::VENUE_MAJOR_ASSET_ID, 1404);
        assert_eq!(off::EMERGENCY_RECIPIENT, 1472);
        assert_eq!(off::EMERGENCY_RECIPIENT_PHUSD, 1592);
        assert_eq!(off::CUM_RECOVERED_PHUSD, 1648);
        assert_eq!(off::RESERVED5, 1656);
    }

    #[test]
    fn params_layouts_tile() {
        assert_tiles(harvest_params::FIELDS, harvest_params::HARVEST_PARAMS_LEN);
        assert_tiles(inflow_params::FIELDS, inflow_params::INFLOW_PARAMS_LEN);
    }

    #[test]
    fn accessors_round_trip() {
        let mut buf = vec![0u8; CONFIG_LEN];
        {
            let mut m = ConfigMut::new(&mut buf).unwrap();
            m.set_discriminator(&DISC_CONFIG);
            m.set_version(1);
            m.set_trader(&[2u8; 32]);
            m.set_admin(&[7u8; 32]);
            m.set_keeper(&[3u8; 32]);
            m.set_cum_inflow_usdc(u64::MAX);
            m.set_venue_down_since_ts(-5);
            assert!(m.set_venue_major_asset_id_at(2, 0x0001_0017));
            assert!(!m.set_venue_major_asset_id_at(3, 1));
        }
        let c = Config::new(&buf).unwrap();
        assert!(c.header_ok());
        assert_eq!(c.trader(), &[2u8; 32]);
        assert_eq!(c.admin(), &[7u8; 32]);
        assert_eq!(c.keeper(), &[3u8; 32]);
        assert_eq!(&buf[48..80], &[3u8; 32]);
        assert_eq!(c.cum_inflow_usdc(), u64::MAX);
        assert_eq!(c.venue_down_since_ts(), -5);
        assert_eq!(c.venue_major_asset_id_at(2), Some(0x0001_0017));
        assert_eq!(c.venue_major_asset_id_at(0), Some(0));
        assert_eq!(c.venue_major_asset_id_at(3), None);
        // Raw bytes land at the SPEC offsets.
        assert_eq!(&buf[80..112], &[2u8; 32]);
        assert_eq!(&buf[1412..1416], &[0x17, 0, 1, 0]);
        assert_eq!(&buf[704..712], &[0xff; 8]);
        assert!(Config::new(&buf[..CONFIG_LEN - 1]).is_none());
    }

    #[test]
    fn harvest_params_validation_bounds() {
        let mut b = [0u8; 64];
        {
            let mut m = harvest_params::HarvestParamsMut::from_array(&mut b);
            m.set_d_min(1);
            m.set_max_harvest_per_call(1);
            m.set_max_buyback_backlog(1);
        }
        assert!(harvest_params::HarvestParams::from_array(&b).validate().is_ok());
        let mut bad = b;
        harvest_params::HarvestParamsMut::from_array(&mut bad).set_max_buyback_backlog(0);
        assert!(harvest_params::HarvestParams::from_array(&bad).validate().is_err());
        let mut bad = b;
        harvest_params::HarvestParamsMut::from_array(&mut bad).set_d_min(0);
        assert!(harvest_params::HarvestParams::from_array(&bad).validate().is_err());
        // SPEC v4 (DECISIONS §23 item 6): the former withdraw tolerance bytes
        // (@32..40 and @56..58) are reserved zeros.
        for i in (32..40).chain(56..58) {
            let mut bad = b;
            bad[i] = 1;
            assert!(harvest_params::HarvestParams::from_array(&bad).validate().is_err(), "byte {i}");
        }
        let mut bad = b;
        harvest_params::HarvestParamsMut::from_array(&mut bad).set_d_min(2);
        assert!(harvest_params::HarvestParams::from_array(&bad).validate().is_err());
        let mut bad = b;
        bad[63] = 1;
        assert!(harvest_params::HarvestParams::from_array(&bad).validate().is_err());
    }

    #[test]
    fn inflow_params_validation_bounds() {
        let mut b = [0u8; 40];
        {
            let mut m = inflow_params::InflowParamsMut::from_array(&mut b);
            m.set_swap_min_lamports(1);
            m.set_swap_max_lamports(1);
            m.set_deposit_min_atoms(1);
        }
        assert!(inflow_params::InflowParams::from_array(&b).validate().is_ok());
        let mut bad = b;
        inflow_params::InflowParamsMut::from_array(&mut bad).set_swap_min_lamports(2);
        assert!(inflow_params::InflowParams::from_array(&bad).validate().is_err());
        // The former `swap_band_bps` / `mark_max_age_slots` (@0..4) and Ember
        // tolerance (@32..40) bytes must be zero.
        for i in (0..4).chain(32..40) {
            let mut bad = b;
            bad[i] = 1;
            assert!(inflow_params::InflowParams::from_array(&bad).validate().is_err(), "byte {i}");
        }
    }
}
