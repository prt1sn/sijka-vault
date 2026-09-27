// Copyright (c) 2026 prt1sn. All rights reserved.
//! Byte offsets of external accounts the program reads (SPEC §3.9). Pure
//! constants and small bounds-checked readers; validation policy lives in
//! `phoenix_accounts.rs` / `pump_accounts.rs` and in the instruction modules.

/// Phoenix `Trader` (disc `DISC_TRADER`; 224-byte header + position map).
pub mod trader {
    pub const DISCRIMINATOR: usize = 0;
    pub const TRADER_KEY: usize = 24;
    pub const AUTHORITY: usize = 56;
    /// `quote_lot_collateral` (`C_hdr`), i64.
    pub const COLLATERAL: usize = 88;
    /// u32: 0 = not activated; bit 0 = hot (value 63), 62 = cold.
    pub const FLAGS: usize = 96;
    pub const MAX_POSITIONS: usize = 112;
    pub const PREFERENCE_BITS: usize = 116;
    pub const POSITION_AUTHORITY: usize = 120;
    pub const PDA_INDEX: usize = 154;
    pub const SUBACCOUNT_INDEX: usize = 155;
    pub const FUNDING_KEY: usize = 156;
    /// `last_deposit_slot`, u64.
    pub const LAST_DEPOSIT_SLOT: usize = 192;
    pub const HEADER_LEN: usize = 224;
    /// Number of position records, u64.
    pub const LEN: usize = 224;
    /// Capacity of the position map, u64.
    pub const CAP: usize = 232;
    /// First position record.
    pub const POSITIONS: usize = 240;
    pub const POSITION_LEN: usize = 40;
    /// Within a record: `asset_index` u64 (low 32 bits used), `base_lot_position` i64.
    pub const POS_ASSET_INDEX: usize = 0;
    pub const POS_BASE_LOTS: usize = 8;
    /// Records with `asset_index ≥ this` are header extensions (native SOL =
    /// 0xFFFF_0000) and are skipped by position scans.
    pub const EXTENSION_ASSET_INDEX_MIN: u32 = 0xFF00_0000;
    /// Minimal length the tag 51 op 1 light check requires (reads `@192`).
    pub const MIN_LEN_WITHDRAW_ONLY: usize = 200;
}

/// Phoenix `GlobalConfig` (`PHOENIX_GLOBAL_CONFIG`, disc `DISC_GLOBAL_CONFIG`).
pub mod global_config {
    pub const DISCRIMINATOR: usize = 0;
    /// Own key (anchor, §5.6.1 G5).
    pub const ACCOUNT_KEY: usize = 8;
    /// root / risk / market authorities, 40..296 (tests patch these).
    pub const AUTHORITIES: usize = 40;
    /// Canonical mint (PhUSD).
    pub const CANONICAL_MINT: usize = 296;
    pub const GLOBAL_VAULT: usize = 328;
    pub const PERP_ASSET_MAP: usize = 360;
    /// GTI header (= GTI[0]).
    pub const GTI_HEADER: usize = 392;
    /// ATB header (= ATB[0]).
    pub const ATB_HEADER: usize = 424;
    pub const WITHDRAW_QUEUE: usize = 472;
    /// u8 status bits: 7 initialized, 0 active, 1 gated, 2 maintenance, 3–6 undefined.
    pub const EXCHANGE_STATUS: usize = 504;
    pub const QUOTE_DECIMALS: usize = 505;
    pub const WITHDRAWAL_MARGIN_FACTOR_BPS: usize = 506;
    /// `deposit_cooldown_period_in_slots`, u64.
    pub const DEPOSIT_COOLDOWN_SLOTS: usize = 512;
    /// `acknowledged_restart_slot`, u64.
    pub const ACKNOWLEDGED_RESTART_SLOT: usize = 1096;

    pub const STATUS_INITIALIZED: u8 = 1 << 7;
    pub const STATUS_ACTIVE: u8 = 1 << 0;
    pub const STATUS_GATED: u8 = 1 << 1;
    pub const STATUS_MAINTENANCE: u8 = 1 << 2;
    /// Bits 3–6: not defined by the SDK.
    pub const STATUS_UNDEFINED_MASK: u8 = 0x78;
}

/// Phoenix `PerpAssetMap` (disc `DISC_PAM`, `48 + capacity·1584` bytes).
pub mod perp_asset_map {
    pub const DISCRIMINATOR: usize = 0;
    pub const NUM_ASSETS: usize = 24; // u16
    pub const SLOTS_USED: usize = 32; // u32
    pub const TOMBSTONES: usize = 36; // u32
    pub const CAPACITY: usize = 40; // u64
    pub const HEADER_LEN: usize = 48;
    pub const ENTRY_LEN: usize = 1584;

    /// Offsets inside one entry `e = 48 + slot·1584`.
    pub const E_SYMBOL: usize = 0; // [u8; 16]
    pub const E_MARK_SLOT: usize = 32; // u64
    pub const E_MARK_TICKS: usize = 40; // u64
    /// Spot components (not read by the program: no oracle, SPEC v4).
    pub const E_SPOT_COMPONENTS: usize = 48;
    pub const E_MARKET_ACCOUNT: usize = 920; // Pubkey (orderbook)
    pub const E_TICK_SIZE: usize = 952; // u64
    pub const E_ASSET_ID_LO: usize = 960; // u16
    pub const E_BASE_LOT_DECIMALS: usize = 962; // i8
    pub const E_ASSET_ID_HI: usize = 964; // u16
    /// `risk_params.leverage_tiers[k]` at `e + 1032 + 24·k`, k < 4.
    pub const E_LEVERAGE_TIERS: usize = 1032;
    pub const LEVERAGE_TIER_LEN: usize = 24;
    pub const LEVERAGE_TIER_COUNT: usize = 4;
    pub const TIER_UPPER_BOUND: usize = 0; // u64
    pub const TIER_MAX_LEVERAGE: usize = 8; // u64, whole "×"
    pub const TIER_LIMIT_ORDER_RISK_FACTOR: usize = 16; // u64, bps
    pub const E_ISOLATED_ONLY: usize = 1224; // u8
    pub const E_POST_ONLY_PRICE_RADIUS_PCT: usize = 1225; // u8
    pub const E_FINALIZED_MARK_PRICE: usize = 1456; // u64 ticks; ≠ 0 ⇔ closed
    pub const E_SHORT_MAP_INDEX_NUM: usize = 1464; // u16
    pub const E_IS_TOMBSTONED: usize = 1466; // u8
}

/// Hawkeye `ViewMarginReturn` (exactly 112 bytes).
pub mod hawkeye_margin {
    pub const MAGIC: usize = 0;
    pub const VERSION: usize = 8; // u16
    pub const POSITION_COUNT: usize = 10; // u16
    pub const RISK_STATE: usize = 12;
    pub const RISK_TIER: usize = 13;
    pub const IS_LIQUIDATABLE: usize = 14;
    pub const COLLATERAL: usize = 16; // i64, C_hk (USDC only)
    pub const EFFECTIVE_COLLATERAL: usize = 24; // i64
    pub const FREE_COLLATERAL: usize = 32; // i64
    pub const WITHDRAWABLE_COLLATERAL: usize = 40; // u64
    pub const INITIAL_MARGIN: usize = 48; // u64
    pub const MAINTENANCE_MARGIN: usize = 56; // u64
    pub const CANCEL_MARGIN: usize = 64;
    pub const BACKSTOP_MARGIN: usize = 72;
    pub const HIGH_RISK_MARGIN: usize = 80;
    pub const UNREALIZED_PNL: usize = 88; // i64, U
    pub const DISCOUNTED_UNREALIZED_PNL: usize = 96; // i64
    pub const UNSETTLED_FUNDING: usize = 104; // i64, F
    pub const LEN: usize = 112;
}

/// Phoenix withdraw queue (`GC@472`, disc `DISC_WITHDRAW_QUEUE`).
pub mod withdraw_queue {
    pub const DISCRIMINATOR: usize = 0;
    pub const MAX_BUDGET: usize = 24;
    pub const REMAINING: usize = 32;
    pub const REPLENISH_PER_SLOT: usize = 40;
    pub const LAST_UPDATE_SLOT: usize = 48;
    pub const TOTAL_QUEUED: usize = 56;
    pub const WITHDRAWAL_FEE: usize = 64;
    pub const ENQUEUEING_FEE: usize = 72;
    pub const HEADER_LEN: usize = 120;
    pub const HEAD: usize = 120; // u32
    pub const TAIL: usize = 124; // u32
    pub const SIZE: usize = 128; // u64
    pub const BUMP_INDEX: usize = 136; // u32
    pub const FREE_LIST_HEAD: usize = 140; // u32
    /// Node `i` (1-based; 0 = none) at `144 + 104·(i − 1)`.
    pub const NODES: usize = 144;
    pub const NODE_LEN: usize = 104;
    pub const N_PREV: usize = 0; // u32
    pub const N_NEXT: usize = 4; // u32
    pub const N_TRADER_KEY: usize = 8;
    pub const N_WALLET_KEY: usize = 40;
    pub const N_AMOUNT: usize = 72; // u64
    pub const N_SUBMISSION_SLOT: usize = 80;
    pub const N_LAST_UPDATE_SLOT: usize = 88;
    pub const N_TRANSITION_COUNT: usize = 96; // u16
    /// 0 Pending, 1 Queued, 2 Processing, 3 Waiting (active); 4..7 final.
    pub const N_STATE: usize = 98;
    pub const N_LAST_TRANSITION_REASON: usize = 99;
    pub const STATE_ACTIVE_MAX: u8 = 3;
}

/// Ember state (`EMBER_STATE`, 136 bytes, disc `DISC_EMBER_STATE`).
pub mod ember_state {
    pub const DISCRIMINATOR: usize = 0;
    pub const INPUT_MINT: usize = 40; // USDC
    pub const OUTPUT_MINT: usize = 72; // PhUSD
    pub const PHOENIX_PROGRAM: usize = 104;
    pub const MIN_LEN: usize = 136;
}

/// SPL Token account (Token and Token-2022 agree on the first 165 bytes).
pub mod token_account {
    pub const MINT: usize = 0;
    pub const OWNER: usize = 32;
    pub const AMOUNT: usize = 64;
    /// COption<Pubkey> tag (u32).
    pub const DELEGATE_TAG: usize = 72;
    pub const STATE: usize = 108;
    pub const STATE_INITIALIZED: u8 = 1;
    pub const STATE_FROZEN: u8 = 2;
    /// COption<u64> tag (u32) + value at 113.
    pub const IS_NATIVE_TAG: usize = 109;
    pub const NATIVE_RESERVE: usize = 113;
    pub const DELEGATED_AMOUNT: usize = 121;
    /// COption<Pubkey> tag (u32).
    pub const CLOSE_AUTHORITY_TAG: usize = 129;
    pub const LEN: usize = 165;
}

/// SPL Mint (82 bytes; Token-2022: account type at 165, TLV from 166).
pub mod mint {
    pub const MINT_AUTHORITY_TAG: usize = 0; // u32
    pub const SUPPLY: usize = 36;
    pub const DECIMALS: usize = 44;
    pub const IS_INITIALIZED: usize = 45;
    pub const FREEZE_AUTHORITY_TAG: usize = 46; // u32
    pub const LEN: usize = 82;
    /// Token-2022: account type byte (1 = Mint) and TLV start.
    pub const T22_ACCOUNT_TYPE: usize = 165;
    pub const T22_ACCOUNT_TYPE_MINT: u8 = 1;
    pub const T22_TLV_START: usize = 166;
    /// Allowed Token-2022 extensions (U-26): MetadataPointer, TokenMetadata.
    pub const EXT_METADATA_POINTER: u16 = 18;
    pub const EXT_TOKEN_METADATA: u16 = 19;
}

/// BPF Loader Upgradeable accounts (tag 0 `program_data`; §5.6.1 X1).
pub mod loader {
    /// `UpgradeableLoaderState` variant tag (u32 @0).
    pub const STATE_TAG: usize = 0;
    pub const TAG_UNINITIALIZED: u32 = 0;
    pub const TAG_PROGRAM: u32 = 2;
    pub const TAG_PROGRAM_DATA: u32 = 3;
    /// `Program { programdata_address }` at 4..36 (account is 36 bytes).
    pub const PROGRAM_DATA_ADDRESS: usize = 4;
    pub const PROGRAM_ACCOUNT_LEN: usize = 36;
    /// `ProgramData { slot, upgrade_authority: Option<Pubkey> }`.
    pub const PD_SLOT: usize = 4;
    pub const PD_AUTHORITY_TAG: usize = 12; // u8, 1 = Some
    pub const PD_AUTHORITY: usize = 13;
    pub const PD_METADATA_LEN: usize = 45;
}

// Entry fields lie inside one entry.
const _: () = assert!(perp_asset_map::E_IS_TOMBSTONED < perp_asset_map::ENTRY_LEN);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_sizes() {
        assert_eq!(trader::POSITIONS, trader::CAP + 8);
        assert_eq!(perp_asset_map::HEADER_LEN, crate::constants::PAM_HEADER);
        assert_eq!(perp_asset_map::ENTRY_LEN, crate::constants::PAM_ENTRY);
        assert_eq!(
            perp_asset_map::E_LEVERAGE_TIERS + perp_asset_map::LEVERAGE_TIER_COUNT * perp_asset_map::LEVERAGE_TIER_LEN,
            1128
        );
        assert_eq!(global_config::ACKNOWLEDGED_RESTART_SLOT + 8, crate::constants::GC_PREFIX_LEN);
        assert_eq!(hawkeye_margin::UNSETTLED_FUNDING + 8, hawkeye_margin::LEN);
        assert_eq!(withdraw_queue::NODES, crate::constants::WITHDRAW_QUEUE_NODES_OFFSET);
        assert_eq!(withdraw_queue::NODES + 2048 * withdraw_queue::NODE_LEN, crate::constants::WITHDRAW_QUEUE_LEN);
        assert_eq!(token_account::CLOSE_AUTHORITY_TAG + 36, token_account::LEN);
        assert_eq!(loader::PD_AUTHORITY + 32, loader::PD_METADATA_LEN);
    }
}
