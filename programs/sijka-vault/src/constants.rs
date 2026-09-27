// Copyright (c) 2026 prt1sn. All rights reserved.
//! Constants compiled into the program (SPEC §2.3, §5.5.1, §5.6).
//!
//! Addresses are pinned; nothing here is an admin-tunable limit (SPEC §2.4).
//! Host tests in this file re-derive PDAs and discriminators from their seeds
//! and preimages, and `abi_check` compares the addresses with the ABI manifest.

use phoenix_rise::ix::discriminants::PhoenixInstruction;
use pinocchio::pubkey::Pubkey;
use pinocchio_pubkey::pubkey;

// ------------------------------------------------------------------ programs

pub const PHOENIX_PROGRAM_ID: Pubkey = pubkey!("EtrnLzgbS7nMMy5fbD42kXiUzGg8XQzJ972Xtk1cjWih");
pub const PHOENIX_LOG_AUTHORITY: Pubkey = pubkey!("GdxfTLSsdSY37G6fZoYtdGDSfgFnbT2EmRpuePZxWShS");
/// = PDA(Phoenix, ["global"]), bump 255.
pub const PHOENIX_GLOBAL_CONFIG: Pubkey = pubkey!("2zskx2iyCvb6Stg7RBZkt1f6MrF4dpYtMG3yMvKwqtUZ");
/// = PDA(BPF_LOADER_UPGRADEABLE_ID, [PHOENIX_PROGRAM_ID]), bump 253 (O-14).
pub const PHOENIX_PROGRAM_DATA: Pubkey = pubkey!("B5ayDaz9HegiNZqYeBtcFqfZBVSGwjB2CJgHshoSfMQg");
pub const HAWKEYE_PROGRAM_ID: Pubkey = pubkey!("RiSeVw3ZjNfsaXPRb4mgaqYaEEt41pNNJoDvVh7pgQj");
pub const EMBER_PROGRAM_ID: Pubkey = pubkey!("EMBERpYNE6ehWmXymZZS2skiFmCa9V5dp14e1iduM5qy");
/// = PDA(Ember, [PHOENIX, "state"]).
pub const EMBER_STATE: Pubkey = pubkey!("6ur7v6AXNpnHeEb6xuk7PyezvZ1i5GrgYyWZkNCpzbRz");
/// = PDA(Ember, [PHOENIX, "vault"]).
pub const EMBER_VAULT: Pubkey = pubkey!("FKcEb4TdPDTRuMnQDpSEPQBcrm15S73xiUD6Qf8ZLUkq");
pub const JUPITER_V6: Pubkey = pubkey!("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4");
pub const PUMP_PROGRAM: Pubkey = pubkey!("6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P");
pub const PUMP_AMM_PROGRAM: Pubkey = pubkey!("pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA");
pub const PUMP_FEES_PROGRAM: Pubkey = pubkey!("pfeeUxB6jkeY1Hxd7CsFCAjcbHA9rWtchMGdZ6VojVZ");
/// pump ["global"].
pub const PUMP_GLOBAL: Pubkey = pubkey!("4wTV1YmiEkRvAtNtsSGPtUrqRYQMe5SKy2uB4Jjaxnjf");
/// pump ["__event_authority"].
pub const PUMP_EVENT_AUTHORITY: Pubkey = pubkey!("Ce6TQqeHC9p8KetsN6JsjHK7UTZk7nasjjnr7XxXp9F1");
/// pump ["global_volume_accumulator"].
pub const PUMP_GVA: Pubkey = pubkey!("Hq2wp8uJ9jCPsYgNHex8RtqdvMPfVGoYwjvF1ATiwn2Y");
/// pump_fees ["fee_config", PUMP_PROGRAM].
pub const PUMP_FEE_CONFIG: Pubkey = pubkey!("8Wf5TiAheLUqBrKXeYg2JtAFFMWtKdG2BSFgqUcPVwTt");
/// pump_amm ["global_config"].
pub const AMM_GLOBAL_CONFIG: Pubkey = pubkey!("ADyA8hdefvWN2dbGGWFotbzWxrAvLW83WG6QCVXvJKqw");
/// pump_amm ["__event_authority"].
pub const AMM_EVENT_AUTHORITY: Pubkey = pubkey!("GS4CU59F31iL7aR2Q8zVS8DRrcRnXX1yjQ66TqNVQnaR");
/// pump_amm ["global_volume_accumulator"].
pub const AMM_GVA: Pubkey = pubkey!("C2aFPdENg4A2HQsmrd5rTw5TaYBX5Ku887cWjbFKtZpw");
/// pump_fees ["fee_config", PUMP_AMM_PROGRAM].
pub const AMM_FEE_CONFIG: Pubkey = pubkey!("5PHirr8joyTMp9JMm6nW7hNDVyEYdkzDqazxPD7RaTjx");
pub const SPL_TOKEN_PROGRAM_ID: Pubkey = pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
pub const TOKEN_2022_PROGRAM_ID: Pubkey = pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
pub const ATA_PROGRAM_ID: Pubkey = pubkey!("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
pub const SYSTEM_PROGRAM_ID: Pubkey = pubkey!("11111111111111111111111111111111");
pub const COMPUTE_BUDGET_PROGRAM_ID: Pubkey = pubkey!("ComputeBudget111111111111111111111111111111");
pub const INSTRUCTIONS_SYSVAR: Pubkey = pubkey!("Sysvar1nstructions1111111111111111111111111");
pub const BPF_LOADER_UPGRADEABLE_ID: Pubkey = pubkey!("BPFLoaderUpgradeab1e11111111111111111111111");
/// wSOL (= NATIVE_MINT).
pub const WSOL_MINT: Pubkey = pubkey!("So11111111111111111111111111111111111111112");
pub const JITO_DONT_FRONT: Pubkey = pubkey!("jitodontfront111111111111111111111111111111");

// ---------------------------------------------------------------- our seeds

pub const SEED_CONFIG: &[u8] = b"config";
pub const SEED_BUYBACK_STATE: &[u8] = b"buyback_state";
pub const SEED_FEE_INBOX: &[u8] = b"fee_inbox";
pub const SEED_PHX_AUTHORITY: &[u8] = b"phx_authority";
pub const SEED_SWAP_AUTHORITY: &[u8] = b"swap";
pub const SEED_BUYBACK_AUTHORITY: &[u8] = b"buyback";
pub const SEED_RENT_PAYER: &[u8] = b"rent_payer";
pub const SEED_CREATOR_ESCROW: &[u8] = b"creator_escrow";
pub const SEED_BB_UNWRAP: &[u8] = b"bb_unwrap";

// ----------------------------------------------------- external PDA seeds

/// Phoenix trader: PDA(Phoenix, ["trader", authority, [pda_index, subaccount_index]]).
pub const SEED_PHOENIX_TRADER: &[u8] = b"trader";
/// pump_fees ["sharing-config", mint].
pub const SEED_PUMP_SHARING_CONFIG: &[u8] = b"sharing-config";
/// pump ["bonding-curve", mint].
pub const SEED_PUMP_BONDING_CURVE: &[u8] = b"bonding-curve";
/// pump ["creator-vault", creator].
pub const SEED_PUMP_CREATOR_VAULT: &[u8] = b"creator-vault";
/// pump / pump_amm ["user_volume_accumulator", user].
pub const SEED_USER_VOLUME_ACCUMULATOR: &[u8] = b"user_volume_accumulator";
/// pump ["pool-authority", mint].
pub const SEED_PUMP_POOL_AUTHORITY: &[u8] = b"pool-authority";
/// pump_amm ["pool", index u16 LE, creator, base_mint, quote_mint].
pub const SEED_AMM_POOL: &[u8] = b"pool";
/// pump_amm ["creator_vault", coin_creator] (underscore, not dash).
pub const SEED_AMM_CREATOR_VAULT: &[u8] = b"creator_vault";
/// pump_amm ["pool-v2", mint].
pub const SEED_AMM_POOL_V2: &[u8] = b"pool-v2";

// ----------------------------------------------------------- discriminators

/// Our account discriminators (SPEC §3).
pub const DISC_CONFIG: [u8; 8] = *b"SIJKACFG";
pub const DISC_BUYBACK_STATE: [u8; 8] = *b"SIJKABBS";

/// Phoenix / Ember / pump account discriminators.
pub const DISC_GLOBAL_CONFIG: [u8; 8] = [0x25, 0x92, 0xd4, 0xd2, 0x2f, 0x88, 0x6f, 0x14];
pub const DISC_PAM: [u8; 8] = [0x8e, 0x36, 0x73, 0xdf, 0x7c, 0xef, 0x6c, 0x26];
pub const DISC_TRADER: [u8; 8] = [0x29, 0x61, 0x49, 0x69, 0x6e, 0xd6, 0x70, 0x09];
/// = sha256("account:state_account")[..8].
pub const DISC_EMBER_STATE: [u8; 8] = [0x8e, 0xce, 0x0b, 0xb1, 0x3f, 0x9d, 0x37, 0x62];
/// = sha256("account:withdraw_queue")[..8].
pub const DISC_WITHDRAW_QUEUE: [u8; 8] = [0x7d, 0x3b, 0x5e, 0x6c, 0xab, 0x10, 0x2b, 0xe4];
pub const SHARING_CONFIG_DISC: [u8; 8] = [216, 74, 9, 0, 56, 140, 93, 75];
pub const BONDING_CURVE_DISC: [u8; 8] = [23, 183, 248, 55, 96, 216, 172, 96];
pub const POOL_DISC: [u8; 8] = [241, 154, 109, 4, 17, 177, 109, 188];

/// pump instruction discriminators.
pub const IX_BUY_EXACT_QUOTE_IN_V2: [u8; 8] = [194, 171, 28, 70, 104, 77, 91, 47];
pub const IX_AMM_BUY_EXACT_QUOTE_IN: [u8; 8] = [198, 46, 21, 82, 180, 217, 232, 112];

/// Jupiter v6 exact-in instructions allowed by SPEC §5.3.3.
pub const JUP_ROUTE: [u8; 8] = [0xe5, 0x17, 0xcb, 0x97, 0x7a, 0xe3, 0xad, 0x2a];
pub const JUP_SHARED_ACCOUNTS_ROUTE: [u8; 8] = [0xc1, 0x20, 0x9b, 0x33, 0x41, 0xd6, 0x9c, 0x81];
pub const JUP_ROUTE_V2: [u8; 8] = [0xbb, 0x64, 0xfa, 0xcc, 0x31, 0xc4, 0xaf, 0x14];
pub const JUP_SHARED_ACCOUNTS_ROUTE_V2: [u8; 8] = [0xd1, 0x98, 0x53, 0x93, 0x7c, 0xfe, 0xd8, 0xe9];

/// Phoenix CPI discriminators, taken from the SDK's const fn (SPEC §2.3: not a
/// runtime hash). Tests check them against the SPEC hex values.
pub const IX_PHX_REGISTER_TRADER: [u8; 8] = PhoenixInstruction::RegisterTrader.discriminant();
pub const IX_PHX_DEPOSIT_FUNDS: [u8; 8] = PhoenixInstruction::DepositFunds.discriminant();
pub const IX_PHX_WITHDRAW_FUNDS: [u8; 8] = PhoenixInstruction::WithdrawFunds.discriminant();
/// Ember `deposit` / `withdraw` (= sha256("global:deposit"/"global:withdraw")[..8]).
pub const IX_EMBER_DEPOSIT: [u8; 8] = [0xf2, 0x23, 0xc6, 0x89, 0x52, 0xe1, 0xf2, 0xb6];
pub const IX_EMBER_WITHDRAW: [u8; 8] = [0xb7, 0x12, 0x46, 0x9c, 0x94, 0x6d, 0xa1, 0x22];
/// Hawkeye views (all accounts read-only).
pub const IX_HAWKEYE_VIEW_MARGIN: [u8; 8] = [0xb2, 0x0a, 0x7c, 0xad, 0xec, 0xd2, 0x75, 0x06];

/// Hawkeye return-data magics (LE of sha2_const("return:phoenix_hawkeye_*")).
pub const HAWKEYE_MARGIN_MAGIC: [u8; 8] = [0x3f, 0x25, 0xff, 0x3d, 0x9d, 0x5b, 0x5f, 0x95];
pub const HAWKEYE_RETURN_VERSION: u16 = 1;
/// `ViewMarginReturn` length (SPEC §3.9).
pub const HAWKEYE_MARGIN_RETURN_LEN: usize = 112;

// ---------------------------------------------------------------- numbers

/// Our account sizes (SPEC §3).
pub const CONFIG_LEN: usize = 5144;
pub const BUYBACK_STATE_LEN: usize = 1304;
pub const ACCOUNT_VERSION: u8 = 1;

pub const CREATOR_SHARE_BPS: u64 = 2000;
pub const BPS: u64 = 10_000;

pub const TRADER_MAX_POSITIONS: u64 = 128;
/// Registration prefs: no collateral sweep, no `SwapNative` for a position
/// authority. Defence in depth only (SPEC §2.3, §5.1.2): `SwapNative` and
/// sub-accounts are unreachable through tag 10 anyway.
pub const TRADER_PREFS: u32 = 0b11;
/// Size of the Phoenix trader account created by `RegisterTrader(128)`.
pub const TRADER_ACCOUNT_LEN: usize = 5360;

pub const MAX_GTI: usize = 8;
pub const MAX_ATB: usize = 8;
pub const MAX_ROUTE_ACCOUNTS: usize = 64;
pub const MIN_JUP_DATA: usize = 8;
pub const MAX_JUP_DATA: usize = 512;

// ------------------------------------------------------ tag 10 `trade`

/// Where the Phoenix signer (`traderWallet`, must be `phx_authority`) sits in
/// the Phoenix account list `P` of an allowed instruction (SPEC §5.2.1 `AU`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TraderWalletSlot {
    /// Fixed index.
    At(usize),
    /// `n - 3`, counted from the end (`PlaceStopLoss`,
    /// `PlacePositionConditionalOrder`); `P[n - 1]` must be the System program.
    NMinus3,
}

/// One allowed Phoenix trading instruction (SPEC §5.2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AllowedTrade {
    /// Discriminator as a little-endian u64 (`PhoenixInstruction::tag()`).
    pub disc: u64,
    /// Index of the trader account in `P` (`TR`, must be `cfg.phoenix_trader`).
    pub trader: usize,
    /// Index of the Phoenix signer in `P` (`AU`).
    pub wallet: TraderWalletSlot,
    /// Smallest `n = len(P)` at `g = a = 1` (`MIN`).
    pub min_accounts: usize,
}

const fn allow(i: PhoenixInstruction, trader: usize, wallet: TraderWalletSlot, min_accounts: usize) -> AllowedTrade {
    AllowedTrade { disc: i.tag(), trader, wallet, min_accounts }
}

/// Upper bound of `n` in tag 10 (T4): the longest allowed layout is
/// `11 + g + a` (SPEC §2.3, appendix H §6.3).
pub const MAX_TRADE_ACCOUNTS: usize = 11 + MAX_GTI + MAX_ATB;

/// The Phoenix instructions tag 10 forwards (SPEC §5.2.1, DECISIONS §19):
/// orders of every kind, batches, cancels, stop-losses and conditional
/// orders. Deny by default: everything else is `TradeInstructionNotAllowed`.
/// New Phoenix trading commands are added only by a program upgrade.
pub const TRADE_ALLOWLIST: [AllowedTrade; 14] = {
    use PhoenixInstruction as I;
    use TraderWalletSlot::{At, NMinus3};
    [
        allow(I::PlaceMarketOrder, 4, At(3), 10),
        allow(I::PlaceLimitOrder, 4, At(3), 10),
        allow(I::PlaceMultiLimitOrder, 4, At(3), 10),
        allow(I::PlaceMultiLimitOrderV2, 4, At(3), 10),
        allow(I::CancelOrdersById, 4, At(3), 10),
        allow(I::CancelUpTo, 4, At(3), 10),
        allow(I::CancelAll, 4, At(3), 10),
        allow(I::CancelAllPlusConditional, 4, At(3), 11),
        allow(I::PlaceLimitOrderWithConditionals, 4, At(3), 13),
        allow(I::PlaceStopLoss, 4, NMinus3, 13),
        allow(I::PlacePositionConditionalOrder, 4, NMinus3, 13),
        allow(I::PlaceAttachedConditionalOrder, 3, At(4), 11),
        allow(I::CancelConditionalOrder, 3, At(4), 7),
        allow(I::CancelStopLoss, 4, At(5), 8),
    ]
};

/// The allowlist entry of a discriminator, if any (T3).
#[inline]
pub fn allowed_trade(disc: u64) -> Option<&'static AllowedTrade> {
    TRADE_ALLOWLIST.iter().find(|r| r.disc == disc)
}

// Every fixed slot of an entry lies below its minimum account count and above
// the three Phoenix header slots, so T6 and T7 never index past `P` once T4
// passed; the trader and signer slots never coincide. Evaluated at compile
// time: an index out of range is a build error, not a runtime panic.
#[allow(clippy::indexing_slicing)]
const _: () = {
    let mut i = 0;
    while i < TRADE_ALLOWLIST.len() {
        let r = TRADE_ALLOWLIST[i];
        assert!(r.trader >= 3 && r.trader < r.min_accounts);
        match r.wallet {
            TraderWalletSlot::At(k) => assert!(k >= 3 && k < r.min_accounts && k != r.trader),
            TraderWalletSlot::NMinus3 => assert!(r.min_accounts >= 7 && r.min_accounts - 3 > r.trader),
        }
        assert!(r.min_accounts <= MAX_TRADE_ACCOUNTS);
        i += 1;
    }
};

pub const PAM_HEADER: usize = 48;
pub const PAM_ENTRY: usize = 1584;
pub const GC_PREFIX_LEN: usize = 1104;
pub const GC_QUOTE_DECIMALS: u8 = 6;
/// Minimal GlobalConfig length for account checks (SPEC §3.9).
pub const GC_MIN_LEN: usize = 504;
/// GlobalConfig length when `deposit_cooldown_period_in_slots@512` is read.
pub const GC_MIN_LEN_WITH_COOLDOWN: usize = 520;

pub const WITHDRAW_QUEUE_HEADER_LEN: usize = 120;
pub const WITHDRAW_QUEUE_LEN: usize = 213_136;
pub const WITHDRAW_QUEUE_MAX_NODES: u64 = 2048;
pub const WITHDRAW_QUEUE_NODES_OFFSET: usize = 144;
pub const WITHDRAW_QUEUE_NODE_LEN: usize = 104;

pub const DEPOSIT_QUIET_MIN_PERIOD_SLOTS: u64 = 216_000;
pub const DEPOSIT_QUIET_HARVEST_SLOTS: u64 = 9_000;

/// Emergency recovery (SPEC §2.3, §5.6). Constants, not parameters.
pub const RECOVERY_DOWN_SECS: i64 = 864_000;
pub const MAX_VENUE_OBS_GAP_SECS: i64 = 3_600;
pub const VENUE_OBS_MIN_INTERVAL_S: i64 = 30;
pub const RECOVERY_ENQUEUE_MIN_SLOTS: u64 = 216_000;
/// How much a caller of tag 51 op 1 / op 6 may leave on Phoenix below the
/// full amount (SPEC §5.6.4 step 7: `shave(D) = max(RECOVERY_SHAVE_ABS,
/// ⌊D·RECOVERY_SHAVE_BPS/10 000⌋)`, room for a Phoenix fee charged on top).
/// Fixed at the former launch values of the retired `withdraw_fee_tolerance`
/// (1 USDC) and `withdraw_fee_tolerance_bps` (50), SPEC v4, DECISIONS §23
/// item 6. It widens what the caller may ask for; it never refuses an arrival.
pub const RECOVERY_SHAVE_ABS: u64 = 1_000_000;
pub const RECOVERY_SHAVE_BPS: u16 = 50;

/// SOL, BTC, ETH, each zero-padded to 16 bytes (DECISIONS §17).
pub const MAJOR_SYMBOLS: [[u8; 16]; 3] =
    [*b"SOL\0\0\0\0\0\0\0\0\0\0\0\0\0", *b"BTC\0\0\0\0\0\0\0\0\0\0\0\0\0", *b"ETH\0\0\0\0\0\0\0\0\0\0\0\0\0"];

/// Buyback algorithm constants (SPEC §5.5.1).
pub const OBS_MIN_INTERVAL_S: i64 = 15;
pub const EMA_TAU_S: u64 = 600;
pub const DT_MAX_S: u64 = 60;
pub const OBS_MAX_GAP_S: i64 = 120;
pub const MAX_RENT_EXTRA: u64 = 15_000_000;
pub const MIN_BASE_RESERVE: u64 = 1_000_000;
pub const MAX_QUOTE_RESERVE: u64 = 0x7FFF_FFFF_FFFF_FFFF; // 2^63 − 1

/// SPL token account / mint sizes.
pub const TOKEN_ACCOUNT_LEN: usize = 165;
pub const MINT_LEN: usize = 82;

/// BPF Loader Upgradeable: `Program` account size and `ProgramData` metadata size.
pub const LOADER_PROGRAM_ACCOUNT_LEN: usize = 36;
pub const PROGRAMDATA_METADATA_LEN: usize = 45;

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use solana_pubkey::Pubkey as SPubkey;

    fn sp(k: &Pubkey) -> SPubkey {
        SPubkey::new_from_array(*k)
    }

    fn disc(preimage: &str) -> [u8; 8] {
        let h = Sha256::digest(preimage.as_bytes());
        let mut out = [0u8; 8];
        out.copy_from_slice(&h[..8]);
        out
    }

    #[test]
    fn external_pdas_match_seeds() {
        let (gc, bump) = SPubkey::find_program_address(&[b"global"], &sp(&PHOENIX_PROGRAM_ID));
        assert_eq!(gc.to_bytes(), PHOENIX_GLOBAL_CONFIG);
        assert_eq!(bump, 255);

        let (pd, bump) = SPubkey::find_program_address(&[&PHOENIX_PROGRAM_ID], &sp(&BPF_LOADER_UPGRADEABLE_ID));
        assert_eq!(pd.to_bytes(), PHOENIX_PROGRAM_DATA);
        assert_eq!(bump, 253);

        let ember = sp(&EMBER_PROGRAM_ID);
        let (state, _) = SPubkey::find_program_address(&[&PHOENIX_PROGRAM_ID, b"state"], &ember);
        assert_eq!(state.to_bytes(), EMBER_STATE);
        let (vault, _) = SPubkey::find_program_address(&[&PHOENIX_PROGRAM_ID, b"vault"], &ember);
        assert_eq!(vault.to_bytes(), EMBER_VAULT);
    }

    #[test]
    fn pump_constants_match_seeds() {
        let pump = sp(&PUMP_PROGRAM);
        let amm = sp(&PUMP_AMM_PROGRAM);
        let fees = sp(&PUMP_FEES_PROGRAM);
        assert_eq!(SPubkey::find_program_address(&[b"global"], &pump).0.to_bytes(), PUMP_GLOBAL);
        assert_eq!(SPubkey::find_program_address(&[b"__event_authority"], &pump).0.to_bytes(), PUMP_EVENT_AUTHORITY);
        assert_eq!(SPubkey::find_program_address(&[b"global_volume_accumulator"], &pump).0.to_bytes(), PUMP_GVA);
        assert_eq!(SPubkey::find_program_address(&[b"fee_config", &PUMP_PROGRAM], &fees).0.to_bytes(), PUMP_FEE_CONFIG);
        assert_eq!(SPubkey::find_program_address(&[b"global_config"], &amm).0.to_bytes(), AMM_GLOBAL_CONFIG);
        assert_eq!(SPubkey::find_program_address(&[b"__event_authority"], &amm).0.to_bytes(), AMM_EVENT_AUTHORITY);
        assert_eq!(SPubkey::find_program_address(&[b"global_volume_accumulator"], &amm).0.to_bytes(), AMM_GVA);
        assert_eq!(
            SPubkey::find_program_address(&[b"fee_config", &PUMP_AMM_PROGRAM], &fees).0.to_bytes(),
            AMM_FEE_CONFIG
        );
    }

    #[test]
    fn discriminators_match_preimages() {
        assert_eq!(disc("account:state_account"), DISC_EMBER_STATE);
        assert_eq!(disc("account:withdraw_queue"), DISC_WITHDRAW_QUEUE);
        assert_eq!(disc("account:SharingConfig"), SHARING_CONFIG_DISC);
        assert_eq!(disc("account:BondingCurve"), BONDING_CURVE_DISC);
        assert_eq!(disc("account:Pool"), POOL_DISC);
        assert_eq!(disc("global:buy_exact_quote_in_v2"), IX_BUY_EXACT_QUOTE_IN_V2);
        assert_eq!(disc("global:buy_exact_quote_in"), IX_AMM_BUY_EXACT_QUOTE_IN);
        assert_eq!(disc("global:route"), JUP_ROUTE);
        assert_eq!(disc("global:shared_accounts_route"), JUP_SHARED_ACCOUNTS_ROUTE);
        assert_eq!(disc("global:route_v2"), JUP_ROUTE_V2);
        assert_eq!(disc("global:shared_accounts_route_v2"), JUP_SHARED_ACCOUNTS_ROUTE_V2);
        assert_eq!(disc("global:deposit"), IX_EMBER_DEPOSIT);
        assert_eq!(disc("global:withdraw"), IX_EMBER_WITHDRAW);
        assert_eq!(disc("global:view_margin"), IX_HAWKEYE_VIEW_MARGIN);
        assert_eq!(disc("return:phoenix_hawkeye_margin"), HAWKEYE_MARGIN_MAGIC);
    }

    #[test]
    fn phoenix_cpi_discriminators_match_spec_hex() {
        // SPEC §2.3 hex values.
        assert_eq!(IX_PHX_REGISTER_TRADER, [0x4b, 0xf3, 0xe0, 0xa7, 0x01, 0x05, 0x33, 0x20]);
        assert_eq!(IX_PHX_DEPOSIT_FUNDS, [0xca, 0x27, 0x34, 0xd3, 0x35, 0x14, 0xfa, 0x58]);
        assert_eq!(IX_PHX_WITHDRAW_FUNDS, [0xf1, 0x24, 0x1d, 0x6f, 0xd0, 0x1f, 0x68, 0xd9]);
        assert_eq!(disc("global:register_trader"), IX_PHX_REGISTER_TRADER);
        assert_eq!(disc("global:withdraw_funds"), IX_PHX_WITHDRAW_FUNDS);
        assert_eq!(TRADER_PREFS, 0b11);
    }

    #[test]
    fn trade_allowlist_is_the_spec_table() {
        use TraderWalletSlot::{At, NMinus3};
        // SPEC §5.2.1: snake name, discriminator hex (data byte order), TR, AU, MIN.
        let spec: [(&str, &str, usize, TraderWalletSlot, usize); 14] = [
            ("place_market_order", "5a76c0fcc0632791", 4, At(3), 10),
            ("place_limit_order", "6cb021ba92e501c5", 4, At(3), 10),
            ("place_multi_limit_order", "ecd0ddac8de28154", 4, At(3), 10),
            ("place_multi_limit_order_v2", "406f28d202b126b2", 4, At(3), 10),
            ("cancel_orders_by_id", "eacc7e5ede168d18", 4, At(3), 10),
            ("cancel_up_to", "1ad1f4fd3bafe336", 4, At(3), 10),
            ("cancel_all", "62bf4bdc732847ed", 4, At(3), 10),
            ("cancel_all_plus_conditional", "8eadee7e4f133567", 4, At(3), 11),
            ("place_limit_order_with_conditionals", "5f2d44a8e8dad25c", 4, At(3), 13),
            ("place_stop_loss", "ec2ea442eb5ca289", 4, NMinus3, 13),
            ("place_position_conditional_order", "416c53814cc15c8f", 4, NMinus3, 13),
            ("place_attached_conditional_order", "2b7588804896657a", 3, At(4), 11),
            ("cancel_conditional_order", "52681933f83642b8", 3, At(4), 7),
            ("cancel_stop_loss", "78c90a660c096f7e", 4, At(5), 8),
        ];
        for (r, (snake, hex, tr, au, min)) in TRADE_ALLOWLIST.iter().zip(spec) {
            assert_eq!(r.disc.to_le_bytes(), disc(&format!("global:{snake}")), "{snake}: sha256 preimage");
            let want: Vec<u8> = (0..8).map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap()).collect();
            assert_eq!(r.disc.to_le_bytes().to_vec(), want, "{snake}: SPEC hex");
            assert_eq!((r.trader, r.wallet, r.min_accounts), (tr, au, min), "{snake}");
            assert_eq!(allowed_trade(r.disc), Some(r));
        }
        assert_eq!(MAX_TRADE_ACCOUNTS, 27);
        for (i, a) in TRADE_ALLOWLIST.iter().enumerate() {
            assert!(TRADE_ALLOWLIST[i + 1..].iter().all(|b| b.disc != a.disc), "duplicate");
        }
        assert_eq!(allowed_trade(PhoenixInstruction::SwapNative.tag()), None);
        assert_eq!(allowed_trade(PhoenixInstruction::DelegateTrader.tag()), None);
    }

    #[test]
    fn sdk_constants_agree() {
        use phoenix_rise::ix::constants as c;
        assert_eq!(c::PROD_PHOENIX_PROGRAM_ID.to_bytes(), PHOENIX_PROGRAM_ID);
        assert_eq!(c::PROD_PHOENIX_LOG_AUTHORITY.to_bytes(), PHOENIX_LOG_AUTHORITY);
        assert_eq!(c::PROD_PHOENIX_GLOBAL_CONFIGURATION.to_bytes(), PHOENIX_GLOBAL_CONFIG);
        assert_eq!(c::EMBER_PROGRAM_ID.to_bytes(), EMBER_PROGRAM_ID);
        assert_eq!(c::SPL_TOKEN_PROGRAM_ID.to_bytes(), SPL_TOKEN_PROGRAM_ID);
        assert_eq!(c::ASSOCIATED_TOKEN_PROGRAM_ID.to_bytes(), ATA_PROGRAM_ID);
        assert_eq!(c::SYSTEM_PROGRAM_ID.to_bytes(), SYSTEM_PROGRAM_ID);
        assert_eq!(phoenix_rise::ix::HAWKEYE_PROGRAM_ID.to_bytes(), HAWKEYE_PROGRAM_ID);
        assert_eq!(phoenix_rise::ix::hawkeye::HAWKEYE_RETURN_VERSION, HAWKEYE_RETURN_VERSION);
        assert_eq!(pinocchio::sysvars::instructions::INSTRUCTIONS_ID, INSTRUCTIONS_SYSVAR);
    }

    #[test]
    fn jito_dont_front_bytes() {
        // SPEC §2.3 byte form of `jitodontfront1…`.
        assert_eq!(
            JITO_DONT_FRONT,
            [
                0x0a, 0xf1, 0xc3, 0x43, 0x21, 0x88, 0xca, 0x3a, 0x63, 0x51, 0x35, 0xa1, 0x3a, 0x18, 0x95, 0x1a, 0xce,
                0xbd, 0x29, 0xe6, 0xac, 0x2d, 0xae, 0x67, 0xff, 0xdb, 0x06, 0xd7, 0x40, 0x00, 0x00, 0x00
            ]
        );
        // SPEC v4 (DECISIONS §23 item 6): the recovery shave keeps the former
        // launch values of the retired withdraw tolerance.
        assert_eq!((RECOVERY_SHAVE_ABS, RECOVERY_SHAVE_BPS), (1_000_000, 50));
        assert_eq!(MAX_QUOTE_RESERVE, u64::try_from(i64::MAX).unwrap());
    }
}
