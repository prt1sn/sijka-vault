// Copyright (c) 2026 prt1sn. All rights reserved.
//! Program errors, SPEC §6.
//!
//! On chain every error is `ProgramError::Custom(0x534A_0000 + n)`. Numbers are
//! fixed by SPEC §6.2 and only ever appended at the end of their group. Before
//! returning an error the program logs one static line `Sijka: <Name>`
//! (SPEC §5.0.8); use [`err`] (or [`SijkaError::fail`]) so the log and the code
//! always agree.

use pinocchio::program_error::ProgramError;

/// Base of all program error codes ("SJ").
pub const ERROR_BASE: u32 = 0x534A_0000;

macro_rules! sijka_errors {
    ($( $name:ident = $off:literal => $class:literal, )*) => {
        /// All program errors. The discriminant is the offset from [`ERROR_BASE`].
        #[repr(u32)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum SijkaError {
            $( $name = $off, )*
        }

        impl SijkaError {
            /// Every variant, in declaration order.
            pub const ALL: &'static [SijkaError] = &[$( SijkaError::$name, )*];

            /// On-chain code: `ERROR_BASE + offset`.
            #[inline(always)]
            pub const fn code(self) -> u32 {
                // The offsets are < 0x1000, so the sum never overflows.
                ERROR_BASE | (self as u32)
            }

            /// Variant name, as in SPEC §6.2.
            pub const fn name(self) -> &'static str {
                match self { $( SijkaError::$name => stringify!($name), )* }
            }

            /// The log line emitted before the error (SPEC §5.0.8).
            #[inline(always)]
            pub const fn log_line(self) -> &'static str {
                match self { $( SijkaError::$name => concat!("Sijka: ", stringify!($name)), )* }
            }

            /// Behaviour class for off-chain components (SPEC §6.1). Not used on chain.
            pub const fn class(self) -> &'static str {
                match self { $( SijkaError::$name => $class, )* }
            }
        }

        /// Log lines of every variant, in declaration order (compile time only).
        const LOG_LINES: &[&str] = &[$( concat!("Sijka: ", stringify!($name)), )*];
    };
}

sijka_errors! {
    // +0x001 general
    UnknownInstruction = 0x001 => "bad_args",
    InvalidInstructionData = 0x002 => "bad_args",
    InvalidAccountCount = 0x003 => "bad_account",
    InvalidConfigAccount = 0x004 => "bad_account",
    InvalidPda = 0x005 => "bad_account",
    InvalidProgramId = 0x006 => "external_id_mismatch",
    InvalidExternalAccount = 0x007 => "bad_account",
    AccountNotWritable = 0x008 => "bad_account",
    AccountMustBeReadonly = 0x009 => "bad_account",
    InvalidTokenAccount = 0x00A => "bad_account",
    MathOverflow = 0x00B => "other",
    InvariantViolated = 0x00C => "invariant",
    NotTopLevel = 0x00D => "tx_composition",
    ForeignInstruction = 0x00E => "tx_composition",
    TraderNotRegistered = 0x00F => "not_ready",
    InvalidPhoenixGlobalConfig = 0x010 => "bad_account",
    InvalidPerpAssetMap = 0x011 => "bad_account",
    InvalidPhoenixTraderAccount = 0x012 => "bad_account",
    InvalidArenaAccounts = 0x013 => "bad_account",
    InvalidEmberAccount = 0x014 => "bad_account",
    HawkeyeReturnInvalid = 0x015 => "hawkeye_unavailable",
    // 0x016 InvalidTradeConfig: retired (SPEC v2), not reused.
    InvalidBuybackState = 0x017 => "bad_account",
    // 0x018 VaultPaused: retired (SPEC v2), not reused.
    // +0x040 setup / admin
    Unauthorized = 0x040 => "admin",
    // 0x041 AdminRenounced, 0x042 RenounceNotReady, 0x043
    // RenounceConfirmationMismatch (tag 8 `renounce_admin`): retired (SPEC v4,
    // DECISIONS §23), not reused.
    NotUpgradeAuthority = 0x044 => "admin",
    ConfigAlreadyInitialized = 0x045 => "already_done",
    InvalidQuoteMint = 0x046 => "bad_args",
    InvalidParams = 0x047 => "bad_args",
    TokenMintAlreadySet = 0x048 => "already_done",
    InvalidTokenMint = 0x049 => "bad_account",
    InvalidSharingConfig = 0x04A => "bad_account",
    TraderAlreadyRegistered = 0x04B => "already_done",
    InvalidPhoenixTraderPda = 0x04C => "bad_account",
    RentPayerUnderfunded = 0x04D => "not_ready",
    // 0x04E-0x053 (market table errors): retired (SPEC v2), not reused.
    // 0x054 TraderPrefsUnsafe (tag 9 of SPEC v2): retired (SPEC v3), not reused.
    // +0x100 trading. SPEC v3: `UnauthorizedTrader` is back with its SPEC v1
    // meaning (tag 10, T1); 0x101-0x11A and 0x11C-0x11E (the SPEC v1 guardrail
    // errors) stay retired and are not reused; the tag 10 errors are appended.
    UnauthorizedTrader = 0x100 => "not_trader",
    PositionAssetUnresolved = 0x11B => "market_changed",
    TradeInstructionNotAllowed = 0x11F => "bad_args",
    InvalidTradeAccounts = 0x120 => "bad_account",
    ForbiddenTradeAccount = 0x121 => "bad_account",
    // +0x200 inflow / swaps
    // 0x200 InflowPaused (tag 26): retired (SPEC v4), not reused.
    SwapTooSoon = 0x201 => "interval",
    SwapAmountInvalid = 0x202 => "bad_args",
    FeeInboxInsufficient = 0x203 => "nothing_to_do",
    JupiterTooManyAccounts = 0x204 => "route_rejected",
    JupiterIxForbidden = 0x205 => "route_rejected",
    JupiterArgsMismatch = 0x206 => "route_rejected",
    JupiterRoutePinMismatch = 0x207 => "route_rejected",
    JupiterAccountForbidden = 0x208 => "route_rejected",
    SwapNoop = 0x209 => "route_rejected",
    SwapInputExceeded = 0x20A => "route_rejected",
    SwapOutputBelowMin = 0x20B => "slippage",
    SwapAccountTampered = 0x20C => "route_rejected",
    // 0x20D OracleInvalid, 0x20E OracleStale (the SOL oracle of tags 20 and
    // 43): retired (SPEC v4), not reused.
    DepositNothing = 0x20F => "nothing_to_do",
    EmberWrapMismatch = 0x210 => "invariant",
    DepositNotSettled = 0x211 => "invariant",
    SweepNothing = 0x212 => "nothing_to_do",
    DepositQuietWindow = 0x213 => "interval",
    UnauthorizedKeeper = 0x214 => "not_keeper",
    // +0x300 harvest
    HarvestTooEarly = 0x300 => "too_early",
    HarvestBelowMinimum = 0x301 => "nothing_to_harvest",
    HarvestRiskState = 0x302 => "nothing_to_harvest",
    WithdrawNotImmediate = 0x303 => "withdraw_not_immediate",
    WithdrawAmountMismatch = 0x304 => "invariant",
    EmberAmountMismatch = 0x305 => "invariant",
    CreatorAtaInvalid = 0x306 => "not_ready",
    BuybackAtaInvalid = 0x307 => "not_ready",
    HarvestBuybackBacklog = 0x308 => "not_ready",
    WithdrawQueueBusy = 0x309 => "withdraw_not_immediate",
    WithdrawCooldown = 0x30A => "too_early",
    HarvestMarkStale = 0x30B => "mark_stale",
    CreatorEscrowInvalid = 0x30C => "not_ready",
    CreatorPayNothing = 0x30D => "nothing_to_do",
    // +0x400 buyback
    BbAlreadyInitialized = 0x400 => "already_done",
    BbMintNotSet = 0x401 => "not_ready",
    BbAlreadyPinned = 0x402 => "already_done",
    BbNotPinned = 0x403 => "not_ready",
    BbBadPumpAccount = 0x404 => "bad_account",
    BbPinnedAccountMismatch = 0x405 => "bad_account",
    BbWrongQuote = 0x406 => "bad_account",
    BbCoinFlagsUnexpected = 0x407 => "bad_account",
    BbCreatorNotSharing = 0x408 => "bad_account",
    BbPoolNotReady = 0x409 => "not_ready",
    BbVenueMismatch = 0x40A => "not_ready",
    BbVenueSwitchPending = 0x40B => "not_ready",
    BbMissingDontFront = 0x40C => "tx_composition",
    // 0x40D BbPaused (tag 48): retired (SPEC v4), not reused.
    BbObserveTooSoon = 0x40E => "interval",
    BbWarmup = 0x40F => "warmup",
    BbSameSlot = 0x410 => "interval",
    BbStaleObservation = 0x411 => "warmup",
    BbBuyTooSoon = 0x412 => "interval",
    BbReserveAnomaly = 0x413 => "guard",
    // 0x414 BbSpotAboveGuard (the spot guard of tags 44/45): retired (SPEC v4,
    // DECISIONS §23 item 3), not reused.
    BbChunkBelowMin = 0x415 => "nothing_to_do",
    BbCurveNearComplete = 0x416 => "guard",
    BbExpectedOutBelowMin = 0x417 => "slippage",
    BbFloatLow = 0x418 => "not_ready",
    BbBaseAtaMissing = 0x419 => "not_ready",
    BbQuoteAtaMissing = 0x41A => "not_ready",
    BbOverspend = 0x41B => "invariant",
    BbSlippage = 0x41C => "slippage",
    BbBurnIncomplete = 0x41D => "invariant",
    BbNotSolPair = 0x41E => "bad_args",
    BbSwapTooSoon = 0x41F => "interval",
    BbSolBudgetFull = 0x420 => "nothing_to_do",
    BbSwapAmountInvalid = 0x421 => "bad_args",
    BbUnwrapAccountBusy = 0x422 => "invariant",
    BbAccountTampered = 0x423 => "invariant",
    // +0x500 emergency recovery (tags 50-51)
    RecoveryActive = 0x500 => "recovery",
    RecoveryNotActive = 0x501 => "not_ready",
    RecoveryAlreadyActive = 0x502 => "already_done",
    VenueNotDown = 0x503 => "too_early",
    VenueDownTooShort = 0x504 => "too_early",
    VenueObserveTooSoon = 0x505 => "interval",
    RecoveryNothing = 0x506 => "nothing_to_do",
    RecoveryBelowMinimum = 0x507 => "withdraw_not_immediate",
    RecoveryRecipientInvalid = 0x508 => "not_ready",
    // 0x509 RecoveryRouteUnavailable (route BUYBACK after renounce): retired
    // (SPEC v4), not reused.
    RecoveryAlreadyQueued = 0x50A => "withdraw_not_immediate",
    RecoveryEnqueueTooSoon = 0x50B => "interval",
    RecoveryNotFlat = 0x50C => "not_ready",
    RecoverySwapRestricted = 0x50D => "bad_args",
}

// Compact form of the log lines for the on-chain path (DECISIONS §16): one
// byte blob with every "Sijka: <Name>" line back to back, the end offset of
// each line and the code offset of each variant. A `match` over 160 variants
// compiles to a large jump table; these tables take under 1 KB besides the
// text itself. Built by const evaluation, so an out-of-range index or an
// overflow here is a compile error, never a runtime panic.
const LOG_COUNT: usize = LOG_LINES.len();

#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
const LOG_BLOB_LEN: usize = {
    let mut n = 0;
    let mut i = 0;
    while i < LOG_COUNT {
        n += LOG_LINES[i].len();
        i += 1;
    }
    n
};

#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
static LOG_BLOB: [u8; LOG_BLOB_LEN] = {
    let mut out = [0u8; LOG_BLOB_LEN];
    let mut pos = 0;
    let mut i = 0;
    while i < LOG_COUNT {
        let b = LOG_LINES[i].as_bytes();
        let mut j = 0;
        while j < b.len() {
            out[pos] = b[j];
            pos += 1;
            j += 1;
        }
        i += 1;
    }
    out
};

#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]
static LOG_ENDS: [u16; LOG_COUNT] = {
    assert!(LOG_BLOB_LEN <= u16::MAX as usize);
    let mut out = [0u16; LOG_COUNT];
    let mut pos = 0;
    let mut i = 0;
    while i < LOG_COUNT {
        pos += LOG_LINES[i].len();
        out[i] = pos as u16;
        i += 1;
    }
    out
};

#[allow(clippy::indexing_slicing, clippy::cast_possible_truncation)]
static LOG_CODES: [u16; LOG_COUNT] = {
    assert!(SijkaError::ALL.len() == LOG_COUNT);
    let mut out = [0u16; LOG_COUNT];
    let mut i = 0;
    while i < LOG_COUNT {
        // Offsets are < 0x1000 (see `code`).
        out[i] = SijkaError::ALL[i] as u32 as u16;
        i += 1;
    }
    out
};

/// The `Sijka: <Name>` line of `e` from the compact tables (the same text as
/// [`SijkaError::log_line`]; a test checks every variant).
fn compact_log_line(e: SijkaError) -> &'static [u8] {
    let off = e as u32;
    let Some(i) = LOG_CODES.iter().position(|c| u32::from(*c) == off) else {
        return b"Sijka: error";
    };
    let start = match i.checked_sub(1) {
        Some(p) => LOG_ENDS.get(p).copied().unwrap_or(0),
        None => 0,
    };
    let end = LOG_ENDS.get(i).copied().unwrap_or(0);
    LOG_BLOB.get(usize::from(start)..usize::from(end)).unwrap_or(b"Sijka: error")
}

impl SijkaError {
    /// Log `Sijka: <Name>` and return the error. Use as
    /// `return Err(SijkaError::InvalidPda.fail())` or `.ok_or_else(|| e.fail())`.
    #[cold]
    #[inline(never)]
    pub fn fail(self) -> ProgramError {
        crate::util::runtime::log_bytes(compact_log_line(self));
        ProgramError::Custom(self.code())
    }
}

/// Shorthand for [`SijkaError::fail`].
#[inline(always)]
pub fn err(e: SijkaError) -> ProgramError {
    e.fail()
}

impl From<SijkaError> for ProgramError {
    /// Converts without logging. Prefer [`SijkaError::fail`] on error paths.
    fn from(e: SijkaError) -> Self {
        ProgramError::Custom(e.code())
    }
}

/// Map a `ProgramError` back to a program error, if it is one of ours.
pub fn decode(e: &ProgramError) -> Option<SijkaError> {
    match e {
        ProgramError::Custom(c) => SijkaError::ALL.iter().copied().find(|x| x.code() == *c),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_unique_and_based() {
        let mut seen = std::collections::HashSet::new();
        for e in SijkaError::ALL {
            assert!(seen.insert(e.code()), "duplicate code {:?}", e);
            assert_eq!(e.code() & 0xFFFF_0000, ERROR_BASE);
            assert!(e.log_line().starts_with("Sijka: "));
            assert!(e.log_line().ends_with(e.name()));
        }
    }

    #[test]
    fn spot_values_from_spec_6_2() {
        assert_eq!(SijkaError::UnknownInstruction.code(), 1_397_358_593);
        assert_eq!(SijkaError::InvalidBuybackState.code(), 1_397_358_615);
        assert_eq!(SijkaError::Unauthorized.code(), 1_397_358_656);
        assert_eq!(SijkaError::UnauthorizedTrader.code(), 1_397_358_848);
        assert_eq!(SijkaError::PositionAssetUnresolved.code(), 1_397_358_875);
        assert_eq!(SijkaError::TradeInstructionNotAllowed.code(), 1_397_358_879);
        assert_eq!(SijkaError::InvalidTradeAccounts.code(), 1_397_358_880);
        assert_eq!(SijkaError::ForbiddenTradeAccount.code(), 1_397_358_881);
        assert_eq!(SijkaError::DepositQuietWindow.code(), 1_397_359_123);
        assert_eq!(SijkaError::UnauthorizedKeeper.code(), 1_397_359_124);
        assert_eq!(SijkaError::SwapOutputBelowMin.code(), 1_397_359_115);
        assert_eq!(SijkaError::CreatorPayNothing.code(), 1_397_359_373);
        assert_eq!(SijkaError::BbAccountTampered.code(), 1_397_359_651);
        assert_eq!(SijkaError::RecoverySwapRestricted.code(), 1_397_359_885);
    }

    #[test]
    fn compact_log_lines_match() {
        for e in SijkaError::ALL {
            assert_eq!(compact_log_line(*e), e.log_line().as_bytes(), "{e:?}");
        }
        assert_eq!(LOG_COUNT, SijkaError::ALL.len());
    }

    #[test]
    fn decode_round_trip() {
        for e in SijkaError::ALL {
            assert_eq!(decode(&ProgramError::from(*e)), Some(*e));
        }
        assert_eq!(decode(&ProgramError::Custom(7)), None);
        assert_eq!(decode(&ProgramError::InvalidArgument), None);
    }
}
