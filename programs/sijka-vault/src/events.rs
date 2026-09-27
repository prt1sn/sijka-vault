// Copyright (c) 2026 prt1sn. All rights reserved.
//! Event encoders, SPEC §7 (and §5.0.9).
//!
//! One `sol_log_data` record per event with one slice:
//! `tag [8] ‖ ver u8 = 1 ‖ ts i64 ‖ fields` (little-endian, no padding). No
//! event is emitted on an error path. Structs below are generated from the
//! SPEC §7 tables (via `abi/sijka-vault.json`); field comments give the byte
//! offset. Field names are the SPEC names in snake_case (`I` → `i`,
//! `old`/`new` → `old_value`/`new_value`).
//!
//! Encoding never panics: [`EventWriter`] tracks overflow and `finish` fails
//! with `InvariantViolated` unless exactly `LEN` bytes were written (the tests
//! encode every event).

use pinocchio::ProgramResult;
use pinocchio::program_error::ProgramError;
use pinocchio::pubkey::Pubkey;

use crate::error::SijkaError;
use crate::util::runtime::emit;

/// Event record format version (`ver @8`).
pub const EVENT_VERSION: u8 = 1;
/// Common header length: tag, ver, ts.
pub const EVENT_HEADER_LEN: usize = 17;

/// Fixed-size little-endian writer for one event.
pub struct EventWriter<const N: usize> {
    buf: [u8; N],
    pos: usize,
    ok: bool,
}

impl<const N: usize> EventWriter<N> {
    /// Start an event: writes `tag`, `ver = 1` and `ts`.
    #[inline(always)]
    pub fn new(tag: &[u8; 8], ts: i64) -> Self {
        let mut w = Self { buf: [0u8; N], pos: 0, ok: true };
        w.bytes(tag);
        w.u8(EVENT_VERSION);
        w.i64(ts);
        w
    }

    /// Append `L` bytes. Fixed-size array writes (no `copy_from_slice` call)
    /// let the compiler fold `pos` to constants, so an event compiles to plain
    /// stores at fixed offsets.
    #[inline(always)]
    pub fn bytes<const L: usize>(&mut self, v: &[u8; L]) {
        match crate::util::bytes::array_mut::<L>(&mut self.buf, self.pos) {
            Some(dst) => {
                *dst = *v;
                // In range: `pos + L <= N` was just checked by `array_mut`.
                self.pos = self.pos.saturating_add(L);
            }
            None => self.ok = false,
        }
    }

    #[inline(always)]
    pub fn u8(&mut self, v: u8) {
        self.bytes(&[v]);
    }
    #[inline(always)]
    pub fn i8(&mut self, v: i8) {
        self.bytes(&v.to_le_bytes());
    }
    #[inline(always)]
    pub fn u16(&mut self, v: u16) {
        self.bytes(&v.to_le_bytes());
    }
    #[inline(always)]
    pub fn u32(&mut self, v: u32) {
        self.bytes(&v.to_le_bytes());
    }
    #[inline(always)]
    pub fn u64(&mut self, v: u64) {
        self.bytes(&v.to_le_bytes());
    }
    #[inline(always)]
    pub fn i64(&mut self, v: i64) {
        self.bytes(&v.to_le_bytes());
    }
    #[inline(always)]
    pub fn u128(&mut self, v: u128) {
        self.bytes(&v.to_le_bytes());
    }

    /// The encoded record, or `InvariantViolated` if the length is not `N`.
    #[inline(always)]
    pub fn finish(self) -> Result<[u8; N], ProgramError> {
        if self.ok && self.pos == N { Ok(self.buf) } else { Err(SijkaError::InvariantViolated.fail()) }
    }
}

// ------------------------------------------------------------ generated ----
/// `SJKEVINI` (179 bytes, SPEC §7).
#[derive(Clone, Copy, Debug)]
pub struct EvInitialize<'a> {
    pub ts: i64,
    /// `admin` @17.
    pub admin: &'a Pubkey,
    /// `creator_payout` @49.
    pub creator_payout: &'a Pubkey,
    /// `quote_mint` @81.
    pub quote_mint: &'a Pubkey,
    /// `usdc_mint` @113.
    pub usdc_mint: &'a Pubkey,
    /// `phusd_mint` @145.
    pub phusd_mint: &'a Pubkey,
    /// `config_version` @177.
    pub config_version: u16,
}

impl EvInitialize<'_> {
    pub const TAG: [u8; 8] = *b"SJKEVINI";
    pub const LEN: usize = 179;

    pub fn encode(&self) -> Result<[u8; 179], ProgramError> {
        let mut w = EventWriter::<179>::new(&Self::TAG, self.ts);
        w.bytes(self.admin);
        w.bytes(self.creator_payout);
        w.bytes(self.quote_mint);
        w.bytes(self.usdc_mint);
        w.bytes(self.phusd_mint);
        w.u16(self.config_version);
        w.finish()
    }

    /// Log the event (`sol_log_data`, one slice).
    pub fn emit(&self) -> ProgramResult {
        emit(&self.encode()?);
        Ok(())
    }
}

/// `SJKEVMNT` (146 bytes, SPEC §7).
#[derive(Clone, Copy, Debug)]
pub struct EvTokenMintSet<'a> {
    pub ts: i64,
    /// `token_mint` @17.
    pub token_mint: &'a Pubkey,
    /// `token_program` @49.
    pub token_program: &'a Pubkey,
    /// `decimals` @81.
    pub decimals: u8,
    /// `sharing_config` @82.
    pub sharing_config: &'a Pubkey,
    /// `buyback_token` @114.
    pub buyback_token: &'a Pubkey,
}

impl EvTokenMintSet<'_> {
    pub const TAG: [u8; 8] = *b"SJKEVMNT";
    pub const LEN: usize = 146;

    pub fn encode(&self) -> Result<[u8; 146], ProgramError> {
        let mut w = EventWriter::<146>::new(&Self::TAG, self.ts);
        w.bytes(self.token_mint);
        w.bytes(self.token_program);
        w.u8(self.decimals);
        w.bytes(self.sharing_config);
        w.bytes(self.buyback_token);
        w.finish()
    }

    /// Log the event (`sol_log_data`, one slice).
    pub fn emit(&self) -> ProgramResult {
        emit(&self.encode()?);
        Ok(())
    }
}

/// `SJKEVREG` (94 bytes, SPEC §7).
#[derive(Clone, Copy, Debug)]
pub struct EvTraderRegistered<'a> {
    pub ts: i64,
    /// `phoenix_trader` @17.
    pub phoenix_trader: &'a Pubkey,
    /// `prefs` @49.
    pub prefs: u32,
    /// `max_positions` @53.
    pub max_positions: u32,
    /// `created_by_program` @57.
    pub created_by_program: u8,
    /// `funding_key` @58.
    pub funding_key: &'a Pubkey,
    /// `flags` @90.
    pub flags: u32,
}

impl EvTraderRegistered<'_> {
    pub const TAG: [u8; 8] = *b"SJKEVREG";
    pub const LEN: usize = 94;

    pub fn encode(&self) -> Result<[u8; 94], ProgramError> {
        let mut w = EventWriter::<94>::new(&Self::TAG, self.ts);
        w.bytes(self.phoenix_trader);
        w.u32(self.prefs);
        w.u32(self.max_positions);
        w.u8(self.created_by_program);
        w.bytes(self.funding_key);
        w.u32(self.flags);
        w.finish()
    }

    /// Log the event (`sol_log_data`, one slice).
    pub fn emit(&self) -> ProgramResult {
        emit(&self.encode()?);
        Ok(())
    }
}

/// `SJKEVTRD` (81 bytes, SPEC §7), tag 3 `set_trader`.
#[derive(Clone, Copy, Debug)]
pub struct EvTraderSet<'a> {
    pub ts: i64,
    /// `old` @17: `cfg.trader` before (0 = trading was off).
    pub old_value: &'a Pubkey,
    /// `new` @49: the new trading key (0 = trading off).
    pub new_value: &'a Pubkey,
}

impl EvTraderSet<'_> {
    pub const TAG: [u8; 8] = *b"SJKEVTRD";
    pub const LEN: usize = 81;

    pub fn encode(&self) -> Result<[u8; 81], ProgramError> {
        let mut w = EventWriter::<81>::new(&Self::TAG, self.ts);
        w.bytes(self.old_value);
        w.bytes(self.new_value);
        w.finish()
    }

    /// Log the event (`sol_log_data`, one slice).
    pub fn emit(&self) -> ProgramResult {
        emit(&self.encode()?);
        Ok(())
    }
}

/// `SJKEVSWI` (90 bytes, SPEC §7), tag 20. SPEC v4: no oracle fields; `min_out`
/// is the keeper's.
#[derive(Clone, Copy, Debug)]
pub struct EvSwapIn {
    pub ts: i64,
    /// `jup_kind` @17.
    pub jup_kind: u8,
    /// `slot` @18.
    pub slot: u64,
    /// `amount_in` @26.
    pub amount_in: u64,
    /// `spent` @34.
    pub spent: u64,
    /// `received` @42.
    pub received: u64,
    /// `min_out` @50: the keeper's `min_out` (instruction data).
    pub min_out: u64,
    /// `topup` @58.
    pub topup: u64,
    /// `fee_inbox_after` @66.
    pub fee_inbox_after: u64,
    /// `wsol_left` @74.
    pub wsol_left: u64,
    /// `swap_count` @82.
    pub swap_count: u64,
}

impl EvSwapIn {
    pub const TAG: [u8; 8] = *b"SJKEVSWI";
    pub const LEN: usize = 90;

    pub fn encode(&self) -> Result<[u8; 90], ProgramError> {
        let mut w = EventWriter::<90>::new(&Self::TAG, self.ts);
        w.u8(self.jup_kind);
        w.u64(self.slot);
        w.u64(self.amount_in);
        w.u64(self.spent);
        w.u64(self.received);
        w.u64(self.min_out);
        w.u64(self.topup);
        w.u64(self.fee_inbox_after);
        w.u64(self.wsol_left);
        w.u64(self.swap_count);
        w.finish()
    }

    /// Log the event (`sol_log_data`, one slice).
    pub fn emit(&self) -> ProgramResult {
        emit(&self.encode()?);
        Ok(())
    }
}

/// `SJKEVDEP` (97 bytes, SPEC §7).
#[derive(Clone, Copy, Debug)]
pub struct EvDeposit {
    pub ts: i64,
    /// `slot` @17.
    pub slot: u64,
    /// `usdc_wrapped` @25.
    pub usdc_wrapped: u64,
    /// `phusd_direct` @33.
    pub phusd_direct: u64,
    /// `deposited` @41.
    pub deposited: u64,
    /// `I_after` @49.
    pub i_after: u64,
    /// `collateral_before` @57.
    pub collateral_before: i64,
    /// `collateral_after` @65.
    pub collateral_after: i64,
    /// `deposit_count` @73.
    pub deposit_count: u64,
    /// `ember_fee` @81.
    pub ember_fee: u64,
    /// `max_amount` @89.
    pub max_amount: u64,
}

impl EvDeposit {
    pub const TAG: [u8; 8] = *b"SJKEVDEP";
    pub const LEN: usize = 97;

    pub fn encode(&self) -> Result<[u8; 97], ProgramError> {
        let mut w = EventWriter::<97>::new(&Self::TAG, self.ts);
        w.u64(self.slot);
        w.u64(self.usdc_wrapped);
        w.u64(self.phusd_direct);
        w.u64(self.deposited);
        w.u64(self.i_after);
        w.i64(self.collateral_before);
        w.i64(self.collateral_after);
        w.u64(self.deposit_count);
        w.u64(self.ember_fee);
        w.u64(self.max_amount);
        w.finish()
    }

    /// Log the event (`sol_log_data`, one slice).
    pub fn emit(&self) -> ProgramResult {
        emit(&self.encode()?);
        Ok(())
    }
}

/// `SJKEVSFU` (65 bytes, SPEC §7).
#[derive(Clone, Copy, Debug)]
pub struct EvSweepFeeInbox<'a> {
    pub ts: i64,
    /// `slot` @17.
    pub slot: u64,
    /// `source` @25.
    pub source: &'a Pubkey,
    /// `amount` @57.
    pub amount: u64,
}

impl EvSweepFeeInbox<'_> {
    pub const TAG: [u8; 8] = *b"SJKEVSFU";
    pub const LEN: usize = 65;

    pub fn encode(&self) -> Result<[u8; 65], ProgramError> {
        let mut w = EventWriter::<65>::new(&Self::TAG, self.ts);
        w.u64(self.slot);
        w.bytes(self.source);
        w.u64(self.amount);
        w.finish()
    }

    /// Log the event (`sol_log_data`, one slice).
    pub fn emit(&self) -> ProgramResult {
        emit(&self.encode()?);
        Ok(())
    }
}

/// `SJKEVSSU` (65 bytes, SPEC §7).
#[derive(Clone, Copy, Debug)]
pub struct EvSweepSwapUsdc<'a> {
    pub ts: i64,
    /// `slot` @17.
    pub slot: u64,
    /// `source` @25.
    pub source: &'a Pubkey,
    /// `amount` @57.
    pub amount: u64,
}

impl EvSweepSwapUsdc<'_> {
    pub const TAG: [u8; 8] = *b"SJKEVSSU";
    pub const LEN: usize = 65;

    pub fn encode(&self) -> Result<[u8; 65], ProgramError> {
        let mut w = EventWriter::<65>::new(&Self::TAG, self.ts);
        w.u64(self.slot);
        w.bytes(self.source);
        w.u64(self.amount);
        w.finish()
    }

    /// Log the event (`sol_log_data`, one slice).
    pub fn emit(&self) -> ProgramResult {
        emit(&self.encode()?);
        Ok(())
    }
}

/// `SJKEVKPR` (81 bytes, SPEC §7), tag 28 `set_keeper`.
#[derive(Clone, Copy, Debug)]
pub struct EvKeeperSet<'a> {
    pub ts: i64,
    /// `old` @17: `cfg.keeper` before (0 = swaps were off).
    pub old_value: &'a Pubkey,
    /// `new` @49: the new keeper key (0 = swaps off).
    pub new_value: &'a Pubkey,
}

impl EvKeeperSet<'_> {
    pub const TAG: [u8; 8] = *b"SJKEVKPR";
    pub const LEN: usize = 81;

    pub fn encode(&self) -> Result<[u8; 81], ProgramError> {
        let mut w = EventWriter::<81>::new(&Self::TAG, self.ts);
        w.bytes(self.old_value);
        w.bytes(self.new_value);
        w.finish()
    }

    /// Log the event (`sol_log_data`, one slice).
    pub fn emit(&self) -> ProgramResult {
        emit(&self.encode()?);
        Ok(())
    }
}

/// `SJKEVHRV` (164 bytes, SPEC §7).
#[derive(Clone, Copy, Debug)]
pub struct EvHarvest {
    pub ts: i64,
    /// `slot` @17.
    pub slot: u64,
    /// `I` @25.
    pub i: u64,
    /// `O_after` @33.
    pub o_after: u64,
    /// `C_hk` @41.
    pub c_hk: i64,
    /// `C_hdr` @49.
    pub c_hdr: i64,
    /// `U` @57.
    pub u: i64,
    /// `F` @65.
    pub f: i64,
    /// `D_star` @73.
    pub d_star: i64,
    /// `W` @81.
    pub w: u64,
    /// `buf` @89.
    pub buf: u64,
    /// `IM` @97.
    pub im: u64,
    /// `D` @105.
    pub d: u64,
    /// `r` @113.
    pub r: u64,
    /// `creator` @121.
    pub creator: u64,
    /// `buyback` @129.
    pub buyback: u64,
    /// `harvest_count` @137.
    pub harvest_count: u64,
    /// `position_count` @145.
    pub position_count: u16,
    /// `usdc_received` @147.
    pub usdc_received: u64,
    /// `queue_cap` @155.
    pub queue_cap: u64,
    /// `bits` @163.
    pub bits: u8,
}

impl EvHarvest {
    pub const TAG: [u8; 8] = *b"SJKEVHRV";
    pub const LEN: usize = 164;

    pub fn encode(&self) -> Result<[u8; 164], ProgramError> {
        let mut w = EventWriter::<164>::new(&Self::TAG, self.ts);
        w.u64(self.slot);
        w.u64(self.i);
        w.u64(self.o_after);
        w.i64(self.c_hk);
        w.i64(self.c_hdr);
        w.i64(self.u);
        w.i64(self.f);
        w.i64(self.d_star);
        w.u64(self.w);
        w.u64(self.buf);
        w.u64(self.im);
        w.u64(self.d);
        w.u64(self.r);
        w.u64(self.creator);
        w.u64(self.buyback);
        w.u64(self.harvest_count);
        w.u16(self.position_count);
        w.u64(self.usdc_received);
        w.u64(self.queue_cap);
        w.u8(self.bits);
        w.finish()
    }

    /// Log the event (`sol_log_data`, one slice).
    pub fn emit(&self) -> ProgramResult {
        emit(&self.encode()?);
        Ok(())
    }
}

/// `SJKEVPCR` (49 bytes, SPEC §7).
#[derive(Clone, Copy, Debug)]
pub struct EvPayCreator {
    pub ts: i64,
    /// `slot` @17.
    pub slot: u64,
    /// `amount` @25.
    pub amount: u64,
    /// `cum_creator_paid_out` @33.
    pub cum_creator_paid_out: u64,
    /// `cum_payout_creator` @41.
    pub cum_payout_creator: u64,
}

impl EvPayCreator {
    pub const TAG: [u8; 8] = *b"SJKEVPCR";
    pub const LEN: usize = 49;

    pub fn encode(&self) -> Result<[u8; 49], ProgramError> {
        let mut w = EventWriter::<49>::new(&Self::TAG, self.ts);
        w.u64(self.slot);
        w.u64(self.amount);
        w.u64(self.cum_creator_paid_out);
        w.u64(self.cum_payout_creator);
        w.finish()
    }

    /// Log the event (`sol_log_data`, one slice).
    pub fn emit(&self) -> ProgramResult {
        emit(&self.encode()?);
        Ok(())
    }
}

/// `SJKEVBIN` (114 bytes, SPEC §7).
#[derive(Clone, Copy, Debug)]
pub struct EvBuybackInit<'a> {
    pub ts: i64,
    /// `quote_kind` @17.
    pub quote_kind: u8,
    /// `bb_usdc` @18.
    pub bb_usdc: &'a Pubkey,
    /// `swap_usdc` @50.
    pub swap_usdc: &'a Pubkey,
    /// `bb_wsol` @82.
    pub bb_wsol: &'a Pubkey,
}

impl EvBuybackInit<'_> {
    pub const TAG: [u8; 8] = *b"SJKEVBIN";
    pub const LEN: usize = 114;

    pub fn encode(&self) -> Result<[u8; 114], ProgramError> {
        let mut w = EventWriter::<114>::new(&Self::TAG, self.ts);
        w.u8(self.quote_kind);
        w.bytes(self.bb_usdc);
        w.bytes(self.swap_usdc);
        w.bytes(self.bb_wsol);
        w.finish()
    }

    /// Log the event (`sol_log_data`, one slice).
    pub fn emit(&self) -> ProgramResult {
        emit(&self.encode()?);
        Ok(())
    }
}

/// `SJKEVBPN` (154 bytes, SPEC §7).
#[derive(Clone, Copy, Debug)]
pub struct EvBuybackPin<'a> {
    pub ts: i64,
    /// `mint` @17.
    pub mint: &'a Pubkey,
    /// `base_tp` @49.
    pub base_tp: &'a Pubkey,
    /// `venue` @81.
    pub venue: u8,
    /// `bonding_curve` @82.
    pub bonding_curve: &'a Pubkey,
    /// `pool` @114.
    pub pool: &'a Pubkey,
    /// `slot` @146.
    pub slot: u64,
}

impl EvBuybackPin<'_> {
    pub const TAG: [u8; 8] = *b"SJKEVBPN";
    pub const LEN: usize = 154;

    pub fn encode(&self) -> Result<[u8; 154], ProgramError> {
        let mut w = EventWriter::<154>::new(&Self::TAG, self.ts);
        w.bytes(self.mint);
        w.bytes(self.base_tp);
        w.u8(self.venue);
        w.bytes(self.bonding_curve);
        w.bytes(self.pool);
        w.u64(self.slot);
        w.finish()
    }

    /// Log the event (`sol_log_data`, one slice).
    pub fn emit(&self) -> ProgramResult {
        emit(&self.encode()?);
        Ok(())
    }
}

/// `SJKEVOBS` (85 bytes, SPEC §7).
#[derive(Clone, Copy, Debug)]
pub struct EvObserve {
    pub ts: i64,
    /// `venue` @17.
    pub venue: u8,
    /// `slot` @18.
    pub slot: u64,
    /// `q` @26.
    pub q: u64,
    /// `b` @34.
    pub b: u64,
    /// `p_raw` @42.
    pub p_raw: u128,
    /// `ema` @58.
    pub ema: u128,
    /// `q_ema` @74.
    pub q_ema: u64,
    /// `fresh_obs` @82.
    pub fresh_obs: u16,
    /// `clamped` @84.
    pub clamped: u8,
}

impl EvObserve {
    pub const TAG: [u8; 8] = *b"SJKEVOBS";
    pub const LEN: usize = 85;

    pub fn encode(&self) -> Result<[u8; 85], ProgramError> {
        let mut w = EventWriter::<85>::new(&Self::TAG, self.ts);
        w.u8(self.venue);
        w.u64(self.slot);
        w.u64(self.q);
        w.u64(self.b);
        w.u128(self.p_raw);
        w.u128(self.ema);
        w.u64(self.q_ema);
        w.u16(self.fresh_obs);
        w.u8(self.clamped);
        w.finish()
    }

    /// Log the event (`sol_log_data`, one slice).
    pub fn emit(&self) -> ProgramResult {
        emit(&self.encode()?);
        Ok(())
    }
}

/// `SJKEVVEN` (51 bytes, SPEC §7).
#[derive(Clone, Copy, Debug)]
pub struct EvVenueSwitch {
    pub ts: i64,
    /// `old` @17.
    pub old_value: u8,
    /// `new` @18.
    pub new_value: u8,
    /// `slot` @19.
    pub slot: u64,
    /// `p` @27.
    pub p: u128,
    /// `q` @43.
    pub q: u64,
}

impl EvVenueSwitch {
    pub const TAG: [u8; 8] = *b"SJKEVVEN";
    pub const LEN: usize = 51;

    pub fn encode(&self) -> Result<[u8; 51], ProgramError> {
        let mut w = EventWriter::<51>::new(&Self::TAG, self.ts);
        w.u8(self.old_value);
        w.u8(self.new_value);
        w.u64(self.slot);
        w.u128(self.p);
        w.u64(self.q);
        w.finish()
    }

    /// Log the event (`sol_log_data`, one slice).
    pub fn emit(&self) -> ProgramResult {
        emit(&self.encode()?);
        Ok(())
    }
}

/// `SJKEVBSW` (65 bytes, SPEC §7), tag 43. SPEC v4: no oracle fields; `min_out`
/// is the keeper's.
#[derive(Clone, Copy, Debug)]
pub struct EvBuybackSwap {
    pub ts: i64,
    /// `amount_in` @17.
    pub amount_in: u64,
    /// `spent` @25.
    pub spent: u64,
    /// `out` @33.
    pub out: u64,
    /// `min_out` @41: the keeper's `min_out` (instruction data).
    pub min_out: u64,
    /// `cum_usdc_swapped` @49.
    pub cum_usdc_swapped: u64,
    /// `cum_sol_from_swaps` @57.
    pub cum_sol_from_swaps: u64,
}

impl EvBuybackSwap {
    pub const TAG: [u8; 8] = *b"SJKEVBSW";
    pub const LEN: usize = 65;

    pub fn encode(&self) -> Result<[u8; 65], ProgramError> {
        let mut w = EventWriter::<65>::new(&Self::TAG, self.ts);
        w.u64(self.amount_in);
        w.u64(self.spent);
        w.u64(self.out);
        w.u64(self.min_out);
        w.u64(self.cum_usdc_swapped);
        w.u64(self.cum_sol_from_swaps);
        w.finish()
    }

    /// Log the event (`sol_log_data`, one slice).
    pub fn emit(&self) -> ProgramResult {
        emit(&self.encode()?);
        Ok(())
    }
}

/// `SJKEVCHK` (138 bytes, SPEC §7).
#[derive(Clone, Copy, Debug)]
pub struct EvChunk {
    pub ts: i64,
    /// `venue` @17.
    pub venue: u8,
    /// `v` @18.
    pub v: u64,
    /// `quote_spent` @26.
    pub quote_spent: u64,
    /// `rent_extra` @34.
    pub rent_extra: u64,
    /// `min_out` @42.
    pub min_out: u64,
    /// `bought` @50.
    pub bought: u64,
    /// `burned` @58.
    pub burned: u64,
    /// `p_now` @66.
    pub p_now: u128,
    /// `p_ref` @82.
    pub p_ref: u128,
    /// `q_ref` @98.
    pub q_ref: u64,
    /// `slot` @106.
    pub slot: u64,
    /// `cum_burned_tokens` @114.
    pub cum_burned_tokens: u64,
    /// `cum_payout_buyback_spent` @122.
    pub cum_payout_buyback_spent: u64,
    /// `n_chunks` @130.
    pub n_chunks: u64,
}

impl EvChunk {
    pub const TAG: [u8; 8] = *b"SJKEVCHK";
    pub const LEN: usize = 138;

    pub fn encode(&self) -> Result<[u8; 138], ProgramError> {
        let mut w = EventWriter::<138>::new(&Self::TAG, self.ts);
        w.u8(self.venue);
        w.u64(self.v);
        w.u64(self.quote_spent);
        w.u64(self.rent_extra);
        w.u64(self.min_out);
        w.u64(self.bought);
        w.u64(self.burned);
        w.u128(self.p_now);
        w.u128(self.p_ref);
        w.u64(self.q_ref);
        w.u64(self.slot);
        w.u64(self.cum_burned_tokens);
        w.u64(self.cum_payout_buyback_spent);
        w.u64(self.n_chunks);
        w.finish()
    }

    /// Log the event (`sol_log_data`, one slice).
    pub fn emit(&self) -> ProgramResult {
        emit(&self.encode()?);
        Ok(())
    }
}

/// `SJKEVBRN` (33 bytes, SPEC §7).
#[derive(Clone, Copy, Debug)]
pub struct EvBurn {
    pub ts: i64,
    /// `amount` @17.
    pub amount: u64,
    /// `cum_burned_tokens` @25.
    pub cum_burned_tokens: u64,
}

impl EvBurn {
    pub const TAG: [u8; 8] = *b"SJKEVBRN";
    pub const LEN: usize = 33;

    pub fn encode(&self) -> Result<[u8; 33], ProgramError> {
        let mut w = EventWriter::<33>::new(&Self::TAG, self.ts);
        w.u64(self.amount);
        w.u64(self.cum_burned_tokens);
        w.finish()
    }

    /// Log the event (`sol_log_data`, one slice).
    pub fn emit(&self) -> ProgramResult {
        emit(&self.encode()?);
        Ok(())
    }
}

/// `SJKEVVOB` (76 bytes, SPEC §7).
#[derive(Clone, Copy, Debug)]
pub struct EvVenueObservation {
    pub ts: i64,
    /// `verdict` @17.
    pub verdict: u8,
    /// `reason` @18.
    pub reason: u8,
    /// `exchange_status` @19.
    pub exchange_status: u8,
    /// `majors_open` @20.
    pub majors_open: u8,
    /// `majors_closed` @21.
    pub majors_closed: u8,
    /// `majors_unknown` @22.
    pub majors_unknown: u8,
    /// `flags` @23.
    pub flags: u8,
    /// `slot` @24.
    pub slot: u64,
    /// `ack` @32.
    pub ack: u64,
    /// `lrs` @40.
    pub lrs: u64,
    /// `live` @48.
    pub live: u32,
    /// `down_since` @52.
    pub down_since: i64,
    /// `last_down_obs_ts` @60.
    pub last_down_obs_ts: i64,
    /// `obs_count` @68.
    pub obs_count: u64,
}

impl EvVenueObservation {
    pub const TAG: [u8; 8] = *b"SJKEVVOB";
    pub const LEN: usize = 76;

    pub fn encode(&self) -> Result<[u8; 76], ProgramError> {
        let mut w = EventWriter::<76>::new(&Self::TAG, self.ts);
        w.u8(self.verdict);
        w.u8(self.reason);
        w.u8(self.exchange_status);
        w.u8(self.majors_open);
        w.u8(self.majors_closed);
        w.u8(self.majors_unknown);
        w.u8(self.flags);
        w.u64(self.slot);
        w.u64(self.ack);
        w.u64(self.lrs);
        w.u32(self.live);
        w.i64(self.down_since);
        w.i64(self.last_down_obs_ts);
        w.u64(self.obs_count);
        w.finish()
    }

    /// Log the event (`sol_log_data`, one slice).
    pub fn emit(&self) -> ProgramResult {
        emit(&self.encode()?);
        Ok(())
    }
}

/// `SJKEVRCL` (107 bytes, SPEC §7).
#[derive(Clone, Copy, Debug)]
pub struct EvRecoveryLatch<'a> {
    pub ts: i64,
    /// `reason` @17.
    pub reason: u8,
    /// `route` @18: always 0 (RECIPIENT) since SPEC v4 (no route BUYBACK).
    pub route: u8,
    /// `slot` @19.
    pub slot: u64,
    /// `down_since` @27.
    pub down_since: i64,
    /// `down_secs` @35.
    pub down_secs: i64,
    /// `emergency_recipient` @43.
    pub emergency_recipient: &'a Pubkey,
    /// `usdc_destination` @75.
    pub usdc_destination: &'a Pubkey,
}

impl EvRecoveryLatch<'_> {
    pub const TAG: [u8; 8] = *b"SJKEVRCL";
    pub const LEN: usize = 107;

    pub fn encode(&self) -> Result<[u8; 107], ProgramError> {
        let mut w = EventWriter::<107>::new(&Self::TAG, self.ts);
        w.u8(self.reason);
        w.u8(self.route);
        w.u64(self.slot);
        w.i64(self.down_since);
        w.i64(self.down_secs);
        w.bytes(self.emergency_recipient);
        w.bytes(self.usdc_destination);
        w.finish()
    }

    /// Log the event (`sol_log_data`, one slice).
    pub fn emit(&self) -> ProgramResult {
        emit(&self.encode()?);
        Ok(())
    }
}

/// `SJKEVRCW` (123 bytes, SPEC §7).
#[derive(Clone, Copy, Debug)]
pub struct EvRecoveryWithdraw {
    pub ts: i64,
    /// `op` @17.
    pub op: u8,
    /// `bits` @18.
    pub bits: u8,
    /// `slot` @19.
    pub slot: u64,
    /// `D` @27.
    pub d: u64,
    /// `r` @35.
    pub r: u64,
    /// `max_amount` @43.
    pub max_amount: u64,
    /// `free` @51.
    pub free: i64,
    /// `wd` @59.
    pub wd: u64,
    /// `IM` @67.
    pub im: u64,
    /// `buf` @75.
    pub buf: u64,
    /// `c_hdr` @83.
    pub c_hdr: i64,
    /// `q_tmp` @91.
    pub q_tmp: u64,
    /// `total_queued_after` @99.
    pub total_queued_after: u64,
    /// `cum_withdrawn_after` @107.
    pub cum_withdrawn_after: u64,
    /// `cum_queued_after` @115.
    pub cum_queued_after: u64,
}

impl EvRecoveryWithdraw {
    pub const TAG: [u8; 8] = *b"SJKEVRCW";
    pub const LEN: usize = 123;

    pub fn encode(&self) -> Result<[u8; 123], ProgramError> {
        let mut w = EventWriter::<123>::new(&Self::TAG, self.ts);
        w.u8(self.op);
        w.u8(self.bits);
        w.u64(self.slot);
        w.u64(self.d);
        w.u64(self.r);
        w.u64(self.max_amount);
        w.i64(self.free);
        w.u64(self.wd);
        w.u64(self.im);
        w.u64(self.buf);
        w.i64(self.c_hdr);
        w.u64(self.q_tmp);
        w.u64(self.total_queued_after);
        w.u64(self.cum_withdrawn_after);
        w.u64(self.cum_queued_after);
        w.finish()
    }

    /// Log the event (`sol_log_data`, one slice).
    pub fn emit(&self) -> ProgramResult {
        emit(&self.encode()?);
        Ok(())
    }
}

/// `SJKEVRCS` (91 bytes, SPEC §7).
#[derive(Clone, Copy, Debug)]
pub struct EvRecoverySend<'a> {
    pub ts: i64,
    /// `op` @17.
    pub op: u8,
    /// `route` @18: always 0 (RECIPIENT) since SPEC v4 (no route BUYBACK).
    pub route: u8,
    /// `slot` @19.
    pub slot: u64,
    /// `phusd_unwrapped` @27.
    pub phusd_unwrapped: u64,
    /// `usdc_from_ember` @35.
    pub usdc_from_ember: u64,
    /// `amount` @43.
    pub amount: u64,
    /// `destination` @51.
    pub destination: &'a Pubkey,
    /// `cum_after` @83.
    pub cum_after: u64,
}

impl EvRecoverySend<'_> {
    pub const TAG: [u8; 8] = *b"SJKEVRCS";
    pub const LEN: usize = 91;

    pub fn encode(&self) -> Result<[u8; 91], ProgramError> {
        let mut w = EventWriter::<91>::new(&Self::TAG, self.ts);
        w.u8(self.op);
        w.u8(self.route);
        w.u64(self.slot);
        w.u64(self.phusd_unwrapped);
        w.u64(self.usdc_from_ember);
        w.u64(self.amount);
        w.bytes(self.destination);
        w.u64(self.cum_after);
        w.finish()
    }

    /// Log the event (`sol_log_data`, one slice).
    pub fn emit(&self) -> ProgramResult {
        emit(&self.encode()?);
        Ok(())
    }
}

/// All event tags with their lengths (for the ABI consistency test).
pub const EVENTS: &[(&[u8; 8], usize)] = &[
    (&EvInitialize::TAG, EvInitialize::LEN),
    (&EvTokenMintSet::TAG, EvTokenMintSet::LEN),
    (&EvTraderRegistered::TAG, EvTraderRegistered::LEN),
    (&EvTraderSet::TAG, EvTraderSet::LEN),
    (&EvSwapIn::TAG, EvSwapIn::LEN),
    (&EvDeposit::TAG, EvDeposit::LEN),
    (&EvSweepFeeInbox::TAG, EvSweepFeeInbox::LEN),
    (&EvSweepSwapUsdc::TAG, EvSweepSwapUsdc::LEN),
    (&EvKeeperSet::TAG, EvKeeperSet::LEN),
    (&EvHarvest::TAG, EvHarvest::LEN),
    (&EvPayCreator::TAG, EvPayCreator::LEN),
    (&EvBuybackInit::TAG, EvBuybackInit::LEN),
    (&EvBuybackPin::TAG, EvBuybackPin::LEN),
    (&EvObserve::TAG, EvObserve::LEN),
    (&EvVenueSwitch::TAG, EvVenueSwitch::LEN),
    (&EvBuybackSwap::TAG, EvBuybackSwap::LEN),
    (&EvChunk::TAG, EvChunk::LEN),
    (&EvBurn::TAG, EvBurn::LEN),
    (&EvVenueObservation::TAG, EvVenueObservation::LEN),
    (&EvRecoveryLatch::TAG, EvRecoveryLatch::LEN),
    (&EvRecoveryWithdraw::TAG, EvRecoveryWithdraw::LEN),
    (&EvRecoverySend::TAG, EvRecoverySend::LEN),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writer_rejects_wrong_length() {
        let mut w = EventWriter::<18>::new(b"SJKEVXXX", 5);
        assert!(EventWriter::<17>::new(b"SJKEVXXX", 5).finish().is_ok());
        w.u8(1);
        let b = w.finish().unwrap();
        assert_eq!(&b[0..8], b"SJKEVXXX");
        assert_eq!(b[8], 1);
        assert_eq!(i64::from_le_bytes(b[9..17].try_into().unwrap()), 5);
        let mut short = EventWriter::<18>::new(b"SJKEVXXX", 5);
        short.u16(1); // one byte too many
        assert!(short.finish().is_err());
        assert!(EventWriter::<19>::new(b"SJKEVXXX", 5).finish().is_err());
    }

    #[test]
    fn every_event_encodes_to_its_length() {
        let k = [3u8; 32];
        let checks: Vec<(usize, Vec<u8>)> = vec![
            (
                EvInitialize::LEN,
                EvInitialize {
                    ts: 1,
                    admin: &k,
                    creator_payout: &k,
                    quote_mint: &k,
                    usdc_mint: &k,
                    phusd_mint: &k,
                    config_version: 1,
                }
                .encode()
                .unwrap()
                .to_vec(),
            ),
            (
                EvTokenMintSet::LEN,
                EvTokenMintSet {
                    ts: 1,
                    token_mint: &k,
                    token_program: &k,
                    decimals: 6,
                    sharing_config: &k,
                    buyback_token: &k,
                }
                .encode()
                .unwrap()
                .to_vec(),
            ),
            (
                EvTraderRegistered::LEN,
                EvTraderRegistered {
                    ts: 1,
                    phoenix_trader: &k,
                    prefs: 3,
                    max_positions: 128,
                    created_by_program: 1,
                    funding_key: &k,
                    flags: 62,
                }
                .encode()
                .unwrap()
                .to_vec(),
            ),
            (EvTraderSet::LEN, EvTraderSet { ts: 1, old_value: &k, new_value: &k }.encode().unwrap().to_vec()),
            (EvKeeperSet::LEN, EvKeeperSet { ts: 1, old_value: &k, new_value: &k }.encode().unwrap().to_vec()),
            (
                EvSwapIn::LEN,
                EvSwapIn {
                    ts: 1,
                    jup_kind: 3,
                    slot: 2,
                    amount_in: 3,
                    spent: 4,
                    received: 5,
                    min_out: 6,
                    topup: 7,
                    fee_inbox_after: 8,
                    wsol_left: 9,
                    swap_count: 10,
                }
                .encode()
                .unwrap()
                .to_vec(),
            ),
            (
                EvBuybackSwap::LEN,
                EvBuybackSwap {
                    ts: 1,
                    amount_in: 2,
                    spent: 3,
                    out: 4,
                    min_out: 5,
                    cum_usdc_swapped: 6,
                    cum_sol_from_swaps: 7,
                }
                .encode()
                .unwrap()
                .to_vec(),
            ),
            (EvBurn::LEN, EvBurn { ts: 1, amount: 2, cum_burned_tokens: 3 }.encode().unwrap().to_vec()),
        ];
        for (len, bytes) in checks {
            assert_eq!(bytes.len(), len);
            assert_eq!(bytes[8], EVENT_VERSION);
        }
        // Spot-check field placement against SPEC §7.
        let e = EvTraderRegistered {
            ts: -1,
            phoenix_trader: &k,
            prefs: 0x0102_0304,
            max_positions: 128,
            created_by_program: 1,
            funding_key: &[9u8; 32],
            flags: 63,
        }
        .encode()
        .unwrap();
        assert_eq!(&e[0..8], b"SJKEVREG");
        assert_eq!(i64::from_le_bytes(e[9..17].try_into().unwrap()), -1);
        assert_eq!(&e[49..53], &[4, 3, 2, 1]);
        assert_eq!(e[57], 1);
        assert_eq!(&e[58..90], &[9u8; 32]);
        assert_eq!(&e[90..94], &63u32.to_le_bytes());
        // SPEC v4 swap events: `min_out` @50 (SJKEVSWI) and @41 (SJKEVBSW).
        let s = EvSwapIn {
            ts: 0,
            jup_kind: 1,
            slot: 0,
            amount_in: 0,
            spent: 0,
            received: 0,
            min_out: 0x0102,
            topup: 0,
            fee_inbox_after: 0,
            wsol_left: 0,
            swap_count: 0x0304,
        }
        .encode()
        .unwrap();
        assert_eq!(s[17], 1);
        assert_eq!(&s[50..58], &0x0102u64.to_le_bytes());
        assert_eq!(&s[82..90], &0x0304u64.to_le_bytes());
        let b = EvBuybackSwap {
            ts: 0,
            amount_in: 0,
            spent: 0,
            out: 0,
            min_out: 0x0506,
            cum_usdc_swapped: 0,
            cum_sol_from_swaps: 0x0708,
        }
        .encode()
        .unwrap();
        assert_eq!(&b[41..49], &0x0506u64.to_le_bytes());
        assert_eq!(&b[57..65], &0x0708u64.to_le_bytes());
        let kp = EvKeeperSet { ts: 0, old_value: &[1; 32], new_value: &[2; 32] }.encode().unwrap();
        assert_eq!(&kp[0..8], b"SJKEVKPR");
        assert_eq!(&kp[17..49], &[1; 32]);
        assert_eq!(&kp[49..81], &[2; 32]);
    }

    #[test]
    fn event_table_is_complete() {
        assert_eq!(EVENTS.len(), 22);
        let mut tags: Vec<_> = EVENTS.iter().map(|(t, _)| **t).collect();
        tags.sort();
        tags.dedup();
        assert_eq!(tags.len(), 22);
        // Retired with SPEC v4 (DECISIONS §23).
        for t in [b"SJKEVHPR", b"SJKEVREN", b"SJKEVIPR", b"SJKEVIPA", b"SJKEVBPR", b"SJKEVBPA"] {
            assert!(!EVENTS.iter().any(|(x, _)| *x == t), "{t:?}");
        }
        for (t, len) in EVENTS {
            assert!(t.starts_with(b"SJKEV"));
            assert!(*len >= EVENT_HEADER_LEN);
        }
    }
}
