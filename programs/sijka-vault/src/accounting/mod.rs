// Copyright (c) 2026 prt1sn. All rights reserved.
//! Pure profit accounting (SPEC §5.4.1): the payout formula
//! `D* = C − I + min(0, U + F)` with every clamp, the Phoenix withdraw-queue
//! clamp (review ACC-5 / RT-5), the arrival checks of the withdraw path
//! (SPEC v4, DECISIONS §23 item 6: no tolerance, whatever Phoenix and Ember
//! deliver is booked), the 20/80 split and the
//! monotonic counter update. No account access, no syscalls: every function
//! here is deterministic and host-testable (`proptests.rs` holds the property
//! tests of the invariants, SPEC §9.2 TU-A1, §9.9 INV-2/INV-3).
//!
//! Units: USDC atoms (1e-6) = Phoenix quote lots. Counters are u64,
//! intermediate values i128/u128, all checked (SPEC §5.0.7). Errors are
//! returned as [`SijkaError`] values; the instruction maps them with
//! `SijkaError::fail` (which logs) at the call site.

pub mod preview;

#[cfg(test)]
mod proptests;

use crate::constants::{BPS, CREATOR_SHARE_BPS, DISC_WITHDRAW_QUEUE, PHOENIX_PROGRAM_ID, WITHDRAW_QUEUE_HEADER_LEN};
use crate::cpi::hawkeye::MarginView;
use crate::error::SijkaError;
use crate::external::layout::{trader as trl, withdraw_queue as wq};
use crate::external::phoenix_accounts::{PamEntry, pam_entry, pam_header};
use crate::state::config::harvest_params::HarvestParams;
use crate::util::bytes::{array_ref, read_i64, read_u64};
use crate::util::math::saturate_u64;

/// Result of the pure accounting functions.
pub type AccResult<T> = Result<T, SijkaError>;

const OVERFLOW: SijkaError = SijkaError::MathOverflow;

// ------------------------------------------------------------- formula ----

/// Intermediate values of the harvest formula (SPEC §5.4.1), all in i128.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HarvestCalc {
    /// `C = min(C_hk, C_hdr)`.
    pub c: i128,
    /// `D* = C − I + min(0, U + F)`.
    pub d_star: i128,
    /// `W = min(max(free, 0), wd)`.
    pub w: i128,
    /// `buf = max(margin_buffer_abs, ⌈IM·margin_buffer_im_bps / 10 000⌉)`.
    pub buf: i128,
    /// `min(D* − ε, W − buf, max_harvest_per_call)` (before the queue clamp).
    pub d_pre: i128,
    /// `min(d_pre, Q_perm)`.
    pub d_perm: i128,
    /// `D = min(d_perm, Q_tmp)`; may be ≤ 0.
    pub d: i128,
    /// `D < d_perm`: the transient budget `Q_tmp` cut `D`, so `last_harvest_ts`
    /// is not moved (review RT-5).
    pub timer_held: bool,
}

impl HarvestCalc {
    /// Event / preview bit0: `D` was cut by the queue clamp `Q = min(Q_perm, Q_tmp)`.
    #[inline]
    pub fn queue_limited(&self) -> bool {
        self.d < self.d_pre
    }
}

/// `⌈x·bps / 10 000⌉` in u128 (a threshold the pool keeps, rounded up; SPEC §5.0.7).
#[inline]
fn ceil_bps_u128(x: u64, bps: u32) -> AccResult<u128> {
    let num = u128::from(x).checked_mul(u128::from(bps)).ok_or(OVERFLOW)?;
    let den = u128::from(BPS);
    let q = num.checked_div(den).ok_or(OVERFLOW)?;
    let r = num.checked_rem(den).ok_or(OVERFLOW)?;
    if r == 0 { Ok(q) } else { q.checked_add(1).ok_or(OVERFLOW) }
}

/// `compute_harvest` (SPEC §5.4.1, reviews ACC-5, ACC-13, RT-5). The same
/// function is mirrored by the SDK `harvestPreview` (SPEC §8.2.7).
///
/// `q_perm` / `q_tmp` are the permanent (`max_budget`) and transient
/// (`remaining + replenish·Δslot`) withdraw budgets, `u64::MAX` when the
/// queue header was not recognised. The clamps only ever lower `D`.
pub fn compute_harvest(
    m: &MarginView,
    c_hdr: i64,
    i: u64,
    p: &HarvestParams<'_>,
    q_perm: u64,
    q_tmp: u64,
) -> AccResult<HarvestCalc> {
    let c = i128::from(m.collateral).min(i128::from(c_hdr));
    let upnl_funding = i128::from(m.unrealized_pnl).checked_add(i128::from(m.unsettled_funding)).ok_or(OVERFLOW)?;
    let d_star = c.checked_sub(i128::from(i)).and_then(|x| x.checked_add(upnl_funding.min(0))).ok_or(OVERFLOW)?;
    let w = i128::from(m.free_collateral.max(0)).min(i128::from(m.withdrawable_collateral));
    let im_part = i128::try_from(ceil_bps_u128(m.initial_margin, p.margin_buffer_im_bps())?).map_err(|_| OVERFLOW)?;
    let buf = i128::from(p.margin_buffer_abs()).max(im_part);
    let by_profit = d_star.checked_sub(i128::from(p.epsilon())).ok_or(OVERFLOW)?;
    let by_margin = w.checked_sub(buf).ok_or(OVERFLOW)?;
    let d_pre = by_profit.min(by_margin).min(i128::from(p.max_harvest_per_call()));
    let d_perm = d_pre.min(i128::from(q_perm));
    let d = d_perm.min(i128::from(q_tmp));
    Ok(HarvestCalc { c, d_star, w, buf, d_pre, d_perm, d, timer_held: d < d_perm })
}

/// 20/80 split of the USDC that actually arrived (`u`): `creator =
/// ⌊u·2000 / 10 000⌋`, `buyback = u − creator` (rounding in favour of the
/// buyback, SPEC §5.0.7). The share is the compile-time constant, not the
/// informational `Config.creator_share_bps`.
pub fn split_payout(u: u64) -> AccResult<(u64, u64)> {
    let creator = u128::from(u)
        .checked_mul(u128::from(CREATOR_SHARE_BPS))
        .and_then(|x| x.checked_div(u128::from(BPS)))
        .ok_or(OVERFLOW)?;
    let creator = u64::try_from(creator).map_err(|_| OVERFLOW)?;
    let buyback = u.checked_sub(creator).ok_or(OVERFLOW)?;
    Ok((creator, buyback))
}

// ------------------------------------------------------ withdraw queue ----

/// Phoenix withdraw-queue clamp inputs (SPEC §3.9 `WithdrawQueueHeader`,
/// §5.4.2 step 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueueState {
    /// Header recognised (owner Phoenix, length ≥ 120, discriminator).
    pub parsed: bool,
    /// `Q_perm = max_budget`.
    pub q_perm: u64,
    /// `Q_tmp = remaining + replenish·(slot − last_update)`, saturated to u64.
    pub q_tmp: u64,
    /// `total_queued` (0 when not parsed).
    pub total_queued: u64,
}

impl QueueState {
    /// Header not recognised: no clamp (behaviour before review ACC-5).
    pub const UNPARSED: Self = Self { parsed: false, q_perm: u64::MAX, q_tmp: u64::MAX, total_queued: 0 };

    /// `Q = min(Q_perm, Q_tmp)` (`u64::MAX` when not parsed).
    #[inline]
    pub fn cap(&self) -> u64 {
        self.q_perm.min(self.q_tmp)
    }

    /// Recognised header with queued requests (`WithdrawQueueBusy`).
    #[inline]
    pub fn busy(&self) -> bool {
        self.parsed && self.total_queued > 0
    }
}

/// Parse the withdraw-queue header. Anything unexpected (other owner, short
/// data, other discriminator) gives [`QueueState::UNPARSED`]: the clamp can
/// only lower `D`, so a parse failure never raises a payout.
pub fn parse_withdraw_queue(owner: &[u8; 32], data: &[u8], slot: u64) -> QueueState {
    if owner != &PHOENIX_PROGRAM_ID
        || data.len() < WITHDRAW_QUEUE_HEADER_LEN
        || array_ref::<8>(data, wq::DISCRIMINATOR) != Some(&DISC_WITHDRAW_QUEUE)
    {
        return QueueState::UNPARSED;
    }
    let (Some(max_budget), Some(remaining), Some(replenish), Some(last_update), Some(total_queued)) = (
        read_u64(data, wq::MAX_BUDGET),
        read_u64(data, wq::REMAINING),
        read_u64(data, wq::REPLENISH_PER_SLOT),
        read_u64(data, wq::LAST_UPDATE_SLOT),
        read_u64(data, wq::TOTAL_QUEUED),
    ) else {
        return QueueState::UNPARSED;
    };
    let elapsed = slot.saturating_sub(last_update);
    // u128: replenish·elapsed < 2^128; the sum saturates (formula U-50).
    let q_tmp = u128::from(replenish)
        .checked_mul(u128::from(elapsed))
        .and_then(|x| x.checked_add(u128::from(remaining)))
        .map_or(u64::MAX, saturate_u64);
    QueueState { parsed: true, q_perm: max_budget, q_tmp, total_queued }
}

// -------------------------------------------------------------- gates ----

/// Harvest status, in the numbering of the `harvest_preview` return data
/// (SPEC §5.4.3). Each non-ready status maps to the error tag 30 returns.
/// Code 4 (`Paused`) is retired with the admin pause (SPEC v2) and not reused.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HarvestStatus {
    Ready = 0,
    TooEarly = 1,
    BelowMinimum = 2,
    RiskState = 3,
    BuybackBacklog = 5,
    QueueBusy = 6,
    Cooldown = 7,
    MarkStale = 8,
    Recovery = 9,
}

impl HarvestStatus {
    #[inline]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// The tag 30 error for this status (`None` for `Ready`).
    pub const fn error(self) -> Option<SijkaError> {
        match self {
            HarvestStatus::Ready => None,
            HarvestStatus::TooEarly => Some(SijkaError::HarvestTooEarly),
            HarvestStatus::BelowMinimum => Some(SijkaError::HarvestBelowMinimum),
            HarvestStatus::RiskState => Some(SijkaError::HarvestRiskState),
            HarvestStatus::BuybackBacklog => Some(SijkaError::HarvestBuybackBacklog),
            HarvestStatus::QueueBusy => Some(SijkaError::WithdrawQueueBusy),
            HarvestStatus::Cooldown => Some(SijkaError::WithdrawCooldown),
            HarvestStatus::MarkStale => Some(SijkaError::HarvestMarkStale),
            HarvestStatus::Recovery => Some(SijkaError::RecoveryActive),
        }
    }

    /// `Ok(())` for `Ready`, else the error.
    #[inline]
    pub fn check(self) -> AccResult<()> {
        match self.error() {
            None => Ok(()),
            Some(e) => Err(e),
        }
    }
}

/// Inputs of the gates that run before any CPI (SPEC §5.4.2 steps 1–5).
#[derive(Clone, Copy, Debug)]
pub struct GateInputs {
    pub recovery_mode: u8,
    pub now: i64,
    pub last_harvest_ts: i64,
    pub t_min_secs: u32,
    pub max_buyback_backlog: u64,
    /// `buyback_usdc.amount` (the 80% not yet spent, review ACC-1).
    pub buyback_usdc: u64,
    /// `GC@512 deposit_cooldown_period_in_slots`.
    pub cooldown_slots: u64,
    /// Trader `@192 last_deposit_slot`.
    pub last_deposit_slot: u64,
    pub slot: u64,
    pub queue: QueueState,
}

/// `last_harvest_ts` that `initialize` writes (SPEC §5.1.0 step 9, DECISIONS
/// §23 item 7): `created_ts − t_min_secs`. The `T_min` gate of [`early_gate`]
/// (`now ≥ last_harvest_ts + t_min_secs`) is then open from `created_ts` on,
/// so the first harvest may run right after `initialize`. The first harvest
/// that moves the timer writes `now` (step 18, [`Ledger::apply`]), and every
/// later one waits `T_min` as before; a first harvest with `timer_held`
/// (review RT-5) keeps this anchor, so the next one stays allowed at once.
/// The gate formula itself is unchanged (tag 30, tag 31, SDK, keeper).
/// Checked `i64 − u32`: `MathOverflow` only for a clock below
/// `i64::MIN + u32::MAX`.
pub fn initial_last_harvest_ts(created_ts: i64, t_min_secs: u32) -> AccResult<i64> {
    created_ts.checked_sub(i64::from(t_min_secs)).ok_or(OVERFLOW)
}

impl GateInputs {
    /// `last_harvest_ts + t_min_secs` (saturating: an absurd timestamp keeps
    /// the gate closed rather than wrapping open). Before the first harvest
    /// this is `created_ts` ([`initial_last_harvest_ts`]).
    #[inline]
    pub fn next_allowed_ts(&self) -> i64 {
        self.last_harvest_ts.saturating_add(i64::from(self.t_min_secs))
    }

    /// `last_deposit_slot + cd` (saturating), 0 when `cd = 0`.
    #[inline]
    pub fn cooldown_until_slot(&self) -> u64 {
        if self.cooldown_slots == 0 { 0 } else { self.last_deposit_slot.saturating_add(self.cooldown_slots) }
    }
}

/// Gates before the position scan, in tag 30 order: recovery → `T_min` →
/// buyback backlog (review ACC-1) → Phoenix deposit cooldown (ACC-6) → busy
/// withdraw queue (ACC-5).
pub fn early_gate(g: &GateInputs) -> HarvestStatus {
    if g.recovery_mode != 0 {
        HarvestStatus::Recovery
    } else if g.now < g.next_allowed_ts() {
        HarvestStatus::TooEarly
    } else if g.max_buyback_backlog != 0 && g.buyback_usdc > g.max_buyback_backlog {
        HarvestStatus::BuybackBacklog
    } else if g.cooldown_slots > 0 && g.slot < g.cooldown_until_slot() {
        HarvestStatus::Cooldown
    } else if g.queue.busy() {
        HarvestStatus::QueueBusy
    } else {
        HarvestStatus::Ready
    }
}

/// Risk gate after Hawkeye (step 9): `risk_tier == 0 && is_liquidatable == 0`.
#[inline]
pub fn risk_ok(m: &MarginView) -> bool {
    m.risk_tier == 0 && m.is_liquidatable == 0
}

/// Full status for `harvest_preview` (SPEC §5.4.3 order: Recovery →
/// TooEarly → BuybackBacklog → Cooldown → QueueBusy → MarkStale → RiskState →
/// BelowMinimum → Ready).
pub fn preview_status(g: &GateInputs, stale: u32, m: &MarginView, calc: &HarvestCalc, d_min: u64) -> HarvestStatus {
    let early = early_gate(g);
    if early != HarvestStatus::Ready {
        early
    } else if stale > 0 {
        HarvestStatus::MarkStale
    } else if !risk_ok(m) {
        HarvestStatus::RiskState
    } else if calc.d < i128::from(d_min) {
        HarvestStatus::BelowMinimum
    } else {
        HarvestStatus::Ready
    }
}

// ---------------------------------------------------------- mark scan ----

/// Result of the mark-freshness scan over the trader's position map
/// (SPEC §5.4.2 steps 6 and 8a, reviews ACC-9 and RT-3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MarkScan {
    /// `n_scan`: records with `base ≠ 0` (header extensions skipped).
    pub positions: u32,
    /// Positions whose mark is older than the limit, or whose asset does
    /// not resolve in the PAM (the preview counts both as stale).
    pub stale: u32,
    /// First failing record, in map order (tag 30 returns it):
    /// `PositionAssetUnresolved` or `HarvestMarkStale`.
    pub first_failure: Option<SijkaError>,
    /// `n_rec`: all records except header extensions, `base = 0` included
    /// (a market with resting orders only is a `base = 0` record, U-55).
    pub records: u32,
    /// Records with `base = 0` whose PAM entry resolves and whose mark is
    /// older than the limit (step 8a). Unresolved flat records are not
    /// counted: a closed or deleted market cannot hide a position that
    /// Hawkeye would price.
    pub flat_stale: u32,
}

impl MarkScan {
    /// Step 8a (review RT-3, without the market whitelist; full audit FA-4):
    /// a position the map does not show yet (maker fill or trigger order in
    /// someone else's transaction) can only sit on a `base = 0` record of the
    /// map (the market of a resting order placed by tag 10, whose CPI synced
    /// the map) or, in theory, on a market the map has no record for
    /// (`pc > n_rec`, where Hawkeye counts `pc` markets with a position or
    /// resting orders). So the marks of the flat records must always be fresh
    /// too. This is not gated on `pc > n_scan`: a lagging map may still show
    /// a position that is already closed in the ATB, so `pc ≤ n_scan` does
    /// not prove that no flat record hides one (FA-4). Does not depend on
    /// Hawkeye's own, per-market staleness rules. Returns the number of
    /// records counted as stale; 0 passes.
    pub fn hidden_stale(&self, pc: u16) -> u32 {
        self.flat_stale.saturating_add(u32::from(pc).saturating_sub(self.records))
    }
}

/// PAM entry of a position record (SPEC §5.2.8): `slot = idx & 0xFFFF`,
/// `slot < slots_used`, entry inside the data, `asset_id(e) == idx`.
fn resolve_position(pam: &[u8], slots_used: u32, idx: u32) -> Option<PamEntry> {
    let slot = idx & 0xFFFF;
    if slot >= slots_used {
        return None;
    }
    pam_entry(pam, slot).filter(|e| e.asset_id == idx)
}

/// Scan every open position of the trader account (`trader` = its data) and
/// check the age of its PAM mark: `slot − mark.slot > max_age` is stale.
/// Flat records are counted and aged too, for step 8a
/// ([`MarkScan::hidden_stale`]). Only call with `max_age ≠ 0` (0 disables
/// the check, SPEC §3.2).
pub fn scan_position_marks(trader: &[u8], pam: &[u8], slot: u64, max_age: u64) -> AccResult<MarkScan> {
    let len = read_u64(trader, trl::LEN).ok_or(SijkaError::InvalidPhoenixTraderAccount)?;
    let slots_used = pam_header(pam).ok_or(SijkaError::InvalidPerpAssetMap)?.slots_used;
    let mut s = MarkScan::default();
    let mut rec = trl::POSITIONS;
    for _ in 0..len {
        let bad = SijkaError::InvalidPhoenixTraderAccount;
        let raw = read_u64(trader, rec.checked_add(trl::POS_ASSET_INDEX).ok_or(bad)?).ok_or(bad)?;
        let base = read_i64(trader, rec.checked_add(trl::POS_BASE_LOTS).ok_or(bad)?).ok_or(bad)?;
        rec = rec.checked_add(trl::POSITION_LEN).ok_or(bad)?;
        // Low 32 bits of `asset_index` (SPEC §3.9); the mask makes it fit.
        let idx = u32::try_from(raw & 0xFFFF_FFFF).map_err(|_| bad)?;
        if idx >= trl::EXTENSION_ASSET_INDEX_MIN {
            continue;
        }
        s.records = s.records.checked_add(1).ok_or(OVERFLOW)?;
        if base == 0 {
            // Step 8a input: only a resolved entry with an old mark counts.
            if resolve_position(pam, slots_used, idx).is_some_and(|e| slot.saturating_sub(e.mark_slot) > max_age) {
                s.flat_stale = s.flat_stale.checked_add(1).ok_or(OVERFLOW)?;
            }
            continue;
        }
        s.positions = s.positions.checked_add(1).ok_or(OVERFLOW)?;
        let fail = match resolve_position(pam, slots_used, idx) {
            None => Some(SijkaError::PositionAssetUnresolved),
            Some(e) if slot.saturating_sub(e.mark_slot) > max_age => Some(SijkaError::HarvestMarkStale),
            Some(_) => None,
        };
        if let Some(f) = fail {
            s.stale = s.stale.checked_add(1).ok_or(OVERFLOW)?;
            s.first_failure.get_or_insert(f);
        }
    }
    Ok(s)
}

// ------------------------------------------------------ arrival checks ----

/// Step 13: PhUSD that arrived on `vault_phusd` from `withdraw_funds(D)`,
/// measured as the exact delta of our own account. A balance decrease is
/// `InvariantViolated`; nothing arrived (the request was queued, SPEC §5.4.4)
/// is `WithdrawNotImmediate`; `r > D` is `WithdrawAmountMismatch`. Any
/// holdback `D − r` of Phoenix is accepted (SPEC v4, DECISIONS §23 item 6:
/// whatever arrives is what counts; the former tolerance `tol(D)` of review
/// ACC-7 is retired). Returns `r`.
pub fn check_withdraw_arrival(phusd_before: u64, phusd_after: u64, d: u64) -> AccResult<u64> {
    let r = phusd_after.checked_sub(phusd_before).ok_or(SijkaError::InvariantViolated)?;
    if r == 0 {
        return Err(SijkaError::WithdrawNotImmediate);
    }
    if r > d {
        return Err(SijkaError::WithdrawAmountMismatch);
    }
    Ok(r)
}

/// Step 13a: the withdrawal put nothing into the Phoenix queue. If Phoenix
/// ever filled part of `D` and queued the rest, step 13 would book the
/// queued part as a holdback, and `ConsumeWithdrawQueue` would later bring it
/// to `vault_phusd`, where tag 21 would count profit as capital (SPEC §5.4.1:
/// a queued withdrawal rolls back). This is not a fee tolerance: any holdback
/// is still accepted. Checked only when the header was recognised before the
/// CPI (the clamp is skipped otherwise too); `WithdrawNotImmediate` if the
/// header is no longer recognised or `total_queued` grew.
pub fn check_nothing_queued(before: &QueueState, after: &QueueState) -> AccResult<()> {
    if before.parsed && (!after.parsed || after.total_queued > before.total_queued) {
        return Err(SijkaError::WithdrawNotImmediate);
    }
    Ok(())
}

/// Step 15: after Ember `withdraw(Some(r))`, `vault_phusd` is back at its
/// pre-harvest balance (exactly `r` left it, donated PhUSD untouched), and
/// the USDC delta `u` satisfies `0 < u ≤ r`. Anything else is
/// `EmberAmountMismatch`. Any Ember holdback `r − u` is accepted (SPEC v4,
/// DECISIONS §23 item 6). Returns `u`.
pub fn check_ember_arrival(
    phusd_before: u64,
    phusd_after: u64,
    usdc_before: u64,
    usdc_after: u64,
    r: u64,
) -> AccResult<u64> {
    let e = SijkaError::EmberAmountMismatch;
    if phusd_after != phusd_before {
        return Err(e);
    }
    let u = usdc_after.checked_sub(usdc_before).ok_or(e)?;
    if u == 0 || u > r {
        return Err(e);
    }
    Ok(u)
}

// -------------------------------------------------------------- ledger ----

/// The `Config` counters harvest writes (SPEC §3.1 `@712..784`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ledger {
    /// `O` (`cum_payout_usdc`).
    pub o: u64,
    pub cum_payout_creator: u64,
    pub cum_payout_buyback: u64,
    pub cum_withdraw_fees: u64,
    pub harvest_count: u64,
    pub last_harvest_ts: i64,
    pub last_harvest_slot: u64,
    pub last_harvest_amount: u64,
}

/// Amounts of one verified harvest.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Payout {
    /// Requested from Phoenix.
    pub d: u64,
    /// PhUSD received.
    pub r: u64,
    /// USDC received (the payout, `O`-increment).
    pub u: u64,
    pub creator: u64,
    pub buyback: u64,
}

impl Ledger {
    /// Step 18 (checked): `O += u`, creator / buyback sums, `cum_withdraw_fees
    /// += D − u`, `harvest_count += 1`, `last_harvest_ts = now` unless
    /// `timer_held` (review RT-5), slot and amount; then `O == creator_sum +
    /// buyback_sum`. The payout must be consistent (`u = creator + buyback`,
    /// `0 < u ≤ r ≤ D`), else `InvariantViolated`.
    pub fn apply(&self, p: &Payout, timer_held: bool, now: i64, slot: u64) -> AccResult<Ledger> {
        let inv = SijkaError::InvariantViolated;
        if p.creator.checked_add(p.buyback) != Some(p.u) || p.u == 0 || p.u > p.r || p.r > p.d {
            return Err(inv);
        }
        let fee = p.d.checked_sub(p.u).ok_or(inv)?;
        let next = Ledger {
            o: self.o.checked_add(p.u).ok_or(OVERFLOW)?,
            cum_payout_creator: self.cum_payout_creator.checked_add(p.creator).ok_or(OVERFLOW)?,
            cum_payout_buyback: self.cum_payout_buyback.checked_add(p.buyback).ok_or(OVERFLOW)?,
            cum_withdraw_fees: self.cum_withdraw_fees.checked_add(fee).ok_or(OVERFLOW)?,
            harvest_count: self.harvest_count.checked_add(1).ok_or(OVERFLOW)?,
            last_harvest_ts: if timer_held { self.last_harvest_ts } else { now },
            last_harvest_slot: slot,
            last_harvest_amount: p.u,
        };
        if next.cum_payout_creator.checked_add(next.cum_payout_buyback) != Some(next.o) {
            return Err(inv);
        }
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::config::harvest_params::HarvestParamsMut;

    pub(crate) fn params(eps: u64, d_min: u64, abs: u64, max: u64, im_bps: u32) -> [u8; 64] {
        let mut b = [0u8; 64];
        let mut m = HarvestParamsMut::from_array(&mut b);
        m.set_epsilon(eps);
        m.set_d_min(d_min);
        m.set_margin_buffer_abs(abs);
        m.set_max_harvest_per_call(max);
        m.set_margin_buffer_im_bps(im_bps);
        b
    }

    pub(crate) fn margin(c: i64, u: i64, f: i64, free: i64, wd: u64, im: u64) -> MarginView {
        MarginView {
            collateral: c,
            unrealized_pnl: u,
            unsettled_funding: f,
            free_collateral: free,
            withdrawable_collateral: wd,
            initial_margin: im,
            ..MarginView::default()
        }
    }

    const M: u64 = 1_000_000; // 1 USDC

    #[test]
    fn note06_scenario_d_star() {
        // research note 06 §9.1 (ε = 0, D_min = 0, W not binding).
        let pb = params(0, 1, 0, u64::MAX, 0);
        let p = HarvestParams::from_array(&pb);
        let big = 1_000_000 * M;
        let run = |c: u64, u: i64, i: u64| {
            let m = margin(c as i64, u * M as i64, 0, big as i64, big, 0);
            compute_harvest(&m, c as i64, i, &p, u64::MAX, u64::MAX).unwrap()
        };
        // t2: C 1300, U +50, I 1000 → D* = 300.
        assert_eq!(run(1300 * M, 50, 1000 * M).d_star, (300 * M) as i128);
        // t3a / t3b: deficit −150 survives the +200 inflow.
        assert_eq!(run(850 * M, 0, 1000 * M).d_star, -150 * M as i128);
        assert_eq!(run(1050 * M, 0, 1200 * M).d_star, -150 * M as i128);
        // t5: 80 realized − 40 open loss.
        assert_eq!(run(1280 * M, -40, 1200 * M).d, (40 * M) as i128);
        // t6: positive uPnL is not paid; the 40 hidden by the open loss is freed.
        assert_eq!(run(1240 * M, 500, 1200 * M).d, (40 * M) as i128);
    }

    #[test]
    fn clamps_each_bind() {
        let pb = params(M, 25 * M, 5 * M, 250_000 * M, 5_000);
        let p = HarvestParams::from_array(&pb);
        // Profit-bound: C − I − ε.
        let m = margin(1_100 * M as i64, 0, 0, 1_000 * M as i64, 1_000 * M, 0);
        let c = compute_harvest(&m, 1_100 * M as i64, 1_000 * M, &p, u64::MAX, u64::MAX).unwrap();
        assert_eq!(c.d, (99 * M) as i128);
        assert!(!c.timer_held && !c.queue_limited());
        // Margin-bound: W − max(abs, ⌈IM·bps⌉); IM = 101 → ⌈50.5⌉ = 51 atoms... use USDC.
        let m = margin(10_000 * M as i64, 0, 0, 60 * M as i64, 70 * M, 100 * M + 1);
        let c = compute_harvest(&m, 10_000 * M as i64, 0, &p, u64::MAX, u64::MAX).unwrap();
        assert_eq!(c.buf, (50 * M + 1) as i128); // ⌈(100e6 + 1)·0.5⌉ rounds up
        assert_eq!(c.d, (60 * M - 50 * M - 1) as i128);
        // Negative free collateral: W = 0.
        let m = margin(10_000 * M as i64, 0, 0, -5, 70 * M, 0);
        assert_eq!(compute_harvest(&m, 10_000 * M as i64, 0, &p, u64::MAX, u64::MAX).unwrap().w, 0);
        // C = min(C_hk, C_hdr): the header is lower.
        let m = margin(10_000 * M as i64, 0, 0, 10_000 * M as i64, 10_000 * M, 0);
        let c = compute_harvest(&m, 2_000 * M as i64, 1_000 * M, &p, u64::MAX, u64::MAX).unwrap();
        assert_eq!(c.c, (2_000 * M) as i128);
        assert_eq!(c.d, (999 * M) as i128);
        // Max per call.
        let pb2 = params(0, 1, 0, 7 * M, 0);
        let c =
            compute_harvest(&m, 10_000 * M as i64, 0, &HarvestParams::from_array(&pb2), u64::MAX, u64::MAX).unwrap();
        assert_eq!(c.d, (7 * M) as i128);
        // Funding counts with its sign.
        let m = margin(1_100 * M as i64, 10 * M as i64, -30 * M as i64, 1_000 * M as i64, 1_000 * M, 0);
        let c = compute_harvest(&m, 1_100 * M as i64, 1_000 * M, &p, u64::MAX, u64::MAX).unwrap();
        assert_eq!(c.d_star, (80 * M) as i128);
    }

    #[test]
    fn queue_clamps_and_timer() {
        let pb = params(0, 1, 0, u64::MAX, 0);
        let p = HarvestParams::from_array(&pb);
        let m = margin(1_000 * M as i64, 0, 0, 1_000 * M as i64, 1_000 * M, 0);
        // Permanent budget binds: D = Q_perm, timer moves.
        let c = compute_harvest(&m, 1_000 * M as i64, 0, &p, 300 * M, u64::MAX).unwrap();
        assert_eq!(c.d, (300 * M) as i128);
        assert!(c.queue_limited() && !c.timer_held);
        // Transient budget binds: timer held.
        let c = compute_harvest(&m, 1_000 * M as i64, 0, &p, 300 * M, 30 * M).unwrap();
        assert_eq!(c.d, (30 * M) as i128);
        assert!(c.queue_limited() && c.timer_held);
        // q_tmp ≥ q_perm never holds the timer.
        let c = compute_harvest(&m, 1_000 * M as i64, 0, &p, 300 * M, 300 * M).unwrap();
        assert!(!c.timer_held);
    }

    #[test]
    fn split() {
        // SPEC §5.4.1 example.
        assert_eq!(split_payout(12_345_678), Ok((2_469_135, 9_876_543)));
        assert_eq!(split_payout(1), Ok((0, 1)));
        assert_eq!(split_payout(4), Ok((0, 4)));
        assert_eq!(split_payout(5), Ok((1, 4)));
        assert_eq!(split_payout(u64::MAX).map(|(c, b)| c + b), Ok(u64::MAX));
    }

    fn queue_bytes(max_budget: u64, remaining: u64, replenish: u64, last: u64, queued: u64) -> Vec<u8> {
        let mut d = vec![0u8; crate::constants::WITHDRAW_QUEUE_LEN];
        d[0..8].copy_from_slice(&DISC_WITHDRAW_QUEUE);
        d[8..24].copy_from_slice(&[7u8; 16]); // sequence number
        d[24..32].copy_from_slice(&max_budget.to_le_bytes());
        d[32..40].copy_from_slice(&remaining.to_le_bytes());
        d[40..48].copy_from_slice(&replenish.to_le_bytes());
        d[48..56].copy_from_slice(&last.to_le_bytes());
        d[56..64].copy_from_slice(&queued.to_le_bytes());
        d[64..72].copy_from_slice(&500_000u64.to_le_bytes());
        d[72..80].copy_from_slice(&500_000u64.to_le_bytes());
        d
    }

    #[test]
    fn withdraw_queue_header() {
        // Live numbers (SPEC §3.9, review ACC-5 / RT-5): max_budget 2e12,
        // remaining ≈ 1.9989e12, replenish 4.5e8 per slot.
        let d = queue_bytes(2_000_000_000_000, 1_998_900_000_000, 450_000_000, 450_426_800, 0);
        let q = parse_withdraw_queue(&PHOENIX_PROGRAM_ID, &d, 450_426_817);
        assert!(q.parsed && !q.busy());
        assert_eq!(q.q_perm, 2_000_000_000_000);
        assert_eq!(q.q_tmp, 1_998_900_000_000 + 450_000_000 * 17);
        assert_eq!(q.cap(), 2_000_000_000_000);
        // Slot before last_update: Δ = 0.
        assert_eq!(parse_withdraw_queue(&PHOENIX_PROGRAM_ID, &d, 1).q_tmp, 1_998_900_000_000);
        // Saturation.
        let s = queue_bytes(5, u64::MAX, u64::MAX, 0, 0);
        assert_eq!(parse_withdraw_queue(&PHOENIX_PROGRAM_ID, &s, u64::MAX).q_tmp, u64::MAX);
        // Busy.
        let b = queue_bytes(5, 5, 5, 0, 1);
        assert!(parse_withdraw_queue(&PHOENIX_PROGRAM_ID, &b, 0).busy());
        // Other owner, short data, other discriminator → unparsed (no clamp).
        assert_eq!(parse_withdraw_queue(&[1u8; 32], &d, 0), QueueState::UNPARSED);
        assert_eq!(parse_withdraw_queue(&PHOENIX_PROGRAM_ID, &d[..119], 0), QueueState::UNPARSED);
        let mut x = d.clone();
        x[0] ^= 1;
        assert_eq!(parse_withdraw_queue(&PHOENIX_PROGRAM_ID, &x, 0), QueueState::UNPARSED);
        assert_eq!(QueueState::UNPARSED.cap(), u64::MAX);
        assert!(!QueueState::UNPARSED.busy());
        // The header prefix alone (120 bytes) is enough.
        assert!(parse_withdraw_queue(&PHOENIX_PROGRAM_ID, &d[..120], 0).parsed);
    }

    #[test]
    fn withdraw_queue_parity_with_sdk_view() {
        use phoenix_rise::accounts::withdraw_queue::WithdrawQueueHeader;
        assert_eq!(phoenix_rise::accounts::PhoenixAccount::WithdrawQueueHeader.discriminant(), DISC_WITHDRAW_QUEUE);
        let d = queue_bytes(2_000_000_000_000, 123_456, 450_000_000, 99, 777);
        let h = WithdrawQueueHeader::try_from_account_bytes(&d).unwrap();
        let t = h.withdraw_throttle();
        let q = parse_withdraw_queue(&PHOENIX_PROGRAM_ID, &d, 100);
        assert_eq!(q.q_perm, t.max_budget().as_inner());
        assert_eq!(q.q_tmp, t.remaining_budget().as_inner() + t.replenish_amount_per_slot().as_inner());
        assert_eq!(t.last_update_slot(), 99);
        assert_eq!(q.total_queued, h.total_queued_amount().as_inner());
        assert_eq!(h.withdrawal_fee().as_inner(), 500_000);
    }

    #[test]
    fn gate_order_matches_tag_30() {
        let base = GateInputs {
            recovery_mode: 0,
            now: 1_000,
            last_harvest_ts: 0,
            t_min_secs: 1_000,
            max_buyback_backlog: 10,
            buyback_usdc: 10,
            cooldown_slots: 0,
            last_deposit_slot: 0,
            slot: 50,
            queue: QueueState::UNPARSED,
        };
        assert_eq!(early_gate(&base), HarvestStatus::Ready);
        let all_bad = GateInputs {
            recovery_mode: 1,
            now: 999,
            buyback_usdc: 11,
            cooldown_slots: 10,
            last_deposit_slot: 41,
            queue: QueueState { parsed: true, q_perm: 1, q_tmp: 1, total_queued: 1 },
            ..base
        };
        let mut g = all_bad;
        assert_eq!(early_gate(&g), HarvestStatus::Recovery);
        g.recovery_mode = 0;
        assert_eq!(early_gate(&g), HarvestStatus::TooEarly);
        g.now = 1_000;
        assert_eq!(early_gate(&g), HarvestStatus::BuybackBacklog);
        g.max_buyback_backlog = 0; // gate disabled
        assert_eq!(early_gate(&g), HarvestStatus::Cooldown);
        g.last_deposit_slot = 40; // 40 + 10 = 50 = slot: open
        assert_eq!(early_gate(&g), HarvestStatus::QueueBusy);
        g.queue.total_queued = 0;
        assert_eq!(early_gate(&g), HarvestStatus::Ready);
        // Saturation keeps gates closed.
        let g = GateInputs { last_harvest_ts: i64::MAX, now: i64::MAX - 1, ..base };
        assert_eq!(early_gate(&g), HarvestStatus::TooEarly);
        let g = GateInputs { cooldown_slots: u64::MAX, last_deposit_slot: 5, slot: u64::MAX - 1, ..base };
        assert_eq!(early_gate(&g), HarvestStatus::Cooldown);
        assert_eq!(g.cooldown_until_slot(), u64::MAX);
        assert_eq!(base.cooldown_until_slot(), 0);
        // Status → error mapping.
        assert_eq!(HarvestStatus::Recovery.error(), Some(SijkaError::RecoveryActive));
        assert_eq!(HarvestStatus::BuybackBacklog.code(), 5, "code 4 (Paused) stays retired");
        assert_eq!(HarvestStatus::Ready.check(), Ok(()));
        assert_eq!(HarvestStatus::MarkStale.code(), 8);
    }

    /// DECISIONS §23 item 7: the first harvest right after `initialize`, the
    /// second only after `T_min`; a `timer_held` first harvest (RT-5) keeps
    /// the next one open.
    #[test]
    fn first_harvest_right_after_initialize() {
        let created = 1_800_000_000i64;
        let p = Payout { d: 100, r: 100, u: 100, creator: 20, buyback: 80 };
        for t_min in [0u32, 1, 3_600, 604_800, u32::MAX] {
            let anchor = initial_last_harvest_ts(created, t_min).unwrap();
            let g = GateInputs {
                recovery_mode: 0,
                now: created,
                last_harvest_ts: anchor,
                t_min_secs: t_min,
                max_buyback_backlog: 0,
                buyback_usdc: 0,
                cooldown_slots: 0,
                last_deposit_slot: 0,
                slot: 0,
                queue: QueueState::UNPARSED,
            };
            assert_eq!(g.next_allowed_ts(), created);
            assert_eq!(early_gate(&g), HarvestStatus::Ready, "t_min {t_min}: first harvest at created_ts");
            // The first harvest moves the timer: the second waits T_min.
            let l = Ledger { last_harvest_ts: anchor, ..Ledger::default() };
            let now = created + 5;
            let n = l.apply(&p, false, now, 1).unwrap();
            assert_eq!(n.last_harvest_ts, now);
            let g2 = GateInputs { now, last_harvest_ts: n.last_harvest_ts, ..g };
            let wait = i64::from(t_min);
            let early = if t_min > 0 { HarvestStatus::TooEarly } else { HarvestStatus::Ready };
            assert_eq!(early_gate(&g2), early, "t_min {t_min}: second harvest right away");
            if t_min > 0 {
                assert_eq!(early_gate(&GateInputs { now: now + wait - 1, ..g2 }), HarvestStatus::TooEarly);
            }
            assert_eq!(early_gate(&GateInputs { now: now + wait, ..g2 }), HarvestStatus::Ready);
            // RT-5: a held first harvest does not use up the open gate.
            let h = l.apply(&p, true, now, 1).unwrap();
            assert_eq!((h.last_harvest_ts, h.harvest_count), (anchor, 1));
            assert_eq!(early_gate(&GateInputs { now, last_harvest_ts: h.last_harvest_ts, ..g }), HarvestStatus::Ready);
        }
        assert_eq!(initial_last_harvest_ts(i64::MIN, 1), Err(SijkaError::MathOverflow));
        assert_eq!(initial_last_harvest_ts(i64::MIN + 604_800, 604_800), Ok(i64::MIN));
        assert_eq!(initial_last_harvest_ts(0, u32::MAX), Ok(-i64::from(u32::MAX)));
    }

    #[test]
    fn preview_status_order() {
        let pb = params(0, 10, 0, u64::MAX, 0);
        let p = HarvestParams::from_array(&pb);
        let g = GateInputs {
            recovery_mode: 0,
            now: 0,
            last_harvest_ts: 0,
            t_min_secs: 0,
            max_buyback_backlog: 0,
            buyback_usdc: 0,
            cooldown_slots: 0,
            last_deposit_slot: 0,
            slot: 0,
            queue: QueueState::UNPARSED,
        };
        let mut m = margin(100, 0, 0, 100, 100, 0);
        let calc = compute_harvest(&m, 100, 95, &p, u64::MAX, u64::MAX).unwrap();
        assert_eq!(preview_status(&g, 0, &m, &calc, 10), HarvestStatus::BelowMinimum);
        m.risk_tier = 1;
        assert_eq!(preview_status(&g, 0, &m, &calc, 10), HarvestStatus::RiskState);
        assert_eq!(preview_status(&g, 1, &m, &calc, 10), HarvestStatus::MarkStale);
        let gr = GateInputs { recovery_mode: 1, ..g };
        assert_eq!(preview_status(&gr, 1, &m, &calc, 10), HarvestStatus::Recovery);
        m.risk_tier = 0;
        let calc = compute_harvest(&m, 100, 0, &p, u64::MAX, u64::MAX).unwrap();
        assert_eq!(preview_status(&g, 0, &m, &calc, 10), HarvestStatus::Ready);
        m.is_liquidatable = 1;
        assert_eq!(preview_status(&g, 0, &m, &calc, 10), HarvestStatus::RiskState);
    }

    #[test]
    fn arrival_checks() {
        // Withdraw: exact; any holdback (SPEC v4: no tolerance, even 99%);
        // nothing; too much; decrease.
        assert_eq!(check_withdraw_arrival(5, 105, 100), Ok(100));
        assert_eq!(check_withdraw_arrival(5, 95, 100), Ok(90));
        assert_eq!(check_withdraw_arrival(5, 6, 100), Ok(1));
        assert_eq!(check_withdraw_arrival(5, 5, 100), Err(SijkaError::WithdrawNotImmediate));
        assert_eq!(check_withdraw_arrival(5, 106, 100), Err(SijkaError::WithdrawAmountMismatch));
        assert_eq!(check_withdraw_arrival(5, 4, 100), Err(SijkaError::InvariantViolated));
        // Step 13a: nothing queued (the before state is empty: WithdrawQueueBusy
        // stops a busy queue earlier); an unrecognised header is not checked.
        let q = |parsed: bool, total_queued: u64| QueueState { parsed, q_perm: 9, q_tmp: 9, total_queued };
        assert_eq!(check_nothing_queued(&q(true, 0), &q(true, 0)), Ok(()));
        assert_eq!(check_nothing_queued(&q(true, 0), &q(true, 1)), Err(SijkaError::WithdrawNotImmediate));
        assert_eq!(check_nothing_queued(&q(true, 0), &QueueState::UNPARSED), Err(SijkaError::WithdrawNotImmediate));
        assert_eq!(check_nothing_queued(&q(true, 3), &q(true, 2)), Ok(()));
        assert_eq!(check_nothing_queued(&QueueState::UNPARSED, &q(true, 5)), Ok(()));
        assert_eq!(check_nothing_queued(&QueueState::UNPARSED, &QueueState::UNPARSED), Ok(()));
        // Ember: donated PhUSD (7) stays; 0 < u ≤ r, any holdback r − u.
        assert_eq!(check_ember_arrival(7, 7, 3, 103, 100), Ok(100));
        assert_eq!(check_ember_arrival(7, 7, 3, 93, 100), Ok(90));
        assert_eq!(check_ember_arrival(7, 7, 3, 4, 100), Ok(1));
        // Some(r) must take exactly r PhUSD: the vault_phusd balance is back.
        assert_eq!(check_ember_arrival(7, 6, 3, 103, 100), Err(SijkaError::EmberAmountMismatch));
        assert_eq!(check_ember_arrival(7, 8, 3, 103, 100), Err(SijkaError::EmberAmountMismatch));
        assert_eq!(check_ember_arrival(7, 7, 3, 3, 100), Err(SijkaError::EmberAmountMismatch));
        assert_eq!(check_ember_arrival(7, 7, 3, 104, 100), Err(SijkaError::EmberAmountMismatch));
        assert_eq!(check_ember_arrival(7, 7, 3, 2, 100), Err(SijkaError::EmberAmountMismatch));
    }

    /// PAM with `slots_used` entries; entry `s` gets `asset_id = s | hi<<16`,
    /// `mark.slot = marks[s]`.
    fn pam_bytes(marks: &[u64], hi: u16) -> Vec<u8> {
        use crate::constants::{DISC_PAM, PAM_ENTRY, PAM_HEADER};
        let cap = marks.len().max(1);
        let mut d = vec![0u8; PAM_HEADER + cap * PAM_ENTRY];
        d[0..8].copy_from_slice(&DISC_PAM);
        d[32..36].copy_from_slice(&(marks.len() as u32).to_le_bytes());
        d[40..48].copy_from_slice(&(cap as u64).to_le_bytes());
        for (s, m) in marks.iter().enumerate() {
            let e = PAM_HEADER + s * PAM_ENTRY;
            d[e + 32..e + 40].copy_from_slice(&m.to_le_bytes());
            d[e + 960..e + 962].copy_from_slice(&(s as u16).to_le_bytes());
            d[e + 964..e + 966].copy_from_slice(&hi.to_le_bytes());
        }
        d
    }

    /// Trader data with position records `(asset_index, base)`.
    fn trader_bytes(records: &[(u64, i64)]) -> Vec<u8> {
        let cap = records.len().max(1);
        let mut d = vec![0u8; 240 + 40 * cap];
        d[224..232].copy_from_slice(&(records.len() as u64).to_le_bytes());
        d[232..240].copy_from_slice(&(cap as u64).to_le_bytes());
        for (j, (idx, base)) in records.iter().enumerate() {
            let o = 240 + 40 * j;
            d[o..o + 8].copy_from_slice(&idx.to_le_bytes());
            d[o + 8..o + 16].copy_from_slice(&base.to_le_bytes());
        }
        d
    }

    #[test]
    fn position_mark_scan() {
        let pam = pam_bytes(&[1_000, 850, 990], 0);
        // Fresh positions (age ≤ 150), a flat record, the native-SOL extension.
        let t = trader_bytes(&[(0, 5), (2, -3), (1, 0), (0xFFFF_0000, 77)]);
        let s = scan_position_marks(&t, &pam, 1_000, 150).unwrap();
        assert_eq!(s, MarkScan { positions: 2, stale: 0, first_failure: None, records: 3, flat_stale: 0 });
        // Age 151 is stale; age exactly 150 is not.
        let t = trader_bytes(&[(1, 1)]);
        assert_eq!(scan_position_marks(&t, &pam, 1_000, 150).unwrap().first_failure, None);
        assert_eq!(
            scan_position_marks(&t, &pam, 1_001, 150).unwrap().first_failure,
            Some(SijkaError::HarvestMarkStale)
        );
        // Mark in the future: age 0.
        assert_eq!(scan_position_marks(&t, &pam, 10, 150).unwrap().stale, 0);
        // Unresolved: slot beyond slots_used, or another asset generation.
        let t = trader_bytes(&[(0, 1), (3, 1), (1, 1)]);
        let s = scan_position_marks(&t, &pam, 1_001, 150).unwrap();
        assert_eq!((s.positions, s.stale), (3, 2));
        assert_eq!(s.first_failure, Some(SijkaError::PositionAssetUnresolved));
        let t = trader_bytes(&[(1, 1), (0x0001_0000, 1)]); // stale first, then wrong generation
        let s = scan_position_marks(&t, &pam, 1_001, 150).unwrap();
        assert_eq!(s.first_failure, Some(SijkaError::HarvestMarkStale));
        assert_eq!(s.stale, 2);
        // Only the low 32 bits of asset_index are used.
        let t = trader_bytes(&[(0xABCD_0000_0000_0002, 4)]);
        assert_eq!(scan_position_marks(&t, &pam, 1_000, 150).unwrap().positions, 1);
        // A record past the data is a trader error, not a silent skip.
        let mut t = trader_bytes(&[(0, 1)]);
        t[224..232].copy_from_slice(&2u64.to_le_bytes());
        assert_eq!(scan_position_marks(&t, &pam, 1_000, 150), Err(SijkaError::InvalidPhoenixTraderAccount));
        assert_eq!(scan_position_marks(&t[..100], &pam, 1_000, 150), Err(SijkaError::InvalidPhoenixTraderAccount));
        assert_eq!(scan_position_marks(&trader_bytes(&[]), &pam[..20], 1, 1), Err(SijkaError::InvalidPerpAssetMap));
    }

    /// Step 8a (RT-3, FA-4): flat records are counted and aged; `hidden_stale`
    /// counts every stale flat record and every market Hawkeye counts beyond
    /// the map's records.
    #[test]
    fn flat_records_and_hidden_positions() {
        // Marks: slot 0 fresh, slot 1 old (age 151 at slot 1 001), slot 2 fresh.
        let pam = pam_bytes(&[1_000, 850, 990], 0);
        // Position on 0, flat records on 1 (stale) and 2 (fresh), an
        // unresolved flat record (slot 3), the native-SOL extension.
        let t = trader_bytes(&[(0, 5), (1, 0), (2, 0), (3, 0), (0xFFFF_0000, 9)]);
        let s = scan_position_marks(&t, &pam, 1_001, 150).unwrap();
        assert_eq!(
            s,
            MarkScan { positions: 1, stale: 0, first_failure: None, records: 4, flat_stale: 1 },
            "flat records never fail step 6; the unresolved one is not stale"
        );
        // pc ≤ n_scan (FA-4): the map's position may already be closed in the
        // ATB while the stale flat record hides the live one: still stale.
        assert_eq!(s.hidden_stale(0), 1);
        assert_eq!(s.hidden_stale(1), 1);
        // pc > n_scan: the stale flat record may hide a position.
        assert_eq!(s.hidden_stale(2), 1);
        assert_eq!(s.hidden_stale(4), 1);
        // pc > n_rec: a market the map has no record for.
        assert_eq!(s.hidden_stale(5), 2);
        assert_eq!(s.hidden_stale(u16::MAX), 1 + u32::from(u16::MAX) - 4);
        // All flat marks fresh: only pc > n_rec counts.
        let s = scan_position_marks(&t, &pam, 1_000, 150).unwrap();
        assert_eq!((s.flat_stale, s.hidden_stale(4), s.hidden_stale(6)), (0, 0, 2));
        // No records at all (flat, synced map): any pc is unseen.
        let s = scan_position_marks(&trader_bytes(&[]), &pam, 1_000, 150).unwrap();
        assert_eq!((s.records, s.hidden_stale(0), s.hidden_stale(1)), (0, 0, 1));
        // A flat record of an old asset generation does not resolve: not stale.
        let t = trader_bytes(&[(0x0001_0001, 0)]);
        assert_eq!(scan_position_marks(&t, &pam, 1_001, 150).unwrap().flat_stale, 0);
    }

    #[test]
    fn ledger_update() {
        let l = Ledger { last_harvest_ts: 7, ..Ledger::default() };
        let p = Payout { d: 100, r: 99, u: 98, creator: 19, buyback: 79 };
        let n = l.apply(&p, false, 1_000, 55).unwrap();
        assert_eq!(n.o, 98);
        assert_eq!((n.cum_payout_creator, n.cum_payout_buyback), (19, 79));
        assert_eq!(n.cum_withdraw_fees, 2);
        assert_eq!(n.harvest_count, 1);
        assert_eq!((n.last_harvest_ts, n.last_harvest_slot, n.last_harvest_amount), (1_000, 55, 98));
        // Timer held: last_harvest_ts unchanged, everything else moves.
        let h = l.apply(&p, true, 1_000, 55).unwrap();
        assert_eq!(h.last_harvest_ts, 7);
        assert_eq!(h.o, 98);
        // Inconsistent payouts.
        for bad in [
            Payout { creator: 20, ..p },
            Payout { u: 0, creator: 0, buyback: 0, ..p },
            Payout { r: 97, ..p },
            Payout { d: 98, r: 99, ..p },
        ] {
            assert_eq!(l.apply(&bad, false, 0, 0), Err(SijkaError::InvariantViolated));
        }
        // Pre-existing broken invariant is caught.
        let broken = Ledger { o: 1, ..Ledger::default() };
        assert_eq!(broken.apply(&p, false, 0, 0), Err(SijkaError::InvariantViolated));
        // Overflow.
        let full = Ledger { o: u64::MAX, cum_payout_buyback: u64::MAX, ..Ledger::default() };
        assert_eq!(full.apply(&p, false, 0, 0), Err(SijkaError::MathOverflow));
    }
}
