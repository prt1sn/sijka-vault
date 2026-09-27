// Copyright (c) 2026 prt1sn. All rights reserved.
//! Buyback math without floating point (SPEC §5.5.2): price in Q64.64,
//! the clamped EMA, the observation step (with the warm-up rule of review
//! RT-8), chunk sizing (reviews ACC-13, RT-6; SPEC v4: no spot guard, the
//! chunks are keeper-signed and the keeper's `min_out` is the only price
//! limit, DECISIONS §23 items 3 and 6), and the volume-proportional cool-downs.
//!
//! Everything here is pure and returns a bare [`SijkaError`]; handlers log it
//! once with `.map_err(SijkaError::fail)`.

use crate::constants::{BPS, DT_MAX_S, EMA_TAU_S, MAX_QUOTE_RESERVE, MIN_BASE_RESERVE, OBS_MAX_GAP_S};
use crate::error::SijkaError;

const OVERFLOW: SijkaError = SijkaError::MathOverflow;
/// `BPS` widened to u128 (lossless: u64 → u128; `From` is not const).
const BPS_128: u128 = BPS as u128;

#[inline]
fn mul(a: u128, b: u128) -> Result<u128, SijkaError> {
    a.checked_mul(b).ok_or(OVERFLOW)
}

#[inline]
fn div(a: u128, b: u128) -> Result<u128, SijkaError> {
    a.checked_div(b).ok_or(OVERFLOW)
}

/// `⌈a / b⌉`; `b == 0` is `MathOverflow`.
#[inline]
pub fn div_ceil(a: u128, b: u128) -> Result<u128, SijkaError> {
    let q = a.checked_div(b).ok_or(OVERFLOW)?;
    let r = a.checked_rem(b).ok_or(OVERFLOW)?;
    if r == 0 { Ok(q) } else { q.checked_add(1).ok_or(OVERFLOW) }
}

#[inline]
fn to_u64(x: u128) -> Result<u64, SijkaError> {
    u64::try_from(x).map_err(|_| OVERFLOW)
}

/// `x · 2^64`, failing instead of losing high bits.
#[inline]
fn shl64(x: u128) -> Result<u128, SijkaError> {
    if x > u128::from(u64::MAX) {
        return Err(OVERFLOW);
    }
    Ok(x << 64)
}

/// `price_x64(q, b)`: atoms of quote per atom of SIJKA in Q64.64.
/// `b ≥ MIN_BASE_RESERVE` and `1 ≤ q ≤ MAX_QUOTE_RESERVE`, else
/// `BbReserveAnomaly`. The result is `≥ 1` and `< 2^108`.
pub fn price_x64(q: u64, b: u64) -> Result<u128, SijkaError> {
    if b < MIN_BASE_RESERVE || q == 0 || q > MAX_QUOTE_RESERVE {
        return Err(SijkaError::BbReserveAnomaly);
    }
    // q < 2^63, so q·2^64 < 2^127 fits.
    div(shl64(u128::from(q))?, u128::from(b))
}

/// `ema_step(ema, x, dt, clamp_bps)` (SPEC §5.5.2): the observation is clamped
/// into `[ema·(1 − c), ema·(1 + c)]`, then the EMA moves toward it with weight
/// `min(dt, DT_MAX_S) / EMA_TAU_S` (rounded down in both directions).
/// Returns the new EMA and whether `x` was clamped.
pub fn ema_step(ema: u128, x: u128, dt: u64, clamp_bps: u16) -> Result<(u128, bool), SijkaError> {
    let c = u128::from(clamp_bps);
    let lo = div(mul(ema, BPS_128.checked_sub(c).ok_or(OVERFLOW)?)?, BPS_128)?;
    let hi = div(mul(ema, BPS_128.checked_add(c).ok_or(OVERFLOW)?)?, BPS_128)?;
    let (xi, clamped) = if x < lo {
        (lo, true)
    } else if x > hi {
        (hi, true)
    } else {
        (x, false)
    };
    let w = u128::from(dt.min(DT_MAX_S));
    let tau = u128::from(EMA_TAU_S);
    let next = if xi >= ema {
        let up = div(mul(xi.checked_sub(ema).ok_or(OVERFLOW)?, w)?, tau)?;
        ema.checked_add(up).ok_or(OVERFLOW)?
    } else {
        let down = div(mul(ema.checked_sub(xi).ok_or(OVERFLOW)?, w)?, tau)?;
        ema.checked_sub(down).ok_or(OVERFLOW)?
    };
    Ok((next, clamped))
}

/// Observation state before a `bb_observe` (SPEC §3.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObsPrev {
    /// `flags & OBS_INIT`.
    pub init: bool,
    pub ema: u128,
    pub q_ema: u64,
    pub fresh_obs: u16,
    pub last_obs_ts: i64,
}

/// Observation state after a `bb_observe`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObsNext {
    pub ema: u128,
    pub q_ema: u64,
    pub fresh_obs: u16,
    /// Event `clamped`: bit0 price, bit1 Q.
    pub clamped: u8,
}

/// One observation (SPEC §5.5.2 `observe`, review RT-8):
///
/// - first observation (`!OBS_INIT`): `ema = p`, `q_ema = q`, `fresh_obs = 1`;
/// - otherwise `dt = now − last_obs_ts` (the caller has checked `dt ≥ 15`),
///   `fresh_obs = dt > OBS_MAX_GAP_S ? 1 : fresh_obs + 1` (saturating), both
///   EMAs step with the clamp, and during warm-up (`fresh_obs < warmup_obs`)
///   they may fall freely but rise only through the clamp:
///   `ema = min(e1, p)`, `q_ema = min(q1, q)`.
///
/// The EMA is never reset after a gap: a gap only restarts the warm-up.
pub fn observe_step(
    prev: &ObsPrev,
    now: i64,
    p: u128,
    q: u64,
    clamp_bps: u16,
    warmup_obs: u16,
) -> Result<ObsNext, SijkaError> {
    if !prev.init {
        return Ok(ObsNext { ema: p, q_ema: q, fresh_obs: 1, clamped: 0 });
    }
    let dt_signed = now.checked_sub(prev.last_obs_ts).ok_or(OVERFLOW)?;
    let dt = u64::try_from(dt_signed).map_err(|_| OVERFLOW)?;
    let fresh_obs = if dt_signed > OBS_MAX_GAP_S { 1 } else { prev.fresh_obs.saturating_add(1) };
    let (e1, pc) = ema_step(prev.ema, p, dt, clamp_bps)?;
    let (q1, qc) = ema_step(u128::from(prev.q_ema), u128::from(q), dt, clamp_bps)?;
    let q1 = to_u64(q1)?;
    let (ema, q_ema) = if fresh_obs < warmup_obs { (e1.min(p), q1.min(q)) } else { (e1, q1) };
    let clamped = u8::from(pc) | (u8::from(qc) << 1);
    Ok(ObsNext { ema, q_ema, fresh_obs, clamped })
}

/// Bonding-curve reserves used to clamp a chunk (SPEC §5.5.2, review ACC-13).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CurveReserves {
    /// `vT`.
    pub virtual_token: u64,
    /// `vQ`.
    pub virtual_quote: u64,
    /// `R = real_token_reserves`.
    pub real_token: u64,
}

/// `v_max = ⌊(R − 1)·vQ / (vT − R + 1)⌋` (saturated to u64): the largest spend
/// whose fee-free output `t0 = v·vT/(vQ + v)` stays `≤ R − 1`, so our chunk
/// never takes the last tokens of the curve. Needs `R ≥ 2`
/// (`BbCurveNearComplete`) and `vT ≥ R` (`BbReserveAnomaly`).
pub fn curve_v_max(c: &CurveReserves) -> Result<u64, SijkaError> {
    if c.real_token < 2 {
        return Err(SijkaError::BbCurveNearComplete);
    }
    if c.virtual_token < c.real_token {
        return Err(SijkaError::BbReserveAnomaly);
    }
    let r1 = c.real_token.checked_sub(1).ok_or(OVERFLOW)?;
    let den = c.virtual_token.checked_sub(c.real_token).and_then(|x| x.checked_add(1)).ok_or(OVERFLOW)?;
    // (2^64 − 1)^2 < 2^128: the product always fits.
    let v = div(mul(u128::from(r1), u128::from(c.virtual_quote))?, u128::from(den))?;
    Ok(u64::try_from(v).unwrap_or(u64::MAX))
}

/// Fee-free curve output `t0 = ⌊v·vT / (vQ + v)⌋`.
pub fn curve_t0(v: u64, c: &CurveReserves) -> Result<u128, SijkaError> {
    let den = u128::from(c.virtual_quote).checked_add(u128::from(v)).ok_or(OVERFLOW)?;
    div(mul(u128::from(v), u128::from(c.virtual_token))?, den)
}

/// Everything [`plan_chunk`] needs (tags 44 and 45).
#[derive(Clone, Copy, Debug)]
pub struct ChunkInputs {
    // Observation state (BuybackState).
    pub obs_init: bool,
    pub fresh_obs: u16,
    pub last_obs_ts: i64,
    pub last_obs_slot: u64,
    pub ema: u128,
    pub last_obs_price: u128,
    pub last_obs_quote: u64,
    pub q_ema: u64,
    pub next_buy_ts: i64,
    pub last_buy_slot: u64,
    // Parameters (BuybackParams).
    pub warmup_obs: u16,
    pub obs_max_age_s: u32,
    pub chunk_bps: u16,
    pub chunk_max_quote: u64,
    pub chunk_min_quote: u64,
    // Live market: quote reserve (curve: `vQ`; PumpSwap:
    // `pool_quote_ta + virtual_quote_reserves`).
    pub now: i64,
    pub slot: u64,
    pub q_now: u64,
    /// `Some` on the bonding curve (tag 44): clamp `v ≤ v_max` and check `t0`.
    pub curve: Option<CurveReserves>,
    // Budget.
    pub avail: u64,
    /// USDC pair: `lamports(k0) ≥ rent(0)` (else `BbFloatLow`, audit EA-1); always `true` on the SOL pair.
    pub float_ok: bool,
    // Keeper arguments (SPEC v4: tags 44 and 45 are keeper-signed). `max_quote_in`
    // can only shrink `v`; `min_out_keeper` is the keeper's floor (its quote at
    // the live price minus its slippage), the only price limit of the chunk.
    pub max_quote_in: u64,
    pub min_out_keeper: u64,
}

/// Result of [`plan_chunk`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChunkPlan {
    /// Spend of this chunk.
    pub v: u64,
    /// Full chunk `min(⌊Q_ref·chunk_bps/10⁴⌋, chunk_max_quote)` (cool-down base, RT-6).
    pub v_cap: u64,
    /// The keeper's `min_out` (≥ 1): the floor passed to pump and checked on
    /// the balance after the CPI (SPEC v4, DECISIONS §23 item 6).
    pub min_out: u64,
    /// `min(ema, last_obs_price)`: information for the event only (SPEC v4:
    /// no spot guard).
    pub p_ref: u128,
    pub q_ref: u64,
}

/// Chunk sizing and `min_out` (SPEC §5.5.2; SPEC v4 without the spot guard),
/// in this order:
///
/// 1. `OBS_INIT ∧ fresh_obs ≥ warmup_obs` (`BbWarmup`);
/// 2. `slot > last_obs_slot` (`BbSameSlot`);
/// 3. `now − last_obs_ts ≤ obs_max_age_s` (`BbStaleObservation`);
/// 4. `now ≥ next_buy_ts ∧ slot > last_buy_slot` (`BbBuyTooSoon`, RT-6);
/// 5. `Q_ref = min(q_now, last_obs_quote, q_ema)`;
/// 6. float (`BbFloatLow`, USDC pair);
/// 7. curve: `v_max` (ACC-13); AMM: no clamp;
/// 8. `v_cap = min(⌊Q_ref·chunk_bps/10⁴⌋, chunk_max_quote)`,
///    `v = min(avail, v_cap, max_quote_in (0 = none), v_max)`,
///    `v ≥ v_min = max(min(chunk_min_quote, v_cap), 1)` else
///    `BbCurveNearComplete` if `v_max` is the reason, `BbChunkBelowMin`
///    otherwise. The floor never exceeds the full chunk (audit v4 round 2,
///    AR2-10): a pool with `Q_ref·chunk_bps/10⁴ < chunk_min_quote` (below
///    10 SOL on the SOL pair) still gets its 10 bps chunk instead of every
///    chunk failing for good (`BuybackParams` are fixed since SPEC v4);
/// 9. `min_out = min_out_keeper ≥ 1` (`BbExpectedOutBelowMin`; SPEC v4: no
///    program-side floor from the pump fees, whatever pump charges is paid,
///    the keeper's quote bounds the price);
/// 10. curve: `t0 < R` (`BbCurveNearComplete`; holds by construction).
pub fn plan_chunk(i: &ChunkInputs) -> Result<ChunkPlan, SijkaError> {
    if !i.obs_init || i.fresh_obs < i.warmup_obs {
        return Err(SijkaError::BbWarmup);
    }
    if i.slot <= i.last_obs_slot {
        return Err(SijkaError::BbSameSlot);
    }
    let age = i.now.checked_sub(i.last_obs_ts).ok_or(OVERFLOW)?;
    if age > i64::from(i.obs_max_age_s) {
        return Err(SijkaError::BbStaleObservation);
    }
    if i.now < i.next_buy_ts || i.slot <= i.last_buy_slot {
        return Err(SijkaError::BbBuyTooSoon);
    }
    let p_ref = i.ema.min(i.last_obs_price);
    let q_ref = i.q_now.min(i.last_obs_quote).min(i.q_ema);
    if !i.float_ok {
        return Err(SijkaError::BbFloatLow);
    }
    let v_max = match &i.curve {
        Some(c) => curve_v_max(c)?,
        None => u64::MAX,
    };
    let v_rel = to_u64(div(mul(u128::from(q_ref), u128::from(i.chunk_bps))?, BPS_128)?)?;
    let v_cap = v_rel.min(i.chunk_max_quote);
    let arg_cap = if i.max_quote_in == 0 { u64::MAX } else { i.max_quote_in };
    let v = i.avail.min(v_cap).min(arg_cap).min(v_max);
    // AR2-10: the absolute floor never exceeds the full chunk. Dust below
    // v_cap (budget or max_quote_in) is still refused.
    let v_min = i.chunk_min_quote.min(v_cap).max(1);
    if v < v_min {
        return Err(if v_max < v_min { SijkaError::BbCurveNearComplete } else { SijkaError::BbChunkBelowMin });
    }
    let min_out = i.min_out_keeper;
    if min_out == 0 {
        return Err(SijkaError::BbExpectedOutBelowMin);
    }
    if let Some(c) = &i.curve
        && curve_t0(v, c)? >= u128::from(c.real_token)
    {
        return Err(SijkaError::BbCurveNearComplete);
    }
    Ok(ChunkPlan { v, v_cap, min_out, p_ref, q_ref })
}

/// Volume-proportional cool-down (review RT-6):
/// `now + ⌈interval_s · used / full⌉`. `full == 0` is `MathOverflow`.
pub fn next_ts(now: i64, interval_s: u32, used: u64, full: u64) -> Result<i64, SijkaError> {
    let wait = div_ceil(mul(u128::from(interval_s), u128::from(used))?, u128::from(full))?;
    let wait = i64::try_from(wait).map_err(|_| OVERFLOW)?;
    now.checked_add(wait).ok_or(OVERFLOW)
}

/// Settlement of a curve chunk on the SOL pair (SPEC §5.5.2): the quote is
/// lamports of `buyback_authority`. `spent_total = lam_before − lam_after`
/// (saturating: an increase is not a loss) must be `≤ v + max_rent_extra`
/// (`BbOverspend`); returns `(quote_spent = min(spent_total, v), rent_extra)`.
pub fn settle_sol_curve(
    v: u64,
    lam_before: u64,
    lam_after: u64,
    max_rent_extra: u64,
) -> Result<(u64, u64), SijkaError> {
    let spent_total = lam_before.saturating_sub(lam_after);
    let limit = v.checked_add(max_rent_extra).ok_or(OVERFLOW)?;
    if spent_total > limit {
        return Err(SijkaError::BbOverspend);
    }
    let quote_spent = spent_total.min(v);
    let rent = spent_total.checked_sub(quote_spent).ok_or(OVERFLOW)?;
    Ok((quote_spent, rent))
}

/// Settlement when the quote is a token account (SOL / AMM via `bb_wsol`, USDC
/// pair): `quote_spent = q_before − q_after ≤ v`, `rent = lam_before −
/// lam_after ≤ max_rent_extra` (both saturating), else `BbOverspend`.
pub fn settle_token_quote(
    v: u64,
    q_before: u64,
    q_after: u64,
    lam_before: u64,
    lam_after: u64,
    max_rent_extra: u64,
) -> Result<(u64, u64), SijkaError> {
    let quote_spent = q_before.saturating_sub(q_after);
    let rent = lam_before.saturating_sub(lam_after);
    if quote_spent > v || rent > max_rent_extra {
        return Err(SijkaError::BbOverspend);
    }
    Ok((quote_spent, rent))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    const X64: u128 = 1u128 << 64;

    /// Deterministic xorshift64* for property loops (no proptest on this host).
    pub struct Rng(u64);
    impl Rng {
        pub fn new(seed: u64) -> Self {
            Self(seed.max(1))
        }
        pub fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
            lo + self.next() % (hi - lo + 1)
        }
    }

    // ---- pump exact-quote-in formulas (note 07 §1.4 / §2.3, IDL docs of
    // `buy_exact_sol_in`; verified to the unit on-chain for v2 by the verifier).

    /// `net` after fees: `⌊q·10⁴/(10⁴ + Σfees)⌋`, fees `⌈net·f/10⁴⌉` each, shaved
    /// if `net + fees > q`.
    pub fn pump_net(spendable: u64, fees: &[u64]) -> u64 {
        let total: u64 = fees.iter().sum();
        let mut net = (u128::from(spendable) * 10_000 / u128::from(10_000 + total)) as u64;
        let fee_sum: u64 = fees.iter().map(|f| (u128::from(net) * u128::from(*f)).div_ceil(10_000) as u64).sum();
        if net + fee_sum > spendable {
            net -= net + fee_sum - spendable;
        }
        net
    }

    /// Curve `buy_exact_quote_in_v2`: `⌊(net − 1)·vT / (vQ + net − 1)⌋`.
    pub fn pump_curve_out(spendable: u64, vt: u64, vq: u64, protocol: u64, creator: u64) -> u64 {
        let net = pump_net(spendable, &[protocol, creator]);
        let n1 = u128::from(net - 1);
        (n1 * u128::from(vt) / (u128::from(vq) + n1)) as u64
    }

    /// PumpSwap `buy_exact_quote_in`: `⌊B·(net − 1) / (Q + net − 1)⌋`.
    pub fn pump_amm_out(spendable: u64, b: u64, q: u64, lp: u64, protocol: u64, creator: u64) -> u64 {
        let net = pump_net(spendable, &[lp, protocol, creator]);
        let n1 = u128::from(net - 1);
        (u128::from(b) * n1 / (u128::from(q) + n1)) as u64
    }

    #[test]
    fn pump_formula_matches_verifier_simulations() {
        // Note 07, verifier §2: T1 (USDC, 1e6) net = 987 654, no shave;
        // T2 (SOL, 1e7) net = 9 876 543 → shave by 1 → 9 876 542.
        assert_eq!(pump_net(1_000_000, &[95, 30]), 987_654);
        assert_eq!(pump_net(10_000_000, &[95, 30]), 9_876_542);
        // Monotone in the spend and bounded by the reserves.
        let (vt, vq) = (1_073_000_000_000_000u64, 30_000_000_000u64);
        let a = pump_curve_out(10_000_000, vt, vq, 95, 30);
        let b = pump_curve_out(20_000_000, vt, vq, 95, 30);
        assert!(a > 0 && b > a && b < vt);
        // PumpSwap: three fee components, same shape; lower fees give more.
        let (pb, pq) = (500_000_000_000_000u64, 100_000_000_000u64);
        let hi_fee = pump_amm_out(10_000_000, pb, pq, 2, 93, 30);
        let lo_fee = pump_amm_out(10_000_000, pb, pq, 20, 5, 5);
        assert!(hi_fee > 0 && lo_fee > hi_fee && lo_fee < pb);
    }

    #[test]
    fn price_x64_bounds() {
        assert_eq!(price_x64(1, MIN_BASE_RESERVE), Ok(X64 / u128::from(MIN_BASE_RESERVE)));
        assert_eq!(
            price_x64(30_000_000_000, 1_073_000_000_000_000),
            Ok((30_000_000_000u128 << 64) / 1_073_000_000_000_000)
        );
        assert_eq!(price_x64(0, MIN_BASE_RESERVE), Err(SijkaError::BbReserveAnomaly));
        assert_eq!(price_x64(1, MIN_BASE_RESERVE - 1), Err(SijkaError::BbReserveAnomaly));
        assert_eq!(price_x64(MAX_QUOTE_RESERVE + 1, MIN_BASE_RESERVE), Err(SijkaError::BbReserveAnomaly));
        let top = price_x64(MAX_QUOTE_RESERVE, MIN_BASE_RESERVE).unwrap();
        assert!(top < 1u128 << 108);
        assert!(price_x64(1, u64::MAX).unwrap() >= 1);
    }

    #[test]
    fn ema_step_clamp_weight_direction() {
        let e = 1_000_000u128 * X64;
        // Inside the clamp: moves by (x − e)·w/600.
        assert_eq!(ema_step(e, e + 600 * X64, 60, 1_000), Ok((e + 60 * X64, false)));
        assert_eq!(ema_step(e, e - 600 * X64, 60, 1_000), Ok((e - 60 * X64, false)));
        // dt above DT_MAX_S weighs as 60 s.
        assert_eq!(ema_step(e, e + 600 * X64, 3_600, 1_000), ema_step(e, e + 600 * X64, 60, 1_000));
        // dt 15 s: quarter of the weight.
        assert_eq!(ema_step(e, e + 600 * X64, 15, 1_000), Ok((e + 15 * X64, false)));
        // ×3 spike: clamped to +10%, then 10% weight → +1% max (SPEC: ≤ 0.25% at 15 s).
        let (up, c) = ema_step(e, 3 * e, 60, 1_000).unwrap();
        assert!(c);
        assert_eq!(up, e + e / 100);
        let (up15, _) = ema_step(e, 3 * e, 15, 1_000).unwrap();
        assert_eq!(up15, e + e / 400);
        let (down, c) = ema_step(e, e / 3, 60, 1_000).unwrap();
        assert!(c);
        assert_eq!(down, e - e / 100);
        // Equal input: unchanged.
        assert_eq!(ema_step(e, e, 60, 1_000), Ok((e, false)));
        // Full clamp band (10 000): lower bound is zero, never below zero.
        let (z, _) = ema_step(1, 0, 60, 10_000).unwrap();
        assert_eq!(z, 1);
        // Structural: clamp above 10 000 is rejected.
        assert_eq!(ema_step(e, e, 60, 10_001), Err(SijkaError::MathOverflow));
    }

    fn prev(ema: u128, q_ema: u64, fresh: u16, ts: i64) -> ObsPrev {
        ObsPrev { init: true, ema, q_ema, fresh_obs: fresh, last_obs_ts: ts }
    }

    #[test]
    fn observe_first_and_gap() {
        let p = 1_000 * X64;
        let first = observe_step(
            &ObsPrev { init: false, ema: 0, q_ema: 0, fresh_obs: 7, last_obs_ts: 0 },
            100,
            p,
            5,
            1_000,
            40,
        );
        assert_eq!(first, Ok(ObsNext { ema: p, q_ema: 5, fresh_obs: 1, clamped: 0 }));
        // Normal cadence counts up; a gap > 120 s restarts the counter but keeps the EMA.
        let n = observe_step(&prev(p, 5, 3, 100), 115, p, 5, 1_000, 40).unwrap();
        assert_eq!((n.fresh_obs, n.ema), (4, p));
        let n = observe_step(&prev(p, 5, 50, 100), 220, p, 5, 1_000, 40).unwrap();
        assert_eq!(n.fresh_obs, 51);
        let n = observe_step(&prev(p, 5, 50, 100), 221, p * 2, 5, 1_000, 40).unwrap();
        assert_eq!(n.fresh_obs, 1);
        assert!(n.ema > p && n.ema <= p + p / 100, "gap weight ≤ 1%");
        // Saturation of the counter.
        assert_eq!(observe_step(&prev(p, 5, u16::MAX, 100), 115, p, 5, 1_000, 40).unwrap().fresh_obs, u16::MAX);
        // Time going backwards is an error, not a wrap.
        assert!(observe_step(&prev(p, 5, 1, 100), 99, p, 5, 1_000, 40).is_err());
    }

    #[test]
    fn observe_warmup_falls_freely_rises_by_clamp() {
        // RT-8 / TD-68: a first observation pumped ×2 is erased by the next honest one.
        let honest = 1_000 * X64;
        let pumped = 2 * honest;
        let first = observe_step(
            &ObsPrev { init: false, ema: 0, q_ema: 0, fresh_obs: 0, last_obs_ts: 0 },
            0,
            pumped,
            2_000,
            1_000,
            40,
        )
        .unwrap();
        let second =
            observe_step(&prev(first.ema, first.q_ema, first.fresh_obs, 0), 15, honest, 1_000, 1_000, 40).unwrap();
        assert_eq!(second.ema, honest);
        assert_eq!(second.q_ema, 1_000);
        // A depressed first observation only rises through the clamp (≤ 0.25% per 15 s).
        let low = observe_step(
            &ObsPrev { init: false, ema: 0, q_ema: 0, fresh_obs: 0, last_obs_ts: 0 },
            0,
            honest / 2,
            500,
            1_000,
            40,
        )
        .unwrap();
        let up = observe_step(&prev(low.ema, low.q_ema, low.fresh_obs, 0), 15, honest, 1_000, 1_000, 40).unwrap();
        assert_eq!(up.ema, low.ema + low.ema / 400);
        assert_eq!(up.clamped & 1, 1);
        assert_eq!(up.clamped & 2, 2);
        // After warm-up a drop is also clamped (no free fall).
        let warm = observe_step(&prev(honest, 1_000, 39, 0), 15, honest / 2, 500, 1_000, 40).unwrap();
        assert_eq!(warm.fresh_obs, 40);
        assert_eq!(warm.ema, honest - honest / 400);
        // Q EMA respects the same rule during warm-up.
        let q = observe_step(&prev(honest, 1_000, 1, 0), 15, honest, 400, 1_000, 40).unwrap();
        assert_eq!(q.q_ema, 400);
    }

    #[test]
    fn observe_pump_three_times_moves_ema_at_most_quarter_percent() {
        // TD-9: "the market" triples the price: EMA ≤ +0.25% per 15 s observation, clamped flag set.
        let e = 5_000 * X64;
        let n = observe_step(&prev(e, 10, 45, 0), 15, 3 * e, 30, 1_000, 40).unwrap();
        assert_eq!(n.ema, e + e / 400);
        assert_eq!(n.clamped, 0b11);
    }

    fn base_inputs() -> ChunkInputs {
        // SOL curve near launch: vQ = 40 SOL, vT = 800M tokens (6 decimals).
        let vq = 40_000_000_000u64;
        let vt = 800_000_000_000_000u64;
        let p = price_x64(vq, vt).unwrap();
        ChunkInputs {
            obs_init: true,
            fresh_obs: 40,
            last_obs_ts: 1_000,
            last_obs_slot: 10,
            ema: p,
            last_obs_price: p,
            last_obs_quote: vq,
            q_ema: vq,
            next_buy_ts: 0,
            last_buy_slot: 0,
            warmup_obs: 40,
            obs_max_age_s: 120,
            chunk_bps: 10,
            chunk_max_quote: 1_000_000_000,
            chunk_min_quote: 10_000_000,
            now: 1_010,
            slot: 11,
            q_now: vq,
            curve: Some(CurveReserves { virtual_token: vt, virtual_quote: vq, real_token: 520_000_000_000_000 }),
            avail: 100_000_000_000,
            float_ok: true,
            max_quote_in: 0,
            min_out_keeper: 1,
        }
    }

    #[test]
    fn chunk_gates_in_order() {
        let ok = base_inputs();
        let plan = plan_chunk(&ok).unwrap();
        // 10 bps of 40 SOL = 0.04 SOL.
        assert_eq!(plan.v, 40_000_000);
        assert_eq!(plan.v_cap, 40_000_000);
        type Case = (fn(&mut ChunkInputs), SijkaError);
        let cases: [Case; 10] = [
            (|i| i.obs_init = false, SijkaError::BbWarmup),
            (|i| i.fresh_obs = 39, SijkaError::BbWarmup),
            (|i| i.slot = 10, SijkaError::BbSameSlot),
            (|i| i.now = 1_121, SijkaError::BbStaleObservation),
            (|i| i.next_buy_ts = 1_011, SijkaError::BbBuyTooSoon),
            (|i| i.last_buy_slot = 11, SijkaError::BbBuyTooSoon),
            (|i| i.float_ok = false, SijkaError::BbFloatLow),
            (|i| i.avail = 9_999_999, SijkaError::BbChunkBelowMin),
            (|i| i.max_quote_in = 9_999_999, SijkaError::BbChunkBelowMin),
            (|i| i.min_out_keeper = 0, SijkaError::BbExpectedOutBelowMin),
        ];
        for (k, (m, e)) in cases.iter().enumerate() {
            let mut i = ok;
            m(&mut i);
            assert_eq!(plan_chunk(&i), Err(*e), "case {k}");
        }
        // The observation exactly at max age passes.
        let mut aged = ok;
        aged.now = 1_120;
        assert!(plan_chunk(&aged).is_ok());
        // P_ref (event only) is the lower of EMA and the last observation.
        let mut low_ema = ok;
        low_ema.ema = ok.ema / 2;
        assert_eq!(plan_chunk(&low_ema).unwrap().p_ref, ok.ema / 2);
    }

    /// SPEC v4 (DECISIONS §23 items 3 and 6): no spot guard and no fee-based
    /// floor. A spot far above the EMA reference (a pump, or the EMA still
    /// catching up) does not stop the chunk; the size stays bounded by
    /// `Q_ref`, and the floor handed to pump (and checked after the CPI) is
    /// exactly the keeper's `min_out`, which protects against a front-run
    /// between the keeper's quote and the chunk.
    #[test]
    fn chunk_runs_with_spot_far_above_the_ema() {
        let ok = base_inputs();
        let c = ok.curve.unwrap();
        // The market pushed the price ×2.89 since the EMA.
        let (vq, vt) = (ok.q_now * 17 / 10, c.virtual_token * 10 / 17);
        let mut pumped = ok;
        pumped.q_now = vq;
        pumped.curve = Some(CurveReserves { virtual_token: vt, virtual_quote: vq, real_token: vt / 2 });
        assert!(price_x64(vq, vt).unwrap() > 2 * ok.ema);
        // The keeper quoted the pumped reserves (fees 95 + 30 bps, 1% slippage).
        let quoted = pump_curve_out(40_000_000, vt, vq, 95, 30) * 99 / 100;
        pumped.min_out_keeper = quoted;
        let p = plan_chunk(&pumped).unwrap();
        // v is still 10 bps of Q_ref = min(q_now, last_obs_quote, q_ema).
        assert_eq!((p.v, p.q_ref), (40_000_000, ok.q_now));
        assert_eq!(p.min_out, quoted);
        assert!(pump_curve_out(p.v, vt, vq, 95, 30) >= p.min_out, "pump delivers the keeper's floor");
        // A front-run after the quote (price up another 10%) leaves pump's
        // output below the keeper's floor: pump and the post-CPI check refuse.
        let (fq, ft) = (vq * 105 / 100, vt * 100 / 105);
        assert!(pump_curve_out(p.v, ft, fq, 95, 30) < p.min_out);
        // The program's floor is the keeper's value whatever pump's fees are
        // (no fee cap any more).
        let mut other = pumped;
        other.q_now = vq * 2;
        assert_eq!(plan_chunk(&other).unwrap().min_out, quoted);
    }

    #[test]
    fn chunk_size_min_of_all_caps() {
        let ok = base_inputs();
        // Q_ref = min(q_now, last_obs_quote, q_ema): a JIT deposit into q_now does not help.
        let mut jit = ok;
        jit.q_now = ok.q_now * 3;
        assert_eq!(plan_chunk(&jit).unwrap().q_ref, ok.q_now);
        let mut small_ema = ok;
        small_ema.q_ema = 20_000_000_000;
        assert_eq!(plan_chunk(&small_ema).unwrap().v, 20_000_000);
        // chunk_max_quote cap.
        let mut capped = ok;
        capped.chunk_max_quote = 15_000_000;
        let p = plan_chunk(&capped).unwrap();
        assert_eq!((p.v, p.v_cap), (15_000_000, 15_000_000));
        // Budget and caller cap shrink v but not v_cap (RT-6 cool-down base).
        let mut poor = ok;
        poor.avail = 12_000_000;
        let p = plan_chunk(&poor).unwrap();
        assert_eq!((p.v, p.v_cap), (12_000_000, 40_000_000));
        let mut arg = ok;
        arg.max_quote_in = 11_000_000;
        assert_eq!(plan_chunk(&arg).unwrap().v, 11_000_000);
        // The keeper's floor is passed through as is (SPEC v4): any value
        // ≥ 1, even one pump cannot give (pump then refuses the buy).
        for m in [1u64, 777, u64::MAX] {
            let mut keeper = ok;
            keeper.min_out_keeper = m;
            assert_eq!(plan_chunk(&keeper).unwrap().min_out, m);
        }
        // AMM: no curve clamp.
        let mut amm = ok;
        amm.curve = None;
        assert_eq!(plan_chunk(&amm).unwrap().v, 40_000_000);
    }

    /// AR2-10 (audit v4 round 2): on a PumpSwap pool with less than 10 SOL of
    /// quote the 10 bps chunk is below `chunk_min_quote` (0.01 SOL). The floor
    /// is capped at the full chunk, so the chunk runs; dust below the full
    /// chunk is still refused.
    #[test]
    fn small_pool_gets_its_full_chunk_below_chunk_min() {
        let mut i = base_inputs();
        i.curve = None;
        let q = 9_000_000_000u64; // 9 SOL of pool quote.
        (i.q_now, i.last_obs_quote, i.q_ema) = (q, q, q);
        i.avail = 1_000_000_000;
        let p = plan_chunk(&i).unwrap();
        assert!(p.v_cap < i.chunk_min_quote);
        assert_eq!((p.v, p.v_cap), (9_000_000, 9_000_000));
        // Dust below the full chunk is still refused: budget or keeper cap.
        let mut poor = i;
        poor.avail = 8_999_999;
        assert_eq!(plan_chunk(&poor), Err(SijkaError::BbChunkBelowMin));
        let mut arg = i;
        arg.max_quote_in = 8_999_999;
        assert_eq!(plan_chunk(&arg), Err(SijkaError::BbChunkBelowMin));
        // The floor still applies when the full chunk is above it.
        let mut big = i;
        (big.q_now, big.last_obs_quote, big.q_ema) = (40_000_000_000, 40_000_000_000, 40_000_000_000);
        big.avail = 9_999_999;
        assert_eq!(plan_chunk(&big), Err(SijkaError::BbChunkBelowMin));
        // A nearly empty pool: v_cap = 1 lamport still works, v_cap = 0 is
        // refused (the floor is at least 1).
        let mut tiny = i;
        (tiny.q_now, tiny.last_obs_quote, tiny.q_ema) = (1_000, 1_000, 1_000);
        assert_eq!(plan_chunk(&tiny).unwrap().v, 1);
        (tiny.q_now, tiny.last_obs_quote, tiny.q_ema) = (999, 999, 999);
        assert_eq!(plan_chunk(&tiny), Err(SijkaError::BbChunkBelowMin));
        // The cool-down of a full small chunk is the whole interval.
        assert_eq!(next_ts(1_000, 60, p.v, p.v_cap), Ok(1_060));
        // Property: whenever the plan passes, v_cap ≥ v ≥ 1 and v is either
        // ≥ chunk_min_quote or exactly the full chunk.
        let mut rng = Rng::new(70);
        for _ in 0..5_000 {
            let mut x = i;
            let q = rng.range(0, 2_000_000_000_000);
            (x.q_now, x.last_obs_quote, x.q_ema) = (q, rng.range(0, 2_000_000_000_000), q);
            x.avail = rng.range(0, 2_000_000_000);
            x.max_quote_in = if rng.range(0, 2) == 0 { 0 } else { rng.range(1, 2_000_000_000) };
            if let Ok(p) = plan_chunk(&x) {
                assert!(p.v >= 1 && p.v <= p.v_cap);
                assert!(p.v >= x.chunk_min_quote || p.v == p.v_cap);
            }
        }
    }

    #[test]
    fn curve_v_max_property() {
        // TU-D11: t0(v_max) ≤ R − 1 and t0(v_max + 1) ≥ R − 1 (or overflow).
        let mut rng = Rng::new(11);
        for _ in 0..5_000 {
            let r = rng.range(2, 1_000_000_000_000_000);
            let vt = r + rng.range(0, 300_000_000_000_000);
            let vq = rng.range(1, 500_000_000_000);
            let c = CurveReserves { virtual_token: vt, virtual_quote: vq, real_token: r };
            let vm = curve_v_max(&c).unwrap();
            assert!(curve_t0(vm, &c).unwrap() <= u128::from(r - 1));
            if vm < u64::MAX {
                assert!(curve_t0(vm + 1, &c).unwrap() >= u128::from(r - 1));
            }
        }
        assert_eq!(
            curve_v_max(&CurveReserves { virtual_token: 10, virtual_quote: 10, real_token: 1 }),
            Err(SijkaError::BbCurveNearComplete)
        );
        assert_eq!(
            curve_v_max(&CurveReserves { virtual_token: 9, virtual_quote: 10, real_token: 10 }),
            Err(SijkaError::BbReserveAnomaly)
        );
    }

    #[test]
    fn chunk_clamps_at_curve_end() {
        // TD-63: R slightly above the full chunk's t0 → v = v_max, t0 < R.
        let mut i = base_inputs();
        let c = i.curve.unwrap();
        let full_t0 = curve_t0(40_000_000, &c).unwrap() as u64;
        let r = full_t0 / 2;
        i.curve = Some(CurveReserves { real_token: r, ..c });
        let p = plan_chunk(&i).unwrap();
        let c2 = i.curve.unwrap();
        assert_eq!(p.v, curve_v_max(&c2).unwrap());
        assert!(curve_t0(p.v, &c2).unwrap() < u128::from(r));
        // v_max below chunk_min_quote → BbCurveNearComplete, not BbChunkBelowMin.
        i.curve = Some(CurveReserves { real_token: 1_000, ..c });
        assert_eq!(plan_chunk(&i), Err(SijkaError::BbCurveNearComplete));
        i.curve = Some(CurveReserves { real_token: 1, ..c });
        assert_eq!(plan_chunk(&i), Err(SijkaError::BbCurveNearComplete));
    }

    #[test]
    fn cooldown_is_proportional() {
        // TD-67: dust chunk occupies only its share of the interval.
        assert_eq!(next_ts(1_000, 60, 40_000_000, 40_000_000), Ok(1_060));
        assert_eq!(next_ts(1_000, 60, 10_000_000, 40_000_000), Ok(1_015));
        assert_eq!(next_ts(1_000, 60, 1, 40_000_000), Ok(1_001));
        assert_eq!(next_ts(1_000, 60, 0, 40_000_000), Ok(1_000));
        // Tag 43 example: 0.01 USDC against 1000 USDC → ⌈60·0.01/1000⌉ = 1 s.
        assert_eq!(next_ts(1_000, 60, 10_000, 1_000_000_000), Ok(1_001));
        assert_eq!(next_ts(1_000, 0, 10, 10), Ok(1_000));
        assert_eq!(next_ts(1_000, 60, 1, 0), Err(SijkaError::MathOverflow));
        assert_eq!(next_ts(i64::MAX, 60, 1, 1), Err(SijkaError::MathOverflow));
    }

    #[test]
    fn settlements() {
        // SOL curve: spend up to v + rent.
        assert_eq!(settle_sol_curve(100, 1_000, 900, 15), Ok((100, 0)));
        assert_eq!(settle_sol_curve(100, 1_000, 890, 15), Ok((100, 10)));
        assert_eq!(settle_sol_curve(100, 1_000, 885, 15), Ok((100, 15)));
        assert_eq!(settle_sol_curve(100, 1_000, 884, 15), Err(SijkaError::BbOverspend));
        assert_eq!(settle_sol_curve(100, 1_000, 950, 15), Ok((50, 0)));
        assert_eq!(settle_sol_curve(100, 1_000, 1_100, 15), Ok((0, 0)));
        // Token quote.
        assert_eq!(settle_token_quote(100, 500, 400, 1_000, 990, 15), Ok((100, 10)));
        assert_eq!(settle_token_quote(100, 500, 399, 1_000, 990, 15), Err(SijkaError::BbOverspend));
        assert_eq!(settle_token_quote(100, 500, 400, 1_000, 984, 15), Err(SijkaError::BbOverspend));
        assert_eq!(settle_token_quote(100, 500, 600, 1_000, 1_000, 15), Ok((0, 0)));
    }
}
