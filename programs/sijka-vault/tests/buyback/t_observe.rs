// Copyright (c) 2026 prt1sn. All rights reserved.
//! `bb_observe` (tag 42): EMA, clamp, warm-up, gaps, venue switch; SPEC
//! §5.5.2, §5.5.6; TD-7…TD-14, TD-33, TD-68.

use sijka_vault::error::SijkaError as E;

use crate::harness::*;
use crate::pumpix::*;

/// TD-7: the first observation after `bb_pin` sets `ema = p`, `q_ema = q`,
/// `fresh_obs = 1`, `OBS_INIT`, and emits `SJKEVOBS`.
#[test]
fn first_observation_initializes_the_ema() {
    let mut v = vault!(Setup::sol("solcurve"));
    let (vt, vq, _, _) = curve_reserves(&v);
    let (slot, now) = v.clock();
    let m = ok(v.observe());
    println!("U-37 tag 42 CU: {}", m.compute_units_consumed);
    let p = price_x64(vq, vt);
    let bs = v.bs();
    assert_eq!(bs.flags(), 3, "PINNED | OBS_INIT");
    assert_eq!(bs.ema_price_x64(), p);
    assert_eq!(bs.last_obs_price_x64(), p);
    assert_eq!(bs.q_ema(), vq);
    assert_eq!(bs.last_obs_quote(), vq);
    assert_eq!(bs.fresh_obs(), 1);
    assert_eq!(bs.n_obs(), 1);
    assert_eq!(bs.last_obs_ts(), now);
    assert_eq!(bs.last_obs_slot(), slot);
    let e = event(&m.logs, "SJKEVOBS");
    assert_eq!(e.len(), 85);
    assert_eq!(e[17], 1);
    assert_eq!(u64_at(&e, 18), slot);
    assert_eq!(u64_at(&e, 26), vq);
    assert_eq!(u64_at(&e, 34), vt);
    assert_eq!(u128_at(&e, 42), p);
    assert_eq!(u128_at(&e, 58), p);
    assert_eq!(u64_at(&e, 74), vq);
    assert_eq!(u16_at(&e, 82), 1);
    assert_eq!(e[84], 0, "not clamped");
}

/// TD-8: a second observation within 15 s, or in the same slot, fails.
#[test]
fn observe_too_soon() {
    let mut v = vault!(Setup::sol("solcurve"));
    ok(v.observe());
    let (s, t) = v.clock();
    v.set_clock(s + 1, t + 14);
    assert_sijka(&v.observe(), E::BbObserveTooSoon);
    v.set_clock(s, t + 15);
    assert_sijka(&v.observe(), E::BbObserveTooSoon);
    v.set_clock(s + 1, t + 15);
    ok(v.observe());
    assert_eq!(v.bs().fresh_obs(), 2);
}

/// Reference `ema_step` (SPEC §5.5.2), written independently of the program.
pub fn ref_ema_step(ema: u128, x: u128, dt: u64, clamp_bps: u16) -> (u128, bool) {
    let c = u128::from(clamp_bps);
    let lo = ema * (10_000 - c) / 10_000;
    let hi = ema * (10_000 + c) / 10_000;
    let (xi, clamped) = if x < lo {
        (lo, true)
    } else if x > hi {
        (hi, true)
    } else {
        (x, false)
    };
    let w = u128::from(dt.min(60));
    let next = if xi >= ema { ema + (xi - ema) * w / 600 } else { ema - (ema - xi) * w / 600 };
    (next, clamped)
}

pub fn curve_price(v: &Vault) -> (u128, u64) {
    let (vt, vq, _, _) = curve_reserves(v);
    (price_x64(vq, vt), vq)
}

/// TD-9: after the warm-up, the "market" triples the price; one observation
/// 15 s later moves the EMA by exactly the clamped step (+10% · 15/600 =
/// +0.25%), flags `clamped` for price and Q. SPEC v4: no spot guard — the
/// keeper's chunk then runs at ≈ 3× the EMA reference, its size bounded by
/// `Q_ref` (the reserve EMA barely moved).
#[test]
fn market_pump_moves_the_ema_only_through_the_clamp() {
    let mut v = vault!(Setup::sol("solcurve"));
    v.warm_up(40);
    let bs0 = v.bs();
    let (ema0, q_ema0) = (bs0.ema_price_x64(), bs0.q_ema());
    let (p0, _) = curve_price(&v);
    let t = Trader::new(&mut v, 100 * LAMPORTS_PER_SOL);
    ok(t.curve_buy(&mut v, 24 * LAMPORTS_PER_SOL));
    let (p, q) = curve_price(&v);
    assert!(p > 2 * p0 + p0 * 8 / 10, "the market roughly tripled the price: {p} vs {p0}");
    v.tick(15, 1);
    let m = ok(v.observe());
    let (e1, pc) = ref_ema_step(ema0, p, 15, 1_000);
    let (q1, qc) = ref_ema_step(u128::from(q_ema0), u128::from(q), 15, 1_000);
    assert!(pc && qc);
    let bs = v.bs();
    assert_eq!(bs.ema_price_x64(), e1);
    assert_eq!(bs.q_ema(), q1 as u64);
    assert_eq!(bs.last_obs_price_x64(), p, "raw price is kept as last_obs");
    assert!(e1 * 10_000 <= ema0 * 10_025, "one observation moves the EMA by at most 0.25%");
    let e = event(&m.logs, "SJKEVOBS");
    assert_eq!(e[84], 3, "clamped: bit0 price, bit1 Q");
    assert_eq!(u128_at(&e, 42), p);
    assert_eq!(u128_at(&e, 58), e1);
    // The chunk sees p_now ≈ 3·P_ref (TD-20 by a large move): it runs, and v
    // stays within chunk_bps of Q_ref = min(q_now, last_obs_quote, q_ema).
    v.fund_authority(LAMPORTS_PER_SOL);
    v.tick(1, 1);
    let bs = v.bs();
    let q_ref = q.min(bs.last_obs_quote()).min(bs.q_ema());
    let p = bs.buyback_params();
    let cap = ((u128::from(q_ref) * u128::from(p.chunk_bps()) / 10_000) as u64).min(p.chunk_max_quote());
    let m = ok(v.call(chunk_curve_ix(&v, 0, 0)));
    let e = event(&m.logs, "SJKEVCHK");
    assert!(u64_at(&e, 18) <= cap, "v {} above chunk_bps·Q_ref {cap}", u64_at(&e, 18));
    assert_eq!(u64_at(&e, 98), q_ref);
}

/// TD-10 (and TD-16): a gap above `OBS_MAX_GAP_S = 120 s` restarts the
/// warm-up (`fresh_obs = 1`) but keeps the EMA; exactly 120 s is not a gap.
#[test]
fn gap_restarts_the_warmup_but_keeps_the_ema() {
    let mut v = vault!(Setup::sol("solcurve"));
    v.warm_up(3);
    let ema = v.bs().ema_price_x64();
    v.tick(120, 1);
    ok(v.observe());
    assert_eq!(v.bs().fresh_obs(), 4, "120 s: not a gap");
    v.tick(121, 1);
    ok(v.observe());
    let bs = v.bs();
    assert_eq!(bs.fresh_obs(), 1, "121 s: gap");
    assert_eq!(bs.ema_price_x64(), ema, "flat market: EMA unchanged, not reset");
    assert_eq!(bs.n_obs(), 5);
    v.fund_authority(LAMPORTS_PER_SOL);
    v.tick(1, 1);
    let ix = chunk_curve_ix(&v, 0, 0);
    assert_sijka(&v.call(ix), E::BbWarmup);
}

/// TD-11, TD-12: observe must be the only non-ComputeBudget instruction and
/// run at top level: a pump buy in the same transaction → ForeignInstruction;
/// twice → ForeignInstruction; through a CPI wrapper → NotTopLevel.
#[test]
fn observe_must_be_alone_and_top_level() {
    let mut v = vault!(Setup::sol("solcurve"));
    let t = Trader::new(&mut v, 10 * LAMPORTS_PER_SOL);
    let buy = t.curve_buy_ix(&v, LAMPORTS_PER_SOL / 10, 1);
    let obs = v.observe_ix();
    let kp = t.kp.insecure_clone();
    let res = v.send(vec![buy, obs.clone()], &[&kp]);
    assert_sijka(&res, E::ForeignInstruction);
    let kp = v.keeper.insecure_clone();
    let res = v.send(vec![obs.clone(), obs.clone()], &[&kp]);
    assert_sijka(&res, E::ForeignInstruction);
    let res = v.send(vec![crate::mocks::wrap_cpi(obs.clone())], &[&kp]);
    assert_sijka(&res, E::NotTopLevel);
    // Alone, even without a ComputeBudget instruction, it is fine.
    ok(v.send_raw(vec![obs], &[&kp]));
}

/// TD-13: another coin's curve / pool accounts → BbPinnedAccountMismatch.
#[test]
fn observe_rejects_foreign_market_accounts() {
    let mut v = vault!(Setup::sol("solcurve"));
    let other_curve = v.fx.key("solamm bonding_curve");
    let other_pool = v.fx.key("solamm pool");
    for (i, k) in [(2usize, other_curve), (3, other_pool), (4, other_pool), (5, other_pool)] {
        let mut ix = v.observe_ix();
        ix.accounts[i].pubkey = k;
        assert_sijka(&v.call(ix), E::BbPinnedAccountMismatch);
    }
}

/// TD-14: the warm-up counter counts consecutive observations; the chunk is
/// refused until `fresh_obs ≥ warmup_obs` (40).
#[test]
fn warmup_counter_gates_the_chunk() {
    let mut v = vault!(Setup::sol("solcurve"));
    v.fund_authority(LAMPORTS_PER_SOL);
    let ix = chunk_curve_ix(&v, 0, 0);
    assert_sijka(&v.call(ix), E::BbWarmup);
    v.warm_up(39);
    assert_eq!(v.bs().fresh_obs(), 39);
    v.tick(1, 1);
    let ix = chunk_curve_ix(&v, 0, 0);
    assert_sijka(&v.call(ix), E::BbWarmup);
    v.tick(14, 1);
    ok(v.observe());
    assert_eq!(v.bs().fresh_obs(), 40);
    v.tick(1, 1);
    let ix = chunk_curve_ix(&v, 0, 0);
    ok(v.call(ix));
}

/// TD-68 (review RT-8): an inflated first observation after `bb_pin` (market
/// buy right before it) is erased by the next honest one; a deflated first
/// observation lets the EMA rise only through the clamp.
#[test]
fn warmup_rule_first_observation_up_and_down() {
    // Inflated first observation.
    let mut v = vault!(Setup::sol("solcurve"));
    let t = Trader::new(&mut v, 100 * LAMPORTS_PER_SOL);
    ok(t.curve_buy(&mut v, 13 * LAMPORTS_PER_SOL));
    let (p_up, _) = curve_price(&v);
    ok(v.observe());
    assert_eq!(v.bs().ema_price_x64(), p_up, "first observation is raw");
    let bal = t.base(&v);
    ok(t.curve_sell(&mut v, bal));
    let (p_back, q_back) = curve_price(&v);
    assert!(p_back < p_up);
    v.tick(15, 1);
    ok(v.observe());
    let bs = v.bs();
    assert_eq!(bs.ema_price_x64(), p_back, "warm-up: ema = min(e1, p) = honest price");
    assert_eq!(bs.q_ema(), q_back);

    // Deflated first observation: the price then doubles for good.
    let mut v = vault!(Setup::sol("solcurve"));
    ok(v.observe());
    let ema0 = v.bs().ema_price_x64();
    let t = Trader::new(&mut v, 100 * LAMPORTS_PER_SOL);
    ok(t.curve_buy(&mut v, 13 * LAMPORTS_PER_SOL));
    let (p2, _) = curve_price(&v);
    assert!(p2 > ema0 * 18 / 10);
    for i in 1..=3u32 {
        let before = v.bs().ema_price_x64();
        v.tick(15, 1);
        ok(v.observe());
        let (e1, clamped) = ref_ema_step(before, p2, 15, 1_000);
        assert!(clamped);
        assert_eq!(v.bs().ema_price_x64(), e1.min(p2), "observation {i}: up only through the clamp");
        assert!(e1 * 10_000 <= before * 10_025);
    }
}

/// TD-33 (graduation) and TD-68 (switch with a pool at 2× the curve EMA): the
/// switching observation keeps the EMA (clamped step, warm-up min rule),
/// `q_ema ≤ Q` of the pool, `fresh_obs` restarts at 1, `SJKEVVEN`; tag 44 then
/// fails with BbVenueMismatch and tag 45 waits for the new warm-up.
#[test]
fn venue_switch_keeps_the_ema_and_restarts_the_warmup() {
    let mut v = vault!(Setup::sol("solamm").no_pin());
    let (b, q) = pool_reserves(&v);
    // Make the graduated coin's curve look live at half the pool price.
    let vt: u64 = 1_000_000_000_000_000;
    let vq = (u128::from(q) * u128::from(vt) / (2 * u128::from(b))) as u64;
    let rt: u64 = 700_000_000_000_000;
    let curve = v.coin().curve;
    v.patch(&curve, |d| {
        d[8..16].copy_from_slice(&vt.to_le_bytes());
        d[16..24].copy_from_slice(&vq.to_le_bytes());
        d[24..32].copy_from_slice(&rt.to_le_bytes());
        d[48] = 0;
    });
    ok(v.bb_pin());
    assert_eq!(v.bs().venue(), 1);
    v.warm_up(40);
    let bs0 = v.bs();
    let (ema_c, q_ema_c) = (bs0.ema_price_x64(), bs0.q_ema());
    assert_eq!(ema_c, price_x64(vq, vt));
    // Graduation: complete curve, canonical pool exists.
    v.patch(&curve, |d| d[48] = 1);
    v.tick(15, 1);
    let (slot, _) = v.clock();
    let m = ok(v.observe());
    let p_pool = price_x64(q, b);
    let ven = event(&m.logs, "SJKEVVEN");
    assert_eq!(ven.len(), 51);
    assert_eq!((ven[17], ven[18]), (1, 2));
    assert_eq!(u64_at(&ven, 19), slot);
    assert_eq!(u128_at(&ven, 27), p_pool);
    assert_eq!(u64_at(&ven, 43), q);
    let bs = v.bs();
    assert_eq!(bs.venue(), 2);
    assert_eq!(bs.venue_since_slot(), slot);
    assert_eq!(bs.fresh_obs(), 1, "new warm-up");
    let (e1, pc) = ref_ema_step(ema_c, p_pool, 15, 1_000);
    assert!(pc, "pool at 2x the EMA is clamped");
    assert_eq!(bs.ema_price_x64(), e1.min(p_pool), "EMA kept, moved by one clamped step");
    assert!(bs.ema_price_x64() * 10_000 <= ema_c * 10_025);
    let q_start = q_ema_c.min(q);
    let (q1, _) = ref_ema_step(u128::from(q_start), u128::from(q), 15, 1_000);
    assert_eq!(bs.q_ema(), (q1 as u64).min(q), "q_ema = min(q_ema, Q_pool), then the step");
    assert!(bs.q_ema() <= q);
    assert_eq!(event(&m.logs, "SJKEVOBS")[17], 2);
    v.fund_authority(LAMPORTS_PER_SOL);
    v.tick(1, 1);
    let ix = chunk_curve_ix(&v, 0, 0);
    assert_sijka(&v.call(ix), E::BbVenueMismatch);
    let ix = chunk_amm_ix(&v, 0, 0);
    assert_sijka(&v.call(ix), E::BbWarmup);
    // SPEC v4 (no spot guard): right after the warm-up the pool (2× the kept
    // EMA) is bought by the keeper's chunk; the price limit is its min_out.
    v.warm_up(39);
    v.tick(1, 1);
    let bs = v.bs();
    let p_ref = bs.ema_price_x64().min(bs.last_obs_price_x64());
    assert!(p_pool * 10_000 > p_ref * 10_200, "the pool is still well above the EMA reference");
    ok(v.call(chunk_amm_ix(&v, 0, 0)));
}

/// TD-34 (second half): the curve completes but no pool exists yet: observe
/// fails with BbPoolNotReady without changing the state; tag 44 then fails
/// with BbVenueSwitchPending.
#[test]
fn complete_curve_without_pool_waits() {
    let mut v = vault!(Setup::sol("solcurve"));
    v.fund_authority(LAMPORTS_PER_SOL);
    v.warm_up(40);
    let before = v.state_data();
    let curve = v.coin().curve;
    v.patch(&curve, |d| d[48] = 1);
    v.tick(15, 1);
    assert_sijka(&v.observe(), E::BbPoolNotReady);
    assert_eq!(v.state_data(), before, "a failed observation leaves the state as it was");
    let ix = chunk_curve_ix(&v, 0, 0);
    assert_sijka(&v.call(ix), E::BbVenueSwitchPending);
}

/// Observation of a PumpSwap pool uses `Q = quote TA + virtual_quote_reserves`
/// (the live USDC pool has `vqr ≠ 0`).
#[test]
fn pool_observation_includes_virtual_quote_reserves() {
    let mut v = vault!(Setup::usdc("usdcamm"));
    let ck = v.coin().clone();
    let pool = v.data(&ck.pool);
    let vqr = i128::from_le_bytes(pool[245..261].try_into().unwrap());
    println!("usdcamm pool virtual_quote_reserves = {vqr}");
    assert!(vqr > 0, "this live pool carries virtual quote reserves");
    let qt = v.token_amount(&ck.pool_quote_ta);
    let b = v.token_amount(&ck.pool_base_ta);
    let m = ok(v.observe());
    let e = event(&m.logs, "SJKEVOBS");
    assert_eq!(e[17], 2);
    assert_eq!(u64_at(&e, 26), qt + vqr as u64, "q = Qt + vqr");
    assert_eq!(u64_at(&e, 34), b);
    assert_eq!(u128_at(&e, 42), price_x64(qt + vqr as u64, b));
}
