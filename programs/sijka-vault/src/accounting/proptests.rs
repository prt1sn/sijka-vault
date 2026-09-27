// Copyright (c) 2026 prt1sn. All rights reserved.
//! Property tests of the harvest accounting (SPEC §9.2 TU-A1, §9.9 INV-2,
//! INV-3; task invariants: the payout never exceeds `D*`, the creator gets at
//! most 20%, `O` grows exactly by the paid amount, donations never create a
//! payout).
//!
//! Deterministic property loops over a SplitMix64 generator biased towards
//! edge values, instead of `proptest`: the `proptest` dependency tree does not
//! link on the Windows GNU development host, and fixed seeds make every
//! failure reproducible. Each property runs `N` cases.

use super::*;
use crate::state::config::harvest_params::HarvestParamsMut;

const N: usize = 40_000;

/// SplitMix64.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next() % n }
    }

    /// u64 biased to edges and realistic magnitudes.
    fn u64(&mut self) -> u64 {
        match self.below(10) {
            0 => [0, 1, 2, u64::MAX, u64::MAX - 1, i64::MAX as u64, (i64::MAX as u64) + 1][self.below(7) as usize],
            1 => self.below(1_000),
            2 => self.below(1_000_000_000),             // ≤ 1 000 USDC
            3 | 4 => self.below(1_000_000_000_000_000), // ≤ 1e9 USDC
            5 => self.below(u64::from(u32::MAX)),
            _ => self.next(),
        }
    }

    /// i64 biased to edges, both signs.
    fn i64(&mut self) -> i64 {
        match self.below(10) {
            0 => [0, 1, -1, i64::MAX, i64::MIN, i64::MAX - 1, i64::MIN + 1][self.below(7) as usize],
            1..=4 => {
                let v = self.below(1_000_000_000_000_000) as i64;
                if self.next() & 1 == 0 { v } else { -v }
            }
            _ => self.next() as i64,
        }
    }

    fn u32(&mut self) -> u32 {
        match self.below(4) {
            0 => [0, 1, 10_000, u32::MAX][self.below(4) as usize],
            1 | 2 => self.below(20_001) as u32,
            _ => self.next() as u32,
        }
    }

    fn u16(&mut self) -> u16 {
        match self.below(3) {
            0 => [0, 1, 10_000, u16::MAX][self.below(4) as usize],
            1 => self.below(10_001) as u16,
            _ => self.next() as u16,
        }
    }
}

fn random_params(rng: &mut Rng) -> [u8; 64] {
    let mut b = [0u8; 64];
    let mut m = HarvestParamsMut::from_array(&mut b);
    m.set_epsilon(rng.u64());
    let d_min = rng.u64().max(1);
    m.set_d_min(d_min);
    m.set_margin_buffer_abs(rng.u64());
    m.set_max_harvest_per_call(rng.u64().max(d_min));
    m.set_t_min_secs(rng.u32());
    m.set_margin_buffer_im_bps(rng.u32());
    m.set_max_buyback_backlog(rng.u64());
    m.set_harvest_mark_max_age_slots(rng.u16());
    b
}

fn random_margin(rng: &mut Rng) -> MarginView {
    MarginView {
        position_count: rng.u16(),
        risk_state: 0,
        risk_tier: 0,
        is_liquidatable: 0,
        collateral: rng.i64(),
        effective_collateral: rng.i64(),
        free_collateral: rng.i64(),
        withdrawable_collateral: rng.u64(),
        initial_margin: rng.u64(),
        unrealized_pnl: rng.i64(),
        unsettled_funding: rng.i64(),
    }
}

/// Recommended-range parameters and a pool that is often in profit.
fn realistic_state(rng: &mut Rng) -> ([u8; 64], MarginView, i64, u64) {
    let mut b = [0u8; 64];
    let mut pm = HarvestParamsMut::from_array(&mut b);
    let d_min = rng.below(50_000_000).max(1);
    pm.set_epsilon(rng.below(2_000_000));
    pm.set_d_min(d_min);
    pm.set_margin_buffer_abs(rng.below(10_000_000));
    pm.set_max_harvest_per_call(d_min + rng.below(500_000_000_000));
    pm.set_margin_buffer_im_bps(rng.below(10_001) as u32);
    let i = rng.below(1_000_000_000_000); // ≤ 1M USDC
    let profit = rng.below(200_000_000_000) as i64 - 20_000_000_000;
    let c = i as i64 + profit;
    let im = rng.below(100_000_000_000);
    let m = MarginView {
        collateral: c,
        unrealized_pnl: rng.below(20_000_000_000) as i64 - 10_000_000_000,
        unsettled_funding: rng.below(2_000_000_000) as i64 - 1_000_000_000,
        free_collateral: c - im as i64,
        withdrawable_collateral: (c - im as i64).max(0) as u64,
        initial_margin: im,
        ..MarginView::default()
    };
    let c_hdr = c + rng.below(1_000_000_000) as i64;
    (b, m, c_hdr, i)
}

#[test]
fn compute_harvest_clamps_hold() {
    let mut rng = Rng::new(0x5EED_0001);
    for case in 0..N {
        let pb = random_params(&mut rng);
        let p = HarvestParams::from_array(&pb);
        let m = random_margin(&mut rng);
        let c_hdr = rng.i64();
        let i = rng.u64();
        let (q_perm, q_tmp) = (rng.u64(), rng.u64());
        let c = compute_harvest(&m, c_hdr, i, &p, q_perm, q_tmp).unwrap();

        // C = min(C_hk, C_hdr); D* exactly as specified.
        assert_eq!(c.c, i128::from(m.collateral).min(i128::from(c_hdr)), "case {case}");
        let uf = i128::from(m.unrealized_pnl) + i128::from(m.unsettled_funding);
        assert_eq!(c.d_star, c.c - i128::from(i) + uf.min(0), "case {case}");
        if uf >= 0 {
            assert_eq!(c.d_star, c.c - i128::from(i), "positive uPnL is never paid (case {case})");
        }
        // W and buf (buf rounds up, SPEC §5.0.7).
        assert_eq!(c.w, i128::from(m.free_collateral.max(0)).min(i128::from(m.withdrawable_collateral)));
        let num = u128::from(m.initial_margin) * u128::from(p.margin_buffer_im_bps());
        let im_part = num.div_ceil(10_000);
        assert!(im_part * 10_000 >= num && (im_part == 0 || (im_part - 1) * 10_000 < num));
        assert_eq!(c.buf, i128::from(p.margin_buffer_abs()).max(im_part as i128), "case {case}");

        // Every clamp holds: the payout never exceeds D* − ε, the margin room,
        // the per-call cap or either queue budget.
        assert!(c.d <= c.d_star - i128::from(p.epsilon()), "case {case}");
        assert!(c.d <= c.w - c.buf, "case {case}");
        assert!(c.d <= i128::from(p.max_harvest_per_call()), "case {case}");
        assert!(c.d <= i128::from(q_perm) && c.d <= i128::from(q_tmp), "case {case}");
        assert!(c.d <= c.d_perm && c.d_perm <= c.d_pre, "case {case}");
        assert_eq!(
            c.d_pre,
            (c.d_star - i128::from(p.epsilon())).min(c.w - c.buf).min(i128::from(p.max_harvest_per_call()))
        );
        // Timer rule (review RT-5).
        assert_eq!(c.timer_held, c.d < c.d_pre.min(i128::from(q_perm)), "case {case}");
        if q_tmp >= q_perm {
            assert!(!c.timer_held, "case {case}");
        }
        assert_eq!(c.queue_limited(), c.d < c.d_pre);
    }
}

#[test]
fn compute_harvest_is_monotonic_in_c_and_i() {
    let mut rng = Rng::new(0x5EED_0002);
    for case in 0..N {
        let pb = random_params(&mut rng);
        let p = HarvestParams::from_array(&pb);
        let m = random_margin(&mut rng);
        let c_hdr = rng.i64();
        let i = rng.u64();
        let base = compute_harvest(&m, c_hdr, i, &p, u64::MAX, u64::MAX).unwrap();

        // More collateral (both views) never lowers D*.
        let x = rng.below(1_000_000_000_000) as i64;
        let m2 = MarginView { collateral: m.collateral.saturating_add(x), ..m };
        let more = compute_harvest(&m2, c_hdr.saturating_add(x), i, &p, u64::MAX, u64::MAX).unwrap();
        assert!(more.d_star >= base.d_star, "case {case}");

        // A larger I never raises D* or D.
        let y = rng.below(1_000_000_000_000);
        let i2 = i.saturating_add(y);
        let less = compute_harvest(&m, c_hdr, i2, &p, u64::MAX, u64::MAX).unwrap();
        assert!(less.d_star <= base.d_star && less.d <= base.d, "case {case}");
    }
}

#[test]
fn donations_never_create_a_payout() {
    let mut rng = Rng::new(0x5EED_0003);
    for case in 0..N {
        let pb = random_params(&mut rng);
        let p = HarvestParams::from_array(&pb);
        // Realistic magnitudes so that a donation fits in i64.
        let c0 = (rng.below(1_000_000_000_000_000) as i64) - 100_000_000_000_000;
        let m = MarginView {
            collateral: c0,
            free_collateral: (rng.below(1_000_000_000_000_000) as i64) - 1_000_000,
            withdrawable_collateral: rng.below(1_000_000_000_000_000),
            initial_margin: rng.below(1_000_000_000_000),
            unrealized_pnl: (rng.below(2_000_000_000_000) as i64) - 1_000_000_000_000,
            unsettled_funding: (rng.below(2_000_000_000) as i64) - 1_000_000_000,
            ..MarginView::default()
        };
        let c_hdr = c0.saturating_add((rng.below(1_000_000_000) as i64) - 500_000_000);
        let i = rng.below(1_000_000_000_000_000);
        let (q_perm, q_tmp) = (rng.u64(), rng.u64());
        let before = compute_harvest(&m, c_hdr, i, &p, q_perm, q_tmp).unwrap();

        // (a) A donation deposited by tag 21 raises C and I by the same x
        // (DECISIONS §2.2): D* is unchanged, so the payout bound D* − ε is too.
        let x = rng.below(1_000_000_000_000_000);
        let xi = x as i64;
        let m2 = MarginView {
            collateral: m.collateral + xi,
            free_collateral: m.free_collateral + xi,
            withdrawable_collateral: m.withdrawable_collateral + x,
            ..m
        };
        let after = compute_harvest(&m2, c_hdr + xi, i + x, &p, q_perm, q_tmp).unwrap();
        assert_eq!(after.d_star, before.d_star, "case {case}");
        assert!(after.d <= before.d_star - i128::from(p.epsilon()), "case {case}");
        // Unless the margin room was the binding clamp, D itself is unchanged.
        let by_margin = before.w - before.buf;
        if before.d_pre < by_margin {
            assert_eq!(after.d, before.d, "case {case}");
        }

        // (b) Tokens donated to vault_phusd / vault_usdc (not deposited) do not
        // enter the formula, and the arrival checks measure deltas only: the
        // same Phoenix/Ember result gives the same r and u whatever balance
        // was already there.
        let d = rng.below(1_000_000_000_000).max(1);
        // SPEC v4: any holdback of Phoenix (D − r) and Ember (r − u) is booked.
        let r = d - rng.below(d);
        let u = r - rng.below(r);
        let donation = rng.below(1_000_000_000_000);
        let (p0, q0) = (rng.below(1_000_000), rng.below(1_000_000));
        let clean_r = check_withdraw_arrival(p0, p0 + r, d);
        let donated_r = check_withdraw_arrival(p0 + donation, p0 + donation + r, d);
        assert_eq!(clean_r, Ok(r));
        assert_eq!(clean_r, donated_r);
        let clean_u = check_ember_arrival(p0, p0, q0, q0 + u, r);
        let donated_u = check_ember_arrival(p0 + donation, p0 + donation, q0 + donation, q0 + donation + u, r);
        assert_eq!(clean_u, Ok(u));
        assert_eq!(clean_u, donated_u);
    }
}

#[test]
fn accepted_payout_never_exceeds_d_star() {
    // u ≤ r ≤ D ≤ D* − ε for every (r, u) the arrival checks accept, with D
    // taken from compute_harvest and required ≥ d_min (SPEC §9.9 INV-2).
    let mut rng = Rng::new(0x5EED_0004);
    let mut accepted = 0u32;
    for case in 0..N {
        // Half the cases fully random (edges), half a realistic profitable pool.
        let (pb, m, c_hdr, i) = if case % 2 == 0 {
            (random_params(&mut rng), random_margin(&mut rng), rng.i64(), rng.u64())
        } else {
            realistic_state(&mut rng)
        };
        let p = HarvestParams::from_array(&pb);
        let (q_perm, q_tmp) = if rng.below(4) == 0 { (rng.u64(), rng.u64()) } else { (u64::MAX, u64::MAX) };
        let c = compute_harvest(&m, c_hdr, i, &p, q_perm, q_tmp).unwrap();
        if c.d < i128::from(p.d_min()) {
            continue;
        }
        let d = u64::try_from(c.d).unwrap();
        let phusd0 = rng.below(1 << 40);
        let usdc0 = rng.below(1 << 40);
        // Arbitrary Phoenix / Ember outcomes, including hostile ones.
        let r_raw = match rng.below(4) {
            0 => d,
            1 => d.saturating_sub(rng.below(d.saturating_add(2))),
            2 => d.saturating_add(rng.below(3)),
            _ => rng.u64(),
        };
        let Some(phusd1) = phusd0.checked_add(r_raw) else { continue };
        let Ok(r) = check_withdraw_arrival(phusd0, phusd1, d) else { continue };
        let u_raw = match rng.below(3) {
            0 => r,
            1 => r.saturating_sub(rng.below(r.saturating_add(2))),
            _ => rng.u64(),
        };
        let Some(usdc1) = usdc0.checked_add(u_raw) else { continue };
        let Ok(u) = check_ember_arrival(phusd0, phusd0, usdc0, usdc1, r) else { continue };
        accepted += 1;
        // Whatever arrives is booked, never more than requested: the
        // payout (O += u) stays within D ≤ D* − ε (SPEC v4, DECISIONS §23 item 6).
        assert!(0 < u && u <= r && r <= d, "case {case}");
        assert!(i128::from(d) <= c.d_star - i128::from(p.epsilon()), "case {case}");
    }
    assert!(accepted > 1_000, "too few accepted cases: {accepted}");
}

#[test]
fn split_gives_creator_at_most_twenty_percent() {
    let mut rng = Rng::new(0x5EED_0005);
    for _ in 0..N {
        let u = rng.u64();
        let (creator, buyback) = split_payout(u).unwrap();
        assert_eq!(u128::from(creator) + u128::from(buyback), u128::from(u));
        // creator = ⌊u/5⌋: at most 20%, and the remainder goes to the buyback.
        assert!(u128::from(creator) * 10_000 <= u128::from(u) * 2_000);
        assert!((u128::from(creator) + 1) * 10_000 > u128::from(u) * 2_000);
        assert!(u128::from(buyback) >= 4 * u128::from(creator));
    }
}

/// SPEC v4 (DECISIONS §23 item 6): no fee tolerance. Every holdback of
/// Phoenix and Ember is accepted and booked (`O += u`, `cum_withdraw_fees +=
/// D − u`); what is refused is only what is impossible for our own accounts:
/// nothing arrived, more than requested, a balance that fell, or Ember taking
/// other than exactly `r` PhUSD.
#[test]
fn any_holdback_is_booked() {
    let mut rng = Rng::new(0x5EED_0006);
    for _ in 0..N {
        let d = rng.u64().max(1);
        let r = d - rng.below(d);
        let u = r - rng.below(r);
        let (p0, q0) = (rng.below(1 << 40), rng.below(1 << 40));
        assert_eq!(check_withdraw_arrival(p0, p0 + r, d), Ok(r));
        assert_eq!(check_ember_arrival(p0, p0, q0, q0 + u, r), Ok(u));
        let (creator, buyback) = split_payout(u).unwrap();
        let n = Ledger::default().apply(&Payout { d, r, u, creator, buyback }, false, 0, 0).unwrap();
        assert_eq!((n.o, n.cum_withdraw_fees), (u, d - u));
        // The impossible outcomes stay refused.
        assert_eq!(check_withdraw_arrival(p0, p0, d), Err(SijkaError::WithdrawNotImmediate));
        if d < u64::MAX - (1 << 41) {
            assert_eq!(check_withdraw_arrival(p0, p0 + d + 1, d), Err(SijkaError::WithdrawAmountMismatch));
        }
        assert_eq!(check_ember_arrival(p0, p0, q0, q0, r), Err(SijkaError::EmberAmountMismatch));
        assert_eq!(check_ember_arrival(p0, p0 + 1, q0, q0 + u, r), Err(SijkaError::EmberAmountMismatch));
        if r < u64::MAX - (1 << 41) {
            assert_eq!(check_ember_arrival(p0, p0, q0, q0 + r + 1, r), Err(SijkaError::EmberAmountMismatch));
        }
    }
}

#[test]
fn ledger_counters_are_monotonic_and_exact() {
    let mut rng = Rng::new(0x5EED_0007);
    for _ in 0..(N / 40) {
        let mut l = Ledger { last_harvest_ts: rng.below(1 << 40) as i64, ..Ledger::default() };
        let mut now = l.last_harvest_ts;
        for _ in 0..40 {
            let d = rng.below(1_000_000_000_000).max(1);
            let r = d - rng.below(d);
            let u = r - rng.below(r);
            let (creator, buyback) = split_payout(u).unwrap();
            let held = rng.next() & 1 == 1;
            now += rng.below(1_000_000) as i64;
            let p = Payout { d, r, u, creator, buyback };
            let n = l.apply(&p, held, now, rng.next()).unwrap();
            // O grows exactly by the paid amount (u, not D or r).
            assert_eq!(n.o, l.o + u);
            assert_eq!(n.cum_payout_creator, l.cum_payout_creator + creator);
            assert_eq!(n.cum_payout_buyback, l.cum_payout_buyback + buyback);
            assert_eq!(n.cum_withdraw_fees, l.cum_withdraw_fees + (d - u));
            assert_eq!(n.harvest_count, l.harvest_count + 1);
            assert_eq!(n.o, n.cum_payout_creator + n.cum_payout_buyback);
            // Cumulative creator share never exceeds 20% of O (sum of floors ≤ floor of sum).
            assert!(u128::from(n.cum_payout_creator) * 10_000 <= u128::from(n.o) * 2_000);
            assert_eq!(n.last_harvest_ts, if held { l.last_harvest_ts } else { now });
            assert!(n.last_harvest_ts >= l.last_harvest_ts);
            l = n;
        }
    }
}

/// DECISIONS §23 item 7 against a model: with the anchor `initialize` writes
/// (`created_ts − t_min_secs`), the `T_min` gate is open from `created_ts`
/// on; after a harvest that moves the timer the next one waits exactly
/// `T_min`; a `timer_held` harvest (RT-5) changes nothing. Model: `next =
/// created`, then `next = now + t_min` after each timer-moving harvest.
#[test]
fn harvest_timer_from_initialize() {
    let mut rng = Rng::new(0x5EED_0011);
    let p = Payout { d: 10, r: 10, u: 10, creator: 2, buyback: 8 };
    for _ in 0..(N / 20) {
        let created = rng.below(1 << 40) as i64;
        let t_min = match rng.below(4) {
            0 => 0,
            1 => 604_800,
            2 => rng.below(1 << 20) as u32,
            _ => rng.next() as u32,
        };
        let mut l = Ledger { last_harvest_ts: initial_last_harvest_ts(created, t_min).unwrap(), ..Ledger::default() };
        let mut next = created;
        let mut now = created;
        for _ in 0..20 {
            now += rng.below(2 * u64::from(t_min) + 2) as i64;
            let g = GateInputs {
                recovery_mode: 0,
                now,
                last_harvest_ts: l.last_harvest_ts,
                t_min_secs: t_min,
                max_buyback_backlog: 0,
                buyback_usdc: 0,
                cooldown_slots: 0,
                last_deposit_slot: 0,
                slot: 0,
                queue: QueueState::UNPARSED,
            };
            assert_eq!(g.next_allowed_ts(), next);
            let open = early_gate(&g) == HarvestStatus::Ready;
            assert_eq!(open, now >= next, "created {created} t_min {t_min} now {now} next {next}");
            if open {
                let held = rng.next() & 1 == 1;
                l = l.apply(&p, held, now, 0).unwrap();
                if !held {
                    next = now + i64::from(t_min);
                }
            }
        }
    }
}

/// Whole-pool model: deposits (fees and donations), realized PnL, open PnL
/// and harvests with any Phoenix/Ember holdbacks (SPEC v4). Checks the
/// high-water-mark property: a harvest pays only the trading result above the
/// payouts so far (`O + u ≤ G − ε` with `G = E + O − I`), deposits never make
/// a payout, `I` and `O` only grow, creator ≤ 20% of `O` (SPEC §5.4.1, §9.9).
#[test]
fn pool_model_high_water_mark() {
    let mut rng = Rng::new(0x5EED_0008);
    const USDC: i128 = 1_000_000;
    let mut harvests = 0u32;
    for _ in 0..(N / 100) {
        let pb = {
            let mut b = [0u8; 64];
            let mut m = HarvestParamsMut::from_array(&mut b);
            m.set_epsilon(rng.below(2_000_000));
            m.set_d_min(rng.below(50_000_000).max(1));
            m.set_margin_buffer_abs(rng.below(10_000_000));
            m.set_max_harvest_per_call(rng.below(500_000_000_000).max(50_000_000));
            m.set_margin_buffer_im_bps(rng.below(10_001) as u32);
            b
        };
        let p = HarvestParams::from_array(&pb);
        let (mut c, mut i, mut upnl, mut im): (i128, u64, i128, u64) = (0, 0, 0, 0);
        let mut l = Ledger::default();
        for _ in 0..100 {
            match rng.below(6) {
                // Inflow (fees or a donation deposited by tag 21): capital.
                0 => {
                    let x = rng.below(10_000 * 1_000_000);
                    let before = compute_harvest(&view(c, upnl, im), c as i64, i, &p, u64::MAX, u64::MAX).unwrap();
                    c += i128::from(x);
                    i += x;
                    let after = compute_harvest(&view(c, upnl, im), c as i64, i, &p, u64::MAX, u64::MAX).unwrap();
                    assert_eq!(after.d_star, before.d_star, "an inflow is never profit");
                }
                // Realized PnL.
                1 | 2 => c += i128::from(rng.below(2_000 * 1_000_000) as i64 - 1_000 * USDC as i64),
                // Open PnL and margin.
                3 => {
                    upnl = i128::from(rng.below(2_000 * 1_000_000) as i64 - 1_000 * USDC as i64);
                    im = rng.below(500 * 1_000_000);
                }
                // Harvest.
                _ => {
                    let calc = compute_harvest(&view(c, upnl, im), c as i64, i, &p, u64::MAX, u64::MAX).unwrap();
                    if calc.d < i128::from(p.d_min()) {
                        continue;
                    }
                    let d = u64::try_from(calc.d).unwrap();
                    // Holdbacks of any size (SPEC v4: no tolerance), mostly small.
                    let cap = if rng.below(4) == 0 { d - 1 } else { (d / 100).min(d - 1) };
                    let k1 = rng.below(cap + 1);
                    let k2 = rng.below(d - k1);
                    let r = check_withdraw_arrival(0, d - k1, d).unwrap();
                    let u = check_ember_arrival(0, 0, 0, r - k2, r).unwrap();
                    let (creator, buyback) = split_payout(u).unwrap();
                    let g_before = c + upnl - i128::from(i) + i128::from(l.o);
                    // HWM: only the result above O is paid, minus ε.
                    assert!(
                        i128::from(l.o) + i128::from(u) <= g_before - i128::from(p.epsilon()),
                        "payout above the high-water mark"
                    );
                    let n = l.apply(&Payout { d, r, u, creator, buyback }, calc.timer_held, 0, 0).unwrap();
                    harvests += 1;
                    assert_eq!(n.o - l.o, u);
                    assert!(n.o >= l.o);
                    assert!(u128::from(n.cum_payout_creator) * 10_000 <= u128::from(n.o) * 2_000);
                    // Phoenix debits D from the collateral (holdbacks are pool costs).
                    c -= i128::from(d);
                    l = n;
                    // Right after a harvest nothing more is payable (D* ≤ ε + margin effects).
                    let again = compute_harvest(&view(c, upnl, im), c as i64, i, &p, u64::MAX, u64::MAX).unwrap();
                    assert!(again.d_star <= calc.d_star - calc.d);
                }
            }
        }
    }

    assert!(harvests > 500, "too few harvests in the model: {harvests}");

    fn view(c: i128, upnl: i128, im: u64) -> MarginView {
        let free = c + upnl.min(0) - i128::from(im);
        MarginView {
            collateral: c as i64,
            unrealized_pnl: upnl as i64,
            free_collateral: free as i64,
            withdrawable_collateral: free.max(0) as u64,
            initial_margin: im,
            ..MarginView::default()
        }
    }
}

#[test]
fn parsers_never_panic_on_garbage() {
    // Random bytes in the trader, PAM and queue views: errors or counts, no panics.
    let mut rng = Rng::new(0x5EED_0009);
    for _ in 0..2_000 {
        let tl = rng.below(700) as usize;
        let mut trader: Vec<u8> = (0..tl).map(|_| rng.next() as u8).collect();
        if trader.len() >= 232 && rng.next() & 1 == 0 {
            let len = rng.below(12);
            trader[224..232].copy_from_slice(&len.to_le_bytes());
        }
        let pl = if rng.next() & 1 == 0 { rng.below(200) as usize } else { 48 + 1584 * rng.below(3) as usize };
        let mut pam: Vec<u8> = (0..pl).map(|_| rng.next() as u8).collect();
        if pam.len() >= 36 && rng.next() & 1 == 0 {
            pam[32..36].copy_from_slice(&(rng.below(4) as u32).to_le_bytes());
        }
        let _ = scan_position_marks(&trader, &pam, rng.next(), rng.u64().max(1));
        let q: Vec<u8> = (0..rng.below(200)).map(|_| rng.next() as u8).collect();
        let s = parse_withdraw_queue(&PHOENIX_PROGRAM_ID, &q, rng.next());
        assert!(s.cap() <= s.q_perm && s.cap() <= s.q_tmp);
    }
}
