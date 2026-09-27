// Copyright (c) 2026 prt1sn. All rights reserved.
//! Tag 30 `harvest`, tag 31 `harvest_preview` and tag 32 `pay_creator` on the
//! mainnet Phoenix / Hawkeye / Ember binaries (SPEC §5.4; TH-1…TH-3, TH-7,
//! TH-8, TH-13, TH-16…TH-18, TH-20, TH-22, TH-26). Expected numbers are
//! recomputed here from a Hawkeye `ViewMargin` taken in the same state, with
//! the formulas of SPEC §5.4.1 (independent of the program's own code).

use phoenix_rise::ix::types::Side;
use solana_pubkey::Pubkey;

use crate::abi;
use crate::harness::*;
use crate::ixs::*;
use crate::phx::*;

const DISC_WITHDRAW_QUEUE: [u8; 8] = [0x7d, 0x3b, 0x5e, 0x6c, 0xab, 0x10, 0x2b, 0xe4];

/// SPEC §5.4.1 `compute_harvest`, re-implemented for the assertions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Expect {
    pub c: i128,
    pub d_star: i128,
    pub w: i128,
    pub buf: i128,
    pub d: i128,
    pub timer_held: bool,
    pub queue_limited: bool,
    pub q_cap: u64,
}

pub struct Inputs {
    pub m: Margin,
    pub c_hdr: i64,
    pub i: u64,
    pub q_perm: u64,
    pub q_tmp: u64,
    pub total_queued: u64,
}

impl Env {
    pub fn hp(&self, f: &str) -> u64 {
        self.cfg_harvest_u64(f)
    }

    /// `(Q_perm, Q_tmp, total_queued)` from the withdraw queue header, as the
    /// program reads it (SPEC §5.4.2 step 5); `u64::MAX` when not parsed.
    pub fn queue_caps(&self) -> (u64, u64, u64) {
        let d = self.data(&self.fx.withdraw_queue);
        let parsed =
            self.owner(&self.fx.withdraw_queue) == Some(PHOENIX) && d.len() >= 120 && d[0..8] == DISC_WITHDRAW_QUEUE;
        if !parsed {
            return (u64::MAX, u64::MAX, 0);
        }
        let u = |o: usize| u64::from_le_bytes(d[o..o + 8].try_into().unwrap());
        let (slot, _) = self.clock();
        let tmp = u128::from(u(wq::REMAINING))
            + u128::from(u(wq::REPLENISH)) * u128::from(slot.saturating_sub(u(wq::LAST_UPDATE)));
        (u(wq::MAX_BUDGET), u64::try_from(tmp).unwrap_or(u64::MAX), u(wq::TOTAL_QUEUED))
    }

    pub fn harvest_inputs(&mut self) -> Inputs {
        let t = self.pdas.trader.0;
        let m = self.margin(&t);
        let (q_perm, q_tmp, total_queued) = self.queue_caps();
        Inputs {
            m,
            c_hdr: self.our_trader().collateral,
            i: self.cfg_u64("cum_inflow_usdc"),
            q_perm,
            q_tmp,
            total_queued,
        }
    }

    pub fn expect_harvest(&self, x: &Inputs) -> Expect {
        let m = &x.m;
        let c = i128::from(m.c_hk).min(i128::from(x.c_hdr));
        let d_star = c - i128::from(x.i) + (i128::from(m.upnl) + i128::from(m.funding)).min(0);
        let w = i128::from(m.free.max(0)).min(i128::from(m.wd));
        let im_part = (i128::from(m.im) * i128::from(self.hp("margin_buffer_im_bps")) + 9_999) / 10_000;
        let buf = i128::from(self.hp("margin_buffer_abs")).max(im_part);
        let d_pre =
            (d_star - i128::from(self.hp("epsilon"))).min(w - buf).min(i128::from(self.hp("max_harvest_per_call")));
        let d_perm = d_pre.min(i128::from(x.q_perm));
        let d = d_perm.min(i128::from(x.q_tmp));
        Expect { c, d_star, w, buf, d, timer_held: d < d_perm, queue_limited: d < d_pre, q_cap: x.q_perm.min(x.q_tmp) }
    }

    /// Vault trade with a realized profit: buy `lots` SOL at the fixture ask,
    /// counterparty `taker0` bids higher after the price moves, sell RO into it.
    pub fn realize_sol_profit(&mut self, lots: u64) {
        let px = self.ticks_for("SOL", 151_000);
        ok(self.send1(self.ioc_ix("SOL", 0, false, px, lots), S_BOT), "vault IOC buy at the fixture ask");
        let sol = self.pam_entry("SOL").asset_id;
        let pos = |h: &TraderHdr| h.positions.iter().find(|(a, _)| (*a as u32) == sol).map_or(0, |p| p.1);
        assert_eq!(pos(&self.our_trader()), lots as i64, "long after the buy");
        self.cancel_fixture_levels();
        self.set_price_milli("SOL", 160_000);
        let bid_px = self.ticks_for("SOL", 159_000);
        ok(self.actor_limit("taker0", "SOL", Side::Bid, bid_px, lots), "counterparty bid (taker0)");
        let sell_px = self.ticks_for("SOL", 155_000);
        ok(self.send1(self.ioc_ix("SOL", 1, true, sell_px, lots), S_BOT), "vault RO IOC sell into the bid");
        assert_eq!(pos(&self.our_trader()), 0, "flat after the sell");
    }

    /// Profit without trading: `taker0` sends collateral to our trader (U-47).
    pub fn gift(&mut self, amount: u64) {
        let t = self.pdas.trader.0;
        ok(self.actor_gift_collateral("taker0", &t, amount), "TransferCollateral gift");
    }
}

/// Check one successful harvest against the expectation: event, return data,
/// token deltas, Config counters (SPEC §5.4.2 steps 13–19).
pub fn check_harvest(env: &mut Env, x: &Inputs, ex: &Expect, label: &str) -> (u64, u64, u64) {
    let (esc, bb, vu, vp) = (env.escrow_usdc(), env.buyback_usdc(), env.vault_usdc(), env.vault_phusd());
    let (esc0, bb0, vu0, vp0) =
        (env.token_amount(&esc), env.token_amount(&bb), env.token_amount(&vu), env.token_amount(&vp));
    let o0 = env.cfg_u64("cum_payout_usdc");
    let (pc0, pb0, fees0, n0) = (
        env.cfg_u64("cum_payout_creator"),
        env.cfg_u64("cum_payout_buyback"),
        env.cfg_u64("cum_withdraw_fees"),
        env.cfg_u64("harvest_count"),
    );
    let ts_before = env.cfg_i64("last_harvest_ts");
    let pv = env.preview();
    let hp = abi::harvest_preview();
    assert_eq!(hp.u8(&pv, "status"), 0, "{label}: preview Ready");
    assert_eq!(i128::from(hp.i64(&pv, "D")), ex.d, "{label}: preview D");

    let (slot, now) = env.clock();
    let m = ok(env.harvest(), label);
    eprintln!("{label}: harvest CU {}", m.compute_units_consumed);
    let ev = one_event(&m.logs, "SJKEVHRV");
    assert_eq!(m.return_data.program_id, env.program);
    assert_eq!(m.return_data.data, ev, "{label}: return data = event payload");
    let e = abi::event("SJKEVHRV");
    let d = e.u64(&ev, "D");
    let r = e.u64(&ev, "r");
    let u = e.u64(&ev, "usdc_received");
    let creator = e.u64(&ev, "creator");
    let buyback = e.u64(&ev, "buyback");
    eprintln!(
        "{label}: D {d} r {r} u {u} creator {creator} buyback {buyback} D* {} W {} buf {}",
        ex.d_star, ex.w, ex.buf
    );
    // The amount (SPEC §5.4.1).
    assert_eq!(i128::from(d), ex.d, "{label}: D");
    assert_eq!(i128::from(e.i64(&ev, "D_star")), ex.d_star, "{label}: D*");
    assert_eq!(i128::from(e.u64(&ev, "W")), ex.w, "{label}: W");
    assert_eq!(i128::from(e.u64(&ev, "buf")), ex.buf, "{label}: buf");
    assert_eq!(e.i64(&ev, "C_hk"), x.m.c_hk);
    assert_eq!(e.i64(&ev, "C_hdr"), x.c_hdr);
    assert_eq!(e.i64(&ev, "U"), x.m.upnl);
    assert_eq!(e.i64(&ev, "F"), x.m.funding);
    assert_eq!(e.u64(&ev, "IM"), x.m.im);
    assert_eq!(e.u64(&ev, "I"), x.i);
    assert_eq!(e.u64(&ev, "queue_cap"), ex.q_cap);
    let bits = e.u8(&ev, "bits");
    assert_eq!(bits & 1 != 0, ex.queue_limited, "{label}: bits.0 queue limited ({bits:#b})");
    assert_eq!(bits & 2 != 0, ex.timer_held, "{label}: bits.1 timer held ({bits:#b})");
    // Preview = event (SPEC TH-2: event equals harvest_preview before the call).
    for (pf, ef) in [("D_star", "D_star"), ("C_hk", "C_hk"), ("C_hdr", "C_hdr"), ("U", "U"), ("F", "F")] {
        assert_eq!(hp.i64(&pv, pf), e.i64(&ev, ef), "{label}: preview {pf}");
    }
    for (pf, ef) in [("W", "W"), ("buf", "buf"), ("IM", "IM"), ("I", "I"), ("queue_cap", "queue_cap")] {
        assert_eq!(hp.u64(&pv, pf), e.u64(&ev, ef), "{label}: preview {pf}");
    }
    assert_eq!(hp.u8(&pv, "bits") & 3, bits & 3, "{label}: preview bits");
    // Arrival: 0 < u ≤ r ≤ D (SPEC v4: no tolerance); the fixture takes no fee.
    assert!(0 < u && u <= r && r <= d, "{label}: arrival r {r} u {u} D {d}");
    assert_eq!(r, d, "{label}: Phoenix delivered exactly D");
    assert_eq!(u, r, "{label}: Ember unwrapped 1:1");
    // 20 / 80 split, floor for the creator.
    assert_eq!(creator, u * 2000 / 10_000, "{label}: creator = floor(u*2000/1e4)");
    assert_eq!(buyback, u - creator, "{label}: buyback = u - creator");
    assert_eq!(env.token_amount(&esc), esc0 + creator, "{label}: escrow delta");
    assert_eq!(env.token_amount(&bb), bb0 + buyback, "{label}: buyback_usdc delta");
    assert_eq!(env.token_amount(&vu), vu0, "{label}: vault_usdc unchanged");
    assert_eq!(env.token_amount(&vp), vp0, "{label}: vault_phusd unchanged");
    // Config (step 18).
    assert_eq!(env.cfg_u64("cum_payout_usdc"), o0 + u, "{label}: O += u");
    assert_eq!(e.u64(&ev, "O_after"), o0 + u);
    assert_eq!(env.cfg_u64("cum_payout_creator"), pc0 + creator);
    assert_eq!(env.cfg_u64("cum_payout_buyback"), pb0 + buyback);
    assert_eq!(env.cfg_u64("cum_payout_usdc"), env.cfg_u64("cum_payout_creator") + env.cfg_u64("cum_payout_buyback"));
    assert_eq!(env.cfg_u64("cum_withdraw_fees"), fees0 + (d - u));
    assert_eq!(env.cfg_u64("harvest_count"), n0 + 1);
    assert_eq!(e.u64(&ev, "harvest_count"), n0 + 1);
    assert_eq!(env.cfg_u64("last_harvest_slot"), slot);
    assert_eq!(env.cfg_u64("last_harvest_amount"), u);
    let want_ts = if ex.timer_held { ts_before } else { now };
    assert_eq!(env.cfg_i64("last_harvest_ts"), want_ts, "{label}: last_harvest_ts (timer held {})", ex.timer_held);
    assert_eq!(env.cfg_u64("cum_inflow_usdc"), x.i, "{label}: I unchanged");
    (d, creator, buyback)
}

#[test]
fn harvest_end_to_end_real_trade_profit() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(10_000_000_000);
    env.realize_sol_profit(1000);
    let c_after_trades = env.our_trader().collateral;
    eprintln!("collateral after round trip: {c_after_trades} (I = {})", env.cfg_u64("cum_inflow_usdc"));
    assert!(c_after_trades > 10_000_000_000 + 50_000_000, "realized profit > 50 USDC");

    // DECISIONS §23 item 7: the first harvest right away, no T_min wait
    // (initialize wrote last_harvest_ts = created_ts - t_min_secs).
    let hp = abi::harvest_preview();
    let created = env.cfg_i64("created_ts");
    let t_min = env.hp("t_min_secs") as i64;
    assert_eq!(env.cfg_i64("last_harvest_ts"), created - t_min);
    assert_eq!(env.cfg_u64("harvest_count"), 0);
    let pv = env.preview();
    assert_eq!(hp.u8(&pv, "status"), 0, "Ready: the first harvest needs no T_min");
    assert_eq!(hp.i64(&pv, "next_allowed_ts"), created);

    let x = env.harvest_inputs();
    let ex = env.expect_harvest(&x);
    assert_eq!(x.m.position_count, 0);
    assert_eq!((x.m.risk_tier, x.m.liq, x.m.risk_state), (0, 0, 0), "healthy (U-18: risk_state 0)");
    assert!(ex.d > 50_000_000, "D = realized profit - epsilon");
    assert_eq!(ex.d, ex.d_star - i128::from(env.hp("epsilon")), "D = D* - eps (no clamp binds)");
    let (_, creator, _) = check_harvest(&mut env, &x, &ex, "harvest after the round trip");

    // The second one waits T_min, then nothing is left above epsilon.
    let (_, now) = env.clock();
    assert_eq!(env.cfg_i64("last_harvest_ts"), now, "the first harvest moved the timer");
    expect_err(env.harvest(), "HarvestTooEarly", "second harvest right away");
    let pv = env.preview();
    assert_eq!(hp.u8(&pv, "status"), 1);
    assert_eq!(hp.i64(&pv, "next_allowed_ts"), now + t_min);
    env.pass_t_min();
    expect_err(env.harvest(), "HarvestBelowMinimum", "only epsilon left");
    let pv = env.preview();
    assert_eq!(hp.u8(&pv, "status"), 2, "BelowMinimum");

    // pay_creator moves the whole escrow (SPEC §5.4.5).
    let (esc, cu) = (env.escrow_usdc(), env.creator_usdc());
    let cu0 = env.token_amount(&cu);
    let m = ok(env.send1(env.pay_creator_ix(), S_PAYER), "pay_creator");
    assert_eq!(env.token_amount(&esc), 0);
    assert_eq!(env.token_amount(&cu), cu0 + creator);
    assert_eq!(env.cfg_u64("cum_creator_paid_out"), creator);
    assert_eq!(env.cfg_u64("creator_pay_count"), 1);
    assert_eq!(env.cfg_u64("cum_payout_creator"), creator, "O-side counters unchanged by tag 32");
    let ev = one_event(&m.logs, "SJKEVPCR");
    assert_eq!(ev.len(), abi::event("SJKEVPCR").size);
    expect_err(env.send1(env.pay_creator_ix(), S_PAYER), "CreatorPayNothing", "empty escrow");
    // U-3: the preference bits survived activation, trades, deposit, withdraw.
    let h = env.our_trader();
    assert_eq!((h.prefs, h.max_positions), (0b11, 128));
}

/// TH-16: with several gates closed at once, the preview status and the
/// tag 30 error follow the same order (SPEC §5.4.3: TooEarly → BuybackBacklog
/// → Cooldown → QueueBusy → … → Ready); `T_min` is inclusive at
/// `last_harvest_ts + t_min_secs`. `T_min` binds only after a harvest
/// (DECISIONS §23 item 7), so a first harvest runs here first.
#[test]
fn harvest_gate_order_matches_preview() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(0);
    let cd = 1_500u64;
    env.set_deposit_cooldown(cd);
    let (_, ts0) = env.clock();
    let dep_slot = 216_000 + cd + 9_000;
    env.set_clock(dep_slot, ts0);
    env.refresh_prices();
    ok(env.deposit(1_000_000_000), "deposit");
    env.gift(60_000_000);
    // The first harvest: no T_min, only the Phoenix cooldown of the deposit.
    env.set_clock(dep_slot + cd, ts0);
    env.refresh_prices();
    let x = env.harvest_inputs();
    let ex = env.expect_harvest(&x);
    check_harvest(&mut env, &x, &ex, "first harvest, no T_min");
    let h0 = env.cfg_i64("last_harvest_ts");
    assert_eq!(h0, ts0);
    // A second deposit (outside the tag 21 quiet window) restarts the cooldown.
    let dep2 = dep_slot + cd + 1;
    env.set_clock(dep2, h0);
    env.refresh_prices();
    ok(env.deposit(1_000_000_000), "second deposit");
    env.gift(60_000_000);
    let bb = env.buyback_usdc();
    env.mint_usdc(&bb, 2_000_000);
    env.set_harvest_params(&with(harvest_params_default(), "max_buyback_backlog", 1_000_000));
    env.wq_set(wq::TOTAL_QUEUED, 5);
    let hp = abi::harvest_preview();
    let t_min = env.hp("t_min_secs") as i64;
    let step = |env: &mut Env, status: u8, err: &str, label: &str| {
        let pv = env.preview();
        assert_eq!(hp.u8(&pv, "status"), status, "{label}: preview status");
        expect_err(env.harvest(), err, label);
    };
    // Every gate closed; T_min one second short.
    env.set_clock(dep2 + 10, h0 + t_min - 1);
    env.refresh_prices();
    step(&mut env, 1, "HarvestTooEarly", "T_min - 1 s, all gates closed");
    let pv = env.preview();
    assert_eq!(hp.i64(&pv, "next_allowed_ts"), h0 + t_min);
    assert_eq!(hp.u64(&pv, "cooldown_until_slot"), dep2 + cd);
    assert_eq!(hp.u64(&pv, "total_queued"), 5);
    // Exactly at T_min: the next gate.
    env.set_clock(dep2 + 20, h0 + t_min);
    env.refresh_prices();
    step(&mut env, 5, "HarvestBuybackBacklog", "T_min reached; backlog");
    env.set_harvest_params(&harvest_params_default());
    step(&mut env, 7, "WithdrawCooldown", "cooldown");
    env.set_clock(dep2 + cd, h0 + t_min + 5);
    env.refresh_prices();
    step(&mut env, 6, "WithdrawQueueBusy", "queue busy");
    env.wq_set(wq::TOTAL_QUEUED, 0);
    assert_eq!(hp.u8(&env.preview(), "status"), 0);
    let x = env.harvest_inputs();
    let ex = env.expect_harvest(&x);
    check_harvest(&mut env, &x, &ex, "all gates open");
}

/// TH-3 (DECISIONS §23 item 7): the first harvest runs right after
/// `initialize`, without any clock move (`initialize` wrote `last_harvest_ts
/// = created_ts − t_min_secs`). A first harvest whose `D` the transient queue
/// budget cut (`timer_held`, review RT-5) leaves the timer where it was, so
/// the next harvest still runs at once; that one moves the timer, and the
/// one after it waits `T_min` (inclusive at `last_harvest_ts + t_min_secs`).
#[test]
fn first_harvest_at_once_second_after_t_min() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(1_000_000_000);
    let hp = abi::harvest_preview();
    let created = env.cfg_i64("created_ts");
    let t_min = env.hp("t_min_secs") as i64;
    assert!(t_min > 0);
    let anchor = created - t_min;
    assert_eq!(env.cfg_i64("last_harvest_ts"), anchor, "initialize: created_ts - t_min_secs");
    assert_eq!(env.cfg_u64("harvest_count"), 0);
    env.gift(100_000_000);
    let (slot, now0) = env.clock();
    assert!(now0 >= created);
    let pv = env.preview();
    assert_eq!(hp.u8(&pv, "status"), 0, "no T_min before the first harvest");
    assert_eq!(hp.i64(&pv, "next_allowed_ts"), created);

    // First harvest cut by the transient budget: D = remaining, timer held.
    let mb = env.wq_u64(wq::MAX_BUDGET);
    env.wq_set(wq::REMAINING, 30_000_000);
    env.wq_set(wq::LAST_UPDATE, slot);
    let x = env.harvest_inputs();
    let ex = env.expect_harvest(&x);
    assert_eq!(ex.d, 30_000_000);
    assert!(ex.timer_held);
    check_harvest(&mut env, &x, &ex, "first harvest, timer held");
    assert_eq!(env.cfg_i64("last_harvest_ts"), anchor, "a held first harvest keeps the anchor");
    assert_eq!(env.cfg_u64("harvest_count"), 1);

    // The budget refills: the next harvest runs at once and moves the timer.
    env.wq_set(wq::REMAINING, mb);
    let x = env.harvest_inputs();
    let ex = env.expect_harvest(&x);
    assert!(!ex.timer_held && ex.d >= 25_000_000);
    check_harvest(&mut env, &x, &ex, "second harvest right after the held one");
    let (_, h1) = env.clock();
    assert_eq!(env.cfg_i64("last_harvest_ts"), h1);
    assert_eq!(env.cfg_u64("harvest_count"), 2);

    // Every later harvest waits T_min.
    env.gift(50_000_000);
    let pv = env.preview();
    assert_eq!(hp.u8(&pv, "status"), 1, "TooEarly right after a timer-moving harvest");
    assert_eq!(hp.i64(&pv, "next_allowed_ts"), h1 + t_min);
    expect_err(env.harvest(), "HarvestTooEarly", "third harvest right away");
    env.set_clock(slot + 10, h1 + t_min - 1);
    env.refresh_prices();
    expect_err(env.harvest(), "HarvestTooEarly", "T_min - 1 s");
    env.set_clock(slot + 20, h1 + t_min);
    env.refresh_prices();
    let x = env.harvest_inputs();
    let ex = env.expect_harvest(&x);
    check_harvest(&mut env, &x, &ex, "exactly at last_harvest_ts + t_min_secs");
    assert_eq!(env.cfg_i64("last_harvest_ts"), h1 + t_min);
    assert_eq!(env.cfg_u64("harvest_count"), 3);
}

/// SPEC §5.4.2 step 13 on the real Phoenix: during exchange maintenance
/// `withdraw_funds` does not pay out at once. Harvest must not succeed and
/// must leave no trace (queued request rolled back with the transaction).
#[test]
fn harvest_during_exchange_maintenance() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(1_000_000_000);
    env.gift(30_000_000);
    env.pass_t_min();
    env.set_exchange_status(None, None, Some(true));
    eprintln!("exchange status in maintenance: {:#010b}", env.exchange_status());
    let q0 = env.wq_u64(wq::TOTAL_QUEUED);
    let o0 = env.cfg_u64("cum_payout_usdc");
    let c0 = env.our_trader().collateral;
    let r = env.harvest();
    match &r {
        Ok(m) => panic!("harvest succeeded in maintenance\n{}", m.logs.join("\n")),
        Err(e) => {
            let ours = e.meta.logs.iter().find(|l| l.contains("Sijka: ")).cloned();
            let enq = log_contains(&e.meta.logs, "enqueued");
            eprintln!("harvest in maintenance: {:?}; our error line {ours:?}; Phoenix enqueued: {enq}", e.err);
        }
    }
    assert_eq!(env.wq_u64(wq::TOTAL_QUEUED), q0, "nothing left in the queue");
    assert_eq!(env.cfg_u64("cum_payout_usdc"), o0);
    assert_eq!(env.our_trader().collateral, c0);
    env.set_exchange_status(None, None, Some(false));
    let x = env.harvest_inputs();
    let ex = env.expect_harvest(&x);
    check_harvest(&mut env, &x, &ex, "after maintenance");
}

/// TH-7: `u = 12 345 678` → creator 2 469 135, buyback 9 876 543. The profit
/// is a collateral gift through `TransferCollateral` (U-47): it bypasses `I`.
#[test]
fn harvest_rounding_split_on_gift() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(1_000_000_000);
    env.set_harvest_params(&with(harvest_params_default(), "epsilon", 0));
    let lds = env.our_trader().last_deposit_slot;
    env.gift(12_345_678);
    assert_eq!(env.cfg_u64("cum_inflow_usdc"), 1_000_000_000, "U-47: the gift is not I");
    assert_eq!(env.our_trader().last_deposit_slot, lds, "U-47: @192 of the receiver unchanged");
    env.pass_t_min();
    let x = env.harvest_inputs();
    let ex = env.expect_harvest(&x);
    assert_eq!(ex.d, 12_345_678);
    let (d, creator, buyback) = check_harvest(&mut env, &x, &ex, "rounding");
    assert_eq!((d, creator, buyback), (12_345_678, 2_469_135, 9_876_543));
}

/// Smallest payouts (`ε = 0`, `d_min = 1`): `u = 4` pays the creator 0 (no
/// escrow transfer) and the buyback 4; `u = 5` pays 1 / 4. Then the counters
/// near `u64::MAX`: `O` overflow reverts the whole harvest (MathOverflow).
#[test]
fn harvest_tiny_amounts_and_overflow() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(1_000_000_000);
    env.set_harvest_params(&with(with(with(harvest_params_default(), "epsilon", 0), "d_min", 1), "t_min_secs", 0));
    for (gift, creator, buyback) in [(4u64, 0u64, 4u64), (5, 1, 4), (1, 0, 1)] {
        env.gift(gift);
        let x = env.harvest_inputs();
        let ex = env.expect_harvest(&x);
        assert_eq!(ex.d, i128::from(gift));
        let got = check_harvest(&mut env, &x, &ex, &format!("u = {gift}"));
        assert_eq!(got, (gift, creator, buyback));
    }
    // O near u64::MAX: the checked add fails after the CPIs, everything reverts.
    env.gift(10_000_000);
    let cfg = env.pdas.config.0;
    let f = abi::config().field("cum_payout_usdc").offset;
    let o_max = u64::MAX - 1_000;
    env.patch(&cfg, |d| d[f..f + 8].copy_from_slice(&o_max.to_le_bytes()));
    let (esc, bb) = (env.escrow_usdc(), env.buyback_usdc());
    let (e0, b0, c0) = (env.token_amount(&esc), env.token_amount(&bb), env.our_trader().collateral);
    expect_err(env.harvest(), "MathOverflow", "O + u overflows");
    assert_eq!((env.token_amount(&esc), env.token_amount(&bb), env.our_trader().collateral), (e0, b0, c0));
    assert_eq!(env.cfg_u64("cum_payout_usdc"), o_max);
}

/// TC-28: `I` next to `u64::MAX` — the deposit reverts with MathOverflow and
/// nothing moves.
#[test]
fn deposit_i_overflow() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(0);
    let cfg = env.pdas.config.0;
    let f = abi::config().field("cum_inflow_usdc").offset;
    let i_max = u64::MAX - 5_000_000;
    env.patch(&cfg, |d| d[f..f + 8].copy_from_slice(&i_max.to_le_bytes()));
    let vu = env.vault_usdc();
    env.mint_usdc(&vu, 10_000_000);
    let c0 = env.our_trader().collateral;
    expect_err(env.send1(env.deposit_ix(0), S_PAYER), "MathOverflow", "I + dep overflows");
    assert_eq!(env.token_amount(&vu), 10_000_000);
    assert_eq!(env.our_trader().collateral, c0);
    ok(env.send1(env.deposit_ix(5_000_000), S_PAYER), "exactly up to u64::MAX");
    assert_eq!(env.cfg_u64("cum_inflow_usdc"), u64::MAX);
}

/// TH-1, D_min, backlog gate (TH-18), pause (TH-17), busy queue (TH-22) and
/// the preview status of each (TH-16).
#[test]
fn harvest_gates_before_any_cpi() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(1_000_000_000);
    env.pass_t_min();
    let hp = abi::harvest_preview();
    // TH-1: deposit only.
    expect_err(env.harvest(), "HarvestBelowMinimum", "no profit");
    assert_eq!(hp.u8(&env.preview(), "status"), 2);

    env.gift(100_000_000);
    let x = env.harvest_inputs();
    let d0 = env.expect_harvest(&x).d as u64;
    assert_eq!(d0, 99_000_000);
    // D_min one above D, then equal (checked through the preview).
    env.set_harvest_params(&with(harvest_params_default(), "d_min", u128::from(d0) + 1));
    expect_err(env.harvest(), "HarvestBelowMinimum", "D = d_min - 1");
    env.set_harvest_params(&with(harvest_params_default(), "d_min", u128::from(d0)));
    assert_eq!(hp.u8(&env.preview(), "status"), 0, "D = d_min is Ready");

    // Backlog gate: buyback_usdc above max_buyback_backlog.
    let bb = env.buyback_usdc();
    env.mint_usdc(&bb, 10_000_001);
    env.set_harvest_params(&with(harvest_params_default(), "max_buyback_backlog", 10_000_000));
    let pv = env.preview();
    assert_eq!(hp.u8(&pv, "status"), 5, "BuybackBacklog");
    assert_eq!(hp.u64(&pv, "buyback_usdc"), 10_000_001);
    let o0 = env.cfg_u64("cum_payout_usdc");
    expect_err(env.harvest(), "HarvestBuybackBacklog", "backlog above the gate");
    assert_eq!(env.cfg_u64("cum_payout_usdc"), o0);
    env.set_harvest_params(&with(harvest_params_default(), "max_buyback_backlog", 10_000_001));
    assert_eq!(hp.u8(&env.preview(), "status"), 0, "backlog equal to the gate passes");
    env.set_harvest_params(&with(harvest_params_default(), "max_buyback_backlog", 0));
    assert_eq!(hp.u8(&env.preview(), "status"), 0, "gate off (unreachable by initialize since SPEC v4)");

    // No admin pause since SPEC v2: the retired byte Config@10 changes nothing.
    let cfg = env.pdas.config.0;
    env.patch(&cfg, |d| d[10] = 2);
    assert_eq!(hp.u8(&env.preview(), "status"), 0, "retired pause byte ignored");
    env.patch(&cfg, |d| d[10] = 0);

    // Busy withdraw queue: total_queued > 0.
    env.wq_set(wq::TOTAL_QUEUED, 1);
    assert_eq!(hp.u8(&env.preview(), "status"), 6, "QueueBusy");
    expect_err(env.harvest(), "WithdrawQueueBusy", "total_queued > 0");
    env.wq_set(wq::TOTAL_QUEUED, 0);

    // Unparsed queue header: the preview skips the clamp (queue_cap = MAX).
    let wqk = env.fx.withdraw_queue;
    env.patch(&wqk, |d| d[0] ^= 0xff);
    let pv = env.preview();
    assert_eq!(hp.u64(&pv, "queue_cap"), u64::MAX, "no clamp without a parsed header");
    assert_eq!(hp.u8(&pv, "status"), 0);
    env.patch(&wqk, |d| d[0] ^= 0xff);

    // Everything open again: the harvest pays D.
    let x = env.harvest_inputs();
    let ex = env.expect_harvest(&x);
    check_harvest(&mut env, &x, &ex, "after the gates");
}

/// `max_harvest_per_call`, `W − buf`, and the withdraw-queue clamps with the
/// T_min timer rule (SPEC §5.4.1, TH-4…TH-6, TH-22; U-50 against the real
/// Phoenix budget logic).
#[test]
fn harvest_clamps_and_timer() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(1_000_000_000);
    env.gift(300_000_000);
    env.pass_t_min();

    // Per-call cap: D = 10 USDC, the timer moves.
    env.set_harvest_params(&with(harvest_params_default(), "max_harvest_per_call", 10_000_000));
    let x = env.harvest_inputs();
    let ex = env.expect_harvest(&x);
    assert_eq!(ex.d, 10_000_000);
    assert!(!ex.timer_held);
    check_harvest(&mut env, &x, &ex, "per-call cap");
    expect_err(env.harvest(), "HarvestTooEarly", "timer moved by the per-call cap");
    env.set_harvest_params(&harvest_params_default());
    env.pass_t_min();

    // Permanent budget: max_budget below D → D = max_budget, the timer moves.
    let (mb0, rem0, rep0, lu0) =
        (env.wq_u64(wq::MAX_BUDGET), env.wq_u64(wq::REMAINING), env.wq_u64(wq::REPLENISH), env.wq_u64(wq::LAST_UPDATE));
    eprintln!("fixture withdraw queue: max_budget {mb0} remaining {rem0} replenish {rep0} last_update {lu0}");
    eprintln!(
        "fixture withdraw queue fees: withdrawal {} enqueueing {}",
        env.wq_u64(wq::WITHDRAWAL_FEE),
        env.wq_u64(wq::ENQUEUEING_FEE)
    );
    env.wq_set(wq::MAX_BUDGET, 7_000_000);
    env.wq_set(wq::REMAINING, 7_000_000);
    let x = env.harvest_inputs();
    let ex = env.expect_harvest(&x);
    assert_eq!(ex.d, 7_000_000);
    assert!(ex.queue_limited && !ex.timer_held);
    check_harvest(&mut env, &x, &ex, "max_budget clamp");
    expect_err(env.harvest(), "HarvestTooEarly", "Q_perm moves the timer");
    env.wq_set(wq::MAX_BUDGET, mb0);
    env.pass_t_min();

    // Temporary budget: remaining small, updated this slot → D = remaining,
    // the timer is held; after the budget refills the next harvest runs at
    // once with the full D and moves the timer.
    let (slot, _) = env.clock();
    env.wq_set(wq::REMAINING, 3_000_000);
    env.wq_set(wq::LAST_UPDATE, slot);
    let x = env.harvest_inputs();
    let ex = env.expect_harvest(&x);
    assert_eq!(ex.d, 3_000_000);
    assert!(ex.queue_limited && ex.timer_held);
    check_harvest(&mut env, &x, &ex, "remaining clamp (timer held)");
    env.wq_set(wq::REMAINING, mb0);
    let x = env.harvest_inputs();
    let ex = env.expect_harvest(&x);
    assert!(!ex.timer_held && ex.d > 3_000_000);
    check_harvest(&mut env, &x, &ex, "full D right after the held timer");
    env.pass_t_min();

    // U-50: remaining 0, last_update N slots ago: Q_tmp = replenish * N. The
    // real Phoenix must pay D = Q_tmp at once (else WithdrawNotImmediate).
    env.gift(50_000_000);
    let (slot, _) = env.clock();
    env.wq_set(wq::REPLENISH, 1_000_000);
    env.wq_set(wq::REMAINING, 0);
    env.wq_set(wq::LAST_UPDATE, slot - 4);
    let x = env.harvest_inputs();
    let ex = env.expect_harvest(&x);
    assert_eq!(x.q_tmp, 4_000_000, "Q_tmp = replenish * 4");
    assert_eq!(ex.d, 4_000_000);
    check_harvest(&mut env, &x, &ex, "U-50 replenish formula");
    env.wq_set(wq::REPLENISH, rep0);
    env.wq_set(wq::REMAINING, mb0);
    env.pass_t_min();

    // W − buf: a margin buffer that leaves exactly 2 USDC above it.
    let x = env.harvest_inputs();
    let w = i128::from(x.m.free.max(0)).min(i128::from(x.m.wd));
    let buf_abs = u128::try_from(w).unwrap() - 2_000_000;
    env.set_harvest_params(&with(harvest_params_default(), "margin_buffer_abs", buf_abs));
    let x = env.harvest_inputs();
    let ex = env.expect_harvest(&x);
    assert_eq!(ex.d, 2_000_000, "D = W - buf");
    check_harvest(&mut env, &x, &ex, "W - buf clamp");
}

/// TH-13: donations on vault_usdc / vault_phusd are neither paid out nor taken.
#[test]
fn harvest_leaves_donations_on_vault_accounts() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(1_000_000_000);
    env.gift(40_000_000);
    env.pass_t_min();
    let (vu, vp) = (env.vault_usdc(), env.vault_phusd());
    env.mint_usdc(&vu, 7_000_000);
    env.donate_phusd(&vp, 5_000_000);
    let x = env.harvest_inputs();
    let ex = env.expect_harvest(&x);
    assert_eq!(ex.d, 39_000_000, "donations do not change D");
    check_harvest(&mut env, &x, &ex, "with donations");
    assert_eq!(env.token_amount(&vu), 7_000_000);
    assert_eq!(env.token_amount(&vp), 5_000_000);
    // Tag 21 takes them into I later.
    ok(env.send1(env.deposit_ix(0), S_PAYER), "deposit of the donations");
    assert_eq!(env.cfg_u64("cum_inflow_usdc"), 1_012_000_000);
}

/// TH-8, TH-26: payout accounts. The escrow and buyback ATAs must exist and
/// be clean; `creator_usdc` is not needed by harvest.
#[test]
fn harvest_payout_account_checks() {
    let Some(mut env) = Env::new() else { return };
    env.set_deposit_cooldown(0);
    env.set_gated();
    env.initialize();
    let (phx, usdc, phusd) = (env.pdas.phx_authority.0, env.fx.usdc, env.fx.phusd);
    env.create_ata(&phx, &usdc, &SPL_TOKEN);
    env.create_ata(&phx, &phusd, &SPL_TOKEN);
    let need = env.rent_payer_need();
    env.fund_rent_payer(need);
    ok(env.send1(env.register_ix(), S_ADMIN), "register");
    env.activate_our_trader();
    ok(env.deposit(1_000_000_000), "deposit");
    env.gift(30_000_000);
    env.pass_t_min();
    expect_err(env.harvest(), "CreatorEscrowInvalid", "escrow ATA missing");
    let esc_owner = env.pdas.creator_escrow.0;
    env.create_ata(&esc_owner, &usdc, &SPL_TOKEN);
    expect_err(env.harvest(), "BuybackAtaInvalid", "buyback ATA missing");
    let bb_owner = env.pdas.buyback_authority.0;
    let bb = env.create_ata(&bb_owner, &usdc, &SPL_TOKEN);
    // TH-26: a delegate on buyback_usdc.
    env.patch(&bb, |d| {
        d[72..76].copy_from_slice(&1u32.to_le_bytes());
        d[76..108].copy_from_slice(Pubkey::new_unique().as_ref());
    });
    expect_err(env.harvest(), "BuybackAtaInvalid", "buyback_usdc with a delegate");
    env.patch(&bb, |d| d[72..108].fill(0));
    // Frozen escrow.
    let esc = env.escrow_usdc();
    env.patch(&esc, |d| d[108] = 2);
    expect_err(env.harvest(), "CreatorEscrowInvalid", "frozen escrow");
    env.patch(&esc, |d| d[108] = 1);
    // creator_usdc does not exist: harvest still pays (ACC-3).
    assert!(!env.exists(&env.creator_usdc()));
    let x = env.harvest_inputs();
    let ex = env.expect_harvest(&x);
    check_harvest(&mut env, &x, &ex, "without creator_usdc");
}

/// TH-20 and SPEC §5.4.5: `pay_creator` account checks.
#[test]
fn pay_creator_checks() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(1_000_000_000);
    env.gift(50_000_000);
    env.pass_t_min();
    let x = env.harvest_inputs();
    let ex = env.expect_harvest(&x);
    let (_, creator, _) = check_harvest(&mut env, &x, &ex, "harvest before pay_creator");
    let cu = env.creator_usdc();
    // Frozen / foreign-owned creator_usdc.
    env.patch(&cu, |d| d[108] = 2);
    expect_err(env.send1(env.pay_creator_ix(), S_PAYER), "CreatorAtaInvalid", "frozen creator_usdc");
    env.patch(&cu, |d| d[108] = 1);
    let attacker = env.attacker;
    env.patch(&cu, |d| d[32..64].copy_from_slice(attacker.as_ref()));
    expect_err(env.send1(env.pay_creator_ix(), S_PAYER), "CreatorAtaInvalid", "creator_usdc owner changed");
    let creator_key = env.creator;
    env.patch(&cu, |d| d[32..64].copy_from_slice(creator_key.as_ref()));
    // A donation to the escrow goes to the creator too (no O change).
    let esc = env.escrow_usdc();
    env.mint_usdc(&esc, 1_000);
    let o = env.cfg_u64("cum_payout_usdc");
    ok(env.send1(env.pay_creator_ix(), S_PAYER), "pay_creator");
    assert_eq!(env.token_amount(&cu), creator + 1_000);
    assert_eq!(env.cfg_u64("cum_creator_paid_out"), creator + 1_000);
    assert_eq!(env.cfg_u64("cum_payout_usdc"), o);
    // Wrong escrow PDA key.
    let mut ix = env.pay_creator_ix();
    ix.accounts[1].pubkey = env.pdas.buyback_authority.0;
    expect_err(env.send1(ix, S_PAYER), "InvalidPda", "wrong escrow PDA");
}
