// Copyright (c) 2026 prt1sn. All rights reserved.
//! Tag 51 op 1 / op 6 / op 4 / op 2 / op 5 against the mainnet Phoenix,
//! Ember and Hawkeye binaries (TR-15, TR-16, TR-17 cooldown, TR-20, TR-23,
//! TR-27 queue, TR-28, U-65, U-67). The vault is initialized, registered and
//! funded for real (tags 0, 2, 21); the latch is a real 10-day maintenance
//! streak observed by tag 50, after which Phoenix "comes back" (TR-23).

use sijka_vault::constants::RECOVERY_ENQUEUE_MIN_SLOTS;
use sijka_vault::error::SijkaError;
use solana_signer::Signer;

use crate::harness::*;
use crate::vault::*;

const USDC: u64 = 1_000_000;

fn wq_header(env: &VaultEnv) -> (u64, u64, u64, u64, u64, u64, u64) {
    let d = data_of(&env.ctx.svm, &env.fx.wq);
    (rd_u64(&d, 24), rd_u64(&d, 32), rd_u64(&d, 40), rd_u64(&d, 48), rd_u64(&d, 56), rd_u64(&d, 64), rd_u64(&d, 72))
}

/// Nodes of the withdraw queue as `(trader, amount, state, last_reason)`
/// (every allocated node, including final ones).
fn wq_nodes(env: &VaultEnv) -> Vec<(solana_pubkey::Pubkey, u64, u8, u8)> {
    let d = data_of(&env.ctx.svm, &env.fx.wq);
    let bump = rd_u32(&d, 136) as usize;
    (1..bump.min(2049))
        .map(|i| 144 + 104 * (i - 1))
        .filter(|&o| o + 104 <= d.len())
        .map(|o| (rd_key(&d, o + 8), rd_u64(&d, o + 72), d[o + 98], d[o + 99]))
        .collect()
}

fn rcw(r: &TxResult) -> (u8, u8, u64, u64, u64, u64, u64) {
    let m = assert_ok(r);
    let ev = event(&m.logs, b"SJKEVRCW").expect("SJKEVRCW");
    assert_eq!(m.return_data.data, ev, "op 1 / op 6 return data = SJKEVRCW payload");
    parse_rcw(&ev)
}

fn rcs(r: &TxResult) -> (u8, u8, u64, solana_pubkey::Pubkey, u64) {
    parse_rcs(&event(&assert_ok(r).logs, b"SJKEVRCS").expect("SJKEVRCS"))
}

/// TR-20: every op before the latch is `RecoveryNotActive`; op 7 / op 8 do
/// not exist (O-16).
#[test]
fn tr20_ops_before_latch_are_rejected() {
    let Some(mut env) = VaultEnv::new(VaultOpts::default()) else { return };
    let (er_usdc, er_phusd, admin) = (env.er_usdc, env.er_phusd, env.admin);
    let ixs = vec![
        env.op_withdraw_ix(1, 0),
        env.op_withdraw_ix(6, 0),
        env.op_unwrap_ix(),
        env.op_send_token_ix(2, er_usdc),
        env.op_send_token_ix(5, er_phusd),
        env.op_send_sol_ix(admin),
    ];
    for ix in ixs {
        let op = ix.data[1];
        let r = env.send(STRANGER_SEED, vec![ix]);
        assert_err(&r, SijkaError::RecoveryNotActive);
        println!("op {op}: RecoveryNotActive");
    }
    for data in [vec![51u8, 7, 0, 0, 0, 0, 0, 0, 0, 1, 1], vec![51, 8, 1, 1], vec![51, 9], vec![51]] {
        let mut ix = env.op_unwrap_ix();
        ix.data = data;
        assert_err(&env.send(STRANGER_SEED, vec![ix]), SijkaError::InvalidInstructionData);
    }
}

/// TR-15 + TR-23: flat account, real 10-day latch, Phoenix active again:
/// op 1 withdraws everything (`buf_r = 0`) to `vault_phusd` (donations
/// included later), op 4 unwraps through Ember, op 2 pays the admin's ATA.
#[test]
fn tr15_flat_withdraw_unwrap_and_send_to_admin() {
    let Some(mut env) = VaultEnv::new(VaultOpts::default()) else { return };
    let c0 = env.collateral();
    let (i0, o0) = env.cfg(|c| (c.cum_inflow_usdc(), c.cum_payout_usdc()));
    env.latch_via_maintenance(true);
    let protected = env.protected_snapshot();
    // Donations: 5 PhUSD on vault_phusd, 7 USDC on vault_usdc.
    let vp = env.vault_phusd;
    env.donate_phusd(vp, 5 * USDC);
    let vu = env.vault_usdc;
    env.ctx.mint_fake_usdc_to_token_account(vu, 7 * USDC);
    let er0 = env.amount(&env.er_usdc);

    let r = env.op_withdraw(1, 0);
    let (op, bits, d, got, buf, im, _) = rcw(&r);
    println!("op 1: C_hdr before {c0}, D {d}, r {got}, bits {bits:#07b}, buf {buf}, IM {im}");
    assert_eq!(op, 1);
    assert_eq!(bits & 0x02, 0x02, "IM = 0: no buffer");
    assert_eq!(bits & 0x04, 0, "immediate");
    assert_eq!((buf, im), (0, 0));
    assert!(got > 0 && got <= d);
    assert_eq!(d, u64::try_from(c0).unwrap(), "flat: W = the whole collateral");
    assert_eq!(env.amount(&env.vault_phusd), 5 * USDC + got);
    assert_eq!(env.amount(&env.er_usdc), er0, "op 1 never pays out");
    env.cfg(|c| {
        assert_eq!(c.cum_recovery_withdrawn(), got);
        assert_eq!(c.cum_recovery_fees(), d - got);
        assert_eq!((c.cum_inflow_usdc(), c.cum_payout_usdc()), (i0, o0), "I and O unchanged");
        assert_eq!(c.recovery_op_count(), 1);
    });
    assert_eq!(env.collateral(), c0 - i64::try_from(got).unwrap());
    // Nothing left.
    env.tick(10);
    let r = env.op_withdraw(1, 0);
    assert_err(&r, SijkaError::RecoveryNothing);

    // Op 4: all of vault_phusd → vault_usdc.
    let p = env.amount(&env.vault_phusd);
    let r = env.op_unwrap();
    let (op, route, u, dest, cum) = rcs(&r);
    assert_eq!((op, route, dest), (4, 0, env.vault_usdc));
    assert_eq!(env.amount(&env.vault_phusd), 0);
    assert!(u > 0 && u <= p);
    assert_eq!(env.amount(&env.vault_usdc), 7 * USDC + u);
    assert_eq!(cum, p);
    assert_eq!(env.cfg(|c| c.cum_recovery_unwrapped()), p);
    println!("op 4: P {p} → u {u}");

    // Op 2: everything on vault_usdc → ATA(admin, USDC).
    let total = env.amount(&env.vault_usdc);
    let er = env.er_usdc;
    let r = env.op_send_token(2, er);
    let (op, route, amount, dest, cum) = rcs(&r);
    assert_eq!((op, route, amount, dest, cum), (2, 0, total, env.er_usdc, total));
    assert_eq!(env.amount(&env.vault_usdc), 0);
    assert_eq!(env.amount(&env.er_usdc), er0 + total);
    assert_eq!(env.cfg(|c| c.cum_recovered_usdc()), total);
    assert_err(&env.op_send_token(2, er), SijkaError::RecoveryNothing);
    assert_err(&env.op_unwrap(), SijkaError::RecoveryNothing);
    assert_eq!(env.protected_snapshot(), protected, "buyback escrow and creator share untouched");
    assert_eq!(env.cfg(|c| c.recovery_op_count()), 3);
}

/// Op 6 (no Hawkeye) on a flat account and op 5 (PhUSD as is to the admin);
/// TR-28: `max_amount < d_min` is `RecoveryBelowMinimum`.
#[test]
fn tr28_flat_op6_and_op5_phusd_to_admin() {
    let Some(mut env) = VaultEnv::new(VaultOpts::default()) else { return };
    env.latch_via_maintenance(true);
    let c0 = env.collateral();
    assert_err(&env.op_withdraw(6, 999_999), SijkaError::RecoveryBelowMinimum);
    // A smaller slice is the caller's choice (not below d_min).
    let r = env.op_withdraw(6, 400 * USDC);
    let (op, bits, d, got, _, _, _) = rcw(&r);
    assert_eq!((op, d), (6, 400 * USDC));
    assert_eq!(bits & 0x0A, 0x0A, "buf 0 and limited by max_amount");
    assert_eq!(got, d);
    env.tick(10);
    let r = env.op_withdraw(6, 0);
    let (_, _, d2, got2, _, _, _) = rcw(&r);
    assert_eq!(d2, u64::try_from(c0).unwrap() - 400 * USDC, "op 6: D = C_hdr");
    let phusd = env.amount(&env.vault_phusd);
    assert_eq!(phusd, got + got2);
    env.tick(10);
    assert_err(&env.op_withdraw(6, 0), SijkaError::RecoveryNothing);
    let er = env.er_phusd;
    let r = env.op_send_token(5, er);
    let (op, route, amount, dest, cum) = rcs(&r);
    assert_eq!((op, route, amount, dest, cum), (5, 0, phusd, er, phusd));
    assert_eq!(env.amount(&er), phusd);
    assert_eq!(env.amount(&env.vault_phusd), 0);
    assert_eq!(env.cfg(|c| c.cum_recovered_phusd()), phusd);
    // Wrong PhUSD destination.
    let vp = env.vault_phusd;
    env.donate_phusd(vp, USDC);
    let stranger_phusd = ata(&env.stranger, &env.fx.phusd);
    assert_err(&env.op_send_token(5, stranger_phusd), SijkaError::RecoveryRecipientInvalid);
    let er_usdc = env.er_usdc;
    assert_err(&env.op_send_token(5, er_usdc), SijkaError::RecoveryRecipientInvalid);
}

/// TR-16, TR-28 (position), U-67: with an open position op 6 refuses
/// (`RecoveryNotFlat`, withdrawal rolled back) and op 1 keeps the buffer;
/// the trading key's reduce-only close at any price (tag 10) frees the rest.
#[test]
fn tr16_open_position_buffer_then_reduce_only_close() {
    let Some(mut env) = VaultEnv::new(VaultOpts::default()) else { return };
    let mark = env.mark("SOL");
    assert_ok(&env.ioc("SOL", 0, mark * 102 / 100, 100, false));
    let pos = env.positions();
    println!("positions: {pos:?}");
    assert_eq!(pos.len(), 1);
    env.latch_via_maintenance(true);
    let before = env.amount(&env.vault_phusd);
    // A slice Phoenix allows (full C_hdr would fail its own margin check).
    let r = env.op_withdraw(6, 10 * USDC);
    assert_err(&r, SijkaError::RecoveryNotFlat);
    assert_eq!(env.amount(&env.vault_phusd), before, "op 6 rolled back with the withdrawal");

    let c0 = env.collateral();
    let r = env.op_withdraw(1, 0);
    let (_, bits, d, got, buf, im, _) = rcw(&r);
    println!("op 1 with a position: C_hdr {c0}, D {d}, r {got}, buf {buf}, IM {im}, bits {bits:#07b}");
    assert!(im > 0);
    assert_eq!(bits & 0x02, 0, "buffer applies");
    assert_eq!(buf, (5 * USDC).max((im * 2_000).div_ceil(10_000)));
    assert!(got > 0);
    // The buffer stays on Phoenix.
    env.tick(10);
    let again = env.op_withdraw(1, 0);
    println!("op 1 again: {}", err_text(&again));
    assert!(again.is_err(), "nothing above the buffer");

    // Reduce-only close by the trading key at 1 tick through tag 10 (no
    // price rule in the program, T13); tag 10 emits no event of its own (T12).
    env.tick(10);
    let r = env.ioc("SOL", 1, 1, 100, true);
    let m = assert_ok(&r);
    assert!(events(&m.logs).is_empty(), "tag 10 emits no SJKEV event");
    assert!(env.positions().is_empty(), "closed: {:?}", env.positions());
    env.tick(10);
    let r = env.op_withdraw(1, 0);
    let (_, bits, d, got, _, im, _) = rcw(&r);
    println!("op 1 after the close: D {d}, r {got}, IM {im}");
    assert_eq!(im, 0);
    assert_eq!(bits & 0x02, 0x02);
    env.tick(10);
    assert_err(&env.op_withdraw(1, 0), SijkaError::RecoveryNothing);
    assert_eq!(env.collateral(), 0);
}

/// U-67: our PostOnly bid is filled by another trader (a maker fill updates
/// the ATB, not our position map); op 6's post-CPI scan must still see the
/// position, i.e. `withdraw_funds` synchronizes the map.
#[test]
fn u67_withdraw_cpi_synchronizes_the_position_map() {
    let Some(mut env) = VaultEnv::new(VaultOpts::default()) else { return };
    let mark = env.mark("SOL");
    let bid = mark * 999 / 1000;
    let r = env.post_only("SOL", 0, bid, 50);
    println!("post-only bid at {bid}: {}", err_text(&r));
    assert_ok(&r);
    let map_before = env.positions();
    // taker0 sells into our bid.
    let taker = env.ctx.actor("taker0");
    let (w, t) = (
        phoenix_rise_litesvm_test::parse_pubkey(&taker.pubkey).unwrap(),
        phoenix_rise_litesvm_test::parse_pubkey(&taker.trader_account).unwrap(),
    );
    let fx = env.fx.clone();
    let sol = env.orderbook("SOL");
    let r = env.send("taker-0000", vec![ix_market_order(&fx, w, t, sol, 1, bid, 50, false, env.slot + 100)]);
    assert_ok(&r);
    let map_after_fill = env.positions();
    println!("U-67: our map before the fill {map_before:?}, after the taker's fill {map_after_fill:?}");
    env.latch_via_maintenance(true);
    // No CPI of ours on this trader since the fill (a cancel would resync the
    // map, U-54): op 6's scan runs right after its own `withdraw_funds` CPI.
    println!("U-67: map before op 6: {:?}", env.positions());
    env.tick(10);
    let r = env.op_withdraw(6, 10 * USDC);
    println!("U-67: op 6 with a maker-filled position: {}", err_text(&r));
    assert_err(&r, SijkaError::RecoveryNotFlat);
    // Op 1 (Hawkeye reads the ATB) sees the position's margin.
    let r = env.op_withdraw(1, 0);
    let (_, _, _, _, _, im, _) = rcw(&r);
    assert!(im > 0, "Hawkeye sees the maker-filled position");
    println!("U-67: map after op 1's withdraw CPI: {:?}", env.positions());
}

/// TR-27 + U-65: budget clamp (immediate, bit0), then QUEUE mode (request
/// in Phoenix's queue, `r = 0`), the enqueue interval, one request per
/// trader, and delivery by a stranger's `consume_withdraw_queue`.
#[test]
fn tr27_u65_budget_clamp_queue_and_consume() {
    let Some(mut env) = VaultEnv::new(VaultOpts::default()) else { return };
    env.latch_via_maintenance(true);
    let fx = env.fx.clone();
    println!("withdraw queue header (max, remaining, replenish, last, total, wfee, efee): {:?}", wq_header(&env));
    // Budget 100 USDC, no replenishment, enqueueing fee 2 USDC.
    assert_ok(&env.send("payer", vec![ix_update_withdraw_rate_limits(&fx, Some(100 * USDC), Some(0))]));
    assert_ok(&env.send("payer", vec![ix_update_withdraw_parameters(&fx, None, None, Some(2 * USDC))]));
    println!("after update: {:?}", wq_header(&env));
    let c0 = env.collateral();

    // Immediate, clamped to the budget.
    env.tick(10);
    let r = env.op_withdraw(1, 0);
    let (_, bits, d, got, _, _, _) = rcw(&r);
    println!("op 1 #1: D {d}, r {got}, bits {bits:#07b}; queue {:?}", wq_header(&env));
    assert_eq!(bits & 0x05, 0x01, "budget limited, immediate");
    assert_eq!(d, 100 * USDC);
    assert_eq!(got, d);

    // Budget exhausted: QUEUE mode.
    env.tick(10);
    let c1 = env.collateral();
    let tq0 = wq_header(&env).4;
    let r = env.op_withdraw(1, 0);
    println!("op 1 #2 (queue): {}", err_text(&r));
    let (_, bits, d, got, _, _, tq) = rcw(&r);
    println!("op 1 #2: D {d}, r {got}, bits {bits:#07b}, total_queued {tq}; C_hdr {c1} → {}", env.collateral());
    assert_eq!(bits & 0x04, 0x04, "queued");
    assert_eq!(got, 0);
    assert_eq!(tq, tq0 + d);
    println!(
        "U-65: enqueueing fee 2 USDC charged at enqueue: {} (C_hdr delta {})",
        c1 - env.collateral() == 2_000_000,
        c1 - env.collateral()
    );
    let enq_slot = env.slot;
    env.cfg(|c| {
        assert_eq!(c.cum_recovery_queued(), d);
        assert_eq!(c.recovery_last_enqueue_slot(), enq_slot);
    });

    // Too soon for another request.
    env.tick(10);
    assert_err(&env.op_withdraw(1, 0), SijkaError::RecoveryEnqueueTooSoon);
    // After the interval: our request is still active → not replaced.
    env.tick_slots(RECOVERY_ENQUEUE_MIN_SLOTS);
    env.refresh_prices();
    assert_err(&env.op_withdraw(1, 0), SijkaError::RecoveryAlreadyQueued);
    let small = env.op_withdraw(1, 2 * USDC);
    println!("stranger op 1 with a small max_amount: {}", err_text(&small));
    assert!(small.is_err(), "a stranger cannot replace our queued request");

    // Delivery by consume_withdraw_queue: budget back, crank by a stranger.
    assert_ok(&env.send("payer", vec![ix_update_withdraw_rate_limits(&fx, Some(1_000_000 * USDC), Some(USDC))]));
    env.tick_slots(500);
    println!("queue before consume: {:?}", wq_header(&env));
    let (auth, trader, vp) = (env.p.phx_authority, env.trader, env.vault_phusd);
    let wrong = ata(&env.stranger, &env.fx.phusd);
    let w0 = env.amount(&wrong);
    let r = env.send(STRANGER_SEED, vec![ix_consume_withdraw_queue(&fx, auth, wrong, trader)]);
    println!("U-65: consume_withdraw_queue to a foreign destination: {}", err_text(&r));
    assert_eq!(env.amount(&wrong), w0, "U-65: queued PhUSD never goes to a foreign account");
    let p_before = env.amount(&vp);
    let r = env.send(STRANGER_SEED, vec![ix_consume_withdraw_queue(&fx, auth, vp, trader)]);
    println!(
        "U-65: consume_withdraw_queue by a stranger to vault_phusd: {}; vault_phusd {} → {}; queue {:?}",
        err_text(&r),
        p_before,
        env.amount(&vp),
        wq_header(&env)
    );
    assert_ok(&r);
    assert_eq!(env.amount(&vp), p_before + d, "U-65: delivered to ATA(wallet, PhUSD) = vault_phusd");
    // Then op 4 → op 2 as usual.
    assert_ok(&env.op_unwrap());
    let er = env.er_usdc;
    assert_ok(&env.op_send_token(2, er));
    assert!(env.amount(&er) >= 200 * USDC - 4 * USDC);
    println!("C_hdr {c0} → {}", env.collateral());
}

/// U-65 / TR-3: a queued request of ours while the exchange goes inactive:
/// what `consume_withdraw_queue` does with it (processed, dropped with
/// `ExchangeInactive = 8`, or kept), and op 1 afterwards.
#[test]
fn u65_queued_request_when_the_exchange_goes_inactive() {
    let Some(mut env) = VaultEnv::new(VaultOpts::default()) else { return };
    env.latch_via_maintenance(true);
    let fx = env.fx.clone();
    assert_ok(&env.send("payer", vec![ix_update_withdraw_rate_limits(&fx, Some(100 * USDC), Some(0))]));
    env.tick(10);
    assert_ok(&env.op_withdraw(1, 0)); // immediate, budget exhausted
    env.tick(10);
    let r = env.op_withdraw(1, 0);
    let (_, bits, d, _, _, _, _) = rcw(&r);
    assert_eq!(bits & 0x04, 0x04, "queued");
    let ours = env.trader;
    let node = |env: &VaultEnv| wq_nodes(env).into_iter().filter(|n| n.0 == ours).collect::<Vec<_>>();
    println!("U-65: our node after enqueue (trader, amount, state, reason): {:?}", node(&env));
    // Exchange inactive, budget back, crank by a stranger.
    assert_ok(&env.set_exchange(None, Some(true)));
    assert_ok(&env.send("payer", vec![ix_update_withdraw_rate_limits(&fx, Some(1_000_000 * USDC), Some(USDC))]));
    env.tick_slots(500);
    let (auth, trader, vp) = (env.p.phx_authority, env.trader, env.vault_phusd);
    let p0 = env.amount(&vp);
    let c0 = env.collateral();
    let r = env.send(STRANGER_SEED, vec![ix_consume_withdraw_queue(&fx, auth, vp, trader)]);
    println!(
        "U-65: consume in maintenance: {}; vault_phusd {p0} → {}; C_hdr {c0} → {}; node {:?}; queue {:?}",
        err_text(&r),
        env.amount(&vp),
        env.collateral(),
        node(&env),
        wq_header(&env)
    );
    // Our own op 1 while inactive (queue busy or Phoenix refusal).
    env.tick(10);
    let r = env.op_withdraw(1, 0);
    println!("U-57/U-65: op 1 in maintenance with a queued request: {}", err_text(&r));
    assert!(r.is_err(), "no withdrawal while the exchange is in maintenance");
    // Back to active: the request is delivered (or was dropped and op 1 works again).
    assert_ok(&env.set_exchange(None, Some(false)));
    env.tick_slots(10);
    env.refresh_prices();
    let r = env.send(STRANGER_SEED, vec![ix_consume_withdraw_queue(&fx, auth, vp, trader)]);
    println!(
        "U-65: consume after reactivation: {}; vault_phusd {}; node {:?}; queue {:?}",
        err_text(&r),
        env.amount(&vp),
        node(&env),
        wq_header(&env)
    );
    let delivered = env.amount(&vp) - p0;
    if delivered == 0 {
        // Dropped: nothing lost, the collateral is still on Phoenix; op 1 again
        // after the enqueue interval.
        assert_eq!(wq_header(&env).4, 0, "no request left in the queue");
        env.tick_slots(RECOVERY_ENQUEUE_MIN_SLOTS);
        env.refresh_prices();
        let r = env.op_withdraw(1, 0);
        println!("op 1 after the drop: {}", err_text(&r));
        assert_ok(&r);
    } else {
        assert_eq!(delivered, d);
    }
}

/// TR-17 (cooldown): `cd > 0` and a fresh `last_deposit_slot` → `WithdrawCooldown`.
#[test]
fn tr17_withdraw_cooldown() {
    let Some(mut env) = VaultEnv::new(VaultOpts::default()) else { return };
    env.latch_via_maintenance(true);
    let fx = env.fx.clone();
    let lds = rd_u64(&env.trader_data(), 192);
    println!("cooldown {}; last_deposit_slot {lds}; slot {}", rd_u64(&env.gc(), gcx::COOLDOWN), env.slot);
    let cd = env.slot - lds + 1_000;
    assert_ok(&env.send("payer", vec![ix_update_withdraw_parameters(&fx, Some(cd), None, None)]));
    env.tick(10);
    assert_err(&env.op_withdraw(1, 0), SijkaError::WithdrawCooldown);
    assert_err(&env.op_withdraw(6, 0), SijkaError::WithdrawCooldown);
    env.tick_slots(1_000);
    assert_ok(&env.op_withdraw(1, 0));
}

/// TR-21: GlobalConfig gone after the latch: op 1 / op 6 fail on the account
/// check, op 4 / op 2 / op 3 / op 5 still pay out what is already out.
#[test]
fn tr21_global_config_gone_after_latch() {
    let Some(mut env) = VaultEnv::new(VaultOpts::default()) else { return };
    env.latch_via_maintenance(true);
    let vp = env.vault_phusd;
    env.donate_phusd(vp, 10 * USDC);
    let p = env.p;
    env.ctx.svm.airdrop(&p.fee_inbox, 2_000_000_000).unwrap();
    remove(env.svm(), global_config_key());
    assert_err(&env.op_withdraw(1, 0), SijkaError::InvalidPhoenixGlobalConfig);
    assert_err(&env.op_withdraw(6, 0), SijkaError::InvalidPhoenixGlobalConfig);
    let er_phusd = env.er_phusd;
    // Op 5 first with half the PhUSD cannot be split: send all, then donate again for op 4.
    assert_ok(&env.op_send_token(5, er_phusd));
    env.donate_phusd(vp, 3 * USDC);
    assert_ok(&env.op_unwrap());
    let er = env.er_usdc;
    assert_ok(&env.op_send_token(2, er));
    let admin = env.admin;
    let a0 = env.lamports(&admin);
    assert_ok(&env.op_send_sol(admin));
    assert!(env.lamports(&admin) > a0);
}

/// SPEC v3 §5.0.5 (REC-9; §11.10: no delegate): op 1 and op 6 accept our
/// trader only while Phoenix names `phx_authority` both authority (`@56`)
/// and position authority (`@120`). A position authority set to the trading
/// key (what SPEC v2's delegate did) or to a stranger, or another authority,
/// is `InvalidPhoenixTraderAccount` before any CPI; nothing moves.
#[test]
fn tr_ops_require_phx_authority_as_both_authorities() {
    let Some(mut env) = VaultEnv::new(VaultOpts::default()) else { return };
    env.edit_cfg(|m| m.set_recovery_mode(1));
    let (trader, bot, stranger) = (env.trader, env.bot, env.stranger);
    let original = env.trader_data();
    let c0 = env.collateral();
    let vp0 = env.amount(&env.vault_phusd);
    let cases = [
        (120usize, bot, "position authority = the trading key"),
        (120, stranger, "position authority = a stranger"),
        (56, bot, "authority = the trading key"),
    ];
    for (off, key, label) in cases {
        patch(env.svm(), &trader, |d| d[off..off + 32].copy_from_slice(key.as_ref()));
        for op in [1u8, 6] {
            let r = env.op_withdraw(op, 0);
            assert_err(&r, SijkaError::InvalidPhoenixTraderAccount);
            println!("op {op}, {label}: InvalidPhoenixTraderAccount");
        }
        let o = original.clone();
        patch(env.svm(), &trader, move |d| d.copy_from_slice(&o));
    }
    assert_eq!(env.collateral(), c0, "collateral unchanged");
    assert_eq!(env.amount(&env.vault_phusd), vp0, "vault_phusd unchanged");
}

/// TR-34, full audit FA-2: in QUEUE mode op 6 must ask for (nearly) all of `D_max`,
/// like op 1. A stranger's op 6 with `max_amount = d_min` is
/// `RecoveryBelowMinimum` and writes nothing; otherwise the one active
/// request of ours and `RECOVERY_ENQUEUE_MIN_SLOTS` would hold the recovery at
/// `d_min` per day. An IMMEDIATE op 6 still goes down to `d_min` (TR-28).
#[test]
fn fa2_op6_queue_request_must_be_near_full() {
    let Some(mut env) = VaultEnv::new(VaultOpts::default()) else { return };
    env.latch_via_maintenance(true);
    let fx = env.fx.clone();
    // Budget 100 USDC, no replenishment: one immediate withdrawal, then QUEUE mode.
    assert_ok(&env.send("payer", vec![ix_update_withdraw_rate_limits(&fx, Some(100 * USDC), Some(0))]));
    env.tick(10);
    let (_, bits, d, _, _, _, _) = rcw(&env.op_withdraw(6, 0));
    assert_eq!((bits & 0x04, d), (0, 100 * USDC), "immediate, budget exhausted");
    env.tick(10);
    let d_min = env.cfg(|c| c.harvest().d_min());
    let tq0 = wq_header(&env).4;
    let r = env.op_withdraw(6, d_min);
    println!("FA-2: stranger op 6 with max_amount = d_min in QUEUE mode: {}", err_text(&r));
    assert_err(&r, SijkaError::RecoveryBelowMinimum);
    assert_eq!(wq_header(&env).4, tq0, "nothing queued");
    assert_eq!(env.cfg(|c| c.recovery_last_enqueue_slot()), 0, "no enqueue interval started");
    // Strict bound: D_max − max(withdrawal_fee, enqueueing_fee, shave(D_max)),
    // shave(100 USDC) = max(RECOVERY_SHAVE_ABS 1 USDC, 0.5%) = 1 USDC (SPEC v4).
    let (_, _, _, _, _, wfee, efee) = wq_header(&env);
    let bound = 100 * USDC - wfee.max(efee).max(USDC);
    println!("FA-2: fees {wfee}/{efee}, smallest queued request {bound}");
    assert_err(&env.op_withdraw(6, bound - 1), SijkaError::RecoveryBelowMinimum);
    let r = env.op_withdraw(6, bound);
    let (op, bits, d, got, _, _, tq) = rcw(&r);
    assert_eq!((op, bits & 0x04, d, got), (6, 0x04, bound, 0), "near-full request queued");
    assert_eq!(tq, tq0 + d);
}

/// SPL Token account bytes (165): `mint`, `owner`, `amount`, Initialized.
fn token_account_bytes(mint: &solana_pubkey::Pubkey, owner: &solana_pubkey::Pubkey, amount: u64) -> Vec<u8> {
    let mut d = vec![0u8; 165];
    d[0..32].copy_from_slice(mint.as_ref());
    d[32..64].copy_from_slice(owner.as_ref());
    d[64..72].copy_from_slice(&amount.to_le_bytes());
    d[108] = 1;
    d
}

/// TR-35, full audit FA-3 (U-65 remainder): Phoenix's permissionless
/// `consume_withdraw_queue` takes the destination from its caller, and anyone
/// can create a non-ATA SPL Token PhUSD account owned by `phx_authority`
/// (`InitializeAccount3` needs no signature of the owner; the state is put
/// directly here). A stranger cranks our queued request into such an
/// account. Whatever Phoenix does with it, the PhUSD must not be locked: op 4
/// unwraps from any clean PhUSD account of `phx_authority` into
/// `vault_usdc`, op 5 sends from it to the recipient; others' accounts are
/// not sources.
#[test]
fn fa3_queue_delivery_to_a_non_ata_account_of_phx_authority() {
    let Some(mut env) = VaultEnv::new(VaultOpts::default()) else { return };
    env.latch_via_maintenance(true);
    let fx = env.fx.clone();
    assert_ok(&env.send("payer", vec![ix_update_withdraw_rate_limits(&fx, Some(100 * USDC), Some(0))]));
    env.tick(10);
    assert_ok(&env.op_withdraw(1, 0)); // immediate, budget exhausted
    env.tick(10);
    let (_, bits, d, _, _, _, _) = rcw(&env.op_withdraw(1, 0));
    assert_eq!(bits & 0x04, 0x04, "queued");
    let (auth, trader, vp) = (env.p.phx_authority, env.trader, env.vault_phusd);
    let alt = solana_keypair::Keypair::new().pubkey();
    let phusd = env.fx.phusd;
    put_rent_exempt(env.svm(), alt, token_program(), token_account_bytes(&phusd, &auth, 0));
    assert_ok(&env.send("payer", vec![ix_update_withdraw_rate_limits(&fx, Some(1_000_000 * USDC), Some(USDC))]));
    env.tick_slots(500);
    let r = env.send(STRANGER_SEED, vec![ix_consume_withdraw_queue(&fx, auth, alt, trader)]);
    println!(
        "FA-3 / U-65: consume_withdraw_queue into a non-ATA PhUSD account of phx_authority: {}; delivered {}",
        err_text(&r),
        env.amount(&alt)
    );
    if r.is_ok() {
        assert_eq!(env.amount(&alt), d, "delivered to the non-ATA account");
    } else {
        // Phoenix insists on ATA(wallet, PhUSD): deliver there, and put PhUSD
        // on the non-ATA account by a plain transfer to exercise op 4 / op 5.
        assert_ok(&env.send(STRANGER_SEED, vec![ix_consume_withdraw_queue(&fx, auth, vp, trader)]));
        env.donate_phusd(alt, 5 * USDC);
    }
    // Op 4 from the non-ATA account → vault_usdc.
    let p_alt = env.amount(&alt);
    let vu = env.vault_usdc;
    let vu0 = env.amount(&vu);
    let mut ix = env.op_unwrap_ix();
    ix.accounts[2].pubkey = alt;
    let r = env.send(STRANGER_SEED, vec![ix]);
    println!("FA-3: op 4 from the non-ATA account ({p_alt} PhUSD): {}", err_text(&r));
    let (op, _, u, dest, _) = rcs(&r);
    assert_eq!((op, dest), (4, vu));
    assert!(u > 0 && u <= p_alt);
    assert_eq!(env.amount(&alt), 0);
    assert_eq!(env.amount(&vu), vu0 + u);
    // Op 5 from it → the recipient's PhUSD ATA.
    env.donate_phusd(alt, 3 * USDC);
    let er = env.er_phusd;
    let e0 = env.amount(&er);
    let mut ix = env.op_send_token_ix(5, er);
    ix.accounts[2].pubkey = alt;
    let (op, _, amount, dest, _) = rcs(&env.send(STRANGER_SEED, vec![ix]));
    assert_eq!((op, amount, dest), (5, 3 * USDC, er));
    assert_eq!(env.amount(&er), e0 + 3 * USDC);
    // Someone else's PhUSD account is never a source.
    let foreign = ata(&env.stranger, &phusd);
    let mut ix = env.op_unwrap_ix();
    ix.accounts[2].pubkey = foreign;
    assert_err(&env.send(STRANGER_SEED, vec![ix]), SijkaError::InvalidTokenAccount);
    let mut ix = env.op_send_token_ix(5, er);
    ix.accounts[2].pubkey = foreign;
    assert_err(&env.send(STRANGER_SEED, vec![ix]), SijkaError::InvalidTokenAccount);
    // Op 2 stays on vault_usdc and pays everything out.
    let er_usdc = env.er_usdc;
    assert_ok(&env.op_send_token(2, er_usdc));
    assert_eq!(env.amount(&vu), 0);
}
