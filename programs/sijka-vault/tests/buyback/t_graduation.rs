// Copyright (c) 2026 prt1sn. All rights reserved.
//! Real graduation on the mainnet binaries (TD-33): the market buys out the
//! live curve, pump completes it, pump `migrate_v2` creates the canonical
//! PumpSwap pool, `bb_observe` switches the venue, and tag 45 buys and burns
//! in the new pool. Also research 07 §8 q.2: what pump does when
//! `spendable_quote_in` exceeds the cost of the remaining tokens.

use sijka_vault::error::SijkaError as E;

use crate::harness::*;
use crate::pumpix::*;

#[test]
fn curve_completes_migrates_and_the_venue_switches() {
    let mut v = vault!(Setup::sol("solcurve"));
    v.fund_authority(3 * LAMPORTS_PER_SOL);
    v.warm_up(10);
    let ck = v.coin().clone();
    let (vt0, vq0, rt0, _) = curve_reserves(&v);
    // Buy out the curve with more than it costs.
    let whale = Trader::new(&mut v, 400 * LAMPORTS_PER_SOL);
    let sol0 = v.lamports(&whale.pubkey());
    let spend = 150 * LAMPORTS_PER_SOL;
    let res = whale.curve_buy(&mut v, spend);
    println!(
        "graduation: buy_exact_quote_in_v2 with {} SOL on vQ {} / rT {}: {:?}",
        spend / LAMPORTS_PER_SOL,
        vq0,
        rt0,
        res.as_ref().err().map(|f| &f.err)
    );
    // Finding (research 07 §8 q.2): exact-quote-in above the cost of the
    // remaining tokens is refused with 6021 NotEnoughTokensToBuy — no partial
    // fill, no change. This is why tag 44 clamps v to v_max (review ACC-13).
    assert_custom(&res, 6021);
    // Buy exactly the remaining tokens with buy_v2(amount, max_sol_cost).
    let ix = whale.curve_buy_tokens_ix(&v, rt0, spend);
    let kp = whale.kp.insecure_clone();
    let m = ok(v.send(vec![ix], &[&kp]));
    println!("graduation: buy_v2 of all {rt0} remaining tokens, CU {}", m.compute_units_consumed);
    let _ = vt0;
    let paid = sol0 - v.lamports(&whale.pubkey());
    let (_, vq1, rt1, complete) = curve_reserves(&v);
    println!(
        "graduation: whale paid {:.3} SOL, got {} tokens, rT {} -> {}, complete {} (vQ {} -> {})",
        paid as f64 / 1e9,
        whale.base(&v),
        rt0,
        rt1,
        complete,
        vq0,
        vq1
    );
    assert_eq!(complete, 1, "the curve completed");
    assert_eq!(rt1, 0);
    // Curve complete, no pool yet.
    v.tick(15, 1);
    assert_sijka(&v.observe(), E::BbPoolNotReady);
    v.tick(1, 1);
    assert_sijka(&v.call(chunk_curve_ix(&v, 0, 0)), E::BbVenueSwitchPending);
    // Anyone may migrate.
    let ix = migrate_v2_ix(&v, &whale.pubkey());
    let kp = whale.kp.insecure_clone();
    let res = v.send(vec![ix], &[&kp]);
    match &res {
        Ok(m) => println!("graduation: migrate_v2 ok, CU {}", m.compute_units_consumed),
        Err(f) => panic!("migrate_v2 failed: {:?}\n{}", f.err, f.meta.logs.join("\n")),
    }
    assert!(v.exists(&ck.pool), "canonical pool created");
    let pool = v.data(&ck.pool);
    println!(
        "graduation: pool len {} coin_creator == sharing_config: {} B {} Q {}",
        pool.len(),
        key_at(&pool, 211) == ck.sharing_config,
        v.token_amount(&ck.pool_base_ta),
        v.token_amount(&ck.pool_quote_ta)
    );
    // The switch.
    let ema_curve = v.bs().ema_price_x64();
    v.tick(15, 1);
    let m = ok(v.observe());
    let e = event(&m.logs, "SJKEVVEN");
    assert_eq!((e[17], e[18]), (1, 2));
    let bs = v.bs();
    assert_eq!(bs.venue(), 2);
    assert_eq!(bs.fresh_obs(), 1);
    let (b, q) = pool_reserves(&v);
    println!("graduation: EMA before {ema_curve}, pool price {}, EMA after {}", price_x64(q, b), bs.ema_price_x64());
    assert!(bs.q_ema() <= q);
    // The buy-out multiplied the price while observations failed: the kept
    // EMA is far below the pool price. SPEC v4 (DECISIONS §23 item 3): there
    // is no spot guard, so the keeper's chunk runs right after the warm-up of
    // the reserve EMA (its size is still bounded by Q_ref and its price by the
    // keeper's min_out).
    v.warm_up(39);
    v.tick(1, 1);
    let bs = v.bs();
    let p_ref = bs.ema_price_x64().min(bs.last_obs_price_x64());
    println!("graduation: pool price {} vs EMA reference {p_ref}", price_x64(q, b));
    let m = ok(v.call(chunk_amm_ix(&v, 0, 0)));
    let e = event(&m.logs, "SJKEVCHK");
    println!("graduation: first pool chunk v {} bought {} burned {}", u64_at(&e, 18), u64_at(&e, 50), u64_at(&e, 58));
    assert_eq!(e[17], 2);
    assert_eq!(v.token_amount(&v.buyback_token()), 0);
}
