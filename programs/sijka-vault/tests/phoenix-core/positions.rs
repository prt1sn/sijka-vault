// Copyright (c) 2026 prt1sn. All rights reserved.
//! Harvest with open positions and Phoenix-side effects on the vault trader:
//! unrealized PnL and the IM buffer (TH-4, TH-5), mark age (TH-24), the hot
//! account whose position map lags ATB after a maker fill (TH-25, RT-3),
//! permissionless `ReallocTrader` + `SyncNative` under a deposit cooldown
//! (TF-6b / U-53 for `prefs = 0b11`, TB-37), and funding settlement at
//! deposit (U-38).

use phoenix_rise::accounts::global_config::GlobalConfig;
use phoenix_rise::accounts::spot_collateral::{SPOT_COLLATERAL_FLAG_HAS_PERP_ASSET, SpotCollateralMetadata};
use phoenix_rise::accounts::trader::Trader;
use phoenix_rise::ix::native_sol::{SyncNativeParams, create_realloc_trader_ix, create_sync_native_ix};
use phoenix_rise::ix::types::Side;
use phoenix_rise_litesvm_test::{FixtureOraclePriceUpdate, FixturePrice, decode_fixture_instruction};
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::abi;
use crate::harness::*;
use crate::harvest::*;
use crate::ixs::*;
use crate::phx::*;

fn sol_position(env: &Env) -> i64 {
    let sol = env.pam_entry("SOL").asset_id;
    env.our_trader().positions.iter().find(|(a, _)| (*a as u32) == sol).map_or(0, |p| p.1)
}

/// TH-5: a winning open position pays nothing (U > 0 is not realized).
/// TH-4: realized profit with a losing open position: `D* = C − I + U + F`.
/// `buf` follows IM (`⌈IM·5000/1e4⌉` above `margin_buffer_abs`).
/// TH-24: an open position whose mark is older than
/// `harvest_mark_max_age_slots` blocks harvest before any CPI.
#[test]
fn harvest_unrealized_pnl_im_buffer_and_mark_age() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(10_000_000_000);
    let px = env.ticks_for("SOL", 151_000);
    ok(env.send1(env.ioc_ix("SOL", 0, false, px, 1000), S_BOT), "open 10 SOL long at 150.5");
    assert_eq!(sol_position(&env), 1000);
    env.pass_t_min();
    // TH-5: price up, the gain stays unrealized.
    env.set_price_milli("SOL", 160_000);
    let x = env.harvest_inputs();
    assert!(x.m.upnl > 0, "unrealized gain {}", x.m.upnl);
    let ex = env.expect_harvest(&x);
    assert!(ex.d_star <= 0, "D* ignores U > 0: {}", ex.d_star);
    let hp = abi::harvest_preview();
    let pv = env.preview();
    assert_eq!(hp.u8(&pv, "status"), 2);
    assert_eq!(i128::from(hp.i64(&pv, "D_star")), ex.d_star);
    expect_err(env.harvest(), "HarvestBelowMinimum", "U > 0 only");

    // TH-4: realized profit (gift) and the price below entry.
    env.gift(200_000_000);
    env.set_price_milli("SOL", 145_000);
    let x = env.harvest_inputs();
    assert!(x.m.upnl < 0, "unrealized loss {}", x.m.upnl);
    assert!(x.m.im > 0, "IM of the open position");
    let ex = env.expect_harvest(&x);
    let im_buf = (i128::from(x.m.im) * 5000 + 9_999) / 10_000;
    eprintln!("TH-4: U {} F {} IM {} buf {} D* {} D {}", x.m.upnl, x.m.funding, x.m.im, ex.buf, ex.d_star, ex.d);
    assert_eq!(ex.buf, im_buf.max(5_000_000));
    assert!(ex.d_star < 200_000_000 + i128::from(x.m.upnl) + 1, "D* reduced by |U + F|");

    // TH-24: the SOL mark older than harvest_mark_max_age_slots. Hawkeye has
    // its own, shorter staleness limit (see `hawkeye_mark_staleness_probe`),
    // so the program's check is exercised with a limit of 4 slots.
    env.set_harvest_params(&with(harvest_params_default(), "harvest_mark_max_age_slots", 4));
    let (slot, ts) = env.clock();
    env.set_clock(slot + 5, ts);
    let pv = env.preview();
    assert_eq!(hp.u8(&pv, "status"), 8, "MarkStale");
    assert_eq!(hp.u16(&pv, "stale_positions"), 1);
    expect_err(env.harvest(), "HarvestMarkStale", "stale mark of an open position");
    // Check disabled (parameter 0): the stale mark no longer blocks.
    env.set_harvest_params(&with(harvest_params_default(), "harvest_mark_max_age_slots", 0));
    assert_ne!(hp.u8(&env.preview(), "status"), 8, "no mark check with parameter 0");
    // Beyond Hawkeye's limit with the default 150: tag 30 stops at step 6,
    // before the Hawkeye CPI.
    env.set_harvest_params(&harvest_params_default());
    let (slot, ts) = env.clock();
    env.set_clock(slot + 151, ts);
    expect_err(env.harvest(), "HarvestMarkStale", "151 slots, default limit 150");
    // Fresh mark: harvest pays D* − ε with U < 0 included.
    env.refresh_prices();
    let x = env.harvest_inputs();
    let ex = env.expect_harvest(&x);
    check_harvest(&mut env, &x, &ex, "profit with a losing open position");
}

/// TH-25 (RT-3, SPEC v3 step 8a): the vault's resting ask is filled in a
/// counterparty's transaction; the hot account's position map still shows a
/// flat SOL record (the market of the resting order, U-55) while Hawkeye
/// (ATB) has the position. With `pc > n_scan` the flat record's mark must be
/// fresh too: a mark older than `harvest_mark_max_age_slots` is status 8 /
/// `HarvestMarkStale` whatever Hawkeye's own, per-market limit is (review
/// accounting-3), and a mark older than Hawkeye's limit fails inside Hawkeye.
/// Once the trading key's own transaction synced the map, a stale mark of a
/// flat market does not block.
#[test]
fn harvest_hot_account_map_lag_after_maker_fill() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(1_000_000_000);
    // The profit first: a TransferCollateral into our trader rewrites its map
    // from ATB (observed below), which would hide the lag.
    env.gift(50_000_000);
    env.cancel_fixture_levels();
    let px = env.ticks_for("SOL", 151_000);
    ok(env.send1(env.post_only_ix("SOL", 1, px, 10), S_BOT), "vault resting ask 0.1 SOL");
    assert_eq!(env.our_trader().flags, FLAGS_HOT);
    ok(env.actor_limit("taker0", "SOL", Side::Bid, px, 10), "taker0 lifts the ask");
    let t = env.pdas.trader.0;
    let m = env.margin(&t);
    eprintln!("after maker fill: map SOL position {}, Hawkeye position_count {}", sol_position(&env), m.position_count);
    assert_eq!(sol_position(&env), 0, "map lags ATB (hot account, maker fill)");
    assert_eq!(m.position_count, 1, "Hawkeye sees the short");
    let sol = env.pam_entry("SOL").asset_id;
    let map = env.our_trader().positions;
    eprintln!("TH-25: map records after the maker fill: {map:?}");
    assert!(map.iter().any(|(a, b)| (*a as u32) == sol && *b == 0), "U-55: flat SOL record of the resting order");

    env.pass_t_min();
    // Mark limit below Hawkeye's own staleness limit (see the probe test).
    env.set_harvest_params(&with(harvest_params_default(), "harvest_mark_max_age_slots", 4));
    let hp = abi::harvest_preview();
    let pv = env.preview();
    assert_eq!(hp.u8(&pv, "bits") & 4, 4, "bit2: pc > n_scan");
    assert_eq!(hp.u8(&pv, "status"), 0, "fresh mark of the flat record");
    let (slot, ts) = env.clock();
    env.set_clock(slot + 5, ts);
    let pv = env.preview();
    assert_eq!(hp.u8(&pv, "bits") & 4, 4, "bit2: pc > n_scan");
    assert_eq!(hp.u8(&pv, "status"), 8, "step 8a: the flat record's mark is older than the limit");
    assert_eq!(hp.u16(&pv, "stale_positions"), 1);
    assert_eq!(hp.u16(&pv, "position_count"), 1, "Hawkeye was called (its own limit not reached)");
    expect_err(env.harvest(), "HarvestMarkStale", "hidden position behind a stale flat record (step 8a)");
    // Older than Hawkeye's own limit (U-52): tag 30 fails inside Hawkeye.
    env.set_clock(slot + 500, ts);
    expect_foreign_err(env.harvest(), "hidden position with a mark older than Hawkeye's limit");
    env.refresh_prices();
    let x = env.harvest_inputs();
    let ex = env.expect_harvest(&x);
    check_harvest(&mut env, &x, &ex, "hot account, fresh marks");
    eprintln!(
        "U-67: map SOL position right after our withdraw_funds CPI on a hot trader: {} (ATB: -10)",
        sol_position(&env)
    );

    // A stranger's TransferCollateral into our trader syncs the map.
    env.gift(1);
    eprintln!("after a 1-atom TransferCollateral gift: map SOL position {}", sol_position(&env));
    assert_eq!(sol_position(&env), -10, "TransferCollateral rewrites the destination map from ATB");

    // Close with the trading key's IOC (its transaction writes our trader):
    // the map syncs (pc == n_scan == 0).
    let ask_px = env.ticks_for("SOL", 150_000);
    ok(env.actor_limit("taker0", "SOL", Side::Ask, ask_px, 10), "taker0 offers 0.1 SOL");
    let buy_px = env.ticks_for("SOL", 151_000);
    ok(env.send1(env.ioc_ix("SOL", 0, true, buy_px, 10), S_BOT), "vault RO buy closes the short");
    assert_eq!(sol_position(&env), 0);
    assert_eq!(env.margin(&t).position_count, 0);
    env.gift(20_000_000);
    env.pass_t_min();
    let (slot, ts) = env.clock();
    env.set_clock(slot + 5, ts);
    let pv = env.preview();
    assert_eq!(hp.u8(&pv, "bits") & 4, 0);
    assert_eq!(hp.u8(&pv, "status"), 0, "flat account: a stale mark does not block");
    ok(env.harvest(), "harvest with a stale mark of a flat market");
}

/// Base lots of `symbol` in the position map of `trader` (`None`: no record).
fn map_position_of(env: &Env, trader: &Pubkey, symbol: &str) -> Option<i64> {
    let id = env.pam_entry(symbol).asset_id;
    env.trader_hdr(trader).positions.iter().find(|(a, _)| (*a as u32) == id).map(|p| p.1)
}

/// Our trader's (possibly lagging) map record of `symbol`.
fn map_position(env: &Env, symbol: &str) -> Option<i64> {
    map_position_of(env, &env.pdas.trader.0, symbol)
}

/// TH-27, full audit FA-4 (step 8a without the `pc > n_scan` gate): the lagging map
/// can still show a position that is already closed in the ATB. Here the
/// vault is long SOL with a resting reduce ask, and has a resting ETH ask
/// (a `base = 0` record, U-55). Outside takers fill both in their own
/// transactions: SOL is flat and ETH is short in the ATB, while the map still
/// shows SOL `+10` and ETH `0`. Hawkeye counts `pc = 1 = n_scan`, so the old
/// gate skipped step 8a, step 6 checked only SOL's fresh mark, and a stale
/// ETH mark (hiding a loss) went into `D*`. Now the stale flat record is
/// status 8 / `HarvestMarkStale`; fresh marks harvest normally.
#[test]
fn harvest_stale_flat_record_behind_a_closed_map_position() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(1_000_000_000);
    // The profit first: a TransferCollateral into our trader resyncs its map.
    env.gift(50_000_000);
    // SOL long 0.1 against the fixture liquidity (our own CPI: map in sync).
    let px = env.ticks_for("SOL", 151_000);
    ok(env.send1(env.ioc_ix("SOL", 0, false, px, 10), S_BOT), "open 0.1 SOL long");
    assert_eq!(map_position(&env, "SOL"), Some(10));
    env.cancel_fixture_levels();
    // Resting ETH ask (orders only), then the SOL reduce ask: both through tag 10.
    let eth_px = env.ticks_for("ETH", 3_523_500);
    ok(env.send1(env.post_only_ix("ETH", 1, eth_px, 20), S_BOT), "vault resting ETH ask");
    let sol_px = env.ticks_for("SOL", 151_000);
    ok(env.send1(env.post_only_ix("SOL", 1, sol_px, 10), S_BOT), "vault resting SOL reduce ask");
    assert_eq!(env.our_trader().flags, FLAGS_HOT);
    eprintln!("FA-4: map after our orders: {:?}", env.our_trader().positions);
    assert_eq!((map_position(&env, "SOL"), map_position(&env, "ETH")), (Some(10), Some(0)));
    // Outside takers fill both orders in their own transactions (the taker's
    // own map is synced by its own CPI: it shows what it bought from us).
    let taker = env.ctx.actor_trader("taker0");
    let taker_at = |env: &Env, sym: &str| map_position_of(env, &taker, sym).unwrap_or(0);
    let (ts0, te0) = (taker_at(&env, "SOL"), taker_at(&env, "ETH"));
    ok(env.actor_limit("taker0", "SOL", Side::Bid, sol_px, 10), "taker0 lifts the SOL ask");
    ok(env.actor_limit("taker0", "ETH", Side::Bid, eth_px, 20), "taker0 lifts the ETH ask");
    assert_eq!((taker_at(&env, "SOL") - ts0, taker_at(&env, "ETH") - te0), (10, 20), "both our orders filled");
    let t = env.pdas.trader.0;
    let m = env.margin(&t);
    eprintln!("FA-4: map after the maker fills: {:?}; Hawkeye pc {}", env.our_trader().positions, m.position_count);
    assert_eq!(map_position(&env, "SOL"), Some(10), "map still shows the closed SOL position");
    assert_eq!(map_position(&env, "ETH"), Some(0), "map still shows ETH flat");
    assert_eq!(m.position_count, 1, "ATB: only the ETH short (SOL flat, no orders left)");

    env.pass_t_min();
    env.set_harvest_params(&with(harvest_params_default(), "harvest_mark_max_age_slots", 4));
    let hp = abi::harvest_preview();
    let pv = env.preview();
    assert_eq!(hp.u8(&pv, "bits") & 4, 0, "pc == n_scan: the old gate would skip step 8a");
    assert_eq!(hp.u8(&pv, "status"), 0, "all marks fresh");
    // 5 slots later only SOL's mark is refreshed: the ETH mark (flat record) is stale.
    let (slot, ts) = env.clock();
    env.set_clock(slot + 5, ts);
    env.set_price_milli("SOL", 150_000);
    let (sol_e, eth_e) = (env.pam_entry("SOL"), env.pam_entry("ETH"));
    if (slot + 5).saturating_sub(eth_e.mark_slot) <= 4 {
        // The oracle update touched every market: age the ETH mark by hand.
        let pam = env.fx.pam;
        let o = 48 + eth_e.slot * 1584 + 32;
        env.patch(&pam, |d| d[o..o + 8].copy_from_slice(&slot.to_le_bytes()));
    }
    eprintln!(
        "FA-4: slot {}, SOL mark slot {}, ETH mark slot {}",
        slot + 5,
        sol_e.mark_slot,
        env.pam_entry("ETH").mark_slot
    );
    assert!((slot + 5).saturating_sub(env.pam_entry("SOL").mark_slot) <= 4, "SOL (map position) fresh");
    let pv = env.preview();
    assert_eq!(hp.u8(&pv, "status"), 8, "step 8a: stale mark of the flat ETH record");
    assert_eq!(hp.u16(&pv, "stale_positions"), 1);
    assert_eq!(hp.u16(&pv, "position_count"), 1, "Hawkeye was called (its own limit not reached)");
    expect_err(env.harvest(), "HarvestMarkStale", "live ETH short behind a stale flat record, pc == n_scan");
    // Fresh marks: harvest pays as usual.
    env.refresh_prices();
    let x = env.harvest_inputs();
    let ex = env.expect_harvest(&x);
    check_harvest(&mut env, &x, &ex, "lagging map, fresh marks");
}

/// U-52: Hawkeye's own mark-staleness limit. `ViewMargin` is called at
/// growing mark ages (no oracle update in between) for a trader with an open
/// SOL position and for a flat trader; the first refused age is printed and
/// the flat trader must never be refused (harvest liveness of a flat vault
/// must not depend on other markets' oracles).
#[test]
fn hawkeye_mark_staleness_probe() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(10_000_000_000);
    let px = env.ticks_for("SOL", 151_000);
    ok(env.send1(env.ioc_ix("SOL", 0, false, px, 100), S_BOT), "open 1 SOL long");
    let ours = env.pdas.trader.0;
    let flat = env.ctx.actor_trader("taker1");
    env.refresh_prices();
    let (s0, ts) = env.clock();
    let mut first_refused = None;
    for age in [1u64, 2, 3, 5, 8, 10, 15, 20, 25, 30, 40, 50, 64, 75, 100, 125, 150, 151, 200, 500, 5000] {
        env.set_clock(s0 + age, ts);
        let ix = env.hawkeye_ix(&ours);
        let r = env.send1(ix, S_PAYER);
        if r.is_err() && first_refused.is_none() {
            first_refused = Some(age);
            let line = logs_of(&r).iter().find(|l| l.contains("stale")).cloned();
            eprintln!("U-52: Hawkeye refuses ViewMargin at mark age {age} slots (position open): {line:?}");
        }
        let ix = env.hawkeye_ix(&flat);
        let rf = env.send1(ix, S_PAYER);
        if rf.is_err() {
            eprintln!("U-52: Hawkeye refuses ViewMargin of a FLAT trader at mark age {age}");
        }
    }
    eprintln!("U-52: first refused age with a position: {first_refused:?}");
    assert!(first_refused.is_some(), "Hawkeye must refuse a very old mark");
}

/// SPEC §5.4.3: `harvest_preview` reports every refusal of tag 30 as a
/// status. When the map scan finds a stale position mark (here older than
/// Hawkeye's own limit too), the preview skips Hawkeye like tag 30 does at
/// step 6 and returns status 8 (MarkStale) with the Hawkeye fields zero
/// (BUG-phoenix-core-2 fixed).
#[test]
fn preview_reports_mark_stale_past_hawkeye_limit() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(10_000_000_000);
    let px = env.ticks_for("SOL", 151_000);
    ok(env.send1(env.ioc_ix("SOL", 0, false, px, 100), S_BOT), "open 1 SOL long");
    env.pass_t_min();
    let (slot, ts) = env.clock();
    env.set_clock(slot + 151, ts);
    let r = env.send1(env.preview_ix(), S_PAYER);
    let m = ok(r, "harvest_preview with a 151-slot-old mark");
    let hp = abi::harvest_preview();
    let pv = &m.return_data.data;
    assert_eq!(hp.u8(pv, "status"), 8);
    assert_eq!(hp.u16(pv, "stale_positions"), 1);
    assert!(!log_contains(&m.logs, &format!("Program {HAWKEYE} invoke")), "Hawkeye not called");
    assert_eq!(hp.i64(pv, "C_hk"), 0, "Hawkeye fields zero");
    assert_eq!(hp.i64(pv, "D"), 0);
    assert_eq!(hp.u16(pv, "position_count"), 0);
}

/// Set up the native collateral account state for the SyncNative regression.
/// The 0.6.5 fixture's ConfigureNativeSol admin payload no longer deserializes
/// against current mainnet Phoenix. That admin API is outside this test and
/// deliberately absent from the public SDK. Keep its real availability and
/// activation instructions, but seed the same caps / 20% discount directly.
/// Published layout: phoenix-rise-accounts 0.6.6, global_config.rs (@776) and
/// spot_collateral.rs (320 bytes); the SDK decoder checks our field offsets.
fn setup_native_sol_collateral(env: &mut Env) {
    const OFFSET: usize = 776;
    const LEN: usize = 320;
    assert_eq!(core::mem::size_of::<SpotCollateralMetadata>(), LEN);
    let setup = env.ctx.fixture.action_templates.iter().find(|t| t.name == "sol-collateral-setup").unwrap().clone();
    assert_eq!(
        setup.instructions.iter().map(|ix| ix.name.as_str()).collect::<Vec<_>>(),
        ["sol-collateral-availability", "sol-collateral-parameters", "sol-collateral-activation"]
    );
    let sol_asset = env.pam_entry("SOL").asset_id;
    for instruction in setup.instructions {
        if instruction.name == "sol-collateral-parameters" {
            env.patch(&PHOENIX_GC, |data| {
                let spot = &mut data[OFFSET..OFFSET + LEN];
                spot.fill(0); // native mint = zero, global balance = zero, reserved bytes = zero
                spot[32..36].copy_from_slice(&9u32.to_le_bytes());
                spot[36..40].copy_from_slice(&sol_asset.to_le_bytes());
                for (offset, value) in [
                    (40, 10_000_000_000u64), // per-trader cap (10 SOL)
                    (48, 100_000_000_000),   // exchange cap (100 SOL)
                    (80, 10_000_000_000),    // max liquidation size
                    (88, 10_000_000),        // post-liquidation quote buffer
                    (96, 10_000_000_000),    // quote shortfall buffer
                ] {
                    spot[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
                }
                for (offset, value) in [(64, 2_000u32), (68, 2_000), (72, 500), (76, 5)] {
                    spot[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
                }
                spot[104] = SPOT_COLLATERAL_FLAG_HAS_PERP_ASSET;
            });
            let config = GlobalConfig::try_from_account_bytes(&env.gc()).unwrap();
            let spot = config.native_sol_spot_metadata();
            assert_eq!(spot.mint_address(), [0; 32]);
            assert_eq!(spot.decimals(), 9);
            assert_eq!(spot.get_asset_id(), Some(sol_asset));
            assert_eq!(spot.max_per_trader_balance(), 10_000_000_000);
            assert_eq!(spot.max_global_balance(), 100_000_000_000);
            assert_eq!(spot.curr_global_balance(), 0);
            assert_eq!(spot.min_margin_discount().as_inner(), 2_000);
            assert_eq!(spot.max_margin_discount().as_inner(), 2_000);
            assert_eq!(spot.max_liquidation_discount().as_inner(), 500);
            assert_eq!(spot.min_liquidation_slippage().as_inner(), 5);
            assert_eq!(spot.max_liquidation_size(), 10_000_000_000);
            assert_eq!(spot.post_liquidation_buffer().as_inner(), 10_000_000);
            assert_eq!(spot.quote_lot_collateral_shortfall_buffer().as_inner(), 10_000_000_000);
            assert!(spot.discounts_in_bounds());
            assert!(!spot.is_active(), "activation must still happen through Phoenix");
        } else {
            let ix = decode_fixture_instruction(&instruction).unwrap();
            env.ctx.send_instructions(vec![ix], S_PAYER, &instruction.name);
        }
    }
    let config = GlobalConfig::try_from_account_bytes(&env.gc()).unwrap();
    assert!(config.native_sol_spot_metadata().is_active(), "real ActivateNativeSol must succeed");
}

/// TF-6b (U-53 remainder) and TB-37: with a Phoenix deposit cooldown `cd > 0`
/// a stranger runs `ReallocTrader` + a SOL transfer + `SyncNative` on our
/// `prefs = 0b11` trader. `last_deposit_slot@192` must not move, so harvest
/// is not held in `WithdrawCooldown`; the trader with `cap = 129` still works.
#[test]
fn sync_native_by_stranger_keeps_deposit_slot() {
    let Some(mut env) = Env::new() else { return };
    setup_native_sol_collateral(&mut env);
    env.setup_funded(0);
    let cd = 1_500u64;
    env.set_deposit_cooldown(cd);
    let p = 216_000u64;
    let (_, ts) = env.clock();
    let dep_slot = p + cd + 9_000;
    env.set_clock(dep_slot, ts);
    env.refresh_prices();
    ok(env.deposit(1_000_000_000), "deposit");
    let t = env.pdas.trader.0;
    assert_eq!(env.our_trader().last_deposit_slot, dep_slot);
    env.gift(40_000_000);
    env.set_clock(dep_slot + cd + 10, ts + 7200);
    env.refresh_prices();

    let attacker = env.attacker;
    let phx = env.pdas.phx_authority.0;
    let realloc = to_sol_ix(create_realloc_trader_ix(attacker, phx, t));
    let mut data = vec![2, 0, 0, 0];
    data.extend_from_slice(&10_000_000u64.to_le_bytes());
    let transfer = Instruction {
        program_id: SYSTEM_PROGRAM,
        accounts: vec![AccountMeta::new(attacker, true), AccountMeta::new(t, false)],
        data,
    };
    let sync = to_sol_ix(
        create_sync_native_ix(
            SyncNativeParams::builder()
                .trader_account(t)
                .global_trader_index(env.fx.gti.clone())
                .active_trader_buffer(env.fx.atb.clone())
                .build()
                .unwrap(),
        )
        .unwrap(),
    );
    let before = env.our_trader();
    let r = env.send(vec![realloc, transfer, sync], S_ATTACKER);
    let m = ok(r, "stranger: ReallocTrader + transfer + SyncNative");
    let after = env.our_trader();
    eprintln!(
        "TF-6b: cap {} -> {}, len {} -> {}, @192 {} -> {}, C_hdr {} -> {}, SyncNative logs: {}",
        before.cap,
        after.cap,
        before.len,
        after.len,
        before.last_deposit_slot,
        after.last_deposit_slot,
        before.collateral,
        after.collateral,
        m.logs.iter().filter(|l| l.contains("Sync") || l.contains("native")).cloned().collect::<Vec<_>>().join(" | ")
    );
    assert_eq!(after.last_deposit_slot, dep_slot, "U-53: SyncNative does not write @192 with cd > 0, prefs 0b11");
    assert!(after.positions.iter().any(|(a, _)| *a >= 0xFF00_0000), "native SOL record added");
    let trader_data = env.data(&t);
    let trader = Trader::try_from_account_bytes(&trader_data).unwrap();
    assert_eq!(trader.native_sol_collateral(), 10_000_000, "SyncNative must really credit the stranger's SOL");
    let config = GlobalConfig::try_from_account_bytes(&env.gc()).unwrap();
    assert_eq!(
        config.native_sol_spot_metadata().curr_global_balance(),
        10_000_000,
        "global native SOL tally follows the credit"
    );
    // Harvest and tag 21 keep working on the reallocated trader (TB-37).
    let x = env.harvest_inputs();
    let ex = env.expect_harvest(&x);
    check_harvest(&mut env, &x, &ex, "harvest after a stranger's SyncNative");
}

/// U-38: does Phoenix settle funding at `deposit_funds` (Δcollateral ≠ dep)?
/// A long with mark above spot accrues funding over time; the deposit is then
/// compared with the equity change `ΔC + ΔF`.
#[test]
fn deposit_with_accrued_funding_u38() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(10_000_000_000);
    let px = env.ticks_for("SOL", 151_000);
    ok(env.send1(env.ioc_ix("SOL", 0, false, px, 1000), S_BOT), "open 10 SOL long");
    let t = env.pdas.trader.0;
    let premium = |env: &mut Env| {
        env.ctx.update_oracle_prices(&[FixtureOraclePriceUpdate::new(
            "SOL",
            Some(FixturePrice::from_usd(150.0)),
            FixturePrice::from_usd(140.0),
        )]);
    };
    premium(&mut env);
    for _ in 0..8 {
        let (s, ts) = env.clock();
        env.set_clock(s + 9_000, ts + 3600);
        premium(&mut env);
    }
    let m0 = env.margin(&t);
    let c0 = env.our_trader().collateral;
    let dep = 100_000_000u64;
    ok(env.deposit(dep), "deposit with accrued funding");
    let m1 = env.margin(&t);
    let c1 = env.our_trader().collateral;
    eprintln!(
        "U-38: F {} -> {}, C_hdr {} -> {} (dC {}), C_hk {} -> {}, dep {dep}",
        m0.funding,
        m1.funding,
        c0,
        c1,
        c1 - c0,
        m0.c_hk,
        m1.c_hk
    );
    assert_eq!(env.cfg_u64("cum_inflow_usdc"), 10_000_000_000 + dep, "I += dep whatever Phoenix settles");
    let e0 = m0.c_hk + m0.upnl + m0.funding;
    let e1 = m1.c_hk + m1.upnl + m1.funding;
    eprintln!(
        "U-38: Hawkeye equity {e0} -> {e1} (dE {}), header dC {} vs dep {dep}: funding settled at deposit = {}",
        e1 - e0,
        c1 - c0,
        c1 - c0 != dep as i64
    );
    assert_eq!(e1 - e0, dep as i64, "equity C + U + F grows by exactly dep");

    // Harvest with unsettled funding F < 0: D* includes min(0, U + F), and
    // Phoenix may settle F at withdraw (U-8, SPEC §5.4.4).
    env.gift(100_000_000);
    let (s, ts) = env.clock();
    env.set_clock(s + 2, ts + 3601);
    premium(&mut env);
    let x = env.harvest_inputs();
    let ex = env.expect_harvest(&x);
    let c_before = env.our_trader().collateral;
    eprintln!("U-8: before harvest F {} U {} C_hk {} C_hdr {}", x.m.funding, x.m.upnl, x.m.c_hk, x.c_hdr);
    let (d, _, _) = check_harvest(&mut env, &x, &ex, "harvest with unsettled funding");
    let m2 = env.margin(&t);
    let c_after = env.our_trader().collateral;
    eprintln!(
        "U-8: after withdraw of D {d}: C_hdr -{}, F {} -> {} (settled at withdraw = {})",
        c_before - c_after,
        x.m.funding,
        m2.funding,
        m2.funding != x.m.funding
    );
}

/// U-7: a non-zero `withdrawal_fee` in the queue header. Is it taken out of
/// the amount (`r < D`, any holdback accepted since SPEC v4, booked in `cum_withdraw_fees`) or on
/// top of it (`r = D`, collateral −(D + fee))? Harvest must go through in
/// both cases (SPEC §5.4.4, ACC-7).
#[test]
fn harvest_with_withdrawal_fee_u7() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(1_000_000_000);
    env.gift(100_000_000);
    env.pass_t_min();
    env.wq_set(wq::WITHDRAWAL_FEE, 500_000);
    let x = env.harvest_inputs();
    let ex = env.expect_harvest(&x);
    let c0 = env.our_trader().collateral;
    let m = ok(env.harvest(), "harvest with withdrawal_fee 0.5 USDC");
    let ev = one_event(&m.logs, "SJKEVHRV");
    let e = abi::event("SJKEVHRV");
    let (d, r, u) = (e.u64(&ev, "D"), e.u64(&ev, "r"), e.u64(&ev, "usdc_received"));
    let dc = c0 - env.our_trader().collateral;
    eprintln!(
        "U-7: D {d} r {r} u {u} collateral -{dc} cum_withdraw_fees {} fee {}",
        env.cfg_u64("cum_withdraw_fees"),
        env.wq_u64(wq::WITHDRAWAL_FEE)
    );
    assert_eq!(i128::from(d), ex.d);
    assert_eq!(env.cfg_u64("cum_withdraw_fees"), d - u, "held-back part booked");
    assert_eq!(env.cfg_u64("cum_payout_usdc"), u, "O += u (what arrived)");
}

/// U-52: does Phoenix withdraw against a stale mark? With
/// `harvest_mark_max_age_slots = 0` the program does not look; the outcome
/// shows what Phoenix itself does with an open position and an old mark.
#[test]
fn stale_mark_withdraw_u52() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(10_000_000_000);
    let px = env.ticks_for("SOL", 151_000);
    ok(env.send1(env.ioc_ix("SOL", 0, false, px, 1000), S_BOT), "open 10 SOL long");
    env.gift(100_000_000);
    env.pass_t_min();
    env.set_harvest_params(&with(harvest_params_default(), "harvest_mark_max_age_slots", 0));
    let (slot, ts) = env.clock();
    env.set_clock(slot + 5_000, ts + 60);
    let r = env.harvest();
    match &r {
        Ok(m) => {
            let ev = one_event(&m.logs, "SJKEVHRV");
            eprintln!("U-52: Phoenix paid D {} against a 5000-slot-old mark", abi::event("SJKEVHRV").u64(&ev, "D"));
        }
        Err(e) => eprintln!("U-52: Phoenix refused the withdraw with a 5000-slot-old mark: {:?}", e.err),
    }
}

/// U-45: what the fixture provides (native mint, SOL mark and tick filled,
/// deposits work without patching `@88`) and its defaults the tests rely on.
#[test]
fn fixture_facts_u45() {
    let Some(mut env) = Env::new() else { return };
    let native = env.ctx.svm.get_account(&WSOL_MINT);
    eprintln!(
        "native mint present: {} (owner {:?}, {} bytes)",
        native.is_some(),
        native.as_ref().map(|a| a.owner),
        native.as_ref().map_or(0, |a| a.data.len())
    );
    // U-45 refuted for the native mint: neither LiteSVM 0.16 nor the fixture
    // creates `So111…112`; tests that need wSOL accounts must install it.
    assert!(native.is_none(), "native mint unexpectedly present: update U-45");
    let sol = env.pam_entry("SOL");
    let (slot, _) = env.clock();
    eprintln!(
        "SOL PAM: slot {} asset_id {} mark {} ticks at slot {} (now {slot}), tick {} lots 10^-{}",
        sol.slot, sol.asset_id, sol.mark_ticks, sol.mark_slot, sol.tick_size, sol.base_lot_decimals
    );
    assert!(sol.mark_ticks > 0 && sol.tick_size > 0, "U-45: SOL mark and tick filled");
    assert_eq!(sol.mark_slot, slot, "marks are re-published at the test slot");
    assert_eq!(env.ticks_for("SOL", 150_000), sol.mark_ticks, "150 USD = the fixture SOL mark");
    eprintln!(
        "GC@504 {:#010b} (fixture not gated), GC@512 cd {}, withdraw queue max_budget {} replenish {}",
        env.exchange_status(),
        env.gc_u64(512),
        env.wq_u64(wq::MAX_BUDGET),
        env.wq_u64(wq::REPLENISH)
    );
    assert_eq!(env.exchange_status() & 0b10, 0, "fixture exchange is not gated");
    // Deposits credit @88 without a set_account fallback.
    env.setup_funded(10_000_000);
    assert_eq!(env.our_trader().collateral, 10_000_000, "U-45: no @88 fallback needed");
}
