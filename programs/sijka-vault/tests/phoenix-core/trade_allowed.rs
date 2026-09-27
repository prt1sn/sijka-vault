// Copyright (c) 2026 prt1sn. All rights reserved.
//! TT-1, TT-10, TT-11, TT-12, TT-14 (SPEC v3 §5.2, §9.4): each of the 14
//! allowlisted Phoenix instructions goes through tag 10 on the mainnet
//! Phoenix binary and does what it does for any trader: orders fill or rest
//! (checked on the FIFO orderbook and in Phoenix's own return data), batches
//! rest, every cancel removes exactly what it names, stop-loss and conditional
//! orders land in their PDAs and cancel. The trading key pays the rent of the
//! PDAs; nothing outside Phoenix moves (INV-9). Pauses and admin state do not
//! restrict trading (T13; SPEC v4: no pauses at all). Prices are chosen away from the fixture maker's
//! levels (149–151 USD on SOL), so resting orders at them are ours.

use phoenix_rise::ix::market_order::{MarketOrderParams, create_place_market_order_ix};
use phoenix_rise::ix::types::{OrderFlags, SelfTradeBehavior, Side};
use phoenix_rise_litesvm_test::parse_pubkey;
use solana_pubkey::Pubkey;

use crate::abi;
use crate::harness::*;
use crate::phx::*;
use crate::phx_trade::*;

impl Env {
    /// SOL price in ticks for each of `usd_milli`.
    fn sol<const N: usize>(&self, usd_milli: [u64; N]) -> [u64; N] {
        usd_milli.map(|u| self.ticks_for("SOL", u))
    }

    /// A fixture actor's own IOC, sent directly to Phoenix.
    fn actor_ioc(&mut self, actor: &str, symbol: &str, price_ticks: u64, lots: u64) -> TxResult {
        let a = self.ctx.actor(actor);
        let (slot, _) = self.clock();
        let params = MarketOrderParams::builder()
            .trader(parse_pubkey(&a.pubkey).unwrap())
            .trader_account(parse_pubkey(&a.trader_account).unwrap())
            .perp_asset_map(self.fx.pam)
            .orderbook(self.market_book(symbol))
            .spline_collection(self.market_spline(symbol))
            .global_trader_index(self.fx.gti.clone())
            .active_trader_buffer(self.fx.atb.clone())
            .side(Side::Bid)
            .price_in_ticks(price_ticks)
            .num_base_lots(lots)
            .self_trade_behavior(SelfTradeBehavior::CancelProvide)
            .client_order_id(7)
            .last_valid_slot(slot + 100)
            .order_flags(OrderFlags::None)
            .build()
            .unwrap();
        let ix = to_sol_ix(create_place_market_order_ix(params).unwrap());
        self.send1(ix, &a.seed)
    }
}

fn one_at(env: &Env, bid: bool, price: u64, lots: u64, label: &str) {
    let o = env.book_at("SOL", bid, price);
    assert_eq!(o.len(), 1, "{label}: one order at {price}: {o:?}");
    assert_eq!(o[0].lots, lots, "{label}: size at {price}");
}

/// TT-1 #1, #2, #7: IOC and a crossing Limit fill (taker, the position map
/// follows), a Limit and a PostOnly rest with the id Phoenix returns, any
/// market of the fixture works, large orders far from the mark reach Phoenix
/// (the program has no size, leverage or price rule, T13), `CancelAll`
/// clears the book and sets no return data.
#[test]
fn tt1_market_limit_post_only_and_cancel_all() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(1_000_000_000);
    let before = env.outside();
    let [take, bid, ask, far, big] = env.sol([151_000, 140_000, 160_000, 75_000, 165_000]);

    // #1 PlaceMarketOrder: an IOC bid fills against the fixture asks.
    let m = ok(env.send1(env.ioc_ix("SOL", 0, false, take, 10), S_BOT), "#1 PlaceMarketOrder");
    assert!(phoenix_called(&m.logs), "Phoenix called by the program");
    let r = order_result(&m, Side::Bid, "#1 IOC");
    assert_eq!((r.filled, r.posted), (10, 0), "#1: filled, nothing rests");
    assert_eq!(env.position("SOL"), 10);

    // #2 PlaceLimitOrder, Limit packet across the book: it takes.
    let m = ok(env.send1(env.trade_ix(env.phx_limit_ix("SOL", 0, take, 4)), S_BOT), "#2 Limit crossing");
    let r = order_result(&m, Side::Bid, "#2 Limit crossing");
    assert_eq!((r.filled, r.posted), (4, 0));
    assert_eq!(env.position("SOL"), 14);

    // #2 Limit packet below the book: it rests with the id of the response.
    let m = ok(env.send1(env.trade_ix(env.phx_limit_ix("SOL", 0, bid, 5)), S_BOT), "#2 Limit resting");
    let r = order_result(&m, Side::Bid, "#2 Limit resting");
    assert_eq!((r.filled, r.posted, r.price), (0, 5, bid));
    assert_eq!(env.book_at("SOL", true, bid), vec![BookOrder { bid: true, price: bid, seq: r.seq, lots: 5 }]);

    // #2 PostOnly packet: an ask above the book rests.
    let m = ok(env.send1(env.trade_ix(env.phx_post_only_ix("SOL", 1, ask, 3)), S_BOT), "#2 PostOnly");
    let r = order_result(&m, Side::Ask, "#2 PostOnly");
    assert_eq!((r.filled, r.posted, r.price), (0, 3, ask));
    assert_eq!(env.book_at("SOL", false, ask), vec![BookOrder { bid: false, price: ask, seq: r.seq, lots: 3 }]);

    // Any market of the fixture: no market list in the program.
    for sym in ["BTC", "ETH"] {
        let px = env.ticks_for(sym, env.mark_usd_milli(sym) * 97 / 100);
        let m = ok(env.send1(env.post_only_ix(sym, 0, px, 2), S_BOT), &format!("#2 resting bid on {sym}"));
        assert_eq!(order_result(&m, Side::Bid, sym).posted, 2);
        let mine: Vec<_> = env.book(sym).into_iter().filter(|o| o.bid && o.price == px).collect();
        assert_eq!(mine.len(), 1, "{sym}: our bid rests");
        let m = ok(env.send1(env.cancel_all_ix(sym), S_BOT), &format!("#7 CancelAll {sym}"));
        assert!(m.return_data.data.is_empty(), "cancels set no return data");
        assert!(!env.book(sym).iter().any(|o| o.bid && o.price == px), "{sym}: cancelled");
    }

    // Large and far from the mark: forwarded; Phoenix's margin rules decide.
    ok_or_foreign(env.send1(env.post_only_ix("SOL", 0, far, 100_000), S_BOT), "1000 SOL bid at half the mark");
    ok_or_foreign(env.send1(env.ioc_ix("SOL", 0, false, big, 20_000), S_BOT), "200 SOL IOC buy");

    // #7 CancelAll.
    let m = ok(env.send1(env.cancel_all_ix("SOL"), S_BOT), "#7 CancelAll");
    assert!(phoenix_called(&m.logs));
    assert!(m.return_data.data.is_empty(), "cancels set no return data");
    for (b, px) in [(true, bid), (false, ask), (true, far)] {
        assert!(env.book_at("SOL", b, px).is_empty(), "#7: nothing of ours at {px}");
    }
    assert_eq!(env.outside(), before, "INV-9: nothing outside Phoenix moved");
}

/// TT-1 #3, #4, #5, #6, #7: post-only batches (V1 and V2) rest on both
/// sides and set no return data; `CancelOrdersById` cancels our id and
/// passes over an id nobody has; `CancelUpTo` takes one side; `CancelAll`
/// the rest.
#[test]
fn tt1_batches_and_cancels() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(1_000_000_000);
    let before = env.outside();
    let [b1, b2, b3, ghost, a1, a2, a3] = env.sol([141_000, 142_000, 143_000, 141_500, 157_000, 158_000, 159_000]);

    // #3 PlaceMultiLimitOrder.
    let ix = env.trade_ix(env.phx_multi_ix("SOL", &[(b1, 3), (b2, 4)], &[(a2, 3), (a3, 4)], false));
    let m = ok(env.send1(ix, S_BOT), "#3 PlaceMultiLimitOrder");
    assert!(phoenix_called(&m.logs));
    assert!(m.return_data.data.is_empty(), "#3: batches set no return data");
    for (bid, px, lots) in [(true, b1, 3), (true, b2, 4), (false, a2, 3), (false, a3, 4)] {
        one_at(&env, bid, px, lots, "#3");
    }

    // #4 PlaceMultiLimitOrderV2.
    let ix = env.trade_ix(env.phx_multi_ix("SOL", &[(b3, 2)], &[(a1, 2)], true));
    let m = ok(env.send1(ix, S_BOT), "#4 PlaceMultiLimitOrderV2");
    assert!(m.return_data.data.is_empty(), "#4: batches set no return data");
    one_at(&env, true, b3, 2, "#4");
    one_at(&env, false, a1, 2, "#4");

    // #5 CancelOrdersById: our bid at b1 and an id that is not on the book.
    let own = env.book_at("SOL", true, b1)[0];
    let ix = env.trade_ix(env.phx_cancel_by_id_ix("SOL", &[(b1, own.seq), (ghost, own.seq)]));
    let m = ok(env.send1(ix, S_BOT), "#5 CancelOrdersById (own and unknown id)");
    assert!(m.return_data.data.is_empty());
    assert!(log_contains(&m.logs, "Failed to cancel order"), "#5: Phoenix logs the unknown id\n{}", m.logs.join("\n"));
    assert!(env.book_at("SOL", true, b1).is_empty(), "#5: our order cancelled");
    one_at(&env, true, b2, 4, "#5: the others stay");
    one_at(&env, false, a2, 3, "#5: the others stay");

    // #6 CancelUpTo on the ask side, no threshold: every ask of ours.
    let m = ok(env.send1(env.trade_ix(env.phx_cancel_up_to_ix("SOL", 1)), S_BOT), "#6 CancelUpTo asks");
    assert!(m.return_data.data.is_empty());
    for px in [a1, a2, a3] {
        assert!(env.book_at("SOL", false, px).is_empty(), "#6: ask at {px} cancelled");
    }
    one_at(&env, true, b2, 4, "#6: bids stay");
    one_at(&env, true, b3, 2, "#6: bids stay");

    // #7 CancelAll.
    ok(env.send1(env.cancel_all_ix("SOL"), S_BOT), "#7 CancelAll");
    for px in [b2, b3] {
        assert!(env.book_at("SOL", true, px).is_empty(), "#7: bid at {px} cancelled");
    }
    assert_eq!(env.outside(), before, "INV-9");
}

/// TT-1 #8, #9, #11, #12, #13 and SPEC §5.2.6: the trading key creates the
/// conditional-orders PDA directly on Phoenix (not an allowlisted
/// instruction, refused by tag 10); a position conditional order (signer at
/// `n − 3`) lands and cancels; a limit order with a take-profit leg rests
/// with the leg attached; a stop leg attaches to our own resting order; and
/// `CancelAllPlusConditional` clears the orders with their legs. The trading
/// key pays the PDA; nothing outside Phoenix moves.
#[test]
fn tt1_conditional_orders() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(1_000_000_000);
    let before = env.outside();
    let (bot, a, t) = (env.bot, env.pdas.phx_authority.0, env.pdas.trader.0);
    let sol = env.pam_entry("SOL").asset_id;
    let [take, stop, stop_x, bid1, bid2, tp, tp_x, stop2, stop2_x] =
        env.sol([151_000, 140_000, 139_000, 141_000, 142_000, 170_000, 169_000, 130_000, 129_000]);

    // SPEC §5.2.6: CreateConditionalOrdersAccount needs no owner signature;
    // tag 10 refuses it, the trading key calls Phoenix directly.
    let ix = env.trade_ix(env.phx_create_cond_orders_ix(&bot, 8));
    env.refuse(ix, "TradeInstructionNotAllowed", "CreateConditionalOrdersAccount through tag 10");
    let key_before = env.lamports(&bot);
    let ix = env.phx_create_cond_orders_ix(&bot, 8);
    ok(env.send1(ix, S_BOT), "CreateConditionalOrdersAccount by the trading key");
    let cond = env.cond_orders_key();
    assert!(env.exists(&cond), "conditional-orders PDA created");
    assert!(env.lamports(&bot) < key_before, "the trading key paid the rent");
    assert!(env.active_cond_orders().is_empty());

    // A long for the position conditional order.
    ok(env.send1(env.ioc_ix("SOL", 0, false, take, 10), S_BOT), "open a long");

    // #11 PlacePositionConditionalOrder: signer slot n − 3, System last.
    let phx = env.phx_position_conditional_ix("SOL", stop_below(stop, stop_x), 100);
    let n = phx.accounts.len();
    assert_eq!(phx.accounts[n - 3].pubkey, a, "AU = n - 3");
    assert_eq!(phx.accounts[n - 1].pubkey, SYSTEM_PROGRAM, "System last");
    assert_eq!((phx.accounts[3].pubkey, phx.accounts[4].pubkey), (bot, t), "payer, T");
    let m = ok(env.send1(env.trade_ix(phx), S_BOT), "#11 PlacePositionConditionalOrder");
    assert!(m.return_data.data.is_empty());
    let c = env.active_cond_orders();
    assert_eq!(c.len(), 1, "#11: one conditional order: {c:?}");
    assert_eq!(c[0].asset_id, sol);

    // #13 CancelConditionalOrder of that entry.
    let phx = env.phx_cancel_conditional_ix("SOL", c[0].index);
    assert_eq!((phx.accounts[3].pubkey, phx.accounts[4].pubkey), (t, a), "T at 3, signer at 4");
    let m = ok(env.send1(env.trade_ix(phx), S_BOT), "#13 CancelConditionalOrder");
    assert!(m.return_data.data.is_empty());
    assert!(env.active_cond_orders().is_empty(), "#13: cancelled");

    // #9 PlaceLimitOrderWithConditionals: a resting bid with a take-profit leg.
    let phx = env.phx_limit_with_conditionals_ix("SOL", 0, bid1, 5, Some(take_profit_above(tp, tp_x)), None);
    let m = ok(env.send1(env.trade_ix(phx), S_BOT), "#9 PlaceLimitOrderWithConditionals");
    let r9 = order_result(&m, Side::Bid, "#9");
    assert_eq!((r9.filled, r9.posted, r9.price), (0, 5, bid1));
    one_at(&env, true, bid1, 5, "#9");
    let c = env.active_cond_orders();
    assert_eq!(c.len(), 1, "#9: the take-profit leg: {c:?}");
    assert_eq!(c[0].order_id, Some((bid1, r9.seq)), "#9: the leg belongs to our resting bid");

    // #12 PlaceAttachedConditionalOrder to our own resting order (its id from
    // the return data of #2).
    let m = ok(env.send1(env.trade_ix(env.phx_limit_ix("SOL", 0, bid2, 4)), S_BOT), "#2 parent order");
    let parent = order_result(&m, Side::Bid, "#2 parent");
    assert_eq!(parent.posted, 4);
    let phx = env.phx_attached_conditional_ix("SOL", (parent.price, parent.seq), stop_below(stop2, stop2_x));
    assert_eq!(
        (phx.accounts[3].pubkey, phx.accounts[4].pubkey, phx.accounts[7].pubkey),
        (t, a, bot),
        "T, signer, payer"
    );
    let m = ok(env.send1(env.trade_ix(phx), S_BOT), "#12 PlaceAttachedConditionalOrder");
    assert!(m.return_data.data.is_empty());
    let c = env.active_cond_orders();
    assert_eq!(c.len(), 2, "#12: {c:?}");
    assert!(c.iter().any(|o| o.order_id == Some((bid2, parent.seq))), "#12: attached to the parent: {c:?}");

    // #8 CancelAllPlusConditional: the resting orders and their legs.
    let m = ok(env.send1(env.trade_ix(env.phx_cancel_all_plus_conditional_ix("SOL")), S_BOT), "#8");
    assert!(m.return_data.data.is_empty());
    assert!(env.book_at("SOL", true, bid1).is_empty() && env.book_at("SOL", true, bid2).is_empty(), "#8: orders");
    let c = env.active_cond_orders();
    assert!(c.is_empty(), "#8: conditional legs cleared: {c:?}");

    assert_eq!(env.outside(), before, "INV-9: the trading key paid, nothing outside Phoenix moved");
}

/// TT-1 #10, #14 and TT-10: a legacy stop loss funded by the trading key
/// (signer slot `n − 3`, System last) lands in its PDA; after `set_trader`
/// the new key cannot redirect its rent (Phoenix: "Stop loss funding key
/// mismatch"), but cancels it with the old key as funder (writable, not a
/// signer), and the rent goes back to the old key; the new key then places
/// and cancels its own.
#[test]
fn tt1_tt10_stop_loss_and_key_rotation() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(1_000_000_000);
    let (bot, a) = (env.bot, env.pdas.phx_authority.0);
    let [take, trigger] = env.sol([151_000, 100_000]);
    ok(env.send1(env.ioc_ix("SOL", 0, false, take, 10), S_BOT), "open a long");
    let before = env.outside();
    let sl = env.stop_loss_key("SOL");
    assert_eq!(env.stop_loss("SOL"), None);

    // #10 PlaceStopLoss.
    let phx = env.phx_stop_loss_ix("SOL", trigger);
    let n = phx.accounts.len();
    assert_eq!(phx.accounts[n - 3].pubkey, a, "AU = n - 3");
    assert_eq!(phx.accounts[n - 1].pubkey, SYSTEM_PROGRAM, "System last");
    assert_eq!(phx.accounts[3].pubkey, bot, "funder = the trading key");
    let m = ok(env.send1(env.trade_ix(phx), S_BOT), "#10 PlaceStopLoss");
    assert!(m.return_data.data.is_empty());
    assert_eq!(env.stop_loss("SOL"), Some((true, bot)), "#10: active, funded by the trading key");
    let rent = env.lamports(&sl);
    assert!(rent > 0);

    // TT-10: rotate the key.
    let bot2 = env.ctx.add_signer(S_BOT2, 10_000_000_000);
    ok(env.set_trader(&bot2), "set_trader(new key)");
    let ix = env.trade_ix(env.phx_cancel_stop_loss_ix("SOL", &bot));
    expect_err(env.send1(ix, S_BOT), "UnauthorizedTrader", "the old key after rotation");
    // Funder = the new key: past our checks, refused by Phoenix.
    let ix = env.trade_ix_as(&bot2, env.phx_cancel_stop_loss_ix("SOL", &bot2));
    let e = expect_foreign_err(env.send1(ix, S_BOT2), "TT-10: rent to the new key");
    assert!(phoenix_called(&e.meta.logs), "our checks passed");
    assert!(
        log_contains(&e.meta.logs, "Stop loss funding key mismatch"),
        "Phoenix refuses another funder\n{}",
        e.meta.logs.join("\n")
    );
    assert_eq!(env.stop_loss("SOL"), Some((true, bot)));
    // #14 CancelStopLoss signed by the new key, rent to the old key.
    let old_before = env.lamports(&bot);
    let ix = env.trade_ix_as(&bot2, env.phx_cancel_stop_loss_ix("SOL", &bot));
    let m = ok(env.send1(ix, S_BOT2), "#14 CancelStopLoss, funder = the old key");
    assert!(m.return_data.data.is_empty());
    assert!(!env.exists(&sl), "#14: stop-loss PDA closed");
    assert_eq!(env.lamports(&bot), old_before + rent, "rent back to the original payer");

    // The new key on its own.
    let ix = env.trade_ix_as(&bot2, env.phx_stop_loss_ix_by("SOL", &bot2, trigger));
    ok(env.send1(ix, S_BOT2), "#10 by the new key");
    assert_eq!(env.stop_loss("SOL"), Some((true, bot2)));
    let ix = env.trade_ix_as(&bot2, env.phx_cancel_stop_loss_ix("SOL", &bot2));
    ok(env.send1(ix, S_BOT2), "#14 by the new key");
    assert!(!env.exists(&sl));

    let after = env.outside();
    assert_eq!(after.tokens, before.tokens, "INV-9: token balances");
    assert_eq!((after.fee_inbox, after.phx_authority), (before.fee_inbox, before.phx_authority), "INV-9: lamports");
    assert_eq!((after.authority, after.position_authority), (a, a), "no delegate");
}

/// TT-11 (T13): the retired pause bytes (SPEC v4: `Config@1152`, the former
/// `inflow_pause_mask`, and `BuybackState@24`, the former `pause_until`)
/// and a keeper key change nothing for trading: the trading key opens,
/// closes reduce-only at any price, rests and cancels; the deposit ignores
/// the old pause byte too.
#[test]
fn tt11_pauses_do_not_stop_trading() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(1_000_000_000);
    ok(env.send1(env.bb_init_ix(), S_PAYER), "bb_init");
    let (cfg, bbs) = (env.pdas.config.0, env.pdas.buyback_state.0);
    let pause_off = abi::config().field("_reserved10").offset;
    let bb_pause_off = abi::buyback_state().field("_reserved1").offset;
    env.patch(&cfg, |d| d[pause_off] = 3);
    env.patch(&bbs, |d| d[bb_pause_off..bb_pause_off + 8].copy_from_slice(&i64::MAX.to_le_bytes()));
    let keeper = Pubkey::new_unique();
    ok(env.set_keeper(&keeper), "a keeper key");
    ok(env.deposit(5_000_000), "no inflow pause since SPEC v4");

    let [take, bid] = env.sol([151_000, 140_000]);
    ok(env.send1(env.ioc_ix("SOL", 0, false, take, 10), S_BOT), "open a long while paused");
    assert_eq!(env.position("SOL"), 10);
    ok(env.send1(env.ioc_ix("SOL", 1, true, 1, 10), S_BOT), "reduce-only close at 1 tick while paused");
    assert_eq!(env.position("SOL"), 0);
    let m = ok(env.send1(env.post_only_ix("SOL", 0, bid, 5), S_BOT), "resting bid while paused");
    assert_eq!(order_result(&m, Side::Bid, "paused").posted, 5);
    ok(env.send1(env.cancel_all_ix("SOL"), S_BOT), "CancelAll while paused");
    assert!(env.book_at("SOL", true, bid).is_empty());
}

/// TT-12: tag 10 costs ≤ 20k CU over the same Phoenix instruction sent
/// directly by a fixture trader (both accounts warmed up: the first order
/// makes a cold trader hot).
#[test]
fn tt12_cu_overhead_of_tag_10() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(1_000_000_000);
    let [w_ours, w_theirs, ours_px, theirs_px, take] = env.sol([139_000, 139_100, 138_000, 138_100, 151_000]);
    ok(env.send1(env.trade_ix(env.phx_limit_ix("SOL", 0, w_ours, 1)), S_BOT), "warm-up (ours)");
    ok(env.actor_limit("taker0", "SOL", Side::Bid, w_theirs, 1), "warm-up (taker0)");

    let ours = ok(env.send1(env.trade_ix(env.phx_limit_ix("SOL", 0, ours_px, 1)), S_BOT), "PlaceLimitOrder via tag 10");
    let direct = ok(env.actor_limit("taker0", "SOL", Side::Bid, theirs_px, 1), "PlaceLimitOrder direct");
    let (o, d) = (ours.compute_units_consumed, direct.compute_units_consumed);
    eprintln!("TT-12 PlaceLimitOrder: tag 10 {o} CU, direct {d} CU, overhead {}", o as i64 - d as i64);
    assert!(o <= d + 20_000, "PlaceLimitOrder: tag 10 overhead {} > 20k", o as i64 - d as i64);

    let ours = ok(env.send1(env.ioc_ix("SOL", 0, false, take, 1), S_BOT), "PlaceMarketOrder via tag 10");
    let direct = ok(env.actor_ioc("taker0", "SOL", take, 1), "PlaceMarketOrder direct");
    let (o, d) = (ours.compute_units_consumed, direct.compute_units_consumed);
    eprintln!("TT-12 PlaceMarketOrder: tag 10 {o} CU, direct {d} CU, overhead {}", o as i64 - d as i64);
    assert!(o <= d + 20_000, "PlaceMarketOrder: tag 10 overhead {} > 20k", o as i64 - d as i64);
}

/// TT-14: several tag 10 in one transaction work; the transaction's return
/// data is the last order-placing call's, and any later CPI (a cancel through
/// tag 10) clears it (SPEC §5.2.4).
#[test]
fn tt14_several_trades_in_one_transaction() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(1_000_000_000);
    let [bid, take] = env.sol([140_000, 151_000]);
    let ixs = vec![env.trade_ix(env.phx_limit_ix("SOL", 0, bid, 5)), env.ioc_ix("SOL", 0, false, take, 3)];
    let m = ok(env.send(ixs, S_BOT), "resting bid, then IOC");
    let r = order_result(&m, Side::Bid, "last order-placing call");
    assert_eq!((r.filled, r.posted), (3, 0), "the IOC's response, not the resting bid's");
    one_at(&env, true, bid, 5, "the first order rests");
    assert_eq!(env.position("SOL"), 3);

    let ixs = vec![env.ioc_ix("SOL", 0, false, take, 2), env.cancel_all_ix("SOL")];
    let m = ok(env.send(ixs, S_BOT), "IOC, then CancelAll");
    assert!(m.return_data.data.is_empty(), "the cancel's CPI cleared the IOC's return data");
    assert!(env.book_at("SOL", true, bid).is_empty());
    assert_eq!(env.position("SOL"), 5);
}
