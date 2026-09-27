// Copyright (c) 2026 prt1sn. All rights reserved.
//! Shared pieces of the tag 10 tests (SPEC v3 §5.2, §9.4 TT-*): builders for
//! the 14 allowlisted Phoenix trading instructions on our trader `T` with
//! `traderWallet = phx_authority` and the trading key as payer / funder, the
//! Phoenix instructions tag 10 must refuse (money movers, account and
//! permission changes, delegation), a raw tag 10 wrapper for layouts the
//! program must reject, and readers of the Phoenix state the tests assert on:
//! the order result in the transaction's return data
//! (`MatchingEngineCPIResponse`), the FIFO orderbook, the conditional-orders
//! and stop-loss PDAs, and the balances outside Phoenix (INV-9).

#![allow(deprecated)] // legacy stop-loss builders of the SDK (still on the allowlist)

use litesvm::types::{FailedTransactionMetadata, TransactionMetadata};
use phoenix_rise::accounts::conditional_orders::ConditionalOrders;
use phoenix_rise::accounts::orderbook::Orderbook;
use phoenix_rise::accounts::stop_losses::StopLosses;
use phoenix_rise::ix::cancel_orders::{
    CancelOrdersByIdParams, CancelUpToParams, create_cancel_orders_by_id_ix, create_cancel_up_to_ix,
};
use phoenix_rise::ix::cancel_stop_loss::{CancelStopLossParams, create_cancel_stop_loss_ix};
use phoenix_rise::ix::conditional_order::{
    CancelConditionalOrderParams, CreateConditionalOrdersAccountParams, PlaceAttachedConditionalOrderParams,
    PlaceLimitOrderWithConditionalsParams, PlacePositionConditionalOrderParams, TriggerOrderParams,
    create_cancel_conditional_order_ix, create_create_conditional_orders_account_ix,
    create_place_attached_conditional_order_ix, create_place_limit_order_with_conditionals_ix,
    create_place_position_conditional_order_ix,
};
use phoenix_rise::ix::constants::{get_conditional_orders_address, get_stop_loss_address};
use phoenix_rise::ix::delegate_trader::{DelegateTraderParams, create_delegate_trader_ix};
use phoenix_rise::ix::deposit_funds::{DepositFundsParams, create_deposit_funds_ix};
use phoenix_rise::ix::discriminants::PhoenixInstruction;
use phoenix_rise::ix::market_order::{
    MarketOrderDelegatedParams, MarketOrderParams, create_place_market_order_delegated_ix,
};
use phoenix_rise::ix::multi_limit_order::{
    MultiLimitOrderParams, MultiLimitOrderParamsV2, create_place_multi_limit_order_ix,
    create_place_multi_limit_order_v2_ix,
};
use phoenix_rise::ix::native_sol::create_realloc_trader_ix;
use phoenix_rise::ix::order_packet::{CondensedOrder, CondensedOrderV2, OrderPacket};
use phoenix_rise::ix::place_stop_loss::{PlaceStopLossParams, create_place_stop_loss_ix};
use phoenix_rise::ix::sync_parent_to_child::{SyncParentToChildParams, create_sync_parent_to_child_ix};
use phoenix_rise::ix::transfer_collateral::{
    TransferCollateralChildToParentParams, TransferCollateralParams, create_transfer_collateral_child_to_parent_ix,
    create_transfer_collateral_ix,
};
use phoenix_rise::ix::types::{
    CancelId, Direction, FifoOrderId, OrderFlags, SelfTradeBehavior, Side, StopLossOrderKind,
};
use phoenix_rise::ix::withdraw_funds::{WithdrawFundsParams, create_withdraw_funds_ix};
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::harness::*;
use crate::ixs::side_of;
use crate::phx::*;

/// Second trading key (rotation tests).
pub const S_BOT2: &str = "pc-bot-2";

/// Phoenix instructions that exist only in the on-chain IDL (not in the SDK
/// enum), with their `sha256("global:<snake>")[..8]` from appendix H §1.
pub const IDL_ONLY: [(&str, &str); 10] = [
    ("set_trader_cap_override", "bf93afb9c064e95e"),
    ("clear_position_flip_orders", "f57125625234785b"),
    ("update_perp_risk_factors", "08f2d1cc4f911825"),
    ("update_perp_transfer_fee_tiers", "aaf6b7c173bd975e"),
    ("update_perp_parameters_delegated", "f5b934e4b5588ede"),
    ("set_spot_asset_price", "f6ace619be3a3a09"),
    ("change_spot_asset_params", "296ece48bbc5c570"),
    ("configure_native_sol", "f1132c257733c51b"),
    ("activate_native_sol", "0ff65b5d46e9bf78"),
    ("migrate_trader_state", "160e4ad66c48cf64"),
];

/// Our program called Phoenix (depth 2): every check of tag 10 passed.
pub fn phoenix_called(logs: &[String]) -> bool {
    log_contains(logs, &format!("Program {PHOENIX} invoke [2]"))
}

/// No Phoenix invocation at any depth.
pub fn no_phoenix(logs: &[String]) -> bool {
    !log_contains(logs, &format!("Program {PHOENIX} invoke"))
}

/// Ok, or a failure inside Phoenix after our checks passed (never one of our
/// errors). What Phoenix does with a layout the program accepted is Phoenix's
/// business (margin, price bands of the venue).
pub fn ok_or_foreign(r: TxResult, label: &str) -> bool {
    match r {
        Ok(m) => {
            assert!(phoenix_called(&m.logs), "{label}: Phoenix not called\n{}", m.logs.join("\n"));
            eprintln!("{label}: ok");
            true
        }
        Err(e) => {
            assert!(!e.meta.logs.iter().any(|l| l.contains("Sijka: ")), "{label}: Sijka error\n{:?}", e.meta.logs);
            assert!(phoenix_called(&e.meta.logs), "{label}: failed before Phoenix\n{}", e.meta.logs.join("\n"));
            eprintln!("{label}: Phoenix refused: {:?}", e.err);
            false
        }
    }
}

/// A trigger that closes a long below `trigger` (stop-loss leg).
pub fn stop_below(trigger: u64, execution: u64) -> TriggerOrderParams {
    TriggerOrderParams::new(Direction::LessThan, Side::Ask, StopLossOrderKind::IOC, trigger, execution)
}

/// A limit take-profit of a long above `trigger`.
pub fn take_profit_above(trigger: u64, execution: u64) -> TriggerOrderParams {
    TriggerOrderParams::new(Direction::GreaterThan, Side::Ask, StopLossOrderKind::Limit, trigger, execution)
}

/// Phoenix trader PDA `["trader", authority, [pda_index, subaccount_index]]`.
pub fn trader_pda(authority: &Pubkey, pda_index: u8, sub_index: u8) -> Pubkey {
    find_pda(&[b"trader", authority.as_ref(), &[pda_index, sub_index]], &PHOENIX).0
}

/// `MatchingEngineCPIResponse` of an order-placing instruction (SPEC §5.2.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OrderResult {
    /// Order id of the resting part (zero when nothing rests).
    pub price: u64,
    pub seq: u64,
    /// Base lots matched right away.
    pub filled: u64,
    /// Base lots resting on the book.
    pub posted: u64,
}

/// The transaction's return data must be Phoenix's own 64-byte
/// `MatchingEngineCPIResponse` (our program sets none, T12). Bids rest with
/// the top bit of the sequence number set, asks without (appendix H §5).
pub fn order_result(m: &TransactionMetadata, side: Side, label: &str) -> OrderResult {
    assert_eq!(m.return_data.program_id, PHOENIX, "{label}: return data is Phoenix's");
    let d = &m.return_data.data;
    assert_eq!(d.len(), 64, "{label}: MatchingEngineCPIResponse length");
    let u = |o: usize| u64::from_le_bytes(d[o..o + 8].try_into().unwrap());
    let (base_in, base_out) = (u(24), u(40));
    assert!(base_in == 0 || base_out == 0, "{label}: one direction only: in {base_in}, out {base_out}");
    let r = OrderResult { price: u(0), seq: u(8), filled: base_in + base_out, posted: u(56) };
    if r.posted > 0 {
        assert_eq!(r.seq >> 63 == 1, side == Side::Bid, "{label}: sequence number side of {r:?}");
    }
    eprintln!("{label}: {r:?}");
    r
}

/// One resting order of the FIFO orderbook.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BookOrder {
    pub bid: bool,
    pub price: u64,
    pub seq: u64,
    pub lots: u64,
}

/// An active entry of our conditional-orders PDA and its raw index (the
/// index `CancelConditionalOrder` takes; 0 is never used).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CondOrder {
    pub index: u8,
    pub asset_id: u32,
    /// The resting order it is attached to, if any.
    pub order_id: Option<(u64, u64)>,
}

/// Balances and state outside Phoenix that tag 10 must never touch (INV-9).
#[derive(Debug, PartialEq, Eq)]
pub struct Outside {
    pub tokens: Vec<u64>,
    pub fee_inbox: u64,
    pub phx_authority: u64,
    pub config: Vec<u8>,
    pub authority: Pubkey,
    pub position_authority: Pubkey,
    pub prefs: u32,
}

impl Env {
    pub fn outside(&self) -> Outside {
        let h = self.our_trader();
        Outside {
            tokens: [self.vault_usdc(), self.vault_phusd(), self.escrow_usdc(), self.buyback_usdc()]
                .iter()
                .map(|k| self.token_amount(k))
                .collect(),
            fee_inbox: self.lamports(&self.pdas.fee_inbox.0),
            phx_authority: self.lamports(&self.pdas.phx_authority.0),
            config: self.config(),
            authority: h.authority,
            position_authority: h.position_authority,
            prefs: h.prefs,
        }
    }

    /// Signed base lots of our trader's position in `symbol` (position map).
    pub fn position(&self, symbol: &str) -> i64 {
        let asset = self.pam_entry(symbol).asset_id;
        self.our_trader().positions.iter().find(|(a, _)| (*a as u32) == asset).map_or(0, |p| p.1)
    }

    /// Tag 10 over an arbitrary Phoenix account list and data (no layout
    /// assumptions): `[signer, config, phx_authority] ‖ P`, `[10] ‖ data`.
    pub fn trade_raw(&self, signer: &Pubkey, p: Vec<AccountMeta>, phx_data: &[u8]) -> Instruction {
        self.trade_ix_as(signer, Instruction { program_id: PHOENIX, accounts: p, data: phx_data.to_vec() })
    }

    /// Tag 10 by the trading key refused with our error `name` before any
    /// Phoenix CPI.
    pub fn refuse(&mut self, ix: Instruction, name: &str, label: &str) -> FailedTransactionMetadata {
        let e = expect_err(self.send1(ix, S_BOT), name, label);
        assert!(no_phoenix(&e.meta.logs), "{label}: Phoenix was called\n{}", e.meta.logs.join("\n"));
        e
    }

    // ------------------------------------------------------ Phoenix state ----

    /// All resting orders of the FIFO orderbook of `symbol` (the spline's
    /// liquidity is not in it).
    pub fn book(&self, symbol: &str) -> Vec<BookOrder> {
        let data = self.data(&self.market_book(symbol));
        let book = Orderbook::try_from_account_bytes(&data).unwrap_or_else(|e| panic!("orderbook {symbol}: {e:?}"));
        book.bid_orders()
            .map(|o| (true, o))
            .chain(book.ask_orders().map(|o| (false, o)))
            .map(|(bid, o)| BookOrder {
                bid,
                price: o.price_in_ticks().as_inner(),
                seq: o.order_sequence_number(),
                lots: o.num_base_lots_remaining().as_inner(),
            })
            .collect()
    }

    /// Resting orders at one price (the tests use prices the fixture's maker
    /// never quotes, so these are ours).
    pub fn book_at(&self, symbol: &str, bid: bool, price: u64) -> Vec<BookOrder> {
        self.book(symbol).into_iter().filter(|o| o.bid == bid && o.price == price).collect()
    }

    pub fn cond_orders_key(&self) -> Pubkey {
        get_conditional_orders_address(&self.pdas.trader.0).unwrap()
    }

    /// Active entries of our conditional-orders PDA (empty when it does not
    /// exist).
    pub fn active_cond_orders(&self) -> Vec<CondOrder> {
        let data = self.data(&self.cond_orders_key());
        if data.is_empty() {
            return vec![];
        }
        let c =
            ConditionalOrders::try_from_account_bytes(&data).unwrap_or_else(|e| panic!("conditional orders: {e:?}"));
        c.iter()
            .enumerate()
            .filter_map(|(i, o)| {
                let o = o.unwrap_or_else(|e| panic!("conditional order {i}: {e:?}"));
                let id = o.order_id();
                o.is_active().then(|| CondOrder {
                    index: u8::try_from(i).unwrap(),
                    asset_id: o.asset_id(),
                    order_id: id.is_some().then(|| (id.price_in_ticks().as_inner(), id.order_sequence_number())),
                })
            })
            .collect()
    }

    pub fn stop_loss_key(&self, symbol: &str) -> Pubkey {
        let asset = u64::from(self.pam_entry(symbol).asset_id);
        get_stop_loss_address(&self.pdas.trader.0, asset).unwrap()
    }

    /// `(less-than stop active, funding key)` of our stop-loss PDA on
    /// `symbol`, `None` when the account does not exist.
    pub fn stop_loss(&self, symbol: &str) -> Option<(bool, Pubkey)> {
        let data = self.data(&self.stop_loss_key(symbol));
        if data.is_empty() {
            return None;
        }
        let s = StopLosses::try_from_account_bytes(&data).unwrap_or_else(|e| panic!("stop losses: {e:?}"));
        Some((s.less_than_stop_loss().is_active(), Pubkey::new_from_array(s.funding_key())))
    }

    // --------------------------------------------- the 14 allowlisted ixs ----
    //
    // Phoenix instructions for our trader `T` with `traderWallet =
    // phx_authority` and payer / funder = the trading key; wrap them with
    // `trade_ix` (tag 10). `phx_ioc_ix` (#1), `phx_limit_ix` (#2, Limit
    // packet) and `phx_cancel_all_ix` (#7) are in `ixs.rs`.

    /// #2 `PlaceLimitOrder` with a `PostOnly` packet (Borsh enum 0; the SDK's
    /// Rust builder only emits `Limit`): side, price, lots, client id,
    /// `slide = false`, no expiry, no flags, `cancel_existing = false`.
    pub fn phx_post_only_ix(&self, symbol: &str, side: u8, price_ticks: u64, lots: u64) -> Instruction {
        let mut ix = self.phx_limit_ix(symbol, side, price_ticks, lots);
        let mut data = PhoenixInstruction::PlaceLimitOrder.discriminant().to_vec();
        data.push(0);
        data.push(side);
        data.extend_from_slice(&price_ticks.to_le_bytes());
        data.extend_from_slice(&lots.to_le_bytes());
        data.extend_from_slice(&13u128.to_le_bytes());
        data.extend_from_slice(&[0, 0, 0, 0]);
        ix.data = data;
        ix
    }

    /// #3 `PlaceMultiLimitOrder` (`v2 = false`) or #4 `PlaceMultiLimitOrderV2`:
    /// post-only `(price, lots)` batches without expiry.
    pub fn phx_multi_ix(&self, symbol: &str, bids: &[(u64, u64)], asks: &[(u64, u64)], v2: bool) -> Instruction {
        let (a, t, book, spline) =
            (self.pdas.phx_authority.0, self.pdas.trader.0, self.market_book(symbol), self.market_spline(symbol));
        let ix = if v2 {
            let o = |&(p, l): &(u64, u64)| CondensedOrderV2::new(p, l, None, false, false);
            let params = MultiLimitOrderParamsV2::builder()
                .trader(a)
                .trader_account(t)
                .perp_asset_map(self.fx.pam)
                .orderbook(book)
                .spline_collection(spline)
                .global_trader_index(self.fx.gti.clone())
                .active_trader_buffer(self.fx.atb.clone())
                .bids(bids.iter().map(o).collect())
                .asks(asks.iter().map(o).collect())
                .client_order_id(22)
                .build()
                .unwrap();
            create_place_multi_limit_order_v2_ix(params).unwrap()
        } else {
            let o = |&(p, l): &(u64, u64)| CondensedOrder {
                price_in_ticks: p,
                size_in_base_lots: l,
                last_valid_slot: None,
            };
            let params = MultiLimitOrderParams::builder()
                .trader(a)
                .trader_account(t)
                .perp_asset_map(self.fx.pam)
                .orderbook(book)
                .spline_collection(spline)
                .global_trader_index(self.fx.gti.clone())
                .active_trader_buffer(self.fx.atb.clone())
                .bids(bids.iter().map(o).collect())
                .asks(asks.iter().map(o).collect())
                .client_order_id(21)
                .build()
                .unwrap();
            create_place_multi_limit_order_ix(params).unwrap()
        };
        to_sol_ix(ix)
    }

    /// #5 `CancelOrdersById` for `(price, sequence number)` ids.
    pub fn phx_cancel_by_id_ix(&self, symbol: &str, ids: &[(u64, u64)]) -> Instruction {
        let params = CancelOrdersByIdParams::builder()
            .trader(self.pdas.phx_authority.0)
            .trader_account(self.pdas.trader.0)
            .perp_asset_map(self.fx.pam)
            .orderbook(self.market_book(symbol))
            .spline_collection(self.market_spline(symbol))
            .global_trader_index(self.fx.gti.clone())
            .active_trader_buffer(self.fx.atb.clone())
            .order_ids(ids.iter().map(|&(p, s)| CancelId::new(p, s)).collect())
            .build()
            .unwrap();
        to_sol_ix(create_cancel_orders_by_id_ix(params).unwrap())
    }

    /// #6 `CancelUpTo` on one side, without a count or price threshold.
    pub fn phx_cancel_up_to_ix(&self, symbol: &str, side: u8) -> Instruction {
        let params = CancelUpToParams::builder()
            .trader(self.pdas.phx_authority.0)
            .trader_account(self.pdas.trader.0)
            .perp_asset_map(self.fx.pam)
            .orderbook(self.market_book(symbol))
            .spline_collection(self.market_spline(symbol))
            .global_trader_index(self.fx.gti.clone())
            .active_trader_buffer(self.fx.atb.clone())
            .side(side_of(side))
            .build()
            .unwrap();
        to_sol_ix(create_cancel_up_to_ix(params).unwrap())
    }

    /// #8 `CancelAllPlusConditional`: the `CancelAll` accounts plus our
    /// conditional-orders PDA (writable), data = the discriminator
    /// (`cpi.rs::CancelAllPlusConditional`; the SDK has no off-chain builder).
    pub fn phx_cancel_all_plus_conditional_ix(&self, symbol: &str) -> Instruction {
        let mut ix = self.phx_cancel_all_ix(symbol);
        ix.data = PhoenixInstruction::CancelAllPlusConditional.discriminant().to_vec();
        ix.accounts.push(AccountMeta::new(self.cond_orders_key(), false));
        ix
    }

    /// #9 `PlaceLimitOrderWithConditionals`: a `Limit` packet on `side` with
    /// the given trigger legs; payer = the trading key.
    pub fn phx_limit_with_conditionals_ix(
        &self,
        symbol: &str,
        side: u8,
        price_ticks: u64,
        lots: u64,
        greater: Option<TriggerOrderParams>,
        less: Option<TriggerOrderParams>,
    ) -> Instruction {
        let (slot, _) = self.clock();
        let packet = OrderPacket::limit(
            side_of(side),
            price_ticks,
            lots,
            SelfTradeBehavior::CancelProvide,
            None,
            31u128.to_le_bytes(),
            None,
            OrderFlags::None,
            false,
        );
        let mut b = PlaceLimitOrderWithConditionalsParams::builder()
            .trader_wallet(self.pdas.phx_authority.0)
            .trader_account(self.pdas.trader.0)
            .perp_asset_map(self.fx.pam)
            .orderbook(self.market_book(symbol))
            .spline_collection(self.market_spline(symbol))
            .global_trader_index(self.fx.gti.clone())
            .active_trader_buffer(self.fx.atb.clone())
            .payer(self.bot)
            .order_packet(packet)
            .slot(slot);
        if let Some(g) = greater {
            b = b.greater_trigger_order(g);
        }
        if let Some(l) = less {
            b = b.less_trigger_order(l);
        }
        to_sol_ix(create_place_limit_order_with_conditionals_ix(b.build().unwrap()).unwrap())
    }

    /// #10 legacy `PlaceStopLoss` on `symbol` for our long (IOC ask below
    /// `trigger`), funder `funder`; the signer slot is `n − 3`, System last.
    pub fn phx_stop_loss_ix_by(&self, symbol: &str, funder: &Pubkey, trigger: u64) -> Instruction {
        let asset = u64::from(self.pam_entry(symbol).asset_id);
        let params = PlaceStopLossParams::builder()
            .funder(*funder)
            .trader_account(self.pdas.trader.0)
            .position_authority(self.pdas.phx_authority.0)
            .perp_asset_map(self.fx.pam)
            .orderbook(self.market_book(symbol))
            .spline_collection(self.market_spline(symbol))
            .global_trader_index(self.fx.gti.clone())
            .active_trader_buffer(self.fx.atb.clone())
            .asset_id(asset)
            .trigger_price(trigger)
            .execution_price(1)
            .trade_side(Side::Ask)
            .execution_direction(Direction::LessThan)
            .order_kind(StopLossOrderKind::IOC)
            .build()
            .unwrap();
        to_sol_ix(create_place_stop_loss_ix(params).unwrap())
    }

    /// #10 with the trading key as funder.
    pub fn phx_stop_loss_ix(&self, symbol: &str, trigger: u64) -> Instruction {
        self.phx_stop_loss_ix_by(symbol, &self.bot, trigger)
    }

    /// #11 `PlacePositionConditionalOrder` on our position in `symbol` with a
    /// stop leg, `size_percent` of the position; payer = the trading key; the
    /// signer slot is `n − 3`, System last.
    pub fn phx_position_conditional_ix(&self, symbol: &str, less: TriggerOrderParams, size_percent: u8) -> Instruction {
        let params = PlacePositionConditionalOrderParams::builder()
            .payer(self.bot)
            .trader_account(self.pdas.trader.0)
            .perp_asset_map(self.fx.pam)
            .orderbook(self.market_book(symbol))
            .spline_collection(self.market_spline(symbol))
            .global_trader_index(self.fx.gti.clone())
            .active_trader_buffer(self.fx.atb.clone())
            .trader_wallet(self.pdas.phx_authority.0)
            .asset_id(self.pam_entry(symbol).asset_id)
            .less_trigger_order(less)
            .size_percent(size_percent)
            .build()
            .unwrap();
        to_sol_ix(create_place_position_conditional_order_ix(params).unwrap())
    }

    /// #12 `PlaceAttachedConditionalOrder` on our resting order `(price, seq)`
    /// with a stop leg; payer = the trading key; `T` at slot 3, signer at 4.
    pub fn phx_attached_conditional_ix(
        &self,
        symbol: &str,
        order: (u64, u64),
        less: TriggerOrderParams,
    ) -> Instruction {
        let params = PlaceAttachedConditionalOrderParams::builder()
            .trader_account(self.pdas.trader.0)
            .trader_wallet(self.pdas.phx_authority.0)
            .orderbook(self.market_book(symbol))
            .payer(self.bot)
            .global_trader_index(self.fx.gti.clone())
            .active_trader_buffer(self.fx.atb.clone())
            .order_id(FifoOrderId { price_in_ticks: order.0, order_sequence_number: order.1 })
            .asset_id(self.pam_entry(symbol).asset_id)
            .less_trigger_order(less)
            .build()
            .unwrap();
        to_sol_ix(create_place_attached_conditional_order_ix(params).unwrap())
    }

    /// #13 `CancelConditionalOrder`: both legs of entry `index`.
    pub fn phx_cancel_conditional_ix(&self, symbol: &str, index: u8) -> Instruction {
        let params = CancelConditionalOrderParams::builder()
            .trader_account(self.pdas.trader.0)
            .trader_wallet(self.pdas.phx_authority.0)
            .orderbook(self.market_book(symbol))
            .conditional_order_index(index)
            .disable_first(true)
            .disable_second(true)
            .build()
            .unwrap();
        to_sol_ix(create_cancel_conditional_order_ix(params).unwrap())
    }

    /// #14 legacy `CancelStopLoss` of our stop on `symbol`; rent goes to
    /// `funder` (Phoenix requires the original payer).
    pub fn phx_cancel_stop_loss_ix(&self, symbol: &str, funder: &Pubkey) -> Instruction {
        let asset = u64::from(self.pam_entry(symbol).asset_id);
        let params = CancelStopLossParams::builder()
            .funder(*funder)
            .trader_account(self.pdas.trader.0)
            .position_authority(self.pdas.phx_authority.0)
            .asset_id(asset)
            .execution_direction(Direction::LessThan)
            .build()
            .unwrap();
        to_sol_ix(create_cancel_stop_loss_ix(params).unwrap())
    }

    /// `CreateConditionalOrdersAccount` for `T` (not on the allowlist: no
    /// owner signature needed, the trading key calls Phoenix directly, SPEC
    /// §5.2.6).
    pub fn phx_create_cond_orders_ix(&self, payer: &Pubkey, capacity: u8) -> Instruction {
        let params = CreateConditionalOrdersAccountParams::builder()
            .payer(*payer)
            .trader_wallet(self.pdas.phx_authority.0)
            .trader_account(self.pdas.trader.0)
            .capacity(capacity)
            .build()
            .unwrap();
        to_sol_ix(create_create_conditional_orders_account_ix(params).unwrap())
    }

    // ------------------------------------------- instructions tag 10 refuses ----

    /// `WithdrawFunds` of our trader with `traderWallet = wallet`.
    pub fn phx_withdraw_ix(&self, wallet: &Pubkey, destination: &Pubkey, amount: u64) -> Instruction {
        let params = WithdrawFundsParams::builder()
            .trader(*wallet)
            .trader_account(self.pdas.trader.0)
            .perp_asset_map(self.fx.pam)
            .global_vault(self.fx.global_vault)
            .trader_token_account(*destination)
            .global_trader_index(self.fx.gti.clone())
            .active_trader_buffer(self.fx.atb.clone())
            .withdraw_queue(self.fx.withdraw_queue)
            .amount(amount)
            .build()
            .unwrap();
        to_sol_ix(create_withdraw_funds_ix(params).unwrap())
    }

    /// `TransferCollateral` from `src` to `dst` signed by `wallet`.
    pub fn phx_transfer_ix(&self, wallet: &Pubkey, src: &Pubkey, dst: &Pubkey, amount: u64) -> Instruction {
        let params = TransferCollateralParams::builder()
            .trader(*wallet)
            .src_trader_account(*src)
            .dst_trader_account(*dst)
            .perp_asset_map(self.fx.pam)
            .global_trader_index(self.fx.gti.clone())
            .active_trader_buffer(self.fx.atb.clone())
            .amount(amount)
            .build()
            .unwrap();
        to_sol_ix(create_transfer_collateral_ix(params).unwrap())
    }

    /// `TransferCollateral` out of our trader.
    pub fn phx_transfer_out_ix(&self, wallet: &Pubkey, dst: &Pubkey, amount: u64) -> Instruction {
        let t = self.pdas.trader.0;
        self.phx_transfer_ix(wallet, &t, dst, amount)
    }

    /// `TransferCollateralChildToParent` from `child` into our trader.
    pub fn phx_child_to_parent_ix(&self, wallet: &Pubkey, child: &Pubkey) -> Instruction {
        let params = TransferCollateralChildToParentParams::builder()
            .trader(*wallet)
            .child_trader_account(*child)
            .parent_trader_account(self.pdas.trader.0)
            .perp_asset_map(self.fx.pam)
            .global_trader_index(self.fx.gti.clone())
            .active_trader_buffer(self.fx.atb.clone())
            .build()
            .unwrap();
        to_sol_ix(create_transfer_collateral_child_to_parent_ix(params).unwrap())
    }

    /// `DelegateTrader` of `trader_account` to `new_key`.
    pub fn phx_delegate_ix(&self, wallet: &Pubkey, trader_account: &Pubkey, new_key: &Pubkey) -> Instruction {
        let params = DelegateTraderParams::builder()
            .trader_wallet(*wallet)
            .trader_account(*trader_account)
            .new_position_authority(*new_key)
            .build()
            .unwrap();
        to_sol_ix(create_delegate_trader_ix(params).unwrap())
    }

    /// `SyncParentToChild`: our trader's capabilities onto `child`.
    pub fn phx_sync_parent_to_child_ix(&self, wallet: &Pubkey, child: &Pubkey) -> Instruction {
        let params = SyncParentToChildParams::builder()
            .trader_wallet(*wallet)
            .parent_trader_account(self.pdas.trader.0)
            .child_trader_account(*child)
            .global_trader_index(self.fx.gti.clone())
            .build()
            .unwrap();
        to_sol_ix(create_sync_parent_to_child_ix(params).unwrap())
    }

    /// `DepositFunds` into our trader from `source` (a phUSD account).
    pub fn phx_deposit_funds_ix(&self, wallet: &Pubkey, source: &Pubkey, amount: u64) -> Instruction {
        let params = DepositFundsParams::builder()
            .trader(*wallet)
            .trader_account(self.pdas.trader.0)
            .canonical_mint(self.fx.phusd)
            .global_vault(self.fx.global_vault)
            .trader_token_account(*source)
            .global_trader_index(self.fx.gti.clone())
            .active_trader_buffer(self.fx.atb.clone())
            .amount(amount)
            .build()
            .unwrap();
        to_sol_ix(create_deposit_funds_ix(params).unwrap())
    }

    /// `SwapNative` (sell direction, no venue instructions, no slippage floor)
    /// on `trader_account` signed by `signer`, output to `signer_quote`
    /// (`native_sol.rs::create_swap_native_ix` layout, built by hand).
    pub fn phx_swap_native_ix(
        &self,
        signer: &Pubkey,
        trader_account: &Pubkey,
        signer_quote: &Pubkey,
        amount: u64,
    ) -> Instruction {
        let mut data = PhoenixInstruction::SwapNative.discriminant().to_vec();
        data.push(0);
        data.extend_from_slice(&amount.to_le_bytes());
        data.extend_from_slice(&0u64.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        let global_vault = find_pda(&[b"vault", WSOL_MINT.as_ref()], &PHOENIX).0;
        let native_sol = find_pda(&[b"native_sol"], &PHOENIX).0;
        let mut accounts = vec![
            AccountMeta::new_readonly(PHOENIX, false),
            AccountMeta::new_readonly(PHOENIX_LOG, false),
            AccountMeta::new(PHOENIX_GC, false),
            AccountMeta::new(self.fx.pam, false),
            AccountMeta::new(global_vault, false),
            AccountMeta::new_readonly(SPL_TOKEN, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            AccountMeta::new_readonly(native_sol, false),
            AccountMeta::new(*signer, true),
            AccountMeta::new(*signer_quote, false),
            AccountMeta::new(*trader_account, false),
            AccountMeta::new(self.fx.withdraw_queue, false),
        ];
        accounts.extend(self.fx.gti.iter().chain(self.fx.atb.iter()).map(|k| AccountMeta::new(*k, false)));
        Instruction { program_id: PHOENIX, accounts, data }
    }

    /// `RegisterTrader` of `(authority, pda_index, sub_index)` paid by
    /// `payer`, without the authority's signature (appendix H §0.3 p.5).
    pub fn phx_register_ix(
        &self,
        payer: &Pubkey,
        authority: &Pubkey,
        prefs: u32,
        max_positions: u32,
        pda_index: u8,
        sub_index: u8,
    ) -> (Instruction, Pubkey) {
        let trader = trader_pda(authority, pda_index, sub_index);
        let mut data = PhoenixInstruction::RegisterTrader.discriminant().to_vec();
        data.extend_from_slice(&max_positions.to_le_bytes());
        data.extend_from_slice(&prefs.to_le_bytes());
        data.extend_from_slice(&[pda_index, sub_index]);
        let ix = Instruction {
            program_id: PHOENIX,
            accounts: vec![
                AccountMeta::new_readonly(PHOENIX, false),
                AccountMeta::new_readonly(PHOENIX_LOG, false),
                AccountMeta::new_readonly(PHOENIX_GC, false),
                AccountMeta::new(*payer, true),
                AccountMeta::new_readonly(*authority, false),
                AccountMeta::new(trader, false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            ],
            data,
        };
        (ix, trader)
    }

    /// `ReallocTrader` of our trader paid by `payer`.
    pub fn phx_realloc_ix(&self, payer: &Pubkey) -> Instruction {
        to_sol_ix(create_realloc_trader_ix(*payer, self.pdas.phx_authority.0, self.pdas.trader.0))
    }

    /// `PlaceMarketOrderDelegated` for our trader (the same IOC through a
    /// permission account).
    pub fn phx_market_delegated_ix(&self, symbol: &str, permission: &Pubkey) -> Instruction {
        let a = self.pdas.phx_authority.0;
        let order = MarketOrderParams::builder()
            .trader(a)
            .trader_account(self.pdas.trader.0)
            .perp_asset_map(self.fx.pam)
            .orderbook(self.market_book(symbol))
            .spline_collection(self.market_spline(symbol))
            .global_trader_index(self.fx.gti.clone())
            .active_trader_buffer(self.fx.atb.clone())
            .side(Side::Bid)
            .price_in_ticks(self.ticks_for(symbol, 151_000))
            .num_base_lots(1)
            .self_trade_behavior(SelfTradeBehavior::CancelProvide)
            .order_flags(OrderFlags::None)
            .build()
            .unwrap();
        let params = MarketOrderDelegatedParams::builder()
            .market_order(order)
            .trader_wallet(a)
            .permission_account(*permission)
            .build()
            .unwrap();
        to_sol_ix(create_place_market_order_delegated_ix(params).unwrap())
    }
}
