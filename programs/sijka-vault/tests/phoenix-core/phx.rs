// Copyright (c) 2026 prt1sn. All rights reserved.
//! Phoenix-side helpers: exchange status, onboarder permission and delegated
//! capability activation (what Phoenix's `send-register-ixs` does on mainnet),
//! direct `RegisterTrader` (the front-runner), trader header / PAM / withdraw
//! queue readers, Hawkeye `ViewMargin`, and fixture counterparty orders.
//! Raw layouts follow SPEC §3.9; builders come from `phoenix_rise::ix`.

use phoenix_rise::ix::hawkeye::{HawkeyeTraderViewAccounts, create_hawkeye_view_margin_ix};
use phoenix_rise::ix::limit_order::{LimitOrderParams, create_place_limit_order_ix};
use phoenix_rise::ix::onboard_trader_delegated::{OnboardTraderDelegatedParams, create_onboard_trader_delegated_ix};
use phoenix_rise::ix::transfer_collateral::{TransferCollateralParams, create_transfer_collateral_ix};
use phoenix_rise::ix::types::{OrderFlags, SelfTradeBehavior, Side};
use phoenix_rise_litesvm_test::parse_pubkey;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::harness::*;

/// `Permission` bit of the trader onboarder (`accounts/src/permission.rs:20`).
pub const TRADER_ONBOARDING_PERMISSION: u64 = 1 << 4;
/// Trader capability flags (`trader/capabilities.rs`).
pub const FLAG_HOT: u32 = 1;
pub const FLAGS_FROZEN: u32 = 2 | 4;
pub const FLAGS_COLD: u32 = 62;
pub const FLAGS_HOT: u32 = 63;

pub fn to_sol_ix(ix: phoenix_rise::ix::types::Instruction) -> Instruction {
    Instruction {
        program_id: ix.program_id,
        accounts: ix
            .accounts
            .into_iter()
            .map(|a| AccountMeta { pubkey: a.pubkey, is_signer: a.is_signer, is_writable: a.is_writable })
            .collect(),
        data: ix.data,
    }
}

fn opt_bool(out: &mut Vec<u8>, v: Option<bool>) {
    match v {
        None => out.push(0),
        Some(b) => out.extend_from_slice(&[1, u8::from(b)]),
    }
}

/// Phoenix trader header (SPEC §3.9).
#[derive(Clone, Debug)]
pub struct TraderHdr {
    pub disc: [u8; 8],
    pub trader_key: Pubkey,
    pub authority: Pubkey,
    pub collateral: i64,
    pub flags: u32,
    pub max_positions: u32,
    pub prefs: u32,
    pub position_authority: Pubkey,
    pub pda_index: u8,
    pub sub_index: u8,
    pub funding_key: Pubkey,
    pub last_deposit_slot: u64,
    pub len: u64,
    pub cap: u64,
    /// `(asset_index, base_lots)` of the position map.
    pub positions: Vec<(u64, i64)>,
}

pub fn parse_trader(d: &[u8]) -> TraderHdr {
    let k = |o: usize| Pubkey::new_from_array(d[o..o + 32].try_into().unwrap());
    let u64_at = |o: usize| u64::from_le_bytes(d[o..o + 8].try_into().unwrap());
    let u32_at = |o: usize| u32::from_le_bytes(d[o..o + 4].try_into().unwrap());
    let len = u64_at(224);
    let positions = (0..len as usize)
        .map(|j| {
            let o = 240 + 40 * j;
            (u64_at(o), u64_at(o + 8) as i64)
        })
        .collect();
    TraderHdr {
        disc: d[0..8].try_into().unwrap(),
        trader_key: k(24),
        authority: k(56),
        collateral: u64_at(88) as i64,
        flags: u32_at(96),
        max_positions: u32_at(112),
        prefs: u32_at(116),
        position_authority: k(120),
        pda_index: d[154],
        sub_index: d[155],
        funding_key: k(156),
        last_deposit_slot: u64_at(192),
        len,
        cap: u64_at(232),
        positions,
    }
}

/// Hawkeye `ViewMarginReturn` (112 bytes, SPEC §3.9).
#[derive(Clone, Copy, Debug, Default)]
pub struct Margin {
    pub position_count: u16,
    pub risk_state: u8,
    pub risk_tier: u8,
    pub liq: u8,
    pub c_hk: i64,
    pub effective: i64,
    pub free: i64,
    pub wd: u64,
    pub im: u64,
    pub upnl: i64,
    pub funding: i64,
}

pub fn parse_margin(d: &[u8]) -> Margin {
    assert_eq!(d.len(), 112, "ViewMarginReturn length");
    let i = |o: usize| i64::from_le_bytes(d[o..o + 8].try_into().unwrap());
    assert_eq!(u16::from_le_bytes([d[8], d[9]]), 1, "Hawkeye return version");
    Margin {
        position_count: u16::from_le_bytes([d[10], d[11]]),
        risk_state: d[12],
        risk_tier: d[13],
        liq: d[14],
        c_hk: i(16),
        effective: i(24),
        free: i(32),
        wd: i(40) as u64,
        im: i(48) as u64,
        upnl: i(88),
        funding: i(104),
    }
}

/// One PerpAssetMap entry (SPEC §3.9 offsets).
#[derive(Clone, Debug)]
pub struct PamEntry {
    pub slot: usize,
    pub asset_id: u32,
    pub mark_slot: u64,
    pub mark_ticks: u64,
    pub orderbook: Pubkey,
    pub tick_size: u64,
    pub base_lot_decimals: i8,
}

/// Withdraw queue header fields (SPEC §3.9).
pub mod wq {
    pub const MAX_BUDGET: usize = 24;
    pub const REMAINING: usize = 32;
    pub const REPLENISH: usize = 40;
    pub const LAST_UPDATE: usize = 48;
    pub const TOTAL_QUEUED: usize = 56;
    pub const WITHDRAWAL_FEE: usize = 64;
    pub const ENQUEUEING_FEE: usize = 72;
}

impl Env {
    // ------------------------------------------------------ global config ----

    pub fn gc(&self) -> Vec<u8> {
        self.data(&PHOENIX_GC)
    }

    pub fn gc_u64(&self, off: usize) -> u64 {
        u64::from_le_bytes(self.gc()[off..off + 8].try_into().unwrap())
    }

    pub fn exchange_status(&self) -> u8 {
        self.gc()[504]
    }

    /// `deposit_cooldown_period_in_slots @512` (patched in place).
    pub fn set_deposit_cooldown(&mut self, cd: u64) {
        self.patch(&PHOENIX_GC, |d| d[512..520].copy_from_slice(&cd.to_le_bytes()));
    }

    /// `change_exchange_status` signed by the fixture root authority (`payer`).
    pub fn set_exchange_status(&mut self, active: Option<bool>, gated: Option<bool>, maintenance: Option<bool>) {
        let root = self.ctx.signer_pubkey(S_PAYER);
        let mut data = disc("global:change_exchange_status").to_vec();
        opt_bool(&mut data, active);
        opt_bool(&mut data, gated);
        opt_bool(&mut data, maintenance);
        let ix = Instruction {
            program_id: PHOENIX,
            accounts: vec![
                AccountMeta::new_readonly(PHOENIX, false),
                AccountMeta::new_readonly(PHOENIX_LOG, false),
                AccountMeta::new(PHOENIX_GC, false),
                AccountMeta::new_readonly(root, true),
                AccountMeta::new(root, false),
            ],
            data,
        };
        ok(self.send1(ix, S_PAYER), "change_exchange_status");
    }

    pub fn set_gated(&mut self) {
        self.set_exchange_status(Some(true), Some(true), None);
        assert_eq!(self.exchange_status() & 0b10, 0b10, "gated bit");
    }

    // ------------------------------------------------ onboarder permission ----

    pub fn permission_address(authority: &Pubkey, user: &Pubkey) -> Pubkey {
        find_pda(&[b"permission", authority.as_ref(), user.as_ref()], &PHOENIX).0
    }

    /// Risk authority (fixture `payer`) creates and sets a permission account
    /// for `user` with `bits` (as Phoenix did for its production onboarder).
    pub fn grant_permission(&mut self, user: &Pubkey, bits: u64) -> TxResult {
        let payer = self.ctx.signer_pubkey(S_PAYER);
        let perm = Self::permission_address(&payer, user);
        let create = Instruction {
            program_id: PHOENIX,
            accounts: vec![
                AccountMeta::new_readonly(PHOENIX, false),
                AccountMeta::new_readonly(PHOENIX_LOG, false),
                AccountMeta::new_readonly(payer, true),
                AccountMeta::new(perm, false),
                AccountMeta::new_readonly(payer, false),
                AccountMeta::new_readonly(*user, false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            ],
            data: disc("global:create_permission").to_vec(),
        };
        let mut data = disc("global:set_permission").to_vec();
        data.extend_from_slice(&bits.to_le_bytes());
        data.push(0); // expires_at_timestamp: None
        data.push(0); // allowed_signer_actions: None
        let set = Instruction {
            program_id: PHOENIX,
            accounts: vec![
                AccountMeta::new_readonly(PHOENIX, false),
                AccountMeta::new_readonly(PHOENIX_LOG, false),
                AccountMeta::new(perm, false),
                AccountMeta::new_readonly(payer, true),
                AccountMeta::new_readonly(*user, false),
            ],
            data,
        };
        self.send(vec![create, set], S_PAYER)
    }

    /// `SetTraderCapabilitiesDelegated` signed by `onboarder_seed` with its
    /// permission account (all six capabilities on).
    pub fn onboard_ix(&self, onboarder: &Pubkey, trader_account: &Pubkey) -> Instruction {
        let payer = self.ctx.signer_pubkey(S_PAYER);
        let params = OnboardTraderDelegatedParams::builder()
            .authority(*onboarder)
            .permission_account(Self::permission_address(&payer, onboarder))
            .trader_account(*trader_account)
            .global_trader_index(self.fx.gti.clone())
            .active_trader_buffer(self.fx.atb.clone())
            .build()
            .unwrap();
        to_sol_ix(create_onboard_trader_delegated_ix(params).unwrap())
    }

    /// The onboarder flow: permission for `S_ONBOARDER`, then activation.
    pub fn activate_our_trader(&mut self) {
        let onboarder = self.onboarder;
        ok(self.grant_permission(&onboarder, TRADER_ONBOARDING_PERMISSION), "grant onboarder permission");
        let ix = self.onboard_ix(&onboarder, &self.pdas.trader.0);
        ok(self.send1(ix, S_ONBOARDER), "SetTraderCapabilitiesDelegated");
    }

    // ------------------------------------------------------ direct Phoenix ----

    /// Phoenix `RegisterTrader` sent directly (not through our program): any
    /// payer may register any authority's `(A, 0, 0)` trader.
    pub fn register_direct_ix(
        &self,
        payer: &Pubkey,
        authority: &Pubkey,
        prefs: u32,
        max_positions: u32,
    ) -> Instruction {
        let trader = find_pda(&[b"trader", authority.as_ref(), &[0u8, 0u8]], &PHOENIX).0;
        let mut data = hex8("4bf3e0a701053320").to_vec();
        data.extend_from_slice(&max_positions.to_le_bytes());
        data.extend_from_slice(&prefs.to_le_bytes());
        data.extend_from_slice(&[0, 0]);
        Instruction {
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
        }
    }

    pub fn trader_hdr(&self, key: &Pubkey) -> TraderHdr {
        parse_trader(&self.data(key))
    }

    pub fn our_trader(&self) -> TraderHdr {
        self.trader_hdr(&self.pdas.trader.0)
    }

    pub fn hawkeye_ix(&self, trader: &Pubkey) -> Instruction {
        to_sol_ix(create_hawkeye_view_margin_ix(HawkeyeTraderViewAccounts {
            phoenix_program_id: PHOENIX,
            global_config: PHOENIX_GC,
            global_trader_index: self.fx.gti.clone(),
            active_trader_buffer: self.fx.atb.clone(),
            perp_asset_map: self.fx.pam,
            trader: *trader,
        }))
    }

    /// Hawkeye `ViewMargin` of a trader (a separate read-only transaction).
    pub fn margin(&mut self, trader: &Pubkey) -> Margin {
        let ix = self.hawkeye_ix(trader);
        let m = ok(self.send1(ix, S_PAYER), "Hawkeye ViewMargin");
        assert_eq!(m.return_data.program_id, HAWKEYE, "Hawkeye return data program");
        parse_margin(&m.return_data.data)
    }

    // ---------------------------------------------------------------- PAM ----

    pub fn pam_entry(&self, symbol: &str) -> PamEntry {
        let d = self.data(&self.fx.pam);
        let slots_used = u32::from_le_bytes(d[32..36].try_into().unwrap()) as usize;
        let mut sym = [0u8; 16];
        sym[..symbol.len()].copy_from_slice(symbol.as_bytes());
        for slot in 0..slots_used {
            let e = 48 + slot * 1584;
            if d[e..e + 16] == sym {
                let u64_at = |o: usize| u64::from_le_bytes(d[e + o..e + o + 8].try_into().unwrap());
                let lo = u16::from_le_bytes([d[e + 960], d[e + 961]]);
                let hi = u16::from_le_bytes([d[e + 964], d[e + 965]]);
                return PamEntry {
                    slot,
                    asset_id: u32::from(lo) | (u32::from(hi) << 16),
                    mark_slot: u64_at(32),
                    mark_ticks: u64_at(40),
                    orderbook: Pubkey::new_from_array(d[e + 920..e + 952].try_into().unwrap()),
                    tick_size: u64_at(952),
                    base_lot_decimals: d[e + 962] as i8,
                };
            }
        }
        panic!("PAM: no market {symbol}");
    }

    /// Price in ticks for `usd_milli / 1000` USD per whole base unit.
    pub fn ticks_for(&self, symbol: &str, usd_milli: u64) -> u64 {
        let e = self.pam_entry(symbol);
        let lot = 10u64.pow(e.base_lot_decimals as u32);
        // quote atoms per base unit = usd_milli * 1000; per lot / tick size.
        usd_milli * 1000 / lot / e.tick_size
    }

    /// Oracle mark of `symbol` in milli-USD per base unit.
    pub fn mark_usd_milli(&self, symbol: &str) -> u64 {
        let e = self.pam_entry(symbol);
        let lot = 10u64.pow(e.base_lot_decimals as u32);
        e.mark_ticks * e.tick_size * lot / 1000
    }

    /// Move oracle mark + spot and the spline mid of `symbol` (fixture helper)
    /// and remember the price for later `refresh_prices`.
    pub fn set_price_milli(&mut self, symbol: &str, usd_milli: u64) {
        self.ctx.move_market_price_usd(symbol, usd_milli as f64 / 1000.0);
        if let Some(p) = self.prices.iter_mut().find(|(s, _)| *s == symbol) {
            p.1 = usd_milli;
        }
    }

    pub fn market_spline(&self, symbol: &str) -> Pubkey {
        parse_pubkey(&self.ctx.market(symbol).spline).unwrap()
    }

    pub fn market_book(&self, symbol: &str) -> Pubkey {
        parse_pubkey(&self.ctx.market(symbol).orderbook).unwrap()
    }

    // ------------------------------------------------------ counterparties ----

    /// A fixture actor places a Phoenix limit order directly.
    pub fn actor_limit(&mut self, actor: &str, symbol: &str, side: Side, price_ticks: u64, lots: u64) -> TxResult {
        let a = self.ctx.actor(actor);
        let params = LimitOrderParams::builder()
            .trader(parse_pubkey(&a.pubkey).unwrap())
            .trader_account(parse_pubkey(&a.trader_account).unwrap())
            .perp_asset_map(self.fx.pam)
            .orderbook(self.market_book(symbol))
            .spline_collection(self.market_spline(symbol))
            .global_trader_index(self.fx.gti.clone())
            .active_trader_buffer(self.fx.atb.clone())
            .side(side)
            .price_in_ticks(price_ticks)
            .num_base_lots(lots)
            .self_trade_behavior(SelfTradeBehavior::CancelProvide)
            .order_flags(OrderFlags::None)
            .build()
            .unwrap();
        let ix = to_sol_ix(create_place_limit_order_ix(params).unwrap());
        self.send1(ix, &a.seed)
    }

    /// `TransferCollateral` from a fixture actor's trader to `dst` (U-47).
    pub fn actor_gift_collateral(&mut self, actor: &str, dst: &Pubkey, amount: u64) -> TxResult {
        let a = self.ctx.actor(actor);
        let params = TransferCollateralParams::builder()
            .trader(parse_pubkey(&a.pubkey).unwrap())
            .src_trader_account(parse_pubkey(&a.trader_account).unwrap())
            .dst_trader_account(*dst)
            .perp_asset_map(self.fx.pam)
            .global_trader_index(self.fx.gti.clone())
            .active_trader_buffer(self.fx.atb.clone())
            .amount(amount)
            .build()
            .unwrap();
        let ix = to_sol_ix(create_transfer_collateral_ix(params).unwrap());
        self.send1(ix, &a.seed)
    }

    pub fn cancel_fixture_levels(&mut self) {
        self.ctx.send_fixture_transaction("orderbookCancelLevels");
    }

    // ------------------------------------------------------ withdraw queue ----

    pub fn wq_u64(&self, off: usize) -> u64 {
        u64::from_le_bytes(self.data(&self.fx.withdraw_queue)[off..off + 8].try_into().unwrap())
    }

    pub fn wq_set(&mut self, off: usize, v: u64) {
        let key = self.fx.withdraw_queue;
        self.patch(&key, |d| d[off..off + 8].copy_from_slice(&v.to_le_bytes()));
    }
}

pub fn hex8(s: &str) -> [u8; 8] {
    let mut out = [0u8; 8];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

pub fn bid() -> Side {
    Side::Bid
}
