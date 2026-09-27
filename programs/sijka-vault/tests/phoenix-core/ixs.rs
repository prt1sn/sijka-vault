// Copyright (c) 2026 prt1sn. All rights reserved.
//! Instruction builders for our program (SPEC §4, account order and data
//! layout from `abi/sijka-vault.json`) and the setup steps the other tests
//! share: initialize, ATAs, register, onboarder activation, `set_trader`
//! (tag 3), deposit, trade. SPEC v3: the trading key (`S_BOT`) trades through
//! tag 10 `trade`, which forwards a Phoenix trading instruction built for
//! `traderWallet = phx_authority` (SPEC §5.2.2).

use phoenix_rise::ix::cancel_orders::{CancelAllParams, create_cancel_all_ix};
use phoenix_rise::ix::limit_order::{LimitOrderParams, create_place_limit_order_ix};
use phoenix_rise::ix::market_order::{MarketOrderParams, create_place_market_order_ix};
use phoenix_rise::ix::types::{OrderFlags, SelfTradeBehavior, Side};
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::abi;
use crate::harness::*;
use crate::phx::to_sol_ix;

fn w(k: Pubkey) -> AccountMeta {
    AccountMeta::new(k, false)
}
fn r(k: Pubkey) -> AccountMeta {
    AccountMeta::new_readonly(k, false)
}
fn rs(k: Pubkey) -> AccountMeta {
    AccountMeta::new_readonly(k, true)
}
fn ws(k: Pubkey) -> AccountMeta {
    AccountMeta::new(k, true)
}

/// Check a builder against the ABI (count, W, S of the fixed part).
fn check_abi(name: &str, metas: &[AccountMeta]) {
    let want = abi::ix_accounts(name);
    assert!(metas.len() >= want.len(), "{name}: {} accounts < ABI {}", metas.len(), want.len());
    for (i, (n, wr, sg)) in want.iter().enumerate() {
        assert_eq!(metas[i].is_writable, *wr, "{name}: account {i} ({n}) writable");
        assert_eq!(metas[i].is_signer, *sg, "{name}: account {i} ({n}) signer");
    }
}

/// Default parameters (SPEC §3.2, §3.3 recommended values; T_min 1 h). SPEC v4:
/// the retired withdraw / Ember tolerances and the oracle band / mark age are
/// reserved zeros (`_reserved*`), so they are not set.
pub fn harvest_params_default() -> Vec<(&'static str, u128)> {
    vec![
        ("epsilon", 1_000_000),
        ("d_min", 1_000_000),
        ("margin_buffer_abs", 5_000_000),
        ("max_harvest_per_call", 250_000_000_000),
        ("t_min_secs", 3600),
        ("margin_buffer_im_bps", 5000),
        ("max_buyback_backlog", 50_000_000_000),
        ("harvest_mark_max_age_slots", 150),
    ]
}

pub fn inflow_params_default() -> Vec<(&'static str, u128)> {
    vec![
        ("swap_min_interval_s", 0),
        ("swap_max_lamports", 10_000_000_000),
        ("swap_min_lamports", 50_000_000),
        ("deposit_min_atoms", 1_000_000),
    ]
}

/// `vals` with `name` replaced (or added).
pub fn with(mut vals: Vec<(&'static str, u128)>, name: &'static str, v: u128) -> Vec<(&'static str, u128)> {
    if let Some(p) = vals.iter_mut().find(|(n, _)| *n == name) {
        p.1 = v;
    } else {
        vals.push((name, v));
    }
    vals
}

pub struct InitArgs {
    pub payer: Pubkey,
    pub admin: Pubkey,
    pub creator: Pubkey,
    pub quote_mint: Pubkey,
    pub harvest: Vec<u8>,
    pub inflow: Vec<u8>,
    pub program_data: Pubkey,
    pub config: Pubkey,
}

impl Env {
    pub fn init_args(&self) -> InitArgs {
        InitArgs {
            payer: self.upgrade_authority,
            admin: self.admin,
            creator: self.creator,
            quote_mint: WSOL_MINT,
            harvest: abi::harvest_params().encode(&harvest_params_default()),
            inflow: abi::inflow_params().encode(&inflow_params_default()),
            program_data: self.pdas.program_data,
            config: self.pdas.config.0,
        }
    }

    pub fn initialize_ix(&self, a: &InitArgs) -> Instruction {
        let mut data = vec![0u8];
        for k in [&a.admin, &a.creator, &a.quote_mint] {
            data.extend_from_slice(k.as_ref());
        }
        data.extend_from_slice(&a.harvest);
        data.extend_from_slice(&a.inflow);
        assert_eq!(data.len(), abi::ix_data_size("initialize"));
        let accounts =
            vec![ws(a.payer), w(a.config), r(a.program_data), r(SYSTEM_PROGRAM), r(PHOENIX_GC), r(EMBER_STATE)];
        check_abi("initialize", &accounts);
        Instruction { program_id: self.program, accounts, data }
    }

    pub fn initialize(&mut self) {
        let ix = self.initialize_ix(&self.init_args());
        ok(self.send1(ix, S_UPGRADE), "initialize");
    }

    // -------------------------------------------------------------- admin ----

    pub fn admin_ix(&self, name: &str, admin: &Pubkey, extra: Vec<AccountMeta>, data: Vec<u8>) -> Instruction {
        let mut accounts = vec![rs(*admin), w(self.pdas.config.0)];
        accounts.extend(extra);
        check_abi(name, &accounts);
        assert_eq!(data.len(), abi::ix_data_size(name), "{name} data");
        Instruction { program_id: self.program, accounts, data }
    }

    pub fn set_token_mint_ix(&self, admin: &Pubkey, mint: &Pubkey, sharing_config: &Pubkey) -> Instruction {
        self.admin_ix("set_token_mint", admin, vec![r(*mint), r(*sharing_config)], vec![1])
    }

    pub fn register_ix_with(&self, admin: &Pubkey, trader_account: &Pubkey, bump: u8) -> Instruction {
        let extra = vec![
            r(self.pdas.phx_authority.0),
            w(self.pdas.rent_payer.0),
            r(PHOENIX),
            r(PHOENIX_LOG),
            r(PHOENIX_GC),
            w(*trader_account),
            r(SYSTEM_PROGRAM),
        ];
        self.admin_ix("register_phoenix_trader", admin, extra, vec![2, bump])
    }

    pub fn register_ix(&self) -> Instruction {
        self.register_ix_with(&self.admin, &self.pdas.trader.0, self.pdas.trader.1)
    }

    /// Fund `rent_payer` with exactly rent(5360) + rent(0) (SPEC §5.1.2 step 2).
    pub fn rent_payer_need(&self) -> u64 {
        self.rent(5360) + self.rent(0)
    }

    pub fn fund_rent_payer(&mut self, lamports: u64) {
        let rp = self.pdas.rent_payer.0;
        ok(self.transfer_lamports(S_PAYER, &rp, lamports), "fund rent_payer");
    }

    /// Tag 3 `set_trader` (SPEC §5.1.3): the trading key, the only signer of
    /// tag 10; 0 turns trading off.
    pub fn set_trader_ix(&self, admin: &Pubkey, key: &Pubkey) -> Instruction {
        let mut data = vec![3u8];
        data.extend_from_slice(key.as_ref());
        self.admin_ix("set_trader", admin, vec![], data)
    }

    pub fn set_trader(&mut self, key: &Pubkey) -> TxResult {
        let ix = self.set_trader_ix(&self.admin, key);
        self.send1(ix, S_ADMIN)
    }

    /// SPEC v4 (DECISIONS §23 item 1): `HarvestParams` are fixed at
    /// `initialize` and there is no setter (tag 7 retired). Tests that need
    /// other values write them into `Config@832` directly (test-only state
    /// surgery, as if the vault had been initialized with them).
    pub fn set_harvest_params(&mut self, vals: &[(&'static str, u128)]) {
        let p = abi::harvest_params().encode(vals);
        let off = abi::config().field("harvest_params").offset;
        let cfg = self.pdas.config.0;
        self.patch(&cfg, |d| d[off..off + p.len()].copy_from_slice(&p));
    }

    /// Tag 28 `set_keeper` (SPEC §5.1.10): the keeper key, the only signer of
    /// tags 20, 43, 44, 45; 0 turns them off.
    pub fn set_keeper_ix(&self, admin: &Pubkey, key: &Pubkey) -> Instruction {
        let mut data = vec![28u8];
        data.extend_from_slice(key.as_ref());
        self.admin_ix("set_keeper", admin, vec![], data)
    }

    pub fn set_keeper(&mut self, key: &Pubkey) -> TxResult {
        let ix = self.set_keeper_ix(&self.admin, key);
        self.send1(ix, S_ADMIN)
    }

    /// A retired admin tag (SPEC v4: 7, 8, 25, 26, 47, 48) with its old data
    /// length and the admin pair of accounts; the program refuses it with
    /// `UnknownInstruction` before reading any account.
    pub fn retired_admin_ix(&self, tag: u8, data_len: usize) -> Instruction {
        let mut data = vec![0u8; data_len];
        data[0] = tag;
        Instruction { program_id: self.program, accounts: vec![rs(self.admin), w(self.pdas.config.0)], data }
    }

    // ------------------------------------------------------------ inflow ----

    pub fn vault_usdc(&self) -> Pubkey {
        ata(&self.pdas.phx_authority.0, &self.fx.usdc, &SPL_TOKEN)
    }
    pub fn vault_phusd(&self) -> Pubkey {
        ata(&self.pdas.phx_authority.0, &self.fx.phusd, &SPL_TOKEN)
    }
    pub fn escrow_usdc(&self) -> Pubkey {
        ata(&self.pdas.creator_escrow.0, &self.fx.usdc, &SPL_TOKEN)
    }
    pub fn buyback_usdc(&self) -> Pubkey {
        ata(&self.pdas.buyback_authority.0, &self.fx.usdc, &SPL_TOKEN)
    }
    pub fn creator_usdc(&self) -> Pubkey {
        ata(&self.creator, &self.fx.usdc, &SPL_TOKEN)
    }

    /// The ATAs scripts create after `initialize` (SPEC §2.2).
    pub fn create_vault_atas(&mut self) {
        let (phx, esc, bb, creator) =
            (self.pdas.phx_authority.0, self.pdas.creator_escrow.0, self.pdas.buyback_authority.0, self.creator);
        let (usdc, phusd) = (self.fx.usdc, self.fx.phusd);
        self.create_ata(&phx, &usdc, &SPL_TOKEN);
        self.create_ata(&phx, &phusd, &SPL_TOKEN);
        self.create_ata(&esc, &usdc, &SPL_TOKEN);
        self.create_ata(&bb, &usdc, &SPL_TOKEN);
        self.create_ata(&creator, &usdc, &SPL_TOKEN);
    }

    fn arenas(&self, writable: bool) -> Vec<AccountMeta> {
        self.fx.gti.iter().chain(self.fx.atb.iter()).map(|k| if writable { w(*k) } else { r(*k) }).collect()
    }

    pub fn deposit_ix(&self, max_amount: u64) -> Instruction {
        let mut accounts = vec![
            w(self.pdas.config.0),
            r(self.pdas.phx_authority.0),
            w(self.vault_usdc()),
            w(self.vault_phusd()),
            r(self.fx.usdc),
            w(self.fx.phusd),
            r(EMBER),
            r(EMBER_STATE),
            w(EMBER_VAULT),
            r(PHOENIX),
            r(PHOENIX_LOG),
            w(PHOENIX_GC),
            w(self.pdas.trader.0),
            w(self.fx.global_vault),
            r(SPL_TOKEN),
        ];
        check_abi("deposit_usdc", &accounts);
        accounts.extend(self.arenas(true));
        let mut data = vec![21u8, self.fx.gti.len() as u8, self.fx.atb.len() as u8];
        data.extend_from_slice(&max_amount.to_le_bytes());
        Instruction { program_id: self.program, accounts, data }
    }

    /// Mint `amount` fake USDC to `vault_usdc` and run tag 21 for all of it.
    pub fn deposit(&mut self, amount: u64) -> TxResult {
        let v = self.vault_usdc();
        self.mint_usdc(&v, amount);
        let ix = self.deposit_ix(0);
        self.send1(ix, S_PAYER)
    }

    // ----------------------------------------------------------- harvest ----

    pub fn harvest_ix(&self) -> Instruction {
        let mut accounts = vec![
            w(self.pdas.config.0),
            r(self.pdas.phx_authority.0),
            r(PHOENIX),
            r(HAWKEYE),
            r(EMBER),
            r(PHOENIX_LOG),
            w(PHOENIX_GC),
            w(self.pdas.trader.0),
            w(self.fx.pam),
            w(self.fx.global_vault),
            w(self.fx.withdraw_queue),
            r(self.fx.usdc),
            w(self.fx.phusd),
            w(self.vault_phusd()),
            w(self.vault_usdc()),
            r(EMBER_STATE),
            w(EMBER_VAULT),
            r(SPL_TOKEN),
            w(self.escrow_usdc()),
            w(self.buyback_usdc()),
        ];
        check_abi("harvest", &accounts);
        accounts.extend(self.arenas(true));
        Instruction {
            program_id: self.program,
            accounts,
            data: vec![30, self.fx.gti.len() as u8, self.fx.atb.len() as u8],
        }
    }

    pub fn harvest(&mut self) -> TxResult {
        let ix = self.harvest_ix();
        self.send1(ix, S_PAYER)
    }

    pub fn preview_ix(&self) -> Instruction {
        let mut accounts = vec![
            r(self.pdas.config.0),
            r(PHOENIX),
            r(HAWKEYE),
            r(PHOENIX_GC),
            r(self.pdas.trader.0),
            r(self.fx.pam),
            r(self.fx.withdraw_queue),
            r(self.buyback_usdc()),
        ];
        check_abi("harvest_preview", &accounts);
        accounts.extend(self.arenas(false));
        Instruction {
            program_id: self.program,
            accounts,
            data: vec![31, self.fx.gti.len() as u8, self.fx.atb.len() as u8],
        }
    }

    /// Tag 31 return data (168 bytes, SPEC §5.4.3).
    pub fn preview(&mut self) -> Vec<u8> {
        let ix = self.preview_ix();
        let m = ok(self.send1(ix, S_PAYER), "harvest_preview");
        assert_eq!(m.return_data.program_id, self.program, "preview return data program");
        assert_eq!(m.return_data.data.len(), abi::harvest_preview().size, "preview length");
        assert_eq!(&m.return_data.data[0..8], b"SJKRTHPV", "preview magic");
        m.return_data.data
    }

    pub fn pay_creator_ix(&self) -> Instruction {
        let accounts = vec![
            w(self.pdas.config.0),
            r(self.pdas.creator_escrow.0),
            w(self.escrow_usdc()),
            w(self.creator_usdc()),
            r(SPL_TOKEN),
        ];
        check_abi("pay_creator", &accounts);
        Instruction { program_id: self.program, accounts, data: vec![32] }
    }

    pub fn bb_init_ix(&self) -> Instruction {
        let payer = self.ctx.signer_pubkey(S_PAYER);
        let accounts = vec![
            ws(payer),
            r(self.pdas.config.0),
            w(self.pdas.buyback_state.0),
            r(self.pdas.buyback_authority.0),
            r(self.pdas.swap_authority.0),
            r(self.pdas.bb_unwrap.0),
            r(SYSTEM_PROGRAM),
        ];
        check_abi("bb_init", &accounts);
        Instruction { program_id: self.program, accounts, data: vec![40] }
    }

    // ----------------------------------------------------------- trading ----
    //
    // SPEC v3: Phoenix instructions for our trader with `traderWallet =
    // phx_authority`, wrapped in tag 10 `trade` and signed by the trading key
    // (`bot`); send them with `S_BOT`.

    /// Tag 10 `trade` (SPEC §5.2.2): `[signer (S), config (R), phx_authority
    /// (R)]` followed by the Phoenix instruction's accounts, in which
    /// `phx_authority` is downgraded to a read-only non-signer (the program
    /// signs for it); data `[10] + phoenix data`.
    pub fn trade_ix_as(&self, signer: &Pubkey, phx: Instruction) -> Instruction {
        assert_eq!(phx.program_id, PHOENIX, "tag 10 forwards Phoenix instructions only");
        let a = self.pdas.phx_authority.0;
        let mut accounts = vec![rs(*signer), r(self.pdas.config.0), r(a)];
        check_abi("trade", &accounts);
        accounts.extend(phx.accounts.into_iter().map(|m| if m.pubkey == a { r(a) } else { m }));
        let mut data = vec![10u8];
        data.extend_from_slice(&phx.data);
        Instruction { program_id: self.program, accounts, data }
    }

    /// Tag 10 signed by the trading key.
    pub fn trade_ix(&self, phx: Instruction) -> Instruction {
        self.trade_ix_as(&self.bot, phx)
    }

    /// Tag 10 IOC by the trading key. `side` 0 Bid / 1 Ask; `ro` reduce-only.
    pub fn ioc_ix(&self, symbol: &str, side: u8, ro: bool, price_ticks: u64, lots: u64) -> Instruction {
        self.ioc_ix_as(&self.bot, symbol, side, ro, price_ticks, lots)
    }

    /// Tag 10 IOC on our trader signed by `signer`.
    pub fn ioc_ix_as(
        &self,
        signer: &Pubkey,
        symbol: &str,
        side: u8,
        ro: bool,
        price_ticks: u64,
        lots: u64,
    ) -> Instruction {
        let phx = self.phx_ioc_ix(&self.pdas.phx_authority.0, symbol, side, ro, price_ticks, lots);
        self.trade_ix_as(signer, phx)
    }

    /// Plain Phoenix IOC on our trader with `traderWallet = wallet` (not
    /// wrapped: used inside tag 10 and for direct-to-Phoenix negatives).
    pub fn phx_ioc_ix(
        &self,
        wallet: &Pubkey,
        symbol: &str,
        side: u8,
        ro: bool,
        price_ticks: u64,
        lots: u64,
    ) -> Instruction {
        let (slot, _) = self.clock();
        let params = MarketOrderParams::builder()
            .trader(*wallet)
            .trader_account(self.pdas.trader.0)
            .perp_asset_map(self.fx.pam)
            .orderbook(self.market_book(symbol))
            .spline_collection(self.market_spline(symbol))
            .global_trader_index(self.fx.gti.clone())
            .active_trader_buffer(self.fx.atb.clone())
            .side(side_of(side))
            .price_in_ticks(price_ticks)
            .num_base_lots(lots)
            .self_trade_behavior(SelfTradeBehavior::CancelProvide)
            .client_order_id(7)
            .last_valid_slot(slot + 100)
            .order_flags(if ro { OrderFlags::ReduceOnly } else { OrderFlags::None })
            .build()
            .unwrap();
        to_sol_ix(create_place_market_order_ix(params).unwrap())
    }

    /// A resting limit order by the trading key through tag 10 (placed away
    /// from the book, so it does not cross).
    pub fn post_only_ix(&self, symbol: &str, side: u8, price_ticks: u64, lots: u64) -> Instruction {
        let phx = self.phx_limit_ix(symbol, side, price_ticks, lots);
        self.trade_ix(phx)
    }

    /// Plain Phoenix `PlaceLimitOrder` for our trader (`traderWallet =
    /// phx_authority`).
    pub fn phx_limit_ix(&self, symbol: &str, side: u8, price_ticks: u64, lots: u64) -> Instruction {
        let params = LimitOrderParams::builder()
            .trader(self.pdas.phx_authority.0)
            .trader_account(self.pdas.trader.0)
            .perp_asset_map(self.fx.pam)
            .orderbook(self.market_book(symbol))
            .spline_collection(self.market_spline(symbol))
            .global_trader_index(self.fx.gti.clone())
            .active_trader_buffer(self.fx.atb.clone())
            .side(side_of(side))
            .price_in_ticks(price_ticks)
            .num_base_lots(lots)
            .self_trade_behavior(SelfTradeBehavior::CancelProvide)
            .client_order_id(11)
            .order_flags(OrderFlags::None)
            .build()
            .unwrap();
        to_sol_ix(create_place_limit_order_ix(params).unwrap())
    }

    /// Phoenix `cancel_all` on the book of `symbol` through tag 10 by the
    /// trading key.
    pub fn cancel_all_ix(&self, symbol: &str) -> Instruction {
        let phx = self.phx_cancel_all_ix(symbol);
        self.trade_ix(phx)
    }

    /// Plain Phoenix `CancelAll` for our trader (`traderWallet = phx_authority`).
    pub fn phx_cancel_all_ix(&self, symbol: &str) -> Instruction {
        let params = CancelAllParams::builder()
            .trader(self.pdas.phx_authority.0)
            .trader_account(self.pdas.trader.0)
            .perp_asset_map(self.fx.pam)
            .orderbook(self.market_book(symbol))
            .spline_collection(self.market_spline(symbol))
            .global_trader_index(self.fx.gti.clone())
            .active_trader_buffer(self.fx.atb.clone())
            .build()
            .unwrap();
        to_sol_ix(create_cancel_all_ix(params).unwrap())
    }

    // ------------------------------------------------------------ flows ----

    /// initialize + ATAs + register (rent_payer funded) + onboarder activation
    /// and `set_trader(bot)` (SPEC v3). `gated` mirrors mainnet (exchange
    /// gated before registration).
    pub fn setup_registered(&mut self, gated: bool) {
        if gated {
            self.set_gated();
        }
        self.initialize();
        self.create_vault_atas();
        let need = self.rent_payer_need();
        self.fund_rent_payer(need);
        let ix = self.register_ix();
        ok(self.send1(ix, S_ADMIN), "register_phoenix_trader");
        self.activate_our_trader();
        let bot = self.bot;
        ok(self.set_trader(&bot), "set_trader");
    }

    /// Mainnet-like vault: gated exchange, cooldown 0, registered, activated,
    /// `deposit` USDC deposited (skipped when 0).
    pub fn setup_funded(&mut self, deposit: u64) {
        self.set_deposit_cooldown(0);
        self.setup_registered(true);
        if deposit > 0 {
            ok(self.deposit(deposit), "deposit_usdc");
        }
    }

    /// Move time `T_min + 1` s forward (1 h default), past the `T_min` of the
    /// last harvest. Not needed before the first harvest (DECISIONS §23 item
    /// 7: `initialize` writes `last_harvest_ts = created_ts − t_min_secs`);
    /// tests that call it there only move the clock.
    pub fn pass_t_min(&mut self) {
        let t = self.cfg_harvest_u64("t_min_secs") as i64;
        self.advance(10, t + 1);
    }
}

pub fn side_of(side: u8) -> Side {
    if side == 0 { Side::Bid } else { Side::Ask }
}
