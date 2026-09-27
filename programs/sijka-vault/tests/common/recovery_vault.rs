// Copyright (c) 2026 prt1sn. All rights reserved.
//! The vault on the Rise localnet fixture (mainnet Phoenix / Ember / Hawkeye
//! binaries): real `initialize`, `register_phoenix_trader`, `set_trader`
//! (tag 3: the bot key becomes the trading key, SPEC v3), Ember + Phoenix
//! deposit (tag 21), and Phoenix admin instructions (signed by the fixture's
//! root / market authority, the `payer` signer) to put the exchange and its
//! markets into the states of SPEC §5.6.7. The bot key trades through tag 10
//! `trade`, which forwards Phoenix trading instructions built for
//! `traderWallet = phx_authority` (SPEC §5.2).
//!
//! Phoenix admin instructions are built by hand: account lists from the
//! on-chain Phoenix IDL, discriminators from the SDK (`sha256("global:…")`).

#![allow(dead_code)]

use litesvm::LiteSVM;
use phoenix_rise::ix::discriminants::PhoenixInstruction as PI;
use phoenix_rise::ix::limit_order::{LimitOrderParams, create_place_limit_order_ix};
use phoenix_rise::ix::types::{OrderFlags, SelfTradeBehavior, Side};
use phoenix_rise_litesvm_test::{
    FixtureOraclePriceUpdate, SdkLocalnetContext, SdkLocalnetProgram, decode_fixture_instruction,
    default_sdk_localnet_fixture, find_sdk_localnet_program_paths, parse_pubkey,
};
use sijka_vault::constants as k;
use sijka_vault::error::SijkaError;
use sijka_vault::state::config::{Config, ConfigMut};
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;

use super::harness::*;

// ------------------------------------------------------ fixture addresses

/// Phoenix accounts of the fixture exchange.
#[derive(Clone, Debug)]
pub struct Fx {
    pub authority: Pubkey,
    pub pam: Pubkey,
    pub gvault: Pubkey,
    pub wq: Pubkey,
    pub gti: Pubkey,
    pub atb: Pubkey,
    pub usdc: Pubkey,
    pub phusd: Pubkey,
    pub ember_state: Pubkey,
    pub ember_vault: Pubkey,
}

impl Fx {
    fn from(ctx: &SdkLocalnetContext) -> Self {
        let a = &ctx.fixture.addresses;
        let p = |s: &str| parse_pubkey(s).unwrap();
        Self {
            authority: ctx.signer_pubkey("payer"),
            pam: p(&a.perp_asset_map),
            gvault: p(&a.global_vault),
            wq: p(&a.withdraw_queue),
            gti: p(&a.global_trader_index[0]),
            atb: p(&a.active_trader_buffer[0]),
            usdc: ctx.fake_usdc_mint(),
            phusd: ctx.phoenix_collateral_mint(),
            ember_state: p(&a.ember_state),
            ember_vault: p(&a.ember_vault),
        }
    }
}

// ------------------------------------------------ Phoenix instructions

fn phx(accounts: Vec<AccountMeta>, i: PI, args: &[u8]) -> Instruction {
    let mut data = i.discriminant().to_vec();
    data.extend_from_slice(args);
    Instruction { program_id: phoenix_id(), accounts, data }
}

fn head() -> Vec<AccountMeta> {
    vec![AccountMeta::new_readonly(phoenix_id(), false), AccountMeta::new_readonly(log_authority(), false)]
}

pub fn opt_bool(v: Option<bool>) -> Vec<u8> {
    match v {
        None => vec![0],
        Some(b) => vec![1, u8::from(b)],
    }
}

pub fn opt_u64(v: Option<u64>) -> Vec<u8> {
    match v {
        None => vec![0],
        Some(x) => {
            let mut o = vec![1];
            o.extend_from_slice(&x.to_le_bytes());
            o
        }
    }
}

/// `change_exchange_status {active, gated, maintenance}` (root authority).
pub fn ix_change_exchange_status(
    auth: Pubkey,
    active: Option<bool>,
    gated: Option<bool>,
    maintenance: Option<bool>,
) -> Instruction {
    let mut a = head();
    a.extend([
        AccountMeta::new(global_config_key(), false),
        AccountMeta::new_readonly(auth, true),
        AccountMeta::new(auth, false),
    ]);
    let mut args = opt_bool(active);
    args.extend(opt_bool(gated));
    args.extend(opt_bool(maintenance));
    phx(a, PI::ChangeExchangeStatus, &args)
}

/// Phoenix `MarketStatus`: 1 Active, 2 PostOnly, 3 Paused, 4 Closed, 5 Tombstoned.
pub fn ix_change_market_status(auth: Pubkey, pam: Pubkey, orderbook: Pubkey, status: u8) -> Instruction {
    let mut a = head();
    a.extend([
        AccountMeta::new_readonly(global_config_key(), false),
        AccountMeta::new_readonly(auth, true),
        AccountMeta::new(auth, false),
        AccountMeta::new(orderbook, false),
        AccountMeta::new(pam, false),
    ]);
    phx(a, PI::ChangeMarketStatus, &[status])
}

pub fn ix_close_market(auth: Pubkey, pam: Pubkey, orderbook: Pubkey) -> Instruction {
    let mut a = head();
    a.extend([
        AccountMeta::new_readonly(global_config_key(), false),
        AccountMeta::new_readonly(auth, true),
        AccountMeta::new(auth, false),
        AccountMeta::new(pam, false),
        AccountMeta::new(orderbook, false),
    ]);
    phx(a, PI::CloseMarket, &[])
}

pub fn ix_tombstone_market(fx: &Fx, auth: Pubkey, orderbook: Pubkey, spline: Pubkey) -> Instruction {
    let mut a = head();
    a.extend([
        AccountMeta::new_readonly(global_config_key(), false),
        AccountMeta::new_readonly(auth, true),
        AccountMeta::new(auth, false),
        AccountMeta::new(orderbook, false),
        AccountMeta::new_readonly(fx.pam, false),
        AccountMeta::new_readonly(spline, false),
        AccountMeta::new(fx.gti, false),
        AccountMeta::new(fx.atb, false),
    ]);
    phx(a, PI::TombstoneMarket, &[])
}

pub fn ix_delete_tombstoned_market(
    fx: &Fx,
    auth: Pubkey,
    recipient: Pubkey,
    orderbook: Pubkey,
    spline: Pubkey,
) -> Instruction {
    let mut a = head();
    a.extend([
        AccountMeta::new_readonly(global_config_key(), false),
        AccountMeta::new_readonly(auth, true),
        AccountMeta::new(auth, false),
        AccountMeta::new(recipient, false),
        AccountMeta::new(fx.pam, false),
        AccountMeta::new(orderbook, false),
        AccountMeta::new(spline, false),
    ]);
    phx(a, PI::DeleteTombstonedMarket, &[])
}

pub fn ix_settle_closed_market_position(
    fx: &Fx,
    auth: Pubkey,
    orderbook: Pubkey,
    long: Pubkey,
    short: Pubkey,
) -> Instruction {
    let mut a = head();
    a.extend([
        AccountMeta::new_readonly(global_config_key(), false),
        AccountMeta::new_readonly(auth, true),
        AccountMeta::new(auth, false),
        AccountMeta::new(fx.pam, false),
        AccountMeta::new(orderbook, false),
        AccountMeta::new(fx.gti, false),
        AccountMeta::new(fx.atb, false),
        AccountMeta::new(long, false),
        AccountMeta::new(short, false),
    ]);
    phx(a, PI::SettleClosedMarketPosition, &[])
}

pub fn ix_deactivate_spline(fx: &Fx, auth: Pubkey, spline: Pubkey, orderbook: Pubkey, trader: Pubkey) -> Instruction {
    let mut a = head();
    a.extend([
        AccountMeta::new_readonly(global_config_key(), false),
        AccountMeta::new_readonly(auth, true),
        AccountMeta::new(auth, false),
        AccountMeta::new(spline, false),
        AccountMeta::new_readonly(orderbook, false),
        AccountMeta::new(fx.gti, false),
        AccountMeta::new(fx.atb, false),
        AccountMeta::new(trader, false),
        AccountMeta::new_readonly(fx.pam, false),
        AccountMeta::new_readonly(system_program(), false),
    ]);
    phx(a, PI::DeactivateSpline, &[])
}

/// `update_trader_state` (permissionless in the IDL): resync one trader.
pub fn ix_update_trader_state(fx: &Fx, trader: Pubkey) -> Instruction {
    let mut a = head();
    a.extend([
        AccountMeta::new_readonly(global_config_key(), false),
        AccountMeta::new(trader, false),
        AccountMeta::new_readonly(fx.pam, false),
        AccountMeta::new(fx.gti, false),
        AccountMeta::new(fx.atb, false),
    ]);
    phx(a, PI::UpdateTraderState, &[])
}

/// `acknowledge_restart(expected_restart_slot)`: no authority in the IDL.
pub fn ix_acknowledge_restart(expected: u64) -> Instruction {
    let mut a = head();
    a.push(AccountMeta::new(global_config_key(), false));
    phx(a, PI::AcknowledgeRestart, &expected.to_le_bytes())
}

pub fn ix_update_withdraw_rate_limits(fx: &Fx, max_budget: Option<u64>, replenish: Option<u64>) -> Instruction {
    let mut a = head();
    a.extend([
        AccountMeta::new_readonly(global_config_key(), false),
        AccountMeta::new_readonly(fx.authority, true),
        AccountMeta::new(fx.authority, false),
        AccountMeta::new(fx.wq, false),
    ]);
    let mut args = opt_u64(max_budget);
    args.extend(opt_u64(replenish));
    phx(a, PI::UpdateWithdrawRateLimits, &args)
}

pub fn ix_update_withdraw_parameters(
    fx: &Fx,
    cooldown: Option<u64>,
    withdrawal_fee: Option<u64>,
    enqueueing_fee: Option<u64>,
) -> Instruction {
    let mut a = head();
    a.extend([
        AccountMeta::new(global_config_key(), false),
        AccountMeta::new_readonly(fx.authority, true),
        AccountMeta::new(fx.authority, false),
        AccountMeta::new(fx.wq, false),
    ]);
    let mut args = opt_u64(cooldown);
    args.extend(opt_u64(withdrawal_fee));
    args.extend(opt_u64(enqueueing_fee));
    phx(a, PI::UpdateWithdrawParameters, &args)
}

/// `consume_withdraw_queue`: no signer besides the fee payer (IDL).
pub fn ix_consume_withdraw_queue(fx: &Fx, wallet: Pubkey, destination: Pubkey, trader: Pubkey) -> Instruction {
    let mut a = head();
    a.extend([
        AccountMeta::new(global_config_key(), false),
        AccountMeta::new(fx.pam, false),
        AccountMeta::new(fx.gvault, false),
        AccountMeta::new(fx.gti, false),
        AccountMeta::new(fx.atb, false),
        AccountMeta::new(fx.wq, false),
        AccountMeta::new_readonly(token_program(), false),
        AccountMeta::new_readonly(wallet, false),
        AccountMeta::new(destination, false),
        AccountMeta::new(trader, false),
    ]);
    phx(a, PI::ConsumeWithdrawQueue, &[])
}

/// Direct Phoenix `withdraw_funds` by a trader wallet (probe of U-57 / U-62).
pub fn ix_withdraw_funds(fx: &Fx, wallet: Pubkey, trader: Pubkey, destination: Pubkey, amount: u64) -> Instruction {
    let mut a = head();
    a.extend([
        AccountMeta::new(global_config_key(), false),
        AccountMeta::new_readonly(wallet, true),
        AccountMeta::new(trader, false),
        AccountMeta::new(fx.pam, false),
        AccountMeta::new(fx.gvault, false),
        AccountMeta::new(destination, false),
        AccountMeta::new_readonly(token_program(), false),
        AccountMeta::new(fx.gti, false),
        AccountMeta::new(fx.atb, false),
        AccountMeta::new(fx.wq, false),
    ]);
    phx(a, PI::WithdrawFunds, &amount.to_le_bytes())
}

/// Direct Phoenix `deposit_funds` by a trader wallet.
pub fn ix_deposit_funds(fx: &Fx, wallet: Pubkey, trader: Pubkey, source: Pubkey, amount: u64) -> Instruction {
    let mut a = head();
    a.extend([
        AccountMeta::new(global_config_key(), false),
        AccountMeta::new_readonly(wallet, true),
        AccountMeta::new(source, false),
        AccountMeta::new(trader, false),
        AccountMeta::new(fx.gvault, false),
        AccountMeta::new_readonly(token_program(), false),
        AccountMeta::new(fx.gti, false),
        AccountMeta::new(fx.atb, false),
    ]);
    phx(a, PI::DepositFunds, &amount.to_le_bytes())
}

/// Phoenix IOC `place_market_order` (73 bytes of order packet) with
/// `traderWallet = wallet` as a signer meta (for our trader: `phx_authority`,
/// wrapped in tag 10, which downgrades the meta and signs in the CPI).
#[allow(clippy::too_many_arguments)]
pub fn ix_market_order(
    fx: &Fx,
    wallet: Pubkey,
    trader: Pubkey,
    orderbook: Pubkey,
    side: u8,
    price_ticks: u64,
    lots: u64,
    reduce_only: bool,
    lvs: u64,
) -> Instruction {
    let mut a = head();
    a.extend([
        AccountMeta::new(global_config_key(), false),
        AccountMeta::new_readonly(wallet, true),
        AccountMeta::new(trader, false),
        AccountMeta::new(fx.pam, false),
        AccountMeta::new(fx.gti, false),
        AccountMeta::new(fx.atb, false),
        AccountMeta::new(orderbook, false),
        AccountMeta::new(spline_pda(&orderbook), false),
    ]);
    let mut d = vec![2u8, side, 1];
    d.extend_from_slice(&price_ticks.to_le_bytes());
    d.extend_from_slice(&lots.to_le_bytes());
    d.push(0); // num_quote_lots None
    d.extend_from_slice(&0u64.to_le_bytes()); // min_base_lots_to_fill
    d.extend_from_slice(&0u64.to_le_bytes()); // min_quote_lots_to_fill
    d.push(1); // self_trade_behavior CancelProvide
    d.push(0); // match_limit None
    d.extend_from_slice(&[0u8; 16]); // client_order_id
    d.push(1);
    d.extend_from_slice(&lvs.to_le_bytes());
    d.push(if reduce_only { 128 } else { 0 });
    d.push(0); // cancel_existing false
    phx(a, PI::PlaceMarketOrder, &d)
}

/// Direct Phoenix `cancel_all` by a trader wallet on one book.
pub fn ix_phx_cancel_all(fx: &Fx, wallet: Pubkey, trader: Pubkey, orderbook: Pubkey) -> Instruction {
    let mut a = head();
    a.extend([
        AccountMeta::new(global_config_key(), false),
        AccountMeta::new_readonly(wallet, true),
        AccountMeta::new(trader, false),
        AccountMeta::new(fx.pam, false),
        AccountMeta::new(fx.gti, false),
        AccountMeta::new(fx.atb, false),
        AccountMeta::new(orderbook, false),
        AccountMeta::new(spline_pda(&orderbook), false),
    ]);
    phx(a, PI::CancelAll, &[])
}

/// Ember `deposit` (USDC → PhUSD) by any wallet (fixture layout).
pub fn ix_ember_deposit(fx: &Fx, owner: Pubkey, usdc_src: Pubkey, phusd_dst: Pubkey, amount: u64) -> Instruction {
    let mut data = k::IX_EMBER_DEPOSIT.to_vec();
    data.extend_from_slice(&amount.to_le_bytes());
    Instruction {
        program_id: ember_id(),
        accounts: vec![
            AccountMeta::new_readonly(owner, true),
            AccountMeta::new_readonly(fx.ember_state, false),
            AccountMeta::new_readonly(fx.usdc, false),
            AccountMeta::new(fx.phusd, false),
            AccountMeta::new(usdc_src, false),
            AccountMeta::new(phusd_dst, false),
            AccountMeta::new(fx.ember_vault, false),
            AccountMeta::new_readonly(token_program(), false),
        ],
        data,
    }
}

// ------------------------------------------------------- SPL instructions

pub fn ix_create_ata(payer: Pubkey, owner: Pubkey, mint: Pubkey) -> Instruction {
    Instruction {
        program_id: ata_program(),
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(ata(&owner, &mint), false),
            AccountMeta::new_readonly(owner, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new_readonly(system_program(), false),
            AccountMeta::new_readonly(token_program(), false),
        ],
        data: vec![1],
    }
}

pub fn ix_token_transfer(src: Pubkey, dst: Pubkey, owner: Pubkey, amount: u64) -> Instruction {
    let mut data = vec![3u8];
    data.extend_from_slice(&amount.to_le_bytes());
    Instruction {
        program_id: token_program(),
        accounts: vec![
            AccountMeta::new(src, false),
            AccountMeta::new(dst, false),
            AccountMeta::new_readonly(owner, true),
        ],
        data,
    }
}

pub fn ix_token_close(account: Pubkey, dest: Pubkey, owner: Pubkey) -> Instruction {
    Instruction {
        program_id: token_program(),
        accounts: vec![
            AccountMeta::new(account, false),
            AccountMeta::new(dest, false),
            AccountMeta::new_readonly(owner, true),
        ],
        data: vec![9],
    }
}

/// `SetAuthority(AccountOwner → new_owner)`.
pub fn ix_token_set_owner(account: Pubkey, owner: Pubkey, new_owner: Pubkey) -> Instruction {
    let mut data = vec![6u8, 2, 1];
    data.extend_from_slice(new_owner.as_ref());
    Instruction {
        program_id: token_program(),
        accounts: vec![AccountMeta::new(account, false), AccountMeta::new_readonly(owner, true)],
        data,
    }
}

pub fn ix_system_transfer(from: Pubkey, to: Pubkey, lamports: u64) -> Instruction {
    let mut data = 2u32.to_le_bytes().to_vec();
    data.extend_from_slice(&lamports.to_le_bytes());
    Instruction {
        program_id: system_program(),
        accounts: vec![AccountMeta::new(from, true), AccountMeta::new(to, false)],
        data,
    }
}

// --------------------------------------------------------------- params

fn le(v: &mut [u8], o: usize, bytes: &[u8]) {
    v[o..o + bytes.len()].copy_from_slice(bytes);
}

/// `HarvestParams` (SPEC §3.2).
pub fn harvest_params() -> [u8; 64] {
    let mut b = [0u8; 64];
    le(&mut b, 0, &0u64.to_le_bytes()); // epsilon
    le(&mut b, 8, &1_000_000u64.to_le_bytes()); // d_min = 1 USDC
    le(&mut b, 16, &5_000_000u64.to_le_bytes()); // margin_buffer_abs = 5 USDC
    le(&mut b, 24, &10_000_000_000_000u64.to_le_bytes()); // max_harvest_per_call
    le(&mut b, 40, &3_600u32.to_le_bytes()); // t_min_secs
    le(&mut b, 44, &2_000u32.to_le_bytes()); // margin_buffer_im_bps
    le(&mut b, 48, &1_000_000_000_000u64.to_le_bytes()); // max_buyback_backlog
    // @32..40, @56..58: the retired withdraw tolerance (SPEC v4), zeros.
    b
}

/// `InflowParams` (SPEC §3.3).
pub fn inflow_params() -> [u8; 40] {
    let mut b = [0u8; 40];
    // @0..4 (the retired oracle band / mark age) and @32..40 (the retired
    // Ember tolerance): reserved zeros (SPEC v4).
    le(&mut b, 4, &60u32.to_le_bytes());
    le(&mut b, 8, &1_000_000_000u64.to_le_bytes());
    le(&mut b, 16, &1_000_000u64.to_le_bytes());
    le(&mut b, 24, &1_000_000u64.to_le_bytes()); // deposit_min_atoms
    b
}

// -------------------------------------------------------------- the vault

pub struct VaultOpts {
    pub sol_pair: bool,
    /// USDC atoms deposited into Phoenix by tag 21 (0 = none).
    pub deposit: u64,
}

impl Default for VaultOpts {
    fn default() -> Self {
        Self { sol_pair: true, deposit: 1_000_000_000 }
    }
}

pub const ADMIN_SEED: &str = "sijka-recovery-admin";
pub const BOT_SEED: &str = "sijka-recovery-bot";
pub const CREATOR_SEED: &str = "sijka-recovery-creator";
pub const STRANGER_SEED: &str = "sijka-recovery-stranger";

/// Our vault, initialized for real on the fixture exchange.
pub struct VaultEnv {
    pub ctx: SdkLocalnetContext,
    pub program_id: Pubkey,
    pub p: Pdas,
    pub fx: Fx,
    pub admin: Pubkey,
    pub bot: Pubkey,
    pub creator: Pubkey,
    pub stranger: Pubkey,
    pub trader: Pubkey,
    pub trader_bump: u8,
    pub vault_usdc: Pubkey,
    pub vault_phusd: Pubkey,
    pub er_usdc: Pubkey,
    pub er_phusd: Pubkey,
    pub buyback_usdc: Pubkey,
    pub creator_escrow_usdc: Pubkey,
    pub slot: u64,
    pub ts: i64,
    /// Last oracle update timestamp sent (fixture updates use 1.9e9 + n).
    pub oracle_ts: u64,
}

/// First slot of the vault environment: `slot % 216 000 ≥ cd + 9 000`
/// (deposit quiet window of tag 21, fixture cd = 150), and close to the
/// fixture's setup slot 0.
pub const VAULT_SLOT0: u64 = 9_200;
/// First clock time: close to the fixture's setup time (LiteSVM default 0).
pub const VAULT_T0: i64 = 1_000;

/// Fixture context on the mainnet binaries with our program loaded.
pub fn fixture_ctx(program_id: Pubkey) -> Option<SdkLocalnetContext> {
    let paths = need(find_sdk_localnet_program_paths(), "Phoenix/Ember/Hawkeye SBF artifacts")?;
    let so = need(program_so(), "sijka_vault.so")?;
    let fixture = default_sdk_localnet_fixture().expect("fixture parses");
    let mut ctx = SdkLocalnetContext::new_with_programs(fixture, paths, [SdkLocalnetProgram::new(program_id, so)]);
    ctx.execute_setup();
    Some(ctx)
}

impl VaultEnv {
    pub fn new(o: VaultOpts) -> Option<Self> {
        let program_id = Keypair::new().pubkey();
        let mut ctx = fixture_ctx(program_id)?;
        let fx = Fx::from(&ctx);
        let p = Pdas::derive(&program_id);
        let admin = ctx.add_signer(ADMIN_SEED, 100_000_000_000);
        let bot = ctx.add_signer(BOT_SEED, 100_000_000_000);
        let creator = ctx.add_signer(CREATOR_SEED, 1_000_000_000);
        let stranger = ctx.add_signer(STRANGER_SEED, 100_000_000_000);
        let (trader, trader_bump) = phoenix_trader_pda(&p.phx_authority);
        let mut env = Self {
            ctx,
            program_id,
            p,
            vault_usdc: ata(&p.phx_authority, &fx.usdc),
            vault_phusd: ata(&p.phx_authority, &fx.phusd),
            er_usdc: ata(&admin, &fx.usdc),
            er_phusd: ata(&admin, &fx.phusd),
            buyback_usdc: ata(&p.buyback_authority, &fx.usdc),
            creator_escrow_usdc: ata(&p.creator_escrow, &fx.usdc),
            fx,
            admin,
            bot,
            creator,
            stranger,
            trader,
            trader_bump,
            // slot % 216 000 ≥ cd + 9 000 (deposit quiet window, fixture cd = 150).
            slot: VAULT_SLOT0,
            ts: VAULT_T0,
            oracle_ts: 1_950_000_000,
        };
        env.sync_clock();
        env.refresh_prices();

        // Our ProgramData: upgrade authority = the fixture payer (initialize #0).
        let payer = env.ctx.signer_pubkey("payer");
        let pd = Pubkey::find_program_address(&[program_id.as_ref()], &loader_v3()).0;
        patch(&mut env.ctx.svm, &pd, |d| {
            d[12] = 1;
            d[13..45].copy_from_slice(payer.as_ref());
        });
        let r = env.initialize(o.sol_pair);
        assert_ok(&r);
        env.ctx.svm.airdrop(&env.p.rent_payer, 1_000_000_000).unwrap();
        let r = env.register();
        assert_ok(&r);
        let flags = rd_u32(&env.trader_data(), 96);
        eprintln!("vault trader {} flags after RegisterTrader: {flags:#x}", env.trader);
        if flags == 0 {
            env.enable_capabilities();
        }
        // SPEC v3: the bot key becomes the trading key (tag 3).
        let bot = env.bot;
        assert_ok(&env.set_trader(bot));
        for (owner, mint) in [
            (env.p.phx_authority, env.fx.usdc),
            (env.p.phx_authority, env.fx.phusd),
            (env.admin, env.fx.usdc),
            (env.admin, env.fx.phusd),
            (env.p.buyback_authority, env.fx.usdc),
            (env.p.creator_escrow, env.fx.usdc),
            (env.stranger, env.fx.usdc),
            (env.stranger, env.fx.phusd),
        ] {
            let ix = ix_create_ata(payer, owner, mint);
            assert_ok(&env.send("payer", vec![ix]));
        }
        if o.deposit > 0 {
            env.deposit(o.deposit);
        }
        Some(env)
    }

    // ------------------------------------------------------------ plumbing

    pub fn svm(&mut self) -> &mut LiteSVM {
        &mut self.ctx.svm
    }

    pub fn sync_clock(&mut self) {
        set_clock(&mut self.ctx.svm, self.slot, self.ts);
    }

    /// Advance the clock by `secs` and by one slot per minute (at least one):
    /// the fixture exchange pays in CU for every slot Phoenix catches up on,
    /// so slots advance slower than on mainnet (our program only needs them
    /// to increase).
    pub fn tick(&mut self, secs: i64) {
        self.ts += secs;
        self.slot += u64::try_from((secs / 60).max(1)).unwrap();
        self.sync_clock();
    }

    pub fn tick_slots(&mut self, slots: u64) {
        self.slot += slots;
        self.ts += i64::try_from(slots * 2 / 5).unwrap().max(1);
        self.sync_clock();
    }

    /// Send with a 1.4M CU limit; signers are resolved by the fixture context.
    pub fn send(&mut self, fee_payer_seed: &str, ixs: Vec<Instruction>) -> TxResult {
        let mut all = vec![cu_limit_ix(1_400_000)];
        all.extend(ixs);
        self.ctx.try_send_instructions_with_metadata(all, fee_payer_seed)
    }

    /// Oracle + spline prices at the current slot (fixture levels).
    /// The fixture's `updateOraclePrices` (delegated price oracle) with our CU
    /// limit and increasing update timestamps; the context's helper runs with
    /// the default 200k CU, which Phoenix exceeds after a clock jump.
    pub fn refresh_prices(&mut self) {
        let r = self.try_refresh_prices();
        match &r {
            Ok(m) => eprintln!("oracle refresh at slot {}: {} CU", self.slot, m.compute_units_consumed),
            Err(f) => panic!("oracle refresh at slot {} failed: {:?}\n{}", self.slot, f.err, f.meta.logs.join("\n")),
        }
    }

    pub fn try_refresh_prices(&mut self) -> TxResult {
        let t = self.ctx.fixture.setup_transactions.iter().find(|t| t.name == "oracleSetPrices").unwrap().clone();
        let si = t.instructions.iter().find(|i| i.name == "updateOraclePrices").unwrap();
        let mut ix = decode_fixture_instruction(si).unwrap();
        self.oracle_ts += 1;
        let mut data = PI::UpdateOraclePricesWithOrdering.discriminant().to_vec();
        data.extend_from_slice(&self.oracle_ts.to_le_bytes());
        let ups = [("BTC", 100_000.0), ("ETH", 3_500.0), ("SOL", 150.0)];
        data.extend_from_slice(&(ups.len() as u32).to_le_bytes());
        for (s, px) in ups {
            let u = FixtureOraclePriceUpdate::mark_and_spot_usd(s, px);
            data.extend_from_slice(&sym16(&u.symbol));
            match u.new_exchange_perp_price {
                Some(p) => {
                    data.push(1);
                    data.extend_from_slice(&p.value.to_le_bytes());
                    data.push(p.expo);
                }
                None => data.push(0),
            }
            data.extend_from_slice(&u.new_exchange_spot_price.value.to_le_bytes());
            data.push(u.new_exchange_spot_price.expo);
        }
        data.push(0); // flags
        ix.data = data;
        self.send("price-oracle", vec![ix])
    }

    pub fn orderbook(&self, symbol: &str) -> Pubkey {
        parse_pubkey(&self.ctx.market(symbol).orderbook).unwrap()
    }

    pub fn spline(&self, symbol: &str) -> Pubkey {
        parse_pubkey(&self.ctx.market(symbol).spline).unwrap()
    }

    pub fn cfg<T>(&self, f: impl FnOnce(&Config<'_>) -> T) -> T {
        with_cfg(&self.ctx.svm, &self.p.config, f)
    }

    pub fn edit_cfg(&mut self, f: impl FnOnce(&mut ConfigMut<'_>)) {
        let key = self.p.config;
        edit_cfg(&mut self.ctx.svm, &key, f);
    }

    pub fn trader_data(&self) -> Vec<u8> {
        data_of(&self.ctx.svm, &self.trader)
    }

    pub fn pam_data(&self) -> Vec<u8> {
        data_of(&self.ctx.svm, &self.fx.pam)
    }

    pub fn gc(&self) -> Vec<u8> {
        data_of(&self.ctx.svm, &global_config_key())
    }

    pub fn amount(&self, key: &Pubkey) -> u64 {
        token_amount(&self.ctx.svm, key)
    }

    pub fn lamports(&self, key: &Pubkey) -> u64 {
        lamports(&self.ctx.svm, key)
    }

    /// `C_hdr` (`trader@88`).
    pub fn collateral(&self) -> i64 {
        rd_i64(&self.trader_data(), 88)
    }

    /// Position map records `(asset_index, base_lots)` with a non-zero position.
    pub fn positions(&self) -> Vec<(u32, i64)> {
        trader_positions(&self.trader_data())
    }

    pub fn asset_id(&self, symbol: &str) -> u32 {
        let p = self.pam_data();
        pam_entry(&p, pam_find(&p, symbol).expect("symbol in PAM")).asset_id
    }

    pub fn mark(&self, symbol: &str) -> u64 {
        let p = self.pam_data();
        pam_entry(&p, pam_find(&p, symbol).expect("symbol in PAM")).mark
    }

    // ---------------------------------------------------- setup instructions

    fn initialize(&mut self, sol_pair: bool) -> TxResult {
        let payer = self.ctx.signer_pubkey("payer");
        let pd = Pubkey::find_program_address(&[self.program_id.as_ref()], &loader_v3()).0;
        let mut data = vec![0u8];
        data.extend_from_slice(self.admin.as_ref());
        data.extend_from_slice(self.creator.as_ref());
        data.extend_from_slice(if sol_pair { wsol_mint() } else { self.fx.usdc }.as_ref());
        data.extend_from_slice(&harvest_params());
        data.extend_from_slice(&inflow_params());
        let ix = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(payer, true),
                AccountMeta::new(self.p.config, false),
                AccountMeta::new_readonly(pd, false),
                AccountMeta::new_readonly(system_program(), false),
                AccountMeta::new_readonly(global_config_key(), false),
                AccountMeta::new_readonly(self.fx.ember_state, false),
            ],
            data,
        };
        self.send("payer", vec![ix])
    }

    fn register(&mut self) -> TxResult {
        let ix = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new_readonly(self.admin, true),
                AccountMeta::new(self.p.config, false),
                AccountMeta::new_readonly(self.p.phx_authority, false),
                AccountMeta::new(self.p.rent_payer, false),
                AccountMeta::new_readonly(phoenix_id(), false),
                AccountMeta::new_readonly(log_authority(), false),
                AccountMeta::new_readonly(global_config_key(), false),
                AccountMeta::new(self.trader, false),
                AccountMeta::new_readonly(system_program(), false),
            ],
            data: vec![2, self.trader_bump],
        };
        self.send(ADMIN_SEED, vec![ix])
    }

    /// Replay the fixture's capability grant for `taker0` on our trader.
    fn enable_capabilities(&mut self) {
        let tx = self
            .ctx
            .fixture
            .setup_transactions
            .iter()
            .find(|t| t.name == "seedTaker0Collateral")
            .expect("fixture tx")
            .clone();
        let si = tx.instructions.iter().find(|i| i.name == "enableTaker0TraderCapabilities").expect("ix");
        let mut ix = decode_fixture_instruction(si).unwrap();
        let taker0_trader = self.ctx.actor_trader("taker0");
        for m in ix.accounts.iter_mut() {
            if m.pubkey == taker0_trader {
                m.pubkey = self.trader;
            }
        }
        assert_ok(&self.send("payer", vec![ix]));
        eprintln!("vault trader flags after capability grant: {:#x}", rd_u32(&self.trader_data(), 96));
    }

    /// Mint `usdc` atoms to `vault_usdc`, then tag 21 (Ember wrap + Phoenix deposit).
    pub fn deposit(&mut self, usdc: u64) {
        let vu = self.vault_usdc;
        self.ctx.mint_fake_usdc_to_token_account(vu, usdc);
        let r = self.deposit_ix_send(0);
        assert_ok(&r);
    }

    pub fn deposit_ix(&self, max_amount: u64) -> Instruction {
        let mut data = vec![21u8, 1, 1];
        data.extend_from_slice(&max_amount.to_le_bytes());
        Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(self.p.config, false),
                AccountMeta::new_readonly(self.p.phx_authority, false),
                AccountMeta::new(self.vault_usdc, false),
                AccountMeta::new(self.vault_phusd, false),
                AccountMeta::new_readonly(self.fx.usdc, false),
                AccountMeta::new(self.fx.phusd, false),
                AccountMeta::new_readonly(ember_id(), false),
                AccountMeta::new_readonly(self.fx.ember_state, false),
                AccountMeta::new(self.fx.ember_vault, false),
                AccountMeta::new_readonly(phoenix_id(), false),
                AccountMeta::new_readonly(log_authority(), false),
                AccountMeta::new(global_config_key(), false),
                AccountMeta::new(self.trader, false),
                AccountMeta::new(self.fx.gvault, false),
                AccountMeta::new_readonly(token_program(), false),
                AccountMeta::new(self.fx.gti, false),
                AccountMeta::new(self.fx.atb, false),
            ],
            data,
        }
    }

    pub fn deposit_ix_send(&mut self, max_amount: u64) -> TxResult {
        let ix = self.deposit_ix(max_amount);
        self.send("payer", vec![ix])
    }

    /// Tag 3 `set_trader` (SPEC §5.1.3): the trading key, 0 = trading off.
    pub fn set_trader_ix(&self, key: Pubkey) -> Instruction {
        let mut data = vec![3u8];
        data.extend_from_slice(key.as_ref());
        Instruction {
            program_id: self.program_id,
            accounts: vec![AccountMeta::new_readonly(self.admin, true), AccountMeta::new(self.p.config, false)],
            data,
        }
    }

    pub fn set_trader(&mut self, key: Pubkey) -> TxResult {
        let ix = self.set_trader_ix(key);
        self.send(ADMIN_SEED, vec![ix])
    }

    // --------------------------------------------------------- trading
    //
    // SPEC v3: Phoenix trading instructions for our trader with
    // `traderWallet = phx_authority`, wrapped in tag 10 `trade` and signed by
    // the trading key (`self.bot`).

    /// Tag 10 `trade` (SPEC §5.2.2): `[signer (S), config (R), phx_authority
    /// (R)]` + the Phoenix accounts, `phx_authority` among them downgraded to
    /// a read-only non-signer; data `[10] + phoenix data`.
    pub fn trade_ix(&self, signer: Pubkey, phx: Instruction) -> Instruction {
        let a = self.p.phx_authority;
        let mut accounts = vec![
            AccountMeta::new_readonly(signer, true),
            AccountMeta::new_readonly(self.p.config, false),
            AccountMeta::new_readonly(a, false),
        ];
        accounts.extend(
            phx.accounts.into_iter().map(|m| if m.pubkey == a { AccountMeta::new_readonly(a, false) } else { m }),
        );
        let mut data = vec![10u8];
        data.extend_from_slice(&phx.data);
        Instruction { program_id: self.program_id, accounts, data }
    }

    /// Tag 10 IOC signed by `wallet` (seed `seed`) on our trader,
    /// `lvs = slot + 100`.
    pub fn ioc_as(
        &mut self,
        seed: &str,
        wallet: Pubkey,
        symbol: &str,
        side: u8,
        price: u64,
        lots: u64,
        reduce_only: bool,
    ) -> TxResult {
        let book = self.orderbook(symbol);
        let a = self.p.phx_authority;
        let phx = ix_market_order(&self.fx, a, self.trader, book, side, price, lots, reduce_only, self.slot + 100);
        let ix = self.trade_ix(wallet, phx);
        self.send(seed, vec![ix])
    }

    /// IOC by the trading key.
    pub fn ioc(&mut self, symbol: &str, side: u8, price: u64, lots: u64, reduce_only: bool) -> TxResult {
        let bot = self.bot;
        self.ioc_as(BOT_SEED, bot, symbol, side, price, lots, reduce_only)
    }

    /// Resting limit order by the trading key through tag 10 (the tests only
    /// need an order that rests on the book, so no post-only packet).
    pub fn limit(&mut self, symbol: &str, side: u8, price: u64, lots: u64, reduce_only: bool) -> TxResult {
        let book = self.orderbook(symbol);
        let params = LimitOrderParams::builder()
            .trader(self.p.phx_authority)
            .trader_account(self.trader)
            .perp_asset_map(self.fx.pam)
            .orderbook(book)
            .spline_collection(spline_pda(&book))
            .global_trader_index(vec![self.fx.gti])
            .active_trader_buffer(vec![self.fx.atb])
            .side(if side == 0 { Side::Bid } else { Side::Ask })
            .price_in_ticks(price)
            .num_base_lots(lots)
            .self_trade_behavior(SelfTradeBehavior::CancelProvide)
            .order_flags(if reduce_only { OrderFlags::ReduceOnly } else { OrderFlags::None })
            .build()
            .unwrap();
        let phx = to_sol_ix(create_place_limit_order_ix(params).unwrap());
        let ix = self.trade_ix(self.bot, phx);
        self.send(BOT_SEED, vec![ix])
    }

    /// A resting (non-crossing) bid or ask by the trading key.
    pub fn post_only(&mut self, symbol: &str, side: u8, price: u64, lots: u64) -> TxResult {
        self.limit(symbol, side, price, lots, false)
    }

    /// Phoenix `cancel_all` on `symbol`'s book through tag 10 by the trading key.
    pub fn cancel_all(&mut self, symbol: &str) -> TxResult {
        let book = self.orderbook(symbol);
        let phx = ix_phx_cancel_all(&self.fx, self.p.phx_authority, self.trader, book);
        let ix = self.trade_ix(self.bot, phx);
        self.send(BOT_SEED, vec![ix])
    }

    // ------------------------------------------------------ venue / latch

    pub fn observe(&mut self) -> TxResult {
        let ix = observe_ix(self.program_id, self.p.config, self.fx.pam);
        self.send("payer", vec![ix])
    }

    #[track_caller]
    pub fn observe_after(&mut self, secs: i64) -> Vob {
        self.tick(secs);
        let r = self.observe();
        Vob::from_meta(assert_ok(&r))
    }

    pub fn latch(&mut self) -> TxResult {
        let ix = latch_ix(self.program_id, self.p.config, self.fx.pam);
        self.send("payer", vec![ix])
    }

    pub fn set_exchange(&mut self, active: Option<bool>, maintenance: Option<bool>) -> TxResult {
        let a = self.fx.authority;
        self.send("payer", vec![ix_change_exchange_status(a, active, None, maintenance)])
    }

    /// DOWN (maintenance) observed every 3 000 s for 10 days, then op 0.
    /// With `restore`, the exchange is set active again afterwards and the
    /// prices refreshed (Phoenix "came back", TR-23).
    pub fn latch_via_maintenance(&mut self, restore: bool) {
        assert_ok(&self.set_exchange(None, Some(true)));
        let first = self.observe_after(60);
        assert_eq!((first.verdict, first.reason), (DOWN, 3), "{first:?}");
        let start = self.ts;
        while self.ts - start < 864_000 {
            let v = self.observe_after(3_000);
            assert_eq!(v.verdict, DOWN, "{v:?}");
        }
        let r = self.latch();
        let m = assert_ok(&r);
        assert!(event(&m.logs, b"SJKEVRCL").is_some(), "SJKEVRCL");
        assert_eq!(self.cfg(|c| c.recovery_mode()), 1);
        if restore {
            assert_ok(&self.set_exchange(None, Some(false)));
            self.tick(60);
            self.refresh_prices();
        }
    }

    // -------------------------------------------------- recovery ops

    pub fn op_withdraw_ix(&self, op: u8, max_amount: u64) -> Instruction {
        let mut accounts = vec![
            AccountMeta::new(self.p.config, false),
            AccountMeta::new_readonly(self.p.phx_authority, false),
            AccountMeta::new_readonly(phoenix_id(), false),
        ];
        if op == 1 {
            accounts.push(AccountMeta::new_readonly(hawkeye_id(), false));
        }
        accounts.extend([
            AccountMeta::new_readonly(log_authority(), false),
            AccountMeta::new(global_config_key(), false),
            AccountMeta::new(self.trader, false),
            AccountMeta::new(self.fx.pam, false),
            AccountMeta::new(self.fx.gvault, false),
            AccountMeta::new(self.fx.wq, false),
            AccountMeta::new(self.vault_phusd, false),
            AccountMeta::new_readonly(token_program(), false),
            AccountMeta::new(self.fx.gti, false),
            AccountMeta::new(self.fx.atb, false),
        ]);
        let mut data = vec![51u8, op, 1, 1];
        data.extend_from_slice(&max_amount.to_le_bytes());
        Instruction { program_id: self.program_id, accounts, data }
    }

    /// Op 1 (Hawkeye) or op 6 (flat), sent by the stranger (permissionless).
    pub fn op_withdraw(&mut self, op: u8, max_amount: u64) -> TxResult {
        let ix = self.op_withdraw_ix(op, max_amount);
        self.send(STRANGER_SEED, vec![ix])
    }

    pub fn op_unwrap_ix(&self) -> Instruction {
        Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(self.p.config, false),
                AccountMeta::new_readonly(self.p.phx_authority, false),
                AccountMeta::new(self.vault_phusd, false),
                AccountMeta::new(self.vault_usdc, false),
                AccountMeta::new_readonly(self.fx.usdc, false),
                AccountMeta::new(self.fx.phusd, false),
                AccountMeta::new_readonly(ember_id(), false),
                AccountMeta::new_readonly(self.fx.ember_state, false),
                AccountMeta::new(self.fx.ember_vault, false),
                AccountMeta::new_readonly(token_program(), false),
            ],
            data: vec![51, 4],
        }
    }

    pub fn op_unwrap(&mut self) -> TxResult {
        let ix = self.op_unwrap_ix();
        self.send(STRANGER_SEED, vec![ix])
    }

    pub fn op_send_token_ix(&self, op: u8, dest: Pubkey) -> Instruction {
        let source = if op == 5 { self.vault_phusd } else { self.vault_usdc };
        Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(self.p.config, false),
                AccountMeta::new_readonly(self.p.phx_authority, false),
                AccountMeta::new(source, false),
                AccountMeta::new_readonly(token_program(), false),
                AccountMeta::new(dest, false),
            ],
            data: vec![51, op],
        }
    }

    /// Op 2 (USDC) or op 5 (PhUSD) to `dest`.
    pub fn op_send_token(&mut self, op: u8, dest: Pubkey) -> TxResult {
        let ix = self.op_send_token_ix(op, dest);
        self.send(STRANGER_SEED, vec![ix])
    }

    pub fn op_send_sol_ix(&self, dest: Pubkey) -> Instruction {
        Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(self.p.config, false),
                AccountMeta::new(self.p.fee_inbox, false),
                AccountMeta::new(dest, false),
                AccountMeta::new_readonly(system_program(), false),
            ],
            data: vec![51, 3],
        }
    }

    pub fn op_send_sol(&mut self, dest: Pubkey) -> TxResult {
        let ix = self.op_send_sol_ix(dest);
        self.send(STRANGER_SEED, vec![ix])
    }

    /// Mint PhUSD for the stranger through Ember and give `amount` to `dest`.
    pub fn donate_phusd(&mut self, dest: Pubkey, amount: u64) {
        let (s_usdc, s_phusd) = (ata(&self.stranger, &self.fx.usdc), ata(&self.stranger, &self.fx.phusd));
        self.ctx.mint_fake_usdc_to_token_account(s_usdc, amount);
        let dep = ix_ember_deposit(&self.fx, self.stranger, s_usdc, s_phusd, amount);
        assert_ok(&self.send(STRANGER_SEED, vec![dep]));
        let got = self.amount(&s_phusd);
        let tr = ix_token_transfer(s_phusd, dest, self.stranger, got);
        assert_ok(&self.send(STRANGER_SEED, vec![tr]));
    }

    /// Accounts whose balances no recovery op may touch (SPEC §5.6.6):
    /// token balances of the buyback escrow and the unpaid creator share,
    /// and lamports of the buyback SOL budget and the creator escrow PDA.
    pub fn protected_snapshot(&self) -> Vec<(String, u64)> {
        vec![
            ("buyback_usdc".into(), self.amount(&self.buyback_usdc)),
            ("creator_escrow_usdc".into(), self.amount(&self.creator_escrow_usdc)),
            ("buyback_authority lamports".into(), self.lamports(&self.p.buyback_authority)),
            ("creator_escrow lamports".into(), self.lamports(&self.p.creator_escrow)),
            ("swap_usdc".into(), self.amount(&ata(&self.p.swap_authority, &self.fx.usdc))),
            ("bb_unwrap lamports".into(), self.lamports(&self.p.bb_unwrap)),
        ]
    }

    /// Error helper for chained checks.
    #[track_caller]
    pub fn expect_err(&self, r: &TxResult, e: SijkaError) {
        assert_err(r, e);
    }

    // ------------------------------------------------ other tags (TR-14)

    /// Tag 30 `harvest` (SPEC §5.4.2 account table).
    pub fn harvest_ix(&self) -> Instruction {
        Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(self.p.config, false),
                AccountMeta::new_readonly(self.p.phx_authority, false),
                AccountMeta::new_readonly(phoenix_id(), false),
                AccountMeta::new_readonly(hawkeye_id(), false),
                AccountMeta::new_readonly(ember_id(), false),
                AccountMeta::new_readonly(log_authority(), false),
                AccountMeta::new(global_config_key(), false),
                AccountMeta::new(self.trader, false),
                AccountMeta::new(self.fx.pam, false),
                AccountMeta::new(self.fx.gvault, false),
                AccountMeta::new(self.fx.wq, false),
                AccountMeta::new_readonly(self.fx.usdc, false),
                AccountMeta::new(self.fx.phusd, false),
                AccountMeta::new(self.vault_phusd, false),
                AccountMeta::new(self.vault_usdc, false),
                AccountMeta::new_readonly(self.fx.ember_state, false),
                AccountMeta::new(self.fx.ember_vault, false),
                AccountMeta::new_readonly(token_program(), false),
                AccountMeta::new(self.creator_escrow_usdc, false),
                AccountMeta::new(self.buyback_usdc, false),
                AccountMeta::new(self.fx.gti, false),
                AccountMeta::new(self.fx.atb, false),
            ],
            data: vec![30, 1, 1],
        }
    }

    /// Tag 31 `harvest_preview`.
    pub fn preview_ix(&self) -> Instruction {
        Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new_readonly(self.p.config, false),
                AccountMeta::new_readonly(phoenix_id(), false),
                AccountMeta::new_readonly(hawkeye_id(), false),
                AccountMeta::new_readonly(global_config_key(), false),
                AccountMeta::new_readonly(self.trader, false),
                AccountMeta::new_readonly(self.fx.pam, false),
                AccountMeta::new_readonly(self.fx.wq, false),
                AccountMeta::new_readonly(self.buyback_usdc, false),
                AccountMeta::new_readonly(self.fx.gti, false),
                AccountMeta::new_readonly(self.fx.atb, false),
            ],
            data: vec![31, 1, 1],
        }
    }

    /// Tag 32 `pay_creator` (creates `creator_usdc` first).
    pub fn pay_creator(&mut self) -> TxResult {
        let payer = self.ctx.signer_pubkey("payer");
        let creator_usdc = ata(&self.creator, &self.fx.usdc);
        assert_ok(&self.send("payer", vec![ix_create_ata(payer, self.creator, self.fx.usdc)]));
        let ix = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(self.p.config, false),
                AccountMeta::new_readonly(self.p.creator_escrow, false),
                AccountMeta::new(self.creator_escrow_usdc, false),
                AccountMeta::new(creator_usdc, false),
                AccountMeta::new_readonly(token_program(), false),
            ],
            data: vec![32],
        };
        self.send(STRANGER_SEED, vec![ix])
    }
}

/// Position map records with a non-zero position (extensions skipped).
pub fn trader_positions(t: &[u8]) -> Vec<(u32, i64)> {
    if t.len() < 240 {
        return vec![];
    }
    let len = rd_u64(t, 224) as usize;
    (0..len)
        .filter_map(|i| {
            let o = 240 + 40 * i;
            if o + 40 > t.len() {
                return None;
            }
            let aid = rd_u32(t, o);
            let base = rd_i64(t, o + 8);
            (aid < 0xFF00_0000 && base != 0).then_some((aid, base))
        })
        .collect()
}

/// `SJKEVRCW` fields used by the tests: `(op, bits, d, r, buf, im, total_queued_after)`.
pub fn parse_rcw(d: &[u8]) -> (u8, u8, u64, u64, u64, u64, u64) {
    assert_eq!(d.len(), 123, "SJKEVRCW length");
    assert_eq!(&d[..8], b"SJKEVRCW");
    (d[17], d[18], rd_u64(d, 27), rd_u64(d, 35), rd_u64(d, 75), rd_u64(d, 67), rd_u64(d, 99))
}

/// `SJKEVRCS`: `(op, route, amount, destination, cum_after)`.
pub fn parse_rcs(d: &[u8]) -> (u8, u8, u64, Pubkey, u64) {
    assert_eq!(d.len(), 91, "SJKEVRCS length");
    assert_eq!(&d[..8], b"SJKEVRCS");
    (d[17], d[18], rd_u64(d, 43), rd_key(d, 51), rd_u64(d, 83))
}

/// `phoenix_rise` instruction → `solana_instruction::Instruction`.
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
