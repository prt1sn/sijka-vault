// Copyright (c) 2026 prt1sn. All rights reserved.
//! TT-2 … TT-8 (SPEC v3 §5.2.1–§5.2.5, §9.4) on the real runtime: every
//! Phoenix instruction outside the allowlist is refused before any CPI, with
//! a plausible layout and with its own real layout; only Phoenix can be
//! called; only our trader account; `phx_authority` only in the signer slot
//! and only once; none of our PDAs or token accounts in any slot; the layout
//! tricks that pass our checks fail inside Phoenix and change nothing. And
//! the regression for the reason of SPEC v3 (DECISIONS §19, revised
//! 2026-09-26): the delegate-child `SwapNative` bypass has no path left.

use phoenix_rise::ix::FLICKER_PROGRAM_ID;
use phoenix_rise::ix::discriminants::PhoenixInstruction;
use phoenix_rise::ix::flight::{FLIGHT_PROGRAM_ID, ProxyInstructionParams, create_proxy_instruction_ix};
use phoenix_rise::ix::transfer_collateral::{TransferCollateralParams, create_transfer_collateral_ix};
use phoenix_rise::ix::types::Side;
use phoenix_rise_litesvm_test::parse_pubkey;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::abi;
use crate::harness::*;
use crate::phx::*;
use crate::phx_trade::*;

/// `ix` with the Phoenix discriminator of `name` in place of its own.
fn with_disc(ix: &Instruction, name: &str) -> Instruction {
    let mut ix = ix.clone();
    let d = PhoenixInstruction::from_instruction_name(name).unwrap_or_else(|| panic!("SDK: no {name}"));
    ix.data[..8].copy_from_slice(&d.discriminant());
    ix
}

/// TT-2: the allowlist of the ABI is the SDK's 14 trading instructions, and
/// each of the other 99 Phoenix instructions (89 of the SDK enum, 10 only in
/// the on-chain IDL) is `TradeInstructionNotAllowed` before any CPI, with or
/// without payload, in a layout that passes every account rule; data shorter
/// than tag + discriminator too. Nothing changes.
#[test]
fn tt2_every_other_phoenix_instruction_is_refused() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(1_000_000_000);
    let before = env.outside();
    let c0 = env.our_trader().collateral;

    let allow = abi::trade_allowlist();
    assert_eq!(allow.len(), 14);
    for e in &allow {
        let sdk = PhoenixInstruction::from_instruction_name(&e.name).unwrap_or_else(|| panic!("SDK: no {}", e.name));
        assert_eq!(sdk.discriminant(), e.disc, "{}: ABI discriminator = SDK", e.name);
        assert!(e.min <= abi::max_trade_accounts());
    }
    let allowed: Vec<[u8; 8]> = allow.iter().map(|e| e.disc).collect();
    let mut others: Vec<(String, [u8; 8])> = PhoenixInstruction::ALL
        .iter()
        .filter(|i| !allowed.contains(&i.discriminant()))
        .map(|i| (i.instruction_name().to_string(), i.discriminant()))
        .collect();
    assert_eq!(others.len(), PhoenixInstruction::ALL.len() - 14, "all 14 are in the SDK enum");
    for (snake, hex) in IDL_ONLY {
        let d = disc(&format!("global:{snake}"));
        assert_eq!(d, hex8(hex), "{snake}: appendix H §1");
        assert!(!others.iter().any(|(_, o)| *o == d) && !allowed.contains(&d), "{snake}: not in the SDK enum");
        others.push((snake.to_string(), d));
    }
    assert_eq!(others.len(), 99, "113 Phoenix instructions, 14 allowed");

    let base = env.phx_limit_ix("SOL", 0, env.ticks_for("SOL", 140_000), 1);
    let bot = env.bot;
    for (name, d) in &others {
        for payload in [0usize, 64] {
            let mut data = d.to_vec();
            data.resize(8 + payload, 0);
            let ix = env.trade_raw(&bot, base.accounts.clone(), &data);
            env.refuse(ix, "TradeInstructionNotAllowed", &format!("{name}, payload {payload}"));
        }
    }
    for len in [1usize, 5, 8] {
        let mut ix = env.trade_ix(base.clone());
        ix.data.truncate(len);
        env.refuse(ix, "TradeInstructionNotAllowed", &format!("{len} bytes of data"));
    }
    assert_eq!(env.our_trader().collateral, c0);
    assert_eq!(env.outside(), before, "INV-9");
}

/// TT-2 with the real layouts of the instructions that move money, change
/// accounts or grant rights (built by the Phoenix SDK for `traderWallet =
/// phx_authority`): refused by the allowlist before any CPI; nothing moves.
#[test]
fn tt2_money_movers_with_their_real_layouts() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(1_000_000_000);
    let (a, t, bot, attacker) = (env.pdas.phx_authority.0, env.pdas.trader.0, env.bot, env.attacker);
    let phusd = env.fx.phusd;
    let bot_phusd = env.create_ata(&bot, &phusd, &SPL_TOKEN);
    let taker = env.ctx.actor_trader("taker0");
    let (reg, child) = env.phx_register_ix(&attacker, &a, 0, 1, 0, 1);
    ok(env.send1(reg, S_ATTACKER), "a stranger registers (phx_authority, 0, 1)");
    let before = env.outside();
    let c0 = env.our_trader().collateral;
    let vault_phusd = env.vault_phusd();
    let wd = env.phx_withdraw_ix(&a, &bot_phusd, 1_000_000);
    let tc = env.phx_transfer_out_ix(&a, &taker, 1_000_000);
    let cases: Vec<(&str, Instruction)> = vec![
        ("SwapNative on T", env.phx_swap_native_ix(&a, &t, &bot_phusd, 1_000_000)),
        ("SwapNative on a child", env.phx_swap_native_ix(&a, &child, &bot_phusd, 1_000_000)),
        ("TransferCollateral to a stranger", tc.clone()),
        ("TransferCollateral to a child", env.phx_transfer_out_ix(&a, &child, 1_000_000)),
        ("TransferCollateralChildToParent", env.phx_child_to_parent_ix(&a, &child)),
        ("AuthorizedTransferCollateral", with_disc(&tc, "AuthorizedTransferCollateral")),
        ("WithdrawFunds", wd.clone()),
        ("WithdrawFundsWithFee", with_disc(&wd, "WithdrawFundsWithFee")),
        ("WithdrawNativeSol", with_disc(&wd, "WithdrawNativeSol")),
        ("DepositFunds from vault_phusd", env.phx_deposit_funds_ix(&a, &vault_phusd, 1_000_000)),
        ("DelegateTrader", env.phx_delegate_ix(&a, &t, &bot)),
        ("RegisterTrader", env.phx_register_ix(&bot, &a, 0, 1, 0, 2).0),
        ("SyncParentToChild", env.phx_sync_parent_to_child_ix(&a, &child)),
        ("CloseTraderAccount", with_disc(&wd, "CloseTraderAccount")),
        ("ReallocTrader", env.phx_realloc_ix(&bot)),
        ("PlaceMarketOrderDelegated", env.phx_market_delegated_ix("SOL", &Pubkey::new_unique())),
        ("CreateConditionalOrdersAccount", env.phx_create_cond_orders_ix(&bot, 8)),
    ];
    for (label, phx) in cases {
        let ix = env.trade_ix(phx);
        env.refuse(ix, "TradeInstructionNotAllowed", label);
    }
    assert_eq!(env.token_amount(&bot_phusd), 0, "nothing reached the key");
    assert_eq!(env.our_trader().collateral, c0, "collateral unchanged");
    assert_eq!(env.trader_hdr(&child).collateral, 0, "nothing reached the child");
    assert!(!env.exists(&trader_pda(&a, 0, 2)), "no account registered through tag 10");
    assert_eq!(env.outside(), before, "INV-9");
}

/// TT-3: the CPI target is the constant Phoenix id and `P[0]` must be it: a
/// Flight `ProxyInstruction` (builder fee through a collateral transfer) is
/// not an allowlisted discriminator; its accounts with a trading
/// discriminator, or any other program in `P[0]`, are `InvalidTradeAccounts`;
/// so is a substituted log authority or GlobalConfig.
#[test]
fn tt3_only_phoenix_is_called() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(1_000_000_000);
    let (a, t, bot) = (env.pdas.phx_authority.0, env.pdas.trader.0, env.bot);
    let before = env.outside();
    let base = env.phx_limit_ix("SOL", 0, env.ticks_for("SOL", 140_000), 1);

    let builder = env.ctx.actor("taker1");
    let inner = TransferCollateralParams::builder()
        .trader(a)
        .src_trader_account(t)
        .dst_trader_account(parse_pubkey(&builder.trader_account).unwrap())
        .perp_asset_map(env.fx.pam)
        .global_trader_index(env.fx.gti.clone())
        .active_trader_buffer(env.fx.atb.clone())
        .amount(1_000_000)
        .build()
        .unwrap();
    let params = ProxyInstructionParams::builder()
        .builder_authority(parse_pubkey(&builder.pubkey).unwrap())
        .builder_trader_account(parse_pubkey(&builder.trader_account).unwrap())
        .trader_wallet(a)
        .inner_instruction(create_transfer_collateral_ix(inner).unwrap())
        .root_authority(env.ctx.signer_pubkey(S_PAYER))
        .build()
        .unwrap();
    let proxy = to_sol_ix(create_proxy_instruction_ix(params).unwrap());
    assert_eq!(proxy.program_id, FLIGHT_PROGRAM_ID);
    let ix = env.trade_raw(&bot, proxy.accounts.clone(), &proxy.data);
    env.refuse(ix, "TradeInstructionNotAllowed", "Flight ProxyInstruction");
    let ix = env.trade_raw(&bot, proxy.accounts.clone(), &base.data);
    env.refuse(ix, "InvalidTradeAccounts", "Flight proxy accounts, PlaceLimitOrder data");

    for program in
        [FLIGHT_PROGRAM_ID, FLICKER_PROGRAM_ID, EMBER, HAWKEYE, SYSTEM_PROGRAM, SPL_TOKEN, TOKEN_2022, env.program]
    {
        let mut p = base.accounts.clone();
        p[0].pubkey = program;
        let ix = env.trade_raw(&bot, p, &base.data);
        env.refuse(ix, "InvalidTradeAccounts", &format!("P[0] = {program}"));
    }
    for (slot, key) in [(1usize, Pubkey::new_unique()), (1, PHOENIX), (2, Pubkey::new_unique()), (2, EMBER_STATE)] {
        let mut p = base.accounts.clone();
        p[slot].pubkey = key;
        let ix = env.trade_raw(&bot, p, &base.data);
        env.refuse(ix, "InvalidTradeAccounts", &format!("P[{slot}] = {key}"));
    }
    assert_eq!(env.outside(), before, "INV-9");
}

/// TT-4: only `T = (phx_authority, 0, 0)`: sub-accounts of `phx_authority`
/// that a stranger registered with preference bits 0 (no owner signature
/// needed, appendix H §0.3 p.5; Phoenix makes `phx_authority` their position
/// authority too), a fixture trader, `T` twice, `T` nowhere — in the trader
/// slot of every layout family (`TR` = 4 and `TR` = 3). A sub-account after
/// the layout is inert: Phoenix reads `T` at its slot and ignores the tail.
#[test]
fn tt4_only_our_trader_account() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(1_000_000_000);
    let (a, t, attacker) = (env.pdas.phx_authority.0, env.pdas.trader.0, env.attacker);
    let (reg1, sub1) = env.phx_register_ix(&attacker, &a, 0, 1, 0, 1);
    let (reg2, sub2) = env.phx_register_ix(&attacker, &a, 0, 1, 2, 1);
    ok(env.send1(reg1, S_ATTACKER), "(phx_authority, 0, 1) with prefs 0 by a stranger");
    ok(env.send1(reg2, S_ATTACKER), "(phx_authority, 2, 1) with prefs 0 by a stranger");
    for s in [sub1, sub2] {
        let h = env.trader_hdr(&s);
        assert_eq!((h.authority, h.position_authority, h.prefs), (a, a, 0), "{s}: phx_authority's account, prefs 0");
    }
    let before = env.outside();
    let taker0 = env.ctx.actor_trader("taker0");
    let px = env.ticks_for("SOL", 140_000);
    let foreign = [
        (sub1, "sub-account (0, 1)"),
        (sub2, "sub-account (2, 1)"),
        (taker0, "taker0"),
        (Pubkey::new_unique(), "T nowhere"),
    ];

    let limit = env.phx_limit_ix("SOL", 0, px, 1);
    let cancel_cond = env.phx_cancel_conditional_ix("SOL", 1);
    let stop = env.phx_stop_loss_ix("SOL", env.ticks_for("SOL", 100_000));
    for (layout, tr) in [(&limit, 4usize), (&cancel_cond, 3), (&stop, 4)] {
        assert_eq!(layout.accounts[tr].pubkey, t);
        for (key, label) in foreign {
            let mut ix = env.trade_ix(layout.clone());
            ix.accounts[3 + tr].pubkey = key;
            env.refuse(ix, "InvalidTradeAccounts", &format!("{label} in TR = {tr}"));
        }
        // T in its slot and once more in the tail (T8).
        let mut ix = env.trade_ix(layout.clone());
        ix.accounts.push(AccountMeta::new(t, false));
        env.refuse(ix, "InvalidTradeAccounts", &format!("T twice, TR = {tr}"));
    }

    let sub_data = env.data(&sub1);
    let mut ix = env.trade_ix(limit.clone());
    ix.accounts.push(AccountMeta::new(sub1, false));
    let m = ok(env.send1(ix, S_BOT), "a sub-account after the layout");
    assert_eq!(order_result(&m, Side::Bid, "tail").posted, 1, "the order is T's");
    assert_eq!(env.data(&sub1), sub_data, "the sub-account is untouched");
    ok(env.send1(env.cancel_all_ix("SOL"), S_BOT), "CancelAll");
    assert_eq!(env.outside(), before, "INV-9");
}

/// TT-5: `phx_authority` only in the signer slot of the entry and only once:
/// in the payer / funder slot of #9, #10, #11, #12, #14 (with the trading key
/// in the signer slot, or with `phx_authority` in both), and `P[n − 1]` not
/// System for #10 / #11 — all `InvalidTradeAccounts` before any CPI. (A
/// layout where Phoenix would take `phx_authority` for a payer cannot pass
/// T7 + T8, so it never reaches Phoenix.)
#[test]
fn tt5_phx_authority_only_in_the_signer_slot() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(1_000_000_000);
    let (a, bot) = (env.pdas.phx_authority.0, env.bot);
    let [px, tp, tp_x, stop, stop_x, trig] =
        [141_000, 170_000, 169_000, 140_000, 139_000, 100_000].map(|u| env.ticks_for("SOL", u));
    let lwc = env.phx_limit_with_conditionals_ix("SOL", 0, px, 1, Some(take_profit_above(tp, tp_x)), None);
    let att = env.phx_attached_conditional_ix("SOL", (px, 1), stop_below(stop, stop_x));
    let sl = env.phx_stop_loss_ix("SOL", trig);
    let pco = env.phx_position_conditional_ix("SOL", stop_below(stop, stop_x), 100);
    let csl = env.phx_cancel_stop_loss_ix("SOL", &bot);
    // (layout, AU, payer / funder slot)
    let n = |ix: &Instruction| ix.accounts.len();
    let cases = [
        ("#9", &lwc, 3usize, 10usize),
        ("#12", &att, 4, 7),
        ("#10", &sl, n(&sl) - 3, 3),
        ("#11", &pco, n(&pco) - 3, 3),
        ("#14", &csl, 5, 3),
    ];
    for (label, ix, au, payer) in cases {
        assert_eq!(ix.accounts[au].pubkey, a, "{label}: AU");
        assert_eq!(ix.accounts[payer].pubkey, bot, "{label}: payer / funder");
        let mut p = ix.accounts.clone();
        p[payer].pubkey = a;
        p[au].pubkey = bot;
        let tx = env.trade_raw(&bot, p, &ix.data);
        env.refuse(tx, "InvalidTradeAccounts", &format!("{label}: phx_authority as payer, the key as signer"));
        let mut p = ix.accounts.clone();
        p[payer].pubkey = a;
        let tx = env.trade_raw(&bot, p, &ix.data);
        env.refuse(tx, "InvalidTradeAccounts", &format!("{label}: phx_authority as payer and signer"));
    }
    for (label, ix) in [("#10", &sl), ("#11", &pco)] {
        let mut p = ix.accounts.clone();
        let last = p.len() - 1;
        p[last].pubkey = Pubkey::new_unique();
        let tx = env.trade_raw(&bot, p, &ix.data);
        env.refuse(tx, "InvalidTradeAccounts", &format!("{label}: P[n - 1] not System"));
    }
}

/// TT-6: none of our accounts in any slot of `P`: our token accounts and a
/// foreign one (owner SPL Token), a Token-2022 account, `config` and
/// `buyback_state` (owner: the program), the System PDAs by key. Slots
/// 0–2 fail T5, the signer slot T7, the trader slot T6, the rest and the
/// tail T9. Executables other than `P[0]` and System fail T10.
#[test]
fn tt6_our_accounts_in_every_slot() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(1_000_000_000);
    ok(env.send1(env.bb_init_ix(), S_PAYER), "bb_init");
    let (usdc, attacker, swap) = (env.fx.usdc, env.attacker, env.pdas.swap_authority.0);
    let emergency = env.cfg_key("emergency_recipient");
    let swap_usdc = env.create_ata(&swap, &usdc, &SPL_TOKEN);
    let emergency_usdc = env.create_ata(&emergency, &usdc, &SPL_TOKEN);
    let foreign_usdc = env.create_ata(&attacker, &usdc, &SPL_TOKEN);
    let t22 = Pubkey::new_unique();
    env.install(&t22, &TOKEN_2022, vec![0u8; 165]);
    let before = env.outside();
    let forbidden = [
        (env.vault_usdc(), "vault_usdc"),
        (env.vault_phusd(), "vault_phusd"),
        (env.escrow_usdc(), "creator_escrow_usdc"),
        (env.buyback_usdc(), "buyback_usdc"),
        (env.creator_usdc(), "creator_usdc"),
        (swap_usdc, "swap_usdc"),
        (emergency_usdc, "emergency_recipient_usdc"),
        (foreign_usdc, "a foreign token account"),
        (t22, "a Token-2022 account"),
        (env.pdas.config.0, "config"),
        (env.pdas.buyback_state.0, "buyback_state"),
        (env.pdas.fee_inbox.0, "fee_inbox"),
        (env.pdas.swap_authority.0, "swap_authority"),
        (env.pdas.buyback_authority.0, "buyback_authority"),
        (env.pdas.rent_payer.0, "rent_payer"),
        (env.pdas.creator_escrow.0, "creator_escrow"),
        (env.pdas.bb_unwrap.0, "bb_unwrap"),
    ];
    let base = env.phx_limit_ix("SOL", 0, env.ticks_for("SOL", 140_000), 1);
    let bot = env.bot;
    let n = base.accounts.len();
    for (key, name) in forbidden {
        for slot in 0..=n {
            let mut p = base.accounts.clone();
            let meta = AccountMeta {
                pubkey: key,
                is_signer: false,
                // A writable `config` would make slot 1 writable in the
                // message (AccountMustBeReadonly first).
                is_writable: key != env.pdas.config.0 && p.get(slot).is_none_or(|m| m.is_writable),
            };
            if slot == n {
                p.push(meta);
            } else {
                p[slot] = meta;
            }
            let want = if slot <= 4 { "InvalidTradeAccounts" } else { "ForbiddenTradeAccount" };
            let ix = env.trade_raw(&bot, p, &base.data);
            env.refuse(ix, want, &format!("{name} in P[{slot}]"));
        }
    }
    for program in [SPL_TOKEN, TOKEN_2022, ATA_PROGRAM, env.program, PHOENIX, EMBER, HAWKEYE] {
        let mut p = base.accounts.clone();
        p.push(AccountMeta::new_readonly(program, false));
        let ix = env.trade_raw(&bot, p, &base.data);
        env.refuse(ix, "ForbiddenTradeAccount", &format!("executable {program} in the tail"));
    }
    // T4: MIN ≤ n ≤ 27.
    let mut p = base.accounts.clone();
    p.pop();
    let ix = env.trade_raw(&bot, p, &base.data);
    env.refuse(ix, "InvalidTradeAccounts", "n = MIN - 1");
    let max = abi::max_trade_accounts();
    let mut p = base.accounts.clone();
    p.resize(max + 1, AccountMeta::new_readonly(SYSTEM_PROGRAM, false));
    let ix = env.trade_raw(&bot, p, &base.data);
    env.refuse(ix, "InvalidTradeAccounts", "n = 28");
    let mut p = base.accounts.clone();
    p.resize(max, AccountMeta::new_readonly(SYSTEM_PROGRAM, false));
    let ix = env.trade_raw(&bot, p, &base.data);
    ok(env.send1(ix, S_BOT), "n = 27 (System accounts after the layout)");
    ok(env.send1(env.cancel_all_ix("SOL"), S_BOT), "CancelAll");
    assert_eq!(env.outside(), before, "INV-9");
}

/// TT-8 (appendix H §4.3): layouts that pass our checks but disagree with
/// Phoenix's own reading fail inside Phoenix and move nothing:
/// `PlaceStopLoss` with extra accounts so that our `n − 3` holds
/// `phx_authority` while Phoenix's signer slot (`8 + g + a`) holds the
/// trading key (mainnet simulation: `IncorrectAuthority`); `PlaceLimitOrder`
/// with one arena account more than the headers declare (the orderbook slot
/// then holds an arena: `InvalidAccountData`).
#[test]
fn tt8_layout_tricks_reach_phoenix_and_fail_there() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(1_000_000_000);
    let (a, bot) = (env.pdas.phx_authority.0, env.bot);
    let [take, trig, bid] = [151_000, 100_000, 140_000].map(|u| env.ticks_for("SOL", u));
    ok(env.send1(env.ioc_ix("SOL", 0, false, take, 10), S_BOT), "open a long");
    let before = env.outside();

    let sl = env.phx_stop_loss_ix("SOL", trig);
    assert_eq!(sl.accounts.len(), 13, "g = a = 1");
    let slot = 8 + env.fx.gti.len() + env.fx.atb.len();
    assert_eq!(sl.accounts[slot].pubkey, a, "Phoenix's signer slot");
    let mut p = sl.accounts.clone();
    p[slot] = AccountMeta::new_readonly(bot, true);
    p.push(AccountMeta::new_readonly(a, false));
    p.push(AccountMeta::new_readonly(Pubkey::new_unique(), false));
    p.push(AccountMeta::new_readonly(SYSTEM_PROGRAM, false));
    let ix = env.trade_raw(&bot, p, &sl.data);
    let e = expect_foreign_err(env.send1(ix, S_BOT), "PlaceStopLoss, phx_authority at n - 3 only");
    assert!(phoenix_called(&e.meta.logs), "our checks passed: Phoenix decided\n{}", e.meta.logs.join("\n"));
    assert_eq!(env.stop_loss("SOL"), None, "no stop loss");

    let base = env.phx_limit_ix("SOL", 0, bid, 1);
    let mut p = base.accounts.clone();
    let atb_at = 6 + env.fx.gti.len();
    let atb = p[atb_at].clone();
    p.insert(atb_at + 1, atb);
    let ix = env.trade_raw(&bot, p, &base.data);
    let e = expect_foreign_err(env.send1(ix, S_BOT), "PlaceLimitOrder with one ATB account too many");
    assert!(phoenix_called(&e.meta.logs), "our checks passed: Phoenix decided");
    assert!(env.book_at("SOL", true, bid).is_empty(), "no order");

    assert_eq!(env.position("SOL"), 10);
    assert_eq!(env.outside(), before, "INV-9");
}

/// Regression, DECISIONS §19 (revised 2026-09-26; mainnet simulations
/// `gdel/batch*.out`): under the abandoned delegate model the trading key was
/// Phoenix position authority of `T` and could register a child `(A, 0, k)`
/// with preference bits 0, sync it, move collateral there and `SwapNative`
/// it out to itself. Now there is no delegate: `phx_authority` is authority
/// and position authority of `T` and of every child anyone registers, the
/// trading key is neither, and tag 10 forwards none of the steps. The first
/// step (registering the child) still works on Phoenix and is harmless.
#[test]
fn delegate_child_swap_native_bypass_is_closed() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(1_000_000_000);
    let (a, t, bot, attacker) = (env.pdas.phx_authority.0, env.pdas.trader.0, env.bot, env.attacker);
    let h = env.our_trader();
    assert_eq!((h.authority, h.position_authority), (a, a), "no delegate: phx_authority is both");
    let phusd = env.fx.phusd;
    let bot_phusd = env.create_ata(&bot, &phusd, &SPL_TOKEN);
    let take = env.ticks_for("SOL", 151_000);
    let c0 = h.collateral;
    assert!(c0 > 0);

    // Step 1 of the old chain: a child of phx_authority with prefs 0.
    let (reg, child) = env.phx_register_ix(&attacker, &a, 0, 1, 0, 7);
    ok(env.send1(reg, S_ATTACKER), "child (phx_authority, 0, 7), prefs 0");
    let ch = env.trader_hdr(&child);
    assert_eq!((ch.authority, ch.position_authority, ch.prefs, ch.collateral), (a, a, 0, 0));
    let before = env.outside();

    // The trading key cannot become a position authority, of T or of the child.
    for (label, phx) in [
        ("DelegateTrader T -> the key", env.phx_delegate_ix(&a, &t, &bot)),
        ("DelegateTrader child -> the key", env.phx_delegate_ix(&a, &child, &bot)),
    ] {
        let ix = env.trade_ix(phx);
        env.refuse(ix, "TradeInstructionNotAllowed", label);
    }
    // Steps 2–4 through tag 10: sync, collateral to the child, swap out.
    for (label, phx) in [
        ("SyncParentToChild", env.phx_sync_parent_to_child_ix(&a, &child)),
        ("TransferCollateral T -> child", env.phx_transfer_out_ix(&a, &child, c0 as u64 / 2)),
        ("SwapNative on the child", env.phx_swap_native_ix(&a, &child, &bot_phusd, 1_000_000)),
        ("SwapNative on T", env.phx_swap_native_ix(&a, &t, &bot_phusd, 1_000_000)),
        ("TransferCollateralChildToParent", env.phx_child_to_parent_ix(&a, &child)),
    ] {
        let ix = env.trade_ix(phx);
        env.refuse(ix, "TradeInstructionNotAllowed", label);
    }
    // The same signed by the trading key directly on Phoenix: it is nobody's
    // authority or position authority.
    for (label, ix) in [
        ("DelegateTrader of T", env.phx_delegate_ix(&bot, &t, &bot)),
        ("DelegateTrader of the child", env.phx_delegate_ix(&bot, &child, &bot)),
        ("SyncParentToChild", env.phx_sync_parent_to_child_ix(&bot, &child)),
        ("TransferCollateral T -> child", env.phx_transfer_out_ix(&bot, &child, 1_000_000)),
        ("SwapNative on the child", env.phx_swap_native_ix(&bot, &child, &bot_phusd, 1_000_000)),
        ("SwapNative on T", env.phx_swap_native_ix(&bot, &t, &bot_phusd, 1_000_000)),
    ] {
        expect_foreign_err(env.send1(ix, S_BOT), &format!("{label} by the trading key directly"));
    }
    // An allowlisted discriminator cannot be pointed at the child (T6) nor
    // carry the SwapNative accounts (T6: P[4] is not T).
    let mut ix = env.ioc_ix("SOL", 0, false, take, 1);
    ix.accounts[3 + 4].pubkey = child;
    env.refuse(ix, "InvalidTradeAccounts", "IOC on the child");
    let swap = env.phx_swap_native_ix(&a, &t, &bot_phusd, 1_000_000);
    let mut data = PhoenixInstruction::PlaceMarketOrder.discriminant().to_vec();
    data.extend_from_slice(&swap.data[8..]);
    let ix = env.trade_raw(&bot, swap.accounts.clone(), &data);
    env.refuse(ix, "InvalidTradeAccounts", "SwapNative accounts under a PlaceMarketOrder discriminator");

    // Nothing moved; nobody but phx_authority controls T or the child.
    assert_eq!(env.token_amount(&bot_phusd), 0, "nothing reached the key");
    assert_eq!(env.our_trader().collateral, c0, "T's collateral");
    let ch = env.trader_hdr(&child);
    assert_eq!((ch.authority, ch.position_authority, ch.collateral), (a, a, 0), "the child");
    assert_eq!(env.outside(), before, "INV-9");
}

/// TT-14 (T0, review passthrough-1): tag 10 only at the top level. The
/// trading key signs a transaction that calls another program (the test
/// mock), which CPIs tag 10 with the key's signer privilege: `NotTopLevel`
/// before any Phoenix CPI, nothing moves. The same `trade` at the top level
/// of the same transaction shape works.
#[test]
fn tt14_trade_through_cpi_is_not_top_level() {
    let Some(mock_so) = mock_program_so() else { return };
    let Some(mut env) = Env::new() else { return };
    let mock = Pubkey::new_from_array([0x4d; 32]);
    env.ctx.svm.add_program(mock, &std::fs::read(mock_so).expect("mock .so")).expect("load the mock program");
    env.setup_funded(1_000_000_000);
    let before = env.outside();
    let take = env.ticks_for("SOL", 151_000);
    let inner = env.ioc_ix("SOL", 0, false, take, 1);
    let mut accounts = vec![AccountMeta::new_readonly(env.program, false)];
    accounts.extend(inner.accounts.iter().cloned());
    let mut data = b"SJKCALL\0".to_vec();
    data.extend_from_slice(&inner.data);
    let outer = Instruction { program_id: mock, accounts, data };
    env.refuse(outer, "NotTopLevel", "tag 10 called by another program");
    assert_eq!(env.position("SOL"), 0);
    assert_eq!(env.outside(), before, "INV-9");
    ok(env.send1(inner, S_BOT), "the same IOC at the top level");
    assert_eq!(env.position("SOL"), 1);
}
