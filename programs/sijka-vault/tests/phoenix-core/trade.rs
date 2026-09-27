// Copyright (c) 2026 prt1sn. All rights reserved.
//! Tag 10 `trade` on the mainnet Phoenix binary and tag 3 `set_trader`
//! (SPEC v3 §5.1.3, §5.2, §9.4 TT-1…TT-9, TA-11; DECISIONS §19): the trading
//! key trades through the program, which forwards only the 14 Phoenix
//! trading instructions for our trader account `T` signed by `phx_authority`;
//! withdrawals, collateral transfers and delegation are refused before any
//! CPI; every account rule of §5.2.3 holds on the real runtime; nothing
//! outside Phoenix moves (INV-9). Every allowlisted instruction one by one:
//! `trade_allowed.rs`; every other Phoenix instruction, account substitution
//! and the delegate-bypass regression: `trade_denied.rs`.

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::abi;
use crate::harness::*;
use crate::phx_trade::*;

/// TT-1 (U-1, U-2): IOC, resting limit and cancel through tag 10 on the
/// real binary; Phoenix sees `phx_authority` as signer at depth 2; the
/// return data of the order instructions is Phoenix's own
/// `MatchingEngineCPIResponse` (64 bytes), cancels leave none (§5.2.4); no
/// balance outside Phoenix moves and the trader header keeps its authorities
/// (INV-9).
#[test]
fn tt1_orders_and_cancels_through_tag_10() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(1_000_000_000);
    assert_eq!(env.cfg_key("trader"), env.bot);
    let before = env.outside();
    assert_eq!(before.position_authority, env.pdas.phx_authority.0, "no delegate");

    let px = env.ticks_for("SOL", 151_000);
    let m = ok(env.send1(env.ioc_ix("SOL", 0, false, px, 10), S_BOT), "IOC buy through tag 10");
    eprintln!("TT-12: IOC through tag 10 CU = {}", m.compute_units_consumed);
    assert!(log_contains(&m.logs, &format!("Program {PHOENIX} invoke [2]")), "Phoenix called by the program");
    assert_eq!(m.return_data.program_id, PHOENIX, "return data is Phoenix's");
    assert_eq!(m.return_data.data.len(), 64, "MatchingEngineCPIResponse");
    let sol = env.pam_entry("SOL").asset_id;
    let h = env.our_trader();
    assert!(h.positions.iter().any(|(a, b)| (*a as u32) == sol && *b == 10), "position +10: {:?}", h.positions);

    let px = env.ticks_for("SOL", 140_000);
    let m = ok(env.send1(env.post_only_ix("SOL", 0, px, 5), S_BOT), "resting bid through tag 10");
    assert_eq!(m.return_data.program_id, PHOENIX);
    assert_eq!(m.return_data.data.len(), 64);
    let m = ok(env.send1(env.cancel_all_ix("SOL"), S_BOT), "CancelAll through tag 10");
    assert!(m.return_data.data.is_empty(), "CancelAll sets no return data");
    // No event of our own (T12).
    assert!(events(&m.logs, "SJKEVTRD").is_empty());

    // Other markets, any size far from the mark (no market list, no band).
    for sym in ["BTC", "ETH"] {
        let px = env.ticks_for(sym, env.mark_usd_milli(sym) / 2);
        let r = env.send1(env.post_only_ix(sym, 0, px, 1), S_BOT);
        ok_or_foreign(r, &format!("TT-1: resting bid on {sym} at half the mark"));
    }
    let after = env.outside();
    assert_eq!(after, before, "INV-9: nothing outside Phoenix moved");
}

/// TT-2: withdraw, collateral transfer and delegation are refused by the
/// allowlist before any CPI, whatever the accounts; sent directly to
/// Phoenix by the trading key they fail in Phoenix (the key is neither
/// authority nor position authority); nothing moves.
#[test]
fn tt2_money_movers_are_not_allowed() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(1_000_000_000);
    let before = env.outside();
    let c0 = env.our_trader().collateral;
    let (bot, phusd, phx) = (env.bot, env.fx.phusd, env.pdas.phx_authority.0);
    let bot_phusd = env.create_ata(&bot, &phusd, &SPL_TOKEN);
    let taker = env.ctx.actor_trader("taker0");
    let (attacker, t) = (env.attacker, env.pdas.trader.0);
    let cases: Vec<(&str, Instruction)> = vec![
        ("WithdrawFunds", env.phx_withdraw_ix(&phx, &bot_phusd, 1_000_000)),
        ("TransferCollateral", env.phx_transfer_out_ix(&phx, &taker, 1_000_000)),
        ("DelegateTrader", env.phx_delegate_ix(&phx, &t, &attacker)),
    ];
    for (label, phx_ix) in cases {
        let ix = env.trade_ix(phx_ix);
        let e = expect_err(env.send1(ix, S_BOT), "TradeInstructionNotAllowed", label);
        assert!(!log_contains(&e.meta.logs, &format!("Program {PHOENIX} invoke")), "{label}: no CPI");
    }
    // Directly on Phoenix, signed by the trading key: refused by Phoenix.
    let ix = env.phx_withdraw_ix(&bot, &bot_phusd, 1_000_000);
    expect_foreign_err(env.send1(ix, S_BOT), "withdraw_funds by the trading key");
    let ix = env.phx_transfer_out_ix(&bot, &taker, 1_000_000);
    expect_foreign_err(env.send1(ix, S_BOT), "TransferCollateral by the trading key");
    let ix = env.phx_delegate_ix(&bot, &t, &attacker);
    expect_foreign_err(env.send1(ix, S_BOT), "DelegateTrader by the trading key");
    let ix = env.phx_ioc_ix(&bot, "SOL", 0, false, env.ticks_for("SOL", 151_000), 1);
    expect_foreign_err(env.send1(ix, S_BOT), "IOC by the trading key without tag 10");
    // Short data and an unknown discriminator.
    let mut ix = env.ioc_ix("SOL", 0, false, 1, 1);
    ix.data.truncate(8);
    expect_err(env.send1(ix, S_BOT), "TradeInstructionNotAllowed", "8 bytes");
    let mut ix = env.ioc_ix("SOL", 0, false, 1, 1);
    ix.data[1..9].copy_from_slice(&disc("global:swap_native"));
    expect_err(env.send1(ix, S_BOT), "TradeInstructionNotAllowed", "SwapNative discriminator");

    assert_eq!(env.token_amount(&bot_phusd), 0, "nothing reached the key");
    assert_eq!(env.our_trader().collateral, c0, "collateral unchanged");
    assert_eq!(env.outside(), before, "INV-9");
}

/// TT-3, TT-5, TT-6, TT-9: account rules on the real runtime.
#[test]
fn tt3_tt6_account_rules() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(1_000_000_000);
    let px = env.ticks_for("SOL", 140_000);
    let base = env.post_only_ix("SOL", 0, px, 1);
    let p = |i: usize| 3 + i;

    // TT-3: P[0] not Phoenix; log authority / GlobalConfig replaced.
    for (slot, key) in
        [(p(0), SPL_TOKEN), (p(0), env.program), (p(1), Pubkey::new_unique()), (p(2), Pubkey::new_unique())]
    {
        let mut ix = base.clone();
        ix.accounts[slot].pubkey = key;
        expect_err(env.send1(ix, S_BOT), "InvalidTradeAccounts", &format!("slot {slot} = {key}"));
    }
    // TT-4: another trader account in the TR slot.
    let mut ix = base.clone();
    ix.accounts[p(4)].pubkey = env.ctx.actor_trader("taker0");
    expect_err(env.send1(ix, S_BOT), "InvalidTradeAccounts", "foreign trader account");
    // TT-5: the reference slot 2; phx_authority twice; missing.
    let mut ix = base.clone();
    ix.accounts[2].pubkey = Pubkey::new_unique();
    expect_err(env.send1(ix, S_BOT), "InvalidPda", "slot 2");
    let mut ix = base.clone();
    ix.accounts.push(AccountMeta::new_readonly(env.pdas.phx_authority.0, false));
    expect_err(env.send1(ix, S_BOT), "InvalidTradeAccounts", "phx_authority twice");
    let mut ix = base.clone();
    ix.accounts[p(3)].pubkey = env.bot;
    expect_err(env.send1(ix, S_BOT), "InvalidTradeAccounts", "no phx_authority in AU");
    // TT-6: our accounts anywhere in P (the tail too).
    let forbidden = [
        env.vault_usdc(),
        env.vault_phusd(),
        env.escrow_usdc(),
        env.buyback_usdc(),
        env.pdas.config.0,
        env.pdas.fee_inbox.0,
        env.pdas.rent_payer.0,
        env.pdas.creator_escrow.0,
        env.pdas.buyback_authority.0,
        env.pdas.swap_authority.0,
    ];
    // Read-only in the tail: a writable `config` would also make slot 1
    // writable in the message (AccountMustBeReadonly first).
    for k in forbidden {
        let mut ix = base.clone();
        ix.accounts.push(AccountMeta::new_readonly(k, false));
        expect_err(env.send1(ix, S_BOT), "ForbiddenTradeAccount", &format!("{k} in the tail"));
    }
    for program in [SPL_TOKEN, TOKEN_2022, ATA_PROGRAM, env.program] {
        let mut ix = base.clone();
        ix.accounts.push(AccountMeta::new_readonly(program, false));
        expect_err(env.send1(ix, S_BOT), "ForbiddenTradeAccount", &format!("program {program} in the tail"));
    }
    // TT-9: config must be read-only; a writable phx_authority is downgraded.
    let mut ix = base.clone();
    ix.accounts[1].is_writable = true;
    expect_err(env.send1(ix, S_BOT), "AccountMustBeReadonly", "config writable");
    let mut ix = base.clone();
    ix.accounts[2].is_writable = true;
    ix.accounts[p(3)].is_writable = true;
    ok(env.send1(ix, S_BOT), "writable phx_authority outside: still a read-only signer in the CPI");
    // Trailing extra accounts Phoenix ignores are fine (n ≤ 27).
    let mut ix = base.clone();
    ix.accounts.push(AccountMeta::new_readonly(SYSTEM_PROGRAM, false));
    ok(env.send1(ix, S_BOT), "System program in the tail");
    ok(env.send1(env.cancel_all_ix("SOL"), S_BOT), "cancel_all");
}

/// TA-11, TT-7: `set_trader` rotates the only signer of tag 10 at once; 0
/// turns trading off; program PDAs and strangers are refused; the retired
/// tags stay unknown.
#[test]
fn ta11_tt7_set_trader_and_the_signer() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(1_000_000_000);
    let bot2 = env.ctx.add_signer(S_BOT2, 10_000_000_000);
    let px = env.ticks_for("SOL", 151_000);

    // TT-7: strangers, the admin and an unsigned trader slot.
    let attacker = env.attacker;
    let ix = env.ioc_ix_as(&attacker, "SOL", 0, false, px, 1);
    expect_err(env.send1(ix, S_ATTACKER), "UnauthorizedTrader", "attacker");
    let admin = env.admin;
    let ix = env.ioc_ix_as(&admin, "SOL", 0, false, px, 1);
    expect_err(env.send1(ix, S_ADMIN), "UnauthorizedTrader", "admin is not the trading key");
    let mut ix = env.ioc_ix("SOL", 0, false, px, 1);
    ix.accounts[0].is_signer = false;
    expect_err(env.send1(ix, S_PAYER), "UnauthorizedTrader", "trading key did not sign");

    // TA-11: the admin rotates the key.
    let ix = env.set_trader_ix(&attacker, &attacker);
    expect_err(env.send1(ix, S_ATTACKER), "Unauthorized", "attacker sets the key");
    for k in env.pdas.program_pdas() {
        expect_err(env.set_trader(&k), "InvalidParams", "program PDA as the trading key");
    }
    let (_, ts) = env.clock();
    let m = ok(env.set_trader(&bot2), "rotate to bot2");
    eprintln!("set_trader CU = {}", m.compute_units_consumed);
    let ev = one_event(&m.logs, "SJKEVTRD");
    let e = abi::event("SJKEVTRD");
    assert_eq!(ev.len(), 81);
    assert_eq!(e.i64(&ev, "ts"), ts);
    assert_eq!(key_of(e.key(&ev, "old")), env.bot);
    assert_eq!(key_of(e.key(&ev, "new")), bot2);
    assert_eq!(env.cfg_key("trader"), bot2);
    assert_eq!(env.cfg_i64("last_admin_action_ts"), ts);
    assert_eq!(env.our_trader().position_authority, env.pdas.phx_authority.0, "Phoenix header untouched");
    expect_err(env.send1(env.ioc_ix("SOL", 0, false, px, 1), S_BOT), "UnauthorizedTrader", "old key");
    let ix = env.ioc_ix_as(&bot2, "SOL", 0, false, px, 1);
    ok(env.send1(ix, S_BOT2), "new key trades");

    // 0: trading off for everyone.
    let m = ok(env.set_trader(&Pubkey::default()), "trading off");
    let ev = one_event(&m.logs, "SJKEVTRD");
    assert_eq!(key_of(e.key(&ev, "new")), Pubkey::default());
    let ix = env.ioc_ix_as(&bot2, "SOL", 0, false, px, 1);
    expect_err(env.send1(ix, S_BOT2), "UnauthorizedTrader", "trader = 0");
    let bot = env.bot;
    ok(env.set_trader(&bot), "back to bot");

    // Retired tags are unknown.
    for tag in [4u8, 5, 6, 9, 11, 12, 13, 14, 15, 16] {
        let mut ix = env.set_trader_ix(&admin, &bot2);
        ix.data[0] = tag;
        expect_err(env.send1(ix, S_ADMIN), "UnknownInstruction", &format!("retired tag {tag}"));
    }
}

/// TT-7: the trading key before the trader account is registered.
#[test]
fn tt7_trade_before_registration() {
    let Some(mut env) = Env::new() else { return };
    env.initialize();
    let bot = env.bot;
    ok(env.set_trader(&bot), "set_trader before register");
    let px = env.ticks_for("SOL", 151_000);
    expect_err(env.send1(env.ioc_ix("SOL", 0, false, px, 1), S_BOT), "TraderNotRegistered", "not registered");
}
