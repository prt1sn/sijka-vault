// Copyright (c) 2026 prt1sn. All rights reserved.
//! Tag 2 `register_phoenix_trader` through the mainnet Phoenix binary
//! (SPEC §5.1.2; TA-5…TA-9; U-3, U-4, U-5, U-10), the onboarder activation
//! (`SetTraderCapabilitiesDelegated` with a Phoenix permission account, the
//! path of `send-register-ixs`), and cold to hot through orders of the trading
//! key sent through tag 10 `trade` (SPEC v3).

use solana_instruction::AccountMeta;
use solana_pubkey::Pubkey;

use crate::abi;
use crate::harness::*;
use crate::phx::*;

const DISC_TRADER: [u8; 8] = [0x29, 0x61, 0x49, 0x69, 0x6e, 0xd6, 0x70, 0x09];

#[test]
fn register_gated_prefs_0b11_rent_payer_pda() {
    let Some(mut env) = Env::new() else { return };
    env.set_gated();
    env.initialize();
    let need = env.rent_payer_need();
    env.fund_rent_payer(need);
    let (_, ts) = env.clock();
    let m = ok(env.send1(env.register_ix(), S_ADMIN), "register_phoenix_trader");
    eprintln!("U-10: register_phoenix_trader CU = {}", m.compute_units_consumed);
    assert!(log_contains(&m.logs, &format!("Program {PHOENIX} invoke")), "Phoenix CPI happened");

    let t = env.pdas.trader.0;
    let h = env.our_trader();
    assert_eq!(env.owner(&t), Some(PHOENIX));
    assert_eq!(h.disc, DISC_TRADER, "trader discriminator");
    assert_eq!(h.trader_key, t);
    assert_eq!(h.authority, env.pdas.phx_authority.0, "authority = phx_authority");
    assert_eq!(h.position_authority, env.pdas.phx_authority.0, "position_authority = phx_authority");
    assert_eq!((h.pda_index, h.sub_index), (0, 0));
    // U-3: RegisterTrader accepts prefs 0b11 and 128 positions for (0, 0); the bits stick.
    assert_eq!(h.prefs, 0b11, "U-3: trader_preference_bits");
    assert_eq!(h.max_positions, 128, "U-3: max_positions");
    assert_eq!(h.cap, 128, "position map capacity");
    assert_eq!(env.data(&t).len(), 5360, "trader account length at cap 128");
    // U-4: the PDA payer created the account and is its funding key.
    assert_eq!(h.funding_key, env.pdas.rent_payer.0, "U-4: funding_key == rent_payer");
    assert_eq!(env.lamports(&env.pdas.rent_payer.0), env.rent(0), "rent_payer keeps exactly rent(0)");
    assert_eq!(env.lamports(&t), env.rent(5360));
    eprintln!("gated RegisterTrader flags = {} (exchange status {:#010b})", h.flags, env.exchange_status());
    assert_eq!(h.flags, FLAGS_FROZEN, "gated registration leaves the trader frozen (limit + market only)");

    // Config (SPEC §5.1.2 step 5).
    let c = abi::config();
    let d = env.config();
    assert_eq!(env.cfg_key("phoenix_trader"), t);
    assert_eq!(c.u8(&d, "phoenix_trader_bump"), env.pdas.trader.1);
    assert_eq!(c.u32(&d, "trader_preference_bits"), 0b11);
    assert_eq!(c.u32(&d, "trader_max_positions"), 128);
    assert_eq!(c.u8(&d, "trader_registered_by_program"), 1);
    assert_eq!(c.i64(&d, "trader_registered_ts"), ts);
    assert_eq!(c.i64(&d, "last_admin_action_ts"), ts);

    // Event SJKEVREG.
    let ev = one_event(&m.logs, "SJKEVREG");
    let e = abi::event("SJKEVREG");
    assert_eq!(key_of(e.key(&ev, "phoenix_trader")), t);
    assert_eq!(e.u32(&ev, "prefs"), 0b11);
    assert_eq!(e.u32(&ev, "max_positions"), 128);
    assert_eq!(e.u8(&ev, "created_by_program"), 1);
    assert_eq!(key_of(e.key(&ev, "funding_key")), env.pdas.rent_payer.0);
    assert_eq!(e.u32(&ev, "flags"), h.flags);

    // Repeat and non-admin.
    expect_err(env.send1(env.register_ix(), S_ADMIN), "TraderAlreadyRegistered", "second registration");
    let ix = env.register_ix_with(&env.attacker, &t, env.pdas.trader.1);
    expect_err(env.send1(ix, S_ATTACKER), "Unauthorized", "attacker as admin");
}

#[test]
fn register_account_checks_and_rent_boundary() {
    let Some(mut env) = Env::new() else { return };
    env.initialize();
    let need = env.rent_payer_need();
    // TA-8: one lamport short.
    env.fund_rent_payer(need - 1);
    expect_err(env.send1(env.register_ix(), S_ADMIN), "RentPayerUnderfunded", "rent(5360) + rent(0) - 1");

    let t = env.pdas.trader.0;
    let bump = env.pdas.trader.1;
    // TA-6: wrong bump / someone else's trader account.
    let other_bump = (0u8..=255)
        .rev()
        .find(|b| {
            *b != bump
                && Pubkey::create_program_address(
                    &[b"trader", env.pdas.phx_authority.0.as_ref(), &[0, 0], &[*b]],
                    &PHOENIX,
                )
                .is_ok()
        })
        .unwrap();
    let ix = env.register_ix_with(&env.admin, &t, other_bump);
    expect_err(env.send1(ix, S_ADMIN), "InvalidPhoenixTraderPda", "wrong bump");
    let taker0 = env.ctx.actor_trader("taker0");
    let ix = env.register_ix_with(&env.admin, &taker0, bump);
    expect_err(env.send1(ix, S_ADMIN), "InvalidPhoenixTraderPda", "another trader account");
    // Other slots.
    let base = env.register_ix();
    for (slot, key, e) in [
        (2usize, env.pdas.rent_payer.0, "InvalidPda"),
        (3, env.pdas.fee_inbox.0, "InvalidPda"),
        (4, HAWKEYE, "InvalidProgramId"),
        (5, Pubkey::new_unique(), "InvalidExternalAccount"),
        (6, Pubkey::new_unique(), "InvalidPhoenixGlobalConfig"),
        (8, SPL_TOKEN, "InvalidProgramId"),
    ] {
        let mut ix = base.clone();
        ix.accounts[slot].pubkey = key;
        expect_err(env.send1(ix, S_ADMIN), e, &format!("register slot #{slot}"));
    }
    let mut ix = base.clone();
    ix.accounts[3] = AccountMeta::new_readonly(env.pdas.rent_payer.0, false);
    expect_err(env.send1(ix, S_ADMIN), "AccountNotWritable", "rent_payer readonly");
    assert!(!env.exists(&t), "no trader created by rejected calls");

    // Top up the last lamport: registration passes.
    env.fund_rent_payer(1);
    ok(env.send1(env.register_ix(), S_ADMIN), "register after top-up");
    assert_eq!(env.our_trader().prefs, 0b11);
}

/// TA-7: somebody registers `(phx_authority, 0, 0)` directly with prefs 0 and
/// their own funding key before tag 2. The program accepts the account and
/// records what it found (SPEC §5.1.2 step 3).
#[test]
fn register_front_run_direct_registration() {
    let Some(mut env) = Env::new() else { return };
    env.initialize();
    let ix = env.register_direct_ix(&env.attacker, &env.pdas.phx_authority.0, 0, 128);
    ok(env.send1(ix, S_ATTACKER), "front-runner RegisterTrader");
    let h = env.our_trader();
    assert_eq!(h.funding_key, env.attacker);
    assert_eq!(h.prefs, 0);
    // rent_payer is not even funded: no CPI in this path.
    let m = ok(env.send1(env.register_ix(), S_ADMIN), "register after front-run");
    assert!(!log_contains(&m.logs, &format!("Program {PHOENIX} invoke")), "no Phoenix CPI");
    let d = env.config();
    let c = abi::config();
    assert_eq!(env.cfg_key("phoenix_trader"), env.pdas.trader.0);
    assert_eq!(c.u8(&d, "trader_registered_by_program"), 0);
    assert_eq!(c.u32(&d, "trader_preference_bits"), 0, "actual prefs recorded");
    assert_eq!(c.u32(&d, "trader_max_positions"), 128);
    let ev = one_event(&m.logs, "SJKEVREG");
    assert_eq!(abi::event("SJKEVREG").u8(&ev, "created_by_program"), 0);
    assert_eq!(key_of(abi::event("SJKEVREG").key(&ev, "funding_key")), env.attacker);
}

/// Front-runner registers `(A,0,0)` with other positions / prefs. The
/// mainnet Phoenix binary accepts the request but stores at least 32
/// positions for `(0,0)` (1 → 32): a front-runner can lower the capacity to
/// 32, not below (SPEC §2.3 "для (0,0) допустимо 32..=128"). Tag 2 records
/// what it found (SPEC §5.1.2 step 3).
#[test]
fn register_front_run_other_max_positions() {
    for (prefs, requested, stored) in [(1u32, 32u32, 32u32), (0, 1, 32), (2, 64, 64)] {
        let Some(mut env) = Env::new() else { return };
        env.initialize();
        let ix = env.register_direct_ix(&env.attacker, &env.pdas.phx_authority.0, prefs, requested);
        let r = env.send1(ix, S_ATTACKER);
        eprintln!("Phoenix RegisterTrader (A,0,0) prefs {prefs} max_positions {requested}: accepted = {}", r.is_ok());
        ok(r, "front-runner RegisterTrader");
        let h = env.our_trader();
        eprintln!("  stored prefs {} max_positions {} cap {}", h.prefs, h.max_positions, h.cap);
        assert_eq!((h.prefs, h.max_positions), (prefs, stored));
        ok(env.send1(env.register_ix(), S_ADMIN), "register after front-run");
        let d = env.config();
        assert_eq!(abi::config().u32(&d, "trader_max_positions"), stored);
        assert_eq!(abi::config().u32(&d, "trader_preference_bits"), prefs);
        assert_eq!(abi::config().u8(&d, "trader_registered_by_program"), 0);
    }
}

/// U-5: lamports sent to the trader PDA before tag 2 (griefing). A 1-lamport
/// transfer is refused by the runtime (a new system account must be
/// rent-exempt), so the cheapest grief is `rent(0)`; registration must still
/// be possible after it.
#[test]
fn register_after_lamports_prefunded_on_trader_pda() {
    let Some(mut env) = Env::new() else { return };
    env.initialize();
    let t = env.pdas.trader.0;
    let r = env.transfer_lamports(S_ATTACKER, &t, 1);
    let e = r.expect_err("1 lamport to a new account is refused by the runtime");
    assert!(format!("{:?}", e.err).contains("InsufficientFundsForRent"), "{:?}", e.err);
    let grief = env.rent(0);
    ok(env.transfer_lamports(S_ATTACKER, &t, grief), "griefer sends rent(0) to the trader PDA");
    assert_eq!(env.owner(&t), Some(SYSTEM_PROGRAM));
    let need = env.rent_payer_need();
    env.fund_rent_payer(need);
    let r = env.send1(env.register_ix(), S_ADMIN);
    if let Err(e) = &r {
        eprintln!("U-5: tag 2 after a rent(0) prefund failed: {:?}\n{}", e.err, e.meta.logs.join("\n"));
    }
    ok(r, "U-5: register_phoenix_trader after prefund");
    let h = env.our_trader();
    assert_eq!(h.prefs, 0b11);
    assert_eq!(h.funding_key, env.pdas.rent_payer.0);
    assert!(env.lamports(&t) >= env.rent(5360));
}

/// TA-9 and TC-27: activation the way Phoenix's onboarder does it. A local
/// key gets the trader-onboarding permission from the risk authority, then
/// signs `SetTraderCapabilitiesDelegated` for our trader.
#[test]
fn onboarder_activation_unfreezes_trader() {
    let Some(mut env) = Env::new() else { return };
    env.set_deposit_cooldown(0);
    env.set_gated();
    env.initialize();
    env.create_vault_atas();
    let need = env.rent_payer_need();
    env.fund_rent_payer(need);
    ok(env.send1(env.register_ix(), S_ADMIN), "register");
    let t = env.pdas.trader.0;
    assert_eq!(env.our_trader().flags, FLAGS_FROZEN);

    // TC-27: deposit before activation fails in Phoenix; nothing moves.
    let v = env.vault_usdc();
    env.mint_usdc(&v, 50_000_000);
    let r = env.send1(env.deposit_ix(0), S_PAYER);
    let e = expect_foreign_err(r, "deposit on a frozen trader");
    eprintln!("frozen deposit error: {:?}", e.err);
    assert_eq!(env.cfg_u64("cum_inflow_usdc"), 0);
    assert_eq!(env.token_amount(&v), 50_000_000);

    // A key without permission cannot activate.
    let ix = env.onboard_ix(&env.attacker, &t);
    expect_foreign_err(env.send1(ix, S_ATTACKER), "activation without permission");
    // A permission without the onboarding bit cannot either.
    let attacker = env.attacker;
    ok(env.grant_permission(&attacker, 1), "permission bit 0 only");
    let ix = env.onboard_ix(&attacker, &t);
    expect_foreign_err(env.send1(ix, S_ATTACKER), "activation with a non-onboarding permission");
    assert_eq!(env.our_trader().flags, FLAGS_FROZEN);

    env.activate_our_trader();
    let h = env.our_trader();
    assert_eq!(h.flags, FLAGS_COLD, "all capabilities, cold");
    assert_eq!(h.prefs, 0b11, "activation keeps the preference bits");
    ok(env.send1(env.deposit_ix(0), S_PAYER), "deposit after activation");
    assert_eq!(env.cfg_u64("cum_inflow_usdc"), 50_000_000);
}

/// The program does not check Phoenix's activation (SPEC v2/v3). On a gated,
/// not yet activated trader (`flags = 6`) the trading key's risk-increasing
/// order through tag 10 passes our checks and is refused by Phoenix itself.
#[test]
fn frozen_trader_orders_refused_by_phoenix() {
    let Some(mut env) = Env::new() else { return };
    env.set_deposit_cooldown(0);
    env.set_gated();
    env.initialize();
    env.create_vault_atas();
    let need = env.rent_payer_need();
    env.fund_rent_payer(need);
    ok(env.send1(env.register_ix(), S_ADMIN), "register");
    assert_eq!(env.our_trader().flags, FLAGS_FROZEN);
    let bot = env.bot;
    ok(env.set_trader(&bot), "set_trader on a frozen trader");
    assert_eq!(env.our_trader().position_authority, env.pdas.phx_authority.0);
    let t = env.pdas.trader.0;
    let gift = env.actor_gift_collateral("taker0", &t, 100_000_000);
    eprintln!("gift to a frozen trader: ok = {}", gift.is_ok());
    let px = env.ticks_for("SOL", 151_000);
    let r = env.send1(env.ioc_ix("SOL", 0, false, px, 10), S_BOT);
    expect_foreign_err(r, "non-RO IOC of the trading key on a frozen (flags 6) trader");
}

/// Without gating (fixture default) Phoenix registers the trader directly
/// with all capabilities.
#[test]
fn ungated_registration_flags() {
    let Some(mut env) = Env::new() else { return };
    env.initialize();
    let need = env.rent_payer_need();
    env.fund_rent_payer(need);
    ok(env.send1(env.register_ix(), S_ADMIN), "register ungated");
    let h = env.our_trader();
    eprintln!("ungated RegisterTrader flags = {} (exchange status {:#010b})", h.flags, env.exchange_status());
    assert_eq!(h.flags, FLAGS_COLD);
    assert_eq!(h.prefs, 0b11);
}

/// U-1, U-2 (SPEC v3): Phoenix accepts orders and cancels forwarded by tag 10
/// and signed by `phx_authority`; the first resting limit turns the cold
/// account hot, an IOC does not.
#[test]
fn trading_key_signs_orders_and_first_limit_turns_hot() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(1_000_000_000);
    assert_eq!(env.our_trader().flags, FLAGS_COLD);
    assert_eq!(env.our_trader().position_authority, env.pdas.phx_authority.0, "no delegate");

    // IOC buy 10 lots at the fixture ask (150.5): fills, account stays cold.
    let px = env.ticks_for("SOL", 151_000);
    let m = ok(env.send1(env.ioc_ix("SOL", 0, false, px, 10), S_BOT), "IOC buy");
    assert!(log_contains(&m.logs, &format!("Program {} invoke", env.program)), "through sijka-vault");
    assert!(log_contains(&m.logs, &format!("Program {PHOENIX} invoke [2]")), "Phoenix at depth 2");
    let h = env.our_trader();
    assert_eq!(h.flags & FLAG_HOT, 0, "IOC does not activate the hot bit");
    let sol = env.pam_entry("SOL").asset_id;
    assert!(h.positions.iter().any(|(a, b)| (*a as u32) == sol && *b == 10), "position +10 lots: {:?}", h.positions);

    // Limit bid far below the book: rests, account turns hot (U-2).
    let px = env.ticks_for("SOL", 140_000);
    let m = ok(env.send1(env.post_only_ix("SOL", 0, px, 5), S_BOT), "resting bid");
    let h = env.our_trader();
    eprintln!(
        "flags after the first resting order: {} (logs mention activation: {})",
        h.flags,
        log_contains(&m.logs, "activated")
    );
    assert_eq!(h.flags, FLAGS_HOT, "U-2: the first resting order makes the account hot");

    // CancelAll by the trading key.
    ok(env.send1(env.cancel_all_ix("SOL"), S_BOT), "cancel_all");
}
