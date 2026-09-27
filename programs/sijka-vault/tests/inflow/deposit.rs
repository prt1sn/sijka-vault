// Copyright (c) 2026 prt1sn. All rights reserved.
//! Tag 21 `deposit_usdc` on the real Ember and Phoenix binaries (SPEC §5.3.5;
//! TC-23…TC-29, TC-32, TC-33): USDC is wrapped by Ember, PhUSD goes to
//! Phoenix `deposit_funds`, and capital `I` grows by exactly what reached
//! Phoenix.

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use solana_signer::Signer;

use crate::harness::*;

pub const USDC: u64 = 1_000_000;

pub fn deposit_ix(env: &Env, max_amount: u64) -> Instruction {
    let k = &env.k;
    let mut accounts = vec![
        AccountMeta::new(k.config, false),
        AccountMeta::new_readonly(k.phx_authority, false),
        AccountMeta::new(k.vault_usdc, false),
        AccountMeta::new(k.vault_phusd, false),
        AccountMeta::new_readonly(k.usdc_mint, false),
        AccountMeta::new(k.phusd_mint, false),
        AccountMeta::new_readonly(ember_program(), false),
        AccountMeta::new_readonly(ember_state(), false),
        AccountMeta::new(ember_vault(), false),
        AccountMeta::new_readonly(phoenix_program(), false),
        AccountMeta::new_readonly(phoenix_log_authority(), false),
        AccountMeta::new(phoenix_global_config(), false),
        AccountMeta::new(k.phoenix_trader, false),
        AccountMeta::new(env.global_vault, false),
        AccountMeta::new_readonly(token_program(), false),
    ];
    accounts.extend(env.gti.iter().chain(env.atb.iter()).map(|a| AccountMeta::new(*a, false)));
    let mut data = vec![21u8, env.gti.len() as u8, env.atb.len() as u8];
    data.extend_from_slice(&max_amount.to_le_bytes());
    Instruction { program_id: k.program, accounts, data }
}

pub fn deposit(env: &mut Env, max_amount: u64) -> TxResult {
    let ix = deposit_ix(env, max_amount);
    env.send(vec![cu_limit(400_000), ix], &[])
}

/// Real PhUSD: the keeper wraps its own USDC with Ember (as the fixture actors
/// do) and transfers the PhUSD to `to` (a PhUSD donation to the vault).
pub fn donate_phusd(env: &mut Env, to: Pubkey, amount: u64) {
    let keeper = env.keeper.pubkey();
    let (usdc, phusd) = (env.k.usdc_mint, env.k.phusd_mint);
    let ku = env.create_ata(&keeper, &usdc);
    let kp = env.create_ata(&keeper, &phusd);
    env.mint_usdc(ku, amount);
    let mut data = vec![0xf2, 0x23, 0xc6, 0x89, 0x52, 0xe1, 0xf2, 0xb6];
    data.extend_from_slice(&amount.to_le_bytes());
    let wrap = Instruction {
        program_id: ember_program(),
        accounts: vec![
            AccountMeta::new_readonly(keeper, true),
            AccountMeta::new_readonly(ember_state(), false),
            AccountMeta::new_readonly(usdc, false),
            AccountMeta::new(phusd, false),
            AccountMeta::new(ku, false),
            AccountMeta::new(kp, false),
            AccountMeta::new(ember_vault(), false),
            AccountMeta::new_readonly(token_program(), false),
        ],
        data,
    };
    let mut t = vec![3u8];
    t.extend_from_slice(&amount.to_le_bytes());
    let transfer = Instruction {
        program_id: token_program(),
        accounts: vec![
            AccountMeta::new(kp, false),
            AccountMeta::new(to, false),
            AccountMeta::new_readonly(keeper, true),
        ],
        data: t,
    };
    expect_ok(env.send(vec![wrap, transfer], &[]));
}

fn trader_env() -> Option<Env> {
    Env::new(Opts { trader: true, ..Opts::default() })
}

fn last_deposit_slot_of_trader(env: &Env) -> u64 {
    u64_at(&env.account(&env.k.phoenix_trader).unwrap().data, 192)
}

#[test]
fn tc23_usdc_to_phoenix_and_capital() {
    let Some(mut env) = trader_env() else { return };
    let v = env.k.vault_usdc;
    env.mint_usdc(v, 100 * USDC);
    let c0 = env.trader_collateral();
    let gv0 = env.token_amount(&env.global_vault);
    let m = expect_ok(deposit(&mut env, 0));
    assert_eq!(env.token_amount(&env.k.vault_usdc), 0);
    assert_eq!(env.token_amount(&env.k.vault_phusd), 0);
    assert_eq!(env.token_amount(&env.global_vault), gv0 + 100 * USDC);
    let c1 = env.trader_collateral();
    eprintln!("tc23: collateral {c0} → {c1} (Δ {}) for 100 USDC", c1 - c0);
    assert_eq!(c1 - c0, (100 * USDC) as i64, "fixture: 1 quote lot = 1 atom, Δcollateral = dep");
    assert_eq!(env.cfg("cum_inflow_usdc"), 100 * USDC);
    assert_eq!(env.cfg("inflow_count"), 1);
    assert_eq!(env.cfg("cum_ember_wrapped"), 100 * USDC);
    assert_eq!(env.cfg("cum_ember_wrap_fees"), 0);
    assert_eq!(env.cfg("cum_phusd_direct"), 0);
    assert_eq!(env.cfg("last_deposit_slot"), env.slot());
    assert_eq!(env.cfg("last_deposit_amount"), 100 * USDC);
    // Nothing counts as profit or payout.
    assert_eq!(env.cfg("cum_payout_usdc"), 0);
    assert_eq!(env.cfg("harvest_count"), 0);
    // Phoenix wrote last_deposit_slot@192 (U-53 control).
    assert_eq!(last_deposit_slot_of_trader(&env), env.slot());
    let e = event(&m.logs, "SJKEVDEP");
    assert_eq!(e.u("usdc_wrapped"), 100 * USDC);
    assert_eq!(e.u("phusd_direct"), 0);
    assert_eq!(e.u("deposited"), 100 * USDC);
    assert_eq!(e.u("I_after"), 100 * USDC);
    assert_eq!(e.i("collateral_before"), c0);
    assert_eq!(e.i("collateral_after"), c1);
    assert_eq!(e.u("deposit_count"), 1);
    assert_eq!(e.u("ember_fee"), 0);
    assert_eq!(e.u("max_amount"), 0);
    // A second deposit accumulates.
    env.mint_usdc(v, 3 * USDC);
    expect_ok(deposit(&mut env, 0));
    assert_eq!(env.cfg("cum_inflow_usdc"), 103 * USDC);
    assert_eq!(env.cfg("inflow_count"), 2);
}

#[test]
fn tc24_phusd_direct_and_mixed() {
    let Some(mut env) = trader_env() else { return };
    let (vu, vp) = (env.k.vault_usdc, env.k.vault_phusd);
    donate_phusd(&mut env, vp, 5 * USDC);
    env.mint_usdc(vu, 10 * USDC);
    let m = expect_ok(deposit(&mut env, 0));
    let e = event(&m.logs, "SJKEVDEP");
    assert_eq!(e.u("deposited"), 15 * USDC);
    assert_eq!(e.u("usdc_wrapped"), 10 * USDC);
    assert_eq!(e.u("phusd_direct"), 5 * USDC);
    assert_eq!(env.cfg("cum_inflow_usdc"), 15 * USDC);
    assert_eq!(env.cfg("cum_phusd_direct"), 5 * USDC);
    // Only PhUSD: Ember is not called.
    donate_phusd(&mut env, vp, 2 * USDC);
    let m = expect_ok(deposit(&mut env, 0));
    assert!(
        !m.logs.iter().any(|l| l.contains(&format!("Program {} invoke", ember_program()))),
        "Ember must not be called without USDC"
    );
    assert_eq!(event(&m.logs, "SJKEVDEP").u("usdc_wrapped"), 0);
    assert_eq!(env.cfg("cum_inflow_usdc"), 17 * USDC);
    assert_eq!(env.cfg("cum_phusd_direct"), 7 * USDC);
}

#[test]
fn tc25_below_minimum() {
    let Some(mut env) = trader_env() else { return };
    let v = env.k.vault_usdc;
    expect_err(deposit(&mut env, 0), "DepositNothing");
    env.mint_usdc(v, DEPOSIT_MIN - 1);
    expect_err(deposit(&mut env, 0), "DepositNothing");
    env.mint_usdc(v, 1);
    expect_ok(deposit(&mut env, 0));
    assert_eq!(env.cfg("cum_inflow_usdc"), DEPOSIT_MIN);
}

#[test]
fn tc26_foreign_accounts() {
    let Some(mut env) = trader_env() else { return };
    let v = env.k.vault_usdc;
    env.mint_usdc(v, 10 * USDC);
    let k = env.k.clone();
    let other_trader = env.ctx.actor_trader("taker0");
    let fake = Pubkey::new_from_array([0xE1; 32]);
    let other_usdc = Pubkey::new_from_array([0xE2; 32]);
    env.set_token(other_usdc, k.usdc_mint, k.phx_authority, 10 * USDC, false);
    let cases: Vec<(usize, AccountMeta, &str)> = vec![
        (1, AccountMeta::new_readonly(fake, false), "InvalidPda"),
        (2, AccountMeta::new(other_usdc, false), "InvalidPda"),
        (3, AccountMeta::new(fake, false), "InvalidPda"),
        (4, AccountMeta::new_readonly(k.phusd_mint, false), "InvalidExternalAccount"),
        (5, AccountMeta::new(k.usdc_mint, false), "InvalidPhoenixGlobalConfig"),
        (6, AccountMeta::new_readonly(token_program(), false), "InvalidProgramId"),
        (7, AccountMeta::new_readonly(fake, false), "InvalidEmberAccount"),
        (8, AccountMeta::new(fake, false), "InvalidEmberAccount"),
        (9, AccountMeta::new_readonly(ember_program(), false), "InvalidProgramId"),
        (10, AccountMeta::new_readonly(fake, false), "InvalidExternalAccount"),
        (11, AccountMeta::new(fake, false), "InvalidPhoenixGlobalConfig"),
        (12, AccountMeta::new(other_trader, false), "InvalidPhoenixTraderAccount"),
        (13, AccountMeta::new(fake, false), "InvalidPhoenixGlobalConfig"),
        (14, AccountMeta::new_readonly(token_2022(), false), "InvalidProgramId"),
        (15, AccountMeta::new(fake, false), "InvalidArenaAccounts"),
        (16, AccountMeta::new(fake, false), "InvalidArenaAccounts"),
    ];
    for (i, meta, err) in cases {
        let mut ix = deposit_ix(&env, 0);
        ix.accounts[i] = meta;
        let r = env.send(vec![cu_limit(400_000), ix], &[]);
        assert!(r.is_err(), "slot {i} must fail");
        let s = format!("{:?}", r.as_ref().unwrap_err().err);
        let code = abi().err(err);
        assert!(s.contains(&format!("Custom({code})")), "slot {i}: expected {err}, got {s}");
    }
    assert_eq!(env.cfg("cum_inflow_usdc"), 0);
    // Arena counts outside 1..=8.
    let mut ix = deposit_ix(&env, 0);
    ix.data[1] = 0;
    expect_err(env.send(vec![cu_limit(400_000), ix], &[]), "InvalidArenaAccounts");
    let mut ix = deposit_ix(&env, 0);
    ix.data[2] = 9;
    let r = env.send(vec![cu_limit(400_000), ix], &[]);
    assert!(r.is_err());
    // Writable slots given read-only.
    for i in [2usize, 3, 5, 8, 11, 12, 13] {
        let mut ix = deposit_ix(&env, 0);
        ix.accounts[i].is_writable = false;
        let r = env.send(vec![cu_limit(400_000), ix], &[]);
        assert!(r.is_err(), "read-only slot {i} must fail");
    }
    // The genuine accounts still work.
    expect_ok(deposit(&mut env, 0));
}

#[test]
fn tc26_trader_not_registered() {
    let Some(mut env) = Env::new(Opts::default()) else { return };
    let v = env.k.vault_usdc;
    env.mint_usdc(v, 10 * USDC);
    let r = deposit(&mut env, 0);
    let s = format!("{:?}", r.as_ref().unwrap_err().err);
    let ok = ["TraderNotRegistered", "InvalidPhoenixTraderAccount"]
        .iter()
        .any(|n| s.contains(&format!("Custom({})", abi().err(n))));
    assert!(ok, "deposit before tag 2: {s}");
}

#[test]
fn tc27_trader_without_capabilities() {
    let Some(mut env) = Env::new(Opts { trader: true, capabilities: false, ..Opts::default() }) else { return };
    let v = env.k.vault_usdc;
    env.mint_usdc(v, 10 * USDC);
    let gc = phoenix_global_config();
    let status = env.account(&gc).unwrap().data[504];
    let trader = env.k.phoenix_trader;
    let flags = u32::from_le_bytes(env.account(&trader).unwrap().data[96..100].try_into().unwrap());
    eprintln!("tc27: fixture exchange_status {status:#04x}, trader flags after tag 2: {flags}");
    // The fixture exchange is not gated (0x81) and registration there grants
    // the cold capability set (62). On the gated mainnet exchange (0x83) a
    // new trader stays frozen (flags 0) until activated: reproduce that.
    env.patch(&gc, 504, &[status | 0b10]);
    env.patch(&trader, 96, &0u32.to_le_bytes());
    let f = deposit(&mut env, 0).expect_err("Phoenix refuses a deposit from a frozen trader");
    eprintln!("tc27 frozen: {:?}", f.err);
    let logs = f.meta.logs.join("\n");
    assert!(logs.contains(&format!("Program {} failed", phoenix_program())), "{logs}");
    assert_eq!(env.cfg("cum_inflow_usdc"), 0);
    assert_eq!(env.cfg("inflow_count"), 0);
    assert_eq!(env.token_amount(&v), 10 * USDC, "Ember wrap rolled back too");
    // With the capabilities back (flags 62) the same deposit goes through.
    env.patch(&trader, 96, &flags.to_le_bytes());
    expect_ok(deposit(&mut env, 0));
    assert_eq!(env.cfg("cum_inflow_usdc"), 10 * USDC);
}

#[test]
fn registration_on_the_ungated_fixture_grants_cold_capabilities() {
    // Fixture-only behaviour (not mainnet): without the gate, RegisterTrader
    // leaves flags = 62 (all but HOT) and the deposit works without the
    // delegated activation.
    let Some(mut env) = Env::new(Opts { trader: true, capabilities: false, ..Opts::default() }) else { return };
    let status = env.account(&phoenix_global_config()).unwrap().data[504];
    assert_eq!(status & 0b10, 0, "fixture exchange is not gated");
    let flags = u32::from_le_bytes(env.account(&env.k.phoenix_trader).unwrap().data[96..100].try_into().unwrap());
    assert_eq!(flags, 62);
    let v = env.k.vault_usdc;
    env.mint_usdc(v, 10 * USDC);
    expect_ok(deposit(&mut env, 0));
    assert_eq!(env.cfg("cum_inflow_usdc"), 10 * USDC);
}

#[test]
fn tc28_capital_overflow() {
    let Some(mut env) = trader_env() else { return };
    let v = env.k.vault_usdc;
    env.mint_usdc(v, 10 * USDC);
    env.set_cfg("cum_inflow_usdc", u64::MAX - 5 * USDC);
    expect_err(deposit(&mut env, 0), "MathOverflow");
    // All-or-nothing: the Ember wrap and the Phoenix deposit rolled back.
    assert_eq!(env.token_amount(&v), 10 * USDC);
    assert_eq!(env.token_amount(&env.k.vault_phusd), 0);
    assert_eq!(env.cfg("cum_inflow_usdc"), u64::MAX - 5 * USDC);
}

/// TC-29 (SPEC v4): no inflow pause — the byte of the former
/// `inflow_pause_mask@1152` is not read; CU of a deposit.
#[test]
fn tc29_no_pause_and_cu() {
    let Some(mut env) = trader_env() else { return };
    let v = env.k.vault_usdc;
    env.mint_usdc(v, 10 * USDC);
    env.set_cfg("_reserved10", 3);
    let m = expect_ok(deposit(&mut env, 0));
    let total = consumed_by(&m.logs, &env.k.program).into_iter().max().unwrap();
    let ember = consumed_by(&m.logs, &ember_program()).into_iter().max().unwrap_or(0);
    let phoenix = consumed_by(&m.logs, &phoenix_program()).into_iter().max().unwrap_or(0);
    eprintln!("tc29 CU: vault total {total} (Ember {ember}, Phoenix {phoenix}, own {})", total - ember - phoenix);
    assert!(total <= 80_000, "SPEC §5.3.5 limit 80k: {total}");
}

#[test]
fn tc29_cu_within_60k() {
    let Some(mut env) = trader_env() else { return };
    let v = env.k.vault_usdc;
    env.mint_usdc(v, 10 * USDC);
    let m = expect_ok(deposit(&mut env, 0));
    let total = consumed_by(&m.logs, &env.k.program).into_iter().max().unwrap();
    assert!(total <= 60_000, "TC-29: deposit CU {total} > 60k");
}

#[test]
fn tc32_quiet_window_with_cooldown() {
    let Some(mut env) = trader_env() else { return };
    let v = env.k.vault_usdc;
    env.mint_usdc(v, 10 * USDC);
    // GC@512 = deposit_cooldown_period_in_slots = 1500.
    env.patch(&phoenix_global_config(), 512, &1500u64.to_le_bytes());
    let p = 216_000u64;
    let busy = 1_500 + 9_000;
    // START_SLOT (9 200) < busy: inside the quiet window.
    assert!(env.slot() % p < busy);
    expect_err(deposit(&mut env, 0), "DepositQuietWindow");
    env.warp(p + busy - 1);
    expect_err(deposit(&mut env, 0), "DepositQuietWindow");
    env.warp(p + busy);
    expect_ok(deposit(&mut env, 0));
    assert_eq!(last_deposit_slot_of_trader(&env), p + busy);
    // A GlobalConfig too short to hold @512.
    let mut gc = env.account(&phoenix_global_config()).unwrap();
    gc.data.truncate(519);
    env.set(phoenix_global_config(), gc);
    env.mint_usdc(v, 10 * USDC);
    expect_err(deposit(&mut env, 0), "InvalidPhoenixGlobalConfig");
}

#[test]
fn quiet_window_with_the_fixture_cooldown() {
    // The fixture exchange itself runs with a deposit→withdraw cooldown
    // (`setWithdrawCooldown`, GC@512 = 150): P = 216 000, busy = 9 150.
    let Some(mut env) = trader_env() else { return };
    let cd = u64_at(&env.account(&phoenix_global_config()).unwrap().data, 512);
    assert_eq!(cd, 150, "fixture GC@512");
    let v = env.k.vault_usdc;
    env.mint_usdc(v, 10 * USDC);
    let p = 216_000u64;
    let busy = cd + 9_000;
    for slot in [p, p + busy - 1] {
        env.warp(slot);
        expect_err(deposit(&mut env, 0), "DepositQuietWindow");
    }
    env.warp(p + busy);
    expect_ok(deposit(&mut env, 0));
    // Phoenix then enforces its own cooldown on withdrawals from @192.
    assert_eq!(last_deposit_slot_of_trader(&env), p + busy);
}

#[test]
fn tc33_max_amount_partial() {
    let Some(mut env) = trader_env() else { return };
    let (vu, vp) = (env.k.vault_usdc, env.k.vault_phusd);
    env.mint_usdc(vu, 10 * USDC);
    // Cap 4 USDC: 4 wrapped and deposited, 6 stay.
    let m = expect_ok(deposit(&mut env, 4 * USDC));
    assert_eq!(event(&m.logs, "SJKEVDEP").u("max_amount"), 4 * USDC);
    assert_eq!(env.token_amount(&vu), 6 * USDC);
    assert_eq!(env.cfg("cum_inflow_usdc"), 4 * USDC);
    // 3 PhUSD + 6 USDC, cap 5: PhUSD first, then 2 USDC wrapped.
    donate_phusd(&mut env, vp, 3 * USDC);
    let m = expect_ok(deposit(&mut env, 5 * USDC));
    let e = event(&m.logs, "SJKEVDEP");
    assert_eq!(e.u("usdc_wrapped"), 2 * USDC);
    assert_eq!(e.u("deposited"), 5 * USDC);
    assert_eq!(env.token_amount(&vu), 4 * USDC);
    assert_eq!(env.token_amount(&vp), 0);
    assert_eq!(env.cfg("cum_inflow_usdc"), 9 * USDC);
    // A cap below deposit_min_atoms.
    expect_err(deposit(&mut env, DEPOSIT_MIN - 1), "DepositNothing");
}

#[test]
fn deposit_refused_in_recovery() {
    let Some(mut env) = trader_env() else { return };
    let v = env.k.vault_usdc;
    env.mint_usdc(v, 10 * USDC);
    env.set_cfg("recovery_mode", 1);
    expect_err(deposit(&mut env, 0), "RecoveryActive");
}
