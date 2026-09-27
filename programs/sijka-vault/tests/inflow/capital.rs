// Copyright (c) 2026 prt1sn. All rights reserved.
//! The capital rule (DECISIONS §2.2, SPEC §5.3): everything that reaches
//! `deposit_usdc` is capital `I` — fees and donations alike, SOL, USDC or
//! PhUSD, on the SOL pair and on the USDC pair — and `I` changes only in tag
//! 21, by exactly what reached Phoenix. Nothing on these paths is profit.

use crate::deposit::{USDC, deposit, donate_phusd};
use crate::harness::*;
use crate::route::*;
use crate::swap::{SOL, fund_fee_inbox, honest, run};
use crate::sweep::sweep;

fn profit_counters(env: &Env) -> [u64; 5] {
    [
        env.cfg("cum_payout_usdc"),
        env.cfg("cum_payout_creator"),
        env.cfg("cum_payout_buyback"),
        env.cfg("harvest_count"),
        env.cfg("last_harvest_amount"),
    ]
}

#[test]
fn every_donation_becomes_capital_sol_pair() {
    let Some(mut env) = Env::new(Opts { trader: true, ..Opts::default() }) else { return };
    let k = env.k.clone();
    // Launch script: R on fee_inbox; then pump fees (2 SOL) and a SOL
    // donation (0.5 SOL) both land on fee_inbox.
    fund_fee_inbox(&mut env, 0);
    env.transfer_lamports(&k.fee_inbox, 2 * SOL);
    env.transfer_lamports(&k.fee_inbox, SOL / 2);
    // A donation of lamports straight to swap_wsol (pending wSOL).
    env.transfer_lamports(&k.swap_wsol, SOL / 4);
    let (s, out_sol) = honest(&env, Kind::RouteV2, 11 * SOL / 4);
    let m = expect_ok(run(&mut env, &s));
    assert_eq!(event(&m.logs, "SJKEVSWI").u("topup"), 5 * SOL / 2);
    assert_eq!(env.cfg("cum_inflow_usdc"), 0, "tag 20 never writes I");
    // USDC donations: to vault_usdc directly, to swap_usdc (tag 23), to a USDC
    // account of fee_inbox (tag 22); a PhUSD donation to vault_phusd.
    env.mint_usdc(k.vault_usdc, 7 * USDC);
    env.mint_usdc(k.swap_usdc, 3 * USDC);
    expect_ok(sweep(&mut env, 23, k.swap_usdc));
    let fi_usdc = env.create_ata(&k.fee_inbox, &k.usdc_mint);
    env.mint_usdc(fi_usdc, 4 * USDC);
    expect_ok(sweep(&mut env, 22, fi_usdc));
    donate_phusd(&mut env, k.vault_phusd, 2 * USDC);
    let before = profit_counters(&env);
    let c0 = env.trader_collateral();
    let m = expect_ok(deposit(&mut env, 0));
    let total = out_sol + 7 * USDC + 3 * USDC + 4 * USDC + 2 * USDC;
    let e = event(&m.logs, "SJKEVDEP");
    assert_eq!(e.u("deposited"), total);
    assert_eq!(e.u("phusd_direct"), 2 * USDC);
    assert_eq!(env.cfg("cum_inflow_usdc"), total);
    assert_eq!(env.cfg("cum_ember_wrapped"), total - 2 * USDC);
    assert_eq!(env.cfg("cum_phusd_direct"), 2 * USDC);
    assert_eq!(env.cfg("cum_swap_usdc_received"), out_sol);
    assert_eq!(env.cfg("cum_swap_usdc_swept"), 3 * USDC);
    assert_eq!(env.cfg("cum_fee_usdc_swept"), 4 * USDC);
    assert_eq!(env.trader_collateral() - c0, total as i64);
    assert_eq!(profit_counters(&env), before, "no profit / payout on inflow paths");
    assert_eq!(env.token_amount(&k.vault_usdc), 0);
    assert_eq!(env.token_amount(&k.vault_phusd), 0);
    assert_eq!(env.token_amount(&k.swap_usdc), 0);
}

#[test]
fn usdc_pair_fee_path() {
    let Some(mut env) = Env::new(Opts { usdc_pair: true, trader: true, ..Opts::default() }) else { return };
    let k = env.k.clone();
    assert_eq!(env.cfg_key("quote_mint"), k.usdc_mint);
    fund_fee_inbox(&mut env, 0);
    // pump pays creator fees in USDC to ATA(fee_inbox, USDC)
    // (`distribute_creator_fees_v2(initialize_ata = true)`).
    let fi_usdc = env.create_ata(&k.fee_inbox, &k.usdc_mint);
    env.mint_usdc(fi_usdc, 50 * USDC);
    expect_ok(sweep(&mut env, 22, fi_usdc));
    // SOL donations to fee_inbox still go through tag 20 on the USDC pair.
    env.transfer_lamports(&k.fee_inbox, SOL);
    let (s, out) = honest(&env, Kind::SharedV2, SOL);
    expect_ok(run(&mut env, &s));
    let m = expect_ok(deposit(&mut env, 0));
    assert_eq!(event(&m.logs, "SJKEVDEP").u("deposited"), 50 * USDC + out);
    assert_eq!(env.cfg("cum_inflow_usdc"), 50 * USDC + out);
    assert_eq!(env.cfg("cum_fee_usdc_swept"), 50 * USDC);
}

#[test]
fn capital_only_at_deposit() {
    let Some(mut env) = Env::new(Opts { trader: true, ..Opts::default() }) else { return };
    let k = env.k.clone();
    fund_fee_inbox(&mut env, 3 * SOL);
    for _ in 0..3 {
        let (s, _) = honest(&env, Kind::Route, SOL);
        expect_ok(run(&mut env, &s));
        assert_eq!(env.cfg("cum_inflow_usdc"), 0);
    }
    let received = env.cfg("cum_swap_usdc_received");
    assert_eq!(env.token_amount(&k.vault_usdc), received);
    // Deposit in two capped steps; I tracks each exactly.
    let half = received / 2;
    expect_ok(deposit(&mut env, half));
    assert_eq!(env.cfg("cum_inflow_usdc"), half);
    expect_ok(deposit(&mut env, 0));
    assert_eq!(env.cfg("cum_inflow_usdc"), received);
    assert_eq!(env.cfg("inflow_count"), 2);
}
