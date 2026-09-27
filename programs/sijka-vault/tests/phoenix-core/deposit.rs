// Copyright (c) 2026 prt1sn. All rights reserved.
//! Tag 21 `deposit_usdc` on the mainnet Ember and Phoenix binaries
//! (SPEC §5.3.5; TC-23…TC-25, TC-29, TC-32; U-38): Ember wrap, `deposit_funds`,
//! `I += dep`, the quiet window and the Phoenix deposit cooldown.

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::abi;
use crate::harness::*;
use crate::phx::*;

impl Env {
    /// PhUSD for `S_ATTACKER` through a real Ember deposit (a donor), then
    /// an SPL transfer of `amount` PhUSD to `dst`.
    pub fn donate_phusd(&mut self, dst: &Pubkey, amount: u64) {
        let donor = self.attacker;
        let (usdc, phusd) = (self.fx.usdc, self.fx.phusd);
        let donor_usdc = ata(&donor, &usdc, &SPL_TOKEN);
        let donor_phusd = ata(&donor, &phusd, &SPL_TOKEN);
        if !self.exists(&donor_usdc) {
            self.create_ata(&donor, &usdc, &SPL_TOKEN);
            self.create_ata(&donor, &phusd, &SPL_TOKEN);
        }
        self.mint_usdc(&donor_usdc, amount);
        let mut data = hex8("f223c68952e1f2b6").to_vec();
        data.extend_from_slice(&amount.to_le_bytes());
        let ix = Instruction {
            program_id: EMBER,
            accounts: vec![
                AccountMeta::new_readonly(donor, true),
                AccountMeta::new_readonly(EMBER_STATE, false),
                AccountMeta::new_readonly(usdc, false),
                AccountMeta::new(phusd, false),
                AccountMeta::new(donor_usdc, false),
                AccountMeta::new(donor_phusd, false),
                AccountMeta::new(EMBER_VAULT, false),
                AccountMeta::new_readonly(SPL_TOKEN, false),
            ],
            data,
        };
        ok(self.send1(ix, S_ATTACKER), "donor Ember deposit");
        ok(self.spl_transfer(&donor_phusd, dst, S_ATTACKER, amount), "PhUSD donation");
    }
}

#[test]
fn deposit_wraps_usdc_and_credits_i() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(0);
    let t = env.pdas.trader.0;
    let (vu, vp) = (env.vault_usdc(), env.vault_phusd());
    assert_eq!(env.our_trader().flags, FLAGS_COLD, "deposit on a cold trader (U-38)");
    let before = env.our_trader();
    let ember_vault0 = env.token_amount(&EMBER_VAULT);
    let global_vault0 = env.token_amount(&env.fx.global_vault);
    let amount = 1_000_000_000u64;
    env.mint_usdc(&vu, amount);
    let (slot, ts) = env.clock();
    let m = ok(env.send1(env.deposit_ix(0), S_PAYER), "deposit_usdc");
    eprintln!("deposit_usdc CU: {}", m.compute_units_consumed);

    assert_eq!(env.token_amount(&vu), 0, "vault_usdc drained");
    assert_eq!(env.token_amount(&vp), 0, "vault_phusd drained");
    assert_eq!(env.token_amount(&EMBER_VAULT), ember_vault0 + amount, "Ember holds the USDC");
    assert_eq!(env.token_amount(&env.fx.global_vault), global_vault0 + amount, "Phoenix holds the PhUSD");
    let after = env.our_trader();
    // U-38: on a cold trader without positions Δcollateral == dep.
    assert_eq!(after.collateral - before.collateral, amount as i64, "U-38: collateral += dep");
    assert_eq!(after.last_deposit_slot, slot, "DepositFunds writes @192 = slot (U-53 writer)");
    assert_eq!(env.cfg_u64("cum_inflow_usdc"), amount, "I += dep");
    assert_eq!(env.cfg_u64("inflow_count"), 1);
    assert_eq!(env.cfg_u64("cum_ember_wrapped"), amount);
    assert_eq!(env.cfg_u64("cum_ember_wrap_fees"), 0, "Ember 1:1");
    assert_eq!(env.cfg_u64("cum_phusd_direct"), 0);
    assert_eq!(env.cfg_u64("last_deposit_slot"), slot);
    assert_eq!(env.cfg_u64("last_deposit_amount"), amount);
    assert_eq!(env.cfg_u64("cum_payout_usdc"), 0, "O untouched");

    let ev = one_event(&m.logs, "SJKEVDEP");
    let e = abi::event("SJKEVDEP");
    assert_eq!(e.i64(&ev, "ts"), ts);
    assert_eq!(e.u64(&ev, "slot"), slot);
    assert_eq!(e.u64(&ev, "usdc_wrapped"), amount);
    assert_eq!(e.u64(&ev, "phusd_direct"), 0);
    assert_eq!(e.u64(&ev, "deposited"), amount);
    assert_eq!(e.u64(&ev, "I_after"), amount);
    assert_eq!(e.i64(&ev, "collateral_before"), before.collateral);
    assert_eq!(e.i64(&ev, "collateral_after"), after.collateral);
    assert_eq!(e.u64(&ev, "deposit_count"), 1);
    assert_eq!(e.u64(&ev, "ember_fee"), 0);
    assert_eq!(e.u64(&ev, "max_amount"), 0);

    // max_amount: partial deposit, the rest stays on vault_usdc.
    env.mint_usdc(&vu, 500_000_000);
    ok(env.send1(env.deposit_ix(200_000_000), S_PAYER), "partial deposit");
    assert_eq!(env.token_amount(&vu), 300_000_000);
    assert_eq!(env.cfg_u64("cum_inflow_usdc"), amount + 200_000_000);
    assert_eq!(env.our_trader().collateral - after.collateral, 200_000_000);

    // TC-25: below deposit_min_atoms (1 USDC) after the remainder is taken.
    ok(env.send1(env.deposit_ix(0), S_PAYER), "rest");
    env.mint_usdc(&vu, 999_999);
    expect_err(env.send1(env.deposit_ix(0), S_PAYER), "DepositNothing", "0.999999 USDC < deposit_min");
    expect_err(env.send1(env.deposit_ix(500_000), S_PAYER), "DepositNothing", "max_amount < deposit_min");
    assert_eq!(env.cfg_u64("cum_inflow_usdc"), 1_500_000_000);
    let _ = t;
}

#[test]
fn deposit_phusd_donation_and_mix() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(0);
    let (vu, vp) = (env.vault_usdc(), env.vault_phusd());
    // TC-24: 5 PhUSD donated + 10 USDC.
    env.donate_phusd(&vp, 5_000_000);
    env.mint_usdc(&vu, 10_000_000);
    let m = ok(env.send1(env.deposit_ix(0), S_PAYER), "PhUSD + USDC");
    let ev = one_event(&m.logs, "SJKEVDEP");
    let e = abi::event("SJKEVDEP");
    assert_eq!(e.u64(&ev, "deposited"), 15_000_000);
    assert_eq!(e.u64(&ev, "usdc_wrapped"), 10_000_000);
    assert_eq!(e.u64(&ev, "phusd_direct"), 5_000_000);
    assert_eq!(env.cfg_u64("cum_phusd_direct"), 5_000_000);
    assert_eq!(env.cfg_u64("cum_inflow_usdc"), 15_000_000);
    // Only PhUSD: Ember is not invoked.
    env.donate_phusd(&vp, 3_000_000);
    let m = ok(env.send1(env.deposit_ix(0), S_PAYER), "PhUSD only");
    assert!(!log_contains(&m.logs, &format!("Program {EMBER} invoke")), "no Ember CPI for PhUSD only");
    assert_eq!(env.cfg_u64("cum_inflow_usdc"), 18_000_000);
    assert_eq!(env.token_amount(&vp), 0);
    // max_amount below the PhUSD balance: PhUSD first, no wrap, rest stays.
    env.donate_phusd(&vp, 5_000_000);
    env.mint_usdc(&vu, 10_000_000);
    let m = ok(env.send1(env.deposit_ix(3_000_000), S_PAYER), "max_amount < PhUSD balance");
    assert!(!log_contains(&m.logs, &format!("Program {EMBER} invoke")), "no wrap needed");
    assert_eq!(env.token_amount(&vp), 2_000_000);
    assert_eq!(env.token_amount(&vu), 10_000_000);
    assert_eq!(env.cfg_u64("cum_inflow_usdc"), 21_000_000);
    assert_eq!(env.cfg_u64("cum_phusd_direct"), 11_000_000);
    // max_amount between PhUSD and the total: wrap only the difference.
    let m = ok(env.send1(env.deposit_ix(6_000_000), S_PAYER), "max_amount above the PhUSD balance");
    let ev = one_event(&m.logs, "SJKEVDEP");
    let e = abi::event("SJKEVDEP");
    assert_eq!((e.u64(&ev, "usdc_wrapped"), e.u64(&ev, "deposited")), (4_000_000, 6_000_000));
    assert_eq!(env.token_amount(&vp), 0);
    assert_eq!(env.token_amount(&vu), 6_000_000);
}

/// SPEC v4 (DECISIONS §23 item 1): there is no inflow pause. Whatever byte
/// sits at the former `inflow_pause_mask@1152` (now `_reserved10`), the
/// deposit goes through.
#[test]
fn deposit_ignores_the_retired_pause_byte() {
    let Some(mut env) = Env::new() else { return };
    env.setup_funded(0);
    let vu = env.vault_usdc();
    env.mint_usdc(&vu, 10_000_000);
    let off = abi::config().field("_reserved10").offset;
    assert_eq!(off, 1152);
    let cfg = env.pdas.config.0;
    env.patch(&cfg, |d| d[off] = 3);
    ok(env.send1(env.deposit_ix(0), S_PAYER), "deposit with the old pause byte set");
}

/// TC-32: with a Phoenix deposit cooldown `cd > 0` tag 21 keeps a quiet
/// window at the start of every period `P`, and harvest waits for
/// `last_deposit_slot + cd` (SPEC §5.3.5 step 3, §5.4.2 step 4).
#[test]
fn deposit_quiet_window_and_harvest_cooldown() {
    let Some(mut env) = Env::new() else { return };
    let fixture_cd = env.gc_u64(512);
    eprintln!(
        "fixture GC@512 deposit_cooldown_period_in_slots = {fixture_cd}; GC@504 = {:#010b}",
        env.exchange_status()
    );
    env.setup_funded(0);
    let cd = 1_500u64;
    env.set_deposit_cooldown(cd);
    let p = 216_000u64.max(2 * (cd + 9_000));
    let (_, ts) = env.clock();
    let vu = env.vault_usdc();
    env.mint_usdc(&vu, 100_000_000);
    // Inside the window: slot % P < cd + 9000 (time only moves forward).
    env.set_clock(3 * p, ts);
    env.refresh_prices();
    expect_err(env.send1(env.deposit_ix(0), S_PAYER), "DepositQuietWindow", "first slot of the window");
    env.set_clock(3 * p + cd + 9_000 - 1, ts);
    env.refresh_prices();
    expect_err(env.send1(env.deposit_ix(0), S_PAYER), "DepositQuietWindow", "last slot of the window");
    // First slot after the window.
    let dep_slot = 3 * p + cd + 9_000;
    env.set_clock(dep_slot, ts);
    env.refresh_prices();
    ok(env.send1(env.deposit_ix(0), S_PAYER), "deposit outside the window");
    assert_eq!(env.our_trader().last_deposit_slot, dep_slot);

    // A profit so that harvest has something to pay (U-47 gift).
    let t = env.pdas.trader.0;
    ok(env.actor_gift_collateral("taker0", &t, 20_000_000), "gift");
    assert_eq!(env.our_trader().last_deposit_slot, dep_slot, "TransferCollateral from another authority keeps @192");
    env.set_clock(dep_slot + cd - 1, ts + 7200);
    env.refresh_prices();
    let pv = env.preview();
    let hp = abi::harvest_preview();
    assert_eq!(hp.u8(&pv, "status"), 7, "preview status Cooldown");
    assert_eq!(hp.u64(&pv, "cooldown_until_slot"), dep_slot + cd);
    expect_err(env.harvest(), "WithdrawCooldown", "harvest inside the cooldown");
    env.set_clock(dep_slot + cd, ts + 7200);
    env.refresh_prices();
    let pv = env.preview();
    assert_eq!(hp.u8(&pv, "status"), 0, "Ready at last_deposit_slot + cd");
    ok(env.harvest(), "harvest at last_deposit_slot + cd");
}
