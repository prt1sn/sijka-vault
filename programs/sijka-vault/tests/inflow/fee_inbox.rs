// Copyright (c) 2026 prt1sn. All rights reserved.
//! `fee_inbox` and its rent reserve (SPEC §5.3.1, §5.3.4 step 5, TC-17):
//! only the surplus above `R = rent(0)` is ever taken, `pending` wSOL
//! (including unsynced lamports) is used first, and the account itself is
//! pinned (key, System owner, no data).

use solana_account::Account;
use solana_instruction::AccountMeta;
use solana_signer::Signer;

use crate::harness::*;
use crate::route::*;
use crate::swap::{SOL, fund_fee_inbox, honest, run, snap};

#[test]
fn tc17_insufficient_surplus_then_pending() {
    let Some(mut env) = Env::new(Opts::default()) else { return };
    let r = env.rent(0);
    fund_fee_inbox(&mut env, 3 * SOL / 10);
    // fee_inbox = R + 0.3 SOL, pending = 0, amount = 1 SOL.
    let (s, _) = honest(&env, Kind::RouteV2, SOL);
    let before = snap(&env);
    expect_err(run(&mut env, &s), "FeeInboxInsufficient");
    assert_eq!(snap(&env), before);
    // 0.7 SOL of unsynced lamports on swap_wsol count as pending: only the
    // missing 0.3 SOL comes from fee_inbox, which ends at exactly R.
    let w = env.k.swap_wsol;
    env.transfer_lamports(&w, 7 * SOL / 10);
    let m = expect_ok(run(&mut env, &s));
    let e = event(&m.logs, "SJKEVSWI");
    assert_eq!(e.u("topup"), 3 * SOL / 10);
    assert_eq!(e.u("fee_inbox_after"), r);
    assert_eq!(env.lamports(&env.k.fee_inbox), r);
    assert_eq!(e.u("spent"), SOL);
}

#[test]
fn reserve_is_never_taken() {
    let Some(mut env) = Env::new(Opts::default()) else { return };
    let r = env.rent(0);
    // Surplus one lamport short of the amount.
    fund_fee_inbox(&mut env, SOL - 1);
    let (s, _) = honest(&env, Kind::RouteV2, SOL);
    expect_err(run(&mut env, &s), "FeeInboxInsufficient");
    // Exactly the amount above R: fee_inbox ends at R.
    env.transfer_lamports(&env.k.fee_inbox.clone(), 1);
    expect_ok(run(&mut env, &s));
    assert_eq!(env.lamports(&env.k.fee_inbox), r);
    // Nothing above R: the next swap needs pending wSOL.
    expect_err(run(&mut env, &s), "FeeInboxInsufficient");
    assert_eq!(env.lamports(&env.k.fee_inbox), r);
}

#[test]
fn fee_inbox_below_reserve_is_untouched() {
    let Some(mut env) = Env::new(Opts::default()) else { return };
    let r = env.rent(0);
    // fee_inbox holds exactly R and wSOL is already pending: the swap runs
    // and fee_inbox is not touched. (Below R but above 0 cannot exist: the
    // runtime refuses a System account under the rent-exempt minimum.)
    let fi = env.k.fee_inbox;
    env.transfer_lamports(&fi, r);
    let w = env.k.swap_wsol;
    env.transfer_lamports(&w, SOL);
    let (s, _) = honest(&env, Kind::RouteV2, SOL);
    let m = expect_ok(run(&mut env, &s));
    assert_eq!(event(&m.logs, "SJKEVSWI").u("topup"), 0);
    assert_eq!(env.lamports(&fi), r);
    // No fee_inbox account at all (never funded) behaves the same.
    let Some(mut env) = Env::new(Opts::default()) else { return };
    assert_eq!(env.lamports(&env.k.fee_inbox), 0);
    let w = env.k.swap_wsol;
    env.transfer_lamports(&w, SOL);
    let (s, _) = honest(&env, Kind::RouteV2, SOL);
    expect_ok(run(&mut env, &s));
    assert_eq!(env.lamports(&env.k.fee_inbox), 0);
    // And a shortfall with no fee_inbox is FeeInboxInsufficient.
    expect_err(run(&mut env, &s), "FeeInboxInsufficient");
}

#[test]
fn donated_lamports_are_swapped() {
    let Some(mut env) = Env::new(Opts::default()) else { return };
    let r = env.rent(0);
    // Anyone may send SOL to fee_inbox (a donation, SPEC §5.3.1): it is
    // swapped like fees (SOL → USDC → vault_usdc; I only at tag 21).
    let fi = env.k.fee_inbox;
    env.transfer_lamports(&fi, r + 2 * SOL);
    let (s, out) = honest(&env, Kind::RouteV2, 2 * SOL);
    expect_ok(run(&mut env, &s));
    assert_eq!(env.lamports(&fi), r);
    assert_eq!(env.token_amount(&env.k.vault_usdc), out);
    assert_eq!(env.cfg("cum_inflow_usdc"), 0);
}

#[test]
fn fee_inbox_account_is_pinned() {
    let Some(mut env) = Env::new(Opts::default()) else { return };
    fund_fee_inbox(&mut env, 2 * SOL);
    let fi = env.k.fee_inbox;
    let lamports = env.lamports(&fi);
    // Another account in slot #1.
    let (mut s, _) = honest(&env, Kind::RouteV2, SOL);
    s.fixed[1] = AccountMeta::new(env.attacker.pubkey(), false);
    expect_err(run(&mut env, &s), "InvalidPda");
    // fee_inbox with data or a non-System owner (never made by the program).
    let (s, _) = honest(&env, Kind::RouteV2, SOL);
    for (owner, len) in [(system_program(), 1usize), (env.k.program, 0), (token_program(), 0)] {
        env.set(fi, Account { lamports, data: vec![0; len], owner, executable: false, rent_epoch: 0 });
        expect_err(run(&mut env, &s), "InvalidExternalAccount");
    }
    env.set(fi, Account { lamports, data: vec![], owner: system_program(), executable: false, rent_epoch: 0 });
    expect_ok(run(&mut env, &s));
}

#[test]
fn swap_authority_is_pinned() {
    let Some(mut env) = Env::new(Opts::default()) else { return };
    fund_fee_inbox(&mut env, 2 * SOL);
    let sa = env.k.swap_authority;
    // Lamports donated to swap_authority do not matter (it only signs), but
    // data or a non-System owner is refused.
    env.transfer_lamports(&sa, 1_000_000);
    let (s, _) = honest(&env, Kind::RouteV2, SOL);
    expect_ok(run(&mut env, &s));
    assert_eq!(env.lamports(&sa), 1_000_000);
    env.set(
        sa,
        Account { lamports: 1_000_000, data: vec![0], owner: system_program(), executable: false, rent_epoch: 0 },
    );
    let (s, _) = honest(&env, Kind::RouteV2, SOL);
    expect_err(run(&mut env, &s), "InvalidExternalAccount");
}
