// Copyright (c) 2026 prt1sn. All rights reserved.
//! SPEC v4 (DECISIONS §23 item 4): tag 20 is signed by the keeper key
//! `config.keeper` only and bounded by the keeper's `min_out`; the program
//! reads no oracle (the PAM mark and Pyth are gone). Replaces the SPEC v3
//! oracle tests TC-15/TC-16 and the recovery-mode Pyth tests (REC-5): the
//! recovery restriction of REC-11 stays (no `fee_inbox` top-up in recovery).

use solana_instruction::AccountMeta;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;

use crate::harness::*;
use crate::route::*;
use crate::swap::{SOL, fund_fee_inbox, honest, out_at, run, snap};

fn setup() -> Option<Env> {
    let mut env = Env::new(Opts::default())?;
    fund_fee_inbox(&mut env, 10 * SOL);
    Some(env)
}

/// Tag 20 with `who` in slot #6 as signer, paid and signed by `who`.
fn swap_signed_by(env: &mut Env, who: &Keypair) -> TxResult {
    let (mut s, _) = honest(env, Kind::RouteV2, SOL);
    s.fixed[6] = AccountMeta::new_readonly(who.pubkey(), true);
    let ix = s.ix(env);
    env.send_as(who, vec![cu_limit(1_400_000), ix], &[])
}

/// Only `config.keeper`, signed, reaches the swap: another signer, the admin,
/// the keeper without a signature (another fee payer), the PAM or any other
/// account in the old oracle slot, and `keeper == 0` are all
/// `UnauthorizedKeeper`, and nothing moves.
#[test]
fn only_the_keeper_signs_tag_20() {
    let Some(mut env) = setup() else { return };
    let before = snap(&env);
    let attacker = env.attacker.insecure_clone();
    expect_err(swap_signed_by(&mut env, &attacker), "UnauthorizedKeeper");
    let admin = env.admin.insecure_clone();
    expect_err(swap_signed_by(&mut env, &admin), "UnauthorizedKeeper");
    // The keeper key present but not signing (the attacker pays).
    let (mut s, _) = honest(&env, Kind::RouteV2, SOL);
    s.fixed[6] = AccountMeta::new_readonly(env.keeper.pubkey(), false);
    let ix = s.ix(&env);
    expect_err(env.send_as(&attacker, vec![cu_limit(1_400_000), ix], &[]), "UnauthorizedKeeper");
    // The former oracle account (PAM) in slot #6.
    let (mut s, _) = honest(&env, Kind::RouteV2, SOL);
    s.fixed[6] = AccountMeta::new_readonly(env.pam, false);
    expect_err(run(&mut env, &s), "UnauthorizedKeeper");
    assert_eq!(snap(&env), before, "nothing moved");

    // The keeper passes.
    let (s, out) = honest(&env, Kind::RouteV2, SOL);
    let m = expect_ok(run(&mut env, &s));
    assert_eq!(event(&m.logs, "SJKEVSWI").u("received"), out);

    // keeper = 0: nobody swaps, the old keeper included.
    expect_ok(env.set_keeper(&Pubkey::default()));
    let (s, _) = honest(&env, Kind::RouteV2, SOL);
    expect_err(run(&mut env, &s), "UnauthorizedKeeper");

    // Rotation: the new key passes, the old one is refused.
    let new_keeper = Keypair::new_from_array([0xA7; 32]);
    env.svm().airdrop(&new_keeper.pubkey(), 10 * SOL).unwrap();
    expect_ok(env.set_keeper(&new_keeper.pubkey()));
    let (s, _) = honest(&env, Kind::RouteV2, SOL);
    expect_err(run(&mut env, &s), "UnauthorizedKeeper");
    expect_ok(swap_signed_by(&mut env, &new_keeper));

    // Tag 28 itself is admin-only.
    let ix = env.set_keeper_ix(&attacker.pubkey(), &attacker.pubkey());
    expect_err(env.send_as(&attacker, vec![ix], &[]), "Unauthorized");
}

/// The keeper's `min_out` is the only price limit: 0 is refused
/// (`SwapAmountInvalid`), `received < min_out` fails (`SwapOutputBelowMin`)
/// with a full rollback, exactly `min_out` passes; the price of the fixture
/// PAM does not matter any more (no oracle).
#[test]
fn keeper_min_out_is_the_floor() {
    let Some(mut env) = setup() else { return };
    let (mut s, out) = honest(&env, Kind::RouteV2, SOL);
    s.min_out = 0;
    expect_err(run(&mut env, &s), "SwapAmountInvalid");
    s.min_out = out + 1;
    let before = snap(&env);
    expect_err(run(&mut env, &s), "SwapOutputBelowMin");
    assert_eq!(snap(&env), before, "rollback");
    s.min_out = out;
    let m = expect_ok(run(&mut env, &s));
    let e = event(&m.logs, "SJKEVSWI");
    assert_eq!((e.u("min_out"), e.u("received")), (out, out));

    // A route far below the Phoenix mark passes when the keeper allows it:
    // the program has no oracle floor (accepted risk of a stolen keeper key,
    // SPEC §1.6).
    let low = out_at(SOL, env.pam_px(), 500, 1000);
    let mut s = Swap::mock(&env, Kind::RouteV2, SOL, mode::HONEST, low, 0);
    s.min_out = low;
    expect_ok(run(&mut env, &s));
    // A stale PAM mark changes nothing either.
    let mark = env.pam_mark_slot();
    env.warp(mark + 10_000);
    let (s, _) = honest(&env, Kind::RouteV2, SOL);
    expect_ok(run(&mut env, &s));
}

/// Recovery mode (REC-11): the `fee_inbox` surplus is never swapped (op 3
/// sends it to the recipient; SPEC v4 has no BUYBACK route, so on both pairs);
/// wSOL already on `swap_wsol` is swapped by the keeper as usual.
#[test]
fn recovery_mode_swaps_only_the_wsol_left() {
    for usdc_pair in [false, true] {
        let Some(mut env) = Env::new(Opts { usdc_pair, ..Opts::default() }) else { return };
        fund_fee_inbox(&mut env, 3 * SOL);
        env.set_cfg("recovery_mode", 1);
        let (s, out) = honest(&env, Kind::RouteV2, SOL);
        expect_err(run(&mut env, &s), "RecoverySwapRestricted");
        // A zeroed admin (the retired renounce) opens nothing any more.
        env.set_cfg_bytes("admin", &[0u8; 32]);
        expect_err(run(&mut env, &s), "RecoverySwapRestricted");
        let w = env.k.swap_wsol;
        env.transfer_lamports(&w, SOL);
        let fi = env.lamports(&env.k.fee_inbox);
        let m = expect_ok(run(&mut env, &s));
        let e = event(&m.logs, "SJKEVSWI");
        assert_eq!((e.u("topup"), e.u("received")), (0, out), "usdc_pair {usdc_pair}");
        assert_eq!(env.lamports(&env.k.fee_inbox), fi, "fee_inbox untouched in recovery");
    }
}
