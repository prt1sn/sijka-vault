// Copyright (c) 2026 prt1sn. All rights reserved.
//! Tag 20 against a malicious Jupiter (the mock at `JUP6…`, SPEC §5.3.3
//! `post_route_check`, §5.3.4 step 7; TC-5…TC-7, review RT-1): overspending
//! the input, underpaying, paying elsewhere, changing owner / delegate / close
//! authority of the swap accounts, closing them, touching the signer, touching
//! accounts it does not own, reentering the vault, and nesting CPIs deeper
//! (U-28). Every attack must be rejected with nothing moved.

use solana_instruction::AccountMeta;

use crate::harness::*;
use crate::route::*;
use crate::swap::{SOL, Snap, fund_fee_inbox, honest, out_at, run, snap};

fn setup() -> Option<(Env, u64)> {
    let mut env = Env::new(Opts::default())?;
    fund_fee_inbox(&mut env, 5 * SOL);
    let out = out_at(SOL, env.pam_px(), 998, 1000);
    Some((env, out))
}

fn attack(env: &mut Env, kind: Kind, mode: u8, out: u64, arg: u64, extra: &[AccountMeta]) -> (TxResult, Snap) {
    let mut s = Swap::mock(env, kind, SOL, mode, out, arg);
    s.route = route_accounts(env, kind, extra);
    let before = snap(env);
    (run(env, &s), before)
}

#[track_caller]
fn rejected(env: &mut Env, kind: Kind, mode: u8, out: u64, arg: u64, extra: &[AccountMeta], err: &str) {
    let (r, before) = attack(env, kind, mode, out, arg, extra);
    expect_err(r, err);
    assert_eq!(snap(env), before, "mode {mode} ({kind:?}): state must roll back");
}

#[track_caller]
fn rejected_by_runtime(env: &mut Env, mode: u8, out: u64, arg: u64, extra: &[AccountMeta], needle: &str) {
    let (r, before) = attack(env, Kind::RouteV2, mode, out, arg, extra);
    expect_runtime_err(r, needle);
    assert_eq!(snap(env), before, "mode {mode}: state must roll back");
}

#[test]
fn tc05_overspend_input() {
    let Some((mut env, out)) = setup() else { return };
    // Enough wSOL on swap_wsol for the route to take more than amount_in.
    let w = env.k.swap_wsol;
    env.transfer_lamports(&w, 2 * SOL);
    for kind in ALL_KINDS {
        rejected(&mut env, kind, mode::OVERSPEND, out, 1, &[], "SwapInputExceeded");
    }
}

#[test]
fn tc06_tamper_swap_accounts() {
    let Some((mut env, out)) = setup() else { return };
    for kind in [Kind::RouteV2, Kind::Route] {
        for target in [0u64, 1] {
            for m in [mode::APPROVE_DELEGATE, mode::SET_OWNER, mode::SET_CLOSE_AUTHORITY] {
                rejected(&mut env, kind, m, out, target, &[], "SwapAccountTampered");
            }
        }
        rejected(&mut env, kind, mode::CLOSE_SRC, out, 0, &[], "SwapAccountTampered");
    }
}

#[test]
fn tc07_pay_to_other_account() {
    let Some((mut env, out)) = setup() else { return };
    for kind in ALL_KINDS {
        rejected(&mut env, kind, mode::PAY_TO_OTHER, out, 0, &[], "SwapOutputBelowMin");
    }
}

#[test]
fn underpay_by_rate() {
    let Some((mut env, _)) = setup() else { return };
    let px = env.pam_px();
    // Rate one bps below the keeper's slippage (TC-3 as a pool rate): px·(1 − 0.0051).
    let out = out_at(SOL, px, 9_949, 10_000);
    rejected(&mut env, Kind::RouteV2, mode::HONEST, out, 0, &[], "SwapOutputBelowMin");
}

#[test]
fn nothing_spent() {
    let Some((mut env, out)) = setup() else { return };
    rejected(&mut env, Kind::RouteV2, mode::NOOP, out, 0, &[], "SwapNoop");
}

#[test]
fn input_account_credited() {
    let Some((mut env, out)) = setup() else { return };
    // The route pays wSOL back into swap_wsol (w1 > w0).
    rejected(&mut env, Kind::RouteV2, mode::CREDIT_SRC, out, SOL + 1, &[], "SwapAccountTampered");
}

#[test]
fn output_account_debited() {
    let Some((mut env, out)) = setup() else { return };
    // swap_usdc holds a donation D; the route takes it.
    let d = 5_000_000;
    let su = env.k.swap_usdc;
    env.mint_usdc(su, d);
    // Take D and pay only `out`: net delta out − D < floor.
    rejected(&mut env, Kind::RouteV2, mode::STEAL_DST, out, d, &[], "SwapOutputBelowMin");
    // Take more than was paid: u1 < u0.
    rejected(&mut env, Kind::RouteV2, mode::STEAL_DST, 1, d, &[], "SwapAccountTampered");
    // Take D and pay out + D: the vault still nets `out` and D stays on
    // swap_usdc for tag 23 (only the delta moves, SPEC §5.3.4 step 8).
    let (r, before) = attack(&mut env, Kind::RouteV2, mode::STEAL_DST, out + d, d, &[]);
    let m = expect_ok(r);
    assert_eq!(event(&m.logs, "SJKEVSWI").u("received"), out);
    assert_eq!(env.token_amount(&env.k.swap_usdc), before.swap_usdc);
    assert_eq!(env.token_amount(&env.k.vault_usdc), before.vault_usdc + out);
}

#[test]
fn signer_lamports_and_owner() {
    let Some((mut env, out)) = setup() else { return };
    // swap_authority is read-only in the vault's CPI: System Transfer / Assign
    // with its signature cannot be made writable by the route.
    rejected_by_runtime(&mut env, mode::DRAIN_AUTHORITY, out, 0, &[], "PrivilegeEscalation");
    rejected_by_runtime(&mut env, mode::DRAIN_AUTHORITY, out, 1, &[], "PrivilegeEscalation");
    rejected_by_runtime(&mut env, mode::ASSIGN_AUTHORITY, out, 0, &[], "PrivilegeEscalation");
}

#[test]
fn write_foreign_account_data() {
    let Some((mut env, out)) = setup() else { return };
    // The mock writes swap_usdc's bytes directly (owner Tokenkeg): the runtime
    // refuses the change.
    let extra = [AccountMeta::new(env.k.swap_usdc, false)];
    let (r, before) = attack(&mut env, Kind::RouteV2, mode::WRITE_FOREIGN, out, 0, &extra);
    let f = r.expect_err("foreign data write must fail");
    let s = format!("{:?}", f.err);
    assert!(s.contains("ExternalAccountDataModified") || s.contains("ReadonlyDataModified"), "{s}");
    assert_eq!(snap(&env), before);
}

#[test]
fn reentrancy_into_the_vault() {
    let Some((mut env, out)) = setup() else { return };
    // The route calls back into the vault (tag 23 / tag 20 / unknown tag):
    // Solana forbids A → B → A reentrancy, whatever the vault would check.
    let program = env.k.program;
    for tag in [23u64, 20, 22, 255] {
        let extra = [AccountMeta::new_readonly(program, false)];
        rejected_by_runtime(&mut env, mode::REENTER, out, tag, &extra, "ReentrancyNotAllowed");
    }
    // With the sweep accounts it would need: `config` is protected, so the
    // route is refused before any CPI.
    let k = env.k.clone();
    let extra = [
        AccountMeta::new_readonly(program, false),
        AccountMeta::new(k.config, false),
        AccountMeta::new_readonly(k.swap_authority, false),
        AccountMeta::new(k.swap_usdc, false),
        AccountMeta::new(k.vault_usdc, false),
        AccountMeta::new_readonly(token_program(), false),
    ];
    rejected(&mut env, Kind::RouteV2, mode::REENTER, out, 23, &extra, "JupiterAccountForbidden");
}

#[test]
fn benign_behaviours_pass() {
    let Some((mut env, out)) = setup() else { return };
    // Extra output is fine and fully accounted.
    let (r, before) = attack(&mut env, Kind::RouteV2, mode::CREDIT_EXTRA, out, 7, &[]);
    let m = expect_ok(r);
    assert_eq!(event(&m.logs, "SJKEVSWI").u("received"), out + 7);
    assert_eq!(env.token_amount(&env.k.vault_usdc), before.vault_usdc + out + 7);
    // A SyncNative inside the route changes nothing.
    let (r, _) = attack(&mut env, Kind::RouteV2, mode::SYNC_SRC, out, 0, &[]);
    expect_ok(r);
}

#[test]
fn partial_input_spend() {
    let Some((mut env, out)) = setup() else { return };
    let px = env.pam_px();
    // 0.6 SOL of 1 SOL spent, full output: ok, 0.4 SOL stays on swap_wsol.
    let (r, _) = attack(&mut env, Kind::RouteV2, mode::PARTIAL, out, 6 * SOL / 10, &[]);
    let m = expect_ok(r);
    let e = event(&m.logs, "SJKEVSWI");
    assert_eq!(e.u("spent"), 6 * SOL / 10);
    assert_eq!(e.u("wsol_left"), 4 * SOL / 10);
    assert_eq!(env.token_amount(&env.k.swap_wsol), 4 * SOL / 10);
    assert_eq!(env.cfg("cum_swap_lamports_spent"), 6 * SOL / 10);
    // The keeper's min_out bounds the whole amount_in, not what was spent.
    let proportional = out_at(6 * SOL / 10, px, 998, 1000);
    rejected(&mut env, Kind::RouteV2, mode::PARTIAL, proportional, 6 * SOL / 10, &[], "SwapOutputBelowMin");
    // The leftover counts as pending on the next call (no fee_inbox top-up).
    let fi = env.lamports(&env.k.fee_inbox);
    let (s, _) = honest(&env, Kind::RouteV2, 4 * SOL / 10);
    let m = expect_ok(run(&mut env, &s));
    assert_eq!(event(&m.logs, "SJKEVSWI").u("topup"), 0);
    assert_eq!(env.lamports(&env.k.fee_inbox), fi);
}

#[test]
fn u28_amm_cpi_depth_under_the_vault() {
    let Some((mut env, out)) = setup() else { return };
    // sijka(1) → Jupiter(2) → mock AMM(3) → … → Token. `arg` extra self-CPI
    // levels before the Token transfer of the output.
    let me = [AccountMeta::new_readonly(jup6(), false)];
    let mut depths = Vec::new();
    for levels in 0u64..=3 {
        let (r, before) = attack(&mut env, Kind::RouteV2, mode::CHAIN, out, levels, &me);
        // Token program depth = 4 + levels.
        let token_depth = 4 + levels;
        match r {
            Ok(_) => depths.push(format!("token at depth {token_depth}: ok")),
            Err(f) => {
                let s = format!("{:?}", f.err);
                assert!(s.contains("CallDepth"), "levels {levels}: {s}\n{}", f.meta.logs.join("\n"));
                assert_eq!(snap(&env), before);
                depths.push(format!("token at depth {token_depth}: CallDepth"));
            }
        }
    }
    eprintln!("U-28 depth: {}", depths.join("; "));
    assert!(depths[0].ends_with("ok") && depths[1].ends_with("ok"), "{depths:?}");
    assert!(depths[2].ends_with("CallDepth") && depths[3].ends_with("CallDepth"), "{depths:?}");
}
