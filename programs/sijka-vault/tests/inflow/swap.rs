// Copyright (c) 2026 prt1sn. All rights reserved.
//! Tag 20 `swap_sol_to_usdc` (SPEC §5.3.3, §5.3.4) against the Jupiter mock:
//! honest routes of all four layouts with full accounting, the route checks
//! (slots, arguments, tail size, protected keys), amount bounds, top-level
//! rule and the CU budget (TC-1…TC-4, TC-8…TC-14, TC-18, TC-19, TC-22).
//! SPEC v4: every swap is signed by the keeper key (the fee payer of `send`)
//! with the keeper's `min_out`; the fixture SOL mark is only the keeper's
//! quote here, the program reads no oracle.

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use solana_signer::Signer;

use crate::harness::*;
use crate::route::*;

pub const SOL: u64 = 1_000_000_000;

/// `amount·px·num/den / 10⁹` (floor): the output of a mock "pool" at
/// `rate = px·num/den`.
pub fn out_at(amount: u64, px: u64, num: u64, den: u64) -> u64 {
    (amount as u128 * px as u128 * num as u128 / den as u128 / 1_000_000_000) as u64
}

/// Everything a failed tag 20 must leave untouched.
#[derive(Debug, PartialEq, Eq)]
pub struct Snap {
    pub fee_inbox: u64,
    pub wsol_lamports: u64,
    pub wsol: u64,
    pub swap_usdc: u64,
    pub vault_usdc: u64,
    pub config: Vec<u8>,
    pub pool_usdc: u64,
}

pub fn snap(env: &Env) -> Snap {
    Snap {
        fee_inbox: env.lamports(&env.k.fee_inbox),
        wsol_lamports: env.lamports(&env.k.swap_wsol),
        wsol: env.token_amount(&env.k.swap_wsol),
        swap_usdc: env.token_amount(&env.k.swap_usdc),
        vault_usdc: env.token_amount(&env.k.vault_usdc),
        config: env.config(),
        pool_usdc: env.token_amount(&env.pool_usdc),
    }
}

pub fn fund_fee_inbox(env: &mut Env, surplus: u64) {
    let r = env.rent(0);
    let fi = env.k.fee_inbox;
    let have = env.lamports(&fi);
    let want = r + surplus;
    if want > have {
        env.transfer_lamports(&fi, want - have);
    }
}

/// An honest mock swap at `px·0.998` (above the keeper's `min_out`, quote
/// minus 50 bps).
pub fn honest(env: &Env, kind: Kind, amount: u64) -> (Swap, u64) {
    let out = out_at(amount, env.pam_px(), 998, 1000);
    (Swap::mock(env, kind, amount, mode::HONEST, out, 0), out)
}

pub fn run(env: &mut Env, s: &Swap) -> TxResult {
    let ix = s.ix(env);
    env.send1(ix)
}

fn new_env() -> Option<Env> {
    Env::new(Opts::default())
}

#[test]
fn tc01_honest_route_v2_full_accounting() {
    let Some(mut env) = new_env() else { return };
    eprintln!("tc01: Phoenix oracle update CU {}", env.oracle_cu);
    env.set_now(1_234);
    let r = env.rent(0);
    fund_fee_inbox(&mut env, 3 * SOL / 2);
    // The keeper quotes the fixture mark (150.000 USD) minus 50 bps.
    let px = env.pam_px();
    assert_eq!(px, FIXTURE_SOL_PX);
    let (s, out) = honest(&env, Kind::RouteV2, SOL);
    let floor = keeper_min_out(SOL, px, KEEPER_SLIPPAGE_BPS);
    assert_eq!(floor, 149_250_000);
    assert_eq!(s.min_out, floor);
    assert!(out >= floor);
    let before = snap(&env);
    let m = expect_ok(run(&mut env, &s));
    // fee_inbox: R + 1.5 SOL → R + 0.5 SOL; exactly `out` reaches vault_usdc.
    assert_eq!(env.lamports(&env.k.fee_inbox), r + SOL / 2);
    assert_eq!(env.token_amount(&env.k.vault_usdc), before.vault_usdc + out);
    assert_eq!(env.token_amount(&env.k.swap_usdc), before.swap_usdc);
    assert_eq!(env.token_amount(&env.k.swap_wsol), 0);
    assert_eq!(env.token_amount(&env.pool_usdc), before.pool_usdc - out);
    // Config counters; I is not touched by tag 20.
    assert_eq!(env.cfg("cum_swap_lamports_spent"), SOL);
    assert_eq!(env.cfg("cum_swap_usdc_received"), out);
    assert_eq!(env.cfg("swap_count"), 1);
    assert_eq!(env.cfg("last_swap_ts"), env.now() as u64);
    assert_eq!(env.cfg("last_swap_slot"), env.slot());
    assert_eq!(env.cfg("cum_inflow_usdc"), 0);
    assert_eq!(env.cfg("inflow_count"), 0);
    assert_eq!(env.cfg("next_swap_ts"), 0);
    // Event SJKEVSWI (SPEC v4: 90 bytes, no oracle fields).
    let e = event(&m.logs, "SJKEVSWI");
    assert_eq!(e.d.len(), abi().ev_size("SJKEVSWI"));
    assert_eq!(e.d.len(), 90);
    assert_eq!(e.u("ver"), 1);
    assert_eq!(e.u("jup_kind"), Kind::RouteV2.code());
    assert_eq!(e.u("amount_in"), SOL);
    assert_eq!(e.u("spent"), SOL);
    assert_eq!(e.u("received"), out);
    assert_eq!(e.u("min_out"), floor);
    assert_eq!(e.u("topup"), SOL);
    assert_eq!(e.u("fee_inbox_after"), r + SOL / 2);
    assert_eq!(e.u("wsol_left"), 0);
    assert_eq!(e.u("swap_count"), 1);
    assert_eq!(e.u("slot"), env.slot());
    assert_eq!(e.i("ts"), env.now());
}

#[test]
fn tc02_all_four_layouts() {
    let Some(mut env) = new_env() else { return };
    fund_fee_inbox(&mut env, 10 * SOL);
    let mut received = 0;
    for (i, kind) in ALL_KINDS.into_iter().enumerate() {
        let (s, out) = honest(&env, kind, SOL);
        let m = expect_ok(run(&mut env, &s));
        let e = event(&m.logs, "SJKEVSWI");
        assert_eq!(e.u("jup_kind"), kind.code(), "{kind:?}");
        assert_eq!(e.u("received"), out);
        received += out;
        assert_eq!(env.cfg("swap_count"), i as u64 + 1);
    }
    assert_eq!(env.token_amount(&env.k.vault_usdc), received);
    assert_eq!(env.cfg("cum_swap_usdc_received"), received);
    assert_eq!(env.cfg("cum_swap_lamports_spent"), 4 * SOL);
}

#[test]
fn tc03_output_floor_boundary() {
    let Some(mut env) = new_env() else { return };
    fund_fee_inbox(&mut env, 5 * SOL);
    let floor = keeper_min_out(SOL, env.pam_px(), KEEPER_SLIPPAGE_BPS);
    for kind in ALL_KINDS {
        // One atom below the keeper's min_out: rejected, nothing moves.
        let s = Swap::mock(&env, kind, SOL, mode::HONEST, floor - 1, 0);
        assert_eq!(s.min_out, floor);
        let before = snap(&env);
        expect_err(run(&mut env, &s), "SwapOutputBelowMin");
        assert_eq!(snap(&env), before, "{kind:?}: rollback");
    }
    // Exactly the floor passes.
    let s = Swap::mock(&env, Kind::RouteV2, SOL, mode::HONEST, floor, 0);
    let m = expect_ok(run(&mut env, &s));
    assert_eq!(event(&m.logs, "SJKEVSWI").u("received"), floor);
}

#[test]
fn tc04_keeper_minimum() {
    let Some(mut env) = new_env() else { return };
    fund_fee_inbox(&mut env, 5 * SOL);
    let (mut s, out) = honest(&env, Kind::RouteV2, SOL);
    s.min_out = out + 1;
    expect_err(run(&mut env, &s), "SwapOutputBelowMin");
    s.min_out = 0;
    expect_err(run(&mut env, &s), "SwapAmountInvalid");
    s.min_out = out;
    let m = expect_ok(run(&mut env, &s));
    let e = event(&m.logs, "SJKEVSWI");
    assert_eq!(e.u("min_out"), out, "min_out is the keeper's (SPEC v4)");
}

#[test]
fn tc08_swap_authority_writable() {
    let Some(mut env) = new_env() else { return };
    fund_fee_inbox(&mut env, 2 * SOL);
    let (mut s, _) = honest(&env, Kind::RouteV2, SOL);
    s.fixed[2] = AccountMeta::new(env.k.swap_authority, false);
    expect_err(run(&mut env, &s), "AccountMustBeReadonly");
}

#[test]
fn tc09_protected_keys_in_tail() {
    let Some(mut env) = Env::new(Opts { trader: true, ..Opts::default() }) else { return };
    fund_fee_inbox(&mut env, 2 * SOL);
    let k = env.k.clone();
    let protected = [
        ("config", k.config),
        ("buyback_state", k.buyback_state),
        ("fee_inbox", k.fee_inbox),
        ("phx_authority", k.phx_authority),
        ("rent_payer", k.rent_payer),
        ("buyback_authority", k.buyback_authority),
        ("phoenix_trader", k.phoenix_trader),
        ("vault_usdc", k.vault_usdc),
        ("vault_phusd", k.vault_phusd),
        ("buyback_usdc", k.buyback_usdc),
        ("bb_unwrap", k.bb_unwrap),
        ("creator_escrow", k.creator_escrow),
        ("creator_escrow_usdc", k.creator_escrow_usdc),
    ];
    for (name, key) in protected {
        for writable in [false, true] {
            let (mut s, _) = honest(&env, Kind::RouteV2, SOL);
            s.route.push(AccountMeta { pubkey: key, is_signer: false, is_writable: writable });
            let before = snap(&env);
            expect_err(run(&mut env, &s), "JupiterAccountForbidden");
            assert_eq!(snap(&env), before, "{name}");
        }
    }
    // The honest route itself passes in the same environment.
    let (s, _) = honest(&env, Kind::RouteV2, SOL);
    expect_ok(run(&mut env, &s));
}

#[test]
fn tc10_foreign_swap_authority_token_accounts() {
    let Some(mut env) = new_env() else { return };
    fund_fee_inbox(&mut env, 2 * SOL);
    let sa = env.k.swap_authority;
    let usdc = env.k.usdc_mint;
    // A third USDC account, a second wSOL account and a Token-2022 account,
    // all with owner@32 = swap_authority.
    let third_usdc = Pubkey::new_from_array([0xB1; 32]);
    env.set_token(third_usdc, usdc, sa, 5, false);
    let second_wsol = Pubkey::new_from_array([0xB2; 32]);
    env.set_token(second_wsol, wsol_mint(), sa, 0, true);
    let t22 = Pubkey::new_from_array([0xB3; 32]);
    env.set_token(t22, usdc, sa, 5, false);
    let mut a = env.account(&t22).unwrap();
    a.owner = token_2022();
    env.set(t22, a);
    for key in [third_usdc, second_wsol, t22] {
        let (mut s, _) = honest(&env, Kind::RouteV2, SOL);
        s.route.push(AccountMeta::new(key, false));
        expect_err(run(&mut env, &s), "JupiterAccountForbidden");
    }
    // A token account of someone else (the attacker's, already in every mock
    // route) is fine.
    let (s, _) = honest(&env, Kind::RouteV2, SOL);
    expect_ok(run(&mut env, &s));
}

#[test]
fn tc11_route_slot_pins() {
    let Some(mut env) = new_env() else { return };
    fund_fee_inbox(&mut env, 2 * SOL);
    let k = env.k.clone();
    let att = env.attacker_usdc;
    let other = Pubkey::new_from_array([0xEE; 32]);
    let ro = AccountMeta::new_readonly;
    // (kind, slot, replacement)
    let cases: Vec<(Kind, usize, AccountMeta)> = vec![
        (Kind::RouteV2, 0, ro(env.attacker.pubkey(), false)), // authority
        (Kind::RouteV2, 1, AccountMeta::new(k.swap_usdc, false)), // src
        (Kind::RouteV2, 2, AccountMeta::new(k.swap_wsol, false)), // dst
        (Kind::RouteV2, 3, ro(k.usdc_mint, false)),           // src mint
        (Kind::RouteV2, 4, ro(wsol_mint(), false)),           // dst mint
        (Kind::RouteV2, 5, ro(token_2022(), false)),          // source token program
        (Kind::RouteV2, 6, ro(token_2022(), false)),          // destination token program
        (Kind::RouteV2, 7, AccountMeta::new(att, false)),     // destination_token_account
        (Kind::RouteV2, 9, ro(mock_elsewhere(), false)),      // program
        (Kind::SharedV2, 1, ro(other, false)),
        (Kind::SharedV2, 2, AccountMeta::new(att, false)),
        (Kind::SharedV2, 5, AccountMeta::new(att, false)),
        (Kind::SharedV2, 6, ro(k.usdc_mint, false)),
        (Kind::SharedV2, 7, ro(other, false)),
        (Kind::SharedV2, 8, ro(token_2022(), false)),
        (Kind::SharedV2, 9, ro(other, false)),
        (Kind::SharedV2, 11, ro(other, false)),
        (Kind::Route, 0, ro(token_2022(), false)),
        (Kind::Route, 1, ro(other, false)),
        (Kind::Route, 2, AccountMeta::new(att, false)),
        (Kind::Route, 3, AccountMeta::new(att, false)),
        (Kind::Route, 4, AccountMeta::new(att, false)), // destination_token_account
        (Kind::Route, 5, ro(wsol_mint(), false)),
        (Kind::Route, 6, AccountMeta::new(att, false)), // platform_fee_account ≠ None
        (Kind::Route, 8, ro(other, false)),
        (Kind::Shared, 0, ro(other, false)),
        (Kind::Shared, 2, ro(other, false)),
        (Kind::Shared, 3, AccountMeta::new(att, false)),
        (Kind::Shared, 6, AccountMeta::new(att, false)),
        (Kind::Shared, 7, ro(k.usdc_mint, false)),
        (Kind::Shared, 8, ro(other, false)),
        (Kind::Shared, 9, AccountMeta::new(att, false)), // platform_fee_account ≠ None
        (Kind::Shared, 12, ro(other, false)),
    ];
    for (kind, slot, meta) in cases {
        let (mut s, _) = honest(&env, kind, SOL);
        s.route[slot] = meta;
        let before = snap(&env);
        let r = run(&mut env, &s);
        let f = expect_err(r, "JupiterRoutePinMismatch");
        assert!(!f.meta.logs.iter().any(|l| l.contains(&format!("Program {} invoke [2]", jup6()))), "{kind:?}/{slot}");
        assert_eq!(snap(&env), before);
    }
    // `destination_token_account` = dst (instead of None) is allowed (live API shape).
    let (mut s, _) = honest(&env, Kind::RouteV2, SOL);
    s.route[7] = AccountMeta::new(k.swap_usdc, false);
    expect_ok(run(&mut env, &s));
    let (mut s, _) = honest(&env, Kind::Route, SOL);
    s.route[4] = AccountMeta::new(k.swap_usdc, false);
    expect_ok(run(&mut env, &s));
    // Data of one layout with the accounts of another.
    let (mut s, _) = honest(&env, Kind::RouteV2, SOL);
    s.route = route_accounts(&env, Kind::Route, &[]);
    expect_err(run(&mut env, &s), "JupiterRoutePinMismatch");
    // Tail shorter than the program slot.
    let (mut s, _) = honest(&env, Kind::RouteV2, SOL);
    s.route.truncate(9);
    expect_err(run(&mut env, &s), "JupiterRoutePinMismatch");
}

#[test]
fn tc12_jupiter_program_elsewhere() {
    let Some(mut env) = new_env() else { return };
    fund_fee_inbox(&mut env, 2 * SOL);
    let (mut s, _) = honest(&env, Kind::RouteV2, SOL);
    s.fixed[9] = AccountMeta::new_readonly(mock_elsewhere(), false);
    expect_err(run(&mut env, &s), "InvalidProgramId");
    // A non-executable account at slot #9.
    let (mut s, _) = honest(&env, Kind::RouteV2, SOL);
    s.fixed[9] = AccountMeta::new_readonly(env.attacker.pubkey(), false);
    expect_err(run(&mut env, &s), "InvalidProgramId");
}

#[test]
fn tc13_arguments_and_forbidden_instructions() {
    let Some(mut env) = new_env() else { return };
    fund_fee_inbox(&mut env, 2 * SOL);
    let px = env.pam_px();
    let out = out_at(SOL, px, 998, 1000);
    let step = mock_step(mode::HONEST, out, 0);
    let mut cases: Vec<(Kind, Args)> = Vec::new();
    for kind in [Kind::RouteV2, Kind::SharedV2] {
        cases.push((kind, Args { platform_fee_bps: 5, ..Args::new(SOL) }));
        cases.push((kind, Args { positive_slippage_bps: 1, ..Args::new(SOL) }));
        cases.push((kind, Args::new(SOL + 1)));
        cases.push((kind, Args::new(SOL - 1)));
    }
    for kind in [Kind::Route, Kind::Shared] {
        cases.push((kind, Args { platform_fee_bps: 1, ..Args::new(SOL) }));
        cases.push((kind, Args::new(SOL + 1)));
        cases.push((kind, Args::new(SOL - 1)));
    }
    for (kind, a) in cases {
        let mut s = Swap::mock(&env, kind, SOL, mode::HONEST, out, 0);
        s.jup = jup_data(kind, &a, &step);
        expect_err(run(&mut env, &s), "JupiterArgsMismatch");
    }
    // Truncated v2 arguments (33 bytes, `jup_len` itself is valid).
    let mut s = Swap::mock(&env, Kind::RouteV2, SOL, mode::HONEST, out, 0);
    s.jup.truncate(33);
    expect_err(run(&mut env, &s), "JupiterArgsMismatch");
    // Every other Jupiter instruction (discriminators of the on-chain IDL).
    let forbidden: [[u8; 8]; 13] = [
        [0x3e, 0xc6, 0xd6, 0xc1, 0xd5, 0x9f, 0x6c, 0xd2], // claim
        [0x74, 0xce, 0x1b, 0xbf, 0xa6, 0x13, 0x00, 0x49], // claim_token
        [0x1a, 0x4a, 0xec, 0x97, 0x68, 0x40, 0xb7, 0xf9], // close_token
        [0xe8, 0xf2, 0xc5, 0xfd, 0xf0, 0x8f, 0x81, 0x34], // create_token_ledger
        [0x93, 0xf1, 0x7b, 0x64, 0xf4, 0x84, 0xae, 0x76], // create_token_account
        [0xcb, 0x81, 0x67, 0x85, 0xc5, 0x7d, 0x6b, 0x56], // close_wsol_token_account
        [0xd0, 0x33, 0xef, 0x97, 0x7b, 0x2b, 0xed, 0x5c], // exact_out_route
        [0x96, 0x56, 0x47, 0x74, 0xa7, 0x5d, 0x0e, 0x68], // route_with_token_ledger
        [0xe4, 0x55, 0xb9, 0x70, 0x4e, 0x4f, 0x4d, 0x02], // set_token_ledger
        [0xb0, 0xd1, 0x69, 0xa8, 0x9a, 0x7d, 0x45, 0x3e], // shared_accounts_exact_out_route
        [0xe6, 0x79, 0x8f, 0x50, 0x77, 0x9f, 0x6a, 0xaa], // shared_accounts_route_with_token_ledger
        [0x9d, 0x8a, 0xb8, 0x52, 0x15, 0xf4, 0xf3, 0x24], // exact_out_route_v2
        [0x35, 0x60, 0xe5, 0xca, 0xd8, 0xbb, 0xfa, 0x18], // shared_accounts_exact_out_route_v2
    ];
    for disc in forbidden {
        let mut s = Swap::mock(&env, Kind::RouteV2, SOL, mode::HONEST, out, 0);
        s.jup[..8].copy_from_slice(&disc);
        expect_err(run(&mut env, &s), "JupiterIxForbidden");
    }
    // Shape: jup_len outside 8..=512, or not matching the data.
    for len in [0usize, 7] {
        let mut s = Swap::mock(&env, Kind::RouteV2, SOL, mode::HONEST, out, 0);
        s.jup.truncate(len);
        expect_err(run(&mut env, &s), "InvalidInstructionData");
    }
    let mut s = Swap::mock(&env, Kind::RouteV2, SOL, mode::HONEST, out, 0);
    s.jup.resize(513, 0);
    expect_err(run(&mut env, &s), "InvalidInstructionData");
    let s = Swap::mock(&env, Kind::RouteV2, SOL, mode::HONEST, out, 0);
    let mut ix = s.ix(&env);
    ix.data.push(0);
    expect_err(env.send1(ix), "InvalidInstructionData");
}

#[test]
fn tc14_route_tail_size() {
    let Some(mut env) = new_env() else { return };
    fund_fee_inbox(&mut env, 2 * SOL);
    // Exactly 64 tail accounts (MAX_ROUTE_ACCOUNTS; the CPI trampoline frame,
    // U-27) passes.
    let (mut s, _) = honest(&env, Kind::RouteV2, SOL);
    while s.route.len() < 64 {
        s.route.push(AccountMeta::new_readonly(system_program(), false));
    }
    let m = expect_ok(run(&mut env, &s));
    eprintln!("tc14: 64-account route, CU {}", m.compute_units_consumed);
    // 65 → JupiterTooManyAccounts before anything else.
    s.route.push(AccountMeta::new_readonly(system_program(), false));
    expect_err(run(&mut env, &s), "JupiterTooManyAccounts");
    // No tail at all.
    let (mut s, _) = honest(&env, Kind::RouteV2, SOL);
    s.route.clear();
    expect_err(run(&mut env, &s), "JupiterTooManyAccounts");
}

#[test]
fn tc18_amount_bounds() {
    let Some(mut env) = new_env() else { return };
    fund_fee_inbox(&mut env, 2 * SWAP_MAX);
    for amount in [SWAP_MIN - 1, SWAP_MAX + 1, 0] {
        let (s, _) = honest(&env, Kind::RouteV2, amount);
        expect_err(run(&mut env, &s), "SwapAmountInvalid");
    }
    for amount in [SWAP_MIN, SWAP_MAX] {
        let (s, _) = honest(&env, Kind::RouteV2, amount);
        expect_ok(run(&mut env, &s));
    }
}

#[test]
fn tc19_not_top_level() {
    let Some(mut env) = new_env() else { return };
    fund_fee_inbox(&mut env, 2 * SOL);
    let (s, _) = honest(&env, Kind::RouteV2, SOL);
    let inner = s.ix(&env);
    // The mock (any program) calls tag 20 through CPI: `SJKCALL | data`.
    let mut accounts = vec![AccountMeta::new_readonly(env.k.program, false)];
    accounts.extend(inner.accounts.iter().cloned());
    let mut data = b"SJKCALL\0".to_vec();
    data.extend_from_slice(&inner.data);
    let outer = Instruction { program_id: mock_elsewhere(), accounts, data };
    expect_err(env.send1(outer), "NotTopLevel");
}

/// TC-22: the vault's own CU of tag 20 is at most 30k for every layout
/// (BUG-inflow-1 fixed: the route is validated once, `invoke_route` takes a
/// `ValidatedRoute`).
#[test]
fn tc22_compute_budget() {
    let Some(mut env) = new_env() else { return };
    let (report, worst) = tag20_cu_report(&mut env);
    assert!(worst <= 30_000, "TC-22: vault CU {worst} > 30k\n{}", report.join("\n"));
}

/// CU of tag 20 with an honest mock route of every layout, the vault's own
/// share (total − Jupiter mock), and where it goes: a call that stops right
/// after the fixed account checks (`SwapAmountInvalid`), one that stops after
/// the keeper check and the route validation (`JupiterAccountForbidden` on the
/// last tail account).
pub fn tag20_cu_report(env: &mut Env) -> (Vec<String>, u64) {
    fund_fee_inbox(env, 10 * SOL);
    let mut report = Vec::new();
    let mut worst = 0;
    for kind in ALL_KINDS {
        let (s, _) = honest(env, kind, SOL);
        let m = expect_ok(run(env, &s));
        let jup: u64 = consumed_by(&m.logs, &jup6()).into_iter().max().unwrap_or(0);
        let vault_total: u64 = consumed_by(&m.logs, &env.k.program).into_iter().max().unwrap();
        let ours = vault_total - jup;
        worst = worst.max(ours);
        report.push(format!("{kind:?}: tail {}, total {vault_total}, mock {jup}, vault {ours}", s.route.len()));
    }
    let stop_cu = |r: &TxResult, p: &Pubkey| consumed_by(logs_of(r), p).into_iter().max().unwrap_or(0);
    let (s, _) = honest(env, Kind::RouteV2, SWAP_MAX + 1);
    let r = run(env, &s);
    report.push(format!("stop at SwapAmountInvalid (fixed checks): {}", stop_cu(&r, &env.k.program)));
    let (mut s, _) = honest(env, Kind::RouteV2, SOL);
    s.jup[..8].copy_from_slice(&[0u8; 8]);
    let r = run(env, &s);
    report.push(format!("stop at JupiterIxForbidden (+ clock, keeper, min_out): {}", stop_cu(&r, &env.k.program)));
    let (mut s, _) = honest(env, Kind::RouteV2, SOL);
    s.route.push(AccountMeta::new_readonly(env.k.buyback_usdc, false));
    let r = run(env, &s);
    report.push(format!(
        "stop at JupiterAccountForbidden (+ args, pins, full scan of {} accounts): {}",
        s.route.len(),
        stop_cu(&r, &env.k.program)
    ));
    eprintln!("tag 20 CU:\n  {}", report.join("\n  "));
    (report, worst)
}

#[test]
fn tag20_cu_measurement() {
    // The numbers behind BUG-inflow-1, always printed; the SPEC §5.3.4 limit
    // for the keeper (1.4M) is far away.
    let Some(mut env) = new_env() else { return };
    let (_, worst) = tag20_cu_report(&mut env);
    assert!(worst <= 60_000, "vault CU {worst}");
}

#[test]
fn account_checks_of_the_fixed_part() {
    let Some(mut env) = new_env() else { return };
    fund_fee_inbox(&mut env, 2 * SOL);
    let k = env.k.clone();
    let other_wsol = Pubkey::new_from_array([0xC1; 32]);
    env.set_token(other_wsol, wsol_mint(), k.swap_authority, 0, true);
    let ro = AccountMeta::new_readonly;
    let cases: Vec<(usize, AccountMeta, &str)> = vec![
        (1, AccountMeta::new(env.attacker.pubkey(), false), "InvalidPda"),
        (2, ro(env.attacker.pubkey(), false), "InvalidPda"),
        (3, AccountMeta::new(other_wsol, false), "InvalidPda"),
        (4, AccountMeta::new(env.attacker_usdc, false), "InvalidPda"),
        (5, AccountMeta::new(env.attacker_usdc, false), "InvalidPda"),
        (7, ro(token_2022(), false), "InvalidProgramId"),
        (8, ro(token_program(), false), "InvalidProgramId"),
        (1, ro(k.fee_inbox, false), "AccountNotWritable"),
        (3, ro(k.swap_wsol, false), "AccountNotWritable"),
        (5, ro(k.vault_usdc, false), "AccountNotWritable"),
    ];
    for (i, meta, err) in cases {
        let (mut s, _) = honest(&env, Kind::RouteV2, SOL);
        // Keep the tail consistent with a read-only fixed slot.
        if !meta.is_writable {
            for r in s.route.iter_mut().filter(|r| r.pubkey == meta.pubkey) {
                r.is_writable = false;
            }
        }
        s.fixed[i] = meta;
        expect_err(run(&mut env, &s), err);
    }
    // Config of another program / wrong key.
    let (mut s, _) = honest(&env, Kind::RouteV2, SOL);
    s.fixed[0] = AccountMeta::new(env.attacker.pubkey(), false);
    expect_err(run(&mut env, &s), "InvalidConfigAccount");
}
