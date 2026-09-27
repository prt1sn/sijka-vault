// Copyright (c) 2026 prt1sn. All rights reserved.
//! Tag 20 against the real Jupiter v6 binary (dumped from mainnet) routing
//! through the real SPL token-swap program and a snapshot of a live SOL/USDC
//! pool (`tests/fixtures/inflow-fetch.sh`), with the account layout the live
//! Jupiter API returns for this pool (`swap-instructions`, 2026-09-26). Also
//! the U-21 / U-22 / U-23 experiments on the real Jupiter program.
//!
//! The vault's `usdc_mint` comes from `ember_state@40` at `initialize` (SPEC
//! §2.3), so this environment patches the fixture Ember state to the real
//! USDC mint before `initialize`. Tag 21 is not used here.

use std::path::Path;

use serde_json::Value;
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;

use crate::harness::*;
use crate::route::{DISC_ROUTE, DISC_ROUTE_V2, swap_data, swap_fixed};
use crate::swap::SOL;

pub fn token_swap_program() -> Pubkey {
    pk("SwaPpA9LAaLfeLi3a68M4DjnLqgtticKg6CnyNwgAC8")
}
pub fn real_usdc() -> Pubkey {
    pk("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
}
/// Jupiter's Anchor event authority `PDA(["__event_authority"], JUP6)` as in
/// the live API responses.
pub fn jup_event_authority() -> Pubkey {
    pk("D8cy77BBepLMngZx6ZukaTff5hCt1HrWyKk3Hnd9oitf")
}

/// Swap enum index of `TokenSwap` in the on-chain Jupiter IDL.
const SWAP_TOKEN_SWAP: u8 = 3;
/// Anchor `InstructionDidNotDeserialize`.
const ANCHOR_DID_NOT_DESERIALIZE: u32 = 102;
/// Jupiter `MissingPlatformFeeAccount`.
const JUP_MISSING_PLATFORM_FEE_ACCOUNT: u32 = 6003;
/// Jupiter `InvalidTokenAccount`.
const JUP_INVALID_TOKEN_ACCOUNT: u32 = 6025;

pub struct Pool {
    pub state: Pubkey,
    pub authority: Pubkey,
    pub vault_sol: Pubkey,
    pub vault_usdc: Pubkey,
    pub mint: Pubkey,
    pub fee: Pubkey,
    /// Jupiter program authority id 4 and its wSOL / USDC token accounts
    /// (`shared_accounts_route*`).
    pub prog_authority: Pubkey,
    pub prog_wsol: Pubkey,
    pub prog_usdc: Pubkey,
}

/// Jupiter program authority `PDA(["authority", id], JUP6)`.
pub fn jup_program_authority(id: u8) -> Pubkey {
    Pubkey::find_program_address(&[b"authority", &[id]], &jup6()).0
}

fn snapshot(dir: &Path) -> Vec<(Pubkey, Account)> {
    let keys: Vec<String> =
        serde_json::from_str(&std::fs::read_to_string(dir.join("jupiter_snapshot.keys.json")).unwrap()).unwrap();
    let v: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("jupiter_snapshot.json")).unwrap()).unwrap();
    let values = v["result"]["value"].as_array().expect("getMultipleAccounts result");
    keys.iter()
        .zip(values)
        .map(|(k, a)| {
            let data = b64(a["data"][0].as_str().unwrap());
            let acc = Account {
                lamports: a["lamports"].as_u64().unwrap(),
                data,
                owner: pk(a["owner"].as_str().unwrap()),
                executable: a["executable"].as_bool().unwrap(),
                rent_epoch: 0,
            };
            (pk(k), acc)
        })
        .collect()
}

fn b64(s: &str) -> Vec<u8> {
    // Same decoder as the event parser.
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => continue,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

fn real_env() -> Option<(Env, Pool)> {
    let dir = fixture_dir()?;
    let snap = snapshot(&dir);
    let state_data = snap[0].1.data.clone();
    assert_eq!(snap[0].1.owner, token_swap_program());
    assert_eq!(state_data.len(), 324);
    let pool = Pool {
        state: snap[0].0,
        authority: Pubkey::create_program_address(&[snap[0].0.as_ref(), &[state_data[2]]], &token_swap_program())
            .unwrap(),
        vault_sol: key_at(&state_data, 35),
        vault_usdc: key_at(&state_data, 67),
        mint: key_at(&state_data, 99),
        fee: key_at(&state_data, 195),
        prog_authority: jup_program_authority(4),
        prog_wsol: snap[6].0,
        prog_usdc: snap[7].0,
    };
    assert_eq!(pool.prog_authority, pk("4xDsmeTWPNjgSVSS1VTfzFq3iHZhp77ffPkAmkZkdu71"));
    for (i, mint) in [(6usize, wsol_mint()), (7, real_usdc())] {
        let a = &snap[i].1;
        assert_eq!(a.owner, token_program());
        assert_eq!(key_at(&a.data, 0), mint);
        assert_eq!(key_at(&a.data, 32), pool.prog_authority, "program authority token account {i}");
    }
    assert_eq!(pool.vault_sol, snap[1].0);
    assert_eq!(pool.vault_usdc, snap[2].0);
    assert_eq!(pool.mint, snap[3].0);
    assert_eq!(pool.fee, snap[4].0);
    assert_eq!(key_at(&state_data, 131), wsol_mint());
    assert_eq!(key_at(&state_data, 163), real_usdc());
    let extra = vec![
        (jup6(), dir.join("jupiter_v6-mainnet.so")),
        (token_swap_program(), dir.join("spl_token_swap-mainnet.so")),
    ];
    let opts = Opts { mock_pools: false, ..Opts::default() };
    let env = Env::with_programs(opts, &extra, move |ctx| {
        for (k, mut a) in snap {
            // Mainnet rent is lower than LiteSVM's default (SPEC §5.3.1:
            // rent(0) = 650 240 on mainnet vs 890 880 here): accounts created
            // recently on mainnet would be rent-paying in LiteSVM, and the
            // runtime refuses to write them (InsufficientFundsForRent).
            let min = ctx.svm.minimum_balance_for_rent_exemption(a.data.len());
            if a.lamports < min {
                eprintln!("snapshot {k}: {} lamports < LiteSVM rent-exempt {min}, topped up", a.lamports);
                a.lamports = min;
            }
            ctx.svm.set_account(k, a).unwrap();
        }
        let mut es = ctx.svm.get_account(&ember_state()).unwrap();
        es.data[40..72].copy_from_slice(real_usdc().as_ref());
        ctx.svm.set_account(ember_state(), es).unwrap();
    })?;
    assert_eq!(env.k.usdc_mint, real_usdc());
    Some((env, pool))
}

/// Pool spot price in USDC atoms per SOL.
fn spot_px(env: &Env, pool: &Pool) -> u64 {
    let a = env.token_amount(&pool.vault_sol) as u128;
    let b = env.token_amount(&pool.vault_usdc) as u128;
    (b * 1_000_000_000 / a) as u64
}

/// The TokenSwap step accounts of the live API response for this pool.
fn step_accounts(pool: &Pool, user: &Pubkey, src: &Pubkey, dst: &Pubkey) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new_readonly(token_swap_program(), false),
        AccountMeta::new_readonly(token_program(), false),
        AccountMeta::new_readonly(pool.state, false),
        AccountMeta::new_readonly(pool.authority, false),
        AccountMeta::new_readonly(*user, false),
        AccountMeta::new(*src, false),
        AccountMeta::new(pool.vault_sol, false),
        AccountMeta::new(pool.vault_usdc, false),
        AccountMeta::new(*dst, false),
        AccountMeta::new(pool.mint, false),
        AccountMeta::new(pool.fee, false),
    ]
}

/// `route_v2` accounts (live API shape: destination_token_account = dst).
fn route_v2_accounts(pool: &Pool, user: &Pubkey, src: &Pubkey, dst: &Pubkey, signer: bool) -> Vec<AccountMeta> {
    let mut v = vec![
        AccountMeta::new_readonly(*user, signer),
        AccountMeta::new(*src, false),
        AccountMeta::new(*dst, false),
        AccountMeta::new_readonly(wsol_mint(), false),
        AccountMeta::new_readonly(real_usdc(), false),
        AccountMeta::new_readonly(token_program(), false),
        AccountMeta::new_readonly(token_program(), false),
        AccountMeta::new(*dst, false),
        AccountMeta::new_readonly(jup_event_authority(), false),
        AccountMeta::new_readonly(jup6(), false),
    ];
    v.extend(step_accounts(pool, user, src, dst));
    v
}

/// `route` (v1) accounts (live API shape).
fn route_v1_accounts(
    pool: &Pool,
    user: &Pubkey,
    src: &Pubkey,
    dst: &Pubkey,
    signer: bool,
    fee_account: Option<Pubkey>,
) -> Vec<AccountMeta> {
    let fee = match fee_account {
        Some(k) => AccountMeta::new(k, false),
        None => AccountMeta::new_readonly(jup6(), false),
    };
    let mut v = vec![
        AccountMeta::new_readonly(token_program(), false),
        AccountMeta::new_readonly(*user, signer),
        AccountMeta::new(*src, false),
        AccountMeta::new(*dst, false),
        AccountMeta::new(*dst, false),
        AccountMeta::new_readonly(real_usdc(), false),
        fee,
        AccountMeta::new_readonly(jup_event_authority(), false),
        AccountMeta::new_readonly(jup6(), false),
    ];
    v.extend(step_accounts(pool, user, src, dst));
    v
}

fn route_v2_data(in_amount: u64, quoted: u64, pf: u16, pos: u16) -> Vec<u8> {
    let mut d = DISC_ROUTE_V2.to_vec();
    d.extend_from_slice(&in_amount.to_le_bytes());
    d.extend_from_slice(&quoted.to_le_bytes());
    d.extend_from_slice(&50u16.to_le_bytes());
    d.extend_from_slice(&pf.to_le_bytes());
    d.extend_from_slice(&pos.to_le_bytes());
    d.extend_from_slice(&1u32.to_le_bytes());
    d.extend_from_slice(&[SWAP_TOKEN_SWAP, 0x10, 0x27, 0, 1]);
    d
}

/// `shared_accounts_route_v2` accounts (live API / `/swap/v2/build` shape):
/// Jupiter moves the input to its program-authority account, the AMM step
/// runs on the program-authority accounts, the output goes to `dst`.
fn shared_v2_accounts(pool: &Pool, user: &Pubkey, src: &Pubkey, dst: &Pubkey) -> Vec<AccountMeta> {
    let mut v = vec![
        AccountMeta::new_readonly(pool.prog_authority, false),
        AccountMeta::new_readonly(*user, false),
        AccountMeta::new(*src, false),
        AccountMeta::new(pool.prog_wsol, false),
        AccountMeta::new(pool.prog_usdc, false),
        AccountMeta::new(*dst, false),
        AccountMeta::new_readonly(wsol_mint(), false),
        AccountMeta::new_readonly(real_usdc(), false),
        AccountMeta::new_readonly(token_program(), false),
        AccountMeta::new_readonly(token_program(), false),
        AccountMeta::new_readonly(jup_event_authority(), false),
        AccountMeta::new_readonly(jup6(), false),
    ];
    v.extend(step_accounts(pool, &pool.prog_authority, &pool.prog_wsol, &pool.prog_usdc));
    v
}

fn shared_v2_data(id: u8, in_amount: u64, quoted: u64) -> Vec<u8> {
    let mut d = crate::route::DISC_SHARED_V2.to_vec();
    d.push(id);
    d.extend_from_slice(&in_amount.to_le_bytes());
    d.extend_from_slice(&quoted.to_le_bytes());
    d.extend_from_slice(&50u16.to_le_bytes());
    d.extend_from_slice(&0u16.to_le_bytes());
    d.extend_from_slice(&0u16.to_le_bytes());
    d.extend_from_slice(&1u32.to_le_bytes());
    d.extend_from_slice(&[SWAP_TOKEN_SWAP, 0x10, 0x27, 0, 1]);
    d
}

fn route_v1_data(in_amount: u64, quoted: u64, pf: u8) -> Vec<u8> {
    let mut d = DISC_ROUTE.to_vec();
    d.extend_from_slice(&1u32.to_le_bytes());
    d.extend_from_slice(&[SWAP_TOKEN_SWAP, 100, 0, 1]);
    d.extend_from_slice(&in_amount.to_le_bytes());
    d.extend_from_slice(&quoted.to_le_bytes());
    d.extend_from_slice(&50u16.to_le_bytes());
    d.push(pf);
    d
}

fn fee_inbox_surplus(env: &mut Env, lamports: u64) {
    let fi = env.k.fee_inbox;
    let want = env.rent(0) + lamports;
    let have = env.lamports(&fi);
    if want > have {
        env.transfer_lamports(&fi, want - have);
    }
}

/// Tag 20 signed by the keeper (the fee payer of `send`) with its `min_out`
/// (SPEC v4: no oracle).
fn vault_swap(env: &mut Env, amount: u64, min_out: u64, route: Vec<AccountMeta>, jup: Vec<u8>) -> TxResult {
    let mut accounts = swap_fixed(env, env.keeper.pubkey());
    accounts.extend(route);
    let ix = Instruction { program_id: env.k.program, accounts, data: swap_data(amount, min_out, &jup) };
    env.send(vec![cu_limit(1_400_000), ix], &[])
}

fn custom_code(r: &TxResult) -> Option<u32> {
    let s = format!("{:?}", r.as_ref().err()?.err);
    let i = s.find("Custom(")? + 7;
    s[i..].split(')').next()?.parse().ok()
}

#[test]
fn real_jupiter_shared_route_v2_through_the_vault() {
    // The default instruction of `/swap/v2/build` (U-39).
    let Some((mut env, pool)) = real_env() else { return };
    let spot = spot_px(&env, &pool);
    // The keeper quotes the pool spot minus its 50 bps slippage.
    let amount = SOL / 10;
    fee_inbox_surplus(&mut env, 2 * SOL);
    let floor = keeper_min_out(amount, spot, KEEPER_SLIPPAGE_BPS);
    let k = env.k.clone();
    let b0 = env.token_amount(&pool.vault_usdc);
    let (pw0, pu0) = (env.token_amount(&pool.prog_wsol), env.token_amount(&pool.prog_usdc));
    let route = shared_v2_accounts(&pool, &k.swap_authority, &k.swap_wsol, &k.swap_usdc);
    let m = expect_ok(vault_swap(&mut env, amount, floor, route, shared_v2_data(4, amount, floor)));
    let e = event(&m.logs, "SJKEVSWI");
    let paid = b0 - env.token_amount(&pool.vault_usdc);
    assert_eq!(e.u("jup_kind"), 3);
    assert_eq!(e.u("received"), paid);
    assert!(paid >= floor);
    assert!(e.u("spent") <= amount);
    eprintln!(
        "real shared_accounts_route_v2: spent {}, out {paid}, program-authority accounts wSOL {pw0} → {}, USDC {pu0} → {}",
        e.u("spent"),
        env.token_amount(&pool.prog_wsol),
        env.token_amount(&pool.prog_usdc)
    );
}

#[test]
fn real_jupiter_route_v2_through_the_vault() {
    let Some((mut env, pool)) = real_env() else { return };
    let spot = spot_px(&env, &pool);
    eprintln!("pool spot {spot} atoms/SOL (the keeper's quote)");
    let amount = SOL / 10;
    fee_inbox_surplus(&mut env, 2 * SOL);
    let floor = keeper_min_out(amount, spot, KEEPER_SLIPPAGE_BPS);
    let k = env.k.clone();
    let b0 = env.token_amount(&pool.vault_usdc);
    let a0 = env.token_amount(&pool.vault_sol);
    let route = route_v2_accounts(&pool, &k.swap_authority, &k.swap_wsol, &k.swap_usdc, false);
    let m = expect_ok(vault_swap(&mut env, amount, floor, route, route_v2_data(amount, floor, 0, 0)));
    let e = event(&m.logs, "SJKEVSWI");
    let paid = b0 - env.token_amount(&pool.vault_usdc);
    let taken = env.token_amount(&pool.vault_sol) - a0;
    assert_eq!(e.u("received"), paid, "everything the pool paid reached the vault");
    assert_eq!(e.u("jup_kind"), 2);
    // SPL token-swap moves only `source_amount_swapped` (curve rounding): a
    // few lamports of amount_in can stay on swap_wsol (SPEC §5.3.4: the
    // leftover is pending wSOL of the next call).
    assert_eq!(e.u("spent"), taken, "spent = what the pool received");
    assert!(taken <= amount && taken > 0);
    assert_eq!(e.u("wsol_left"), amount - taken);
    assert_eq!(env.token_amount(&k.swap_wsol), amount - taken);
    eprintln!("real route_v2: spent {taken} of {amount} (left on swap_wsol {})", amount - taken);
    assert!(paid >= floor);
    assert_eq!(env.token_amount(&k.vault_usdc), paid);
    assert_eq!(env.token_amount(&k.swap_usdc), 0);
    let jup_cu = consumed_by(&m.logs, &jup6()).into_iter().max().unwrap_or(0);
    let total = consumed_by(&m.logs, &k.program).into_iter().max().unwrap();
    eprintln!(
        "real route_v2: out {paid} (floor {floor}), CU vault {total} = Jupiter {jup_cu} + own {}",
        total - jup_cu
    );
    // CPI depth used: vault(1) → Jupiter(2) → token-swap(3) → Token(4).
    assert!(m.logs.iter().any(|l| l.contains(&format!("Program {} invoke [3]", token_swap_program()))));
    assert!(m.logs.iter().any(|l| l.contains(&format!("Program {} invoke [4]", token_program()))));
}

#[test]
fn real_jupiter_route_v1_through_the_vault() {
    let Some((mut env, pool)) = real_env() else { return };
    let spot = spot_px(&env, &pool);
    let amount = SOL / 10;
    fee_inbox_surplus(&mut env, 2 * SOL);
    let floor = keeper_min_out(amount, spot, KEEPER_SLIPPAGE_BPS);
    let k = env.k.clone();
    let route = route_v1_accounts(&pool, &k.swap_authority, &k.swap_wsol, &k.swap_usdc, false, None);
    let m = expect_ok(vault_swap(&mut env, amount, floor, route, route_v1_data(amount, floor, 0)));
    let e = event(&m.logs, "SJKEVSWI");
    assert_eq!(e.u("jup_kind"), 0);
    assert!(e.u("received") >= floor);
}

#[test]
fn real_jupiter_underpaying_pool_is_refused() {
    let Some((mut env, pool)) = real_env() else { return };
    // The keeper quoted 2% above the pool (the market moved after the
    // quote): honest Jupiter + honest pool, but below the keeper's min_out →
    // the vault refuses (SwapOutputBelowMin), rollback.
    let spot = spot_px(&env, &pool);
    let min_out = keeper_min_out(SOL / 10, spot * 102 / 100, KEEPER_SLIPPAGE_BPS);
    let amount = SOL / 10;
    fee_inbox_surplus(&mut env, 2 * SOL);
    let k = env.k.clone();
    let route = route_v2_accounts(&pool, &k.swap_authority, &k.swap_wsol, &k.swap_usdc, false);
    let fi = env.lamports(&k.fee_inbox);
    expect_err(vault_swap(&mut env, amount, min_out, route, route_v2_data(amount, 1, 0, 0)), "SwapOutputBelowMin");
    assert_eq!(env.lamports(&k.fee_inbox), fi);
}

/// U-21 through the vault: v1 data whose real `in_amount` is 2× the vault's
/// `amount_in`, followed by a forged 19-byte tail with `in_amount = amount_in`
/// and `platform_fee_bps = 0`. The vault's tail parse sees the forged tail;
/// Jupiter (Anchor) reads the real arguments and ignores the rest. The balance
/// check is what stops it (SwapInputExceeded).
#[test]
fn u21_forged_v1_tail_is_stopped_by_the_balance_check() {
    let Some((mut env, pool)) = real_env() else { return };
    let spot = spot_px(&env, &pool);
    let amount = SOL / 10;
    let k = env.k.clone();
    // Enough wSOL pending for Jupiter to take 2× amount_in.
    env.transfer_lamports(&k.swap_wsol, 3 * amount);
    let floor = keeper_min_out(amount, spot, KEEPER_SLIPPAGE_BPS);
    let mut jup = route_v1_data(2 * amount, floor, 0);
    let mut forged = Vec::new();
    forged.extend_from_slice(&amount.to_le_bytes());
    forged.extend_from_slice(&floor.to_le_bytes());
    forged.extend_from_slice(&50u16.to_le_bytes());
    forged.push(0);
    jup.extend_from_slice(&forged);
    let route = route_v1_accounts(&pool, &k.swap_authority, &k.swap_wsol, &k.swap_usdc, false, None);
    let r = vault_swap(&mut env, amount, floor, route, jup);
    let code = custom_code(&r);
    eprintln!("U-21 via vault: {:?}", r.as_ref().err().map(|f| &f.err));
    if code == Some(ANCHOR_DID_NOT_DESERIALIZE) {
        panic!("U-21: Jupiter rejects trailing bytes (InstructionDidNotDeserialize) — the v1 tail cannot be forged");
    }
    expect_err(r, "SwapInputExceeded");
}

struct User {
    kp: Keypair,
    wsol: Pubkey,
    usdc: Pubkey,
}

fn user(env: &mut Env) -> User {
    let kp = Keypair::new_from_array([0x55; 32]);
    env.svm().airdrop(&kp.pubkey(), 10 * SOL).unwrap();
    let wsol = Pubkey::new_from_array([0x56; 32]);
    let usdc = Pubkey::new_from_array([0x57; 32]);
    env.set_token(wsol, wsol_mint(), kp.pubkey(), 5 * SOL, true);
    env.set_token(usdc, real_usdc(), kp.pubkey(), 0, false);
    User { kp, wsol, usdc }
}

fn direct(env: &mut Env, u: &User, accounts: Vec<AccountMeta>, data: Vec<u8>) -> TxResult {
    let ix = Instruction { program_id: jup6(), accounts, data };
    let kp = u.kp.insecure_clone();
    env.send_as(&kp, vec![cu_limit(1_400_000), ix], &[])
}

/// U-21 / U-22 / U-23 directly on the real Jupiter program (top level, a
/// wallet as the user).
#[test]
fn u21_u22_u23_real_jupiter_arguments() {
    let Some((mut env, pool)) = real_env() else { return };
    let u = user(&mut env);
    let amount = SOL / 10;
    let pk_u = u.kp.pubkey();
    let mut report = Vec::new();

    // Baseline v1.
    let acc = route_v1_accounts(&pool, &pk_u, &u.wsol, &u.usdc, true, None);
    let r = direct(&mut env, &u, acc.clone(), route_v1_data(amount, 1, 0));
    let base_out = env.token_amount(&u.usdc);
    report.push(format!("v1 baseline: {:?}, out {base_out}", r.as_ref().err().map(|f| &f.err)));
    expect_ok(r);

    // U-21: 19 extra bytes after the real arguments.
    let mut d = route_v1_data(amount, 1, 0);
    d.extend_from_slice(&[0xAB; 19]);
    let before = env.token_amount(&u.usdc);
    let r21 = direct(&mut env, &u, acc.clone(), d);
    report.push(format!(
        "U-21 v1 + 19 bytes: {:?}, out {}",
        r21.as_ref().err().map(|f| &f.err),
        env.token_amount(&u.usdc) - before
    ));

    // U-22: platform_fee_bps = 1 with platform_fee_account = None.
    let r22 = direct(&mut env, &u, acc.clone(), route_v1_data(amount, 1, 1));
    report.push(format!(
        "U-22 v1 pf=1, fee account None: {:?} (code {:?})",
        r22.as_ref().err().map(|f| &f.err),
        custom_code(&r22)
    ));

    // U-22 control: pf = 1 with a fee account (a USDC account of someone else).
    let fee_acc = Pubkey::new_from_array([0x58; 32]);
    env.set_token(fee_acc, real_usdc(), Pubkey::new_from_array([0x59; 32]), 0, false);
    let acc_fee = route_v1_accounts(&pool, &pk_u, &u.wsol, &u.usdc, true, Some(fee_acc));
    let before = env.token_amount(&u.usdc);
    let r22c = direct(&mut env, &u, acc_fee, route_v1_data(amount, 1, 100));
    report.push(format!(
        "U-22 control v1 pf=100 with fee account: {:?}, user +{}, fee account +{}",
        r22c.as_ref().err().map(|f| &f.err),
        env.token_amount(&u.usdc) - before,
        env.token_amount(&fee_acc)
    ));

    // U-23: route_v2 with positive_slippage_bps and a low quote.
    let acc2 = route_v2_accounts(&pool, &pk_u, &u.wsol, &u.usdc, true);
    let before = env.token_amount(&u.usdc);
    let b0 = env.token_amount(&pool.vault_usdc);
    let r23b = direct(&mut env, &u, acc2.clone(), route_v2_data(amount, 1, 0, 0));
    let (user_b, pool_b) = (env.token_amount(&u.usdc) - before, b0 - env.token_amount(&pool.vault_usdc));
    report.push(format!("v2 baseline: {:?}, user +{user_b}, pool paid {pool_b}", r23b.as_ref().err().map(|f| &f.err)));
    let before = env.token_amount(&u.usdc);
    let b0 = env.token_amount(&pool.vault_usdc);
    let quoted = pool_b / 2;
    let r23 = direct(&mut env, &u, acc2.clone(), route_v2_data(amount, quoted, 0, 5_000));
    let (user_p, pool_p) = (env.token_amount(&u.usdc) - before, b0 - env.token_amount(&pool.vault_usdc));
    report.push(format!(
        "U-23 v2 positive_slippage_bps=5000, quoted {quoted}: {:?}, user +{user_p}, pool paid {pool_p}",
        r23.as_ref().err().map(|f| &f.err)
    ));
    // v2 platform_fee_bps without any fee account.
    let r23f = direct(&mut env, &u, acc2.clone(), route_v2_data(amount, 1, 100, 0));
    report.push(format!(
        "v2 platform_fee_bps=100: {:?} (code {:?})",
        r23f.as_ref().err().map(|f| &f.err),
        custom_code(&r23f)
    ));
    // Hypothesis: route_v2 takes the fee account as the first remaining
    // account when platform_fee_bps > 0 or positive_slippage_bps > 0.
    let with_fee = |fee: Pubkey| {
        let mut a = acc2.clone();
        a.insert(10, AccountMeta::new(fee, false));
        a
    };
    let fee_pf = Pubkey::new_from_array([0x5A; 32]);
    env.set_token(fee_pf, real_usdc(), Pubkey::new_from_array([0x59; 32]), 0, false);
    let before = env.token_amount(&u.usdc);
    let b0 = env.token_amount(&pool.vault_usdc);
    let r23fa = direct(&mut env, &u, with_fee(fee_pf), route_v2_data(amount, 1, 100, 0));
    let (user_f, pool_f) = (env.token_amount(&u.usdc) - before, b0 - env.token_amount(&pool.vault_usdc));
    report.push(format!(
        "v2 platform_fee_bps=100 + fee account first in the tail: {:?} (code {:?}), user +{user_f}, pool paid {pool_f}, fee account +{}",
        r23fa.as_ref().err().map(|f| &f.err),
        custom_code(&r23fa),
        env.token_amount(&fee_pf)
    ));
    let fee_pos = Pubkey::new_from_array([0x5B; 32]);
    env.set_token(fee_pos, real_usdc(), Pubkey::new_from_array([0x59; 32]), 0, false);
    let before = env.token_amount(&u.usdc);
    let b0 = env.token_amount(&pool.vault_usdc);
    let r23pa = direct(&mut env, &u, with_fee(fee_pos), route_v2_data(amount, quoted, 0, 5_000));
    let (user_s, pool_s) = (env.token_amount(&u.usdc) - before, b0 - env.token_amount(&pool.vault_usdc));
    report.push(format!(
        "U-23 v2 positive_slippage_bps=5000, quoted {quoted} + fee account first in the tail: {:?} (code {:?}), user +{user_s}, pool paid {pool_s}, fee account +{}",
        r23pa.as_ref().err().map(|f| &f.err),
        custom_code(&r23pa),
        env.token_amount(&fee_pos)
    ));
    // Same share with a quote close to the output and with a smaller share:
    // does the cut depend on `quoted_out`?
    for (q, pos) in [(pool_b * 99 / 100, 5_000u16), (1, 1_000), (pool_b * 99 / 100, 1_000)] {
        let fee_x = Pubkey::new_unique();
        env.set_token(fee_x, real_usdc(), Pubkey::new_from_array([0x59; 32]), 0, false);
        let before = env.token_amount(&u.usdc);
        let b0 = env.token_amount(&pool.vault_usdc);
        let r = direct(&mut env, &u, with_fee(fee_x), route_v2_data(amount, q, 0, pos));
        report.push(format!(
            "U-23 v2 positive_slippage_bps={pos}, quoted {q} + fee account: {:?}, user +{}, pool paid {}, fee account +{}",
            r.as_ref().err().map(|f| &f.err),
            env.token_amount(&u.usdc) - before,
            b0 - env.token_amount(&pool.vault_usdc),
            env.token_amount(&fee_x)
        ));
    }

    eprintln!("real Jupiter experiments:\n  {}", report.join("\n  "));
    let rep = report.join("\n");
    // U-21: Anchor ignores bytes after the real arguments.
    assert!(r21.is_ok(), "U-21\n{rep}");
    // U-22: v1 with pf > 0 and no fee account is refused (no fee leaks). The
    // error is 6025 InvalidTokenAccount (the None placeholder, the Jupiter
    // program id, is not a token account), not 6003 as SPEC §10.1 guessed.
    assert!(r22.is_err(), "U-22\n{rep}");
    assert_eq!(custom_code(&r22), Some(JUP_INVALID_TOKEN_ACCOUNT), "U-22 error code\n{rep}");
    assert_ne!(custom_code(&r22), Some(JUP_MISSING_PLATFORM_FEE_ACCOUNT));
    // With a fee account the fee is taken from the output (the leak the
    // vault's fee-slot pin prevents).
    assert!(r22c.is_ok() && env.token_amount(&fee_acc) > 0, "U-22 control\n{rep}");
    // v2: pf / positive slippage without a fee account are refused.
    assert!(r23.is_err() && r23f.is_err(), "U-23\n{rep}");
}
