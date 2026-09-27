// Copyright (c) 2026 prt1sn. All rights reserved.
//! `bb_swap_usdc_to_sol` (tag 43) with the mock Jupiter (SPEC §5.5.7, §5.3.3):
//! TD-40…TD-51, TD-64, TD-65, TD-67. Token programs are the mainnet
//! binaries. SPEC v4 (DECISIONS §23 item 4): the swap is signed by the keeper
//! key with the keeper's `min_out`; the program reads no oracle. The tests
//! quote the SOL price of the mainnet PerpAssetMap snapshot, like a keeper
//! quoting Jupiter.

use sha2::{Digest, Sha256};
use sijka_vault::constants as c;
use sijka_vault::error::SijkaError as E;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;

use crate::harness::*;
use crate::mocks::{JupCfg, JupMode, jup_reserve_authority, set_jup};

pub struct SwapEnv {
    pub reserve_usdc: Pubkey,
    pub reserve_wsol: Pubkey,
    pub event_authority: Pubkey,
}

pub fn pam_key(v: &Vault) -> Pubkey {
    key_at(&v.data(&pk(c::PHOENIX_GLOBAL_CONFIG)), 360)
}

/// Offset of the live SOL entry in the PerpAssetMap.
fn sol_entry(v: &Vault) -> usize {
    let d = v.data(&pam_key(v));
    let used = u32_at(&d, 32) as usize;
    (0..used)
        .map(|i| 48 + 1584 * i)
        .find(|e| &d[*e..*e + 4] == b"SOL\0" && d[*e + 1466] == 0)
        .expect("SOL entry in the PAM snapshot")
}

/// The keeper's quote: `px = mark·tick·10^bld` of the snapshot (USDC atoms
/// per SOL). Only the tests read it (SPEC v4: no oracle in the program).
pub fn sol_px(v: &Vault) -> u64 {
    let e = sol_entry(v);
    let d = v.data(&pam_key(v));
    let bld = d[e + 962] as i8;
    u64_at(&d, e + 40) * u64_at(&d, e + 952) * 10u64.pow(u32::from(bld.unsigned_abs()))
}

/// The keeper's default slippage for tag 43 (SPEC §5.5.7: quote minus 50 bps).
pub const KEEPER_SWAP_SLIPPAGE_BPS: u16 = 50;

/// The keeper's `min_out` of tag 43: `⌈amount·10⁹·(10⁴ − slippage)/(px·10⁴)⌉`.
pub fn keeper_min_out(amount: u64, px: u64, slippage: u16) -> u64 {
    (u128::from(amount) * 1_000_000_000 * u128::from(10_000 - slippage)).div_ceil(u128::from(px) * 10_000) as u64
}

/// Fair lamports for `amount` USDC atoms at `px`.
pub fn fair_out(amount: u64, px: u64) -> u64 {
    (u128::from(amount) * 1_000_000_000 / u128::from(px)) as u64
}

/// Fund `buyback_usdc`, give `buyback_authority` a float, set up the mock
/// Jupiter's reserves.
pub fn setup_swap(v: &mut Vault, usdc_amount: u64) -> SwapEnv {
    let k0 = v.k.buyback_authority;
    let bb = v.k.buyback_usdc;
    v.set_token_account(bb, tokenkeg(), usdc(), k0, usdc_amount);
    v.fund_authority(LAMPORTS_PER_SOL);
    let ra = jup_reserve_authority();
    let reserve_usdc = Keypair::new().pubkey();
    v.set_token_account(reserve_usdc, tokenkeg(), usdc(), ra, 0);
    let reserve_wsol = Keypair::new().pubkey();
    v.set_token_account(reserve_wsol, tokenkeg(), wsol(), ra, 10_000 * LAMPORTS_PER_SOL);
    SwapEnv { reserve_usdc, reserve_wsol, event_authority: Keypair::new().pubkey() }
}

/// Jupiter `route_v2` data: `in_amount`, `quoted_out`, slippage, platform fee,
/// positive slippage, empty route plan (34 bytes, SPEC §5.3.3).
pub fn route_v2_data(in_amount: u64, platform_fee_bps: u16, positive_slippage_bps: u16) -> Vec<u8> {
    let mut d = c::JUP_ROUTE_V2.to_vec();
    d.extend_from_slice(&in_amount.to_le_bytes());
    d.extend_from_slice(&1u64.to_le_bytes());
    d.extend_from_slice(&50u16.to_le_bytes());
    d.extend_from_slice(&platform_fee_bps.to_le_bytes());
    d.extend_from_slice(&positive_slippage_bps.to_le_bytes());
    d.extend_from_slice(&0u32.to_le_bytes());
    d
}

/// Route accounts in the `route_v2` layout plus the mock's reserves.
pub fn route_accounts(v: &Vault, env: &SwapEnv) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new_readonly(v.k.swap_authority, false),
        AccountMeta::new(v.k.swap_usdc, false),
        AccountMeta::new(v.k.bb_unwrap, false),
        AccountMeta::new_readonly(usdc(), false),
        AccountMeta::new_readonly(wsol(), false),
        AccountMeta::new_readonly(tokenkeg(), false),
        AccountMeta::new_readonly(tokenkeg(), false),
        AccountMeta::new_readonly(jup_program(), false),
        AccountMeta::new_readonly(env.event_authority, false),
        AccountMeta::new_readonly(jup_program(), false),
        AccountMeta::new(env.reserve_usdc, false),
        AccountMeta::new(env.reserve_wsol, false),
        AccountMeta::new_readonly(jup_reserve_authority(), false),
    ]
}

/// Tag 43 signed by the keeper (#12, SPEC v4; it was the oracle) with the
/// keeper's `min_out`.
pub fn swap_ix_with(v: &Vault, amount_in: u64, min_out: u64, jup: Vec<u8>, route: Vec<AccountMeta>) -> Instruction {
    let mut d = vec![43u8];
    d.extend_from_slice(&amount_in.to_le_bytes());
    d.extend_from_slice(&min_out.to_le_bytes());
    d.extend_from_slice(&(jup.len() as u16).to_le_bytes());
    d.extend_from_slice(&jup);
    let mut accounts = vec![
        AccountMeta::new(v.k.buyback_state, false),
        AccountMeta::new_readonly(v.k.config, false),
        AccountMeta::new_readonly(ix_sysvar(), false),
        AccountMeta::new(v.k.buyback_authority, false),
        AccountMeta::new(v.k.buyback_usdc, false),
        AccountMeta::new_readonly(v.k.swap_authority, false),
        AccountMeta::new(v.k.swap_usdc, false),
        AccountMeta::new(v.k.bb_unwrap, false),
        AccountMeta::new_readonly(wsol(), false),
        AccountMeta::new_readonly(usdc(), false),
        AccountMeta::new_readonly(tokenkeg(), false),
        AccountMeta::new_readonly(system(), false),
        AccountMeta::new_readonly(v.keeper.pubkey(), true),
        AccountMeta::new_readonly(jup_program(), false),
        AccountMeta::new_readonly(v.k.bb_wsol, false),
    ];
    accounts.extend(route);
    v.ix(d, accounts)
}

/// Tag 43 with the keeper's default `min_out` (quote minus 50 bps).
pub fn swap_ix(v: &Vault, env: &SwapEnv, amount_in: u64) -> Instruction {
    let min_out = keeper_min_out(amount_in, sol_px(v), KEEPER_SWAP_SLIPPAGE_BPS);
    swap_ix_with(v, amount_in, min_out, route_v2_data(amount_in, 0, 0), route_accounts(v, env))
}

/// Mock pays `out_bps` of the fair value of `amount` (10 000 = fair).
pub fn pay(amount: u64, px: u64, out_bps: u64) -> u64 {
    fair_out(amount, px) * out_bps / 10_000
}

fn sol_vault(coin: &'static str) -> Option<Vault> {
    Vault::try_new(Setup::sol(coin))
}

/// TD-40: happy path. USDC moves `buyback_usdc → swap_usdc → route`, wSOL
/// arrives on the temporary `bb_unwrap` (created and closed in the same
/// instruction), `out ≥` the keeper's `min_out`, lamports land on
/// `buyback_authority`; counters, cool-down and `SJKEVBSW` (SPEC v4: 65 bytes).
#[test]
fn swap_happy_path() {
    let Some(mut v) = sol_vault("solcurve") else { return };
    let amount = 100_000_000; // 100 USDC
    let env = setup_swap(&mut v, 250_000_000);
    let px = sol_px(&v);
    let out = pay(amount, px, 9_990);
    set_jup(JupCfg { mode: JupMode::Honest, out, extra: 0 });
    let k0 = v.k.buyback_authority;
    let lam0 = v.lamports(&k0);
    let (_, now) = v.clock();
    let m = ok(v.call(swap_ix(&v, &env, amount)));
    println!("U-37 tag 43 CU (mock route): {}", m.compute_units_consumed);
    assert_eq!(v.token_amount(&v.k.buyback_usdc), 150_000_000);
    assert_eq!(v.token_amount(&v.k.swap_usdc), 0);
    assert_eq!(v.token_amount(&env.reserve_usdc), amount);
    assert!(!v.exists(&v.k.bb_unwrap), "bb_unwrap closed");
    assert_eq!(v.lamports(&k0), lam0 + out, "k0 got exactly out (its rent for bb_unwrap came back)");
    let e = event(&m.logs, "SJKEVBSW");
    assert_eq!(e.len(), 65);
    assert_eq!(u64_at(&e, 17), amount);
    assert_eq!(u64_at(&e, 25), amount, "spent");
    assert_eq!(u64_at(&e, 33), out);
    assert_eq!(u64_at(&e, 41), keeper_min_out(amount, px, KEEPER_SWAP_SLIPPAGE_BPS), "min_out = the keeper's");
    assert_eq!(u64_at(&e, 49), amount, "cum_usdc_swapped");
    assert_eq!(u64_at(&e, 57), out, "cum_sol_from_swaps");
    let bs = v.bs();
    assert_eq!(bs.n_swaps(), 1);
    assert_eq!(bs.cum_usdc_swapped(), amount);
    assert_eq!(bs.cum_payout_buyback_spent(), amount);
    assert_eq!(bs.cum_sol_from_swaps(), out);
    assert_eq!(bs.last_swap_ts(), now);
    let p = bs.buyback_params();
    let wait =
        (u128::from(p.swap_min_interval_s()) * u128::from(amount)).div_ceil(u128::from(p.swap_max_usdc())) as i64;
    assert_eq!(bs.next_swap_ts(), now + wait, "cool-down ⌈60·amount/swap_max⌉");
}

/// TD-41 (SPEC v4): output below the keeper's `min_out` → SwapOutputBelowMin
/// (nothing moves); `min_out == 0` → BbSwapAmountInvalid; exactly `min_out`
/// passes.
#[test]
fn swap_output_below_min() {
    let Some(mut v) = sol_vault("solcurve") else { return };
    let amount = 100_000_000;
    let env = setup_swap(&mut v, amount);
    let px = sol_px(&v);
    let floor = keeper_min_out(amount, px, KEEPER_SWAP_SLIPPAGE_BPS);
    set_jup(JupCfg { mode: JupMode::Honest, out: floor - 1, extra: 0 });
    let before = (v.token_amount(&v.k.buyback_usdc), v.lamports(&v.k.buyback_authority));
    assert_sijka(&v.call(swap_ix(&v, &env, amount)), E::SwapOutputBelowMin);
    assert_eq!((v.token_amount(&v.k.buyback_usdc), v.lamports(&v.k.buyback_authority)), before);
    set_jup(JupCfg { mode: JupMode::Honest, out: floor, extra: 0 });
    let ix = swap_ix_with(&v, amount, floor + 1, route_v2_data(amount, 0, 0), route_accounts(&v, &env));
    assert_sijka(&v.call(ix), E::SwapOutputBelowMin);
    let ix = swap_ix_with(&v, amount, 0, route_v2_data(amount, 0, 0), route_accounts(&v, &env));
    assert_sijka(&v.call(ix), E::BbSwapAmountInvalid);
    ok(v.call(swap_ix(&v, &env, amount)));
}

/// TD-42: the route takes more than `amount_in` from `swap_usdc` (which holds
/// extra USDC, e.g. from the inflow section) → SwapInputExceeded.
#[test]
fn swap_input_exceeded() {
    let Some(mut v) = sol_vault("solcurve") else { return };
    let amount = 100_000_000;
    let env = setup_swap(&mut v, amount);
    let sa = v.k.swap_authority;
    let su = v.k.swap_usdc;
    v.set_token_account(su, tokenkeg(), usdc(), sa, 5_000_000);
    set_jup(JupCfg { mode: JupMode::Overspend, out: pay(amount, sol_px(&v), 10_000), extra: 1 });
    assert_sijka(&v.call(swap_ix(&v, &env, amount)), E::SwapInputExceeded);
}

/// TD-43: a token account of `swap_authority` outside the allowed pair
/// (`swap_wsol`), or a protected key (`buyback_state`, `buyback_token`), in
/// the route → JupiterAccountForbidden.
#[test]
fn swap_route_account_policy() {
    let Some(mut v) = sol_vault("solcurve") else { return };
    let amount = 100_000_000;
    let env = setup_swap(&mut v, amount);
    let kp = v.keeper.insecure_clone();
    ok(v.send(vec![create_ata_ix(&kp.pubkey(), &v.k.swap_authority, &wsol(), &tokenkeg())], &[&kp]));
    set_jup(JupCfg { mode: JupMode::Honest, out: pay(amount, sol_px(&v), 10_000), extra: 0 });
    for extra in [v.k.swap_wsol, v.k.buyback_state, v.buyback_token(), v.k.bb_wsol, v.k.buyback_usdc] {
        let mut route = route_accounts(&v, &env);
        route.push(AccountMeta::new_readonly(extra, false));
        let ix = swap_ix_with(&v, amount, 1, route_v2_data(amount, 0, 0), route);
        assert_sijka(&v.call(ix), E::JupiterAccountForbidden);
    }
    // Wrong pinned slot (destination not bb_unwrap).
    let mut route = route_accounts(&v, &env);
    route[2].pubkey = env.reserve_wsol;
    let ix = swap_ix_with(&v, amount, 1, route_v2_data(amount, 0, 0), route);
    assert_sijka(&v.call(ix), E::JupiterRoutePinMismatch);
}

/// TD-44, TD-45: platform fee / positive slippage / `in_amount ≠ amount_in`
/// → JupiterArgsMismatch; `exact_out_route` → JupiterIxForbidden.
#[test]
fn swap_jupiter_args_policy() {
    let Some(mut v) = sol_vault("solcurve") else { return };
    let amount = 100_000_000;
    let env = setup_swap(&mut v, amount);
    set_jup(JupCfg { mode: JupMode::Honest, out: pay(amount, sol_px(&v), 10_000), extra: 0 });
    for data in [route_v2_data(amount, 1, 0), route_v2_data(amount, 0, 1), route_v2_data(amount - 1, 0, 0)] {
        let ix = swap_ix_with(&v, amount, 1, data, route_accounts(&v, &env));
        assert_sijka(&v.call(ix), E::JupiterArgsMismatch);
    }
    let h = Sha256::digest(b"global:exact_out_route");
    let mut data = route_v2_data(amount, 0, 0);
    data[..8].copy_from_slice(&h[..8]);
    let ix = swap_ix_with(&v, amount, 1, data, route_accounts(&v, &env));
    assert_sijka(&v.call(ix), E::JupiterIxForbidden);
}

/// TD-46 (SPEC v4, DECISIONS §23 item 4): only `config.keeper`, signed,
/// swaps. Another signer, the admin, the keeper not signing (another fee
/// payer) and `keeper == 0` → UnauthorizedKeeper; after `set_keeper` the old
/// key fails and the new one passes. A stale or missing PAM mark no longer
/// matters (no oracle).
#[test]
fn swap_only_by_the_keeper() {
    let Some(mut v) = sol_vault("solcurve") else { return };
    let amount = 100_000_000;
    let env = setup_swap(&mut v, amount);
    set_jup(JupCfg { mode: JupMode::Honest, out: pay(amount, sol_px(&v), 10_000), extra: 0 });
    let stranger = Keypair::new();
    v.svm.airdrop(&stranger.pubkey(), LAMPORTS_PER_SOL).unwrap();
    let admin = v.admin.insecure_clone();
    for who in [&stranger, &admin] {
        let mut ix = swap_ix(&v, &env, amount);
        ix.accounts[12] = AccountMeta::new_readonly(who.pubkey(), true);
        assert_sijka(&v.send(vec![ix], &[who]), E::UnauthorizedKeeper);
    }
    // The keeper key in #12 without its signature (the stranger pays).
    let mut ix = swap_ix(&v, &env, amount);
    ix.accounts[12].is_signer = false;
    assert_sijka(&v.send(vec![ix], &[&stranger]), E::UnauthorizedKeeper);
    // keeper = 0: nobody swaps.
    ok(v.set_keeper(&Pubkey::default()));
    assert_sijka(&v.call(swap_ix(&v, &env, amount)), E::UnauthorizedKeeper);
    // Rotation to the stranger.
    ok(v.set_keeper(&stranger.pubkey()));
    assert_sijka(&v.call(swap_ix(&v, &env, amount)), E::UnauthorizedKeeper);
    let mut ix = swap_ix(&v, &env, amount);
    ix.accounts[12] = AccountMeta::new_readonly(stranger.pubkey(), true);
    ok(v.send(vec![ix], &[&stranger]));
}

/// TD-47, TD-64 (reviews ACC-13, RT-7): the SOL budget counts `bb_wsol` only on
/// the AMM venue; `bb_wsol` must exist.
#[test]
fn swap_sol_budget_cap() {
    let amount = 100_000_000;
    for (coin, venue_amm) in [("solamm", true), ("solcurve", false)] {
        let Some(mut v) = sol_vault(coin) else { return };
        let env = setup_swap(&mut v, amount);
        set_jup(JupCfg { mode: JupMode::Honest, out: pay(amount, sol_px(&v), 10_000), extra: 0 });
        let cap = v.bs().buyback_params().sol_budget_cap();
        v.fund_authority(cap / 2);
        let w = v.k.bb_wsol;
        v.set_token_amount(&w, cap / 2);
        let res = v.call(swap_ix(&v, &env, amount));
        if venue_amm {
            assert_sijka(&res, E::BbSolBudgetFull);
        } else {
            ok(res);
        }
        // Lamports alone at the cap.
        let Some(mut v) = sol_vault(coin) else { return };
        let env = setup_swap(&mut v, amount);
        v.fund_authority(cap);
        assert_sijka(&v.call(swap_ix(&v, &env, amount)), E::BbSolBudgetFull);
        v.fund_authority(cap - 1);
        ok(v.call(swap_ix(&v, &env, amount)));
        // Without bb_wsol.
        let Some(mut v) = sol_vault(coin) else { return };
        let env = setup_swap(&mut v, amount);
        let w = v.k.bb_wsol;
        v.set_lamports(&w, 0);
        assert_sijka(&v.call(swap_ix(&v, &env, amount)), E::BbQuoteAtaMissing);
    }
}

/// TD-48: lamports sent to the `bb_unwrap` address beforehand: the account is
/// still created (transfer + allocate + assign), only the route's wSOL counts
/// as `out`.
#[test]
fn swap_with_prefunded_unwrap_address() {
    let Some(mut v) = sol_vault("solcurve") else { return };
    let amount = 100_000_000;
    let env = setup_swap(&mut v, amount);
    let px = sol_px(&v);
    let out = pay(amount, px, 10_000);
    set_jup(JupCfg { mode: JupMode::Honest, out, extra: 0 });
    let u = v.k.bb_unwrap;
    v.set_lamports(&u, 5_000_000);
    let k0 = v.k.buyback_authority;
    let lam0 = v.lamports(&k0);
    let m = ok(v.call(swap_ix(&v, &env, amount)));
    assert_eq!(u64_at(&event(&m.logs, "SJKEVBSW"), 33), out, "the donation is not output");
    assert!(!v.exists(&u));
    assert_eq!(v.lamports(&k0), lam0 + out + 5_000_000, "the donation ends on k0 with the close");
    // A token account already sitting at bb_unwrap → BbUnwrapAccountBusy.
    let Some(mut v) = sol_vault("solcurve") else { return };
    let env = setup_swap(&mut v, amount);
    let u = v.k.bb_unwrap;
    let sa = v.k.swap_authority;
    v.set_token_account(u, tokenkeg(), wsol(), sa, 0);
    assert_sijka(&v.call(swap_ix(&v, &env, amount)), E::BbUnwrapAccountBusy);
}

/// TD-49: tag 43 is for the SOL pair only.
#[test]
fn swap_refused_on_usdc_pair() {
    let Some(mut v) = Vault::try_new(Setup::usdc("usdccurve")) else { return };
    let env = setup_swap(&mut v, 100_000_000);
    assert_sijka(&v.call(swap_ix(&v, &env, 100_000_000)), E::BbNotSolPair);
}

/// TD-50 and TD-67 (review RT-6): a route that spends half of `amount_in` must
/// still pay the keeper's `min_out` for all of it; then the unspent half
/// returns to `buyback_usdc`. Paying only for the half → SwapOutputBelowMin.
#[test]
fn swap_partial_spend() {
    let Some(mut v) = sol_vault("solcurve") else { return };
    let amount = 100_000_000;
    let env = setup_swap(&mut v, amount);
    let px = sol_px(&v);
    set_jup(JupCfg { mode: JupMode::SpendHalf, out: pay(amount / 2, px, 10_000), extra: 0 });
    assert_sijka(&v.call(swap_ix(&v, &env, amount)), E::SwapOutputBelowMin);
    set_jup(JupCfg { mode: JupMode::SpendHalf, out: pay(amount, px, 10_000), extra: 0 });
    let m = ok(v.call(swap_ix(&v, &env, amount)));
    let e = event(&m.logs, "SJKEVBSW");
    assert_eq!(u64_at(&e, 17), amount);
    assert_eq!(u64_at(&e, 25), amount / 2);
    assert_eq!(v.token_amount(&v.k.buyback_usdc), amount / 2, "unspent USDC returned");
    assert_eq!(v.token_amount(&v.k.swap_usdc), 0);
    let bs = v.bs();
    assert_eq!(bs.cum_usdc_swapped(), amount / 2);
    assert_eq!(bs.cum_payout_buyback_spent(), amount / 2);
    // The cool-down is charged on amount_in, not on spent (RT-6).
    let p = bs.buyback_params();
    let wait =
        (u128::from(p.swap_min_interval_s()) * u128::from(amount)).div_ceil(u128::from(p.swap_max_usdc())) as i64;
    assert_eq!(bs.next_swap_ts() - bs.last_swap_ts(), wait);
}

/// TD-65 (review RT-1): the route abuses the `swap_authority` signature; every
/// case is caught by `post_route_check` → SwapAccountTampered, and nothing
/// moves. A `swap_usdc` with a delegate before the call → InvalidTokenAccount.
#[test]
fn swap_tampering_route_is_rejected() {
    let amount = 100_000_000;
    let modes = [
        JupMode::ApproveDelegateSrc,
        JupMode::SetOwnerSrc,
        JupMode::SetCloseAuthoritySrc,
        JupMode::CloseSrc,
        JupMode::SetOwnerDst,
        JupMode::SetCloseAuthorityDst,
        JupMode::AssignAuthority,
        JupMode::DrainAuthority,
    ];
    for mode in modes {
        let Some(mut v) = sol_vault("solcurve") else { return };
        let env = setup_swap(&mut v, amount);
        let sa = v.k.swap_authority;
        if mode == JupMode::DrainAuthority {
            v.set_lamports(&sa, 1_000_000);
        }
        set_jup(JupCfg { mode, out: pay(amount, sol_px(&v), 10_000), extra: 0 });
        let before = (v.token_amount(&v.k.buyback_usdc), v.lamports(&v.k.buyback_authority), v.lamports(&sa));
        let res = v.call(swap_ix(&v, &env, amount));
        println!("TD-65 mode {mode:?}: {:?}", res.as_ref().err().map(|f| &f.err));
        if matches!(mode, JupMode::AssignAuthority | JupMode::DrainAuthority) {
            // `swap_authority` is read-only in the outer instruction (tag 43
            // #5) and therefore in the route CPI: the runtime refuses the
            // nested System instruction (writable privilege) before our
            // post-route check could even run.
            let f = res.expect_err("route abusing swap_authority must fail");
            let s = format!("{:?}", f.err);
            assert!(s.contains("PrivilegeEscalation") || s.contains("Custom"), "{s}");
        } else {
            assert_sijka(&res, E::SwapAccountTampered);
        }
        let after = (v.token_amount(&v.k.buyback_usdc), v.lamports(&v.k.buyback_authority), v.lamports(&sa));
        assert_eq!(after, before);
    }
    let Some(mut v) = sol_vault("solcurve") else { return };
    let env = setup_swap(&mut v, amount);
    let su = v.k.swap_usdc;
    let delegate = Keypair::new().pubkey();
    v.patch(&su, |d| {
        d[72..76].copy_from_slice(&1u32.to_le_bytes());
        d[76..108].copy_from_slice(delegate.as_ref());
        d[121..129].copy_from_slice(&1u64.to_le_bytes());
    });
    set_jup(JupCfg { mode: JupMode::Honest, out: pay(amount, sol_px(&v), 10_000), extra: 0 });
    assert_sijka(&v.call(swap_ix(&v, &env, amount)), E::InvalidTokenAccount);
}

/// TD-67: a dust swap (0.01 USDC) occupies ⌈60·0.01/1000⌉ = 1 s; a full swap
/// (`swap_max_usdc`) closes the window for 60 s (BbSwapTooSoon).
#[test]
fn swap_cooldown_is_proportional() {
    let Some(mut v) = sol_vault("solcurve") else { return };
    let max = v.bs().buyback_params().swap_max_usdc();
    let env = setup_swap(&mut v, 3 * max);
    let px = sol_px(&v);
    set_jup(JupCfg { mode: JupMode::Honest, out: pay(10_000, px, 10_000), extra: 0 });
    ok(v.call(swap_ix(&v, &env, 10_000)));
    assert_eq!(v.bs().next_swap_ts() - v.now(), 1);
    assert_sijka(&v.call(swap_ix(&v, &env, 10_000)), E::BbSwapTooSoon);
    v.tick(1, 1);
    set_jup(JupCfg { mode: JupMode::Honest, out: pay(max, px, 10_000), extra: 0 });
    ok(v.call(swap_ix(&v, &env, max)));
    assert_eq!(v.bs().next_swap_ts() - v.now(), 60);
    v.tick(30, 1);
    assert_sijka(&v.call(swap_ix(&v, &env, max)), E::BbSwapTooSoon);
}

/// `amount_in` must be in `1..=min(buyback_usdc, swap_max_usdc)`; the float
/// `lamports(k0) ≥ rent(0) + rent(165)` (the temporary `bb_unwrap`; audit
/// EA-1: RESERVE itself is not required, the swap refills it).
#[test]
fn swap_amount_and_float_rules() {
    let Some(mut v) = sol_vault("solcurve") else { return };
    let max = v.bs().buyback_params().swap_max_usdc();
    let env = setup_swap(&mut v, 5_000_000);
    for amount in [0, 5_000_001] {
        assert_sijka(&v.call(swap_ix(&v, &env, amount)), E::BbSwapAmountInvalid);
    }
    let Some(mut v) = sol_vault("solcurve") else { return };
    let env = setup_swap(&mut v, 2 * max);
    assert_sijka(&v.call(swap_ix(&v, &env, max + 1)), E::BbSwapAmountInvalid);
    let k0 = v.k.buyback_authority;
    let float = v.rent(0) + v.rent(165);
    v.set_lamports(&k0, float - 1);
    let out = pay(max, sol_px(&v), 10_000);
    set_jup(JupCfg { mode: JupMode::Honest, out, extra: 0 });
    assert_sijka(&v.call(swap_ix(&v, &env, max)), E::BbFloatLow);
    v.set_lamports(&k0, float);
    ok(v.call(swap_ix(&v, &env, max)));
    assert_eq!(v.lamports(&k0), float + out, "the bb_unwrap rent came back, out landed on k0");
}

/// Audit EA-1 (TD-69): the last chunk of a portion spends the whole budget
/// (`v = avail`) and pump takes the rent of a cold account out of RESERVE,
/// leaving k0 at `RESERVE − r`. The SOL budget is then 0, and tag 43 must
/// still refill k0 (before the fix: `BbFloatLow` until someone donated SOL).
#[test]
fn swap_after_a_chunk_took_rent_from_reserve() {
    let Some(mut v) = sol_vault("solcurve") else { return };
    let amount = 100_000_000;
    let env = setup_swap(&mut v, amount);
    let k0 = v.k.buyback_authority;
    let min = v.bs().buyback_params().chunk_min_quote();
    v.fund_authority(min);
    v.warm();
    let (_, vq, _, _) = crate::pumpix::curve_reserves(&v);
    let pl = crate::t_curve::plan(&v, vq, crate::t_curve::avail_sol(&v), 0);
    assert!(min < pl.v_cap, "budget {min} below v_cap {}", pl.v_cap);
    assert_eq!(pl.v, min, "the last chunk of the portion: v = avail");
    assert!(!v.exists(&crate::pumpix::pump_uva(&k0)), "user_volume_accumulator is cold");
    let m = ok(v.call(crate::pumpix::chunk_curve_ix(&v, 0, 0)));
    let e = event(&m.logs, "SJKEVCHK");
    let (spent, rent) = (u64_at(&e, 26), u64_at(&e, 34));
    println!("EA-1: chunk v = avail = {min}, spent {spent}, pump rent {rent}");
    assert_eq!(spent, min);
    assert!(rent > 0, "pump created a cold account");
    assert_eq!(v.lamports(&k0), v.reserve() - rent, "k0 below RESERVE");
    assert_eq!(crate::t_curve::avail_sol(&v), 0, "no SOL budget left");
    // Tag 43 refills k0.
    let out = pay(amount, sol_px(&v), 9_990);
    set_jup(JupCfg { mode: JupMode::Honest, out, extra: 0 });
    let lam0 = v.lamports(&k0);
    ok(v.call(swap_ix(&v, &env, amount)));
    assert_eq!(v.lamports(&k0), lam0 + out);
    assert_eq!(crate::t_curve::avail_sol(&v), out - rent, "the swap refilled RESERVE first");
}

/// Fixed accounts of tag 43: `swap_authority` must be read-only (it would
/// otherwise be writable inside the route, review RT-1), #12 is the keeper
/// (the former oracle slot: the PAM there is `UnauthorizedKeeper`), the data
/// length must match `jup_len`.
#[test]
fn swap_fixed_account_rules() {
    let Some(mut v) = sol_vault("solcurve") else { return };
    let amount = 100_000_000;
    let env = setup_swap(&mut v, amount);
    set_jup(JupCfg { mode: JupMode::Honest, out: pay(amount, sol_px(&v), 10_000), extra: 0 });
    let mut ix = swap_ix(&v, &env, amount);
    ix.accounts[5].is_writable = true;
    assert_sijka(&v.call(ix), E::AccountMustBeReadonly);
    let mut ix = swap_ix(&v, &env, amount);
    ix.accounts[12] = AccountMeta::new_readonly(pam_key(&v), false);
    assert_sijka(&v.call(ix), E::UnauthorizedKeeper);
    let mut ix = swap_ix(&v, &env, amount);
    ix.data.push(0);
    assert_sijka(&v.call(ix), E::InvalidInstructionData);
    let mut ix = swap_ix(&v, &env, amount);
    ix.accounts[9].pubkey = wsol();
    assert_sijka(&v.call(ix), E::BbPinnedAccountMismatch);
    ok(v.call(swap_ix(&v, &env, amount)));
}

/// End to end on the SOL pair: USDC of the 80% share → SOL (tag 43) → the
/// SOL is the budget of the next chunk on the real pump curve → burned.
#[test]
fn swap_then_chunk_end_to_end() {
    let Some(mut v) = sol_vault("solcurve") else { return };
    let amount = 200_000_000;
    let env = setup_swap(&mut v, amount);
    v.fund_authority(0);
    let px = sol_px(&v);
    let out = pay(amount, px, 9_990);
    set_jup(JupCfg { mode: JupMode::Honest, out, extra: 0 });
    ok(v.call(swap_ix(&v, &env, amount)));
    assert_eq!(crate::t_curve::avail_sol(&v), out);
    v.warm();
    let m = ok(v.call(crate::pumpix::chunk_curve_ix(&v, 0, 0)));
    let e = event(&m.logs, "SJKEVCHK");
    assert!(u64_at(&e, 50) > 0);
    assert_eq!(u64_at(&e, 58), u64_at(&e, 50));
    let bs = v.bs();
    assert_eq!(bs.cum_payout_buyback_spent(), amount, "the USDC counter moved with the swap only");
    assert_eq!(bs.cum_sol_from_swaps(), out);
    assert_eq!(bs.cum_quote_spent_curve(), u64_at(&e, 26));
}

/// Transaction composition for tag 43 (TD-60); SPEC v4 has no pause (TD-29
/// retired): the former `pause_until@24` byte is ignored.
#[test]
fn swap_no_pause_and_composition() {
    let Some(mut v) = sol_vault("solcurve") else { return };
    let amount = 100_000_000;
    let env = setup_swap(&mut v, amount);
    set_jup(JupCfg { mode: JupMode::Honest, out: pay(amount, sol_px(&v), 10_000), extra: 0 });
    let bs = v.k.buyback_state;
    v.patch(&bs, |d| d[24..32].copy_from_slice(&i64::MAX.to_le_bytes()));
    let kp = v.keeper.insecure_clone();
    let ix = swap_ix(&v, &env, amount);
    assert_sijka(&v.send(vec![foreign_ix(&kp.pubkey()), ix.clone()], &[&kp]), E::ForeignInstruction);
    assert_sijka(&v.send(vec![crate::mocks::wrap_cpi(ix.clone())], &[&kp]), E::NotTopLevel);
    ok(v.send(vec![ix], &[&kp]));
}
