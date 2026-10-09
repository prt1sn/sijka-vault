// Copyright (c) 2026 prt1sn. All rights reserved.
//! `bb_chunk_amm` (tag 45) on the real pump_amm binary and live graduated
//! coins (SOL and USDC pools): SPEC §5.5.3, §5.5.9; TD-35…TD-39, TD-62;
//! U-32, U-33, U-34.

use sijka_vault::constants as c;
use sijka_vault::error::SijkaError as E;
use solana_keypair::Keypair;
use solana_signer::Signer;

use crate::harness::*;
use crate::pumpix::*;
use crate::t_curve::plan;

/// SOL budget on the AMM venue: lamports(k0) + bb_wsol − RESERVE.
pub fn avail_amm(v: &Vault) -> u64 {
    (v.lamports(&v.k.buyback_authority) + v.token_amount(&v.k.bb_wsol)).saturating_sub(v.reserve())
}

/// A real outside v2 trade leaves negative vQR on an ordinary SOL pool.
/// Pinning, warming observations and the vault's legacy CPI then still work,
/// with retained fees excluded from price and the buyback budget.
#[test]
fn v2_retained_fees_allow_pin_observe_buy_and_burn() {
    let mut v = vault!(Setup::sol("solamm").no_pin());
    v.fund_authority(2 * LAMPORTS_PER_SOL);
    let ck = v.coin().clone();
    let before = v.data(&ck.pool);
    let vqr_before = if before.len() >= 261 { i128::from_le_bytes(before[245..261].try_into().unwrap()) } else { 0 };
    let fees_before = if before.len() >= 287 { u64_at(&before, 271) + u64_at(&before, 279) } else { 0 };
    assert_eq!(vqr_before + i128::from(fees_before), 0, "fixture must be an ordinary, unboosted pool");

    let trader = Trader::new(&mut v, LAMPORTS_PER_SOL);
    trader.wrap(&mut v, LAMPORTS_PER_SOL / 10);
    ok(trader.amm_buy_v2(&mut v, LAMPORTS_PER_SOL / 10));
    let after = v.data(&ck.pool);
    let vqr_after = i128::from_le_bytes(after[245..261].try_into().unwrap());
    let fees_after = u64_at(&after, 271) + u64_at(&after, 279);
    assert!(fees_after > fees_before, "real v2 trade retained fees");
    assert_eq!(vqr_after, -i128::from(fees_after));
    let (b, q) = pool_reserves(&v);
    assert_eq!(v.token_amount(&ck.pool_quote_ta) - q, fees_after);
    assert!(trader.base(&v) > 0);

    ok(v.bb_pin());
    v.warm();
    assert_eq!(v.bs().last_obs_quote(), q);
    assert_eq!(v.bs().q_ema(), q);
    assert_eq!(v.bs().last_obs_price_x64(), price_x64(q, b));
    let pl = plan(&v, q, avail_amm(&v), 0);
    let supply = v.mint_supply(&ck.mint);
    let m = ok(v.call(chunk_amm_ix(&v, 0, 0)));
    let e = event(&m.logs, "SJKEVCHK");
    assert_eq!(u64_at(&e, 18), pl.v);
    assert_eq!(u64_at(&e, 42), pl.min_out);
    assert_eq!(u128_at(&e, 66), price_x64(q, b));
    assert_eq!(u64_at(&e, 98), q);
    let bought = u64_at(&e, 50);
    assert!(bought > 0);
    assert_eq!(u64_at(&e, 58), bought);
    assert_eq!(v.mint_supply(&ck.mint), supply - bought);
    assert_eq!(v.token_amount(&v.buyback_token()), 0);
}

/// TD-35 (U-32, U-33): one chunk in the canonical SOL pool: the shortfall is
/// wrapped into `bb_wsol` (System transfer + SyncNative), pump_amm
/// `buy_exact_quote_in` with the remaining accounts `[pool_v2,
/// buyback_fee_recipient, its quote ATA]` and `track_volume = 0` accepts our
/// PDA, everything bought is burned.
#[test]
fn chunk_in_sol_pool_wraps_buys_and_burns() {
    let mut v = vault!(Setup::sol("solamm"));
    v.fund_authority(2 * LAMPORTS_PER_SOL);
    v.warm();
    let ck = v.coin().clone();
    let k0 = v.k.buyback_authority;
    let (b0, q0) = pool_reserves(&v);
    let pl = plan(&v, q0, avail_amm(&v), 0);
    let lam0 = v.lamports(&k0);
    let supply0 = v.mint_supply(&ck.mint);
    assert!(!v.exists(&ck.pool_v2), "pool_v2 of this coin does not exist on mainnet");
    let uva_before = v.exists(&amm_uva(&k0));
    let ix = chunk_amm_ix(&v, 0, 0);
    let m = ok(v.call(ix));
    println!("U-37 tag 45 CU (first chunk): {}", m.compute_units_consumed);
    assert!(m.compute_units_consumed < 400_000);
    let e = event(&m.logs, "SJKEVCHK");
    assert_eq!(e[17], 2, "venue AMM");
    let (ev_v, spent, rent_extra, min_out, bought, burned) =
        (u64_at(&e, 18), u64_at(&e, 26), u64_at(&e, 34), u64_at(&e, 42), u64_at(&e, 50), u64_at(&e, 58));
    assert_eq!(ev_v, pl.v);
    assert_eq!(min_out, pl.min_out);
    assert_eq!(u128_at(&e, 66), price_x64(q0, b0), "p_now = Q/B of the pool");
    assert!(spent <= pl.v && spent > 0);
    assert!(rent_extra <= c::MAX_RENT_EXTRA);
    let lam1 = v.lamports(&k0);
    // k0 funded bb_wsol with exactly the shortfall; pump_amm may take rent.
    assert_eq!(lam0 - lam1, pl.v + rent_extra, "k0 paid the wrap of v plus rent");
    assert_eq!(v.token_amount(&v.k.bb_wsol), pl.v - spent, "unspent wSOL stays in bb_wsol");
    assert!(bought >= min_out);
    assert_eq!(burned, bought);
    assert_eq!(v.token_amount(&v.buyback_token()), 0);
    assert_eq!(v.mint_supply(&ck.mint), supply0 - bought);
    let (b1, q1) = pool_reserves(&v);
    assert_eq!(b0 - b1, bought, "pool base reserve paid the tokens");
    assert!(q1 > q0 && q1 - q0 <= spent, "pool quote grew by the amount after fees");
    let bs = v.bs();
    assert_eq!(bs.n_chunks(), 1);
    assert_eq!(bs.cum_quote_spent_amm(), spent);
    assert_eq!(bs.cum_quote_spent_curve(), 0);
    assert_eq!(bs.cum_burned_tokens(), bought);
    println!(
        "U-33/U-34 AMM chunk: v {} spent {} bought {} rent {} uva before {} after {}",
        pl.v,
        spent,
        bought,
        rent_extra,
        uva_before,
        v.exists(&amm_uva(&k0))
    );
}

/// wSOL already on `bb_wsol` (a donation or the rest of a previous chunk) is
/// used first: only the shortfall is wrapped.
#[test]
fn existing_wsol_is_used_before_wrapping() {
    let mut v = vault!(Setup::sol("solamm"));
    v.fund_authority(2 * LAMPORTS_PER_SOL);
    v.warm();
    let (_, q0) = pool_reserves(&v);
    let pl = plan(&v, q0, u64::MAX, 0);
    let w = v.k.bb_wsol;
    v.set_token_amount(&w, pl.v / 2);
    let k0 = v.k.buyback_authority;
    let lam0 = v.lamports(&k0);
    let m = ok(v.call(chunk_amm_ix(&v, 0, 0)));
    let e = event(&m.logs, "SJKEVCHK");
    let (ev_v, spent, rent) = (u64_at(&e, 18), u64_at(&e, 26), u64_at(&e, 34));
    assert_eq!(ev_v, pl.v);
    assert_eq!(lam0 - v.lamports(&k0), ev_v - pl.v / 2 + rent, "only the shortfall was wrapped");
    assert_eq!(v.token_amount(&w), ev_v - spent);
}

/// TD-36: JIT liquidity (pool base and quote +50%, same price) right before
/// the chunk does not enlarge it: `Q_ref = min(q_now, last_obs_quote, q_ema)`.
#[test]
fn jit_liquidity_does_not_enlarge_the_chunk() {
    let mut v = vault!(Setup::sol("solamm"));
    v.fund_authority(2 * LAMPORTS_PER_SOL);
    v.warm();
    let ck = v.coin().clone();
    let (b0, q0) = pool_reserves(&v);
    let q_obs = v.bs().last_obs_quote();
    v.set_token_amount(&ck.pool_base_ta, b0 / 2 * 3);
    v.set_token_amount(&ck.pool_quote_ta, q0 / 2 * 3);
    let (_, q1) = pool_reserves(&v);
    let m = ok(v.call(chunk_amm_ix(&v, 0, 0)));
    let e = event(&m.logs, "SJKEVCHK");
    let chunk_bps = u64::from(v.bs().buyback_params().chunk_bps());
    assert_eq!(u64_at(&e, 98), q_obs.min(v.bs().q_ema()), "q_ref ignores the JIT deposit");
    assert!(u64_at(&e, 98) < q1);
    assert_eq!(u64_at(&e, 18), q_obs * chunk_bps / 10_000);
}

/// TD-37 / U-32: remaining `r1 = pool_v2` is pinned (ours), `r2` is checked by
/// pump_amm itself; its writable flag is copied from the outer instruction and
/// both flags work.
#[test]
fn remaining_accounts_of_the_pool_buy() {
    let mut v = vault!(Setup::sol("solamm"));
    v.fund_authority(3 * LAMPORTS_PER_SOL);
    v.warm();
    let mut ix = chunk_amm_ix(&v, 0, 0);
    ix.accounts[27].pubkey = Keypair::new().pubkey();
    assert_sijka(&v.call(ix), E::BbPinnedAccountMismatch);
    let rc = Recips::pick(&v);
    let stranger = Keypair::new().pubkey();
    let res = v.call(chunk_amm_ix_with(&v, 0, 0, &Recips { amm_buyback: stranger, ..rc.clone() }));
    println!("U-29/U-32 random pump_amm buyback_fee_recipient: {:?}", res.as_ref().err().map(|f| &f.err));
    assert!(res.is_err(), "pump_amm must reject an unknown buyback fee recipient");
    let res = v.call(chunk_amm_ix_with(&v, 0, 0, &Recips { amm_protocol: stranger, ..rc.clone() }));
    println!("U-29 random pump_amm protocol_fee_recipient: {:?}", res.as_ref().err().map(|f| &f.err));
    assert!(res.is_err(), "pump_amm must reject an unknown protocol fee recipient");
    // r2 writable.
    let mut ix = chunk_amm_ix(&v, 0, 0);
    ix.accounts[28].is_writable = true;
    ok(v.call(ix));
    // r2 read-only (the keeper default) in a later window.
    let t = v.bs().next_buy_ts();
    v.tick(15, 1);
    ok(v.observe());
    let s = v.slot();
    v.set_clock(s + 1, t.max(v.now() + 1));
    let ix = chunk_amm_ix(&v, 0, 0);
    assert!(!ix.accounts[28].is_writable);
    ok(v.call(ix));
}

/// TD-38 / U-33: what `track_volume` changes. Our chunk always passes 0; a
/// market wallet's buys with 0 and 1 are compared on their volume
/// accumulators.
#[test]
fn track_volume_effect() {
    let mut v = vault!(Setup::sol("solamm"));
    let mut uvas = Vec::new();
    for tv in [0u8, 1u8] {
        let t = Trader::new(&mut v, 5 * LAMPORTS_PER_SOL);
        t.wrap(&mut v, LAMPORTS_PER_SOL);
        let m = ok(t.amm_buy(&mut v, LAMPORTS_PER_SOL / 10, tv));
        let uva = v.data(&amm_uva(&t.pubkey()));
        println!(
            "U-33 track_volume={tv}: CU {} uva len {} data {:02x?}",
            m.compute_units_consumed,
            uva.len(),
            &uva[..uva.len().min(137)]
        );
        uvas.push(uva);
    }
    v.fund_authority(2 * LAMPORTS_PER_SOL);
    v.warm();
    ok(v.call(chunk_amm_ix(&v, 0, 0)));
    let ours = v.data(&amm_uva(&v.k.buyback_authority));
    println!("U-33 our uva (track_volume=0): len {} data {:02x?}", ours.len(), &ours[..ours.len().min(137)]);
    assert!(!ours.is_empty(), "pump_amm creates the accumulator even with track_volume = 0");
    // Volume fields differ between the two market wallets only if tracking matters.
    println!("U-33 accumulators with 0 and 1 identical apart from the user key: {}", uvas[0][40..] == uvas[1][40..]);
}

/// TD-39: USDC pair in the live USDC pool (`Q = Qt + vqr`), quote from
/// `buyback_usdc`, `cum_payout_buyback_spent`.
#[test]
fn usdc_pool_chunk() {
    let mut v = vault!(Setup::usdc("usdcamm"));
    let k0 = v.k.buyback_authority;
    let bb = v.k.buyback_usdc;
    v.set_token_account(bb, tokenkeg(), usdc(), k0, 1_000_000_000);
    let r = v.reserve();
    v.set_lamports(&k0, r);
    v.warm();
    let (b0, q0) = pool_reserves(&v);
    let pl = plan(&v, q0, 1_000_000_000, 0);
    let m = ok(v.call(chunk_amm_ix(&v, 0, 0)));
    println!("U-37 tag 45 CU (USDC pool): {}", m.compute_units_consumed);
    let e = event(&m.logs, "SJKEVCHK");
    let (spent, rent, bought) = (u64_at(&e, 26), u64_at(&e, 34), u64_at(&e, 50));
    assert_eq!(u64_at(&e, 18), pl.v);
    assert_eq!(u128_at(&e, 66), price_x64(q0, b0), "p_now uses Q = Qt + vqr");
    assert_eq!(v.token_amount(&bb), 1_000_000_000 - spent);
    assert!(rent <= c::MAX_RENT_EXTRA);
    println!("U-34 USDC pool cold chunk: rent {rent}");
    assert!(bought >= pl.min_out);
    assert_eq!(v.bs().cum_payout_buyback_spent(), spent);
    assert_eq!(v.token_amount(&v.buyback_token()), 0);
}

/// TD-62 / U-51 (AMM): after a CTO of the pool (`coin_creator = X`), the chunk
/// uses the coin creator vault derived from X and works on the mainnet
/// pump_amm; the pinned k23 / k24 are refused before the CPI. The venue
/// switch also accepts a pool whose coin_creator is not the sharing config.
#[test]
fn chunk_after_pool_cto() {
    let mut v = vault!(Setup::sol("solamm"));
    v.fund_authority(2 * LAMPORTS_PER_SOL);
    v.warm();
    let ck = v.coin().clone();
    let x = Keypair::new().pubkey();
    v.patch(&ck.pool, |d| d[211..243].copy_from_slice(x.as_ref()));
    let mut ix = chunk_amm_ix(&v, 0, 0);
    ix.accounts[21].pubkey = ck.coin_creator_vault_ata;
    ix.accounts[22].pubkey = ck.coin_creator_vault_authority;
    assert_sijka(&v.call(ix), E::BbPinnedAccountMismatch);
    let res = v.call(chunk_amm_ix(&v, 0, 0));
    match &res {
        Ok(m) => println!(
            "U-51 confirmed (pool): chunk after coin_creator CTO bought {}",
            u64_at(&event(&m.logs, "SJKEVCHK"), 50)
        ),
        Err(f) => panic!("U-51 refuted on PumpSwap: {:?}\n{}", f.err, f.meta.logs.join("\n")),
    }
}

/// TD-62 (switch): the canonical pool with a foreign `coin_creator` still
/// switches the venue (working mode).
#[test]
fn venue_switch_with_cto_pool() {
    let mut v = vault!(Setup::sol("solamm").no_pin());
    let ck = v.coin().clone();
    v.patch(&ck.curve, |d| {
        d[8..16].copy_from_slice(&1_000_000_000_000_000u64.to_le_bytes());
        d[16..24].copy_from_slice(&40_000_000_000u64.to_le_bytes());
        d[24..32].copy_from_slice(&700_000_000_000_000u64.to_le_bytes());
        d[48] = 0;
    });
    ok(v.bb_pin());
    ok(v.observe());
    let x = Keypair::new().pubkey();
    v.patch(&ck.pool, |d| d[211..243].copy_from_slice(x.as_ref()));
    v.patch(&ck.curve, |d| d[48] = 1);
    v.tick(15, 1);
    let m = ok(v.observe());
    let e = event(&m.logs, "SJKEVVEN");
    assert_eq!((e[17], e[18]), (1, 2));
    assert_eq!(v.bs().venue(), 2);
}

/// SPEC v4 (DECISIONS §23 item 3): no spot guard on the AMM venue either.
/// After a market buy of 5% of Q the spot is ~10% above the EMA reference and
/// the keeper's chunk still runs, sized by `Q_ref`; then the missing
/// `bb_wsol`.
#[test]
fn amm_no_guard_and_missing_quote_account() {
    let mut v = vault!(Setup::sol("solamm"));
    v.fund_authority(2 * LAMPORTS_PER_SOL);
    v.warm();
    let (_, q) = pool_reserves(&v);
    let t = Trader::new(&mut v, 20 * LAMPORTS_PER_SOL);
    t.wrap(&mut v, q / 20 + LAMPORTS_PER_SOL);
    ok(t.amm_buy(&mut v, q / 20, 0));
    let (b1, q1) = pool_reserves(&v);
    let bs = v.bs();
    let p_ref = bs.ema_price_x64().min(bs.last_obs_price_x64());
    assert!(price_x64(q1, b1) * 10_000 > p_ref * 10_500, "spot more than 5% above P_ref");
    let pl = plan(&v, q1, avail_amm(&v), 0);
    let m = ok(v.call(chunk_amm_ix(&v, 0, 0)));
    assert_eq!(u64_at(&event(&m.logs, "SJKEVCHK"), 18), pl.v, "v bounded by Q_ref, not by the pumped Q");
    let w = v.k.bb_wsol;
    v.set_lamports(&w, 0);
    assert_sijka(&v.call(chunk_amm_ix(&v, 0, 0)), E::BbQuoteAtaMissing);
}

/// TD-71 (audit v4 round 2, AR2-10): a PumpSwap pool with less than 10 SOL of
/// quote. The full 10 bps chunk is below `chunk_min_quote` (0.01 SOL); since
/// `BuybackParams` are fixed (SPEC v4), a floor above the full chunk would
/// stop the buyback for good. The floor is capped at `v_cap`: the full chunk
/// runs on the mainnet pump_amm, dust below it is still refused.
#[test]
fn small_pool_chunk_below_chunk_min() {
    let mut v = vault!(Setup::sol("solamm"));
    v.fund_authority(2 * LAMPORTS_PER_SOL);
    let ck = v.coin().clone();
    // Shrink the pool to 5 SOL of quote at the same price, before the warm-up.
    let (b0, q0) = pool_reserves(&v);
    let q_target = 5 * LAMPORTS_PER_SOL;
    let vqr = i128::from(q0) - i128::from(v.token_amount(&ck.pool_quote_ta));
    assert!(vqr < i128::from(q_target), "virtual quote reserves {vqr}");
    v.set_token_amount(&ck.pool_quote_ta, u64::try_from(i128::from(q_target) - vqr).unwrap());
    v.set_token_amount(&ck.pool_base_ta, (u128::from(b0) * u128::from(q_target) / u128::from(q0)) as u64);
    v.warm();
    let (_, q1) = pool_reserves(&v);
    assert_eq!(q1, q_target);
    let min = v.bs().buyback_params().chunk_min_quote();
    let pl = plan(&v, q1, avail_amm(&v), 0);
    assert!(pl.v_cap < min, "full chunk {} below chunk_min_quote {min}", pl.v_cap);
    // Dust below the full chunk: refused.
    assert_sijka(&v.call(chunk_amm_ix(&v, pl.v_cap - 1, 0)), E::BbChunkBelowMin);
    // The full chunk runs (before AR2-10: BbChunkBelowMin forever).
    let supply0 = v.mint_supply(&ck.mint);
    let m = ok(v.call(chunk_amm_ix(&v, 0, 0)));
    let e = event(&m.logs, "SJKEVCHK");
    let (ev_v, bought, burned) = (u64_at(&e, 18), u64_at(&e, 50), u64_at(&e, 58));
    assert_eq!(ev_v, pl.v_cap);
    assert!(bought > 0 && burned == bought);
    assert_eq!(v.mint_supply(&ck.mint), supply0 - bought);
    println!("AR2-10 small pool: Q {q1} v {ev_v} (chunk_min {min}) bought {bought}");
}
