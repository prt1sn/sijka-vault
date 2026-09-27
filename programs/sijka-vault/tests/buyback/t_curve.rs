// Copyright (c) 2026 prt1sn. All rights reserved.
//! `bb_chunk_curve` (tag 44) on the real pump binary and a live SOL / USDC
//! bonding-curve coin: SPEC §5.5.2, §5.5.3, §5.5.8; TD-15…TD-32, TD-61,
//! TD-63, TD-67; U-29, U-30, U-34, U-51. SPEC v4: the chunk is signed by the
//! keeper with its own `min_out` (no spot guard, no program-side floor).

use sijka_vault::constants as c;
use sijka_vault::error::SijkaError as E;
use solana_keypair::Keypair;
use solana_signer::Signer;

use crate::harness::*;
use crate::pumpix::*;

/// Expected chunk plan from the state, the live curve and the budget
/// (SPEC §5.5.2, independent re-implementation). SPEC v4: `min_out` is the
/// keeper's; the harness floor of `chunk_*_ix(…, 0)` is 1.
pub struct Plan {
    pub v: u64,
    pub v_cap: u64,
    pub min_out: u64,
    pub p_ref: u128,
    pub q_ref: u64,
}

pub fn plan(v: &Vault, q_now: u64, avail: u64, max_quote_in: u64) -> Plan {
    let bs = v.bs();
    let p = bs.buyback_params();
    let p_ref = bs.ema_price_x64().min(bs.last_obs_price_x64());
    let q_ref = q_now.min(bs.last_obs_quote()).min(bs.q_ema());
    let v_cap = ((u128::from(q_ref) * u128::from(p.chunk_bps()) / 10_000) as u64).min(p.chunk_max_quote());
    let arg = if max_quote_in == 0 { u64::MAX } else { max_quote_in };
    let vv = avail.min(v_cap).min(arg);
    Plan { v: vv, v_cap, min_out: 1, p_ref, q_ref }
}

pub fn avail_sol(v: &Vault) -> u64 {
    v.lamports(&v.k.buyback_authority).saturating_sub(v.reserve())
}

/// TD-15 (U-30, U-34): one chunk on the curve. `buyback_authority` is a
/// plain (non-whitelisted) PDA of our program signing through
/// `invoke_signed`; pump takes exactly `v` plus the rent of the accounts it
/// creates; everything bought is burned (`burn_checked` Token-2022, supply
/// −bought); counters and `SJKEVCHK`.
#[test]
fn chunk_on_curve_buys_and_burns_everything() {
    let mut v = vault!(Setup::sol("solcurve"));
    v.fund_authority(2 * LAMPORTS_PER_SOL);
    v.warm();
    let ck = v.coin().clone();
    let k0 = v.k.buyback_authority;
    let (vt0, vq0, rt0, _) = curve_reserves(&v);
    let pl = plan(&v, vq0, avail_sol(&v), 0);
    assert_eq!(pl.p_ref, price_x64(vq0, vt0), "flat market: P_ref = spot");
    let lam0 = v.lamports(&k0);
    let supply0 = v.mint_supply(&ck.mint);
    let cv0 = v.lamports(&ck.creator_vault);
    assert!(!v.exists(&pump_uva(&k0)), "user_volume_accumulator is cold before the first chunk");
    let (slot, now) = v.clock();
    let ix = chunk_curve_ix(&v, 0, 0);
    let m = ok(v.call(ix));
    println!("U-37 tag 44 CU (first chunk, cold accounts): {}", m.compute_units_consumed);
    assert!(m.compute_units_consumed < 400_000, "tag 44 above its 400k limit");
    let e = event(&m.logs, "SJKEVCHK");
    assert_eq!(e.len(), 138);
    assert_eq!(e[17], 1, "venue CURVE");
    let (ev_v, spent, rent_extra, min_out, bought, burned) =
        (u64_at(&e, 18), u64_at(&e, 26), u64_at(&e, 34), u64_at(&e, 42), u64_at(&e, 50), u64_at(&e, 58));
    assert_eq!(ev_v, pl.v, "v = min(Q_ref·chunk_bps, chunk_max, budget)");
    assert_eq!(min_out, pl.min_out, "min_out = the keeper's (harness floor 1, SPEC v4)");
    assert_eq!(u128_at(&e, 66), price_x64(vq0, vt0), "p_now");
    assert_eq!(u128_at(&e, 82), pl.p_ref);
    assert_eq!(u64_at(&e, 98), pl.q_ref);
    assert_eq!(u64_at(&e, 106), slot);
    let lam1 = v.lamports(&k0);
    assert_eq!(lam0 - lam1, spent + rent_extra, "lamports of k0 = quote spent + rent");
    assert_eq!(spent, pl.v, "exact-quote-in spends all of v on the curve");
    assert!(rent_extra <= c::MAX_RENT_EXTRA, "U-34: rent {rent_extra} within MAX_RENT_EXTRA");
    println!(
        "U-34 curve cold chunk: rent taken by pump = {rent_extra} lamports (MAX_RENT_EXTRA {})",
        c::MAX_RENT_EXTRA
    );
    assert!(v.exists(&pump_uva(&k0)), "pump created user_volume_accumulator (init_if_needed, paid by k0)");
    assert!(bought >= min_out && bought > 0);
    assert_eq!(burned, bought, "everything bought is burned");
    assert_eq!(v.token_amount(&v.buyback_token()), 0, "buyback_token empty after the chunk");
    assert_eq!(v.mint_supply(&ck.mint), supply0 - bought, "supply decreased by the burn");
    let (vt1, vq1, rt1, _) = curve_reserves(&v);
    assert_eq!(rt0 - rt1, bought, "real_token_reserves moved by the bought amount");
    assert_eq!(vt0 - vt1, bought);
    assert!(vq1 > vq0 && vq1 - vq0 < spent, "virtual quote grew by the net (after fees)");
    println!(
        "curve chunk: v {} spent {} bought {} net to curve {} creator vault +{}",
        pl.v,
        spent,
        bought,
        vq1 - vq0,
        v.lamports(&ck.creator_vault) - cv0
    );
    let bs = v.bs();
    assert_eq!(bs.n_chunks(), 1);
    assert_eq!(bs.cum_quote_spent_curve(), spent);
    assert_eq!(bs.cum_quote_spent_amm(), 0);
    assert_eq!(bs.cum_bought_tokens(), bought);
    assert_eq!(bs.cum_burned_tokens(), bought);
    assert_eq!(bs.cum_rent_spent(), rent_extra);
    assert_eq!(bs.cum_payout_buyback_spent(), 0, "SOL pair: USDC counter untouched");
    assert_eq!(bs.last_buy_ts(), now);
    assert_eq!(bs.last_buy_slot(), slot);
    let interval = u128::from(bs.buyback_params().buy_min_interval_s());
    let wait = (interval * u128::from(spent)).div_ceil(u128::from(pl.v_cap)) as i64;
    assert_eq!(bs.next_buy_ts(), now + wait, "cool-down proportional to quote_spent / v_cap (RT-6)");
    assert_eq!(u64_at(&e, 114), bought);
    assert_eq!(u64_at(&e, 122), 0);
    assert_eq!(u64_at(&e, 130), 1);
    assert!(v.lamports(&k0) >= v.rent(0), "k0 stays rent-exempt");
}

/// pump's exact-quote-in output (research 07 §1.4, IDL doc of
/// `buy_exact_sol_in`) with the live 95 + 30 bps.
pub fn pump_curve_out(v_in: u64, vq: u64, vt: u64) -> u64 {
    let total = 125u128;
    let spend = u128::from(v_in);
    let mut net = spend * 10_000 / (10_000 + total);
    let fees = (net * 95).div_ceil(10_000) + (net * 30).div_ceil(10_000);
    if net + fees > spend {
        net -= net + fees - spend;
    }
    ((net - 1) * u128::from(vt) / (u128::from(vq) + net - 1)) as u64
}

/// TD-17…TD-19: stale observation, same slot as the observation, and the
/// volume-proportional cool-down after a chunk (also same slot as the chunk).
#[test]
fn chunk_timing_rules() {
    let mut v = vault!(Setup::sol("solcurve"));
    v.fund_authority(3 * LAMPORTS_PER_SOL);
    v.warm_up(40);
    let (s0, t0) = v.clock();
    // Same slot as the last observation.
    assert_sijka(&v.call(chunk_curve_ix(&v, 0, 0)), E::BbSameSlot);
    // Observation older than obs_max_age_s = 120 s.
    v.set_clock(s0 + 1, t0 + 121);
    assert_sijka(&v.call(chunk_curve_ix(&v, 0, 0)), E::BbStaleObservation);
    // Exactly 120 s is still fresh.
    v.set_clock(s0 + 1, t0 + 120);
    ok(v.call(chunk_curve_ix(&v, 0, 0)));

    // Fresh vault for the cool-down rules.
    let mut v = vault!(Setup::sol("solcurve"));
    v.fund_authority(3 * LAMPORTS_PER_SOL);
    v.warm_up(40);
    let (s0, t0) = v.clock();
    v.set_clock(s0 + 1, t0 + 1);
    ok(v.call(chunk_curve_ix(&v, 0, 0)));
    let bs = v.bs();
    let next = bs.next_buy_ts();
    assert_eq!(bs.last_buy_slot(), s0 + 1);
    assert!(next > t0 + 1);
    // next_buy_ts reached, but still the slot of the last buy.
    v.set_clock(s0 + 1, next);
    assert_sijka(&v.call(chunk_curve_ix(&v, 0, 0)), E::BbBuyTooSoon);
    // A later slot, one second before next_buy_ts.
    v.set_clock(s0 + 2, next - 1);
    assert_sijka(&v.call(chunk_curve_ix(&v, 0, 0)), E::BbBuyTooSoon);
    // Both conditions met.
    v.set_clock(s0 + 2, next);
    ok(v.call(chunk_curve_ix(&v, 0, 0)));
}

/// TD-20 (SPEC v4, DECISIONS §23 item 3): no spot guard. The market buys ~3%
/// of the curve's Q right before our chunk (spot ≈ +6% above the EMA
/// reference): the chunk still executes, its size still bounded by `Q_ref`.
/// The keeper's `min_out` still protects: a floor quoted before the market
/// buy (a front-run between the quote and the chunk) is refused by pump
/// (6042 BuySlippageBelowMinTokensOut) with nothing moved; a floor quoted at
/// the live reserves passes and is what the event reports.
#[test]
fn chunk_runs_with_spot_far_above_the_ema() {
    let mut v = vault!(Setup::sol("solcurve"));
    v.fund_authority(2 * LAMPORTS_PER_SOL);
    v.warm();
    let (vt0, vq0, _, _) = curve_reserves(&v);
    let pl0 = plan(&v, vq0, avail_sol(&v), 0);
    let quoted_before = pump_curve_out(pl0.v, vq0, vt0) * 995 / 1_000;
    let t = Trader::new(&mut v, 10 * LAMPORTS_PER_SOL);
    ok(t.curve_buy(&mut v, vq0 * 3 / 100));
    let (vt1, vq1, _, _) = curve_reserves(&v);
    let bs = v.bs();
    let p_ref = bs.ema_price_x64().min(bs.last_obs_price_x64());
    assert!(price_x64(vq1, vt1) * 10_000 > p_ref * 10_500, "spot more than 5% above P_ref");
    // The keeper's pre-buy floor: pump refuses, nothing moves.
    let k0 = v.k.buyback_authority;
    let (lam0, n0) = (v.lamports(&k0), v.bs().n_chunks());
    let res = v.call(chunk_curve_ix(&v, 0, quoted_before));
    assert_custom(&res, 6042);
    assert_eq!((v.lamports(&k0), v.bs().n_chunks()), (lam0, n0));
    // A floor at the live reserves: the chunk runs, v still ≤ chunk_bps of Q_ref.
    let pl = plan(&v, vq1, avail_sol(&v), 0);
    assert_eq!(pl.q_ref, vq0.min(bs.q_ema()), "Q_ref ignores the pumped q_now");
    let live = pump_curve_out(pl.v, vq1, vt1) * 99 / 100;
    let m = ok(v.call(chunk_curve_ix(&v, 0, live)));
    let e = event(&m.logs, "SJKEVCHK");
    assert_eq!(u64_at(&e, 18), pl.v);
    assert_eq!(u64_at(&e, 42), live, "min_out = the keeper's");
    assert!(u64_at(&e, 50) >= live);
    assert_eq!(u128_at(&e, 66), price_x64(vq1, vt1), "p_now");
}

/// SPEC v4 (DECISIONS §23 items 3 and 6): only `config.keeper`, signed, runs
/// a chunk, and its `min_out` must be ≥ 1: another signer, the admin, the
/// keeper not signing, `keeper == 0` → UnauthorizedKeeper; `min_out = 0` →
/// InvalidInstructionData; after `set_keeper` the old key fails. Nothing is
/// bought on a refusal.
#[test]
fn chunk_only_by_the_keeper() {
    let mut v = vault!(Setup::sol("solcurve"));
    v.fund_authority(2 * LAMPORTS_PER_SOL);
    v.warm();
    let n0 = v.bs().n_chunks();
    let stranger = Keypair::new();
    v.svm.airdrop(&stranger.pubkey(), LAMPORTS_PER_SOL).unwrap();
    let admin = v.admin.insecure_clone();
    let last = CURVE_KEEPER_INDEX;
    for who in [&stranger, &admin] {
        let mut ix = chunk_curve_ix(&v, 0, 0);
        ix.accounts[last] = solana_instruction::AccountMeta::new_readonly(who.pubkey(), true);
        assert_sijka(&v.send(vec![ix], &[who]), E::UnauthorizedKeeper);
    }
    let mut ix = chunk_curve_ix(&v, 0, 0);
    ix.accounts[last].is_signer = false;
    assert_sijka(&v.send(vec![ix], &[&stranger]), E::UnauthorizedKeeper);
    let rc = Recips::pick(&v);
    assert_sijka(&v.call(chunk_curve_ix_raw(&v, 0, 0, &rc)), E::InvalidInstructionData);
    assert_eq!(v.bs().n_chunks(), n0);
    ok(v.set_keeper(&solana_pubkey::Pubkey::default()));
    assert_sijka(&v.call(chunk_curve_ix(&v, 0, 0)), E::UnauthorizedKeeper);
    ok(v.set_keeper(&stranger.pubkey()));
    assert_sijka(&v.call(chunk_curve_ix(&v, 0, 0)), E::UnauthorizedKeeper);
    let mut ix = chunk_curve_ix(&v, 0, 0);
    ix.accounts[last] = solana_instruction::AccountMeta::new_readonly(stranger.pubkey(), true);
    ok(v.send(vec![ix], &[&stranger]));
    assert_eq!(v.bs().n_chunks(), n0 + 1);
}

/// Outer index of the keeper in tag 44 (after the 27 pump accounts, SPEC v4).
pub const CURVE_KEEPER_INDEX: usize = 31;

/// TD-21…TD-23: `jitodontfront` missing, a foreign instruction in the
/// transaction, a CPI wrapper.
#[test]
fn chunk_composition_rules() {
    let mut v = vault!(Setup::sol("solcurve"));
    v.fund_authority(2 * LAMPORTS_PER_SOL);
    v.warm();
    let mut ix = chunk_curve_ix(&v, 0, 0);
    ix.accounts[3].pubkey = Keypair::new().pubkey();
    assert_sijka(&v.call(ix), E::BbMissingDontFront);
    let ix = chunk_curve_ix(&v, 0, 0);
    let kp = v.keeper.insecure_clone();
    let res = v.send(vec![foreign_ix(&kp.pubkey()), ix.clone()], &[&kp]);
    assert_sijka(&res, E::ForeignInstruction);
    let res = v.send(vec![crate::mocks::wrap_cpi(ix.clone())], &[&kp]);
    assert_sijka(&res, E::NotTopLevel);
    ok(v.send(vec![ix], &[&kp]));
}

/// TD-24: substituted curve / user / buyback_token / creator vault, and a
/// fee-recipient slot pointing at one of our accounts → BbPinnedAccountMismatch.
#[test]
fn chunk_rejects_substituted_accounts() {
    let mut v = vault!(Setup::sol("solcurve"));
    v.fund_authority(2 * LAMPORTS_PER_SOL);
    v.warm();
    let t = Trader::new(&mut v, LAMPORTS_PER_SOL);
    let other_curve = v.fx.key("solamm bonding_curve");
    let cases: Vec<(usize, solana_pubkey::Pubkey, &str)> = vec![
        (14, other_curve, "bonding_curve"),
        (15, v.fx.key("solamm curve base ata"), "associated_base_bonding_curve"),
        (17, t.pubkey(), "user"),
        (18, t.base_ata(&v), "associated_base_user"),
        (20, Keypair::new().pubkey(), "creator_vault"),
        (21, Keypair::new().pubkey(), "associated_creator_vault"),
        (24, pump_uva(&t.pubkey()), "user_volume_accumulator"),
        (10, v.k.buyback_state, "fee_recipient = buyback_state"),
        (12, v.k.buyback_authority, "buyback_fee_recipient = buyback_authority"),
        (11, v.buyback_token(), "associated_quote_fee_recipient = buyback_token"),
        (13, v.k.buyback_usdc, "assoc buyback fee recipient = buyback_usdc"),
    ];
    for (i, k, name) in cases {
        let mut ix = chunk_curve_ix(&v, 0, 0);
        ix.accounts[i].pubkey = k;
        let res = v.call(ix);
        println!("substitution: {name}");
        assert_sijka(&res, E::BbPinnedAccountMismatch);
    }
    // Writable flags are required where pump writes (SPEC §5.0.3).
    let mut ix = chunk_curve_ix(&v, 0, 0);
    ix.accounts[5].is_writable = false;
    assert_sijka(&v.call(ix), E::AccountNotWritable);
}

/// TD-25 / U-29: pump itself checks `fee_recipient` and
/// `buyback_fee_recipient` against its Global; any of the listed recipients
/// is accepted.
#[test]
fn pump_checks_fee_recipients_itself() {
    let mut v = vault!(Setup::sol("solcurve"));
    v.fund_authority(2 * LAMPORTS_PER_SOL);
    v.warm();
    let good = Recips::pick(&v);
    let stranger = Keypair::new().pubkey();
    v.set_lamports(&stranger, LAMPORTS_PER_SOL);
    let rc = Recips { fee_recipient: stranger, ..good.clone() };
    let res = v.call(chunk_curve_ix_with(&v, 0, 0, &rc));
    let code_fee = match &res {
        Err(f) => custom_code(f),
        Ok(_) => None,
    };
    println!(
        "U-29 random fee_recipient: {:?} logs tail {:?}",
        code_fee,
        logs_of(&res).iter().rev().take(4).collect::<Vec<_>>()
    );
    assert!(res.is_err(), "U-29: pump must reject an unknown fee_recipient");
    let rc = Recips { buyback_fee_recipient: stranger, ..good.clone() };
    let res = v.call(chunk_curve_ix_with(&v, 0, 0, &rc));
    let code_bb = match &res {
        Err(f) => custom_code(f),
        Ok(_) => None,
    };
    println!("U-29 random buyback_fee_recipient: {:?}", code_bb);
    assert_custom(&res, 6057);
    // Another listed recipient (Global.fee_recipients[3], buyback_fee_recipients[5]) works.
    let fees = Recips::global_fee_recipients(&v);
    let bbs = Recips::global_buyback_recipients(&v);
    let rc = Recips { fee_recipient: fees[4], buyback_fee_recipient: bbs[5], ..good };
    ok(v.call(chunk_curve_ix_with(&v, 0, 0, &rc)));
}

/// TD-26: the budget `lamports(k0) − RESERVE` below `chunk_min_quote` →
/// BbChunkBelowMin; a budget below `v_cap` limits `v`.
#[test]
fn chunk_budget_limits() {
    let mut v = vault!(Setup::sol("solcurve"));
    let min = v.bs().buyback_params().chunk_min_quote();
    v.fund_authority(min - 1);
    v.warm();
    let ix = chunk_curve_ix(&v, 0, 0);
    assert_sijka(&v.call(ix), E::BbChunkBelowMin);
    // Budget between chunk_min and v_cap: v = budget.
    let (_, vq, _, _) = curve_reserves(&v);
    let pl = plan(&v, vq, u64::MAX, 0);
    let budget = (pl.v_cap + min) / 2;
    v.fund_authority(budget);
    let m = ok(v.call(chunk_curve_ix(&v, 0, 0)));
    let e = event(&m.logs, "SJKEVCHK");
    assert_eq!(u64_at(&e, 18), budget, "v = budget");
    // max_quote_in below the budget also limits v.
    let mut v = vault!(Setup::sol("solcurve"));
    v.fund_authority(2 * LAMPORTS_PER_SOL);
    v.warm();
    let m = ok(v.call(chunk_curve_ix(&v, min + 7, 0)));
    assert_eq!(u64_at(&event(&m.logs, "SJKEVCHK"), 18), min + 7);
    // chunk_bps = 100% of Q: v_cap = chunk_max_quote (1 SOL).
    let mut v = vault!(Setup::sol("solcurve"));
    v.fund_authority(3 * LAMPORTS_PER_SOL);
    v.set_params(|p| put_u16(p, bp::CHUNK_BPS, 10_000));
    v.warm();
    let m = ok(v.call(chunk_curve_ix(&v, 0, 0)));
    assert_eq!(u64_at(&event(&m.logs, "SJKEVCHK"), 18), LAMPORTS_PER_SOL, "v = chunk_max_quote");
}

/// TD-27 / TD-63: near the end of the curve `v` is clamped to
/// `v_max = ⌊(R−1)·vQ/(vT−R+1)⌋`, pump accepts it and the curve stays
/// incomplete; `v_max < chunk_min_quote` and `R = 1` → BbCurveNearComplete.
#[test]
fn chunk_near_the_end_of_the_curve() {
    let mut v = vault!(Setup::sol("solcurve"));
    v.fund_authority(2 * LAMPORTS_PER_SOL);
    v.warm();
    let (vt, vq, _, _) = curve_reserves(&v);
    let pl = plan(&v, vq, avail_sol(&v), 0);
    let t0_full = u128::from(pl.v) * u128::from(vt) / (u128::from(vq) + u128::from(pl.v));
    // R just above half of the full chunk's t0.
    let r = (t0_full / 2) as u64 + 1;
    let curve = v.coin().curve;
    v.patch(&curve, |d| d[24..32].copy_from_slice(&r.to_le_bytes()));
    let v_max = (u128::from(r - 1) * u128::from(vq) / u128::from(vt - r + 1)) as u64;
    assert!(v_max < pl.v && v_max >= v.bs().buyback_params().chunk_min_quote());
    let m = ok(v.call(chunk_curve_ix(&v, 0, 0)));
    let e = event(&m.logs, "SJKEVCHK");
    assert_eq!(u64_at(&e, 18), v_max, "v clamped to v_max");
    let bought = u64_at(&e, 50);
    assert!(bought < r, "t0 < real_token_reserves");
    let (_, _, r1, complete) = curve_reserves(&v);
    assert_eq!(complete, 0, "curve not completed by our chunk");
    assert_eq!(r1, r - bought);

    // v_max below chunk_min_quote.
    let mut v = vault!(Setup::sol("solcurve"));
    v.fund_authority(2 * LAMPORTS_PER_SOL);
    v.warm();
    let min = v.bs().buyback_params().chunk_min_quote();
    let (vt, vq, _, _) = curve_reserves(&v);
    let r_small = (u128::from(min / 2) * u128::from(vt) / u128::from(vq)) as u64;
    let curve = v.coin().curve;
    v.patch(&curve, |d| d[24..32].copy_from_slice(&r_small.to_le_bytes()));
    assert_sijka(&v.call(chunk_curve_ix(&v, 0, 0)), E::BbCurveNearComplete);
    v.patch(&curve, |d| d[24..32].copy_from_slice(&1u64.to_le_bytes()));
    assert_sijka(&v.call(chunk_curve_ix(&v, 0, 0)), E::BbCurveNearComplete);
}

/// TD-28 (SPEC v4, DECISIONS §23 item 6): the keeper's `min_out` is the only
/// price limit and is passed to pump as is (no program-side floor from the
/// pump fees, no early check): one above what pump pays → pump 6042
/// BuySlippageBelowMinTokensOut; exactly what pump pays passes and is the
/// `min_out` of the event.
#[test]
fn chunk_keeper_min_out() {
    let mut v = vault!(Setup::sol("solcurve"));
    v.fund_authority(2 * LAMPORTS_PER_SOL);
    v.warm();
    let (vt, vq, _, _) = curve_reserves(&v);
    let pl = plan(&v, vq, avail_sol(&v), 0);
    let pump_out = pump_curve_out(pl.v, vq, vt);
    println!("keeper min_out test: v {} pump formula {}", pl.v, pump_out);
    assert_custom(&v.call(chunk_curve_ix(&v, 0, pump_out + 1)), 6042);
    let m = ok(v.call(chunk_curve_ix(&v, 0, pump_out)));
    let e = event(&m.logs, "SJKEVCHK");
    assert_eq!(u64_at(&e, 42), pump_out);
    assert_eq!(u64_at(&e, 50), pump_out, "pump paid exactly its formula");
}

/// TD-30, TD-52: SIJKA sent to `buyback_token` is burned by the next chunk
/// (`cum_burned ≥ cum_bought`) or by `bb_burn`; `bb_burn` of a zero balance is
/// Ok without an event.
#[test]
fn donations_are_burned() {
    let mut v = vault!(Setup::sol("solcurve"));
    v.fund_authority(2 * LAMPORTS_PER_SOL);
    let ck = v.coin().clone();
    // A holder buys and donates to buyback_token.
    let t = Trader::new(&mut v, 10 * LAMPORTS_PER_SOL);
    ok(t.curve_buy(&mut v, LAMPORTS_PER_SOL / 20));
    let donated = t.base(&v) / 2;
    let donate = {
        let mut d = vec![12u8];
        d.extend_from_slice(&donated.to_le_bytes());
        d.push(6);
        solana_instruction::Instruction {
            program_id: ck.token_program,
            accounts: vec![
                solana_instruction::AccountMeta::new(t.base_ata(&v), false),
                solana_instruction::AccountMeta::new_readonly(ck.mint, false),
                solana_instruction::AccountMeta::new(v.buyback_token(), false),
                solana_instruction::AccountMeta::new_readonly(t.pubkey(), true),
            ],
            data: d,
        }
    };
    let kp = t.kp.insecure_clone();
    ok(v.send(vec![donate.clone()], &[&kp]));
    // bb_burn burns the donation alone.
    let supply0 = v.mint_supply(&ck.mint);
    let m = ok(v.call(v.bb_burn_ix()));
    let e = event(&m.logs, "SJKEVBRN");
    assert_eq!(e.len(), 33);
    assert_eq!(u64_at(&e, 17), donated);
    assert_eq!(u64_at(&e, 25), donated);
    assert_eq!(v.mint_supply(&ck.mint), supply0 - donated);
    assert_eq!(v.bs().cum_burned_tokens(), donated);
    // Zero balance: Ok without an event.
    let m = ok(v.call(v.bb_burn_ix()));
    assert!(events(&m.logs).is_empty(), "no event on a zero balance");
    // A donation before a chunk is burned with the purchase.
    ok(v.send(
        vec![{
            let mut ix = donate;
            ix.data[1..9].copy_from_slice(&(t.base(&v)).to_le_bytes());
            ix
        }],
        &[&kp],
    ));
    let donated2 = v.token_amount(&v.buyback_token());
    v.warm();
    let m = ok(v.call(chunk_curve_ix(&v, 0, 0)));
    let e = event(&m.logs, "SJKEVCHK");
    let (bought, burned) = (u64_at(&e, 50), u64_at(&e, 58));
    assert_eq!(burned, bought + donated2);
    let bs = v.bs();
    assert_eq!(bs.cum_bought_tokens(), bought);
    assert_eq!(bs.cum_burned_tokens(), donated + donated2 + bought);
    assert!(bs.cum_burned_tokens() >= bs.cum_bought_tokens());
    assert_eq!(v.token_amount(&v.buyback_token()), 0);
}

/// TD-67 (review RT-6): a dust chunk occupies only its share of the interval
/// (`⌈60·v/v_cap⌉` s), so a full chunk follows right after; a full chunk
/// closes the window for 60 s.
#[test]
fn cooldown_is_proportional_to_volume() {
    let mut v = vault!(Setup::sol("solcurve"));
    v.fund_authority(3 * LAMPORTS_PER_SOL);
    v.warm();
    let min = v.bs().buyback_params().chunk_min_quote();
    let m = ok(v.call(chunk_curve_ix(&v, min, 0)));
    let e = event(&m.logs, "SJKEVCHK");
    let spent = u64_at(&e, 26);
    let (_, vq, _, _) = curve_reserves(&v);
    let bs = v.bs();
    // Q_ref = min(q_now, last_obs_quote, q_ema) is unchanged by our own buy.
    let v_cap = plan(&v, vq, u64::MAX, 0).v_cap;
    let wait = (60u128 * u128::from(spent)).div_ceil(u128::from(v_cap)) as i64;
    println!("dust chunk {spent} of v_cap {v_cap}: wait {wait} s");
    assert_eq!(bs.next_buy_ts() - v.now(), wait, "next_buy_ts = now + ⌈60·spent/v_cap⌉");
    assert!(wait < 60, "dust does not close the whole interval");
    // Full chunk right after the short wait, in a later slot.
    let t = bs.next_buy_ts();
    let s = v.slot();
    v.set_clock(s + 1, t);
    let m = ok(v.call(chunk_curve_ix(&v, 0, 0)));
    let spent_full = u64_at(&event(&m.logs, "SJKEVCHK"), 26);
    let bs = v.bs();
    assert!(spent_full > spent);
    assert!(bs.next_buy_ts() - v.now() >= 59, "a full chunk waits ~60 s");
    v.tick(15, 1);
    ok(v.observe());
    v.tick(15, 1);
    assert_sijka(&v.call(chunk_curve_ix(&v, 0, 0)), E::BbBuyTooSoon);
}

/// TD-32: USDC pair on the live USDC curve: quote from `buyback_usdc`,
/// `cum_payout_buyback_spent`, rent of the cold pump accounts from the float;
/// TD-31: below rent(0) → BbFloatLow; TD-69 (audit EA-1): after pump took
/// its rent out of RESERVE, the next chunk still runs.
#[test]
fn usdc_curve_chunk_and_float() {
    let mut v = vault!(Setup::usdc("usdccurve"));
    let k0 = v.k.buyback_authority;
    let bb_usdc = v.k.buyback_usdc;
    v.set_token_account(bb_usdc, tokenkeg(), usdc(), k0, 500_000_000);
    let r = v.reserve();
    let rent0 = v.rent(0);
    v.set_lamports(&k0, rent0 - 1);
    v.warm();
    assert_sijka(&v.call(chunk_curve_ix(&v, 0, 0)), E::BbFloatLow);
    v.set_lamports(&k0, r);
    let (vt, vq, _, _) = curve_reserves(&v);
    let pl = plan(&v, vq, 500_000_000, 0);
    let lam0 = v.lamports(&k0);
    let m = ok(v.call(chunk_curve_ix(&v, 0, 0)));
    println!("U-37 tag 44 CU (USDC curve): {}", m.compute_units_consumed);
    let e = event(&m.logs, "SJKEVCHK");
    let (spent, rent_extra, bought) = (u64_at(&e, 26), u64_at(&e, 34), u64_at(&e, 50));
    assert_eq!(u64_at(&e, 18), pl.v);
    assert_eq!(spent, pl.v);
    assert_eq!(v.token_amount(&bb_usdc), 500_000_000 - spent);
    assert_eq!(lam0 - v.lamports(&k0), rent_extra);
    assert!(rent_extra <= c::MAX_RENT_EXTRA, "U-34 (USDC): rent {rent_extra}");
    println!("U-34 USDC curve cold chunk: rent {rent_extra} lamports");
    assert!(bought >= pl.min_out);
    assert_eq!(u64_at(&e, 122), spent, "cum_payout_buyback_spent in the event");
    let bs = v.bs();
    assert_eq!(bs.cum_payout_buyback_spent(), spent);
    assert_eq!(bs.cum_quote_spent_curve(), spent);
    let _ = vt;
    // TD-69 (audit EA-1): k0 is now RESERVE − rent; the next chunk (warm
    // accounts) must not stop at BbFloatLow.
    assert_eq!(v.lamports(&k0), r - rent_extra);
    v.warm();
    let m = ok(v.call(chunk_curve_ix(&v, 0, 0)));
    let e = event(&m.logs, "SJKEVCHK");
    let (spent2, rent2) = (u64_at(&e, 26), u64_at(&e, 34));
    println!("EA-1 (USDC pair): k0 {} below RESERVE {r}; next chunk spent {spent2}, rent {rent2}", r - rent_extra);
    assert!(spent2 > 0);
    assert_eq!(v.lamports(&k0), r - rent_extra - rent2);
    assert!(v.lamports(&k0) >= rent0);
}

/// TD-61 / U-51: after a CTO (`is_holder_reward = 1`, `creator = X`), the
/// chunk pays pump with the creator vault derived from the live creator and
/// works on the mainnet binary with the same 27 accounts; the pinned
/// k15 / k16 are refused before the CPI.
#[test]
fn chunk_after_cto_uses_the_live_creator_vault() {
    let mut v = vault!(Setup::sol("solcurve"));
    v.fund_authority(2 * LAMPORTS_PER_SOL);
    v.warm();
    let ck = v.coin().clone();
    let x = pda(&[b"holder-rewards", ck.mint.as_ref()], &pump());
    v.patch(&ck.curve, |d| {
        d[49..81].copy_from_slice(x.as_ref());
        d[124] = 1;
    });
    // Pinned vault (k15/k16) → refused before the CPI.
    let mut ix = chunk_curve_ix(&v, 0, 0);
    ix.accounts[20].pubkey = ck.creator_vault;
    ix.accounts[21].pubkey = ck.creator_vault_ata;
    assert_sijka(&v.call(ix), E::BbPinnedAccountMismatch);
    // Vault of the live creator: the builder derives it.
    let (cv_x, _) = ck.creator_vault_for(&x);
    let cv0 = v.lamports(&cv_x);
    let res = v.call(chunk_curve_ix(&v, 0, 0));
    match &res {
        Ok(m) => {
            let e = event(&m.logs, "SJKEVCHK");
            println!(
                "U-51 confirmed (curve): chunk after CTO bought {} ; creator vault of X +{} lamports",
                u64_at(&e, 50),
                v.lamports(&cv_x) - cv0
            );
        }
        Err(f) => panic!("U-51 refuted on the curve: {:?}\n{}", f.err, f.meta.logs.join("\n")),
    }
}
