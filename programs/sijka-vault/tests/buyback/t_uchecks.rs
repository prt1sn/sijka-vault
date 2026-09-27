// Copyright (c) 2026 prt1sn. All rights reserved.
//! SPEC §10.1 UNVERIFIED items of the buyback area measured on the real
//! pump / pump_amm binaries (the others live next to the flow they need):
//! U-46 (USDC creator-fee distribution), U-48 (sandwich economics).

use solana_signer::Signer;

use crate::harness::*;
use crate::pumpix::*;

/// U-46: on a USDC coin, `distribute_creator_fees_v2` pays the shareholder's
/// canonical USDC ATA. With `initialize_ata = false` and no ATA of our
/// `fee_inbox`, pump refuses (expected 6070
/// UnableToDistributeCreatorFeesToUninitializedAccount); with `true` pump
/// creates it (payer = keeper) and pays; afterwards `false` works.
#[test]
fn u46_usdc_distribution_and_the_fee_inbox_ata() {
    let mut v = vault!(Setup::usdc("usdccurve").no_pin());
    let ck = v.coin().clone();
    let (_, cv_ata) = ck.creator_vault_for(&live_creator(&v));
    assert_eq!(live_creator(&v), ck.sharing_config);
    v.set_token_amount(&cv_ata, 5_000_000);
    let inbox = v.k.fee_inbox;
    let inbox_usdc = ata(&inbox, &tokenkeg(), &usdc());
    assert!(!v.exists(&inbox_usdc));
    let payer = v.keeper.insecure_clone();
    let res = v.send(vec![distribute_v2_ix(&v, &payer.pubkey(), false, &[inbox, inbox_usdc])], &[&payer]);
    let code = res.as_ref().err().and_then(custom_code);
    println!("U-46 initialize_ata=false, fee_inbox USDC ATA missing: {:?}", res.as_ref().err().map(|f| &f.err));
    println!("U-46 logs: {:?}", logs_of(&res).iter().rev().take(6).collect::<Vec<_>>());
    assert!(res.is_err(), "U-46: pump must not pay into a missing ATA without initialize_ata");
    if code != Some(6070) {
        println!("U-46: error code differs from the SPEC note (6070): {code:?}");
    }
    let lam0 = v.lamports(&payer.pubkey());
    let m = ok(v.send(vec![distribute_v2_ix(&v, &payer.pubkey(), true, &[inbox, inbox_usdc])], &[&payer]));
    let got = v.token_amount(&inbox_usdc);
    println!(
        "U-46 initialize_ata=true: fee_inbox_usdc created, received {got} of 5 000 000; vault ATA left {}; payer paid {} lamports; CU {}",
        v.token_amount(&cv_ata),
        lam0 - v.lamports(&payer.pubkey()),
        m.compute_units_consumed
    );
    assert!(v.exists(&inbox_usdc));
    assert!(got > 0);
    // With the ATA in place, false works; a 1-atom balance shows the threshold.
    let cv_left = v.token_amount(&cv_ata);
    v.set_token_amount(&cv_ata, cv_left + 1);
    let res = v.send(vec![distribute_v2_ix(&v, &payer.pubkey(), false, &[inbox, inbox_usdc])], &[&payer]);
    println!(
        "U-46 1 atom with existing ATA: {:?}, fee_inbox_usdc {} -> {}",
        res.as_ref().err().map(|f| &f.err),
        got,
        v.token_amount(&inbox_usdc)
    );
    v.set_token_amount(&cv_ata, cv_left + 2_000_000);
    ok(v.send(vec![distribute_v2_ix(&v, &payer.pubkey(), false, &[inbox, inbox_usdc])], &[&payer]));
    println!("U-46 2 USDC with existing ATA and initialize_ata=false: fee_inbox_usdc {}", v.token_amount(&inbox_usdc));
    assert!(v.token_amount(&inbox_usdc) >= got + 1_000_000);
}

/// U-34: the worst "cold" case: every `init_if_needed` account pump creates
/// at the buyer's expense is missing (volume accumulator and its quote ATA,
/// fee recipient's quote ATA, creator vault's quote ATA on the USDC curve;
/// coin creator vault ATA and protocol fee recipient ATA in the pools). The
/// rent pump takes from `buyback_authority` stays below MAX_RENT_EXTRA.
#[test]
fn u34_rent_of_cold_accounts_within_max_rent_extra() {
    use sijka_vault::constants::MAX_RENT_EXTRA;
    // USDC curve.
    let mut v = vault!(Setup::usdc("usdccurve"));
    let k0 = v.k.buyback_authority;
    let bb = v.k.buyback_usdc;
    v.set_token_account(bb, tokenkeg(), usdc(), k0, 500_000_000);
    v.fund_authority(0);
    v.warm();
    let rc = Recips::pick(&v);
    let ck = v.coin().clone();
    let cold = [ata(&rc.fee_recipient, &tokenkeg(), &usdc()), ck.creator_vault_ata];
    for k in cold {
        v.set_lamports(&k, 0);
    }
    let res = v.call(chunk_curve_ix(&v, 0, 0));
    match &res {
        Ok(m) => {
            let rent = u64_at(&event(&m.logs, "SJKEVCHK"), 34);
            println!(
                "U-34 USDC curve, all cold: rent {rent} (MAX_RENT_EXTRA {MAX_RENT_EXTRA}); recreated {:?}",
                cold.map(|k| v.exists(&k))
            );
            assert!(rent <= MAX_RENT_EXTRA);
        }
        Err(f) => println!("U-34 USDC curve, all cold: pump refused {:?} (does not create these ATAs)", f.err),
    }
    // Pools (SOL and USDC).
    for (coin, quote) in [("solamm", Quote::Sol), ("usdcamm", Quote::Usdc)] {
        let s = if quote == Quote::Sol { Setup::sol(coin) } else { Setup::usdc(coin) };
        let mut v = vault!(s);
        let k0 = v.k.buyback_authority;
        if quote == Quote::Usdc {
            let bb = v.k.buyback_usdc;
            v.set_token_account(bb, tokenkeg(), usdc(), k0, 1_000_000_000);
            v.fund_authority(0);
        } else {
            v.fund_authority(2 * LAMPORTS_PER_SOL);
        }
        v.warm();
        let rc = Recips::pick(&v);
        let ck = v.coin().clone();
        let cold = [ck.coin_creator_vault_ata, ata(&rc.amm_protocol, &tokenkeg(), &ck.quote_mint)];
        for k in cold {
            v.set_lamports(&k, 0);
        }
        let res = v.call(chunk_amm_ix_with(&v, 0, 0, &rc));
        match &res {
            Ok(m) => {
                let rent = u64_at(&event(&m.logs, "SJKEVCHK"), 34);
                println!("U-34 {coin}, all cold: rent {rent}; recreated {:?}", cold.map(|k| v.exists(&k)));
                assert!(rent <= MAX_RENT_EXTRA);
            }
            Err(f) => println!("U-34 {coin}, all cold: pump_amm refused {:?}", f.err),
        }
    }
}

/// One sandwich round on the live SOL curve: the attacker buys `x` right
/// before our chunk, sells everything right after. Returns (chunk executed,
/// attacker PnL in lamports, tokens our chunk bought).
fn sandwich(x: u64, hold_obs: usize) -> Option<(bool, i128, u64)> {
    let mut v = Vault::try_new(Setup::sol("solcurve"))?;
    v.fund_authority(2 * LAMPORTS_PER_SOL);
    v.warm_up(40);
    let a = Trader::new(&mut v, 200 * LAMPORTS_PER_SOL);
    let sol0 = i128::from(v.lamports(&a.pubkey()));
    if x > 0 {
        ok(a.curve_buy(&mut v, x));
    }
    // Multi-block variant (SPEC §5.5.2 "vector E"): hold the pump while the
    // EMA climbs through the clamp.
    for _ in 0..hold_obs {
        v.tick(15, 1);
        ok(v.observe());
    }
    v.tick(1, 1);
    let res = v.call(chunk_curve_ix(&v, 0, 0));
    let (done, bought) = match &res {
        Ok(m) => (true, u64_at(&event(&m.logs, "SJKEVCHK"), 50)),
        Err(_) => (false, 0),
    };
    let bal = a.base(&v);
    if bal > 0 {
        ok(a.curve_sell(&mut v, bal));
    }
    let pnl = i128::from(v.lamports(&a.pubkey())) - sol0;
    Some((done, pnl, bought))
}

/// U-48: with the live curve reserves (vQ ≈ 31 SOL) and live fees (1.25% per
/// side), front-running our chunk never pays: the sandwich costs the attacker
/// more in fees than our chunk (≤ chunk_bps of Q_ref) moves the price, with no
/// spot guard (SPEC v4; the harness keeper floor is 1, so only the chunk size
/// limits the loss here); holding a pump across observations (the reserve EMA
/// climbs only 0.25% per 15 s) does not help. The multi-victim variant is why
/// the chunks are keeper-signed (DECISIONS §23 item 3).
#[test]
fn u48_sandwich_is_unprofitable_on_the_live_curve() {
    let Some((_, _, base_bought)) = sandwich(0, 0) else { return };
    println!("U-48 baseline: our chunk bought {base_bought} tokens without an attacker");
    for (x, hold) in [
        (LAMPORTS_PER_SOL / 100, 0),
        (LAMPORTS_PER_SOL / 20, 0),
        (LAMPORTS_PER_SOL / 10, 0),
        (LAMPORTS_PER_SOL * 3 / 10, 0),
        (LAMPORTS_PER_SOL, 0),
        (LAMPORTS_PER_SOL * 3 / 10, 10),
        (LAMPORTS_PER_SOL * 6 / 10, 10),
        (LAMPORTS_PER_SOL * 6 / 10, 20),
    ] {
        let (done, pnl, bought) = sandwich(x, hold).unwrap();
        let vault_loss_bps = if done { (base_bought - bought.min(base_bought)) * 10_000 / base_bought } else { 0 };
        println!(
            "U-48 front-run {:.3} SOL, hold {hold} obs: chunk executed {done}, attacker PnL {:+.6} SOL, our tokens {bought} (−{vault_loss_bps} bps vs baseline)",
            x as f64 / 1e9,
            pnl as f64 / 1e9
        );
        assert!(pnl < 0, "U-48 refuted: sandwich of {x} lamports (hold {hold}) earned {pnl}");
    }
}
