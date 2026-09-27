// Copyright (c) 2026 prt1sn. All rights reserved.
//! Remaining error paths of tags 41–46 (SPEC §6.2 via §5.5): not pinned,
//! malformed pump accounts, reserve anomalies, working-mode coin checks,
//! missing token accounts; and the CU of every buyback instruction (TD-59,
//! U-37).

use sijka_vault::error::SijkaError as E;
use solana_keypair::Keypair;
use solana_signer::Signer;

use crate::harness::*;
use crate::pumpix::*;

/// Tags 42, 44, 46 before `bb_pin` → BbNotPinned.
#[test]
fn not_pinned() {
    let mut v = vault!(Setup::sol("solcurve").no_pin());
    v.fund_authority(LAMPORTS_PER_SOL);
    // The pinned keys are still zero: build the instructions from the coin.
    assert_sijka(&v.observe(), E::BbNotPinned);
    assert_sijka(&v.call(v.bb_burn_ix()), E::BbNotPinned);
    assert_sijka(&v.call(chunk_curve_ix(&v, 0, 0)), E::BbNotPinned);
    let mut v = vault!(Setup::sol("solamm").no_pin());
    v.fund_authority(LAMPORTS_PER_SOL);
    assert_sijka(&v.call(chunk_amm_ix(&v, 0, 0)), E::BbNotPinned);
}

/// Observation of malformed curve / pool data: wrong owner or discriminator →
/// BbBadPumpAccount; reserves outside the price domain → BbReserveAnomaly.
#[test]
fn observe_rejects_malformed_or_anomalous_markets() {
    type Patch = Box<dyn Fn(&mut Vault)>;
    let cases: Vec<(&str, Patch, E)> = vec![
        (
            "curve discriminator",
            Box::new(|v| {
                let c = v.coin().curve;
                v.patch(&c, |d| d[0] ^= 1)
            }),
            E::BbBadPumpAccount,
        ),
        (
            "curve owner",
            Box::new(|v| {
                let c = v.coin().curve;
                let mut a = v.account(&c).unwrap();
                a.owner = Keypair::new().pubkey();
                v.set(c, a)
            }),
            E::BbBadPumpAccount,
        ),
        (
            "vT below MIN_BASE_RESERVE",
            Box::new(|v| {
                let c = v.coin().curve;
                v.patch(&c, |d| d[8..16].copy_from_slice(&999_999u64.to_le_bytes()))
            }),
            E::BbReserveAnomaly,
        ),
        (
            "vQ = 0",
            Box::new(|v| {
                let c = v.coin().curve;
                v.patch(&c, |d| d[16..24].copy_from_slice(&0u64.to_le_bytes()))
            }),
            E::BbReserveAnomaly,
        ),
        (
            "vQ ≥ 2^63",
            Box::new(|v| {
                let c = v.coin().curve;
                v.patch(&c, |d| d[16..24].copy_from_slice(&(1u64 << 63).to_le_bytes()))
            }),
            E::BbReserveAnomaly,
        ),
    ];
    for (name, patch, err) in cases {
        let mut v = vault!(Setup::sol("solcurve"));
        patch(&mut v);
        println!("observe anomaly case: {name}");
        assert_sijka(&v.observe(), err);
    }
    // Pool: negative virtual quote reserves, foreign base mint.
    let mut v = vault!(Setup::sol("solamm"));
    let pool = v.coin().pool;
    v.patch(&pool, |d| d[245..261].copy_from_slice(&(-1i128).to_le_bytes()));
    assert_sijka(&v.observe(), E::BbReserveAnomaly);
    let mut v = vault!(Setup::sol("solamm"));
    let pool = v.coin().pool;
    let other = Keypair::new().pubkey();
    v.patch(&pool, |d| d[43..75].copy_from_slice(other.as_ref()));
    assert_sijka(&v.observe(), E::BbPinnedAccountMismatch);
}

/// Working-mode coin checks of the chunk (SPEC §5.5.2, review ACC-2):
/// mayhem, cashback and a zero creator are refused; the quote field must
/// match the pair. SPEC v4 (DECISIONS §23 item 6, closes O-11): the coin's own
/// `creator_fee_bps` no longer stops the chunk (curve `@115`, pool `@261`).
#[test]
fn chunk_working_mode_coin_checks() {
    let cases: [(&str, usize, Vec<u8>, E); 4] = [
        ("mayhem", 81, vec![1], E::BbCoinFlagsUnexpected),
        ("cashback", 82, vec![1], E::BbCoinFlagsUnexpected),
        ("zero creator", 49, vec![0; 32], E::BbCreatorNotSharing),
        ("usdc quote", 83, usdc().to_bytes().to_vec(), E::BbWrongQuote),
    ];
    for (name, off, bytes, err) in cases {
        let mut v = vault!(Setup::sol("solcurve"));
        v.fund_authority(LAMPORTS_PER_SOL);
        v.warm();
        let curve = v.coin().curve;
        v.patch(&curve, |d| d[off..off + bytes.len()].copy_from_slice(&bytes));
        println!("working-mode case: {name}");
        if name == "zero creator" {
            // The creator vault is derived from the (zero) creator.
            let mut ix = chunk_curve_ix(&v, 0, 0);
            let (cv, cva) = v.coin().creator_vault_for(&solana_pubkey::Pubkey::default());
            ix.accounts[20].pubkey = cv;
            ix.accounts[21].pubkey = cva;
            assert_sijka(&v.call(ix), err);
        } else {
            assert_sijka(&v.call(chunk_curve_ix(&v, 0, 0)), err);
        }
    }
    // Pool: mayhem in the pool.
    let mut v = vault!(Setup::sol("solamm"));
    v.fund_authority(LAMPORTS_PER_SOL);
    v.warm();
    let pool = v.coin().pool;
    v.patch(&pool, |d| d[243] = 1);
    assert_sijka(&v.call(chunk_amm_ix(&v, 0, 0)), E::BbCoinFlagsUnexpected);
    // SPEC v4: a non-zero creator_fee_bps of the coin is paid, not refused.
    let mut v = vault!(Setup::sol("solcurve"));
    v.fund_authority(LAMPORTS_PER_SOL);
    v.warm();
    let curve = v.coin().curve;
    v.patch(&curve, |d| d[115..123].copy_from_slice(&30u64.to_le_bytes()));
    ok(v.call(chunk_curve_ix(&v, 0, 0)));
    let mut v = vault!(Setup::sol("solamm"));
    v.fund_authority(LAMPORTS_PER_SOL);
    v.warm();
    let pool = v.coin().pool;
    if v.data(&pool).len() >= 269 {
        v.patch(&pool, |d| d[261..269].copy_from_slice(&5u64.to_le_bytes()));
    }
    ok(v.call(chunk_amm_ix(&v, 0, 0)));
}

/// Missing or foreign token accounts of `buyback_authority`.
#[test]
fn chunk_token_accounts() {
    // buyback_token missing.
    let mut v = vault!(Setup::sol("solcurve"));
    v.fund_authority(LAMPORTS_PER_SOL);
    v.warm();
    let bt = v.buyback_token();
    v.set_lamports(&bt, 0);
    assert_sijka(&v.call(chunk_curve_ix(&v, 0, 0)), E::BbBaseAtaMissing);
    // buyback_token with a close authority (only possible through tampering) → InvalidTokenAccount.
    let mut v = vault!(Setup::sol("solcurve"));
    v.fund_authority(LAMPORTS_PER_SOL);
    v.warm();
    let bt = v.buyback_token();
    let x = Keypair::new().pubkey();
    v.patch(&bt, |d| {
        d[129..133].copy_from_slice(&1u32.to_le_bytes());
        d[133..165].copy_from_slice(x.as_ref());
    });
    assert_sijka(&v.call(chunk_curve_ix(&v, 0, 0)), E::InvalidTokenAccount);
    assert_sijka(&v.call(v.bb_burn_ix()), E::InvalidTokenAccount);
    // USDC pair: buyback_usdc missing → BbQuoteAtaMissing.
    let mut v = vault!(Setup::usdc("usdccurve"));
    v.fund_authority(0);
    v.warm();
    let bb = v.k.buyback_usdc;
    v.set_lamports(&bb, 0);
    assert_sijka(&v.call(chunk_curve_ix(&v, 0, 0)), E::BbQuoteAtaMissing);
    // SOL curve without bb_wsol is fine (pump spends lamports).
    let mut v = vault!(Setup::sol("solcurve"));
    v.fund_authority(LAMPORTS_PER_SOL);
    v.warm();
    let w = v.k.bb_wsol;
    v.set_lamports(&w, 0);
    ok(v.call(chunk_curve_ix(&v, 0, 0)));
    println!("SOL curve chunk without bb_wsol: ok; bb_wsol exists afterwards: {}", v.exists(&w));
}

/// TD-59 / U-37: CU of every buyback instruction against the limits of SPEC
/// §5.5 (40: 100k, 41: 300k, 42: 40k, 43: route-dependent, 44 / 45: 400k,
/// 46: burn; SPEC v4: tags 47 / 48 retired, tag 28 `set_keeper` small).
#[test]
fn compute_units_of_every_buyback_instruction() {
    let mut v = vault!(Setup::bare(Quote::Sol, Some("solcurve")));
    ok(v.set_token_mint());
    let m = ok(v.bb_init());
    let cu_init = m.compute_units_consumed;
    v.create_bb_atas();
    let cu_pin = ok(v.bb_pin()).compute_units_consumed;
    let cu_obs = ok(v.observe()).compute_units_consumed;
    let keeper = v.keeper.pubkey();
    let cu_keeper = ok(v.set_keeper(&keeper)).compute_units_consumed;
    let cu_burn0 = ok(v.call(v.bb_burn_ix())).compute_units_consumed;
    v.fund_authority(LAMPORTS_PER_SOL);
    v.warm_up(39);
    v.tick(1, 1);
    let cu_chunk = ok(v.call(chunk_curve_ix(&v, 0, 0))).compute_units_consumed;
    println!(
        "TD-59 CU (incl. the ComputeBudget ix, ~150): bb_init {cu_init}, bb_pin {cu_pin}, observe {cu_obs}, set_keeper {cu_keeper}, burn(0) {cu_burn0}, chunk_curve {cu_chunk}"
    );
    assert!(cu_init < 100_000);
    assert!(cu_pin < 300_000);
    assert!(cu_obs < 40_000);
    assert!(cu_chunk < 400_000);
    assert!(cu_keeper < 20_000 && cu_burn0 < 50_000);
}
