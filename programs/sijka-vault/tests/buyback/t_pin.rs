// Copyright (c) 2026 prt1sn. All rights reserved.
//! `bb_init` (tag 40) and `bb_pin` (tag 41), SPEC §5.5.4, §5.5.5, §3.7.1;
//! TD-1…TD-6, TD-34, TD-61 (strict mode).

use sijka_vault::buyback::default_params;
use sijka_vault::error::SijkaError as E;
use sijka_vault::state::buyback_state::pinned as k;
use solana_keypair::Keypair;
use solana_signer::Signer;

use crate::harness::*;
use crate::pumpix::*;

/// TD-1, TD-2: `bb_init` writes the header, k0–k5 from `Config`, the cached
/// `usdc_mint`, the default parameters of the pair and `SJKEVBIN`; a second
/// call fails.
#[test]
fn bb_init_writes_state_and_refuses_a_second_call() {
    for quote in [Quote::Sol, Quote::Usdc] {
        let mut v = vault!(Setup::bare(quote, None));
        let res = v.bb_init();
        let m = ok(res);
        let bs = v.bs();
        assert_eq!(&bs[0..8], b"SIJKABBS");
        assert_eq!(bs[8], 1, "version");
        assert_eq!(bs.flags(), 0);
        assert_eq!(bs.venue(), 0);
        let kind = if quote == Quote::Sol { 1 } else { 2 };
        assert_eq!(bs.quote_kind(), kind);
        let cfg = v.config_data();
        // Bumps cached from Config@993/@660/@659/@994 (SPEC §3.7 @14..18).
        assert_eq!(bs[14], cfg[993], "buyback_state bump");
        assert_eq!(bs[15], cfg[660], "buyback_authority bump");
        assert_eq!(bs[16], cfg[659], "swap_authority bump");
        assert_eq!(bs[17], cfg[994], "bb_unwrap bump");
        assert_eq!(bs.pinned(k::BUYBACK_AUTHORITY), v.k.buyback_authority);
        assert_eq!(bs.pinned(k::BUYBACK_AUTHORITY), key_at(&cfg, 432));
        assert_eq!(bs.pinned(k::SWAP_AUTHORITY), v.k.swap_authority);
        assert_eq!(bs.pinned(k::BB_UNWRAP), v.k.bb_unwrap);
        assert_eq!(bs.pinned(k::BB_USDC), v.k.buyback_usdc);
        assert_eq!(bs.pinned(k::BB_USDC), key_at(&cfg, 592));
        assert_eq!(bs.pinned(k::SWAP_USDC), v.k.swap_usdc);
        assert_eq!(bs.pinned(k::SWAP_USDC), key_at(&cfg, 1280));
        let want_wsol = if quote == Quote::Sol { v.k.bb_wsol } else { solana_pubkey::Pubkey::default() };
        assert_eq!(bs.pinned(k::BB_WSOL), want_wsol);
        for i in 6..27 {
            assert_eq!(bs.pinned(i), solana_pubkey::Pubkey::default(), "k{i} is written by bb_pin only");
        }
        assert_eq!(key_at(&bs, 1176), usdc(), "usdc_mint cache");
        assert_eq!(v.params(), default_params(kind), "default params of the pair");
        let e = event(&m.logs, "SJKEVBIN");
        assert_eq!(e.len(), 114);
        assert_eq!(e[17], kind);
        assert_eq!(key_at(&e, 18), v.k.buyback_usdc);
        assert_eq!(key_at(&e, 50), v.k.swap_usdc);
        assert_eq!(key_at(&e, 82), want_wsol);
        assert_sijka(&v.bb_init(), E::BbAlreadyInitialized);
    }
}

/// TD-3: lamports sent to the `buyback_state` address beforehand do not block
/// `bb_init`.
#[test]
fn bb_init_with_prefunded_state_address() {
    let mut v = vault!(Setup::bare(Quote::Sol, None));
    let k = v.k.buyback_state;
    v.set_lamports(&k, 1_234_567);
    ok(v.bb_init());
    assert_eq!(&v.bs()[0..8], b"SIJKABBS");
    assert_eq!(v.state_data().len(), 1304);
}

/// TD-4: `bb_pin` before `set_token_mint` → `BbMintNotSet`.
#[test]
fn bb_pin_before_set_token_mint() {
    let mut v = vault!(Setup { bb_init: true, ..Setup::bare(Quote::Sol, Some("solcurve")) });
    let res = v.bb_pin();
    assert_sijka(&res, E::BbMintNotSet);
}

/// TD-6 (and U-37 CU): the pinned k6–k26 equal the addresses derived here from
/// the IDL seeds; flags, venue and the event; a second pin fails.
#[test]
fn bb_pin_curve_coin_pins_every_address() {
    let mut v = vault!(Setup::sol("solcurve").no_pin());
    let res = v.bb_pin();
    let m = ok(res);
    let cu = m.compute_units_consumed;
    println!("U-37 bb_pin CU (curve coin, incl. ComputeBudget ix): {cu}");
    assert!(cu < 300_000, "bb_pin CU {cu} above the 300k limit of SPEC §5.5.5");
    let ck = v.coin().clone();
    let bb = v.k.buyback_authority;
    let (slot, _) = v.clock();
    let bs = v.bs();
    let expect = [
        (k::MINT, ck.mint),
        (k::BASE_TOKEN_PROGRAM, t22()),
        (k::QUOTE_MINT, wsol()),
        (k::BB_SIJKA, ata(&bb, &t22(), &ck.mint)),
        (k::BB_QUOTE, v.k.bb_wsol),
        (k::BONDING_CURVE, ck.curve),
        (k::ASSOC_BASE_BONDING_CURVE, ck.curve_base_ata),
        (k::ASSOC_QUOTE_BONDING_CURVE, ck.curve_quote_ata),
        (k::SHARING_CONFIG, ck.sharing_config),
        (k::CREATOR_VAULT, ck.creator_vault),
        (k::ASSOC_CREATOR_VAULT, ck.creator_vault_ata),
        (k::PUMP_USER_VOLUME_ACC, pump_uva(&bb)),
        (k::PUMP_ASSOC_USER_VOLUME_ACC, ata(&pump_uva(&bb), &tokenkeg(), &wsol())),
        (k::POOL_AUTHORITY, ck.pool_authority),
        (k::POOL, ck.pool),
        (k::POOL_BASE_TA, ck.pool_base_ta),
        (k::POOL_QUOTE_TA, ck.pool_quote_ta),
        (k::COIN_CREATOR_VAULT_AUTHORITY, ck.coin_creator_vault_authority),
        (k::COIN_CREATOR_VAULT_ATA, ck.coin_creator_vault_ata),
        (k::AMM_USER_VOLUME_ACC, amm_uva(&bb)),
        (k::POOL_V2, ck.pool_v2),
    ];
    for (i, want) in expect {
        assert_eq!(bs.pinned(i), want, "pinned k{i}");
    }
    // Cross-check with the snapshot labels written by fetch.mjs.
    assert_eq!(bs.pinned(k::POOL), v.fx.key("solcurve pool"));
    assert_eq!(bs.pinned(k::POOL_V2), v.fx.key("solcurve pool_v2"));
    assert_eq!(bs.pinned(k::COIN_CREATOR_VAULT_ATA), v.fx.key("solcurve coin_creator_vault ata"));
    assert_eq!(bs.pinned(k::BB_SIJKA), key_at(&v.config_data(), 624), "k9 == cfg.buyback_token");
    assert_eq!(bs.flags(), 1, "PINNED, OBS_INIT clear");
    assert_eq!(bs.venue(), 1, "CURVE");
    assert_eq!(bs.base_decimals(), 6);
    assert_eq!(bs.base_tp_kind(), 2, "Token-2022");
    assert_eq!(bs.venue_since_slot(), slot);
    let e = event(&m.logs, "SJKEVBPN");
    assert_eq!(e.len(), 154);
    assert_eq!(key_at(&e, 17), ck.mint);
    assert_eq!(key_at(&e, 49), t22());
    assert_eq!(e[81], 1);
    assert_eq!(key_at(&e, 82), ck.curve);
    assert_eq!(key_at(&e, 114), ck.pool);
    assert_eq!(u64_at(&e, 146), slot);
    v.tick(1, 1);
    assert_sijka(&v.bb_pin(), E::BbAlreadyPinned);
}

/// A graduated coin (curve complete, canonical PumpSwap pool) is pinned with
/// `venue = AMM`.
#[test]
fn bb_pin_graduated_coin_selects_amm() {
    let mut v = vault!(Setup::sol("solamm").no_pin());
    let m = ok(v.bb_pin());
    let bs = v.bs();
    assert_eq!(bs.venue(), 2, "AMM");
    assert_eq!(bs.pinned(k::POOL), v.coin().pool);
    assert_eq!(bs.pinned(k::POOL), v.fx.key("solamm pool"));
    assert_eq!(event(&m.logs, "SJKEVBPN")[81], 2);
}

/// USDC pair: k8 = USDC, k10 = buyback_usdc, k5 zero; USDC pool with
/// `virtual_quote_reserves ≠ 0` pins as AMM.
#[test]
fn bb_pin_usdc_coins() {
    let mut v = vault!(Setup::usdc("usdccurve").no_pin());
    ok(v.bb_pin());
    let bs = v.bs();
    assert_eq!(bs.venue(), 1);
    assert_eq!(bs.pinned(k::QUOTE_MINT), usdc());
    assert_eq!(bs.pinned(k::BB_QUOTE), v.k.buyback_usdc);
    assert_eq!(bs.pinned(k::BB_WSOL), solana_pubkey::Pubkey::default());
    assert_eq!(bs.pinned(k::ASSOC_QUOTE_BONDING_CURVE), v.fx.key("usdccurve curve quote ata"));

    let mut v = vault!(Setup::usdc("usdcamm").no_pin());
    ok(v.bb_pin());
    assert_eq!(v.bs().venue(), 2);
    assert_eq!(v.bs().pinned(k::POOL), v.fx.key("usdcamm pool"));
}

/// TD-5: the curve's creator is not the sharing config → `BbCreatorNotSharing`.
#[test]
fn bb_pin_rejects_creator_other_than_sharing_config() {
    let mut v = vault!(Setup::sol("solcurve").no_pin());
    let curve = v.coin().curve;
    let someone = Keypair::new().pubkey();
    v.patch(&curve, |d| d[49..81].copy_from_slice(someone.as_ref()));
    assert_sijka(&v.bb_pin(), E::BbCreatorNotSharing);
}

/// Strict coin checks of tag 41 (SPEC §5.5.2, TD-61 last case): mayhem,
/// cashback, holder rewards, wrong quote. SPEC v4 (DECISIONS §23 item 6): the
/// coin's `creator_fee_bps` is not checked (pinning with it set succeeds).
#[test]
fn bb_pin_strict_coin_flags() {
    let cases: [(&str, usize, Vec<u8>, E); 4] = [
        ("mayhem", 81, vec![1], E::BbCoinFlagsUnexpected),
        ("cashback", 82, vec![1], E::BbCoinFlagsUnexpected),
        ("holder_reward", 124, vec![1], E::BbCoinFlagsUnexpected),
        ("usdc quote on a SOL vault", 83, usdc().to_bytes().to_vec(), E::BbWrongQuote),
    ];
    for (name, off, bytes, err) in cases {
        let mut v = vault!(Setup::sol("solcurve").no_pin());
        let curve = v.coin().curve;
        v.patch(&curve, |d| d[off..off + bytes.len()].copy_from_slice(&bytes));
        let res = v.bb_pin();
        println!("strict flag case: {name}");
        assert_sijka(&res, err);
    }
    let mut v = vault!(Setup::sol("solcurve").no_pin());
    let curve = v.coin().curve;
    v.patch(&curve, |d| d[115..123].copy_from_slice(&100u64.to_le_bytes()));
    ok(v.bb_pin());
}

/// Accounts 3–6 must be the derived curve / pool / pool token accounts.
#[test]
fn bb_pin_rejects_substituted_accounts() {
    let mut v = vault!(Setup::sol("solcurve").no_pin());
    let other = v.fx.key("solamm bonding_curve");
    for i in [3usize, 4, 5, 6] {
        let mut ix = v.bb_pin_ix();
        ix.accounts[i].pubkey = other;
        let res = v.call(ix);
        assert_sijka(&res, E::BbPinnedAccountMismatch);
    }
}

/// TD-34: a complete curve without a canonical pool → `BbPoolNotReady`, and the
/// pool of a graduated coin with a foreign coin_creator → `BbPoolNotReady`.
#[test]
fn bb_pin_complete_curve_without_valid_pool() {
    let mut v = vault!(Setup::sol("solcurve").no_pin());
    let curve = v.coin().curve;
    v.patch(&curve, |d| d[48] = 1);
    assert_sijka(&v.bb_pin(), E::BbPoolNotReady);

    let mut v = vault!(Setup::sol("solamm").no_pin());
    let pool = v.coin().pool;
    let someone = Keypair::new().pubkey();
    v.patch(&pool, |d| d[211..243].copy_from_slice(someone.as_ref()));
    assert_sijka(&v.bb_pin(), E::BbPoolNotReady);
}
