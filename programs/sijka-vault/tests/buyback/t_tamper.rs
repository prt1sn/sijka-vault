// Copyright (c) 2026 prt1sn. All rights reserved.
//! Post-CPI authority and token-account checks of tags 44 / 45 against a pump
//! that abuses the `buyback_authority` signature (SPEC §5.5.2 "Проверки порчи
//! после CPI pump", review RT-2): TD-66. The mock pump / pump_amm run at the
//! real program ids in their own SVM (`PumpMode::Mock`), do an honest
//! constant-product buy and then one abuse with the `user` signature.

use sijka_vault::error::SijkaError as E;

use crate::harness::*;
use crate::mocks::{PumpEvil, set_pump_evil};
use crate::pumpix::*;

fn run(coin: &'static str, quote: Quote, amm: bool, mode: PumpEvil, prep: impl FnOnce(&mut Vault)) -> Option<()> {
    let s = if quote == Quote::Sol { Setup::sol(coin) } else { Setup::usdc(coin) };
    let mut v = Vault::try_new(s.mock())?;
    match quote {
        Quote::Sol => v.fund_authority(2 * LAMPORTS_PER_SOL),
        Quote::Usdc => {
            let k0 = v.k.buyback_authority;
            let bb = v.k.buyback_usdc;
            v.set_token_account(bb, tokenkeg(), usdc(), k0, 1_000_000_000);
            v.fund_authority(0);
        }
    }
    prep(&mut v);
    v.warm();
    set_pump_evil(mode);
    let ix = if amm { chunk_amm_ix(&v, 0, 0) } else { chunk_curve_ix(&v, 0, 0) };
    let before = (v.lamports(&v.k.buyback_authority), v.token_amount(&v.bb_quote()), v.bs().n_chunks());
    let res = v.call(ix);
    set_pump_evil(PumpEvil::Honest);
    println!("TD-66 {coin} amm={amm} mode {mode:?}: {:?}", res.as_ref().err().map(|f| &f.err));
    if mode == PumpEvil::Honest {
        let m = ok(res);
        let e = event(&m.logs, "SJKEVCHK");
        assert!(u64_at(&e, 50) > 0 && u64_at(&e, 50) == u64_at(&e, 58), "honest mock: bought and burned");
    } else {
        assert_sijka(&res, E::BbAccountTampered);
        let after = (v.lamports(&v.k.buyback_authority), v.token_amount(&v.bb_quote()), v.bs().n_chunks());
        assert_eq!(after, before, "rolled back");
    }
    Some(())
}

/// SOL curve: `user` assigned / allocated, delegate or close authority on
/// `buyback_token`, `bb_wsol` touched although the curve does not spend it
/// (approve, close authority, close, transfer out) → BbAccountTampered.
#[test]
fn tampering_pump_on_the_sol_curve() {
    let fund_wsol = |v: &mut Vault| {
        let w = v.k.bb_wsol;
        v.set_token_amount(&w, 1_000_000);
    };
    for mode in [
        PumpEvil::Honest,
        PumpEvil::AssignUser,
        PumpEvil::AllocateUser,
        PumpEvil::ApproveBase,
        PumpEvil::SetCloseAuthorityBase,
        PumpEvil::ApproveQuote,
        PumpEvil::SetCloseAuthorityQuote,
        PumpEvil::CloseQuote,
        PumpEvil::TransferQuoteOut,
    ] {
        if run("solcurve", Quote::Sol, false, mode, fund_wsol).is_none() {
            return;
        }
    }
}

/// SOL pool: the same abuses on `buyback_authority`, `buyback_token` and the
/// wrapped `bb_wsol` → BbAccountTampered.
#[test]
fn tampering_pump_amm_on_the_sol_pool() {
    for mode in [
        PumpEvil::Honest,
        PumpEvil::AssignUser,
        PumpEvil::AllocateUser,
        PumpEvil::ApproveBase,
        PumpEvil::SetCloseAuthorityBase,
        PumpEvil::ApproveQuote,
        PumpEvil::SetCloseAuthorityQuote,
        PumpEvil::CloseQuote,
    ] {
        if run("solamm", Quote::Sol, true, mode, |_| {}).is_none() {
            return;
        }
    }
}

/// USDC pair (curve and pool): `buyback_usdc` is a Tokenkeg ATA without an
/// immutable owner: SetAuthority(AccountOwner) would move the whole backlog
/// and every future 80% share (review ACC-3) → BbAccountTampered; also
/// delegate and close authority.
#[test]
fn tampering_pump_on_the_usdc_pair() {
    for (coin, amm) in [("usdccurve", false), ("usdcamm", true)] {
        for mode in [
            PumpEvil::Honest,
            PumpEvil::SetOwnerQuote,
            PumpEvil::ApproveQuote,
            PumpEvil::SetCloseAuthorityQuote,
            PumpEvil::ApproveBase,
            PumpEvil::AssignUser,
        ] {
            if run(coin, Quote::Usdc, amm, mode, |_| {}).is_none() {
                return;
            }
        }
    }
}
