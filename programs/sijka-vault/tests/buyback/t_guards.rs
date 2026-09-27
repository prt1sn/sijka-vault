// Copyright (c) 2026 prt1sn. All rights reserved.
//! Transaction composition (SPEC §5.0.11 `require_sole_top_level`),
//! `jitodontfront`, and the SPEC v4 absence of pauses and of the admin tags
//! 47 / 48 (SPEC §5.5.11): TD-21…TD-23 (tag 45), TD-29, TD-53…TD-57, TD-60.

use sijka_vault::buyback::default_params;
use sijka_vault::error::SijkaError as E;
use solana_keypair::Keypair;
use solana_signer::Signer;

use crate::harness::*;
use crate::pumpix::*;

/// TD-21…TD-23 for tag 45: `jitodontfront`, a foreign instruction, a CPI
/// wrapper, our own instruction twice.
#[test]
fn amm_chunk_composition_rules() {
    let mut v = vault!(Setup::sol("solamm"));
    v.fund_authority(2 * LAMPORTS_PER_SOL);
    v.warm();
    let mut ix = chunk_amm_ix(&v, 0, 0);
    ix.accounts[3].pubkey = Keypair::new().pubkey();
    assert_sijka(&v.call(ix), E::BbMissingDontFront);
    let ix = chunk_amm_ix(&v, 0, 0);
    let kp = v.keeper.insecure_clone();
    assert_sijka(&v.send(vec![foreign_ix(&kp.pubkey()), ix.clone()], &[&kp]), E::ForeignInstruction);
    assert_sijka(&v.send(vec![ix.clone(), foreign_ix(&kp.pubkey())], &[&kp]), E::ForeignInstruction);
    assert_sijka(&v.send(vec![v.observe_ix(), ix.clone()], &[&kp]), E::ForeignInstruction);
    assert_sijka(&v.send(vec![crate::mocks::wrap_cpi(ix.clone())], &[&kp]), E::NotTopLevel);
    // Several ComputeBudget instructions are fine.
    let res = v.send(vec![cu_price(1), ix], &[&kp]);
    ok(res);
}

/// A ComputeBudget `SetComputeUnitPrice`.
fn cu_price(micro_lamports: u64) -> solana_instruction::Instruction {
    let mut d = vec![3u8];
    d.extend_from_slice(&micro_lamports.to_le_bytes());
    solana_instruction::Instruction { program_id: compute_budget_program(), accounts: vec![], data: d }
}

/// TD-29, TD-57 (SPEC v4, DECISIONS §23 item 1): there is no buyback pause.
/// Tag 48 (`bb_set_pause`) is `UnknownInstruction` whoever signs, and the
/// former `pause_until@24` (now `_reserved1`) is not read: a chunk runs with
/// `i64::MAX` there, and observe and burn keep working.
#[test]
fn no_buyback_pause_since_v4() {
    let mut v = vault!(Setup::sol("solcurve"));
    v.fund_authority(2 * LAMPORTS_PER_SOL);
    v.warm();
    let a = v.admin.insecure_clone();
    let st = v.state_data();
    for data in [vec![48u8, 1], vec![48u8, 0]] {
        let ix = v.ix(
            data,
            vec![
                solana_instruction::AccountMeta::new_readonly(a.pubkey(), true),
                solana_instruction::AccountMeta::new(v.k.config, false),
                solana_instruction::AccountMeta::new(v.k.buyback_state, false),
            ],
        );
        assert_sijka(&v.send(vec![ix], &[&a]), E::UnknownInstruction);
    }
    assert_eq!(v.state_data(), st, "nothing written");
    let bs = v.k.buyback_state;
    v.patch(&bs, |d| d[24..32].copy_from_slice(&i64::MAX.to_le_bytes()));
    ok(v.call(chunk_curve_ix(&v, 0, 0)));
    v.tick(15, 1);
    ok(v.observe());
    ok(v.call(v.bb_burn_ix()));
}

/// TD-60 (SPEC v2): there is no global admin pause any more. Tag 4 is a
/// reserved tag (`UnknownInstruction`), and a non-zero retired byte
/// `Config@10` (was `pause_mode`) does not stop the chunks.
#[test]
fn no_vault_pause_since_v2() {
    for coin in ["solcurve", "solamm"] {
        let mut v = vault!(Setup::sol(coin));
        v.fund_authority(2 * LAMPORTS_PER_SOL);
        v.warm();
        let a = v.admin.insecure_clone();
        let ix = v.ix(
            vec![4, 1],
            vec![
                solana_instruction::AccountMeta::new_readonly(a.pubkey(), true),
                solana_instruction::AccountMeta::new(v.k.config, false),
            ],
        );
        assert_sijka(&v.send(vec![ix], &[&a]), E::UnknownInstruction);
        let key = v.k.config;
        v.patch(&key, |d| d[10] = 2);
        let ix = if coin == "solamm" { chunk_amm_ix(&v, 0, 0) } else { chunk_curve_ix(&v, 0, 0) };
        ok(v.call(ix));
    }
}

/// TD-53…TD-56 (SPEC v4, DECISIONS §23 item 1): the buyback parameters are
/// the `bb_init` defaults for good. The retired spot guard / fee cap / swap
/// band / mark age bytes are zeros; tag 47 (`bb_set_params`) is
/// `UnknownInstruction` for the admin and anybody else; the chunk size
/// follows `chunk_bps` of `Q_ref` (checked with a test-only patch of the
/// parameters).
#[test]
fn params_are_the_bb_init_defaults() {
    let mut v = vault!(Setup::sol("solcurve"));
    v.fund_authority(2 * LAMPORTS_PER_SOL);
    v.warm();
    let old = v.params();
    assert_eq!(old, default_params(1));
    assert_eq!(&old[bp::RESERVED0..bp::RESERVED0 + 4], &[0; 4], "former max_dev_bps / fee_cap_bps");
    assert_eq!(&old[bp::RESERVED1..bp::RESERVED1 + 2], &[0; 2], "former swap_band_bps");
    assert_eq!(&old[bp::RESERVED2..bp::RESERVED2 + 4], &[0; 4], "former mark_max_age_slots");
    let stranger = Keypair::new();
    v.svm.airdrop(&stranger.pubkey(), LAMPORTS_PER_SOL).unwrap();
    let a = v.admin.insecure_clone();
    for signer in [&a, &stranger] {
        let mut d = vec![47u8];
        d.extend_from_slice(&default_params(1));
        let ix = v.ix(
            d,
            vec![
                solana_instruction::AccountMeta::new_readonly(signer.pubkey(), true),
                solana_instruction::AccountMeta::new(v.k.config, false),
                solana_instruction::AccountMeta::new(v.k.buyback_state, false),
            ],
        );
        assert_sijka(&v.send(vec![ix], &[signer]), E::UnknownInstruction);
    }
    assert_eq!(v.params(), old);
    // chunk_bps 10 → 5 (test-only patch) halves the next chunk.
    v.set_params(|p| put_u16(p, bp::CHUNK_BPS, 5));
    let (_, vq, _, _) = curve_reserves(&v);
    let q_ref = vq.min(v.bs().last_obs_quote()).min(v.bs().q_ema());
    let m = ok(v.call(chunk_curve_ix(&v, 0, 0)));
    assert_eq!(u64_at(&event(&m.logs, "SJKEVCHK"), 18), q_ref * 5 / 10_000, "v with chunk_bps 5");
}
