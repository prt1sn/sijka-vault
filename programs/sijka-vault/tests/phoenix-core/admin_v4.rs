// Copyright (c) 2026 prt1sn. All rights reserved.
//! SPEC v4 (DECISIONS §23 items 1, 2, 4): the admin exists for good and can
//! only `set_token_mint`, `register_phoenix_trader`, `set_trader` and the new
//! tag 28 `set_keeper`. The retired admin tags (7 `set_harvest_params`, 8
//! `renounce_admin`, 25/26 inflow parameters and pause, 47/48 buyback
//! parameters and pause) are refused before any account is read, whatever the
//! data and accounts (TA-16…TA-19 of SPEC v3 are replaced by these tests).

use solana_pubkey::Pubkey;

use crate::abi;
use crate::harness::*;

/// Tag 28: admin only, never a program PDA, 0 allowed; event `SJKEVKPR` and
/// `last_admin_action_ts`; rotation; the admin and the trading key are
/// untouched.
#[test]
fn set_keeper_rules_and_event() {
    let Some(mut env) = Env::new() else { return };
    env.initialize();
    assert_eq!(env.cfg_key("keeper"), Pubkey::default(), "no keeper after initialize (swaps and chunks off)");

    let keeper = Pubkey::new_unique();
    // Only the admin signs tag 28.
    let ix = env.set_keeper_ix(&env.attacker, &keeper);
    expect_err(env.send1(ix, S_ATTACKER), "Unauthorized", "attacker");
    let ix = env.set_keeper_ix(&env.bot, &keeper);
    expect_err(env.send1(ix, S_BOT), "Unauthorized", "the trading key is not the admin");

    // A program PDA can never be the keeper (it cannot sign an outer transaction).
    let p = &env.pdas;
    let pdas = [
        ("config", p.config.0),
        ("buyback_state", p.buyback_state.0),
        ("fee_inbox", p.fee_inbox.0),
        ("phx_authority", p.phx_authority.0),
        ("swap_authority", p.swap_authority.0),
        ("buyback_authority", p.buyback_authority.0),
        ("rent_payer", p.rent_payer.0),
        ("creator_escrow", p.creator_escrow.0),
        ("bb_unwrap", p.bb_unwrap.0),
    ];
    for (label, pda) in pdas {
        expect_err(env.set_keeper(&pda), "InvalidParams", label);
    }
    assert_eq!(env.cfg_key("keeper"), Pubkey::default());

    // Set: exactly `keeper@48` and `last_admin_action_ts` change.
    let before = env.config();
    let (_, ts) = env.clock();
    let m = ok(env.set_keeper(&keeper), "set_keeper");
    let after = env.config();
    assert_eq!(env.cfg_key("keeper"), keeper);
    assert_eq!(env.cfg_i64("last_admin_action_ts"), ts);
    let keeper_off = abi::config().field("keeper").offset;
    let stamp_off = abi::config().field("last_admin_action_ts").offset;
    for (i, (a, b)) in before.iter().zip(after.iter()).enumerate() {
        if !(keeper_off..keeper_off + 32).contains(&i) && !(stamp_off..stamp_off + 8).contains(&i) {
            assert_eq!(a, b, "Config byte {i} changed");
        }
    }
    let ev = one_event(&m.logs, "SJKEVKPR");
    let e = abi::event("SJKEVKPR");
    assert_eq!(ev.len(), e.size);
    assert_eq!(key_of(e.key(&ev, "old")), Pubkey::default());
    assert_eq!(key_of(e.key(&ev, "new")), keeper);

    // Rotation and switching off.
    let k2 = Pubkey::new_unique();
    let m = ok(env.set_keeper(&k2), "rotate");
    let ev = one_event(&m.logs, "SJKEVKPR");
    assert_eq!(key_of(e.key(&ev, "old")), keeper);
    assert_eq!(key_of(e.key(&ev, "new")), k2);
    ok(env.set_keeper(&Pubkey::default()), "keeper off");
    assert_eq!(env.cfg_key("keeper"), Pubkey::default());
    assert_eq!(env.cfg_key("admin"), env.admin, "the admin never changes");
    assert_eq!(env.cfg_key("emergency_recipient"), env.admin, "the recovery recipient is the admin");
}

/// Retired tags fail with `UnknownInstruction` before any account is read,
/// with their old data lengths and account pairs; nothing is written.
#[test]
fn retired_admin_tags_are_unknown() {
    let Some(mut env) = Env::new() else { return };
    env.initialize();
    let before = env.config();
    for (tag, len) in [(7u8, 65usize), (8, 65), (25, 41), (26, 2), (47, 81), (48, 2)] {
        let ix = env.retired_admin_ix(tag, len);
        expect_err(env.send1(ix, S_ADMIN), "UnknownInstruction", &format!("tag {tag}"));
    }
    assert_eq!(env.config(), before, "nothing written");
    assert_eq!(env.cfg_key("admin"), env.admin);
}
