// Copyright (c) 2026 prt1sn. All rights reserved.
//! Inflow parameters (SPEC §3.3; SPEC v4, DECISIONS §23 item 1): fixed at
//! `initialize`, no admin setter or pause (tags 25, 26 retired, TC-20, TC-31
//! replaced), and the volume-proportional swap interval (TC-21) with the
//! parameters written into `Config` directly (as if initialized with them).

use solana_instruction::{AccountMeta, Instruction};
use solana_signer::Signer;

use crate::harness::*;
use crate::route::*;
use crate::swap::{SOL, fund_fee_inbox, honest, run};

pub fn params_with(edits: &[(&str, u64)]) -> Vec<u8> {
    let mut p = default_inflow_params();
    for (name, v) in edits {
        let (off, size) = abi().field("InflowParams", name);
        p[off..off + size].copy_from_slice(&v.to_le_bytes()[..size]);
    }
    p
}

/// Test-only: write `InflowParams` into `Config@1112` (SPEC v4 has no setter).
pub fn set_params(env: &mut Env, edits: &[(&str, u64)]) {
    let p = params_with(edits);
    env.set_cfg_bytes("inflow_params", &p);
}

fn inflow_params_bytes(env: &Env) -> Vec<u8> {
    let (off, size) = abi().field("Config", "inflow_params");
    env.config()[off..off + size].to_vec()
}

/// The retired admin tags 25 / 26 with their old shapes, signed by the admin.
fn retired_ix(env: &Env, data: Vec<u8>) -> Instruction {
    Instruction {
        program_id: env.k.program,
        accounts: vec![AccountMeta::new_readonly(env.admin.pubkey(), true), AccountMeta::new(env.k.config, false)],
        data,
    }
}

/// TC-31 (SPEC v4): `initialize` stored the parameters, and nobody (the
/// admin included) can change them or pause the inflow: tags 25 and 26 are
/// `UnknownInstruction`; nothing is written.
#[test]
fn tc31_params_fixed_at_initialize() {
    let Some(mut env) = Env::new(Opts::default()) else { return };
    let before = inflow_params_bytes(&env);
    assert_eq!(before, default_inflow_params(), "initialize stored the inflow params");
    let (off, _) = abi().field("InflowParams", "_reserved0");
    assert_eq!(&before[off..off + 4], &[0; 4], "former band / mark age: reserved zeros");
    let (off, _) = abi().field("InflowParams", "_reserved1");
    assert_eq!(&before[off..off + 8], &[0; 8], "former Ember tolerance: reserved zeros");
    let cfg0 = env.config();
    let admin = env.admin.insecure_clone();
    let mut tag25 = vec![25u8];
    tag25.extend_from_slice(&params_with(&[("swap_min_interval_s", 60)]));
    for data in [tag25, vec![26, 1], vec![26, 0]] {
        let ix = retired_ix(&env, data);
        expect_err(env.send(vec![ix], &[&admin]), "UnknownInstruction");
    }
    assert_eq!(env.config(), cfg0, "nothing written");
}

/// TC-20 (SPEC v4): there is no inflow pause. The byte of the former
/// `inflow_pause_mask@1152` (now `_reserved10`) is not read: the swap and the
/// sweeps work whatever it holds.
#[test]
fn tc20_no_pause() {
    let Some(mut env) = Env::new(Opts::default()) else { return };
    fund_fee_inbox(&mut env, 2 * SOL);
    let (off, size) = abi().field("Config", "_reserved10");
    assert_eq!((off, size), (1152, 1));
    let cfg = env.k.config;
    env.patch(&cfg, off, &[3]);
    let (s, _) = honest(&env, Kind::RouteV2, SOL);
    expect_ok(run(&mut env, &s));
    let su = env.k.swap_usdc;
    env.mint_usdc(su, 1_000_000);
    expect_ok(crate::sweep::sweep(&mut env, 23, su));
}

#[test]
fn tc21_volume_proportional_interval() {
    let Some(mut env) = Env::new(Opts::default()) else { return };
    fund_fee_inbox(&mut env, 20 * SOL);
    let max = 2 * SOL;
    let min = SOL / 100;
    set_params(&mut env, &[("swap_min_interval_s", 60), ("swap_max_lamports", max), ("swap_min_lamports", min)]);
    let t0 = env.now();
    // A full swap takes the whole interval.
    let (s, _) = honest(&env, Kind::RouteV2, max);
    expect_ok(run(&mut env, &s));
    assert_eq!(env.cfg("next_swap_ts"), (t0 + 60) as u64);
    let (s2, _) = honest(&env, Kind::RouteV2, min);
    expect_err(run(&mut env, &s2), "SwapTooSoon");
    env.set_now(t0 + 59);
    expect_err(run(&mut env, &s2), "SwapTooSoon");
    env.set_now(t0 + 60);
    // A dust swap takes only ⌈60·min/max⌉ = 1 s of the interval (review RT-6).
    expect_ok(run(&mut env, &s2));
    assert_eq!(env.cfg("next_swap_ts"), (t0 + 61) as u64);
    let (s3, _) = honest(&env, Kind::RouteV2, max);
    expect_err(run(&mut env, &s3), "SwapTooSoon");
    env.set_now(t0 + 61);
    expect_ok(run(&mut env, &s3));
    assert_eq!(env.cfg("next_swap_ts"), (t0 + 121) as u64);
    // Interval 0 turns the limit off (next_swap_ts is then not written).
    set_params(&mut env, &[("swap_min_interval_s", 0), ("swap_max_lamports", max), ("swap_min_lamports", min)]);
    let (s4, _) = honest(&env, Kind::RouteV2, max);
    expect_ok(run(&mut env, &s4));
    assert_eq!(env.cfg("next_swap_ts"), (t0 + 121) as u64);
}
