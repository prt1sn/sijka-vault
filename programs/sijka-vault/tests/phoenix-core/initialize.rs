// Copyright (c) 2026 prt1sn. All rights reserved.
//! Tag 0 `initialize` (SPEC §5.1.0; TA-1…TA-4): every PDA, bump and ATA
//! against the off-chain derivation, the ProgramData upgrade-authority gate
//! (the front-running defence), pre-funded state addresses, repeat, argument
//! and account checks. SPEC v2/v3: 6 accounts, 201 bytes, no `TradeConfig`;
//! `trader = 0` (trading off) until tag 3.

use solana_instruction::AccountMeta;
use solana_pubkey::Pubkey;

use crate::abi;
use crate::harness::*;
use crate::ixs::*;

#[test]
fn initialize_writes_every_pda_bump_and_ata() {
    let Some(mut env) = Env::new() else { return };
    let (slot, ts) = env.clock();
    let a = env.init_args();
    let ix = env.initialize_ix(&a);
    let m = ok(env.send1(ix, S_UPGRADE), "initialize");
    eprintln!("initialize CU: {}", m.compute_units_consumed);

    let c = abi::config();
    let d = env.config();
    let p = env.pdas;
    // Account shape.
    assert_eq!(env.owner(&p.config.0), Some(env.program), "config owner");
    assert_eq!(d.len(), 5144, "Config length (SPEC §3.1)");
    assert!(env.lamports(&p.config.0) >= env.rent(5144), "config rent-exempt");
    assert_eq!(c.bytes(&d, "discriminator"), b"SIJKACFG");
    assert_eq!(c.u16(&d, "version"), 1);
    assert_eq!(c.u16(&d, "creator_share_bps"), 2000);
    // Roles and mints.
    assert_eq!(env.cfg_key("admin"), env.admin);
    assert_eq!(env.cfg_key("trader"), Pubkey::default(), "no trading key before tag 3");
    assert_eq!(env.cfg_key("creator_payout"), env.creator);
    assert_eq!(env.cfg_key("quote_mint"), WSOL_MINT);
    assert_eq!(env.cfg_key("usdc_mint"), env.fx.usdc, "usdc_mint = ember_state@40 = fixture fake USDC");
    assert_eq!(env.cfg_key("phusd_mint"), env.fx.phusd, "phusd_mint = GC@296");
    let gc = env.gc();
    assert_eq!(&gc[296..328], env.fx.phusd.as_ref(), "GC@296 is the fixture PhUSD mint");
    assert_eq!(env.cfg_key("token_mint"), Pubkey::default());
    assert_eq!(env.cfg_key("phoenix_trader"), Pubkey::default());
    // PDAs and bumps (canonical, SPEC §2.1).
    for (field, bump_field, pda) in [
        ("fee_inbox", Some("fee_inbox_bump"), p.fee_inbox),
        ("phx_authority", Some("phx_authority_bump"), p.phx_authority),
        ("swap_authority", Some("swap_authority_bump"), p.swap_authority),
        ("buyback_authority", Some("buyback_authority_bump"), p.buyback_authority),
        ("rent_payer", Some("rent_payer_bump"), p.rent_payer),
        ("buyback_state", Some("buyback_state_bump"), p.buyback_state),
        ("bb_unwrap", Some("bb_unwrap_bump"), p.bb_unwrap),
        ("creator_escrow", Some("creator_escrow_bump"), p.creator_escrow),
    ] {
        assert_eq!(env.cfg_key(field), pda.0, "{field}");
        if let Some(b) = bump_field {
            assert_eq!(c.u8(&d, b), pda.1, "{b}");
        }
    }
    assert_eq!(c.u8(&d, "config_bump"), p.config.1, "config_bump");
    // ATAs (SPEC §2.2, §5.1.0 step 7).
    let usdc = env.fx.usdc;
    let phusd = env.fx.phusd;
    for (field, owner, mint) in [
        ("vault_usdc", p.phx_authority.0, usdc),
        ("vault_phusd", p.phx_authority.0, phusd),
        ("swap_wsol", p.swap_authority.0, WSOL_MINT),
        ("swap_usdc", p.swap_authority.0, usdc),
        ("creator_usdc", env.creator, usdc),
        ("creator_escrow_usdc", p.creator_escrow.0, usdc),
        ("buyback_usdc", p.buyback_authority.0, usdc),
        ("emergency_recipient_usdc", env.admin, usdc),
        ("emergency_recipient_phusd", env.admin, phusd),
    ] {
        assert_eq!(env.cfg_key(field), ata(&owner, &mint, &SPL_TOKEN), "{field}");
    }
    assert_eq!(env.cfg_key("buyback_token"), Pubkey::default(), "buyback_token set by tag 1 only");
    // Recovery block (DECISIONS §17).
    assert_eq!(env.cfg_key("emergency_recipient"), env.admin);
    assert_eq!(c.u8(&d, "recovery_mode"), 0);
    for f in ["venue_last_verdict", "venue_last_reason", "venue_major_seen"] {
        assert_eq!(c.u8(&d, f), 0, "{f}");
    }
    for f in ["venue_down_since_ts", "venue_last_down_obs_ts", "last_venue_obs_ts", "recovery_latched_ts"] {
        assert_eq!(c.i64(&d, f), 0, "{f}");
    }
    // Time and counters.
    assert_eq!(c.i64(&d, "created_ts"), ts);
    // DECISIONS §23 item 7: the T_min timer is anchored so that the first
    // harvest is allowed at once (SPEC §5.1.0 step 9).
    let t_min = env.cfg_harvest_u64("t_min_secs") as i64;
    assert!(t_min > 0, "the fixture parameters use a real T_min");
    assert_eq!(c.i64(&d, "last_harvest_ts"), ts - t_min, "last_harvest_ts = created_ts - t_min_secs");
    for f in ["cum_inflow_usdc", "cum_payout_usdc", "cum_payout_creator", "cum_payout_buyback", "harvest_count"] {
        assert_eq!(c.u64(&d, f), 0, "{f}");
    }
    // Parameters stored verbatim.
    assert_eq!(c.bytes(&d, "harvest_params"), &a.harvest[..]);
    assert_eq!(c.bytes(&d, "inflow_params"), &a.inflow[..]);
    // Reserved / padding bytes are zero.
    for (name, f) in &c.fields {
        if name.starts_with("_") {
            assert!(d[f.offset..f.offset + f.size].iter().all(|b| *b == 0), "{name} not zero");
        }
    }

    // No TradeConfig any more (SPEC v2): its old PDA stays empty.
    let old_tc = find_pda(&[b"trade_config"], &env.program).0;
    assert!(!env.exists(&old_tc), "no TradeConfig account (SPEC v2)");

    // No other account was created by initialize.
    for k in [p.fee_inbox.0, p.phx_authority.0, p.rent_payer.0, p.buyback_state.0, p.creator_escrow.0] {
        assert!(!env.exists(&k), "{k} should not exist after initialize");
    }

    // Event SJKEVINI (SPEC §7).
    let ev = one_event(&m.logs, "SJKEVINI");
    let e = abi::event("SJKEVINI");
    assert_eq!(e.i64(&ev, "ts"), ts);
    assert_eq!(key_of(e.key(&ev, "admin")), env.admin);
    assert_eq!(ev.len(), 179, "SJKEVINI without `trader` (SPEC v2)");
    assert_eq!(key_of(e.key(&ev, "creator_payout")), env.creator);
    assert_eq!(key_of(e.key(&ev, "quote_mint")), WSOL_MINT);
    assert_eq!(key_of(e.key(&ev, "usdc_mint")), usdc);
    assert_eq!(key_of(e.key(&ev, "phusd_mint")), phusd);
    assert_eq!(e.u16(&ev, "config_version"), 1);
    let _ = slot;
}

#[test]
fn initialize_only_by_upgrade_authority() {
    let Some(mut env) = Env::new() else { return };
    // A front-runner signs as payer with its own roles.
    let mut a = env.init_args();
    a.payer = env.attacker;
    a.admin = env.attacker;
    let ix = env.initialize_ix(&a);
    expect_err(env.send1(ix, S_ATTACKER), "NotUpgradeAuthority", "front-runner payer");

    // The authority's key in the payer slot but not signing (fee payer = attacker).
    let a = env.init_args();
    let mut ix = env.initialize_ix(&a);
    ix.accounts[0] = AccountMeta::new(env.upgrade_authority, false);
    expect_err(env.send1(ix, S_ATTACKER), "NotUpgradeAuthority", "payer not signer");

    // A forged ProgramData elsewhere naming the attacker.
    let fake_pd = Pubkey::new_unique();
    let mut pd = env.data(&env.pdas.program_data)[..45].to_vec();
    pd[12] = 1;
    pd[13..45].copy_from_slice(env.attacker.as_ref());
    env.install(&fake_pd, &BPF_LOADER_UPGRADEABLE, pd);
    let mut a = env.init_args();
    a.payer = env.attacker;
    a.program_data = fake_pd;
    let ix = env.initialize_ix(&a);
    expect_err(env.send1(ix, S_ATTACKER), "InvalidExternalAccount", "forged ProgramData");

    // Frozen program (no upgrade authority): nobody can initialize.
    env.set_upgrade_authority(None);
    let ix = env.initialize_ix(&env.init_args());
    expect_err(env.send1(ix, S_UPGRADE), "NotUpgradeAuthority", "program without upgrade authority");
    assert!(!env.exists(&env.pdas.config.0), "config must not exist after failed attempts");

    // The real authority succeeds.
    env.set_upgrade_authority(Some(env.upgrade_authority));
    env.initialize();
    assert_eq!(env.cfg_key("admin"), env.admin);
}

#[test]
fn initialize_prefunded_addresses_then_repeat() {
    let Some(mut env) = Env::new() else { return };
    // Anyone can send lamports to the config address first (SPEC §5.0.10:
    // transfer + allocate + assign path). A new system account must be
    // rent-exempt, so the smallest prefund is rent(0); a large prefund stays.
    let cfg = env.pdas.config.0;
    let min = env.rent(0);
    ok(env.transfer_lamports(S_ATTACKER, &cfg, min), "prefund config with rent(0)");
    ok(env.transfer_lamports(S_ATTACKER, &cfg, 5_000_000_000), "prefund config 5 SOL more");
    env.initialize();
    assert_eq!(env.owner(&cfg), Some(env.program));
    assert_eq!(env.data(&cfg).len(), 5144);
    assert!(env.lamports(&cfg) >= 5_000_000_000 + min, "pre-funded lamports stay");

    // Repeat.
    let ix = env.initialize_ix(&env.init_args());
    expect_err(env.send1(ix, S_UPGRADE), "ConfigAlreadyInitialized", "second initialize");
}

#[test]
fn initialize_argument_and_account_checks() {
    let Some(mut env) = Env::new() else { return };
    let usdc = env.fx.usdc;
    let p = env.pdas;

    let mut bad: Vec<(String, InitArgs, &str)> = Vec::new();
    let mut push = |label: &str, f: &dyn Fn(&mut InitArgs), e: &'static str, env: &Env| {
        let mut a = env.init_args();
        f(&mut a);
        bad.push((label.to_string(), a, e));
    };
    push("quote mint foreign", &|a| a.quote_mint = Pubkey::new_unique(), "InvalidQuoteMint", &env);
    push("quote mint PhUSD", &|a| a.quote_mint = env.fx.phusd, "InvalidQuoteMint", &env);
    push("admin zero", &|a| a.admin = Pubkey::default(), "InvalidParams", &env);
    push("creator zero", &|a| a.creator = Pubkey::default(), "InvalidParams", &env);
    for (i, pda) in p.program_pdas().iter().enumerate() {
        let k = *pda;
        let e = "InvalidParams";
        push(&format!("admin = PDA #{i}"), &move |a: &mut InitArgs| a.admin = k, e, &env);
        push(&format!("creator = PDA #{i}"), &move |a: &mut InitArgs| a.creator = k, e, &env);
    }
    // Structural parameter checks, one violation each (SPEC §3.2, §3.3).
    let hp = |f: &'static str, v: u128| abi::harvest_params().encode(&with(harvest_params_default(), f, v));
    let ip = |f: &'static str, v: u128| abi::inflow_params().encode(&with(inflow_params_default(), f, v));
    let harvest_bad = [
        hp("d_min", 0),
        hp("max_harvest_per_call", 999_999),
        hp("max_buyback_backlog", 0),
        // SPEC v4: the retired withdraw tolerance bytes are reserved zeros.
        hp("_reserved0", 1),
        hp("_reserved1", 1),
        hp("_reserved", 1),
    ];
    for (i, h) in harvest_bad.into_iter().enumerate() {
        push(&format!("harvest params #{i}"), &move |a: &mut InitArgs| a.harvest = h.clone(), "InvalidParams", &env);
    }
    let inflow_bad = [
        // SPEC v4: the retired oracle band / mark age and Ember tolerance bytes
        // are reserved zeros.
        ip("_reserved0", 1),
        ip("swap_min_lamports", 0),
        ip("swap_min_lamports", 10_000_000_001),
        ip("deposit_min_atoms", 0),
        ip("_reserved1", 1),
    ];
    for (i, f) in inflow_bad.into_iter().enumerate() {
        push(&format!("inflow params #{i}"), &move |a: &mut InitArgs| a.inflow = f.clone(), "InvalidParams", &env);
    }
    for (label, a, e) in bad {
        let ix = env.initialize_ix(&a);
        expect_err(env.send1(ix, S_UPGRADE), e, &label);
    }

    // Account slots.
    let good = env.init_args();
    let base = env.initialize_ix(&good);
    let cases: Vec<(usize, Pubkey, &str)> = vec![
        (1, Pubkey::new_unique(), "InvalidPda"),
        (1, p.buyback_state.0, "InvalidPda"),
        (2, Pubkey::new_unique(), "InvalidExternalAccount"),
        (3, SPL_TOKEN, "InvalidProgramId"),
        (4, Pubkey::new_unique(), "InvalidPhoenixGlobalConfig"),
        (5, Pubkey::new_unique(), "InvalidEmberAccount"),
    ];
    for (slot, key, e) in cases {
        let mut ix = base.clone();
        ix.accounts[slot].pubkey = key;
        expect_err(env.send1(ix, S_UPGRADE), e, &format!("account #{slot}"));
    }
    let mut ix = base.clone();
    ix.accounts.pop();
    expect_err(env.send1(ix, S_UPGRADE), "InvalidAccountCount", "5 accounts");
    let mut ix = base.clone();
    ix.accounts.push(AccountMeta::new_readonly(SYSTEM_PROGRAM, false));
    expect_err(env.send1(ix, S_UPGRADE), "InvalidAccountCount", "7 accounts");
    let mut ix = base.clone();
    ix.data.push(0);
    expect_err(env.send1(ix, S_UPGRADE), "InvalidInstructionData", "202 bytes");
    let mut ix = base.clone();
    ix.data.pop();
    expect_err(env.send1(ix, S_UPGRADE), "InvalidInstructionData", "200 bytes");
    // The pre-v2 layout (297 bytes, 7 accounts with TradeConfig) is refused.
    let mut ix = base.clone();
    ix.data.resize(297, 0);
    expect_err(env.send1(ix, S_UPGRADE), "InvalidInstructionData", "297 bytes (pre-v2)");
    assert!(!env.exists(&p.config.0), "nothing created by rejected calls");

    // Boundary values that must pass, USDC pair.
    let mut a = env.init_args();
    a.quote_mint = usdc;
    a.harvest = abi::harvest_params().encode(&with(
        with(with(harvest_params_default(), "max_harvest_per_call", 1_000_000), "max_buyback_backlog", 1),
        "epsilon",
        0,
    ));
    a.inflow = abi::inflow_params().encode(&with(inflow_params_default(), "swap_min_lamports", 10_000_000_000));
    let ix = env.initialize_ix(&a);
    ok(env.send1(ix, S_UPGRADE), "boundary initialize");
    assert_eq!(env.cfg_key("quote_mint"), usdc);
    assert_eq!(env.cfg_key("trader"), Pubkey::default());
}
