// Copyright (c) 2026 prt1sn. All rights reserved.
//! Real Phoenix state transitions on the localnet fixture (mainnet Phoenix,
//! Ember and Hawkeye binaries), driven by Phoenix's own admin instructions:
//! TR-1 (fixture), TR-2 / TR-3 / TR-4 with the U-57 / U-62 probes of what
//! Phoenix still allows, and TR-5 (market close → settle → tombstone →
//! delete → relist) for U-58, U-59, U-61, U-64.

use sijka_vault::error::SijkaError;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::harness::*;
use crate::vault::*;

#[track_caller]
fn expect(v: &Vob, verdict: u8, reason: u8) {
    assert_eq!((v.verdict, v.reason), (verdict, reason), "{v:?}");
}

fn outcome(r: &TxResult) -> String {
    match r {
        Ok(_) => "ok".into(),
        Err(f) => {
            let tail: Vec<&String> = f
                .meta
                .logs
                .iter()
                .filter(|l| !l.contains("consumed") && !l.contains(" invoke [") && !l.ends_with(" success"))
                .rev()
                .take(6)
                .collect();
            format!("{:?} {:?}", f.err, tail)
        }
    }
}

/// What Phoenix lets through right now: our op 1 / op 6, reduce-only IOC and
/// cancel through our program, and a fixture trader's direct withdraw,
/// deposit and IOC. Returns `(probe, outcome)`.
fn probe(env: &mut VaultEnv, label: &str) -> Vec<(String, String)> {
    let mut out = vec![];
    let taker = env.ctx.actor("taker0");
    let (wallet, trader) = (parse(&taker.pubkey), parse(&taker.trader_account));
    let (t_usdc, t_phusd) = (parse(&taker.fake_usdc_token_account), parse(&taker.phoenix_token_account));
    let sol = env.orderbook("SOL");
    let mark = env.mark("SOL");
    let slot = env.slot;
    // Past the fixture's deposit cooldown (150 slots after our tag 21), with
    // fresh oracle prices (itself a probe: the delegated oracle's update).
    env.tick_slots(200);
    let r = env.try_refresh_prices();
    out.push(("oracle price update".into(), outcome(&r)));
    env.tick(5);
    let r = env.op_withdraw(1, 0);
    out.push(("vault op 1 (withdraw above the buffer, Hawkeye)".into(), outcome(&r)));
    env.tick(5);
    let r = env.ioc("SOL", 1, 1, 1, true);
    out.push(("vault key reduce-only IOC (1 lot, Phoenix direct)".into(), outcome(&r)));
    env.tick(5);
    let r = env.cancel_all("SOL");
    out.push(("vault key cancel_all".into(), outcome(&r)));
    env.tick(5);
    let fx = env.fx.clone();
    let r = env.send("taker-0000", vec![ix_withdraw_funds(&fx, wallet, trader, t_phusd, 1_000_000)]);
    out.push(("taker0 withdraw_funds 1 USDC".into(), outcome(&r)));
    env.tick(5);
    let wrap = ix_ember_deposit(&fx, wallet, t_usdc, t_phusd, 1_000_000);
    let r = env.send("taker-0000", vec![wrap, ix_deposit_funds(&fx, wallet, trader, t_phusd, 1_000_000)]);
    out.push(("taker0 deposit_funds 1 USDC".into(), outcome(&r)));
    env.tick(5);
    let r = env.send(
        "taker-0000",
        vec![ix_market_order(&fx, wallet, trader, sol, 0, mark * 103 / 100, 1, false, env.slot + 100)],
    );
    out.push(("taker0 IOC buy 1 lot (risk increasing)".into(), outcome(&r)));
    env.tick(5);
    let r = env.send("taker-0000", vec![ix_phx_cancel_all(&fx, wallet, trader, sol)]);
    out.push(("taker0 cancel_all".into(), outcome(&r)));
    for (p, o) in &out {
        println!("PHOENIX-PROBE [{label}] {p}: {o}");
    }
    assert!(env.slot > slot);
    out
}

fn parse(s: &str) -> Pubkey {
    phoenix_rise_litesvm_test::parse_pubkey(s).unwrap()
}

fn find<'a>(v: &'a [(String, String)], prefix: &str) -> &'a str {
    &v.iter().find(|(p, _)| p.starts_with(prefix)).expect("probe").1
}

/// TR-1 on the fixture exchange created by the real Phoenix binary.
#[test]
fn tr1_fixture_exchange_is_up() {
    let Some(mut env) = VaultEnv::new(VaultOpts::default()) else { return };
    let gc = env.gc();
    let p = env.pam_data();
    println!(
        "fixture GC: status {:#04x}, ack {}, cooldown {}, PAM {:?}, entries {:?}",
        gc[gcx::STATUS],
        rd_u64(&gc, gcx::ACK),
        rd_u64(&gc, gcx::COOLDOWN),
        pam_header(&p),
        pam_entries(&p).iter().map(|e| (e.symbol.clone(), e.asset_id, e.finalized, e.tombstoned)).collect::<Vec<_>>()
    );
    let v = env.observe_after(60);
    expect(&v, UP, 0);
    assert_eq!(v.majors_open, 0b111);
    assert_eq!(v.flags, 0, "X1 on: litesvm loads Phoenix upgradeable (Program + ProgramData)");
    let ids: Vec<u32> = ["SOL", "BTC", "ETH"].iter().map(|s| env.asset_id(s)).collect();
    env.cfg(|c| {
        assert_eq!(c.venue_major_seen(), 0b111);
        assert_eq!((0..3).map(|k| c.venue_major_asset_id_at(k).unwrap()).collect::<Vec<_>>(), ids);
        assert_eq!(c.emergency_recipient(), &env.admin.to_bytes());
        assert_eq!(c.emergency_recipient_usdc(), &env.er_usdc.to_bytes());
        assert_eq!(c.emergency_recipient_phusd(), &env.er_phusd.to_bytes());
        assert_eq!(c.phusd_mint(), &env.fx.phusd.to_bytes());
    });
    // The deposit really reached Phoenix (tag 21 on the mainnet binaries).
    assert!(env.collateral() > 0, "collateral {}", env.collateral());
    assert_eq!(env.cfg(|c| c.cum_inflow_usdc()), 1_000_000_000);
}

/// TR-2 / TR-3 and U-57: `change_exchange_status` of the mainnet binary sets
/// maintenance / clears active; the verdict follows; what Phoenix still
/// allows in each state is probed (and asserted against the SPEC model).
#[test]
fn tr2_tr3_u57_maintenance_and_suspended_real_phoenix() {
    let Some(mut env) = VaultEnv::new(VaultOpts::default()) else { return };
    let mark = env.mark("SOL");
    let r = env.ioc("SOL", 0, mark * 102 / 100, 10, false);
    assert_ok(&r);
    assert_eq!(env.positions().len(), 1, "vault position for the reduce-only probes");
    // Recovery mode injected so that op 1 can be probed in every state (the
    // real 10-day latch is covered by window.rs and withdraw.rs).
    env.edit_cfg(|m| m.set_recovery_mode(1));
    env.tick(200);
    let base = probe(&mut env, "active");
    assert_eq!(find(&base, "vault op 1"), "ok");
    assert_eq!(find(&base, "taker0 withdraw"), "ok");

    let states: [(&str, Option<bool>, Option<bool>, u8, u8); 2] =
        [("maintenance", None, Some(true), 3, 0x04), ("suspended", Some(false), None, 2, 0x00)];
    for (label, active, maintenance, reason, bit) in states {
        assert_ok(&env.set_exchange(active, maintenance));
        let st = env.gc()[gcx::STATUS];
        println!("exchange status after {label}: {st:#010b}");
        assert_eq!(st & 0x04, bit, "{label}: maintenance bit");
        if label == "suspended" {
            assert_eq!(st & 0x01, 0);
        }
        let v = env.observe_after(60);
        expect(&v, DOWN, reason);
        assert_eq!(v.exchange_status, st);
        let res = probe(&mut env, label);
        // U-57 (observed on the mainnet binary): in maintenance only cancels
        // and the oracle update pass ("Global configuration must be active"
        // for withdrawals, deposits and every order, reduce-only included);
        // suspended refuses everything ("... must be active or maintenance").
        println!("U-57 [{label}]: op 1 → {}", find(&res, "vault op 1"));
        let allowed: &[&str] = match label {
            "maintenance" => &["oracle price update", "vault key cancel_all", "taker0 cancel_all"],
            _ => &[],
        };
        for (p, o) in &res {
            let expect_ok = allowed.iter().any(|a| p.starts_with(a));
            assert_eq!(o == "ok", expect_ok, "U-57 [{label}] {p}: {o}");
        }
        assert!(find(&res, "taker0 withdraw").contains("Global configuration must be active"), "{label}");
        assert_ok(&env.set_exchange(Some(true), Some(false)));
        env.tick(60);
        env.refresh_prices();
        let v = env.observe_after(60);
        expect(&v, UP, 0);
    }
}

/// TR-4 / U-62 on the real binary: `acknowledge_restart` and
/// `LastRestartSlot`; the verdict and what Phoenix allows before the ack.
#[test]
fn tr4_u62_restart_interlock_real_phoenix() {
    let Some(mut env) = VaultEnv::new(VaultOpts::default()) else { return };
    let mark = env.mark("SOL");
    assert_ok(&env.ioc("SOL", 0, mark * 102 / 100, 10, false));
    env.edit_cfg(|m| m.set_recovery_mode(1));
    println!("fixture acknowledged_restart_slot: {}", rd_u64(&env.gc(), gcx::ACK));
    set_last_restart_slot(env.svm(), 5_000);
    // Signed by nobody but a stranger fee payer: the ack is permissionless.
    let r = env.send(STRANGER_SEED, vec![ix_acknowledge_restart(5_000)]);
    println!("acknowledge_restart(5000) by a stranger: {}", outcome(&r));
    assert_ok(&r);
    assert_eq!(rd_u64(&env.gc(), gcx::ACK), 5_000);
    let v = env.observe_after(60);
    expect(&v, UP, 0);
    assert_eq!((v.ack, v.lrs), (5_000, 5_000));
    // Cluster restart, not yet acknowledged.
    set_last_restart_slot(env.svm(), 6_000);
    let v = env.observe_after(60);
    // Not a verdict any more (BUG-recovery-2 fixed): the PAM decides.
    expect(&v, UP, 0);
    assert_eq!((v.ack, v.lrs), (5_000, 6_000));
    env.tick(60);
    env.refresh_prices();
    let res = probe(&mut env, "restart-unacked");
    println!("U-62: op 1 → {}; taker withdraw → {}", find(&res, "vault op 1"), find(&res, "taker0 withdraw"));
    // U-62 (observed): the mainnet binary does not enforce the interlock on
    // orders, withdrawals or deposits; only the SDK models it.
    for p in [
        "vault op 1",
        "vault key reduce-only",
        "vault key cancel_all",
        "taker0 withdraw",
        "taker0 deposit",
        "taker0 IOC",
    ] {
        assert_eq!(find(&res, p), "ok", "U-62: {p} while the restart is not acknowledged");
    }
    // A wrong expected slot is refused; the right one (by anyone) clears it.
    let r = env.send(STRANGER_SEED, vec![ix_acknowledge_restart(5_999)]);
    println!("acknowledge_restart(5999) with lrs 6000: {}", outcome(&r));
    assert!(r.is_err(), "Phoenix must refuse an ack for another restart slot");
    assert_ok(&env.send(STRANGER_SEED, vec![ix_acknowledge_restart(6_000)]));
    let v = env.observe_after(60);
    expect(&v, UP, 0);
    // ack > lrs (LiteSVM default 0): UNKNOWN(GC_RESTART_ANOMALY).
    set_last_restart_slot(env.svm(), 0);
    expect(&env.observe_after(60), UNKNOWN, 21);
}

/// U-62 was refuted by `tr4_u62_restart_interlock_real_phoenix`: while the
/// restart is not acknowledged, the mainnet binary still trades, withdraws
/// and deposits, i.e. Phoenix works. DECISIONS §17 counts only "Phoenix does
/// not work" and O-18 prefers no count over a false trigger, so such
/// observations must not count toward the 10 days (BUG-recovery-2, fixed:
/// SPEC §5.6.1 G9 no longer gives DOWN for `0 < ack < lrs`).
#[test]
fn u62_unacked_restart_with_working_phoenix_is_not_down() {
    let Some(mut env) = VaultEnv::new(VaultOpts::default()) else { return };
    set_last_restart_slot(env.svm(), 5_000);
    assert_ok(&env.send(STRANGER_SEED, vec![ix_acknowledge_restart(5_000)]));
    set_last_restart_slot(env.svm(), 6_000);
    env.tick_slots(200);
    let taker = env.ctx.actor("taker0");
    let (w, t, dst) = (parse(&taker.pubkey), parse(&taker.trader_account), parse(&taker.phoenix_token_account));
    let fx = env.fx.clone();
    assert_ok(&env.send("taker-0000", vec![ix_withdraw_funds(&fx, w, t, dst, 1_000_000)]));
    let v = env.observe_after(60);
    assert_ne!(v.verdict, DOWN, "Phoenix works, yet the observation counts as DOWN: {v:?}");
    expect(&v, UP, 0);
    assert_eq!(v.down_since, 0, "no countdown while Phoenix works");
}

/// Accounts of a new market in a free PAM slot: a clone of the fixture's
/// `addSOLMarket` with another orderbook and symbol.
fn add_market(env: &mut VaultEnv, seed: &str, symbol: &str) -> Pubkey {
    let book = env.ctx.add_signer(seed, 0);
    let pick = |env: &VaultEnv, tx: &str, name: &str| {
        let t = env.ctx.fixture.setup_transactions.iter().find(|t| t.name == tx).unwrap().clone();
        phoenix_rise_litesvm_test::decode_fixture_instruction(t.instructions.iter().find(|i| i.name == name).unwrap())
            .unwrap()
    };
    let old_book = env.orderbook("SOL");
    let old_spline = env.spline("SOL");
    let mut create = pick(env, "initializeMarkets", "createSOLOrderbook");
    create.accounts[1].pubkey = book;
    let mut add = pick(env, "initializeMarkets", "addSOLMarket");
    for m in add.accounts.iter_mut() {
        if m.pubkey == old_book {
            m.pubkey = book;
        } else if m.pubkey == old_spline {
            m.pubkey = spline_pda(&book);
        }
    }
    add.data[8..24].copy_from_slice(&sym16(symbol));
    let mut activate = pick(env, "initializeMarkets", "activateSOLMarket");
    for m in activate.accounts.iter_mut() {
        if m.pubkey == old_book {
            m.pubkey = book;
        }
    }
    let r = env.send("payer", vec![create]);
    assert_ok(&r);
    let r = env.send("payer", vec![add]);
    println!("add_market {symbol}: {}", outcome(&r));
    assert_ok(&r);
    let r = env.send("payer", vec![activate]);
    println!("activate {symbol}: {}", outcome(&r));
    book
}

fn pam_report(env: &VaultEnv, label: &str) {
    let p = env.pam_data();
    println!(
        "PAM [{label}] header (num, slots_used, tombstones, capacity) = {:?}; entries {:?}",
        pam_header(&p),
        pam_entries(&p)
            .iter()
            .map(|e| format!(
                "{}#{} aid={:#x} fin={} tomb={} gen={}",
                e.symbol, e.slot, e.asset_id, e.finalized, e.tombstoned, e.index_num
            ))
            .collect::<Vec<_>>()
    );
}

/// TR-5, U-58, U-59, U-61, U-64: close BTC and ETH, pause then close SOL,
/// settle the vault's SOL position (only the market authority can), tombstone
/// and delete SOL, then list new markets into the freed slot.
#[test]
fn tr5_market_lifecycle_real_phoenix() {
    let Some(mut env) = VaultEnv::new(VaultOpts::default()) else { return };
    let fx = env.fx.clone();
    let auth = fx.authority;
    let mark = env.mark("SOL");
    assert_ok(&env.ioc("SOL", 0, mark * 102 / 100, 10, false));
    let pos = env.positions();
    println!("vault positions after the buy: {pos:?}");
    assert_eq!(pos.len(), 1);
    let sol_aid = env.asset_id("SOL");
    expect(&env.observe_after(60), UP, 0);
    // No resting maker orders (tombstone needs NO_ORDERS).
    env.ctx.send_fixture_transaction("orderbookCancelLevels");
    pam_report(&env, "start");

    // BTC and ETH: Paused → Closed.
    for s in ["BTC", "ETH"] {
        let book = env.orderbook(s);
        assert_ok(&env.send("payer", vec![ix_change_market_status(auth, fx.pam, book, 3)]));
        let r = env.send("payer", vec![ix_close_market(auth, fx.pam, book)]);
        println!("close_market {s}: {}", outcome(&r));
        assert_ok(&r);
        let p = env.pam_data();
        let e = pam_entry(&p, pam_find(&p, s).expect("closed market stays in the PAM"));
        println!("U-58: {s} finalized_mark_price @e+1456 after CloseMarket = {}", e.finalized);
        assert_ne!(e.finalized, 0, "U-58: CloseMarket writes the final price into the PAM");
    }
    let v = env.observe_after(60);
    expect(&v, UP, 0);
    assert_eq!((v.majors_open, v.majors_closed), (0b001, 0b110));

    // SOL Paused: not "closed" (DECISIONS §17), still UP.
    let sol = env.orderbook("SOL");
    assert_ok(&env.send("payer", vec![ix_change_market_status(auth, fx.pam, sol, 3)]));
    let v = env.observe_after(60);
    expect(&v, UP, 0);
    assert_eq!(v.majors_open, 0b001, "Paused SOL counts as open");

    // SOL closed: all three closed → DOWN(MAJORS_CLOSED).
    assert_ok(&env.send("payer", vec![ix_close_market(auth, fx.pam, sol)]));
    let p = env.pam_data();
    let sol_e = pam_entry(&p, pam_find(&p, "SOL").unwrap());
    println!("U-58: SOL finalized_mark_price = {} (mark before {mark})", sol_e.finalized);
    assert_ne!(sol_e.finalized, 0);
    let v = env.observe_after(60);
    expect(&v, DOWN, 5);
    assert_eq!(v.majors_closed, 0b111);

    // U-61: settle_closed_market_position is the market authority's.
    let ob_trader = env.ctx.actor_trader("orderbookTrader");
    let vault_trader = env.trader;
    let stranger = env.stranger;
    let r =
        env.send(STRANGER_SEED, vec![ix_settle_closed_market_position(&fx, stranger, sol, vault_trader, ob_trader)]);
    println!("U-61: settle signed by a stranger: {}", outcome(&r));
    assert!(r.is_err(), "U-61: a stranger cannot settle");
    let bot = env.bot;
    let r = env.send(BOT_SEED, vec![ix_settle_closed_market_position(&fx, bot, sol, vault_trader, ob_trader)]);
    println!("U-61: settle signed by the vault's trading key: {}", outcome(&r));
    assert!(r.is_err(), "U-61: the trading key cannot settle");
    let c0 = env.collateral();
    let r = env.send("payer", vec![ix_settle_closed_market_position(&fx, auth, sol, vault_trader, ob_trader)]);
    println!("U-61: settle signed by the market authority: {}", outcome(&r));
    assert_ok(&r);
    println!(
        "U-61: vault positions after settle {:?}, C_hdr {} → {} (settlement price {})",
        env.positions(),
        c0,
        env.collateral(),
        sol_e.finalized
    );
    assert!(env.positions().iter().all(|&(a, _)| a != sol_aid), "vault SOL position settled by Phoenix");

    // Tombstone needs no positions referencing the asset: resync every
    // trader of the fixture (permissionless `update_trader_state`).
    let mut traders = vec![env.trader];
    for a in ["orderbookTrader", "splineTrader", "taker0", "taker1", "stopLossTaker"] {
        traders.push(env.ctx.actor_trader(a));
    }
    for t in traders {
        let r = env.send(STRANGER_SEED, vec![ix_update_trader_state(&fx, t)]);
        println!("update_trader_state {t}: {}", outcome(&r));
    }
    // Tombstone (needs no splines) and delete.
    let spline = env.spline("SOL");
    let st = env.ctx.actor_trader("splineTrader");
    let r = env.send("payer", vec![ix_deactivate_spline(&fx, auth, spline, sol, st)]);
    println!("deactivate_spline SOL: {}", outcome(&r));
    let r = env.send("payer", vec![ix_tombstone_market(&fx, auth, sol, spline)]);
    println!("tombstone_market SOL: {}", outcome(&r));
    assert_ok(&r);
    pam_report(&env, "after TombstoneMarket");
    let p = env.pam_data();
    let (num, su, tomb, _) = pam_header(&p);
    let live = pam_entries(&p).iter().filter(|e| e.tombstoned == 0).count() as u32;
    println!(
        "U-59 after tombstone: live {live} == num {num}: {}; su − tomb {} == num: {}",
        live == u32::from(num),
        su - tomb,
        su - tomb == u32::from(num)
    );
    let v = env.observe_after(60);
    println!("verdict after tombstone: {v:?}");
    let payer = env.ctx.signer_pubkey("payer");
    let r = env.send("payer", vec![ix_delete_tombstoned_market(&fx, auth, payer, sol, spline)]);
    println!("delete_tombstoned_market SOL: {}", outcome(&r));
    assert_ok(&r);
    pam_report(&env, "after DeleteTombstonedMarket");
    let p = env.pam_data();
    let (num, su, tomb, _) = pam_header(&p);
    let live = pam_entries(&p).iter().filter(|e| e.tombstoned == 0).count() as u32;
    println!(
        "U-59 after delete: live {live} == num {num}: {}; su − tomb {} == num: {}",
        live == u32::from(num),
        su - tomb,
        su - tomb == u32::from(num)
    );
    assert_eq!(live, u32::from(num), "U-59 (a) P4a after delete");
    assert_eq!(su - tomb, u32::from(num), "U-59 (b) P4b after delete");
    assert!(pam_find(&p, "SOL").is_none(), "SOL removed from the PAM");
    let v = env.observe_after(60);
    expect(&v, DOWN, 5);
    assert_eq!(v.majors_closed, 0b111, "deleted after being seen = closed");

    // U-64: a new market in the freed slot gets a new asset_id generation, so
    // the deleted SOL is not taken for "renamed".
    add_market(&mut env, "recovery-new-market-1", "NEWMKT");
    pam_report(&env, "after AddMarket NEWMKT");
    let p = env.pam_data();
    let new_e = pam_entry(&p, pam_find(&p, "NEWMKT").expect("new market listed"));
    println!("U-64: SOL asset_id {sol_aid:#x}; new market in slot {} asset_id {:#x}", new_e.slot, new_e.asset_id);
    assert_ne!(new_e.asset_id, sol_aid, "U-64: a deleted market's asset_id is not reused");
    let v = env.observe_after(60);
    expect(&v, DOWN, 5);

    // Relisting "SOL" (new book, new asset_id): found by symbol → UP, memory follows.
    add_market(&mut env, "recovery-new-market-2", "SOL");
    let new_sol = env.asset_id("SOL");
    let v = env.observe_after(60);
    expect(&v, UP, 0);
    assert_eq!(env.cfg(|c| c.venue_major_asset_id_at(0).unwrap()), new_sol);
    assert_ne!(new_sol, sol_aid);
}

/// TR-32 / U-68 with the real loader: `Close` of Phoenix's ProgramData by its
/// upgrade authority (patched to the fixture payer) keeps the Program account
/// at BPFLoaderUpgradeable and removes the ProgramData; the verdict is
/// DOWN(PROGRAM_CLOSED), the latch follows after 10 days, CPI into the
/// closed program fails (op 1 / op 6), and op 2 / op 5 still pay out.
#[test]
fn tr32_u68_loader_close_of_phoenix_programdata() {
    let Some(mut env) = VaultEnv::new(VaultOpts::default()) else { return };
    let payer = env.ctx.signer_pubkey("payer");
    let pd = phoenix_program_data();
    patch(env.svm(), &pd, |d| {
        d[12] = 1;
        d[13..45].copy_from_slice(payer.as_ref());
    });
    env.tick(60);
    let close = Instruction {
        program_id: loader_v3(),
        accounts: vec![
            AccountMeta::new(pd, false),
            AccountMeta::new(payer, false),
            AccountMeta::new_readonly(payer, true),
            AccountMeta::new(phoenix_id(), false),
        ],
        data: 5u32.to_le_bytes().to_vec(),
    };
    let r = env.send("payer", vec![close]);
    println!("loader Close of Phoenix ProgramData: {}", outcome(&r));
    assert_ok(&r);
    let prog = env.ctx.svm.get_account(&phoenix_id()).expect("program account stays");
    println!(
        "U-68: after Close: program owner {}, {} bytes, executable {}; ProgramData present: {}",
        prog.owner,
        prog.data.len(),
        prog.executable,
        env.ctx.svm.get_account(&pd).is_some()
    );
    assert_eq!(prog.owner, loader_v3());
    assert_eq!(prog.data.len(), 36);
    assert_eq!(rd_u32(&prog.data, 0), 2);
    assert_eq!(rd_key(&prog.data, 4), pd);
    assert!(env.ctx.svm.get_account(&pd).is_none(), "ProgramData removed");
    let v = env.observe_after(60);
    expect(&v, DOWN, 6);
    let start = env.ts;
    while env.ts - start < 864_000 {
        let v = env.observe_after(3_000);
        expect(&v, DOWN, 6);
    }
    let r = env.latch();
    let rcl = event(&assert_ok(&r).logs, b"SJKEVRCL").expect("SJKEVRCL");
    assert_eq!(rcl[17], 6, "latch reason PROGRAM_CLOSED");
    env.tick_slots(200);
    let r = env.op_withdraw(1, 0);
    println!("op 1 into the closed Phoenix: {}", outcome(&r));
    assert!(r.is_err(), "CPI into a closed program fails");
    let r = env.op_withdraw(6, 0);
    println!("op 6 into the closed Phoenix: {}", outcome(&r));
    assert!(r.is_err());
    // What is already out still reaches the admin.
    let vp = env.vault_phusd;
    env.donate_phusd(vp, 3_000_000);
    let er_phusd = env.er_phusd;
    assert_ok(&env.op_send_token(5, er_phusd));
    let vu = env.vault_usdc;
    env.ctx.mint_fake_usdc_to_token_account(vu, 4_000_000);
    let er = env.er_usdc;
    assert_ok(&env.op_send_token(2, er));
    assert_eq!(env.amount(&er), 4_000_000);
}

/// The countdown cannot be reset by Phoenix accounts at wrong keys on the
/// real exchange either (TR-8 on the fixture), and the latch needs DOWN.
#[test]
fn tr8_fixture_substitution_and_latch_needs_down() {
    let Some(mut env) = VaultEnv::new(VaultOpts::default()) else { return };
    assert_ok(&env.set_exchange(None, Some(true)));
    expect(&env.observe_after(60), DOWN, 3);
    let before = venue_state(&env.ctx.svm, &env.p.config);
    env.tick(60);
    let mut ix = observe_ix(env.program_id, env.p.config, env.fx.pam);
    ix.accounts[2].pubkey = env.fx.wq; // a Phoenix-owned account at a foreign key
    let r = env.send("payer", vec![ix]);
    assert_err(&r, SijkaError::InvalidPerpAssetMap);
    assert_eq!(venue_state(&env.ctx.svm, &env.p.config), before);
    env.tick(60);
    assert_err(&env.latch(), SijkaError::VenueDownTooShort);
    assert_eq!(venue_state(&env.ctx.svm, &env.p.config), before);
}
