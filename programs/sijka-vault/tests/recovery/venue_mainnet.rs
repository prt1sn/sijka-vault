// Copyright (c) 2026 prt1sn. All rights reserved.
//! Venue verdict (SPEC §5.6.1) on mainnet snapshots of GlobalConfig,
//! PerpAssetMap, the Phoenix program account and its ProgramData (TR-1,
//! TR-4, TR-6..TR-8, TR-11, TR-12, TR-31, TR-32 byte cases), and on
//! byte-level mutations of those snapshots.

use sijka_vault::error::SijkaError;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::harness::*;

const MAJORS: [&str; 3] = ["SOL", "BTC", "ETH"];
const LOADER_V4: Pubkey = Pubkey::from_str_const("LoaderV411111111111111111111111111111111111");

fn slot_of(p: &[u8], s: &str) -> usize {
    pam_find(p, s).unwrap_or_else(|| panic!("{s} not live in the PAM snapshot"))
}

fn close(p: &mut [u8], s: &str) {
    let e = pamx::e(slot_of(p, s));
    wr_u64(p, e + pamx::E_FINAL, 1_234_567);
}

fn rename(p: &mut [u8], s: &str, to: &str) {
    let e = pamx::e(slot_of(p, s));
    p[e..e + 16].copy_from_slice(&sym16(to));
}

/// Tombstone the entry and keep the header consistent (`live == num`,
/// `slots_used − tombstones == num`).
fn delete(p: &mut [u8], s: &str) {
    let e = pamx::e(slot_of(p, s));
    p[e + pamx::E_TOMB] = 1;
    let num = rd_u16(p, pamx::NUM_ASSETS);
    wr_u16(p, pamx::NUM_ASSETS, num - 1);
    let t = rd_u32(p, pamx::TOMBSTONES);
    wr_u32(p, pamx::TOMBSTONES, t + 1);
}

fn first_non_major(p: &[u8]) -> usize {
    pam_entries(p)
        .into_iter()
        .find(|e| e.tombstoned == 0 && !MAJORS.contains(&e.symbol.as_str()))
        .expect("a non-major market")
        .slot
}

#[track_caller]
fn expect(v: &Vob, verdict: u8, reason: u8) {
    assert_eq!((v.verdict, v.reason), (verdict, reason), "{v:?}");
}

/// TR-1: the live mainnet state is UP; the three majors are remembered.
#[test]
fn tr1_mainnet_snapshot_is_up_and_remembers_majors() {
    let Some(mut env) = VenueEnv::mainnet() else { return };
    let gc = env.gc();
    let p = env.pam_data();
    let (num, su, tomb, cap) = pam_header(&p);
    let ids: Vec<u32> = MAJORS.iter().map(|s| pam_entry(&p, slot_of(&p, s)).asset_id).collect();
    println!(
        "mainnet snapshot (slot {}): status {:#04x}, ack {}, PAM {} num {num} su {su} tomb {tomb} cap {cap}, majors {ids:?}",
        env.snap_slot,
        gc[gcx::STATUS],
        rd_u64(&gc, gcx::ACK),
        env.pam
    );
    let r = env.observe();
    let m = assert_ok(&r);
    println!("U-63: tag 50 on mainnet PAM ({su} entries): {} CU", m.compute_units_consumed);
    let v = Vob::from_meta(m);
    expect(&v, UP, 0);
    assert_eq!((v.majors_open, v.majors_closed, v.majors_unknown), (0b111, 0, 0));
    assert_eq!(v.flags & 0x10, 0, "X1 signal on for the real Program/ProgramData pair");
    assert_eq!(v.flags, 0);
    assert_eq!(v.exchange_status, gc[gcx::STATUS]);
    assert_eq!((v.ack, v.lrs), (rd_u64(&gc, gcx::ACK), rd_u64(&gc, gcx::ACK)));
    assert_eq!(v.live, u32::from(num));
    assert_eq!((v.down_since, v.last_down_obs_ts, v.obs_count), (0, 0, 1));
    env.cfg(|c| {
        assert_eq!(c.venue_major_seen(), 0b111);
        let mem: Vec<u32> = (0..3).map(|k| c.venue_major_asset_id_at(k).unwrap()).collect();
        assert_eq!(mem, ids, "memory = PAM asset ids of SOL, BTC, ETH");
        assert_eq!((c.venue_last_verdict(), c.venue_last_reason()), (UP, 0));
        assert_eq!(c.last_venue_obs_ts(), env.ts);
        assert_eq!(c.last_venue_obs_slot(), env.slot);
    });
    // SPEC TR-1 / appendix F §2.4: SOL, BTC, ETH are PAM slots 0, 1, 2.
    assert_eq!(ids, vec![0, 1, 2], "live asset ids of SOL, BTC, ETH");
}

/// G6 / G8: exchange status bits on the mainnet GlobalConfig.
#[test]
fn exchange_status_bits_on_mainnet_global_config() {
    let Some(mut env) = VenueEnv::mainnet() else { return };
    let live = env.gc()[gcx::STATUS];
    assert_eq!(live & 0x81, 0x81, "live exchange initialized and active: {live:#x}");
    let cases: [(u8, u8, u8); 6] = [
        (live & !0x01, DOWN, 2),          // suspended
        (live | 0x04, DOWN, 3),           // maintenance
        ((live | 0x04) & !0x01, DOWN, 2), // suspended wins (checked first)
        (live | 0x08, DOWN, 20),          // undefined bit 3 (FORMAT, SPEC v4)
        (live | 0x40, DOWN, 20),          // undefined bit 6 (FORMAT)
        (live & !0x80, DOWN, 20),         // not initialized (FORMAT)
    ];
    for (s, verdict, reason) in cases {
        env.patch_gc(|d| d[gcx::STATUS] = s);
        let v = env.observe_after(60);
        expect(&v, verdict, reason);
        assert_eq!(v.exchange_status, s);
        if verdict == DOWN {
            // G8 is self-sufficient: PAM not scanned, majors not evaluated.
            assert_eq!((v.live, v.majors_open), (0, 0));
        }
    }
    // Undefined bit together with "not active": FORMAT DOWN(20) (G6 before G8).
    env.patch_gc(|d| d[gcx::STATUS] = (live | 0x10) & !0x01);
    expect(&env.observe_after(60), DOWN, 20);
    env.patch_gc(|d| d[gcx::STATUS] = live);
    expect(&env.observe_after(60), UP, 0);
}

/// G9 / TR-4 (bytes): restart interlock against `sol_get_last_restart_slot`.
/// An unacknowledged restart is not a verdict (U-62 refuted, BUG-recovery-2
/// fixed): the PAM decides, so the live snapshot stays UP.
#[test]
fn tr4_restart_interlock_on_mainnet_bytes() {
    let Some(mut env) = VenueEnv::mainnet() else { return };
    let ack = rd_u64(&env.gc(), gcx::ACK);
    assert_eq!(ack, MAINNET_RESTART_SLOT, "live acknowledged_restart_slot");
    set_last_restart_slot(&mut env.svm, ack + 1);
    let v = env.observe_after(60);
    expect(&v, UP, 0);
    assert_eq!((v.ack, v.lrs), (ack, ack + 1));
    assert!(v.live > 0, "PAM scanned past G9");
    // LiteSVM default (0): ack > lrs is impossible for a live exchange.
    set_last_restart_slot(&mut env.svm, 0);
    let v = env.observe_after(60);
    expect(&v, UNKNOWN, 21);
    assert_eq!(v.down_since, 0, "UNKNOWN resets the countdown");
    // ack == 0: interlock off (Rust SDK rule), any lrs.
    env.patch_gc(|d| wr_u64(d, gcx::ACK, 0));
    set_last_restart_slot(&mut env.svm, ack + 5);
    expect(&env.observe_after(60), UP, 0);
    env.patch_gc(|d| wr_u64(d, gcx::ACK, ack));
    set_last_restart_slot(&mut env.svm, ack);
    expect(&env.observe_after(60), UP, 0);
}

/// TR-6: GlobalConfig closed, then 1 lamport donated: DOWN(GC_ABSENT) both
/// times, and the PAM is not checked (any key).
#[test]
fn tr6_global_config_absent_is_down() {
    let Some(mut env) = VenueEnv::mainnet() else { return };
    let gc_key = global_config_key();
    remove(&mut env.svm, gc_key);
    let v = env.observe_after(60);
    expect(&v, DOWN, 1);
    assert_eq!((v.exchange_status, v.live, v.ack), (0, 0, 0));
    assert_eq!(v.flags & 0x02, 0x02, "streak started");
    // Donation: owner System, no data, 1 lamport.
    put(&mut env.svm, gc_key, system_program(), 1, vec![], false);
    let v = env.observe_after(60);
    expect(&v, DOWN, 1);
    // A foreign PAM key is not an error while GC is absent (G7 not reached).
    env.tick(60);
    let mut ix = observe_ix(env.program_id, env.config, env.pam);
    ix.accounts[2] = AccountMeta::new_readonly(Pubkey::new_unique(), false);
    let r = env.send(vec![ix]);
    expect(&Vob::from_meta(assert_ok(&r)), DOWN, 1);
    // GC owner System but with data (impossible for the PDA, still not
    // "absent"): FORMAT DOWN(GC_OWNER) since SPEC v4.
    put(&mut env.svm, gc_key, system_program(), 1_000_000, vec![0u8; 8], false);
    expect(&env.observe_after(60), DOWN, 16);
}

/// TR-7 (SPEC v4, DECISIONS §23 item 5, variant A): unrecognized
/// GlobalConfig formats are FORMAT DOWN (with the step's code) and continue a
/// running DOWN countdown instead of resetting it.
#[test]
fn tr7_global_config_format_changes_are_down_and_count() {
    let Some(mut env) = VenueEnv::mainnet() else { return };
    let orig = env.gc();
    type Mutation = fn(&mut Vec<u8>);
    let cases: [(&str, Mutation, u8); 9] = [
        ("bit 0x08", |d| d[gcx::STATUS] |= 0x08, 20),
        ("bit 7 cleared", |d| d[gcx::STATUS] &= !0x80, 20),
        ("@505 = 7", |d| d[gcx::QUOTE_DECIMALS] = 7, 19),
        ("foreign @296", |d| d[gcx::PHUSD] ^= 0xFF, 19),
        ("foreign @8", |d| d[gcx::KEY + 5] ^= 0x01, 19),
        ("length 1103", |d| d.truncate(gcx::PREFIX - 1), 17),
        ("length 505", |d| d.truncate(505), 17),
        ("foreign disc", |d| d[0] ^= 0x80, 18),
        ("empty data, owner Phoenix", |d| d.clear(), 17),
    ];
    for (name, m, reason) in cases {
        // A running countdown (maintenance), then the unrecognized format.
        let mut dm = orig.clone();
        dm[gcx::STATUS] |= 0x04;
        put_rent_exempt(&mut env.svm, global_config_key(), phoenix_id(), dm);
        let v = env.observe_after(60);
        expect(&v, DOWN, 3);
        let since = env.cfg(|c| c.venue_down_since_ts());
        assert_ne!(since, 0);
        let mut d = orig.clone();
        m(&mut d);
        put_rent_exempt(&mut env.svm, global_config_key(), phoenix_id(), d);
        let v = env.observe_after(60);
        assert_eq!((v.verdict, v.reason), (DOWN, reason), "{name}: {v:?}");
        assert_eq!(v.flags & 0x06, 0, "{name}: neither reset nor restart");
        assert_eq!(v.down_since, since, "{name}: the streak continues");
        env.cfg(|c| {
            assert_eq!(c.venue_down_since_ts(), since, "{name}");
            assert_eq!((c.venue_last_verdict(), c.venue_last_reason()), (DOWN, reason), "{name}");
        });
    }
    // Owner not Phoenix (with the live bytes).
    put_rent_exempt(&mut env.svm, global_config_key(), token_program(), orig.clone());
    expect(&env.observe_after(60), DOWN, 16);
    // A grown GlobalConfig (realloc larger, F5) is still recognized.
    let mut big = orig.clone();
    big.extend_from_slice(&[0u8; 512]);
    put_rent_exempt(&mut env.svm, global_config_key(), phoenix_id(), big);
    expect(&env.observe_after(60), UP, 0);
    // `GC@508` (U-60, "padding" that is 0x06 live) does not affect the verdict.
    let mut pad = orig;
    println!("U-60: live GC@508..512 = {:02x?}", &pad[508..512]);
    pad[508..512].copy_from_slice(&[0xff; 4]);
    put_rent_exempt(&mut env.svm, global_config_key(), phoenix_id(), pad);
    expect(&env.observe_after(60), UP, 0);
}

/// TR-8: substituted or mis-flagged accounts are instruction errors, never a
/// verdict, and leave the countdown untouched.
#[test]
fn tr8_account_substitutions_are_errors_not_verdicts() {
    let Some(mut env) = VenueEnv::mainnet() else { return };
    // A running DOWN streak that a griefer would like to reset.
    env.patch_gc(|d| d[gcx::STATUS] |= 0x04);
    expect(&env.observe_after(60), DOWN, 3);
    let before = env.venue_state();
    let (pid, cfg, pam) = (env.program_id, env.config, env.pam);
    let fake_pam = Pubkey::new_unique();
    // A PAM clone owned by Phoenix at a foreign key (right disc and layout).
    let pam_bytes = env.pam_data();
    put_rent_exempt(&mut env.svm, fake_pam, phoenix_id(), pam_bytes);
    let base = || observe_metas(cfg, global_config_key(), pam);
    type Edit = Box<dyn Fn(&mut Vec<AccountMeta>)>;
    let cases: Vec<(&str, Edit, SijkaError)> = vec![
        ("foreign GC key", Box::new(move |a| a[1].pubkey = pam), SijkaError::InvalidPhoenixGlobalConfig),
        ("PAM != GC@360", Box::new(move |a| a[2].pubkey = fake_pam), SijkaError::InvalidPerpAssetMap),
        ("GC writable", Box::new(|a| a[1].is_writable = true), SijkaError::AccountMustBeReadonly),
        ("PAM writable", Box::new(|a| a[2].is_writable = true), SijkaError::AccountMustBeReadonly),
        ("program writable", Box::new(|a| a[3].is_writable = true), SijkaError::AccountMustBeReadonly),
        ("ProgramData writable", Box::new(|a| a[4].is_writable = true), SijkaError::AccountMustBeReadonly),
        ("foreign program", Box::new(|a| a[3].pubkey = hawkeye_id()), SijkaError::InvalidProgramId),
        ("Hawkeye ProgramData", Box::new(|a| a[4].pubkey = HAWKEYE_PROGRAM_DATA), SijkaError::InvalidExternalAccount),
        (
            "extra account",
            Box::new(|a| a.push(AccountMeta::new_readonly(Pubkey::new_unique(), false))),
            SijkaError::InvalidAccountCount,
        ),
        ("4 accounts (pre O-14 layout)", Box::new(|a| a.truncate(4)), SijkaError::InvalidAccountCount),
        ("config read-only", Box::new(|a| a[0].is_writable = false), SijkaError::AccountNotWritable),
    ];
    for (name, edit, e) in cases {
        for data in [vec![50u8], vec![51u8, 0]] {
            env.tick(60);
            let mut accounts = base();
            edit(&mut accounts);
            let r = env.send(vec![Instruction { program_id: pid, accounts, data: data.clone() }]);
            assert_err(&r, e);
            assert_eq!(env.venue_state(), before, "{name} (tag {data:?}): state unchanged");
        }
    }
    // A PAM with owner System at the key GC@360 is a verdict (FORMAT DOWN
    // since SPEC v4), not an error: nobody but Phoenix can close it, so it is
    // Phoenix's own state.
    let pam_bytes = env.pam_data();
    put_rent_exempt(&mut env.svm, pam, system_program(), pam_bytes);
    expect(&env.observe_after(60), DOWN, 3); // G8 still decides first
    env.patch_gc(|d| d[gcx::STATUS] &= !0x04);
    expect(&env.observe_after(60), DOWN, 32);
    remove(&mut env.svm, pam);
    expect(&env.observe_after(60), DOWN, 32);
}

/// TR-12 and the M rules: symbol lookup, rename / duplicate / delete /
/// never-seen / moved asset id.
#[test]
fn tr12_majors_by_symbol_with_rename_protection() {
    let Some(mut env) = VenueEnv::mainnet() else { return };
    let orig = env.pam_data();
    expect(&env.observe_after(60), UP, 0); // memory: SOL, BTC, ETH
    let sol_aid = env.cfg(|c| c.venue_major_asset_id_at(0).unwrap());

    // Renamed SOL while BTC / ETH are open: still UP (any open major wins).
    env.patch_pam(|p| rename(p, "SOL", "SOL-PERP"));
    let v = env.observe_after(60);
    expect(&v, UP, 0);
    assert_eq!((v.majors_open, v.majors_unknown), (0b110, 0b001));

    // BTC and ETH closed (finalized price), SOL open: UP.
    let mut p2 = orig.clone();
    close(&mut p2, "BTC");
    close(&mut p2, "ETH");
    put_rent_exempt(&mut env.svm, env.pam, phoenix_id(), p2.clone());
    let v = env.observe_after(60);
    expect(&v, UP, 0);
    assert_eq!((v.majors_open, v.majors_closed), (0b001, 0b110));

    // + SOL renamed with the same asset_id: UNKNOWN(MAJOR_RENAMED), not DOWN.
    let mut p3 = p2.clone();
    rename(&mut p3, "SOL", "SOL-PERP");
    put_rent_exempt(&mut env.svm, env.pam, phoenix_id(), p3);
    let v = env.observe_after(60);
    expect(&v, UNKNOWN, 38);
    assert_eq!((v.majors_closed, v.majors_unknown), (0b110, 0b001));
    assert_eq!(env.cfg(|c| c.venue_major_asset_id_at(0).unwrap()), sol_aid, "memory kept");

    // + a second live "SOL": UNKNOWN(MAJOR_DUPLICATE).
    let mut p4 = p2.clone();
    let other = first_non_major(&p4);
    let e = pamx::e(other);
    p4[e..e + 16].copy_from_slice(&sym16("SOL"));
    put_rent_exempt(&mut env.svm, env.pam, phoenix_id(), p4);
    expect(&env.observe_after(60), UNKNOWN, 36);

    // SOL deleted (tombstoned, header consistent) after it was seen: CLOSED,
    // so with BTC / ETH closed the verdict is DOWN(MAJORS_CLOSED).
    let mut p5 = p2.clone();
    delete(&mut p5, "SOL");
    put_rent_exempt(&mut env.svm, env.pam, phoenix_id(), p5);
    let v = env.observe_after(60);
    expect(&v, DOWN, 5);
    assert_eq!(v.majors_closed, 0b111);
    assert_eq!(v.live, u32::from(rd_u16(&orig, pamx::NUM_ASSETS)) - 1);

    // SOL moved to a new asset_id (next generation) with the same symbol: UP,
    // memory follows.
    let mut p6 = orig.clone();
    let e = pamx::e(slot_of(&p6, "SOL"));
    let hi = rd_u16(&p6, e + pamx::E_AID_HI);
    wr_u16(&mut p6, e + pamx::E_AID_HI, hi + 1);
    put_rent_exempt(&mut env.svm, env.pam, phoenix_id(), p6);
    expect(&env.observe_after(60), UP, 0);
    let moved = env.cfg(|c| c.venue_major_asset_id_at(0).unwrap());
    assert_eq!(moved, sol_aid + 0x1_0000);
    // ... and the old id alive under another symbol no longer matters.

    // Never seen: fresh memory and none of the three present: UNKNOWN(37).
    let mut p7 = orig.clone();
    for s in MAJORS {
        let e = pamx::e(slot_of(&p7, s));
        let hi = rd_u16(&p7, e + pamx::E_AID_HI);
        wr_u16(&mut p7, e + pamx::E_AID_HI, hi + 7);
        p7[e..e + 16].copy_from_slice(&sym16(&format!("X{s}")));
    }
    put_rent_exempt(&mut env.svm, env.pam, phoenix_id(), p7);
    let key = env.config;
    edit_cfg(&mut env.svm, &key, |m| {
        m.set_venue_major_seen(0);
        for kk in 0..3 {
            m.set_venue_major_asset_id_at(kk, 0);
        }
    });
    let v = env.observe_after(60);
    expect(&v, UNKNOWN, 37);
    assert_eq!(v.majors_unknown, 0b111);
}

/// DECISIONS §17: only SOL, BTC and ETH count; every other market may be
/// closed or open without effect; all three closed is DOWN.
#[test]
fn all_three_majors_closed_is_down_other_markets_irrelevant() {
    let Some(mut env) = VenueEnv::mainnet() else { return };
    let orig = env.pam_data();
    // Every non-major closed: UP.
    let mut p = orig.clone();
    for e in pam_entries(&orig) {
        if !MAJORS.contains(&e.symbol.as_str()) {
            wr_u64(&mut p, pamx::e(e.slot) + pamx::E_FINAL, 99);
        }
    }
    put_rent_exempt(&mut env.svm, env.pam, phoenix_id(), p);
    let v = env.observe_after(60);
    expect(&v, UP, 0);
    assert_eq!(v.majors_open, 0b111);
    // Two majors closed: UP; all three: DOWN(MAJORS_CLOSED).
    let mut p = orig.clone();
    close(&mut p, "SOL");
    close(&mut p, "BTC");
    put_rent_exempt(&mut env.svm, env.pam, phoenix_id(), p.clone());
    expect(&env.observe_after(60), UP, 0);
    close(&mut p, "ETH");
    put_rent_exempt(&mut env.svm, env.pam, phoenix_id(), p);
    let v = env.observe_after(60);
    expect(&v, DOWN, 5);
    assert_eq!((v.majors_open, v.majors_closed, v.majors_unknown), (0, 0b111, 0));
    // All three deleted (tombstoned) after being seen: still DOWN.
    let mut p = orig.clone();
    for s in MAJORS {
        delete(&mut p, s);
    }
    put_rent_exempt(&mut env.svm, env.pam, phoenix_id(), p);
    expect(&env.observe_after(60), DOWN, 5);
    // Header slots_used = 0 is inconsistent with num_assets → FORMAT
    // DOWN(PAM_COUNT) since SPEC v4 (the counters changed meaning), never
    // DOWN(MAJORS_CLOSED).
    let mut p = orig.clone();
    wr_u32(&mut p, pamx::SLOTS_USED, 0);
    put_rent_exempt(&mut env.svm, env.pam, phoenix_id(), p);
    expect(&env.observe_after(60), DOWN, 35);
    // An empty exchange (num = su = tomb = 0) after the majors were seen: DOWN.
    let mut p = orig;
    wr_u32(&mut p, pamx::SLOTS_USED, 0);
    wr_u16(&mut p, pamx::NUM_ASSETS, 0);
    wr_u32(&mut p, pamx::TOMBSTONES, 0);
    put_rent_exempt(&mut env.svm, env.pam, phoenix_id(), p);
    let v = env.observe_after(60);
    expect(&v, DOWN, 5);
    assert_eq!(v.live, 0);
}

/// P1–P4b and TR-31 (SPEC v4, variant A): unrecognized PAM formats and
/// inconsistent counters are FORMAT DOWN with their own reason (never
/// DOWN(MAJORS_CLOSED): the scan stops before M), and they count.
#[test]
fn tr31_pam_format_and_counter_anomalies_are_format_down() {
    let Some(mut env) = VenueEnv::mainnet() else { return };
    let mut closed = env.pam_data();
    for s in MAJORS {
        close(&mut closed, s);
    }
    let pam = env.pam;
    type Mutation = fn(&mut Vec<u8>);
    fn add_u32(p: &mut [u8], o: usize, delta: i64) {
        let v = i64::from(rd_u32(p, o)) + delta;
        wr_u32(p, o, u32::try_from(v).unwrap());
    }
    let cases: [(&str, Mutation, u8); 10] = [
        ("foreign disc", |p| p[0] ^= 1, 33),
        ("one extra byte", |p| p.push(0), 33),
        ("one byte short", |p| p.truncate(p.len() - 1), 33),
        ("slots_used > capacity", |p| wr_u32(p, pamx::SLOTS_USED, 1025), 33),
        (
            "tombstones > slots_used",
            |p| {
                let su = rd_u32(p, pamx::SLOTS_USED);
                wr_u32(p, pamx::TOMBSTONES, su + 1)
            },
            33,
        ),
        ("is_tombstoned = 2", |p| p[pamx::e(5) + pamx::E_TOMB] = 2, 34),
        ("live entry without market", |p| p[pamx::e(7) + pamx::E_MARKET..pamx::e(7) + pamx::E_MARKET + 32].fill(0), 34),
        (
            "num_assets + 1",
            |p| {
                let n = rd_u16(p, pamx::NUM_ASSETS);
                wr_u16(p, pamx::NUM_ASSETS, n + 1)
            },
            35,
        ),
        // live == num but slots_used − tombstones ≠ num (P4b, review REC-1).
        ("tombstones + 1", |p| add_u32(p, pamx::TOMBSTONES, 1), 39),
        // A live entry beyond slots_used that num_assets counts (P4a guards the scan).
        ("live entry beyond slots_used", |p| add_u32(p, pamx::SLOTS_USED, -1), 35),
    ];
    for (name, m, reason) in cases {
        let mut p = closed.clone();
        m(&mut p);
        put_rent_exempt(&mut env.svm, pam, phoenix_id(), p);
        let v = env.observe_after(60);
        assert_eq!((v.verdict, v.reason), (DOWN, reason), "{name}: {v:?}");
        assert_ne!(v.down_since, 0, "{name}: counts");
        assert_eq!((v.majors_open, v.majors_closed), (0, 0), "{name}: M not reached");
    }
    put_rent_exempt(&mut env.svm, pam, token_program(), closed.clone());
    expect(&env.observe_after(60), DOWN, 32);
    // Sanity: the unmutated "all closed" PAM is DOWN.
    put_rent_exempt(&mut env.svm, pam, phoenix_id(), closed);
    expect(&env.observe_after(60), DOWN, 5);
}

/// X1 (O-14) and TR-32 byte cases: ProgramData of the Phoenix program gone
/// is DOWN(PROGRAM_CLOSED) whatever GC / PAM say; a loader migration or an
/// unrecognized ProgramData only switches the signal off (flags bit4).
#[test]
fn tr32_program_closed_signal_x1() {
    let Some(mut env) = VenueEnv::mainnet() else { return };
    let (prog, pd) = (data_of(&env.svm, &phoenix_id()), data_of(&env.svm, &phoenix_program_data()));
    assert_eq!(prog.len(), 36, "mainnet Program account");
    assert_eq!(rd_u32(&prog, 0), 2);
    assert_eq!(rd_key(&prog, 4), phoenix_program_data());
    assert_eq!(rd_u32(&pd, 0), 3, "mainnet ProgramData tag");
    println!(
        "mainnet Phoenix ProgramData: {} bytes, deploy slot {}, upgrade authority {}",
        pd.len(),
        rd_u64(&pd, 4),
        if pd[12] == 1 { rd_key(&pd, 13).to_string() } else { "none".into() }
    );
    remove(&mut env.svm, phoenix_program_data());
    let v = env.observe_after(60);
    expect(&v, DOWN, 6);
    assert_eq!(v.flags & 0x10, 0);
    // Donated lamports: still absent (loader PDA, only the loader writes data).
    put(&mut env.svm, phoenix_program_data(), system_program(), 1, vec![], false);
    expect(&env.observe_after(60), DOWN, 6);
    // GC and PAM are not consulted: a foreign PAM key is no error here.
    env.tick(60);
    let mut ix = observe_ix(env.program_id, env.config, env.pam);
    ix.accounts[2].pubkey = Pubkey::new_unique();
    expect(&Vob::from_meta(assert_ok(&env.send(vec![ix]))), DOWN, 6);
    // Loader migration (program owned by loader-v4) with ProgramData gone:
    // no DOWN, signal off, verdict from GC / PAM.
    put(&mut env.svm, phoenix_id(), LOADER_V4, 1_141_440, prog.clone(), false);
    let v = env.observe_after(60);
    expect(&v, UP, 0);
    assert_eq!(v.flags & 0x10, 0x10);
    // Back to the v3 program account; ProgramData with tag 1 (unrecognized).
    put(&mut env.svm, phoenix_id(), loader_v3(), 1_141_440, prog.clone(), false);
    let mut pd1 = pd.clone();
    wr_u32(&mut pd1, 0, 1);
    put_rent_exempt(&mut env.svm, phoenix_program_data(), loader_v3(), pd1);
    let v = env.observe_after(60);
    expect(&v, UP, 0);
    assert_eq!(v.flags & 0x10, 0x10);
    // Program account without the ProgramData pointer (36 bytes, tag 2, other key).
    let mut prog2 = prog.clone();
    prog2[4] ^= 1;
    put(&mut env.svm, phoenix_id(), loader_v3(), 1_141_440, prog2, false);
    remove(&mut env.svm, phoenix_program_data());
    let v = env.observe_after(60);
    expect(&v, UP, 0);
    assert_eq!(v.flags & 0x10, 0x10);
    // Signal off, exchange suspended: DOWN(EXCH_SUSPENDED) still works.
    env.patch_gc(|d| d[gcx::STATUS] &= !0x01);
    let v = env.observe_after(60);
    expect(&v, DOWN, 2);
    assert_eq!(v.flags & 0x10, 0x10);
    // Restore: signal on again.
    put(&mut env.svm, phoenix_id(), loader_v3(), 1_141_440, prog, false);
    put_rent_exempt(&mut env.svm, phoenix_program_data(), loader_v3(), pd);
    env.patch_gc(|d| d[gcx::STATUS] |= 0x01);
    let v = env.observe_after(60);
    expect(&v, UP, 0);
    assert_eq!(v.flags & 0x10, 0);
}

/// CU of tag 50 (live PAM, full PAM) and op 0 (full PAM):
/// `(cu_live, cu_full, cu_latch, entries_live, capacity)`.
fn cu_at_live_and_full_pam(env: &mut VenueEnv) -> (u64, u64, u64, u32, u64) {
    let orig = env.pam_data();
    let (_, su, _, cap) = pam_header(&orig);
    let r = env.observe();
    let cu_live = assert_ok(&r).compute_units_consumed;
    // Fill every slot: clones of a non-major entry with unique symbols and ids.
    let mut full = orig.clone();
    let src = first_non_major(&orig);
    let tmpl = full[pamx::e(src)..pamx::e(src) + pamx::ENTRY].to_vec();
    for i in su as usize..cap as usize {
        let e = pamx::e(i);
        full[e..e + pamx::ENTRY].copy_from_slice(&tmpl);
        full[e..e + 16].copy_from_slice(&sym16(&format!("Z{i:05}")));
        wr_u16(&mut full, e + pamx::E_AID_LO, i as u16);
        wr_u16(&mut full, e + pamx::E_AID_HI, 0);
        full[e + pamx::E_TOMB] = 0;
        wr_u64(&mut full, e + pamx::E_FINAL, 0);
    }
    wr_u32(&mut full, pamx::SLOTS_USED, cap as u32);
    wr_u32(&mut full, pamx::TOMBSTONES, 0);
    wr_u16(&mut full, pamx::NUM_ASSETS, cap as u16);
    put_rent_exempt(&mut env.svm, env.pam, phoenix_id(), full);
    env.tick(60);
    let r = env.observe();
    let m = assert_ok(&r);
    let v = Vob::from_meta(m);
    expect(&v, UP, 0);
    assert_eq!(v.live, cap as u32);
    let cu_full = m.compute_units_consumed;
    // Op 0 on the full PAM (UP now: VenueNotDown, CU still reported).
    env.tick(60);
    let r = env.latch();
    assert_err(&r, SijkaError::VenueNotDown);
    let cu_latch = r.as_ref().err().unwrap().meta.compute_units_consumed;
    println!("U-63: tag 50 CU: {cu_live} at {su} entries, {cu_full} at {cap} entries; op 0 {cu_latch} at {cap}");
    (cu_live, cu_full, cu_latch, su, cap)
}

/// TR-11 / U-63 (closed, SPEC v3 §5.6.3, §11.10 item 110): the live PAM is
/// far below the limit, and a full 1024-entry PAM fits the 200k CU limit of
/// tag 50 and op 0 (measured on the mainnet PAM grown to 1024 entries before
/// the P3 scan was trimmed: about 158.5k for tag 50 and 159k for op 0, test
/// finding BUG-recovery-1; the old 150k figure is retired). Totals include
/// the 150-CU budget instruction.
#[test]
fn tr11_compute_units_at_90_and_1024_entries() {
    let Some(mut env) = VenueEnv::mainnet() else { return };
    let (cu_live, cu_full, cu_latch, su, cap) = cu_at_live_and_full_pam(&mut env);
    assert!(cu_live <= 150_000, "tag 50 at {su} entries: {cu_live} CU");
    assert!(cu_full <= 200_000, "tag 50 at {cap} entries: {cu_full} CU (SPEC limit 200k)");
    assert!(cu_latch <= 200_000, "op 0 at {cap} entries: {cu_latch} CU (SPEC limit 200k)");
}
