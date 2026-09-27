// Copyright (c) 2026 prt1sn. All rights reserved.
//! The 10-day continuous window (SPEC §5.6.2), `MAX_VENUE_OBS_GAP_SECS`, the
//! tag 50 rate limit and the latch (tag 51 op 0, §5.6.4) — TR-9, TR-13, and
//! the latch half of TR-14 / TR-23 — on the mainnet GlobalConfig with the
//! maintenance bit set (DOWN(EXCH_MAINTENANCE)).

use sijka_vault::constants::{MAX_VENUE_OBS_GAP_SECS, RECOVERY_DOWN_SECS};
use sijka_vault::error::SijkaError;

use crate::harness::*;

const STEP: i64 = 3_540; // 59 minutes

fn maintenance_on(env: &mut VenueEnv) {
    env.patch_gc(|d| d[gcx::STATUS] |= 0x04);
}

fn maintenance_off(env: &mut VenueEnv) {
    env.patch_gc(|d| d[gcx::STATUS] &= !0x04);
}

/// A transient UNKNOWN (SPEC v4: still resets): the restart interlock reads
/// `ack > LastRestartSlot` (reason 21 `GC_RESTART_ANOMALY`).
fn restart_anomaly_on(env: &mut VenueEnv) -> [u8; 8] {
    let old: [u8; 8] = env.gc()[gcx::ACK..gcx::ACK + 8].try_into().unwrap();
    let ack = u64::from_le_bytes(old);
    env.patch_gc(|d| d[gcx::ACK..gcx::ACK + 8].copy_from_slice(&(ack + 1_000).to_le_bytes()));
    old
}

fn restart_anomaly_off(env: &mut VenueEnv, old: [u8; 8]) {
    env.patch_gc(|d| d[gcx::ACK..gcx::ACK + 8].copy_from_slice(&old));
}

/// TR-9: DOWN every 59 minutes for 10 days → op 0 latches; `SJKEVRCL` and
/// the irreversible `recovery_mode`.
#[test]
fn tr9_ten_days_of_down_every_59_minutes_latches() {
    let Some(mut env) = VenueEnv::mainnet() else { return };
    assert_eq!(RECOVERY_DOWN_SECS, 864_000);
    assert_eq!(MAX_VENUE_OBS_GAP_SECS, 3_600);
    maintenance_on(&mut env);
    let first = env.observe_after(60);
    assert_eq!(first.flags & 0x02, 0x02, "streak starts");
    let t0 = env.ts;
    assert_eq!(first.down_since, t0);
    let mut n = 1u64;
    while env.ts - t0 < RECOVERY_DOWN_SECS {
        let v = env.observe_after(STEP);
        assert_eq!((v.verdict, v.reason), (DOWN, 3));
        assert_eq!(v.down_since, t0, "continuous streak");
        assert_eq!(v.flags & 0x06, 0, "no restart / reset");
        n += 1;
    }
    assert_eq!(env.cfg(|c| c.venue_obs_count()), n);
    // Op 0 right after tag 50 in the same slot: not rate limited.
    let r = env.latch();
    let m = assert_ok(&r);
    let vob = Vob::from_meta(m);
    assert_eq!((vob.verdict, vob.reason), (DOWN, 3));
    assert_eq!(vob.flags & 0x09, 0x09, "from_latch | recovery_mode");
    let rcl = event(&m.logs, b"SJKEVRCL").expect("SJKEVRCL");
    assert_eq!(rcl.len(), 107);
    assert_eq!(rcl[17], 3, "reason");
    assert_eq!(rcl[18], 0, "route RECIPIENT while admin is set");
    assert_eq!(rd_u64(&rcl, 19), env.slot);
    assert_eq!(rd_i64(&rcl, 27), t0);
    assert_eq!(rd_i64(&rcl, 35), env.ts - t0);
    assert!(rd_i64(&rcl, 35) >= RECOVERY_DOWN_SECS);
    assert_eq!(rd_key(&rcl, 43), env.admin, "emergency_recipient");
    env.cfg(|c| {
        assert_eq!(c.recovery_mode(), 1);
        assert_eq!(c.recovery_latched_ts(), env.ts);
        assert_eq!(c.recovery_latched_slot(), env.slot);
        assert_eq!(c.venue_obs_count(), n + 1);
    });
    // Irreversible: a second op 0 fails; Phoenix "coming back" does not undo it.
    env.tick(60);
    assert_err(&env.latch(), SijkaError::RecoveryAlreadyActive);
    maintenance_off(&mut env);
    let v = env.observe_after(60);
    assert_eq!(v.verdict, UP);
    assert_eq!(v.flags & 0x08, 0x08, "tag 50 still observes (informational), recovery_mode kept");
    assert_eq!(env.cfg(|c| c.recovery_mode()), 1);
}

/// Exactly 10 days: `now − down_since = 863 999` is too short, `864 000` latches.
#[test]
fn latch_boundary_is_exactly_ten_days() {
    let Some(mut env) = VenueEnv::mainnet() else { return };
    maintenance_on(&mut env);
    env.observe_after(60);
    let t0 = env.ts;
    while env.ts - t0 < RECOVERY_DOWN_SECS - 3_600 {
        env.observe_after(3_000);
    }
    let rest = t0 + RECOVERY_DOWN_SECS - 1 - env.ts;
    assert!(rest > 0 && rest <= MAX_VENUE_OBS_GAP_SECS);
    env.tick(rest);
    let before = env.venue_state();
    assert_err(&env.latch(), SijkaError::VenueDownTooShort);
    assert_eq!(env.venue_state(), before, "a failed op 0 rolls its observation back");
    env.tick(1);
    assert_eq!(env.ts - t0, RECOVERY_DOWN_SECS);
    assert_ok(&env.latch());
    assert_eq!(env.cfg(|c| c.recovery_mode()), 1);
}

/// TR-9: one gap longer than `MAX_VENUE_OBS_GAP_SECS` restarts the streak;
/// a gap of exactly 3 600 s does not.
#[test]
fn tr9_gap_over_one_hour_restarts_the_streak() {
    let Some(mut env) = VenueEnv::mainnet() else { return };
    maintenance_on(&mut env);
    env.observe_after(60);
    let t0 = env.ts;
    // Exactly the limit: continues.
    let v = env.observe_after(MAX_VENUE_OBS_GAP_SECS);
    assert_eq!(v.down_since, t0);
    assert_eq!(v.flags & 0x06, 0);
    env.down_series(STEP, 5 * 86_400);
    // 3 601 s without an observation.
    let v = env.observe_after(MAX_VENUE_OBS_GAP_SECS + 1);
    assert_eq!(v.verdict, DOWN);
    assert_eq!(v.flags & 0x06, 0x06, "streak restarted and old countdown reset");
    let t1 = env.ts;
    assert_eq!(v.down_since, t1);
    // Ten days after the first streak's start, but not after the restart.
    while env.ts - t0 < RECOVERY_DOWN_SECS + 60 {
        env.observe_after(STEP);
    }
    let before = env.venue_state();
    assert_err(&env.latch(), SijkaError::VenueDownTooShort);
    assert_eq!(env.venue_state(), before);
    // A gap before op 0 itself also restarts (the latch observes too).
    while env.ts - t1 < RECOVERY_DOWN_SECS - 100 {
        env.observe_after(STEP);
    }
    env.tick(MAX_VENUE_OBS_GAP_SECS + 200);
    assert!(env.ts - t1 >= RECOVERY_DOWN_SECS);
    assert_err(&env.latch(), SijkaError::VenueDownTooShort);
    assert_eq!(env.cfg(|c| c.recovery_mode()), 0);
}

/// TR-9: one UP or one transient UNKNOWN (SPEC v4: restart anomaly, reason
/// 21) observation in the middle resets the countdown.
#[test]
fn tr9_one_up_or_unknown_observation_resets() {
    let Some(mut env) = VenueEnv::mainnet() else { return };
    for interrupt in ["up", "unknown"] {
        maintenance_on(&mut env);
        env.observe_after(60);
        env.down_series(STEP, 6 * 86_400);
        let live = env.gc()[gcx::STATUS];
        let mut ack = None;
        // G8 (maintenance) is read before G9: switch it off for both cases.
        maintenance_off(&mut env);
        if interrupt == "unknown" {
            ack = Some(restart_anomaly_on(&mut env));
        }
        let v = env.observe_after(STEP);
        assert_eq!(v.verdict, if interrupt == "up" { UP } else { UNKNOWN }, "{interrupt}");
        if interrupt == "unknown" {
            assert_eq!(v.reason, 21, "GC_RESTART_ANOMALY is NEUTRAL (SPEC v4)");
        }
        assert_eq!(v.flags & 0x04, 0x04, "{interrupt}: reset");
        assert_eq!(env.cfg(|c| (c.venue_down_since_ts(), c.venue_last_down_obs_ts())), (0, 0));
        if let Some(old) = ack {
            restart_anomaly_off(&mut env, old);
        }
        env.patch_gc(|d| d[gcx::STATUS] = live);
        let v = env.observe_after(STEP);
        assert_eq!(v.flags & 0x02, 0x02, "{interrupt}: new streak");
        let t1 = env.ts;
        // 16 days of DOWN in total, but only 9 since the interruption.
        env.down_series(STEP, 9 * 86_400);
        assert!(env.ts - t1 < RECOVERY_DOWN_SECS);
        assert_err(&env.latch(), SijkaError::VenueDownTooShort);
        maintenance_off(&mut env);
        env.observe_after(60);
    }
}

/// TR-9: after 10 days of DOWN, op 0 needs DOWN *now*: UP → VenueNotDown, and
/// the rolled-back observation leaves the countdown intact.
#[test]
fn tr9_latch_needs_live_down() {
    let Some(mut env) = VenueEnv::mainnet() else { return };
    maintenance_on(&mut env);
    env.observe_after(60);
    let t0 = env.ts;
    env.down_series(STEP, RECOVERY_DOWN_SECS + 60);
    maintenance_off(&mut env);
    env.tick(60);
    let before = env.venue_state();
    assert_err(&env.latch(), SijkaError::VenueNotDown);
    assert_eq!(env.venue_state(), before, "rolled back: down_since still {t0}");
    assert_eq!(env.cfg(|c| c.venue_down_since_ts()), t0);
    // A transient UNKNOWN now (restart anomaly): also VenueNotDown.
    let old = restart_anomaly_on(&mut env);
    assert_err(&env.latch(), SijkaError::VenueNotDown);
    restart_anomaly_off(&mut env, old);
    // DOWN again within the gap: the streak is still the old one, op 0 latches.
    maintenance_on(&mut env);
    env.tick(60);
    assert_ok(&env.latch());
}

/// SPEC v4 (DECISIONS §23 item 5, variant A): ten days of an unrecognized
/// format (status bits 3–6 set, reason 20 `GC_STATUS_BITS`) are DOWN and
/// latch; a FORMAT observation in the middle of a maintenance streak
/// continues it (same `down_since`).
#[test]
fn ten_days_of_format_down_latch() {
    let Some(mut env) = VenueEnv::mainnet() else { return };
    maintenance_on(&mut env);
    let first = env.observe_after(60);
    let t0 = first.down_since;
    env.down_series(STEP, 3 * 86_400);
    env.patch_gc(|d| d[gcx::STATUS] |= 0x20);
    let v = env.observe_after(STEP);
    assert_eq!((v.verdict, v.reason, v.down_since), (DOWN, 20, t0), "FORMAT continues the streak");
    assert_eq!(v.flags & 0x06, 0, "no restart / reset");
    while env.ts - t0 < RECOVERY_DOWN_SECS {
        let v = env.observe_after(STEP);
        assert_eq!((v.verdict, v.reason, v.down_since), (DOWN, 20, t0));
    }
    let r = env.latch();
    let m = assert_ok(&r);
    let rcl = event(&m.logs, b"SJKEVRCL").expect("SJKEVRCL");
    assert_eq!((rcl[17], rcl[18]), (20, 0), "FORMAT reason, route RECIPIENT");
    assert_eq!(env.cfg(|c| c.recovery_mode()), 1);
}

/// Ten days of a transient UNKNOWN (restart anomaly, reason 21) never latch
/// (SPEC v4: only FORMAT reasons count).
#[test]
fn ten_days_of_transient_unknown_never_latch() {
    let Some(mut env) = VenueEnv::mainnet() else { return };
    // The exchange itself is active (G8 passes), only the interlock is odd.
    restart_anomaly_on(&mut env);
    let start = env.ts;
    while env.ts - start < RECOVERY_DOWN_SECS + STEP {
        let v = env.observe_after(STEP);
        assert_eq!((v.verdict, v.reason), (UNKNOWN, 21));
        assert_eq!(v.down_since, 0);
    }
    assert_err(&env.latch(), SijkaError::VenueNotDown);
}

/// TR-13: tag 50 rate limit (one per slot, 30 s); op 0 is not limited.
#[test]
fn tr13_observe_rate_limit() {
    let Some(mut env) = VenueEnv::mainnet() else { return };
    env.observe_after(60);
    // Same slot, same time.
    assert_err(&env.observe(), SijkaError::VenueObserveTooSoon);
    // Next slot, 29 s later.
    env.slot += 1;
    env.ts += 29;
    env.sync_clock();
    assert_err(&env.observe(), SijkaError::VenueObserveTooSoon);
    // 30 s later but the same slot.
    env.ts += 1;
    env.slot -= 1;
    env.sync_clock();
    assert_err(&env.observe(), SijkaError::VenueObserveTooSoon);
    // 30 s and a new slot: ok.
    env.slot += 1;
    env.sync_clock();
    assert_ok(&env.observe());
    let count = env.cfg(|c| c.venue_obs_count());
    // Op 0 in the same slot (UP: VenueNotDown, but not VenueObserveTooSoon).
    assert_err(&env.latch(), SijkaError::VenueNotDown);
    assert_eq!(env.cfg(|c| c.venue_obs_count()), count);
}
