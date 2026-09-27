// Copyright (c) 2026 prt1sn. All rights reserved.
//! Phoenix up / down / unknown verdict (SPEC §5.6.1) and the 10-day countdown
//! (§5.6.2), shared by tags 50 and 51 op 0.
//!
//! The verdict is a pure function of account snapshots (key, owner, data),
//! `LastRestartSlot` and the majors memory from `Config`, so it is tested on
//! the host with synthetic GlobalConfig / PerpAssetMap buffers. Its only error
//! is `InvalidPerpAssetMap` (step G7: GC recognized but the PAM key is not
//! `GC@360`); every other anomaly is a verdict. Fail-safe rules:
//!
//! - DOWN on the literal conditions of §5.6.1 (program closed, GC absent,
//!   exchange suspended / in maintenance, or none of SOL, BTC, ETH open,
//!   looked up by symbol); an unacknowledged restart is not DOWN (U-62);
//! - DOWN also when Phoenix changed the format of its own data so that the
//!   program no longer recognizes it (DECISIONS §23 item 5, variant A): the
//!   FORMAT reasons 16–20 (GlobalConfig owner, length, discriminator,
//!   anchors, status bits) and 32–35, 39 (PerpAssetMap owner, layout, entry,
//!   scan counters), see [`reason::is_format`]. Only Phoenix can produce these
//!   states (pinned keys; program upgrade or its own account changes);
//! - UNKNOWN only for transient or symbol reasons (21 restart anomaly,
//!   36–38 majors duplicated / never seen / renamed): it never counts towards
//!   the 10 days and resets the countdown (O-18 for these reasons);
//! - every read is bounds-checked; a read that does not fit is a FORMAT DOWN
//!   (`GC_SHORT`, `PAM_ENTRY`).

use pinocchio::program_error::ProgramError;
use pinocchio::pubkey::{Pubkey, pubkey_eq};

use crate::constants::{
    BPF_LOADER_UPGRADEABLE_ID, DISC_GLOBAL_CONFIG, DISC_PAM, GC_PREFIX_LEN, GC_QUOTE_DECIMALS, MAJOR_SYMBOLS,
    MAX_VENUE_OBS_GAP_SECS, PHOENIX_GLOBAL_CONFIG, PHOENIX_PROGRAM_DATA, PHOENIX_PROGRAM_ID, RECOVERY_DOWN_SECS,
    SYSTEM_PROGRAM_ID,
};
use crate::error::SijkaError;
use crate::external::layout::{global_config as gcl, loader, perp_asset_map as paml};
use crate::external::phoenix_accounts::{pam_entry_offset, pam_layout_ok};
use crate::state::config::{Config, ConfigMut, MAJOR_COUNT};
use crate::util::bytes::{ZERO_KEY, array_ref, read_u8, read_u16, read_u32, read_u64};

/// Snapshot of one account for the verdict.
#[derive(Clone, Copy, Debug)]
pub struct AccountView<'a> {
    pub key: &'a Pubkey,
    pub owner: &'a Pubkey,
    pub data: &'a [u8],
}

/// Reason codes (`venue_last_reason`, SPEC §5.6.1 table).
pub mod reason {
    pub const UP: u8 = 0;
    pub const GC_ABSENT: u8 = 1;
    pub const EXCH_SUSPENDED: u8 = 2;
    pub const EXCH_MAINTENANCE: u8 = 3;
    /// Retired (test finding BUG-recovery-2, U-62 refuted): an unacknowledged
    /// restart is not a verdict. The code is never produced and not reused.
    pub const RESTART_UNACKED: u8 = 4;
    pub const MAJORS_CLOSED: u8 = 5;
    pub const PROGRAM_CLOSED: u8 = 6;
    pub const GC_OWNER: u8 = 16;
    pub const GC_SHORT: u8 = 17;
    pub const GC_DISC: u8 = 18;
    pub const GC_ANCHOR: u8 = 19;
    pub const GC_STATUS_BITS: u8 = 20;
    pub const GC_RESTART_ANOMALY: u8 = 21;
    pub const PAM_OWNER: u8 = 32;
    pub const PAM_LAYOUT: u8 = 33;
    pub const PAM_ENTRY: u8 = 34;
    pub const PAM_COUNT: u8 = 35;
    pub const MAJOR_DUPLICATE: u8 = 36;
    pub const MAJOR_NEVER_SEEN: u8 = 37;
    pub const MAJOR_RENAMED: u8 = 38;
    pub const PAM_SLOTS: u8 = 39;

    /// FORMAT reasons (DECISIONS §23 item 5, SPEC §5.6.1): Phoenix's data is
    /// not recognized. They are DOWN verdicts and count towards the 10 days.
    pub const fn is_format(r: u8) -> bool {
        matches!(r, 16..=20 | 32..=35 | 39)
    }
}

/// Verdict of one observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Up,
    /// DOWN with a reason code 1..=6, or a FORMAT code 16..=20, 32..=35, 39
    /// (SPEC v4, [`reason::is_format`]).
    Down(u8),
    /// UNKNOWN (transient / symbol) with a reason code 21 or 36..=38.
    Unknown(u8),
}

impl Verdict {
    /// `venue_last_verdict` value: 1 UP, 2 DOWN, 3 UNKNOWN.
    pub const fn kind(&self) -> u8 {
        match self {
            Verdict::Up => crate::state::config::venue_verdict::UP,
            Verdict::Down(_) => crate::state::config::venue_verdict::DOWN,
            Verdict::Unknown(_) => crate::state::config::venue_verdict::UNKNOWN,
        }
    }

    /// `venue_last_reason` value.
    pub const fn reason(&self) -> u8 {
        match self {
            Verdict::Up => reason::UP,
            Verdict::Down(r) | Verdict::Unknown(r) => *r,
        }
    }

    /// `true` for DOWN.
    pub const fn is_down(&self) -> bool {
        matches!(self, Verdict::Down(_))
    }
}

/// Majors memory (`Config.venue_major_seen`, `venue_major_asset_id`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MajorMemory {
    pub seen: u8,
    pub asset_ids: [u32; MAJOR_COUNT],
}

impl MajorMemory {
    /// Read the memory from `Config`.
    pub fn from_config(cfg: &Config<'_>) -> Self {
        Self {
            seen: cfg.venue_major_seen(),
            asset_ids: [
                cfg.venue_major_asset_id_at(0).unwrap_or(0),
                cfg.venue_major_asset_id_at(1).unwrap_or(0),
                cfg.venue_major_asset_id_at(2).unwrap_or(0),
            ],
        }
    }
}

/// Details for `SJKEVVOB` and the memory update.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VerdictDetails {
    /// `GC@504` if GC passed G2–G3, else 0.
    pub exchange_status: u8,
    /// `GC@1096`, 0 if not read.
    pub ack: u64,
    pub lrs: u64,
    /// Live PAM entries after a complete P3 scan (0 if the PAM was not read or
    /// the scan stopped at a bad entry).
    pub live: u32,
    pub majors_open: u8,
    pub majors_closed: u8,
    pub majors_unknown: u8,
    /// X1 signal off (event `flags` bit 4, O-14).
    pub program_signal_off: bool,
    /// Step M reached (memory must be written).
    pub reached_majors: bool,
    /// Updated memory (valid when `reached_majors`).
    pub memory: MajorMemory,
}

/// Bit `k` of the majors masks and of `venue_major_seen` (0 SOL, 1 BTC, 2 ETH).
const MAJOR_BITS: [u8; MAJOR_COUNT] = [1 << 0, 1 << 1, 1 << 2];

/// Scan state of one major (SOL, BTC or ETH) during P3.
#[derive(Clone, Copy)]
struct MajorScan {
    /// The 16 symbol bytes (zero-padded).
    symbol: [u8; 16],
    bit: u8,
    /// `venue_major_seen` bit set.
    seen: bool,
    /// Remembered `asset_id` (meaningful when `seen`).
    remembered: u32,
    /// Live entries with this symbol.
    hits: u32,
    /// `asset_id` and `finalized_mark_price` of the (last) live entry with this symbol.
    asset_id: u32,
    finalized: u64,
    /// A live entry carries the remembered `asset_id`.
    ref_alive: bool,
}

impl MajorScan {
    const fn new(symbol: &[u8; 16], bit: u8, memory: &MajorMemory, remembered: u32) -> Self {
        Self {
            symbol: *symbol,
            bit,
            seen: memory.seen & bit != 0,
            remembered,
            hits: 0,
            asset_id: 0,
            finalized: 0,
            ref_alive: false,
        }
    }
}

/// `venue_verdict(prog, pd, gc, pam, cfg)` — SPEC §5.6.1 steps X1, G1–G9,
/// P1–P4b, M, in this order. `phusd_mint` is `cfg.phusd_mint` (anchor G5),
/// `lrs` is `sol_get_last_restart_slot()`.
///
/// The keys of `prog`, `program_data` and `gc` are checked by the caller
/// (instruction account checks, §5.6.3); `pam.key` is checked here (G7) only
/// when GC is recognized.
pub fn venue_verdict(
    prog: &AccountView<'_>,
    program_data: &AccountView<'_>,
    gc: &AccountView<'_>,
    pam: &AccountView<'_>,
    lrs: u64,
    memory: &MajorMemory,
    phusd_mint: &Pubkey,
) -> Result<(Verdict, VerdictDetails), ProgramError> {
    let mut det = VerdictDetails { lrs, memory: *memory, ..VerdictDetails::default() };

    // ---- X1: the Phoenix program (O-14). Checked first: GC and PAM of a
    // closed program are frozen and mean nothing.
    let prog_v3 = pubkey_eq(prog.owner, &BPF_LOADER_UPGRADEABLE_ID)
        && prog.data.len() == loader::PROGRAM_ACCOUNT_LEN
        && read_u32(prog.data, loader::STATE_TAG) == Some(loader::TAG_PROGRAM)
        && array_ref::<32>(prog.data, loader::PROGRAM_DATA_ADDRESS) == Some(&PHOENIX_PROGRAM_DATA);
    if prog_v3 && pubkey_eq(program_data.owner, &SYSTEM_PROGRAM_ID) && program_data.data.is_empty() {
        // Any lamports: only the loader can write owner and data at its PDA.
        return Ok((Verdict::Down(reason::PROGRAM_CLOSED), det));
    }
    let pd_live = pubkey_eq(program_data.owner, &BPF_LOADER_UPGRADEABLE_ID)
        && program_data.data.len() >= loader::PD_METADATA_LEN
        && read_u32(program_data.data, loader::STATE_TAG) == Some(loader::TAG_PROGRAM_DATA);
    // Event flag only; any other program / ProgramData state is neither DOWN
    // nor UNKNOWN (a loader migration must not silence the exchange signals).
    det.program_signal_off = !(prog_v3 && pd_live);

    let v = gc_and_pam(gc, pam, lrs, memory, phusd_mint, &mut det)?;
    Ok((v, det))
}

/// Steps G1–M.
fn gc_and_pam(
    gc: &AccountView<'_>,
    pam: &AccountView<'_>,
    lrs: u64,
    memory: &MajorMemory,
    phusd_mint: &Pubkey,
    det: &mut VerdictDetails,
) -> Result<Verdict, ProgramError> {
    use Verdict::{Down, Unknown};
    use reason::*;

    // G1: GC is the Phoenix PDA ["global"]; only Phoenix can put data there,
    // anyone can send lamports. Owner System without data = absent.
    if pubkey_eq(gc.owner, &SYSTEM_PROGRAM_ID) && gc.data.is_empty() {
        return Ok(Down(GC_ABSENT));
    }
    // G2, G3.
    if !pubkey_eq(gc.owner, &PHOENIX_PROGRAM_ID) {
        return Ok(Down(GC_OWNER));
    }
    let d = gc.data;
    let Some(s) = read_u8(d, gcl::EXCHANGE_STATUS).filter(|_| d.len() >= GC_PREFIX_LEN) else {
        return Ok(Down(GC_SHORT));
    };
    det.exchange_status = s;
    // G4.
    if array_ref::<8>(d, gcl::DISCRIMINATOR) != Some(&DISC_GLOBAL_CONFIG) {
        return Ok(Down(GC_DISC));
    }
    // G5: anchors (own key, PhUSD, quote decimals).
    let anchors = array_ref::<32>(d, gcl::ACCOUNT_KEY) == Some(&PHOENIX_GLOBAL_CONFIG)
        && array_ref::<32>(d, gcl::CANONICAL_MINT) == Some(phusd_mint)
        && read_u8(d, gcl::QUOTE_DECIMALS) == Some(GC_QUOTE_DECIMALS);
    if !anchors {
        return Ok(Down(GC_ANCHOR));
    }
    // G6: initialized, and no bit the SDK does not define.
    if s & gcl::STATUS_INITIALIZED == 0 || s & gcl::STATUS_UNDEFINED_MASK != 0 {
        return Ok(Down(GC_STATUS_BITS));
    }
    // G7: GC recognized, so the PAM must be the one it points to (an
    // instruction error, not a verdict: nobody can reset the countdown with a
    // foreign PAM).
    let Some(gc_pam) = array_ref::<32>(d, gcl::PERP_ASSET_MAP) else {
        return Ok(Down(GC_SHORT));
    };
    if !pubkey_eq(pam.key, gc_pam) {
        return Err(SijkaError::InvalidPerpAssetMap.fail());
    }
    // G8: the exchange signal is self-sufficient (PAM not needed).
    if s & gcl::STATUS_ACTIVE == 0 {
        return Ok(Down(EXCH_SUSPENDED));
    }
    if s & gcl::STATUS_MAINTENANCE != 0 {
        return Ok(Down(EXCH_MAINTENANCE));
    }
    // G9: restart interlock. `ack > lrs` is impossible on a live exchange
    // (UNKNOWN). `0 < ack < lrs` (restart not acknowledged) is not a verdict:
    // the mainnet binary keeps trading, withdrawing and depositing without the
    // acknowledgement (U-62 refuted, test finding BUG-recovery-2), so it does
    // not mean "Phoenix does not work" (DECISIONS §17); the PAM decides.
    // `ack` and `lrs` go to the event (keeper alert).
    let Some(ack) = read_u64(d, gcl::ACKNOWLEDGED_RESTART_SLOT) else {
        return Ok(Down(GC_SHORT));
    };
    det.ack = ack;
    if ack != 0 && ack > lrs {
        return Ok(Unknown(GC_RESTART_ANOMALY));
    }

    // ---- PerpAssetMap.
    if !pubkey_eq(pam.owner, &PHOENIX_PROGRAM_ID) {
        return Ok(Down(PAM_OWNER));
    }
    let p = pam.data;
    if array_ref::<8>(p, paml::DISCRIMINATOR) != Some(&DISC_PAM) || !pam_layout_ok(p) {
        return Ok(Down(PAM_LAYOUT));
    }
    let (Some(num), Some(su), Some(tomb)) =
        (read_u16(p, paml::NUM_ASSETS), read_u32(p, paml::SLOTS_USED), read_u32(p, paml::TOMBSTONES))
    else {
        return Ok(Down(PAM_LAYOUT));
    };
    let mut majors = [
        MajorScan::new(&MAJOR_SYMBOLS[0], MAJOR_BITS[0], memory, memory.asset_ids[0]),
        MajorScan::new(&MAJOR_SYMBOLS[1], MAJOR_BITS[1], memory, memory.asset_ids[1]),
        MajorScan::new(&MAJOR_SYMBOLS[2], MAJOR_BITS[2], memory, memory.asset_ids[2]),
    ];
    // P3: scan exactly `slots_used` entries, like the SDK iterator
    // (`pam_layout_ok` guarantees `slots_used ≤ capacity`, so they fit).
    // Per entry only the tombstone byte, the market key, the first symbol byte
    // and the asset id are read; the full symbol and the final price only for
    // an entry whose first byte is a major's (review TR-11 / U-63: ≈ 156 CU
    // per entry before, over the 150k budget at 1024 entries). All reads are
    // inside the fixed-size entry, so none of them can fail.
    let mut live: u32 = 0;
    for i in 0..su {
        let Some(ent) = pam_entry_offset(p, i).and_then(|e| array_ref::<{ paml::ENTRY_LEN }>(p, e)) else {
            return Ok(Down(PAM_ENTRY));
        };
        match read_u8(ent, paml::E_IS_TOMBSTONED) {
            Some(0) => {}
            Some(1) => continue, // tombstoned: no entry
            _ => return Ok(Down(PAM_ENTRY)),
        }
        live = live.checked_add(1).ok_or_else(|| SijkaError::MathOverflow.fail())?;
        if array_ref::<32>(ent, paml::E_MARKET_ACCOUNT).is_none_or(|k| pubkey_eq(k, &ZERO_KEY)) {
            return Ok(Down(PAM_ENTRY));
        }
        let (Some(lo), Some(hi)) = (read_u16(ent, paml::E_ASSET_ID_LO), read_u16(ent, paml::E_ASSET_ID_HI)) else {
            return Ok(Down(PAM_ENTRY));
        };
        let Some(hi) = u32::from(hi).checked_shl(16) else {
            return Ok(Down(PAM_ENTRY));
        };
        let aid = u32::from(lo) | hi;
        let first = read_u8(ent, paml::E_SYMBOL);
        for m in majors.iter_mut() {
            if first == Some(m.symbol[0]) && array_ref::<16>(ent, paml::E_SYMBOL) == Some(&m.symbol) {
                let Some(finalized) = read_u64(ent, paml::E_FINALIZED_MARK_PRICE) else {
                    return Ok(Down(PAM_ENTRY));
                };
                m.hits = m.hits.saturating_add(1);
                m.asset_id = aid;
                m.finalized = finalized;
            }
            if m.seen && aid == m.remembered {
                m.ref_alive = true;
            }
        }
    }
    det.live = live;
    // P4a: completeness of the scan (the only in-program check that no live
    // entry lies beyond `slots_used`). P4b: header counters agree.
    if live != u32::from(num) {
        return Ok(Down(PAM_COUNT));
    }
    if su.checked_sub(tomb) != Some(u32::from(num)) {
        return Ok(Down(PAM_SLOTS));
    }

    // ---- M: SOL, BTC, ETH (DECISIONS §17).
    det.reached_majors = true;
    let mut first_unknown: Option<u8> = None;
    for (m, remembered) in majors.iter().zip(det.memory.asset_ids.iter_mut()) {
        let unknown = if m.hits > 1 {
            Some(MAJOR_DUPLICATE)
        } else if m.hits == 1 {
            // Found by symbol: remember it; closed = final settlement price set.
            det.memory.seen |= m.bit;
            *remembered = m.asset_id;
            if m.finalized == 0 {
                det.majors_open |= m.bit;
            } else {
                det.majors_closed |= m.bit;
            }
            None
        } else if !m.seen {
            Some(MAJOR_NEVER_SEEN)
        } else if m.ref_alive {
            // Same asset_id alive under another symbol: renamed, not deleted.
            Some(MAJOR_RENAMED)
        } else {
            // Deleted after it was seen (a deleted market does not keep its asset_id).
            det.majors_closed |= m.bit;
            None
        };
        if let Some(r) = unknown {
            det.majors_unknown |= m.bit;
            first_unknown = first_unknown.or(Some(r));
        }
    }
    if det.majors_open != 0 {
        return Ok(Verdict::Up);
    }
    if let Some(r) = first_unknown {
        return Ok(Unknown(r));
    }
    Ok(Down(MAJORS_CLOSED))
}

/// Flags produced by [`apply_observation`] for `SJKEVVOB.flags`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ObservationOutcome {
    /// bit1: a DOWN streak started with this observation.
    pub streak_restarted: bool,
    /// bit2: a running countdown was reset (UP / UNKNOWN, or a DOWN, FORMAT
    /// included, after a gap longer than `MAX_VENUE_OBS_GAP_SECS`).
    pub reset: bool,
}

/// `apply_observation(cfg, v, now, slot)` (SPEC §5.6.2): update the countdown,
/// last verdict / reason, observation time / slot / count (checked) and the
/// majors memory; writes `Config@1401..1456` only.
pub fn apply_observation(
    cfg: &mut ConfigMut<'_>,
    v: &Verdict,
    details: &VerdictDetails,
    now: i64,
    slot: u64,
) -> Result<ObservationOutcome, ProgramError> {
    let (down_since, last_down, count) = {
        let c = cfg.view();
        (c.venue_down_since_ts(), c.venue_last_down_obs_ts(), c.venue_obs_count())
    };
    let count = count.checked_add(1).ok_or_else(|| SijkaError::MathOverflow.fail())?;
    let mut out = ObservationOutcome::default();
    if v.is_down() {
        // A negative clock step continues the streak (saturating_sub).
        let restarted = down_since == 0 || now.saturating_sub(last_down) > MAX_VENUE_OBS_GAP_SECS;
        if restarted {
            cfg.set_venue_down_since_ts(now);
            out.streak_restarted = true;
            out.reset = down_since != 0;
        }
        cfg.set_venue_last_down_obs_ts(now);
    } else {
        // UP and UNKNOWN (transient / symbol reasons only since SPEC v4) both
        // reset (DECISIONS §17, O-18, §23 item 5).
        out.reset = down_since != 0;
        cfg.set_venue_down_since_ts(0);
        cfg.set_venue_last_down_obs_ts(0);
    }
    cfg.set_venue_last_verdict(v.kind());
    cfg.set_venue_last_reason(v.reason());
    cfg.set_last_venue_obs_ts(now);
    cfg.set_last_venue_obs_slot(slot);
    cfg.set_venue_obs_count(count);
    if details.reached_majors {
        cfg.set_venue_major_seen(details.memory.seen);
        for (k, aid) in details.memory.asset_ids.iter().enumerate() {
            if !cfg.set_venue_major_asset_id_at(k, *aid) {
                return Err(SijkaError::InvariantViolated.fail());
            }
        }
    }
    Ok(out)
}

/// `recovery_ready(cfg, v, now)` (SPEC §5.6.2): `v` is DOWN (FORMAT reasons
/// included, SPEC v4), `venue_down_since_ts ≠ 0` and
/// `now − down_since ≥ RECOVERY_DOWN_SECS`.
/// Call after [`apply_observation`] with the same `v` and `now`.
pub fn recovery_ready(cfg: &Config<'_>, v: &Verdict, now: i64) -> bool {
    let ds = cfg.venue_down_since_ts();
    v.is_down() && ds != 0 && now.saturating_sub(ds) >= RECOVERY_DOWN_SECS
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::constants::{DISC_CONFIG, PAM_ENTRY, PAM_HEADER};
    use crate::state::config::CONFIG_LEN;

    pub const PHUSD: Pubkey = [0x50; 32];
    pub const PAM_KEY: Pubkey = [0x51; 32];
    /// Live mainnet values (SPEC Review log "Recovery").
    pub const LIVE_STATUS: u8 = 0b1000_0011;
    pub const LIVE_ACK: u64 = 246_464_040;

    pub fn prog_bytes() -> Vec<u8> {
        let mut d = vec![0u8; 36];
        d[0..4].copy_from_slice(&2u32.to_le_bytes());
        d[4..36].copy_from_slice(&PHOENIX_PROGRAM_DATA);
        d
    }

    pub fn pd_bytes() -> Vec<u8> {
        let mut d = vec![0u8; 64];
        d[0..4].copy_from_slice(&3u32.to_le_bytes());
        d[12] = 1;
        d[13..45].copy_from_slice(&[0x77; 32]);
        d
    }

    /// 2560-byte GlobalConfig like the live one.
    pub fn gc_bytes(status: u8, ack: u64) -> Vec<u8> {
        let mut d = vec![0u8; 2560];
        d[0..8].copy_from_slice(&DISC_GLOBAL_CONFIG);
        d[8..40].copy_from_slice(&PHOENIX_GLOBAL_CONFIG);
        d[40..296].copy_from_slice(&[0x33; 256]);
        d[296..328].copy_from_slice(&PHUSD);
        d[328..360].copy_from_slice(&[0x41; 32]);
        d[360..392].copy_from_slice(&PAM_KEY);
        d[392..424].copy_from_slice(&[0x42; 32]);
        d[424..456].copy_from_slice(&[0x43; 32]);
        d[472..504].copy_from_slice(&[0x44; 32]);
        d[504] = status;
        d[505] = 6;
        d[508] = 6; // live quirk: SDK padding holds 0x06 (U-60)
        d[1096..1104].copy_from_slice(&ack.to_le_bytes());
        d
    }

    #[derive(Clone, Copy)]
    pub struct Ent {
        pub symbol: &'static str,
        pub asset_id: u32,
        pub finalized: u64,
        pub tombstoned: u8,
    }

    pub const fn ent(symbol: &'static str, asset_id: u32) -> Ent {
        Ent { symbol, asset_id, finalized: 0, tombstoned: 0 }
    }

    /// PAM with `cap` slots, entries in slots `0..ents.len()`; header counters
    /// consistent with the entries.
    pub fn pam_bytes(cap: u64, ents: &[Ent]) -> Vec<u8> {
        let mut d = vec![0u8; PAM_HEADER + cap as usize * PAM_ENTRY];
        d[0..8].copy_from_slice(&DISC_PAM);
        let tomb = ents.iter().filter(|e| e.tombstoned != 0).count() as u32;
        let live = ents.len() as u32 - tomb;
        d[24..26].copy_from_slice(&(live as u16).to_le_bytes());
        d[32..36].copy_from_slice(&(ents.len() as u32).to_le_bytes());
        d[36..40].copy_from_slice(&tomb.to_le_bytes());
        d[40..48].copy_from_slice(&cap.to_le_bytes());
        for (i, x) in ents.iter().enumerate() {
            let e = PAM_HEADER + i * PAM_ENTRY;
            d[e..e + x.symbol.len()].copy_from_slice(x.symbol.as_bytes());
            d[e + 32..e + 40].copy_from_slice(&7u64.to_le_bytes());
            d[e + 40..e + 48].copy_from_slice(&12_000u64.to_le_bytes());
            d[e + 920] = 0xB0;
            d[e + 921..e + 925].copy_from_slice(&(i as u32).to_le_bytes());
            d[e + 952..e + 960].copy_from_slice(&100u64.to_le_bytes());
            d[e + 960..e + 962].copy_from_slice(&((x.asset_id & 0xFFFF) as u16).to_le_bytes());
            d[e + 964..e + 966].copy_from_slice(&((x.asset_id >> 16) as u16).to_le_bytes());
            d[e + 1456..e + 1464].copy_from_slice(&x.finalized.to_le_bytes());
            d[e + 1464..e + 1466].copy_from_slice(&(i as u16).to_le_bytes());
            d[e + 1466] = x.tombstoned;
        }
        d
    }

    /// Live-like PAM: SOL / BTC / ETH in slots 0 / 1 / 2 plus fillers.
    pub fn live_pam(cap: u64, fillers: usize) -> Vec<u8> {
        let names = ["DOGE", "XRP", "SUI", "HYPE", "TON", "BNB", "AVAX", "LINK"];
        let mut ents = vec![ent("SOL", 0), ent("BTC", 1), ent("ETH", 2)];
        for i in 0..fillers {
            ents.push(ent(names[i % names.len()], 3 + i as u32));
        }
        pam_bytes(cap, &ents)
    }

    pub const SEEN_ALL: MajorMemory = MajorMemory { seen: 0b111, asset_ids: [0, 1, 2] };

    pub struct Fixture {
        pub prog_owner: Pubkey,
        pub prog: Vec<u8>,
        pub pd_owner: Pubkey,
        pub pd: Vec<u8>,
        pub gc_owner: Pubkey,
        pub gc: Vec<u8>,
        pub pam_key: Pubkey,
        pub pam_owner: Pubkey,
        pub pam: Vec<u8>,
        pub lrs: u64,
        pub memory: MajorMemory,
    }

    impl Fixture {
        pub fn live() -> Self {
            Self {
                prog_owner: BPF_LOADER_UPGRADEABLE_ID,
                prog: prog_bytes(),
                pd_owner: BPF_LOADER_UPGRADEABLE_ID,
                pd: pd_bytes(),
                gc_owner: PHOENIX_PROGRAM_ID,
                gc: gc_bytes(LIVE_STATUS, LIVE_ACK),
                pam_key: PAM_KEY,
                pam_owner: PHOENIX_PROGRAM_ID,
                pam: live_pam(8, 3),
                lrs: LIVE_ACK,
                memory: SEEN_ALL,
            }
        }

        pub fn run(&self) -> Result<(Verdict, VerdictDetails), ProgramError> {
            let prog = AccountView { key: &PHOENIX_PROGRAM_ID, owner: &self.prog_owner, data: &self.prog };
            let pd = AccountView { key: &PHOENIX_PROGRAM_DATA, owner: &self.pd_owner, data: &self.pd };
            let gc = AccountView { key: &PHOENIX_GLOBAL_CONFIG, owner: &self.gc_owner, data: &self.gc };
            let pam = AccountView { key: &self.pam_key, owner: &self.pam_owner, data: &self.pam };
            venue_verdict(&prog, &pd, &gc, &pam, self.lrs, &self.memory, &PHUSD)
        }

        pub fn verdict(&self) -> Verdict {
            self.run().expect("verdict").0
        }
    }

    fn set_status(f: &mut Fixture, s: u8) {
        f.gc[504] = s;
    }

    #[test]
    fn live_snapshot_is_up() {
        let f = Fixture::live();
        let (v, d) = f.run().unwrap();
        assert_eq!(v, Verdict::Up);
        assert_eq!(d.live, 6);
        assert_eq!(d.exchange_status, LIVE_STATUS);
        assert_eq!(d.ack, LIVE_ACK);
        assert_eq!(d.lrs, LIVE_ACK);
        assert_eq!((d.majors_open, d.majors_closed, d.majors_unknown), (0b111, 0, 0));
        assert!(d.reached_majors);
        assert!(!d.program_signal_off);
        assert_eq!(d.memory, SEEN_ALL);
        // First observation after launch: nothing remembered yet, all three found.
        let mut f = Fixture::live();
        f.memory = MajorMemory::default();
        let (v, d) = f.run().unwrap();
        assert_eq!(v, Verdict::Up);
        assert_eq!(d.memory, SEEN_ALL);
    }

    #[test]
    fn x1_program_closed_is_down_regardless_of_gc_and_pam() {
        let mut f = Fixture::live();
        f.pd_owner = SYSTEM_PROGRAM_ID;
        f.pd = vec![];
        assert_eq!(f.verdict(), Verdict::Down(reason::PROGRAM_CLOSED));
        // PAM is not compared with GC (no griefing possible: DOWN does not depend on it).
        f.pam_key = [9; 32];
        f.pam_owner = SYSTEM_PROGRAM_ID;
        f.gc = vec![1, 2, 3];
        let (v, d) = f.run().unwrap();
        assert_eq!(v, Verdict::Down(reason::PROGRAM_CLOSED));
        assert!(!d.program_signal_off);
        assert!(!d.reached_majors);
    }

    #[test]
    fn x1_other_states_only_switch_the_signal_off() {
        // Program under another loader (loader-v4 migration) and ProgramData gone.
        let mut f = Fixture::live();
        f.prog_owner = [0x44; 32];
        f.pd_owner = SYSTEM_PROGRAM_ID;
        f.pd = vec![];
        let (v, d) = f.run().unwrap();
        assert_eq!(v, Verdict::Up);
        assert!(d.program_signal_off);
        // Same, and the exchange suspended: the GC signal still works.
        set_status(&mut f, 0x80);
        assert_eq!(f.verdict(), Verdict::Down(reason::EXCH_SUSPENDED));
        // Mutations of the program account: never DOWN(PROGRAM_CLOSED).
        for mutate in 0..5 {
            let mut f = Fixture::live();
            f.pd_owner = SYSTEM_PROGRAM_ID;
            f.pd = vec![];
            match mutate {
                0 => f.prog.push(0),
                1 => f.prog[0] = 3,
                2 => f.prog[4] ^= 1,
                3 => f.prog_owner = SYSTEM_PROGRAM_ID,
                _ => f.prog.truncate(35),
            }
            let (v, d) = f.run().unwrap();
            assert_eq!(v, Verdict::Up, "mutation {mutate}");
            assert!(d.program_signal_off);
        }
        // ProgramData in an unrecognized form: signal off, verdict by GC/PAM.
        for mutate in 0..4 {
            let mut f = Fixture::live();
            match mutate {
                0 => f.pd[0] = 1,
                1 => f.pd.truncate(44),
                2 => f.pd_owner = [0x45; 32],
                _ => f.pd_owner = SYSTEM_PROGRAM_ID, // owner System but with data
            }
            let (v, d) = f.run().unwrap();
            assert_eq!(v, Verdict::Up, "pd mutation {mutate}");
            assert!(d.program_signal_off);
        }
    }

    #[test]
    fn gc_steps_g1_to_g6() {
        let mut f = Fixture::live();
        f.gc_owner = SYSTEM_PROGRAM_ID;
        f.gc = vec![];
        assert_eq!(f.verdict(), Verdict::Down(reason::GC_ABSENT));
        // Owner System with data is not "absent".
        let mut f = Fixture::live();
        f.gc_owner = SYSTEM_PROGRAM_ID;
        assert_eq!(f.verdict(), Verdict::Down(reason::GC_OWNER));
        let mut f = Fixture::live();
        f.gc_owner = [0x66; 32];
        assert_eq!(f.verdict(), Verdict::Down(reason::GC_OWNER));
        let mut f = Fixture::live();
        f.gc.truncate(GC_PREFIX_LEN - 1);
        let (v, d) = f.run().unwrap();
        assert_eq!(v, Verdict::Down(reason::GC_SHORT));
        assert_eq!(d.exchange_status, 0);
        // Exactly the prefix is enough.
        let mut f = Fixture::live();
        f.gc.truncate(GC_PREFIX_LEN);
        assert_eq!(f.verdict(), Verdict::Up);
        let mut f = Fixture::live();
        f.gc[3] ^= 1;
        let (v, d) = f.run().unwrap();
        assert_eq!(v, Verdict::Down(reason::GC_DISC));
        assert_eq!(d.exchange_status, LIVE_STATUS);
        for off in [8usize, 39, 296, 327, 505] {
            let mut f = Fixture::live();
            f.gc[off] ^= 1;
            assert_eq!(f.verdict(), Verdict::Down(reason::GC_ANCHOR), "anchor @{off}");
        }
        for s in [0x88u8, 0x90, 0xA0, 0xC0, 0x03, 0x01, 0xF9] {
            let mut f = Fixture::live();
            set_status(&mut f, s);
            assert_eq!(f.verdict(), Verdict::Down(reason::GC_STATUS_BITS), "status {s:#x}");
        }
        // The gated bit is defined and does not matter.
        let mut f = Fixture::live();
        set_status(&mut f, 0x81);
        assert_eq!(f.verdict(), Verdict::Up);
    }

    #[test]
    fn g7_pam_key_is_checked_only_when_gc_is_recognized() {
        let mut f = Fixture::live();
        f.pam_key = [0x52; 32];
        assert_eq!(f.run(), Err(SijkaError::InvalidPerpAssetMap.into()));
        // Unrecognized GC: the PAM is not read, any key is accepted.
        f.gc[3] ^= 1;
        assert_eq!(f.verdict(), Verdict::Down(reason::GC_DISC));
        let mut f = Fixture::live();
        f.pam_key = [0x52; 32];
        f.gc_owner = SYSTEM_PROGRAM_ID;
        f.gc = vec![];
        assert_eq!(f.verdict(), Verdict::Down(reason::GC_ABSENT));
    }

    #[test]
    fn g8_exchange_signal_needs_no_pam() {
        let mut f = Fixture::live();
        f.pam_owner = SYSTEM_PROGRAM_ID;
        f.pam = vec![];
        set_status(&mut f, 0x80);
        assert_eq!(f.verdict(), Verdict::Down(reason::EXCH_SUSPENDED));
        set_status(&mut f, 0x84);
        assert_eq!(f.verdict(), Verdict::Down(reason::EXCH_SUSPENDED));
        set_status(&mut f, 0x85);
        assert_eq!(f.verdict(), Verdict::Down(reason::EXCH_MAINTENANCE));
        set_status(&mut f, 0x87);
        assert_eq!(f.verdict(), Verdict::Down(reason::EXCH_MAINTENANCE));
        set_status(&mut f, 0x83);
        assert_eq!(f.verdict(), Verdict::Down(reason::PAM_OWNER));
    }

    #[test]
    fn g9_restart_interlock() {
        let mut f = Fixture::live();
        // Unacknowledged restart: not a verdict (U-62 refuted); the PAM decides.
        f.lrs = LIVE_ACK + 1;
        let (v, d) = f.run().unwrap();
        assert_eq!(v, Verdict::Up);
        assert_eq!((d.ack, d.lrs), (LIVE_ACK, LIVE_ACK + 1));
        f.lrs = u64::MAX;
        assert_eq!(f.verdict(), Verdict::Up);
        // ... and with all majors closed the verdict is still MAJORS_CLOSED.
        let mut g = Fixture::live();
        g.lrs = LIVE_ACK + 1;
        g.pam = pam_bytes(8, &[closed(ent("SOL", 0)), closed(ent("BTC", 1)), closed(ent("ETH", 2))]);
        assert_eq!(g.verdict(), Verdict::Down(reason::MAJORS_CLOSED));
        f.lrs = LIVE_ACK - 1;
        assert_eq!(f.verdict(), Verdict::Unknown(reason::GC_RESTART_ANOMALY));
        f.lrs = 0; // LiteSVM default
        assert_eq!(f.verdict(), Verdict::Unknown(reason::GC_RESTART_ANOMALY));
        // ack == 0: interlock off.
        let mut f = Fixture::live();
        f.gc[1096..1104].copy_from_slice(&0u64.to_le_bytes());
        f.lrs = 5;
        assert_eq!(f.verdict(), Verdict::Up);
    }

    #[test]
    fn pam_layout_steps() {
        let mut f = Fixture::live();
        f.pam_owner = [0x66; 32];
        assert_eq!(f.verdict(), Verdict::Down(reason::PAM_OWNER));
        let mut f = Fixture::live();
        f.pam[0] ^= 1;
        assert_eq!(f.verdict(), Verdict::Down(reason::PAM_LAYOUT));
        let mut f = Fixture::live();
        f.pam.push(0);
        assert_eq!(f.verdict(), Verdict::Down(reason::PAM_LAYOUT));
        let mut f = Fixture::live();
        f.pam.truncate(40);
        assert_eq!(f.verdict(), Verdict::Down(reason::PAM_LAYOUT));
        let mut f = Fixture::live();
        f.pam[32..36].copy_from_slice(&9u32.to_le_bytes()); // slots_used > capacity
        assert_eq!(f.verdict(), Verdict::Down(reason::PAM_LAYOUT));
        // A larger capacity with a matching length is fine.
        let mut f = Fixture::live();
        f.pam = live_pam(32, 3);
        assert_eq!(f.verdict(), Verdict::Up);
    }

    #[test]
    fn pam_entries_and_counters() {
        // Tombstone byte other than 0/1.
        let mut f = Fixture::live();
        f.pam[PAM_HEADER + 3 * PAM_ENTRY + 1466] = 2;
        assert_eq!(f.verdict(), Verdict::Down(reason::PAM_ENTRY));
        // Live entry without a market account.
        let mut f = Fixture::live();
        let e = PAM_HEADER + 4 * PAM_ENTRY + 920;
        f.pam[e..e + 32].fill(0);
        assert_eq!(f.verdict(), Verdict::Down(reason::PAM_ENTRY));
        // A tombstoned entry may be empty.
        let mut ents = vec![ent("SOL", 0), ent("BTC", 1), ent("ETH", 2), ent("TON", 23)];
        ents[3].tombstoned = 1;
        let mut f = Fixture::live();
        f.pam = pam_bytes(8, &ents);
        let e = PAM_HEADER + 3 * PAM_ENTRY + 920;
        f.pam[e..e + 32].fill(0);
        let (v, d) = f.run().unwrap();
        assert_eq!(v, Verdict::Up);
        assert_eq!(d.live, 3);
        // P4a: num_assets does not match the live entries.
        let mut f = Fixture::live();
        f.pam[24..26].copy_from_slice(&7u16.to_le_bytes());
        let (v, d) = f.run().unwrap();
        assert_eq!(v, Verdict::Down(reason::PAM_COUNT));
        assert_eq!((d.live, d.reached_majors), (6, false));
        // P4a: a live SOL beyond slots_used, counted by num_assets (BTC, ETH closed).
        let mut f = Fixture::live();
        f.pam = pam_bytes(8, &[closed(ent("BTC", 1)), closed(ent("ETH", 2)), ent("SOL", 0)]);
        f.pam[32..36].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(f.verdict(), Verdict::Down(reason::PAM_COUNT), "not DOWN(MAJORS_CLOSED)");
        // P4b: slots_used − tombstones ≠ num_assets while live == num_assets.
        let mut f = Fixture::live();
        f.pam = pam_bytes(8, &ents);
        f.pam[36..40].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(f.verdict(), Verdict::Down(reason::PAM_SLOTS));
    }

    fn closed(mut e: Ent) -> Ent {
        e.finalized = 11_900;
        e
    }

    #[test]
    fn majors_rules() {
        let run = |ents: &[Ent], memory: MajorMemory| {
            let mut f = Fixture::live();
            f.pam = pam_bytes(8, ents);
            f.memory = memory;
            f.run().unwrap()
        };
        let (sol, btc, eth, doge) = (ent("SOL", 0), ent("BTC", 1), ent("ETH", 2), ent("DOGE", 3));
        // Renamed SOL with the same asset_id while BTC/ETH are open: still UP.
        let (v, _) = run(&[ent("SOL-PERP", 0), btc, eth], SEEN_ALL);
        assert_eq!(v, Verdict::Up);
        // Renamed SOL, BTC and ETH closed: UNKNOWN, not DOWN.
        let (v, d) = run(&[ent("SOL-PERP", 0), closed(btc), closed(eth)], SEEN_ALL);
        assert_eq!(v, Verdict::Unknown(reason::MAJOR_RENAMED));
        assert_eq!((d.majors_open, d.majors_closed, d.majors_unknown), (0, 0b110, 0b001));
        // Duplicate live SOL.
        let (v, _) = run(&[sol, ent("SOL", 9), closed(btc), closed(eth)], SEEN_ALL);
        assert_eq!(v, Verdict::Unknown(reason::MAJOR_DUPLICATE));
        let (v, _) = run(&[sol, ent("SOL", 9), btc, eth], SEEN_ALL);
        assert_eq!(v, Verdict::Up);
        // Only SOL deleted: UP.
        let (v, d) = run(&[btc, eth, doge], SEEN_ALL);
        assert_eq!(v, Verdict::Up);
        assert_eq!(d.majors_closed, 0b001);
        // All three missing and never seen.
        let (v, d) = run(&[doge], MajorMemory::default());
        assert_eq!(v, Verdict::Unknown(reason::MAJOR_NEVER_SEEN));
        assert_eq!(d.majors_unknown, 0b111);
        assert_eq!(d.memory, MajorMemory::default());
        // SOL moved to a new asset_id with the same symbol: UP, memory updated.
        let (v, d) = run(&[ent("SOL", 0x0001_0017), btc, eth], SEEN_ALL);
        assert_eq!(v, Verdict::Up);
        assert_eq!(d.memory.asset_ids, [0x0001_0017, 1, 2]);
        // All closed by final settlement price, or deleted after being seen.
        let (v, d) = run(&[closed(sol), closed(btc), closed(eth), doge], SEEN_ALL);
        assert_eq!(v, Verdict::Down(reason::MAJORS_CLOSED));
        assert_eq!((d.majors_open, d.majors_closed, d.majors_unknown), (0, 0b111, 0));
        assert_eq!(d.memory, SEEN_ALL);
        let (v, _) = run(&[doge, ent("XRP", 4)], SEEN_ALL);
        assert_eq!(v, Verdict::Down(reason::MAJORS_CLOSED));
        let (v, _) = run(&[closed(sol), doge], SEEN_ALL);
        assert_eq!(v, Verdict::Down(reason::MAJORS_CLOSED));
        // Deleted, and a new market reuses the slot with a new generation: still closed.
        let (v, _) = run(&[ent("SNDK", 0x0001_0000), closed(btc), closed(eth)], SEEN_ALL);
        assert_eq!(v, Verdict::Down(reason::MAJORS_CLOSED));
        // A tombstoned SOL entry does not count as live.
        let mut t = sol;
        t.tombstoned = 1;
        let (v, _) = run(&[t, closed(btc), closed(eth)], SEEN_ALL);
        assert_eq!(v, Verdict::Down(reason::MAJORS_CLOSED));
        // Reason of the first unknown major.
        let (v, _) =
            run(&[ent("ETH", 2), ent("ETH", 2), ent("SOL-X", 0)], MajorMemory { seen: 0b001, asset_ids: [0; 3] });
        assert_eq!(v, Verdict::Unknown(reason::MAJOR_RENAMED));
        // Symbols are compared on all 16 bytes.
        let mut f = Fixture::live();
        f.pam = pam_bytes(8, &[ent("SOL", 0), closed(btc), closed(eth)]);
        f.pam[PAM_HEADER + 15] = b'X';
        assert_eq!(f.verdict(), Verdict::Unknown(reason::MAJOR_RENAMED));
    }

    /// Deterministic byte mutations of GC and PAM (TR-10 on the host): a DOWN
    /// verdict only ever comes with its literal condition (INV-8) or with a
    /// FORMAT reason (DECISIONS §23 item 5), and a FORMAT verdict never writes
    /// the majors memory; every UNKNOWN is a transient / symbol reason.
    #[test]
    fn mutations_give_down_only_by_condition_or_format() {
        let mut seed: u64 = 0x5EED_1234_ABCD_0001;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let base = Fixture::live();
        let pam_hot: Vec<usize> = (0..48)
            .chain((0..6).flat_map(|i| {
                let e = PAM_HEADER + i * PAM_ENTRY;
                [e, e + 1, e + 2, e + 15, e + 920, e + 960, e + 961, e + 964, e + 1456, e + 1463, e + 1466]
            }))
            .collect();
        let mut formats = 0u32;
        for round in 0..4000 {
            let mut f = Fixture::live();
            let n = 1 + (next() % 3) as usize;
            for _ in 0..n {
                if next() % 2 == 0 {
                    let off = (next() % GC_PREFIX_LEN as u64) as usize;
                    f.gc[off] ^= 1u8 << (next() % 8);
                } else {
                    let off = pam_hot[(next() % pam_hot.len() as u64) as usize];
                    f.pam[off] = next() as u8;
                }
            }
            let Ok((v, d)) = f.run() else { continue };
            let s = f.gc[504];
            match v {
                Verdict::Down(reason::EXCH_SUSPENDED) => assert!(s & 0x81 == 0x80 && s & 0x78 == 0, "round {round}"),
                Verdict::Down(reason::EXCH_MAINTENANCE) => assert!(s & 0x85 == 0x85 && s & 0x78 == 0, "round {round}"),
                Verdict::Down(reason::MAJORS_CLOSED) => {
                    assert_eq!(d.majors_closed, 0b111, "round {round}");
                    assert_eq!(d.live, u32::from(u16::from_le_bytes(f.pam[24..26].try_into().unwrap())));
                }
                Verdict::Down(r) if reason::is_format(r) => {
                    assert!(!d.reached_majors, "round {round}: FORMAT({r}) reached the majors");
                    formats += 1;
                }
                Verdict::Down(r) => panic!("round {round}: unexpected DOWN({r})"),
                Verdict::Unknown(r) => {
                    assert!(matches!(r, 21 | 36..=38), "round {round}: UNKNOWN({r}) is a FORMAT reason");
                }
                Verdict::Up => {}
            }
        }
        assert!(formats > 100, "the mutations reach FORMAT verdicts ({formats})");
        assert_eq!(base.verdict(), Verdict::Up);
    }

    /// DECISIONS §23 item 5 (variant A): the FORMAT set is exactly the GC /
    /// PAM recognition reasons; the transient and symbol reasons are not in it.
    #[test]
    fn format_reason_set() {
        let format: Vec<u8> = (0..=255u8).filter(|r| reason::is_format(*r)).collect();
        assert_eq!(format, vec![16, 17, 18, 19, 20, 32, 33, 34, 35, 39]);
        for r in [reason::GC_RESTART_ANOMALY, reason::MAJOR_DUPLICATE, reason::MAJOR_NEVER_SEEN, reason::MAJOR_RENAMED]
        {
            assert!(!reason::is_format(r));
        }
        for r in 1..=6u8 {
            assert!(!reason::is_format(r), "literal DOWN {r}");
        }
    }

    /// Parity with the SDK decoders (`phoenix_rise::accounts`) on full-size
    /// synthetic accounts (capacity 1024, as live).
    #[test]
    fn sdk_parity_on_full_size_accounts() {
        use phoenix_rise::accounts::global_config::{GlobalConfig, LastRestartSlot};
        use phoenix_rise::accounts::perp_asset_map::PerpAssetMap;

        let mut f = Fixture::live();
        f.pam = live_pam(1024, 87);
        let (v, d) = f.run().unwrap();
        assert_eq!(v, Verdict::Up);
        assert_eq!(d.live, 90);

        let g = GlobalConfig::try_from_account_bytes(&f.gc).unwrap();
        assert_eq!(g.account_key(), PHOENIX_GLOBAL_CONFIG);
        assert_eq!(g.canonical_token_mint_key(), PHUSD);
        assert_eq!(g.perp_asset_map_key(), PAM_KEY);
        assert_eq!(g.exchange_status(), LIVE_STATUS);
        assert_eq!(g.quote_decimals(), 6);
        assert_eq!(g.acknowledged_restart_slot(), LIVE_ACK);
        assert_eq!(g.global_vault_key(), [0x41; 32]);
        assert_eq!(g.withdraw_queue_key(), [0x44; 32]);

        // Exchange activity: our DOWN (G8) ⇔ SDK inactive, for recognized
        // statuses. The one intended divergence: an unacknowledged restart is
        // inactive for the SDK model but not DOWN for us (U-62 refuted: the
        // mainnet binary does not enforce the interlock).
        for s in [0x80u8, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87] {
            for (ack, lrs) in [(LIVE_ACK, LIVE_ACK), (LIVE_ACK, LIVE_ACK + 1), (0, 9)] {
                let mut f = Fixture::live();
                set_status(&mut f, s);
                f.gc[1096..1104].copy_from_slice(&ack.to_le_bytes());
                f.lrs = lrs;
                let g = GlobalConfig::try_from_account_bytes(&f.gc).unwrap();
                let sdk_active = g.is_exchange_active(LastRestartSlot::Known(lrs));
                let sdk_bits_active = g.is_exchange_active(LastRestartSlot::Known(ack));
                assert_eq!(!f.verdict().is_down(), sdk_bits_active, "status {s:#x} ack {ack} lrs {lrs}");
                if ack != 0 && ack < lrs {
                    assert!(!sdk_active, "SDK models the interlock: status {s:#x}");
                }
            }
        }

        let m = PerpAssetMap::try_from_account_bytes(&f.pam).unwrap();
        assert_eq!(m.num_assets(), 90);
        assert_eq!(m.slots_used(), 90);
        assert_eq!(m.capacity(), 1024);
        let mut n = 0;
        for (i, e) in m.iter().enumerate() {
            let e = e.unwrap();
            let ours = crate::external::phoenix_accounts::pam_entry(&f.pam, i as u32).unwrap();
            assert_eq!(e.metadata.static_market_params().asset_id(), ours.asset_id);
            assert_eq!(e.metadata.static_market_params().market_account, ours.market_account);
            assert_eq!(e.metadata.finalized_mark_price().as_inner(), ours.finalized_mark_price);
            assert_eq!(e.metadata.map_index(), i as u16);
            n += 1;
        }
        assert_eq!(n, 90);
        for (k, sym) in ["SOL", "BTC", "ETH"].iter().enumerate() {
            let e = m.find_by_symbol(sym).unwrap().unwrap();
            assert_eq!(e.metadata.static_market_params().asset_id(), k as u32);
        }
        // Tombstones are skipped by both.
        let mut ents = vec![ent("SOL", 0), ent("BTC", 1), ent("ETH", 2), ent("TON", 23)];
        ents[3].tombstoned = 1;
        let mut f = Fixture::live();
        f.pam = pam_bytes(1024, &ents);
        let m = PerpAssetMap::try_from_account_bytes(&f.pam).unwrap();
        assert_eq!(m.iter().count() as u32, f.run().unwrap().1.live);
    }

    fn cfg_buf() -> Vec<u8> {
        let mut buf = vec![0u8; CONFIG_LEN];
        let mut m = ConfigMut::new(&mut buf).unwrap();
        m.set_discriminator(&DISC_CONFIG);
        m.set_version(1);
        buf
    }

    fn observe(buf: &mut [u8], v: Verdict, now: i64) -> ObservationOutcome {
        let mut m = ConfigMut::new(buf).unwrap();
        let det = VerdictDetails::default();
        apply_observation(&mut m, &v, &det, now, now as u64).unwrap()
    }

    fn down_since(buf: &[u8]) -> i64 {
        Config::new(buf).unwrap().venue_down_since_ts()
    }

    fn ready(buf: &[u8], v: Verdict, now: i64) -> bool {
        recovery_ready(&Config::new(buf).unwrap(), &v, now)
    }

    const DOWN: Verdict = Verdict::Down(reason::EXCH_MAINTENANCE);

    #[test]
    fn countdown_gap_and_reset() {
        let t0 = 1_800_000_000i64;
        let mut b = cfg_buf();
        let o = observe(&mut b, DOWN, t0);
        assert_eq!(o, ObservationOutcome { streak_restarted: true, reset: false });
        assert_eq!(down_since(&b), t0);
        // Gap of exactly 3600 s continues the streak; 3601 restarts it.
        let o = observe(&mut b, DOWN, t0 + 3600);
        assert_eq!(o, ObservationOutcome::default());
        assert_eq!(down_since(&b), t0);
        let o = observe(&mut b, DOWN, t0 + 7201);
        assert_eq!(o, ObservationOutcome { streak_restarted: true, reset: true });
        assert_eq!(down_since(&b), t0 + 7201);
        // A clock step backwards continues.
        observe(&mut b, DOWN, t0 + 7000);
        assert_eq!(down_since(&b), t0 + 7201);
        assert_eq!(Config::new(&b).unwrap().venue_last_down_obs_ts(), t0 + 7000);
        // UP and UNKNOWN reset.
        let o = observe(&mut b, Verdict::Up, t0 + 7300);
        assert_eq!(o, ObservationOutcome { streak_restarted: false, reset: true });
        assert_eq!(down_since(&b), 0);
        assert_eq!(Config::new(&b).unwrap().venue_last_down_obs_ts(), 0);
        let o = observe(&mut b, Verdict::Up, t0 + 7400);
        assert_eq!(o, ObservationOutcome::default());
        observe(&mut b, DOWN, t0 + 7500);
        // SPEC v4: a FORMAT verdict (PAM layout not recognized) continues the
        // streak; a transient UNKNOWN (restart anomaly) resets it.
        let o = observe(&mut b, Verdict::Down(reason::PAM_LAYOUT), t0 + 7550);
        assert_eq!(o, ObservationOutcome::default());
        assert_eq!(down_since(&b), t0 + 7500);
        let c = Config::new(&b).unwrap();
        assert_eq!((c.venue_last_verdict(), c.venue_last_reason()), (2, reason::PAM_LAYOUT));
        observe(&mut b, Verdict::Unknown(reason::GC_RESTART_ANOMALY), t0 + 7600);
        assert_eq!(down_since(&b), 0);
        let c = Config::new(&b).unwrap();
        assert_eq!(c.venue_last_verdict(), 3);
        assert_eq!(c.venue_last_reason(), reason::GC_RESTART_ANOMALY);
        assert_eq!(c.last_venue_obs_ts(), t0 + 7600);
        assert_eq!(c.venue_obs_count(), 9);
        // A FORMAT verdict after a gap > 3600 s restarts, like any DOWN.
        observe(&mut b, Verdict::Down(reason::GC_DISC), t0 + 8000);
        let o = observe(&mut b, Verdict::Down(reason::GC_DISC), t0 + 11_601);
        assert_eq!(o, ObservationOutcome { streak_restarted: true, reset: true });
        assert_eq!(down_since(&b), t0 + 11_601);
    }

    #[test]
    fn ready_boundary() {
        let t0 = 1_800_000_000i64;
        let mut b = cfg_buf();
        observe(&mut b, DOWN, t0);
        let mut t = t0;
        while t + 3000 < t0 + RECOVERY_DOWN_SECS {
            t += 3000;
            observe(&mut b, DOWN, t);
        }
        assert!(!ready(&b, DOWN, t0 + RECOVERY_DOWN_SECS - 1));
        observe(&mut b, DOWN, t0 + RECOVERY_DOWN_SECS - 1);
        assert!(!ready(&b, DOWN, t0 + RECOVERY_DOWN_SECS - 1));
        observe(&mut b, DOWN, t0 + RECOVERY_DOWN_SECS);
        assert!(ready(&b, DOWN, t0 + RECOVERY_DOWN_SECS));
        // Only for a DOWN verdict; a FORMAT DOWN counts (SPEC v4), a
        // transient / symbol UNKNOWN does not.
        assert!(!ready(&b, Verdict::Up, t0 + RECOVERY_DOWN_SECS));
        assert!(ready(&b, Verdict::Down(reason::GC_DISC), t0 + RECOVERY_DOWN_SECS));
        for r in [reason::GC_RESTART_ANOMALY, reason::MAJOR_DUPLICATE, reason::MAJOR_NEVER_SEEN, reason::MAJOR_RENAMED]
        {
            assert!(!ready(&b, Verdict::Unknown(r), t0 + RECOVERY_DOWN_SECS), "reason {r}");
        }
        // No streak.
        assert!(!ready(&cfg_buf(), DOWN, t0));
    }

    /// TR-9 on the host: DOWN every 59 min for 10 days is ready; a single
    /// 61-min gap or a single UP / transient UNKNOWN in the middle is not; a
    /// FORMAT DOWN in the middle, or FORMAT all the way, is (SPEC v4).
    #[test]
    fn ten_day_scenarios() {
        let t0 = 1_800_000_000i64;
        let step = 59 * 60;
        let run = |interrupt: Option<(i64, Verdict)>, gap_at: Option<i64>| {
            let mut b = cfg_buf();
            let mut t = t0;
            observe(&mut b, DOWN, t);
            while t < t0 + RECOVERY_DOWN_SECS {
                t += step;
                if gap_at.is_some_and(|g| t >= g && t < g + step) {
                    t += 2 * 60; // 61 min since the previous observation
                }
                let v = match interrupt {
                    Some((at, v)) if t >= at && t < at + step => v,
                    _ => DOWN,
                };
                observe(&mut b, v, t);
            }
            ready(&b, DOWN, t)
        };
        assert!(run(None, None));
        assert!(!run(None, Some(t0 + 5 * 86_400)));
        assert!(!run(Some((t0 + 3 * 86_400, Verdict::Up)), None));
        assert!(run(Some((t0 + 9 * 86_400, Verdict::Down(reason::GC_ANCHOR))), None));
        for r in [reason::GC_RESTART_ANOMALY, reason::MAJOR_DUPLICATE, reason::MAJOR_NEVER_SEEN, reason::MAJOR_RENAMED]
        {
            assert!(!run(Some((t0 + 9 * 86_400, Verdict::Unknown(r))), None), "reason {r}");
        }
        // Ten days of an unrecognized format alone (the program reads the
        // format change of a Phoenix upgrade as "not working").
        let mut b = cfg_buf();
        let mut t = t0;
        let fmt = Verdict::Down(reason::PAM_SLOTS);
        observe(&mut b, fmt, t);
        while t < t0 + RECOVERY_DOWN_SECS {
            t += step;
            observe(&mut b, fmt, t);
        }
        assert!(ready(&b, fmt, t));
    }

    #[test]
    fn memory_and_counter_writes() {
        let mut b = cfg_buf();
        {
            let mut m = ConfigMut::new(&mut b).unwrap();
            let det = VerdictDetails {
                reached_majors: true,
                memory: MajorMemory { seen: 0b101, asset_ids: [7, 0, 0x0001_0002] },
                ..VerdictDetails::default()
            };
            apply_observation(&mut m, &Verdict::Up, &det, 10, 20).unwrap();
        }
        let c = Config::new(&b).unwrap();
        assert_eq!(MajorMemory::from_config(&c), MajorMemory { seen: 0b101, asset_ids: [7, 0, 0x0001_0002] });
        assert_eq!(c.last_venue_obs_slot(), 20);
        // Without step M the memory is untouched.
        {
            let mut m = ConfigMut::new(&mut b).unwrap();
            apply_observation(&mut m, &DOWN, &VerdictDetails::default(), 11, 21).unwrap();
        }
        assert_eq!(MajorMemory::from_config(&Config::new(&b).unwrap()).seen, 0b101);
        // Only Config@1401..1456 changes.
        let before = b.clone();
        {
            let mut m = ConfigMut::new(&mut b).unwrap();
            let det = VerdictDetails { reached_majors: true, memory: SEEN_ALL, ..VerdictDetails::default() };
            apply_observation(&mut m, &Verdict::Up, &det, 99, 98).unwrap();
        }
        for (i, (x, y)) in before.iter().zip(b.iter()).enumerate() {
            if x != y {
                assert!((1401..1456).contains(&i), "byte {i} changed");
            }
        }
        // Checked observation counter.
        ConfigMut::new(&mut b).unwrap().set_venue_obs_count(u64::MAX);
        let mut m = ConfigMut::new(&mut b).unwrap();
        assert_eq!(
            apply_observation(&mut m, &Verdict::Up, &VerdictDetails::default(), 1, 1),
            Err(SijkaError::MathOverflow.into())
        );
    }
}
