// Copyright (c) 2026 prt1sn. All rights reserved.
//! `harvest_preview` return data (tag 31, SPEC §5.4.3): 168 bytes,
//! little-endian, magic `SJKRTHPV`, version 1. Pure encoder; the numbers are
//! always filled in, whatever the status.

use crate::util::bytes::{write_bytes, write_i64, write_u8, write_u16, write_u64};

/// Return-data magic.
pub const PREVIEW_MAGIC: [u8; 8] = *b"SJKRTHPV";
/// Return-data version.
pub const PREVIEW_VERSION: u8 = 1;
/// Return-data length.
pub const PREVIEW_LEN: usize = 168;

/// Byte offsets (SPEC §5.4.3 table).
pub mod off {
    pub const MAGIC: usize = 0;
    pub const VERSION: usize = 8;
    pub const STATUS: usize = 9;
    pub const NOW: usize = 16;
    pub const NEXT_ALLOWED_TS: usize = 24;
    pub const I: usize = 32;
    pub const O: usize = 40;
    pub const C_HK: usize = 48;
    pub const C_HDR: usize = 56;
    pub const U: usize = 64;
    pub const F: usize = 72;
    pub const D_STAR: usize = 80;
    pub const W: usize = 88;
    pub const BUF: usize = 96;
    pub const D: usize = 104;
    pub const IM: usize = 112;
    pub const POSITION_COUNT: usize = 120;
    pub const RISK_TIER: usize = 122;
    pub const IS_LIQUIDATABLE: usize = 123;
    pub const BUYBACK_USDC: usize = 128;
    pub const QUEUE_CAP: usize = 136;
    pub const TOTAL_QUEUED: usize = 144;
    pub const COOLDOWN_UNTIL_SLOT: usize = 152;
    pub const STALE_POSITIONS: usize = 160;
    pub const BITS: usize = 162;
}

/// Bits shared by the preview (`bits@162`) and `SJKEVHRV.bits`.
pub mod bits {
    /// `D` was cut by the queue clamp `Q`.
    pub const QUEUE_LIMITED: u8 = 1 << 0;
    /// `timer_held`: this harvest does not move `last_harvest_ts` (review RT-5).
    pub const TIMER_HELD: u8 = 1 << 1;
    /// Hawkeye `position_count > n_scan` (review RT-3): Hawkeye sees markets
    /// (positions or resting orders) the map scan did not. Informational
    /// since SPEC v2: those marks are covered by Hawkeye's own staleness
    /// refusal (U-52).
    pub const PC_ABOVE_SCAN: u8 = 1 << 2;
}

/// Fields of the preview return data (already saturated to their types).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HarvestPreviewData {
    pub status: u8,
    pub now: i64,
    pub next_allowed_ts: i64,
    pub i: u64,
    pub o: u64,
    pub c_hk: i64,
    pub c_hdr: i64,
    pub u: i64,
    pub f: i64,
    pub d_star: i64,
    pub w: i64,
    pub buf: u64,
    pub d: i64,
    pub im: u64,
    pub position_count: u16,
    pub risk_tier: u8,
    pub is_liquidatable: u8,
    pub buyback_usdc: u64,
    pub queue_cap: u64,
    pub total_queued: u64,
    pub cooldown_until_slot: u64,
    pub stale_positions: u16,
    pub bits: u8,
}

impl HarvestPreviewData {
    /// Encode to the 168-byte layout; padding bytes stay zero. `None` only if
    /// an offset table entry were out of range (compile-time constants; the
    /// unit test encodes every field).
    pub fn encode(&self) -> Option<[u8; PREVIEW_LEN]> {
        let mut b = [0u8; PREVIEW_LEN];
        write_bytes(&mut b, off::MAGIC, &PREVIEW_MAGIC)?;
        write_u8(&mut b, off::VERSION, PREVIEW_VERSION)?;
        write_u8(&mut b, off::STATUS, self.status)?;
        write_i64(&mut b, off::NOW, self.now)?;
        write_i64(&mut b, off::NEXT_ALLOWED_TS, self.next_allowed_ts)?;
        write_u64(&mut b, off::I, self.i)?;
        write_u64(&mut b, off::O, self.o)?;
        write_i64(&mut b, off::C_HK, self.c_hk)?;
        write_i64(&mut b, off::C_HDR, self.c_hdr)?;
        write_i64(&mut b, off::U, self.u)?;
        write_i64(&mut b, off::F, self.f)?;
        write_i64(&mut b, off::D_STAR, self.d_star)?;
        write_i64(&mut b, off::W, self.w)?;
        write_u64(&mut b, off::BUF, self.buf)?;
        write_i64(&mut b, off::D, self.d)?;
        write_u64(&mut b, off::IM, self.im)?;
        write_u16(&mut b, off::POSITION_COUNT, self.position_count)?;
        write_u8(&mut b, off::RISK_TIER, self.risk_tier)?;
        write_u8(&mut b, off::IS_LIQUIDATABLE, self.is_liquidatable)?;
        write_u64(&mut b, off::BUYBACK_USDC, self.buyback_usdc)?;
        write_u64(&mut b, off::QUEUE_CAP, self.queue_cap)?;
        write_u64(&mut b, off::TOTAL_QUEUED, self.total_queued)?;
        write_u64(&mut b, off::COOLDOWN_UNTIL_SLOT, self.cooldown_until_slot)?;
        write_u16(&mut b, off::STALE_POSITIONS, self.stale_positions)?;
        write_u8(&mut b, off::BITS, self.bits)?;
        Some(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const ABI_JSON: &str = include_str!("../../../../abi/sijka-vault.json");

    #[test]
    fn layout_matches_abi() {
        let a: Value = serde_json::from_str(ABI_JSON).unwrap();
        let l = &a["accounts"]["HarvestPreview"];
        assert_eq!(l["size"].as_u64().unwrap() as usize, PREVIEW_LEN);
        let want: &[(&str, usize)] = &[
            ("magic", off::MAGIC),
            ("version", off::VERSION),
            ("status", off::STATUS),
            ("now", off::NOW),
            ("next_allowed_ts", off::NEXT_ALLOWED_TS),
            ("I", off::I),
            ("O", off::O),
            ("C_hk", off::C_HK),
            ("C_hdr", off::C_HDR),
            ("U", off::U),
            ("F", off::F),
            ("D_star", off::D_STAR),
            ("W", off::W),
            ("buf", off::BUF),
            ("D", off::D),
            ("IM", off::IM),
            ("position_count", off::POSITION_COUNT),
            ("risk_tier", off::RISK_TIER),
            ("is_liquidatable", off::IS_LIQUIDATABLE),
            ("buyback_usdc", off::BUYBACK_USDC),
            ("queue_cap", off::QUEUE_CAP),
            ("total_queued", off::TOTAL_QUEUED),
            ("cooldown_until_slot", off::COOLDOWN_UNTIL_SLOT),
            ("stale_positions", off::STALE_POSITIONS),
            ("bits", off::BITS),
        ];
        let fields = l["fields"].as_array().unwrap();
        for (name, o) in want {
            let f = fields.iter().find(|f| f["name"] == *name).unwrap_or_else(|| panic!("abi: no field {name}"));
            assert_eq!(f["offset"].as_u64().unwrap() as usize, *o, "{name}");
        }
        // Everything else in the ABI is padding.
        for f in fields {
            let n = f["name"].as_str().unwrap();
            assert!(n.starts_with("_pad") || want.iter().any(|(w, _)| *w == n), "unexpected field {n}");
        }
    }

    #[test]
    fn encodes_every_field() {
        let d = HarvestPreviewData {
            status: 8,
            now: -2,
            next_allowed_ts: 3,
            i: 4,
            o: 5,
            c_hk: -6,
            c_hdr: 7,
            u: -8,
            f: 9,
            d_star: i64::MIN,
            w: 11,
            buf: 12,
            d: -13,
            im: 14,
            position_count: 0x0f0e,
            risk_tier: 16,
            is_liquidatable: 17,
            buyback_usdc: 18,
            queue_cap: u64::MAX,
            total_queued: 20,
            cooldown_until_slot: 21,
            stale_positions: 0x1716,
            bits: 7,
        };
        let b = d.encode().unwrap();
        assert_eq!(&b[0..8], b"SJKRTHPV");
        assert_eq!(b[8], 1);
        assert_eq!(b[9], 8);
        assert!(b[10..16].iter().all(|x| *x == 0));
        assert_eq!(i64::from_le_bytes(b[16..24].try_into().unwrap()), -2);
        assert_eq!(i64::from_le_bytes(b[80..88].try_into().unwrap()), i64::MIN);
        assert_eq!(i64::from_le_bytes(b[104..112].try_into().unwrap()), -13);
        assert_eq!(&b[120..124], &[0x0e, 0x0f, 16, 17]);
        assert!(b[124..128].iter().all(|x| *x == 0));
        assert_eq!(u64::from_le_bytes(b[136..144].try_into().unwrap()), u64::MAX);
        assert_eq!(&b[160..163], &[0x16, 0x17, 7]);
        assert!(b[163..168].iter().all(|x| *x == 0));
    }
}
