// Copyright (c) 2026 prt1sn. All rights reserved.
//! Bounds-checked little-endian reads and writes over byte slices.
//!
//! Every function returns `None` instead of panicking when the range does not
//! fit, and computes the end offset with `checked_add`. Use these for any
//! offset that depends on account data or instruction data. Fixed layouts in
//! `crate::state` also go through them; there the offsets are asserted at
//! compile time, so the `None` branch is dead code.

use pinocchio::pubkey::Pubkey;

/// Borrow `N` bytes at `off` as a fixed-size array.
#[inline(always)]
pub fn array_ref<const N: usize>(d: &[u8], off: usize) -> Option<&[u8; N]> {
    let end = off.checked_add(N)?;
    d.get(off..end)?.try_into().ok()
}

/// Mutably borrow `N` bytes at `off` as a fixed-size array.
#[inline(always)]
pub fn array_mut<const N: usize>(d: &mut [u8], off: usize) -> Option<&mut [u8; N]> {
    let end = off.checked_add(N)?;
    d.get_mut(off..end)?.try_into().ok()
}

/// Copy `N` bytes at `off`.
#[inline(always)]
pub fn read_array<const N: usize>(d: &[u8], off: usize) -> Option<[u8; N]> {
    array_ref::<N>(d, off).copied()
}

#[inline(always)]
pub fn read_u8(d: &[u8], off: usize) -> Option<u8> {
    d.get(off).copied()
}

#[inline(always)]
pub fn read_i8(d: &[u8], off: usize) -> Option<i8> {
    read_array::<1>(d, off).map(i8::from_le_bytes)
}

#[inline(always)]
pub fn read_u16(d: &[u8], off: usize) -> Option<u16> {
    read_array::<2>(d, off).map(u16::from_le_bytes)
}

#[inline(always)]
pub fn read_u32(d: &[u8], off: usize) -> Option<u32> {
    read_array::<4>(d, off).map(u32::from_le_bytes)
}

#[inline(always)]
pub fn read_i32(d: &[u8], off: usize) -> Option<i32> {
    read_array::<4>(d, off).map(i32::from_le_bytes)
}

#[inline(always)]
pub fn read_u64(d: &[u8], off: usize) -> Option<u64> {
    read_array::<8>(d, off).map(u64::from_le_bytes)
}

#[inline(always)]
pub fn read_i64(d: &[u8], off: usize) -> Option<i64> {
    read_array::<8>(d, off).map(i64::from_le_bytes)
}

#[inline(always)]
pub fn read_u128(d: &[u8], off: usize) -> Option<u128> {
    read_array::<16>(d, off).map(u128::from_le_bytes)
}

#[inline(always)]
pub fn read_key(d: &[u8], off: usize) -> Option<&Pubkey> {
    array_ref::<32>(d, off)
}

/// Copy `src` into `d` at `off`. Returns `None` (and writes nothing) if it does
/// not fit.
#[inline(always)]
pub fn write_bytes(d: &mut [u8], off: usize, src: &[u8]) -> Option<()> {
    let end = off.checked_add(src.len())?;
    d.get_mut(off..end)?.copy_from_slice(src);
    Some(())
}

/// Write the fixed-size array `v` into `d` at `off`. Returns `None` (and
/// writes nothing) if it does not fit. Unlike [`write_bytes`] this compiles to
/// plain stores (no `copy_from_slice` call), which keeps the binary small.
#[inline(always)]
pub fn write_array<const N: usize>(d: &mut [u8], off: usize, v: &[u8; N]) -> Option<()> {
    *array_mut::<N>(d, off)? = *v;
    Some(())
}

#[inline(always)]
pub fn write_u8(d: &mut [u8], off: usize, v: u8) -> Option<()> {
    *d.get_mut(off)? = v;
    Some(())
}

#[inline(always)]
pub fn write_i8(d: &mut [u8], off: usize, v: i8) -> Option<()> {
    write_array(d, off, &v.to_le_bytes())
}

#[inline(always)]
pub fn write_u16(d: &mut [u8], off: usize, v: u16) -> Option<()> {
    write_array(d, off, &v.to_le_bytes())
}

#[inline(always)]
pub fn write_u32(d: &mut [u8], off: usize, v: u32) -> Option<()> {
    write_array(d, off, &v.to_le_bytes())
}

#[inline(always)]
pub fn write_u64(d: &mut [u8], off: usize, v: u64) -> Option<()> {
    write_array(d, off, &v.to_le_bytes())
}

#[inline(always)]
pub fn write_i64(d: &mut [u8], off: usize, v: i64) -> Option<()> {
    write_array(d, off, &v.to_le_bytes())
}

#[inline(always)]
pub fn write_u128(d: &mut [u8], off: usize, v: u128) -> Option<()> {
    write_array(d, off, &v.to_le_bytes())
}

/// `true` if every byte in `d[off..off+len]` is zero; `false` if the range does
/// not fit.
#[inline]
pub fn is_zero(d: &[u8], off: usize, len: usize) -> bool {
    match off.checked_add(len).and_then(|end| d.get(off..end)) {
        Some(s) => s.iter().all(|b| *b == 0),
        None => false,
    }
}

/// `true` for the all-zero key ("not set", SPEC §3.0).
#[inline(always)]
pub fn is_zero_key(k: &Pubkey) -> bool {
    k.iter().all(|b| *b == 0)
}

/// Zero key constant.
pub const ZERO_KEY: Pubkey = [0u8; 32];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_are_bounds_checked() {
        let d = [1u8, 2, 3, 4, 5, 6, 7, 8, 9];
        assert_eq!(read_u64(&d, 0), Some(u64::from_le_bytes([1, 2, 3, 4, 5, 6, 7, 8])));
        assert_eq!(read_u64(&d, 1), Some(u64::from_le_bytes([2, 3, 4, 5, 6, 7, 8, 9])));
        assert_eq!(read_u64(&d, 2), None);
        assert_eq!(read_u64(&d, usize::MAX), None);
        assert_eq!(read_u8(&d, 9), None);
        assert_eq!(read_i8(&[0xff], 0), Some(-1));
        assert_eq!(read_key(&d, 0), None);
    }

    #[test]
    fn writes_are_bounds_checked() {
        let mut d = [0u8; 4];
        assert_eq!(write_u32(&mut d, 0, 0x0403_0201), Some(()));
        assert_eq!(d, [1, 2, 3, 4]);
        assert_eq!(write_u32(&mut d, 1, 7), None);
        assert_eq!(d, [1, 2, 3, 4]);
        assert_eq!(write_bytes(&mut d, usize::MAX, &[1]), None);
        assert!(!is_zero(&d, 0, 4));
        assert!(!is_zero(&d, 3, 2));
        assert!(is_zero(&[0, 0], 0, 2));
        assert!(is_zero_key(&ZERO_KEY));
    }
}
