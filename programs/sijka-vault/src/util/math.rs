// Copyright (c) 2026 prt1sn. All rights reserved.
//! Checked integer arithmetic (SPEC §5.0.7). No floating point.
//!
//! u64 counters use `checked_*`; intermediate products use u128/i128, also
//! checked. Every failure is `MathOverflow` (logged). Rounding direction is the
//! caller's choice: amounts paid out round down (`*_floor`), thresholds the pool
//! requires round up (`*_ceil`).

use pinocchio::program_error::ProgramError;

use crate::constants::BPS;
use crate::error::SijkaError;

#[inline(always)]
fn overflow() -> ProgramError {
    SijkaError::MathOverflow.fail()
}

#[inline]
pub fn add_u64(a: u64, b: u64) -> Result<u64, ProgramError> {
    a.checked_add(b).ok_or_else(overflow)
}

#[inline]
pub fn sub_u64(a: u64, b: u64) -> Result<u64, ProgramError> {
    a.checked_sub(b).ok_or_else(overflow)
}

#[inline]
pub fn mul_u64(a: u64, b: u64) -> Result<u64, ProgramError> {
    a.checked_mul(b).ok_or_else(overflow)
}

#[inline]
pub fn add_i64(a: i64, b: i64) -> Result<i64, ProgramError> {
    a.checked_add(b).ok_or_else(overflow)
}

#[inline]
pub fn sub_i64(a: i64, b: i64) -> Result<i64, ProgramError> {
    a.checked_sub(b).ok_or_else(overflow)
}

#[inline]
pub fn add_u128(a: u128, b: u128) -> Result<u128, ProgramError> {
    a.checked_add(b).ok_or_else(overflow)
}

#[inline]
pub fn sub_u128(a: u128, b: u128) -> Result<u128, ProgramError> {
    a.checked_sub(b).ok_or_else(overflow)
}

#[inline]
pub fn mul_u128(a: u128, b: u128) -> Result<u128, ProgramError> {
    a.checked_mul(b).ok_or_else(overflow)
}

#[inline]
pub fn add_i128(a: i128, b: i128) -> Result<i128, ProgramError> {
    a.checked_add(b).ok_or_else(overflow)
}

#[inline]
pub fn sub_i128(a: i128, b: i128) -> Result<i128, ProgramError> {
    a.checked_sub(b).ok_or_else(overflow)
}

#[inline]
pub fn mul_i128(a: i128, b: i128) -> Result<i128, ProgramError> {
    a.checked_mul(b).ok_or_else(overflow)
}

/// `⌊a / b⌋`; `b == 0` is an error.
#[inline]
pub fn div_floor_u128(a: u128, b: u128) -> Result<u128, ProgramError> {
    a.checked_div(b).ok_or_else(overflow)
}

/// `⌈a / b⌉ = (a + b − 1) / b` (SPEC §5.0.7); `b == 0` is an error.
#[inline]
pub fn div_ceil_u128(a: u128, b: u128) -> Result<u128, ProgramError> {
    if b == 0 {
        return Err(overflow());
    }
    let q = a.checked_div(b).ok_or_else(overflow)?;
    let r = a.checked_rem(b).ok_or_else(overflow)?;
    if r == 0 { Ok(q) } else { q.checked_add(1).ok_or_else(overflow) }
}

/// `⌊a·b / d⌋` in u128.
#[inline]
pub fn mul_div_floor(a: u128, b: u128, d: u128) -> Result<u128, ProgramError> {
    div_floor_u128(mul_u128(a, b)?, d)
}

/// `⌈a·b / d⌉` in u128.
#[inline]
pub fn mul_div_ceil(a: u128, b: u128, d: u128) -> Result<u128, ProgramError> {
    div_ceil_u128(mul_u128(a, b)?, d)
}

/// `⌊x·bps / 10 000⌋`.
#[inline]
pub fn bps_floor(x: u64, bps: u64) -> Result<u64, ProgramError> {
    to_u64(mul_div_floor(u128::from(x), u128::from(bps), u128::from(BPS))?)
}

/// `⌈x·bps / 10 000⌉`.
#[inline]
pub fn bps_ceil(x: u64, bps: u64) -> Result<u64, ProgramError> {
    to_u64(mul_div_ceil(u128::from(x), u128::from(bps), u128::from(BPS))?)
}

/// u128 → u64, error if it does not fit.
#[inline]
pub fn to_u64(x: u128) -> Result<u64, ProgramError> {
    u64::try_from(x).map_err(|_| overflow())
}

/// i128 → i64, error if it does not fit.
#[inline]
pub fn i128_to_i64(x: i128) -> Result<i64, ProgramError> {
    i64::try_from(x).map_err(|_| overflow())
}

/// i128 → u64, error if negative or too large.
#[inline]
pub fn i128_to_u64(x: i128) -> Result<u64, ProgramError> {
    u64::try_from(x).map_err(|_| overflow())
}

/// u64 → i64, error above `i64::MAX`.
#[inline]
pub fn u64_to_i64(x: u64) -> Result<i64, ProgramError> {
    i64::try_from(x).map_err(|_| overflow())
}

/// i64 → u64, error if negative.
#[inline]
pub fn i64_to_u64(x: i64) -> Result<u64, ProgramError> {
    u64::try_from(x).map_err(|_| overflow())
}

/// usize → u64 (lossless on 64-bit targets, checked anyway).
#[inline]
pub fn usize_to_u64(x: usize) -> Result<u64, ProgramError> {
    u64::try_from(x).map_err(|_| overflow())
}

/// u64 → usize, checked.
#[inline]
pub fn u64_to_usize(x: u64) -> Result<usize, ProgramError> {
    usize::try_from(x).map_err(|_| overflow())
}

/// i128 saturated into the i64 range (for event fields SPEC marks "насыщение").
#[inline]
pub fn saturate_i64(x: i128) -> i64 {
    i64::try_from(x).unwrap_or(if x < 0 { i64::MIN } else { i64::MAX })
}

/// u128 saturated into the u64 range.
#[inline]
pub fn saturate_u64(x: u128) -> u64 {
    u64::try_from(x).unwrap_or(u64::MAX)
}

/// Rent-exempt minimum for `data_len` bytes, from the Rent sysvar, without
/// floating point: supports the two exemption thresholds the runtime uses
/// (2.0, and 1.0 after SIMD-0194); any other threshold fails closed.
#[allow(deprecated)] // the SIMD-0194 renames are not out yet; both fields are read as integers
pub fn rent_exempt_minimum(data_len: usize) -> Result<u64, ProgramError> {
    use pinocchio::sysvars::{Sysvar, rent::Rent};
    let rent = Rent::get()?;
    rent_exempt_minimum_with(rent.lamports_per_byte_year, rent.exemption_threshold.to_bits(), data_len)
}

/// Pure form of [`rent_exempt_minimum`]: `threshold_bits` are the IEEE-754 bits
/// of the exemption threshold.
pub fn rent_exempt_minimum_with(
    lamports_per_byte_year: u64,
    threshold_bits: u64,
    data_len: usize,
) -> Result<u64, ProgramError> {
    /// Account storage overhead added to every account (bytes).
    const ACCOUNT_STORAGE_OVERHEAD: u64 = 128;
    const THRESHOLD_2_0: u64 = 0x4000_0000_0000_0000;
    const THRESHOLD_1_0: u64 = 0x3ff0_0000_0000_0000;
    let bytes = add_u64(ACCOUNT_STORAGE_OVERHEAD, usize_to_u64(data_len)?)?;
    let base = mul_u64(bytes, lamports_per_byte_year)?;
    match threshold_bits {
        THRESHOLD_2_0 => mul_u64(base, 2),
        THRESHOLD_1_0 => Ok(base),
        _ => Err(overflow()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_ops() {
        assert_eq!(add_u64(1, 2), Ok(3));
        assert!(add_u64(u64::MAX, 1).is_err());
        assert!(sub_u64(0, 1).is_err());
        assert!(mul_u64(u64::MAX, 2).is_err());
        assert!(add_i64(i64::MAX, 1).is_err());
        assert!(sub_i64(i64::MIN, 1).is_err());
        assert!(mul_i128(i128::MAX, 2).is_err());
        assert!(div_floor_u128(1, 0).is_err());
        assert!(div_ceil_u128(1, 0).is_err());
    }

    #[test]
    fn rounding() {
        assert_eq!(div_ceil_u128(10, 5), Ok(2));
        assert_eq!(div_ceil_u128(11, 5), Ok(3));
        assert_eq!(div_ceil_u128(0, 5), Ok(0));
        assert_eq!(div_ceil_u128(u128::MAX, 1), Ok(u128::MAX));
        assert_eq!(mul_div_floor(7, 3, 2), Ok(10));
        assert_eq!(mul_div_ceil(7, 3, 2), Ok(11));
        // SPEC §5.4.1 example: u = 12 345 678 → creator 2 469 135.
        assert_eq!(bps_floor(12_345_678, 2000), Ok(2_469_135));
        assert_eq!(bps_ceil(12_345_678, 2000), Ok(2_469_136));
        // SPEC §5.3.4 example: amount_in = 1e9, px = 120 610 000, band = 50.
        let min_out = mul_div_ceil(1_000_000_000u128 * 120_610_000, 10_000 - 50, 1_000_000_000u128 * 10_000);
        assert_eq!(min_out, Ok(120_006_950));
    }

    #[test]
    fn conversions() {
        assert_eq!(to_u64(u128::from(u64::MAX)), Ok(u64::MAX));
        assert!(to_u64(u128::from(u64::MAX) + 1).is_err());
        assert!(i128_to_i64(i128::from(i64::MAX) + 1).is_err());
        assert!(i128_to_u64(-1).is_err());
        assert!(u64_to_i64(u64::MAX).is_err());
        assert!(i64_to_u64(-1).is_err());
        assert_eq!(saturate_i64(i128::MIN), i64::MIN);
        assert_eq!(saturate_i64(i128::MAX), i64::MAX);
        assert_eq!(saturate_u64(u128::MAX), u64::MAX);
    }

    #[test]
    fn rent_without_float() {
        // Default mainnet rent: 3480 lamports/byte-year, threshold 2.0.
        // minimum_balance(0) = 128·3480·2 = 890 880; (5144) = 5272·3480·2.
        let t2 = 2.0f64.to_bits();
        assert_eq!(rent_exempt_minimum_with(3480, t2, 0), Ok(890_880));
        assert_eq!(rent_exempt_minimum_with(3480, t2, 5144), Ok((5144 + 128) * 3480 * 2));
        // SIMD-0194 form: threshold 1.0, doubled rate.
        let t1 = 1.0f64.to_bits();
        assert_eq!(rent_exempt_minimum_with(6960, t1, 0), Ok(890_880));
        // SPEC §3.1 / §5.1.2 reference numbers (5080 lamports per byte, threshold 1.0).
        assert_eq!(rent_exempt_minimum_with(5080, t1, 0), Ok(650_240));
        assert_eq!(rent_exempt_minimum_with(5080, t1, 5144), Ok(26_781_760));
        assert_eq!(rent_exempt_minimum_with(5080, t1, 5360), Ok(27_879_040));
        assert!(rent_exempt_minimum_with(3480, 1.5f64.to_bits(), 0).is_err());
    }
}
