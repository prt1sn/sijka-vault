// Copyright (c) 2026 prt1sn. All rights reserved.
//! Our account layouts (SPEC §3): `Config`, `BuybackState` and the parameter
//! structs embedded in them.
//!
//! Every layout is a byte array with fixed little-endian offsets. The `layout!`
//! macro generates, for each field, an offset constant in `off::`, a getter on
//! the read view and a setter on the write view, plus a `FIELDS` table that the
//! tests compare with SPEC (via `abi/sijka-vault.json`). Offsets are checked at
//! compile time against the struct length, so accessors cannot go out of
//! bounds. There is no pointer casting (SPEC §3.0).

pub mod buyback_state;
pub mod config;

use pinocchio::account_info::{AccountInfo, Ref, RefMut};
use pinocchio::pubkey::Pubkey;

use crate::error::SijkaError;
use crate::util::accounts::expect_key;

/// One field of a layout: name as in SPEC, offset, size in bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldSpec {
    pub name: &'static str,
    pub offset: usize,
    pub size: usize,
}

/// Generates a fixed-size layout. Field kinds:
/// `u8 i8 u16 u32 u64 i64 u128` scalars, `key` (Pubkey), `bytes(N)` (array,
/// returned by reference), `sub(N)` (nested parameter struct, by reference),
/// `raw(N)` (reserved bytes or tables with custom helpers: offset only).
macro_rules! layout {
    (
        $(#[$m:meta])*
        view $view:ident, $view_mut:ident, $len_name:ident = $len:literal;
        $( $kind:ident $( ($n:literal) )? $name:ident $setter:ident $konst:ident @ $off:literal; )*
    ) => {
        /// Total length in bytes.
        pub const $len_name: usize = $len;

        /// Field offsets.
        pub mod off {
            $( pub const $konst: usize = $off; )*
        }

        // Every field lies inside the struct.
        #[allow(clippy::int_plus_one)]
        const _: () = { $( assert!($off + layout!(@size $kind $(($n))?) <= $len); )* };

        /// Field table (name, offset, size) for layout tests.
        pub const FIELDS: &[$crate::state::FieldSpec] = &[
            $( $crate::state::FieldSpec {
                name: stringify!($name), offset: $off, size: layout!(@size $kind $(($n))?),
            }, )*
        ];

        $(#[$m])*
        #[derive(Clone, Copy)]
        pub struct $view<'a>(&'a [u8; $len]);

        /// Mutable view over the same bytes.
        pub struct $view_mut<'a>(&'a mut [u8; $len]);

        #[allow(dead_code)]
        impl<'a> $view<'a> {
            /// View over exactly `LEN` bytes; `None` for any other length.
            #[inline(always)]
            pub fn new(d: &'a [u8]) -> Option<Self> {
                <&[u8; $len]>::try_from(d).ok().map(Self)
            }
            #[inline(always)]
            pub const fn from_array(d: &'a [u8; $len]) -> Self {
                Self(d)
            }
            #[inline(always)]
            pub const fn bytes(&self) -> &'a [u8; $len] {
                self.0
            }
            $( layout!(@get $kind $(($n))? $name $konst); )*
        }

        #[allow(dead_code)]
        impl<'a> $view_mut<'a> {
            /// Mutable view over exactly `LEN` bytes; `None` for any other length.
            #[inline(always)]
            pub fn new(d: &'a mut [u8]) -> Option<Self> {
                <&mut [u8; $len]>::try_from(d).ok().map(Self)
            }
            #[inline(always)]
            pub fn from_array(d: &'a mut [u8; $len]) -> Self {
                Self(d)
            }
            /// Read view of the current bytes.
            #[inline(always)]
            pub fn view(&self) -> $view<'_> {
                $view(self.0)
            }
            #[inline(always)]
            pub fn bytes_mut(&mut self) -> &mut [u8; $len] {
                self.0
            }
            $( layout!(@set $kind $(($n))? $setter $konst); )*
        }
    };

    (@size u8) => { 1 };
    (@size i8) => { 1 };
    (@size u16) => { 2 };
    (@size u32) => { 4 };
    (@size u64) => { 8 };
    (@size i64) => { 8 };
    (@size u128) => { 16 };
    (@size key) => { 32 };
    (@size bytes($n:literal)) => { $n };
    (@size sub($n:literal)) => { $n };
    (@size raw($n:literal)) => { $n };

    (@get u8 $name:ident $k:ident) => {
        #[inline(always)] pub fn $name(&self) -> u8 { $crate::util::bytes::read_u8(self.0, off::$k).unwrap_or(0) }
    };
    (@get i8 $name:ident $k:ident) => {
        #[inline(always)] pub fn $name(&self) -> i8 { $crate::util::bytes::read_i8(self.0, off::$k).unwrap_or(0) }
    };
    (@get u16 $name:ident $k:ident) => {
        #[inline(always)] pub fn $name(&self) -> u16 { $crate::util::bytes::read_u16(self.0, off::$k).unwrap_or(0) }
    };
    (@get u32 $name:ident $k:ident) => {
        #[inline(always)] pub fn $name(&self) -> u32 { $crate::util::bytes::read_u32(self.0, off::$k).unwrap_or(0) }
    };
    (@get u64 $name:ident $k:ident) => {
        #[inline(always)] pub fn $name(&self) -> u64 { $crate::util::bytes::read_u64(self.0, off::$k).unwrap_or(0) }
    };
    (@get i64 $name:ident $k:ident) => {
        #[inline(always)] pub fn $name(&self) -> i64 { $crate::util::bytes::read_i64(self.0, off::$k).unwrap_or(0) }
    };
    (@get u128 $name:ident $k:ident) => {
        #[inline(always)] pub fn $name(&self) -> u128 { $crate::util::bytes::read_u128(self.0, off::$k).unwrap_or(0) }
    };
    (@get key $name:ident $k:ident) => {
        #[inline(always)] pub fn $name(&self) -> &'a pinocchio::pubkey::Pubkey {
            $crate::util::bytes::array_ref::<32>(self.0, off::$k).unwrap_or(&$crate::util::bytes::ZERO_KEY)
        }
    };
    (@get bytes($n:literal) $name:ident $k:ident) => {
        #[inline(always)] pub fn $name(&self) -> &'a [u8; $n] {
            $crate::util::bytes::array_ref::<$n>(self.0, off::$k).unwrap_or(&[0u8; $n])
        }
    };
    (@get sub($n:literal) $name:ident $k:ident) => {
        #[inline(always)] pub fn $name(&self) -> &'a [u8; $n] {
            $crate::util::bytes::array_ref::<$n>(self.0, off::$k).unwrap_or(&[0u8; $n])
        }
    };
    (@get raw($n:literal) $name:ident $k:ident) => {};

    (@set u8 $setter:ident $k:ident) => {
        #[inline(always)] pub fn $setter(&mut self, v: u8) { let _ = $crate::util::bytes::write_u8(self.0, off::$k, v); }
    };
    (@set i8 $setter:ident $k:ident) => {
        #[inline(always)] pub fn $setter(&mut self, v: i8) { let _ = $crate::util::bytes::write_i8(self.0, off::$k, v); }
    };
    (@set u16 $setter:ident $k:ident) => {
        #[inline(always)] pub fn $setter(&mut self, v: u16) { let _ = $crate::util::bytes::write_u16(self.0, off::$k, v); }
    };
    (@set u32 $setter:ident $k:ident) => {
        #[inline(always)] pub fn $setter(&mut self, v: u32) { let _ = $crate::util::bytes::write_u32(self.0, off::$k, v); }
    };
    (@set u64 $setter:ident $k:ident) => {
        #[inline(always)] pub fn $setter(&mut self, v: u64) { let _ = $crate::util::bytes::write_u64(self.0, off::$k, v); }
    };
    (@set i64 $setter:ident $k:ident) => {
        #[inline(always)] pub fn $setter(&mut self, v: i64) { let _ = $crate::util::bytes::write_i64(self.0, off::$k, v); }
    };
    (@set u128 $setter:ident $k:ident) => {
        #[inline(always)] pub fn $setter(&mut self, v: u128) { let _ = $crate::util::bytes::write_u128(self.0, off::$k, v); }
    };
    (@set key $setter:ident $k:ident) => {
        #[inline(always)] pub fn $setter(&mut self, v: &pinocchio::pubkey::Pubkey) {
            let _ = $crate::util::bytes::write_array(self.0, off::$k, v);
        }
    };
    (@set bytes($n:literal) $setter:ident $k:ident) => {
        #[inline(always)] pub fn $setter(&mut self, v: &[u8; $n]) { let _ = $crate::util::bytes::write_array(self.0, off::$k, v); }
    };
    (@set sub($n:literal) $setter:ident $k:ident) => {
        #[inline(always)] pub fn $setter(&mut self, v: &[u8; $n]) { let _ = $crate::util::bytes::write_array(self.0, off::$k, v); }
    };
    (@set raw($n:literal) $setter:ident $k:ident) => {};
}
pub(crate) use layout;

/// Standard checks shared by our three state accounts (SPEC §3.0): owner is
/// this program and the length is exact. Header bytes are checked by the
/// per-account loaders.
fn check_owner_len(ai: &AccountInfo, program_id: &Pubkey, len: usize, e: SijkaError) -> Result<(), SijkaError> {
    if !ai.is_owned_by(program_id) || ai.data_len() != len {
        return Err(e);
    }
    Ok(())
}

/// Borrow account data read-only after the owner/length check.
pub(crate) fn borrow_checked<'a>(
    ai: &'a AccountInfo,
    program_id: &Pubkey,
    len: usize,
    e: SijkaError,
) -> Result<Ref<'a, [u8]>, pinocchio::program_error::ProgramError> {
    check_owner_len(ai, program_id, len, e).map_err(SijkaError::fail)?;
    ai.try_borrow_data()
}

/// Borrow account data mutably after the owner/length and writable checks.
pub(crate) fn borrow_mut_checked<'a>(
    ai: &'a AccountInfo,
    program_id: &Pubkey,
    len: usize,
    e: SijkaError,
    not_writable: SijkaError,
) -> Result<RefMut<'a, [u8]>, pinocchio::program_error::ProgramError> {
    check_owner_len(ai, program_id, len, e).map_err(SijkaError::fail)?;
    if !ai.is_writable() {
        return Err(not_writable.fail());
    }
    ai.try_borrow_mut_data()
}

/// Key check used by `buyback_state` (the key is stored in `Config`).
pub(crate) fn check_stored_key(ai: &AccountInfo, expected: &Pubkey, e: SijkaError) -> pinocchio::ProgramResult {
    expect_key(ai, expected, e)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::FieldSpec;

    /// Fields must tile `[0, len)` in order, without gaps or overlaps.
    pub fn assert_tiles(fields: &[FieldSpec], len: usize) {
        let mut pos = 0usize;
        for f in fields {
            assert_eq!(f.offset, pos, "field {} starts at {}, expected {}", f.name, f.offset, pos);
            pos += f.size;
        }
        assert_eq!(pos, len, "fields end at {pos}, struct is {len}");
    }

    /// Every field is aligned to its natural size where SPEC promises it
    /// (Config, SPEC §3.0: "каждое поле лежит на смещении, кратном своему размеру").
    pub fn assert_natural_alignment(fields: &[FieldSpec]) {
        for f in fields {
            let align = match f.size {
                1 | 2 | 4 | 8 => f.size,
                12 => 4,      // [u32; 3]
                40 | 64 => 8, // parameter structs with u64 fields
                _ => 1,       // Pubkey and byte arrays
            };
            assert_eq!(f.offset % align, 0, "field {} at {} is not {}-aligned", f.name, f.offset, align);
        }
    }
}
