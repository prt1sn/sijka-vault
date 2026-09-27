// Copyright (c) 2026 prt1sn. All rights reserved.
//! Shared helpers: bounds-checked byte access, account validation, checked
//! math, PDA derivation and runtime queries.

pub mod accounts;
pub mod bytes;
pub mod math;
pub mod pda;
pub mod runtime;

#[cfg(test)]
pub mod test_utils;
