// Copyright (c) 2026 prt1sn. All rights reserved.
//! Phoenix venue status and the pure parts of the emergency recovery
//! (SPEC §5.6, DECISIONS §17).
//!
//! - [`status`]: the up / down / unknown verdict over the Phoenix program,
//!   its ProgramData, GlobalConfig and PerpAssetMap (§5.6.1) and the 10-day
//!   countdown (§5.6.2). Used by tags 50 and 51 op 0.
//! - [`withdraw`]: withdraw-queue header parsing, the queue walk and the
//!   amount selection of tag 51 op 1 / op 6 (§5.6.4 steps 4, 7, 8).
//!
//! Everything here is a pure function of byte slices and integers, so it is
//! unit-tested on the host; the instruction handlers live in
//! `instructions/recovery.rs`.

pub mod status;
pub mod withdraw;
