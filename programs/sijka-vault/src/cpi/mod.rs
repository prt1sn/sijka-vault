// Copyright (c) 2026 prt1sn. All rights reserved.
//! Cross-program invocations. Typed Phoenix / Ember / Hawkeye wrappers and all
//! hand-built variable-size CPIs go through `crate::cpi_tramp` (SPEC §5.0.6);
//! `token` and `system` hold the small fixed-size Token / System CPIs.

pub mod ember;
pub mod hawkeye;
pub mod jupiter;
pub mod phoenix_deposit;
pub mod phoenix_withdraw;
pub mod pump;
pub mod pump_amm;
pub mod system;
pub mod token;

use pinocchio::instruction::Seed;

/// Signer seeds `[seed, [bump]]` for our single-seed PDAs (SPEC §5.0.6:
/// `seeds!(b"phx_authority", &[cfg.phx_authority_bump])` and the same for
/// `fee_inbox`, `swap`, `buyback`, `rent_payer`, `bb_unwrap`, `creator_escrow`,
/// `config`, `buyback_state`).
///
/// ```ignore
/// let pda = PdaSeeds::new(SEED_PHX_AUTHORITY, cfg.phx_authority_bump());
/// let seeds = pda.seeds();
/// let signer = [Signer::from(&seeds)];
/// ```
pub struct PdaSeeds {
    seed: &'static [u8],
    bump: [u8; 1],
}

impl PdaSeeds {
    #[inline(always)]
    pub const fn new(seed: &'static [u8], bump: u8) -> Self {
        Self { seed, bump: [bump] }
    }

    #[inline(always)]
    pub fn seeds(&self) -> [Seed<'_>; 2] {
        [Seed::from(self.seed), Seed::from(&self.bump)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::SEED_PHX_AUTHORITY;

    #[test]
    fn pda_seeds_shape() {
        let p = PdaSeeds::new(SEED_PHX_AUTHORITY, 254);
        let s = p.seeds();
        assert_eq!(s.len(), 2);
        let signer = pinocchio::instruction::Signer::from(&s);
        let _ = signer;
    }
}
