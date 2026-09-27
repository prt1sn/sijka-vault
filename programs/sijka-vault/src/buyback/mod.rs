// Copyright (c) 2026 prt1sn. All rights reserved.
//! Buyback and burn support (SPEC §5.5): pure math in [`math`] (price, EMA,
//! observation step, chunk sizing, guard, `min_out`, cool-downs, settlement)
//! and account-level helpers in [`ops`] (`burn_all`, `create_bb_unwrap`,
//! tamper checks after the pump CPI).

pub mod math;
pub mod ops;

#[cfg(test)]
mod flow_tests;

use crate::constants::MAX_RENT_EXTRA;
use crate::error::SijkaError;
use crate::state::buyback_state::buyback_params::BuybackParamsMut;
use crate::state::buyback_state::quote_kind;

/// USDC decimals for `transfer_checked` in tag 43 (SPEC §5.5.7 step 6).
pub const USDC_DECIMALS: u8 = 6;

/// `RESERVE = Rent::minimum_balance(0) + MAX_RENT_EXTRA` (SPEC §5.5.1): the
/// floor of `buyback_authority` lamports. pump takes `init_if_needed` rent from
/// it and tag 43 pays the temporary `bb_unwrap` rent from it; it is never part
/// of the SOL budget.
#[inline]
pub fn reserve(rent_exempt_zero: u64) -> Result<u64, SijkaError> {
    rent_exempt_zero.checked_add(MAX_RENT_EXTRA).ok_or(SijkaError::MathOverflow)
}

/// Default `BuybackParams` for the pair (SPEC §3.8), written by tag 40.
pub fn default_params(kind: u8) -> [u8; 80] {
    let mut b = [0u8; 80];
    let usdc = kind == quote_kind::USDC;
    let mut m = BuybackParamsMut::from_array(&mut b);
    m.set_chunk_bps(10);
    m.set_obs_clamp_bps(1_000);
    m.set_warmup_obs(40);
    m.set_buy_min_interval_s(60);
    m.set_obs_max_age_s(120);
    m.set_swap_min_interval_s(60);
    m.set_chunk_max_quote(if usdc { 100_000_000 } else { 1_000_000_000 });
    m.set_chunk_min_quote(if usdc { 1_000_000 } else { 10_000_000 });
    m.set_swap_max_usdc(1_000_000_000);
    m.set_sol_budget_cap(20_000_000_000);
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::buyback_state::buyback_params::BuybackParams;

    #[test]
    fn defaults_are_valid_and_match_spec() {
        for (kind, max, min) in
            [(quote_kind::SOL, 1_000_000_000, 10_000_000), (quote_kind::USDC, 100_000_000, 1_000_000)]
        {
            let b = default_params(kind);
            let p = BuybackParams::from_array(&b);
            assert_eq!(p.validate(), Ok(()));
            assert_eq!((p.chunk_max_quote(), p.chunk_min_quote()), (max, min));
            assert_eq!((p.chunk_bps(), p.obs_clamp_bps()), (10, 1_000));
            assert_eq!((p.warmup_obs(), p.buy_min_interval_s()), (40, 60));
            assert_eq!((p.obs_max_age_s(), p.swap_min_interval_s()), (120, 60));
            // SPEC v4: the former spot guard (@2), fee cap (@4), swap band
            // (@8) and mark age (@24) are reserved zeros.
            assert_eq!(&b[2..6], &[0; 4]);
            assert_eq!(&b[8..10], &[0; 2]);
            assert_eq!(&b[24..28], &[0; 4]);
            assert_eq!((p.swap_max_usdc(), p.sol_budget_cap()), (1_000_000_000, 20_000_000_000));
        }
    }

    #[test]
    fn reserve_adds_rent_extra() {
        assert_eq!(reserve(890_880), Ok(890_880 + 15_000_000));
        assert_eq!(reserve(u64::MAX), Err(SijkaError::MathOverflow));
    }
}
