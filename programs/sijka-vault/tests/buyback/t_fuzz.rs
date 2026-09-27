// Copyright (c) 2026 prt1sn. All rights reserved.
//! TD-58: a random walk of observations, chunks and market trades on the real
//! pump binary and the live SOL curve; after every step the invariants of
//! SPEC §9.7 TD-58 hold.

use sijka_vault::error::SijkaError;

use crate::harness::*;
use crate::pumpix::*;

/// Deterministic xorshift64*.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next() % (hi - lo + 1)
    }
}

#[test]
fn fuzz_observations_chunks_and_market_trades() {
    for seed in [0x5EED_0001u64, 0x5EED_0002, 0x5EED_0003] {
        let mut v = vault!(Setup::sol("solcurve"));
        v.fund_authority(5 * LAMPORTS_PER_SOL);
        v.warm_up(40);
        let t = Trader::new(&mut v, 300 * LAMPORTS_PER_SOL);
        let mut rng = Rng(seed);
        let k0 = v.k.buyback_authority;
        let rent0 = v.rent(0);
        let mut last_spent_counter = v.bs().cum_payout_buyback_spent();
        let (mut chunks, mut refused) = (0u32, std::collections::BTreeMap::<String, u32>::new());
        for _step in 0..80 {
            match rng.range(0, 5) {
                0 => {
                    let x = rng.range(1_000_000, 400_000_000);
                    let _ = t.curve_buy(&mut v, x);
                }
                1 => {
                    let bal = t.base(&v);
                    if bal > 0 {
                        let amt = bal * rng.range(1, 100) / 100;
                        let _ = t.curve_sell(&mut v, amt.max(1));
                    }
                }
                2 | 3 => {
                    v.tick(rng.range(15, 45) as i64, 1);
                    let _ = v.observe();
                }
                _ => {
                    v.tick(rng.range(1, 70) as i64, 1);
                    let bs = v.bs();
                    let p = bs.buyback_params();
                    let q_ref = crate::pumpix::curve_reserves(&v).1.min(bs.last_obs_quote()).min(bs.q_ema());
                    let res = v.call(chunk_curve_ix(&v, 0, 0));
                    match &res {
                        Ok(m) => {
                            chunks += 1;
                            let e = event(&m.logs, "SJKEVCHK");
                            let (vv, spent, bought) = (u64_at(&e, 18), u64_at(&e, 26), u64_at(&e, 50));
                            assert_eq!(v.token_amount(&v.buyback_token()), 0, "buyback_token empty after a chunk");
                            // SPEC v4 (no spot guard, the price limit is the
                            // keeper's min_out): the size bounds still hold.
                            let cap = ((u128::from(q_ref) * u128::from(p.chunk_bps()) / 10_000) as u64)
                                .min(p.chunk_max_quote());
                            assert!(vv <= cap && spent <= vv, "chunk above its caps: v {vv} spent {spent} cap {cap}");
                            assert!(bought >= u64_at(&e, 42) && bought > 0, "bought below the keeper's min_out");
                        }
                        Err(f) => {
                            let code = custom_code(f).unwrap_or(0);
                            let name = SijkaError::ALL
                                .iter()
                                .find(|e| e.code() == code)
                                .map(|e| e.name().to_string())
                                .unwrap_or_else(|| format!("external {code}"));
                            *refused.entry(name).or_default() += 1;
                        }
                    }
                }
            }
            let bs = v.bs();
            assert!(bs.cum_burned_tokens() >= bs.cum_bought_tokens());
            assert!(v.lamports(&k0) >= rent0, "k0 stays rent-exempt");
            assert!(bs.cum_payout_buyback_spent() >= last_spent_counter);
            last_spent_counter = bs.cum_payout_buyback_spent();
        }
        let bs = v.bs();
        println!(
            "TD-58 seed {seed:#x}: {chunks} chunks, burned {} (bought {}), refusals {refused:?}, trader {}",
            bs.cum_burned_tokens(),
            bs.cum_bought_tokens(),
            t.pubkey()
        );
        assert_eq!(bs.n_chunks(), u64::from(chunks));
    }
}
